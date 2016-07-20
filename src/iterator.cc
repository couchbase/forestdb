/* -*- Mode: C++; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2010 Couchbase, Inc
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>

#include "libforestdb/forestdb.h"
#include "fdb_internal.h"
#include "hbtrie.h"
#include "docio.h"
#include "btreeblock.h"
#include "common.h"
#include "wal.h"
#include "avltree.h"
#include "list.h"
#include "internal_types.h"
#include "btree_var_kv_ops.h"
#include "timing.h"

#include "memleak.h"

#ifdef __DEBUG
#ifndef __DEBUG_FDB
    #undef DBG
    #undef DBGCMD
    #undef DBGSW
    #define DBG(...)
    #define DBGCMD(...)
    #define DBGSW(n, ...)
#endif
#endif

// lexicographically compares two variable-length binary streams
static int _fdb_keycmp(void *key1, size_t keylen1, void *key2, size_t keylen2)
{
    if (keylen1 == keylen2) {
        return memcmp(key1, key2, keylen1);
    }else {
        size_t len = MIN(keylen1, keylen2);
        int cmp = memcmp(key1, key2, len);
        if (cmp != 0) return cmp;
        else {
            return (int)((int)keylen1 - (int)keylen2);
        }
    }
}

static int _fdb_key_cmp(fdb_iterator *iterator, void *key1, size_t keylen1,
                        void *key2, size_t keylen2) {
    int cmp;
    if (iterator->handle->kvs_config.custom_cmp) {
        // custom compare function for variable length key
        if (iterator->handle->kvs) {
            // multi KV instance mode
            // KV ID should be compared separately
            size_t size_chunk = iterator->handle->config.chunksize;
            fdb_kvs_id_t a_id, b_id;
            buf2kvid(size_chunk, key1, &a_id);
            buf2kvid(size_chunk, key2, &b_id);

            if (a_id < b_id) {
                cmp = -1;
            } else if (a_id > b_id) {
                cmp = 1;
            } else {
                if (keylen1 == size_chunk) { // key1 < key2
                    return -1;
                } else if (keylen2 == size_chunk) { // key1 > key2
                    return 1;
                }
                cmp = iterator->handle->kvs_config.custom_cmp(
                          (uint8_t*)key1 + size_chunk, keylen1 - size_chunk,
                          (uint8_t*)key2 + size_chunk, keylen2 - size_chunk);
            }
        } else {
            cmp = iterator->handle->kvs_config.custom_cmp(key1, keylen1,
                                                       key2, keylen2);
        }
    } else {
        cmp = _fdb_keycmp(key1, keylen1, key2, keylen2);
    }
    return cmp;
}

LIBFDB_API
fdb_status fdb_iterator_init(fdb_kvs_handle *handle,
                             fdb_iterator **ptr_iterator,
                             const void *start_key,
                             size_t start_keylen,
                             const void *end_key,
                             size_t end_keylen,
                             fdb_iterator_opt_t opt)
{
    if (!handle) {
        return FDB_RESULT_INVALID_HANDLE;
    }

    if (start_keylen > FDB_MAX_KEYLEN ||
        (handle->kvs_config.custom_cmp &&
           (start_keylen > handle->config.blocksize - HBTRIE_HEADROOM ||
            end_keylen > handle->config.blocksize - HBTRIE_HEADROOM)) ||
        end_keylen > FDB_MAX_KEYLEN) {
        return FDB_RESULT_INVALID_ARGS;
    }

    if ((opt & FDB_ITR_SKIP_MIN_KEY && (!start_key || !start_keylen)) ||
        (opt & FDB_ITR_SKIP_MAX_KEY && (!end_key || !end_keylen))) {
        return FDB_RESULT_INVALID_ARGS;
    }

    hbtrie_result hr;
    fdb_status fs;
    LATENCY_STAT_START();

    if (!handle->shandle) {
        // If compaction is already done before this line,
        // handle->file needs to be replaced with handle->new_file.
        fdb_check_file_reopen(handle, NULL);
        fdb_sync_db_header(handle);
    }

    fdb_iterator *iterator = (fdb_iterator *)calloc(1, sizeof(fdb_iterator));

    if (!handle->shandle) {
        // snapshot handle doesn't exist
        // open a new handle to make the iterator handle as a snapshot
        fs = fdb_snapshot_open(handle, &iterator->handle, FDB_SNAPSHOT_INMEM);
        if (fs != FDB_RESULT_SUCCESS) {
            fdb_log(&handle->log_callback, fs,
                    "Failed to create an iterator instance due to the failure of "
                    "open operation on the KV Store '%s' in a database file '%s'",
                    _fdb_kvs_get_name(handle, handle->file),
                    handle->file->filename);
            return fs;
        }
        iterator->snapshot_handle = false;
    } else {
        // Snapshot handle exists
        // We don't need to open a new handle.. just point to the snapshot handle.
        iterator->handle = handle;
        iterator->snapshot_handle = true;
    }
    iterator->opt = opt;

    iterator->_key = (void*)malloc(FDB_MAX_KEYLEN_INTERNAL);
    // set to zero the first <chunksize> bytes
    memset(iterator->_key, 0x0, iterator->handle->config.chunksize);
    iterator->_keylen = 0;
    iterator->_offset = BLK_NOT_FOUND;
    iterator->hbtrie_iterator = NULL;
    iterator->seqtree_iterator = NULL;
    iterator->seqtrie_iterator = NULL;

    if (iterator->handle->kvs) {
        // multi KV instance mode .. prepend KV ID
        size_t size_chunk = handle->config.chunksize;
        uint8_t *start_key_temp, *end_key_temp;

        if (start_key == NULL) {
            start_key_temp = alca(uint8_t, size_chunk);
            kvid2buf(size_chunk, iterator->handle->kvs->id, start_key_temp);
            start_key = start_key_temp;
            start_keylen = size_chunk;
        } else {
            start_key_temp = alca(uint8_t, size_chunk + start_keylen);
            kvid2buf(size_chunk, iterator->handle->kvs->id, start_key_temp);
            memcpy(start_key_temp + size_chunk, start_key, start_keylen);
            start_key = start_key_temp;
            start_keylen += size_chunk;
        }

        if (end_key == NULL) {
            // set end_key as NULL key of the next KV ID.
            // NULL key doesn't actually exist so that the iterator ends
            // at the last key of the current KV ID.
            end_key_temp = alca(uint8_t, size_chunk);
            kvid2buf(size_chunk, iterator->handle->kvs->id+1, end_key_temp);
            end_key = end_key_temp;
            end_keylen = size_chunk;
        } else {
            end_key_temp = alca(uint8_t, size_chunk + end_keylen);
            kvid2buf(size_chunk, iterator->handle->kvs->id, end_key_temp);
            memcpy(end_key_temp + size_chunk, end_key, end_keylen);
            end_key = end_key_temp;
            end_keylen += size_chunk;
        }

        iterator->start_key = (void*)malloc(start_keylen);
        memcpy(iterator->start_key, start_key, start_keylen);
        iterator->start_keylen = start_keylen;

        iterator->end_key = (void*)malloc(end_keylen);
        memcpy(iterator->end_key, end_key, end_keylen);
        iterator->end_keylen = end_keylen;

    } else { // single KV instance mode
        if (start_key == NULL) {
            iterator->start_key = NULL;
            iterator->start_keylen = 0;
        } else {
            iterator->start_key = (void*)malloc(start_keylen);
            memcpy(iterator->start_key, start_key, start_keylen);
            iterator->start_keylen = start_keylen;
        }

        if (end_key == NULL) {
            iterator->end_key = NULL;
            end_keylen = 0;
        }else{
            iterator->end_key = (void*)malloc(end_keylen);
            memcpy(iterator->end_key, end_key, end_keylen);
        }
        iterator->end_keylen = end_keylen;
    }

    // create an iterator handle for hb-trie
    iterator->hbtrie_iterator = (struct hbtrie_iterator *)
                                malloc(sizeof(struct hbtrie_iterator));
    hr = hbtrie_iterator_init(iterator->handle->trie,
                              iterator->hbtrie_iterator,
                              (void *)start_key, start_keylen);
    assert(hr == HBTRIE_RESULT_SUCCESS);

    wal_itr_init(iterator->handle->file, iterator->handle->shandle, true,
                 &iterator->wal_itr);

    if (start_key) {
        struct wal_item query;
        struct wal_item_header query_key;
        query.header = &query_key;
        query_key.key = iterator->start_key;
        query_key.keylen = iterator->start_keylen;
        iterator->tree_cursor = wal_itr_search_greater(iterator->wal_itr,
                                                       &query);
    } else {
        iterator->tree_cursor = wal_itr_first(iterator->wal_itr);
    }
    // to know reverse iteration endpoint store the start cursor
    if (iterator->tree_cursor) {
        iterator->tree_cursor_start = iterator->tree_cursor;
    }
    iterator->tree_cursor_prev = iterator->tree_cursor;
    iterator->direction = FDB_ITR_DIR_NONE;
    iterator->status = FDB_ITR_IDX;
    iterator->_dhandle = NULL; // populated at the first iterator movement

    *ptr_iterator = iterator;

    ++iterator->handle->num_iterators; // Increment the iterator counter of the KV handle
    fdb_iterator_next(iterator); // position cursor at first key

    LATENCY_STAT_END(iterator->handle->file, FDB_LATENCY_ITR_INIT);

    return FDB_RESULT_SUCCESS;
}

LIBFDB_API
fdb_status fdb_iterator_sequence_init(fdb_kvs_handle *handle,
                                      fdb_iterator **ptr_iterator,
                                      const fdb_seqnum_t start_seq,
                                      const fdb_seqnum_t end_seq,
                                      fdb_iterator_opt_t opt)
{
    if (!handle) {
        return FDB_RESULT_INVALID_HANDLE;
    }

    if (ptr_iterator == NULL || (end_seq && start_seq > end_seq)) {
        return FDB_RESULT_INVALID_ARGS;
    }

    fdb_status fs;
    fdb_seqnum_t _start_seq = _endian_encode(start_seq);
    fdb_kvs_id_t _kv_id;
    size_t size_id, size_seq;
    uint8_t *start_seq_kv;
    struct wal_item query;
    struct wal_item_header query_key;
    LATENCY_STAT_START();

    query.header = &query_key;

    // Sequence trees are a must for byseq operations
    if (handle->config.seqtree_opt != FDB_SEQTREE_USE) {
        return FDB_RESULT_INVALID_CONFIG;
    }

    if (!handle->shandle) {
        // If compaction is already done before this line,
        // handle->file needs to be replaced with handle->new_file.
        fdb_check_file_reopen(handle, NULL);
        fdb_sync_db_header(handle);
    }

    size_id = sizeof(fdb_kvs_id_t);
    size_seq = sizeof(fdb_seqnum_t);
    fdb_iterator *iterator = (fdb_iterator *)calloc(1, sizeof(fdb_iterator));

    if (!handle->shandle) {
        // snapshot handle doesn't exist
        // open a new handle to make the iterator handle as a snapshot
        fs = fdb_snapshot_open(handle, &iterator->handle, FDB_SNAPSHOT_INMEM);
        if (fs != FDB_RESULT_SUCCESS) {
            fdb_log(&handle->log_callback, fs,
                    "Failed to create an sequence iterator instance due to the "
                    "failure of "
                    "open operation on the KV Store '%s' in a database file '%s'",
                    _fdb_kvs_get_name(handle, handle->file),
                    handle->file->filename);
            return fs;
        }
        iterator->snapshot_handle = false;
    } else {
        // Snapshot handle exists
        // We don't need to open a new handle.. just point to the snapshot handle.
        iterator->handle = handle;
        iterator->snapshot_handle = true;
    }

    iterator->hbtrie_iterator = NULL;
    iterator->_key = NULL;
    iterator->_keylen = 0;
    iterator->opt = opt;
    iterator->_offset = BLK_NOT_FOUND;
    iterator->_seqnum = start_seq;

    // For easy API call, treat zero seq as 0xffff...
    // (because zero seq number is not used)
    if (end_seq == 0) {
        iterator->end_seqnum = SEQNUM_NOT_USED;
    } else {
        iterator->end_seqnum = end_seq;
    }

    iterator->start_seqnum = start_seq;

    iterator->start_key = NULL;
    iterator->end_key = NULL;

    wal_itr_init(handle->file, iterator->handle->shandle, false,
                 &iterator->wal_itr);

    if (iterator->handle->kvs) {
        int size_chunk = handle->config.chunksize;
        // create an iterator handle for hb-trie
        start_seq_kv = alca(uint8_t, size_chunk + size_seq);
        _kv_id = _endian_encode(iterator->handle->kvs->id);
        memcpy(start_seq_kv, &_kv_id, size_id);
        memcpy(start_seq_kv + size_id, &_start_seq, size_seq);

        iterator->seqtrie_iterator = (struct hbtrie_iterator *)
                                     calloc(1, sizeof(struct hbtrie_iterator));
        hbtrie_iterator_init(iterator->handle->seqtrie,
                             iterator->seqtrie_iterator,
                             start_seq_kv, size_id + size_seq);

        query_key.key = start_seq_kv;
        kvid2buf(size_chunk, iterator->handle->kvs->id, start_seq_kv);
        memcpy(start_seq_kv + size_chunk, &start_seq, size_seq);
        query_key.keylen = size_chunk + size_seq;
        query.seqnum = start_seq;
        iterator->tree_cursor = wal_itr_search_greater(iterator->wal_itr,
                                                       &query);
    } else {
        // create an iterator handle for b-tree
        iterator->seqtree_iterator = (struct btree_iterator *)
                                     calloc(1, sizeof(struct btree_iterator));
        btree_iterator_init(iterator->handle->seqtree,
                            iterator->seqtree_iterator,
                            (void *)(start_seq ? &_start_seq : NULL));
        query_key.key = (void*)NULL;
        query_key.keylen = 0;
        query.seqnum = start_seq;
        iterator->tree_cursor = wal_itr_search_greater(iterator->wal_itr,
                                                       &query);
    }

    // to know reverse iteration endpoint store the start cursor
    if (iterator->tree_cursor) {
        iterator->tree_cursor_start = iterator->tree_cursor;
    }
    iterator->tree_cursor_prev = iterator->tree_cursor;
    iterator->direction = FDB_ITR_DIR_NONE;
    iterator->status = FDB_ITR_IDX;
    iterator->_dhandle = NULL; // populated at the first iterator movement

    *ptr_iterator = iterator;

    ++iterator->handle->num_iterators; // Increment the iterator counter of the KV handle
    fdb_iterator_next(iterator); // position cursor at first key

    LATENCY_STAT_END(iterator->handle->file, FDB_LATENCY_ITR_SEQ_INIT);

    return FDB_RESULT_SUCCESS;
}

static fdb_status _fdb_iterator_prev(fdb_iterator *iterator)
{
    int cmp;
    void *key;
    size_t keylen;
    uint64_t offset;
    hbtrie_result hr = HBTRIE_RESULT_SUCCESS;
    struct docio_handle *dhandle;
    struct wal_item *snap_item = NULL;

    if (iterator->direction != FDB_ITR_REVERSE) {
        iterator->_offset = BLK_NOT_FOUND; // need to re-examine Trie/trees
        if (iterator->tree_cursor) {
            // just turn around
            // WAL:   0  v  2->   4    (OLD state)
            // TRIE:     1  2  3  4
            iterator->tree_cursor = wal_itr_search_smaller(iterator->wal_itr,
                                                  iterator->tree_cursor);
            if (iterator->direction == FDB_ITR_FORWARD &&
                iterator->status != FDB_ITR_WAL) {
                iterator->tree_cursor = wal_itr_prev(iterator->wal_itr);
            }
            // WAL: <-0  v  2     4    (NEW state)
            // TRIE:  0  1  2  3  4
        } else if (iterator->tree_cursor_prev) { // gone past the end..
            iterator->tree_cursor = wal_itr_search_smaller(iterator->wal_itr,
                                             iterator->tree_cursor_prev);
            iterator->status = FDB_ITR_IDX;
        } // else Don't move - seek()/init() has already positioned cursor
    }
start:
    key = iterator->_key;
    dhandle = iterator->handle->dhandle;

    // retrieve from hb-trie
    if (iterator->_offset == BLK_NOT_FOUND) {
        // no key waiting for being returned
        // get next key from hb-trie (or idtree)
        struct docio_object _doc;
        // Move Main index Cursor backward...
        int64_t _offset;
        do {
            hr = hbtrie_prev(iterator->hbtrie_iterator, key,
                             &iterator->_keylen, (void*)&iterator->_offset);
            btreeblk_end(iterator->handle->bhandle);
            iterator->_offset = _endian_decode(iterator->_offset);
            if (!(iterator->opt & FDB_ITR_NO_DELETES) ||
                  hr != HBTRIE_RESULT_SUCCESS) {
                break;
            }
            // deletion check
            memset(&_doc, 0x0, sizeof(struct docio_object));
            _offset = docio_read_doc_key_meta(dhandle, iterator->_offset,
                                              &_doc, true);
            if (_offset <= 0) { // read fail
                continue; // get prev doc
            }
            if (_doc.length.flag & DOCIO_DELETED) { // deleted doc
                free(_doc.key);
                free(_doc.meta);
                continue; // get prev doc
            }
            free(_doc.key);
            free(_doc.meta);
            break;
        } while (1);
    }
    keylen = iterator->_keylen;
    offset = iterator->_offset;

    if (hr != HBTRIE_RESULT_SUCCESS && !iterator->tree_cursor) {
        return FDB_RESULT_ITERATOR_FAIL;
    }

    // Move the WAL cursor backward...
    while (iterator->tree_cursor) {
        if (iterator->status == FDB_ITR_WAL) {
            iterator->tree_cursor_prev = iterator->tree_cursor;
            iterator->tree_cursor = wal_itr_prev(iterator->wal_itr);
        }// else don't move - seek()/ init() has already positioned cursor

        // get the current item of avl-tree
        snap_item = iterator->tree_cursor;
        if (!snap_item) {
            if (hr == HBTRIE_RESULT_SUCCESS) {
                break;
            } else {
                return FDB_RESULT_ITERATOR_FAIL;
            }
        }
        if (hr == HBTRIE_RESULT_SUCCESS) {
            cmp = _fdb_key_cmp(iterator, snap_item->header->key,
                               snap_item->header->keylen,
                               key, keylen);
        } else {
            // no more docs in hb-trie
            cmp = 1;
        }

        if (cmp >= 0) {
            // key[WAL] >= key[hb-trie] .. take key[WAL] first
            uint8_t drop_logical_deletes =
                (snap_item->action == WAL_ACT_LOGICAL_REMOVE) &&
                (iterator->opt & FDB_ITR_NO_DELETES);
            iterator->status = FDB_ITR_WAL;
            if (cmp > 0) {
                if (snap_item->action == WAL_ACT_REMOVE ||
                    drop_logical_deletes) {
                    // this key is removed .. get prev key[WAL]
                    continue;
                }
            } else { // same key found in WAL
                iterator->_offset = BLK_NOT_FOUND; // drop key from trie
                if (snap_item->action == WAL_ACT_REMOVE || drop_logical_deletes) {
                    // the key is removed .. start over again
                    goto start;
                }
            }

            key = snap_item->header->key;
            keylen = snap_item->header->keylen;
            // key[hb-trie] is stashed in iterator->_key for future call
            offset = snap_item->offset;
        }
        break;
    }

    if (offset == iterator->_offset) {
        // take key[hb-trie] & and fetch the prev key[hb-trie] at next turn
        iterator->_offset = BLK_NOT_FOUND;
        iterator->status = FDB_ITR_IDX;
    }

    if (iterator->start_key) {
        cmp = _fdb_key_cmp(iterator, iterator->start_key,
                           iterator->start_keylen, key, keylen);

        if ((cmp == 0 && iterator->opt & FDB_ITR_SKIP_MIN_KEY) || cmp > 0) {
            // current key (KEY) is lexicographically less than START_KEY
            // OR it is the start key and user wishes to skip it..
            // terminate the iteration
            return FDB_RESULT_ITERATOR_FAIL;
        }
    }

    if (iterator->end_key) {
        cmp = _fdb_key_cmp(iterator, iterator->end_key,
                           iterator->end_keylen, key, keylen);

        if ((cmp == 0 && iterator->opt & FDB_ITR_SKIP_MAX_KEY) || cmp < 0) {
            // key is the end_key but users wishes to skip it, redo..
            // OR current key (KEY) is lexicographically greater than END_KEY
            goto start;
        }
    }

    iterator->_dhandle = dhandle; // store for fdb_iterator_get()
    iterator->_get_offset = offset; // store for fdb_iterator_get()

    return FDB_RESULT_SUCCESS;
}

static fdb_status _fdb_iterator_next(fdb_iterator *iterator)
{
    int cmp;
    void *key;
    size_t keylen;
    uint64_t offset;
    hbtrie_result hr = HBTRIE_RESULT_SUCCESS;
    struct docio_handle *dhandle;
    struct wal_item *snap_item = NULL;

    if (iterator->direction != FDB_ITR_FORWARD) {
        iterator->_offset = BLK_NOT_FOUND; // need to re-examine Trie/trees
        // just turn around and face forward..
        if (iterator->tree_cursor) {
            // WAL: <-0  v  2     4    (OLD state)
            // TRIE:     1  2  3  4
            iterator->tree_cursor = wal_itr_search_greater(iterator->wal_itr,
                                                  iterator->tree_cursor);
            if (iterator->direction == FDB_ITR_REVERSE &&
                iterator->status != FDB_ITR_WAL) {
                iterator->tree_cursor = wal_itr_next(iterator->wal_itr);
            }
            // WAL:   0  v  2->   4    (NEW state)
            // TRIE:  0  1  2  3  4
        } else if (iterator->tree_cursor_prev) {
            iterator->tree_cursor = wal_itr_search_greater(iterator->wal_itr,
                                             iterator->tree_cursor_prev);
            iterator->status = FDB_ITR_IDX;
        } // else Don't move - seek()/init() has already positioned cursor
    }

start:
    key = iterator->_key;
    dhandle = iterator->handle->dhandle;

    // retrieve from hb-trie
    if (iterator->_offset == BLK_NOT_FOUND) {
        // no key waiting for being returned
        // get next key from hb-trie (or idtree)
        struct docio_object _doc;
        // Move Main index Cursor forward...
        int64_t _offset;
        do {
            hr = hbtrie_next(iterator->hbtrie_iterator, key,
                             &iterator->_keylen, (void*)&iterator->_offset);
            btreeblk_end(iterator->handle->bhandle);
            iterator->_offset = _endian_decode(iterator->_offset);
            if (!(iterator->opt & FDB_ITR_NO_DELETES) ||
                  hr != HBTRIE_RESULT_SUCCESS) {
                break;
            }
            // deletion check
            memset(&_doc, 0x0, sizeof(struct docio_object));
            _offset = docio_read_doc_key_meta(dhandle, iterator->_offset, &_doc,
                                              true);
            if (_offset <= 0) { // read fail
                continue; // get next doc
            }
            if (_doc.length.flag & DOCIO_DELETED) { // deleted doc
                free(_doc.key);
                free(_doc.meta);
                continue; // get next doc
            }
            free(_doc.key);
            free(_doc.meta);
            break;
        } while (1);
    }

    keylen = iterator->_keylen;
    offset = iterator->_offset;

    if (hr != HBTRIE_RESULT_SUCCESS && iterator->tree_cursor == NULL) {
        return FDB_RESULT_ITERATOR_FAIL;
    }

    // Move WAL Cursor forward...
    while (iterator->tree_cursor) {
        if (iterator->status == FDB_ITR_WAL) {
            iterator->tree_cursor_prev = iterator->tree_cursor;
            iterator->tree_cursor = wal_itr_next(iterator->wal_itr);
        } // else Don't move - seek()/ init() has already positioned cursor
        snap_item = iterator->tree_cursor;
        if (!snap_item) {
            if (hr == HBTRIE_RESULT_SUCCESS) {
                break;
            } else { // no more keys in WAL or main index
                return FDB_RESULT_ITERATOR_FAIL;
            }
        }
        // Compare key[WAL] with key[hb-trie]
        if (hr == HBTRIE_RESULT_SUCCESS) {
            cmp = _fdb_key_cmp(iterator, snap_item->header->key,
                               snap_item->header->keylen,
                               key, keylen);
        } else {
            // no more docs in hb-trie
            cmp = -1;
        }

        if (cmp <= 0) {
            // key[WAL] <= key[hb-trie] .. take key[WAL] first
            uint8_t drop_logical_deletes =
                (snap_item->action == WAL_ACT_LOGICAL_REMOVE) &&
                (iterator->opt & FDB_ITR_NO_DELETES);
            iterator->status = FDB_ITR_WAL;
            if (cmp < 0) {
                if (snap_item->action == WAL_ACT_REMOVE ||
                    drop_logical_deletes) {
                    // this key is removed .. get next key[WAL]
                    continue;
                }
            } else { // Same key from trie also found from WAL
                iterator->_offset = BLK_NOT_FOUND; // drop key from trie
                if (snap_item->action == WAL_ACT_REMOVE || drop_logical_deletes) {
                    // the key is removed .. start over again
                    goto start;
                }
            }
            key = snap_item->header->key;
            keylen = snap_item->header->keylen;
            // key[hb-trie] is stashed in iterator->key for next call
            offset = snap_item->offset;
        }
        break;
    }

    if (offset == iterator->_offset) {
        // take key[hb-trie] & and fetch the next key[hb-trie] at next turn
        iterator->_offset = BLK_NOT_FOUND;
        iterator->status = FDB_ITR_IDX;
    }

    if (iterator->start_key) {
        cmp = _fdb_key_cmp(iterator, iterator->start_key,
                           iterator->start_keylen, key, keylen);

        if ((cmp == 0 && iterator->opt & FDB_ITR_SKIP_MIN_KEY) || cmp > 0) {
            // If user wishes to skip start key, redo first step
            // OR current key (KEY) is lexicographically smaller than START_KEY
            goto start;
        }
    }

    if (iterator->end_key) {
        cmp = _fdb_key_cmp(iterator, iterator->end_key, iterator->end_keylen,
                           key, keylen);
        if ((cmp == 0 && iterator->opt & FDB_ITR_SKIP_MAX_KEY) || cmp < 0) {
            // current key (KEY) is lexicographically greater than END_KEY
            // OR it is the end_key and user wishes to skip it
            // terminate the iteration
            return FDB_RESULT_ITERATOR_FAIL;
        }
    }

    iterator->_dhandle = dhandle; // store for fdb_iterator_get()
    iterator->_get_offset = offset; // store for fdb_iterator_get()

    return FDB_RESULT_SUCCESS;
}

static
bool _validate_range_limits(fdb_iterator *iterator,
                            void *ret_key,
                            const size_t ret_keylen)
{
    int cmp;
    if (iterator->end_key) {
        cmp = _fdb_key_cmp(iterator, ret_key, ret_keylen,
                iterator->end_key, iterator->end_keylen);
        if ((cmp == 0 && iterator->opt & FDB_ITR_SKIP_MAX_KEY) ||
                cmp > 0) { // greater than end_key OR at skipped MAX_KEY
            return false;
        }
    }
    if (iterator->start_key) {
        cmp = _fdb_key_cmp(iterator, ret_key, ret_keylen,
                iterator->start_key, iterator->start_keylen);
        if ((cmp == 0 && iterator->opt & FDB_ITR_SKIP_MIN_KEY) ||
                cmp < 0) { // smaller than start_key OR at skipped MIN_KEY
            return false;
        }
    }
    return true;
}

LIBFDB_API
fdb_status fdb_iterator_seek(fdb_iterator *iterator,
                             const void *seek_key,
                             const size_t seek_keylen,
                             const fdb_iterator_seek_opt_t seek_pref)
{
    if (!iterator || !iterator->handle) {
        return FDB_RESULT_INVALID_HANDLE;
    }

    int cmp, cmp2; // intermediate results of comparison
    int next_op = 0; // 0: none, -1: prev(), 1: next();
    int size_chunk = iterator->handle->config.chunksize;
    uint8_t *seek_key_kv;
    int64_t _offset;
    size_t seek_keylen_kv;
    bool skip_wal = false, fetch_next = true, fetch_wal = true;
    hbtrie_result hr = HBTRIE_RESULT_SUCCESS;
    struct wal_item *snap_item = NULL, query;
    struct wal_item_header query_header;
    struct docio_object _doc;
    fdb_status ret;
    LATENCY_STAT_START();

    iterator->_dhandle = NULL; // setup for get() to return FAIL

    if (!seek_key || !iterator->_key ||
        seek_keylen > FDB_MAX_KEYLEN ||
        (iterator->handle->kvs_config.custom_cmp &&
         seek_keylen > iterator->handle->config.blocksize - HBTRIE_HEADROOM)) {
        return FDB_RESULT_INVALID_ARGS;
    }

    if (!atomic_cas_uint8_t(&iterator->handle->handle_busy, 0, 1)) {
        return FDB_RESULT_HANDLE_BUSY;
    }

    atomic_incr_uint64_t(&iterator->handle->op_stats->num_iterator_moves,
                         std::memory_order_relaxed);

    if (iterator->handle->kvs) {
        seek_keylen_kv = seek_keylen + size_chunk;
        seek_key_kv = alca(uint8_t, seek_keylen_kv);
        kvid2buf(size_chunk, iterator->handle->kvs->id, seek_key_kv);
        memcpy(seek_key_kv + size_chunk, seek_key, seek_keylen);
    } else {
        seek_keylen_kv = seek_keylen;
        seek_key_kv = (uint8_t*)seek_key;
    }

    // disable seeking beyond the end key...
    if (iterator->end_key) {
        cmp = _fdb_key_cmp(iterator, (void *)iterator->end_key,
                                    iterator->end_keylen,
                                    (void *)seek_key_kv, seek_keylen_kv);
        if (cmp == 0 && iterator->opt & FDB_ITR_SKIP_MAX_KEY) {
            // seek the end key at this time,
            // and call prev() next.
            next_op = -1;
        }
        if (cmp < 0) {
            atomic_cas_uint8_t(&iterator->handle->handle_busy, 1, 0);
            return FDB_RESULT_ITERATOR_FAIL;
        }
    }

    // disable seeking beyond the start key...
    if (iterator->start_key) {
        cmp = _fdb_key_cmp(iterator,
                                  (void *)iterator->start_key,
                                  iterator->start_keylen,
                                  (void *)seek_key_kv, seek_keylen_kv);
        if (cmp == 0 && iterator->opt & FDB_ITR_SKIP_MIN_KEY) {
            // seek the start key at this time,
            // and call next() next.
            next_op = 1;
        }
        if (cmp > 0) {
            atomic_cas_uint8_t(&iterator->handle->handle_busy, 1, 0);
            return FDB_RESULT_ITERATOR_FAIL;
        }
    }

    iterator->direction = FDB_ITR_FORWARD;

    // reset HB+trie's iterator
    hbtrie_iterator_free(iterator->hbtrie_iterator);
    hbtrie_iterator_init(iterator->handle->trie, iterator->hbtrie_iterator,
                         seek_key_kv, seek_keylen_kv);

fetch_hbtrie:
    if (seek_pref == FDB_ITR_SEEK_HIGHER) {
        // fetch next key
        hr = hbtrie_next(iterator->hbtrie_iterator, iterator->_key,
                         &iterator->_keylen, (void*)&iterator->_offset);
        btreeblk_end(iterator->handle->bhandle);

        if (hr == HBTRIE_RESULT_SUCCESS) {
            cmp = _fdb_key_cmp(iterator,
                               iterator->_key, iterator->_keylen,
                               seek_key_kv, seek_keylen_kv);
            if (cmp < 0) {
                // key[HB+trie] < seek_key .. move forward
                hr = hbtrie_next(iterator->hbtrie_iterator, iterator->_key,
                                 &iterator->_keylen, (void*)&iterator->_offset);
                btreeblk_end(iterator->handle->bhandle);
            }
            iterator->_offset = _endian_decode(iterator->_offset);

            while (iterator->opt & FDB_ITR_NO_DELETES &&
                   hr == HBTRIE_RESULT_SUCCESS        &&
                   fetch_next) {
                fetch_next = false;
                memset(&_doc, 0x0, sizeof(struct docio_object));
                _offset = docio_read_doc_key_meta(iterator->handle->dhandle,
                                                  iterator->_offset, &_doc,
                                                  true);
                if (_offset <= 0) { // read fail
                    fetch_next = true; // get next
                } else if (_doc.length.flag & DOCIO_DELETED) { // deleted doc
                    free(_doc.key);
                    free(_doc.meta);
                    fetch_next = true; // get next
                } else {
                    free(_doc.key);
                    free(_doc.meta);
                }
                if (fetch_next) {
                    hr = hbtrie_next(iterator->hbtrie_iterator, iterator->_key,
                                     &iterator->_keylen,
                                     (void*)&iterator->_offset);
                    btreeblk_end(iterator->handle->bhandle);
                    iterator->_offset = _endian_decode(iterator->_offset);
                }
            }
        }
    } else {
        // fetch prev key
        hr = hbtrie_prev(iterator->hbtrie_iterator, iterator->_key,
                         &iterator->_keylen, (void*)&iterator->_offset);
        btreeblk_end(iterator->handle->bhandle);
        if (hr == HBTRIE_RESULT_SUCCESS) {
            cmp = _fdb_key_cmp(iterator,
                               iterator->_key, iterator->_keylen,
                               seek_key_kv, seek_keylen_kv);
            if (cmp > 0) {
                // key[HB+trie] > seek_key .. move backward
                hr = hbtrie_prev(iterator->hbtrie_iterator, iterator->_key,
                                 &iterator->_keylen, (void*)&iterator->_offset);
                btreeblk_end(iterator->handle->bhandle);
            }
            iterator->_offset = _endian_decode(iterator->_offset);

            while (iterator->opt & FDB_ITR_NO_DELETES &&
                   hr == HBTRIE_RESULT_SUCCESS        &&
                   fetch_next) {
                fetch_next = false;
                memset(&_doc, 0x0, sizeof(struct docio_object));
                _offset = docio_read_doc_key_meta(iterator->handle->dhandle,
                                                  iterator->_offset, &_doc,
                                                  true);
                if (_offset <= 0) { // read fail
                    fetch_next = true; // get prev
                } else if (_doc.length.flag & DOCIO_DELETED) { // deleted doc
                    free(_doc.key);
                    free(_doc.meta);
                    fetch_next = true; // get prev
                } else {
                    free(_doc.key);
                    free(_doc.meta);
                }
                if (fetch_next) {
                    hr = hbtrie_prev(iterator->hbtrie_iterator, iterator->_key,
                                     &iterator->_keylen,
                                     (void*)&iterator->_offset);
                    btreeblk_end(iterator->handle->bhandle);
                    iterator->_offset = _endian_decode(iterator->_offset);
                }
            }
        }
    }

    if (hr == HBTRIE_RESULT_SUCCESS && // Validate iteration range limits..
        !next_op) { // only if caller is not seek_to_max/min (handled later)
        if (!_validate_range_limits(iterator, iterator->_key, iterator->_keylen)) {
            hr = HBTRIE_RESULT_FAIL;
        }
    }

    if (iterator->handle->kvs) {
        fdb_kvs_id_t kv_id;
        buf2kvid(size_chunk, iterator->_key, &kv_id);
        if (iterator->handle->kvs->id != kv_id) {
            // seek is done beyond the KV ID
            hr = HBTRIE_RESULT_FAIL;
        }
    }
    if (hr == HBTRIE_RESULT_SUCCESS) {
        iterator->_get_offset = iterator->_offset;
        iterator->_dhandle = iterator->handle->dhandle;
    } else {
        // larger than the largest key or smaller than the smallest key
        iterator->_get_offset = BLK_NOT_FOUND;
        iterator->_dhandle = NULL;
    }

    // HB+trie's iterator should fetch another entry next time
    iterator->_offset = BLK_NOT_FOUND;
    iterator->status = FDB_ITR_IDX;

    // retrieve avl-tree
    query.header = &query_header;
    query_header.key = seek_key_kv;
    query_header.keylen = seek_keylen_kv;

    if (seek_pref == FDB_ITR_SEEK_HIGHER) {
        if (fetch_wal) {
            iterator->tree_cursor = wal_itr_search_greater(iterator->wal_itr,
                                                           &query);
            iterator->direction = FDB_ITR_FORWARD;
        }
        if (iterator->tree_cursor) {
            // skip deleted WAL entry
            do {
                if (!next_op && // only validate range if not skip max/min key mode
                    !_validate_range_limits(iterator,
                                            iterator->tree_cursor->header->key,
                                            iterator->tree_cursor->header->keylen)) {
                    iterator->tree_cursor = NULL;
                    break;
                }
                snap_item = iterator->tree_cursor;
                if ((snap_item->action == WAL_ACT_LOGICAL_REMOVE && // skip
                    iterator->opt & FDB_ITR_NO_DELETES) || //logical delete OR
                    snap_item->action == WAL_ACT_REMOVE) { // immediate purge
                    if (iterator->_dhandle) {
                        cmp = _fdb_key_cmp(iterator,
                                           snap_item->header->key,
                                           snap_item->header->keylen,
                                           iterator->_key, iterator->_keylen);
                        if (cmp == 0) {
                            // same doc exists in HB+trie
                            // move tree cursor
                            iterator->tree_cursor = wal_itr_next(
                                                     iterator->wal_itr);
                            // do not move tree cursor next time
                            fetch_wal = false;
                            // fetch next key[HB+trie]
                            goto fetch_hbtrie;
                        } else if (cmp > 0) {
                            break;
                        }
                    }
                    iterator->tree_cursor = wal_itr_next(iterator->wal_itr);
                    continue;
                } else if (iterator->end_key &&
                           iterator->opt & FDB_ITR_SKIP_MAX_KEY) {
                    cmp = _fdb_key_cmp(iterator,
                                       iterator->end_key, iterator->end_keylen,
                                       snap_item->header->key,
                                       snap_item->header->keylen);
                    if (cmp == 0 ||
                        // WAL cursor is positioned exactly at seeked end key
                        // but iterator must skip the end key!
                        // If hb+trie has an item, use that else return FAIL
                        (cmp < 0 &&// WAL key out of range...
                        !next_op)) { // Not called from fdb_iterator_seek_to_max
                        skip_wal = true;
                        iterator->status = FDB_ITR_WAL;
                    }
                }
                break;
            } while(iterator->tree_cursor);
        }
        iterator->tree_cursor_prev = iterator->tree_cursor;
        if (!iterator->tree_cursor) {
            // seek_key is larger than the largest key
            // set prev key to the largest key.
            // if prev operation is called next, tree_cursor will be set to
            // tree_cursor_prev.
            iterator->tree_cursor_prev = wal_itr_search_smaller(iterator->wal_itr,
                                                                &query);
            skip_wal = true;
        }
    } else if (seek_pref == FDB_ITR_SEEK_LOWER) {
        if (fetch_wal) {
            iterator->tree_cursor = wal_itr_search_smaller(iterator->wal_itr,
                                                           &query);
            iterator->direction = FDB_ITR_REVERSE;
        }
        if (iterator->tree_cursor) {
            // skip deleted WAL entry
            do {
                if (!next_op && // only validate range if not skip max/min key mode
                    !_validate_range_limits(iterator,
                                            iterator->tree_cursor->header->key,
                                            iterator->tree_cursor->header->keylen)) {
                    iterator->tree_cursor = NULL;
                    break;
                }
                snap_item = iterator->tree_cursor;
                if ((snap_item->action == WAL_ACT_LOGICAL_REMOVE && // skip
                     iterator->opt & FDB_ITR_NO_DELETES) || //logical delete OR
                     snap_item->action == WAL_ACT_REMOVE) { //immediate purge
                    if (iterator->_dhandle) {
                        cmp = _fdb_key_cmp(iterator,
                                           snap_item->header->key,
                                           snap_item->header->keylen,
                                           iterator->_key, iterator->_keylen);
                        if (cmp == 0) {
                            // same doc exists in HB+trie
                            // move tree cursor
                            iterator->tree_cursor = wal_itr_prev(iterator->
                                                                 wal_itr);
                            // do not move tree cursor next time
                            fetch_wal = false;
                            // fetch next key[HB+trie]
                            goto fetch_hbtrie;
                        } else if (cmp < 0) {
                            break;
                        }
                    }
                    iterator->tree_cursor = wal_itr_prev(iterator->wal_itr);
                    continue;
                } else if (iterator->start_key &&
                           iterator->opt & FDB_ITR_SKIP_MIN_KEY) {
                    cmp = _fdb_key_cmp(iterator,
                                  snap_item->header->key,
                                  snap_item->header->keylen,
                                  iterator->start_key, iterator->start_keylen);
                    if (cmp == 0 ||
                        // WAL cursor is positioned exactly at seeked start key
                        // but iterator must skip the start key!
                        // If hb+trie has an item, use that else return FAIL
                        (cmp < 0 && // WAL key out of range and
                        !next_op)) { // Not called from fdb_iterator_seek_to_min
                        skip_wal = true;
                        iterator->status = FDB_ITR_WAL;
                    }
                }
                break;
            } while(iterator->tree_cursor);
        }
        iterator->tree_cursor_prev = iterator->tree_cursor;
        if (!iterator->tree_cursor) {
            // seek_key is smaller than the smallest key
            // Only allow fdb_iterator_next() call, fdb_iterator_prev() should
            // hit failure. To ensure this set the direction to as if
            // fdb_iterator_prev call has gone past the smallest key...
            iterator->tree_cursor_prev = wal_itr_search_greater(iterator->wal_itr,
                                                                &query);
            // since the current key[WAL] is smaller than seek_key,
            // skip key[WAL] this time
            skip_wal = true;
        }
    }

    if (iterator->tree_cursor && !skip_wal) {
        bool take_wal = false;
        bool discard_hbtrie = false;

        snap_item = iterator->tree_cursor;

        if (hr == HBTRIE_RESULT_SUCCESS) {
            cmp = _fdb_key_cmp(iterator,
                               snap_item->header->key, snap_item->header->keylen,
                               iterator->_key, iterator->_keylen);

            if (cmp == 0) {
                // same key exists in both HB+trie and WAL
                fdb_assert(snap_item->action != WAL_ACT_REMOVE,
                           snap_item->action, iterator->_offset);
                take_wal = true;
                discard_hbtrie = true;
            } else if (cmp < 0) { // key[WAL] < key[HB+trie]
                if (seek_pref == FDB_ITR_SEEK_HIGHER) {
                    // higher mode .. take smaller one (key[WAL]) first
                    take_wal = true;
                    discard_hbtrie = false;
                } else if (seek_pref == FDB_ITR_SEEK_LOWER) {
                    take_wal = false;
                    discard_hbtrie = false;
                    // In seek_to_max call with skip_max_key option,
                    if (next_op < 0) {
                        // if key[HB+trie] is the largest key
                        // smaller than max key,
                        // do not call prev() next.
                        if (iterator->end_key) {
                            cmp2 = _fdb_key_cmp(iterator,
                                                iterator->_key,
                                                iterator->_keylen,
                                                iterator->end_key,
                                                iterator->end_keylen);
                        } else {
                            cmp2 = -1;
                        }
                        if (cmp2 < 0) {
                            next_op = 0;
                        }
                    }
                }
            } else { // key[HB+trie] < key[WAL]
                if (seek_pref == FDB_ITR_SEEK_HIGHER) {
                    // higher mode .. take smaller one (key[HB+trie]) first
                    take_wal = false;
                    discard_hbtrie = false;
                    // In seek_to_min call with skip_min_key option,
                    if (next_op > 0) {
                        // if key[HB+trie] is the smallest key
                        // larger than min key,
                        // do not call next() next.
                        if (iterator->start_key) {
                            cmp2 = _fdb_key_cmp(iterator,
                                                iterator->start_key,
                                                iterator->start_keylen,
                                                iterator->_key,
                                                iterator->_keylen);
                        } else {
                            cmp2 = -1;
                        }
                        if (cmp2 < 0) {
                            next_op = 0;
                        }
                    }
                } else if (seek_pref == FDB_ITR_SEEK_LOWER) {
                    // lower mode .. discard smaller one (key[HB+trie])
                    take_wal = true;
                    discard_hbtrie = true;
                    // reset HB+trie's iterator to get the current
                    // key[HB+trie] one more time
                    hbtrie_iterator_free(iterator->hbtrie_iterator);
                    hbtrie_iterator_init(iterator->handle->trie,
                                         iterator->hbtrie_iterator,
                                         seek_key_kv, seek_keylen_kv);
                    iterator->_offset = BLK_NOT_FOUND;
                }
            }
        } else {
            // HB+trie seek fail (key[HB+trie] doesn't exist)
            take_wal = true;
            discard_hbtrie = true;
        }

        if (take_wal) { // take key[WAL]
            if (!discard_hbtrie) { // do not skip the current key[HB+trie]
                // key[HB+trie] will be returned next time
                iterator->_offset = iterator->_get_offset;
            }
            iterator->_get_offset = snap_item->offset;
            iterator->_dhandle = iterator->handle->dhandle;
            iterator->status = FDB_ITR_WAL;
        }
    }

    if (!iterator->_dhandle) {
        atomic_cas_uint8_t(&iterator->handle->handle_busy, 1, 0);
        return FDB_RESULT_ITERATOR_FAIL;
    }

    if (next_op < 0) {
        atomic_cas_uint8_t(&iterator->handle->handle_busy, 1, 0);
        ret = fdb_iterator_prev(iterator);
    } else if (next_op > 0) {
        atomic_cas_uint8_t(&iterator->handle->handle_busy, 1, 0);
        ret = fdb_iterator_next(iterator);
    } else {
        atomic_cas_uint8_t(&iterator->handle->handle_busy, 1, 0);
        ret = FDB_RESULT_SUCCESS;
    }

    LATENCY_STAT_END(iterator->handle->file, FDB_LATENCY_ITR_SEEK);
    return ret;
}

LIBFDB_API
fdb_status fdb_iterator_seek_to_min(fdb_iterator *iterator)
{
    if (!iterator || !iterator->handle) {
        return FDB_RESULT_INVALID_HANDLE;
    }

    if (!iterator->_key) {
        return FDB_RESULT_INVALID_ARGS;
    }

    size_t size_chunk = iterator->handle->config.chunksize;
    fdb_status ret;
    LATENCY_STAT_START();

    // Initialize direction iteration to FORWARD just in case this function was
    // called right after fdb_iterator_init() so the cursor gets positioned
    // correctly
    iterator->direction = FDB_ITR_FORWARD;
    if (iterator->start_keylen > size_chunk) {
        fdb_iterator_seek_opt_t dir = (iterator->opt & FDB_ITR_SKIP_MIN_KEY) ?
                                      FDB_ITR_SEEK_HIGHER : FDB_ITR_SEEK_LOWER;
        fdb_status status = fdb_iterator_seek(iterator,
                (uint8_t *)iterator->start_key + size_chunk,
                iterator->start_keylen - size_chunk, dir);
        if (status != FDB_RESULT_SUCCESS && dir == FDB_ITR_SEEK_LOWER) {
            dir = FDB_ITR_SEEK_HIGHER;
            // It is possible that the min key specified during init does not
            // exist, so retry the seek with the HIGHER key
            return fdb_iterator_seek(iterator,
                (uint8_t *)iterator->start_key + size_chunk,
                iterator->start_keylen - size_chunk, dir);
        }
        return status;
    }

    // reset HB+trie iterator using start key
    hbtrie_iterator_free(iterator->hbtrie_iterator);
    hbtrie_iterator_init(iterator->handle->trie, iterator->hbtrie_iterator,
                         iterator->start_key, iterator->start_keylen);

    // reset WAL tree cursor using search because of the sharded nature of WAL
    if (iterator->tree_cursor_start) {
        iterator->tree_cursor_prev = iterator->tree_cursor =
                                     wal_itr_search_greater(iterator->wal_itr,
                                     iterator->tree_cursor_start);
        iterator->status = FDB_ITR_IDX; // WAL is already set
    }

    ret = fdb_iterator_next(iterator);
    LATENCY_STAT_END(iterator->handle->file, FDB_LATENCY_ITR_SEEK_MIN);
    return ret;
}

fdb_status _fdb_iterator_seek_to_max_key(fdb_iterator *iterator) {
    int cmp;

    if (!iterator || !iterator->handle) {
        return FDB_RESULT_INVALID_HANDLE;
    }

    if (!iterator->_key) {
        return FDB_RESULT_INVALID_ARGS;
    }

    size_t size_chunk = iterator->handle->config.chunksize;

    // Initialize direction iteration to FORWARD just in case this function was
    // called right after fdb_iterator_init() so the cursor gets positioned
    // correctly
    iterator->direction = FDB_ITR_FORWARD;
    if (iterator->end_keylen > size_chunk) {
        fdb_iterator_seek_opt_t dir = (iterator->opt & FDB_ITR_SKIP_MAX_KEY) ?
                                      FDB_ITR_SEEK_LOWER : FDB_ITR_SEEK_HIGHER;
        fdb_status status = fdb_iterator_seek(iterator,
                (uint8_t *)iterator->end_key + size_chunk,
                iterator->end_keylen - size_chunk, dir);

        if (status != FDB_RESULT_SUCCESS && dir == FDB_ITR_SEEK_HIGHER) {
            dir = FDB_ITR_SEEK_LOWER;
            // It is possible that the max key specified during init does not
            // exist, so retry the seek with the LOWER key
            return fdb_iterator_seek(iterator,
                    (uint8_t *)iterator->end_key + size_chunk,
                    iterator->end_keylen - size_chunk, dir);
        }
        return status;
    }
    iterator->direction = FDB_ITR_REVERSE; // only reverse iteration possible

    if (iterator->end_key && iterator->end_keylen == size_chunk) {
        // end_key exists but end_keylen == size_id
        // it means that user doesn't assign end_key but
        // end_key is automatically assigned due to multi KVS mode.

        // reset HB+trie's iterator using end_key
        hbtrie_iterator_free(iterator->hbtrie_iterator);
        hbtrie_iterator_init(iterator->handle->trie, iterator->hbtrie_iterator,
                             iterator->end_key, iterator->end_keylen);
        // get first key
        hbtrie_prev(iterator->hbtrie_iterator, iterator->_key,
                         &iterator->_keylen, (void*)&iterator->_offset);
        iterator->_offset = _endian_decode(iterator->_offset);
        cmp = _fdb_key_cmp(iterator,
                               iterator->end_key, iterator->end_keylen,
                               iterator->_key, iterator->_keylen);
        if (cmp < 0) {
            // returned key is larger than the end key .. skip
            iterator->_offset = BLK_NOT_FOUND;
        }
    } else {
        // move HB+trie iterator's cursor to the last entry
        hbtrie_last(iterator->hbtrie_iterator);
    }

    // also move WAL tree's cursor to the last entry
    struct wal_item_header hdr;
    struct wal_item query;
    query.header = &hdr;
    hdr.key = iterator->end_key;
    hdr.keylen = iterator->end_keylen;
    iterator->tree_cursor = wal_itr_search_smaller(iterator->wal_itr,
                                                   &query);
    iterator->tree_cursor_prev = iterator->tree_cursor;
    iterator->status = FDB_ITR_IDX;

    return fdb_iterator_prev(iterator);
}

fdb_status _fdb_iterator_seek_to_max_seq(fdb_iterator *iterator) {
    if (!iterator || !iterator->handle) {
        return FDB_RESULT_INVALID_HANDLE;
    }

    iterator->direction = FDB_ITR_REVERSE; // only reverse iteration possible
    iterator->_seqnum = iterator->end_seqnum;

    if (iterator->handle->kvs) {
        // create an iterator handle for hb-trie
        uint8_t *end_seq_kv = alca(uint8_t, sizeof(size_t)*2);
        fdb_kvs_id_t _kv_id = _endian_encode(iterator->handle->kvs->id);
        memcpy(end_seq_kv, &_kv_id, sizeof(size_t));
        memcpy(end_seq_kv + sizeof(size_t), &iterator->end_seqnum,
                sizeof(size_t));

        // reset HB+trie's seqtrie iterator using end_seq_kv
        hbtrie_iterator_free(iterator->seqtrie_iterator);
        hbtrie_iterator_init(iterator->handle->seqtrie,
                             iterator->seqtrie_iterator,
                             end_seq_kv, sizeof(size_t)*2);
    } else {
        // reset Btree iterator to end_seqnum
        btree_iterator_free(iterator->seqtree_iterator);
        // create an iterator handle for b-tree
        btree_iterator_init(iterator->handle->seqtree,
                            iterator->seqtree_iterator,
                            (void *)(&iterator->end_seqnum));
    }

    if (iterator->end_seqnum != SEQNUM_NOT_USED) {
        struct wal_item query;
        struct wal_item_header query_key;
        size_t size_seq = sizeof(fdb_seqnum_t);
        size_t size_chunk = iterator->handle->config.chunksize;
        uint8_t *end_seq_kv = alca(uint8_t, size_chunk + size_seq);
        if (iterator->handle->kvs) {
            query_key.key = end_seq_kv;
            kvid2buf(size_chunk, iterator->handle->kvs->id, end_seq_kv);
            memcpy(end_seq_kv + size_chunk, &iterator->end_seqnum, size_seq);
            query_key.keylen = size_chunk + size_seq;
        } else {
            query_key.key = (void *) NULL;
            query_key.keylen = 0;
        }
        query.header = &query_key;
        query.seqnum = iterator->end_seqnum;

        // reset WAL tree cursor using search because of the sharded WAL
        iterator->tree_cursor = wal_itr_search_smaller(iterator->wal_itr,
                                                       &query);
    } else { // no end_seqnum specified, just head to the last entry
        iterator->tree_cursor = wal_itr_last(iterator->wal_itr);
    }

    if (iterator->tree_cursor) {
        struct wal_item *snap_item = iterator->tree_cursor;
        if (snap_item->seqnum == iterator->end_seqnum &&
            iterator->opt & FDB_ITR_SKIP_MAX_KEY) {
            iterator->tree_cursor = wal_itr_prev(iterator->wal_itr);
        }
    }

    if (iterator->tree_cursor) {
        // If WAL tree has an entry, skip Main index for reverse iteration..
        iterator->_offset = iterator->tree_cursor->offset;
    } else {
        iterator->_offset = BLK_NOT_FOUND; // fetch from main index
    }

    iterator->tree_cursor_prev = iterator->tree_cursor;
    return fdb_iterator_prev(iterator);
}

LIBFDB_API
fdb_status fdb_iterator_seek_to_max(fdb_iterator *iterator)
{
    if (!iterator || !iterator->handle) {
        return FDB_RESULT_INVALID_HANDLE;
    }

    fdb_status ret;
    LATENCY_STAT_START();

    if (!iterator->hbtrie_iterator) {
        ret = _fdb_iterator_seek_to_max_seq(iterator);
    } else {
        ret = _fdb_iterator_seek_to_max_key(iterator);
    }
    LATENCY_STAT_END(iterator->handle->file, FDB_LATENCY_ITR_SEEK_MAX);
    return ret;
}

static fdb_status _fdb_iterator_seq_prev(fdb_iterator *iterator)
{
    size_t size_id, size_seq, seq_kv_len;
    uint8_t *seq_kv;
    uint64_t offset = BLK_NOT_FOUND;
    btree_result br = BTREE_RESULT_FAIL;
    hbtrie_result hr;
    struct docio_object _doc;
    struct docio_handle *dhandle;
    struct wal_item *snap_item = NULL;
    fdb_seqnum_t seqnum;
    fdb_kvs_id_t kv_id;

    size_id = sizeof(fdb_kvs_id_t);
    size_seq = sizeof(fdb_seqnum_t);
    seq_kv = alca(uint8_t, size_id + size_seq);

    if (iterator->direction != FDB_ITR_REVERSE) {
        if (iterator->status == FDB_ITR_IDX) {
            iterator->_offset = BLK_NOT_FOUND; // need to re-examine Trie/trees
        }
        // re-position WAL key to previous key returned using search because of
        // sharded nature of wal (we cannot directly assign prev to cursor)
        if (iterator->tree_cursor_prev &&
            iterator->tree_cursor != iterator->tree_cursor_prev) {
            iterator->tree_cursor = wal_itr_search_smaller(iterator->wal_itr,
                                                  iterator->tree_cursor_prev);
            iterator->status = FDB_ITR_IDX;
        } // else Don't move - seek()/init() has already positioned cursor
    }

start_seq:
    seqnum = iterator->_seqnum;
    dhandle = iterator->handle->dhandle;

    if (iterator->_offset == BLK_NOT_FOUND || // was iterating over btree
        !iterator->tree_cursor) { // WAL exhausted
        if (iterator->handle->kvs) { // multi KV instance mode
            hr = hbtrie_prev(iterator->seqtrie_iterator, seq_kv, &seq_kv_len,
                             (void *)&offset);
            if (hr == HBTRIE_RESULT_SUCCESS) {
                br = BTREE_RESULT_SUCCESS;
                buf2kvid(size_id, seq_kv, &kv_id);
                if (kv_id != iterator->handle->kvs->id) {
                    // iterator is beyond the boundary
                    br = BTREE_RESULT_FAIL;
                }
                memcpy(&seqnum, seq_kv + size_id, size_seq);
            } else {
                br = BTREE_RESULT_FAIL;
            }
        } else {
            br = btree_prev(iterator->seqtree_iterator, &seqnum,
                            (void *)&offset);
        }
        btreeblk_end(iterator->handle->bhandle);
        if (br == BTREE_RESULT_SUCCESS) {
            seqnum = _endian_decode(seqnum);
            iterator->_seqnum = seqnum;
            if (seqnum < iterator->start_seqnum) {
                return FDB_RESULT_ITERATOR_FAIL;
            }
            offset = _endian_decode(offset);
            iterator->status = FDB_ITR_IDX;
        } else {
            iterator->_offset = BLK_NOT_FOUND;
            // B-tree has no more items
            return FDB_RESULT_ITERATOR_FAIL;
        }
    } else while (iterator->tree_cursor) {
        if (iterator->status == FDB_ITR_WAL) {
            iterator->tree_cursor_prev = iterator->tree_cursor;
            iterator->tree_cursor = wal_itr_prev(iterator->wal_itr);
            if (!iterator->tree_cursor) {
                goto start_seq;
            }
        }// else don't move - seek()/ init() has already positioned cursor

        iterator->status = FDB_ITR_WAL;
        // get the current item of avl tree
        snap_item = iterator->tree_cursor;
        uint8_t drop_logical_deletes =
            (snap_item->action == WAL_ACT_LOGICAL_REMOVE) &&
            (iterator->opt & FDB_ITR_NO_DELETES);
        if (snap_item->action == WAL_ACT_REMOVE ||
                drop_logical_deletes) {
            if (br == BTREE_RESULT_FAIL && !iterator->tree_cursor) {
                return FDB_RESULT_ITERATOR_FAIL;
            }
            // this key is removed .. get prev key[WAL]
            continue;
        }

        offset = snap_item->offset;
        iterator->_offset = offset; // WAL is not exhausted, ignore B-Tree
        iterator->_seqnum = snap_item->seqnum;
        break;
    }

    // To prevent returning duplicate items from sequence iterator, only return
    // those b-tree items that exist in HB-trie but not WAL
    // (WAL items should have already been returned in reverse iteration)
    if (br == BTREE_RESULT_SUCCESS) {
        fdb_doc doc_kv;
        _doc.key = NULL;
        _doc.length.keylen = 0;
        _doc.meta = NULL;
        _doc.body = NULL;

        int64_t _offset = docio_read_doc_key_meta(dhandle, offset, &_doc,
                                                  true);
        if (_offset <= 0) {
            return _offset < 0 ? (fdb_status)_offset : FDB_RESULT_KEY_NOT_FOUND;
        }
        if (_doc.length.flag & DOCIO_DELETED &&
            (iterator->opt & FDB_ITR_NO_DELETES)) {
            free(_doc.key);
            free(_doc.meta);
            return FDB_RESULT_KEY_NOT_FOUND;
        }

        doc_kv.key = _doc.key;
        doc_kv.keylen = _doc.length.keylen;
        doc_kv.seqnum = SEQNUM_NOT_USED;
        if (wal_find(iterator->handle->shandle->snap_txn,
                     iterator->handle->file,
                     &iterator->handle->shandle->cmp_info,
                     iterator->handle->shandle,
                     &doc_kv, (uint64_t *) &_offset) == FDB_RESULT_SUCCESS &&
                     iterator->start_seqnum <= doc_kv.seqnum &&
                     doc_kv.seqnum <= iterator->end_seqnum) {
            free(_doc.key);
            free(_doc.meta);
            goto start_seq; // B-tree item exists in WAL, skip for now
        }
        // Also look in HB-Trie to eliminate duplicates
        uint64_t hboffset;
        struct docio_object _hbdoc;
        hr = hbtrie_find(iterator->handle->trie, _doc.key, _doc.length.keylen,
                         (void *)&hboffset);
        btreeblk_end(iterator->handle->bhandle);

        if (hr != HBTRIE_RESULT_SUCCESS) {
            free(_doc.key);
            free(_doc.meta);
            goto start_seq;
        } else { // If present in HB-trie ensure it's seqnum is in range
            int64_t _offset;
            _hbdoc.key = _doc.key;
            _hbdoc.meta = NULL;
            hboffset = _endian_decode(hboffset);
            _offset = docio_read_doc_key_meta(iterator->handle->dhandle,
                                              hboffset, &_hbdoc, true);
            if (_offset <= 0) {
                free(_doc.key);
                free(_doc.meta);
                return _offset < 0 ? (fdb_status)_offset : FDB_RESULT_KEY_NOT_FOUND;
            }

            if (_doc.seqnum < _hbdoc.seqnum &&
                _hbdoc.seqnum <= iterator->end_seqnum) {
                free(_doc.key);
                free(_doc.meta);
                free(_hbdoc.meta);
                goto start_seq;
            }
            free(_hbdoc.meta);
        }
        free(_doc.key);
        free(_doc.meta);
    }

    iterator->_dhandle = dhandle; // store for fdb_iterator_get()
    iterator->_get_offset = offset; // store for fdb_iterator_get()

    return FDB_RESULT_SUCCESS;
}

static fdb_status _fdb_iterator_seq_next(fdb_iterator *iterator)
{
    size_t size_id, size_seq, seq_kv_len;
    uint8_t *seq_kv;
    uint64_t offset = BLK_NOT_FOUND;
    btree_result br = BTREE_RESULT_FAIL;
    hbtrie_result hr;
    struct docio_object _doc;
    struct docio_handle *dhandle;
    struct wal_item *snap_item = NULL;
    fdb_seqnum_t seqnum;
    fdb_kvs_id_t kv_id;

    size_id = sizeof(fdb_kvs_id_t);
    size_seq = sizeof(fdb_seqnum_t);
    seq_kv = alca(uint8_t, size_id + size_seq);

    if (iterator->direction != FDB_ITR_FORWARD) {
        if (iterator->status == FDB_ITR_IDX) {
            iterator->_offset = BLK_NOT_FOUND; // need to re-examine Trie/trees
        }
        // re-position WAL key to previous key returned
        if (iterator->tree_cursor_prev) {
            iterator->tree_cursor = wal_itr_search_greater(iterator->wal_itr,
                                    iterator->tree_cursor_prev);
            iterator->status = FDB_ITR_IDX;
        } // else Don't move - seek()/init() has already positioned cursor
    }

start_seq:
    seqnum = iterator->_seqnum;
    dhandle = iterator->handle->dhandle;

    // retrieve from sequence b-tree first
    if (iterator->_offset == BLK_NOT_FOUND) {
        if (iterator->handle->kvs) { // multi KV instance mode
            hr = hbtrie_next(iterator->seqtrie_iterator, seq_kv, &seq_kv_len,
                             (void *)&offset);
            if (hr == HBTRIE_RESULT_SUCCESS) {
                br = BTREE_RESULT_SUCCESS;
                buf2kvid(size_id, seq_kv, &kv_id);
                if (kv_id != iterator->handle->kvs->id) {
                    // iterator is beyond the boundary
                    br = BTREE_RESULT_FAIL;
                }
                memcpy(&seqnum, seq_kv + size_id, size_seq);
            } else {
                br = BTREE_RESULT_FAIL;
            }
        } else {
            br = btree_next(iterator->seqtree_iterator, &seqnum,
                            (void *)&offset);
        }
        btreeblk_end(iterator->handle->bhandle);
        if (br == BTREE_RESULT_SUCCESS) {
            seqnum = _endian_decode(seqnum);
            iterator->_seqnum = seqnum;
            if (seqnum > iterator->end_seqnum) {
                return FDB_RESULT_ITERATOR_FAIL;
            }
            offset = _endian_decode(offset);
            iterator->_offset = BLK_NOT_FOUND; // continue with B-tree
            iterator->status = FDB_ITR_IDX;
        }
    }

    if (br == BTREE_RESULT_FAIL) {
        if (iterator->tree_cursor == NULL) {
            return FDB_RESULT_ITERATOR_FAIL;
        } else {
            while (iterator->tree_cursor) {
                if (iterator->status == FDB_ITR_WAL) {
                    // save the current point for direction change
                    iterator->tree_cursor_prev = iterator->tree_cursor;
                    iterator->tree_cursor = wal_itr_next(iterator->wal_itr);
                    if (!iterator->tree_cursor) {
                        return FDB_RESULT_ITERATOR_FAIL;
                    }
                }// else don't move - seek()/ init() already positioned cursor
                // get the current item of WAL tree
                iterator->status = FDB_ITR_WAL;
                snap_item = iterator->tree_cursor;
                uint8_t drop_logical_deletes =
                    (snap_item->action == WAL_ACT_LOGICAL_REMOVE) &&
                    (iterator->opt & FDB_ITR_NO_DELETES);
                if (snap_item->action == WAL_ACT_REMOVE ||
                    drop_logical_deletes) {
                    if (br == BTREE_RESULT_FAIL && !iterator->tree_cursor) {
                        return FDB_RESULT_ITERATOR_FAIL;
                    }
                    // this key is removed .. get next key[WAL]
                    continue;
                }
                if (snap_item->seqnum < iterator->_seqnum) {
                    // smaller than the current seqnum .. get next key[WAL]
                    continue;
                }
                if (snap_item->seqnum > iterator->end_seqnum) {
                    // out-of-range .. iterator terminates
                    return FDB_RESULT_ITERATOR_FAIL;
                }

                offset = snap_item->offset;
                iterator->_offset = offset; // stops b-tree lookups. favor wal
                iterator->_seqnum = snap_item->seqnum;
                break;
            }
        }
    }

    // To prevent returning duplicate items from sequence iterator, only return
    // those b-tree items that exist in HB-trie but not WAL (visit WAL later)
    if (br == BTREE_RESULT_SUCCESS) {
        _doc.key = NULL;
        _doc.length.keylen = 0;
        _doc.meta = NULL;
        _doc.body = NULL;

        fdb_doc doc_kv;
        int64_t _offset = docio_read_doc_key_meta(dhandle, offset, &_doc,
                                                  true);
        if (_offset <= 0) {
            return _offset < 0 ? (fdb_status)_offset : FDB_RESULT_KEY_NOT_FOUND;
        }
        if (_doc.length.flag & DOCIO_DELETED && (iterator->opt & FDB_ITR_NO_DELETES)) {
            free(_doc.key);
            free(_doc.meta);
            return FDB_RESULT_KEY_NOT_FOUND;
        }
        doc_kv.key = _doc.key;
        doc_kv.keylen = _doc.length.keylen;
        doc_kv.seqnum = SEQNUM_NOT_USED; // search by key not seqnum
        if (wal_find(iterator->handle->shandle->snap_txn,
                    iterator->handle->file,
                    &iterator->handle->shandle->cmp_info,
                    iterator->handle->shandle,
                     &doc_kv, (uint64_t *) &_offset) == FDB_RESULT_SUCCESS &&
                iterator->start_seqnum <= doc_kv.seqnum &&
                doc_kv.seqnum <= iterator->end_seqnum) {
            free(_doc.key);
            free(_doc.meta);
            goto start_seq; // B-tree item exists in WAL, skip for now
        }
        // Also look in HB-Trie to eliminate duplicates
        uint64_t hboffset;
        struct docio_object _hbdoc;
        hr = hbtrie_find(iterator->handle->trie, _doc.key, _doc.length.keylen,
                         (void *)&hboffset);
        btreeblk_end(iterator->handle->bhandle);

        if (hr != HBTRIE_RESULT_SUCCESS) {
            free(_doc.key);
            free(_doc.meta);
            goto start_seq;
        } else { // If present in HB-trie ensure it's seqnum is in range
            int64_t _offset;
            _hbdoc.key = _doc.key;
            _hbdoc.meta = NULL;
            hboffset = _endian_decode(hboffset);
            _offset = docio_read_doc_key_meta(iterator->handle->dhandle,
                                              hboffset, &_hbdoc,
                                              true);
            if (_offset <= 0) {
                free(_doc.key);
                free(_doc.meta);
                return _offset < 0 ? (fdb_status)_offset : FDB_RESULT_KEY_NOT_FOUND;
            }
            if (_doc.seqnum < _hbdoc.seqnum &&
                _hbdoc.seqnum <= iterator->end_seqnum) {
                free(_doc.key);
                free(_doc.meta);
                free(_hbdoc.meta);
                goto start_seq;
            }
            free(_hbdoc.meta);
        }
        free(_doc.key);
        free(_doc.meta);
    }

    iterator->_dhandle = dhandle; // store for fdb_iterator_get
    iterator->_get_offset = offset; // store for fdb_iterator_get

    return FDB_RESULT_SUCCESS;
}

LIBFDB_API
fdb_status fdb_iterator_prev(fdb_iterator *iterator)
{
    if (!iterator || !iterator->handle) {
        return FDB_RESULT_INVALID_HANDLE;
    }

    fdb_status result = FDB_RESULT_SUCCESS;
    LATENCY_STAT_START();

    if (!atomic_cas_uint8_t(&iterator->handle->handle_busy, 0, 1)) {
        return FDB_RESULT_HANDLE_BUSY;
    }

    if (iterator->hbtrie_iterator) {
        while ((result = _fdb_iterator_prev(iterator)) ==
                FDB_RESULT_KEY_NOT_FOUND);
    } else {
        while ((result = _fdb_iterator_seq_prev(iterator)) ==
                FDB_RESULT_KEY_NOT_FOUND);
    }
    if (result == FDB_RESULT_SUCCESS) {
        iterator->direction = FDB_ITR_REVERSE;
    } else {
        iterator->_dhandle = NULL; // fail fdb_iterator_get also
        if (iterator->direction != FDB_ITR_DIR_NONE) {
            if ((iterator->seqtree_iterator || iterator->seqtrie_iterator) &&
                    iterator->status == FDB_ITR_IDX) {
                iterator->_offset = BLK_NOT_FOUND;
            }
        }
    }

    atomic_cas_uint8_t(&iterator->handle->handle_busy, 1, 0);
    atomic_incr_uint64_t(&iterator->handle->op_stats->num_iterator_moves,
                         std::memory_order_relaxed);
    LATENCY_STAT_END(iterator->handle->file, FDB_LATENCY_ITR_PREV);
    return result;
}

LIBFDB_API
fdb_status fdb_iterator_next(fdb_iterator *iterator)
{
    if (!iterator || !iterator->handle) {
        return FDB_RESULT_INVALID_HANDLE;
    }

    fdb_status result = FDB_RESULT_SUCCESS;
    LATENCY_STAT_START();

    if (!atomic_cas_uint8_t(&iterator->handle->handle_busy, 0, 1)) {
        return FDB_RESULT_HANDLE_BUSY;
    }

    if (iterator->hbtrie_iterator) {
        while ((result = _fdb_iterator_next(iterator)) ==
                FDB_RESULT_KEY_NOT_FOUND);
    } else {
        while ((result = _fdb_iterator_seq_next(iterator)) ==
                FDB_RESULT_KEY_NOT_FOUND);
    }
    if (result == FDB_RESULT_SUCCESS) {
        iterator->direction = FDB_ITR_FORWARD;
    } else {
        iterator->_dhandle = NULL; // fail fdb_iterator_get also
        if (iterator->direction != FDB_ITR_DIR_NONE) {
            if ((iterator->seqtree_iterator || iterator->seqtrie_iterator) &&
                    iterator->status == FDB_ITR_IDX) {
                iterator->_offset = BLK_NOT_FOUND;
            }
        }
    }

    atomic_cas_uint8_t(&iterator->handle->handle_busy, 1, 0);
    atomic_incr_uint64_t(&iterator->handle->op_stats->num_iterator_moves,
                         std::memory_order_relaxed);
    LATENCY_STAT_END(iterator->handle->file, FDB_LATENCY_ITR_NEXT);
    return result;
}

// DOC returned by this function must be freed by fdb_doc_free
// if it was allocated because the incoming doc was pointing to NULL
LIBFDB_API
fdb_status fdb_iterator_get(fdb_iterator *iterator, fdb_doc **doc)
{
    if (!iterator || !iterator->handle) {
        return FDB_RESULT_INVALID_HANDLE;
    }

    if (!doc) {
        return FDB_RESULT_INVALID_ARGS;
    }

    struct docio_object _doc;
    fdb_status ret = FDB_RESULT_SUCCESS;
    uint64_t offset;
    struct docio_handle *dhandle;
    size_t size_chunk = iterator->handle->config.chunksize;
    bool alloced_key, alloced_meta, alloced_body;
    LATENCY_STAT_START();

    dhandle = iterator->_dhandle;
    if (!dhandle || iterator->_get_offset == BLK_NOT_FOUND) {
        return FDB_RESULT_ITERATOR_FAIL;
    }

    if (!atomic_cas_uint8_t(&iterator->handle->handle_busy, 0, 1)) {
        return FDB_RESULT_HANDLE_BUSY;
    }

    offset = iterator->_get_offset;

    if (*doc == NULL) {
        ret = fdb_doc_create(doc, NULL, 0, NULL, 0, NULL, 0);
        if (ret != FDB_RESULT_SUCCESS) { // LCOV_EXCL_START
            atomic_cas_uint8_t(&iterator->handle->handle_busy, 1, 0);
            return ret;
        } // LCOV_EXCL_STOP
        _doc.key = NULL;
        _doc.length.keylen = 0;
        _doc.meta = NULL;
        _doc.body = NULL;
        alloced_key = true;
        alloced_meta = true;
        alloced_body = true;
    } else {
        _doc.key = (*doc)->key;
        _doc.meta = (*doc)->meta;
        _doc.body = (*doc)->body;
        alloced_key = _doc.key ? false : true;
        alloced_meta = _doc.meta ? false : true;
        alloced_body = _doc.body ? false : true;
    }

    int64_t _offset = docio_read_doc(dhandle, offset, &_doc, true);
    if (_offset <= 0) {
        atomic_cas_uint8_t(&iterator->handle->handle_busy, 1, 0);
        return _offset < 0 ? (fdb_status) _offset : FDB_RESULT_KEY_NOT_FOUND;
    }
    if (_doc.length.flag & DOCIO_DELETED &&
        (iterator->opt & FDB_ITR_NO_DELETES)) {
        if (alloced_key) {
            free(_doc.key);
        }
        if (alloced_meta) {
            free(_doc.meta);
        }
        if (alloced_body) {
            free(_doc.body);
        }
        atomic_cas_uint8_t(&iterator->handle->handle_busy, 1, 0);
        return FDB_RESULT_KEY_NOT_FOUND;
    }

    if (iterator->handle->kvs) {
        // eliminate KV ID from key
        _doc.length.keylen -= size_chunk;
        memmove(_doc.key, (uint8_t*)_doc.key + size_chunk, _doc.length.keylen);
    }

    if (alloced_key) {
        (*doc)->key = _doc.key;
    }
    if (alloced_meta) {
        (*doc)->meta = _doc.meta;
    }
    if (alloced_body) {
        (*doc)->body = _doc.body;
    }
    (*doc)->keylen = _doc.length.keylen;
    (*doc)->metalen = _doc.length.metalen;
    (*doc)->bodylen = _doc.length.bodylen;
    (*doc)->seqnum = _doc.seqnum;
    (*doc)->deleted = _doc.length.flag & DOCIO_DELETED;
    (*doc)->offset = offset;

    atomic_cas_uint8_t(&iterator->handle->handle_busy, 1, 0);
    atomic_incr_uint64_t(&iterator->handle->op_stats->num_iterator_gets,
                         std::memory_order_relaxed);
    LATENCY_STAT_END(iterator->handle->file, FDB_LATENCY_ITR_GET);
    return ret;
}

// DOC returned by this function must be freed using 'fdb_doc_free'
LIBFDB_API
fdb_status fdb_iterator_get_metaonly(fdb_iterator *iterator, fdb_doc **doc)
{
    if (!iterator || !iterator->handle) {
        return FDB_RESULT_INVALID_HANDLE;
    }

    if (!doc) {
        return FDB_RESULT_INVALID_ARGS;
    }

    struct docio_object _doc;
    fdb_status ret = FDB_RESULT_SUCCESS;
    uint64_t offset;
    int64_t _offset;
    struct docio_handle *dhandle;
    size_t size_chunk = iterator->handle->config.chunksize;
    bool alloced_key, alloced_meta;
    LATENCY_STAT_START();

    dhandle = iterator->_dhandle;
    if (!dhandle || iterator->_get_offset == BLK_NOT_FOUND) {
        return FDB_RESULT_ITERATOR_FAIL;
    }

    if (!atomic_cas_uint8_t(&iterator->handle->handle_busy, 0, 1)) {
        return FDB_RESULT_HANDLE_BUSY;
    }

    offset = iterator->_get_offset;

    if (*doc == NULL) {
        ret = fdb_doc_create(doc, NULL, 0, NULL, 0, NULL, 0);
        if (ret != FDB_RESULT_SUCCESS) { // LCOV_EXCL_START
            atomic_cas_uint8_t(&iterator->handle->handle_busy, 1, 0);
            return ret;
        } // LCOV_EXCL_STOP
        _doc.key = NULL;
        _doc.length.keylen = 0;
        _doc.meta = NULL;
        _doc.body = NULL;
        alloced_key = true;
        alloced_meta = true;
    } else {
        _doc.key = (*doc)->key;
        _doc.meta = (*doc)->meta;
        _doc.body = NULL;
        alloced_key = _doc.key ? false : true;
        alloced_meta = _doc.meta ? false : true;
    }

    _offset = docio_read_doc_key_meta(dhandle, offset, &_doc, true);
    if (_offset <= 0) {
        atomic_cas_uint8_t(&iterator->handle->handle_busy, 1, 0);
        return _offset < 0 ? (fdb_status)_offset : FDB_RESULT_KEY_NOT_FOUND;
    }
    if (_doc.length.flag & DOCIO_DELETED &&
            (iterator->opt & FDB_ITR_NO_DELETES)) {
        if (alloced_key) {
            free(_doc.key);
        }
        if (alloced_meta) {
            free(_doc.meta);
        }
        atomic_cas_uint8_t(&iterator->handle->handle_busy, 1, 0);
        return FDB_RESULT_KEY_NOT_FOUND;
    }

    if (iterator->handle->kvs) {
        // eliminate KV ID from key
        _doc.length.keylen -= size_chunk;
        memmove(_doc.key, (uint8_t*)_doc.key + size_chunk, _doc.length.keylen);
    }
    if (alloced_key) {
        (*doc)->key = _doc.key;
    }
    if (alloced_meta) {
        (*doc)->meta = _doc.meta;
    }
    (*doc)->keylen = _doc.length.keylen;
    (*doc)->metalen = _doc.length.metalen;
    (*doc)->bodylen = _doc.length.bodylen;
    (*doc)->seqnum = _doc.seqnum;
    (*doc)->deleted = _doc.length.flag & DOCIO_DELETED;
    (*doc)->offset = offset;

    atomic_cas_uint8_t(&iterator->handle->handle_busy, 1, 0);
    atomic_incr_uint64_t(&iterator->handle->op_stats->num_iterator_gets,
                         std::memory_order_relaxed);
    LATENCY_STAT_END(iterator->handle->file, FDB_LATENCY_ITR_GET_META);
    return ret;
}

LIBFDB_API
fdb_status fdb_iterator_close(fdb_iterator *iterator)
{
    if (!iterator || !iterator->handle) {
        return FDB_RESULT_INVALID_HANDLE;
    }

    LATENCY_STAT_START();
    if (iterator->hbtrie_iterator) {
        hbtrie_iterator_free(iterator->hbtrie_iterator);
        free(iterator->hbtrie_iterator);
    }

    if (iterator->seqtree_iterator) {
        btree_iterator_free(iterator->seqtree_iterator);
        free(iterator->seqtree_iterator);
    }
    if (iterator->seqtrie_iterator) {
        hbtrie_iterator_free(iterator->seqtrie_iterator);
        free(iterator->seqtrie_iterator);
    }

    if (iterator->start_key) {
        free(iterator->start_key);
    }

    if (iterator->end_key) {
        free(iterator->end_key);
    }

    --iterator->handle->num_iterators; // Decrement the iterator counter of the KV handle
    wal_itr_close(iterator->wal_itr);

    LATENCY_STAT_END(iterator->handle->file, FDB_LATENCY_ITR_CLOSE);

    if (!iterator->snapshot_handle) {
        // Close the opened handle in the iterator,
        // if the handle is not for snapshot.
        fdb_status fs = fdb_kvs_close(iterator->handle);
        if (fs != FDB_RESULT_SUCCESS) {
            fdb_log(&iterator->handle->log_callback, fs,
                    "Failed to close the KV Store from a database file '%s' as "
                    "part of closing the iterator",
                    iterator->handle->file->filename);
        }
    }

    free(iterator->_key);
    free(iterator);
    return FDB_RESULT_SUCCESS;
}
