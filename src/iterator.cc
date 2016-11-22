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
#include "fdb_engine.h"
#include "fdb_internal.h"
#include "hbtrie.h"
#include "docio.h"
#include "btreeblock.h"
#include "common.h"
#include "wal.h"
#include "avltree.h"
#include "list.h"
#include "iterator.h"
#include "btree_var_kv_ops.h"
#include "time_utils.h"
#include "version.h"

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
    if (iterator->getHandle()->kvs_config.custom_cmp) {
        // custom compare function for variable length key
        if (iterator->getHandle()->kvs) {
            // multi KV instance mode
            // KV ID should be compared separately
            size_t size_chunk = iterator->getHandle()->config.chunksize;
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
                cmp = iterator->getHandle()->kvs_config.custom_cmp(
                          (uint8_t*)key1 + size_chunk, keylen1 - size_chunk,
                          (uint8_t*)key2 + size_chunk, keylen2 - size_chunk);
            }
        } else {
            cmp = iterator->getHandle()->kvs_config.custom_cmp(key1, keylen1,
                                                       key2, keylen2);
        }
    } else {
        cmp = _fdb_keycmp(key1, keylen1, key2, keylen2);
    }
    return cmp;
}

FdbIterator::FdbIterator(FdbKvsHandle *_handle,
                         bool snapshoted_handle,
                         const void *start_key,
                         size_t start_keylen,
                         const void *end_key,
                         size_t end_keylen,
                         fdb_iterator_opt_t opt)
    : iterHandle(_handle), snapshotHandle(snapshoted_handle),
      seqtreeIterator(nullptr), seqtrieIterator(nullptr),
      seqNum(0), iterOpt(opt), iterDirection(FDB_ITR_DIR_NONE),
      iterStatus(FDB_ITR_IDX), iterOffset(BLK_NOT_FOUND),
      dHandle(nullptr), getOffset(0), iterType(FDB_ITR_REG)
{
    iterKey.data = (void*)malloc(FDB_MAX_KEYLEN_INTERNAL);
    // set to zero the first <chunksize> bytes
    memset(iterKey.data, 0x0, iterHandle->config.chunksize);
    iterKey.len = 0;

    if (iterHandle->kvs) {
        // multi KV instance mode .. prepend KV ID
        size_t size_chunk = _handle->config.chunksize;
        uint8_t *start_key_temp, *end_key_temp;

        if (start_key == NULL) {
            start_key_temp = alca(uint8_t, size_chunk);
            kvid2buf(size_chunk, iterHandle->kvs->getKvsId(),
                     start_key_temp);
            start_key = start_key_temp;
            start_keylen = size_chunk;
        } else {
            start_key_temp = alca(uint8_t, size_chunk + start_keylen);
            kvid2buf(size_chunk, iterHandle->kvs->getKvsId(),
                     start_key_temp);
            memcpy(start_key_temp + size_chunk, start_key, start_keylen);
            start_key = start_key_temp;
            start_keylen += size_chunk;
        }

        if (end_key == NULL) {
            // set endKey as NULL key of the next KV ID.
            // NULL key doesn't actually exist so that the iterator ends
            // at the last key of the current KV ID.
            end_key_temp = alca(uint8_t, size_chunk);
            kvid2buf(size_chunk, iterHandle->kvs->getKvsId() + 1,
                     end_key_temp);
            end_key = end_key_temp;
            end_keylen = size_chunk;
        } else {
            end_key_temp = alca(uint8_t, size_chunk + end_keylen);
            kvid2buf(size_chunk, iterHandle->kvs->getKvsId(),
                     end_key_temp);
            memcpy(end_key_temp + size_chunk, end_key, end_keylen);
            end_key = end_key_temp;
            end_keylen += size_chunk;
        }

        startKey.data = (void*)malloc(start_keylen);
        memcpy(startKey.data, start_key, start_keylen);
        startKey.len = start_keylen;

        endKey.data = (void*)malloc(end_keylen);
        memcpy(endKey.data, end_key, end_keylen);
        endKey.len = end_keylen;

    } else { // single KV instance mode

        if (start_key == NULL) {
            startKey.data = NULL;
            startKey.len = 0;
        } else {
            startKey.data = (void*)malloc(start_keylen);
            memcpy(startKey.data, start_key, start_keylen);
            startKey.len = start_keylen;
        }

        if (end_key == NULL) {
            endKey.data = NULL;
            endKey.len = 0;
        } else {
            endKey.data = (void*)malloc(end_keylen);
            memcpy(endKey.data, end_key, end_keylen);
            endKey.len = end_keylen;
        }
    }

    // create an iterator handle for hb-trie
    hbtrieIterator = new HBTrieIterator(iterHandle->trie,
                                        (void *)start_key,
                                        start_keylen);

    walIterator = new WalItr(iterHandle->file,
                             iterHandle->shandle,
                             true);

    if (start_key) {
        struct wal_item query;
        struct wal_item_header query_key;
        query.header = &query_key;
        query_key.key = startKey.data;
        query_key.keylen = startKey.len;
        treeCursor = walIterator->searchGreater_WalItr(&query);
    } else {
        treeCursor = walIterator->first_WalItr();
    }

    // to know reverse iteration endpoint store the start cursor
    if (treeCursor) {
        treeCursorStart = treeCursor;
    }
    treeCursorPrev = treeCursor;

    // Increment the iterator counter of the KV handle
    ++iterHandle->num_iterators;
}

FdbIterator::FdbIterator(FdbKvsHandle *_handle,
                         bool snapshoted_handle,
                         const fdb_seqnum_t start_seq,
                         const fdb_seqnum_t end_seq,
                         fdb_iterator_opt_t opt)
    : iterHandle(_handle), snapshotHandle(snapshoted_handle),
      hbtrieIterator(nullptr), seqtreeIterator(nullptr),
      seqtrieIterator(nullptr), seqNum(start_seq),
      startSeqnum(start_seq), iterOpt(opt), iterDirection(FDB_ITR_DIR_NONE),
      iterStatus(FDB_ITR_IDX), iterKey({nullptr, 0}),
      iterOffset(BLK_NOT_FOUND), dHandle(nullptr), getOffset(0),
      iterType(FDB_ITR_SEQ)
{
    // For easy API call, treat zero seq as 0xffff...
    // (because zero seq number is not used)
    if (end_seq == 0) {
        endSeqnum = SEQNUM_NOT_USED;
    } else {
        endSeqnum = end_seq;
    }

    walIterator = new WalItr(_handle->file, iterHandle->shandle, false);

    fdb_seqnum_t _start_seq = _endian_encode(start_seq);
    fdb_kvs_id_t _kv_id;
    size_t size_id = sizeof(fdb_kvs_id_t);
    size_t size_seq = sizeof(fdb_seqnum_t);
    uint8_t *start_seq_kv;
    struct wal_item query;
    query.shandle = iterHandle->shandle;
    if (iterHandle->kvs) {
        int size_chunk = _handle->config.chunksize;
        // create an iterator handle for hb-trie
        start_seq_kv = alca(uint8_t, size_chunk + size_seq);
        _kv_id = _endian_encode(iterHandle->kvs->getKvsId());
        memcpy(start_seq_kv, &_kv_id, size_id);
        memcpy(start_seq_kv + size_id, &_start_seq, size_seq);

        seqtrieIterator = new HBTrieIterator(iterHandle->seqtrie,
                                             start_seq_kv,
                                             size_id + size_seq);

        query.seqnum = start_seq;
        treeCursor = walIterator->searchGreater_WalItr(&query);
    } else {
        // create an iterator handle for b-tree
        seqtreeIterator = new BTreeIterator(iterHandle->seqtree,
                              (void *)( start_seq ? (&_start_seq) : (NULL) ));

        query.seqnum = start_seq;
        treeCursor = walIterator->searchGreater_WalItr(&query);
    }

    // to know reverse iteration endpoint store the start cursor
    if (treeCursor) {
        treeCursorStart = treeCursor;
    }
    treeCursorPrev = treeCursor;

    // Increment the iterator counter of the KV handle
    ++iterHandle->num_iterators;
}

FdbIterator::~FdbIterator()
{
    if (hbtrieIterator) {
        delete hbtrieIterator;
    }

    if (seqtreeIterator) {
        delete seqtreeIterator;
    }

    if (seqtrieIterator) {
        delete seqtrieIterator;
    }

    if (ver_btreev2_format(iterHandle->file->getVersion())) {
        iterHandle->bnodeMgr->releaseCleanNodes();
    }

    if (iterType == FDB_ITR_REG) {
        // Free startKey, endKey data which would've been
        // allocated in case of a regular iterator.
        free(startKey.data);
        free(endKey.data);
    }

    // Decrement the iterator counter of the KV handle
    --iterHandle->num_iterators;

    delete walIterator;

    if (iterKey.data) {
        free(iterKey.data);
    }

    if (!snapshotHandle) {
        // Close the opened handle in the iterator,
        // if the handle is not for snapshot.
        fdb_status fs = FdbEngine::getInstance()->closeKvs(iterHandle);
        if (fs != FDB_RESULT_SUCCESS) {
            fdb_log(&iterHandle->log_callback, fs,
                    "Failed to close the KV Store from a database file '%s' as "
                    "part of closing the iterator",
                    iterHandle->file->getFileName());
        }
    }
}

fdb_status FdbIterator::initIterator(FdbKvsHandle *handle,
                                     fdb_iterator **ptr_iterator,
                                     const void *start_key,
                                     size_t start_keylen,
                                     const void *end_key,
                                     size_t end_keylen,
                                     fdb_iterator_opt_t opt) {

    fdb_status fs = FDB_RESULT_SUCCESS;

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

    if (ptr_iterator == NULL ||
        (opt & FDB_ITR_SKIP_MIN_KEY && (!start_key || !start_keylen)) ||
        (opt & FDB_ITR_SKIP_MAX_KEY && (!end_key || !end_keylen))) {
        return FDB_RESULT_INVALID_ARGS;
    }

    if (!handle->shandle) {
        // If compaction is already done before this line,
        // handle->file needs to be replaced with handle->new_file.
        fs = fdb_check_file_reopen(handle, NULL);
        if (fs != FDB_RESULT_SUCCESS) {
            return fs;
        }
        fdb_sync_db_header(handle);
    }

    LATENCY_STAT_START();

    FdbIterator *iterator;
    if (!handle->shandle) {
        // snapshot handle doesn't exist
        // open a new handle to make the iterator handle as a snapshot
        FdbKvsHandle *new_handle;
        fs = fdb_snapshot_open(handle, &new_handle, FDB_SNAPSHOT_INMEM);
        if (fs != FDB_RESULT_SUCCESS) {
            fdb_log(&handle->log_callback, fs,
                    "Failed to create an iterator instance due to the failure of "
                    "open operation on the KV Store '%s' in a database file '%s'",
                    _fdb_kvs_get_name(handle, handle->file),
                    handle->file->getFileName());
            return fs;
        }

        iterator = new FdbIterator(new_handle, false, start_key, start_keylen,
                                   end_key, end_keylen, opt);
    } else {
        // Snapshot handle exists
        // We don't need to open a new handle.. just point to the snapshot handle.
        iterator = new FdbIterator(handle, true, start_key, start_keylen,
                                   end_key, end_keylen, opt);
    }

    *ptr_iterator = iterator;

    iterator->iterateToNext(); // position cursor at first key

    LATENCY_STAT_END(iterator->getHandle()->file, FDB_LATENCY_ITR_INIT);

    return FDB_RESULT_SUCCESS;
}

fdb_status FdbIterator::initSeqIterator(FdbKvsHandle *handle,
                                        fdb_iterator **ptr_iterator,
                                        const fdb_seqnum_t start_seq,
                                        const fdb_seqnum_t end_seq,
                                        fdb_iterator_opt_t opt) {

    fdb_status fs = FDB_RESULT_SUCCESS;

    if (!handle) {
        return FDB_RESULT_INVALID_HANDLE;
    }

    if (ptr_iterator == NULL || (end_seq && start_seq > end_seq)) {
        return FDB_RESULT_INVALID_ARGS;
    }

    // Sequence trees are a must for byseq operations
    if (handle->config.seqtree_opt != FDB_SEQTREE_USE) {
        return FDB_RESULT_INVALID_CONFIG;
    }

    if (!handle->shandle) {
        // If compaction is already done before this line,
        // handle->file needs to be replaced with handle->new_file.
        fs = fdb_check_file_reopen(handle, NULL);
        if (fs != FDB_RESULT_SUCCESS) {
            return fs;
        }
        fdb_sync_db_header(handle);
    }

    LATENCY_STAT_START();

    FdbIterator *iterator;

    if (!handle->shandle) {
        // snapshot handle doesn't exist
        // open a new handle to make the iterator handle as a snapshot
        FdbKvsHandle *new_handle;
        fs = fdb_snapshot_open(handle, &new_handle, FDB_SNAPSHOT_INMEM);
        if (fs != FDB_RESULT_SUCCESS) {
            fdb_log(&handle->log_callback, fs,
                    "Failed to create an sequence iterator instance due to the "
                    "failure of "
                    "open operation on the KV Store '%s' in a database file '%s'",
                    _fdb_kvs_get_name(handle, handle->file),
                    handle->file->getFileName());
            return fs;
        }
        iterator = new FdbIterator(new_handle, false, start_seq, end_seq, opt);
    } else {
        // Snapshot handle exists
        // We don't need to open a new handle.. just point to the snapshot handle.
        iterator = new FdbIterator(handle, true, start_seq, end_seq, opt);
    }

    *ptr_iterator = iterator;

    iterator->iterateToNext(); // position cursor at first key

    LATENCY_STAT_END(iterator->getHandle()->file, FDB_LATENCY_ITR_SEQ_INIT);

    return FDB_RESULT_SUCCESS;
}

fdb_status FdbIterator::destroyIterator(fdb_iterator *iterator) {
    if (!iterator || !iterator->getHandle()) {
        return FDB_RESULT_INVALID_HANDLE;
    }

    FileMgr *file = iterator->getHandle()->file;

    LATENCY_STAT_START();

    delete iterator;

    LATENCY_STAT_END(file, FDB_LATENCY_ITR_CLOSE);

    return FDB_RESULT_SUCCESS;
}

fdb_status FdbIterator::seek(const void *seek_key,
                             const size_t seek_keylen,
                             const fdb_iterator_seek_opt_t seek_pref,
                             const bool seek_min_max) {

    int cmp, cmp2; // intermediate results of comparison
    int next_op = 0; // 0: none, -1: prev(), 1: next();
    int size_chunk = iterHandle->config.chunksize;
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

    dHandle = NULL; // setup for get() to return FAIL

    if (!seek_key || !iterKey.data ||
        seek_keylen > FDB_MAX_KEYLEN ||
        (iterHandle->kvs_config.custom_cmp &&
         seek_keylen > iterHandle->config.blocksize - HBTRIE_HEADROOM)) {
        return FDB_RESULT_INVALID_ARGS;
    }

    if (!BEGIN_HANDLE_BUSY(iterHandle)) {
        return FDB_RESULT_HANDLE_BUSY;
    }

    iterHandle->op_stats->num_iterator_moves++;

    if (iterHandle->kvs) {
        seek_keylen_kv = seek_keylen + size_chunk;
        seek_key_kv = alca(uint8_t, seek_keylen_kv);
        kvid2buf(size_chunk, iterHandle->kvs->getKvsId(), seek_key_kv);
        memcpy(seek_key_kv + size_chunk, seek_key, seek_keylen);
    } else {
        seek_keylen_kv = seek_keylen;
        seek_key_kv = (uint8_t*)seek_key;
    }

    // disable seeking beyond the end key...
    if (endKey.data) {
        cmp = _fdb_key_cmp(this, endKey.data, endKey.len,
                           (void *)seek_key_kv, seek_keylen_kv);
        if (cmp == 0 && iterOpt & FDB_ITR_SKIP_MAX_KEY) {
            // seek the end key at this time,
            // and call prev() next iff caller is seek_to_max()
            if (seek_min_max) {
                next_op = -1;
            }
        }
        if (cmp < 0) {
            END_HANDLE_BUSY(iterHandle);
            return FDB_RESULT_ITERATOR_FAIL;
        }
    }

    // disable seeking beyond the start key...
    if (startKey.data) {
        cmp = _fdb_key_cmp(this, startKey.data, startKey.len,
                           (void *)seek_key_kv, seek_keylen_kv);
        if (cmp == 0 && iterOpt & FDB_ITR_SKIP_MIN_KEY) {
            // seek the start key at this time,
            // and call next() next iff caller is seek_to_min()
            if (seek_min_max) {
                next_op = 1;
            }
        }
        if (cmp > 0) {
            END_HANDLE_BUSY(iterHandle);
            return FDB_RESULT_ITERATOR_FAIL;
        }
    }

    iterDirection = FDB_ITR_FORWARD;

    // reset HB+trie's iterator
    delete hbtrieIterator;
    hbtrieIterator = new HBTrieIterator(iterHandle->trie,
                                        seek_key_kv, seek_keylen_kv);

fetch_hbtrie:
    if (seek_pref == FDB_ITR_SEEK_HIGHER) {
        // fetch next key
        hr = hbtrieIterator->next(iterKey.data, iterKey.len, (void*)&iterOffset);
        if (!ver_btreev2_format(iterHandle->file->getVersion())) {
            iterHandle->bhandle->flushBuffer();
        }

        if (hr == HBTRIE_RESULT_SUCCESS) {
            cmp = _fdb_key_cmp(this, iterKey.data, iterKey.len,
                               seek_key_kv, seek_keylen_kv);
            if (cmp < 0) {
                // key[HB+trie] < seek_key .. move forward
                hr = hbtrieIterator->next(iterKey.data, iterKey.len,
                                          &iterOffset);
                if (!ver_btreev2_format(iterHandle->file->getVersion())) {
                    iterHandle->bhandle->flushBuffer();
                }
            }
            iterOffset = _endian_decode(iterOffset);

            while (iterOpt & FDB_ITR_NO_DELETES &&
                   hr == HBTRIE_RESULT_SUCCESS &&
                   fetch_next) {
                fetch_next = false;
                memset(&_doc, 0x0, sizeof(struct docio_object));
                _offset = iterHandle->dhandle->readDocKeyMeta_Docio(iterOffset,
                                                                    &_doc,
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
                    hr = hbtrieIterator->next(iterKey.data, iterKey.len,
                                              (void*)&iterOffset);
                    if (!ver_btreev2_format(iterHandle->file->getVersion())) {
                        iterHandle->bhandle->flushBuffer();
                    }
                    iterOffset = _endian_decode(iterOffset);
                }
            }
        }
    } else {
        // fetch prev key
        hr = hbtrieIterator->prev(iterKey.data, iterKey.len, (void*)&iterOffset);
        if (!ver_btreev2_format(iterHandle->file->getVersion())) {
            iterHandle->bhandle->flushBuffer();
        }
        if (hr == HBTRIE_RESULT_SUCCESS) {
            cmp = _fdb_key_cmp(this, iterKey.data, iterKey.len,
                               seek_key_kv, seek_keylen_kv);
            if (cmp > 0) {
                // key[HB+trie] > seek_key .. move backward
                hr = hbtrieIterator->prev(iterKey.data, iterKey.len,
                                          (void*)&iterOffset);

                if (!ver_btreev2_format(iterHandle->file->getVersion())) {
                    iterHandle->bhandle->flushBuffer();
                }
            }
            iterOffset = _endian_decode(iterOffset);

            while (iterOpt & FDB_ITR_NO_DELETES &&
                   hr == HBTRIE_RESULT_SUCCESS &&
                   fetch_next) {
                fetch_next = false;
                memset(&_doc, 0x0, sizeof(struct docio_object));
                _offset = iterHandle->dhandle->readDocKeyMeta_Docio(iterOffset,
                                                                    &_doc,
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
                    hr = hbtrieIterator->prev(iterKey.data, iterKey.len,
                                              (void*)&iterOffset);
                    if (!ver_btreev2_format(iterHandle->file->getVersion())) {
                        iterHandle->bhandle->flushBuffer();
                    }
                    iterOffset = _endian_decode(iterOffset);
                }
            }
        }
    }

    if (hr == HBTRIE_RESULT_SUCCESS && // Validate iteration range limits..
        !next_op) { // only if caller is not seek_to_max/min (handled later)
        if (!validateRangeLimits(iterKey.data, iterKey.len)) {
            hr = HBTRIE_RESULT_FAIL;
        }
    }

    if (iterHandle->kvs) {
        fdb_kvs_id_t kv_id;
        buf2kvid(size_chunk, iterKey.data, &kv_id);
        if (iterHandle->kvs->getKvsId() != kv_id) {
            // seek is done beyond the KV ID
            hr = HBTRIE_RESULT_FAIL;
        }
    }
    if (hr == HBTRIE_RESULT_SUCCESS) {
        getOffset = iterOffset;
        dHandle = iterHandle->dhandle;
    } else {
        // larger than the largest key or smaller than the smallest key
        getOffset = BLK_NOT_FOUND;
        dHandle = NULL;
    }

    // HB+trie's iterator should fetch another entry next time
    iterOffset = BLK_NOT_FOUND;
    iterStatus = FDB_ITR_IDX;

    // retrieve avl-tree
    query.header = &query_header;
    query_header.key = seek_key_kv;
    query_header.keylen = seek_keylen_kv;

    if (seek_pref == FDB_ITR_SEEK_HIGHER) {
        if (fetch_wal) {
            treeCursor = walIterator->searchGreater_WalItr(&query);
            iterDirection = FDB_ITR_FORWARD;
        }
        if (treeCursor) {
            // skip deleted WAL entry
            do {
                if (!next_op && // only validate range if not skip max/min key mode
                    !validateRangeLimits(treeCursor->header->key,
                                         treeCursor->header->keylen)) {
                    treeCursor = NULL;
                    break;
                }
                snap_item = treeCursor;
                if ((snap_item->action == WAL_ACT_LOGICAL_REMOVE && // skip
                    iterOpt & FDB_ITR_NO_DELETES) || //logical delete OR
                    snap_item->action == WAL_ACT_REMOVE) { // immediate purge
                    if (dHandle) {
                        cmp = _fdb_key_cmp(this,
                                           snap_item->header->key,
                                           snap_item->header->keylen,
                                           iterKey.data, iterKey.len);
                        if (cmp == 0) {
                            // same doc exists in HB+trie
                            // move tree cursor
                            treeCursor = walIterator->next_WalItr();
                            // do not move tree cursor next time
                            fetch_wal = false;
                            // fetch next key[HB+trie]
                            goto fetch_hbtrie;
                        } else if (cmp > 0) {
                            break;
                        }
                    }
                    treeCursor = walIterator->next_WalItr();
                    continue;
                } else if (endKey.data &&
                           iterOpt & FDB_ITR_SKIP_MAX_KEY) {
                    cmp = _fdb_key_cmp(this,
                                       endKey.data, endKey.len,
                                       snap_item->header->key,
                                       snap_item->header->keylen);
                    if (cmp == 0 ||
                        // WAL cursor is positioned exactly at seeked end key
                        // but iterator must skip the end key!
                        // If hb+trie has an item, use that else return FAIL
                        (cmp < 0 &&// WAL key out of range...
                        !next_op)) { // Not called from FdbIterator::seekToMax()
                        skip_wal = true;
                        iterStatus = FDB_ITR_WAL;
                    }
                }
                break;
            } while(treeCursor);
        }
        treeCursorPrev = treeCursor;
        if (!treeCursor) {
            // seek_key is larger than the largest key
            // set prev key to the largest key.
            // if prev operation is called next, treeCursor will be set to
            // treeCursorPrev.
            treeCursorPrev = walIterator->searchSmaller_WalItr(&query);
            skip_wal = true;
        }
    } else if (seek_pref == FDB_ITR_SEEK_LOWER) {
        if (fetch_wal) {
            treeCursor = walIterator->searchSmaller_WalItr(&query);
            iterDirection = FDB_ITR_REVERSE;
        }
        if (treeCursor) {
            // skip deleted WAL entry
            do {
                if (!next_op && // only validate range if not skip max/min key mode
                    !validateRangeLimits(treeCursor->header->key,
                                         treeCursor->header->keylen)) {
                    treeCursor = NULL;
                    break;
                }
                snap_item = treeCursor;
                if ((snap_item->action == WAL_ACT_LOGICAL_REMOVE && // skip
                     iterOpt & FDB_ITR_NO_DELETES) || //logical delete OR
                     snap_item->action == WAL_ACT_REMOVE) { //immediate purge
                    if (dHandle) {
                        cmp = _fdb_key_cmp(this,
                                           snap_item->header->key,
                                           snap_item->header->keylen,
                                           iterKey.data, iterKey.len);
                        if (cmp == 0) {
                            // same doc exists in HB+trie
                            // move tree cursor
                            treeCursor = walIterator->prev_WalItr();
                            // do not move tree cursor next time
                            fetch_wal = false;
                            // fetch next key[HB+trie]
                            goto fetch_hbtrie;
                        } else if (cmp < 0) {
                            break;
                        }
                    }
                    treeCursor = walIterator->prev_WalItr();
                    continue;
                } else if (startKey.data &&
                           iterOpt & FDB_ITR_SKIP_MIN_KEY) {
                    cmp = _fdb_key_cmp(this,
                                       snap_item->header->key,
                                       snap_item->header->keylen,
                                       startKey.data, startKey.len);
                    if (cmp == 0 ||
                        // WAL cursor is positioned exactly at seeked start key
                        // but iterator must skip the start key!
                        // If hb+trie has an item, use that else return FAIL
                        (cmp < 0 && // WAL key out of range and
                        !next_op)) { // Not called from FdbIterator::seekToMin()
                        skip_wal = true;
                        iterStatus = FDB_ITR_WAL;
                    }
                }
                break;
            } while(treeCursor);
        }
        treeCursorPrev = treeCursor;
        if (!treeCursor) {
            // seek_key is smaller than the smallest key
            // Only allow FdbIterator::iterateToNext() call,
            // FdbIterator::iterateToPrev() should hit failure.
            // To ensure this set the direction to as if
            // FdbIterator::iterateToPrev() call has gone past the
            // smallest key...
            treeCursorPrev = walIterator->searchGreater_WalItr(&query);
            // since the current key[WAL] is smaller than seek_key,
            // skip key[WAL] this time
            skip_wal = true;
        }
    }

    if (treeCursor && !skip_wal) {
        bool take_wal = false;
        bool discard_hbtrie = false;

        snap_item = treeCursor;

        if (hr == HBTRIE_RESULT_SUCCESS) {
            cmp = _fdb_key_cmp(this,
                               snap_item->header->key, snap_item->header->keylen,
                               iterKey.data, iterKey.len);

            if (cmp == 0) {
                // same key exists in both HB+trie and WAL
                fdb_assert(snap_item->action != WAL_ACT_REMOVE,
                           snap_item->action, iterOffset);
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
                        if (endKey.data) {
                            cmp2 = _fdb_key_cmp(this,
                                                iterKey.data, iterKey.len,
                                                endKey.data, endKey.len);
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
                        if (startKey.data) {
                            cmp2 = _fdb_key_cmp(this,
                                                startKey.data, startKey.len,
                                                iterKey.data, iterKey.len);
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
                    delete hbtrieIterator;
                    hbtrieIterator = new HBTrieIterator(iterHandle->trie,
                                                        seek_key_kv,
                                                        seek_keylen_kv);
                    iterOffset = BLK_NOT_FOUND;
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
                iterOffset = getOffset;
            }
            getOffset = snap_item->offset;
            dHandle = iterHandle->dhandle;
            iterStatus = FDB_ITR_WAL;
        }
    }

    END_HANDLE_BUSY(iterHandle);
    if (!dHandle) {
        return FDB_RESULT_ITERATOR_FAIL;
    }

    if (next_op < 0) {
        ret = iterateToPrev();
    } else if (next_op > 0) {
        ret = iterateToNext();
    } else {
        ret = FDB_RESULT_SUCCESS;
    }

    LATENCY_STAT_END(iterHandle->file, FDB_LATENCY_ITR_SEEK);
    return ret;
}

fdb_status FdbIterator::seekToMin() {
    size_t size_chunk = iterHandle->config.chunksize;
    fdb_status ret;
    LATENCY_STAT_START();

    // Initialize direction iteration to FORWARD just in case this function was
    // called right after FdbIterator::initIterator() so the cursor gets
    // positioned correctly
    iterDirection = FDB_ITR_FORWARD;
    if (startKey.len > size_chunk) {
        fdb_iterator_seek_opt_t dir = (iterOpt & FDB_ITR_SKIP_MIN_KEY) ?
                                      FDB_ITR_SEEK_HIGHER : FDB_ITR_SEEK_LOWER;
        fdb_status status = seek((uint8_t *)startKey.data + size_chunk,
                                 startKey.len - size_chunk,
                                 dir, true);// not regular seek
        if (status != FDB_RESULT_SUCCESS && dir == FDB_ITR_SEEK_LOWER) {
            dir = FDB_ITR_SEEK_HIGHER;
            // It is possible that the min key specified during init does not
            // exist, so retry the seek with the HIGHER key
            return seek((uint8_t *)startKey.data + size_chunk,
                        startKey.len - size_chunk,
                        dir, true); // not a regular seek
        }
        return status;
    }

    // reset HB+trie iterator using start key
    delete hbtrieIterator;
    hbtrieIterator = new HBTrieIterator(iterHandle->trie,
                                        startKey.data, startKey.len);

    // reset WAL tree cursor using search because of the sharded nature of WAL
    if (treeCursorStart) {
        treeCursorPrev = treeCursor = walIterator->searchGreater_WalItr(
                                                            treeCursorStart);
        iterStatus = FDB_ITR_IDX; // WAL is already set
    }

    ret = iterateToNext();
    LATENCY_STAT_END(iterHandle->file, FDB_LATENCY_ITR_SEEK_MIN);
    return ret;
}

fdb_status FdbIterator::seekToMax() {
    fdb_status ret;
    LATENCY_STAT_START();

    if (!hbtrieIterator) {
        ret = seekToMaxSeq();
    } else {
        ret = seekToMaxKey();
    }

    LATENCY_STAT_END(iterHandle->file, FDB_LATENCY_ITR_SEEK_MAX);
    return ret;
}

fdb_status FdbIterator::iterateToPrev() {
    fdb_status result = FDB_RESULT_SUCCESS;
    LATENCY_STAT_START();

    if (!BEGIN_HANDLE_BUSY(iterHandle)) {
        return FDB_RESULT_HANDLE_BUSY;
    }

    if (hbtrieIterator) {
        while ((result = iterate(ITR_SEEK_PREV)) == FDB_RESULT_KEY_NOT_FOUND);
    } else {
        while ((result = iterateSeqPrev()) == FDB_RESULT_KEY_NOT_FOUND);
    }
    if (result == FDB_RESULT_SUCCESS) {
        iterDirection = FDB_ITR_REVERSE;
    } else {
        dHandle = NULL; // fail FdbIterator::get() also
        if (iterDirection != FDB_ITR_DIR_NONE) {
            if ((seqtreeIterator || seqtrieIterator) &&
                iterStatus == FDB_ITR_IDX) {

                iterOffset = BLK_NOT_FOUND;
            }
        }
    }

    END_HANDLE_BUSY(iterHandle);
    iterHandle->op_stats->num_iterator_moves++;
    LATENCY_STAT_END(iterHandle->file, FDB_LATENCY_ITR_PREV);
    return result;
}

fdb_status FdbIterator::iterateToNext() {
    fdb_status result = FDB_RESULT_SUCCESS;
    LATENCY_STAT_START();

    if (!BEGIN_HANDLE_BUSY(iterHandle)) {
        return FDB_RESULT_HANDLE_BUSY;
    }

    if (hbtrieIterator) {
        while ((result = iterate(ITR_SEEK_NEXT)) == FDB_RESULT_KEY_NOT_FOUND);
    } else {
        while ((result = iterateSeqNext()) == FDB_RESULT_KEY_NOT_FOUND);
    }
    if (result == FDB_RESULT_SUCCESS) {
        iterDirection = FDB_ITR_FORWARD;
    } else {
        dHandle = NULL; // fail FdbIterator::get() also
        if (iterDirection != FDB_ITR_DIR_NONE) {
            if ((seqtreeIterator || seqtrieIterator) &&
                iterStatus == FDB_ITR_IDX) {

                iterOffset = BLK_NOT_FOUND;
            }
        }
    }

    END_HANDLE_BUSY(iterHandle);
    iterHandle->op_stats->num_iterator_moves++;
    LATENCY_STAT_END(iterHandle->file, FDB_LATENCY_ITR_NEXT);
    return result;
}

fdb_status FdbIterator::get(fdb_doc **doc, bool metaOnly) {

    if (!doc) {
        return FDB_RESULT_INVALID_ARGS;
    }

    struct docio_object _doc;
    fdb_status ret = FDB_RESULT_SUCCESS;
    uint64_t offset;
    DocioHandle *dhandle;
    size_t size_chunk = iterHandle->config.chunksize;
    bool alloced_key, alloced_meta, alloced_body;
    LATENCY_STAT_START();

    dhandle = dHandle;
    if (!dhandle || getOffset == BLK_NOT_FOUND) {
        return FDB_RESULT_ITERATOR_FAIL;
    }

    if (!BEGIN_HANDLE_BUSY(iterHandle)) {
        return FDB_RESULT_HANDLE_BUSY;
    }

    offset = getOffset;

    if (*doc == NULL) {
        ret = fdb_doc_create(doc, NULL, 0, NULL, 0, NULL, 0);
        if (ret != FDB_RESULT_SUCCESS) { // LCOV_EXCL_START
            END_HANDLE_BUSY(iterHandle);
            return ret;
        } // LCOV_EXCL_STOP

        _doc.key = NULL;
        _doc.length.keylen = 0;
        _doc.meta = NULL;
        _doc.body = NULL;
        alloced_key = true;
        alloced_meta = true;
        alloced_body = metaOnly ? false : true;
    } else {
        _doc.key = (*doc)->key;
        _doc.meta = (*doc)->meta;
        _doc.body = metaOnly ? NULL : (*doc)->body;
        alloced_key = _doc.key ? false : true;
        alloced_meta = _doc.meta ? false : true;
        alloced_body = (metaOnly || _doc.body) ? false : true;
    }

    int64_t _offset = 0;
    if (metaOnly) {
        _offset = dhandle->readDocKeyMeta_Docio(offset, &_doc, true);
    } else {
        _offset = dhandle->readDoc_Docio(offset, &_doc, true);
    }

    if (_offset <= 0) {
        END_HANDLE_BUSY(iterHandle);
        return _offset < 0 ? (fdb_status) _offset : FDB_RESULT_KEY_NOT_FOUND;
    }
    if ((_doc.length.flag & DOCIO_DELETED) &&
        (iterOpt & FDB_ITR_NO_DELETES)) {

        END_HANDLE_BUSY(iterHandle);
        free_docio_object(&_doc, alloced_key, alloced_meta, alloced_body);
        return FDB_RESULT_KEY_NOT_FOUND;
    }

    if (iterHandle->kvs && _doc.key) {
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

    END_HANDLE_BUSY(iterHandle);
    iterHandle->op_stats->num_iterator_gets++;
    if (metaOnly) {
        LATENCY_STAT_END(iterHandle->file, FDB_LATENCY_ITR_GET_META);
    } else {
        LATENCY_STAT_END(iterHandle->file, FDB_LATENCY_ITR_GET);
    }

    return ret;
}

fdb_status FdbIterator::iterate(itr_seek_t seek_type) {
    int cmp;
    void *key;
    size_t keylen;
    uint64_t offset;
    hbtrie_result hr = HBTRIE_RESULT_SUCCESS;
    DocioHandle *dhandle;
    struct wal_item *snap_item = NULL;

    if (seek_type == ITR_SEEK_PREV && iterDirection != FDB_ITR_REVERSE) {
        iterOffset = BLK_NOT_FOUND; // need to re-examine Trie/trees
        if (treeCursor) {
            // just turn around
            // WAL:   0  v  2->   4    (OLD state)
            // TRIE:     1  2  3  4
            treeCursor = walIterator->searchSmaller_WalItr(treeCursor);
            if (iterDirection == FDB_ITR_FORWARD &&
                iterStatus != FDB_ITR_WAL) {
                treeCursor = walIterator->prev_WalItr();
            }
            // WAL: <-0  v  2     4    (NEW state)
            // TRIE:  0  1  2  3  4
        } else if (treeCursorPrev) { // gone past the end..
            treeCursor = walIterator->searchSmaller_WalItr(treeCursorPrev);
            iterStatus = FDB_ITR_IDX;
        } // else Don't move - seek()/init() has already positioned cursor

    } else if (seek_type == ITR_SEEK_NEXT && iterDirection != FDB_ITR_FORWARD) {
        iterOffset = BLK_NOT_FOUND; // need to re-examine Trie/trees
        // just turn around and face forward..
        if (treeCursor) {
            // WAL: <-0  v  2     4    (OLD state)
            // TRIE:     1  2  3  4
            treeCursor = walIterator->searchGreater_WalItr(treeCursor);
            if (iterDirection == FDB_ITR_REVERSE &&
                iterStatus != FDB_ITR_WAL) {
                treeCursor = walIterator->next_WalItr();
            }
            // WAL:   0  v  2->   4    (NEW state)
            // TRIE:  0  1  2  3  4
        } else if (treeCursorPrev) {
            treeCursor = walIterator->searchGreater_WalItr(treeCursorPrev);
            iterStatus = FDB_ITR_IDX;
        } // else Don't move - seek()/init() has already positioned cursor

    }

start:
    key = iterKey.data;
    dhandle = iterHandle->dhandle;

    // retrieve from hb-trie
    if (iterOffset == BLK_NOT_FOUND) {
        // no key waiting to being returned
        // get next key from hb-trie (or idtree)
        struct docio_object _doc;
        // Move Main index Cursor backward or forward based on seek type...
        int64_t _offset;
        do {
            if (seek_type == ITR_SEEK_PREV) {
                hr = hbtrieIterator->prev(key, iterKey.len, (void*)&iterOffset);
            } else { // seek_type == ITR_SEEK_NEXT
                hr = hbtrieIterator->next(key, iterKey.len, (void*)&iterOffset);
            }
            if (!ver_btreev2_format(iterHandle->file->getVersion())) {
                iterHandle->bhandle->flushBuffer();
            }
            iterOffset = _endian_decode(iterOffset);
            if (!(iterOpt & FDB_ITR_NO_DELETES) ||
                  hr != HBTRIE_RESULT_SUCCESS) {
                break;
            }
            // deletion check
            memset(&_doc, 0x0, sizeof(struct docio_object));
            _offset = dhandle->readDocKeyMeta_Docio(iterOffset, &_doc, true);
            if (_offset <= 0) { // read fail
                continue; // get prev/next doc
            }
            if (_doc.length.flag & DOCIO_DELETED) { // deleted doc
                free(_doc.key);
                free(_doc.meta);
                continue; // get prev/next doc
            }
            free(_doc.key);
            free(_doc.meta);
            break;
        } while (1);
    }

    keylen = iterKey.len;
    offset = iterOffset;

    if (hr != HBTRIE_RESULT_SUCCESS && !treeCursor) {
        return FDB_RESULT_ITERATOR_FAIL;
    }

    // Move the WAL cursor backward/forward based on seek type...
    while (treeCursor) {
        if (iterStatus == FDB_ITR_WAL) {
            treeCursorPrev = treeCursor;
            treeCursor = (seek_type == ITR_SEEK_PREV) ?
                                walIterator->prev_WalItr() :
                                walIterator->next_WalItr();

        } // else don't move - seek()/ init() has already positioned cursor

        // get the current item of avl-tree
        snap_item = treeCursor;
        if (!snap_item) {
            if (hr == HBTRIE_RESULT_SUCCESS) {
                break;
            } else { // no more keys in WAL or main index
                return FDB_RESULT_ITERATOR_FAIL;
            }
        }

        // Compare key[WAL] with key[hb-trie]
        if (hr == HBTRIE_RESULT_SUCCESS) {
            cmp = _fdb_key_cmp(this, snap_item->header->key,
                               snap_item->header->keylen,
                               key, keylen);
        } else {
            // no more docs in hb-trie
            cmp = (seek_type == ITR_SEEK_PREV) ? 1 : -1;
        }

        if (((seek_type == ITR_SEEK_PREV) && cmp >= 0) ||
            ((seek_type == ITR_SEEK_NEXT) && cmp <= 0)) {
            /**
             * In case of ITR_SEEK_PREV:
             *      key[WAL] >= key[hb-trie] .. take key[WAL] first
             * In case of ITR_SEEK_NEXT:
             *      key[WAL] <= key[hb-trie] .. take key[WAL] first
             */
            uint8_t drop_logical_deletes =
                            (snap_item->action == WAL_ACT_LOGICAL_REMOVE) &&
                            (iterOpt & FDB_ITR_NO_DELETES);
            iterStatus = FDB_ITR_WAL;

            if (cmp != 0) {
                if (snap_item->action == WAL_ACT_REMOVE ||
                    drop_logical_deletes) {
                    // this key is removed .. get prev/next key[WAL]
                    continue;
                }
            } else { // same key (from trie) found in WAL
                iterOffset = BLK_NOT_FOUND; // drop key from trie
                if (snap_item->action == WAL_ACT_REMOVE ||
                    drop_logical_deletes) {
                    // the key is removed .. start over again
                    goto start;
                }
            }

            key = snap_item->header->key;
            keylen = snap_item->header->keylen;
            // key[hb-trie] is stashed in iterKey for next call
            offset = snap_item->offset;
        }
        break;
    }

    if (offset == iterOffset) {
        // take key[hb-trie] & and fetch the prev/next key[hb-trie] in next turn
        iterOffset = BLK_NOT_FOUND;
        iterStatus = FDB_ITR_IDX;
    }

    if (startKey.data) {
        cmp = _fdb_key_cmp(this, startKey.data,
                           startKey.len, key, keylen);

        if ((cmp == 0 && iterOpt & FDB_ITR_SKIP_MIN_KEY) || cmp > 0) {
            if (seek_type == ITR_SEEK_PREV) {
                // current key (KEY) is lexicographically less than START_KEY
                // OR it is the start key and user wishes to skip it..
                // terminate the iteration
                return FDB_RESULT_ITERATOR_FAIL;
            } else { // seek_type == ITR_SEEK_NEXT
                // If user wishes to skip start key, redo first step
                // OR current key (KEY) is lexicographically smaller than START_KEY
                goto start;
            }
        }
    }

    if (endKey.data) {
        cmp = _fdb_key_cmp(this,
                           endKey.data, endKey.len,
                           key, keylen);

        if ((cmp == 0 && iterOpt & FDB_ITR_SKIP_MAX_KEY) || cmp < 0) {
            if (seek_type == ITR_SEEK_PREV) {
                // key is the endKey but users wishes to skip it, redo..
                // OR current key (KEY) is lexicographically greater than END_KEY
                goto start;
            } else { // seek_type == ITR_SEEK_NEXT
                // current key (KEY) is lexicographically greater than END_KEY
                // OR it is the endKey and user wishes to skip it
                // terminate the iteration
                return FDB_RESULT_ITERATOR_FAIL;
            }
        }
    }

    dHandle = dhandle; // store for FdbIterator::get()
    getOffset = offset; // store for FdbIterator::get()

    return FDB_RESULT_SUCCESS;
}

bool FdbIterator::validateRangeLimits(void *ret_key,
                                      const size_t ret_keylen) {
    int cmp;

    if (endKey.data) {
        cmp = _fdb_key_cmp(this, ret_key, ret_keylen,
                           endKey.data, endKey.len);
        if ((cmp == 0 && iterOpt & FDB_ITR_SKIP_MAX_KEY) ||
            cmp > 0) { // greater than endKey OR at skipped MAX_KEY
            return false;
        }
    }

    if (startKey.data) {
        cmp = _fdb_key_cmp(this, ret_key, ret_keylen,
                           startKey.data, startKey.len);
        if ((cmp == 0 && iterOpt & FDB_ITR_SKIP_MIN_KEY) ||
            cmp < 0) { // smaller than startKey OR at skipped MIN_KEY
            return false;
        }
    }
    return true;
}

fdb_status FdbIterator::seekToMaxKey() {
    int cmp;

    if (!iterKey.data) {
        return FDB_RESULT_INVALID_ARGS;
    }

    size_t size_chunk = iterHandle->config.chunksize;

    // Initialize direction iteration to FORWARD just in case this function was
    // called right after FdbIterator::initIterator() so the cursor gets
    // positioned correctly
    iterDirection = FDB_ITR_FORWARD;
    if (endKey.len > size_chunk) {
        fdb_iterator_seek_opt_t dir = (iterOpt & FDB_ITR_SKIP_MAX_KEY) ?
                                            FDB_ITR_SEEK_LOWER :
                                            FDB_ITR_SEEK_HIGHER;
        fdb_status status = seek((uint8_t *)endKey.data + size_chunk,
                                 endKey.len - size_chunk,
                                 dir, true); //not regular seek

        if (status != FDB_RESULT_SUCCESS && dir == FDB_ITR_SEEK_HIGHER) {
            dir = FDB_ITR_SEEK_LOWER;
            // It is possible that the max key specified during init does not
            // exist, so retry the seek with the LOWER key
            return seek((uint8_t *)endKey.data + size_chunk,
                        endKey.len - size_chunk,
                        dir, true); // not a regular seek
        }
        return status;
    }
    iterDirection = FDB_ITR_REVERSE; // only reverse iteration possible

    if (endKey.data && endKey.len == size_chunk) {
        // endKey exists but endKeylen == size_id
        // it means that user doesn't assign endKey but
        // endKey is automatically assigned due to multi KVS mode.

        // reset HB+trie's iterator using endKey
        delete hbtrieIterator;
        hbtrieIterator = new HBTrieIterator(iterHandle->trie,
                                            endKey.data,
                                            endKey.len);

        // get first key
        hbtrieIterator->prev(iterKey.data, iterKey.len, (void*)&iterOffset);
        iterOffset = _endian_decode(iterOffset);
        cmp = _fdb_key_cmp(this, endKey.data, endKey.len,
                           iterKey.data, iterKey.len);
        if (cmp < 0) {
            // returned key is larger than the end key .. skip
            iterOffset = BLK_NOT_FOUND;
        }
    } else {
        // move HB+trie iterator's cursor to the last entry
        hbtrieIterator->last();
    }

    // also move WAL tree's cursor to the last entry
    struct wal_item_header hdr;
    struct wal_item query;
    query.header = &hdr;
    hdr.key = endKey.data;
    hdr.keylen = endKey.len;
    treeCursor = walIterator->searchSmaller_WalItr(&query);
    treeCursorPrev = treeCursor;
    iterStatus = FDB_ITR_IDX;

    return iterateToPrev();
}

fdb_status FdbIterator::seekToMaxSeq() {

    iterDirection = FDB_ITR_REVERSE; // only reverse iteration possible
    seqNum = endSeqnum;

    if (iterHandle->kvs) {
        // create an iterator handle for hb-trie
        uint8_t *end_seq_kv = alca(uint8_t, sizeof(size_t)*2);
        fdb_kvs_id_t _kv_id = _endian_encode(iterHandle->kvs->getKvsId());
        memcpy(end_seq_kv, &_kv_id, sizeof(size_t));
        memcpy(end_seq_kv + sizeof(size_t), &endSeqnum,
               sizeof(size_t));

        // reset HB+trie's seqtrie iterator using end_seq_kv
        delete seqtrieIterator;
        seqtrieIterator = new HBTrieIterator(iterHandle->seqtrie,
                                             end_seq_kv,
                                             sizeof(size_t)*2);
    } else {
        // reset Btree iterator to end_seqnum
        delete seqtreeIterator;
        // create an iterator handle for b-tree
        seqtreeIterator = new BTreeIterator(iterHandle->seqtree,
                                            (void *)(&endSeqnum));
    }

    if (endSeqnum != SEQNUM_NOT_USED) {
        struct wal_item query;
        struct wal_item_header query_key;
        size_t size_seq = sizeof(fdb_seqnum_t);
        size_t size_chunk = iterHandle->config.chunksize;
        uint8_t *end_seq_kv = alca(uint8_t, size_chunk + size_seq);
        if (iterHandle->kvs) {
            query_key.key = end_seq_kv;
            kvid2buf(size_chunk, iterHandle->kvs->getKvsId(), end_seq_kv);
            memcpy(end_seq_kv + size_chunk, &endSeqnum, size_seq);
            query_key.keylen = size_chunk + size_seq;
        } else {
            query_key.key = (void *) NULL;
            query_key.keylen = 0;
        }
        query.header = &query_key;
        query.seqnum = endSeqnum;

        // reset WAL tree cursor using search because of the sharded WAL
        treeCursor = walIterator->searchSmaller_WalItr(&query);
    } else { // no end_seqnum specified, just head to the last entry
        treeCursor = walIterator->last_WalItr();
    }

    if (treeCursor) {
        struct wal_item *snap_item = treeCursor;
        if (snap_item->seqnum == endSeqnum &&
            iterOpt & FDB_ITR_SKIP_MAX_KEY) {
            treeCursor = walIterator->prev_WalItr();
        }
    }

    if (treeCursor) {
        // If WAL tree has an entry, skip Main index for reverse iteration..
        iterOffset = treeCursor->offset;
    } else {
        iterOffset = BLK_NOT_FOUND; // fetch from main index
    }

    treeCursorPrev = treeCursor;
    return iterateToPrev();
}

fdb_status FdbIterator::iterateSeqPrev() {
    size_t size_id, size_seq, seq_kv_len;
    uint8_t *seq_kv;
    uint64_t offset = BLK_NOT_FOUND;
    btree_result br = BTREE_RESULT_FAIL;
    hbtrie_result hr;
    struct docio_object _doc;
    DocioHandle *dhandle;
    struct wal_item *snap_item = NULL;
    fdb_seqnum_t seqnum;
    fdb_kvs_id_t kv_id;

    size_id = sizeof(fdb_kvs_id_t);
    size_seq = sizeof(fdb_seqnum_t);
    seq_kv = alca(uint8_t, size_id + size_seq);

    if (iterDirection != FDB_ITR_REVERSE) {
        if (iterStatus == FDB_ITR_IDX) {
            iterOffset = BLK_NOT_FOUND; // need to re-examine Trie/trees
        }
        // re-position WAL key to previous key returned using search because of
        // sharded nature of wal (we cannot directly assign prev to cursor)
        if (treeCursorPrev &&
            treeCursor != treeCursorPrev) {
            treeCursor = walIterator->searchSmaller_WalItr(treeCursorPrev);
            iterStatus = FDB_ITR_IDX;
        } // else Don't move - seek()/init() has already positioned cursor
    }

start_seq:
    seqnum = seqNum;
    dhandle = iterHandle->dhandle;

    if (iterOffset == BLK_NOT_FOUND || // was iterating over btree
        !treeCursor) { // WAL exhausted
        if (iterHandle->kvs) { // multi KV instance mode
            hr = seqtrieIterator->prev(seq_kv, seq_kv_len, (void *)&offset);
            if (hr == HBTRIE_RESULT_SUCCESS) {
                br = BTREE_RESULT_SUCCESS;
                buf2kvid(size_id, seq_kv, &kv_id);
                if (kv_id != iterHandle->kvs->getKvsId()) {
                    // iterator is beyond the boundary
                    br = BTREE_RESULT_FAIL;
                }
                memcpy(&seqnum, seq_kv + size_id, size_seq);
            } else {
                br = BTREE_RESULT_FAIL;
            }
        } else {
            br = seqtreeIterator->prev(&seqnum, (void *)&offset);
        }
        if (!ver_btreev2_format(iterHandle->file->getVersion())) {
            iterHandle->bhandle->flushBuffer();
        }
        if (br == BTREE_RESULT_SUCCESS) {
            seqnum = _endian_decode(seqnum);
            seqNum = seqnum;
            if (seqnum < startSeqnum) {
                return FDB_RESULT_ITERATOR_FAIL;
            }
            offset = _endian_decode(offset);
            iterStatus = FDB_ITR_IDX;
        } else {
            iterOffset = BLK_NOT_FOUND;
            // B-tree has no more items
            return FDB_RESULT_ITERATOR_FAIL;
        }
    } else {
        while (treeCursor) {
            if (iterStatus == FDB_ITR_WAL) {
                treeCursorPrev = treeCursor;
                treeCursor = walIterator->prev_WalItr();
                if (!treeCursor) {
                    goto start_seq;
                }
            }// else don't move - seek()/ init() has already positioned cursor

            iterStatus = FDB_ITR_WAL;
            // get the current item of avl tree
            snap_item = treeCursor;
            uint8_t drop_logical_deletes =
                        (snap_item->action == WAL_ACT_LOGICAL_REMOVE) &&
                        (iterOpt & FDB_ITR_NO_DELETES);
            if (snap_item->action == WAL_ACT_REMOVE ||
                drop_logical_deletes) {

                if (br == BTREE_RESULT_FAIL && !treeCursor) {
                    return FDB_RESULT_ITERATOR_FAIL;
                }
                // this key is removed .. get prev key[WAL]
                continue;
            }

            offset = snap_item->offset;
            iterOffset = offset; // WAL is not exhausted, ignore B-Tree
            seqNum = snap_item->seqnum;
            break;
        }
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

        int64_t _offset = dhandle->readDocKeyMeta_Docio(offset, &_doc, true);
        if (_offset <= 0) {
            return _offset < 0 ? (fdb_status)_offset : FDB_RESULT_KEY_NOT_FOUND;
        }
        if (_doc.length.flag & DOCIO_DELETED &&
            (iterOpt & FDB_ITR_NO_DELETES)) {
            free(_doc.key);
            free(_doc.meta);
            return FDB_RESULT_KEY_NOT_FOUND;
        }

        doc_kv.key = _doc.key;
        doc_kv.keylen = _doc.length.keylen;
        doc_kv.seqnum = SEQNUM_NOT_USED;
        if (iterHandle->file->getWal()->find_Wal(
                        iterHandle->shandle->snap_txn,
                        &iterHandle->shandle->cmp_info,
                        iterHandle->shandle,
                        &doc_kv, (uint64_t *) &_offset) == FDB_RESULT_SUCCESS &&
            startSeqnum <= doc_kv.seqnum &&
            doc_kv.seqnum <= endSeqnum) {

            free(_doc.key);
            free(_doc.meta);
            goto start_seq; // B-tree item exists in WAL, skip for now
        }
        // Also look in HB-Trie to eliminate duplicates
        uint64_t hboffset;
        struct docio_object _hbdoc;
        hr = iterHandle->trie->find(_doc.key, _doc.length.keylen,
                                 (void *)&hboffset);
        if (!ver_btreev2_format(iterHandle->file->getVersion())) {
            iterHandle->bhandle->flushBuffer();
        }

        if (hr != HBTRIE_RESULT_SUCCESS) {
            free(_doc.key);
            free(_doc.meta);
            goto start_seq;
        } else { // If present in HB-trie ensure it's seqnum is in range
            int64_t _offset;
            _hbdoc.key = _doc.key;
            _hbdoc.meta = NULL;
            hboffset = _endian_decode(hboffset);
            _offset = iterHandle->dhandle->readDocKeyMeta_Docio(hboffset,
                                                             &_hbdoc, true);
            if (_offset <= 0) {
                free(_doc.key);
                free(_doc.meta);
                return _offset < 0 ? (fdb_status)_offset : FDB_RESULT_KEY_NOT_FOUND;
            }

            if (_doc.seqnum < _hbdoc.seqnum &&
                _hbdoc.seqnum <= endSeqnum) {
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

    dHandle = dhandle; // store for FdbIterator::get()
    getOffset = offset; // store for FdbIterator::get()

    return FDB_RESULT_SUCCESS;
}

fdb_status FdbIterator::iterateSeqNext() {
    size_t size_id, size_seq, seq_kv_len;
    uint8_t *seq_kv;
    uint64_t offset = BLK_NOT_FOUND;
    btree_result br = BTREE_RESULT_FAIL;
    hbtrie_result hr;
    struct docio_object _doc;
    DocioHandle *dhandle;
    struct wal_item *snap_item = NULL;
    fdb_seqnum_t seqnum;
    fdb_kvs_id_t kv_id;

    size_id = sizeof(fdb_kvs_id_t);
    size_seq = sizeof(fdb_seqnum_t);
    seq_kv = alca(uint8_t, size_id + size_seq);

    if (iterDirection != FDB_ITR_FORWARD) {
        if (iterStatus == FDB_ITR_IDX) {
            iterOffset = BLK_NOT_FOUND; // need to re-examine Trie/trees
        }
        // re-position WAL key to previous key returned
        if (treeCursorPrev) {
            treeCursor = walIterator->searchGreater_WalItr(treeCursorPrev);
            iterStatus = FDB_ITR_IDX;
        } // else Don't move - seek()/init() has already positioned cursor
    }

start_seq:
    seqnum = seqNum;
    dhandle = iterHandle->dhandle;

    // retrieve from sequence b-tree first
    if (iterOffset == BLK_NOT_FOUND) {
        if (iterHandle->kvs) { // multi KV instance mode
            hr = seqtrieIterator->next(seq_kv, seq_kv_len,
                                       (void *)&offset);
            if (hr == HBTRIE_RESULT_SUCCESS) {
                br = BTREE_RESULT_SUCCESS;
                buf2kvid(size_id, seq_kv, &kv_id);
                if (kv_id != iterHandle->kvs->getKvsId()) {
                    // iterator is beyond the boundary
                    br = BTREE_RESULT_FAIL;
                }
                memcpy(&seqnum, seq_kv + size_id, size_seq);
            } else {
                br = BTREE_RESULT_FAIL;
            }
        } else {
            br = seqtreeIterator->next(&seqnum, (void *)&offset);
        }
        if (!ver_btreev2_format(iterHandle->file->getVersion())) {
            iterHandle->bhandle->flushBuffer();
        }
        if (br == BTREE_RESULT_SUCCESS) {
            seqnum = _endian_decode(seqnum);
            seqNum = seqnum;
            if (seqnum > endSeqnum) {
                return FDB_RESULT_ITERATOR_FAIL;
            }
            offset = _endian_decode(offset);
            iterOffset = BLK_NOT_FOUND; // continue with B-tree
            iterStatus = FDB_ITR_IDX;
        }
    }

    if (br == BTREE_RESULT_FAIL) {
        if (treeCursor == NULL) {
            return FDB_RESULT_ITERATOR_FAIL;
        } else {
            while (treeCursor) {
                if (iterStatus == FDB_ITR_WAL) {
                    // save the current point for direction change
                    treeCursorPrev = treeCursor;
                    treeCursor = walIterator->next_WalItr();
                    if (!treeCursor) {
                        return FDB_RESULT_ITERATOR_FAIL;
                    }
                }// else don't move - seek()/ init() already positioned cursor
                // get the current item of WAL tree
                iterStatus = FDB_ITR_WAL;
                snap_item = treeCursor;
                uint8_t drop_logical_deletes =
                        (snap_item->action == WAL_ACT_LOGICAL_REMOVE) &&
                        (iterOpt & FDB_ITR_NO_DELETES);
                if (snap_item->action == WAL_ACT_REMOVE ||
                    drop_logical_deletes) {
                    if (br == BTREE_RESULT_FAIL && !treeCursor) {
                        return FDB_RESULT_ITERATOR_FAIL;
                    }
                    // this key is removed .. get next key[WAL]
                    continue;
                }
                if (snap_item->seqnum < seqNum) {
                    // smaller than the current seqnum .. get next key[WAL]
                    continue;
                }
                if (snap_item->seqnum > endSeqnum) {
                    // out-of-range .. iterator terminates
                    return FDB_RESULT_ITERATOR_FAIL;
                }

                offset = snap_item->offset;
                iterOffset = offset; // stops b-tree lookups. favor wal
                seqNum = snap_item->seqnum;
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
        int64_t _offset = dhandle->readDocKeyMeta_Docio(offset, &_doc, true);
        if (_offset <= 0) {
            return _offset < 0 ? (fdb_status)_offset : FDB_RESULT_KEY_NOT_FOUND;
        }
        if (_doc.length.flag & DOCIO_DELETED && (iterOpt & FDB_ITR_NO_DELETES)) {
            free(_doc.key);
            free(_doc.meta);
            return FDB_RESULT_KEY_NOT_FOUND;
        }
        doc_kv.key = _doc.key;
        doc_kv.keylen = _doc.length.keylen;
        doc_kv.seqnum = SEQNUM_NOT_USED; // search by key not seqnum
        if (iterHandle->file->getWal()->find_Wal(
                        iterHandle->shandle->snap_txn,
                        &iterHandle->shandle->cmp_info,
                        iterHandle->shandle,
                        &doc_kv, (uint64_t *) &_offset) == FDB_RESULT_SUCCESS &&
            startSeqnum <= doc_kv.seqnum &&
            doc_kv.seqnum <= endSeqnum) {

            free(_doc.key);
            free(_doc.meta);
            goto start_seq; // B-tree item exists in WAL, skip for now
        }
        // Also look in HB-Trie to eliminate duplicates
        uint64_t hboffset;
        struct docio_object _hbdoc;
        hr = iterHandle->trie->find(_doc.key, _doc.length.keylen,
                                 (void *)&hboffset);
        if (!ver_btreev2_format(iterHandle->file->getVersion())) {
            iterHandle->bhandle->flushBuffer();
        }

        if (hr != HBTRIE_RESULT_SUCCESS) {
            free(_doc.key);
            free(_doc.meta);
            goto start_seq;
        } else { // If present in HB-trie ensure it's seqnum is in range
            int64_t _offset;
            _hbdoc.key = _doc.key;
            _hbdoc.meta = NULL;
            hboffset = _endian_decode(hboffset);
            _offset = iterHandle->dhandle->readDocKeyMeta_Docio(hboffset,
                                                             &_hbdoc,
                                                             true);
            if (_offset <= 0) {
                free(_doc.key);
                free(_doc.meta);
                return _offset < 0 ? (fdb_status)_offset : FDB_RESULT_KEY_NOT_FOUND;
            }
            if (_doc.seqnum < _hbdoc.seqnum &&
                _hbdoc.seqnum <= endSeqnum) {
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

    dHandle = dhandle; // store for FdbIterator::get()
    getOffset = offset; // store for FdbIterator::get()

    return FDB_RESULT_SUCCESS;
}

LIBFDB_API
fdb_status fdb_iterator_init(FdbKvsHandle *handle,
                             fdb_iterator **ptr_iterator,
                             const void *start_key,
                             size_t start_keylen,
                             const void *end_key,
                             size_t end_keylen,
                             fdb_iterator_opt_t opt)
{
    return FdbIterator::initIterator(handle, ptr_iterator,
                                     start_key, start_keylen,
                                     end_key, end_keylen, opt);
}

LIBFDB_API
fdb_status fdb_iterator_sequence_init(FdbKvsHandle *handle,
                                      fdb_iterator **ptr_iterator,
                                      const fdb_seqnum_t start_seq,
                                      const fdb_seqnum_t end_seq,
                                      fdb_iterator_opt_t opt)
{
    return FdbIterator::initSeqIterator(handle, ptr_iterator,
                                        start_seq, end_seq, opt);
}


LIBFDB_API
fdb_status fdb_iterator_seek(fdb_iterator *iterator,
                             const void *seek_key,
                             const size_t seek_keylen,
                             const fdb_iterator_seek_opt_t seek_pref)
{
    if (!iterator || !iterator->getHandle()) {
        return FDB_RESULT_INVALID_HANDLE;
    }
    if (seek_pref != FDB_ITR_SEEK_HIGHER && seek_pref != FDB_ITR_SEEK_LOWER) {
        return FDB_RESULT_INVALID_ARGS;
    }

    return iterator->seek(seek_key, seek_keylen, seek_pref,
                          false); // not from seek_to_min/max()
}

LIBFDB_API
fdb_status fdb_iterator_seek_to_min(fdb_iterator *iterator)
{
    if (!iterator || !iterator->getHandle()) {
        return FDB_RESULT_INVALID_HANDLE;
    }

    if (!iterator->getIterKey()) {
        return FDB_RESULT_INVALID_ARGS;
    }

    return iterator->seekToMin();
}

LIBFDB_API
fdb_status fdb_iterator_seek_to_max(fdb_iterator *iterator)
{
    if (!iterator || !iterator->getHandle()) {
        return FDB_RESULT_INVALID_HANDLE;
    }

    return iterator->seekToMax();
}

LIBFDB_API
fdb_status fdb_iterator_prev(fdb_iterator *iterator)
{
    if (!iterator || !iterator->getHandle()) {
        return FDB_RESULT_INVALID_HANDLE;
    }

    return iterator->iterateToPrev();
}

LIBFDB_API
fdb_status fdb_iterator_next(fdb_iterator *iterator)
{
    if (!iterator || !iterator->getHandle()) {
        return FDB_RESULT_INVALID_HANDLE;
    }

    return iterator->iterateToNext();
}

// DOC returned by this function must be freed by fdb_doc_free
// if it was allocated because the incoming doc was pointing to NULL
LIBFDB_API
fdb_status fdb_iterator_get(fdb_iterator *iterator, fdb_doc **doc)
{
    if (!iterator || !iterator->getHandle()) {
        return FDB_RESULT_INVALID_HANDLE;
    }

    return iterator->get(doc, /*metaOnly*/false);
}

// DOC returned by this function must be freed using 'fdb_doc_free'
LIBFDB_API
fdb_status fdb_iterator_get_metaonly(fdb_iterator *iterator, fdb_doc **doc)
{
    if (!iterator || !iterator->getHandle()) {
        return FDB_RESULT_INVALID_HANDLE;
    }

    return iterator->get(doc, /*metaOnly*/true);
}

LIBFDB_API
fdb_status fdb_iterator_close(fdb_iterator *iterator)
{
    return FdbIterator::destroyIterator(iterator);
}

LIBFDB_API
fdb_status fdb_changes_since(FdbKvsHandle *handle,
                             fdb_seqnum_t since,
                             fdb_iterator_opt_t opt,
                             fdb_changes_callback_fn callback,
                             void *ctx)
{
    return FdbIterator::changesSince(handle, since, opt, callback, ctx);
}

fdb_status FdbIterator::changesSince(fdb_kvs_handle *handle,
                                     fdb_seqnum_t since,
                                     fdb_iterator_opt_t opt,
                                     fdb_changes_callback_fn callback,
                                     void *ctx) {
    if (!handle) {
        return FDB_RESULT_INVALID_HANDLE;
    }

    if (!callback) {
        // Callback function not provided
        return FDB_RESULT_INVALID_ARGS;
    }

    fdb_status status = FDB_RESULT_SUCCESS;
    fdb_iterator *iterator;
    const char *kvs_name = _fdb_kvs_get_name(handle, handle->file);
    if (!kvs_name) {
        kvs_name = DEFAULT_KVS_NAME;
    }

    // Create an iterator to traverse by seqno range
    status = fdb_iterator_sequence_init(handle, &iterator, since, 0, opt);
    if (status != FDB_RESULT_SUCCESS) {
        fdb_log(&handle->log_callback, status,
                "Failed to initialize iterator to traverse by sequence number "
                "range: (%llu - MAX_SEQ) over KV store '%s' database file '%s'",
                since, kvs_name, handle->file->getFileName());
        return status;
    }

    int result = 0;
    do {
        fdb_doc *doc = NULL;
        if (opt & FDB_ITR_NO_VALUES) {
            status = fdb_iterator_get_metaonly(iterator, &doc);
        } else {
            status = fdb_iterator_get(iterator, &doc);
        }
        if (status != FDB_RESULT_SUCCESS) {
            break;
        }
        result = callback(handle, doc, ctx);
        if (result == FDB_CHANGES_CLEAN) {
            fdb_doc_free(doc);
        } else if (result == FDB_CHANGES_CANCEL) {
            fdb_doc_free(doc);
            status = FDB_RESULT_CANCELLED;
            fdb_log(&handle->log_callback, status,
                    "Changes callback returned a negative value: %d, while "
                    "iterating over KV store '%s' in database file '%s'",
                    result, kvs_name, handle->file->getFileName());
            break;
        }
    } while (fdb_iterator_next(iterator) == FDB_RESULT_SUCCESS);

    // Close iterator
    fdb_iterator_close(iterator);

    return status;
}
