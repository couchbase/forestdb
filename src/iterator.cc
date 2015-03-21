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
#include "snapshot.h"
#include "avltree.h"
#include "list.h"
#include "internal_types.h"
#include "btree_var_kv_ops.h"

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

static int _fdb_seqnum_cmp(struct avl_node *a, struct avl_node *b, void *aux)
{
    struct snap_wal_entry *aa, *bb;
    aa = _get_entry(a, struct snap_wal_entry, avl_seq);
    bb = _get_entry(b, struct snap_wal_entry, avl_seq);
    return (aa->seqnum - bb->seqnum);
}

static int _fdb_wal_cmp(struct avl_node *a, struct avl_node *b, void *aux)
{
    _fdb_key_cmp_info *info = (_fdb_key_cmp_info*)aux;
    struct snap_wal_entry *aa, *bb;
    aa = _get_entry(a, struct snap_wal_entry, avl);
    bb = _get_entry(b, struct snap_wal_entry, avl);

    if (info->kvs_config.custom_cmp) {
        // custom compare function for variable-length key
        if (info->kvs) {
            // multi KV instance mode
            // KV ID should be compared separately
            size_t size_chunk = info->kvs->root->config.chunksize;
            fdb_kvs_id_t a_id, b_id;
            buf2kvid(size_chunk, aa->key, &a_id);
            buf2kvid(size_chunk, bb->key, &b_id);

            if (a_id < b_id) {
                return -1;
            } else if (a_id > b_id) {
                return 1;
            } else {
                if (aa->keylen == size_chunk) { // key1 < key2
                    return -1;
                } else if (bb->keylen == size_chunk) { // key1 > key2
                    return 1;
                }
                return info->kvs_config.custom_cmp(
                            (uint8_t*)aa->key + size_chunk,
                            aa->keylen - size_chunk,
                            (uint8_t*)bb->key + size_chunk,
                            bb->keylen - size_chunk);
            }
        } else {
            return info->kvs_config.custom_cmp(aa->key, aa->keylen,
                                               bb->key, bb->keylen);
        }
    } else {
        return _fdb_keycmp(aa->key, aa->keylen, bb->key, bb->keylen);
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

static void _fdb_itr_sync_dirty_root(fdb_iterator *iterator,
                                     fdb_kvs_handle *handle)
{
    if (handle->shandle) {
        // Note that snapshot handle (including in-memory snapshot)
        // does not need to update the dirty root, since
        // 1) a normal snapshot is created on a committed point,
        // 2) in-memory snapshot already updated their dirty root nodes
        //    during the initialization.
        return;
    }
    if (( handle->dirty_updates ||
           filemgr_dirty_root_exist(handle->file) ) &&
         filemgr_get_header_bid(handle->file) == handle->last_hdr_bid ) {
        // 1) { a) dirty WAL flush by this handle exists OR
        //      b) dirty WAL flush by other handle exists } AND
        // 2) no commit was performed yet.
        bid_t dirty_idtree_root, dirty_seqtree_root;

        filemgr_mutex_lock(iterator->handle->file);

        // get dirty root nodes
        filemgr_get_dirty_root(iterator->handle->file,
                               &dirty_idtree_root, &dirty_seqtree_root);
        if (dirty_idtree_root != BLK_NOT_FOUND) {
            iterator->handle->trie->root_bid = dirty_idtree_root;
        }
        if (iterator->handle->config.seqtree_opt == FDB_SEQTREE_USE) {
            if (dirty_seqtree_root != BLK_NOT_FOUND) {
                if (iterator->handle->kvs) {
                    iterator->handle->seqtrie->root_bid = dirty_seqtree_root;
                } else {
                    iterator->handle->seqtree->root_bid = dirty_seqtree_root;
                }
            }
        }
        btreeblk_discard_blocks(iterator->handle->bhandle);

        // create snapshot for dirty HB+trie nodes
        btreeblk_create_dirty_snapshot(iterator->handle->bhandle);

        filemgr_mutex_unlock(iterator->handle->file);
    }
}

fdb_status fdb_iterator_init(fdb_kvs_handle *handle,
                             fdb_iterator **ptr_iterator,
                             const void *start_key,
                             size_t start_keylen,
                             const void *end_key,
                             size_t end_keylen,
                             fdb_iterator_opt_t opt)
{
    int cmp;
    hbtrie_result hr;
    fdb_status fs;
    struct list_elem *he, *ie;
    struct wal_item_header *wal_item_header;
    struct wal_item *wal_item;
    struct snap_wal_entry *snap_item;

    if (handle == NULL ||
        start_keylen > FDB_MAX_KEYLEN ||
        (handle->kvs_config.custom_cmp &&
           (start_keylen > handle->config.blocksize - HBTRIE_HEADROOM ||
            end_keylen > handle->config.blocksize - HBTRIE_HEADROOM) ) ||
        end_keylen > FDB_MAX_KEYLEN) {
        return FDB_RESULT_INVALID_ARGS;
    }

    if ((opt & FDB_ITR_SKIP_MIN_KEY && (!start_key || !start_keylen)) ||
        (opt & FDB_ITR_SKIP_MAX_KEY && (!end_key || !end_keylen))) {
        return FDB_RESULT_INVALID_ARGS;
    }

    if (!handle->shandle) {
        // If compaction is already done before this line,
        // handle->file needs to be replaced with handle->new_file.
        fdb_check_file_reopen(handle, NULL);
        fdb_link_new_file(handle);
        fdb_sync_db_header(handle);
    }

    fdb_iterator *iterator = (fdb_iterator *)calloc(1, sizeof(fdb_iterator));

    if (!handle->shandle) {
        // snapshot handle doesn't exist
        // open a new handle to make the iterator handle as a snapshot
        fs = fdb_kvs_open(handle->fhandle, &iterator->handle,
                          _fdb_kvs_get_name(handle, handle->file),
                          &handle->kvs_config);
        if (fs != FDB_RESULT_SUCCESS) {
            return fs;
        }

        // Since fdb_kvs_open doesn't assign handle->new_file automatically,
        // we need to call these functions again.
        fdb_check_file_reopen(iterator->handle, NULL);
        fdb_link_new_file(iterator->handle);
        fdb_sync_db_header(iterator->handle);
    } else {
        // Snapshot handle exists
        // We don't need to open a new handle.. just point to the snapshot handle.
        iterator->handle = handle;
        // link new file if wal_tree points to the new file
        if (handle->shandle->type == FDB_SNAP_COMPACTION) {
            fdb_link_new_file_enforce(iterator->handle);
        }
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
    _fdb_itr_sync_dirty_root(iterator, handle);

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

    // create a snapshot for WAL (avl-tree)
    // (from the beginning to the last committed element)

    // init tree
    if (!handle->shandle) {
        struct filemgr *wal_file;

        if (iterator->handle->new_file == NULL) {
            wal_file = iterator->handle->file;
        } else {
            wal_file = iterator->handle->new_file;
        }

        fdb_txn *txn = handle->fhandle->root->txn;
        if (!txn) {
            txn = &wal_file->global_txn;
        }

        iterator->wal_tree = (struct avl_tree*)malloc(sizeof(struct avl_tree));
        avl_init(iterator->wal_tree, (void*)iterator->handle);

        size_t i = 0;
        size_t num_shards = wal_file->wal->num_shards;
        for (; i < num_shards; ++i) {
            spin_lock(&wal_file->wal->key_shards[i].lock);
            he = list_begin(&wal_file->wal->key_shards[i].list);
            while(he) {
                wal_item_header = _get_entry(he, struct wal_item_header, list_elem);
                ie = list_begin(&wal_item_header->items);
                if (txn->isolation == FDB_ISOLATION_READ_COMMITTED) {
                    // Search for the first uncommitted item belonging to this txn..
                    for (; ie; ie = list_next(ie)) {
                        wal_item = _get_entry(ie, struct wal_item, list_elem);
                        if (wal_item->txn == txn) {
                            break;
                        } // else fall through and pick the committed item at end..
                    }
                    if (!ie) {
                        ie = list_end(&wal_item_header->items);
                    }
                }

                wal_item = _get_entry(ie, struct wal_item, list_elem);
                if (wal_item->flag & WAL_ITEM_BY_COMPACTOR) {
                    // ignore items moved by compactor
                    he = list_next(he);
                    continue;
                }
                if ((wal_item->flag & WAL_ITEM_COMMITTED) ||
                    (wal_item->txn == txn) ||
                    (txn->isolation == FDB_ISOLATION_READ_UNCOMMITTED)) {
                    if (end_key) {
                        cmp = _fdb_key_cmp(iterator,
                                           (void *)end_key, end_keylen,
                                           wal_item_header->key,
                                           wal_item_header->keylen);
                        if ((cmp == 0 && opt & FDB_ITR_SKIP_MAX_KEY) || cmp < 0) {
                            he = list_next(he);
                            continue; // skip keys greater than max or equal (opt)
                        }
                    }
                    if (start_key) {
                        cmp = _fdb_key_cmp(iterator,
                                           (void *)start_key, start_keylen,
                                           wal_item_header->key,
                                           wal_item_header->keylen);
                        if ((cmp == 0 && opt & FDB_ITR_SKIP_MIN_KEY) || cmp > 0) {
                            he = list_next(he);
                            continue; // skip keys smaller than min or equal (opt)
                        }
                    }
                    // copy from 'wal_item_header'
                    snap_item = (struct snap_wal_entry*)malloc(sizeof(struct snap_wal_entry));
                    snap_item->keylen = wal_item_header->keylen;
                    snap_item->key = (void*)malloc(snap_item->keylen);
                    memcpy(snap_item->key, wal_item_header->key, snap_item->keylen);
                    snap_item->action = wal_item->action;
                    snap_item->offset = wal_item->offset;
                    if (wal_file == iterator->handle->new_file) {
                        snap_item->flag = SNAP_ITEM_IN_NEW_FILE;
                    } else {
                        snap_item->flag = 0x0;
                    }

                    // insert into tree
                    avl_insert(iterator->wal_tree, &snap_item->avl, _fdb_wal_cmp);
                }
                he = list_next(he);
            }
            spin_unlock(&wal_file->wal->key_shards[i].lock);
        }
    } else {
        iterator->wal_tree = handle->shandle->key_tree;
    }

    if (iterator->wal_tree) {
        if (start_key) {
            struct snap_wal_entry query;
            query.key = (void*)start_key;
            query.keylen = start_keylen;
            iterator->tree_cursor = avl_search_greater(iterator->wal_tree,
                                                       &query.avl,
                                                       _fdb_wal_cmp);
        } else {
            iterator->tree_cursor = avl_first(iterator->wal_tree);
        }
    } else {
        iterator->tree_cursor = NULL;
    }
    // to know reverse iteration endpoint store the start cursor
    iterator->tree_cursor_start = iterator->tree_cursor;
    iterator->tree_cursor_prev = NULL;
    iterator->direction = FDB_ITR_DIR_NONE;
    iterator->status = FDB_ITR_IDX;
    iterator->_dhandle = NULL; // populated at the first iterator movement

    *ptr_iterator = iterator;

    fdb_iterator_next(iterator); // position cursor at first key

    return FDB_RESULT_SUCCESS;
}

LIBFDB_API
fdb_status fdb_iterator_sequence_init(fdb_kvs_handle *handle,
                                      fdb_iterator **ptr_iterator,
                                      const fdb_seqnum_t start_seq,
                                      const fdb_seqnum_t end_seq,
                                      fdb_iterator_opt_t opt)
{
    struct list_elem *he, *ie;
    struct wal_item_header *wal_item_header;
    struct wal_item *wal_item;
    struct snap_wal_entry *snap_item;
    fdb_status fs;
    fdb_seqnum_t _start_seq = _endian_encode(start_seq);
    fdb_kvs_id_t kv_id, _kv_id;
    size_t size_id, size_seq;
    uint8_t *start_seq_kv;

    if (handle == NULL || ptr_iterator == NULL ||
        start_seq > end_seq) {
        return FDB_RESULT_INVALID_ARGS;
    }

    // Sequence trees are a must for byseq operations
    if (handle->config.seqtree_opt != FDB_SEQTREE_USE) {
        return FDB_RESULT_INVALID_CONFIG;
    }

    if (!handle->shandle) {
        // If compaction is already done before this line,
        // handle->file needs to be replaced with handle->new_file.
        fdb_check_file_reopen(handle, NULL);
        fdb_link_new_file(handle);
        fdb_sync_db_header(handle);
    }

    size_id = sizeof(fdb_kvs_id_t);
    size_seq = sizeof(fdb_seqnum_t);
    fdb_iterator *iterator = (fdb_iterator *)calloc(1, sizeof(fdb_iterator));

    if (!handle->shandle) {
        // snapshot handle doesn't exist
        // open a new handle to make the iterator handle as a snapshot
        fs = fdb_kvs_open(handle->fhandle, &iterator->handle,
                          _fdb_kvs_get_name(handle, handle->file),
                          &handle->kvs_config);
        if (fs != FDB_RESULT_SUCCESS) {
            return fs;
        }

        // Since fdb_kvs_open doesn't assign handle->new_file automatically,
        // we need to call these functions again.
        fdb_check_file_reopen(iterator->handle, NULL);
        fdb_link_new_file(iterator->handle);
        fdb_sync_db_header(iterator->handle);
    } else {
        // Snapshot handle exists
        // We don't need to open a new handle.. just point to the snapshot handle.
        iterator->handle = handle;
        // link new file if wal_tree points to the new file
        if (handle->shandle->type == FDB_SNAP_COMPACTION) {
            fdb_link_new_file_enforce(iterator->handle);
        }
    }
    iterator->hbtrie_iterator = NULL;
    iterator->_key = NULL;
    iterator->_keylen = 0;
    iterator->opt = opt;
    iterator->_offset = BLK_NOT_FOUND;
    iterator->_seqnum = start_seq;
    _fdb_itr_sync_dirty_root(iterator, handle);

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

    if (iterator->handle->kvs) {
        // create an iterator handle for hb-trie
        start_seq_kv = alca(uint8_t, size_id + size_seq);
        _kv_id = _endian_encode(iterator->handle->kvs->id);
        memcpy(start_seq_kv, &_kv_id, size_id);
        memcpy(start_seq_kv + size_id, &_start_seq, size_seq);

        iterator->seqtrie_iterator = (struct hbtrie_iterator *)
                                     calloc(1, sizeof(struct hbtrie_iterator));
        hbtrie_iterator_init(iterator->handle->seqtrie,
                             iterator->seqtrie_iterator,
                             start_seq_kv, size_id + size_seq);
    } else {
        // create an iterator handle for b-tree
        iterator->seqtree_iterator = (struct btree_iterator *)
                                     calloc(1, sizeof(struct btree_iterator));
        btree_iterator_init(iterator->handle->seqtree,
                            iterator->seqtree_iterator,
                            (void *)(start_seq ? &_start_seq : NULL));
    }

    // create a snapshot for WAL (avl-tree)
    // (from the beginning to the last committed element)

    // init tree
    if (!handle->shandle) {
        struct filemgr *wal_file;

        if (iterator->handle->new_file == NULL) {
            wal_file = iterator->handle->file;
        } else {
            wal_file = iterator->handle->new_file;
        }

        fdb_txn *txn = handle->fhandle->root->txn;
        if (!txn) {
            txn = &wal_file->global_txn;
        }

        iterator->wal_tree = (struct avl_tree*)
                             malloc(sizeof(struct avl_tree));
        avl_init(iterator->wal_tree, (void*)_fdb_seqnum_cmp);

        size_t i = 0;
        size_t num_shards = wal_file->wal->num_shards;
        for (; i < num_shards; ++i) {
            spin_lock(&wal_file->wal->key_shards[i].lock);
            he = list_begin(&wal_file->wal->key_shards[i].list);
            while(he) {
                wal_item_header = _get_entry(he, struct wal_item_header, list_elem);

                // compare committed item only (at the end of the list)
                ie = list_end(&wal_item_header->items);
                wal_item = _get_entry(ie, struct wal_item, list_elem);
                if (wal_item->flag & WAL_ITEM_BY_COMPACTOR) {
                    // ignore items moved by compactor
                    he = list_next(he);
                    continue;
                }
                if ((wal_item->flag & WAL_ITEM_COMMITTED) ||
                    (wal_item->txn == txn) ||
                    (txn->isolation == FDB_ISOLATION_READ_UNCOMMITTED)) {
                    if (iterator->_seqnum <= wal_item->seqnum) {
                        // (documents whose seq numbers are greater than end_seqnum
                        //  also have to be included for duplication check)
                        // copy from WAL_ITEM
                        if (iterator->handle->kvs) { // multi KV instance mode
                            // get KV ID from key
                            buf2kvid(wal_item_header->chunksize,
                                     wal_item_header->key, &kv_id);
                            if (kv_id != iterator->handle->kvs->id) {
                                // KV instance doesn't match
                                he = list_next(he);
                                continue;
                            }
                        }
                        snap_item = (struct snap_wal_entry*)
                            malloc(sizeof(struct snap_wal_entry));
                        snap_item->keylen = wal_item_header->keylen;
                        snap_item->key = (void*)malloc(snap_item->keylen);
                        memcpy(snap_item->key, wal_item_header->key, snap_item->keylen);
                        snap_item->seqnum = wal_item->seqnum;
                        snap_item->action = wal_item->action;
                        snap_item->offset = wal_item->offset;
                        if (wal_file == iterator->handle->new_file) {
                            snap_item->flag = SNAP_ITEM_IN_NEW_FILE;
                        } else {
                            snap_item->flag = 0x0;
                        }

                        // insert into tree
                        avl_insert(iterator->wal_tree, &snap_item->avl_seq,
                                   _fdb_seqnum_cmp);
                    }
                }
                he = list_next(he);
            }
            spin_unlock(&wal_file->wal->key_shards[i].lock);
        }
    } else {
        iterator->wal_tree = handle->shandle->seq_tree;
    }

    if (iterator->wal_tree) {
        iterator->tree_cursor = avl_first(iterator->wal_tree);
    } else {
        iterator->tree_cursor = NULL;
    }

    // to know reverse iteration endpoint store the start cursor
    iterator->tree_cursor_start = iterator->tree_cursor;
    iterator->tree_cursor_prev = iterator->tree_cursor;
    iterator->direction = FDB_ITR_DIR_NONE;
    iterator->status = FDB_ITR_IDX;
    iterator->_dhandle = NULL; // populated at the first iterator movement

    *ptr_iterator = iterator;

    fdb_iterator_next(iterator); // position cursor at first key

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
    struct snap_wal_entry *snap_item = NULL;

    if (iterator->direction == FDB_ITR_FORWARD) {
        iterator->_offset = BLK_NOT_FOUND; // need to re-examine Trie/trees
        if (!iterator->tree_cursor && iterator->tree_cursor_prev) {
            // this only happens right after seek operation
            // (when seek is executed using a key larger than
            //  the largest key in WAL)
            if (iterator->status == FDB_ITR_WAL) {
                iterator->tree_cursor = avl_prev(iterator->tree_cursor_prev);
                iterator->tree_cursor_prev = iterator->tree_cursor;
            } else {
                iterator->tree_cursor = iterator->tree_cursor_prev;
            }
        } else if (iterator->tree_cursor) { // on turning direction
            if (iterator->status == FDB_ITR_WAL) { // skip 2 items
                iterator->tree_cursor = avl_prev(iterator->tree_cursor_prev);
            } else { // skip 1 item if the last doc was returned from the main index
                iterator->tree_cursor = avl_prev(iterator->tree_cursor);
            }
            iterator->tree_cursor_prev = iterator->tree_cursor;
        }
    }
    iterator->tree_cursor = iterator->tree_cursor_prev;
start:
    key = iterator->_key;
    dhandle = iterator->handle->dhandle;

    // retrieve from hb-trie
    if (iterator->_offset == BLK_NOT_FOUND) {
        // no key waiting for being returned
        // get next key from hb-trie (or idtree)
        struct docio_object _doc;
        uint64_t _offset;
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
            _offset = docio_read_doc_key_meta(dhandle, iterator->_offset, &_doc);
            if (_offset == iterator->_offset) { // read fail
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
    iterator->status = FDB_ITR_IDX;

    if (hr == HBTRIE_RESULT_FAIL && !iterator->tree_cursor) {
        return FDB_RESULT_ITERATOR_FAIL;
    }

    while (iterator->tree_cursor) {
        // get the current item of avl-tree
        snap_item = _get_entry(iterator->tree_cursor, struct snap_wal_entry,
                               avl);
        if (hr != HBTRIE_RESULT_FAIL) {
            cmp = _fdb_key_cmp(iterator, snap_item->key, snap_item->keylen,
                               key, keylen);
        } else {
            // no more docs in hb-trie
            cmp = 1;
        }

        if (cmp >= 0) {
            // key[WAL] >= key[hb-trie] .. take key[WAL] first
            iterator->tree_cursor = avl_prev(iterator->tree_cursor);
            iterator->tree_cursor_prev = iterator->tree_cursor;
            uint8_t drop_logical_deletes =
                (snap_item->action == WAL_ACT_LOGICAL_REMOVE) &&
                (iterator->opt & FDB_ITR_NO_DELETES);
            if (cmp > 0) {
                if (snap_item->action == WAL_ACT_REMOVE || drop_logical_deletes) {
                    if (hr == HBTRIE_RESULT_FAIL &&
                        iterator->tree_cursor == iterator->tree_cursor_start) {
                        return FDB_RESULT_ITERATOR_FAIL;
                    }
                    // this key is removed .. get prev key[WAL]
                    continue;
                }
            }else{ // same key found in WAL
                iterator->_offset = BLK_NOT_FOUND; // drop key from trie
                if (snap_item->action == WAL_ACT_REMOVE || drop_logical_deletes) {
                    // the key is removed .. start over again
                    goto start;
                }
            }

            key = snap_item->key;
            keylen = snap_item->keylen;
            // key[hb-trie] is stashed in iterator->_key for future call
            offset = snap_item->offset;
            iterator->status = FDB_ITR_WAL;
            if (snap_item->flag & SNAP_ITEM_IN_NEW_FILE) {
                dhandle = iterator->handle->new_dhandle;
            }
        }
        break;
    }

    if (offset == iterator->_offset) {
        // take key[hb-trie] & and fetch the prev key[hb-trie] at next turn
        iterator->_offset = BLK_NOT_FOUND;
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
    struct snap_wal_entry *snap_item = NULL;

    if (iterator->direction == FDB_ITR_REVERSE) {
        iterator->_offset = BLK_NOT_FOUND; // need to re-examine Trie/trees
        if (iterator->tree_cursor) {
            iterator->tree_cursor = avl_next(iterator->tree_cursor);
            if (iterator->tree_cursor &&
                iterator->status == FDB_ITR_WAL) {
                // if the last document was returned from WAL,
                // shift again, past curkey into next
                iterator->tree_cursor = avl_next(iterator->tree_cursor);
            }
        }
    }

    if (!iterator->tree_cursor && iterator->direction != FDB_ITR_FORWARD) {
        // In case reverse iteration went past the start, reset the
        // cursor to the start point
        iterator->tree_cursor = iterator->tree_cursor_start;
    }

start:
    key = iterator->_key;
    dhandle = iterator->handle->dhandle;

    // retrieve from hb-trie
    if (iterator->_offset == BLK_NOT_FOUND) {
        // no key waiting for being returned
        // get next key from hb-trie (or idtree)
        struct docio_object _doc;
        uint64_t _offset;
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
            _offset = docio_read_doc_key_meta(dhandle, iterator->_offset, &_doc);
            if (_offset == iterator->_offset) { // read fail
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
    iterator->status = FDB_ITR_IDX;

    if (hr == HBTRIE_RESULT_FAIL && iterator->tree_cursor == NULL) {
        return FDB_RESULT_ITERATOR_FAIL;
    }

    while (iterator->tree_cursor) {
        // get the current item of avl-tree
        snap_item = _get_entry(iterator->tree_cursor, struct snap_wal_entry,
                               avl);
        if (hr != HBTRIE_RESULT_FAIL) {
            cmp = _fdb_key_cmp(iterator, snap_item->key, snap_item->keylen,
                               key, keylen);
        } else {
            // no more docs in hb-trie
            cmp = -1;
        }

        if (cmp <= 0) {
            // key[WAL] <= key[hb-trie] .. take key[WAL] first
            // save the current pointer for reverse iteration
            iterator->tree_cursor_prev = iterator->tree_cursor;
            iterator->tree_cursor = avl_next(iterator->tree_cursor);
            uint8_t drop_logical_deletes =
                (snap_item->action == WAL_ACT_LOGICAL_REMOVE) &&
                (iterator->opt & FDB_ITR_NO_DELETES);
            if (cmp < 0) {
                if (snap_item->action == WAL_ACT_REMOVE || drop_logical_deletes) {
                    if (hr == HBTRIE_RESULT_FAIL &&
                        iterator->tree_cursor == NULL) {
                        return FDB_RESULT_ITERATOR_FAIL;
                    }
                    // this key is removed .. get next key[WAL]
                    continue;
                }
            }else{ // Same key from trie also found from WAL
                iterator->_offset = BLK_NOT_FOUND; // drop key from trie
                if (snap_item->action == WAL_ACT_REMOVE || drop_logical_deletes) {
                    // the key is removed .. start over again
                    goto start;
                }
            }
            key = snap_item->key;
            keylen = snap_item->keylen;
            // key[hb-trie] is stashed in iterator->key for next call
            offset = snap_item->offset;
            iterator->status = FDB_ITR_WAL;
            if (snap_item->flag & SNAP_ITEM_IN_NEW_FILE) {
                dhandle = iterator->handle->new_dhandle;
            }
        }
        break;
    }

    if (offset == iterator->_offset) {
        // take key[hb-trie] & and fetch the next key[hb-trie] at next turn
        iterator->_offset = BLK_NOT_FOUND;
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

fdb_status fdb_iterator_seek(fdb_iterator *iterator,
                             const void *seek_key,
                             const size_t seek_keylen,
                             const fdb_iterator_seek_opt_t seek_preference)
{
    int cmp, cmp2; // intermediate results of comparison
    int next_op = 0; // 0: none, -1: prev(), 1: next();
    int size_chunk = iterator->handle->config.chunksize;
    uint8_t *seek_key_kv;
    uint64_t _offset;
    size_t seek_keylen_kv;
    bool skip_wal = false, fetch_next = true, fetch_wal = true;
    hbtrie_result hr = HBTRIE_RESULT_SUCCESS;
    struct snap_wal_entry *snap_item = NULL, query;
    struct docio_object _doc;
    fdb_iterator_seek_opt_t seek_pref = seek_preference;

    iterator->_dhandle = NULL; // setup for get() to return FAIL

    if (!iterator || !seek_key || !iterator->_key ||
        seek_keylen > FDB_MAX_KEYLEN ||
        (iterator->handle->kvs_config.custom_cmp &&
            seek_keylen > iterator->handle->config.blocksize - HBTRIE_HEADROOM)) {
        return FDB_RESULT_INVALID_ARGS;
    }

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
                                                  iterator->_offset, &_doc);
                if (_offset == iterator->_offset) { // read fail
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
                                                  iterator->_offset, &_doc);
                if (_offset == iterator->_offset) { // read fail
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

    if (hr == HBTRIE_RESULT_SUCCESS && iterator->handle->kvs) {
        // seek is done byeond the KV ID
        fdb_kvs_id_t kv_id;
        buf2kvid(size_chunk, iterator->_key, &kv_id);
        if (iterator->handle->kvs->id != kv_id) {
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
    query.key = seek_key_kv;
    query.keylen = seek_keylen_kv;

    if (seek_pref == FDB_ITR_SEEK_HIGHER) {
        if (fetch_wal) {
            iterator->tree_cursor = avl_search_greater(iterator->wal_tree,
                                                       &query.avl,
                                                       _fdb_wal_cmp);
        }
        if (iterator->opt & FDB_ITR_NO_DELETES &&
            iterator->tree_cursor) {
            // skip deleted WAL entry
            do {
                snap_item = _get_entry(iterator->tree_cursor,
                                       struct snap_wal_entry, avl);
                if (snap_item->action == WAL_ACT_LOGICAL_REMOVE) {
                    if (iterator->_dhandle) {
                        cmp = _fdb_key_cmp(iterator,
                                           snap_item->key, snap_item->keylen,
                                           iterator->_key, iterator->_keylen);
                        if (cmp == 0) {
                            // same doc exists in HB+trie
                            // move tree cursor
                            iterator->tree_cursor = avl_next(iterator->
                                                             tree_cursor);
                            // do not move tree cursor next time
                            fetch_wal = false;
                            // fetch next key[HB+trie]
                            goto fetch_hbtrie;
                        } else if (cmp > 0) {
                            break;
                        }
                    }
                    iterator->tree_cursor = avl_next(iterator->tree_cursor);
                    continue;
                }
                break;
            } while(1);
        }
        if (!iterator->tree_cursor) {
            // seek_key is larger than the largest key
            // set prev key to the largest key.
            // if prev operation is called next, tree_cursor will be set to
            // tree_cursor_prev.
            iterator->tree_cursor_prev = avl_search_smaller(iterator->wal_tree,
                                                            &query.avl,
                                                            _fdb_wal_cmp);
        } else {
            iterator->tree_cursor_prev = iterator->tree_cursor;
        }
    } else if (seek_pref == FDB_ITR_SEEK_LOWER) {
        if (fetch_wal) {
            iterator->tree_cursor = avl_search_smaller(iterator->wal_tree,
                                                       &query.avl,
                                                       _fdb_wal_cmp);
        }
        if (iterator->opt & FDB_ITR_NO_DELETES &&
            iterator->tree_cursor) {
            // skip deleted WAL entry
            do {
                snap_item = _get_entry(iterator->tree_cursor,
                                       struct snap_wal_entry, avl);
                if (snap_item->action == WAL_ACT_LOGICAL_REMOVE) {
                    if (iterator->_dhandle) {
                        cmp = _fdb_key_cmp(iterator,
                                           snap_item->key, snap_item->keylen,
                                           iterator->_key, iterator->_keylen);
                        if (cmp == 0) {
                            // same doc exists in HB+trie
                            // move tree cursor
                            iterator->tree_cursor = avl_prev(iterator->
                                                             tree_cursor);
                            // do not move tree cursor next time
                            fetch_wal = false;
                            // fetch next key[HB+trie]
                            goto fetch_hbtrie;
                        } else if (cmp < 0) {
                            break;
                        }
                    }
                    iterator->tree_cursor = avl_prev(iterator->tree_cursor);
                    continue;
                }
                break;
            } while(1);
        }
        iterator->tree_cursor_prev = iterator->tree_cursor;
        if (!iterator->tree_cursor) {
            // seek_key is smaller than the smallest key
            iterator->tree_cursor = avl_search_greater(iterator->wal_tree,
                                                       &query.avl,
                                                       _fdb_wal_cmp);
            // need to set direction to NONE.
            // if next operation is called next, tree_cursor will be set to
            // cursor_start.
            iterator->direction = FDB_ITR_DIR_NONE;
            // since the current key[WAL] is larger than seek_key,
            // skip key[WAL] this time
            skip_wal = true;
        }
    }

    if (iterator->tree_cursor && !skip_wal) {
        bool take_wal = false;
        bool discard_hbtrie = false;

        snap_item = _get_entry(iterator->tree_cursor, struct snap_wal_entry,
                               avl);

        if (hr == HBTRIE_RESULT_SUCCESS) {
            cmp = _fdb_key_cmp(iterator,
                               snap_item->key, snap_item->keylen,
                               iterator->_key, iterator->_keylen);

            if (cmp == 0) {
                // same key exists in both HB+trie and WAL
                take_wal = true;
                discard_hbtrie = true;
            } else if (cmp < 0) { // key[WAL] < key[HB+trie]
                if (seek_pref == FDB_ITR_SEEK_HIGHER) {
                    // higher mode .. take smaller one (key[WAL]) first
                    take_wal = true;
                    discard_hbtrie = false;
                } else if (seek_pref == FDB_ITR_SEEK_LOWER) {
                    // lower mode .. discard smaller one (key[WAL])
                    iterator->tree_cursor = avl_next(iterator->tree_cursor);
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
            // Since WAL tree doesn't contain max/min key if
            // skip_min/max options are enabled, we don't need to
            // invoke next()/prev() call if no key is found in
            // HB+trie.
            next_op = 0;
        }

        if (take_wal) { // take key[WAL]
            if (!discard_hbtrie) { // do not skip the current key[HB+trie]
                // key[HB+trie] will be returned next time
                iterator->_offset = iterator->_get_offset;
            }
            iterator->_get_offset = snap_item->offset;
            if (snap_item->flag & SNAP_ITEM_IN_NEW_FILE) {
                iterator->_dhandle = iterator->handle->new_dhandle;
            } else {
                iterator->_dhandle = iterator->handle->dhandle;
            }
            // move to next WAL entry
            iterator->tree_cursor = avl_next(iterator->tree_cursor);
            iterator->status = FDB_ITR_WAL;
        }
    }

    if (!iterator->_dhandle) {
        return FDB_RESULT_ITERATOR_FAIL;
    }

    if (next_op < 0) {
        return fdb_iterator_prev(iterator);
    } else if (next_op > 0) {
        return fdb_iterator_next(iterator);
    } else {
        return FDB_RESULT_SUCCESS;
    }
}

fdb_status fdb_iterator_seek_to_min(fdb_iterator *iterator) {
    size_t size_chunk = iterator->handle->config.chunksize;

    if (!iterator || !iterator->_key) {
        return FDB_RESULT_INVALID_ARGS;
    }

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

    // reset WAL tree cursor
    iterator->tree_cursor_prev = iterator->tree_cursor =
                                 iterator->tree_cursor_start;

    return fdb_iterator_next(iterator);
}

fdb_status fdb_iterator_seek_to_max(fdb_iterator *iterator) {
    int cmp;
    size_t size_chunk = iterator->handle->config.chunksize;

    if (!iterator || !iterator->_key) {
        return FDB_RESULT_INVALID_ARGS;
    }

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
    iterator->tree_cursor = avl_last(iterator->wal_tree);
    iterator->tree_cursor_prev = iterator->tree_cursor;

    return fdb_iterator_prev(iterator);
}

static fdb_status _fdb_iterator_seq_prev(fdb_iterator *iterator)
{
    size_t size_id, size_seq, seq_kv_len;
    uint8_t *seq_kv;
    uint64_t offset = BLK_NOT_FOUND;
    btree_result br = BTREE_RESULT_FAIL;
    hbtrie_result hr;
    struct docio_object _doc;
    struct docio_object _hbdoc;
    struct docio_handle *dhandle;
    struct snap_wal_entry *snap_item = NULL;
    fdb_seqnum_t seqnum;
    fdb_kvs_id_t kv_id;
    struct avl_node *cursor;

    size_id = sizeof(fdb_kvs_id_t);
    size_seq = sizeof(fdb_seqnum_t);
    seq_kv = alca(uint8_t, size_id + size_seq);

    // in forward iteration, cursor points to the next key to be returned
    // therefore, in return iteration, make cursor point to prev key
    if (iterator->direction == FDB_ITR_FORWARD) {
        if (iterator->status == FDB_ITR_IDX) {
            iterator->_offset = BLK_NOT_FOUND; // need to re-examine Trie/trees
        }
        if (iterator->tree_cursor) { // on turning direction
            if (iterator->status == FDB_ITR_WAL) { // skip 2 items
                iterator->tree_cursor = avl_prev(iterator->tree_cursor_prev);
            } else { // skip 1 item if the last doc was returned from the main index
                iterator->tree_cursor = avl_prev(iterator->tree_cursor);
            }
            iterator->tree_cursor_prev = iterator->tree_cursor;
        }
    }
    iterator->tree_cursor = iterator->tree_cursor_prev;
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
            br = btree_prev(iterator->seqtree_iterator, &seqnum, (void *)&offset);
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
        // get the current item of avl tree
        snap_item = _get_entry(iterator->tree_cursor,
                struct snap_wal_entry, avl_seq);
        iterator->tree_cursor = avl_prev(iterator->tree_cursor);
        iterator->tree_cursor_prev = iterator->tree_cursor;
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
        iterator->status = FDB_ITR_WAL;
        if (snap_item->flag & SNAP_ITEM_IN_NEW_FILE) {
            dhandle = iterator->handle->new_dhandle;
        }
        break;
    }

    // To prevent returning duplicate items from sequence iterator, only return
    // those b-tree items that exist in HB-trie but not WAL
    // (WAL items should have already been returned in reverse iteration)
    if (br == BTREE_RESULT_SUCCESS) {
        _doc.key = NULL;
        _doc.length.keylen = 0;
        _doc.meta = NULL;
        _doc.body = NULL;
        uint64_t _offset = docio_read_doc_key_meta(dhandle, offset, &_doc);
        if (_offset == offset) {
            return FDB_RESULT_KEY_NOT_FOUND;
        }
        if (_doc.length.flag & DOCIO_DELETED &&
            (iterator->opt & FDB_ITR_NO_DELETES)) {
            free(_doc.key);
            free(_doc.meta);
            return FDB_RESULT_KEY_NOT_FOUND;
        }

        for (cursor = iterator->tree_cursor_start;
             cursor;
             cursor = avl_next(cursor)) {
            // get the current item of avl tree
            snap_item = _get_entry(cursor, struct snap_wal_entry, avl_seq);
            // we MUST not use 'memcmp' for comparison of two keys
            // because it returns false positive when snap_item->key is a
            // sub-string of _doc.key
            // (e.g, "abc" and "abcd" -> memcmp("abc", "abcd", 3) == 0)
            if (!_fdb_keycmp(snap_item->key, snap_item->keylen,
                             _doc.key, _doc.length.keylen)) {
                free(_doc.key);
                free(_doc.meta);
                goto start_seq; // B-tree item exists in WAL, skip for now
            }
        }

        // Also look in HB-Trie to eliminate duplicates
        uint64_t hboffset;
        hr = hbtrie_find(iterator->handle->trie, _doc.key, _doc.length.keylen,
                         (void *)&hboffset);
        btreeblk_end(iterator->handle->bhandle);

        if (hr == HBTRIE_RESULT_FAIL) {
            free(_doc.key);
            free(_doc.meta);
            goto start_seq;
        } else { // If present in HB-trie ensure it's seqnum is in range
            uint64_t _offset;
            _hbdoc.key = _doc.key;
            _hbdoc.meta = NULL;
            hboffset = _endian_decode(hboffset);
            _offset = docio_read_doc_key_meta(iterator->handle->dhandle, hboffset, &_hbdoc);
            if (_offset == hboffset) {
                free(_doc.key);
                free(_doc.meta);
                return FDB_RESULT_KEY_NOT_FOUND;
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
    struct docio_object _hbdoc;
    struct docio_handle *dhandle;
    struct snap_wal_entry *snap_item = NULL;
    fdb_seqnum_t seqnum;
    fdb_kvs_id_t kv_id;
    struct avl_node *cursor;

    size_id = sizeof(fdb_kvs_id_t);
    size_seq = sizeof(fdb_seqnum_t);
    seq_kv = alca(uint8_t, size_id + size_seq);

    if (iterator->direction == FDB_ITR_REVERSE) {
        if (iterator->status == FDB_ITR_IDX) {
            iterator->_offset = BLK_NOT_FOUND; // need to re-examine Trie/trees
        }
        if (iterator->tree_cursor) {
            iterator->tree_cursor = avl_next(iterator->tree_cursor);
            if (iterator->tree_cursor &&
                iterator->status == FDB_ITR_WAL) {
                // if the last document was returned from WAL,
                // shift again, past curkey into next
                iterator->tree_cursor = avl_next(iterator->tree_cursor);
            }
        }
    }

    if (!iterator->tree_cursor && iterator->direction != FDB_ITR_FORWARD) {
        // In case reverse iteration went past the start, reset the
        // cursor to the start point
        iterator->tree_cursor = iterator->tree_cursor_start;
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
            br = btree_next(iterator->seqtree_iterator, &seqnum, (void *)&offset);
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
                // get the current item of avl tree
                snap_item = _get_entry(iterator->tree_cursor,
                                       struct snap_wal_entry, avl_seq);
                // save the current point for reverse iteration
                iterator->tree_cursor_prev = iterator->tree_cursor;
                iterator->tree_cursor = avl_next(iterator->tree_cursor);
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
                iterator->status = FDB_ITR_WAL;
                if (snap_item->flag & SNAP_ITEM_IN_NEW_FILE) {
                    dhandle = iterator->handle->new_dhandle;
                }
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
        uint64_t _offset = docio_read_doc_key_meta(dhandle, offset, &_doc);
        if (_offset == offset) {
            return FDB_RESULT_KEY_NOT_FOUND;
        }
        if (_doc.length.flag & DOCIO_DELETED && (iterator->opt & FDB_ITR_NO_DELETES)) {
            free(_doc.key);
            free(_doc.meta);
            return FDB_RESULT_KEY_NOT_FOUND;
        }

        for (cursor = iterator->tree_cursor; cursor;
             cursor = avl_next(cursor)) {
            // get the current item of avl tree
            snap_item = _get_entry(cursor, struct snap_wal_entry, avl_seq);
            // we MUST not use 'memcmp' for comparison of two keys
            // because it returns false positive when snap_item->key is a
            // sub-string of _doc.key
            // (e.g, "abc" and "abcd" -> memcmp("abc", "abcd", 3) == 0)
            if (!_fdb_keycmp(snap_item->key, snap_item->keylen,
                             _doc.key, _doc.length.keylen)) {
                free(_doc.key);
                free(_doc.meta);
                goto start_seq; // B-tree item exists in WAL, skip for now
            }
        } // WAL search complete

        // Also look in HB-Trie to eliminate duplicates
        uint64_t hboffset;
        hr = hbtrie_find(iterator->handle->trie, _doc.key, _doc.length.keylen,
                         (void *)&hboffset);
        btreeblk_end(iterator->handle->bhandle);

        if (hr == HBTRIE_RESULT_FAIL) {
            free(_doc.key);
            free(_doc.meta);
            goto start_seq;
        } else { // If present in HB-trie ensure it's seqnum is in range
            uint64_t _offset;
            _hbdoc.key = _doc.key;
            _hbdoc.meta = NULL;
            hboffset = _endian_decode(hboffset);
            _offset = docio_read_doc_key_meta(iterator->handle->dhandle,
                                              hboffset, &_hbdoc);
            if (_offset == hboffset) {
                free(_doc.key);
                free(_doc.meta);
                return FDB_RESULT_KEY_NOT_FOUND;
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

fdb_status fdb_iterator_prev(fdb_iterator *iterator)
{
    fdb_status result = FDB_RESULT_SUCCESS;

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
            iterator->direction = FDB_ITR_DIR_NONE;
            if ((iterator->seqtree_iterator || iterator->seqtrie_iterator) &&
                    iterator->status == FDB_ITR_IDX) {
                iterator->_offset = BLK_NOT_FOUND;
            }
            if (iterator->tree_cursor) {
                iterator->tree_cursor = avl_next(iterator->tree_cursor);
                if (iterator->tree_cursor &&
                        iterator->status == FDB_ITR_WAL) {
                    // if the last document was returned from WAL,
                    // shift again, past curkey into next
                    iterator->tree_cursor = avl_next(iterator->tree_cursor);
                }
            }
        }
    }

    return result;
}

fdb_status fdb_iterator_next(fdb_iterator *iterator)
{
    fdb_status result = FDB_RESULT_SUCCESS;

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
            iterator->direction = FDB_ITR_DIR_NONE;
            if ((iterator->seqtree_iterator || iterator->seqtrie_iterator) &&
                    iterator->status == FDB_ITR_IDX) {
                iterator->_offset = BLK_NOT_FOUND;
            }
            if (iterator->tree_cursor) {
                if (iterator->status == FDB_ITR_WAL) { // move 2 steps
                    iterator->tree_cursor =
                                  avl_prev(iterator->tree_cursor_prev);
                } else {
                    // move 1 step if last doc was returned from the main index
                    iterator->tree_cursor = avl_prev(iterator->tree_cursor);
                }
                iterator->tree_cursor_prev = iterator->tree_cursor;
            }
        }
    }

    return result;
}

// DOC returned by this function must be freed by fdb_doc_free
// if it was allocated because the incoming doc was pointing to NULL
fdb_status fdb_iterator_get(fdb_iterator *iterator, fdb_doc **doc)
{
    struct docio_object _doc;
    fdb_status ret = FDB_RESULT_SUCCESS;
    uint64_t offset;
    struct docio_handle *dhandle;
    size_t size_chunk = iterator->handle->config.chunksize;
    bool alloced_key, alloced_meta, alloced_body;

    if (!iterator || !doc) {
        return FDB_RESULT_INVALID_ARGS;
    }

    dhandle = iterator->_dhandle;
    if (!dhandle || iterator->_get_offset == BLK_NOT_FOUND) {
        return FDB_RESULT_ITERATOR_FAIL;
    }

    offset = iterator->_get_offset;

    if (*doc == NULL) {
        ret = fdb_doc_create(doc, NULL, 0, NULL, 0, NULL, 0);
        if (ret != FDB_RESULT_SUCCESS) { // LCOV_EXCL_START
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

    uint64_t _offset = docio_read_doc(dhandle, offset, &_doc);
    if (_offset == offset) {
        return FDB_RESULT_KEY_NOT_FOUND;
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

    return ret;
}

// DOC returned by this function must be freed using 'fdb_doc_free'
fdb_status fdb_iterator_get_metaonly(fdb_iterator *iterator, fdb_doc **doc)
{
    struct docio_object _doc;
    fdb_status ret = FDB_RESULT_SUCCESS;
    uint64_t offset, _offset;
    struct docio_handle *dhandle;
    size_t size_chunk = iterator->handle->config.chunksize;
    bool alloced_key, alloced_meta;

    if (!iterator || !doc) {
        return FDB_RESULT_INVALID_ARGS;
    }

    dhandle = iterator->_dhandle;
    if (!dhandle || iterator->_get_offset == BLK_NOT_FOUND) {
        return FDB_RESULT_ITERATOR_FAIL;
    }

    offset = iterator->_get_offset;

    if (*doc == NULL) {
        ret = fdb_doc_create(doc, NULL, 0, NULL, 0, NULL, 0);
        if (ret != FDB_RESULT_SUCCESS) { // LCOV_EXCL_START
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

    _offset = docio_read_doc_key_meta(dhandle, offset, &_doc);
    if (_offset == offset) {
        return FDB_RESULT_KEY_NOT_FOUND;
    }
    if (_doc.length.flag & DOCIO_DELETED &&
            (iterator->opt & FDB_ITR_NO_DELETES)) {
        if (alloced_key) {
            free(_doc.key);
        }
        if (alloced_meta) {
            free(_doc.meta);
        }
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

    return ret;
}

fdb_status fdb_iterator_close(fdb_iterator *iterator)
{
    struct avl_node *a;
    struct snap_wal_entry *snap_item;

    if (iterator->hbtrie_iterator) {
        hbtrie_iterator_free(iterator->hbtrie_iterator);
        free(iterator->hbtrie_iterator);

        if (!iterator->handle->shandle) {
            a = avl_first(iterator->wal_tree);
            while(a) {
                snap_item = _get_entry(a, struct snap_wal_entry, avl);
                a = avl_next(a);
                avl_remove(iterator->wal_tree, &snap_item->avl);

                free(snap_item->key);
                free(snap_item);
            }

            free(iterator->wal_tree);
        }
    } else { // sequence iterator
        if (!iterator->handle->shandle) {
            a = avl_first(iterator->wal_tree);
            while(a) {
                snap_item = _get_entry(a, struct snap_wal_entry, avl_seq);
                a = avl_next(a);
                avl_remove(iterator->wal_tree, &snap_item->avl_seq);

                free(snap_item->key);
                free(snap_item);
            }

            free(iterator->wal_tree);
        }
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

    if (!iterator->handle->shandle) {
        // Close the opened handle in the iterator,
        // if the handle is not for snapshot.
        fdb_kvs_close(iterator->handle);
    }

    free(iterator->_key);
    free(iterator);

    return FDB_RESULT_SUCCESS;
}
