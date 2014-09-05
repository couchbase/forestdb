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
int _fdb_keycmp(void *key1, size_t keylen1, void *key2, size_t keylen2)
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

int _fdb_seqnum_cmp(struct avl_node *a, struct avl_node *b, void *aux)
{
    struct snap_wal_entry *aa, *bb;
    aa = _get_entry(a, struct snap_wal_entry, avl);
    bb = _get_entry(b, struct snap_wal_entry, avl);
    return (aa->seqnum - bb->seqnum);
}

int _fdb_wal_cmp(struct avl_node *a, struct avl_node *b, void *aux)
{
    fdb_handle *handle = (fdb_handle*)aux;
    struct snap_wal_entry *aa, *bb;
    aa = _get_entry(a, struct snap_wal_entry, avl);
    bb = _get_entry(b, struct snap_wal_entry, avl);

    if (handle->kvs_config.custom_cmp) {
        // custom compare function for variable-length key
        if (handle->kvs) {
            // multi KV instance mode
            // KV ID should be compared separately
            size_t size_id = sizeof(fdb_kvs_id_t);
            fdb_kvs_id_t a_id, b_id, _a_id, _b_id;
            _a_id = *(fdb_kvs_id_t*)aa->key;
            _b_id = *(fdb_kvs_id_t*)bb->key;
            a_id = _endian_decode(_a_id);
            b_id = _endian_decode(_b_id);

            if (a_id < b_id) {
                return -1;
            } else if (a_id > b_id) {
                return 1;
            } else {
                if (aa->keylen == size_id) { // key1 < key2
                    return -1;
                } else if (bb->keylen == size_id) { // key1 > key2
                    return 1;
                }
                return handle->kvs_config.custom_cmp(
                            (uint8_t*)aa->key + size_id, aa->keylen - size_id,
                            (uint8_t*)bb->key + size_id, bb->keylen - size_id);
            }
        } else {
            return handle->kvs_config.custom_cmp(aa->key, aa->keylen,
                                               bb->key, bb->keylen);
        }
    } else {
        return _fdb_keycmp(aa->key, aa->keylen, bb->key, bb->keylen);
    }
}

int _fdb_key_cmp(fdb_iterator *iterator, void *key1, size_t keylen1,
                 void *key2, size_t keylen2) {
    int cmp;
    if (iterator->handle.kvs_config.custom_cmp) {
        // custom compare function for variable length key
        if (iterator->handle.kvs) {
            // multi KV instance mode
            // KV ID should be compared separately
            size_t size_id = sizeof(fdb_kvs_id_t);
            fdb_kvs_id_t a_id, b_id, _a_id, _b_id;
            _a_id = *(fdb_kvs_id_t*)key1;
            _b_id = *(fdb_kvs_id_t*)key2;
            a_id = _endian_decode(_a_id);
            b_id = _endian_decode(_b_id);

            if (a_id < b_id) {
                cmp = -1;
            } else if (a_id > b_id) {
                cmp = 1;
            } else {
                if (keylen1 == size_id) { // key1 < key2
                    return -1;
                } else if (keylen2 == size_id) { // key1 > key2
                    return 1;
                }
                cmp = iterator->handle.kvs_config.custom_cmp(
                          (uint8_t*)key1 + size_id, keylen1 - size_id,
                          (uint8_t*)key2 + size_id, keylen2 - size_id);
            }
        } else {
            cmp = iterator->handle.kvs_config.custom_cmp(key1, keylen1,
                                                       key2, keylen2);
        }
    } else {
        cmp = _fdb_keycmp(key1, keylen1, key2, keylen2);
    }
    return cmp;
}

void _fdb_free_iterator(fdb_iterator *iterator) {
    free(iterator->_key);
    free(iterator->end_key);
    free(iterator->idtree_iterator);
    free(iterator->hbtrie_iterator);
    free(iterator->seqtree_iterator);
    free(iterator);
}

fdb_status fdb_iterator_init(fdb_handle *handle,
                             fdb_iterator **ptr_iterator,
                             const void *start_key,
                             size_t start_keylen,
                             const void *end_key,
                             size_t end_keylen,
                             fdb_iterator_opt_t opt)
{
    int cmp;
    hbtrie_result hr;
    btree_result br;
    struct list_elem *he, *ie;
    struct wal_item_header *wal_item_header;
    struct wal_item *wal_item;
    struct snap_wal_entry *snap_item;

    if (handle == NULL || start_keylen > FDB_MAX_KEYLEN ||
        end_keylen > FDB_MAX_KEYLEN) {
        return FDB_RESULT_INVALID_ARGS;
    }

    if (!handle->shandle) {
        fdb_check_file_reopen(handle);
        fdb_link_new_file(handle);
        fdb_sync_db_header(handle);
    }

    fdb_iterator *iterator = (fdb_iterator *)calloc(1, sizeof(fdb_iterator));

    iterator->handle = *handle;
    iterator->opt = opt;

    iterator->_key = (void*)malloc(FDB_MAX_KEYLEN_INTERNAL);
    iterator->_keylen = 0;
    iterator->_offset = BLK_NOT_FOUND;
    iterator->hbtrie_iterator = NULL;
    iterator->idtree_iterator = NULL;
    iterator->seqtree_iterator = NULL;

    if (handle->kvs) {
        // multi KV instance mode .. prepend KV ID
        size_t size_id = sizeof(fdb_kvs_id_t);
        uint8_t *start_key_temp, *end_key_temp;
        fdb_kvs_id_t _kv_id = _endian_encode(handle->kvs->id);

        if (start_key == NULL) {
            start_key_temp = alca(uint8_t, size_id);
            memcpy(start_key_temp, &_kv_id, size_id);
            start_key = start_key_temp;
            start_keylen = size_id;
        } else {
            start_key_temp = alca(uint8_t, size_id + start_keylen);
            memcpy(start_key_temp, &_kv_id, size_id);
            memcpy(start_key_temp + size_id, start_key, start_keylen);
            start_key = start_key_temp;
            start_keylen += size_id;
        }

        if (end_key == NULL) {
            end_key_temp = alca(uint8_t, size_id);
            // set end_key as NULL key of the next KV ID.
            // NULL key doesn't actually exist so that the iterator ends
            // at the last key of the current KV ID.
            _kv_id = _endian_encode(handle->kvs->id+1);
            memcpy(end_key_temp, &_kv_id, size_id);
            end_key = end_key_temp;
            end_keylen = size_id;
        } else {
            end_key_temp = alca(uint8_t, size_id + end_keylen);
            memcpy(end_key_temp, &_kv_id, size_id);
            memcpy(end_key_temp + size_id, end_key, end_keylen);
            end_key = end_key_temp;
            end_keylen += size_id;
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
    iterator->hbtrie_iterator = (struct hbtrie_iterator *)malloc(sizeof(struct hbtrie_iterator));
    hr = hbtrie_iterator_init(handle->trie, iterator->hbtrie_iterator,
                              (void *)start_key, start_keylen);
    if (hr == HBTRIE_RESULT_FAIL) {
        _fdb_free_iterator(iterator);
        return FDB_RESULT_ITERATOR_FAIL;
    }

    // create a snapshot for WAL (avl-tree)
    // (from the beginning to the last committed element)

    // init tree
    if (!handle->shandle) {
        struct filemgr *wal_file;

        if (handle->new_file == NULL) {
            wal_file = handle->file;
        } else {
            wal_file = handle->new_file;
        }

        fdb_txn *txn = handle->fhandle->root->txn;
        if (!txn) {
            txn = &wal_file->global_txn;
        }

        iterator->wal_tree = (struct avl_tree*)malloc(sizeof(struct avl_tree));
        avl_init(iterator->wal_tree, (void*)handle);

        spin_lock(&wal_file->wal->lock);
        he = list_begin(&wal_file->wal->list);
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
                if (start_key) {
                    cmp = _fdb_key_cmp(iterator, (void *)start_key, start_keylen,
                                       wal_item_header->key, wal_item_header->keylen);
                } else {
                    cmp = 0;
                }

                if (cmp <= 0) {
                    // copy from 'wal_item_header'
                    snap_item = (struct snap_wal_entry*)malloc(sizeof(
                                                        struct snap_wal_entry));
                    snap_item->keylen = wal_item_header->keylen;
                    snap_item->key = (void*)malloc(snap_item->keylen);
                    memcpy(snap_item->key, wal_item_header->key, snap_item->keylen);
                    snap_item->action = wal_item->action;
                    snap_item->offset = wal_item->offset;
                    if (wal_file == handle->new_file) {
                        snap_item->flag = SNAP_ITEM_IN_NEW_FILE;
                    } else {
                        snap_item->flag = 0x0;
                    }

                    // insert into tree
                    avl_insert(iterator->wal_tree, &snap_item->avl, _fdb_wal_cmp);
                }
            }
            he = list_next(he);
        }

        spin_unlock(&wal_file->wal->lock);
    } else {
        iterator->wal_tree = handle->shandle->key_tree;
    }

    if (iterator->wal_tree) {
        iterator->tree_cursor = avl_first(iterator->wal_tree);
    } else {
        iterator->tree_cursor = NULL;
    }
    // to know reverse iteration endpoint store the start cursor
    iterator->tree_cursor_start = iterator->tree_cursor;
    iterator->tree_cursor_prev = NULL;
    iterator->direction = FDB_ITR_DIR_NONE;
    iterator->status = FDB_ITR_IDX;

    *ptr_iterator = iterator;

    return FDB_RESULT_SUCCESS;
}

LIBFDB_API
fdb_status fdb_iterator_sequence_init(fdb_handle *handle,
                                      fdb_iterator **ptr_iterator,
                                      const fdb_seqnum_t start_seq,
                                      const fdb_seqnum_t end_seq,
                                      fdb_iterator_opt_t opt)
{
    struct list_elem *he, *ie;
    struct wal_item_header *wal_item_header;
    struct wal_item *wal_item;
    struct snap_wal_entry *snap_item;
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
        fdb_check_file_reopen(handle);
        fdb_link_new_file(handle);
        fdb_sync_db_header(handle);
    }

    size_id = sizeof(fdb_kvs_id_t);
    size_seq = sizeof(fdb_seqnum_t);
    fdb_iterator *iterator = (fdb_iterator *)calloc(1, sizeof(fdb_iterator));

    iterator->handle = *handle;
    iterator->hbtrie_iterator = NULL;
    iterator->idtree_iterator = NULL;
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
    iterator->start_keylen = 0;
    iterator->end_key = NULL;
    iterator->end_keylen = 0;

    if (handle->kvs) {
        // create an iterator handle for hb-trie
        start_seq_kv = alca(uint8_t, size_id + size_seq);
        _kv_id = _endian_encode(handle->kvs->id);
        memcpy(start_seq_kv, &_kv_id, size_id);
        memcpy(start_seq_kv + size_id, &_start_seq, size_seq);

        iterator->seqtrie_iterator = (struct hbtrie_iterator *)
                                     calloc(1, sizeof(struct hbtrie_iterator));
        hbtrie_iterator_init(handle->seqtrie, iterator->seqtrie_iterator,
                             start_seq_kv, size_id + size_seq);
    } else {
        // create an iterator handle for b-tree
        iterator->seqtree_iterator = (struct btree_iterator *)
                                     calloc(1, sizeof(struct btree_iterator));
        btree_iterator_init(handle->seqtree, iterator->seqtree_iterator,
                            (void *)(start_seq ? &_start_seq : NULL));
    }

    // create a snapshot for WAL (avl-tree)
    // (from the beginning to the last committed element)

    // init tree
    if (!handle->shandle) {
        struct filemgr *wal_file;

        if (handle->new_file == NULL) {
            wal_file = handle->file;
        } else {
            wal_file = handle->new_file;
        }

        fdb_txn *txn = handle->fhandle->root->txn;
        if (!txn) {
            txn = &wal_file->global_txn;
        }

        iterator->wal_tree = (struct avl_tree*)
                             malloc(sizeof(struct avl_tree));
        avl_init(iterator->wal_tree, (void*)_fdb_seqnum_cmp);

        spin_lock(&wal_file->wal->lock);
        he = list_begin(&wal_file->wal->list);
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
                    if (handle->kvs) { // multi KV instance mode
                        // get KV ID from key
                        _kv_id = *((fdb_kvs_id_t*)wal_item_header->key);
                        kv_id = _endian_decode(_kv_id);
                        if (kv_id != handle->kvs->id) {
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
                    if (wal_file == handle->new_file) {
                        snap_item->flag = SNAP_ITEM_IN_NEW_FILE;
                    } else {
                        snap_item->flag = 0x0;
                    }

                    // insert into tree
                    avl_insert(iterator->wal_tree, &snap_item->avl,
                               _fdb_seqnum_cmp);
                }
            }
            he = list_next(he);
        }
        spin_unlock(&wal_file->wal->lock);
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

    *ptr_iterator = iterator;

    return FDB_RESULT_SUCCESS;
}

// DOC returned by this function must be freed using 'fdb_doc_free'
static fdb_status _fdb_iterator_prev(fdb_iterator *iterator,
                                     fdb_doc **doc)
{
    int cmp;
    void *key;
    size_t keylen;
    uint64_t offset;
    hbtrie_result hr = HBTRIE_RESULT_SUCCESS;
    btree_result br;
    fdb_status fs;
    struct docio_object _doc;
    struct docio_handle *dhandle;
    struct snap_wal_entry *snap_item = NULL;

    if (iterator->direction == FDB_ITR_FORWARD) {
        iterator->_offset = BLK_NOT_FOUND; // need to re-examine Trie/trees
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
start:
    key = iterator->_key;
    dhandle = iterator->handle.dhandle;

    // retrieve from hb-trie
    if (iterator->_offset == BLK_NOT_FOUND) {
        // no key waiting for being returned
        // get next key from hb-trie (or idtree)
        hr = hbtrie_prev(iterator->hbtrie_iterator, key,
                         &iterator->_keylen, (void*)&iterator->_offset);
        btreeblk_end(iterator->handle.bhandle);
        iterator->_offset = _endian_decode(iterator->_offset);
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
                dhandle = iterator->handle.new_dhandle;
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

        if (cmp > 0) {
            // current key (KEY) is lexicographically less than
            // START key terminate the iteration
            return FDB_RESULT_ITERATOR_FAIL;
        }
    }

    _doc.key = key;
    _doc.length.keylen = keylen;
    _doc.length.bodylen = 0;
    _doc.meta = NULL;
    _doc.body = NULL;
    if (iterator->opt & FDB_ITR_METAONLY) {
        uint64_t _offset = docio_read_doc_key_meta(dhandle, offset, &_doc);
        if (_offset == offset) {
            return FDB_RESULT_KEY_NOT_FOUND;
        }
        if (_doc.length.flag & DOCIO_DELETED &&
            (iterator->opt & FDB_ITR_NO_DELETES)) {
            free(_doc.meta);
            return FDB_RESULT_KEY_NOT_FOUND;
        }
    } else {
        uint64_t _offset = docio_read_doc(dhandle, offset, &_doc);
        if (_offset == offset) {
            return FDB_RESULT_KEY_NOT_FOUND;
        }
        if (_doc.length.flag & DOCIO_DELETED && (iterator->opt & FDB_ITR_NO_DELETES)) {
            free(_doc.meta);
            free(_doc.body);
            return FDB_RESULT_KEY_NOT_FOUND;
        }
    }

    if (iterator->handle.kvs) {
        // eliminate KV ID from 'key'
        size_t size_id = sizeof(fdb_kvs_id_t);
        fs = fdb_doc_create(doc, (uint8_t*)key + size_id, keylen - size_id,
                            NULL, 0, NULL, 0);
    } else {
        fs = fdb_doc_create(doc, key, keylen, NULL, 0, NULL, 0);
    }
    if (fs != FDB_RESULT_SUCCESS) {
        free(_doc.meta);
        free(_doc.body);
        return fs;
    }

    (*doc)->meta = _doc.meta;
    (*doc)->metalen = _doc.length.metalen;
    (*doc)->body = _doc.body;
    (*doc)->bodylen = _doc.length.bodylen;
    (*doc)->seqnum = _doc.seqnum;
    (*doc)->deleted = _doc.length.flag & DOCIO_DELETED;
    (*doc)->offset = offset;

    return FDB_RESULT_SUCCESS;
}
// DOC returned by this function must be freed using 'fdb_doc_free'
static fdb_status _fdb_iterator_next(fdb_iterator *iterator,
                                     fdb_doc **doc)
{
    int cmp;
    void *key;
    size_t keylen;
    uint64_t offset;
    hbtrie_result hr = HBTRIE_RESULT_SUCCESS;
    btree_result br;
    fdb_status fs;
    struct docio_object _doc;
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
    dhandle = iterator->handle.dhandle;

    // retrieve from hb-trie
    if (iterator->_offset == BLK_NOT_FOUND) {
        // no key waiting for being returned
        // get next key from hb-trie (or idtree)
        hr = hbtrie_next(iterator->hbtrie_iterator, key,
                         &iterator->_keylen, (void*)&iterator->_offset);
        btreeblk_end(iterator->handle.bhandle);
        iterator->_offset = _endian_decode(iterator->_offset);
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
                dhandle = iterator->handle.new_dhandle;
            }
        }
        break;
    }

    if (offset == iterator->_offset) {
        // take key[hb-trie] & and fetch the next key[hb-trie] at next turn
        iterator->_offset = BLK_NOT_FOUND;
    }

    if (iterator->end_key) {
        cmp = _fdb_key_cmp(iterator, iterator->end_key, iterator->end_keylen,
                           key, keylen);

        if (cmp < 0) {
            // current key (KEY) is lexicographically greater than END_KEY
            // terminate the iteration
            return FDB_RESULT_ITERATOR_FAIL;
        }
    }

    _doc.key = key;
    _doc.length.keylen = keylen;
    _doc.length.bodylen = 0;
    _doc.meta = NULL;
    _doc.body = NULL;
    if (iterator->opt & FDB_ITR_METAONLY) {
        uint64_t _offset = docio_read_doc_key_meta(dhandle,
                                                   offset, &_doc);
        if (_offset == offset) {
            return FDB_RESULT_KEY_NOT_FOUND;
        }
        if (_doc.length.flag & DOCIO_DELETED && (iterator->opt & FDB_ITR_NO_DELETES)) {
            free(_doc.meta);
            return FDB_RESULT_KEY_NOT_FOUND;
        }
    } else {
        uint64_t _offset = docio_read_doc(dhandle, offset, &_doc);
        if (_offset == offset) {
            return FDB_RESULT_KEY_NOT_FOUND;
        }
        if (_doc.length.flag & DOCIO_DELETED && (iterator->opt & FDB_ITR_NO_DELETES)) {
            free(_doc.meta);
            free(_doc.body);
            return FDB_RESULT_KEY_NOT_FOUND;
        }
    }

    if (iterator->handle.kvs) {
        // eliminate KV ID from 'key'
        size_t size_id = sizeof(fdb_kvs_id_t);
        fs = fdb_doc_create(doc, (uint8_t*)key + size_id, keylen - size_id,
                            NULL, 0, NULL, 0);
    } else {
        fs = fdb_doc_create(doc, key, keylen, NULL, 0, NULL, 0);
    }
    if (fs != FDB_RESULT_SUCCESS) {
        free(_doc.meta);
        free(_doc.body);
        return fs;
    }

    (*doc)->meta = _doc.meta;
    (*doc)->metalen = _doc.length.metalen;
    (*doc)->body = _doc.body;
    (*doc)->bodylen = _doc.length.bodylen;
    (*doc)->seqnum = _doc.seqnum;
    (*doc)->deleted = _doc.length.flag & DOCIO_DELETED;
    (*doc)->offset = offset;

    return FDB_RESULT_SUCCESS;
}

fdb_status fdb_iterator_seek(fdb_iterator *iterator, const void *seek_key,
                             const size_t seek_keylen) {
    hbtrie_result hr = HBTRIE_RESULT_SUCCESS;
    btree_result br;
    struct snap_wal_entry *snap_item = NULL;
    int dir; // compare result gives seek direction >0 is forward, <=0 reverse
    int save_direction; // if we move past seek_key and need to turn back to it
    size_t seek_keylen_kv = seek_keylen + sizeof(fdb_kvs_id_t);
    size_t finalRun = (size_t) (-1);
    uint8_t *seek_key_kv = alca(uint8_t, seek_keylen_kv);
    fdb_kvs_id_t _kv_id;

    if (!iterator || !seek_key || !iterator->_key ||
        seek_keylen > FDB_MAX_KEYLEN) {
        return FDB_RESULT_INVALID_ARGS;
    }

    if (iterator->handle.kvs) {
        seek_keylen_kv = seek_keylen + sizeof(fdb_kvs_id_t);
        seek_key_kv = alca(uint8_t, seek_keylen_kv);
        _kv_id = _endian_encode(iterator->handle.kvs->id);
        memcpy(seek_key_kv, &_kv_id, sizeof(fdb_kvs_id_t));
        memcpy(seek_key_kv + sizeof(fdb_kvs_id_t), seek_key, seek_keylen);
    } else {
        seek_keylen_kv = seek_keylen;
        seek_key_kv = (uint8_t*)seek_key;
    }

    // disable seeking beyond the end key...
    if (iterator->end_key && _fdb_key_cmp(iterator, (void *)iterator->end_key,
                                         iterator->end_keylen,
                                         (void *)seek_key_kv, seek_keylen_kv) < 0) {
        return FDB_RESULT_ITERATOR_FAIL;
    }

    // disable seeking beyond the start key...
    if (iterator->start_key && _fdb_key_cmp(iterator,
                                         (void *)iterator->start_key,
                                         iterator->start_keylen,
                                         (void *)seek_key_kv, seek_keylen_kv) > 0) {
        return FDB_RESULT_ITERATOR_FAIL;
    }

    dir = _fdb_key_cmp(iterator, (void *)seek_key_kv, seek_keylen_kv,
                    (void *)iterator->_key, iterator->_keylen);
    save_direction = dir;

    // Roll the hb-trie/btree iterator to seek key based on direction
    while (hr == HBTRIE_RESULT_SUCCESS && finalRun--) {
        int cmp = _fdb_key_cmp(iterator, (void *)seek_key_kv, seek_keylen_kv,
                    (void *)iterator->_key, iterator->_keylen);

        if ((cmp <= 0 && dir >= 0) || // Forward seek went past seek_key
            (cmp >= 0 && dir <= 0)) { // Backward seek went past seek_key
            if (cmp != 0) {
                if (dir <= 0 && iterator->direction != FDB_ITR_REVERSE &&
                    finalRun) {// Oops we moved cursor backward one extra step!
                    dir = 1; // But user is not iterating in backward direction
                    finalRun = 1; //so run just once more in opposite direction
                    continue;
                }
                if (dir >= 0 && iterator->direction != FDB_ITR_FORWARD &&
                    finalRun) { // Oops we moved cursor forward one extra step!
                    dir = -1; // But user is not iterating in forward direction
                    finalRun = 1; //so run just once more in opposite direction
                    continue;
                }
            }

            // iterator->_key and iterator->_offset will help return seek_key
            // on iterator call if we went past it in either direction
            break;
        }

        // get next key from hb-trie (or idtree)
        if (dir <= 0) { // need to seek backwards
            hr = hbtrie_prev(iterator->hbtrie_iterator, iterator->_key,
                    &iterator->_keylen, (void*)&iterator->_offset);
        } else { // need to seek forward
            hr = hbtrie_next(iterator->hbtrie_iterator, iterator->_key,
                    &iterator->_keylen, (void*)&iterator->_offset);
        }
        btreeblk_end(iterator->handle.bhandle);
        iterator->_offset = _endian_decode(iterator->_offset);
    }

    // Reset the WAL cursor based on direction of iteration
    dir = save_direction;

    if (!iterator->tree_cursor) {
        if (dir < 0) { // need to seek backwards, but went past end point?
            if (iterator->direction != FDB_ITR_REVERSE) {
                iterator->tree_cursor = iterator->tree_cursor_prev;
            }
        } else { // need to seek forward, but went before start point?
            if (iterator->direction != FDB_ITR_FORWARD) {
                iterator->tree_cursor = iterator->tree_cursor_start;
            }
        }
    }

    finalRun = (size_t)(-1);
    while (iterator->tree_cursor && finalRun--) {
        int cmp;
        snap_item = _get_entry(iterator->tree_cursor, struct snap_wal_entry,
                               avl);
        cmp = _fdb_key_cmp(iterator, (void *)snap_item->key, snap_item->keylen,
                         (void *)seek_key_kv, seek_keylen_kv);
        if (dir < 0) { // need to seek backwards
            if (cmp > 0) {
                iterator->tree_cursor = avl_prev(iterator->tree_cursor);
                iterator->tree_cursor_prev = iterator->tree_cursor;
            } else {
                if (cmp != 0 && iterator->direction != FDB_ITR_REVERSE &&
                    finalRun) {
                    // Cursor ready at prev key but we aren't reverse iterating
                    dir = 1; // As we were seeking backward, must turn around
                    finalRun = 1; // just run once in opposite direction
                    continue;
                }
                break;
            }
        } else { // need to seek forward
            if (cmp < 0) {
                iterator->tree_cursor_prev = iterator->tree_cursor;
                iterator->tree_cursor = avl_next(iterator->tree_cursor);
            } else {
                if (cmp != 0 && iterator->direction != FDB_ITR_FORWARD &&
                    finalRun) {
                    // Cursor ready at next key but we aren't forward iterating
                    dir = -1; // As we were seeking forward, must turn around
                    finalRun = 1; // just run once in opposite direction
                    continue;
                }
                break;
            }
        }
    }
    return FDB_RESULT_SUCCESS;
}

// DOC returned by this function must be freed using 'fdb_doc_free'
static fdb_status _fdb_iterator_seq_prev(fdb_iterator *iterator,
                                     fdb_doc **doc)
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
    fdb_kvs_id_t kv_id, _kv_id;
    fdb_status ret = FDB_RESULT_SUCCESS;
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
    dhandle = iterator->handle.dhandle;

    if (iterator->_offset == BLK_NOT_FOUND || // was iterating over btree
        !iterator->tree_cursor) { // WAL exhausted
        if (iterator->handle.kvs) { // multi KV instance mode
            hr = hbtrie_prev(iterator->seqtrie_iterator, seq_kv, &seq_kv_len,
                             (void *)&offset);
            if (hr == HBTRIE_RESULT_SUCCESS) {
                br = BTREE_RESULT_SUCCESS;
                memcpy(&_kv_id, seq_kv, size_id);
                kv_id = _endian_decode(_kv_id);
                if (kv_id != iterator->handle.kvs->id) {
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
        btreeblk_end(iterator->handle.bhandle);
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
                struct snap_wal_entry, avl);
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
            dhandle = iterator->handle.new_dhandle;
        }
        break;
    }

    _doc.key = NULL;
    _doc.length.keylen = 0;
    _doc.meta = NULL;
    _doc.body = NULL;
    if (iterator->opt & FDB_ITR_METAONLY) {
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
    } else {
        uint64_t _offset = docio_read_doc(dhandle, offset, &_doc);
        if (_offset == offset) {
            return FDB_RESULT_KEY_NOT_FOUND;
        }
        if (_doc.length.flag & DOCIO_DELETED &&
            (iterator->opt & FDB_ITR_NO_DELETES)) {
            free(_doc.key);
            free(_doc.meta);
            free(_doc.body);
            return FDB_RESULT_KEY_NOT_FOUND;
        }
    }

    // To prevent returning duplicate items from sequence iterator, only return
    // those b-tree items that exist in HB-trie but not WAL
    // (WAL items should have already been returned in reverse iteration)
    if (br == BTREE_RESULT_SUCCESS) {
        for (cursor = iterator->tree_cursor_start;
             cursor;
             cursor = avl_next(cursor)) {
            // get the current item of avl tree
            snap_item = _get_entry(cursor, struct snap_wal_entry, avl);
            // we MUST not use 'memcmp' for comparison of two keys
            // because it returns false positive when snap_item->key is a
            // sub-string of _doc.key
            // (e.g, "abc" and "abcd" -> memcmp("abc", "abcd", 3) == 0)
            if (!_fdb_keycmp(snap_item->key, snap_item->keylen,
                             _doc.key, _doc.length.keylen)) {
                free(_doc.key);
                free(_doc.meta);
                free(_doc.body);
                goto start_seq; // B-tree item exists in WAL, skip for now
            }
        }

        // Also look in HB-Trie to eliminate duplicates
        uint64_t hboffset;
        hr = hbtrie_find(iterator->handle.trie, _doc.key, _doc.length.keylen,
                         (void *)&hboffset);
        btreeblk_end(iterator->handle.bhandle);

        if (hr == HBTRIE_RESULT_FAIL) {
            free(_doc.key);
            free(_doc.meta);
            free(_doc.body);
            goto start_seq;
        } else { // If present in HB-trie ensure it's seqnum is in range
            uint64_t _offset;
            _hbdoc.key = _doc.key;
            _hbdoc.meta = NULL;
            hboffset = _endian_decode(hboffset);
            _offset = docio_read_doc_key_meta(iterator->handle.dhandle, hboffset, &_hbdoc);
            if (_offset == hboffset) {
                free(_doc.key);
                free(_doc.meta);
                free(_doc.body);
                return FDB_RESULT_KEY_NOT_FOUND;
            }
            if (_doc.seqnum < _hbdoc.seqnum &&
                _hbdoc.seqnum <= iterator->end_seqnum) {
                free(_doc.key);
                free(_doc.meta);
                free(_hbdoc.meta);
                free(_doc.body);
                goto start_seq;
            }
            free(_hbdoc.meta);
        }
    }

    ret = fdb_doc_create(doc, NULL, 0, NULL, 0, NULL, 0);
    if (ret != FDB_RESULT_SUCCESS) {
        free(_doc.key);
        free(_doc.meta);
        free(_doc.body);
        return ret;
    }

    if (iterator->handle.kvs) {
        // eliminate KV ID from key
        _doc.length.keylen -= size_id;
        memmove(_doc.key, (uint8_t*)_doc.key + size_id, _doc.length.keylen);
    }
    (*doc)->key = _doc.key;
    (*doc)->keylen = _doc.length.keylen;
    (*doc)->meta = _doc.meta;
    (*doc)->metalen = _doc.length.metalen;
    (*doc)->body = _doc.body;
    (*doc)->bodylen = _doc.length.bodylen;
    (*doc)->seqnum = _doc.seqnum;
    (*doc)->deleted = _doc.length.flag & DOCIO_DELETED;
    (*doc)->offset = offset;

    return FDB_RESULT_SUCCESS;
}

// DOC returned by this function must be freed using 'fdb_doc_free'
static fdb_status _fdb_iterator_seq_next(fdb_iterator *iterator,
                                     fdb_doc **doc)
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
    fdb_kvs_id_t kv_id, _kv_id;
    fdb_status ret = FDB_RESULT_SUCCESS;
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
    dhandle = iterator->handle.dhandle;

    // retrieve from sequence b-tree first
    if (iterator->_offset == BLK_NOT_FOUND) {
        if (iterator->handle.kvs) { // multi KV instance mode
            hr = hbtrie_next(iterator->seqtrie_iterator, seq_kv, &seq_kv_len,
                             (void *)&offset);
            if (hr == HBTRIE_RESULT_SUCCESS) {
                br = BTREE_RESULT_SUCCESS;
                memcpy(&_kv_id, seq_kv, size_id);
                kv_id = _endian_decode(_kv_id);
                if (kv_id != iterator->handle.kvs->id) {
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
        btreeblk_end(iterator->handle.bhandle);
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
                                       struct snap_wal_entry, avl);
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
                    dhandle = iterator->handle.new_dhandle;
                }
                break;
            }
        }
    }

    _doc.key = NULL;
    _doc.length.keylen = 0;
    _doc.meta = NULL;
    _doc.body = NULL;
    if (iterator->opt & FDB_ITR_METAONLY) {
        uint64_t _offset = docio_read_doc_key_meta(dhandle,
                                                   offset, &_doc);
        if (_offset == offset) {
            return FDB_RESULT_KEY_NOT_FOUND;
        }
        if (_doc.length.flag & DOCIO_DELETED && (iterator->opt & FDB_ITR_NO_DELETES)) {
            free(_doc.key);
            free(_doc.meta);
            return FDB_RESULT_KEY_NOT_FOUND;
        }
    } else {
        uint64_t _offset = docio_read_doc(dhandle, offset, &_doc);
        if (_offset == offset) {
            return FDB_RESULT_KEY_NOT_FOUND;
        }
        if (_doc.length.flag & DOCIO_DELETED && (iterator->opt & FDB_ITR_NO_DELETES)) {
            free(_doc.key);
            free(_doc.meta);
            free(_doc.body);
            return FDB_RESULT_KEY_NOT_FOUND;
        }
    }

    // To prevent returning duplicate items from sequence iterator, only return
    // those b-tree items that exist in HB-trie but not WAL (visit WAL later)
    if (br == BTREE_RESULT_SUCCESS) {
        for (cursor = iterator->tree_cursor; cursor;
             cursor = avl_next(cursor)) {
            // get the current item of avl tree
            snap_item = _get_entry(cursor, struct snap_wal_entry, avl);
            // we MUST not use 'memcmp' for comparison of two keys
            // because it returns false positive when snap_item->key is a
            // sub-string of _doc.key
            // (e.g, "abc" and "abcd" -> memcmp("abc", "abcd", 3) == 0)
            if (!_fdb_keycmp(snap_item->key, snap_item->keylen,
                             _doc.key, _doc.length.keylen)) {
                free(_doc.key);
                free(_doc.meta);
                free(_doc.body);
                goto start_seq; // B-tree item exists in WAL, skip for now
            }
        }

        // Also look in HB-Trie to eliminate duplicates
        uint64_t hboffset;
        hr = hbtrie_find(iterator->handle.trie, _doc.key, _doc.length.keylen,
                         (void *)&hboffset);
        btreeblk_end(iterator->handle.bhandle);

        if (hr == HBTRIE_RESULT_FAIL) {
            free(_doc.key);
            free(_doc.meta);
            free(_doc.body);
            goto start_seq;
        } else { // If present in HB-trie ensure it's seqnum is in range
            uint64_t _offset;
            _hbdoc.key = _doc.key;
            _hbdoc.meta = NULL;
            hboffset = _endian_decode(hboffset);
            _offset = docio_read_doc_key_meta(iterator->handle.dhandle,
                                              hboffset, &_hbdoc);
            if (_offset == hboffset) {
                free(_doc.key);
                free(_doc.meta);
                free(_doc.body);
                return FDB_RESULT_KEY_NOT_FOUND;
            }
            if (_doc.seqnum < _hbdoc.seqnum &&
                _hbdoc.seqnum <= iterator->end_seqnum) {
                free(_doc.key);
                free(_doc.meta);
                free(_hbdoc.meta);
                free(_doc.body);
                goto start_seq;
            }
            free(_hbdoc.meta);
        }
    }

    ret = fdb_doc_create(doc, NULL, 0, NULL, 0, NULL, 0);
    if (ret != FDB_RESULT_SUCCESS) {
        free(_doc.key);
        free(_doc.meta);
        free(_doc.body);
        return ret;
    }

    if (iterator->handle.kvs) {
        // eliminate KV ID from key
        _doc.length.keylen -= size_id;
        memmove(_doc.key, (uint8_t*)_doc.key + size_id, _doc.length.keylen);
    }
    (*doc)->key = _doc.key;
    (*doc)->keylen = _doc.length.keylen;
    (*doc)->meta = _doc.meta;
    (*doc)->metalen = _doc.length.metalen;
    (*doc)->body = _doc.body;
    (*doc)->bodylen = _doc.length.bodylen;
    (*doc)->seqnum = _doc.seqnum;
    (*doc)->deleted = _doc.length.flag & DOCIO_DELETED;
    (*doc)->offset = offset;

    return FDB_RESULT_SUCCESS;
}

fdb_status fdb_iterator_next_metaonly(fdb_iterator *iterator,
                                    fdb_doc **doc)
{
    fdb_iterator_opt_t opt = iterator->opt;
    iterator->opt |= FDB_ITR_METAONLY;
    fdb_status result = fdb_iterator_next(iterator, doc);
    iterator->opt = opt;
    return result;
}

fdb_status fdb_iterator_prev(fdb_iterator *iterator, fdb_doc **doc)
{
    fdb_status result = FDB_RESULT_SUCCESS;
    if (iterator->hbtrie_iterator || iterator->idtree_iterator) {
        while ((result = _fdb_iterator_prev(iterator, doc)) ==
                FDB_RESULT_KEY_NOT_FOUND);
    } else {
        while ((result = _fdb_iterator_seq_prev(iterator, doc)) ==
                FDB_RESULT_KEY_NOT_FOUND);
    }
    if (result == FDB_RESULT_SUCCESS) {
        iterator->direction = FDB_ITR_REVERSE;
    } else if (iterator->direction != FDB_ITR_DIR_NONE) {
        iterator->direction = FDB_ITR_DIR_NONE;
        if (iterator->seqtree_iterator &&
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
    return result;
}

fdb_status fdb_iterator_next(fdb_iterator *iterator, fdb_doc **doc)
{
    fdb_status result = FDB_RESULT_SUCCESS;
    if (iterator->hbtrie_iterator || iterator->idtree_iterator) {
        while ((result = _fdb_iterator_next(iterator, doc)) ==
                FDB_RESULT_KEY_NOT_FOUND);
    } else {
        while ((result = _fdb_iterator_seq_next(iterator, doc)) ==
                FDB_RESULT_KEY_NOT_FOUND);
    }
    if (result == FDB_RESULT_SUCCESS) {
        iterator->direction = FDB_ITR_FORWARD;
    } else if (iterator->direction != FDB_ITR_DIR_NONE) {
        iterator->direction = FDB_ITR_DIR_NONE;
        if (iterator->seqtree_iterator &&
            iterator->status == FDB_ITR_IDX) {
            iterator->_offset = BLK_NOT_FOUND;
        }
        if (iterator->tree_cursor) {
            if (iterator->status == FDB_ITR_WAL) { // move 2 steps
                iterator->tree_cursor = avl_prev(iterator->tree_cursor_prev);
            } else { // move 1 step if the last doc was returned from the main index
                iterator->tree_cursor = avl_prev(iterator->tree_cursor);
            }
            iterator->tree_cursor_prev = iterator->tree_cursor;
        }
    }
    return result;
}

fdb_status fdb_iterator_close(fdb_iterator *iterator)
{
    hbtrie_result hr;
    struct avl_node *a;
    struct snap_wal_entry *snap_item;

    if (iterator->hbtrie_iterator) {
        hr = hbtrie_iterator_free(iterator->hbtrie_iterator);
        free(iterator->hbtrie_iterator);
    }
    if (iterator->idtree_iterator) {
        btree_iterator_free(iterator->idtree_iterator);
        free(iterator->idtree_iterator);
    }
    if (iterator->seqtree_iterator) {
        btree_iterator_free(iterator->seqtree_iterator);
        free(iterator->seqtree_iterator);
    }
    if (iterator->seqtrie_iterator) {
        hr = hbtrie_iterator_free(iterator->seqtrie_iterator);
        free(iterator->seqtrie_iterator);
    }

    if (iterator->start_key) {
        free(iterator->start_key);
    }
    if (iterator->end_key) {
        free(iterator->end_key);
    }

    if (!iterator->handle.shandle) {
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
    free(iterator->_key);
    free(iterator);

    return FDB_RESULT_SUCCESS;
}

