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

    if (handle->config.cmp_fixed) {
        // custom compare function for fixed-size key
        return handle->config.cmp_fixed(aa->key, bb->key);
    } else if (handle->config.cmp_variable) {
        // custom compare function for variable-length key
        return handle->config.cmp_variable(aa->key, aa->keylen,
                                           bb->key, bb->keylen);
    } else {
        return _fdb_keycmp(aa->key, aa->keylen, bb->key, bb->keylen);
    }
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
    struct list_elem *e;
    struct wal_item *wal_item;
    struct snap_wal_entry *snap_item;

    if (handle == NULL) {
        return FDB_RESULT_INVALID_ARGS;
    }

    fdb_iterator *iterator = (fdb_iterator *) malloc(sizeof(fdb_iterator));

    iterator->handle = *handle;
    iterator->opt = opt;

    iterator->_key = (void*)malloc(FDB_MAX_KEYLEN);
    iterator->_keylen = 0;
    iterator->_offset = BLK_NOT_FOUND;
    iterator->hbtrie_iterator = NULL;
    iterator->idtree_iterator = NULL;
    iterator->seqtree_iterator = NULL;

    if (start_key == NULL) start_keylen = 0;
    if (end_key == NULL) {
        iterator->end_key = NULL;
        end_keylen = 0;
    }else{
        iterator->end_key = (void*)malloc(end_keylen);
        memcpy(iterator->end_key, end_key, end_keylen);
    }
    iterator->end_keylen = end_keylen;

    if (handle->config.cmp_variable) {
        // custom compare function for variable length key
        uint8_t *initial_key = alca(uint8_t, handle->config.chunksize);
        iterator->idtree_iterator = (struct btree_iterator *)malloc(sizeof(struct btree_iterator));

        if (start_key) {
            _set_var_key(initial_key, (void*)start_key, start_keylen);
            br = btree_iterator_init(handle->idtree, iterator->idtree_iterator, initial_key);
            _free_var_key(initial_key);
        } else {
            br = btree_iterator_init(handle->idtree, iterator->idtree_iterator, NULL);
        }

        if (br == BTREE_RESULT_FAIL) {
            free(iterator);
            return FDB_RESULT_ITERATOR_FAIL;
        }
    } else {
        // create an iterator handle for hb-trie
        iterator->hbtrie_iterator = (struct hbtrie_iterator *)malloc(sizeof(struct hbtrie_iterator));
        hr = hbtrie_iterator_init(handle->trie, iterator->hbtrie_iterator,
                                  (void *)start_key, start_keylen);
        if (hr == HBTRIE_RESULT_FAIL) {
            free(iterator);
            return FDB_RESULT_ITERATOR_FAIL;
        }
    }

    // create a snapshot for WAL (avl-tree)
    // (from the beginning to the last committed element)

    // init tree
    if (!handle->shandle) {
        iterator->wal_tree = (struct avl_tree*)malloc(sizeof(struct avl_tree));
        avl_init(iterator->wal_tree, (void*)handle);

        spin_lock(&handle->file->wal->lock);
        e = list_begin(&handle->file->wal->list);
        while(e) {
            wal_item = _get_entry(e, struct wal_item, list_elem);
            if (start_key) {
                if (handle->config.cmp_fixed) {
                    // custom compare function for fixed size key
                    cmp = handle->config.cmp_fixed((void*)start_key,
                                                   wal_item->key);
                } else if (handle->config.cmp_variable) {
                    // custom compare function for variable length key
                    cmp = handle->config.cmp_variable(
                            (void*)start_key, start_keylen,
                            wal_item->key, wal_item->keylen);
                } else {
                    cmp = _fdb_keycmp((void *)start_key, start_keylen,
                            wal_item->key, wal_item->keylen);
                }
            }else{
                cmp = 0;
            }

            if (cmp <= 0) {
                // copy from WAL_ITEM
                snap_item = (struct snap_wal_entry*)malloc(sizeof(
                                                    struct snap_wal_entry));
                snap_item->keylen = wal_item->keylen;
                snap_item->key = (void*)malloc(snap_item->keylen);
                memcpy(snap_item->key, wal_item->key, snap_item->keylen);
                snap_item->action = wal_item->action;
                snap_item->offset = wal_item->offset;

                // insert into tree
                avl_insert(iterator->wal_tree, &snap_item->avl, _fdb_wal_cmp);
            }

            if (e == handle->file->wal->last_commit) break;
            e = list_next(e);
        }

        spin_unlock(&handle->file->wal->lock);
    } else {
        iterator->wal_tree = handle->shandle->key_tree;
    }

    iterator->tree_cursor = avl_first(iterator->wal_tree);

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
    struct list_elem *e;
    struct wal_item *wal_item;
    struct snap_wal_entry *snap_item;
    fdb_seqnum_t _start_seq = _endian_encode(start_seq);

    if (handle == NULL || ptr_iterator == NULL ||
        start_seq > end_seq) {
        return FDB_RESULT_INVALID_ARGS;
    }

    fdb_iterator *iterator = (fdb_iterator *) malloc(sizeof(fdb_iterator));

    iterator->handle = *handle;
    iterator->hbtrie_iterator = NULL;
    iterator->idtree_iterator = NULL;
    iterator->seqtree_iterator = (struct btree_iterator *)
                                 malloc(sizeof(struct btree_iterator));
    iterator->_key = NULL;
    iterator->_keylen = 0;
    iterator->opt = opt;
    iterator->_offset = BLK_NOT_FOUND;
    iterator->_seqnum = start_seq;
    iterator->end_seqnum = end_seq;

    iterator->end_key = NULL;
    iterator->end_keylen = 0;

    // create an iterator handle for b-tree
    btree_iterator_init(handle->seqtree, iterator->seqtree_iterator,
                        (void *)(start_seq ? &_start_seq : NULL));

    // create a snapshot for WAL (avl-tree)
    // (from the beginning to the last committed element)

    // init tree
    if (!handle->shandle) {
        iterator->wal_tree = (struct avl_tree*)malloc(sizeof(
                    struct avl_tree));
        avl_init(iterator->wal_tree, (void*)_fdb_seqnum_cmp);

        spin_lock(&handle->file->wal->lock);
        e = list_begin(&handle->file->wal->list);
        while(e) {
            wal_item = _get_entry(e, struct wal_item, list_elem);
            if (start_seq <= wal_item->seqnum && wal_item->seqnum <= end_seq) {
                // copy from WAL_ITEM
                snap_item = (struct snap_wal_entry*)malloc(sizeof(
                            struct snap_wal_entry));
                snap_item->keylen = wal_item->keylen;
                snap_item->key = (void*)malloc(snap_item->keylen);
                memcpy(snap_item->key, wal_item->key, snap_item->keylen);
                snap_item->seqnum = wal_item->seqnum;
                snap_item->action = wal_item->action;
                snap_item->offset = wal_item->offset;

                // insert into tree
                avl_insert(iterator->wal_tree, &snap_item->avl,
                           _fdb_seqnum_cmp);
            }

            if (e == handle->file->wal->last_commit) break;
            e = list_next(e);
        }
        spin_unlock(&handle->file->wal->lock);
    } else {
        iterator->wal_tree = handle->shandle->seq_tree;
    }

    iterator->tree_cursor = avl_first(iterator->wal_tree);

    *ptr_iterator = iterator;

    return FDB_RESULT_SUCCESS;
}

// DOC returned by this function must be freed using 'fdb_doc_free'
static fdb_status _fdb_iterator_next(fdb_iterator *iterator,
                                     fdb_doc **doc,
                                     uint64_t *doc_offset_out)
{
    int cmp;
    void *key;
    size_t keylen;
    uint64_t offset;
    hbtrie_result hr = HBTRIE_RESULT_SUCCESS;
    btree_result br;
    fdb_status fs;
    struct docio_object _doc;
    struct snap_wal_entry *snap_item = NULL;

start:
    key = iterator->_key;

    // retrieve from hb-trie
    if (iterator->_offset == BLK_NOT_FOUND) {
        // no key waiting for being returned
        // get next key from hb-trie (or idtree)
        if (iterator->handle.config.cmp_variable) {
            uint8_t *var_key = alca(uint8_t, iterator->handle.config.chunksize);
            memset(var_key, 0, iterator->handle.config.chunksize);

            br = btree_next(iterator->idtree_iterator, var_key, (void*)&iterator->_offset);
            if (br == BTREE_RESULT_FAIL) {
                hr = HBTRIE_RESULT_FAIL;
            } else {
                _get_var_key(var_key, key, &iterator->_keylen);
                _free_var_key(var_key);
            }
        } else {
            hr = hbtrie_next(
                iterator->hbtrie_iterator, key, &iterator->_keylen, (void*)&iterator->_offset);
        }
        btreeblk_end(iterator->handle.bhandle);
        iterator->_offset = _endian_decode(iterator->_offset);
    }
    keylen = iterator->_keylen;
    offset = iterator->_offset;

    if (hr == HBTRIE_RESULT_FAIL && iterator->tree_cursor == NULL) {
        return FDB_RESULT_ITERATOR_FAIL;
    }

    while (iterator->tree_cursor) {
        // get the current item of avl-tree
        snap_item = _get_entry(iterator->tree_cursor, struct snap_wal_entry, avl);
        if (hr != HBTRIE_RESULT_FAIL) {
            if (iterator->handle.config.cmp_fixed) {
                // custom compare function for fixed size key
                cmp = iterator->handle.config.cmp_fixed(
                          snap_item->key, key);
            } else if (iterator->handle.config.cmp_variable) {
                // custom compare function for variable length key
                cmp = iterator->handle.config.cmp_variable(
                          snap_item->key, snap_item->keylen,
                          key, keylen);
            } else {
                cmp = _fdb_keycmp(snap_item->key, snap_item->keylen, key, keylen);
            }
        }else{
            // no more docs in hb-trie
            cmp = -1;
        }

        if (cmp <= 0) {
            // key[WAL] <= key[hb-trie] .. take key[WAL] first
            iterator->tree_cursor = avl_next(iterator->tree_cursor);
            uint8_t drop_logical_deletes =
                (snap_item->action == WAL_ACT_LOGICAL_REMOVE) &&
                (iterator->opt & FDB_ITR_NO_DELETES);
            if (cmp < 0) {
                if (snap_item->action == WAL_ACT_REMOVE || drop_logical_deletes) {
                    if (hr == HBTRIE_RESULT_FAIL && iterator->tree_cursor == NULL) {
                        return FDB_RESULT_ITERATOR_FAIL;
                    }
                    // this key is removed .. get next key[WAL]
                    continue;
                }
            }else{
                iterator->_offset = BLK_NOT_FOUND;
                if (snap_item->action == WAL_ACT_REMOVE || drop_logical_deletes) {
                    // the key is removed .. start over again
                    goto start;
                }
            }

            key = snap_item->key;
            keylen = snap_item->keylen;
            offset = snap_item->offset;
        }
        break;
    }

    if (offset == iterator->_offset) {
        // take key[hb-trie] & and fetch the next key[hb-trie] at next turn
        iterator->_offset = BLK_NOT_FOUND;
    }

    if (iterator->end_key) {

        if (iterator->handle.config.cmp_fixed) {
            // custom compare function for fixed size key
            cmp = iterator->handle.config.cmp_fixed(
                      iterator->end_key, key);
        } else if (iterator->handle.config.cmp_variable) {
            // custom compare function for variable length key
            cmp = iterator->handle.config.cmp_variable(
                      iterator->end_key, iterator->end_keylen,
                      key, keylen);
        } else {
            cmp = _fdb_keycmp(iterator->end_key, iterator->end_keylen, key, keylen);
        }

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
        uint64_t _offset = docio_read_doc_key_meta(iterator->handle.dhandle,
                                                   offset, &_doc);
        if (_offset == offset) {
            return FDB_RESULT_KEY_NOT_FOUND;
        }
        if (_doc.length.flag & DOCIO_DELETED && (iterator->opt & FDB_ITR_NO_DELETES)) {
            free(_doc.meta);
            return FDB_RESULT_KEY_NOT_FOUND;
        }
        if (doc_offset_out) {
            *doc_offset_out = offset;
        }
    } else {
        uint64_t _offset = docio_read_doc(iterator->handle.dhandle, offset, &_doc);
        if (_offset == offset) {
            return FDB_RESULT_KEY_NOT_FOUND;
        }
        if (_doc.length.flag & DOCIO_DELETED && (iterator->opt & FDB_ITR_NO_DELETES)) {
            free(_doc.meta);
            free(_doc.body);
            return FDB_RESULT_KEY_NOT_FOUND;
        }
    }

    fs = fdb_doc_create(doc, key, keylen, NULL, 0, NULL, 0);
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
static fdb_status _fdb_iterator_seq_next(fdb_iterator *iterator,
                                     fdb_doc **doc,
                                     uint64_t *doc_offset_out)
{
    uint64_t offset;
    btree_result br = BTREE_RESULT_FAIL;
    hbtrie_result hr;
    fdb_status fs;
    struct docio_object _doc;
    struct docio_object _hbdoc;
    struct snap_wal_entry *snap_item = NULL;
    fdb_seqnum_t seqnum;
    fdb_status ret = FDB_RESULT_SUCCESS;
    struct avl_node *cursor;

start_seq:
    seqnum = iterator->_seqnum;

    // retrieve from sequence b-tree first
    if (iterator->_offset == BLK_NOT_FOUND) {
        br = btree_next(iterator->seqtree_iterator, &seqnum, (void *) &offset);
        if (br == BTREE_RESULT_SUCCESS) {
            seqnum = _endian_decode(seqnum);
            iterator->_seqnum = seqnum;
            if (seqnum > iterator->end_seqnum) {
                return FDB_RESULT_ITERATOR_FAIL;
            }
            offset = _endian_decode(offset);
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

                offset = snap_item->offset;
                iterator->_offset = offset; // stops b-tree lookups. favor wal
                break;
            }
        }
    }

    _doc.key = NULL;
    _doc.length.keylen = 0;
    _doc.meta = NULL;
    _doc.body = NULL;
    if (iterator->opt & FDB_ITR_METAONLY) {
        uint64_t _offset = docio_read_doc_key_meta(iterator->handle.dhandle,
                                                   offset, &_doc);
        if (_offset == offset) {
            return FDB_RESULT_KEY_NOT_FOUND;
        }
        if (_doc.length.flag & DOCIO_DELETED && (iterator->opt & FDB_ITR_NO_DELETES)) {
            free(_doc.key);
            free(_doc.meta);
            return FDB_RESULT_KEY_NOT_FOUND;
        }
        if (doc_offset_out) {
            *doc_offset_out = offset;
        }
    } else {
        uint64_t _offset = docio_read_doc(iterator->handle.dhandle, offset, &_doc);
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
            if (!memcmp(snap_item->key, _doc.key, snap_item->keylen)) {
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
            _hbdoc.meta = _doc.meta;
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
                free(_doc.body);
                goto start_seq;
            }
        }
    }

    ret = fdb_doc_create(doc, NULL, 0, NULL, 0, NULL, 0);
    if (ret != FDB_RESULT_SUCCESS) {
        free(_doc.key);
        free(_doc.meta);
        free(_doc.body);
        return ret;
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

fdb_status fdb_iterator_next_offset(fdb_iterator *iterator,
                                    fdb_doc **doc,
                                    uint64_t *doc_offset_out)
{
    fdb_iterator_opt_t opt = iterator->opt;
    iterator->opt |= FDB_ITR_METAONLY;
    fdb_status result = FDB_RESULT_SUCCESS;
    if (iterator->hbtrie_iterator) {
        while ((result = _fdb_iterator_next(iterator, doc, doc_offset_out)) ==
                FDB_RESULT_KEY_NOT_FOUND);
    } else {
        while ((result = _fdb_iterator_seq_next(iterator, doc,
                                                doc_offset_out)) ==
                FDB_RESULT_KEY_NOT_FOUND);
    }
    iterator->opt = opt;
    return result;
}

fdb_status fdb_iterator_next(fdb_iterator *iterator, fdb_doc **doc)
{
    fdb_status result = FDB_RESULT_SUCCESS;
    if (iterator->hbtrie_iterator || iterator->idtree_iterator) {
        while ((result = _fdb_iterator_next(iterator, doc, NULL)) ==
                FDB_RESULT_KEY_NOT_FOUND);
    } else {
        while ((result = _fdb_iterator_seq_next(iterator, doc, NULL)) ==
                FDB_RESULT_KEY_NOT_FOUND);
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

    if (iterator->end_key)
        free(iterator->end_key);

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

