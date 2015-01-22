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

#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdint.h>

#include "filemgr.h"
#include "common.h"
#include "hash.h"
#include "docio.h"
#include "wal.h"
#include "hash_functions.h"
#include "fdb_internal.h"

#include "memleak.h"

#ifdef __DEBUG
#ifndef __DEBUG_WAL
    #undef DBG
    #undef DBGCMD
    #undef DBGSW
    #define DBG(...)
    #define DBGCMD(...)
    #define DBGSW(n, ...)
#endif
#endif

INLINE uint32_t _wal_hash_bykey(struct hash *hash, struct hash_elem *e)
{
    struct wal_item_header *item = _get_entry(e, struct wal_item_header, he_key);
    return chksum((uint8_t*)item->key, item->keylen) & ((uint64_t)hash->nbuckets - 1);
}

INLINE int _wal_cmp_bykey(struct hash_elem *a, struct hash_elem *b)
{
    struct wal_item_header *aa, *bb;
    aa = _get_entry(a, struct wal_item_header, he_key);
    bb = _get_entry(b, struct wal_item_header, he_key);

    if (aa->keylen == bb->keylen) return memcmp(aa->key, bb->key, aa->keylen);
    else {
        size_t len = MIN(aa->keylen , bb->keylen);
        int cmp = memcmp(aa->key, bb->key, len);
        if (cmp != 0) return cmp;
        else {
            return (int)((int)aa->keylen - (int)bb->keylen);
        }
    }
}

INLINE uint32_t _wal_hash_byseq(struct hash *hash, struct hash_elem *e)
{
    struct wal_item *item = _get_entry(e, struct wal_item, he_seq);
    return (item->seqnum) & ((uint64_t)hash->nbuckets - 1);
}

INLINE int _wal_cmp_byseq(struct hash_elem *a, struct hash_elem *b)
{
    struct wal_item *aa, *bb;
    aa = _get_entry(a, struct wal_item, he_seq);
    bb = _get_entry(b, struct wal_item, he_seq);

    if (aa->flag & WAL_ITEM_MULTI_KV_INS_MODE) {
        // multi KV instance mode
        int size_chunk = aa->header->chunksize;
        fdb_kvs_id_t id_aa, id_bb;
        // KV ID is stored at the first 8 bytes in the key
        buf2kvid(size_chunk, aa->header->key, &id_aa);
        buf2kvid(size_chunk, bb->header->key, &id_bb);
        if (id_aa < id_bb) {
            return -1;
        } else if (id_aa > id_bb) {
            return 1;
        } else {
            return _CMP_U64(aa->seqnum, bb->seqnum);
        }
    } else {
        return _CMP_U64(aa->seqnum, bb->seqnum);
    }
}

fdb_status wal_init(struct filemgr *file, int nbucket)
{
    file->wal->flag = WAL_FLAG_INITIALIZED;
    file->wal->size = 0;
    file->wal->num_flushable = 0;
    file->wal->datasize = 0;
    file->wal->wal_dirty = FDB_WAL_CLEAN;
    hash_init(&file->wal->hash_bykey, nbucket, _wal_hash_bykey, _wal_cmp_bykey);
    hash_init(&file->wal->hash_byseq, nbucket, _wal_hash_byseq, _wal_cmp_byseq);
    list_init(&file->wal->list);
    list_init(&file->wal->txn_list);
    spin_init(&file->wal->lock);

    DBG("wal item size %d\n", (int)sizeof(struct wal_item));
    return FDB_RESULT_SUCCESS;
}

int wal_is_initialized(struct filemgr *file)
{
    return file->wal->flag & WAL_FLAG_INITIALIZED;
}

fdb_status wal_insert(fdb_txn *txn,
                      struct filemgr *file,
                      fdb_doc *doc,
                      uint64_t offset,
                      int is_compactor)
{
    struct wal_item *item;
    struct wal_item_header query, *header;
    struct list_elem *le;
    struct hash_elem *he;
    void *key = doc->key;
    size_t keylen = doc->keylen;
    fdb_kvs_id_t kv_id;

    if (file->kv_header) { // multi KV instance mode
        buf2kvid(file->config->chunksize, doc->key, &kv_id);
    } else {
        kv_id = 0;
    }
    query.key = key;
    query.keylen = keylen;

    spin_lock(&file->wal->lock);

    he = hash_find(&file->wal->hash_bykey, &query.he_key);

    if (he) {
        // already exist .. retrieve header
        header = _get_entry(he, struct wal_item_header, he_key);

        // if this entry is inserted by compactor, AND
        // any other COMMITTED entry for the same key already exists,
        // then we know that the other entry is inserted by the other writer
        // after compaction is started.
        // AND also the other entry is always fresher than
        // the entry inserted by compactor.
        // Thus, we ignore the entry by compactor if and only if
        // there is a committed entry for the same key.
        if (!is_compactor) {
            // normal insert .. find uncommitted item belonging to the same txn
            le = list_begin(&header->items);
            while (le) {
                item = _get_entry(le, struct wal_item, list_elem);

                if (item->txn == txn && !(item->flag & WAL_ITEM_COMMITTED)) {
                    item->flag &= ~WAL_ITEM_FLUSH_READY;

                    hash_remove(&file->wal->hash_byseq, &item->he_seq);
                    item->seqnum = doc->seqnum;
                    hash_insert(&file->wal->hash_byseq, &item->he_seq);

                    file->wal->datasize -= item->doc_size;
                    file->wal->datasize += doc->size_ondisk;
                    item->doc_size = doc->size_ondisk;
                    item->offset = offset;
                    item->action = doc->deleted ? WAL_ACT_LOGICAL_REMOVE : WAL_ACT_INSERT;

                    // move the item to the front of the list (header)
                    list_remove(&header->items, &item->list_elem);
                    list_push_front(&header->items, &item->list_elem);
                    break;
                }
                le = list_next(le);
            }
        } else {
            // insertion by compactor
            // check whether there is a committed entry
            le = list_end(&header->items);
            if (le) {
                item = _get_entry(le, struct wal_item, list_elem);
                if (!(item->flag & WAL_ITEM_COMMITTED)) {
                    // there is no committed entry .. insert the entry from compactor
                    le = NULL;
                    // increase num_docs
                    // (if committed entry already exists,
                    //  num_docs doesn't need to be increased)
                    _kvs_stat_update_attr(file, kv_id, KVS_STAT_WAL_NDOCS, 1);
                }
            }
        }

        if (le == NULL) {
            // not exist
            // create new item
            item = (struct wal_item *)malloc(sizeof(struct wal_item));
            if (is_compactor) {
                item->flag = WAL_ITEM_COMMITTED | WAL_ITEM_BY_COMPACTOR;
            } else {
                item->flag = 0x0;
            }
            if (file->kv_header) { // multi KV instance mode
                item->flag |= WAL_ITEM_MULTI_KV_INS_MODE;
            }
            item->txn = txn;
            if (txn == &file->global_txn) {
                file->wal->num_flushable++;
            }
            item->header = header;

            item->seqnum = doc->seqnum;
            item->action = doc->deleted ? WAL_ACT_LOGICAL_REMOVE : WAL_ACT_INSERT;
            item->offset = offset;
            item->doc_size = doc->size_ondisk;
            file->wal->datasize += doc->size_ondisk;

            hash_insert(&file->wal->hash_byseq, &item->he_seq);
            if (!is_compactor) {
                // insert into header's list
                list_push_front(&header->items, &item->list_elem);
                // also insert into transaction's list
                list_push_back(txn->items, &item->list_elem_txn);
            } else {
                // compactor
                // always push back because it is already committed
                list_push_back(&header->items, &item->list_elem);
            }
            file->wal->size++;
        }
    } else {
        // not exist .. create new one
        // create new header and new item
        header = (struct wal_item_header*)malloc(sizeof(struct wal_item_header));
        list_init(&header->items);
        header->chunksize = file->config->chunksize;
        header->keylen = keylen;
        header->key = (void *)malloc(header->keylen);
        memcpy(header->key, key, header->keylen);
        hash_insert(&file->wal->hash_bykey, &header->he_key);

        item = (struct wal_item *)malloc(sizeof(struct wal_item));
        // entries inserted by compactor is already committed
        if (is_compactor) {
            item->flag = WAL_ITEM_COMMITTED | WAL_ITEM_BY_COMPACTOR;
        } else {
            item->flag = 0x0;
        }
        if (file->kv_header) { // multi KV instance mode
            item->flag |= WAL_ITEM_MULTI_KV_INS_MODE;
        }
        item->txn = txn;
        if (txn == &file->global_txn) {
            file->wal->num_flushable++;
        }
        item->header = header;

        item->seqnum = doc->seqnum;
        item->action = doc->deleted ? WAL_ACT_LOGICAL_REMOVE : WAL_ACT_INSERT;
        item->offset = offset;
        item->doc_size = doc->size_ondisk;
        file->wal->datasize += doc->size_ondisk;
        hash_insert(&file->wal->hash_byseq, &item->he_seq);
        // insert into header's list
        // (pushing front is ok for compactor because no other item already exists)
        list_push_front(&header->items, &item->list_elem);
        if (!is_compactor) {
            // also insert into transaction's list
            list_push_back(txn->items, &item->list_elem_txn);
        } else {
            // increase num_docs
            _kvs_stat_update_attr(file, kv_id, KVS_STAT_WAL_NDOCS, 1);
        }

        // insert header into wal global list
        list_push_back(&file->wal->list, &header->list_elem);
        ++file->wal->size;
    }

    spin_unlock(&file->wal->lock);

    return FDB_RESULT_SUCCESS;
}

static fdb_status _wal_find(fdb_txn *txn,
                            struct filemgr *file,
                            fdb_kvs_id_t kv_id,
                            fdb_doc *doc,
                            uint64_t *offset)
{
    struct wal_item item_query, *item = NULL;
    struct wal_item_header query, *header = NULL;
    struct list_elem *le = NULL;
    struct hash_elem *he = NULL;
    void *key = doc->key;
    size_t keylen = doc->keylen;

    spin_lock(&file->wal->lock);

    if (doc->seqnum == SEQNUM_NOT_USED || (key && keylen>0)) {
        // search by key
        query.key = key;
        query.keylen = keylen;
        he = hash_find(&file->wal->hash_bykey, &query.he_key);
        if (he) {
            // retrieve header
            header = _get_entry(he, struct wal_item_header, he_key);
            le = list_begin(&header->items);
            while(le) {
                item = _get_entry(le, struct wal_item, list_elem);
                // only committed items can be seen by the other handles, OR
                // items belonging to the same txn can be found, OR
                // a transaction's isolation level is read uncommitted.
                if ((item->flag & WAL_ITEM_COMMITTED) ||
                    (item->txn == txn) ||
                    (txn->isolation == FDB_ISOLATION_READ_UNCOMMITTED)) {
                    *offset = item->offset;
                    if (item->action == WAL_ACT_INSERT) {
                        doc->deleted = false;
                    } else {
                        doc->deleted = true;
                    }
                    spin_unlock(&file->wal->lock);
                    return FDB_RESULT_SUCCESS;
                }
                le = list_next(le);
            }
        }
    } else {
        // search by seqnum
        struct wal_item_header temp_header;

        if (file->kv_header) { // multi KV instance mode
            temp_header.key = (void*)alca(uint8_t, file->config->chunksize);
            kvid2buf(file->config->chunksize, kv_id, temp_header.key);
            item_query.header = &temp_header;
        }
        item_query.seqnum = doc->seqnum;
        he = hash_find(&file->wal->hash_byseq, &item_query.he_seq);
        if (he) {
            item = _get_entry(he, struct wal_item, he_seq);
            if ((item->flag & WAL_ITEM_COMMITTED) ||
                (item->txn == txn) ||
                (txn->isolation == FDB_ISOLATION_READ_UNCOMMITTED)) {
                *offset = item->offset;
                if (item->action == WAL_ACT_INSERT) {
                    doc->deleted = false;
                } else {
                    doc->deleted = true;
                }
                spin_unlock(&file->wal->lock);
                return FDB_RESULT_SUCCESS;
            }
        }
    }

    spin_unlock(&file->wal->lock);
    return FDB_RESULT_KEY_NOT_FOUND;
}

fdb_status wal_find(fdb_txn *txn, struct filemgr *file, fdb_doc *doc, uint64_t *offset)
{
    return _wal_find(txn, file, 0, doc, offset);
}

fdb_status wal_find_kv_id(fdb_txn *txn,
                          struct filemgr *file,
                          fdb_kvs_id_t kv_id,
                          fdb_doc *doc,
                          uint64_t *offset)
{
    return _wal_find(txn, file, kv_id, doc, offset);
}

// move all uncommitted items into 'new_file'
fdb_status wal_txn_migration(void *dbhandle,
                             void *new_dhandle,
                             struct filemgr *old_file,
                             struct filemgr *new_file,
                             wal_doc_move_func *move_doc)
{
    uint64_t offset;
    fdb_doc doc;
    fdb_txn *txn;
    struct wal_txn_wrapper *txn_wrapper;
    struct wal_item_header *header;
    struct wal_item *item;
    struct list_elem *e1, *e2;

    spin_lock(&old_file->wal->lock);

    e1 = list_begin(&old_file->wal->list);
    while(e1) {
        header = _get_entry(e1, struct wal_item_header, list_elem);

        e2 = list_end(&header->items);
        while(e2) {
            item = _get_entry(e2, struct wal_item, list_elem);
            if (!(item->flag & WAL_ITEM_COMMITTED)) {
                // not committed yet
                // move doc
                offset = move_doc(dbhandle, new_dhandle, item, &doc);
                // insert into new_file's WAL
                wal_insert(item->txn, new_file, &doc, offset, 0);
                // remove from seq hash table
                hash_remove(&old_file->wal->hash_byseq, &item->he_seq);
                // remove from header's list
                e2 = list_remove_reverse(&header->items, e2);
                // remove from transaction's list
                list_remove(item->txn->items, &item->list_elem_txn);
                // decrease num_flushable of old_file if non-transactional update
                if (item->txn == &old_file->global_txn) {
                    old_file->wal->num_flushable--;
                }
                if (item->action != WAL_ACT_REMOVE) {
                    old_file->wal->datasize -= item->doc_size;
                }
                // free item
                free(item);
                // free doc
                free(doc.key);
                free(doc.meta);
                free(doc.body);
                old_file->wal->size--;
            } else {
                e2= list_prev(e2);
            }
        }

        if (list_begin(&header->items) == NULL) {
            // header's list becomes empty
            // remove from key hash table
            hash_remove(&old_file->wal->hash_bykey, &header->he_key);
            // remove from wal list
            e1 = list_remove(&old_file->wal->list, &header->list_elem);
            // free key & header
            free(header->key);
            free(header);
        } else {
            e1 = list_next(e1);
        }
    }

    // migrate all entries in txn list
    e1 = list_begin(&old_file->wal->txn_list);
    while(e1) {
        txn_wrapper = _get_entry(e1, struct wal_txn_wrapper, le);
        txn = txn_wrapper->txn;
        // except for global_txn
        if (txn != &old_file->global_txn) {
            e1 = list_remove(&old_file->wal->txn_list, &txn_wrapper->le);
            list_push_front(&new_file->wal->txn_list, &txn_wrapper->le);
            // remove previous header info
            txn->prev_hdr_bid = BLK_NOT_FOUND;
        } else {
            e1 = list_next(e1);
        }
    }

    spin_unlock(&old_file->wal->lock);

    return FDB_RESULT_SUCCESS;
}

fdb_status wal_commit(fdb_txn *txn, struct filemgr *file,
                      wal_commit_mark_func *func)
{
    int prev_commit;
    wal_item_action prev_action;
    struct wal_item *item;
    struct wal_item *_item;
    struct list_elem *e1, *e2;
    fdb_kvs_id_t kv_id;
    fdb_status status;

    spin_lock(&file->wal->lock);

    e1 = list_begin(txn->items);
    while(e1) {
        item = _get_entry(e1, struct wal_item, list_elem_txn);
        assert(item->txn == txn);

        if (!(item->flag & WAL_ITEM_COMMITTED)) {
            // get KVS ID
            if (item->flag & WAL_ITEM_MULTI_KV_INS_MODE) {
                buf2kvid(item->header->chunksize, item->header->key, &kv_id);
            } else {
                kv_id = 0;
            }

            item->flag |= WAL_ITEM_COMMITTED;
            // append commit mark if necessary
            if (func) {
                status = func(txn->handle, item->offset);
                if (status != FDB_RESULT_SUCCESS) {
                    spin_unlock(&file->wal->lock);
                    return status;
                }
            }
            // remove previously committed item
            prev_commit = 0;
            // next item on the wal_item_header's items
            e2 = list_next(&item->list_elem);
            while(e2) {
                _item = _get_entry(e2, struct wal_item, list_elem);
                e2 = list_next(e2);
                // committed but not flush-ready
                // (flush-readied item will be removed by flushing)
                if ((_item->flag & WAL_ITEM_COMMITTED) &&
                    !(_item->flag & WAL_ITEM_FLUSH_READY)) {
                    list_remove(&item->header->items, &_item->list_elem);
                    hash_remove(&file->wal->hash_byseq, &_item->he_seq);
                    prev_action = _item->action;
                    prev_commit = 1;
                    file->wal->size--;
                    file->wal->num_flushable--;
                    if (item->action != WAL_ACT_REMOVE) {
                        file->wal->datasize -= _item->doc_size;
                    }
                    free(_item);
                }
            }
            if (!prev_commit) {
                // there was no previous commit .. increase num_docs
                _kvs_stat_update_attr(file, kv_id, KVS_STAT_WAL_NDOCS, 1);
                if (item->action == WAL_ACT_LOGICAL_REMOVE) {
                    _kvs_stat_update_attr(file, kv_id, KVS_STAT_WAL_NDELETES, 1);
                }
            } else {
                if (prev_action == WAL_ACT_INSERT &&
                    item->action == WAL_ACT_LOGICAL_REMOVE) {
                    _kvs_stat_update_attr(file, kv_id, KVS_STAT_WAL_NDELETES, 1);
                } else if (prev_action == WAL_ACT_LOGICAL_REMOVE &&
                           item->action == WAL_ACT_INSERT) {
                    _kvs_stat_update_attr(file, kv_id, KVS_STAT_WAL_NDELETES, -1);
                }
            }
            // increase num_flushable if it is transactional update
            if (item->txn != &file->global_txn) {
                file->wal->num_flushable++;
            }
            // move the committed item to the end of the wal_item_header's list
            list_remove(&item->header->items, &item->list_elem);
            list_push_back(&item->header->items, &item->list_elem);
        }

        // remove from transaction's list
        e1 = list_remove(txn->items, e1);
    }

    spin_unlock(&file->wal->lock);
    return FDB_RESULT_SUCCESS;
}

static int _wal_flush_cmp(struct avl_node *a, struct avl_node *b, void *aux)
{
    struct wal_item *aa, *bb;
    aa = _get_entry(a, struct wal_item, avl);
    bb = _get_entry(b, struct wal_item, avl);

    if (aa->old_offset < bb->old_offset) {
        return -1;
    } else if (aa->old_offset > bb->old_offset) {
        return 1;
    } else {
        // old_offset can be 0 if the document was newly inserted
        if (aa->offset < bb->offset) {
            return -1;
        } else if (aa->offset > bb->offset) {
            return 1;
        } else {
            return 0;
        }
    }
}

fdb_status wal_release_flushed_items(struct filemgr *file,
                                     struct avl_tree *flush_items)
{
    struct avl_tree *tree = flush_items;
    struct avl_node *a;
    struct wal_item *item;
    fdb_kvs_id_t kv_id;

    // scan and remove entries in the avl-tree
    spin_lock(&file->wal->lock);
    while (1) {
        if ((a = avl_first(tree)) == NULL) {
            break;
        }
        item = _get_entry(a, struct wal_item, avl);
        avl_remove(tree, &item->avl);

        // get KVS ID
        if (item->flag & WAL_ITEM_MULTI_KV_INS_MODE) {
            buf2kvid(item->header->chunksize, item->header->key, &kv_id);
        } else {
            kv_id = 0;
        }

        list_remove(&item->header->items, &item->list_elem);
        hash_remove(&file->wal->hash_byseq, &item->he_seq);
        if (list_begin(&item->header->items) == NULL) {
            // wal_item_header becomes empty
            // free header and remove from hash table & wal list
            list_remove(&file->wal->list, &item->header->list_elem);
            hash_remove(&file->wal->hash_bykey, &item->header->he_key);
            free(item->header->key);
            free(item->header);
        }

        if (item->action == WAL_ACT_LOGICAL_REMOVE ||
            item->action == WAL_ACT_REMOVE) {
            _kvs_stat_update_attr(file, kv_id, KVS_STAT_WAL_NDELETES, -1);
        }
        _kvs_stat_update_attr(file, kv_id, KVS_STAT_WAL_NDOCS, -1);
        file->wal->size--;
        file->wal->num_flushable--;
        if (item->action != WAL_ACT_REMOVE) {
            file->wal->datasize -= item->doc_size;
        }
        free(item);
    }
    spin_unlock(&file->wal->lock);

    return FDB_RESULT_SUCCESS;
}

static fdb_status _wal_flush(struct filemgr *file,
                             void *dbhandle,
                             wal_flush_func *flush_func,
                             wal_get_old_offset_func *get_old_offset,
                             struct avl_tree *flush_items,
                             bool by_compactor)
{
    struct avl_tree *tree = flush_items;
    struct avl_node *a;
    struct list_elem *e, *ee;
    struct wal_item *item;
    struct wal_item_header *header;

    // sort by old byte-offset of the document (for sequential access)
    spin_lock(&file->wal->lock);
    avl_init(tree, NULL);
    e = list_begin(&file->wal->list);
    while(e){
        header = _get_entry(e, struct wal_item_header, list_elem);
        ee = list_end(&header->items);
        while(ee) {
            item = _get_entry(ee, struct wal_item, list_elem);
            // committed but not flushed items
            if (!(item->flag & WAL_ITEM_COMMITTED)) {
                break;
            }
            if (by_compactor &&
                !(item->flag & WAL_ITEM_BY_COMPACTOR)) {
                // during compaction, do not flush normally committed item
                break;
            }
            if (!(item->flag & WAL_ITEM_FLUSH_READY)) {
                item->flag |= WAL_ITEM_FLUSH_READY;
                // if WAL_ITEM_FLUSH_READY flag is set,
                // this item becomes immutable, so that
                // no other concurrent thread modifies it.
                spin_unlock(&file->wal->lock);
                item->old_offset = get_old_offset(dbhandle, item);
                avl_insert(tree, &item->avl, _wal_flush_cmp);
                spin_lock(&file->wal->lock);
            }
            ee = list_prev(ee);
        }
        e = list_next(e);
    }
    spin_unlock(&file->wal->lock);

    // scan and flush entries in the avl-tree
    a = avl_first(tree);
    while (a) {
        item = _get_entry(a, struct wal_item, avl);
        a = avl_next(a);

        // check weather this item is updated after insertion into tree
        if (item->flag & WAL_ITEM_FLUSH_READY) {
            fdb_status fs = flush_func(dbhandle, item);
            if (fs != FDB_RESULT_SUCCESS) {
                return fs;
            }
        }
    }

    return FDB_RESULT_SUCCESS;
}

fdb_status wal_flush(struct filemgr *file,
                     void *dbhandle,
                     wal_flush_func *flush_func,
                     wal_get_old_offset_func *get_old_offset,
                     struct avl_tree *flush_items)
{
    return _wal_flush(file, dbhandle, flush_func, get_old_offset,
                      flush_items, false);
}

fdb_status wal_flush_by_compactor(struct filemgr *file,
                                  void *dbhandle,
                                  wal_flush_func *flush_func,
                                  wal_get_old_offset_func *get_old_offset,
                                  struct avl_tree *flush_items)
{
    return _wal_flush(file, dbhandle, flush_func, get_old_offset,
                      flush_items, true);
}

// Used to copy all the WAL items for non-durable snapshots
fdb_status wal_snapshot(struct filemgr *file,
                        void *dbhandle, fdb_txn *txn,
                        wal_snapshot_func *snapshot_func)
{
    struct list_elem *e, *ee;
    struct wal_item *item;
    struct wal_item_header *header;

    spin_lock(&file->wal->lock);
    e = list_begin(&file->wal->list);
    while(e){
        header = _get_entry(e, struct wal_item_header, list_elem);
        ee = list_begin(&header->items);
        while(ee) {
            item = _get_entry(ee, struct wal_item, list_elem);
            if (!(item->flag & WAL_ITEM_COMMITTED) && // Skip uncommitted items
                item->txn != &file->global_txn && // that aren't part of global
                item->txn != txn) { // nor current transaction
                ee = list_next(ee);
                continue;
            }
            fdb_doc doc;
            doc.keylen = item->header->keylen;
            doc.key = malloc(doc.keylen); // (freed in fdb_snapshot_close)
            memcpy(doc.key, item->header->key, doc.keylen);
            doc.seqnum = item->seqnum;
            doc.deleted = (item->action == WAL_ACT_LOGICAL_REMOVE ||
                    item->action == WAL_ACT_REMOVE);
            snapshot_func(dbhandle, &doc, item->offset);
            break; // We just require a single latest copy in the snapshot
        }
        e = list_next(e);
    }
    spin_unlock(&file->wal->lock);

    return FDB_RESULT_SUCCESS;
}

// discard entries in txn
fdb_status wal_discard(struct filemgr *file, fdb_txn *txn)
{
    struct wal_item *item;
    struct list_elem *e;

    spin_lock(&file->wal->lock);

    e = list_begin(txn->items);
    while(e) {
        item = _get_entry(e, struct wal_item, list_elem_txn);

        // remove from seq hash table
        hash_remove(&file->wal->hash_byseq, &item->he_seq);
        // remove from header's list
        list_remove(&item->header->items, &item->list_elem);
        // remove header if empty
        if (list_begin(&item->header->items) == NULL) {
            //remove from key hash table
            hash_remove(&file->wal->hash_bykey, &item->header->he_key);
            // remove from wal list
            list_remove(&file->wal->list, &item->header->list_elem);
            // free key and header
            free(item->header->key);
            free(item->header);
        }
        // remove from txn's list
        e = list_remove(txn->items, e);
        if (item->txn == &file->global_txn ||
            item->flag & WAL_ITEM_COMMITTED) {
            file->wal->num_flushable--;
        }
        if (item->action != WAL_ACT_REMOVE) {
            file->wal->datasize -= item->doc_size;
        }
        // free
        free(item);
        file->wal->size--;
    }

    spin_unlock(&file->wal->lock);
    return FDB_RESULT_SUCCESS;
}

typedef enum wal_discard_type {
    WAL_DISCARD_UNCOMMITTED_ONLY,
    WAL_DISCARD_ALL,
    WAL_DISCARD_KV_INS,
} wal_discard_t;

// discard all entries
static fdb_status _wal_close(struct filemgr *file,
                             wal_discard_t type, void *aux)
{
    struct wal_item *item;
    struct wal_item_header *header;
    struct list_elem *e1, *e2;
    fdb_kvs_id_t kv_id, kv_id_req;
    bool committed;
    wal_item_action committed_item_action;

    if (type == WAL_DISCARD_KV_INS) { // multi KV ins mode
        if (aux == NULL) { // aux must contain pointer to KV ID
            return FDB_RESULT_INVALID_ARGS;
        }
        kv_id_req = *(fdb_kvs_id_t*)aux;
    }

    spin_lock(&file->wal->lock);

    e1 = list_begin(&file->wal->list);
    while(e1){
        header = _get_entry(e1, struct wal_item_header, list_elem);

        if (type == WAL_DISCARD_KV_INS) { // multi KV ins mode
            buf2kvid(header->chunksize, header->key, &kv_id);
            // begin while loop only on matching KV ID
            e2 = (kv_id == kv_id_req)?(list_begin(&header->items)):(NULL);
        } else {
            kv_id = 0;
            e2 = list_begin(&header->items);
        }

        committed = false;
        while(e2) {
            item = _get_entry(e2, struct wal_item, list_elem);

            if ( type == WAL_DISCARD_ALL ||
                (type == WAL_DISCARD_UNCOMMITTED_ONLY &&
                    !(item->flag & WAL_ITEM_COMMITTED)) ||
                 type == WAL_DISCARD_KV_INS) {
                // remove from header's list
                e2 = list_remove(&header->items, e2);
                if (!(item->flag & WAL_ITEM_COMMITTED)) {
                    // and also remove from transaction's list
                    list_remove(item->txn->items, &item->list_elem_txn);
                } else {
                    // committed item exists and will be removed
                    committed = true;
                    committed_item_action = item->action;
                }
                // remove from seq hash table
                hash_remove(&file->wal->hash_byseq, &item->he_seq);

                if (item->action != WAL_ACT_REMOVE) {
                    file->wal->datasize -= item->doc_size;
                }
                if (item->txn == &file->global_txn) {
                    file->wal->num_flushable--;
                }

                free(item);
                file->wal->size--;
            } else {
                e2 = list_next(e2);
            }
        }
        e1 = list_next(e1);

        if (list_begin(&header->items) == NULL) {
            // wal_item_header becomes empty
            // free header and remove from hash table & wal list
            list_remove(&file->wal->list, &header->list_elem);
            hash_remove(&file->wal->hash_bykey, &header->he_key);
            free(header->key);
            free(header);

            if (committed) {
                // this document was committed
                // num_docs and num_deletes should be updated
                if (committed_item_action == WAL_ACT_LOGICAL_REMOVE ||
                    committed_item_action == WAL_ACT_REMOVE) {
                    _kvs_stat_update_attr(file, kv_id, KVS_STAT_WAL_NDELETES, -1);
                }
                _kvs_stat_update_attr(file, kv_id, KVS_STAT_WAL_NDOCS, -1);
            }
        }
    }

    spin_unlock(&file->wal->lock);
    return FDB_RESULT_SUCCESS;
}

fdb_status wal_close(struct filemgr *file)
{
    return _wal_close(file, WAL_DISCARD_UNCOMMITTED_ONLY, NULL);
}

// discard all WAL entries
fdb_status wal_shutdown(struct filemgr *file)
{
    fdb_status wr = _wal_close(file, WAL_DISCARD_ALL, NULL);
    file->wal->size = 0;
    file->wal->num_flushable = 0;
    return wr;
}

// discard all WAL entries belonging to KV_ID
fdb_status wal_close_kv_ins(struct filemgr *file,
                            fdb_kvs_id_t kv_id)
{
    return _wal_close(file, WAL_DISCARD_KV_INS, &kv_id);
}

size_t wal_get_size(struct filemgr *file)
{
    return file->wal->size;
}

size_t wal_get_num_flushable(struct filemgr *file)
{
    return file->wal->num_flushable;
}

size_t wal_get_num_docs(struct filemgr *file) {
    return _kvs_stat_get_sum(file, KVS_STAT_WAL_NDOCS);
}

size_t wal_get_num_deletes(struct filemgr *file) {
    return _kvs_stat_get_sum(file, KVS_STAT_WAL_NDELETES);
}

size_t wal_get_datasize(struct filemgr *file)
{
    size_t datasize = 0;
    spin_lock(&file->wal->lock);
    datasize = file->wal->datasize;
    spin_unlock(&file->wal->lock);

    return datasize;
}

void wal_set_dirty_status(struct filemgr *file, wal_dirty_t status)
{
    spin_lock(&file->wal->lock);
    file->wal->wal_dirty = status;
    spin_unlock(&file->wal->lock);
}

wal_dirty_t wal_get_dirty_status(struct filemgr *file)
{
    wal_dirty_t ret;
    spin_lock(&file->wal->lock);
    ret = file->wal->wal_dirty;
    spin_unlock(&file->wal->lock);
    return ret;
}

void wal_add_transaction(struct filemgr *file, fdb_txn *txn)
{
    spin_lock(&file->wal->lock);
    list_push_front(&file->wal->txn_list, &txn->wrapper->le);
    spin_unlock(&file->wal->lock);
}

void wal_remove_transaction(struct filemgr *file, fdb_txn *txn)
{
    spin_lock(&file->wal->lock);
    list_remove(&file->wal->txn_list, &txn->wrapper->le);
    spin_unlock(&file->wal->lock);
}

fdb_txn * wal_earliest_txn(struct filemgr *file, fdb_txn *cur_txn)
{
    struct list_elem *le;
    struct wal_txn_wrapper *txn_wrapper;
    fdb_txn *txn;
    fdb_txn *ret = NULL;
    bid_t bid = BLK_NOT_FOUND;

    spin_lock(&file->wal->lock);

    le = list_begin(&file->wal->txn_list);
    while(le) {
        txn_wrapper = _get_entry(le, struct wal_txn_wrapper, le);
        txn = txn_wrapper->txn;
        if (txn != cur_txn && list_begin(txn->items)) {
            if (bid == BLK_NOT_FOUND || txn->prev_hdr_bid < bid) {
                bid = txn->prev_hdr_bid;
                ret = txn;
            }
        }
        le = list_next(le);
    }
    spin_unlock(&file->wal->lock);

    return ret;
}

bool wal_txn_exists(struct filemgr *file)
{
    struct list_elem *le;
    struct wal_txn_wrapper *txn_wrapper;
    fdb_txn *txn;

    spin_lock(&file->wal->lock);

    le = list_begin(&file->wal->txn_list);
    while(le) {
        txn_wrapper = _get_entry(le, struct wal_txn_wrapper, le);
        txn = txn_wrapper->txn;
        if (txn != &file->global_txn) {
            spin_unlock(&file->wal->lock);
            return true;
        }
        le = list_next(le);
    }
    spin_unlock(&file->wal->lock);

    return false;
}
