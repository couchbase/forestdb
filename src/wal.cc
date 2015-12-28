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

INLINE int _wal_cmp_bykey(struct avl_node *a, struct avl_node *b, void *aux)
{
    struct wal_item_header *aa, *bb;
    aa = _get_entry(a, struct wal_item_header, avl_key);
    bb = _get_entry(b, struct wal_item_header, avl_key);
    (void)aux;

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

INLINE int _wal_cmp_byseq(struct avl_node *a, struct avl_node *b, void *aux)
{
    struct wal_item *aa, *bb;
    aa = _get_entry(a, struct wal_item, avl_seq);
    bb = _get_entry(b, struct wal_item, avl_seq);

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
    size_t num_shards;

    file->wal->flag = WAL_FLAG_INITIALIZED;
    atomic_init_uint32_t(&file->wal->size, 0);
    atomic_init_uint32_t(&file->wal->num_flushable, 0);
    atomic_init_uint64_t(&file->wal->datasize, 0);
    atomic_init_uint64_t(&file->wal->mem_overhead, 0);
    file->wal->wal_dirty = FDB_WAL_CLEAN;

    list_init(&file->wal->txn_list);
    spin_init(&file->wal->lock);

    if (file->config->num_wal_shards) {
        file->wal->num_shards = file->config->num_wal_shards;
    } else {
        file->wal->num_shards = DEFAULT_NUM_WAL_PARTITIONS;
    }

    num_shards = wal_get_num_shards(file);
    file->wal->key_shards = (wal_shard_by_key *)
        malloc(sizeof(struct wal_shard_by_key) * num_shards);
    file->wal->seq_shards = (wal_shard_by_seq *)
        malloc(sizeof(struct wal_shard_by_seq) * num_shards);

    for (int i = num_shards - 1; i >= 0; --i) {
        avl_init(&file->wal->key_shards[i].map_bykey, NULL);
        avl_init(&file->wal->seq_shards[i].map_byseq, NULL);
        spin_init(&file->wal->key_shards[i].lock);
        spin_init(&file->wal->seq_shards[i].lock);
    }

    DBG("wal item size %" _F64 "\n", sizeof(struct wal_item));
    return FDB_RESULT_SUCCESS;
}

int wal_is_initialized(struct filemgr *file)
{
    return file->wal->flag & WAL_FLAG_INITIALIZED;
}

INLINE fdb_status _wal_insert(fdb_txn *txn,
                              struct filemgr *file,
                              fdb_doc *doc,
                              uint64_t offset,
                              wal_insert_by caller,
                              bool immediate_remove)
{
    struct wal_item *item;
    struct wal_item_header query, *header;
    struct list_elem *le;
    struct avl_node *node;
    void *key = doc->key;
    size_t keylen = doc->keylen;
    size_t chk_sum;
    size_t shard_num;
    fdb_kvs_id_t kv_id;

    if (file->kv_header) { // multi KV instance mode
        buf2kvid(file->config->chunksize, doc->key, &kv_id);
    } else {
        kv_id = 0;
    }
    query.key = key;
    query.keylen = keylen;
    chk_sum = get_checksum((uint8_t*)key, keylen);
    shard_num = chk_sum % file->wal->num_shards;
    if (caller == WAL_INS_WRITER) {
        spin_lock(&file->wal->key_shards[shard_num].lock);
    }

    node = avl_search(&file->wal->key_shards[shard_num].map_bykey,
                      &query.avl_key, _wal_cmp_bykey);

    if (node) {
        // already exist .. retrieve header
        header = _get_entry(node, struct wal_item_header, avl_key);

        // find uncommitted item belonging to the same txn
        le = list_begin(&header->items);
        while (le) {
            item = _get_entry(le, struct wal_item, list_elem);

            if (item->txn == txn &&
                (!(item->flag & WAL_ITEM_COMMITTED) ||
                 /* compactor should be able to overwrite committed item */
                 caller == WAL_INS_COMPACT_PHASE1) ) {

                item->flag &= ~WAL_ITEM_FLUSH_READY;
                // overwrite existing WAL item

                size_t seq_shard_num = item->seqnum % file->wal->num_shards;
                if (caller == WAL_INS_WRITER) {
                    spin_lock(&file->wal->seq_shards[seq_shard_num].lock);
                }
                avl_remove(&file->wal->seq_shards[seq_shard_num].map_byseq,
                           &item->avl_seq);
                if (caller == WAL_INS_WRITER) {
                    spin_unlock(&file->wal->seq_shards[seq_shard_num].lock);
                }

                item->seqnum = doc->seqnum;
                seq_shard_num = doc->seqnum % file->wal->num_shards;
                if (caller == WAL_INS_WRITER) {
                    spin_lock(&file->wal->seq_shards[seq_shard_num].lock);
                }
                avl_insert(&file->wal->seq_shards[seq_shard_num].map_byseq,
                           &item->avl_seq, _wal_cmp_byseq);
                if (caller == WAL_INS_WRITER) {
                    spin_unlock(&file->wal->seq_shards[seq_shard_num].lock);
                }

                // mark previous doc region as stale
                size_t doc_size_ondisk = doc->size_ondisk;
                uint32_t stale_len = item->doc_size;
                uint64_t stale_offset = item->offset;
                if (item->action == WAL_ACT_INSERT ||
                    item->action == WAL_ACT_LOGICAL_REMOVE) {
                    // insert or logical remove
                    filemgr_mark_stale(file, stale_offset, stale_len);
                }

                if (doc->deleted) {
                    if (offset != BLK_NOT_FOUND && !immediate_remove) {
                        // purge interval not met yet
                        item->action = WAL_ACT_LOGICAL_REMOVE;// insert deleted
                    } else { // drop the deleted doc right away
                        item->action = WAL_ACT_REMOVE; // immediate prune index

                        if (offset != BLK_NOT_FOUND) {
                            // immediately mark as stale if offset is given
                            // (which means that a deletion mark was appended into
                            //  the file before calling wal_insert()).
                            filemgr_mark_stale(file, offset, doc_size_ondisk);
                        }
                        offset = 0; // must process these first
                        doc_size_ondisk = 0;
                    }
                } else {
                    item->action = WAL_ACT_INSERT;
                }
                atomic_add_uint64_t(&file->wal->datasize,
                                    doc_size_ondisk - item->doc_size);
                item->doc_size = doc->size_ondisk;
                item->offset = offset;

                // move the item to the front of the list (header)
                list_remove(&header->items, &item->list_elem);
                list_push_front(&header->items, &item->list_elem);
                break;
            }
            le = list_next(le);
        }

        if (le == NULL) {
            // not exist
            // create new item
            item = (struct wal_item *)calloc(1, sizeof(struct wal_item));
            item->flag = 0x0;

            if (file->kv_header) { // multi KV instance mode
                item->flag |= WAL_ITEM_MULTI_KV_INS_MODE;
            }
            item->txn = txn;
            if (txn == &file->global_txn) {
                atomic_incr_uint32_t(&file->wal->num_flushable);
            }
            item->header = header;
            item->seqnum = doc->seqnum;

            if (doc->deleted) {
                if (offset != BLK_NOT_FOUND && !immediate_remove) {
                    // purge interval not met yet
                    item->action = WAL_ACT_LOGICAL_REMOVE;// insert deleted
                } else { // compactor purge deleted doc
                    item->action = WAL_ACT_REMOVE; // immediate prune index

                    if (offset != BLK_NOT_FOUND) {
                        // immediately mark as stale if offset is given
                        // (which means that a deletion mark was appended into
                        //  the file before calling wal_insert()).
                        filemgr_mark_stale(file, offset, doc->size_ondisk);
                    }
                    offset = 0; // must process these first
                }
            } else {
                item->action = WAL_ACT_INSERT;
            }
            item->offset = offset;
            item->doc_size = doc->size_ondisk;
            if (item->action != WAL_ACT_REMOVE) {
                atomic_add_uint64_t(&file->wal->datasize, doc->size_ondisk);
            }

            size_t seq_shard_num = doc->seqnum % file->wal->num_shards;
            if (caller == WAL_INS_WRITER) {
                spin_lock(&file->wal->seq_shards[seq_shard_num].lock);
            }
            avl_insert(&file->wal->seq_shards[seq_shard_num].map_byseq,
                      &item->avl_seq, _wal_cmp_byseq);
            if (caller == WAL_INS_WRITER) {
                spin_unlock(&file->wal->seq_shards[seq_shard_num].lock);
            }
            // insert into header's list
            list_push_front(&header->items, &item->list_elem);
            // also insert into transaction's list
            list_push_back(txn->items, &item->list_elem_txn);

            atomic_incr_uint32_t(&file->wal->size);
            atomic_add_uint64_t(&file->wal->mem_overhead, sizeof(struct wal_item));
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

        avl_insert(&file->wal->key_shards[shard_num].map_bykey,
                   &header->avl_key, _wal_cmp_bykey);

        item = (struct wal_item *)malloc(sizeof(struct wal_item));
        // entries inserted by compactor is already committed
        if (caller == WAL_INS_COMPACT_PHASE1) {
            item->flag = WAL_ITEM_COMMITTED | WAL_ITEM_BY_COMPACTOR;
        } else {
            item->flag = 0x0;
        }
        if (file->kv_header) { // multi KV instance mode
            item->flag |= WAL_ITEM_MULTI_KV_INS_MODE;
        }
        item->txn = txn;
        if (txn == &file->global_txn) {
            atomic_incr_uint32_t(&file->wal->num_flushable);
        }
        item->header = header;

        item->seqnum = doc->seqnum;

        if (doc->deleted) {
            if (offset != BLK_NOT_FOUND && !immediate_remove) {// purge interval not met yet
                item->action = WAL_ACT_LOGICAL_REMOVE;// insert deleted
            } else { // compactor purge deleted doc
                item->action = WAL_ACT_REMOVE; // immediate prune index

                if (offset != BLK_NOT_FOUND) {
                    // immediately mark as stale if offset is given
                    // (which means that an empty doc was appended before
                    //  calling wal_insert()).
                    filemgr_mark_stale(file, offset, doc->size_ondisk);
                }
                offset = 0; // must process these first
            }
        } else {
            item->action = WAL_ACT_INSERT;
        }
        item->offset = offset;
        item->doc_size = doc->size_ondisk;
        if (item->action != WAL_ACT_REMOVE) {
            atomic_add_uint64_t(&file->wal->datasize, doc->size_ondisk);
        }

        size_t seq_shard_num;
        seq_shard_num = doc->seqnum % file->wal->num_shards;
        if (caller == WAL_INS_WRITER) {
            spin_lock(&file->wal->seq_shards[seq_shard_num].lock);
        }
        avl_insert(&file->wal->seq_shards[seq_shard_num].map_byseq,
                   &item->avl_seq, _wal_cmp_byseq);
        if (caller == WAL_INS_WRITER) {
            spin_unlock(&file->wal->seq_shards[seq_shard_num].lock);
        }

        // insert into header's list
        list_push_front(&header->items, &item->list_elem);
        if (caller == WAL_INS_WRITER || caller == WAL_INS_COMPACT_PHASE2) {
            // also insert into transaction's list
            list_push_back(txn->items, &item->list_elem_txn);
        } else {
            // increase num_docs
            _kvs_stat_update_attr(file, kv_id, KVS_STAT_WAL_NDOCS, 1);
        }

        atomic_incr_uint32_t(&file->wal->size);
        atomic_add_uint64_t(&file->wal->mem_overhead,
            sizeof(struct wal_item) + sizeof(struct wal_item_header) + keylen);
    }

    if (caller == WAL_INS_WRITER) {
        spin_unlock(&file->wal->key_shards[shard_num].lock);
    }

    return FDB_RESULT_SUCCESS;
}

fdb_status wal_insert(fdb_txn *txn,
                      struct filemgr *file,
                      fdb_doc *doc,
                      uint64_t offset,
                      wal_insert_by caller)
{
    return _wal_insert(txn, file, doc, offset, caller, false);
}

fdb_status wal_immediate_remove(fdb_txn *txn,
                                struct filemgr *file,
                                fdb_doc *doc,
                                uint64_t offset,
                                wal_insert_by caller)
{
    return _wal_insert(txn, file, doc, offset, caller, true);
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
    struct avl_node *node = NULL;
    void *key = doc->key;
    size_t keylen = doc->keylen;

    if (doc->seqnum == SEQNUM_NOT_USED || (key && keylen>0)) {
        size_t chk_sum = get_checksum((uint8_t*)key, keylen);
        // _wal_find() doesn't care compactor's shard
        size_t shard_num = chk_sum % file->wal->num_shards;
        spin_lock(&file->wal->key_shards[shard_num].lock);
        // search by key
        query.key = key;
        query.keylen = keylen;
        node = avl_search(&file->wal->key_shards[shard_num].map_bykey,
                          &query.avl_key, _wal_cmp_bykey);
        if (node) {
            // retrieve header
            header = _get_entry(node, struct wal_item_header, avl_key);
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
                        if (item->action == WAL_ACT_REMOVE) {
                            // Immediately deleted & purged doc have no real
                            // presence on-disk. wal_find must return SUCCESS
                            // here to indicate that the doc was deleted to
                            // prevent main index lookup. Also, it must set the
                            // offset to BLK_NOT_FOUND to ensure that caller
                            // does NOT attempt to fetch the doc OR its
                            // metadata from file.
                            *offset = BLK_NOT_FOUND;
                        }
                    }
                    spin_unlock(&file->wal->key_shards[shard_num].lock);
                    return FDB_RESULT_SUCCESS;
                }
                le = list_next(le);
            }
        }
        spin_unlock(&file->wal->key_shards[shard_num].lock);
    } else {
        // search by seqnum
        struct wal_item_header temp_header;

        if (file->kv_header) { // multi KV instance mode
            temp_header.key = (void*)alca(uint8_t, file->config->chunksize);
            kvid2buf(file->config->chunksize, kv_id, temp_header.key);
            item_query.header = &temp_header;
        }
        item_query.seqnum = doc->seqnum;

        size_t shard_num = doc->seqnum % file->wal->num_shards;
        spin_lock(&file->wal->seq_shards[shard_num].lock);
        node = avl_search(&file->wal->seq_shards[shard_num].map_byseq,
                          &item_query.avl_seq, _wal_cmp_byseq);
        if (node) {
            item = _get_entry(node, struct wal_item, avl_seq);
            if ((item->flag & WAL_ITEM_COMMITTED) ||
                (item->txn == txn) ||
                (txn->isolation == FDB_ISOLATION_READ_UNCOMMITTED)) {
                *offset = item->offset;
                if (item->action == WAL_ACT_INSERT) {
                    doc->deleted = false;
                } else {
                    doc->deleted = true;
                    if (item->action == WAL_ACT_REMOVE) {
                        // Immediately deleted & purged doc have no real
                        // presence on-disk. wal_find must return SUCCESS
                        // here to indicate that the doc was deleted to
                        // prevent main index lookup. Also, it must set the
                        // offset to BLK_NOT_FOUND to ensure that caller
                        // does NOT attempt to fetch the doc OR its
                        // metadata from file.
                        *offset = BLK_NOT_FOUND;
                    }
                }
                spin_unlock(&file->wal->seq_shards[shard_num].lock);
                return FDB_RESULT_SUCCESS;
            }
        }
        spin_unlock(&file->wal->seq_shards[shard_num].lock);
    }

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
    struct avl_node *node;
    struct list_elem *e;
    size_t i = 0;
    size_t num_shards = old_file->wal->num_shards;
    uint64_t mem_overhead = 0;

    // Note that the caller (i.e., compactor) alreay owns the locks on
    // both old_file and new_file filemgr instances. Therefore, it is OK to
    // grab each partition lock individually and move all uncommitted items
    // to the new_file filemgr instance.

    for (; i < num_shards; ++i) {
        spin_lock(&old_file->wal->key_shards[i].lock);
        node = avl_first(&old_file->wal->key_shards[i].map_bykey);
        while(node) {
            header = _get_entry(node, struct wal_item_header, avl_key);
            e = list_end(&header->items);
            while(e) {
                item = _get_entry(e, struct wal_item, list_elem);
                if (!(item->flag & WAL_ITEM_COMMITTED)) {
                    // not committed yet
                    // move doc
                    offset = move_doc(dbhandle, new_dhandle, item, &doc);
                    // Note that all items belonging to global_txn should be
                    // flushed before calling this function
                    // (migrate transactional items only).
                    fdb_assert(item->txn != &old_file->global_txn,
                               (uint64_t)item->txn, 0);
                    // insert into new_file's WAL
                    wal_insert(item->txn, new_file, &doc, offset,
                               WAL_INS_WRITER);
                    // remove from seq map
                    size_t shard_num = item->seqnum % num_shards;
                    spin_lock(&old_file->wal->seq_shards[shard_num].lock);
                    avl_remove(&old_file->wal->seq_shards[shard_num].map_byseq,
                               &item->avl_seq);
                    spin_unlock(&old_file->wal->seq_shards[shard_num].lock);
                    // remove from header's list
                    e = list_remove_reverse(&header->items, e);
                    // remove from transaction's list
                    list_remove(item->txn->items, &item->list_elem_txn);
                    // decrease num_flushable of old_file if non-transactional update
                    if (item->txn == &old_file->global_txn) {
                        atomic_decr_uint32_t(&old_file->wal->num_flushable);
                    }
                    if (item->action != WAL_ACT_REMOVE) {
                        atomic_sub_uint64_t(&old_file->wal->datasize, item->doc_size);
                    }
                    // free item
                    free(item);
                    // free doc
                    free(doc.key);
                    free(doc.meta);
                    free(doc.body);
                    atomic_decr_uint32_t(&old_file->wal->size);
                    mem_overhead += sizeof(struct wal_item);
                } else {
                    e = list_prev(e);
                }
            }

            if (list_begin(&header->items) == NULL) {
                // header's list becomes empty
                // remove from key map
                node = avl_next(node);
                avl_remove(&old_file->wal->key_shards[i].map_bykey,
                           &header->avl_key);
                mem_overhead += header->keylen + sizeof(struct wal_item_header);
                // free key & header
                free(header->key);
                free(header);
            } else {
                node = avl_next(node);
            }
        }
        spin_unlock(&old_file->wal->key_shards[i].lock);
    }
    atomic_sub_uint64_t(&old_file->wal->mem_overhead, mem_overhead);

    spin_lock(&old_file->wal->lock);

    // migrate all entries in txn list
    e = list_begin(&old_file->wal->txn_list);
    while(e) {
        txn_wrapper = _get_entry(e, struct wal_txn_wrapper, le);
        txn = txn_wrapper->txn;
        // except for global_txn
        if (txn != &old_file->global_txn) {
            e = list_remove(&old_file->wal->txn_list, &txn_wrapper->le);
            list_push_front(&new_file->wal->txn_list, &txn_wrapper->le);
            // remove previous header info & revnum
            txn->prev_hdr_bid = BLK_NOT_FOUND;
            txn->prev_revnum = 0;
        } else {
            e = list_next(e);
        }
    }

    spin_unlock(&old_file->wal->lock);

    return FDB_RESULT_SUCCESS;
}

fdb_status wal_commit(fdb_txn *txn, struct filemgr *file,
                      wal_commit_mark_func *func, err_log_callback *log_callback)
{
    int prev_commit;
    wal_item_action prev_action;
    struct wal_item *item;
    struct wal_item *_item;
    struct list_elem *e1, *e2;
    fdb_kvs_id_t kv_id;
    fdb_status status;
    size_t shard_num;
    uint64_t mem_overhead = 0;

    e1 = list_begin(txn->items);
    while(e1) {
        item = _get_entry(e1, struct wal_item, list_elem_txn);
        assert(item->txn == txn);
        // Grab the WAL key shard lock.
        shard_num = get_checksum((uint8_t*)item->header->key,
                                 item->header->keylen) %
                                 file->wal->num_shards;
        spin_lock(&file->wal->key_shards[shard_num].lock);

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
                    fdb_log(log_callback, status,
                            "Error in appending a commit mark at offset %" _F64 " in "
                            "a database file '%s'", item->offset, file->filename);
                    spin_unlock(&file->wal->key_shards[shard_num].lock);
                    atomic_sub_uint64_t(&file->wal->mem_overhead, mem_overhead);
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
                    // remove from list & hash
                    list_remove(&item->header->items, &_item->list_elem);
                    size_t seq_shard_num = _item->seqnum % file->wal->num_shards;
                    spin_lock(&file->wal->seq_shards[seq_shard_num].lock);
                    avl_remove(&file->wal->seq_shards[seq_shard_num].map_byseq,
                               &_item->avl_seq);
                    spin_unlock(&file->wal->seq_shards[seq_shard_num].lock);

                    // mark previous doc region as stale
                    uint32_t stale_len = _item->doc_size;
                    uint64_t stale_offset = _item->offset;
                    if (_item->action == WAL_ACT_INSERT ||
                        _item->action == WAL_ACT_LOGICAL_REMOVE) {
                        // insert or logical remove
                        filemgr_mark_stale(file, stale_offset, stale_len);
                    }

                    prev_action = _item->action;
                    prev_commit = 1;
                    atomic_decr_uint32_t(&file->wal->size);
                    atomic_decr_uint32_t(&file->wal->num_flushable);
                    if (item->action != WAL_ACT_REMOVE) {
                        atomic_sub_uint64_t(&file->wal->datasize, _item->doc_size);
                    }
                    mem_overhead += sizeof(struct wal_item);
                    free(_item);
                }
            }
            if (!prev_commit) {
                // there was no previous commit .. increase num_docs
                _kvs_stat_update_attr(file, kv_id, KVS_STAT_WAL_NDOCS, 1);
                if (item->action == WAL_ACT_LOGICAL_REMOVE ||
                    item->action == WAL_ACT_REMOVE) {
                    _kvs_stat_update_attr(file, kv_id, KVS_STAT_WAL_NDELETES, 1);
                }
            } else {
                if (prev_action == WAL_ACT_INSERT &&
                    (item->action == WAL_ACT_LOGICAL_REMOVE ||
                     item->action == WAL_ACT_REMOVE)) {
                    _kvs_stat_update_attr(file, kv_id, KVS_STAT_WAL_NDELETES, 1);
                } else if ((prev_action == WAL_ACT_LOGICAL_REMOVE ||
                            prev_action == WAL_ACT_REMOVE) &&
                            item->action == WAL_ACT_INSERT) {
                    _kvs_stat_update_attr(file, kv_id, KVS_STAT_WAL_NDELETES, -1);
                }
            }
            // increase num_flushable if it is transactional update
            if (item->txn != &file->global_txn) {
                atomic_incr_uint32_t(&file->wal->num_flushable);
            }
            // move the committed item to the end of the wal_item_header's list
            list_remove(&item->header->items, &item->list_elem);
            list_push_back(&item->header->items, &item->list_elem);
        }

        // remove from transaction's list
        e1 = list_remove(txn->items, e1);
        spin_unlock(&file->wal->key_shards[shard_num].lock);
    }
    atomic_sub_uint64_t(&file->wal->mem_overhead, mem_overhead);

    return FDB_RESULT_SUCCESS;
}

static int _wal_flush_cmp(struct avl_node *a, struct avl_node *b, void *aux)
{
    struct wal_item *aa, *bb;
    aa = _get_entry(a, struct wal_item, avl_flush);
    bb = _get_entry(b, struct wal_item, avl_flush);

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

INLINE void _wal_release_item(struct filemgr *file, size_t shard_num,
                              struct wal_item *item) {
    fdb_kvs_id_t kv_id;
    size_t seq_shard_num;
    uint64_t mem_overhead = 0;

    // get KVS ID
    if (item->flag & WAL_ITEM_MULTI_KV_INS_MODE) {
        buf2kvid(item->header->chunksize, item->header->key, &kv_id);
    } else {
        kv_id = 0;
    }

    list_remove(&item->header->items, &item->list_elem);
    seq_shard_num = item->seqnum % file->wal->num_shards;
    spin_lock(&file->wal->seq_shards[seq_shard_num].lock);
    avl_remove(&file->wal->seq_shards[seq_shard_num].map_byseq,
                &item->avl_seq);
    spin_unlock(&file->wal->seq_shards[seq_shard_num].lock);
    if (list_begin(&item->header->items) == NULL) {
        // wal_item_header becomes empty
        // free header and remove from key map
        avl_remove(&file->wal->key_shards[shard_num].map_bykey,
                   &item->header->avl_key);
        mem_overhead = sizeof(wal_item_header) + item->header->keylen;
        free(item->header->key);
        free(item->header);
    }

    if (item->action == WAL_ACT_LOGICAL_REMOVE ||
        item->action == WAL_ACT_REMOVE) {
        _kvs_stat_update_attr(file, kv_id, KVS_STAT_WAL_NDELETES, -1);
    }
    _kvs_stat_update_attr(file, kv_id, KVS_STAT_WAL_NDOCS, -1);
    atomic_decr_uint32_t(&file->wal->size);
    atomic_decr_uint32_t(&file->wal->num_flushable);
    if (item->action != WAL_ACT_REMOVE) {
        atomic_sub_uint64_t(&file->wal->datasize, item->doc_size);
    }
    atomic_sub_uint64_t(&file->wal->mem_overhead,
                        mem_overhead + sizeof(struct wal_item));
    free(item);
}

#define WAL_SORTED_FLUSH ((void *)1) // stored in aux if avl tree is used

INLINE bool _wal_are_items_sorted(union wal_flush_items *flush_items)
{
    return (flush_items->tree.aux == WAL_SORTED_FLUSH);
}

fdb_status wal_release_flushed_items(struct filemgr *file,
                                     union wal_flush_items *flush_items)
{
    struct wal_item *item;
    size_t shard_num;

    if (_wal_are_items_sorted(flush_items)) {
        struct avl_tree *tree = &flush_items->tree;
        // scan and remove entries in the avl-tree
        while (1) {
            struct avl_node *a;
            if ((a = avl_first(tree)) == NULL) {
                break;
            }
            item = _get_entry(a, struct wal_item, avl_flush);
            avl_remove(tree, &item->avl_flush);

            // Grab the WAL key shard lock.
            shard_num = get_checksum((uint8_t*)item->header->key,
                                     item->header->keylen) % file->wal->num_shards;
            spin_lock(&file->wal->key_shards[shard_num].lock);

            _wal_release_item(file, shard_num, item);

            spin_unlock(&file->wal->key_shards[shard_num].lock);
        }
    } else {
        struct list *list_head = &flush_items->list;
        // scan and remove entries in the avl-tree
        while (1) {
            struct list_elem *a;
            if ((a = list_begin(list_head)) == NULL) {
                break;
            }
            item = _get_entry(a, struct wal_item, list_elem_flush);
            list_remove(list_head, &item->list_elem_flush);

            // Grab the WAL key shard lock.
            shard_num = get_checksum((uint8_t*)item->header->key,
                                     item->header->keylen) % file->wal->num_shards;
            spin_lock(&file->wal->key_shards[shard_num].lock);
            _wal_release_item(file, shard_num, item);
            spin_unlock(&file->wal->key_shards[shard_num].lock);
        }
    }

    return FDB_RESULT_SUCCESS;
}

INLINE fdb_status _wal_do_flush(struct wal_item *item,
                                wal_flush_func *flush_func,
                                void *dbhandle,
                                struct avl_tree *stale_seqnum_list,
                                struct avl_tree *kvs_delta_stats)
{
    // check weather this item is updated after insertion into tree
    if (item->flag & WAL_ITEM_FLUSH_READY) {
        fdb_status fs = flush_func(dbhandle, item, stale_seqnum_list, kvs_delta_stats);
        if (fs != FDB_RESULT_SUCCESS) {
            fdb_kvs_handle *handle = (fdb_kvs_handle *) dbhandle;
            fdb_log(&handle->log_callback, fs,
                    "Failed to flush WAL item (key '%s') into a database file '%s'",
                    (const char *) item->header->key, handle->file->filename);
            return fs;
        }
    }
    return FDB_RESULT_SUCCESS;
}

struct fdb_root_info {
    bid_t orig_id_root;
    bid_t orig_seq_root;
    bid_t orig_stale_root;
};

INLINE void _wal_backup_root_info(void *voidhandle,
                                  struct fdb_root_info *root_info)
{
    fdb_kvs_handle *handle = (fdb_kvs_handle*)voidhandle;

    root_info->orig_id_root = handle->trie->root_bid;
    if (handle->config.seqtree_opt == FDB_SEQTREE_USE) {
        if (handle->kvs) {
            root_info->orig_seq_root = handle->seqtrie->root_bid;
        } else {
            root_info->orig_seq_root = handle->seqtree->root_bid;
        }
    }
    if (handle->staletree) {
        root_info->orig_stale_root = handle->staletree->root_bid;
    }
}

INLINE void _wal_restore_root_info(void *voidhandle,
                                   struct fdb_root_info *root_info)
{
    fdb_kvs_handle *handle = (fdb_kvs_handle*)voidhandle;

    handle->trie->root_bid = root_info->orig_id_root;
    if (handle->config.seqtree_opt == FDB_SEQTREE_USE) {
        if (handle->kvs) {
            handle->seqtrie->root_bid = root_info->orig_seq_root;
        } else {
            handle->seqtree->root_bid = root_info->orig_seq_root;
        }
    }
    if (handle->staletree) {
        handle->staletree->root_bid = root_info->orig_stale_root;
    }
}

static fdb_status _wal_flush(struct filemgr *file,
                             void *dbhandle,
                             wal_flush_func *flush_func,
                             wal_get_old_offset_func *get_old_offset,
                             wal_flush_seq_purge_func *seq_purge_func,
                             wal_flush_kvs_delta_stats_func *delta_stats_func,
                             union wal_flush_items *flush_items,
                             bool by_compactor)
{
    struct avl_tree *tree = &flush_items->tree;
    struct list *list_head = &flush_items->list;
    struct list_elem *ee, *ee_prev;
    struct avl_node *a, *a_next;
    struct wal_item *item;
    struct wal_item_header *header;
    struct fdb_root_info root_info;
    size_t i = 0;
    size_t num_shards = file->wal->num_shards;
    bool do_sort = !filemgr_is_fully_resident(file);

    if (do_sort) {
        avl_init(tree, WAL_SORTED_FLUSH);
    } else {
        list_init(list_head);
    }

    memset(&root_info, 0xff, sizeof(root_info));
    _wal_backup_root_info(dbhandle, &root_info);

    for (; i < num_shards; ++i) {
        spin_lock(&file->wal->key_shards[i].lock);
        a = avl_first(&file->wal->key_shards[i].map_bykey);
        while (a) {
            a_next = avl_next(a);
            header = _get_entry(a, struct wal_item_header, avl_key);
            ee = list_end(&header->items);
            while (ee) {
                ee_prev = list_prev(ee);
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
                    if (by_compactor) {
                        // During the first phase of compaction, we don't need
                        // to retrieve the old offsets of WAL items because they
                        // are all new insertions into new file's hbtrie index.
                        item->old_offset = 0;
                        if (do_sort) {
                            avl_insert(tree, &item->avl_flush, _wal_flush_cmp);
                        } else {
                            list_push_back(list_head, &item->list_elem_flush);
                        }
                    } else {
                        spin_unlock(&file->wal->key_shards[i].lock);
                        item->old_offset = get_old_offset(dbhandle, item);
                        spin_lock(&file->wal->key_shards[i].lock);
                        if (item->old_offset == 0 && // doc not in main index
                            item->action == WAL_ACT_REMOVE) {// insert & delete
                            // drop and release this item right away from WAL
                            _wal_release_item(file, i, item);
                        } else if (do_sort) {
                            avl_insert(tree, &item->avl_flush, _wal_flush_cmp);
                        } else {
                            list_push_back(list_head, &item->list_elem_flush);
                        }
                    }
                }
                ee = ee_prev;
            }
            a = a_next;
        }
        spin_unlock(&file->wal->key_shards[i].lock);
    }

    filemgr_set_io_inprog(file); // MB-16622:prevent parallel writes by flusher
    fdb_status fs = FDB_RESULT_SUCCESS;
    struct avl_tree stale_seqnum_list;
    struct avl_tree kvs_delta_stats;
    avl_init(&stale_seqnum_list, NULL);
    avl_init(&kvs_delta_stats, NULL);

    // scan and flush entries in the avl-tree or list
    if (do_sort) {
        struct avl_node *a = avl_first(tree);
        while (a) {
            item = _get_entry(a, struct wal_item, avl_flush);
            a = avl_next(a);
            fs = _wal_do_flush(item, flush_func, dbhandle,
                               &stale_seqnum_list, &kvs_delta_stats);
            if (fs != FDB_RESULT_SUCCESS) {
                _wal_restore_root_info(dbhandle, &root_info);
                break;
            }
        }
    } else {
        struct list_elem *a = list_begin(list_head);
        while (a) {
            item = _get_entry(a, struct wal_item, list_elem_flush);
            a = list_next(a);
            fs = _wal_do_flush(item, flush_func, dbhandle,
                               &stale_seqnum_list, &kvs_delta_stats);
            if (fs != FDB_RESULT_SUCCESS) {
                _wal_restore_root_info(dbhandle, &root_info);
                break;
            }
        }
    }

    // Remove all stale seq entries from the seq tree
    seq_purge_func(dbhandle, &stale_seqnum_list, &kvs_delta_stats);
    // Update each KV store stats after WAL flush
    delta_stats_func(file, &kvs_delta_stats);

    filemgr_clear_io_inprog(file);
    return fs;
}

fdb_status wal_flush(struct filemgr *file,
                     void *dbhandle,
                     wal_flush_func *flush_func,
                     wal_get_old_offset_func *get_old_offset,
                     wal_flush_seq_purge_func *seq_purge_func,
                     wal_flush_kvs_delta_stats_func *delta_stats_func,
                     union wal_flush_items *flush_items)
{
    return _wal_flush(file, dbhandle, flush_func, get_old_offset,
                      seq_purge_func, delta_stats_func,
                      flush_items, false);
}

fdb_status wal_flush_by_compactor(struct filemgr *file,
                                  void *dbhandle,
                                  wal_flush_func *flush_func,
                                  wal_get_old_offset_func *get_old_offset,
                                  wal_flush_seq_purge_func *seq_purge_func,
                                  wal_flush_kvs_delta_stats_func *delta_stats_func,
                                  union wal_flush_items *flush_items)
{
    return _wal_flush(file, dbhandle, flush_func, get_old_offset,
                      seq_purge_func, delta_stats_func,
                      flush_items, true);
}

INLINE bool item_partially_committed(struct filemgr *file,
                                     struct list *active_txn_list,
                                     fdb_txn *current_txn,
                                     struct wal_item *item)
{
    bool partial_commit = false;

    if (item->flag & WAL_ITEM_COMMITTED &&
        item->txn != &file->global_txn && item->txn != current_txn) {
        struct wal_txn_wrapper *txn_wrapper;
        struct list_elem *txn_elem = list_begin(active_txn_list);
        while(txn_elem) {
            txn_wrapper = _get_entry(txn_elem, struct wal_txn_wrapper, le);
            if (txn_wrapper->txn == item->txn) {
                partial_commit = true;
                break;
            }
            txn_elem = list_next(txn_elem);
        }
    }
    return partial_commit;
}

// Used to copy all the WAL items for non-durable snapshots
fdb_status wal_snapshot(struct filemgr *file,
                        void *dbhandle, fdb_txn *txn,
                        fdb_seqnum_t *upto_seq,
                        wal_snapshot_func *snapshot_func)
{
    struct list_elem *ee;
    struct avl_node *a;
    struct wal_item *item;
    struct wal_item_header *header;
    fdb_seqnum_t copy_upto = *upto_seq;
    fdb_seqnum_t copied_seq = 0;
    fdb_doc doc;
    size_t i = 0;
    size_t num_shards = file->wal->num_shards;

    // Get the list of active transactions now
    fdb_txn *active_txn;
    struct wal_txn_wrapper *txn_wrapper;
    struct list active_txn_list;
    list_init(&active_txn_list);
    spin_lock(&file->wal->lock);
    ee = list_begin(&file->wal->txn_list);
    while(ee) {
        txn_wrapper = _get_entry(ee, struct wal_txn_wrapper, le);
        active_txn = txn_wrapper->txn;
        // except for global_txn
        if (active_txn != &file->global_txn) {
            txn_wrapper = (struct wal_txn_wrapper *)
                calloc(1, sizeof(struct wal_txn_wrapper));
            txn_wrapper->txn = active_txn;
            list_push_front(&active_txn_list, &txn_wrapper->le);
        }
        ee = list_next(ee);
    }
    spin_unlock(&file->wal->lock);

    for (; i < num_shards; ++i) {
        spin_lock(&file->wal->key_shards[i].lock);
        a = avl_first(&file->wal->key_shards[i].map_bykey);
        while (a) {
            header = _get_entry(a, struct wal_item_header, avl_key);
            ee = list_begin(&header->items);
            while (ee) {
                item = _get_entry(ee, struct wal_item, list_elem);
                if (item->flag & WAL_ITEM_BY_COMPACTOR) { // Always skip
                    ee = list_next(ee); // items moved by compactor to prevent
                    continue; // duplication of items in WAL & Main-index
                }
                if (copy_upto != FDB_SNAPSHOT_INMEM) {
                    // Take stable snapshot in new_file: Skip all items that are
                    // higher than requested seqnum or uncommitted.
                    if (copy_upto < item->seqnum ||
                        !(item->flag & WAL_ITEM_COMMITTED)) {
                        ee = list_next(ee);
                        continue;
                    }
                } else { // An in-memory snapshot in current file..
                    // Skip any uncommitted item, if not part of either global or
                    // the current transaction
                    if (!(item->flag & WAL_ITEM_COMMITTED) &&
                        item->txn != &file->global_txn &&
                        item->txn != txn) {
                        ee = list_next(ee);
                        continue;
                    }
                }
                // Skip the partially committed items too.
                if (item_partially_committed(file, &active_txn_list, txn, item)) {
                    ee = list_next(ee);
                    continue;
                }

                doc.keylen = item->header->keylen;
                doc.key = malloc(doc.keylen); // (freed in fdb_snapshot_close)
                memcpy(doc.key, item->header->key, doc.keylen);
                doc.seqnum = item->seqnum;
                doc.deleted = (item->action == WAL_ACT_LOGICAL_REMOVE ||
                               item->action == WAL_ACT_REMOVE);
                snapshot_func(dbhandle, &doc, item->offset);
                if (doc.seqnum > copied_seq) {
                    copied_seq = doc.seqnum;
                }
                break; // We just require a single latest copy in the snapshot
            }
            a = avl_next(a);
        }
        spin_unlock(&file->wal->key_shards[i].lock);
    }

    ee = list_begin(&active_txn_list);
    while (ee) {
        txn_wrapper = _get_entry(ee, struct wal_txn_wrapper, le);
        ee = list_remove(&active_txn_list, &txn_wrapper->le);
        free(txn_wrapper);
    }

    *upto_seq = copied_seq; // Return to caller the highest copied seqnum
    return FDB_RESULT_SUCCESS;
}

// discard entries in txn
fdb_status wal_discard(struct filemgr *file, fdb_txn *txn)
{
    struct wal_item *item;
    struct list_elem *e;
    size_t shard_num, seq_shard_num;
    uint64_t mem_overhead = 0;

    e = list_begin(txn->items);
    while(e) {
        item = _get_entry(e, struct wal_item, list_elem_txn);
        shard_num = get_checksum((uint8_t*)item->header->key,
                                 item->header->keylen) %
                                 file->wal->num_shards;
        spin_lock(&file->wal->key_shards[shard_num].lock);

        // remove from seq map
        seq_shard_num = item->seqnum % file->wal->num_shards;
        spin_lock(&file->wal->seq_shards[seq_shard_num].lock);
        avl_remove(&file->wal->seq_shards[seq_shard_num].map_byseq,
                   &item->avl_seq);
        spin_unlock(&file->wal->seq_shards[seq_shard_num].lock);

        // remove from header's list
        list_remove(&item->header->items, &item->list_elem);
        // remove header if empty
        if (list_begin(&item->header->items) == NULL) {
            //remove from key map
            avl_remove(&file->wal->key_shards[shard_num].map_bykey,
                       &item->header->avl_key);
            mem_overhead += sizeof(struct wal_item_header) + item->header->keylen;
            // free key and header
            free(item->header->key);
            free(item->header);
        }
        // remove from txn's list
        e = list_remove(txn->items, e);
        if (item->txn == &file->global_txn ||
            item->flag & WAL_ITEM_COMMITTED) {
            atomic_decr_uint32_t(&file->wal->num_flushable);
        }
        if (item->action != WAL_ACT_REMOVE) {
            atomic_sub_uint64_t(&file->wal->datasize, item->doc_size);
            // mark as stale if the item is not an immediate remove
            filemgr_mark_stale(file, item->offset, item->doc_size);
        }

        // free
        free(item);
        atomic_decr_uint32_t(&file->wal->size);
        mem_overhead += sizeof(struct wal_item);
        spin_unlock(&file->wal->key_shards[shard_num].lock);
    }
    atomic_sub_uint64_t(&file->wal->mem_overhead, mem_overhead);

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
    struct list_elem *e;
    struct avl_node *a;
    fdb_kvs_id_t kv_id, kv_id_req;
    bool committed;
    wal_item_action committed_item_action;
    size_t i = 0, seq_shard_num;
    size_t num_shards = wal_get_num_shards(file);
    uint64_t mem_overhead = 0;

    if (type == WAL_DISCARD_KV_INS) { // multi KV ins mode
        if (aux == NULL) { // aux must contain pointer to KV ID
            return FDB_RESULT_INVALID_ARGS;
        }
        kv_id_req = *(fdb_kvs_id_t*)aux;
    }

    for (; i < num_shards; ++i) {
        spin_lock(&file->wal->key_shards[i].lock);
        a = avl_first(&file->wal->key_shards[i].map_bykey);
        while (a) {
            header = _get_entry(a, struct wal_item_header, avl_key);
            if (type == WAL_DISCARD_KV_INS) { // multi KV ins mode
                buf2kvid(header->chunksize, header->key, &kv_id);
                // begin while loop only on matching KV ID
                e = (kv_id == kv_id_req)?(list_begin(&header->items)):(NULL);
            } else {
                kv_id = 0;
                e = list_begin(&header->items);
            }

            committed = false;
            while (e) {
                item = _get_entry(e, struct wal_item, list_elem);
                if ( type == WAL_DISCARD_ALL ||
                     (type == WAL_DISCARD_UNCOMMITTED_ONLY &&
                      !(item->flag & WAL_ITEM_COMMITTED)) ||
                     type == WAL_DISCARD_KV_INS) {
                    // remove from header's list
                    e = list_remove(&header->items, e);
                    if (!(item->flag & WAL_ITEM_COMMITTED)) {
                        // and also remove from transaction's list
                        list_remove(item->txn->items, &item->list_elem_txn);
                        if (item->action != WAL_ACT_REMOVE) {
                            // mark as stale if item is not committed and not an immediate remove
                            filemgr_mark_stale(file, item->offset, item->doc_size);
                        }
                    } else {
                        // committed item exists and will be removed
                        committed = true;
                        committed_item_action = item->action;
                    }
                    // remove from seq hash table
                    seq_shard_num = item->seqnum % num_shards;
                    spin_lock(&file->wal->seq_shards[seq_shard_num].lock);
                    avl_remove(&file->wal->seq_shards[seq_shard_num].map_byseq,
                               &item->avl_seq);
                    spin_unlock(&file->wal->seq_shards[seq_shard_num].lock);

                    if (item->action != WAL_ACT_REMOVE) {
                        atomic_sub_uint64_t(&file->wal->datasize, item->doc_size);
                    }
                    if (item->txn == &file->global_txn) {
                        atomic_decr_uint32_t(&file->wal->num_flushable);
                    }
                    free(item);
                    atomic_decr_uint32_t(&file->wal->size);
                    mem_overhead += sizeof(struct wal_item);
                } else {
                    e = list_next(e);
                }
            }
            a = avl_next(a);

            if (list_begin(&header->items) == NULL) {
                // wal_item_header becomes empty
                // free header and remove from key map
                avl_remove(&file->wal->key_shards[i].map_bykey,
                           &header->avl_key);
                mem_overhead += sizeof(struct wal_item_header) + header->keylen;
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
        spin_unlock(&file->wal->key_shards[i].lock);
    }
    atomic_sub_uint64_t(&file->wal->mem_overhead, mem_overhead);

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
    atomic_store_uint32_t(&file->wal->size, 0);
    atomic_store_uint32_t(&file->wal->num_flushable, 0);
    atomic_store_uint64_t(&file->wal->datasize, 0);
    atomic_store_uint64_t(&file->wal->mem_overhead, 0);
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
    return atomic_get_uint32_t(&file->wal->size);
}

size_t wal_get_num_shards(struct filemgr *file)
{
    return file->wal->num_shards;
}

size_t wal_get_num_flushable(struct filemgr *file)
{
    return atomic_get_uint32_t(&file->wal->num_flushable);
}

size_t wal_get_num_docs(struct filemgr *file) {
    return _kvs_stat_get_sum(file, KVS_STAT_WAL_NDOCS);
}

size_t wal_get_num_deletes(struct filemgr *file) {
    return _kvs_stat_get_sum(file, KVS_STAT_WAL_NDELETES);
}

size_t wal_get_datasize(struct filemgr *file)
{
    return atomic_get_uint64_t(&file->wal->datasize);
}

size_t wal_get_mem_overhead(struct filemgr *file)
{
    return atomic_get_uint64_t(&file->wal->mem_overhead);
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
    uint64_t min_revnum = 0;

    spin_lock(&file->wal->lock);

    le = list_begin(&file->wal->txn_list);
    while(le) {
        txn_wrapper = _get_entry(le, struct wal_txn_wrapper, le);
        txn = txn_wrapper->txn;

        if (txn != cur_txn && list_begin(txn->items)) {
            if (min_revnum == 0 || txn->prev_revnum < min_revnum) {
                min_revnum = txn->prev_revnum;
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
