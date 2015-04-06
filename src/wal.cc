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

INLINE uint32_t _wal_hash_bykey(struct hash *hash, struct hash_elem *e)
{
    struct wal_item_header *item = _get_entry(e, struct wal_item_header, he_key);
    return chksum((uint8_t*)item->key, item->keylen) % ((uint64_t)hash->nbuckets);
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
    return (item->seqnum) % ((uint64_t)hash->nbuckets);
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
    int i, num_hash_buckets;
    size_t num_all_shards;

    file->wal->flag = WAL_FLAG_INITIALIZED;
    atomic_init_uint32_t(&file->wal->size, 0);
    atomic_init_uint32_t(&file->wal->num_flushable, 0);
    atomic_init_uint64_t(&file->wal->datasize, 0);
    file->wal->wal_dirty = FDB_WAL_CLEAN;

    list_init(&file->wal->txn_list);
    spin_init(&file->wal->lock);

    if (file->config->num_wal_shards) {
        file->wal->num_shards = file->config->num_wal_shards;
    } else {
        file->wal->num_shards = DEFAULT_NUM_WAL_PARTITIONS;
    }

    // Create one more WAL shard (num_shards+1)
    // The additional shard is reserved for compactor
    num_all_shards = wal_get_num_all_shards(file);
    file->wal->key_shards = (wal_shard_by_key *)
        malloc(sizeof(struct wal_shard_by_key) * num_all_shards);
    file->wal->seq_shards = (wal_shard_by_seq *)
        malloc(sizeof(struct wal_shard_by_seq) * num_all_shards);

    num_hash_buckets = nbucket / file->wal->num_shards;
    for (i = 0; i < num_all_shards; ++i) {
        if (i == file->wal->num_shards - 1) {
            num_hash_buckets = nbucket - (num_hash_buckets * i);
        } else if (i == file->wal->num_shards) {
            // WAL shard for compactor .. use more buckets
            num_hash_buckets = nbucket;
        }
        hash_init(&file->wal->key_shards[i].hash_bykey, num_hash_buckets,
                  _wal_hash_bykey, _wal_cmp_bykey);
        hash_init(&file->wal->seq_shards[i].hash_byseq, num_hash_buckets,
                  _wal_hash_byseq, _wal_cmp_byseq);
        list_init(&file->wal->key_shards[i].list);
        spin_init(&file->wal->key_shards[i].lock);
        spin_init(&file->wal->seq_shards[i].lock);
    }

    file->wal->key_seg.cur_addr = NULL;
    file->wal->key_seg.offset = 0;
    file->wal->key_seg.cur_maxsize = FDB_WAL_MIN_MMAP_FILESIZE;

    DBG("wal item size %d\n", (int)sizeof(struct wal_item));
    return FDB_RESULT_SUCCESS;
}

int wal_is_initialized(struct filemgr *file)
{
    return file->wal->flag & WAL_FLAG_INITIALIZED;
}

void *_wal_alloc_mmap(struct filemgr *file, size_t size)
{
    void *addr;

    if (!file->wal->key_seg.cur_addr ||
        file->wal->key_seg.offset + size >= file->wal->key_seg.cur_maxsize) {
        if (file->wal->key_seg.cur_addr) {
            // double the mmap file size for next allocation
            file->wal->key_seg.cur_maxsize *= 2;
            if (file->wal->key_seg.cur_maxsize > FDB_WAL_MAX_MMAP_FILESIZE) {
                file->wal->key_seg.cur_maxsize = FDB_WAL_MAX_MMAP_FILESIZE;
            }
        }
        file->wal->key_seg.cur_addr =
            filemgr_add_keystr_file(file, file->wal->key_seg.cur_maxsize);
        file->wal->key_seg.offset = 0;
    }
    addr = (uint8_t*)file->wal->key_seg.cur_addr + file->wal->key_seg.offset;
    file->wal->key_seg.offset += size;

    return addr;
}

void wal_release_keystr_files(struct filemgr *file)
{
    // Note that this function is protected by filemgr_mutex
    size_t i = 0;
    size_t num_shards = file->wal->num_shards;
    void *old_ptr;
    struct list_elem *e;
    struct wal_item_header *header;

    // convert all mmapped memory regions to malloc regions
    for (; i < num_shards; ++i) {
        spin_lock(&file->wal->key_shards[i].lock);
        e = list_begin(&file->wal->key_shards[i].list);
        while (e) {
            header = _get_entry(e, struct wal_item_header, list_elem);
            if (header->mmap) {
                old_ptr = header->key;
                header->key = (void *)malloc(header->keylen);
                memcpy(header->key, old_ptr, header->keylen);
                header->mmap = 0;
            }
            e = list_next(e);
        }
        spin_unlock(&file->wal->key_shards[i].lock);
    }

    if (file->wal->key_seg.cur_addr) {
        filemgr_remove_keystr_files(file);
        file->wal->key_seg.cur_addr = NULL;
        file->wal->key_seg.offset = 0;
        file->wal->key_seg.cur_maxsize = FDB_WAL_MIN_MMAP_FILESIZE;
    }
}

fdb_status wal_insert(fdb_txn *txn,
                      struct filemgr *file,
                      fdb_doc *doc,
                      uint64_t offset,
                      int is_compactor,
                      int mmap_alloc)
{
    struct wal_item *item;
    struct wal_item_header query, *header;
    struct list_elem *le;
    struct hash_elem *he;
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

    // During the compaction, WAL entry inserted by compactor is always stored
    // in the special shard (shard_num), while WAL entry inserted by normal
    // writer is stored in the corresponding normal shards (0 ~ shard_num-1).
    // Note that wal_find() always searches the normal shards only, thus
    // documents inserted by compactor but not exist in the normal shards
    // cannot be retrieved by wal_find(). However, fdb_get() continues to
    // search in the HB+trie in the old file if wal_find() fails, thus they
    // can be retrieved eventually.
    chk_sum = chksum((uint8_t*)key, keylen);
    if (is_compactor) {
        // Document inserted by compactor is always stored in
        // the compactor's shard (i.e., shards[shard_num])
        shard_num = file->wal->num_shards;
    } else {
        // Insertion by normal writer
        shard_num = chk_sum % file->wal->num_shards;
    }
    spin_lock(&file->wal->key_shards[shard_num].lock);

    he = hash_find_by_hash_val(&file->wal->key_shards[shard_num].hash_bykey,
                               &query.he_key, (uint32_t) chk_sum);

    if (he) {
        // already exist .. retrieve header
        header = _get_entry(he, struct wal_item_header, he_key);

        // it cannot happen that
        // same doc already exists in the compactor's shard
        assert(!is_compactor);

        // find uncommitted item belonging to the same txn
        le = list_begin(&header->items);
        while (le) {
            item = _get_entry(le, struct wal_item, list_elem);

            if (item->txn == txn && !(item->flag & WAL_ITEM_COMMITTED)) {
                item->flag &= ~WAL_ITEM_FLUSH_READY;

                size_t seq_shard_num = item->seqnum % file->wal->num_shards;
                spin_lock(&file->wal->seq_shards[seq_shard_num].lock);
                hash_remove(&file->wal->seq_shards[seq_shard_num].hash_byseq,
                            &item->he_seq);
                spin_unlock(&file->wal->seq_shards[seq_shard_num].lock);
                item->seqnum = doc->seqnum;
                seq_shard_num = doc->seqnum % file->wal->num_shards;
                spin_lock(&file->wal->seq_shards[seq_shard_num].lock);
                hash_insert(&file->wal->seq_shards[seq_shard_num].hash_byseq,
                            &item->he_seq);
                spin_unlock(&file->wal->seq_shards[seq_shard_num].lock);

                atomic_add_uint64_t(&file->wal->datasize, doc->size_ondisk - item->doc_size);

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

        if (le == NULL) {
            // not exist
            // create new item
            item = (struct wal_item *)malloc(sizeof(struct wal_item));
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
            item->action = doc->deleted ? WAL_ACT_LOGICAL_REMOVE : WAL_ACT_INSERT;
            item->offset = offset;
            item->doc_size = doc->size_ondisk;
            atomic_add_uint64_t(&file->wal->datasize, doc->size_ondisk);

            // don't care about compactor's shard here
            size_t seq_shard_num = doc->seqnum % file->wal->num_shards;
            spin_lock(&file->wal->seq_shards[seq_shard_num].lock);
            hash_insert(&file->wal->seq_shards[seq_shard_num].hash_byseq, &item->he_seq);
            spin_unlock(&file->wal->seq_shards[seq_shard_num].lock);

            // insert into header's list
            list_push_front(&header->items, &item->list_elem);
            // also insert into transaction's list
            list_push_back(txn->items, &item->list_elem_txn);

            atomic_incr_uint32_t(&file->wal->size);
        }
    } else {
        // not exist .. create new one
        // create new header and new item
        header = (struct wal_item_header*)malloc(sizeof(struct wal_item_header));
        list_init(&header->items);
        header->chunksize = file->config->chunksize;
        header->keylen = keylen;
        if (mmap_alloc) {
            // alloc from mmap file
            header->key = (void *)_wal_alloc_mmap(file, header->keylen);
            header->mmap = 1;
        } else {
            header->key = (void *)malloc(header->keylen);
            header->mmap = 0;
        }
        memcpy(header->key, key, header->keylen);

        hash_insert_by_hash_val(&file->wal->key_shards[shard_num].hash_bykey,
                                &header->he_key, (uint32_t) chk_sum);

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
            atomic_incr_uint32_t(&file->wal->num_flushable);
        }
        item->header = header;

        item->seqnum = doc->seqnum;
        item->action = doc->deleted ? WAL_ACT_LOGICAL_REMOVE : WAL_ACT_INSERT;
        item->offset = offset;
        item->doc_size = doc->size_ondisk;
        atomic_add_uint64_t(&file->wal->datasize, doc->size_ondisk);

        size_t seq_shard_num;
        if (is_compactor) {
            // Document inserted by compactor is always stored in
            // the compactor's shard
            seq_shard_num = file->wal->num_shards;
        } else {
            seq_shard_num = doc->seqnum % file->wal->num_shards;
        }
        spin_lock(&file->wal->seq_shards[seq_shard_num].lock);
        hash_insert(&file->wal->seq_shards[seq_shard_num].hash_byseq, &item->he_seq);
        spin_unlock(&file->wal->seq_shards[seq_shard_num].lock);

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

        // insert an item header into a WAL shard's list
        list_push_back(&file->wal->key_shards[shard_num].list, &header->list_elem);
        atomic_incr_uint32_t(&file->wal->size);
    }

    spin_unlock(&file->wal->key_shards[shard_num].lock);

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

    if (doc->seqnum == SEQNUM_NOT_USED || (key && keylen>0)) {
        size_t chk_sum = chksum((uint8_t*)key, keylen);
        // _wal_find() doesn't care compactor's shard
        size_t shard_num = chk_sum % file->wal->num_shards;
        spin_lock(&file->wal->key_shards[shard_num].lock);
        // search by key
        query.key = key;
        query.keylen = keylen;
        he = hash_find_by_hash_val(&file->wal->key_shards[shard_num].hash_bykey,
                                   &query.he_key, (uint32_t) chk_sum);
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
        he = hash_find(&file->wal->seq_shards[shard_num].hash_byseq, &item_query.he_seq);
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
    struct list_elem *e1, *e2;
    size_t i = 0;
    size_t num_shards = old_file->wal->num_shards;

    // Note that the caller (i.e., compactor) alreay owns the locks on
    // both old_file and new_file filemgr instances. Therefore, it is OK to
    // grab each partition lock individually and move all uncommitted items
    // to the new_file filemgr instance.

    for (; i < num_shards; ++i) {
        spin_lock(&old_file->wal->key_shards[i].lock);
        e1 = list_begin(&old_file->wal->key_shards[i].list);
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
                    wal_insert(item->txn, new_file, &doc, offset, 0, 1);
                    // remove from seq hash table
                    size_t shard_num = item->seqnum % num_shards;
                    spin_lock(&old_file->wal->seq_shards[shard_num].lock);
                    hash_remove(&old_file->wal->seq_shards[shard_num].hash_byseq,
                                &item->he_seq);
                    spin_unlock(&old_file->wal->seq_shards[shard_num].lock);
                    // remove from header's list
                    e2 = list_remove_reverse(&header->items, e2);
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
                } else {
                    e2= list_prev(e2);
                }
            }

            if (list_begin(&header->items) == NULL) {
                // header's list becomes empty
                // remove from key hash table
                hash_remove(&old_file->wal->key_shards[i].hash_bykey, &header->he_key);
                // remove from wal list
                e1 = list_remove(&old_file->wal->key_shards[i].list, &header->list_elem);
                // free key & header
                if (!header->mmap) {
                    free(header->key);
                }
                free(header);
            } else {
                e1 = list_next(e1);
            }
        }
        spin_unlock(&old_file->wal->key_shards[i].lock);
    }

    spin_lock(&old_file->wal->lock);

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
    size_t shard_num;

    e1 = list_begin(txn->items);
    while(e1) {
        item = _get_entry(e1, struct wal_item, list_elem_txn);
        assert(item->txn == txn);
        // Grab the WAL key shard lock.
        shard_num = chksum((uint8_t*)item->header->key, item->header->keylen) %
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
                    spin_unlock(&file->wal->key_shards[shard_num].lock);
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
                    size_t seq_shard_num = _item->seqnum % file->wal->num_shards;
                    spin_lock(&file->wal->seq_shards[seq_shard_num].lock);
                    hash_remove(&file->wal->seq_shards[seq_shard_num].hash_byseq,
                                &_item->he_seq);
                    spin_unlock(&file->wal->seq_shards[seq_shard_num].lock);
                    prev_action = _item->action;
                    prev_commit = 1;
                    atomic_decr_uint32_t(&file->wal->size);
                    atomic_decr_uint32_t(&file->wal->num_flushable);
                    if (item->action != WAL_ACT_REMOVE) {
                        atomic_sub_uint64_t(&file->wal->datasize, _item->doc_size);
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
    size_t shard_num, seq_shard_num;

    // scan and remove entries in the avl-tree
    while (1) {
        if ((a = avl_first(tree)) == NULL) {
            break;
        }
        item = _get_entry(a, struct wal_item, avl);
        avl_remove(tree, &item->avl);

        // Grab the WAL key shard lock.
        if (item->flag & WAL_ITEM_BY_COMPACTOR) {
            shard_num = file->wal->num_shards;
        } else {
            shard_num = chksum((uint8_t*)item->header->key, item->header->keylen) %
                file->wal->num_shards;
        }
        spin_lock(&file->wal->key_shards[shard_num].lock);

        // get KVS ID
        if (item->flag & WAL_ITEM_MULTI_KV_INS_MODE) {
            buf2kvid(item->header->chunksize, item->header->key, &kv_id);
        } else {
            kv_id = 0;
        }

        list_remove(&item->header->items, &item->list_elem);
        if (item->flag & WAL_ITEM_BY_COMPACTOR) {
            seq_shard_num = file->wal->num_shards;
        } else {
            seq_shard_num = item->seqnum % file->wal->num_shards;
        }
        spin_lock(&file->wal->seq_shards[seq_shard_num].lock);
        hash_remove(&file->wal->seq_shards[seq_shard_num].hash_byseq,
                    &item->he_seq);
        spin_unlock(&file->wal->seq_shards[seq_shard_num].lock);
        if (list_begin(&item->header->items) == NULL) {
            // wal_item_header becomes empty
            // free header and remove from hash table & wal list
            list_remove(&file->wal->key_shards[shard_num].list, &item->header->list_elem);
            hash_remove(&file->wal->key_shards[shard_num].hash_bykey, &item->header->he_key);
            if (!item->header->mmap) {
                free(item->header->key);
            }
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
        free(item);
        spin_unlock(&file->wal->key_shards[shard_num].lock);
    }

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
    size_t i = 0;
    size_t num_shards = file->wal->num_shards;

    if (by_compactor) {
        // If this flushing is requested by compactor,
        // flush WAL entries by compactor only.
        i = file->wal->num_shards;
        num_shards = i+1;
    }

    // sort by old byte-offset of the document (for sequential access)
    avl_init(tree, NULL);
    for (; i < num_shards; ++i) {
        spin_lock(&file->wal->key_shards[i].lock);
        e = list_begin(&file->wal->key_shards[i].list);
        while (e) {
            header = _get_entry(e, struct wal_item_header, list_elem);
            ee = list_end(&header->items);
            while (ee) {
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
                    spin_unlock(&file->wal->key_shards[i].lock);
                    item->old_offset = get_old_offset(dbhandle, item);
                    avl_insert(tree, &item->avl, _wal_flush_cmp);
                    spin_lock(&file->wal->key_shards[i].lock);
                }
                ee = list_prev(ee);
            }
            e = list_next(e);
        }
        spin_unlock(&file->wal->key_shards[i].lock);
    }

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
                        fdb_seqnum_t *upto_seq,
                        wal_snapshot_func *snapshot_func)
{
    struct list_elem *e, *ee;
    struct wal_item *item;
    struct wal_item_header *header;
    fdb_seqnum_t copy_upto = *upto_seq;
    fdb_seqnum_t copied_seq = 0;
    fdb_doc doc;
    size_t i = 0;
    size_t num_shards = file->wal->num_shards;

    for (; i < num_shards; ++i) {
        spin_lock(&file->wal->key_shards[i].lock);
        e = list_begin(&file->wal->key_shards[i].list);
        while (e) {
            header = _get_entry(e, struct wal_item_header, list_elem);
            ee = list_begin(&header->items);
            while (ee) {
                item = _get_entry(ee, struct wal_item, list_elem);
                if (item->flag & WAL_ITEM_BY_COMPACTOR) { // Always skip
                    ee = list_next(ee); // items moved by compactor to prevent
                    continue; // duplication of items in WAL & Main-index
                }
                if (copy_upto != FDB_SNAPSHOT_INMEM) {
                    // Take stable snapshot in new_file: Skip all items that are...
                    if (copy_upto < item->seqnum || // higher than requested seqnum
                        !(item->flag & WAL_ITEM_COMMITTED)) { // or uncommitted
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
            e = list_next(e);
        }
        spin_unlock(&file->wal->key_shards[i].lock);
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

    e = list_begin(txn->items);
    while(e) {
        item = _get_entry(e, struct wal_item, list_elem_txn);
        shard_num = chksum((uint8_t*)item->header->key, item->header->keylen) %
            file->wal->num_shards;
        spin_lock(&file->wal->key_shards[shard_num].lock);

        // remove from seq hash table
        seq_shard_num = item->seqnum % file->wal->num_shards;
        spin_lock(&file->wal->seq_shards[seq_shard_num].lock);
        hash_remove(&file->wal->seq_shards[seq_shard_num].hash_byseq,
                    &item->he_seq);
        spin_unlock(&file->wal->seq_shards[seq_shard_num].lock);

        // remove from header's list
        list_remove(&item->header->items, &item->list_elem);
        // remove header if empty
        if (list_begin(&item->header->items) == NULL) {
            //remove from key hash table
            hash_remove(&file->wal->key_shards[shard_num].hash_bykey,
                        &item->header->he_key);
            // remove from wal list
            list_remove(&file->wal->key_shards[shard_num].list,
                        &item->header->list_elem);
            // free key and header
            if (!item->header->mmap) {
                free(item->header->key);
            }
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
        }
        // free
        free(item);
        atomic_decr_uint32_t(&file->wal->size);
        spin_unlock(&file->wal->key_shards[shard_num].lock);
    }

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
    size_t i = 0, seq_shard_num;
    size_t num_all_shards = wal_get_num_all_shards(file);

    if (type == WAL_DISCARD_KV_INS) { // multi KV ins mode
        if (aux == NULL) { // aux must contain pointer to KV ID
            return FDB_RESULT_INVALID_ARGS;
        }
        kv_id_req = *(fdb_kvs_id_t*)aux;
    }

    for (; i < num_all_shards; ++i) {
        spin_lock(&file->wal->key_shards[i].lock);
        e1 = list_begin(&file->wal->key_shards[i].list);
        while (e1) {
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
            while (e2) {
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
                    if (item->flag & WAL_ITEM_BY_COMPACTOR) {
                        seq_shard_num = file->wal->num_shards;
                    } else {
                        seq_shard_num = item->seqnum % file->wal->num_shards;
                    }
                    spin_lock(&file->wal->seq_shards[seq_shard_num].lock);
                    hash_remove(&file->wal->seq_shards[seq_shard_num].hash_byseq,
                                &item->he_seq);
                    spin_unlock(&file->wal->seq_shards[seq_shard_num].lock);

                    if (item->action != WAL_ACT_REMOVE) {
                        atomic_sub_uint64_t(&file->wal->datasize, item->doc_size);
                    }
                    if (item->txn == &file->global_txn) {
                        atomic_decr_uint32_t(&file->wal->num_flushable);
                    }
                    free(item);
                    atomic_decr_uint32_t(&file->wal->size);
                } else {
                    e2 = list_next(e2);
                }
            }
            e1 = list_next(e1);

            if (list_begin(&header->items) == NULL) {
                // wal_item_header becomes empty
                // free header and remove from hash table & wal list
                list_remove(&file->wal->key_shards[i].list, &header->list_elem);
                hash_remove(&file->wal->key_shards[i].hash_bykey, &header->he_key);
                if (!header->mmap) {
                    free(header->key);
                }
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
    return file->wal->size.val;
}

size_t wal_get_num_all_shards(struct filemgr *file)
{
    // normal shards (shard[0] ~ shard[num_shard-1]) +
    // special shard (shard[num_shard]) for compactor
    return file->wal->num_shards + 1;
}

size_t wal_get_num_flushable(struct filemgr *file)
{
    return file->wal->num_flushable.val;
}

size_t wal_get_num_docs(struct filemgr *file) {
    return _kvs_stat_get_sum(file, KVS_STAT_WAL_NDOCS);
}

size_t wal_get_num_deletes(struct filemgr *file) {
    return _kvs_stat_get_sum(file, KVS_STAT_WAL_NDELETES);
}

size_t wal_get_datasize(struct filemgr *file)
{
    return file->wal->datasize.val;
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
