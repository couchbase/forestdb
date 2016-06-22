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
#include "iterator.h"

#include "memleak.h"
#include "time_utils.h"


#ifdef __DEBUG
#ifndef __DEBUG_WAL
    #undef DBG
    #undef DBGCMD
    #undef DBGSW
    #define DBG(...)
    #define DBGCMD(...)
    #define DBGSW(n, ...)
#else
# include "debug.h"
#endif
#endif

INLINE int _wal_keycmp(void *key1, size_t keylen1, void *key2, size_t keylen2)
{
    if (keylen1 == keylen2) {
        return memcmp(key1, key2, keylen1);
    } else {
        size_t len = MIN(keylen1, keylen2);
        int cmp = memcmp(key1, key2, len);
        if (cmp != 0) return cmp;
        else {
            return (int)((int)keylen1 - (int)keylen2);
        }
    }
}

INLINE int __wal_cmp_bykey(struct wal_item_header *aa,
                           struct wal_item_header *bb,
                           void *aux)
{
    struct _fdb_key_cmp_info *info = (struct _fdb_key_cmp_info *)aux;
    if (info->kvs_config.custom_cmp) {
        // custom compare function for variable-length key
        if (info->kvs) {
            // multi KV instance mode
            // KV ID should be compared separately
            size_t size_chunk = info->kvs->getRootHandle()->config.chunksize;
            fdb_kvs_id_t a_id, b_id;
            buf2kvid(size_chunk, aa->key, &a_id);
            buf2kvid(size_chunk, bb->key, &b_id);

            if (a_id < b_id) {
                return -1;
            } else if (a_id > b_id) {
                return 1;
            } else {
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
        return _wal_keycmp(aa->key, aa->keylen, bb->key, bb->keylen);
    }
}

INLINE int _wal_cmp_bykey(struct avl_node *a, struct avl_node *b, void *aux)
{
    struct wal_item_header *aa, *bb;
    aa = _get_entry(a, struct wal_item_header, avl_key);
    bb = _get_entry(b, struct wal_item_header, avl_key);
    return __wal_cmp_bykey(aa, bb, aux);
}

INLINE int _merge_cmp_bykey(struct avl_node *a, struct avl_node *b, void *aux)
{
    struct wal_cursor *aa, *bb;
    aa = _get_entry(a, struct wal_cursor, avl_merge);
    bb = _get_entry(b, struct wal_cursor, avl_merge);
    return __wal_cmp_bykey(aa->item->header, bb->item->header, aux);
}

INLINE int _snap_cmp_bykey(struct avl_node *a, struct avl_node *b, void *aux)
{
    struct wal_item *aa, *bb;
    aa = _get_entry(a, struct wal_item, avl_keysnap);
    bb = _get_entry(b, struct wal_item, avl_keysnap);
    return __wal_cmp_bykey(aa->header, bb->header, aux);
}

INLINE int __wal_cmp_byseq(struct wal_item *aa, struct wal_item *bb) {
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
    }
    return _CMP_U64(aa->seqnum, bb->seqnum);
}

INLINE int _wal_cmp_byseq(struct avl_node *a, struct avl_node *b, void *aux)
{
    struct wal_item *aa, *bb;
    aa = _get_entry(a, struct wal_item, avl_seq);
    bb = _get_entry(b, struct wal_item, avl_seq);
    return __wal_cmp_byseq(aa, bb);
}

INLINE int _merge_cmp_byseq(struct avl_node *a, struct avl_node *b, void *aux)
{
    struct wal_cursor *aa, *bb;
    aa = _get_entry(a, struct wal_cursor, avl_merge);
    bb = _get_entry(b, struct wal_cursor, avl_merge);
    return __wal_cmp_byseq(aa->item, bb->item);
}

INLINE int _wal_kvs_cmp(struct avl_node *a, struct avl_node *b, void *aux)
{
    struct wal_kvs_snaps *aa, *bb;
    aa = _get_entry(a, struct wal_kvs_snaps, avl_id);
    bb = _get_entry(b, struct wal_kvs_snaps, avl_id);

    if (aa->id < bb->id) {
        return -1;
    } else if (aa->id > bb->id) {
        return 1;
    }
    return 0;
}

Wal::Wal(FileMgr *_file, size_t nbucket)
    : file(_file)
{
    flag = WAL_FLAG_INITIALIZED;
    size = 0;
    num_flushable = 0;
    datasize = 0;
    mem_overhead = 0;
    wal_dirty = FDB_WAL_CLEAN;

    list_init(&txn_list);
    spin_init(&lock);

    if (file->getConfig()->getNumWalShards()) {
        num_shards = file->getConfig()->getNumWalShards();
    } else {
        num_shards = DEFAULT_NUM_WAL_PARTITIONS;
    }

    key_shards = (wal_shard *)malloc(sizeof(struct wal_shard) * num_shards);

    if (file->getConfig()->getSeqtreeOpt() == FDB_SEQTREE_USE) {
        seq_shards = (wal_shard *)
            malloc(sizeof(struct wal_shard) * num_shards);
    } else {
        seq_shards = NULL;
    }

    for (int i = num_shards - 1; i >= 0; --i) {
        avl_init(&key_shards[i]._map, NULL);
        spin_init(&key_shards[i].lock);
        if (file->getConfig()->getSeqtreeOpt() == FDB_SEQTREE_USE) {
            avl_init(&seq_shards[i]._map, NULL);
            spin_init(&seq_shards[i].lock);
        }
    }

    avl_init(&wal_kvs_snap_tree, NULL);

    DBG("wal item size %ld\n", sizeof(struct wal_item));
}

Wal::~Wal()
{
    size_t i = 0;
    // Free all WAL shards
    for (; i < num_shards; ++i) {
        spin_destroy(&key_shards[i].lock);
        if (file->getConfig()->getSeqtreeOpt() == FDB_SEQTREE_USE) {
            spin_destroy(&seq_shards[i].lock);
        }
    }
    spin_destroy(&lock);
    free(key_shards);
    if (file->getConfig()->getSeqtreeOpt() == FDB_SEQTREE_USE) {
        free(seq_shards);
    }
}

int Wal::isInitialized_Wal()
{
    return flag & WAL_FLAG_INITIALIZED;
}

inline
struct wal_kvs_snaps *Wal::_wal_get_kvs_snaplist(fdb_kvs_id_t kv_id)
{
    struct wal_kvs_snaps query, *kv_snaps;
    query.id = kv_id;
    struct avl_node *node;
    node = avl_search(&wal_kvs_snap_tree, &query.avl_id, _wal_kvs_cmp);
    if (node) {
        kv_snaps = _get_entry(node, struct wal_kvs_snaps, avl_id);
        return kv_snaps;
    }
    return NULL;
}

inline
struct snap_handle * Wal::_wal_get_latest_snapshot(struct wal_kvs_snaps *kv_snaps)
{
    struct snap_handle *shandle = NULL;
    struct list_elem *e = list_end(&kv_snaps->snap_list);
    if (e) {
        shandle = _get_entry(e, struct snap_handle, snaplist_elem);
    }
    return shandle;
}

inline
struct snap_handle *Wal::_wal_snapshot_create(fdb_kvs_id_t kv_id,
                                              wal_snapid_t snap_tag,
                                              wal_snapid_t snap_flush_tag,
                                              _fdb_key_cmp_info *key_cmp_info,
                                              struct wal_kvs_snaps *kvs_snapshots)
{
   struct snap_handle *shandle = (struct snap_handle *)
                                   calloc(1, sizeof(struct snap_handle));
   if (shandle) {
       shandle->id = kv_id;
       shandle->snap_tag_idx = snap_tag;
       shandle->snap_stop_idx = snap_flush_tag;
       shandle->ref_cnt_kvs = 0;
       shandle->wal_ndocs = 0;
       shandle->cmp_info = *key_cmp_info; // (key_cmp_info may be stack memory)
       avl_init(&shandle->key_tree, &shandle->cmp_info);
       avl_init(&shandle->seq_tree, NULL);
       shandle->kvs_snapshots = kvs_snapshots;
       return shandle;
   }
   return NULL;
}

/**
 * Returns highest mutable snapshot or creates one if...
 * No snapshot exists (First item for a given kv store is inserted)
 * If the highest snapshot was made immutable by snapshot_open (Write barrier)
 * If the highest snapshot was made un-readable by flush_Wal (Read barrier)
 */
inline
struct snap_handle * Wal::_wal_fetch_snapshot(fdb_kvs_id_t kv_id,
                                              _fdb_key_cmp_info *key_cmp_info)

{
    struct wal_kvs_snaps *kvs_snapshots;
    struct snap_handle *open_snapshot;
    wal_snapid_t snap_id, snap_flush_id = 0;
    spin_lock(&lock);
    kvs_snapshots = _wal_get_kvs_snaplist(kv_id);
    if (!kvs_snapshots) { // First time a KV Store item is inserted..
        kvs_snapshots = (struct wal_kvs_snaps *)malloc(sizeof(struct wal_kvs_snaps));
        kvs_snapshots->id = kv_id;
        kvs_snapshots->num_snaps = 0;
        list_init(&kvs_snapshots->snap_list);
        avl_insert(&wal_kvs_snap_tree, &kvs_snapshots->avl_id, _wal_kvs_cmp);
    }
    open_snapshot = _wal_get_latest_snapshot(kvs_snapshots);
    if (!open_snapshot || // if first WAL item inserted for KV store
        _wal_snap_is_immutable(open_snapshot) ||//Write barrier (snapshot_open)
        open_snapshot->is_flushed) { // flush_Waled (read-write barrier)
        if (!open_snapshot) {
            snap_id = 1; // begin snapshots id at 1
            snap_flush_id = 0; // all past elements can be returned
            DBG("Fresh KV id %" _F64 " Snapshot %" _F64 "- %" _F64"\n",
                kv_id, snap_flush_id, snap_id);
        } else { // read/write barrier means a new WAL snapshot gets created
            snap_id = open_snapshot->snap_tag_idx + 1;
            if (!open_snapshot->is_flushed) { // Write barrier only
                snap_flush_id = open_snapshot->snap_stop_idx;
                DBG("Write Barrier WAL KV id %" _F64 " Snapshot %" _F64
                    " - %" _F64 "\n", kv_id, snap_flush_id, snap_id);
            } else { // WAL flushed! Read & Write barrier
                snap_flush_id = open_snapshot->snap_tag_idx;
                DBG("Read-Write Barrier WAL KV id %" _F64 " Snapshot %" _F64
                    "- %" _F64 "\n",
                    kv_id, snap_flush_id, snap_id);
            }
        }
        open_snapshot = _wal_snapshot_create(kv_id, snap_id, snap_flush_id,
                                             key_cmp_info, kvs_snapshots);
        list_push_back(&kvs_snapshots->snap_list, &open_snapshot->snaplist_elem);
        kvs_snapshots->num_snaps++;
    }
    // Increment ndocs for garbage collection of the snapshot
    // When no more docs refer to a snapshot, it can be safely deleted
    open_snapshot->wal_ndocs++;
    spin_unlock(&lock);
    return open_snapshot;
}

inline fdb_status Wal::_wal_snapshot_init(struct snap_handle *shandle,
                                          fdb_txn *txn,
                                          fdb_seqnum_t seqnum)
{
    struct list_elem *ee;
    shandle->snap_txn = txn;
    shandle->ref_cnt_kvs++;
    file->getKvsStatOps()->statGet(shandle->id, &shandle->stat);
    if (seqnum == FDB_SNAPSHOT_INMEM) {
        shandle->seqnum = fdb_kvs_get_seqnum(file, shandle->id);
        shandle->is_persisted_snapshot = false;
    } else {
        shandle->stat.wal_ndocs = 0; // WAL copy will populate
        shandle->stat.wal_ndeletes = 0; // these 2 stats
        shandle->seqnum = seqnum;
        shandle->is_persisted_snapshot = true;
    }
    shandle->global_txn = file->getGlobalTxn();
    list_init(&shandle->active_txn_list);
    ee = list_begin(&txn_list);
    while (ee) {
        struct wal_txn_wrapper *txn_wrapper;
        fdb_txn *active_txn;
        txn_wrapper = _get_entry(ee, struct wal_txn_wrapper, le);
        active_txn = txn_wrapper->txn;
        // except for global_txn
        if (active_txn != file->getGlobalTxn()) {
            txn_wrapper = (struct wal_txn_wrapper *)
                calloc(1, sizeof(struct wal_txn_wrapper));
            txn_wrapper->txn_id = active_txn->txn_id;
            list_push_front(&shandle->active_txn_list, &txn_wrapper->le);
        }
        ee = list_next(ee);
    }

    return FDB_RESULT_SUCCESS;
}

fdb_status Wal::snapshotOpen_Wal(fdb_txn *txn,
                                 fdb_kvs_id_t kv_id,
                                 fdb_seqnum_t seqnum,
                                 _fdb_key_cmp_info *key_cmp_info,
                                 struct snap_handle **shandle)
{
    struct wal_kvs_snaps *kvs_snapshots;
    struct snap_handle *_shandle;

    spin_lock(&lock);
    kvs_snapshots = _wal_get_kvs_snaplist(kv_id);
    if (kvs_snapshots) {
        _shandle = _wal_get_latest_snapshot(kvs_snapshots);
    } else {
        _shandle = NULL;
    }
    if (!_shandle || // No item exist in WAL for this KV Store
        !_shandle->wal_ndocs.load() || // Empty snapshot
        _shandle->is_flushed) { // Latest snapshot has read-write barrier
        // This can happen when a new snapshot is attempted and WAL was flushed
        // and no mutations after WAL flush - the snapshot exists solely for
        // existing open snapshot iterators
        _shandle = _wal_snapshot_create(kv_id, 0, 0, key_cmp_info, kvs_snapshots);
        if (!_shandle) { // LCOV_EXCL_START
            spin_unlock(&lock);
            return FDB_RESULT_ALLOC_FAIL;
        } // LCOV_EXCL_STOP
        // This snapshot is not inserted into global shared tree
        _wal_snapshot_init(_shandle, txn, seqnum);
        DBG("%s Persisted snapshot taken at %" _F64 " for kv id %" _F64 "\n",
            file->getFileName(), _shandle->seqnum, kv_id);
    } else { // Take a snapshot of the latest WAL state for this KV Store
        // Bump up ref count on all past snapshots to prevent deletion!
        int num_prev_snaps = 0;
        struct list_elem *e = list_prev(&_shandle->snaplist_elem);
        while (e) {
            struct snap_handle *__shandle = _get_entry(e,
                    struct snap_handle, snaplist_elem);
            if (__shandle->snap_tag_idx <= _shandle->snap_stop_idx) {
                    break;
            }
            __shandle->ref_cnt_kvs++;
            num_prev_snaps++;
            e = list_prev(e);
        }
        if (_wal_snap_is_immutable(_shandle)) { // existing snapshot still open
            _shandle->ref_cnt_kvs++; // ..just Clone it
            DBG("%s Snapshot Clone %" _F64 " - %" _F64 " taken at %"
                _F64 " for kv id %" _F64 " Prev Snapshots =%d\n",
                file->getFileName(), _shandle->snap_stop_idx,
                _shandle->snap_tag_idx, _shandle->seqnum, kv_id,
                _shandle->num_prev_snaps);
            fdb_assert(_shandle->num_prev_snaps == num_prev_snaps,
                       _shandle->num_prev_snaps, num_prev_snaps);
        } else { // make this snapshot of the WAL immutable..
            _shandle->num_prev_snaps = num_prev_snaps;
            _wal_snapshot_init(_shandle, txn, seqnum);
            DBG("%s New Snapshot %" _F64 " - %" _F64 " taken at %"
                _F64 " for kv id %" _F64 " prev_snaps=%d\n",
                file->getFileName(), _shandle->snap_stop_idx,
                _shandle->snap_tag_idx, _shandle->seqnum, kv_id,
                _shandle->num_prev_snaps);
        }
    }
    spin_unlock(&lock);
    *shandle = _shandle;
    return FDB_RESULT_SUCCESS;
}

inline void Wal::_wal_update_stat(fdb_kvs_id_t kv_id,
                                  _wal_update_type type)
{
    switch (type) {
        case _WAL_NEW_DEL: // inserted deleted doc: ++wal_ndocs, ++wal_ndeletes
            file->getKvsStatOps()->statUpdateAttr(kv_id, KVS_STAT_WAL_NDELETES, 1);
        case _WAL_NEW_SET: // inserted new doc: ++wal_ndocs
            file->getKvsStatOps()->statUpdateAttr(kv_id, KVS_STAT_WAL_NDOCS, 1);
            break;
        case _WAL_SET_TO_DEL: // update prev doc to deleted: ++wal_ndeletes
            file->getKvsStatOps()->statUpdateAttr(kv_id, KVS_STAT_WAL_NDELETES, 1);
            break;
        case _WAL_DEL_TO_SET: // update prev deleted doc to set: --wal_ndeletes
            file->getKvsStatOps()->statUpdateAttr(kv_id, KVS_STAT_WAL_NDELETES, -1);
            break;
        case _WAL_DROP_DELETE: // drop deleted item: --wal_ndocs,--wal_ndeletes
            file->getKvsStatOps()->statUpdateAttr(kv_id, KVS_STAT_WAL_NDELETES, -1);
        case _WAL_DROP_SET: // drop item: --wal_ndocs
            file->getKvsStatOps()->statUpdateAttr(kv_id, KVS_STAT_WAL_NDOCS, -1);
            break;
    }
}

inline fdb_status Wal::_insert_Wal(fdb_txn *txn,
                                   struct _fdb_key_cmp_info *cmp_info,
                                   fdb_doc *doc,
                                   uint64_t offset,
                                   wal_insert_by caller,
                                   bool immediate_remove)
{
    struct wal_item *item;
    struct wal_item_header query, *header;
    struct snap_handle *shandle;
    struct list_elem *le;
    struct avl_node *node;
    void *key = doc->key;
    size_t keylen = doc->keylen;
    size_t chk_sum;
    size_t shard_num;
    wal_snapid_t snap_tag;
    fdb_kvs_id_t kv_id;
    LATENCY_STAT_START();

    if (file->getKVHeader_UNLOCKED()) { // multi KV instance mode
        buf2kvid(file->getConfig()->getChunkSize(), doc->key, &kv_id);
    } else {
        kv_id = 0;
    }
    shandle = _wal_fetch_snapshot(kv_id, cmp_info);
    snap_tag = shandle->snap_tag_idx;
    query.key = key;
    query.keylen = keylen;
    chk_sum = get_checksum((uint8_t*)key, keylen);
    shard_num = chk_sum % num_shards;
    if (caller == WAL_INS_WRITER) {
        spin_lock(&key_shards[shard_num].lock);
    }

    // Since we can have a different custom comparison function per kv store
    // set the custom compare aux function every time before a search is done
    avl_set_aux(&key_shards[shard_num]._map,
                (void *)cmp_info);
    node = avl_search(&key_shards[shard_num]._map,
                      &query.avl_key, _wal_cmp_bykey);

    if (node) {
        // already exist .. retrieve header
        header = _get_entry(node, struct wal_item_header, avl_key);

        // find uncommitted item belonging to the same txn
        le = list_begin(&header->items);
        while (le) {
            item = _get_entry(le, struct wal_item, list_elem);

            if (item->txn_id == txn->txn_id
                && !(item->flag & WAL_ITEM_COMMITTED ||
                caller == WAL_INS_COMPACT_PHASE1) &&
                item->shandle->snap_tag_idx == snap_tag) {
                item->flag &= ~WAL_ITEM_FLUSH_READY;

                if (file->getConfig()->getSeqtreeOpt() == FDB_SEQTREE_USE) {
                    // Re-index the item by new sequence number..
                    size_t seq_shard_num = item->seqnum % num_shards;
                    if (caller == WAL_INS_WRITER) {
                        spin_lock(&seq_shards[seq_shard_num].lock);
                    }
                    avl_remove(&seq_shards[seq_shard_num]._map,
                               &item->avl_seq);
                    if (caller == WAL_INS_WRITER) {
                        spin_unlock(&seq_shards[seq_shard_num].lock);
                    }

                    item->seqnum = doc->seqnum;
                    seq_shard_num = doc->seqnum % num_shards;
                    if (caller == WAL_INS_WRITER) {
                        spin_lock(&seq_shards[seq_shard_num].lock);
                    }
                    avl_insert(&seq_shards[seq_shard_num]._map,
                               &item->avl_seq, _wal_cmp_byseq);
                    if (caller == WAL_INS_WRITER) {
                        spin_unlock(&seq_shards[seq_shard_num].lock);
                    }
                } else {
                    // just overwrite existing WAL item
                    item->seqnum = doc->seqnum;
                }

                // mark previous doc region as stale
                size_t doc_size_ondisk = doc->size_ondisk;
                uint32_t stale_len = item->doc_size;
                uint64_t stale_offset = item->offset;
                if (item->action == WAL_ACT_INSERT ||
                    item->action == WAL_ACT_LOGICAL_REMOVE) {
                    // insert or logical remove
                    file->markStale(stale_offset, stale_len);
                }

                if (doc->deleted) {
                    if (item->txn_id == file->getGlobalTxn()->txn_id &&
                        item->action == WAL_ACT_INSERT) {
                        _wal_update_stat(kv_id, _WAL_SET_TO_DEL);
                    }
                    if (offset != BLK_NOT_FOUND && !immediate_remove) {
                        // purge interval not met yet
                        item->action = WAL_ACT_LOGICAL_REMOVE;// insert deleted
                    } else { // drop the deleted doc right away
                        item->action = WAL_ACT_REMOVE; // immediate prune index

                        if (offset != BLK_NOT_FOUND) {
                            // immediately mark as stale if offset is given
                            // (which means that a deletion mark was appended into
                            //  the file before calling wal_insert()).
                            file->markStale(offset, doc_size_ondisk);
                        }
                        doc_size_ondisk = 0;
                    }
                } else {
                    if (item->txn_id == file->getGlobalTxn()->txn_id &&
                        item->action != WAL_ACT_INSERT) {
                        _wal_update_stat(kv_id, _WAL_DEL_TO_SET);
                    }
                    item->action = WAL_ACT_INSERT;
                }
                datasize.fetch_add(doc_size_ondisk - item->doc_size,
                                   std::memory_order_relaxed);
                item->doc_size = doc->size_ondisk;
                item->offset = offset;
                item->shandle = shandle;

                // move the item to the front of the list (header)
                list_remove(&header->items, &item->list_elem);
                list_push_front(&header->items, &item->list_elem);
                shandle->wal_ndocs--;
                break;
            }
            le = list_next(le);
        }

        if (le == NULL) {
            // not exist
            // create new item
            item = (struct wal_item *)calloc(1, sizeof(struct wal_item));

            if (file->getKVHeader_UNLOCKED()) { // multi KV instance mode
                item->flag |= WAL_ITEM_MULTI_KV_INS_MODE;
            }
            item->txn = txn;
            item->txn_id = txn->txn_id;
            if (txn->txn_id == file->getGlobalTxn()->txn_id) {
                num_flushable++;
            }
            item->header = header;
            item->seqnum = doc->seqnum;

            if (doc->deleted) {
                if (item->txn_id == file->getGlobalTxn()->txn_id) {
                    _wal_update_stat(kv_id, _WAL_NEW_DEL);
                }
                if (offset != BLK_NOT_FOUND && !immediate_remove) {
                    // purge interval not met yet
                    item->action = WAL_ACT_LOGICAL_REMOVE;// insert deleted
                } else { // compactor purge deleted doc
                    item->action = WAL_ACT_REMOVE; // immediate prune index

                    if (offset != BLK_NOT_FOUND) {
                        // immediately mark as stale if offset is given
                        // (which means that a deletion mark was appended into
                        //  the file before calling insert_Wal()).
                        file->markStale(offset, doc->size_ondisk);
                    }
                }
            } else {
                if (item->txn_id == file->getGlobalTxn()->txn_id) {
                    _wal_update_stat(kv_id, _WAL_NEW_SET);
                }
                item->action = WAL_ACT_INSERT;
            }
            item->offset = offset;
            item->doc_size = doc->size_ondisk;
            item->shandle = shandle;
            if (item->action != WAL_ACT_REMOVE) {
                datasize.fetch_add(doc->size_ondisk,
                                              std::memory_order_relaxed);
            }

            if (file->getConfig()->getSeqtreeOpt() == FDB_SEQTREE_USE) {
                size_t seq_shard_num = doc->seqnum % num_shards;
                if (caller == WAL_INS_WRITER) {
                    spin_lock(&seq_shards[seq_shard_num].lock);
                }
                avl_insert(&seq_shards[seq_shard_num]._map,
                           &item->avl_seq, _wal_cmp_byseq);
                if (caller == WAL_INS_WRITER) {
                    spin_unlock(&seq_shards[seq_shard_num].lock);
                }
            }
            // insert into header's list
            list_push_front(&header->items, &item->list_elem);
            // also insert into transaction's list
            list_push_back(txn->items, &item->list_elem_txn);

            size++;
            mem_overhead.fetch_add(sizeof(struct wal_item),
                                   std::memory_order_relaxed);
        }
    } else {
        // not exist .. create new one
        // create new header and new item
        header = (struct wal_item_header*)malloc(sizeof(struct wal_item_header));
        list_init(&header->items);
        header->chunksize = file->getConfig()->getChunkSize();
        header->keylen = keylen;
        header->key = (void *)malloc(header->keylen);
        memcpy(header->key, key, header->keylen);

        avl_insert(&key_shards[shard_num]._map,
                   &header->avl_key, _wal_cmp_bykey);

        item = (struct wal_item *)malloc(sizeof(struct wal_item));
        // entries inserted by compactor is already committed
        if (caller == WAL_INS_COMPACT_PHASE1) {
            item->flag = WAL_ITEM_COMMITTED;
        } else {
            item->flag = 0x0;
        }
        if (file->getKVHeader_UNLOCKED()) { // multi KV instance mode
            item->flag |= WAL_ITEM_MULTI_KV_INS_MODE;
        }
        item->txn = txn;
        item->txn_id = txn->txn_id;
        if (txn->txn_id == file->getGlobalTxn()->txn_id) {
            num_flushable++;
        }
        item->header = header;

        item->seqnum = doc->seqnum;

        if (doc->deleted) {
            if (item->txn_id == file->getGlobalTxn()->txn_id) {
                _wal_update_stat(kv_id, _WAL_NEW_DEL);
            }
            if (offset != BLK_NOT_FOUND && !immediate_remove) {// purge interval not met yet
                item->action = WAL_ACT_LOGICAL_REMOVE;// insert deleted
            } else { // compactor purge deleted doc
                item->action = WAL_ACT_REMOVE; // immediate prune index

                if (offset != BLK_NOT_FOUND) {
                    // immediately mark as stale if offset is given
                    // (which means that an empty doc was appended before
                    //  calling insert_Wal()).
                    file->markStale(offset, doc->size_ondisk);
                }
            }
        } else {
            if (item->txn_id == file->getGlobalTxn()->txn_id) {
                _wal_update_stat(kv_id, _WAL_NEW_SET);
            }
            item->action = WAL_ACT_INSERT;
        }
        item->offset = offset;
        item->doc_size = doc->size_ondisk;
        item->shandle = shandle;
        if (item->action != WAL_ACT_REMOVE) {
            datasize.fetch_add(doc->size_ondisk,
                               std::memory_order_relaxed);
        }

        if (file->getConfig()->getSeqtreeOpt() == FDB_SEQTREE_USE) {
            size_t seq_shard_num = doc->seqnum % num_shards;
            if (caller == WAL_INS_WRITER) {
                spin_lock(&seq_shards[seq_shard_num].lock);
            }
            avl_insert(&seq_shards[seq_shard_num]._map,
                       &item->avl_seq, _wal_cmp_byseq);
            if (caller == WAL_INS_WRITER) {
                spin_unlock(&seq_shards[seq_shard_num].lock);
            }
        }

        // insert into header's list
        list_push_front(&header->items, &item->list_elem);
        if (caller == WAL_INS_WRITER || caller == WAL_INS_COMPACT_PHASE2) {
            // also insert into transaction's list
            list_push_back(txn->items, &item->list_elem_txn);
        }

        size++;
        mem_overhead.fetch_add(
            sizeof(struct wal_item) + sizeof(struct wal_item_header) + keylen,
            std::memory_order_relaxed);
    }

    if (caller == WAL_INS_WRITER) {
        spin_unlock(&key_shards[shard_num].lock);
    }

    LATENCY_STAT_END(file, FDB_LATENCY_WAL_INS);
    return FDB_RESULT_SUCCESS;
}

fdb_status Wal::insert_Wal(fdb_txn *txn,
                           struct _fdb_key_cmp_info *cmp_info,
                           fdb_doc *doc,
                           uint64_t offset,
                           wal_insert_by caller)
{
    return _insert_Wal(txn, cmp_info, doc, offset, caller, false);
}

fdb_status Wal::immediateRemove_Wal(fdb_txn *txn,
                                    struct _fdb_key_cmp_info *cmp_info,
                                    fdb_doc *doc,
                                    uint64_t offset,
                                    wal_insert_by caller)
{
    return _insert_Wal(txn, cmp_info, doc, offset, caller, true);
}

inline bool Wal::_wal_item_partially_committed(fdb_txn *global_txn,
                                               struct list *active_txn_list,
                                               fdb_txn *current_txn,
                                               struct wal_item *item)
{
    bool partial_commit = false;

    if (item->flag & WAL_ITEM_COMMITTED &&
        item->txn != global_txn && item->txn != current_txn) {
        struct wal_txn_wrapper *txn_wrapper;
        struct list_elem *txn_elem = list_begin(active_txn_list);
        while(txn_elem) {
            txn_wrapper = _get_entry(txn_elem, struct wal_txn_wrapper, le);
            if (txn_wrapper->txn_id == item->txn_id) {
                partial_commit = true;
                break;
            }
            txn_elem = list_next(txn_elem);
        }
    }
    return partial_commit;
}

/**
 * Since items are shared with current & future snapshots...
 * Find item belonging to snapshot OR
 * The item from the previous most recent snapshot
 *
 * TODO: Due to the fact that transactional items can overwrite
 *       more recent items created upon fdb_end_trans, we must scan entire list
 *       to find a qualifying item from the previous most recent snapshot
 *       This is not efficient and we need a better way of ordering the list
 */
inline struct wal_item *Wal::_wal_get_snap_item(struct wal_item_header *header,
                                                struct snap_handle *shandle)
{
    struct wal_item *item;
    struct wal_item *max_shared_item = NULL;
    fdb_txn *txn = shandle->snap_txn;
    wal_snapid_t tag = shandle->snap_tag_idx;
    wal_snapid_t snap_stop_tag = shandle->snap_stop_idx;
    struct list_elem *le = list_begin(&header->items);

    // discard wal keys that have no items in them
    if (!le) {
        return NULL;
    }

    for (; le; le = list_next(le)) {
        item = _get_entry(le, struct wal_item, list_elem);
        if (item->txn_id != txn->txn_id && !(item->flag & WAL_ITEM_COMMITTED)) {
            continue;
        }
        if (item->shandle->snap_tag_idx > tag) {
            continue; // this item was inserted after snapshot creation -> skip
        }
        if (_wal_item_partially_committed(shandle->global_txn,
                                          &shandle->active_txn_list,
                                          txn, item)) {
            continue;
        }
        if (item->shandle->snap_tag_idx == tag) {// Found exact snapshot item
            max_shared_item = item; // look no further
            break;
        }

        // if my snapshot was taken after a WAL flush..
        if (item->shandle->snap_tag_idx <= snap_stop_tag) {
            continue; // then do not consider pre-flush items
        }
        if (item->shandle->snap_tag_idx < tag) {
            if (!max_shared_item) {
                max_shared_item = item;
            } else if (item->shandle->snap_tag_idx >
                       max_shared_item->shandle->snap_tag_idx) {
                max_shared_item = item;
            }
        }
    }
    return (struct wal_item *)max_shared_item;
}

fdb_status Wal::_find_Wal(fdb_txn *txn,
                          fdb_kvs_id_t kv_id,
                          struct _fdb_key_cmp_info *cmp_info,
                          struct snap_handle *shandle,
                          fdb_doc *doc,
                          uint64_t *offset)
{
    struct wal_item item_query, *item = NULL;
    struct wal_item_header query, *header = NULL;
    struct list_elem *le = NULL, *_le;
    struct avl_node *node = NULL;
    void *key = doc->key;
    size_t keylen = doc->keylen;
    LATENCY_STAT_START();

    if (doc->seqnum == SEQNUM_NOT_USED || (key && keylen>0)) {
        size_t chk_sum = get_checksum((uint8_t*)key, keylen);
        size_t shard_num = chk_sum % num_shards;
        spin_lock(&key_shards[shard_num].lock);
        // search by key
        query.key = key;
        query.keylen = keylen;
        avl_set_aux(&key_shards[shard_num]._map,
                    (void *)cmp_info);
        node = avl_search(&key_shards[shard_num]._map,
                          &query.avl_key, _wal_cmp_bykey);
        if (node) {
            struct wal_item *committed_item = NULL;
            // retrieve header
            header = _get_entry(node, struct wal_item_header, avl_key);
            if (shandle) {
                item = _wal_get_snap_item(header, shandle);
            } else { // regular non-snapshot lookup
                for (le = list_begin(&header->items);
                     le; le = _le) {
                    item = _get_entry(le, struct wal_item, list_elem);
                    // Items get ordered as follows in the header's list..
                    // (begin) 6 --- 5 --- 4 --- 1 --- 2 --- 3 <-- (end)
                    //  Uncommitted items-->     <--- Committed items
                    if (!committed_item) {
                        if (item->flag & WAL_ITEM_COMMITTED) {
                            committed_item = item;
                            _le = list_end(&header->items);
                            if (_le == le) { // just one element at the end
                                _le = NULL; // process current element & exit
                            } else { // current element is not the last item..
                                continue; // start reverse scan from the end
                            }
                        } else { // uncommitted items - still continue forward
                            _le = list_next(le);
                        }
                    } else { // reverse scan list over committed items..
                        _le = list_prev(le);
                        // is it back to the first committed item..
                        if (_le == &committed_item->list_elem) {
                            _le = NULL; // need not re-iterate over uncommitted
                        }
                    }
                    if (item->flag & WAL_ITEM_FLUSHED_OUT) {
                        item = NULL; // item reflected in main index and is not
                        break; // to be returned for non-snapshot reads
                    }
                    // only committed items can be seen by the other handles, OR
                    // items belonging to the same txn can be found, OR
                    // a transaction's isolation level is read uncommitted.
                    if ((item->flag & WAL_ITEM_COMMITTED) ||
                        (item->txn_id == txn->txn_id) ||
                        (txn->isolation == FDB_ISOLATION_READ_UNCOMMITTED)) {
                        break;
                    } else {
                        item = NULL;
                    }
                } // done for all items in the header's list
            } // done for regular (non-snapshot) lookup
            if (item) {
                *offset = item->offset;
                if (item->action == WAL_ACT_INSERT) {
                    doc->deleted = false;
                } else {
                    doc->deleted = true;
                    if (item->action == WAL_ACT_REMOVE) {
                        // Immediately deleted & purged docs have no real
                        // presence on-disk. find_Wal must return SUCCESS
                        // here to indicate that the doc was deleted to
                        // prevent main index lookup. Also, it must set the
                        // offset to BLK_NOT_FOUND to ensure that caller
                        // does NOT attempt to fetch the doc OR its
                        // metadata from file.
                        *offset = BLK_NOT_FOUND;
                    }
                }
                doc->seqnum = item->seqnum;
                spin_unlock(&key_shards[shard_num].lock);
                LATENCY_STAT_END(file, FDB_LATENCY_WAL_FIND);
                return FDB_RESULT_SUCCESS;
            }
        }
        spin_unlock(&key_shards[shard_num].lock);
    } else {
        if (file->getConfig()->getSeqtreeOpt() != FDB_SEQTREE_USE) {
            return FDB_RESULT_INVALID_CONFIG;
        }
        // search by seqnum
        struct wal_item_header temp_header;

        if (file->getKVHeader_UNLOCKED()) { // multi KV instance mode
            temp_header.key = (void*)alca(uint8_t, file->getConfig()->getChunkSize());
            kvid2buf(file->getConfig()->getChunkSize(), kv_id, temp_header.key);
            item_query.header = &temp_header;
        }
        item_query.seqnum = doc->seqnum;

        size_t shard_num = doc->seqnum % num_shards;
        spin_lock(&seq_shards[shard_num].lock);
        node = avl_search(&seq_shards[shard_num]._map,
                          &item_query.avl_seq, _wal_cmp_byseq);
        if (node) {
            item = _get_entry(node, struct wal_item, avl_seq);
            if ((item->flag & WAL_ITEM_COMMITTED) ||
                (item->txn_id == txn->txn_id) ||
                (txn->isolation == FDB_ISOLATION_READ_UNCOMMITTED)) {
                *offset = item->offset;
                if (item->action == WAL_ACT_INSERT) {
                    doc->deleted = false;
                } else {
                    doc->deleted = true;
                    if (item->action == WAL_ACT_REMOVE) {
                        // Immediately deleted & purged doc have no real
                        // presence on-disk. find_Wal must return SUCCESS
                        // here to indicate that the doc was deleted to
                        // prevent main index lookup. Also, it must set the
                        // offset to BLK_NOT_FOUND to ensure that caller
                        // does NOT attempt to fetch the doc OR its
                        // metadata from file.
                        *offset = BLK_NOT_FOUND;
                    }
                }
                spin_unlock(&seq_shards[shard_num].lock);
                LATENCY_STAT_END(file, FDB_LATENCY_WAL_FIND);
                return FDB_RESULT_SUCCESS;
            }
        }
        spin_unlock(&seq_shards[shard_num].lock);
    }

    LATENCY_STAT_END(file, FDB_LATENCY_WAL_FIND);
    return FDB_RESULT_KEY_NOT_FOUND;
}

fdb_status Wal::find_Wal(fdb_txn *txn, struct _fdb_key_cmp_info *cmp_info,
                         struct snap_handle *shandle,
                         fdb_doc *doc, uint64_t *offset)
{
    if (shandle) {
        if (shandle->is_persisted_snapshot) {
            return _snapFind_Wal(shandle, doc, offset);
        }
    }
    return _find_Wal(txn, 0, cmp_info, shandle, doc, offset);
}

fdb_status Wal::findWithKvid_Wal(fdb_txn *txn,
                                 fdb_kvs_id_t kv_id,
                                 struct _fdb_key_cmp_info *cmp_info,
                                 struct snap_handle *shandle,
                                 fdb_doc *doc,
                                 uint64_t *offset)
{
    if (shandle) {
        if (shandle->is_persisted_snapshot) {
            return _snapFind_Wal(shandle, doc, offset);
        }
    }
    return _find_Wal(txn, kv_id, cmp_info, shandle, doc, offset);
}

// Pre-condition: writer lock (filemgr mutex) must be held for this call
// Readers can interleave without lock
inline void Wal::_wal_free_item(struct wal_item *item, bool gotlock) {
    struct snap_handle *shandle = item->shandle;
    if (!(--shandle->wal_ndocs)) {
        if (!gotlock) {
            spin_lock(&lock);
        }
        fdb_assert(!_wal_snap_is_immutable(shandle), shandle->snap_tag_idx,
                   shandle->snap_stop_idx);
        DBG("%s Last item removed from snapshot %" _F64 "-%" _F64 " %" _F64
                " kv id %" _F64 ". Destroy snapshot handle..\n",
                shandle->snap_txn && shandle->snap_txn->handle ?
                shandle->snap_txn->handle->file->getFileName() : "",
                shandle->snap_stop_idx, shandle->snap_tag_idx,
                shandle->seqnum, shandle->id);
        list_remove(&shandle->kvs_snapshots->snap_list, &shandle->snaplist_elem);
        --shandle->kvs_snapshots->num_snaps;
        for (struct list_elem *e = list_begin(&shandle->active_txn_list); e;) {
            struct list_elem *e_next = list_next(e);
            struct wal_txn_wrapper *active_txn = _get_entry(e,
                                                 struct wal_txn_wrapper, le);
            free(active_txn);
            e = e_next;
        }
        free(shandle);
        if (!gotlock) {
            spin_unlock(&lock);
        }
    }
#ifdef __DEBUG_WAL
    memset(item, 0, sizeof(struct wal_item));
#endif // __DEBUG_WAL
    free(item);
}

fdb_status Wal::migrateUncommittedTxns_Wal(void *dbhandle,
                                           void *new_dhandle,
                                           FileMgr *old_file,
                                           FileMgr *new_file,
                                           wal_doc_move_func *move_doc)
{
    int64_t offset;
    fdb_doc doc;
    fdb_txn *txn;
    struct wal_txn_wrapper *txn_wrapper;
    struct wal_item_header *header;
    struct wal_item *item;
    struct avl_node *node;
    struct list_elem *e;
    size_t i = 0;
    size_t num_shards = old_file->getWal()->num_shards;
    uint64_t mem_overhead = 0;
    struct _fdb_key_cmp_info cmp_info;

    // Note that the caller (i.e., compactor) alreay owns the locks on
    // both old_file and new_file filemgr instances. Therefore, it is OK to
    // grab each partition lock individually and move all uncommitted items
    // to the new_file filemgr instance.

    for (; i < num_shards; ++i) {
        spin_lock(&old_file->getWal()->key_shards[i].lock);
        node = avl_first(&old_file->getWal()->key_shards[i]._map);
        while(node) {
            header = _get_entry(node, struct wal_item_header, avl_key);
            e = list_end(&header->items);
            while(e) {
                item = _get_entry(e, struct wal_item, list_elem);
                if (!(item->flag & WAL_ITEM_COMMITTED)) {
                    // not committed yet
                    // move doc
                    offset = move_doc(dbhandle, new_dhandle, item, &doc);
                    if (offset <= 0) {
                        spin_unlock(&old_file->getWal()->key_shards[i].lock);
                        return offset < 0 ? (fdb_status) offset : FDB_RESULT_READ_FAIL;
                    }
                    // Note that all items belonging to global_txn should be
                    // flushed before calling this function
                    // (migrate transactional items only).
                    fdb_assert(item->txn != old_file->getGlobalTxn(),
                               (uint64_t)item->txn, 0);
                    cmp_info.kvs_config = item->txn->handle->kvs_config;
                    cmp_info.kvs = item->txn->handle->kvs;
                    // insert into new_file's WAL
                    new_file->getWal()->insert_Wal(item->txn, &cmp_info, &doc, offset,
                               WAL_INS_WRITER);

                    if (old_file->getConfig()->getSeqtreeOpt() == FDB_SEQTREE_USE) {
                        // remove from seq map
                        size_t shard_num = item->seqnum % num_shards;
                        spin_lock(&old_file->getWal()->seq_shards[shard_num].lock);
                        avl_remove(&old_file->getWal()->seq_shards[shard_num]._map,
                                &item->avl_seq);
                        spin_unlock(&old_file->getWal()->seq_shards[shard_num].lock);
                    }

                    // remove from header's list
                    e = list_remove_reverse(&header->items, e);
                    // remove from transaction's list
                    list_remove(item->txn->items, &item->list_elem_txn);
                    // decrease num_flushable of old_file if non-transactional update
                    if (item->txn_id == old_file->getGlobalTxn()->txn_id) {
                        old_file->getWal()->num_flushable--;
                    }
                    if (item->action != WAL_ACT_REMOVE) {
                        old_file->getWal()->datasize.fetch_sub(item->doc_size,
                                                          std::memory_order_relaxed);
                    }
                    // free item
                    free(item);
                    // free doc
                    free(doc.key);
                    free(doc.meta);
                    free(doc.body);
                    old_file->getWal()->size--;
                    mem_overhead += sizeof(struct wal_item);
                } else {
                    e = list_prev(e);
                }
            }

            if (list_begin(&header->items) == NULL) {
                // header's list becomes empty
                // remove from key map
                node = avl_next(node);
                avl_remove(&old_file->getWal()->key_shards[i]._map,
                           &header->avl_key);
                mem_overhead += header->keylen + sizeof(struct wal_item_header);
                // free key & header
                free(header->key);
                free(header);
            } else {
                node = avl_next(node);
            }
        }
        spin_unlock(&old_file->getWal()->key_shards[i].lock);
    }
    old_file->getWal()->mem_overhead.fetch_sub(mem_overhead,
                                          std::memory_order_relaxed);

    spin_lock(&old_file->getWal()->lock);

    // migrate all entries in txn list
    e = list_begin(&old_file->getWal()->txn_list);
    while(e) {
        txn_wrapper = _get_entry(e, struct wal_txn_wrapper, le);
        txn = txn_wrapper->txn;
        // except for global_txn
        if (txn != old_file->getGlobalTxn()) {
            e = list_remove(&old_file->getWal()->txn_list, &txn_wrapper->le);
            list_push_front(&new_file->getWal()->txn_list, &txn_wrapper->le);
            // remove previous header info & revnum
            txn->prev_hdr_bid = BLK_NOT_FOUND;
            txn->prev_revnum = 0;
        } else {
            e = list_next(e);
        }
    }

    spin_unlock(&old_file->getWal()->lock);

    return FDB_RESULT_SUCCESS;
}

fdb_status Wal::commit_Wal(fdb_txn *txn, wal_commit_mark_func *func,
                           ErrLogCallback *log_callback)
{
    int can_overwrite;
    struct wal_item *item, *_item;
    struct list_elem *e1, *e2;
    fdb_kvs_id_t kv_id;
    fdb_status status = FDB_RESULT_SUCCESS;
    size_t shard_num;
    uint64_t _mem_overhead = 0;
    LATENCY_STAT_START();

    e1 = list_begin(txn->items);
    while(e1) {
        item = _get_entry(e1, struct wal_item, list_elem_txn);
        fdb_assert(item->txn_id == txn->txn_id, item->txn_id, txn->txn_id);
        // Grab the WAL key shard lock.
        shard_num = get_checksum((uint8_t*)item->header->key,
                                 item->header->keylen) %
                                 num_shards;
        spin_lock(&key_shards[shard_num].lock);

        if (!(item->flag & WAL_ITEM_COMMITTED)) {
            // get KVS ID
            if (item->flag & WAL_ITEM_MULTI_KV_INS_MODE) {
                buf2kvid(item->header->chunksize, item->header->key, &kv_id);
            } else {
                kv_id = 0;
            }

            item->flag |= WAL_ITEM_COMMITTED;
            if (item->txn != file->getGlobalTxn()) {
                // increase num_flushable if it is transactional update
                num_flushable++;
                // Also since a transaction doc was committed
                // update global WAL stats to reflect this change..
                if (item->action == WAL_ACT_INSERT) {
                    _wal_update_stat(kv_id, _WAL_NEW_SET);
                } else {
                    _wal_update_stat(kv_id, _WAL_NEW_DEL);
                }
            }
            // append commit mark if necessary
            if (func) {
                status = func(txn->handle, item->offset);
                if (status != FDB_RESULT_SUCCESS) {
                    fdb_log(log_callback, status,
                            "Error in appending a commit mark at offset %"
                            _F64 " in "
                            "a database file '%s'", item->offset,
                            file->getFileName());
                    spin_unlock(&key_shards[shard_num].lock);
                    mem_overhead.fetch_sub(_mem_overhead,
                                           std::memory_order_relaxed);
                    return status;
                }
            }
            // remove previously committed item if no snapshots refer to it,
            // move the committed item to the end of the wal_item_header's list
            list_remove(&item->header->items, &item->list_elem);
            list_push_back(&item->header->items, &item->list_elem);
            // now reverse scan among other committed items to de-duplicate..
            e2 = list_prev(&item->list_elem);
            while(e2) {
                _item = _get_entry(e2, struct wal_item, list_elem);
                if (!(_item->flag & WAL_ITEM_COMMITTED)) {
                    break;
                }
                e2 = list_prev(e2);
                spin_lock(&lock); // guard global snaplist from snapshot_open
                can_overwrite = (item->shandle == _item->shandle ||
                                 !_wal_snap_is_immutable(_item->shandle));
                if (!can_overwrite) {
                    item = _item; // new covering item found
                    spin_unlock(&lock);
                    continue;
                }
                // committed but not flush-ready
                // (flush-readied item will be removed by flushing)
                if (!(_item->flag & WAL_ITEM_FLUSH_READY)) {
                    // remove from list & hash
                    list_remove(&item->header->items, &_item->list_elem);
                    if (file->getConfig()->getSeqtreeOpt() == FDB_SEQTREE_USE) {
                        size_t seq_shard_num = _item->seqnum % num_shards;
                        spin_lock(&seq_shards[seq_shard_num].lock);
                        avl_remove(&seq_shards[seq_shard_num]._map,
                                   &_item->avl_seq);
                        spin_unlock(&seq_shards[seq_shard_num].lock);
                    }

                    // mark previous doc region as stale
                    uint32_t stale_len = _item->doc_size;
                    uint64_t stale_offset = _item->offset;
                    if (_item->action == WAL_ACT_INSERT ||
                        _item->action == WAL_ACT_LOGICAL_REMOVE) {
                        // insert or logical remove
                        file->markStale(stale_offset, stale_len);
                    }

                    size--;
                    num_flushable--;
                    if (item->action != WAL_ACT_REMOVE) {
                        datasize.fetch_sub(_item->doc_size,
                                           std::memory_order_relaxed);
                    }
                    // simply reduce the stat count...
                    if (_item->action == WAL_ACT_INSERT) {
                        _wal_update_stat(kv_id, _WAL_DROP_SET);
                    } else {
                        _wal_update_stat(kv_id, _WAL_DROP_DELETE);
                    }
                    _mem_overhead += sizeof(struct wal_item);
                    _wal_free_item(_item, true);
                } else {
                    fdb_log(log_callback, status,
                            "Wal commit called when flush_Wal in progress."
                            "item seqnum %" _F64
                            " keylen %d flags %x action %d"
                            "%s", _item->seqnum, item->header->keylen,
                            _item->flag.load(), _item->action,
                            file->getFileName());
                }
                spin_unlock(&lock);
            }
        }

        // remove from transaction's list
        e1 = list_remove(txn->items, e1);
        spin_unlock(&key_shards[shard_num].lock);
    }
    mem_overhead.fetch_sub(_mem_overhead, std::memory_order_relaxed);

    LATENCY_STAT_END(file, FDB_LATENCY_WAL_COMMIT);
    return status;
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
            // Note: get_old_offset() may return same old_offset on different keys;
            // this is because hbtrie_find_offset() (internally called by
            // get_old_offset()) does not compare entire key string but just prefix
            // only due to performance issue.
            // As a result, this case (keys are different but both old_offset and
            // offset are same) very rarely happens and causes crash.
            // In this case, we need to additionally compare sequence numbers
            // to distinguish those two different items.
            if (aa->seqnum < bb->seqnum) {
                return -1;
            } else if (aa->seqnum > bb->seqnum) {
                return 1;
            } else {
                return 0;
            }
        }
    }
}

void Wal::releaseItem_Wal(size_t shard_num, fdb_kvs_id_t kv_id,
                          struct wal_item *item)
{
    list_remove(&item->header->items, &item->list_elem);
    if (file->getConfig()->getSeqtreeOpt() == FDB_SEQTREE_USE) {
        size_t seq_shard_num;
        seq_shard_num = item->seqnum % num_shards;
        spin_lock(&seq_shards[seq_shard_num].lock);
        avl_remove(&seq_shards[seq_shard_num]._map,
                   &item->avl_seq);
        spin_unlock(&seq_shards[seq_shard_num].lock);
    }

    if (item->action == WAL_ACT_LOGICAL_REMOVE ||
        item->action == WAL_ACT_REMOVE) {
        file->getKvsStatOps()->statUpdateAttr(kv_id, KVS_STAT_WAL_NDELETES, -1);
    }
    file->getKvsStatOps()->statUpdateAttr(kv_id, KVS_STAT_WAL_NDOCS, -1);
    size--;
    num_flushable--;
    if (item->action != WAL_ACT_REMOVE) {
        datasize.fetch_sub(item->doc_size, std::memory_order_relaxed);
    }
    _wal_free_item(item, false);
}

list_elem *Wal::_releaseItems_Wal(size_t shard_num, struct wal_item *item)
{
    fdb_kvs_id_t kv_id;
    uint64_t _mem_overhead = 0;
    struct list_elem *le = &item->list_elem;
    struct wal_item_header *header = item->header;

    // get KVS ID
    if (item->flag & WAL_ITEM_MULTI_KV_INS_MODE) {
        buf2kvid(item->header->chunksize, item->header->key, &kv_id);
    } else {
        kv_id = 0;
    }
    le = list_prev(le);
    if (!_wal_snap_is_immutable(item->shandle)) {
        releaseItem_Wal(shard_num, kv_id, item);
        _mem_overhead += sizeof(struct wal_item);
        item = NULL;
    } else {
        item->flag &= ~WAL_ITEM_FLUSH_READY;
        item->flag |= WAL_ITEM_FLUSHED_OUT;
    }
    // try to cleanup items from prior snapshots as well..
    while (le) {
        struct wal_item *sitem = _get_entry(le, struct wal_item, list_elem);
        if (!(sitem->flag & WAL_ITEM_COMMITTED)) { // uncommitted items will
            le = NULL; // be flushed in the next flush_Wal operation
            break;
        }
        le = list_prev(le);
        if (!_wal_snap_is_immutable(sitem->shandle)) {
            releaseItem_Wal(shard_num, kv_id, sitem);
            _mem_overhead += sizeof(struct wal_item);
        } else {
            item = sitem; // this is the latest and greatest item
            item->flag &= ~WAL_ITEM_FLUSH_READY;
            item->flag |= WAL_ITEM_FLUSHED_OUT;
        }
    }
    if (list_begin(&header->items) == NULL) {
        // wal_item_header becomes empty
        // free header and remove from key map
        avl_remove(&key_shards[shard_num]._map,
                &header->avl_key);
        _mem_overhead = sizeof(wal_item_header) + header->keylen;
        free(header->key);
        free(header);
        le = NULL;
    }
    mem_overhead.fetch_sub(_mem_overhead + sizeof(struct wal_item),
                           std::memory_order_relaxed);
    return le;
}

// Mark all snapshots are flushed to indicate that all items have been
// reflected in the main index and future snapshots must not access these
inline void Wal::_wal_snap_mark_flushed(void)
{
    struct avl_node *a;
    spin_lock(&lock);
    for (a = avl_first(&wal_kvs_snap_tree); a; a = avl_next(a)) {
        struct wal_kvs_snaps *kvs_snapshots = _get_entry(a, struct wal_kvs_snaps,
                                                     avl_id);
        for (struct list_elem *e = list_end(&kvs_snapshots->snap_list);
             e; e = list_prev(e)) {
            struct snap_handle *shandle = _get_entry(e, struct snap_handle,
                                                     snaplist_elem);
            if (shandle->is_flushed) {
                break; // all previous snapshots are already flushed before
            }
            shandle->is_flushed = true;
        }
    }
    spin_unlock(&lock);
}

#define WAL_SORTED_FLUSH ((void *)1) // stored in aux if avl tree is used

inline bool Wal::_wal_are_items_sorted(union wal_flush_items *flush_items)
{
    return (flush_items->tree.aux == WAL_SORTED_FLUSH);
}

fdb_status Wal::releaseFlushedItems_Wal(union wal_flush_items *flush_items)
{
    struct wal_item *item;
    size_t shard_num;
    LATENCY_STAT_START();

    _wal_snap_mark_flushed(); // Read-write barrier: items are in trie

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
                                     item->header->keylen)
                                     % num_shards;
            spin_lock(&key_shards[shard_num].lock);

            _releaseItems_Wal(shard_num, item);

            spin_unlock(&key_shards[shard_num].lock);
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
                                     item->header->keylen)
                                     % num_shards;
            spin_lock(&key_shards[shard_num].lock);
            _releaseItems_Wal(shard_num, item);
            spin_unlock(&key_shards[shard_num].lock);
        }
    }

    LATENCY_STAT_END(file, FDB_LATENCY_WAL_RELEASE);
    return FDB_RESULT_SUCCESS;
}

inline fdb_status Wal::_wal_do_flush(struct wal_item *item,
                                     wal_flush_func *flush_func,
                                     void *dbhandle,
                                     struct avl_tree *stale_seqnum_list,
                                     struct avl_tree *kvs_delta_stats)
{
    // check weather this item is updated after insertion into tree
    if (item->flag & WAL_ITEM_FLUSH_READY) {
        fdb_status fs = flush_func(dbhandle, item, stale_seqnum_list, kvs_delta_stats);
        if (fs != FDB_RESULT_SUCCESS) {
            FdbKvsHandle *handle = reinterpret_cast<FdbKvsHandle *>(dbhandle);
            fdb_log(&handle->log_callback, fs,
                    "Failed to flush WAL item (key '%s') into a database file '%s'",
                    (const char *) item->header->key,
                    handle->file->getFileName());
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
    FdbKvsHandle *handle = reinterpret_cast<FdbKvsHandle *>(voidhandle);

    root_info->orig_id_root = handle->trie->getRootBid();
    if (handle->config.seqtree_opt == FDB_SEQTREE_USE) {
        if (handle->kvs) {
            root_info->orig_seq_root = handle->seqtrie->getRootBid();
        } else {
            root_info->orig_seq_root = handle->seqtree->getRootBid();
        }
    }
    if (handle->staletree) {
        root_info->orig_stale_root = handle->staletree->getRootBid();
    }
}

INLINE void _wal_restore_root_info(void *voidhandle,
                                   struct fdb_root_info *root_info)
{
    FdbKvsHandle *handle = reinterpret_cast<FdbKvsHandle *>(voidhandle);

    handle->trie->setRootBid(root_info->orig_id_root);
    if (handle->config.seqtree_opt == FDB_SEQTREE_USE) {
        if (handle->kvs) {
            handle->seqtrie->setRootBid(root_info->orig_seq_root);
        } else {
            handle->seqtree->setRootBid(root_info->orig_seq_root);
        }
    }
    if (handle->staletree) {
        handle->staletree->setRootBid(root_info->orig_stale_root);
    }
}

fdb_status Wal::_flush_Wal(void *dbhandle,
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
    LATENCY_STAT_START();
    bool do_sort = !file->isFullyResident();

    if (do_sort) {
        avl_init(tree, WAL_SORTED_FLUSH);
    } else {
        list_init(list_head);
    }

    memset(&root_info, 0xff, sizeof(root_info));
    _wal_backup_root_info(dbhandle, &root_info);

    for (; i < num_shards; ++i) {
        spin_lock(&key_shards[i].lock);
        a = avl_first(&key_shards[i]._map);
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
                // Don't re-flush flushed items, try to free them up instead
                if (item->flag & WAL_ITEM_FLUSHED_OUT) {
                    _releaseItems_Wal(i, item);
                    break; // most recent item is already reflected in trie
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
                        spin_unlock(&key_shards[i].lock);
                        item->old_offset = get_old_offset(dbhandle, item);
                        spin_lock(&key_shards[i].lock);
                        if (item->old_offset == 0 && // doc not in main index
                            item->action == WAL_ACT_REMOVE) {// insert & delete
                            item->old_offset = BLK_NOT_FOUND;
                        }
                        if (do_sort) {
                            avl_insert(tree, &item->avl_flush, _wal_flush_cmp);
                        } else {
                            list_push_back(list_head, &item->list_elem_flush);
                        }
                        break; // only pick one item per key
                    }
                }
                ee = ee_prev;
            }
            a = a_next;
        }
        spin_unlock(&key_shards[i].lock);
    }

    file->setIoInprog(); // MB-16622:prevent parallel writes by flusher
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
            if (item->old_offset == BLK_NOT_FOUND && // doc not in main index
                item->action == WAL_ACT_REMOVE) {// insert & immediate delete
                continue; // need not flush this item into main index..
            } // item exists solely for in-memory snapshots
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
            if (item->old_offset == BLK_NOT_FOUND && // doc not in main index
                item->action == WAL_ACT_REMOVE) {// insert & immediate delete
                continue; // need not flush this item into main index..
            } // item exists solely for in-memory snapshots
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

    file->clearIoInprog();
    LATENCY_STAT_END(file, FDB_LATENCY_WAL_FLUSH);
    return fs;
}

fdb_status Wal::flush_Wal(void *dbhandle,
                          wal_flush_func *flush_func,
                          wal_get_old_offset_func *get_old_offset,
                          wal_flush_seq_purge_func *seq_purge_func,
                          wal_flush_kvs_delta_stats_func *delta_stats_func,
                          union wal_flush_items *flush_items)
{
    return _flush_Wal(dbhandle, flush_func, get_old_offset,
                      seq_purge_func, delta_stats_func,
                      flush_items, false);
}

fdb_status Wal::flushByCompactor_Wal(void *dbhandle,
                                     wal_flush_func *flush_func,
                                     wal_get_old_offset_func *get_old_offset,
                                     wal_flush_seq_purge_func *seq_purge_func,
                                     wal_flush_kvs_delta_stats_func *delta_stats_func,
                                     union wal_flush_items *flush_items)
{
    return _flush_Wal(dbhandle, flush_func, get_old_offset,
                      seq_purge_func, delta_stats_func,
                      flush_items, true);
}

fdb_status Wal::snapshotClone_Wal(struct snap_handle *shandle_in,
                              struct snap_handle **shandle_out,
                              fdb_seqnum_t seqnum)
{
    if (seqnum == FDB_SNAPSHOT_INMEM ||
        shandle_in->seqnum == seqnum) {
        // Bump up ref count on all shared snapshots to prevent deletion!
        struct snap_handle *shandle = shandle_in;
        for (int i = 0;; ++i) {
            shandle->ref_cnt_kvs++;
            if (i < shandle_in->num_prev_snaps) {
                struct list_elem *snap_elem = list_prev(&shandle->snaplist_elem);
                shandle = _get_entry(snap_elem, struct snap_handle, snaplist_elem);
            } else {
                break;
            }
        }
        *shandle_out = shandle_in;
        return FDB_RESULT_SUCCESS;
    }
    return FDB_RESULT_INVALID_ARGS;
}

fdb_status Wal::getSnapStats_Wal(struct snap_handle *shandle, KvsStat *stat)
{
    *stat = shandle->stat;
    return FDB_RESULT_SUCCESS;
}

fdb_status Wal::snapshotOpenPersisted_Wal(fdb_seqnum_t seqnum,
                                          _fdb_key_cmp_info *key_cmp_info,
                                          fdb_txn *txn,
                                          struct snap_handle **shandle)
{
    struct snap_handle *_shandle;
    fdb_kvs_id_t kv_id;
    fdb_assert(seqnum != FDB_SNAPSHOT_INMEM, seqnum, key_cmp_info->kvs);
    if (!key_cmp_info->kvs) {
        kv_id = 0;
    } else {
        kv_id = key_cmp_info->kvs->getKvsId();
    }
    _shandle = _wal_snapshot_create(kv_id, 0, 0, key_cmp_info, NULL);
    if (!_shandle) { // LCOV_EXCL_START
        return FDB_RESULT_ALLOC_FAIL;
    } // LCOV_EXCL_STOP
    spin_lock(&lock);
    _wal_snapshot_init(_shandle, txn, seqnum);
    spin_unlock(&lock);
    *shandle = _shandle;
    return FDB_RESULT_SUCCESS;
}

fdb_status Wal::snapInsert_Wal(struct snap_handle *shandle, fdb_doc *doc,
                           uint64_t offset)
{
    struct wal_item query;
    struct wal_item_header query_hdr;
    struct wal_item *item;
    struct avl_node *node;
    query_hdr.key = doc->key;
    query_hdr.keylen = doc->keylen;
    query.header = &query_hdr;
    node = avl_search(&shandle->key_tree, &query.avl_keysnap, _snap_cmp_bykey);

    if (!node) {
        item = (struct wal_item *) calloc(1, sizeof(struct wal_item));
        item->header = (struct wal_item_header *) malloc(
                                  sizeof(struct wal_item_header));
        item->header->key = doc->key;
        item->header->keylen = doc->keylen;
        item->seqnum = doc->seqnum;
        if (doc->deleted) {
            if (!offset) { // deleted item can never be at offset 0
                item->action = WAL_ACT_REMOVE; // must be a purged item
            } else {
                item->action = WAL_ACT_LOGICAL_REMOVE;
            }
        } else {
            item->action = WAL_ACT_INSERT;
        }
        item->offset = offset;
        avl_insert(&shandle->key_tree, &item->avl_keysnap, _snap_cmp_bykey);
        avl_insert(&shandle->seq_tree, &item->avl_seq, _wal_cmp_byseq);

        // Note: same logic in commit_Wal
        shandle->stat.wal_ndocs++;
        if (doc->deleted) {
            shandle->stat.wal_ndeletes++;
        }
        item->shandle = shandle;
    } else {
        // replace existing node with new values so there are no duplicates
        item = _get_entry(node, struct wal_item, avl_keysnap);
        free(item->header->key);
        item->header->key = doc->key;
        item->header->keylen = doc->keylen;
        if (item->seqnum != doc->seqnum) { // Re-index duplicate into seqtree
            item->seqnum = doc->seqnum;
            avl_remove(&shandle->seq_tree, &item->avl_seq);
            avl_insert(&shandle->seq_tree, &item->avl_seq, _wal_cmp_byseq);
        }

        // Note: same logic in commit_Wal
        if (item->action == WAL_ACT_INSERT &&
            doc->deleted) {
            shandle->stat.wal_ndeletes++;
        } else if (item->action == WAL_ACT_LOGICAL_REMOVE &&
                   !doc->deleted) {
            shandle->stat.wal_ndeletes--;
        }

        item->action = doc->deleted ? WAL_ACT_LOGICAL_REMOVE : WAL_ACT_INSERT;
        item->offset = offset;
    }
    return FDB_RESULT_SUCCESS;
}

fdb_status Wal::copy2Snapshot_Wal(struct snap_handle *shandle,
                                  bool is_multi_kv)
{
    struct list_elem *ee;
    struct avl_node *a;
    struct wal_item *item;
    struct wal_item_header *header;
    fdb_kvs_id_t kv_id = 0;
    fdb_doc doc;
    size_t i = 0;

    shandle->stat.wal_ndocs = 0; // WAL copy will populate
    shandle->stat.wal_ndeletes = 0; // these 2 stats

    // Get the list of active transactions now
    for (; i < num_shards; ++i) {
        spin_lock(&key_shards[i].lock);
        a = avl_first(&key_shards[i]._map);
        while (a) {
            header = _get_entry(a, struct wal_item_header, avl_key);
            if (is_multi_kv) {
                buf2kvid(header->chunksize, header->key, &kv_id);
                if (kv_id != shandle->id) {
                    a = avl_next(a);
                    continue;
                }
            }
            ee = list_begin(&header->items);
            while (ee) {
                uint64_t offset;
                item = _get_entry(ee, struct wal_item, list_elem);
                // Skip any uncommitted item, if not part of either global or
                // the current transaction
                if (!(item->flag & WAL_ITEM_COMMITTED) &&
                        item->txn != file->getGlobalTxn() &&
                        item->txn != shandle->snap_txn) {
                    ee = list_next(ee);
                    continue;
                }
                // Skip the partially committed items too.
                if (_wal_item_partially_committed(shandle->global_txn,
                                                  &shandle->active_txn_list,
                                                  shandle->snap_txn, item)) {
                    ee = list_next(ee);
                    continue;
                }

                if (item->seqnum > shandle->seqnum) {
                    ee = list_next(ee);
                    continue;
                }

                doc.keylen = item->header->keylen;
                doc.key = malloc(doc.keylen); // (freed in fdb_snapshot_close)
                memcpy(doc.key, item->header->key, doc.keylen);
                doc.seqnum = item->seqnum;
                doc.deleted = (item->action == WAL_ACT_LOGICAL_REMOVE ||
                               item->action == WAL_ACT_REMOVE);
                if (item->action == WAL_ACT_REMOVE) {
                    offset = 0;
                } else {
                    offset = item->offset;
                }

                snapInsert_Wal(shandle, &doc, offset);
                break; // We just require a single latest copy in the snapshot
            }
            a = avl_next(a);
        }
        spin_unlock(&key_shards[i].lock);
    }
    return FDB_RESULT_SUCCESS;
}

fdb_status Wal::_snapFind_Wal(struct snap_handle *shandle, fdb_doc *doc,
                              uint64_t *offset)
{
    struct wal_item query, *item;
    struct avl_node *node;
    if (doc->seqnum == SEQNUM_NOT_USED || (doc->key && doc->keylen > 0)) {
        if (!shandle->key_tree.root) {
            return FDB_RESULT_KEY_NOT_FOUND;
        }
        struct wal_item_header query_hdr;
        query.header = &query_hdr;
        // search by key
        query_hdr.key = doc->key;
        query_hdr.keylen = doc->keylen;
        node = avl_search(&shandle->key_tree, &query.avl_keysnap,
                          _snap_cmp_bykey);
        if (!node) {
            return FDB_RESULT_KEY_NOT_FOUND;
        } else {
            item = _get_entry(node, struct wal_item, avl_keysnap);
            *offset = item->offset;
            if (item->action == WAL_ACT_INSERT) {
                doc->deleted = false;
            } else {
                doc->deleted = true;
                if (item->action == WAL_ACT_REMOVE) {
                    *offset = BLK_NOT_FOUND;
                }
            }
            doc->seqnum = item->seqnum;
            return FDB_RESULT_SUCCESS;
        }
    } else if (shandle->seq_tree.root) {
        // search by sequence number
        query.seqnum = doc->seqnum;
        node = avl_search(&shandle->seq_tree, &query.avl_seq, _wal_cmp_byseq);
        if (!node) {
            return FDB_RESULT_KEY_NOT_FOUND;
        } else {
            item = _get_entry(node, struct wal_item, avl_seq);
            *offset = item->offset;
            if (item->action == WAL_ACT_INSERT) {
                doc->deleted = false;
            } else {
                doc->deleted = true;
                if (item->action == WAL_ACT_REMOVE) {
                    *offset = BLK_NOT_FOUND;
                }
            }
            return FDB_RESULT_SUCCESS;
        }
    }
    return FDB_RESULT_KEY_NOT_FOUND;
}

void Wal::_snapshotClose_Wal(struct snap_handle *shandle) {
    struct avl_node *a, *nexta;
    for (a = avl_first(&shandle->key_tree); a; a = nexta) {
        struct wal_item *item = _get_entry(a, struct wal_item, avl_keysnap);
        nexta = avl_next(a);
        avl_remove(&shandle->key_tree, &item->avl_keysnap);
        free(item->header->key);
        free(item->header);
        free(item);
    }
    for (struct list_elem *e = list_begin(&shandle->active_txn_list); e;) {
        struct list_elem *e_next = list_next(e);
        struct wal_txn_wrapper *active_txn = _get_entry(e,
                                            struct wal_txn_wrapper, le);
        free(active_txn);
        e = e_next;
    }
    free(shandle);
}

fdb_status Wal::snapshotClose_Wal(struct snap_handle *shandle)
{
    fdb_status fs = FDB_RESULT_SUCCESS;
    if (!shandle->is_persisted_snapshot &&
        shandle->snap_tag_idx) { // the KVS did have items in WAL..
        spin_lock(&lock);
        struct snap_handle *_shandle = shandle;
        DBG("%s Close InMem Snapshot %" _F64 " - %" _F64 " taken at %"
                _F64 " for kv id %" _F64 " prev_snaps=%d\n",
                file->getFileName(), _shandle->snap_stop_idx,
                _shandle->snap_tag_idx, _shandle->seqnum,
                _shandle->kvs_snapshots->id,
                _shandle->num_prev_snaps);
        // Decrement ref counts on all the previous shared snapshots..
        int num_prev_snaps = shandle->num_prev_snaps;
        for (int idx = 0; idx < num_prev_snaps; ++idx) {
            struct list_elem *snap_elem = list_prev(&_shandle->snaplist_elem);
            _shandle = _get_entry(snap_elem, struct snap_handle, snaplist_elem);
            fdb_assert(_shandle->ref_cnt_kvs, _shandle->ref_cnt_kvs, 1);
            _shandle->ref_cnt_kvs--;
        }
        // Decrement ref count on current handle so it may be removed
        fdb_assert(shandle->ref_cnt_kvs, shandle->ref_cnt_kvs, 1);
        shandle->ref_cnt_kvs--;
        spin_unlock(&lock);
        return fs;
    } // ELSE persisted or un-shared snapshot ...
    if (!(--shandle->ref_cnt_kvs)) {
        _snapshotClose_Wal(shandle);
    }
    return fs;
}

WalItr::WalItr(FileMgr *file,
               struct snap_handle *shandle,
               bool by_key)
{
    // If key_cmp_info is non-null it implies key-range iteration
    if (by_key) {
        map_shards = file->getWal()->key_shards;
        avl_init(&merge_tree, &shandle->cmp_info);
        this->by_key = true;
    } else {
        // Otherwise wal iteration is requested over sequence range
        fdb_assert(file->getConfig()->getSeqtreeOpt() == FDB_SEQTREE_USE,
                   file->getConfig()->getSeqtreeOpt(), FDB_SEQTREE_USE);
        map_shards = file->getWal()->seq_shards;
        avl_init(&merge_tree, NULL);
        this->by_key = false;
    }

    if (shandle->cmp_info.kvs) {
        multi_kvs = true;
    } else {
        multi_kvs = false;
    }
    cursor_pos = NULL;
    item_prev = NULL;

    num_shards = file->getWal()->num_shards;
    if (!shandle->is_persisted_snapshot) {
        cursors = (struct wal_cursor *)calloc(num_shards,
                           sizeof(struct wal_cursor));
    } else {
        cursors = NULL;
    }
    this->shandle = shandle;
    _wal = file->getWal();
    direction = FDB_ITR_DIR_NONE;
}

INLINE bool _wal_is_my_kvs(struct wal_item_header *header,
                           struct snap_handle *shandle)
{
    if (shandle->cmp_info.kvs) {
        fdb_kvs_id_t kv_id;
        buf2kvid(header->chunksize, header->key, &kv_id);
        if (kv_id != shandle->id) {
            return false;
        }
    }
    return true;
}

struct wal_item* WalItr::_searchGreaterByKey_WalItr(struct wal_item *query)
{
    struct avl_node *a = NULL;
    struct wal_cursor *cursor;

    // search is a stateless operation, so re-initialize shard's merge-sort tree
    avl_init(&merge_tree, (void*)&shandle->cmp_info);
    for (size_t i = 0; i < num_shards; ++i) {
        struct wal_item *item = NULL;
        spin_lock(&map_shards[i].lock);
        if (query) {
            avl_set_aux(&map_shards[i]._map,
                        (void*)&shandle->cmp_info);
            a = avl_search_greater(&map_shards[i]._map,
                                   &query->header->avl_key,
                                   _wal_cmp_bykey);
        } else {
            a = avl_first(&map_shards[i]._map);
        }
        if (a) {
            do {
                struct wal_item_header *header;
                header = _get_entry(a, struct wal_item_header, avl_key);
                if (!_wal_is_my_kvs(header, shandle)) {
                    item = NULL;
                    break;
                }
                item = Wal::_wal_get_snap_item(header, shandle);
            } while (!item && (a = avl_next(a)));
        }
        spin_unlock(&map_shards[i].lock);
        if (item) {
            cursors[i].item = item;
            // re-insert into the merge-sorted AVL tree across all shards
            avl_insert(&merge_tree, &cursors[i].avl_merge,
                       _merge_cmp_bykey);
        } else {
            cursors[i].item = NULL;
        }
    } // done for all WAL shards

    cursor_pos = avl_first(&merge_tree);

    if (!cursor_pos) {
        item_prev = NULL;
        return NULL;
    }
    cursor = _get_entry(cursor_pos, struct wal_cursor, avl_merge);
    // save the current cursor position for reverse iteration
    item_prev = cursor->item;
    return cursor->item;
}

struct wal_item * WalItr::_searchGreaterBySeq_WalItr(struct wal_item *query)
{
    struct avl_node *a = NULL;
    struct wal_cursor *cursor;

    // search is a stateless operation, so re-initialize shard's merge-sort tree
    avl_init(&merge_tree, &shandle->cmp_info);
    for (size_t i = 0; i < num_shards; ++i) {
        struct wal_item *item = NULL, *_item;
        if (query) {
            spin_lock(&map_shards[i].lock);
            a = avl_search_greater(&map_shards[i]._map, &query->avl_seq,
                                   _wal_cmp_byseq);
        } else {
            a = avl_first(&map_shards[i]._map);
        }
        while (a) {
            item = _get_entry(a, struct wal_item, avl_seq);
            if (!_wal_is_my_kvs(item->header, shandle)) {
                item = NULL;
                break;
            }
            _item = Wal::_wal_get_snap_item(item->header, shandle);
            if (item == _item) {
                break;
            } else {
                item = NULL;
            }
            a = avl_next(a);
        }
        spin_unlock(&map_shards[i].lock);
        if (item) {
            cursors[i].item = item;
            // re-insert into the merge-sorted AVL tree across all shards
            avl_insert(&merge_tree, &cursors[i].avl_merge,
                       _merge_cmp_byseq);
        } else {
            cursors[i].item = NULL;
        }
    } // done for all WAL shards

    cursor_pos = avl_first(&merge_tree);
    if (!cursor_pos) {
        return NULL;
    }
    cursor = _get_entry(cursor_pos, struct wal_cursor, avl_merge);
    // save the current cursor position for reverse iteration
    item_prev = cursor->item;
    return cursor->item;
}

struct wal_item* WalItr::searchGreater_WalItr(struct wal_item *query)
{
    if (shandle->is_persisted_snapshot) {
        struct avl_node *a;
        if (by_key) {
            a = avl_search_greater(&shandle->key_tree,
                                   &query->avl_keysnap,
                                   _snap_cmp_bykey);
            cursor_pos = a;
            return a ? _get_entry(a, struct wal_item, avl_keysnap) : NULL;
        } else {
            a = avl_search_greater(&shandle->seq_tree,
                                   &query->avl_seq,
                                   _wal_cmp_byseq);
            cursor_pos = a;
            return a ? _get_entry(a, struct wal_item, avl_seq) : NULL;
        }
    }
    if (shandle->snap_tag_idx) {
        direction = FDB_ITR_FORWARD;
        if (by_key) {
            return _searchGreaterByKey_WalItr(query);
        } else {
            return _searchGreaterBySeq_WalItr(query);
        }
    } // else no items in WAL in snapshot..
    return NULL;
}

struct wal_item* WalItr::_searchSmallerByKey_WalItr(struct wal_item *query)
{
    struct avl_node *a = NULL;
    struct wal_cursor *cursor;

    // search is a stateless operation, so re-initialize shard's merge-sort tree
    avl_init(&merge_tree, &shandle->cmp_info);
    for (size_t i = 0; i < num_shards; ++i) {
        struct wal_item *item = NULL;
        spin_lock(&map_shards[i].lock);
        if (query) {
            avl_set_aux(&map_shards[i]._map,
                        (void*)&shandle->cmp_info);
            a = avl_search_smaller(&map_shards[i]._map,
                                   &query->header->avl_key,
                                   _wal_cmp_bykey);
        } else { // no item implies search to last key
            a = avl_last(&map_shards[i]._map);
        }
        if (a) {
            do {
                struct wal_item_header *header;
                header = _get_entry(a, struct wal_item_header, avl_key);
                if (!_wal_is_my_kvs(header, shandle)) {
                    item = NULL;
                    break;
                }
                item = Wal::_wal_get_snap_item(header, shandle);
            } while (!item && (a = avl_prev(a)));
        }
        spin_unlock(&map_shards[i].lock);
        if (item) {
            cursors[i].item = item;
            // re-insert into the merge-sorted AVL tree across all shards
            avl_insert(&merge_tree, &cursors[i].avl_merge,
                       _merge_cmp_bykey);
        } else {
            cursors[i].item = NULL;
        }
    } // done for all WAL shards

    cursor_pos = avl_last(&merge_tree);
    if (!cursor_pos) {
        item_prev = NULL;
        return NULL;
    }

    cursor = _get_entry(cursor_pos, struct wal_cursor, avl_merge);
    // save the current cursor position for reverse iteration
    item_prev = cursor->item;
    return cursor->item;
}

struct wal_item * WalItr::_searchSmallerBySeq_WalItr(struct wal_item *query)
{
    struct avl_node *a = NULL;
    struct wal_cursor *cursor;

    // search is a stateless operation, so re-initialize shard's merge-sort tree
    avl_init(&merge_tree, &shandle->cmp_info);
    for (size_t i = 0; i < num_shards; ++i) {
        struct wal_item *item = NULL, *_item;
        spin_lock(&map_shards[i].lock);
        if (query) {
            a = avl_search_smaller(&map_shards[i]._map,
                                   &query->avl_seq, _wal_cmp_byseq);
        } else {
            a = avl_last(&map_shards[i]._map);
        }
        while (a) {
            item = _get_entry(a, struct wal_item, avl_seq);

            if (!_wal_is_my_kvs(item->header, shandle)) {
                item = NULL;
                break;
            }
            _item = Wal::_wal_get_snap_item(item->header, shandle);
            if (item == _item) {
                break;
            } else {
                item = NULL;
            }
            a = avl_prev(a);
        }
        spin_unlock(&map_shards[i].lock);
        if (item) {
            cursors[i].item = item;
            // re-insert into the merge-sorted AVL tree across all shards
            avl_insert(&merge_tree, &cursors[i].avl_merge,
                       _merge_cmp_byseq);
        } else {
            cursors[i].item = NULL;
        }
    } // done for all WAL shards

    cursor_pos = avl_last(&merge_tree);
    if (!cursor_pos) {
        item_prev = NULL;
        return NULL;
    }
    cursor = _get_entry(cursor_pos, struct wal_cursor, avl_merge);
    // save the current cursor position for reverse iteration
    item_prev = cursor->item;
    return cursor->item;
}

struct wal_item* WalItr::searchSmaller_WalItr(struct wal_item *query)
{
    if (shandle->is_persisted_snapshot) {
        struct avl_node *a;
        if (by_key) {
            a = avl_search_smaller(&shandle->key_tree,
                                   &query->avl_keysnap,
                                   _snap_cmp_bykey);
            cursor_pos = a;
            return a ? _get_entry(a, struct wal_item, avl_keysnap) : NULL;
        } else {
            a = avl_search_smaller(&shandle->seq_tree,
                                   &query->avl_seq,
                                   _wal_cmp_byseq);
            cursor_pos = a;
            return a ? _get_entry(a, struct wal_item, avl_seq) : NULL;
        }
    }

    if (shandle->snap_tag_idx) {
        direction = FDB_ITR_REVERSE;
        if (!by_key) {
            return _searchSmallerBySeq_WalItr(query);
        } else {
            return _searchSmallerByKey_WalItr(query);
        }
    } // else no items in WAL in for this snapshot..
    return NULL;
}

struct wal_item * WalItr::_nextByKey_WalItr(void)
{
    struct wal_cursor *cursor = _get_entry(cursor_pos,
                                           struct wal_cursor, avl_merge);
    struct wal_cursor cur_item = *cursor; // save cur item for merge sort
    struct wal_item_header *header = cur_item.item->header;
    size_t cur_shard_num = cursor - cursors;
    struct wal_item *item = NULL;

    item_prev = cursor->item; // save for direction change

    spin_lock(&map_shards[cur_shard_num].lock);
    avl_set_aux(&map_shards[cur_shard_num]._map,
            (void*)&shandle->cmp_info);
    struct avl_node *a = avl_next(&header->avl_key);
    if (a) {
        do {
            header = _get_entry(a, struct wal_item_header, avl_key);
            if (!_wal_is_my_kvs(header, shandle)) {
                item = NULL;
                break;
            }
            item = Wal::_wal_get_snap_item(header, shandle);
        } while (!item && (a = avl_next(a)));
    }
    spin_unlock(&map_shards[cur_shard_num].lock);
    avl_remove(&merge_tree, &cursor->avl_merge);
    if (item) {
        // re-insert this merge sorted item back into merge-sort tree..
        cursors[cur_shard_num].item = item;
        avl_insert(&merge_tree,
                   &cursors[cur_shard_num].avl_merge,
                   _merge_cmp_bykey);
    } else {
        cursors[cur_shard_num].item = NULL;
    }

    cursor_pos = avl_search_greater(&merge_tree,
                                             &cur_item.avl_merge,
                                             _merge_cmp_bykey);
    if (!cursor_pos) {
        return NULL;
    }
    cursor = _get_entry(cursor_pos, struct wal_cursor, avl_merge);
    return cursor->item;
}

struct wal_item * WalItr::_nextBySeq_WalItr(void)
{
    struct wal_cursor *cursor = _get_entry(cursor_pos,
                                           struct wal_cursor, avl_merge);
    struct wal_cursor cur_item = *cursor; // save cur item for merge sort
    size_t cur_shard_num = cursor - cursors;
    struct wal_item *item = NULL, *_item;

    item_prev = cursor->item; // save for direction change

    spin_lock(&map_shards[cur_shard_num].lock);
    struct avl_node *a = avl_next(&cur_item.item->avl_seq);
    while (a) {
        item = _get_entry(a, struct wal_item, avl_seq);
        if (!_wal_is_my_kvs(item->header, shandle)) {
            item = NULL;
            break;
        }
        _item = Wal::_wal_get_snap_item(item->header, shandle);
        if (item == _item) {
            break;
        } else {
            item = NULL;
        }
        a = avl_next(a);
    }
    spin_unlock(&map_shards[cur_shard_num].lock);
    avl_remove(&merge_tree, &cursor->avl_merge);
    if (item) {
        cursors[cur_shard_num].item = item;
        // re-insert this merge sorted item back into merge-sort tree..
        avl_insert(&merge_tree,
                   &cursors[cur_shard_num].avl_merge,
                   _merge_cmp_byseq);
    } else {
        cursors[cur_shard_num].item = NULL;
    }

    cursor_pos = avl_search_greater(&merge_tree,
                                             &cur_item.avl_merge,
                                             _merge_cmp_byseq);
    if (!cursor_pos) {
        return NULL;
    }
    cursor = _get_entry(cursor_pos, struct wal_cursor, avl_merge);
    return cursor->item;
}

struct wal_item* WalItr::next_WalItr(void)
{
    struct wal_item *result = NULL;
    if (shandle->is_persisted_snapshot) {
        cursor_pos = avl_next(cursor_pos);
        if (by_key) {
            return cursor_pos ? _get_entry(cursor_pos,
                                                struct wal_item, avl_keysnap) : NULL;
        } else {
            return cursor_pos ? _get_entry(cursor_pos,
                                                struct wal_item, avl_seq) : NULL;
        }
    }

    if (!shandle->snap_tag_idx) { // no items in WAL in snapshot..
        return NULL;
    }
    if (direction == FDB_ITR_FORWARD) {
        if (!cursor_pos) {
            return result;
        }
        if (by_key) {
            result = _nextByKey_WalItr();
        } else {
            result = _nextBySeq_WalItr();
        }
    } else { // change of direction involves searching across all shards..
        if (!item_prev) {
            return result;
        }
        if (by_key) {
            result = _searchGreaterByKey_WalItr(item_prev);
        } else {
            result = _searchGreaterBySeq_WalItr(item_prev);
        }
    }
    direction = FDB_ITR_FORWARD;
    return result;
}

struct wal_item *WalItr::_prevByKey_WalItr(void)
{

    struct wal_cursor *cursor = _get_entry(cursor_pos,
                                           struct wal_cursor, avl_merge);
    struct wal_cursor cur_item = *cursor; // save cur item for merge sort
    struct wal_item_header *header = cur_item.item->header;
    size_t cur_shard_num = cursor - cursors;
    struct wal_item *item = NULL;

    item_prev = cursor->item; // save for direction change

    spin_lock(&map_shards[cur_shard_num].lock);
    avl_set_aux(&map_shards[cur_shard_num]._map,
                (void*)&shandle->cmp_info);
    struct avl_node *a = avl_prev(&header->avl_key);
    if (a) {
        do {
            header = _get_entry(a, struct wal_item_header, avl_key);
            if (!_wal_is_my_kvs(header, shandle)) {
                item = NULL;
                break;
            }
            item = Wal::_wal_get_snap_item(header, shandle);
        } while (!item && (a = avl_prev(a)));
    }
    spin_unlock(&map_shards[cur_shard_num].lock);
    avl_remove(&merge_tree, &cursor->avl_merge);
    if (item) {
        // re-insert this merge sorted item back into merge-sort tree..
        cursors[cur_shard_num].item = item;
        avl_insert(&merge_tree,
                   &cursors[cur_shard_num].avl_merge,
                   _merge_cmp_bykey);
    } else {
        cursors[cur_shard_num].item = NULL;
    }

    cursor_pos = avl_search_smaller(&merge_tree,
                                             &cur_item.avl_merge,
                                             _merge_cmp_bykey);
    if (!cursor_pos) {
        return NULL;
    }
    cursor = _get_entry(cursor_pos, struct wal_cursor, avl_merge);
    return cursor->item;
}

struct wal_item * WalItr::_prevBySeq_WalItr(void)
{
    struct wal_cursor *cursor = _get_entry(cursor_pos,
                                           struct wal_cursor, avl_merge);
    struct wal_cursor cur_item = *cursor; // save cur item for merge sort
    size_t cur_shard_num = cursor - cursors;
    struct wal_item *item = NULL, *_item;

    item_prev = cursor->item; // save for direction change

    spin_lock(&map_shards[cur_shard_num].lock);
    struct avl_node *a = avl_prev(&cur_item.item->avl_seq);
    while (a) {
        item = _get_entry(a, struct wal_item, avl_seq);
        if (!_wal_is_my_kvs(item->header, shandle)) {
            item = NULL;
            break;
        }
        _item = Wal::_wal_get_snap_item(item->header, shandle);
        if (item == _item) {
            break;
        } else {
            item = NULL;
        }
        a = avl_prev(a);
    }
    spin_unlock(&map_shards[cur_shard_num].lock);
    avl_remove(&merge_tree, &cursor->avl_merge);
    if (item) {
        cursors[cur_shard_num].item = item;
        // re-insert this merge sorted item back into merge-sort tree..
        avl_insert(&merge_tree,
                &cursors[cur_shard_num].avl_merge,
                _merge_cmp_byseq);
    } else {
        cursors[cur_shard_num].item = NULL;
    }

    cursor_pos = avl_search_smaller(&merge_tree,
            &cur_item.avl_merge,
            _merge_cmp_byseq);
    if (!cursor_pos) {
        return NULL;
    }
    cursor = _get_entry(cursor_pos, struct wal_cursor, avl_merge);
    return cursor->item;
}

struct wal_item* WalItr::prev_WalItr(void)
{
    struct wal_item *result = NULL;
    if (shandle->is_persisted_snapshot) {
        cursor_pos = avl_prev(cursor_pos);
        if (by_key) {
            return cursor_pos ? _get_entry(cursor_pos,
                    struct wal_item, avl_keysnap) : NULL;
        } else {
            return cursor_pos ? _get_entry(cursor_pos,
                    struct wal_item, avl_seq) : NULL;
        }
    }

    if (!shandle->snap_tag_idx) { // no items in WAL in snapshot..
        return NULL;
    }
    if (direction == FDB_ITR_REVERSE) {
        if (!cursor_pos) {
            return result;
        }
        if (by_key) {
            result = _prevByKey_WalItr();
        } else {
            result = _prevBySeq_WalItr();
        }
    } else { // change of direction involves searching across all shards..
        if (!item_prev) {
            return result;
        }
        if (by_key) {
            result = _searchSmallerByKey_WalItr(item_prev);
        } else {
            result = _searchSmallerBySeq_WalItr(item_prev);
        }
    }
    direction = FDB_ITR_REVERSE;
    return result;
}

struct wal_item * WalItr::_firstByKey_WalItr(void)
{
    struct wal_item_header dummy_key;
    struct wal_item dummy_item;
    fdb_kvs_id_t kv_id = shandle->id;
    dummy_key.key = &kv_id;
    dummy_key.keylen = sizeof(fdb_kvs_id_t);
    dummy_item.header = &dummy_key;
    if (multi_kvs) {
        return _searchGreaterByKey_WalItr(&dummy_item);
    } // else we are in single kv instance mode
    return _searchGreaterByKey_WalItr(NULL);
}

struct wal_item* WalItr::_firstBySeq_WalItr(void)
{
    return _searchGreaterBySeq_WalItr(NULL);
}

struct wal_item* WalItr::first_WalItr(void) {
    if (shandle->is_persisted_snapshot) {
        struct avl_node *a;
        if (by_key) {
            a = avl_first(&shandle->key_tree);
            cursor_pos = a;
            return a ? _get_entry(a, struct wal_item, avl_keysnap) : NULL;
        } else {
            a = avl_first(&shandle->seq_tree);
            cursor_pos = a;
            return a ? _get_entry(a, struct wal_item, avl_seq) : NULL;
        }
    }

    if (shandle->snap_tag_idx) {
        direction = FDB_ITR_FORWARD;
        if (by_key) {
            return _firstByKey_WalItr();
        } else {
            return _firstBySeq_WalItr();
        }
    } // else no items in WAL for this snapshot
    return NULL;
}

struct wal_item * WalItr::_lastByKey_WalItr(void)
{
    struct wal_item_header dummy_key;
    struct wal_item dummy_item;
    fdb_kvs_id_t kv_id = shandle->id + 1; // set to next higher KVS
    dummy_key.key = &kv_id;
    dummy_key.keylen = sizeof(fdb_kvs_id_t);
    dummy_item.header = &dummy_key;
    if (multi_kvs) {
        return _searchSmallerByKey_WalItr(&dummy_item);
    } // else search go to last element in single kv instance mode..
    return _searchSmallerByKey_WalItr(NULL);
}

struct wal_item * WalItr::_lastBySeq_WalItr(void)
{
    return _searchSmallerBySeq_WalItr(NULL);
}

struct wal_item* WalItr::last_WalItr(void) {
    if (shandle->is_persisted_snapshot) {
        struct avl_node *a;
        if (by_key) {
            a = avl_last(&shandle->key_tree);
            cursor_pos = a;
            return a ? _get_entry(a, struct wal_item, avl_keysnap) : NULL;
        } else {
            a = avl_last(&shandle->seq_tree);
            cursor_pos = a;
            return a ? _get_entry(a, struct wal_item, avl_seq) : NULL;
        }
    }

    if (shandle->snap_tag_idx) { // no items in WAL in snapshot..
        direction = FDB_ITR_REVERSE;
        if (by_key) {
            return _lastByKey_WalItr();
        } else {
            return _lastBySeq_WalItr();
        }
    }
    return NULL;
}

WalItr::~WalItr()
{
    free(cursors);
}

// discard entries in txn
fdb_status Wal::discardTxnEntries_Wal(fdb_txn *txn)
{
    struct wal_item *item;
    struct list_elem *e;
    size_t shard_num, seq_shard_num;
    uint64_t _mem_overhead = 0;

    e = list_begin(txn->items);
    while(e) {
        item = _get_entry(e, struct wal_item, list_elem_txn);
        shard_num = get_checksum((uint8_t*)item->header->key,
                                 item->header->keylen) %
                                 num_shards;
        spin_lock(&key_shards[shard_num].lock);

        if (file->getConfig()->getSeqtreeOpt() == FDB_SEQTREE_USE) {
            // remove from seq map
            seq_shard_num = item->seqnum % num_shards;
            spin_lock(&seq_shards[seq_shard_num].lock);
            avl_remove(&seq_shards[seq_shard_num]._map,
                       &item->avl_seq);
            spin_unlock(&seq_shards[seq_shard_num].lock);
        }

        // remove from header's list
        list_remove(&item->header->items, &item->list_elem);
        // remove header if empty
        if (list_begin(&item->header->items) == NULL) {
            //remove from key map
            avl_remove(&key_shards[shard_num]._map,
                       &item->header->avl_key);
            _mem_overhead += sizeof(struct wal_item_header) +
                             item->header->keylen;
            // free key and header
            free(item->header->key);
            free(item->header);
        }
        // remove from txn's list
        e = list_remove(txn->items, e);
        if (item->txn_id == file->getGlobalTxn()->txn_id ||
            item->flag & WAL_ITEM_COMMITTED) {
            num_flushable--;
        }
        if (item->action != WAL_ACT_REMOVE) {
            datasize.fetch_sub(item->doc_size, std::memory_order_relaxed);
            // mark as stale if the item is not an immediate remove
            file->markStale(item->offset, item->doc_size);
        }

        // free
        free(item);
        size--;
        _mem_overhead += sizeof(struct wal_item);
        spin_unlock(&key_shards[shard_num].lock);
    }
    mem_overhead.fetch_sub(_mem_overhead, std::memory_order_relaxed);

    return FDB_RESULT_SUCCESS;
}

fdb_status Wal::_close_Wal(wal_discard_t type, void *aux,
                           ErrLogCallback *log_callback)
{
    struct wal_item *item;
    struct wal_item_header *header;
    struct list_elem *e;
    struct avl_node *a, *next_a;
    struct snap_handle *shandle;
    fdb_kvs_id_t kv_id, kv_id_req = 0;
    bool committed;
    size_t i = 0, seq_shard_num;
    uint64_t _mem_overhead = 0;
    struct wal_kvs_snaps query;

    if (type == WAL_DISCARD_KV_INS) { // multi KV ins mode
        if (aux == NULL) { // aux must contain pointer to KV ID
            return FDB_RESULT_INVALID_ARGS;
        }
        kv_id_req = *(fdb_kvs_id_t*)aux;
        query.id = kv_id_req;
        a = avl_search(&wal_kvs_snap_tree,
                       &query.avl_id, _wal_kvs_cmp);
        if (a) { // kv store found
            struct wal_kvs_snaps *kvs_snapshots = _get_entry(a,
                    struct wal_kvs_snaps, avl_id);
            // cleanup any snapshot handles not reclaimed by wal_flush
            for (struct list_elem *snap_elem = list_begin(&kvs_snapshots->snap_list);
                 snap_elem;) {
                shandle = _get_entry(snap_elem, struct snap_handle, snaplist_elem);
                if (_wal_snap_is_immutable(shandle)) {
                    fdb_log(log_callback, FDB_RESULT_INVALID_ARGS,
                            "Unclosed Snapshot in KVS id %" _F64
                            " with %" _F64 " docs in file %s."
                            "Snap id=%" _F64 " SnapSTOP=%" _F64 " "
                            "refcnt=%d", shandle->kvs_snapshots->id,
                            shandle->wal_ndocs.load(),
                            file->getFileName(),
                            shandle->snap_tag_idx, shandle->snap_stop_idx,
                            shandle->ref_cnt_kvs.load());
                }
                for (struct list_elem *ee = list_begin(&shandle->active_txn_list);
                        ee;) {
                    struct list_elem *e_next = list_next(ee);
                    struct wal_txn_wrapper *active_txn = _get_entry(ee,
                            struct wal_txn_wrapper, le);
                    free(active_txn);
                    ee = e_next;
                }
                snap_elem = list_next(snap_elem);
                free(shandle);
            } // done for all snapshots of specific kv store
            avl_remove(&file->getWal()->wal_kvs_snap_tree,
                       &kvs_snapshots->avl_id);
            free(kvs_snapshots);
        } // done for specific kv store
    } else {
        // cleanup all snapshot handles not reclaimed by wal_flush
        for (a = avl_first(&wal_kvs_snap_tree), next_a = NULL;
             a; a = next_a) {
            struct wal_kvs_snaps *kvs_snapshots = _get_entry(a,
                                                 struct wal_kvs_snaps, avl_id);
            for (struct list_elem *snap_elem = list_begin(&kvs_snapshots->snap_list);
                 snap_elem;) {
                shandle = _get_entry(snap_elem, struct snap_handle, snaplist_elem);
                if (_wal_snap_is_immutable(shandle)) {
                    fdb_log(log_callback, FDB_RESULT_INVALID_ARGS,
                            "WAL closed before snapshot close in kv id %" _F64
                            " with %" _F64 " docs in file %s", shandle->id,
                            shandle->wal_ndocs.load(), file->getFileName());
                }
                snap_elem = list_next(snap_elem);
                for (struct list_elem *ee = list_begin(&shandle->active_txn_list);
                        ee;) {
                    struct list_elem *e_next = list_next(ee);
                    struct wal_txn_wrapper *active_txn = _get_entry(ee,
                            struct wal_txn_wrapper, le);
                    free(active_txn);
                    ee = e_next;
                }
                free(shandle);
            } // done for all snapshots in kv store
            next_a = avl_next(a);
            avl_remove(&wal_kvs_snap_tree, a);
            free(kvs_snapshots);
        } // done for all kv stores
    }

    for (; i < num_shards; ++i) {
        spin_lock(&key_shards[i].lock);
        a = avl_first(&key_shards[i]._map);
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
                            file->markStale(item->offset, item->doc_size);
                        }
                    } else {
                        // committed item exists and will be removed
                        committed = true;
                    }

                    if (file->getConfig()->getSeqtreeOpt() == FDB_SEQTREE_USE) {
                        // remove from seq hash table
                        seq_shard_num = item->seqnum % num_shards;
                        spin_lock(&seq_shards[seq_shard_num].lock);
                        avl_remove(&seq_shards[seq_shard_num]._map,
                                   &item->avl_seq);
                        spin_unlock(&seq_shards[seq_shard_num].lock);
                    }

                    if (item->action != WAL_ACT_REMOVE) {
                        datasize.fetch_sub(item->doc_size,
                                           std::memory_order_relaxed);
                    }
                    if (item->txn_id == file->getGlobalTxn()->txn_id || committed) {
                        if (item->action != WAL_ACT_INSERT) {
                            _wal_update_stat(kv_id, _WAL_DROP_DELETE);
                        } else {
                            _wal_update_stat(kv_id, _WAL_DROP_SET);
                        }
                        num_flushable--;
                    }
                    free(item);
                    size--;
                    _mem_overhead += sizeof(struct wal_item);
                } else {
                    e = list_next(e);
                }
            }
            a = avl_next(a);

            if (list_begin(&header->items) == NULL) {
                // wal_item_header becomes empty
                // free header and remove from key map
                avl_remove(&key_shards[i]._map,
                           &header->avl_key);
                _mem_overhead += sizeof(struct wal_item_header) +
                                 header->keylen;
                free(header->key);
                free(header);
            }
        }
        spin_unlock(&key_shards[i].lock);
    }
    mem_overhead.fetch_sub(_mem_overhead, std::memory_order_relaxed);

    return FDB_RESULT_SUCCESS;
}

fdb_status Wal::close_Wal(ErrLogCallback *log_callback)
{
    return _close_Wal(WAL_DISCARD_UNCOMMITTED_ONLY, NULL, log_callback);
}

// discard all WAL entries
fdb_status Wal::shutdown_Wal(ErrLogCallback *log_callback)
{
    fdb_status wr = _close_Wal(WAL_DISCARD_ALL, NULL, log_callback);
    size = 0;
    num_flushable = 0;
    datasize = 0;
    mem_overhead = 0;
    return wr;
}

// discard all WAL entries belonging to KV_ID
fdb_status Wal::closeKvs_Wal(fdb_kvs_id_t kv_id,
                             ErrLogCallback *log_callback)
{
    return _close_Wal(WAL_DISCARD_KV_INS, &kv_id, log_callback);
}

size_t Wal::getSize_Wal(void)
{
    return size.load();
}

size_t Wal::getNumShards_Wal(void)
{
    return num_shards;
}

size_t Wal::getNumFlushable_Wal(void)
{
    return num_flushable.load();
}

size_t Wal::getNumDocs_Wal(void) {
    return file->getKvsStatOps()->statGetSum(KVS_STAT_WAL_NDOCS);
}

size_t Wal::getNumDeletes_Wal(void) {
    return file->getKvsStatOps()->statGetSum(KVS_STAT_WAL_NDELETES);
}

size_t Wal::getDataSize_Wal(void)
{
    return datasize.load(std::memory_order_relaxed);
}

size_t Wal::getMemOverhead_Wal(void)
{
    return mem_overhead.load(std::memory_order_relaxed);
}

void Wal::setDirtyStatus_Wal(wal_dirty_t status,
                             bool set_on_non_pending)
{
    spin_lock(&lock);
    if (set_on_non_pending && wal_dirty == FDB_WAL_PENDING) {
        spin_unlock(&lock);
        return;
    }
    wal_dirty = status;
    spin_unlock(&lock);
}

wal_dirty_t Wal::getDirtyStatus_Wal(void)
{
    wal_dirty_t ret;
    spin_lock(&lock);
    ret = wal_dirty;
    spin_unlock(&lock);
    return ret;
}

void Wal::addTransaction_Wal(fdb_txn *txn)
{
    spin_lock(&lock);
    list_push_front(&txn_list, &txn->wrapper->le);
    spin_unlock(&lock);
}

void Wal::removeTransaction_Wal(fdb_txn *txn)
{
    spin_lock(&lock);
    list_remove(&txn_list, &txn->wrapper->le);
    spin_unlock(&lock);
}

fdb_txn * Wal::getEarliestTxn_Wal(fdb_txn *cur_txn)
{
    struct list_elem *le;
    struct wal_txn_wrapper *txn_wrapper;
    fdb_txn *txn;
    fdb_txn *ret = NULL;
    uint64_t min_revnum = 0;

    spin_lock(&lock);

    le = list_begin(&txn_list);
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
    spin_unlock(&lock);

    return ret;
}

bool Wal::doesTxnExist_Wal(void)
{
    struct list_elem *le;
    struct wal_txn_wrapper *txn_wrapper;
    fdb_txn *txn;

    spin_lock(&lock);

    le = list_begin(&txn_list);
    while(le) {
        txn_wrapper = _get_entry(le, struct wal_txn_wrapper, le);
        txn = txn_wrapper->txn;
        if (txn != file->getGlobalTxn()) {
            spin_unlock(&lock);
            return true;
        }
        le = list_next(le);
    }
    spin_unlock(&lock);

    return false;
}
