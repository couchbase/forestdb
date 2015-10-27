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

#ifndef _JSAHN_WAL_H
#define _JSAHN_WAL_H

#include <stdint.h>
#include "internal_types.h"
#include "hash.h"
#include "list.h"
#include "avltree.h"
#include "atomic.h"
#include "libforestdb/fdb_errors.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef uint8_t wal_item_action;
enum{
    WAL_ACT_INSERT,
    WAL_ACT_LOGICAL_REMOVE, // An item is marked as "DELETED" by removing its doc body only.
    WAL_ACT_REMOVE // An item (key, metadata, body) is removed immediately.
};
typedef int wal_insert_by;
enum {
    WAL_INS_WRITER = 0, // normal writer inserting
    WAL_INS_COMPACT_PHASE1, // compactor in first phase moving unique docs
    WAL_INS_COMPACT_PHASE2 // compactor in delta phase (catchup, uncommitted)
};

struct wal_item_header{
    void *key;
    uint16_t keylen;
    uint8_t chunksize;
    struct list items;
    struct avl_node avl_key;
};

#define WAL_ITEM_COMMITTED (0x01)
#define WAL_ITEM_FLUSH_READY (0x02)
#define WAL_ITEM_BY_COMPACTOR (0x04)
#define WAL_ITEM_MULTI_KV_INS_MODE (0x08)
struct wal_item{
    fdb_txn *txn;
    wal_item_action action;
    uint8_t flag;
    uint32_t doc_size;
    uint64_t offset;
    uint64_t old_offset;
    fdb_seqnum_t seqnum;
    struct avl_node avl_seq;
    struct list_elem list_elem; // for wal_item_header's 'items'
    struct list_elem list_elem_txn; // for transaction
    union { // for offset-based sorting for WAL flush
        struct avl_node avl_flush;
        struct list_elem list_elem_flush;
    };
    struct wal_item_header *header;
};

typedef fdb_status wal_flush_func(void *dbhandle, struct wal_item *item);
typedef fdb_status wal_snapshot_func(void *shandle, fdb_doc *doc,
                                     uint64_t offset);
typedef uint64_t wal_get_old_offset_func(void *dbhandle,
                                         struct wal_item *item);
typedef uint64_t wal_doc_move_func(void *dbhandle,
                                   void *new_dhandle,
                                   struct wal_item *item,
                                   fdb_doc *doc);
typedef fdb_status wal_commit_mark_func(void *dbhandle,
                                        uint64_t offset);

#define WAL_FLAG_INITIALIZED 0x1


typedef uint8_t wal_dirty_t;
enum {
    FDB_WAL_CLEAN = 0,
    FDB_WAL_DIRTY = 1,
    FDB_WAL_PENDING = 2
};

struct wal_shard_by_key {
    struct avl_tree map_bykey; // tree of all 'wal_item_header' (keys) in shard
    spin_t lock;
};

struct wal_shard_by_seq {
    struct avl_tree map_byseq; // indexes 'wal_item's seq num in WAL shard
    spin_t lock;
};

struct wal {
    uint8_t flag;
    atomic_uint32_t size; // total # entries in WAL (uint32_t)
    atomic_uint32_t num_flushable; // # flushable entries in WAL (uint32_t)
    atomic_uint64_t datasize; // total data size in WAL (uint64_t)
    atomic_uint64_t mem_overhead; // memory overhead of all WAL entries
    struct list txn_list; // list of active transactions
    wal_dirty_t wal_dirty;
    struct wal_shard_by_key *key_shards;
    struct wal_shard_by_seq *seq_shards;
    size_t num_shards;
    spin_t lock;
};

struct wal_txn_wrapper {
    fdb_txn *txn;
    struct list_elem le;
};

union wal_flush_items {
    struct avl_tree tree; // if WAL items are to be sorted by offset
    struct list list; // if WAL items need not be sorted
};

fdb_status wal_init(struct filemgr *file, int nbucket);
int wal_is_initialized(struct filemgr *file);
fdb_status wal_insert(fdb_txn *txn,
                      struct filemgr *file,
                      fdb_doc *doc,
                      uint64_t offset,
                      wal_insert_by caller);
fdb_status wal_immediate_remove(fdb_txn *txn,
                                struct filemgr *file,
                                fdb_doc *doc,
                                uint64_t offset,
                                wal_insert_by caller);
fdb_status wal_find(fdb_txn *txn, struct filemgr *file, fdb_doc *doc, uint64_t *offset);
fdb_status wal_find_kv_id(fdb_txn *txn,
                          struct filemgr *file,
                          fdb_kvs_id_t kv_id,
                          fdb_doc *doc,
                          uint64_t *offset);

fdb_status wal_txn_migration(void *dbhandle,
                             void *new_dhandle,
                             struct filemgr *old_file,
                             struct filemgr *new_file,
                             wal_doc_move_func *move_doc);
fdb_status wal_commit(fdb_txn *txn, struct filemgr *file, wal_commit_mark_func *func,
                      err_log_callback *log_callback);
fdb_status wal_release_flushed_items(struct filemgr *file,
                                     union wal_flush_items *flush_items);
fdb_status wal_flush(struct filemgr *file,
                     void *dbhandle,
                     wal_flush_func *flush_func,
                     wal_get_old_offset_func *get_old_offset,
                     union wal_flush_items *flush_items);
fdb_status wal_flush_by_compactor(struct filemgr *file,
                                  void *dbhandle,
                                  wal_flush_func *flush_func,
                                  wal_get_old_offset_func *get_old_offset,
                                  union wal_flush_items *flush_items);
fdb_status wal_snapshot(struct filemgr *file,
                        void *dbhandle, fdb_txn *txn,
                        fdb_seqnum_t *upto_seq,
                        wal_snapshot_func *snapshot_func);
fdb_status wal_discard(struct filemgr *file, fdb_txn *txn);
fdb_status wal_close(struct filemgr *file);
fdb_status wal_shutdown(struct filemgr *file);
fdb_status wal_close_kv_ins(struct filemgr *file,
                            fdb_kvs_id_t kv_id);

size_t wal_get_size(struct filemgr *file);
size_t wal_get_num_shards(struct filemgr *file);
size_t wal_get_num_flushable(struct filemgr *file);
size_t wal_get_num_docs(struct filemgr *file);
size_t wal_get_num_deletes(struct filemgr *file);
size_t wal_get_datasize(struct filemgr *file);
void wal_set_dirty_status(struct filemgr *file, wal_dirty_t status);
wal_dirty_t wal_get_dirty_status(struct filemgr *file);
void wal_add_transaction(struct filemgr *file, fdb_txn *txn);
void wal_remove_transaction(struct filemgr *file, fdb_txn *txn);
fdb_txn * wal_earliest_txn(struct filemgr *file, fdb_txn *cur_txn);
bool wal_txn_exists(struct filemgr *file);

/**
 * Get the memory overhead of the WAL index for a given file manager
 * @param file the instance of a file manager whose WAL index memory overhead
 *        should be returned
 * @return the memory overhead of a given file manager's WAL index
 */
size_t wal_get_mem_overhead(struct filemgr *file);

#ifdef __cplusplus
}
#endif

#endif
