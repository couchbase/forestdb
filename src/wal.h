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
    struct avl_node avl_key;
    void *key;
    uint16_t keylen;
    uint8_t chunksize;
    struct list items;
};

typedef uint64_t wal_snapid_t;
#define OPEN_SNAPSHOT_TAG ((wal_snapid_t)(-1)) // any latest snapshot item
struct snap_handle {
    /**
     * Link to the tree of snapshots indexed by (kvs_id, snap_id) pair.
     */
    struct avl_node avl_id;
    /**
     * Unique KV Store ID (keep as second member).
     */
    fdb_kvs_id_t id;
    /**
     * Back pointer to index into the global WAL snapshot array
     */
    wal_snapid_t snap_tag_idx;
    /**
     * Snapshot stop index that denotes a WAL flush
     */
    wal_snapid_t snap_stop_idx;
    /**
     * Incremented on snapshot_open, decremented on snapshot_close(Write Barrier)
     * Reference count to avoid copy if same KV store WAL snapshot is cloned.
     */
    atomic_uint16_t ref_cnt_kvs;
    /**
     * Did wal_flush make me inaccessible to later snapshots, (Read-Write Barrier)
     */
    bool is_flushed;
    /**
     * Is this a persistent snapshot completely separate from WAL.
     */
    bool is_persisted_snapshot;
    /**
     * Number of WAL items put into this snapshot before it became immutable.
     */
    atomic_uint64_t wal_ndocs;
    /**
     * Highest sequence number seen in this KV store snapshot.
     */
    fdb_seqnum_t seqnum;
    /**
     * Transaction that the handle was in at the time of snapshot creation.
     */
    fdb_txn *snap_txn;
    /**
     * Global transaction pointer to distinguish from local transactions
     * for partially committed items.
     */
    fdb_txn *global_txn;
    /**
     * Active transaction list to hide partially committed items whose
     * transaction is still being ended.
     */
    struct list active_txn_list;
    /**
     * Local DB stats for cloned snapshots
     */
    struct kvs_stat stat;
    /**
     * Custom compare function context and callback set by user.
     * TODO: Store original pointer on which snapshot was taken & use to clone
     * index nodes as well!
     */
    struct _fdb_key_cmp_info cmp_info;
    /**
     * AVL tree to store unflushed WAL entries of a snapshot by key range
     */
    struct avl_tree key_tree;
    /**
     * AVL tree to store unflushed WAL entries of a snapshot by sequence number
     */
    struct avl_tree seq_tree;
};

#define WAL_ITEM_COMMITTED (0x01)
#define WAL_ITEM_FLUSH_READY (0x02)
#define WAL_ITEM_MULTI_KV_INS_MODE (0x04)
#define WAL_ITEM_FLUSHED_OUT (0x08)
struct wal_item{
    struct list_elem list_elem; // for wal_item_header's 'items'
    struct avl_node avl_seq; // used for indexing by sequence number
    struct wal_item_header *header;
    fdb_txn *txn;
    uint64_t txn_id; // used to track closed transactions
    struct snap_handle *shandle; // Pointer into wal_snapshot_tree for KV Store
    wal_item_action action;
    atomic_uint8_t flag;
    uint32_t doc_size;
    uint64_t offset;
    fdb_seqnum_t seqnum;
    uint64_t old_offset;
    union { // for offset-based sorting for WAL flush
        struct list_elem list_elem_txn; // for transaction
        struct avl_node avl_flush;
        struct list_elem list_elem_flush;
        struct avl_node avl_keysnap; // for durable snapshot unique key lookup
    };
};

typedef fdb_status wal_flush_func(void *dbhandle, struct wal_item *item,
                                  struct avl_tree *stale_seqnum_list,
                                  struct avl_tree *kvs_delta_stats);

/**
 * Pointer of function that purges stale entries from the sequence tree
 * as part of WAL flush.
 */
typedef void wal_flush_seq_purge_func(void *dbhandle,
                                      struct avl_tree *stale_seqnum_list,
                                      struct avl_tree *kvs_delta_stats);

/**
 * Pointer of function that updates a KV store stats for each WAL flush
 */
typedef void wal_flush_kvs_delta_stats_func(struct filemgr *file,
                                            avl_tree *kvs_delta_stats);

typedef fdb_status wal_snapshot_func(void *shandle, fdb_doc *doc,
                                     uint64_t offset);
typedef uint64_t wal_get_old_offset_func(void *dbhandle,
                                         struct wal_item *item);
typedef int64_t wal_doc_move_func(void *dbhandle,
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

struct wal_shard {
    struct avl_tree _map;
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
    // tree of all 'wal_item_header' (keys) in shard
    struct wal_shard *key_shards;
    // indexes 'wal_item's seq num in WAL shard
    struct wal_shard *seq_shards;
    size_t num_shards;
    // Global shared WAL Snapshot Data
    struct avl_tree wal_snapshot_tree;
    spin_t lock;
};

struct wal_cursor {
    struct avl_node avl_merge; // avl node for merge sort across all shards
    struct wal_item *item; // pointer to the shared WAL snapshot item
    struct wal_item *first_item; // first key/seqnum item in snapshot of shard
    struct wal_item *last_item; // last key/seqnum item in snapshot of shard
};

struct wal_iterator {
    struct wal *_wal; // Pointer to global WAL
    struct snap_handle *shandle; // Pointer to KVS snapshot handle.
    struct wal_shard *map_shards; // pointer to the shared WAL key/seq shards
    size_t num_shards; // number of shards in the global shared WAL key/seq
    bool by_key; // if not set means iteration is by sequence number range
    bool multi_kvs; // single kv mode vs multi kv instance mode
    uint8_t direction; // forward/backward/none to avoid grabbing all locks
    struct avl_tree merge_tree; // AVL tree to perform merge-sort over cursors
    struct avl_node *cursor_pos; // points to shard that returns current item
    struct wal_item *item_prev; // points to previous iterator item returned
    struct wal_cursor *cursors; // cursor to item from each shard's tree
};

struct wal_txn_wrapper {
    struct list_elem le;
    union {
        fdb_txn *txn; // when used in wal's transaction list
        uint64_t txn_id; // when used in snapshot's active_txn_list
    };
};

union wal_flush_items {
    struct avl_tree tree; // if WAL items are to be sorted by offset
    struct list list; // if WAL items need not be sorted
};


fdb_status wal_init(struct filemgr *file, int nbucket);
int wal_is_initialized(struct filemgr *file);
fdb_status wal_insert(fdb_txn *txn,
                      struct filemgr *file,
                      struct _fdb_key_cmp_info *cmp_info,
                      fdb_doc *doc,
                      uint64_t offset,
                      wal_insert_by caller);
fdb_status wal_immediate_remove(fdb_txn *txn,
                                struct filemgr *file,
                                struct _fdb_key_cmp_info *cmp_info,
                                fdb_doc *doc,
                                uint64_t offset,
                                wal_insert_by caller);
fdb_status wal_find(fdb_txn *txn, struct filemgr *file,
                    struct _fdb_key_cmp_info *cmp_info,
                    struct snap_handle *shandle,
                    fdb_doc *doc, uint64_t *offset);
fdb_status wal_find_kv_id(fdb_txn *txn,
                          struct filemgr *file,
                          fdb_kvs_id_t kv_id,
                          struct _fdb_key_cmp_info *cmp_info,
                          struct snap_handle *shandle,
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

/**
 * Flush WAL entries into the main indexes (i.e., hbtrie and sequence tree)
 *
 * @param file Pointer to the file manager
 * @param dbhandle Pointer to the KV store handle
 * @param flush_func Pointer of function that flushes each WAL entry into the
 *                   main indexes
 * @param get_old_offset Pointer of function that retrieves an offset of the
 *                       old KV item from the hbtrie
 * @param seq_purge_func Pointer of function that purges an old entry with the
 *                       same key from the sequence tree
 * @param delta_stats_func Pointer of function that updates each KV store's stats
 * @param flush_items Pointer to the list that contains the list of all WAL entries
 *                    that are flushed into the main indexes
 * @return FDB_RESULT upon successful WAL flush
 */
fdb_status wal_flush(struct filemgr *file,
                     void *dbhandle,
                     wal_flush_func *flush_func,
                     wal_get_old_offset_func *get_old_offset,
                     wal_flush_seq_purge_func *seq_purge_func,
                     wal_flush_kvs_delta_stats_func *delta_stats_func,
                     union wal_flush_items *flush_items);

/**
 * Flush WAL entries into the main indexes (i.e., hbtrie and sequence tree)
 * by the compactor
 *
 * @param file Pointer to the file manager
 * @param dbhandle Pointer to the KV store handle
 * @param flush_func Pointer of function that flushes each WAL entry into the
 *                   main indexes
 * @param get_old_offset Pointer of function that retrieves an offset of the
 *                       old KV item from the hbtrie
 * @param seq_purge_func Pointer of function that purges an old entry with the
 *                       same key from the sequence tree
 * @param delta_stats_func Pointer of function that updates each KV store's stats
 * @param flush_items Pointer to the list that contains the list of all WAL entries
 *                    that are flushed into the main indexes
 * @return FDB_RESULT upon successful WAL flush
 */
fdb_status wal_flush_by_compactor(struct filemgr *file,
                                  void *dbhandle,
                                  wal_flush_func *flush_func,
                                  wal_get_old_offset_func *get_old_offset,
                                  wal_flush_seq_purge_func *seq_purge_func,
                                  wal_flush_kvs_delta_stats_func *delta_stats_func,
                                  union wal_flush_items *flush_items);

/**
 * Create a WAL snapshot for a specific KV Store
 * @param file - the underlying file for the database
 * @param txn - transaction that the snapshot is to be taken on
 * @param kv_id - KV Store ID whose snapshot is to be taken
 * @param seqnum - The sequence number at which the snapshot is to be taken
 * @param key_cmp_info - custom comparison function.
 * @param shandle - WAL snapshot handle result
 */
fdb_status wal_snapshot_open(struct filemgr *file,
                             fdb_txn *txn,
                             fdb_kvs_id_t kv_id,
                             fdb_seqnum_t seqnum,
                             _fdb_key_cmp_info *key_cmp_info,
                             struct snap_handle **shandle);
/**
 * Clone from an existing WAL snapshot
 * @param shandle_in - incoming snapshot handle
 * @param shandle_out - cloned snapshot handle out
 * @param seqnum - The sequence number at which the snapshot is to be taken
 */
fdb_status wal_snapshot_clone(struct snap_handle *shandle_in,
                              struct snap_handle **shandle_out,
                              fdb_seqnum_t seqnum);
/**
 * Create a persisted (durable) WAL snapshot for a specific KV Store
 * @param seqnum - the highest sequence number for this persisted snapshot.
 * @param key_cmp_info - custom comparison function.
 * @param file - the underlying file
 * @param txn - the current active transaction at time of snapshot creation
 * @param shandle - WAL snapshot handle result
 */
fdb_status wal_dur_snapshot_open(fdb_seqnum_t seqnum,
                                 _fdb_key_cmp_info *key_cmp_info,
                                 struct filemgr *file, fdb_txn *txn,
                                 struct snap_handle **shandle);
/**
 * Create an exclusive Snapshot of the WAL by copying all entries to
 * immutable AVL trees
 * @param file - the underlying file
 * @param shandle - WAL snapshot handle created by wal_dur_snapshot_open()
 * @param is_multi_kv - Does the WAL have multiple KV Stores
 */

fdb_status wal_copyto_snapshot(struct filemgr *file,
                               struct snap_handle *shandle,
                               bool is_multi_kv);

/**
 * Closes a WAL snapshot
 * @param shandle - the snapshot handle to be closed
 * @param file - the underlying file for the database
 */
fdb_status wal_snapshot_close(struct snap_handle *shandle,
                              struct filemgr *file);
/**
 * Retrieve the KV Store stats of this KV Store from the WAL Snapshot
 * @param shandle - the WAL snapshot handle
 * @param stat - (OUT) returned stat
 */
fdb_status snap_get_stat(struct snap_handle *shandle, struct kvs_stat *stat);

/**
 * Persisted snapshots opened from disk needs to have its own immutable tree
 * This routine is used by _fdb_restore_wal() to load immutable items into it
 * @param shandle - the WAL snapshot handle
 * @param doc - the immutable document to be inserted into the snapshot
 * @param offset - offset of the immutable doc
 */
fdb_status wal_snap_insert(struct snap_handle *shandle, fdb_doc *doc,
                           uint64_t offset);
/**
 * Initialize a WAL iterator snapshot by creating a barrier to future writes
 * @param file - underlying ForestDB database file shared by all KV Stores
 * @param shandle - pointer to snap_handle created by snapshot_open
 * @param by_key - is the iteration done by key or by sequence number
 * @param wal_iterator - Return pointer to initialized wal_iterator
 */
fdb_status wal_itr_init(struct filemgr *file,
                        struct snap_handle *shandle,
                        bool by_key,
                        struct wal_iterator **wal_iterator);
/**
 * Initialize the boundaries of the iteration by setting first element
 * @param - wal_itr - the WAL iterator whose bounds need to be set
 * @param - first_elem - could be key or seqnum, NULL means first in snapshot
 */
fdb_status wal_itr_set_first(struct wal_iterator *wal_itr,
                             struct wal_item *first_elem);
/**
 * Initialize the boundaries of the iteration by setting last element
 * @param - wal_itr - the WAL iterator whose bounds need to be set
 * @param - last_elem - could be key or seqnum, NULL means last in snapshot
 */
fdb_status wal_itr_set_last(struct wal_iterator *wal_itr,
                            struct wal_item *last_elem);
/**
 * Position the sharded WAL iterator to a key/seqnum greater than the query
 * if the queried key/seqnum does not exist.
 * @param wal_itr - the wal iterator snapshot whose cursor needs to be set.
 * @param wal_item - the avl pointer of the query wal_item.
 */
struct wal_item *wal_itr_search_greater(struct wal_iterator *wal_itr,
                                        struct wal_item *query_item);
/**
 * Position the sharded WAL iterator to a key/seqnum smaller than the query
 * if the queried key/seqnum does not exist.
 * @param wal_itr - the wal iterator snapshot whose cursor needs to be set.
 * @param wal_item - the pointer of the query wal_item.
 */
struct wal_item *wal_itr_search_smaller(struct wal_iterator *wal_itr,
                                        struct wal_item *query_item);
/**
 * Position the sharded WAL iterator to the next key/seqnum than current pos
 * @param wal_itr - the wal iterator snapshot whose cursor needs to be set.
 */
struct wal_item *wal_itr_next(struct wal_iterator *wal_itr);

/**
 * Position the sharded WAL iterator to the previous key/seqnum from current pos
 * @param wal_itr - the wal iterator snapshot whose cursor needs to be set.
 */
struct wal_item *wal_itr_prev(struct wal_iterator *wal_itr);
/**
 * Position the sharded WAL iterator to the first key/seqnum in KV Store snapshot
 * @param wal_itr - the wal iterator snapshot whose cursor needs to be set.
 */
struct wal_item *wal_itr_first(struct wal_iterator *wal_itr);
/**
 * Position the sharded WAL iterator to the last key/seqnum in KV Store snapshot
 * @param wal_itr - the wal iterator snapshot whose cursor needs to be set.
 */
struct wal_item *wal_itr_last(struct wal_iterator *wal_itr);
/**
 * Free memory associated with the wal iteration
 * @param wal_itr - the wal iterator whose memory needs to be freed.
 */
fdb_status wal_itr_close(struct wal_iterator *wal_itr);

fdb_status wal_discard(struct filemgr *file, fdb_txn *txn);
fdb_status wal_close(struct filemgr *file, err_log_callback *log_callback);
fdb_status wal_shutdown(struct filemgr *file, err_log_callback *log_callback);

/**
 * Free memory associated with wal data structures.
 */
fdb_status wal_destroy(struct filemgr *file);

fdb_status wal_close_kv_ins(struct filemgr *file,
                            fdb_kvs_id_t kv_id, err_log_callback *log_callback);

size_t wal_get_size(struct filemgr *file);
size_t wal_get_num_shards(struct filemgr *file);
size_t wal_get_num_flushable(struct filemgr *file);
size_t wal_get_num_docs(struct filemgr *file);
size_t wal_get_num_deletes(struct filemgr *file);
size_t wal_get_datasize(struct filemgr *file);

/**
 * Set the dirty status of the WAL
 *
 * @param file Pointer to the file manager instance
 * @param status New dirty status to be set
 * @param set_on_non_pending Flag indicating the status can be only overriden
 *        if the current status is not in FDB_WAL_PENDING
 */
void wal_set_dirty_status(struct filemgr *file,
                          wal_dirty_t status,
                          bool set_on_non_pending = false);

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
