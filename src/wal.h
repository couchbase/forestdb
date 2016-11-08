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

#pragma once

#include <stdint.h>
#include "internal_types.h"
#include "hash.h"
#include "list.h"
#include "avltree.h"
#include "atomic.h"
#include "libforestdb/fdb_errors.h"

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
    struct list_elem le_key;
    struct hash_elem he_key;
    void *key;
    uint16_t keylen;
    uint32_t checksum; // cache key's checksum to avoid recomputation
    struct list items;
};

struct wal_kvs_snaps; // forward declaration for snap_handle
struct wal_item; // forward declaration for snap_handle
typedef uint64_t wal_snapid_t;
#define OPEN_SNAPSHOT_TAG ((wal_snapid_t)(-1)) // any latest snapshot item
struct Snapshot {
    Snapshot(); // Empty default constructor for dummy snapshot handles
    /**
     * @param snap_kvid - ID of KV Store this snapshot belongs to
     * @param snap_range_start - Id of this snapshot
     * @param snap_range_end - Id of oldest snapshot whose items are shared
     *                         with this snapshot
     * @param cmp_info - Custom compare callback context
     * @param parentFile - FileMgr instance where this Snapshot belongs.
     * @param parent_kvs - Parent KV Store list where this snapshot belongs.
     */
    Snapshot(fdb_kvs_id_t snap_kvid, wal_snapid_t snap_range_start,
             wal_snapid_t snap_range_end, _fdb_key_cmp_info *cmp_info,
             FileMgr *parentFile,
             struct wal_kvs_snaps *parent_kvs);
    ~Snapshot();

    /**
     * Under the auspices of the WAL lock, this function is used to initialize
     * a snapshot with a given sequence number and a copy of all the active
     * transactions at this point in time
     * @param txn - transaction under which the snapshot is taken
     * @param snap_seqnum - the highest sequence number seen in this snapshot
     * @param txn_list_to_snapshot - the WAL's list of active transactions
     * @return - FDB_RESULT_SUCCESS or an error code upon failure
     */
    fdb_status initSnapshot(fdb_txn *txn, fdb_seqnum_t snap_seqnum,
                            struct list *txn_list_to_snapshot);

    /**
     * Persisted snapshot opened from disk must have its own immutable index
     * That is not shared with other snapshots present in the WAL
     * This routine is used by _fdb_restore_wal() to load immutable items into it
     * @param doc - the immutable document to be inserted into the snapshot
     * @param offset - offset of the immutable doc
     */
    fdb_status snapInsertDoc(fdb_doc *doc, uint64_t offset);

    /**
     * Persisted snapshots opened from disk have their own immutable indexes
     * that are not shared with other snapshots present in the WAL
     * This routine is used by find_Wal() to locate an item from the above.
     * @param doc - the immutable document to be returned from the snapshot
     * @param offset - offset of the immutable doc to be returned
     */
    fdb_status snapFindDoc(fdb_doc *doc, uint64_t *offset);

    /**
     * Index a WAL item into this snapshot by key. Also displace an older item
     * from its snapshot (which may be same as this snapshot or a different one)
     * @param item - new item to be indexed into the WAL
     * @param old_item - old item to be un-indexed from its snapshot if indexed
     */
    void snapAddItemByKey(wal_item *item, wal_item *old_item);

    /**
     * Index a WAL item into this snapshot by sequence number. Optionally
     * displace an older item from its snapshot.
     * @param item - new item to be indexed into the WAL
     * @param old_item - old item to be un-indexed from its snapshot if indexed
     */
    void snapAddItemBySeq(wal_item *item, wal_item *old_item);

    /**
     * The following functions are used for iteration of this snapshot's items
     */
    struct wal_item * snapGetGreaterByKey(struct wal_item *query);
    struct wal_item * snapGetGreaterBySeq(struct wal_item *query);
    struct wal_item * snapGetSmallerByKey(struct wal_item *query);
    struct wal_item * snapGetSmallerBySeq(struct wal_item *query);
    struct wal_item * nextSnapItemByKey(struct wal_item *cur_item);
    struct wal_item * nextSnapItemBySeq(struct wal_item *cur_item);
    struct wal_item * prevSnapItemByKey(struct wal_item *cur_item);
    struct wal_item * prevSnapItemBySeq(struct wal_item *cur_item);
    struct wal_item * firstSnapItemByKey(void);
    struct wal_item * firstSnapItemBySeq(void);
    struct wal_item * lastSnapItemByKey(void);
    struct wal_item * lastSnapItemBySeq(void);

    /**
     * Remove an item from this snapshot
     * @param item - item to be removed from the key & seqnum indexes
     */
    void snapRemoveItem(wal_item *item);

    /**
     * Release memory of all indexed items in this snapshot
     */
    void snapFreeItems();

    /**
     * Link to the list of snapshots for a kv store.
     */
    struct list_elem snaplist_elem;
    /**
     * Back pointer to the parent KV Store in whose list this struct belongs.
     */
    struct wal_kvs_snaps *kvs_snapshots;
    /**
     * ID of the KV Store to which this snapshot belongs.
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
    std::atomic<uint64_t> ref_cnt_kvs;
    /**
     * Did flush_Wal make me inaccessible to later snapshots, (Read-Write Barrier)
     */
    bool is_flushed;
    /**
     * Is this a persistent snapshot completely separate from WAL.
     */
    bool is_persisted_snapshot;
    /**
     * Number of previous snapshots which share items with current snapshot.
     */
    int num_prev_snaps;
    /**
     * Number of WAL items put into this snapshot before it became immutable.
     */
    std::atomic<uint64_t> wal_ndocs;
    /**
     * Highest sequence number seen in this KV store snapshot.
     */
    fdb_seqnum_t seqnum;
    /**
     * Transaction that the handle was in at the time of snapshot creation.
     */
    fdb_txn *snap_txn;
    /**
     * Parent file where this snapshot belongs. It is required for fetching
     * the global transaction pointer to distinguish from local transactions
     * for partially committed items.
     */
    FileMgr *snapFile;
    /**
     * Active transaction list to hide partially committed items whose
     * transaction is still being ended.
     */
    struct list active_txn_list;
    /**
     * Local DB stats for cloned snapshots
     */
    KvsStat stat;
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

/**
 * This struct tracks the KV Stores whose items are present in the WAL
 * It is inserted into the AVL tree of the WAL sorted by the KV Store's id
 * The main purpose of this struct is to house a list of shared snapshots
 * created in the KV Store.
 */
struct wal_kvs_snaps {
    struct avl_node avl_id; // link into wal_kvs_snap_tree
    fdb_kvs_id_t id; // id of KV store whose snapshots are tracked
    struct list snap_list; // list of globally shared snapshots
    size_t num_snaps; // bookeeping number of concurrent snapshots opened
};

#define WAL_ITEM_COMMITTED (0x01)
#define WAL_ITEM_FLUSH_READY (0x02)
#define WAL_ITEM_MULTI_KV_INS_MODE (0x04)
#define WAL_ITEM_FLUSHED_OUT (0x08)
// not all wal_items are indexed into their KV Store's snapshot handles
// (for example uncommitted transactional items)
// this flag is only set in those items which are inserted into their snapshot
// It is used during updates when one item is replaced with another
#define WAL_ITEM_IN_SNAP_TREE (0x10)

struct wal_item{
    struct list_elem list_elem; // for wal_item_header's 'items'
    struct hash_elem he_seq; // used for indexing by sequence number
    struct avl_node avl_keysnap; // for durable snapshot unique key lookup
    struct avl_node avl_seqsnap; // for durable snapshot unique seqnum lookup
    struct wal_item_header *header;
    fdb_txn *txn;
    uint64_t txn_id; // used to track closed transactions
    Snapshot *shandle; // Pointer into item's parent snapshot
    wal_item_action action;
    std::atomic<uint8_t> flag;
    uint32_t doc_size;
    uint64_t offset;
    fdb_seqnum_t seqnum;
    uint64_t old_offset;
    union { // for offset-based sorting for WAL flush
        struct list_elem list_elem_txn; // for transaction
        struct avl_node avl_flush;
        struct list_elem list_elem_flush;
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
typedef void wal_flush_kvs_delta_stats_func(FileMgr *file,
                                            avl_tree *kvs_delta_stats);

typedef uint64_t wal_get_old_offset_func(void *dbhandle,
                                         struct wal_item *item);
typedef int64_t wal_doc_move_func(void *dbhandle,
                                  void *new_dhandle,
                                  struct wal_item *item,
                                  fdb_doc *doc);
typedef fdb_status wal_commit_mark_func(void *dbhandle,
                                        uint64_t offset);

typedef uint8_t wal_dirty_t;
enum {
    FDB_WAL_CLEAN = 0,
    FDB_WAL_DIRTY = 1,
    FDB_WAL_PENDING = 2
};

struct wal_shard {
    struct hash _map;
    struct list _list;
    spin_t lock;
};

class WalItr;

typedef enum wal_discard_type {
    WAL_DISCARD_UNCOMMITTED_ONLY,
    WAL_DISCARD_ALL,
    WAL_DISCARD_KV_INS,
} wal_discard_t;


class Wal {
    friend class WalItr;

public:
    Wal(FileMgr *file, size_t nbucket);
    ~Wal();

    /**
     * Index a mutation into the Write Ahead Log
     */
    fdb_status insert_Wal(fdb_txn *txn,
                          struct _fdb_key_cmp_info *cmp_info,
                          fdb_doc *doc,
                          uint64_t offset,
                          wal_insert_by caller);

    /**
     * Insert a deleted item with action WAL_ACT_REMOVE
     */
    fdb_status immediateRemove_Wal(fdb_txn *txn,
                                   struct _fdb_key_cmp_info *cmp_info,
                                   fdb_doc *doc,
                                   uint64_t offset,
                                   wal_insert_by caller);

    /**
     * Search WAL item in default or single KV instance mode
     */
    fdb_status find_Wal(fdb_txn *txn, struct _fdb_key_cmp_info *cmp_info,
                        Snapshot *shandle,
                        fdb_doc *doc, uint64_t *offset);

    /**
     * Search WAL item in a specific KV Store in multi kv instance mode
     */
    fdb_status findWithKvid_Wal(fdb_txn *txn,
                                fdb_kvs_id_t kv_id,
                                struct _fdb_key_cmp_info *cmp_info,
                                Snapshot *shandle,
                                fdb_doc *doc,
                                uint64_t *offset);

    /**
     * Move uncommitted transaction items on compaction from old file
     * to new file
     */
    static fdb_status migrateUncommittedTxns_Wal(void *dbhandle,
                                                 void *new_dhandle,
                                                 FileMgr *old_file,
                                                 FileMgr *new_file,
                                                 wal_doc_move_func *move_doc);

    /**
     * Walk through all uncommitted WAL items mutated since last commit/flush
     * and mark them as committed. De-duplicate items as necessary.
     * @param txn - parent transaction which is ending (global_txn if no txn)
     * @param func - callback function to append a commit mark for txn restore
     * @param log_callback - error log callback since i/o may be done.
     * @return FDB_RESULT_SUCCESS on success, or errcode as per error
     */
    fdb_status commit_Wal(fdb_txn *txn, wal_commit_mark_func *func,
                          ErrLogCallback *log_callback);

    /**
     * Free memory associated with the WAL items now that they are reflected in
     * the main index
     * @param flush_items pointer to the index carrying the WAL items
     */
    fdb_status releaseFlushedItems_Wal(union wal_flush_items *flush_items);

    /**
     * Flush WAL entries into the main indexes (i.e., hbtrie and sequence tree)
     *
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
     */
    fdb_status flush_Wal(void *dbhandle,
                         wal_flush_func *flush_func,
                         wal_get_old_offset_func *get_old_offset,
                         wal_flush_seq_purge_func *seq_purge_func,
                         wal_flush_kvs_delta_stats_func *delta_stats_func,
                         union wal_flush_items *flush_items);

    /**
     * Flush WAL entries into the main indexes (i.e., hbtrie and sequence tree)
     * by the compactor
     *
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
    fdb_status flushByCompactor_Wal(void *dbhandle,
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
    fdb_status snapshotOpen_Wal(fdb_txn *txn,
                                fdb_kvs_id_t kv_id,
                                fdb_seqnum_t seqnum,
                                _fdb_key_cmp_info *key_cmp_info,
                                Snapshot **shandle);
    /**
     * Clone from an existing WAL snapshot
     * @param shandle_in - incoming snapshot handle
     * @param shandle_out - cloned snapshot handle out
     * @param seqnum - The sequence number at which the snapshot is to be taken
     */
    fdb_status snapshotClone_Wal(Snapshot *shandle_in,
                                 Snapshot **shandle_out,
                                 fdb_seqnum_t seqnum);
    /**
     * Create a persisted (durable) WAL snapshot for a specific KV Store
     * @param seqnum - the highest sequence number for this persisted snapshot.
     * @param key_cmp_info - custom comparison function.
     * @param file - the underlying file
     * @param txn - the current active transaction at time of snapshot creation
     * @param shandle - WAL snapshot handle result
     */
    fdb_status snapshotOpenPersisted_Wal(fdb_seqnum_t seqnum,
                                         _fdb_key_cmp_info *key_cmp_info,
                                         fdb_txn *txn,
                                         Snapshot **shandle);

    /**
     * Create an exclusive Snapshot of the WAL by copying all entries to
     * immutable AVL trees
     * @param file - the underlying file
     * @param shandle - Snapshot handle created by snapshotOpenPersisted_Wal()
     */

    fdb_status copy2Snapshot_Wal(Snapshot *shandle);

    /**
     * Closes a WAL snapshot
     * @param shandle - the snapshot handle to be closed
     * @param file - the underlying file for the database
     */
    fdb_status snapshotClose_Wal(Snapshot *shandle);

    /**
     * Retrieve the KV Store stats of this KV Store from the WAL Snapshot
     * @param shandle - the WAL snapshot handle
     * @param stat - (OUT) returned stat
     */
    fdb_status getSnapStats_Wal(Snapshot *shandle, KvsStat *stat);

    /**
     * Discard WAL entries belonging to specific transaction
     */
    fdb_status discardTxnEntries_Wal(fdb_txn *txn);

    /**
     * Close and free all WAL entries
     */
    fdb_status close_Wal(ErrLogCallback *log_callback);
    /**
     * Wrapper around close WAL
     */
    fdb_status shutdown_Wal(ErrLogCallback *log_callback);

    fdb_status closeKvs_Wal(fdb_kvs_id_t kv_id,
                            ErrLogCallback *log_callback);
    /**
     * Set the dirty status of the WAL
     *
     * @param status New dirty status to be set
     * @param set_on_non_pending Flag indicating the status can be only overriden
     *        if the current status is not in FDB_WAL_PENDING
     */
    void setDirtyStatus_Wal(wal_dirty_t status,
                            bool set_on_non_pending = false);

    void addTransaction_Wal(fdb_txn *txn);
    void removeTransaction_Wal(fdb_txn *txn);
    fdb_txn * getEarliestTxn_Wal(fdb_txn *cur_txn);
    bool doesTxnExist_Wal(void);

    wal_dirty_t getDirtyStatus_Wal(void);
    size_t getSize_Wal(void);
    size_t getNumShards_Wal(void);
    size_t getNumFlushable_Wal(void);
    size_t getNumDocs_Wal(void);
    size_t getNumDeletes_Wal(void);
    size_t getDataSize_Wal(void);
    size_t getMemOverhead_Wal(void);
    bool tryRestore_Wal() {
        bool inverse = false;
        return isPopulated.compare_exchange_strong(inverse, true);
    }

private:
    fdb_status _insert_Wal(fdb_txn *txn,
                           struct _fdb_key_cmp_info *cmp_info,
                           fdb_doc *doc,
                           uint64_t offset,
                           wal_insert_by caller,
                           bool immediate_remove);
    fdb_status _find_Wal(fdb_txn *txn,
                         fdb_kvs_id_t kv_id,
                         struct _fdb_key_cmp_info *cmp_info,
                         Snapshot *shandle,
                         fdb_doc *doc,
                         uint64_t *offset);

    fdb_status _flush_Wal(void *dbhandle,
                          wal_flush_func *flush_func,
                          wal_get_old_offset_func *get_old_offset,
                          wal_flush_seq_purge_func *seq_purge_func,
                          wal_flush_kvs_delta_stats_func *delta_stats_func,
                          union wal_flush_items *flush_items,
                          bool by_compactor);

    void releaseItem_Wal(size_t shard_num, fdb_kvs_id_t kv_id,
                         struct wal_item *item);
    list_elem *_releaseItems_Wal(size_t shard_num, struct wal_item *item);

    fdb_status _close_Wal(wal_discard_t type, void *aux,
                          ErrLogCallback *log_callback);

    struct wal_kvs_snaps *_wal_get_kvs_snaplist(fdb_kvs_id_t kv_id);
    Snapshot * _wal_get_latest_snapshot(struct wal_kvs_snaps *slist);

    void _wal_snap_mark_flushed(void);

    // When a snapshot reader has called snapshotOpen_Wal(), the ref count
    // on the snapshot handle will be incremented
    bool _wal_snap_is_immutable(Snapshot *shandle) {
        return shandle->ref_cnt_kvs.load();
    }

    Snapshot * _wal_fetch_snapshot(fdb_kvs_id_t kv_id,
                                   _fdb_key_cmp_info *key_cmp_info);

    typedef enum _wal_update_type_t {
        _WAL_NEW_DEL, // A new deleted item inserted into WAL
        _WAL_NEW_SET, // A new non-deleted item inserted into WAL
        _WAL_SET_TO_DEL, // A set item updated to be deleted
        _WAL_DEL_TO_SET, // A deleted item updated to a set
        _WAL_DROP_DELETE, // A deleted item is de-duplicated or dropped
        _WAL_DROP_SET // A set item is de-duplicated or dropped
    } _wal_update_type;

    void _wal_update_stat(fdb_kvs_id_t kv_id,
                          _wal_update_type type);

    static bool _wal_item_partially_committed(fdb_txn *global_txn,
                                              struct list *active_txn_list,
                                              fdb_txn *current_txn,
                                              struct wal_item *item);

    struct wal_item *_wal_get_snap_item(struct wal_item_header *header,
                                        Snapshot *shandle);

    void _wal_free_item(struct wal_item *item, bool gotlock);
    /*
     * Given a key, return the version of the key which was valid at the
     * time of the given snapshot creation
     */
    static wal_item *getSnapItemHdr_Wal(struct wal_item_header *header,
                                        Snapshot *shandle);

    bool _wal_are_items_sorted(union wal_flush_items *flush_items);
    fdb_status _wal_do_flush(struct wal_item *item,
                             wal_flush_func *flush_func,
                             void *dbhandle,
                             struct avl_tree *stale_seqnum_list,
                             struct avl_tree *kvs_delta_stats);

    std::atomic<bool> isPopulated; // Set when WAL is first populated OR restored from disk
    std::atomic<uint32_t> size; // total # entries in WAL (uint32_t)
    std::atomic<uint32_t> num_flushable; // # flushable entries in WAL (uint32_t)
    std::atomic<uint64_t> datasize; // total data size in WAL (uint64_t)
    std::atomic<uint64_t> mem_overhead; // memory overhead of all WAL entries
    struct list txn_list; // list of active transactions
    wal_dirty_t wal_dirty;
    // Are there uncommitted or, committed but not flushed, Transactions..
    std::atomic<bool> unFlushedTransactions; //TODO:Transactional Snapshots
    // tree of all 'wal_item_header' (keys) in shard
    struct wal_shard *key_shards;
    // indexes 'wal_item's seq num in WAL shard
    struct wal_shard *seq_shards;
    size_t num_shards;
    // Global shared WAL Snapshot Data
    struct avl_tree wal_kvs_snap_tree;
    spin_t lock;
    FileMgr *file;
    DISALLOW_COPY_AND_ASSIGN(Wal);
};

struct wal_cursor {
    struct avl_node avl_merge; // avl node for merge sort across all shards
    struct wal_item *item; // pointer to the shared WAL snapshot item
};

class WalItr {
public:
    /**
     * Initialize a WAL iterator snapshot by creating a barrier to future writes
     * @param file - underlying ForestDB database file shared by all KV Stores
     * @param shandle - pointer to snap_handle created by snapshot_open
     * @param by_key - is the iteration done by key or by sequence number
     */
    WalItr(FileMgr *fileWal,
           Snapshot *shandle,
           bool by_key);

     ~WalItr();

     /**
      * Position the sharded WAL iterator to a key/seqnum greater than the query
      * if the queried key/seqnum does not exist.
      * @param wal_itr - the wal iterator snapshot whose cursor needs to be set.
      * @param wal_item - the avl pointer of the query wal_item.
      */
    struct wal_item *searchGreater_WalItr(struct wal_item *query_item);

     /**
      * Position the sharded WAL iterator to a key/seqnum smaller than the query
      * if the queried key/seqnum does not exist.
      * @param wal_itr - the wal iterator snapshot whose cursor needs to be set.
      * @param wal_item - the pointer of the query wal_item.
      */
    struct wal_item *searchSmaller_WalItr(struct wal_item *query_item);

     /**
      * Position the sharded WAL iterator to the next key/seqnum than current pos
      * @param wal_itr - the wal iterator snapshot whose cursor needs to be set.
      */
    struct wal_item *next_WalItr(void);

     /**
      * Position the sharded WAL iterator to the previous key/seqnum from current pos
      * @param wal_itr - the wal iterator snapshot whose cursor needs to be set.
      */
    struct wal_item *prev_WalItr(void);
     /**
      * Position the sharded WAL iterator to the first key/seqnum in KV Store snapshot
      * @param wal_itr - the wal iterator snapshot whose cursor needs to be set.
      */
    struct wal_item *first_WalItr(void);
     /**
      * Position the sharded WAL iterator to the last key/seqnum in KV Store snapshot
      * @param wal_itr - the wal iterator snapshot whose cursor needs to be set.
      */
    struct wal_item *last_WalItr(void);

private:
    struct wal_item * _searchGreaterByKey_WalItr(struct wal_item *q);
    struct wal_item * _searchGreaterBySeq_WalItr(struct wal_item *q);
    struct wal_item * _searchSmallerByKey_WalItr(struct wal_item *q);
    struct wal_item * _searchSmallerBySeq_WalItr(struct wal_item *q);
    struct wal_item * _nextByKey_WalItr(void);
    struct wal_item * _nextBySeq_WalItr(void);
    struct wal_item * _prevByKey_WalItr(void);
    struct wal_item * _prevBySeq_WalItr(void);
    struct wal_item * _firstByKey_WalItr(void);
    struct wal_item * _firstBySeq_WalItr(void);
    struct wal_item * _lastByKey_WalItr(void);
    struct wal_item * _lastBySeq_WalItr(void);

    Wal *_wal; // Pointer to global WAL
    struct wal_shard *map_shards; // pointer to the shared WAL key/seq shards
    Snapshot *shandle; // Pointer to KVS snapshot handle.
    bool by_key; // if not set means iteration is by sequence number range
    bool multi_kvs; // single kv mode vs multi kv instance mode
    uint8_t direction; // forward/backward/none to avoid grabbing all locks
    size_t numCursors; // number of shared kvs snapshots from the global WAL
    struct avl_tree mergeTree; // AVL tree to perform merge-sort over mergeCursors
    struct wal_cursor *mergeCursors; // cursor to item from each snapshot's tree
    union {
        /**
         * Iterator's position of an in-memory snapshot
         * It points to the item of a given snapshot among multiple shared
         * in-memory snapshots
         */
        struct avl_node *cursorPos;
        /**
         * Iterator's position in a single, non-shared durable snapshot
         */
        struct wal_item *cursorItem;
    };
    struct wal_item *prevItem; // points to previous iterator item returned
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
