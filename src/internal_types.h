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

#ifndef _INTERNAL_TYPES_H
#define _INTERNAL_TYPES_H

#include <stdint.h>

#include "libforestdb/fdb_types.h"
#include "common.h"
#include "avltree.h"

#ifdef __cplusplus
extern "C" {
#endif

struct hbtrie;
struct btree;
struct filemgr;
struct btreeblk_handle;
struct docio_handle;
struct btree_blk_ops;
struct snap_handle;

#define OFFSET_SIZE (sizeof(uint64_t))

#define FDB_MAX_KEYLEN_INTERNAL (65520)

/**
 * Error logging callback struct definition.
 */
typedef struct {
    /**
     * Error logging callback function.
     */
    fdb_log_callback callback;
    /**
     * Application-specific context data that is passed to the logging callback
     * function.
     */
    void *ctx_data;
} err_log_callback;

typedef struct _fdb_transaction fdb_txn;

typedef uint64_t fdb_kvs_id_t;

typedef uint8_t kvs_type_t;
enum {
    KVS_ROOT = 0,
    KVS_SUB = 1
};

struct list;
struct kvs_opened_node;

/**
 * KV store info for each handle.
 */
struct kvs_info {
    /**
     * KV store type.
     */
    kvs_type_t type;
    /**
     * KV store ID.
     */
    fdb_kvs_id_t id;
    /**
     * Pointer to root handle.
     */
    fdb_kvs_handle *root;
};

/**
 * Attributes in KV store statistics.
 */
typedef enum {
    KVS_STAT_NLIVENODES,
    KVS_STAT_NDOCS,
    KVS_STAT_DATASIZE,
    KVS_STAT_WAL_NDOCS,
    KVS_STAT_WAL_NDELETES
} kvs_stat_attr_t;

/**
 * KV store statistics.
 */
struct kvs_stat {
    /**
     * The number of live index nodes.
     */
    uint64_t nlivenodes;
    /**
     * The number of documents.
     */
    uint64_t ndocs;
    /**
     * The amount of space occupied by documents.
     */
    uint64_t datasize;
    /**
     * The number of documents in WAL.
     */
    uint64_t wal_ndocs;
    /**
     * The number of deleted documents in WAL.
     */
    uint64_t wal_ndeletes;
};

#define FHANDLE_ROOT_OPENED (0x1)
#define FHANDLE_ROOT_INITIALIZED (0x2)
#define FHANDLE_ROOT_CUSTOM_CMP (0x4)
/**
 * ForestDB file handle definition.
 */
struct _fdb_file_handle {
    /**
     * The root KV store handle.
     */
    fdb_kvs_handle *root;
    /**
     * List of opened default KV store handles
     * (except for the root handle).
     */
    struct list *handles;
    /**
     * List of custom compare functions assigned by user
     */
    struct list *cmp_func_list;
    /**
     * Flags for the file handle.
     */
    uint64_t flags;
    /**
     * Spin lock for the file handle.
     */
    spin_t lock;
};

/**
 * ForestDB KV store key comparison callback context
 */
struct _fdb_key_cmp_info {
    /**
     * ForestDB KV store level config.
     */
    fdb_kvs_config kvs_config;
    /**
     * KV store information.
     */
    struct kvs_info *kvs;
};

/**
 * ForestDB KV store handle definition.
 */
struct _fdb_kvs_handle {
    /**
     * ForestDB KV store level config. (Please retain as first struct member)
     */
    fdb_kvs_config kvs_config;
    /**
     * KV store information. (Please retain as second struct member)
     */
    struct kvs_info *kvs;
    /**
     * Pointer to the corresponding file handle.
     */
    fdb_file_handle *fhandle;
    /**
     * HB+-Tree Trie instance.
     */
    struct hbtrie *trie;
    /**
     * Document key B+-Tree instance.
     * Used for custom compare function of variable length key
     */
    struct btree *idtree;
    /**
     * Sequence B+-Tree instance.
     */
    union {
        struct btree *seqtree; // single KV instance mode
        struct hbtrie *seqtrie; // multi KV instance mode
    };
    /**
     * File manager instance.
     */
    struct filemgr *file;
    /**
     * New file manager instance created during compaction.
     */
    struct filemgr *new_file;
    /**
     * Doc IO handle instance.
     */
    struct docio_handle *dhandle;
    /**
     * New doc IO handle instance created during compaction.
     */
    struct docio_handle *new_dhandle;
    /**
     * B+-Tree handle instance.
     */
    struct btreeblk_handle *bhandle;
    /**
     * B+-Tree block operation handle.
     */
    struct btree_blk_ops *btreeblkops;
    /**
     * File manager IO operation handle.
     */
    struct filemgr_ops *fileops;
    /**
     * ForestDB file level config.
     */
    fdb_config config;
    /**
     * Error logging callback.
     */
    err_log_callback log_callback;
    /**
     * File header revision number.
     */
    uint64_t cur_header_revnum;
    /**
     * Last header's block ID.
     */
    uint64_t last_hdr_bid;
    /**
     * Block ID of a header created with most recent WAL flush.
     */
    uint64_t last_wal_flush_hdr_bid;
    /**
     * File offset of a document containing KV instance info.
     */
    uint64_t kv_info_offset;
    /**
     * Snapshot Information.
     */
    struct snap_handle *shandle;
    /**
     * KV store's current sequence number.
     */
    fdb_seqnum_t seqnum;
    /**
     * KV store's max sequence number for snapshot or rollback.
     */
    fdb_seqnum_t max_seqnum;
    /**
     * Virtual filename (DB instance filename given by users).
     */
    char *filename;
    /**
     * Transaction handle.
     */
    fdb_txn *txn;
    /**
     * Flag that indicates whether this handle made dirty updates or not.
     */
    uint8_t dirty_updates;
    /**
     * List element that will be inserted into 'handles' list in the root handle.
     */
    struct kvs_opened_node *node;
#ifdef _TRACE_HANDLES
    struct avl_node avl_trace;
#endif
};

struct hbtrie_iterator;
struct avl_tree;
struct avl_node;

/**
 * ForestDB iterator cursor movement direction
 */
typedef uint8_t fdb_iterator_dir_t;
enum {
    /**
     * Iterator cursor default.
     */
    FDB_ITR_DIR_NONE = 0x00,
    /**
     * Iterator cursor moving forward
     */
    FDB_ITR_FORWARD = 0x01,
    /**
     * Iterator cursor moving backwards
     */
    FDB_ITR_REVERSE = 0x02
};

/**
 * ForestDB iterator status
 */
typedef uint8_t fdb_iterator_status_t;
enum {
    /**
     * The last returned doc was retrieved from the main index.
     */
    FDB_ITR_IDX = 0x00,
    /**
     * The last returned doc was retrieved from the WAL.
     */
    FDB_ITR_WAL = 0x01
};

/**
 * ForestDB iterator structure definition.
 */
struct _fdb_iterator {
    /**
     * ForestDB KV store handle.
     */
    fdb_kvs_handle *handle;
    /**
     * HB+Trie iterator instance.
     */
    struct hbtrie_iterator *hbtrie_iterator;
    /**
     * B+Tree iterator for sequence number iteration
     */
    struct btree_iterator *seqtree_iterator;
    /**
     * HB+Trie iterator for sequence number iteration
     * (for multiple KV instance mode)
     */
    struct hbtrie_iterator *seqtrie_iterator;
    /**
     * Current seqnum pointed by the iterator.
     */
    fdb_seqnum_t _seqnum;
    /**
     * AVL tree for WAL entries.
     */
    struct avl_tree *wal_tree;
    /**
     * Cursor instance of AVL tree for WAL entries.
     */
    struct avl_node *tree_cursor;
    /**
     * Start position of AVL tree cursor.
     */
    struct avl_node *tree_cursor_start;
    /**
     * Previous position of AVL tree cursor.
     */
    struct avl_node *tree_cursor_prev;
    /**
     * Iterator start key.
     */
    void *start_key;
    union {
        /**
         * Iterator start seqnum.
         */
        fdb_seqnum_t start_seqnum;
        /**
         * Start key length.
         */
        size_t start_keylen;
    };
    /**
     * Iterator end key.
     */
    void *end_key;
    union {
        /**
         * Iterator end seqnum.
         */
        fdb_seqnum_t end_seqnum;
        /**
         * End key length.
         */
        size_t end_keylen;
    };
    /**
     * Iterator option.
     */
    fdb_iterator_opt_t opt;
    /**
     * Iterator cursor direction status.
     */
    fdb_iterator_dir_t direction;
    /**
     * The last returned document info.
     */
    fdb_iterator_status_t status;
    /**
     * Current key pointed by the iterator.
     */
    void *_key;
    /**
     * Length of key pointed by the iterator.
     */
    size_t _keylen;
    /**
     * Key offset.
     */
    uint64_t _offset;
    /**
     * Doc IO handle instance to the correct file.
     */
    struct docio_handle *_dhandle;
    /**
     * Cursor offset to key, meta and value on disk
     */
    uint64_t _get_offset;
};

struct wal_txn_wrapper;

/**
 * ForestDB transaction structure definition.
 */
struct _fdb_transaction {
    /**
     * ForestDB KV store handle.
     */
    fdb_kvs_handle *handle;
    /**
     * Block ID of the last header before the transaction begins.
     */
    uint64_t prev_hdr_bid;
    /**
     * List of dirty WAL items.
     */
    struct list *items;
    /**
     * Transaction isolation level.
     */
    fdb_isolation_level_t isolation;
    /**
     * Pointer to transaction wrapper.
     */
    struct wal_txn_wrapper *wrapper;
};

#ifdef __cplusplus
}
#endif

#endif
