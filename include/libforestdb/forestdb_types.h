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

#ifndef _FDB_TYPES_H
#define _FDB_TYPES_H

#include <stdint.h>
#include "option.h"
#include "arch.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Status values returned by calling ForestDB APIs.
 */
typedef enum {
    /**
     * ForestDB operation success.
     */
    FDB_RESULT_SUCCESS = 0,
    /**
     * Invalid parameters to ForestDB APIs.
     */
    FDB_RESULT_INVALID_ARGS = -1,
    /**
     * Database open operation fails.
     */
    FDB_RESULT_OPEN_FAIL = -2,
    /**
     * Database file not found.
     */
    FDB_RESULT_NO_SUCH_FILE = -3,
    /**
     * Database write operation fails.
     */
    FDB_RESULT_WRITE_FAIL = -4,
    /**
     * Database read operation fails.
     */
    FDB_RESULT_READ_FAIL = -5,
    /**
     * Database close operation fails.
     */
    FDB_RESULT_CLOSE_FAIL = -6,
    /**
     * Database commit operation fails.
     */
    FDB_RESULT_COMMIT_FAIL = -7,
    /**
     * Memory allocation fails.
     */
    FDB_RESULT_ALLOC_FAIL = -8,
    /**
     * A key not found in database.
     */
    FDB_RESULT_KEY_NOT_FOUND = -9,
    /**
     * Read-only access violation.
     */
    FDB_RESULT_RONLY_VIOLATION = -10,
    /**
     * Database compaction fails.
     */
    FDB_RESULT_COMPACTION_FAIL = -11,
    /**
     * Database iterator operation fails.
     */
    FDB_RESULT_ITERATOR_FAIL = -12,
    /**
     * General database opertion fails.
     */
    FDB_RESULT_FAIL = -100
} fdb_status;

/**
 * Flags to be passed to fdb_open() API
     */
typedef uint32_t fdb_open_flags;
enum {
    /**
     * Create a new empty ForestDB file if it doesn't exist.
     */
    FDB_OPEN_FLAG_CREATE = 1,
    /**
     * Open the database in read only mode
     */
    FDB_OPEN_FLAG_RDONLY = 2
};


/**
 * Flag to enable / disable a sequence btree.
 */
typedef uint8_t fdb_seqtree_opt_t;
enum {
    FDB_SEQTREE_NOT_USE = 0,
    FDB_SEQTREE_USE = 1
};

/**
 * Durability options for ForestDB.
 */
typedef uint8_t fdb_durability_opt_t;
enum {
    /**
     * Synchronous commit through OS page cache.
     */
    FDB_DRB_NONE = 0x0,
    /**
     * Synchronous commit through the direct IO option to bypass
     * the OS page cache.
     */
    FDB_DRB_ODIRECT = 0x1,
    /**
     * Asynchronous commit through OS page cache.
     */
    FDB_DRB_ASYNC = 0x2,
    /**
     * Asynchronous commit through the direct IO option to bypass
     * the OS page cache.
     */
    FDB_DRB_ODIRECT_ASYNC = 0x3
};

/**
 * ForestDB config options that are passed to fdb_open API.
 */
typedef struct {
    /**
     * Chunk size that is used to build B+-tree at each level.
     */
    uint16_t chunksize;
    /**
     * Size of offset type in a database file.
     */
    uint16_t offsetsize;
    /**
     * Size of block that is a unit of IO operations
     */
    uint32_t blocksize;
    /**
     * Buffer cache size in bytes. If the size is not given, then the buffer
     * cache is disabled.
     */
    uint64_t buffercache_size;
    /**
     * WAL index size threshold in memory. It is set to 4096 entries by default.
     */
    uint64_t wal_threshold;
    /**
     * Abstract file raw IO APIs that allow a user to pass their
     * platform-specific raw IO implementation. If it is not given, it is
     * selected among Linux, Mac OS, and Windows.
     */
    struct filemgr_ops *fileops;
    /**
     * Flag to enable or disable a sequence B+-Tree.
     */
    fdb_seqtree_opt_t seqtree_opt;
    /**
     * Flag to enable synchronous or asynchronous commit options
     */
    fdb_durability_opt_t durability_opt;
    /**
     * Flags for fdb_open API. It can be used for specifying read-only mode.
     */
    uint32_t flags;
    /**
     * Maximum size of temporary buffer for compaction.
     */
    uint32_t compaction_buf_maxsize;
    /**
     * Auxiliary config options.
     */
    void *aux;
} fdb_config;

/**
 * ForestDB doc structure definition
 */
typedef struct fdb_doc_struct {
    /**
     * key length.
     */
    size_t keylen;
    /**
     * metadata length.
     */
    size_t metalen;
    /**
     * doc body length.
     */
    size_t bodylen;
    /**
     * Pointer to doc's key.
     */
    void *key;
#ifdef __FDB_SEQTREE
    /**
     * Sequence number assigned to a doc.
     */
    fdb_seqnum_t seqnum;
#endif
    /**
     * Pointer to doc's metadata.
     */
    void *meta;
    /**
     * Pointer to doc's body.
     */
    void *body;
} fdb_doc;

struct hbtrie;
struct btree;
struct filemgr;
struct btreeblk_handle;
struct docio_handle;
struct btree_blk_ops;

/**
 * Pointer type definition of a customized compare function.
 */
typedef int (*fdb_custom_cmp)(void *a, void *b);

/**
 * ForestDB database handle definition.
 */
typedef struct {
    /**
     * HB+-Tree Trie instance.
     */
    struct hbtrie *trie;
    /**
     * Sequence B+-Tree instance.
     */
    struct btree *seqtree;
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
     * ForestDB config.
     */
    fdb_config config;
    /**
     * Database header revision number.
     */
    uint64_t cur_header_revnum;
    /**
     * Last header's block id
     */
    uint64_t last_header_bid;
    /**
     * Database overall size.
     */
    uint64_t datasize;
    /**
     * Number of documents in database.
     */
    uint64_t ndocs;
    /**
     * Customized compare function.
     */
    fdb_custom_cmp cmp_func;
    /**
     * B+-Tree fanout degree.
     */
    uint16_t btree_fanout;
#ifdef __FDB_SEQTREE
    /**
     * Database's current sequence number.
     */
    fdb_seqnum_t seqnum;
#endif
} fdb_handle;

/**
 * ForestDB iterator option.
 */
typedef uint8_t fdb_iterator_opt_t;
enum {
    /**
     * Return both key and value through iterator.
     */
    FDB_ITR_NONE = 0x0,
    /**
     * Return key and its metadata only through iterator.
     */
    FDB_ITR_METAONLY = 0x1
};

struct hbtrie_iterator;
struct avl_tree;
struct avl_node;

/**
 * ForestDB iterator structure definition.
 */
typedef struct {
    /**
     * ForestDB database handle.
     */
    fdb_handle handle;
    /**
     * HB+-Tree Trie iterator instance.
     */
    struct hbtrie_iterator *hbtrie_iterator;
    /**
     * AVL tree for WAL entries.
     */
    struct avl_tree *wal_tree;
    /**
     * Cursor instance of AVL tree for WAL entries.
     */
    struct avl_node *tree_cursor;
    /**
     * Iterator end key.
     */
    void *end_key;
    /**
     * End key length.
     */
    size_t end_keylen;
    /**
     * Iterator option.
     */
    fdb_iterator_opt_t opt;

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
} fdb_iterator;

#ifdef __cplusplus
}
#endif

#endif
