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
#include "option.h"
#include "arch.h"

#ifdef __cplusplus
extern "C" {
#endif

struct hbtrie;
struct btree;
struct filemgr;
struct btreeblk_handle;
struct docio_handle;
struct btree_blk_ops;

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
     * Clean up all the cache entries when a database file is closed.
     */
    uint8_t cleanup_cache_onclose;
    /**
     * Compress the body of documents using snappy.
     */
    uint8_t compress_document_body;
    /**
     * Auxiliary config options.
     */
    void *aux;
    /**
     * Customized compare function for fixed size key.
     */
    fdb_custom_cmp_fixed cmp_fixed;
    /**
     * Customized compare function for variable length key.
     */
    fdb_custom_cmp_variable cmp_variable;
} fdb_config;

/**
 * ForestDB database handle definition.
 */
struct _fdb_handle {
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
     * B+-Tree fanout degree.
     */
    uint16_t btree_fanout;
#ifdef __FDB_SEQTREE
    /**
     * Database's current sequence number.
     */
    fdb_seqnum_t seqnum;
#endif
};

struct hbtrie_iterator;
struct avl_tree;
struct avl_node;

/**
 * ForestDB iterator structure definition.
 */
struct _fdb_iterator {
    /**
     * ForestDB database handle.
     */
    fdb_handle handle;
    /**
     * HB+-Tree Trie iterator instance.
     */
    struct hbtrie_iterator *hbtrie_iterator;
    /**
     * B-Tree iterator for custom compare function
     */
     struct btree_iterator *idtree_iterator;
    /**
     * B-Tree iterator for sequence number iteration
     */
     struct btree_iterator *seqtree_iterator;
    /**
     * Current seqnum pointed by the iterator.
     */
    fdb_seqnum_t _seqnum;
    /**
     * Iterator end seqnum.
     */
    fdb_seqnum_t end_seqnum;
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
};

#ifdef __cplusplus
}
#endif

#endif
