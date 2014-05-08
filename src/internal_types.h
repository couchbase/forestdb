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
struct snap_handle;

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
     * Error logging callback.
     */
    err_log_callback log_callback;
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
#ifdef __FDB_SEQTREE
    /**
     * Snapshot Information.
     */
    struct snap_handle *shandle;
    /**
     * Database's current sequence number.
     */
    fdb_seqnum_t seqnum;
    /**
     * Database's max sequence number for snapshot or rollback
     */
    fdb_seqnum_t max_seqnum;
    /**
     * Virtual filename (DB instance filename given by users).
     * Only used when compaction daemon is enabled.
     */
    char *filename;
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
