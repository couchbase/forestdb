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

#ifndef _JSAHN_BTREEBLOCK_H
#define _JSAHN_BTREEBLOCK_H

#include "filemgr.h"
#include "list.h"
#include "avltree.h"
#include "btree.h"
#include "libforestdb/fdb_errors.h"

#ifdef __cplusplus
extern "C" {
#endif

struct btreeblk_block;

struct btreeblk_subblocks{
    bid_t bid;
    uint32_t sb_size;
    uint16_t nblocks;
    uint8_t *bitmap;
};

struct btreeblk_handle{
    uint32_t nodesize;
    uint16_t nnodeperblock;
    uint64_t nlivenodes;
    struct list alc_list;
    struct list read_list;
    struct filemgr *file;
    err_log_callback *log_callback;

#ifdef __BTREEBLK_READ_TREE
    struct avl_tree read_tree;
#endif
#ifdef __BTREEBLK_BLOCKPOOL
    struct list blockpool;
#endif

#ifdef __BTREEBLK_CACHE
    uint16_t bin_size;
    struct list recycle_bin;
    struct btreeblk_block *cache[BTREEBLK_CACHE_LIMIT];
#endif

    uint32_t nsb;
    struct btreeblk_subblocks *sb;
    struct avl_tree *dirty_snapshot;
};

struct btree_blk_ops *btreeblk_get_ops();
void btreeblk_init(struct btreeblk_handle *handle, struct filemgr *file, int nodesize);
void btreeblk_reset_subblock_info(struct btreeblk_handle *handle);
void btreeblk_free(struct btreeblk_handle *handle);
void btreeblk_discard_blocks(struct btreeblk_handle *handle);
fdb_status btreeblk_end(struct btreeblk_handle *handle);

fdb_status btreeblk_create_dirty_snapshot(struct btreeblk_handle *handle);
void btreeblk_clone_dirty_snapshot(struct btreeblk_handle *dst,
                                   struct btreeblk_handle *src);
void btreeblk_free_dirty_snapshot(struct btreeblk_handle *handle);

#ifdef __cplusplus
}
#endif

#endif
