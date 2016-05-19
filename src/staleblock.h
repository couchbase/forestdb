/* -*- Mode: C++; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2015 Couchbase, Inc
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

#ifndef _FDB_STALEBLOCK_H
#define _FDB_STALEBLOCK_H

#include "libforestdb/fdb_types.h"
#include "libforestdb/fdb_errors.h"
#include "common.h"

#include "filemgr.h"
#include "avltree.h"

/**
 * Gather stale region info from stale list and store it as a system doc.
 *
 * @param handle Pointer to ForestDB KV store handle.
 * @param revnum Header revision number that will be stored as a key in stale tree.
 * @param prev_hdr Currently up-to-date header BID.
 * @param kv_info_offset Currently up-to-date KVS header doc offset.
 * @param seqnum Currently up-to-date seq number of the default KVS.
 * @param e_last Last (rightmost) stale region that should not be gathered at this time.
 * @param from_mergetree If true, gather stale regions from merge-tree (which contains
 *        remaining items after block reclaim) instead of stale list.
 * @return void.
 */
void fdb_gather_stale_blocks(fdb_kvs_handle *handle,
                             filemgr_header_revnum_t revnum,
                             bid_t prev_hdr,
                             uint64_t kv_info_offset,
                             fdb_seqnum_t seqnum,
                             struct list_elem *e_last,
                             bool from_mergetree);

struct reusable_block {
    bid_t bid;
    bid_t count;
};

typedef struct {
    size_t n_blocks;
    struct reusable_block *blocks;
} reusable_block_list;

typedef struct {
    filemgr_header_revnum_t revnum;
    bid_t bid;
} stale_header_info;

// in-memory structure for stale info
// (corresponding to a commit, an entry of stale-block-tree)
struct stale_info_commit {
    struct avl_node avl;
    // commit revision number
    filemgr_header_revnum_t revnum;
    // list of system docs (there will be more than one doc)
    struct list doc_list;
};

// in-memory structure for stale info
// (corresponding to a system doc)
struct stale_info_entry {
    struct list_elem le;
    // document body
    void *ctx;
    // document offset
    uint64_t offset;
    // actual document length on disk
    uint64_t doclen;
    // length of 'ctx'
    uint32_t ctxlen;
    // length of compressed 'ctx'
    uint32_t comp_ctxlen;
};

/**
 * Gather and merge all stale regions up to 'stale_header', and then return the list
 * of reusable blocks.
 *
 * @param handle Pointer to ForestDB KV store handle.
 * @param stale_header Revision number and block ID of a header. All stale regions
 *        corresponding to commit headers whose seq number is equal to or smaller
 *        than that of 'stale_header' are gathered and merged for block reusing.
 * @return List of reusable blocks.
 */
reusable_block_list fdb_get_reusable_block(fdb_kvs_handle *handle,
                                           stale_header_info stale_header);

/**
 * Load all system documents pointed to by stale tree into memory.
 *
 * @param handle Pointer to ForestDB KV store handle.
 * @return void.
 */
void fdb_load_inmem_stale_info(fdb_kvs_handle *handle);

/**
 * Remove all stale-tree entries since the rollback point.
 *
 * @param handle Pointer to ForestDB KV store handle.
 * @param cur_revnum Revision number of the header that will be appended next.
 * @return void.
 */
void fdb_rollback_stale_blocks(fdb_kvs_handle *handle,
                               filemgr_header_revnum_t cur_revnum);

#endif /* _FDB_STALEBLOCK_H */

