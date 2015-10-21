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
 * @return void.
 */
void fdb_gather_stale_blocks(fdb_kvs_handle *handle,
                             filemgr_header_revnum_t revnum);

struct reusable_block {
    bid_t bid;
    bid_t count;
};

typedef struct {
    size_t n_blocks;
    struct reusable_block *blocks;
} reusable_block_list;

/**
 * Merge all stale region generated before commit header corresponding to
 * 'revnum_upto', and then return the list of reusable blocks.
 *
 * @param handle Pointer to ForestDB KV store handle.
 * @param revnum_upto Maximum header revision number that stale regions to be merged
 *        are belonged to.
 * @return List of reusable blocks.
 */
reusable_block_list fdb_get_reusable_block(fdb_kvs_handle *handle,
                                           filemgr_header_revnum_t revnum_upto);

#endif /* _FDB_STALEBLOCK_H */

