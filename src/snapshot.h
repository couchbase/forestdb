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

#ifndef _FDB_SNAPSHOT_H
#define _FDB_SNAPSHOT_H

#include <stdint.h>
#include "internal_types.h"
#include "hash.h"
#include "list.h"
#include "wal.h"
#include "avltree.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SNAP_ITEM_IN_NEW_FILE (0x1)
struct snap_wal_entry {
    void *key;
    fdb_seqnum_t seqnum;
    wal_item_action action;
    uint8_t flag;
    uint16_t keylen;
    uint64_t offset;
    struct avl_node avl;
    struct avl_node avl_seq;
};

struct snap_handle {
    /**
     * Snapshot marker indicating highest sequence number
     */
     fdb_seqnum_t max_seqnum;
    /**
     * AVL tree to store unflushed WAL entries of a snapshot by key range
     */
     struct avl_tree *key_tree;
    /**
     * AVL tree to store unflushed WAL entries of a snapshot by sequence number
     */
     struct avl_tree *seq_tree;
};

wal_result snap_init(struct snap_handle *shandle, fdb_handle *handle);
wal_result snap_insert(struct snap_handle *shandle, fdb_doc *doc,
                        uint64_t offset);
wal_result snap_find(struct snap_handle *shandle, fdb_doc *doc,
                      uint64_t *offset);
wal_result snap_remove(struct snap_handle *shandle, fdb_doc *doc);
wal_result snap_close(struct snap_handle *shandle);

#ifdef __cplusplus
}
#endif

#endif
