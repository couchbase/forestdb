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
#include "partiallock.h"

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

typedef uint8_t snap_handle_type;
enum {
    /**
     * Normal type: both main index and WAL are in the same file.
     */
    FDB_SNAP_NORMAL = 0,
    /**
     * Compaction in progress: main index is in the old file, while WAL
     * is in the new file.
     */
    FDB_SNAP_COMPACTION = 1
};

struct snap_handle {
    /**
     * Lock to protect the reference count of cloned snapshots
     */
    spin_t lock;
    /**
     * Reference count to avoid copy in cloned snapshots
     */
    volatile uint16_t ref_cnt;
    /**
     * Type of the snapshot handle
     */
    snap_handle_type type;
    /**
     * Cache custom compare function from original handle
     */
    struct _fdb_key_cmp_info cmp_info;
    /**
     * AVL tree to store unflushed WAL entries of a snapshot by key range
     */
    struct avl_tree *key_tree;
    /**
     * AVL tree to store unflushed WAL entries of a snapshot by sequence number
     */
    struct avl_tree *seq_tree;
    /**
     * Local DB stats for cloned snapshots
     */
    struct kvs_stat stat;
};

fdb_status snap_init(struct snap_handle *shandle, fdb_kvs_handle *handle);
fdb_status snap_insert(struct snap_handle *shandle, fdb_doc *doc,
                        uint64_t offset);
fdb_status snap_find(struct snap_handle *shandle, fdb_doc *doc,
                      uint64_t *offset);
fdb_status snap_remove(struct snap_handle *shandle, fdb_doc *doc);
fdb_status snap_clone(struct snap_handle *in, fdb_seqnum_t in_seq,
                      struct snap_handle **out, fdb_seqnum_t snap_seq);
fdb_status snap_close(struct snap_handle *shandle);
fdb_status snap_get_stat(struct snap_handle *shandle, struct kvs_stat *stat);

#ifdef __cplusplus
}
#endif

#endif
