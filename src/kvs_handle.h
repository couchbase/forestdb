/* -*- Mode: C++; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2016 Couchbase, Inc
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

#include <string>

#include "arch.h"
#include "common.h"
#include "internal_types.h"

class BTreeBlkHandle;
class BTree;

/**
 * ForestDB KV store handle definition.
 */
class FdbKvsHandle {

public:

    // Default constructor
    FdbKvsHandle();

    // Copy constructor
    FdbKvsHandle(const FdbKvsHandle& kv_handle);

    // Destructor
    ~FdbKvsHandle();

    // Operator=
    FdbKvsHandle& operator=(const FdbKvsHandle& kv_handle);

    // Free the KVS info memory.
    void freeKvsInfo();

    /**
     * Create the KVS info instance.
     *
     * @param root_handle Pointer to the root handle instance.
     * @param kvs_name KV Store's name.
     */
    void createKvsInfo(FdbKvsHandle *root_handle,
                       const char *kvs_name);

    /**
     * Initialize the root handle.
     */
    void initRootHandle();


    // TODO: Move these variables to private members as we refactor the code in C++.

    /**
     * ForestDB KV store level config.
     */
    fdb_kvs_config kvs_config;
    /**
     * KV store information.
     */
    KvsInfo *kvs;
    /**
     * Operational statistics for this kv store.
     */
    KvsOpsStat *op_stats;
    /**
     * Pointer to the corresponding file handle.
     */
    FdbFileHandle *fhandle;
    /**
     * HB+-Tree Trie instance.
     */
    HBTrie *trie;
    /**
     * Stale block B+-Tree instance.
     * Maps from 'commit revision number' to 'stale block info' system document.
     */
    BTree *staletree;
    /**
     * Sequence B+-Tree instance.
     */
    union {
        BTree *seqtree; // single KV instance mode
        HBTrie *seqtrie; // multi KV instance mode
    };
    /**
     * File manager instance.
     */
    FileMgr *file;
    /**
     * Doc IO handle instance.
     */
    DocioHandle *dhandle;
    /**
     * B+-Tree handle instance.
     */
    BTreeBlkHandle *bhandle;
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
    ErrLogCallback log_callback;
    /**
     * File header revision number.
     */
    std::atomic<uint64_t> cur_header_revnum;
    /**
     * Header revision number of rollback point.
     */
    uint64_t rollback_revnum;
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
    std::string filename;
    /**
     * Transaction handle.
     */
    fdb_txn *txn;
    /**
     * Atomic flag to detect if handles are being shared among threads.
     */
    std::atomic<uint8_t> handle_busy;
    /**
     * Flag that indicates whether this handle made dirty updates or not.
     */
    uint8_t dirty_updates;
    /**
     * List element that will be inserted into 'handles' list in the root handle.
     */
    struct kvs_opened_node *node;
    /**
     * Number of active iterator instances created from this handle
     */
    uint32_t num_iterators;

private:

    void copyFromOtherHandle(const FdbKvsHandle& kv_handle);
};
