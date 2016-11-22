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
class BnodeMgr;
class BTree;
class BtreeV2;
// Windows MSVC has a buggy standard library for std::atomic<const char *>
// Any attempts to set a const char * using atomic::store()
// method fails since atomic::store() is defined as
// _Atomic_address::store(void *) which breaks const qualifier
// So to work around this, declare func_name_t as char * on windows only
// compatible with __FUNCTION__ type.
#if defined(WIN32) || defined(_WIN32)
    #define BEGIN_HANDLE_BUSY(H) ((H)->beginBusy(__FUNCTION__))
    #define END_HANDLE_BUSY(H)   ((H)->endBusy(__FUNCTION__))
    typedef char * func_name_t;
#else
    #define BEGIN_HANDLE_BUSY(H)  ((H)->beginBusy(__func__))
    #define END_HANDLE_BUSY(H)    ((H)->endBusy(__func__))
    typedef const char * func_name_t;
#endif // WIN32

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
     * Reset index and doc I/O handles.
     */
    void resetIOHandles();
    /**
     * Free and release index and doc I/O handles.
     * @param useBtreeV2format - indicates which I/O handles needs freeing.
     * @return FDB_RESULT_ALLOC_FAIL - as the default return type.
     */
    fdb_status freeIOHandles(bool useBtreeV2format);

    /**
     * Initialize the root handle.
     */
    void initRootHandle();

    /**
     * Initialize the handle busy pointer
     */
    void initBusy();

    /**
     * Store function name using the current handle
     * If handle is already busy, log the current function using it.
     */
    bool beginBusy(func_name_t funcName);

    /**
     * Release the handle to indicate end of its use in current function.
     */
    bool endBusy(func_name_t funcName);

    /**
     * Temporarily let other callers use the handle
     *    (used for compaction callbacks which may call ForestDB api)
     */
    func_name_t suspendBusy(void);

    /**
     * Let the temporarily suspended thread resume the ownership
     */
    bool resumeBusy(func_name_t funcName);

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
    union {
        BtreeV2 *staletreeV2; // for BtreeV2 format
        BTree *staletree;
    };
    /**
     * Sequence B+-Tree instance.
     */
    union {
        BtreeV2 *seqtreeV2; // single KV instance mode with BtreeV2
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
    union {
        /**
         * B+-Tree handle instance.
         */
        BTreeBlkHandle *bhandle;
        /**
         * BtreeV2 Node Manager instance.
         */
        BnodeMgr *bnodeMgr;
    };
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
     * Why Atomic?
     * In Writer's commit, getOldestActiveHeader() from reclaimReusableBlocks
     * can race with sync_db_header of any reader thread api like fdb_get
     */
    std::atomic<uint64_t> last_hdr_bid;
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
    Snapshot *shandle;
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
    /**
     * Atomic flag to detect if handles are being shared among threads.
     */
    std::atomic<func_name_t> handle_busy;

    void copyFromOtherHandle(const FdbKvsHandle& kv_handle);
};
