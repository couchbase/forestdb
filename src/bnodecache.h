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

#include <stdio.h>
#include <stdlib.h>

#include <algorithm>
#include <functional>
#include <list>
#include <map>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include "libforestdb/fdb_types.h"

#include "atomic.h"
#include "bnode.h"
#include "common.h"
#include "list.h"

// Forward declaration
class FileMgr;

/**
 * Index Block Meta structure that is suffixed at the end of
 * every raw Bnode when written to file.
 */
struct IndexBlkMeta {
    IndexBlkMeta() {
        nextBid = BLK_NOT_FOUND;
        sbBmpRevnumHash = 0;
        memset(reserved, 0x0, 5);
        marker = BLK_MARKER_BNODE;
    }

    void set(bid_t _bid, uint64_t _sb_revnum) {
        nextBid = _endian_encode(_bid);
        sbBmpRevnumHash = _sb_revnum & 0xffff;
        sbBmpRevnumHash = _endian_encode(sbBmpRevnumHash);
        marker = BLK_MARKER_BNODE;
    }

    void decode() {
        nextBid = _endian_decode(nextBid);
        sbBmpRevnumHash = _endian_decode(sbBmpRevnumHash);
    }

    bid_t nextBid;
    uint16_t sbBmpRevnumHash;
    uint8_t reserved[5];
    uint8_t marker;
};

/**
 * Shard Bnodecache instance
 */
class BnodeCacheShard {
public:
    BnodeCacheShard(size_t _id)
        : id(_id)
    {
        spin_init(&lock);
        list_init(&cleanNodes);
    }

    ~BnodeCacheShard() {
        for (auto entry : allNodes) {
            delete entry.second;
        }
        spin_destroy(&lock);
    }

private:
    friend class BnodeCacheMgr;
    friend class FileBnodeCache;

    size_t getId() const {
        return id;
    }

    bool empty() {
        // Caller should grab the shard lock before calling this function
        return list_empty(&cleanNodes) && dirtyIndexNodes.empty();
    }

    // Shard id
    size_t id;
    // Lock to synchronize access to cleanNodes, dirtyIndexNodes, allNodes
    spin_t lock;
    // LRU list of clean index nodes
    struct list cleanNodes;
    // Tree map of dirty index nodes
    std::map<cs_off_t, Bnode*> dirtyIndexNodes;
    // Hashtable of all the btree nodes belonging to this shard
    std::unordered_map<cs_off_t, Bnode*> allNodes;
};

/**
 * File Bnodecache instance
 */
class FileBnodeCache {
public:
    FileBnodeCache(std::string fname, FileMgr* file, size_t num_shards);

    ~FileBnodeCache() { }

    /* Fetch filename that the bnode cache instance is associated with */
    const std::string& getFileName(void) const;

    /* Fetch the filemgr instance for the bnode cache */
    FileMgr* getFileManager(void) const;

    /* Fetch the Reference count of the file bnode cache instance */
    uint32_t getRefCount(void) const;

    /* Fetch the number of victims selected for eviction */
    uint64_t getNumVictims(void) const;

    /* Fetch the number of items in the bnode cache */
    uint64_t getNumItems(void) const;

    /* Fetch the total number of items written to the bnode cache */
    uint64_t getNumItemsWritten(void) const;

    /* Get the last time of access for this bnode cache */
    uint64_t getAccessTimestamp(void) const;

    /* Get the number of shards for this bnode cache */
    size_t getNumShards(void) const;

    /* Update last time of access of this bnode cache */
    void setAccessTimestamp(uint64_t timestamp);

    /**
     * Check if a file bnode cache is empty of not.
     * @return true If a file bnode cache is empty
     */
    bool empty();

    /* Acquire the locks of all shards within this bnode cache */
    void acquireAllShardLocks();

    /* Release the locks of all shards within this bnode cache */
    void releaseAllShardLocks();

    /* Sets eviction in progress flag */
    bool setEvictionInProgress(bool to);

private:
    friend class BnodeCacheMgr;

    const std::string filename;
    // File manager instance for the file
    FileMgr* curFile;
    // Shards of the bnode cache for a file
    std::vector<std::unique_ptr<BnodeCacheShard>> shards;

    std::atomic<uint32_t> refCount;
    std::atomic<uint64_t> numVictims;
    std::atomic<uint64_t> numItems;
    std::atomic<uint64_t> numItemsWritten;
    std::atomic<uint64_t> accessTimestamp;

    // Flag if eviction is running on this victim
    std::atomic<bool> evictionInProgress;
};

typedef std::pair<Bnode*, cs_off_t> bnode_offset_t;

/**
 * The BnodeCacheMgr class will be responsible for handling all
 * the bnode cache operations for every file, memory management
 * for the bnode cache and the eviction operations.
 */
class BnodeCacheMgr {
public:
    /**
     * Instantiate the bnode cache manager
     *
     * @param cache_size Allowed buffer cache size in bytes.
     * @param flush_limit Maximum amount of dirty bnode memory
     *                    to be flushed.
     */
     static BnodeCacheMgr* init(uint64_t cache_size, uint64_t flush_limit);

     /**
      * Get the singleton instance of the bnode cache manager.
      */
     static BnodeCacheMgr* get();

     /**
      * Release all the resources including memory allocated
      * and destroy the bnode cache manager.
      */
     static void destroyInstance();

     /**
      * Removes dirty bnodes (not written to disk) and clean bnodes
      * for a file and the file entry itself from the global file list,
      * if and only if a BnodeCacheMgr instance is available.
      *
      * @param file Pointer to the file manager instance
      */
     static void eraseFileHistory(FileMgr* file);

    /**
     * Fetches bnode at the specified offset.
     *
     * @param file Pointer to the FileMgr instance
     * @param node Pointer reference to the retrieved bnode
     * @param offset Offset at which the bnode is read
     *
     * @returns the number of bytes that read from the cache
     */
    int read(FileMgr* file, Bnode** node, cs_off_t offset);

    /**
     * Writes/overwrites a btree node at the specified offset.
     *
     * @param file Pointer to the FileMgr instance
     * @param node Pointer to the bnode that is copied at the specfied offset
     * @param offset Offset at which the bnode is written
     *
     * @returns the number of bytes written into the cache
     */
    int write(FileMgr* file, Bnode* node, cs_off_t offset);

    /**
     * Issues writes on the vector of btree nodes at the specified offsets.
     *
     * @param file Pointer to the FileMgr instance
     * @param nodes Vector of bnode and offset pairs
     *
     * @returns the number of bytes written into the cache
     */
    int writeMulti(FileMgr* file, std::vector<bnode_offset_t> &nodes);

    /**
     * Flushes all dirty nodes in the bnodecache, typically upon commit.
     *
     * @param file Pointer to the FileMgr instance
     *
     * @returns FDB_RESULT_SUCCESS on success
     */
    fdb_status flush(FileMgr* file);

    /**
     * Adds meta information at the end of the last block, specified
     * through the block id.
     *
     * @param file Pointer to the FileMgr instance
     * @param bid Last block's bid
     *
     * @returns FDB_RESULT_SUCCESS on success
     */
    fdb_status addLastBlockMeta(FileMgr* file, bid_t bid);

    /**
     * Removes the bnode from the cache iff the ref count is less
     * than or equal to one.
     *
     * @param file Pointer to the FileMgr instance
     * @param node Pointer to the Bnode
     *
     * @returns FDB_RESULT_SUCCESS on success
     */
    fdb_status invalidateBnode(FileMgr* file, Bnode* node);

    /**
     * Create a file block cache for a given file
     *
     * @param file Pointer to a file manager instance
     *
     * @return Pointer to a file bnode cache instance
     *
     */
    FileBnodeCache* createFileBnodeCache(FileMgr* file);

    /**
     * Free a given file bnode cache and its allocated resources
     *
     * @param fcache Pointer to the file bnode cache to be freed
     * @param force Flag indicating if a file bnode cache should be
     *              freed even if it is still referenced or not empty
     *
     * @return True if a given file bnode cache is freed successfully
     */
    bool freeFileBnodeCache(FileBnodeCache* fcache, bool force = false);

    /**
     * Discard all the dirty bnodes for a given file from the bnode cache.
     * Note that those dirty bnodes are not written to disk.
     *
     * @param file Pointer to the file manager instance
     */
    void removeDirtyBnodes(FileMgr* file);

    void updateBnodeCacheLimit(uint64_t to) {
        bnodeCacheLimit.store(to);
    }

    void updateBnodeCacheFlushLimit(uint64_t to) {
        flushLimit.store(to);
    }

    /**
     * Fetch the current memory usage by the bnodeCache.
     */
    uint64_t getMemoryUsage() {
        return bnodeCacheCurrentUsage.load();
    }

private:
    /**
     * Constructor
     *
     * @param cache_size Allowed buffer cache size in bytes.
     * @param flush_limit Maximum amount of dirty bnode memory
     *                    to be flushed.
     */
    BnodeCacheMgr(uint64_t cache_size, uint64_t flush_limit);

    /**
     * Destructor
     */
    ~BnodeCacheMgr();

    /**
     * Function to update the config parameters
     *
     * @param cache_size Allowed buffer cache size in bytes.
     * @param flush_limit Maximum amount of dirty bnode memory
     *                    to be flushed.
     */
    void updateParams(uint64_t cache_size, uint64_t flush_limit);


    /**
     * Discard all the clean bnodes for a given file from the bnode cache.
     *
     * @param file Pointer to the file manager instance
     */
    void removeCleanBnodes(FileMgr* file);

    /**
     * Remove a given file from the bnode cache's global file list.
     *
     * @param file Pointer to the file manager instance
     *
     * @return True upon success
     */
    bool removeFile(FileMgr* file);

     /**
      * Create a file block cache for a given file
      *
      * @param file Pointer to a file manager instance
      *
      * @return Pointer to a file bnode cache instance
      */
    FileBnodeCache* createFileBnodeCache_UNLOCKED(FileMgr* file);

    /**
     * Fetch bnode from file
     *
     * @param file Pointer to file manager instance
     * @param node Pointer reference to the retrieved bnode
     * @param offset offset where the the bnode is to be retrieved from
     *
     * @return FDB_RESULT_SUCCESS on success.
     */
    fdb_status fetchFromFile(FileMgr* file,
                             Bnode** node,
                             cs_off_t offset);

    /**
     * Flush some dirty bnodes from a given file bnode cache
     *
     * @param fcache Pointer to the file bnode cache whose dirty nodes
     *               are to be flushed
     * @param sync True if dirty nodes should be flushed into disk
     * @param flush_all True if all the dirty nodes should be flushed
     *
     * @return FDB_RESULT_SUCCESS if flush is successful
     */
    fdb_status flushDirtyIndexNodes(FileBnodeCache* fcache,
                                    bool sync,
                                    bool flush_all);

    /**
     * Prepare the resource deallocation for a given file bnode cache
     *
     * @param fcache Pointer to the file bnode cache to be prepared for
     *               deallocation
     *
     * @return True if a given file bnode cache is ready for deallocation
     */
    bool prepareDeallocationForFileBnodeCache(FileBnodeCache* fcache);

    /**
     * Clean up all file bnode caches that are no longer valid
     */
    void cleanUpInvalidFileBnodeCaches();

    /**
     * Perform cache eviction
     *
     * @param node_to_protect Bnode that should not be evicted during this call.
     */
    void performEviction(Bnode *node_to_protect);

    /**
     * Choose a file bnode cache that is going to be a victim for eviction
     *
     * @return Pointer to a file bnode cache that is chosen as an eviction victim
     */
    FileBnodeCache* chooseEvictionVictim();

    /**
     * Removes select bnodes from the file's bnodecache: dirty/clean.
     * Invoked in-case of failure within writeMulti API.
     *
     * @param file Pointer to FileMgr instance
     * @param nodes Vector of bnodes to be discarded.
     */
    void removeSelectBnodes(FileMgr* file, std::vector<Bnode*> &nodes);

private:
    struct WriteCachedDataArgs {
        WriteCachedDataArgs(FileBnodeCache* _fcache,
                            size_t temp_buf_size,
                            bool _flush_all) :
            fcache(_fcache),
            temp_buf(std::move(new uint8_t[temp_buf_size])),
            batch_write_offset(0),
            temp_buf_pos(0),
            size_to_append(0), cur_offset(0),
            data_to_append(nullptr),
            flush_all(_flush_all) { }

        FileBnodeCache* fcache;
        std::unique_ptr<uint8_t[]> temp_buf;
        uint64_t batch_write_offset;
        size_t temp_buf_pos;
        size_t size_to_append;
        size_t cur_offset;
        void* data_to_append;
        bool flush_all;
    };

    fdb_status writeCachedData(WriteCachedDataArgs& args);

    // BnodeCache size limit (in bytes), obtained from config (buffercache_size)
    std::atomic<uint64_t> bnodeCacheLimit;

    // Current BnodeCache usage, if this value were to exceed the limit
    // upon a write, eviction is done before writing the data.
    std::atomic<uint64_t> bnodeCacheCurrentUsage;

    // Dirty nodes flush limit (in bytes)
    std::atomic<uint64_t> flushLimit;

    // Spin lock to synchronize fileMap access
    spin_t bnodeCacheLock;
    std::unordered_map<std::string, FileBnodeCache*> fileMap;

    // Reader-writer lock for the file list
    fdb_rw_lock fileListLock;
    // File block cache list
    std::vector<FileBnodeCache*> fileList;
    // File zombies
    std::list<FileBnodeCache*> fileZombies;

    //Singleton bnode cache manager and a mutex guard
    static std::atomic<BnodeCacheMgr*> instance;
    static std::mutex instanceMutex;
};
