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

#pragma once

#include <atomic>
#include <unordered_map>
#include <list>
#include <vector>
#include <mutex>
#include <string>

#include "filemgr.h"

typedef enum {
    BCACHE_REQ_CLEAN,
    BCACHE_REQ_DIRTY
} bcache_dirty_t;

class BlockCacheItem;
class BlockCacheShard;

// Block cache file map with a file name as a key.
typedef std::unordered_map<std::string, FileBlockCache *> bcache_file_map;

class FileBlockCache {
public:
    FileBlockCache();

    FileBlockCache(std::string fname, FileMgr *file, size_t num_shards);

    ~FileBlockCache();

    const std::string &getFileName(void) const;

    FileMgr *getFileManager(void) const;

    uint32_t getRefCount(void) const;

    uint64_t getNumVictims(void) const;

    uint64_t getNumItems(void) const;

    uint64_t getNumImmutables(void) const;

    uint64_t getAccessTimestamp(void) const;

    size_t getNumShards(void) const;

    void setAccessTimestamp(uint64_t timestamp);

    /**
     * Check if a file block cache is empty or not.
     *
     * @return True if a file block cache is empty
     */
    bool empty();

    void acquireAllShardLocks();

    void releaseAllShardLocks();

private:
    friend class BlockCacheManager;

    std::string fileName;
    // File manager instance
    // (can be changed on-the-fly when file is closed and re-opened)
    FileMgr *curFile;
    // Shards of the block cache for a file.
    std::vector<BlockCacheShard *> shards;

    std::atomic<uint32_t> refCount;
    std::atomic<uint64_t> numVictims;
    std::atomic<uint64_t> numItems;
    std::atomic<uint64_t> numImmutables;
    std::atomic<uint64_t> accessTimestamp;
    size_t numShards;
};


/**
 * Global block cache manager that maintains the list of active files and their
 * cache entries.
 */
class BlockCacheManager {

public:
    /**
     * Instantiate the block cache manager and allocate the memory requested.
     *
     * @param nblock Number of blocks to be allocated in the cache
     * @param blocksize Size of each block in the cache
     * @return Pointer to the block cache manager
     */
    static BlockCacheManager* init(uint64_t nblock,
                                   uint32_t blocksize);

    /**
     * Get the singleton instance of the block cache manager.
     */
    static BlockCacheManager* getInstance();

    /**
     * Release all the resources including memory allocated and destroy the
     * block cache manager.
     */
    static void destroyInstance();

    /**
     * Removes dirty blocks (not written to disk) and clean blocks for a file
     * and the file entry itself from the global file list, if and only if a
     * BlockCacheManager instance is available.
     *
     * @param file Pointer to the file manager instance
     */
    static void eraseFileHistory(FileMgr *file);

    /**
     * Read a given block from the block cache.
     *
     * @param file Pointer to the file manager instance
     * @param bid ID of a block to be read from the cache
     * @param buf Pointer to the read buffer
     * @return the number of bytes that are read from the cache.
     */
    int read(FileMgr *file,
             bid_t bid,
             void *buf);

    /**
     * Invalidate a given cached block and return its memory to the free list
     * to be used for future allocations.
     *
     * @param file Pointer to the file manager instance
     * @param bid ID of a block to be invalidated.
     * @return true if a given cached block is invalidated and its memory is
     *         successfully returned back to the free list.
     */
    bool invalidateBlock(FileMgr *file,
                         bid_t bid);

    /**
     * Write a given block into the block cache.
     *
     * @param file Pointer to the file manager instance
     * @param bid ID of block to be written
     * @param buf Pointer to the buffer containing the block content
     * @param dirty Flag indicating if a given block is dirty or not
     * @param final_write Flag indicating if a given block becomes immutable
     *        after the write operation
     * @return Number of bytes written into the cache
     */
    int write(FileMgr *file,
              bid_t bid,
              void *buf,
              bcache_dirty_t dirty,
              bool final_write);

    /**
     * Write a offset range of a given block into the block cache.
     *
     * @param file Pointer to the file manager instance
     * @param bid ID of block to be written partially
     * @param buf Pointer to the buffer containing the partial content of
     *        a block
     * @param offset Offset within a block to be written from
     * @param len Size of data to be written
     * @param final_write Flag indicating if a given block becomes immutable
     *        after the write operation
     * @return Number of bytes written into the cache
     */
    int writePartial(FileMgr *file,
                     bid_t bid,
                     void *buf,
                     size_t offset,
                     size_t len,
                     bool final_write);

    /**
     * Discard all the dirty blocks for a given file from the block cache.
     * Note that those dirty blocks are not written into disk.
     *
     *@param file Pointer to the file manager instance
     */
    void removeDirtyBlocks(FileMgr *file);

    /**
     * Discard all the clean blocks for a given file from the block cache.
     *
     * @param file Pointer to the file manager instance
     */
    void removeCleanBlocks(FileMgr *file);

    /**
     * Remove a give file from the block cache's global file list.
     *
     * @param file Pointer to the file manager instance
     */
    bool removeFile(FileMgr *file);

    /**
     * Flush all the dirty blocks for a given file into disk and mark them as
     * clean.
     *
     * @param file Pointer to the file manager instance
     * @return FDB_RESULT_SUCCESS if the flush operation is completed successfully.
     */
    fdb_status flush(FileMgr *file);

    /**
     * Flush all the immutable dirty blocks for a given file into disk and
     * mark them as clean.
     *
     * @param file Pointer to the file manager instance
     * @return FDB_RESULT_SUCCESS if the flush operation is completed successfully.
     */
    fdb_status flushImmutable(FileMgr *file);

    /**
     * Return the total number of blocks in the block cache.
     *
     * @Param file Pointer to the file manager instance
     */
    uint64_t getNumBlocks(FileMgr *file);

    /**
     * Return the number of immutable blocks in the block cache.
     *
     * @param file Pointer to the file manager instance
     * @return Number of immutable blocks in the block cache
     */
    uint64_t getNumImmutables(FileMgr *file);

    /**
     * Return the number of blocks in the block cache's free list.
     *
     */
    uint64_t getNumFreeBlocks() const {
        return freeListCount;
    }

    /**
     * Print the stats summary of the block cache.
     */
    void printItems();

private:
    /**
     * Constructor
     *
     * @param nblock Number of blocks to be allocated in the cache
     * @param blocksize Size of each block in the cache
     */
    BlockCacheManager(uint64_t nblock, uint32_t blocksize);

    ~BlockCacheManager();

    /**
     * Set the cache weighted score for a given cache item.
     *
     * @param item A cache item whose weighted score is set
     */
    void setScore(BlockCacheItem &item);

    /**
     * Add a given cache item to the free block list.
     *
     * @param item Pointer to a cache item to be added to the free block list
     */
    void addToFreeBlockList(BlockCacheItem *item);

    /**
     * Create a file block cache for a given file.
     *
     * @param file Pointer to a file manager instance
     * @return Pointer to a file block cache instantiated
     */
    FileBlockCache* createFileBlockCache(FileMgr *file);

    /**
     * Free a given file block cache and its allocated resouces.
     *
     * @param fcache Pointer to the file block cache to be freed.
     * @param force Flag indicating if a file block cache should be freed even if
     *        it is still referenced or not empty.
     * @return True if a given file block cache is freed successfully
     */
    bool freeFileBlockCache(FileBlockCache *fcache, bool force = false);

    /**
     * Prepare the resource deallocation for a given file block cache
     *
     * @param fcache Pointer to the file block cache to be prepared for deallocation
     * @return True if a given file block cache is ready for deallocation
     */
    bool prepareDeallocationForFileBlockCache(FileBlockCache *fcache);

    /**
     * Clean up all file block caches that are no longer valid.
     */
    void cleanUpInvalidFileBlockCaches();

    /**
     * Get a block from the free block list.
     *
     * @return Pointer to the free block
     */
    BlockCacheItem *getFreeBlock();

    /**
     * Perform cache eviction.
     *
     */
    void performEviction();

    /**
     * Choose a file block cache that is goint to be a victim for eviction.
     *
     * @return Pointer to a file block cache that is chosen as an eviction victim
     */
    FileBlockCache *chooseEvictionVictim();

    /**
     * Flush some dirty blocks from a given file block cache
     *
     * @param fcache Pointer to a file block cache whose dirty blocks are flushed
     * @param sync True if dirty blocks should be flushed into disk
     * @param flush_all True if all the dirty blocks should be flushed
     * @param immutable_only True if only immutable dirty blocks should be flushed
     * @return FDB_RESULT_SUCCESS if flush is successful
     */
    fdb_status flushDirtyBlocks(FileBlockCache *fcache,
                                bool sync,
                                bool flush_all,
                                bool immutables_only);


    // Singleton block cache manager and mutex guarding it's creation.
    static std::atomic<BlockCacheManager *> instance;
    static std::mutex instanceMutex;
    // Default block cache size in bytes
    static const uint64_t defaultCacheSize;
    // Default block size in bytes
    static const uint32_t defaultBlockSize;

    // global lock
    spin_t bcacheLock;

    // free block list
    std::atomic<uint64_t> freeListCount;
    struct list freeList;
    spin_t freeListLock;

    // file block cache list
    bcache_file_map fileMap;
    std::vector<FileBlockCache *> fileList;
    std::list<FileBlockCache *> fileZombies;
    // Reader-Writer lock for the file list
    fdb_rw_lock fileListLock;

    // Number of blocks in the block cache
    uint64_t numBlocks;
    // Size of a block
    uint32_t blockSize;
    // Number of bytes to be written for each flush
    size_t flushUnit;
    // Pointer to the block cache memory
    void *bufferCache;

    DISALLOW_COPY_AND_ASSIGN(BlockCacheManager);
};
