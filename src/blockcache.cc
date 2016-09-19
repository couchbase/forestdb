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

#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#if !defined(WIN32) && !defined(_WIN32)
#include <sys/time.h>
#endif
#include <map>

#include "hash_functions.h"
#include "common.h"
#include "libforestdb/fdb_errors.h"
#include "hash.h"
#include "list.h"
#include "blockcache.h"
#include "avltree.h"
#include "atomic.h"
#include "fdb_internal.h"
#include "time_utils.h"
#include "memleak.h"

#ifdef __DEBUG
#ifndef __DEBUG_BCACHE
    #undef DBG
    #undef DBGCMD
    #undef DBGSW
    #define DBG(...)
    #define DBGCMD(...)
    #define DBGSW(n, ...)
#endif
#endif

std::atomic<BlockCacheManager *> BlockCacheManager::instance(nullptr);
std::mutex BlockCacheManager::instanceMutex;
const uint64_t BlockCacheManager::defaultCacheSize = 134217728; // 128MB
const uint32_t BlockCacheManager::defaultBlockSize = FDB_BLOCKSIZE; // 4KB

class BlockCacheItem {
public:
    BlockCacheItem() : bid(BLK_NOT_FOUND), addr(NULL), flag(0), score(0) {
        list_elem.prev = list_elem.next = NULL;
    }

    BlockCacheItem(bid_t _bid, void *_addr, uint8_t _flag, uint8_t _score) :
        bid(_bid), addr(_addr), flag(_flag), score(_score) {
        list_elem.prev = list_elem.next = NULL;
    }

    ~BlockCacheItem() { }

    bid_t getBid(void) const {
        return bid;
    }

    void *getBlockAddr(void) const {
        return addr;
    }

    uint8_t getFlag(void) const {
        return flag;
    }

    uint8_t getScore(void) const {
        return score;
    }

    void setBid(bid_t _bid) {
        bid = _bid;
    }

    void setFlag(uint8_t _flag) {
        flag = _flag;
    }

    void setScore(uint8_t _score) {
        score = _score;
    }

    // list elem for {free, clean} lists
    struct list_elem list_elem;

private:
    // block ID
    bid_t bid;
    // block address
    void *addr;
    // Flag indicating if a given block is dirty or immutable or free to use
    std::atomic<uint8_t> flag;
    // cache block score
    uint8_t score;
};

typedef std::unordered_map<bid_t, BlockCacheItem *> block_map_t;

class BlockCacheShard {
public:
    BlockCacheShard() {
        spin_init(&lock);
        list_init(&cleanBlocks);
    }

    ~BlockCacheShard() {
        spin_destroy(&lock);
        // Free all the blocks allocated to this shard
        for (auto &block_entry : allBlocks) {
            delete block_entry.second;
        }
    }

    bool empty() {
        // Caller should grab the shard lock before calling this function.
        return list_empty(&cleanBlocks) && dirtyDataBlocks.empty() &&
            dirtyIndexBlocks.empty();
    }

private:
    friend class BlockCacheManager;
    friend class FileBlockCache;

    spin_t lock;
    // LRU List of clean blocks
    struct list cleanBlocks;
    // Tree map of dirty data blocks
    std::map<bid_t, BlockCacheItem *> dirtyDataBlocks;
    // Tree map of dirty index blocks
    std::map<bid_t, BlockCacheItem *> dirtyIndexBlocks;
    // Hashtable of all the blocks belonging to this shard
    block_map_t allBlocks;
};

FileBlockCache::FileBlockCache()
    : curFile(NULL), refCount(0), numVictims(0), numItems(0), numImmutables(0),
      accessTimestamp(0), numShards(DEFAULT_NUM_BCACHE_PARTITIONS) { }

FileBlockCache::FileBlockCache(std::string fname, FileMgr *file,
                               size_t num_shards)
    : fileName(fname), curFile(file), refCount(0), numVictims(0), numItems(0),
      numImmutables(0), accessTimestamp(0), numShards(num_shards)
{
    // Create a block cache shard instance.
    for (size_t i = 0; i < numShards; ++i) {
        BlockCacheShard *shard = new BlockCacheShard();
        shards.push_back(shard);
    }
}

FileBlockCache::~FileBlockCache() {
        for (auto shard : shards) {
            delete shard;
        }
    }

const std::string& FileBlockCache::getFileName(void) const {
    return fileName;
}

FileMgr* FileBlockCache::getFileManager(void) const {
    return curFile;
}

uint32_t FileBlockCache::getRefCount(void) const {
    return refCount;
}

uint64_t FileBlockCache::getNumVictims(void) const {
    return numVictims;
}

uint64_t FileBlockCache::getNumItems(void) const {
    return numItems;
}

uint64_t FileBlockCache::getNumImmutables(void) const {
    return numImmutables;
}

uint64_t FileBlockCache::getAccessTimestamp(void) const {
    return accessTimestamp.load(std::memory_order_relaxed);
}

size_t FileBlockCache::getNumShards(void) const {
    return numShards;
}

void FileBlockCache::setAccessTimestamp(uint64_t timestamp) {
    accessTimestamp.store(timestamp, std::memory_order_relaxed);
}

bool FileBlockCache::empty() {
    bool empty = true;
    size_t i = 0;
    acquireAllShardLocks();
    for (; i < numShards; ++i) {
        if (!shards[i]->empty()) {
            empty = false;
            break;
        }
    }
    releaseAllShardLocks();
    return empty;
}

void FileBlockCache::acquireAllShardLocks() {
    size_t i = 0;
    for (; i < numShards; ++i) {
        spin_lock(&shards[i]->lock);
    }
}

void FileBlockCache::releaseAllShardLocks() {
    size_t i = 0;
    for (; i < numShards; ++i) {
        spin_unlock(&shards[i]->lock);
    }
}

static const size_t MAX_VICTIM_SELECTIONS = 5;
static const size_t MIN_TIMESTAMP_GAP = 15000; // 15 seconds

#define BCACHE_DIRTY (0x1)
#define BCACHE_IMMUTABLE (0x2)
#define BCACHE_FREE (0x4)

FileBlockCache *BlockCacheManager::chooseEvictionVictim() {
    FileBlockCache *ret = NULL;
    uint64_t max_items = 0;
    uint64_t min_timestamp = static_cast<uint64_t>(-1);
    uint64_t max_timestamp = 0;
    uint64_t victim_timestamp;
    uint64_t victim_num_items;
    int victim_idx, victim_by_time, victim_by_items;
    size_t num_attempts;

    if (reader_lock(&fileListLock) == 0) {
        // Pick the victim that has the oldest access timestamp
        // among the files randomly selected, if the gap between
        // the oldest and newest timestamps is greater than the threshold.
        // Otherwise, pick the victim that has the largest number of
        // cached items among the files.
        num_attempts = fileList.size() / 10 + 1;
        if (num_attempts > MAX_VICTIM_SELECTIONS) {
            num_attempts = MAX_VICTIM_SELECTIONS;
        } else {
            if(num_attempts == 1 && fileList.size() > 1) {
                ++num_attempts;
            }
        }

        victim_by_time = victim_by_items = -1;

        for (size_t i = 0; i < num_attempts && !fileList.empty(); ++i) {
            victim_idx = rand() % fileList.size();
            victim_timestamp = fileList[victim_idx]->getAccessTimestamp();
            victim_num_items = fileList[victim_idx]->numItems;

            if (victim_num_items) {
                if (victim_timestamp < min_timestamp) {
                    min_timestamp = victim_timestamp;
                    victim_by_time = victim_idx;
                }
                if (victim_timestamp > max_timestamp) {
                    max_timestamp = victim_timestamp;
                }
                if (victim_num_items > max_items) {
                    max_items = victim_num_items;
                    victim_by_items = victim_idx;
                }
            }
        }


        if (max_timestamp - min_timestamp > MIN_TIMESTAMP_GAP) {
            if (victim_by_time != -1) {
                ret = fileList[victim_by_time];
            }
        } else {
            if (victim_by_items != -1) {
                ret = fileList[victim_by_items];
            }
        }

        if (ret) {
            ret->refCount++;
        }
        reader_unlock(&fileListLock);
    } else {
        fprintf(stderr, "Error in BlockCacheManager::chooseEvictionVictim(): "
                        "Failed to acquire ReaderLock on a file list lock!\n");
    }

    return ret;
}

BlockCacheItem *BlockCacheManager::getFreeBlock() {
    struct list_elem *elem = NULL;

    spin_lock(&freeListLock);
    elem = list_pop_front(&freeList);
    if (elem) {
        freeListCount--;
    }
    spin_unlock(&freeListLock);

    if (elem) {
        BlockCacheItem *item = reinterpret_cast<BlockCacheItem *>(elem);
        return item;
    }

    return NULL;
}

void BlockCacheManager::addToFreeBlockList(BlockCacheItem *item) {
    spin_lock(&freeListLock);
    item->setFlag(BCACHE_FREE);
    item->setScore(0);
    list_push_front(&freeList, &item->list_elem);
    ++freeListCount;
    spin_unlock(&freeListLock);
}

bool BlockCacheManager::freeFileBlockCache(FileBlockCache *fcache,
                                           bool force)
{
    // file block cache must be empty
    if (!fcache->empty() && !force) {
        DBG("Warning: failed to free a file block cache instance for a file '%s' "
            "because the file block cache instance is not empty!\n",
            fcache->getFileName().c_str());
        return false;
    }

    if (fcache->getRefCount() != 0 && !force) {
        DBG("Warning: failed to free a file block cache instance for a file '%s' "
            "because its ref counter is not zero!\n",
            fcache->getFileName().c_str());
        return false;
    }

    // free a file block cache
    delete fcache;
    return true;
}

void BlockCacheManager::cleanUpInvalidFileBlockCaches() {
    FileBlockCache *fcache;

    if (writer_lock(&fileListLock) == 0) {
        std::list<FileBlockCache *>::iterator iter = fileZombies.begin();
        for (; iter != fileZombies.end();) {
            fcache = *iter;
            if (freeFileBlockCache(fcache)) {
                iter = fileZombies.erase(iter);
            } else {
                ++iter;
            }
        }
        writer_unlock(&fileListLock);
    } else {
        fprintf(stderr, "Error in cleanUpInvalidFileBlockCaches(): "
                        "Failed to acquire WriterLock on a file list lock!\n");
    }
}

// Flush some consecutive or all dirty blocks for a given file and
// move them to the clean list.
fdb_status BlockCacheManager::flushDirtyBlocks(FileBlockCache *fcache,
                                               bool sync,
                                               bool flush_all,
                                               bool immutables_only) {
    void *buf = NULL;
    std::map<bid_t, BlockCacheItem *> *shard_dirty_tree;

    uint64_t count = 0;
    ssize_t ret = 0;
    bid_t start_bid = 0, prev_bid = 0;
    void *ptr = NULL;
    uint8_t marker = 0x0;
    fdb_status status = FDB_RESULT_SUCCESS;
    bool o_direct = false;
    bool data_block_completed = false;

    // Cross-shard dirty block list for sequential writes.
    std::map<bid_t, BlockCacheItem *> dirty_blocks;

    if (fcache->getFileManager()->getConfig()->getFlag() & _ARCH_O_DIRECT) {
        o_direct = true;
    }

    // scan and write back dirty blocks sequentially for O_DIRECT option.
    if (sync && o_direct) {
        malloc_align(buf, FDB_SECTOR_SIZE, flushUnit);
        fcache->acquireAllShardLocks();
    }

    prev_bid = start_bid = BLK_NOT_FOUND;
    count = 0;

    // Try to flush the dirty data blocks first and then index blocks.
    size_t i = 0;
    bool consecutive_blocks = true;
    BlockCacheItem *item = NULL;

    while (1) {
        if (dirty_blocks.empty()) {
            for (i = 0; i < fcache->getNumShards(); ++i) {
                if (!(sync && o_direct)) {
                    spin_lock(&fcache->shards[i]->lock);
                }
                if (!data_block_completed) {
                    auto entry = fcache->shards[i]->dirtyDataBlocks.begin();
                    if (entry != fcache->shards[i]->dirtyDataBlocks.end()) {
                        item = entry->second;
                    } else {
                        item = NULL;
                    }
                } else {
                    auto entry = fcache->shards[i]->dirtyIndexBlocks.begin();
                    if (entry != fcache->shards[i]->dirtyIndexBlocks.end()) {
                        item = entry->second;
                    } else {
                        item = NULL;
                    }
                }
                if (item) {
                    if (!immutables_only || // don't load mutable items
                        item->getFlag() & BCACHE_IMMUTABLE) {
                        dirty_blocks.insert(std::make_pair(item->getBid(), item));
                    }
                }
                if (!(sync && o_direct)) {
                    spin_unlock(&fcache->shards[i]->lock);
                }
            }
            if (dirty_blocks.empty()) {
                if (!data_block_completed) {
                    data_block_completed = true;
                    if (count > 0 && !flush_all) {
                        // Finished flushing some dirty data blocks.
                        // Not move over to the dirty index block list because
                        // flush_all is not requestd.
                        break;
                    }
                    continue;
                } else {
                    break;
                }
            }
        }

        auto dirty_entry = dirty_blocks.begin();
        bid_t dirty_bid = dirty_entry->first;

        size_t shard_num = dirty_bid % fcache->getNumShards();
        if (!(sync && o_direct)) {
            spin_lock(&fcache->shards[shard_num]->lock);
        }
        if (!data_block_completed) {
            shard_dirty_tree = &fcache->shards[shard_num]->dirtyDataBlocks;
        } else {
            shard_dirty_tree = &fcache->shards[shard_num]->dirtyIndexBlocks;
        }

        BlockCacheItem *dirty_block = NULL;
        bool item_exist = false;
        if (!shard_dirty_tree->empty()) {
            auto entry = shard_dirty_tree->begin();
            dirty_block = entry->second;
            if (dirty_bid == dirty_block->getBid()) {
                item_exist = true;
            }
        }

        // remove from the cross-shard dirty block list.
        dirty_blocks.erase(dirty_bid);
        if (!item_exist) {
            // The original first item in the shard dirty block list was removed.
            // Grab the next one from the cross-shard dirty block list.
            if (!(sync && o_direct)) {
                spin_unlock(&fcache->shards[shard_num]->lock);
            }
            if (immutables_only && !fcache->numImmutables.load()) {
                break;
            }
            continue;
        }

        consecutive_blocks = true;
        // if BID of next dirty block is not consecutive .. stop
        if (dirty_block->getBid() != prev_bid + 1 && prev_bid != BLK_NOT_FOUND &&
            sync) {
            if (flush_all) {
                consecutive_blocks = false;
            } else {
                if (!(sync && o_direct)) {
                    spin_unlock(&fcache->shards[shard_num]->lock);
                }
                break;
            }
        }
        // set START_BID if this is the start block for a single batch write.
        if (start_bid == BLK_NOT_FOUND) {
            start_bid = dirty_block->getBid();
        }
        // set PREV_BID and go to next block
        prev_bid = dirty_block->getBid();

        // set PTR and get block MARKER
        ptr = dirty_block->getBlockAddr();
        marker = *((uint8_t*)(ptr) + blockSize - 1);

        // Get the next dirty block from the victim shard and insert it into
        // the cross-shard dirty block list.
        if (shard_dirty_tree->size() > 1) {
            auto entry = shard_dirty_tree->begin();
            ++entry;
            BlockCacheItem *ditem = entry->second;
            if (!immutables_only || ditem->getFlag() & BCACHE_IMMUTABLE) {
                dirty_blocks.insert(std::make_pair(ditem->getBid(), ditem));
            }
        }

        // remove from the shard dirty block list.
        shard_dirty_tree->erase(dirty_block->getBid());
        if (dirty_block->getFlag() & BCACHE_IMMUTABLE) {
            fcache->numImmutables--;
            if (!(sync && o_direct)) {
                spin_unlock(&fcache->shards[shard_num]->lock);
            }
        }

        if (sync) {
            // copy to buffer
#ifdef __CRC32
            if (marker == BLK_MARKER_BNODE) {
                // b-tree node .. calculate crc32 and put it into the block
                memset((uint8_t *)(ptr) + BTREE_CRC_OFFSET,
                       0xff, BTREE_CRC_FIELD_LEN);
                uint32_t crc = get_checksum(reinterpret_cast<const uint8_t*>(ptr),
                                            blockSize,
                                            fcache->getFileManager()->getCrcMode());
                crc = _endian_encode(crc);
                memcpy((uint8_t *)(ptr) + BTREE_CRC_OFFSET, &crc, sizeof(crc));
            }
#endif
            if (o_direct) {
                if (count > 0 && !consecutive_blocks) {
                    int64_t bytes_written;
                    // Note that this path can be only executed in flush_all case.
                    bytes_written = fcache->getFileManager()->writeBlocks(buf,
                                                                          count,
                                                                          start_bid);
                    if ((uint64_t)bytes_written != count * blockSize) {
                        count = 0;
                        status = bytes_written < 0 ?
                            (fdb_status) bytes_written : FDB_RESULT_WRITE_FAIL;
                        break;
                    }
                    // Start a new batch again.
                    count = 0;
                    start_bid = dirty_block->getBid();
                }
                memcpy((uint8_t *)(buf) + count * blockSize,
                       dirty_block->getBlockAddr(), blockSize);
            } else {
                ret = fcache->getFileManager()->writeBlocks(
                                            dirty_block->getBlockAddr(),
                                            1,
                                            dirty_block->getBid());
                if (ret != blockSize) {
                    if (!(dirty_block->getFlag() & BCACHE_IMMUTABLE) &&
                        !(sync && o_direct)) {
                        spin_unlock(&fcache->shards[shard_num]->lock);
                    }
                    status = ret < 0 ? (fdb_status) ret : FDB_RESULT_WRITE_FAIL;
                    break;
                }
            }
        }

        if (!(sync && o_direct)) {
            if (dirty_block->getFlag() & BCACHE_IMMUTABLE) {
                spin_lock(&fcache->shards[shard_num]->lock);
            }
        }

        dirty_block->setFlag(dirty_block->getFlag() & ~(BCACHE_DIRTY));
        dirty_block->setFlag(dirty_block->getFlag() & ~(BCACHE_IMMUTABLE));
        // move to the shard clean block list.
        list_push_front(&fcache->shards[shard_num]->cleanBlocks,
                        &dirty_block->list_elem);

        fdb_assert(!(dirty_block->getFlag() & BCACHE_FREE),
                   dirty_block->getFlag(), BCACHE_FREE);

        if (!(sync && o_direct)) {
            spin_unlock(&fcache->shards[shard_num]->lock);
        }

        count++;
        if (count * blockSize >= flushUnit && sync) {
            if (flush_all) {
                if (o_direct) {
                    ret = fcache->getFileManager()->writeBlocks(buf,
                                                                count,
                                                                start_bid);
                    if ((size_t)ret != count * blockSize) {
                        count = 0;
                        status = ret < 0 ? (fdb_status) ret : FDB_RESULT_WRITE_FAIL;
                        break;
                    }
                    count = 0;
                    start_bid = BLK_NOT_FOUND;
                    prev_bid = BLK_NOT_FOUND;
                }
            } else {
                break;
            }
        }
    }

    // synchronize
    if (sync && o_direct) {
        if (count > 0) {
            ret = fcache->getFileManager()->writeBlocks(buf, count, start_bid);
            if ((size_t)ret != count * blockSize) {
                status = ret < 0 ? (fdb_status) ret : FDB_RESULT_WRITE_FAIL;
            }
        }
        fcache->releaseAllShardLocks();
        free_align(buf);
    }

    return status;
}

void BlockCacheManager::performEviction() {
    size_t n_evict;
    struct list_elem *elem = NULL;
    BlockCacheItem *item = NULL;
    FileBlockCache *victim = NULL;

    // We don't need to grab the global buffer cache lock here because
    // the file's buffer cache instance (FileBlockCache) can be freed only if
    // there are no database handles opened for that file.

    while (victim == NULL) {
        // select a victim file
        victim = chooseEvictionVictim();
        if (victim) {
            // check whether this file has at least one block to be evictied
            if (victim->numItems.load()) {
                // select this file as victim
                break;
            } else {
                victim->refCount--;
                victim = NULL; // Try to select a victim again
            }
        }
    }
    fdb_assert(victim, victim, NULL);

    victim->numVictims++;

    // select the clean blocks from the victim file
    n_evict = 0;
    while (n_evict < BCACHE_EVICT_UNIT) {
        size_t num_shards = victim->getNumShards();
        size_t i = random(num_shards);
        bool found_victim_shard = false;
        BlockCacheShard *bshard = NULL;

        for (size_t to_visit = num_shards; to_visit; --to_visit) {
            i = (i + 1) % num_shards; // Round robin over empty shards..
            bshard = victim->shards[i];
            spin_lock(&bshard->lock);
            if (bshard->empty()) {
                spin_unlock(&bshard->lock);
                continue;
            }

            if (list_empty(&bshard->cleanBlocks)) {
                spin_unlock(&bshard->lock);
                // When the victim shard has no clean block, evict some dirty blocks
                // from shards.
                if (flushDirtyBlocks(victim, true, false, false)
                    != FDB_RESULT_SUCCESS) {
                    victim->refCount--;
                    return;
                }
                continue; // Select a victim shard again.
            }

            elem = list_pop_back(&bshard->cleanBlocks);
            item = reinterpret_cast<BlockCacheItem *>(elem);
#ifdef __BCACHE_SECOND_CHANCE
            // repeat until zero-score item is found
            if (item->getScore() == 0) {
                found_victim_shard = true;
                break;
            } else {
                // give second chance to the item
                item->setScore(item->getScore() - 1);
                list_push_front(&bshard->cleanBlocks, &item->list_elem);
                spin_unlock(&bshard->lock);
            }
#else
            found_victim_shard = true;
            break;
#endif
        }
        if (!found_victim_shard) {
            // We couldn't find any non-empty shards even after 'num_shards'
            // attempts.
            // The file is *likely* empty. Note that it is OK to return here
            // even if the file is not empty because the caller will retry again.
            victim->refCount--;
            return;
        }

        victim->numItems--;
        // remove from the shard block list
        bshard->allBlocks.erase(item->getBid());
        // add to the free block list
        addToFreeBlockList(item);
        n_evict++;

        spin_unlock(&bshard->lock);

        if (victim->numItems.load() == 0) {
            break;
        }
    }

    victim->refCount--;
}

FileBlockCache* BlockCacheManager::createFileBlockCache(FileMgr *file) {
    // TODO: we MUST NOT directly read file sturcture

    // Before we create a new file block cache, garbage collect zombies
    cleanUpInvalidFileBlockCaches();

    size_t num_shards;
    if (file->getConfig()->getNumBcacheShards()) {
        num_shards = file->getConfig()->getNumBcacheShards();
    } else {
        num_shards = DEFAULT_NUM_BCACHE_PARTITIONS;
    }

    std::string file_name(file->getFileName());
    FileBlockCache *fcache = new FileBlockCache(file_name, file, num_shards);

    // For random eviction among shards
    randomize();

    // insert into a file map
    fileMap.insert(std::make_pair(file_name, fcache));
    file->setBCache(fcache);

    if (writer_lock(&fileListLock) == 0) {
        fileList.push_back(fcache);
        writer_unlock(&fileListLock);
    } else {
        fprintf(stderr, "Error in BlockCacheManager::createFileBlockCache(): "
                        "Failed to acquire WriterLock on a file list lock!\n");
    }

    return fcache;
}

bool BlockCacheManager::prepareDeallocationForFileBlockCache(FileBlockCache *fcache) {
    bool ret = true;

    if (writer_lock(&fileListLock) == 0) {
        // Remove from the global file list
        bool found = false;
        for (auto entry = fileList.begin(); entry != fileList.end(); ++entry) {
            if (*entry == fcache) {
                fileList.erase(entry);
                found = true;
                break;
            }
        }
        if (!found) {
            writer_unlock(&fileListLock);
            fprintf(stderr, "Error: a file block cache instance for a file '%s' can't be "
                    "found in the global file list.\n", fcache->getFileName().c_str());
            return false;
        }

        if (fcache->getRefCount() != 0) {
            // The file block cache is currently accessed by another thread for eviction
            fileZombies.push_front(fcache);
            ret = false; // Delay deletion
        }

        writer_unlock(&fileListLock);
    } else {
        ret = false;
        fprintf(stderr, "Error in BlockCacheManager::prepareDeallocationForFileBlockCache(): "
                        "Failed to acquire WriterLock on the global file list!\n");
    }

    return ret;
}

void BlockCacheManager::setScore(BlockCacheItem &item) {
#ifdef __CRC32
    uint8_t marker;

    // set PTR and get block MARKER
    marker = *(reinterpret_cast<uint8_t *>(item.getBlockAddr()) + blockSize - 1);
    if (marker == BLK_MARKER_BNODE ) {
        // b-tree node .. set item's score to 1
        item.setScore(1);
    } else {
        item.setScore(0);
    }
#endif
}

int BlockCacheManager::read(FileMgr *file,
                            bid_t bid,
                            void *buf) {
    FileBlockCache *fcache;

    // Note that we don't need to grab bcacheLock here as the block cache
    // is already created and binded when the file is created or opened for
    // the first time.
    fcache = file->getBCache();

    if (fcache) {
        // file exists
        fcache->setAccessTimestamp(gethrtime() / 1000000); // access timestamp in ms

        size_t shard_num = bid % fcache->getNumShards();
        spin_lock(&fcache->shards[shard_num]->lock);

        // search shard hash table
        auto block_entry = fcache->shards[shard_num]->allBlocks.find(bid);
        if (block_entry != fcache->shards[shard_num]->allBlocks.end()) {
            // cache hit
            BlockCacheItem *item = block_entry->second;
            if (item->getFlag() & BCACHE_FREE) {
                spin_unlock(&fcache->shards[shard_num]->lock);
                DBG("Warning: failed to read the buffer cache entry for a file '%s' "
                    "because the entry belongs to the free list!\n",
                    file->getFileName());
                return 0;
            }

            // move the item to the head of list if the block is clean
            // (don't care if the block is dirty)
            if (!(item->getFlag() & BCACHE_DIRTY)) {
                // TODO: Scanning the list would cause some overhead. We need to devise
                // the better data structure to provide a fast lookup for the clean list.
                list_remove(&fcache->shards[shard_num]->cleanBlocks, &item->list_elem);
                list_push_front(&fcache->shards[shard_num]->cleanBlocks, &item->list_elem);
            }

            memcpy(buf, item->getBlockAddr(), blockSize);
            setScore(*item);

            spin_unlock(&fcache->shards[shard_num]->lock);

            return blockSize;
        } else {
            // cache miss
            spin_unlock(&fcache->shards[shard_num]->lock);
        }
    }

    // does not exist .. cache miss
    return 0;
}

bool BlockCacheManager::invalidateBlock(FileMgr *file,
                                        bid_t bid) {
    FileBlockCache *fcache;
    bool ret = false;

    // Note that we don't need to grab bcache_lock here as the block cache
    // is already created and binded when the file is created or opened for
    // the first time.
    fcache = file->getBCache();

    if (fcache) {
        // file exists
        // Update the access timestamp.
        fcache->setAccessTimestamp(gethrtime() / 1000000);

        size_t shard_num = bid % fcache->getNumShards();
        spin_lock(&fcache->shards[shard_num]->lock);

        // search BHASH
        auto block_entry = fcache->shards[shard_num]->allBlocks.find(bid);
        if (block_entry != fcache->shards[shard_num]->allBlocks.end()) {
            // cache hit
            BlockCacheItem *item = block_entry->second;

            if (item->getFlag() & BCACHE_FREE) {
                spin_unlock(&fcache->shards[shard_num]->lock);
                DBG("Warning: failed to invalidate the buffer cache entry for a file '%s' "
                    "because the entry belongs to the free list!\n",
                    file->getFileName());
                return false;
            }

            if (!(item->getFlag() & BCACHE_DIRTY)) {
                fcache->numItems--;
                // only for clean blocks
                // remove from the shard block list
                fcache->shards[shard_num]->allBlocks.erase(bid);
                // remove from the shard clean list
                list_remove(&fcache->shards[shard_num]->cleanBlocks, &item->list_elem);
                spin_unlock(&fcache->shards[shard_num]->lock);

                // add the block to the global free list
                addToFreeBlockList(item);
                ret = true;
            } else {
                // stale index node block
                uint8_t flag = item->getFlag() | BCACHE_IMMUTABLE;
                item->setFlag(flag);
                fcache->numImmutables++;
                spin_unlock(&fcache->shards[shard_num]->lock);
            }
        } else {
            // cache miss
            spin_unlock(&fcache->shards[shard_num]->lock);
        }
    }
    return ret;
}

int BlockCacheManager::write(FileMgr *file,
                             bid_t bid,
                             void *buf,
                             bcache_dirty_t dirty,
                             bool final_write) {
    BlockCacheItem *item;
    FileBlockCache *fcache;

    fcache = file->getBCache();
    if (fcache == NULL) {
        spin_lock(&bcacheLock);
        fcache = file->getBCache();
        if (fcache == NULL) {
            // A file block cache doesn't exist in the block cache manager.
            // Create it.
            fcache = createFileBlockCache(file);
        }
        spin_unlock(&bcacheLock);
    }

    // Update the access timestamp.
    fcache->setAccessTimestamp(gethrtime() / 1000000);

    size_t shard_num = bid % fcache->getNumShards();
    spin_lock(&fcache->shards[shard_num]->lock);

    // search shard hash table
    auto block_entry = fcache->shards[shard_num]->allBlocks.find(bid);
    if (block_entry == fcache->shards[shard_num]->allBlocks.end()) {
        // cache miss
        // get a block from the free list
        while ((item = getFreeBlock()) == NULL) {
            // no free block .. perform eviction
            spin_unlock(&fcache->shards[shard_num]->lock);
            performEviction();
            spin_lock(&fcache->shards[shard_num]->lock);
        }

        // re-search hash table
        block_entry = fcache->shards[shard_num]->allBlocks.find(bid);
        if (block_entry == fcache->shards[shard_num]->allBlocks.end()) {
            // insert into hash table
            item->setBid(bid);
            item->setFlag(BCACHE_FREE);
            fcache->shards[shard_num]->allBlocks.insert(std::make_pair(item->getBid(),
                                                                       item));
        } else {
            // insert into freelist again
            addToFreeBlockList(item);
            item = block_entry->second;
        }
    } else {
        item = block_entry->second;
    }

    fdb_assert(item, item, NULL);

    if (item->getFlag() & BCACHE_FREE) {
        fcache->numItems++;
    }

    // remove from the list if the block is in clean list
    if (!(item->getFlag() & BCACHE_DIRTY) && !(item->getFlag() & BCACHE_FREE)) {
        list_remove(&fcache->shards[shard_num]->cleanBlocks, &item->list_elem);
    }
    item->setFlag(item->getFlag() & ~BCACHE_FREE);

    if (dirty == BCACHE_REQ_DIRTY) {
        // DIRTY request
        // to avoid re-insert already existing item into tree
        if (!(item->getFlag() & BCACHE_DIRTY)) {
            // dirty block
            // insert into tree
            uint8_t marker = *((uint8_t*)buf + blockSize - 1);
            if (marker == BLK_MARKER_BNODE) {
                // b-tree node
                fcache->shards[shard_num]->dirtyIndexBlocks.insert(
                    std::make_pair(item->getBid(), item));
            } else {
                if (final_write) {
                    // (fully written doc block)
                    item->setFlag(item->getFlag() | BCACHE_IMMUTABLE);
                    fcache->numImmutables++;
                }
                fcache->shards[shard_num]->dirtyDataBlocks.insert(
                    std::make_pair(item->getBid(), item));
            }
        }
        item->setFlag(item->getFlag() | BCACHE_DIRTY);
    } else {
        // CLEAN request
        // insert into clean list only when it was originally clean
        if (!(item->getFlag() & BCACHE_DIRTY)) {
            list_push_front(&fcache->shards[shard_num]->cleanBlocks, &item->list_elem);
            item->setFlag(item->getFlag() & ~(BCACHE_DIRTY));
        }
    }

    memcpy(item->getBlockAddr(), buf, blockSize);
    setScore(*item);

    spin_unlock(&fcache->shards[shard_num]->lock);

    return blockSize;
}

int BlockCacheManager::writePartial(FileMgr *file,
                                    bid_t bid,
                                    void *buf,
                                    size_t offset,
                                    size_t len,
                                    bool final_write) {
    BlockCacheItem *item = NULL;
    FileBlockCache *fcache = NULL;

    fcache = file->getBCache();
    if (fcache == NULL) {
        spin_lock(&bcacheLock);
        fcache = file->getBCache();
        if (fcache == NULL) {
            // A file block cache doesn't exist in the block cache manager.
            // Create it.
            fcache = createFileBlockCache(file);
        }
        spin_unlock(&bcacheLock);
    }

    // Update the access timestamp.
    fcache->setAccessTimestamp(gethrtime() / 1000000);

    size_t shard_num = bid % fcache->getNumShards();
    spin_lock(&fcache->shards[shard_num]->lock);

    // search the shard block hashtable
    auto block_entry = fcache->shards[shard_num]->allBlocks.find(bid);
    if (block_entry == fcache->shards[shard_num]->allBlocks.end()) {
        // cache miss .. partial write fail .. return 0
        spin_unlock(&fcache->shards[shard_num]->lock);
        return 0;
    } else {
        // cache hit .. get the block
        item = block_entry->second;
    }

    if (item->getFlag() & BCACHE_FREE) {
        DBG("Warning: failed to write on the buffer cache entry for a file '%s' "
            "because the entry belongs to the free list!\n",
            file->getFileName());
        return 0;
    }

    // check whether this is dirty block
    // to avoid re-inserting the existing item into the dirty block list
    if (!(item->getFlag() & BCACHE_DIRTY)) {
        // This block was a clean block. Remove it from the clean block list
        list_remove(&fcache->shards[shard_num]->cleanBlocks, &item->list_elem);

        // Insert into the dirty data or index block tree
        uint8_t marker = *((uint8_t*)item->getBlockAddr() + blockSize - 1);
        if (marker == BLK_MARKER_BNODE ) {
            // b-tree node
            fcache->shards[shard_num]->dirtyIndexBlocks.insert(
                std::make_pair(item->getBid(), item));
        } else {
            fcache->shards[shard_num]->dirtyDataBlocks.insert(
                    std::make_pair(item->getBid(), item));
            if (final_write) {
                // (fully written doc block)
                item->setFlag(item->getFlag() | BCACHE_IMMUTABLE);
                fcache->numImmutables++;
            }
        }
    } else if (!(item->getFlag() & BCACHE_IMMUTABLE)) {
        if (final_write) {
            // (fully written doc block)
            item->setFlag(item->getFlag() | BCACHE_IMMUTABLE);
            fcache->numImmutables++;
        }
    }

    // always set this block as dirty
    item->setFlag(item->getFlag() | BCACHE_DIRTY);

    memcpy((uint8_t *)(item->getBlockAddr()) + offset, buf, len);
    setScore(*item);

    spin_unlock(&fcache->shards[shard_num]->lock);

    return len;
}

// flush and synchronize a batch of contiguous dirty immutable blocks in file
// dirty blocks will be changed to clean blocks (not discarded)
// Note: This function can be invoked as part of background flushing
fdb_status BlockCacheManager::flushImmutable(FileMgr *file) {
    FileBlockCache *fcache;
    fdb_status status = FDB_RESULT_SUCCESS;
    fcache = file->getBCache();

    if (fcache) {
        status = flushDirtyBlocks(fcache, true, true, true);
    }
    return status;
}

// remove all dirty blocks of the FILE
// (they are only discarded and not written back)
void BlockCacheManager::removeDirtyBlocks(FileMgr *file) {
    FileBlockCache *fcache;
    fcache = file->getBCache();

    if (fcache) {
        // Note that this function is only invoked as part of database file close or
        // removal when there are no database handles for a given file. Therefore,
        // we don't need to grab all the shard locks at once.

        // remove all dirty blocks
        flushDirtyBlocks(fcache, false, true, false);
    }
}

// remove all clean blocks of the FILE
void BlockCacheManager::removeCleanBlocks(FileMgr *file) {
    struct list_elem *elem;
    BlockCacheItem *item;
    FileBlockCache *fcache;

    fcache = file->getBCache();

    if (fcache) {
        // Note that this function is only invoked as part of database file close or
        // removal when there are no database handles for a given file. Therefore,
        // we don't need to grab all the shard locks at once.

        // remove all clean blocks from each shard in a file.
        size_t i = 0;
        for (; i < fcache->getNumShards(); ++i) {
            spin_lock(&fcache->shards[i]->lock);
            elem = list_begin(&fcache->shards[i]->cleanBlocks);
            while (elem) {
                item = reinterpret_cast<BlockCacheItem *>(elem);
                // remove from clean block list
                elem = list_remove(&fcache->shards[i]->cleanBlocks, elem);
                // remove from the all block list
                fcache->shards[i]->allBlocks.erase(item->getBid());
                fcache->numItems--;
                // insert into the free block list
                addToFreeBlockList(item);
            }
            spin_unlock(&fcache->shards[i]->lock);
        }
    }
}

// Remove a file block cache from the file block cache list
// MUST sure that there is no dirty block belongs to this FILE
// (or memory leak occurs)
bool BlockCacheManager::removeFile(FileMgr *file) {
    bool rv = false;
    FileBlockCache *fcache;

    // Before proceeding with deletion, garbage collect zombie file cache instances
    cleanUpInvalidFileBlockCaches();
    fcache = file->getBCache();

    if (fcache) {
        // acquire lock
        spin_lock(&bcacheLock);
        // file block cache must be empty
        if (!fcache->empty()) {
            spin_unlock(&bcacheLock);
            DBG("Warning: failed to remove a file cache instance for a file '%s' "
                "because the file cache instance is not empty!\n",
                file->getFileName());
            return rv;
        }

        // remove from the file block cache map
        fileMap.erase(std::string(file->getFileName()));
        spin_unlock(&bcacheLock);

        // We don't need to grab the file buffer cache's partition locks
        // at once because this function is only invoked when there are
        // no database handles that access the file.
        if (prepareDeallocationForFileBlockCache(fcache)) {
            freeFileBlockCache(fcache); // no other callers accessing this file
            rv = true;
        } // Otherwise, a file block cache is in use by eviction. Deletion delayed
    }
    return rv;
}

// flush and synchronize all dirty blocks of the FILE
// dirty blocks will be changed to clean blocks (not discarded)
fdb_status BlockCacheManager::flush(FileMgr *file) {
    FileBlockCache *fcache;
    fdb_status status = FDB_RESULT_SUCCESS;

    fcache = file->getBCache();

    if (fcache) {
        // Note that this function is invoked as part of a commit operation while
        // the filemgr's lock is already grabbed by a committer.
        // Therefore, we don't need to grab all the shard locks at once.
        status = flushDirtyBlocks(fcache, true, true, false);
    }
    return status;
}

BlockCacheManager::BlockCacheManager(uint64_t nblock, uint32_t blocksize) {
    BlockCacheItem *item;
    uint8_t *block_ptr;

    blockSize = blocksize;
    flushUnit = BCACHE_FLUSH_UNIT;
    numBlocks = nblock;

    spin_init(&bcacheLock);
    spin_init(&freeListLock);

    list_init(&freeList);

    int rv = init_rw_lock(&fileListLock);
    if (rv != 0) {
        fdb_log(NULL, FDB_RESULT_ALLOC_FAIL , "Error in bcache_init(): "
                        "RW Lock initialization failed; ErrorCode: %d\n", rv);
    }

    freeListCount = 0;

    // Allocate entire buffer cache memory
    block_ptr = (uint8_t *) malloc((uint64_t) blockSize * numBlocks);
    bufferCache = block_ptr;

    for (uint64_t i = 0; i < numBlocks; ++i) {
        item = new BlockCacheItem(BLK_NOT_FOUND, block_ptr, (0x0 | BCACHE_FREE), 0);
        block_ptr += blockSize;
        list_push_front(&freeList, &item->list_elem);
        freeListCount++;
    }
}

BlockCacheManager* BlockCacheManager::init(uint64_t nblock, uint32_t blocksize) {
    BlockCacheManager* tmp = instance.load();
    if (tmp == nullptr) {
        // Ensure two threads don't both create an instance.
        LockHolder lock(instanceMutex);
        tmp = instance.load();
        if (tmp == nullptr) {
            tmp = new BlockCacheManager(nblock, blocksize);
            instance.store(tmp);
        }
    }
    return tmp;
}

BlockCacheManager* BlockCacheManager::getInstance() {
    BlockCacheManager* cache_manager = instance.load();
    if (cache_manager == nullptr) {
        // Create the buffer cache manager with default configs.
        return init(defaultCacheSize / defaultBlockSize, defaultBlockSize);
    }
    return cache_manager;
}

void BlockCacheManager::destroyInstance() {
    LockHolder lock(instanceMutex);
    BlockCacheManager* tmp = instance.load();
    if (tmp != nullptr) {
        delete tmp;
        instance = nullptr;
    }
}

BlockCacheManager::~BlockCacheManager() {
    spin_lock(&freeListLock);
    struct list_elem *elem = list_begin(&freeList);
    while (elem) {
        BlockCacheItem *item = reinterpret_cast<BlockCacheItem *>(elem);
        elem = list_remove(&freeList, elem);
        freeListCount--;
        delete item;
    }
    spin_unlock(&freeListLock);

    writer_lock(&fileListLock);
    // Force clean zombie files if any
    for (auto &fcache : fileZombies) {
        freeFileBlockCache(fcache);
    }
    writer_unlock(&fileListLock);

    // Free entire buffer cache memory
    free(bufferCache);

    spin_lock(&bcacheLock);
    for (auto &file_entry : fileMap) {
        freeFileBlockCache(file_entry.second, true);
    }
    spin_unlock(&bcacheLock);

    spin_destroy(&bcacheLock);
    spin_destroy(&freeListLock);

    int rv = destroy_rw_lock(&fileListLock);
    if (rv != 0) {
        fprintf(stderr, "Error in destroying buffer cache: "
                        "RW Lock's destruction failed; ErrorCode: %d\n", rv);
    }
}

void BlockCacheManager::eraseFileHistory(FileMgr *file) {
    LockHolder lock(instanceMutex);
    BlockCacheManager* tmp = instance.load();
    if (tmp) {
        tmp->removeDirtyBlocks(file);
        tmp->removeCleanBlocks(file);
        tmp->removeFile(file);
    }
}

uint64_t BlockCacheManager::getNumBlocks(FileMgr *file) {
    FileBlockCache *fcache = file->getBCache();
    if (fcache) {
        return fcache->getNumItems();
    }
    return 0;
}

uint64_t BlockCacheManager::getNumImmutables(FileMgr *file) {
    FileBlockCache *fcache = file->getBCache();
    if (fcache) {
        return fcache->getNumImmutables();
    }
    return 0;
}

// LCOV_EXCL_START
void BlockCacheManager::printItems() {
    size_t n=1;
    size_t nfiles, nitems, nfileitems, nclean, ndirty;
    size_t scores[100], i, scores_local[100];
    size_t docs, bnodes;
    size_t docs_local, bnodes_local;
    uint8_t *ptr;

    nfiles = nitems = nfileitems = nclean = ndirty = 0;
    docs = bnodes = 0;
    memset(scores, 0, sizeof(size_t)*100);

    FileBlockCache *fcache;
    BlockCacheItem *item;
    struct list_elem *elem;

    printf(" === Block cache statistics summary ===\n");
    printf("%3s %20s (%6s)(%6s)(c%6s d%6s)",
        "No", "Filename", "#Pages", "#Evict", "Clean", "Dirty");
#ifdef __CRC32
    printf("%6s%6s", "Doc", "Node");
#endif
    for (i=0;i<=n;++i) {
        printf("   [%d] ", (int)i);
    }
    printf("\n");

    for (auto &file_entry : fileList) {
        fcache = file_entry;
        memset(scores_local, 0, sizeof(size_t)*100);
        nfileitems = nclean = ndirty = 0;
        docs_local = bnodes_local = 0;

        size_t i = 0;
        for (; i < fcache->getNumShards(); ++i) {
            elem = list_begin(&fcache->shards[i]->cleanBlocks);
            while (elem) {
                item = reinterpret_cast<BlockCacheItem *>(elem);
                scores[item->getScore()]++;
                scores_local[item->getScore()]++;
                nitems++;
                nfileitems++;
                nclean++;
#ifdef __CRC32
                ptr = (uint8_t*)item->getBlockAddr() + blockSize - 1;
                switch (*ptr) {
                case BLK_MARKER_BNODE:
                    bnodes_local++;
                    break;
                case BLK_MARKER_DOC:
                    docs_local++;
                    break;
                }
#endif
                elem = list_next(elem);
            }

            for (auto &data_entry : fcache->shards[i]->dirtyDataBlocks) {
                item = data_entry.second;
                scores[item->getScore()]++;
                scores_local[item->getScore()]++;
                nitems++;
                nfileitems++;
                ndirty++;
#ifdef __CRC32
                ptr = (uint8_t*)item->getBlockAddr() + blockSize - 1;
                switch (*ptr) {
                case BLK_MARKER_BNODE:
                    bnodes_local++;
                    break;
                case BLK_MARKER_DOC:
                    docs_local++;
                    break;
                }
#endif
            }
        }

        printf("%3d %20s (%6d)(%6d)(c%6d d%6d)",
               static_cast<int>(nfiles + 1),
               fcache->getFileName().c_str(),
               static_cast<int>(fcache->getNumItems()),
               static_cast<int>(fcache->getNumVictims()),
               static_cast<int>(nclean),
               static_cast<int>(ndirty));
        printf("%6d%6d", static_cast<int>(docs_local),
                         static_cast<int>(bnodes_local));
        for (i=0;i<=n;++i){
            printf("%6d ", static_cast<int>(scores_local[i]));
        }
        printf("\n");

        docs += docs_local;
        bnodes += bnodes_local;

        nfiles++;
    }
    printf(" ===\n");

    printf("%d files %d items\n", static_cast<int>(nfiles),
                                  static_cast<int>(nitems));
    for (i=0;i<=n;++i){
        printf("[%d]: %d\n", static_cast<int>(i),
                             static_cast<int>(scores[i]));
    }
    printf("Documents: %d blocks\n", static_cast<int>(docs));
    printf("Index nodes: %d blocks\n", static_cast<int>(bnodes));
}
// LCOV_EXCL_STOP
