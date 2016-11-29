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

#include "bnodecache.h"
#include "fdb_internal.h"
#include "filemgr.h"

std::atomic<BnodeCacheMgr*> BnodeCacheMgr::instance(nullptr);
std::mutex BnodeCacheMgr::instanceMutex;
static uint64_t defaultCacheSize = 134217728;   // 128MB
static uint64_t defaultFlushLimit = 1048576;    // 1MB

/**
 * Hash function to determine the shard within a file
 * using the offset.
 */
static std::hash<std::string> str_hash;

FileBnodeCache::FileBnodeCache(std::string fname,
                               FileMgr* file,
                               size_t num_shards)
    : filename(fname),
      curFile(file),
      refCount(0),
      numVictims(0),
      numItems(0),
      numItemsWritten(0),
      accessTimestamp(0),
      evictionInProgress(false)
{

    for (size_t i = 0; i < num_shards; ++i) {
        shards.emplace_back(new BnodeCacheShard(i));
    }
}

const std::string& FileBnodeCache::getFileName(void) const {
    return filename;
}

FileMgr* FileBnodeCache::getFileManager(void) const {
    return curFile;
}

uint32_t FileBnodeCache::getRefCount(void) const {
    return refCount.load();
}

uint64_t FileBnodeCache::getNumVictims(void) const {
    return numVictims.load();
}

uint64_t FileBnodeCache::getNumItems(void) const {
    return numItems.load();
}

uint64_t FileBnodeCache::getNumItemsWritten(void) const {
    return numItemsWritten.load();
}

uint64_t FileBnodeCache::getAccessTimestamp(void) const {
    return accessTimestamp.load(std::memory_order_relaxed);
}

size_t FileBnodeCache::getNumShards(void) const {
    return shards.size();
}

void FileBnodeCache::setAccessTimestamp(uint64_t timestamp) {
    accessTimestamp.store(timestamp, std::memory_order_relaxed);
}

bool FileBnodeCache::empty() {
    bool empty = true;
    acquireAllShardLocks();
    for (size_t i = 0; i < shards.size(); ++i) {
        if (!shards[i]->empty()) {
            empty = false;
            break;
        }
    }
    releaseAllShardLocks();
    return empty;
}

void FileBnodeCache::acquireAllShardLocks() {
    for (size_t i = 0; i < shards.size(); ++i) {
        spin_lock(&shards[i]->lock);
    }
}

void FileBnodeCache::releaseAllShardLocks() {
    for (size_t i = 0; i < shards.size(); ++i) {
        spin_unlock(&shards[i]->lock);
    }
}

bool FileBnodeCache::setEvictionInProgress(bool to) {
    bool inverse = !to;
    return evictionInProgress.compare_exchange_strong(inverse, to);
}

BnodeCacheMgr* BnodeCacheMgr::init(uint64_t cache_size, uint64_t flush_limit) {
    BnodeCacheMgr* tmp = instance.load();
    if (tmp == nullptr) {
        // Ensure two threads don't both create an instance
        LockHolder lh(instanceMutex);
        tmp = instance.load();
        if (tmp == nullptr) {
            tmp = new BnodeCacheMgr(cache_size, flush_limit);
            instance.store(tmp);
        } else {
            tmp->updateParams(cache_size, flush_limit);
        }
    } else {
        LockHolder lh(instanceMutex);
        tmp->updateParams(cache_size, flush_limit);
    }
    return tmp;
}

BnodeCacheMgr* BnodeCacheMgr::get() {
    BnodeCacheMgr* cacheMgr = instance.load();
    if (cacheMgr == nullptr) {
        // Create the buffer cache manager with default config
        return init(defaultCacheSize, defaultFlushLimit);
    }
    return cacheMgr;
}

void BnodeCacheMgr::destroyInstance() {
    LockHolder lh(instanceMutex);
    BnodeCacheMgr* tmp = instance.load();
    if (tmp != nullptr) {
        delete tmp;
        instance = nullptr;
    }
}

void BnodeCacheMgr::eraseFileHistory(FileMgr* file) {
    if (!file) {
        return;
    }

    LockHolder lh(instanceMutex);
    BnodeCacheMgr* tmp = instance.load();
    if (tmp) {
        tmp->removeDirtyBnodes(file);
        tmp->removeCleanBnodes(file);
        tmp->removeFile(file);
    }
}

BnodeCacheMgr::BnodeCacheMgr(uint64_t cache_size,
                             uint64_t flush_limit)
    : bnodeCacheLimit(cache_size),
      bnodeCacheCurrentUsage(0),
      flushLimit(flush_limit)
{
    spin_init(&bnodeCacheLock);
    int rv = init_rw_lock(&fileListLock);
    if (rv != 0) {
        fdb_log(nullptr, FDB_RESULT_ALLOC_FAIL,
                "BnodeCacheMgr::BnodeCacheMgr: RW Lock init failed; "
                "error code: %d", rv);
        assert(false);
    }
}

BnodeCacheMgr::~BnodeCacheMgr() {
    spin_lock(&bnodeCacheLock);
    for (auto entry : fileMap) {
        delete entry.second;
    }
    spin_unlock(&bnodeCacheLock);

    spin_destroy(&bnodeCacheLock);
    int rv = destroy_rw_lock(&fileListLock);
    if (rv != 0) {
        fdb_log(nullptr, FDB_RESULT_ALLOC_FAIL,
                "BnodeCacheMgr::~BnodeCacheMgr: RW lock destroy failed; "
                "error code: %d", rv);
        assert(false);
    }
}

void BnodeCacheMgr::updateParams(uint64_t cache_size, uint64_t flush_limit) {
    bnodeCacheLimit.store(cache_size);
    flushLimit.store(flush_limit);
}

int BnodeCacheMgr::read(FileMgr* file,
                        Bnode** node,
                        cs_off_t offset) {

    if (!file) {
        return FDB_RESULT_INVALID_ARGS;
    }

    // Note that we don't need to grab the bnodeCacheLock here as the bnode
    // cache is already created and binded when the file is created or opened
    // for the first time.
    FileBnodeCache* fcache = file->getBnodeCache();

    if (fcache == nullptr) {
        spin_lock(&bnodeCacheLock);
        // Check again within bnodeCacheLock
        fcache = file->getBnodeCache();
        if (fcache == nullptr) {
            // A file bnode cache doesn not exist, creating it
            fcache = createFileBnodeCache_UNLOCKED(file);
        }
        spin_unlock(&bnodeCacheLock);
    }

    if (fcache) {
        // file exists, update the access timestamp (in ms)
        fcache->setAccessTimestamp(gethrtime() / 1000000);
        size_t shard_num = str_hash(std::to_string(offset)) %
                           fcache->getNumShards();

        spin_lock(&fcache->shards[shard_num]->lock);

        auto entry = fcache->shards[shard_num]->allNodes.find(offset);
        if (entry != fcache->shards[shard_num]->allNodes.end()) {
            // cache hit
            *node = entry->second;
            entry->second->incRefCount();

            // Move the item to the back of the clean node list if the item is
            // not dirty (to ensure that it is the last entry in this file's
            // clean node list that is evicted which is done based on LRU)
            if (fcache->shards[shard_num]->dirtyIndexNodes.find(
                                        entry->second->getCurOffset()) ==
                    fcache->shards[shard_num]->dirtyIndexNodes.end()) {

                list_remove(&fcache->shards[shard_num]->cleanNodes,
                            &entry->second->list_elem);
                list_push_back(&fcache->shards[shard_num]->cleanNodes,
                               &entry->second->list_elem);
            }

            spin_unlock(&fcache->shards[shard_num]->lock);
            return (*node)->getNodeSize();
        } else {
            // cache miss
            fdb_status status = fetchFromFile(file, node, offset);
            if (status != FDB_RESULT_SUCCESS) {
                // does not exist
                spin_unlock(&fcache->shards[shard_num]->lock);
                return status;
            } else {
                // Add back to allBNodes hash table
                fcache->shards[shard_num]->allNodes.insert(
                                std::make_pair((*node)->getCurOffset(), *node));
                // Add to back of clean node list
                list_push_back(&fcache->shards[shard_num]->cleanNodes,
                               &((*node)->list_elem));
                bnodeCacheCurrentUsage.fetch_add((*node)->getMemConsumption());
                fcache->numItems++;
                (*node)->incRefCount();
                spin_unlock(&fcache->shards[shard_num]->lock);

                // Do Eviction if necessary
                // TODO: Implement an eviction daemon perhaps rather than having
                //       the reader do it ..
                performEviction(*node);

                return (*node)->getNodeSize();
            }
        }
    }

    // does not exist .. cache miss
    return 0;
}

int BnodeCacheMgr::write(FileMgr* file,
                         Bnode* node,
                         cs_off_t offset) {

    if (!file) {
        return FDB_RESULT_INVALID_ARGS;
    }

    FileBnodeCache* fcache = file->getBnodeCache();
    if (fcache == nullptr) {
        spin_lock(&bnodeCacheLock);
        // Check again within bnodeCacheLock
        fcache = file->getBnodeCache();
        if (fcache == nullptr) {
            // A file bnode cache doesn not exist, creating it
            fcache = createFileBnodeCache_UNLOCKED(file);
        }
        spin_unlock(&bnodeCacheLock);
    }

    // Update the access timestamp (in ms)
    fcache->setAccessTimestamp(gethrtime() / 1000000);

    size_t shard_num = str_hash(std::to_string(offset)) %
                       fcache->getNumShards();
    spin_lock(&fcache->shards[shard_num]->lock);

    // search shard hash table
    auto entry = fcache->shards[shard_num]->allNodes.find(offset);
    if (entry == fcache->shards[shard_num]->allNodes.end()) {
        // insert into hash table
        auto result = fcache->shards[shard_num]->allNodes.insert(
                                std::make_pair(node->getCurOffset(), node));
        if (!result.second) {   // Offset already exists
            fdb_log(nullptr, FDB_RESULT_EEXIST,
                    "Fatal Error: Offset (%s) already in use (race)!",
                    std::to_string(offset).c_str());
            spin_unlock(&fcache->shards[shard_num]->lock);
            return FDB_RESULT_EEXIST;
        }
        bnodeCacheCurrentUsage.fetch_add(node->getMemConsumption());
        fcache->numItems++;
        fcache->numItemsWritten++;
    } else {
        fdb_log(nullptr, FDB_RESULT_EEXIST,
                "Fatal Error: Offset (%s) already in use!",
                std::to_string(offset).c_str());
        spin_unlock(&fcache->shards[shard_num]->lock);
        return FDB_RESULT_EEXIST;
    }

    fcache->shards[shard_num]->dirtyIndexNodes[offset] = node;
    spin_unlock(&fcache->shards[shard_num]->lock);

    performEviction(node);

    return node->getNodeSize();
}

int BnodeCacheMgr::writeMulti(FileMgr* file,
                              std::vector<bnode_offset_t> &nodes) {

    if (!file) {
        return FDB_RESULT_INVALID_ARGS;
    }

    int total_bytes_written = 0;
    std::vector<Bnode*> wrote;
    for (auto node : nodes) {
        int bytes_written = write(file, node.first, node.second);
        if (bytes_written == static_cast<int>(node.first->getNodeSize())) {
            total_bytes_written += bytes_written;
            wrote.push_back(node.first);
        } else {
            // Return the failed response code, after un-doing
            // writes written as part of this change.
            total_bytes_written = bytes_written;
            removeSelectBnodes(file, wrote);
            break;
        }
    }

    return total_bytes_written;
}

fdb_status BnodeCacheMgr::flush(FileMgr* file) {
    FileBnodeCache* fcache = file->getBnodeCache();

    if (fcache) {
        // Note that this function is invoked as part of a commit operation
        // while the filemgr's lock is already grabbed by a committer.
        // Therefore, we don't need to grab all the shard locks at once.
        return flushDirtyIndexNodes(fcache, true, true);
    }
    return FDB_RESULT_FILE_NOT_OPEN;
}

fdb_status BnodeCacheMgr::addLastBlockMeta(FileMgr* file, bid_t bid) {
    if (!file) {
        return FDB_RESULT_INVALID_ARGS;
    }

    FileBnodeCache* fcache = file->getBnodeCache();
    if (!fcache) {
        return FDB_RESULT_FILE_NOT_OPEN;
    }

    fdb_status status = FDB_RESULT_SUCCESS;

    size_t blocksize = fcache->getFileManager()->getBlockSize();
    size_t offset_of_blk = blocksize - sizeof(IndexBlkMeta);

    IndexBlkMeta blk_meta;
    blk_meta.set(BLK_NOT_FOUND,
                 fcache->getFileManager()->getSbBmpRevnum());
    ssize_t ret = fcache->getFileManager()->writeBuf(
                                               &blk_meta,
                                               sizeof(IndexBlkMeta),
                                               bid * blocksize + offset_of_blk);
    if (ret != static_cast<ssize_t>(sizeof(IndexBlkMeta))) {
        status = ret < 0 ? (fdb_status)ret : FDB_RESULT_WRITE_FAIL;
    }

    return status;
}

fdb_status BnodeCacheMgr::invalidateBnode(FileMgr* file, Bnode* node) {
    if (!file || !node) {
        return FDB_RESULT_INVALID_ARGS;
    }

    FileBnodeCache* fcache = file->getBnodeCache();
    if (!fcache) {
        return FDB_RESULT_FILE_NOT_OPEN;
    }

    size_t shard_num = str_hash(std::to_string(node->getCurOffset())) %
                                fcache->getNumShards();

    if (node->getRefCount() <= 1) {
        spin_lock(&fcache->shards[shard_num]->lock);
        // Search shard hash table
        auto entry = fcache->shards[shard_num]->allNodes.find(node->getCurOffset());
        if (entry != fcache->shards[shard_num]->allNodes.end()) {
            // Remove from all nodes list
            fcache->shards[shard_num]->allNodes.erase(node->getCurOffset());
            // Remove from dirty index nodes (if present)
            fcache->shards[shard_num]->dirtyIndexNodes.erase(node->getCurOffset());
            // Remove from clean nodes (if present)
            list_remove(&fcache->shards[shard_num]->cleanNodes,
                        &node->list_elem);
            fcache->numItems--;
            fcache->numItemsWritten--;
            // Decrement memory usage
            bnodeCacheCurrentUsage.fetch_sub(node->getMemConsumption());
            spin_unlock(&fcache->shards[shard_num]->lock);
        } else {
            spin_unlock(&fcache->shards[shard_num]->lock);
            fdb_log(nullptr, FDB_RESULT_KEY_NOT_FOUND,
                    "Warning: Failed to remove bnode (at offset: %s) "
                    "in file '%s', because it wasn't found in the cache!",
                    std::to_string(node->getCurOffset()).c_str(),
                    fcache->getFileName().c_str());
            return FDB_RESULT_KEY_NOT_FOUND;
        }
    } else {
        // failure of invalidation is used as one of conditions
        // in BnodeMgr layer during node cloning, so we don't
        // need to report warning here.
        return FDB_RESULT_FILE_IS_BUSY;
    }

    return FDB_RESULT_SUCCESS;
}

// Remove all dirty index nodes for the File
// (they are only discarded and not written back)
void BnodeCacheMgr::removeDirtyBnodes(FileMgr* file) {
    if (!file) {
        return;
    }

    FileBnodeCache* fcache = file->getBnodeCache();
    if (fcache) {
        // Note that this function is only invoked as part of database
        // file close or removal when there are no database handles
        // for a given file. Therefore we don't need to grab all the
        // shard locks at once.

        // Remove all dirty bnodes
        flushDirtyIndexNodes(fcache, false, true);
    }
}

// Remove all clean bnodes of the File
void BnodeCacheMgr::removeCleanBnodes(FileMgr* file) {
    if (!file) {
        return;
    }

    FileBnodeCache* fcache = file->getBnodeCache();

    if (fcache) {
        struct list_elem *elem;
        Bnode* item;
        // Note that this function is only invoked as part of database
        // file close or removal when there are no database handles
        // for a given file. Therefore we don't need to grab all the
        // shard locks at once.

        // Remove all clean blocksfrom each shard in the file
        for (size_t i = 0; i < fcache->getNumShards(); ++i) {
            spin_lock(&fcache->shards[i]->lock);
            elem = list_begin(&fcache->shards[i]->cleanNodes);
            while (elem) {
                item = reinterpret_cast<Bnode*>(elem);
                // Remove from the clean nodes list
                elem = list_remove(&fcache->shards[i]->cleanNodes, elem);
                // Remove from the all node list
                fcache->shards[i]->allNodes.erase(item->getCurOffset());
                fcache->numItems--;
                // Decrement memory usage
                bnodeCacheCurrentUsage.fetch_sub(item->getMemConsumption());
                // Free the item
                delete item;
            }
            spin_unlock(&fcache->shards[i]->lock);
        }
    }
}

// Remove a file bnode cache from the file bnode cache list.
// MUST ensure that there is no dirty index node that belongs to this File
// (or memory leak occurs).
bool BnodeCacheMgr::removeFile(FileMgr* file) {
    bool rv = false;
    if (!file) {
        return rv;
    }

    FileBnodeCache* fcache = file->getBnodeCache();

    if (fcache) {
        // Acquire lock
        spin_lock(&bnodeCacheLock);
        // File Bnode cache must be empty
        if (!fcache->empty()) {
            spin_unlock(&bnodeCacheLock);
            fdb_log(nullptr, FDB_RESULT_FILE_REMOVE_FAIL,
                    "Warning: Failed to remove file cache instance for "
                    "a file '%s' because the file cache instance is not "
                    "empty!", file->getFileName());
            return rv;
        }

        // Remove from the file bnode cache map
        fileMap.erase(std::string(file->getFileName()));
        spin_unlock(&bnodeCacheLock);

        // We don't need to grab the file bnode cache's partition locks
        // at once because this function is only invoked when there are
        // no database handles that access the file.
        if (prepareDeallocationForFileBnodeCache(fcache)) {
            freeFileBnodeCache(fcache); // No other callers accessing the file
            rv = true;
        } // Otherwise, a file bnode cache is in use by eviction, Deletion delayed
    }

    return rv;
}

FileBnodeCache* BnodeCacheMgr::createFileBnodeCache(FileMgr* file) {
    spin_lock(&bnodeCacheLock);
    FileBnodeCache* fcache = createFileBnodeCache_UNLOCKED(file);
    spin_unlock(&bnodeCacheLock);
    return fcache;
}

// bnodeCacheLock to be acquired before invoking this function
FileBnodeCache* BnodeCacheMgr::createFileBnodeCache_UNLOCKED(FileMgr* file) {
    if (!file) {
        return nullptr;
    }

    // Before a new file bnode cache is created, garbage collect zombies
    cleanUpInvalidFileBnodeCaches();

    size_t num_shards;
    if (file->getConfig()->getNumBcacheShards()) {
        num_shards = file->getConfig()->getNumBcacheShards();
    } else {
        num_shards = DEFAULT_NUM_BCACHE_PARTITIONS;
    }

    std::string file_name(file->getFileName());
    FileBnodeCache* fcache = new FileBnodeCache(file_name, file, num_shards);

    // For random eviction among shards
    randomize();

    // Insert into file map
    fileMap[file_name] = fcache;
    file->setBnodeCache(fcache);

    if (writer_lock(&fileListLock) == 0) {
        fileList.push_back(fcache);
        writer_unlock(&fileListLock);
    } else {
        fdb_log(nullptr, FDB_RESULT_LOCK_FAIL,
                "BnodeCacheMgr::createFileBnodeCache(): "
                "Failed to acquire writer lock on the file list lock!");
    }

    return fcache;
}

bool BnodeCacheMgr::freeFileBnodeCache(FileBnodeCache* fcache, bool force) {
    if (!fcache) {
        return false;
    }

    if (!fcache->empty() && !force) {
        fdb_log(nullptr, FDB_RESULT_FILE_IS_BUSY,
                "Warning: Failed to free file bnode cache instance for file "
                "'%s', because the file block cache instance isn't empty!",
                fcache->getFileName().c_str());
        return false;
    }

    if (fcache->getRefCount() != 0 && !force) {
        fdb_log(nullptr, FDB_RESULT_FILE_IS_BUSY,
                "Warning: Failed to free file bnode cache instance for file "
                "'%s', because its ref counter is not zero!",
                fcache->getFileName().c_str());
        return false;
    }

    fileMap.erase(fcache->getFileName());

    // Free file bnode cache
    delete fcache;

    return true;
}

static const size_t BNODE_BUFFER_HEADROOM = 256;

fdb_status BnodeCacheMgr::fetchFromFile(FileMgr* file,
                                        Bnode** node,
                                        cs_off_t offset) {

    if (!file) {
        return FDB_RESULT_INVALID_ARGS;
    }

    fdb_status status = FDB_RESULT_SUCCESS;
    ssize_t ret = 0;

    // 1> Read the first 4 bytes
    uint32_t length;
    ret = file->readBuf(&length, sizeof(length), offset);
    if (ret != sizeof(length)) {
        status = ret < 0 ? (fdb_status)ret : FDB_RESULT_READ_FAIL;
        return status;
    }
    length = Bnode::readNodeSize(&length);

    // 2> Alloc Buffer
    // Note: we allocate a little bit more memory to avoid to call
    //       realloc() if a few new entries are inserted.
    void *buf = malloc(length + BNODE_BUFFER_HEADROOM);

    // 3> Read: If the node is written over multiple blocks, read
    //    them accoding to the block meta.
    size_t blocksize = file->getBlockSize();
    size_t blocksize_avail = blocksize - sizeof(IndexBlkMeta);
    size_t offset_of_block = offset % blocksize;
    size_t offset_of_buffer = 0;
    size_t remaining_size = length;
    bid_t cur_bid = offset / blocksize;
    IndexBlkMeta blk_meta;

    Bnode* bnode_out = new Bnode();

    if (offset_of_block + length <= blocksize_avail) {
        // Entire node is stored in a single block
        ret = file->readBuf(buf, length, offset);
        if (ret != static_cast<ssize_t>(length)) {
            status = ret < 0 ? (fdb_status)ret : FDB_RESULT_READ_FAIL;
            free(buf);
            delete bnode_out;
            return status;
        }
        // add BID info into the bnode
        bnode_out->addBidList(cur_bid);
    } else {
        size_t cur_slice_size;
        while (remaining_size) {
            cur_slice_size = blocksize_avail - offset_of_block;
            if (cur_slice_size > remaining_size) {
                cur_slice_size = remaining_size;
            }

            // read data from the block
            ret = file->readBuf((uint8_t*)buf + offset_of_buffer,
                                cur_slice_size,
                                cur_bid * blocksize + offset_of_block);
            if (ret != static_cast<ssize_t>(cur_slice_size)) {
                status = ret < 0 ? (fdb_status)ret : FDB_RESULT_READ_FAIL;
                free(buf);
                delete bnode_out;
                return status;
            }
            // add BID info into the bnode
            bnode_out->addBidList(cur_bid);

            remaining_size -= cur_slice_size;
            offset_of_buffer += cur_slice_size;

            if (remaining_size) {
                // Read next block's info from the meta segment
                ret = file->readBuf(&blk_meta,
                                    sizeof(IndexBlkMeta),
                                    cur_bid * blocksize + blocksize_avail);
                if (ret != static_cast<ssize_t>(sizeof(IndexBlkMeta))) {
                    status = ret < 0 ? (fdb_status)ret : FDB_RESULT_READ_FAIL;
                    free(buf);
                    delete bnode_out;
                    return status;
                }

                blk_meta.decode();
                cur_bid = blk_meta.nextBid;
                offset_of_block = 0;
            }
        }
    }

    bnode_out->importRaw(buf, length + BNODE_BUFFER_HEADROOM);
    bnode_out->setCurOffset(offset);
    // 'buf' to be freed by client
    *node = bnode_out;

    return status;

}

bool dirtyNodesCustomSort(std::pair<size_t, Bnode*> entry1,
                          std::pair<size_t, Bnode*> entry2) {
    return (entry1.second->getCurOffset() < entry2.second->getCurOffset());
}

fdb_status BnodeCacheMgr::writeCachedData(WriteCachedDataArgs& args)
{
    ssize_t ret = 0;
    fdb_status status = FDB_RESULT_SUCCESS;

    if (args.flush_all) {
        // 'Flush all' option
        // => use temp_buf to write as large as data sequentially.
        if (args.temp_buf_pos + args.size_to_append > defaultFlushLimit ||
            args.batch_write_offset + args.temp_buf_pos != args.cur_offset) {
            // 1) The remaining space in the temp buf is not enough, OR
            // 2) Last written data in the buffer and incoming data are not
            //    consecutive,
            // => flush current buffer and reset.
            ret = args.fcache->getFileManager()->writeBuf(args.temp_buf.get(),
                                                          args.temp_buf_pos,
                                                          args.batch_write_offset);
            if (ret != static_cast<ssize_t>(args.temp_buf_pos)) {
                status = ret < 0 ? (fdb_status)ret : FDB_RESULT_WRITE_FAIL;
                return status;
            }
            args.temp_buf_pos = 0;
            args.batch_write_offset = args.cur_offset;
        }
        memcpy(args.temp_buf.get() + args.temp_buf_pos,
               args.data_to_append,
               args.size_to_append);
        args.temp_buf_pos += args.size_to_append;
    } else {
        // Otherwise => directly invoke writeBuf().
        ret = args.fcache->getFileManager()->writeBuf(args.data_to_append,
                                                      args.size_to_append,
                                                      args.cur_offset);
        if (ret != static_cast<ssize_t>(args.size_to_append)) {
            status = ret < 0 ? (fdb_status)ret : FDB_RESULT_WRITE_FAIL;
            return status;
        }
    }

    return FDB_RESULT_SUCCESS;
}

fdb_status BnodeCacheMgr::flushDirtyIndexNodes(FileBnodeCache* fcache,
                                               bool sync,
                                               bool flush_all) {

    if (!fcache) {
        return FDB_RESULT_INVALID_ARGS;
    }

    ssize_t ret = 0;
    fdb_status status = FDB_RESULT_SUCCESS;
    std::vector<std::pair<size_t, Bnode*>> dirty_nodes;
    std::map<cs_off_t, Bnode*>* shard_dirty_tree;
    uint64_t flushed = 0;
    size_t count = 0;

    // Allocate the temporary buffer (1MB) to write multiple dirty index nodes at once
    WriteCachedDataArgs temp_buf_args(fcache, defaultFlushLimit,
                                      flush_all);

    while (true) {
        if (count == 0) {
            for (size_t i = 0; i < fcache->getNumShards(); ++i) {
                spin_lock(&fcache->shards[i]->lock);
                if (flush_all) {
                    // In case of flush_all, push all the dirty items to
                    // the temporary vector to sort those items with their offsets.
                    for (auto &entry : fcache->shards[i]->dirtyIndexNodes) {
                        dirty_nodes.push_back(std::make_pair(i, entry.second));
                    }
                } else {
                    auto entry = fcache->shards[i]->dirtyIndexNodes.begin();
                    if (entry != fcache->shards[i]->dirtyIndexNodes.end()) {
                        dirty_nodes.push_back(std::make_pair(i, entry->second));
                    }
                }
                spin_unlock(&fcache->shards[i]->lock);
            }

            if (dirty_nodes.empty()) {
                break;
            } else if (dirty_nodes.size() > 1) {
                // Ensure that the dirty nodes are written in increasing
                // offset order
                std::sort(dirty_nodes.begin(), dirty_nodes.end(),
                          dirtyNodesCustomSort);
            }
        }


        auto dirty_entry = dirty_nodes[count++];
        size_t shard_num = dirty_entry.first;
        Bnode* dirty_bnode = dirty_entry.second;

        spin_lock(&fcache->shards[shard_num]->lock);

        shard_dirty_tree = &fcache->shards[shard_num]->dirtyIndexNodes;

        bool item_exist = false;
        if (!shard_dirty_tree->empty()) {
            if (shard_dirty_tree->find(dirty_bnode->getCurOffset())
                                            != shard_dirty_tree->end()) {
                item_exist = true;
            }
        }

        if (!item_exist) {
            // The original item in the shard dirty index node map was removed.
            // Moving on to the next one in the cross-shard dirty node list
            spin_unlock(&fcache->shards[shard_num]->lock);
            if (count == dirty_nodes.size()) {
                count = 0;
                dirty_nodes.clear();
            }
            continue;
        }

        // Remove from the shard dirty index node list
        shard_dirty_tree->erase(dirty_bnode->getCurOffset());

        if (sync) {
            size_t nodesize = dirty_bnode->getNodeSize();
            size_t blocksize = fcache->getFileManager()->getBlockSize();
            size_t blocksize_avail = blocksize - sizeof(IndexBlkMeta);
            size_t offset_of_block = dirty_bnode->getCurOffset() % blocksize;
            size_t offset_of_buf = 0;
            size_t remaining_size = nodesize;

            void *buf = nullptr;
            if ( !(buf = dirty_bnode->exportRaw()) ) {
                // TODO: Handle this gracefully perhaps ..
                assert(false);
            }

            uint64_t dirty_bnode_offset = dirty_bnode->getCurOffset();
            if (flush_all && count == 1) {
                temp_buf_args.batch_write_offset = dirty_bnode_offset;
            }

            if (flush_all &&
                temp_buf_args.batch_write_offset + temp_buf_args.temp_buf_pos <
                                                            dirty_bnode_offset) {
                // To avoid 'node size' field (4 bytes) being written over multiple
                // blocks, a few bytes can be skipped and we need to calibrate it.

                // before calibration, we should append block meta if necessary.
                bid_t prev_bid = (temp_buf_args.batch_write_offset +
                                  temp_buf_args.temp_buf_pos) / blocksize;
                bid_t cur_bid = dirty_bnode_offset / blocksize;
                size_t prev_blk_offset = (temp_buf_args.batch_write_offset +
                                          temp_buf_args.temp_buf_pos) % blocksize;

                // skipped length should be smaller than 4 bytes.
                if (prev_bid + 1 == cur_bid &&
                    prev_blk_offset + sizeof(uint32_t) > blocksize_avail) {
                    // adjust temp_buf_pos to point to the IndexBlkMeta location
                    // (i.e., the last 16 bytes in the block).
                    temp_buf_args.temp_buf_pos += (blocksize_avail - prev_blk_offset);

                    IndexBlkMeta blk_meta;
                    blk_meta.set(cur_bid, fcache->getFileManager()->getSbBmpRevnum());

                    temp_buf_args.data_to_append = &blk_meta;
                    temp_buf_args.size_to_append = sizeof(IndexBlkMeta);
                    temp_buf_args.cur_offset = prev_bid * blocksize + blocksize_avail;
                    status = writeCachedData(temp_buf_args);
                    if (status != FDB_RESULT_SUCCESS) {
                        spin_unlock(&fcache->shards[shard_num]->lock);
                        return status;
                    }
                }
            }

            if (remaining_size <= blocksize_avail - offset_of_block) {
                // entire node can be written in a block .. just write it.
                temp_buf_args.data_to_append = buf;
                temp_buf_args.size_to_append = remaining_size;
                temp_buf_args.cur_offset = dirty_bnode->getCurOffset();
                status = writeCachedData(temp_buf_args);
                if (status != FDB_RESULT_SUCCESS) {
                    spin_unlock(&fcache->shards[shard_num]->lock);
                    return status;
                }
            } else {
                IndexBlkMeta blk_meta;
                size_t cur_slice_size;
                size_t num_blocks = dirty_bnode->getBidListSize();
                bid_t cur_bid;

                for (size_t i = 0; i < num_blocks; ++i) {
                    cur_bid = dirty_bnode->getBidFromList(i);
                    cur_slice_size = blocksize_avail - offset_of_block;
                    if (cur_slice_size > remaining_size) {
                        cur_slice_size = remaining_size;
                    }

                    // write data for the block
                    temp_buf_args.data_to_append = static_cast<uint8_t*>(buf) + offset_of_buf;
                    temp_buf_args.size_to_append = cur_slice_size;
                    temp_buf_args.cur_offset = cur_bid * blocksize + offset_of_block;
                    status = writeCachedData(temp_buf_args);
                    if (status != FDB_RESULT_SUCCESS) {
                        spin_unlock(&fcache->shards[shard_num]->lock);
                        return status;
                    }

                    remaining_size -= cur_slice_size;
                    offset_of_buf += cur_slice_size;

                    if (remaining_size) {
                        // Intermediate block, write metadata to indicate it
                        blk_meta.set(dirty_bnode->getBidFromList(i+1),
                                     fcache->getFileManager()->getSbBmpRevnum());

                        temp_buf_args.data_to_append = &blk_meta;
                        temp_buf_args.size_to_append = sizeof(IndexBlkMeta);
                        temp_buf_args.cur_offset = cur_bid * blocksize + blocksize_avail;
                        status = writeCachedData(temp_buf_args);
                        if (status != FDB_RESULT_SUCCESS) {
                            spin_unlock(&fcache->shards[shard_num]->lock);
                            return status;
                        }

                        // new block .. reset block offset
                        offset_of_block = 0;
                    }
                }
            }

            // Move to the shard clean node list
            list_push_back(&fcache->shards[shard_num]->cleanNodes,
                           &dirty_bnode->list_elem);
            flushed += dirty_bnode->getNodeSize();
        } else {
            // Not synced, just discarded
            fcache->numItems--;
            fcache->numItemsWritten--;
            // Remove from the all node list
            fcache->shards[shard_num]->allNodes.erase(dirty_bnode->getCurOffset());
            // Decrement memory usage
            bnodeCacheCurrentUsage.fetch_sub(dirty_bnode->getMemConsumption());
            flushed += dirty_bnode->getNodeSize();
            // Free the dirty node as it can be simply discarded
            delete dirty_bnode;
        }

        spin_unlock(&fcache->shards[shard_num]->lock);

        if (count == dirty_nodes.size()) {
            count = 0;
            dirty_nodes.clear();
        }
        if (sync) {
            if (flush_all || flushed < flushLimit) {
                continue;
            } else {
                break;
            }
        }
    }

    if (flush_all && temp_buf_args.temp_buf_pos) {
        ret = fcache->getFileManager()->writeBuf(temp_buf_args.temp_buf.get(),
                                                 temp_buf_args.temp_buf_pos,
                                                 temp_buf_args.batch_write_offset);
        if (ret != static_cast<ssize_t>(temp_buf_args.temp_buf_pos)) {
            status = ret < 0 ? (fdb_status)ret : FDB_RESULT_WRITE_FAIL;
            return status;
        }
    }

    return status;
}

bool BnodeCacheMgr::prepareDeallocationForFileBnodeCache(FileBnodeCache* fcache) {
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
            // File has already been removed form fileList
            writer_unlock(&fileListLock);
            return false;
        }

        if (fcache->getRefCount() != 0) {
            // The file bnode cache is currently being accessed by another
            // thread for eviction
            fileZombies.push_front(fcache);
            ret = false;    // Delay the deletion
        }

        writer_unlock(&fileListLock);
    } else {
        ret = false;
        fdb_log(nullptr, FDB_RESULT_LOCK_FAIL,
                "BnodeCacheMgr::prepareDeallocationForFileBnodeCache(): "
                "Failed to acquire writer lock on the file list lock!");
    }
    return ret;
}

void BnodeCacheMgr::cleanUpInvalidFileBnodeCaches() {
    if (writer_lock(&fileListLock) == 0) {
        for (auto itr = fileZombies.begin(); itr != fileZombies.end();) {
            if (freeFileBnodeCache(*itr)) {
                itr = fileZombies.erase(itr);
            } else {
                ++itr;
            }
        }
        writer_unlock(&fileListLock);
    } else {
        fdb_log(nullptr, FDB_RESULT_LOCK_FAIL,
                "BnodeCacheMgr::cleanUpInvalidFileBnodeCaches(): "
                "Failed to acquire writer lock on the file list lock!");
    }
}

void BnodeCacheMgr::performEviction(Bnode *node_to_protect) {
    // The global bnode cache lock need not be acquired here because the
    // file's bnode cache instance (FileBnodeCache) can be freed only if
    // there are no database handles opened for the file.

    struct list_elem* elem;
    Bnode* item = nullptr;
    FileBnodeCache* victim = nullptr;

    // Select the victim and then the clean blocks from the victim file, eject
    // items until memory usage falls 4K (max btree node size) less than
    // the allowed bnodeCacheLimit.
    // TODO: Maybe implement a daemon task that does this eviction,
    //       rather than the reader/writer doing it.
    while (bnodeCacheCurrentUsage.load() >= bnodeCacheLimit) {
        // Firstly, select the victim file
        victim = chooseEvictionVictim();
        if (victim && victim->setEvictionInProgress(true)) {
            // Check whether the file has at least one block to be evicted,
            // if not try picking a random victim again
            if (victim->numItems.load() == 0) {
                victim->refCount--;
                victim->setEvictionInProgress(false);
                victim = nullptr;
            }
        } else if (victim) {
            victim->refCount--;
            victim = nullptr;
        }

        if (victim == nullptr) {
            continue;
        }

        size_t num_shards = victim->getNumShards();
        size_t i = random(num_shards);
        BnodeCacheShard* bshard = nullptr;
        size_t toVisit = num_shards;

        while (bnodeCacheCurrentUsage.load() > (bnodeCacheLimit - 4096) &&
               toVisit-- != 0) {
            i = (i + 1) % num_shards;   // Round-robin over empty shards
            bshard = victim->shards[i].get();
            spin_lock(&bshard->lock);
            if (bshard->empty()) {
                spin_unlock(&bshard->lock);
                continue;
            }

            if (list_empty(&bshard->cleanNodes)) {
                spin_unlock(&bshard->lock);
                // When the victim shard has no clean index node, evict
                // some dirty blocks from shards.
                fdb_status status = flushDirtyIndexNodes(victim, true, false);
                if (status != FDB_RESULT_SUCCESS) {
                    fdb_log(nullptr, status,
                            "BnodeCacheMgr::performEviction(): Flushing dirty "
                            "index nodes failed for shard %s in file '%s'",
                            std::to_string(i).c_str(),
                            victim->getFileName().c_str());
                    return;
                }
                spin_lock(&bshard->lock);
            }

            elem = list_pop_front(&bshard->cleanNodes);
            if (elem) {
                item = reinterpret_cast<Bnode*>(elem);
                if (item != node_to_protect && item->getRefCount() == 0) {
                    victim->numVictims++;

                    victim->numItems--;
                    // Remove from the shard nodes list
                    bshard->allNodes.erase(item->getCurOffset());
                    // Decrement mem usage stat
                    bnodeCacheCurrentUsage.fetch_sub(item->getMemConsumption());

                    // Free bnode instance
                    delete item;
                } else {
                    list_push_back(&bshard->cleanNodes,
                                   &item->list_elem);
                }
            }
            spin_unlock(&bshard->lock);
        }

        victim->refCount--;
        victim->setEvictionInProgress(false);
        victim = nullptr;
    }
}

static const size_t MAX_VICTIM_SELECTIONS = 5;
static const size_t MIN_TIMESTAMP_GAP = 15000;  // 15 seconds

FileBnodeCache* BnodeCacheMgr::chooseEvictionVictim() {
    FileBnodeCache* ret = nullptr;

    uint64_t max_items = 0;
    uint64_t min_timestamp = static_cast<uint64_t>(-1);
    uint64_t max_timestamp = 0;
    uint64_t victim_timestamp, victim_num_items;
    int victim_idx, victim_by_time = -1, victim_by_items = -1;
    size_t num_attempts;

    if (reader_lock(&fileListLock) == 0) {
        // Pick the victim that has the oldest access timestamp
        // among the files randomly selected, if the gap between
        // the oldest and the newest timestamps is greater than
        // the threshold. Otherwise, pick the victim that has the
        // largest number of cached items among the files.
        num_attempts = fileList.size() / 10 + 1;
        if (num_attempts > MAX_VICTIM_SELECTIONS) {
            num_attempts = MAX_VICTIM_SELECTIONS;
        } else {
            if (num_attempts == 1 && fileList.size() > 1) {
                ++num_attempts;
            }
        }

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
                ret = fileList.at(victim_by_time);
            }
        } else {
            if (victim_by_items != -1) {
                ret = fileList.at(victim_by_items);
            }
        }

        if (ret) {
            ret->refCount++;
        }

        reader_unlock(&fileListLock);
    } else {
        fdb_log(nullptr, FDB_RESULT_LOCK_FAIL,
                "BnodeCacheMgr::chooseEvictionVictim(): "
                "Failed to acquire reader lock on the file list lock!");
    }

    return ret;
}

void BnodeCacheMgr::removeSelectBnodes(FileMgr* file,
                                       std::vector<Bnode*>& nodes) {
    if (!file) {
        return;
    }

    FileBnodeCache* fcache = file->getBnodeCache();
    if (!fcache) {
        return;
    }

    for (auto node : nodes) {
        size_t shard_num = str_hash(std::to_string(node->getCurOffset())) %
                           fcache->getNumShards();
        spin_lock(&fcache->shards[shard_num]->lock);

        // Search shard hash table
        auto entry = fcache->shards[shard_num]->allNodes.find(node->getCurOffset());
        if (entry != fcache->shards[shard_num]->allNodes.end()) {
            // Remove from all nodes list
            fcache->shards[shard_num]->allNodes.erase(node->getCurOffset());
            // Remove from dirty index nodes (if present)
            fcache->shards[shard_num]->dirtyIndexNodes.erase(node->getCurOffset());
            // Remove from clean nodes (if present)
            list_remove(&fcache->shards[shard_num]->cleanNodes,
                        &node->list_elem);
            fcache->numItems--;
            fcache->numItemsWritten--;
            // Decrement memory usage
            bnodeCacheCurrentUsage.fetch_sub(node->getMemConsumption());
        }

        spin_unlock(&fcache->shards[shard_num]->lock);
    }
}
