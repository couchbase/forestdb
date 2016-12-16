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

#include <sys/types.h>
#include <sys/stat.h>
#include <stdint.h>
#include <errno.h>

#ifdef _ASYNC_IO
#if !defined(WIN32) && !defined(_WIN32)
#include <libaio.h>
#include <sys/time.h>
#endif
#endif

#include "libforestdb/fdb_errors.h"

#include "internal_types.h"
#include "common.h"
#include "hash.h"
#include "partiallock.h"
#include "atomic.h"
#include "checksum.h"
#include "filemgr_ops.h"
#include "encryption.h"
#include "superblock.h"
#include "staleblock.h"
#include "taskable.h"

#include <atomic>
#include <mutex>
#include <string>
#include <unordered_map>
#include <unordered_set>

#ifdef _PLATFORM_LIB_AVAILABLE
#include <platform/histogram.h>
#endif

#define FILEMGR_SYNC 0x01
#define FILEMGR_READONLY 0x02
#define FILEMGR_ROLLBACK_IN_PROG 0x04
#define FILEMGR_CREATE 0x08
#define FILEMGR_REMOVAL_IN_PROG 0x10
#define FILEMGR_CREATE_CRC32 0x20 // Used in testing upgrade path
#define FILEMGR_CANCEL_COMPACTION 0x40 // Cancel the compaction
#define FILEMGR_EXCL_CREATE 0x80 // fail open if file already exists

class SuperblockBase;

class FileMgrConfig {
public:
    FileMgrConfig()
        : blocksize(FDB_BLOCKSIZE), ncacheblock(0),
          flushlimit(1048576), flag(0), chunksize(sizeof(uint64_t)),
          options(0x00), seqtree_opt(FDB_SEQTREE_NOT_USE), prefetch_duration(0),
          num_wal_shards(DEFAULT_NUM_WAL_PARTITIONS),
          num_bcache_shards(DEFAULT_NUM_BCACHE_PARTITIONS),
          block_reusing_threshold(65/*default*/),
          num_keeping_headers(5/*default*/)
    {
        encryption_key.algorithm = FDB_ENCRYPTION_NONE;
        memset(encryption_key.bytes, 0, sizeof(encryption_key.bytes));
    }

    FileMgrConfig(int _blocksize, int _ncacheblock,
                  size_t _flushlimit, int _flag, int _chunksize, uint8_t _options,
                  uint8_t _seqtree_opt, uint64_t _prefetch_duration,
                  uint64_t _num_wal_shards, uint64_t _num_bcache_shards,
                  fdb_encryption_algorithm_t _algorithm,
                  uint8_t _encryption_bytes,
                  uint64_t _block_reusing_threshold,
                  uint64_t _num_keeping_headers)
        : blocksize(_blocksize),
          ncacheblock(_ncacheblock),
          flushlimit(_flushlimit),
          flag(_flag),
          chunksize(_chunksize),
          options(_options),
          seqtree_opt(_seqtree_opt),
          prefetch_duration(_prefetch_duration),
          num_wal_shards(_num_wal_shards),
          num_bcache_shards(_num_bcache_shards),
          block_reusing_threshold(_block_reusing_threshold),
          num_keeping_headers(_num_keeping_headers)
    {
        encryption_key.algorithm = _algorithm;
        memset(encryption_key.bytes,
               _encryption_bytes,
               sizeof(encryption_key.bytes));
    }

    void operator=(const FileMgrConfig& config) {
        blocksize = config.blocksize;
        ncacheblock = config.ncacheblock;
        flushlimit = config.flushlimit;
        flag = config.flag;
        seqtree_opt = config.seqtree_opt;
        chunksize = config.chunksize;
        options = config.options;
        prefetch_duration = config.prefetch_duration;
        num_wal_shards = config.num_wal_shards;
        num_bcache_shards = config.num_bcache_shards;
        encryption_key = config.encryption_key;
        block_reusing_threshold.store(config.block_reusing_threshold.load(),
                                      std::memory_order_relaxed);
        num_keeping_headers.store(config.num_keeping_headers.load(),
                                  std::memory_order_relaxed);
    }

    void setBlockSize(int to) {
        blocksize = to;
    }

    void setNcacheBlock(int to) {
        ncacheblock = to;
    }

    void setFlushLimit(size_t to) {
        flushlimit = to;
    }

    void setFlag(int to) {
        flag = to;
    }

    void addFlag(int to) {
        flag |= to;
    }

    void setChunkSize(int to) {
        chunksize = to;
    }

    void setOptions(uint8_t option) {
        options = option;
    }

    void addOptions(uint8_t option) {
        options |= option;
    }

    void setSeqtreeOpt(uint8_t to) {
        seqtree_opt = to;
    }

    void setPrefetchDuration(uint64_t to) {
        prefetch_duration = to;
    }

    void setNumWalShards(uint16_t to) {
        num_wal_shards = to;
    }

    void setNumBcacheShards(uint16_t to) {
        num_bcache_shards = to;
    }

    void setEncryptionKey(fdb_encryption_algorithm_t to,
                          uint8_t byte) {
        encryption_key.algorithm = to;
        memset(encryption_key.bytes, byte, sizeof(encryption_key.bytes));
    }

    void setEncryptionKey(const fdb_encryption_key &key) {
        encryption_key = key;
    }

    void setBlockReusingThreshold(uint64_t to) {
        block_reusing_threshold.store(to, std::memory_order_relaxed);
    }

    void setNumKeepingHeaders(uint64_t to) {
        num_keeping_headers.store(to, std::memory_order_relaxed);
    }

    int getBlockSize() const {
        return blocksize;
    }

    int getNcacheBlock() const {
        return ncacheblock;
    }

    size_t getFlushLimit() const {
        return flushlimit;
    }

    int getFlag() const {
        return flag;
    }

    int getChunkSize() const {
        return chunksize;
    }

    uint8_t getOptions() const {
        return options;
    }

    uint8_t getSeqtreeOpt() const {
        return seqtree_opt;
    }

    uint64_t getPrefetchDuration() const {
        return prefetch_duration;
    }

    uint16_t getNumWalShards() const {
        return num_wal_shards;
    }

    uint8_t getNumBcacheShards() const {
        return num_bcache_shards;
    }

    fdb_encryption_key* getEncryptionKey() {
        return &encryption_key;
    }

    uint64_t getBlockReusingThreshold() const {
        return block_reusing_threshold.load(std::memory_order_relaxed);
    }

    uint64_t getNumKeepingHeaders() const {
        return num_keeping_headers.load(std::memory_order_relaxed);
    }

private:
    int blocksize;
    int ncacheblock;
    size_t flushlimit;
    int flag;
    int chunksize;
    uint8_t options;
    uint8_t seqtree_opt;
    uint64_t prefetch_duration;
    uint16_t num_wal_shards;
    uint16_t num_bcache_shards;
    fdb_encryption_key encryption_key;
    // Stale block reusing threshold
    std::atomic<uint64_t> block_reusing_threshold;
    // Number of the last commit headders whose stale blocks should
    // be kept for snapshot readers.
    std::atomic<uint64_t> num_keeping_headers;
};

#ifndef _LATENCY_STATS
#define LATENCY_STAT_START()
#define LATENCY_STAT_END(file, type)
#else
class LatencyStats;
#define LATENCY_STAT_START() \
    uint64_t begin=get_monotonic_ts();
#define LATENCY_STAT_END(file, type) \
    uint64_t end = get_monotonic_ts();\
    LatencyStats::update(file, type, ts_diff(begin, end));

struct latency_stat {
    std::atomic<uint64_t> lat_min;
    std::atomic<uint64_t> lat_max;
    std::atomic<uint64_t> lat_sum;
    std::atomic<uint64_t> lat_num;
};

#endif // _LATENCY_STATS

struct async_io_handle {
#ifdef _ASYNC_IO
#if !defined(WIN32) && !defined(_WIN32)
    struct iocb **ioq;
    struct io_event *events;
    io_context_t ioctx;
#endif
#endif
    uint8_t *aio_buf;
    uint64_t *offset_array;
    size_t queue_depth;
    size_t block_size;
    fdb_fileops_handle fops_handle;
};

typedef int filemgr_fs_type_t;
enum {
    FILEMGR_FS_NO_COW = 0x01,
    FILEMGR_FS_EXT4_WITH_COW = 0x02,
    FILEMGR_FS_BTRFS = 0x03
};

struct filemgr_buffer {
    void *block;
    bid_t lastbid;
};

class FileMgr;

/**
 * Callback definitions for operations supported in FileMgrMap
 */
typedef void *filemgr_factory_scan_cb(FileMgr *file, void *ctx);
typedef void filemgr_factory_free_cb(FileMgr *file);

/**
 * Callback definitions for SuperblockBase (or its child class) initialization.
 */
typedef void (*superblock_init_cb)(FileMgr *file);

/**
 * File Manager factory singleton class whose purpose is to maintain an
 * unordered map of all the file manager instances.
 */
class FileMgrMap {
public:
    FileMgrMap();

    ~FileMgrMap();

    /* Adds a new entry to the map */
    void addEntry(const std::string filename, FileMgr *file);

    /* Removes the entry from the map */
    void removeEntry(const std::string filename);

    /* Looks up and fetches the entry from the map, nullptr if not found */
    FileMgr* fetchEntry(const std::string filename);

    /* Scans through all the entries of the map and invokes the callback
       function for each, stops iteration and returns the first NON-NULL
       entry obtained as return value from the callback invocation */
    void* scan(filemgr_factory_scan_cb *scan_callback, void *ctx);

    /* Iterates through all the entries of the map and invokes the
       free callback function for each */
    void freeEntries(filemgr_factory_free_cb iter_callback);

    /* Returns a singleton instance for the class */
    static FileMgrMap* get(void);

    /* Destroys the singleton instance of the class */
    static void shutdown(void);

private:
    // Lock to protect the unordered map
    spin_t fileMapLock;
    // Unordered map that maps filenames to FileMgr instances
    std::unordered_map<std::string, FileMgr *> fileMap;

    // Singleton creation
    static std::mutex initGuard;
    static std::atomic<FileMgrMap *> instance;
};

class FileMgrHeader {
public:
    FileMgrHeader()
        : size(0), revnum(0), seqnum(0), bid(0), data(nullptr) { }

    ~FileMgrHeader() { }

    void reset() {
        size = 0;
        revnum = 0;
        seqnum = 0;
        bid = 0;
        if (data) {
            free(data);
            data = nullptr;
        }
        op_stat.reset();
        stat.reset();
    }

    // Why Atomic?
    // Consider following example of a race..
    // 1. Thread 1 does commit, loading the header with a new size
    //    since the new filename needs to be persisted in header
    // 2. Auto compaction daemon opens file for compaction and does
    //    fdb_kvs_get_committed_seqnum() which calls getHeaderBid()
    //    which first checks if a header is present by reading the
    //    size variable outside of the file manager spin lock
    //    Atomic allows us to avoid grabbing spin lock for simple
    //    header size reads
    std::atomic<filemgr_header_len_t> size;
    filemgr_header_revnum_t revnum;
    std::atomic<uint64_t> seqnum;
    std::atomic<uint64_t> bid;
    KvsOpsStat op_stat;             // op stats for default KVS
    KvsStat stat;                   // stats for the default KVS
    void *data;
};

typedef uint8_t filemgr_prefetch_status_t;
enum {
    FILEMGR_PREFETCH_IDLE = 0,
    FILEMGR_PREFETCH_RUNNING = 1,
    FILEMGR_PREFETCH_ABORT = 2,
    FILEMGR_PREFETCH_TERMINATED = 3
};

#define DLOCK_MAX (41) /* a prime number */
class Wal;
class KvsHeader;
class FileBlockCache;
class FileBnodeCache;

typedef struct {
    mutex_t mutex;
    bool locked;
} mutex_lock_t;

class StaleDataManagerBase;

typedef fdb_status (*register_file_removal_func)(FileMgr *file,
                                                 ErrLogCallback *log_callback);
typedef bool (*check_file_removal_func)(const char *filename);

typedef struct {
    FileMgr *file;
    int rv;
} filemgr_open_result;

typedef char* (filemgr_redirect_hdr_func)(FileMgr *old_file, uint8_t *buf,
                                          FileMgr *new_file);

struct filemgr_dirty_update_node {
    union {
        // AVL-tree element
        struct avl_node avl;
        // list element
        struct list_elem le;
    };
    // ID from the counter number
    uint64_t id;
    // flag indicating if this set of dirty blocks can be accessible.
    bool immutable;
    // flag indicating if this set of dirty blocks are already copied to newer node.
    bool expired;
    // number of threads (snapshots) accessing this dirty block set.
    std::atomic<uint32_t> ref_count;
    // dirty root node BID for ID tree
    bid_t idtree_root;
    // dirty root node BID for sequence tree
    bid_t seqtree_root;
    // index for dirty blocks
    struct avl_tree dirty_blocks;
};

struct filemgr_dirty_update_block {
    // AVL-tree element
    struct avl_node avl;
    // contents of the block
    void *addr;
    // Block ID
    bid_t bid;
    // flag indicating if this block is immutable
    bool immutable;
};

class KvsStatOperations {
public:
    KvsStatOperations(FileMgr *_file)
        : file(_file) { }

    ~KvsStatOperations() { }

    void statSet(fdb_kvs_id_t kv_id, KvsStat stat);

    void statUpdateAttr(fdb_kvs_id_t kv_id, kvs_stat_attr_t attr,
                        int delta);

    static int statGetKvHeader(KvsHeader *kv_header,
                               fdb_kvs_id_t kv_id,
                               KvsStat *stat);

    int statGet(fdb_kvs_id_t kv_id, KvsStat *stat);

    uint64_t statGetSum(kvs_stat_attr_t attr);

    int opsStatGet(fdb_kvs_id_t kv_id, KvsOpsStat *stat);

    KvsOpsStat *getOpsStats(KvsInfo *info);

    static KvsOpsStat* migrateOpStats(FileMgr *old_file,
                                      FileMgr *new_file);

private:
    int opsStatGetKvHeader(KvsHeader *kv_header,
                           fdb_kvs_id_t kv_id,
                           KvsOpsStat *stat);

    FileMgr *file;
};

/**
 * A Context for managing I/O Tasks queued into the global shared thread pool
 */
class FdbTaskable : public Taskable {
public:
    FdbTaskable(FileMgr *file);

    /**
     * Simply returns the current filename of the forestdb file
     */
    const std::string& getName() const { return taskableName; }

    /**
     * Returns the opaque value of fopsHandle to uniquely identify a file
     */
    task_gid_t getGID() const;

    /**
     * Default set to LOW_BUCKET_PRIORITY
     */
    bucket_priority_t getWorkloadPriority() const {
        return LOW_BUCKET_PRIORITY;
    }

    /**
     * Default set to LOW_BUCKET_PRIORITY
     */
    void setWorkloadPriority(bucket_priority_t prio) { }

    /**
     * Default set to WRITE_HEAVY
     */
    WorkLoadPolicy& getWorkLoadPolicy(void) {
        return workLoadPolicy;
    }

    /**
     * TODO: Implement latency stats/histogram for Task scheduling wait times
     */
    void logQTime(type_id_t id, hrtime_t enqTime) { }

    /**
     * TODO: Implement latency stats/histogram for Task run times
     */
    void logRunTime(type_id_t id, hrtime_t runTime) { }
private:
   FileMgr *fileExPoolCtx;
   WorkLoadPolicy workLoadPolicy;
   const std::string taskableName;
};

class FileMgr {
public:
    FileMgr();

    ~FileMgr();

    /* Public member functions */

    const char* getFileName() const {
        return fileName;
    }

    uint16_t getFileNameLen() const {
        return fileNameLen;
    }

    void incrRefCount() {
        refCount++;
    }

    void decrRefCount() {
        refCount--;
    }

    size_t getRefCount();

    uint32_t getRefCount_UNLOCKED() const {
        return refCount.load();
    }

    void addToFlags(uint8_t flag) {
        fMgrFlags |= flag;
    }

    uint8_t getFlags() const {
        return fMgrFlags;
    }

    uint32_t getBlockSize() const {
        return blockSize;
    }

    fdb_fileops_handle getFopsHandle() {
        return fopsHandle;
    }

    void decrPos(uint64_t by) {
        lastPos.fetch_sub(by);
    }

    uint64_t getPos() const {
        return lastPos.load();
    }

    bid_t getNextAllocBlock() const {
        return lastPos.load() / blockSize;
    }

    void setLastCommit(uint64_t to) {
        lastCommit.store(to);
    }

    uint64_t getLastCommit() const {
        return lastCommit.load();
    }

    void setLastWritableBmpRevnum(uint64_t to) {
        lastWritableBmpRevnum.store(to);
    }

    uint64_t getLastWritableBmpRevnum() const {
        return lastWritableBmpRevnum.load();
    }

    void setIoInprog() {
        ioInprog++;
    }

    void clearIoInprog() {
        ioInprog--;
    }

    Wal* getWal() {
        return fMgrWal;
    }

    FdbTaskable *getTaskable() {
        return &exPoolCtx;
    }

    uint64_t updateHeader(void *buf, size_t len);

    FileMgrHeader* accessHeader() {
        return &fMgrHeader;
    }

    /**
     * Get the revision number of the current commit header
     */
    filemgr_header_revnum_t getHeaderRevnum();

    /**
     * Get the revision number of a given commit header
     *
     * @param bid Block ID of a commit header whose revision number is returned
     */
    filemgr_header_revnum_t getHeaderRevnum(bid_t bid);

    fdb_seqnum_t getSeqnum() const;

    void setSeqnum(fdb_seqnum_t seqnum);

    bid_t getHeaderBid() {
        return (fMgrHeader.size > 0) ? fMgrHeader.bid.load() : BLK_NOT_FOUND;
    }

    void* getHeader(void *buf, size_t *len,
                    bid_t *header_bid, fdb_seqnum_t *seqnum,
                    filemgr_header_revnum_t *header_revnum);

    /**
     * Get the current bitmap revision number of superblock.
     *
     * @param file Pointer to filemgr handle.
     * @return Current bitmap revision number.
     */
    uint64_t getSbBmpRevnum();

    /**
     * Get the bitmap revision number of superblock that corresponds to a given
     * commit header
     *
     * @param bid Block ID of a commit header whose bitmap revision number
     *        should be returned.
     */
    uint64_t getSbBmpRevnum(bid_t bid);

    fdb_status fetchHeader(uint64_t bid, void *buf, size_t *len,
                           fdb_seqnum_t *seqnum,
                           filemgr_header_revnum_t *header_revnum,
                           uint64_t *deltasize, uint64_t *version,
                           uint64_t *sb_bmp_revnum,
                           ErrLogCallback *log_callback);

    uint64_t fetchPrevHeader(uint64_t bid, void *buf, size_t *len,
                             fdb_seqnum_t *seqnum,
                             filemgr_header_revnum_t *revnum,
                             uint64_t *deltasize, uint64_t *version,
                             uint64_t *sb_bmp_revnum,
                             ErrLogCallback *log_callback);

    void setOps(struct filemgr_ops *to) {
        fMgrOps = to;
    }

    struct filemgr_ops* getOps() {
        return fMgrOps;
    }

    file_status_t getFileStatus() const {
        return fMgrStatus.load();
    }

    FileMgrConfig* getConfig() {
        return fileConfig;
    }

    const std::string& getOldFileName() {
        return oldFileName;
    }

    const std::string& getNewFileName() {
        return newFileName;
    }

    void setBCache(FileBlockCache *to) {
        bCache.store(to, std::memory_order_relaxed);
    }

    FileBlockCache* getBCache() {
        return bCache.load(std::memory_order_relaxed);
    }

    void setBnodeCache(FileBnodeCache* to) {
        bnodeCache.store(to, std::memory_order_relaxed);
    }

    FileBnodeCache* getBnodeCache() {
        return bnodeCache.load(std::memory_order_relaxed);
    }

    uint64_t getBCacheItems();

    uint64_t getBCacheVictims();

    uint64_t getBCacheImmutables();

    fdb_txn* getGlobalTxn() {
        return &globalTxn;
    }

    void setInPlaceCompaction(bool in_place_compaction);

    bool isInPlaceCompactionSet();

    bool setKVHeader(KvsHeader *kv_header,
                     void (*free_kv_header)(FileMgr *file));

    void setKVHeader_UNLOCKED(KvsHeader *to) {
        kvHeader = to;
    }

    KvsHeader* getKVHeader();

    KvsHeader* getKVHeader_UNLOCKED() {
        return kvHeader;
    }

    void setFreeKVHeaderCB(void (*free_kv_header)(FileMgr *file)) {
        this->free_kv_header = free_kv_header;
    }

    void setThrottlingDelay(uint64_t delay_us);

    uint32_t getThrottlingDelay() const;

    void setVersion(filemgr_magic_t to) {
        fMgrVersion = to;
    }

    filemgr_magic_t getVersion() const {
        return fMgrVersion;
    }

    void setSb(SuperblockBase *to) {
        fMgrSb = to;
    }

    SuperblockBase* getSb() {
        return fMgrSb;
    }

    KvsStatOperations* getKvsStatOps() {
        return &kvsStatOps;
    }

    void acquireSpinLock() {
        spin_lock(&fMgrLock);
    }

    void releaseSpinLock() {
        spin_unlock(&fMgrLock);
    }

    void mutexLock();

    bool mutexTrylock();

    void mutexUnlock();

    void setCrcMode(crc_mode_e to) {
        crcMode = to;
    }

    crc_mode_e getCrcMode() {
        return crcMode;
    }

    encryptor* getEncryption() {
        return &fMgrEncryption;
    }

    void setStaleData(StaleDataManagerBase *to) {
        staleData = to;
    }

    StaleDataManagerBase* getStaleData() {
        return staleData;
    }

    void removeAllBufferBlocks();

    bid_t alloc_FileMgr(ErrLogCallback *log_callback);

    void allocMultiple(int nblock, bid_t *begin,
                       bid_t *end, ErrLogCallback *log_callback);

    bid_t allocMultipleCond(bid_t nextbid, int nblock,
                            bid_t *begin, bid_t *end,
                            ErrLogCallback *log_callback);

    /* Returns true if the block invalidated is from recent uncommited blocks */
    bool invalidateBlock(bid_t bid);

    bool isFullyResident();

    /* Returns number of immutable blocks that remain in file */
    uint64_t flushImmutable(ErrLogCallback *log_callback);

    fdb_status read_FileMgr(bid_t bid, void *buf,
                            ErrLogCallback *log_callback,
                            bool read_on_cache_miss);

    fdb_status writeOffset(bid_t bid, uint64_t offset,
                           uint64_t len, void *buf, bool final_write,
                           ErrLogCallback *log_callback);

    fdb_status write_FileMgr(bid_t bid, void *buf,
                             ErrLogCallback *log_callback);

    /* Reads block of data from offset, calculated as bid * blocksize,
       decrypts if necessary */
    ssize_t readBlock(void *buf, bid_t bid);

    /* Writes block(s) of data at offset, calculated as start_bid * blocksize,
       encrypts if necessary */
    ssize_t writeBlocks(void *buf, unsigned num_blocks, bid_t start_bid);

    /* Reads block of data from specified offset,
       decrypts if necessary */
    ssize_t readBuf(void *buf, size_t nbytes, cs_off_t offset);

    /* Writes chunk of data at specified offset,
       encrypts if necessary */
    ssize_t writeBuf(void *buf, size_t nbytes, cs_off_t offset);

    int isWritable(bid_t bid);

    fdb_status commit_FileMgr(bool sync, ErrLogCallback *log_callback);

    /**
     * Commit DB file, and write a DB header at the given BID.
     *
     * @param bid ID of the block that DB header will be written. If this value
     *            is set to BLK_NOT_FOUND, then DB header is appended at the end
     *            of the file.
     * @param bmp_revnum Revision number of superblock's bitmap when this commit
     *                   is called.
     * @param sync Flag for calling fsync().
     * @param log_callback Pointer to log callback function.
     * @return FDB_RESULT_SUCCESS on success.
     */
    fdb_status commitBid(bid_t bid, uint64_t bmp_revnum, bool sync,
                         ErrLogCallback *log_callback);

    fdb_status sync_FileMgr(bool sync_option, ErrLogCallback *log_callback);

    /**
     * Updates the file status and oldFileName of the FileMgr instance,
     * with the arguments provided.
     *
     * Returns false if argument:old_filename is non-null but oldFileName
     * has already been set.
     */
    bool updateFileStatus(file_status_t status, const char *old_filename);

    bool isRollbackOn();

    void setRollback(uint8_t new_val);

    /**
     * Set the file manager's flag to cancel the compaction task that is
     * currently running.
     *
     * @param file Pointer to the file manager instance
     * @param cancel True if the compaction should be cancelled.
     */
    void setCancelCompaction(bool cancel);

    /**
     * Return true if a compaction cancellation is requested.
     *
     * @param file Pointer to the file manager instance
     * @return True if a compaction cancellation is requested.
     */
    bool isCompactionCancellationRequested();

    /**
     * Add an item into stale-block list of the given 'file'.
     *
     * @param offset Byte offset to the beginning of the stale region.
     * @param len Length of the stale region.
     * @return void.
     */
    void addStaleRegion(bid_t offset, size_t len);

    /**
     * Mark the given region (offset, length) as stale.
     * This function automatically calculates the additional space used for
     * block markers or block matadata, by internally calling
     * FileMgr::actualStaleRegions().
     *
     * @param offset Byte offset to the beginning of the data.
     * @param length Length of the data.
     * @return void.
     */
    void markDocStale(bid_t offset, size_t length);

    FileMgr* searchStaleLinks();

    /**
     * Add a FDB file handle into the superblock's global index.
     *
     * @param fhandle Pointer to FDB file handle.
     * @return True if successfully added.
     */
    bool fhandleAdd(void *fhandle);

    /**
     * Remove a FDB file handle from the superblock's global index.
     *
     * @param fhandle Pointer to FDB file handle.
     * @return True if successfully removed.
     */
    bool fhandleRemove(void *fhandle);

    static void setCompactionState(FileMgr *old_file,
                                   FileMgr *new_file,
                                   file_status_t status);

    static void removePending(FileMgr *old_file,
                              FileMgr *new_file,
                              ErrLogCallback *log_callback);

    static void init(FileMgrConfig *config);

    static void setLazyFileDeletion(bool enable,
                                    register_file_removal_func regis_func,
                                    check_file_removal_func check_func);

    /**
     * Assign superblock operations.
     *
     * @param ops Set of superblock operations to be assigned.
     * @return void.
     */
    static void setSbInitializer(superblock_init_cb func);

    static uint64_t getBcacheUsedSpace(void);

    /**
     * This is a helper function that does 'file open ops' on a file
     *
     * @param filename: name of the file
     * @param struct filemgr_ops: Pointer to ops to be performed on a file
     * @param fdb_fileops_handle: Handle to the file
     * @param flags: File open flags.
     * @param mode: File open mode
     * @return fdb_status: file close status converted to fdb_status
     */
    static fdb_status fileOpen(const char* filename, struct filemgr_ops *ops,
                               fdb_fileops_handle* fops_handle, int flags,
                               mode_t mode);

    static filemgr_open_result open(std::string filename,
                                    struct filemgr_ops *ops,
                                    FileMgrConfig *config,
                                    ErrLogCallback *log_callback);

    static void freeFunc(FileMgr *file);

    static fdb_status shutdown();

    /**
     * This is a helper function that does 'file close ops' on a file
     *
     *
     * @param struct filemgr_ops: Pointer to ops to be performed on a file
     * @param fdb_fileops_handle: Handle to the file
     * @return fdb_status: file close status converted to fdb_status
     */
    static fdb_status fileClose(struct filemgr_ops *ops,
                                fdb_fileops_handle fops_handle);

    static fdb_status close(FileMgr *file,
                            bool cleanup_cache_onclose,
                            const char *orig_file_name,
                            ErrLogCallback *log_callback);

    static void removeFile(FileMgr *file, ErrLogCallback *log_callback);

    static fdb_status destroyFile(std::string filename,
                                  FileMgrConfig *config,
                                  std::unordered_set<std::string> *destroy_set);

    static char* redirectOldFile(FileMgr *very_old_file,
                                 FileMgr *new_file,
                                 filemgr_redirect_hdr_func redirect_func);

    static fdb_status copyFileRange(FileMgr *src_file,
                                    FileMgr *dst_file,
                                    bid_t src_bid, bid_t dst_bid,
                                    bid_t clone_len);


    static void mutexOpenlock(FileMgrConfig *config);

    static void mutexOpenunlock(void);

    static bool isCommitHeader(void *head_buffer, size_t blocksize);

    static bool isCowSupported(FileMgr *src, FileMgr *dst);

    /**
     * Initialize global structures for dirty update management.
     *
     * @return void.
     */
    void dirtyUpdateInit();

    /**
     * Free global structures for dirty update management.
     *
     * @return void.
     */
    void dirtyUpdateFree();

    /**
     * Create a new dirty update entry.
     *
     * @return Newly created dirty update entry.
     */
    struct filemgr_dirty_update_node* dirtyUpdateNewNode();

    /**
     * Return the latest complete (i.e., immutable) dirty update entry.
     * Note that a dirty update that is being updated by a writer thread
     * will not be returned.
     *
     * @return Latest dirty update entry.
     */
    struct filemgr_dirty_update_node* dirtyUpdateGetLatest();

    /**
     * Increase the reference counter for the given dirty update entry.
     *
     * @param node Pointer to dirty update entry to increase reference counter.
     * @return void.
     */
    static void dirtyUpdateIncRefCount(struct filemgr_dirty_update_node *node);

    /**
     * Commit the latest complete dirty update entry and write back all updated
     * blocks into DB file. This API will remove all complete (i.e., immutable)
     * dirty update entries whose reference counter is zero.
     *
     * @param commit_node Pointer to dirty update entry to be flushed.
     * @param log_callback Pointer to the log callback function.
     * @return void.
     */
    void dirtyUpdateCommit(struct filemgr_dirty_update_node *commit_node,
                           ErrLogCallback *log_callback);

    /**
     * Complete the given dirty update entry and make it immutable. This API will
     * remove all complete (i.e., immutable) dirty update entries which are prior
     * than the given dirty update entry and whose reference counter is zero.
     *
     * @param node Pointer to dirty update entry to complete.
     * @param node Pointer to previous dirty update entry.
     * @return void.
     */
    void dirtyUpdateSetImmutable(struct filemgr_dirty_update_node *prev_node,
                                 struct filemgr_dirty_update_node *node);

    /**
     * Remove a dirty update entry and discard all dirty blocks from memory.
     *
     * @param node Pointer to dirty update entry to be removed.
     * @return void.
     */
    void dirtyUpdateRemoveNode(struct filemgr_dirty_update_node *node);

    /**
     * Close a dirty update entry. This API will remove all complete (i.e., immutable)
     * dirty update entries except for the last immutable update entry.
     *
     * @param node Pointer to dirty update entry to be closed.
     * @return void.
     */
    static void dirtyUpdateCloseNode(struct filemgr_dirty_update_node *node);

    /**
     * Set dirty root nodes for the given dirty update entry.
     *
     * @param node Pointer to dirty update entry.
     * @param dirty_idtree_root BID of ID tree root node.
     * @param dirty_seqtree_root BID of sequence tree root node.
     * @return void.
     */
    static void dirtyUpdateSetRoot(struct filemgr_dirty_update_node *node,
                                   bid_t dirty_idtree_root,
                                   bid_t dirty_seqtree_root) {
        if (node) {
            node->idtree_root = dirty_idtree_root;
            node->seqtree_root = dirty_seqtree_root;
        }
    }

    /**
     * Get dirty root nodes for the given dirty update entry.
     *
     * @param node Pointer to dirty update entry.
     * @param dirty_idtree_root Pointer to the BID of ID tree root node.
     * @param dirty_seqtree_root Pointer to the BID of sequence tree root node.
     * @return void.
     */
    static void dirtyUpdateGetRoot(struct filemgr_dirty_update_node *node,
                                   bid_t *dirty_idtree_root,
                                   bid_t *dirty_seqtree_root) {
        if (node) {
            *dirty_idtree_root = node->idtree_root;
            *dirty_seqtree_root = node->seqtree_root;
        } else {
            *dirty_idtree_root = *dirty_seqtree_root = BLK_NOT_FOUND;
        }
    }

    /**
     * Set dirty root nodes for B+tree V2.
     *
     * @param dirty_idtree_root BID of ID tree root node.
     * @param dirty_seqtree_root BID of sequence tree root node.
     * @return void.
     */
    void dirtyUpdateSetRootV2(bid_t dirty_idtree_root,
                              bid_t dirty_seqtree_root) {
        dirtyIdtreeRoot = dirty_idtree_root;
        dirtySeqtreeRoot = dirty_seqtree_root;
    }

    /**
     * Get dirty root nodes for B+tree V2.
     *
     * @param dirty_idtree_root BID of ID tree root node.
     * @param dirty_seqtree_root BID of sequence tree root node.
     * @return void.
     */
    void dirtyUpdateGetRootV2(bid_t& dirty_idtree_root,
                              bid_t& dirty_seqtree_root) {
        dirty_idtree_root = dirtyIdtreeRoot;
        dirty_seqtree_root = dirtySeqtreeRoot;
    }

    /**
     * Write a dirty block into the given dirty update entry.
     *
     * @param bid BID of the block to be written.
     * @param buf Pointer to the buffer containing the data to be written.
     * @param node Pointer to the dirty update entry.
     * @param log_callback Pointer to the log callback function.
     * @return FDB_RESULT_SUCCESS on success.
     */
    fdb_status writeDirty(bid_t bid,
                          void *buf,
                          struct filemgr_dirty_update_node *node,
                          ErrLogCallback *log_callback);

    /**
     * Read a block through the given dirty update entries. It first tries to read
     * the block from the writer's (which is being updated) dirty update entry,
     * and then tries to read it from the reader's (which already became immutable)
     * dirty update entry. If the block doesn't exist in both entries, then it reads
     * the block from DB file.
     *
     * @param bid BID of the block to be read.
     * @param buf Pointer to the buffer where the read data will be copied.
     * @param node_reader Pointer to the immutable dirty update entry.
     * @param node_writer Pointer to the mutable dirty update entry.
     * @param log_callback Pointer to the log callback function.
     * @param read_on_cache_miss True if we want to read the block from file after
     *        cache miss.
     * @return FDB_RESULT_SUCCESS on success.
     */
    fdb_status readDirty(bid_t bid,
                         void *buf,
                         struct filemgr_dirty_update_node *node_reader,
                         struct filemgr_dirty_update_node *node_writer,
                         ErrLogCallback *log_callback,
                         bool read_on_cache_miss);

    /**
     * Return name of the latency stat given its type.
     * @param stat The type of the latency stat to be named.
     */
    static const char* getLatencyStatName(fdb_latency_stat_type stat);

    struct avl_tree* getHandleIdx() {
        return &handleIdx;
    }

    void acquireHandleIdxLock() {
        spin_lock(&handleIdxLock);
    }

    void releaseHandleIdxLock() {
        spin_unlock(&handleIdxLock);
    }

    void incrBlockCacheHits() {
        ++bcacheHits;
    }

    size_t fetchBlockCacheHits() {
        return bcacheHits.load();
    }

    void incrBlockCacheMisses() {
        ++bcacheMisses;
    }

    size_t fetchBlockCacheMisses() {
        return bcacheMisses.load();
    }

    // variables related to prefetching
    std::atomic<uint8_t> prefetchStatus;
    thread_t prefetchTid;

#ifdef _LATENCY_STATS
    struct latency_stat latStats[FDB_LATENCY_NUM_STATS];
#ifdef _PLATFORM_LIB_AVAILABLE
    Histogram<hrtime_t> histStats[FDB_LATENCY_NUM_STATS];
#endif // _PLATFORM_LIB_AVAILABLE
#endif //_LATENCY_STATS

private:

    /**
     * Remove a given dirty node from the dirty block tree
     */
    void removeDirtyNode(struct filemgr_dirty_update_node *node);

    /**
     * Flush all the dirty blocks that belong to a given node in the dirty
     * index tree
     *
     * @param node Pointer to a given node in the dirty index tree
     * @param log_callback Pointer to the log callback function
     */
    void flushDirtyNode(struct filemgr_dirty_update_node *node,
                        ErrLogCallback *log_callback);

    /**
     * Read the latest header block
     *
     * @param log_callback Pointer to the error log callback
     * @return FDB_RESULT_SUCCESS upon successful read
     */
    fdb_status readHeader(ErrLogCallback *log_callback);

    /**
     * Load the superblock
     *
     * @param log_callback Pointer to the error log callback
     * @return FDB_RESULT_SUCCESS upon successful read
     */
    fdb_status loadSuperBlock(ErrLogCallback *log_callback);

    /**
     * Free the file handle index
     */
    void freeFileHandleIdx();

    /**
     * Spawn a thread to prefetch index blocks from the file
     */
    void prefetch(ErrLogCallback *log_callback);

    /**
     * CRC32 check for a given buffer
     *
     * @param buf Pointer to the buffer on which CRC32 check is performed
     * @return FDB_RESULT_SUCCESS on successful CRC32 verification
     */
    fdb_status checkCRC32(void *buf);

    /**
     * Get the I/O buffer available from the buffer pool
     */
    static void* getTempBuf();

    /**
     * Release a given I/O buffer to the buffer pool
     *
     * @param buf Pointer to the I/O buffer to be released to the pool.
     */
    static void releaseTempBuf(void *buf);

    /**
     * Destroy the I/O buffer pool
     */
    static void shutdownTempBuf();

    /**
     * Check if a given file exists or not
     *
     * @param filename File name whose existence is checked
     * @return FDB_RESULT_SUCCESS if a given file exists
     */
    static fdb_status doesFileExist(const char *filename);

    char fileName[FDB_MAX_FILENAME_LEN]; // Current file name
    uint16_t fileNameLen;
    std::atomic<uint32_t> refCount;
    uint8_t fMgrFlags;
    uint32_t blockSize;
    fdb_fileops_handle fopsHandle;    // FileOps Handle
    std::atomic<uint64_t> lastPos;
    std::atomic<uint64_t> lastCommit;
    std::atomic<uint64_t> lastWritableBmpRevnum;
    std::atomic<uint8_t> ioInprog;
    Wal *fMgrWal;
    FdbTaskable exPoolCtx; // executor pool context
    FileMgrHeader fMgrHeader;
    struct filemgr_ops *fMgrOps;
    std::atomic<uint8_t> fMgrStatus;
    FileMgrConfig *fileConfig;
    std::string oldFileName;          // Old file name before compaction
    std::string newFileName;          // Latest filename after compaction
    std::atomic<FileBlockCache *> bCache;
    std::atomic<FileBnodeCache *> bnodeCache;
    fdb_txn globalTxn;
    bool inPlaceCompaction;
    filemgr_fs_type_t fsType;
    KvsHeader *kvHeader;
    void (*free_kv_header)(FileMgr *file); // callback function
    std::atomic<uint32_t> throttlingDelay;

    // File format version
    filemgr_magic_t fMgrVersion;

    // superblock
    SuperblockBase *fMgrSb;

    KvsStatOperations kvsStatOps;

    // spin lock for small region
    spin_t fMgrLock;

    // lock for data consistency
#ifdef __FILEMGR_DATA_PARTIAL_LOCK
    struct plock fMgrPlock;
#elif defined(__FILEMGR_DATA_MUTEX_LOCK)
    mutex_t dataMutex[DLOCK_MAX];
#else
    spin_t dataSpinlock[DLOCK_MAX];
#endif //__FILEMGR_DATA_PARTIAL_LOCK

    // mutex for synchronization among multiple writers
    mutex_lock_t writerLock;

    // CRC the file is using
    crc_mode_e crcMode;

    // Encryption type
    encryptor fMgrEncryption;

    StaleDataManagerBase *staleData;

    // in-memory index for a set of dirty index block updates
    struct avl_tree dirtyUpdateIdx;
    // counter for the set of dirty index updates
    std::atomic<uint64_t> dirtyUpdateCounter;
    // latest dirty (immutable but not committed yet) update
    struct filemgr_dirty_update_node *latestDirtyUpdate;
    // spin lock for dirty_update_idx
    spin_t dirtyUpdateLock;

    // In Btree V2, only root node info is necessary
    // instead of above dirtyUpdateXXX.
    std::atomic<uint64_t> dirtyIdtreeRoot;
    std::atomic<uint64_t> dirtySeqtreeRoot;

    // Index for fdb_file_handle belonging to the same filemgr handle
    struct avl_tree handleIdx;
    // Spin lock for file handle index
    spin_t handleIdxLock;

    // Global Atomic variable to track if filemgr's config has been initialized
    static std::atomic<bool> fileMgrInitialized;
    // Global mutex to synchronize the initialization of filemgr's configs
    static std::mutex initMutex;
    // Global static spin lock used by open() and close() methods
    static spin_t fileMgrOpenlock;
    // Temporal I/O buffer pool
    static struct list tempBuf;
    // Lock to synchronize I/O buffer pool accesses
    static spin_t tempBufLock;
    // Flag indicating if the lazy file deletion is enabled or not
    static bool lazyFileDeletionEnabled;
    // Pointer to the file removal registration function
    static register_file_removal_func registerFileRemoval;
    // Pointer to the file removal check function
    static check_file_removal_func isFileRemoved;
    // Pointer to the superblock init function
    static superblock_init_cb sbInitializer;

    // Block cache hit count for read ops
    std::atomic<size_t> bcacheHits;
    // Block cache miss count for read ops
    std::atomic<size_t> bcacheMisses;
};

/**
 * The node structure of fhandle index.
 */
struct filemgr_fhandle_idx_node {
    /**
     * Void pointer to file handle.
     */
    void *fhandle;
    /**
     * AVL tree element.
     */
    struct avl_node avl;
};

/**
 * Convert a given errno value to the corresponding fdb_status value.
 *
 * @param errno_value errno value
 * @param default_status Default fdb_status value to be returned if
 *        there is no corresponding fdb_status value for a given errno value.
 * @return fdb_status value that corresponds to a given errno value
 */
fdb_status convert_errno_to_fdb_status(int errno_value,
                                       fdb_status default_status);

#ifdef _LATENCY_STATS
class LatencyStats {
public:
    /**
     * Initialize a latency stats instance
     *
     * @param val Pointer to a latency stats instance to be initialized
     */
    static void init(struct latency_stat *val);

    /**
     * Destroy a latency stats instance
     *
     * @param val Pointer to a latency stats instance to be destroyed
     */
    static void destroy(struct latency_stat *val);

    /**
     * Migrate the latency stats from the source file to the destination file
     *
     * @param oldf Pointer to the source file manager
     * @param newf Pointer to the destination file manager
     */
    static void migrate(FileMgr *src, FileMgr *dest);

    /**
     * Update the latency stats for a given file manager
     *
     * @param file Pointer to the file manager whose latency stats
     *             needs to be updated
     * @param type Type of a latency stat to be updated
     * @param val New value of a latency stat
     */
    static void update(FileMgr *file, fdb_latency_stat_type type,
                       uint64_t val);

    /**
     * Get the latency stats from a given file manager
     *
     * @param file Pointer to the file manager
     * @param type Type of a latency stat to be retrieved
     * @param stat Pointer to the stats instance to be populated
     */
    static void get(FileMgr *file, fdb_latency_stat_type type,
                    fdb_latency_stat *stat);

#ifdef _PLATFORM_LIB_AVAILABLE
    /**
     * Get the histogram of latencies from a given file manager
     *
     * @param file Pointer to the file manager
     * @param type Type of a latency stat to be retrieved
     * @param stat Pointer to the histogram of latencies
     * @param stat_length Pointer to the length of the buffer pointer to by
     *                    the stat pointer
     */
    static void getHistogram(FileMgr *file, fdb_latency_stat_type type,
                             char **stat, size_t *stat_length);
#endif // _PLATFORM_LIB_AVAILABLE

#ifdef _LATENCY_STATS_DUMP_TO_FILE
    /**
     * Write all the latency stats for a given file manager to a stat log file
     *
     * @param file Pointer to the file manager
     * @param log_callback Pointer to the log callback function
     */
    static void dump(FileMgr *file, ErrLogCallback *log_callback);
#endif // _LATENCY_STATS_DUMP_TO_FILE

};
#endif // _LATENCY_STATS
