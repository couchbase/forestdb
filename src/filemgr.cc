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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <stdarg.h>
#if !defined(WIN32) && !defined(_WIN32)
#include <sys/time.h>
#endif

#include <sstream>

#include "filemgr.h"
#include "filemgr_ops.h"
#include "hash_functions.h"
#include "blockcache.h"
#include "bnodecache.h"
#include "wal.h"
#include "list.h"
#include "fdb_internal.h"
#include "time_utils.h"
#include "executorpool.h"
#include "version.h"

#include "memleak.h"

#ifdef __DEBUG
#ifndef __DEBUG_FILEMGR
    #undef DBG
    #undef DBGCMD
    #undef DBGSW
    #define DBG(...)
    #define DBGCMD(...)
    #define DBGSW(n, ...)
#endif
#endif

// NBUCKET must be power of 2
#define NBUCKET (1024)

static FileMgrConfig global_config;

std::atomic<bool> FileMgr::fileMgrInitialized(false);
std::mutex FileMgr::initMutex;
spin_t FileMgr::fileMgrOpenlock;

struct list FileMgr::tempBuf;
spin_t FileMgr::tempBufLock;
bool FileMgr::lazyFileDeletionEnabled(false);
register_file_removal_func FileMgr::registerFileRemoval(nullptr);
check_file_removal_func FileMgr::isFileRemoved(nullptr);
superblock_init_cb FileMgr::sbInitializer(nullptr);

std::mutex FileMgrMap::initGuard;
std::atomic<FileMgrMap *> FileMgrMap::instance(nullptr);

static const int MAX_STAT_UPDATE_RETRIES = 5;

struct temp_buf_item {
    void *addr;
    struct list_elem le;
};

static void spin_init_wrap(void *lock) {
    spin_init((spin_t*)lock);
}

static void spin_destroy_wrap(void *lock) {
    spin_destroy((spin_t*)lock);
}

static void spin_lock_wrap(void *lock) {
    spin_lock((spin_t*)lock);
}

static void spin_unlock_wrap(void *lock) {
    spin_unlock((spin_t*)lock);
}

static void mutex_init_wrap(void *lock) {
    mutex_init((mutex_t*)lock);
}

static void mutex_destroy_wrap(void *lock) {
    mutex_destroy((mutex_t*)lock);
}

static void mutex_lock_wrap(void *lock) {
    mutex_lock((mutex_t*)lock);
}

static void mutex_unlock_wrap(void *lock) {
    mutex_unlock((mutex_t*)lock);
}

static int _kvs_stat_cmp(struct avl_node *a, struct avl_node *b, void *aux)
{
    struct kvs_node *aa, *bb;
    aa = _get_entry(a, struct kvs_node, avl_id);
    bb = _get_entry(b, struct kvs_node, avl_id);

    if (aa->id < bb->id) {
        return -1;
    } else if (aa->id > bb->id) {
        return 1;
    } else {
        return 0;
    }
}

static int _block_is_overlapped(void *pbid1, void *pis_writer1,
                                void *pbid2, void *pis_writer2,
                                void *aux)
{
    (void)aux;
    bid_t bid1, is_writer1, bid2, is_writer2;
    bid1 = *(bid_t*)pbid1;
    is_writer1 = *(bid_t*)pis_writer1;
    bid2 = *(bid_t*)pbid2;
    is_writer2 = *(bid_t*)pis_writer2;

    if (bid1 != bid2) {
        // not overlapped
        return 0;
    } else {
        // overlapped
        if (!is_writer1 && !is_writer2) {
            // both are readers
            return 0;
        } else {
            return 1;
        }
    }
}

fdb_status fdb_log(ErrLogCallback *log_callback,
                   fdb_status status,
                   const char *format, ...)
{
    char msg[4096];
    va_list args;
    va_start(args, format);
    vsprintf(msg, format, args);
    va_end(args);

    fdb_log_callback callback;
    if (log_callback && (callback = log_callback->getCallback())) {
        callback(status, msg, log_callback->getCtxData());
    } else {
        if (status != FDB_RESULT_SUCCESS) {
            fprintf(stderr, "[FDB ERR: %d] %s\n", status, msg);
        } else {
            fprintf(stderr, "[FDB INFO] %s\n", msg);
        }
    }
    return status;
}

static void _log_errno_str(fdb_fileops_handle fops_handle,
                           struct filemgr_ops *ops,
                           ErrLogCallback *log_callback,
                           fdb_status io_error,
                           const char *what,
                           const char *filename)
{
    if (io_error < 0) {
        char errno_msg[512];
        ops->get_errno_str(fops_handle, errno_msg, 512);
        fdb_log(log_callback, io_error,
                "Error in %s on a database file '%s', %s", what, filename, errno_msg);
    }
}

FileMgrMap* FileMgrMap::get(void) {
    auto *tmp = instance.load();
    if (tmp == nullptr) {
        LockHolder lock(initGuard);
        tmp = instance.load();
        if (tmp == nullptr) {
            // Second check under lock - to ensure that an instance is not
            // create twice by two threads if it were null.
            tmp = new FileMgrMap();
            instance.store(tmp);
        }
    }
    return tmp;
}

void FileMgrMap::shutdown(void) {
    LockHolder lock(initGuard);
    auto *tmp = instance.load();
    if (tmp != nullptr) {
        delete tmp;
        instance = nullptr;
    }
}

FileMgrMap::FileMgrMap() {
    spin_init(&fileMapLock);
}

FileMgrMap::~FileMgrMap() {
    spin_destroy(&fileMapLock);
}

void FileMgrMap::addEntry(const std::string filename, FileMgr *file) {
    spin_lock(&fileMapLock);
    fileMap[filename] = file;
    spin_unlock(&fileMapLock);
}

void FileMgrMap::removeEntry(const std::string filename) {
    spin_lock(&fileMapLock);
    fileMap.erase(filename);
    spin_unlock(&fileMapLock);
}

FileMgr* FileMgrMap::fetchEntry(const std::string filename) {
    if (filename.empty()) {
        return nullptr;
    }

    FileMgr *file;
    spin_lock(&fileMapLock);
    auto it = fileMap.find(filename);
    if (it == fileMap.end()) {
        file = nullptr;
    } else {
        file = it->second;
    }
    spin_unlock(&fileMapLock);
    return file;
}

void* FileMgrMap::scan(filemgr_factory_scan_cb *scan_callback,
                       void *ctx) {
    // Make a copy of the unordered map within lock, this is done
    // so that the callback can be invoked outside fileMapLock's
    // context to avoid any potential lock inversions.
    spin_lock(&fileMapLock);
    std::unordered_map<std::string, FileMgr*> fileMapCopy = fileMap;
    spin_unlock(&fileMapLock);

    for (auto &it : fileMapCopy) {
        void *ret = scan_callback(it.second/*FileMgr* */,
                                  ctx);
        if (ret) {
            return ret;
        }
    }
    return nullptr;
}

void FileMgrMap::freeEntries(filemgr_factory_free_cb free_callback) {
    spin_lock(&fileMapLock);

    for (auto &it : fileMap) {
        free_callback(it.second/*FileMgr* */);
    }
    spin_unlock(&fileMapLock);
}

FileMgr::FileMgr()
    : refCount(1), fMgrFlags(0x00), blockSize(global_config.getBlockSize()),
      fopsHandle(nullptr), lastPos(0), lastCommit(0), lastWritableBmpRevnum(0),
      ioInprog(0), fMgrWal(nullptr), exPoolCtx(this), fMgrOps(nullptr),
      fMgrStatus(FILE_NORMAL), fileConfig(nullptr), bCache(nullptr),
      bnodeCache(nullptr), inPlaceCompaction(false),
      fsType(0), kvHeader(nullptr), throttlingDelay(0), fMgrVersion(0),
      fMgrSb(nullptr), kvsStatOps(this), crcMode(CRC_DEFAULT),
      staleData(nullptr), latestDirtyUpdate(nullptr),
      bcacheHits(0), bcacheMisses(0)
{

    fMgrHeader.bid = 0;
    fMgrHeader.op_stat.reset();

    memset(&globalTxn, 0, sizeof(fdb_txn));

    prefetchStatus = FILEMGR_PREFETCH_IDLE;
    prefetchTid = 0;

#ifdef _LATENCY_STATS
    for (int i = 0; i < FDB_LATENCY_NUM_STATS; ++i) {
        LatencyStats::init(&latStats[i]);
    }
#endif // _LATENCY_STATS

    spin_init(&fMgrLock);

#ifdef __FILEMGR_DATA_PARTIAL_LOCK
    struct plock_ops pops;
    struct plock_config pconfig;

    pops.init_user = mutex_init_wrap;
    pops.lock_user = mutex_lock_wrap;
    pops.unlock_user = mutex_unlock_wrap;
    pops.destroy_user = mutex_destroy_wrap;
    pops.init_internal = spin_init_wrap;
    pops.lock_internal = spin_lock_wrap;
    pops.unlock_internal = spin_unlock_wrap;
    pops.destroy_internal = spin_destroy_wrap;
    pops.is_overlapped = _block_is_overlapped;

    memset(&pconfig, 0x0, sizeof(pconfig));
    pconfig.ops = &pops;
    pconfig.sizeof_lock_internal = sizeof(spin_t);
    pconfig.sizeof_lock_user = sizeof(mutex_t);
    pconfig.sizeof_range = sizeof(bid_t);
    pconfig.aux = NULL;
    plock_init(&fMgrPlock, &pconfig);
#elif defined(__FILEMGR_DATA_MUTEX_LOCK)
    int i;
    for (i = 0; i < DLOCK_MAX; ++i) {
        mutex_init(&dataMutex[i]);
    }
#else
    int i;
    for (i = 0; i < DLOCK_MAX; ++i) {
        spin_init(&dataSpinlock[i]);
    }
#endif //__FILEMGR_DATA_PARTIAL_LOCK

    mutex_init(&writerLock.mutex);
    writerLock.locked = false;

    memset(&fMgrEncryption, 0, sizeof(encryptor));

    dirtyUpdateInit();
    dirtyIdtreeRoot = dirtySeqtreeRoot = BLK_NOT_FOUND;

    avl_init(&handleIdx, nullptr);
    spin_init(&handleIdxLock);
}

FileMgr::~FileMgr()
{
#ifdef _LATENCY_STATS
    for (int x = 0; x < FDB_LATENCY_NUM_STATS; ++x) {
        LatencyStats::destroy(&latStats[x]);
    }
#endif // _LATENCY_STATS

    spin_destroy(&fMgrLock);

#ifdef __FILEMGR_DATA_PARTIAL_LOCK
    plock_destroy(&fMgrPlock);
#elif defined(__FILEMGR_DATA_MUTEX_LOCK)
    int i;
    for (i = 0; i < DLOCK_MAX; ++i) {
        mutex_destroy(&dataMutex[i]);
    }
#else
    int i;
    for (i = 0; i < DLOCK_MAX; ++i) {
        spin_destroy(&dataSpinlock[i]);
    }
#endif //__FILEMGR_DATA_PARTIAL_LOCK

    mutex_destroy(&writerLock.mutex);

    dirtyUpdateFree();

    freeFileHandleIdx();
    spin_destroy(&handleIdxLock);
 }

void FileMgr::init(FileMgrConfig *config)
{
    // global initialization
    // initialized only once at first time
    if (!fileMgrInitialized) {
        LockHolder lock(FileMgr::initMutex);
        if (!fileMgrInitialized) {
            global_config = *config;

            // Initialize buffer cache.
            // Block-aligned or non-block-aligned based on the latest file
            // version supported.
            if (global_config.getNcacheBlock() > 0) {
                if (ver_btreev2_format(ver_get_latest_magic())) {
                    BnodeCacheMgr::init(static_cast<uint64_t>(
                                            global_config.getNcacheBlock()) *
                                        global_config.getBlockSize(),
                                        global_config.getFlushLimit());
                } else {
                    BlockCacheManager::init(global_config.getNcacheBlock(),
                                            global_config.getBlockSize());
                }
            }

            // initialize temp buffer
            list_init(&tempBuf);
            spin_init(&tempBufLock);

            // initialize global lock
            spin_init(&fileMgrOpenlock);

            // set the initialize flag
            fileMgrInitialized.store(true);
        }
    }
}

void FileMgr::setLazyFileDeletion(bool enable,
                                  register_file_removal_func regis_func,
                                  check_file_removal_func check_func)
{
    lazyFileDeletionEnabled = enable;
    registerFileRemoval = regis_func;
    isFileRemoved = check_func;
}

void FileMgr::setSbInitializer(superblock_init_cb func)
{
    sbInitializer = func;
}

void * FileMgr::getTempBuf()
{
    struct list_elem *e;
    struct temp_buf_item *item;

    spin_lock(&tempBufLock);
    e = list_pop_front(&tempBuf);
    if (e) {
        item = _get_entry(e, struct temp_buf_item, le);
    } else {
        void *addr = NULL;

        malloc_align(addr, FDB_SECTOR_SIZE,
                global_config.getBlockSize() + sizeof(struct temp_buf_item));

        item = (struct temp_buf_item *)((uint8_t *) addr +
                                        global_config.getBlockSize());
        item->addr = addr;
    }
    spin_unlock(&tempBufLock);

    return item->addr;
}

void FileMgr::releaseTempBuf(void *buf)
{
    struct temp_buf_item *item;

    spin_lock(&tempBufLock);
    item = (struct temp_buf_item*)((uint8_t *)buf +
                                   global_config.getBlockSize());
    list_push_front(&tempBuf, &item->le);
    spin_unlock(&tempBufLock);
}

void FileMgr::shutdownTempBuf()
{
    struct list_elem *e;
    struct temp_buf_item *item;
    size_t count=0;

    spin_lock(&tempBufLock);
    e = list_begin(&tempBuf);
    while(e){
        item = _get_entry(e, struct temp_buf_item, le);
        e = list_remove(&tempBuf, e);
        free_align(item->addr);
        count++;
    }
    spin_unlock(&tempBufLock);
}

// Read a block from the file, decrypting if necessary.
ssize_t FileMgr::readBlock(void *buf, bid_t bid) {
    return readBuf(buf, blockSize, blockSize * bid);
}

// Write consecutive block(s) to the file, encrypting if necessary.
ssize_t FileMgr::writeBlocks(void *buf, unsigned num_blocks,
                             bid_t start_bid) {
    return writeBuf(buf,
                    num_blocks * blockSize,
                    start_bid * blockSize);
}

// Read buf from file, decrypting if necessary.
ssize_t FileMgr::readBuf(void* buf, size_t nbytes, cs_off_t offset) {
    if (nbytes > blockSize) {
        // This API will issue a pread for a buffer that is less than
        // or equal to the specified blocksize.
        fdb_log(nullptr, FDB_RESULT_READ_FAIL,
                "FileMgr::readBuf: Exceeded the max allowed buffer size: "
                "%s > %s!",
                std::to_string(nbytes).c_str(),
                std::to_string(blockSize).c_str());
        return FDB_RESULT_READ_FAIL;
    }
    if (fMgrEncryption.ops == nullptr) {
        return fMgrOps->pread(fopsHandle, buf, nbytes, offset);
    } else {    // Decryption (at a block level)
        void* new_buf;
        size_t new_nbytes;
        cs_off_t new_offset;
        size_t offset_in_block = offset % blockSize;
        if (offset_in_block) {
            /**
             * Offset falls within a block.
             */
            new_offset = offset - offset_in_block;
            new_buf = malloc(blockSize);
            new_nbytes = blockSize;
        } else {
            /**
             * Offset falls at the start of a block.
             */
            new_offset = offset;
            new_buf = buf;
            new_nbytes = nbytes;
        }

        ssize_t result = fMgrOps->pread(fopsHandle, new_buf,
                                        new_nbytes, new_offset);

        if (result != (ssize_t)new_nbytes) {
            if (new_offset != offset) {
                free(new_buf);
            }
            fdb_log(nullptr, FDB_RESULT_READ_FAIL,
                    "FileMgr::readBuf: pread failed with result: %s",
                    std::to_string(result).c_str());
            return result;
        }
        fdb_status status = fdb_decrypt_block(&fMgrEncryption,
                                              new_buf,
                                              result,
                                              new_offset / blockSize);
        if (status != FDB_RESULT_SUCCESS) {
            if (new_offset != offset) {
                free(new_buf);
            }
            fdb_log(nullptr, status,
                    "FileMgr::readBuf: fdb_decrypt_block failed!");
            return status;
        }

        if (offset_in_block) {
            memcpy(buf, (uint8_t*)new_buf + offset_in_block, nbytes);
            if (new_offset != offset) {
                free(new_buf);
            }
        }

        return result;
    }
}

// Write buf to file, encrypting if necessary.
ssize_t FileMgr::writeBuf(void* buf, size_t nbytes, cs_off_t offset) {
    if (fMgrEncryption.ops == nullptr) {
        return fMgrOps->pwrite(fopsHandle, buf, nbytes, offset);
    } else {    // Encryption (at a block level)
        void* new_buf;
        size_t new_nbytes;
        cs_off_t new_offset;
        size_t offset_in_block = offset % blockSize;
        if (offset_in_block) {
            /**
             * Offset falls within a block.
             *
             * In this case, we will need to issue a pread on that block's
             * starting offset, decrypt the block and append buf and then
             * encrypt the new buf at a block level and pwrite, as
             * encryption happens at a block level.
             */

            new_offset = offset - offset_in_block;
            new_nbytes = nbytes + offset_in_block;
            new_buf = malloc(new_nbytes);

            ssize_t result = readBuf(new_buf, offset_in_block, new_offset);
            if (result != static_cast<ssize_t>(offset_in_block)) {
                free(new_buf);
                return result;
            }

            memcpy((uint8_t*)new_buf + offset_in_block, buf, nbytes);

        } else {
            /**
             * Offset falls at the start of a block.
             */
            new_buf = buf;
            new_nbytes = nbytes;
            new_offset = offset;
        }

        uint8_t* encrypted_buf;
        if (new_nbytes > FDB_BLOCKSIZE) {
            encrypted_buf = (uint8_t*) malloc(new_nbytes);
        } else {
            encrypted_buf = alca(uint8_t, new_nbytes);
        }

        if (!encrypted_buf) {
            return FDB_RESULT_ALLOC_FAIL;
        }

        fdb_status status = fdb_encrypt_blocks(&fMgrEncryption,
                                               encrypted_buf,
                                               new_buf,
                                               blockSize,
                                               ((new_nbytes - 1)/blockSize) + 1,
                                               new_offset / blockSize);

        if (offset_in_block) {
            free(new_buf);
        }

        if (new_nbytes > FDB_BLOCKSIZE) {
            free(encrypted_buf);
        }

        if (status != FDB_RESULT_SUCCESS) {
            return status;
        }

        return fMgrOps->pwrite(fopsHandle, encrypted_buf, nbytes, offset);
    }
}

int FileMgr::isWritable(bid_t bid) {
    if (fMgrSb && fMgrSb->bmpExists()) {
        // block reusing is enabled
        return fMgrSb->isWritable(bid);
    } else {
        uint64_t pos = bid * blockSize;
        // Note that we don't need to grab fMgrLock here because
        // 1) both lastPos and lastCommit are only incremented.
        // 2) file->lastCommit is updated using the value of lastPos,
        //    and always equal to or smaller than lastPos.
        return (pos <  lastPos.load() &&
                pos >= lastCommit.load());
    }
}

uint64_t FileMgr::getSbBmpRevnum() {
    if (fMgrSb) {
        return fMgrSb->getBmpRevnum();
    } else {
        return 0;
    }
}

uint64_t FileMgr::getSbBmpRevnum(bid_t bid) {
    uint8_t *buf = alca(uint8_t, getBlockSize());
    uint64_t version, bmp_revnum = 0;
    size_t header_len;
    fdb_seqnum_t seqnum;
    filemgr_header_revnum_t revnum;
    fdb_status fs;

    fs = fetchHeader(bid, buf, &header_len,
                     &seqnum, &revnum, NULL, &version, &bmp_revnum,
                     NULL);
    if (fs != FDB_RESULT_SUCCESS) {
        return 0;
    }
    return bmp_revnum;
}

fdb_status FileMgr::readHeader(ErrLogCallback *log_callback)
{
    uint8_t marker[BLK_MARKER_SIZE];
    filemgr_magic_t magic = ver_get_latest_magic();
    filemgr_header_len_t len;
    uint8_t *buf;
    uint32_t crc, crc_file;
    bool check_crc32_open_rule = false;
    fdb_status status = FDB_RESULT_SUCCESS;
    bid_t hdr_bid, hdr_bid_local;
    size_t min_filesize = 0;

    // get temp buffer
    buf = (uint8_t *) FileMgr::getTempBuf();

    // If a header is found crc_mode can change to reflect the file
    if (getCrcMode() == CRC32) {
        check_crc32_open_rule = true;
    }

    hdr_bid = (getPos() / getBlockSize()) - 1;
    hdr_bid_local = hdr_bid;

    if (getSb()) {
        // superblock exists .. file size does not start from zero.
        min_filesize = getSb()->getConfig().num_sb * getBlockSize();
        bid_t sb_last_hdr_bid = getSb()->getLastHdrBid();
        if (sb_last_hdr_bid != BLK_NOT_FOUND) {
            hdr_bid = hdr_bid_local = sb_last_hdr_bid;
        }
        // if header info does not exist in superblock,
        // get DB header at the end of the file.
    }

    if (getPos() > min_filesize) {
        // Crash Recovery Test 1: unaligned last block write
        uint64_t remain = getPos() % getBlockSize();
        if (remain) {
            decrPos(remain);
            setLastCommit(getPos());
            const char *msg = "Crash Detected: %" _F64 " non-block aligned "
                "bytes discarded from a database file '%s'\n";
            DBG(msg, remain, getFileName());
            // TODO: Need to add a better error code
            fdb_log(log_callback, FDB_RESULT_READ_FAIL,
                    msg, remain, getFileName());
        }

        size_t block_counter = 0;
        do {
            if (hdr_bid_local * getBlockSize() >= getPos()) {
                // Handling EOF scenario
                status = FDB_RESULT_NO_DB_HEADERS;
                const char *msg = "Unable to read block from file '%s' as EOF "
                    "reached\n";
                fdb_log(log_callback, status, msg, getFileName());
                break;
            }
            ssize_t rv = readBlock(buf, hdr_bid_local);
            if (rv != (ssize_t) getBlockSize()) {
                status = (fdb_status)rv;
                const char *msg = "Unable to read a database file '%s' with "
                    "blocksize %u\n";
                DBG(msg, getFileName(), getBlockSize());
                fdb_log(log_callback, status, msg, getFileName(),
                        getBlockSize());
                break;
            }
            ++block_counter;
            memcpy(marker, buf + getBlockSize() - BLK_MARKER_SIZE,
                   BLK_MARKER_SIZE);

            if (marker[0] == BLK_MARKER_DBHEADER) {
                // possible need for byte conversions here
                memcpy(&magic,
                       buf + getBlockSize() - BLK_MARKER_SIZE - sizeof(magic),
                       sizeof(magic));
                magic = _endian_decode(magic);

                if (ver_is_valid_magic(magic)) {
                    memcpy(&len,
                           buf + getBlockSize() - BLK_MARKER_SIZE -
                           sizeof(magic) - sizeof(len),
                           sizeof(len));
                    len = _endian_decode(len);

                    memcpy(&crc_file, buf + len - sizeof(crc), sizeof(crc));
                    crc_file = _endian_decode(crc_file);

                    // crc check and detect the crc_mode
                    crc_mode_e crc_mode = getCrcMode();
                    bool ret = detect_and_check_crc(reinterpret_cast<const uint8_t*>(buf),
                                                    len - sizeof(crc),
                                                    crc_file,
                                                    &crc_mode);
                    setCrcMode(crc_mode);
                    if (ret) {
                        // crc mode is detected and known.
                        // check the rules of opening legacy CRC
                        if (check_crc32_open_rule && getCrcMode() != CRC32) {
                            const char *msg = "Open of CRC32C file"
                                              " with forced CRC32 mode=x\n";
                            status = FDB_RESULT_INVALID_ARGS;
                            DBG(msg);
                            fdb_log(log_callback, status, msg, getCrcMode());
                            break;
                        } else {
                            status = FDB_RESULT_SUCCESS;

                            accessHeader()->data = (void*) malloc (getBlockSize());
                            memcpy(accessHeader()->data, buf, len);

                            memcpy(&accessHeader()->revnum, buf + len,
                                   sizeof(filemgr_header_revnum_t));

                            memcpy(&accessHeader()->seqnum,
                                   buf + len + sizeof(filemgr_header_revnum_t),
                                   sizeof(fdb_seqnum_t));

                            if (ver_superblock_support(magic)) {
                                // last_writable_bmp_revnum should be same with
                                // the current bmp_revnum (since it indicates the
                                // 'bmp_revnum' of 'sb->cur_alloc_bid').
                                setLastWritableBmpRevnum(getSbBmpRevnum());
                            }

                            accessHeader()->revnum =
                                _endian_decode(accessHeader()->revnum);
                            accessHeader()->seqnum =
                                _endian_decode(accessHeader()->seqnum.load());

                            accessHeader()->size = len;
                            accessHeader()->bid = hdr_bid_local;

                            // release temp buffer
                            releaseTempBuf(buf);
                        }

                        setVersion(magic);
                        return status;
                    } else {
                        status = FDB_RESULT_CHECKSUM_ERROR;
                        uint32_t crc32 = 0, crc32c = 0;
                        crc32 = get_checksum(reinterpret_cast<const uint8_t*>(buf),
                                             len - sizeof(crc),
                                             CRC32);
#ifdef _CRC32C
                        crc32c = get_checksum(reinterpret_cast<const uint8_t*>(buf),
                                              len - sizeof(crc),
                                              CRC32C);
#endif
                        const char *msg = "Crash Detected: CRC on disk %u != (%u | %u) "
                            "in a database file '%s'\n";
                        DBG(msg, crc_file, crc32, crc32c, getFileName());
                        fdb_log(log_callback, status, msg, crc_file, crc32, crc32c,
                                getFileName());
                    }
                } else {
                    status = FDB_RESULT_FILE_CORRUPTION;
                    const char *msg = "Crash Detected: Wrong Magic %" _F64
                        " in a database file '%s'\n";
                    fdb_log(log_callback, status, msg, magic, getFileName());
                }
            } else {
                status = FDB_RESULT_NO_DB_HEADERS;
                if (block_counter == 1) {
                    const char *msg = "Crash Detected: Last Block not DBHEADER %0.01x "
                        "in a database file '%s'\n";
                    DBG(msg, marker[0], getFileName());
                    fdb_log(log_callback, status, msg, marker[0], getFileName());
                }
            }

            setLastCommit(hdr_bid_local * getBlockSize());
            // traverse headers in a circular manner
            if (hdr_bid_local) {
                hdr_bid_local--;
            } else {
                hdr_bid_local = (getPos() / getBlockSize()) - 1;
            }
        } while (hdr_bid_local != hdr_bid);
    }

    // release temp buffer
    releaseTempBuf(buf);

    accessHeader()->reset();
    setVersion(magic);
    return status;
}

size_t FileMgr::getRefCount()
{
    size_t ret = 0;
    acquireSpinLock();
    ret = getRefCount_UNLOCKED();
    releaseSpinLock();
    return ret;
}

uint64_t FileMgr::getBcacheUsedSpace(void)
{
    uint64_t bcache_space = 0;
    if (global_config.getNcacheBlock() > 0) {
        if (ver_btreev2_format(ver_get_latest_magic())) {
            // Use New Bnode Cache Manager to get memory used
            bcache_space = BnodeCacheMgr::get()->getMemoryUsage();
        } else {
            // Block-aligned cache is configured
            bcache_space = BlockCacheManager::getInstance()->getNumFreeBlocks();
            bcache_space = (global_config.getNcacheBlock() - bcache_space)
                           * global_config.getBlockSize();
        }
    }
    return bcache_space;
}

FdbTaskable::FdbTaskable(FileMgr *file) : fileExPoolCtx(file),
    // Workload Policy allows ExecutorPool to have tasks grouped by priority
    // The first parameter marks the file as low (default) or high priority
    // Currently this feature is unused by forestdb as all files are equal.
    workLoadPolicy(FDB_EXPOOL_NUM_WRITERS, // Marks DB file priority as LOW
                   FDB_EXPOOL_NUM_QUEUES), // Shard count (unused feature)
    taskableName(file->getFileName()) {
}

task_gid_t FdbTaskable::getGID() const {
    return task_gid_t(fileExPoolCtx->getFopsHandle());
}

struct filemgr_prefetch_args {
    FileMgr *file;
    uint64_t duration;
    ErrLogCallback *log_callback;
    void *aux;
};

static void *_filemgr_prefetch_thread(void *voidargs)
{
    struct filemgr_prefetch_args *args = (struct filemgr_prefetch_args*)voidargs;

    // Applies to block-aligned buffer cache only for now
    if (ver_btreev2_format(args->file->getVersion())) {
        return nullptr;
    }

    uint8_t *buf = alca(uint8_t, args->file->getBlockSize());
    uint64_t cur_pos = 0, i;
    uint64_t bcache_free_space;
    bid_t bid;
    bool terminate = false;
    struct timeval begin, cur, gap;

    args->file->acquireSpinLock();
    cur_pos = args->file->getLastCommit();
    args->file->releaseSpinLock();
    if (cur_pos < FILEMGR_PREFETCH_UNIT) {
        terminate = true;
    } else {
        cur_pos -= FILEMGR_PREFETCH_UNIT;
    }
    // read backwards from the end of the file, in the unit of FILEMGR_PREFETCH_UNIT
    gettimeofday(&begin, NULL);
    while (!terminate) {
        for (i = cur_pos;
             i < cur_pos + FILEMGR_PREFETCH_UNIT;
             i += args->file->getBlockSize()) {

            gettimeofday(&cur, NULL);
            gap = _utime_gap(begin, cur);
            bcache_free_space = BlockCacheManager::getInstance()->getNumFreeBlocks();
            bcache_free_space *= args->file->getBlockSize();

            if (args->file->prefetchStatus.load() == FILEMGR_PREFETCH_ABORT ||
                gap.tv_sec >= (int64_t)args->duration ||
                bcache_free_space < FILEMGR_PREFETCH_UNIT) {
                // terminate thread when
                // 1. got abort signal
                // 2. time out
                // 3. not enough free space in block cache
                terminate = true;
                break;
            } else {
                bid = i / args->file->getBlockSize();
                if (args->file->read_FileMgr(bid, buf, NULL, true)
                        != FDB_RESULT_SUCCESS) {
                    // 4. read failure
                    fdb_log(args->log_callback, FDB_RESULT_READ_FAIL,
                            "Prefetch thread failed to read a block with block "
                            "id %" _F64 " from a database file '%s'",
                            bid, args->file->getFileName());
                    terminate = true;
                    break;
                }
            }
        }

        if (cur_pos >= FILEMGR_PREFETCH_UNIT) {
            cur_pos -= FILEMGR_PREFETCH_UNIT;
        } else {
            // remaining space is less than FILEMGR_PREFETCH_UNIT
            terminate = true;
        }
    }

    args->file->prefetchStatus.store(FILEMGR_PREFETCH_TERMINATED);
    free(args);
    return NULL;
}

// prefetch the given DB file
void FileMgr::prefetch(ErrLogCallback *log_callback)
{
    // Applies to block-aligned buffer cache only for now
    if (ver_btreev2_format(getVersion())) {
        return;
    }

    uint64_t bcache_free_space;
    bcache_free_space = BlockCacheManager::getInstance()->getNumFreeBlocks();
    bcache_free_space *= getBlockSize();

    // block cache should have free space larger than FILEMGR_PREFETCH_UNIT
    acquireSpinLock();
    filemgr_prefetch_status_t cond = FILEMGR_PREFETCH_IDLE;
    if (getLastCommit() > 0 &&
        bcache_free_space >= FILEMGR_PREFETCH_UNIT &&
        prefetchStatus.compare_exchange_strong(cond, FILEMGR_PREFETCH_RUNNING)) {
        // invoke prefetch thread
        struct filemgr_prefetch_args *args;
        args = (struct filemgr_prefetch_args *)
                            calloc(1, sizeof(struct filemgr_prefetch_args));
        args->file = this;
        args->duration = fileConfig->getPrefetchDuration();
        args->log_callback = log_callback;
        thread_create(&prefetchTid, _filemgr_prefetch_thread, args);
    }
    releaseSpinLock();
}

fdb_status FileMgr::doesFileExist(const char *filename) {
    struct filemgr_ops *ops = get_filemgr_ops();
    fdb_fileops_handle fops_handle;
    fdb_status status = FileMgr::fileOpen(filename, ops, &fops_handle, O_RDONLY,
                                          0444);

    if (status != FDB_RESULT_SUCCESS) {
        return status;
    }
    FileMgr::fileClose(ops, fops_handle);
    return FDB_RESULT_SUCCESS;
}

fdb_status FileMgr::loadSuperBlock(ErrLogCallback *log_callback)
{
    fdb_status status = FDB_RESULT_SUCCESS;

    if (sbInitializer) {
        if (!getSb()) {
            sbInitializer(this);
        }
        if (getPos()) {
            // existing file
            status = getSb()->readLatest(log_callback);
        } else {
            // new file
            status = getSb()->init(log_callback);
        }
        if (status != FDB_RESULT_SUCCESS) {
            delete getSb();
            setSb(nullptr);
        }
    }

    return status;
}

fdb_status FileMgr::fileOpen(const char* filename, struct filemgr_ops *ops,
                             fdb_fileops_handle* fops_handle, int flags,
                             mode_t mode)
{
    *fops_handle = ops->constructor(ops->ctx);
    fdb_status result = ops->open(filename, fops_handle, flags, mode);
    if (result != FDB_RESULT_SUCCESS) {
        ops->destructor(*fops_handle);
        *fops_handle = nullptr;
    }
    return result;
}

filemgr_open_result FileMgr::open(std::string filename,
                                  struct filemgr_ops *ops,
                                  FileMgrConfig *config,
                                  ErrLogCallback *log_callback)
{
    bool create = config->getOptions() & FILEMGR_CREATE;
    bool fail_if_exists = config->getOptions() & FILEMGR_EXCL_CREATE;
    int file_flag = 0x0;
    fdb_status status;
    filemgr_open_result result = {nullptr, FDB_RESULT_OPEN_FAIL};

    init(config);

    if (config->getEncryptionKey()->algorithm != FDB_ENCRYPTION_NONE &&
        global_config.getNcacheBlock() <= 0) {
        // cannot use encryption without a block cache
        result.rv = FDB_RESULT_CRYPTO_ERROR;
        return result;
    }

    // check whether file is already opened or not
    spin_lock(&fileMgrOpenlock);
    FileMgr *file = FileMgrMap::get()->fetchEntry(filename);

    if (file) {
        if (fail_if_exists) {
            spin_unlock(&fileMgrOpenlock);
            result.rv = FDB_RESULT_EEXIST;
            return result;
        }

        // already opened (return existing structure)
        if ((++file->refCount) > 1 &&
            file->fMgrStatus.load() != FILE_CLOSED) {
            spin_unlock(&fileMgrOpenlock);
            result.file = file;
            result.rv = FDB_RESULT_SUCCESS;
            return result;
        }

        file->acquireSpinLock();

        if (file->fMgrStatus.load() == FILE_CLOSED) { // if file was closed before
            file_flag = O_RDWR;
            if (create) {
                file_flag |= O_CREAT;
            }
            *file->fileConfig = *config;
            file->fileConfig->setBlockSize(global_config.getBlockSize());
            file->fileConfig->setNcacheBlock(global_config.getNcacheBlock());
            file_flag |= config->getFlag();
            status = FileMgr::fileOpen(file->getFileName(),
                                       ops, &file->fopsHandle,
                                       file_flag, 0666);
            if (status != FDB_RESULT_SUCCESS) {
                if (status == FDB_RESULT_NO_SUCH_FILE) {
                    // A database file was manually deleted by the user.
                    // Clean up FileMgrMap's unordered map, WAL index, and buffer cache.
                    // Then, retry it with a create option below IFF it is not
                    // a read-only open attempt
                    file->releaseSpinLock();
                    FileMgrMap::get()->removeEntry(file->getFileName());
                    if (!create) {
                        _log_errno_str(file->fopsHandle, file->fMgrOps, log_callback,
                                       FDB_RESULT_NO_SUCH_FILE, "OPEN",
                                       filename.c_str());
                        FileMgr::freeFunc(file);
                        spin_unlock(&fileMgrOpenlock);
                        result.rv = FDB_RESULT_NO_SUCH_FILE;
                        return result;
                    }

                    FileMgr::freeFunc(file);
                } else {
                    _log_errno_str(file->fopsHandle, file->fMgrOps, log_callback,
                                   status, "OPEN", filename.c_str());
                    file->decrRefCount();
                    file->releaseSpinLock();
                    spin_unlock(&fileMgrOpenlock);
                    result.rv = status;
                    return result;
                }
            } else { // Reopening the closed file is succeed.
                file->fMgrStatus.store(FILE_NORMAL);
                if (config->getOptions() & FILEMGR_SYNC) {
                    file->fMgrFlags |= FILEMGR_SYNC;
                } else {
                    file->fMgrFlags &= ~FILEMGR_SYNC;
                }

                file->releaseSpinLock();
                spin_unlock(&fileMgrOpenlock);

                result.file = file;
                result.rv = FDB_RESULT_SUCCESS;
                return result;
            }
        } else { // file is already opened.

            if (config->getOptions() & FILEMGR_SYNC) {
                file->fMgrFlags |= FILEMGR_SYNC;
            } else {
                file->fMgrFlags &= ~FILEMGR_SYNC;
            }

            file->releaseSpinLock();
            spin_unlock(&fileMgrOpenlock);
            result.file = file;
            result.rv = FDB_RESULT_SUCCESS;
            return result;
        }
    }

    file_flag = O_RDWR;
    if (create) {
        file_flag |= O_CREAT;
    }
    if (fail_if_exists) {
        file_flag |= O_EXCL;
    }
    file_flag |= config->getFlag();

    fdb_fileops_handle fops_handle;
    status = FileMgr::fileOpen(filename.c_str(), ops, &fops_handle,
                               file_flag, 0666);
    if (status != FDB_RESULT_SUCCESS) {
        _log_errno_str(fops_handle, ops, log_callback, status, "OPEN",
                       filename.c_str());
        spin_unlock(&fileMgrOpenlock);
        result.rv = status;
        return result;
    }
    file = new FileMgr();
    strcpy(file->fileName, filename.c_str());
    file->fileNameLen = filename.length();

    status = fdb_init_encryptor(&file->fMgrEncryption,
                                config->getEncryptionKey());
    if (status != FDB_RESULT_SUCCESS) {
        FileMgr::fileClose(ops, fops_handle);
        delete file;
        spin_unlock(&fileMgrOpenlock);
        result.rv = status;
        return result;
    }

    file->fMgrOps = ops;
    file->fileConfig = new FileMgrConfig();
    *file->fileConfig = *config;
    file->fileConfig->setBlockSize(global_config.getBlockSize());
    file->fileConfig->setNcacheBlock(global_config.getNcacheBlock());
    file->fopsHandle = fops_handle;

    cs_off_t offset = file->fMgrOps->goto_eof(file->fopsHandle);
    if (offset < 0) {
        _log_errno_str(file->fopsHandle, file->fMgrOps, log_callback,
                       (fdb_status) offset, "SEEK_END", filename.c_str());
        FileMgr::fileClose(file->fMgrOps, file->fopsHandle);
        delete file->fileConfig;
        delete file;
        spin_unlock(&fileMgrOpenlock);
        result.rv = (fdb_status) offset;
        return result;
    }

    file->lastPos = offset;
    file->lastCommit = offset;

    // Note: CRC must be initialized before superblock loading
    // initialize CRC mode
    if (file->fileConfig && file->fileConfig->getOptions() & FILEMGR_CREATE_CRC32) {
        file->crcMode = CRC32;
    } else {
        file->crcMode = CRC_DEFAULT;
    }

    do { // repeat until both superblock and DB header are correctly read
        // init or load superblock
        status = file->loadSuperBlock(log_callback);
        // we can tolerate SB_READ_FAIL for old version file
        if (status != FDB_RESULT_SB_READ_FAIL &&
            status != FDB_RESULT_SUCCESS) {
            _log_errno_str(file->fopsHandle, file->fMgrOps, log_callback,
                           status, "READ", file->fileName);
            FileMgr::fileClose(file->fMgrOps, file->fopsHandle);
            delete file->staleData;
            delete file->fileConfig;
            delete file;
            spin_unlock(&fileMgrOpenlock);
            result.rv = status;
            return result;
        }

        // read header
        status = file->readHeader(log_callback);
        if (file->getSb() && status == FDB_RESULT_NO_DB_HEADERS) {
            // this happens when user created & closed a file without any mutations,
            // thus there is no other data but superblocks.
            // we can tolerate this case.
        } else if (status != FDB_RESULT_SUCCESS) {
            _log_errno_str(file->fopsHandle, file->fMgrOps, log_callback,
                           status, "READ", filename.c_str());
            FileMgr::fileClose(file->fMgrOps, file->fopsHandle);
            delete file->getSb();
            delete file->staleData;
            delete file->fileConfig;
            delete file;
            spin_unlock(&fileMgrOpenlock);
            result.rv = status;
            return result;
        }

        if (file->getSb() &&
            file->accessHeader()->revnum != file->getSb()->getLastHdrRevnum()) {
            // superblock exists but the corresponding DB header does not match.
            // read another candidate.
            continue;
        }

        break;
    } while (true);

    if (!file->staleData) {
        // this means that superblock is not used.
        // init with dummy instance.
        file->staleData = new StaleDataManagerBase();
    }

    // initialize WAL
    if (!file->fMgrWal) {
        file->fMgrWal = new Wal(file, FDB_WAL_NBUCKET);
    }

    // init global transaction for the file
    file->globalTxn.wrapper = (struct wal_txn_wrapper*)
                               malloc(sizeof(struct wal_txn_wrapper));
    file->globalTxn.wrapper->txn = &file->globalTxn;
    file->globalTxn.handle = NULL;
    if (file->getPos()) {
        file->globalTxn.prev_hdr_bid = (file->getPos() / file->getBlockSize()) - 1;
    } else {
        file->globalTxn.prev_hdr_bid = BLK_NOT_FOUND;
    }
    file->globalTxn.prev_revnum = 0;
    file->globalTxn.items = (struct list *)malloc(sizeof(struct list));
    list_init(file->globalTxn.items);
    file->globalTxn.isolation = FDB_ISOLATION_READ_COMMITTED;
    file->fMgrWal->addTransaction_Wal(&file->globalTxn);

    FileMgrMap::get()->addEntry(filename, file);

    if (config->getPrefetchDuration() > 0) {
        file->prefetch(log_callback);
    }

    spin_unlock(&fileMgrOpenlock);

    if (config->getOptions() & FILEMGR_SYNC) {
        file->fMgrFlags |= FILEMGR_SYNC;
    } else {
        file->fMgrFlags &= ~FILEMGR_SYNC;
    }

    result.file = file;
    result.rv = FDB_RESULT_SUCCESS;

    return result;
}

uint64_t FileMgr::updateHeader(void *buf,
                               size_t len) {
    uint64_t ret;
    acquireSpinLock();
    if (fMgrHeader.data == nullptr) {
        fMgrHeader.data = (void *)malloc(blockSize);
    }
    memcpy(fMgrHeader.data, buf, len);
    fMgrHeader.size = len;

    // Since header has been updated, return the next higher revnum
    // But the actual update of the revnum will occur in commitBid
    // atomically along with the DB header bid update
    ret = fMgrHeader.revnum + 1;

    releaseSpinLock();
    return ret;
}

filemgr_header_revnum_t FileMgr::getHeaderRevnum() {
    filemgr_header_revnum_t ret;
    acquireSpinLock();
    ret = fMgrHeader.revnum;
    releaseSpinLock();
    return ret;
}

filemgr_header_revnum_t FileMgr::getHeaderRevnum(bid_t bid) {
    uint8_t *buf = alca(uint8_t, getBlockSize());
    uint64_t version;
    size_t header_len;
    fdb_seqnum_t seqnum;
    filemgr_header_revnum_t revnum = 0;
    fdb_status fs;

    fs = fetchHeader(bid, buf, &header_len, &seqnum, &revnum,
                     NULL, &version, NULL, NULL);
    if (fs != FDB_RESULT_SUCCESS) {
        return 0;
    }
    return revnum;
}

// 'filemgr_get_seqnum', 'filemgr_set_seqnum',
// 'filemgr_get_walflush_revnum', 'filemgr_set_walflush_revnum'
// have to be protected by 'filemgr_mutex_lock' & 'filemgr_mutex_unlock'.
fdb_seqnum_t FileMgr::getSeqnum() const {
    return fMgrHeader.seqnum;
}

void FileMgr::setSeqnum(fdb_seqnum_t seqnum) {
    fMgrHeader.seqnum = seqnum;
}

void* FileMgr::getHeader(void *buf, size_t *len,
                         bid_t *header_bid, fdb_seqnum_t *seqnum,
                         filemgr_header_revnum_t *header_revnum) {
    acquireSpinLock();

    if (fMgrHeader.size > 0) {
        if (buf == NULL) {
            buf = (void*)malloc(fMgrHeader.size);
        }
        memcpy(buf, fMgrHeader.data, fMgrHeader.size);
    }

    if (len) {
        *len = fMgrHeader.size;
    }
    if (header_bid) {
        *header_bid = getHeaderBid();
    }
    if (seqnum) {
        *seqnum = fMgrHeader.seqnum;
    }
    if (header_revnum) {
        *header_revnum = fMgrHeader.revnum;
    }

    releaseSpinLock();

    return buf;
}

fdb_status FileMgr::fetchHeader(uint64_t bid, void *buf, size_t *len,
                                fdb_seqnum_t *seqnum,
                                filemgr_header_revnum_t *header_revnum,
                                uint64_t *deltasize, uint64_t *version,
                                uint64_t *sb_bmp_revnum,
                                ErrLogCallback *log_callback) {
    uint8_t *_buf;
    uint8_t marker[BLK_MARKER_SIZE];
    filemgr_header_len_t hdr_len;
    uint64_t _deltasize, _bmp_revnum;
    filemgr_magic_t magic;
    fdb_status status = FDB_RESULT_SUCCESS;

    *len = 0;

    if (!bid || bid == BLK_NOT_FOUND) {
        // No other header available
        return FDB_RESULT_SUCCESS;
    }

    _buf = (uint8_t *) getTempBuf();

    status = read_FileMgr((bid_t)bid, _buf, log_callback, true);

    if (status != FDB_RESULT_SUCCESS) {
        fdb_log(log_callback, status,
                "Failed to read a database header with block id %" _F64 " in "
                "a database file '%s'", bid, fileName);
        releaseTempBuf(_buf);
        return status;
    }
    memcpy(marker, _buf + blockSize - BLK_MARKER_SIZE, BLK_MARKER_SIZE);

    if (marker[0] != BLK_MARKER_DBHEADER) {
        // Comment this warning log as of now because the circular block reuse
        // can cause false alarms as a previous stale header block can be reclaimed
        // and reused for incoming writes.
        /*
        fdb_log(log_callback, FDB_RESULT_FILE_CORRUPTION,
                "A block marker of the database header block id %" _F64 " in "
                "a database file '%s' does NOT match BLK_MARKER_DBHEADER!",
                bid, fileName.c_str());
        */
        releaseTempBuf(_buf);
        return FDB_RESULT_READ_FAIL;
    }
    memcpy(&magic,
           _buf + blockSize - BLK_MARKER_SIZE - sizeof(magic),
           sizeof(magic));
    magic = _endian_decode(magic);
    if (!ver_is_valid_magic(magic)) {
        fdb_log(log_callback, FDB_RESULT_FILE_CORRUPTION,
                "A block magic value of %" _F64 " in the database header block"
                "id %" _F64 " in a database file '%s'"
                "does NOT match FILEMGR_MAGIC %" _F64 "!",
                magic, bid, fileName, ver_get_latest_magic());
        releaseTempBuf(_buf);
        return FDB_RESULT_FILE_CORRUPTION;
    }
    memcpy(&hdr_len,
           _buf + blockSize - BLK_MARKER_SIZE - sizeof(magic) -
           sizeof(hdr_len), sizeof(hdr_len));
    hdr_len = _endian_decode(hdr_len);

    memcpy(buf, _buf, hdr_len);
    *len = hdr_len;
    *version = magic;

    if (header_revnum) {
        // copy the DB header revnum
        filemgr_header_revnum_t _revnum;
        memcpy(&_revnum, _buf + hdr_len, sizeof(_revnum));
        *header_revnum = _endian_decode(_revnum);
    }
    if (seqnum) {
        // copy default KVS's seqnum
        fdb_seqnum_t _seqnum;
        memcpy(&_seqnum, _buf + hdr_len + sizeof(filemgr_header_revnum_t),
               sizeof(_seqnum));
        *seqnum = _endian_decode(_seqnum);
    }

    if (ver_is_atleast_magic_001(magic)) {
        if (deltasize) {
            memcpy(&_deltasize, _buf + blockSize - BLK_MARKER_SIZE
                   - sizeof(magic) - sizeof(hdr_len) - sizeof(bid)
                   - sizeof(_deltasize), sizeof(_deltasize));
            *deltasize = _endian_decode(_deltasize);
        }
    }

    if (sb_bmp_revnum && ver_superblock_support(magic)) {
        memcpy(&_bmp_revnum, _buf + blockSize - BLK_MARKER_SIZE
               - sizeof(magic) - sizeof(hdr_len) - sizeof(bid)
               - sizeof(_deltasize) - sizeof(_bmp_revnum), sizeof(_bmp_revnum));
        *sb_bmp_revnum = _endian_decode(_bmp_revnum);
    }

    releaseTempBuf(_buf);

    return status;
}

uint64_t FileMgr::fetchPrevHeader(uint64_t bid, void *buf, size_t *len,
                                  fdb_seqnum_t *seqnum,
                                  filemgr_header_revnum_t *revnum,
                                  uint64_t *deltasize, uint64_t *version,
                                  uint64_t *sb_bmp_revnum,
                                  ErrLogCallback *log_callback) {
    uint8_t *_buf;
    uint8_t marker[BLK_MARKER_SIZE];
    fdb_seqnum_t _seqnum;
    filemgr_header_revnum_t _revnum, cur_revnum, prev_revnum;
    filemgr_header_len_t hdr_len;
    filemgr_magic_t magic;
    bid_t _prev_bid, prev_bid;
    uint64_t _deltasize, _bmp_revnum;
    int found = 0;

    *len = 0;

    if (!bid || bid == BLK_NOT_FOUND) {
        // No other header available
        return bid;
    }
    _buf = (uint8_t *) getTempBuf();

    // Reverse scan the file for a previous DB header
    do {
        // Get prev_bid from the current header.
        // Since the current header is already cached during the previous
        // operation, no disk I/O will be triggered.
        if (read_FileMgr((bid_t)bid, _buf, log_callback, true)
                != FDB_RESULT_SUCCESS) {
            break;
        }

        memcpy(marker, _buf + blockSize - BLK_MARKER_SIZE,
               BLK_MARKER_SIZE);
        memcpy(&magic,
               _buf + blockSize - BLK_MARKER_SIZE - sizeof(magic),
               sizeof(magic));
        magic = _endian_decode(magic);

        if (marker[0] != BLK_MARKER_DBHEADER ||
                !ver_is_valid_magic(magic)) {
            // not a header block
            // this happens when this function is invoked between
            // fdb_set() call and fdb_commit() call, so the last block
            // in the file is not a header block
            bid_t latest_hdr = getHeaderBid();
            if (latest_hdr != BLK_NOT_FOUND && bid > latest_hdr) {
                // get the latest header BID
                bid = latest_hdr;
            } else {
                break;
            }
            cur_revnum = fMgrHeader.revnum + 1;
        } else {
            memcpy(&hdr_len,
                   _buf + blockSize - BLK_MARKER_SIZE - sizeof(magic) -
                   sizeof(hdr_len), sizeof(hdr_len));
            hdr_len = _endian_decode(hdr_len);

            memcpy(&_revnum, _buf + hdr_len, sizeof(filemgr_header_revnum_t));
            cur_revnum = _endian_decode(_revnum);

            if (fMgrSb && fMgrSb->bmpExists()) {
                // first check revnum
                if (cur_revnum <= fMgrSb->getMinLiveHdrRevnum()) {
                    // previous headers already have been reclaimed
                    // no more logical prev header
                    break;
                }
            }

            memcpy(&_prev_bid,
                   _buf + blockSize - BLK_MARKER_SIZE - sizeof(magic) -
                   sizeof(hdr_len) - sizeof(_prev_bid),
                   sizeof(_prev_bid));
            prev_bid = _endian_decode(_prev_bid);
            bid = prev_bid;
        }

        // Read the prev header
        fdb_status fs = read_FileMgr((bid_t)bid, _buf, log_callback, true);
        if (fs != FDB_RESULT_SUCCESS) {
            fdb_log(log_callback, fs,
                    "Failed to read a previous database header with block id %"
                    _F64 " in a database file '%s'", bid, fileName);
            break;
        }

        memcpy(marker, _buf + blockSize - BLK_MARKER_SIZE,
               BLK_MARKER_SIZE);
        if (marker[0] != BLK_MARKER_DBHEADER) {
            if (bid) {
                // broken linked list
                fdb_log(log_callback, FDB_RESULT_FILE_CORRUPTION,
                        "A block marker of the previous database header block "
                        "id %" _F64 " in a database file '%s' does NOT match "
                        "BLK_MARKER_DBHEADER!", bid, fileName);
            }
            break;
        }

        memcpy(&magic,
               _buf + blockSize - BLK_MARKER_SIZE - sizeof(magic),
               sizeof(magic));
        magic = _endian_decode(magic);
        if (!ver_is_valid_magic(magic)) {
            // broken linked list
            fdb_log(log_callback, FDB_RESULT_FILE_CORRUPTION,
                    "A block magic value of %" _F64
                    " of the previous database header block id %" _F64 " in "
                    "a database file '%s' does NOT match FILEMGR_MAGIC %"
                    _F64"!", magic, bid, fileName,
                    ver_get_latest_magic());
            break;
        }

        memcpy(&hdr_len,
               _buf + blockSize - BLK_MARKER_SIZE - sizeof(magic) -
               sizeof(hdr_len), sizeof(hdr_len));
        hdr_len = _endian_decode(hdr_len);

        if (buf) {
            memcpy(buf, _buf, hdr_len);
        }
        memcpy(&_revnum, _buf + hdr_len,
               sizeof(filemgr_header_revnum_t));
        prev_revnum = _endian_decode(_revnum);
        if (  prev_revnum >= cur_revnum ||
            ( fMgrSb && prev_revnum < fMgrSb->getMinLiveHdrRevnum() ) ) {
            // no more prev header, or broken linked list
            break;
        }

        memcpy(&_seqnum,
               _buf + hdr_len + sizeof(filemgr_header_revnum_t),
               sizeof(fdb_seqnum_t));
        if (ver_is_atleast_magic_001(magic)) {
            if (deltasize) {
                memcpy(&_deltasize,
                       _buf + blockSize - BLK_MARKER_SIZE - sizeof(magic) -
                       sizeof(hdr_len) - sizeof(prev_bid) - sizeof(_deltasize),
                       sizeof(_deltasize));
                *deltasize = _endian_decode(_deltasize);
            }
        }

        if (sb_bmp_revnum && ver_superblock_support(magic)) {
            memcpy(&_bmp_revnum,
                    _buf + blockSize - BLK_MARKER_SIZE - sizeof(magic) -
                    sizeof(hdr_len) - sizeof(bid) - sizeof(_deltasize) -
                    sizeof(_bmp_revnum),
                    sizeof(_bmp_revnum));
            *sb_bmp_revnum = _endian_decode(_bmp_revnum);
        }

        if (revnum) {
            *revnum = prev_revnum;
        }
        *seqnum = _endian_decode(_seqnum);
        *len = hdr_len;
        *version = magic;
        found = 1;
        break;
    } while (false); // no repetition

    if (!found) { // no other header found till end of file
        *len = 0;
        bid = BLK_NOT_FOUND;
    }

    releaseTempBuf(_buf);

    return bid;
}

fdb_status FileMgr::fileClose(struct filemgr_ops *ops,
                              fdb_fileops_handle fops_handle)
{
    ssize_t ret = ops->close(fops_handle);
    ops->destructor(fops_handle);
    return static_cast<fdb_status>(ret);
}

fdb_status FileMgr::close(FileMgr *file,
                          bool cleanup_cache_onclose,
                          const char *orig_file_name,
                          ErrLogCallback *log_callback)
{
    int rv = FDB_RESULT_SUCCESS;

    if (!file) {
        return FDB_RESULT_INVALID_ARGS;
    }

    if ((--file->refCount) > 0) {
        // File is still accessed by other readers or writers.
        return FDB_RESULT_SUCCESS;
    }

    spin_lock(&fileMgrOpenlock);  // Grab the fileMgrOpenlock to avoid the race with
                                  // Filemgr::open() because file->fMgrLock won't
                                  // prevent the race condition.

    // remove filemgr structure if no thread refers to the file
    file->acquireSpinLock();
    if (file->getRefCount_UNLOCKED() == 0) {
        if (global_config.getNcacheBlock() > 0 &&
            file->getFileStatus() != FILE_REMOVED_PENDING) {
            file->releaseSpinLock();
            // discard all dirty blocks belonged to this file
            if (ver_btreev2_format(file->getVersion())) {
                BnodeCacheMgr::get()->removeDirtyBnodes(file);
            } else {
                BlockCacheManager::getInstance()->removeDirtyBlocks(file);
            }
        } else {
            // If the file is in pending removal (i.e., FILE_REMOVED_PENDING),
            // then its dirty block entries will be cleaned up in either
            // FileMgr::freeFunc() or register_file_removal() below.
            file->releaseSpinLock();
        }

        if (file->fMgrWal) {
            file->fMgrWal->close_Wal(log_callback);
        }
#ifdef _LATENCY_STATS_DUMP_TO_FILE
        LatencyStats::dump(file, log_callback);
#endif // _LATENCY_STATS_DUMP_TO_FILE

        file->acquireSpinLock();

        if (file->fMgrStatus.load() == FILE_REMOVED_PENDING) {

            bool foreground_deletion = false;
            FileMgr *new_file = FileMgrMap::get()->fetchEntry(file->newFileName);

            // immediately remove file if background remove function is not set
            if (!lazyFileDeletionEnabled ||
                (new_file && new_file->inPlaceCompaction)) {
                // TODO: to avoid the scenario below, we prevent background
                //       deletion of in-place compacted files at this time.
                // 1) In-place compacted from 'A' to 'A.1'.
                // 2) Request to delete 'A'.
                // 3) Close 'A.1'; since 'A' is not deleted yet, 'A.1' is not renamed.
                // 4) User opens DB file using its original name 'A', not 'A.1'.
                // 5) Old file 'A' is opened, and then background thread deletes 'A'.
                // 6) Crash!

                // As the file is already unlinked, the file will be removed
                // as soon as we close it.
                rv = FileMgr::fileClose(file->fMgrOps, file->fopsHandle);
                _log_errno_str(file->fopsHandle, file->fMgrOps, log_callback,
                               (fdb_status)rv, "CLOSE", file->fileName);
#if defined(WIN32) || defined(_WIN32)
                // For Windows, we need to manually remove the file.
                remove(file->fileName);
#endif
                foreground_deletion = true;
            }

            // we can release lock becuase no one will open this file
            file->releaseSpinLock();
            FileMgrMap::get()->removeEntry(file->getFileName());

            spin_unlock(&fileMgrOpenlock);

            if (foreground_deletion) {
                FileMgr::freeFunc(file);
            } else {
                registerFileRemoval(file, log_callback);
            }
            return (fdb_status) rv;
        } else {
            rv = FileMgr::fileClose(file->fMgrOps, file->fopsHandle);
            if (cleanup_cache_onclose) {
                _log_errno_str(file->fopsHandle, file->fMgrOps, log_callback,
                               (fdb_status)rv, "CLOSE", file->fileName);
                if (file->inPlaceCompaction && orig_file_name) {
                    uint32_t old_file_refcount = 0;
                    FileMgr *orig_file = FileMgrMap::get()->fetchEntry(
                                                                orig_file_name);
                    // get old file's ref count if exists
                    FileMgr *old_file = FileMgrMap::get()->fetchEntry(
                                                            file->oldFileName);
                    if (old_file) {
                        old_file_refcount = old_file->refCount.load();
                    }

                    // If old file is opened by other handle, renaming should be
                    // postponed. It will be renamed later by the handle referring
                    // to the old file.
                    if (!orig_file && old_file_refcount == 0 &&
                        isFileRemoved(orig_file_name)) {
                        // If background file removal is not done yet, we postpone
                        // file renaming at this time.
                        if (rename(file->fileName, orig_file_name) < 0) {
                            // Note that the renaming failure is not a critical
                            // issue because the last compacted file will be
                            // automatically identified and opened in the next
                            // fdb_open call.
                            _log_errno_str(file->fopsHandle, file->fMgrOps,
                                           log_callback,
                                           FDB_RESULT_FILE_RENAME_FAIL,
                                           "CLOSE", file->fileName);
                        }
                    }
                }
                file->releaseSpinLock();
                // Clean up FileMgrFactory's unordered map, WAL index, and buffer cache.
                FileMgrMap::get()->removeEntry(file->getFileName());

                spin_unlock(&fileMgrOpenlock);

                FileMgr::freeFunc(file);
                return (fdb_status) rv;
            } else {
                file->fMgrStatus.store(FILE_CLOSED);
            }
        }
    }

    _log_errno_str(file->fopsHandle, file->fMgrOps, log_callback,
                   (fdb_status)rv, "CLOSE", file->fileName);

    file->releaseSpinLock();
    spin_unlock(&fileMgrOpenlock);
    return (fdb_status) rv;
}

void FileMgr::removeAllBufferBlocks() {
    // remove all cached blocks
    if (global_config.getNcacheBlock() > 0) {
        if (ver_btreev2_format(getVersion())) {
            if (bnodeCache.load(std::memory_order_relaxed)) {
                BnodeCacheMgr::eraseFileHistory(this);
                bnodeCache.store(nullptr, std::memory_order_relaxed);
            }
        } else {
            if (bCache.load(std::memory_order_relaxed)) {
                BlockCacheManager::eraseFileHistory(this);
                bCache.store(nullptr, std::memory_order_relaxed);
            }
        }
    }
}

void FileMgr::freeFunc(FileMgr *file)
{
    if (!file) {
        return;
    }

    filemgr_prefetch_status_t cond = FILEMGR_PREFETCH_RUNNING;
    if (file->prefetchStatus.compare_exchange_strong(cond, FILEMGR_PREFETCH_ABORT)) {
        // prefetch thread is now running
        // change its status to ABORT to avoid other thread attempts to terminate it.
        void *ret;
        // wait (the thread must have been created..)
        thread_join(file->prefetchTid, &ret);
    }

    // remove all cached blocks
    file->removeAllBufferBlocks();

    if (file->getKVHeader_UNLOCKED()) {
        // multi KV intance mode & KV header exists
        file->free_kv_header(file);
    }

    // free global transaction
    file->fMgrWal->removeTransaction_Wal(&file->globalTxn);
    free(file->globalTxn.items);
    free(file->globalTxn.wrapper);

    // destroy WAL
    if (file->fMgrWal) {
        file->fMgrWal->shutdown_Wal(NULL);
        delete file->fMgrWal;
        file->fMgrWal = NULL;
    }

    // free file header
    if (file->accessHeader()->data) {
        free(file->accessHeader()->data);
        file->accessHeader()->data = nullptr;
    }

    // free superblock
    delete file->getSb();

    // free file structure
    delete file->staleData;
    delete file->fileConfig;
    delete file;
}

// permanently remove file from cache (not just close)
// LCOV_EXCL_START
void FileMgr::removeFile(FileMgr *file,
                         ErrLogCallback *log_callback) {

    if (!file) {
        return;
    }

    if (file->refCount.load() > 0) {
        return;
    }

    // remove from global hash table
    spin_lock(&fileMgrOpenlock);
    FileMgrMap::get()->removeEntry(file->fileName);
    spin_unlock(&fileMgrOpenlock);

    FileMgr *new_file = FileMgrMap::get()->fetchEntry(file->getNewFileName());

    if (!lazyFileDeletionEnabled ||
        (new_file && new_file->inPlaceCompaction)) {
        FileMgr::freeFunc(file);
    } else {
        registerFileRemoval(file, log_callback);
    }
}
// LCOV_EXCL_STOP

static void* _filemgr_is_closed(FileMgr *file, void *ctx) {
    void *ret;
    file->acquireSpinLock();
    if (file->getRefCount_UNLOCKED() != 0) {
        ret = (void *)file;
    } else {
        ret = NULL;
    }
    file->releaseSpinLock();
    return ret;
}

fdb_status FileMgr::shutdown()
{
    fdb_status ret = FDB_RESULT_SUCCESS;
    void *open_file;
    if (fileMgrInitialized) {
        UniqueLock lh(FileMgr::initMutex);

        if (!fileMgrInitialized) {
            // filemgr is already shut down
            return ret;
        }

        spin_lock(&fileMgrOpenlock);
        open_file = FileMgrMap::get()->scan(_filemgr_is_closed, nullptr);
        spin_unlock(&fileMgrOpenlock);
        if (!open_file) {
            FileMgrMap::get()->freeEntries(FileMgr::freeFunc);
            FileMgrMap::shutdown();
            if (global_config.getNcacheBlock() > 0) {
                BlockCacheManager::destroyInstance();
                BnodeCacheMgr::destroyInstance();
            }
            fileMgrInitialized.store(false);
            shutdownTempBuf();
        } else {
            ret = FDB_RESULT_FILE_IS_BUSY;
        }
    }
    return ret;
}

bid_t FileMgr::alloc_FileMgr(ErrLogCallback *log_callback) {
    acquireSpinLock();
    bid_t bid = BLK_NOT_FOUND;

    // block reusing is not allowed for being compacted file
    // for easy implementation.
    if (getFileStatus() == FILE_NORMAL && fMgrSb) {
        bid = fMgrSb->allocBlock();
    }
    if (bid == BLK_NOT_FOUND) {
        bid = lastPos.load() / blockSize;
        lastPos.fetch_add(blockSize);
    }

    if (global_config.getNcacheBlock() <= 0) {
        // if block cache is turned off, write the allocated block before use
        uint8_t _buf = 0x0;
        ssize_t rv = fMgrOps->pwrite(fopsHandle, &_buf, 1,
                                     (bid + 1) * blockSize - 1);
        _log_errno_str(fopsHandle, fMgrOps, log_callback, (fdb_status) rv,
                       "WRITE", fileName);
    }
    releaseSpinLock();

    return bid;
}

// Note that both alloc_multiple & alloc_multiple_cond are not used in
// the new version of DB file (with superblock support).
void FileMgr::allocMultiple(int nblock, bid_t *begin,
                            bid_t *end, ErrLogCallback *log_callback) {
    acquireSpinLock();
    *begin = lastPos.load() / blockSize;
    *end = *begin + nblock - 1;
    lastPos.fetch_add(blockSize * nblock);

    if (global_config.getNcacheBlock() <= 0) {
        // if block cache is turned off, write the allocated block before use
        uint8_t _buf = 0x0;
        ssize_t rv = fMgrOps->pwrite(fopsHandle, &_buf, 1, lastPos.load() - 1);
        _log_errno_str(fopsHandle, fMgrOps, log_callback, (fdb_status) rv,
                       "WRITE", fileName);
    }
    releaseSpinLock();
}

// atomically allocate NBLOCK blocks only when current file position is same
// to nextbid
bid_t FileMgr::allocMultipleCond(bid_t nextbid, int nblock,
                                 bid_t *begin, bid_t *end,
                                 ErrLogCallback *log_callback)
{
    bid_t bid;
    acquireSpinLock();
    bid = lastPos.load() / blockSize;
    if (bid == nextbid) {
        *begin = lastPos.load() / blockSize;
        *end = *begin + nblock - 1;
        lastPos.fetch_add(blockSize * nblock);

        if (global_config.getNcacheBlock() <= 0) {
            // if block cache is turned off, write the allocated block before use
            uint8_t _buf = 0x0;
            ssize_t rv = fMgrOps->pwrite(fopsHandle, &_buf, 1, lastPos.load());
            _log_errno_str(fopsHandle, fMgrOps, log_callback, (fdb_status) rv,
                           "WRITE", fileName);
        }
    }else{
        *begin = BLK_NOT_FOUND;
        *end = BLK_NOT_FOUND;
    }
    releaseSpinLock();
    return bid;
}

fdb_status FileMgr::checkCRC32(void *buf)
{
    if ( *((uint8_t*)buf + getBlockSize()-1) == BLK_MARKER_BNODE ) {
        uint32_t crc_file = 0;
        memcpy(&crc_file, (uint8_t *) buf + BTREE_CRC_OFFSET, sizeof(crc_file));
        crc_file = _endian_decode(crc_file);
        memset((uint8_t *) buf + BTREE_CRC_OFFSET, 0xff, BTREE_CRC_FIELD_LEN);
        if (!perform_integrity_check(reinterpret_cast<const uint8_t*>(buf),
                                     getBlockSize(),
                                     crc_file,
                                     getCrcMode())) {
            return FDB_RESULT_CHECKSUM_ERROR;
        }
    }
    return FDB_RESULT_SUCCESS;
}

bool FileMgr::invalidateBlock(bid_t bid) {
    // Applies to block-aligned buffer cache only
    bool ret;
    if (lastCommit.load() < bid * blockSize) {
        ret = true; // block invalidated was allocated recently (uncommitted)
    } else {
        ret = false; // a block from the past is invalidated (committed)
    }
    if (global_config.getNcacheBlock() > 0 &&
        !ver_btreev2_format(getVersion())) {
        BlockCacheManager::getInstance()->invalidateBlock(this, bid);
    }
    return ret;
}

bool FileMgr::isFullyResident() {
    bool ret = false;
    if (global_config.getNcacheBlock() > 0) {
        if (bCache.load(std::memory_order_relaxed)) {
            //TODO: A better thing to do is to track number of document blocks
            // and only compare those with the cached document block count
            double num_cached_blocks = static_cast<double>(
                        BlockCacheManager::getInstance()->getNumBlocks(this));
            uint64_t num_blocks = lastPos.load() / blockSize;
            double num_fblocks = static_cast<double>(num_blocks);
            if (num_cached_blocks > num_fblocks * FILEMGR_RESIDENT_THRESHOLD) {
                ret = true;
            }
        } else if (bnodeCache.load(std::memory_order_relaxed)) {
            // Note that with bnodeCache these stats do not fully represent a
            // file's resident status, as document blocks are not cached
            // anymore; This function is only used by WAL flush
            // optimization which is not necessary for BTreeV2.
            if (bnodeCache.load()->getNumItems() ==
                                    bnodeCache.load()->getNumItemsWritten()) {
                ret = true;
            }
        }
    }
    return ret;
}

uint64_t FileMgr::flushImmutable(ErrLogCallback *log_callback) {
    // Does not apply to non-block-aligned buffer cache
    uint64_t ret = 0;
    if (global_config.getNcacheBlock() > 0 &&
        !ver_btreev2_format(getVersion())) {

        if (ioInprog.load()) {
            return 0;
        }
        ret = BlockCacheManager::getInstance()->getNumImmutables(this);
        if (!ret) {
            return ret;
        }
        fdb_status rv = BlockCacheManager::getInstance()->flushImmutable(this);
        if (rv != FDB_RESULT_SUCCESS) {
            _log_errno_str(fopsHandle, fMgrOps, log_callback, (fdb_status)rv,
                           "WRITE", fileName);
        }
        return BlockCacheManager::getInstance()->getNumImmutables(this);
    }

    return ret;
}

fdb_status FileMgr::read_FileMgr(bid_t bid, void *buf,
                                 ErrLogCallback *log_callback,
                                 bool read_on_cache_miss) {

    // In Btree V2 mode, DocIO or appending/reading header
    // can invoke this function.

    size_t lock_no;
    ssize_t r;
    uint64_t pos = bid * blockSize;
    fdb_status status = FDB_RESULT_SUCCESS;
    uint64_t curr_pos = lastPos.load();

    if (pos >= curr_pos) {
        const char *msg = "Read error: read offset %" _F64 " exceeds the file's "
                          "current offset %" _F64 " in a database file '%s'\n";
        fdb_log(log_callback, FDB_RESULT_READ_FAIL, msg, pos, curr_pos,
                fileName);
        return FDB_RESULT_READ_FAIL;
    }

    if (global_config.getNcacheBlock() > 0 &&
        !ver_btreev2_format(getVersion())) {
        lock_no = bid % DLOCK_MAX;
        (void)lock_no;

#ifdef __FILEMGR_DATA_PARTIAL_LOCK
        plock_entry_t *plock_entry = NULL;
        bid_t is_writer = 0;
#endif
        bool locked = false;
        // Note: we don't need to grab lock for committed blocks
        // because they are immutable so that no writer will interfere and
        // overwrite dirty data
        if (isWritable(bid)) {
#ifdef __FILEMGR_DATA_PARTIAL_LOCK
            plock_entry = plock_lock(&fMgrPlock, &bid, &is_writer);
#elif defined(__FILEMGR_DATA_MUTEX_LOCK)
            mutex_lock(&dataMutex[lock_no]);
#else
            spin_lock(&dataSpinlock[lock_no]);
#endif //__FILEMGR_DATA_PARTIAL_LOCK
            locked = true;
        }

        r = BlockCacheManager::getInstance()->read(this, bid, buf);
        if (r == 0) {
            // cache miss
            incrBlockCacheMisses();
            if (!read_on_cache_miss) {
                if (locked) {
#ifdef __FILEMGR_DATA_PARTIAL_LOCK
                    plock_unlock(&fMgrPlock, plock_entry);
#elif defined(__FILEMGR_DATA_MUTEX_LOCK)
                    mutex_unlock(&dataMutex[lock_no]);
#else
                    spin_unlock(&dataSpinlock[lock_no]);
#endif //__FILEMGR_DATA_PARTIAL_LOCK
                }

                const char *msg = "Read error: BID %" _F64 " in a database file"
                                  " '%s' doesn't exist in the cache and "
                                  "read_on_cache_miss flag is turned on";
                fdb_log(log_callback, FDB_RESULT_READ_FAIL, msg, bid,
                        fileName);
                return FDB_RESULT_READ_FAIL;
            }

            // if normal file, just read a block
            r = readBlock(buf, bid);
            if (r != (ssize_t)blockSize) {
                _log_errno_str(fopsHandle, fMgrOps, log_callback,
                               (fdb_status) r, "READ", fileName);
                if (locked) {
#ifdef __FILEMGR_DATA_PARTIAL_LOCK
                    plock_unlock(&fMgrPlock, plock_entry);
#elif defined(__FILEMGR_DATA_MUTEX_LOCK)
                    mutex_unlock(&dataMutex[lock_no]);
#else
                    spin_unlock(&dataSpinlock[lock_no]);
#endif //__FILEMGR_DATA_PARTIAL_LOCK
                }
                const char *msg = "Read error: BID %" _F64 " in a database file"
                                  " '%s' " "is not read correctly: only %d "
                                  "bytes read";
                status = r < 0 ? (fdb_status)r : FDB_RESULT_READ_FAIL;
                fdb_log(log_callback, status, msg, bid, fileName, r);
                if (!log_callback || !log_callback->getCallback()) {
                    dbg_print_buf(buf, blockSize, true, 16);
                }
                return status;
            }

            status = checkCRC32(buf);
            if (status != FDB_RESULT_SUCCESS) {
                _log_errno_str(fopsHandle, fMgrOps, log_callback, status, "READ",
                               fileName);
                if (locked) {
#ifdef __FILEMGR_DATA_PARTIAL_LOCK
                    plock_unlock(&fMgrPlock, plock_entry);
#elif defined(__FILEMGR_DATA_MUTEX_LOCK)
                    mutex_unlock(&dataMutex[lock_no]);
#else
                    spin_unlock(&dataSpinlock[lock_no]);
#endif //__FILEMGR_DATA_PARTIAL_LOCK
                }
                const char *msg = "Read error: checksum error on BID %" _F64
                                  " in a database file '%s' : marker %x";
                fdb_log(log_callback, status, msg, bid,
                        fileName, *((uint8_t*)buf + blockSize - 1));
                if (!log_callback || !log_callback->getCallback()) {
                    dbg_print_buf(buf, blockSize, true, 16);
                }
                return status;
            }

            r = BlockCacheManager::getInstance()->write(this, bid, buf,
                                                        BCACHE_REQ_CLEAN,
                                                        false);
            if (r != global_config.getBlockSize()) {
                if (locked) {
#ifdef __FILEMGR_DATA_PARTIAL_LOCK
                    plock_unlock(&fMgrPlock, plock_entry);
#elif defined(__FILEMGR_DATA_MUTEX_LOCK)
                    mutex_unlock(&dataMutex[lock_no]);
#else
                    spin_unlock(&dataSpinlock[lock_no]);
#endif //__FILEMGR_DATA_PARTIAL_LOCK
                }
                _log_errno_str(fopsHandle, fMgrOps, log_callback,
                               (fdb_status) r, "WRITE", fileName);
                const char *msg = "Read error: BID %" _F64 " in a database file"
                                  " '%s' is not written in cache correctly: "
                                  "only %d bytes written";
                status = r < 0 ? (fdb_status) r : FDB_RESULT_WRITE_FAIL;
                fdb_log(log_callback, status, msg, bid, fileName, r);
                if (!log_callback || !log_callback->getCallback()) {
                    dbg_print_buf(buf, blockSize, true, 16);
                }
                return status;
            }
        } else {
            incrBlockCacheHits();
        }

        if (locked) {
#ifdef __FILEMGR_DATA_PARTIAL_LOCK
            plock_unlock(&fMgrPlock, plock_entry);
#elif defined(__FILEMGR_DATA_MUTEX_LOCK)
            mutex_unlock(&dataMutex[lock_no]);
#else
            spin_unlock(&dataSpinlock[lock_no]);
#endif //__FILEMGR_DATA_PARTIAL_LOCK
        }
    } else {
        if (!read_on_cache_miss) {
            const char *msg = "Read error: BID %" _F64 " in a database file "
                              "'%s': block cache is not enabled.\n";
            fdb_log(log_callback, FDB_RESULT_READ_FAIL, msg, bid,
                    fileName);
            return FDB_RESULT_READ_FAIL;
        }

        r = readBlock(buf, bid);
        if (r != (ssize_t)blockSize) {
            _log_errno_str(fopsHandle, fMgrOps, log_callback, (fdb_status) r,
                           "READ", fileName);
            const char *msg = "Read error: BID %" _F64 " in a database file "
                              "'%s' is not read correctly: only %d bytes read "
                              "(block cache disabled)";
            status = (r < 0)? (fdb_status)r : FDB_RESULT_READ_FAIL;
            fdb_log(log_callback, status, msg, bid, fileName, r);
            if (!log_callback || !log_callback->getCallback()) {
                dbg_print_buf(buf, blockSize, true, 16);
            }
            return status;
        }

        status = checkCRC32(buf);
        if (status != FDB_RESULT_SUCCESS) {
            _log_errno_str(fopsHandle, fMgrOps, log_callback, status, "READ",
                           fileName);
            const char *msg = "Read error: checksum error on BID %" _F64 " in "
                              "a database file '%s' : marker %x (block cache "
                              "disabled)";
            fdb_log(log_callback, status, msg, bid,
                    fileName, *((uint8_t*)buf + blockSize - 1));
            if (!log_callback || !log_callback->getCallback()) {
                dbg_print_buf(buf, blockSize, true, 16);
            }
            return status;
        }
    }
    return status;
}

fdb_status FileMgr::writeOffset(bid_t bid, uint64_t offset, uint64_t len,
                                void *buf, bool final_write,
                                ErrLogCallback *log_callback) {

    size_t lock_no;
    ssize_t r = 0;
    uint64_t pos = bid * blockSize + offset;
    uint64_t curr_commit_pos = lastCommit.load();

    if (offset + len > blockSize) {
        const char *msg = "Write error: trying to write the buffer data "
            "(offset: %" _F64 ", len: %" _F64 " that exceeds the block size "
            "%" _F64 " in a database file '%s'";
        fdb_log(log_callback, FDB_RESULT_WRITE_FAIL, msg, offset, len,
                blockSize, fileName);
        return FDB_RESULT_WRITE_FAIL;
    }

    if (fMgrSb && fMgrSb->bmpExists()) {
        // block reusing is enabled
        if (!fMgrSb->isWritable(bid)) {
            const char *msg = "Write error: trying to write at the offset "
                              "%" _F64 " that is not identified as a reusable "
                              "block in a database file '%s'";
            fdb_log(log_callback, FDB_RESULT_WRITE_FAIL, msg, pos,
                    fileName);
            return FDB_RESULT_WRITE_FAIL;
        }
    } else if (pos < curr_commit_pos) {
        // stale blocks are not reused yet
        if (fMgrSb == NULL ||
            (fMgrSb && pos >= fMgrSb->getConfig().num_sb * blockSize)) {
            // (non-sequential update is exceptionally allowed for superblocks)
            const char *msg = "Write error: trying to write at the offset "
                              "%" _F64 " that is smaller than the current "
                              "commit offset %" _F64 " in a database file '%s'";
            fdb_log(log_callback, FDB_RESULT_WRITE_FAIL, msg, pos,
                    curr_commit_pos, fileName);
            return FDB_RESULT_WRITE_FAIL;
        }
    }

    if (global_config.getNcacheBlock() > 0 &&
        !ver_btreev2_format(getVersion())) {
        lock_no = bid % DLOCK_MAX;
        (void)lock_no;

        bool locked = false;
#ifdef __FILEMGR_DATA_PARTIAL_LOCK
        plock_entry_t *plock_entry;
        bid_t is_writer = 1;
        plock_entry = plock_lock(&fMgrPlock, &bid, &is_writer);
#elif defined(__FILEMGR_DATA_MUTEX_LOCK)
        mutex_lock(&dataMutex[lock_no]);
#else
        spin_lock(&dataSpinlock[lock_no]);
#endif //__FILEMGR_DATA_PARTIAL_LOCK
        locked = true;

        if (len == blockSize) {
            // write entire block .. we don't need to read previous block
            r = BlockCacheManager::getInstance()->write(this, bid, buf,
                                                        BCACHE_REQ_DIRTY,
                                                        final_write);
            if (r != global_config.getBlockSize()) {
                if (locked) {
#ifdef __FILEMGR_DATA_PARTIAL_LOCK
                    plock_unlock(&fMgrPlock, plock_entry);
#elif defined(__FILEMGR_DATA_MUTEX_LOCK)
                    mutex_unlock(&dataMutex[lock_no]);
#else
                    spin_unlock(&dataSpinlock[lock_no]);
#endif //__FILEMGR_DATA_PARTIAL_LOCK
                }
                _log_errno_str(fopsHandle, fMgrOps, log_callback,
                               (fdb_status) r, "WRITE", fileName);
                return r < 0 ? (fdb_status) r : FDB_RESULT_WRITE_FAIL;
            }
        } else {
            // partially write buffer cache first
            r = BlockCacheManager::getInstance()->writePartial(this, bid, buf,
                                                               offset, len,
                                                               final_write);
            if (r == 0) {
                // cache miss
                // write partially .. we have to read previous contents of the block
                int64_t cur_file_pos = fMgrOps->goto_eof(fopsHandle);
                if (cur_file_pos < 0) {
                    _log_errno_str(fopsHandle, fMgrOps, log_callback,
                                   (fdb_status) cur_file_pos, "EOF",
                                   fileName);
                    return (fdb_status) cur_file_pos;
                }
                bid_t cur_file_last_bid = cur_file_pos / blockSize;
                void *_buf = getTempBuf();

                if (bid >= cur_file_last_bid) {
                    // this is the first time to write this block
                    // we don't need to read previous block from file.
                } else {
                    r = readBlock(_buf, bid);
                    if (r != (ssize_t)blockSize) {
                        if (locked) {
#ifdef __FILEMGR_DATA_PARTIAL_LOCK
                            plock_unlock(&fMgrPlock, plock_entry);
#elif defined(__FILEMGR_DATA_MUTEX_LOCK)
                            mutex_unlock(&dataMutex[lock_no]);
#else
                            spin_unlock(&dataSpinlock[lock_no]);
#endif //__FILEMGR_DATA_PARTIAL_LOCK
                        }
                        releaseTempBuf(_buf);
                        _log_errno_str(fopsHandle, fMgrOps, log_callback,
                                       (fdb_status)r, "READ", fileName);
                        return r < 0 ? (fdb_status) r : FDB_RESULT_READ_FAIL;
                    }
                }

                memcpy((uint8_t *)_buf + offset, buf, len);
                r = BlockCacheManager::getInstance()->write(this, bid, _buf,
                                                            BCACHE_REQ_DIRTY,
                                                            final_write);
                if (r != global_config.getBlockSize()) {
                    if (locked) {
#ifdef __FILEMGR_DATA_PARTIAL_LOCK
                        plock_unlock(&fMgrPlock, plock_entry);
#elif defined(__FILEMGR_DATA_MUTEX_LOCK)
                        mutex_unlock(&dataMutex[lock_no]);
#else
                        spin_unlock(&dataSpinlock[lock_no]);
#endif //__FILEMGR_DATA_PARTIAL_LOCK
                    }
                    releaseTempBuf(_buf);
                    _log_errno_str(fopsHandle, fMgrOps, log_callback,
                                   (fdb_status) r, "WRITE", fileName);
                    return r < 0 ? (fdb_status) r : FDB_RESULT_WRITE_FAIL;
                }

                releaseTempBuf(_buf);
            } // cache miss
        } // full block or partial block

        if (locked) {
#ifdef __FILEMGR_DATA_PARTIAL_LOCK
            plock_unlock(&fMgrPlock, plock_entry);
#elif defined(__FILEMGR_DATA_MUTEX_LOCK)
            mutex_unlock(&dataMutex[lock_no]);
#else
            spin_unlock(&dataSpinlock[lock_no]);
#endif //__FILEMGR_DATA_PARTIAL_LOCK
        }
    } else { // block cache disabled

#ifdef __CRC32
        if (len == blockSize) {
            uint8_t marker = *((uint8_t*)buf + blockSize - 1);
            if (marker == BLK_MARKER_BNODE) {
                memset((uint8_t *)buf + BTREE_CRC_OFFSET, 0xff,
                       BTREE_CRC_FIELD_LEN);
                uint32_t crc32 = get_checksum(
                                        reinterpret_cast<const uint8_t*>(buf),
                                        blockSize,
                                        crcMode);
                crc32 = _endian_encode(crc32);
                memcpy((uint8_t *)buf + BTREE_CRC_OFFSET, &crc32, sizeof(crc32));
            }
        }
#endif

        r = fMgrOps->pwrite(fopsHandle, buf, len, pos);
        _log_errno_str(fopsHandle, fMgrOps, log_callback, (fdb_status) r,
                       "WRITE", fileName);
        if ((uint64_t)r != len) {
            return r < 0 ? (fdb_status) r : FDB_RESULT_WRITE_FAIL;
        }
    } // block cache check
    return FDB_RESULT_SUCCESS;
}

fdb_status FileMgr::write_FileMgr(bid_t bid, void *buf,
                                  ErrLogCallback *log_callback) {
    return writeOffset(bid, 0, blockSize, buf,
                       false, // TODO: track immutability of index blk
                       log_callback);
}

fdb_status FileMgr::commit_FileMgr(bool sync, ErrLogCallback *log_callback) {
    // append header at the end of the file
    uint64_t bmp_revnum = 0;
    if (fMgrSb) {
        bmp_revnum = fMgrSb->getBmpRevnum();
    }
    return commitBid(BLK_NOT_FOUND, bmp_revnum, sync, log_callback);
}

fdb_status FileMgr::commitBid(bid_t bid, uint64_t bmp_revnum, bool sync,
                              ErrLogCallback *log_callback) {
    struct avl_node *a;
    struct kvs_node *node;
    bid_t prev_bid, _prev_bid;
    uint64_t _deltasize, _bmp_revnum;
    fdb_seqnum_t _seqnum;
    filemgr_header_revnum_t _revnum;
    int result = FDB_RESULT_SUCCESS;
    bool block_reusing = false;

    setIoInprog();
    if (global_config.getNcacheBlock() > 0) {
        if (ver_btreev2_format(getVersion())) {
            if (bnodeCache.load(std::memory_order_relaxed)) {
                result = BnodeCacheMgr::get()->flush(this);
            } else {
                // It means that 'FileBnodeCache' instance is not
                // created yet, because no B+tree related operation
                // has been executed. This is not an actual error.
                result = FDB_RESULT_SUCCESS;
            }
        } else {
            result = BlockCacheManager::getInstance()->flush(this);
        }

        if (result != FDB_RESULT_SUCCESS) {
            _log_errno_str(fopsHandle, fMgrOps, log_callback, (fdb_status)result,
                           "FLUSH", fileName);
            clearIoInprog();
            return (fdb_status)result;
        }
    }

    acquireSpinLock();

    uint16_t header_len = fMgrHeader.size;
    KvsHeader *kv_header = kvHeader;
    filemgr_magic_t magic = fMgrVersion;

    if (header_len > 0 && fMgrHeader.data) {
        void *buf = getTempBuf();
        uint8_t marker[BLK_MARKER_SIZE];

        // [header data]:        'header_len' bytes   <---+
        // [header revnum]:      8 bytes                  |
        // [default KVS seqnum]: 8 bytes                  |
        // ...                                            |
        // (empty)                                    blocksize
        // ...                                            |
        // [SB bitmap revnum]:   8 bytes                  |
        // [Delta size]:         8 bytes                  |
        // [prev header bid]:    8 bytes                  |
        // [header length]:      2 bytes                  |
        // [magic number]:       8 bytes                  |
        // [block marker]:       1 byte               <---+

        // header data
        memcpy(buf, fMgrHeader.data, header_len);

        ++fMgrHeader.revnum; // Only Commit increments header revnum

        // header rev number
        _revnum = _endian_encode(fMgrHeader.revnum);
        memcpy((uint8_t *)buf + header_len, &_revnum,
               sizeof(filemgr_header_revnum_t));
        // file's sequence number (default KVS seqnum)
        _seqnum = _endian_encode(fMgrHeader.seqnum.load());
        memcpy((uint8_t *)buf + header_len + sizeof(filemgr_header_revnum_t),
               &_seqnum, sizeof(fdb_seqnum_t));

        // current header's sb bmp revision number
        if (fMgrSb) {
            _bmp_revnum = _endian_encode(bmp_revnum);
            memcpy((uint8_t *)buf + (blockSize - sizeof(filemgr_magic_t)
                   - sizeof(header_len) - sizeof(_prev_bid) - sizeof(_deltasize)
                   - sizeof(_bmp_revnum) - BLK_MARKER_SIZE),
                   &_bmp_revnum,
                   sizeof(_bmp_revnum));
        }

        // delta size since prior commit
        _deltasize = _endian_encode(fMgrHeader.stat.deltasize //index+data
                                    + fMgrWal->getDataSize_Wal()); // wal datasize
        memcpy((uint8_t *)buf + (blockSize - sizeof(filemgr_magic_t)
               - sizeof(header_len) - sizeof(_prev_bid) * 2 - BLK_MARKER_SIZE),
               &_deltasize, sizeof(_deltasize));

        // Reset in-memory delta size of the header for next commit...
        fMgrHeader.stat.deltasize = 0; // single kv store header
        if (kv_header) { // multi kv store stats
            a = avl_first(kv_header->idx_id);
            while (a) {
                node = _get_entry(a, struct kvs_node, avl_id);
                a = avl_next(&node->avl_id);
                node->stat.deltasize = 0;
            }
        }

        // prev header bid
        prev_bid = fMgrHeader.bid;
        _prev_bid = _endian_encode(prev_bid);
        memcpy((uint8_t *)buf + (blockSize - sizeof(filemgr_magic_t)
               - sizeof(header_len) - sizeof(_prev_bid) - BLK_MARKER_SIZE),
               &_prev_bid,
               sizeof(_prev_bid));
        // header length
        header_len = _endian_encode(header_len);
        memcpy((uint8_t *)buf + (blockSize - sizeof(filemgr_magic_t)
               - sizeof(header_len) - BLK_MARKER_SIZE),
               &header_len,
               sizeof(header_len));
        // magic number
        magic = _endian_encode(magic);
        memcpy((uint8_t *)buf + (blockSize - sizeof(filemgr_magic_t)
               - BLK_MARKER_SIZE), &magic, sizeof(magic));

        // marker
        memset(marker, BLK_MARKER_DBHEADER, BLK_MARKER_SIZE);
        memcpy((uint8_t *)buf + blockSize - BLK_MARKER_SIZE,
               marker, BLK_MARKER_SIZE);

        if (bid == BLK_NOT_FOUND) {
            // append header at the end of file
            bid = lastPos.load() / blockSize;
            block_reusing = false;
        } else {
            // write header in the allocated (reused) block
            block_reusing = true;
            // we MUST invalidate the header block 'bid', since previous
            // contents of 'bid' may remain in block cache and cause data
            // inconsistency if reading header block hits the cache.
            invalidateBlock(bid);
        }

        ssize_t rv = writeBlocks(buf, 1, bid);
        _log_errno_str(fopsHandle, fMgrOps, log_callback, (fdb_status) rv,
                       "WRITE", fileName);
        if (rv != (ssize_t)blockSize) {
            releaseTempBuf(buf);
            releaseSpinLock();
            clearIoInprog();
            return rv < 0 ? (fdb_status) rv : FDB_RESULT_WRITE_FAIL;
        }

        if (prev_bid) {
            // mark prev DB header as stale
            addStaleRegion(prev_bid * blockSize, blockSize);
        }

        fMgrHeader.bid = bid;
        if (!block_reusing) {
            lastPos.fetch_add(blockSize);
        }

        releaseTempBuf(buf);
    }

    if (fMgrSb && fMgrSb->bmpExists() &&
        fMgrSb->getCurAllocBid() != BLK_NOT_FOUND &&
        fMgrStatus.load() == FILE_NORMAL) {
        // block reusing is currently enabled
        lastCommit.store(fMgrSb->getCurAllocBid() * blockSize);
    } else {
        lastCommit.store(lastPos.load());
    }

    if (fMgrSb) {
        // Since some more blocks may be allocated after the header block
        // (for storing BMP data or system docs for stale info)
        // so that the block pointed to by 'cur_alloc_bid' may have
        // different BMP revision number. So we have to use the
        // up-to-date bmp_revnum here.
        lastWritableBmpRevnum.store(getSbBmpRevnum());
    }

    releaseSpinLock();

    if (sync) {
        result = fMgrOps->fsync(fopsHandle);
        _log_errno_str(fopsHandle, fMgrOps, log_callback, (fdb_status)result,
                       "FSYNC", fileName);
    }
    clearIoInprog();
    return (fdb_status) result;
}

fdb_status FileMgr::sync_FileMgr(bool sync_option,
                                 ErrLogCallback *log_callback) {
    fdb_status result = FDB_RESULT_SUCCESS;
    if (global_config.getNcacheBlock() > 0) {
        if (ver_btreev2_format(getVersion())) {
            result = BnodeCacheMgr::get()->flush(this);
        } else {
            result = BlockCacheManager::getInstance()->flush(this);
        }

        if (result != FDB_RESULT_SUCCESS) {
            _log_errno_str(fopsHandle, fMgrOps, log_callback, (fdb_status)result,
                           "FLUSH", fileName);
            return result;
        }
    }

    if (sync_option && (fMgrFlags & FILEMGR_SYNC)) {
        int rv = fMgrOps->fsync(fopsHandle);
        _log_errno_str(fopsHandle, fMgrOps, log_callback, (fdb_status)rv, "FSYNC",
                       fileName);
        return (fdb_status) rv;
    }
    return result;
}

fdb_status FileMgr::copyFileRange(FileMgr *src_file,
                                  FileMgr *dst_file,
                                  bid_t src_bid, bid_t dst_bid,
                                  bid_t clone_len) {
    uint32_t blocksize = src_file->getBlockSize();
    fdb_status fs = (fdb_status)dst_file->fMgrOps->copy_file_range(
                                            src_file->fsType,
                                            src_file->fopsHandle,
                                            dst_file->fopsHandle,
                                            src_bid * blocksize,
                                            dst_bid * blocksize,
                                            clone_len * blocksize);
    if (fs != FDB_RESULT_SUCCESS) {
        return fs;
    }
    dst_file->lastPos.store((dst_bid + clone_len) * blocksize);
    return FDB_RESULT_SUCCESS;
}

bool FileMgr::updateFileStatus(file_status_t status, const char *old_filename) {
    bool ret = true;
    acquireSpinLock();
    fMgrStatus = status;
    if (old_filename) {
        if (oldFileName.empty()) {
            oldFileName = std::string(old_filename);
        } else {
            ret = false;
            fdb_assert(refCount.load(), refCount.load(), 0);
        }
    }
    releaseSpinLock();
    return ret;
}

void FileMgr::setCompactionState(FileMgr *old_file, FileMgr *new_file,
                                 file_status_t status) {
    if (old_file) {
        spin_lock(&old_file->fMgrLock);
        if (new_file) {
            old_file->newFileName = std::string(new_file->getFileName());
        } else {
            old_file->newFileName.clear();
        }
        old_file->fMgrStatus = status;
        spin_unlock(&old_file->fMgrLock);

        if (new_file) {
            spin_lock(&new_file->fMgrLock);
            new_file->oldFileName = std::string(old_file->getFileName());
            spin_unlock(&new_file->fMgrLock);
        }
    }
}

bool FileMgr::setKVHeader(KvsHeader *kv_header,
                          void (*free_kv_header)(FileMgr *file)) {
    bool ret;
    acquireSpinLock();

    if (!kvHeader) {
        setKVHeader_UNLOCKED(kv_header);
        setFreeKVHeaderCB(free_kv_header);
        ret = true;
    } else {
        ret = false;
    }

    releaseSpinLock();

    return ret;
}

KvsHeader* FileMgr::getKVHeader() {
    KvsHeader *kv_header = NULL;
    acquireSpinLock();
    kv_header = getKVHeader_UNLOCKED();
    releaseSpinLock();
    return kv_header;
}

// Check if there is a file that still points to the old_file that is being
// compacted away. If so open the file and return its pointer.
static void *_filemgr_check_stale_link(FileMgr *file, void *ctx) {
    FileMgr *cur_file = reinterpret_cast<FileMgr *>(ctx);
    file->acquireSpinLock();
    if (file->getFileStatus() == FILE_REMOVED_PENDING &&
        file->getNewFileName().compare(std::string(cur_file->getFileName())) == 0) {
        // Incrementing reference counter below is the same as Filemgr::open()
        // We need to do this to ensure that the pointer returned does not
        // get freed outside the filemgr_open lock
        file->incrRefCount();
        file->releaseSpinLock();
        return (void *)file;
    }
    file->releaseSpinLock();
    return (void *)NULL;
}

FileMgr* FileMgr::searchStaleLinks() {
    FileMgr *very_old_file;
    spin_lock(&fileMgrOpenlock);
    very_old_file = reinterpret_cast<FileMgr *>(
                    FileMgrMap::get()->scan(_filemgr_check_stale_link, this));
    spin_unlock(&fileMgrOpenlock);
    return very_old_file;
}

char* FileMgr::redirectOldFile(FileMgr *very_old_file,
                               FileMgr *new_file,
                               filemgr_redirect_hdr_func redirect_header_func) {
    if (!very_old_file || !new_file) {
        return NULL;
    }

    size_t old_header_len, new_header_len;
    char *past_filename;
    spin_lock(&very_old_file->fMgrLock);

    FileMgr *newFile = FileMgrMap::get()->fetchEntry(very_old_file->newFileName);

    if (very_old_file->accessHeader()->size == 0 || !newFile) {
        spin_unlock(&very_old_file->fMgrLock);
        return NULL;
    }

    old_header_len = very_old_file->accessHeader()->size;
    // Find out the new DB header length with new_file's filename
    new_header_len = old_header_len -
                     newFile->getFileNameLen() + new_file->getFileNameLen();
    // As we are going to change the new_filename field in the DB header of the
    // very_old_file, maybe reallocate DB header buf to accomodate bigger value
    if (new_header_len > old_header_len) {
        very_old_file->accessHeader()->data = realloc(very_old_file->accessHeader()->data,
                                                      new_file->getBlockSize());
    }
    // Re-direct very_old_file to new_file
    very_old_file->newFileName = std::string(new_file->getFileName());
    // Note that the oldFileName of the new_file is not updated, this
    // is so that every file in the history is reachable from the current file.

    past_filename = redirect_header_func(very_old_file,
                                         (uint8_t *)very_old_file->accessHeader()->data,
                                         new_file);//Update in-memory header
    very_old_file->accessHeader()->size = new_header_len;
    ++very_old_file->accessHeader()->revnum;

    spin_unlock(&very_old_file->fMgrLock);
    return past_filename;
}

void FileMgr::removePending(FileMgr *old_file,
                            FileMgr *new_file,
                            ErrLogCallback *log_callback) {
    if (old_file == NULL || new_file == NULL) {
        return;
    }

    spin_lock(&old_file->fMgrLock);
    if (old_file->refCount.load() > 0) {
        // delay removing
        old_file->newFileName = std::string(new_file->getFileName());
        old_file->fMgrStatus.store(FILE_REMOVED_PENDING);

#if !(defined(WIN32) || defined(_WIN32))
        // Only for Posix
        int ret = unlink(old_file->fileName);
        if (errno == ENOENT) {
            // Ignore 'No such file or directory' error as the file
            // must've been removed already
        } else {
            _log_errno_str(old_file->fopsHandle, old_file->fMgrOps,
                           log_callback, (fdb_status)ret, "UNLINK",
                           old_file->fileName);
        }
#endif

        spin_unlock(&old_file->fMgrLock);

    } else {
        // immediatly remove
        // LCOV_EXCL_START
        spin_unlock(&old_file->fMgrLock);

        FileMgr *new_file = FileMgrMap::get()->fetchEntry(
                                                old_file->getNewFileName());

        if (!lazyFileDeletionEnabled ||
            (new_file && new_file->inPlaceCompaction)) {
            remove(old_file->fileName);
        }
        FileMgr::removeFile(old_file, log_callback);
        // LCOV_EXCL_STOP
    }
}

// Note: fileMgrOpenlock should be held before calling this function.
fdb_status FileMgr::destroyFile(std::string filename,
                                FileMgrConfig *config,
                                std::unordered_set<std::string> *destroy_file_set) {
    std::unordered_set<std::string> to_destroy_files;
    std::unordered_set<std::string> *destroy_set = (destroy_file_set
                                                        ? destroy_file_set
                                                        : &to_destroy_files);
    fdb_status status = FDB_RESULT_SUCCESS;
    char *old_filename = NULL;

    // check whether file is already being destroyed in parent recursive call
    auto it = destroy_set->find(filename);
    if (it != destroy_set->end()) {
        // Duplicate filename found, nothing to be done in this call
        if (!destroy_file_set) {
            // top level or non-recursive call
            destroy_set->clear();
        }
        return status;
    } else {
        // Remember file. Stack value ok IFF single direction recursion
        destroy_set->insert(filename);
    }

    // check global list of known files to see if it is already opened or not
    FileMgr *file = FileMgrMap::get()->fetchEntry(filename);
    if (file) {
        // already opened (return existing structure)
        file->acquireSpinLock();
        if (file->refCount.load()) {
            file->releaseSpinLock();
            status = FDB_RESULT_FILE_IS_BUSY;
            if (!destroy_file_set) { // top level or non-recursive call
                destroy_set->clear();
            }
            return status;
        }
        file->releaseSpinLock();
        if (!file->oldFileName.empty()) {
            status = destroyFile(file->oldFileName, config, destroy_set);
            if (status != FDB_RESULT_SUCCESS) {
                if (!destroy_file_set) { // top level or non-recursive call
                    destroy_set->clear();
                }
                return status;
            }
        }

        // Cleanup file from in-memory as well as on-disk
        FileMgr::freeFunc(file);
        if (doesFileExist(filename.c_str()) == FDB_RESULT_SUCCESS) {
            if (remove(filename.c_str())) {
                status = FDB_RESULT_FILE_REMOVE_FAIL;
            }
        }
    } else { // file not in memory, read on-disk to destroy older versions..
        FileMgr disk_file;
        strcpy(disk_file.fileName, filename.c_str());
        disk_file.fileNameLen = filename.length();
        disk_file.fMgrOps = get_filemgr_ops();
        status = FileMgr::fileOpen(disk_file.fileName,
                                   disk_file.fMgrOps,
                                   &disk_file.fopsHandle,
                                   O_RDWR, 0666);
        disk_file.blockSize = global_config.getBlockSize();
        FileMgrConfig fmc;
        disk_file.fileConfig = &fmc;
        *disk_file.fileConfig = *config;
        fdb_init_encryptor(&disk_file.fMgrEncryption, config->getEncryptionKey());
        if (status != FDB_RESULT_SUCCESS) {
            if (status != FDB_RESULT_NO_SUCH_FILE) {
                if (!destroy_file_set) { // top level or non-recursive call
                    destroy_set->clear();
                }
                return status;
            }
            status = FDB_RESULT_SUCCESS;
        } else { // file successfully opened, seek to end to get DB header
            cs_off_t offset = disk_file.fMgrOps->goto_eof(disk_file.fopsHandle);
            if (offset < 0) {
                if (!destroy_file_set) { // top level or non-recursive call
                    destroy_set->clear();
                }
                return (fdb_status) offset;
            } else { // Need to read DB header which contains old filename
                disk_file.lastPos.store(offset);
                // initialize CRC mode
                if (disk_file.fileConfig &&
                    disk_file.fileConfig->getOptions() & FILEMGR_CREATE_CRC32) {
                    disk_file.crcMode = CRC32;
                } else {
                    disk_file.crcMode = CRC_DEFAULT;
                }

                status = disk_file.loadSuperBlock(NULL);
                if (status != FDB_RESULT_SUCCESS) {
                    if (!destroy_file_set) { // top level or non-recursive call
                        destroy_set->clear();
                    }
                    FileMgr::fileClose(disk_file.fMgrOps, disk_file.fopsHandle);
                    return status;
                }

                status = disk_file.readHeader(NULL);
                if (status != FDB_RESULT_SUCCESS) {
                    if (!destroy_file_set) { // top level or non-recursive call
                        destroy_set->clear();
                    }
                    FileMgr::fileClose(disk_file.fMgrOps, disk_file.fopsHandle);
                    // Delete staleData allocated within FileMgr::loadSuperBlock()
                    delete disk_file.staleData;
                    delete disk_file.fMgrSb;
                    return status;
                }
                if (disk_file.fMgrHeader.data) {
                    size_t new_fileNamelen_off = ver_get_new_filename_off(
                                                            disk_file.fMgrVersion);
                    size_t old_fileNamelen_off = new_fileNamelen_off + 2;
                    uint16_t *new_filename_len_ptr = (uint16_t *)((char *)
                                                     disk_file.fMgrHeader.data
                                                     + new_fileNamelen_off);
                    uint16_t new_filename_len =
                                      _endian_decode(*new_filename_len_ptr);
                    uint16_t *old_filename_len_ptr = (uint16_t *)((char *)
                                                     disk_file.fMgrHeader.data
                                                     + old_fileNamelen_off);
                    uint16_t old_filename_len =
                                      _endian_decode(*old_filename_len_ptr);
                    old_filename = (char *)disk_file.fMgrHeader.data +
                                    old_fileNamelen_off + 2 + new_filename_len;
                    if (old_filename_len) {
                        status = destroyFile(std::string(old_filename),
                                             config, destroy_set);
                    }
                    free(disk_file.fMgrHeader.data);
                    disk_file.fMgrHeader.data = nullptr;
                }
                FileMgr::fileClose(disk_file.fMgrOps, disk_file.fopsHandle);
                // Delete staleData allocated within FileMgr::loadSuperBlock()
                delete disk_file.staleData;
                delete disk_file.fMgrSb;
                if (status == FDB_RESULT_SUCCESS) {
                    if (doesFileExist(filename.c_str()) == FDB_RESULT_SUCCESS) {
                        if (remove(filename.c_str())) {
                            status = FDB_RESULT_FILE_REMOVE_FAIL;
                        }
                    }
                }
            }
        }
    }

    if (!destroy_file_set) { // top level or non-recursive call
        destroy_set->clear();
    }

    return status;
}

uint64_t FileMgr::getBCacheItems() {
    // If bnodeCache is available fetch stats from it,
    // or else if blockCache is available fetch stats from it.
    // Note that both bnodeCache and blockCache cannot exist at the same time.
    if (bnodeCache.load()) {
        return bnodeCache.load()->getNumItems();
    } else if (bCache.load()) {
        return bCache.load()->getNumItems();
    } else {
        return 0;
    }

}

uint64_t FileMgr::getBCacheVictims() {
    // If bnodeCache is available fetch stats from it,
    // or else if blockCache is available fetch stats from it.
    // Note that both bnodeCache and blockCache cannot exist at the same time.
    if (bnodeCache.load()) {
        return bnodeCache.load()->getNumVictims();
    } else if (bCache.load()) {
        return bCache.load()->getNumVictims();
    } else {
        return 0;
    }
}

uint64_t FileMgr::getBCacheImmutables() {
    // If bnodeCache is available fetch stats from it,
    // or else if blockCache is available fetch stats from it.
    // Note that both bnodeCache and blockCache cannot exist at the same time.
    if (bCache.load()) {
        return bCache.load()->getNumImmutables();
    } else if (bnodeCache.load()) {
        // Items written to a bnodeCache are treated as immutable
        return bnodeCache.load()->getNumItems();
    } else {
        return 0;
    }
}

bool FileMgr::isRollbackOn() {
    bool rv;
    acquireSpinLock();
    rv = (fMgrFlags & FILEMGR_ROLLBACK_IN_PROG);
    releaseSpinLock();
    return rv;
}

void FileMgr::setRollback(uint8_t new_val) {
    acquireSpinLock();
    if (new_val) {
        fMgrFlags |= FILEMGR_ROLLBACK_IN_PROG;
    } else {
        fMgrFlags &= ~FILEMGR_ROLLBACK_IN_PROG;
    }
    releaseSpinLock();
}

void FileMgr::setCancelCompaction(bool cancel) {
    acquireSpinLock();
    if (cancel) {
        fMgrFlags |= FILEMGR_CANCEL_COMPACTION;
    } else {
        fMgrFlags &= ~FILEMGR_CANCEL_COMPACTION;
    }
    releaseSpinLock();
}

bool FileMgr::isCompactionCancellationRequested() {
    bool rv;
    acquireSpinLock();
    rv = (fMgrFlags & FILEMGR_CANCEL_COMPACTION);
    releaseSpinLock();
    return rv;
}

void FileMgr::setInPlaceCompaction(bool in_place_compaction) {
    acquireSpinLock();
    inPlaceCompaction = in_place_compaction;
    releaseSpinLock();
}

bool FileMgr::isInPlaceCompactionSet() {
    bool ret = false;
    acquireSpinLock();
    ret = inPlaceCompaction;
    releaseSpinLock();
    return ret;
}

void FileMgr::mutexOpenlock(FileMgrConfig *config) {
    init(config);
    spin_lock(&fileMgrOpenlock);
}

void FileMgr::mutexOpenunlock(void) {
    spin_unlock(&fileMgrOpenlock);
}

void FileMgr::mutexLock() {
    mutex_lock(&writerLock.mutex);
    writerLock.locked = true;
}

bool FileMgr::mutexTrylock() {
    if (mutex_trylock(&writerLock.mutex)) {
        writerLock.locked = true;
        return true;
    }
    return false;
}

void FileMgr::mutexUnlock() {
    if (writerLock.locked) {
        writerLock.locked = false;
        mutex_unlock(&writerLock.mutex);
    }
}

bool FileMgr::isCommitHeader(void *head_buffer, size_t blocksize) {
    uint8_t marker[BLK_MARKER_SIZE];
    filemgr_magic_t magic;
    marker[0] = *(((uint8_t *)head_buffer)
                 + blocksize - BLK_MARKER_SIZE);
    if (marker[0] != BLK_MARKER_DBHEADER) {
        return false;
    }

    memcpy(&magic, (uint8_t *) head_buffer
            + blocksize - BLK_MARKER_SIZE - sizeof(magic), sizeof(magic));
    magic = _endian_decode(magic);

    return ver_is_valid_magic(magic);
}

bool FileMgr::isCowSupported(FileMgr *src, FileMgr *dst) {
    src->fsType = src->fMgrOps->get_fs_type(src->fopsHandle);
    if (src->fsType < 0) {
        return false;
    }
    dst->fsType = dst->fMgrOps->get_fs_type(dst->fopsHandle);
    if (dst->fsType < 0) {
        return false;
    }
    if (src->fsType == dst->fsType && src->fsType != FILEMGR_FS_NO_COW) {
        return true;
    }
    return false;
}

void FileMgr::setThrottlingDelay(uint64_t delay_us) {
    throttlingDelay.store(delay_us, std::memory_order_relaxed);
}

uint32_t FileMgr::getThrottlingDelay() const {
    return throttlingDelay.load(std::memory_order_relaxed);
}

void FileMgr::addStaleRegion(bid_t offset,
                            size_t len) {
    staleData->addStaleRegion(offset, len);
}

void FileMgr::markDocStale(bid_t offset,
                        size_t length) {
    staleData->markDocStale(offset, length);
}

INLINE int _fhandle_idx_cmp(struct avl_node *a, struct avl_node *b, void *aux) {
    uint64_t aaa, bbb;
    struct filemgr_fhandle_idx_node *aa, *bb;
    aa = _get_entry(a, struct filemgr_fhandle_idx_node, avl);
    bb = _get_entry(b, struct filemgr_fhandle_idx_node, avl);
    aaa = (uint64_t)aa->fhandle;
    bbb = (uint64_t)bb->fhandle;

#ifdef __BIT_CMP
    return _CMP_U64(aaa, bbb);
#else
    if (aaa < bbb) {
        return -1;
    } else if (aaa > bbb) {
        return 1;
    } else {
        return 0;
    }
#endif
}

void FileMgr::freeFileHandleIdx() {
    struct avl_node *a;
    struct filemgr_fhandle_idx_node *item;

    a = avl_first(&handleIdx);
    while (a) {
        item = _get_entry(a, struct filemgr_fhandle_idx_node, avl);
        a = avl_next(a);
        avl_remove(&handleIdx, &item->avl);
        free(item);
    }
}

bool FileMgr::fhandleAdd(void *fhandle) {
    bool ret;
    struct filemgr_fhandle_idx_node *item, query;
    struct avl_node *a;

    spin_lock(&handleIdxLock);

    query.fhandle = fhandle;
    a = avl_search(&handleIdx, &query.avl, _fhandle_idx_cmp);
    if (!a) {
        // not exist, create a node and insert
        item = (struct filemgr_fhandle_idx_node *)calloc(1,
                                sizeof(struct filemgr_fhandle_idx_node));
        item->fhandle = fhandle;
        avl_insert(&handleIdx, &item->avl, _fhandle_idx_cmp);
        ret = true;
    } else {
        ret = false;
    }

    spin_unlock(&handleIdxLock);
    return ret;
}

bool FileMgr::fhandleRemove(void *fhandle) {
    bool ret;
    struct filemgr_fhandle_idx_node *item, query;
    struct avl_node *a;

    spin_lock(&handleIdxLock);

    query.fhandle = fhandle;
    a = avl_search(&handleIdx, &query.avl, _fhandle_idx_cmp);
    if (a) {
        // exist, remove & free the item
        item = _get_entry(a, struct filemgr_fhandle_idx_node, avl);
        avl_remove(&handleIdx, &item->avl);
        free(item);
        ret = true;
    } else {
        ret = false;
    }

    spin_unlock(&handleIdxLock);
    return ret;
}

void FileMgr::dirtyUpdateInit() {
    avl_init(&dirtyUpdateIdx, NULL);
    spin_init(&dirtyUpdateLock);
    dirtyUpdateCounter = 0;
    latestDirtyUpdate = NULL;
}

void FileMgr::dirtyUpdateFree() {
    struct avl_node *a = avl_first(&dirtyUpdateIdx);
    struct filemgr_dirty_update_node *node;

    while (a) {
        node = _get_entry(a, struct filemgr_dirty_update_node, avl);
        a = avl_next(a);
        avl_remove(&dirtyUpdateIdx, &node->avl);
        removeDirtyNode(node);
    }
    spin_destroy(&dirtyUpdateLock);
}

INLINE int _dirtyUpdateIdx_cmp(struct avl_node *a, struct avl_node *b, void *aux) {
    struct filemgr_dirty_update_node *aa, *bb;
    aa = _get_entry(a, struct filemgr_dirty_update_node, avl);
    bb = _get_entry(b, struct filemgr_dirty_update_node, avl);

    return _CMP_U64(aa->id, bb->id);
}

INLINE int _dirty_blocks_cmp(struct avl_node *a, struct avl_node *b, void *aux) {
    struct filemgr_dirty_update_block *aa, *bb;
    aa = _get_entry(a, struct filemgr_dirty_update_block, avl);
    bb = _get_entry(b, struct filemgr_dirty_update_block, avl);

    return _CMP_U64(aa->bid, bb->bid);
}

struct filemgr_dirty_update_node* FileMgr::dirtyUpdateNewNode() {
    struct filemgr_dirty_update_node *node;

    node = (struct filemgr_dirty_update_node *)
           calloc(1, sizeof(struct filemgr_dirty_update_node));
    node->id = ++dirtyUpdateCounter;
    node->immutable = false; // currently being written
    node->expired = false;
    node->ref_count = 0;
    node->idtree_root = node->seqtree_root = BLK_NOT_FOUND;
    avl_init(&node->dirty_blocks, NULL);

    spin_lock(&dirtyUpdateLock);
    avl_insert(&dirtyUpdateIdx, &node->avl, _dirtyUpdateIdx_cmp);
    spin_unlock(&dirtyUpdateLock);

    return node;
}

struct filemgr_dirty_update_node* FileMgr::dirtyUpdateGetLatest() {
    struct filemgr_dirty_update_node *node = NULL;

    // find the first immutable node from the end
    spin_lock(&dirtyUpdateLock);

    node = latestDirtyUpdate;
    if (node) {
        node->ref_count++;
    }

    spin_unlock(&dirtyUpdateLock);
    return node;
}

void FileMgr::dirtyUpdateIncRefCount(struct filemgr_dirty_update_node *node) {
    if (!node) {
        return;
    }
    node->ref_count++;
}

void FileMgr::flushDirtyNode(struct filemgr_dirty_update_node *node,
                             ErrLogCallback *log_callback) {
    struct avl_node *a;
    struct filemgr_dirty_update_block *block;

    if (!node) {
        return;
    }

    // Flush all dirty blocks belonging to this dirty update entry
    a = avl_first(&node->dirty_blocks);
    while (a) {
        block = _get_entry(a, struct filemgr_dirty_update_block, avl);
        a = avl_next(a);
        if (isWritable(block->bid) && !block->immutable) {
            write_FileMgr(block->bid, block->addr, log_callback);
        }
    }
    node->expired = true;
}

void FileMgr::dirtyUpdateCommit(struct filemgr_dirty_update_node *commit_node,
                                ErrLogCallback *log_callback) {
    struct avl_node *a;
    struct filemgr_dirty_update_node *node;
    struct list remove_queue;
    struct list_elem *le;

    // 1. write back all blocks in the given (committed) node
    // 2. remove all other immutable dirty update entries
    list_init(&remove_queue);
    if (commit_node) {
        flushDirtyNode(commit_node, log_callback);
    }

    spin_lock(&dirtyUpdateLock);
    latestDirtyUpdate = NULL;

    a = avl_first(&dirtyUpdateIdx);
    while (a) {
        node = _get_entry(a, struct filemgr_dirty_update_node, avl);
        a = avl_next(a);

        if (node->immutable && node->ref_count.load() == 0) {
            // detach from tree and insert into remove queue
            avl_remove(&dirtyUpdateIdx, &node->avl);
            list_push_front(&remove_queue, &node->le);
        }
    }

    spin_unlock(&dirtyUpdateLock);

    le = list_begin(&remove_queue);
    while (le) {
        node = _get_entry(le, struct filemgr_dirty_update_node, le);
        le = list_remove(&remove_queue, &node->le);
        removeDirtyNode(node);
    }
}

void FileMgr::dirtyUpdateSetImmutable(struct filemgr_dirty_update_node *prev_node,
                                      struct filemgr_dirty_update_node *node) {
    struct avl_node *a;
    struct filemgr_dirty_update_node *cur_node;
    struct list remove_queue;
    struct list_elem *le;

    if (!node) {
        return;
    }

    list_init(&remove_queue);

    spin_lock(&dirtyUpdateLock);
    node->immutable = true;

    // absorb all blocks that exist in the previous dirty update
    // but not exist in the current dirty update
    if (prev_node) {
        bool migration = false;
        struct avl_node *aa, *bb;
        struct filemgr_dirty_update_block *block, *block_copy, query;

        if (prev_node->immutable && prev_node->ref_count.load() == 1) {
            // only the current thread is referring this dirty update entry.
            // we don't need to copy blocks; just migrate them directly.
            migration = true;
        }

        if (prev_node->expired) {
            // skip already copied node as its blocks are already in
            // the new node or DB file
            aa = NULL;
        } else {
            aa = avl_first(&prev_node->dirty_blocks);
        }

        while (aa) {
            block = _get_entry(aa, struct filemgr_dirty_update_block, avl);
            aa = avl_next(aa);

            if (block->immutable || !isWritable(block->bid)) {
                // this block is already committed.
                // it can happen when previous dirty update was flushed but
                // was not closed as other handle was still referring it.

                // ignore this block and set the flag to avoid future copy
                // (FileMgr::isWritable() alone is not enough because a block
                //  can become writable again due to circular block reuse).
                block->immutable = true;
                continue;
            }

            query.bid = block->bid;
            bb = avl_search(&node->dirty_blocks, &query.avl, _dirty_blocks_cmp);
            if (!bb) {
                // not exist in the current dirty update .. copy (or move) it
                if (migration) {
                    // move
                    avl_remove(&prev_node->dirty_blocks, &block->avl);
                    block_copy = block;
                } else {
                    // copy
                    block_copy = (struct filemgr_dirty_update_block *)
                                 calloc(1, sizeof(struct filemgr_dirty_update_block));
                    void *addr;
                    malloc_align(addr, FDB_SECTOR_SIZE, blockSize);
                    block_copy->addr = addr;
                    block_copy->bid = block->bid;
                    block_copy->immutable = block->immutable;
                    memcpy(block_copy->addr, block->addr, blockSize);
                }
                avl_insert(&node->dirty_blocks, &block_copy->avl, _dirty_blocks_cmp);
            }
        }

        // now we don't need to copy blocks in this node in the future
        prev_node->expired = true;
    }

    // set latest dirty update
    latestDirtyUpdate = node;

    // remove all previous dirty updates whose ref_count == 0
    // (except for 'node')
    a = avl_first(&dirtyUpdateIdx);
    while (a) {
        cur_node = _get_entry(a, struct filemgr_dirty_update_node, avl);
        if (cur_node == node) {
            break;
        }
        a = avl_next(a);
        if (cur_node->immutable && cur_node->ref_count.load() == 0 &&
            cur_node != node) {
            // detach from tree and insert into remove queue
            avl_remove(&dirtyUpdateIdx, &cur_node->avl);
            list_push_front(&remove_queue, &cur_node->le);
        }
    }

    spin_unlock(&dirtyUpdateLock);

    le = list_begin(&remove_queue);
    while (le) {
        cur_node = _get_entry(le, struct filemgr_dirty_update_node, le);
        le = list_remove(&remove_queue, &cur_node->le);
        removeDirtyNode(cur_node);
    }
}

void FileMgr::removeDirtyNode(struct filemgr_dirty_update_node *node) {
    struct avl_node *a;
    struct filemgr_dirty_update_block *block;

    if (!node) {
        return;
    }

    // free all dirty blocks belonging to this node
    a = avl_first(&node->dirty_blocks);
    while (a) {
        block = _get_entry(a, struct filemgr_dirty_update_block, avl);
        a = avl_next(a);
        avl_remove(&node->dirty_blocks, &block->avl);
        free_align(block->addr);
        free(block);
    }

    free(node);
}

void FileMgr::dirtyUpdateRemoveNode(struct filemgr_dirty_update_node *node) {
    if (!node) {
        return;
    }

    spin_lock(&dirtyUpdateLock);
    avl_remove(&dirtyUpdateIdx, &node->avl);
    spin_unlock(&dirtyUpdateLock);

    removeDirtyNode(node);
}

void FileMgr::dirtyUpdateCloseNode(struct filemgr_dirty_update_node *node) {
    if (!node) {
        return;
    }

    // just decrease the ref count
    // (any nodes whose ref_count==0 will be removed lazily)
    node->ref_count--;
}

fdb_status FileMgr::writeDirty(bid_t bid, void *buf,
                               struct filemgr_dirty_update_node *node,
                               ErrLogCallback *log_callback) {
    struct avl_node *a;
    struct filemgr_dirty_update_block *block, query;

    query.bid = bid;
    a = avl_search(&node->dirty_blocks, &query.avl, _dirty_blocks_cmp);
    if (a) {
        // already exist .. overwrite
        block = _get_entry(a, struct filemgr_dirty_update_block, avl);
    } else {
        // not exist .. create a new block for this update node
        block = (struct filemgr_dirty_update_block *)
                calloc(1, sizeof(struct filemgr_dirty_update_block));
        void *addr = NULL;
        malloc_align(addr, FDB_SECTOR_SIZE, blockSize);
        block->addr = addr;
        block->bid = bid;
        block->immutable = false;
        avl_insert(&node->dirty_blocks, &block->avl, _dirty_blocks_cmp);
    }

    memcpy(block->addr, buf, blockSize);
    return FDB_RESULT_SUCCESS;
}

fdb_status FileMgr::readDirty(bid_t bid, void *buf,
                              struct filemgr_dirty_update_node *node_reader,
                              struct filemgr_dirty_update_node *node_writer,
                              ErrLogCallback *log_callback,
                              bool read_on_cache_miss) {
    struct avl_node *a;
    struct filemgr_dirty_update_block *block, query;

    if (node_writer) {
        // search the current (being written / mutable) dirty update first
        query.bid = bid;
        a = avl_search(&node_writer->dirty_blocks, &query.avl, _dirty_blocks_cmp);
        if (a) {
            // exist .. directly read the dirty block
            block = _get_entry(a, struct filemgr_dirty_update_block, avl);
            memcpy(buf, block->addr, blockSize);
            return FDB_RESULT_SUCCESS;
        }
        // not exist .. search the latest immutable dirty update next
    }

    if (node_reader) {
        query.bid = bid;
        a = avl_search(&node_reader->dirty_blocks, &query.avl, _dirty_blocks_cmp);
        if (a) {
            // exist .. directly read the dirty block
            block = _get_entry(a, struct filemgr_dirty_update_block, avl);
            memcpy(buf, block->addr, blockSize);
            return FDB_RESULT_SUCCESS;
        }
    }

    // not exist in both dirty update entries .. call FileMgr::read()
    return read_FileMgr(bid, buf, log_callback, read_on_cache_miss);
}

const char* FileMgr::getLatencyStatName(fdb_latency_stat_type stat) {
    switch(stat) {
        case FDB_LATENCY_SETS:          return "sets            ";
        case FDB_LATENCY_GETS:          return "gets            ";
        case FDB_LATENCY_SNAP_INMEM:    return "in-mem_snapshot ";
        case FDB_LATENCY_SNAP_DUR:      return "durable_snapshot";
        case FDB_LATENCY_COMMITS:       return "commits         ";
        case FDB_LATENCY_COMPACTS:      return "compact         ";
        case FDB_LATENCY_ITR_INIT:      return "itr-init        ";
        case FDB_LATENCY_ITR_SEQ_INIT:  return "itr-seq-ini     ";
        case FDB_LATENCY_ITR_NEXT:      return "itr-next        ";
        case FDB_LATENCY_ITR_PREV:      return "itr-prev        ";
        case FDB_LATENCY_ITR_GET:       return "itr-get         ";
        case FDB_LATENCY_ITR_GET_META:  return "itr-get-meta    ";
        case FDB_LATENCY_ITR_SEEK:      return "itr-seek        ";
        case FDB_LATENCY_ITR_SEEK_MAX:  return "itr-seek-max    ";
        case FDB_LATENCY_ITR_SEEK_MIN:  return "itr-seek-min    ";
        case FDB_LATENCY_ITR_CLOSE:     return "itr-close       ";
        case FDB_LATENCY_OPEN:          return "fdb_open        ";
        case FDB_LATENCY_KVS_OPEN:      return "fdb_kvs_open    ";
        case FDB_LATENCY_SNAP_CLONE:    return "clone-snapshot  ";
        case FDB_LATENCY_WAL_INS:       return "wal_insert      ";
        case FDB_LATENCY_WAL_FIND:      return "wal_find        ";
        case FDB_LATENCY_WAL_COMMIT:    return "wal_commit      ";
        case FDB_LATENCY_WAL_FLUSH:     return "wal_flush       ";
        case FDB_LATENCY_WAL_RELEASE:   return "wal_releas_items";
    }
    return NULL;
}

void KvsStatOperations::statSet(fdb_kvs_id_t kv_id, KvsStat stat) {
    if (kv_id == 0) {
        file->acquireSpinLock();
        file->accessHeader()->stat = stat;
        file->releaseSpinLock();
    } else {
        struct avl_node *a;
        struct kvs_node query, *node;
        KvsHeader *kv_header = file->getKVHeader_UNLOCKED();

        spin_lock(&kv_header->lock);
        query.id = kv_id;
        a = avl_search(kv_header->idx_id, &query.avl_id, _kvs_stat_cmp);
        if (a) {
            node = _get_entry(a, struct kvs_node, avl_id);
            node->stat = stat;
        }
        spin_unlock(&kv_header->lock);
    }
}

void KvsStatOperations::statUpdateAttr(fdb_kvs_id_t kv_id,
                                       kvs_stat_attr_t attr,
                                       int delta) {
    KvsStat *stat;
    KvsHeader *kv_header = file->getKVHeader_UNLOCKED();

    if (kv_id == 0) {
        stat = &file->accessHeader()->stat;
        file->acquireSpinLock();
    } else {
        struct avl_node *a;
        struct kvs_node query, *node;

        spin_lock(&kv_header->lock);
        query.id = kv_id;
        a = avl_search(kv_header->idx_id, &query.avl_id, _kvs_stat_cmp);
        if (!a) {
            // KV instance corresponding to the kv_id is already removed
            spin_unlock(&kv_header->lock);
            return;
        }
        node = _get_entry(a, struct kvs_node, avl_id);
        stat = &node->stat;
    }

    if (attr == KVS_STAT_DATASIZE) {
        stat->datasize += delta;
    } else if (attr == KVS_STAT_NDOCS) {
        stat->ndocs += delta;
    } else if (attr == KVS_STAT_NDELETES) {
        stat->ndeletes += delta;
    } else if (attr == KVS_STAT_NLIVENODES) {
        stat->nlivenodes += delta;
    } else if (attr == KVS_STAT_WAL_NDELETES) {
        stat->wal_ndeletes += delta;
    } else if (attr == KVS_STAT_WAL_NDOCS) {
        stat->wal_ndocs += delta;
    } else if (attr == KVS_STAT_DELTASIZE) {
        stat->deltasize += delta;
    }

    if (kv_id == 0) {
        file->releaseSpinLock();
    } else {
        spin_unlock(&kv_header->lock);
    }
}

int KvsStatOperations::statGetKvHeader(KvsHeader *kv_header,
                                       fdb_kvs_id_t kv_id,
                                       KvsStat *stat) {
    int ret = 0;
    struct avl_node *a;
    struct kvs_node query, *node;

    query.id = kv_id;
    a = avl_search(kv_header->idx_id, &query.avl_id, _kvs_stat_cmp);
    if (a) {
        node = _get_entry(a, struct kvs_node, avl_id);
        *stat = node->stat;
    } else {
        ret = -1;
    }
    return ret;
}

int KvsStatOperations::statGet(fdb_kvs_id_t kv_id,
                               KvsStat *stat) {
    int ret = 0;

    if (kv_id == 0) {
        file->acquireSpinLock();
        *stat = file->accessHeader()->stat;
        file->releaseSpinLock();
    } else {
        KvsHeader *kv_header = file->getKVHeader_UNLOCKED();

        spin_lock(&kv_header->lock);
        ret = statGetKvHeader(kv_header, kv_id, stat);
        spin_unlock(&kv_header->lock);
    }

    return ret;
}

uint64_t KvsStatOperations::statGetSum(kvs_stat_attr_t attr) {
    struct avl_node *a;
    struct kvs_node *node;
    KvsHeader *kv_header = file->getKVHeader_UNLOCKED();

    uint64_t ret = 0;
    file->acquireSpinLock();
    if (attr == KVS_STAT_DATASIZE) {
        ret += file->accessHeader()->stat.datasize;
    } else if (attr == KVS_STAT_NDOCS) {
        ret += file->accessHeader()->stat.ndocs;
    } else if (attr == KVS_STAT_NDELETES) {
        ret += file->accessHeader()->stat.ndeletes;
    } else if (attr == KVS_STAT_NLIVENODES) {
        ret += file->accessHeader()->stat.nlivenodes;
    } else if (attr == KVS_STAT_WAL_NDELETES) {
        ret += file->accessHeader()->stat.wal_ndeletes;
    } else if (attr == KVS_STAT_WAL_NDOCS) {
        ret += file->accessHeader()->stat.wal_ndocs;
    } else if (attr == KVS_STAT_DELTASIZE) {
        ret += file->accessHeader()->stat.deltasize;
    }
    file->releaseSpinLock();

    if (kv_header) {
        spin_lock(&kv_header->lock);
        a = avl_first(kv_header->idx_id);
        while (a) {
            node = _get_entry(a, struct kvs_node, avl_id);
            a = avl_next(&node->avl_id);

            if (attr == KVS_STAT_DATASIZE) {
                ret += node->stat.datasize;
            } else if (attr == KVS_STAT_NDOCS) {
                ret += node->stat.ndocs;
            } else if (attr == KVS_STAT_NDELETES) {
                ret += node->stat.ndeletes;
            } else if (attr == KVS_STAT_NLIVENODES) {
                ret += node->stat.nlivenodes;
            } else if (attr == KVS_STAT_WAL_NDELETES) {
                ret += node->stat.wal_ndeletes;
            } else if (attr == KVS_STAT_WAL_NDOCS) {
                ret += node->stat.wal_ndocs;
            } else if (attr == KVS_STAT_DELTASIZE) {
                ret += node->stat.deltasize;
            }
        }
        spin_unlock(&kv_header->lock);
    }

    return ret;
}

int KvsStatOperations::opsStatGetKvHeader(KvsHeader *kv_header,
                                          fdb_kvs_id_t kv_id,
                                          KvsOpsStat *stat) {
    int ret = 0;
    struct avl_node *a;
    struct kvs_node query, *node;

    query.id = kv_id;
    a = avl_search(kv_header->idx_id, &query.avl_id, _kvs_stat_cmp);
    if (a) {
        node = _get_entry(a, struct kvs_node, avl_id);
        *stat = node->op_stat;
    } else {
        ret = -1;
    }
    return ret;
}

int KvsStatOperations::opsStatGet(fdb_kvs_id_t kv_id,
                                  KvsOpsStat *stat) {
    int ret = 0;

    if (kv_id == 0) {
        file->acquireSpinLock();
        *stat = file->accessHeader()->op_stat;
        file->releaseSpinLock();
    } else {
        KvsHeader *kv_header = file->getKVHeader_UNLOCKED();

        spin_lock(&kv_header->lock);
        ret = opsStatGetKvHeader(kv_header, kv_id, stat);
        spin_unlock(&kv_header->lock);
    }

    return ret;
}

KvsOpsStat* KvsStatOperations::getOpsStats(KvsInfo *kvs) {
    KvsOpsStat *stat = NULL;
    if (!kvs || (kvs && kvs->getKvsId() == 0)) {
        return &file->accessHeader()->op_stat;
    } else {
        KvsHeader *kv_header = file->getKVHeader_UNLOCKED();
        struct avl_node *a;
        struct kvs_node query, *node;
        spin_lock(&kv_header->lock);
        query.id = kvs->getKvsId();
        a = avl_search(kv_header->idx_id, &query.avl_id, _kvs_stat_cmp);
        if (a) {
            node = _get_entry(a, struct kvs_node, avl_id);
            stat = &node->op_stat;
        }
        spin_unlock(&kv_header->lock);
    }
    return stat;
}

// migrate default kv store stats over to new_file
KvsOpsStat* KvsStatOperations::migrateOpStats(FileMgr *old_file,
                                              FileMgr *new_file) {
    KvsOpsStat *ret = NULL;
    if (new_file == NULL) {
        return NULL;
    }

    old_file->acquireSpinLock();
    new_file->accessHeader()->op_stat = old_file->accessHeader()->op_stat;
    ret = &new_file->accessHeader()->op_stat;
    old_file->releaseSpinLock();
    return ret;
}

#ifdef _LATENCY_STATS
void LatencyStats::init(struct latency_stat *val) {
    val->lat_max = 0;
    val->lat_min = static_cast<uint64_t>(-1);
    val->lat_sum = 0;
    val->lat_num = 0;
}

void LatencyStats::destroy(struct latency_stat *val) {
    (void) val;
}

void LatencyStats::migrate(FileMgr *src, FileMgr *dst) {
    for (int type = 0; type < FDB_LATENCY_NUM_STATS; ++type) {
        dst->latStats[type].lat_min.store(src->latStats[type].lat_min.load(),
                                          std::memory_order_relaxed);
        dst->latStats[type].lat_max.store(src->latStats[type].lat_max.load(),
                                          std::memory_order_relaxed);
        dst->latStats[type].lat_sum.store(src->latStats[type].lat_sum.load(),
                                          std::memory_order_relaxed);
        dst->latStats[type].lat_num.store(src->latStats[type].lat_num.load(),
                                          std::memory_order_relaxed);
    }
}

void LatencyStats::update(FileMgr *file, fdb_latency_stat_type type,
                          uint64_t val) {
    int retry = MAX_STAT_UPDATE_RETRIES;
    do {
        uint64_t lat_max = file->latStats[type].lat_max.load(
                                                    std::memory_order_relaxed);
        if (lat_max < val) {
            if (!file->latStats[type].lat_max.compare_exchange_strong(lat_max,
                                                                      val)) {
                continue;
            }
        }
        break;
    } while (--retry);
    retry = MAX_STAT_UPDATE_RETRIES;
    do {
        uint64_t lat_min = file->latStats[type].lat_min.load(
                                                    std::memory_order_relaxed);
        if (val < lat_min) {
            if (!file->latStats[type].lat_min.compare_exchange_strong(lat_min,
                                                                      val)) {
                continue;
            }
        }
        break;
    } while (--retry);
    file->latStats[type].lat_sum.fetch_add(val, std::memory_order_relaxed);
    file->latStats[type].lat_num++;
#ifdef _PLATFORM_LIB_AVAILABLE
    file->histStats[type].add(val / 1000);
#endif
}

void LatencyStats::get(FileMgr *file, fdb_latency_stat_type type,
                       fdb_latency_stat *stat) {
    uint64_t num = file->latStats[type].lat_num.load(std::memory_order_relaxed);
    if (!num) {
        memset(stat, 0, sizeof(fdb_latency_stat));
        return;
    }
    stat->lat_max = file->latStats[type].lat_max.load(std::memory_order_relaxed);
    stat->lat_min = file->latStats[type].lat_min.load(std::memory_order_relaxed);
    stat->lat_count = num;
    stat->lat_avg = file->latStats[type].lat_sum.load(std::memory_order_relaxed) / num;
}

#ifdef _PLATFORM_LIB_AVAILABLE
void LatencyStats::getHistogram(FileMgr *file,
                                fdb_latency_stat_type type,
                                char **stat,
                                size_t *stat_length) {

    uint64_t num = file->latStats[type].lat_num.load(std::memory_order_relaxed);
    if (!num) {
        *stat = nullptr;
        *stat_length = 0;
        return;
    }
    std::stringstream ss;
    ss << "{";
    for (auto& it : file->histStats[type]) {
        if (it->count()) {
            ss << "(" << it->start() << "µs - " << it->end() << "µs) : ";
            ss << it->count() << "; ";
        } else {
            break;
        }
    }
    ss << "}";
    char *buffer = (char*) malloc(ss.str().length());
    memcpy(buffer, ss.str().c_str(), ss.str().length());
    *stat = buffer;
    *stat_length = ss.str().length();
}
#endif

#ifdef _LATENCY_STATS_DUMP_TO_FILE
static const int _MAX_STATSFILE_LEN = FDB_MAX_FILENAME_LEN + 4;

void LatencyStats::dump(FileMgr *file, ErrLogCallback *log_callback) {
    FILE *lat_file;
    char latency_file_path[_MAX_STATSFILE_LEN];
    strncpy(latency_file_path, file->getFileName(), _MAX_STATSFILE_LEN);
    strncat(latency_file_path, ".lat", _MAX_STATSFILE_LEN);
    lat_file = fopen(latency_file_path, "a");
    if (!lat_file) {
        fdb_status status = FDB_RESULT_OPEN_FAIL;
        const char *msg = "Warning: Unable to open latency stats file '%s'\n";
        fdb_log(log_callback, status, msg, latency_file_path);
        return;
    }
    fprintf(lat_file, "%15.15s  %15.4s %15.3s %15.3s %15.11s\n",
            "latency(µs)    ", "tmin", "avg", "max", "num_samples");
    for (int i = 0; i < FDB_LATENCY_NUM_STATS; ++i) {
        uint64_t num = file->latStats[i].lat_num.load(std::memory_order_relaxed);
        if (!num) {
            continue;
        }
        uint64_t avg = file->latStats[i].lat_sum.load(std::memory_order_relaxed) / num;
        uint64_t min = file->latStats[i].lat_min.load(std::memory_order_relaxed);
        uint64_t max = file->latStats[i].lat_max.load(std::memory_order_relaxed);
        fprintf(lat_file, "%15.15s:%15.10s %15.10s %15.10s %15.10s\n",
                FileMgr::getLatencyStatName(i),
                std::to_string(min).c_str(),
                std::to_string(avg).c_str(),
                std::to_string(max).c_str(),
                std::to_string(num).c_str());

    }

#ifdef _PLATFORM_LIB_AVAILABLE
    fprintf(lat_file, "\n\nHistograms:\n\n");
    for (int i = 0; i < FDB_LATENCY_NUM_STATS; ++i) {
        uint64_t count = file->latStats[i].lat_num.load(std::memory_order_relaxed);
        if (count) {
            fprintf(lat_file, "%s (Total: %" _F64 ")\n"
                              "----------------------------------------\n",
                    FileMgr::getLatencyStatName(i), count);
            for (auto it : file->histStats[i]) {
                if (it->count()) {
                    std::stringstream ss;
                    ss << it->start() << "µs - " << it->end() << "µs";
                    fprintf(lat_file, "%20.20s:%" _F64 " (%.2f%%)\n",
                            ss.str().c_str(),
                            static_cast<uint64_t>(it->count()),
                            (100.0 * it->count() / count));
                }
            }
            fprintf(lat_file, "\n");
        }
    }
#endif

    fflush(lat_file);
    fclose(lat_file);
}
#endif // _LATENCY_STATS_DUMP_TO_FILE
#endif // _LATENCY_STATS

// TODO: All the functions below should be also moved to FileMgr or
// other classes

fdb_seqnum_t _fdb_kvs_get_seqnum(KvsHeader *kv_header,
                                 fdb_kvs_id_t id) {
    fdb_seqnum_t seqnum;
    struct kvs_node query, *node;
    struct avl_node *a;

    spin_lock(&kv_header->lock);
    query.id = id;
    a = avl_search(kv_header->idx_id, &query.avl_id, _kvs_stat_cmp);
    if (a) {
        node = _get_entry(a, struct kvs_node, avl_id);
        seqnum = node->seqnum;
    } else {
        // not existing KV ID.
        // this is necessary for _fdb_restore_wal()
        // not to restore documents in deleted KV store.
        seqnum = 0;
    }
    spin_unlock(&kv_header->lock);

    return seqnum;
}

fdb_seqnum_t fdb_kvs_get_seqnum(FileMgr *file,
                                fdb_kvs_id_t id) {
    if (id == 0) {
        // default KV instance
        return file->getSeqnum();
    }

    return _fdb_kvs_get_seqnum(file->getKVHeader_UNLOCKED(), id);
}

void buf2kvid(size_t chunksize, void *buf, fdb_kvs_id_t *id) {
    size_t size_id = sizeof(fdb_kvs_id_t);
    fdb_kvs_id_t temp;

    if (chunksize == size_id) {
        temp = *((fdb_kvs_id_t*)buf);
    } else if (chunksize < size_id) {
        temp = 0;
        memcpy((uint8_t*)&temp + (size_id - chunksize), buf, chunksize);
    } else { // chunksize > sizeof(fdb_kvs_id_t)
        memcpy(&temp, (uint8_t*)buf + (chunksize - size_id), size_id);
    }
    *id = _endian_decode(temp);
}

void kvid2buf(size_t chunksize, fdb_kvs_id_t id, void *buf)
{
    size_t size_id = sizeof(fdb_kvs_id_t);
    id = _endian_encode(id);

    if (chunksize == size_id) {
        memcpy(buf, &id, size_id);
    } else if (chunksize < size_id) {
        memcpy(buf, (uint8_t*)&id + (size_id - chunksize), chunksize);
    } else { // chunksize > sizeof(fdb_kvs_id_t)
        memset(buf, 0x0, chunksize - size_id);
        memcpy((uint8_t*)buf + (chunksize - size_id), &id, size_id);
    }
}

void buf2buf(size_t chunksize_src, void *buf_src,
             size_t chunksize_dst, void *buf_dst)
{
    if (chunksize_dst == chunksize_src) {
        memcpy(buf_dst, buf_src, chunksize_src);
    } else if (chunksize_dst < chunksize_src) {
        memcpy(buf_dst, (uint8_t*)buf_src + (chunksize_src - chunksize_dst),
               chunksize_dst);
    } else { // chunksize_dst > chunksize_src
        memset(buf_dst, 0x0, chunksize_dst - chunksize_src);
        memcpy((uint8_t*)buf_dst + (chunksize_dst - chunksize_src),
               buf_src, chunksize_src);
    }
}

fdb_status convert_errno_to_fdb_status(int errno_value,
                                       fdb_status default_status)
{
    switch (errno_value) {
    case EACCES:
        return FDB_RESULT_EACCESS;
    case EEXIST:
        return FDB_RESULT_EEXIST;
    case EFAULT:
        return FDB_RESULT_EFAULT;
    case EFBIG:
        return FDB_RESULT_EFBIG;
    case EINVAL:
        return FDB_RESULT_EINVAL;
    case EISDIR:
        return FDB_RESULT_EISDIR;
    case ELOOP:
        return FDB_RESULT_ELOOP;
    case EMFILE:
        return FDB_RESULT_EMFILE;
    case ENAMETOOLONG:
        return FDB_RESULT_ENAMETOOLONG;
    case ENFILE:
        return FDB_RESULT_ENFILE;
    case ENODEV:
        return FDB_RESULT_ENODEV;
    case ENOENT:
        return FDB_RESULT_NO_SUCH_FILE;
    case ENOMEM:
        return FDB_RESULT_ENOMEM;
    case ENOSPC:
        return FDB_RESULT_ENOSPC;
    case ENOTDIR:
        return FDB_RESULT_ENOTDIR;
    case ENXIO:
        return FDB_RESULT_ENXIO;
    case EOPNOTSUPP:
        return FDB_RESULT_EOPNOTSUPP;
    case EOVERFLOW:
        return FDB_RESULT_EOVERFLOW;
    case EPERM:
        return FDB_RESULT_EPERM;
    case EROFS:
        return FDB_RESULT_EROFS;
    case EBADF:
        return FDB_RESULT_EBADF;
    case EIO:
        return FDB_RESULT_EIO;
    case ENOBUFS:
        return FDB_RESULT_ENOBUFS;
    case EAGAIN:
        return FDB_RESULT_EAGAIN;

    default:
        return default_status;
    }
}
