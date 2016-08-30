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

#if defined(WIN32) || defined(_WIN32)
#ifdef _MSC_VER
#define NOMINMAX 1
#include <winsock2.h>
#undef NOMINMAX
#endif // _MSC_VER
#include <windows.h>
#define _last_errno_ GetLastError()
#else
#include <sys/time.h>
#include <dirent.h>
#include <unistd.h>
#define _last_errno_ errno
#endif

#include "libforestdb/forestdb.h"
#include "fdb_engine.h"
#include "fdb_internal.h"
#include "filemgr.h"
#include "avltree.h"
#include "list.h"
#include "common.h"
#include "filemgr_ops.h"
#include "configuration.h"
#include "internal_types.h"
#include "compaction.h"
#include "compactor.h"
#include "wal.h"
#include "memleak.h"
#include "time_utils.h"

#ifdef __DEBUG
#ifndef __DEBUG_CPT
    #undef DBG
    #undef DBGCMD
    #undef DBGSW
    #define DBG(...)
    #define DBGCMD(...)
    #define DBGSW(n, ...)
#endif
#endif

#define COMPACTOR_META_VERSION (1)
#define MAX_FNAMELEN (FDB_MAX_FILENAME_LEN)

std::atomic<CompactionManager *> CompactionManager::instance(nullptr);
std::mutex CompactionManager::instanceMutex;

/**
 * File compaction task entry for daemon compaction
 */
class FileCompactionEntry {
public:
    FileCompactionEntry(const std::string &_filename,
                        FileMgr *_file,
                        fdb_config &_config,
                        ErrLogCallback *_log_callback,
                        struct timeval _last_compaction_timestamp,
                        size_t _interval,
                        size_t _register_count,
                        bool _compaction_flag,
                        bool _daemon_compact_in_progress,
                        bool _removal_activated) :
        filename(_filename), file(_file), config(_config), logCallback(_log_callback),
        lastCompactionTimestamp(_last_compaction_timestamp), interval(_interval),
        registerCount(_register_count), compactionFlag(_compaction_flag),
        daemonCompactInProgress(_daemon_compact_in_progress),
        removalActivated(_removal_activated) { }

    const std::string& getFileName() const {
        return filename;
    }

    void setFileName(const std::string &_filename) {
        filename = _filename;
    }

    FileMgr* getFileManager() const {
        return file;
    }

    void setFileManager(FileMgr *_file) {
        file = _file;
    }

    fdb_config& getFdbConfig() {
        return config;
    }

    void setCleanupCacheOnClose(bool cleanup) {
        config.cleanup_cache_onclose = cleanup;
    }

    void setCompactionThreshold (size_t threshold) {
        config.compaction_threshold = threshold;
    }

    ErrLogCallback* getLogCallback() const {
        return logCallback;
    }

    struct timeval getLastCompactionTimestamp() const {
        return lastCompactionTimestamp;
    }

    void setLastCompactionTimestamp(struct timeval &timestamp) {
        lastCompactionTimestamp = timestamp;
    }

    size_t getCompactionInterval() const {
        return interval;
    }

    void setCompactionInterval(size_t _interval) {
        interval = _interval;
    }

    uint32_t getRegisterCount() const {
        return registerCount;
    }

    void setRegisterCount(uint32_t count) {
        registerCount = count;
    }

    uint32_t incrRegisterCount() {
        return ++registerCount;
    }

    uint32_t decrRegisterCount() {
        return --registerCount;
    }

    bool getCompactionFlag() const {
        return compactionFlag;
    }

    void setCompactionFlag(bool flag) {
        compactionFlag = flag;
    }

    bool isDaemonCompactRunning() const {
        return daemonCompactInProgress;
    }

    void setDaemonCompactRunning(bool in_progress) {
        daemonCompactInProgress = in_progress;
    }

    bool isFileRemovalActivated() const {
        return removalActivated;
    }

    void setFileRemovalActivated(bool removal_activated) {
        removalActivated = removal_activated;
    }

    bool isCompactionThresholdSatisfied();

private:
    uint64_t estimateActiveSpace();

    std::string filename;
    FileMgr *file;
    fdb_config config;
    ErrLogCallback *logCallback;
    struct timeval lastCompactionTimestamp;
    size_t interval;
    uint32_t registerCount;
    bool compactionFlag; // set when the file is being compacted
    bool daemonCompactInProgress;
    bool removalActivated;
};

uint64_t FileCompactionEntry::estimateActiveSpace() {
    uint64_t ret = 0;
    uint64_t datasize;
    uint64_t nlivenodes;

    datasize = file->getKvsStatOps()->statGetSum(KVS_STAT_DATASIZE);
    nlivenodes = file->getKvsStatOps()->statGetSum(KVS_STAT_NLIVENODES);

    ret = datasize;
    ret += nlivenodes * config.blocksize;
    ret += file->getWal()->getDataSize_Wal();

    return ret;
}

bool FileCompactionEntry::isCompactionThresholdSatisfied() {
    uint64_t filesize;
    uint64_t active_data;
    int threshold;

    if (compactionFlag || file->isRollbackOn()) {
        // do not perform compaction if the file is already being compacted or
        // in rollback.
        return false;
    }

    struct timeval curr_time, gap;
    gettimeofday(&curr_time, NULL);
    gap = _utime_gap(lastCompactionTimestamp, curr_time);
    uint64_t elapsed_us = (uint64_t)gap.tv_sec * 1000000 + gap.tv_usec;
    if (elapsed_us < (interval * 1000000)) {
        return false;
    }

    threshold = config.compaction_threshold;
    if (config.compaction_mode == FDB_COMPACTION_AUTO &&
        threshold > 0) {
        filesize = file->getPos();
        active_data = estimateActiveSpace();
        if (active_data == 0 || active_data >= filesize ||
            filesize < config.compaction_minimum_filesize) {
            return false;
        }

        return ((filesize / 100.0 * threshold) < (filesize - active_data));
    } else {
        return false;
    }
}

class CompactorThread {
public:
    // Start a thread
    void start();
    // Main function for a thread
    void run();
    // Stop a thread
    void stop();

private:
    thread_t threadId;
};

extern "C" {
    static void* launch_compactor_thread(void *arg) {
        CompactorThread *compactor = (CompactorThread*) arg;
        compactor->run();
        return NULL;
    }
}

void CompactorThread::start() {
    thread_create(&threadId, launch_compactor_thread, (void *)this);
}

void CompactorThread::stop() {
    void *ret;
    thread_join(threadId, &ret);
}

void CompactorThread::run() {
    fdb_file_handle *fhandle;
    fdb_status fs;
    CompactionManager *manager = CompactionManager::getInstance();

    // Sleep for a configured period by default to allow applications to warm up
    // their data.
    // TODO: Need to implement more flexible way of scheduling the compaction
    // daemon (e.g., public APIs to start / stop the compaction daemon).
    {
        UniqueLock lh(manager->syncMutex);
        if (manager->terminateSignal) {
            return;
        }
        manager->syncMutex.wait_for(lh, static_cast<double>(manager->sleepDuration));
    }

    while (true) {
        manager->cptLock.lock();
        auto entry = manager->openFiles.begin();
        while (entry != manager->openFiles.end()) {
            FileCompactionEntry *file_entry = entry->second;
            FileMgr *file = file_entry->getFileManager();
            if (!file) {
                entry = manager->openFiles.erase(entry);
                delete file_entry;
                continue;
            }

            if (file_entry->isCompactionThresholdSatisfied()) {
                file_entry->setDaemonCompactRunning(true);
                // set compaction flag
                file_entry->setCompactionFlag(true);
                // Copy the file name and config as they are accessed after
                // releasing the lock.
                std::string file_name = file_entry->getFileName();
                fdb_config fconfig = file_entry->getFdbConfig();
                manager->cptLock.unlock();

                std::string vfilename = manager->getVirtualFileName(file_name);
                // Get the list of custom compare functions.
                struct list cmp_func_list;
                list_init(&cmp_func_list);
                fdb_cmp_func_list_from_filemgr(file, &cmp_func_list);
                fs = fdb_open_for_compactor(&fhandle, vfilename.c_str(),
                                            &fconfig,
                                            &cmp_func_list);
                fdb_free_cmp_func_list(&cmp_func_list);

                if (fs == FDB_RESULT_SUCCESS) {
                    std::string new_filename = manager->getNextFileName(file_name);
                    Compaction::compactFile(fhandle, new_filename.c_str(), false,
                                            (bid_t) -1, false, NULL);
                    fdb_close(fhandle);

                    manager->cptLock.lock();
                    // Search the next file for compaction.
                    entry = manager->openFiles.upper_bound(new_filename);
                } else {
                    // As a workaround for MB-17009, call fprintf instead of fdb_log
                    // until c->cgo->go callback trace issue is resolved.
                    fprintf(stderr,
                            "Error status code: %d, Failed to open the file "
                            "'%s' for auto daemon compaction.\n",
                            fs, vfilename.c_str());
                    // fail to open file
                    manager->cptLock.lock();
                    // As cptLock was released and grabbed again in the above,
                    // the iterator entry should be refreshed again in case other
                    // threads modified the map structure between them.
                    entry = manager->openFiles.find(file_name);
                    if (entry != manager->openFiles.end()) {
                        file_entry = entry->second;
                        file_entry->setDaemonCompactRunning(false);
                        // clear compaction flag
                        file_entry->setCompactionFlag(false);
                    }
                    // Get the next file for compaction.
                    entry = manager->openFiles.upper_bound(file_name);
                }

            } else if (manager->checkFileRemoval(file_entry)) {
                // remove file
                int ret;

                // set activation flag to prevent other compactor threads attempting
                // to remove the same file and double free the file_entry instance,
                // during 'cpt_lock' is released.
                file_entry->setFileRemovalActivated(true);
                // Copy the file name and log callback as they are accessed after
                // releasing the lock.
                std::string file_name = file_entry->getFileName();
                ErrLogCallback* log_callback = file_entry->getLogCallback();
                manager->cptLock.unlock();

                // As the file is already unlinked, just close it.
                ret = FileMgr::fileClose(file->getOps(),
                                         file->getFopsHandle());
#if defined(WIN32) || defined(_WIN32)
                // For Windows, we need to manually remove the file.
                ret = remove(file->getFileName());
#endif
                file->removeAllBufferBlocks();
                manager->cptLock.lock();

                if (log_callback && ret != 0) {
                    char errno_msg[512];
                    file->getOps()->get_errno_str(file->getFopsHandle(), errno_msg, 512);

                    if (_last_errno_ == ENOENT) {
                        // Ignore 'No such file or directory' error as the file
                        // must've been removed already
                    } else {
                        // As a workaround for MB-17009, call fprintf instead of fdb_log
                        // until c->cgo->go callback trace issue is resolved.
                        fprintf(stderr,
                                "Error status code: %d, Error in REMOVE on a "
                                "database file '%s', %s",
                                ret, file->getFileName(), errno_msg);
                    }
                }

                // free filemgr structure
                FileMgr::freeFunc(file);
                // As cptLock was released and grabbed again in the above,
                // the iterator entry should be refreshed again in case other
                // threads modified the map structure between them.
                entry = manager->openFiles.find(file_name);
                if (entry != manager->openFiles.end()) {
                    file_entry = entry->second;
                    // remove & free elem
                    entry = manager->openFiles.erase(entry);
                    delete file_entry;
                }
            } else {
                // Get the next file for compaction
                ++entry;
            }
            if (manager->terminateSignal) {
                manager->cptLock.unlock();
                return;
            }
        }
        manager->cptLock.unlock();

        {
            UniqueLock lh(manager->syncMutex);
            if (manager->terminateSignal) {
                break;
            }
            // As each database file can be opened at different times, we need to
            // wake up each compaction thread with a shorter interval to check if
            // the time since the last compaction of a given file is already passed
            // by a configured compaction interval and consequently the file should
            // be compacted or not.
            manager->syncMutex.wait_for(lh, static_cast<double>(15)); // Wait for 15 secs
            if (manager->terminateSignal) {
                break;
            }
        }
    }
}

struct compactor_meta {
    uint32_t version;
    char filename[MAX_FNAMELEN];
    uint32_t crc;
};

#if !defined(WIN32) && !defined(_WIN32)
static bool does_file_exist(const char *filename) {
    struct stat st;
    int result = stat(filename, &st);
    return result == 0;
}
#else
static bool does_file_exist(const char *filename) {
    return GetFileAttributes(filename) != INVALID_FILE_ATTRIBUTES;
}
#endif

bool CompactionManager::checkFileRemoval(FileCompactionEntry *entry) {
    if (entry->getFileManager()->getFlags() & FILEMGR_REMOVAL_IN_PROG &&
        !entry->isFileRemovalActivated()) {
        return true;
    }
    return false;
}

bool compactor_is_file_removed(const char *filename) {
    std::string file_name(filename);
    return CompactionManager::getInstance()->isFileRemoved(file_name);
}

bool CompactionManager::isFileRemoved(const std::string &filename) {
    LockHolder lock(cptLock);
    if (openFiles.find(filename) != openFiles.end()) {
        // exist .. old file is not removed yet
        return false;
    }
    return true;
}

// return the location of '.'
INLINE int _compactor_prefix_len(const char *filename)
{
    int i;
    int file_len = strlen(filename);
    int prefix_len = 0;
    // find the first '.'
    for (i=file_len-1; i>=0; --i){
        if (filename[i] == '.') {
            prefix_len = i+1;
            break;
        }
    }
    return prefix_len;
}

// return the the location of '/' or '\'
INLINE int _compactor_dir_len(const char *filename)
{
    int i;
    int file_len = strlen(filename);
    int dir_len = 0;
    // find the first '/' or '\'
    for (i=file_len-1; i>=0; --i){
        if (filename[i] == '/' || filename[i] == '\\') {
            dir_len = i+1;
            break;
        }
    }
    return dir_len;
}

// copy from 'foo/bar.baz' to 'bar.baz'
static void _strcpy_fname(char *dst, const char *src)
{
    int dir_len = _compactor_dir_len(src);
    strcpy(dst, src + dir_len);
}

// copy from 'foo/bar.baz' to 'foo/' (including '/')
static void _strcpy_dirname(char *dst, const char *src)
{
    int dir_len = _compactor_dir_len(src);
    if (dir_len) {
        strncpy(dst, src, dir_len);
    }
    // set NULL char
    dst[dir_len] = 0;
}

// <example>
// fname: 'foo.bar'
// path: 'tmp/dir/other.file'
// returned dst: 'tmp/dir/foo.bar'
static void _reconstruct_path(char *dst, const char *path, const char *fname)
{
    _strcpy_dirname(dst, path);
    strcat(dst + strlen(dst), fname);
}

static void _compactor_convert_dbfile_to_metafile(const char *dbfile, char *metafile)
{
    int prefix_len = _compactor_prefix_len(dbfile);

    if (prefix_len > 0) {
        strncpy(metafile, dbfile, prefix_len);
        metafile[prefix_len] = 0;
        strcat(metafile, "meta");
    }
}

static bool _allDigit(const char *str) {
    int numchar = strlen(str);
    for(int i = 0; i < numchar; ++i) {
        if (str[i] < '0' || str[i] > '9') {
            return false;
        }
    }
    return true;
}

std::string CompactionManager::getNextFileName(const std::string &filename) {
    int compaction_no = 0;
    int prefix_len = _compactor_prefix_len(filename.c_str());
    char str_no[24];
    char nextfile[MAX_FNAMELEN];

    if (prefix_len > 0 && _allDigit(filename.c_str() + prefix_len)) {
        sscanf(filename.c_str() + prefix_len, "%d", &compaction_no);
        strncpy(nextfile, filename.c_str(), prefix_len);
        do {
            nextfile[prefix_len] = 0;
            sprintf(str_no, "%d", ++compaction_no);
            strcat(nextfile, str_no);
        } while (does_file_exist(nextfile));
    } else {
        do {
            strcpy(nextfile, filename.c_str());
            sprintf(str_no, ".%d", ++compaction_no);
            strcat(nextfile, str_no);
        } while (does_file_exist(nextfile));
    }
    return std::string(nextfile);
}

bool CompactionManager::switchCompactionFlag(FileMgr *file, bool flag) {
    LockHolder lock(cptLock);
    auto iter = openFiles.find(std::string(file->getFileName()));
    if (iter != openFiles.end()) {
        // found
        FileCompactionEntry *entry = iter->second;
        if (entry->getCompactionFlag() == flag) {
            // already switched by other thread .. return false
            return false;
        }
        // switch
        entry->setCompactionFlag(flag);
        return true;
    }
    // file doesn't exist .. already compacted or deregistered
    return false;
}

CompactionManager::CompactionManager(const struct compactor_config &config) :
    numThreads(config.num_threads), sleepDuration(config.sleep_duration),
    terminateSignal(0) { }

void CompactionManager::spawnCompactorThreads() {
     // create worker threads
    for (size_t i = 0; i < numThreads; ++i) {
        CompactorThread *thread = new CompactorThread();
        compactorThreads.push_back(thread);
        thread->start();
    }
}

CompactionManager* CompactionManager::init(const struct compactor_config &config) {
    CompactionManager* tmp = instance.load();
    if (tmp == nullptr) {
        // Ensure two threads don't both create an instance.
        LockHolder lock(instanceMutex);
        tmp = instance.load();
        if (tmp == nullptr) {
            tmp = new CompactionManager(config);
            instance.store(tmp);
            tmp->spawnCompactorThreads();
        }
    }
    return tmp;
}

CompactionManager* CompactionManager::getInstance() {
    CompactionManager* compaction_manager = instance.load();
    if (compaction_manager == nullptr) {
        // Create the compaction manager with default configs.
        struct compactor_config config =
            {FDB_COMPACTOR_SLEEP_DURATION, DEFAULT_NUM_COMPACTOR_THREADS};
        return init(config);
    }
    return compaction_manager;
}

void CompactionManager::destroyInstance() {
    LockHolder lock(instanceMutex);
    CompactionManager* tmp = instance.load();
    if (tmp != nullptr) {
        delete tmp;
        instance = nullptr;
    }
}

CompactionManager::~CompactionManager() {
    // set terminate signal
    syncMutex.lock();
    terminateSignal.store(1);
    syncMutex.notify_all();
    syncMutex.unlock();

    for (auto &thread : compactorThreads) {
        thread->stop();
        delete thread;
    }

    LockHolder lock(cptLock);
    // Free all elements in the compaction file list
    for (auto &entry : openFiles) {
        FileCompactionEntry *file_entry = entry.second;
        if (checkFileRemoval(file_entry)) {
            // remove file if removal is pended.
            remove(file_entry->getFileName().c_str());
            FileMgr::freeFunc(file_entry->getFileManager());
        }
        delete file_entry;
    }
}

fdb_status CompactionManager::registerFile(FileMgr *file,
                                           fdb_config *config,
                                           ErrLogCallback *log_callback) {
    file_status_t fstatus;
    fdb_status fs = FDB_RESULT_SUCCESS;

    // Ignore files whose status is COMPACT_OLD or REMOVED_PENDING.
    // Those files do not need to be compacted again.
    fstatus = file->getFileStatus();
    if (fstatus == FILE_COMPACT_OLD ||
        fstatus == FILE_REMOVED_PENDING) {
        return fs;
    }

    // Firstly, search the existing file.
    std::string filename(file->getFileName());
    cptLock.lock();
    auto entry = openFiles.find(filename);
    if (entry == openFiles.end()) {
        // doesn't exist
        // create a file compaction entry and insert it into the file list
        struct timeval timestamp;

        gettimeofday(&timestamp, NULL);
        FileCompactionEntry *file_entry =
            new FileCompactionEntry(filename, file,
                                    *config, log_callback,
                                    timestamp,
                                    sleepDuration, 1 /* register count */,
                                    false /* compaction flag*/,
                                    false /* daemon compaction in progress */,
                                    false /* removal activated */);
        file_entry->setCleanupCacheOnClose(false); // prevent MB-16422
        openFiles.insert(std::make_pair(file_entry->getFileName(), file_entry));

        cptLock.unlock(); // Releasing the lock here should be OK as
                          // subsequent registration attempts for the same file
                          // will be simply processed by incrementing its
                          // counter below.

        // store in metafile
        fs = storeMetaFile(filename, log_callback);
    } else {
        // already exists
        FileCompactionEntry *file_entry = entry->second;
        if (!file_entry->getFileManager()) {
            file_entry->setFileManager(file);
        }
        file_entry->incrRegisterCount();
        cptLock.unlock();
    }
    return fs;
}

void CompactionManager::deregisterFile(FileMgr *file) {
    LockHolder lock(cptLock);
    auto entry = openFiles.find(std::string(file->getFileName()));
    if (entry != openFiles.end()) {
        FileCompactionEntry *file_entry = entry->second;
        if (file_entry->decrRegisterCount() == 0) {
            // if no handle refers this file
            if (file_entry->isDaemonCompactRunning()) {
                // This file is waiting for compaction by compactor (but not opened
                // yet). Do not remove 'file_entry' for now. The 'file_entry' will be
                // automatically replaced after the compaction is done by calling
                // 'switchFile()'. However, file_entry->file should be set to NULL
                // in order to be removed from the compaction file list in case of
                // the compaction failure.
                file_entry->setFileManager(NULL);
            } else {
                // remove from the compaction file list
                openFiles.erase(entry);
                delete file_entry;
            }
        }
    }
}

fdb_status compactor_register_file_removing(FileMgr *file,
                                            ErrLogCallback *log_callback) {
    return CompactionManager::getInstance()->registerFileRemoval(file, log_callback);
}

fdb_status CompactionManager::registerFileRemoval(FileMgr *file,
                                                  ErrLogCallback *log_callback) {
    fdb_status fs = FDB_RESULT_SUCCESS;

    // first search the existing file
    std::string filename(file->getFileName());
    cptLock.lock();
    auto entry = openFiles.find(filename);
    if (entry == openFiles.end()) {
        // doesn't exist
        // create a fake & temporary element for the file to be removed.
        struct timeval timestamp;
        fdb_config config;

        gettimeofday(&timestamp, NULL);
        FileCompactionEntry *file_entry =
            new FileCompactionEntry(filename, file,
                                    config, log_callback,
                                    timestamp,
                                    sleepDuration, 1 /* register count */,
                                    // To prevent this file from being compacted,
                                    // set compaction-related flags to true
                                    true /* compaction flag*/,
                                    true /* daemon compaction in progress */,
                                    false /* removal activated */);
        // set flag
        file->addToFlags(FILEMGR_REMOVAL_IN_PROG);
        openFiles.insert(std::make_pair(file_entry->getFileName(), file_entry));

        cptLock.unlock(); // Releasing the lock here should be OK as
                          // subsequent registration attempts for the same file
                          // will be simply processed by incrementing its
                          // counter below.

        // wake up any sleeping thread
        syncMutex.lock();
        syncMutex.notify_one();
        syncMutex.unlock();

    } else {
        // already exists .. just ignore
        cptLock.unlock();
    }
    return fs;
}

void CompactionManager::setCompactionThreshold(FileMgr *file,
                                               size_t new_threshold) {
    LockHolder lock(cptLock);
    auto entry = openFiles.find(std::string(file->getFileName()));
    if (entry != openFiles.end()) {
        FileCompactionEntry *file_entry = entry->second;
        file_entry->setCompactionThreshold(new_threshold);
    }
}

fdb_status CompactionManager::setCompactionInterval(FileMgr *file,
                                                    size_t interval) {
    fdb_status result = FDB_RESULT_SUCCESS;

    LockHolder lock(cptLock);
    auto entry = openFiles.find(std::string(file->getFileName()));
    if (entry != openFiles.end()) {
        FileCompactionEntry *file_entry = entry->second;
        file_entry->setCompactionInterval(interval);
    } else {
        result = FDB_RESULT_INVALID_ARGS;
    }
    return result;
}

struct compactor_meta* CompactionManager::readMetaFile(const char *metafile,
                                                       struct compactor_meta *metadata,
                                                       ErrLogCallback *log_callback) {
    ssize_t ret;
    uint8_t buf[sizeof(struct compactor_meta)];
    uint32_t crc;
    char fullpath[MAX_FNAMELEN];
    struct filemgr_ops *ops;
    struct compactor_meta meta;
    fdb_fileops_handle fops_meta_handle, fops_db_handle;

    ops = get_filemgr_ops();
    fdb_status status = FileMgr::fileOpen(metafile, ops, &fops_meta_handle,
                                          O_RDONLY, 0644);

    if (status == FDB_RESULT_SUCCESS) {
        // metafile exists .. read metadata
        ret = ops->pread(fops_meta_handle, buf, sizeof(struct compactor_meta), 0);
        if (ret < 0 || (size_t)ret < sizeof(struct compactor_meta)) {
            char errno_msg[512];
            ops->get_errno_str(fops_meta_handle, errno_msg, 512);
            // As a workaround for MB-17009, call fprintf instead of fdb_log
            // until c->cgo->go callback trace issue is resolved.
            fprintf(stderr,
                    "Error status code: %d, Failed to read the meta file '%s', "
                    "errno_message: %s\n",
                    (int)ret, metafile, errno_msg);
            FileMgr::fileClose(ops, fops_meta_handle);
            return NULL;
        }
        memcpy(&meta, buf, sizeof(struct compactor_meta));
        meta.version = _endian_decode(meta.version);
        meta.crc = _endian_decode(meta.crc);
        FileMgr::fileClose(ops, fops_meta_handle);

        // CRC check, mode UNKNOWN means all modes are checked.
        if (!perform_integrity_check(buf,
                                     sizeof(struct compactor_meta) - sizeof(crc),
                                     meta.crc,
                                     CRC_UNKNOWN)) {
            fprintf(stderr,
                    "Error status code: %d, Checksum mismatch in the meta file '%s'\n",
                    FDB_RESULT_CHECKSUM_ERROR, metafile);
            return NULL;
        }
        // check if the file exists
        _reconstruct_path(fullpath, metafile, meta.filename);
        status = FileMgr::fileOpen(fullpath, ops, &fops_db_handle, O_RDONLY,
                                   0644);

        if (status != FDB_RESULT_SUCCESS) {
            return NULL;
        }
        FileMgr::fileClose(ops, fops_db_handle);
    } else {
        // file doesn't exist
        return NULL;
    }

    *metadata = meta;
    return metadata;
}

fdb_status CompactionManager::storeMetaFile(const std::string &filename,
                                            ErrLogCallback*log_callback) {
    ssize_t ret;
    uint32_t crc;
    struct filemgr_ops *ops;

    char metafile[MAX_FNAMELEN];
    struct compactor_meta meta;
    fdb_fileops_handle fileops_meta;

    _compactor_convert_dbfile_to_metafile(filename.c_str(), metafile);
    _strcpy_fname(meta.filename, filename.c_str());

    ops = get_filemgr_ops();
    fdb_status status = FileMgr::fileOpen(metafile, ops, &fileops_meta,
                                          O_RDWR | O_CREAT, 0644);

    if (status == FDB_RESULT_SUCCESS) {
        meta.version = _endian_encode(COMPACTOR_META_VERSION);
        crc = get_checksum(reinterpret_cast<const uint8_t*>(&meta),
                           sizeof(struct compactor_meta) - sizeof(crc));
        meta.crc = _endian_encode(crc);

        char errno_msg[512];
        ret = ops->pwrite(fileops_meta, &meta, sizeof(struct compactor_meta), 0);
        if (ret < 0 || (size_t)ret < sizeof(struct compactor_meta)) {
            ops->get_errno_str(fileops_meta, errno_msg, 512);
            // As a workaround for MB-17009, call fprintf instead of fdb_log
            // until c->cgo->go callback trace issue is resolved.
            fprintf(stderr,
                    "Error status code: %d, Failed to perform a write in the meta "
                    "file '%s', errno_message: %s\n",
                    (int)ret, metafile, errno_msg);
            FileMgr::fileClose(ops, fileops_meta);
            return (fdb_status) ret;
        }
        ret = ops->fsync(fileops_meta);
        if (ret < 0) {
            ops->get_errno_str(fileops_meta, errno_msg, 512);
            fprintf(stderr,
                    "Error status code: %d, Failed to perform a sync in the meta "
                    "file '%s', errno_message: %s\n",
                    (int)ret, metafile, errno_msg);
            FileMgr::fileClose(ops, fileops_meta);
            return (fdb_status) ret;
        }
        FileMgr::fileClose(ops, fileops_meta);
    } else {
        return FDB_RESULT_OPEN_FAIL;
    }

    return FDB_RESULT_SUCCESS;
}

void CompactionManager::switchFile(FileMgr *old_file,
                                   FileMgr *new_file,
                                   ErrLogCallback *log_callback) {

    std::string old_filename(old_file->getFileName());

    cptLock.lock();
    auto entry = openFiles.find(old_filename);
    if (entry != openFiles.end()) {
        fdb_compaction_mode_t comp_mode;
        std::string new_filename(new_file->getFileName());
        FileCompactionEntry *file_entry = entry->second;

        openFiles.erase(entry);
        file_entry->setFileName(new_filename);
        file_entry->setFileManager(new_file);
        file_entry->setRegisterCount(1);
        file_entry->setDaemonCompactRunning(false);
        // clear compaction flag
        file_entry->setCompactionFlag(false);
        // As this function is invoked at the end of compaction, set the compaction
        // timestamp to the current time.
        struct timeval timestamp;
        gettimeofday(&timestamp, NULL);
        file_entry->setLastCompactionTimestamp(timestamp);

        openFiles.insert(std::make_pair(file_entry->getFileName(), file_entry));
        comp_mode = file_entry->getFdbConfig().compaction_mode;

        cptLock.unlock(); // Releasing the lock here should be OK as we don't
                          // expect more than one compaction task completion for
                          // the same file.

        if (comp_mode == FDB_COMPACTION_AUTO) {
            storeMetaFile(new_filename, log_callback);
        }
    } else {
        cptLock.unlock();
    }
}

std::string CompactionManager::getVirtualFileName(const std::string &filename) {
    int prefix_len = _compactor_prefix_len(filename.c_str()) - 1;
    if (prefix_len > 0) {
        return std::string(filename, 0, prefix_len);
    } else {
        return std::string(filename);
    }
}

std::string CompactionManager::getActualFileName(const std::string &filename,
                                                 fdb_compaction_mode_t comp_mode,
                                                 ErrLogCallback *log_callback) {
    size_t filename_len;
    size_t dirname_len;
    int compaction_no, max_compaction_no = -1;
    char path[MAX_FNAMELEN];
    char dirname[MAX_FNAMELEN], prefix[MAX_FNAMELEN];
    char ret_name[MAX_FNAMELEN];
    struct compactor_meta meta, *meta_ptr;

    // get actual filename from metafile
    sprintf(path, "%s.meta", filename.c_str());
    meta_ptr = readMetaFile(path, &meta, log_callback);

    if (meta_ptr == NULL) {
        if (comp_mode == FDB_COMPACTION_MANUAL && does_file_exist(filename.c_str())) {
            return filename;
        }

        // error handling .. scan directory
        // backward search until find the first '/' or '\' (Windows)
        filename_len = filename.length();
        dirname_len = 0;

#if !defined(WIN32) && !defined(_WIN32)
        DIR *dir_info;
        struct dirent *dir_entry;

        for (int i = static_cast<int>(filename_len-1); i >= 0; --i){
            if (filename[i] == '/') {
                dirname_len = i+1;
                break;
            }
        }

        if (dirname_len > 0) {
            strncpy(dirname, filename.c_str(), dirname_len);
            dirname[dirname_len] = 0;
        } else {
            strcpy(dirname, ".");
        }
        strcpy(prefix, filename.c_str() + dirname_len);
        strcat(prefix, ".");

        dir_info = opendir(dirname);
        if (dir_info != NULL) {
            while ((dir_entry = readdir(dir_info))) {
                if (!strncmp(dir_entry->d_name, prefix, strlen(prefix))) {
                    compaction_no = -1;
                    sscanf(dir_entry->d_name + strlen(prefix), "%d", &compaction_no);
                    if (compaction_no >= 0) {
                        if (compaction_no > max_compaction_no) {
                            max_compaction_no = compaction_no;
                        }
                    }
                }
            }
            closedir(dir_info);
        }
#else
        // Windows
        for (int i = static_cast<int>(filename_len-1); i >= 0; --i){
            if (filename[i] == '/' || filename[i] == '\\') {
                dirname_len = i+1;
                break;
            }
        }

        if (dirname_len > 0) {
            strncpy(dirname, filename.c_str(), dirname_len);
            dirname[dirname_len] = 0;
        } else {
            strcpy(dirname, ".");
        }
        strcpy(prefix, filename.c_str() + dirname_len);
        strcat(prefix, ".");

        WIN32_FIND_DATA filedata;
        HANDLE hfind;
        char query_str[MAX_FNAMELEN];

        // find all files start with 'prefix'
        sprintf(query_str, "%s*", prefix);
        hfind = FindFirstFile(query_str, &filedata);
        while (hfind != INVALID_HANDLE_VALUE) {
            if (!strncmp(filedata.cFileName, prefix, strlen(prefix))) {
                compaction_no = -1;
                sscanf(filedata.cFileName + strlen(prefix), "%d", &compaction_no);
                if (compaction_no >= 0) {
                    if (compaction_no > max_compaction_no) {
                        max_compaction_no = compaction_no;
                    }
                }
            }

            if (!FindNextFile(hfind, &filedata)) {
                FindClose(hfind);
                hfind = INVALID_HANDLE_VALUE;
            }
        }

#endif

        if (max_compaction_no < 0) {
            if (comp_mode == FDB_COMPACTION_AUTO) {
                // DB files with a revision number are not found.
                // initialize filename to '[filename].0'
                sprintf(ret_name, "%s.0", filename.c_str());
            } else { // Manual compaction mode.
                // Simply use the file name passed to this function.
                return filename;
            }
        } else {
            // return the file that has the largest compaction number
            sprintf(ret_name, "%s.%d", filename.c_str(), max_compaction_no);
        }
        return std::string(ret_name);
    } else {
        // metadata is successfully read from the metafile .. just return the filename
        _reconstruct_path(ret_name, (char*)filename.c_str(), meta.filename);
        return std::string(ret_name);
    }
}

bool CompactionManager::isValidCompactionMode(const std::string &filename,
                                              const fdb_config &config) {
    fdb_fileops_handle fileops_handle;
    struct filemgr_ops *ops;
    fdb_status status;

    ops = get_filemgr_ops();

    if (config.compaction_mode == FDB_COMPACTION_AUTO) {
        // auto compaction mode: invalid when
        // the file '[filename]' exists
        fdb_status status = FileMgr::fileOpen(filename.c_str(), ops, &fileops_handle,
                                              O_RDONLY, 0644);
        if (status != FDB_RESULT_NO_SUCH_FILE) {
            if (status == FDB_RESULT_SUCCESS) {
                FileMgr::fileClose(ops, fileops_handle);
            }
            return false;
        }

    } else if (config.compaction_mode == FDB_COMPACTION_MANUAL) {
        // manual compaction mode: invalid when
        // the file '[filename].meta' exists
        char path[MAX_FNAMELEN];
        sprintf(path, "%s.meta", filename.c_str());
        status = FileMgr::fileOpen(path, ops, &fileops_handle, O_RDONLY, 0644);
        if (status != FDB_RESULT_NO_SUCH_FILE) {
            if (status == FDB_RESULT_SUCCESS) {
                FileMgr::fileClose(ops, fileops_handle);
            }
            return false;
        }
    } else {
        // unknown mode
        return false;
    }

    return true;
}

fdb_status CompactionManager::searchAndDestroyFiles(const char *filename) {
    int i;
    int filename_len;
    int dirname_len;
    char dirname[MAX_FNAMELEN], prefix[MAX_FNAMELEN];
    char full_fname[MAX_FNAMELEN];
    fdb_status fs = FDB_RESULT_SUCCESS;

    // error handling .. scan directory
    // backward search until find the first '/' or '\' (Windows)
    filename_len = strlen(filename);
    dirname_len = 0;

#if !defined(WIN32) && !defined(_WIN32)
    DIR *dir_info;
    struct dirent *dir_entry;

    for (i=filename_len-1; i>=0; --i){
        if (filename[i] == '/') {
            dirname_len = i+1;
            break;
        }
    }

    if (dirname_len > 0) {
        strncpy(dirname, filename, dirname_len);
        dirname[dirname_len] = 0;
    } else {
        strcpy(dirname, ".");
    }
    strcpy(prefix, filename + dirname_len);
    strcat(prefix, ".");

    dir_info = opendir(dirname);
    if (dir_info != NULL) {
        while ((dir_entry = readdir(dir_info))) {
            if (!strncmp(dir_entry->d_name, prefix, strlen(prefix))) {
                // Need to check filemgr for possible open entry?
                // Reconstruct full path
                _reconstruct_path(full_fname, dirname, dir_entry->d_name);
                if (remove(full_fname)) {
                    fs = FDB_RESULT_FILE_REMOVE_FAIL;
                    closedir(dir_info);
                    return fs;
                }
            }
        }
        closedir(dir_info);
    }
#else
    // Windows
    for (i=filename_len-1; i>=0; --i){
        if (filename[i] == '/' || filename[i] == '\\') {
            dirname_len = i+1;
            break;
        }
    }

    if (dirname_len > 0) {
        strncpy(dirname, filename, dirname_len);
        dirname[dirname_len] = 0;
    } else {
        strcpy(dirname, ".");
    }
    strcpy(prefix, filename + dirname_len);
    strcat(prefix, ".");

    WIN32_FIND_DATA filedata;
    HANDLE hfind;
    char query_str[MAX_FNAMELEN];

    // find all files start with 'prefix'
    sprintf(query_str, "%s.*", filename);
    hfind = FindFirstFile(query_str, &filedata);
    while (hfind != INVALID_HANDLE_VALUE) {
        if (!strncmp(filedata.cFileName, prefix, strlen(prefix))) {
            // Need to check filemgr for possible open entry?
            // Reconstruct full path
            _reconstruct_path(full_fname, dirname, filedata.cFileName);
            if (remove(full_fname)) {
                fs = FDB_RESULT_FILE_REMOVE_FAIL;
                FindClose(hfind);
                hfind = INVALID_HANDLE_VALUE;
                return fs;
            }
        }

        if (!FindNextFile(hfind, &filedata)) {
            FindClose(hfind);
            hfind = INVALID_HANDLE_VALUE;
        }
    }

#endif
    return fs;
}

fdb_status CompactionManager::destroyFile(const std::string &fname_prefix,
                                          const fdb_config &config) {
    size_t strcmp_len;
    fdb_status status = FDB_RESULT_SUCCESS;
    char fname[MAX_FNAMELEN];

    strcpy(fname, fname_prefix.c_str());
    strcmp_len = fname_prefix.length();
    fname[strcmp_len] = '.'; // add '.' suffix in place
    strcmp_len++;
    fname[strcmp_len] = '\0';

    cptLock.lock();
    auto entry = openFiles.lower_bound(std::string(fname));
    if (entry != openFiles.end()) {
        FileCompactionEntry *file_entry = entry->second;
        if (strncmp(fname, file_entry->getFileName().c_str(), strcmp_len) == 0) {
            if (file_entry->isDaemonCompactRunning()) {
                // This file is being compacted by compactor.
                // Return a temporary failure, user must retry after sometime
                status = FDB_RESULT_IN_USE_BY_COMPACTOR;
            } else { // File handle not closed, fail operation
                status = FDB_RESULT_FILE_IS_BUSY;
            }
        }
    }

    cptLock.unlock(); // Releasing the lock here should be OK as file
                      // deletions doesn't require strict synchronization.
    if (status == FDB_RESULT_SUCCESS) {
        status = searchAndDestroyFiles(fname_prefix.c_str());
    }

    return status;
}
