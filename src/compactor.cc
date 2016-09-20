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
#include "executorpool.h"
#include "compactor.h"
#include "globaltask.h"
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

CompactionTask::CompactionTask(CompactionMgrTaskable &e,
                               CompactionManager *compactMgr,
                               FileMgr *file,
                               fdb_config &config) :
        GlobalTask(e, // Instance of owning Taskable (FileMgr)
                   Priority::CompactorPriority, // Task Priority
                   double(config.compactor_sleep_duration),
                   false), // OK to cancel pending tasks on shutdown
        compMgr(compactMgr),
        fileToCompact(file),
        fdbConfig(config),
        sleepTime(double(config.compactor_sleep_duration)),
        compactionFlag(false),
        openHandles(0) {
    desc = "Compact " + e.getName();
    // prevents MB-16422 (deletion of parent file at end of run() method)
    fdbConfig.cleanup_cache_onclose = false;
    snooze(sleepTime); //wait before first run
}

uint64_t CompactionTask::estimateActiveSpace() {
    uint64_t ret = 0;
    uint64_t datasize;
    uint64_t nlivenodes;

    datasize = fileToCompact->getKvsStatOps()->statGetSum(KVS_STAT_DATASIZE);
    nlivenodes = fileToCompact->getKvsStatOps()->statGetSum(KVS_STAT_NLIVENODES);

    ret = datasize;
    ret += nlivenodes * fdbConfig.blocksize;
    ret += fileToCompact->getWal()->getDataSize_Wal();

    return ret;
}

bool CompactionTask::isCompactionThresholdSatisfied() {
    uint64_t filesize;
    uint64_t active_data;
    int threshold;

    if (compactionFlag || fileToCompact->isRollbackOn()) {
        // do not perform compaction if the file is already being compacted or
        // in rollback.
        return false;
    }

    threshold = fdbConfig.compaction_threshold;
    if (fdbConfig.compaction_mode == FDB_COMPACTION_AUTO &&
        threshold > 0) {
        filesize = fileToCompact->getPos();
        active_data = estimateActiveSpace();
        if (active_data == 0 || active_data >= filesize ||
            filesize < fdbConfig.compaction_minimum_filesize) {
            return false;
        }

        return ((filesize / 100.0 * threshold) < (filesize - active_data));
    } else {
        return false;
    }
}

void CompactionTask::setCompactionInterval(size_t newInterval) {
    sleepTime = double(newInterval);
    ExecutorPool::get()->snooze(taskId, sleepTime);
}

bool CompactionTask::run() {
    if (!isCompactionThresholdSatisfied()) {
        snooze(sleepTime);
        return true;
    }

    // set compaction flag
    compactionFlag = true;

    // Copy the file name and config as they are accessed after
    // releasing the lock.
    std::string file_name(fileToCompact->getFileName());

    std::string vfilename = CompactionManager::getVirtualFileName(file_name);
    // Get the list of custom compare functions.
    struct list cmp_func_list;
    fdb_file_handle *fhandle;
    fdb_status fs;

    list_init(&cmp_func_list);
    fdb_cmp_func_list_from_filemgr(fileToCompact, &cmp_func_list);
    fs = fdb_open_for_compactor(&fhandle, vfilename.c_str(),
            &fdbConfig,
            &cmp_func_list);
    fdb_free_cmp_func_list(&cmp_func_list);

    if (fs == FDB_RESULT_SUCCESS) {
        std::string new_filename = CompactionManager::getNextFileName(file_name);
        fs = Compaction::compactFile(fhandle, new_filename.c_str(), false,
                (bid_t) -1, false, NULL);

        fdb_status fs2 = fdb_close(fhandle);
        if (fs2 != FDB_RESULT_SUCCESS) {
            fprintf(stderr, "Error status code %d, Failed to close file %s"
                    " after auto daemon compaction.\n", fs2, vfilename.c_str());
        }
    } else {
        // As a workaround for MB-17009, call fprintf instead of fdb_log
        // until c->cgo->go callback trace issue is resolved.
        fprintf(stderr,
                "Error status code: %d, Failed to open the file "
                "'%s' for auto daemon compaction.\n",
                fs, vfilename.c_str());
        // fail to open file
    }

    // Upon success the compaction task is removed already
    if (fs != FDB_RESULT_SUCCESS) {
        compMgr->removeCompactionTask(file_name);
    }

    // Newly compacted file will have its own compaction task
    return false; // so return false here to end current task
}

FileRemovalTask::FileRemovalTask(CompactionMgrTaskable &e,
                                 FileMgr *file,
                                 ErrLogCallback *log_callback)
    : GlobalTask(e, Priority::FileRemovalPriority, 0, true),
      compMgr(e.getCompactionMgr()),
      fileToRemove(file),
      logCallback(log_callback),
      filename(std::string(file->getFileName()))
{
    desc = "Running file removal task for file: " + filename;
}

bool FileRemovalTask::run() {
    int ret;

    if (compMgr->isPendingCompaction(std::string(fileToRemove->getFileName()))) {
        // Re-schedule in case of a pending compaction on the file
        return true;
    }

    // As the file is already unlinked, just close it
    ret = FileMgr::fileClose(fileToRemove->getOps(),
                             fileToRemove->getFopsHandle());
#if defined(WIN32) || defined(_WIN32)
    // For windows, we need to manually remove the file
    ret = remove(filename.c_str());
#endif
    fileToRemove->removeAllBufferBlocks();

    if (logCallback && ret != 0) {
        char errno_msg[512];
        fileToRemove->getOps()->get_errno_str(fileToRemove->getFopsHandle(),
                                              errno_msg, 512);

        if (_last_errno_ == ENOENT) {
            // Ignore 'No such file or directory' error as the file
            // must've been removed already
        } else {
            // TODO: As a workaround for MB-17009, call fprintf instead of
            // fdb_log until c->cgo->go callback trace issue is resolved.
            fprintf(stderr,
                    "Error status code: %d, Error in REMOVE on a "
                    "database file '%s', %s",
                    ret, filename.c_str(), errno_msg);
        }
    }

    // free filemgr structure
    FileMgr::freeFunc(fileToRemove);

    compMgr->removeFromFileRemovalList(filename);

    return false;
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

bool compactor_is_file_removed(const char *filename) {
    std::string file_name(filename);
    return CompactionManager::getInstance()->isFileRemoved(file_name);
}

bool CompactionManager::isFileRemoved(const std::string &filename) {
    LockHolder lock(cptLock);
    if (fileRemovalList.find(filename) != fileRemovalList.end()) {
        // exist .. old file is not removed yet
        return false;
    }
    return true;
}

void CompactionManager::removeFromFileRemovalList(const std::string &filename) {
    LockHolder lock(cptLock);
    fileRemovalList.erase(filename);

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

CompactionManager::CompactionManager()
    : compactionTaskable(this)
{
    ExecutorPool::get()->registerTaskable(compactionTaskable);
}

CompactionManager* CompactionManager::init() {
    CompactionManager* tmp = instance.load();
    if (tmp == nullptr) {
        // Ensure two threads don't both create an instance.
        LockHolder lock(instanceMutex);
        tmp = instance.load();
        if (tmp == nullptr) {
            tmp = new CompactionManager();
            instance.store(tmp);
        }
    }
    return tmp;
}

CompactionManager* CompactionManager::getInstance() {
    CompactionManager* compaction_manager = instance.load();
    if (compaction_manager == nullptr) {
        // Create the compaction manager
        return init();
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
    // Clear pending compactions, so any pending fileRemoval tasks can
    // complete
    {
        UniqueLock lock(cptLock);
        pendingCompactions.clear();
    }

    // Tasks queued inside pendingCompactions will be cancelled by the call
    // below since we specify blockShutdown = false
    // They will be released as part of the destructor of CompactionManager
    // Wait for all unfinished tasks, cancelling them if needed.
    ExecutorPool::get()->unregisterTaskable(compactionTaskable, false /*!force*/);
}

fdb_status CompactionManager::registerFile(FileMgr *file,
                                           fdb_config *config,
                                           ErrLogCallback *log_callback)
{
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
    UniqueLock lock(cptLock);
    auto entry = pendingCompactions.find(filename);
    if (entry == pendingCompactions.end()) {
        CompactionTask *compactTask =
            new CompactionTask(compactionTaskable, // ExecutorPool Group Id
                               this,
                               file,
                               *config); // Full configuration params
        if (!compactTask) { // LCOV_EXCL_START
            return FDB_RESULT_ALLOC_FAIL;
        } // LCOV_EXCL_STOP

        compactTask->incrOpenHandles();
        pendingCompactions.insert(std::make_pair(filename, compactTask));
        lock.unlock();

        ExecutorPool::get()->schedule(compactTask, WRITER_TASK_IDX);

        // store in metafile
        fs = storeMetaFile(filename, log_callback);
    } else {
        CompactionTask *compactTask =
              reinterpret_cast<CompactionTask *>(entry->second.get());
        compactTask->incrOpenHandles();
    }

    return fs;
}

/* Expectations:
 * When last user close happens, given file's auto compaction task must
 * be cancelled and its entry removed if task never ran,
 * If task is running, simply remove its entry, ~CompactionTask cleans up entry
*/
void CompactionManager::deregisterFile(FileMgr *file) {
    UniqueLock lock(cptLock);
    std::string file_name(file->getFileName());
    auto entry = pendingCompactions.find(std::string(file_name));
    if (entry != pendingCompactions.end()) {
        ExTask compTask = entry->second;
        CompactionTask *compactTask =
              reinterpret_cast<CompactionTask *>(compTask.get());
        if (compactTask->decrOpenHandles() == 0) {
            pendingCompactions.erase(entry);
            lock.unlock();
            ExecutorPool::get()->cancel(compTask->getId());
        }
    }
}

bool CompactionManager::removeCompactionTask(const std::string file_name)
{
    UniqueLock lock(cptLock);
    auto entry = pendingCompactions.find(file_name);
    if (entry == pendingCompactions.end()) {
        return false;
    }
    ExTask compTask = entry->second;
    pendingCompactions.erase(entry);
    lock.unlock();

    // This function is invoked whenever any compaction completes
    CompactionTask *compactTask =
                      reinterpret_cast<CompactionTask *>(compTask.get());
    if (!compactTask->getCompactionFlag()) {
        // If compaction has completed on an auto-compaction file, but this
        // flag is not set, indicates that manual compaction was triggerred on
        // this file meant for auto-compaction. Since compaction is complete,
        // we must cancel the auto-compaction task.
        ExecutorPool::get()->cancel(compTask->getId());
    } // else It means this call was invoked by the CompactionTask::run()
    // in which case we do not have to cancel the task.
    return true;
}

bool CompactionManager::isPendingCompaction(const std::string &filename) {
    UniqueLock lock(cptLock);
    if (pendingCompactions.find(filename) != pendingCompactions.end()) {
        return true;
    } else {
        return false;
    }
}

fdb_status compactor_register_file_removing(FileMgr *file,
                                            ErrLogCallback *log_callback) {
    return CompactionManager::getInstance()->registerFileRemoval(file, log_callback);
}

fdb_status CompactionManager::registerFileRemoval(FileMgr *file,
                                                  ErrLogCallback *log_callback) {
    std::string file_name = std::string(file->getFileName());
    UniqueLock lh(cptLock);
    if (fileRemovalList.find(file_name) != fileRemovalList.end()) {
        // File Removal already scheduled
        return FDB_RESULT_SUCCESS;
    }

    ExTask fileRemovalTask = new FileRemovalTask(compactionTaskable,
                                                 file,
                                                 log_callback);
    fileRemovalList.insert(file_name);
    lh.unlock();

    ExecutorPool::get()->schedule(fileRemovalTask, WRITER_TASK_IDX);

    return FDB_RESULT_SUCCESS;
}

fdb_status CompactionManager::setCompactionThreshold(FileMgr *file,
                                                     size_t new_threshold) {
    LockHolder lh(cptLock);
    auto entry = pendingCompactions.find(std::string(file->getFileName()));
    if (entry == pendingCompactions.end()) {
        return FDB_RESULT_INVALID_ARGS;
    }

    CompactionTask *autoCompactTask =
              reinterpret_cast<CompactionTask *>(entry->second.get());

    autoCompactTask->setCompactionThreshold(new_threshold);

    return FDB_RESULT_SUCCESS;
}

fdb_status CompactionManager::setCompactionInterval(FileMgr *file,
                                                    size_t interval) {
    LockHolder lh(cptLock);
    auto entry = pendingCompactions.find(std::string(file->getFileName()));
    if (entry == pendingCompactions.end()) {
        return FDB_RESULT_INVALID_ARGS;
    }

    CompactionTask *autoCompactTask =
              reinterpret_cast<CompactionTask *>(entry->second.get());

    // The following function will invoke ExecutorPool::snooze()
    autoCompactTask->setCompactionInterval(interval);

    return FDB_RESULT_SUCCESS;
}

bool CompactionManager::switchCompactionFlag(FileMgr *file, bool flag) {
    LockHolder lh(cptLock);
    auto entry = pendingCompactions.find(std::string(file->getFileName()));
    if (entry == pendingCompactions.end()) {
        return false;
    }

    CompactionTask *autoCompactTask =
              reinterpret_cast<CompactionTask *>(entry->second.get());

    autoCompactTask->setCompactionFlag(flag);
    return true;
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
    sprintf(query_str, "%s*", prefix);
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
