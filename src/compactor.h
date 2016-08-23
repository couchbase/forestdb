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

#include <time.h>

#include <algorithm>
#include <atomic>
#include <map>
#include <mutex>
#include <string>
#include <unordered_set>

#include "globaltask.h"
#include "taskable.h"
#include "internal_types.h"
#include "sync_object.h"

struct compactor_config {
    size_t sleep_duration;
    size_t num_threads;
};

struct compactor_meta;
class CompactionManager;

class CompactionMgrTaskable : public Taskable {
public:
    CompactionMgrTaskable(CompactionManager *cm) : compMgrCtx(cm),
        taskableName("CompactionManager"),
        // Workload Policy allows ExecutorPool to have tasks grouped by priority
        // The first parameter marks the file as low (default) or high priority
        // Currently this feature is unused by forestdb as all files are equal.
        workLoadPolicy(FDB_EXPOOL_NUM_WRITERS, // Marks DB file priority as LOW
                       FDB_EXPOOL_NUM_QUEUES) {} // Shard count (unused feature)

    /**
     * Return the parent FileMgr pointer
     */
    CompactionManager *getCompactionMgr(void) { return compMgrCtx; }

    /**
     * Simply returns the current filename of the forestdb file
     */
    const std::string& getName() const { return taskableName; }

    /**
     * Returns the address of CompactionManager (just some unique value)
     */
    task_gid_t getGID() const {
        return task_gid_t(compMgrCtx);
    }

    /**
     * Default set to LOW_BUCKET_PRIORITY
     */
    bucket_priority_t getWorkloadPriority() const {
        return LOW_BUCKET_PRIORITY;
    }

    /**
     * Unused but implementation of a pure virtual function.
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
   CompactionManager *compMgrCtx;
   const std::string taskableName;
   WorkLoadPolicy workLoadPolicy;
};

class CompactionTask : public GlobalTask {
public:
    CompactionTask(CompactionMgrTaskable &e, CompactionManager *c,
                   FileMgr *f, fdb_config &config);
    bool run();
    std::string getDescription() {
        return desc;
    }
    uint32_t incrOpenHandles() {
        return ++openHandles;
    }
    uint32_t decrOpenHandles() {
        return --openHandles;
    }
    bool getCompactionFlag() {
        return compactionFlag;
    }
    void setCompactionFlag(bool newFlag) {
        compactionFlag = newFlag;
    }
    void setCompactionInterval(size_t newInterval);
    void setCompactionThreshold (size_t threshold) {
        fdbConfig.compaction_threshold = threshold;
    }
private:
    uint64_t estimateActiveSpace();
    bool isCompactionThresholdSatisfied();

    CompactionManager *compMgr;
    FileMgr *fileToCompact;
    fdb_config fdbConfig;
    double sleepTime;
    bool compactionFlag; // set when the file is being compacted
    std::string desc;
    uint32_t openHandles;
};

class FileRemovalTask : public GlobalTask {
public:
    FileRemovalTask(CompactionMgrTaskable &e,
                    FileMgr *file,
                    ErrLogCallback *log_callback);

    bool run();

    std::string getDescription() {
        return desc;
    }

private:
    CompactionManager *compMgr;
    FileMgr *fileToRemove;
    ErrLogCallback *logCallback;
    std::string filename;
    std::string desc;
};

/**
 * Compaction manager that monitors the fragmentation degree of each registered
 * file and performs the compaction through the daemon threads.
 */
class CompactionManager {

public:

    /**
     * Instantiate the compaction manager that performs the database compaction
     * through the daemon threads.
     *
     * @return Pointer to the compaction manager instantiated
     */
    static CompactionManager* init();

    /**
     * Get the singleton instance of the compaction manager.
     */
    static CompactionManager* getInstance();

    /**
     * Register a given file in the compaction file list for auto compaction.
     *
     * @param file Pointer to a file manager instance
     * @param config Pointer to a forestdb config
     * @param log_callback Pointer to a log callback given by the client
     * @return FDB_RESULT_SUCCESS on the successful compaction registration
     */
    fdb_status registerFile(FileMgr *file,
                            fdb_config *config,
                            ErrLogCallback *log_callback);

    /**
     * Release all the resources including threads and memory allocated and
     * destroy the compaction manager.
     */
    static void destroyInstance();

    /**
     * Register a given file for the removal from the file system.
     *
     * @param file Pointer to a file manager instance
     * @param log_callback Pointer to a log callback given by the client
     * @return FDB_RESULT_SUCCESS on the successful file removal registration
     */
    fdb_status registerFileRemoval(FileMgr *file,
                                   ErrLogCallback *log_callback);

    /**
     * Check if a given file is already removed from the file system or not.
     *
     * @param filename Name of a file to be checked
     * @return True if a given file is already removed
     */
    bool isFileRemoved(const std::string &filename);

    /**
     * Remove entry from the file removal list
     */
    void removeFromFileRemovalList(const std::string &filename);

    /**
     * Deregister a give file from the compaction list.
     *
     * @param file Pointer to a file manager instance
     */
    void deregisterFile(FileMgr *file);

    /**
     * Helps a compactionTask remove it's parent Taskable entry from map
     * @param Name of file to look up filesToCompact map
     * @returns true if entry was present, false if task was deregistered
     */
    bool removeCompactionTask(const std::string file_name);

    /**
     * Set the flag that indicates if a compaction task is currently running
     * for a given file.
     *
     * @param file Pointer to a file manager instance
     * @param flag Flag value to be set
     * @return True if the flag is set successfully
     */
    bool switchCompactionFlag(FileMgr *file,
                              bool flag);

    /**
     * Set a compaction fragmentation threshold for a given file
     *
     * @param file Pointer to a file manager instance
     * @param new_threshold Fragmentation threshold to be set
     * @returns FDB_RESULT_INVALID_ARGS if not auto compaction task present
     */
    fdb_status setCompactionThreshold(FileMgr *file,
                                size_t new_threshold);

    /**
     * Set the daemon compaction interval for a given file.
     *
     * @param file Pointer to a file manager instance
     * @param interval Daemon compaction interval to be set
     * @return FDB_RESULT_SUCCESS upon successful interval change
     */
    fdb_status setCompactionInterval(FileMgr *file,
                                     size_t interval);

    /**
     * Return the virtual name of a given file.
     *
     * @param filename File name
     * @return Virtual name of a given file
     */
    static std::string getVirtualFileName(const std::string &filename);

    /**
     * Return the actual name of a given file.
     *
     * @param filename File name
     * @param comp_mode Compaction mode (i.e., auto or manual)
     * @param log_callback Pointer to a log callback given by the client
     * @return Actual name of a given file
     */
    static std::string getActualFileName(const std::string &filename,
                                         fdb_compaction_mode_t comp_mode,
                                         ErrLogCallback *log_callback);

    /**
     * Return the next target name for a given file for compaction.
     *
     * @param filename File name
     * @return Next target name for a given file for compaction
     */
    static std::string getNextFileName(const std::string &filename);

    /**
     * Check if a given file is configured with a valid compaction mode.
     *
     * @param filename File name
     * @param config Pointer to a forestdb config instance
     * @return True if a give file's compaction mode is valid
     */
    static bool isValidCompactionMode(const std::string &filename,
                                      const fdb_config &config);

    /*
     * Create the meta file for a given forestdb file.
     */
    static fdb_status storeMetaFile(const std::string &filename,
                                    ErrLogCallback*log_callback);

    /**
     * Search the list of files that have a given file name as a prefix, and remove them
     * from the file system.
     *
     * @param filename File name to be searched
     * @return FDB_RESULT_SUCCESS upon successful operation
     */
    fdb_status searchAndDestroyFiles(const char *filename);

private:

     // Constructor
    CompactionManager();

    // Destructor
    ~CompactionManager();

    /**
     * Read the metadata from a given meta file.
     *
     * @param metafile Name of a meta file
     * @param metadata Pointer to the metadata buffer
     * @param log_callback Pointer to the log callback given by an application
     * @return Pointer to the metadata buffer
     */
    static struct compactor_meta* readMetaFile(const char *metafile,
                                               struct compactor_meta *metadata,
                                               ErrLogCallback *log_callback);

    // Singleton compaction manager and mutex guarding it's creation.
    static std::atomic<CompactionManager *> instance;
    static std::mutex instanceMutex;

    // Lock to synchronize an access to the compaction manager's internal states
    std::mutex cptLock;

    // Compaction Taskable context
    CompactionMgrTaskable compactionTaskable;

    // Map of files registered for compaction
    std::map<std::string, ExTask> pendingCompactions;

    // Unordered_set of files registered for file removal
    std::unordered_set<std::string> fileRemovalList;

    DISALLOW_COPY_AND_ASSIGN(CompactionManager);
};

// TODO: Need to adapt 'FileMgr' in order to invoke
// CompactionManager::registerFileRemoval and CompactionManager::isFileRemoved APIs
// without going through these two wrapper functions.
fdb_status compactor_register_file_removing(FileMgr *file,
                                            ErrLogCallback *log_callback);
bool compactor_is_file_removed(const char *filename);
