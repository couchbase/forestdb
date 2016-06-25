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

#include <atomic>
#include <map>
#include <vector>
#include <mutex>
#include <string>

#include "internal_types.h"
#include "sync_object.h"

struct compactor_config {
    size_t sleep_duration;
    size_t num_threads;
};

class FileCompactionEntry;
class CompactorThread;
struct compactor_meta;

// Compaction file map with a file name as a key.
typedef std::map<std::string, FileCompactionEntry *> compaction_file_map;

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
     * @param config Compaction manager configurations
     * @return Pointer to the compaction manager instantiated
     */
    static CompactionManager* init(const struct compactor_config &config);

    /**
     * Get the singleton instance of the compaction manager.
     */
    static CompactionManager* getInstance();

    /**
     * Release all the resources including threads and memory allocated and
     * destroy the compaction manager.
     */
    static void destroyInstance();

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
     * Deregister a give file from the compaction list.
     *
     * @param file Pointer to a file manager instance
     */
    void deregisterFile(FileMgr *file);

    /**
     * Set a compaction fragmentation threshold for a given file
     *
     * @param file Pointer to a file manager instance
     * @param new_threshold Fragmentation threshold to be set
     */
    void setCompactionThreshold(FileMgr *file,
                                size_t new_threshold);

    /**
     * Replace a given old file with a new file in the compaction file list.
     *
     * @param old_file Pointer to a old file manager instance
     * @param new_file Pointer to a new file manager instance
     * @param log_callback Pointer to a log callback given by the client
     */
    void switchFile(FileMgr *old_file,
                    FileMgr *new_file,
                    ErrLogCallback *log_callback);

    /**
     * Return the virtual name of a given file.
     *
     * @param filename File name
     * @return Virtual name of a given file
     */
    std::string getVirtualFileName(const std::string &filename);

    /**
     * Return the actual name of a given file.
     *
     * @param filename File name
     * @param comp_mode Compaction mode (i.e., auto or manual)
     * @param log_callback Pointer to a log callback given by the client
     * @return Actual name of a given file
     */
    std::string getActualFileName(const std::string &filename,
                                  fdb_compaction_mode_t comp_mode,
                                  ErrLogCallback *log_callback);

    /**
     * Return the next target name for a given file for compaction.
     *
     * @param filename File name
     * @return Next target name for a given file for compaction
     */
    std::string getNextFileName(const std::string &filename);

    /**
     * Check if a given file is configured with a valid compaction mode.
     *
     * @param filename File name
     * @param config Pointer to a forestdb config instance
     * @return True if a give file's compaction mode is valid
     */
    bool isValidCompactionMode(const std::string &filename,
                               const fdb_config &config);

    /**
     * Remove a given file from the file system and free its allocated resources.
     *
     * @param fname_prefix Prefix of a file name to be removed
     * @config Pointer to a forestdb config instance
     * @return FDB_RESULT_SUCCESS if the operation is completed successfully
     */
    fdb_status destroyFile(const std::string &fname_prefix,
                           const fdb_config &config);

    /**
     * Set the daemon compaction interval for a given file.
     *
     * @param file Pointer to a file manager instance
     * @param interval Daemon compaction interval to be set
     * @return FDB_RESULT_SUCCESS upon successful interval change
     */
    fdb_status setCompactionInterval(FileMgr *file,
                                     size_t interval);

private:

    friend class CompactorThread;

    /**
     * Constructor
     *
     * @param config Compaction manager configurations
     */
    CompactionManager(const struct compactor_config &config);

    // Destructor
    ~CompactionManager();

    // Spawn compactor threads
    void spawnCompactorThreads();

    // Create the meta file for a given forestdb file.
    fdb_status storeMetaFile(const std::string &filename,
                             ErrLogCallback*log_callback);

    /**
     * Check if a given file is waiting for being removed
     *
     * @param entry Pointer to FileCompactionEntry instance
     * @return True if a given file is waiting for removal
     */
    bool checkFileRemoval(FileCompactionEntry *entry);

    /**
     * Read the metadata from a given meta file.
     *
     * @param metafile Name of a meta file
     * @param metadata Pointer to the metadata buffer
     * @param log_callback Pointer to the log callback given by an application
     * @return Pointer to the metadata buffer
     */
    struct compactor_meta* readMetaFile(const char *metafile,
                                        struct compactor_meta *metadata,
                                        ErrLogCallback *log_callback);

    /**
     * Search the list of files that have a given file name as a prefix, and remove them
     * from the file system.
     *
     * @param filename File name to be searched
     * @return FDB_RESULT_SUCCESS upon successful operation
     */
    fdb_status searchAndDestroyFiles(const char *filename);

    // Singleton compaction manager and mutex guarding it's creation.
    static std::atomic<CompactionManager *> instance;
    static std::mutex instanceMutex;

    // Lock to synchronize an access to the compaction manager's internal states
    std::mutex cptLock;
    // Lock to synchronize and notify the compactor threads
    SyncObject syncMutex;

    // Number of daemon compactor threads
    size_t numThreads;
    // List of compactor threads
    std::vector<CompactorThread *> compactorThreads;
    // Compactor thread sleep time
    size_t sleepDuration;
    // Flag indicating if a compaction termination signal is received
    std::atomic<uint8_t> terminateSignal;
    // List of files registered for compaction
    compaction_file_map openFiles;

    DISALLOW_COPY_AND_ASSIGN(CompactionManager);
};

// TODO: Need to adapt 'FileMgr' in order to invoke
// CompactionManager::registerFileRemoval and CompactionManager::isFileRemoved APIs
// without going through these two wrapper functions.
fdb_status compactor_register_file_removing(FileMgr *file,
                                            ErrLogCallback *log_callback);
bool compactor_is_file_removed(const char *filename);
