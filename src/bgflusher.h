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
#include <mutex>
#include <time.h>
#include <algorithm>
#include <atomic>
#include <unordered_map>
#include <mutex>
#include <string>

#include "globaltask.h"
#include "taskable.h"
#include "internal_types.h"

class BgFlushManager : public Taskable {
public:
    BgFlushManager();
    ~BgFlushManager();

    const std::string& getName() const { return taskableName; }

    /**
     * Returns the address of self (just some unique value)
     */
    task_gid_t getGID() const {
        return task_gid_t(this);
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

    /**
     * Creates a BgFlushTask within the given file
     * @param file - the file which is to be background flushed.
     * @param log_callback - to log errors in case of failures.
     * @return fdb_status - fdb_error on failure & FDB_RESULT_SUCCESS otherwise
     */
    fdb_status registerFileBgF(FileMgr *file,
                               ErrLogCallback *log_callback);

    /**
     * On last close of the file, cancels background flush task of given file
     * @param file - the file which is to be background flushed.
     * @return fdb_status - fdb_error on failure & FDB_RESULT_SUCCESS otherwise
     */
    fdb_status deregisterFileBgF(FileMgr *file);

    DISALLOW_COPY_AND_ASSIGN(BgFlushManager);

private:
   const std::string taskableName;
   WorkLoadPolicy workLoadPolicy;
};

class BgFlushTask : public GlobalTask {
public:
    BgFlushTask(BgFlushManager &m, FileMgr *f);

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
private:
    FileMgr *fileToFlush;
    std::string desc;
    uint32_t openHandles;
};
