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
#if !defined(WIN32) && !defined(_WIN32)
#include <sys/time.h>
#include <dirent.h>
#include <unistd.h>
#endif

#include "libforestdb/forestdb.h"
#include "fdb_internal.h"
#include "filemgr.h"
#include "common.h"
#include "bgflusher.h"
#include "time_utils.h"
#include "executorpool.h"

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

BgFlushTask::BgFlushTask(BgFlushManager &manager, FileMgr *file) :
    GlobalTask(manager, // Instance of owning Taskable
               Priority::BgFlusherPriority, // Task Priority
               FDB_DEFAULT_BGFLUSHER_SLEEP,
               false), // OK to cancel pending tasks on shutdown
    fileToFlush(file), desc(file->getFileName()), openHandles(0) { }

bool BgFlushTask::run() {
    if (state == TASK_DEAD) {
        return false;
    }

    file_status_t fstatus = fileToFlush->getFileStatus();
    if (fstatus == FILE_REMOVED_PENDING) {
        return false;
    }
    snooze(FDB_DEFAULT_BGFLUSHER_SLEEP);
    return true;
}

BgFlushManager::BgFlushManager() :
        taskableName("BgFlushManager"),
        // Workload Policy allows ExecutorPool to have tasks grouped by priority
        // The first parameter marks the file as low (default) or high priority
        // Currently this feature is unused by forestdb as all files are equal.
        workLoadPolicy(FDB_EXPOOL_NUM_WRITERS, // Marks DB file priority as LOW
                       FDB_EXPOOL_NUM_QUEUES)  // Shard count (unused feature)
{
    ExecutorPool::get()->registerTaskable(*this);
}

BgFlushManager::~BgFlushManager()
{
    // Wait for all unfinished tasks, cancelling them if needed.
    ExecutorPool::get()->unregisterTaskable(*this, false /*!force*/);
}

fdb_status BgFlushManager::registerFileBgF(FileMgr *file,
                                           ErrLogCallback *log_callback)
{
    file_status_t fstatus;
    fdb_status fs = FDB_RESULT_SUCCESS;

    // Ignore files whose status is REMOVED_PENDING.
    // We can save I/O by not flushed these into partitioned file again.
    fstatus = file->getFileStatus();
    if (fstatus == FILE_REMOVED_PENDING) {
        return fs;
    }
    file->acquireSpinLock();
    BgFlushTask *bgflushTask = file->getBgFlusherTask();
    if (bgflushTask == nullptr) {
        bgflushTask = new BgFlushTask(*this, // Common ID for all BgFlush tasks
                                      file);
        if (!bgflushTask) { // LCOV_EXCL_START
            file->releaseSpinLock();
            return FDB_RESULT_ALLOC_FAIL;
        } // LCOV_EXCL_STOP

        bgflushTask->incrOpenHandles();

        // Stash away reference to this task inside the file's smart pointer
        file->setBgFlusherTask(bgflushTask);

        file->releaseSpinLock();

        ExecutorPool::get()->schedule(bgflushTask, WRITER_TASK_IDX);
    } else {
        bgflushTask->incrOpenHandles();
        file->releaseSpinLock();
    }

    return fs;
}

/* Expectations:
 * When last user close happens, given file's flusher task must
 * be cancelled. If the task is running then the thread that is
 * the running the flusher task should clean it up.
 * This is done internally using RCPtr. This method simply resets
 * the FileMgr's RCPtr so that the cleanup can happen as described.
*/
fdb_status BgFlushManager::deregisterFileBgF(FileMgr *file) {
    file->acquireSpinLock();
    BgFlushTask *bgflushTask = file->getBgFlusherTask();
    if (bgflushTask && bgflushTask->decrOpenHandles() == 0) {
        size_t bgfTaskId = bgflushTask->getId(); // Save Task Id first

        file->setBgFlusherTask(nullptr); // Reset the Smart Pointer reference..
        // ..now the only reference to this task should be inside the
        // ExecutorPool which can be removed as part of the cancel call below..
        file->releaseSpinLock();

        ExecutorPool::get()->cancel(bgfTaskId);
    } else {
        file->releaseSpinLock();
    }
    return FDB_RESULT_SUCCESS;
}
