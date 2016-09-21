/* -*- Mode: C++; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2013 Couchbase, Inc.
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

#include "common.h"

#include <algorithm>
#include <queue>
#include <sstream>

#include "fdb_internal.h"
#include "taskqueue.h"
#include "executorpool.h"
#include "executorthread.h"

#define LOG(...)

std::mutex ExecutorPool::initGuard;
std::atomic<ExecutorPool*> ExecutorPool::instance;

static const size_t EP_MIN_READER_THREADS = 4;
static const size_t EP_MIN_WRITER_THREADS = 4;

static const size_t EP_MAX_READER_THREADS = 12;
static const size_t EP_MAX_WRITER_THREADS = 8;
static const size_t EP_MAX_AUXIO_THREADS  = 8;
static const size_t EP_MAX_NONIO_THREADS  = 8;

size_t ExecutorPool::getNumCPU(void) {
    size_t numCPU;
#ifdef WIN32
    SYSTEM_INFO sysinfo;
    GetSystemInfo(&sysinfo);
    numCPU = (size_t)sysinfo.dwNumberOfProcessors;
#else
    numCPU = (size_t)sysconf(_SC_NPROCESSORS_ONLN);
#endif

    return (numCPU < 256) ? numCPU : 0;
}

size_t ExecutorPool::getNumNonIO(void) {
    // 1. compute: ceil of 10% of total threads
    size_t count = maxGlobalThreads / 10;
    if (!count || maxGlobalThreads % 10) {
        count++;
    }
    // 2. adjust computed value to be within range
    if (count > EP_MAX_NONIO_THREADS) {
        count = EP_MAX_NONIO_THREADS;
    }
    // 3. pick user's value if specified
    if (maxWorkers[NONIO_TASK_IDX]) {
        count = maxWorkers[NONIO_TASK_IDX];
    }
    return count;
}

size_t ExecutorPool::getNumAuxIO(void) {
    // 1. compute: ceil of 10% of total threads
    size_t count = maxGlobalThreads / 10;
    if (!count || maxGlobalThreads % 10) {
        count++;
    }
    // 2. adjust computed value to be within range
    if (count > EP_MAX_AUXIO_THREADS) {
        count = EP_MAX_AUXIO_THREADS;
    }
    // 3. Override with user's value if specified
    if (maxWorkers[AUXIO_TASK_IDX]) {
        count = maxWorkers[AUXIO_TASK_IDX];
    }
    return count;
}

size_t ExecutorPool::getNumWriters(void) {
    size_t count = 0;
    // 1. compute: floor of Half of what remains after nonIO, auxIO threads
    if (maxGlobalThreads > (getNumAuxIO() + getNumNonIO())) {
        count = maxGlobalThreads - getNumAuxIO() - getNumNonIO();
        count = count >> 1;
    }
    // 2. adjust computed value to be within range
    if (count > EP_MAX_WRITER_THREADS) {
        count = EP_MAX_WRITER_THREADS;
    } else if (count < EP_MIN_WRITER_THREADS) {
        count = EP_MIN_WRITER_THREADS;
    }
    // 3. Override with user's value if specified
    if (maxWorkers[WRITER_TASK_IDX]) {
        count = maxWorkers[WRITER_TASK_IDX];
    }
    return count;
}

size_t ExecutorPool::getNumReaders(void) {
    size_t count = 0;
    // 1. compute: what remains after writers, nonIO & auxIO threads are taken
    if (maxGlobalThreads >
            (getNumWriters() + getNumAuxIO() + getNumNonIO())) {
        count = maxGlobalThreads
              - getNumWriters() - getNumAuxIO() - getNumNonIO();
    }
    // 2. adjust computed value to be within range
    if (count > EP_MAX_READER_THREADS) {
        count = EP_MAX_READER_THREADS;
    } else if (count < EP_MIN_READER_THREADS) {
        count = EP_MIN_READER_THREADS;
    }
    // 3. Override with user's value if specified
    if (maxWorkers[READER_TASK_IDX]) {
        count = maxWorkers[READER_TASK_IDX];
    }
    return count;
}

ExecutorPool *ExecutorPool::initExPool(threadpool_config &config) {
    auto* tmp = instance.load();
    if (tmp == nullptr) {
        tmp = new ExecutorPool(config.num_threads,
                               FDB_EXPOOL_NUM_QUEUES,
                               0, // Bump on background reader queue
                               FDB_EXPOOL_NUM_WRITERS,
                               0, // Bump on background auxio queue
                               0); // Bump on background nonio queue
        instance.store(tmp);
    }
    return tmp;
}

ExecutorPool *ExecutorPool::get(void) {
    auto* tmp = instance.load();
    if (tmp == nullptr) {
        LockHolder lh(initGuard);
        tmp = instance.load();
        if (tmp == nullptr) {
            // Double-checked locking if instance is null - ensure two threads
            // don't both create an instance.
            tmp = new ExecutorPool(FDB_EXPOOL_NUM_THREADS,
                                   FDB_EXPOOL_NUM_QUEUES,
                                   0, // Bump on background reader queue
                                   FDB_EXPOOL_NUM_WRITERS,
                                   0, // Bump on background auxio queue
                                   0); // Bump on background nonio queue
            instance.store(tmp);
        }
    }
    return tmp;
}

bool ExecutorPool::shutdown(void) {
    LockHolder lh(initGuard);
    auto* tmp = instance.load();
    if (tmp != nullptr) {
        if (tmp->taskOwners.size() != 0) {
            // Open taskables
            return false;
        }
        delete tmp;
        instance = nullptr;
    }
    return true;
}

ExecutorPool::ExecutorPool(size_t maxThreads, size_t nTaskSets,
                           size_t maxReaders, size_t maxWriters,
                           size_t maxAuxIO,   size_t maxNonIO) :
                  numTaskSets(nTaskSets), totReadyTasks(0),
                  isHiPrioQset(false), isLowPrioQset(false), numBuckets(0),
                  numSleepers(0) {
    maxGlobalThreads = maxThreads;
    curWorkers  = new std::atomic<uint16_t>[nTaskSets];
    maxWorkers  = new std::atomic<uint16_t>[nTaskSets];
    numReadyTasks  = new std::atomic<size_t>[nTaskSets];
    for (size_t i = 0; i < nTaskSets; i++) {
        curWorkers[i] = 0;
        numReadyTasks[i] = 0;
    }
    maxWorkers[WRITER_TASK_IDX] = maxWriters;
    maxWorkers[READER_TASK_IDX] = maxReaders;
    maxWorkers[AUXIO_TASK_IDX]  = maxAuxIO;
    maxWorkers[NONIO_TASK_IDX]  = maxNonIO;
}

ExecutorPool::~ExecutorPool(void) {
    _stopAndJoinThreads();

    delete [] curWorkers;
    delete[] maxWorkers;
    delete[] numReadyTasks;

    if (isHiPrioQset) {
        for (size_t i = 0; i < numTaskSets; i++) {
            delete hpTaskQ[i];
        }
    }
    if (isLowPrioQset) {
        for (size_t i = 0; i < numTaskSets; i++) {
            delete lpTaskQ[i];
        }
    }
}

// To prevent starvation of low priority queues, we define their
// polling frequencies as follows ...
#define LOW_PRIORITY_FREQ 5 // 1 out of 5 times threads check low priority Q

TaskQueue *ExecutorPool::_nextTask(ExecutorThread &t, uint8_t tick) {
    if (!tick) {
        return NULL;
    }

    unsigned int myq = t.startIndex;
    TaskQueue *checkQ; // which TaskQueue set should be polled first
    TaskQueue *checkNextQ; // which set of TaskQueue should be polled next
    TaskQueue *toggle = NULL;
    if ( !(tick % LOW_PRIORITY_FREQ)) { // if only 1 Q set, both point to it
        checkQ = isLowPrioQset ? lpTaskQ[myq] :
                (isHiPrioQset ? hpTaskQ[myq] : NULL);
        checkNextQ = isHiPrioQset ? hpTaskQ[myq] : checkQ;
    } else {
        checkQ = isHiPrioQset ? hpTaskQ[myq] :
                (isLowPrioQset ? lpTaskQ[myq] : NULL);
        checkNextQ = isLowPrioQset ? lpTaskQ[myq] : checkQ;
    }
    while (t.state == EXECUTOR_RUNNING) {
        if (checkQ &&
            checkQ->fetchNextTask(t, false)) {
            return checkQ;
        }
        if (toggle || checkQ == checkNextQ) {
            TaskQueue *sleepQ = getSleepQ(myq);
            if (sleepQ->fetchNextTask(t, true)) {
                return sleepQ;
            } else {
                return NULL;
            }
        }
        toggle = checkQ;
        checkQ = checkNextQ;
        checkNextQ = toggle;
    }
    return NULL;
}

TaskQueue *ExecutorPool::nextTask(ExecutorThread &t, uint8_t tick) {
    TaskQueue *tq = _nextTask(t, tick);
    return tq;
}

void ExecutorPool::addWork(size_t newWork, task_type_t qType) {
    if (newWork) {
        totReadyTasks.fetch_add(newWork);
        numReadyTasks[qType].fetch_add(newWork);
    }
}

void ExecutorPool::lessWork(task_type_t qType) {
    if (numReadyTasks[qType].load() == 0) {
        fdb_log(NULL, FDB_RESULT_INVALID_CONFIG,
                "Number of ready tasks on qType:%d is zero!\n", qType);
        fdb_assert(false, qType, 0);
    }
    numReadyTasks[qType]--;
    totReadyTasks--;
}

void ExecutorPool::doneWork(task_type_t &curTaskType) {
    if (curTaskType != NO_TASK_TYPE) {
        LOG(EXTENSION_LOG_DEBUG, "Done with Task Type %d capacity = %d",
                curTaskType, curWorkers[curTaskType].load());
        curWorkers[curTaskType]--;
        curTaskType = NO_TASK_TYPE;
    }
}

task_type_t ExecutorPool::tryNewWork(task_type_t newTaskType) {
    task_type_t ret = newTaskType;
    curWorkers[newTaskType]++; // atomic increment
    // Test if a thread can take up task from the target Queue type
    if (curWorkers[newTaskType] <= maxWorkers[newTaskType]) {
        // Ok to proceed as limit not hit
        LOG(EXTENSION_LOG_DEBUG,
                "Taking up work in task type %d capacity = %d, max=%d",
                newTaskType, curWorkers[newTaskType].load(),
                maxWorkers[newTaskType].load());
    } else {
        curWorkers[newTaskType]--; // do not exceed the limit at maxWorkers
        LOG(EXTENSION_LOG_DEBUG, "Limiting from taking up work in task "
                "type %d capacity = %d, max = %d", newTaskType,
                curWorkers[newTaskType].load(),
                maxWorkers[newTaskType].load());
        ret = NO_TASK_TYPE;
    }

    return ret;
}

bool ExecutorPool::_cancel(size_t taskId, bool eraseTask) {
    LockHolder lh(tMutex);
    std::map<size_t, TaskQpair>::iterator itr = taskLocator.find(taskId);
    if (itr == taskLocator.end()) {
        LOG(EXTENSION_LOG_DEBUG, "Task id %" PRIu64 " not found",
            uint64_t(taskId));
        return false;
    }

    ExTask task = itr->second.first;
    LOG(EXTENSION_LOG_DEBUG, "Cancel task %s id %" PRIu64 " on bucket %s %s",
            task->getDescription().c_str(), uint64_t(task->getId()),
            task->getTaskable().getName().c_str(), eraseTask ? "final erase" : "!");

    task->cancel(); // must be idempotent, just set state to dead

    if (eraseTask) { // only internal threads can erase tasks
        if (!task->isdead()) {
            fdb_log(NULL, FDB_RESULT_INVALID_CONFIG,
                    "Task (%s) is not dead after cancelling it!\n",
                    task->getDescription().c_str());
            fdb_assert(false, 0, 0);
        }
        taskLocator.erase(itr);
        tMutex.notify_all();
    } else { // wake up the task from the TaskQ so a thread can safely erase it
             // otherwise we may race with unregisterTaskable where a unlocated
             // task runs in spite of its bucket getting unregistered
        itr->second.second->wake(task);
    }
    return true;
}

bool ExecutorPool::cancel(size_t taskId, bool eraseTask) {
    bool rv = _cancel(taskId, eraseTask);
    return rv;
}

bool ExecutorPool::_wake(size_t taskId) {
    LockHolder lh(tMutex);
    std::map<size_t, TaskQpair>::iterator itr = taskLocator.find(taskId);
    if (itr != taskLocator.end()) {
        itr->second.second->wake(itr->second.first);
        return true;
    }
    return false;
}

bool ExecutorPool::wake(size_t taskId) {
    bool rv = _wake(taskId);
    return rv;
}

bool ExecutorPool::_snooze(size_t taskId, double toSleep) {
    LockHolder lh(tMutex);
    std::map<size_t, TaskQpair>::iterator itr = taskLocator.find(taskId);
    if (itr != taskLocator.end()) {
        itr->second.second->snooze(itr->second.first, toSleep);
        return true;
    }
    return false;
}

bool ExecutorPool::snooze(size_t taskId, double toSleep) {
    bool rv = _snooze(taskId, toSleep);
    return rv;
}

TaskQueue* ExecutorPool::_getTaskQueue(const Taskable& t,
                                       task_type_t qidx) {
    TaskQueue         *q             = NULL;
    size_t            curNumThreads  = 0;

    bucket_priority_t bucketPriority = t.getWorkloadPriority();

    if (qidx < 0 || static_cast<size_t>(qidx) >= numTaskSets) {
        fdb_log(NULL, FDB_RESULT_INVALID_CONFIG,
                "Invalid args: qidx(%d) is outside the range [0, %" _F64 "]!\n",
                qidx, static_cast<uint64_t>(numTaskSets));
        fdb_assert(false, 0, 0);
    }

    curNumThreads = threadQ.size();

    if (!bucketPriority) {
        LOG(EXTENSION_LOG_WARNING, "Trying to schedule task for unregistered "
            "bucket %s", t.getName().c_str());
        return q;
    }

    if (curNumThreads < maxGlobalThreads) {
        if (isHiPrioQset) {
            q = hpTaskQ[qidx];
        } else if (isLowPrioQset) {
            q = lpTaskQ[qidx];
        }
    } else { // Max capacity Mode scheduling ...
        switch (bucketPriority) {
        case LOW_BUCKET_PRIORITY:
            if (lpTaskQ.size() != numTaskSets) {
                fdb_log(NULL, FDB_RESULT_INVALID_CONFIG,
                        "TaskQueue at maximum capacity but low-priority taskQ "
                        "size (%" _F64 "), is not %" _F64 "!\n",
                        static_cast<uint64_t>(lpTaskQ.size()),
                        static_cast<uint64_t>(numTaskSets));
                fdb_assert(false, lpTaskQ.size(), numTaskSets);
            }
            q = lpTaskQ[qidx];
            break;

        case HIGH_BUCKET_PRIORITY:
            if (hpTaskQ.size() != numTaskSets) {
                fdb_log(NULL, FDB_RESULT_INVALID_CONFIG,
                        "TaskQueue at maximum capacity but high-priority taskQ "
                        "size (%" _F64 "), is not %" _F64 "!\n",
                        static_cast<uint64_t>(hpTaskQ.size()),
                        static_cast<uint64_t>(numTaskSets));
                fdb_assert(false, hpTaskQ.size(), numTaskSets);
            }
            q = hpTaskQ[qidx];
            break;

        default:
            fdb_log(NULL, FDB_RESULT_INVALID_CONFIG,
                    "Invalid bucket priority: %d!\n", bucketPriority);
            fdb_assert(false, 0, 0);
        }
    }
    return q;
}

size_t ExecutorPool::_schedule(ExTask task, task_type_t qidx) {
    LockHolder lh(tMutex);
    TaskQueue *q = _getTaskQueue(task->getTaskable(), qidx);
    TaskQpair tqp(task, q);
    taskLocator[task->getId()] = tqp;

    q->schedule(task);

    return task->getId();
}

size_t ExecutorPool::schedule(ExTask task, task_type_t qidx) {
    size_t rv = _schedule(task, qidx);
    return rv;
}

void ExecutorPool::_registerTaskable(Taskable& taskable) {
    TaskQ *taskQ;
    bool *whichQset;
    const char *queueName;
    WorkLoadPolicy &workload = taskable.getWorkLoadPolicy();
    bucket_priority_t priority = workload.getBucketPriority();

    if (priority < HIGH_BUCKET_PRIORITY) {
        taskable.setWorkloadPriority(LOW_BUCKET_PRIORITY);
        taskQ = &lpTaskQ;
        whichQset = &isLowPrioQset;
        queueName = "LowPrioQ_";
        LOG(EXTENSION_LOG_NOTICE, "Taskable %s registered with low priority",
            taskable.getName().c_str());
    } else {
        taskable.setWorkloadPriority(HIGH_BUCKET_PRIORITY);
        taskQ = &hpTaskQ;
        whichQset = &isHiPrioQset;
        queueName = "HiPrioQ_";
        LOG(EXTENSION_LOG_NOTICE, "Taskable %s registered with high priority",
            taskable.getName().c_str());
    }

    LockHolder lh(tMutex);

    if (!(*whichQset)) {
        taskQ->reserve(numTaskSets);
        for (size_t i = 0; i < numTaskSets; i++) {
            taskQ->push_back(new TaskQueue(this, (task_type_t)i, queueName));
        }
        *whichQset = true;
    }

    taskOwners.insert(&taskable);
    numBuckets++;

    _startWorkers();
}

void ExecutorPool::registerTaskable(Taskable& taskable) {
    _registerTaskable(taskable);
}

bool ExecutorPool::_startWorkers(void) {
    if (threadQ.size()) {
        return false;
    }

    size_t numReaders = getNumReaders();
    size_t numWriters = getNumWriters();
    size_t numAuxIO   = getNumAuxIO();
    size_t numNonIO   = getNumNonIO();

    std::stringstream ss;
    ss << "Spawning " << numReaders << " readers, " << numWriters <<
    " writers, " << numAuxIO << " auxIO, " << numNonIO << " nonIO threads";
    LOG(EXTENSION_LOG_NOTICE, "%s", ss.str().c_str());

    for (size_t tidx = 0; tidx < numReaders; ++tidx) {
        std::stringstream ss;
        ss << "reader_worker_" << tidx;

        threadQ.push_back(new ExecutorThread(this, READER_TASK_IDX, ss.str()));
        threadQ.back()->start();
    }
    for (size_t tidx = 0; tidx < numWriters; ++tidx) {
        std::stringstream ss;
        ss << "writer_worker_" << numReaders + tidx;

        threadQ.push_back(new ExecutorThread(this, WRITER_TASK_IDX, ss.str()));
        threadQ.back()->start();
    }
    for (size_t tidx = 0; tidx < numAuxIO; ++tidx) {
        std::stringstream ss;
        ss << "auxio_worker_" << numReaders + numWriters + tidx;

        threadQ.push_back(new ExecutorThread(this, AUXIO_TASK_IDX, ss.str()));
        threadQ.back()->start();
    }
    for (size_t tidx = 0; tidx < numNonIO; ++tidx) {
        std::stringstream ss;
        ss << "nonio_worker_" << numReaders + numWriters + numAuxIO + tidx;

        threadQ.push_back(new ExecutorThread(this, NONIO_TASK_IDX, ss.str()));
        threadQ.back()->start();
    }

    if (!maxWorkers[WRITER_TASK_IDX]) {
        // MB-12279: Limit writers to 4 for faster bgfetches in DGM by default
        numWriters = 4;
    }
    maxWorkers[WRITER_TASK_IDX] = numWriters;
    maxWorkers[READER_TASK_IDX] = numReaders;
    maxWorkers[AUXIO_TASK_IDX]  = numAuxIO;
    maxWorkers[NONIO_TASK_IDX]  = numNonIO;

    return true;
}

bool ExecutorPool::_stopTaskGroup(task_gid_t taskGID,
                                  task_type_t taskType,
                                  bool force) {
    bool unfinishedTask;
    bool retVal = false;
    std::map<size_t, TaskQpair>::iterator itr;

    UniqueLock lh(tMutex);
    do {
        ExTask task;
        unfinishedTask = false;
        for (itr = taskLocator.begin(); itr != taskLocator.end(); itr++) {
            task = itr->second.first;
            TaskQueue *q = itr->second.second;
            if (task->getTaskable().getGID() == taskGID &&
                (taskType == NO_TASK_TYPE || q->queueType == taskType)) {
                LOG(EXTENSION_LOG_WARNING, "Stopping Task id %" PRIu64 " %s %s ",
                    uint64_t(task->getId()),
                    task->getTaskable().getName().c_str(),
                    task->getDescription().c_str());
                // If force flag is set during shutdown, cancel all tasks
                // without considering the blockShutdown status of the task.
                if (force || !task->blockShutdown) {
                    task->cancel(); // Must be idempotent
                }
                q->wake(task);
                unfinishedTask = true;
                retVal = true;
            }
        }
        if (unfinishedTask) {
            tMutex.wait_for(lh, MIN_SLEEP_TIME); // Wait till task gets cancelled
        }
    } while (unfinishedTask);

    return retVal;
}

bool ExecutorPool::stopTaskGroup(task_gid_t taskGID,
                                 task_type_t taskType,
                                 bool force) {
    bool rv = _stopTaskGroup(taskGID, taskType, force);
    return rv;
}

void ExecutorPool::_unregisterTaskable(Taskable& taskable, bool force) {

    LOG(EXTENSION_LOG_NOTICE, "Unregistering %s taskable %s",
            (numBuckets == 1)? "last" : "", taskable.getName().c_str());

    _stopTaskGroup(taskable.getGID(), NO_TASK_TYPE, force);

    LockHolder lh(tMutex);
    taskOwners.erase(&taskable);
    if (!(--numBuckets)) {
        if (taskLocator.size()) {
            fdb_log(NULL, FDB_RESULT_INVALID_CONFIG,
                    "Attempting to unregister taskable (%s), but "
                    "taskLocator is not empty!\n",
                    taskable.getName().c_str());
            fdb_assert(false, 0, 0);
        }
        for (unsigned int idx = 0; idx < numTaskSets; idx++) {
            TaskQueue *sleepQ = getSleepQ(idx);
            size_t wakeAll = threadQ.size();
            numReadyTasks[idx]++; // this prevents woken workers from sleeping
            totReadyTasks++;
            sleepQ->doWake(wakeAll);
        }
        for (size_t tidx = 0; tidx < threadQ.size(); ++tidx) {
            threadQ[tidx]->stop(false); // only set state to DEAD
        }
        for (unsigned int idx = 0; idx < numTaskSets; idx++) {
            numReadyTasks[idx]--; // once woken reset the ready tasks
            totReadyTasks--;
        }

        for (size_t tidx = 0; tidx < threadQ.size(); ++tidx) {
            threadQ[tidx]->stop(/*wait for threads */);
            delete threadQ[tidx];
        }

        for (size_t i = 0; i < numTaskSets; i++) {
            curWorkers[i] = 0;
        }

        threadQ.clear();
        if (isHiPrioQset) {
            for (size_t i = 0; i < numTaskSets; i++) {
                delete hpTaskQ[i];
            }
            hpTaskQ.clear();
            isHiPrioQset = false;
        }
        if (isLowPrioQset) {
            for (size_t i = 0; i < numTaskSets; i++) {
                delete lpTaskQ[i];
            }
            lpTaskQ.clear();
            isLowPrioQset = false;
        }
    }
}

void ExecutorPool::unregisterTaskable(Taskable& taskable, bool force) {
    _unregisterTaskable(taskable, force);
}

void ExecutorPool::_stopAndJoinThreads() {

    // Ask all threads to stop (but don't wait)
    for (auto thread : threadQ) {
        thread->stop(false);
    }

    // Go over all tasks and wake them up.
    for (auto tq : lpTaskQ) {
        size_t wakeAll = threadQ.size();
        tq->doWake(wakeAll);
    }
    for (auto tq : hpTaskQ) {
        size_t wakeAll = threadQ.size();
        tq->doWake(wakeAll);
    }

    // Now reap/join those threads.
    for (auto thread : threadQ) {
        thread->stop(true);
    }
}
