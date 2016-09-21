/*
 *     Copyright 2014 Couchbase, Inc.
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

#ifndef SRC_EXECUTORPOOL_H_
#define SRC_EXECUTORPOOL_H_ 1

#include <map>
#include <set>
#include "common.h"

#include "tasks.h"
#include "task_type.h"
#include "taskable.h"
#include "sync_object.h"

// Forward decl
class TaskQueue;
class ExecutorThread;

typedef std::vector<ExecutorThread *> ThreadQ;
typedef std::pair<ExTask, TaskQueue *> TaskQpair;
typedef std::vector<TaskQueue *> TaskQ;

struct threadpool_config {
    size_t num_threads;
};

class ExecutorPool {
public:

    void addWork(size_t newWork, task_type_t qType);

    void lessWork(task_type_t qType);

    void doneWork(task_type_t &doneTaskType);

    task_type_t tryNewWork(task_type_t newTaskType);

    bool trySleep(task_type_t task_type) {
        if (!numReadyTasks[task_type]) {
            numSleepers++;
            return true;
        }
        return false;
    }

    void woke(void) {
        numSleepers--;
    }

    TaskQueue *nextTask(ExecutorThread &t, uint8_t tick);

    TaskQueue *getSleepQ(unsigned int curTaskType) {
        return isHiPrioQset ? hpTaskQ[curTaskType] : lpTaskQ[curTaskType];
    }

    bool cancel(size_t taskId, bool eraseTask=false);

    bool stopTaskGroup(task_gid_t taskGID, task_type_t qidx, bool force);

    bool wake(size_t taskId);

    bool snooze(size_t taskId, double tosleep);

    void registerTaskable(Taskable& taskable);

    void unregisterTaskable(Taskable& taskable, bool force);

    size_t getNumWorkersStat(void) { return threadQ.size(); }

    size_t getNumCPU(void);

    size_t getNumReaders(void);

    size_t getNumWriters(void);

    size_t getNumAuxIO(void);

    size_t getNumNonIO(void);

    size_t getMaxReaders(void) { return maxWorkers[READER_TASK_IDX]; }

    size_t getMaxWriters(void) { return maxWorkers[WRITER_TASK_IDX]; }

    size_t getMaxAuxIO(void) { return maxWorkers[AUXIO_TASK_IDX]; }

    size_t getMaxNonIO(void) { return maxWorkers[NONIO_TASK_IDX]; }

    void setMaxReaders(uint16_t v) { maxWorkers[READER_TASK_IDX] = v; }

    void setMaxWriters(uint16_t v) { maxWorkers[WRITER_TASK_IDX] = v; }

    void setMaxAuxIO(uint16_t v) { maxWorkers[AUXIO_TASK_IDX] = v; }

    void setMaxNonIO(uint16_t v) { maxWorkers[NONIO_TASK_IDX] = v; }

    size_t getNumReadyTasks(void) { return totReadyTasks; }

    size_t getNumSleepers(void) { return numSleepers; }

    size_t schedule(ExTask task, task_type_t qidx);

    static ExecutorPool *initExPool(struct threadpool_config &config);

    static ExecutorPool *get(void);

    static bool shutdown(void);

protected:

    ExecutorPool(size_t t, size_t nTaskSets, size_t r, size_t w, size_t a,
                 size_t n);
    virtual ~ExecutorPool(void);

    TaskQueue* _nextTask(ExecutorThread &t, uint8_t tick);
    bool _cancel(size_t taskId, bool eraseTask=false);
    bool _wake(size_t taskId);
    virtual bool _startWorkers(void);
    bool _snooze(size_t taskId, double tosleep);
    size_t _schedule(ExTask task, task_type_t qidx);
    void _registerTaskable(Taskable& taskable);
    void _unregisterTaskable(Taskable& taskable, bool force);
    bool _stopTaskGroup(task_gid_t taskGID, task_type_t qidx, bool force);
    TaskQueue* _getTaskQueue(const Taskable& t, task_type_t qidx);
    void _stopAndJoinThreads();

    size_t numTaskSets; // safe to read lock-less not altered after creation
    size_t maxGlobalThreads;

    std::atomic<size_t> totReadyTasks;
    SyncObject mutex; // Thread management condition var + mutex

    //! A mapping of task ids to Task, TaskQ in the thread pool
    std::map<size_t, TaskQpair> taskLocator;

    //A list of threads
    ThreadQ threadQ;

    // Global cross bucket priority queues where tasks get scheduled into ...
    TaskQ hpTaskQ; // a vector array of numTaskSets elements for high priority
    bool isHiPrioQset;

    TaskQ lpTaskQ; // a vector array of numTaskSets elements for low priority
    bool isLowPrioQset;

    size_t numBuckets;

    SyncObject tMutex; // to serialize taskLocator, threadQ, numBuckets access

    std::atomic<uint16_t> numSleepers; // total number of sleeping threads
    std::atomic<uint16_t> *curWorkers; // track # of active workers per TaskSet
    std::atomic<uint16_t> *maxWorkers; // and limit it to the value set here
    std::atomic<size_t> *numReadyTasks; // number of ready tasks per task set

    // Set of all known task owners
    std::set<void *> taskOwners;

    // Singleton creation
    static std::mutex initGuard;
    static std::atomic<ExecutorPool*> instance;
};
#endif  // SRC_EXECUTORPOOL_H_
