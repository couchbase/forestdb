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

#ifndef SRC_TASKQUEUE_H_
#define SRC_TASKQUEUE_H_ 1

#include "common.h"

#include <queue>
#include <list>

#include "futurequeue.h"
#include "ringbuffer.h"
#include "task_type.h"
#include "sync_object.h"
#include "tasks.h"

class ExecutorPool;
class ExecutorThread;

class TaskQueue {
    friend class ExecutorPool;
public:
    TaskQueue(ExecutorPool *m, task_type_t t, const char *nm);
    ~TaskQueue();

    void schedule(ExTask &task);

    hrtime_t reschedule(ExTask &task, task_type_t &curTaskType);

    void checkPendingQueue(void);

    void doWake(size_t &numToWake);

    bool fetchNextTask(ExecutorThread &thread, bool toSleep);

    void wake(ExTask &task);

    static const std::string taskType2Str(task_type_t type);

    const std::string getName() const;

    const task_type_t getQueueType() const { return queueType; }

    size_t getReadyQueueSize();

    size_t getFutureQueueSize();

    size_t getPendingQueueSize();

    void snooze(ExTask& task, const double secs) {
        futureQueue.snooze(task, secs);
    }

private:
    void _schedule(ExTask &task);
    hrtime_t _reschedule(ExTask &task, task_type_t &curTaskType);
    void _checkPendingQueue(void);
    bool _fetchNextTask(ExecutorThread &thread, bool toSleep);
    void _wake(ExTask &task);
    bool _doSleep(ExecutorThread &thread, UniqueLock& lock);
    void _doWake_UNLOCKED(size_t &numToWake);
    size_t _moveReadyTasks(hrtime_t tv);
    ExTask _popReadyTask(void);

    SyncObject mutex;
    const std::string name;
    task_type_t queueType;
    ExecutorPool *manager;
    size_t sleepers; // number of threads sleeping in this taskQueue

    // sorted by task priority.
    std::priority_queue<ExTask, std::deque<ExTask>,
                        CompareByPriority> readyQueue;

    // sorted by waketime.
    FutureQueue<> futureQueue;

    std::list<ExTask> pendingQueue;
};

#endif  // SRC_TASKQUEUE_H_
