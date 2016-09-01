/* -*- Mode: C++; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2015 Couchbase, Inc.
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

#include "taskqueue.h"
#include "executorpool.h"
#include "executorthread.h"

TaskQueue::TaskQueue(ExecutorPool *m, task_type_t t, const char *nm) :
    name(nm), queueType(t), manager(m), sleepers(0)
{
    // EMPTY
}

TaskQueue::~TaskQueue() {
    LOG(EXTENSION_LOG_INFO, "Task Queue killing %s", name.c_str());
}

const std::string TaskQueue::getName() const {
    return (name+taskType2Str(queueType));
}

size_t TaskQueue::getReadyQueueSize() {
    LockHolder lh(mutex);
    return readyQueue.size();
}

size_t TaskQueue::getFutureQueueSize() {
    LockHolder lh(mutex);
    return futureQueue.size();
}

size_t TaskQueue::getPendingQueueSize() {
    LockHolder lh(mutex);
    return pendingQueue.size();
}

ExTask TaskQueue::_popReadyTask(void) {
    ExTask t = readyQueue.top();
    readyQueue.pop();
    manager->lessWork(queueType);
    return t;
}

void TaskQueue::doWake(size_t &numToWake) {
    LockHolder lh(mutex);
    _doWake_UNLOCKED(numToWake);
}

void TaskQueue::_doWake_UNLOCKED(size_t &numToWake) {
    if (sleepers && numToWake)  {
        if (numToWake < sleepers) {
            for (; numToWake; --numToWake) {
                mutex.notify_one(); // cond_signal 1
            }
        } else {
            mutex.notify_all(); // cond_broadcast
            numToWake -= sleepers;
        }
    }
}

bool TaskQueue::_doSleep(ExecutorThread &t,
                         UniqueLock& lock) {
    t.now = gethrtime();
    if (t.now < t.waketime && manager->trySleep(queueType)) {
        // Atomically switch from running to sleeping; iff we were previously
        // running.
        executor_state_t expected_state = EXECUTOR_RUNNING;
        if (!t.state.compare_exchange_strong(expected_state,
                                             EXECUTOR_SLEEPING)) {
            return false;
        }
        sleepers++;
        // zzz....
        hrtime_t snooze_nsecs = t.waketime - t.now;

        if (snooze_nsecs > MIN_SLEEP_TIME * 1000000000) {
            mutex.wait_for(lock, MIN_SLEEP_TIME);
        } else {
            mutex.wait_for(lock, snooze_nsecs);
        }
        // ... woke!
        sleepers--;
        manager->woke();

        // Finished our sleep, atomically switch back to running iff we were
        // previously sleeping.
        expected_state = EXECUTOR_SLEEPING;
        if (!t.state.compare_exchange_strong(expected_state,
                                             EXECUTOR_RUNNING)) {
            return false;
        }
        t.now = gethrtime();
    }
    t.waketime = hrtime_t(-1);
    return true;
}

bool TaskQueue::_fetchNextTask(ExecutorThread &t, bool toSleep) {
    bool ret = false;
    UniqueLock lh(mutex);

    if (toSleep && !_doSleep(t, lh)) {
        return ret; // shutting down
    }

    size_t numToWake = _moveReadyTasks(t.now);

    if (!futureQueue.empty() && t.startIndex == queueType &&
        futureQueue.top()->getWaketime() < t.waketime) {
        t.waketime = futureQueue.top()->getWaketime(); // record earliest waketime
    }

    if (!readyQueue.empty() && readyQueue.top()->isdead()) {
        t.setCurrentTask(_popReadyTask()); // clean out dead tasks first
        ret = true;
    } else if (!readyQueue.empty() || !pendingQueue.empty()) {
        t.curTaskType = manager->tryNewWork(queueType);
        if (t.curTaskType != NO_TASK_TYPE) {
            // if this TaskQueue has obtained capacity for the thread, then we must
            // consider any pending tasks too. To ensure prioritized run order,
            // the function below will push any pending task back into
            // the readyQueue (sorted by priority)
            _checkPendingQueue();

            ExTask tid = _popReadyTask(); // and pop out the top task
            t.setCurrentTask(tid);
            ret = true;
        } else if (!readyQueue.empty()) { // We hit limit on max # workers
            ExTask tid = _popReadyTask(); // that can work on current Q type!
            pendingQueue.push_back(tid);
            numToWake = numToWake ? numToWake - 1 : 0; // 1 fewer task ready
        } else { // Let the task continue waiting in pendingQueue
            numToWake = numToWake ? numToWake - 1 : 0; // 1 fewer task ready
        }
    }

    _doWake_UNLOCKED(numToWake);
    lh.unlock();

    return ret;
}

bool TaskQueue::fetchNextTask(ExecutorThread &thread, bool toSleep) {
    bool rv = _fetchNextTask(thread, toSleep);
    return rv;
}

size_t TaskQueue::_moveReadyTasks(hrtime_t tv) {
    if (!readyQueue.empty()) {
        return 0;
    }

    size_t numReady = 0;
    while (!futureQueue.empty()) {
        ExTask tid = futureQueue.top();
        if (tid->getWaketime() <= tv) {
            futureQueue.pop();
            readyQueue.push(tid);
            numReady++;
        } else {
            break;
        }
    }

    manager->addWork(numReady, queueType);

    // Current thread will pop one task, so wake up one less thread
    return numReady ? numReady - 1 : 0;
}

void TaskQueue::_checkPendingQueue(void) {
    if (!pendingQueue.empty()) {
        ExTask runnableTask = pendingQueue.front();
        readyQueue.push(runnableTask);
        manager->addWork(1, queueType);
        pendingQueue.pop_front();
    }
}

hrtime_t TaskQueue::_reschedule(ExTask &task, task_type_t &curTaskType) {
    hrtime_t wakeTime;
    manager->doneWork(curTaskType);

    LockHolder lh(mutex);

    futureQueue.push(task);
    if (curTaskType == queueType) {
        wakeTime = futureQueue.top()->getWaketime();
    } else {
        wakeTime = hrtime_t(-1);
    }

    return wakeTime;
}

hrtime_t TaskQueue::reschedule(ExTask &task, task_type_t &curTaskType) {
    hrtime_t rv = _reschedule(task, curTaskType);
    return rv;
}

void TaskQueue::_schedule(ExTask &task) {
    UniqueLock lh(mutex);

    futureQueue.push(task);

    LOG(EXTENSION_LOG_DEBUG, "%s: Schedule a task \"%s\" id %" PRIu64,
        name.c_str(), task->getDescription().c_str(), uint64_t(task->getId()));

    size_t numToWake = 1;
    TaskQueue *sleepQ = manager->getSleepQ(queueType);
    _doWake_UNLOCKED(numToWake);
    lh.unlock();
    if (this != sleepQ) {
        sleepQ->doWake(numToWake);
    }
}

void TaskQueue::schedule(ExTask &task) {
    _schedule(task);
}

void TaskQueue::_wake(ExTask &task) {
    const hrtime_t now = gethrtime();

    UniqueLock lh(mutex);
    LOG(EXTENSION_LOG_DEBUG, "%s: Wake a task \"%s\" id %" PRIu64,
        name.c_str(), task->getDescription().c_str(), uint64_t(task->getId()));

    std::queue<ExTask> notReady;
    // Wake thread-count-serialized tasks too
    for (std::list<ExTask>::iterator it = pendingQueue.begin();
         it != pendingQueue.end();) {
        ExTask tid = *it;
        if (tid->getId() == task->getId() || tid->isdead()) {
            notReady.push(tid);
            it = pendingQueue.erase(it);
        } else {
            it++;
        }
    }

    futureQueue.updateWaketime(task, now);
    task->setState(TASK_RUNNING, TASK_SNOOZED);

    // One task is being made ready regardless of the queue it's in.
    size_t readyCount = 1;
    while (!notReady.empty()) {
        ExTask tid = notReady.front();
        if (tid->getWaketime() <= now || tid->isdead()) {
            readyCount++;
        }

        // MB-18453: Only push to the futureQueue
        futureQueue.push(tid);
        notReady.pop();
    }

    _doWake_UNLOCKED(readyCount);
    TaskQueue *sleepQ = manager->getSleepQ(queueType);
    lh.unlock();
    if (this != sleepQ) {
        sleepQ->doWake(readyCount);
    }
}

void TaskQueue::wake(ExTask &task) {
    _wake(task);
}

const std::string TaskQueue::taskType2Str(task_type_t type) {
    switch (type) {
    case WRITER_TASK_IDX:
        return std::string("Writer");
    case READER_TASK_IDX:
        return std::string("Reader");
    case AUXIO_TASK_IDX:
        return std::string("AuxIO");
    case NONIO_TASK_IDX:
        return std::string("NonIO");
    default:
        return std::string("None");
    }
}
