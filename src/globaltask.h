/* -*- Mode: C++; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2016 Couchbase, Inc.
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

#include "common.h"
#include "atomic.h"
#include "task_priority.h"

enum task_state_t {
    TASK_RUNNING,
    TASK_SNOOZED,
    TASK_DEAD
};

enum class TaskId : int {
    NOTASK=0 // TODO: implement mapping from taskId to strigified name
};

class Taskable;

class GlobalTask : public RCValue {
friend class CompareByDueDate;
friend class CompareByPriority;
friend class ExecutorPool;
friend class ExecutorThread;
public:

    GlobalTask(Taskable& t, const Priority &p,
               double sleeptime = 0, bool completeBeforeShutdown = true);

    /* destructor */
    virtual ~GlobalTask(void) {
    }

    /**
     * The invoked function when the task is executed.
     *
     * @return Whether or not this task should be rescheduled
     */
    virtual bool run(void) = 0;

    /**
     * Gives a description of this task.
     *
     * @return A description of this task
     */
    virtual std::string getDescription(void) = 0;

    virtual int maxExpectedDuration(void) {
        return 3600;
    }

    /**
     * test if a task is dead
     */
     bool isdead(void) {
        return (state == TASK_DEAD);
     }


    /**
     * Cancels this task by marking it dead.
     */
    void cancel(void) {
        state = TASK_DEAD;
    }

    /**
     * Puts the task to sleep for a given duration.
     */
    virtual void snooze(const double secs);

    /**
     * Returns the id of this task.
     *
     * @return A unique task id number.
     */
    size_t getId() const { return taskId; }

    /**
     * Returns the type id of this task.
     *
     * @return A type id of the task.
     */
    type_id_t getTypeId() { return priority.getTypeId(); }

    task_state_t getState(void) {
        return state.load();
    }

    void setState(task_state_t tstate, task_state_t expected) {
        state.compare_exchange_strong(expected, tstate);
    }

    Taskable& getTaskable() const {
        return taskable;
    }

    hrtime_t getWaketime() const {
        return waketime.load();
    }

    void updateWaketime(hrtime_t to) {
        waketime.store(to);
    }

    void updateWaketimeIfLessThan(hrtime_t to) {
        atomic_setIfBigger(waketime, to);
    }

protected:
    const Priority &priority;
    bool blockShutdown;
    std::atomic<task_state_t> state;
    const size_t taskId;
    Taskable& taskable;

    static std::atomic<size_t> task_id_counter;
    static size_t nextTaskId() { return task_id_counter.fetch_add(1); }


private:
    std::atomic<hrtime_t> waketime;      // used for priority_queue
};

typedef SingleThreadedRCPtr<GlobalTask> ExTask;

/**
 * Order tasks by their priority and taskId (try to ensure FIFO)
 */
class CompareByPriority {
public:
    bool operator()(ExTask &t1, ExTask &t2) {
        return (t1->priority == t2->priority) ?
               (t1->taskId   > t2->taskId)    :
               (t1->priority < t2->priority);
    }
};

/**
 * Order tasks by their ready date.
 */
class CompareByDueDate {
public:
    bool operator()(ExTask &t1, ExTask &t2) {
        return t2->waketime < t1->waketime;
    }
};
