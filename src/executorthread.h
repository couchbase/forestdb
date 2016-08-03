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

#ifndef SRC_SCHEDULER_H_
#define SRC_SCHEDULER_H_ 1

#include "common.h"

#include <atomic>
#include <deque>
#include <list>
#include <map>
#include <queue>
#include <string>
#include <utility>
#include <vector>

#include "tasks.h"
#include "task_type.h"

#define LOG(...)
#define MIN_SLEEP_TIME 2.0

class ExecutorPool;
class ExecutorThread;
class TaskQueue;
class WorkLoadPolicy;

enum executor_state_t {
    EXECUTOR_RUNNING,
    EXECUTOR_WAITING,
    EXECUTOR_SLEEPING,
    EXECUTOR_SHUTDOWN,
    EXECUTOR_DEAD
};


class ExecutorThread {
    friend class ExecutorPool;
    friend class TaskQueue;
public:

    ExecutorThread(ExecutorPool *m, int startingQueue,
                   const std::string nm) : manager(m),
          startIndex(startingQueue), name(nm),
          state(EXECUTOR_RUNNING), taskStart(0),
          currentTask(NULL), curTaskType(NO_TASK_TYPE) {
              now = gethrtime();
              waketime = hrtime_t(-1);
    }

    ~ExecutorThread() {
        LOG(EXTENSION_LOG_INFO, "Executor killing %s", name.c_str());
    }

    void start(void);

    void run(void);

    void stop(bool wait=true);

    void schedule(ExTask &task);

    void reschedule(ExTask &task);

    void wake(ExTask &task);

    // Changes this threads' current task to the specified task
    void setCurrentTask(ExTask newTask);

    const std::string& getName() const { return name; }

    const std::string getTaskName() {
        LockHolder lh(currentTaskMutex);
        if (currentTask) {
            return currentTask->getDescription();
        } else {
            return std::string("Not currently running any task");
        }
    }

    const std::string getTaskableName() {
        LockHolder lh(currentTaskMutex);
        if (currentTask) {
            return currentTask->getTaskable().getName();
        } else {
            return std::string();
        }
    }

    hrtime_t getTaskStart() const { return taskStart; }

    const std::string getStateName();

    const hrtime_t getWaketime(void) { return waketime; }

    const hrtime_t getCurTime(void) { return now; }

protected:

    thread_t thread;
    ExecutorPool *manager;
    int startIndex;
    const std::string name;
    std::atomic<executor_state_t> state;

    std::atomic<hrtime_t> now;  // record of current time
    std::atomic<hrtime_t> waketime; // set to the earliest

    std::atomic<hrtime_t> taskStart;

    std::mutex currentTaskMutex; // Protects currentTask
    ExTask currentTask;

    task_type_t curTaskType;

    std::mutex logMutex;
};

#endif  // SRC_SCHEDULER_H_
