/* -*- Mode: C++; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2016 Couchbase, Inc
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

#include <mutex>
#include <sstream>
#include <string>
#include <vector>

#include "atomic.h"
#include "executorpool.h"
#include "globaltask.h"
#include "taskable.h"

#include "stat_aggregator.h"
#include "test.h"

#define MAX_SNOOZE 3

// _num_tasks_ to always be the last entry of the following
// enum class to estimate the number of tasks
enum test_task_type_t {
    REGULAR_TASK,
    RECURRING_TASK,
    _num_tasks_
};

/**
 * Each entry in the vector maintained by the Task Tracker.
 */
struct TaskEntry {
    TaskEntry(test_task_type_t _type,
              size_t _taskid,
              int _priority,
              ts_nsec _scheduletime,
              double _initialsnooze,
              ts_nsec _runtime) {
        type = _type;
        taskid = _taskid;
        priority = _priority;
        scheduletime = _scheduletime;
        initialsnooze = _initialsnooze;
        runtime = _runtime;
    }

    test_task_type_t type;
    size_t taskid;
    int priority;
    ts_nsec scheduletime;
    double initialsnooze;
    ts_nsec runtime;
};

/**
 * Callback definition for task_vector scan operation
 */
typedef void task_vector_scan_cb(TaskEntry *te, void *ctx);

/**
 * This class maintains a vector of task entries, and will primarily
 * be used to track the task execution order.
 */
class TaskTracker {
public:
    TaskTracker() {
        spin_init(&task_vector_lock);
    }

    ~TaskTracker() {
        for (auto &it : task_vector) {
            delete it;
        }

        spin_destroy(&task_vector_lock);
    }

    void addEntry(test_task_type_t type, size_t id, int priority,
                  ts_nsec scheduletime, double initialsnooze,
                  ts_nsec runtime) {
        TaskEntry *te = new TaskEntry(type, id, priority,
                                      scheduletime, initialsnooze, runtime);
        spin_lock(&task_vector_lock);
        task_vector.push_back(te);
        spin_unlock(&task_vector_lock);
    }

    void scan(task_vector_scan_cb *scan_callback,
              void *ctx) {
        spin_lock(&task_vector_lock);
        std::vector<TaskEntry *> task_vector_copy(task_vector);
        spin_unlock(&task_vector_lock);

        for (auto &it : task_vector_copy) {
            scan_callback(it, ctx);
        }
    }

private:
    // Vector to track order of task execution
    std::vector<TaskEntry *> task_vector;
    // Spin lock for task_vector access
    spin_t task_vector_lock;
};

class FileEngine;

/**
 * Class that inherits taskable
 */
class EngineTaskable : public Taskable {
public:
    EngineTaskable(FileEngine *_fe)
        : fe(_fe) { }

    std::string& getName() const;

    task_gid_t getGID() const;

    bucket_priority_t getWorkloadPriority() const;

    void setWorkloadPriority(bucket_priority_t prio);

    WorkLoadPolicy& getWorkLoadPolicy();

    void logQTime(type_id_t tasktype, hrtime_t enqTime) { }

    void logRunTime(type_id_t tasktype, hrtime_t runTime) { }

private:
    FileEngine *fe;
};

/**
 * File engine structure
 */
class FileEngine {
public:
    FileEngine() :
        workload_priority(NO_BUCKET_PRIORITY),
        workload_policy(nullptr),
        et(this)
    { }

    FileEngine(std::string _name,
               bucket_priority_t _workload_priority,
               WorkLoadPolicy *_workload_policy)
        : name(_name),
          workload_priority(_workload_priority),
          workload_policy(_workload_policy),
          et(this)
    { }

    EngineTaskable& getTaskable() {
        return et;
    }

    std::string name;
    bucket_priority_t workload_priority;
    WorkLoadPolicy *workload_policy;

private:
    EngineTaskable et;
};

std::string& EngineTaskable::getName() const {
    return fe->name;
}

task_gid_t EngineTaskable::getGID() const {
    return reinterpret_cast<task_gid_t>(fe);
}

bucket_priority_t EngineTaskable::getWorkloadPriority() const {
    return fe->workload_priority;
}

void EngineTaskable::setWorkloadPriority(bucket_priority_t prio) {
    fe->workload_priority = prio;
}

WorkLoadPolicy& EngineTaskable::getWorkLoadPolicy() {
    return *fe->workload_policy;
}

class RegularTask : public GlobalTask {
public:
    RegularTask(EngineTaskable& e, TaskTracker *tt,
                const Priority &p, double sleep = 0.0/*seconds*/)
        : GlobalTask(e      /*Taskable:EngineTaskable*/,
                     p      /*Task priority*/,
                     sleep  /*Snooze after exec*/,
                     true   /*Complete before shutdown*/),
          taskTrack(tt),
          priority(p.getPriorityValue()),
          snoozeFor(sleep),
          scheduleTime(get_monotonic_ts())
    { }

    bool run() {
        taskTrack->addEntry(REGULAR_TASK, getId(), priority,
                            scheduleTime, snoozeFor, get_monotonic_ts());
        return false;
    }

    std::string getDescription() {
        std::stringstream ss;
        ss << "Running regular task of priority: " << priority;
        return ss.str();
    }

private:
    TaskTracker *taskTrack;
    int priority;
    double snoozeFor;
    ts_nsec scheduleTime;
};

std::atomic<int> recurringTaskIterations(0);

class RecurringTask : public GlobalTask {
public:
    RecurringTask(EngineTaskable& e, TaskTracker *tt,
                  const Priority &p, double sleep = 0.0/*seconds*/,
                  bool incrementCounter = false)
        : GlobalTask(e      /*Taskable:EngineTaskable*/,
                     p      /*Task priority*/,
                     sleep  /*Snooze after exec*/,
                     true   /*Complete before shutdown*/),
          taskTrack(tt),
          priority(p.getPriorityValue()),
          snoozeFor(sleep),
          doIncrementIterationCounter(incrementCounter),
          scheduleTime(get_monotonic_ts())
    { }

    bool run() {
        taskTrack->addEntry(RECURRING_TASK, getId(), priority,
                            scheduleTime, snoozeFor, get_monotonic_ts());
        if (doIncrementIterationCounter) {
            ++recurringTaskIterations;
        }
        snooze(snoozeFor);
        scheduleTime = get_monotonic_ts();
        return true;
    }

    std::string getDescription() {
        std::stringstream ss;
        ss << "Running recurring task of priority: " << priority;
        return ss.str();
    }

private:
    TaskTracker *taskTrack;
    int priority;
    double snoozeFor;
    bool doIncrementIterationCounter;
    ts_nsec scheduleTime;
};

int samples(0);
static std::mutex guard;

void collect_stat(StatAggregator *sa, test_task_type_t type,
                  uint64_t diff) {
    LockHolder lh(guard);
    sa->t_stats[type][0].latencies.push_back(diff);
    ++samples;
}

void task_entry_scanner(TaskEntry *te, void *ctx) {
    StatAggregator *statAgg = static_cast<StatAggregator *>(ctx);
    collect_stat(statAgg, te->type, te->runtime - te->scheduletime);
}

void regular_task_behavior_test(size_t num_threads,
                                size_t num_tasks,
                                bool check_task_order) {
    TEST_INIT();

    TaskTracker *tracker = new TaskTracker();
    StatAggregator *sa = new StatAggregator(1, 1);
    sa->t_stats[REGULAR_TASK][0].name = "regular_task";
    samples = 0;

    WorkLoadPolicy wlp(static_cast<int>(num_threads),
                       static_cast<int>(num_threads));
    FileEngine *fe = new FileEngine("REGULAR_TASK_ENGINE",
                                    LOW_BUCKET_PRIORITY,
                                    &wlp);

    threadpool_config config = {num_threads/*all writer threads*/};
    ExecutorPool::initExPool(config);
    ExecutorPool::get()->registerTaskable(fe->getTaskable());

    for (size_t i = 0; i < num_tasks; ++i) {
        ExTask task = new RegularTask(fe->getTaskable(),
                                      tracker,
                                      Priority::CompactorPriority/*TODO:task_order*/,
                                      check_task_order ? rand() % MAX_SNOOZE : 0);
        ExecutorPool::get()->schedule(task, WRITER_TASK_IDX);
    }

    /* Waits for all tasks to complete before shutdown */
    ExecutorPool::get()->unregisterTaskable(fe->getTaskable(), false/*force*/);
    ExecutorPool::shutdown();

    /* Terminate file engine */
    delete fe;

    tracker->scan(task_entry_scanner, sa);
    if (check_task_order) {
        sa->aggregateAndPrintStats("REGULAR_TASK_TEST (wait times)", samples, "ms");
    } else {
        sa->aggregateAndPrintStats("REGULAR_TASK_TEST (wait times)", samples, "µs");
    }

    delete sa;
    delete tracker;

    std::string title("Regular task behavior test - " +
                      std::to_string(num_threads) + " threads, " +
                      std::to_string(num_tasks) + " tasks");
    if (check_task_order) {
        title += " - With snooze times(0-2s)";
    } else {
        title += " - With snooze times(0s)";
    }
    TEST_RESULT(title.c_str());
}

void recurring_task_behavior_test(int runCount) {
    TEST_INIT();
    TaskTracker *tracker = new TaskTracker();

    WorkLoadPolicy wlp(1, 1);
    FileEngine *fe = new FileEngine("RECURRING_TASK_ENGINE",
                                    LOW_BUCKET_PRIORITY,
                                    &wlp);

    threadpool_config config = {1   /*one writer thread*/};
    ExecutorPool::initExPool(config);
    ExecutorPool::get()->registerTaskable(fe->getTaskable());

    recurringTaskIterations = 0;
    ExTask task = new RecurringTask(fe->getTaskable(),
                                    tracker,
                                    Priority::BgFlusherPriority,
                                    1   /*1 second*/,
                                    true /*increment iteration count*/);
    ExecutorPool::get()->schedule(task, WRITER_TASK_IDX);

    // Wait till the recurring task runs the desired number of times
    while (recurringTaskIterations.load() < runCount);

    /* Force shutdown */
    ExecutorPool::get()->unregisterTaskable(fe->getTaskable(), true/*force*/);
    ExecutorPool::shutdown();

    /* Terminate file engine */
    delete fe;

    delete tracker;

    TEST_RESULT("Recurring task behavior test");
}

void mixed_task_behavior_test(size_t num_threads,
                              size_t num_regular_tasks,
                              size_t num_recurring_tasks,
                              bool check_task_order) {
    TEST_INIT();

    TaskTracker *tracker = new TaskTracker();
    StatAggregator *sa = new StatAggregator(2, 1);
    sa->t_stats[REGULAR_TASK][0].name = "regular_task";
    sa->t_stats[RECURRING_TASK][0].name = "recurring_task";
    samples = 0;

    WorkLoadPolicy wlp(static_cast<int>(num_threads),
                       static_cast<int>(num_threads));
    FileEngine *fe = new FileEngine("MULTI_TASK_ENGINE",
                                    LOW_BUCKET_PRIORITY,
                                    &wlp);

    threadpool_config config = {num_threads/*all writer threads*/};
    ExecutorPool::initExPool(config);
    ExecutorPool::get()->registerTaskable(fe->getTaskable());

    size_t spawned_reg_tasks = 0, spawned_rec_tasks = 0;
    while (true) {
        if (spawned_reg_tasks < num_regular_tasks) {
            ExTask task = new RegularTask(fe->getTaskable(),
                                          tracker,
                                          Priority::CompactorPriority/*TODO:task_order*/,
                                          check_task_order ? rand() % MAX_SNOOZE : 0);
            ExecutorPool::get()->schedule(task, WRITER_TASK_IDX);
            ++spawned_reg_tasks;
        }

        if (spawned_rec_tasks < num_recurring_tasks) {
            ExTask task = new RecurringTask(fe->getTaskable(),
                                            tracker,
                                            Priority::CompactorPriority/*TODO:task_order*/,
                                            check_task_order ? rand() % MAX_SNOOZE : 0);
            ExecutorPool::get()->schedule(task, WRITER_TASK_IDX);
            ++spawned_rec_tasks;
        }

        if (spawned_reg_tasks == num_regular_tasks &&
            spawned_rec_tasks == num_recurring_tasks) {
            break;
        }
    }

    // Sleep for 20 seconds for atleast a few of re-runs
    // of the recurring tasks
    sleep(20);

    /* Force shutdown */
    ExecutorPool::get()->unregisterTaskable(fe->getTaskable(), true/*force*/);
    ExecutorPool::shutdown();

    /* Terminate file engine */
    delete fe;

    tracker->scan(task_entry_scanner, sa);
    if (check_task_order) {
        sa->aggregateAndPrintStats("MIXED_TASK_TEST (wait times)", samples, "ms");
    } else {
        sa->aggregateAndPrintStats("MIXED_TASK_TEST (wait times)", samples, "µs");
    }

    delete sa;
    delete tracker;

    std::string title("Mixed task behavior test - " +
                      std::to_string(num_threads) + " threads, " +
                      std::to_string(num_regular_tasks) + " reg. tasks, " +
                      std::to_string(num_recurring_tasks) + " recur. tasks");
    if (check_task_order) {
        title += " - With snooze times(0-2s)";
    } else {
        title += " - With snooze times(0s)";
    }
    TEST_RESULT(title.c_str());
}

int main() {

    regular_task_behavior_test(4        /* num threads */,
                               100      /* num tasks */,
                               false    /* no check for task ordering */);

    regular_task_behavior_test(4        /* num threads */,
                               100      /* num tasks */,
                               true     /* check task ordering */);

    recurring_task_behavior_test(10);   /* desired number of iterations */

    mixed_task_behavior_test(4          /* num threads */,
                             50         /* num regular tasks */,
                             10         /* num recurring tasks */,
                             false      /* no check for task ordering */);

    mixed_task_behavior_test(4          /* num threads */,
                             50         /* num regular tasks */,
                             10         /* num recurring tasks */,
                             true       /* check for task ordering */);

    return 0;
}
