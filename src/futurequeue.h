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

/*
 * The FutureQueue provides a std::priority_queue style interface
 * onto a queue of ExTask objects that are sorted by the tasks wakeTime.
 * The lowest wakeTime will be the top() task.
 *
 * FutureQueue provides methods that allow a task's wakeTime to be mutated
 * whilst maintaining the priority ordering.
 */

#pragma once

#include <algorithm>
#include <mutex>
#include <queue>

#include "tasks.h"

template <class C = std::deque<ExTask>,
          class Compare = CompareByDueDate>
class FutureQueue {
public:

    void push(ExTask task) {
        std::lock_guard<std::mutex> lock(queueMutex);
        queue.push(task);
    }

    void pop() {
        std::lock_guard<std::mutex> lock(queueMutex);
        queue.pop();
    }

    ExTask top() {
        std::lock_guard<std::mutex> lock(queueMutex);
        return queue.top();
    }

    size_t size() {
        std::lock_guard<std::mutex> lock(queueMutex);
        return queue.size();
    }

    bool empty() {
        std::lock_guard<std::mutex> lock(queueMutex);
        return queue.empty();
    }

    /*
     * Update the wakeTime of task and ensure the heap property is
     * maintained.
     * @returns true if 'task' is in the FutureQueue.
     */
    bool updateWaketime(const ExTask& task, hrtime_t newTime) {
        std::lock_guard<std::mutex> lock(queueMutex);
        task->updateWaketime(newTime);
        // After modifiying the task's wakeTime, rebuild the heap
        return queue.heapify(task);
    }

    /*
     * snooze the task (by altering its wakeTime) and ensure the
     * heap property is maintained.
     * @returns true if 'task' is in the FutureQueue.
     */
    bool snooze(const ExTask& task, const double secs) {
        std::lock_guard<std::mutex> lock(queueMutex);
        task->snooze(secs);
        // After modifiying the task's wakeTime, rebuild the heap
        return queue.heapify(task);
    }

protected:

    /*
     * HeapifiableQueue exposes a method to maintain the heap ordering
     * of the underlying queue.
     *
     * This class is deliberately hidden inside FutureQueue so that any
     * extensions made to priority_queue can't be accessed without work.
     * I.e. correct locking and any need to 'heapify'.
     */
    class HeapifiableQueue : public std::priority_queue<ExTask, C, Compare> {
    public:
        /*
         * Ensure the heap property is maintained
         * @returns true if 'task' is in the queue and heapify() did something.
         */
        bool heapify(const ExTask& task) {
            // if the task exists, rebuild
            if (exists(task)) {
                if (this->c.back()->getId() == task->getId()) {
                    std::push_heap(this->c.begin(),
                                   this->c.end(),
                                   this->comp);
                } else {
                    std::make_heap(this->c.begin(),
                                   this->c.end(),
                                   this->comp);
                }
                return true;
            } else {
                return false;
            }
        }

    protected:
        bool exists(const ExTask& task) {
            return std::find_if(this->c.begin(),
                                this->c.end(),
                                [&task](const ExTask& qTask) {
                                    return task->getId() == qTask->getId();
                                }) != this->c.end();
        }

    } queue;

    // All access to queue must be done with the queueMutex
    std::mutex queueMutex;
};
