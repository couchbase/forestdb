/* -*- Mode: C++; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2015 Couchbase, Inc
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
    An abstract baseclass for classes which wish to create and own tasks.
*/

#pragma once

#include "workload.h"
#include "task_priority.h"

/*
    A type for identifying all tasks belonging to a task owner.
*/
typedef uintptr_t task_gid_t;

class Taskable {
public:
    /*
        Return a name for the task, used for logging
    */
    virtual const std::string& getName() const = 0;

    /*
        Return a 'group' ID for the task.

        The use-case here is to allow the lookup of all tasks
        owned by this taskable.

        The address of the object is a safe GID.
    */
    virtual task_gid_t getGID() const = 0;

    /*
        Return the workload priority for the task
    */
    virtual bucket_priority_t getWorkloadPriority() const = 0;

    /*
        Set the taskable object's workload priority.
    */
    virtual void setWorkloadPriority(bucket_priority_t prio) = 0;

    /*
        Return the taskable object's workload policy.
    */
    virtual WorkLoadPolicy& getWorkLoadPolicy() = 0;

    /*
        Called with the time spent queued
    */
    virtual void logQTime(type_id_t taskType, hrtime_t enqTime) = 0;

    /*
        Called with the time spent running
    */
    virtual void logRunTime(type_id_t taskType, hrtime_t runTime) = 0;

protected:
    virtual ~Taskable() {}
};
