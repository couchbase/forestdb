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

#ifndef SRC_PRIORITY_H_
#define SRC_PRIORITY_H_ 1

#include "common.h"

enum type_id_t {
    COMPACTOR_ID,
    BGFLUSHER_ID,
    MAX_TYPE_ID // Keep this as the last enum value
};

/**
 * Task priority definition.
 */
class Priority {
public:
    // Priorities for Read-only tasks

    // Priorities for Read-Write tasks
    static const Priority CompactorPriority;
    static const Priority BgFlusherPriority;

    // Priorities for NON-IO tasks

    bool operator==(const Priority &other) const {
        return other.getPriorityValue() == this->priority;
    }

    bool operator<(const Priority &other) const {
        return this->priority > other.getPriorityValue();
    }

    bool operator>(const Priority &other) const {
        return this->priority < other.getPriorityValue();
    }

    /**
     * Return the task name.
     *
     * @return a task name
     */
    static const char *getTypeName(const type_id_t i);

    /**
     * Return the type id representing a task
     *
     * @return type id
     */
    type_id_t getTypeId() const {
        return t_id;
    }

    /**
     * Return an integer value that represents a priority.
     *
     * @return a priority value
     */
    int getPriorityValue() const {
        return priority;
    }

    // gcc didn't like the idea of having a class with no constructor
    // available to anyone.. let's make it protected instead to shut
    // gcc up :(
protected:
    Priority(type_id_t id, int p) : t_id(id), priority(p) { }
    type_id_t t_id;
    int priority;

private:
    DISALLOW_COPY_AND_ASSIGN(Priority);
};

#endif  // SRC_PRIORITY_H_
