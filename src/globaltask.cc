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

#include <limits.h>

#include "globaltask.h"

std::atomic<size_t> GlobalTask::task_id_counter(1);

GlobalTask::GlobalTask(Taskable& t, const Priority &p,
           double sleeptime, bool completeBeforeShutdown) :
      RCValue(), priority(p),
      blockShutdown(completeBeforeShutdown),
      state(TASK_RUNNING), taskId(nextTaskId()), taskable(t) {
    snooze(sleeptime);
}

void GlobalTask::snooze(const double secs) {
    if (secs == INT_MAX) {
        setState(TASK_SNOOZED, TASK_RUNNING);
        updateWaketime(hrtime_t(-1));
        return;
    }

    hrtime_t curTime = gethrtime();
    if (secs) {
        setState(TASK_SNOOZED, TASK_RUNNING);
        waketime.store(curTime + hrtime_t(secs * 1000000000));
    } else {
        waketime.store(curTime);
    }
}
