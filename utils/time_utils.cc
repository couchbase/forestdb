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

#include "time_utils.h"

#if defined(WIN32) || defined(_WIN32)
void usleep(unsigned int useconds)
{
    unsigned int msec = useconds / 1000;
    if (msec == 0) {
        msec = 1;
    }
    Sleep(msec);
}
#endif

void decaying_usleep(unsigned int *sleep_time, unsigned int max_sleep_time) {
    usleep(*sleep_time);
    *sleep_time = *sleep_time << 1;
    if (max_sleep_time < *sleep_time) {
        *sleep_time = max_sleep_time;
    }
}