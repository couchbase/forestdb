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

#ifndef _JSAHN_STOPWATCH_H
#define _JSAHN_STOPWATCH_H

#include <sys/time.h>

struct stopwatch {
    struct timeval elapsed;
    struct timeval start;
};

void stopwatch_init(struct stopwatch *sw);
void stopwatch_start(struct stopwatch *sw);
int stopwatch_check_ms(struct stopwatch *sw, size_t ms);
int stopwatch_check_us(struct stopwatch *sw, size_t us);
struct timeval stopwatch_stop(struct stopwatch *sw);

#endif
