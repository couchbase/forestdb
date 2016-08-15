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

#pragma once

#if defined(WIN32) || defined(_WIN32)
#include <winsock2.h>
#include <Windows.h>
#else
#include <sys/time.h>
#include <unistd.h>
#endif
#include <time.h>
#include "stdint.h"

#ifndef hrtime_t
#include <stdint.h>
  typedef uint64_t hrtime_t;
#endif //ifndef hrtime_t

#ifndef _PLATFORM_LIB_AVAILABLE
extern "C" hrtime_t gethrtime(void);
extern "C" hrtime_t gethrtime_period(void);
#endif

typedef  long int ts_nsec;
ts_nsec get_monotonic_ts();
ts_nsec ts_diff(ts_nsec start, ts_nsec end);

struct timeval _utime_gap(struct timeval a, struct timeval b);
uint64_t timeval_to_us(struct timeval tv);

#if defined(WIN32) || defined(_WIN32)
#ifdef _PLATFORM_LIB_AVAILABLE
#include <platform/platform.h>
#else
// If platform library has not been included, usleep
// needs to be explicitly defined for windows.
void usleep(unsigned int useconds);
#endif // _PLATFORM_LIB_AVAILABLE
#endif // defined(WIN32) || defined(_WIN32)

void decaying_usleep(unsigned int *sleep_time, unsigned int max_sleep_time);

#if !defined(WIN32) && !defined(_WIN32)
struct timespec convert_reltime_to_abstime(unsigned int ms);
#endif

