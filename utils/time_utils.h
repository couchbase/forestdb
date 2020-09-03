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

#ifndef _JSAHN_TIME_UTILS_H
#define _JSAHN_TIME_UTILS_H

#include <time.h>
#if defined(WIN32) || defined(_WIN32)
#include <Windows.h>
#else
#include <sys/time.h>
#include <unistd.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

struct timeval _utime_gap(struct timeval a, struct timeval b);

#if defined(WIN32) || defined(_WIN32)
void usleep(unsigned int useconds);
#endif

void decaying_usleep(unsigned int *sleep_time, unsigned int max_sleep_time);

#if !defined(WIN32) && !defined(_WIN32)
struct timespec convert_reltime_to_abstime(unsigned int ms);
#endif

#ifdef __cplusplus
}
#endif

#endif

