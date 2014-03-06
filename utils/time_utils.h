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
#include <sys/time.h>

static struct timespec _ntime_gap(struct timespec a, struct timespec b)
{
    struct timespec ret;
    if (b.tv_nsec >= a.tv_nsec) {
        ret.tv_nsec = b.tv_nsec - a.tv_nsec;
        ret.tv_sec = b.tv_sec - a.tv_sec;
    }else{
        ret.tv_nsec = 1000000000 + b.tv_nsec - a.tv_nsec;
        ret.tv_sec = b.tv_sec - a.tv_sec - 1;
    }
    return ret;
}

static struct timeval _utime_gap(struct timeval a, struct timeval b)
{
    struct timeval ret;
    if (b.tv_usec >= a.tv_usec) {
        ret.tv_usec = b.tv_usec - a.tv_usec;
        ret.tv_sec = b.tv_sec - a.tv_sec;
    }else{
        ret.tv_usec = 1000000 + b.tv_usec - a.tv_usec;
        ret.tv_sec = b.tv_sec - a.tv_sec - 1;
    }
    return ret;
}

#endif

