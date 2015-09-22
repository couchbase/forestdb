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
#include "stdint.h"
#include "string.h"

struct timeval _utime_gap(struct timeval a, struct timeval b)
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

#if defined(WIN32) || defined(_WIN32)

void usleep(unsigned int usec)
{
    HANDLE timer;
    LARGE_INTEGER ft;

    // Convert to 100 nanosecond interval, negative value indicates relative time
    ft.QuadPart = -(10*usec);

    timer = CreateWaitableTimer(NULL, TRUE, NULL);
    SetWaitableTimer(timer, &ft, 0, NULL, NULL, 0);
    WaitForSingleObject(timer, INFINITE);
    CloseHandle(timer);
}

#else

struct timespec convert_reltime_to_abstime(unsigned int ms) {
    struct timespec ts;
    struct timeval tp;
    uint64_t wakeup;

    memset(&ts, 0, sizeof(ts));

    /*
     * Unfortunately pthread_cond_timedwait doesn't support relative sleeps
     * so we need to convert back to an absolute time.
     */
    gettimeofday(&tp, NULL);
    wakeup = ((uint64_t)(tp.tv_sec) * 1000) + (tp.tv_usec / 1000) + ms;
    /* Round up for sub ms */
    if ((tp.tv_usec % 1000) > 499) {
        ++wakeup;
    }

    ts.tv_sec = wakeup / 1000;
    wakeup %= 1000;
    ts.tv_nsec = wakeup * 1000000;
    return ts;
}
#endif //!defined(WIN32) && !defined(_WIN32)

void decaying_usleep(unsigned int *sleep_time, unsigned int max_sleep_time) {
    usleep(*sleep_time);
    *sleep_time = *sleep_time << 1;
    if (max_sleep_time < *sleep_time) {
        *sleep_time = max_sleep_time;
    }
}
