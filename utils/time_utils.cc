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

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <chrono>

#if defined(__APPLE__)
#include <mach/mach_time.h>
#endif

#ifndef _PLATFORM_LIB_AVAILABLE
extern "C" hrtime_t gethrtime(void)
{
    auto now = std::chrono::high_resolution_clock::now();
    return std::chrono::duration_cast<std::chrono::nanoseconds>(now.time_since_epoch()).count();
}

extern "C" hrtime_t gethrtime_period(void)
{
    std::chrono::nanoseconds ns = std::chrono::high_resolution_clock::duration(1);
    return ns.count();
}
#endif // _PLATFORM_LIB_AVAILABLE

#if defined(WIN32) || defined(_WIN32)

#ifndef _PLATFORM_LIB_AVAILABLE
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
#endif // _PLATFORM_LIB_AVAILABLE

#else
#include <unistd.h>

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

uint64_t timeval_to_us(struct timeval tv)
{
    return (uint64_t)tv.tv_sec * 1000000 + tv.tv_usec;
}

void decaying_usleep(unsigned int *sleep_time, unsigned int max_sleep_time) {
    usleep(*sleep_time);
    *sleep_time = *sleep_time << 1;
    if (max_sleep_time < *sleep_time) {
        *sleep_time = max_sleep_time;
    }
}

/*
    return a monotonically increasing value with a seconds frequency.
*/
ts_nsec get_monotonic_ts() {
    ts_nsec ts = 0;
#if defined(WIN32)
    LARGE_INTEGER _ts;
    QueryPerformanceCounter(&_ts);
    ts = _ts.QuadPart;
#elif defined(__APPLE__)
    long time = mach_absolute_time();

    static mach_timebase_info_data_t timebase;
    if (timebase.denom == 0) {
      mach_timebase_info(&timebase);
    }

    ts = (double)time * timebase.numer / timebase.denom;
#elif defined(__linux__) || defined(__sun) || defined(__FreeBSD__)
    /* Linux and Solaris can use clock_gettime */
    struct timespec tm;
    if (clock_gettime(CLOCK_MONOTONIC, &tm) == -1) {
        abort();
    }
    ts = tm.tv_nsec;
#else
#error "Don't know how to build get_monotonic_ts"
#endif

    return ts;
}

ts_nsec ts_diff(ts_nsec start, ts_nsec end)
{
    ts_nsec diff = 0;
    if ((end-start)<0) {
        diff  = 1000000000+end-start;
    } else {
        diff = end-start;
    }
#if defined(WIN32)
    LARGE_INTEGER Pf;
    QueryPerformanceFrequency(&Pf);
    return diff / (Pf.QuadPart/1000000);
#else
    return diff/1000;
#endif // defined(WIN32)
}
