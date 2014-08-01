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

#ifndef _JSAHN_ARCH_H
#define _JSAHN_ARCH_H

#define __STDC_FORMAT_MACROS

#include <stdio.h>
#include <fcntl.h>

#include "forestdb_endian.h"
/* Large File Support */
#define _LARGE_FILE 1
#ifndef _FILE_OFFSET_BITS
#  define _FILE_OFFSET_BITS 64
#elif (_FILE_OFFSET_BITS != 64)
#error "bad things"
#endif
#define _LARGEFILE_SOURCE 1
#ifndef O_LARGEFILE
# define O_LARGEFILE 0
#endif

#ifndef _MSC_VER
#include <stdbool.h>
#else
#ifndef __cplusplus
#pragma once
#define false (0)
#define true (1)
#define bool int
#endif
#endif

#ifdef __APPLE__
    #include <inttypes.h>
    #include <alloca.h>
    #include <TargetConditionals.h>

    #define INLINE extern inline

    #define _X64 "llx"
    #define _F64 "lld"
    #define _FSEC "ld"
    #define _FUSEC "d"

    #define _ARCH_O_DIRECT (0x0)

    #if TARGET_CPU_ARM
    #define _ALIGN_MEM_ACCESS
    #endif

    #define malloc_align(addr, align, size) \
        {int __ret__=0; __ret__=posix_memalign(&(addr), (align), (size));}
    #define free_align(addr) free(addr)

    #ifndef spin_t
        // spinlock
        #include <libkern/OSAtomic.h>
        #define spin_t OSSpinLock
        #define spin_lock(arg) OSSpinLockLock(arg)
        #define spin_unlock(arg) OSSpinLockUnlock(arg)
        #define SPIN_INITIALIZER (spin_t)(0)
        #define spin_init(arg) *(arg) = (spin_t)(0)
        #define spin_destroy(arg)
    #endif
    #ifndef mutex_t
        // mutex
        #include <pthread.h>
        #define mutex_t pthread_mutex_t
        #define mutex_init(arg) pthread_mutex_init(arg, NULL)
        #define mutex_lock(arg) pthread_mutex_lock(arg)
        #define mutex_unlock(arg) pthread_mutex_unlock(arg)
        #define MUTEX_INITIALIZER PTHREAD_MUTEX_INITIALIZER
        #define mutex_destroy(arg) pthread_mutex_destroy(arg)
    #endif
    #ifndef thread_t
            // thread
        #include <pthread.h>
        #define thread_t pthread_t
        #define thread_cond_t pthread_cond_t
        #define thread_create(tid, func, args) \
            pthread_create((tid), NULL, (func), (args))
        #define thread_join(tid, ret) pthread_join(tid, ret)
        #define thread_cancel(tid) pthread_cancel(tid)
        #define thread_exit(code) pthread_exit(code)
        #define thread_cond_init(cond) pthread_cond_init(cond, NULL)
        #define thread_cond_destroy(cond) pthread_cond_destroy(cond)
        #define thread_cond_wait(cond, mutex) pthread_cond_wait(cond, mutex)
        #define thread_cond_timedwait(cond, mutex, ms) \
            { \
            struct timespec ts = convert_reltime_to_abstime(ms); \
            pthread_cond_timedwait(cond, mutex, &ts); \
            }
        #define thread_cond_signal(cond) pthread_cond_signal(cond)
        #define thread_cond_broadcast(cond) pthread_cond_broadcast(cond)
    #endif

#elif __ANDROID__
    #include <inttypes.h>
    #include <alloca.h>

    #define INLINE __inline

    #define _X64 "llx"
    #define _F64 "lld"
    #define _FSEC "ld"
    #define _FUSEC "ld"

    #define _ARCH_O_DIRECT (O_DIRECT)
    #define malloc_align(addr, align, size) \
        (addr = memalign((align), (size)))
    #define free_align(addr) free(addr)

    #ifndef spin_t
        // spinlock
        #include <pthread.h>
        #define spin_t pthread_mutex_t
        #define spin_init(arg) pthread_mutex_init(arg, NULL)
        #define spin_lock(arg) pthread_mutex_lock(arg)
        #define spin_unlock(arg) pthread_mutex_unlock(arg)
        #define spin_destroy(arg) pthread_mutex_destroy(arg)
        #define SPIN_INITIALIZER ((spin_t)PTHREAD_MUTEX_INITIALIZER)
    #endif
    #ifndef mutex_t
        // mutex
        #include <pthread.h>
        #define mutex_t pthread_mutex_t
        #define mutex_init(arg) pthread_mutex_init(arg, NULL)
        #define mutex_lock(arg) pthread_mutex_lock(arg)
        #define mutex_unlock(arg) pthread_mutex_unlock(arg)
        #define MUTEX_INITIALIZER PTHREAD_MUTEX_INITIALIZER
        #define mutex_destroy(arg) pthread_mutex_destroy(arg)
    #endif
    #ifndef thread_t
        // thread
        #include <pthread.h>
        #define thread_t pthread_t
        #define thread_cond_t pthread_cond_t
        #define thread_create(tid, func, args) \
            pthread_create((tid), NULL, (func), (args))
        #define thread_join(tid, ret) pthread_join(tid, ret)
        #define thread_cancel(tid) pthread_cancel(tid)
        #define thread_exit(code) pthread_exit(code)
        #define thread_cond_init(cond) pthread_cond_init(cond, NULL)
        #define thread_cond_destroy(cond) pthread_cond_destroy(cond)
        #define thread_cond_wait(cond, mutex) pthread_cond_wait(cond, mutex)
        #define thread_cond_timedwait(cond, mutex, ms) \
            { \
            struct timespec ts = convert_reltime_to_abstime(ms); \
            pthread_cond_timedwait(cond, mutex, &ts); \
            }
        #define thread_cond_signal(cond) pthread_cond_signal(cond)
        #define thread_cond_broadcast(cond) pthread_cond_broadcast(cond)
    #endif

    #ifdef assert
        #undef assert
    #endif
    #define assert(a) (a)

#elif __linux__
    #include <inttypes.h>
    #include <alloca.h>

    #define INLINE __inline

    #define _X64 PRIx64
    #define _F64 PRIu64
    #define _FSEC "ld"
    #define _FUSEC "ld"

    #define _ARCH_O_DIRECT (O_DIRECT)

    #define malloc_align(addr, align, size) \
        {int __ret__=0; __ret__=posix_memalign(&(addr), (align), (size));}
    #define free_align(addr) free(addr)

    #ifndef spin_t
        // spinlock
        #include <pthread.h>
        #define spin_t pthread_spinlock_t
        #define spin_init(arg) pthread_spin_init(arg, PTHREAD_PROCESS_SHARED)
        #define spin_lock(arg) pthread_spin_lock(arg)
        #define spin_unlock(arg) pthread_spin_unlock(arg)
        #define spin_destroy(arg) pthread_spin_destroy(arg)
        #define SPIN_INITIALIZER (spin_t)(1)
    #endif
    #ifndef mutex_t
        // mutex
        #include <pthread.h>
        #define mutex_t pthread_mutex_t
        #define mutex_init(arg) pthread_mutex_init(arg, NULL)
        #define mutex_lock(arg) pthread_mutex_lock(arg)
        #define mutex_unlock(arg) pthread_mutex_unlock(arg)
        #define MUTEX_INITIALIZER PTHREAD_MUTEX_INITIALIZER
        #define mutex_destroy(arg) pthread_mutex_destroy(arg)
    #endif
    #ifndef thread_t
        // thread
        #include <pthread.h>
        #define thread_t pthread_t
        #define thread_cond_t pthread_cond_t
        #define thread_create(tid, func, args) \
            pthread_create((tid), NULL, (func), (args))
        #define thread_join(tid, ret) pthread_join(tid, ret)
        #define thread_cancel(tid) pthread_cancel(tid)
        #define thread_exit(code) pthread_exit(code)
        #define thread_cond_init(cond) pthread_cond_init(cond, NULL)
        #define thread_cond_destroy(cond) pthread_cond_destroy(cond)
        #define thread_cond_wait(cond, mutex) pthread_cond_wait(cond, mutex)
        #define thread_cond_timedwait(cond, mutex, ms) \
            { \
            struct timespec ts = convert_reltime_to_abstime(ms); \
            pthread_cond_timedwait(cond, mutex, &ts); \
            }
        #define thread_cond_signal(cond) pthread_cond_signal(cond)
        #define thread_cond_broadcast(cond) pthread_cond_broadcast(cond)
    #endif

#elif defined(WIN32) || defined(_WIN32)
    // mingw compatiable

    #define _FSEC "ld"
    #define _FUSEC "ld"

    #define _ARCH_O_DIRECT (0x0)

#ifdef _MSC_VER
    // visual studio CL compiler
    #include <Windows.h>
    #include "gettimeofday_vs.h"
    #define INLINE static inline
    //#define alloca(size) _alloca(size)
    #define _X64 "llx"
    #define _F64 "llu"
    #define _CRT_SECURE_NO_WARNINGS
    #define gettimeofday gettimeofday_vs
    #define sleep(sec) Sleep((sec)*1000)
    typedef unsigned long mode_t;
    #include <BaseTsd.h>
    typedef SSIZE_T ssize_t;
#else
    #include <inttypes.h>
    #include <windows.h>
    #define _X64 PRIx64
    #define _F64 PRIu64
    #define INLINE __inline
#endif
    #include <stdint.h>
    #include <stdlib.h>
    #define malloc_align(addr, align, size) \
        (addr = (void*)_aligned_malloc((size), (align)))
    #define free_align(addr) _aligned_free(addr)

    #ifndef spin_t
        // spinlock
        #define spin_t CRITICAL_SECTION
        #define spin_init(arg) InitializeCriticalSection(arg)
        #define spin_lock(arg) EnterCriticalSection(arg)
        #define spin_unlock(arg) LeaveCriticalSection(arg)
        #define spin_destroy(arg) DeleteCriticalSection(arg)
    #endif
    #ifndef mutex_t
        // mutex
        #define mutex_t CRITICAL_SECTION
        #define mutex_init(arg) InitializeCriticalSection(arg)
        #define mutex_lock(arg) EnterCriticalSection(arg)
        #define mutex_unlock(arg) LeaveCriticalSection(arg)
        #define mutex_destroy(arg) DeleteCriticalSection(arg)
    #endif
    #ifndef thread_t
        // thread
        #define thread_t HANDLE
        #define thread_cond_t CONDITION_VARIABLE
        #define thread_create(tid, func, args) \
            { \
            DWORD __dt__; \
            *(tid) = CreateThread(NULL, 0, \
                (LPTHREAD_START_ROUTINE)(func), (args), 0, &__dt__); \
            }
        #define thread_join(tid, ret) WaitForSingleObject(tid, INFINITE)
        #define thread_cancel(tid) TerminateThread(tid, 0);
        #define thread_exit(code) ExitThread(code)
        #define thread_cond_init(cond) InitializeConditionVariable(cond)
        #define thread_cond_destroy(cond) (void)cond
        #define thread_cond_wait(cond, mutex) SleepConditionVariableCS(cond, mutex, INFINITE)
        #define thread_cond_timedwait(cond, mutex, msec) \
            SleepConditionVariableCS(cond, mutex, msec)
        #define thread_cond_signal(cond) WakeConditionVariable(cond)
        #define thread_cond_broadcast(cond) WakeAllConditionVariable(cond)
    #endif

#elif __CYGWIN__
    // cygwin compatiable
    #include <inttypes.h>
    #include <alloca.h>

    #define INLINE __inline

    #define _X64 PRIx64
    #define _F64 PRIu64
    #define _FSEC "ld"
    #define _FUSEC "ld"

    #define _ARCH_O_DIRECT (0x0)

    #define malloc_align(addr, align, size) \
        (addr = memalign((align), (size)))
    #define free_align(addr) free(addr)

    #ifndef spin_t
        // spinlock
        #include <pthread.h>
        #define spin_t pthread_spinlock_t
        #define spin_init(arg) pthread_spin_init(arg, PTHREAD_PROCESS_SHARED)
        #define spin_lock(arg) pthread_spin_lock(arg)
        #define spin_unlock(arg) pthread_spin_unlock(arg)
        #define spin_destroy(arg) pthread_spin_destroy(arg)
        #define SPIN_INITIALIZER (spin_t)(1)
    #endif
    #ifndef mutex_t
        // mutex
        #include <pthread.h>
        #define mutex_t pthread_mutex_t
        #define mutex_init(arg) pthread_mutex_init(arg, NULL)
        #define mutex_lock(arg) pthread_mutex_lock(arg)
        #define mutex_unlock(arg) pthread_mutex_unlock(arg)
        #define MUTEX_INITIALIZER PTHREAD_MUTEX_INITIALIZER
        #define mutex_destroy(arg) pthread_mutex_destroy(arg)
    #endif
    #ifndef thread_t
        // thread
        #include <pthread.h>
        #define thread_t pthread_t
        #define thread_cond_t pthread_cond_t
        #define thread_create(tid, func, args) \
            pthread_create((tid), NULL, (func), (args))
        #define thread_join(tid, ret) pthread_join(tid, ret)
        #define thread_cancel(tid) pthread_cancel(tid)
        #define thread_exit(code) pthread_exit(code)
        #define thread_cond_init(cond) pthread_cond_init(cond, NULL)
        #define thread_cond_destroy(cond) pthread_cond_destroy(cond)
        #define thread_cond_wait(cond, mutex) pthread_cond_wait(cond, mutex)
        #define thread_cond_timedwait(cond, mutex, ms) \
            { \
            struct timespec ts = convert_reltime_to_abstime(ms); \
            pthread_cond_timedwait(cond, mutex, &ts); \
            }
        #define thread_cond_signal(cond) pthread_cond_signal(cond)
        #define thread_cond_broadcast(cond) pthread_cond_broadcast(cond)
    #endif

#else
    #define INLINE make_error
#endif

#endif
