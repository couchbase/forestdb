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

#ifndef __STDC_FORMAT_MACROS
#define __STDC_FORMAT_MACROS
#endif

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

    #ifdef HAVE_JEMALLOC
    // string has some memory allocators of its own which MUST come first
    // in the include order to ensure that je_malloc can correctly override
    // the string malloc and free definitions too, otherwise we can have
    // asymmetrical operation resulting in crashes.
    // TODO: We plan to address this in a modularized way in the future.
    #include <string>
    #include <jemalloc/jemalloc.h>
    #define malloc(size) je_malloc(size)
    #define calloc(nmemb, size) je_calloc(nmemb, size)
    #define realloc(ptr, size) je_realloc(ptr, size)
    #define free(addr) je_free(addr)
    #define posix_memalign(memptr, alignment, size)\
                           je_posix_memalign(memptr, alignment, size)
    #define memalign(alignment, size) je_memalign(alignment, size)
    #define aligned_malloc(size, align) je_aligned_malloc(size, align)
    #define aligned_free(addr) je_aligned_free(addr)
    #endif //HAVE_JEMALLOC

    #define malloc_align(addr, align, size) \
        {int __ret__; __ret__=posix_memalign(&(addr), (align), (size));\
         (void)__ret__;}
    #define free_align(addr) free(addr)

    #ifndef spin_t
        // spinlock
        #include <libkern/OSAtomic.h>
        #define spin_t OSSpinLock
        #define spin_lock(arg) OSSpinLockLock(arg)
        #define spin_trylock(arg) OSSpinLockTry(arg)
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
        #define mutex_trylock(arg) \
            (pthread_mutex_trylock(arg) == 0)
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

    #define INLINE static __inline

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
        #define spin_trylock(arg) \
            (pthread_mutex_trylock(arg) == 0)
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
        #define mutex_trylock(arg) \
            (pthread_mutex_trylock(arg) == 0)
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

#elif __linux__ && __arm__
    #include <inttypes.h>
    #include <alloca.h>

    #define INLINE static __inline

    #define _X64 "llx"
    #define _F64 "lld"
    #define _FSEC "ld"
    #define _FUSEC "ld"

    #define _ARCH_O_DIRECT (O_DIRECT)
    #define malloc_align(addr, align, size) \
        (addr = memalign((align), (size)))
    #define free_align(addr) free(addr)


    #ifdef HAVE_JEMALLOC
    // string has some memory allocators of its own which MUST come first
    // in the include order to ensure that je_malloc can correctly override
    // the string malloc and free definitions too, otherwise we can have
    // asymmetrical operation resulting in crashes.
    // TODO: We plan to address this in a modularized way in the future.
    #include <string>
    #include <jemalloc/jemalloc.h>
    #define malloc(size) je_malloc(size)
    #define calloc(nmemb, size) je_calloc(nmemb, size)
    #define realloc(ptr, size) je_realloc(ptr, size)
    #define free(addr) je_free(addr)
    #define posix_memalign(memptr, alignment, size)\
                           je_posix_memalign(memptr, alignment, size)
    #define memalign(alignment, size) je_memalign(alignment, size)
    #define aligned_malloc(size, align) je_aligned_malloc(size, align)
    #define aligned_free(addr) je_aligned_free(addr)
    #endif //HAVE_JEMALLOC

    #ifndef spin_t
        // spinlock
        #include <pthread.h>
        #define spin_t pthread_spinlock_t
        #define spin_init(arg) pthread_spin_init(arg, PTHREAD_PROCESS_SHARED)
        #define spin_lock(arg) pthread_spin_lock(arg)
        #define spin_trylock(arg) \
            (pthread_spin_trylock(arg) == 0)
        #define spin_unlock(arg) pthread_spin_unlock(arg)
        #define spin_destroy(arg) pthread_spin_destroy(arg)
        #define SPIN_INITIALIZER (spin_t)(0)
    #endif
    #ifndef mutex_t
        // mutex
        #include <pthread.h>
        #define mutex_t pthread_mutex_t
        #define mutex_init(arg) pthread_mutex_init(arg, NULL)
        #define mutex_lock(arg) pthread_mutex_lock(arg)
        #define mutex_trylock(arg) \
            (pthread_mutex_trylock(arg) == 0)
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

#elif __linux__
    #include <inttypes.h>
    #include <alloca.h>

    #define INLINE __inline

    #define _X64 PRIx64
    #define _F64 PRIu64
    #define _FSEC "ld"
    #define _FUSEC "ld"

    #define _ARCH_O_DIRECT (O_DIRECT)

    #ifdef HAVE_JEMALLOC
    // string has some memory allocators of its own which MUST come first
    // in the include order to ensure that je_malloc can correctly override
    // the string malloc and free definitions too, otherwise we can have
    // asymmetrical operation resulting in crashes.
    // TODO: We plan to address this in a modularized way in the future.
    #include <string>
    #include <jemalloc/jemalloc.h>
    #define malloc(size) je_malloc(size)
    #define calloc(nmemb, size) je_calloc(nmemb, size)
    #define realloc(ptr, size) je_realloc(ptr, size)
    #define free(addr) je_free(addr)
    #define posix_memalign(memptr, alignment, size)\
                           je_posix_memalign(memptr, alignment, size)
    #define memalign(alignment, size) je_memalign(alignment, size)
    #define aligned_malloc(size, align) je_aligned_malloc(size, align)
    #define aligned_free(addr) je_aligned_free(addr)
    #endif //HAVE_JEMALLOC

    #define malloc_align(addr, align, size) \
        {int __ret__; __ret__=posix_memalign(&(addr), (align), (size));\
         (void)__ret__;}
    #define free_align(addr) free(addr)

    #ifndef spin_t
        // spinlock
        #include <pthread.h>
        #define spin_t pthread_spinlock_t
        #define spin_init(arg) pthread_spin_init(arg, PTHREAD_PROCESS_SHARED)
        #define spin_lock(arg) pthread_spin_lock(arg)
        #define spin_trylock(arg) \
            (pthread_spin_trylock(arg) == 0)
        #define spin_unlock(arg) pthread_spin_unlock(arg)
        #define spin_destroy(arg) pthread_spin_destroy(arg)
        #ifdef __GLIBC__
            #define SPIN_INITIALIZER (spin_t)(1)
        #else
            #define SPIN_INITIALIZER (spin_t)(0)
        #endif
    #endif
    #ifndef mutex_t
        // mutex
        #include <pthread.h>
        #define mutex_t pthread_mutex_t
        #define mutex_init(arg) pthread_mutex_init(arg, NULL)
        #define mutex_lock(arg) pthread_mutex_lock(arg)
        #define mutex_trylock(arg) \
            (pthread_mutex_trylock(arg) == 0)
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
            { \
            pthread_attr_t attr; \
            pthread_attr_init(&attr); \
            pthread_attr_setstacksize(&attr, 2097152); \
            pthread_create((tid), &attr, (func), (args)); \
            }
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
#ifndef _CRT_SECURE_NO_WARNINGS
    #define _CRT_SECURE_NO_WARNINGS
#endif
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
        #define spin_trylock(arg) TryEnterCriticalSection(arg)
        #define spin_unlock(arg) LeaveCriticalSection(arg)
        #define spin_destroy(arg) DeleteCriticalSection(arg)
    #endif
    #ifndef mutex_t
        // mutex
        #define mutex_t CRITICAL_SECTION
        #define mutex_init(arg) InitializeCriticalSection(arg)
        #define mutex_lock(arg) EnterCriticalSection(arg)
        #define mutex_trylock(arg) TryEnterCriticalSection(arg)
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
        (addr = (void *)memalign((align), (size)))
    #define free_align(addr) free(addr)

    #ifndef spin_t
        // spinlock
        #include <pthread.h>
        #define spin_t pthread_spinlock_t
        #define spin_init(arg) pthread_spin_init(arg, PTHREAD_PROCESS_SHARED)
        #define spin_lock(arg) pthread_spin_lock(arg)
        #define spin_trylock(arg) \
            (pthread_spin_trylock(arg) == 0)
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
        #define mutex_trylock(arg) \
            (pthread_mutex_trylock(arg) == 0)
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

#elif __sun
    #include <inttypes.h>
    #include <alloca.h>

    #define INLINE __inline

    #define _X64 PRIx64
    #define _F64 PRIu64
    #define _FSEC "ld"
    #define _FUSEC "ld"

    /* Solaris don't have flag to open to set direct io, but
       rather use directio() afterwards to enable it. lets look
       into that later on.
    */
    #define _ARCH_O_DIRECT (0)

    #define malloc_align(addr, align, size) \
        {int __ret__=0; __ret__=posix_memalign(&(addr), (align), (size));}
    #define free_align(addr) free(addr)

    #ifndef spin_t
        // spinlock
        // There isn't much point of keeping a separate
        // spinlock datatype, because the mutexes on
        // solaris is adaptive anyway and will spin
        // initially.
        #include <pthread.h>
        #define spin_t pthread_mutex_t
        #define spin_init(arg) pthread_mutex_init(arg, NULL)
        #define spin_lock(arg) pthread_mutex_lock(arg)
        #define spin_trylock(arg) \
            (pthread_mutex_trylock(arg) == 0)
        #define spin_unlock(arg) pthread_mutex_unlock(arg)
        #define spin_destroy(arg) pthread_mutex_destroy(arg)
        #define SPIN_INITIALIZER PTHREAD_MUTEX_INITIALIZER
    #endif
    #ifndef mutex_t
        // mutex
        #include <pthread.h>
        #define mutex_t pthread_mutex_t
        #define mutex_init(arg) pthread_mutex_init(arg, NULL)
        #define mutex_lock(arg) pthread_mutex_lock(arg)
        #define mutex_trylock(arg) \
            (pthread_mutex_trylock(arg) == 0)
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

#elif __FreeBSD__
    #include <inttypes.h>

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
        #define spin_t pthread_mutex_t
        #define spin_init(arg) pthread_mutex_init(arg, NULL)
        #define spin_lock(arg) pthread_mutex_lock(arg)
        #define spin_trylock(arg) \
            (pthread_mutex_trylock(arg) == 0)
        #define spin_unlock(arg) pthread_mutex_unlock(arg)
        #define spin_destroy(arg) pthread_mutex_destroy(arg)
        #define SPIN_INITIALIZER PTHREAD_MUTEX_INITIALIZER
    #endif
    #ifndef mutex_t
        // mutex
        #include <pthread.h>
        #define mutex_t pthread_mutex_t
        #define mutex_init(arg) pthread_mutex_init(arg, NULL)
        #define mutex_lock(arg) pthread_mutex_lock(arg)
        #define mutex_trylock(arg) \
            (pthread_mutex_trylock(arg) == 0)
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
#pragma error "Unknown architecture"
    #define INLINE make_error
#endif

#endif
