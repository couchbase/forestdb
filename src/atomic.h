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

#ifndef FDB_ATOMIC_H_
#define FDB_ATOMIC_H_ 1

#ifdef HAVE_SCHED_H
#include <sched.h>
#endif

#include "config.h"
#include "common.h"

#include <string.h>

#include <atomic>

#ifdef __cplusplus
extern "C" {
#endif

// RW Lock(s)
#if !defined(WIN32) && !defined(_WIN32)
#include <pthread.h>
typedef pthread_rwlock_t fdb_rw_lock;
#else   // WINDOWS
#include <windows.h>
typedef SRWLOCK fdb_rw_lock;
#endif

// ---> RW Lock

INLINE int init_rw_lock(fdb_rw_lock *lock) {
#if !defined(WIN32) && !defined(_WIN32)
    int rv = pthread_rwlock_init(lock, NULL);
    return rv;
#else
    InitializeSRWLock(lock);
    return 0;
#endif
}

INLINE int destroy_rw_lock(fdb_rw_lock *lock) {
#if !defined(WIN32) && !defined(_WIN32)
    int rv = pthread_rwlock_destroy(lock);
    return rv;
#else
    // Nothing to do on Windows
    (void)lock;
    return 0;
#endif
}

INLINE int reader_lock(fdb_rw_lock *lock) {
#if !defined(WIN32) && !defined(_WIN32)
    int result = pthread_rwlock_rdlock(lock);
    if (result != 0) {
        fprintf(stderr, "pthread_rwlock_rdlock returned %d (%s)\n",
                result, strerror(result));
    }
    return result;
#else
    AcquireSRWLockShared(lock);
    return 0;
#endif
}

INLINE int reader_unlock(fdb_rw_lock *lock) {
#if !defined(WIN32) && !defined(_WIN32)
    int result = pthread_rwlock_unlock(lock);
    if (result != 0) {
        fprintf(stderr, "pthread_rwlock_unlock returned %d (%s)\n",
                result, strerror(result));
    }
    return result;
#else
    ReleaseSRWLockShared(lock);
    return 0;
#endif
}

INLINE int writer_lock(fdb_rw_lock *lock) {
#if !defined(WIN32) && !defined(_WIN32)
    int result = pthread_rwlock_wrlock(lock);
    if (result != 0) {
        fprintf(stderr, "pthread_rwlock_wrlock returned %d (%s)\n",
                result, strerror(result));
    }
    return result;
#else
    AcquireSRWLockExclusive(lock);
    return 0;
#endif
}

INLINE int writer_unlock(fdb_rw_lock *lock) {
#if !defined(WIN32) && !defined(_WIN32)
    int result = pthread_rwlock_unlock(lock);
    if (result != 0) {
        fprintf(stderr, "pthread_rwlock_unlock returned %d (%s)\n",
                result, strerror(result));
    }
    return result;
#else
    ReleaseSRWLockExclusive(lock);
    return 0;
#endif
}

// <--- RW Lock

#ifdef __cplusplus
}
#endif

#endif  // FDB_ATOMIC_H_
