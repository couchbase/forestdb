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
#include <mutex>

template <typename T>
void atomic_setIfBigger(std::atomic<T> &obj, const T &newValue) {
    T oldValue = obj.load();
    while (newValue > oldValue) {
        if (obj.compare_exchange_strong(oldValue, newValue)) {
            break;
        }
        oldValue = obj.load();
    }
}

template <typename T>
void atomic_setIfLess(std::atomic<T> &obj, const T &newValue) {
    T oldValue = obj.load();
    while (newValue < oldValue) {
        if (obj.compare_exchange_strong(oldValue, newValue)) {
            break;
        }
        oldValue = obj.load();
    }
}


template <class T> class RCPtr;
template <class S> class SingleThreadedRCPtr;

/**
 * A reference counted value (used by RCPtr and SingleThreadedRCPtr).
 */
class RCValue {
public:
    RCValue() : _rc_refcount(0) {}
    RCValue(const RCValue &) : _rc_refcount(0) {}
    ~RCValue() {}
private:
    template <class MyTT> friend class RCPtr;
    template <class MySS> friend class SingleThreadedRCPtr;
    int _rc_incref() const {
        return ++_rc_refcount;
    }

    int _rc_decref() const {
        return --_rc_refcount;
    }

    mutable std::atomic<int> _rc_refcount;
};

/**
 * Single-threaded reference counted pointer.
 * "Single-threaded" means that the reference counted pointer should be accessed
 * by only one thread at any time or accesses to the reference counted pointer
 * by multiple threads should be synchronized by the external lock.
 */
template <class T>
class SingleThreadedRCPtr {
public:
    SingleThreadedRCPtr(T *init = NULL) : value(init) {
        if (init != NULL) {
            static_cast<RCValue*>(value)->_rc_incref();
        }
    }

    SingleThreadedRCPtr(const SingleThreadedRCPtr<T> &other) : value(other.gimme()) {}

    ~SingleThreadedRCPtr() {
        if (value && static_cast<RCValue *>(value)->_rc_decref() == 0) {
            delete value;
        }
    }

    void reset(T *newValue = NULL) {
        if (newValue != NULL) {
            static_cast<RCValue *>(newValue)->_rc_incref();
        }
        swap(newValue);
    }

    void reset(const SingleThreadedRCPtr<T> &other) {
        swap(other.gimme());
    }

    // safe for the lifetime of this instance
    T *get() const {
        return value;
    }

    SingleThreadedRCPtr<T> & operator =(const SingleThreadedRCPtr<T> &other) {
        reset(other);
        return *this;
    }

    T &operator *() const {
        return *value;
    }

    T *operator ->() const {
        return value;
    }

    bool operator! () const {
        return !value;
    }

    operator bool () const {
        return (bool)value;
    }

private:
    T *gimme() const {
        if (value) {
            static_cast<RCValue *>(value)->_rc_incref();
        }
        return value;
    }

    void swap(T *newValue) {
        T *old = value;
        value = newValue;
        if (old != NULL && static_cast<RCValue *>(old)->_rc_decref() == 0) {
            delete old;
        }
    }

    T *value;
};

typedef std::lock_guard<std::mutex> LockHolder;
typedef std::unique_lock<std::mutex> UniqueLock;

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
