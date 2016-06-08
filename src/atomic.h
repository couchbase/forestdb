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

// C++11 has built-in atomic support.
#define atomic_uint64_t std::atomic<uint64_t>
#define atomic_uint32_t std::atomic<uint32_t>
#define atomic_uint16_t std::atomic<uint16_t>
#define atomic_uint8_t std::atomic<uint8_t>

// RW Lock(s)
#if !defined(WIN32) && !defined(_WIN32)
#include <pthread.h>
typedef pthread_rwlock_t fdb_rw_lock;
#else   // WINDOWS
#include <windows.h>
typedef SRWLOCK fdb_rw_lock;
#endif

INLINE uint64_t atomic_get_uint64_t(const atomic_uint64_t *atomic_val,
                                    std::memory_order order = std::memory_order_seq_cst) {
    return std::atomic_load_explicit(atomic_val, order);
}

INLINE uint32_t atomic_get_uint32_t(const atomic_uint32_t *atomic_val,
                                    std::memory_order order = std::memory_order_seq_cst) {
    return std::atomic_load_explicit(atomic_val, order);
}

INLINE uint16_t atomic_get_uint16_t(const atomic_uint16_t *atomic_val,
                                    std::memory_order order = std::memory_order_seq_cst) {
    return std::atomic_load_explicit(atomic_val, order);
}

INLINE uint8_t atomic_get_uint8_t(const atomic_uint8_t *atomic_val,
                                  std::memory_order order = std::memory_order_seq_cst) {
    return std::atomic_load_explicit(atomic_val, order);
}

INLINE void atomic_store_uint64_t(atomic_uint64_t *atomic_val, uint64_t new_val,
                                  std::memory_order order = std::memory_order_seq_cst) {
    return std::atomic_store_explicit(atomic_val, new_val, order);
}

INLINE void atomic_store_uint32_t(atomic_uint32_t *atomic_val, uint32_t new_val,
                                  std::memory_order order = std::memory_order_seq_cst) {
    return std::atomic_store_explicit(atomic_val, new_val, order);
}

INLINE void atomic_store_uint16_t(atomic_uint16_t *atomic_val, uint16_t new_val,
                                  std::memory_order order = std::memory_order_seq_cst) {
    return std::atomic_store_explicit(atomic_val, new_val, order);
}

INLINE void atomic_store_uint8_t(atomic_uint8_t *atomic_val, uint8_t new_val,
                                 std::memory_order order = std::memory_order_seq_cst) {
    return std::atomic_store_explicit(atomic_val, new_val, order);
}

INLINE void atomic_init_uint64_t(atomic_uint64_t *atomic_val, uint64_t initial) {
    atomic_store_uint64_t(atomic_val, initial);
}

INLINE void atomic_init_uint32_t(atomic_uint32_t *atomic_val, uint32_t initial) {
    atomic_store_uint32_t(atomic_val, initial);
}

INLINE void atomic_init_uint16_t(atomic_uint16_t *atomic_val, uint16_t initial) {
    atomic_store_uint16_t(atomic_val, initial);
}

INLINE void atomic_init_uint8_t(atomic_uint8_t *atomic_val, uint8_t initial) {
    atomic_store_uint8_t(atomic_val, initial);
}

INLINE bool atomic_cas_uint64_t(atomic_uint64_t *atomic_val,
                                uint64_t expected_val, uint64_t new_val) {
    return std::atomic_compare_exchange_strong(atomic_val, &expected_val, new_val);
}

INLINE bool atomic_cas_uint32_t(atomic_uint32_t *atomic_val,
                                uint32_t expected_val, uint32_t new_val) {
    return std::atomic_compare_exchange_strong(atomic_val, &expected_val, new_val);
}

INLINE bool atomic_cas_uint16_t(atomic_uint16_t *atomic_val,
                                uint16_t expected_val, uint16_t new_val) {
    return std::atomic_compare_exchange_strong(atomic_val, &expected_val, new_val);
}

INLINE bool atomic_cas_uint8_t(atomic_uint8_t *atomic_val,
                               uint8_t expected_val, uint8_t new_val) {
    return std::atomic_compare_exchange_strong(atomic_val, &expected_val, new_val);
}

INLINE uint64_t atomic_incr_uint64_t(atomic_uint64_t *atomic_val,
                                     std::memory_order order = std::memory_order_seq_cst) {
    return std::atomic_fetch_add_explicit(atomic_val, static_cast<uint64_t>(1), order) + 1;
}

INLINE uint32_t atomic_incr_uint32_t(atomic_uint32_t *atomic_val,
                                     std::memory_order order = std::memory_order_seq_cst) {
    return std::atomic_fetch_add_explicit(atomic_val, static_cast<uint32_t>(1), order) + 1;
}

INLINE uint16_t atomic_incr_uint16_t(atomic_uint16_t *atomic_val,
                                     std::memory_order order = std::memory_order_seq_cst) {
    return std::atomic_fetch_add_explicit(atomic_val, static_cast<uint16_t>(1), order) + 1;
}

INLINE uint8_t atomic_incr_uint8_t(atomic_uint8_t *atomic_val,
                                   std::memory_order order = std::memory_order_seq_cst) {
    return std::atomic_fetch_add_explicit(atomic_val, static_cast<uint8_t>(1), order) + 1;
}

INLINE uint64_t atomic_decr_uint64_t(atomic_uint64_t *atomic_val,
                                     std::memory_order order = std::memory_order_seq_cst) {
    return std::atomic_fetch_sub_explicit(atomic_val, static_cast<uint64_t>(1), order) - 1;
}

INLINE uint32_t atomic_decr_uint32_t(atomic_uint32_t *atomic_val,
                                     std::memory_order order = std::memory_order_seq_cst) {
    return std::atomic_fetch_sub_explicit(atomic_val, static_cast<uint32_t>(1), order) - 1;
}

INLINE uint16_t atomic_decr_uint16_t(atomic_uint16_t *atomic_val,
                                     std::memory_order order = std::memory_order_seq_cst) {
    return std::atomic_fetch_sub_explicit(atomic_val, static_cast<uint16_t>(1), order) - 1;
}

INLINE uint8_t atomic_decr_uint8_t(atomic_uint8_t *atomic_val,
                                   std::memory_order order = std::memory_order_seq_cst) {
    return std::atomic_fetch_sub_explicit(atomic_val, static_cast<uint8_t>(1), order) - 1;
}

INLINE uint64_t atomic_add_uint64_t(atomic_uint64_t *atomic_val, int64_t increment,
                                    std::memory_order order = std::memory_order_seq_cst) {
    return std::atomic_fetch_add_explicit(atomic_val, static_cast<uint64_t>(increment), order)
        + increment;
}

INLINE uint32_t atomic_add_uint32_t(atomic_uint32_t *atomic_val, int32_t increment,
                                    std::memory_order order = std::memory_order_seq_cst) {
    return std::atomic_fetch_add_explicit(atomic_val, static_cast<uint32_t>(increment), order)
        + increment;
}

INLINE uint16_t atomic_add_uint16_t(atomic_uint16_t *atomic_val, int16_t increment,
                                    std::memory_order order = std::memory_order_seq_cst) {
    return std::atomic_fetch_add_explicit(atomic_val, static_cast<uint16_t>(increment), order)
        + increment;
}

INLINE uint8_t atomic_add_uint8_t(atomic_uint8_t *atomic_val, int8_t increment,
                                  std::memory_order order = std::memory_order_seq_cst) {
    return std::atomic_fetch_add_explicit(atomic_val, static_cast<uint8_t>(increment), order)
        + increment;
}

INLINE uint64_t atomic_sub_uint64_t(atomic_uint64_t *atomic_val, int64_t decrement,
                                    std::memory_order order = std::memory_order_seq_cst) {
    return std::atomic_fetch_sub_explicit(atomic_val, static_cast<uint64_t>(decrement), order)
        - decrement;
}

INLINE uint32_t atomic_sub_uint32_t(atomic_uint32_t *atomic_val, int32_t decrement,
                                    std::memory_order order = std::memory_order_seq_cst) {
    return std::atomic_fetch_sub_explicit(atomic_val, static_cast<uint32_t>(decrement), order)
        - decrement;
}

INLINE uint16_t atomic_sub_uint16_t(atomic_uint16_t *atomic_val, int16_t decrement,
                                    std::memory_order order = std::memory_order_seq_cst) {
    return std::atomic_fetch_sub_explicit(atomic_val, static_cast<uint16_t>(decrement), order)
        - decrement;
}

INLINE uint8_t atomic_sub_uint8_t(atomic_uint8_t *atomic_val, int8_t decrement,
                                  std::memory_order order = std::memory_order_seq_cst) {
    return std::atomic_fetch_sub_explicit(atomic_val, static_cast<uint8_t>(decrement), order)
        - decrement;
}

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
