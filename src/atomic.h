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

#if defined(HAVE_GCC_ATOMICS)
#include "atomic/gcc_atomics.h"
#elif defined(HAVE_ATOMIC_H)
#include "atomic/libatomic.h"
#elif _MSC_VER
#include <Windows.h>
#else
#error "Don't know how to use atomics on your target system!"
#endif

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _ALIGN_MEM_ACCESS
typedef struct __attribute__((aligned(8))) {
#if _MSC_VER
    volatile LONG64 val;
#else
    volatile uint64_t val;
#endif
} atomic_uint64_t;
#else
typedef struct {
#if _MSC_VER
    volatile LONG64 val;
#else
    volatile uint64_t val;
#endif
} atomic_uint64_t;
#endif

typedef struct {
#if _MSC_VER
    volatile LONG val;
#else
    volatile uint32_t val;
#endif
} atomic_uint32_t;

typedef struct {
#if _MSC_VER
    volatile SHORT val;
#else
    volatile uint16_t val;
#endif
} atomic_uint16_t;

typedef struct {
#ifdef _MSC_VER
    // Windows doesn't support atomic operations for uint8_t separately.
    volatile SHORT val;
#else
    volatile uint8_t val;
#endif
} atomic_uint8_t;


INLINE void atomic_destroy_uint64_t(atomic_uint64_t *atomic_val) {
    (void) atomic_val;
}

INLINE void atomic_destroy_uint32_t(atomic_uint32_t *atomic_val) {
    (void) atomic_val;
}

INLINE void atomic_destroy_uint16_t(atomic_uint16_t *atomic_val) {
    (void) atomic_val;
}

INLINE void atomic_destroy_uint8_t(atomic_uint8_t *atomic_val) {
    (void) atomic_val;
}

INLINE uint64_t atomic_get_uint64_t(atomic_uint64_t *atomic_val) {
#ifdef _MSC_VER
    #ifdef _M_IA64
        // Itanium platform
        return (uint64_t) InterlockedAdd64(&atomic_val->val, 0);
    #else
        // x86(-64) platform
        return (uint64_t) InterlockedExchangeAdd64(&atomic_val->val, 0);
    #endif
#else
    return fdb_sync_fetch_and_add_64(&atomic_val->val, 0);
#endif
}

INLINE uint32_t atomic_get_uint32_t(atomic_uint32_t *atomic_val) {
#ifdef _MSC_VER
    #ifdef _M_IA64
        // Itanium platform
        return (uint32_t) InterlockedAdd(&atomic_val->val, 0);
    #else
        // x86(-64) platform
        return (uint32_t) InterlockedExchangeAdd(&atomic_val->val, 0);
    #endif
#else
    return fdb_sync_fetch_and_add_32(&atomic_val->val, 0);
#endif
}

INLINE uint16_t atomic_get_uint16_t(atomic_uint16_t *atomic_val) {
#ifdef _MSC_VER
    // Windows doesn't have a separate atomic add for uint16_t
    #ifdef _M_IA64
        // Itanium platform
        return (uint16_t) InterlockedAdd((volatile LONG *) &atomic_val->val, 0);
    #else
        // x86(-64) platform
        return (uint16_t) InterlockedExchangeAdd((volatile LONG *) &atomic_val->val, 0);
    #endif
#else
    return fdb_sync_fetch_and_add_16(&atomic_val->val, 0);
#endif
}

INLINE uint8_t atomic_get_uint8_t(atomic_uint8_t *atomic_val) {
#ifdef _MSC_VER
    // Windows doesn't have a separate atomic add for uint8_t
    #ifdef _M_IA64
        // Itanium platform
        return (uint8_t) InterlockedAdd((volatile LONG *) &atomic_val->val, 0);
    #else
        // x86(-64) platform
        return (uint8_t) InterlockedExchangeAdd((volatile LONG *) &atomic_val->val, 0);
    #endif
#else
    return fdb_sync_fetch_and_add_8(&atomic_val->val, 0);
#endif
}

INLINE void atomic_store_uint64_t(atomic_uint64_t *atomic_val, uint64_t new_val) {
#ifdef _MSC_VER
    InterlockedExchange64(&atomic_val->val, (LONG64) new_val);
#else
    fdb_sync_lock_test_and_set_64(&atomic_val->val, new_val);
#endif
}

INLINE void atomic_store_uint32_t(atomic_uint32_t *atomic_val, uint32_t new_val) {
#ifdef _MSC_VER
    InterlockedExchange(&atomic_val->val, (LONG) new_val);
#else
    fdb_sync_lock_test_and_set_32(&atomic_val->val, new_val);
#endif
}

INLINE void atomic_store_uint16_t(atomic_uint16_t *atomic_val, uint16_t new_val) {
#ifdef _MSC_VER
    InterlockedExchange16(&atomic_val->val, (SHORT) new_val);
#else
    fdb_sync_lock_test_and_set_16(&atomic_val->val, new_val);
#endif
}

INLINE void atomic_store_uint8_t(atomic_uint8_t *atomic_val, uint8_t new_val) {
#ifdef _MSC_VER
    // Windows doesn't support atomic store for uint8_t
    InterlockedExchange16(&atomic_val->val, (SHORT) new_val);
#else
    fdb_sync_lock_test_and_set_8(&atomic_val->val, new_val);
#endif
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
    bool rv = false;

#ifdef _MSC_VER
    uint64_t oldval = (uint64_t) InterlockedCompareExchange64(&atomic_val->val,
                                                              (LONG64) new_val,
                                                              (LONG64) expected_val);
    if (oldval == expected_val) {
        rv = true;
    }
#else
    if (fdb_sync_bool_compare_and_swap_64(&atomic_val->val,
                                          expected_val, new_val)) {
        rv = true;
    }
#endif

    return rv;
}

INLINE bool atomic_cas_uint32_t(atomic_uint32_t *atomic_val,
                                uint32_t expected_val, uint32_t new_val) {
    bool rv = false;

#ifdef _MSC_VER
    uint32_t oldval = (uint32_t) InterlockedCompareExchange(&atomic_val->val,
                                                            (LONG) new_val,
                                                            (LONG) expected_val);
    if (oldval == expected_val) {
        rv = true;
    }
#else
    if (fdb_sync_bool_compare_and_swap_32(&atomic_val->val,
                                          expected_val, new_val)) {
        rv = true;
    }
#endif

    return rv;
}

INLINE bool atomic_cas_uint16_t(atomic_uint16_t *atomic_val,
                                uint16_t expected_val, uint16_t new_val) {
    bool rv = false;

#ifdef _MSC_VER
    uint16_t oldval = (uint16_t) InterlockedCompareExchange16(&atomic_val->val,
                                                              (SHORT) new_val,
                                                              (SHORT) expected_val);
    if (oldval == expected_val) {
        rv = true;
    }
#else
    if (fdb_sync_bool_compare_and_swap_16(&atomic_val->val,
                                          expected_val, new_val)) {
        rv = true;
    }
#endif

    return rv;
}

INLINE bool atomic_cas_uint8_t(atomic_uint8_t *atomic_val,
                               uint8_t expected_val, uint8_t new_val) {
    bool rv = false;

#ifdef _MSC_VER
    // Windows doesn't support atomic CAS for uint8_t
    uint8_t oldval = (uint8_t) InterlockedCompareExchange16(&atomic_val->val,
                                                            (SHORT) new_val,
                                                            (SHORT) expected_val);
    if (oldval == expected_val) {
        rv = true;
    }
#else
    if (fdb_sync_bool_compare_and_swap_8(&atomic_val->val,
                                         expected_val, new_val)) {
        rv = true;
    }
#endif

    return rv;
}

INLINE uint64_t atomic_incr_uint64_t(atomic_uint64_t *atomic_val) {
#ifdef _MSC_VER
    return (uint64_t) InterlockedIncrement64(&atomic_val->val);
#else
    return fdb_sync_add_and_fetch_64(&atomic_val->val, 1);
#endif
}

INLINE uint32_t atomic_incr_uint32_t(atomic_uint32_t *atomic_val) {
#ifdef _MSC_VER
    return (uint32_t) InterlockedIncrement(&atomic_val->val);
#else
    return fdb_sync_add_and_fetch_32(&atomic_val->val, 1);
#endif
}

INLINE uint16_t atomic_incr_uint16_t(atomic_uint16_t *atomic_val) {
#ifdef _MSC_VER
    return (uint16_t) InterlockedIncrement16(&atomic_val->val);
#else
    return fdb_sync_add_and_fetch_16(&atomic_val->val, 1);
#endif
}

INLINE uint8_t atomic_incr_uint8_t(atomic_uint8_t *atomic_val) {
#ifdef _MSC_VER
    // Windows doesn't have a separate atomic incr for uint8_t
    return (uint8_t) InterlockedIncrement16(&atomic_val->val);
#else
    return fdb_sync_add_and_fetch_8(&atomic_val->val, 1);
#endif
}

INLINE uint64_t atomic_decr_uint64_t(atomic_uint64_t *atomic_val) {
#ifdef _MSC_VER
    return (uint64_t) InterlockedDecrement64(&atomic_val->val);
#else
    return fdb_sync_add_and_fetch_64(&atomic_val->val, -1);
#endif
}

INLINE uint32_t atomic_decr_uint32_t(atomic_uint32_t *atomic_val) {
#ifdef _MSC_VER
    return (uint32_t) InterlockedDecrement(&atomic_val->val);
#else
    return fdb_sync_add_and_fetch_32(&atomic_val->val, -1);
#endif
}

INLINE uint16_t atomic_decr_uint16_t(atomic_uint16_t *atomic_val) {
#ifdef _MSC_VER
    return (uint16_t) InterlockedDecrement16(&atomic_val->val);
#else
    return fdb_sync_add_and_fetch_16(&atomic_val->val, -1);
#endif
}

INLINE uint8_t atomic_decr_uint8_t(atomic_uint8_t *atomic_val) {
#ifdef _MSC_VER
    // Windows doesn't have a separate atomic decr for uint8_t
    return (uint8_t) InterlockedDecrement16(&atomic_val->val);
#else
    return fdb_sync_add_and_fetch_8(&atomic_val->val, -1);
#endif
}

INLINE uint64_t atomic_add_uint64_t(atomic_uint64_t *atomic_val, int64_t increment) {
#ifdef _MSC_VER
    #ifdef _M_IA64
        // Itanium platform
        return (uint64_t) InterlockedAdd64(&atomic_val->val, (LONG64) increment);
    #else
        // x86(-64) platform
        return (uint64_t)
               InterlockedExchangeAdd64(&atomic_val->val, (LONG64) increment)
               + increment;
    #endif
#else
    return fdb_sync_add_and_fetch_64(&atomic_val->val, increment);
#endif
}

INLINE uint32_t atomic_add_uint32_t(atomic_uint32_t *atomic_val, int32_t increment) {
#ifdef _MSC_VER
    #ifdef _M_IA64
        // Itanium platform
        return (uint32_t) InterlockedAdd(&atomic_val->val, (LONG) increment);
    #else
        // x86(-64) platform
        return (uint32_t)
               InterlockedExchangeAdd(&atomic_val->val, (LONG) increment)
               + increment;
    #endif
#else
    return fdb_sync_add_and_fetch_32(&atomic_val->val, increment);
#endif
}

INLINE uint16_t atomic_add_uint16_t(atomic_uint16_t *atomic_val, int16_t increment) {
#ifdef _MSC_VER
    // Windows doesn't have a separate atomic add for uint16_t
    #ifdef _M_IA64
        // Itanium platform
        return (uint16_t) InterlockedAdd((volatile LONG *) &atomic_val->val, (SHORT) increment);
    #else
        // x86(-64) platform
        return (uint16_t)
               InterlockedExchangeAdd((volatile LONG *) &atomic_val->val, (SHORT) increment)
               + increment;
    #endif
#else
    return fdb_sync_add_and_fetch_16(&atomic_val->val, increment);
#endif
}

INLINE uint8_t atomic_add_uint8_t(atomic_uint8_t *atomic_val, int8_t increment) {
#ifdef _MSC_VER
    // Windows doesn't have a separate atomoic add for uint8_t
    #ifdef _M_IA64
        // Itanium platform
        return (uint8_t) InterlockedAdd((volatile LONG *) &atomic_val->val, (SHORT) increment);
    #else
        // x86(-64) platform
        return (uint8_t)
               InterlockedExchangeAdd((volatile LONG *) &atomic_val->val, (SHORT) increment)
               + increment;
    #endif
#else
    return fdb_sync_add_and_fetch_8(&atomic_val->val, increment);
#endif
}

INLINE uint64_t atomic_sub_uint64_t(atomic_uint64_t *atomic_val, int64_t decrement) {
#ifdef _MSC_VER
    #ifdef _M_IA64
        // Itanium platform
        return (uint64_t) InterlockedAdd64(&atomic_val->val, (LONG64) -decrement);
    #else
        // x86(-64) platform
        return (uint64_t)
               InterlockedExchangeAdd64(&atomic_val->val, (LONG64) -decrement)
               - decrement;
    #endif
#else
    return fdb_sync_add_and_fetch_64(&atomic_val->val, -decrement);
#endif
}

INLINE uint32_t atomic_sub_uint32_t(atomic_uint32_t *atomic_val, int32_t decrement) {
#ifdef _MSC_VER
    #ifdef _M_IA64
        // Itanium platform
        return (uint32_t) InterlockedAdd(&atomic_val->val, (LONG) -decrement);
    #else
        // x86(-64) platform
        return (uint32_t)
               InterlockedExchangeAdd(&atomic_val->val, (LONG) -decrement)
               - decrement;
    #endif
#else
    return fdb_sync_add_and_fetch_32(&atomic_val->val, -decrement);
#endif
}

INLINE uint16_t atomic_sub_uint16_t(atomic_uint16_t *atomic_val, int16_t decrement) {
#ifdef _MSC_VER
    // Windows doesn't have a separate atomic add for uint16_t
    #ifdef _M_IA64
        // Itanium platform
        return (uint16_t) InterlockedAdd((volatile LONG *) &atomic_val->val,
                                         (SHORT) -decrement);
    #else
        // x86(-64) platform
        return (uint16_t)
               InterlockedExchangeAdd((volatile LONG *)&atomic_val->val,
                                      (SHORT) -decrement)
               - decrement;
    #endif
#else
    return fdb_sync_add_and_fetch_16(&atomic_val->val, -decrement);
#endif
}

INLINE uint8_t atomic_sub_uint8_t(atomic_uint8_t *atomic_val, int8_t decrement) {
#ifdef _MSC_VER
    // Windows doesn't have a separate atomoic add for uint8_t
    #ifdef _M_IA64
        // Itanium platform
        return (uint8_t) InterlockedAdd((volatile LONG *) &atomic_val->val,
                                        (SHORT) -decrement);
    #else
        // x86(-64) platform
        return (uint8_t)
               InterlockedExchangeAdd((volatile LONG *)&atomic_val->val,
                                      (SHORT) -decrement)
               - decrement;
    #endif
#else
    return fdb_sync_add_and_fetch_8(&atomic_val->val, -decrement);
#endif
}

// Reader-Writer spinlock

typedef atomic_uint32_t rw_spin_t;

INLINE void thread_yield() {
#ifdef HAVE_SCHED_H
    sched_yield();
#elif _MSC_VER
    SwitchToThread();
#endif
}

INLINE void rw_spin_init(rw_spin_t *rw_lock) {
    atomic_store_uint32_t(rw_lock, 0);
}

INLINE void rw_spin_destroy(rw_spin_t *rw_lock) {
    (void) rw_lock;
}

INLINE void rw_spin_read_lock(rw_spin_t *rw_lock) {
    for(;;) {
        // Wait for active writer to release the lock
        while (rw_lock->val & 0xfff00000) {
            thread_yield();
        }

        if ((atomic_incr_uint32_t(rw_lock) & 0xfff00000) == 0) {
            return;
        }

        atomic_decr_uint32_t(rw_lock);
    }
}

INLINE void rw_spin_read_unlock(rw_spin_t *rw_lock) {
     atomic_decr_uint32_t(rw_lock);
}

INLINE void rw_spin_write_lock(rw_spin_t *rw_lock) {
    for(;;) {
        // Wait for active writer to release the lock
        while (rw_lock->val & 0xfff00000) {
            thread_yield();
        }

        if((atomic_add_uint32_t(rw_lock, 0x100000) & 0xfff00000) == 0x100000) {
            // Wait until there's no more readers
            while (rw_lock->val & 0x000fffff) {
                thread_yield();
            }
            return;
        }

        atomic_sub_uint32_t(rw_lock, 0x100000);
    }
}

INLINE void rw_spin_write_unlock(rw_spin_t *rw_lock) {
    atomic_sub_uint32_t(rw_lock, 0x100000);
}

#ifdef __cplusplus
}
#endif

#endif  // FDB_ATOMIC_H_
