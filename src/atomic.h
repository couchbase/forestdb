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
#define fdb_sync_synchronize() MemoryBarrier()
#else
#error "Don't know how to use atomics on your target system!"
#endif

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _ALIGN_MEM_ACCESS
typedef struct __attribute__((aligned(8))) {
#ifdef _MSC_VER
    // TODO: Need to figure out an atomic support without using lock.
    spin_t lock;
#endif
    volatile uint64_t val;
} atomic_uint64_t;
#else
typedef struct {
#ifdef _MSC_VER
    // TODO: Need to figure out an atomic support without using lock.
    spin_t lock;
#endif
    volatile uint64_t val;
} atomic_uint64_t;
#endif

typedef struct {
#ifdef _MSC_VER
    // TODO: Need to figure out an atomic support without using lock.
    spin_t lock;
#endif
    volatile uint32_t val;
} atomic_uint32_t;

typedef struct {
#ifdef _MSC_VER
    // TODO: Need to figure out an atomic support without using lock.
    spin_t lock;
#endif
    volatile uint16_t val;
} atomic_uint16_t;

typedef struct {
#ifdef _MSC_VER
    // TODO: Need to figure out an atomic support without using lock.
    spin_t lock;
#endif
    volatile uint8_t val;
} atomic_uint8_t;


INLINE void atomic_destroy_uint64_t(atomic_uint64_t *atomic_val) {
#ifdef _MSC_VER
    spin_destroy(&atomic_val->lock);
#endif
}

INLINE void atomic_destroy_uint32_t(atomic_uint32_t *atomic_val) {
#ifdef _MSC_VER
    spin_destroy(&atomic_val->lock);
#endif
}

INLINE void atomic_destroy_uint16_t(atomic_uint16_t *atomic_val) {
#ifdef _MSC_VER
    spin_destroy(&atomic_val->lock);
#endif
}

INLINE void atomic_destroy_uint8_t(atomic_uint8_t *atomic_val) {
#ifdef _MSC_VER
    spin_destroy(&atomic_val->lock);
#endif
}

INLINE uint64_t atomic_get_uint64_t(atomic_uint64_t *atomic_val) {
#ifdef _MSC_VER
    return atomic_val->val;
#else
    return fdb_sync_fetch_and_add_64(&atomic_val->val, 0);
#endif
}

INLINE uint32_t atomic_get_uint32_t(atomic_uint32_t *atomic_val) {
#ifdef _MSC_VER
    return atomic_val->val;
#else
    return fdb_sync_fetch_and_add_32(&atomic_val->val, 0);
#endif
}

INLINE uint16_t atomic_get_uint16_t(atomic_uint16_t *atomic_val) {
#ifdef _MSC_VER
    return atomic_val->val;
#else
    return fdb_sync_fetch_and_add_16(&atomic_val->val, 0);
#endif
}

INLINE uint8_t atomic_get_uint8_t(atomic_uint8_t *atomic_val) {
#ifdef _MSC_VER
    return atomic_val->val;
#else
    return fdb_sync_fetch_and_add_8(&atomic_val->val, 0);
#endif
}

INLINE void atomic_store_uint64_t(atomic_uint64_t *atomic_val, uint64_t new_val) {
#ifdef _MSC_VER
    atomic_val->val = new_val;
    fdb_sync_synchronize();
#else
    fdb_sync_lock_test_and_set_64(&atomic_val->val, new_val);
#endif
}

INLINE void atomic_store_uint32_t(atomic_uint32_t *atomic_val, uint32_t new_val) {
#ifdef _MSC_VER
    atomic_val->val = new_val;
    fdb_sync_synchronize();
#else
    fdb_sync_lock_test_and_set_32(&atomic_val->val, new_val);
#endif
}

INLINE void atomic_store_uint16_t(atomic_uint16_t *atomic_val, uint16_t new_val) {
#ifdef _MSC_VER
    atomic_val->val = new_val;
    fdb_sync_synchronize();
#else
    fdb_sync_lock_test_and_set_16(&atomic_val->val, new_val);
#endif
}

INLINE void atomic_store_uint8_t(atomic_uint8_t *atomic_val, uint8_t new_val) {
#ifdef _MSC_VER
    atomic_val->val = new_val;
    fdb_sync_synchronize();
#else
    fdb_sync_lock_test_and_set_8(&atomic_val->val, new_val);
#endif
}

INLINE void atomic_init_uint64_t(atomic_uint64_t *atomic_val, uint64_t initial) {
#ifdef _MSC_VER
    spin_init(&atomic_val->lock);
#endif
    atomic_store_uint64_t(atomic_val, initial);
}

INLINE void atomic_init_uint32_t(atomic_uint32_t *atomic_val, uint32_t initial) {
#ifdef _MSC_VER
    spin_init(&atomic_val->lock);
#endif
    atomic_store_uint32_t(atomic_val, initial);
}

INLINE void atomic_init_uint16_t(atomic_uint16_t *atomic_val, uint16_t initial) {
#ifdef _MSC_VER
    spin_init(&atomic_val->lock);
#endif
    atomic_store_uint16_t(atomic_val, initial);
}

INLINE void atomic_init_uint8_t(atomic_uint8_t *atomic_val, uint8_t initial) {
#ifdef _MSC_VER
    spin_init(&atomic_val->lock);
#endif
    atomic_store_uint8_t(atomic_val, initial);
}

INLINE bool atomic_cas_uint64_t(atomic_uint64_t *atomic_val,
                                uint64_t expected_val, uint64_t new_val) {
    bool rv = false;

#ifdef _MSC_VER
    spin_lock(&atomic_val->lock);
    if (atomic_val->val == expected_val) {
        atomic_val->val = new_val;
        rv = true;
    }
    spin_unlock(&atomic_val->lock);
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
    spin_lock(&atomic_val->lock);
    if (atomic_val->val == expected_val) {
        atomic_val->val = new_val;
        rv = true;
    }
    spin_unlock(&atomic_val->lock);
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
    spin_lock(&atomic_val->lock);
    if (atomic_val->val == expected_val) {
        atomic_val->val = new_val;
        rv = true;
    }
    spin_unlock(&atomic_val->lock);
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
    spin_lock(&atomic_val->lock);
    if (atomic_val->val == expected_val) {
        atomic_val->val = new_val;
        rv = true;
    }
    spin_unlock(&atomic_val->lock);
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
    spin_lock(&atomic_val->lock);
    uint64_t val = ++atomic_val->val;
    spin_unlock(&atomic_val->lock);
    return val;
#else
    return fdb_sync_add_and_fetch_64(&atomic_val->val, 1);
#endif
}

INLINE uint32_t atomic_incr_uint32_t(atomic_uint32_t *atomic_val) {
#ifdef _MSC_VER
    spin_lock(&atomic_val->lock);
    uint32_t val = ++atomic_val->val;
    spin_unlock(&atomic_val->lock);
    return val;
#else
    return fdb_sync_add_and_fetch_32(&atomic_val->val, 1);
#endif
}

INLINE uint16_t atomic_incr_uint16_t(atomic_uint16_t *atomic_val) {
#ifdef _MSC_VER
    spin_lock(&atomic_val->lock);
    uint16_t val = ++atomic_val->val;
    spin_unlock(&atomic_val->lock);
    return val;
#else
    return fdb_sync_add_and_fetch_16(&atomic_val->val, 1);
#endif
}

INLINE uint8_t atomic_incr_uint8_t(atomic_uint8_t *atomic_val) {
#ifdef _MSC_VER
    spin_lock(&atomic_val->lock);
    uint8_t val = ++atomic_val->val;
    spin_unlock(&atomic_val->lock);
    return val;
#else
    return fdb_sync_add_and_fetch_8(&atomic_val->val, 1);
#endif
}

INLINE uint64_t atomic_decr_uint64_t(atomic_uint64_t *atomic_val) {
#ifdef _MSC_VER
    spin_lock(&atomic_val->lock);
    uint64_t val = --atomic_val->val;
    spin_unlock(&atomic_val->lock);
    return val;
#else
    return fdb_sync_add_and_fetch_64(&atomic_val->val, -1);
#endif
}

INLINE uint32_t atomic_decr_uint32_t(atomic_uint32_t *atomic_val) {
#ifdef _MSC_VER
    spin_lock(&atomic_val->lock);
    uint32_t val = --atomic_val->val;
    spin_unlock(&atomic_val->lock);
    return val;
#else
    return fdb_sync_add_and_fetch_32(&atomic_val->val, -1);
#endif
}

INLINE uint16_t atomic_decr_uint16_t(atomic_uint16_t *atomic_val) {
#ifdef _MSC_VER
    spin_lock(&atomic_val->lock);
    uint16_t val = --atomic_val->val;
    spin_unlock(&atomic_val->lock);
    return val;
#else
    return fdb_sync_add_and_fetch_16(&atomic_val->val, -1);
#endif
}

INLINE uint8_t atomic_decr_uint8_t(atomic_uint8_t *atomic_val) {
#ifdef _MSC_VER
    spin_lock(&atomic_val->lock);
    uint8_t val = --atomic_val->val;
    spin_unlock(&atomic_val->lock);
    return val;
#else
    return fdb_sync_add_and_fetch_8(&atomic_val->val, -1);
#endif
}

INLINE uint64_t atomic_add_uint64_t(atomic_uint64_t *atomic_val, int64_t increment) {
#ifdef _MSC_VER
    spin_lock(&atomic_val->lock);
    atomic_val->val += increment;
    uint64_t val = atomic_val->val;
    spin_unlock(&atomic_val->lock);
    return val;
#else
    return fdb_sync_add_and_fetch_64(&atomic_val->val, increment);
#endif
}

INLINE uint32_t atomic_add_uint32_t(atomic_uint32_t *atomic_val, int32_t increment) {
#ifdef _MSC_VER
    spin_lock(&atomic_val->lock);
    atomic_val->val += increment;
    uint32_t val = atomic_val->val;
    spin_unlock(&atomic_val->lock);
    return val;
#else
    return fdb_sync_add_and_fetch_32(&atomic_val->val, increment);
#endif
}

INLINE uint16_t atomic_add_uint16_t(atomic_uint16_t *atomic_val, int16_t increment) {
#ifdef _MSC_VER
    spin_lock(&atomic_val->lock);
    atomic_val->val += increment;
    uint16_t val = atomic_val->val;
    spin_unlock(&atomic_val->lock);
    return val;
#else
    return fdb_sync_add_and_fetch_16(&atomic_val->val, increment);
#endif
}

INLINE uint8_t atomic_add_uint8_t(atomic_uint8_t *atomic_val, int8_t increment) {
#ifdef _MSC_VER
    spin_lock(&atomic_val->lock);
    atomic_val->val += increment;
    uint8_t val = atomic_val->val;
    spin_unlock(&atomic_val->lock);
    return val;
#else
    return fdb_sync_add_and_fetch_8(&atomic_val->val, increment);
#endif
}

INLINE uint64_t atomic_sub_uint64_t(atomic_uint64_t *atomic_val, int64_t decrement) {
#ifdef _MSC_VER
    spin_lock(&atomic_val->lock);
    atomic_val->val -= decrement;
    uint64_t val = atomic_val->val;
    spin_unlock(&atomic_val->lock);
    return val;
#else
    return fdb_sync_add_and_fetch_64(&atomic_val->val, -decrement);
#endif
}

INLINE uint32_t atomic_sub_uint32_t(atomic_uint32_t *atomic_val, int32_t decrement) {
#ifdef _MSC_VER
    spin_lock(&atomic_val->lock);
    atomic_val->val -= decrement;
    uint32_t val = atomic_val->val;
    spin_unlock(&atomic_val->lock);
    return val;
#else
    return fdb_sync_add_and_fetch_32(&atomic_val->val, -decrement);
#endif
}

INLINE uint16_t atomic_sub_uint16_t(atomic_uint16_t *atomic_val, int16_t decrement) {
#ifdef _MSC_VER
    spin_lock(&atomic_val->lock);
    atomic_val->val -= decrement;
    uint16_t val = atomic_val->val;
    spin_unlock(&atomic_val->lock);
    return val;
#else
    return fdb_sync_add_and_fetch_16(&atomic_val->val, -decrement);
#endif
}

INLINE uint8_t atomic_sub_uint8_t(atomic_uint8_t *atomic_val, int8_t decrement) {
#ifdef _MSC_VER
    spin_lock(&atomic_val->lock);
    atomic_val->val -= decrement;
    uint8_t val = atomic_val->val;
    spin_unlock(&atomic_val->lock);
    return val;
#else
    return fdb_sync_add_and_fetch_8(&atomic_val->val, -decrement);
#endif
}

// Reader-Writer spinlock
#ifndef _MSC_VER // TODO: Need to implement reader-writer spinlock on Windows.

typedef atomic_uint32_t rw_spin_t;

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
            sched_yield();
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
            sched_yield();
        }

        if((atomic_add_uint32_t(rw_lock, 0x100000) & 0xfff00000) == 0x100000) {
            // Wait until there's no more readers
            while (rw_lock->val & 0x000fffff) {
                sched_yield();
            }
            return;
        }

        atomic_sub_uint32_t(rw_lock, 0x100000);
    }
}

INLINE void rw_spin_write_unlock(rw_spin_t *rw_lock) {
    atomic_sub_uint32_t(rw_lock, 0x100000);
}

#endif // Reader-Writer spinlock

#ifdef __cplusplus
}
#endif

#endif  // FDB_ATOMIC_H_
