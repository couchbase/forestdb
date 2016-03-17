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

#include <atomic>

#ifdef __cplusplus
extern "C" {
#endif

// C++11 has built-in atomic support.
#define atomic_uint64_t std::atomic<uint64_t>
#define atomic_uint32_t std::atomic<uint32_t>
#define atomic_uint16_t std::atomic<uint16_t>
#define atomic_uint8_t std::atomic<uint8_t>


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
        while (std::atomic_load_explicit(rw_lock, std::memory_order_relaxed) &
               0xfff00000) {
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
        while (std::atomic_load_explicit(rw_lock, std::memory_order_relaxed) &
               0xfff00000) {
            thread_yield();
        }

        if((atomic_add_uint32_t(rw_lock, 0x100000) & 0xfff00000) == 0x100000) {
            // Wait until there's no more readers
            while (std::atomic_load_explicit(rw_lock, std::memory_order_relaxed) &
                   0x000fffff) {
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
