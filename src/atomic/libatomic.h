/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
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

#ifndef FDB_ATOMIC_LIBATOMIC_H_
#define FDB_ATOMIC_LIBATOMIC_H_ 1

#include "config.h"

#include <atomic.h>

#ifdef __cplusplus
extern "C" {
#endif

inline int fdb_sync_lock_test_and_set(volatile int *dest, int value) {
    return atomic_swap_uint((volatile uint*)dest, value);
}

inline void fdb_sync_lock_release(volatile int *dest) {
    atomic_swap_uint((volatile uint*)dest, 0);
}

inline void fdb_sync_synchronize(void) {
    // TODO: Need to implement it.
}

inline uint64_t fdb_sync_add_and_fetch_64(volatile uint64_t *dest,
                                          int64_t delta) {
     if (delta == 1) {
         return atomic_inc_64_nv(dest);
     } else {
         return atomic_add_64_nv(dest, delta);
     }
}

inline uint32_t fdb_sync_add_and_fetch_32(volatile uint32_t *dest,
                                          int32_t delta) {
     if (delta == 1) {
         return atomic_inc_32_nv(dest);
     } else {
         return atomic_add_32_nv(dest, delta);
     }
}

inline uint16_t fdb_sync_add_and_fetch_16(volatile uint16_t *dest, int16_t delta) {
    if (delta == 1) {
        return atomic_inc_16_nv(dest);
    } else {
        return atomic_add_16_nv(dest, delta);
    }
}

inline uint8_t fdb_sync_add_and_fetch_8(volatile uint8_t *dest,
                                        int8_t delta) {
    if (delta == 1) {
        return atomic_inc_8_nv(dest);
    } else {
        return atomic_add_8_nv(dest, delta);
    }
}

inline uint64_t fdb_sync_fetch_and_add_64(volatile uint64_t *dest,
                                          int64_t delta) {
    uint64_t original = *dest;
    if (delta == 1) {
        atomic_inc_64(dest);
    } else {
        atomic_add_64(dest, delta);
    }

    return original;
}

inline uint32_t fdb_sync_fetch_and_add_32(volatile uint32_t *dest,
                                          int32_t delta) {
    uint32_t original = *dest;
    if (delta == 1) {
        atomic_inc_32(dest);
    } else {
        atomic_add_32(dest, delta);
    }

    return original;
}

inline uint16_t fdb_sync_fetch_and_add_16(volatile uint16_t *dest, int16_t delta) {
    uint16_t original = *dest;
    if (delta == 1) {
        atomic_inc_16(dest);
    } else {
        atomic_add_16(dest, delta);
    }
    return original;
}

inline uint8_t fdb_sync_fetch_and_add_8(volatile uint8_t *dest, int8_t delta) {
    uint8_t original = *dest;
    if (delta == 1) {
        atomic_inc_8(dest);
    } else {
        atomic_add_8(dest, delta);
    }

    return original;
}

inline bool fdb_sync_bool_compare_and_swap_64(volatile uint64_t *dest,
                                              uint64_t prev,
                                              uint64_t next) {
    uint64_t original = *dest;
    if (original == atomic_cas_64(dest, prev, next)) {
        return true;
    } else {
        return false;
    }
}

inline bool fdb_sync_bool_compare_and_swap_32(volatile uint32_t *dest,
                                              uint32_t prev,
                                              uint32_t next) {
    uint32_t original = *dest;
    if (original == atomic_cas_32(dest, prev, next)) {
        return true;
    } else {
        return false;
    }
}

inline bool fdb_sync_bool_compare_and_swap_16(volatile uint16_t *dest,
                                               uint16_t prev, uint16_t next) {
    uint16_t original = *dest;
    if (original == atomic_cas_16(dest, prev, next)) {
        return true;
    } else {
        return false;
    }
}

inline bool fdb_sync_bool_compare_and_swap_8(volatile uint8_t *dest,
                                             uint8_t prev, uint8_t next) {
    uint8_t original = *dest;
    if (original == atomic_cas_8((volatile uint8_t*)dest,
                                 (uint8_t)prev, (uint8_t)next)) {
        return true;
    } else {
        return false;
    }
}

#ifdef __cplusplus
}
#endif

#endif  // FDB_ATOMIC_LIBATOMIC_H_
