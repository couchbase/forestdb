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

struct atomic_val_t {
    union {
        volatile uint64_t val_64;
        volatile uint32_t val_32;
        volatile uint16_t val_16;
        volatile uint8_t  val_8;
    } value;
#ifdef _MSC_VER
    // TODO: Need to figure out an atomic support without using lock.
    spin_t lock;
#endif
};

void atomic_val_init_64(atomic_val_t *atomic_val, uint64_t initial);
void atomic_val_init_32(atomic_val_t *atomic_val, uint32_t initial);
void atomic_val_init_16(atomic_val_t *atomic_val, uint16_t initial);
void atomic_val_init_8(atomic_val_t *atomic_val, uint8_t initial);

void atomic_val_destroy(atomic_val_t *atomic_val);

void atomic_val_store_64(atomic_val_t *atomic_val, uint64_t new_val);
void atomic_val_store_32(atomic_val_t *atomic_val, uint32_t new_val);
void atomic_val_store_16(atomic_val_t *atomic_val, uint16_t new_val);
void atomic_val_store_8(atomic_val_t *atomic_val, uint8_t new_val);


bool atomic_val_compare_and_set_64(atomic_val_t *atomic_val,
                                   uint64_t expected_val, uint64_t new_val);
bool atomic_val_compare_and_set_32(atomic_val_t *atomic_val,
                                   uint32_t expected_val, uint32_t new_val);
bool atomic_val_compare_and_set_16(atomic_val_t *atomic_val,
                                   uint16_t expected_val, uint16_t new_val);
bool atomic_val_compare_and_set_8(atomic_val_t *atomic_val,
                                  uint8_t expected_val, uint8_t new_val);


void atomic_val_incr_64(atomic_val_t *atomic_val);
void atomic_val_decr_64(atomic_val_t *atomic_val);
void atomic_val_incr_32(atomic_val_t *atomic_val);
void atomic_val_decr_32(atomic_val_t *atomic_val);
void atomic_val_incr_16(atomic_val_t *atomic_val);
void atomic_val_decr_16(atomic_val_t *atomic_val);
void atomic_val_incr_8(atomic_val_t *atomic_val);
void atomic_val_decr_8(atomic_val_t *atomic_val);

void atomic_val_add_64(atomic_val_t *atomic_val, int64_t increment);
void atomic_val_add_32(atomic_val_t *atomic_val, int32_t increment);
void atomic_val_add_16(atomic_val_t *atomic_val, int16_t increment);
void atomic_val_add_8(atomic_val_t *atomic_val, int8_t increment);

void atomic_val_sub_64(atomic_val_t *atomic_val, int64_t decrement);
void atomic_val_sub_32(atomic_val_t *atomic_val, int32_t decrement);
void atomic_val_sub_16(atomic_val_t *atomic_val, int16_t decrement);
void atomic_val_sub_8(atomic_val_t *atomic_val, int8_t decrement);

#ifdef __cplusplus
}
#endif

#endif  // FDB_ATOMIC_H_
