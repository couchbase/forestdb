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

void atomic_init_uint64_t(atomic_uint64_t *atomic_val, uint64_t initial);
void atomic_init_uint32_t(atomic_uint32_t *atomic_val, uint32_t initial);
void atomic_init_uint16_t(atomic_uint16_t *atomic_val, uint16_t initial);
void atomic_init_uint8_t(atomic_uint8_t *atomic_val, uint8_t initial);

void atomic_destroy_uint64_t(atomic_uint64_t *atomic_val);
void atomic_destroy_uint32_t(atomic_uint32_t *atomic_val);
void atomic_destroy_uint16_t(atomic_uint16_t *atomic_val);
void atomic_destroy_uint8_t(atomic_uint8_t *atomic_val);

void atomic_store_uint64_t(atomic_uint64_t *atomic_val, uint64_t new_val);
void atomic_store_uint32_t(atomic_uint32_t *atomic_val, uint32_t new_val);
void atomic_store_uint16_t(atomic_uint16_t *atomic_val, uint16_t new_val);
void atomic_store_uint8_t(atomic_uint8_t *atomic_val, uint8_t new_val);


bool atomic_cas_uint64_t(atomic_uint64_t *atomic_val,
                         uint64_t expected_val, uint64_t new_val);
bool atomic_cas_uint32_t(atomic_uint32_t *atomic_val,
                         uint32_t expected_val, uint32_t new_val);
bool atomic_cas_uint16_t(atomic_uint16_t *atomic_val,
                         uint16_t expected_val, uint16_t new_val);
bool atomic_cas_uint8_t(atomic_uint8_t *atomic_val,
                        uint8_t expected_val, uint8_t new_val);


void atomic_incr_uint64_t(atomic_uint64_t *atomic_val);
void atomic_decr_uint64_t(atomic_uint64_t *atomic_val);
void atomic_incr_uint32_t(atomic_uint32_t *atomic_val);
void atomic_decr_uint32_t(atomic_uint32_t *atomic_val);
void atomic_incr_uint16_t(atomic_uint16_t *atomic_val);
void atomic_decr_uint16_t(atomic_uint16_t *atomic_val);
void atomic_incr_uint8_t(atomic_uint8_t *atomic_val);
void atomic_decr_uint8_t(atomic_uint8_t *atomic_val);

void atomic_add_uint64_t(atomic_uint64_t *atomic_val, int64_t increment);
void atomic_add_uint32_t(atomic_uint32_t *atomic_val, int32_t increment);
void atomic_add_uint16_t(atomic_uint16_t *atomic_val, int16_t increment);
void atomic_add_uint8_t(atomic_uint8_t *atomic_val, int8_t increment);

void atomic_sub_uint64_t(atomic_uint64_t *atomic_val, int64_t decrement);
void atomic_sub_uint32_t(atomic_uint32_t *atomic_val, int32_t decrement);
void atomic_sub_uint16_t(atomic_uint16_t *atomic_val, int16_t decrement);
void atomic_sub_uint8_t(atomic_uint8_t *atomic_val, int8_t decrement);

#ifdef __cplusplus
}
#endif

#endif  // FDB_ATOMIC_H_
