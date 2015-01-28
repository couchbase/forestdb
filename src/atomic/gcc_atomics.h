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

#ifndef FDB_ATOMIC_GCC_ATOMICS_H_
#define FDB_ATOMIC_GCC_ATOMICS_H_ 1

#include "config.h"

#ifdef __cplusplus
extern "C" {
#endif

#define fdb_sync_lock_release(a) __sync_lock_release(a)
#define fdb_sync_lock_test_and_set(a, b) __sync_lock_test_and_set(a, b)
#define fdb_sync_synchronize() __sync_synchronize()

#define fdb_sync_add_and_fetch_64(a, b) __sync_add_and_fetch(a, b);
#define fdb_sync_bool_compare_and_swap_64(a, b, c) __sync_bool_compare_and_swap(a, b, c)
#define fdb_sync_fetch_and_add_64(a, b) __sync_fetch_and_add(a, b);

#define fdb_sync_add_and_fetch_32(a, b) __sync_add_and_fetch(a, b);
#define fdb_sync_bool_compare_and_swap_32(a, b, c) __sync_bool_compare_and_swap(a, b, c)
#define fdb_sync_fetch_and_add_32(a, b) __sync_fetch_and_add(a, b);

#define fdb_sync_add_and_fetch_16(a, b) __sync_add_and_fetch(a, b);
#define fdb_sync_bool_compare_and_swap_16(a, b, c) __sync_bool_compare_and_swap(a, b, c)
#define fdb_sync_fetch_and_add_16(a, b) __sync_fetch_and_add(a, b);

#define fdb_sync_add_and_fetch_8(a, b) __sync_add_and_fetch(a, b);
#define fdb_sync_bool_compare_and_swap_8(a, b, c) __sync_bool_compare_and_swap(a, b, c)
#define fdb_sync_fetch_and_add_8(a, b) __sync_fetch_and_add(a, b);

#ifdef __cplusplus
}
#endif

#endif  // FDB_ATOMIC_GCC_ATOMICS_H_
