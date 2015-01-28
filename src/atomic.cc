/* -*- Mode: C++; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2011 Couchbase, Inc
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

#include "atomic.h"

void atomic_val_init_64(atomic_val_t *atomic_val, uint64_t initial) {
#ifdef _MSC_VER
    spin_init(&atomic_val->lock);
#endif
    atomic_val_store_64(atomic_val, initial);
}

void atomic_val_init_32(atomic_val_t *atomic_val, uint32_t initial) {
#ifdef _MSC_VER
    spin_init(&atomic_val->lock);
#endif
    atomic_val_store_32(atomic_val, initial);
}

void atomic_val_init_16(atomic_val_t *atomic_val, uint16_t initial) {
#ifdef _MSC_VER
    spin_init(&atomic_val->lock);
#endif
    atomic_val_store_16(atomic_val, initial);
}

void atomic_val_init_8(atomic_val_t *atomic_val, uint8_t initial) {
#ifdef _MSC_VER
    spin_init(&atomic_val->lock);
#endif
    atomic_val_store_8(atomic_val, initial);
}

void atomic_val_destroy(atomic_val_t *atomic_val) {
#ifdef _MSC_VER
    spin_destroy(&atomic_val->lock);
#endif
}

void atomic_val_store_64(atomic_val_t *atomic_val, uint64_t new_val) {

    atomic_val->value.val_64 = new_val;
    fdb_sync_synchronize();
}

void atomic_val_store_32(atomic_val_t *atomic_val, uint32_t new_val) {

    atomic_val->value.val_32 = new_val;
    fdb_sync_synchronize();
}

void atomic_val_store_16(atomic_val_t *atomic_val, uint16_t new_val) {

    atomic_val->value.val_16 = new_val;
    fdb_sync_synchronize();
}

void atomic_val_store_8(atomic_val_t *atomic_val, uint8_t new_val) {

    atomic_val->value.val_8 = new_val;
    fdb_sync_synchronize();
}

bool atomic_val_compare_and_set_64(atomic_val_t *atomic_val,
                                   uint64_t expected_val, uint64_t new_val) {
    bool rv = false;

#ifdef _MSC_VER
    spin_lock(&atomic_val->lock);
    if (atomic_val->value.val_64 == expected_val) {
        atomic_val->value.val_64 = new_val;
        rv = true;
    }
    spin_unlock(&atomic_val->lock);
#else
    if (fdb_sync_bool_compare_and_swap_64(&atomic_val->value.val_64,
                                          expected_val, new_val)) {
        rv = true;
    }
#endif

    return rv;
}

bool atomic_val_compare_and_set_32(atomic_val_t *atomic_val,
                                   uint32_t expected_val, uint32_t new_val) {
    bool rv = false;

#ifdef _MSC_VER
    spin_lock(&atomic_val->lock);
    if (atomic_val->value.val_32 == expected_val) {
        atomic_val->value.val_32 = new_val;
        rv = true;
    }
    spin_unlock(&atomic_val->lock);
#else
    if (fdb_sync_bool_compare_and_swap_32(&atomic_val->value.val_32,
                                          expected_val, new_val)) {
        rv = true;
    }
#endif

    return rv;
}

bool atomic_val_compare_and_set_16(atomic_val_t *atomic_val,
                                   uint16_t expected_val, uint16_t new_val) {
    bool rv = false;

#ifdef _MSC_VER
    spin_lock(&atomic_val->lock);
    if (atomic_val->value.val_16 == expected_val) {
        atomic_val->value.val_16 = new_val;
        rv = true;
    }
    spin_unlock(&atomic_val->lock);
#else
    if (fdb_sync_bool_compare_and_swap_16(&atomic_val->value.val_16,
                                          expected_val, new_val)) {
        rv = true;
    }
#endif

    return rv;
}

bool atomic_val_compare_and_set_8(atomic_val_t *atomic_val,
                                  uint8_t expected_val, uint8_t new_val) {
    bool rv = false;

#ifdef _MSC_VER
    spin_lock(&atomic_val->lock);
    if (atomic_val->value.val_8 == expected_val) {
        atomic_val->value.val_8 = new_val;
        rv = true;
    }
    spin_unlock(&atomic_val->lock);
#else
    if (fdb_sync_bool_compare_and_swap_8(&atomic_val->value.val_8,
                                         expected_val, new_val)) {
        rv = true;
    }
#endif

    return rv;
}

void atomic_val_incr_64(atomic_val_t *atomic_val) {
#ifdef _MSC_VER
    spin_lock(&atomic_val->lock);
    ++atomic_val->value.val_64;
    spin_unlock(&atomic_val->lock);
#else
    fdb_sync_add_and_fetch_64(&atomic_val->value.val_64, 1);
#endif
}

void atomic_val_incr_32(atomic_val_t *atomic_val) {
#ifdef _MSC_VER
    spin_lock(&atomic_val->lock);
    ++atomic_val->value.val_32;
    spin_unlock(&atomic_val->lock);
#else
    fdb_sync_add_and_fetch_32(&atomic_val->value.val_32, 1);
#endif
}

void atomic_val_incr_16(atomic_val_t *atomic_val) {
#ifdef _MSC_VER
    spin_lock(&atomic_val->lock);
    ++atomic_val->value.val_16;
    spin_unlock(&atomic_val->lock);
#else
    fdb_sync_add_and_fetch_16(&atomic_val->value.val_16, 1);
#endif
}

void atomic_val_incr_8(atomic_val_t *atomic_val) {
#ifdef _MSC_VER
    spin_lock(&atomic_val->lock);
    ++atomic_val->value.val_8;
    spin_unlock(&atomic_val->lock);
#else
    fdb_sync_add_and_fetch_8(&atomic_val->value.val_8, 1);
#endif
}

void atomic_val_decr_64(atomic_val_t *atomic_val) {
#ifdef _MSC_VER
    spin_lock(&atomic_val->lock);
    --atomic_val->value.val_64;
    spin_unlock(&atomic_val->lock);
#else
    fdb_sync_add_and_fetch_64(&atomic_val->value.val_64, -1);
#endif
}

void atomic_val_decr_32(atomic_val_t *atomic_val) {
#ifdef _MSC_VER
    spin_lock(&atomic_val->lock);
    --atomic_val->value.val_32;
    spin_unlock(&atomic_val->lock);
#else
    fdb_sync_add_and_fetch_32(&atomic_val->value.val_32, -1);
#endif
}

void atomic_val_decr_16(atomic_val_t *atomic_val) {
#ifdef _MSC_VER
    spin_lock(&atomic_val->lock);
    --atomic_val->value.val_16;
    spin_unlock(&atomic_val->lock);
#else
    fdb_sync_add_and_fetch_16(&atomic_val->value.val_16, -1);
#endif
}

void atomic_val_decr_8(atomic_val_t *atomic_val) {
#ifdef _MSC_VER
    spin_lock(&atomic_val->lock);
    --atomic_val->value.val_8;
    spin_unlock(&atomic_val->lock);
#else
    fdb_sync_add_and_fetch_8(&atomic_val->value.val_8, -1);
#endif
}

void atomic_val_add_64(atomic_val_t *atomic_val, int64_t increment) {
#ifdef _MSC_VER
    spin_lock(&atomic_val->lock);
    atomic_val->value.val_64 += increment;
    spin_unlock(&atomic_val->lock);
#else
    fdb_sync_add_and_fetch_64(&atomic_val->value.val_64, increment);
#endif
}

void atomic_val_add_32(atomic_val_t *atomic_val, int32_t increment) {
#ifdef _MSC_VER
    spin_lock(&atomic_val->lock);
    atomic_val->value.val_32 += increment;
    spin_unlock(&atomic_val->lock);
#else
    fdb_sync_add_and_fetch_32(&atomic_val->value.val_32, increment);
#endif
}

void atomic_val_add_16(atomic_val_t *atomic_val, int16_t increment) {
#ifdef _MSC_VER
    spin_lock(&atomic_val->lock);
    atomic_val->value.val_16 += increment;
    spin_unlock(&atomic_val->lock);
#else
    fdb_sync_add_and_fetch_16(&atomic_val->value.val_16, increment);
#endif
}

void atomic_val_add_8(atomic_val_t *atomic_val, int8_t increment) {
#ifdef _MSC_VER
    spin_lock(&atomic_val->lock);
    atomic_val->value.val_8 += increment;
    spin_unlock(&atomic_val->lock);
#else
    fdb_sync_add_and_fetch_8(&atomic_val->value.val_8, increment);
#endif
}

void atomic_val_sub_64(atomic_val_t *atomic_val, int64_t decrement) {
#ifdef _MSC_VER
    spin_lock(&atomic_val->lock);
    atomic_val->value.val_64 -= decrement;
    spin_unlock(&atomic_val->lock);
#else
    fdb_sync_add_and_fetch_64(&atomic_val->value.val_64, -decrement);
#endif
}

void atomic_val_sub_32(atomic_val_t *atomic_val, int32_t decrement) {
#ifdef _MSC_VER
    spin_lock(&atomic_val->lock);
    atomic_val->value.val_32 -= decrement;
    spin_unlock(&atomic_val->lock);
#else
    fdb_sync_add_and_fetch_32(&atomic_val->value.val_32, -decrement);
#endif
}

void atomic_val_sub_16(atomic_val_t *atomic_val, int16_t decrement) {
#ifdef _MSC_VER
    spin_lock(&atomic_val->lock);
    atomic_val->value.val_16 -= decrement;
    spin_unlock(&atomic_val->lock);
#else
    fdb_sync_add_and_fetch_16(&atomic_val->value.val_16, -decrement);
#endif
}

void atomic_val_sub_8(atomic_val_t *atomic_val, int8_t decrement) {
#ifdef _MSC_VER
    spin_lock(&atomic_val->lock);
    atomic_val->value.val_8 -= decrement;
    spin_unlock(&atomic_val->lock);
#else
    fdb_sync_add_and_fetch_8(&atomic_val->value.val_8, -decrement);
#endif
}
