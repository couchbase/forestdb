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

void atomic_init_uint64_t(atomic_uint64_t *atomic_val, uint64_t initial) {
#ifdef _MSC_VER
    spin_init(&atomic_val->lock);
#endif
    atomic_store_uint64_t(atomic_val, initial);
}

void atomic_init_uint32_t(atomic_uint32_t *atomic_val, uint32_t initial) {
#ifdef _MSC_VER
    spin_init(&atomic_val->lock);
#endif
    atomic_store_uint32_t(atomic_val, initial);
}

void atomic_init_uint16_t(atomic_uint16_t *atomic_val, uint16_t initial) {
#ifdef _MSC_VER
    spin_init(&atomic_val->lock);
#endif
    atomic_store_uint16_t(atomic_val, initial);
}

void atomic_init_uint8_t(atomic_uint8_t *atomic_val, uint8_t initial) {
#ifdef _MSC_VER
    spin_init(&atomic_val->lock);
#endif
    atomic_store_uint8_t(atomic_val, initial);
}

void atomic_destroy_uint64_t(atomic_uint64_t *atomic_val) {
#ifdef _MSC_VER
    spin_destroy(&atomic_val->lock);
#endif
}

void atomic_destroy_uint32_t(atomic_uint32_t *atomic_val) {
#ifdef _MSC_VER
    spin_destroy(&atomic_val->lock);
#endif
}

void atomic_destroy_uint16_t(atomic_uint16_t *atomic_val) {
#ifdef _MSC_VER
    spin_destroy(&atomic_val->lock);
#endif
}

void atomic_destroy_uint8_t(atomic_uint8_t *atomic_val) {
#ifdef _MSC_VER
    spin_destroy(&atomic_val->lock);
#endif
}

void atomic_store_uint64_t(atomic_uint64_t *atomic_val, uint64_t new_val) {

    atomic_val->val = new_val;
    fdb_sync_synchronize();
}

void atomic_store_uint32_t(atomic_uint32_t *atomic_val, uint32_t new_val) {

    atomic_val->val = new_val;
    fdb_sync_synchronize();
}

void atomic_store_uint16_t(atomic_uint16_t *atomic_val, uint16_t new_val) {

    atomic_val->val = new_val;
    fdb_sync_synchronize();
}

void atomic_store_uint8_t(atomic_uint8_t *atomic_val, uint8_t new_val) {

    atomic_val->val = new_val;
    fdb_sync_synchronize();
}

bool atomic_cas_uint64_t(atomic_uint64_t *atomic_val,
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

bool atomic_cas_uint32_t(atomic_uint32_t *atomic_val,
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

bool atomic_cas_uint16_t(atomic_uint16_t *atomic_val,
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

bool atomic_cas_uint8_t(atomic_uint8_t *atomic_val,
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

void atomic_incr_uint64_t(atomic_uint64_t *atomic_val) {
#ifdef _MSC_VER
    spin_lock(&atomic_val->lock);
    ++atomic_val->val;
    spin_unlock(&atomic_val->lock);
#else
    fdb_sync_add_and_fetch_64(&atomic_val->val, 1);
#endif
}

void atomic_incr_uint32_t(atomic_uint32_t *atomic_val) {
#ifdef _MSC_VER
    spin_lock(&atomic_val->lock);
    ++atomic_val->val;
    spin_unlock(&atomic_val->lock);
#else
    fdb_sync_add_and_fetch_32(&atomic_val->val, 1);
#endif
}

void atomic_incr_uint16_t(atomic_uint16_t *atomic_val) {
#ifdef _MSC_VER
    spin_lock(&atomic_val->lock);
    ++atomic_val->val;
    spin_unlock(&atomic_val->lock);
#else
    fdb_sync_add_and_fetch_16(&atomic_val->val, 1);
#endif
}

void atomic_incr_uint8_t(atomic_uint8_t *atomic_val) {
#ifdef _MSC_VER
    spin_lock(&atomic_val->lock);
    ++atomic_val->val;
    spin_unlock(&atomic_val->lock);
#else
    fdb_sync_add_and_fetch_8(&atomic_val->val, 1);
#endif
}

void atomic_decr_uint64_t(atomic_uint64_t *atomic_val) {
#ifdef _MSC_VER
    spin_lock(&atomic_val->lock);
    --atomic_val->val;
    spin_unlock(&atomic_val->lock);
#else
    fdb_sync_add_and_fetch_64(&atomic_val->val, -1);
#endif
}

void atomic_decr_uint32_t(atomic_uint32_t *atomic_val) {
#ifdef _MSC_VER
    spin_lock(&atomic_val->lock);
    --atomic_val->val;
    spin_unlock(&atomic_val->lock);
#else
    fdb_sync_add_and_fetch_32(&atomic_val->val, -1);
#endif
}

void atomic_decr_uint16_t(atomic_uint16_t *atomic_val) {
#ifdef _MSC_VER
    spin_lock(&atomic_val->lock);
    --atomic_val->val;
    spin_unlock(&atomic_val->lock);
#else
    fdb_sync_add_and_fetch_16(&atomic_val->val, -1);
#endif
}

void atomic_decr_uint8_t(atomic_uint8_t *atomic_val) {
#ifdef _MSC_VER
    spin_lock(&atomic_val->lock);
    --atomic_val->val;
    spin_unlock(&atomic_val->lock);
#else
    fdb_sync_add_and_fetch_8(&atomic_val->val, -1);
#endif
}

void atomic_add_uint64_t(atomic_uint64_t *atomic_val, int64_t increment) {
#ifdef _MSC_VER
    spin_lock(&atomic_val->lock);
    atomic_val->val += increment;
    spin_unlock(&atomic_val->lock);
#else
    fdb_sync_add_and_fetch_64(&atomic_val->val, increment);
#endif
}

void atomic_add_uint32_t(atomic_uint32_t *atomic_val, int32_t increment) {
#ifdef _MSC_VER
    spin_lock(&atomic_val->lock);
    atomic_val->val += increment;
    spin_unlock(&atomic_val->lock);
#else
    fdb_sync_add_and_fetch_32(&atomic_val->val, increment);
#endif
}

void atomic_add_uint16_t(atomic_uint16_t *atomic_val, int16_t increment) {
#ifdef _MSC_VER
    spin_lock(&atomic_val->lock);
    atomic_val->val += increment;
    spin_unlock(&atomic_val->lock);
#else
    fdb_sync_add_and_fetch_16(&atomic_val->val, increment);
#endif
}

void atomic_add_uint8_t(atomic_uint8_t *atomic_val, int8_t increment) {
#ifdef _MSC_VER
    spin_lock(&atomic_val->lock);
    atomic_val->val += increment;
    spin_unlock(&atomic_val->lock);
#else
    fdb_sync_add_and_fetch_8(&atomic_val->val, increment);
#endif
}

void atomic_sub_uint64_t(atomic_uint64_t *atomic_val, int64_t decrement) {
#ifdef _MSC_VER
    spin_lock(&atomic_val->lock);
    atomic_val->val -= decrement;
    spin_unlock(&atomic_val->lock);
#else
    fdb_sync_add_and_fetch_64(&atomic_val->val, -decrement);
#endif
}

void atomic_sub_uint32_t(atomic_uint32_t *atomic_val, int32_t decrement) {
#ifdef _MSC_VER
    spin_lock(&atomic_val->lock);
    atomic_val->val -= decrement;
    spin_unlock(&atomic_val->lock);
#else
    fdb_sync_add_and_fetch_32(&atomic_val->val, -decrement);
#endif
}

void atomic_sub_uint16_t(atomic_uint16_t *atomic_val, int16_t decrement) {
#ifdef _MSC_VER
    spin_lock(&atomic_val->lock);
    atomic_val->val -= decrement;
    spin_unlock(&atomic_val->lock);
#else
    fdb_sync_add_and_fetch_16(&atomic_val->val, -decrement);
#endif
}

void atomic_sub_uint8_t(atomic_uint8_t *atomic_val, int8_t decrement) {
#ifdef _MSC_VER
    spin_lock(&atomic_val->lock);
    atomic_val->val -= decrement;
    spin_unlock(&atomic_val->lock);
#else
    fdb_sync_add_and_fetch_8(&atomic_val->val, -decrement);
#endif
}
