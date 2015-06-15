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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "test.h"
#include "atomic.h"

#include "memleak.h"

void basic_test()
{
    TEST_INIT();

    atomic_uint64_t counter_64;
    uint64_t val_64 = 0, val_64_new = 200;
    int64_t delta_64 = 10;
    atomic_init_uint64_t(&counter_64, val_64);
    val_64 = 100;
    atomic_store_uint64_t(&counter_64, val_64);
    TEST_CHK(atomic_get_uint64_t(&counter_64) == 100);
    atomic_cas_uint64_t(&counter_64, val_64, val_64_new);
    TEST_CHK(atomic_get_uint64_t(&counter_64) == 200);
    atomic_incr_uint64_t(&counter_64);
    TEST_CHK(atomic_get_uint64_t(&counter_64) == 201);
    atomic_decr_uint64_t(&counter_64);
    TEST_CHK(atomic_get_uint64_t(&counter_64) == 200);
    atomic_add_uint64_t(&counter_64, delta_64);
    TEST_CHK(atomic_get_uint64_t(&counter_64) == 210);
    atomic_sub_uint64_t(&counter_64, delta_64);
    TEST_CHK(atomic_get_uint64_t(&counter_64) == 200);
    atomic_destroy_uint64_t(&counter_64);

    atomic_uint32_t counter_32;
    uint32_t val_32 = 0, val_32_new = 200;
    int32_t delta_32 = 10;
    atomic_init_uint32_t(&counter_32, val_32);
    val_32 = 100;
    atomic_store_uint32_t(&counter_32, val_32);
    TEST_CHK(atomic_get_uint32_t(&counter_32) == 100);
    atomic_cas_uint32_t(&counter_32, val_32, val_32_new);
    TEST_CHK(atomic_get_uint32_t(&counter_32) == 200);
    atomic_incr_uint32_t(&counter_32);
    TEST_CHK(atomic_get_uint32_t(&counter_32) == 201);
    atomic_decr_uint32_t(&counter_32);
    TEST_CHK(atomic_get_uint32_t(&counter_32) == 200);
    atomic_add_uint32_t(&counter_32, delta_32);
    TEST_CHK(atomic_get_uint32_t(&counter_32) == 210);
    atomic_sub_uint32_t(&counter_32, delta_32);
    TEST_CHK(atomic_get_uint32_t(&counter_32) == 200);
    atomic_destroy_uint32_t(&counter_32);

    atomic_uint16_t counter_16;
    uint16_t val_16 = 0, val_16_new = 200;
    int16_t delta_16 = 10;
    atomic_init_uint16_t(&counter_16, val_16);
    val_16 = 100;
    atomic_store_uint16_t(&counter_16, val_16);
    TEST_CHK(atomic_get_uint16_t(&counter_16) == 100);
    atomic_cas_uint16_t(&counter_16, val_16, val_16_new);
    TEST_CHK(atomic_get_uint16_t(&counter_16) == 200);
    atomic_incr_uint16_t(&counter_16);
    TEST_CHK(atomic_get_uint16_t(&counter_16) == 201);
    atomic_decr_uint16_t(&counter_16);
    TEST_CHK(atomic_get_uint16_t(&counter_16) == 200);
    atomic_add_uint16_t(&counter_16, delta_16);
    TEST_CHK(atomic_get_uint16_t(&counter_16) == 210);
    atomic_sub_uint16_t(&counter_16, delta_16);
    TEST_CHK(atomic_get_uint16_t(&counter_16) == 200);
    atomic_destroy_uint16_t(&counter_16);

    atomic_uint8_t counter_8;
    uint8_t val_8 = 0, val_8_new = 100;
    int8_t delta_8 = 10;
    atomic_init_uint8_t(&counter_8, val_8);
    val_8 = 50;
    atomic_store_uint8_t(&counter_8, val_8);
    TEST_CHK(atomic_get_uint8_t(&counter_8) == 50);
    atomic_cas_uint8_t(&counter_8, val_8, val_8_new);
    TEST_CHK(atomic_get_uint8_t(&counter_8) == 100);
    atomic_incr_uint8_t(&counter_8);
    TEST_CHK(atomic_get_uint8_t(&counter_8) == 101);
    atomic_decr_uint8_t(&counter_8);
    TEST_CHK(atomic_get_uint8_t(&counter_8) == 100);
    atomic_add_uint8_t(&counter_8, delta_8);
    TEST_CHK(atomic_get_uint8_t(&counter_8) == 110);
    atomic_sub_uint8_t(&counter_8, delta_8);
    TEST_CHK(atomic_get_uint8_t(&counter_8) == 100);
    atomic_destroy_uint8_t(&counter_8);

    TEST_RESULT("basic test");
}

struct worker_args {
    atomic_uint64_t *counter_64;
    atomic_uint32_t *counter_32;
    atomic_uint16_t *counter_16;
    atomic_uint8_t *counter_8;
};

void * worker(void *voidargs)
{
    struct worker_args *args = (struct worker_args*)voidargs;
    int i = 0;
    int64_t delta_64 = 10;
    int32_t delta_32 = 5;
    int16_t delta_16 = 3;
    int8_t delta_8 = 1;

    for (; i < 10000; ++i) {
        atomic_incr_uint64_t(args->counter_64);
        atomic_decr_uint64_t(args->counter_64);
        atomic_add_uint64_t(args->counter_64, delta_64);
        atomic_sub_uint64_t(args->counter_64, delta_64);

        atomic_incr_uint32_t(args->counter_32);
        atomic_decr_uint32_t(args->counter_32);
        atomic_add_uint32_t(args->counter_32, delta_32);
        atomic_sub_uint32_t(args->counter_32, delta_32);

        atomic_incr_uint16_t(args->counter_16);
        atomic_decr_uint16_t(args->counter_16);
        atomic_add_uint16_t(args->counter_16, delta_16);
        atomic_sub_uint16_t(args->counter_16, delta_16);

        atomic_incr_uint8_t(args->counter_8);
        atomic_decr_uint8_t(args->counter_8);
        atomic_add_uint8_t(args->counter_8, delta_8);
        atomic_sub_uint8_t(args->counter_8, delta_8);
    }

    thread_exit(0);
    return NULL;
}

void multi_thread_test(int num_threads)
{
    TEST_INIT();

    thread_t *tid = alca(thread_t, num_threads);
    struct worker_args *args = alca(struct worker_args, num_threads);
    void **ret = alca(void *, num_threads);

    int i = 0;
    atomic_uint64_t counter_64;
    uint64_t val_64 = 0;
    atomic_uint32_t counter_32;
    uint32_t val_32 = 0;
    atomic_uint16_t counter_16;
    uint16_t val_16 = 0;
    atomic_uint8_t counter_8;
    uint8_t val_8 = 0;

    atomic_init_uint64_t(&counter_64, val_64);
    atomic_init_uint32_t(&counter_32, val_32);
    atomic_init_uint16_t(&counter_16, val_16);
    atomic_init_uint8_t(&counter_8, val_8);

    for (; i < num_threads; ++i){
        args[i].counter_64 = &counter_64;
        args[i].counter_32 = &counter_32;
        args[i].counter_16 = &counter_16;
        args[i].counter_8 = &counter_8;
        thread_create(&tid[i], worker, &args[i]);
    }

    for (i = 0; i < num_threads; ++i){
        thread_join(tid[i], &ret[i]);
    }

    TEST_CHK(atomic_get_uint64_t(&counter_64) == 0);
    TEST_CHK(atomic_get_uint32_t(&counter_32) == 0);
    TEST_CHK(atomic_get_uint16_t(&counter_16) == 0);
    TEST_CHK(atomic_get_uint8_t(&counter_8) == 0);

    atomic_destroy_uint64_t(&counter_64);
    atomic_destroy_uint32_t(&counter_32);
    atomic_destroy_uint16_t(&counter_16);
    atomic_destroy_uint8_t(&counter_8);

    TEST_RESULT("multi thread test");
}

int main()
{
    basic_test();
    multi_thread_test(8);

    return 0;
}
