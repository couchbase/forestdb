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
#include "mempool.h"

#include "memleak.h"

struct test_struct {
    uint64_t a[4];
};

#define random_custom(prev, num) (prev) = ((prev)+811)&((num)-1)

void basic_test()
{
    TEST_INIT();

    int i, j, n=9;
    struct test_struct *arr[n];
    
    mempool_init();
    for (i=0;i<n;++i){
        arr[i] = (struct test_struct *)mempool_alloc(sizeof(struct test_struct));    
        for (j=0;j<4;++j) arr[i]->a[j] = 0;
    }
    for (i=0;i<n;++i){
        mempool_free(arr[i]);
    }

    for (i=0;i<n;++i){
        arr[i] = (struct test_struct *)mempool_alloc(sizeof(struct test_struct));    
        for (j=0;j<4;++j) arr[i]->a[j] = 0;
    }
    for (i=0;i<n;++i){
        mempool_free(arr[i]);
    }

    TEST_RESULT("basic test");
}

void speed_test()
{
    TEST_INIT();

    int i, j, n=3000, m=1000;
    void *ptr[m];
    size_t size[m];
    char dummy[65536];
    unsigned r;

    memleak_start();

    mempool_init();

    DBG("test start\n");
    TEST_TIME();
    
    for (i=0;i<n;++i){
        for (j=0;j<m;++j){
            size[j] = r = random_custom(r, 0xff);
            ptr[j] = malloc(32+size[j]);
        }
        for (j=0;j<m;++j)
            memcpy(ptr[j], dummy, size[j]);
        for (j=0;j<m;++j)
            free(ptr[j]);
    }

    TEST_TIME();

    for (i=0;i<n;++i){
        for (j=0;j<m;++j){
            size[j] = r = random_custom(r, 0xff);
            ptr[j] = mempool_alloc(32+size[j]);
        }
        for (j=0;j<m;++j)
            memcpy(ptr[j], dummy, size[j]);
        for (j=0;j<m;++j)
            mempool_free(ptr[j]);
    }

    TEST_TIME();

    mempool_shutdown();

    memleak_end();

    TEST_RESULT("speed test");
}

int main()
{
    //basic_test();
    speed_test();

    return 0;
}
