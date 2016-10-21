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

#include "hash.h"
#include "test.h"
#include "common.h"
#include "hash_functions.h"

struct item {
    int val;
    struct hash_elem e;
};

unsigned hash_func(struct hash *hash, struct hash_elem *e)
{
    struct item *item = _get_entry(e, struct item, e);
    return item->val % hash->nbuckets;
}

int hash_cmp(struct hash_elem *a, struct hash_elem *b)
{
    struct item *aa, *bb;
    aa = _get_entry(a, struct item, e);
    bb = _get_entry(b, struct item, e);
    if (aa->val < bb->val) return -1;
    else if (aa->val > bb->val) return 1;
    else return 0;
}

void basic_test()
{
    TEST_INIT();

    struct hash hash;
    struct item item[16], query, *result;
    struct hash_elem *e;
    int i;

    hash_init(&hash, 4, hash_func, hash_cmp);

    for (i=0;i<16;++i){
        item[i].val = i;
        hash_insert(&hash, &item[i].e);
    }

    for (i=0;i<16;++i){
        query.val = i;
        e = hash_find(&hash, &query.e);
        result = _get_entry(e, struct item, e);
        TEST_CHK(result->val == query.val);
    }

    for (i=1;i<16;i+=2){
        query.val = i;
        e = hash_find(&hash, &query.e);
        result = _get_entry(e, struct item, e);
        TEST_CHK(result->val == query.val);
        hash_remove(&hash, e);
    }

    for (i=0;i<16;++i){
        query.val = i;
        e = hash_find(&hash, &query.e);
        TEST_CHK((i%2==1 && e==NULL) || (i%2==0 && e));
        if (e) {
            result = _get_entry(e, struct item, e);
            TEST_CHK(result->val == query.val);
        }
    }
    hash_free(&hash);

    TEST_RESULT("basic test");
}

void string_hash_test()
{
    TEST_INIT();

    randomize();
    unsigned a, b;
    char str[32];

    int i,j;

    for (i=0;i<16;++i){
        for (j=0;j<8;++j){
            str[j] = 'a' + random('z'-'a');
        }
        str[j] = 0;
        b = hash_djb2((uint8_t *)str, strlen(str));
        (void)b;
        DBG("%s %10u %5u\n",str, b, b&0xfff);
    }

    for (i=0;i<16;++i){
        sprintf(str, "asdf%d.%d",i,random(100));
        b = hash_djb2((uint8_t *)str, strlen(str));
        (void)b;
        DBG("%s %10u %5u\n",str, b, b&((unsigned)1023));
    }

    sprintf(str, "1234aaaaaaaa");
    a = hash_djb2((uint8_t *)str, strlen(str));
    (void)a;
    sprintf(str, "5678aaaaaaaa");
    b = hash_djb2((uint8_t *)str, strlen(str));
    (void)b;
    DBG("%u %u\n", a, b);

    sprintf(str, "1234aaaaaaaa");
    a = hash_djb2_last8((uint8_t *)str, strlen(str));
    (void)a;
    sprintf(str, "5678aaaaaaaa");
    b = hash_djb2_last8((uint8_t *)str, strlen(str));
    (void)b;
    DBG("%u %u\n", a, b);

    sprintf(str, "./dummy0");
    a = hash_djb2_last8((uint8_t *)str, strlen(str));
    (void)a;
    sprintf(str, "./dummy01");
    b = hash_djb2_last8((uint8_t *)str, strlen(str));
    (void)b;
    DBG("%u %u\n", a, b);

    TEST_RESULT("string hash test");
}

void twohash_test()
{
    TEST_INIT();

    randomize();

    int n = 64;
    int i,j;
    uint32_t h;
    int *array = alca(int, n);

    for (i=100;i<108;++i) {
        for (j=333;j<341;++j){
            printf("(%d,%d) = %u\n", i, j, hash_shuffle_2uint(i,j));
        }
    }
    for (i=0;i<n;++i) array[i] = 0;
    for (i=0;i<1000;++i) {
        for (j=0;j<1000;++j){
            h = hash_shuffle_2uint(random(32768), random(32768)) & (uint32_t)(n-1);
            array[h]++;
        }
    }
    for (i=0;i<n;++i) {
        DBG("%d %d\n",i,array[i]);
    }

    TEST_RESULT("two-integer hash test");
}

int main()
{
    basic_test();
    string_hash_test();
    //twohash_test();

    return 0;
}
