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

#include "list.h"
#include "test.h"

void basic_test()
{
    TEST_INIT();

    struct dummy_t {
        int a;
        struct list_elem e;
    };

    int n=10, i;
    struct dummy_t dummy[n], *d;
    struct list list;
    struct list_elem *ee;

    list_init(&list);

    // push front 0 ~ 9
    for (i=0;i<n;++i){
        dummy[i].a = i;
        list_push_front(&list, &dummy[i].e);
    }

    // check in right order
    ee = list_begin(&list);
    i=9;
    while(ee) {
        d = _get_entry(ee, struct dummy_t, e);
        assert(d->a == i--);
        ee = list_next(ee);
    }
    // check in reversed order
    ee = list_end(&list);
    i=0;
    while(ee) {
        d = _get_entry(ee, struct dummy_t, e);
        TEST_CHK(d->a == i++);
        ee = list_prev(ee);
    }    

    // remove even numbers
    ee = list_begin(&list);
    while(ee){
        d = _get_entry(ee, struct dummy_t, e);
        if (d->a % 2 == 0) {
            ee = list_remove(&list, ee);
        }else
            ee = list_next(ee);
    }

    // check
    ee = list_begin(&list);
    i=9;
    while(ee) {
        d = _get_entry(ee, struct dummy_t, e);
        TEST_CHK(d->a == i);
        i-=2;
        ee = list_next(ee);
    }

    // remove head
    list_remove(&list, list_begin(&list));
    
    // check
    ee = list_begin(&list);
    i=7;
    while(ee) {
        d = _get_entry(ee, struct dummy_t, e);
        TEST_CHK(d->a == i);
        i-=2;
        ee = list_next(ee);
    }

    // pop front
    ee = list_pop_front(&list);
    // check
    d = _get_entry(ee, struct dummy_t, e);
    TEST_CHK(d->a == 7);
    ee = list_begin(&list);
    i=5;
    while(ee) {
        d = _get_entry(ee, struct dummy_t, e);
        TEST_CHK(d->a == i);
        i-=2;
        ee = list_next(ee);
    }

    // pop back
    ee = list_pop_back(&list);
    // check
    d = _get_entry(ee, struct dummy_t, e);
    TEST_CHK(d->a == 1);
    ee = list_begin(&list);
    i=5;
    while(ee) {
        d = _get_entry(ee, struct dummy_t, e);
        TEST_CHK(d->a == i);
        i-=2;
        ee = list_next(ee);
    }

    TEST_RESULT("basic test");
}


void insert_test()
{
    TEST_INIT();

    int n= 5;
    int i;
    struct list list;
    struct list_elem *e;
    struct dummy_t {
        int value;
        struct list_elem e;
    } dummy[n], dummy_a, dummy_b, dummy_c, dummy_d, *dummy_ptr;

    list_init(&list);
    
    for (i=0;i<n;++i){
        dummy[i].value = i;
        list_push_back(&list, &dummy[i].e);
    }

    dummy_a.value = 11;
    dummy_b.value = 22;
    dummy_c.value = 33;
    dummy_d.value = 44;

    list_insert_before(&list, &dummy[0].e, &dummy_a.e);
    list_insert_after(&list, &dummy[n-1].e, &dummy_b.e); 
    list_insert_before(&list, &dummy[2].e, &dummy_c.e);
    list_insert_after(&list, &dummy[3].e, &dummy_d.e);

    e = list_begin(&list);
    while(e){
        dummy_ptr = _get_entry(e, struct dummy_t, e);
        printf("%d\n", dummy_ptr->value);
        e = list_next(e);
    }

    TEST_RESULT("insert test");
}

int main(){
    basic_test();
    insert_test();

    return 0;
}
