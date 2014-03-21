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

#include "btree.h"
#include "btree_kv.h"
#include "test.h"
#include "blk_dummy.h"


void print_btree(struct btree *btree, void *key, void *value)
{
    DBG("(%"_F64" %"_F64")", *(uint64_t*)key, *(uint64_t*)value);
}

void getsetkv_test()
{
    TEST_INIT();

    int i;
    int a,b,c;
    struct btree btree;
    struct bnode node;
    struct btree_blk_ops *blk_ops;
    struct btree_kv_ops *kv_ops;

    dummy_init(4096, 10);
    blk_ops = dummy_get_ops();
    kv_ops = btree_kv_get_ku64_vu64();

    btree_init(&btree, NULL, blk_ops, kv_ops, 4096, 4, 8, 0x0, NULL);

    node.data = (void *)malloc(4096);
    node.kvsize = 0x88;

    // basic test
    a = b = c = 0;
    for (i=0;i<10;++i) {
        a = i;
        b += i;
        btree.kv_ops->set_kv(&node, i, &a, &b);
    }
    for (i=0;i<10;++i) {
        c += i;
        btree.kv_ops->get_kv(&node, i, &a, &b);
        
        #ifdef __DEBUG
            fprintf(stderr, "%d %d\n", a, b);
        #endif
        
        TEST_CHK(a==i);
        TEST_CHK(b==c);
    }

    dummy_close();
    
    TEST_RESULT("get set kv test");
}

void basic_test()
{
    TEST_INIT();

    btree_result r;
    struct btree btree;
    uint64_t a,b;
    struct btree_blk_ops *blk_ops;
    struct btree_kv_ops *kv_ops;

    dummy_init(sizeof(struct bnode) + 16*4, 10);
    blk_ops = dummy_get_ops();
    kv_ops = btree_kv_get_ku64_vu64();

    btree_init(&btree, NULL, blk_ops, kv_ops, sizeof(struct bnode) + 16*4, 8, 8, 0x0, NULL);

    a = b = 1;
    r = btree_insert(&btree, &a, &b);
    a = b = 2;
    r = btree_insert(&btree, &a, &b);

    r = btree_find(&btree, &a, &b);
    TEST_CHK(b==2);

    a = 1;
    r = btree_find(&btree, &a, &b);
    TEST_CHK(b==1);
    
    a = 3;
    r = btree_find(&btree, &a, &b);
    TEST_CHK(r==BTREE_RESULT_FAIL);

    // update value
    a = 1; b = 99;
    r = btree_insert(&btree, &a, &b);
    TEST_CHK(r!=BTREE_RESULT_FAIL);
    b = 0;
    r = btree_find(&btree, &a, &b);
    TEST_CHK(r!=BTREE_RESULT_FAIL && b==99);

    btree_print_node(&btree, print_btree);

    dummy_close();

    TEST_RESULT("basic test");
}

void split_test()
{
    TEST_INIT();

    struct btree btree;
    btree_result r;
    struct btree_blk_ops *blk_ops;
    struct btree_kv_ops *kv_ops;
    int i;
    uint64_t a,b,c;
    
    dummy_init(sizeof(struct bnode) + 16*4, 100);
    blk_ops = dummy_get_ops();
    kv_ops = btree_kv_get_ku64_vu64();

    // maximum 4 kv-pairs per node
    btree_init(&btree, NULL, blk_ops, kv_ops, sizeof(struct bnode) + 16*4, 8, 8, 0x0, NULL);

    for (i=10;i<17;++i){
        a = i*2; b = i*10;
        r = btree_insert(&btree, &a, &b);
        TEST_CHK(r != BTREE_RESULT_FAIL);
    }

    btree_print_node(&btree, print_btree);

    for (i=9;i>=5;--i) {
        a = i*2; b = i*10;
        r = btree_insert(&btree, &a, &b);
        TEST_CHK(r != BTREE_RESULT_FAIL);
    }

    btree_print_node(&btree, print_btree);

    a = 9; b=99;
    r = btree_insert(&btree, &a, &b);

    btree_print_node(&btree, print_btree);

    for (i=5;i<17;++i){
        a = i*2;
        r = btree_find(&btree, &a, &b);
        TEST_CHK(r != BTREE_RESULT_FAIL);
        TEST_CHK(b == i*10);
    }

    TEST_RESULT("split test");
}

void remove_test()
{
    TEST_INIT();

    struct btree btree;
    btree_result r;
    struct btree_blk_ops *blk_ops;
    struct btree_kv_ops *kv_ops;
    int i;
    uint64_t a,b,c;
    
    dummy_init(sizeof(struct bnode) + 16*4, 100);
    blk_ops = dummy_get_ops();
    kv_ops = btree_kv_get_ku64_vu64();

    // maximum 4 kv-pairs per node
    btree_init(&btree, NULL, blk_ops, kv_ops, sizeof(struct bnode) + 16*4, 8, 8, 0x0, NULL);

    for (i=0;i<12;++i) {
        a = i; b = i*10;
        r = btree_insert(&btree, &a, &b);
        TEST_CHK(r != BTREE_RESULT_FAIL);        
    }

    btree_print_node(&btree, print_btree);

    for (i=2;i<=5;++i){
        a = i; b = i*10;
        r = btree_remove(&btree, &a);
        btree_print_node(&btree, print_btree);
    }
    for (i=0;i<2;++i) {
        a = i; b = i*10;
        r = btree_remove(&btree, &a);
        btree_print_node(&btree, print_btree);
    }

    for (i=0;i<=5;++i){
        a = i;
        r = btree_find(&btree, &a, &b);
        TEST_CHK(r == BTREE_RESULT_FAIL);
    }
    for (i=6;i<12;++i){
        a = i;
        r = btree_find(&btree, &a, &b);
        TEST_CHK(b == i*10);
    }

    TEST_RESULT("remove test");
}

void flush_test()
{
    TEST_INIT();

    struct btree btree;
    btree_result r;
    struct btree_blk_ops *blk_ops;
    struct btree_kv_ops *kv_ops;
    int i;
    uint64_t a,b,c;
    
    dummy_init(sizeof(struct bnode) + 16*4, 100);
    blk_ops = dummy_get_ops();
    kv_ops = btree_kv_get_ku64_vu64();

    // maximum 4 kv-pairs per node
    btree_init(&btree, NULL, blk_ops, kv_ops, sizeof(struct bnode) + 16*4, 8, 8, 0x0, NULL);

    for (i=0;i<12;++i){
        a = i; b = i*10;
        r = btree_insert(&btree, &a, &b);
        TEST_CHK(r != BTREE_RESULT_FAIL);
    }
    dummy_flush();

    btree_print_node(&btree, print_btree);

    // update one entry and flush
    a = 10; b = 99;
    r = btree_insert(&btree, &a, &b);
    dummy_flush();

    btree_print_node(&btree, print_btree);

    // update two entries and flush
    a = 5; b=55;
    r = btree_insert(&btree, &a, &b);
    a = 3; b=33;
    r = btree_insert(&btree, &a, &b);
    dummy_flush();

    btree_print_node(&btree, print_btree);

    // remove one entry and flush
    a = 0;
    r = btree_remove(&btree, &a);
    dummy_flush();
    btree_print_node(&btree, print_btree);
    
    TEST_RESULT("flush test");
}

void metadata_test()
{
    TEST_INIT();

    struct btree btree;
    btree_result r;
    struct btree_blk_ops *blk_ops;
    struct btree_kv_ops *kv_ops;
    struct btree_meta meta, meta2;
    uint8_t buf[1024];
    char *prefix="testprefix";
    int i;
    uint64_t a,b,c;
    
    dummy_init(sizeof(struct bnode) + 16*4, 100);
    blk_ops = dummy_get_ops();
    kv_ops = btree_kv_get_ku64_vu64();

    // maximum 4 kv-pairs per node
    meta.data = prefix;
    meta.size = strlen(prefix);
    btree_init(&btree, NULL, blk_ops, kv_ops, sizeof(struct bnode) + 16*4, 8, 8, 0x0, &meta);    

    for (i=0;i<4;++i) {
        a = i; b = i*10;
        r = btree_insert(&btree, &a, &b);
        if (i==2) btree_print_node(&btree, print_btree);
    }
    r = btree_find(&btree, &a, &c);

    TEST_CHK(c == b);

    btree_print_node(&btree, print_btree);

    meta2.size = btree_read_meta(&btree, buf);
    TEST_CHK(meta2.size == meta.size);
    TEST_CHK(!strncmp((char*)buf, prefix, strlen(prefix)));

    TEST_RESULT("metadata test");
}

void seqtree_test()
{
    TEST_INIT();

    struct btree btree;
    btree_result r;
    struct btree_blk_ops *blk_ops;
    struct btree_kv_ops *kv_ops;
    int i;
    uint64_t a,b,c;
    
    dummy_init(sizeof(struct bnode) + 16*4, 100);
    blk_ops = dummy_get_ops();
    kv_ops = btree_kv_get_ku64_vu64();

    // maximum 4 kv-pairs per node
    btree_init(&btree, NULL, blk_ops, kv_ops, sizeof(struct bnode) + 16*4, 8, 8, BNODE_MASK_SEQTREE, NULL);

    for (i=0;i<17;++i){
        a = i*2; b = i*10;
        r = btree_insert(&btree, &a, &b);
        TEST_CHK(r != BTREE_RESULT_FAIL);
    }

    btree_print_node(&btree, print_btree);

    TEST_RESULT("split test");
}

int main(){
    getsetkv_test();
    basic_test();
    split_test();
    remove_test();
    flush_test();
    metadata_test();
    seqtree_test();

    return 0;
}
