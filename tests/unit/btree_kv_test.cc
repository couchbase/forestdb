#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "btree.h"
#include "btree_kv.h"
#include "btreeblock.h"
#include "test.h"
#include "common.h"
#include "list.h"
#include "memleak.h"
#include "option.h"

struct bnode* dummy_node(uint8_t ksize, uint8_t vsize, uint16_t level)
{
    struct bnode *node;
    node = (struct bnode*)malloc(sizeof(bnode) + FDB_BLOCKSIZE);
    memset(node, 0, sizeof(bnode));

    node->kvsize = ksize<<8 | vsize;
    node->level = level;
    node->data = (uint8_t *)node + sizeof(bnode);
    return node;
}


void kv_init_ops_test(int i)
{
    TEST_INIT();
    memleak_start();

    btree_kv_ops *kv_ops = NULL, *kv_ops_copy;
    kv_ops_copy = NULL;

    if(i == 0){
        kv_ops =  btree_kv_get_kb64_vb64(NULL);
        TEST_CHK(kv_ops!= NULL);

        // re-init with existing ops
        kv_ops_copy =  btree_kv_get_kb64_vb64(kv_ops);
        if (kv_ops && kv_ops_copy) {
            TEST_CHK(memcmp(kv_ops, kv_ops_copy, sizeof(btree_kv_ops)) == 0);
        }
    }
    if(i == 1){
        kv_ops =  btree_kv_get_kb32_vb64(NULL);
        TEST_CHK(kv_ops!= NULL);

        // re-init with existing ops
        kv_ops_copy =  btree_kv_get_kb32_vb64(kv_ops);
        if (kv_ops && kv_ops_copy) {
            TEST_CHK(memcmp(kv_ops, kv_ops_copy, sizeof(btree_kv_ops)) == 0);
        }
    }

    free(kv_ops);
    memleak_end();
    TEST_RESULT("kv init ops test");
}


void kv_init_var_test(btree_kv_ops *kv_ops)
{
    TEST_INIT();
    memleak_start();
    void *key, *value;
    btree *tree = alca(struct btree, 1);
    uint8_t ksize = 8;
    uint8_t vsize = 8;

    // unintialized key/value
    key = NULL;
    value = NULL;
    kv_ops->init_kv_var(tree, key, value);
    TEST_CHK(key == NULL);
    TEST_CHK(value == NULL);

    // initialized
    key = (void *)alca(uint8_t, ksize);
    value = (void *)alca(uint8_t, vsize);
    tree->ksize = ksize;
    tree->vsize = vsize;
    kv_ops->init_kv_var(tree, key, value);
    TEST_CHK( *(uint8_t *)key == 0 );
    TEST_CHK( *(uint8_t *)value == 0 );

    memleak_end();
    TEST_RESULT("kv init var test");
}


void kv_set_var_test(btree_kv_ops *kv_ops)
{
    TEST_INIT();
    memleak_start();

    bnoderef node;
    uint8_t ksize, vsize;
    int level;
    idx_t idx;
    char key[] = "key";
    uint64_t value = 10;

    ksize = strlen(key);
    vsize = sizeof(value);

    // set key/value in node
    idx = 0;
    level = 1;
    node = dummy_node(ksize, vsize, level);
    kv_ops->set_kv(node, idx, (void*)key, (void*)&value);

    // verify node->data
    TEST_CHK(!(memcmp(node->data, key, ksize)));
    TEST_CHK(!(memcmp((uint8_t*)node->data + ksize, &value, vsize)));

    free(node);

    memleak_end();
    TEST_RESULT("kv set var test");
}


/*
 * Test: kv_set_var_nentry_test
 *
 * verifies multiple key/value entries can be added to bnode
 *
 */
void kv_set_var_nentry_test(btree_kv_ops *kv_ops)
{
    TEST_INIT();
    memleak_start();

    bnoderef node;
    uint8_t v;
    idx_t idx;
    int n = 10;
    uint8_t ksize = 8;
    uint8_t vsize = sizeof(v);
    size_t offset = 0;
    char *key = alca(char, ksize);


    node = dummy_node(ksize, vsize, 1);
    node->nentry = n;

    v = 100;
    for (idx = 0; idx < n; idx ++){

        // set key/value
        sprintf(key, "key%d", idx);
        kv_ops->set_kv(node, idx, key, (void *)&v);

        // verify
        TEST_CHK(!memcmp((uint8_t *)node->data + offset, key, strlen(key)));
        offset += ksize;
        TEST_CHK(!memcmp((uint8_t *)node->data + offset, &v, vsize));
        offset += vsize;

        // update value
        v++;

    }

    free(node);
    memleak_end();
    TEST_RESULT("kv_set_var_nentry_test");
}


/*
 * Test: kv_set_var_nentry_test
 *
 * verifies multiple key/value entries can be added to bnode
 * then the same entries can be updated with new kvs
 *
 */
void kv_set_var_nentry_update_test(btree_kv_ops *kv_ops)
{
    TEST_INIT();
    memleak_start();

    bnoderef node;
    uint8_t v;
    int i, n = 10;
    uint8_t ksize = 8;
    uint8_t vsize = sizeof(v);
    size_t offset = 0;
    char **key = alca(char*, n);

    node = dummy_node(ksize, vsize, 1);
    node->nentry = n;

    v = 100;

    // first pass
    for (i = 0; i < n; i++) {
        key[i] = alca(char, ksize);
        sprintf(key[i], "key%d", i);
        kv_ops->set_kv(node, i, key[i], (void *)&v);

        TEST_CHK(!memcmp((uint8_t *)node->data + offset, key[i], strlen(key[i])));
        offset += ksize;
        TEST_CHK(!memcmp((uint8_t *)node->data + offset, &v, vsize));
        offset += vsize;

    }

    offset = 0;

    // second pass
    for (i = 0; i < n; i++) {

        kv_ops->set_kv(node, i, key[i], (void *)&v);
        TEST_CHK(!memcmp((uint8_t *)node->data + offset, key[i], strlen(key[i])));
        offset += ksize;
        TEST_CHK(!memcmp((uint8_t *)node->data + offset, &v, vsize));
        offset += vsize;
    }

    /* swap first/last entries */

    // copy first key to last
    kv_ops->set_kv(node, n-1, key[0], (void *)&v);
    strcpy(key[0], key[n-1]);

    // copy last key to first
    kv_ops->set_kv(node, 0, key[n-1], (void *)&v);
    strcpy(key[n-1], "key0");

    // verify
    offset = 0;
    for (i = 0; i < n; i++) {
        TEST_CHK(!memcmp((uint8_t *)node->data + offset, key[i], strlen(key[i])));
        offset += ksize;
        TEST_CHK(!memcmp((uint8_t *)node->data + offset, &v, vsize));
        offset += vsize;
    }

    free(node);
    memleak_end();
    TEST_RESULT("kv_set_var_nentry_update_test");
}

void kv_get_var_test(btree_kv_ops *kv_ops)
{
    TEST_INIT();
    memleak_start();

    bnoderef node;
    uint64_t v_in, v_out;
    idx_t idx;
    uint8_t ksize, vsize;

    ksize = 8;
    vsize = sizeof(v_in);
    node = dummy_node(ksize, vsize, 1);

    char *str = alca(char, ksize);
    char *k1 = alca(char, ksize);
    char *k2 = alca(char, ksize);
    memset(str, 0x0, ksize);
    strcpy(str, "keystr");

    idx = 0;
    v_in = 20;

    // set get key
    kv_ops->set_kv(node, idx, str, (void *)&v_in);
    kv_ops->get_kv(node, idx, k1, (void *)&v_out);
    TEST_CHK(!(strcmp(k1, str)));
    TEST_CHK(v_out == v_in);

    // get with value is NULL
    kv_ops->get_kv(node, idx, k2, NULL);
    TEST_CHK(!(strcmp(k2, str)));

    free(node);
    memleak_end();
    TEST_RESULT("kv_get_var_test");
}

void kv_get_var_nentry_test(btree_kv_ops *kv_ops)
{
    TEST_INIT();
    memleak_start();

    bnoderef node;
    uint8_t v, v_out;
    idx_t idx;
    int n = 10;
    uint8_t ksize = 8;
    uint8_t vsize = sizeof(v);
    char **key = alca(char*, n);
    char *k_out = alca(char, ksize);


    node = dummy_node(ksize, vsize, 1);
    node->nentry = n;

    v = 100;

    // set n keys
    for (idx = 0; idx < n; idx ++){
        key[idx] = alca(char, ksize);
        sprintf(key[idx], "key%d", idx);
        kv_ops->set_kv(node, idx, key[idx], (void *)&v);
        v++;
    }

    // get n keys
    v = 100;
    for (idx = 0; idx < n; idx ++){
        kv_ops->get_kv(node, idx, k_out, (void *)&v_out);
        TEST_CHK(!(strcmp(k_out, key[idx])));
        TEST_CHK(v_out == v);
        v++;
    }

    free(node);
    memleak_end();
    TEST_RESULT("kv_get_var_nentry_test");
}

/*
 * Test: kv_ins_var
 *
 * verifies insert op on empty bnode
 *
 */
void kv_ins_var(btree_kv_ops *kv_ops)
{
    TEST_INIT();
    memleak_start();

    bnoderef node;
    uint8_t ksize, vsize;
    idx_t idx;
    uint64_t value = 10;
    uint64_t v_out;

    ksize = 8;
    vsize = sizeof(value);
    node = dummy_node(ksize, vsize, 1);

    char *key = alca(char, ksize);
    char *k_out = alca(char, ksize);
    memset(key, 0x0, ksize);
    strcpy(key, "key");

    // insert key into to empty node
    idx = 0;
    kv_ops->ins_kv(node, idx, key, (void *)&value);

    // get and verify
    kv_ops->get_kv(node, idx, k_out, (void *)&v_out);
    TEST_CHK(!(strcmp(k_out, key)));
    TEST_CHK(v_out == value);

    free(node);
    memleak_end();
    TEST_RESULT("kv_ins_var");
}


/*
 * Test: kv_ins_var_nentry_test
 *
 * verifies inserting twice at index 0 causes entries to shift
 *
 */
void kv_ins_var_nentry_test(btree_kv_ops *kv_ops)
{
    TEST_INIT();
    memleak_start();

    bnoderef node;
    uint8_t ksize, vsize;
    uint64_t v = 100;
    int n = 10;
    char *k1;
    char *k2;

    ksize = 8;
    vsize = sizeof(v);
    node = dummy_node(ksize, vsize, 1);
    node->nentry = n;

    k1 = alca(char, ksize);
    k2 = alca(char, ksize);
    memset(k1, 0x0, ksize);
    memset(k2, 0x0, ksize);
    strcpy(k1, "key1");
    strcpy(k2, "key2");

    // insert twice at beginning of node
    kv_ops->ins_kv(node, 0, k1, (void *)&v);
    v++;
    kv_ops->ins_kv(node, 0, k2, (void *)&v);

    // verify k2 is at entry 0, and k2 at 1
    TEST_CHK(!memcmp(node->data, k2, ksize));
    TEST_CHK(!memcmp((uint8_t *)node->data + ksize + vsize, k1, ksize));

    free(node);
    memleak_end();

    TEST_RESULT("kv_ins_var_nentry_test");
}

/*
 * Test: kv_set_str_key_test
 *
 * verify set key string from src to empty dst and copy back to source
 *
 */
void kv_set_str_key_test(btree_kv_ops *kv_ops)
{
    TEST_INIT();
    memleak_start();

    btree *tree = alca(struct btree, 1);
    char src[] = "srckey";
    char *dst = alca(char, strlen(src));
    tree->ksize = strlen(src);
    kv_ops->set_key(tree, dst, src);
    TEST_CHK(!memcmp(dst, src, tree->ksize));

    memleak_end();
    TEST_RESULT("kv_set_str_key_test");
}

/*
 * Test: kv_set_str_value_test
 *
 * verify set kv value from src to empty dst and copy back to source
 *
 */
void kv_set_str_value_test(btree_kv_ops *kv_ops)
{
    TEST_INIT();
    memleak_start();

    uint64_t v_dst, v_src = 100;
    btree *tree = alca(struct btree, 1);
    tree->vsize = sizeof(v_dst);

    // set dst value
    kv_ops->set_value(tree,(void *)&v_src,(void *)&v_dst);

    // verify
    TEST_CHK(v_src == v_dst);

    // update dest and copy back to source
    v_dst = 200;
    kv_ops->set_value(tree,(void *)&v_dst,(void *)&v_src);
    TEST_CHK(v_src == v_dst);

    memleak_end();
    TEST_RESULT("kv_set_str_value_test");
}


/*
 * Test: kv_get_str_data_size_test
 *
 * verifies datasize of adding new kv values to a node
 *
 */

void kv_get_str_data_size_test(btree_kv_ops *kv_ops)
{
    TEST_INIT();
    memleak_start();


    bnoderef node;
    uint8_t v;
    uint8_t i, n = 10;
    uint8_t ksize = 8;
    uint8_t vsize = sizeof(v);
    char **key = alca(char*, n);
    int *value = alca(int, n);
    void *new_minkey;
    size_t size;


    node = dummy_node(ksize, vsize, 1);
    node->nentry = 0;

    new_minkey = NULL;

    for (i = 0; i < n; i++){
        key[i] = alca(char, ksize);
        sprintf(key[i], "key%d", i);
        value[i] = i;
    }

    // calculate datasize to extend empty node
    size = kv_ops->get_data_size(node, new_minkey, key, value, 2);
    TEST_CHK(size == (size_t)(2*(ksize + vsize)));

    // set kvs
    for (i = 0; i < n; i++){
        kv_ops->set_kv(node, i, key[i], (void *)&value[i]);
    }

    // cacluate datasize to extend node with n entries
    node->nentry = n;
    size = kv_ops->get_data_size(node, new_minkey, key, value, n);
    TEST_CHK(size == (size_t)(2*(n*(ksize+vsize))));

    free(node);
    memleak_end();
    TEST_RESULT("kv_get_str_data_size_test");
}

/*
 * Test: kv_get_str_kv_size
 *
 * verifies retrieving size of a kv entry
 *
 */

void kv_get_str_kv_size_test(btree_kv_ops *kv_ops)
{
    TEST_INIT();
    memleak_start();

    btree *tree;
    int v;
    size_t size;
    char str[] = "teststring";

    tree = alca(struct btree, 1);
    tree->ksize = strlen(str);
    tree->vsize = sizeof(v);
    v = 1;

    // get/verify size of kv string
    size = kv_ops->get_kv_size(tree, str, (void *)&v);
    TEST_CHK(size == (strlen(str) + sizeof(v)));

    // verify with NULL key
    size = kv_ops->get_kv_size(tree, NULL, (void *)&v);
    TEST_CHK(size == (tree->vsize));

    // verify with NULL value
    size = kv_ops->get_kv_size(tree,&str, NULL);
    TEST_CHK(size == (strlen(str)));

    // NULL key/value
    size = kv_ops->get_kv_size(tree, NULL, NULL);
    TEST_CHK(size == 0);

    memleak_end();
    TEST_RESULT("kv_get_str_kv_size_test");
}

/*
 * Test: kv_copy_var_test
 *
 * verify single entry from source bnode can be put into destination
 *
 */
void kv_copy_var_test(btree_kv_ops *kv_ops)
{

    TEST_INIT();
    memleak_start();

    bnoderef node_src, node_dst;
    idx_t src_idx, dst_idx, len;
    uint8_t ksize, vsize;
    uint64_t v;
    char key[] = "key";

    ksize = strlen(key);
    vsize = sizeof(v);
    v = 64;
    node_dst = dummy_node(ksize, vsize, 1);
    node_src = dummy_node(ksize, vsize, 1);

    dst_idx = 0;
    src_idx = 0;
    len = 1;

    // set kv into src node and copy into dest
    kv_ops->set_kv(node_src, src_idx, key, &v);
    kv_ops->copy_kv(node_dst, node_src, dst_idx, src_idx, len);

    // verify
    TEST_CHK(!(memcmp(node_dst->data, key, ksize)));
    TEST_CHK(!(memcmp((uint8_t*)node_dst->data + ksize, &v, vsize)));

    free(node_src); free(node_dst);
    memleak_end();
    TEST_RESULT("kv_copy_var_test");
}

/*
 * Test: kv_copy_var_nentry_test
 *
 * verify n entries from source bnode can be copied into dest at various offsets
 *   -1, copy n/2-entries into empty destination
 *   -2, append n-entries into occupied destination
 *   -3, prepend n-entries into occupied destination
 *
 */
void kv_copy_var_nentry_test(btree_kv_ops *kv_ops)
{
    TEST_INIT();
    memleak_start();

    bnoderef node, node_dst;
    uint8_t v, v_out;
    idx_t idx, src_idx, dst_idx, len;
    int n=10;
    uint8_t ksize = 8;
    uint8_t vsize = sizeof(v);
    char **key = alca(char*, n);
    char *k_out = alca(char, ksize);

    node = dummy_node(ksize, vsize, 1);
    node->nentry = n;

    v = 100;
    // set n items into source node
    for (idx = 0; idx < n; idx++){
        key[idx] = alca(char, ksize);
        sprintf(key[idx], "key%d", idx);
        kv_ops->set_kv(node, idx, key[idx], (void *)&v);
        v++;
    }

    // copy n/2 entries into dest node
    src_idx = n/2;
    dst_idx = 0;
    len = src_idx;
    node_dst = dummy_node(ksize, vsize, 1);
    kv_ops->copy_kv(node_dst, node, dst_idx, src_idx, len);

    // verify
    v = 100 + n/2;
    for (idx = 0; idx < n/2; idx++){

        kv_ops->get_kv(node_dst, idx, k_out, (void *)&v_out);
        TEST_CHK(!(strcmp(k_out, key[idx + n/2])));
        TEST_CHK(v_out == v);
        v++;

    }

    // append n entries into dst node
    dst_idx = src_idx;
    src_idx = 0;
    kv_ops->copy_kv(node_dst, node, dst_idx, src_idx, n);

    // verify
    v = 100;
    for (idx = n/2; idx < n+n/2; idx++){

        kv_ops->get_kv(node_dst, idx, k_out, (void *)&v_out);
        TEST_CHK(!(strcmp(k_out, key[idx - n/2])));
        TEST_CHK(v_out == v);
        v++;
    }

    // prepend n entries into dst node
    dst_idx = 0;
    src_idx = 0;
    kv_ops->copy_kv(node_dst, node, dst_idx, src_idx, n);

    // verify
    v = 100;
    for (idx = src_idx; idx < n; idx++){

        kv_ops->get_kv(node_dst, idx, k_out, (void *)&v_out);
        TEST_CHK(!(strcmp(k_out, key[idx])));
        TEST_CHK(v_out == v);
        v++;
    }

    free(node); free(node_dst);

    memleak_end();
    TEST_RESULT("kv_copy_var_nentry_test");
}


/*
 * Test: kv_get_nth_idx_test
 *
 * verifies calculating nth index of bnode entry
 *
 */
void kv_get_nth_idx_test(btree_kv_ops *kv_ops)
{

    TEST_INIT();
    memleak_start();

    bnoderef node;
    idx_t num, den, location;

    node = dummy_node(0, 0, 0);
    node->nentry = 4;
    num = 3;
    den = 4;

    // verify 3/4th offset
    kv_ops->get_nth_idx(node, num, den, &location);
    TEST_CHK(location == 3);

    // verify 1/4 offset
    num = 1;
    den = 4;
    kv_ops->get_nth_idx(node, num, den, &location);
    TEST_CHK(location == 1);

     // verify with num == 0
    num = 0;
    den = 3;
    kv_ops->get_nth_idx(node, num, den, &location);
    TEST_CHK(location == 0);

    free(node);
    memleak_end();
    TEST_RESULT("kv_get_nth_idx_test");
}

/*
 * Test: kv_get_nth_splitter_test
 *
 * verifies splitter entry can be retrieved
 *
 */
void kv_get_nth_splitter_test(btree_kv_ops *kv_ops)
{
    TEST_INIT();
    memleak_start();

    bnoderef node;
    uint8_t v;
    idx_t idx;
    int n = 10;
    uint8_t ksize = 8;
    uint8_t vsize = sizeof(v);
    char *key = alca(char, ksize);
    char *split = alca(char, ksize);


    node = dummy_node(ksize, vsize, 1);
    node->nentry = n;

    v = 100;

    // set n keys
    for (idx = 0; idx < n; idx ++){
        sprintf(key, "key%d", idx);
        kv_ops->set_kv(node, idx, key, (void *)&v);
        v++;
    }

    // set *key to nth_splitter
    kv_ops->get_nth_splitter(NULL, node, split);

    // verify key[0] is set as splitter
    TEST_CHK(!(strcmp(split, "key0")));

    free(node);
    memleak_end();
    TEST_RESULT("kv_get_nth_splitter_test");
}

/*
 * Test: kv_cmp_key_str_test
 *
 * test comparison of keys for the following scenarios
 *  - equal keylens w/out equality
 *  - null key_ptrs
 *
 */
void kv_cmp_key_str_test(btree_kv_ops *kv_ops, int i)
{

    TEST_INIT();
    memleak_start();

    idx_t idx;
    int cmp;
    int n = 4;
    char **keys = alca(char*, n);
    void *tmp;
    btree_kv_ops *kv_ops2 = NULL;

    if (i == 0){
        kv_ops2 = btree_kv_get_kb64_vb64(NULL);
    }
    if (i == 1){
        kv_ops2 =  btree_kv_get_kb32_vb64(NULL);

    }

    tmp = NULL;

    for (idx = 0; idx < n; idx ++){
        keys[idx] = alca(char, 8);
        sprintf(keys[idx], "key%d", idx);
    }

    // compare strings equal length equal values
    cmp = kv_ops->cmp(keys[0], keys[0], NULL);
    TEST_CHK( cmp == 0 );
    cmp = kv_ops2->cmp(keys[0], keys[0], NULL);
    TEST_CHK( cmp == 0 );

    // compare strings equal length diff values
    cmp = kv_ops->cmp(keys[0], keys[1], NULL);
    TEST_CHK( cmp != 0 );
    cmp = kv_ops2->cmp(keys[0], keys[1], NULL);
    TEST_CHK( cmp != 0 );

    // key1 is NULL
    cmp = kv_ops->cmp(&tmp, keys[0], NULL);
    TEST_CHK( cmp != 0 );
    cmp = kv_ops2->cmp(&tmp, keys[0], NULL);
    TEST_CHK( cmp != 0 );

    // key2 is NULL
    cmp = kv_ops->cmp(&keys[0], &tmp, NULL);
    TEST_CHK( cmp != 0 );
    cmp = kv_ops2->cmp(&keys[0], &tmp, NULL);
    TEST_CHK( cmp != 0 );

    // key1 and key2 are NULL
    cmp = kv_ops->cmp(&tmp, &tmp, NULL);
    TEST_CHK( cmp == 0 );
    cmp = kv_ops2->cmp(&tmp, &tmp, NULL);
    TEST_CHK( cmp == 0 );

    free(kv_ops2);
    memleak_end();
    TEST_RESULT("kv_cmp_key_str_test");
}

/*
 * Test: kv_bid_to_value_to_bid_test
 *
 * verifies conversion of values to bid types and vice-versa
 */
void kv_bid_to_value_to_bid_test(btree_kv_ops *kv_ops)
{
    TEST_INIT();
    memleak_start();

    void *value;
    bid_t bid1, bid2;


    // bid to str value
    bid1 = 10;
    value = kv_ops->bid2value(&bid1);
    TEST_CHK( *(bid_t *)value == bid1 );

    // value to bid
    bid2 = kv_ops->value2bid(value);
    TEST_CHK( bid2 == bid1 );

    memleak_end();
    TEST_RESULT("kv_bid_to_value_to_bid_test");
}


int main()
{
    int i;

    #ifdef _MEMPOOL
        mempool_init();
    #endif

    btree_kv_ops ** ops = alca(btree_kv_ops*, 2);
    ops[0] = btree_kv_get_ku64_vu64();
    ops[1] = btree_kv_get_ku32_vu64();

    for (i=0; i<2; i++){

        kv_init_ops_test(i);
        kv_init_var_test(ops[i]);

        kv_set_var_test(ops[i]);
        kv_set_var_nentry_test(ops[i]);
        kv_set_var_nentry_update_test(ops[i]);

        kv_get_var_test(ops[i]);
        kv_get_var_nentry_test(ops[i]);

        kv_ins_var(ops[i]);
        kv_ins_var_nentry_test(ops[i]);

        kv_set_str_key_test(ops[i]);
        kv_set_str_value_test(ops[i]);

        kv_get_str_data_size_test(ops[i]);
        kv_get_str_kv_size_test(ops[i]);

        kv_copy_var_test(ops[i]);
        kv_copy_var_nentry_test(ops[i]);

        kv_get_nth_idx_test(ops[i]);
        kv_get_nth_splitter_test(ops[i]);

        kv_cmp_key_str_test(ops[i], i);
        kv_bid_to_value_to_bid_test(ops[i]);
    }

    return 0;
}
