#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "btree.h"
#include "btree_kv.h"
#include "btree_str_kv.h"
#include "btreeblock.h"
#include "filemgr_ops.h"
#include "test.h"
#include "common.h"
#include "list.h"
#include "memleak.h"
#include "option.h"

typedef uint16_t key_len_t;


void freevars(void **vv, size_t n)
{
    for(size_t i = 0; i < n; i++){
        void *p = vv[i];
        free(p);
        p = NULL;
    }
}

void kv_set_key_test()
{

    TEST_INIT();
    memleak_start();

    char str[] = "teststring";
    uint8_t *key = alca(uint8_t, sizeof(void *));
    size_t str_len = sizeof(str);

    // set key ptr
    btree_str_kv_set_key(key, str, str_len);
    void *kv_addr;
    memcpy(&kv_addr, key, sizeof(void *));

    // check key len
    key_len_t kv_len;
    memcpy(&kv_len, (key_len_t *)kv_addr, sizeof(key_len_t));
    key_len_t kv_len_dec = _endian_decode(kv_len);
    TEST_CHK(kv_len_dec == str_len);

    // check key size
    char *kv_str = alca(char, str_len);
    TEST_CHK(kv_str != NULL);
    memcpy(kv_str, ((char *)kv_addr) + sizeof(key_len_t), str_len);
    int cmp = strcmp(kv_str, str);
    TEST_CHK(cmp == 0);
    free(kv_addr);

    memleak_end();
    TEST_RESULT("kv set key test");
}


void construct_key_ptr(const char *str, const key_len_t len, void *key_ptr){
    void *key;
    key_len_t _str_len;
    key = (void *)malloc(sizeof(key_len_t) + len);
    _str_len = _endian_encode(len);
    memcpy(key, &_str_len, sizeof(key_len_t));
    memcpy((uint8_t*)key + sizeof(key_len_t), str, len);
    memcpy(key_ptr, &key, sizeof(void *));
}

void kv_get_key_test()
{

    TEST_INIT();
    memleak_start();

    // create kv ptr
    void *key;
    char str[] = "teststring";
    key_len_t str_len = sizeof(str);
    construct_key_ptr(str, str_len, &key);

    // get_key unpacks kv formated key
    char *strbuf = alca(char, str_len);
    size_t len;
    btree_str_kv_get_key(&key, strbuf, &len);

    // check results
    int cmp = strcmp(strbuf, str);
    TEST_CHK(cmp == 0);
    TEST_CHK(len ==str_len);
    free(key);

    memleak_end();
    TEST_RESULT("kv get key test");
}

void kv_get_key_isnull_test()
{

    TEST_INIT();
    memleak_start();

    void *key = NULL;
    char *strbuf = NULL;
    size_t len;
    btree_str_kv_get_key(&key, strbuf, &len);

    // check results
    TEST_CHK(len == 0);
    free(key);

    memleak_end();
    TEST_RESULT("kv get key is null test");
}

void kv_free_test()
{

    TEST_INIT();
    memleak_start();

    void *key;
    char str[] = "teststring";
    key_len_t str_len = sizeof(str);
    construct_key_ptr(str, str_len, &key);

    TEST_CHK(key != NULL);
    btree_str_kv_free_key(&key);
    TEST_CHK(key == NULL);

    memleak_end();
    TEST_RESULT("kv free test");
}

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


void kv_init_ops_test()
{
    TEST_INIT();
    memleak_start();

    // init with null
    btree_kv_ops *kv_ops = btree_str_kv_get_kb64_vb64(NULL);
    TEST_CHK(kv_ops != NULL);

    // re-init with existing ops
    btree_kv_ops *kv_ops_copy =  btree_str_kv_get_kb64_vb64(kv_ops);
    if (kv_ops && kv_ops_copy) {
        TEST_CHK(memcmp(kv_ops, kv_ops_copy, sizeof(btree_kv_ops)) == 0);
    }

    free(kv_ops);
    memleak_end();
    TEST_RESULT("kv init ops test");
}


void kv_init_var_test()
{
    TEST_INIT();
    memleak_start();

    void *key, *value;
    btree_kv_ops *kv_ops = btree_str_kv_get_kb64_vb64(NULL);
    btree *tree = alca(struct btree, 1);
    uint8_t ksize = sizeof(void *);
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
    tree->vsize = vsize;
    kv_ops->init_kv_var(tree, key, value);
    TEST_CHK( *(uint8_t *)key == 0 );
    TEST_CHK( *(uint8_t *)value == 0 );

    free(kv_ops);
    memleak_end();
    TEST_RESULT("kv init var test");
}


void kv_set_var_test()
{
    TEST_INIT();
    memleak_start();

    bnoderef node;
    btree_kv_ops *kv_ops;
    void *key, *value;
    uint8_t ksize, vsize;
    int level;
    uint64_t v;
    int cmp;
    idx_t idx;
    char str[] = "teststring";
    key_len_t str_len = sizeof(str);

    vsize = sizeof(v);
    v = 10;

    construct_key_ptr(str, str_len, &key);
    value = alca(uint8_t, vsize);
    memset(value, 0, vsize);
    memcpy(value, &v, vsize);

    // init ops
    kv_ops = alca(btree_kv_ops, 1);
    btree_str_kv_get_kb64_vb64(kv_ops);

    // set key/value in node
    idx = 0;
    level = 1;
    ksize = str_len + sizeof(key_len_t);
    node = dummy_node(ksize, vsize, level);
    kv_ops->set_kv(node, idx, &key, value);

    // verify node->data
    cmp = strcmp((char *)((uint8_t *)node->data + sizeof(key_len_t)), str);
    TEST_CHK(cmp == 0);
    cmp = memcmp((uint8_t *)node->data + ksize, value, vsize);
    TEST_CHK(cmp == 0);

    void *vars[] = {node, key};
    freevars(vars, sizeof(vars)/sizeof(void *));

    memleak_end();
    TEST_RESULT("kv set var test");
}


/*
 * Test: kv_set_var_nentry_test
 *
 * verifies multiple key/value entries can be added to bnode
 *
 */
void kv_set_var_nentry_test()
{
    TEST_INIT();
    memleak_start();

    bnoderef node;
    btree_kv_ops *kv_ops;
    uint8_t ksize, vsize;
    uint8_t v;
    idx_t idx;
    int cmp, i;
    const char *keys[] = {"string",
                          "longstring",
                          "longerstring",
                          "",
                          "123231234242423428492342",
                          "string with space"};

    int n =  sizeof(keys)/sizeof(void *);
    void **key_ptrs = alca(void *, n);

    for (i = 0; i < n; i++) {
        construct_key_ptr(keys[i], strlen(keys[i]) + 1, &key_ptrs[i]);
    }

    ksize = strlen(keys[0]) + 1 + sizeof(key_len_t);
    vsize = sizeof(v);
    node = dummy_node(ksize, vsize, 1);
    node->nentry = n;

    v = 100;
    kv_ops = alca(btree_kv_ops, 1);
    btree_str_kv_get_kb64_vb64(kv_ops);
    size_t offset_idx = 0;

    for (idx = 0; idx < n; idx ++){
        // verify node->data at each offset
        kv_ops->set_kv(node, idx, &key_ptrs[idx], (void *)&v);

        // check key
        offset_idx += sizeof(key_len_t);
        char *node_str = (char *)((uint8_t *)node->data + offset_idx);
        cmp = strcmp(node_str, keys[idx]);
        TEST_CHK(cmp == 0);

        // check value
        offset_idx += strlen(keys[idx]) + 1;
        cmp = memcmp((uint8_t *)node->data + offset_idx, &v, vsize);
        TEST_CHK(cmp == 0);

        // move offset to next entry
        offset_idx += vsize;

        // update value
        v++;

    }

    free(node);
    freevars(key_ptrs, n);
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
void kv_set_var_nentry_update_test()
{
    TEST_INIT();
    memleak_start();

    bnoderef node;
    btree_kv_ops *kv_ops;
    uint8_t ksize, vsize;
    uint8_t v;
    int cmp, i;

    const char *keys[] = {"string",
                          "longstring",
                          "longerstring",
                          "",
                          "123231234242423428492342",
                          "string WITH space"};

    int n =  sizeof(keys)/sizeof(void *);
    void **key_ptrs = alca(void *, n);

    ksize = strlen(keys[0]) + 1 + sizeof(key_len_t);
    vsize = sizeof(v);
    node = dummy_node(ksize, vsize, 1);
    node->nentry = n;

    v = 100;
    kv_ops = alca(btree_kv_ops, 1);
    btree_str_kv_get_kb64_vb64(kv_ops);
    size_t offset_idx = 0;

    // first pass
    for (i = 0; i < n; i++) {
        construct_key_ptr(keys[i], strlen(keys[i]) + 1, &key_ptrs[i]);
        kv_ops->set_kv(node, i, &key_ptrs[i], (void *)&v);

        // basic node->data verification
        offset_idx += sizeof(key_len_t);
        char *node_str = (char *)((uint8_t *)node->data + offset_idx);
        cmp = strcmp(node_str, keys[i]);
        TEST_CHK(cmp == 0);
        offset_idx += vsize + strlen(keys[i]) + 1;
    }

    freevars(key_ptrs, n);
    key_ptrs = alca(void *, n);
    offset_idx = 0;

    // second pass
    for (i = 0; i < n; i++) {
        construct_key_ptr(keys[i], strlen(keys[i]) + 1, &key_ptrs[i]);
        kv_ops->set_kv(node, i, &key_ptrs[i], (void *)&v);

        // basic node->data verification
        offset_idx += sizeof(key_len_t);
        char *node_str = (char *)((uint8_t *)node->data + offset_idx);
        cmp = strcmp(node_str, keys[i]);
        TEST_CHK(cmp == 0);
        offset_idx += vsize + strlen(keys[i]) + 1;
    }

    /* swap entries */

    // copy first key to middle
    kv_ops->set_kv(node, n/2, &key_ptrs[0], (void *)&v);
    keys[n/2] = keys[0];

    // copy last key to first
    kv_ops->set_kv(node, 0, &key_ptrs[n-1], (void *)&v);
    keys[0] = keys[n - 1];

    // copy middle key to last
    kv_ops->set_kv(node, n - 1, &key_ptrs[0], (void *)&v);
    keys[n - 1] = keys[n/2];

    // verify
    offset_idx = 0;
    for (i = 0; i < n; i++) {
        offset_idx += sizeof(key_len_t);
        char *node_str = (char *)((uint8_t *)node->data + offset_idx);
        cmp = strcmp(node_str, keys[i]);
        TEST_CHK(cmp == 0);
        offset_idx += vsize + strlen(keys[i]) + 1;
    }

    free(node);
    freevars(key_ptrs, n);
    memleak_end();
    TEST_RESULT("kv_set_var_nentry_update_test");
}

void kv_get_var_test()
{
    TEST_INIT();
    memleak_start();

    bnoderef node;
    btree_kv_ops *kv_ops;
    void *k_in, *k_out;
    uint64_t v_in, v_out;
    idx_t idx;
    uint8_t ksize, vsize;
    char *key_str;
    int cmp;
    char str[] = "teststring";
    key_len_t str_len = sizeof(str);

    construct_key_ptr(str, str_len, &k_in);


    ksize = str_len + sizeof(key_len_t);
    vsize = sizeof(v_in);
    node = dummy_node(ksize, vsize, 1);

    idx = 0;
    v_in = 20;
    k_out = NULL;

    // set get key
    kv_ops = btree_str_kv_get_kb64_vb64(NULL);
    kv_ops->set_kv(node, idx, &k_in, (void *)&v_in);
    kv_ops->get_kv(node, idx, &k_out, (void *)&v_out);
    key_str = (char *)((uint8_t *)k_out + sizeof(key_len_t));
    cmp = strcmp(key_str, str);
    TEST_CHK(cmp == 0);
    cmp = memcmp(&v_out, &v_in, vsize);
    TEST_CHK(cmp == 0);

    // get with old key
    kv_ops->get_kv(node, idx, &k_out, (void *)&v_out);
    key_str = (char *)((uint8_t *)k_out + sizeof(key_len_t));
    cmp = strcmp(key_str, str);
    TEST_CHK(cmp == 0);
    cmp = memcmp(&v_out, &v_in, vsize);
    TEST_CHK(cmp == 0);

    // get with value is NULL
    kv_ops->get_kv(node, idx, &k_out, NULL);
    key_str = (char *)((uint8_t *)k_out + sizeof(key_len_t));
    cmp = strcmp(key_str, str);
    TEST_CHK(cmp == 0);
    cmp = memcmp(&v_out, &v_in, vsize);
    TEST_CHK(cmp == 0);


    free(node);
    void *vars[] = {kv_ops, k_in, k_out};
    freevars(vars, sizeof(vars)/sizeof(void *));
    memleak_end();
    TEST_RESULT("kv_get_var_test");
}

void kv_get_var_nentry_test()
{
    TEST_INIT();
    memleak_start();

    bnoderef node;
    btree_kv_ops *kv_ops;
    uint8_t ksize, vsize;
    uint8_t v, v_out;
    idx_t idx;
    int cmp, i;
    void *k_out = NULL;

    const char *keys[] = {"string",
                          "longstring",
                          "longerstring",
                          "",
                          "123231234242423428492342",
                          "string with space"};

    int n =  sizeof(keys)/sizeof(void *);
    void **key_ptrs = alca(void *, n);

    for (i = 0; i < n; i++) {
        construct_key_ptr(keys[i], strlen(keys[i]) + 1, &key_ptrs[i]);
    }

    ksize = strlen(keys[0]) + 1 + sizeof(key_len_t);
    vsize = sizeof(v);
    node = dummy_node(ksize, vsize, 1);
    node->nentry = n;

    v = 100;
    kv_ops = alca(btree_kv_ops, 1);
    btree_str_kv_get_kb64_vb64(kv_ops);

    // set n keys
    for (idx = 0; idx < n; idx ++){
        kv_ops->set_kv(node, idx, &key_ptrs[idx], (void *)&v);
        v++;
    }

    // get n keys
    v = 100;
    for (idx = 0; idx < n; idx ++){
        kv_ops->get_kv(node, idx, &k_out, (void *)&v_out);
        char *node_str = (char *)((uint8_t *)k_out + sizeof(key_len_t));
        cmp = strcmp(node_str, keys[idx]);
        TEST_CHK(cmp == 0);
        cmp = memcmp(&v_out, &v, vsize);
        TEST_CHK(cmp == 0);
        v++;
    }


    void *vars[] = {(void *)node, k_out};
    freevars(vars, sizeof(vars)/sizeof(void *));
    freevars(key_ptrs, n);
    memleak_end();
    TEST_RESULT("kv_get_var_nentry_test");
}

/*
 * Test: kv_ins_var
 *
 * verifies insert op on empty bnode
 *
 */
void kv_ins_var()
{
    TEST_INIT();
    memleak_start();

    bnoderef node;
    btree_kv_ops *kv_ops;
    void *k_in, *k_out;
    uint64_t v_in, v_out;
    idx_t idx;
    uint8_t ksize, vsize;
    char *key_str;
    int cmp;
    char str[] = "teststring";
    key_len_t str_len = sizeof(str);

    construct_key_ptr(str, str_len, &k_in);


    ksize = str_len + sizeof(key_len_t);
    vsize = sizeof(v_in);
    node = dummy_node(ksize, vsize, 1);

    idx = 0;
    v_in = 20;
    k_out= NULL;

    // insert key into to empty node
    kv_ops = btree_str_kv_get_kb64_vb64(NULL);
    kv_ops->ins_kv(node, idx, &k_in, (void *)&v_in);

    // get and verify
    kv_ops->get_kv(node, idx, &k_out, (void *)&v_out);
    key_str = (char *)((uint8_t *)k_out + sizeof(key_len_t));
    cmp = strcmp(key_str, str);
    TEST_CHK(cmp == 0);
    cmp = memcmp(&v_out, &v_in, vsize);
    TEST_CHK(cmp == 0);

    free(node); free(kv_ops); free(k_in); free(k_out);
    memleak_end();
    TEST_RESULT("kv_ins_var");
}


/*
 * Test: kv_ins_var_nentry_test
 *
 * verifies inserting twice at index 0 causes entries to shift
 *
 */
void kv_ins_var_nentry_test()
{
    TEST_INIT();
    memleak_start();

    bnoderef node;
    btree_kv_ops *kv_ops;
    uint8_t ksize, vsize;
    uint8_t v;
    idx_t idx;
    int cmp, i, offset;
    char *node_str;

    const char *keys[] = {"string",
                          "longstring"};

    int n =  sizeof(keys)/sizeof(void *);
    void **key_ptrs = alca(void *, n);

    for (i = 0; i < n; i++) {
        construct_key_ptr(keys[i], strlen(keys[i]) + 1, &key_ptrs[i]);
    }

    ksize = strlen(keys[0]) + 1 + sizeof(key_len_t);
    vsize = sizeof(v);
    node = dummy_node(ksize, vsize, 1);
    node->nentry = n;

    idx = 0;
    v = 100;
    kv_ops = alca(btree_kv_ops, 1);
    btree_str_kv_get_kb64_vb64(kv_ops);

    // insert twice at beginning of node
    kv_ops->ins_kv(node, 0, &key_ptrs[idx], (void *)&v);
    idx++;
    v++;
    kv_ops->ins_kv(node, 0, &key_ptrs[idx], (void *)&(v));

    // verify k1 is at entry 0
    offset = sizeof(key_len_t);
    node_str = (char *)((uint8_t *)node->data + offset);
    cmp = strcmp(node_str, keys[1]);
    TEST_CHK(cmp == 0);
    offset += strlen(keys[1]) + 1;
    cmp = memcmp((uint8_t *)node->data + offset, &v, vsize);
    TEST_CHK(cmp == 0);

    v--;
    // verify k0 is at entry 1
    offset += vsize + sizeof(key_len_t);
    node_str = (char *)((uint8_t *)node->data + offset);
    cmp = strcmp(node_str, keys[0]);
    TEST_CHK(cmp == 0);
    offset += strlen(keys[0]) + 1;
    cmp = memcmp((uint8_t *)node->data + offset, &v, vsize);
    TEST_CHK(cmp == 0);

    free(node);
    freevars(key_ptrs, n);
    memleak_end();

    TEST_RESULT("kv_ins_var_nentry_test");
}

/*
 * Test: kv_set_str_key_test
 *
 * verify set key string from src to empty dst and copy back to source
 *
 */
void kv_set_str_key_test()
{
    TEST_INIT();
    memleak_start();

    void *src, *dst = NULL;
    char str[] = "teststring";
    char str2[] = "updated teststring";
    int cmp;
    key_len_t str_len = sizeof(str);
    btree_kv_ops *kv_ops = btree_str_kv_get_kb64_vb64(NULL);
    construct_key_ptr(str, str_len, &src);

    // set src
    kv_ops->set_key(NULL, &dst, &src);

    // verify dst
    cmp = strcmp((char *)dst + sizeof(key_len_t), str);
    TEST_CHK(cmp == 0);
    free(dst);

    // update dst
    str_len = sizeof(str2);
    construct_key_ptr(str2, str_len, &dst);

    // write back to src and verify
    kv_ops->set_key(NULL, &src, &dst);
    cmp = strcmp((char *)src + sizeof(key_len_t), str2);
    TEST_CHK(cmp == 0);

    free(kv_ops);
    free(src);
    free(dst);
    memleak_end();
    TEST_RESULT("kv_set_str_key_test");
}

/*
 * Test: kv_set_str_value_test
 *
 * verify set kv value from src to empty dst and copy back to source
 *
 */
void kv_set_str_value_test()
{
    TEST_INIT();
    memleak_start();

    uint64_t v_dst, v_src = 100;
    btree *tree = alca(struct btree, 1);
    tree->vsize = sizeof(v_dst);
    btree_kv_ops *kv_ops = btree_str_kv_get_kb64_vb64(NULL);

    // set dst value
    kv_ops->set_value(tree,(void *)&v_src,(void *)&v_dst);

    // verify
    TEST_CHK(v_src == v_dst);

    // update dest and copy back to source
    v_dst = 200;
    kv_ops->set_value(tree,(void *)&v_dst,(void *)&v_src);
    TEST_CHK(v_src == v_dst);

    free(kv_ops);
    memleak_end();
    TEST_RESULT("kv_set_str_value_test");
}


/*
 * Test: kv_get_str_data_size_test
 *
 * verifies datasize of adding new kv values to a node
 *
 */

void kv_get_str_data_size_test()
{
    TEST_INIT();
    memleak_start();

    bnoderef node;
    btree_kv_ops *kv_ops;
    uint8_t ksize, vsize, ksize_total = 0;
    void *new_minkey;
    size_t size, old_size;
    const char *keys[] = {"string",
                           "longstring"};
    int value_arr[] = {1, 10};
    int n =  sizeof(keys)/sizeof(void *);
    void **key_ptrs = alca(void *, n);


    vsize = sizeof(int);
    ksize = strlen(keys[0]) + 1 + sizeof(key_len_t);
    node = dummy_node(ksize, vsize, 1);

    new_minkey = NULL;
    kv_ops = alca(btree_kv_ops, 1);
    btree_str_kv_get_kb64_vb64(kv_ops);

    // construct key_ptrs
    for (int i = 0; i < n; i++){
        construct_key_ptr(keys[i], strlen(keys[i]) + 1, &key_ptrs[i]);
        ksize_total += strlen(keys[i]) + 1 + sizeof(key_len_t);
    }

    // calculate datasize to extend empty node
    size = kv_ops->get_data_size(node, new_minkey, key_ptrs, value_arr, 2);
    TEST_CHK(size == (size_t)(ksize_total + 2*vsize));

    // set kvs
    for (int i = 0; i < n; i++){
        kv_ops->set_kv(node, i, &key_ptrs[i], (void *)&value_arr[i]);
    }

    // cacluate datasize to extend node with n entries
    old_size = size;
    node->nentry = n;
    size = kv_ops->get_data_size(node, new_minkey, key_ptrs, value_arr, 2);
    TEST_CHK(size == (old_size + ksize_total + 2*vsize));

    // verify with new_min_key
    memcpy(&new_minkey, &key_ptrs[1], sizeof(void *));
    size = kv_ops->get_data_size(node, &new_minkey, key_ptrs, value_arr, 2);
    old_size = old_size + (strlen(keys[1]) - strlen(keys[0]));
    TEST_CHK(size == (old_size + ksize_total + 2*vsize));

    free(node);
    freevars(key_ptrs, n);
    memleak_end();
    TEST_RESULT("kv_get_str_data_size_test");
}

/*
 * Test: kv_get_str_kv_size
 *
 * verifies retrieving size of a kv entry
 *
 */

void kv_get_str_kv_size_test()
{
    TEST_INIT();
    memleak_start();

    btree_kv_ops *kv_ops;
    btree *tree;
    void *key;
    int v;
    size_t size;
    char str[] = "teststring";

    kv_ops = alca(btree_kv_ops, 1);
    btree_str_kv_get_kb64_vb64(kv_ops);
    tree = alca(struct btree, 1);
    tree->vsize = sizeof(v);
    v = 1;
    construct_key_ptr(str, sizeof(str), &key);

    // get/verify size of kv string
    size = kv_ops->get_kv_size(tree, &key, (void *)&v);
    TEST_CHK(size == (sizeof(str) + sizeof(key_len_t) + tree->vsize));

    // verify with NULL key
    size = kv_ops->get_kv_size(tree, NULL, (void *)&v);
    TEST_CHK(size == (tree->vsize));

    // verify with NULL value
    size = kv_ops->get_kv_size(tree, &key, NULL);
    TEST_CHK(size == (sizeof(str) + sizeof(key_len_t)));

    // NULL key/value
    size = kv_ops->get_kv_size(tree, NULL, NULL);
    TEST_CHK(size == 0);

    free(key);
    memleak_end();
    TEST_RESULT("kv_get_str_kv_size_test");
}

/*
 * Test: kv_copy_var_test
 *
 * verify single entry from source bnode can be put into destination
 *
 */
void kv_copy_var_test()
{

    TEST_INIT();
    memleak_start();

    bnoderef node_src, node_dst;
    btree_kv_ops *kv_ops;
    idx_t src_idx, dst_idx, len;
    uint8_t str_len, ksize, vsize;
    uint16_t level;
    uint64_t v, cmp;
    char *key;
    char str[] = "teststring";

    kv_ops = alca(btree_kv_ops, 1);
    btree_str_kv_get_kb64_vb64(kv_ops);

    v = 64;
    str_len = strlen(str) + 1;
    ksize = str_len + sizeof(key_len_t);
    vsize = sizeof(v);
    level = 1;
    node_dst = dummy_node(ksize, vsize, level);
    node_src = dummy_node(ksize, vsize, level);
    dst_idx = 0;
    src_idx = 0;
    len = 1;
    construct_key_ptr(str, str_len, &key);

    // set kv into src node and copy into dest
    kv_ops->set_kv(node_src, src_idx, &key, &v);
    kv_ops->copy_kv(node_dst, node_src, dst_idx, src_idx, len);

    // verify
    cmp = strcmp((char *)((uint8_t *)node_dst->data + sizeof(key_len_t)), str);
    TEST_CHK(cmp == 0);
    cmp = memcmp((uint8_t *)node_dst->data + ksize, (void *)&v, vsize);
    TEST_CHK(cmp == 0);

    void *vars[] = {(void *)node_src, (void *)node_dst, key};
    freevars(vars, sizeof(vars)/sizeof(void *));

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
void kv_copy_var_nentry_test()
{
    TEST_INIT();
    memleak_start();

    bnoderef node, node_dst;
    btree_kv_ops *kv_ops;
    uint8_t ksize, vsize;
    uint8_t v;
    idx_t idx, src_idx, dst_idx, len;
    int cmp, i;
    size_t offset_idx;
    const char *keys[] = {"string",
                          "longstring",
                          "longerstring",
                          "",
                          "123231234242423428492342",
                          "string with space"};
    char *node_str;
    int n =  sizeof(keys)/sizeof(void *);
    void **key_ptrs = alca(void *, n);

    for (i = 0; i < n; i++) {
        construct_key_ptr(keys[i], strlen(keys[i]) + 1, &key_ptrs[i]);
    }

    ksize = strlen(keys[0]) + 1 + sizeof(key_len_t);
    vsize = sizeof(v);
    node = dummy_node(ksize, vsize, 1);
    node->nentry = n;

    v = 100;
    kv_ops = alca(btree_kv_ops, 1);
    btree_str_kv_get_kb64_vb64(kv_ops);

    // set n items into source node
    for (idx = 0; idx < n; idx++){
        kv_ops->set_kv(node, idx, &key_ptrs[idx], (void *)&v);
    }

    // copy n/2 entries into dest node
    src_idx = n/2;
    dst_idx = 0;
    len = src_idx;
    node_dst = dummy_node(ksize, vsize, 1);
    kv_ops->copy_kv(node_dst, node, dst_idx, src_idx, len);

    // verify
    offset_idx = 0;
    for (idx = src_idx; idx < n; idx++){

        offset_idx += sizeof(key_len_t);
        node_str = (char *)((uint8_t *)node_dst->data + offset_idx);
        cmp = strcmp(node_str, keys[idx]);
        TEST_CHK(cmp == 0);

        // check value
        offset_idx += strlen(keys[idx]) + 1;
        cmp = memcmp((uint8_t *)node_dst->data + offset_idx, &v, vsize);
        TEST_CHK(cmp == 0);

        offset_idx += vsize;

    }

    // append n entries into dst node
    dst_idx = src_idx;
    src_idx = 0;
    kv_ops->copy_kv(node_dst, node, dst_idx, src_idx, n);

    // verify
    for (idx = src_idx; idx < n; idx++){

        offset_idx += sizeof(key_len_t);
        node_str = (char *)((uint8_t *)node_dst->data + offset_idx);
        cmp = strcmp(node_str, keys[idx]);
        TEST_CHK(cmp == 0);

        // check value
        offset_idx += strlen(keys[idx]) + 1;
        cmp = memcmp((uint8_t *)node_dst->data + offset_idx, &v, vsize);
        TEST_CHK(cmp == 0);

        offset_idx += vsize;
    }

    // prepend n entries into dst node
    dst_idx = 0;
    src_idx = 0;
    kv_ops->copy_kv(node_dst, node, dst_idx, src_idx, n);

    // verify
    offset_idx = 0;
    for (idx = src_idx; idx < n; idx++){

        offset_idx += sizeof(key_len_t);
        node_str = (char *)((uint8_t *)node_dst->data + offset_idx);
        cmp = strcmp(node_str, keys[idx]);
        TEST_CHK(cmp == 0);

        // check value
        offset_idx += strlen(keys[idx]) + 1;
        cmp = memcmp((uint8_t *)node_dst->data + offset_idx, &v, vsize);
        TEST_CHK(cmp == 0);

        offset_idx += vsize;
    }

    free(node); free(node_dst);
    freevars(key_ptrs, n);

    memleak_end();
    TEST_RESULT("kv_copy_var_nentry_test");
}


/*
 * Test: kv_free_kv_var_test
 *
 * verifies freeing a kv entry
 *
 */
void kv_free_kv_var_test()
{
    TEST_INIT();
    memleak_start();

    btree_kv_ops *kv_ops;
    btree *tree;
    void *key;
    int v;
    char str[] = "teststring";

    kv_ops = alca(btree_kv_ops, 1);
    btree_str_kv_get_kb64_vb64(kv_ops);
    tree = alca(struct btree, 1);
    tree->vsize = sizeof(v);
    v = 1;
    construct_key_ptr(str, sizeof(str), &key);

    // free kv string
    kv_ops->free_kv_var(tree, &key, (void *)&v);
    TEST_CHK(key == NULL);

    // attempt double free
    kv_ops->free_kv_var(tree, &key, (void *)&v);
    TEST_CHK(key == NULL);

    memleak_end();
    TEST_RESULT("kv_free_kv_var_test");
}

/*
 * Test: kv_get_nth_idx_test
 *
 * verifies calculating nth index of bnode entry
 *
 */
void kv_get_nth_idx_test()
{

    TEST_INIT();
    memleak_start();

    btree_kv_ops *kv_ops;
    bnoderef node;
    idx_t num, den, location;

    kv_ops = alca(btree_kv_ops, 1);
    btree_str_kv_get_kb64_vb64(kv_ops);
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
void kv_get_nth_splitter_test()
{
    TEST_INIT();
    memleak_start();

    bnoderef node;
    btree_kv_ops *kv_ops;
    uint8_t ksize, vsize;
    uint8_t v;
    idx_t idx;
    int cmp;
    void *key;

    const char *keys[] = {"string",
                          "longstring",
                          "longerstring",
                          "",
                          "123231234242423428492342",
                          "string with space"};

    int n =  sizeof(keys)/sizeof(void *);
    void **key_ptrs = alca(void *, n);

    for (int i = 0; i < n; i++) {
        construct_key_ptr(keys[i], strlen(keys[i]) + 1, &key_ptrs[i]);
    }

    ksize = strlen(keys[0]) + 1 + sizeof(key_len_t);
    vsize = sizeof(v);
    node = dummy_node(ksize, vsize, 1);
    node->nentry = n;

    v = 100;
    kv_ops = alca(btree_kv_ops, 1);
    btree_str_kv_get_kb64_vb64(kv_ops);

    // set n keys
    for (idx = 0; idx < n; idx ++){
        kv_ops->set_kv(node, idx, &key_ptrs[idx], (void *)&v);
        v++;
    }

    // set *key to nth_splitter
    key = NULL;
    kv_ops->get_nth_splitter(NULL, node, &key);

    // verify key[0] is set as splitter
    cmp = memcmp(key, key_ptrs[0], ksize);
    TEST_CHK(cmp == 0);

    free(node);
    free(key);
    freevars(key_ptrs, n);
    memleak_end();
    TEST_RESULT("kv_get_nth_splitter_test");
}

/*
 * Test: kv_cmp_key_str_test
 *
 * test comparison of keys for the following scenarios
 *  - equal keylens w/out equality
 *  - variable keylens with w/out equality
 *  - null key_ptrs
 *
 */
void kv_cmp_key_str_test()
{

    TEST_INIT();
    memleak_start();

    btree_kv_ops *kv_ops;
    int cmp;
    const char *keys[] = {"string",
                          "srting",
                          "longstring",
                          "longstringsuffix"};

    int n =  sizeof(keys)/sizeof(void *);
    void **key_ptrs = alca(void *, n);
    void *tmp = NULL;


    kv_ops = alca(btree_kv_ops, 1);
    btree_str_kv_get_kb64_vb64(kv_ops);

    // construct key_ptrs
    for (int i = 0; i < n; i++){
        // omit null terminator
        construct_key_ptr(keys[i], strlen(keys[i]), &key_ptrs[i]);
    }


    // compare strings equal length equal values
    cmp = kv_ops->cmp(&key_ptrs[0], &key_ptrs[0], NULL);
    TEST_CHK( cmp == 0 );

    // compare strings equal length diff values
    cmp = kv_ops->cmp(&key_ptrs[0], &key_ptrs[1], NULL);
    TEST_CHK( cmp > 0 );

    // compare strings diff length equal substrings
    cmp = kv_ops->cmp(&key_ptrs[2], &key_ptrs[3], NULL);
    TEST_CHK(cmp == ((int)strlen(keys[2]) - (int)strlen(keys[3])) );

    // compare strings diff length diff substrings
    cmp = kv_ops->cmp(&key_ptrs[0], &key_ptrs[3], NULL);
    TEST_CHK( cmp > 0 );

    // key1 is NULL
    cmp = kv_ops->cmp(&tmp, &key_ptrs[0], NULL);
    TEST_CHK( cmp == -1 );

    // key2 is NULL
    cmp = kv_ops->cmp(&key_ptrs[0], &tmp, NULL);
    TEST_CHK( cmp == 1 );

    // key1 and key2 are NULL
    cmp = kv_ops->cmp(&tmp, &tmp, NULL);
    TEST_CHK( cmp == 0 );

    freevars(key_ptrs, n);
    memleak_end();
    TEST_RESULT("kv_cmp_key_str_test");
}

/*
 * Test: kv_bid_to_value_to_bid_test
 *
 * verifies conversion of values to bid types and vice-versa
 */
void kv_bid_to_value_to_bid_test()
{
    TEST_INIT();
    memleak_start();

    btree_kv_ops *kv_ops;
    void *value;
    bid_t bid1, bid2;

    kv_ops = alca(btree_kv_ops, 1);
    btree_str_kv_get_kb64_vb64(kv_ops);

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

    #ifdef _MEMPOOL
        mempool_init();
    #endif

    kv_set_key_test();
    kv_get_key_test();
    kv_get_key_isnull_test();
    kv_free_test();
    kv_init_ops_test();
    kv_init_var_test();

    kv_set_var_test();
    //kv_set_var_nentry_test();
    //kv_set_var_nentry_update_test();

    kv_get_var_test();
    //kv_get_var_nentry_test();

    kv_ins_var();
    //kv_ins_var_nentry_test();

    kv_set_str_key_test();
    kv_set_str_value_test();

    kv_get_str_data_size_test();
    kv_get_str_kv_size_test();

    kv_copy_var_test();
    //kv_copy_var_nentry_test();

    kv_free_kv_var_test();
    kv_get_nth_idx_test();
    //kv_get_nth_splitter_test();

    kv_cmp_key_str_test();

    kv_bid_to_value_to_bid_test();

    return 0;
}
