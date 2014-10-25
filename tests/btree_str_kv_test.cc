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
    for(int i = 0; i < n; i++){
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
    char kv_str[str_len];
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
    char *strbuf;
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

    node->kvsize = ksize<<4 | vsize;
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
    TEST_CHK(memcmp(kv_ops, kv_ops_copy, sizeof(btree_kv_ops)) == 0);

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

    idx = 0;
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
    idx_t idx;
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

    idx = 0;
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
    uint8_t offset;
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

    idx = 0;
    v = 100;
    kv_ops = alca(btree_kv_ops, 1);
    btree_str_kv_get_kb64_vb64(kv_ops);
    size_t offset_idx = 0;

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
    uint8_t offset;
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
    size_t offset_idx = 0;

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

    int cmp;
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
    kv_set_var_nentry_test();
    kv_set_var_nentry_update_test();
    kv_get_var_test();
    kv_get_var_nentry_test();
    kv_ins_var();
    kv_ins_var_nentry_test();
    kv_set_str_key_test();
    kv_set_str_value_test();

    return 0;
}
