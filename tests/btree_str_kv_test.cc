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

typedef uint16_t key_len_t;


void freevars(void **vv, size_t n)
{
    for(int i = 0; i < n; i++){
        free(vv[i]);
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
    node = (struct bnode*)malloc(sizeof(bnode));
    memset(node, 0, sizeof(bnode));

    node->kvsize = ksize<<4 | vsize;
    node->level = level;
    node->data = (void *)malloc(node->kvsize);
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
    char str2[] = "test";
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

    void *vars[] = {node->data, node, key};
    freevars(vars, sizeof(vars)/sizeof(void *));

    memleak_end();
    TEST_RESULT("kv set var test");
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

    return 0;
}
