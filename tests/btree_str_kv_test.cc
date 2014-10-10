#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "btree_str_kv.h"
#include "test.h"
#include "common.h"
#include "list.h"
#include "memleak.h"

typedef uint16_t key_len_t;

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

int main()
{

    #ifdef _MEMPOOL
        mempool_init();
    #endif

    kv_set_key_test();
    kv_get_key_test();
    kv_free_test();
    return 0;
}
