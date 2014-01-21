#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include "filemgr.h"
#include "filemgr_ops_linux.h"
#include "btreeblock.h"
#include "btree.h"
#include "btree_kv.h"
#include "test.h"

#include "memleak.h"

void print_btree(struct btree *btree, void *key, void *value)
{
    fprintf(stderr, "(%"_F64" %"_F64")", *(uint64_t*)key, *(uint64_t*)value);
}

void basic_test()
{
    TEST_INIT();

    int ksize = 8;
    int vsize = 8;
    int nodesize = (ksize + vsize)*4 + sizeof(struct bnode);
    int blocksize = nodesize * 2;
    struct filemgr *file;
    struct btreeblk_handle btree_handle;
    struct btree btree;
    struct filemgr_config config;
    int i, r;
    uint64_t k,v;

    memset(&config, 0, sizeof(config));
    config.blocksize = blocksize;
    config.ncacheblock = 1024;
    config.flag = 0x0;
    r = system("rm -rf ./dummy");
    file = filemgr_open("./dummy", get_linux_filemgr_ops(), &config);
    btreeblk_init(&btree_handle, file, nodesize);

    btree_init(&btree, (void*)&btree_handle, btreeblk_get_ops(), btree_kv_get_ku64_vu64(), nodesize, ksize, vsize, 0x0, NULL);

    for (i=0;i<6;++i) {
        k = i; v = i*10;
        btree_insert(&btree, &k, &v);
    }

    btree_print_node(&btree, print_btree);
    //btree_operation_end(&btree);

    for (i=6;i<12;++i) {
        k = i; v = i*10;
        btree_insert(&btree, &k, &v);
    }

    btree_print_node(&btree, print_btree);
    btreeblk_end(&btree_handle);
    //btree_operation_end(&btree);

    k = 4;
    v = 44;
    btree_insert(&btree, &k, &v);
    btree_print_node(&btree, print_btree);
    //btree_operation_end(&btree);

    btreeblk_end(&btree_handle);
    filemgr_commit(file);

    k = 5;
    v = 55;
    btree_insert(&btree, &k, &v);
    btree_print_node(&btree, print_btree);
    //btree_operation_end(&btree);

    btreeblk_end(&btree_handle);
    filemgr_commit(file);

    k = 5;
    v = 59;
    btree_insert(&btree, &k, &v);
    btree_print_node(&btree, print_btree);
    //btree_operation_end(&btree);

    btreeblk_end(&btree_handle);
    filemgr_commit(file);


    struct btree btree2;

    DBG("re-read using root bid %"_F64"\n", btree.root_bid);
    btree_init_from_bid(&btree2, (void*)&btree_handle, btreeblk_get_ops(), btree_kv_get_ku64_vu64(), nodesize, btree.root_bid);
    btree_print_node(&btree2, print_btree);
    /*
    DBG("re-read using root bid 13\n");
    btree_init_from_bid(&btree2, (void*)&btree_handle, btreeblk_get_ops(), btree_kv_get_ku64_vu64(), nodesize, 13);
    btree_print_node(&btree2, print_btree);
    */
    btreeblk_free(&btree_handle);

    TEST_RESULT("basic test");
}

void iterator_test()
{
    TEST_INIT();

    int ksize = 8;
    int vsize = 8;
    int nodesize = (ksize + vsize)*4 + sizeof(struct bnode);
    int blocksize = nodesize * 2;
    struct filemgr *file;
    struct btreeblk_handle btree_handle;
    struct btree btree;
    struct btree_iterator bi;
    struct filemgr_config config;
    btree_result br;
    int i, r;
    uint64_t k,v;

    memset(&config, 0, sizeof(config));
    config.blocksize = blocksize;
    config.ncacheblock = 0;
    config.flag = 0x0;
    r = system("rm -rf ./dummy");
    file = filemgr_open("./dummy", get_linux_filemgr_ops(), &config);
    btreeblk_init(&btree_handle, file, nodesize);

    btree_init(&btree, (void*)&btree_handle, btreeblk_get_ops(), btree_kv_get_ku64_vu64(), nodesize, ksize, vsize, 0x0, NULL);

    for (i=0;i<6;++i) {
        k = i*2; v = i*10;
        btree_insert(&btree, &k, &v);
    }

    btree_print_node(&btree, print_btree);
    //btree_operation_end(&btree);

    for (i=6;i<12;++i) {
        k = i*2; v = i*10;
        btree_insert(&btree, &k, &v);
    }

    btree_print_node(&btree, print_btree);
    btreeblk_end(&btree_handle);
    //btree_operation_end(&btree);

    filemgr_commit(file);

    k = 4;
    btree_iterator_init(&btree, &bi, &k);
    for (i=0;i<3;++i){
        btree_next(&bi, &k, &v);
        DBG("%"_F64" , %"_F64"\n", k, v);
    }
    btree_iterator_free(&bi);

    DBG("\n");
    k = 7;
    btree_iterator_init(&btree, &bi, &k);
    for (i=0;i<3;++i){
        btree_next(&bi, &k, &v);
        DBG("%"_F64" , %"_F64"\n", k, v);
    }
    btree_iterator_free(&bi);

    DBG("\n");
    btree_iterator_init(&btree, &bi, NULL);
    for (i=0;i<30;++i){
        br = btree_next(&bi, &k, &v);
        if (br == BTREE_RESULT_FAIL) break;
        DBG("%"_F64" , %"_F64"\n", k, v);
    }
    btree_iterator_free(&bi);


    TEST_RESULT("iterator test");
}


void two_btree_test()
{
    TEST_INIT();

    int i;
    int nodesize = sizeof(struct bnode) + 16*4;
    int blocksize = nodesize * 4;
    struct filemgr *file;
    struct btreeblk_handle btreeblk_handle;
    struct btree btree_a, btree_b;
    struct filemgr_config config;
    uint64_t k,v;

    memset(&config, 0, sizeof(config));
    config.blocksize = blocksize;
    config.ncacheblock = 1024;
    file = filemgr_open("./dummy", get_linux_filemgr_ops(), &config);
    btreeblk_init(&btreeblk_handle, file, nodesize);

    btree_init(&btree_a, (void*)&btreeblk_handle, btreeblk_get_ops(), btree_kv_get_ku64_vu64(), nodesize, 8, 8, 0x0, NULL);
    btree_init(&btree_b, (void*)&btreeblk_handle, btreeblk_get_ops(), btree_kv_get_ku64_vu64(), nodesize, 8, 8, 0x0, NULL);

    for (i=0;i<12;++i){
        k = i*2; v = k * 10;
        btree_insert(&btree_a, &k, &v);

        k = i*2 + 1; v = k*10 + 5;
        btree_insert(&btree_b, &k, &v);
    }

    filemgr_commit(file);

    btree_print_node(&btree_a, print_btree);
    btree_print_node(&btree_b, print_btree);

    TEST_RESULT("two btree test");
}

void range_test()
{
    TEST_INIT();

    int i, r, n=16, den=5;
    int blocksize = 512;
    struct filemgr *file;
    struct btreeblk_handle bhandle;
    struct btree btree;
    struct filemgr_config fconfig;
    uint64_t key, value, key_end;

    memset(&fconfig, 0, sizeof(fconfig));
    fconfig.blocksize = blocksize;
    fconfig.ncacheblock = 0;

    r = system("rm -rf ./dummy");
    file = filemgr_open("./dummy", get_linux_filemgr_ops(), &fconfig);
    btreeblk_init(&bhandle, file, blocksize);

    btree_init(&btree, &bhandle, btreeblk_get_ops(), btree_kv_get_ku64_vu64(),
        blocksize, sizeof(uint64_t), sizeof(uint64_t), 0x0, NULL);

    for (i=0;i<n;++i){
        key = i;
        value = i*10;
        btree_insert(&btree, &key, &value);
        btreeblk_end(&bhandle);
    }

    for (i=0;i<den;++i){
        btree_get_key_range(&btree, i, den, &key, &key_end);
        DBG("%d %d\n", (int)key, (int)key_end);
    }

    btreeblk_free(&bhandle);
    filemgr_close(file);
    filemgr_shutdown();

    TEST_RESULT("range test");
}

int main()
{
    #ifdef _MEMPOOL
        mempool_init();
    #endif

    int r = system("rm -rf ./dummy");
    //basic_test();
    //iterator_test();
    //two_btree_test();
    //btreeblk_cache_test();
    range_test();

    return 0;
}
