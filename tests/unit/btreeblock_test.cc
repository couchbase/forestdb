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

#include "filemgr.h"
#include "filemgr_ops.h"
#include "btreeblock.h"
#include "btree.h"
#include "btree_kv.h"
#include "test.h"

#include "memleak.h"

static int blk_test_cmp64(void *key1, void *key2, void *aux)
{
    (void) aux;
    uint64_t a,b;
    a = deref64(key1);
    b = deref64(key2);

#ifdef __BIT_CMP
    return _CMP_U64(a, b);
#else
    if (a < b) {
        return -1;
    } else if (a > b) {
        return 1;
    } else {
        return 0;
    }
#endif
}

void basic_test()
{
    TEST_INIT();

    int ksize = 8;
    int vsize = 8;
    int nodesize = (ksize + vsize)*4 + sizeof(struct bnode);
    int blocksize = nodesize * 2;
    FileMgr *file;
    BTreeBlkHandle *btree_handle;
    BTree *btree;
    FileMgrConfig config(blocksize, 0, 1048576, 0x0, 0, FILEMGR_CREATE,
                         FDB_SEQTREE_NOT_USE, 0, 8, 0, FDB_ENCRYPTION_NONE,
                         0x00, 0, 0);

    int i, r;
    uint64_t k,v;
    std::string fname("./btreeblock_testfile");

    r = system(SHELL_DEL" btreeblock_testfile");
    (void)r;
    r = system(SHELL_DEL" btreeblock_testfile");
    (void)r;

    filemgr_open_result result = FileMgr::open(fname, get_filemgr_ops(), &config, NULL);
    file = result.file;
    btree_handle = new BTreeBlkHandle(file, nodesize);

    BTreeKVOps *kv_ops = new FixedKVOps(sizeof(uint64_t),
                                        sizeof(uint64_t),
                                        blk_test_cmp64);
    btree = new BTree(btree_handle, kv_ops, nodesize, ksize, vsize, 0x0, NULL);

    for (i=0;i<6;++i) {
        k = i; v = i*10;
        btree->insert((void*)&k, (void*)&v);
    }

    for (i=6;i<12;++i) {
        k = i; v = i*10;
        btree->insert((void*)&k, (void*)&v);
    }
    btree_handle->flushBuffer();

    k = 4;
    v = 44;
    btree->insert((void*)&k, (void*)&v);
    btree_handle->flushBuffer();
    file->commit_FileMgr(true, NULL);

    k = 5;
    v = 55;
    btree->insert((void*)&k, (void*)&v);
    btree_handle->flushBuffer();
    file->commit_FileMgr(true, NULL);

    k = 5;
    v = 59;
    btree->insert((void*)&k, (void*)&v);
    btree_handle->flushBuffer();
    file->commit_FileMgr(true, NULL);

    BTree *btree2;

    DBG("re-read using root bid %" _F64 "\n", btree->getRootBid());
    btree2 = new BTree(btree_handle,kv_ops, nodesize, btree->getRootBid());
    (void)btree2;

    delete btree;
    delete btree2;

    delete kv_ops;
    delete btree_handle;

    FileMgr::close(file, true, NULL, NULL);
    FileMgr::shutdown();

    TEST_RESULT("basic test");
}

void iterator_test()
{
    TEST_INIT();

    int ksize = 8;
    int vsize = 8;
    int nodesize = (ksize + vsize)*4 + sizeof(struct bnode);
    int blocksize = nodesize * 2;
    FileMgr *file;
    BTreeBlkHandle *btree_handle;
    BTree *btree;
    BTreeIterator *bi;
    FileMgrConfig config(blocksize, 0, 1048576, 0x0, 0, FILEMGR_CREATE,
                         FDB_SEQTREE_NOT_USE, 0, 8, 0, FDB_ENCRYPTION_NONE,
                         0x00, 0, 0);
    btree_result br;
    int i, r;
    uint64_t k,v;
    std::string fname("./btreeblock_testfile");

    r = system(SHELL_DEL" btreeblock_testfile");
    (void)r;

    filemgr_open_result result = FileMgr::open(fname, get_filemgr_ops(), &config, NULL);
    file = result.file;
    btree_handle = new BTreeBlkHandle(file, nodesize);

    BTreeKVOps *kv_ops = new FixedKVOps(sizeof(uint64_t),
                                        sizeof(uint64_t),
                                        blk_test_cmp64);
    btree = new BTree(btree_handle, kv_ops, nodesize, ksize, vsize, 0x0, NULL);

    for (i=0;i<6;++i) {
        k = i*2; v = i*10;
        btree->insert((void*)&k, (void*)&v);
    }

    for (i=6;i<12;++i) {
        k = i*2; v = i*10;
        btree->insert((void*)&k, (void*)&v);
    }
    btree_handle->flushBuffer();

    file->commit_FileMgr(true, NULL);

    k = 4;
    bi = new BTreeIterator(btree, (void*)&k);
    for (i=0;i<3;++i){
        bi->next((void*)&k, (void*)&v);
        DBG("%" _F64 " , %" _F64 "\n", k, v);
    }
    delete bi;

    DBG("\n");
    k = 7;
    bi = new BTreeIterator(btree, (void*)&k);
    for (i=0;i<3;++i){
        bi->next((void*)&k, (void*)&v);
        DBG("%" _F64 " , %" _F64 "\n", k, v);
    }
    delete bi;

    DBG("\n");
    bi = new BTreeIterator(btree, NULL);
    for (i=0;i<30;++i){
        br = bi->next((void*)&k, (void*)&v);
        if (br == BTREE_RESULT_FAIL) {
            break;
        }
        DBG("%" _F64 " , %" _F64 "\n", k, v);
    }
    delete bi;
    delete btree;
    delete btree_handle;
    delete kv_ops;
    FileMgr::close(file, true, NULL, NULL);
    FileMgr::shutdown();

    TEST_RESULT("iterator test");
}


void two_btree_test()
{
    TEST_INIT();

    int i;
    int nodesize = sizeof(struct bnode) + 16*4;
    int blocksize = nodesize * 4;
    FileMgr *file;
    BTreeBlkHandle *btreeblk_handle;
    BTree *btree_a, *btree_b;
    FileMgrConfig config(blocksize, 1024, 1048576, 0x0, 0, FILEMGR_CREATE,
                         FDB_SEQTREE_NOT_USE, 0, 8, 0, FDB_ENCRYPTION_NONE,
                         0x00, 0, 0);
    uint64_t k,v;
    std::string fname("./btreeblock_testfile");
    int r = system(SHELL_DEL" btreeblock_testfile");
    (void)r;

    filemgr_open_result result = FileMgr::open(fname, get_filemgr_ops(), &config, NULL);
    file = result.file;
    btreeblk_handle = new BTreeBlkHandle(file, nodesize);

    BTreeKVOps *kv_ops = new FixedKVOps(sizeof(uint64_t),
                                        sizeof(uint64_t),
                                        blk_test_cmp64);
    btree_a = new BTree(btreeblk_handle, kv_ops, nodesize, 8, 8, 0x0, NULL);
    btree_b = new BTree(btreeblk_handle, kv_ops, nodesize, 8, 8, 0x0, NULL);

    for (i=0;i<12;++i){
        k = i*2; v = k * 10;
        btree_a->insert((void*)&k, (void*)&v);

        k = i*2 + 1; v = k*10 + 5;
        btree_b->insert((void*)&k, (void*)&v);
    }

    delete btree_a;
    delete btree_b;

    delete btreeblk_handle;
    delete kv_ops;

    file->commit_FileMgr(true, NULL);
    FileMgr::close(file, true, NULL, NULL);
    FileMgr::shutdown();

    TEST_RESULT("two btree test");
}

void range_test()
{
    TEST_INIT();

    int i, r, n=16, den=5;
    int blocksize = 512;
    FileMgr *file;
    BTreeBlkHandle *bhandle;
    BTree *btree;
    FileMgrConfig fconfig(blocksize, 0, 1048576, 0, 0, FILEMGR_CREATE,
                          FDB_SEQTREE_NOT_USE, 0, 8, 0, FDB_ENCRYPTION_NONE,
                          0x00, 0, 0);
    uint64_t key, value, key_end;
    std::string fname("./btreeblock_testfile");

    r = system(SHELL_DEL" btreeblock_testfile");
    (void)r;

    filemgr_open_result result = FileMgr::open(fname, get_filemgr_ops(), &fconfig, NULL);
    file = result.file;
    bhandle = new BTreeBlkHandle(file, blocksize);

    BTreeKVOps *kv_ops = new FixedKVOps(sizeof(uint64_t),
                                        sizeof(uint64_t),
                                        blk_test_cmp64);
    btree = new BTree(bhandle, kv_ops, blocksize,
                      sizeof(uint64_t), sizeof(uint64_t), 0x0, NULL);

    for (i=0;i<n;++i){
        key = i;
        value = i*10;
        btree->insert((void*)&key, (void*)&value);
        bhandle->flushBuffer();
    }

    for (i=0;i<den;++i){
        btree->getKeyRange(i, den, (void*)&key, (void*)&key_end);
        DBG("%d %d\n", (int)key, (int)key_end);
    }

    delete btree;
    delete kv_ops;
    delete bhandle;
    FileMgr::close(file, true, NULL, NULL);
    FileMgr::shutdown();

    TEST_RESULT("range test");
}

INLINE int is_subblock(bid_t subbid)
{
    uint8_t flag;
    flag = (subbid >> (8 * (sizeof(bid_t)-2))) & 0x00ff;
    return flag;
}

INLINE void subbid2bid(bid_t subbid, size_t *subblock_no, size_t *idx, bid_t *bid)
{
    uint8_t flag;
    flag = (subbid >> (8 * (sizeof(bid_t)-2))) & 0x00ff;
    *subblock_no = flag >> 5;
    // to distinguish subblock_no==0 to non-subblock
    *subblock_no -= 1;
    *idx = flag & (0x20 - 0x01);
    *bid = ((bid_t)(subbid << 16)) >> 16;
}

void subblock_test()
{
    TEST_INIT();

    int i, j, k, r, nbtrees;
    int nodesize;
    int blocksize = 4096;
    std::string fname("./btreeblock_testfile");
    char keybuf[256], valuebuf[256], temp[256];
    filemgr_open_result result;
    btree_result br;
    bid_t bid;
    size_t subblock_no, idx;
    FileMgr *file;
    BTreeBlkHandle *bhandle;
    BTree *btree, *btree_arr[64];
    FileMgrConfig fconfig(blocksize, 0, 1048576, 0, 0, FILEMGR_CREATE,
                          FDB_SEQTREE_NOT_USE, 0, 8, 0, FDB_ENCRYPTION_NONE,
                          0x00, 0, 0);
    struct btree_meta meta;

    BTreeKVOps *kv_ops = new FixedKVOps(sizeof(uint64_t),
                                        sizeof(uint64_t),
                                        blk_test_cmp64);

    // btree initialization using large metadata test
    r = system(SHELL_DEL" btreeblock_testfile");
    (void)r;
    result = FileMgr::open(fname, get_filemgr_ops(), &fconfig, NULL);
    file = result.file;
    meta.data = (void*)malloc(4096);

    meta.size = 120;
    bhandle = new BTreeBlkHandle(file, blocksize);
    btree = new BTree(bhandle, kv_ops, blocksize, sizeof(uint64_t),
                      sizeof(uint64_t), 0x0, &meta);
    TEST_CHK(is_subblock(btree->getRootBid()));
    subbid2bid(btree->getRootBid(), &subblock_no, &idx, &bid);
    TEST_CHK(subblock_no == 1);
    delete btree;
    delete bhandle;

    meta.size = 250;
    bhandle = new BTreeBlkHandle(file, blocksize);
    btree = new BTree(bhandle, kv_ops, blocksize, sizeof(uint64_t),
                      sizeof(uint64_t), 0x0, &meta);
    TEST_CHK(is_subblock(btree->getRootBid()));
    subbid2bid(btree->getRootBid(), &subblock_no, &idx, &bid);
    TEST_CHK(subblock_no == 2);
    delete btree;
    delete bhandle;

    meta.size = 510;
    bhandle = new BTreeBlkHandle(file, blocksize);
    btree = new BTree(bhandle, kv_ops, blocksize, sizeof(uint64_t),
                      sizeof(uint64_t), 0x0, &meta);
    TEST_CHK(is_subblock(btree->getRootBid()));
    subbid2bid(btree->getRootBid(), &subblock_no, &idx, &bid);
    TEST_CHK(subblock_no == 3);
    delete btree;
    delete bhandle;

    meta.size = 1020;
    bhandle = new BTreeBlkHandle(file, blocksize);
    btree = new BTree(bhandle, kv_ops, blocksize, sizeof(uint64_t),
                      sizeof(uint64_t), 0x0, &meta);
    TEST_CHK(is_subblock(btree->getRootBid()));
    subbid2bid(btree->getRootBid(), &subblock_no, &idx, &bid);
    TEST_CHK(subblock_no == 4);
    delete btree;
    delete bhandle;

    meta.size = 2040;
    bhandle = new BTreeBlkHandle(file, blocksize);
    btree = new BTree(bhandle, kv_ops, blocksize, sizeof(uint64_t),
                      sizeof(uint64_t), 0x0, &meta);
    TEST_CHK(!is_subblock(btree->getRootBid()));
    delete btree;
    delete bhandle;

    meta.size = 4090;
    bhandle = new BTreeBlkHandle(file, blocksize);
    btree = new BTree();
    br = btree->init(bhandle, kv_ops, blocksize, sizeof(uint64_t),
                     sizeof(uint64_t), 0x0, &meta);
    TEST_CHK(br == BTREE_RESULT_FAIL);
    delete btree;
    delete bhandle;
    FileMgr::close(file, true, NULL, NULL);
    FileMgr::shutdown();
    free(meta.data);

    // coverage: enlarge case 1-1
    r = system(SHELL_DEL" btreeblock_testfile");
    (void)r;
    result = FileMgr::open(fname, get_filemgr_ops(), &fconfig, NULL);
    file = result.file;

    bhandle = new BTreeBlkHandle(file, blocksize);
    btree = new BTree(bhandle, kv_ops, blocksize, sizeof(uint64_t),
                      sizeof(uint64_t), 0x0, NULL);
    for (i=0;i<256;++i){
        sprintf(keybuf, "%08d", i);
        sprintf(valuebuf, "%08x", i);
        btree->insert((void*)keybuf, (void*)valuebuf);
        bhandle->flushBuffer();
        for (j=0;j<=i;++j){
            sprintf(keybuf, "%08d", j);
            sprintf(valuebuf, "%08x", j);
            btree->find((void*)keybuf, (void*)temp);
            bhandle->flushBuffer();
            TEST_CHK(!memcmp(valuebuf, temp, strlen(valuebuf)));
        }
    }
    delete btree;
    delete bhandle;
    FileMgr::close(file, true, NULL, NULL);
    FileMgr::shutdown();

    // coverage: enlarge case 1-2, move case 1
    r = system(SHELL_DEL" btreeblock_testfile");
    (void)r;
    result = FileMgr::open(fname, get_filemgr_ops(), &fconfig, NULL);
    file = result.file;

    bhandle = new BTreeBlkHandle(file, blocksize);
    btree = new BTree(bhandle, kv_ops, blocksize, sizeof(uint64_t),
                      sizeof(uint64_t), 0x0, NULL);
    for (i=0;i<256;++i){
        sprintf(keybuf, "%08d", i);
        sprintf(valuebuf, "%08x", i);
        btree->insert((void*)keybuf, (void*)valuebuf);
        bhandle->flushBuffer();
        file->commit_FileMgr(true, NULL);
        for (j=0;j<=i;++j){
            sprintf(keybuf, "%08d", j);
            sprintf(valuebuf, "%08x", j);
            btree->find((void*)keybuf, (void*)temp);
            bhandle->flushBuffer();
            TEST_CHK(!memcmp(valuebuf, temp, strlen(valuebuf)));
        }
    }
    delete btree;
    delete bhandle;
    FileMgr::close(file, true, NULL, NULL);
    FileMgr::shutdown();

    // coverage: enlarge case 1-1, 2-1, 2-2, 3-1
    nbtrees = 2;
    r = system(SHELL_DEL" btreeblock_testfile");
    (void)r;
    result = FileMgr::open(fname, get_filemgr_ops(), &fconfig, NULL);
    file = result.file;

    bhandle = new BTreeBlkHandle(file, blocksize);
    for (i=0;i<nbtrees;++i){
        btree_arr[i] = new BTree(bhandle, kv_ops, blocksize, sizeof(uint64_t),
                                 sizeof(uint64_t), 0x0, NULL);
    }
    for (i=0;i<256;++i){
        for (j=0;j<nbtrees;++j){
            sprintf(keybuf, "%02d%06d", j, i);
            sprintf(valuebuf, "%02d%06x", j, i);
            btree_arr[j]->insert((void*)keybuf, (void*)valuebuf);
            bhandle->flushBuffer();
            for (k=0;k<=i;++k){
                sprintf(keybuf, "%02d%06d", j, k);
                sprintf(valuebuf, "%02d%06x", j, k);
                btree_arr[j]->find((void*)keybuf, (void*)temp);
                bhandle->flushBuffer();
                TEST_CHK(!memcmp(valuebuf, temp, strlen(valuebuf)));
            }
        }
    }
    for (i=0;i<nbtrees;++i){
        delete btree_arr[i];
    }
    delete bhandle;
    FileMgr::close(file, true, NULL, NULL);
    FileMgr::shutdown();

    // coverage: enlarge case 1-2, 2-1, 3-1, move case 1, 2-1, 2-2
    nbtrees = 2;
    r = system(SHELL_DEL" btreeblock_testfile");
    (void)r;
    result = FileMgr::open(fname, get_filemgr_ops(), &fconfig, NULL);
    file = result.file;

    bhandle = new BTreeBlkHandle(file, blocksize);
    for (i=0;i<nbtrees;++i){
        btree_arr[i] = new BTree(bhandle, kv_ops, blocksize, sizeof(uint64_t),
                                 sizeof(uint64_t), 0x0, NULL);
    }
    for (i=0;i<256;++i){
        for (j=0;j<nbtrees;++j){
            sprintf(keybuf, "%02d%06d", j, i);
            sprintf(valuebuf, "%02d%06x", j, i);
            btree_arr[j]->insert((void*)keybuf, (void*)valuebuf);
            bhandle->flushBuffer();
        }
        file->commit_FileMgr(true, NULL);
        for (j=0;j<nbtrees;++j){
            for (k=0;k<=i;++k){
                sprintf(keybuf, "%02d%06d", j, k);
                sprintf(valuebuf, "%02d%06x", j, k);
                btree_arr[j]->find((void*)keybuf, (void*)temp);
                bhandle->flushBuffer();
                TEST_CHK(!memcmp(valuebuf, temp, strlen(valuebuf)));
            }
        }
    }
    for (i=0;i<nbtrees;++i){
        delete btree_arr[i];
    }
    delete bhandle;
    FileMgr::close(file, true, NULL, NULL);
    FileMgr::shutdown();

    // coverage: enlarge case 1-1, 2-1, 3-2, move case 1, 2-1
    nbtrees = 7;
    r = system(SHELL_DEL" btreeblock_testfile");
    (void)r;
    result = FileMgr::open(fname, get_filemgr_ops(), &fconfig, NULL);
    file = result.file;

    bhandle = new BTreeBlkHandle(file, blocksize);
    for (i=0;i<nbtrees;++i){
        btree_arr[i] = new BTree(bhandle, kv_ops, blocksize, sizeof(uint64_t),
                                 sizeof(uint64_t), 0x0, NULL);
    }
    for (j=0;j<nbtrees;++j){
        nodesize = 128 * (1<<j);
        for (i=0;i<(nodesize-16)/16;++i){
            sprintf(keybuf, "%02d%06d", j, i);
            sprintf(valuebuf, "%02d%06x", j, i);
            btree_arr[j]->insert((void*)keybuf, (void*)valuebuf);
            bhandle->flushBuffer();
        }
        file->commit_FileMgr(true, NULL);
    }
    for (i=0;i<nbtrees;++i){
        delete btree_arr[i];
    }
    delete bhandle;
    FileMgr::close(file, true, NULL, NULL);
    FileMgr::shutdown();

    // coverage: enlarge case 1-1, 1-2, 2-1, 3-2, move case 1, 2-1
    nbtrees = 7;
    r = system(SHELL_DEL" btreeblock_testfile");
    (void)r;
    result = FileMgr::open(fname, get_filemgr_ops(), &fconfig, NULL);
    file = result.file;

    bhandle = new BTreeBlkHandle(file, blocksize);
    for (i=0;i<nbtrees;++i){
        btree_arr[i] = new BTree(bhandle, kv_ops, blocksize, sizeof(uint64_t),
                                 sizeof(uint64_t), 0x0, NULL);
    }
    for (j=0;j<nbtrees;++j){
        nodesize = 128 * (1<<j);
        for (i=0;i<(nodesize-16)/16;++i){
            sprintf(keybuf, "%02d%06d", j, i);
            sprintf(valuebuf, "%02d%06x", j, i);
            btree_arr[j]->insert((void*)keybuf, (void*)valuebuf);
            bhandle->flushBuffer();
            file->commit_FileMgr(true, NULL);
        }
    }
    for (i=0;i<nbtrees;++i){
        delete btree_arr[i];
    }
    delete bhandle;
    FileMgr::close(file, true, NULL, NULL);
    FileMgr::shutdown();

    delete kv_ops;
    TEST_RESULT("subblock test");
}

void btree_reverse_iterator_test()
{
    TEST_INIT();

    int ksize = 8, vsize = 8, r, c;
    int nodesize = 256;
    FileMgr *file;
    BTreeBlkHandle *bhandle;
    BTree *btree;
    BTreeIterator *bi;
    FileMgrConfig config(nodesize, 0, 1048576, 0, 0, FILEMGR_CREATE,
                         FDB_SEQTREE_NOT_USE, 0, 8, 0, FDB_ENCRYPTION_NONE,
                         0x00, 0, 0);
    btree_result br;
    filemgr_open_result fr;
    uint64_t i;
    uint64_t k,v;
    std::string fname("./btreeblock_testfile");

    r = system(SHELL_DEL" btreeblock_testfile");
    (void)r;

    memleak_start();

    fr = FileMgr::open(fname, get_filemgr_ops(), &config, NULL);
    file = fr.file;

    bhandle = new BTreeBlkHandle(file, nodesize);
    BTreeKVOps *kv_ops = new FixedKVOps(sizeof(uint64_t),
                                        sizeof(uint64_t));
    btree = new BTree(bhandle, kv_ops, nodesize, ksize, vsize, 0x0, NULL);

    for (i=10;i<40;++i) {
        k = _endian_encode(i*0x10);
        v = _endian_encode(i*0x100);
        btree->insert((void*)&k, (void*)&v);
        bhandle->flushBuffer();
    }

    c = 0;
    bi = new BTreeIterator(btree, NULL);
    while ((br = bi->next(&k, &v)) == BTREE_RESULT_SUCCESS) {
        bhandle->flushBuffer();
        k = _endian_decode(k);
        v = _endian_decode(v);
        TEST_CHK(k == (uint64_t)(c+10)*0x10);
        TEST_CHK(v == (uint64_t)(c+10)*0x100);
        c++;
    }
    bhandle->flushBuffer();
    delete bi;
    TEST_CHK(c == 30);

    c = 0;
    i=10000;
    k = _endian_encode(i);
    bi = new BTreeIterator(btree, &k);
    while ((br = bi->next(&k, &v)) == BTREE_RESULT_SUCCESS) {
        bhandle->flushBuffer();
        k = _endian_decode(k);
        v = _endian_decode(v);
    }
    bhandle->flushBuffer();
    delete bi;
    TEST_CHK(c == 0);

    // reverse iteration with NULL initial key
    c = 0;
    bi = new BTreeIterator(btree, NULL);
    while ((br = bi->prev(&k, &v)) == BTREE_RESULT_SUCCESS) {
        bhandle->flushBuffer();
        k = _endian_decode(k);
        v = _endian_decode(v);
    }
    bhandle->flushBuffer();
    delete bi;
    TEST_CHK(c == 0);

    c = 0;
    i=10000;
    k = _endian_encode(i);
    bi = new BTreeIterator(btree, &k);
    while ((br = bi->prev(&k, &v)) == BTREE_RESULT_SUCCESS) {
        bhandle->flushBuffer();
        k = _endian_decode(k);
        v = _endian_decode(v);
        TEST_CHK(k == (uint64_t)(39-c)*0x10);
        TEST_CHK(v == (uint64_t)(39-c)*0x100);
        c++;
    }
    bhandle->flushBuffer();
    delete bi;
    TEST_CHK(c == 30);

    c = 0;
    i=0x175;
    k = _endian_encode(i);
    bi = new BTreeIterator(btree, &k);
    while ((br = bi->prev(&k, &v)) == BTREE_RESULT_SUCCESS) {
        bhandle->flushBuffer();
        k = _endian_decode(k);
        v = _endian_decode(v);
        TEST_CHK(k == (uint64_t)(0x17-c)*0x10);
        TEST_CHK(v == (uint64_t)(0x17-c)*0x100);
        c++;
    }
    bhandle->flushBuffer();
    delete bi;
    TEST_CHK(c == 14);

    c = 0xa0 - 0x10;
    bi = new BTreeIterator(btree, NULL);
    for (i=0;i<15;++i){
        c += 0x10;
        br = bi->next(&k, &v);
        TEST_CHK(br == BTREE_RESULT_SUCCESS);
        bhandle->flushBuffer();
        k = _endian_decode(k);
        v = _endian_decode(v);
        TEST_CHK(k == (uint64_t)c);
        TEST_CHK(v == (uint64_t)c*0x10);
    }
    for (i=0;i<7;++i){
        c -= 0x10;
        br = bi->prev(&k, &v);
        TEST_CHK(br == BTREE_RESULT_SUCCESS);
        bhandle->flushBuffer();
        k = _endian_decode(k);
        v = _endian_decode(v);
        TEST_CHK(k == (uint64_t)c);
        TEST_CHK(v == (uint64_t)c*0x10);
    }
    for (i=0;i<10;++i){
        c += 0x10;
        br = bi->next(&k, &v);
        TEST_CHK(br == BTREE_RESULT_SUCCESS);
        bhandle->flushBuffer();
        k = _endian_decode(k);
        v = _endian_decode(v);
        TEST_CHK(k == (uint64_t)c);
        TEST_CHK(v == (uint64_t)c*0x10);
    }
    for (i=0;i<17;++i){
        c -= 0x10;
        br = bi->prev(&k, &v);
        TEST_CHK(br == BTREE_RESULT_SUCCESS);
        bhandle->flushBuffer();
        k = _endian_decode(k);
        v = _endian_decode(v);
        TEST_CHK(k == (uint64_t)c);
        TEST_CHK(v == (uint64_t)c*0x10);
    }
    br = bi->prev(&k, &v);
    bhandle->flushBuffer();
    TEST_CHK(br == BTREE_RESULT_FAIL);

    delete bi;
    delete btree;
    delete kv_ops;
    delete bhandle;
    FileMgr::close(file, true, NULL, NULL);
    FileMgr::shutdown();

    memleak_end();

    TEST_RESULT("btree reverse iterator test");
}

int main()
{
#ifdef _MEMPOOL
    mempool_init();
#endif

    basic_test();
    iterator_test();
    two_btree_test();
    range_test();
    subblock_test();
    btree_reverse_iterator_test();

    return 0;
}
