/* -*- Mode: C++; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2016 Couchbase, Inc
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

#include "test.h"
#include "common.h"
#include "bnode.h"
#include "bnodemgr.h"
#include "bnodecache.h"
#include "btree_new.h"
#include "hbtrie.h"

void bnode_basic_test()
{
    TEST_INIT();

    Bnode *bnode = new Bnode();
    BnodeResult ret;
    size_t i;
    size_t n = 100;
    char keybuf[64], valuebuf[64];

    // add test
    for (i=0; i<n; ++i) {
        sprintf(keybuf, "k%07d\n", (int)i);
        sprintf(valuebuf, "v%07d\n", (int)i*10);
        ret = bnode->addKv(keybuf, 8, valuebuf, 8, nullptr, true);
        TEST_CHK(ret == BnodeResult::SUCCESS);
    }
    TEST_CHK(bnode->getNentry() == n);

    // meta
    char metabuf[64];
    sprintf(metabuf, "meta_data");
    bnode->setMeta(metabuf, 9);

    // find test
    size_t valuelen_out;
    void* value_out;
    Bnode *bnode_out;
    for (i=0; i<n; ++i) {
        sprintf(keybuf, "k%07d\n", (int)i);
        sprintf(valuebuf, "v%07d\n", (int)i*10);
        ret = bnode->findKv(keybuf, 8, value_out, valuelen_out, bnode_out);
        TEST_CHK(ret == BnodeResult::SUCCESS);
        TEST_CMP(value_out, valuebuf, valuelen_out);
    }

    // find min key test
    void* key_out;
    size_t keylen_out;
    i = 0;
    sprintf(keybuf, "k%07d\n", (int)i);
    ret = bnode->findMinKey(key_out, keylen_out);
    TEST_CHK(ret == BnodeResult::SUCCESS);
    TEST_CMP(key_out, keybuf, keylen_out);

    // update test
    for (i=0; i<n; ++i) {
        sprintf(keybuf, "k%07d\n", (int)i);
        sprintf(valuebuf, "v%07d\n", (int)i*20);
        ret = bnode->addKv(keybuf, 8, valuebuf, 8, nullptr, true);
        TEST_CHK(ret == BnodeResult::SUCCESS);
    }
    TEST_CHK(bnode->getNentry() == n);

    for (i=0; i<n; ++i) {
        sprintf(keybuf, "k%07d\n", (int)i);
        sprintf(valuebuf, "v%07d\n", (int)i*20);
        ret = bnode->findKv(keybuf, 8, value_out, valuelen_out, bnode_out);
        TEST_CHK(ret == BnodeResult::SUCCESS);
        TEST_CMP(value_out, valuebuf, valuelen_out);
    }

    // export/import test
    void *temp_buf = nullptr;
    temp_buf = bnode->exportRaw();

    // read node size
    size_t node_size = bnode->getNodeSize();
    size_t node_size_from_buffer = Bnode::readNodeSize(temp_buf);
    TEST_CHK(node_size_from_buffer == node_size);

    // import check
    Bnode *bnode_copy = new Bnode();
    void *temp_read_buf = (void*)malloc(node_size);
    memcpy(temp_read_buf, temp_buf, node_size);

    bnode_copy->importRaw((void*)temp_read_buf, node_size);

    for (i=0; i<n; ++i) {
        sprintf(keybuf, "k%07d\n", (int)i);
        sprintf(valuebuf, "v%07d\n", (int)i*20);
        ret = bnode_copy->findKv(keybuf, 8, value_out, valuelen_out, bnode_out);
        TEST_CHK(ret == BnodeResult::SUCCESS);
        TEST_CMP(value_out, valuebuf, valuelen_out);
    }

    TEST_CMP( bnode_copy->getMeta(),
              bnode->getMeta(),
              bnode_copy->getMetaSize() );

    // meta data update
    sprintf(metabuf, "new_meta_data");
    bnode->setMeta(metabuf, 13);
    bnode_copy->setMeta(metabuf, 13);

    // remove test
    for (i=0; i<n; ++i) {
        sprintf(keybuf, "k%07d\n", (int)i);
        ret = bnode->removeKv(keybuf, 8);
        TEST_CHK(ret == BnodeResult::SUCCESS);
    }
    TEST_CHK(bnode->getNentry() == 0);

    // remove bnode_copy (existing memory mode)
    for (i=0; i<n; ++i) {
        sprintf(keybuf, "k%07d\n", (int)i);
        ret = bnode_copy->removeKv(keybuf, 8);
        TEST_CHK(ret == BnodeResult::SUCCESS);
    }
    TEST_CHK(bnode_copy->getNentry() == 0);

    delete bnode;
    delete bnode_copy;

    TEST_RESULT("bnode basic test");
}

void bnode_iterator_test()
{
    TEST_INIT();

    Bnode *bnode = new Bnode();
    BnodeIterator *bit;
    BnodeResult ret;
    BnodeIteratorResult bit_ret = BnodeIteratorResult::SUCCESS;
    size_t i;
    size_t n = 100;
    char keybuf[64], valuebuf[64];

    // add test
    for (i=0; i<n; i++) {
        sprintf(keybuf, "k%07d\n", (int)i*10);
        sprintf(valuebuf, "v%07d\n", (int)i*100);
        ret = bnode->addKv(keybuf, 8, valuebuf, 8, nullptr, true);
        TEST_CHK(ret == BnodeResult::SUCCESS);
    }
    TEST_CHK(bnode->getNentry() == n);

    BsaItem kvp_out;

    // forward iteration
    bit = new BnodeIterator(bnode);
    i = 0;
    do {
        kvp_out = bit->getKv();
        if ( kvp_out.isEmpty() ) {
            break;
        }

        sprintf(keybuf, "k%07d\n", (int)i*10);
        sprintf(valuebuf, "v%07d\n", (int)i*100);

        TEST_CMP(keybuf, kvp_out.key, kvp_out.keylen);
        TEST_CMP(valuebuf, kvp_out.value, kvp_out.valuelen);
        i++;

        bit_ret = bit->next();
    } while (bit_ret == BnodeIteratorResult::SUCCESS);
    TEST_CHK(i == n);
    delete bit;

    // backward iteration
    bit = new BnodeIterator(bnode);
    bit_ret = bit->end();
    TEST_CHK(bit_ret == BnodeIteratorResult::SUCCESS);

    i = n;
    do {
        kvp_out = bit->getKv();
        if ( kvp_out.isEmpty() ) {
            break;
        }

        i--;
        sprintf(keybuf, "k%07d\n", (int)i*10);
        sprintf(valuebuf, "v%07d\n", (int)i*100);

        TEST_CMP(keybuf, kvp_out.key, kvp_out.keylen);
        TEST_CMP(valuebuf, kvp_out.value, kvp_out.valuelen);

        bit_ret = bit->prev();
    } while (bit_ret == BnodeIteratorResult::SUCCESS);
    TEST_CHK(i == 0);
    delete bit;

    // assigning start_key (seekGreater)
    i = n/2;
    sprintf(keybuf, "k%07d\n", (int)i*10 + 5);
    bit = new BnodeIterator(bnode, keybuf, 8);
    i++;

    do {
        kvp_out = bit->getKv();
        if ( kvp_out.isEmpty() ) {
            break;
        }

        sprintf(keybuf, "k%07d\n", (int)i*10);
        sprintf(valuebuf, "v%07d\n", (int)i*100);
        i++;

        TEST_CMP(keybuf, kvp_out.key, kvp_out.keylen);
        TEST_CMP(valuebuf, kvp_out.value, kvp_out.valuelen);

        bit_ret = bit->next();
    } while (bit_ret == BnodeIteratorResult::SUCCESS);
    TEST_CHK(i == n);
    delete bit;

    // seekSmaller
    bit = new BnodeIterator(bnode);

    i = n/2;
    sprintf(keybuf, "k%07d\n", (int)i*10 - 5);
    bit->seekSmallerOrEqual(keybuf, 8);
    i--;

    do {
        kvp_out = bit->getKv();
        if ( kvp_out.isEmpty() ) {
            break;
        }

        sprintf(keybuf, "k%07d\n", (int)i*10);
        sprintf(valuebuf, "v%07d\n", (int)i*100);
        i++;

        TEST_CMP(keybuf, kvp_out.key, kvp_out.keylen);
        TEST_CMP(valuebuf, kvp_out.value, kvp_out.valuelen);

        bit_ret = bit->next();
    } while (bit_ret == BnodeIteratorResult::SUCCESS);
    TEST_CHK(i == n);
    delete bit;

    delete bnode;

    TEST_RESULT("bnode iterator test");
}

void btree_iterator_test()
{
    TEST_INIT();

    BtreeV2 *btree;
    BtreeV2Result br;
    BnodeMgr *b_mgr;
    BtreeIteratorV2 *bti;
    BtreeKvPair kvp_out;
    BnodeIteratorResult bti_ret = BnodeIteratorResult::SUCCESS;
    FileMgrConfig config(4096, 39, 1048576, 0, 0, FILEMGR_CREATE,
                         FDB_SEQTREE_NOT_USE, 0, 8, 0, FDB_ENCRYPTION_NONE,
                         0x00, 0, 0);
    filemgr_open_result fr;
    std::string fname("./btree_new_testfile");

    int r = system(SHELL_DEL" btree_new_testfile");
    (void)r;

    fr = FileMgr::open(fname, get_filemgr_ops(), &config, NULL);

    size_t i;
    size_t n = 1000;
    char valuebuf[16];
    BtreeKvPair *kv_arr = (BtreeKvPair *)malloc(n * sizeof(BtreeKvPair));
    BnodeCacheMgr::init(160000, 160000);
    BnodeCacheMgr::get()->createFileBnodeCache(fr.file);
    b_mgr = new BnodeMgr();
    b_mgr->setFile(fr.file);
    btree = new BtreeV2();
    btree->setBMgr(b_mgr);

    for (i=0; i<n; i++) {
        kv_arr[i].key = malloc(9);
        kv_arr[i].value = malloc(9);
        sprintf((char *)kv_arr[i].key, "k%07d", (int)i*2 + 10);
        sprintf((char *)kv_arr[i].value, "v%07d", (int)i*2 + 10);
        kv_arr[i].keylen = kv_arr[i].valuelen = 8;
        btree->insert( kv_arr[i] );
    }

    TEST_CHK(btree->getNentry() == n);

    // flush dirty nodes
    btree->writeDirtyNodes();
    b_mgr->moveDirtyNodesToBcache();

    BtreeKvPair kv;
    kv.value = (void*)valuebuf;

    // retrieval check (clean node traversal)
    for (i=0; i<n; ++i) {
        kv.key = kv_arr[i].key;
        kv.keylen = kv_arr[i].keylen;
        br = btree->find(kv);
        TEST_CHK(br == BtreeV2Result::SUCCESS);
        TEST_CMP(kv_arr[i].value, kv.value, kv.valuelen);
    }

    // forward iteration
    bti = new BtreeIteratorV2(btree);
    i = 0;
    do {
        kvp_out = bti->getKvBT();
        if (!kvp_out.key) {
            break;
        }

        TEST_CMP(kvp_out.key, kv_arr[i].key, kvp_out.keylen);
        TEST_CMP(kvp_out.value, kv_arr[i].value, kvp_out.valuelen);
        i++;

        bti_ret = bti->nextBT();
    } while (bti_ret == BnodeIteratorResult::SUCCESS);
    TEST_CHK(i == n);
    delete bti;

    // reverse iteration
    bti = new BtreeIteratorV2(btree);
    bti_ret = bti->endBT();
    TEST_CHK(bti_ret == BnodeIteratorResult::SUCCESS);

    i = n;
    do {
        kvp_out = bti->getKvBT();
        if (!kvp_out.key) {
            break;
        }

        i--;

        TEST_CMP(kvp_out.key, kv_arr[i].key, kvp_out.keylen);
        TEST_CMP(kvp_out.value, kv_arr[i].value, kvp_out.valuelen);

        bti_ret = bti->prevBT();
    } while (bti_ret == BnodeIteratorResult::SUCCESS);
    TEST_CHK(i == 0);
    delete bti;

    // assigning start_key (seekGreater)
    i = n/2;
    bti = new BtreeIteratorV2(btree, kv_arr[i].key, 8);

    do {
        kvp_out = bti->getKvBT();
        if (!kvp_out.key) {
            break;
        }

        TEST_CMP(kvp_out.key, kv_arr[i].key, kvp_out.keylen);
        TEST_CMP(kvp_out.value, kv_arr[i].value, kvp_out.valuelen);

        i++;
        bti_ret = bti->nextBT();
    } while (bti_ret == BnodeIteratorResult::SUCCESS);
    TEST_CHK(i == n);
    delete bti;

    // Special CASE 1 of seekGreater to non-existent key
    i = n/2 - 2;
    sprintf(valuebuf, "k%07d", (int)i*2 + 11);
    bti = new BtreeIteratorV2(btree, valuebuf, 8);
    i++; // Actual key falls between i = 498 and i = 499

    do {
        kvp_out = bti->getKvBT();
        if (!kvp_out.key) {
            break;
        }

        TEST_CMP(kvp_out.key, kv_arr[i].key, kvp_out.keylen);
        TEST_CMP(kvp_out.value, kv_arr[i].value, kvp_out.valuelen);

        i++;
        bti_ret = bti->nextBT();
    } while (bti_ret == BnodeIteratorResult::SUCCESS);
    TEST_CHK(i == n);
    delete bti;

    // Special CASE 2 of seekGreater to non-existent key
    i = n/2 - 1;
    sprintf(valuebuf, "k%07d", (int)i*2 + 11);
    bti = new BtreeIteratorV2(btree, valuebuf, 8);
    i++; // Actual key falls between i = 499 and i = 500

    do {
        kvp_out = bti->getKvBT();
        if (!kvp_out.key) {
            break;
        }

        TEST_CMP(kvp_out.key, kv_arr[i].key, kvp_out.keylen);
        TEST_CMP(kvp_out.value, kv_arr[i].value, kvp_out.valuelen);

        i++;
        bti_ret = bti->nextBT();
    } while (bti_ret == BnodeIteratorResult::SUCCESS);
    TEST_CHK(i == n);
    delete bti;

    // Special CASE 3 of seekGreater to non-existent key
    i = 0;
    sprintf(valuebuf, "k%07d", (int)i*2 + 9);
    bti = new BtreeIteratorV2(btree, valuebuf, 8);
    // Actual key falls even before smallest key i = 0

    do {
        kvp_out = bti->getKvBT();
        if (!kvp_out.key) {
            break;
        }

        TEST_CMP(kvp_out.key, kv_arr[i].key, kvp_out.keylen);
        TEST_CMP(kvp_out.value, kv_arr[i].value, kvp_out.valuelen);

        i++;
        bti_ret = bti->nextBT();
    } while (bti_ret == BnodeIteratorResult::SUCCESS);
    TEST_CHK(i == n);
    delete bti;

    // seekSmaller
    bti = new BtreeIteratorV2(btree);

    i = n/2;
    bti->seekSmallerOrEqualBT(kv_arr[i].key, 8);

    do {
        kvp_out = bti->getKvBT();
        if (!kvp_out.key) {
            break;
        }

        TEST_CMP(kvp_out.key, kv_arr[i].key, kvp_out.keylen);
        TEST_CMP(kvp_out.value, kv_arr[i].value, kvp_out.valuelen);

        i++;

        bti_ret = bti->nextBT();
    } while (bti_ret == BnodeIteratorResult::SUCCESS);
    TEST_CHK(i == n);
    delete bti;

    delete btree;
    delete b_mgr;

    // Close the file before destroying BnodeCacheMgr instance below because
    // FileMgr::close accesses BnodeCacheMgr instance.
    FileMgr::close(fr.file, true, NULL, NULL);

    BnodeCacheMgr::destroyInstance();

    for (i=0; i<n; ++i) {
        free(kv_arr[i].key);
        free(kv_arr[i].value);
    }
    free(kv_arr);

    FileMgr::shutdown();

    TEST_RESULT("btree iterator test");
}

void bnode_split_test()
{
    TEST_INIT();

    Bnode *bnode = new Bnode();
    BnodeResult ret;
    size_t i;
    size_t n = 160;
    char keybuf[64], valuebuf[64];

    // add
    for (i=0; i<n; ++i) {
        sprintf(keybuf, "k%07d\n", (int)i);
        sprintf(valuebuf, "v%07d\n", (int)i*10);
        ret = bnode->addKv(keybuf, 8, valuebuf, 8, nullptr, true);
        TEST_CHK(ret == BnodeResult::SUCCESS);
    }
    TEST_CHK(bnode->getNentry() == n);

    // make this node clean.
    bnode->setCurOffset(0);

    std::list<Bnode *> new_nodes;
    Bnode *bnode_out;
    BnodeIterator *bit;
    BnodeIteratorResult bit_ret = BnodeIteratorResult::SUCCESS;
    BsaItem kvp_out;
    size_t nentry_total = 0;

    bnode->splitNode(1024, new_nodes);
    i = 0;

    auto entry = new_nodes.begin();
    while (entry != new_nodes.end()) {
        bnode_out = *entry;
        nentry_total += bnode_out->getNentry();

        bit = new BnodeIterator(bnode_out);
        do {
            kvp_out = bit->getKv();
            if ( kvp_out.isEmpty() ) {
                break;
            }

            sprintf(keybuf, "k%07d\n", (int)i);
            sprintf(valuebuf, "v%07d\n", (int)i*10);
            i++;

            TEST_CMP(keybuf, kvp_out.key, kvp_out.keylen);
            TEST_CMP(valuebuf, kvp_out.value, kvp_out.valuelen);

            bit_ret = bit->next();
        } while (bit_ret == BnodeIteratorResult::SUCCESS);
        delete bit;

        entry = new_nodes.erase(entry);
        delete bnode_out;
    }

    TEST_CHK(i == n);
    TEST_CHK(nentry_total == n);

    delete bnode;

    TEST_RESULT("bnode split test");
}

static int bnode_custom_cmp_func(void *key1, size_t keylen1,
                                 void *key2, size_t keylen2)
{
    // only compare the last digit (8th byte)
    char chr1 = *((char*)key1 + 7);
    char chr2 = *((char*)key2 + 7);
    if (chr1 < chr2) {
        return -1;
    } else if (chr1 > chr2) {
        return 1;
    } else {
        return 0;
    }
}

void bnode_custom_cmp_test()
{
    TEST_INIT();

    Bnode *bnode = new Bnode();
    BnodeIterator *bit;
    BnodeResult ret;
    BnodeIteratorResult bit_ret = BnodeIteratorResult::SUCCESS;
    size_t i, idx = 0;
    size_t n = 10;
    char keybuf[64], valuebuf[64];

    bnode->setCmpFunc(bnode_custom_cmp_func);

    // add test
    for (i=0; i<n; i++) {
        idx += 7;
        sprintf(keybuf, "k%07d\n", (int)idx);
        sprintf(valuebuf, "v%07d\n", (int)idx);
        ret = bnode->addKv(keybuf, 8, valuebuf, 8, nullptr, true);
        TEST_CHK(ret == BnodeResult::SUCCESS);
    }
    TEST_CHK(bnode->getNentry() == n);

    BsaItem kvp_out;

    // forward iteration
    bit = new BnodeIterator(bnode);
    i = 0;
    do {
        kvp_out = bit->getKv();
        if ( kvp_out.isEmpty() ) {
            break;
        }

        // get 8th character
        char last_chr = *((char*)kvp_out.key + 7);
        // it should be in an ascending order
        TEST_CHK( last_chr == '0'+(char)i );
        i++;

        bit_ret = bit->next();
    } while (bit_ret == BnodeIteratorResult::SUCCESS);
    TEST_CHK(i == n);
    delete bit;

    delete bnode;

    TEST_RESULT("bnode custom compare function test");
}

void bnode_clone_test()
{
    TEST_INIT();

    Bnode *bnode = new Bnode();
    BnodeResult ret;
    size_t i;
    size_t n = 10;
    char keybuf[64], valuebuf[64];

    // add kv pairs
    for (i=0; i<n; ++i) {
        sprintf(keybuf, "k%07d\n", (int)i);
        sprintf(valuebuf, "v%07d\n", (int)i*10);
        ret = bnode->addKv(keybuf, 8, valuebuf, 8, nullptr, true);
        TEST_CHK(ret == BnodeResult::SUCCESS);
    }
    TEST_CHK(bnode->getNentry() == n);

    // meta
    char metabuf[64];
    sprintf(metabuf, "meta_data");
    bnode->setMeta(metabuf, 9);

    // clone node
    Bnode *bnode_clone = bnode->cloneNode();

    // check
    size_t valuelen_out;
    void* value_out;
    Bnode *bnode_out;
    for (i=0; i<n; ++i) {
        sprintf(keybuf, "k%07d\n", (int)i);
        sprintf(valuebuf, "v%07d\n", (int)i*10);
        ret = bnode_clone->findKv(keybuf, 8, value_out, valuelen_out, bnode_out);
        TEST_CHK(ret == BnodeResult::SUCCESS);
        TEST_CMP(value_out, valuebuf, valuelen_out);
    }

    TEST_CMP(bnode_clone->getMeta(),
             bnode->getMeta(),
             bnode_clone->getMetaSize());

    delete bnode;
    delete bnode_clone;

    TEST_RESULT("bnode clone test");
}

void btree_basic_test()
{
    TEST_INIT();

    BtreeV2 *btree;
    BtreeV2Result br;
    BnodeMgr *b_mgr;
    FileMgrConfig config(4096, 3906, 1048576, 0, 0, FILEMGR_CREATE,
                         FDB_SEQTREE_NOT_USE, 0, 8, 0, FDB_ENCRYPTION_NONE,
                         0x00, 0, 0);
    filemgr_open_result fr;
    std::string fname("./btree_new_testfile");

    int r = system(SHELL_DEL" btree_new_testfile");
    (void)r;

    fr = FileMgr::open(fname, get_filemgr_ops(), &config, NULL);

    size_t i;
    size_t n = 70, n_add = 10;
    char keybuf[64], valuebuf[64], valuebuf_chk[64];

    std::vector<BtreeKvPair> kv_list(n);

    for (i=0; i<n; ++i) {
        kv_list[i].keylen = kv_list[i].valuelen = 8;
        kv_list[i].key = (void*)malloc( kv_list[i].keylen+1 );
        kv_list[i].value = (void*)malloc( kv_list[i].valuelen+1 );
        sprintf((char*)kv_list[i].key, "k%07d", (int)i*2 + 10);
        sprintf((char*)kv_list[i].value, "v%07d", (int)i*2 + 10);
    }

    BnodeCacheMgr::init(16000000, 16000000);
    BnodeCacheMgr::get()->createFileBnodeCache(fr.file);
    b_mgr = new BnodeMgr();
    b_mgr->setFile(fr.file);
    btree = new BtreeV2();
    btree->setBMgr(b_mgr);

    btree->insertMulti(kv_list);
    TEST_CHK(btree->getNentry() == n);


    BtreeKvPair kv;
    kv.value = (void*)valuebuf;

    // retrieval check
    for (i=0; i<n; ++i) {
        kv.key = kv_list[i].key;
        kv.keylen = kv_list[i].keylen;
        br = btree->find(kv);
        TEST_CHK(br == BtreeV2Result::SUCCESS);
        TEST_CMP(kv.value, kv_list[i].value, kv.valuelen);
    }

    std::vector<BtreeKvPair> kv_list_add(n_add*2);

    for (i=0; i<n_add; ++i) {
        kv_list_add[i].keylen = kv_list_add[i].valuelen = 8;
        kv_list_add[i].key = (void*)malloc( kv_list_add[i].keylen+1 );
        kv_list_add[i].value = (void*)malloc( kv_list_add[i].valuelen+1 );
        sprintf((char*)kv_list_add[i].key, "k%07d", (int)i*2 + 1);
        sprintf((char*)kv_list_add[i].value, "v%07d", (int)i*2 + 1);
    }
    for (i=n_add; i<n_add*2; ++i) {
        kv_list_add[i].keylen = kv_list_add[i].valuelen = 8;
        kv_list_add[i].key = (void*)malloc( kv_list_add[i].keylen+1 );
        kv_list_add[i].value = (void*)malloc( kv_list_add[i].valuelen+1 );
        sprintf((char*)kv_list_add[i].key, "k%07d", (int)i*2 + 91);
        sprintf((char*)kv_list_add[i].value, "v%07d", (int)i*2 + 91);
    }

    btree->insertMulti( kv_list_add );
    TEST_CHK(btree->getNentry() == n + n_add*2);

    // retrieval check
    for (i=0; i<n; ++i) {
        sprintf(keybuf, "k%07d", (int)i*2 + 10);
        sprintf(valuebuf_chk, "v%07d", (int)i*2 + 10);
        kv.key = keybuf;
        kv.keylen = 8;
        br = btree->find(kv);
        TEST_CHK(br == BtreeV2Result::SUCCESS);
        TEST_CMP(kv.value, valuebuf_chk, kv.valuelen);
    }
    for (i=0; i<n_add; ++i) {
        sprintf(keybuf, "k%07d", (int)i*2 + 1);
        sprintf(valuebuf_chk, "v%07d", (int)i*2 + 1);
        kv.key = keybuf;
        kv.keylen = 8;
        br = btree->find(kv);
        TEST_CHK(br == BtreeV2Result::SUCCESS);
        TEST_CMP(kv.value, valuebuf_chk, kv.valuelen);
    }
    for (i=n_add; i<n_add*2; ++i) {
        sprintf(keybuf, "k%07d", (int)i*2 + 91);
        sprintf(valuebuf_chk, "v%07d", (int)i*2 + 91);
        kv.key = keybuf;
        kv.keylen = 8;
        br = btree->find(kv);
        TEST_CHK(br == BtreeV2Result::SUCCESS);
        TEST_CMP(kv.value, valuebuf_chk, kv.valuelen);
    }

    // flush dirty nodes
    btree->writeDirtyNodes();
    b_mgr->moveDirtyNodesToBcache();

    for (i=0; i<n; ++i) {
        free(kv_list[i].key);
        free(kv_list[i].value);
    }
    for (i=0; i<n_add*2; ++i) {
        free(kv_list_add[i].key);
        free(kv_list_add[i].value);
    }

    delete btree;
    delete b_mgr;

    FileMgr::close(fr.file, true, NULL, NULL);

    BnodeCacheMgr::destroyInstance();

    FileMgr::shutdown();

    TEST_RESULT("btree basic test");
}

void btree_remove_test()
{
    TEST_INIT();

    BtreeV2 *btree;
    BtreeV2Result br;
    BnodeMgr *b_mgr;
    FileMgrConfig config(4096, 3906, 1048576, 0, 0, FILEMGR_CREATE,
                         FDB_SEQTREE_NOT_USE, 0, 8, 0, FDB_ENCRYPTION_NONE,
                         0x00, 0, 0);
    filemgr_open_result fr;
    std::string fname("./btree_new_testfile");

    int r = system(SHELL_DEL" btree_new_testfile");
    (void)r;

    fr = FileMgr::open(fname, get_filemgr_ops(), &config, NULL);

    size_t i, j;
    size_t n = 70;
    char keybuf[64], valuebuf[64], valuebuf_chk[64];;

    std::vector<BtreeKvPair> kv_list(n);

    for (i=0; i<n; ++i) {
        kv_list[i].keylen = kv_list[i].valuelen = 8;
        kv_list[i].key = (void*)malloc( kv_list[i].keylen+1 );
        kv_list[i].value = (void*)malloc( kv_list[i].valuelen+1 );
        sprintf((char*)kv_list[i].key, "k%07d", (int)i);
        sprintf((char*)kv_list[i].value, "v%07d", (int)i);
    }

    BnodeCacheMgr::init(16000000, 16000000);
    BnodeCacheMgr::get()->createFileBnodeCache(fr.file);
    b_mgr = new BnodeMgr();
    b_mgr->setFile(fr.file);
    btree = new BtreeV2();
    btree->setBMgr(b_mgr);

    btree->insertMulti( kv_list );
    TEST_CHK(btree->getNentry() == n);

    BtreeKvPair kv;
    kv.value = valuebuf;

    for (i=0; i<n; ++i) {
        sprintf(keybuf, "k%07d", (int)i);
        kv.key = keybuf;
        kv.keylen = 8;
        br = btree->remove(kv);
        TEST_CHK(br == BtreeV2Result::SUCCESS);

        // retrieval check
        for (j=0; j<n; ++j) {
            sprintf(keybuf, "k%07d", (int)j);
            sprintf(valuebuf_chk, "v%07d", (int)j);
            kv.key = keybuf;
            kv.keylen = 8;
            br = btree->find(kv);
            if (j <= i) {
                TEST_CHK(br != BtreeV2Result::SUCCESS);
            } else {
                TEST_CHK(br == BtreeV2Result::SUCCESS);
                TEST_CMP(kv.value, kv_list[j].value, kv.valuelen);
            }
        }
    }

    // flush dirty nodes
    btree->writeDirtyNodes();
    b_mgr->moveDirtyNodesToBcache();

    for (i=0; i<n; ++i) {
        free(kv_list[i].key);
        free(kv_list[i].value);
    }

    delete btree;
    delete b_mgr;

    FileMgr::close(fr.file, true, NULL, NULL);

    BnodeCacheMgr::destroyInstance();

    FileMgr::shutdown();

    TEST_RESULT("btree remove test");
}

void btree_multiple_block_test()
{
    TEST_INIT();

    BtreeV2 *btree;
    BtreeV2Result br;
    BnodeMgr *b_mgr;
    FileMgrConfig config(4096, 3906, 1048576, 0, 0, FILEMGR_CREATE,
                         FDB_SEQTREE_NOT_USE, 0, 8, 0, FDB_ENCRYPTION_NONE,
                         0x00, 0, 0);
    filemgr_open_result fr;
    std::string fname("./btree_new_testfile");

    int r = system(SHELL_DEL" btree_new_testfile");
    (void)r;

    fr = FileMgr::open(fname, get_filemgr_ops(), &config, NULL);

    size_t i;
    size_t n = 1000;
    char keybuf[64], valuebuf[64], valuebuf_chk[64];

    std::vector<BtreeKvPair> kv_list(n);

    for (i=0; i<n; ++i) {
        kv_list[i].keylen = kv_list[i].valuelen = 8;
        kv_list[i].key = (void*)malloc( kv_list[i].keylen+1 );
        kv_list[i].value = (void*)malloc( kv_list[i].valuelen+1 );
        sprintf((char*)kv_list[i].key, "k%07d", (int)i*2 + 10);
        sprintf((char*)kv_list[i].value, "v%07d", (int)i*2 + 10);
    }

    BnodeCacheMgr::init(16000000, 16000000);
    BnodeCacheMgr::get()->createFileBnodeCache(fr.file);
    b_mgr = new BnodeMgr();
    b_mgr->setFile(fr.file);
    btree = new BtreeV2();
    btree->setBMgr(b_mgr);

    btree->insertMulti( kv_list );
    TEST_CHK(btree->getNentry() == n);

    BtreeKvPair kv;
    kv.value = (void*)valuebuf_chk;

    // retrieval check (dirty node traversal)
    for (i=0; i<n; ++i) {
        kv.key = kv_list[i].key;
        kv.keylen = kv_list[i].keylen;
        br = btree->find(kv);
        b_mgr->releaseCleanNodes();
        TEST_CHK(br == BtreeV2Result::SUCCESS);
        TEST_CMP(kv.value, kv_list[i].value, kv.valuelen);
    }

    // flush dirty nodes
    btree->writeDirtyNodes();
    b_mgr->moveDirtyNodesToBcache();

    // retrieval check (clean node traversal)
    for (i=0; i<n; ++i) {
        kv.key = kv_list[i].key;
        kv.keylen = kv_list[i].keylen;
        br = btree->find(kv);
        b_mgr->releaseCleanNodes();
        TEST_CHK(br == BtreeV2Result::SUCCESS);
        TEST_CMP(kv.value, kv_list[i].value, kv.valuelen);
    }

    // update some key-value pairs
    for (i=0; i<n; i+=100) {
        sprintf(keybuf, "k%07d", (int)i*2 + 10);
        sprintf(valuebuf, "X%07d", (int)i*2 + 10);
        kv.key = keybuf;
        kv.value = valuebuf;
        kv.keylen = kv.valuelen = 8;
        btree->insert( kv );
    }

    // retrieval check (dirty node traversal)
    for (i=0; i<n; ++i) {
        sprintf(keybuf, "k%07d", (int)i*2 + 10);
        if (i % 100 == 0) {
            sprintf(valuebuf, "X%07d", (int)i*2 + 10);
        } else {
            sprintf(valuebuf, "v%07d", (int)i*2 + 10);
        }
        kv.key = keybuf;
        kv.keylen = 8;
        br = btree->find(kv);
        b_mgr->releaseCleanNodes();
        TEST_CHK(br == BtreeV2Result::SUCCESS);
        TEST_CMP(kv.value, valuebuf, kv.valuelen);
    }

    // flush dirty nodes
    btree->writeDirtyNodes();
    b_mgr->moveDirtyNodesToBcache();

    // retrieval check (clean node traversal)
    for (i=0; i<n; ++i) {
        sprintf(keybuf, "k%07d", (int)i*2 + 10);
        if (i % 100 == 0) {
            sprintf(valuebuf, "X%07d", (int)i*2 + 10);
        } else {
            sprintf(valuebuf, "v%07d", (int)i*2 + 10);
        }
        kv.key = keybuf;
        kv.keylen = 8;
        br = btree->find(kv);
        b_mgr->releaseCleanNodes();
        TEST_CHK(br == BtreeV2Result::SUCCESS);
        TEST_CMP(kv.value, valuebuf, kv.valuelen);
    }

    for (i=0; i<n; ++i) {
        free(kv_list[i].key);
        free(kv_list[i].value);
    }

    delete btree;
    delete b_mgr;

    FileMgr::close(fr.file, true, NULL, NULL);

    BnodeCacheMgr::destroyInstance();

    FileMgr::shutdown();

    TEST_RESULT("btree multiple block test");
}

void btree_metadata_test()
{
    TEST_INIT();

    BtreeV2 *btree;
    BtreeV2Result br;
    BnodeMgr *b_mgr;
    FileMgrConfig config(4096, 3906, 1048576, 0, 0, FILEMGR_CREATE,
                         FDB_SEQTREE_NOT_USE, 0, 8, 0, FDB_ENCRYPTION_NONE,
                         0x00, 0, 0);
    filemgr_open_result fr;
    std::string fname("./btree_new_testfile");

    int r = system(SHELL_DEL" btree_new_testfile");
    (void)r;

    fr = FileMgr::open(fname, get_filemgr_ops(), &config, NULL);

    size_t i;
    size_t n = 70, n_remove = 40;
    uint32_t metasize_ret;
    char keybuf[64], valuebuf[64];
    char metabuf[64], metabuf_chk[64];
    BtreeV2Meta meta, meta_chk;
    meta.ctx = metabuf;
    meta_chk.ctx = metabuf_chk;

    BnodeCacheMgr::init(16000000, 16000000);
    BnodeCacheMgr::get()->createFileBnodeCache(fr.file);
    b_mgr = new BnodeMgr();
    b_mgr->setFile(fr.file);
    btree = new BtreeV2();
    btree->setBMgr(b_mgr);

    BtreeKvPair kv;

    for (i=0; i<n; i++) {
        sprintf(keybuf, "k%07d", (int)i);
        sprintf(valuebuf, "v%07d", (int)i);
        kv.key = keybuf;
        kv.value = valuebuf;
        kv.keylen = kv.valuelen = 8;
        btree->insert( kv );

        if (i == 10) {
            // when tree height is 1, put some meta data
            sprintf(metabuf, "this_is_meta_data");

            meta.size = strlen(metabuf);
            btree->updateMeta( meta );

            // check
            metasize_ret = btree->getMetaSize();
            TEST_CHK(metasize_ret == strlen(metabuf));

            br = btree->readMeta(meta_chk);
            TEST_CHK(br == BtreeV2Result::SUCCESS);
            TEST_CMP(meta_chk.ctx, meta.ctx, meta_chk.size);
        }
    }

    // now tree height is grown up to 2
    // check meta data again
    metasize_ret = btree->getMetaSize();
    TEST_CHK(metasize_ret == strlen(metabuf));

    br = btree->readMeta(meta_chk);
    TEST_CHK(br == BtreeV2Result::SUCCESS);
    TEST_CMP(meta_chk.ctx, meta.ctx, meta_chk.size);

    // flush dirty nodes
    btree->writeDirtyNodes();
    b_mgr->moveDirtyNodesToBcache();

    // read meta data from clean root node
    br = btree->readMeta(meta_chk);
    TEST_CHK(br == BtreeV2Result::SUCCESS);
    TEST_CMP(meta_chk.ctx, meta.ctx, meta_chk.size);

    // remove entries to make the tree height shrink
    for (i=0; i<n_remove; ++i) {
        sprintf(keybuf, "k%07d", (int)i);
        kv.key = keybuf;
        kv.keylen = 8;
        br = btree->remove(kv);
        TEST_CHK(br == BtreeV2Result::SUCCESS);
    }

    // read meta data after shrinking
    br = btree->readMeta(meta_chk);
    TEST_CHK(br == BtreeV2Result::SUCCESS);
    TEST_CMP(meta_chk.ctx, meta.ctx, meta_chk.size);

    // flush dirty nodes
    btree->writeDirtyNodes();
    b_mgr->moveDirtyNodesToBcache();

    // read meta data from clean root node
    br = btree->readMeta(meta_chk);
    TEST_CHK(br == BtreeV2Result::SUCCESS);
    TEST_CMP(meta_chk.ctx, meta.ctx, meta_chk.size);

    delete btree;
    delete b_mgr;

    FileMgr::close(fr.file, true, NULL, NULL);

    BnodeCacheMgr::destroyInstance();

    FileMgr::shutdown();

    TEST_RESULT("btree meta data test");
}

void btree_smaller_greater_test()
{
    TEST_INIT();

    BtreeV2 *btree;
    BtreeV2Result br;
    BnodeMgr *b_mgr;

    FileMgrConfig config(4096, 3906, 1048576, 0, 0, FILEMGR_CREATE,
                         FDB_SEQTREE_NOT_USE, 0, 8, 0, FDB_ENCRYPTION_NONE,
                         0x00, 0, 0);
    filemgr_open_result fr;
    std::string fname("./btree_new_testfile");

    int r = system(SHELL_DEL" btree_new_testfile");
    (void)r;

    fr = FileMgr::open(fname, get_filemgr_ops(), &config, NULL);

    size_t i;
    size_t n = 10;
    char keybuf[64], valuebuf[64], keybuf_chk[64];

    BnodeCacheMgr::init(16000000, 16000000);
    BnodeCacheMgr::get()->createFileBnodeCache(fr.file);
    b_mgr = new BnodeMgr();
    b_mgr->setFile(fr.file);
    btree = new BtreeV2();
    btree->setBMgr(b_mgr);

    BtreeKvPair kv;

    for (i=0; i<n; i++) {
        // aaa.., bbb.., ccc.., ...
        memset(keybuf, 'a'+i, 8);
        // AAA.., BBB.., CCC.., ...
        memset(valuebuf, 'A'+i, 8);
        kv.key = keybuf;
        kv.value = valuebuf;
        kv.keylen = kv.valuelen = 8;
        btree->insert( kv );
    }

    // flush dirty nodes
    btree->writeDirtyNodes();
    b_mgr->moveDirtyNodesToBcache();

    for (i=0; i<n; i++) {
        // a, b, c, ...
        memset(keybuf, 'a'+i, 1);

        // query key: a
        // smaller: NOT_FOUND, greater: aaa...

        // query key: b
        // smaller: aaa...   , greater: bbb...

        // query key: c
        // smaller: bbb...   , greater: ccc...

        kv = BtreeKvPair(keybuf, 1, valuebuf, 0);
        br = btree->findSmallerOrEqual( kv );
        if ( i == 0 ) {
            TEST_CHK(br != BtreeV2Result::SUCCESS);
        } else {
            memset(keybuf_chk, 'a'+(i-1), 8);
            TEST_CMP(kv.key, keybuf_chk, kv.keylen);
        }

        memset(keybuf, 'a'+i, 1);
        kv = BtreeKvPair(keybuf, 1, valuebuf, 0);
        br = btree->findGreaterOrEqual( kv );
        TEST_CHK(br == BtreeV2Result::SUCCESS);
        memset(keybuf_chk, 'a'+i, 8);
        TEST_CMP(kv.key, keybuf_chk, kv.keylen);
    }

    delete btree;
    delete b_mgr;

    fr.file->commit_FileMgr(false, nullptr);
    FileMgr::close(fr.file, true, NULL, NULL);

    BnodeCacheMgr::destroyInstance();

    FileMgr::shutdown();

    TEST_RESULT("btree smaller greater test");
}

void btree_smaller_greater_edge_case_test()
{
    TEST_INIT();

    BtreeV2 *btree;
    BtreeV2Result br;
    BnodeMgr *b_mgr;

    FileMgrConfig config(4096, 3906, 1048576, 0, 0, FILEMGR_CREATE,
                         FDB_SEQTREE_NOT_USE, 0, 8, 0, FDB_ENCRYPTION_NONE,
                         0x00, 0, 0);
    filemgr_open_result fr;
    std::string fname("./btree_new_testfile");

    int r = system(SHELL_DEL" btree_new_testfile");
    (void)r;

    fr = FileMgr::open(fname, get_filemgr_ops(), &config, NULL);

    size_t i;
    size_t n = 100;
    char keybuf[64], valuebuf[64], valuebuf_chk[64];

    BnodeCacheMgr::init(16000000, 16000000);
    BnodeCacheMgr::get()->createFileBnodeCache(fr.file);
    b_mgr = new BnodeMgr();
    b_mgr->setFile(fr.file);
    btree = new BtreeV2();
    btree->setBMgr(b_mgr);

    BtreeKvPair kv;

    for (i=0; i<n; i++) {
        // key structure
        // k0000100
        // k0000200
        // k0000300
        // ...
        sprintf(keybuf, "k%07d", (int)i * 100);
        sprintf(valuebuf, "v%07d", (int)i * 100);
        kv.key = keybuf;
        kv.value = valuebuf;
        kv.keylen = kv.valuelen = 8;
        btree->insert(kv);
    }

    // flush dirty nodes
    btree->writeDirtyNodes();
    b_mgr->moveDirtyNodesToBcache();
    BnodeCacheMgr::get()->flush(fr.file);

    // greater check
    for (i=0; i<n; ++i) {
        sprintf(keybuf, "k%07d", (int)i * 100 + 50);
        sprintf(valuebuf_chk, "v%07d", (int)(i+1) * 100);
        kv.key = keybuf;
        kv.keylen = 8;
        kv.value = valuebuf;
        br = btree->findGreaterOrEqual(kv);

        if (i == n-1) {
            // out of the range => must fail
            TEST_CHK(br != BtreeV2Result::SUCCESS);
        } else {
            TEST_CHK(br == BtreeV2Result::SUCCESS);
            TEST_CMP(kv.value, valuebuf_chk, kv.valuelen);
        }
    }

    // smaller check
    for (i=0; i<n; ++i) {
        if (i==0) {
            // make a key smaller than the smallest key
            sprintf(keybuf, "aaaaaaaa");
        } else {
            sprintf(keybuf, "k%07d", (int)i * 100 - 50);
            sprintf(valuebuf_chk, "v%07d", (int)(i-1) * 100);
        }
        kv.key = keybuf;
        kv.keylen = 8;
        kv.value = valuebuf;
        br = btree->findSmallerOrEqual(kv);

        if (i == 0) {
            // out of the range => must fail
            TEST_CHK(br != BtreeV2Result::SUCCESS);
        } else {
            TEST_CHK(br == BtreeV2Result::SUCCESS);
            TEST_CMP(kv.value, valuebuf_chk, kv.valuelen);
        }
    }

    delete btree;
    delete b_mgr;

    fr.file->commit_FileMgr(false, nullptr);
    FileMgr::close(fr.file, true, NULL, NULL);

    BnodeCacheMgr::destroyInstance();

    FileMgr::shutdown();

    TEST_RESULT("btree smaller greater edge case test");
}


static int btree_custom_cmp_func(void *key1, size_t keylen1,
                                 void *key2, size_t keylen2)
{
    // skip first 5 bytes, and only compare the last 3 digit (6~8th bytes)
    uint8_t* key1_suffix = static_cast<uint8_t*>(key1) + 5;
    uint8_t* key2_suffix = static_cast<uint8_t*>(key2) + 5;
    return memcmp(key1_suffix, key2_suffix, 3);
}

void btree_custom_cmp_test()
{
    TEST_INIT();

    BtreeV2 *btree;
    BtreeV2Result br;
    BnodeMgr *b_mgr;

    FileMgrConfig config(4096, 3906, 1048576, 0, 0, FILEMGR_CREATE,
                         FDB_SEQTREE_NOT_USE, 0, 8, 0, FDB_ENCRYPTION_NONE,
                         0x00, 0, 0);
    filemgr_open_result fr;
    std::string fname("./btree_new_testfile");

    int r = system(SHELL_DEL" btree_new_testfile");
    (void)r;

    fr = FileMgr::open(fname, get_filemgr_ops(), &config, NULL);

    size_t i;
    size_t n = 100;
    char keybuf[64], valuebuf[64], valuebuf_chk[64];

    BnodeCacheMgr::init(16000000, 16000000);
    BnodeCacheMgr::get()->createFileBnodeCache(fr.file);
    b_mgr = new BnodeMgr();
    b_mgr->setFile(fr.file);
    btree = new BtreeV2();
    btree->setBMgr(b_mgr);
    btree->setCmpFunc(btree_custom_cmp_func);

    BtreeKvPair kv;

    for (i=0; i<n; i++) {
        // key structure
        // KK100000
        // KK099001
        // KK098002
        // ...
        sprintf(keybuf, "KK%03d%03d", (int)(n-i), (int)i);
        sprintf(valuebuf, "VV%06d", (int)i);
        kv.key = keybuf;
        kv.value = valuebuf;
        kv.keylen = kv.valuelen = 8;
        btree->insert(kv);
    }

    // retrieval check (dirty)
    for (i=0; i<n; ++i) {
        sprintf(keybuf, "KK%03d%03d", (int)(n-i), (int)i);
        sprintf(valuebuf_chk, "VV%06d", (int)i);
        kv.key = keybuf;
        kv.keylen = 8;
        kv.value = valuebuf;
        br = btree->find(kv);
        TEST_CHK(br == BtreeV2Result::SUCCESS);
        TEST_CMP(kv.value, valuebuf_chk, kv.valuelen);
    }

    // flush dirty nodes
    btree->writeDirtyNodes();
    b_mgr->moveDirtyNodesToBcache();
    BnodeCacheMgr::get()->flush(fr.file);

    // retrieval check (clean)
    for (i=0; i<n; ++i) {
        sprintf(keybuf, "KK%03d%03d", (int)(n-i), (int)i);
        sprintf(valuebuf_chk, "VV%06d", (int)i);
        kv.key = keybuf;
        kv.keylen = 8;
        kv.value = valuebuf;
        br = btree->find(kv);
        TEST_CHK(br == BtreeV2Result::SUCCESS);
        TEST_CMP(kv.value, valuebuf_chk, kv.valuelen);
    }

    delete btree;
    delete b_mgr;

    fr.file->commit_FileMgr(false, nullptr);
    FileMgr::close(fr.file, true, NULL, NULL);

    BnodeCacheMgr::destroyInstance();

    FileMgr::shutdown();

    TEST_RESULT("btree custom compare function test");
}

void bsa_seq_insert_test()
{
    TEST_INIT();

    BsArray bsa;
    BsaItem query, item;
    size_t i, idx;
    size_t n = 20;
    char keybuf[64], valuebuf[64];

    for (i=0; i<n; ++i) {
        // 1, 3, 5, ...
        idx = 1 + i*2;
        sprintf(keybuf, "k%07d", (int)idx);
        sprintf(valuebuf, "v%07d", (int)idx);
        query = BsaItem(keybuf, 8, valuebuf, 8);
        bsa.insert( query );
    }

    // smaller than smallest key test
    sprintf(keybuf, "k%07d", (int)0);
    query = BsaItem(keybuf, 8);
    item = bsa.find( query );
    TEST_CHK( item.isEmpty() );

    // greater than greatest key test
    sprintf(keybuf, "k%07d", (int)n*20);
    query = BsaItem(keybuf, 8);
    item = bsa.find( query );
    TEST_CHK( item.isEmpty() );

    for (i=0; i<n; ++i) {
        // 1, 3, 5, ...
        idx = 1 + i*2;
        sprintf(keybuf, "k%07d", (int)idx);
        sprintf(valuebuf, "v%07d", (int)idx);
        query = BsaItem(keybuf, 8);
        item = bsa.find( query );
        TEST_CHK( !item.isEmpty() );
        TEST_CMP(item.value, valuebuf, item.valuelen);
    }

    TEST_RESULT("Bs Array sequential insert test");
}

void bsa_rand_insert_test()
{
    TEST_INIT();

    BsArray bsa;
    BsaItem query, item;
    size_t i, idx;
    size_t n = 20;
    char keybuf[64], valuebuf[64];

    idx = 0;
    for (i=0; i<n; ++i) {
        // simple random number generator using a prime number
        // 7, 14, 1, 8, 15 ...
        idx = (idx + 7) % n;
        sprintf(keybuf, "k%07d", (int)idx);
        sprintf(valuebuf, "v%07d", (int)idx);
        query = BsaItem(keybuf, 8, valuebuf, 8);
        bsa.insert( query );
    }

    for (i=0; i<n; ++i) {
        idx = (idx + 7) % n;
        sprintf(keybuf, "k%07d", (int)idx);
        sprintf(valuebuf, "v%07d", (int)idx);
        query = BsaItem(keybuf, 8);
        item = bsa.find( query );
        TEST_CHK( !item.isEmpty() );
        TEST_CMP(item.value, valuebuf, item.valuelen);
    }

    // update to use longer value..
    idx = 0;
    for (i=0; i<n; ++i) {
        // simple random number generator using a prime number
        // 7, 14, 1, 8, 15 ...
        idx = (idx + 7) % n;
        sprintf(keybuf, "k%07d", (int)idx);
        sprintf(valuebuf, "VV%07d", (int)idx);
        query = BsaItem(keybuf, 8, valuebuf, 9);
        bsa.insert( query );
    }

    // remove
    for (i=2; i<n; i+=2) {
        idx = i;
        sprintf(keybuf, "k%07d", (int)idx);
        sprintf(valuebuf, "v%07d", (int)idx);
        query = BsaItem(keybuf, 8);
        item = bsa.remove( query );
        TEST_CHK(!item.isEmpty());
    }

    TEST_RESULT("Bs Array random insert test");
}

void bsa_insert_ptr_test()
{
    TEST_INIT();

    BsArray bsa;
    BsaItem query, item;
    size_t i, idx;
    size_t n = 20;
    char keybuf[64], valuebuf[64];

    for (i=0; i<n; ++i) {
        idx = i;
        sprintf(keybuf, "k%07d", (int)idx);
        sprintf(valuebuf, "VV%07d", (int)idx);
        query = BsaItem(keybuf, 8, valuebuf, 9);
        bsa.insert( query );
    }

    for (i=0; i<n; ++i) {
        idx = i;
        sprintf(keybuf, "k%07d", (int)idx);
        sprintf(valuebuf, "VV%07d", (int)idx);
        query = BsaItem(keybuf, 8);
        item = bsa.find( query );
        TEST_CHK( !item.isEmpty() );
        TEST_CMP(item.value, valuebuf, item.valuelen);
    }

    // update odd using pointer
    int temp_array[100];
    for (i=1; i<n; i+=2) {
        idx = i;
        temp_array[idx] = i;
        sprintf(keybuf, "k%07d", (int)idx);
        query = BsaItem(keybuf, 8, &temp_array[idx]);
        bsa.insert( query );
    }

    // check
    for (i=0; i<n; ++i) {
        idx = i;
        sprintf(keybuf, "k%07d", (int)idx);
        sprintf(valuebuf, "VV%07d", (int)idx);
        query = BsaItem(keybuf, 8);
        item = bsa.find( query );
        TEST_CHK( !item.isEmpty() );
        if (i % 2 == 1) {
            // should be pointer
            TEST_CHK( item.isValueChildPtr );
            int *item_value = (int*)item.value;
            TEST_CHK(*item_value == temp_array[i]);
        } else {
            // should be string
            TEST_CHK( !item.isValueChildPtr );
            TEST_CMP(item.value, valuebuf, item.valuelen);
        }
    }

    TEST_RESULT("Bs Array insert pointer test");
}

void bsa_iteration_test()
{
    TEST_INIT();

    BsArray bsa;
    BsaItem query;
    size_t i, idx;
    size_t n = 20;
    char keybuf[64], valuebuf[64];

    idx = 0;
    for (i=0; i<n; ++i) {
        // simple random number generator using a prime number
        // 7, 14, 1, 8, 15 ...
        idx = (idx + 7) % n;
        sprintf(keybuf, "k%07d", (int)idx);
        sprintf(valuebuf, "v%07d", (int)idx);
        query = BsaItem(keybuf, 8, valuebuf, 8);
        bsa.insert( query );
    }

    size_t count = 0;
    query = bsa.first();
    while (!query.isEmpty()) {
        sprintf(keybuf, "k%07d", (int)count);
        sprintf(valuebuf, "v%07d", (int)count);
        TEST_CMP(query.key, keybuf, query.keylen);
        query = bsa.next(query);
        count++;
    }
    TEST_CHK(count == n);

    query = bsa.last();
    count = n;
    while (!query.isEmpty()) {
        count--;
        sprintf(keybuf, "k%07d", (int)count);
        sprintf(valuebuf, "v%07d", (int)count);
        TEST_CMP(query.key, keybuf, query.keylen);
        query = bsa.prev(query);
    }
    TEST_CHK(count == 0);

    TEST_RESULT("Bs Array iteration test");
}

void bsa_base_offset_test()
{
    TEST_INIT();

    BsArray bsa;
    BsaItem query, item;
    size_t i, idx;
    size_t n = 20;
    char keybuf[64], valuebuf[64];

    for (i=0; i<n; ++i) {
        idx = i;
        sprintf(keybuf, "k%07d", (int)idx);
        sprintf(valuebuf, "v%07d", (int)idx);
        query = BsaItem(keybuf, 8, valuebuf, 8);
        bsa.insert( query );
    }

    // check
    for (i=0; i<n; ++i) {
        idx = i;
        sprintf(keybuf, "k%07d", (int)idx);
        sprintf(valuebuf, "v%07d", (int)idx);
        query = BsaItem(keybuf, 8);
        item = bsa.find( query );
        TEST_CHK( !item.isEmpty() );
        TEST_CMP(item.value, valuebuf, item.valuelen);
    }

    // adjust
    bsa.adjustBaseOffset(40);
    memset(bsa.getDataArray(), 'x', 40);

    // check
    for (i=0; i<n; ++i) {
        idx = i;
        sprintf(keybuf, "k%07d", (int)idx);
        sprintf(valuebuf, "v%07d", (int)idx);
        query = BsaItem(keybuf, 8);
        item = bsa.find( query );
        TEST_CHK( !item.isEmpty() );
        TEST_CMP(item.value, valuebuf, item.valuelen);
    }

    // update
    for (i=0; i<n; ++i) {
        idx = i;
        sprintf(keybuf, "k%07d", (int)idx);
        sprintf(valuebuf, "VV%07d", (int)idx);
        query = BsaItem(keybuf, 8, valuebuf, 9);
        bsa.insert( query );
    }

    // check
    for (i=0; i<n; ++i) {
        idx = i;
        sprintf(keybuf, "k%07d", (int)idx);
        sprintf(valuebuf, "VV%07d", (int)idx);
        query = BsaItem(keybuf, 8);
        item = bsa.find( query );
        TEST_CHK( !item.isEmpty() );
        TEST_CMP(item.value, valuebuf, item.valuelen);
    }

    // adjust
    bsa.adjustBaseOffset(20);

    // check
    for (i=0; i<n; ++i) {
        idx = i;
        sprintf(keybuf, "k%07d", (int)idx);
        sprintf(valuebuf, "VV%07d", (int)idx);
        query = BsaItem(keybuf, 8);
        item = bsa.find( query );
        TEST_CHK( !item.isEmpty() );
        TEST_CMP(item.value, valuebuf, item.valuelen);
    }

    // remove
    for (i=2; i<n; i+=2) {
        idx = i;
        sprintf(keybuf, "k%07d", (int)idx);
        query = BsaItem(keybuf, 8);
        item = bsa.remove( query );
        TEST_CHK(!item.isEmpty());
    }

    TEST_RESULT("Bs Array base offset test");
}

void bnodemgr_basic_test()
{
    TEST_INIT();

    int r = system(SHELL_DEL" bnodemgr_testfile");
    (void)r;

    Bnode *bnode = new Bnode();
    BnodeMgr *bMgr = new BnodeMgr();;
    BnodeResult ret;
    size_t i;
    size_t n = 100;
    char keybuf[64], valuebuf[64];

    uint64_t threshold = 200000;
    uint64_t flush_limit = 102400;

    BnodeCacheMgr::init(threshold, flush_limit);

    FileMgr *file;
    FileMgrConfig config(4096, 48, 1048576, 0, 0,
                         FILEMGR_CREATE, FDB_SEQTREE_NOT_USE, 0, 8,
                         DEFAULT_NUM_BCACHE_PARTITIONS,
                         FDB_ENCRYPTION_NONE, 0x55, 0, 0);
    std::string fname("./bnodemgr_testfile");
    filemgr_open_result result = FileMgr::open(fname,
                                               get_filemgr_ops(),
                                               &config, nullptr);
    file = result.file;
    TEST_CHK(file != nullptr);

    BnodeCacheMgr::get()->createFileBnodeCache(file);
    bMgr->setFile(file);

    // register the node to bnodemgr
    bMgr->addDirtyNode(bnode);

    // add test
    for (i=0; i<n; ++i) {
        sprintf(keybuf, "k%07d\n", (int)i);
        sprintf(valuebuf, "v%07d\n", (int)i*10);
        ret = bnode->addKv(keybuf, 8, valuebuf, 8, nullptr, true);
        TEST_CHK(ret == BnodeResult::SUCCESS);
    }
    TEST_CHK(bnode->getNentry() == n);

    // meta
    char metabuf[64];
    sprintf(metabuf, "meta_data");
    bnode->setMeta(metabuf, 9);

    // find test
    size_t valuelen_out;
    void* value_out;
    Bnode *bnode_out;
    for (i=0; i<n; ++i) {
        sprintf(keybuf, "k%07d\n", (int)i);
        sprintf(valuebuf, "v%07d\n", (int)i*10);
        ret = bnode->findKv(keybuf, 8, value_out, valuelen_out, bnode_out);
        TEST_CHK(ret == BnodeResult::SUCCESS);
        TEST_CMP(value_out, valuebuf, valuelen_out);
    }

    // assign offset, and flush
    uint64_t node_offset = bMgr->assignDirtyNodeOffset(bnode);
    bnode->setCurOffset(node_offset);
    bMgr->moveDirtyNodesToBcache();
    BnodeCacheMgr::get()->flush(file);

    // read test
    Bnode *bnode_read = bMgr->readNode(node_offset);
    for (i=0; i<n; ++i) {
        sprintf(keybuf, "k%07d\n", (int)i);
        sprintf(valuebuf, "v%07d\n", (int)i*10);
        ret = bnode_read->findKv(keybuf, 8, value_out, valuelen_out, bnode_out);
        TEST_CHK(ret == BnodeResult::SUCCESS);
        TEST_CMP(value_out, valuebuf, valuelen_out);
    }

    bMgr->releaseCleanNodes();
    delete bMgr;

    FileMgr::close(file, true, NULL, NULL);

    BnodeCacheMgr::destroyInstance();

    FileMgr::shutdown();

    TEST_RESULT("bnodemgr basic test");
}

void hbtriev2_basic_test()
{
    // test case for most common insertion cases
    // (1 and 2-2 described in HBTrie::_insertV2()).
    TEST_INIT();

    HBTrie *hbtrie;
    hbtrie_result hr;
    BnodeMgr *b_mgr;
    FileMgrConfig config(4096, 3906, 1048576, 0, 0, FILEMGR_CREATE,
                         FDB_SEQTREE_NOT_USE, 0, 8, 0, FDB_ENCRYPTION_NONE,
                         0x00, 0, 0);
    filemgr_open_result fr;
    std::string fname("./hbtrie_new_testfile");

    int r = system(SHELL_DEL" hbtrie_new_testfile");
    (void)r;

    fr = FileMgr::open(fname, get_filemgr_ops(), &config, NULL);
    // set file version to 003
    fr.file->setVersion(FILEMGR_MAGIC_003);

    size_t i;
    size_t n = 10;
    uint64_t offset;
    char keybuf[64];

    BnodeCacheMgr::init(16000000, 16000000);
    BnodeCacheMgr::get()->createFileBnodeCache(fr.file);
    b_mgr = new BnodeMgr();
    b_mgr->setFile(fr.file);

    BtreeNodeAddr init_root;
    hbtrie = new HBTrie(8, 4096, init_root, b_mgr, fr.file);

    memset(keybuf, '_', sizeof(keybuf));
    for (i=0; i<n; ++i) {
        // key structure:
        // ________k00001111
        // ________k00002222
        // ^       ^       ^
        // chunk0  chunk1  chunk2
        //
        // Due to suffix optimization,
        // third (chunk2) B+tree will not be created, and
        // second (chunk1) B+tree will store 9-byte suffix.

        sprintf(keybuf+8, "k%08d", (int)i*1111);
        offset = i*100;
        offset = _endian_encode(offset);
        hr = hbtrie->insert(keybuf, 17, &offset, nullptr);
        TEST_CHK(hr == HBTRIE_RESULT_SUCCESS);
    }

    // retrieval check
    for (i=0; i<n; ++i) {
        sprintf(keybuf+8, "k%08d", (int)i*1111);
        offset = 0;
        hr = hbtrie->find(keybuf, 17, &offset);
        TEST_CHK(hr == HBTRIE_RESULT_SUCCESS);
        offset = _endian_decode(offset);
        TEST_CHK(offset == i*100);
    }

    // retrieval check using non-existing key
    for (i=0; i<n; ++i) {
        // ________k0000111x
        // ________k0000222x
        // ^       ^       ^
        // chunk0  chunk1  chunk2
        sprintf(keybuf+8, "k%07dx", (int)i*111);
        offset = 0;
        hr = hbtrie->find(keybuf, 17, &offset);
        TEST_CHK(hr != HBTRIE_RESULT_SUCCESS);
    }

    delete hbtrie;
    delete b_mgr;

    FileMgr::close(fr.file, true, NULL, NULL);

    BnodeCacheMgr::destroyInstance();

    FileMgr::shutdown();

    TEST_RESULT("hb+trie V2 basic test");
}

void hbtriev2_substring_test()
{
    // test case for 2-1 described in HBTrie::_insertV2()).
    TEST_INIT();

    HBTrie *hbtrie;
    hbtrie_result hr;
    BnodeMgr *b_mgr;
    FileMgrConfig config(4096, 3906, 1048576, 0, 0, FILEMGR_CREATE,
                         FDB_SEQTREE_NOT_USE, 0, 8, 0, FDB_ENCRYPTION_NONE,
                         0x00, 0, 0);
    filemgr_open_result fr;
    std::string fname("./hbtrie_new_testfile");

    int r = system(SHELL_DEL" hbtrie_new_testfile");
    (void)r;

    fr = FileMgr::open(fname, get_filemgr_ops(), &config, NULL);
    // set file version to 003
    fr.file->setVersion(FILEMGR_MAGIC_003);

    uint64_t offset;
    char keybuf[64];

    BnodeCacheMgr::init(16000000, 16000000);
    BnodeCacheMgr::get()->createFileBnodeCache(fr.file);
    b_mgr = new BnodeMgr();
    b_mgr->setFile(fr.file);

    BtreeNodeAddr init_root;
    hbtrie = new HBTrie(8, 4096, init_root, b_mgr, fr.file);

    memset(keybuf, '_', sizeof(keybuf));

    sprintf(keybuf+8, "c");
    offset = 1;
    offset = _endian_encode(offset);
    hr = hbtrie->insert(keybuf, 9, &offset, nullptr);
    TEST_CHK(hr == HBTRIE_RESULT_SUCCESS);

    // insert two keys, where one key is a sub-string of the others.
    sprintf(keybuf+8, "aaaaaaaa");
    offset = 2;
    offset = _endian_encode(offset);
    hr = hbtrie->insert(keybuf, 16, &offset, nullptr);
    TEST_CHK(hr == HBTRIE_RESULT_SUCCESS);

    sprintf(keybuf+8, "aaaaaaaabbb");
    offset = 3;
    offset = _endian_encode(offset);
    hr = hbtrie->insert(keybuf, 19, &offset, nullptr);
    TEST_CHK(hr == HBTRIE_RESULT_SUCCESS);

    // do the same task in an opposite order.
    sprintf(keybuf+8, "bbbbbbbbccc");
    offset = 4;
    offset = _endian_encode(offset);
    hr = hbtrie->insert(keybuf, 19, &offset, nullptr);
    TEST_CHK(hr == HBTRIE_RESULT_SUCCESS);

    sprintf(keybuf+8, "bbbbbbbb");
    offset = 5;
    offset = _endian_encode(offset);
    hr = hbtrie->insert(keybuf, 16, &offset, nullptr);
    TEST_CHK(hr == HBTRIE_RESULT_SUCCESS);

    // retrieval check
    sprintf(keybuf+8, "c");
    hr = hbtrie->find(keybuf, 9, &offset);
    TEST_CHK(hr == HBTRIE_RESULT_SUCCESS);
    offset = _endian_encode(offset);
    TEST_CHK(offset == 1);

    sprintf(keybuf+8, "aaaaaaaa");
    hr = hbtrie->find(keybuf, 16, &offset);
    TEST_CHK(hr == HBTRIE_RESULT_SUCCESS);
    offset = _endian_encode(offset);
    TEST_CHK(offset == 2);

    sprintf(keybuf+8, "aaaaaaaabbb");
    hr = hbtrie->find(keybuf, 19, &offset);
    TEST_CHK(hr == HBTRIE_RESULT_SUCCESS);
    offset = _endian_encode(offset);
    TEST_CHK(offset == 3);

    sprintf(keybuf+8, "bbbbbbbbccc");
    hr = hbtrie->find(keybuf, 19, &offset);
    TEST_CHK(hr == HBTRIE_RESULT_SUCCESS);
    offset = _endian_encode(offset);
    TEST_CHK(offset == 4);

    sprintf(keybuf+8, "bbbbbbbb");
    hr = hbtrie->find(keybuf, 16, &offset);
    TEST_CHK(hr == HBTRIE_RESULT_SUCCESS);
    offset = _endian_encode(offset);
    TEST_CHK(offset == 5);

    delete hbtrie;
    delete b_mgr;

    FileMgr::close(fr.file, true, NULL, NULL);

    BnodeCacheMgr::destroyInstance();

    FileMgr::shutdown();

    TEST_RESULT("hb+trie V2 sub string test");
}

void hbtriev2_remove_test()
{
    TEST_INIT();

    HBTrie *hbtrie;
    hbtrie_result hr;
    BnodeMgr *b_mgr;
    FileMgrConfig config(4096, 3906, 1048576, 0, 0, FILEMGR_CREATE,
                         FDB_SEQTREE_NOT_USE, 0, 8, 0, FDB_ENCRYPTION_NONE,
                         0x00, 0, 0);
    filemgr_open_result fr;
    std::string fname("./hbtrie_new_testfile");

    int r = system(SHELL_DEL" hbtrie_new_testfile");
    (void)r;

    fr = FileMgr::open(fname, get_filemgr_ops(), &config, NULL);
    // set file version to 003
    fr.file->setVersion(FILEMGR_MAGIC_003);

    size_t i;
    size_t n = 10;
    uint64_t offset;
    char keybuf[64];

    BnodeCacheMgr::init(16000000, 16000000);
    BnodeCacheMgr::get()->createFileBnodeCache(fr.file);
    b_mgr = new BnodeMgr();
    b_mgr->setFile(fr.file);

    BtreeNodeAddr init_root;
    hbtrie = new HBTrie(8, 4096, init_root, b_mgr, fr.file);

    memset(keybuf, '_', sizeof(keybuf));

    // key-value:
    // ________          1
    // ________k0000000  0
    // ________k0000001  100
    // ________k0000002  200
    // ^       ^
    // chunk0  chunk1

    offset = 1;
    offset = _endian_encode(offset);
    hr = hbtrie->insert(keybuf, 8, &offset, nullptr);
    TEST_CHK(hr == HBTRIE_RESULT_SUCCESS);

    for (i=0; i<n; ++i) {
        sprintf(keybuf+8, "k%07d", (int)i);
        offset = i*100;
        offset = _endian_encode(offset);
        hr = hbtrie->insert(keybuf, 16, &offset, nullptr);
        TEST_CHK(hr == HBTRIE_RESULT_SUCCESS);
    }

    // retrieval check
    offset = 0;
    hr = hbtrie->find(keybuf, 8, &offset);
    TEST_CHK(hr == HBTRIE_RESULT_SUCCESS);
    offset = _endian_decode(offset);
    TEST_CHK(offset == 1);
    for (i=0; i<n; ++i) {
        sprintf(keybuf+8, "k%07d", (int)i);
        offset = 0;
        hr = hbtrie->find(keybuf, 16, &offset);
        TEST_CHK(hr == HBTRIE_RESULT_SUCCESS);
        offset = _endian_decode(offset);
        TEST_CHK(offset == i*100);
    }

    // remove substring
    hr = hbtrie->remove(keybuf, 8);
    TEST_CHK(hr == HBTRIE_RESULT_SUCCESS);
    hr = hbtrie->find(keybuf, 8, &offset);
    TEST_CHK(hr != HBTRIE_RESULT_SUCCESS);

    // remove even number keys
    for (i=0; i<n; i+=2) {
        sprintf(keybuf+8, "k%07d", (int)i);
        hr = hbtrie->remove(keybuf, 16);
        TEST_CHK(hr == HBTRIE_RESULT_SUCCESS);
    }

    // retrieval check again
    for (i=0; i<n; ++i) {
        sprintf(keybuf+8, "k%07d", (int)i);
        offset = 0;
        hr = hbtrie->find(keybuf, 16, &offset);
        if (i%2 == 1) {
            // odd number should exist
            TEST_CHK(hr == HBTRIE_RESULT_SUCCESS);
            offset = _endian_decode(offset);
            TEST_CHK(offset == i*100);
        } else {
            // even number should not exist
            TEST_CHK(hr != HBTRIE_RESULT_SUCCESS);
        }
    }

    delete hbtrie;
    delete b_mgr;

    FileMgr::close(fr.file, true, NULL, NULL);

    BnodeCacheMgr::destroyInstance();

    FileMgr::shutdown();

    TEST_RESULT("hb+trie V2 remove test");
}

void hbtriev2_insertion_case3_test()
{
    TEST_INIT();

    HBTrie *hbtrie;
    hbtrie_result hr;
    BnodeMgr *b_mgr;
    FileMgrConfig config(4096, 3906, 1048576, 0, 0, FILEMGR_CREATE,
                         FDB_SEQTREE_NOT_USE, 0, 8, 0, FDB_ENCRYPTION_NONE,
                         0x00, 0, 0);
    filemgr_open_result fr;
    std::string fname("./hbtrie_new_testfile");

    int r = system(SHELL_DEL" hbtrie_new_testfile");
    (void)r;

    fr = FileMgr::open(fname, get_filemgr_ops(), &config, NULL);
    // set file version to 003
    fr.file->setVersion(FILEMGR_MAGIC_003);

    size_t i;
    size_t n = 10;
    uint64_t offset;
    char keybuf[64];

    BnodeCacheMgr::init(16000000, 16000000);
    BnodeCacheMgr::get()->createFileBnodeCache(fr.file);
    b_mgr = new BnodeMgr();
    b_mgr->setFile(fr.file);

    BtreeNodeAddr init_root;
    hbtrie = new HBTrie(8, 4096, init_root, b_mgr, fr.file);

    memset(keybuf, '_', sizeof(keybuf));
    for (i=0; i<n; ++i) {
        // key structure:
        // ________k00000000
        // ________k00000005
        // ________k00000010
        // ________k00000015
        // ^       ^       ^
        // chunk0  chunk1  chunk2

        sprintf(keybuf+8, "k%08d", (int)i*5);
        offset = i*100;
        offset = _endian_encode(offset);
        hr = hbtrie->insert(keybuf, 17, &offset, nullptr);
        TEST_CHK(hr == HBTRIE_RESULT_SUCCESS);
    }

    // retrieval check
    for (i=0; i<n; ++i) {
        sprintf(keybuf+8, "k%08d", (int)i*5);
        offset = 0;
        hr = hbtrie->find(keybuf, 17, &offset);
        TEST_CHK(hr == HBTRIE_RESULT_SUCCESS);
        offset = _endian_decode(offset);
        TEST_CHK(offset == i*100);
    }

    hbtrie->writeDirtyNodes();
    b_mgr->moveDirtyNodesToBcache();
    BnodeCacheMgr::get()->flush(fr.file);

    // retrieval check (clean nodes)
    for (i=0; i<n; ++i) {
        sprintf(keybuf+8, "k%08d", (int)i*5);
        offset = 0;
        hr = hbtrie->find(keybuf, 17, &offset);
        TEST_CHK(hr == HBTRIE_RESULT_SUCCESS);
        offset = _endian_decode(offset);
        TEST_CHK(offset == i*100);
    }

    b_mgr->releaseCleanNodes();

    delete hbtrie;
    delete b_mgr;

    FileMgr::close(fr.file, true, NULL, NULL);

    BnodeCacheMgr::destroyInstance();

    FileMgr::shutdown();

    TEST_RESULT("hb+trie V2 insertion case 3 test");
}

void hbtriev2_partial_update_test()
{
    TEST_INIT();

    HBTrie *hbtrie;
    hbtrie_result hr;
    BnodeMgr *b_mgr;
    FileMgrConfig config(4096, 3906, 1048576, 0, 0, FILEMGR_CREATE,
                         FDB_SEQTREE_NOT_USE, 0, 8, 0, FDB_ENCRYPTION_NONE,
                         0x00, 0, 0);
    filemgr_open_result fr;
    std::string fname("./hbtrie_new_testfile");

    int r = system(SHELL_DEL" hbtrie_new_testfile");
    (void)r;

    fr = FileMgr::open(fname, get_filemgr_ops(), &config, NULL);
    // set file version to 003
    fr.file->setVersion(FILEMGR_MAGIC_003);

    size_t i;
    size_t n = 200;
    uint64_t offset;
    char keybuf[64];

    BnodeCacheMgr::init(16000000, 16000000);
    BnodeCacheMgr::get()->createFileBnodeCache(fr.file);
    b_mgr = new BnodeMgr();
    b_mgr->setFile(fr.file);

    BtreeNodeAddr init_root;
    hbtrie = new HBTrie(8, 4096, init_root, b_mgr, fr.file);

    memset(keybuf, '_', sizeof(keybuf));
    for (i=0; i<n; ++i) {
        // key structure:
        // ________k00000000
        // ________k00000001
        //         ...
        // ________k00000009
        // ________k00000010
        // ________k00000011
        // ^       ^       ^
        // chunk0  chunk1  chunk2

        sprintf(keybuf+8, "k%08d", (int)i);
        offset = i*100;
        offset = _endian_encode(offset);
        hr = hbtrie->insert(keybuf, 17, &offset, nullptr);
        TEST_CHK(hr == HBTRIE_RESULT_SUCCESS);
    }

    // retrieval check
    for (i=0; i<n; ++i) {
        sprintf(keybuf+8, "k%08d", (int)i);
        offset = 0;
        hr = hbtrie->find(keybuf, 17, &offset);
        TEST_CHK(hr == HBTRIE_RESULT_SUCCESS);
        offset = _endian_decode(offset);
        TEST_CHK(offset == i*100);
    }

    hbtrie->writeDirtyNodes();
    b_mgr->moveDirtyNodesToBcache();
    BnodeCacheMgr::get()->flush(fr.file);

    // retrieval check (clean nodes)
    for (i=0; i<n; ++i) {
        sprintf(keybuf+8, "k%08d", (int)i);
        offset = 0;
        hr = hbtrie->find(keybuf, 17, &offset);
        TEST_CHK(hr == HBTRIE_RESULT_SUCCESS);
        offset = _endian_decode(offset);
        TEST_CHK(offset == i*100);
    }

    // update key 55, 75, 95, 115, 135, 155.
    for (i=55; i<=155; i+=20) {
        sprintf(keybuf+8, "k%08d", (int)i);
        // change offset
        offset = i*100 + 1;
        offset = _endian_encode(offset);
        hr = hbtrie->insert(keybuf, 17, &offset, nullptr);
        TEST_CHK(hr == HBTRIE_RESULT_SUCCESS);
    }

    // retrieval check (dirty)
    for (i=0; i<n; ++i) {
        sprintf(keybuf+8, "k%08d", (int)i);
        offset = 0;
        hr = hbtrie->find(keybuf, 17, &offset);
        TEST_CHK(hr == HBTRIE_RESULT_SUCCESS);
        offset = _endian_decode(offset);
        if (55<=i && i<=155 &&
            (i-55) % 20 == 0) {
            TEST_CHK(offset == i*100 + 1);
        } else {
            TEST_CHK(offset == i*100);
        }
    }

    hbtrie->writeDirtyNodes();
    b_mgr->moveDirtyNodesToBcache();
    BnodeCacheMgr::get()->flush(fr.file);

    // retrieval check (clean)
    for (i=0; i<n; ++i) {
        sprintf(keybuf+8, "k%08d", (int)i);
        offset = 0;
        hr = hbtrie->find(keybuf, 17, &offset);
        TEST_CHK(hr == HBTRIE_RESULT_SUCCESS);
        offset = _endian_decode(offset);
        if (55<=i && i<=155 &&
            (i-55) % 20 == 0) {
            TEST_CHK(offset == i*100 + 1);
        } else {
            TEST_CHK(offset == i*100);
        }
    }

    delete hbtrie;
    delete b_mgr;

    FileMgr::close(fr.file, true, NULL, NULL);

    BnodeCacheMgr::destroyInstance();

    FileMgr::shutdown();

    TEST_RESULT("hb+trie V2 partial update test");
}


btree_new_cmp_func* hbtriev2_cmp_func_callback(HBTrie *hbtrie,
                                               uint64_t kvs_id,
                                               void *aux)
{
    (void)hbtrie;
    (void)aux;
    // ID 0: normal lexicographical order
    // ID 1: custom function (btree_custom_cmp_func)
    if (kvs_id == 1) {
        return btree_custom_cmp_func;
    }
    return nullptr;
}

void hbtriev2_custom_cmp_test()
{
    TEST_INIT();

    HBTrie *hbtrie;
    hbtrie_result hr;
    BnodeMgr *b_mgr;
    FileMgrConfig config(4096, 3906, 1048576, 0, 0, FILEMGR_CREATE,
                         FDB_SEQTREE_NOT_USE, 0, 8, 0, FDB_ENCRYPTION_NONE,
                         0x00, 0, 0);
    filemgr_open_result fr;
    std::string fname("./hbtrie_new_testfile");

    int r = system(SHELL_DEL" hbtrie_new_testfile");
    (void)r;

    fr = FileMgr::open(fname, get_filemgr_ops(), &config, NULL);
    // set file version to 003
    fr.file->setVersion(FILEMGR_MAGIC_003);

    size_t i;
    size_t n = 100;
    uint64_t offset;
    uint64_t kvs_id;
    char keybuf[64];

    BnodeCacheMgr::init(16000000, 16000000);
    BnodeCacheMgr::get()->createFileBnodeCache(fr.file);
    b_mgr = new BnodeMgr();
    b_mgr->setFile(fr.file);

    BtreeNodeAddr init_root;
    hbtrie = new HBTrie(8, 4096, init_root, b_mgr, fr.file);
    hbtrie->setCmpFuncCB(hbtriev2_cmp_func_callback);

    for (kvs_id = 0; kvs_id <= 1; ++kvs_id) {
        uint64_t encoded = _endian_encode(kvs_id);
        memcpy(keybuf, &encoded, sizeof(encoded));
        for (i=0; i<n; ++i) {
            // key structure
            // __KVS_ID_KK100000
            // __KVS_ID_KK099001
            // __KVS_ID_KK098002
            // ^        ^
            // chunk0   chunk1
            // ...
            sprintf(keybuf+8, "KK%03d%03d", (int)(n-i), (int)i);
            offset = i*100;
            offset = _endian_encode(offset);
            hr = hbtrie->insert(keybuf, 16, &offset, nullptr);
            TEST_CHK(hr == HBTRIE_RESULT_SUCCESS);
        }
    }

    // retrieval check
    for (kvs_id = 0; kvs_id <= 1; ++kvs_id) {
        uint64_t encoded = _endian_encode(kvs_id);
        memcpy(keybuf, &encoded, sizeof(encoded));
        for (i=0; i<n; ++i) {
            sprintf(keybuf+8, "KK%03d%03d", (int)(n-i), (int)i);
            offset = 0;
            hr = hbtrie->find(keybuf, 16, &offset);
            TEST_CHK(hr == HBTRIE_RESULT_SUCCESS);
            offset = _endian_decode(offset);
            TEST_CHK(offset == i*100);
        }
    }

    hbtrie->writeDirtyNodes();
    b_mgr->moveDirtyNodesToBcache();
    BnodeCacheMgr::get()->flush(fr.file);

    // retrieval check (clean nodes)
    for (kvs_id = 0; kvs_id <= 1; ++kvs_id) {
        uint64_t encoded = _endian_encode(kvs_id);
        memcpy(keybuf, &encoded, sizeof(encoded));
        for (i=0; i<n; ++i) {
            sprintf(keybuf+8, "KK%03d%03d", (int)(n-i), (int)i);
            offset = 0;
            hr = hbtrie->find(keybuf, 16, &offset);
            TEST_CHK(hr == HBTRIE_RESULT_SUCCESS);
            offset = _endian_decode(offset);
            TEST_CHK(offset == i*100);
        }
    }

    delete hbtrie;
    delete b_mgr;

    FileMgr::close(fr.file, true, NULL, NULL);

    BnodeCacheMgr::destroyInstance();

    FileMgr::shutdown();

    TEST_RESULT("hb+trie V2 custom compare function test");
}

void hbtriev2_variable_length_value_test()
{
    TEST_INIT();

    HBTrie *hbtrie;
    hbtrie_result hr;
    BnodeMgr *b_mgr;
    FileMgrConfig config(4096, 3906, 1048576, 0, 0, FILEMGR_CREATE,
                         FDB_SEQTREE_NOT_USE, 0, 8, 0, FDB_ENCRYPTION_NONE,
                         0x00, 0, 0);
    filemgr_open_result fr;
    std::string fname("./hbtrie_new_testfile");

    int r = system(SHELL_DEL" hbtrie_new_testfile");
    (void)r;

    fr = FileMgr::open(fname, get_filemgr_ops(), &config, NULL);
    // set file version to 003
    fr.file->setVersion(FILEMGR_MAGIC_003);

    size_t i;
    size_t n = 10;
    char keybuf[64], valuebuf[64], valuebuf_chk[64];
    char oldvaluebuf[64];

    BnodeCacheMgr::init(16000000, 16000000);
    BnodeCacheMgr::get()->createFileBnodeCache(fr.file);
    b_mgr = new BnodeMgr();
    b_mgr->setFile(fr.file);

    BtreeNodeAddr init_root;
    hbtrie = new HBTrie(8, 4096, init_root, b_mgr, fr.file);

    memset(keybuf, '_', sizeof(keybuf));
    memset(valuebuf, 'x', 32);
    for (i=0; i<n; ++i) {
        // key structure:
        // ________k00000000
        // ________k00000005
        // ________k00000010
        // ________k00000015
        // ^       ^       ^
        // chunk0  chunk1  chunk2

        sprintf(keybuf+8, "k%08d", (int)i*5);
        sprintf(valuebuf+24, "V%07d", (int)i);
        hr = hbtrie->insert_vlen(keybuf, 17, valuebuf, 32, nullptr, nullptr);
        TEST_CHK(hr == HBTRIE_RESULT_SUCCESS);
    }

    // retrieval check
    size_t valuelen;
    for (i=0; i<n; ++i) {
        sprintf(keybuf+8, "k%08d", (int)i*5);
        sprintf(valuebuf+24, "V%07d", (int)i);
        hr = hbtrie->find_vlen(keybuf, 17, valuebuf_chk, &valuelen);
        TEST_CHK(hr == HBTRIE_RESULT_SUCCESS);
        TEST_CMP(valuebuf_chk, valuebuf, valuelen);
    }

    hbtrie->writeDirtyNodes();
    b_mgr->moveDirtyNodesToBcache();
    BnodeCacheMgr::get()->flush(fr.file);

    // retrieval check (clean nodes)
    for (i=0; i<n; ++i) {
        sprintf(keybuf+8, "k%08d", (int)i*5);
        sprintf(valuebuf+24, "V%07d", (int)i);
        hr = hbtrie->find_vlen(keybuf, 17, valuebuf_chk, &valuelen);
        TEST_CHK(hr == HBTRIE_RESULT_SUCCESS);
        TEST_CHK(valuelen == 32);
        TEST_CMP(valuebuf_chk, valuebuf, valuelen);
    }

    b_mgr->releaseCleanNodes();

    // old value check
    size_t oldvalue_size;
    memset(valuebuf_chk, 'x', 32);
    for (i=0; i<n; ++i) {
        sprintf(keybuf+8, "k%08d", (int)i*5);
        sprintf(valuebuf+24, "Z%07d", (int)i);
        sprintf(valuebuf_chk+24, "V%07d", (int)i);
        hr = hbtrie->insert_vlen(keybuf, 17, valuebuf, 32, oldvaluebuf, &oldvalue_size);
        TEST_CHK(hr == HBTRIE_RESULT_SUCCESS);
        TEST_CHK(oldvalue_size == 32);
        TEST_CMP(oldvaluebuf, valuebuf_chk, oldvalue_size);
    }

    hbtrie->writeDirtyNodes();
    b_mgr->moveDirtyNodesToBcache();
    BnodeCacheMgr::get()->flush(fr.file);

    // retrieval check (clean nodes)
    for (i=0; i<n; ++i) {
        sprintf(keybuf+8, "k%08d", (int)i*5);
        sprintf(valuebuf+24, "Z%07d", (int)i);
        hr = hbtrie->find_vlen(keybuf, 17, valuebuf_chk, &valuelen);
        TEST_CHK(hr == HBTRIE_RESULT_SUCCESS);
        TEST_CHK(valuelen == 32);
        TEST_CMP(valuebuf_chk, valuebuf, valuelen);
    }

    // remove check
    for (i=0; i<n; i+=2) {
        sprintf(keybuf+8, "k%08d", (int)i*5);
        sprintf(valuebuf+24, "Z%07d", (int)i);
        hr = hbtrie->remove_vlen(keybuf, 17, oldvaluebuf, &oldvalue_size);
        TEST_CHK(hr == HBTRIE_RESULT_SUCCESS);
        TEST_CHK(oldvalue_size == 32);
        TEST_CMP(oldvaluebuf, valuebuf, oldvalue_size);
    }

    hbtrie->writeDirtyNodes();
    b_mgr->moveDirtyNodesToBcache();
    BnodeCacheMgr::get()->flush(fr.file);

    // retrieval check (clean nodes)
    for (i=0; i<n; ++i) {
        sprintf(keybuf+8, "k%08d", (int)i*5);
        sprintf(valuebuf+24, "Z%07d", (int)i);
        hr = hbtrie->find_vlen(keybuf, 17, valuebuf_chk, &valuelen);
        if (i%2 == 0) {
            TEST_CHK(hr != HBTRIE_RESULT_SUCCESS);
        } else {
            TEST_CHK(hr == HBTRIE_RESULT_SUCCESS);
            TEST_CHK(valuelen == 32);
            TEST_CMP(valuebuf_chk, valuebuf, valuelen);
        }
    }

    b_mgr->releaseCleanNodes();

    delete hbtrie;
    delete b_mgr;

    FileMgr::close(fr.file, true, NULL, NULL);

    BnodeCacheMgr::destroyInstance();

    FileMgr::shutdown();

    TEST_RESULT("hb+trie V2 variable length value test");
}

int main()
{
    bnode_basic_test();
    bnode_iterator_test();
    bnode_split_test();
    bnode_custom_cmp_test();
    bnode_clone_test();

    bsa_seq_insert_test();
    bsa_rand_insert_test();
    bsa_insert_ptr_test();
    bsa_iteration_test();
    bsa_base_offset_test();

    bnodemgr_basic_test();

    btree_basic_test();
    btree_remove_test();
    btree_iterator_test();
    btree_multiple_block_test();
    btree_metadata_test();
    btree_smaller_greater_test();
    btree_smaller_greater_edge_case_test();
    btree_custom_cmp_test();

    hbtriev2_basic_test();
    hbtriev2_substring_test();
    hbtriev2_remove_test();
    hbtriev2_insertion_case3_test();
    hbtriev2_partial_update_test();
    hbtriev2_custom_cmp_test();
    hbtriev2_variable_length_value_test();
    return 0;
}


