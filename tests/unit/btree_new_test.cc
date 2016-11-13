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
    void *key2, size_t keylen2, void *aux)
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
    FileMgrConfig config(4096, 0, 0, 0, FILEMGR_CREATE,
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

    BnodeCacheMgr* bcache = new BnodeCacheMgr(16000000,
                                              16000000);
    FileBnodeCache* fcache = bcache->createFileBnodeCache(fr.file);
    b_mgr = new BnodeMgr();
    b_mgr->setFile(fr.file, bcache);
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

    bcache->freeFileBnodeCache(fcache, true);
    delete bcache;

    FileMgr::close(fr.file, true, NULL, NULL);
    FileMgr::shutdown();

    TEST_RESULT("btree basic test");
}

void btree_remove_test()
{
    TEST_INIT();

    BtreeV2 *btree;
    BtreeV2Result br;
    BnodeMgr *b_mgr;
    FileMgrConfig config(4096, 0, 0, 0, FILEMGR_CREATE,
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

    BnodeCacheMgr* bcache = new BnodeCacheMgr(16000000,
                                              16000000);
    FileBnodeCache* fcache = bcache->createFileBnodeCache(fr.file);
    b_mgr = new BnodeMgr();
    b_mgr->setFile(fr.file, bcache);
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

    for (i=0; i<n; ++i) {
        free(kv_list[i].key);
        free(kv_list[i].value);
    }

    delete btree;
    delete b_mgr;

    bcache->freeFileBnodeCache(fcache, true);
    delete bcache;

    FileMgr::close(fr.file, true, NULL, NULL);
    FileMgr::shutdown();

    TEST_RESULT("btree remove test");
}

void btree_multiple_block_test()
{
    TEST_INIT();

    BtreeV2 *btree;
    BtreeV2Result br;
    BnodeMgr *b_mgr;
    FileMgrConfig config(4096, 0, 0, 0, FILEMGR_CREATE,
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

    BnodeCacheMgr* bcache = new BnodeCacheMgr(16000000,
                                              16000000);
    FileBnodeCache* fcache = bcache->createFileBnodeCache(fr.file);
    b_mgr = new BnodeMgr();
    b_mgr->setFile(fr.file, bcache);
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

    bcache->freeFileBnodeCache(fcache, true);
    delete bcache;

    FileMgr::close(fr.file, true, NULL, NULL);
    FileMgr::shutdown();

    TEST_RESULT("btree multiple block test");
}

void btree_metadata_test()
{
    TEST_INIT();

    BtreeV2 *btree;
    BtreeV2Result br;
    BnodeMgr *b_mgr;
    FileMgrConfig config(4096, 0, 0, 0, FILEMGR_CREATE,
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

    BnodeCacheMgr* bcache = new BnodeCacheMgr(16000000,
                                              16000000);
    FileBnodeCache* fcache = bcache->createFileBnodeCache(fr.file);
    b_mgr = new BnodeMgr();
    b_mgr->setFile(fr.file, bcache);
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

    // read meta data from clean root node
    br = btree->readMeta(meta_chk);
    TEST_CHK(br == BtreeV2Result::SUCCESS);
    TEST_CMP(meta_chk.ctx, meta.ctx, meta_chk.size);

    delete btree;
    delete b_mgr;

    bcache->freeFileBnodeCache(fcache, true);
    delete bcache;

    FileMgr::close(fr.file, true, NULL, NULL);
    FileMgr::shutdown();

    TEST_RESULT("btree meta data test");
}

void btree_smaller_greater_test()
{
    TEST_INIT();

    BtreeV2 *btree;
    BtreeV2Result br;
    BnodeMgr *b_mgr;
    FileMgrConfig config(4096, 0, 0, 0, FILEMGR_CREATE,
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

    BnodeCacheMgr* bcache = new BnodeCacheMgr(16000000,
                                              16000000);
    FileBnodeCache* fcache = bcache->createFileBnodeCache(fr.file);
    b_mgr = new BnodeMgr();
    b_mgr->setFile(fr.file, bcache);
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
        memset(keybuf_chk, 'a'+i, 8);
        TEST_CMP(kv.key, keybuf_chk, kv.keylen);
    }

    delete btree;
    delete b_mgr;

    bcache->freeFileBnodeCache(fcache, true);
    delete bcache;

    fr.file->commit_FileMgr(false, nullptr);

    FileMgr::close(fr.file, true, NULL, NULL);
    FileMgr::shutdown();

    TEST_RESULT("btree smaller greater test");
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

    BnodeCacheMgr* bcache = new BnodeCacheMgr(threshold,
                                              flush_limit);

    FileMgr *file;
    FileMgrConfig config(4096, 1024, 0, 0, FILEMGR_CREATE,
                         FDB_SEQTREE_NOT_USE, 0, 8,
                         DEFAULT_NUM_BCACHE_PARTITIONS,
                         FDB_ENCRYPTION_NONE, 0x55, 0, 0);
    std::string fname("./bnodemgr_testfile");
    filemgr_open_result result = FileMgr::open(fname,
                                               get_filemgr_ops(),
                                               &config, nullptr);
    file = result.file;
    TEST_CHK(file != nullptr);

    FileBnodeCache* fcache = bcache->createFileBnodeCache(file);
    bMgr->setFile(file, bcache);

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
    bMgr->flushDirtyNodes();

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

    bcache->freeFileBnodeCache(fcache, true);
    delete bcache;

    FileMgr::close(file, true, NULL, NULL);
    FileMgr::shutdown();

    TEST_RESULT("bnodemgr basic test");
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
    btree_multiple_block_test();
    btree_metadata_test();
    btree_smaller_greater_test();
    return 0;
}


