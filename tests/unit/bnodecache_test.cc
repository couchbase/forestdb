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

#include "bnode.h"
#include "bnodecache.h"
#include "filemgr.h"
#include "filemgr_ops.h"
#include "test.h"

static uint64_t curBid(BLK_NOT_FOUND);
static uint64_t curOffset(0);

uint64_t assignDirtyNodeOffset(FileMgr* file, Bnode *bnode) {
    size_t blocksize = file->getBlockSize();
    size_t blocksize_avail = blocksize - sizeof(IndexBlkMeta);
    size_t nodesize = bnode->getNodeSize();
    uint64_t offset;

    if (curBid == BLK_NOT_FOUND ||
        !file->isWritable( curBid ) ||
        curOffset + 4 > blocksize_avail ) {

        curBid = file->alloc_FileMgr(nullptr);
        curOffset = 0;
    }

    offset = curBid * blocksize + curOffset;
    size_t room = blocksize_avail - curOffset;
    if ( room >= nodesize ) {
        // we don't need to allocate more blocks
        curOffset += nodesize;
        bnode->addBidList(curBid);
        return offset;
    }

    // otherwise .. allocate more blocks.
    size_t n_blocks;
    size_t remaining_size;

    remaining_size = nodesize - room;
    bnode->addBidList(curBid);

    // e.g.) when blocksize_avail = 1000,
    // remaining_size 1 ~ 1000: 1 block
    // remaining_size 1001 ~ 2000: 2 blocks ...
    n_blocks = ( (remaining_size-1) / blocksize_avail ) + 1;

    size_t i;
    for (i=0; i<n_blocks; ++i) {
        curBid = file->alloc_FileMgr(nullptr);
        bnode->addBidList(curBid);
    }
    curOffset = remaining_size % blocksize_avail;

    return offset;
}

void basic_read_write_test() {
    TEST_INIT();

    int r = system(SHELL_DEL" bnodecache_testfile");
    (void)r;

    curBid = BLK_NOT_FOUND;
    curOffset = 0;

    uint64_t threshold = 200000;
    uint64_t flush_limit = 102400;

    BnodeCacheMgr* bcache = new BnodeCacheMgr(threshold,
                                              flush_limit);

    FileMgr *file;
    FileMgrConfig config(4096, 1024, 0, 0, FILEMGR_CREATE,
                         FDB_SEQTREE_NOT_USE, 0, 8,
                         DEFAULT_NUM_BCACHE_PARTITIONS,
                         FDB_ENCRYPTION_NONE, 0x55, 0, 0);
    std::string fname("./bnodecache_testfile");
    filemgr_open_result result = FileMgr::open(fname,
                                               get_filemgr_ops(),
                                               &config, nullptr);
    file = result.file;
    TEST_CHK(file != nullptr);

    FileBnodeCache* fcache = bcache->createFileBnodeCache(file);

    std::vector<Bnode*> bnodes;
    BnodeResult ret;
    int n = 100;

    char keybuf[128], bodybuf[128], meta[64];
    for (int i = 0; i < 100; ++i) {
        Bnode* bnode = new Bnode();
        for (int j = 0; j < n; ++j) {
            sprintf(keybuf, "key_%d_%d", i, j);
            sprintf(bodybuf, "body_%d_%d", i, j);
            ret = bnode->addKv((void*)keybuf, strlen(keybuf) + 1,
                               (void*)bodybuf, strlen(bodybuf) + 1,
                               nullptr, true);
            TEST_CHK(ret == BnodeResult::SUCCESS);
        }
        TEST_CHK(bnode->getNentry() == static_cast<size_t>(n));
        sprintf(meta, "meta%d", i);
        bnode->setMeta((void*)meta, strlen(meta) + 1);
        bnodes.push_back(bnode);
    }

    std::vector<cs_off_t> offsets;
    for (size_t i = 0; i < bnodes.size(); ++i) {
        cs_off_t offset = assignDirtyNodeOffset(file, bnodes.at(i));
        bnodes[i]->setCurOffset(offset);
        int wrote = bcache->write(file, bnodes.at(i), offset);
        TEST_CHK(wrote == static_cast<int>(bnodes.at(i)->getNodeSize()));
        offsets.push_back(offset);
    }

    TEST_CHK(bcache->flush(file) == FDB_RESULT_SUCCESS);
    TEST_CHK(bcache->getMemoryUsage() < threshold);

    for (size_t i = 0; i < offsets.size(); ++i) {
        Bnode* node = nullptr;
        cs_off_t off = offsets.at(i);
        int read = bcache->read(file, &node, off);
        TEST_CHK(read == static_cast<int>(node->getNodeSize()));
        node->decRefCount();
    }

    bcache->freeFileBnodeCache(fcache, true);
    delete bcache;

    FileMgr::close(file, true, NULL, NULL);

    TEST_RESULT("BnodeCache: Basic read write test");
}

struct ops_args {
    FileMgr* file;
    BnodeCacheMgr* bcache;
    union {
        std::vector<cs_off_t>* offsets;
        std::vector<Bnode*>* nodes;
    };
};

void* reader_ops(void* args) {
    struct ops_args* ra = static_cast<struct ops_args*>(args);
    size_t bnode_read_count = 0;
    int index = 0;
    while (bnode_read_count < ra->offsets->size()) {
        cs_off_t off= ra->offsets->at(index);
        Bnode* readBnode;
        int read = ra->bcache->read(ra->file,
                                    &readBnode,
                                    off);
        assert(read == static_cast<int>(readBnode->getNodeSize()));
        assert(off == static_cast<cs_off_t>(readBnode->getCurOffset()));
        bnode_read_count++;
        readBnode->decRefCount();
        index = (index + 1) % ra->offsets->size();
    }
    return nullptr;
}

void* writer_ops(void* args) {
    struct ops_args* wa = static_cast<struct ops_args*>(args);
    for (size_t i = 0; i < wa->nodes->size(); ++i) {
        cs_off_t offset = assignDirtyNodeOffset(wa->file, wa->nodes->at(i));
        wa->nodes->at(i)->setCurOffset(offset);
        int wrote = wa->bcache->write(wa->file, wa->nodes->at(i), offset);
        assert(wrote == static_cast<int>(wa->nodes->at(i)->getNodeSize()));

        if (i % 100 == 0) {
            assert(wa->bcache->flush(wa->file) == FDB_RESULT_SUCCESS);
        }
    }
    assert(wa->bcache->flush(wa->file) == FDB_RESULT_SUCCESS);
    return nullptr;
}

void multi_threaded_read_write_test(int readers,
                                    bool writer_in_parallel) {
    TEST_INIT();

    int r = system(SHELL_DEL" bnodecache_testfile");
    (void)r;

    curBid = BLK_NOT_FOUND;
    curOffset = 0;

    uint64_t threshold = 10485760;
    uint64_t flush_limit = 10240;

    BnodeCacheMgr* bcache = new BnodeCacheMgr(threshold,
                                              flush_limit);

    FileMgr *file;
    FileMgrConfig config(4096, 1024, 0, 0, FILEMGR_CREATE,
                         FDB_SEQTREE_NOT_USE, 0, 8,
                         DEFAULT_NUM_BCACHE_PARTITIONS,
                         FDB_ENCRYPTION_NONE, 0x55, 0, 0);
    std::string fname("./bnodecache_testfile");
    filemgr_open_result result = FileMgr::open(fname,
                                               get_filemgr_ops(),
                                               &config, nullptr);
    file = result.file;
    TEST_CHK(file != nullptr);

    FileBnodeCache* fcache = bcache->createFileBnodeCache(file);

    int initial_count = 10000;
    std::vector<Bnode*> bnodes;
    BnodeResult ret;
    int n = 100;

    char keybuf[128], bodybuf[128], meta[64];
    for (int i = 0; i < initial_count; ++i) {
        Bnode* bnode = new Bnode();
        for (int j = 0; j < n; ++j) {
            sprintf(keybuf, "key_%d_%d", i, j);
            sprintf(bodybuf, "body_%d_%d", i, j);
            ret = bnode->addKv((void*)keybuf, strlen(keybuf) + 1,
                               (void*)bodybuf, strlen(bodybuf) + 1,
                               nullptr, true);
            TEST_CHK(ret == BnodeResult::SUCCESS);
        }
        TEST_CHK(bnode->getNentry() == static_cast<size_t>(n));
        sprintf(meta, "meta%d", i);
        bnode->setMeta((void*)meta, strlen(meta) + 1);
        bnodes.push_back(bnode);
    }

    // moreBnodes are for any writer threads
    int additional_count = 0;
    if (writer_in_parallel) {
        additional_count = 2500;
    }
    std::vector<Bnode*> moreBnodes;
    for (int i = 0; i < additional_count; ++i) {
        Bnode* bnode = new Bnode();
        for (int j = 0; j < n; ++j) {
            sprintf(keybuf, "add_key_%d_%d", i, j);
            sprintf(bodybuf, "add_body_%d_%d", i, j);
            ret = bnode->addKv((void*)keybuf, strlen(keybuf) + 1,
                               (void*)bodybuf, strlen(bodybuf) + 1,
                               nullptr, true);
            TEST_CHK(ret == BnodeResult::SUCCESS);
        }
        TEST_CHK(bnode->getNentry() == static_cast<size_t>(n));
        sprintf(meta, "add_meta%d", i);
        bnode->setMeta((void*)meta, strlen(meta) + 1);
        moreBnodes.push_back(bnode);
    }

    std::vector<cs_off_t> offsets;
    for (size_t i = 0; i < bnodes.size(); ++i) {
        cs_off_t offset = assignDirtyNodeOffset(file, bnodes.at(i));
        bnodes[i]->setCurOffset(offset);
        int wrote = bcache->write(file, bnodes.at(i), offset);
        TEST_CHK(wrote == static_cast<int>(bnodes.at(i)->getNodeSize()));
        offsets.push_back(offset);

        if (i % 100 == 0) {
            TEST_CHK(bcache->flush(file) == FDB_RESULT_SUCCESS);
        }
    }
    TEST_CHK(bcache->flush(file) == FDB_RESULT_SUCCESS);

    int num_threads = readers + (writer_in_parallel ? 1 : 0);
    thread_t* threads = new thread_t[num_threads];
    struct ops_args rargs;
    rargs.file = file;
    rargs.bcache = bcache;
    rargs.offsets = &offsets;
    int threadid = 0;
    for (threadid = 0; threadid < readers; ++threadid) {
        thread_create(&threads[threadid], reader_ops, &rargs);
    }

    struct ops_args wargs;
    wargs.file = file;
    wargs.bcache = bcache;
    wargs.nodes = &moreBnodes;
    if (writer_in_parallel) {
        thread_create(&threads[threadid], writer_ops, &wargs);
    }

    for (int i = 0; i < num_threads; ++i) {
        r = thread_join(threads[i], nullptr);
        assert(r == 0);
    }
    delete[] threads;

    TEST_CHK(bcache->getMemoryUsage() < threshold);

    bcache->freeFileBnodeCache(fcache, true);
    delete bcache;

    FileMgr::close(file, true, NULL, NULL);

    std::string title("BnodeCache: Multi threaded reader (" +
                      std::to_string(readers) + ") writer test");
    if (writer_in_parallel) {
        title += " with parallel writer";
    }
    TEST_RESULT(title.c_str());
}

int main() {
    basic_read_write_test();
    multi_threaded_read_write_test(4        /* readers */,
                                   false    /* writer in parallel */);
    multi_threaded_read_write_test(4        /* readers */,
                                   true     /* writer in parallel */);
    return 0;
}
