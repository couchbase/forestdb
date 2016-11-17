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

#include "test.h"
#include "blockcache.h"
#include "filemgr.h"
#include "filemgr_ops.h"
#include "crc32.h"

#include "memleak.h"

void basic_test()
{
    TEST_INIT();

    FileMgr *file;
    FileMgrConfig config(4096, 5, 1048576, 0, 0, FILEMGR_CREATE,
                         FDB_SEQTREE_NOT_USE, 0, 8, 0, FDB_ENCRYPTION_NONE,
                         0x00, 0, 0);
    int i;
    uint8_t buf[4096];
    std::string fname("./bcache_testfile");

    filemgr_open_result result = FileMgr::open(fname, get_filemgr_ops(),
                                               &config, NULL);
    file = result.file;

    for (i=0;i<5;++i) {
        file->alloc_FileMgr(NULL);
        file->write_FileMgr(i, buf, NULL);
    }
    file->commit_FileMgr(true, NULL);
    for (i=5;i<10;++i) {
        file->alloc_FileMgr(NULL);
        file->write_FileMgr(i, buf, NULL);
    }
    file->commit_FileMgr(true, NULL);

    file->read_FileMgr(8, buf, NULL, true);
    file->read_FileMgr(9, buf, NULL, true);

    file->read_FileMgr(1, buf, NULL, true);
    file->read_FileMgr(2, buf, NULL, true);
    file->read_FileMgr(3, buf, NULL, true);

    file->read_FileMgr(7, buf, NULL, true);
    file->read_FileMgr(1, buf, NULL, true);
    file->read_FileMgr(9, buf, NULL, true);

    file->alloc_FileMgr(NULL);
    file->write_FileMgr(10, buf, NULL);

    TEST_RESULT("basic test");
}

void basic_test2()
{
    TEST_INIT();

    FileMgr *file;
    FileMgrConfig config(4096, 5, 1048576, 0x0, 0, FILEMGR_CREATE,
                         FDB_SEQTREE_NOT_USE, 0, 8, 0, FDB_ENCRYPTION_NONE,
                         0x00, 0, 0);
    int i;
    uint8_t buf[4096];
    std::string fname("./bcache_testfile");
    int r;
    r = system(SHELL_DEL " bcache_testfile");
    (void)r;

    filemgr_open_result result = FileMgr::open(fname, get_filemgr_ops(),
                                               &config, NULL);
    file = result.file;

    for (i=0;i<5;++i) {
        file->alloc_FileMgr(NULL);
        file->write_FileMgr(i, buf, NULL);
    }
    for (i=5;i<10;++i) {
        file->alloc_FileMgr(NULL);
        file->write_FileMgr(i, buf, NULL);
    }
    file->commit_FileMgr(true, NULL);
    FileMgr::close(file, true, NULL, NULL);
    FileMgr::shutdown();

    TEST_RESULT("basic test");

}

struct worker_args{
    size_t n;
    FileMgr *file;
    size_t writer;
    size_t nblocks;
    size_t time_sec;
};

void * worker(void *voidargs)
{
    uint8_t *buf = (uint8_t *)malloc(4096);
    struct worker_args *args = (struct worker_args*)voidargs;
    struct timeval ts_begin, ts_cur, ts_gap;

    ssize_t ret;
    bid_t bid;
    uint32_t crc, crc_file;
    uint64_t i, c, run_count=0;
    TEST_INIT();

    memset(buf, 0, 4096);
    gettimeofday(&ts_begin, NULL);

    while(1) {
        bid = rand() % args->nblocks;
        ret = BlockCacheManager::getInstance()->read(args->file, bid, buf);
        if (ret <= 0) {
            ret = args->file->getOps()->pread(args->file->getFopsHandle(), buf,
                                              args->file->getBlockSize(),
                                              bid * args->file->getBlockSize());
            TEST_CHK(ret == (ssize_t)args->file->getBlockSize());
            ret = BlockCacheManager::getInstance()->write(args->file, bid, buf,
                                                          BCACHE_REQ_CLEAN, false);
            TEST_CHK(ret == (ssize_t)args->file->getBlockSize());
        }
        crc_file = crc32_8(buf, sizeof(uint64_t)*2, 0);
        (void)crc_file;
        memcpy(&i, buf, sizeof(i));
        memcpy(&crc, buf + sizeof(uint64_t)*2, sizeof(crc));
        // Disable checking the CRC value at this time as pread and pwrite are
        // not thread-safe.
        // TEST_CHK(crc == crc_file && i==bid);
        //DBG("%d %d %d %x %x\n", (int)args->n, (int)i, (int)bid, (int)crc, (int)crc_file);

        if (args->writer) {
            memcpy(&c, buf+sizeof(i), sizeof(c));
            c++;
            memcpy(buf+sizeof(i), &c, sizeof(c));
            crc = crc32_8(buf, sizeof(uint64_t)*2, 0);
            memcpy(buf + sizeof(uint64_t)*2, &crc, sizeof(crc));

            ret = BlockCacheManager::getInstance()->write(args->file, bid, buf,
                                                          BCACHE_REQ_DIRTY, true);
            TEST_CHK(ret == (ssize_t)args->file->getBlockSize());
        } else { // have some of the reader threads flush dirty immutable blocks
            if (bid <= args->nblocks / 4) { // 25% probability
                args->file->flushImmutable(NULL);
            }
        }

        gettimeofday(&ts_cur, NULL);
        ts_gap = _utime_gap(ts_begin, ts_cur);
        if ((size_t)ts_gap.tv_sec >= args->time_sec) break;

        run_count++;
    }

    free(buf);
    thread_exit(0);
    return NULL;
}

void multi_thread_test(int nblocks, int cachesize,
                       int blocksize, int time_sec,
                       int nwriters, int nreaders)
{
    TEST_INIT();

    FileMgr *file;
    FileMgrConfig config(blocksize, cachesize, 1048576, 0x0, 0,
                         FILEMGR_CREATE, FDB_SEQTREE_NOT_USE, 0, 8, 0,
                         FDB_ENCRYPTION_NONE, 0x00, 0, 0);

    int n = nwriters + nreaders;
    uint64_t i, j;
    uint32_t crc;
    uint8_t *buf;
    int r;
    std::string fname("./bcache_testfile");
    thread_t *tid = alca(thread_t, n);
    struct worker_args *args = alca(struct worker_args, n);
    void **ret = alca(void *, n);

    r = system(SHELL_DEL " bcache_testfile");
    (void)r;

    memleak_start();

    buf = (uint8_t *)malloc(4096);
    memset(buf, 0, 4096);

    filemgr_open_result result = FileMgr::open(fname, get_filemgr_ops(),
                                               &config, NULL);
    file = result.file;

    for (i=0;i<(uint64_t)nblocks;++i) {
        memcpy(buf, &i, sizeof(i));
        j = 0;
        memcpy(buf + sizeof(i), &j, sizeof(j));
        crc = crc32_8(buf, sizeof(i) + sizeof(j), 0);
        memcpy(buf + sizeof(i) + sizeof(j), &crc, sizeof(crc));
        BlockCacheManager::getInstance()->write(file, (bid_t)i, buf,
                                                BCACHE_REQ_DIRTY, false);
    }

    for (i=0;i<(uint64_t)n;++i){
        args[i].n = i;
        args[i].file = file;
        args[i].writer = ((i<(uint64_t)nwriters)?(1):(0));
        args[i].nblocks = nblocks;
        args[i].time_sec = time_sec;
        thread_create(&tid[i], worker, &args[i]);
    }

    DBG("wait for %d seconds..\n", time_sec);
    for (i=0;i<(uint64_t)n;++i){
        thread_join(tid[i], &ret[i]);
    }

    file->commit_FileMgr(true, NULL);
    FileMgr::close(file, true, NULL, NULL);
    FileMgr::shutdown();
    free(buf);

    memleak_end();
    TEST_RESULT("multi thread test");
}

int main()
{
    basic_test2();
#if !defined(THREAD_SANITIZER)
    /**
     * The following tests will be disabled when the code is run with
     * thread sanitizer, because they point out a data race in writing/
     * reading from a dirty block which will not happen in reality.
     *
     * The bcache partition lock is release iff a given dirty block has
     * already been marked as immutable. These unit tests attempt to
     * write to the same immutable block again causing this race. In
     * reality, this won't happen as these operations go through
     * FileMgr::read() and FileMgr::write().
     */
    multi_thread_test(4, 1, 32, 20, 1, 7);
    multi_thread_test(100, 1, 32, 10, 1, 7);
#endif

    return 0;
}
