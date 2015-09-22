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

    struct filemgr *file;
    struct filemgr_config config;
    int i;
    uint8_t buf[4096];
    char *fname = (char *) "./bcache_testfile";

    memset(&config, 0, sizeof(config));
    config.blocksize = 4096;
    config.ncacheblock = 5;
    config.options = FILEMGR_CREATE;
    config.num_wal_shards = 8;
    filemgr_open_result result = filemgr_open(fname, get_filemgr_ops(), &config, NULL);
    file = result.file;

    for (i=0;i<5;++i) {
        filemgr_alloc(file, NULL);
        filemgr_write(file, i, buf, NULL);
    }
    filemgr_commit(file, true, NULL);
    for (i=5;i<10;++i) {
        filemgr_alloc(file, NULL);
        filemgr_write(file, i, buf, NULL);
    }
    filemgr_commit(file, true, NULL);

    filemgr_read(file, 8, buf, NULL, true);
    filemgr_read(file, 9, buf, NULL, true);

    filemgr_read(file, 1, buf, NULL, true);
    filemgr_read(file, 2, buf, NULL, true);
    filemgr_read(file, 3, buf, NULL, true);

    filemgr_read(file, 7, buf, NULL, true);
    filemgr_read(file, 1, buf, NULL, true);
    filemgr_read(file, 9, buf, NULL, true);

    filemgr_alloc(file, NULL);
    filemgr_write(file, 10, buf, NULL);

    TEST_RESULT("basic test");
}

void basic_test2()
{
    TEST_INIT();

    struct filemgr *file;
    struct filemgr_config config;
    int i;
    uint8_t buf[4096];
    char *fname = (char *) "./bcache_testfile";
    int r;
    r = system(SHELL_DEL " bcache_testfile");
    (void)r;

    memset(&config, 0, sizeof(config));
    config.blocksize = 4096;
    config.ncacheblock = 5;
    config.flag = 0x0;
    config.options = FILEMGR_CREATE;
    config.num_wal_shards = 8;
    filemgr_open_result result = filemgr_open(fname, get_filemgr_ops(), &config, NULL);
    file = result.file;

    for (i=0;i<5;++i) {
        filemgr_alloc(file, NULL);
        filemgr_write(file, i, buf, NULL);
    }
    for (i=5;i<10;++i) {
        filemgr_alloc(file, NULL);
        filemgr_write(file, i, buf, NULL);
    }
    filemgr_commit(file, true, NULL);
    filemgr_close(file, true, NULL, NULL);
    filemgr_shutdown();

    TEST_RESULT("basic test");

}

struct worker_args{
    size_t n;
    struct filemgr *file;
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
        ret = bcache_read(args->file, bid, buf);
        if (ret <= 0) {
            ret = args->file->ops->pread(args->file->fd, buf,
                                         args->file->blocksize, bid * args->file->blocksize);
            TEST_CHK(ret == args->file->blocksize);
            ret = bcache_write(args->file, bid, buf, BCACHE_REQ_CLEAN, false);
            TEST_CHK(ret == args->file->blocksize);
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

            ret = bcache_write(args->file, bid, buf, BCACHE_REQ_DIRTY, true);
            TEST_CHK(ret == args->file->blocksize);
        } else { // have some of the reader threads flush dirty immutable blocks
            if (bid <= args->nblocks / 4) { // 25% probability
                filemgr_flush_immutable(args->file, NULL);
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

void multi_thread_test(
    int nblocks, int cachesize, int blocksize, int time_sec, int nwriters, int nreaders)
{
    TEST_INIT();

    struct filemgr *file;
    struct filemgr_config config;
    int n = nwriters + nreaders;
    uint64_t i, j;
    uint32_t crc;
    uint8_t *buf;
    int r;
    char *fname = (char *) "./bcache_testfile";
    thread_t *tid = alca(thread_t, n);
    struct worker_args *args = alca(struct worker_args, n);
    void **ret = alca(void *, n);

    r = system(SHELL_DEL " bcache_testfile");
    (void)r;

    memleak_start();

    buf = (uint8_t *)malloc(4096);
    memset(buf, 0, 4096);

    memset(&config, 0, sizeof(config));
    config.blocksize = blocksize;
    config.ncacheblock = cachesize;
    config.flag = 0x0;
    config.options = FILEMGR_CREATE;
    config.num_wal_shards = 8;
    filemgr_open_result result = filemgr_open(fname, get_filemgr_ops(), &config, NULL);
    file = result.file;

    for (i=0;i<(uint64_t)nblocks;++i) {
        memcpy(buf, &i, sizeof(i));
        j = 0;
        memcpy(buf + sizeof(i), &j, sizeof(j));
        crc = crc32_8(buf, sizeof(i) + sizeof(j), 0);
        memcpy(buf + sizeof(i) + sizeof(j), &crc, sizeof(crc));
        bcache_write(file, (bid_t)i, buf, BCACHE_REQ_DIRTY, false);
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

    filemgr_commit(file, true, NULL);
    filemgr_close(file, true, NULL, NULL);
    filemgr_shutdown();
    free(buf);

    memleak_end();
    TEST_RESULT("multi thread test");
}

int main()
{
    basic_test2();
    multi_thread_test(4, 1, 32, 20, 1, 7);
    multi_thread_test(100, 1, 32, 10, 1, 7);

    return 0;
}
