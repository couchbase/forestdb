#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include "test.h"
#include "blockcache.h"
#include "filemgr.h"
#include "filemgr_ops_linux.h"
#include "crc32.h"

#include "memleak.h"

void basic_test()
{
    TEST_INIT();

    struct filemgr *file;
    struct filemgr_config config;
    bid_t bid;
    int i, j;
    uint8_t buf[4096];

    memset(&config, 0, sizeof(config));
    config.blocksize = 4096;
    config.ncacheblock = 5;
    file = filemgr_open("./dummy", get_linux_filemgr_ops(), &config);

    for (i=0;i<5;++i) {
        filemgr_alloc(file);
        filemgr_write(file, i, buf);
    }
    filemgr_commit(file);
    for (i=5;i<10;++i) {
        filemgr_alloc(file);
        filemgr_write(file, i, buf);
    }
    filemgr_commit(file);
    
    filemgr_read(file, 8, buf);
    filemgr_read(file, 9, buf);

    filemgr_read(file, 1, buf);
    filemgr_read(file, 2, buf);
    filemgr_read(file, 3, buf);

    filemgr_read(file, 7, buf);
    filemgr_read(file, 1, buf);
    filemgr_read(file, 9, buf);

    filemgr_alloc(file);
    filemgr_write(file, 10, buf);

    TEST_RESULT("basic test");
}

void basic_test2()
{
    TEST_INIT();

    struct filemgr *file;
    struct filemgr_config config;
    bid_t bid;
    int i, j;
    uint8_t buf[4096];
    int r;
    r = system("rm -rf ./dummy");
    
    memset(&config, 0, sizeof(config));
    config.blocksize = 4096;
    config.ncacheblock = 5;
    config.flag = 0x0;    
    file = filemgr_open("./dummy", get_linux_filemgr_ops(), &config);

    for (i=0;i<5;++i) {
        filemgr_alloc(file);
        filemgr_write(file, i, buf);
    }
    for (i=5;i<10;++i) {
        filemgr_alloc(file);
        filemgr_write(file, i, buf);
    }
    filemgr_commit(file);
    filemgr_close(file);
    filemgr_shutdown();

    TEST_RESULT("basic test");

}

struct timespec _time_gap(struct timespec a, struct timespec b) 
{
	struct timespec ret;
	if (b.tv_nsec >= a.tv_nsec) {
		ret.tv_nsec = b.tv_nsec - a.tv_nsec;
		ret.tv_sec = b.tv_sec - a.tv_sec;
	}else{
		ret.tv_nsec = 1000000000 + b.tv_nsec - a.tv_nsec;
		ret.tv_sec = b.tv_sec - a.tv_sec - 1;
	}
	return ret;
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
    void *buf = (void *)malloc(4096);
    struct worker_args *args = (struct worker_args*)voidargs;
    struct timeval ts_begin, ts_cur, ts_gap;
    
    int ret;
    bid_t bid;
    uint32_t crc, crc_file;
    uint64_t i, c, run_count=0;

    memset(buf, 0, 4096);
    gettimeofday(&ts_begin, NULL);

    while(1) {
        bid = rand() % args->nblocks;
        ret = bcache_read(args->file, bid, buf);
        if (ret <= 0) {
            ret = args->file->ops->pread(args->file->fd, buf, args->file->blocksize, bid * args->file->blocksize);
            assert(ret == args->file->blocksize);
            ret = bcache_write(args->file, bid, buf, BCACHE_CLEAN);
            assert(ret == args->file->blocksize);
        }
        crc_file = crc32_8(buf, sizeof(uint64_t)*2, 0);
        memcpy(&i, buf, sizeof(i));
        memcpy(&crc, buf + sizeof(uint64_t)*2, sizeof(crc));
        assert(crc == crc_file && i==bid);
        //DBG("%d %d %d %x %x\n", (int)args->n, (int)i, (int)bid, (int)crc, (int)crc_file);
        
        if (args->writer) {
            memcpy(&c, buf+sizeof(i), sizeof(c));
            c++;
            memcpy(buf+sizeof(i), &c, sizeof(c));
            crc = crc32_8(buf, sizeof(uint64_t)*2, 0);
            memcpy(buf + sizeof(uint64_t)*2, &crc, sizeof(crc));

            ret = bcache_write(args->file, bid, buf, BCACHE_DIRTY);
            assert(ret == args->file->blocksize);
        }
        
        gettimeofday(&ts_cur, NULL);
        ts_gap = _utime_gap(ts_begin, ts_cur);
        if (ts_gap.tv_sec >= args->time_sec) break;

        run_count++;
    }

    free(buf);
    pthread_exit(NULL);    
    return NULL;
}

void multi_thread_test(
    int nblocks, int cachesize, int blocksize, int time_sec, int nwriters, int nreaders)
{
    TEST_INIT();

    struct filemgr *file;
    struct filemgr_config config;
    bid_t bid;
    int n = nwriters + nreaders;
    uint64_t i, j;
    uint32_t crc;
    void *buf;
    int r;
    pthread_t tid[n];
    struct worker_args args[n];
    void *ret[n];
    
    r = system("rm -rf ./dummy");

    memleak_start();

    buf = (void *)malloc(4096);
    memset(buf, 0, 4096);

    memset(&config, 0, sizeof(config));
    config.blocksize = blocksize;
    config.ncacheblock = cachesize;
    config.flag = 0x0;
    file = filemgr_open("./dummy", get_linux_filemgr_ops(), &config);

    for (i=0;i<nblocks;++i) {
        memcpy(buf, &i, sizeof(i));
        j = 0;
        memcpy(buf + sizeof(i), &j, sizeof(j));
        crc = crc32_8(buf, sizeof(i) + sizeof(j), 0);
        memcpy(buf + sizeof(i) + sizeof(j), &crc, sizeof(crc));
        bcache_write(file, (bid_t)i, buf, BCACHE_DIRTY);
    }

    for (i=0;i<n;++i){
        args[i].n = i;
        args[i].file = file;
        args[i].writer = ((i<nwriters)?(1):(0));
        args[i].nblocks = nblocks;
        args[i].time_sec = time_sec;
        pthread_create(&tid[i], NULL, worker, &args[i]);
    }

    DBG("wait for %d seconds..\n", time_sec);
    for (i=0;i<n;++i){
        pthread_join(tid[i], &ret[i]);
    }

    filemgr_commit(file);
    filemgr_close(file);
    filemgr_shutdown();
    free(buf);

    memleak_end();
    TEST_RESULT("multi thread test");
}

int main()
{
    basic_test2();
    multi_thread_test(4, 1, 32, 60, 1, 7);

    return 0;
}
