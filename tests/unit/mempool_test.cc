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

#include <mutex>

#include "atomic.h"
#include "memory_pool.h"

#include "test.h"
#include "stat_aggregator.h"

int samples(0);
static std::mutex guard;

void collect_stat(StatAggregator *sa, uint64_t diff) {
    LockHolder lh(guard);
    sa->t_stats[0][0].latencies.push_back(diff);
    ++samples;
}

struct worker_args{
    int num_runs;
    int num_bins;
    size_t bin_size;
    MemoryPool *mp;
    StatAggregator *sa;
};

void *basic_tester(void *args_)
{
    TEST_INIT();
    struct worker_args *args = (struct worker_args *)args_;
    size_t bin_size = args->bin_size;
    for (int i = args->num_runs; i; --i) {
        uint8_t *buf;
        ts_nsec start = get_monotonic_ts();
        const int idx = args->mp->fetchBlock(&buf);
        ts_nsec end = get_monotonic_ts();
        TEST_CHK(idx != -1);
        for (int j = 100; j; --j) {
            buf[rand() % (bin_size - 1)] = 'X';
        }
        collect_stat(args->sa, (end - start));
        args->mp->returnBlock(idx);
    }
    return NULL;
}

void basic_test(int iterations, int num_bins, size_t bin_size)
{
    TEST_INIT();
    struct timeval ts_begin, ts_cur, ts_gap;

    StatAggregator *sa = new StatAggregator(1, 1);
    sa->t_stats[0][0].name = "wait_times";
    samples = 0;

    gettimeofday(&ts_begin, NULL);

    struct worker_args mpool;
    mpool.num_runs = iterations;
    mpool.num_bins = num_bins;
    mpool.bin_size = bin_size;
    mpool.mp = new MemoryPool(mpool.num_bins, mpool.bin_size);
    mpool.sa = sa;

    void *ret = basic_tester(&mpool);
    TEST_CHK(!ret);
    delete mpool.mp;

    gettimeofday(&ts_cur, NULL);

    sa->aggregateAndPrintStats("BASIC_TEST", samples, "ns");
    delete sa;

    ts_gap = _utime_gap(ts_begin, ts_cur);
    char res[128];
    sprintf(res,
            "basic test with %d runs of %d bins x %" _F64 "bytes in %ld µs",
            iterations, num_bins, uint64_t(bin_size),
            ts_gap.tv_sec*1000000 + ts_gap.tv_usec);
    TEST_RESULT(res);
}

void multi_thread_test(int num_threads, int iterations, int num_bins,
                       size_t bin_size)
{
    TEST_INIT();
    thread_t *tid = alca(thread_t, num_threads);
    struct timeval ts_begin, ts_cur, ts_gap;

    StatAggregator *sa = new StatAggregator(1, 1);
    sa->t_stats[0][0].name = "wait_times";
    samples = 0;

    gettimeofday(&ts_begin, NULL);

    struct worker_args mpool;
    mpool.num_runs = iterations;
    mpool.num_bins = num_bins;
    mpool.bin_size = bin_size;
    mpool.mp = new MemoryPool(mpool.num_bins, mpool.bin_size);
    mpool.sa = sa;

    for (int i = num_threads - 1; i >= 0; --i) {
        thread_create(&tid[i], basic_tester, &mpool);
    }

    for (int i = num_threads - 1; i >= 0; --i) {
        void *ret;
        thread_join(tid[i], &ret);
        TEST_CHK(!ret);
    }

    delete mpool.mp;

    gettimeofday(&ts_cur, NULL);

    sa->aggregateAndPrintStats("MULTI_THREAD_TEST", samples, "ns");
    delete sa;

    ts_gap = _utime_gap(ts_begin, ts_cur);
    char res[128];
    sprintf(res,
            "multi-thread test with %d threads each with "
            "%d runs of %d bins x %" _F64 "bytes in %ld µs",
            num_threads, iterations, num_bins, uint64_t(bin_size),
            ts_gap.tv_sec*1000000 + ts_gap.tv_usec);
    TEST_RESULT(res);
}

int main()
{
    basic_test(10000, 8, 10485760); //1000 runs of 8 x 10MB buffers
    multi_thread_test(8, 10000, 8, 10485760); // repeat with 8 threads
    return 0;
}
