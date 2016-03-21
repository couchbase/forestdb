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
#include <stdint.h>

#include <atomic>
#include <chrono>
#include <string>
#include <vector>

#include "libforestdb/forestdb.h"
#include "test.h"
#include "timing.h"

#include "stat_aggregator.h"

// NUM_STATS to always be the last entry in the following
// enum class to keep a count of the number of stats tracked
// in the use case tests.
enum _op_ {
    SET,
    COMMIT,
    GET,
    INMEMSNAP,
    NUM_STATS
};

/**
 * Each entry in the vector maintained by the file handle pool.
 */
struct PoolEntry {
    PoolEntry(int _index,
              bool _avail,
              fdb_file_handle *_dbfile,
              fdb_kvs_handle *_db) {
        index = _index;
        available.store(_avail);
        dbfile = _dbfile;
        db = _db;
    }

    int index;
    std::atomic<bool> available;
    fdb_file_handle *dbfile;
    fdb_kvs_handle *db;
};

/**
 * This class maintains a pool of file and kvs handles.
 */
class FileHandlePool {
public:
    FileHandlePool(const char *filename, int count) {
        fdb_status status;
        fdb_config fconfig = fdb_get_default_config();
        fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
        for (int i = 0; i < count; ++i) {
            fdb_file_handle *dbfile;
            fdb_kvs_handle *db;
            status = fdb_open(&dbfile, filename, &fconfig);
            assert(status == FDB_RESULT_SUCCESS);
            status = fdb_kvs_open_default(dbfile, &db, &kvs_config);
            assert(status == FDB_RESULT_SUCCESS);
            PoolEntry *pe = new PoolEntry(i, true, dbfile, db);
            pool_vector.push_back(pe);
        }

        // Set up StatAggregator
        sa = new StatAggregator(NUM_STATS, 1);
        sa->t_stats[SET][0].name = "set";
        sa->t_stats[COMMIT][0].name = "commit";
        sa->t_stats[GET][0].name = "get";
        sa->t_stats[INMEMSNAP][0].name = "in-mem snapshot";

        samples = 0;
        mutex_init(&statlock);
    }

    ~FileHandlePool() {
        fdb_status status;
        for (size_t i = 0; i < pool_vector.size(); ++i) {
            PoolEntry *pe = pool_vector.at(i);
            if (pe) {
                status = fdb_kvs_close(pe->db);
                assert(status == FDB_RESULT_SUCCESS);
                status = fdb_close(pe->dbfile);
                assert(status == FDB_RESULT_SUCCESS);
                delete pe;
            }
        }
        pool_vector.clear();

        // Delete StatAggregator
        delete sa;
    }

    /**
     * Acquire a handle set and its index that is currently available,
     * in the process, the handle set will be marked as unavailable for
     * any other user.
     */
    int getAvailableResource(fdb_file_handle **dbfile, fdb_kvs_handle **db) {
        while (true) {
            int index = rand() % pool_vector.size();
            bool inverse = true;
            PoolEntry *pe = pool_vector.at(index);
            if (pe && pe->available.compare_exchange_strong(inverse, false)) {
                *dbfile = pe->dbfile;
                *db = pe->db;
                return pe->index;
            }
        }
    }

    /**
     * Set the handle set at an index to available, indicating the current
     * user will not be using the handles anymore.
     */
    void returnResourceToPool(int index) {
        PoolEntry *pe = pool_vector.at(index);
        if (!pe) {
            fprintf(stderr, "Invalid entry!\n");
            return;
        }
        bool inverse = false;
        if (!pe->available.compare_exchange_strong(inverse, true)) {
            fprintf(stderr, "Handles were likely used by another thread!");
            assert(false);
        }
    }

    /**
     * Collects stats - invoked by concurrent threads, hence the mutex.
     */
    void collectStat(int index, uint64_t diff) {
        mutex_lock(&statlock);
        if (sa && index < NUM_STATS) {
            sa->t_stats[index][0].latencies.push_back(diff);
            ++samples;
        }
        mutex_unlock(&statlock);
    }

    /**
     * Displays median, percentiles and histogram of the
     * collected stats.
     */
    void displayCollection(const char* title) {
        if (sa) {
            sa->aggregateAndPrintStats(title, samples, "ms");
        }
    }

    /**
     * Print availabity status of the handle sets at every index in the
     * pool.
     */
    void printPoolVector() {
        fprintf(stderr, "---------------------\n");
        for (size_t i = 0; i < pool_vector.size(); ++i) {
            fprintf(stderr, "Index: %d Available: %d\n",
                    (pool_vector.at(i))->index,
                    (pool_vector.at(i))->available.load() ? 1 : 0);
        }
        fprintf(stderr, "---------------------\n");
    }

    /**
     * Print FDB_LATENCY_STATS, for all file handles.
     */
    void printHandleStats() {
        fdb_status status;
        fdb_latency_stat stat;
        int nstats = FDB_LATENCY_NUM_STATS;

        StatAggregator *s = new StatAggregator(nstats, 1);

        for (int i = 0; i < nstats; ++i) {
            const char* name = fdb_latency_stat_name(i);
            s->t_stats[i][0].name = name;

            for (size_t j = 0; j < pool_vector.size(); ++j) {
                memset(&stat, 0, sizeof(fdb_latency_stat));
                status = fdb_get_latency_stats((pool_vector.at(j))->dbfile,
                                               &stat, i);
                assert(status == FDB_RESULT_SUCCESS);

                if (stat.lat_count > 0) {
                    s->t_stats[i][0].latencies.push_back(stat.lat_avg);
                }
            }
        }
        (void)status;

        s->aggregateAndPrintStats("FDB_STATS", pool_vector.size(), "ms");
        delete s;
    }

private:
    std::vector<PoolEntry *> pool_vector;
    int samples;
    StatAggregator *sa;
    mutex_t statlock;
};

struct ops_args {
    FileHandlePool *fhp;
    const float time;
};

static void *invoke_writer_ops(void *args) {
    struct ops_args *oa = static_cast<ops_args *>(args);
    int i = 0;
    fdb_status status;
    std::chrono::time_point<std::chrono::system_clock> start, end;
    start = std::chrono::system_clock::now();
    while (true) {
        /* Acquire handles from pool */
        fdb_file_handle *dbfile = nullptr;
        fdb_kvs_handle *db = nullptr;
        const int index = oa->fhp->getAvailableResource(&dbfile, &db);

        char keybuf[256], bodybuf[256];
        sprintf(keybuf, "key%d", i);
        sprintf(bodybuf, "body%d", i);

        status = fdb_begin_transaction(dbfile, FDB_ISOLATION_READ_COMMITTED);
        assert(status == FDB_RESULT_SUCCESS);

        ts_nsec beginSet = get_monotonic_ts();
        status = fdb_set_kv(db,
                            (void*)keybuf, strlen(keybuf) + 1,
                            (void*)bodybuf, strlen(bodybuf) + 1);
        ts_nsec endSet = get_monotonic_ts();
        assert(status == FDB_RESULT_SUCCESS);

        ts_nsec beginCommit = get_monotonic_ts();
        status = fdb_end_transaction(dbfile, FDB_COMMIT_NORMAL);
        ts_nsec endCommit = get_monotonic_ts();
        assert(status == FDB_RESULT_SUCCESS);

        /* Return resource to pool */
        oa->fhp->returnResourceToPool(index);

        oa->fhp->collectStat(SET, ts_diff(beginSet, endSet));
        oa->fhp->collectStat(COMMIT, ts_diff(beginCommit, endCommit));

        ++i;
        end = std::chrono::system_clock::now();
        std::chrono::duration<double> elapsed_seconds = end - start;
        if (elapsed_seconds.count() > oa->time) {
#ifdef __DEBUG_USECASE
            fprintf(stderr, "Writer: Ends after %fs\n", elapsed_seconds.count());
#endif
            break;
        }
    }
    thread_exit(0);
    return nullptr;
}

static void *invoke_reader_ops(void *args) {
    struct ops_args *oa = static_cast<ops_args *>(args);
    fdb_status status;
    std::chrono::time_point<std::chrono::system_clock> start, end;
    start = std::chrono::system_clock::now();
    while (true) {
        /* Acquire handles from pool */
        fdb_file_handle *dbfile = nullptr;
        fdb_kvs_handle *db = nullptr;
        fdb_kvs_handle *snap_handle = nullptr;
        const int index = oa->fhp->getAvailableResource(&dbfile, &db);

        // Try fetching a random doc
        void *value = nullptr;
        size_t valuelen;
        char keybuf[256], bodybuf[256];
        int i = rand() % 100;
        sprintf(keybuf, "key%d", i);
        sprintf(bodybuf, "body%d", i);
        ts_nsec beginGet = get_monotonic_ts();
        status = fdb_get_kv(db,
                            (void*)keybuf, strlen(keybuf) + 1,
                            &value, &valuelen);
        ts_nsec endGet = get_monotonic_ts();
        if (status == FDB_RESULT_SUCCESS) {
            assert(memcmp(value, bodybuf, valuelen) == 0);
            fdb_free_block(value);
        } else {
            assert(status == FDB_RESULT_KEY_NOT_FOUND);
        }

        // Create an in-memory snapshot
        ts_nsec beginSnap = get_monotonic_ts();
        status = fdb_snapshot_open(db, &snap_handle, FDB_SNAPSHOT_INMEM);
        ts_nsec endSnap = get_monotonic_ts();
        assert(status == FDB_RESULT_SUCCESS);

        // Close snapshot handle
        status = fdb_kvs_close(snap_handle);
        assert(status == FDB_RESULT_SUCCESS);

        /* Return resource to pool */
        oa->fhp->returnResourceToPool(index);

        oa->fhp->collectStat(GET, ts_diff(beginGet, endGet));
        oa->fhp->collectStat(INMEMSNAP, ts_diff(beginSnap, endSnap));

        end = std::chrono::system_clock::now();
        std::chrono::duration<double> elapsed_seconds = end - start;
        if (elapsed_seconds.count() > oa->time) {
#ifdef __DEBUG_USECASE
            fprintf(stderr, "Reader: Ends after %fs\n", elapsed_seconds.count());
#endif
            break;
        }
    }
    thread_exit(0);
    return nullptr;
}

void single_writer_multi_reader_test(int nhandles,
                                     int nthreads,
                                     int time) {
    TEST_INIT();
    memleak_start();

    int r;

    r = system(SHELL_DEL" usecase_test* > errorlog.txt");
    (void)r;


    /* prepare handle pool */
    const char *filename = "./usecase_test1";

    FileHandlePool *fhp = new FileHandlePool(filename, nhandles);

    assert(nthreads > 1);
    thread_t *threads = new thread_t[nthreads];

    int readers = nthreads - 1; // 1 writer

    struct ops_args oa{fhp, (float)time};

    int threadid = 0;
    // Spawn writer thread(s)
    {
        thread_create(&threads[threadid++], invoke_writer_ops, &oa);
    }

    // Spawn reader thread(s)
    for (int i = 0; i < readers; ++i) {
        thread_create(&threads[threadid++], invoke_reader_ops, &oa);
    }

    assert(threadid == nthreads);

    // Wait for child threads
    for (int j = 0; j < nthreads; ++j) {
        int r = thread_join(threads[j], nullptr);
        assert(r == 0);
    }
    delete[] threads;

    /* Print Collected Stats */
    fhp->displayCollection("SINGLE_WRITER, MULTIPLE_READERS");

#ifdef __DEBUG_USECASE
    fhp->printHandleStats();
#endif

    /* cleanup */
    delete fhp;
    fdb_shutdown();

    r = system(SHELL_DEL" usecase_test* > errorlog.txt");
    (void)r;

    memleak_end();
    TEST_RESULT("single writer multi reader test");
}

int main() {

    /* Test single writer with multi readers sharing a common
       pool of file handles, for 30 seconds */
    single_writer_multi_reader_test(10 /*number of handles*/,
                                    5  /*thread count*/,
                                    30 /*test time in seconds*/);

    return 0;
}
