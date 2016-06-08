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

// _num_stats_ to always be the last entry in the following
// enum class to keep a count of the number of stats tracked
// in the use case tests.
enum _op_ {
    SET,
    COMMIT,
    GET,
    IN_MEM_SNAP,
    CLONE_SNAP,
    ITR_INIT,
    ITR_SEEK,
    ITR_GET,
    ITR_CLOSE,
    _num_stats_
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
    FileHandlePool(std::vector<std::string> filenames, int count) {
        fdb_status status;
        fdb_config fconfig = fdb_get_default_config();
        fconfig.multi_kv_instances = false;
        fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
        for (int i = 0; i < count; ++i) {
            fdb_file_handle *dbfile;
            fdb_kvs_handle *db;
            status = fdb_open(&dbfile,
                              filenames.at(i % filenames.size()).c_str(),
                              &fconfig);
            fdb_assert(status == FDB_RESULT_SUCCESS, status, FDB_RESULT_SUCCESS);
            status = fdb_kvs_open_default(dbfile, &db, &kvs_config);
            fdb_assert(status == FDB_RESULT_SUCCESS, status, FDB_RESULT_SUCCESS);
            PoolEntry *pe = new PoolEntry(i, true, dbfile, db);
            pool_vector.push_back(pe);
        }

        mutex_init(&statlock);

        // Set up StatAggregator
        sa = new StatAggregator(_num_stats_, 1);

        sa->t_stats[SET][0].name = "set";
        sa->t_stats[COMMIT][0].name = "commit";
        sa->t_stats[GET][0].name = "get";
        sa->t_stats[IN_MEM_SNAP][0].name = "in-mem snapshot";

        sa->t_stats[ITR_INIT][0].name = "iterator-init";
        sa->t_stats[ITR_GET][0].name = "iterator-get";
        sa->t_stats[ITR_CLOSE][0].name = "iterator-close";

        samples = 0;
    }

    virtual ~FileHandlePool() {
        fdb_status status;
        for (size_t i = 0; i < pool_vector.size(); ++i) {
            PoolEntry *pe = pool_vector.at(i);
            if (pe) {
                status = fdb_kvs_close(pe->db);
                fdb_assert(status == FDB_RESULT_SUCCESS,
                           status, FDB_RESULT_SUCCESS);
                status = fdb_close(pe->dbfile);
                fdb_assert(status == FDB_RESULT_SUCCESS,
                           status, FDB_RESULT_SUCCESS);
                delete pe;
            }
        }
        pool_vector.clear();

        // Delete StatAggregator
        delete sa;

        mutex_destroy(&statlock);
    }

    /**
     * Acquire a handle-set and its index that is currently available,
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
     * Set the handle-set at an index to available, indicating the current
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

    void addStatToAgg(int index, const char* name) {
        mutex_lock(&statlock);
        if (sa) {
            sa->t_stats[index][0].name = name;
        }
        mutex_unlock(&statlock);
    }

    /**
     * Collects stats - invoked by concurrent threads, hence the mutex.
     */
    void collectStat(int index, uint64_t diff) {
        mutex_lock(&statlock);
        if (sa && index < _num_stats_) {
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
                fdb_assert(status == FDB_RESULT_SUCCESS,
                           status, FDB_RESULT_SUCCESS);

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

/**
 * This class inherits functionality of FileHandlePool and in
 * addition to this maintains a pool of snapshot handles.
 */
class SnapHandlePool : public FileHandlePool {
public:
    SnapHandlePool(std::vector<std::string> filenames, int count)
        : FileHandlePool(filenames, count) {
        snap_pool_vector.resize(count, nullptr);
        mutex_init(&snaplock);

        addStatToAgg(CLONE_SNAP, "clone snapshot");
        addStatToAgg(ITR_SEEK, "iterator-seek");
    }

    virtual ~SnapHandlePool() {
        fdb_status status;
        mutex_lock(&snaplock);
        for (size_t i = 0; i < snap_pool_vector.size(); ++i) {
            PoolEntry *pe = snap_pool_vector.at(i);
            if (pe) {
                status = fdb_kvs_close(pe->db);
                fdb_assert(status == FDB_RESULT_SUCCESS,
                           status, FDB_RESULT_SUCCESS);
                delete pe;
            }
        }
        snap_pool_vector.clear();
        mutex_unlock(&snaplock);

        mutex_destroy(&snaplock);
    }

    /**
     * Adds a new snapshot handle to the vector at the specified
     * index of the snapshot handle pool. If one is already in place,
     * the older handle is closed and replaced with the new handle.
     */
    void addNewSnapHandle(int index, fdb_kvs_handle *kvsHandle) {
        fdb_kvs_handle *snap_handle = nullptr;
        ts_nsec beginSnap = get_monotonic_ts();
        fdb_status status = fdb_snapshot_open(kvsHandle,
                                              &snap_handle,
                                              FDB_SNAPSHOT_INMEM);
        ts_nsec endSnap = get_monotonic_ts();
        fdb_assert(status == FDB_RESULT_SUCCESS, status, FDB_RESULT_SUCCESS);

        collectStat(IN_MEM_SNAP, ts_diff(beginSnap, endSnap));

        mutex_lock(&snaplock);
        PoolEntry *pe = snap_pool_vector.at(index);
        if (pe) {
            status = fdb_kvs_close(pe->db);
            fdb_assert(status == FDB_RESULT_SUCCESS, status, FDB_RESULT_SUCCESS);
            delete pe;
        }
        snap_pool_vector[index] = new PoolEntry(index, true,
                                                nullptr, snap_handle);
        mutex_unlock(&snaplock);
    }

    /**
     * Acquires a clone of the snapshot handle at a random index in
     * the snapshot handle pool.
     */
    fdb_kvs_handle *getCloneOfASnapHandle() {
        fdb_kvs_handle *snapClone = nullptr;
        mutex_lock(&snaplock);
        int index = rand() % snap_pool_vector.size();
        PoolEntry *pe = snap_pool_vector.at(index);
        if (pe) {
            ts_nsec beginClone = get_monotonic_ts();
            fdb_status status = fdb_snapshot_open(pe->db, &snapClone,
                                                  FDB_SNAPSHOT_INMEM);
            ts_nsec endClone = get_monotonic_ts();
            fdb_assert(status == FDB_RESULT_SUCCESS, status, FDB_RESULT_SUCCESS);

            collectStat(CLONE_SNAP, ts_diff(beginClone, endClone));
        }
        mutex_unlock(&snaplock);
        return snapClone;
    }

private:
    std::vector<PoolEntry *> snap_pool_vector;
    mutex_t snaplock;
};

struct ops_args {
    FileHandlePool *hp;
    const float time;
    bool snapPoolAvailable;
};

static void *invoke_writer_ops(void *args) {
    struct ops_args *oa = static_cast<ops_args *>(args);
    int i = 0, j;
    fdb_status status;
    std::chrono::time_point<std::chrono::system_clock> start, end;
    start = std::chrono::system_clock::now();

    while (true) {
        // Acquire handles from pool
        fdb_file_handle *dbfile = nullptr;
        fdb_kvs_handle *db = nullptr;
        const int index = oa->hp->getAvailableResource(&dbfile, &db);

        char keybuf[256], bodybuf[256];

        // Start transaction
        status = fdb_begin_transaction(dbfile, FDB_ISOLATION_READ_COMMITTED);
        fdb_assert(status == FDB_RESULT_SUCCESS, status, FDB_RESULT_SUCCESS);

        // Issue a batch of 10 sets
        j = 10;
        while (--j != 0) {
            sprintf(keybuf, "key%d", i);
            sprintf(bodybuf, "body%d", i);

            ts_nsec beginSet = get_monotonic_ts();
            status = fdb_set_kv(db,
                                (void*)keybuf, strlen(keybuf) + 1,
                                (void*)bodybuf, strlen(bodybuf) + 1);
            ts_nsec endSet = get_monotonic_ts();
            fdb_assert(status == FDB_RESULT_SUCCESS, status, FDB_RESULT_SUCCESS);
            oa->hp->collectStat(SET, ts_diff(beginSet, endSet));
            ++i;
        }

        // End transaction (Commit)
        ts_nsec beginCommit = get_monotonic_ts();
        status = fdb_end_transaction(dbfile, FDB_COMMIT_NORMAL);
        ts_nsec endCommit = get_monotonic_ts();
        fdb_assert(status == FDB_RESULT_SUCCESS, status, FDB_RESULT_SUCCESS);

        oa->hp->collectStat(COMMIT, ts_diff(beginCommit, endCommit));

        // Create a snapshot handle if snap handle pool is in use
        if (oa->snapPoolAvailable) {
            (static_cast<SnapHandlePool*>(oa->hp))->addNewSnapHandle(index, db);
        }

        // Return resource to pool
        oa->hp->returnResourceToPool(index);

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

void file_handle_reader_ops(FileHandlePool *fhp, int tracker) {
    fdb_status status;

    // Acquire handles from pool
    fdb_file_handle *dbfile = nullptr;
    fdb_kvs_handle *db = nullptr;
    fdb_kvs_handle *snap_handle = nullptr;
    const int index = fhp->getAvailableResource(&dbfile, &db);

    // Create an in-memory snapshot
    ts_nsec beginSnap = get_monotonic_ts();
    status = fdb_snapshot_open(db, &snap_handle, FDB_SNAPSHOT_INMEM);
    ts_nsec endSnap = get_monotonic_ts();
    fdb_assert(status == FDB_RESULT_SUCCESS, status, FDB_RESULT_SUCCESS);

    fhp->collectStat(IN_MEM_SNAP, ts_diff(beginSnap, endSnap));

    // Iterator ops using the snapshot handle once every 100 times
    if (tracker % 100 == 0) {
        fdb_iterator *iterator = nullptr;
        fdb_doc *rdoc = nullptr;
        ts_nsec begin, end;

        // Initialize iterator
        begin = get_monotonic_ts();
        status = fdb_iterator_init(snap_handle, &iterator,
                                   nullptr, 0, nullptr, 0,
                                   FDB_ITR_NONE);
        end = get_monotonic_ts();
        fdb_assert(status == FDB_RESULT_SUCCESS, status, FDB_RESULT_SUCCESS);

        fhp->collectStat(ITR_INIT, ts_diff(begin, end));

        // Get using iterator
        begin = get_monotonic_ts();
        status = fdb_iterator_get(iterator, &rdoc);
        end = get_monotonic_ts();
        if (status == FDB_RESULT_SUCCESS) {
            fdb_doc_free(rdoc);
            fhp->collectStat(ITR_GET, ts_diff(begin, end));
        } else {
            // Block not found, no keys available
            fdb_assert(status == FDB_RESULT_ITERATOR_FAIL,
                       status, FDB_RESULT_ITERATOR_FAIL);
        }

        // Close iterator
        begin = get_monotonic_ts();
        status = fdb_iterator_close(iterator);
        end = get_monotonic_ts();
        fdb_assert(status == FDB_RESULT_SUCCESS, status, FDB_RESULT_SUCCESS);

        fhp->collectStat(ITR_CLOSE, ts_diff(begin, end));
    } else {
        // Try fetching a random doc, using the snapshot handle
        void *value = nullptr;
        size_t valuelen;
        char keybuf[256], bodybuf[256];

        fdb_file_info info;
        status = fdb_get_file_info(dbfile, &info);
        fdb_assert(status == FDB_RESULT_SUCCESS, status, FDB_RESULT_SUCCESS);
        int i = (info.doc_count > 0) ? rand() % info.doc_count : 0;

        sprintf(keybuf, "key%d", i);
        sprintf(bodybuf, "body%d", i);
        ts_nsec beginGet = get_monotonic_ts();
        status = fdb_get_kv(snap_handle,
                            (void*)keybuf, strlen(keybuf) + 1,
                            &value, &valuelen);
        ts_nsec endGet = get_monotonic_ts();
        if (status == FDB_RESULT_SUCCESS) {
            assert(memcmp(value, bodybuf, valuelen) == 0);
            fdb_free_block(value);
            fhp->collectStat(GET, ts_diff(beginGet, endGet));
        } else { // If doc_count is zero
            fdb_assert(status == FDB_RESULT_KEY_NOT_FOUND,
                       status, FDB_RESULT_KEY_NOT_FOUND);
        }
    }

    // Close snapshot handle
    status = fdb_kvs_close(snap_handle);
    fdb_assert(status == FDB_RESULT_SUCCESS, status, FDB_RESULT_SUCCESS);

    // Return resource to pool
    fhp->returnResourceToPool(index);
}

void snap_handle_reader_ops(SnapHandlePool *shp) {
    fdb_status status;
    fdb_kvs_handle *snapClone = shp->getCloneOfASnapHandle();
    if (!snapClone) {
        // No snapshot handle available yet
        return;
    }

    fdb_iterator *iterator = nullptr;
    fdb_doc *rdoc = nullptr;
    ts_nsec begin, end;

    // Initialize iterator
    begin = get_monotonic_ts();
    status = fdb_iterator_init(snapClone, &iterator,
                               nullptr, 0, nullptr, 0,
                               FDB_ITR_NONE);
    end = get_monotonic_ts();
    fdb_assert(status == FDB_RESULT_SUCCESS, status, FDB_RESULT_SUCCESS);

    shp->collectStat(ITR_INIT, ts_diff(begin, end));

    // Seek random key with iterator
    char keybuf[256];
    int i = rand() % 100;
    sprintf(keybuf, "key%d", i);
    begin = get_monotonic_ts();
    status = fdb_iterator_seek(iterator,
                               (void*)keybuf, strlen(keybuf),
                               FDB_ITR_SEEK_HIGHER);
    end = get_monotonic_ts();
    if (status == FDB_RESULT_SUCCESS) {
        shp->collectStat(ITR_SEEK, ts_diff(begin, end));
    } else {
        // Block not found, no keys available
        fdb_assert(status == FDB_RESULT_ITERATOR_FAIL,
                   status, FDB_RESULT_ITERATOR_FAIL);
    }

    // Get using iterator
    begin = get_monotonic_ts();
    status = fdb_iterator_get(iterator, &rdoc);
    end = get_monotonic_ts();
    if (status == FDB_RESULT_SUCCESS) {
        fdb_doc_free(rdoc);
        shp->collectStat(ITR_GET, ts_diff(begin, end));
    } else {
        fdb_assert(status == FDB_RESULT_ITERATOR_FAIL,
                   status, FDB_RESULT_ITERATOR_FAIL);
    }

    // Close iterator
    begin = get_monotonic_ts();
    status = fdb_iterator_close(iterator);
    end = get_monotonic_ts();
    fdb_assert(status == FDB_RESULT_SUCCESS, status, FDB_RESULT_SUCCESS);

    shp->collectStat(ITR_CLOSE, ts_diff(begin, end));

    // Close snapshot clone
    status = fdb_kvs_close(snapClone);
    fdb_assert(status == FDB_RESULT_SUCCESS, status, FDB_RESULT_SUCCESS);
}

static void *invoke_reader_ops(void *args) {
    struct ops_args *oa = static_cast<ops_args *>(args);
    std::chrono::time_point<std::chrono::system_clock> start, end;
    start = std::chrono::system_clock::now();

    int tracker = 0;
    while (true) {
        if (!oa->snapPoolAvailable) {
            file_handle_reader_ops(oa->hp, ++tracker);
        } else {
            snap_handle_reader_ops(static_cast<SnapHandlePool*>(oa->hp));
        }

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

/**
 * Test that invokes reader(s) and writer(s) that work
 * with the shared file handle pool or writers(s) that
 * work with the file handle pool and readers(s) that
 * work with the snap handle pool.
 */
void test_readers_writers_with_handle_pool(int nhandles,
                                           int nfiles,
                                           int writers,
                                           int readers,
                                           bool useSnapHandlePool,
                                           int time) {
    TEST_INIT();
    memleak_start();

    int r;

    r = system(SHELL_DEL" usecase_test* > errorlog.txt");
    (void)r;

    if (nfiles < 1) {
        fprintf(stderr, "[ERROR] Invalid number of files: %d!", nfiles);
        return;
    }

    // Set filename(s)
    std::vector<std::string> files;
    for (int i = 1; i <= nfiles; ++i) {
        std::string filename("./usecase_test" + std::to_string(i));
        files.push_back(filename);
    }

    if (writers + readers < 1) {
        fprintf(stderr, "[ERROR] Invalid number of readers (%d)/writers (%d)!",
                readers, writers);
        return;
    }

    // Prepare handle pool
    FileHandlePool *hp;
    if (!useSnapHandlePool) {
        hp = new FileHandlePool(files, nhandles);
    } else {
        hp = new SnapHandlePool(files, nhandles);
    }

    thread_t *threads = new thread_t[writers + readers];

    struct ops_args oa{hp, (float)time, useSnapHandlePool};

    int threadid = 0;
    // Spawn writer thread(s)
    for (int i = 0; i < writers; ++i) {
        thread_create(&threads[threadid++], invoke_writer_ops, &oa);
    }

    // Spawn reader thread(s)
    for (int i = 0; i < readers; ++i) {
        thread_create(&threads[threadid++], invoke_reader_ops, &oa);
    }

    assert(threadid == readers + writers);

    // Wait for child threads
    for (int j = 0; j < (readers + writers); ++j) {
        int r = thread_join(threads[j], nullptr);
        assert(r == 0);
    }
    delete[] threads;

    std::string test_title(std::to_string(nhandles) + "H, " +
                           std::to_string(nfiles) + "F, " +
                           std::to_string(writers) + "RW, " +
                           std::to_string(readers) + "RO - ");
    test_title += useSnapHandlePool ? "Seperate Pool test" : "Shared Pool test";

    /* Print Collected Stats */
    hp->displayCollection(test_title.c_str());

#ifdef __DEBUG_USECASE
    hp->printHandleStats();
#endif

    /* cleanup */
    delete hp;

    /* shutdown */
    fdb_shutdown();

#ifndef __DEBUG_USECASE
    r = system(SHELL_DEL" usecase_test* > errorlog.txt");
    (void)r;
#endif

    memleak_end();
    TEST_RESULT(test_title.c_str());
}

int main() {

    /* Test single writer with multiple readers sharing a common
       pool of file handles, over single file for 30 seconds */
    test_readers_writers_with_handle_pool(10       /*number of handles*/,
                                          1        /*number of files*/,
                                          1        /*writer count*/,
                                          4        /*reader count*/,
                                          false    /*do not use snap handle pool*/,
                                          30       /*test time in seconds*/);

    /* Test multiple writers with multiple readers sharing a common
       pool of file handles, over single file for 30 seconds */
    test_readers_writers_with_handle_pool(10       /*number of handles*/,
                                          1        /*number of files*/,
                                          4        /*writer count*/,
                                          4        /*reader count*/,
                                          false    /*do not use snap handle pool*/,
                                          30       /*test time in seconds*/);

    /* Test multiple writers sharing a common pool of file handles
       and multiple readers sharing a common pool of snapshot handles,
       over single file for 30 seconds */
    test_readers_writers_with_handle_pool(5        /*number of handles*/,
                                          1        /*number of files*/,
                                          4        /*writer count*/,
                                          4        /*reader count*/,
                                          true     /*use snap handle pool*/,
                                          30       /*test time in seconds*/);

    /* Test multiple writers sharing a common pool of file handles
       and multiple readers sharing a common pool of snapshot handles,
       over multiple files for 30 seconds */
    test_readers_writers_with_handle_pool(10       /*number of handles*/,
                                          5        /*number of files*/,
                                          4        /*writer count*/,
                                          4        /*reader count*/,
                                          true     /*use snap handle pool*/,
                                          30       /*test time in seconds*/);

    return 0;
}
