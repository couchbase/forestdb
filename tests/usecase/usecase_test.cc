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

#include <algorithm>
#include <atomic>
#include <chrono>
#include <map>
#include <string>
#include <vector>

#include "libforestdb/forestdb.h"
#include "atomic.h"
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
              std::string _kvsname,
              fdb_file_handle *_dbfile,
              fdb_kvs_handle *_db) {
        index = _index;
        available.store(_avail);
        kvsname = _kvsname;
        dbfile = _dbfile;
        db = _db;
    }

    int index;
    std::atomic<bool> available;
    std::string kvsname;
    fdb_file_handle *dbfile;
    fdb_kvs_handle *db;
};

/**
 * This class maintains a pool of file and kvs handles.
 */
class FileHandlePool {
public:
    FileHandlePool(std::vector<std::string> filenames, int kvstore_count,
                   int num_handles_per_kvstore, bool create_default_kvs,
                   bool use_sequence_tree) {
        fdb_status status;
        file_config = fdb_get_default_config();
        if (use_sequence_tree) {
            // enable seqtree since get_byseq
            file_config.seqtree_opt = FDB_SEQTREE_USE;
        }
        kvs_config = fdb_get_default_kvs_config();
        int index = 0;
        for (int i = 0; i < kvstore_count; ++i) {
            for (int j = 0; j < num_handles_per_kvstore; ++j) {
                fdb_file_handle *dbfile;
                fdb_kvs_handle *db;
                std::string filename = filenames.at(i % filenames.size());
                std::string kvs;
                status = fdb_open(&dbfile, filename.c_str(), &file_config);
                fdb_assert(status == FDB_RESULT_SUCCESS, status, FDB_RESULT_SUCCESS);
                if (create_default_kvs) {
                    kvs.assign(DEFAULT_KVS_NAME);
                    status = fdb_kvs_open_default(dbfile, &db, &kvs_config);
                } else {
                    kvs.assign(filename + "_" + std::to_string(i));
                    status = fdb_kvs_open(dbfile, &db, kvs.c_str(), &kvs_config);
                    kvs_file_map[kvs] = filename;
                }
                fdb_assert(status == FDB_RESULT_SUCCESS, status, FDB_RESULT_SUCCESS);
                PoolEntry *pe = new PoolEntry(index++, true, kvs, dbfile, db);
                pool_vector.push_back(pe);
            }
        }

        if (init_rw_lock(&pool_vector_lock) != 0) {
            fprintf(stderr, "Error in init() of rw_lock\n");
            abort();
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

        if (destroy_rw_lock(&pool_vector_lock) != 0) {
            fprintf(stderr, "Error in destroy() of rw_lock\n");
            abort();
        }

        // Delete StatAggregator
        delete sa;

        mutex_destroy(&statlock);
    }

    /**
     * Acquire a handle-set and its index that is currently available,
     * in the process, the handle set will be marked as unavailable for
     * any other user.
     */
    PoolEntry* getAvailableResource() {
        PoolEntry *pe;;
        while (true) {
            if (reader_lock(&pool_vector_lock) == 0) {
                int index = rand() % pool_vector.size();
                bool inverse = true;
                pe = pool_vector.at(index);
                if (pe &&
                    pe->available.compare_exchange_strong(inverse, false)) {
                    reader_unlock(&pool_vector_lock);
                    break;
                }
                reader_unlock(&pool_vector_lock);
            } else {
                fprintf(stderr, "Error in acquiring reader lock!\n");
                abort();
            }
        }
        return pe;
    }

    /**
     * Acquire handle-set at specified index.
     */
    void getResourceAtIndex(int index,
                            fdb_file_handle **dbfile, fdb_kvs_handle **db) {
        while (true) {
            if (reader_lock(&pool_vector_lock) == 0) {
                bool inverse = true;
                PoolEntry *pe = pool_vector.at(index % pool_vector.size());
                if (pe && pe->available.compare_exchange_strong(inverse, false)) {
                    *dbfile = pe->dbfile;
                    *db = pe->db;
                    reader_unlock(&pool_vector_lock);
                    return;
                }
                reader_unlock(&pool_vector_lock);
            } else {
                fprintf(stderr, "Error in acquiring reader lock!\n");
                abort();
            }
        }
    }

    /**
     * Set the handle-set at an index to available, indicating the current
     * user will not be using the handles anymore.
     */
    void returnResourceToPool(int index) {
        if (reader_lock(&pool_vector_lock) == 0) {
            PoolEntry *pe = pool_vector.at(index);
            if (!pe) {
                fprintf(stderr, "Invalid entry!\n");
                reader_unlock(&pool_vector_lock);
                return;
            }
            bool inverse = false;
            if (!pe->available.compare_exchange_strong(inverse, true)) {
                fprintf(stderr, "Handles were likely used by another thread!");
                assert(false);
            }
            reader_unlock(&pool_vector_lock);
        } else {
            fprintf(stderr, "Error in acquiring reader lock!\n");
            abort();
        }

    }

    /**
     * Return the pointer borrowed back to pool.
     */
    void returnResourceToPool(PoolEntry *pe) {
        if (reader_lock(&pool_vector_lock) == 0) {
            if (!pe) {
                fprintf(stderr, "Invalid entry!\n");
                reader_unlock(&pool_vector_lock);
                return;
            }
            bool inverse = false;
            if (!pe->available.compare_exchange_strong(inverse, true)) {
                fprintf(stderr, "Handles were likely used by another thread!");
                assert(false);
            }
            reader_unlock(&pool_vector_lock);
        } else {
            fprintf(stderr, "Error in acquiring reader lock!\n");
            abort();
        }
    }

    /**
     * Moves kvstore from one file to another, in the process:
     * delete handles to old kvstore from pool entry and replace
     * them with handles to the kvstore in the new file.
     */
    void shiftPoolEntries(std::string kvs_name,
                          std::string new_filename) {
        if (kvs_file_map.empty()) {
            // kvs map not available
            fprintf(stderr,
                    "kvs_file_map unavailable => no non-default kv stores!\n");
            abort();
        } else if (kvs_name.empty() || new_filename.empty()) {
            fprintf(stderr,
                    "Kvs name and/or new filename strings are empty!\n");
            abort();
        }

        fdb_status status = FDB_RESULT_SUCCESS;
        size_t i = 0;
        while (true) {
            if (writer_lock(&pool_vector_lock) == 0) {
                if (i >= pool_vector.size()) {
                    writer_unlock(&pool_vector_lock);
                    return;
                }
                PoolEntry *pe = pool_vector.at(i);
                if (pe && kvs_name.compare(pe->kvsname) == 0) {
                    bool inverse = true;
                    if (!pe->available.compare_exchange_strong(inverse, false)) {
                        writer_unlock(&pool_vector_lock);
                        continue;
                    }
                    // Remove old entry
                    status = fdb_kvs_close(pe->db);
                    fdb_assert(status == FDB_RESULT_SUCCESS,
                               status, FDB_RESULT_SUCCESS);
                    status = fdb_kvs_remove(pe->dbfile, kvs_name.c_str());
                    if (status != FDB_RESULT_SUCCESS) {
                        // Consider the possibility that there are
                        // more open handles on the kv store
                        fdb_assert((status == FDB_RESULT_KV_STORE_BUSY
                                    || status == FDB_RESULT_FAIL_BY_COMPACTION
                                    || status == FDB_RESULT_HANDLE_BUSY),
                                   status, FDB_RESULT_SUCCESS);
                    }
                    status = fdb_close(pe->dbfile);
                    fdb_assert(status == FDB_RESULT_SUCCESS,
                               status, FDB_RESULT_SUCCESS);
                    pool_vector.erase(std::remove(pool_vector.begin(),
                                                  pool_vector.end(),
                                                  pe),
                                      pool_vector.end());
                    delete pe;

                    // Add new entry
                    fdb_file_handle *dbfile;
                    fdb_kvs_handle *db;
                    status = fdb_open(&dbfile, new_filename.c_str(),
                                      &file_config);
                    fdb_assert(status == FDB_RESULT_SUCCESS,
                               status, FDB_RESULT_SUCCESS);
                    status = fdb_kvs_open(dbfile, &db, kvs_name.c_str(),
                                          &kvs_config);
                    fdb_assert(status == FDB_RESULT_SUCCESS,
                               status, FDB_RESULT_SUCCESS);
                    kvs_file_map[kvs_name] = new_filename;
                    PoolEntry *new_pe = new PoolEntry(i, true,
                                                      kvs_name,
                                                      dbfile, db);
                    pool_vector.push_back(new_pe);
                }
                i++;
                writer_unlock(&pool_vector_lock);
            } else {
                fprintf(stderr, "Error in acquiring writer lock!\n");
                abort();
            }
        }
    }

    /**
     * Fetch a random entry from the kvs_file_map.
     */
    std::pair<std::string, std::string> fetchRandomAvailableKvs() {
        if (kvs_file_map.empty()) {
            // kvs map not available
            fprintf(stderr,
                    "kvs_file_map unavailable => no non-default kv stores!\n");
            abort();
        }

        int index = rand() % kvs_file_map.size();
        for (auto &it : kvs_file_map) {
            if (index-- == 0) {
                return it;
            }
        }
        fprintf(stderr, "[ERROR] Cannot get here, unless kvs_file_map had "
                        "parallel access, which is not allowed at the "
                        "moment!\n");
        abort();
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
            sa->aggregateAndPrintStats(title, samples, "µs");
        }
    }

    /**
     * Print availabity status of the handle sets at every index in the
     * pool.
     */
    void printPoolVector() {
        if (reader_lock(&pool_vector_lock) == 0) {
            fprintf(stderr, "---------------------\n");
            for (size_t i = 0; i < pool_vector.size(); ++i) {
                fprintf(stderr, "Index: %d Available: %d\n",
                        (pool_vector.at(i))->index,
                        (pool_vector.at(i))->available.load() ? 1 : 0);
            }
            fprintf(stderr, "---------------------\n");
            reader_unlock(&pool_vector_lock);
        } else {
            fprintf(stderr, "Error in acquiring reader lock!\n");
            abort();
        }
    }

    /**
     * Print FDB_LATENCY_STATS, for all file handles.
     */
    void printHandleStats() {
        if (reader_lock(&pool_vector_lock) == 0) {
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

            s->aggregateAndPrintStats("FDB_STATS", pool_vector.size(), "µs");
            delete s;
            reader_unlock(&pool_vector_lock);
        } else {
            fprintf(stderr, "Error in acquiring reader lock!\n");
            abort();
        }
    }

private:
    // File config
    fdb_config file_config;
    // Kvs config
    fdb_kvs_config kvs_config;
    // Vector pool of file/kvs handles
    std::vector<PoolEntry *> pool_vector;
    // Read/Write lock to pool vector
    fdb_rw_lock pool_vector_lock;
    // Map of non-default KV stores to filenames
    std::map<std::string, std::string> kvs_file_map;
    // Number of stat samples
    int samples;
    // Pointer to the stat aggregator class
    StatAggregator *sa;
    // Mutex to protect stat collection & aggregation
    mutex_t statlock;
};

/**
 * This class inherits functionality of FileHandlePool and in
 * addition to this maintains a pool of snapshot handles.
 */
class SnapHandlePool : public FileHandlePool {
public:
    SnapHandlePool(std::vector<std::string> filenames, int count,
                   bool create_default_kvs, bool use_sequence_tree)
        : FileHandlePool(filenames, count, 1, create_default_kvs,
                         use_sequence_tree) {
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

        // Fetch kvs_info to get the name of the KVS instance
        fdb_kvs_info kvs_info;
        status = fdb_get_kvs_info(snap_handle, &kvs_info);
        fdb_assert(status == FDB_RESULT_SUCCESS,
                   status, FDB_RESULT_SUCCESS);

        snap_pool_vector[index] = new PoolEntry(index, true,
                                                std::string(kvs_info.name),
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
        PoolEntry *pe = oa->hp->getAvailableResource();

        char keybuf[256], bodybuf[256];

        // Start transaction
        status = fdb_begin_transaction(pe->dbfile, FDB_ISOLATION_READ_COMMITTED);
        fdb_assert(status == FDB_RESULT_SUCCESS, status, FDB_RESULT_SUCCESS);

        // Issue a batch of 10 sets
        j = 10;
        while (--j != 0) {
            sprintf(keybuf, "key%d", i);
            sprintf(bodybuf, "body%d", i);

            ts_nsec beginSet = get_monotonic_ts();
            status = fdb_set_kv(pe->db,
                                (void*)keybuf, strlen(keybuf) + 1,
                                (void*)bodybuf, strlen(bodybuf) + 1);
            ts_nsec endSet = get_monotonic_ts();
            fdb_assert(status == FDB_RESULT_SUCCESS, status, FDB_RESULT_SUCCESS);
            oa->hp->collectStat(SET, ts_diff(beginSet, endSet));
            ++i;
        }

        // End transaction (Commit)
        ts_nsec beginCommit = get_monotonic_ts();
        status = fdb_end_transaction(pe->dbfile, FDB_COMMIT_NORMAL);
        ts_nsec endCommit = get_monotonic_ts();
        fdb_assert(status == FDB_RESULT_SUCCESS, status, FDB_RESULT_SUCCESS);

        oa->hp->collectStat(COMMIT, ts_diff(beginCommit, endCommit));

        // Create a snapshot handle if snap handle pool is in use
        if (oa->snapPoolAvailable) {
            (static_cast<SnapHandlePool*>(oa->hp))->addNewSnapHandle(pe->index,
                                                                     pe->db);
        }

        // Return resource to pool
        oa->hp->returnResourceToPool(pe);

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
    fdb_kvs_handle *snap_handle = nullptr;
    PoolEntry *pe = fhp->getAvailableResource();

    // Create an in-memory snapshot
    ts_nsec beginSnap = get_monotonic_ts();
    status = fdb_snapshot_open(pe->db, &snap_handle, FDB_SNAPSHOT_INMEM);
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
        status = fdb_get_file_info(pe->dbfile, &info);
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
    fhp->returnResourceToPool(pe);
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
                                           bool createDefaultKvs,
                                           bool useSnapHandlePool,
                                           int time) {
    TEST_INIT();
    memleak_start();

    int r;

    r = system(SHELL_DEL" uc_test* > errorlog.txt");
    (void)r;

    if (nfiles < 1) {
        fprintf(stderr, "[ERROR] Invalid number of files: %d!", nfiles);
        return;
    }

    if (writers + readers < 1) {
        fprintf(stderr, "[ERROR] Invalid number of readers (%d)/writers (%d)!",
                readers, writers);
        return;
    }

    // Set filename(s)
    std::vector<std::string> files;
    for (int i = 1; i <= nfiles; ++i) {
        std::string filename("./uc_test" + std::to_string(i));
        files.push_back(filename);
    }

    // Prepare handle pool
    FileHandlePool *hp;
    if (!useSnapHandlePool) {
        hp = new FileHandlePool(files, nhandles, 1, createDefaultKvs, false);
    } else {
        hp = new SnapHandlePool(files, nhandles, createDefaultKvs, false);
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
    for (int i = 0; i < (readers + writers); ++i) {
        r = thread_join(threads[i], nullptr);
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
    r = system(SHELL_DEL" uc_test* > errorlog.txt");
    (void)r;
#endif

    memleak_end();
    TEST_RESULT(test_title.c_str());
}

struct compact_args {
    std::string filename;
    std::atomic<bool> terminate_compaction;
};

void *compact_thread(void *args) {
    struct compact_args *ca = static_cast<struct compact_args *>(args);
    fdb_config config = fdb_get_default_config();
    fdb_file_handle *dbfile;
    std::string curfilename, nextfilename = ca->filename;
    int revID = 0;
    while (!ca->terminate_compaction) {
        curfilename = nextfilename;
        nextfilename = ca->filename + "." + std::to_string(++revID);
        fdb_status status = FDB_RESULT_SUCCESS;
        status = fdb_open(&dbfile, curfilename.c_str(), &config);
        fdb_assert(status == FDB_RESULT_SUCCESS, status, FDB_RESULT_SUCCESS);
#ifdef __DEBUG_USECASE
        fprintf(stderr, "Compacting %s to %s\n", curfilename.c_str(), nextfilename.c_str());
#endif
        status = fdb_compact(dbfile, nextfilename.c_str());
        fdb_assert(status == FDB_RESULT_SUCCESS, status, FDB_RESULT_SUCCESS);
        status = fdb_close(dbfile);
        fdb_assert(status == FDB_RESULT_SUCCESS, status, FDB_RESULT_SUCCESS);
    }
    return nullptr;
}

/**
 * Test that creates specified number of kvstores on a single file,
 * and writes to them all, while compacting the file.
 */
void test_writes_on_kv_stores_with_compaction(uint16_t numKvStores,
                                              int itemCountPerStore) {
    TEST_INIT();
    memleak_start();

    int r;

    r = system(SHELL_DEL" uc_test* > errorlog.txt");
    (void)r;

    if (numKvStores < 1) {
        fprintf(stderr, "[ERROR] Illegal number for kv store count: %u!\n",
                        numKvStores);
        return;
    }

    std::vector<std::string> filenames;
    filenames.push_back("uc_test");

    /* Prepare file handle pool */
    FileHandlePool *fhp = new FileHandlePool(filenames, numKvStores, 1,
                                             false, true);

    fdb_status status;
    fdb_file_handle *dbfile;
    fdb_kvs_handle *db;
    char keybuf[256], bodybuf[256];

    thread_t tid(0);
    void *ret;

    struct compact_args args;
    args.filename = filenames.at(0);
    args.terminate_compaction.store(false);
    thread_create(&tid, compact_thread, &args);

    for (int i = 0; i < itemCountPerStore; ++i) {
        for (int j = 0; j < numKvStores; ++j) {
            fhp->getResourceAtIndex(j, &dbfile, &db);

            sprintf(keybuf, "key_%d_%d", i, j);
            sprintf(bodybuf, "body_%d_%d", i, j);

            status = fdb_set_kv(db,
                                (void*)keybuf, strlen(keybuf) + 1,
                                (void*)bodybuf, strlen(bodybuf) + 1);
            fdb_assert(status == FDB_RESULT_SUCCESS, status, FDB_RESULT_SUCCESS);

            fhp->returnResourceToPool(j);
        }

        status = fdb_commit(dbfile, FDB_COMMIT_NORMAL);
        fdb_assert(status == FDB_RESULT_SUCCESS, status, FDB_RESULT_SUCCESS);
    }

    args.terminate_compaction.store(true);
    thread_join(tid, &ret);

    // Get total item count in disk
    size_t total_doc_count = 0;
    for (int k = 0; k < numKvStores; ++k) {
        fhp->getResourceAtIndex(k, &dbfile, &db);

        fdb_iterator *itr;
        status = fdb_iterator_sequence_init(db, &itr, 0, 0, FDB_ITR_NONE);
        fdb_assert(status == FDB_RESULT_SUCCESS, status, FDB_RESULT_SUCCESS);

        do {
            ++total_doc_count;
        } while (fdb_iterator_next(itr) == FDB_RESULT_SUCCESS);

        fdb_iterator_close(itr);

        fhp->returnResourceToPool(k);
    }

    /* cleanup */
    delete fhp;

    /* shutdown */
    fdb_shutdown();

    /* validate */
    fdb_assert(total_doc_count ==
               static_cast<size_t>(numKvStores * itemCountPerStore),
               total_doc_count, numKvStores * itemCountPerStore);

#ifndef __DEBUG_USECASE
    r = system(SHELL_DEL" uc_test* > errorlog.txt");
    (void)r;
#endif

    memleak_end();
    TEST_RESULT("Writes-On-Multiple-KV-Stores-With-Compaction test");
}

static std::atomic<bool> exit_execution(false);

void *thread_that_issues_writes(void *args) {
    FileHandlePool *fhp = static_cast<FileHandlePool *>(args);
    int i = 0;
    fdb_status status = FDB_RESULT_SUCCESS;

    while (true) {
        // Acquire handles from pool
        PoolEntry *pe = fhp->getAvailableResource();

        char keybuf[256], bodybuf[256];

        // Issue a batch of 10 sets
        int  j = 10;
        while (--j != 0) {
            sprintf(keybuf, "key%d", i);
            sprintf(bodybuf, "body%d", i);

            status = fdb_set_kv(pe->db,
                                (void*)keybuf, strlen(keybuf) + 1,
                                (void*)bodybuf, strlen(bodybuf) + 1);
            fdb_assert(status == FDB_RESULT_SUCCESS, status, FDB_RESULT_SUCCESS);
            ++i;
        }
        status = fdb_commit(pe->dbfile, FDB_COMMIT_NORMAL);
        fdb_assert(status == FDB_RESULT_SUCCESS, status, FDB_RESULT_SUCCESS);

        // Return resource to pool
        fhp->returnResourceToPool(pe);

        if (exit_execution.load()) {
            break;
        }
    }
    return nullptr;
}

void *thread_that_fetches_stats(void *args) {
    FileHandlePool *fhp = static_cast<FileHandlePool *>(args);
    fdb_status status = FDB_RESULT_SUCCESS;

    while (true) {
        // Runs once every second
        sleep(1);

        // Acquire handles from pool
        PoolEntry *pe = fhp->getAvailableResource();

        // Fetch kvs_info
        fdb_kvs_info kvs_info;
        status = fdb_get_kvs_info(pe->db, &kvs_info);
        fdb_assert(status == FDB_RESULT_SUCCESS,
                   status, FDB_RESULT_SUCCESS);
        (void)kvs_info;

        // Return resource to pool
        fhp->returnResourceToPool(pe);

        if (exit_execution.load()) {
            break;
        }
    }
    return nullptr;
}

void test_kv_engines_rebalance_situation(int nfiles,
                                         int nkvstores,
                                         int nhandles,
                                         int nwriters,
                                         int nreaders,
                                         bool useSeqTree) {
    TEST_INIT();
    memleak_start();

    exit_execution.store(false);

    int r = system(SHELL_DEL" uc_test* > errorlog.txt");
    (void)r;

    if (nfiles < 2 || nkvstores < 1) {
        fprintf(stderr, "[ERROR] Invalid input args: %d %d!\n",
                nfiles, nkvstores);
        return;
    }

    if (nwriters < 1 || nreaders < 1) {
        fprintf(stderr,
                "[ERROR] Insufficient number of readers (%d)/writers (%d)!\n",
                nwriters, nreaders);
        return;
    }

    // Set filename(s)
    std::vector<std::string> files;
    for (int i = 1; i <= nfiles; ++i) {
        std::string filename("./uc_test" + std::to_string(i));
        files.push_back(filename);
    }

    // Prepare handle pool
    FileHandlePool *fhp = new FileHandlePool(files, nkvstores, nhandles,
                                             false, useSeqTree);

    thread_t *threads = new thread_t[nwriters + nreaders];

    int threadid = 0;
    // Spawn writer thread(s)
    for (int i = 0; i < nwriters; ++i) {
        thread_create(&threads[threadid++], thread_that_issues_writes, fhp);
    }

    // Spawn reader/stat thread(s)
    for (int i = 0; i < nreaders; ++i) {
        thread_create(&threads[threadid++], thread_that_fetches_stats, fhp);
    }

    assert(threadid == nreaders + nwriters);

    // Allow threads to run for five seconds
    int num_moves = std::max(nfiles, nkvstores / 2);
    for (int i = 0; i < num_moves; ++i) {
        sleep(3);
        auto kvs_info = fhp->fetchRandomAvailableKvs();
        int pos = std::find(files.begin(), files.end(), kvs_info.second)
                  - files.begin();
        if (pos >= static_cast<int>(files.size())) {
            fprintf(stderr, "[ERROR] Unknown file name: %s!\n",
                    kvs_info.second.c_str());
            abort();
        }
        std::string new_filename = files.at((pos + 1) % files.size());
#ifdef __DEBUG_USECASE
        fprintf(stderr, "Shifting KVS: %s; old: %s; new: %s\n", kvs_info.first.c_str(),
                                                                kvs_info.second.c_str(),
                                                                new_filename.c_str());
#endif
        fhp->shiftPoolEntries(kvs_info.first, new_filename);
    }

    // Terminate execution
    exit_execution.store(true);

    // Wait for child threads
    for (int i = 0; i < (nreaders + nwriters); ++i) {
        r = thread_join(threads[i], nullptr);
        assert(r == 0);
    }
    delete[] threads;

    /* cleanup */
    delete fhp;

    /* shutdown */
    fdb_shutdown();

    std::string test_title(std::to_string(nfiles) + "F, " +
                           std::to_string(nkvstores) + "KVS, " +
                           std::to_string(nhandles) + "H, " +
                           std::to_string(nwriters) + "RW, " +
                           std::to_string(nreaders) + "RO - ");
    if (useSeqTree) {
        test_title += "uses SEQ Trees - ";
    }
    test_title += "Rebalance situation test";

#ifndef __DEBUG_USECASE
    r = system(SHELL_DEL" uc_test* > errorlog.txt");
    (void)r;
#endif

    memleak_end();
    TEST_RESULT(test_title.c_str());
}

struct initial_args {
    std::pair<fdb_file_handle *, fdb_kvs_handle *> handles;
    std::string key_prefix;
    int nsets;
};

void* invoke_initial_ops(void *args) {
    struct initial_args* ia = static_cast<initial_args *>(args);

    fdb_status status;
    char keybuf[256], bodybuf[256];
    for (int i = 0; i < ia->nsets; ++i) {
        sprintf(keybuf, "key%s%d", ia->key_prefix.c_str(), i);
        sprintf(bodybuf, "body%d", i);

        status = fdb_set_kv(ia->handles.second,
                            (void*)keybuf, strlen(keybuf) + 1,
                            (void*)bodybuf, strlen(bodybuf) + 1);
        fdb_assert(status == FDB_RESULT_SUCCESS, status, FDB_RESULT_SUCCESS);

        if (i % 100 == 0) {
            status = fdb_commit(ia->handles.first, FDB_COMMIT_NORMAL);
            fdb_assert(status == FDB_RESULT_SUCCESS,
                       status, FDB_RESULT_SUCCESS);
        }
    }
    status = fdb_commit(ia->handles.first, FDB_COMMIT_NORMAL);
    fdb_assert(status == FDB_RESULT_SUCCESS, status, FDB_RESULT_SUCCESS);
    return nullptr;
}

void test_initial_build_duration(int nthreads,
                                 int individualsets,
                                 bool defaultkvs) {

    TEST_INIT();

    int r = system(SHELL_DEL" uc_test* > errorlog.txt");
    (void)r;

    std::vector<std::pair<fdb_file_handle *, fdb_kvs_handle *> > handles;

    fdb_status status;
    fdb_config file_config = fdb_get_default_config();
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();

    for (int i = 0; i < nthreads; ++i) {
        fdb_file_handle *dbfile;
        fdb_kvs_handle *db;
        status = fdb_open(&dbfile, "uc_test", &file_config);
        TEST_STATUS(status);
        if (defaultkvs) {
            status = fdb_kvs_open_default(dbfile, &db, &kvs_config);
        } else {
            status = fdb_kvs_open(dbfile, &db, "kvs", &kvs_config);
        }
        TEST_STATUS(status);
        handles.push_back(std::make_pair(dbfile, db));
    }

    thread_t *threads = new thread_t[nthreads];
    struct initial_args *args = new struct initial_args[nthreads];

    std::chrono::time_point<std::chrono::system_clock> start, end;
    start = std::chrono::system_clock::now();

    for (int i = 0; i < nthreads; ++i) {
        args[i].handles = handles.at(i);
        args[i].key_prefix = std::string("_thread_") + std::to_string(i);
        args[i].nsets = individualsets;
        thread_create(&threads[i], invoke_initial_ops, &args[i]);
    }

    for (int i = 0; i < nthreads; ++i) {
        r = thread_join(threads[i], nullptr);
        assert(r == 0);
    }

    end = std::chrono::system_clock::now();

    std::chrono::duration<double> elapsed_seconds = end - start;

    fprintf(stderr, "RUNTIME: %fs\n", elapsed_seconds.count());

    delete[] args;
    delete[] threads;

    // Close all open handles
    for (int i = 0; i < nthreads; ++i) {
        fdb_kvs_close(handles.at(i).second);
        fdb_close(handles.at(i).first);
    }

    // Shutdown
    fdb_shutdown();

    std::string test_title("Initial Write Duration test: " +
                           std::to_string(nthreads) + "T " +
                           std::to_string(individualsets) + "S; ");
    test_title += defaultkvs ? "Default KV Store" : "Non-default KV Store";

#ifndef __DEBUG_USECASE
    r = system(SHELL_DEL" uc_test* > errorlog.txt");
    (void)r;
#endif

    TEST_RESULT(test_title.c_str());
}

int main() {

    /* Test single writer with multiple readers sharing a common
       pool of file handles, over single file for 30 seconds */
    test_readers_writers_with_handle_pool(10       /*number of handles*/,
                                          1        /*number of files*/,
                                          1        /*writer count*/,
                                          4        /*reader count*/,
                                          true     /*default kvs?*/,
                                          false    /*do not use snap handle pool*/,
                                          30       /*test time in seconds*/);

    /* Test multiple writers with multiple readers sharing a common
       pool of file handles, over single file for 30 seconds */
    test_readers_writers_with_handle_pool(10       /*number of handles*/,
                                          1        /*number of files*/,
                                          4        /*writer count*/,
                                          4        /*reader count*/,
                                          false    /*default kvs?*/,
                                          false    /*do not use snap handle pool*/,
                                          30       /*test time in seconds*/);

    /* Test multiple writers sharing a common pool of file handles
       and multiple readers sharing a common pool of snapshot handles,
       over single file for 30 seconds */
    test_readers_writers_with_handle_pool(5        /*number of handles*/,
                                          1        /*number of files*/,
                                          4        /*writer count*/,
                                          4        /*reader count*/,
                                          true     /*default kvs?*/,
                                          true     /*use snap handle pool*/,
                                          30       /*test time in seconds*/);

    /* Test multiple writers sharing a common pool of file handles
       and multiple readers sharing a common pool of snapshot handles,
       over multiple files for 30 seconds */
    test_readers_writers_with_handle_pool(10       /*number of handles*/,
                                          5        /*number of files*/,
                                          4        /*writer count*/,
                                          4        /*reader count*/,
                                          false    /*default kvs?*/,
                                          true     /*use snap handle pool*/,
                                          30       /*test time in seconds*/);

    /* Tests compaction of a file while a writer adds data to multiple
       kv stores belonging to the file */
    test_writes_on_kv_stores_with_compaction(256   /*number of kv stores*/,
                                             1500  /*number of items per kvstore*/);

    /* Test fdb_kvs_remove operation when kvs does not have any open handles */
    test_kv_engines_rebalance_situation(4      /*number of files*/,
                                        16     /*number of kv stores*/,
                                        2      /*number of handles per kvs*/,
                                        4      /*writer count*/,
                                        2      /*reader count*/,
                                        false  /*do not use sequence trees*/);

    /* Test fdb_kvs_remove operation when kvs does not have any open handles */
    test_kv_engines_rebalance_situation(4      /*number of files*/,
                                        16     /*number of kv stores*/,
                                        2      /*number of handles per kvs*/,
                                        4      /*writer count*/,
                                        2      /*reader count*/,
                                        true   /*use sequence trees*/);

    /* Test that replicates initial build phase for indexes, and estimates the
       time taken, with non-default kv store */
    test_initial_build_duration(1              /*number of threads*/,
                                500000         /*number of sets per thread*/,
                                false          /*default kvs?*/);

    /* Test that replicates initial build phase for indexes, and estimates the
       time taken, with default kv store */
    test_initial_build_duration(1              /*number of threads*/,
                                500000         /*number of sets per thread*/,
                                true           /*default kvs?*/);

    return 0;
}
