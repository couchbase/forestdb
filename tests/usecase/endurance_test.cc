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

#include <algorithm>
#include <atomic>
#include <iostream>
#include <iterator>
#include <map>
#include <memory>
#include <random>
#include <string>
#include <vector>

#include "libforestdb/forestdb.h"
#include "atomic.h"
#include "test.h"

#define MAX_FILES 1024

#define FIXED_BATCH_SIZE    //! Comment line to enforce random batch sizes
#define MAX_BATCH_SIZE 512
#define MIN_BATCH_SIZE 128

/**
 * Forest KV store handle
 */
class ForestKvsHandle {
public:
    ForestKvsHandle(fdb_file_handle* fHandle,
                    fdb_kvs_handle* kHandle) {
        fileHandle = fHandle;
        kvsHandle  = kHandle;
    }

    ~ForestKvsHandle() {
        if (kvsHandle) {
            fdb_kvs_close(kvsHandle);
        }

        if (fileHandle) {
            fdb_close(fileHandle);
        }
    }

    fdb_kvs_handle* getKvsHandle() {
        return kvsHandle;
    }

    fdb_file_handle* getFileHandle() {
        return fileHandle;
    }

private:

    fdb_file_handle* fileHandle;
    fdb_kvs_handle* kvsHandle;

    DISALLOW_COPY_AND_ASSIGN(ForestKvsHandle);
};

ForestKvsHandle* createFKvsHandle(uint16_t fileId,
                                  std::string dir,
                                  fdb_config* fileConfig,
                                  bool defaultKvs) {
    fdb_file_handle* newFileHandle = nullptr;
    fdb_kvs_handle* newKvsHandle = nullptr;
    fdb_status status;
    fdb_kvs_config kvsConfig = fdb_get_default_kvs_config();

    std::string file(dir + "/" + std::to_string(fileId) + ".fdb.1");

    status = fdb_open(&newFileHandle, file.c_str(), fileConfig);
    if (status != FDB_RESULT_SUCCESS) {
        fprintf(stderr, "[ERROR] FDB_OPEN failed for %s\n", file.c_str());
        abort();
    }

    char kvsname[20];
    if (defaultKvs) {
        status = fdb_kvs_open_default(newFileHandle, &newKvsHandle, &kvsConfig);
    } else {
        sprintf(kvsname, "file%u", fileId);
        status = fdb_kvs_open(newFileHandle, &newKvsHandle, kvsname, &kvsConfig);
    }

    if (status != FDB_RESULT_SUCCESS) {
        fprintf(stderr, "[ERROR] FDB_KVS_OPEN failed for %s in %s\n",
                defaultKvs ? "default" : kvsname, file.c_str());
        abort();
    }

    return new ForestKvsHandle(newFileHandle, newKvsHandle);
}

/**
 * Support for fdb_fetch_handle_stats.
 */
struct fdb_stats_cb_ctx {
    std::map<std::string, uint64_t> stats;
};

void fdbStatsCallback(fdb_kvs_handle* handle, const char* stat,
                      uint64_t value, void* ctx) {
    fdb_stats_cb_ctx* statsCtx = static_cast<fdb_stats_cb_ctx*>(ctx);
    statsCtx->stats[stat] = value;
}

/**
 * This class represents the KV-Store in the cache. Each object
 * to the class will be responsible for managing the specified
 * number of files.
 */
class CacheStore {
public:
    CacheStore(uint16_t _id             /* Id of store */,
               int numShards            /* Number of stores */,
               int numFilesPerStore     /* Number of files per store */,
               std::string dir          /* Directory */,
               bool _genRandomKeys      /* Generate random keys */,
               fdb_config* fileConfig   /* File Config */,
               bool defaultKvs          /* Create default kv handle */)
        : id(_id),
          db(dir),
          genRandomKeys(_genRandomKeys),
          keygen(0),
          cursor(-1),
          numCommits(0)
    {
        docCount.assign(MAX_FILES, 0);
        blockCacheNumItems.assign(MAX_FILES, 0);
        blockCacheNumVictims.assign(MAX_FILES, 0);
        fkvsHandleMap.assign(MAX_FILES, nullptr);
        int count = 0;
        for (uint16_t i = 0; i < MAX_FILES; ++i) {
            if (i % numShards == id) {
                if (++count > numFilesPerStore) {
                    break;
                }
                std::unique_ptr<ForestKvsHandle> fkvs(createFKvsHandle(i,
                                                            db, fileConfig,
                                                            defaultKvs));
                fkvsHandleMap[i] = std::move(fkvs);
            }
        }
    }

    ~CacheStore() {
        fkvsHandleMap.clear();
    }

    void dumpData() {
        fdb_status status;
        std::vector<std::string> keys;
#ifdef FIXED_BATCH_SIZE
        int batch = MIN_BATCH_SIZE;
#else
        int batch = rand() % MAX_BATCH_SIZE;
        if (batch < MIN_BATCH_SIZE) {
            batch = MIN_BATCH_SIZE;
        }
#endif
        getNKeys(batch, keys);

        char keyBuf[32];
        char bodyBuf[32];
        sprintf(bodyBuf, "kv_%u_value", id);

        // Find next available file
        uint16_t index = 0;
        do {
            index = (++cursor) % MAX_FILES;
        } while (!fkvsHandleMap[index]);

        for (auto& itr : keys) {
            sprintf(keyBuf, "%s", itr.c_str());
            status = fdb_set_kv(fkvsHandleMap[index]->getKvsHandle(),
                                (void*)keyBuf, strlen(keyBuf) + 1,
                                (void*)bodyBuf, strlen(bodyBuf) + 1);
            fdb_assert(status == FDB_RESULT_SUCCESS, status, FDB_RESULT_SUCCESS);
        }
        docCount[index] += keys.size();

        status = fdb_commit(fkvsHandleMap[index]->getFileHandle(),
                            FDB_COMMIT_NORMAL);
        fdb_assert(status == FDB_RESULT_SUCCESS, status, FDB_RESULT_SUCCESS);
        ++numCommits;

        // Update block cache item count
        fdb_stats_cb_ctx ctx;
        status = fdb_fetch_handle_stats(fkvsHandleMap[index]->getKvsHandle(),
                                        fdbStatsCallback,
                                        &ctx);
        if (status == FDB_RESULT_SUCCESS) {
            blockCacheNumItems[index] = ctx.stats["Block_cache_num_items"];
            blockCacheNumVictims[index] = ctx.stats["Block_cache_num_victims"];
        }
    }

    std::string getName() {
        return std::string("kv" + std::to_string(id));
    }

    uint64_t getAggregatedDocCount() {
        uint64_t value = 0;
        for (auto& itr : docCount) {
            value += itr;
        }
        return value;
    }

    uint64_t getNumCommits() {
        return numCommits;
    }

    uint64_t getAggregatedBlockCacheNumItems() {
        uint64_t value = 0;
        for (auto& itr : blockCacheNumItems) {
            value += itr;
        }
        return value;
    }

    uint64_t getAggregatedBlockCacheNumVictims() {
        uint64_t value = 0;
        for (auto& itr : blockCacheNumVictims) {
            value += itr;
        }
        return value;
    }

private:
    void getNKeys(int n, std::vector<std::string>& keys) {
        if (!genRandomKeys) {
            for (int i = 0; i < n; ++i) {
                keys.push_back(std::string("kv_" + std::to_string(id) +
                                           "_" + std::to_string(keygen++)));
            }
        } else {
            static const char alphabet[] =
                "abcdefghijklmnopqrstuvwxyz"
                "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                "0123456789";

            static const size_t K_LEN = 10;

            std::random_device rd;
            std::default_random_engine rng(rd());
            std::uniform_int_distribution<> dist(0,sizeof(alphabet)/sizeof(*alphabet)-2);

            keys.reserve(n);
            std::generate_n(std::back_inserter(keys), keys.capacity(),
                            [&] { std::string str;
                            str.reserve(K_LEN);
                            std::generate_n(std::back_inserter(str), K_LEN,
                                [&]() { return alphabet[dist(rng)];});
                            return str; });
        }
    }

private:
    uint16_t id;
    std::string db;
    bool genRandomKeys;
    uint64_t keygen;
    int cursor;

    std::vector<size_t> docCount;
    size_t numCommits;
    std::vector<size_t> blockCacheNumItems;
    std::vector<size_t> blockCacheNumVictims;

    std::vector<std::shared_ptr<ForestKvsHandle>> fkvsHandleMap;
};

struct wr_ops {
    CacheStore* store;
    float time;
};

static void* invoke_writer_ops(void* args) {
    struct wr_ops* wo = static_cast<struct wr_ops *>(args);
    std::chrono::time_point<std::chrono::system_clock> start, end;
    start = std::chrono::system_clock::now();

    while (true) {
        wo->store->dumpData();

        end = std::chrono::system_clock::now();
        std::chrono::duration<double> elapsed_seconds = end - start;
        if (elapsed_seconds.count() > wo->time) {
            break;
        }
    }

    thread_exit(0);
    return nullptr;
}

void test_block_cache_usage(int numShards,
                            int numFilesPerShard,
                            bool genRandomKeys,
                            bool defaultKvs,
                            int runTime) {

    TEST_INIT();

    int r;
    r = system(SHELL_DEL" en_test/* > errorlog.txt");
    (void)r;

    r = system(SHELL_MKDIR" en_test");
    (void)r;

    if (numShards * numFilesPerShard > MAX_FILES) {
        fprintf(stderr, "[CONFIG ERROR] Number of underlying files (%d) more "
                        "than allowed (%d)\n",
                numShards * numFilesPerShard, MAX_FILES);
        return;
    }

    // Init ForestDB
    fdb_config fileConfig = fdb_get_default_config();
    // WAL threshold at 4K
    fileConfig.wal_threshold = 4096;
    // Buffer cache size at 64MB
    fileConfig.buffercache_size = 64 * 1024 * 1024;
    if (defaultKvs) {
        fileConfig.multi_kv_instances = false;
    }
    // Disabling circular block reuse
    fileConfig.block_reusing_threshold = 100;
    // Use sequence trees
    fileConfig.seqtree_opt = FDB_SEQTREE_USE;

    fdb_status status = fdb_init(&fileConfig);
    TEST_STATUS(status);

    // Create virtual shards
    std::vector<CacheStore*> kvstores;
    for (int i = 0; i < numShards; ++i) {
        kvstores.push_back(new CacheStore(i,
                                          numShards,
                                          numFilesPerShard,
                                          "en_test",
                                          genRandomKeys,
                                          &fileConfig,
                                          defaultKvs));
    }

    // Begin load
    thread_t* threads = new thread_t[numShards];
    std::vector<struct wr_ops> args(numShards);
    for (int i = 0; i < numShards; ++i) {
        args[i] = {kvstores[i], static_cast<float>(runTime)};
        thread_create(&threads[i], invoke_writer_ops, &args[i]);
    }

    // End load
    for (int i = 0; i < numShards; ++i) {
        r = thread_join(threads[i], nullptr);
        assert(r == 0);
    }
    delete[] threads;

    // Print stats
    fprintf(stderr, "\n%4s %10s|%10s|%15s|%15s\n",
            "", "DOC_COUNT", "NUM_COMMITS",
            "BCACHE_NUM_ITEMS", "BCACHE_NUM_VICTIMS");
    for (int i = 0; i < numShards; ++i) {
        fprintf(stderr, "%s %10s %10s %15s %15s\n",
                kvstores[i]->getName().c_str(),
                std::to_string(kvstores[i]->getAggregatedDocCount()).c_str(),
                std::to_string(kvstores[i]->getNumCommits()).c_str(),
                std::to_string(kvstores[i]->getAggregatedBlockCacheNumItems()).c_str(),
                std::to_string(kvstores[i]->getAggregatedBlockCacheNumVictims()).c_str());
    }

    // Delete virtual shards
    for (auto& itr : kvstores) {
        delete itr;
    }

    // Shutdown ForestDB
    status = fdb_shutdown();
    TEST_STATUS(status);

    std::string test_title(std::to_string(numShards) + "S, " +
                           std::to_string(numFilesPerShard) + "FPS - ");
    if (genRandomKeys) {
        test_title += "Random keys - ";
    } else {
        test_title += "Sequential keys - ";
    }
    if (defaultKvs) {
        test_title += "Default KVS - ";
    }
    test_title += "Block Cache Usage test";

#ifndef DEBUG_ENDURANCE
    r = system(SHELL_DEL" en_test/* > errorlog.txt");
    (void)r;

    r = system(SHELL_RMDIR" en_test");
    (void)r;
#endif

    TEST_RESULT(test_title.c_str());
}

int main() {

    test_block_cache_usage(4,      /* number of shards/number of threads */
                           16,     /* number of files per shard */
                           true,   /* generate random keys */
                           false,  /* default kvs? */
                           60      /* test run time in seconds */);

    test_block_cache_usage(4,      /* number of shards/number of threads */
                           16,     /* number of files per shard */
                           false,  /* do not generate random keys */
                           false,  /* default kvs? */
                           60      /* test run time in seconds */);

    test_block_cache_usage(4,      /* number of shards/number of threads */
                           16,     /* number of files per shard */
                           true,   /* generate random keys */
                           true,   /* default kvs? */
                           30      /* test run time in seconds */);

    test_block_cache_usage(4,      /* number of shards/number of threads */
                           16,     /* number of files per shard */
                           false,  /* do not generate random keys */
                           true,   /* default kvs? */
                           30      /* test run time in seconds */);

    return 0;
}
