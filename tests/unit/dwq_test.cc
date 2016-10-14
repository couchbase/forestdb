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

#include <atomic>
#include <map>
#include <unordered_map>
#include <vector>

#include "disk_write_queue.h"
#include "wal.h"

#include "stat_aggregator.h"
#include "test.h"

// _num_tasks_ to always be the last entry of the following
// enum class to estimate the number of tasks
enum task_type_t {
    ADD_TXN,
    ADD_TXN_ENTRY,
    MARK_IMMUTABLE,
    FETCH_IMMUTABLES,
    _num_tasks_
};

class DiskWriteQueueHelper {
public:
    DiskWriteQueueHelper(size_t mem_threshold,
                         size_t item_threshold) {
        dwq = new DiskWriteQueue(mem_threshold, item_threshold);
    }

    ~DiskWriteQueueHelper() {
        delete dwq;
    }

    DiskWriteQueue* accessDWQ() {
        return dwq;
    }

private:
    DiskWriteQueue *dwq;
};

void basic_test() {
    TEST_INIT();

    int num_items = 1000;
    std::vector<wal_item*> items;
    for (int i = 0; i < num_items; ++i) {
        wal_item* item = new wal_item;
        item->doc_size = rand() % 100;  // Allowed doc-sizes up to 100B
        items.push_back(item);
    }

    DiskWriteQueueHelper* dwq_helper = new DiskWriteQueueHelper(10000,
                                                                100);

    for (int i = 0; i < num_items; ++i) {
        if (i == 0 || i == 2 || i == 3 || i == 5) {
            dwq_helper->accessDWQ()->addTxn(i);
        }

        if (i && i % 5 == 0) {
            wal_item *old = nullptr;
            if (i > 5 && rand() % 10 == 0) {
                old = items.at(i - 5);
            }
            dwq_helper->accessDWQ()->addTxnEntry(5, items.at(i), old);
        } else if (i && i % 3 == 0) {
            wal_item *old = nullptr;
            if (i > 3 && rand() % 10 == 0) {
                old = items.at(i - 3);
            }
            dwq_helper->accessDWQ()->addTxnEntry(3, items.at(i), old);
        } else if (i && i % 2 == 0) {
            wal_item *old = nullptr;
            if (i > 2 && rand() % 10 == 0) {
                old = items.at(i - 2);
            }
            dwq_helper->accessDWQ()->addTxnEntry(2, items.at(i), old);
        } else {
            wal_item *old = nullptr;
            if (i > 1 && rand() % 10 == 0) {
                old = items.at(i - 1);
            }
            dwq_helper->accessDWQ()->addTxnEntry(0, items.at(i), old);
        }
    }

    dwq_helper->accessDWQ()->commit(0);
    dwq_helper->accessDWQ()->commit(2);
    dwq_helper->accessDWQ()->commit(3);
    dwq_helper->accessDWQ()->commit(5);

    TEST_CHK(dwq_helper->accessDWQ()->getMutableTxnMemoryUsage(0) == 0);
    TEST_CHK(dwq_helper->accessDWQ()->getMutableTxnMemoryUsage(2) == 0);
    TEST_CHK(dwq_helper->accessDWQ()->getMutableTxnMemoryUsage(3) == 0);
    TEST_CHK(dwq_helper->accessDWQ()->getMutableTxnMemoryUsage(5) == 0);

    delete dwq_helper;

    for (auto &it : items) {
        delete it;
    }

    TEST_RESULT("DWQ: Basic test");
}

static int samples(0);
static std::mutex guard;

void collect_stat(StatAggregator *sa, task_type_t type, uint64_t diff) {
    LockHolder lh(guard);
    sa->t_stats[type][0].latencies.push_back(diff);
    ++samples;
}

struct frontend_args {
    std::unordered_map<uint64_t, bool> transaction_ids;
    StatAggregator *sa;
    DiskWriteQueueHelper *dwq_helper;
    size_t items_per_txn;
    size_t items_in_global_txn;
};

void *frontend_writer_ops(void *args) {
    struct frontend_args *fa = static_cast<frontend_args *>(args);

    if (fa->transaction_ids.empty()) {
        return nullptr;
    }

    std::map<uint64_t, size_t> createdTxns;
    createdTxns.insert(std::make_pair(0, 0));

    auto itr = fa->transaction_ids.begin();
    size_t numTxns = fa->transaction_ids.size();
    uint64_t txnId;
    while (numTxns) {
        if (!itr->second) {
            txnId = itr->first;
            if (txnId != 0 && createdTxns.find(txnId) == createdTxns.end()) {
                ts_nsec now = get_monotonic_ts();
                fa->dwq_helper->accessDWQ()->addTxn(txnId);
                collect_stat(fa->sa, ADD_TXN, get_monotonic_ts() - now);
                createdTxns.insert(std::make_pair(txnId, 0));
            }

            wal_item* item = new wal_item;
            item->doc_size = rand() % 100;  // Allowed doc-sizes up to 100B

            ts_nsec now = get_monotonic_ts();
            fa->dwq_helper->accessDWQ()->addTxnEntry(txnId, item);
            collect_stat(fa->sa, ADD_TXN_ENTRY, get_monotonic_ts() - now);

            // Transactional item limit different for non-global transactions
            if (txnId != 0) {
                if (++createdTxns[txnId] >= fa->items_per_txn) {
                    ts_nsec now = get_monotonic_ts();
                    fa->dwq_helper->accessDWQ()->commit(txnId);
                    collect_stat(fa->sa, MARK_IMMUTABLE, get_monotonic_ts() - now);
                    fa->transaction_ids[txnId] = true;
                    --numTxns;
                }
            } else {
                if (++createdTxns[0] >= fa->items_in_global_txn) {
                    fa->transaction_ids[0] = true;
                    --numTxns;
                }
            }
        }

        if ((++itr) == fa->transaction_ids.end()) {
            itr = fa->transaction_ids.begin();
        }
    };

    return nullptr;
}

struct backend_args {
    StatAggregator *sa;
    DiskWriteQueueHelper *dwq_helper;
};

static std::atomic<bool> exit_flusher(false);

void free_cb(wal_item* item, void *ctx) {
    assert(item);
    delete item;
}

void *backend_flusher_ops(void *args) {
    struct backend_args *ba = static_cast<backend_args *>(args);

    while (true) {
        std::unique_ptr<TxnItemList> items;
        ts_nsec now = get_monotonic_ts();
        bool ret = ba->dwq_helper->accessDWQ()->fetchImmutableTxnItems(items);
        if (!ret) {
            size_t mem_used = ba->dwq_helper->accessDWQ()->getMutableTxnMemoryUsage();
            if (mem_used == 0 && exit_flusher.load()) {
                break;
            } else {
                continue;
            }
        } else {
            collect_stat(ba->sa, FETCH_IMMUTABLES, get_monotonic_ts() - now);
        }

        items->scan(free_cb, nullptr);
    }

    return nullptr;
}

void multi_threaded_test(int num_frontend_threads,
                         size_t items_per_txn,
                         size_t num_open_txns,
                         size_t items_in_global_txn) {
    TEST_INIT();

    DiskWriteQueueHelper* dwq_helper = new DiskWriteQueueHelper(1000000,
                                                                4096);

    // Create Stat collector/aggregator
    StatAggregator* sa = new StatAggregator(_num_tasks_, 1);
    sa->t_stats[ADD_TXN][0].name = "add_txn";
    sa->t_stats[ADD_TXN_ENTRY][0].name = "add_txn_entry";
    sa->t_stats[MARK_IMMUTABLE][0].name = "commit";
    sa->t_stats[FETCH_IMMUTABLES][0].name = "fetch_immutables";
    samples = 0;

    exit_flusher.store(false);

    thread_t backend_thread;
    struct backend_args backendArgs = {sa, dwq_helper};
    thread_create(&backend_thread, backend_flusher_ops, &backendArgs);

    thread_t* frontend_threads = new thread_t[num_frontend_threads];
    struct frontend_args* args = new struct frontend_args[num_frontend_threads];

    for (size_t i = 1; i <= num_open_txns; ++i) {
        args[i % num_frontend_threads].transaction_ids.insert(
                                std::make_pair(static_cast<uint64_t>(i), false));
    }

    ts_nsec now = get_monotonic_ts();
    dwq_helper->accessDWQ()->addTxn(0);
    collect_stat(sa, ADD_TXN, get_monotonic_ts() - now);

    int tid = 0;
    for (int i = 0; i < num_frontend_threads; ++i) {
        args[i].sa = sa;
        args[i].dwq_helper = dwq_helper;
        args[i].items_per_txn = items_per_txn;
        args[i].items_in_global_txn = items_in_global_txn;
        args[i].transaction_ids[0] = false;     // global transaction
        thread_create(&frontend_threads[tid++], frontend_writer_ops, &args[i]);
    }

    for (int i = 0; i < num_frontend_threads; ++i) {
        int r = thread_join(frontend_threads[i], nullptr);
        assert(r == 0);
    }
    delete[] args;
    delete[] frontend_threads;

    if (dwq_helper->accessDWQ()->getMutableTxnMemoryUsage(0) != 0) {
        now = get_monotonic_ts();
        dwq_helper->accessDWQ()->commit(0);
        collect_stat(sa, MARK_IMMUTABLE, get_monotonic_ts() - now);
    }
    TEST_CHK(dwq_helper->accessDWQ()->getMutableTxnMemoryUsage() == 0);

    exit_flusher.store(true);
    int r = thread_join(backend_thread, nullptr);
    assert(r == 0);

    std::string title("DWQ: Multi threaded test (" +
                      std::to_string(num_frontend_threads) + "FT, " +
                      "1BT, " +
                      std::to_string(items_per_txn) + "IPT, " +
                      std::to_string(num_open_txns + 1) + "TXNS)");
    sa->aggregateAndPrintStats("MULTI_THREADED_TEST", samples, "µs");

    // Delete stat aggregator
    delete sa;

    delete dwq_helper;

    TEST_RESULT(title.c_str());
}

int main() {
    basic_test();
    multi_threaded_test(4       /* number frontend threads */,
                        100     /* items per transaction */,
                        50      /* number of transactions */,
                        25000   /* items in global transaction (per thread) */);

    return 0;
}
