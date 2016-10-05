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

#pragma once

#include <atomic>
#include <queue>
#include <map>
#include <memory>
#include <unordered_set>
#include <vector>

#include "common.h"
#include "internal_types.h"
#include "wal.h"

// Scan callback for transaction item list
typedef void txn_item_list_scan_cb(wal_item* item, void *ctx);

class TxnItemList {
public:
    TxnItemList()
        : memoryUsage(0) { }

    ~TxnItemList() { }

    size_t getItemCount() {
        return items.size();
    }

    size_t getMemoryUsage() {
        return memoryUsage;
    }

    ssize_t addItem(wal_item* new_item, wal_item* old_item);

    void customSort();

    void scan(txn_item_list_scan_cb callback, void* ctx);

private:
    size_t memoryUsage;
    std::vector<wal_item*> items;
};

/**
  The Disk write queue is a container that maps transaction ids to transactional
  items. It contains:
  - An map of transaction ids mapping to a vectoR of items belonging
    to the transaction.
  - When writers continue to add transactional items, the transaction
    is mutable, and once a commit comes in for the specific transaction,
    it is considered immutable and moved to another queue of immutablesQ
    and the flusher will be able to retrieve all those items.
  - While writers continue to add entries to the map, the flushers will
    work at clearing out the entries as and when they are deemed
    immutable.

                    (mut)      (mut)     (mut)
                +----------+----------+----------+-----
  map:          | fdb_txn0 | fdb_txn2 | fdb_txn3 |   ..
  (mutable)     +----------+----------+----------+----------
                     |          |          |
                     |          |          |    +-----+-----+-----
                     |          |          +--> | it1 | it2 | ..
                     |          |               +-----+-----+-----
                     |          |               +-----+-----+-----+-----
                     |          +-------------> | it1 | it2 | it3 | ..
                     |                          +-----+-----+-----+-----
                     |                          +-----+-----+-----+-----+-----
                     +------------------------> | it1 | it2 | it3 | it4 | ..
                                                +-----+-----+-----+-----+-----

                                                +-----+-----+-----+
                     +------------------------> | it1 | it2 | it3 |
                     |                          +-----+-----+-----+
                     |
                     |
                +----------+-----
  queue:        | fdb_txn1 |   ..
  (immutable)   +----------+----------

*/
class DiskWriteQueue {
public:
    /**
     * Constructor
     *
     * @param transaction_threshold Allowed memory threshold per transaction
     *                              above which the transactional items are
     *                              elibible to be marked as immutable.
     * @param transaction_item_limit Allowed number of items per transaction
     *                               after which the transactional items are
     *                               eligible to be marked as immutable.
     */
    DiskWriteQueue(size_t transaction_threshold,
                   size_t transaction_item_limit);

    ~DiskWriteQueue();

    /**
     * Add a new transaction
     */
    void addTxn(uint64_t id);

    /**
     * Adds a new item to a transaction, optionally accepts
     * an oldItem that needs removal (de-duplication)
     *
     * @param txnId Transaction Id
     * @param item wal_item to insert
     * @param oldItem old wal_item to replace
     * @returns true on success
     */
    bool addTxnEntry(uint64_t txnId, wal_item* item,
                     wal_item* oldItem = nullptr);

    /**
     * Moves a transaction item list to immutablesQ.
     *
     * @param txnId Transaction id
     * @returns true on success (if items were marked as immutable)
     */
    bool commit(uint64_t txnId);

    /**
     * Fetches a batch of transactional items from the immutablesQ queue,
     *
     * @param items Smart pointer reference to a vector of wal_items
     * @returns false if immutable queue is empty, and no eligible items
     */
    bool fetchImmutableTxnItems(std::unique_ptr<TxnItemList> &items);

    /**
     * Fetch memory usage of the mutable set of items owned by the
     * specific transaction.
     */
    size_t getMutableTxnMemoryUsage(uint64_t txnId);

    /**
     * Fetch memory usage of the mutable set of items owned by every
     * transaction present.
     */
    size_t getMutableTxnMemoryUsage();

private:
    /**
     * Moves a transaction item list to immutablesQ.
     *
     * @param txnId Transaction id
     * @param isCommit Set to true if the items being marked as immutable
     *                 is from a commit operation.
     * @return true on success
     */
    bool markImmutable_UNLOCKED(uint64_t txnId, bool isCommit);

private:
    // Memory threshold for any open transaction after which it is
    // eligible for being marked as immutable
    size_t transactionThreshold;

    // Item threshold for any open transaction after which it is
    // eligible for being marked as immutable
    size_t transactionItemLimit;

    // Aggregated memory usage of disk write queue
    std::atomic<size_t> overallMemoryUsage;

    // Spin lock to add/remove entries to transaction map which is a
    // map of lists that will contain the transactional items for
    // each transaction id
    spin_t mutablesLock;
    std::map<uint64_t, std::unique_ptr<TxnItemList>> mutablesMap;

    // List of transactions that are eligible to be marked as
    // immutable (access within mutablesLock)
    std::unordered_set<uint64_t> eligibleMutables;

    // Spin lock to add/remove entries from the immutablesQ queue which
    // contains to transactional vectors that have been marked as
    // immutable
    spin_t immutablesQLock;
    std::queue<std::unique_ptr<TxnItemList>> immutablesQ;
};
