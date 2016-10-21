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

#include <algorithm>

#include "disk_write_queue.h"

ssize_t TxnItemList::addItem(wal_item* new_item, wal_item* old_item) {
    if (old_item &&
        items.size() > old_item->dwq_index &&
        items.at(old_item->dwq_index) == old_item) {

        // De-dup: Replace the old item from the items vector
        items.at(old_item->dwq_index) = new_item;
        new_item->dwq_index = old_item->dwq_index;

        memoryUsage += (new_item->doc_size - old_item->doc_size);
        return new_item->doc_size - old_item->doc_size;
    } else {
        items.push_back(new_item);
        new_item->dwq_index = items.size() - 1;
        memoryUsage += new_item->doc_size;

        return new_item->doc_size;
    }
}

void TxnItemList::customSort() {
    if (items.empty()) {
        return;
    }
    (void)lastFlushIdx;
    (void)flushIdx;
    (void)txnState;
    (void)ptxn;

    std::sort(items.begin(),
              items.end(),
              WalItemComparator::compare);
}

fdb_status TxnItemList::scan(txn_item_list_scan_cb* scan_callback, void* ctx) {
    fdb_status ret = FDB_RESULT_SUCCESS;
    for (auto &itr : items) {
        ret = scan_callback(itr, ctx);
        if (ret != FDB_RESULT_SUCCESS) {
            return ret;
        }
    }
    return ret;
}

DiskWriteQueue::DiskWriteQueue(size_t transaction_threshold,
                               size_t transaction_item_limit)
    : transactionThreshold(transaction_threshold),
      transactionItemLimit(transaction_item_limit),
      overallMemoryUsage(0)
{
    spin_init(&mutablesLock);
    spin_init(&immutablesQLock);
}

DiskWriteQueue::~DiskWriteQueue() {
    spin_destroy(&mutablesLock);
    spin_destroy(&immutablesQLock);
}

void DiskWriteQueue::addTxn(uint64_t id) {
    spin_lock(&mutablesLock);
    mutablesMap[id] = std::unique_ptr<TxnItemList>(new TxnItemList(nullptr));
    spin_unlock(&mutablesLock);
}

bool DiskWriteQueue::addTxnEntry(uint64_t txnId, wal_item* item,
                                 wal_item* oldItem) {
    spin_lock(&mutablesLock);
    auto itr = mutablesMap.find(txnId);
    if (itr == mutablesMap.end()) {
        spin_unlock(&mutablesLock);
        return false;
    }
    overallMemoryUsage.fetch_add(itr->second->addItem(item, oldItem));
    if (itr->second->getMemoryUsage() > transactionThreshold ||
        itr->second->getItemCount() > transactionItemLimit) {
        // Mark the transaction as eligible to be marked
        // as immutable, as the threshold(s) has been reached
        eligibleMutables.insert(itr->first);
    }

    spin_unlock(&mutablesLock);
    return true;
}

bool DiskWriteQueue::commit(uint64_t txnId) {
    spin_lock(&mutablesLock);
    bool ret = markImmutable_UNLOCKED(txnId, true);
    spin_unlock(&mutablesLock);
    return ret;
}

bool DiskWriteQueue::fetchImmutableTxnItems(std::unique_ptr<TxnItemList> &items) {
    spin_lock(&immutablesQLock);
    if (immutablesQ.empty()) {
        spin_unlock(&immutablesQLock);

        spin_lock(&mutablesLock);
        if (eligibleMutables.empty()) {
            spin_unlock(&mutablesLock);
            return false;
        } else {
            auto itr = eligibleMutables.begin();
            markImmutable_UNLOCKED(*itr, false);
            eligibleMutables.erase(itr);
        }

        spin_unlock(&mutablesLock);

        spin_lock(&immutablesQLock);
        if (immutablesQ.empty()) {
            spin_unlock(&immutablesQLock);
            return false;
        }
    }

    items = std::move(immutablesQ.front());
    immutablesQ.pop();
    spin_unlock(&immutablesQLock);

    // Invoke custom sort
    items->customSort();

    return true;
}

size_t DiskWriteQueue::getMutableTxnMemoryUsage(uint64_t txnId) {
    size_t memUsed = 0;
    spin_lock(&mutablesLock);
    auto itr = mutablesMap.find(txnId);
    if (itr != mutablesMap.end()) {
        memUsed = itr->second->getMemoryUsage();
    }
    spin_unlock(&mutablesLock);
    return memUsed;
}

size_t DiskWriteQueue::getMutableTxnMemoryUsage() {
    return overallMemoryUsage.load();
}

bool DiskWriteQueue::markImmutable_UNLOCKED(uint64_t txnId,
                                            bool isCommit) {
    auto itr = mutablesMap.find(txnId);
    if (itr == mutablesMap.end()) {
        // Transaction wasn't found in the transaction map
        return false;
    }

    if (itr->second->getItemCount() == 0) {
        // No items in the current transanction to flush
        return false;
    }

    overallMemoryUsage.fetch_sub(itr->second->getMemoryUsage());

    spin_lock(&immutablesQLock);
    immutablesQ.push(std::move(itr->second));
    spin_unlock(&immutablesQLock);

    if (isCommit) {
        mutablesMap.erase(itr);
    } else {
        mutablesMap[txnId] = std::unique_ptr<TxnItemList>(new TxnItemList(nullptr));
    }

    return true;
}
