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

#include <memory_pool.h>

MemoryPool::MemoryPool(int num_bins, size_t bin_size) :
    numBins(num_bins), binSize(bin_size), memPool(num_bins * bin_size) {
    spin_init(&lock);
    for (int i = num_bins - 1; i >= 0; --i) {
          push(i);
    }
}

MemoryPool::~MemoryPool() {
    spin_destroy(&lock);
}

const int MemoryPool::fetchBlock(uint8_t **buf) {
    const int ret = pop();
    if (ret < 0) {
        *buf = nullptr;
    } else {
        *buf = &memPool.data()[ret * binSize];
    }
    return ret;
}

void MemoryPool::returnBlock(int index) {
    if (index >= 0 && index < numBins) {
        push(index);
    }
}

inline void MemoryPool::push(int index) {
    spin_lock(&lock);
    indexes.push(index);
    spin_unlock(&lock);
}

inline int MemoryPool::pop() {
    int data = -1;
    spin_lock(&lock);
    if (indexes.size()) {
        data = indexes.top();
        indexes.pop();
    }
    spin_unlock(&lock);
    return data;
}
