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

MemoryPool::MemoryPool(int num_bins, size_t bin_size) {
    spin_init(&lock);
    for (int i = 0; i < num_bins; ++i) {
        memPool.push_back((uint8_t *) malloc(bin_size));
        enQueue(i);
    }
}

MemoryPool::~MemoryPool() {
    spin_destroy(&lock);
    for (auto &it : memPool) {
        free(it);
    }
}

const int MemoryPool::fetchBlock(uint8_t **buf) {
    int ret = deQueue();
    if (ret == -1) {
        *buf = nullptr;
    } else {
        *buf = memPool.at(ret);
    }
    return ret;
}

void MemoryPool::returnBlock(int index) {
    if (index >= 0 && index < static_cast<int>(memPool.size())) {
        enQueue(index);
    }
}

inline void MemoryPool::enQueue(int index) {
    spin_lock(&lock);
    indexQ.push(index);
    spin_unlock(&lock);
}

inline int MemoryPool::deQueue() {
    int data = -1;
    spin_lock(&lock);
    if (indexQ.size()) {
        data = indexQ.front();
        indexQ.pop();
    }
    spin_unlock(&lock);
    return data;
}
