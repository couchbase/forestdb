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

#include <stdlib.h>

#include <queue>
#include <vector>

#include "common.h"

class MemoryPool {
/**
  The memory pool is a memory container designed for concurrent access and
  it contains:
  - A vector of pre-allocated heap memory (bins).
  - Each bin will be of the initially provided bin size.
  - A queue containing the indexes of the available bins from the vector.
  - A fetchBlock() operation gets an available resource and returns the index
    to the acquired bin, removes the index entry from the queue.
  - A returnBlock() operation requeues the provided index back into the queue,
    thereby making the bin pointed to by the index available again.

                        +---+---+---+---+---+---+----
            queue:      | 0 | 1 | 2 | 3 | 4 | 5 | ...
                        +---+---+---+---+---+---+----
                          |        ____________
                          +-----> |    bin1    |
                                  |____________|
                                  |    bin2    |
            vector:               |____________|
                                  |    bin3    |
                                  |____________|
                                  |     ..     |
*/

public:
    MemoryPool(int num_bins, size_t bin_size);

    ~MemoryPool();

    /**
     * Fetches an available block of memory (bin), making it unavailable for
     * other clients.
     *
     * @param buf Pointer to where the memory block is initialized.
     * @return index of bin in the vector, -1 if in case of no available bin.
     */
    const int fetchBlock(uint8_t **buf);

    /*
     * Return a block of memory (bin), making it available for other clients.
     *
     * @param index Index of the bin being returned back.
     */
    void returnBlock(int index);

private:

    /**
     * Pushes entry into queue.
     */
    void enQueue(int index);

    /**
     * Pops entry from queue.
     */
    int deQueue();

    // Spin lock for queue ops
    spin_t lock;
    // Queue of indexes
    std::queue<int> indexQ;
    // Vector of pre-allocated memory
    std::vector<uint8_t*> memPool;
};
