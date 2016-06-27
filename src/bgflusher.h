/* -*- Mode: C++; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2010 Couchbase, Inc
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
#include <mutex>
#include <time.h>

#include "internal_types.h"

struct bgflusher_config{
    size_t num_threads;
};

// Singleton Instance of Background Flusher
class BgFlusher {
public:
    static BgFlusher *getBgfInstance();
    static BgFlusher *createBgFlusher(struct bgflusher_config *config);
    static void destroyBgFlusher();

    fdb_status registerFile_BgFlusher(FileMgr *file,
                                      fdb_config *config,
                                      ErrLogCallback *log_callback);
    void switchFile_BgFlusher(FileMgr *old_file,
                              FileMgr *new_file,
                              ErrLogCallback *log_callback);
    void deregisterFile_BgFlusher(FileMgr *file);

private:
    BgFlusher(size_t num_threads);
    ~BgFlusher();

    friend void *bgflusher_thread(void *voidargs);

    void * bgflusherThread();

    static std::atomic<BgFlusher *> bgflusherInstance;
    static std::mutex bgfLock;

    size_t numBgFlusherThreads;
    thread_t *bgflusherThreadIds;

    size_t bgFlusherSleepInSecs;

    mutex_t syncMutex;
    thread_cond_t syncCond;

    std::atomic<uint8_t> bgflusherTerminateSignal;

    struct avl_tree openFiles;

    DISALLOW_COPY_AND_ASSIGN(BgFlusher);
};
