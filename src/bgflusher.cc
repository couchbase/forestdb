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

// TODO: Consolidate Various ForestDB Tasks into a Shared Thread Pool

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#if !defined(WIN32) && !defined(_WIN32)
#include <sys/time.h>
#include <dirent.h>
#include <unistd.h>
#endif

#include "libforestdb/forestdb.h"
#include "fdb_internal.h"
#include "filemgr.h"
#include "avltree.h"
#include "common.h"
#include "bgflusher.h"
#include "memleak.h"
#include "time_utils.h"

#ifdef __DEBUG
#ifndef __DEBUG_CPT
    #undef DBG
    #undef DBGCMD
    #undef DBGSW
    #define DBG(...)
    #define DBGCMD(...)
    #define DBGSW(n, ...)
#endif
#endif

struct openfiles_elem {
    char filename[FDB_MAX_FILENAME_LEN];
    FileMgr *file;
    fdb_config config;
    uint32_t register_count;
    bool background_flush_in_progress;
    ErrLogCallback *log_callback;
    struct avl_node avl;
};

std::atomic<BgFlusher *> BgFlusher::bgflusherInstance(nullptr);
std::mutex BgFlusher::bgfLock;

// compares file names
static int _bgflusher_cmp(struct avl_node *a, struct avl_node *b, void *aux)
{
    struct openfiles_elem *aa, *bb;
    aa = _get_entry(a, struct openfiles_elem, avl);
    bb = _get_entry(b, struct openfiles_elem, avl);
    return strncmp(aa->filename, bb->filename, FDB_MAX_FILENAME_LEN);
}

void *bgflusher_thread(void *voidargs) {
    BgFlusher *bgf = BgFlusher::getBgfInstance();
    fdb_assert(bgf, bgf, NULL);
    return bgf->bgflusherThread();
}

void * BgFlusher::bgflusherThread()
{
    fdb_status fs;
    struct avl_node *a;
    FileMgr *file;
    struct openfiles_elem *elem;
    ErrLogCallback *log_callback = NULL;

    while (1) {
        uint64_t num_blocks = 0;

        UniqueLock l_lock(bgfLock);
        a = avl_first(&openFiles);
        while(a) {
            filemgr_open_result ffs;
            elem = _get_entry(a, struct openfiles_elem, avl);
            file = elem->file;
            if (!file) {
                a = avl_next(a);
                avl_remove(&openFiles, &elem->avl);
                free(elem);
                continue;
            }

            if (elem->background_flush_in_progress) {
                a = avl_next(a);
            } else {
                elem->background_flush_in_progress = true;
                log_callback = elem->log_callback;
                ffs = FileMgr::open(file->getFileName(), file->getOps(),
                                    file->getConfig(), log_callback);
                fs = (fdb_status)ffs.rv;
                l_lock.unlock();
                if (fs == FDB_RESULT_SUCCESS) {
                    num_blocks += file->flushImmutable(log_callback);
                    FileMgr::close(file, false, file->getFileName(), log_callback);

                } else {
                    fdb_log(log_callback, fs,
                            "Failed to open the file '%s' for background flushing\n.",
                            file->getFileName());
                }
                l_lock.lock();
                elem->background_flush_in_progress = false;
                a = avl_next(&elem->avl);
                if (bgflusherTerminateSignal) {
                    return NULL;
                }
            }
        }
        l_lock.unlock();

        mutex_lock(&syncMutex);
        if (bgflusherTerminateSignal) {
            mutex_unlock(&syncMutex);
            break;
        }
        if (!num_blocks) {
            thread_cond_timedwait(&syncCond, &syncMutex,
                                  (unsigned)(bgFlusherSleepInSecs * 1000));
        }
        if (bgflusherTerminateSignal) {
            mutex_unlock(&syncMutex);
            break;
        }
        mutex_unlock(&syncMutex);
    }
    return NULL;
}

BgFlusher * BgFlusher::createBgFlusher(struct bgflusher_config *config)
{
    BgFlusher *tmp = bgflusherInstance.load();
    if (tmp == nullptr) {
        LockHolder l_lock(bgfLock);
        tmp = bgflusherInstance.load();
        if (tmp == nullptr) {
            tmp = new BgFlusher(config->num_threads);
            bgflusherInstance.store(tmp);
            // We must create threads only after the singleton instance is ready
            for (size_t i = 0; i < config->num_threads; ++i) {
                thread_create(&tmp->bgflusherThreadIds[i], bgflusher_thread,
                              NULL);
            }
        }
    }
    return tmp;
}

BgFlusher::BgFlusher(size_t num_threads) {
    // Note that this function is synchronized by spin lock in fdb_init API.
    // initialize
    avl_init(&openFiles, NULL);

    bgflusherTerminateSignal = 0;

    mutex_init(&syncMutex);
    thread_cond_init(&syncCond);

    // create worker threads
    numBgFlusherThreads = num_threads;
    bgFlusherSleepInSecs = FDB_BGFLUSHER_SLEEP_DURATION;

    bgflusherThreadIds = (thread_t *) calloc(numBgFlusherThreads,
                                         sizeof(thread_t));
}

BgFlusher *BgFlusher::getBgfInstance() {
    BgFlusher *bgf = bgflusherInstance.load();
    if (bgf == nullptr) {
        struct bgflusher_config default_config;
        default_config.num_threads = DEFAULT_NUM_BGFLUSHER_THREADS;
        return createBgFlusher(&default_config);
    }
    return bgf;
}

void BgFlusher::destroyBgFlusher() {
    LockHolder l_lock(bgfLock);
    BgFlusher *tmp  = bgflusherInstance.load();
    if (tmp != nullptr) {
        delete tmp;
        bgflusherInstance = nullptr;
    }
}

BgFlusher::~BgFlusher()
{
    void *ret;
    struct avl_node *a = NULL;
    struct openfiles_elem *elem;

    if (!bgflusherThreadIds) {
        return;
    }

    // set terminate signal
    mutex_lock(&syncMutex);
    bgflusherTerminateSignal = 1;
    thread_cond_broadcast(&syncCond);
    mutex_unlock(&syncMutex);

    for (size_t i = 0; i < numBgFlusherThreads; ++i) {
        thread_join(bgflusherThreadIds[i], &ret);
    }
    free(bgflusherThreadIds);
    bgflusherThreadIds = NULL;

    // free all elems in the tree
    a = avl_first(&openFiles);
    while (a) {
        elem = _get_entry(a, struct openfiles_elem, avl);
        a = avl_next(a);

        avl_remove(&openFiles, &elem->avl);
        free(elem);
    }

    bgFlusherSleepInSecs = FDB_BGFLUSHER_SLEEP_DURATION;
    mutex_destroy(&syncMutex);
    thread_cond_destroy(&syncCond);
}

fdb_status BgFlusher::registerFile_BgFlusher(FileMgr *file,
                                             fdb_config *config,
                                             ErrLogCallback *log_callback)
{
    file_status_t fMgrStatus;
    fdb_status fs = FDB_RESULT_SUCCESS;
    struct avl_node *a = NULL;
    struct openfiles_elem query, *elem;

    // Ignore files whose status is FILE_COMPACT_OLD to prevent
    // reinserting of files undergoing compaction if it is in the catchup phase
    // Also ignore files whose status is REMOVED_PENDING.
    fMgrStatus = file->getFileStatus();
    if (fMgrStatus == FILE_COMPACT_OLD ||
        fMgrStatus == FILE_REMOVED_PENDING) {
        return fs;
    }

    strcpy(query.filename, file->getFileName());
    // first search the existing file
    LockHolder l_lock(bgfLock);
    a = avl_search(&openFiles, &query.avl, _bgflusher_cmp);
    if (a == NULL) {
        // doesn't exist
        // create elem and insert into tree
        elem = (struct openfiles_elem *)calloc(1, sizeof(struct openfiles_elem));
        elem->file = file;
        strcpy(elem->filename, file->getFileName());
        elem->config = *config;
        elem->register_count = 1;
        elem->background_flush_in_progress = false;
        elem->log_callback = log_callback;
        avl_insert(&openFiles, &elem->avl, _bgflusher_cmp);
    } else {
        // already exists
        elem = _get_entry(a, struct openfiles_elem, avl);
        if (!elem->file) {
            elem->file = file;
        }
        elem->register_count++;
        elem->log_callback = log_callback; // use the latest
    }
    return fs;
}

void BgFlusher::switchFile_BgFlusher(FileMgr *old_file,
                                     FileMgr *new_file,
                                     ErrLogCallback *log_callback)
{
    struct avl_node *a = NULL;
    struct openfiles_elem query, *elem;

    strcpy(query.filename, old_file->getFileName());
    LockHolder l_lock(bgfLock);
    a = avl_search(&openFiles, &query.avl, _bgflusher_cmp);
    if (a) {
        elem = _get_entry(a, struct openfiles_elem, avl);
        avl_remove(&openFiles, a);
        strcpy(elem->filename, new_file->getFileName());
        elem->file = new_file;
        elem->register_count = 1;
        elem->background_flush_in_progress = false;
        avl_insert(&openFiles, &elem->avl, _bgflusher_cmp);
    }
}

void BgFlusher::deregisterFile_BgFlusher(FileMgr *file)
{
    struct avl_node *a = NULL;
    struct openfiles_elem query, *elem;

    strcpy(query.filename, file->getFileName());
    LockHolder l_lock(bgfLock);
    a = avl_search(&openFiles, &query.avl, _bgflusher_cmp);
    if (a) {
        elem = _get_entry(a, struct openfiles_elem, avl);
        if ((--elem->register_count) == 0) {
            // if no handle refers this file
            if (elem->background_flush_in_progress) {
                // Background flusher is writing blocks while the file is closed.
                // Do not remove 'elem' for now. The 'elem' will be automatically
                // removed once background flushing is done. Set elem->file
                // to NULL to indicate this intent.
                elem->file = NULL;
            } else {
                // remove from the tree
                avl_remove(&openFiles, &elem->avl);
                free(elem);
            }
        }
    }
}
