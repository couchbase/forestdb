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

// variables for initialization
volatile uint8_t bgflusher_initialized = 0;
static mutex_t bgf_lock;

static size_t num_bgflusher_threads = DEFAULT_NUM_BGFLUSHER_THREADS;
static thread_t *bgflusher_tids = NULL;

static size_t sleep_duration = FDB_BGFLUSHER_SLEEP_DURATION;

static mutex_t sync_mutex;
static thread_cond_t sync_cond;

static volatile uint8_t bgflusher_terminate_signal = 0;

static struct avl_tree openfiles;

struct openfiles_elem {
    char filename[FDB_MAX_FILENAME_LEN];
    struct filemgr *file;
    fdb_config config;
    uint32_t register_count;
    bool background_flush_in_progress;
    err_log_callback *log_callback;
    struct avl_node avl;
};

// compares file names
static int _bgflusher_cmp(struct avl_node *a, struct avl_node *b, void *aux)
{
    struct openfiles_elem *aa, *bb;
    aa = _get_entry(a, struct openfiles_elem, avl);
    bb = _get_entry(b, struct openfiles_elem, avl);
    return strncmp(aa->filename, bb->filename, FDB_MAX_FILENAME_LEN);
}

static void * bgflusher_thread(void *voidargs)
{
    fdb_status fs;
    struct avl_node *a;
    struct filemgr *file;
    struct openfiles_elem *elem;
    err_log_callback *log_callback = NULL;

    while (1) {
        uint64_t num_blocks = 0;

        mutex_lock(&bgf_lock);
        a = avl_first(&openfiles);
        while(a) {
            filemgr_open_result ffs;
            elem = _get_entry(a, struct openfiles_elem, avl);
            file = elem->file;
            if (!file) {
                a = avl_next(a);
                avl_remove(&openfiles, &elem->avl);
                free(elem);
                continue;
            }

            if (elem->background_flush_in_progress) {
                a = avl_next(a);
            } else {
                elem->background_flush_in_progress = true;
                log_callback = elem->log_callback;
                ffs = filemgr_open(file->filename, file->ops,
                        file->config, log_callback);
                fs = (fdb_status)ffs.rv;
                mutex_unlock(&bgf_lock);
                if (fs == FDB_RESULT_SUCCESS) {
                    num_blocks += filemgr_flush_immutable(file,
                                                          log_callback);
                    filemgr_close(file, 0, file->filename, log_callback);

                } else {
                    fdb_log(log_callback, fs,
                            "Failed to open the file '%s' for background flushing\n.",
                            file->filename);
                }
                mutex_lock(&bgf_lock);
                elem->background_flush_in_progress = false;
                a = avl_next(&elem->avl);
                if (bgflusher_terminate_signal) {
                    mutex_unlock(&bgf_lock);
                    return NULL;
                }
            }
        }
        mutex_unlock(&bgf_lock);

        mutex_lock(&sync_mutex);
        if (bgflusher_terminate_signal) {
            mutex_unlock(&sync_mutex);
            break;
        }
        if (!num_blocks) {
            thread_cond_timedwait(&sync_cond, &sync_mutex,
                                  (unsigned)(sleep_duration * 1000));
        }
        if (bgflusher_terminate_signal) {
            mutex_unlock(&sync_mutex);
            break;
        }
        mutex_unlock(&sync_mutex);
    }
    return NULL;
}

void bgflusher_init(struct bgflusher_config *config)
{
    if (!bgflusher_initialized) {
        // Note that this function is synchronized by spin lock in fdb_init API.
        mutex_init(&bgf_lock);

        mutex_lock(&bgf_lock);
        if (!bgflusher_initialized) {
            // initialize
            avl_init(&openfiles, NULL);

            bgflusher_terminate_signal = 0;

            mutex_init(&sync_mutex);
            thread_cond_init(&sync_cond);

            // create worker threads
            num_bgflusher_threads = config->num_threads;
            bgflusher_tids = (thread_t *) calloc(num_bgflusher_threads,
                                                 sizeof(thread_t));
            for (size_t i = 0; i < num_bgflusher_threads; ++i) {
                thread_create(&bgflusher_tids[i], bgflusher_thread, NULL);
            }

            bgflusher_initialized = 1;
        }
        mutex_unlock(&bgf_lock);
    }
}

void bgflusher_shutdown()
{
    void *ret;
    struct avl_node *a = NULL;
    struct openfiles_elem *elem;

    // set terminate signal
    mutex_lock(&sync_mutex);
    bgflusher_terminate_signal = 1;
    thread_cond_broadcast(&sync_cond);
    mutex_unlock(&sync_mutex);

    for (size_t i = 0; i < num_bgflusher_threads; ++i) {
        thread_join(bgflusher_tids[i], &ret);
    }
    free(bgflusher_tids);

    mutex_lock(&bgf_lock);
    // free all elems in the tree
    a = avl_first(&openfiles);
    while (a) {
        elem = _get_entry(a, struct openfiles_elem, avl);
        a = avl_next(a);

        avl_remove(&openfiles, &elem->avl);
        free(elem);
    }

    sleep_duration = FDB_BGFLUSHER_SLEEP_DURATION;
    bgflusher_initialized = 0;
    mutex_destroy(&sync_mutex);
    thread_cond_destroy(&sync_cond);
    mutex_unlock(&bgf_lock);

    mutex_destroy(&bgf_lock);
}

fdb_status bgflusher_register_file(struct filemgr *file,
                                   fdb_config *config,
                                   err_log_callback *log_callback)
{
    file_status_t fstatus;
    fdb_status fs = FDB_RESULT_SUCCESS;
    struct avl_node *a = NULL;
    struct openfiles_elem query, *elem;

    // Ignore files whose status is FILE_COMPACT_OLD to prevent
    // reinserting of files undergoing compaction if it is in the catchup phase
    // Also ignore files whose status is REMOVED_PENDING.
    fstatus = filemgr_get_file_status(file);
    if (fstatus == FILE_COMPACT_OLD ||
        fstatus == FILE_REMOVED_PENDING) {
        return fs;
    }

    strcpy(query.filename, file->filename);
    // first search the existing file
    mutex_lock(&bgf_lock);
    a = avl_search(&openfiles, &query.avl, _bgflusher_cmp);
    if (a == NULL) {
        // doesn't exist
        // create elem and insert into tree
        elem = (struct openfiles_elem *)calloc(1, sizeof(struct openfiles_elem));
        elem->file = file;
        strcpy(elem->filename, file->filename);
        elem->config = *config;
        elem->register_count = 1;
        elem->background_flush_in_progress = false;
        elem->log_callback = log_callback;
        avl_insert(&openfiles, &elem->avl, _bgflusher_cmp);
    } else {
        // already exists
        elem = _get_entry(a, struct openfiles_elem, avl);
        if (!elem->file) {
            elem->file = file;
        }
        elem->register_count++;
        elem->log_callback = log_callback; // use the latest
    }
    mutex_unlock(&bgf_lock);
    return fs;
}

void bgflusher_switch_file(struct filemgr *old_file, struct filemgr *new_file,
                           err_log_callback *log_callback)
{
    struct avl_node *a = NULL;
    struct openfiles_elem query, *elem;

    strcpy(query.filename, old_file->filename);
    mutex_lock(&bgf_lock);
    a = avl_search(&openfiles, &query.avl, _bgflusher_cmp);
    if (a) {
        elem = _get_entry(a, struct openfiles_elem, avl);
        avl_remove(&openfiles, a);
        strcpy(elem->filename, new_file->filename);
        elem->file = new_file;
        elem->register_count = 1;
        elem->background_flush_in_progress = false;
        avl_insert(&openfiles, &elem->avl, _bgflusher_cmp);
        mutex_unlock(&bgf_lock);
    } else {
        mutex_unlock(&bgf_lock);
    }
}

void bgflusher_deregister_file(struct filemgr *file)
{
    struct avl_node *a = NULL;
    struct openfiles_elem query, *elem;

    strcpy(query.filename, file->filename);
    mutex_lock(&bgf_lock);
    a = avl_search(&openfiles, &query.avl, _bgflusher_cmp);
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
                avl_remove(&openfiles, &elem->avl);
                free(elem);
            }
        }
    }
    mutex_unlock(&bgf_lock);
}
