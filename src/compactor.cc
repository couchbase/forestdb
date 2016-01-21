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
#include "list.h"
#include "common.h"
#include "filemgr_ops.h"
#include "configuration.h"
#include "internal_types.h"
#include "compactor.h"
#include "wal.h"
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

#define COMPACTOR_META_VERSION (1)
#define MAX_FNAMELEN (FDB_MAX_FILENAME_LEN)

// variables for initialization
static volatile uint8_t compactor_initialized = 0;
mutex_t cpt_lock;

static size_t num_compactor_threads = DEFAULT_NUM_COMPACTOR_THREADS;
static thread_t *compactor_tids = NULL;


static size_t sleep_duration = FDB_COMPACTOR_SLEEP_DURATION;

static mutex_t sync_mutex;
static thread_cond_t sync_cond;

static volatile uint8_t compactor_terminate_signal = 0;

static struct avl_tree openfiles;

struct openfiles_elem {
    char filename[MAX_FNAMELEN];
    struct filemgr *file;
    fdb_config config;
    uint32_t register_count;
    bool compaction_flag; // set when the file is being compacted
    bool daemon_compact_in_progress;
    bool removal_activated;
    err_log_callback *log_callback;
    struct avl_node avl;
    struct timeval last_compaction_timestamp;
    size_t interval;
};

struct compactor_args_t {
    // void *aux; (reserved for future use)
    size_t strcmp_len; // Used to search for prefix match
};
static struct compactor_args_t compactor_args;

struct compactor_meta{
    uint32_t version;
    char filename[MAX_FNAMELEN];
    uint32_t crc;
};

#if !defined(WIN32) && !defined(_WIN32)
static bool does_file_exist(const char *filename) {
    struct stat st;
    int result = stat(filename, &st);
    return result == 0;
}
#else
static bool does_file_exist(const char *filename) {
    return GetFileAttributes(filename) != INVALID_FILE_ATTRIBUTES;
}
#endif

// compares file names
int _compactor_cmp(struct avl_node *a, struct avl_node *b, void *aux)
{
    struct openfiles_elem *aa, *bb;
    struct compactor_args_t *args = (struct compactor_args_t *)aux;
    aa = _get_entry(a, struct openfiles_elem, avl);
    bb = _get_entry(b, struct openfiles_elem, avl);
    return strncmp(aa->filename, bb->filename, args->strcmp_len);
}

INLINE uint64_t _compactor_estimate_space(struct openfiles_elem *elem)
{
    uint64_t ret = 0;
    uint64_t datasize;
    uint64_t nlivenodes;

    datasize = _kvs_stat_get_sum(elem->file, KVS_STAT_DATASIZE);
    nlivenodes = _kvs_stat_get_sum(elem->file, KVS_STAT_NLIVENODES);

    ret = datasize;
    ret += nlivenodes * elem->config.blocksize;
    ret += wal_get_datasize(elem->file);

    return ret;
}

// check if the compaction threshold is satisfied
INLINE bool _compactor_is_threshold_satisfied(struct openfiles_elem *elem)
{
    uint64_t filesize;
    uint64_t active_data;
    int threshold;

    if (elem->compaction_flag || filemgr_is_rollback_on(elem->file)) {
        // do not perform compaction if the file is already being compacted or
        // in rollback.
        return false;
    }

    struct timeval curr_time, gap;
    gettimeofday(&curr_time, NULL);
    gap = _utime_gap(elem->last_compaction_timestamp, curr_time);
    uint64_t elapsed_us = (uint64_t)gap.tv_sec * 1000000 + gap.tv_usec;
    if (elapsed_us < (elem->interval * 1000000)) {
        return false;
    }

    threshold = elem->config.compaction_threshold;
    if (elem->config.compaction_mode == FDB_COMPACTION_AUTO &&
        threshold > 0)
        {
        filesize = filemgr_get_pos(elem->file);
        active_data = _compactor_estimate_space(elem);
        if (active_data == 0 || active_data >= filesize ||
            filesize < elem->config.compaction_minimum_filesize) {
            return false;
        }

        return ((filesize / 100.0 * threshold) < (filesize - active_data));
    } else {
        return false;
    }
}

// check if the file is waiting for being removed
INLINE bool _compactor_check_file_removal(struct openfiles_elem *elem)
{
    if (elem->file->fflags & FILEMGR_REMOVAL_IN_PROG &&
        !elem->removal_activated) {
        return true;
    }
    return false;
}

// check if background file deletion is done
bool compactor_is_file_removed(const char *filename)
{
    struct avl_node *a;
    struct openfiles_elem query;

    strcpy(query.filename, filename);
    mutex_lock(&cpt_lock);
    a = avl_search(&openfiles, &query.avl, _compactor_cmp);
    mutex_unlock(&cpt_lock);
    if (a) {
        // exist .. old file is not removed yet
        return false;
    }
    return true;
}

// return the location of '.'
INLINE int _compactor_prefix_len(char *filename)
{
    int i;
    int file_len = strlen(filename);
    int prefix_len = 0;
    // find the first '.'
    for (i=file_len-1; i>=0; --i){
        if (filename[i] == '.') {
            prefix_len = i+1;
            break;
        }
    }
    return prefix_len;
}

// return the the location of '/' or '\'
INLINE int _compactor_dir_len(char *filename)
{
    int i;
    int file_len = strlen(filename);
    int dir_len = 0;
    // find the first '/' or '\'
    for (i=file_len-1; i>=0; --i){
        if (filename[i] == '/' || filename[i] == '\\') {
            dir_len = i+1;
            break;
        }
    }
    return dir_len;
}

// copy from 'foo/bar.baz' to 'bar.baz'
static void _strcpy_fname(char *dst, char *src)
{
    int dir_len = _compactor_dir_len(src);
    strcpy(dst, src + dir_len);
}

// copy from 'foo/bar.baz' to 'foo/' (including '/')
static void _strcpy_dirname(char *dst, char *src)
{
    int dir_len = _compactor_dir_len(src);
    if (dir_len) {
        strncpy(dst, src, dir_len);
    }
    // set NULL char
    dst[dir_len] = 0;
}

// <example>
// fname: 'foo.bar'
// path: 'tmp/dir/other.file'
// returned dst: 'tmp/dir/foo.bar'
static void _reconstruct_path(char *dst, char *path, char *fname)
{
    _strcpy_dirname(dst, path);
    strcat(dst + strlen(dst), fname);
}

static void _compactor_get_vfilename(char *filename, char *vfilename)
{
    int prefix_len = _compactor_prefix_len(filename);

    if (prefix_len > 0) {
        strncpy(vfilename, filename, prefix_len-1);
        vfilename[prefix_len-1] = 0;
    }
}

static void _compactor_convert_dbfile_to_metafile(char *dbfile, char *metafile)
{
    int prefix_len = _compactor_prefix_len(dbfile);

    if (prefix_len > 0) {
        strncpy(metafile, dbfile, prefix_len);
        metafile[prefix_len] = 0;
        strcat(metafile, "meta");
    }
}

static bool _allDigit(char *str) {
    int numchar = strlen(str);
    for(int i = 0; i < numchar; ++i) {
        if (str[i] < '0' || str[i] > '9') {
            return false;
        }
    }
    return true;
}

void compactor_get_next_filename(char *file, char *nextfile)
{
    int compaction_no = 0;
    int prefix_len = _compactor_prefix_len(file);
    char str_no[24];

    if (prefix_len > 0 && _allDigit(file + prefix_len)) {
        sscanf(file+prefix_len, "%d", &compaction_no);
        strncpy(nextfile, file, prefix_len);
        do {
            nextfile[prefix_len] = 0;
            sprintf(str_no, "%d", ++compaction_no);
            strcat(nextfile, str_no);
        } while (does_file_exist(nextfile));
    } else {
        do {
            strcpy(nextfile, file);
            sprintf(str_no, ".%d", ++compaction_no);
            strcat(nextfile, str_no);
        } while (does_file_exist(nextfile));
    }
}

bool compactor_switch_compaction_flag(struct filemgr *file, bool flag)
{
    struct avl_node *a = NULL;
    struct openfiles_elem query, *elem;

    strcpy(query.filename, file->filename);
    mutex_lock(&cpt_lock);
    a = avl_search(&openfiles, &query.avl, _compactor_cmp);
    if (a) {
        // found
        elem = _get_entry(a, struct openfiles_elem, avl);
        if (elem->compaction_flag == flag) {
            // already switched by other thread .. return false
            mutex_unlock(&cpt_lock);
            return false;
        }
        // switch
        elem->compaction_flag = flag;
        mutex_unlock(&cpt_lock);
        return true;
    }
    // file doesn't exist .. already compacted or deregistered
    mutex_unlock(&cpt_lock);
    return false;
}

void * compactor_thread(void *voidargs)
{
    char vfilename[MAX_FNAMELEN];
    char new_filename[MAX_FNAMELEN];
    fdb_file_handle *fhandle;
    fdb_status fs;
    struct avl_node *a;
    struct openfiles_elem *elem;
    struct openfiles_elem query;

    // Sleep for a configured period by default to allow applications to warm up their data.
    // TODO: Need to implement more flexible way of scheduling the compaction
    // daemon (e.g., public APIs to start / stop the compaction daemon).
    mutex_lock(&sync_mutex);
    if (compactor_terminate_signal) {
        mutex_unlock(&sync_mutex);
        return NULL;
    }
    thread_cond_timedwait(&sync_cond, &sync_mutex, sleep_duration * 1000);
    mutex_unlock(&sync_mutex);

    while (1) {

        mutex_lock(&cpt_lock);
        a = avl_first(&openfiles);
        while(a) {
            elem = _get_entry(a, struct openfiles_elem, avl);
            if (!elem->file) {
                a = avl_next(a);
                avl_remove(&openfiles, &elem->avl);
                free(elem);
                continue;
            }

            if (_compactor_is_threshold_satisfied(elem)) {

                elem->daemon_compact_in_progress = true;
                // set compaction flag
                elem->compaction_flag = true;
                mutex_unlock(&cpt_lock);
                // Once 'daemon_compact_in_progress' is set to true, then it is safe to
                // read the variables of 'elem' until the compaction is completed.
                _compactor_get_vfilename(elem->filename, vfilename);

                // Get the list of custom compare functions.
                struct list cmp_func_list;
                list_init(&cmp_func_list);
                fdb_cmp_func_list_from_filemgr(elem->file, &cmp_func_list);
                fs = fdb_open_for_compactor(&fhandle, vfilename, &elem->config,
                                           &cmp_func_list);
                fdb_free_cmp_func_list(&cmp_func_list);

                if (fs == FDB_RESULT_SUCCESS) {
                    compactor_get_next_filename(elem->filename, new_filename);
                    fdb_compact_file(fhandle, new_filename, false, (bid_t) -1,
                                     false, NULL);
                    fdb_close(fhandle);

                    strcpy(query.filename, new_filename);
                    mutex_lock(&cpt_lock);
                    // Search the next file for compaction.
                    a = avl_search_greater(&openfiles, &query.avl, _compactor_cmp);
                } else {
                    // As a workaround for MB-17009, call fprintf instead of fdb_log
                    // until c->cgo->go callback trace issue is resolved.
                    fprintf(stderr,
                            "Error status code: %d, Failed to open the file "
                            "'%s' for auto daemon compaction.\n",
                            fs, vfilename);
                    // fail to open file
                    mutex_lock(&cpt_lock);
                    a = avl_next(&elem->avl);
                    elem->daemon_compact_in_progress = false;
                    // clear compaction flag
                    elem->compaction_flag = false;
                }

            } else if (_compactor_check_file_removal(elem)) {

                // remove file
                int ret;

                // set activation flag to prevent other compactor threads attempt
                // to remove the same file and double free the 'elem' structure,
                // during 'cpt_lock' is released.
                elem->removal_activated = true;

                mutex_unlock(&cpt_lock);
                // As the file is already unlinked, just close it.
                ret = elem->file->ops->close(elem->file->fd);
#if defined(WIN32) || defined(_WIN32)
                // For Windows, we need to manually remove the file.
                ret = remove(elem->file->filename);
#endif
                filemgr_remove_all_buffer_blocks(elem->file);
                mutex_lock(&cpt_lock);

                if (elem->log_callback && ret != 0) {
                    char errno_msg[512];
                    elem->file->ops->get_errno_str(errno_msg, 512);
                    // As a workaround for MB-17009, call fprintf instead of fdb_log
                    // until c->cgo->go callback trace issue is resolved.
                    fprintf(stderr,
                            "Error status code: %d, Error in REMOVE on a "
                            "database file '%s', %s",
                            ret, elem->file->filename, errno_msg);
                }

                // free filemgr structure
                filemgr_free_func(&elem->file->e);
                // remove & free elem
                a = avl_next(a);
                avl_remove(&openfiles, &elem->avl);
                free(elem);

            } else {

                // next
                a = avl_next(a);

            }
            if (compactor_terminate_signal) {
                mutex_unlock(&cpt_lock);
                return NULL;
            }
        }
        mutex_unlock(&cpt_lock);

        mutex_lock(&sync_mutex);
        if (compactor_terminate_signal) {
            mutex_unlock(&sync_mutex);
            break;
        }
        // As each database file can be opened at different times, we need to
        // wake up each compaction thread with a shorter interval to check if
        // the time since the last compaction of a given file is already passed
        // by a configured compaction interval and consequently the file should
        // be compacted or not.
        thread_cond_timedwait(&sync_cond, &sync_mutex, 15 * 1000); // Wait for 15 secs.
        if (compactor_terminate_signal) {
            mutex_unlock(&sync_mutex);
            break;
        }
        mutex_unlock(&sync_mutex);
    }
    return NULL;
}

void compactor_init(struct compactor_config *config)
{
    if (!compactor_initialized) {
        // Note that this function is synchronized by the spin lock in fdb_init API.
        mutex_init(&cpt_lock);

        mutex_lock(&cpt_lock);
        if (!compactor_initialized) {
            // initialize
            compactor_args.strcmp_len = MAX_FNAMELEN;
            avl_init(&openfiles, &compactor_args);

            if (config) {
                if (config->sleep_duration > 0) {
                    sleep_duration = config->sleep_duration;
                }
            }

            compactor_terminate_signal = 0;

            mutex_init(&sync_mutex);
            thread_cond_init(&sync_cond);

            // create worker threads
            num_compactor_threads = config->num_threads;
            compactor_tids = (thread_t *) calloc(num_compactor_threads, sizeof(thread_t));
            for (size_t i = 0; i < num_compactor_threads; ++i) {
                thread_create(&compactor_tids[i], compactor_thread, NULL);
            }

            compactor_initialized = 1;
        }
        mutex_unlock(&cpt_lock);
    }
}

void compactor_shutdown()
{
    void *ret;
    struct avl_node *a = NULL;
    struct openfiles_elem *elem;

    // set terminate signal
    mutex_lock(&sync_mutex);
    compactor_terminate_signal = 1;
    thread_cond_broadcast(&sync_cond);
    mutex_unlock(&sync_mutex);

    for (size_t i = 0; i < num_compactor_threads; ++i) {
        thread_join(compactor_tids[i], &ret);
    }
    free(compactor_tids);

    mutex_lock(&cpt_lock);
    // free all elems in the tree
    a = avl_first(&openfiles);
    while (a) {
        elem = _get_entry(a, struct openfiles_elem, avl);
        a = avl_next(a);

        if (_compactor_check_file_removal(elem)) {
            // remove file if removal is pended.
            remove(elem->file->filename);
            filemgr_free_func(&elem->file->e);
        }

        avl_remove(&openfiles, &elem->avl);
        free(elem);
    }

    sleep_duration = FDB_COMPACTOR_SLEEP_DURATION;
    compactor_initialized = 0;
    mutex_destroy(&sync_mutex);
    thread_cond_destroy(&sync_cond);
    mutex_unlock(&cpt_lock);

    mutex_destroy(&cpt_lock);
}

static fdb_status _compactor_store_metafile(char *metafile,
                                            struct compactor_meta *metadata,
                                            err_log_callback *log_callback);

fdb_status compactor_register_file(struct filemgr *file,
                                   fdb_config *config,
                                   err_log_callback *log_callback)
{
    file_status_t fstatus;
    fdb_status fs = FDB_RESULT_SUCCESS;
    struct avl_node *a = NULL;
    struct openfiles_elem query, *elem;

    // Ignore files whose status is COMPACT_OLD or REMOVED_PENDING.
    // Those files do not need to be compacted again.
    fstatus = filemgr_get_file_status(file);
    if (fstatus == FILE_COMPACT_OLD ||
        fstatus == FILE_REMOVED_PENDING) {
        return fs;
    }

    strcpy(query.filename, file->filename);
    // first search the existing file
    mutex_lock(&cpt_lock);
    a = avl_search(&openfiles, &query.avl, _compactor_cmp);
    if (a == NULL) {
        // doesn't exist
        // create elem and insert into tree
        char path[MAX_FNAMELEN];
        struct compactor_meta meta;

        elem = (struct openfiles_elem *)calloc(1, sizeof(struct openfiles_elem));
        strcpy(elem->filename, file->filename);
        elem->file = file;
        elem->config = *config;
        elem->config.cleanup_cache_onclose = false; // prevent MB-16422
        elem->register_count = 1;
        elem->compaction_flag = false;
        elem->daemon_compact_in_progress = false;
        elem->removal_activated = false;
        elem->log_callback = log_callback;
        gettimeofday(&elem->last_compaction_timestamp, NULL);
        // Init the compaction interval using the global param
        elem->interval = sleep_duration;
        avl_insert(&openfiles, &elem->avl, _compactor_cmp);
        mutex_unlock(&cpt_lock); // Releasing the lock here should be OK as
                                 // subsequent registration attempts for the same file
                                 // will be simply processed by incrementing its
                                 // counter below.

        // store in metafile
        _compactor_convert_dbfile_to_metafile(file->filename, path);
        _strcpy_fname(meta.filename, file->filename);
        fs = _compactor_store_metafile(path, &meta, log_callback);
    } else {
        // already exists
        elem = _get_entry(a, struct openfiles_elem, avl);
        if (!elem->file) {
            elem->file = file;
        }
        elem->register_count++;
        mutex_unlock(&cpt_lock);
    }
    return fs;
}

void compactor_deregister_file(struct filemgr *file)
{
    struct avl_node *a = NULL;
    struct openfiles_elem query, *elem;

    strcpy(query.filename, file->filename);
    mutex_lock(&cpt_lock);
    a = avl_search(&openfiles, &query.avl, _compactor_cmp);
    if (a) {
        elem = _get_entry(a, struct openfiles_elem, avl);
        if ((--elem->register_count) == 0) {
            // if no handle refers this file
            if (elem->daemon_compact_in_progress) {
                // This file is waiting for compaction by compactor (but not opened
                // yet). Do not remove 'elem' for now. The 'elem' will be automatically
                // replaced after the compaction is done by calling
                // 'compactor_switch_file()'. However, elem->file should be set to NULL
                // in order to be removed from the AVL tree in case of the compaction
                // failure.
                elem->file = NULL;
            } else {
                // remove from the tree
                avl_remove(&openfiles, &elem->avl);
                free(elem);
            }
        }
    }
    mutex_unlock(&cpt_lock);
}

fdb_status compactor_register_file_removing(struct filemgr *file,
                                            err_log_callback *log_callback)
{
    fdb_status fs = FDB_RESULT_SUCCESS;
    struct avl_node *a = NULL;
    struct openfiles_elem query, *elem;

    strcpy(query.filename, file->filename);
    // first search the existing file
    mutex_lock(&cpt_lock);
    a = avl_search(&openfiles, &query.avl, _compactor_cmp);
    if (a == NULL) {
        // doesn't exist
        // create a fake & temporary element for the file to be removed.
        elem = (struct openfiles_elem *)calloc(1, sizeof(struct openfiles_elem));
        strcpy(elem->filename, file->filename);

        // set flag
        file->fflags |= FILEMGR_REMOVAL_IN_PROG;

        elem->file = file;
        elem->register_count = 1;
        // to prevent this element to be compacted, set all flags
        elem->compaction_flag = true;
        elem->daemon_compact_in_progress = true;
        elem->removal_activated = false;
        elem->log_callback = log_callback;
        gettimeofday(&elem->last_compaction_timestamp, NULL);
        // Init the compaction interval using the global param
        elem->interval = sleep_duration;
        avl_insert(&openfiles, &elem->avl, _compactor_cmp);
        mutex_unlock(&cpt_lock); // Releasing the lock here should be OK as
                                 // subsequent registration attempts for the same file
                                 // will be simply processed by incrementing its
                                 // counter below.

        // wake up any sleeping thread
        mutex_lock(&sync_mutex);
        thread_cond_signal(&sync_cond);
        mutex_unlock(&sync_mutex);

    } else {
        // already exists .. just ignore
        mutex_unlock(&cpt_lock);
    }
    return fs;
}

void compactor_change_threshold(struct filemgr *file, size_t new_threshold)
{
    struct avl_node *a = NULL;
    struct openfiles_elem query, *elem;

    strcpy(query.filename, file->filename);
    mutex_lock(&cpt_lock);
    a = avl_search(&openfiles, &query.avl, _compactor_cmp);
    if (a) {
        elem = _get_entry(a, struct openfiles_elem, avl);
        elem->config.compaction_threshold = new_threshold;
    }
    mutex_unlock(&cpt_lock);
}

fdb_status compactor_set_compaction_interval(struct filemgr *file,
                                             size_t interval)
{
    struct avl_node *a = NULL;
    struct openfiles_elem query, *elem;
    fdb_status result = FDB_RESULT_SUCCESS;

    strcpy(query.filename, file->filename);
    mutex_lock(&cpt_lock);
    a = avl_search(&openfiles, &query.avl, _compactor_cmp);
    if (a) {
        elem = _get_entry(a, struct openfiles_elem, avl);
        elem->interval = interval;
    } else {
        result = FDB_RESULT_INVALID_ARGS;
    }
    mutex_unlock(&cpt_lock);
    return result;
}

struct compactor_meta * _compactor_read_metafile(char *metafile,
                                                 struct compactor_meta *metadata,
                                                 err_log_callback *log_callback)
{
    int fd_meta, fd_db;
    ssize_t ret;
    uint8_t *buf = alca(uint8_t, sizeof(struct compactor_meta));
    uint32_t crc;
    char fullpath[MAX_FNAMELEN];
    struct filemgr_ops *ops;
    struct compactor_meta meta;

    ops = get_filemgr_ops();
    fd_meta = ops->open(metafile, O_RDONLY, 0644);

    if (fd_meta >= 0) {
        // metafile exists .. read metadata
        ret = ops->pread(fd_meta, buf, sizeof(struct compactor_meta), 0);
        if (ret < 0 || (size_t)ret < sizeof(struct compactor_meta)) {
            char errno_msg[512];
            ops->get_errno_str(errno_msg, 512);
            // As a workaround for MB-17009, call fprintf instead of fdb_log
            // until c->cgo->go callback trace issue is resolved.
            fprintf(stderr,
                    "Error status code: %d, Failed to read the meta file '%s', "
                    "errno_message: %s\n",
                    (int)ret, metafile, errno_msg);
            ret = ops->close(fd_meta);
            if (ret < 0) {
                ops->get_errno_str(errno_msg, 512);
                fprintf(stderr,
                        "Error status code: %d, Failed to close the meta "
                        "file '%s', errno_message: %s\n",
                        (int)ret, metafile, errno_msg);
            }
            return NULL;
        }
        memcpy(&meta, buf, sizeof(struct compactor_meta));
        meta.version = _endian_decode(meta.version);
        meta.crc = _endian_decode(meta.crc);
        ops->close(fd_meta);

        // CRC check, mode UNKNOWN means all modes are checked.
        if (!perform_integrity_check(buf,
                                     sizeof(struct compactor_meta) - sizeof(crc),
                                     meta.crc,
                                     CRC_UNKNOWN)) {
            fprintf(stderr,
                    "Error status code: %d, Checksum mismatch in the meta file '%s'\n",
                    FDB_RESULT_CHECKSUM_ERROR, metafile);
            return NULL;
        }
        // check if the file exists
        _reconstruct_path(fullpath, metafile, meta.filename);
        fd_db = ops->open(fullpath, O_RDONLY, 0644);
        if (fd_db < 0) {
            // file doesn't exist
            return NULL;
        }
        ops->close(fd_db);
    } else {
        // file doesn't exist
        return NULL;
    }

    *metadata = meta;
    return metadata;
}

static fdb_status _compactor_store_metafile(char *metafile,
                                            struct compactor_meta *metadata,
                                            err_log_callback *log_callback)
{
    int fd_meta;
    ssize_t ret;
    uint32_t crc;
    struct filemgr_ops *ops;
    struct compactor_meta meta;

    ops = get_filemgr_ops();
    fd_meta = ops->open(metafile, O_RDWR | O_CREAT, 0644);

    if (fd_meta >= 0){
        meta.version = _endian_encode(COMPACTOR_META_VERSION);
        strcpy(meta.filename, metadata->filename);
        crc = get_checksum(reinterpret_cast<const uint8_t*>(&meta),
                           sizeof(struct compactor_meta) - sizeof(crc));
        meta.crc = _endian_encode(crc);

        char errno_msg[512];
        ret = ops->pwrite(fd_meta, &meta, sizeof(struct compactor_meta), 0);
        if (ret < 0 || (size_t)ret < sizeof(struct compactor_meta)) {
            ops->get_errno_str(errno_msg, 512);
            // As a workaround for MB-17009, call fprintf instead of fdb_log
            // until c->cgo->go callback trace issue is resolved.
            fprintf(stderr,
                    "Error status code: %d, Failed to perform a write in the meta "
                    "file '%s', errno_message: %s\n",
                    (int)ret, metafile, errno_msg);
            ops->close(fd_meta);
            return FDB_RESULT_WRITE_FAIL;
        }
        ret = ops->fsync(fd_meta);
        if (ret < 0) {
            ops->get_errno_str(errno_msg, 512);
            fprintf(stderr,
                    "Error status code: %d, Failed to perform a sync in the meta "
                    "file '%s', errno_message: %s\n",
                    (int)ret, metafile, errno_msg);
            ops->close(fd_meta);
            return FDB_RESULT_FSYNC_FAIL;
        }
        ops->close(fd_meta);
    } else {
        return FDB_RESULT_OPEN_FAIL;
    }

    return FDB_RESULT_SUCCESS;
}

void compactor_switch_file(struct filemgr *old_file, struct filemgr *new_file,
                           err_log_callback *log_callback)
{
    struct avl_node *a = NULL;
    struct openfiles_elem query, *elem;
    struct compactor_meta meta;

    strcpy(query.filename, old_file->filename);
    mutex_lock(&cpt_lock);
    a = avl_search(&openfiles, &query.avl, _compactor_cmp);
    if (a) {
        char metafile[MAX_FNAMELEN];
        fdb_compaction_mode_t comp_mode;

        elem = _get_entry(a, struct openfiles_elem, avl);
        avl_remove(&openfiles, a);
        strcpy(elem->filename, new_file->filename);
        elem->file = new_file;
        elem->register_count = 1;
        elem->daemon_compact_in_progress = false;
        // clear compaction flag
        elem->compaction_flag = false;
        // As this function is invoked at the end of compaction, set the compaction
        // timestamp to the current time.
        gettimeofday(&elem->last_compaction_timestamp, NULL);
        avl_insert(&openfiles, &elem->avl, _compactor_cmp);
        comp_mode = elem->config.compaction_mode;
        mutex_unlock(&cpt_lock); // Releasing the lock here should be OK as we don't
                                 // expect more than one compaction task completion for
                                 // the same file.

        if (comp_mode == FDB_COMPACTION_AUTO) {
            _compactor_convert_dbfile_to_metafile(new_file->filename, metafile);
            _strcpy_fname(meta.filename, new_file->filename);
            _compactor_store_metafile(metafile, &meta, log_callback);
        }
    } else {
        mutex_unlock(&cpt_lock);
    }
}

void compactor_get_virtual_filename(const char *filename,
                                    char *virtual_filename)
{
    int prefix_len = _compactor_prefix_len((char*)filename) - 1;
    if (prefix_len > 0) {
        strncpy(virtual_filename, filename, prefix_len);
        virtual_filename[prefix_len] = 0;
    } else {
        strcpy(virtual_filename, filename);
    }
}

fdb_status compactor_get_actual_filename(const char *filename,
                                         char *actual_filename,
                                         fdb_compaction_mode_t comp_mode,
                                         err_log_callback *log_callback)
{
    int i;
    int filename_len;
    int dirname_len;
    int compaction_no, max_compaction_no = -1;
    char path[MAX_FNAMELEN];
    char dirname[MAX_FNAMELEN], prefix[MAX_FNAMELEN];
    char ret_name[MAX_FNAMELEN];
    fdb_status fs = FDB_RESULT_SUCCESS;
    struct compactor_meta meta, *meta_ptr;

    // get actual filename from metafile
    sprintf(path, "%s.meta", filename);
    meta_ptr = _compactor_read_metafile(path, &meta, log_callback);

    if (meta_ptr == NULL) {
        if (comp_mode == FDB_COMPACTION_MANUAL && does_file_exist(filename)) {
            strcpy(actual_filename, filename);
            return FDB_RESULT_SUCCESS;
        }

        // error handling .. scan directory
        // backward search until find the first '/' or '\' (Windows)
        filename_len = strlen(filename);
        dirname_len = 0;

#if !defined(WIN32) && !defined(_WIN32)
        DIR *dir_info;
        struct dirent *dir_entry;

        for (i=filename_len-1; i>=0; --i){
            if (filename[i] == '/') {
                dirname_len = i+1;
                break;
            }
        }

        if (dirname_len > 0) {
            strncpy(dirname, filename, dirname_len);
            dirname[dirname_len] = 0;
        } else {
            strcpy(dirname, ".");
        }
        strcpy(prefix, filename + dirname_len);
        strcat(prefix, ".");

        dir_info = opendir(dirname);
        if (dir_info != NULL) {
            while ((dir_entry = readdir(dir_info))) {
                if (!strncmp(dir_entry->d_name, prefix, strlen(prefix))) {
                    compaction_no = -1;
                    sscanf(dir_entry->d_name + strlen(prefix), "%d", &compaction_no);
                    if (compaction_no >= 0) {
                        if (compaction_no > max_compaction_no) {
                            max_compaction_no = compaction_no;
                        }
                    }
                }
            }
            closedir(dir_info);
        }
#else
        // Windows
        for (i=filename_len-1; i>=0; --i){
            if (filename[i] == '/' || filename[i] == '\\') {
                dirname_len = i+1;
                break;
            }
        }

        if (dirname_len > 0) {
            strncpy(dirname, filename, dirname_len);
            dirname[dirname_len] = 0;
        } else {
            strcpy(dirname, ".");
        }
        strcpy(prefix, filename + dirname_len);
        strcat(prefix, ".");

        WIN32_FIND_DATA filedata;
        HANDLE hfind;
        char query_str[MAX_FNAMELEN];

        // find all files start with 'prefix'
        sprintf(query_str, "%s*", prefix);
        hfind = FindFirstFile(query_str, &filedata);
        while (hfind != INVALID_HANDLE_VALUE) {
            if (!strncmp(filedata.cFileName, prefix, strlen(prefix))) {
                compaction_no = -1;
                sscanf(filedata.cFileName + strlen(prefix), "%d", &compaction_no);
                if (compaction_no >= 0) {
                    if (compaction_no > max_compaction_no) {
                        max_compaction_no = compaction_no;
                    }
                }
            }

            if (!FindNextFile(hfind, &filedata)) {
                FindClose(hfind);
                hfind = INVALID_HANDLE_VALUE;
            }
        }

#endif

        if (max_compaction_no < 0) {
            if (comp_mode == FDB_COMPACTION_AUTO) {
                // DB files with a revision number are not found.
                // initialize filename to '[filename].0'
                sprintf(ret_name, "%s.0", filename);
            } else { // Manual compaction mode.
                // Simply use the file name passed to this function.
                strcpy(actual_filename, filename);
                return FDB_RESULT_SUCCESS;
            }
        } else {
            // return the file that has the largest compaction number
            sprintf(ret_name, "%s.%d", filename, max_compaction_no);
            fs = FDB_RESULT_SUCCESS;
        }
        if (fs == FDB_RESULT_SUCCESS) {
            strcpy(actual_filename, ret_name);
        }
        return fs;

    } else {
        // metadata is successfully read from the metafile .. just return the filename
        _reconstruct_path(ret_name, (char*)filename, meta.filename);
        strcpy(actual_filename, ret_name);
        return FDB_RESULT_SUCCESS;
    }
}

bool compactor_is_valid_mode(const char *filename, fdb_config *config)
{
    int fd;
    char path[MAX_FNAMELEN];
    struct filemgr_ops *ops;

    ops = get_filemgr_ops();

    if (config->compaction_mode == FDB_COMPACTION_AUTO) {
        // auto compaction mode: invalid when
        // the file '[filename]' exists
        fd = ops->open(filename, O_RDONLY, 0644);
        if (fd != FDB_RESULT_NO_SUCH_FILE) {
            ops->close(fd);
            return false;
        }

    } else if (config->compaction_mode == FDB_COMPACTION_MANUAL) {
        // manual compaction mode: invalid when
        // the file '[filename].meta' exists
        sprintf(path, "%s.meta", filename);
        fd = ops->open(path, O_RDONLY, 0644);
        if (fd != FDB_RESULT_NO_SUCH_FILE) {
            ops->close(fd);
            return false;
        }

    } else {
        // unknown mode
        return false;
    }

    return true;
}

static fdb_status _compactor_search_n_destroy(const char *filename)
{
    int i;
    int filename_len;
    int dirname_len;
    char dirname[MAX_FNAMELEN], prefix[MAX_FNAMELEN];
    char full_fname[MAX_FNAMELEN];
    fdb_status fs = FDB_RESULT_SUCCESS;

    // error handling .. scan directory
    // backward search until find the first '/' or '\' (Windows)
    filename_len = strlen(filename);
    dirname_len = 0;

#if !defined(WIN32) && !defined(_WIN32)
    DIR *dir_info;
    struct dirent *dir_entry;

    for (i=filename_len-1; i>=0; --i){
        if (filename[i] == '/') {
            dirname_len = i+1;
            break;
        }
    }

    if (dirname_len > 0) {
        strncpy(dirname, filename, dirname_len);
        dirname[dirname_len] = 0;
    } else {
        strcpy(dirname, ".");
    }
    strcpy(prefix, filename + dirname_len);
    strcat(prefix, ".");

    dir_info = opendir(dirname);
    if (dir_info != NULL) {
        while ((dir_entry = readdir(dir_info))) {
            if (!strncmp(dir_entry->d_name, prefix, strlen(prefix))) {
                // Need to check filemgr for possible open entry?
                // Reconstruct full path
                _reconstruct_path(full_fname, dirname, dir_entry->d_name);
                if (remove(full_fname)) {
                    fs = FDB_RESULT_FILE_REMOVE_FAIL;
                    closedir(dir_info);
                    return fs;
                }
            }
        }
        closedir(dir_info);
    }
#else
    // Windows
    for (i=filename_len-1; i>=0; --i){
        if (filename[i] == '/' || filename[i] == '\\') {
            dirname_len = i+1;
            break;
        }
    }

    if (dirname_len > 0) {
        strncpy(dirname, filename, dirname_len);
        dirname[dirname_len] = 0;
    } else {
        strcpy(dirname, ".");
    }
    strcpy(prefix, filename + dirname_len);
    strcat(prefix, ".");

    WIN32_FIND_DATA filedata;
    HANDLE hfind;
    char query_str[MAX_FNAMELEN];

    // find all files start with 'prefix'
    sprintf(query_str, "%s*", prefix);
    hfind = FindFirstFile(query_str, &filedata);
    while (hfind != INVALID_HANDLE_VALUE) {
        if (!strncmp(filedata.cFileName, prefix, strlen(prefix))) {
            // Need to check filemgr for possible open entry?
            // Reconstruct full path
            _reconstruct_path(full_fname, dirname, filedata.cFileName);
            if (remove(full_fname)) {
                fs = FDB_RESULT_FILE_REMOVE_FAIL;
                FindClose(hfind);
                hfind = INVALID_HANDLE_VALUE;
                return fs;
            }
        }

        if (!FindNextFile(hfind, &filedata)) {
            FindClose(hfind);
            hfind = INVALID_HANDLE_VALUE;
        }
    }

#endif
    return fs;
}

fdb_status compactor_destroy_file(char *filename,
                                  fdb_config *config)
{
    struct avl_node *a = NULL;
    struct openfiles_elem query, *elem;
    size_t strcmp_len;
    fdb_status status = FDB_RESULT_SUCCESS;
    compactor_config c_config;

    strcmp_len = strlen(filename);
    filename[strcmp_len] = '.'; // add a . suffix in place
    strcmp_len++;
    filename[strcmp_len] = '\0';
    strcpy(query.filename, filename);

    c_config.sleep_duration = config->compactor_sleep_duration;
    c_config.num_threads = config->num_compactor_threads;
    compactor_init(&c_config);

    mutex_lock(&cpt_lock);
    compactor_args.strcmp_len = strcmp_len; // Do prefix match for all vers
    a = avl_search(&openfiles, &query.avl, _compactor_cmp);
    if (a) {
        elem = _get_entry(a, struct openfiles_elem, avl);
        // if no handle refers this file
        if (elem->daemon_compact_in_progress) {
            // This file is waiting for compaction by compactor
            // Return a temporary failure, user must retry after sometime
            status = FDB_RESULT_IN_USE_BY_COMPACTOR;
        } else { // File handle not closed, fail operation
            status = FDB_RESULT_FILE_IS_BUSY;
        }
    }

    compactor_args.strcmp_len = MAX_FNAMELEN; // restore for normal compare
    mutex_unlock(&cpt_lock); // Releasing the lock here should be OK as file
                             // deletions doesn't require strict synchronization.
    filename[strcmp_len - 1] = '\0'; // restore the filename
    if (status == FDB_RESULT_SUCCESS) {
        status = _compactor_search_n_destroy(filename);
    }

    return status;
}
