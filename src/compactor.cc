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
#ifdef SPIN_INITIALIZER
static spin_t cpt_lock = SPIN_INITIALIZER;
#else
static volatile unsigned int init_lock_status = 0;
static spin_t cpt_lock;
#endif

static thread_t compactor_tid;
static size_t sleep_duration = FDB_COMPACTOR_SLEEP_DURATION;

static mutex_t sync_mutex;
static thread_cond_t sync_cond;

typedef uint8_t compactor_status_t;
enum{
    CPT_IDLE = 0,
    CPT_WORKING = 1,
};
static compactor_status_t compactor_status;
static volatile uint8_t compactor_terminate_signal = 0;

static struct avl_tree openfiles;

// cursor of openfiles_elem that is currently being compacted.
// set to NULL if no file is being compacted.
static struct avl_node *target_cursor;

struct openfiles_elem {
    struct filemgr *file;
    fdb_config config;
    uint32_t register_count;
    bool compaction_flag; // set when the file is being compacted
    struct list *cmp_func_list; // pointer to fhandle's list
    struct avl_node avl;
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
struct timespec convert_reltime_to_abstime(unsigned int ms) {
    struct timespec ts;
    struct timeval tp;
    uint64_t wakeup;

    memset(&ts, 0, sizeof(ts));

    /*
     * Unfortunately pthread_cond_timedwait doesn't support relative sleeps
     * so we need to convert back to an absolute time.
     */
    gettimeofday(&tp, NULL);
    wakeup = ((uint64_t)(tp.tv_sec) * 1000) + (tp.tv_usec / 1000) + ms;
    /* Round up for sub ms */
    if ((tp.tv_usec % 1000) > 499) {
        ++wakeup;
    }

    ts.tv_sec = wakeup / 1000;
    wakeup %= 1000;
    ts.tv_nsec = wakeup * 1000000;
    return ts;
}
#endif

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
    return strncmp(aa->file->filename, bb->file->filename, args->strcmp_len);
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
INLINE int _compactor_is_threshold_satisfied(struct openfiles_elem *elem)
{
    uint64_t filesize;
    uint64_t active_data;
    int threshold;

    if (filemgr_is_rollback_on(elem->file)) {
        // do not perform compaction during rollback
        return 0;
    }

    threshold = elem->config.compaction_threshold;
    if (elem->config.compaction_mode == FDB_COMPACTION_AUTO &&
        threshold > 0 && !elem->compaction_flag)
        {
        filesize = filemgr_get_pos(elem->file);
        active_data = _compactor_estimate_space(elem);
        if (active_data == 0 || active_data >= filesize ||
            filesize < elem->config.compaction_minimum_filesize) {
            return 0;
        }

        return ((filesize / 100.0 * threshold) < (filesize - active_data));
    } else {
        return 0;
    }
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

    spin_lock(&cpt_lock);
    query.file = file;
    a = avl_search(&openfiles, &query.avl, _compactor_cmp);
    if (a) {
        // found
        elem = _get_entry(a, struct openfiles_elem, avl);
        if (elem->compaction_flag == flag) {
            // already switched by other thread .. return false
            spin_unlock(&cpt_lock);
            return false;
        }
        // switch
        elem->compaction_flag = flag;
        spin_unlock(&cpt_lock);
        return true;
    }
    // file doesn't exist .. already compacted or deregistered
    spin_unlock(&cpt_lock);
    return false;
}

void * compactor_thread(void *voidargs)
{
    char filename[MAX_FNAMELEN];
    char vfilename[MAX_FNAMELEN];
    char new_filename[MAX_FNAMELEN];
    fdb_file_handle *fhandle;
    fdb_config config;
    fdb_status fs;
    struct avl_node *a;
    struct openfiles_elem *elem, *target;

    // Sleep for 10 secs by default to allow applications to warm up their data.
    // TODO: Need to implement more flexible way of scheduling the compaction
    // daemon (e.g., public APIs to start / stop the compaction daemon).
    mutex_lock(&sync_mutex);
    thread_cond_timedwait(&sync_cond, &sync_mutex, sleep_duration * 1000);
    mutex_unlock(&sync_mutex);

    while (1) {
        target = NULL;

        spin_lock(&cpt_lock);
        a = avl_first(&openfiles);
        while(a) {
            elem = _get_entry(a, struct openfiles_elem, avl);

            if (_compactor_is_threshold_satisfied(elem)) {
                // perform compaction
                strcpy(filename, elem->file->filename);
                _compactor_get_vfilename(filename, vfilename);
                config = elem->config;
                compactor_status = CPT_WORKING;
                // set target_cursor to avoid deregistering of the 'elem'
                target_cursor = &elem->avl;
                // set compaction flag
                elem->compaction_flag = true;
                spin_unlock(&cpt_lock);

                fs = fdb_open_for_compactor(&fhandle, vfilename, &config,
                                            elem->cmp_func_list);
                if (fs == FDB_RESULT_SUCCESS) {
                    compactor_get_next_filename(filename, new_filename);
                    fdb_compact_file(fhandle, new_filename, false);

                    spin_lock(&cpt_lock);
                    a = avl_next(target_cursor);
                    // we have to set cursor to NULL before fdb_close
                    target_cursor = NULL;
                    spin_unlock(&cpt_lock);

                    fdb_close(fhandle);

                    spin_lock(&cpt_lock);
                    compactor_status = CPT_IDLE;
                } else {
                    // fail to open file
                    spin_lock(&cpt_lock);
                    compactor_status = CPT_IDLE;
                    a = avl_next(target_cursor);
                    target_cursor = NULL;
                    // clear compaction flag
                    elem->compaction_flag = false;
                }
            } else {
                a = avl_next(a);
            }
            if (compactor_terminate_signal) {
                spin_unlock(&cpt_lock);
                return NULL;
            }
        }
        spin_unlock(&cpt_lock);

        mutex_lock(&sync_mutex);
        if (compactor_terminate_signal) {
            mutex_unlock(&sync_mutex);
            break;
        }
        thread_cond_timedwait(&sync_cond, &sync_mutex, sleep_duration * 1000);
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
#ifndef SPIN_INITIALIZER
        // Note that only Windows passes through this routine
        if (InterlockedCompareExchange(&init_lock_status, 1, 0) == 0) {
            // atomically initialize spin lock only once
            spin_init(&cpt_lock);
            init_lock_status = 2;
        } else {
            // the others .. wait until initializing 'cpt_lock' is done
            while (init_lock_status != 2) {
                Sleep(1);
            }
        }
#endif

        spin_lock(&cpt_lock);
        if (!compactor_initialized) {
            // initialize
            compactor_args.strcmp_len = MAX_FNAMELEN;
            avl_init(&openfiles, &compactor_args);
            target_cursor = NULL;

            if (config) {
                if (config->sleep_duration > 0) {
                    sleep_duration = config->sleep_duration;
                }
            }

            compactor_status = CPT_IDLE;
            compactor_terminate_signal = 0;

            mutex_init(&sync_mutex);
            thread_cond_init(&sync_cond);

            // create worker thread
            thread_create(&compactor_tid, compactor_thread, NULL);

            compactor_initialized = 1;
        }
        spin_unlock(&cpt_lock);
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
    thread_cond_signal(&sync_cond);
    mutex_unlock(&sync_mutex);

    thread_join(compactor_tid, &ret);

    spin_lock(&cpt_lock);
    // free all elems in the tree
    a = avl_first(&openfiles);
    while (a) {
        elem = _get_entry(a, struct openfiles_elem, avl);
        a = avl_next(a);

        avl_remove(&openfiles, &elem->avl);
        free(elem);
    }

    sleep_duration = FDB_COMPACTOR_SLEEP_DURATION;
    compactor_initialized = 0;
    mutex_destroy(&sync_mutex);
    thread_cond_destroy(&sync_cond);
    spin_unlock(&cpt_lock);

#ifndef SPIN_INITIALIZER
    spin_destroy(&cpt_lock);
    init_lock_status = 0;
#else
    cpt_lock = SPIN_INITIALIZER;
#endif
}

static fdb_status _compactor_store_metafile(char *metafile,
                                            struct compactor_meta *metadata);

fdb_status compactor_register_file(struct filemgr *file,
                                   fdb_config *config,
                                   struct list *cmp_func_list)
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

    // first search the existing file
    spin_lock(&cpt_lock);
    query.file = file;
    a = avl_search(&openfiles, &query.avl, _compactor_cmp);
    if (a == NULL) {
        // doesn't exist
        // create elem and insert into tree
        char path[MAX_FNAMELEN];
        struct compactor_meta meta;

        elem = (struct openfiles_elem *)malloc(sizeof(struct openfiles_elem));
        elem->file = file;
        elem->config = *config;
        elem->register_count = 1;
        elem->compaction_flag = false;
        elem->cmp_func_list = cmp_func_list;
        avl_insert(&openfiles, &elem->avl, _compactor_cmp);

        // store in metafile
        _compactor_convert_dbfile_to_metafile(file->filename, path);
        _strcpy_fname(meta.filename, file->filename);
        fs = _compactor_store_metafile(path, &meta);
    } else {
        // already exists
        elem = _get_entry(a, struct openfiles_elem, avl);
        elem->register_count++;
    }
    spin_unlock(&cpt_lock);
    return fs;
}

void compactor_deregister_file(struct filemgr *file)
{
    struct avl_node *a = NULL;
    struct openfiles_elem query, *elem;

    spin_lock(&cpt_lock);
    query.file = file;
    a = avl_search(&openfiles, &query.avl, _compactor_cmp);
    if (a) {
        elem = _get_entry(a, struct openfiles_elem, avl);
        if ((--elem->register_count) == 0) {
            // if no handle refers this file
            if (target_cursor == &elem->avl) {
                // This file is waiting for compaction by compactor (but not opened
                // yet). Do not remove 'elem' for now. The 'elem' will be automatically
                // replaced after the compaction is done by calling
                // 'compactor_switch_file()'.
            } else {
                // remove from the tree
                avl_remove(&openfiles, &elem->avl);
                free(elem);
            }
        }
    }
    spin_unlock(&cpt_lock);
}

void compactor_change_threshold(struct filemgr *file, size_t new_threshold)
{
    struct avl_node *a = NULL;
    struct openfiles_elem query, *elem;

    spin_lock(&cpt_lock);
    query.file = file;
    a = avl_search(&openfiles, &query.avl, _compactor_cmp);
    if (a) {
        elem = _get_entry(a, struct openfiles_elem, avl);
        elem->config.compaction_threshold = new_threshold;
    }
    spin_unlock(&cpt_lock);
}

struct compactor_meta * _compactor_read_metafile(char *metafile,
                                                 struct compactor_meta *metadata)
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
        if (ret < sizeof(struct compactor_meta)) {
            ops->close(fd_meta);
            return NULL;
        }
        memcpy(&meta, buf, sizeof(struct compactor_meta));
        meta.version = _endian_decode(meta.version);
        meta.crc = _endian_decode(meta.crc);
        ops->close(fd_meta);

        // CRC check
        crc = chksum(buf, sizeof(struct compactor_meta) - sizeof(crc));
        if (crc != meta.crc) {
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
                                            struct compactor_meta *metadata)
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
        crc = chksum((void*)&meta, sizeof(struct compactor_meta) - sizeof(crc));
        meta.crc = _endian_encode(crc);

        ret = ops->pwrite(fd_meta, &meta, sizeof(struct compactor_meta), 0);
        ops->fsync(fd_meta);
        ops->close(fd_meta);
        if (ret < sizeof(struct compactor_meta)) {
            return FDB_RESULT_WRITE_FAIL;
        }
    } else {
        return FDB_RESULT_OPEN_FAIL;
    }

    return FDB_RESULT_SUCCESS;
}

void compactor_switch_file(struct filemgr *old_file, struct filemgr *new_file)
{
    struct avl_node *a = NULL;
    struct openfiles_elem query, *elem;
    struct compactor_meta meta;

    spin_lock(&cpt_lock);
    query.file = old_file;
    a = avl_search(&openfiles, &query.avl, _compactor_cmp);
    if (a) {
        char metafile[MAX_FNAMELEN];

        elem = _get_entry(a, struct openfiles_elem, avl);
        avl_remove(&openfiles, a);
        elem->file = new_file;
        elem->register_count = 1;
        // clear compaction flag
        elem->compaction_flag = false;
        avl_insert(&openfiles, &elem->avl, _compactor_cmp);

        if (elem->config.compaction_mode == FDB_COMPACTION_AUTO) {
            _compactor_convert_dbfile_to_metafile(new_file->filename, metafile);
            _strcpy_fname(meta.filename, new_file->filename);
            _compactor_store_metafile(metafile, &meta);
        }
        spin_unlock(&cpt_lock);

    } else {
        spin_unlock(&cpt_lock);
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
                                         fdb_compaction_mode_t comp_mode)
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
    meta_ptr = _compactor_read_metafile(path, &meta);

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
                if (remove(dir_entry->d_name)) {
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
            if (remove(filedata.cFileName)) {
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
    struct filemgr query_file;
    struct filemgr *file = &query_file;
    size_t strcmp_len;
    fdb_status status = FDB_RESULT_SUCCESS;
    compactor_config c_config;

    strcmp_len = strlen(filename);
    filename[strcmp_len] = '.'; // add a . suffix in place
    strcmp_len++;
    filename[strcmp_len] = '\0';
    file->filename = filename;

    c_config.sleep_duration = config->compactor_sleep_duration;
    compactor_init(&c_config);

    spin_lock(&cpt_lock); // TODO: use mutex as we are doing I/O
    query.file = file;
    compactor_args.strcmp_len = strcmp_len; // Do prefix match for all vers
    a = avl_search(&openfiles, &query.avl, _compactor_cmp);
    if (a) {
        elem = _get_entry(a, struct openfiles_elem, avl);
        // if no handle refers this file
        if (target_cursor == &elem->avl) {
            // This file is waiting for compaction by compactor
            // Return a temporary failure, user must retry after sometime
            status = FDB_RESULT_IN_USE_BY_COMPACTOR;
        } else { // File handle not closed, fail operation
            status = FDB_RESULT_FILE_IS_BUSY;
        }
    }
    compactor_args.strcmp_len = MAX_FNAMELEN; // restore for normal compare
    filename[strcmp_len - 1] = '\0'; // restore the filename
    if (status == FDB_RESULT_SUCCESS) {
        status = _compactor_search_n_destroy(file->filename);
    }
    spin_unlock(&cpt_lock);

    return status;
}
