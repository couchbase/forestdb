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
#include <sys/stat.h>
#include <stdarg.h>
#if !defined(WIN32) && !defined(_WIN32)
#include <sys/time.h>
#include <dirent.h>
#include <unistd.h>
#endif

#include "filemgr.h"
#include "filemgr_ops.h"
#include "hash_functions.h"
#include "blockcache.h"
#include "wal.h"
#include "list.h"
#include "fdb_internal.h"
#include "time_utils.h"

#include "memleak.h"

#ifdef __DEBUG
#ifndef __DEBUG_FILEMGR
    #undef DBG
    #undef DBGCMD
    #undef DBGSW
    #define DBG(...)
    #define DBGCMD(...)
    #define DBGSW(n, ...)
#endif
#endif

// NBUCKET must be power of 2
#define NBUCKET (1024)
#define FILEMGR_MAGIC (UINT64_C(0xdeadcafebeefbeef))

// global static variables
#ifdef SPIN_INITIALIZER
static spin_t initial_lock = SPIN_INITIALIZER;
#else
static volatile unsigned int initial_lock_status = 0;
static spin_t initial_lock;
#endif


static volatile uint8_t filemgr_initialized = 0;
static struct filemgr_config global_config;
static struct hash hash;
static spin_t filemgr_openlock;

struct temp_buf_item{
    void *addr;
    struct list_elem le;
};
static struct list temp_buf;
static spin_t temp_buf_lock;

struct keystr_file {
    char *filename;
    uint64_t size;
    int fd;
    void *addr;
    void *aux; // reserved for filemap handle in MSVC
    struct list_elem le;
};

static void _filemgr_free_func(struct hash_elem *h);

static void spin_init_wrap(void *lock) {
    spin_init((spin_t*)lock);
}

static void spin_destroy_wrap(void *lock) {
    spin_destroy((spin_t*)lock);
}

static void spin_lock_wrap(void *lock) {
    spin_lock((spin_t*)lock);
}

static void spin_unlock_wrap(void *lock) {
    spin_unlock((spin_t*)lock);
}

static void mutex_init_wrap(void *lock) {
    mutex_init((mutex_t*)lock);
}

static void mutex_destroy_wrap(void *lock) {
    mutex_destroy((mutex_t*)lock);
}

static void mutex_lock_wrap(void *lock) {
    mutex_lock((mutex_t*)lock);
}

static void mutex_unlock_wrap(void *lock) {
    mutex_unlock((mutex_t*)lock);
}

static int _block_is_overlapped(void *pbid1, void *pis_writer1,
                                void *pbid2, void *pis_writer2,
                                void *aux)
{
    (void)aux;
    bid_t bid1, is_writer1, bid2, is_writer2;
    bid1 = *(bid_t*)pbid1;
    is_writer1 = *(bid_t*)pis_writer1;
    bid2 = *(bid_t*)pbid2;
    is_writer2 = *(bid_t*)pis_writer2;

    if (bid1 != bid2) {
        // not overlapped
        return 0;
    } else {
        // overlapped
        if (!is_writer1 && !is_writer2) {
            // both are readers
            return 0;
        } else {
            return 1;
        }
    }
}

fdb_status fdb_log(err_log_callback *log_callback,
                   fdb_status status,
                   const char *format, ...)
{
    if (log_callback && log_callback->callback) {
        char msg[1024];
        va_list args;
        va_start(args, format);
        vsprintf(msg, format, args);
        va_end(args);
        log_callback->callback(status, msg, log_callback->ctx_data);
    }
    return status;
}

static void _log_errno_str(struct filemgr_ops *ops,
                           err_log_callback *log_callback,
                           fdb_status io_error,
                           const char *what,
                           const char *filename)
{
    if (io_error < 0) {
        char errno_msg[512];
        ops->get_errno_str(errno_msg, 512);
        fdb_log(log_callback, io_error,
                "Error in %s on a database file '%s', %s", what, filename, errno_msg);
    }
}

static uint32_t _file_hash(struct hash *hash, struct hash_elem *e)
{
    struct filemgr *file = _get_entry(e, struct filemgr, e);
    int len = strlen(file->filename);
    return chksum(file->filename, len) & ((unsigned)(NBUCKET-1));
}

static int _file_cmp(struct hash_elem *a, struct hash_elem *b)
{
    struct filemgr *aa, *bb;
    aa = _get_entry(a, struct filemgr, e);
    bb = _get_entry(b, struct filemgr, e);
    return strcmp(aa->filename, bb->filename);
}

void filemgr_init(struct filemgr_config *config)
{
    // global initialization
    // initialized only once at first time
    if (!filemgr_initialized) {
#ifndef SPIN_INITIALIZER
        // Note that only Windows passes through this routine
        if (InterlockedCompareExchange(&initial_lock_status, 1, 0) == 0) {
            // atomically initialize spin lock only once
            spin_init(&initial_lock);
            initial_lock_status = 2;
        } else {
            // the others .. wait until initializing 'initial_lock' is done
            while (initial_lock_status != 2) {
                Sleep(1);
            }
        }
#endif

        spin_lock(&initial_lock);
        if (!filemgr_initialized) {
            global_config = *config;

            if (global_config.ncacheblock > 0)
                bcache_init(global_config.ncacheblock, global_config.blocksize);

            hash_init(&hash, NBUCKET, _file_hash, _file_cmp);

            // initialize temp buffer
            list_init(&temp_buf);
            spin_init(&temp_buf_lock);

            // initialize global lock
            spin_init(&filemgr_openlock);

            // set the initialize flag
            filemgr_initialized = 1;
        }
        spin_unlock(&initial_lock);
    }
}

static void * _filemgr_get_temp_buf()
{
    struct list_elem *e;
    struct temp_buf_item *item;

    spin_lock(&temp_buf_lock);
    e = list_pop_front(&temp_buf);
    if (e) {
        item = _get_entry(e, struct temp_buf_item, le);
    }else{
        void *addr;

        malloc_align(addr, FDB_SECTOR_SIZE, global_config.blocksize + sizeof(struct temp_buf_item));

        item = (struct temp_buf_item *)((uint8_t *) addr + global_config.blocksize);
        item->addr = addr;
    }
    spin_unlock(&temp_buf_lock);

    return item->addr;
}

static void _filemgr_release_temp_buf(void *buf)
{
    struct temp_buf_item *item;

    spin_lock(&temp_buf_lock);
    item = (struct temp_buf_item*)((uint8_t *)buf + global_config.blocksize);
    list_push_front(&temp_buf, &item->le);
    spin_unlock(&temp_buf_lock);
}

static void _filemgr_shutdown_temp_buf()
{
    struct list_elem *e;
    struct temp_buf_item *item;
    size_t count=0;

    spin_lock(&temp_buf_lock);
    e = list_begin(&temp_buf);
    while(e){
        item = _get_entry(e, struct temp_buf_item, le);
        e = list_remove(&temp_buf, e);
        free_align(item->addr);
        count++;
    }
    spin_unlock(&temp_buf_lock);
}

static fdb_status _filemgr_read_header(struct filemgr *file)
{
    uint8_t marker[BLK_MARKER_SIZE];
    filemgr_magic_t magic;
    filemgr_header_len_t len;
    uint8_t *buf;
    uint32_t crc, crc_file;
    fdb_status status = FDB_RESULT_SUCCESS;

    // get temp buffer
    buf = (uint8_t *) _filemgr_get_temp_buf();

    if (file->pos.val > 0) {
        // Crash Recovery Test 1: unaligned last block write
        uint64_t remain = file->pos.val % file->blocksize;
        if (remain) {
            atomic_sub_uint64_t(&file->pos, remain);
            atomic_store_uint64_t(&file->last_commit, file->pos.val);
            DBG("Crash Detected: %llu non-block aligned bytes discarded\n",
                remain);
        }

        do {
            ssize_t rv = file->ops->pread(file->fd, buf, file->blocksize,
                             file->pos.val - file->blocksize);
            if (rv != file->blocksize) {
                status = FDB_RESULT_READ_FAIL;
                DBG("Unable to read file %s blocksize %llu\n",
                    file->filename, file->blocksize);
                break;
            }
            memcpy(marker, buf + file->blocksize - BLK_MARKER_SIZE,
                   BLK_MARKER_SIZE);

            if (marker[0] == BLK_MARKER_DBHEADER) {
                // possible need for byte conversions here
                memcpy(&magic,
                       buf + file->blocksize - BLK_MARKER_SIZE - sizeof(magic),
                       sizeof(magic));
                magic = _endian_decode(magic);

                if (magic == FILEMGR_MAGIC) {
                    memcpy(&len,
                           buf + file->blocksize - BLK_MARKER_SIZE -
                           sizeof(magic) - sizeof(len),
                           sizeof(len));
                    len = _endian_decode(len);

                    crc = chksum(buf, len - sizeof(crc));
                    memcpy(&crc_file, buf + len - sizeof(crc), sizeof(crc));
                    crc_file = _endian_decode(crc_file);
                    if (crc == crc_file) {
                        file->header.data = (void *)malloc(len);

                        memcpy(file->header.data, buf, len);
                        memcpy(&file->header.revnum, buf + len,
                               sizeof(filemgr_header_revnum_t));
                        memcpy((void *) &file->header.seqnum,
                                buf + len + sizeof(filemgr_header_revnum_t),
                                sizeof(fdb_seqnum_t));
                        file->header.revnum =
                            _endian_decode(file->header.revnum);
                        file->header.seqnum =
                            _endian_decode(file->header.seqnum);
                        file->header.size = len;
                        atomic_store_uint64_t(&file->header.bid,
                                              (file->pos.val / file->blocksize) - 1);
                        atomic_store_uint64_t(&file->header.dirty_idtree_root,
                                              BLK_NOT_FOUND);
                        atomic_store_uint64_t(&file->header.dirty_seqtree_root,
                                              BLK_NOT_FOUND);
                        memset(&file->header.stat, 0x0, sizeof(file->header.stat));

                        // release temp buffer
                        _filemgr_release_temp_buf(buf);

                        return FDB_RESULT_SUCCESS;
                    } else {
                        status = FDB_RESULT_CHECKSUM_ERROR;
                        DBG("Crash Detected: CRC on disk %u != %u\n",
                                crc_file, crc);
                    }
                } else {
                    status = FDB_RESULT_FILE_CORRUPTION;
                    DBG("Crash Detected: Wrong Magic %llu != %llu\n", magic,
                            FILEMGR_MAGIC);
                }
            } else {
                status = FDB_RESULT_FILE_CORRUPTION;
                DBG("Crash Detected: Last Block not DBHEADER %0.01x\n",
                        marker[0]);
            }

            atomic_sub_uint64_t(&file->pos, file->blocksize);
            atomic_store_uint64_t(&file->last_commit, file->pos.val);
        } while (file->pos.val);
    }

    // release temp buffer
    _filemgr_release_temp_buf(buf);

    file->header.size = 0;
    file->header.revnum = 0;
    file->header.seqnum = 0;
    file->header.data = NULL;
    atomic_store_uint64_t(&file->header.bid, 0);
    atomic_store_uint64_t(&file->header.dirty_idtree_root, BLK_NOT_FOUND);
    atomic_store_uint64_t(&file->header.dirty_seqtree_root, BLK_NOT_FOUND);
    memset(&file->header.stat, 0x0, sizeof(file->header.stat));
    return status;
}

size_t filemgr_get_ref_count(struct filemgr *file)
{
    size_t ret = 0;
    spin_lock(&file->lock);
    ret = file->ref_count;
    spin_unlock(&file->lock);
    return ret;
}

struct filemgr_prefetch_args {
    struct filemgr *file;
    uint64_t duration;
    void *aux;
};

static void *_filemgr_prefetch_thread(void *voidargs)
{
    struct filemgr_prefetch_args *args = (struct filemgr_prefetch_args*)voidargs;
    uint8_t *buf = alca(uint8_t, args->file->blocksize);
    uint64_t cur_pos = 0, i;
    uint64_t bcache_free_space;
    bid_t bid;
    bool terminate = false;
    struct timeval begin, cur, gap;

    spin_lock(&args->file->lock);
    cur_pos = args->file->last_commit.val;
    spin_unlock(&args->file->lock);
    if (cur_pos < FILEMGR_PREFETCH_UNIT) {
        terminate = true;
    } else {
        cur_pos -= FILEMGR_PREFETCH_UNIT;
    }
    // read backwards from the end of the file, in the unit of FILEMGR_PREFETCH_UNIT
    gettimeofday(&begin, NULL);
    while (!terminate) {
        for (i = cur_pos;
             i < cur_pos + FILEMGR_PREFETCH_UNIT;
             i += args->file->blocksize) {

            gettimeofday(&cur, NULL);
            gap = _utime_gap(begin, cur);
            bcache_free_space = bcache_get_num_free_blocks();
            bcache_free_space *= args->file->blocksize;

            if (args->file->prefetch_status == FILEMGR_PREFETCH_ABORT ||
                gap.tv_sec >= args->duration ||
                bcache_free_space < FILEMGR_PREFETCH_UNIT) {
                // terminate thread when
                // 1. got abort signal
                // 2. time out
                // 3. not enough free space in block cache
                terminate = true;
                break;
            } else {
                bid = i / args->file->blocksize;
                if (filemgr_read(args->file, bid, buf, NULL)
                        != FDB_RESULT_SUCCESS) {
                    // 4. read failure
                    terminate = true;
                    break;
                }
            }
        }

        if (cur_pos >= FILEMGR_PREFETCH_UNIT) {
            cur_pos -= FILEMGR_PREFETCH_UNIT;
        } else {
            // remaining space is less than FILEMGR_PREFETCH_UNIT
            terminate = true;
        }
    }

    args->file->prefetch_status = FILEMGR_PREFETCH_IDLE;
    free(args);
    return NULL;
}

// prefetch the given DB file
void filemgr_prefetch(struct filemgr *file,
                      struct filemgr_config *config)
{
    uint64_t bcache_free_space;

    bcache_free_space = bcache_get_num_free_blocks();
    bcache_free_space *= file->blocksize;

    // block cache should have free space larger than FILEMGR_PREFETCH_UNIT
    spin_lock(&file->lock);
    if (file->last_commit.val > 0 &&
        bcache_free_space >= FILEMGR_PREFETCH_UNIT) {
        // invoke prefetch thread
        struct filemgr_prefetch_args *args;
        args = (struct filemgr_prefetch_args *)
               calloc(1, sizeof(struct filemgr_prefetch_args));
        args->file = file;
        args->duration = config->prefetch_duration;

        file->prefetch_status = FILEMGR_PREFETCH_RUNNING;
        thread_create(&file->prefetch_tid, _filemgr_prefetch_thread, args);
    }
    spin_unlock(&file->lock);
}

fdb_status filemgr_does_file_exist(char *filename) {
    struct filemgr_ops *ops = get_filemgr_ops();
    int fd = ops->open(filename, O_RDONLY, 0444);
    if (fd < 0) {
        return (fdb_status) fd;
    }
    ops->close(fd);
    return FDB_RESULT_SUCCESS;
}

filemgr_open_result filemgr_open(char *filename, struct filemgr_ops *ops,
                                 struct filemgr_config *config,
                                 err_log_callback *log_callback)
{
    struct filemgr *file = NULL;
    struct filemgr query;
    struct hash_elem *e = NULL;
    bool create = config->options & FILEMGR_CREATE;
    int file_flag = 0x0;
    int fd = -1;
    fdb_status status;
    filemgr_open_result result = {NULL, FDB_RESULT_OPEN_FAIL};

    filemgr_init(config);

    // check whether file is already opened or not
    query.filename = filename;
    spin_lock(&filemgr_openlock);
    e = hash_find(&hash, &query.e);

    if (e) {
        // already opened (return existing structure)
        file = _get_entry(e, struct filemgr, e);

        spin_lock(&file->lock);
        file->ref_count++;

        if (file->status.val == FILE_CLOSED) { // if file was closed before
            file_flag = O_RDWR;
            if (create) {
                file_flag |= O_CREAT;
            }
            *file->config = *config;
            file->config->blocksize = global_config.blocksize;
            file->config->ncacheblock = global_config.ncacheblock;
            file_flag |= config->flag;
            file->fd = file->ops->open(file->filename, file_flag, 0666);
            if (file->fd < 0) {
                if (file->fd == FDB_RESULT_NO_SUCH_FILE) {
                    // A database file was manually deleted by the user.
                    // Clean up global hash table, WAL index, and buffer cache.
                    // Then, retry it with a create option below IFF it is not
                    // a read-only open attempt
                    struct hash_elem *ret;
                    spin_unlock(&file->lock);
                    ret = hash_remove(&hash, &file->e);
                    fdb_assert(ret, 0, 0);
                    _filemgr_free_func(&file->e);
                    if (!create) {
                        _log_errno_str(ops, log_callback,
                                FDB_RESULT_NO_SUCH_FILE, "OPEN", filename);
                        spin_unlock(&filemgr_openlock);
                        result.rv = FDB_RESULT_NO_SUCH_FILE;
                        return result;
                    }
                } else {
                    _log_errno_str(file->ops, log_callback,
                                  (fdb_status)file->fd, "OPEN", filename);
                    file->ref_count--;
                    spin_unlock(&file->lock);
                    spin_unlock(&filemgr_openlock);
                    result.rv = file->fd;
                    return result;
                }
            } else { // Reopening the closed file is succeed.
                atomic_store_uint8_t(&file->status, FILE_NORMAL);
                if (config->options & FILEMGR_SYNC) {
                    file->fflags |= FILEMGR_SYNC;
                } else {
                    file->fflags &= ~FILEMGR_SYNC;
                }
                spin_unlock(&file->lock);
                spin_unlock(&filemgr_openlock);
                result.file = file;
                result.rv = FDB_RESULT_SUCCESS;
                return result;
            }
        } else { // file is already opened.

            if (config->options & FILEMGR_SYNC) {
                file->fflags |= FILEMGR_SYNC;
            } else {
                file->fflags &= ~FILEMGR_SYNC;
            }

            spin_unlock(&file->lock);
            spin_unlock(&filemgr_openlock);
            result.file = file;
            result.rv = FDB_RESULT_SUCCESS;
            return result;
        }
    }

    file_flag = O_RDWR;
    if (create) {
        file_flag |= O_CREAT;
    }
    file_flag |= config->flag;
    fd = ops->open(filename, file_flag, 0666);
    if (fd < 0) {
        _log_errno_str(ops, log_callback, (fdb_status)fd, "OPEN", filename);
        spin_unlock(&filemgr_openlock);
        result.rv = fd;
        return result;
    }
    file = (struct filemgr*)calloc(1, sizeof(struct filemgr));
    file->filename_len = strlen(filename);
    file->filename = (char*)malloc(file->filename_len + 1);
    strcpy(file->filename, filename);

    file->ref_count = 1;

    file->wal = (struct wal *)calloc(1, sizeof(struct wal));
    file->wal->flag = 0;

    file->ops = ops;
    file->blocksize = global_config.blocksize;
    atomic_init_uint8_t(&file->status, FILE_NORMAL);
    file->config = (struct filemgr_config*)malloc(sizeof(struct filemgr_config));
    *file->config = *config;
    file->config->blocksize = global_config.blocksize;
    file->config->ncacheblock = global_config.ncacheblock;
    file->new_file = NULL;
    file->old_filename = NULL;
    file->fd = fd;

    cs_off_t offset = file->ops->goto_eof(file->fd);
    if (offset == FDB_RESULT_SEEK_FAIL) {
        _log_errno_str(file->ops, log_callback, FDB_RESULT_SEEK_FAIL, "SEEK_END", filename);
        free(file->wal);
        free(file->filename);
        free(file->config);
        free(file);
        spin_unlock(&filemgr_openlock);
        result.rv = FDB_RESULT_SEEK_FAIL;
        return result;
    }
    atomic_init_uint64_t(&file->last_commit, offset);
    atomic_init_uint64_t(&file->pos, offset);

    file->bcache = NULL;
    file->in_place_compaction = false;
    file->kv_header = NULL;
    file->prefetch_status = FILEMGR_PREFETCH_IDLE;

    atomic_init_uint64_t(&file->header.bid, 0);
    atomic_init_uint64_t(&file->header.dirty_idtree_root, 0);
    atomic_init_uint64_t(&file->header.dirty_seqtree_root, 0);
    status = _filemgr_read_header(file);
    if (status != FDB_RESULT_SUCCESS) {
        _log_errno_str(file->ops, log_callback, status, "READ", filename);
        free(file->wal);
        free(file->filename);
        free(file->config);
        free(file);
        spin_unlock(&filemgr_openlock);
        result.rv = status;
        return result;
    }

    spin_init(&file->lock);

#ifdef __FILEMGR_DATA_PARTIAL_LOCK
    struct plock_ops pops;
    struct plock_config pconfig;

    pops.init_user = mutex_init_wrap;
    pops.lock_user = mutex_lock_wrap;
    pops.unlock_user = mutex_unlock_wrap;
    pops.destroy_user = mutex_destroy_wrap;
    pops.init_internal = spin_init_wrap;
    pops.lock_internal = spin_lock_wrap;
    pops.unlock_internal = spin_unlock_wrap;
    pops.destroy_internal = spin_destroy_wrap;
    pops.is_overlapped = _block_is_overlapped;

    memset(&pconfig, 0x0, sizeof(pconfig));
    pconfig.ops = &pops;
    pconfig.sizeof_lock_internal = sizeof(spin_t);
    pconfig.sizeof_lock_user = sizeof(mutex_t);
    pconfig.sizeof_range = sizeof(bid_t);
    pconfig.aux = NULL;
    plock_init(&file->plock, &pconfig);
#elif defined(__FILEMGR_DATA_MUTEX_LOCK)
    int i;
    for (i=0;i<DLOCK_MAX;++i) {
        mutex_init(&file->data_mutex[i]);
    }
#else
    int i;
    for (i=0;i<DLOCK_MAX;++i) {
        spin_init(&file->data_spinlock[i]);
    }
#endif //__FILEMGR_DATA_PARTIAL_LOCK

#ifdef __FILEMGR_MUTEX_LOCK
    mutex_init(&file->mutex);
#else
    spin_init(&file->mutex);
#endif

    list_init(&file->keystr_files);
    file->n_keystr_files = 0;
    // initialize WAL
    if (!wal_is_initialized(file)) {
        wal_init(file, FDB_WAL_NBUCKET);
    }

    // init global transaction for the file
    file->global_txn.wrapper = (struct wal_txn_wrapper*)
                               malloc(sizeof(struct wal_txn_wrapper));
    file->global_txn.wrapper->txn = &file->global_txn;
    file->global_txn.handle = NULL;
    if (file->pos.val) {
        file->global_txn.prev_hdr_bid = (file->pos.val / file->blocksize)-1;
    } else {
        file->global_txn.prev_hdr_bid = BLK_NOT_FOUND;
    }
    file->global_txn.items = (struct list *)malloc(sizeof(struct list));
    list_init(file->global_txn.items);
    file->global_txn.isolation = FDB_ISOLATION_READ_COMMITTED;
    wal_add_transaction(file, &file->global_txn);

    hash_insert(&hash, &file->e);
    if (config->prefetch_duration > 0) {
        filemgr_prefetch(file, config);
    }
    spin_unlock(&filemgr_openlock);

    if (config->options & FILEMGR_SYNC) {
        file->fflags |= FILEMGR_SYNC;
    } else {
        file->fflags &= ~FILEMGR_SYNC;
    }

    result.file = file;
    result.rv = FDB_RESULT_SUCCESS;
    return result;
}

uint64_t filemgr_update_header(struct filemgr *file, void *buf, size_t len)
{
    uint64_t ret;

    spin_lock(&file->lock);

    if (file->header.data == NULL) {
        file->header.data = (void *)malloc(len);
    }else if (file->header.size < len){
        file->header.data = (void *)realloc(file->header.data, len);
    }
    memcpy(file->header.data, buf, len);
    file->header.size = len;
    ++(file->header.revnum);
    ret = file->header.revnum;

    spin_unlock(&file->lock);

    return ret;
}

filemgr_header_revnum_t filemgr_get_header_revnum(struct filemgr *file)
{
    filemgr_header_revnum_t ret;
    spin_lock(&file->lock);
    ret = file->header.revnum;
    spin_unlock(&file->lock);
    return ret;
}

// 'filemgr_get_seqnum' & 'filemgr_set_seqnum' have to be protected by
// 'filemgr_mutex_lock' & 'filemgr_mutex_unlock'.
fdb_seqnum_t filemgr_get_seqnum(struct filemgr *file)
{
    return file->header.seqnum;
}

void filemgr_set_seqnum(struct filemgr *file, fdb_seqnum_t seqnum)
{
    file->header.seqnum = seqnum;
}

// LCOV_EXCL_START
char* filemgr_get_filename_ptr(struct filemgr *file, char **filename, uint16_t *len)
{
    spin_lock(&file->lock);
    *filename = file->filename;
    *len = file->filename_len;
    spin_unlock(&file->lock);
    return *filename;
}
// LCOV_EXCL_STOP

void* filemgr_get_header(struct filemgr *file, void *buf, size_t *len)
{
    spin_lock(&file->lock);

    if (file->header.size > 0) {
        if (buf == NULL) {
            buf = (void*)malloc(file->header.size);
        }
        memcpy(buf, file->header.data, file->header.size);
    }
    *len = file->header.size;

    spin_unlock(&file->lock);

    return buf;
}

fdb_status filemgr_fetch_header(struct filemgr *file, uint64_t bid,
                                void *buf, size_t *len,
                                err_log_callback *log_callback)
{
    uint8_t *_buf;
    uint8_t marker[BLK_MARKER_SIZE];
    filemgr_header_len_t hdr_len;
    filemgr_magic_t magic;
    fdb_status status = FDB_RESULT_SUCCESS;

    if (!bid || bid == BLK_NOT_FOUND) {
        *len = 0; // No other header available
        return FDB_RESULT_SUCCESS;
    }
    _buf = (uint8_t *)_filemgr_get_temp_buf();

    status = filemgr_read(file, (bid_t)bid, _buf, log_callback);

    if (status != FDB_RESULT_SUCCESS) {
        _filemgr_release_temp_buf(_buf);
        return status;
    }
    memcpy(marker, _buf + file->blocksize - BLK_MARKER_SIZE,
            BLK_MARKER_SIZE);

    if (marker[0] != BLK_MARKER_DBHEADER) {
        _filemgr_release_temp_buf(_buf);
        return FDB_RESULT_READ_FAIL;
    }
    memcpy(&magic,
            _buf + file->blocksize - BLK_MARKER_SIZE - sizeof(magic),
            sizeof(magic));
    magic = _endian_decode(magic);
    if (magic != FILEMGR_MAGIC) {
        _filemgr_release_temp_buf(_buf);
        return FDB_RESULT_READ_FAIL;
    }
    memcpy(&hdr_len,
            _buf + file->blocksize - BLK_MARKER_SIZE - sizeof(magic) -
            sizeof(hdr_len), sizeof(hdr_len));
    hdr_len = _endian_decode(hdr_len);

    memcpy(buf, _buf, hdr_len);
    *len = hdr_len;

    _filemgr_release_temp_buf(_buf);

    return status;
}

uint64_t filemgr_fetch_prev_header(struct filemgr *file, uint64_t bid,
                                   void *buf, size_t *len, fdb_seqnum_t *seqnum,
                                   err_log_callback *log_callback)
{
    uint8_t *_buf;
    uint8_t marker[BLK_MARKER_SIZE];
    fdb_seqnum_t _seqnum;
    filemgr_header_revnum_t _revnum;
    filemgr_header_len_t hdr_len;
    filemgr_magic_t magic;
    bid_t _prev_bid, prev_bid;
    int found = 0;

    if (!bid || bid == BLK_NOT_FOUND) {
        *len = 0; // No other header available
        return bid;
    }
    _buf = (uint8_t *)_filemgr_get_temp_buf();

    // Reverse scan the file for a previous DB header
    do {
        // Get prev_bid from the current header.
        // Since the current header is already cached during the previous
        // operation, no disk I/O will be triggered.
        if (filemgr_read(file, (bid_t)bid, _buf, log_callback)
                != FDB_RESULT_SUCCESS) {
            break;
        }

        memcpy(marker, _buf + file->blocksize - BLK_MARKER_SIZE,
               BLK_MARKER_SIZE);
        memcpy(&magic,
               _buf + file->blocksize - BLK_MARKER_SIZE - sizeof(magic),
               sizeof(magic));
        magic = _endian_decode(magic);

        if (marker[0] != BLK_MARKER_DBHEADER ||
            magic != FILEMGR_MAGIC) {
            // not a header block
            // this happens when this function is invoked between
            // fdb_set() call and fdb_commit() call, so the last block
            // in the file is not a header block
            bid_t latest_hdr = filemgr_get_header_bid(file);
            if (latest_hdr != BLK_NOT_FOUND && bid > latest_hdr) {
                // get the latest header BID
                bid = latest_hdr;
            } else {
                break;
            }
        } else {
            memcpy(&_prev_bid,
                   _buf + file->blocksize - BLK_MARKER_SIZE - sizeof(magic) -
                       sizeof(hdr_len) - sizeof(_prev_bid),
                   sizeof(_prev_bid));
            prev_bid = _endian_decode(_prev_bid);
            if (bid <= prev_bid) {
                // no more prev header, or broken linked list
                break;
            }
            bid = prev_bid;
        }

        // Read the prev header
        if (filemgr_read(file, (bid_t)bid, _buf, log_callback)
                != FDB_RESULT_SUCCESS) {
            break;
        }

        memcpy(marker, _buf + file->blocksize - BLK_MARKER_SIZE,
               BLK_MARKER_SIZE);
        if (marker[0] != BLK_MARKER_DBHEADER) {
            // broken linked list
            break;
        }

        memcpy(&magic,
               _buf + file->blocksize - BLK_MARKER_SIZE - sizeof(magic),
               sizeof(magic));
        magic = _endian_decode(magic);
        if (magic != FILEMGR_MAGIC) {
            // broken linked list
            break;
        }

        memcpy(&hdr_len,
               _buf + file->blocksize - BLK_MARKER_SIZE - sizeof(magic) -
               sizeof(hdr_len), sizeof(hdr_len));
        hdr_len = _endian_decode(hdr_len);

        if (buf) {
            memcpy(buf, _buf, hdr_len);
        }
        memcpy(&_revnum, _buf + hdr_len,
               sizeof(filemgr_header_revnum_t));
        memcpy(&_seqnum,
               _buf + hdr_len + sizeof(filemgr_header_revnum_t),
               sizeof(fdb_seqnum_t));
        *seqnum = _endian_decode(_seqnum);
        *len = hdr_len;
        found = 1;
        break;
    } while (false); // no repetition

    if (!found) { // no other header found till end of file
        *len = 0;
    }

    _filemgr_release_temp_buf(_buf);

    return bid;
}

fdb_status filemgr_close(struct filemgr *file, bool cleanup_cache_onclose,
                         const char *orig_file_name,
                         err_log_callback *log_callback)
{
    int rv = FDB_RESULT_SUCCESS;

    spin_lock(&filemgr_openlock); // Grab the filemgr lock to avoid the race with
                                  // filemgr_open() because file->lock won't
                                  // prevent the race condition.

    // remove filemgr structure if no thread refers to the file
    spin_lock(&file->lock);
    if (--(file->ref_count) == 0) {
        spin_unlock(&file->lock);
        if (global_config.ncacheblock > 0) {
            // discard all dirty blocks belonged to this file
            bcache_remove_dirty_blocks(file);
        }

        if (wal_is_initialized(file)) {
            wal_close(file);
        }

        spin_lock(&file->lock);
        rv = file->ops->close(file->fd);
        if (file->status.val == FILE_REMOVED_PENDING) {
            _log_errno_str(file->ops, log_callback, (fdb_status)rv, "CLOSE", file->filename);
            // remove file
            remove(file->filename);
            // we can release lock becuase no one will open this file
            spin_unlock(&file->lock);
            struct hash_elem *ret = hash_remove(&hash, &file->e);
            fdb_assert(ret, 0, 0);
            spin_unlock(&filemgr_openlock);
            _filemgr_free_func(&file->e);
            return (fdb_status) rv;
        } else {
            if (cleanup_cache_onclose) {
                _log_errno_str(file->ops, log_callback, (fdb_status)rv, "CLOSE", file->filename);
                if (file->in_place_compaction && orig_file_name) {
                    struct hash_elem *elem = NULL;
                    struct filemgr query;
                    query.filename = (char *)orig_file_name;
                    elem = hash_find(&hash, &query.e);
                    if (!elem && rename(file->filename, orig_file_name) < 0) {
                        // Note that the renaming failure is not a critical
                        // issue because the last compacted file will be automatically
                        // identified and opened in the next fdb_open call.
                        _log_errno_str(file->ops, log_callback, FDB_RESULT_FILE_RENAME_FAIL,
                                       "CLOSE", file->filename);
                    }
                }
                spin_unlock(&file->lock);
                // Clean up global hash table, WAL index, and buffer cache.
                struct hash_elem *ret = hash_remove(&hash, &file->e);
                fdb_assert(ret, file, 0);
                spin_unlock(&filemgr_openlock);
                _filemgr_free_func(&file->e);
                return (fdb_status) rv;
            } else {
                atomic_store_uint8_t(&file->status, FILE_CLOSED);
            }
        }
    }

    _log_errno_str(file->ops, log_callback, (fdb_status)rv, "CLOSE", file->filename);

    spin_unlock(&file->lock);
    spin_unlock(&filemgr_openlock);
    return (fdb_status) rv;
}

static void _filemgr_free_func(struct hash_elem *h)
{
    struct filemgr *file = _get_entry(h, struct filemgr, e);

    spin_lock(&file->lock);
    if (file->prefetch_status == FILEMGR_PREFETCH_RUNNING) {
        // prefetch thread is running
        void *ret;
        file->prefetch_status = FILEMGR_PREFETCH_ABORT;
        spin_unlock(&file->lock);
        // wait
        thread_join(file->prefetch_tid, &ret);
    } else {
        spin_unlock(&file->lock);
    }

    // remove all cached blocks
    if (global_config.ncacheblock > 0) {
        bcache_remove_dirty_blocks(file);
        bcache_remove_clean_blocks(file);
        bcache_remove_file(file);
    }

    if (file->kv_header) {
        // multi KV intance mode & KV header exists
        file->free_kv_header(file);
    }

    // free global transaction
    wal_remove_transaction(file, &file->global_txn);
    free(file->global_txn.items);
    free(file->global_txn.wrapper);

    // destroy WAL
    if (wal_is_initialized(file)) {
        wal_shutdown(file);
        size_t i = 0;
        size_t num_all_shards = wal_get_num_all_shards(file);
        // Free all WAL shards (including compactor's shard)
        for (; i < num_all_shards; ++i) {
            hash_free(&file->wal->key_shards[i].hash_bykey);
            spin_destroy(&file->wal->key_shards[i].lock);
            hash_free(&file->wal->seq_shards[i].hash_byseq);
            spin_destroy(&file->wal->seq_shards[i].lock);
        }
        spin_destroy(&file->wal->lock);
        atomic_destroy_uint32_t(&file->wal->size);
        atomic_destroy_uint32_t(&file->wal->num_flushable);
        atomic_destroy_uint64_t(&file->wal->datasize);
        free(file->wal->key_shards);
        free(file->wal->seq_shards);
    }
    free(file->wal);

    // free mmap files if exist
    filemgr_remove_keystr_files(file);

    // free filename and header
    free(file->filename);
    if (file->header.data) free(file->header.data);
    // free old filename if any
    free(file->old_filename);

    // destroy locks
    spin_destroy(&file->lock);

#ifdef __FILEMGR_DATA_PARTIAL_LOCK
    plock_destroy(&file->plock);
#elif defined(__FILEMGR_DATA_MUTEX_LOCK)
    int i;
    for (i=0;i<DLOCK_MAX;++i) {
        mutex_destroy(&file->data_mutex[i]);
    }
#else
    int i;
    for (i=0;i<DLOCK_MAX;++i) {
        spin_destroy(&file->data_spinlock[i]);
    }
#endif //__FILEMGR_DATA_PARTIAL_LOCK

#ifdef __FILEMGR_MUTEX_LOCK
    mutex_destroy(&file->mutex);
#else
    spin_destroy(&file->mutex);
#endif

    // free file structure
    free(file->config);
    free(file);
}

// permanently remove file from cache (not just close)
// LCOV_EXCL_START
void filemgr_remove_file(struct filemgr *file)
{
    struct hash_elem *ret;

    fdb_assert(file, file, NULL);
    fdb_assert(file->ref_count <= 0, file->ref_count, 0);

    // remove from global hash table
    spin_lock(&filemgr_openlock);
    ret = hash_remove(&hash, &file->e);
    fdb_assert(ret, ret, NULL);
    spin_unlock(&filemgr_openlock);

    _filemgr_free_func(&file->e);
}
// LCOV_EXCL_STOP

void filemgr_shutdown()
{
    if (filemgr_initialized) {
        spin_lock(&initial_lock);

        hash_free_active(&hash, _filemgr_free_func);
        if (global_config.ncacheblock > 0) {
            bcache_shutdown();
        }
        filemgr_initialized = 0;
#ifndef SPIN_INITIALIZER
        initial_lock_status = 0;
#else
        initial_lock = SPIN_INITIALIZER;
#endif
        _filemgr_shutdown_temp_buf();
        spin_unlock(&initial_lock);
#ifndef SPIN_INITIALIZER
        spin_destroy(&initial_lock);
#endif
    }
}

bid_t filemgr_alloc(struct filemgr *file, err_log_callback *log_callback)
{
    spin_lock(&file->lock);
    bid_t bid = file->pos.val / file->blocksize;
    atomic_add_uint64_t(&file->pos, file->blocksize);

    if (global_config.ncacheblock <= 0) {
        // if block cache is turned off, write the allocated block before use
        uint8_t _buf = 0x0;
        ssize_t rv = file->ops->pwrite(file->fd, &_buf, 1, file->pos.val-1);
        _log_errno_str(file->ops, log_callback, (fdb_status) rv, "WRITE", file->filename);
    }
    spin_unlock(&file->lock);

    return bid;
}

void filemgr_alloc_multiple(struct filemgr *file, int nblock, bid_t *begin,
                            bid_t *end, err_log_callback *log_callback)
{
    spin_lock(&file->lock);
    *begin = file->pos.val / file->blocksize;
    *end = *begin + nblock - 1;
    atomic_add_uint64_t(&file->pos, file->blocksize * nblock);

    if (global_config.ncacheblock <= 0) {
        // if block cache is turned off, write the allocated block before use
        uint8_t _buf = 0x0;
        ssize_t rv = file->ops->pwrite(file->fd, &_buf, 1, file->pos.val-1);
        _log_errno_str(file->ops, log_callback, (fdb_status) rv, "WRITE", file->filename);
    }
    spin_unlock(&file->lock);
}

// atomically allocate NBLOCK blocks only when current file position is same to nextbid
bid_t filemgr_alloc_multiple_cond(struct filemgr *file, bid_t nextbid, int nblock,
                                  bid_t *begin, bid_t *end,
                                  err_log_callback *log_callback)
{
    bid_t bid;
    spin_lock(&file->lock);
    bid = file->pos.val / file->blocksize;
    if (bid == nextbid) {
        *begin = file->pos.val / file->blocksize;
        *end = *begin + nblock - 1;
        atomic_add_uint64_t(&file->pos, file->blocksize * nblock);

        if (global_config.ncacheblock <= 0) {
            // if block cache is turned off, write the allocated block before use
            uint8_t _buf = 0x0;
            ssize_t rv = file->ops->pwrite(file->fd, &_buf, 1, file->pos.val-1);
            _log_errno_str(file->ops, log_callback, (fdb_status) rv, "WRITE", file->filename);
        }
    }else{
        *begin = BLK_NOT_FOUND;
        *end = BLK_NOT_FOUND;
    }
    spin_unlock(&file->lock);
    return bid;
}

#ifdef __CRC32
INLINE fdb_status _filemgr_crc32_check(struct filemgr *file, void *buf)
{
    if ( *((uint8_t*)buf + file->blocksize-1) == BLK_MARKER_BNODE ) {
        uint32_t crc_file, crc;
        memcpy(&crc_file, (uint8_t *) buf + BTREE_CRC_OFFSET, sizeof(crc_file));
        crc_file = _endian_decode(crc_file);
        memset((uint8_t *) buf + BTREE_CRC_OFFSET, 0xff, BTREE_CRC_FIELD_LEN);
        crc = chksum(buf, file->blocksize);
        if (crc != crc_file) {
            return FDB_RESULT_CHECKSUM_ERROR;
        }
    }
    return FDB_RESULT_SUCCESS;
}
#endif

void filemgr_invalidate_block(struct filemgr *file, bid_t bid)
{
    if (global_config.ncacheblock > 0) {
        bcache_invalidate_block(file, bid);
    }
}

fdb_status filemgr_read(struct filemgr *file, bid_t bid, void *buf,
                  err_log_callback *log_callback)
{
    size_t lock_no;
    ssize_t r;
    uint64_t pos = bid * file->blocksize;
    fdb_status status = FDB_RESULT_SUCCESS;
    fdb_assert(pos < file->pos.val, pos, file->pos.val);

    if (global_config.ncacheblock > 0) {
        lock_no = bid % DLOCK_MAX;
        (void)lock_no;

#ifdef __FILEMGR_DATA_PARTIAL_LOCK
        plock_entry_t *plock_entry = NULL;
        bid_t is_writer = 0;
#endif
        bool locked = false;
        // Note: we don't need to grab lock for committed blocks
        // because they are immutable so that no writer will interfere and
        // overwrite dirty data
        if (filemgr_is_writable(file, bid)) {
#ifdef __FILEMGR_DATA_PARTIAL_LOCK
            plock_entry = plock_lock(&file->plock, &bid, &is_writer);
#elif defined(__FILEMGR_DATA_MUTEX_LOCK)
            mutex_lock(&file->data_mutex[lock_no]);
#else
            spin_lock(&file->data_spinlock[lock_no]);
#endif //__FILEMGR_DATA_PARTIAL_LOCK
            locked = true;
        }

        r = bcache_read(file, bid, buf);
        if (r == 0) {
            // cache miss
            // if normal file, just read a block
            r = file->ops->pread(file->fd, buf, file->blocksize, pos);
            if (r != file->blocksize) {
                _log_errno_str(file->ops, log_callback,
                               (fdb_status) r, "READ", file->filename);
                if (locked) {
#ifdef __FILEMGR_DATA_PARTIAL_LOCK
                    plock_unlock(&file->plock, plock_entry);
#elif defined(__FILEMGR_DATA_MUTEX_LOCK)
                    mutex_unlock(&file->data_mutex[lock_no]);
#else
                    spin_unlock(&file->data_spinlock[lock_no]);
#endif //__FILEMGR_DATA_PARTIAL_LOCK
                }
                return (fdb_status)r;
            }
#ifdef __CRC32
            status = _filemgr_crc32_check(file, buf);
            if (status != FDB_RESULT_SUCCESS) {
                _log_errno_str(file->ops, log_callback, status, "READ",
                        file->filename);
                if (locked) {
#ifdef __FILEMGR_DATA_PARTIAL_LOCK
                    plock_unlock(&file->plock, plock_entry);
#elif defined(__FILEMGR_DATA_MUTEX_LOCK)
                    mutex_unlock(&file->data_mutex[lock_no]);
#else
                    spin_unlock(&file->data_spinlock[lock_no]);
#endif //__FILEMGR_DATA_PARTIAL_LOCK
                }
                return status;
            }
#endif
            r = bcache_write(file, bid, buf, BCACHE_REQ_CLEAN);
            if (r != global_config.blocksize) {
                if (locked) {
#ifdef __FILEMGR_DATA_PARTIAL_LOCK
                    plock_unlock(&file->plock, plock_entry);
#elif defined(__FILEMGR_DATA_MUTEX_LOCK)
                    mutex_unlock(&file->data_mutex[lock_no]);
#else
                    spin_unlock(&file->data_spinlock[lock_no]);
#endif //__FILEMGR_DATA_PARTIAL_LOCK
                }
                _log_errno_str(file->ops, log_callback,
                               (fdb_status) r, "WRITE", file->filename);
                return FDB_RESULT_WRITE_FAIL;
            }
        }
        if (locked) {
#ifdef __FILEMGR_DATA_PARTIAL_LOCK
            plock_unlock(&file->plock, plock_entry);
#elif defined(__FILEMGR_DATA_MUTEX_LOCK)
            mutex_unlock(&file->data_mutex[lock_no]);
#else
            spin_unlock(&file->data_spinlock[lock_no]);
#endif //__FILEMGR_DATA_PARTIAL_LOCK
        }
    } else {
        r = file->ops->pread(file->fd, buf, file->blocksize, pos);
        if (r != file->blocksize) {
            _log_errno_str(file->ops, log_callback, (fdb_status) r, "READ",
                           file->filename);
            return (fdb_status)r;
        }

#ifdef __CRC32
        status = _filemgr_crc32_check(file, buf);
        if (status != FDB_RESULT_SUCCESS) {
            _log_errno_str(file->ops, log_callback, status, "READ",
                           file->filename);
            return status;
        }
#endif
    }
    return status;
}

fdb_status filemgr_write_offset(struct filemgr *file, bid_t bid,
                                uint64_t offset, uint64_t len, void *buf,
                                err_log_callback *log_callback)
{
    fdb_assert(offset + len <= file->blocksize, offset + len, file);

    size_t lock_no;
    ssize_t r = 0;
    uint64_t pos = bid * file->blocksize + offset;
    fdb_assert(pos >= file->last_commit.val, pos, file->last_commit.val);

    if (global_config.ncacheblock > 0) {
        lock_no = bid % DLOCK_MAX;
        (void)lock_no;

        bool locked = false;
#ifdef __FILEMGR_DATA_PARTIAL_LOCK
        plock_entry_t *plock_entry;
        bid_t is_writer = 1;
        plock_entry = plock_lock(&file->plock, &bid, &is_writer);
#elif defined(__FILEMGR_DATA_MUTEX_LOCK)
        mutex_lock(&file->data_mutex[lock_no]);
#else
        spin_lock(&file->data_spinlock[lock_no]);
#endif //__FILEMGR_DATA_PARTIAL_LOCK
        locked = true;

        if (len == file->blocksize) {
            // write entire block .. we don't need to read previous block
            r = bcache_write(file, bid, buf, BCACHE_REQ_DIRTY);
            if (r != global_config.blocksize) {
                if (locked) {
#ifdef __FILEMGR_DATA_PARTIAL_LOCK
                    plock_unlock(&file->plock, plock_entry);
#elif defined(__FILEMGR_DATA_MUTEX_LOCK)
                    mutex_unlock(&file->data_mutex[lock_no]);
#else
                    spin_unlock(&file->data_spinlock[lock_no]);
#endif //__FILEMGR_DATA_PARTIAL_LOCK
                }
                _log_errno_str(file->ops, log_callback,
                               (fdb_status) r, "WRITE", file->filename);
                return FDB_RESULT_WRITE_FAIL;
            }
        } else {
            // partially write buffer cache first
            r = bcache_write_partial(file, bid, buf, offset, len);
            if (r == 0) {
                // cache miss
                // write partially .. we have to read previous contents of the block
                uint64_t cur_file_pos = file->ops->goto_eof(file->fd);
                bid_t cur_file_last_bid = cur_file_pos / file->blocksize;
                void *_buf = _filemgr_get_temp_buf();

                if (bid >= cur_file_last_bid) {
                    // this is the first time to write this block
                    // we don't need to read previous block from file.
                } else {
                    r = file->ops->pread(file->fd, _buf, file->blocksize,
                                         bid * file->blocksize);
                    if (r != file->blocksize) {
                        if (locked) {
#ifdef __FILEMGR_DATA_PARTIAL_LOCK
                            plock_unlock(&file->plock, plock_entry);
#elif defined(__FILEMGR_DATA_MUTEX_LOCK)
                            mutex_unlock(&file->data_mutex[lock_no]);
#else
                            spin_unlock(&file->data_spinlock[lock_no]);
#endif //__FILEMGR_DATA_PARTIAL_LOCK
                        }
                        _filemgr_release_temp_buf(_buf);
                        _log_errno_str(file->ops, log_callback, (fdb_status) r,
                                       "READ", file->filename);
                        return FDB_RESULT_READ_FAIL;
                    }
                }
                memcpy((uint8_t *)_buf + offset, buf, len);
                r = bcache_write(file, bid, _buf, BCACHE_REQ_DIRTY);
                if (r != global_config.blocksize) {
                    if (locked) {
#ifdef __FILEMGR_DATA_PARTIAL_LOCK
                        plock_unlock(&file->plock, plock_entry);
#elif defined(__FILEMGR_DATA_MUTEX_LOCK)
                        mutex_unlock(&file->data_mutex[lock_no]);
#else
                        spin_unlock(&file->data_spinlock[lock_no]);
#endif //__FILEMGR_DATA_PARTIAL_LOCK
                    }
                    _filemgr_release_temp_buf(_buf);
                    _log_errno_str(file->ops, log_callback,
                            (fdb_status) r, "WRITE", file->filename);
                    return FDB_RESULT_WRITE_FAIL;
                }

                _filemgr_release_temp_buf(_buf);
            } // cache miss
        } // full block or partial block

        if (locked) {
#ifdef __FILEMGR_DATA_PARTIAL_LOCK
            plock_unlock(&file->plock, plock_entry);
#elif defined(__FILEMGR_DATA_MUTEX_LOCK)
            mutex_unlock(&file->data_mutex[lock_no]);
#else
            spin_unlock(&file->data_spinlock[lock_no]);
#endif //__FILEMGR_DATA_PARTIAL_LOCK
        }

    } else { // block cache disabled

#ifdef __CRC32
        if (len == file->blocksize) {
            uint8_t marker = *((uint8_t*)buf + file->blocksize - 1);
            if (marker == BLK_MARKER_BNODE) {
                memset((uint8_t *)buf + BTREE_CRC_OFFSET, 0xff, BTREE_CRC_FIELD_LEN);
                uint32_t crc32 = chksum(buf, file->blocksize);
                crc32 = _endian_encode(crc32);
                memcpy((uint8_t *)buf + BTREE_CRC_OFFSET, &crc32, sizeof(crc32));
            }
        }
#endif

        r = file->ops->pwrite(file->fd, buf, len, pos);
        _log_errno_str(file->ops, log_callback, (fdb_status) r, "WRITE", file->filename);
        if (r != len) {
            return FDB_RESULT_READ_FAIL;
        }
    } // block cache check
    return FDB_RESULT_SUCCESS;
}

fdb_status filemgr_write(struct filemgr *file, bid_t bid, void *buf,
                   err_log_callback *log_callback)
{
    return filemgr_write_offset(file, bid, 0, file->blocksize, buf,
                                log_callback);
}

fdb_status filemgr_commit(struct filemgr *file,
                          err_log_callback *log_callback)
{
    uint16_t header_len = file->header.size;
    uint16_t _header_len;
    bid_t _prev_bid;
    fdb_seqnum_t _seqnum;
    filemgr_header_revnum_t _revnum;
    int result = FDB_RESULT_SUCCESS;
    filemgr_magic_t magic = FILEMGR_MAGIC;
    filemgr_magic_t _magic;

    if (global_config.ncacheblock > 0) {
        result = bcache_flush(file);
        if (result != FDB_RESULT_SUCCESS) {
            _log_errno_str(file->ops, log_callback, (fdb_status) result,
                           "WRITE", file->filename);
            return (fdb_status)result;
        }
    }

    spin_lock(&file->lock);

    if (file->header.size > 0 && file->header.data) {
        void *buf = _filemgr_get_temp_buf();
        uint8_t marker[BLK_MARKER_SIZE];

        // [header data]:        'header_len' bytes   <---+
        // [header revnum]:      8 bytes                  |
        // [default KVS seqnum]: 8 bytes                  |
        // ...                                            |
        // (empty)                                    blocksize
        // ...                                            |
        // [prev header bid]:    8 bytes                  |
        // [header length]:      2 bytes                  |
        // [magic number]:       8 bytes                  |
        // [block marker]:       1 byte               <---+

        // header data
        memcpy(buf, file->header.data, header_len);
        // header rev number
        _revnum = _endian_encode(file->header.revnum);
        memcpy((uint8_t *)buf + header_len, &_revnum,
               sizeof(filemgr_header_revnum_t));
        // file's sequence number (default KVS seqnum)
        _seqnum = _endian_encode(file->header.seqnum);
        memcpy((uint8_t *)buf + header_len + sizeof(filemgr_header_revnum_t),
               &_seqnum, sizeof(fdb_seqnum_t));

        // prev header bid
        _prev_bid = _endian_encode(file->header.bid.val);
        memcpy((uint8_t *)buf + (file->blocksize - sizeof(filemgr_magic_t)
               - sizeof(header_len) - sizeof(_prev_bid) - BLK_MARKER_SIZE),
               &_prev_bid, sizeof(_prev_bid));
        // header length
        _header_len = _endian_encode(header_len);
        memcpy((uint8_t *)buf + (file->blocksize - sizeof(filemgr_magic_t)
               - sizeof(header_len) - BLK_MARKER_SIZE),
               &_header_len, sizeof(header_len));
        // magic number
        _magic = _endian_encode(magic);
        memcpy((uint8_t *)buf + (file->blocksize - sizeof(filemgr_magic_t)
               - BLK_MARKER_SIZE), &_magic, sizeof(magic));

        // marker
        memset(marker, BLK_MARKER_DBHEADER, BLK_MARKER_SIZE);
        memcpy((uint8_t *)buf + file->blocksize - BLK_MARKER_SIZE,
               marker, BLK_MARKER_SIZE);

        ssize_t rv = file->ops->pwrite(file->fd, buf, file->blocksize, file->pos.val);
        _log_errno_str(file->ops, log_callback, (fdb_status) rv,
                       "WRITE", file->filename);
        if (rv != file->blocksize) {
            _filemgr_release_temp_buf(buf);
            spin_unlock(&file->lock);
            return FDB_RESULT_WRITE_FAIL;
        }
        atomic_store_uint64_t(&file->header.bid, file->pos.val / file->blocksize);
        atomic_add_uint64_t(&file->pos, file->blocksize);

        atomic_store_uint64_t(&file->header.dirty_idtree_root, BLK_NOT_FOUND);
        atomic_store_uint64_t(&file->header.dirty_seqtree_root, BLK_NOT_FOUND);

        _filemgr_release_temp_buf(buf);
    }
    // race condition?
    atomic_store_uint64_t(&file->last_commit, file->pos.val);

    spin_unlock(&file->lock);

    if (file->fflags & FILEMGR_SYNC) {
        result = file->ops->fsync(file->fd);
        _log_errno_str(file->ops, log_callback, (fdb_status)result, "FSYNC", file->filename);
    }
    return (fdb_status) result;
}

fdb_status filemgr_sync(struct filemgr *file, err_log_callback *log_callback)
{
    fdb_status result = FDB_RESULT_SUCCESS;
    if (global_config.ncacheblock > 0) {
        result = bcache_flush(file);
        if (result != FDB_RESULT_SUCCESS) {
            _log_errno_str(file->ops, log_callback, (fdb_status) result,
                           "WRITE", file->filename);
            return result;
        }
    }

    if (file->fflags & FILEMGR_SYNC) {
        int rv = file->ops->fsync(file->fd);
        _log_errno_str(file->ops, log_callback, (fdb_status)rv, "FSYNC", file->filename);
        return (fdb_status) rv;
    }
    return result;
}

int filemgr_update_file_status(struct filemgr *file, file_status_t status,
                                char *old_filename)
{
    int ret = 1;
    spin_lock(&file->lock);
    atomic_store_uint8_t(&file->status, status);
    if (old_filename) {
        if (!file->old_filename) {
            file->old_filename = old_filename;
        } else {
            ret = 0;
            fdb_assert(file->ref_count, file->ref_count, 0);
            free(old_filename);
        }
    }
    spin_unlock(&file->lock);
    return ret;
}

void filemgr_set_compaction_state(struct filemgr *old_file, struct filemgr *new_file,
                                  file_status_t status)
{
    spin_lock(&old_file->lock);
    old_file->new_file = new_file;
    atomic_store_uint8_t(&old_file->status, status);
    spin_unlock(&old_file->lock);
}

// Check if there is a file that still points to the old_file that is being
// compacted away. If so open the file and return its pointer.
static
void *_filemgr_check_stale_link(struct hash_elem *h, void *ctx) {
    struct filemgr *cur_file = (struct filemgr *)ctx;
    struct filemgr *file = _get_entry(h, struct filemgr, e);
    spin_lock(&file->lock);
    if (file->status.val == FILE_REMOVED_PENDING && file->new_file == cur_file) {
        // Incrementing reference counter below is the same as filemgr_open()
        // We need to do this to ensure that the pointer returned does not
        // get freed outside the filemgr_open lock
        file->ref_count++;
        spin_unlock(&file->lock);
        return (void *)file;
    }
    spin_unlock(&file->lock);
    return (void *)NULL;
}

struct filemgr *filemgr_search_stale_links(struct filemgr *cur_file) {
    struct filemgr *very_old_file;
    spin_lock(&filemgr_openlock);
    very_old_file = (struct filemgr *)hash_scan(&hash,
                                         _filemgr_check_stale_link, cur_file);
    spin_unlock(&filemgr_openlock);
    return very_old_file;
}

char *filemgr_redirect_old_file(struct filemgr *very_old_file,
                                     struct filemgr *new_file,
                                     filemgr_redirect_hdr_func
                                     redirect_header_func) {
    size_t old_header_len, new_header_len;
    uint16_t new_filename_len;
    char *past_filename;
    spin_lock(&very_old_file->lock);
    fdb_assert(very_old_file->header.size, very_old_file->header.size, 0);
    fdb_assert(very_old_file->new_file, very_old_file->new_file, 0);
    old_header_len = very_old_file->header.size;
    new_filename_len = strlen(new_file->filename);
    // Find out the new DB header length with new_file's filename
    new_header_len = old_header_len - strlen(very_old_file->new_file->filename)
        + new_filename_len;
    // As we are going to change the new_filename field in the DB header of the
    // very_old_file, maybe reallocate DB header buf to accomodate bigger value
    if (new_header_len > old_header_len) {
        very_old_file->header.data = realloc(very_old_file->header.data,
                new_header_len);
    }
    very_old_file->new_file = new_file; // Re-direct very_old_file to new_file
    past_filename = redirect_header_func((uint8_t *)very_old_file->header.data,
            new_file->filename, new_filename_len + 1);//Update in-memory header
    very_old_file->header.size = new_header_len;
    ++(very_old_file->header.revnum);

    spin_unlock(&very_old_file->lock);
    return past_filename;
}

void filemgr_remove_pending(struct filemgr *old_file, struct filemgr *new_file)
{
    fdb_assert(new_file, new_file, old_file);

    spin_lock(&old_file->lock);
    if (old_file->ref_count > 0) {
        // delay removing
        old_file->new_file = new_file;
        atomic_store_uint8_t(&old_file->status, FILE_REMOVED_PENDING);
        spin_unlock(&old_file->lock);
    } else {
        // immediatly remove
        // LCOV_EXCL_START
        spin_unlock(&old_file->lock);
        remove(old_file->filename);
        filemgr_remove_file(old_file);
        // LCOV_EXCL_STOP
    }
}

// Note: filemgr_openlock should be held before calling this function.
fdb_status filemgr_destroy_file(char *filename,
                                struct filemgr_config *config,
                                struct hash *destroy_file_set)
{
    struct filemgr *file = NULL;
    struct hash to_destroy_files;
    struct hash *destroy_set = (destroy_file_set ? destroy_file_set :
                                                  &to_destroy_files);
    struct filemgr query;
    struct hash_elem *e = NULL;
    fdb_status status = FDB_RESULT_SUCCESS;
    char *old_filename = NULL;

    if (!destroy_file_set) { // top level or non-recursive call
        hash_init(destroy_set, NBUCKET, _file_hash, _file_cmp);
    }

    query.filename = filename;
    // check whether file is already being destroyed in parent recursive call
    e = hash_find(destroy_set, &query.e);
    if (e) { // Duplicate filename found, nothing to be done in this call
        if (!destroy_file_set) { // top level or non-recursive call
            hash_free(destroy_set);
        }
        return status;
    } else {
        // Remember file. Stack value ok IFF single direction recursion
        hash_insert(destroy_set, &query.e);
    }

    // check global list of known files to see if it is already opened or not
    e = hash_find(&hash, &query.e);
    if (e) {
        // already opened (return existing structure)
        file = _get_entry(e, struct filemgr, e);

        spin_lock(&file->lock);
        if (file->ref_count) {
            spin_unlock(&file->lock);
            status = FDB_RESULT_FILE_IS_BUSY;
            if (!destroy_file_set) { // top level or non-recursive call
                hash_free(destroy_set);
            }
            return status;
        }
        spin_unlock(&file->lock);
        if (file->old_filename) {
            status = filemgr_destroy_file(file->old_filename, config,
                                          destroy_set);
            if (status != FDB_RESULT_SUCCESS) {
                if (!destroy_file_set) { // top level or non-recursive call
                    hash_free(destroy_set);
                }
                return status;
            }
        }

        // Cleanup file from in-memory as well as on-disk
        e = hash_remove(&hash, &file->e);
        fdb_assert(e, e, 0);
        _filemgr_free_func(&file->e);
        if (filemgr_does_file_exist(filename) == FDB_RESULT_SUCCESS) {
            if (remove(filename)) {
                status = FDB_RESULT_FILE_REMOVE_FAIL;
            }
        }
    } else { // file not in memory, read on-disk to destroy older versions..
        file = (struct filemgr *)alca(struct filemgr, 1);
        file->filename = filename;
        file->ops = get_filemgr_ops();
        file->fd = file->ops->open(file->filename, O_RDWR, 0666);
        file->blocksize = global_config.blocksize;
        if (file->fd < 0) {
            if (file->fd != FDB_RESULT_NO_SUCH_FILE) {
                if (!destroy_file_set) { // top level or non-recursive call
                    hash_free(destroy_set);
                }
                return FDB_RESULT_OPEN_FAIL;
            }
        } else { // file successfully opened, seek to end to get DB header
            cs_off_t offset = file->ops->goto_eof(file->fd);
            if (offset == FDB_RESULT_SEEK_FAIL) {
                if (!destroy_file_set) { // top level or non-recursive call
                    hash_free(destroy_set);
                }
                return FDB_RESULT_SEEK_FAIL;
            } else { // Need to read DB header which contains old filename
                atomic_store_uint64_t(&file->pos, offset);
                status = _filemgr_read_header(file);
                if (status != FDB_RESULT_SUCCESS) {
                    if (!destroy_file_set) { // top level or non-recursive call
                        hash_free(destroy_set);
                    }
                    file->ops->close(file->fd);
                    return status;
                }
                if (file->header.data) {
                    uint16_t *new_filename_len_ptr = (uint16_t *)((char *)
                                                     file->header.data + 64);
                    uint16_t new_filename_len =
                                      _endian_decode(*new_filename_len_ptr);
                    uint16_t *old_filename_len_ptr = (uint16_t *)((char *)
                                                     file->header.data + 66);
                    uint16_t old_filename_len =
                                      _endian_decode(*old_filename_len_ptr);
                    old_filename = (char *)file->header.data + 68
                                   + new_filename_len;
                    if (old_filename_len) {
                        status = filemgr_destroy_file(old_filename, config,
                                                      destroy_set);
                    }
                    free(file->header.data);
                }
                file->ops->close(file->fd);
                if (status == FDB_RESULT_SUCCESS) {
                    if (filemgr_does_file_exist(filename)
                                               == FDB_RESULT_SUCCESS) {
                        if (remove(filename)) {
                            status = FDB_RESULT_FILE_REMOVE_FAIL;
                        }
                    }
                }
            }
        }
    }

    if (!destroy_file_set) { // top level or non-recursive call
        hash_free(destroy_set);
    }

    return status;
}

bool filemgr_is_rollback_on(struct filemgr *file)
{
    bool rv;
    spin_lock(&file->lock);
    rv = (file->fflags & FILEMGR_ROLLBACK_IN_PROG);
    spin_unlock(&file->lock);
    return rv;
}

void filemgr_set_rollback(struct filemgr *file, uint8_t new_val)
{
    spin_lock(&file->lock);
    if (new_val) {
        file->fflags |= FILEMGR_ROLLBACK_IN_PROG;
    } else {
        file->fflags &= ~FILEMGR_ROLLBACK_IN_PROG;
    }
    spin_unlock(&file->lock);
}

void filemgr_set_in_place_compaction(struct filemgr *file,
                                     bool in_place_compaction) {
    spin_lock(&file->lock);
    file->in_place_compaction = in_place_compaction;
    spin_unlock(&file->lock);
}

void filemgr_mutex_openlock(struct filemgr_config *config)
{
    filemgr_init(config);

    spin_lock(&filemgr_openlock);
}

void filemgr_mutex_openunlock(void)
{
    spin_unlock(&filemgr_openlock);
}

void filemgr_mutex_lock(struct filemgr *file)
{
#ifdef __FILEMGR_MUTEX_LOCK
    mutex_lock(&file->mutex);
#else
    spin_lock(&file->mutex);
#endif
}

void filemgr_mutex_unlock(struct filemgr *file)
{
#ifdef __FILEMGR_MUTEX_LOCK
    mutex_unlock(&file->mutex);
#else
    spin_unlock(&file->mutex);
#endif
}

void filemgr_set_dirty_root(struct filemgr *file,
                            bid_t dirty_idtree_root,
                            bid_t dirty_seqtree_root)
{
    atomic_store_uint64_t(&file->header.dirty_idtree_root, dirty_idtree_root);
    atomic_store_uint64_t(&file->header.dirty_seqtree_root, dirty_seqtree_root);
}

// Create keystr file and return mmapped address
// Note that both filemgr_add_keystr_file() and filemgr_remove_keystr_files()
// are protected by filemgr_mutex_lock, since they are called by update operations
void *filemgr_add_keystr_file(struct filemgr *file, uint64_t size)
{
    struct keystr_file *keystr_file;
    keystr_file = (struct keystr_file *)calloc(1, sizeof(struct keystr_file));

    keystr_file->filename = (char*)malloc(file->filename_len + 32);
    sprintf(keystr_file->filename, "%s.wal_index_%05d", file->filename, file->n_keystr_files);
    keystr_file->fd = file->ops->open(keystr_file->filename,
                                      O_CREAT | O_RDWR | O_TRUNC, 0644);
    if (keystr_file->fd < 0) {
        free(keystr_file->filename);
        free(keystr_file);
        return NULL;
    }

    // allocate file blocks
    ssize_t r = file->ops->pwrite(keystr_file->fd, (void*)"x", 1, size-1);
    if (r != 1) {
        file->ops->close(keystr_file->fd);
        free(keystr_file->filename);
        free(keystr_file);
        return NULL;
    }

    keystr_file->size = size;
    keystr_file->addr = file->ops->mmap(keystr_file->fd, keystr_file->size,
                                        &keystr_file->aux);
    if (keystr_file->addr == NULL) {
        file->ops->close(keystr_file->fd);
        free(keystr_file->filename);
        free(keystr_file);
        return NULL;
    }
    list_push_front(&file->keystr_files, &keystr_file->le);
    file->n_keystr_files++;

    return keystr_file->addr;
}

// Close & unmap & remove all keystr files
void filemgr_remove_keystr_files(struct filemgr *file)
{
    struct keystr_file *keystr_file;
    struct list_elem *e;

    e = list_begin(&file->keystr_files);
    while (e) {
        keystr_file = _get_entry(e, struct keystr_file, le);
        e = list_remove(&file->keystr_files, &keystr_file->le);

        if (file->ops->munmap(keystr_file->addr, keystr_file->size,
                              keystr_file->aux) < 0) {
            continue;
        }
        if (file->ops->close(keystr_file->fd) < 0) {
            continue;
        }
        remove(keystr_file->filename);
        free(keystr_file->filename);
        free(keystr_file);
    }
}

struct filename_item {
    char *filename;
    struct list_elem le;
};

// manually scan & remove all keystr files
void filemgr_scan_remove_keystr_files(struct filemgr *file)
{
    int i;
    int filename_len = file->filename_len;
    int dirname_len = 0;
    char *filename = file->filename;
    char prefix[FDB_MAX_FILENAME_LEN];
    char dirname[FDB_MAX_FILENAME_LEN];
    struct list filelist;
    struct filename_item *item;
    struct list_elem *e;

    list_init(&filelist);

#if !defined(WIN32) && !defined(_WIN32)
    // Posix
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
    strcat(prefix, ".wal_index");

    dir_info = opendir(dirname);
    if (dir_info != NULL) {
        int prefix_size = strlen(prefix);
        while ((dir_entry = readdir(dir_info))) {
            if (!strncmp(dir_entry->d_name, prefix, prefix_size)) {
                item = (struct filename_item*)calloc(1, sizeof(struct filename_item));
                item->filename = (char*)malloc(strlen(dir_entry->d_name)+1);
                strcpy(item->filename, dir_entry->d_name);
                list_push_front(&filelist, &item->le);
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

    strcpy(prefix, filename + dirname_len);
    strcat(prefix, ".wal_index");

    WIN32_FIND_DATA filedata;
    HANDLE hfind;
    char query_str[FDB_MAX_FILENAME_LEN];

    // find all files start with 'prefix'
    int prefix_size = strlen(prefix);
    sprintf(query_str, "%s*", prefix);
    hfind = FindFirstFile(query_str, &filedata);
    while (hfind != INVALID_HANDLE_VALUE) {
        if (!strncmp(filedata.cFileName, prefix, prefix_size)) {
            item = (struct filename_item*)calloc(1, sizeof(struct filename_item));
            item->filename = (char*)malloc(strlen(filedata.cFileName)+1);
            strcpy(item->filename, filedata.cFileName);
            list_push_front(&filelist, &item->le);
        }

        if (!FindNextFile(hfind, &filedata)) {
            FindClose(hfind);
            hfind = INVALID_HANDLE_VALUE;
        }
    }
#endif

    // remove all file in list
    e = list_begin(&filelist);
    while (e) {
        item = _get_entry(e, struct filename_item, le);
        e = list_remove(&filelist, &item->le);
        remove(item->filename);
        free(item->filename);
        free(item);
    }
}

static int _kvs_stat_cmp(struct avl_node *a, struct avl_node *b, void *aux)
{
    struct kvs_node *aa, *bb;
    aa = _get_entry(a, struct kvs_node, avl_id);
    bb = _get_entry(b, struct kvs_node, avl_id);

    if (aa->id < bb->id) {
        return -1;
    } else if (aa->id > bb->id) {
        return 1;
    } else {
        return 0;
    }
}

void _kvs_stat_set(struct filemgr *file,
                   fdb_kvs_id_t kv_id,
                   struct kvs_stat stat)
{
    if (kv_id == 0) {
        spin_lock(&file->lock);
        file->header.stat = stat;
        spin_unlock(&file->lock);
    } else {
        struct avl_node *a;
        struct kvs_node query, *node;
        struct kvs_header *kv_header = file->kv_header;

        spin_lock(&kv_header->lock);
        query.id = kv_id;
        a = avl_search(kv_header->idx_id, &query.avl_id, _kvs_stat_cmp);
        if (a) {
            node = _get_entry(a, struct kvs_node, avl_id);
            node->stat = stat;
        }
        spin_unlock(&kv_header->lock);
    }
}

void _kvs_stat_update_attr(struct filemgr *file,
                           fdb_kvs_id_t kv_id,
                           kvs_stat_attr_t attr,
                           int delta)
{
    spin_t *lock = NULL;
    struct kvs_stat *stat;

    if (kv_id == 0) {
        stat = &file->header.stat;
        lock = &file->lock;
        spin_lock(lock);
    } else {
        struct avl_node *a;
        struct kvs_node query, *node;
        struct kvs_header *kv_header = file->kv_header;

        lock = &kv_header->lock;
        spin_lock(lock);
        query.id = kv_id;
        a = avl_search(kv_header->idx_id, &query.avl_id, _kvs_stat_cmp);
        if (!a) {
            // KV instance corresponding to the kv_id is already removed
            spin_unlock(lock);
            return;
        }
        node = _get_entry(a, struct kvs_node, avl_id);
        stat = &node->stat;
    }

    if (attr == KVS_STAT_DATASIZE) {
        stat->datasize += delta;
    } else if (attr == KVS_STAT_NDOCS) {
        stat->ndocs += delta;
    } else if (attr == KVS_STAT_NLIVENODES) {
        stat->nlivenodes += delta;
    } else if (attr == KVS_STAT_WAL_NDELETES) {
        stat->wal_ndeletes += delta;
    } else if (attr == KVS_STAT_WAL_NDOCS) {
        stat->wal_ndocs += delta;
    }
    spin_unlock(lock);
}

int _kvs_stat_get_kv_header(struct kvs_header *kv_header,
                            fdb_kvs_id_t kv_id,
                            struct kvs_stat *stat)
{
    int ret = 0;
    struct avl_node *a;
    struct kvs_node query, *node;

    query.id = kv_id;
    a = avl_search(kv_header->idx_id, &query.avl_id, _kvs_stat_cmp);
    if (a) {
        node = _get_entry(a, struct kvs_node, avl_id);
        *stat = node->stat;
    } else {
        ret = -1;
    }
    return ret;
}

int _kvs_stat_get(struct filemgr *file,
                  fdb_kvs_id_t kv_id,
                  struct kvs_stat *stat)
{
    int ret = 0;

    if (kv_id == 0) {
        spin_lock(&file->lock);
        *stat = file->header.stat;
        spin_unlock(&file->lock);
    } else {
        struct kvs_header *kv_header = file->kv_header;

        spin_lock(&kv_header->lock);
        ret = _kvs_stat_get_kv_header(kv_header, kv_id, stat);
        spin_unlock(&kv_header->lock);
    }

    return ret;
}

uint64_t _kvs_stat_get_sum(struct filemgr *file,
                           kvs_stat_attr_t attr)
{
    struct avl_node *a;
    struct kvs_node *node;
    struct kvs_header *kv_header = file->kv_header;

    uint64_t ret = 0;
    spin_lock(&file->lock);
    if (attr == KVS_STAT_DATASIZE) {
        ret += file->header.stat.datasize;
    } else if (attr == KVS_STAT_NDOCS) {
        ret += file->header.stat.ndocs;
    } else if (attr == KVS_STAT_NLIVENODES) {
        ret += file->header.stat.nlivenodes;
    } else if (attr == KVS_STAT_WAL_NDELETES) {
        ret += file->header.stat.wal_ndeletes;
    } else if (attr == KVS_STAT_WAL_NDOCS) {
        ret += file->header.stat.wal_ndocs;
    }
    spin_unlock(&file->lock);

    if (kv_header) {
        spin_lock(&kv_header->lock);
        a = avl_first(kv_header->idx_id);
        while (a) {
            node = _get_entry(a, struct kvs_node, avl_id);
            a = avl_next(&node->avl_id);

            if (attr == KVS_STAT_DATASIZE) {
                ret += node->stat.datasize;
            } else if (attr == KVS_STAT_NDOCS) {
                ret += node->stat.ndocs;
            } else if (attr == KVS_STAT_NLIVENODES) {
                ret += node->stat.nlivenodes;
            } else if (attr == KVS_STAT_WAL_NDELETES) {
                ret += node->stat.wal_ndeletes;
            } else if (attr == KVS_STAT_WAL_NDOCS) {
                ret += node->stat.wal_ndocs;
            }
        }
        spin_unlock(&kv_header->lock);
    }

    return ret;
}

void buf2kvid(size_t chunksize, void *buf, fdb_kvs_id_t *id)
{
    int size_id = sizeof(fdb_kvs_id_t);
    fdb_kvs_id_t temp;

    if (chunksize == size_id) {
        temp = *((fdb_kvs_id_t*)buf);
    } else if (chunksize < size_id) {
        temp = 0;
        memcpy((uint8_t*)&temp + (size_id - chunksize), buf, chunksize);
    } else { // chunksize > sizeof(fdb_kvs_id_t)
        memcpy(&temp, (uint8_t*)buf + (chunksize - size_id), size_id);
    }
    *id = _endian_decode(temp);
}

void kvid2buf(size_t chunksize, fdb_kvs_id_t id, void *buf)
{
    int size_id = sizeof(fdb_kvs_id_t);
    id = _endian_encode(id);

    if (chunksize == size_id) {
        memcpy(buf, &id, size_id);
    } else if (chunksize < size_id) {
        memcpy(buf, (uint8_t*)&id + (size_id - chunksize), chunksize);
    } else { // chunksize > sizeof(fdb_kvs_id_t)
        memset(buf, 0x0, chunksize - size_id);
        memcpy((uint8_t*)buf + (chunksize - size_id), &id, size_id);
    }
}

void buf2buf(size_t chunksize_src, void *buf_src,
             size_t chunksize_dst, void *buf_dst)
{
    if (chunksize_dst == chunksize_src) {
        memcpy(buf_dst, buf_src, chunksize_src);
    } else if (chunksize_dst < chunksize_src) {
        memcpy(buf_dst, (uint8_t*)buf_src + (chunksize_src - chunksize_dst),
               chunksize_dst);
    } else { // chunksize_dst > chunksize_src
        memset(buf_dst, 0x0, chunksize_dst - chunksize_src);
        memcpy((uint8_t*)buf_dst + (chunksize_dst - chunksize_src),
               buf_src, chunksize_src);
    }
}
