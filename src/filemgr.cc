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
#include <assert.h>
#include <sys/stat.h>

#include "filemgr.h"
#include "hash_functions.h"
#include "blockcache.h"
#include "wal.h"
#include "crc32.h"
#include "list.h"

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
static spin_t initial_lock;
#endif


static int filemgr_initialized = 0;
static struct filemgr_config global_config;
static struct hash hash;
static spin_t filemgr_openlock;

static size_t filemgr_sys_pagesize;

struct temp_buf_item{
    void *addr;
    struct list_elem le;
};
static struct list temp_buf;
static spin_t temp_buf_lock;

static void _filemgr_free_func(struct hash_elem *h);

static void _log_errno_str(struct filemgr_ops *ops,
                           err_log_callback *log_callback,
                           char *msg,
                           int io_error) {
    if (msg && log_callback && log_callback->callback) {
        char errno_msg[512];
        ops->get_errno_str(errno_msg, 512);
        strcat(msg, errno_msg);
        log_callback->callback(io_error, msg,
                               log_callback->ctx_data);
    }
}

uint32_t _file_hash(struct hash *hash, struct hash_elem *e)
{
    struct filemgr *file = _get_entry(e, struct filemgr, e);
    int len = strlen(file->filename);
    return crc32_8_last8(file->filename, len, 0) & ((unsigned)(NBUCKET-1));
}

int _file_cmp(struct hash_elem *a, struct hash_elem *b)
{
    struct filemgr *aa, *bb;
    aa = _get_entry(a, struct filemgr, e);
    bb = _get_entry(b, struct filemgr, e);
    return strcmp(aa->filename, bb->filename);
}

void filemgr_init(struct filemgr_config *config)
{
    int i, ret;
    uint32_t *temp;

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

void * _filemgr_get_temp_buf()
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

void _filemgr_release_temp_buf(void *buf)
{
    struct temp_buf_item *item;

    spin_lock(&temp_buf_lock);
    item = (struct temp_buf_item*)((uint8_t *)buf + global_config.blocksize);
    list_push_front(&temp_buf, &item->le);
    spin_unlock(&temp_buf_lock);
}

void _filemgr_shutdown_temp_buf()
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

void _filemgr_read_header(struct filemgr *file)
{
    uint8_t marker[BLK_MARKER_SIZE];
    filemgr_magic_t magic;
    filemgr_header_len_t len;
    uint8_t *buf;

    // get temp buffer
    buf = (uint8_t *) _filemgr_get_temp_buf();

    if (file->pos > 0) {
        // Crash Recovery Test 1: unaligned last block write
        uint64_t remain = file->pos % file->blocksize;
        if (remain) {
            file->pos -= remain;
            file->last_commit = file->pos;
            DBG("Crash Detected: %llu non-block aligned bytes discarded\n",
                remain);
        }

        do {
            file->ops->pread(file->fd, buf, file->blocksize,
                             file->pos - file->blocksize);
            memcpy(marker, buf + file->blocksize - BLK_MARKER_SIZE,
                   BLK_MARKER_SIZE);

            if (marker[0] == BLK_MARKER_DBHEADER) {
                // possible need for byte conversions here
                memcpy(&magic, buf + file->blocksize - sizeof(magic)
                               - BLK_MARKER_SIZE, sizeof(magic));
                magic = _endian_decode(magic);

                if (magic == FILEMGR_MAGIC) {
                    memcpy(&len, buf + file->blocksize - sizeof(magic)
                                 - sizeof(len) - BLK_MARKER_SIZE, sizeof(len));
                    len = _endian_decode(len);

                    if (len == BLK_DBHEADER_SIZE) {
                        uint32_t crc, crc_file;
                        crc = crc32_8(buf, len - sizeof(crc), 0);
                        memcpy(&crc_file, buf + len - sizeof(crc), sizeof(crc));
                        crc_file = _endian_decode(crc_file);
                        if (crc == crc_file) {
                            file->header.data = (void *)malloc(len);

                            memcpy(file->header.data, buf, len);
                            memcpy(&file->header.revnum, buf + len,
                                   sizeof(filemgr_header_revnum_t));
                            memcpy(&file->header.seqnum,
                                    buf + len + sizeof(filemgr_header_revnum_t),
                                    sizeof(fdb_seqnum_t));
                            file->header.revnum =
                                _endian_decode(file->header.revnum);
                            file->header.seqnum =
                                _endian_decode(file->header.seqnum);
                            file->header.size = len;

                            // release temp buffer
                            _filemgr_release_temp_buf(buf);

                            return;
                        } else {
                            DBG("Crash Detected: CRC on disk %u != %u\n",
                                    crc_file, crc);
                        }
                    } else {
                        DBG("Crash Detected: Wrong len %u != %u\n", len,
                                BLK_DBHEADER_SIZE);
                    }
                } else {
                    DBG("Crash Detected: Wrong Magic %llu != %llu\n", magic,
                            FILEMGR_MAGIC);
                }
            } else {
                DBG("Crash Detected: Last Block not DBHEADER %0.01x\n",
                        marker[0]);
            }

            file->pos -= file->blocksize;
            file->last_commit = file->pos;
        } while (file->pos);
    }

    // release temp buffer
    _filemgr_release_temp_buf(buf);

    file->header.size = 0;
    file->header.revnum = 0;
    file->header.seqnum = 0;
    file->header.data = NULL;
}

struct filemgr * filemgr_open(char *filename, struct filemgr_ops *ops,
                              struct filemgr_config *config,
                              err_log_callback *log_callback)
{
    struct filemgr *file = NULL;
    struct filemgr query;
    struct hash_elem *e = NULL;
    int read_only = config->options & FILEMGR_READONLY;
    int file_flag = 0x0;
    int fd = -1;

    // global initialization
    // initialized only once at first time
    if (!filemgr_initialized) {
#ifndef SPIN_INITIALIZER
        void *zerobytes = (void *)malloc(sizeof(spin_t));
        memset(zerobytes, 0, sizeof(spin_t));
        if (!memcmp(&initial_lock, zerobytes, sizeof(spin_t))) {
            // NULL value .. initialize
            spin_init(&initial_lock);
        }
        free(zerobytes);
#endif
        filemgr_init(config);
    }

    // check whether file is already opened or not
    query.filename = filename;
    spin_lock(&filemgr_openlock);
    e = hash_find(&hash, &query.e);

    if (e) {
        // already opened (return existing structure)
        file = _get_entry(e, struct filemgr, e);

        spin_lock(&file->lock);
        file->ref_count++;

        if (file->status == FILE_CLOSED) { // if file was closed before
            file_flag = read_only ? O_RDONLY : O_RDWR;
            file_flag |= config->flag;
            file->fd = file->ops->open(file->filename, file_flag, 0666);
            if (file->fd < 0) {
                if (file->fd == FDB_RESULT_NO_SUCH_FILE) {
                    // A database file was manually deleted by the user.
                    // Clean up global hash table, WAL index, and buffer cache.
                    // Then, retry it with a create option below.
                    spin_unlock(&file->lock);
                    assert(hash_remove(&hash, &file->e));
                    _filemgr_free_func(&file->e);
                } else {
                    char msg[1024];
                    sprintf(msg, "Error in OPEN on a database file '%s', ", filename);
                    _log_errno_str(file->ops, log_callback, msg, file->fd);
                    file->ref_count--;
                    spin_unlock(&file->lock);
                    spin_unlock(&filemgr_openlock);
                    return NULL;
                }
            } else { // Reopening the closed file is succeed.
                file->status = FILE_NORMAL;
                if (config->options & FILEMGR_SYNC) {
                    file->fflags |= FILEMGR_SYNC;
                } else {
                    file->fflags &= ~FILEMGR_SYNC;
                }
                spin_unlock(&file->lock);
                spin_unlock(&filemgr_openlock);
                return file;
            }
        } else { // file is already opened.

            if (config->options & FILEMGR_SYNC) {
                file->fflags |= FILEMGR_SYNC;
            } else {
                file->fflags &= ~FILEMGR_SYNC;
            }

            spin_unlock(&file->lock);
            spin_unlock(&filemgr_openlock);
            return file;
        }
    }

    file_flag = read_only ? O_RDONLY : (O_RDWR | O_CREAT);
    file_flag |= config->flag;
    fd = ops->open(filename, file_flag, 0666);
    if (fd < 0) {
        char msg[1024];
        sprintf(msg, "Error in OPEN on a database file '%s', ", filename);
        _log_errno_str(ops, log_callback, msg, fd);
        spin_unlock(&filemgr_openlock);
        return NULL;
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
    file->status = FILE_NORMAL;
    file->config = &global_config;
    file->new_file = NULL;
    file->old_filename = NULL;
    file->fd = fd;

    cs_off_t offset = file->ops->goto_eof(file->fd);
    if (offset == FDB_RESULT_SEEK_FAIL) {
        char msg[1024];
        sprintf(msg, "Error in SEEK_END on a database file '%s', ", filename);
        _log_errno_str(file->ops, log_callback, msg, FDB_RESULT_SEEK_FAIL);
        free(file->wal);
        free(file->filename);
        free(file);
        spin_unlock(&filemgr_openlock);
        return NULL;
    }
    file->pos = file->last_commit = offset;

    file->bcache = NULL;

    _filemgr_read_header(file);

    spin_init(&file->lock);

#ifdef __FILEMGR_MUTEX_LOCK
    mutex_init(&file->mutex);
#else
    spin_init(&file->mutex);
#endif

    // initialize WAL
    if (!wal_is_initialized(file)) {
        wal_init(file, FDB_WAL_NBUCKET);
    }

    hash_insert(&hash, &file->e);
    spin_unlock(&filemgr_openlock);

    if (config->options & FILEMGR_SYNC) {
        file->fflags |= FILEMGR_SYNC;
    } else {
        file->fflags &= ~FILEMGR_SYNC;
    }
    return file;
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

char* filemgr_get_filename_ptr(struct filemgr *file, char **filename, uint16_t *len)
{
    spin_lock(&file->lock);
    *filename = file->filename;
    *len = file->filename_len;
    spin_unlock(&file->lock);
    return *filename;
}

void* filemgr_fetch_header(struct filemgr *file, void *buf, size_t *len)
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

uint64_t filemgr_fetch_prev_header(struct filemgr *file, uint64_t bid,
                                   void *buf, size_t *len, fdb_seqnum_t *seqnum,
                                   err_log_callback *log_callback)
{
    uint8_t *_buf;
    uint8_t marker[BLK_MARKER_SIZE];
    filemgr_magic_t magic;
    fdb_seqnum_t _seqnum;
    filemgr_header_revnum_t _revnum;
    int found = 0;

    if (!bid || bid == BLK_NOT_FOUND) {
        *len = 0; // No other header available
        return bid;
    }
    _buf = (uint8_t *)_filemgr_get_temp_buf();

    bid--;
    // Reverse scan the file for a previous DB header
    do {
        filemgr_read(file, (bid_t)bid, _buf, log_callback);
        memcpy(marker, _buf + file->blocksize - BLK_MARKER_SIZE,
                BLK_MARKER_SIZE);

        if (marker[0] != BLK_MARKER_DBHEADER) {
            continue;
        }
        memcpy(buf, _buf, BLK_DBHEADER_SIZE);
        memcpy(&_revnum, _buf + BLK_DBHEADER_SIZE,
               sizeof(filemgr_header_revnum_t));
        memcpy(&_seqnum,
               _buf + BLK_DBHEADER_SIZE + sizeof(filemgr_header_revnum_t),
               sizeof(fdb_seqnum_t));
        *seqnum = _endian_decode(_seqnum);
        *len = BLK_DBHEADER_SIZE;
        found = 1;
        break;
    } while (bid--); // scan even the first block 0

    if (!found) { // no other header found till end of file
        *len = 0;
    }

    _filemgr_release_temp_buf(_buf);

    return bid;
}

fdb_status filemgr_close(struct filemgr *file, bool cleanup_cache_onclose,
                         err_log_callback *log_callback)
{
    int rv = FDB_RESULT_SUCCESS;
    // remove filemgr structure if no thread refers to the file
    spin_lock(&file->lock);
    if (--(file->ref_count) == 0) {
        spin_unlock(&file->lock);
        if (global_config.ncacheblock > 0) {
            // discard all dirty blocks belonged to this file
            bcache_remove_dirty_blocks(file);
        }

        spin_lock(&file->lock);
        if (wal_is_initialized(file)) {
            wal_close(file);
        }

        rv = file->ops->close(file->fd);
        if (file->status == FILE_REMOVED_PENDING) {
            if (rv != FDB_RESULT_SUCCESS) {
                char msg[1024];
                sprintf(msg, "Error in CLOSE on a database file '%s', ",
                        file->filename);
                _log_errno_str(file->ops, log_callback, msg, rv);
            }
            // remove file
            // we can release lock becuase no one will open this file
            spin_unlock(&file->lock);
            remove(file->filename);
            filemgr_remove_file(file);
            return (fdb_status) rv;
        } else {
            if (cleanup_cache_onclose) {
                if (rv != FDB_RESULT_SUCCESS) {
                    char msg[1024];
                    sprintf(msg, "Error in CLOSE on a database file '%s', ",
                            file->filename);
                    _log_errno_str(file->ops, log_callback, msg, rv);
                }
                // Clean up global hash table, WAL index, and buffer cache.
                // Then, retry it with a create option below.
                spin_unlock(&file->lock);
                filemgr_remove_file(file);
                return (fdb_status) rv;
            } else {
                file->status = FILE_CLOSED;
            }
        }
    }

    if (rv != FDB_RESULT_SUCCESS) {
        char msg[1024];
        sprintf(msg, "Error in CLOSE on a database file '%s', ", file->filename);
        _log_errno_str(file->ops, log_callback, msg, rv);
    }

    spin_unlock(&file->lock);
    return (fdb_status) rv;
}

static void _filemgr_free_func(struct hash_elem *h)
{
    struct filemgr *file = _get_entry(h, struct filemgr, e);

    // remove all cached blocks
    if (global_config.ncacheblock > 0) {
        bcache_remove_dirty_blocks(file);
        bcache_remove_clean_blocks(file);
        bcache_remove_file(file);
    }

    // destroy WAL
    if (wal_is_initialized(file)) {
        wal_shutdown(file);
        hash_free(&file->wal->hash_bykey);
#ifdef __FDB_SEQTREE
        hash_free(&file->wal->hash_byseq);
#endif
        spin_destroy(&file->wal->lock);
    }

    free(file->wal);

    // free filename and header
    free(file->filename);
    if (file->header.data) free(file->header.data);
    // free old filename if any
    free(file->old_filename);

    // destroy locks
    spin_destroy(&file->lock);
#ifdef __FILEMGR_MUTEX_LOCK
    mutex_destroy(&file->mutex);
#else
    spin_destroy(&file->mutex);
#endif

    // free file structure
    free(file);
}

// permanently remove file from cache (not just close)
void filemgr_remove_file(struct filemgr *file)
{
    assert(file);
    assert(file->ref_count <= 0);

    // remove from global hash table
    spin_lock(&filemgr_openlock);
    assert(hash_remove(&hash, &file->e));
    spin_unlock(&filemgr_openlock);

    _filemgr_free_func(&file->e);
}

void filemgr_shutdown()
{
    if (filemgr_initialized) {
        int i;

        spin_lock(&initial_lock);

        hash_free_active(&hash, _filemgr_free_func);
        if (global_config.ncacheblock > 0) {
            bcache_shutdown();
        }
        filemgr_initialized = 0;
        _filemgr_shutdown_temp_buf();

        spin_unlock(&initial_lock);
    }
}

bid_t filemgr_get_next_alloc_block(struct filemgr *file)
{
    spin_lock(&file->lock);
    bid_t bid = file->pos / file->blocksize;
    spin_unlock(&file->lock);
    return bid;
}

bid_t filemgr_alloc(struct filemgr *file, err_log_callback *log_callback)
{
    spin_lock(&file->lock);
    bid_t bid = file->pos / file->blocksize;
    file->pos += file->blocksize;

    if (global_config.ncacheblock <= 0) {
        // if block cache is turned off, write the allocated block before use
        uint8_t _buf = 0x0;
        ssize_t rv = file->ops->pwrite(file->fd, &_buf, 1, file->pos-1);
        if (rv < 0) {
            char msg[1024];
            sprintf(msg, "Error in WRITE on a database file '%s', ", file->filename);
            _log_errno_str(file->ops, log_callback, msg, (int) rv);
        }
    }
    spin_unlock(&file->lock);

    return bid;
}

void filemgr_alloc_multiple(struct filemgr *file, int nblock, bid_t *begin,
                            bid_t *end, err_log_callback *log_callback)
{
    spin_lock(&file->lock);
    *begin = file->pos / file->blocksize;
    *end = *begin + nblock - 1;
    file->pos += file->blocksize * nblock;

    if (global_config.ncacheblock <= 0) {
        // if block cache is turned off, write the allocated block before use
        uint8_t _buf = 0x0;
        ssize_t rv = file->ops->pwrite(file->fd, &_buf, 1, file->pos-1);
        if (rv < 0) {
            char msg[1024];
            sprintf(msg, "Error in WRITE on a database file '%s', ", file->filename);
            _log_errno_str(file->ops, log_callback, msg, (int) rv);
        }
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
    bid = file->pos / file->blocksize;
    if (bid == nextbid) {
        *begin = file->pos / file->blocksize;
        *end = *begin + nblock - 1;
        file->pos += file->blocksize * nblock;

        if (global_config.ncacheblock <= 0) {
            // if block cache is turned off, write the allocated block before use
            uint8_t _buf = 0x0;
            ssize_t rv = file->ops->pwrite(file->fd, &_buf, 1, file->pos-1);
            if (rv < 0) {
                char msg[1024];
                sprintf(msg, "Error in WRITE on a database file '%s', ", file->filename);
                _log_errno_str(file->ops, log_callback, msg, (int) rv);
            }
        }
    }else{
        *begin = BLK_NOT_FOUND;
        *end = BLK_NOT_FOUND;
    }
    spin_unlock(&file->lock);
    return bid;
}

#ifdef __CRC32
INLINE void _filemgr_crc32_check(struct filemgr *file, void *buf)
{
    if ( *((uint8_t*)buf + file->blocksize-1) == BLK_MARKER_BNODE ) {
        uint32_t crc_file, crc;
        memcpy(&crc_file, (uint8_t *) buf + BTREE_CRC_OFFSET, sizeof(crc_file));
        crc_file = _endian_decode(crc_file);
        memset((uint8_t *) buf + BTREE_CRC_OFFSET, 0xff, sizeof(void *));
        crc = crc32_8(buf, file->blocksize, 0);
        assert(crc == crc_file);
    }
}
#endif

void filemgr_invalidate_block(struct filemgr *file, bid_t bid)
{
    if (global_config.ncacheblock > 0) {
        bcache_invalidate_block(file, bid);
    }
}

void filemgr_read(struct filemgr *file, bid_t bid, void *buf,
                  err_log_callback *log_callback)
{
    ssize_t r;
    uint64_t pos = bid * file->blocksize;
    assert(pos < file->pos);

    if (global_config.ncacheblock > 0) {
        r = bcache_read(file, bid, buf);
        if (r == 0) {
            // cache miss
            if (file->status != FILE_COMPACT_OLD_SCAN) {
                // if normal file, just read a block
                r = file->ops->pread(file->fd, buf, file->blocksize, pos);
                if (r != file->blocksize) {
                    char msg[1024];
                    sprintf(msg, "Error in reading a database file '%s', ",
                            file->filename);
                    _log_errno_str(file->ops, log_callback, msg, (int) r);
                    // TODO: This function should return an appropriate fdb_status.
                    return;
                }
#ifdef __CRC32
                _filemgr_crc32_check(file, buf);
#endif

                bcache_write(file, bid, buf, BCACHE_REQ_CLEAN);
            } else {
                // if file is undergoing compaction, bulk read and bulk cache prefetch
                uint64_t pos_bulk;
                uint64_t count_bulk;
                uint64_t nblocks, i;
                void *bulk_buf;

                pos_bulk = (bid / FILEMGR_BULK_READ);
                pos_bulk *= FILEMGR_BULK_READ * file->blocksize;
                count_bulk = FILEMGR_BULK_READ * file->blocksize;
                if (pos_bulk + count_bulk > file->last_commit) {
                    count_bulk = file->last_commit - pos_bulk;
                }
                nblocks = count_bulk / file->blocksize;
                malloc_align(bulk_buf, FDB_SECTOR_SIZE, count_bulk);
                r = file->ops->pread(file->fd, bulk_buf, count_bulk, pos_bulk);
                if (r < 0) {
                    char msg[1024];
                    sprintf(msg, "Error in reading a database file '%s', ",
                            file->filename);
                    _log_errno_str(file->ops, log_callback, msg, (int) r);
                    free_align(bulk_buf);
                    return;
                }

                for (i=0;i<nblocks;++i){
                    bcache_write(file, pos_bulk / file->blocksize + i,
                                 (uint8_t *)bulk_buf + i*file->blocksize, BCACHE_REQ_CLEAN);
                }
                memcpy(buf, (uint8_t *)bulk_buf + (bid*file->blocksize - pos_bulk),
                       file->blocksize);

                free_align(bulk_buf);
            }
        }
    } else {
        r = file->ops->pread(file->fd, buf, file->blocksize, pos);
        if (r != file->blocksize) {
            char msg[1024];
            sprintf(msg, "Error in reading a database file '%s', ",
                    file->filename);
            _log_errno_str(file->ops, log_callback, msg, (int) r);
            return;
        }

#ifdef __CRC32
        _filemgr_crc32_check(file, buf);
#endif
    }
}

void filemgr_write_offset(struct filemgr *file, bid_t bid, uint64_t offset,
                          uint64_t len, void *buf, err_log_callback *log_callback)
{
    assert(offset + len <= file->blocksize);

    ssize_t r = 0;
    uint64_t pos = bid * file->blocksize + offset;
    assert(pos >= file->last_commit);

    if (global_config.ncacheblock > 0) {
        if (len == file->blocksize) {
            // write entire block .. we don't need to read previous block
            bcache_write(file, bid, buf, BCACHE_REQ_DIRTY);
        } else {
            // partially write buffer cache first
            r = bcache_write_partial(file, bid, buf, offset, len);
            if (r == 0) {
                // cache miss
                // write partially .. we have to read previous contents of the block
                void *_buf = _filemgr_get_temp_buf();

                r = file->ops->pread(file->fd, _buf, file->blocksize, bid * file->blocksize);
                memcpy((uint8_t *)_buf + offset, buf, len);
                bcache_write(file, bid, _buf, BCACHE_REQ_DIRTY);

                _filemgr_release_temp_buf(_buf);
            }
        }
    } else {

#ifdef __CRC32
        if (len == file->blocksize) {
            uint8_t marker = *((uint8_t*)buf + file->blocksize - 1);
            if (marker == BLK_MARKER_BNODE) {
                memset((uint8_t *)buf + BTREE_CRC_OFFSET, 0xff, sizeof(void *));
                uint32_t crc32 = crc32_8(buf, file->blocksize, 0);
                crc32 = _endian_encode(crc32);
                memcpy((uint8_t *)buf + BTREE_CRC_OFFSET, &crc32, sizeof(crc32));
            }
        }
#endif

        r = file->ops->pwrite(file->fd, buf, len, pos);
        if (r < 0) {
            char msg[1024];
            sprintf(msg, "Error in WRITE on a database file '%s', ", file->filename);
            _log_errno_str(file->ops, log_callback, msg, (int) r);
        }
        assert(r == len);

    }
}

void filemgr_write(struct filemgr *file, bid_t bid, void *buf,
                   err_log_callback *log_callback)
{
    filemgr_write_offset(file, bid, 0, file->blocksize, buf, log_callback);
}

int filemgr_is_writable(struct filemgr *file, bid_t bid)
{
    spin_lock(&file->lock);
    uint64_t pos = bid * file->blocksize;
    int cond = (pos >= file->last_commit && pos < file->pos);
    spin_unlock(&file->lock);

    return cond;
}

fdb_status filemgr_commit(struct filemgr *file,
                          err_log_callback *log_callback)
{
    uint16_t header_len = file->header.size;
    uint16_t _header_len;
    fdb_seqnum_t _seqnum;
    filemgr_header_revnum_t _revnum;
    int result = FDB_RESULT_SUCCESS;
    filemgr_magic_t magic = FILEMGR_MAGIC;
    filemgr_magic_t _magic;

    if (global_config.ncacheblock > 0) {
        bcache_flush(file);
    }

    spin_lock(&file->lock);

    if (file->header.size > 0 && file->header.data) {
        void *buf = _filemgr_get_temp_buf();
        uint8_t marker[BLK_MARKER_SIZE];

        // <-------------------------- block size --------------------------->
        // <-  len -><---  8 ---><-  8 ->             <-- 2 --><- 8 -><-  1 ->
        // [hdr data][hdr revnum][seqnum] ..(empty).. [hdr len][magic][marker]

        // header data
        memcpy(buf, file->header.data, header_len);
        // header rev number
        _revnum = _endian_encode(file->header.revnum);
        memcpy((uint8_t *)buf + header_len, &_revnum,
               sizeof(filemgr_header_revnum_t));
        // file's sequence number
        _seqnum = _endian_encode(file->header.seqnum);
        memcpy((uint8_t *)buf + header_len + sizeof(filemgr_header_revnum_t),
               &_seqnum, sizeof(fdb_seqnum_t));

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

        ssize_t rv = file->ops->pwrite(file->fd, buf, file->blocksize, file->pos);
        if (rv < 0) {
            char msg[1024];
            sprintf(msg, "Error in WRITE on a database file '%s', ", file->filename);
            _log_errno_str(file->ops, log_callback, msg, (int) rv);
        }
        file->pos += file->blocksize;

        _filemgr_release_temp_buf(buf);
    }
    // race condition?
    file->last_commit = file->pos;

    spin_unlock(&file->lock);

    if (file->fflags & FILEMGR_SYNC) {
        result = file->ops->fsync(file->fd);
        if (result != FDB_RESULT_SUCCESS) {
            char msg[1024];
            sprintf(msg, "Error in FSYNC on a database file '%s', ", file->filename);
            _log_errno_str(file->ops, log_callback, msg, result);
        }
    }
    return (fdb_status) result;
}

fdb_status filemgr_sync(struct filemgr *file, err_log_callback *log_callback)
{
    if (global_config.ncacheblock > 0) {
        bcache_flush(file);
    }

    int rv = file->ops->fsync(file->fd);
    if (rv != FDB_RESULT_SUCCESS) {
        char msg[1024];
        sprintf(msg, "Error in FSYNC on a database file '%s', ", file->filename);
        _log_errno_str(file->ops, log_callback, msg, rv);
    }
    return (fdb_status) rv;
}

int filemgr_update_file_status(struct filemgr *file, file_status_t status,
                                char *old_filename)
{
    int ret = 1;
    spin_lock(&file->lock);
    file->status = status;
    if (old_filename) {
        if (!file->old_filename) {
            file->old_filename = old_filename;
        } else {
            ret = 0;
            assert(file->ref_count);
            free(old_filename);
        }
    }
    spin_unlock(&file->lock);
    return ret;
}

void filemgr_set_compaction_old(struct filemgr *old_file, struct filemgr *new_file)
{
    assert(new_file);

    spin_lock(&old_file->lock);
    old_file->new_file = new_file;
    old_file->status = FILE_COMPACT_OLD;
    spin_unlock(&old_file->lock);
}

void filemgr_remove_pending(struct filemgr *old_file, struct filemgr *new_file)
{
    assert(new_file);

    spin_lock(&old_file->lock);
    if (old_file->ref_count > 0) {
        // delay removing
        old_file->new_file = new_file;
        old_file->status = FILE_REMOVED_PENDING;
        spin_unlock(&old_file->lock);
    }else{
        // immediatly remove
        spin_unlock(&old_file->lock);
        remove(old_file->filename);
        filemgr_remove_file(old_file);
    }
}

file_status_t filemgr_get_file_status(struct filemgr *file)
{
    spin_lock(&file->lock);
    file_status_t status = file->status;
    spin_unlock(&file->lock);
    return status;
}

uint64_t filemgr_get_pos(struct filemgr *file)
{
    spin_lock(&file->lock);
    uint64_t pos = file->pos;
    spin_unlock(&file->lock);
    return pos;
}

uint8_t filemgr_is_rollback_on(struct filemgr *file)
{
    return (file->fflags & FILEMGR_ROLLBACK_IN_PROG);
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

