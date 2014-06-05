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

#ifndef _JSAHN_FILEMGR_H
#define _JSAHN_FILEMGR_H

#include <sys/types.h>
#include <sys/stat.h>
#include <stdint.h>

#include "libforestdb/fdb_errors.h"

#include "internal_types.h"
#include "common.h"
#include "hash.h"

#ifdef __cplusplus
extern "C" {
#endif

struct filemgr_config {
    int blocksize;
    int ncacheblock;
    int flag;
    uint8_t options;
#define FILEMGR_SYNC 0x01
#define FILEMGR_READONLY 0x02
#define FILEMGR_ROLLBACK_IN_PROG 0x04
#define FILEMGR_CREATE 0x08
};

struct filemgr_ops {
    int (*open)(const char *pathname, int flags, mode_t mode);
    ssize_t (*pwrite)(int fd, void *buf, size_t count, cs_off_t offset);
    ssize_t (*pread)(int fd, void *buf, size_t count, cs_off_t offset);
    int (*close)(int fd);
    cs_off_t (*goto_eof)(int fd);
    cs_off_t (*file_size)(const char *filename);
    int (*fdatasync)(int fd);
    int (*fsync)(int fd);
    void (*get_errno_str)(char *buf, size_t size);
};

struct filemgr_buffer{
    void *block;
    bid_t lastbid;
};

typedef uint16_t filemgr_header_len_t;
typedef uint64_t filemgr_magic_t;
typedef uint64_t filemgr_header_revnum_t;

struct filemgr_header{
    filemgr_header_len_t size;
    filemgr_header_revnum_t revnum;
    volatile fdb_seqnum_t seqnum;
    void *data;
};

struct wal;
struct fnamedic_item;
struct filemgr {
    char *filename;
    uint8_t ref_count;
    uint8_t fflags;
    uint16_t filename_len;
    uint32_t blocksize;
    int fd;
    uint64_t pos;
    uint64_t last_commit;
    struct wal *wal;
    struct filemgr_header header;
    struct filemgr_ops *ops;
    struct hash_elem e;
    file_status_t status;
    struct filemgr_config *config;
    struct filemgr *new_file;
    char *old_filename;
    struct fnamedic_item *bcache;
    fdb_txn global_txn;

    // spin lock for small region
    spin_t lock;
    // spin lock for race condition between separate writer
#ifdef __FILEMGR_MUTEX_LOCK
    mutex_t mutex;
#else
    spin_t mutex;
#endif
};

typedef struct {
    struct filemgr *file;
    int rv;
} filemgr_open_result;

void filemgr_init(struct filemgr_config *config);

size_t filemgr_get_ref_count(struct filemgr *file);
filemgr_open_result filemgr_open(char *filename,
                                 struct filemgr_ops *ops,
                                 struct filemgr_config *config,
                                 err_log_callback *log_callback);

uint64_t filemgr_update_header(struct filemgr *file, void *buf, size_t len);
filemgr_header_revnum_t filemgr_get_header_revnum(struct filemgr *file);

fdb_seqnum_t filemgr_get_seqnum(struct filemgr *file);
void filemgr_set_seqnum(struct filemgr *file, fdb_seqnum_t seqnum);

char* filemgr_get_filename_ptr(struct filemgr *file, char **filename, uint16_t *len);

void* filemgr_fetch_header(struct filemgr *file, void *buf, size_t *len);
uint64_t filemgr_fetch_prev_header(struct filemgr *file, uint64_t bid,
                                   void *buf, size_t *len, fdb_seqnum_t *seqnum,
                                   err_log_callback *log_callback);

fdb_status filemgr_close(struct filemgr *file,
                         bool cleanup_cache_onclose,
                         err_log_callback *log_callback);

bid_t filemgr_get_next_alloc_block(struct filemgr *file);
bid_t filemgr_alloc(struct filemgr *file, err_log_callback *log_callback);
void filemgr_alloc_multiple(struct filemgr *file, int nblock, bid_t *begin,
                            bid_t *end, err_log_callback *log_callback);
bid_t filemgr_alloc_multiple_cond(struct filemgr *file, bid_t nextbid, int nblock,
                                  bid_t *begin, bid_t *end,
                                  err_log_callback *log_callback);

void filemgr_invalidate_block(struct filemgr *file, bid_t bid);

void filemgr_read(struct filemgr *file,
                  bid_t bid, void *buf,
                  err_log_callback *log_callback);

void filemgr_write_offset(struct filemgr *file, bid_t bid, uint64_t offset,
                          uint64_t len, void *buf, err_log_callback *log_callback);
void filemgr_write(struct filemgr *file, bid_t bid, void *buf,
                   err_log_callback *log_callback);
int filemgr_is_writable(struct filemgr *file, bid_t bid);
void filemgr_remove_file(struct filemgr *file);

fdb_status filemgr_commit(struct filemgr *file,
                          err_log_callback *log_callback);
fdb_status filemgr_sync(struct filemgr *file,
                        err_log_callback *log_callback);

void filemgr_shutdown();
int filemgr_update_file_status(struct filemgr *file, file_status_t status,
                                char *old_filename);
void filemgr_set_compaction_old(struct filemgr *old_file, struct filemgr *new_file);
void filemgr_remove_pending(struct filemgr *old_file, struct filemgr *new_file);
file_status_t filemgr_get_file_status(struct filemgr *file);
uint64_t filemgr_get_pos(struct filemgr *file);

uint8_t filemgr_is_rollback_on(struct filemgr *file);
void filemgr_set_rollback(struct filemgr *file, uint8_t new_val);

void filemgr_mutex_lock(struct filemgr *file);
void filemgr_mutex_unlock(struct filemgr *file);

#ifdef __cplusplus
}
#endif

#endif
