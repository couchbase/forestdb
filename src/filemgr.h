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

#include "libforestdb/forestdb_types.h"

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
#define FILEMGR_ASYNC 0x01
#define FILEMGR_READONLY 0x02
};

struct filemgr_ops {
    int (*open)(const char *pathname, int flags, mode_t mode);
    ssize_t (*pwrite)(int fd, void *buf, size_t count, cs_off_t offset);
    ssize_t (*pread)(int fd, void *buf, size_t count, cs_off_t offset);
    fdb_status (*close)(int fd);
    cs_off_t (*goto_eof)(int fd);
    cs_off_t (*file_size)(const char *filename);
    fdb_status (*fdatasync)(int fd);
    fdb_status (*fsync)(int fd);
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
    void *data;
};

struct wal;
struct fnamedic_item;
struct filemgr {
    char *filename;
    uint8_t ref_count;
    uint8_t sync;
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

    // spin lock for small region
    spin_t lock;
    // spin lock for race condition between separate writer
#ifdef __FILEMGR_MUTEX_LOCK
    mutex_t mutex;
#else
    spin_t mutex;
#endif
};

struct filemgr * filemgr_open(char *filename, struct filemgr_ops *ops, struct filemgr_config *config);

uint64_t filemgr_update_header(struct filemgr *file, void *buf, size_t len);
filemgr_header_revnum_t filemgr_get_header_revnum(struct filemgr *file);
char* filemgr_get_filename_ptr(struct filemgr *file, char **filename, uint16_t *len);

void* filemgr_fetch_header(struct filemgr *file, void *buf, size_t *len);

fdb_status filemgr_close(struct filemgr *file);

bid_t filemgr_get_next_alloc_block(struct filemgr *file);
bid_t filemgr_alloc(struct filemgr *file);
void filemgr_alloc_multiple(struct filemgr *file, int nblock, bid_t *begin, bid_t *end);
bid_t filemgr_alloc_multiple_cond(
    struct filemgr *file, bid_t nextbid, int nblock, bid_t *begin, bid_t *end);

void filemgr_invalidate_block(struct filemgr *file, bid_t bid);
void filemgr_read(struct filemgr *file, bid_t bid, void *buf);
void filemgr_write_offset(struct filemgr *file, bid_t bid, uint64_t offset, uint64_t len, void *buf);
void filemgr_write(struct filemgr *file, bid_t bid, void *buf);
int filemgr_is_writable(struct filemgr *file, bid_t bid);
void filemgr_remove_file(struct filemgr *file);
fdb_status filemgr_commit(struct filemgr *file);
fdb_status filemgr_sync(struct filemgr *file);
void filemgr_shutdown();
int filemgr_update_file_status(struct filemgr *file, file_status_t status,
                                char *old_filename);
void filemgr_set_compaction_old(struct filemgr *old_file, struct filemgr *new_file);
void filemgr_remove_pending(struct filemgr *old_file, struct filemgr *new_file);
file_status_t filemgr_get_file_status(struct filemgr *file);
uint64_t filemgr_get_pos(struct filemgr *file);

void filemgr_mutex_lock(struct filemgr *file);
void filemgr_mutex_unlock(struct filemgr *file);

#ifdef __cplusplus
}
#endif

#endif
