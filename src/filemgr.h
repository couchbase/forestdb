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
#include "partiallock.h"
#include "atomic.h"

#ifdef __cplusplus
extern "C" {
#endif

struct filemgr_config {
    int blocksize;
    int ncacheblock;
    int flag;
    int chunksize;
    uint8_t options;
#define FILEMGR_SYNC 0x01
#define FILEMGR_READONLY 0x02
#define FILEMGR_ROLLBACK_IN_PROG 0x04
#define FILEMGR_CREATE 0x08
    uint64_t prefetch_duration;
    uint16_t num_wal_shards;
    uint16_t num_bcache_shards;
};

typedef void* voidref;
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
    voidref (*mmap)(int fd, size_t length, void **aux);
    int (*munmap)(void *addr, size_t length, void *aux);
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
    atomic_uint64_t bid;
    atomic_uint64_t dirty_idtree_root; // for wal_flush_before_commit option
    atomic_uint64_t dirty_seqtree_root; // for wal_flush_before_commit option
    struct kvs_stat stat; // stats for the default KVS
    void *data;
};

typedef uint8_t filemgr_prefetch_status_t;
enum {
    FILEMGR_PREFETCH_IDLE = 0,
    FILEMGR_PREFETCH_RUNNING = 1,
    FILEMGR_PREFETCH_ABORT = 2
};

#define DLOCK_MAX (41) /* a prime number */
struct wal;
struct fnamedic_item;
struct kvs_header;
struct filemgr {
    char *filename; // Current file name.
    uint32_t ref_count;
    uint8_t fflags;
    uint16_t filename_len;
    uint32_t blocksize;
    int fd;
    atomic_uint64_t pos;
    atomic_uint64_t last_commit;
    struct wal *wal;
    struct filemgr_header header;
    struct filemgr_ops *ops;
    struct hash_elem e;
    atomic_uint8_t status;
    struct filemgr_config *config;
    struct filemgr *new_file;
    char *old_filename; // Old file name before compaction.
    struct fnamedic_item *bcache;
    fdb_txn global_txn;
    bool in_place_compaction;
    struct kvs_header *kv_header;
    void (*free_kv_header)(struct filemgr *file); // callback function

    // variables related to prefetching
    volatile filemgr_prefetch_status_t prefetch_status;
    thread_t prefetch_tid;

    // list for mmapped files
    struct list keystr_files;
    uint32_t n_keystr_files;

    // spin lock for small region
    spin_t lock;

    // lock for data consistency
#ifdef __FILEMGR_DATA_PARTIAL_LOCK
    struct plock plock;
#elif defined(__FILEMGR_DATA_MUTEX_LOCK)
    mutex_t data_mutex[DLOCK_MAX];
#else
    spin_t data_spinlock[DLOCK_MAX];
#endif //__FILEMGR_DATA_PARTIAL_LOCK

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

INLINE bid_t filemgr_get_header_bid(struct filemgr *file)
{
    return ((file->header.size > 0) ? file->header.bid.val : BLK_NOT_FOUND);
}
bid_t _filemgr_get_header_bid(struct filemgr *file);
void* filemgr_get_header(struct filemgr *file, void *buf, size_t *len);
fdb_status filemgr_fetch_header(struct filemgr *file, uint64_t bid, void *buf,
                           size_t *len, err_log_callback *log_callback);
uint64_t filemgr_fetch_prev_header(struct filemgr *file, uint64_t bid,
                                   void *buf, size_t *len, fdb_seqnum_t *seqnum,
                                   err_log_callback *log_callback);
fdb_status filemgr_close(struct filemgr *file,
                         bool cleanup_cache_onclose,
                         const char *orig_file_name,
                         err_log_callback *log_callback);

INLINE bid_t filemgr_get_next_alloc_block(struct filemgr *file)
{
    return file->pos.val / file->blocksize;
}
bid_t filemgr_alloc(struct filemgr *file, err_log_callback *log_callback);
void filemgr_alloc_multiple(struct filemgr *file, int nblock, bid_t *begin,
                            bid_t *end, err_log_callback *log_callback);
bid_t filemgr_alloc_multiple_cond(struct filemgr *file, bid_t nextbid, int nblock,
                                  bid_t *begin, bid_t *end,
                                  err_log_callback *log_callback);

void filemgr_invalidate_block(struct filemgr *file, bid_t bid);

fdb_status filemgr_read(struct filemgr *file,
                  bid_t bid, void *buf,
                  err_log_callback *log_callback);

fdb_status filemgr_write_offset(struct filemgr *file, bid_t bid, uint64_t offset,
                          uint64_t len, void *buf, err_log_callback *log_callback);
fdb_status filemgr_write(struct filemgr *file, bid_t bid, void *buf,
                   err_log_callback *log_callback);
INLINE int filemgr_is_writable(struct filemgr *file, bid_t bid)
{
    uint64_t pos = bid * file->blocksize;
    // Note that we don't need to grab file->lock here because
    // 1) both file->pos and file->last_commit are only incremented.
    // 2) file->last_commit is updated using the value of file->pos,
    //    and always equal to or smaller than file->pos.
    return (pos <  file->pos.val &&
            pos >= file->last_commit.val);
}
void filemgr_remove_file(struct filemgr *file);

fdb_status filemgr_commit(struct filemgr *file,
                          err_log_callback *log_callback);
fdb_status filemgr_sync(struct filemgr *file,
                        err_log_callback *log_callback);

void filemgr_shutdown();
int filemgr_update_file_status(struct filemgr *file, file_status_t status,
                                char *old_filename);
void filemgr_set_compaction_state(struct filemgr *old_file,
                                  struct filemgr *new_file,
                                  file_status_t status);
void filemgr_remove_pending(struct filemgr *old_file, struct filemgr *new_file);
fdb_status filemgr_destroy_file(char *filename,
                                struct filemgr_config *config,
                                struct hash *destroy_set);

struct filemgr *filemgr_search_stale_links(struct filemgr *cur_file);
typedef char *filemgr_redirect_hdr_func(uint8_t *buf, char *new_filename,
                                       uint16_t new_filename_len);
char *filemgr_redirect_old_file(struct filemgr *very_old_file,
                                struct filemgr *new_file,
                                filemgr_redirect_hdr_func redirect_func);
INLINE file_status_t filemgr_get_file_status(struct filemgr *file)
{
    return file->status.val;
}
INLINE uint64_t filemgr_get_pos(struct filemgr *file)
{
    return file->pos.val;
}

bool filemgr_is_rollback_on(struct filemgr *file);
void filemgr_set_rollback(struct filemgr *file, uint8_t new_val);

void filemgr_set_in_place_compaction(struct filemgr *file,
                                     bool in_place_compaction);

void filemgr_mutex_openlock(struct filemgr_config *config);
void filemgr_mutex_openunlock(void);
void filemgr_mutex_lock(struct filemgr *file);
void filemgr_mutex_unlock(struct filemgr *file);

void filemgr_set_dirty_root(struct filemgr *file,
                            bid_t dirty_idtree_root,
                            bid_t dirty_seqtree_root);
INLINE void filemgr_get_dirty_root(struct filemgr *file,
                                   bid_t *dirty_idtree_root,
                                   bid_t *dirty_seqtree_root)
{
    *dirty_idtree_root = file->header.dirty_idtree_root.val;
    *dirty_seqtree_root = file->header.dirty_seqtree_root.val;
}

INLINE bool filemgr_dirty_root_exist(struct filemgr *file)
{
    return (file->header.dirty_idtree_root.val  != BLK_NOT_FOUND ||
            file->header.dirty_seqtree_root.val != BLK_NOT_FOUND);
}

void *filemgr_add_keystr_file(struct filemgr *file, uint64_t size);
void filemgr_remove_keystr_files(struct filemgr *file);
void filemgr_scan_remove_keystr_files(struct filemgr *file);

void _kvs_stat_set(struct filemgr *file,
                   fdb_kvs_id_t kv_id,
                   struct kvs_stat stat);
void _kvs_stat_update_attr(struct filemgr *file,
                           fdb_kvs_id_t kv_id,
                           kvs_stat_attr_t attr,
                           int delta);
int _kvs_stat_get_kv_header(struct kvs_header *kv_header,
                            fdb_kvs_id_t kv_id,
                            struct kvs_stat *stat);
int _kvs_stat_get(struct filemgr *file,
                  fdb_kvs_id_t kv_id,
                  struct kvs_stat *stat);
uint64_t _kvs_stat_get_sum(struct filemgr *file,
                           kvs_stat_attr_t attr);

#ifdef __cplusplus
}
#endif

#endif
