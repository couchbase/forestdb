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

#ifdef _ASYNC_IO
#if !defined(WIN32) && !defined(_WIN32)
#include <libaio.h>
#include <sys/time.h>
#endif
#endif

#include "libforestdb/fdb_errors.h"

#include "internal_types.h"
#include "common.h"
#include "hash.h"
#include "partiallock.h"
#include "atomic.h"
#include "checksum.h"
#include "filemgr_ops.h"
#include "encryption.h"
#include "superblock.h"

#ifdef __cplusplus
extern "C" {
#endif

#define FILEMGR_SYNC 0x01
#define FILEMGR_READONLY 0x02
#define FILEMGR_ROLLBACK_IN_PROG 0x04
#define FILEMGR_CREATE 0x08
#define FILEMGR_REMOVAL_IN_PROG 0x10
#define FILEMGR_CREATE_CRC32 0x20 // Used in testing upgrade path
#define FILEMGR_CANCEL_COMPACTION 0x40 // Cancel the compaction

struct filemgr_config {
    int blocksize;
    int ncacheblock;
    int flag;
    int chunksize;
    uint8_t options;
    uint64_t prefetch_duration;
    uint16_t num_wal_shards;
    uint16_t num_bcache_shards;
    fdb_encryption_key encryption_key;
    // Stale block reusing threshold
    atomic_uint64_t block_reusing_threshold;
    // Number of the last commit headders whose stale blocks should
    // be kept for snapshot readers.
    atomic_uint64_t num_keeping_headers;
};

#ifndef _LATENCY_STATS
#define LATENCY_STAT_START()
#define LATENCY_STAT_END(file, type)
#else
#define LATENCY_STAT_START() \
     uint64_t begin=get_monotonic_ts();
#define LATENCY_STAT_END(file, type)\
    do {\
        uint64_t end = get_monotonic_ts();\
        filemgr_update_latency_stat(file, type, ts_diff(begin, end));} while(0)

struct latency_stat {
    atomic_uint32_t lat_min;
    atomic_uint32_t lat_max;
    atomic_uint64_t lat_sum;
    atomic_uint64_t lat_num;
};

#endif // _LATENCY_STATS

struct async_io_handle {
#ifdef _ASYNC_IO
#if !defined(WIN32) && !defined(_WIN32)
    struct iocb **ioq;
    struct io_event *events;
    io_context_t ioctx;
#endif
#endif
    uint8_t *aio_buf;
    uint64_t *offset_array;
    size_t queue_depth;
    size_t block_size;
    int fd;
};

typedef int filemgr_fs_type_t;
enum {
    FILEMGR_FS_NO_COW = 0x01,
    FILEMGR_FS_EXT4_WITH_COW = 0x02,
    FILEMGR_FS_BTRFS = 0x03
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
    struct kvs_ops_stat op_stat; // op stats for default KVS
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

typedef struct {
    mutex_t mutex;
    bool locked;
} mutex_lock_t;

struct filemgr {
    char *filename; // Current file name.
    uint32_t ref_count;
    uint8_t fflags;
    uint16_t filename_len;
    uint32_t blocksize;
    int fd;
    atomic_uint64_t pos;
    atomic_uint64_t last_commit;
    atomic_uint64_t last_commit_bmp_revnum;
    atomic_uint64_t num_invalidated_blocks;
    atomic_uint8_t io_in_prog;
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
    filemgr_fs_type_t fs_type;
    struct kvs_header *kv_header;
    void (*free_kv_header)(struct filemgr *file); // callback function
    atomic_uint32_t throttling_delay;

    // variables related to prefetching
    atomic_uint8_t prefetch_status;
    thread_t prefetch_tid;

    // File format version
    uint64_t version;

    // superblock
    struct superblock *sb;

#ifdef _LATENCY_STATS
    struct latency_stat lat_stats[FDB_LATENCY_NUM_STATS];
#endif //_LATENCY_STATS

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

    // mutex for synchronization among multiple writers.
    mutex_lock_t writer_lock;

    // CRC the file is using.
    crc_mode_e crc_mode;

    encryptor encryption;

    // temporary in-memory list of stale blocks
    struct list *stale_list;

    /**
     * Index for fdb_file_handle belonging to the same filemgr handle.
     */
    struct avl_tree fhandle_idx;
    /**
     * Spin lock for file handle index.
     */
    spin_t fhandle_idx_lock;
};

typedef fdb_status (*register_file_removal_func)(struct filemgr *file,
                                                 err_log_callback *log_callback);
typedef bool (*check_file_removal_func)(const char *filename);

typedef struct {
    struct filemgr *file;
    int rv;
} filemgr_open_result;

void filemgr_init(struct filemgr_config *config);
void filemgr_set_lazy_file_deletion(bool enable,
                                    register_file_removal_func regis_func,
                                    check_file_removal_func check_func);

/**
 * Assign superblock operations.
 *
 * @param ops Set of superblock operations to be assigned.
 * @return void.
 */
void filemgr_set_sb_operation(struct sb_ops ops);

uint64_t filemgr_get_bcache_used_space(void);

bool filemgr_set_kv_header(struct filemgr *file, struct kvs_header *kv_header,
                           void (*free_kv_header)(struct filemgr *file),
                           bool got_lock);

size_t filemgr_get_ref_count(struct filemgr *file);

INLINE void filemgr_incr_ref_count(struct filemgr *file) {
    spin_lock(&file->lock);
    ++file->ref_count;
    spin_unlock(&file->lock);
}

filemgr_open_result filemgr_open(char *filename,
                                 struct filemgr_ops *ops,
                                 struct filemgr_config *config,
                                 err_log_callback *log_callback);

uint64_t filemgr_update_header(struct filemgr *file,
                               void *buf,
                               size_t len,
                               bool inc_revnum);
filemgr_header_revnum_t filemgr_get_header_revnum(struct filemgr *file);

fdb_seqnum_t filemgr_get_seqnum(struct filemgr *file);
void filemgr_set_seqnum(struct filemgr *file, fdb_seqnum_t seqnum);

INLINE bid_t filemgr_get_header_bid(struct filemgr *file)
{
    return ((file->header.size > 0) ?
            atomic_get_uint64_t(&file->header.bid) : BLK_NOT_FOUND);
}
bid_t _filemgr_get_header_bid(struct filemgr *file);
void* filemgr_get_header(struct filemgr *file, void *buf, size_t *len,
                         bid_t *header_bid, fdb_seqnum_t *seqnum,
                         filemgr_header_revnum_t *header_revnum);

/**
 * Get the current bitmap revision number of superblock.
 *
 * @param file Pointer to filemgr handle.
 * @return Current bitmap revision number.
 */
uint64_t filemgr_get_sb_bmp_revnum(struct filemgr *file);

fdb_status filemgr_fetch_header(struct filemgr *file, uint64_t bid,
                                void *buf, size_t *len, fdb_seqnum_t *seqnum,
                                filemgr_header_revnum_t *header_revnum,
                                uint64_t *deltasize, uint64_t *version,
                                uint64_t *sb_bmp_revnum,
                                err_log_callback *log_callback);
uint64_t filemgr_fetch_prev_header(struct filemgr *file, uint64_t bid,
                                   void *buf, size_t *len, fdb_seqnum_t *seqnum,
                                   filemgr_header_revnum_t *revnum,
                                   uint64_t *deltasize, uint64_t *version,
                                   uint64_t *sb_bmp_revnum,
                                   err_log_callback *log_callback);
fdb_status filemgr_close(struct filemgr *file,
                         bool cleanup_cache_onclose,
                         const char *orig_file_name,
                         err_log_callback *log_callback);

void filemgr_remove_all_buffer_blocks(struct filemgr *file);
void filemgr_free_func(struct hash_elem *h);

INLINE bid_t filemgr_get_next_alloc_block(struct filemgr *file)
{
    return atomic_get_uint64_t(&file->pos) / file->blocksize;
}
bid_t filemgr_alloc(struct filemgr *file, err_log_callback *log_callback);
void filemgr_alloc_multiple(struct filemgr *file, int nblock, bid_t *begin,
                            bid_t *end, err_log_callback *log_callback);
bid_t filemgr_alloc_multiple_cond(struct filemgr *file, bid_t nextbid, int nblock,
                                  bid_t *begin, bid_t *end,
                                  err_log_callback *log_callback);

// Returns true if the block invalidated is from recent uncommited blocks
bool filemgr_invalidate_block(struct filemgr *file, bid_t bid);
bool filemgr_is_fully_resident(struct filemgr *file);
// returns number of immutable blocks that remain in file
uint64_t filemgr_flush_immutable(struct filemgr *file,
                                 err_log_callback *log_callback);

fdb_status filemgr_read(struct filemgr *file,
                        bid_t bid, void *buf,
                        err_log_callback *log_callback,
                        bool read_on_cache_miss);

fdb_status filemgr_write_offset(struct filemgr *file, bid_t bid, uint64_t offset,
                          uint64_t len, void *buf, bool final_write,
                          err_log_callback *log_callback);
fdb_status filemgr_write(struct filemgr *file, bid_t bid, void *buf,
                   err_log_callback *log_callback);
ssize_t filemgr_write_blocks(struct filemgr *file, void *buf, unsigned num_blocks, bid_t start_bid);
int filemgr_is_writable(struct filemgr *file, bid_t bid);

void filemgr_remove_file(struct filemgr *file);

INLINE void filemgr_set_io_inprog(struct filemgr *file)
{
    atomic_incr_uint8_t(&file->io_in_prog);
}

INLINE void filemgr_clear_io_inprog(struct filemgr *file)
{
    atomic_decr_uint8_t(&file->io_in_prog);
}

fdb_status filemgr_commit(struct filemgr *file, bool sync,
                          err_log_callback *log_callback);
/**
 * Commit DB file, and write a DB header at the given BID.
 *
 * @param file Pointer to filemgr handle.
 * @param bid ID of the block that DB header will be written. If this value is set to
 *        BLK_NOT_FOUND, then DB header is appended at the end of the file.
 * @param bmp_revnum Revision number of superblock's bitmap when this commit is called.
 * @param sync Flag for calling fsync().
 * @param log_callback Pointer to log callback function.
 * @return FDB_RESULT_SUCCESS on success.
 */
fdb_status filemgr_commit_bid(struct filemgr *file, bid_t bid,
                              uint64_t bmp_revnum, bool sync,
                              err_log_callback *log_callback);
fdb_status filemgr_sync(struct filemgr *file, bool sync_option,
                        err_log_callback *log_callback);

fdb_status filemgr_shutdown();
int filemgr_update_file_status(struct filemgr *file, file_status_t status,
                                char *old_filename);
void filemgr_set_compaction_state(struct filemgr *old_file,
                                  struct filemgr *new_file,
                                  file_status_t status);
void filemgr_remove_pending(struct filemgr *old_file,
                            struct filemgr *new_file,
                            err_log_callback *log_callback);

/**
 * Return name of the latency stat given its type.
 * @param stat The type of the latency stat to be named.
 */
const char *filemgr_latency_stat_name(fdb_latency_stat_type stat);

#ifdef _LATENCY_STATS
/**
 * Initialize a latency stats instance
 *
 * @param val Pointer to a latency stats instance to be initialized
 */
void filemgr_init_latency_stat(struct latency_stat *val);

/**
 * Destroy a latency stats instance
 *
 * @param val Pointer to a latency stats instance to be destroyed
 */
void filemgr_destroy_latency_stat(struct latency_stat *val);

/**
 * Migrate the latency stats from the source file to the destination file
 *
 * @param oldf Pointer to the source file manager
 * @param newf Pointer to the destination file manager
 */
void filemgr_migrate_latency_stats(struct filemgr *src,
                                   struct filemgr *dest);

/**
 * Update the latency stats for a given file manager
 *
 * @param file Pointer to the file manager whose latency stats need to be updated
 * @param type Type of a latency stat to be updated
 * @param val New value of a latency stat
 */
void filemgr_update_latency_stat(struct filemgr *file,
                                 fdb_latency_stat_type type,
                                 uint32_t val);

/**
 * Get the latency stats from a given file manager
 *
 * @param file Pointer to the file manager
 * @param type Type of a latency stat to be retrieved
 * @param stat Pointer to the stats instance to be populated
 */
void filemgr_get_latency_stat(struct filemgr *file,
                              fdb_latency_stat_type type,
                              fdb_latency_stat *stat);

#ifdef _LATENCY_STATS_DUMP_TO_FILE
/**
 * Write all the latency stats for a given file manager to a stat log file
 *
 * @param file Pointer to the file manager
 * @param log_callback Pointer to the log callback function
 */
void filemgr_dump_latency_stat(struct filemgr *file,
                               err_log_callback *log_callback);

#endif // _LATENCY_STATS_DUMP_TO_FILE
#endif // _LATENCY_STATS

struct kvs_ops_stat *filemgr_migrate_op_stats(struct filemgr *old_file,
                                              struct filemgr *new_file,
                                              struct kvs_info *kvs);
fdb_status filemgr_destroy_file(char *filename,
                                struct filemgr_config *config,
                                struct hash *destroy_set);

struct filemgr *filemgr_search_stale_links(struct filemgr *cur_file);
typedef char *filemgr_redirect_hdr_func(struct filemgr *old_file,uint8_t *buf,
                                        struct filemgr *new_file);

char *filemgr_redirect_old_file(struct filemgr *very_old_file,
                                struct filemgr *new_file,
                                filemgr_redirect_hdr_func redirect_func);
INLINE file_status_t filemgr_get_file_status(struct filemgr *file)
{
    return atomic_get_uint8_t(&file->status);
}
INLINE uint64_t filemgr_get_pos(struct filemgr *file)
{
    return atomic_get_uint64_t(&file->pos);
}

fdb_status filemgr_copy_file_range(struct filemgr *src_file,
                                   struct filemgr *dst_file,
                                   bid_t src_bid, bid_t dst_bid,
                                   bid_t clone_len);

bool filemgr_is_rollback_on(struct filemgr *file);
void filemgr_set_rollback(struct filemgr *file, uint8_t new_val);

/**
 * Set the file manager's flag to cancel the compaction task that is currently running.
 *
 * @param file Pointer to the file manager instance
 * @param cancel True if the compaction should be cancelled.
 */
void filemgr_set_cancel_compaction(struct filemgr *file, bool cancel);

/**
 * Return true if a compaction cancellation is requested.
 *
 * @param file Pointer to the file manager instance
 * @return True if a compaction cancellation is requested.
 */
bool filemgr_is_compaction_cancellation_requested(struct filemgr *file);

void filemgr_set_in_place_compaction(struct filemgr *file,
                                     bool in_place_compaction);
bool filemgr_is_in_place_compaction_set(struct filemgr *file);

void filemgr_mutex_openlock(struct filemgr_config *config);
void filemgr_mutex_openunlock(void);

void filemgr_mutex_lock(struct filemgr *file);
bool filemgr_mutex_trylock(struct filemgr *file);
void filemgr_mutex_unlock(struct filemgr *file);

void filemgr_set_dirty_root(struct filemgr *file,
                            bid_t dirty_idtree_root,
                            bid_t dirty_seqtree_root);
INLINE void filemgr_get_dirty_root(struct filemgr *file,
                                   bid_t *dirty_idtree_root,
                                   bid_t *dirty_seqtree_root)
{
    *dirty_idtree_root = atomic_get_uint64_t(&file->header.dirty_idtree_root);
    *dirty_seqtree_root = atomic_get_uint64_t(&file->header.dirty_seqtree_root);
}

INLINE bool filemgr_dirty_root_exist(struct filemgr *file)
{
    return (atomic_get_uint64_t(&file->header.dirty_idtree_root)  != BLK_NOT_FOUND ||
            atomic_get_uint64_t(&file->header.dirty_seqtree_root) != BLK_NOT_FOUND);
}

bool filemgr_is_commit_header(void *head_buffer, size_t blocksize);

bool filemgr_is_cow_supported(struct filemgr *src, struct filemgr *dst);

void filemgr_set_throttling_delay(struct filemgr *file, uint64_t delay_us);
uint32_t filemgr_get_throttling_delay(struct filemgr *file);

INLINE void filemgr_set_stale_list(struct filemgr *file,
                            struct list *stale_list)
{
    file->stale_list = stale_list;
}
void filemgr_clear_stale_list(struct filemgr *file);
INLINE struct list * filemgr_get_stale_list(struct filemgr *file)
{
    return file->stale_list;
}

/**
 * Add an item into stale-block list of the given 'file'.
 *
 * @param file Pointer to file handle.
 * @param pos Byte offset to the beginning of the stale region.
 * @param len Length of the stale region.
 * @return void.
 */
void filemgr_add_stale_block(struct filemgr *file,
                             bid_t pos,
                             size_t len);

/**
 * Calculate the actual space (including block markers) used for the given document
 * data, and return the list of regions to be marked as stale (if the given document
 * is not physically consecutive, more than one regions will be returned).
 *
 * @param file Pointer to file handle.
 * @param offset Byte offset to the beginning of the data.
 * @param length Length of the data.
 * @return List of stale regions.
 */
struct stale_regions filemgr_actual_stale_regions(struct filemgr *file,
                                                  bid_t offset,
                                                  size_t length);

/**
 * Mark the given region (offset, length) as stale.
 * This function automatically calculates the additional space used for block
 * markers or block matadata, by internally calling filemgr_actual_stale_regions().
 *
 * @param file Pointer to file handle.
 * @param offset Byte offset to the beginning of the data.
 * @param length Length of the data.
 * @return void.
 */
void filemgr_mark_stale(struct filemgr *file,
                        bid_t offset,
                        size_t length);

/**
 * The node structure of fhandle index.
 */
struct filemgr_fhandle_idx_node {
    /**
     * Void pointer to file handle.
     */
    void *fhandle;
    /**
     * AVL tree element.
     */
    struct avl_node avl;
};

/**
 * Add a FDB file handle into the superblock's global index.
 *
 * @param file Pointer to filemgr handle.
 * @param fhandle Pointer to FDB file handle.
 * @return True if successfully added.
 */
bool filemgr_fhandle_add(struct filemgr *file, void *fhandle);

/**
 * Remove a FDB file handle from the superblock's global index.
 *
 * @param file Pointer to filemgr handle.
 * @param fhandle Pointer to FDB file handle.
 * @return True if successfully removed.
 */
bool filemgr_fhandle_remove(struct filemgr *file, void *fhandle);

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
int _kvs_ops_stat_get_kv_header(struct kvs_header *kv_header,
                                fdb_kvs_id_t kv_id,
                                struct kvs_ops_stat *stat);
int _kvs_ops_stat_get(struct filemgr *file,
                      fdb_kvs_id_t kv_id,
                      struct kvs_ops_stat *stat);

void _init_op_stats(struct kvs_ops_stat *stat);
struct kvs_ops_stat *filemgr_get_ops_stats(struct filemgr *file,
                                          struct kvs_info *info);
#ifdef __cplusplus
}
#endif

#endif
