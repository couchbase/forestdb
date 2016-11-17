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

#ifndef _FDB_TYPES_H
#define _FDB_TYPES_H

#include "fdb_errors.h"

#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>
#ifndef _MSC_VER
#include <stdbool.h>
#else
#ifndef __cplusplus
#pragma once
#define false (0)
#define true (1)
#define bool int
#endif
#endif

/**
 * Maximum key length supported.
 */
#define FDB_MAX_KEYLEN (65408) // 2^16 - 64*2 (64: max chunk size)
/**
 * Maximum metadata length supported.
 */
#define FDB_MAX_METALEN (65535UL) // 2^16 - 1
/**
 * Maximum value length supported.
 */
#define FDB_MAX_BODYLEN (4294967295UL) // 2^32 - 1

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Flags to be passed to fdb_open() API
 */
typedef uint32_t fdb_open_flags;
enum {
    /**
     * Open a ForestDB file with read-write mode and
     * create a new empty ForestDB file if it doesn't exist.
     */
    FDB_OPEN_FLAG_CREATE = 1,
    /**
     * Open a ForestDB file in read only mode, but
     * return an error if a file doesn't exist.
     */
    FDB_OPEN_FLAG_RDONLY = 2,

    /**
     * Open a ForestDB file with legacy CRC.
     *
     * This flag is intended to be used by upgrade tests.
     *
     * This flag is only valid if the file to be opened is a new file or an
     * existing file with legacy CRC.
     *
     * Opening existing files which use CRC32C with this flag results
     * in FDB_RESULT_INVALID_ARGS.
     */
    FDB_OPEN_WITH_LEGACY_CRC = 4
};

/**
 * Options to be passed to fdb_commit() API.
 * Combinational options can be possible.
 */
typedef uint8_t fdb_commit_opt_t;
enum {
    /**
     * Perform commit without any options.
     */
    FDB_COMMIT_NORMAL = 0x00,
    /**
     * Manually flush WAL entries even though it doesn't
     * reach the configured threshold
     */
    FDB_COMMIT_MANUAL_WAL_FLUSH = 0x01
};

/**
 * Flag to enable / disable a sequence btree.
 */
typedef uint8_t fdb_seqtree_opt_t;
enum {
    FDB_SEQTREE_NOT_USE = 0,
    FDB_SEQTREE_USE = 1
};

/**
 * Durability options for ForestDB.
 */
typedef uint8_t fdb_durability_opt_t;
enum {
    /**
     * Synchronous commit through OS page cache.
     */
    FDB_DRB_NONE = 0x0,
    /**
     * Synchronous commit through the direct IO option to bypass
     * the OS page cache.
     */
    FDB_DRB_ODIRECT = 0x1,
    /**
     * Asynchronous commit through OS page cache.
     */
    FDB_DRB_ASYNC = 0x2,
    /**
     * Asynchronous commit through the direct IO option to bypass
     * the OS page cache.
     */
    FDB_DRB_ODIRECT_ASYNC = 0x3
};

/**
 * Options for compaction mode.
 */
typedef uint8_t fdb_compaction_mode_t;
enum {
    FDB_COMPACTION_MANUAL = 0,
    FDB_COMPACTION_AUTO = 1
};

/**
 * Transaction isolation level.
 * Note that both serializable and repeatable-read isolation levels are not
 * supported at this moment. We plan to support them in the future releases.
 */
typedef uint8_t fdb_isolation_level_t;
enum {
    // FDB_ISOLATION_SERIALIZABLE = 0,
    // FDB_ISOLATION_REPEATABLE_READ = 1,
    /**
     * Prevent a transaction from reading uncommitted data from other
     * transactions.
     */
    FDB_ISOLATION_READ_COMMITTED = 2,
    /**
     * Allow a transaction to see uncommitted data from other transaction.
     */
    FDB_ISOLATION_READ_UNCOMMITTED = 3
};

/**
 * Pointer type definition of a customized compare function for fixed size key.
 */
typedef int (*fdb_custom_cmp_fixed)(void *a, void *b);

/**
 * Pointer type definition of a customized compare function for variable length key.
 */
typedef int (*fdb_custom_cmp_variable)(void *a, size_t len_a,
                                       void *b, size_t len_b);

typedef uint64_t fdb_seqnum_t;
#define FDB_SNAPSHOT_INMEM ((fdb_seqnum_t)(-1))

/**
 * ForestDB doc structure definition
 */
typedef struct fdb_doc_struct {
    /**
     * key length.
     */
    size_t keylen;
    /**
     * metadata length.
     */
    size_t metalen;
    /**
     * doc body length.
     */
    size_t bodylen;
    /**
     * actual doc size written on disk.
     */
    size_t size_ondisk;
    /**
     * Pointer to doc's key.
     */
    void *key;
    /**
     * Sequence number assigned to a doc.
     */
    fdb_seqnum_t seqnum;
    /**
     * Offset to the doc (header + key + metadata + body) on disk.
     */
    uint64_t offset;
    /**
     * Pointer to doc's metadata.
     */
    void *meta;
    /**
     * Pointer to doc's body.
     */
    void *body;
    /**
     * Is a doc deleted?
     */
    bool deleted;
    /**
     * Flags for miscellaneous doc properties.
     */
     uint32_t flags;
    /**
     * Use the seqnum set by user instead of auto-generating.
     */
#define FDB_CUSTOM_SEQNUM 0x01
} fdb_doc;

/**
 * Opaque reference to a ForestDB file handle, which is exposed in public APIs.
 */
typedef struct FdbFileHandle fdb_file_handle;

/**
 * Opaque reference to a ForestDB KV store handle, which is exposed in public APIs.
 */
typedef struct FdbKvsHandle fdb_kvs_handle;

/**
 * Compaction status for callback function.
 */
typedef uint32_t fdb_compaction_status;
enum {
    FDB_CS_BEGIN = 0x1,
    FDB_CS_MOVE_DOC = 0x2,
    FDB_CS_BATCH_MOVE = 0x4,
    FDB_CS_FLUSH_WAL = 0x8,
    FDB_CS_END = 0x10, // invoked at the end of every phase of compaction
    FDB_CS_COMPLETE = 0x20 // invoked on completion of compaction
};

/**
 * Compaction decision returned if FDB_CS_MOVE_DOC callback option is used.
 * If this compaction callback option is used then it is upto its corresponding
 * callback function to specify, using the given return values below, if a
 * given document should be retained in the newly compacted file or dropped.
 */
typedef int fdb_compact_decision;
enum {
    FDB_CS_KEEP_DOC = 0x0,
    FDB_CS_DROP_DOC = 0x1
};

/**
 * Pointer type definition of a callback function for compaction.
 */
typedef fdb_compact_decision (*fdb_compaction_callback)(
                               fdb_file_handle *fhandle,
                               fdb_compaction_status status,
                               const char *kv_store_name,
                               fdb_doc *doc,
                               uint64_t last_oldfile_offset,
                               uint64_t last_newfile_offset,
                               void *ctx);

/**
  * Encryption algorithms known to ForestDB.
  */
typedef int fdb_encryption_algorithm_t;
enum {
    FDB_ENCRYPTION_NONE = 0,    /**< No encryption (default) */
    FDB_ENCRYPTION_AES256 = 1   /**< AES with 256-bit key */
};

/**
  * File encryption key.
  */
typedef struct {
    fdb_encryption_algorithm_t algorithm;
    uint8_t bytes[32];
} fdb_encryption_key;

/**
 * Using off_t turned out to be a real challenge. On "unix-like" systems
 * its size is set by a combination of #defines like: _LARGE_FILE,
 * _FILE_OFFSET_BITS and/or _LARGEFILE_SOURCE etc. The interesting
 * part is however Windows.
 *
 * Windows follows the LLP64 data model:
 * http://en.wikipedia.org/wiki/LLP64#64-bit_data_models
 *
 * This means both the int and long int types have a size of 32 bits
 * regardless if it's a 32 or 64 bits Windows system.
 *
 * And Windows defines the type off_t as being a signed long integer:
 * http://msdn.microsoft.com/en-us/library/323b6b3k.aspx
 *
 * This means we can't use off_t on Windows if we deal with files
 * that can have a size of 2Gb or more.
 */
typedef int64_t cs_off_t;

struct async_io_handle;

/**
 * An opaque structure that is passed to the filemgr_ops.
 * The structure will possess all the context that an external
 * client requires for performing custom operations in their
 * respective callbacks
 */
typedef struct fdb_fileops_handle_opaque* fdb_fileops_handle;

#ifdef _MSC_VER
    typedef unsigned long mode_t;
    #include <BaseTsd.h>
#ifdef _PLATFORM_LIB_AVAILABLE
    typedef long fdb_ssize_t;
#else
    typedef SSIZE_T fdb_ssize_t;
#endif // _PLATFORM_LIB_AVAILABLE
#else
    typedef ssize_t fdb_ssize_t;
#endif

typedef void* voidref;
/**
 * This structure can be used to perform custom operations by
 * the external client before performing a file operation on
 * a forestdb file.
 *
 * An example usage of the open API is given below
 *
 * fdb_status client_open(const char* pathname, fdb_fileops_handle* fops_handle,
 *                        int flags, mode_t mode) {
 *     ClientObject* clObj = reinterpret_cast<ClientObject *>(*fops_handle);
 *     return clObj->original_fdb_ops->open(pathname,
 *                                          &clObj->original_fdb_handle,
 *                                          flags, mode);
 * }
 */
typedef struct filemgr_ops {
    fdb_fileops_handle (*constructor)(void *ctx);
    fdb_status (*open)(const char *pathname, fdb_fileops_handle *fops_handle,
                       int flags, mode_t mode);
    fdb_ssize_t (*pwrite)(fdb_fileops_handle fops_handle, void *buf, size_t count,
                          cs_off_t offset);
    fdb_ssize_t (*pread)(fdb_fileops_handle fops_handle, void *buf, size_t count,
                         cs_off_t offset);
    int (*close)(fdb_fileops_handle fops_handle);
    cs_off_t (*goto_eof)(fdb_fileops_handle fops_handle);
    cs_off_t (*file_size)(fdb_fileops_handle fops_handle,
                          const char *filename);
    int (*fdatasync)(fdb_fileops_handle fops_handle);
    int (*fsync)(fdb_fileops_handle fops_handle);
    void (*get_errno_str)(fdb_fileops_handle fops_handle, char *buf, size_t size);
    voidref (*mmap)(fdb_fileops_handle fops_handle, size_t length, void **aux);
    int (*munmap)(fdb_fileops_handle fops_handle, void *addr, size_t length, void *aux);

    // Async I/O operations
    int (*aio_init)(fdb_fileops_handle fops_handle, struct async_io_handle *aio_handle);
    int (*aio_prep_read)(fdb_fileops_handle fops_handle,
                         struct async_io_handle *aio_handle, size_t aio_idx,
                         size_t read_size, uint64_t offset);
    int (*aio_submit)(fdb_fileops_handle fops_handle,
                      struct async_io_handle *aio_handle, int num_subs);
    int (*aio_getevents)(fdb_fileops_handle fops_handle,
                         struct async_io_handle *aio_handle, int min,
                         int max, unsigned int timeout);
    int (*aio_destroy)(fdb_fileops_handle fops_handle,
                       struct async_io_handle *aio_handle);

    int (*get_fs_type)(fdb_fileops_handle src_fd);
    int (*copy_file_range)(int fs_type, fdb_fileops_handle src_fops_handle,
                           fdb_fileops_handle dst_fops_handle, uint64_t src_off,
                           uint64_t dst_off, uint64_t len);
    void (*destructor)(fdb_fileops_handle fops_handle);
    void *ctx;
} fdb_filemgr_ops_t;

/**
 * ForestDB config options that are passed to fdb_open API.
 */
typedef struct {
    /**
     * Chunk size (bytes) that is used to build B+-tree at each level.
     * It is set to 8 bytes by default and has a min value of 4 bytes
     * and a max value of 64 bytes.
     * This is a local config to each ForestDB file.
     */
    uint16_t chunksize;
    /**
     * Size of block that is a unit of IO operations.
     * It is set to 4KB by default and has a min value of 1KB and a max value of
     * 128KB. This is a global config that is used across all ForestDB files.
     */
    uint32_t blocksize;
    /**
     * Buffer cache size in bytes. If the size is set to zero, then the buffer
     * cache is disabled. This is a global config that is used across all
     * ForestDB files.
     */
    uint64_t buffercache_size;
    /**
     * WAL index size threshold in memory (4096 entries by default).
     * This is a local config to each ForestDB file.
     */
    uint64_t wal_threshold;
    /**
     * Flag to enable flushing the WAL whenever it reaches its threshold size.
     * This reduces memory usage when a lot of data is written before a commit.
     */
    bool wal_flush_before_commit;
    /**
     * Flag to enable automatic commit.
     * This is a local config to each ForestDB file.
     */
    bool auto_commit;
    /**
     * Interval for purging logically deleted documents in the unit of second.
     * It is set to 0 second (purge during next compaction) by default.
     * This is a local config to each ForestDB file.
     */
    uint32_t purging_interval;
    /**
     * Flag to enable or disable a sequence B+-Tree.
     * This is a local config to each ForestDB file.
     */
    fdb_seqtree_opt_t seqtree_opt;
    /**
     * Flag to enable synchronous or asynchronous commit options.
     * This is a local config to each ForestDB file.
     */
    fdb_durability_opt_t durability_opt;
    /**
     * Flags for fdb_open API. It can be used for specifying read-only mode.
     * This is a local config to each ForestDB file.
     */
    fdb_open_flags flags;
    /**
     * Maximum size (bytes) of temporary buffer for compaction (4MB by default).
     * This is a local config to each ForestDB file.
     */
    uint32_t compaction_buf_maxsize;
    /**
     * Destroy all the cached blocks in the global buffer cache when a ForestDB
     * file is closed. It is set to true by default. This is a global config
     * that is used across all ForestDB files.
     */
    bool cleanup_cache_onclose;
    /**
     * Compress the body of document when it is written on disk. The compression
     * is disabled by default. This is a global config that is used across all
     * ForestDB files.
     */
    bool compress_document_body;
    /**
     * Flag to enable auto compaction for the file. The auto compaction is disabled
     * by default.
     * This is a local config to each ForestDB file.
     */
    fdb_compaction_mode_t compaction_mode;
    /**
     * Compaction threshold in the unit of percentage (%). It can be calculated
     * as '(stale data size)/(total file size)'. The compaction daemon triggers
     * compaction if this threshold is satisfied.
     * Compaction will not be performed when this value is set to zero or 100.
     * This is a local config to each ForestDB file.
     */
    uint8_t compaction_threshold;
    /**
     * The minimum filesize to perform compaction.
     * This is a local config to each ForestDB file.
     */
    uint64_t compaction_minimum_filesize;
    /**
     * Duration that the compaction daemon task periodically wakes up, in the unit of
     * second. This is a local config that can be configured per file.
     * If the daemon compaction interval for a given file needs to be adjusted, then
     * fdb_set_daemon_compaction_interval API can be used.
     */
    uint64_t compactor_sleep_duration;
    /**
     * Flag to enable supporting multiple KV instances in a DB instance.
     * This is a global config that is used across all ForestDB files.
     */
    bool multi_kv_instances;
    /**
     * Duration that prefetching of DB file will be performed when the file
     * is opened, in the unit of second. If the duration is set to zero,
     * prefetching is disabled. This is a local config to each ForestDB file.
     */
    uint64_t prefetch_duration;
    /**
     * Number of in-memory WAL index partitions for a DB file.
     * This is a local config to each ForestDB file.
     */
    uint16_t num_wal_partitions;
    /**
     * Number of buffer cache partitions for each DB file.
     * This is a local config to each ForestDB file.
     */
    uint16_t num_bcache_partitions;
    /**
     * Callback function for compaction.
     * This is a local config to each ForestDB file.
     */
    fdb_compaction_callback compaction_cb;
    /**
     * Mask to select when to invoke callback function during compaction.
     * Note that mask value is a combination of flags defined in
     * fdb_compaction_status.
     * This is a local config to each ForestDB file.
     */
    uint32_t compaction_cb_mask;
    /**
     * Auxiliary data for compaction callback function.
     * This is a local config to each ForestDB file.
     */
    void *compaction_cb_ctx;
    /**
     * Maximum probability (range: 20% ~ 100%) for the compactor to grab
     * the writer's lock during each batch write in case the writer's throughput
     * is faster than the compactor, to make sure that the compactor can keep
     * pace with the writer and eventually complete the compaction.
     * Note that we plan to reduce the compaction overhead significantly soon
     * and deprecate this parameter when it is not needed anymore.
     * This is a local config to each ForestDB file.
     */
    size_t max_writer_lock_prob;
    /**
     * Number of daemon compactor threads. It is set to 4 threads by default.
     * If many files are opened and accessed concurrently, then it is
     * recommended to increase this value if the host machine has enough cores
     * and disk I/O bandwidth.
     * This is a global config that is configured across all ForestDB files.
     */
    size_t num_compactor_threads;
    /**
     * Number of background flusher threads. It is set to 4 threads by default.
     * For write intensive workloads with large commit intervals and many files
     * it is recommended to increase this value if the host machine has enough
     * cores and disk I/O bandwidth.
     * This is a global config that is configured across all ForestDB files.
     */
    size_t num_bgflusher_threads;
    /**
     * Encryption key for the database. Default value has algorithm = FDB_ENCRYPTION_NONE,
     * i.e. no encryption. When a database file is being created, its contents will be
     * encrypted with the given key. When a database is re-opened, the same key
     * must be given, otherwise fdb_open will fail with error FDB_RESULT_NO_DB_HEADERS.
     */
    fdb_encryption_key encryption_key;
    /**
     * Circular block reusing threshold in the unit of percentage (%), which can be
     * represented as '(stale data size)/(total file size)'. When stale data size
     * grows beyond the threshold, circular block reusing is triggered so that stale
     * blocks are reused for further block allocation. Block reusing is disabled if
     * this threshold is set to zero or 100.
     */
    size_t block_reusing_threshold;
    /**
     * Number of the last commit headers whose stale blocks should be kept for
     * snapshot readers.
     */
    size_t num_keeping_headers;
    /**
     * Breakpad crash catcher settings
     */
    const char* breakpad_minidump_dir;
    /**
     * Custom file operations
     */
    fdb_filemgr_ops_t* custom_file_ops;
    /**
     * Number of global background I/O threads used across all forestdb instances
     * Default value is 50% the number of cores
     */
    size_t num_background_threads;
    /**
     * Flush limit in bytes for non-block aligned buffer cache
     */
    size_t bcache_flush_limit;

} fdb_config;

typedef struct {
    /**
     * Flag to create a new empty KV store instance in a DB instance,
     * if it doesn't exist.
     */
    bool create_if_missing;
    /**
     * Customized compare function for an KV store instance.
     */
    fdb_custom_cmp_variable custom_cmp;
} fdb_kvs_config;

/**
 * Pointer type definition of an error logging callback function.
 */
typedef void (*fdb_log_callback)(int err_code, const char *err_msg, void *ctx_data);

/**
 * Function pointer definition of the fatal error callback function.
 */
typedef void (*fdb_fatal_error_callback)(void);

/**
 * ForestDB iterator options.Combinational options can be passed to the iterator.
 * For example, FDB_ITR_SKIP_MIN_KEY | FDB_ITR_SKIP_MAX_KEY means
 * "The smallest and largest keys in the iteration ragne won't be returned by the
 * iterator".
 */
typedef uint16_t fdb_iterator_opt_t;
enum {
    /**
     * Return both key and value through iterator.
     */
    FDB_ITR_NONE = 0x00,
    /**
     * Return only non-deleted items through iterator.
     */
    FDB_ITR_NO_DELETES = 0x02,
    /**
     * The lowest key specified will not be returned by the iterator.
     */
    FDB_ITR_SKIP_MIN_KEY = 0x04,
    /**
     * The highest key specified will not be returned by the iterator.
     */
    FDB_ITR_SKIP_MAX_KEY = 0x08,
    /**
     * Return Keys and Metadata only for fdb_changes_since API.
     */
    FDB_ITR_NO_VALUES = 0x10
};

/**
 * ForestDB iterator seek options.
 */
typedef uint8_t fdb_iterator_seek_opt_t;
enum {
    /**
     * If seek_key does not exist return the next sorted key higher than it.
     */
    FDB_ITR_SEEK_HIGHER = 0x00,
    /**
     * If seek_key does not exist return the previous sorted key lower than it.
     */
    FDB_ITR_SEEK_LOWER = 0x01
};

/**
 * Opaque reference to ForestDB iterator structure definition, which is exposed
 * in public APIs.
 */
typedef struct FdbIterator fdb_iterator;

/**
 * Return type for the fdb_changes_since API's callback: fdb_changes_function_fn
 */
typedef int fdb_changes_decision;
enum {
    /**
     * This return value means that the fdb_doc instance passed to the callback
     * function will not to be freed in the fdb_changes_since API, the caller
     * would have to take care of it.
     */
    FDB_CHANGES_PRESERVE = 1,
    /**
     * This return value means that the fdb_doc instance passed to the callback
     * function will automatically be freed in the fdb_changes_since API.
     */
    FDB_CHANGES_CLEAN = 0,
    /**
     * This return value means that the fdb_doc instance passed to the callback
     * function will automatically be freed in the fdb_changes_since API and
     * the iteration within the API will be stopped.
     */
    FDB_CHANGES_CANCEL = -1
};

/**
 * The callback function used by fdb_changes_since() to iterate through
 * the documents.
 *
 * @param handle Pointer to ForestDB KV store instance
 * @param doc Pointer to the current document
 * @param ctx Client context
 */
typedef fdb_changes_decision (*fdb_changes_callback_fn)(
                                                 fdb_kvs_handle *handle,
                                                 fdb_doc *doc,
                                                 void *ctx);

/**
 * Using off_t turned out to be a real challenge. On "unix-like" systems
 * its size is set by a combination of #defines like: _LARGE_FILE,
 * _FILE_OFFSET_BITS and/or _LARGEFILE_SOURCE etc. The interesting
 * part is however Windows.
 *
 * Windows follows the LLP64 data model:
 * http://en.wikipedia.org/wiki/LLP64#64-bit_data_models
 *
 * This means both the int and long int types have a size of 32 bits
 * regardless if it's a 32 or 64 bits Windows system.
 *
 * And Windows defines the type off_t as being a signed long integer:
 * http://msdn.microsoft.com/en-us/library/323b6b3k.aspx
 *
 * This means we can't use off_t on Windows if we deal with files
 * that can have a size of 2Gb or more.
 */
typedef int64_t cs_off_t;

/**
 * Information about a ForestDB file
 */
typedef struct {
    /**
     * A file name.
     */
    const char* filename;
    /**
     * A new file name that is used after compaction.
     */
    const char* new_filename;
    /**
     * Total number of non-deleted documents aggregated across all KV stores.
     */
    uint64_t doc_count;
    /**
     * Total number of deleted documents aggregated across all KV stores.
     */
    uint64_t deleted_count;
    /**
     * Disk space actively used by the file.
     */
    uint64_t space_used;
    /**
     * Total disk space used by the file, including stale btree nodes and docs.
     */
    uint64_t file_size;
    /**
     * Number of KV store instances in a ForestDB file
     */
    size_t num_kv_stores;
} fdb_file_info;

/**
 * Information about a ForestDB KV store
 */
typedef struct {
    /**
     * A KV store name.
     */
    const char* name;
    /**
     * Last sequence number assigned.
     */
    fdb_seqnum_t last_seqnum;
    /**
     * Total number of non-deleted documents in a KV store.
     */
    uint64_t doc_count;
    /**
     * Total number of deleted documents in a KV store.
     */
    uint64_t deleted_count;
    /**
     * Disk space actively used by the KV store.
     */
    uint64_t space_used;
    /**
     * File handle that owns the KV store.
     */
    fdb_file_handle* file;
} fdb_kvs_info;

/**
 * Information about a ForestDB KV store's operational counters
 */
typedef struct {
    /**
     * Number of fdb_set operations.
     */
    uint64_t num_sets;
    /**
     * Number of fdb_del operations.
     */
    uint64_t num_dels;
    /**
     * Number of fdb_commit operations.
     */
    uint64_t num_commits;
    /**
     * Number of fdb_compact operations on underlying file.
     */
    uint64_t num_compacts;
    /**
     * Number of fdb_get* (includes metaonly, byseq etc) operations.
     */
    uint64_t num_gets;
    /**
     * Number of fdb_iterator_get* (includes meta_only) operations.
     */
    uint64_t num_iterator_gets;
    /**
     * Number of fdb_iterator_moves (includes next,prev,seek) operations.
     */
    uint64_t num_iterator_moves;
} fdb_kvs_ops_info;

/**
 * Latency stat type for each public API
 */
typedef uint8_t fdb_latency_stat_type;
enum {
    FDB_LATENCY_SETS         = 0, // fdb_set API
    FDB_LATENCY_GETS         = 1, // fdb_get API
    FDB_LATENCY_COMMITS      = 2, // fdb_commit API
    FDB_LATENCY_SNAP_INMEM   = 3, // fdb_snapshot_open in-memory API
    FDB_LATENCY_SNAP_DUR     = 4, // fdb_snapshot_open durable API
    FDB_LATENCY_COMPACTS     = 5, // fdb_compact API
    FDB_LATENCY_ITR_INIT     = 6, // fdb_iterator_init API
    FDB_LATENCY_ITR_SEQ_INIT = 7, // fdb_iterator_sequence_init API
    FDB_LATENCY_ITR_NEXT     = 8, // fdb_iterator_next API
    FDB_LATENCY_ITR_PREV     = 9, // fdb_iterator_prev API
    FDB_LATENCY_ITR_GET      = 10, // fdb_iterator_get API
    FDB_LATENCY_ITR_GET_META = 11, // fdb_iterator_get_metaonly API
    FDB_LATENCY_ITR_SEEK     = 12, // fdb_iterator_seek API
    FDB_LATENCY_ITR_SEEK_MAX = 13, // fdb_iterator_seek_to_max API
    FDB_LATENCY_ITR_SEEK_MIN = 14, // fdb_iterator_seek_to_min API
    FDB_LATENCY_ITR_CLOSE    = 15, // fdb_iterator_close API
    FDB_LATENCY_OPEN         = 16, // fdb_open API
    FDB_LATENCY_KVS_OPEN     = 17, // fdb_kvs_open API
    FDB_LATENCY_SNAP_CLONE   = 18, // fdb_snapshot_open from another snapshot
    FDB_LATENCY_WAL_INS      = 19, // wal_insert()
    FDB_LATENCY_WAL_FIND     = 20, // wal_find()
    FDB_LATENCY_WAL_COMMIT   = 21, // wal_commit()
    FDB_LATENCY_WAL_FLUSH    = 22, // _wal_flush()
    FDB_LATENCY_WAL_RELEASE  = 23, // wal_release_flushed_items()
    FDB_LATENCY_NUM_STATS    = 24  // Number of stats (keep as highest elem)
};

/**
 * Latency statistics of a specific ForestDB api call
 */
typedef struct {
    /**
     * Total number this call was invoked.
     */
    uint64_t lat_count;
    /**
     * The fastest call took this amount of time in micro seconds.
     */
    uint32_t lat_min;
    /**
     * The slowest call took this amount of time in micro seconds.
     */
    uint32_t lat_max;
    /**
     * The average time taken by this call in micro seconds.
     */
    uint32_t lat_avg;
} fdb_latency_stat;

/**
 * List of ForestDB KV store names
 */
typedef struct {
    /**
     * Number of KV store names listed in kvs_names.
     */
    size_t num_kvs_names;
    /**
     * Pointer to array of KV store names.
     */
    char **kvs_names;
} fdb_kvs_name_list;

/**
 * Persisted Snapshot Marker in file (Sequence number + KV Store name)
 */
typedef struct {
    /**
     * NULL-terminated KV Store name.
     */
    char *kv_store_name;
    /**
     * A Sequence number of the above KV store, which results from an
     * fdb_commit operation.
     */
    fdb_seqnum_t seqnum;
} fdb_kvs_commit_marker_t;

/**
 * An opaque file-level snapshot marker that can be used to purge
 * stale data up to a given file-level snapshot marker.
*/
typedef uint64_t fdb_snapshot_marker_t;

/**
 * Snapshot Information structure for a ForestDB database file.
 */
typedef struct {
    /**
     * Opaque file-level snapshot marker that can be passed to
     * fdb_compact_upto() api.
     */
    fdb_snapshot_marker_t marker;
    /**
     * Number of KV store snapshot markers in the kvs_markers array.
     */
    int64_t num_kvs_markers;
    /**
     * Pointer to an array of {kv_store_name, committed_seqnum} pairs.
     */
    fdb_kvs_commit_marker_t *kvs_markers;
} fdb_snapshot_info_t;

/**
 * The callback function is used by fdb_fetch_handle_stats.
 *
 * @param handle Pointer to ForestDB KV store instance
 * @param stat stat name
 * @param value stat value
 * @param ctx Client context
 */
typedef void (*fdb_handle_stats_cb)(fdb_kvs_handle *handle,
                                    const char *stat,
                                    uint64_t value,
                                    void *ctx);


#ifdef __cplusplus
}
#endif

#endif
