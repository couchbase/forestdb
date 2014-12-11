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

#include <stdint.h>
#include <stddef.h>
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
 * Note that we plan to support a longer key that is greater than
 * the current max size 3840 bytes
 */
#define FDB_MAX_KEYLEN (3840)
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
    FDB_OPEN_FLAG_RDONLY = 2
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
     * Duration that the compaction daemon periodically wakes up, in the unit of
     * second. This is a global config that is used across all ForestDB files.
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
} fdb_doc;

/**
 * Pointer type definition of an error logging callback function.
 */
typedef void (*fdb_log_callback)(int err_code, const char *err_msg, void *ctx_data);

/**
 * Opaque reference to a ForestDB file handle, which is exposed in public APIs.
 */
typedef struct _fdb_file_handle fdb_file_handle;

/**
 * Opaque reference to a ForestDB KV store handle, which is exposed in public APIs.
 */
typedef struct _fdb_kvs_handle fdb_kvs_handle;

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
    FDB_ITR_SKIP_MAX_KEY = 0x08
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
typedef struct _fdb_iterator fdb_iterator;

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
     * Disk space actively used by the file.
     */
    uint64_t space_used;
    /**
     * Total disk space used by the file, including stale btree nodes and docs.
     */
    uint64_t file_size;
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
     * Disk space actively used by the KV store.
     */
    uint64_t space_used;
    /**
     * File handle that owns the KV store.
     */
    fdb_file_handle* file;
} fdb_kvs_info;

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


#ifdef __cplusplus
}
#endif

#endif
