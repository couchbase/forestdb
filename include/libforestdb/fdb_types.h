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

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Flags to be passed to fdb_open() API
 */
typedef uint32_t fdb_open_flags;
enum {
    /**
     * Create a new empty ForestDB file if it doesn't exist.
     */
    FDB_OPEN_FLAG_CREATE = 1,
    /**
     * Open the database in read only mode
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
     * This is a local config to each ForestDB database instance.
     */
    uint16_t chunksize;
    /**
     * Size of block that is a unit of IO operations.
     * It is set to 4KB by default and has a min value of 1KB and a max value of
     * 128KB. This is a global config that is used across all ForestDB database
     * instances.
     */
    uint32_t blocksize;
    /**
     * Buffer cache size in bytes. If the size is set to zero, then the buffer
     * cache is disabled. This is a global config that is used across all
     * ForestDB database instances.
     */
    uint64_t buffercache_size;
    /**
     * WAL index size threshold in memory (4096 entries by default).
     * This is a local config to each ForestDB database instance.
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
     * This is a local config to each ForestDB database instance.
     */
    uint32_t purging_interval;
    /**
     * Flag to enable or disable a sequence B+-Tree.
     * This is a local config to each ForestDB database instance.
     */
    fdb_seqtree_opt_t seqtree_opt;
    /**
     * Flag to enable synchronous or asynchronous commit options.
     * This is a local config to each ForestDB database instance.
     */
    fdb_durability_opt_t durability_opt;
    /**
     * Flags for fdb_open API. It can be used for specifying read-only mode.
     * This is a local config to each ForestDB database instance.
     */
    fdb_open_flags flags;
    /**
     * Maximum size (bytes) of temporary buffer for compaction (16MB by default).
     * This is a local config to each ForestDB database instance.
     */
    uint32_t compaction_buf_maxsize;
    /**
     * Destroy all the cached blocks in the global buffer cache when a database
     * file is closed. It is set to true by default. This is a global config
     * that is used across all ForestDB database instances.
     */
    bool cleanup_cache_onclose;
    /**
     * Compress the body of document when it is written on disk. The compression
     * is disabled by default. This is a global config that is used across all
     * ForestDB database instances.
     */
    bool compress_document_body;
    /**
     * Compaction threshold in the unit of percentage (%). It can be calculated
     * as '(stale data size)/(total file size)'. The compaction daemon triggers
     * compaction if this threshold is satisfied.
     * The compaction daemon is disabled when this value is set to zero,
     * and compaction will not be performed when this value is set to 100.
     * This is a local config to each ForestDB database instance.
     */
    uint8_t compaction_threshold;
    /**
     * The minimum filesize to perform compaction.
     * This is a local config to each ForestDB database instance.
     */
    uint64_t compaction_minimum_filesize;
    /**
     * Duration that the compaction daemon periodically waks up, in the unit of
     * second. This is a global config that is used across all ForestDB database
     * instances.
     */
    uint64_t compactor_sleep_duration;
    /**
     * Customized compare function for fixed size key.
     * This is a local config to each ForestDB database instance.
     */
    fdb_custom_cmp_fixed cmp_fixed;
    /**
     * Customized compare function for variable length key.
     * This is a local config to each ForestDB database instance.
     */
    fdb_custom_cmp_variable cmp_variable;
} fdb_config;


typedef uint64_t fdb_seqnum_t;

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
 *Opaque reference to the database handle, which is exposed in public APIs.
 */
typedef struct _fdb_handle fdb_handle;

/**
 * ForestDB iterator options.Combinational options can be passed to the iterator.
 * For example, FDB_ITR_METAONLY | FDB_ITR_NO_DELETES means
 * "Return non-deleted key and its metadata only through iterator".
 */
typedef uint8_t fdb_iterator_opt_t;
enum {
    /**
     * Return both key and value through iterator.
     */
    FDB_ITR_NONE = 0x00,
    /**
     * Return key and its metadata only through iterator.
     */
    FDB_ITR_METAONLY = 0x01,
    /**
     * Return only non-deleted items through iterator.
     */
    FDB_ITR_NO_DELETES = 0x02
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
 * Information about a given database file
 */
typedef struct {
    /**
     * A database file name.
     */
    const char* filename;
    /**
     * A new database file name that is used after compaction.
     */
    const char* new_filename;
    /**
     * Last sequence number assigned
     */
    fdb_seqnum_t last_seqnum;
    /**
     * Total number of non-deleted documents
     */
    uint64_t doc_count;
    /**
     * Disk space actively used by database
     */
    uint64_t space_used;
    /**
     * Total disk space used by database, including stale btree nodes and docs.
     */
    uint64_t file_size;
} fdb_info;

#ifdef __cplusplus
}
#endif

#endif
