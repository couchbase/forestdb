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

#ifndef _INTERNAL_TYPES_H
#define _INTERNAL_TYPES_H

#include <stdint.h>

#include "libforestdb/fdb_types.h"
#include "common.h"
#include "atomic.h"
#include "avltree.h"
#include "list.h"

#ifdef __cplusplus
extern "C" {
#endif

struct btree;
class FileMgr;
struct btreeblk_handle;
class DocioHandle;
struct btree_blk_ops;
struct Snapshot;

class FdbKvsHandle;
class HBTrie;
class WalItr;

#define OFFSET_SIZE (sizeof(uint64_t))

#define FDB_MAX_KEYLEN_INTERNAL (65520)

// Versioning information...
// Version 003 - New non-block aligned BtreeV2
#define FILEMGR_MAGIC_003 (UINT64_C(0xdeadcafebeefc003))
// Version 002 - added stale-block tree info
#define FILEMGR_MAGIC_002 (UINT64_C(0xdeadcafebeefc002))
// Version 001 - added delta size to DB header and CRC-32C
#define FILEMGR_MAGIC_001 (UINT64_C(0xdeadcafebeefc001))
// Version 000 - old format (It involves various DB header formats so that we cannot
//               identify those different formats by using magic number. To avoid
//               unexpected behavior or crash, this magic number is no longer
//               supported.)
#define FILEMGR_MAGIC_000 (UINT64_C(0xdeadcafebeefbeef))

// TODO: Set to 003 once BtreeV2 is ready
#define FILEMGR_LATEST_MAGIC FILEMGR_MAGIC_002


/**
 * Error logging callback struct definition.
 */
class ErrLogCallback {
public:
    ErrLogCallback() :
        callback(NULL), ctx_data(NULL) { }

    ErrLogCallback(fdb_log_callback _callback, void *_ctx_data) :
        callback(_callback), ctx_data(_ctx_data) { }

    fdb_log_callback getCallback(void) const {
        return callback;
    }

    void *getCtxData(void) const {
        return ctx_data;
    }

    void setCallback(fdb_log_callback _callback) {
        callback = _callback;
    }

    void setCtxData(void *_ctx_data) {
        ctx_data = _ctx_data;
    }

private:
    /**
     * Error logging callback function.
     */
    fdb_log_callback callback;
    /**
     * Application-specific context data that is passed to the logging callback
     * function.
     */
    void *ctx_data;
};

typedef struct _fdb_transaction fdb_txn;

typedef uint64_t fdb_kvs_id_t;
typedef uint16_t filemgr_header_len_t;
typedef uint64_t filemgr_magic_t;
typedef uint64_t filemgr_header_revnum_t;

typedef uint8_t kvs_type_t;
enum {
    KVS_ROOT = 0,
    KVS_SUB = 1
};

struct list;
struct kvs_opened_node;

/**
 * KV store info for each handle.
 */
class KvsInfo {
public:
    KvsInfo() :
        type(KVS_ROOT), id(0), root(NULL) { }

    KvsInfo(const KvsInfo &info) :
        type(info.type), id(info.id), root(info.root) { }

    KvsInfo(kvs_type_t _type, fdb_kvs_id_t _id, FdbKvsHandle *_root):
        type(_type), id(_id), root(_root) { }

    kvs_type_t getKvsType() const {
        return type;
    }

    fdb_kvs_id_t getKvsId() const {
        return id;
    }

    FdbKvsHandle *getRootHandle() const {
        return root;
    }

    void setKvsType(kvs_type_t _type) {
        type = _type;
    }

    void setKvsId(fdb_kvs_id_t _id) {
        id = _id;
    }

    void setRootHandle(FdbKvsHandle *_root) {
        root = _root;
    }

private:
    /**
     * KV store type.
     */
    kvs_type_t type;
    /**
     * KV store ID.
     */
    fdb_kvs_id_t id;
    /**
     * Pointer to root handle.
     */
    FdbKvsHandle *root;
};

/**
 * Attributes in KV store statistics.
 */
typedef enum {
    KVS_STAT_NLIVENODES,
    KVS_STAT_NDOCS,
    KVS_STAT_NDELETES,
    KVS_STAT_DATASIZE,
    KVS_STAT_WAL_NDOCS,
    KVS_STAT_WAL_NDELETES,
    KVS_STAT_DELTASIZE
} kvs_stat_attr_t;

/**
 * KV store statistics.
 */
class KvsStat {
public:
    KvsStat() :
        nlivenodes(0), ndocs(0), ndeletes(0), datasize(0),
        wal_ndocs(0), wal_ndeletes(0), deltasize(0) { }

    void reset() {
        nlivenodes = 0;
        ndocs = 0;
        ndeletes = 0;
        datasize = 0;
        wal_ndocs = 0;
        wal_ndeletes = 0;
        deltasize = 0;
    }

    /**
     * The number of live index nodes.
     */
    uint64_t nlivenodes;
    /**
     * The number of documents.
     */
    uint64_t ndocs;
    /**
     * The number of deleted documents in main index.
     */
    uint64_t ndeletes;
    /**
     * The amount of space occupied by documents.
     */
    uint64_t datasize;
    /**
     * The number of documents in WAL.
     */
    uint64_t wal_ndocs;
    /**
     * The number of deleted documents in WAL.
     */
    uint64_t wal_ndeletes;
    /**
     * The amount of space occupied by documents+index since last commit.
     */
    int64_t deltasize;
};

/**
 * Atomic counters of operational statistics in ForestDB KV store.
 */
class KvsOpsStat {
public:
    KvsOpsStat() :
        num_sets(0), num_dels(0), num_commits(0), num_compacts(0),
        num_gets(0), num_iterator_gets(0), num_iterator_moves(0) { }

    void reset() {
        num_sets = 0;
        num_dels = 0;
        num_commits = 0;
        num_compacts = 0;
        num_gets = 0;
        num_iterator_gets = 0;
        num_iterator_moves = 0;
    }

    KvsOpsStat& operator=(const KvsOpsStat& ops_stat) {
        num_sets.store(ops_stat.num_sets.load(std::memory_order_relaxed),
                       std::memory_order_relaxed);
        num_dels.store(ops_stat.num_dels.load(std::memory_order_relaxed),
                       std::memory_order_relaxed);
        num_commits.store(ops_stat.num_commits.load( std::memory_order_relaxed),
                          std::memory_order_relaxed);
        num_compacts.store(ops_stat.num_compacts.load(std::memory_order_relaxed),
                           std::memory_order_relaxed);
        num_gets.store(ops_stat.num_gets.load(std::memory_order_relaxed),
                       std::memory_order_relaxed);
        num_iterator_gets.store(ops_stat.num_iterator_gets.load(std::memory_order_relaxed),
                                std::memory_order_relaxed);
        num_iterator_moves.store(ops_stat.num_iterator_moves.load(std::memory_order_relaxed),
                                 std::memory_order_relaxed);
        return *this;
    }

    /**
     * Number of fdb_set operations.
     */
    std::atomic<uint64_t> num_sets;
    /**
     * Number of fdb_del operations.
     */
    std::atomic<uint64_t> num_dels;
    /**
     * Number of fdb_commit operations.
     */
    std::atomic<uint64_t> num_commits;
    /**
     * Number of fdb_compact operations on underlying file.
     */
    std::atomic<uint64_t> num_compacts;
    /**
     * Number of fdb_get* (includes metaonly, byseq etc) operations.
     */
    std::atomic<uint64_t> num_gets;
    /**
     * Number of fdb_iterator_get* (includes meta_only) operations.
     */
    std::atomic<uint64_t> num_iterator_gets;
    /**
     * Number of fdb_iterator_moves (includes next,prev,seek) operations.
     */
    std::atomic<uint64_t> num_iterator_moves;
};

/**
 * ForestDB KV store key comparison callback context
 */
struct _fdb_key_cmp_info {
    /**
     * ForestDB KV store level config.
     */
    fdb_kvs_config kvs_config;
    /**
     * KV store information.
     */
    KvsInfo *kvs;
};

struct wal_txn_wrapper;

/**
 * ForestDB transaction structure definition.
 */
struct _fdb_transaction {
    /**
     * ForestDB KV store handle.
     */
    FdbKvsHandle *handle;
    /**
     * Unique monotonically increasing transaction id to distinguish
     * items that once belonged to a transaction which has ended.
     */
    uint64_t txn_id;
    /**
     * Block ID of the last header before the transaction begins.
     */
    uint64_t prev_hdr_bid;
    /**
     * Rev number of the last header before the transaction begins.
     */
    uint64_t prev_revnum;
    /**
     * List of dirty WAL items.
     */
    struct list *items;
    /**
     * Transaction isolation level.
     */
    fdb_isolation_level_t isolation;
    /**
     * Pointer to transaction wrapper.
     */
    struct wal_txn_wrapper *wrapper;
};

/* Global KV store header for each file
 */
class KvsHeader {
public:
    KvsHeader(fdb_kvs_id_t _id_counter,
              size_t _num_kv_stores)
        : id_counter(_id_counter), default_kvs_cmp(nullptr),
          custom_cmp_enabled(0), num_kv_stores(_num_kv_stores)
    {
        idx_name = (struct avl_tree*)malloc(sizeof(struct avl_tree));
        avl_init(idx_name, nullptr);
        idx_id = (struct avl_tree*)malloc(sizeof(struct avl_tree));
        avl_init(idx_id, nullptr);
        spin_init(&lock);
    }

    ~KvsHeader() {
        free(idx_name);
        free(idx_id);
        spin_destroy(&lock);
    }

    /**
     * Monotonically increasing counter to generate KV store IDs.
     */
    fdb_kvs_id_t id_counter;
    /**
     * The custom comparison function if set by user.
     */
    fdb_custom_cmp_variable default_kvs_cmp;
    /**
     * A tree linking all KV stores in a file by their KV store name.
     */
    struct avl_tree *idx_name;
    /**
     * A tree linking all KV stores in file by their ID.
     */
    struct avl_tree *idx_id;
    /**
     * Boolean to determine if custom compare function for a KV store is set.
     */
    uint8_t custom_cmp_enabled;
    /**
     * Number of KV store instances
     */
    size_t num_kv_stores;
    /**
     * lock to protect access to the idx_name and idx_id trees above
     */
    spin_t lock;
};

/** Mapping data for each KV store in DB file.
 * (global & most fields are persisted in the DB file)
 */
#define KVS_FLAG_CUSTOM_CMP (0x1)
struct kvs_node {
    /**
     * Name of the KV store as given by user.
     */
    char *kvs_name;
    /**
     * Unique KV Store ID generated and permanently assigned.
     */
    fdb_kvs_id_t id;
    /**
     * Highest sequence number seen in this KV store.
     */
    fdb_seqnum_t seqnum;
    /**
     * Flags indicating various states of the KV store.
     */
    uint64_t flags;
    /**
     * Custom compare function set by user (in-memory only).
     */
    fdb_custom_cmp_variable custom_cmp;
    /**
     * Operational CRUD statistics for this KV store (in-memory only).
     */
    KvsOpsStat op_stat;
    /**
     * Persisted KV store statistics.
     */
    KvsStat stat;
    /**
     * Link to the global list of KV stores indexed by store name.
     */
    struct avl_node avl_name;
    /**
     * Link to the global list of KV stores indexed by store ID.
     */
    struct avl_node avl_id;
};

/**
 * Type of filename in use.
 */
typedef enum {
    /**
     * Filename used is a virtual filename (typically in auto compaction).
     */
    FDB_VFILENAME = 0,
    /**
     * Filename used is the actual filename (typically in manual compaction).
     */
    FDB_AFILENAME = 1,
} fdb_filename_mode_t;

/**
 * Stale data position & length
 */
struct stale_data {
    /**
     * Starting offset of the stale data
     */
    uint64_t pos;
    /**
     * Length of the stale data
     */
    uint32_t len;
};

/**
 * List of stale data
 */
struct stale_regions {
    /**
     * Number of regions
     */
    size_t n_regions;
    union {
        /**
         * Pointer to the array of regions, if n_regions > 1
         */
        struct stale_data *regions;
        /**
         * Stale region, if n_regions == 1
         */
        struct stale_data region;
    };
};

#define FDB_FLAG_SEQTREE_USE (0x1)
#define FDB_FLAG_ROOT_INITIALIZED (0x2)
#define FDB_FLAG_ROOT_CUSTOM_CMP (0x4)


#define FDB_DOC_META_DELETED (0x1)

/**
 * Document meta data that will be stored as a value in HB+trie.
 */
struct DocMetaForIndex
{
    DocMetaForIndex() :
        offset(BLK_NOT_FOUND), seqnum(SEQNUM_NOT_USED),
        onDiskSize(0), flags(0)
    {
        reserved[0] = reserved[1] = reserved[2] = 0;
    }

    DocMetaForIndex(uint64_t _offset,
        uint64_t _seqnum,
        uint32_t _on_disk_size,
        uint8_t _flags) :
        offset(_offset),
        seqnum(_seqnum),
        onDiskSize(_on_disk_size),
        flags(_flags)
    {
        reserved[0] = reserved[1] = reserved[2] = 0;
    }

    void encode() {
        offset = _endian_encode(offset);
        seqnum = _endian_encode(seqnum);
        onDiskSize = _endian_encode(onDiskSize);
    }

    void decode() {
        offset = _endian_decode(offset);
        seqnum = _endian_decode(seqnum);
        onDiskSize = _endian_decode(onDiskSize);
    }

    bool isDeleted() {
        return flags & FDB_DOC_META_DELETED;
    }

    size_t size() {
        return sizeof(DocMetaForIndex);
    }

    // Document disk offset.
    uint64_t offset;
    // Document sequence number.
    uint64_t seqnum;
    // Document on-disk size (compressed size if compression is enabled).
    uint32_t onDiskSize;
    // Additional flags.
    uint8_t flags;
    // Reserved bytes.
    uint8_t reserved[3];
};

#ifdef __cplusplus
}
#endif

#endif
