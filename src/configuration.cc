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

#include <stdint.h>
#include <string.h>

#include "libforestdb/fdb_errors.h"
#include "fdb_internal.h"

#include "configuration.h"
#include "system_resource_stats.h"

static ssize_t prime_size_table[] = {
    11, 31, 47, 73, 97, 109, 211, 313, 419, -1
};

fdb_config get_default_config(void) {
    fdb_config fconfig;

    fconfig.chunksize = sizeof(uint64_t);
    // 4KB by default.
    fconfig.blocksize = FDB_BLOCKSIZE;
    // 128MB by default.
    fconfig.buffercache_size = 134217728;
#ifdef _MVCC_WAL_ENABLE
    // 40K WAL entries by default.
    fconfig.wal_threshold = 40960;
#else
    // 4K WAL entries by default.
    fconfig.wal_threshold = 4096;
#endif
    fconfig.wal_flush_before_commit = true;
    fconfig.auto_commit = false;
    // 0 second by default.
    fconfig.purging_interval = 0;
    // Sequence trees are disabled by default.
    fconfig.seqtree_opt = FDB_SEQTREE_NOT_USE;
    // Use a synchronous commit by default.
    fconfig.durability_opt = FDB_DRB_NONE;
    fconfig.flags = FDB_OPEN_FLAG_CREATE;
    // 4MB by default.
    fconfig.compaction_buf_maxsize = FDB_COMP_BUF_MINSIZE;
    // Clean up cache entries when a file is closed.
    fconfig.cleanup_cache_onclose = true;
    // Compress the body of documents using snappy. Disabled by default.
    fconfig.compress_document_body = false;
    // Auto compaction is disabled by default
    fconfig.compaction_mode = FDB_COMPACTION_MANUAL;
    // Compaction threshold, 30% by default
    fconfig.compaction_threshold = FDB_DEFAULT_COMPACTION_THRESHOLD;
    fconfig.compaction_minimum_filesize = 1048576; // 1MB by default
    // 8 hours by default
    fconfig.compactor_sleep_duration = FDB_COMPACTOR_SLEEP_DURATION;
    // Multi KV Instance mode is enabled by default
    fconfig.multi_kv_instances = true;
    // TODO: Re-enable this after prefetch ThreadSanitizer fixes are in..
    fconfig.prefetch_duration = 0;

    // Determine the number of WAL and buffer cache partitions by considering the
    // number of cores available in the host environment.
    int i = 0;
    ssize_t num_cores = (ssize_t) get_num_cores();
    for (; prime_size_table[i] > 0 && prime_size_table[i] < num_cores; ++i) {
        // Finding the smallest prime number that is greater than the number of cores.
    }
    if (prime_size_table[i] == -1) {
        fconfig.num_wal_partitions = prime_size_table[i-1];
        fconfig.num_bcache_partitions = prime_size_table[i-1];
    } else {
        fconfig.num_wal_partitions = prime_size_table[i];
        // For bcache partitions pick a higher value for smaller avl trees
        fconfig.num_bcache_partitions = prime_size_table[i];
    }

    // No compaction callback function by default
    fconfig.compaction_cb = NULL;
    fconfig.compaction_cb_mask = 0x0;
    fconfig.compaction_cb_ctx = NULL;
    fconfig.max_writer_lock_prob = 100;
    // 4 daemon compactor threads by default
    fconfig.num_compactor_threads = DEFAULT_NUM_COMPACTOR_THREADS;
    fconfig.num_bgflusher_threads = DEFAULT_NUM_BGFLUSHER_THREADS;
    if (num_cores/2 > FDB_EXPOOL_NUM_THREADS &&
        num_cores/2 < FDB_EXPOOL_MAX_THREADS) {
        fconfig.num_background_threads = num_cores / 2;
    } else {
        fconfig.num_background_threads = FDB_EXPOOL_NUM_THREADS;
    }
    // Block reusing threshold, 65% by default (i.e., almost 3x space amplification)
    fconfig.block_reusing_threshold = 65;
    // Keep at most 5 recent committed database snapshots
    fconfig.num_keeping_headers = 5;

    fconfig.encryption_key.algorithm = FDB_ENCRYPTION_NONE;
    memset(fconfig.encryption_key.bytes, 0, sizeof(fconfig.encryption_key.bytes));

    // Breakpad minidump directory, set to current working dir
    fconfig.breakpad_minidump_dir = ".";

    fconfig.custom_file_ops = NULL;

    // Flush limit in bytes for non-block aligned buffer cache
    fconfig.bcache_flush_limit = 1048576;

    return fconfig;
}

fdb_kvs_config get_default_kvs_config(void) {
    fdb_kvs_config kvs_config;

    // create an empty KV store if it doesn't exist.
    kvs_config.create_if_missing = true;
    // lexicographical key order by default
    kvs_config.custom_cmp = NULL;

    return kvs_config;
}

bool validate_fdb_config(fdb_config *fconfig) {
    assert(fconfig);

    if (fconfig->chunksize < 4 || fconfig->chunksize > 64) {
        // Chunk size should be set between 4 and 64 bytes.
        fdb_log(NULL, FDB_RESULT_INVALID_ARGS,
                "Config Error: Chunk size (%u) not between 4 and 64 Bytes!\n",
                fconfig->chunksize);
        return false;
    }

    if (fconfig->chunksize < sizeof(void *)) {
        // Chunk size should be equal to or greater than the address bus size
        fdb_log(NULL, FDB_RESULT_INVALID_ARGS,
                "Config Error: Chunk size (%u) less than address bus size!\n",
                fconfig->chunksize);
        return false;
    }

    if (fconfig->blocksize < 1024 || fconfig->blocksize > 131072) {
        // Block size should be set between 1KB and 128KB
        fdb_log(NULL, FDB_RESULT_INVALID_ARGS,
                "Config Error: Block size (%" _F64 ") not between 1KB and 128KB!\n",
                static_cast<uint64_t>(fconfig->blocksize));
        return false;
    }

    if (fconfig->seqtree_opt != FDB_SEQTREE_NOT_USE &&
        fconfig->seqtree_opt != FDB_SEQTREE_USE) {
        fdb_log(NULL, FDB_RESULT_INVALID_ARGS,
                "Config Error: Sequence trees option (%d) : Not recognized! "
                "[Allowed options: FDB_SEQTREE_NOT_USE (%d), FDB_SEQTREE_USE (%d)]\n",
                fconfig->seqtree_opt, FDB_SEQTREE_NOT_USE, FDB_SEQTREE_USE);
        return false;
    }

    if (fconfig->durability_opt != FDB_DRB_NONE &&
        fconfig->durability_opt != FDB_DRB_ODIRECT &&
        fconfig->durability_opt != FDB_DRB_ASYNC &&
        fconfig->durability_opt != FDB_DRB_ODIRECT_ASYNC) {
        fdb_log(NULL, FDB_RESULT_INVALID_ARGS,
                "Config Error: Durability option (%x) : Not recognized! "
                "[Allowed options: FDB_DRB_NONE (%x), FDB_DRB_ODIRECT (%x),"
                " FDB_DRB_ASYNC (%x), FDB_DRB_ODIRECT_ASYNC (%x)]\n",
                fconfig->durability_opt, FDB_DRB_NONE, FDB_DRB_ODIRECT,
                FDB_DRB_ASYNC, FDB_DRB_ODIRECT_ASYNC);
        return false;
    }

    if ((fconfig->flags & FDB_OPEN_FLAG_CREATE) &&
        (fconfig->flags & FDB_OPEN_FLAG_RDONLY)) {
        fdb_log(NULL, FDB_RESULT_INVALID_ARGS,
                "Config Error: Open flags (%x) : Not recognized! "
                "[Allowed options: FDB_OPEN_FLAG_CREATE (%x),"
                " FDB_OPEN_FLAG_RDONLY (%x)]\n",
                fconfig->flags, FDB_OPEN_FLAG_CREATE, FDB_OPEN_FLAG_RDONLY);
        return false;
    }

    if (fconfig->compaction_threshold > 100) {
        // Compaction threshold should be equal or less then 100 (%).
        fdb_log(NULL, FDB_RESULT_INVALID_ARGS,
                "Config Error: Compaction threshold (%u) greater than 100!\n",
                fconfig->compaction_threshold);
        return false;
    }

    if (fconfig->compactor_sleep_duration == 0) {
        // Sleep duration should be larger than zero
        fdb_log(NULL, FDB_RESULT_INVALID_ARGS,
                "Config Error: Compactor sleep duration is ZERO (should be larger)!\n");
        return false;
    }

    if (!fconfig->num_wal_partitions ||
        (fconfig->num_wal_partitions > MAX_NUM_WAL_PARTITIONS)) {
        fdb_log(NULL, FDB_RESULT_INVALID_ARGS,
                "Config Error: Number of WAL partitions now within range: "
                "[0 < %u < %d]!\n",
                fconfig->num_wal_partitions, MAX_NUM_WAL_PARTITIONS);
        return false;
    }

    if (!fconfig->num_bcache_partitions ||
        (fconfig->num_bcache_partitions > MAX_NUM_BCACHE_PARTITIONS)) {
        fdb_log(NULL, FDB_RESULT_INVALID_ARGS,
                "Config Error: Number of bcache partitions now within range: "
                "[0 < %u < %d]!\n",
                fconfig->num_bcache_partitions, MAX_NUM_BCACHE_PARTITIONS);
        return false;
    }

    if (fconfig->max_writer_lock_prob < 20 ||
        fconfig->max_writer_lock_prob > 100) {
        fdb_log(NULL, FDB_RESULT_INVALID_ARGS,
                "Config Error: Max probability for compactor to grab writer lock "
                "not within allowed range: [20 <= %" _F64 " <= 100]!\n",
                (uint64_t)fconfig->max_writer_lock_prob);
        return false;
    }

    if (fconfig->num_compactor_threads < 1 ||
        fconfig->num_compactor_threads > MAX_NUM_COMPACTOR_THREADS) {
        fdb_log(NULL, FDB_RESULT_INVALID_ARGS,
                "Config Error: Num compactor threads not within allowed range: "
                "[1 <= %" _F64 " <= %d]!\n",
                (uint64_t)fconfig->num_compactor_threads, MAX_NUM_COMPACTOR_THREADS);
        return false;
    }

    if (fconfig->num_bgflusher_threads > MAX_NUM_BGFLUSHER_THREADS) {
        fdb_log(NULL, FDB_RESULT_INVALID_ARGS,
                "Config Error: Num bgflusher threads (%" _F64 ") greater than "
                "allowed value (%d)!\n",
                (uint64_t)fconfig->num_bgflusher_threads, MAX_NUM_BGFLUSHER_THREADS);
        return false;
    }
    if (fconfig->num_keeping_headers == 0) {
        // num_keeping_headers should be greater than zero
        return false;
    }
    if (fconfig->num_background_threads > FDB_EXPOOL_MAX_THREADS) {
        fdb_log(NULL, FDB_RESULT_INVALID_ARGS,
                "Config Error: Num background threads (%" _F64 ") greater than "
                "allowed value (%d)!\n",
                (uint64_t)fconfig->num_background_threads, FDB_EXPOOL_MAX_THREADS);
        return false;
    }

    return true;
}

bool validate_fdb_kvs_config(fdb_kvs_config *kvs_config) {
    return true;
}

