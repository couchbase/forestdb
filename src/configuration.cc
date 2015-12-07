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
    // 4096 WAL entries by default.
    fconfig.wal_threshold = 4096;
    fconfig.wal_flush_before_commit = true;
    fconfig.auto_commit = false;
    // 0 second by default.
    fconfig.purging_interval = 0;
    // Use a seq btree by default.
    fconfig.seqtree_opt = FDB_SEQTREE_USE;
    // Use a synchronous commit by default.
    fconfig.durability_opt = FDB_DRB_NONE;
    fconfig.flags = FDB_OPEN_FLAG_CREATE;
    // 4MB by default.
    fconfig.compaction_buf_maxsize = FDB_COMP_BUF_MINSIZE;
    // Clean up cache entries when a file is closed.
    fconfig.cleanup_cache_onclose = true;
    // Compress the body of documents using snappy.
    fconfig.compress_document_body = false;
    // Auto compaction is disabled by default
    fconfig.compaction_mode = FDB_COMPACTION_MANUAL;
    // Compaction threshold, 30% by default
    fconfig.compaction_threshold = FDB_DEFAULT_COMPACTION_THRESHOLD;
    fconfig.compaction_minimum_filesize = 1048576; // 1MB by default
    // 15 seconds by default
    fconfig.compactor_sleep_duration = FDB_COMPACTOR_SLEEP_DURATION;
    // Disable supporting multiple KV instances by default
    fconfig.multi_kv_instances = true;
    // 30 seconds by default
    fconfig.prefetch_duration = 30;

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
    // Block reusing threshold, 65% by default (i.e., almost 3x space amplification)
    fconfig.block_reusing_threshold = 65;
    // Keep at least 5 headers
    fconfig.num_keeping_headers = 5;

    fconfig.encryption_key.algorithm = FDB_ENCRYPTION_NONE;
    memset(fconfig.encryption_key.bytes, 0, sizeof(fconfig.encryption_key.bytes));

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
        return false;
    }
    if (fconfig->chunksize < sizeof(void *)) {
        // Chunk size should be equal to or greater than the address bus size
        return false;
    }
    if (fconfig->blocksize < 1024 || fconfig->blocksize > 131072) {
        // Block size should be set between 1KB and 128KB
        return false;
    }
    if (fconfig->seqtree_opt != FDB_SEQTREE_NOT_USE &&
        fconfig->seqtree_opt != FDB_SEQTREE_USE) {
        return false;
    }
    if (fconfig->durability_opt != FDB_DRB_NONE &&
        fconfig->durability_opt != FDB_DRB_ODIRECT &&
        fconfig->durability_opt != FDB_DRB_ASYNC &&
        fconfig->durability_opt != FDB_DRB_ODIRECT_ASYNC) {
        return false;
    }
    if ((fconfig->flags & FDB_OPEN_FLAG_CREATE) &&
        (fconfig->flags & FDB_OPEN_FLAG_RDONLY)) {
        return false;
    }
    if (fconfig->compaction_threshold > 100) {
        // Compaction threshold should be equal or less then 100 (%).
        return false;
    }
    if (fconfig->compactor_sleep_duration == 0) {
        // Sleep duration should be larger than zero
        return false;
    }
    if (!fconfig->num_wal_partitions ||
        (fconfig->num_wal_partitions > MAX_NUM_WAL_PARTITIONS)) {
        return false;
    }
    if (!fconfig->num_bcache_partitions ||
        (fconfig->num_bcache_partitions > MAX_NUM_BCACHE_PARTITIONS)) {
        return false;
    }
    if (fconfig->max_writer_lock_prob < 20 ||
        fconfig->max_writer_lock_prob > 100) {
        return false;
    }
    if (fconfig->num_compactor_threads < 1 ||
        fconfig->num_compactor_threads > MAX_NUM_COMPACTOR_THREADS) {
        return false;
    }
    if (fconfig->num_bgflusher_threads > MAX_NUM_BGFLUSHER_THREADS) {
        return false;
    }

    return true;
}

bool validate_fdb_kvs_config(fdb_kvs_config *kvs_config) {
    return true;
}

