/* -*- Mode: C++; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2016 Couchbase, Inc
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

#pragma once

#include <string>

#include "common.h"
#include "docio.h"
#include "file_handle.h"
#include "internal_types.h"
#include "kvs_handle.h"

// Forward declarations
class FileMgr;
class BTreeBlkHandle;
class BnodeMgr;
class DocioHandle;
class HBTrie;
class BTree;
class BtreeV2;

/**
 * Abstraction that defines all operations related to compaction
 */
class Compaction {
public:
    Compaction() : fileMgr(nullptr), btreeHandle(nullptr), docHandle(nullptr),
                   keyTrie(nullptr), seqTree(nullptr), seqTrie(nullptr),
                   staleTree(nullptr), oldFileStaleOps(nullptr) { }

    /**
     * Compact a given file by copying its active blocks to the new file.
     *
     * @param fhandle Pointer to the file handle whose file is compacted
     * @param new_filename Name of a new compacted file
     * @param in_place_compaction Flag indicating if the new compacted file
     *        should be renamed to the old file after compaction
     * @param marker_bid Block id of a snapshot marker. The stale data up to this
     *        snapshot marker will be retained in the new file.
     * @param clone_docs Flag indicating if the compaction can be done through the
     *         block-level COW support from the host OS.
     * @param new_encryption_key Key with which to encrypt the new compacted file.
     *        To remove encryption, set the key's algorithm to FDB_ENCRYPTION_NONE.
     * @return FDB_RESULT_SUCCESS on success.
     */
    static fdb_status compactFile(FdbFileHandle *fhandle,
                                  const char *new_filename,
                                  bool in_place_compaction,
                                  bid_t marker_bid,
                                  bool clone_docs,
                                  const fdb_encryption_key *new_encryption_key);

private:

    /**
     * Check if a given file can be compacted or not.
     *
     * @param handle Pointer to the KV store handle of the file that is checked
     *        for the compaction readiness
     * @param new_filename Name of a new file for compaction
     * @return FDB_RESULT_SUCCESS if a given file can be compacted
     */
    static fdb_status checkCompactionReadiness(FdbKvsHandle *handle,
                                               const char *new_filename);

    /**
     * Create a new file for compaction.
     *
     * @param file_name Name of a new file for compaction
     * @param fconfig File manager configs for a new file
     * @param in_place_compaction Flag indicating if in-place compaction or not
     * @param handle Pointer to the KV store handle of the current file
     * @return FDB_RESULT_SUCCESS on a successful file creation
     */
    fdb_status createFile(const std::string file_name,
                          FileMgrConfig &fconfig,
                          bool in_place_compaction,
                          FdbKvsHandle *handle);

    /**
     * Clean up all the resources allocated in case of compaction failure
     */
    void cleanUpCompactionErr(FdbKvsHandle *handle);

    /**
     * Copy all the active blocks upto a given snapshot marker from the current
     * file to the new file
     *
     * @param rhandle Pointer to the KV store handle of the current file
     * @param marker_bid Block ID of a snapshot marker
     * @param last_hdr_bid Block ID of the last commit header
     * @param last_seq Last seq number of the current file
     * @param prob Write throttling probability
     * @param clone_docs Flag indicating if the compaction can be performed by the
     *        COW support from the host OS
     * @return FDB_RESULT_SUCCESS on a successful copy operation
     */
    fdb_status copyDocsUptoMarker(FdbKvsHandle *rhandle,
                                  bid_t marker_bid,
                                  bid_t last_hdr_bid,
                                  fdb_seqnum_t last_seq,
                                  size_t *prob,
                                  bool clone_docs);

    /**
     * Copy all the active blocks belonging to the last commit marker from
     * the current file to the new file
     *
     * @param handle Pointer to the KV store handle of the current file
     * @param prob Write throttling probability
     * @param clone_docs Flag indicating if the compaction can be performed by the
     *        COW support from the host OS
     * @return FDB_RESULT_SUCCESS on a successful copy operation
     */
    fdb_status copyDocs(FdbKvsHandle *handle,
                        size_t *prob,
                        bool clone_docs);

    /**
     * Copy all the active blocks from a given beginning block to ending block in
     * the current file to the new file
     *
     * @param handle Pointer to the KV store handle of the current file
     * @param begin_hdr Beginning block ID
     * @param end_hdr Ending block ID
     * @param compact_upto Flag indicating if this is invoked as part of
     *        fdb_compact_upto API call
     * @param clone_docs Flag indicating if the compaction can be performed by the
     *        COW support from the host OS
     * @param got_lock Flag indicating if the filemgr's lock on the current file is
     *        currently grabbed by the caller of this function
     * @param last_loop Flag indicating if this call is the last round of copying
     *        the delta blocks from the current file to the new file
     * @param prob Write throttling probability
     * @return FDB_RESULT_SUCCESS on a successful copy operation
     */
    fdb_status copyDelta(FdbKvsHandle *handle,
                         bid_t begin_hdr,
                         bid_t end_hdr,
                         bool compact_upto,
                         bool clone_docs,
                         bool got_lock,
                         bool last_loop,
                         size_t *prob);
    /**
     * Copy all the WAL blocks from a given beginning position to ending
     * position from the current file to the new file
     *
     * @param handle Pointer to the KV store handle of the current file
     * @param start_bid Beginning block ID
     * @param stop_bid Ending block ID
     * @return FDB_RESULT_SUCCESS on a successful copy operation
     */
    fdb_status copyWalDocs(FdbKvsHandle *handle,
                           bid_t start_bid,
                           bid_t stop_bid);

#ifdef _COW_COMPACTION
    /**
     * Copy all the active blocks belonging to the last commit marker from
     * the current file to the new file by using the block-level COW support
     * from the host OS.
     *
     * @param handle Pointer to the KV store handle of the current file
     * @param prob Write throttling probability
     */
    fdb_status cloneDocs(FdbKvsHandle *handle, size_t *prob);

    /**
     * Copy the given batch documents from the current file to the new file by
     * using the block-level COW support from the host OS.
     *
     * @param handle Pointer to the KV store handle of the current file
     * @param new_handle Pointer to the KV store handle of the new file
     * @param doc Pointer to the array containning documents to be copied
     * @param old_offset_array Pointer to the array containning the offsets of
     *        documents to be copied
     * @param n_buf Size of the document array
     * @param got_lock Flag indicating if the filemgr's lock on the current file is
     *        currently grabbed by the caller of this function
     * @param prob Write throttling probability
     * @param delay_us Write throttling time in microseconds
     */
    void cloneBatchedDelta(FdbKvsHandle *handle,
                           FdbKvsHandle *new_handle,
                           struct docio_object *doc,
                           uint64_t *old_offset_array,
                           uint64_t n_buf,
                           bool got_lock,
                           size_t *prob,
                           uint64_t delay_us);
#endif

    /**
     * Copy the given batch documents from the current file to the new file
     *
     * @param handle Pointer to the KV store handle of the current file
     * @param new_handle Pointer to the KV store handle of the new file
     * @param doc Pointer to the array containning documents to be copied
     * @param old_offset_array Pointer to the array containning the offsets of
     *        documents to be copied
     * @param n_buf Size of the document array
     * @param clone_docs Flag indicating if the compaction can be performed by the
     *        COW support from the host OS
     * @param got_lock Flag indicating if the filemgr's lock on the current file is
     *        currently grabbed by the caller of this function
     * @param prob Write throttling probability
     * @param delay_us Write throttling time in microseconds
     */
    void appendBatchedDelta(FdbKvsHandle *handle,
                            FdbKvsHandle *new_handle,
                            struct docio_object *doc,
                            uint64_t *old_offset_array,
                            uint64_t n_buf,
                            bool clone_docs,
                            bool got_lock,
                            size_t *prob,
                            uint64_t delay_us);

    /**
     * Commit the new file and set the old file's status to pending removal
     *
     * @param handle Pointer to the KV store handle of the new file
     * @param old_file Pointer to the old file manager
     * @return FDB_RESULT_SUCCESS if the operation is completed successfully
     */
    fdb_status commitAndRemovePending(FdbKvsHandle *handle,
                                      FileMgr *old_file);

    /**
     * Calculate the throttling delay time for a writer
     *
     * @param n_moved_docs Number of documents copied from the old file to
     *        the new files since a given start timestamp.
     * @param start_timestamp Start timestamp of the copy operation
     * @return Throttling delay time for a writer
     */
    uint64_t calculateWriteThrottlingDelay(uint64_t n_moved_docs,
                                           struct timeval start_timestamp);

    /**
     * Update the write throttling probability by calculating the throughput ratio
     * of the writer to the compactor
     *
     * @param writer_curr_bid ID of the block where the writer writes currently
     * @param compactor_curr_bid ID of the block where the compactor writes currently
     * @param writer_prev_bid ID of the block where the writer wrote first since
     *        the last update on the write throttling probability
     * @param compactor_prev_bid ID of the block where the compactor wrote first since
     *        the last update on the write throttling probability
     * @param prob Write throttling probability to be updated
     * @param max_prob Maximum write throttling probability allowed
     */
    void updateWriteThrottlingProb(bid_t writer_curr_bid,
                                   bid_t compactor_curr_bid,
                                   bid_t *writer_prev_bid,
                                   bid_t *compactor_prev_bid,
                                   size_t *prob,
                                   size_t max_prob);

    /**
     * Adjust the write throttling probability based on a given throughput ratio
     * of the writer to the compactor
     *
     * @param cur_ratio Throughput ratio of the writer to the compactor
     * @param prob Write throttling probability to be updated
     * @param max_prob Maximum write throttling probability allowed
     */
    void adjustWriteThrottlingProb(size_t cur_ratio,
                                   size_t *prob,
                                   size_t max_prob);


    FileMgr *fileMgr; // file manager instance for a new file
    union {
        BTreeBlkHandle *btreeHandle; // btree block handle for a new file
        BnodeMgr *bnodeMgr; // BTree Node Manager for the new file
    };
    DocioHandle *docHandle; // document block handle for a new file
    HBTrie *keyTrie; // key index trie for a new file
    union {
        BTree *seqTree; // seq index tree for a new file
        BtreeV2 *seqTreeV2; // seq index tree for a new file based on BtreeV2
    };
    HBTrie *seqTrie; // seq index trie for a new file
    union {
        BTree *staleTree; // stale block tree for a new file
        BtreeV2 *staleTreeV2; // stale block tree for a new file
    };
    BTreeKVOps *oldFileStaleOps; // stale ops of old file, freed on success!
};
