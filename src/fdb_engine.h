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

#include <stdint.h>

#include "common.h"
#include "configuration.h"
#include "internal_types.h"
#include "file_handle.h"
#include "kvs_handle.h"
#include "bnode.h"

/**
 * Class that defines the list of callback functions invoked for each WAL item
 * during the WAL flush
 */
class WalFlushCallbacks {
public:
    static fdb_status flushItem(void *dbhandle,
                                struct wal_item *item,
                                struct avl_tree *stale_seqnum_list,
                                struct avl_tree *kvs_delta_stats);

    static uint64_t getOldOffset(void *dbhandle,
                                 struct wal_item *item);

    static void purgeSeqTreeEntry(void *dbhandle,
                                  struct avl_tree *stale_seqnum_list,
                                  struct avl_tree *kvs_delta_stats);

    static void updateKvsDeltaStats(FileMgr *file,
                                    struct avl_tree *kvs_delta_stats);

};

/**
 * ForestDB engine that implements all the public APIs defined in ForestDB's
 * public header.
 */
class FdbEngine {
public:

    /**
     * Instantiate the singleton ForestDB engine.
     *
     * @param config ForestDB global configurations
     * @return FDB_RESULT_SUCCESS if the init is completed successfully
     */
    static fdb_status init(fdb_config *config);

    /**
     * Get the singleton instance of the ForestDB engine.
     */
    static FdbEngine* getInstance();

    /**
     * Destroy the ForestDB engine.
     */
    static fdb_status destroyInstance();

    /**
     * Return the ForestDB's default configs
     */
    static fdb_config getDefaultConfig() {
        return get_default_config();
    }

    /**
     * Return the ForestDB KV store's default configs
     */
    static fdb_kvs_config getDefaultKvsConfig() {
        return get_default_kvs_config();
    }

    /**
     * Check if a given forestdb config is valid or not
     *
     * @param config ForestDB config to be validated
     * @return True if a config is valid
     */
    static bool validateFdbConfig(fdb_config &config) {
        return validate_fdb_config(&config);
    }

    /**
     * Init a file manager config using a given ForestDB config
     *
     * @param config ForestDB config
     * @param fconfig File manager config
     */
    static void initFileConfig(const fdb_config *config,
                               FileMgrConfig *fconfig);

    /**
     * Incr the file open in-progress counter
     */
    static size_t incrOpenInProgCounter() {
        LockHolder lock(instanceMutex);
        return ++fdbOpenInProg;
    }

    /**
     * Decr the file open in-progress counter
     */
    static size_t decrOpenInProgCounter() {
        LockHolder lock(instanceMutex);
        return --fdbOpenInProg;
    }

    /**
     * Get the file open in-progress counter
     */
    static size_t getOpenInProgCounter() {
        return fdbOpenInProg;
    }

    /**
     * Open a ForestDB file.
     * The file should be closed with closeFile API call.
     *
     * @param ptr_fhandle Pointer to the place where ForestDB file handle is
     *        instantiated as result of this API call.
     * @param filename Name of the ForestDB file to be opened.
     * @param fconfig Pointer to the config instance that contains ForestDB configs.
     *        If NULL is passed, then we use default settings of ForestDB configs.
     * @return FDB_RESULT_SUCCESS on success.
     */
    fdb_status openFile(FdbFileHandle **ptr_fhandle,
                        const char *filename,
                        fdb_config &fconfig);

    /**
     * Open a ForestDB file.
     * Note that if any KV store in the file uses a customized compare function,
     * then the file should be opened with this API by passing the list of all KV
     * instance names that use customized compare functions, and their corresponding
     * customized compare functions.
     *
     * Documents in the file will be indexed using their corresponding
     * customized compare functions. The file should be closed with closeFile
     * API call.
     *
     * @param ptr_fhandle Pointer to the place where ForestDB file handle is
     *        instantiated as result of this API call.
     * @param filename Name of the ForestDB file to be opened.
     * @param fconfig Pointer to the config instance that contains ForestDB configs.
     *        If NULL is passed, then we use default settings of ForestDB configs.
     * @param num_functions The number of customized compare functions.
     * @param kvs_names List of KV store names to be indexed using the customized
     *        compare functions.
     * @param functions List of customized compare functions corresponding to each
     *        KV store listed in kvs_names.
     * @return FDB_RESULT_SUCCESS on success.
     */
    fdb_status openFileWithCustomCmp(FdbFileHandle **ptr_fhandle,
                                     const char *filename,
                                     fdb_config &fconfig,
                                     size_t num_functions,
                                     char **kvs_names,
                                     fdb_custom_cmp_variable *functions);

    /**
     * Open a ForestDB file with a given file name and ForestDB configs
     * TODO: Need to move this function to a private member
     *
     * @param handle Pointer to a KV store handle
     * @param filename Name of the ForestDB file to be opened
     * @param filename_mode Type of a file name
     * @param config Pointer to the ForestDB configs
     * @return FDB_RESULT_SUCCESS on a successful file open
     */
    fdb_status openFdb(FdbKvsHandle *handle,
                       const char *filename,
                       fdb_filename_mode_t filename_mode,
                       const fdb_config *config);

    /**
     * Set up the error logging callback that allows an application to process
     * error code and message from ForestDB.
     *
     * @param handle Pointer to ForestDB KV store handle.
     * @param log_callback Logging callback function that receives and processes
     *        error codes and messages from ForestDB.
     * @param ctx_data Pointer to application-specific context data that is going
     *        to be passed to the logging callback function.
     * @return FDB_RESULT_SUCCESS on success.
     */
    fdb_status setLogCallback(FdbKvsHandle *handle,
                              fdb_log_callback log_callback,
                              void *ctx_data);

    /**
     * Retrieve the metadata and doc body for a given key.
     * Note that FDB_DOC instance should be created by calling
     * fdb_doc_create(doc, key, keylen, NULL, 0, NULL, 0) before using this API.
     *
     * @param handle Pointer to ForestDB KV store handle.
     * @param doc Pointer to ForestDB doc instance whose metadata and doc body
     *        are populated as a result of this API call.
     * @param metaOnly Flag indicating if a key's metadata should be only retrieved.
     * @return FDB_RESULT_SUCCESS on success.
     */
    fdb_status get(FdbKvsHandle *handle,
                   fdb_doc *doc,
                   bool metaOnly);

    /**
     * Retrieve the metadata and doc body for a given sequence number.
     * Note that FDB_DOC instance should be created by calling
     * fdb_doc_create(doc, NULL, 0, NULL, 0, NULL, 0) before using this API.
     *
     * @param handle Pointer to ForestDB KV store handle.
     * @param doc Pointer to ForestDB doc instance whose key, metadata and doc body
     *        are populated as a result of this API call.
     * @param metaOnly Flag indicating if a key's metadata should be only retrieved.
     * @return FDB_RESULT_SUCCESS on success.
     */
    fdb_status getBySeq(FdbKvsHandle *handle,
                        fdb_doc *doc,
                        bool metaOnly);

    /**
     * Retrieve a doc's metadata and body with a given doc offset in the file.
     * Note that FDB_DOC instance should be first instantiated and populated
     * by calling fdb_get_metaonly, fdb_get_metaonly_byseq, or
     * fdb_iterator_next_offset, which returns an offset to a doc. Then,
     * the FDB_DOC instance and the offset should be passed together to this API.
     *
     * WARNING: If the document was deleted but not yet purged, then the metadata
     *          will still be populated in the fdb_doc passed into the function,
     *          even though the return code is FDB_RESULT_KEY_NOT_FOUND.
     *
     * @param handle Pointer to ForestDB KV store handle.
     * @param doc Pointer to ForestDB doc instance that contains the offset to a doc
     *        and whose doc body is populated as a result of this API call.
     * @return FDB_RESULT_SUCCESS on success.
     */
    fdb_status getByOffset(FdbKvsHandle *handle,
                           fdb_doc *doc);

    /**
     * Update the metadata and doc body for a given key.
     * Note that FDB_DOC instance should be created by calling
     * fdb_doc_create(doc, key, keylen, meta, metalen, body, bodylen) before using
     * this API. Setting "deleted" flag in FDB_DOC instance to true is equivalent to
     * calling fdb_del api described below.
     *
     * @param handle Pointer to ForestDB KV store handle.
     * @param doc Pointer to ForestDB doc instance that is used to update a key.
     * @return FDB_RESULT_SUCCESS on success.
     */
    fdb_status set(FdbKvsHandle *handle,
                   fdb_doc *doc);

    /**
     * Delete a key, its metadata and value
     * Note that FDB_DOC instance should be created by calling
     * fdb_doc_create(doc, key, keylen, meta, metalen, body, bodylen) before using
     * this API.
     *
     * @param handle Pointer to ForestDB KV store handle.
     * @param doc Pointer to ForestDB doc instance that is used to delete a key.
     * @return FDB_RESULT_SUCCESS on success.
     */
    fdb_status del(FdbKvsHandle *handle,
                   fdb_doc *doc);

    /**
     * Simplified get API without key's metadata:
     * Retrieve the value (doc body in fdb_get) for a given key.
     *
     * @param handle Pointer to ForestDB KV store handle.
     * @param key Pointer to the key to be retrieved.
     * @param keylen Length of the key.
     * @param value_out Pointer to the value as a result of this API call. Note that this
     *        pointer should be released using free().
     * @param valuelen_out Length of the value as a result of this API call.
     * @return FDB_RESULT_SUCCESS on success.
     */
    fdb_status getKeyValue(FdbKvsHandle *handle,
                           const void *key, size_t keylen,
                           void **value_out, size_t *valuelen_out);

    /**
     * Simplified set API without key's metadata:
     * Update the value (doc body in fdb_set) for a given key.
     *
     * @param handle Pointer to ForestDB KV store handle.
     * @param key Pointer to the key to be updated.
     * @param keylen Length of the key.
     * @param value Pointer to the value corresponding to the key.
     * @param valuelen Length of the value.
     * @return FDB_RESULT_SUCCESS on success.
     */
    fdb_status setKeyValue(FdbKvsHandle *handle,
                           const void *key, size_t keylen,
                           const void *value, size_t valuelen);

    /**
     * Simplified del API with a key:
     * Delete a key and its value.
     *
     * @param handle Pointer to ForestDB KV store handle.
     * @param key Pointer to the key to be deleted.
     * @param keylen Length of the key.
     * @return FDB_RESULT_SUCCESS on success.
     */
    fdb_status delKey(FdbKvsHandle *handle,
                      const void *key, size_t keylen);

    /**
     * Commit all pending changes on a ForestDB file into disk.
     * Note that this API should be invoked with a ForestDB file handle.
     *
     * @param fhandle Pointer to ForestDB file handle.
     * @param opt Commit option.
     * @return FDB_RESULT_SUCCESS on success.
     */
    fdb_status commit(FdbFileHandle *fhandle, fdb_commit_opt_t opt);

    /**
     * Commit all dirty blocks with a given KV handle
     *
     * @param root_handle Pointer to the root KV handle
     * @param opt Commit option
     * @param sync Flag indicating if fsync should be performed or not
     * @return FDB_RESULT_SUCCESS on success
     */
    fdb_status commitWithKVHandle(FdbKvsHandle *handle,
                                  fdb_commit_opt_t opt,
                                  bool sync);
    /**
     * Create a snapshot of a KV store.
     *
     * @param handle_in ForestDB KV store handle pointer from which snapshot is to be made
     * @param handle_out Pointer to KV store snapshot handle, close with fdb_kvs_close()
     * @param snapshot_seqnum The sequence number or snapshot marker of snapshot.
     *        Note that this seq number should correspond to one of the commits
     *        that have been persisted for a given KV store instance.
     *        To create an in-memory snapshot for a given KV store, pass
     *        FDB_SNAPSHOT_INMEM as the sequence number.
     *        In-memory snapshot is a non-durable consistent copy of the KV store
     *        instance and carries the latest version of all the keys at the point
     *        of the snapshot and can even be taken out of uncommitted transaction.
     * @return FDB_RESULT_SUCCESS on success.
     *         FDB_RESULT_INVALID_ARGS if any input param is NULL, or,
     *                                 if sequence number tree is not enabled
     *         Any other error from fdb_open may be returned
     */
    fdb_status openSnapshot(FdbKvsHandle *handle_in,
                            FdbKvsHandle **handle_out,
                            fdb_seqnum_t snapshot_seqnum);

    /**
     * Rollback a KV store to a specified point represented by a given sequence
     * number.
     *
     * @param handle_ptr ForestDB KV store handle that needs to be rolled back.
     * @param rollback_seqnum sequence number or rollback point marker of snapshot
     * @return FDB_RESULT_SUCCESS on success.
     *         FDB_RESULT_INVALID_ARGS if any input param is NULL, or,
     *                                 if sequence number tree is not enabled
     *         Any other error from fdb_open may be returned
     */
    fdb_status rollback(FdbKvsHandle **handle_ptr, fdb_seqnum_t rollback_seqnum);

    /**
     * Rollback all the KV stores in a file to a specified point represented by
     * a file-level snapshot marker returned by fdb_get_all_snap_markers api.
     *
     * @param fhandle ForestDB file handle.
     * @param marker file level marker or the rollback point of all KV stores
     * @return FDB_RESULT_SUCCESS on success.
     *         FDB_RESULT_HANDLE_BUSY if there are multiple kv stores used whose
     *                                handles have not yet been closed
     */
    fdb_status rollbackAll(FdbFileHandle *fhandle,
                           fdb_snapshot_marker_t marker);

    /**
     * Compact the current file and create a new compacted file.
     * Note that a new file name passed to this API will be ignored if the compaction
     * mode of the handle is auto-compaction (i.e., FDB_COMPACTION_AUTO). In the auto
     * compaction mode, the name of a new compacted file will be automatically generated
     * by increasing its current file revision number.
     *
     * If a new file name is not given (i.e., NULL is passed) in a manual compaction
     * mode, then a new file name will be automatically created by appending
     * a file revision number to the original file name. Also note that if a given
     * ForestDB file is currently being compacted by the compaction daemon, then
     * FDB_RESULT_FILE_IS_BUSY is returned to the caller.
     *
     * @param fhandle Pointer to ForestDB file handle
     * @param new_filename Name of a new compacted file
     * @param marker Snapshot marker retrieved from fdb_get_all_snap_markers() API,
     *        indicating the stale data up to a given snapshot marker will be
     *        retained in the new file.
     * @param clone_docs Flag indicating if the compaction can be done through the
     *         block-level COW support from the host OS. Currently, Btrfs
     *         supports the block-level COW for compaction.
     * @param new_encryption_key Key with which to encrypt the new compacted file.
     *        To remove encryption, set the key's algorithm to FDB_ENCRYPTION_NONE.
     * @return FDB_RESULT_SUCCESS on success.
     */
    fdb_status compact(FdbFileHandle *fhandle,
                       const char *new_filename,
                       fdb_snapshot_marker_t marker,
                       bool clone_docs,
                       const fdb_encryption_key *new_encryption_key);

    /**
     * Cancel the compaction task if it is running currently.
     *
     * @param fhandle Pointer to ForestDB file handle
     * @return FDB_RESULT_SUCCESS on successful cancellation.
     */

    fdb_status cancelCompaction(FdbFileHandle *fhandle);

    /**
     * Set the daemon compaction interval for a given file.
     *
     * @param fhandle Pointer to ForestDB file handle.
     * @param interval Daemon compaction intervel to be set for a given file
     * @return FDB_RESULT_SUCCESS on successful compaction interval change.
     */
    fdb_status setDaemonCompactionInterval(FdbFileHandle *fhandle,
                                           size_t interval);

    /**
     * Change the database file's encryption, by compacting it while writing
     * with a new key.
     * @param fhandle Pointer to ForestDB file handle.
     * @param new_key Key with which to encrypt the new file. To remove encryption,
     * set the key's algorithm to FDB_ENCRYPTION_NONE.
     * @return FDB_RESULT_SUCCESS on success.
     */
    fdb_status reKey(FdbFileHandle *fhandle,
                     fdb_encryption_key new_key);

    /**
     * Return the overall buffer cache space actively used by all ForestDB files.
     * Note that this does not include space in WAL, hash tables and other
     * in-memory data structures allocated by ForestDB api
     *
     * @return Size of buffer cache currently used.
     */
    size_t getBufferCacheUsed();

    /**
     * Return the overall disk space actively used by a ForestDB file.
     * Note that this doesn't include the disk space used by stale btree nodes
     * and docs.
     *
     * @param fhandle Pointer to ForestDB file handle.
     * @return Disk space actively used by a ForestDB file.
     */
    size_t estimateSpaceUsed(FdbFileHandle *fhandle);

    /* Internal function to estimate space used
     * @param - root handle
     * @return Disk space actively used by a ForestDB file.
     */
    size_t estimateSpaceUsedInternal(FdbKvsHandle *handle);

    /**
     * Return the overall disk space actively used by all snapshots starting from
     * a given snapshot marker.
     * Note that this doesn't include the disk space used by stale btree nodes
     * and docs.
     *
     * @param fhandle Pointer to ForestDB file handle.
     * @param marker Snapshot marker returned by fdb_get_all_snap_markers()
     * @return Disk space actively used by all snapshots starting from a given
     *         snapshot marker. fdb_log used internally to log errors.
     *
     */
    size_t estimateSpaceUsedFrom(FdbFileHandle *fhandle,
                                 fdb_snapshot_marker_t marker);

    /**
     * Return the information about a ForestDB file.
     *
     * @param fhandle Pointer to ForestDB file handle.
     * @param info Pointer to ForestDB File Info instance.
     * @return FDB_RESULT_SUCCESS on success.
     */
    fdb_status getFileInfo(FdbFileHandle *fhandle, fdb_file_info *info);

    /**
     * Return the information about a ForestDB KV store instance.
     *
     * @param handle Pointer to ForestDB KV store handle.
     * @param info Pointer to KV Store Info instance.
     * @return FDB_RESULT_SUCCESS on success.
     */
    fdb_status getKvsInfo(FdbKvsHandle *handle, fdb_kvs_info *info);

    /**
     * Return the information about operational counters in a ForestDB KV store.
     *
     * @param handle Pointer to ForestDB KV store handle.
     * @param info Pointer to KV Store Ops Info instance.
     * @return FDB_RESULT_SUCCESS on success.
     */
    fdb_status getKvsOpsInfo(FdbKvsHandle *handle, fdb_kvs_ops_info *info);

    /**
     * Return the latency information about various forestdb api calls
     *
     * @param fhandle Pointer to ForestDB file handle
     * @param stats Pointer to a latency_stats instance
     * @param type Type of latency stat to be retrieved
     * @return FDB_RESULT_SUCCESS on success.
     */
    fdb_status getLatencyStats(FdbFileHandle *fhandle,
                               fdb_latency_stat *stats,
                               fdb_latency_stat_type type);

    /**
     * Returns a histogram of latencies for various forestdb api calls
     * (Works with Couchbase Server Build only)
     *
     * @param fhandle Pointer to ForestDB file handle
     * @param stats Char pointer to stats (need to be freed from heap
     *              by client on SUCCESS)
     * @param stats_length Pointer to the length of the buffer pointed to by the
     *                     stats pointer
     * @param type Type of latency stat to be retrieved
     * @return FDB_RESULT_SUCCESS on success.
     */
    fdb_status getLatencyHistogram(FdbFileHandle *fhandle,
                                   char **stats,
                                   size_t *stats_length,
                                   fdb_latency_stat_type type);

    /**
     * Get the current sequence number of a ForestDB KV store instance.
     *
     * @param handle Pointer to ForestDB KV store handle.
     * @param seqnum Pointer to the variable that sequence number will be returned.
     * @return FDB_RESULT_SUCCESS on success.
     */
    fdb_status getKvsSeqnum(FdbKvsHandle *handle, fdb_seqnum_t *seqnum);

    /**
     * Return the name of the latency stat
     *
     * @param type The type of the latency stat to be named.
     * @return const char pointer to the stat name. This must not be freed.
     */
    static const char * getLatencyStatName(fdb_latency_stat_type type);

    /**
     * Get all KV store names in a ForestDB file.
     *
     * @param fhandle Pointer to ForestDB file handle.
     * @param kvs_name_list Pointer to a KV store name list. Note that this list
     *        should be released using fdb_free_kvs_name_list API call().
     * @return FDB_RESULT_SUCCESS on success.
     */
    fdb_status getKvsNameList(FdbFileHandle *fhandle,
                              fdb_kvs_name_list *kvs_name_list);

    /**
     * Return all the snapshot markers in a ForestDB file.
     *
     * @param fhandle Pointer to ForestDB file handle.
     * @param markers Pointer to the allocated array of snapshot_info instances
     *                that correspond to each of the commit markers in a file.
     * @param size Number of elements of the markers that are allocated.
     * @return file i/o or other on failure, FDB_RESULT_SUCCESS if successful.
     *
     */
    fdb_status getAllSnapMarkers(FdbFileHandle *fhandle,
                                 fdb_snapshot_info_t **markers,
                                 uint64_t *size);

    /**
     * Returns the last available rollback sequence number for a given
     * sequence number of a KV store.
     *
     * @param handle Pointer to ForestDB kvs handle.
     * @param request_seqno Sequence number to rollback to.
     * @return last available rollback sequence number.
     *
     */
    fdb_seqnum_t getAvailableRollbackSeq(FdbKvsHandle *handle,
                                         uint64_t request_seqno);

    /**
     * Free a kv snapshot_info array allocated by getAllSnapMarkers API.
     *
     * @param markers Pointer to a KV snapshot_info array that is allocated by
     *        fdb_get_all_snap_markers API.
     * @param size Number of elements in above array.
     * @return FDB_RESULT_SUCCESS on success.
     */
    fdb_status freeSnapMarkers(fdb_snapshot_info_t *markers, uint64_t size);

    /**
     * Free a KV store name list allocated by getKvsNameList API.
     *
     * @param kvs_name_list Pointer to a KV store name list to be freed.
     * @return FDB_RESULT_SUCCESS on success.
     */
    fdb_status freeKvsNameList(fdb_kvs_name_list *kvs_name_list);

    /**
     * Change the compaction mode of a ForestDB file referred by the handle passed.
     * If the mode is changed to auto-compaction (i.e., FDB_COMPACTION_AUTO),
     * the compaction threshold is set to the threshold passed to this API.
     * This API can be also used to change the compaction threshould for a ForestDB file
     * whose compaction mode is currently auto-compaction.
     *
     * Note that all the other handles referring the same ForestDB file should be closed
     * before this API call, and no concurrent operation should be performed on the same
     * file until the mode switching is done.
     *
     * @param fhandle Pointer to ForestDB file handle.
     * @param mode New compaction mode to be set.
     * @param new_threshold New compaction threshold to be set.
     * @return FDB_RESULT_SUCCESS on success.
     */
    fdb_status switchCompactionMode(FdbFileHandle *fhandle,
                                    fdb_compaction_mode_t mode,
                                    size_t new_threshold);

    /**
     * Close a ForestDB file.
     *
     * @param fhandle Pointer to ForestDB file handle.
     * @return FDB_RESULT_SUCCESS on success.
     */
    fdb_status closeFile(FdbFileHandle *fhandle);

    /**
     * Close the KV store handle
     *
     * @param handle Pointer to the KV store handle
     * @return FDB_RESULT_SUCCESS on success.
     */
    fdb_status closeKVHandle(FdbKvsHandle *handle);

    /**
     * Destroy all resources associated with a ForestDB file permanently
     * (e.g., buffer cache, in-memory WAL, indexes, daemon compaction thread)
     * including current and past versions of the file.
     * Note that all handles on the file should be closed through fdb_close
     * calls before calling this API.
     *
     * NOTE: If manual compaction is being used, fdb_destroy() is best-effort only
     *       and must be called with the correct filename
     * Reason for best-effort in manual compaction case:
     * FileA --> FileB --> FileC --> FileA --> FileD --> FileC -->DESTROY
     * (In above case, FileB cannot be destroyed as its info is not
     *  reachable from file path "FileC", api will wipe out FileA, FileC and FileD)
     *
     * @param filename The file path that needs to be destroyed
     * @param fconfig  The forestdb configuration to determine
     *        error log callbacks, manual/auto compaction etc
     * @return FDB_RESULT_SUCCESS on success.
     */
    static fdb_status destroyFile(const char *filename,
                                  fdb_config *fconfig);

    /**
     * Begin a transaction with a given ForestDB file handle and isolation level.
     * The transaction should be closed with fdb_end_transaction API call.
     * The isolation levels supported are "read committed" or "read uncommitted".
     * We plan to support both serializable and repeatable read isolation levels
     * in the upcoming releases. For more information about database isolation levels,
     * please refer to the following link:
     * http://en.wikipedia.org/wiki/Isolation_level
     *
     * @param fhandle Pointer to ForestDB file handle.
     * @param isolation_level Isolation level (i.e., read_committed or read_uncommitted)
     *        of the transaction.
     * @return FDB_RESULT_SUCCESS on success.
     */
    fdb_status beginTransaction(FdbFileHandle *fhandle,
                                fdb_isolation_level_t isolation_level);

    /**
     * End a transaction for a given ForestDB file handle by commiting all the dirty
     * updates and releasing all the resouces allocated for that transaction.
     *
     * @param fhandle Pointer to ForestDB file handle.
     * @param opt Commit option.
     * @return FDB_RESULT_SUCCESS on success.
     */
    fdb_status endTransaction(FdbFileHandle *fhandle,
                              fdb_commit_opt_t opt);

    /**
     * Abort the transaction for a given ForestDB file handle.
     * All uncommitted dirty updates in the handle will be discarded.
     *
     * @param fhandle Pointer to ForestDB file handle.
     * @return FDB_RESULT_SUCCESS on success.
     */
    fdb_status abortTransaction(FdbFileHandle *fhandle);

    /**
     * Open the KV store with a given instance name.
     * The KV store should be closed with closeKvs API call.
     *
     * @param fhandle Pointer to ForestDB file handle.
     * @param ptr_handle Pointer to the place where the KV store handle is
     *        instantiated as a result of this API call.
     * @param kvs_name The name of KV store to be opened. If the name is not given
     *        (i.e., NULL is passed), the KV store instance named "default" will be
     *        returned.
     * @param config Pointer to the config instance that contains KV store configs.
     *        If NULL is passed, then we use default settings of KV store configs.
     * @return FDB_RESULT_SUCCESS on success.
     */
    fdb_status openKvs(FdbFileHandle *fhandle,
                       FdbKvsHandle **ptr_handle,
                       const char *kvs_name,
                       fdb_kvs_config *config);

    /**
     * Open the default KV store.
     * The KV store should be closed with closeKvs API call.
     *
     * @param fhandle Pointer to ForestDB file handle.
     * @param ptr_handle Pointer to the place where the KV store handle is
     *        instantiated as a result of this API call.
     * @param config Pointer to the config instance that contains KV store configs.
     *        If NULL is passed, then we use default settings of KV store configs.
     * @return FDB_RESULT_SUCCESS on success.
     */
    fdb_status openDefaultKvs(FdbFileHandle *fhandle,
                              FdbKvsHandle **ptr_handle,
                              fdb_kvs_config *config);

    /**
     * Close the KV store.
     *
     * @param handle Pointer to KV store handle.
     * @return FDB_RESULT_SUCCESS on success.
     */
    fdb_status closeKvs(fdb_kvs_handle *handle);

    /**
     * Permanently drop a given KV store instance from a ForestDB file.
     *
     * @param fhandle Pointer to ForestDB file handle.
     * @param kvs_name The name of KV store instance to be removed. If the name is
     *        not given (i.e., NULL is passed), the KV store instance named "default"
     *        will be dropped.
     * @return FDB_RESULT_SUCCESS on success.
     */
    fdb_status removeKvs(fdb_file_handle *fhandle,
                         const char *kvs_name);

    /**
     * Change the config parameters for reusing stale blocks
     *
     * @param fhandle Pointer to ForestDB file handle.
     * @param block_reusing_threshold Circular block reusing threshold in the unit of
     *        percentage(%), which can be represented as
     *        '(stale data size)/(total file size)
     *        When stale data size grows beyond this threshold, circular block reusing is
     *        triggered so that stale blocks are reused for further block allocations.
     *        Block reusing is disabled if this threshold is set to zero or 100.
     * @param num_keeping_headers Number of the last commit headers whose stale blocks
     *        should be kept for snapshot readers
     * @return FDB_RESULT_SUCCESS on success.
     */
    fdb_status setBlockReusingParams(FdbFileHandle *fhandle,
                                     size_t block_reusing_threshold,
                                     size_t num_keeping_headers);
    /**
     * Retrieve ForestDB error code as a string
     *
     * @param  err_code Error code
     * @return A text string that describes an error code. Note that the string
     *         returned is a constant. The application must not try to modify
     *         it or try to free the pointer to this string.
     */
    static const char* getErrorMsg(fdb_status err_code);

    /**
     * Return the string representation of ForestDB library version that is based on
     * git-describe output.
     *
     * @return A text string that represents ForestDB library version
     */
    static const char* getLibVersion();

    /**
     * Return the version of a given ForestDB file.
     *
     * @param fhandle Pointer to ForestDB file handle whose file version is returned.
     * @return Version of a given ForestDB file.
     */
    const char* getFileVersion(fdb_file_handle *fhandle);

    /**
     * Return the default file operations used by ForestDB.
     *
     * @return pointer to the struct having all the default file operations
     */
    static fdb_filemgr_ops_t* getDefaultFileOps();

    /**
     * Fetch handle stats for the ForestDB KV store instance
     *
     * @param handle Pointer to the KV store instance
     * @param callback Callback that is invoked for every stat fetched
     * @param ctx Client context that is passed to the callback
     *
     * @return FDB_RESULT_SUCCESS on success
     */
    static fdb_status fetchHandleStats(fdb_kvs_handle *handle,
                                       fdb_handle_stats_cb callback,
                                       void *ctx);
    /**
     * Callback function for HB+trie, to get custom compare function for the
     * given KVS ID.
     *
     * @param hbtrie HB+trie instance.
     * @param kvs_id KVS ID.
     * @param aux Auxiliary parameter.
     * @return Pointer to custom compare function.
     */
    static btree_new_cmp_func* getCmpFuncCB(HBTrie *hbtrie,
                                            uint64_t kvs_id,
                                            void *aux);

private:

    friend class Compaction;

    /**
     * Constructor
     *
     * @param config ForestDB global configurations
     */
    FdbEngine(const fdb_config &config);

    // Destructor
    ~FdbEngine();

    /**
     * Close the root KV store handle.
     *
     * @param handle Pointer to the root KV store handle
     * @return FDB_RESULT_SUCCESS on success.
     */
    fdb_status closeRootHandle(FdbKvsHandle *handle);

    /**
     * Open the KV store with a given file and KV store name.
     *
     * @param root_handle Pointer to the root KV store handle
     * @param config  ForestDB config
     * @param kvs_config KV store config
     * @param file Pointer to the file manager instance
     * @param filename ForestDB file's name
     * @param kvs_name The name of KV store to be opened. If the name is not given
     *        (i.e., NULL is passed), the KV store instance named "default" will be
     *        returned.
     * @param handle Pointer to the KV store handle that is initialized by this function
     * @return FDB_RESULT_SUCCESS on success.
     */
    fdb_status openKvs(FdbKvsHandle *root_handle,
                       fdb_config *config,
                       fdb_kvs_config *kvs_config,
                       FileMgr *file,
                       const char *filename,
                       const char *kvs_name,
                       FdbKvsHandle *handle);

    /**
     * Rollback a KV store to a given sequence number
     *
     * @param handle_ptr Pointer to the KV store
     * @param seqnum Sequence number of the rollback
     * @return FDB_RESULT_SUCCESS on success.
     */
    fdb_status rollbackKvs(FdbKvsHandle **handle_ptr,
                           fdb_seqnum_t seqnum);

    /**
     * Create a KV store with a given name
     *
     * @param root_handle Pointer to the root KV store handle
     * @param kvs_name KV store's name
     * @param kvs_config KV store's config
     * @return FDB_RESULT_SUCCESS on success
     */
    fdb_status createKvs(FdbKvsHandle *root_handle,
                         const char *kvs_name,
                         fdb_kvs_config *kvs_config);

    /**
     * Close the KV store
     *
     * @param handle Pointer to the KV store handle
     * @return FDB_RESULT_SUCCESS on success
     */
    fdb_status closeKvsInternal(FdbKvsHandle *handle);

    /**
     * Permanently drop a given KV store instance from a ForestDB file.
     *
     * @param fhandle Pointer to ForestDB file handle.
     * @param kvs_name The name of KV store instance to be removed. If the name is
     *        not given (i.e., NULL is passed), the KV store instance named "default"
     *        will be dropped.
     * @param rollback_recreate Flag indicating if the request is to drop the KV store
     *        and recreate it
     * @return FDB_RESULT_SUCCESS on success.
     */
    fdb_status removeKvs(FdbFileHandle *fhandle,
                         const char *kvs_name,
                         bool rollback_recreate);

    /**
     * Check if any KV store handle is still opened and active in the file handle
     *
     * @param fhandle Pointer to the file handle
     * @param kv_id KV store's ID
     * @return True if any KV store handle is still active in the file handle
     */
    bool isAnyKvsHandleOpened(FdbFileHandle *fhandle,
                              fdb_kvs_id_t kv_id);

    // Singleton ForestDB engine instance and mutex guarding it's creation.
    static std::atomic<FdbEngine *> instance;
    static std::mutex instanceMutex;
    // Number of open API calls that are currently running.
    static volatile size_t fdbOpenInProg;
};
