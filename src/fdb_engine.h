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
    fdb_status rollback(fdb_kvs_handle **handle_ptr, fdb_seqnum_t rollback_seqnum);

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
    fdb_status rollbackAll(fdb_file_handle *fhandle,
                           fdb_snapshot_marker_t marker);

private:

    /**
     * Constructor
     *
     * @param config ForestDB global configurations
     */
    FdbEngine(const fdb_config &config);

    // Destructor
    ~FdbEngine();

    /**
     * Incr the file open in-progress counter
     */
    size_t incrOpenInProgCounter() {
        std::lock_guard<std::mutex> lock(instanceMutex);
        return ++fdbOpenInProg;
    }

    /**
     * Decr the file open in-progress counter
     */
    size_t decrOpenInProgCounter() {
        std::lock_guard<std::mutex> lock(instanceMutex);
        return --fdbOpenInProg;
    }

    /**
     * Get the file open in-progress counter
     */
    size_t getOpenInProgCounter() {
        return fdbOpenInProg;
    }

    // Singleton ForestDB engine instance and mutex guarding it's creation.
    static std::atomic<FdbEngine *> instance;
    static std::mutex instanceMutex;

    volatile size_t fdbOpenInProg;
};
