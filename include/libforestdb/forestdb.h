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

#ifndef _JSAHN_FDB_H
#define _JSAHN_FDB_H

#include "fdb_errors.h"
#include "fdb_types.h"

#if defined(_MSC_VER) && !defined(_FDB_TOOLS)
    #ifdef forestdb_EXPORTS
        #define LIBFDB_API extern __declspec(dllexport)
    #else
        #define LIBFDB_API extern __declspec(dllimport)
    #endif
#elif defined __GNUC__
    #define LIBFDB_API __attribute ((visibility("default")))
#else
    #define LIBFDB_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Initialize all global resources (e.g., buffer cache, daemon compaction thread, etc.)
 * for ForestDB engine, using the given configurations. Note that all open API
 * calls automatically invoke this API if ForestDB engine is not initialized.
 *
 * @param config Pointer to the config instance that contains ForestDB configs.
 *               If NULL is passed, then we use default settings of ForestDB configs.
 * @return FDB_RESULT_SUCCESS on success.
 */
LIBFDB_API
fdb_status fdb_init(fdb_config *config);

/**
 * Get the default ForestDB configs.
 * The general recommendation is to invoke this API to get the default configs
 * and change some configs if necessary and then pass them to fdb_open APIs.
 *
 * @return fdb_config instance that contains the default configs.
 */
LIBFDB_API
fdb_config fdb_get_default_config(void);

/**
 * Get the default ForestDB KV(Key-Value) store configs. Note that multiple KV
 * store instances can be created in a single ForestDB file.
 * The general recommendation is to invoke this API to get the default configs
 * and change some configs if necessary and then pass them to fdb_kvs_open APIs.
 *
 * @return fdb_kvs_config instance that contains the default configs.
 */
LIBFDB_API
fdb_kvs_config fdb_get_default_kvs_config(void);

/**
 * Open a ForestDB file.
 * The file should be closed with fdb_close API call.
 *
 * @param ptr_fhandle Pointer to the place where ForestDB file handle is
 *        instantiated as result of this API call.
 * @param filename Name of the ForestDB file to be opened.
 * @param fconfig Pointer to the config instance that contains ForestDB configs.
 *        If NULL is passed, then we use default settings of ForestDB configs.
 * @return FDB_RESULT_SUCCESS on success.
 */
LIBFDB_API
fdb_status fdb_open(fdb_file_handle **ptr_fhandle,
                    const char *filename,
                    fdb_config *fconfig);

/**
 * Open a ForestDB file.
 * Note that if any KV store in the file uses a customized compare function,
 * then the file should be opened with this API by passing the list of all KV
 * instance names that use customized compare functions, and their corresponding
 * customized compare functions.
 *
 * Documents in the file will be indexed using their corresponding
 * customized compare functions. The file should be closed with fdb_close
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
LIBFDB_API
fdb_status fdb_open_custom_cmp(fdb_file_handle **ptr_fhandle,
                               const char *filename,
                               fdb_config *fconfig,
                               size_t num_functions,
                               char **kvs_names,
                               fdb_custom_cmp_variable *functions);

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
LIBFDB_API
fdb_status fdb_set_log_callback(fdb_kvs_handle *handle,
                                fdb_log_callback log_callback,
                                void *ctx_data);

/**
 * Set the fatal error callback that allows an application to specify a
 * function to be called if forestdb encounters a fatal error, before
 * forestdb raises a SIGABRT.
 *
 * @param err_callback Error callback that will be called upon detecting a
 *        fatal error (but before forestdb raises SIGABRT). Any previously
 *        registered fatal error callback will be replaced.
 */
LIBFDB_API
void fdb_set_fatal_error_callback(fdb_fatal_error_callback err_callback);

/**
 * Create a new FDB_DOC instance on heap with a given key, its metadata, and
 * its doc body.
 *
 * @param doc Pointer to a FDB_DOC instance created.
 * @param key Pointer to a key.
 * @param keylen Key length.
 * @param meta Pointer to key's metadata.
 * @param metalen Metadata length.
 * @param body Pointer to key's doc body.
 * @param bodylen Doc body length.
 * @return FDB_RESULT_SUCCESS on success.
 */
LIBFDB_API
fdb_status fdb_doc_create(fdb_doc **doc,
                          const void *key,
                          size_t keylen,
                          const void *meta,
                          size_t metalen,
                          const void *body,
                          size_t bodylen);

/**
 * Update a FDB_DOC instance with a given metadata and body.
 * Note that this API does not update an item in the ForestDB KV store, but
 * instead simply updates a given FDB_DOC instance only.
 *
 * @param doc Pointer to a FDB_DOC instance to be updated.
 * @param meta Pointer to key's metadata.
 * @param metalen Metadata length.
 * @param body Pointer to key's doc body.
 * @param bodylen Doc body length.
 * @return FDB_RESULT_SUCCESS on success.
 */
LIBFDB_API
fdb_status fdb_doc_update(fdb_doc **doc,
                          const void *meta,
                          size_t metalen,
                          const void *body,
                          size_t bodylen);

/**
 * Explicitly set the sequence number of a FDB_DOC instance instead of having
 * ForestDB internally generate it upon fdb_set().
 * Note that this API does not update an item in the ForestDB KV store, but
 * instead simply updates a given FDB_DOC instance only.
 *
 * WARNING: It is upto the caller to ensure that sequence numbers are unique
 *          and monotonically increasing based on the order of mutations.
 *
 * @param doc Pointer to a FDB_DOC instance to be updated.
 * @param seqnum The value of the custom sequence number for this mutation.
 *
 */
LIBFDB_API
void fdb_doc_set_seqnum(fdb_doc *doc,
                        const fdb_seqnum_t seqnum);

/**
 * Free a given FDB_DOC instance from heap.
 *
 * @param doc Pointer to a FDB_DOC instance to be freed from heap.
 * @return FDB_RESULT_SUCCESS on success.
 */
LIBFDB_API
fdb_status fdb_doc_free(fdb_doc *doc);

/**
 * Retrieve the metadata and doc body for a given key.
 * Note that FDB_DOC instance should be created by calling
 * fdb_doc_create(doc, key, keylen, NULL, 0, NULL, 0) before using this API.
 *
 * @param handle Pointer to ForestDB KV store handle.
 * @param doc Pointer to ForestDB doc instance whose metadata and doc body
 *        are populated as a result of this API call.
 * @return FDB_RESULT_SUCCESS on success.
 */
LIBFDB_API
fdb_status fdb_get(fdb_kvs_handle *handle,
                   fdb_doc *doc);

/**
 * Retrieve the metadata for a given key.
 * Note that FDB_DOC instance should be created by calling
 * fdb_doc_create(doc, key, keylen, NULL, 0, NULL, 0) before using this API.
 *
 * WARNING: If the document was deleted but not yet purged, then the metadata
 *          will still be populated in the fdb_doc passed into the function.
 *
 * @param handle Pointer to ForestDB KV store handle.
 * @param doc Pointer to ForestDB doc instance whose metadata including the offset
 *        on disk is populated as a result of this API call.
 *        Note that the offset returned can be used by fdb_get_byoffset API to
 *        retrieve a doc body.
 * @return FDB_RESULT_SUCCESS on success.
 */
LIBFDB_API
fdb_status fdb_get_metaonly(fdb_kvs_handle *handle,
                            fdb_doc *doc);

/**
 * Retrieve the metadata and doc body for a given sequence number.
 * Note that FDB_DOC instance should be created by calling
 * fdb_doc_create(doc, NULL, 0, NULL, 0, NULL, 0) before using this API.
 *
 * @param handle Pointer to ForestDB KV store handle.
 * @param doc Pointer to ForestDB doc instance whose key, metadata and doc body
 *        are populated as a result of this API call.
 * @return FDB_RESULT_SUCCESS on success.
 */
LIBFDB_API
fdb_status fdb_get_byseq(fdb_kvs_handle *handle,
                         fdb_doc *doc);

/**
 * Retrieve the metadata for a given sequence number.
 * Note that FDB_DOC instance should be created by calling
 * fdb_doc_create(doc, NULL, 0, NULL, 0, NULL, 0) before using this API.
 *
 * WARNING: If the document was deleted but not yet purged, then the metadata
 *          will still be populated in the fdb_doc passed into the function.
 *
 * @param handle Pointer to ForestDB KV store handle.
 * @param doc Pointer to ForestDB doc instance whose key and metadata including
 *        the offset on disk are populated as a result of this API call.
 *        Note that the offset returned can be used by fdb_get_byoffset API to
 *        retrieve a doc body.
 * @return FDB_RESULT_SUCCESS on success.
 */
LIBFDB_API
fdb_status fdb_get_metaonly_byseq(fdb_kvs_handle *handle,
                                  fdb_doc *doc);

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
LIBFDB_API
fdb_status fdb_get_byoffset(fdb_kvs_handle *handle,
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
LIBFDB_API
fdb_status fdb_set(fdb_kvs_handle *handle,
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
LIBFDB_API
fdb_status fdb_del(fdb_kvs_handle *handle,
                   fdb_doc *doc);

/**
 * Simplified API for fdb_get:
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
LIBFDB_API
fdb_status fdb_get_kv(fdb_kvs_handle *handle,
                      const void *key, size_t keylen,
                      void **value_out, size_t *valuelen_out);

/**
 * Simplified API for fdb_set:
 * Update the value (doc body in fdb_set) for a given key.
 *
 * @param handle Pointer to ForestDB KV store handle.
 * @param key Pointer to the key to be updated.
 * @param keylen Length of the key.
 * @param value Pointer to the value corresponding to the key.
 * @param valuelen Length of the value.
 * @return FDB_RESULT_SUCCESS on success.
 */
LIBFDB_API
fdb_status fdb_set_kv(fdb_kvs_handle *handle,
                      const void *key, size_t keylen,
                      const void *value, size_t valuelen);

/**
 * Simplified API for fdb_del:
 * Delete a key, and its value (doc body in fdb_del).
 *
 * @param handle Pointer to ForestDB KV store handle.
 * @param key Pointer to the key to be deleted.
 * @param keylen Length of the key.
 * @return FDB_RESULT_SUCCESS on success.
 */
LIBFDB_API
fdb_status fdb_del_kv(fdb_kvs_handle *handle,
                      const void *key, size_t keylen);

/**
 * Free memory allocated by fdb_get_kv:
 * Release the memory allocated by ForestDB when fdb_get_kv called.
 *
 * @param ptr Pointer to the value memory that must be freed.
 * @return FDB_RESULT_SUCCESS on success.
 */
LIBFDB_API
fdb_status fdb_free_block(void *ptr);

/**
 * Commit all pending changes on a ForestDB file into disk.
 * Note that this API should be invoked with a ForestDB file handle.
 *
 * @param fhandle Pointer to ForestDB file handle.
 * @param opt Commit option.
 * @return FDB_RESULT_SUCCESS on success.
 */
LIBFDB_API
fdb_status fdb_commit(fdb_file_handle *fhandle, fdb_commit_opt_t opt);

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
LIBFDB_API
fdb_status fdb_snapshot_open(fdb_kvs_handle *handle_in, fdb_kvs_handle **handle_out,
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
LIBFDB_API
fdb_status fdb_rollback(fdb_kvs_handle **handle_ptr, fdb_seqnum_t rollback_seqnum);

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
LIBFDB_API
fdb_status fdb_rollback_all(fdb_file_handle *fhandle,
                            fdb_snapshot_marker_t marker);

/**
 * Create an iterator to traverse a ForestDB KV store snapshot by key range
 *
 * @param handle Pointer to ForestDB KV store handle.
 * @param iterator Pointer to the place where the iterator is created
 *        as a result of this API call.
 * @param min_key Pointer to the smallest key. Passing NULL means that
 *        it wants to start with the smallest key in the KV store.
 * @param min_keylen Length of the smallest key.
 * @param max_key Pointer to the largest key. Passing NULL means that it wants
 *        to end iteration with the largest key in the KV store.
 * @param max_keylen Length of the largest key.
 * @param opt Iterator option.
 * @return FDB_RESULT_SUCCESS on success.
 */
LIBFDB_API
fdb_status fdb_iterator_init(fdb_kvs_handle *handle,
                             fdb_iterator **iterator,
                             const void *min_key,
                             size_t min_keylen,
                             const void *max_key,
                             size_t max_keylen,
                             fdb_iterator_opt_t opt);

/**
 * Create an iterator to traverse a ForestDB KV store snapshot by sequence
 * number range
 *
 * @param handle Pointer to ForestDB KV store handle.
 * @param iterator Pointer to the iterator to be created as a result of
 *        this API call.
 * @param min_seq Smallest document sequence number of the iteration.
 * @param max_seq Largest document sequence number of the iteration.
 *        Passing 0 means that it wants iteration to end with the latest
 *        mutation
 * @param opt Iterator option.
 * @return FDB_RESULT_SUCCESS on success.
 */
LIBFDB_API
fdb_status fdb_iterator_sequence_init(fdb_kvs_handle *handle,
                                      fdb_iterator **iterator,
                                      const fdb_seqnum_t min_seq,
                                      const fdb_seqnum_t max_seq,
                                      fdb_iterator_opt_t opt);

/**
 * Move the iterator backward by one.
 *
 * @param iterator Pointer to the iterator.
 * @return FDB_RESULT_SUCCESS on success.
 */
LIBFDB_API
fdb_status fdb_iterator_prev(fdb_iterator *iterator);

/**
 * Move the iterator forward by one.
 *
 * @param iterator Pointer to the iterator.
 * @return FDB_RESULT_SUCCESS on success.
 */
LIBFDB_API
fdb_status fdb_iterator_next(fdb_iterator *iterator);

/**
 * Get the item (key, metadata, doc body) from the iterator.
 * Note that the parameter 'doc' should be set to NULL before passing it
 * to this API if the API caller wants a fdb_doc instance to be created and
 * returned by this API.
 *
 * Example usage:
 *   ...
 *   fdb_doc *doc = NULL;
 *   // fdb_doc instance is created and returned by fdb_iterator_get API.
 *   fdb_status status = fdb_iterator_get(iterator, &doc);
 *   ...
 *   fdb_doc_free(doc);
 *
 * Otherwise, if the client knows the max lengths of key, metadata, and
 * value in the iterator range, then it can pre-allocate fdb_doc instance with
 * these max lengths, and pass it to this API, so that the memory allocation
 * overhead can be avoided for each iteration.
 *
 * Example usage:
 *   ...
 *   fdb_doc *doc;
 *   fdb_doc_create(&doc, NULL, 0, NULL, 0, NULL, 0);
 *   doc->key = malloc(MAX_KEY_LENGTH);
 *   doc->meta = malloc(MAX_META_LENGTH);
 *   doc->body = malloc(MAX_VALUE_LENGTH);
 *   while (...) {
 *       status = fdb_iterator_get(iterator, &doc);
 *       ...
 *   }
 *   fdb_doc_free(doc);
 *
 * @param iterator Pointer to the iterator.
 * @param doc Pointer to FDB_DOC instance to be populated by the iterator.
 * @return FDB_RESULT_SUCCESS on success.
 */
LIBFDB_API
fdb_status fdb_iterator_get(fdb_iterator *iterator, fdb_doc **doc);

/**
 * Get item metadata only (key, metadata, offset to doc body) from the iterator.
 * Note that the parameter 'doc' should be set to NULL before passing it
 * to this API if the API caller wants a fdb_doc instance to be created and
 * returned by this API.
 *
 * @param iterator Pointer to the iterator.
 * @param doc Pointer to FDB_DOC instance to be populated by the iterator.
 *        Note that the API call won't return the doc body, but instead the
 *        offset to the doc on disk.
 * @return FDB_RESULT_SUCCESS on success.
 */
LIBFDB_API
fdb_status fdb_iterator_get_metaonly(fdb_iterator *iterator, fdb_doc **doc);

/**
 * Fast forward / backward an iterator to return documents starting from
 * the given seek_key. If the seek key does not exist, the iterator is
 * positioned to start from the next sorted key.
 *
 * @param iterator Pointer to the iterator.
 * @param seek_key Pointer to the key to seek to.
 * @param seek_keylen Length of the seek_key
 * @param direction Specifies which key to return if seek_key does not exist.
 *        Default value of 0 indicates FDB_ITR_SEEK_HIGHER
 * @return FDB_RESULT_SUCCESS on success.
 */
LIBFDB_API
fdb_status fdb_iterator_seek(fdb_iterator *iterator, const void *seek_key,
                             const size_t seek_keylen,
                             const fdb_iterator_seek_opt_t direction);

/**
 * Rewind an iterator to position at the smallest key of the iteration.
 *
 * @param iterator Pointer to the iterator.
 * @return FDB_RESULT_SUCCESS on success.
 */
LIBFDB_API
fdb_status fdb_iterator_seek_to_min(fdb_iterator *iterator);

/**
 * Fast forward an iterator to position at the largest key of the iteration.
 *
 * @param iterator Pointer to the iterator.
 * @return FDB_RESULT_SUCCESS on success.
 */
LIBFDB_API
fdb_status fdb_iterator_seek_to_max(fdb_iterator *iterator);

/**
 * Close the iterator and free its associated resources.
 *
 * @param iterator Pointer to the iterator.
 * @return FDB_RESULT_SUCCESS on success.
 */
LIBFDB_API
fdb_status fdb_iterator_close(fdb_iterator *iterator);

/**
 * Iterate through the changes since sequence number `since` with a provided
 * callback function.
 *
 * @param handle Pointer to ForestDB KV store instance.
 * @param since The sequence number to start iterating from.
 * @param opt Iterator option.
 * @param callback The callback function used to iterate over all changes.
 * @param ctx Client context (passed to the callback).
 * @return FDB_RESULT_SUCCESS on success, FDB_RESULT_CANCELLED if cancelled
 *         by caller through callback.
 */
LIBFDB_API
fdb_status fdb_changes_since(fdb_kvs_handle *handle,
                             fdb_seqnum_t since,
                             fdb_iterator_opt_t opt,
                             fdb_changes_callback_fn callback,
                             void *ctx);

/**
 * Compact the current file and create a new compacted file.
 * Note that a new file name passed to this API will be ignored if the compaction
 * mode of the handle is auto-compaction (i.e., FDB_COMPACTION_AUTO). In the auto
 * compaction mode, the name of a new compacted file will be automatically generated
 * by increasing its current file revision number.
 *
 * If a new file name is not given (i.e., NULL is passed) in a manual compaction
 * mode, then a new file name will be automatically created by appending
 * a file revision number to the original file name.
 *
 *  Example usage:
 *
 *   fdb_open(db1, "test.fdb");
 *   ...
 *   fdb_compact(db1, NULL); // "test.fdb.1" is created after compaction.
 *                           // Note that "test.fdb" will be removed automatically
 *                           // when its reference counter becomes zero.
 *   ...
 *   fdb_compact(db1, NULL); // "test.fdb.2" is created after compaction.
 *                           // Note that "test.fdb.1" will be removed automatically
 *                           // when its reference counter becomes zero.
 *   fdb_open(db2, "test.fdb"); // "test.fdb.2" is opened because that is the last
 *                              // compacted file.
 *   ...
 *   fdb_close(db1);
 *   fdb_close(db2); // "test.fdb.2" is automatically renamed to the original
 *                   // file name "test.fdb" because there are no file handles
 *                   // on "test.fdb.2".
 *
 * Also note that if a given ForestDB file is currently being compacted by the
 * compaction daemon, then FDB_RESULT_FILE_IS_BUSY is returned to the caller.
 *
 * @param fhandle Pointer to ForestDB file handle.
 * @param new_filename Name of a new compacted file.
 * @return FDB_RESULT_SUCCESS on success.
 */
LIBFDB_API
fdb_status fdb_compact(fdb_file_handle *fhandle,
                       const char *new_filename);
/**
 * Compact the database file by sharing valid document blocks from
 * the old file.
 *
 * Currently this API works only on Btrfs (B-tree file system) having the
 * copy-file-range support that allows physical pages to be shared across files
 * through the copy-on-write (CoW) nature of Btrfs.
 *
 *  WARNING: Currently this API performs best only in the offline compaction mode.
 *  NOTE: Only one compaction will be allowed per file, and any other calls made
 *        while the first call is in-progress will fail.
 *
 * @param fhandle Pointer to ForestDB file handle.
 * @param new_filename Name of a new compacted file. The semantics are the same
 *                     as that of fdb_compact() call described above.
 * @return FDB_RESULT_SUCCESS on success or an error indicating either
 *         temporary failure like FDB_RESULT_FAIL_BY_COMPACTION, or permanent
 *         failure such as FDB_RESULT_COMPACTION_FAIL if not supported.
 */
LIBFDB_API
fdb_status fdb_compact_with_cow(fdb_file_handle *fhandle,
                                const char *new_filename);

/**
 * Compact the database file by retaining the stale data up to a given file-level
 * snapshot marker.
 *
 *  NOTE: Only one compaction will be allowed per file, and any other calls made
 *        while the first call is in-progress will fail.
 *
 * @param fhandle Pointer to ForestDB file handle.
 * @param new_filename Name of a new compacted file. The semantics are the same
 *                     as that of fdb_compact() call described above.
 * @param marker Snapshot marker retrieved from fdb_get_all_snap_markers() API,
 *               indicating the stale data up to a given snapshot marker will be
 *               retained.
 * @return FDB_RESULT_SUCCESS on success or an error indicating either
 *         temporary failure like FDB_RESULT_FAIL_BY_COMPACTION, or permanent
 *         failure such as FDB_RESULT_NO_DB_INSTANCE.
 */
LIBFDB_API
fdb_status fdb_compact_upto(fdb_file_handle *fhandle,
                            const char *new_filename,
                            fdb_snapshot_marker_t marker);
/**
 * Compact the database file by retaining the stale data upto a given file-level
 * snapshot marker and sharing valid document blocks from the old file.
 *
 * Currently this API works only on Btrfs (B-tree file system) having the
 * copy-file-range support that allows physical pages to be shared across files
 * through the copy-on-write (CoW) nature of Btrfs.
 *
 *  WARNING: Currently this API performs best only in the offline compaction mode.
 *  NOTE: Only one compaction will be allowed per file, and any other calls made
 *        while the first call is in-progress will fail.
 *
 * @param fhandle Pointer to ForestDB file handle.
 * @param new_filename Name of a new compacted file. The semantics are the same
 *                     as that of fdb_compact() call described above.
 * @param marker Snapshot marker retrieved from fdb_get_all_snap_markers() API,
 *               indicating the stale data up to a given snapshot marker will be
 *               retained.
 * @return FDB_RESULT_SUCCESS on success or an error indicating either
 *         temporary failure like FDB_RESULT_FAIL_BY_COMPACTION, or permanent
 *         failure such as FDB_RESULT_COMPACTION_FAIL if not supported.
 */
LIBFDB_API
fdb_status fdb_compact_upto_with_cow(fdb_file_handle *fhandle,
                                     const char *new_filename,
                                     fdb_snapshot_marker_t marker);

/**
 * Cancel the compaction task if it is running currently.
 *
 * @param fhandle Pointer to ForestDB file handle
 * @return FDB_RESULT_SUCCESS on successful cancellation.
 */
LIBFDB_API
fdb_status fdb_cancel_compaction(fdb_file_handle *fhandle);

/**
 * Set the daemon compaction interval for a given file.
 *
 * @param fhandle Pointer to ForestDB file handle.
 * @param interval Daemon compaction intervel to be set for a given file
 * @return FDB_RESULT_SUCCESS on successful compaction interval change.
 */
LIBFDB_API
fdb_status fdb_set_daemon_compaction_interval(fdb_file_handle *fhandle,
                                              size_t interval);

/**
 * Change the database file's encryption, by compacting it while writing with a new key.
 * @param fhandle Pointer to ForestDB file handle.
 * @param new_key Key with which to encrypt the new file. To remove encryption, set the key's
 *                algorithm to FDB_ENCRYPTION_NONE.
 * @return FDB_RESULT_SUCCESS on success.
 */
LIBFDB_API
fdb_status fdb_rekey(fdb_file_handle *fhandle,
                     fdb_encryption_key new_key);

/**
 * Return the overall buffer cache space actively used by all ForestDB files.
 * Note that this does not include space in WAL, hash tables and other
 * in-memory data structures allocated by ForestDB api
 *
 * @return Size of buffer cache currently used.
 */
LIBFDB_API
size_t fdb_get_buffer_cache_used();

/**
 * Return the overall disk space actively used by a ForestDB file.
 * Note that this doesn't include the disk space used by stale btree nodes
 * and docs.
 *
 * @param fhandle Pointer to ForestDB file handle.
 * @return Disk space actively used by a ForestDB file.
 */
LIBFDB_API
size_t fdb_estimate_space_used(fdb_file_handle *fhandle);

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
LIBFDB_API
size_t fdb_estimate_space_used_from(fdb_file_handle *fhandle,
                                    fdb_snapshot_marker_t marker);

/**
 * Return the information about a ForestDB file.
 *
 * @param fhandle Pointer to ForestDB file handle.
 * @param info Pointer to ForestDB File Info instance.
 * @return FDB_RESULT_SUCCESS on success.
 */
LIBFDB_API
fdb_status fdb_get_file_info(fdb_file_handle *fhandle, fdb_file_info *info);

/**
 * Return the information about a ForestDB KV store instance.
 *
 * @param handle Pointer to ForestDB KV store handle.
 * @param info Pointer to KV Store Info instance.
 * @return FDB_RESULT_SUCCESS on success.
 */
LIBFDB_API
fdb_status fdb_get_kvs_info(fdb_kvs_handle *handle, fdb_kvs_info *info);

/**
 * Return the information about operational counters in a ForestDB KV store.
 *
 * @param handle Pointer to ForestDB KV store handle.
 * @param info Pointer to KV Store Ops Info instance.
 * @return FDB_RESULT_SUCCESS on success.
 */
LIBFDB_API
fdb_status fdb_get_kvs_ops_info(fdb_kvs_handle *handle, fdb_kvs_ops_info *info);

/**
 * Return the latency information about various forestdb api calls
 *
 * @param fhandle Pointer to ForestDB file handle
 * @param stats Pointer to a latency_stats instance
 * @param type Type of latency stat to be retrieved
 * @return FDB_RESULT_SUCCESS on success.
 */
LIBFDB_API
fdb_status fdb_get_latency_stats(fdb_file_handle *fhandle,
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
LIBFDB_API
fdb_status fdb_get_latency_histogram(fdb_file_handle *fhandle,
                                     char **stats,
                                     size_t *stats_length,
                                     fdb_latency_stat_type type);

/**
 * Return the name of the latency stat
 *
 * @param type The type of the latency stat to be named.
 * @return const char pointer to the stat name. This must not be freed.
 */
LIBFDB_API
const char * fdb_latency_stat_name(fdb_latency_stat_type type);

/**
 * Get the current sequence number of a ForestDB KV store instance.
 *
 * @param handle Pointer to ForestDB KV store handle.
 * @param seqnum Pointer to the variable that sequence number will be returned.
 * @return FDB_RESULT_SUCCESS on success.
 */
LIBFDB_API
fdb_status fdb_get_kvs_seqnum(fdb_kvs_handle *handle, fdb_seqnum_t *seqnum);

/**
 * Get all KV store names in a ForestDB file.
 *
 * @param fhandle Pointer to ForestDB file handle.
 * @param kvs_name_list Pointer to a KV store name list. Note that this list
 *        should be released using fdb_free_kvs_name_list API call().
 * @return FDB_RESULT_SUCCESS on success.
 */
LIBFDB_API
fdb_status fdb_get_kvs_name_list(fdb_file_handle *fhandle,
                                 fdb_kvs_name_list *kvs_name_list);

/**
 * Return all the snapshot markers in a given database file.
 *
 * @param fhandle Pointer to ForestDB file handle.
 * @param markers Pointer to the allocated array of snapshot_info instances
 *                that correspond to each of the commit markers in a file.
 * @param size Number of elements of the markers that are allocated.
 * @return file i/o or other on failure, FDB_RESULT_SUCCESS if successful.
 *
 */
LIBFDB_API
fdb_status fdb_get_all_snap_markers(fdb_file_handle *fhandle,
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
LIBFDB_API
fdb_seqnum_t fdb_get_available_rollback_seq(fdb_kvs_handle *handle,
                                            uint64_t request_seqno);

/**
 * Free a kv snapshot_info array allocated by fdb_get_all_snap_markers API.
 *
 * @param markers Pointer to a KV snapshot_info array that is allocated by
 *        fdb_get_all_snap_markers API.
 * @param size Number of elements in above array.
 * @return FDB_RESULT_SUCCESS on success.
 */
LIBFDB_API
fdb_status fdb_free_snap_markers(fdb_snapshot_info_t *markers, uint64_t size);

/**
 * Free a KV store name list.
 *
 * @param kvs_name_list Pointer to a KV store name list to be freed.
 * @return FDB_RESULT_SUCCESS on success.
 */
LIBFDB_API
fdb_status fdb_free_kvs_name_list(fdb_kvs_name_list *kvs_name_list);

/**
 * Change the compaction mode of a ForestDB file referred by the handle passed.
 * If the mode is changed to auto-compaction (i.e., FDB_COMPACTION_AUTO), the compaction
 * threshold is set to the threshold passed to this API.
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
LIBFDB_API
fdb_status fdb_switch_compaction_mode(fdb_file_handle *fhandle,
                                      fdb_compaction_mode_t mode,
                                      size_t new_threshold);

/**
 * Close a ForestDB file.
 *
 * @param fhandle Pointer to ForestDB file handle.
 * @return FDB_RESULT_SUCCESS on success.
 */
LIBFDB_API
fdb_status fdb_close(fdb_file_handle *fhandle);

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
LIBFDB_API
fdb_status fdb_destroy(const char *filename,
                       fdb_config *fconfig);

/**
 * Destroy all the resources (e.g., buffer cache, in-memory WAL indexes,
 * daemon compaction thread, etc.) and then shutdown the ForestDB engine.
 * Note that all the ForestDB files should be closed through fdb_close calls
 * before calling this API.
 *
 * @return FDB_RESULT_SUCCESS on success.
 */
LIBFDB_API
fdb_status fdb_shutdown();

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
LIBFDB_API
fdb_status fdb_begin_transaction(fdb_file_handle *fhandle,
                                 fdb_isolation_level_t isolation_level);

/**
 * End a transaction for a given ForestDB file handle by commiting all the dirty
 * updates and releasing all the resouces allocated for that transaction.
 *
 * @param fhandle Pointer to ForestDB file handle.
 * @param opt Commit option.
 * @return FDB_RESULT_SUCCESS on success.
 */
LIBFDB_API
fdb_status fdb_end_transaction(fdb_file_handle *fhandle,
                               fdb_commit_opt_t opt);

/**
 * Abort the transaction for a given ForestDB file handle.
 * All uncommitted dirty updates in the handle will be discarded.
 *
 * @param fhandle Pointer to ForestDB file handle.
 * @return FDB_RESULT_SUCCESS on success.
 */
LIBFDB_API
fdb_status fdb_abort_transaction(fdb_file_handle *fhandle);

/**
 * Open the KV store with a given instance name.
 * The KV store should be closed with fdb_kvs_close API call.
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
LIBFDB_API
fdb_status fdb_kvs_open(fdb_file_handle *fhandle,
                        fdb_kvs_handle **ptr_handle,
                        const char *kvs_name,
                        fdb_kvs_config *config);


/**
 * Open the default KV store.
 * The KV store should be closed with fdb_kvs_close API call.
 *
 * @param fhandle Pointer to ForestDB file handle.
 * @param ptr_handle Pointer to the place where the KV store handle is
 *        instantiated as a result of this API call.
 * @param config Pointer to the config instance that contains KV store configs.
 *        If NULL is passed, then we use default settings of KV store configs.
 * @return FDB_RESULT_SUCCESS on success.
 */
LIBFDB_API
fdb_status fdb_kvs_open_default(fdb_file_handle *fhandle,
                                fdb_kvs_handle **ptr_handle,
                                fdb_kvs_config *config);

/**
 * Close the KV store handle.
 *
 * @param handle Pointer to KV store handle.
 * @return FDB_RESULT_SUCCESS on success.
 */
LIBFDB_API
fdb_status fdb_kvs_close(fdb_kvs_handle *handle);

/**
 * Permanently drop a given KV store instance from a ForestDB file.
 *
 * @param fhandle Pointer to ForestDB file handle.
 * @param kvs_name The name of KV store instance to be removed. If the name is not given
 *        (i.e., NULL is passed), the KV store instance named "default" will be
 *        dropped.
 * @return FDB_RESULT_SUCCESS on success.
 */
LIBFDB_API
fdb_status fdb_kvs_remove(fdb_file_handle *fhandle,
                          const char *kvs_name);

/**
 * Change the config parameters for reusing stale blocks
 *
 * @param fhandle Pointer to ForestDB file handle.
 * @param block_reusing_threshold Circular block reusing threshold in the unit of
 *        percentage(%), which can be represented as '(stale data size)/(total file size)
 *        When stale data size grows beyond this threshold, circular block reusing is
 *        triggered so that stale blocks are reused for further block allocations.
 *        Block reusing is disabled if this threshold is set to zero or 100.
 * @param num_keeping_headers Number of the last commit headers whose stale blocks should
 *        be kept for snapshot readers
 * @return FDB_RESULT_SUCCESS on success.
 */
LIBFDB_API
fdb_status fdb_set_block_reusing_params(fdb_file_handle *fhandle,
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
LIBFDB_API
const char* fdb_error_msg(fdb_status err_code);

/**
 * Return the string representation of ForestDB library version that is based on
 * git-describe output.
 *
 * @return A text string that represents ForestDB library version
 */
LIBFDB_API
const char* fdb_get_lib_version();

/**
 * Return the version of a given ForestDB file.
 *
 * @param fhandle Pointer to ForestDB file handle whose file version is returned.
 * @return Version of a given ForestDB file.
 */
LIBFDB_API
const char* fdb_get_file_version(fdb_file_handle *fhandle);

/**
 * Return the default file operations used by ForestDB.
 *
 * @return pointer to the struct having all the default file operations
 */
LIBFDB_API
fdb_filemgr_ops_t* fdb_get_default_file_ops();

/**
 * Fetch select stats for the ForestDB KV store handle.
 *
 * @param handle Pointer to ForestDB KV store instance
 * @param callback Callback function that the caller will register, this callback
 *                 function is invoked for every stat of the KV store handle
 * @param ctx Client context that is passed to the callback
 *
 * Stats returned (File level)
 *  1> Num_wal_shards               : Number of shards in the WAL
 *  2> Num_bcache_shards            : Number of shards in FDB's global block cache
 *  3> Block_cache_hits             : Number of block cache hits
 *  4> Block_cache_misses           : Number of block cache misses
 *  5> Block_cache_num_items        : Number of block cache items
 *  6> Block_cache_num_victims      : Number of block cache victims (evictions)
 *  7> Block_cache_num_immutables   : Number of block cache immutables (eligible for eviction)
 *
 */
LIBFDB_API
fdb_status fdb_fetch_handle_stats(fdb_kvs_handle *handle,
                                  fdb_handle_stats_cb callback,
                                  void *ctx);

#ifdef __cplusplus
}
#endif

#endif
