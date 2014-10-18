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
 * Open the database with a given file name.
 * The database should be closed with fdb_close API call.
 *
 * @param ptr_handle Pointer to the place where ForestDB handle is instantiated
 *        as result of this API call.
 * @param filename Name of database file to be opened.
 * @param fconfig Pointer to the config instance that contains ForestDB configs.
 *        If NULL is passed, then we use default settings of ForestDB configs.
 * @return FDB_RESULT_SUCCESS on success.
 */
LIBFDB_API
fdb_status fdb_open(fdb_handle **ptr_handle,
                    const char *filename,
                    fdb_config *fconfig);

/**
 * Open the database with a given file name.
 * The documents in the database will be indexed using the customized compare
 * function. The key size MUST be fixed and same as the chunk_size in the
 * configuration. The typical example is to use a primitive type (e.g., int,
 * double) as a primary key and the numeric compare function as a custom
 * function.
 * The database should be closed with fdb_close API call.
 *
 * @param ptr_handle Pointer to the place where ForestDB handle is instantiated
 *        as result of this API call.
 * @param filename Name of database file to be opened.
 * @param fconfig Pointer to the config instance that contains ForestDB configs.
 *        If NULL is passed, then it returns FDB_RESULT_INVALID_ARGS to the caller.
 *        The function pointer "fdb_custom_cmp_fixed" in fdb_config should be
 *        set by an application.
 * @return FDB_RESULT_SUCCESS on success.
 */
LIBFDB_API
fdb_status fdb_open_cmp_fixed(fdb_handle **ptr_handle,
                              const char *filename,
                              fdb_config *fconfig);

/**
 * Open the database with a given file name.
 * The documents in the database will be indexed using the customized compare
 * function. The key size can be variable.
 * The database should be closed with fdb_close API call.
 *
 * @param ptr_handle Pointer to the place where ForestDB handle is instantiated
 *        as result of this API call.
 * @param filename Name of database file to be opened.
 * @param fconfig Pointer to the config instance that contains ForestDB configs.
 *        If NULL is passed, then it returns FDB_RESULT_INVALID_ARGS to the caller.
 *        The function pointer "fdb_custom_cmp_variable" in fdb_config should be
 *        set by an application.
 * @return FDB_RESULT_SUCCESS on success.
 */
LIBFDB_API
fdb_status fdb_open_cmp_variable(fdb_handle **ptr_handle,
                                 const char *filename,
                                 fdb_config *fconfig);

/**
 * Set up the error logging callback that allows an application to process
 * error code and message from ForestDB.
 *
 * @param handle Pointer to ForestDB handle.
 * @param log_callback Logging callback function that receives and processes
 *        error codes and messages from ForestDB.
 * @param ctx_data Pointer to application-specific context data that is going
 *        to be passed to the logging callback function.
 * @return FDB_RESULT_SUCCESS on success.
 */
LIBFDB_API
fdb_status fdb_set_log_callback(fdb_handle *handle,
                                fdb_log_callback log_callback,
                                void *ctx_data);

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
 * Note that this API does not update the ForestDB database, but
 * instead simply update a given FDB_DOC instance only.
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
 * @param handle Pointer to ForestDB handle.
 * @param doc Pointer to ForestDB doc instance whose metadata and doc body
 *        are populated as a result of this API call.
 * @return FDB_RESULT_SUCCESS on success.
 */
LIBFDB_API
fdb_status fdb_get(fdb_handle *handle,
                   fdb_doc *doc);

/**
 * Retrieve the metadata for a given key.
 * Note that FDB_DOC instance should be created by calling
 * fdb_doc_create(doc, key, keylen, NULL, 0, NULL, 0) before using this API.
 *
 * @param handle Pointer to ForestDB handle.
 * @param doc Pointer to ForestDB doc instance whose metadata including the offset
 *        on disk is populated as a result of this API call.
 *        Note that the offset returned can be used by fdb_get_byoffset API to
 *        retrieve a doc body.
 * @return FDB_RESULT_SUCCESS on success.
 */
LIBFDB_API
fdb_status fdb_get_metaonly(fdb_handle *handle,
                            fdb_doc *doc);

/**
 * Retrieve the metadata and doc body for a given sequence number.
 * Note that FDB_DOC instance should be created by calling
 * fdb_doc_create(doc, NULL, 0, NULL, 0, NULL, 0) before using this API.
 *
 * @param handle Pointer to ForestDB handle.
 * @param doc Pointer to ForestDB doc instance whose key, metadata and doc body
 *        are populated as a result of this API call.
 * @return FDB_RESULT_SUCCESS on success.
 */
LIBFDB_API
fdb_status fdb_get_byseq(fdb_handle *handle,
                         fdb_doc *doc);

/**
 * Retrieve the metadata for a given sequence number.
 * Note that FDB_DOC instance should be created by calling
 * fdb_doc_create(doc, NULL, 0, NULL, 0, NULL, 0) before using this API.
 *
 * @param handle Pointer to ForestDB handle.
 * @param doc Pointer to ForestDB doc instance whose key and metadata including
 *        the offset on disk are populated as a result of this API call.
 *        Note that the offset returned can be used by fdb_get_byoffset API to
 *        retrieve a doc body.
 * @return FDB_RESULT_SUCCESS on success.
 */
LIBFDB_API
fdb_status fdb_get_metaonly_byseq(fdb_handle *handle,
                                  fdb_doc *doc);

/**
 * Retrieve a doc's metadata and body with a given doc offset in the database file.
 * Note that FDB_DOC instance should be first instantiated and populated
 * by calling fdb_get_metaonly, fdb_get_metaonly_byseq, or
 * fdb_iterator_next_offset, which returns an offset to a doc. Then,
 * the FDB_DOC instance and the offset should be passed together to this API.
 *
 * @param handle Pointer to ForestDB handle.
 * @param doc Pointer to ForestDB doc instance that contains the offset to a doc
 *        and whose doc body is populated as a result of this API call.
 * @return FDB_RESULT_SUCCESS on success.
 */
LIBFDB_API
fdb_status fdb_get_byoffset(fdb_handle *handle,
                            fdb_doc *doc);

/**
 * Update the metadata and doc body for a given key.
 * Note that FDB_DOC instance should be created by calling
 * fdb_doc_create(doc, key, keylen, meta, metalen, body, bodylen) before using
 * this API. Setting "deleted" flag in FDB_DOC instance to true is equivalent to
 * calling fdb_del api described below.
 *
 * @param handle Pointer to ForestDB handle.
 * @param doc Pointer to ForestDB doc instance that is used to update a key.
 * @return FDB_RESULT_SUCCESS on success.
 */
LIBFDB_API
fdb_status fdb_set(fdb_handle *handle,
                   fdb_doc *doc);

/**
 * Delete a key, its metadata and value
 * Note that FDB_DOC instance should be created by calling
 * fdb_doc_create(doc, key, keylen, meta, metalen, body, bodylen) before using
 * this API.
 *
 * @param handle Pointer to ForestDB handle.
 * @param doc Pointer to ForestDB doc instance that is used to delete a key.
 * @return FDB_RESULT_SUCCESS on success.
 */
LIBFDB_API
fdb_status fdb_del(fdb_handle *handle,
                   fdb_doc *doc);

/**
 * Simplified API for fdb_get:
 * Retrieve the value (doc body in fdb_get) for a given key.
 *
 * @param handle Pointer to ForestDB handle.
 * @param key Pointer to the key to be retrieved.
 * @param keylen Length of the key.
 * @param value_out Pointer to the value as a result of this API call. Note that this
 *        pointer should be released using free().
 * @param valuelen_out Length of the value as a result of this API call.
 * @return FDB_RESULT_SUCCESS on success.
 */
LIBFDB_API
fdb_status fdb_get_kv(fdb_handle *handle,
                      void *key, size_t keylen,
                      void **value_out, size_t *valuelen_out);

/**
 * Simplified API for fdb_set:
 * Update the value (doc body in fdb_set) for a given key.
 *
 * @param handle Pointer to ForestDB handle.
 * @param key Pointer to the key to be updated.
 * @param keylen Length of the key.
 * @param value Pointer to the value corresponding to the key.
 * @param valuelen Length of the value.
 * @return FDB_RESULT_SUCCESS on success.
 */
LIBFDB_API
fdb_status fdb_set_kv(fdb_handle *handle,
                      void *key, size_t keylen,
                      void *value, size_t valuelen);

/**
 * Simplified API for fdb_del:
 * Delete a key, and its value (doc body in fdb_del).
 *
 * @param handle Pointer to ForestDB handle.
 * @param key Pointer to the key to be deleted.
 * @param keylen Length of the key.
 * @return FDB_RESULT_SUCCESS on success.
 */
LIBFDB_API
fdb_status fdb_del_kv(fdb_handle *handle,
                      void *key, size_t keylen);

/**
 * Commit all pending changes into disk.
 *
 * @param handle Pointer to ForestDB handle.
 * @param opt Commit option.
 * @return FDB_RESULT_SUCCESS on success.
 */
LIBFDB_API
fdb_status fdb_commit(fdb_handle *handle, fdb_commit_opt_t opt);

/**
 * Create an snapshot of a database file in ForestDB.
 *
 * @param handle_in ForestDB handle pointer from which snapshot is to be made
 * @param handle_out Pointer to snapshot handle, close with fdb_close()
 * @param snapshot_seqnum The sequence number or snapshot marker of snapshot.
 *        Note that this seq number should correspond to one of the commits
 *        that have been persisted in the same database instance.
 *        To create an in-memory snapshot of the current database, pass
 *        FDB_SNAPSHOT_INMEM as the sequence number.
 *        In-memory snapshot is a non-durable consistent copy of the forestdb
 *        instance and carries the latest version of all the keys at the point
 *        of the snapshot and can even be taken out of uncommitted transaction.
 * @return FDB_RESULT_SUCCESS on success.
 *         FDB_RESULT_INVALID_ARGS if any input param is NULL, or,
 *                                 if sequence number tree is not enabled
 *         Any other error from fdb_open may be returned
 */
LIBFDB_API
fdb_status fdb_snapshot_open(fdb_handle *handle_in, fdb_handle **handle_out,
                             fdb_seqnum_t snapshot_seqnum);

/**
 * Rollback a database to a specified point represented by the sequence number
 *
 * @param handle_ptr ForestDB database handle that needs to be rolled back
 * @param rollback_seqnum sequence number or rollback point marker of snapshot
 * @return FDB_RESULT_SUCCESS on success.
 *         FDB_RESULT_INVALID_ARGS if any input param is NULL, or,
 *                                 if sequence number tree is not enabled
 *         Any other error from fdb_open may be returned
 */
LIBFDB_API
fdb_status fdb_rollback(fdb_handle **handle_ptr, fdb_seqnum_t rollback_seqnum);

/**
 * Create an iterator to traverse a ForestDB snapshot by key range
 *
 * @param handle Pointer to ForestDB handle.
 * @param iterator Pointer to the place where the iterator is created
 *        as a result of this API call.
 * @param start_key Pointer to the start key. Passing NULL means that
 *        it wants to start with the smallest key in the database.
 * @param start_keylen Length of the start key.
 * @param end_key Pointer to the end key. Passing NULL means that it wants
 *        to end with the largest key in the database.
 * @param end_keylen Length of the end key.
 * @param opt Iterator option.
 * @return FDB_RESULT_SUCCESS on success.
 */
LIBFDB_API
fdb_status fdb_iterator_init(fdb_handle *handle,
                             fdb_iterator **iterator,
                             const void *start_key,
                             size_t start_keylen,
                             const void *end_key,
                             size_t end_keylen,
                             fdb_iterator_opt_t opt);

/**
 * Create an iterator to traverse a ForestDB snapshot by sequence number range
 *
 * @param handle Pointer to ForestDB handle.
 * @param iterator Pointer to the iterator to be created as a result of
 *        this API call.
 * @param start_seq Starting document sequence number to begin iteration from
 * @param end_seq Ending sequence number indicating the last iterated item.
 *        Passing 0 means that it wants to end with the latest key
 *
 * @param opt Iterator option.
 * @return FDB_RESULT_SUCCESS on success.
 */
LIBFDB_API
fdb_status fdb_iterator_sequence_init(fdb_handle *handle,
                             fdb_iterator **iterator,
                             const fdb_seqnum_t start_seq,
                             const fdb_seqnum_t end_seq,
                             fdb_iterator_opt_t opt);

/**
 * Get the prev item (key, metadata, doc body) from the iterator.
 *
 * @param iterator Pointer to the iterator.
 * @param doc Pointer to FDB_DOC instance to be populated by the iterator.
 * @return FDB_RESULT_SUCCESS on success.
 */
LIBFDB_API
fdb_status fdb_iterator_prev(fdb_iterator *iterator,
                             fdb_doc **doc);

/**
 * Get the next item (key, metadata, doc body) from the iterator.
 *
 * @param iterator Pointer to the iterator.
 * @param doc Pointer to FDB_DOC instance to be populated by the iterator.
 * @return FDB_RESULT_SUCCESS on success.
 */
LIBFDB_API
fdb_status fdb_iterator_next(fdb_iterator *iterator,
                             fdb_doc **doc);

/**
 * Get the next item (key, metadata, offset to doc body) from the iterator.
 *
 * @param iterator Pointer to the iterator.
 * @param doc Pointer to FDB_DOC instance to be populated by the iterator.
 *        Note that the API call won't return the doc body, but instead the
 *        offset to the doc on disk.
 * @return FDB_RESULT_SUCCESS on success.
 */
LIBFDB_API
fdb_status fdb_iterator_next_metaonly(fdb_iterator *iterator,
                                      fdb_doc **doc);

/**
 * Fast forward / backward an iterator to return documents after the given
 * seek_key. If the seek key does not exist, the iterator is positioned to
 * return the next sorted key.
 *
 * @param iterator Pointer to the iterator.
 * @param seek_key Pointer to the key to seek to.
 * @param seek_keylen Length of the seek_key
 * @return FDB_RESULT_SUCCESS on success.
 */
LIBFDB_API
fdb_status fdb_iterator_seek(fdb_iterator *iterator, const void *seek_key,
                             const size_t seek_keylen);

/**
 * Close the iterator and free its associated resources.
 *
 * @param iterator Pointer to the iterator.
 * @return FDB_RESULT_SUCCESS on success.
 */
LIBFDB_API
fdb_status fdb_iterator_close(fdb_iterator *iterator);

/**
 * Compact the current database file and create a new compacted file.
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
 *                   // file name "test.fdb" because there are no database handles
 *                   // on "test.fdb.2".
 *
 * Also note that if a given database file is currently being compacted by the
 * compaction daemon, then FDB_RESULT_FILE_IS_BUSY is returned to the caller.
 *
 * @param handle Pointer to ForestDB handle.
 * @param new_filename Name of a new compacted database file.
 * @return FDB_RESULT_SUCCESS on success.
 */
LIBFDB_API
fdb_status fdb_compact(fdb_handle *handle,
                       const char *new_filename);

/**
 * Return the overall disk space actively used by the current database file.
 * Note that this doesn't include the disk space used by stale btree nodes
 * and docs.
 *
 * @param handle Pointer to ForestDB handle.
 * @return FDB_RESULT_SUCCESS on success.
 */
LIBFDB_API
size_t fdb_estimate_space_used(fdb_handle *handle);

/**
 * Return the information about a given database handle.
 *
 * @param handle Pointer to ForestDB handle.
 * @param info Pointer to ForestDB Info instance.
 * @return FDB_RESULT_SUCCESS on success.
 */
LIBFDB_API
fdb_status fdb_get_dbinfo(fdb_handle *handle, fdb_info *info);

/**
 * Change the compaction mode of a given database file referred by the handle passed.
 * If the mode is changed to auto-compaction (i.e., FDB_COMPACTION_AUTO), the compaction
 * threshold is set to the threshold passed to this API.
 * This API can be also used to change the compaction threshould for a given database
 * file whose compaction mode is currently auto-compaction.
 *
 * Note that all the other handles referring the same database file should be closed
 * before this API call, and no concurrent operation should be performed on the same
 * file until the mode switching is done.
 *
 * @param handle Pointer to ForestDB handle.
 * @param mode New compaction mode to be set.
 * @param new_threshold New compaction threshold to be set.
 * @return FDB_RESULT_SUCCESS on success.
 */
LIBFDB_API
fdb_status fdb_switch_compaction_mode(fdb_handle *handle,
                                      fdb_compaction_mode_t mode,
                                      size_t new_threshold);

/**
 * Close the database file.
 *
 * @param handle Pointer to ForestDB handle.
 * @return FDB_RESULT_SUCCESS on success.
 */
LIBFDB_API
fdb_status fdb_close(fdb_handle *handle);

/**
 * Destroy all the resources (e.g., buffer cache, in-memory WAL indexes,
 * daemon compaction thread, etc.) and then shutdown the ForestDB engine.
 * Note that all the database files should be closed through fdb_close calls
 * before calling this API.
 *
 * @return FDB_RESULT_SUCCESS on success.
 */
LIBFDB_API
fdb_status fdb_shutdown();

/**
 * Begin a transaction with the given database handle and isolation level.
 * The transaction should be closed with fdb_end_transaction API call.
 * The isolation levels supported are "read committed" or "read uncommitted".
 * We plan to support both serializable and repeatable read isolation levels
 * in the upcoming releases. For more information about database isolation levels,
 * please refer to the following link:
 * http://en.wikipedia.org/wiki/Isolation_level
 *
 * @param handle Pointer to ForestDB handle.
 * @param isolation_level Isolation level (i.e., read_committed or read_uncommitted)
 *        of the transaction.
 * @return FDB_RESULT_SUCCESS on success.
 */
LIBFDB_API
fdb_status fdb_begin_transaction(fdb_handle *handle,
                                 fdb_isolation_level_t isolation_level);

/**
 * End a transaction for the given database handle by commiting all the dirty
 * updates and releasing all the resouces allocated for that transaction.
 *
 * @param handle Pointer to ForestDB handle.
 * @param opt Commit option.
 * @return FDB_RESULT_SUCCESS on success.
 */
LIBFDB_API
fdb_status fdb_end_transaction(fdb_handle *handle, fdb_commit_opt_t opt);

/**
 * Abort the transaction for a given handle.
 * All uncommitted dirty updates in the handle will be discarded.
 *
 * @param handle Pointer to ForestDB handle.
 * @return FDB_RESULT_SUCCESS on success.
 */
LIBFDB_API
fdb_status fdb_abort_transaction(fdb_handle *handle);


#ifdef __cplusplus
}
#endif

#endif
