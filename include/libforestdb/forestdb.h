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

#include "forestdb_types.h"

#ifdef _MSC_VER
    #ifdef forestdb_EXPORTS
        #define LIBFDB_API extern __declspec(dllexport)
    #else
        #define LIBFDB_API extern __declspec(dllimport)
    #endif
#else
    #define LIBFDB_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Open the database with a given file name.
 * The database should be closed with fdb_close API call.
 *
 * @param handle Pointer to the place where ForestDB handle is instantiated
 *        as result of this API call.
 * @param filename Name of database file to be opened.
 * @param fdb_config_file Path to the JSON file that contains ForestDB configs.
 * @return FDB_RESULT_SUCCESS on success.
 */
LIBFDB_API
fdb_status fdb_open(fdb_handle **handle,
                    const char *filename,
                    fdb_open_flags flags,
                    const char *fdb_config_file);

/**
 * Pass the customized compare function for B+-Tree traverse.
 *
 * @param handle Pointer to ForestDB handle.
 * @param cmp_func Customized compare function to be used.
 * @return FDB_RESULT_SUCCESS on success.
 */
LIBFDB_API
fdb_status fdb_set_custom_cmp(fdb_handle *handle,
                              fdb_custom_cmp cmp_func);

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
 * @param doc Pointer to ForestDB doc instance whose metadata is populated
 *        as a result of this API call.
 * @param doc_offset Pointer to the offset value of the doc (header + key +
 *        metadata + body) on disk, which is returned from this API call.
 * @return FDB_RESULT_SUCCESS on success.
 */
LIBFDB_API
fdb_status fdb_get_metaonly(fdb_handle *handle,
                            fdb_doc *doc,
                            uint64_t *doc_offset);

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
 * @param doc Pointer to ForestDB doc instance whose key and metadata are
 *        populated as a result of this API call.
 * @param doc_offset Pointer to the offset value of the doc (header + key +
 *        metadata + body) on disk, which is returned from this API call.
 * @return FDB_RESULT_SUCCESS on success.
 */
LIBFDB_API
fdb_status fdb_get_metaonly_byseq(fdb_handle *handle,
                                  fdb_doc *doc,
                                  uint64_t *doc_offset);

/**
 * Retrieve a doc's metadata and body with a given doc offset in the database file.
 * Note that FDB_DOC instance should be first instantiated and populated
 * by calling fdb_get_metaonly, fdb_get_metaonly_byseq, or
 * fdb_iterator_next_offset, which returns an offset to a doc. Then,
 * the FDB_DOC instance and the offset should be passed together to this API.
 *
 * @param handle Pointer to ForestDB handle.
 * @param doc Pointer to ForestDB doc instance whose doc body is
 *        populated as a result of this API call.
 * @param offset Offset to a doc (header + key + metadata + body)
 *        in a database file.
 * @return FDB_RESULT_SUCCESS on success.
 */
LIBFDB_API
fdb_status fdb_get_byoffset(fdb_handle *handle,
                            fdb_doc *doc,
                            uint64_t offset);

/**
 * Update the metadata and doc body for a given key.
 * Note that FDB_DOC instance should be created by calling
 * fdb_doc_create(doc, key, keylen, meta, metalen, body, bodylen) before using
 * this API. Setting bodylen to 0 and body to NULL is equivalent to calling
 * fdb_del api described below
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
 * Commit all pending changes into disk.
 *
 * @param handle Pointer to ForestDB handle.
 * @return FDB_RESULT_SUCCESS on success.
 */
LIBFDB_API
fdb_status fdb_commit(fdb_handle *handle);

/**
 * Create an iterator to traverse the ForestDB snapshot.
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
 * @param doc_offset_out Pointer to the offset value of the doc (header + key +
 *        metadata + body) on disk, which is returned from this API call.
 * @return FDB_RESULT_SUCCESS on success.
 */
LIBFDB_API
fdb_status fdb_iterator_next_offset(fdb_iterator *iterator,
                                    fdb_doc **doc,
                                    uint64_t *doc_offset_out);

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
 *
 * @param handle Pointer to ForestDB handle.
 * @param new_filename Name of a new compacted database file.
 * @return FDB_RESULT_SUCCESS on success.
 */
LIBFDB_API
fdb_status fdb_compact(fdb_handle *handle,
                       const char *new_filename);

/**
 * Flush the in-memory WAL index entries to update the HB+-Tree instance.
 *
 * @param handle Pointer to ForestDB handle.
 * @return FDB_RESULT_SUCCESS on success.
 */
LIBFDB_API
fdb_status fdb_flush_wal(fdb_handle *handle);

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

#ifdef __cplusplus
}
#endif

#endif
