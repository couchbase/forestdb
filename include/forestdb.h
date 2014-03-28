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

#include <stdint.h>
#include "option.h"
#include "arch.h"

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
 * Status values returned by calling ForestDB APIs.
 */
typedef enum {
    FDB_RESULT_SUCCESS,
    FDB_RESULT_FAIL,
    FDB_RESULT_INVALID_ARGS
} fdb_status;

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
 * ForestDB config options that are passed to fdb_open API.
 */
typedef struct {
    /**
     * Chunk size that is used to build B+-tree at each level.
     */
    uint16_t chunksize;
    /**
     * Size of offset type in a database file.
     */
    uint16_t offsetsize;
    /**
     * Size of block that is a unit of IO operations
     */
    uint32_t blocksize;
    /**
     * Buffer cache size in bytes. If the size is not given, then the buffer
     * cache is disabled.
     */
    uint64_t buffercache_size;
    /**
     * WAL index size threshold in memory. It is set to 4096 entries by default.
     */
    uint64_t wal_threshold;
    /**
     * Abstract file raw IO APIs that allow a user to pass their
     * platform-specific raw IO implementation. If it is not given, it is
     * selected among Linux, Mac OS, and Windows.
     */
    struct filemgr_ops *fileops;
    /**
     * Flag to enable or disable a sequence B+-Tree.
     */
    fdb_seqtree_opt_t seqtree_opt;
    /**
     * Flag to enable synchronous or asynchronous commit options
     */
    fdb_durability_opt_t durability_opt;
    /**
     * Flags for fdb_open API. It can be used for specifying read-only mode.
     */
    uint32_t flag;
    /**
     * Auxiliary config options.
     */
    void *aux;
} fdb_config;

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
     * Pointer to doc's key.
     */
    void *key;
#ifdef __FDB_SEQTREE
    /**
     * Sequence number assigned to a doc.
     */
    fdb_seqnum_t seqnum;
#endif
    /**
     * Pointer to doc's metadata.
     */
    void *meta;
    /**
     * Pointer to doc's body.
     */
    void *body;
} fdb_doc;

struct hbtrie;
struct btree;
struct filemgr;
struct btreeblk_handle;
struct docio_handle;
struct btree_blk_ops;

/**
 * Pointer type definition of a customized compare function.
 */
typedef int (*fdb_custom_cmp)(void *a, void *b);

/**
 * ForestDB database handle definition.
 */
typedef struct {
    /**
     * HB+-Tree Trie instance.
     */
    struct hbtrie *trie;
    /**
     * Sequence B+-Tree instance.
     */
    struct btree *seqtree;
    /**
     * File manager instance.
     */
    struct filemgr *file;
    /**
     * New file manager instance created during compaction.
     */
    struct filemgr *new_file;
    /**
     * Doc IO handle instance.
     */
    struct docio_handle *dhandle;
    /**
     * New doc IO handle instance created during compaction.
     */
    struct docio_handle *new_dhandle;
    /**
     * B+-Tree handle instance.
     */
    struct btreeblk_handle *bhandle;
    /**
     * B+-Tree block operation handle.
     */
    struct btree_blk_ops *btreeblkops;
    /**
     * File manager IO operation handle.
     */
    struct filemgr_ops *fileops;
    /**
     * ForestDB config.
     */
    fdb_config config;
    /**
     * Database header revision number.
     */
    uint64_t cur_header_revnum;
    /**
     * Last header's block id
     */
    uint64_t last_header_bid;
    /**
     * Database overall size.
     */
    uint64_t datasize;
    /**
     * Number of documents in database.
     */
    uint64_t ndocs;
    /**
     * Customized compare function.
     */
    fdb_custom_cmp cmp_func;
    /**
     * B+-Tree fanout degree.
     */
    uint16_t btree_fanout;
#ifdef __FDB_SEQTREE
    /**
     * Database's current sequence number.
     */
    fdb_seqnum_t seqnum;
#endif
} fdb_handle;

/**
 * ForestDB iterator option.
 */
typedef uint8_t fdb_iterator_opt_t;
enum {
    /**
     * Return both key and value through iterator.
     */
    FDB_ITR_NONE = 0x0,
    /**
     * Return key and its metadata only through iterator.
     */
    FDB_ITR_METAONLY = 0x1
};

struct hbtrie_iterator;
struct avl_tree;
struct avl_node;

/**
 * ForestDB iterator structure definition.
 */
typedef struct {
    /**
     * ForestDB database handle.
     */
    fdb_handle handle;
    /**
     * HB+-Tree Trie iterator instance.
     */
    struct hbtrie_iterator *hbtrie_iterator;
    /**
     * AVL tree for WAL entries.
     */
    struct avl_tree *wal_tree;
    /**
     * Cursor instance of AVL tree for WAL entries.
     */
    struct avl_node *tree_cursor;
    /**
     * Iterator end key.
     */
    void *end_key;
    /**
     * End key length.
     */
    size_t end_keylen;
    /**
     * Iterator option.
     */
    fdb_iterator_opt_t opt;

    /**
     * Current key pointed by the iterator.
     */
    void *_key;
    /**
     * Length of key pointed by the iterator.
     */
    size_t _keylen;
    /**
     * Key offset.
     */
    uint64_t _offset;
} fdb_iterator;


/**
 * Open the database with a given file name.
 * The database should be closed with fdb_close API call.
 *
 * @param handle Pointer to ForestDB handle that is initialized as a result of
 *        this API call.
 * @param filename Name of database file to be opened.
 * @param config Pointer to ForestDB config instance.
 * @return FDB_RESULT_SUCCESS on success.
 */
LIBFDB_API
fdb_status fdb_open(fdb_handle *handle,
                    const char *filename,
                    fdb_config *config);

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
 * @param body_offset Pointer to the offset variable that is populated as
 *        a result of this API call.
 * @return FDB_RESULT_SUCCESS on success.
 */
LIBFDB_API
fdb_status fdb_get_metaonly(fdb_handle *handle,
                            fdb_doc *doc,
                            uint64_t *body_offset);

#ifdef __FDB_SEQTREE
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
 * @param body_offset Pointer to the offset variable that is populated as
 *        a result of this API call.
 * @return FDB_RESULT_SUCCESS on success.
 */
LIBFDB_API
fdb_status fdb_get_metaonly_byseq(fdb_handle *handle,
                                  fdb_doc *doc,
                                  uint64_t *body_offset);
#endif

/**
 * Update the metadata and doc body for a given key.
 * Note that FDB_DOC instance should be created by calling
 * fdb_doc_create(doc, key, keylen, meta, metalen, body, bodylen) before using
 * this API. For a key deletion, its body and bodylen should be set to NULL and
 * 0, respectively, in fdb_doc_create API call.
 *
 * @param handle Pointer to ForestDB handle.
 * @param doc Pointer to ForestDB doc instance that is used to update a key.
 * @return FDB_RESULT_SUCCESS on success.
 */
LIBFDB_API
fdb_status fdb_set(fdb_handle *handle,
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
 * @param iterator Pointer to the iterator to be created as a result of
 *        this API call.
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
                             fdb_iterator *iterator,
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
 *        offset to the doc body on disk.
 * @param doc_offset_out Pointer to the offset variable that is set as a result
 *        of this API call.
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
 * Return the overall space used by the current database file.
 *
 * @param handle Pointer to ForestDB handle.
 * @return FDB_RESULT_SUCCESS on success.
 */
LIBFDB_API
size_t fdb_estimate_space_used(fdb_handle *handle);

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
