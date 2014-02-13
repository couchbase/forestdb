/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
#ifndef COUCHSTORE_COUCH_DB_H
#define COUCHSTORE_COUCH_DB_H

#include "couch_common.h"

#include <libcouchstore/error.h>
#include <libcouchstore/file_ops.h>

#ifdef __cplusplus
extern "C" {
#endif

    /*///////////////////  OPENING/CLOSING DATABASES: */

    /*
     * Flags to pass as the flags parameter to couchstore_open_db
     */
    typedef uint64_t couchstore_open_flags;
    enum {
        /**
         * Create a new empty .couch file if file doesn't exist.
         */
        COUCHSTORE_OPEN_FLAG_CREATE = 1,
        /**
         * Open the database in read only mode
         */
        COUCHSTORE_OPEN_FLAG_RDONLY = 2
    };


    /**
     * Open a database.
     *
     * The database should be closed with couchstore_close_db().
     *
     * @param filename The name of the file containing the database
     * @param flags Additional flags for how the database should
     *              be opened. See couchstore_open_flags_* for the
     *              available flags.
     * @param db Pointer to where you want the handle to the database to be
     *           stored.
     * @return COUCHSTORE_SUCCESS for success
     */
    LIBCOUCHSTORE_API
    couchstore_error_t couchstore_open_db(const char *filename,
                                          couchstore_open_flags flags,
                                          Db **db);

    /**
     * Open a database, with custom I/O callbacks.
     *
     * The database should be closed with couchstore_close_db().
     *
     * @param filename The name of the file containing the database
     * @param flags Additional flags for how the database should
     *              be opened. See couchstore_open_flags_* for the
     *              available flags.
     * @param ops Pointer to a structure containing the file I/O operations
     *            you want the library to use.
     * @param db Pointer to where you want the handle to the database to be
     *           stored.
     * @return COUCHSTORE_SUCCESS for success
     */
    LIBCOUCHSTORE_API
    couchstore_error_t couchstore_open_db_ex(const char *filename,
                                             couchstore_open_flags flags,
                                             const couch_file_ops *ops,
                                             Db **db);

    /**
     * Close an open database and free all allocated resources.
     *
     * @param db Pointer to the database handle to free.
     * @return COUCHSTORE_SUCCESS upon success
     */
    LIBCOUCHSTORE_API
    couchstore_error_t couchstore_close_db(Db *db);

    /**
     * Get the default couch_file_ops object
     */
    LIBCOUCHSTORE_API
    const couch_file_ops *couchstore_get_default_file_ops(void);

    /**
     * Get information about the database.
     *
     * @param db Pointer to the database handle.
     * @param info Pointer to where you want the info to be stored.
     * @return COUCHSTORE_SUCCESS upon success
     */
    LIBCOUCHSTORE_API
    couchstore_error_t couchstore_db_info(Db *db, DbInfo* info);


    /**
     * Returns the filename of the database, as given when it was opened.
     *
     * @param db Pointer to the database handle.
     * @return Pointer to filename (path). This is an exact copy of the filename given to
     *         couchstore_open_db.
     */
    LIBCOUCHSTORE_API
    const char* couchstore_get_db_filename(Db *db);


    /**
     * Get the position in the file of the mostly recently written
     * database header.
     */
    LIBCOUCHSTORE_API
    uint64_t couchstore_get_header_position(Db *db);


    /*////////////////////  WRITING DOCUMENTS: */

    /*
     * Options used by couchstore_save_document() and
     * couchstore_save_documents():
     */
    typedef uint64_t couchstore_save_options;
    enum {
        /**
         * Snappy compress document data if the high bit of the
         * content_meta field of the DocInfo is set. This is NOT the
         * default, and if this is not set the data field of the Doc will
         * be written to disk as-is, regardless of the content_meta flags.
         */
        COMPRESS_DOC_BODIES = 1
    };

    /**
     * Save document pointed to by doc and docinfo to db.
     *
     * When saving documents you should only set the id, rev_meta,
     * rev_seq, deleted, and content_meta fields on the DocInfo.
     *
     * To delete a docuemnt, set doc to NULL.
     *
     * On return, the db_seq field of the DocInfo will be filled in with the
     * document's (or deletion's) sequence number.
     *
     * @param db database to save the document in
     * @param doc the document to save
     * @param info document info
     * @param options see descrtiption of COMPRESS_DOC_BODIES below
     * @return COUCHSTORE_SUCCESS upon success
     */
    LIBCOUCHSTORE_API
    couchstore_error_t couchstore_save_document(Db *db,
                                                const Doc *doc,
                                                DocInfo *info,
                                                couchstore_save_options options);

    /**
     * Save array of docs to db
     *
     * To delete documents, set docs to NULL: the docs referenced by
     * the docinfos will be deleted. To intermix deletes and inserts
     * in a bulk update, pass docinfos with the deleted flag set.
     *
     * On return, the db_seq fields of the DocInfos will be filled in with the
     * documents' (or deletions') sequence numbers.
     *
     * @param db the database to save documents in
     * @param docs an array of document pointers
     * @param infos an array of docinfo pointers
     * @param numDocs the number documents to save
     * @param options see descrtiption of COMPRESS_DOC_BODIES below
     * @return COUCHSTORE_SUCCESS upon success
     */
    LIBCOUCHSTORE_API
    couchstore_error_t couchstore_save_documents(Db *db,
                                                 Doc* const docs[],
                                                 DocInfo *infos[],
                                                 unsigned numDocs,
                                                 couchstore_save_options options);
    /**
     * Commit all pending changes and flush buffers to persistent storage.
     *
     * @param db database to perform the commit on
     * @return COUCHSTORE_SUCCESS on success
     */
    LIBCOUCHSTORE_API
    couchstore_error_t couchstore_commit(Db *db);


    /*////////////////////  RETRIEVING DOCUMENTS: */

    /**
     * Retrieve the document info for a given key.
     *
     * The info should be freed with couchstore_free_docinfo().
     *
     * @param id the document identifier
     * @param idlen the number of bytes in the identifier
     * @param pInfo where to store the result
     * @return COUCHSTORE_SUCCESS on success.
     */
    LIBCOUCHSTORE_API
    couchstore_error_t couchstore_docinfo_by_id(Db *db,
                                                const void *id,
                                                size_t idlen,
                                                DocInfo **pInfo);

    /**
     * Retrieve the document info for a given sequence number.
     *
     * To look up multiple sequences, it's more efficient to call couchstore_docinfos_by_sequence.
     *
     * @param sequence the document sequence number
     * @param pInfo where to store the result. Must be freed with couchstore_free_docinfo().
     * @return COUCHSTORE_SUCCESS on success.
     */
    LIBCOUCHSTORE_API
    couchstore_error_t couchstore_docinfo_by_sequence(Db *db,
                                                      uint64_t sequence,
                                                      DocInfo **pInfo);

    /** Options flags for open_doc and open_doc_with_docinfo */
    typedef uint64_t couchstore_open_options;
    enum {
        /* Snappy decompress document data if the high bit of the content_meta field
         * of the DocInfo is set.
         * This is NOT the default, and if this is not set the data field of the Doc
         * will be read from disk as-is, regardless of the content_meta flags. */
        DECOMPRESS_DOC_BODIES = 1
    };

    /**
     * Retrieve a doc from the db.
     *
     * The document should be freed with couchstore_free_document()
     *
     * On a successful return, doc.id.buf will point to the id you passed in,
     * so don't free or overwrite the id buffer before freeing the document!
     *
     * @param db database to load document from
     * @param id the identifier to load
     * @param idlen the number of bytes in the id
     * @param pDoc Where to store the result
     * @param options See DECOMPRESS_DOC_BODIES
     * @return COUCHSTORE_SUCCESS if found
     */
    LIBCOUCHSTORE_API
    couchstore_error_t couchstore_open_document(Db *db,
                                                const void *id,
                                                size_t idlen,
                                                Doc **pDoc,
                                                couchstore_open_options options);

    /**
     * Retrieve a doc from the db, using a DocInfo.
     * The DocInfo must have been filled in with valid values by an API call such
     * as couchstore_docinfo_by_id().
     *
     * Do not free the docinfo before freeing the doc, with couchstore_free_document().
     *
     * @param db database to load document from
     * @param docinfo a valid DocInfo, as filled in by couchstore_docinfo_by_id()
     * @param pDoc Where to store the result
     * @param options See DECOMPRESS_DOC_BODIES
     * @return COUCHSTORE_SUCCESS if found
     */
    LIBCOUCHSTORE_API
    couchstore_error_t couchstore_open_doc_with_docinfo(Db *db,
                                                        DocInfo *docinfo,
                                                        Doc **pDoc,
                                                        couchstore_open_options options);

    /**
     * Free all allocated resources from a document returned from
     * couchstore_open_document().
     *
     * @param doc the document to free. May be NULL.
     */
    LIBCOUCHSTORE_API
    void couchstore_free_document(Doc *doc);


    /**
     * Free all allocated resources from a docinfo structure returned by
     * couchstore_docinfo_by_id() or passed to a couchstore_changes_callback_fn.
     *
     * @param docinfo the document info to free. May be NULL.
     */
    LIBCOUCHSTORE_API
    void couchstore_free_docinfo(DocInfo *docinfo);


    /*////////////////////  ITERATING DOCUMENTS: */

    /**
     * The callback function used by couchstore_changes_since(), couchstore_docinfos_by_id()
     * and couchstore_docinfos_by_sequence() to iterate through the documents.
     *
     * The docinfo structure is automatically freed if the callback
     * returns 0. A positive return value will preserve the DocInfo
     * for future use (should be freed with free_docinfo by the
     * caller). A negative return value will cancel the iteration and
     * pass the error value back to the caller.
     *
     * @param db the database being traversed
     * @param docinfo the current document
     * @param ctx user context
     * @return 1 to preserve the DocInfo, 0 or negative error value to free it (see above).
     */
    typedef int (*couchstore_changes_callback_fn)(Db *db,
                                                  DocInfo *docinfo,
                                                  void *ctx);

    /** Options flags for document iteration */
    typedef uint64_t couchstore_docinfos_options;
    enum {
        /* If set, the sequences/ids lists are interpreted as pairs of range endpoints,
         * and all documents within those ranges will be iterated over.
         */
        RANGES = 1,
        /**
         * Send only deleted items.
         */
        COUCHSTORE_DELETES_ONLY = 2,
        /**
         * Send only non-deleted items.
         */
        COUCHSTORE_NO_DELETES = 4
    };
    
    /**
     * Iterate through the changes since sequence number `since`.
     *
     * @param db the database to iterate through
     * @param since the sequence number to start iterating from
     * @param options COUCHSTORE_DELETES_ONLY and COUCHSTORE_NO_DELETES are supported
     * @param callback the callback function used to iterate over all changes
     * @param ctx client context (passed to the callback)
     * @return COUCHSTORE_SUCCESS upon success
     */
    LIBCOUCHSTORE_API
    couchstore_error_t couchstore_changes_since(Db *db,
                                                uint64_t since,
                                                couchstore_docinfos_options options,
                                                couchstore_changes_callback_fn callback,
                                                void *ctx);

    /**
     * Iterate through all documents in order by key.
     *
     * @param db the database to iterate through
     * @param startKeyPtr  The key to start at, or NULL to start from the beginning
     * @param options COUCHSTORE_DELETES_ONLY and COUCHSTORE_NO_DELETES are supported
     * @param callback the callback function used to iterate over all documents
     * @param ctx client context (passed to the callback)
     * @return COUCHSTORE_SUCCESS upon success
     */
    LIBCOUCHSTORE_API
    couchstore_error_t couchstore_all_docs(Db *db,
                                           const sized_buf* startKeyPtr,
                                           couchstore_docinfos_options options,
                                           couchstore_changes_callback_fn callback,
                                           void *ctx);

    /**
     * Iterate over the document infos of a set of sequence numbers.
     *
     * The DocInfos will be presented to the callback in order of ascending sequence
     * number, *not* in the order in which they appear in the sequence[] array.
     *
     * If the RANGES option flag is set, the sequences array is interpreted as
     * alternating begin/end points of ranges, and all DocInfos within those ranges
     * are iterated over. (If there is an odd number of sequences, the iteration will
     * stop at the last sequence.)
     *
     * The callback will not be invoked for nonexistent sequence numbers.
     *
     * @param sequence array of document sequence numbers. Need not be sorted but must not contain
     *          duplicates.
     * @param numDocs number of documents to look up (size of sequence[] array)
     * @param options Set the RANGES bit for range mode (see above)
     * @param callback the callback function used to iterate over document infos
     * @param ctx client context (passed to the callback)
     * @return COUCHSTORE_SUCCESS on success.
     */
    LIBCOUCHSTORE_API
    couchstore_error_t couchstore_docinfos_by_sequence(Db *db,
                                                       const uint64_t sequence[],
                                                       unsigned numDocs,
                                                       couchstore_docinfos_options options,
                                                       couchstore_changes_callback_fn callback,
                                                       void *ctx);

    /**
     * Iterate over the document infos of a set of ids.
     *
     * The DocInfos will be presented to the callback in order of ascending document id,
     * *not* in the order in which they appear in the ids[] array.
     *
     * If the RANGES option flag is set, the ids array is interpreted as alternating
     * begin/end points of ranges, and all DocInfos with IDs within those ranges
     * are iterated over. (If there is an odd number of IDs, the iteration will
     * stop at the last ID.)
     *
     * The callback will not be invoked for nonexistent ids.
     *
     * @param ids array of document ids. Need not be sorted but must not contain
     *          duplicates.
     * @param numDocs number of documents to look up (size of ids[] array)
     * @param options Set the RANGES bit for range mode (see above)
     * @param callback the callback function used to iterate over document infos
     * @param ctx client context (passed to the callback)
     * @return COUCHSTORE_SUCCESS on success.
     */
    LIBCOUCHSTORE_API
    couchstore_error_t couchstore_docinfos_by_id(Db *db,
                                                 const sized_buf ids[],
                                                 unsigned numDocs,
                                                 couchstore_docinfos_options options,
                                                 couchstore_changes_callback_fn callback,
                                                 void *ctx);

    /*////////////////////  ITERATING TREES: */

    /**
     * The callback function used by couchstore_walk_id_tree() and couchstore_walk_seq_tree()
     * to iterate through the B-tree.
     *
     * This function is called both for documents and tree nodes. reduce_value will be non-NULL
     * for a node; doc_info will be non-NULL for a document.
     *
     * The docinfo structure is automatically freed if the callback
     * returns 0. A positive return value will preserve the DocInfo
     * for future use (should be freed with free_docinfo by the
     * caller). A negative return value will cancel the iteration and
     * pass the error value back to the caller.
     *
     * @param db the database being traversed
     * @param depth the current depth in the tree (the root node is 0, and documents are one level
     *          deeper than their leaf nodes)
     * @param doc_info the current document, or NULL if this is a tree node
     * @param subtree_size the on-disk size of this tree node and its children, or 0 for a document
     * @param reduce_value the reduce data of this node, or NULL for a document
     * @param ctx user context
     * @return 1 to preserve the DocInfo, 0 to free it, or a negative error code to abort iteration.
     */
    typedef int (*couchstore_walk_tree_callback_fn)(Db *db,
                                                    int depth,
                                                    const DocInfo* doc_info,
                                                    uint64_t subtree_size,
                                                    const sized_buf* reduce_value,
                                                    void *ctx);

    /**
     * Iterate through the by-ID B-tree, including interior and leaf nodes as well as documents.
     *
     * The iteration is depth-first, in order by document ID. The callback is invoked on a tree
     * node before its children. The first call is for the root node.
     *
     * This is only useful for tools that want to examine the B-tree structure or reduced values,
     * such as couch_dbdump. It's unlikely that applications will need to use it.
     *
     * @param db the database to iterate through
     * @param startDocID  The key to start at, or NULL to start from the beginning
     * @param options COUCHSTORE_DELETES_ONLY and COUCHSTORE_NO_DELETES are supported
     * @param callback the callback function used to iterate over all documents
     * @param ctx client context (passed to the callback)
     * @return COUCHSTORE_SUCCESS upon success
     */
    LIBCOUCHSTORE_API
    couchstore_error_t couchstore_walk_id_tree(Db *db,
                                               const sized_buf* startDocID,
                                               couchstore_docinfos_options options,
                                               couchstore_walk_tree_callback_fn callback,
                                               void *ctx);

    /**
     * Iterate through the by-sequence B-tree, including interior and leaf nodes as well as documents.
     *
     * The iteration is depth-first, in order by sequence. The callback is invoked on a tree
     * node before its children. The first call is for the root node.
     *
     * This is only useful for tools that want to examine the B-tree structure or reduced values,
     * such as couch_dbdump. It's unlikely that applications will need to use it.
     *
     * @param db the database to iterate through
     * @param startSequence the sequence number to start from
     * @param options COUCHSTORE_DELETES_ONLY and COUCHSTORE_NO_DELETES are supported
     * @param callback the callback function used to iterate over all documents
     * @param ctx client context (passed to the callback)
     * @return COUCHSTORE_SUCCESS upon success
     */
    LIBCOUCHSTORE_API
    couchstore_error_t couchstore_walk_seq_tree(Db *db,
                                                uint64_t startSequence,
                                                couchstore_docinfos_options options,
                                                couchstore_walk_tree_callback_fn callback,
                                                void *ctx);

    /*////////////////////  LOCAL DOCUMENTS: */

    /**
     * Get a local doc from the db.
     *
     * The document should be freed with couchstore_free_local_document().
     *
     * @param db database to load document from
     * @param id the identifier to load (must begin with "_local/")
     * @param idlen the number of bytes in the id
     * @param lDoc Where to store the result
     * @return COUCHSTORE_SUCCESS if found
     */
    LIBCOUCHSTORE_API
    couchstore_error_t couchstore_open_local_document(Db *db,
                                                      const void *id,
                                                      size_t idlen,
                                                      LocalDoc **lDoc);

    /**
     * Save a local doc to the db. Its identifier must begin with "_local/".
     * To delete an existing doc, set the deleted flag on the LocalDoc
     * struct. The json buffer will be ignored for a deletion.
     *
     * @param db the database to store the document in
     * @param lDoc the document to store
     * @return COUCHSTORE_SUCCESS on success
     */
    LIBCOUCHSTORE_API
    couchstore_error_t couchstore_save_local_document(Db *db, LocalDoc *lDoc);

    /*
     * Free all allocated resources from a LocalDoc obtained from
     * couchstore_open_local_document().
     *
     * @param lDoc document to free
     */
    LIBCOUCHSTORE_API
    void couchstore_free_local_document(LocalDoc *lDoc);

    /*
     * Compact a database. This creates a new DB file with the same data as the
     * source db, omitting data that is no longer needed.
     * Will use default couch_file_ops to create and write the target db.
     *
     * @param source the source database
     * @param target_filename the filename of the new database to create.
     * @return COUCHSTORE_SUCCESS on success
     */
    LIBCOUCHSTORE_API
    couchstore_error_t couchstore_compact_db(Db* source, const char* target_filename);


    /*
     * Flags to pass as the flags parameter to couchstore_compact_db_ex
     */
    typedef uint64_t couchstore_compact_flags;
    enum {
        /**
         * Do not copy the tombstones of deleted items into compacted file.
         */
        COUCHSTORE_COMPACT_FLAG_DROP_DELETES = 1
    };

    /*
     * Compact a database. This creates a new DB file with the same data as the
     * source db, omitting data that is no longer needed.
     * Will use specified couch_file_ops to create and write the target db.
     *
     * @param source the source database
     * @param target_filename the filename of the new database to create.
     * @param flags flags that change compaction behavior
     * @param ops Pointer to a structure containing the file I/O operations
     *            you want the library to use.
     * @return COUCHSTORE_SUCCESS on success
     */
    LIBCOUCHSTORE_API
    couchstore_error_t couchstore_compact_db_ex(Db* source, const char* target_filename,
                                                uint64_t flags, const couch_file_ops *ops);
    /*////////////////////  MISC: */

    /**
     * Convert an error code from couchstore to a textual description. The
     * text is a constant within the library so you should not try to modify
     * or free the pointer.
     *
     * @param errcode The error code to look up
     * @return a textual description of the error
     */
    LIBCOUCHSTORE_API
    const char *couchstore_strerror(couchstore_error_t errcode);

    /**
     * Prints a description of the last OS-level errors that Couchstore
     * encountered on this thread into buf.
     *
     * @param buf The buffer to store the message in
     * @param size The size of the buffer.
     */
     LIBCOUCHSTORE_API
     void couchstore_last_os_error(char* buf, size_t size);

#ifdef __cplusplus
}
#endif
#endif
