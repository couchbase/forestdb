/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
#ifndef COUCH_COMMON_H
#define COUCH_COMMON_H
#include <sys/types.h>
#include <stdint.h>

#include <libcouchstore/visibility.h>

#ifdef __cplusplus
extern "C" {
#endif

    /**
     * Using off_t turned out to be a real challenge. On "unix-like" systems
     * its size is set by a combination of #defines like: _LARGE_FILE,
     * _FILE_OFFSET_BITS and/or _LARGEFILE_SOURCE etc. The interesting
     * part is however Windows.
     *
     * Windows follows the LLP64 data model:
     * http://en.wikipedia.org/wiki/LLP64#64-bit_data_models
     *
     * This means both the int and long int types have a size of 32 bits
     * regardless if it's a 32 or 64 bits Windows system.
     *
     * And Windows defines the type off_t as being a signed long integer:
     * http://msdn.microsoft.com/en-us/library/323b6b3k.aspx
     *
     * This means we can't use off_t on Windows if we deal with files
     * that can have a size of 2Gb or more.
     */
    typedef int64_t cs_off_t;

    /** Document content metadata flags */
    typedef uint8_t couchstore_content_meta_flags;
    enum {
        COUCH_DOC_IS_COMPRESSED = 128,  /**< Document contents compressed via Snappy */
        /* Content Type Reasons (content_meta & 0x0F): */
        COUCH_DOC_IS_JSON = 0,      /**< Document is valid JSON data */
        COUCH_DOC_INVALID_JSON = 1, /**< Document was checked, and was not valid JSON */
        COUCH_DOC_INVALID_JSON_KEY = 2, /**< Document was checked, and contained reserved keys,
                                             was not inserted as JSON. */
        COUCH_DOC_NON_JSON_MODE = 3 /**< Document was not checked (DB running in non-JSON mode) */
    };

    /** A generic data blob. Nothing is implied about ownership of the block pointed to. */
    typedef struct _sized_buf {
        char *buf;
        size_t size;
    } sized_buf;

    /** A CouchStore document, consisting of an ID (key) and data, each of which is a blob. */
    typedef struct _doc {
        sized_buf id;
        sized_buf data;
    } Doc;

    /** Metadata of a CouchStore document. */
    typedef struct _docinfo {
        sized_buf id;               /**< Document ID (key) */
        uint64_t db_seq;            /**< Sequence number in database */
        uint64_t rev_seq;           /**< Revision number of document */
        sized_buf rev_meta;         /**< Revision metadata; uninterpreted by CouchStore.
                                         Needs to be kept small enough to fit in a B-tree index.*/
        int deleted;                /**< Is this a deleted revision? */
        couchstore_content_meta_flags content_meta;  /**< Content metadata flags */
        uint64_t bp;                /**< Byte offset of document data in file */
        size_t size;                /**< Data size in bytes */
    } DocInfo;

#define DOC_INFO_INITIALIZER { {0, 0}, 0, 0, {0, 0}, 0, 0, 0, 0 }

    /** Contents of a 'local' (unreplicated) document. */
    typedef struct _local_doc {
        sized_buf id;
        sized_buf json;
        int deleted;
    } LocalDoc;

    /** Information about the database as a whole. */
    typedef struct {
        const char* filename;       /**< Filesystem path */
        uint64_t last_sequence;     /**< Last sequence number allocated */
        uint64_t doc_count;         /**< Total number of (non-deleted) documents */
        uint64_t deleted_count;     /**< Total number of deleted documents */
        uint64_t space_used;        /**< Disk space actively used by docs */
        cs_off_t header_position;   /**< File offset of current header */
    } DbInfo;


    /** Opaque reference to an open database. */
    typedef struct _db Db;

#ifdef __cplusplus
}
#endif

#endif
