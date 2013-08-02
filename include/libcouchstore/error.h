/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
#ifndef LIBCOUCHSTORE_ERROR_H
#define LIBCOUCHSTORE_ERROR_H 1

#ifndef COUCHSTORE_COUCH_DB_H
#error "You should include <libcouchstore/couch_db.h> instead"
#endif

#ifdef __cplusplus
extern "C" {
#endif

    /** Error values returned by CouchStore API calls. */
    typedef enum {
        COUCHSTORE_SUCCESS = 0,
        COUCHSTORE_ERROR_OPEN_FILE = -1,
        COUCHSTORE_ERROR_CORRUPT = -2,
        COUCHSTORE_ERROR_ALLOC_FAIL = -3,
        COUCHSTORE_ERROR_READ = -4,
        COUCHSTORE_ERROR_DOC_NOT_FOUND = -5,
        COUCHSTORE_ERROR_NO_HEADER = -6,
        COUCHSTORE_ERROR_WRITE = -7,
        COUCHSTORE_ERROR_HEADER_VERSION = -8,
        COUCHSTORE_ERROR_CHECKSUM_FAIL = -9,
        COUCHSTORE_ERROR_INVALID_ARGUMENTS = -10,
        COUCHSTORE_ERROR_NO_SUCH_FILE = -11,
        COUCHSTORE_ERROR_CANCEL = -12
    } couchstore_error_t;

#ifdef __cplusplus
}
#endif

#endif
