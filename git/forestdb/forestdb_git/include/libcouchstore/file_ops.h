/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
#ifndef LIBCOUCHSTORE_FILE_OPS_H
#define LIBCOUCHSTORE_FILE_OPS_H

#include <stdint.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

    /**
     * Abstract file handle. Implementations can use it for anything they want, whether
     * a pointer to an allocated data structure, or an integer such as a Unix file descriptor.
     */
    typedef struct couch_file_handle_opaque* couch_file_handle;

    /**
     * A structure that defines the implementation of the file I/O primitives
     * used by CouchStore. Passed to couchstore_open_db_ex().
     */
    typedef struct {
        /**
         * Version number that describes the layout of the structure. Should be set
         * to 3.
         */
        uint64_t version;

        /**
         * Initialize state (e.g. allocate memory) for a file handle before opening a file.
         * This callback is optional and doesn't need to do anything at all; it can just return
         * NULL if there isn't anything to do.
         */
        couch_file_handle (*constructor)(void* cookie);

        /**
         * Open a file.
         *
         * @param on input, a pointer to the file handle that was returned by the constructor
         *        function. The function can change this value if it wants to; the value stored
         *        here on return is the one that will be passed to the other functions.
         * @param path the name of the file
         * @param flags flags as specified by UNIX open(2) system call
         * @return COUCHSTORE_SUCCESS upon success.
         */
        couchstore_error_t (*open)(couch_file_handle* handle, const char *path, int oflag);

        /**
         * Close file associated with this handle.
         *
         * @param handle file handle to close
         */
        void (*close)(couch_file_handle handle);

        /**
         * Read a chunk of data from a given offset in the file.
         *
         * @param handle file handle to read from
         * @param buf where to store data
         * @param nbyte number of bytes to read
         * @param offset where to read from
         * @return number of bytes read (which may be less than nbytes),
         *         or a value <= 0 if an error occurred
         */
        ssize_t (*pread)(couch_file_handle handle, void *buf, size_t nbytes, cs_off_t offset);

        /**
         * Write a chunk of data to a given offset in the file.
         *
         * @param handle file handle to write to
         * @param buf where to read data
         * @param nbyte number of bytes to write
         * @param offset where to write to
         * @return number of bytes written (which may be less than nbytes),
         *         or a value <= 0 if an error occurred
         */
        ssize_t (*pwrite)(couch_file_handle handle, const void *buf, size_t nbytes, cs_off_t offset);

        /**
         * Move to the end of the file.
         *
         * @param handle file handle to move the filepointer in
         * @return the offset (from beginning of the file), or -1 if the operation failed
         */
        cs_off_t (*goto_eof)(couch_file_handle handle);

        /**
         * Flush the buffers to disk
         *
         * @param handle file handle to flush
         * @return COUCHSTORE_SUCCESS upon success
         */
        couchstore_error_t (*sync)(couch_file_handle handle);

        /**
         * Called as part of shutting down the db instance this instance was
         * passed to. A hook to for releasing allocated resources
         *
         * @param handle file handle to be released
         */
        void (*destructor)(couch_file_handle handle);

        /**
         * Will be passed to handle constructor. Can be used to keep global state across
         * all handles.
         */
        void *cookie;
    } couch_file_ops;

#ifdef __cplusplus
}
#endif

#endif
