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

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdint.h>
#include <fcntl.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

#include "filemgr.h"
#include "filemgr_ops.h"

#if !defined(WIN32) && !defined(_WIN32)

int _filemgr_linux_open(const char *pathname, int flags, mode_t mode)
{
    int fd;
    do {
        fd = open(pathname, flags | O_LARGEFILE, mode);
    } while (fd == -1 && errno == EINTR);

    if (fd < 0) {
        if (errno == ENOENT) {
            return (int) FDB_RESULT_NO_SUCH_FILE;
        } else {
            return (int) FDB_RESULT_OPEN_FAIL; // LCOV_EXCL_LINE
        }
    }
    return fd;
}

ssize_t _filemgr_linux_pwrite(int fd, void *buf, size_t count, cs_off_t offset)
{
    ssize_t rv;
    do {
        rv = pwrite(fd, buf, count, offset);
    } while (rv == -1 && errno == EINTR); // LCOV_EXCL_LINE

    if (rv < 0) {
        return (ssize_t) FDB_RESULT_WRITE_FAIL; // LCOV_EXCL_LINE
    }
    return rv;
}

ssize_t _filemgr_linux_pread(int fd, void *buf, size_t count, cs_off_t offset)
{
    ssize_t rv;
    do {
        rv = pread(fd, buf, count, offset);
    } while (rv == -1 && errno == EINTR); // LCOV_EXCL_LINE

    if (rv < 0) {
        return (ssize_t) FDB_RESULT_READ_FAIL; // LCOV_EXCL_LINE
    }
    return rv;
}

int _filemgr_linux_close(int fd)
{
    int rv = 0;
    if (fd != -1) {
        do {
            rv = close(fd);
        } while (rv == -1 && errno == EINTR); // LCOV_EXCL_LINE
    }

    if (rv < 0) {
        return FDB_RESULT_CLOSE_FAIL; // LCOV_EXCL_LINE
    }

    return FDB_RESULT_SUCCESS;
}

cs_off_t _filemgr_linux_goto_eof(int fd)
{
    cs_off_t rv = lseek(fd, 0, SEEK_END);
    if (rv < 0) {
        return (cs_off_t) FDB_RESULT_SEEK_FAIL; // LCOV_EXCL_LINE
    }
    return rv;
}

// LCOV_EXCL_START
cs_off_t _filemgr_linux_file_size(const char *filename)
{
    struct stat st;
    if (stat(filename, &st) == -1) {
        return (cs_off_t) FDB_RESULT_READ_FAIL;
    }
    return st.st_size;
}
// LCOV_EXCL_STOP

int _filemgr_linux_fsync(int fd)
{
    int rv;
    do {
        rv = fsync(fd);
    } while (rv == -1 && errno == EINTR); // LCOV_EXCL_LINE

    if (rv == -1) {
        return FDB_RESULT_FSYNC_FAIL; // LCOV_EXCL_LINE
    }

    return FDB_RESULT_SUCCESS;
}

// LCOV_EXCL_START
int _filemgr_linux_fdatasync(int fd)
{
#if defined(__linux__) && !defined(__ANDROID__)
    int rv;
    do {
        rv = fdatasync(fd);
    } while (rv == -1 && errno == EINTR);

    if (rv == -1) {
        return FDB_RESULT_FSYNC_FAIL;
    }

    return FDB_RESULT_SUCCESS;
#else // __linux__ && not __ANDROID__
    return _filemgr_linux_fsync(fd);
#endif // __linux__ && not __ANDROID__
}
// LCOV_EXCL_STOP

void _filemgr_linux_get_errno_str(char *buf, size_t size) {
    if (!buf) {
        return;
    } else {
        char *tbuf = alca(char, size);
#ifdef _POSIX_SOURCE
        char *ret = strerror_r(errno, tbuf, size);
        snprintf(buf, size, "errno = %d: '%s'", errno, ret);
#else
        (void)strerror_r(errno, tbuf, size);
        snprintf(buf, size, "errno = %d: '%s'", errno, tbuf);
#endif
    }
}

int _filemgr_aio_init(struct async_io_handle *aio_handle)
{
#ifdef _ASYNC_IO
    if (!aio_handle) {
        return FDB_RESULT_INVALID_ARGS;
    }
    if (!aio_handle->queue_depth || aio_handle->queue_depth > 512) {
        aio_handle->queue_depth =  ASYNC_IO_QUEUE_DEPTH;
    }
    if (!aio_handle->block_size) {
        aio_handle->block_size = FDB_BLOCKSIZE;
    }

    void *buf;
    malloc_align(buf, FDB_SECTOR_SIZE,
                 aio_handle->block_size * aio_handle->queue_depth);
    aio_handle->aio_buf = (uint8_t *) buf;
    aio_handle->offset_array = (uint64_t*)
        malloc(sizeof(uint64_t) * aio_handle->queue_depth);

    aio_handle->ioq = (struct iocb**)
        malloc(sizeof(struct iocb*) * aio_handle->queue_depth);
    aio_handle->events = (struct io_event *)
        calloc(aio_handle->queue_depth, sizeof(struct io_event));

    for (size_t k = 0; k < aio_handle->queue_depth; ++k) {
        aio_handle->ioq[k] = (struct iocb*) malloc(sizeof(struct iocb));
    }
    memset(&aio_handle->ioctx, 0, sizeof(io_context_t));

    int rc = io_queue_init(aio_handle->queue_depth, &aio_handle->ioctx);
    if (rc < 0) {
        return FDB_RESULT_AIO_INIT_FAIL;
    }
    return FDB_RESULT_SUCCESS;
#else
    return FDB_RESULT_AIO_NOT_SUPPORTED;
#endif
}

int _filemgr_aio_prep_read(struct async_io_handle *aio_handle, size_t aio_idx,
                           size_t read_size, uint64_t offset)
{
#ifdef _ASYNC_IO
    if (!aio_handle) {
        return FDB_RESULT_INVALID_ARGS;
    }
    io_prep_pread(aio_handle->ioq[aio_idx], aio_handle->fd,
                  aio_handle->aio_buf + (aio_idx * aio_handle->block_size),
                  aio_handle->block_size,
                  (offset / aio_handle->block_size) * aio_handle->block_size);
    // Record the original offset.
    aio_handle->offset_array[aio_idx] = offset;
    aio_handle->ioq[aio_idx]->data = &aio_handle->offset_array[aio_idx];
    return FDB_RESULT_SUCCESS;
#else
    return FDB_RESULT_AIO_NOT_SUPPORTED;
#endif
}

int _filemgr_aio_submit(struct async_io_handle *aio_handle, int num_subs)
{
#ifdef _ASYNC_IO
    if (!aio_handle) {
        return FDB_RESULT_INVALID_ARGS;
    }
    int rc = io_submit(aio_handle->ioctx, num_subs, aio_handle->ioq);
    if (rc < 0) {
        return FDB_RESULT_AIO_SUBMIT_FAIL;
    }
    return rc; // 'rc' should be equal to 'num_subs' upon succcess.
#else
    return FDB_RESULT_AIO_NOT_SUPPORTED;
#endif
}

int _filemgr_aio_getevents(struct async_io_handle *aio_handle, int min,
                           int max, unsigned int timeout)
{
#ifdef _ASYNC_IO
    if (!aio_handle) {
        return FDB_RESULT_INVALID_ARGS;
    }

    // Passing max timeout (ms) means that it waits until at least 'min' events
    // have been seen.
    bool wait_for_min = true;
    struct timespec ts;
    if (timeout < (unsigned int) -1) {
        ts.tv_sec = timeout / 1000;
        timeout %= 1000;
        ts.tv_nsec = timeout * 1000000;
        wait_for_min = false;
    }

    int num_events = io_getevents(aio_handle->ioctx, min, max, aio_handle->events,
                                  wait_for_min ? NULL : &ts);
    if (num_events < 0) {
        return FDB_RESULT_AIO_GETEVENTS_FAIL;
    }
    return num_events;
#else
    return FDB_RESULT_AIO_NOT_SUPPORTED;
#endif
}

int _filemgr_aio_destroy(struct async_io_handle *aio_handle)
{
#ifdef _ASYNC_IO
    if (!aio_handle) {
        return FDB_RESULT_INVALID_ARGS;
    }

    io_queue_release(aio_handle->ioctx);
    for(size_t k = 0; k < aio_handle->queue_depth; ++k)
    {
        free(aio_handle->ioq[k]);
    }
    free(aio_handle->ioq);
    free(aio_handle->events);
    free_align(aio_handle->aio_buf);
    free(aio_handle->offset_array);
    return FDB_RESULT_SUCCESS;
#else
    return FDB_RESULT_AIO_NOT_SUPPORTED;
#endif
}

struct filemgr_ops linux_ops = {
    _filemgr_linux_open,
    _filemgr_linux_pwrite,
    _filemgr_linux_pread,
    _filemgr_linux_close,
    _filemgr_linux_goto_eof,
    _filemgr_linux_file_size,
    _filemgr_linux_fdatasync,
    _filemgr_linux_fsync,
    _filemgr_linux_get_errno_str,
    // Async I/O operations
    _filemgr_aio_init,
    _filemgr_aio_prep_read,
    _filemgr_aio_submit,
    _filemgr_aio_getevents,
    _filemgr_aio_destroy
};

struct filemgr_ops * get_linux_filemgr_ops()
{
    return &linux_ops;
}

#endif
