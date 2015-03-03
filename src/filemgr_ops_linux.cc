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
#include <sys/mman.h>

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

void *_filemgr_linux_mmap(int fd, size_t length, void **aux)
{
    (void) aux;
    return mmap(0, length, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
}

int _filemgr_linux_munmap(void *addr, size_t length, void *aux)
{
    (void) aux;
    return munmap(addr, length);
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
    _filemgr_linux_mmap,
    _filemgr_linux_munmap
};

struct filemgr_ops * get_linux_filemgr_ops()
{
    return &linux_ops;
}

#endif
