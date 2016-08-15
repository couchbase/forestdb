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
#include <stdint.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "filemgr.h"
#include "filemgr_ops.h"

#if defined(WIN32) || defined(_WIN32)
#include <windows.h>
#include <io.h>

static inline HANDLE handle_to_win(int fd)
{
    return (HANDLE)_get_osfhandle(fd);
}

fdb_fileops_handle _filemgr_win_constructor(void *ctx) {
    return fd_to_handle(-1);
}

fdb_status _filemgr_win_open(const char *pathname,
                             fdb_fileops_handle *fileops_handle,
                             int flags, mode_t mode)
{
#ifdef _MSC_VER
    int fd = _open(pathname, flags, mode);
    if (fd < 0) {
        errno_t err;
        _get_errno(&err);
        return (fdb_status) convert_errno_to_fdb_status(err, FDB_RESULT_OPEN_FAIL);
    }

    *fileops_handle = fd_to_handle(fd);

    return FDB_RESULT_SUCCESS;
#else
    int fd;
    do {
        fd = open(pathname, flags | O_LARGEFILE, mode);
    } while (fd == -1 && errno == EINTR);

    if (fd < 0) {
        return (fdb_status) convert_errno_to_fdb_status(errno, FDB_RESULT_OPEN_FAIL);
    }

    *fileops_handle = fd_to_handle(fd);

    return FDB_RESULT_SUCCESS;
#endif
}

ssize_t _filemgr_win_pwrite(fdb_fileops_handle fileops_handle, void *buf,
                            size_t count, cs_off_t offset)
{
    int fd = handle_to_fd(fileops_handle);
    HANDLE file = handle_to_win(fd);
    BOOL rv;
    DWORD byteswritten;
    OVERLAPPED winoffs;
    memset(&winoffs, 0, sizeof(winoffs));
    winoffs.Offset = offset & 0xFFFFFFFF;
    winoffs.OffsetHigh = ((uint64_t)offset >> 32) & 0x7FFFFFFF;
    rv = WriteFile(file, buf, count, &byteswritten, &winoffs);
    if(!rv) {
#ifdef _MSC_VER
        errno_t err;
        _get_errno(&err);
        return (ssize_t) convert_errno_to_fdb_status(err, FDB_RESULT_WRITE_FAIL);
#else
        return (ssize_t) convert_errno_to_fdb_status(errno, FDB_RESULT_WRITE_FAIL);
#endif
    }
    return (ssize_t) byteswritten;
}

ssize_t _filemgr_win_pread(fdb_fileops_handle fileops_handle, void *buf,
                           size_t count, cs_off_t offset)
{
    int fd = handle_to_fd(fileops_handle);
    HANDLE file = handle_to_win(fd);
    BOOL rv;
    DWORD bytesread;
    OVERLAPPED winoffs;
    memset(&winoffs, 0, sizeof(winoffs));
    winoffs.Offset = offset & 0xFFFFFFFF;
    winoffs.OffsetHigh = ((uint64_t)offset >> 32) & 0x7FFFFFFF;
    rv = ReadFile(file, buf, count, &bytesread, &winoffs);
    if(!rv) {
#ifdef _MSC_VER
        errno_t err;
        _get_errno(&err);
        return (ssize_t) convert_errno_to_fdb_status(err, FDB_RESULT_READ_FAIL);
#else
        return (ssize_t) convert_errno_to_fdb_status(errno, FDB_RESULT_READ_FAIL);
#endif
    }
    return (ssize_t) bytesread;
}

int _filemgr_win_close(fdb_fileops_handle fileops_handle)
{
    int fd = handle_to_fd(fileops_handle);
#ifdef _MSC_VER
    int rv = 0;
    if (fd != -1) {
        rv = _close(fd);
    }

    if (rv < 0) {
        errno_t err;
        _get_errno(&err);
        return (int) convert_errno_to_fdb_status(err, FDB_RESULT_CLOSE_FAIL);
    }
    return FDB_RESULT_SUCCESS;
#else
    int rv = 0;
    if (fd != -1) {
        do {
            rv = close(fd);
        } while (rv == -1 && errno == EINTR);
    }

    if (rv < 0) {
        return (int) convert_errno_to_fdb_status(errno, FDB_RESULT_CLOSE_FAIL);
    }
    return FDB_RESULT_SUCCESS;
#endif
}

cs_off_t _filemgr_win_goto_eof(fdb_fileops_handle fileops_handle)
{
#ifdef _MSC_VER
    cs_off_t rv = _lseeki64(handle_to_fd(fileops_handle), 0, SEEK_END);
    if (rv < 0) {
        errno_t err;
        _get_errno(&err);
        return (cs_off_t) convert_errno_to_fdb_status(err, FDB_RESULT_SEEK_FAIL);
    }
    return rv;
#else
    cs_off_t rv = lseek(handle_to_fd(fileops_handle), 0, SEEK_END);
    if (rv < 0) {
        return (cs_off_t) convert_errno_to_fdb_status(errno, FDB_RESULT_SEEK_FAIL);
    }
    return rv;
#endif
}

cs_off_t _filemgr_win_file_size(fdb_fileops_handle fileops_handle,
                                const char *filename)
{
#ifdef _MSC_VER
    struct _stat st;
    if (_stat(filename, &st) == -1) {
        errno_t err;
        _get_errno(&err);
        return (cs_off_t) convert_errno_to_fdb_status(err, FDB_RESULT_READ_FAIL);
    }
    return st.st_size;
#else
    struct stat st;
    if (stat(filename, &st) == -1) {
        return (cs_off_t) convert_errno_to_fdb_status(errno, FDB_RESULT_READ_FAIL);
    }
    return st.st_size;
#endif
}

int _filemgr_win_fsync(fdb_fileops_handle fileops_handle)
{
    int fd = handle_to_fd(fileops_handle);
    HANDLE file = handle_to_win(fd);

    if (!FlushFileBuffers(file)) {
#ifdef _MSC_VER
        errno_t err;
        _get_errno(&err);
        return (int) convert_errno_to_fdb_status(err, FDB_RESULT_FSYNC_FAIL);
#else
        return (int) convert_errno_to_fdb_status(errno, FDB_RESULT_FSYNC_FAIL);
#endif
    }
    return FDB_RESULT_SUCCESS;
}

int _filemgr_win_fdatasync(fdb_fileops_handle fileops_handle)
{
    return _filemgr_win_fsync(fileops_handle);
}

void _filemgr_win_get_errno_str(fdb_fileops_handle fileops_handle,
                                char *buf, size_t size)
{
    if (!buf) {
        return;
    }

    char* win_msg = NULL;
    DWORD err = GetLastError();
    FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER |
                   FORMAT_MESSAGE_FROM_SYSTEM |
                   FORMAT_MESSAGE_IGNORE_INSERTS,
                   NULL, err,
                   MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                   (LPTSTR) &win_msg,
                   0, NULL);
    _snprintf(buf, size, "errno = %d: '%s'", err, win_msg);
    LocalFree(win_msg);
}

void *_filemgr_win_mmap(fdb_fileops_handle fileops_handle, size_t length, void **aux)
{
    int fd = handle_to_fd(fileops_handle);
    HANDLE file = handle_to_win(fd);
    HANDLE map = CreateFileMapping(file, NULL, PAGE_READWRITE, 0, length, NULL);
    if (map == NULL) {
        return NULL;
    }
    void *addr = MapViewOfFile(map, FILE_MAP_ALL_ACCESS, 0, 0, length);
    *aux = map;
    return addr;
}

int _filemgr_win_munmap(fdb_fileops_handle fileops_handle,
                        void *addr, size_t length, void *aux)
{
    (void) fileops_handle;
    int ret;
    ret = UnmapViewOfFile(addr);
    if (ret) {
        HANDLE map = aux;
        CloseHandle(map);
        return 0;
    } else {
        return -1;
    }
}

int _filemgr_aio_init(fdb_fileops_handle fileops_handle,
                      struct async_io_handle *aio_handle)
{
    return FDB_RESULT_AIO_NOT_SUPPORTED;
}

int _filemgr_aio_prep_read(fdb_fileops_handle fileops_handle,
                           struct async_io_handle *aio_handle, size_t aio_idx,
                           size_t read_size, uint64_t offset)
{
    return FDB_RESULT_AIO_NOT_SUPPORTED;
}

int _filemgr_aio_submit(fdb_fileops_handle fileops_handle,
                        struct async_io_handle *aio_handle, int num_subs)
{
    return FDB_RESULT_AIO_NOT_SUPPORTED;
}

int _filemgr_aio_getevents(fdb_fileops_handle fileops_handle,
                           struct async_io_handle *aio_handle, int min,
                           int max, unsigned int timeout)
{
    return FDB_RESULT_AIO_NOT_SUPPORTED;
}

int _filemgr_aio_destroy(fdb_fileops_handle fileops_handle,
                         struct async_io_handle *aio_handle)
{
    return FDB_RESULT_AIO_NOT_SUPPORTED;
}

int _filemgr_win_get_fs_type(fdb_fileops_handle src_fileops_handle)
{
    return FILEMGR_FS_NO_COW;
}

int _filemgr_win_copy_file_range(int fstype,
                                 fdb_fileops_handle src_fileops_handle,
                                 fdb_fileops_handle dst_fileops_handle,
                                 uint64_t src_off, uint64_t dst_off,
                                 uint64_t len)
{
    return FDB_RESULT_INVALID_ARGS;
}

void _filemgr_win_destructor(fdb_fileops_handle fileops_handle) {
    (void)fileops_handle;
}

struct filemgr_ops win_ops = {
    _filemgr_win_constructor,
    _filemgr_win_open,
    _filemgr_win_pwrite,
    _filemgr_win_pread,
    _filemgr_win_close,
    _filemgr_win_goto_eof,
    _filemgr_win_file_size,
    _filemgr_win_fdatasync,
    _filemgr_win_fsync,
    _filemgr_win_get_errno_str,
    _filemgr_win_mmap,
    _filemgr_win_munmap,
    // Async I/O operations
    _filemgr_aio_init,
    _filemgr_aio_prep_read,
    _filemgr_aio_submit,
    _filemgr_aio_getevents,
    _filemgr_aio_destroy,
    _filemgr_win_get_fs_type,
    _filemgr_win_copy_file_range,
    _filemgr_win_destructor,
    NULL
};

struct filemgr_ops * get_win_filemgr_ops()
{
    return &win_ops;
}

#endif
