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

#include "filemgr.h"
#include "filemgr_ops.h"

#if defined(WIN32) || defined(_WIN32)
#include <windows.h>
#include <io.h>

static inline HANDLE handle_to_win(int fd)
{
    return (HANDLE)_get_osfhandle(fd);
}

int _filemgr_win_open(const char *pathname, int flags, mode_t mode)
{
#ifdef _MSC_VER
    return _open(pathname, flags, mode);
#else
    return open(pathname, flags, mode);
#endif
}

int _filemgr_win_pwrite(int fd, void *buf, size_t count, off_t offset)
{
    HANDLE file = handle_to_win(fd);
    BOOL rv;
    DWORD byteswritten;
    OVERLAPPED winoffs;
    memset(&winoffs, 0, sizeof(winoffs));
    winoffs.Offset = offset & 0xFFFFFFFF;
    winoffs.OffsetHigh = ((uint64_t)offset >> 32) & 0x7FFFFFFF;
    rv = WriteFile(file, buf, count, &byteswritten, &winoffs);
    if(!rv) {
        return 0;
    }
    return byteswritten;
}

int _filemgr_win_pread(int fd, void *buf, size_t count, off_t offset)
{
    HANDLE file = handle_to_win(fd);
    BOOL rv;
    DWORD bytesread;
    OVERLAPPED winoffs;
    memset(&winoffs, 0, sizeof(winoffs));
    winoffs.Offset = offset & 0xFFFFFFFF;
    winoffs.OffsetHigh = ((uint64_t)offset >> 32) & 0x7FFFFFFF;
    rv = ReadFile(file, buf, count, &bytesread, &winoffs);
    if(!rv) {
        return 0;
    }
    return bytesread;
}

int _filemgr_win_close(int fd)
{
#ifdef _MSC_VER
    return _close(fd);
#else
    return close(fd);
#endif
}

off_t _filemgr_win_goto_eof(int fd)
{
#ifdef _MSC_VER
    return _lseek(fd, 0, SEEK_END);
#else
    return lseek(fd, 0, SEEK_END);
#endif
}

int _filemgr_win_fsync(int fd)
{
    HANDLE file = handle_to_win(fd);

    if (!FlushFileBuffers(file)) {
        return -1;
    }
    return 0;
}

int _filemgr_win_fdatasync(int fd)
{
    return _filemgr_win_fsync(fd);
}

struct filemgr_ops win_ops = {
    _filemgr_win_open,
    _filemgr_win_pwrite,
    _filemgr_win_pread,
    _filemgr_win_close,
    _filemgr_win_goto_eof,
    _filemgr_win_fdatasync,
    _filemgr_win_fsync
};

struct filemgr_ops * get_win_filemgr_ops()
{
    return &win_ops;
}

#endif
