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

static struct filemgr_ops *normal_filemgr_ops;
static int _write_fails;

void filemgr_ops_anomalous_init() {
    filemgr_ops_set_anomalous(0);
    normal_filemgr_ops = get_filemgr_ops();
    filemgr_ops_set_anomalous(1);
    _write_fails = 0;
}

int _filemgr_anomalous_open(const char *pathname, int flags, mode_t mode)
{
    return normal_filemgr_ops->open(pathname, flags, mode);
}

void filemgr_anomalous_writes_set(int behavior) {
    _write_fails = behavior;
}

ssize_t _filemgr_anomalous_pwrite(int fd, void *buf, size_t count, cs_off_t offset)
{
    if (_write_fails) {
        return -1;
    }

    return normal_filemgr_ops->pwrite(fd, buf, count, offset);
}

ssize_t _filemgr_anomalous_pread(int fd, void *buf, size_t count, cs_off_t offset)
{
    return normal_filemgr_ops->pread(fd, buf, count, offset);
}

int _filemgr_anomalous_close(int fd)
{
    return normal_filemgr_ops->close(fd);
}

cs_off_t _filemgr_anomalous_goto_eof(int fd)
{
    return normal_filemgr_ops->goto_eof(fd);
}

cs_off_t _filemgr_anomalous_file_size(const char *filename)
{
    return normal_filemgr_ops->file_size(filename);
}

int _filemgr_anomalous_fsync(int fd)
{
    return normal_filemgr_ops->fsync(fd);
}

int _filemgr_anomalous_fdatasync(int fd)
{
    return normal_filemgr_ops->fdatasync(fd);
}

void _filemgr_anomalous_get_errno_str(char *buf, size_t size) {
    return normal_filemgr_ops->get_errno_str(buf, size);
}

struct filemgr_ops anomalous_ops = {
    _filemgr_anomalous_open,
    _filemgr_anomalous_pwrite,
    _filemgr_anomalous_pread,
    _filemgr_anomalous_close,
    _filemgr_anomalous_goto_eof,
    _filemgr_anomalous_file_size,
    _filemgr_anomalous_fdatasync,
    _filemgr_anomalous_fsync,
    _filemgr_anomalous_get_errno_str
};

struct filemgr_ops * get_anomalous_filemgr_ops()
{
    return &anomalous_ops;
}
