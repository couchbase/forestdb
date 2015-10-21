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
#include <stdio.h>
#include <errno.h>
#include <string.h>
#if !defined(WIN32) && !defined(_WIN32)
#include <unistd.h>
#endif

#include "filemgr_ops.h"
#include "filemgr_anomalous_ops.h"
#include "libforestdb/forestdb.h"

struct filemgr_ops * get_anomalous_filemgr_ops();
static int filemgr_anomalous_behavior = 0;

// The routines below are adapted from filemgr_ops.cc to add indirection
struct filemgr_ops * get_win_filemgr_ops();
struct filemgr_ops * get_linux_filemgr_ops();
struct filemgr_ops * get_filemgr_ops()
{
    if (filemgr_anomalous_behavior) {
        return get_anomalous_filemgr_ops();
    }

#if defined(WIN32) || defined(_WIN32)
    // windows
    return get_win_filemgr_ops();
#else
    // linux, mac os x
    return get_linux_filemgr_ops();
#endif
}

void filemgr_ops_set_anomalous(int behavior) {
    filemgr_anomalous_behavior = behavior;
}

static struct filemgr_ops *normal_filemgr_ops;
static struct anomalous_callbacks *anon_cbs;
static void *anon_ctx;

// Callbacks default behavior..
int _open_cb(void *ctx, struct filemgr_ops *normal_ops,
             const char *pathname, int flags, mode_t mode)
{
    return normal_ops->open(pathname, flags, mode);
}

ssize_t _pwrite_cb(void *ctx, struct filemgr_ops *normal_ops,
                   int fd, void *buf, size_t count, cs_off_t offset)
{
    return normal_ops->pwrite(fd, buf, count, offset);
}

ssize_t _pread_cb(void *ctx, struct filemgr_ops *normal_ops,
                  int fd, void *buf, size_t count, cs_off_t offset)
{
    return normal_ops->pread(fd, buf, count, offset);
}

int _close_cb(void *ctx, struct filemgr_ops *normal_ops,
              int fd)
{
    return normal_ops->close(fd);
}

cs_off_t _goto_eof_cb(void *ctx, struct filemgr_ops *normal_ops,
                      int fd)
{
    return normal_ops->goto_eof(fd);
}

cs_off_t _file_size_cb(void *ctx, struct filemgr_ops *normal_ops,
                       const char *filename)
{
    return normal_ops->file_size(filename);
}

int _fdatasync_cb(void *ctx, struct filemgr_ops *normal_ops,
                  int fd)
{
    return normal_ops->fdatasync(fd);
}

int _fsync_cb(void *ctx, struct filemgr_ops *normal_ops,
              int fd)
{
    return normal_ops->fsync(fd);
}

void _get_errno_str_cb(void *ctx, struct filemgr_ops *normal_ops,
                    char *buf, size_t size)
{
    normal_ops->get_errno_str(buf, size);
}

int _aio_init_cb(void *ctx, struct filemgr_ops *normal_ops,
                 struct async_io_handle *aio_handle)
{
    return normal_ops->aio_init(aio_handle);
}

int _aio_prep_read_cb(void *ctx, struct filemgr_ops *normal_ops,
                      struct async_io_handle *aio_handle,
                      size_t aio_idx, size_t read_size, uint64_t offset)
{
    return normal_ops->aio_prep_read(aio_handle, aio_idx, read_size, offset);
}

int _aio_submit_cb(void *ctx, struct filemgr_ops *normal_ops,
                   struct async_io_handle *aio_handle, int num_subs)
{
    return normal_ops->aio_submit(aio_handle, num_subs);
}

int _aio_getevents_cb(void *ctx, struct filemgr_ops *normal_ops,
                      struct async_io_handle *aio_handle, int min,
                      int max, unsigned int timeout)
{
    return normal_ops->aio_getevents(aio_handle, min, max, timeout);
}

int _aio_destroy_cb(void *ctx, struct filemgr_ops *normal_ops,
                    struct async_io_handle *aio_handle)
{
    return normal_ops->aio_destroy(aio_handle);
}

int _get_fs_type_cb(void *ctx, struct filemgr_ops *normal_ops, int src)
{
    return normal_ops->get_fs_type(src);
}

int _copy_file_range_cb(void *ctx, struct filemgr_ops *normal_ops,
                        int fstype, int src, int dst, uint64_t src_off,
                        uint64_t dst_off, uint64_t len)
{
    return normal_ops->copy_file_range(fstype, src, dst, src_off, dst_off, len);
}

struct anomalous_callbacks default_callbacks = {
    _open_cb,
    _pwrite_cb,
    _pread_cb,
    _close_cb,
    _goto_eof_cb,
    _file_size_cb,
    _fdatasync_cb,
    _fsync_cb,
    _get_errno_str_cb,
    _aio_init_cb,
    _aio_prep_read_cb,
    _aio_submit_cb,
    _aio_getevents_cb,
    _aio_destroy_cb,
    _get_fs_type_cb,
    _copy_file_range_cb
};

struct anomalous_callbacks default_callbacks_backup = default_callbacks;

struct anomalous_callbacks * get_default_anon_cbs() {
    default_callbacks = default_callbacks_backup;
    return &default_callbacks;
}

void filemgr_ops_anomalous_init(struct anomalous_callbacks *cbs, void *ctx) {
    filemgr_ops_set_anomalous(0);
    normal_filemgr_ops = get_filemgr_ops();
    filemgr_ops_set_anomalous(1);
    if (!cbs) {
        anon_cbs = &default_callbacks;
        anon_ctx = (void *)NULL;
    } else {
        anon_cbs = cbs;
        anon_ctx = ctx;
    }
}

int _filemgr_anomalous_open(const char *pathname, int flags, mode_t mode)
{
    return anon_cbs->open_cb(anon_ctx, normal_filemgr_ops, pathname, flags,
                             mode);
}

ssize_t _filemgr_anomalous_pwrite(int fd, void *buf, size_t count,
                                  cs_off_t offset)
{
    return anon_cbs->pwrite_cb(anon_ctx, normal_filemgr_ops, fd, buf, count,
                               offset);
}

ssize_t _filemgr_anomalous_pread(int fd, void *buf, size_t count,
                                 cs_off_t offset)
{
    return anon_cbs->pread_cb(anon_ctx, normal_filemgr_ops, fd, buf, count,
                              offset);
}

int _filemgr_anomalous_close(int fd)
{
    return anon_cbs->close_cb(anon_ctx, normal_filemgr_ops, fd);
}

cs_off_t _filemgr_anomalous_goto_eof(int fd)
{
    return anon_cbs->goto_eof_cb(anon_ctx, normal_filemgr_ops, fd);
}

cs_off_t _filemgr_anomalous_file_size(const char *filename)
{
    return anon_cbs->file_size_cb(anon_ctx, normal_filemgr_ops, filename);
}

int _filemgr_anomalous_fsync(int fd)
{
    return anon_cbs->fsync_cb(anon_ctx, normal_filemgr_ops, fd);
}

int _filemgr_anomalous_fdatasync(int fd)
{
    return anon_cbs->fdatasync_cb(anon_ctx, normal_filemgr_ops, fd);
}

void _filemgr_anomalous_get_errno_str(char *buf, size_t size)
{
    return anon_cbs->get_errno_str_cb(anon_ctx, normal_filemgr_ops, buf, size);
}

int _filemgr_anomalous_aio_init(struct async_io_handle *aio_handle)
{
    return anon_cbs->aio_init_cb(anon_ctx, normal_filemgr_ops, aio_handle);
}

int _filemgr_anomalous_aio_prep_read(struct async_io_handle *aio_handle,
                                     size_t aio_idx, size_t read_size,
                                     uint64_t offset)
{
    return anon_cbs->aio_prep_read_cb(anon_ctx, normal_filemgr_ops, aio_handle,
                                      aio_idx, read_size, offset);
}

int _filemgr_anomalous_aio_submit(struct async_io_handle *aio_handle, int num_subs)
{
    return anon_cbs->aio_submit_cb(anon_ctx, normal_filemgr_ops, aio_handle,
                                   num_subs);
}

int _filemgr_anomalous_aio_getevents(struct async_io_handle *aio_handle, int min,
                                     int max, unsigned int timeout)
{
    return anon_cbs->aio_getevents_cb(anon_ctx, normal_filemgr_ops, aio_handle, min, max, timeout);
}

int _filemgr_anomalous_aio_destroy(struct async_io_handle *aio_handle)
{
    return anon_cbs->aio_destroy_cb(anon_ctx, normal_filemgr_ops, aio_handle);
}

int _filemgr_anomalous_get_fs_type(int src_fd)
{
    return anon_cbs->get_fs_type_cb(anon_ctx, normal_filemgr_ops, src_fd);
}

int _filemgr_anomalous_copy_file_range(int fs_type, int src_fd, int dst_fd,
                                       uint64_t src_off, uint64_t dst_off,
                                       uint64_t len)
{
    return anon_cbs->copy_file_range_cb(anon_ctx, normal_filemgr_ops, fs_type,
                                        src_fd, dst_fd, src_off, dst_off, len);
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
    _filemgr_anomalous_get_errno_str,
    _filemgr_anomalous_aio_init,
    _filemgr_anomalous_aio_prep_read,
    _filemgr_anomalous_aio_submit,
    _filemgr_anomalous_aio_getevents,
    _filemgr_anomalous_aio_destroy,
    _filemgr_anomalous_get_fs_type,
    _filemgr_anomalous_copy_file_range
};

struct filemgr_ops * get_anomalous_filemgr_ops()
{
    return &anomalous_ops;
}
