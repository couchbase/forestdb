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

#ifndef _JSAHN_FILEMGR_OPS
#define _JSAHN_FILEMGR_OPS

#include "libforestdb/fdb_types.h"
#include "arch.h"

#ifdef __cplusplus
extern "C" {
#endif

// Note: Please try to ensure that the following filemgr ops also have
// equivalent test/filemgr_anomalous_ops.h/cc test apis for failure testing
struct filemgr_ops {
    int (*open)(const char *pathname, int flags, mode_t mode);
    ssize_t (*pwrite)(int fd, void *buf, size_t count, cs_off_t offset);
    ssize_t (*pread)(int fd, void *buf, size_t count, cs_off_t offset);
    int (*close)(int fd);
    cs_off_t (*goto_eof)(int fd);
    cs_off_t (*file_size)(const char *filename);
    int (*fdatasync)(int fd);
    int (*fsync)(int fd);
    void (*get_errno_str)(char *buf, size_t size);

    // Async I/O operations
    int (*aio_init)(struct async_io_handle *aio_handle);
    int (*aio_prep_read)(struct async_io_handle *aio_handle, size_t aio_idx,
                         size_t read_size, uint64_t offset);
    int (*aio_submit)(struct async_io_handle *aio_handle, int num_subs);
    int (*aio_getevents)(struct async_io_handle *aio_handle, int min,
                         int max, unsigned int timeout);
    int (*aio_destroy)(struct async_io_handle *aio_handle);

    int (*get_fs_type)(int src_fd);
    int (*copy_file_range)(int fs_type, int src_fd, int dst_fd,
                           uint64_t src_off, uint64_t dst_off, uint64_t len);
};

struct filemgr_ops * get_filemgr_ops();

#ifdef __cplusplus
}
#endif

#endif
