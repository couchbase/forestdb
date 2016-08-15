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

fdb_fileops_handle _filemgr_linux_constructor(void *ctx) {
    return fd_to_handle(-1);
}

fdb_status _filemgr_linux_open(const char *pathname,
                               fdb_fileops_handle *fileops_handle,
                               int flags, mode_t mode)
{
    int fd;
    do {
        fd = open(pathname, flags | O_LARGEFILE, mode);
    } while (fd == -1 && errno == EINTR);

    if (fd < 0) {
        return (fdb_status) convert_errno_to_fdb_status(errno, // LCOV_EXCL_LINE
                                                 FDB_RESULT_OPEN_FAIL);
    }

    *fileops_handle = fd_to_handle(fd);

    return FDB_RESULT_SUCCESS;
}

ssize_t _filemgr_linux_pwrite(fdb_fileops_handle fileops_handle, void *buf,
                              size_t count, cs_off_t offset)
{
    ssize_t rv;
    do {
        rv = pwrite(handle_to_fd(fileops_handle), buf, count, offset);
    } while (rv == -1 && errno == EINTR); // LCOV_EXCL_LINE

    if (rv < 0) {
        return (ssize_t) convert_errno_to_fdb_status(errno, // LCOV_EXCL_LINE
                                                     FDB_RESULT_WRITE_FAIL);
    }
    return rv;
}

ssize_t _filemgr_linux_pread(fdb_fileops_handle fileops_handle, void *buf, size_t count,
                             cs_off_t offset)
{
    ssize_t rv;
    do {
        rv = pread(handle_to_fd(fileops_handle), buf, count, offset);
    } while (rv == -1 && errno == EINTR); // LCOV_EXCL_LINE

    if (rv < 0) {
        return (ssize_t) convert_errno_to_fdb_status(errno, // LCOV_EXCL_LINE
                                                     FDB_RESULT_READ_FAIL);
    }
    return rv;
}

int _filemgr_linux_close(fdb_fileops_handle fileops_handle)
{
    int rv = 0;
    int fd = handle_to_fd(fileops_handle);
    if (fd != -1) {
        do {
            rv = close(fd);
        } while (rv == -1 && errno == EINTR); // LCOV_EXCL_LINE
    }

    if (rv < 0) {
        return (int) convert_errno_to_fdb_status(errno, // LCOV_EXCL_LINE
                                                 FDB_RESULT_CLOSE_FAIL);
    }

    return FDB_RESULT_SUCCESS;
}

cs_off_t _filemgr_linux_goto_eof(fdb_fileops_handle fileops_handle)
{
    cs_off_t rv = lseek(handle_to_fd(fileops_handle), 0, SEEK_END);
    if (rv < 0) {
        return (cs_off_t) convert_errno_to_fdb_status(errno, // LCOV_EXCL_LINE
                                                      FDB_RESULT_SEEK_FAIL);
    }
    return rv;
}

// LCOV_EXCL_START
cs_off_t _filemgr_linux_file_size(fdb_fileops_handle fileops_handle,
                                  const char *filename)
{
    struct stat st;
    if (stat(filename, &st) == -1) {
        return (cs_off_t) convert_errno_to_fdb_status(errno,
                                                      FDB_RESULT_READ_FAIL);
    }
    return st.st_size;
}
// LCOV_EXCL_STOP

int _filemgr_linux_fsync(fdb_fileops_handle fileops_handle)
{
    int rv;
    do {
        rv = fsync(handle_to_fd(fileops_handle));
    } while (rv == -1 && errno == EINTR); // LCOV_EXCL_LINE

    if (rv == -1) {
        return (int) convert_errno_to_fdb_status(errno, // LCOV_EXCL_LINE
                                                 FDB_RESULT_FSYNC_FAIL);
    }

    return FDB_RESULT_SUCCESS;
}

// LCOV_EXCL_START
int _filemgr_linux_fdatasync(fdb_fileops_handle fileops_handle)
{
#if defined(__linux__) && !defined(__ANDROID__)
    int rv;
    do {
        rv = fdatasync(handle_to_fd(fileops_handle));
    } while (rv == -1 && errno == EINTR);

    if (rv == -1) {
        return (int) convert_errno_to_fdb_status(errno, // LCOV_EXCL_LINE
                                                 FDB_RESULT_FSYNC_FAIL);
    }

    return FDB_RESULT_SUCCESS;
#else // __linux__ && not __ANDROID__
    return _filemgr_linux_fsync(fileops_handle);
#endif // __linux__ && not __ANDROID__
}
// LCOV_EXCL_STOP

void _filemgr_linux_get_errno_str(fdb_fileops_handle fileops_handle, char *buf,
                                  size_t size) {
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

void *_filemgr_linux_mmap(fdb_fileops_handle fileops_handle, size_t length, void **aux)
{
    (void) aux;
    void *addr = mmap(0, length, PROT_READ|PROT_WRITE, MAP_SHARED,
                      handle_to_fd(fileops_handle), 0);
    if (addr == MAP_FAILED) {
        return NULL;
    } else {
        return addr;
    }
}

int _filemgr_linux_munmap(fdb_fileops_handle fileops_handle,
                          void *addr, size_t length, void *aux)
{
    (void) fileops_handle;
    (void) aux;
    return munmap(addr, length);
}

int _filemgr_aio_init(fdb_fileops_handle fileops_handle,
                      struct async_io_handle *aio_handle)
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

int _filemgr_aio_prep_read(fdb_fileops_handle fops_handle,
                           struct async_io_handle *aio_handle, size_t aio_idx,
                           size_t read_size, uint64_t offset)
{
#ifdef _ASYNC_IO
    if (!aio_handle) {
        return FDB_RESULT_INVALID_ARGS;
    }
    io_prep_pread(aio_handle->ioq[aio_idx], handle_to_fd(aio_handle->fops_handle),
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

int _filemgr_aio_submit(fdb_fileops_handle fops_handle,
                        struct async_io_handle *aio_handle, int num_subs)
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

int _filemgr_aio_getevents(fdb_fileops_handle fops_handle,
                           struct async_io_handle *aio_handle, int min,
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

int _filemgr_aio_destroy(fdb_fileops_handle fops_handle,
                         struct async_io_handle *aio_handle)
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

#if defined(__APPLE__) || defined(__FreeBSD__)
#include <sys/mount.h>
#elif !defined(__sun)
#include <sys/vfs.h>
#endif

#ifndef BTRFS_SUPER_MAGIC
#define BTRFS_SUPER_MAGIC 0x9123683E
#endif

#ifdef HAVE_BTRFS_IOCTL_H
#include <btrfs/ioctl.h>
#else
#include <sys/ioctl.h>
#ifndef BTRFS_IOCTL_MAGIC
#define BTRFS_IOCTL_MAGIC 0x94
#endif //BTRFS_IOCTL_MAGIC

struct btrfs_ioctl_clone_range_args {
    int64_t src_fd;
    uint64_t src_offset;
    uint64_t src_length;
    uint64_t dest_offset;
};

#define _IOC_NRBITS     8
#define _IOC_TYPEBITS   8

#ifndef _IOC_SIZEBITS
# define _IOC_SIZEBITS  14
#endif

#ifndef _IOC_DIRBITS
# define _IOC_DIRBITS   2
#endif

#define _IOC_NRSHIFT    0
#define _IOC_TYPESHIFT  (_IOC_NRSHIFT+_IOC_NRBITS)
#define _IOC_SIZESHIFT  (_IOC_TYPESHIFT+_IOC_TYPEBITS)
#define _IOC_DIRSHIFT   (_IOC_SIZESHIFT+_IOC_SIZEBITS)

#ifndef _IOC_WRITE
# define _IOC_WRITE     1U
#endif

#ifndef _IOC
#define _IOC(dir,type,nr,size) \
        (((dir)  << _IOC_DIRSHIFT) | \
        ((type) << _IOC_TYPESHIFT) | \
        ((nr)   << _IOC_NRSHIFT) | \
        ((size) << _IOC_SIZESHIFT))
#endif // _IOC

#define _IOC_TYPECHECK(t) (sizeof(t))
#ifndef _IOW
#define _IOW(type,nr,size) _IOC(_IOC_WRITE,(type),(nr),\
                          (_IOC_TYPECHECK(size)))
#endif //_IOW

#define BTRFS_IOC_CLONE_RANGE _IOW(BTRFS_IOCTL_MAGIC, 13, \
                              struct btrfs_ioctl_clone_range_args)
#endif // HAVE_BTRFS_IOCTL_H

#ifndef EXT4_SUPER_MAGIC
#define EXT4_SUPER_MAGIC 0xEF53
#endif

#ifndef EXT4_IOC_TRANFER_BLK_OWNERSHIP
/* linux/fs/ext4/ext4.h */
#define EXT4_IOC_TRANFER_BLK_OWNERSHIP  _IOWR('f', 22, struct tranfer_blk_ownership)

struct tranfer_blk_ownership {
    int32_t dest_fd;           /* destination file decriptor */
    uint64_t src_start;        /* logical start offset in block for src */
    uint64_t dest_start;       /* logical start offset in block for dest */
    uint64_t len;              /* block length to be onwership-transfered */
};
#endif // EXT4_IOC_TRANSFER_BLK_OWNERSHIP

#ifndef __sun
static
int _filemgr_linux_ext4_share_blks(int src_fd, int dst_fd, uint64_t src_off,
                                   uint64_t dst_off, uint64_t len)
{
    int err;
    struct tranfer_blk_ownership tbo;
    tbo.dest_fd = dst_fd;
    tbo.src_start = src_off;
    tbo.dest_start = dst_off;
    tbo.len = len;
    err = ioctl(src_fd, EXT4_IOC_TRANFER_BLK_OWNERSHIP, &tbo);
    if (err) {
        return errno;
    }
    return err;
}
#endif

int _filemgr_linux_get_fs_type(fdb_fileops_handle src_fileops_handle)
{
#ifdef __sun
    // No support for ZFS
    return FILEMGR_FS_NO_COW;
#else
    int ret;
    struct statfs sfs;
    int src_fd = handle_to_fd(src_fileops_handle);
    ret = fstatfs(src_fd, &sfs);
    if (ret != 0) {
        return FDB_RESULT_INVALID_ARGS;
    }
    switch (sfs.f_type) {
        case EXT4_SUPER_MAGIC:
            ret = _filemgr_linux_ext4_share_blks(src_fd, src_fd, 0, 0, 0);
            if (ret == 0) {
                ret = FILEMGR_FS_EXT4_WITH_COW;
            } else {
                ret = FILEMGR_FS_NO_COW;
            }
            break;
        case BTRFS_SUPER_MAGIC:
            ret = FILEMGR_FS_BTRFS;
            break;
        default:
            ret = FILEMGR_FS_NO_COW;
    }
    return ret;
#endif
}

int _filemgr_linux_copy_file_range(int fs_type,
                                   fdb_fileops_handle src_fileops_handle,
                                   fdb_fileops_handle dst_fileops_handle,
                                   uint64_t src_off, uint64_t dst_off,
                                   uint64_t len)
{
    int ret = (int)FDB_RESULT_INVALID_ARGS;
    int src_fd = handle_to_fd(src_fileops_handle);
    int dst_fd = handle_to_fd(dst_fileops_handle);
#ifndef __sun
    if (fs_type == FILEMGR_FS_BTRFS) {
        struct btrfs_ioctl_clone_range_args cr_args;

        memset(&cr_args, 0, sizeof(cr_args));
        cr_args.src_fd = src_fd;
        cr_args.src_offset = src_off;
        cr_args.src_length = len;
        cr_args.dest_offset = dst_off;
        ret = ioctl(dst_fd, BTRFS_IOC_CLONE_RANGE, &cr_args);
        if (ret != 0) { // LCOV_EXCL_START
            ret = errno;
        }              // LCOV_EXCL_STOP
    } else if (fs_type == FILEMGR_FS_EXT4_WITH_COW) {
        ret = _filemgr_linux_ext4_share_blks(src_fd, dst_fd, src_off,
                                             dst_off, len);
    }
#endif
    return ret;
}

void  _filemgr_linux_destructor(fdb_fileops_handle fileops_handle) {
    (void)fileops_handle;
}

struct filemgr_ops linux_ops = {
    _filemgr_linux_constructor,
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
    _filemgr_linux_munmap,
    // Async I/O operations
    _filemgr_aio_init,
    _filemgr_aio_prep_read,
    _filemgr_aio_submit,
    _filemgr_aio_getevents,
    _filemgr_aio_destroy,
    _filemgr_linux_get_fs_type,
    _filemgr_linux_copy_file_range,
    _filemgr_linux_destructor,
    NULL
};

struct filemgr_ops * get_linux_filemgr_ops()
{
    return &linux_ops;
}

#endif
