/*
 * Copyright 2013 Jung-Sang Ahn <jungsang.ahn@gmail.com>.
 * All Rights Reserved.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdint.h>
#include <fcntl.h>

#include "filemgr.h"
#include "filemgr_ops_linux.h"

int _filemgr_linux_open(const char *pathname, int flags, mode_t mode)
{
    return open(pathname, flags, mode);
}

int _filemgr_linux_pwrite(int fd, void *buf, size_t count, off_t offset)
{
    return pwrite(fd, buf, count, offset);
}

int _filemgr_linux_pread(int fd, void *buf, size_t count, off_t offset)
{
    return pread(fd, buf, count, offset);
}

int _filemgr_linux_close(int fd)
{
    return close(fd);
}

off_t _filemgr_linux_goto_eof(int fd)
{
    return lseek(fd, 0, SEEK_END);
}

int _filemgr_linux_fdatasync(int fd)
{
#ifdef __APPLE__
    return fsync(fd);
#elif __linux
    return fdatasync(fd);
#endif
}

int _filemgr_linux_fsync(int fd)
{
    return fsync(fd);
}

struct filemgr_ops linux_ops = {
    _filemgr_linux_open,
    _filemgr_linux_pwrite,
    _filemgr_linux_pread,
    _filemgr_linux_close,
    _filemgr_linux_goto_eof,
    _filemgr_linux_fdatasync,
    _filemgr_linux_fsync
};

struct filemgr_ops * get_linux_filemgr_ops()
{
    return &linux_ops;
}


