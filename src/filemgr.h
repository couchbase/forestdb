/*
 * Copyright 2013 Jung-Sang Ahn <jungsang.ahn@gmail.com>.
 * All Rights Reserved.
 */

#ifndef _JSAHN_FILEMGR_H
#define _JSAHN_FILEMGR_H

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdint.h>
#include <pthread.h>

#include "common.h"
#include "hash.h"

struct filemgr_config {
    int blocksize;
    int ncacheblock;
    int flag;
};

struct filemgr_ops {
    int (*open)(const char *pathname, int flags, mode_t mode);
    int (*pwrite)(int fd, void *buf, size_t count, off_t offset);
    int (*pread)(int fd, void *buf, size_t count, off_t offset);
    int (*close)(int fd);
    off_t (*goto_eof)(int fd);
    int (*fdatasync)(int fd);
    int (*fsync)(int fd);
};

struct filemgr_buffer{
    void *block;
    bid_t lastbid;
};

struct wal;

struct filemgr_header{
    uint16_t size;
    void *data;
};

struct filemgr {
    char *filename;
    uint16_t filename_len;
    int fd;
    uint8_t ref_count;
    uint64_t pos;
    uint64_t last_commit;
    uint32_t blocksize;
    struct wal *wal;
    struct filemgr_header header;
    struct filemgr_ops *ops;
    struct hash_elem e;
    spin_t lock;
};

struct filemgr * filemgr_open(char *filename, struct filemgr_ops *ops, struct filemgr_config config);
void filemgr_update_header(struct filemgr *file, void *buf, size_t len);
void filemgr_close(struct filemgr *file);
bid_t filemgr_get_next_alloc_block(struct filemgr *file);
bid_t filemgr_alloc(struct filemgr *file);
void filemgr_alloc_multiple(struct filemgr *file, int nblock, bid_t *begin, bid_t *end);
void filemgr_read(struct filemgr *file, bid_t bid, void *buf);
void filemgr_write_offset(struct filemgr *file, bid_t bid, uint64_t offset, uint64_t len, void *buf);
void filemgr_write(struct filemgr *file, bid_t bid, void *buf);
int filemgr_is_writable(struct filemgr *file, bid_t bid);
void filemgr_remove_from_cache(struct filemgr *file);
void filemgr_commit(struct filemgr *file);
void filemgr_free();


#endif
