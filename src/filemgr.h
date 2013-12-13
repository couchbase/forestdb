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
    uint8_t async;
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

typedef uint16_t filemgr_header_len_t;
typedef uint64_t filemgr_magic_t; 
typedef uint64_t filemgr_header_revnum_t;

struct filemgr_header{
    filemgr_header_len_t size;
    filemgr_header_revnum_t revnum;
    void *data;
};

struct fnamedic_item;
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
    file_status_t status;
    struct filemgr_config *config;
    struct filemgr *new_file;
    struct fnamedic_item *bcache;
    uint8_t sync;
    spin_t lock;
};

struct filemgr * filemgr_open(char *filename, struct filemgr_ops *ops, struct filemgr_config config);

uint64_t filemgr_update_header(struct filemgr *file, void *buf, size_t len);
filemgr_header_revnum_t filemgr_get_header_revnum(struct filemgr *file);
void filemgr_get_filename_ptr(struct filemgr *file, char **filename, uint16_t *len);

void* filemgr_fetch_header(struct filemgr *file, void *buf, size_t *len);

void filemgr_close(struct filemgr *file);

bid_t filemgr_get_next_alloc_block(struct filemgr *file);
bid_t filemgr_alloc(struct filemgr *file);
void filemgr_alloc_multiple(struct filemgr *file, int nblock, bid_t *begin, bid_t *end);
bid_t filemgr_alloc_multiple_cond(
    struct filemgr *file, bid_t nextbid, int nblock, bid_t *begin, bid_t *end);

void filemgr_read(struct filemgr *file, bid_t bid, void *buf);
void filemgr_write_offset(struct filemgr *file, bid_t bid, uint64_t offset, uint64_t len, void *buf);
void filemgr_write(struct filemgr *file, bid_t bid, void *buf);
int filemgr_is_writable(struct filemgr *file, bid_t bid);
void filemgr_remove_file(struct filemgr *file);
void filemgr_commit(struct filemgr *file);
void filemgr_sync(struct filemgr *file);
void filemgr_shutdown();
void filemgr_update_file_status(struct filemgr *file, file_status_t status);
void filemgr_remove_pending(struct filemgr *old_file, struct filemgr *new_file);
file_status_t filemgr_get_file_status(struct filemgr *file);

#endif
