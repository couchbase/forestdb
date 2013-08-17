/*
 * Copyright 2013 Jung-Sang Ahn <jungsang.ahn@gmail.com>.
 * All Rights Reserved.
 */

#ifndef _JSAHN_FDB_H
#define _JSAHN_FDB_H

#include <stdint.h>

typedef enum {
    FDB_RESULT_SUCCESS,
    FDB_RESULT_FAIL,
    FDB_RESULT_INVALID_ARGS
} fdb_status;

typedef uint8_t fdb_seqtree_t;
enum {
    FDB_SEQTREE_NOT_USE = 0,
    FDB_SEQTREE_USE = 1
};

typedef uint64_t fdb_seqnum_t;

typedef struct {
    size_t chunksize;
    size_t offsetsize;
    size_t blocksize;
    uint64_t buffercache_size;
    uint64_t wal_threshold;
    struct filemgr_ops *fileops;
    fdb_seqtree_t seqtree;
    unsigned char flag;
} fdb_config;

typedef struct fdb_doc_struct {
    size_t keylen;
    size_t metalen;
    size_t bodylen;
    void *key;
    void *meta;
    void *body;
} fdb_doc;

struct hbtrie;
struct btree;
struct filemgr;
struct btreeblk_handle;
struct docio_handle;
struct btree_blk_ops;

typedef uint8_t fdb_wal_dirty_t;
enum {
    FDB_WAL_CLEAN = 0,
    FDB_WAL_DIRTY = 1
};

typedef struct {
    struct hbtrie *trie;
    struct btree *seqtree;
    struct filemgr *file;
    struct docio_handle *dhandle;
    struct btreeblk_handle *bhandle;
    struct btree_blk_ops *btreeblkops;
    struct filemgr_ops *fileops;
    fdb_config config;
    uint64_t last_header_bid;
    uint64_t datasize;
    uint64_t ndocs;
    uint16_t btree_fanout;
    fdb_wal_dirty_t wal_dirty;
} fdb_handle;

fdb_status fdb_open(fdb_handle *handle, char *filename, fdb_config config);
fdb_status fdb_doc_create(fdb_doc **doc, void *key, size_t keylen, void *meta, size_t metalen,
    void *body, size_t bodylen);
fdb_status fdb_doc_free(fdb_doc *doc);
fdb_status fdb_get(fdb_handle *handle, fdb_doc *doc);
fdb_status fdb_get_metaonly(fdb_handle *handle, fdb_doc *doc, uint64_t *body_offset);
fdb_status fdb_set(fdb_handle *handle, fdb_doc *doc);
fdb_status fdb_commit(fdb_handle *handle);
fdb_status fdb_compact(fdb_handle *handle, char *new_filename);
fdb_status fdb_flush_wal(fdb_handle *handle);
fdb_status fdb_close(fdb_handle *handle);


#endif
