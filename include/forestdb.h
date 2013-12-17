/*
 * Copyright 2013 Jung-Sang Ahn <jungsang.ahn@gmail.com>.
 * All Rights Reserved.
 */

#ifndef _JSAHN_FDB_H
#define _JSAHN_FDB_H

#include <stdint.h>
#include "option.h"
#include "arch.h"

typedef enum {
    FDB_RESULT_SUCCESS,
    FDB_RESULT_FAIL,
    FDB_RESULT_INVALID_ARGS
} fdb_status;

typedef uint8_t fdb_seqtree_opt_t;
enum {
    FDB_SEQTREE_NOT_USE = 0,
    FDB_SEQTREE_USE = 1
};

typedef uint8_t fdb_durability_opt_t;
enum {
    FDB_DRB_NONE = 0x0,
    FDB_DRB_ODIRECT = 0x1,
    FDB_DRB_ASYNC = 0x2,
    FDB_DRB_ODIRECT_ASYNC = 0x3
};

typedef struct {
    uint16_t chunksize;
    uint16_t offsetsize;
    uint32_t blocksize;
    uint64_t buffercache_size;
    uint64_t wal_threshold;
    struct filemgr_ops *fileops;
    fdb_seqtree_opt_t seqtree_opt;
    fdb_durability_opt_t durability_opt;
    uint32_t flag;
    void *aux;
} fdb_config;

typedef struct fdb_doc_struct {
    size_t keylen;
    size_t metalen;
    size_t bodylen;
    void *key;
    #ifdef __FDB_SEQTREE
        fdb_seqnum_t seqnum;
    #endif
    void *meta;
    void *body;
} fdb_doc;

struct hbtrie;
struct btree;
struct filemgr;
struct btreeblk_handle;
struct docio_handle;
struct btree_blk_ops;

typedef struct {
    struct hbtrie *trie;
    struct btree *seqtree;
    struct filemgr *file;
    struct docio_handle *dhandle;
    struct btreeblk_handle *bhandle;
    struct btree_blk_ops *btreeblkops;
    struct filemgr_ops *fileops;
    fdb_config config;
    uint64_t cur_header_revnum;
    uint64_t last_header_bid;
    uint64_t datasize;
    uint64_t ndocs;
    uint16_t btree_fanout;
#ifdef __FDB_SEQTREE
    fdb_seqnum_t seqnum;
#endif
} fdb_handle;

fdb_status fdb_open(fdb_handle *handle, char *filename, fdb_config *config);
fdb_status fdb_doc_create(fdb_doc **doc, void *key, size_t keylen, void *meta, size_t metalen,
    void *body, size_t bodylen);
fdb_status fdb_doc_update(fdb_doc **doc, void *meta, size_t metalen, void *body, size_t bodylen);
fdb_status fdb_doc_free(fdb_doc *doc);
fdb_status fdb_get(fdb_handle *handle, fdb_doc *doc);
fdb_status fdb_get_metaonly(fdb_handle *handle, fdb_doc *doc, uint64_t *body_offset);
#ifdef __FDB_SEQTREE
fdb_status fdb_get_byseq(fdb_handle *handle, fdb_doc *doc);
fdb_status fdb_get_metaonly_byseq(fdb_handle *handle, fdb_doc *doc, uint64_t *body_offset);
#endif
fdb_status fdb_set(fdb_handle *handle, fdb_doc *doc);
fdb_status fdb_commit(fdb_handle *handle);
fdb_status fdb_compact(fdb_handle *handle, char *new_filename);
fdb_status fdb_flush_wal(fdb_handle *handle);
size_t fdb_estimate_space_used(fdb_handle *handle);
fdb_status fdb_close(fdb_handle *handle);
fdb_status fdb_shutdown();

#endif
