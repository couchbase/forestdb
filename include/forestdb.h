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

#ifndef _JSAHN_FDB_H
#define _JSAHN_FDB_H

#include <stdint.h>
#include "option.h"
#include "arch.h"

#ifdef __cplusplus
extern "C" {
#endif

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

typedef int (*fdb_custom_cmp)(void *a, void *b);

typedef struct {
    struct hbtrie *trie;
    struct btree *seqtree;
    struct filemgr *file;
    struct filemgr *new_file;
    struct docio_handle *dhandle;
    struct docio_handle *new_dhandle;
    struct btreeblk_handle *bhandle;
    struct btree_blk_ops *btreeblkops;
    struct filemgr_ops *fileops;
    fdb_config config;
    uint64_t cur_header_revnum;
    uint64_t last_header_bid;
    uint64_t datasize;
    uint64_t ndocs;
    fdb_custom_cmp cmp_func;
    uint16_t btree_fanout;
#ifdef __FDB_SEQTREE
    fdb_seqnum_t seqnum;
#endif
} fdb_handle;

typedef uint8_t fdb_iterator_opt_t;
enum {
    FDB_ITR_NONE = 0x0,
    FDB_ITR_METAONLY = 0x1,
};
struct hbtrie_iterator;
struct avl_tree;
struct avl_node;
typedef struct {
    fdb_handle handle;
    struct hbtrie_iterator *hbtrie_iterator;
    struct avl_tree *wal_tree;
    struct avl_node *tree_cursor;
    void *end_key;
    size_t end_keylen;
    fdb_iterator_opt_t opt;

    // for temporary buffering previous key & offset
    void *_key;
    size_t _keylen;
    uint64_t _offset;
} fdb_iterator;

fdb_status fdb_recover_compaction(fdb_handle *handle, char *new_filename);
fdb_status fdb_set_custom_cmp(fdb_handle *handle, fdb_custom_cmp cmp_func);
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

fdb_status fdb_iterator_init(fdb_handle *handle,
                             fdb_iterator *iterator,
                             void *start_key,
                             size_t start_keylen,
                             void *end_key,
                             size_t end_keylen,
                             fdb_iterator_opt_t opt);
fdb_status fdb_iterator_next(fdb_iterator *iterator, fdb_doc **doc);
fdb_status fdb_iterator_next_offset(fdb_iterator *iterator,
                                    fdb_doc **doc,
                                    uint64_t *doc_offset_out);
fdb_status fdb_iterator_close(fdb_iterator *iterator);

fdb_status fdb_compact(fdb_handle *handle, char *new_filename);
fdb_status fdb_flush_wal(fdb_handle *handle);
size_t fdb_estimate_space_used(fdb_handle *handle);
fdb_status fdb_close(fdb_handle *handle);
fdb_status fdb_shutdown();

#ifdef __cplusplus
}
#endif

#endif
