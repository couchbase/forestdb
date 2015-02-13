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

#ifndef _FDB_INTERNAL_H
#define _FDB_INTERNAL_H

#include <stdint.h>
#include "common.h"
#include "internal_types.h"
#include "avltree.h"

#ifdef __cplusplus
extern "C" {
#endif

// global KV store header for each file
struct kvs_header {
    fdb_kvs_id_t id_counter;    // increasing counter for KV store ID
    fdb_custom_cmp_variable default_kvs_cmp;
    struct avl_tree *idx_name;
    struct avl_tree *idx_id;
    uint8_t custom_cmp_enabled;
    spin_t lock;
};

// mapping data for each KV store
// (global & permanent data: written into DB file)
#define KVS_FLAG_CUSTOM_CMP (0x1)
struct kvs_node {
    char *kvs_name;
    fdb_kvs_id_t id;
    fdb_seqnum_t seqnum;
    uint64_t flags;
    fdb_custom_cmp_variable custom_cmp; // in-memory attribute
    struct kvs_stat stat;
    struct avl_node avl_name;
    struct avl_node avl_id;
};

typedef enum {
    FDB_VFILENAME = 0,
    FDB_AFILENAME = 1,
} fdb_filename_mode_t;

#define FDB_FLAG_SEQTREE_USE (0x1)
#define FDB_FLAG_ROOT_INITIALIZED (0x2)
#define FDB_FLAG_ROOT_CUSTOM_CMP (0x4)

void buf2kvid(size_t chunksize, void *buf, fdb_kvs_id_t *id);
void kvid2buf(size_t chunksize, fdb_kvs_id_t id, void *buf);
void buf2buf(size_t chunksize_src, void *buf_src,
             size_t chunksize_dst, void *buf_dst);

size_t _fdb_readkey_wrap(void *handle, uint64_t offset, void *buf);
size_t _fdb_readseq_wrap(void *handle, uint64_t offset, void *buf);
int _fdb_custom_cmp_wrap(void *key1, void *key2, void *aux);

fdb_status fdb_log(err_log_callback *callback,
                   fdb_status status,
                   const char *format, ...);
fdb_status _fdb_open(fdb_kvs_handle *handle,
                     const char *filename,
                     fdb_filename_mode_t filename_mode,
                     const fdb_config *config);
fdb_status _fdb_close_root(fdb_kvs_handle *handle);
fdb_status _fdb_close(fdb_kvs_handle *handle);
fdb_status _fdb_commit(fdb_kvs_handle *handle, fdb_commit_opt_t opt);

fdb_status fdb_check_file_reopen(fdb_kvs_handle *handle, file_status_t *status);
void fdb_link_new_file(fdb_kvs_handle *handle);
void fdb_link_new_file_enforce(fdb_kvs_handle *handle);
void fdb_sync_db_header(fdb_kvs_handle *handle);

void fdb_fetch_header(void *header_buf,
                      bid_t *trie_root_bid,
                      bid_t *seq_root_bid,
                      uint64_t *ndocs,
                      uint64_t *nlivenodes,
                      uint64_t *datasize,
                      uint64_t *last_wal_flush_hdr_bid,
                      uint64_t *kv_info_offset,
                      uint64_t *header_flags,
                      char **new_filename,
                      char **old_filename);
uint64_t fdb_set_file_header(fdb_kvs_handle *handle);

fdb_status fdb_open_for_compactor(fdb_file_handle **ptr_fhandle,
                                  const char *filename,
                                  fdb_config *fconfig,
                                  struct list *cmp_func_list);

fdb_status fdb_compact_file(fdb_file_handle *fhandle,
                            const char *new_filename,
                            bool in_place_compaction);

fdb_status _fdb_abort_transaction(fdb_kvs_handle *handle);

void fdb_file_handle_init(fdb_file_handle *fhandle,
                           fdb_kvs_handle *root);
void fdb_file_handle_close_all(fdb_file_handle *fhandle);
void fdb_file_handle_parse_cmp_func(fdb_file_handle *fhandle,
                                    size_t n_func,
                                    char **kvs_names,
                                    fdb_custom_cmp_variable *functions);
void fdb_file_handle_clone_cmp_func_list(fdb_file_handle *fhandle,
                                         struct list *cmp_func_list);
void fdb_file_handle_add_cmp_func(fdb_file_handle *fhandle,
                                  char *kvs_name,
                                  fdb_custom_cmp_variable cmp_func);
void fdb_file_handle_free(fdb_file_handle *fhandle);

fdb_status fdb_kvs_cmp_check(fdb_kvs_handle *handle);
void * fdb_kvs_find_cmp_chunk(void *chunk, void *aux);

void fdb_kvs_info_create(fdb_kvs_handle *root_handle,
                         fdb_kvs_handle *handle,
                         struct filemgr *file,
                         const char *kvs_name);
void fdb_kvs_info_free(fdb_kvs_handle *handle);
void fdb_kvs_header_reset_all_stats(struct filemgr *file);
void fdb_kvs_header_create(struct filemgr *file);
uint64_t fdb_kvs_header_append(struct filemgr *file,
                                  struct docio_handle *dhandle);
void fdb_kvs_header_read(struct filemgr *file,
                            struct docio_handle *dhandle,
                            uint64_t kv_info_offset);
void fdb_kvs_header_copy(fdb_kvs_handle *handle,
                         struct filemgr *new_file,
                         struct docio_handle *new_dhandle);

struct kvs_header;
void _fdb_kvs_init_root(fdb_kvs_handle *handle, struct filemgr *file);
void _fdb_kvs_header_create(struct kvs_header **kv_header_ptr);
void _fdb_kvs_header_import(struct kvs_header *kv_header,
                               void *data, size_t len);
fdb_status _fdb_kvs_get_snap_info(void *data,
                                  fdb_snapshot_info_t *snap_info);
void _fdb_kvs_header_free(struct kvs_header *kv_header);
fdb_seqnum_t _fdb_kvs_get_seqnum(struct kvs_header *kv_header,
                                    fdb_kvs_id_t id);

void fdb_kvs_header_free(struct filemgr *file);

char* _fdb_kvs_get_name(fdb_kvs_handle *kv_ins, struct filemgr *file);

fdb_status _fdb_kvs_open(fdb_kvs_handle *root_handle,
                         fdb_config *config,
                         fdb_kvs_config *kvs_config,
                         struct filemgr *file,
                         const char *filename,
                         const char *kvs_name,
                         fdb_kvs_handle *handle);
fdb_status fdb_kvs_close_all(fdb_kvs_handle *root_handle);

fdb_seqnum_t fdb_kvs_get_seqnum(struct filemgr *file,
                                   fdb_kvs_id_t id);
void fdb_kvs_set_seqnum(struct filemgr *file,
                           fdb_kvs_id_t id,
                           fdb_seqnum_t seqnum);

fdb_status fdb_kvs_rollback(fdb_kvs_handle **handle_ptr, fdb_seqnum_t seqnum);

#ifdef __cplusplus
}
#endif

#endif
