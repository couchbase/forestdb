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

#ifndef _JSAHN_WAL_H
#define _JSAHN_WAL_H

#include <stdint.h>
#include "internal_types.h"
#include "hash.h"
#include "list.h"
#include "avltree.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    WAL_RESULT_SUCCESS,
    WAL_RESULT_FAIL
} wal_result;

typedef uint8_t wal_item_action;
enum{
    WAL_ACT_INSERT,
    WAL_ACT_LOGICAL_REMOVE, // An item is marked as "DELETED" by removing its doc body only.
    WAL_ACT_REMOVE // An item (key, metadata, body) is removed immediately.
};

struct wal_item_header{
    void *key;
    uint16_t keylen;
    struct list items;
    struct hash_elem he_key;
    struct list_elem list_elem;
};

#define WAL_ITEM_COMMITTED (0x01)
#define WAL_ITEM_FLUSH_READY (0x02)
#define WAL_ITEM_BY_COMPACTOR (0x04)
struct wal_item{
    fdb_txn *txn;
    wal_item_action action;
    uint8_t flag;
    uint32_t doc_size;
    uint64_t offset;
    uint64_t old_offset;
    fdb_seqnum_t seqnum;
    struct hash_elem he_seq;
    struct list_elem list_elem; // for wal_item_header's 'items'
    struct list_elem list_elem_txn; // for transaction
    struct avl_node avl;
    struct wal_item_header *header;
};

typedef void wal_flush_func(void *dbhandle, struct wal_item *item);
typedef uint64_t wal_get_old_offset_func(void *dbhandle,
                                         struct wal_item *item);
typedef uint64_t wal_doc_move_func(void *dbhandle,
                                   void *new_dhandle,
                                   struct wal_item *item,
                                   fdb_doc *doc);
typedef void wal_commit_mark_func(void *dbhandle,
                                  uint64_t offset);

#define WAL_FLAG_INITIALIZED 0x1


typedef uint8_t wal_dirty_t;
enum {
    FDB_WAL_CLEAN = 0,
    FDB_WAL_DIRTY = 1,
    FDB_WAL_PENDING = 2
};

struct wal {
    uint8_t flag;
    size_t size; // total # entries in WAL
    size_t num_flushable; // # flushable entries in WAL
    size_t num_docs; // # committed docs
    size_t num_deletes; // # committed deleted docs
    uint64_t datasize;
    struct hash hash_bykey; // indexes 'wal_item_header's
    struct hash hash_byseq; // indexes 'wal_item's
    struct list list; // list of 'wal_item_header's
    wal_dirty_t wal_dirty;
    spin_t lock;
};

//typedef struct fdb_doc_struct fdb_doc;

wal_result wal_init(struct filemgr *file, int nbucket);
int wal_is_initialized(struct filemgr *file);
wal_result wal_insert(fdb_txn *txn, struct filemgr *file, fdb_doc *doc, uint64_t offset);
wal_result wal_insert_by_compactor(fdb_txn *txn,
                                   struct filemgr *file,
                                   fdb_doc *doc,
                                   uint64_t offset);
wal_result wal_find(fdb_txn *txn, struct filemgr *file, fdb_doc *doc, uint64_t *offset);
wal_result wal_remove(fdb_txn *txn, struct filemgr *file, fdb_doc *doc);
wal_result wal_txn_migration(void *dbhandle,
                             void *new_dhandle,
                             struct filemgr *old_file,
                             struct filemgr *new_file,
                             wal_doc_move_func *move_doc);
wal_result wal_commit(fdb_txn *txn, struct filemgr *file, wal_commit_mark_func *func);
wal_result wal_flush(struct filemgr *file,
                     void *dbhandle,
                     wal_flush_func *flush_func,
                     wal_get_old_offset_func *get_old_offset);
wal_result wal_flush_by_compactor(struct filemgr *file,
                                  void *dbhandle,
                                  wal_flush_func *flush_func,
                                  wal_get_old_offset_func *get_old_offset);
wal_result wal_discard(fdb_txn *txn, struct filemgr *file);
wal_result wal_close(struct filemgr *file);
wal_result wal_shutdown(struct filemgr *file);
size_t wal_get_size(struct filemgr *file);
size_t wal_get_num_flushable(struct filemgr *file);
size_t wal_get_num_docs(struct filemgr *file);
size_t wal_get_num_deletes(struct filemgr *file);
size_t wal_get_datasize(struct filemgr *file);
void wal_set_dirty_status(struct filemgr *file, wal_dirty_t status);
wal_dirty_t wal_get_dirty_status(struct filemgr *file);

#ifdef __cplusplus
}
#endif

#endif
