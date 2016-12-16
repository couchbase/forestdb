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
#include "btreeblock.h"
#include "hbtrie.h"
#include "docio.h"
#include "staleblock.h"
#include "kvs_handle.h"
#include "version.h"

#ifdef __cplusplus
extern "C" {
#endif

/* If non-NULL, callback invoked when handling a fatal error. */
extern fdb_fatal_error_callback fatal_error_callback;

// TODO: Need to move these functions to (static) member functions of classes

int _cmp_uint64_t_endian_safe(void *key1, void *key2, void *aux);

void fdb_dummy_log_callback(int err_code, const char *err_msg, void *ctx_data);

void buf2kvid(size_t chunksize, void *buf, fdb_kvs_id_t *id);
void kvid2buf(size_t chunksize, fdb_kvs_id_t id, void *buf);
void buf2buf(size_t chunksize_src, void *buf_src,
             size_t chunksize_dst, void *buf_dst);

/**
 * Callback function for ID-trie, to fetch the ID of document.
 */
size_t _fdb_readkey_wrap(void *handle,
                         uint64_t offset,
                         void *req_key,
                         void *chunk,
                         size_t curchunkno,
                         void *buf);
/**
 * Callback function for seq-trie, to fetch the sequence number of document.
 */
size_t _fdb_readseq_wrap(void *handle,
                         uint64_t offset,
                         void *req_key,
                         void *chunk,
                         size_t curchunkno,
                         void *buf);
int _fdb_custom_cmp_wrap(void *key1, void *key2, void *aux);

#ifndef __printflike
#define PRINTFLIKE(n,m)
#else
#define PRINTFLIKE(n,m) __printflike(n,m)
#endif

fdb_status fdb_log(ErrLogCallback *callback,
                   fdb_status status,
                   const char *format, ...) PRINTFLIKE(3, 4);

fdb_status _fdb_clone_snapshot(FdbKvsHandle *handle_in,
                               FdbKvsHandle *handle_out);

fdb_status fdb_check_file_reopen(FdbKvsHandle *handle, file_status_t *status);
void fdb_sync_db_header(FdbKvsHandle *handle);

void fdb_fetch_header(uint64_t version,
                      void *header_buf,
                      bid_t *trie_root_bid,
                      bid_t *seq_root_bid,
                      bid_t *stale_root_bid,
                      uint64_t *ndocs,
                      uint64_t *ndeletes,
                      uint64_t *nlivenodes,
                      uint64_t *datasize,
                      uint64_t *last_wal_flush_hdr_bid,
                      uint64_t *kv_info_offset,
                      uint64_t *header_flags,
                      char **new_filename,
                      char **old_filename);
uint64_t fdb_set_file_header(FdbKvsHandle *handle);

fdb_status fdb_open_for_compactor(fdb_file_handle **ptr_fhandle,
                                  const char *filename,
                                  fdb_config *fconfig,
                                  struct list *cmp_func_list);

fdb_status fdb_compact_file(fdb_file_handle *fhandle,
                            const char *new_filename,
                            bool in_place_compaction,
                            bid_t marker_bid,
                            bool clone_docs,
                            const fdb_encryption_key *new_encryption_key);

typedef enum {
    FDB_RESTORE_NORMAL,
    FDB_RESTORE_KV_INS,
} fdb_restore_mode_t;

void fdb_cmp_func_list_from_filemgr(FileMgr *file,
                                    struct list *cmp_func_list);
void fdb_free_cmp_func_list(struct list *cmp_func_list);

fdb_status fdb_kvs_cmp_check(FdbKvsHandle *handle);
hbtrie_cmp_func * fdb_kvs_find_cmp_chunk(void *chunk, void *aux);

void fdb_kvs_header_reset_all_stats(FileMgr *file);
void fdb_kvs_header_create(FileMgr *file);
uint64_t fdb_kvs_header_append(FdbKvsHandle *handle);

class KvsHeader;

void fdb_kvs_header_read(KvsHeader *kv_header,
                         DocioHandle *dhandle,
                         uint64_t kv_info_offset,
                         uint64_t version,
                         bool only_seq_nums);
void fdb_kvs_header_copy(FdbKvsHandle *handle,
                         FileMgr *new_file,
                         DocioHandle *new_dhandle,
                         uint64_t *new_file_kv_info_offset,
                         bool create_new);
void _fdb_kvs_header_create(KvsHeader **kv_header_ptr);
void _fdb_kvs_header_import(KvsHeader *kv_header,
                            void *data, size_t len, uint64_t version,
                            bool only_seq_nums);

fdb_status _fdb_kvs_get_snap_info(void *data, uint64_t version,
                                  fdb_snapshot_info_t *snap_info);
void _fdb_kvs_header_free(KvsHeader *kv_header);
fdb_seqnum_t _fdb_kvs_get_seqnum(KvsHeader *kv_header,
                                 fdb_kvs_id_t id);
uint64_t _kvs_stat_get_sum_attr(void *data, uint64_t version,
                                kvs_stat_attr_t attr);

bool _fdb_kvs_is_busy(fdb_file_handle *fhandle);

void fdb_kvs_header_free(FileMgr *file);

char* _fdb_kvs_get_name(FdbKvsHandle *kv_ins, FileMgr *file);
/**
 * Extracts the KV Store name from a key sample and offset to start of user key
 * @param handle - pointer to root handle
 * @param keybuf - pointer to key which may include the KV Store Id prefix
 * @param key_offset - return variable of offset to where real key begins
 */
const char* _fdb_kvs_extract_name_off(FdbKvsHandle *handle, void *keybuf,
                                      size_t *key_offset);

fdb_status _fdb_kvs_clone_snapshot(FdbKvsHandle *handle_in,
                                   FdbKvsHandle *handle_out);

fdb_seqnum_t fdb_kvs_get_seqnum(FileMgr *file,
                                fdb_kvs_id_t id);
fdb_seqnum_t fdb_kvs_get_committed_seqnum(FdbKvsHandle *handle);

void fdb_kvs_set_seqnum(FileMgr *file,
                        fdb_kvs_id_t id,
                        fdb_seqnum_t seqnum);

/**
 * Return the smallest commit revision number that are currently being referred.
 *
 * @param handle Pointer to ForestDB KV store handle.
 * @return Header revision number and block ID.
 */
stale_header_info fdb_get_smallest_active_header(FdbKvsHandle *handle);

INLINE size_t _fdb_get_docsize(struct docio_length len)
{
    size_t ret =
        len.keylen +
        len.metalen +
        len.bodylen_ondisk +
        sizeof(struct docio_length);

    ret += sizeof(timestamp_t);

    ret += sizeof(fdb_seqnum_t);

#ifdef __CRC32
    ret += sizeof(uint32_t);
#endif

    return ret;
}

INLINE void _fdb_import_dirty_root(FdbKvsHandle *handle,
                                   bid_t dirty_idtree_root,
                                   bid_t dirty_seqtree_root)
{
    if (ver_btreev2_format(handle->file->getVersion())) {
        // B+tree V2
        if (dirty_idtree_root != BLK_NOT_FOUND) {
            BtreeNodeAddr root_addr(dirty_idtree_root);
            handle->trie->setRootAddr(root_addr);
        }

        if (handle->config.seqtree_opt == FDB_SEQTREE_USE &&
            dirty_seqtree_root != BLK_NOT_FOUND) {
            if (dirty_seqtree_root != handle->seqtree->getRootBid()) {
                if (handle->config.multi_kv_instances) {
                    BtreeNodeAddr root_addr(dirty_seqtree_root);
                    handle->seqtrie->setRootAddr(root_addr);
                } else {
                    BtreeNodeAddr root_addr(dirty_seqtree_root);
                    handle->seqtreeV2->initFromAddr(root_addr);
                }
            }
        }
    } else {
        // old B+tree
        if (dirty_idtree_root != BLK_NOT_FOUND) {
            handle->trie->setRootBid(dirty_idtree_root);
        }
        if (handle->config.seqtree_opt == FDB_SEQTREE_USE) {
            if (dirty_seqtree_root != BLK_NOT_FOUND) {
                if (handle->kvs) {
                    handle->seqtrie->setRootBid(dirty_seqtree_root);
                } else {
                    handle->seqtree->initFromBid(handle->seqtree->getBhandle(),
                                                 handle->seqtree->getKVOps(),
                                                 handle->seqtree->getBlkSize(),
                                                 dirty_seqtree_root);
                }
            }
        }
    }
}

INLINE void _fdb_export_dirty_root(FdbKvsHandle *handle,
                                   bid_t *dirty_idtree_root,
                                   bid_t *dirty_seqtree_root)
{
    if (ver_btreev2_format(handle->file->getVersion())) {
        // B+tree V2
        *dirty_idtree_root = handle->trie->getRootAddr().offset;
        if (handle->config.seqtree_opt == FDB_SEQTREE_USE) {
            if (handle->config.multi_kv_instances) {
                *dirty_seqtree_root = handle->seqtrie->getRootAddr().offset;
            } else {
                *dirty_seqtree_root = handle->seqtreeV2->getRootAddr().offset;
            }
        }
    } else {
        // old B+tree
        *dirty_idtree_root = handle->trie->getRootBid();
        if (handle->config.seqtree_opt == FDB_SEQTREE_USE) {
            if (handle->kvs) {
                *dirty_seqtree_root = handle->seqtrie->getRootBid();
            } else {
                *dirty_seqtree_root = handle->seqtree->getRootBid();
            }
        }
    }
}

// 1. fetch dirty update if exist,
// 2. and assign dirty root nodes to FDB handle
INLINE void _fdb_dirty_update_ready(FdbKvsHandle *handle,
                                    struct filemgr_dirty_update_node **prev_node,
                                    struct filemgr_dirty_update_node **new_node,
                                    bid_t *dirty_idtree_root,
                                    bid_t *dirty_seqtree_root,
                                    bool dirty_wal_flush)
{
    // Note: in B+tree V2 mode, BnodeMgr instance keeps and manages all
    // dirty nodes so we don't need to use FileMgr's dirty node
    // related APIs anymore.
    if (ver_btreev2_format(handle->file->getVersion())) {
        // B+tree V2: sync dirty root info.
        uint64_t local_idtree_root;
        uint64_t local_seqtree_root;
        handle->file->dirtyUpdateGetRootV2(local_idtree_root,
                                           local_seqtree_root);
        _fdb_import_dirty_root(handle, local_idtree_root, local_seqtree_root);
    } else {
        // Otherwise (old B+tree)
        *prev_node = *new_node = NULL;
        *dirty_idtree_root = *dirty_seqtree_root = BLK_NOT_FOUND;

        *prev_node = handle->file->dirtyUpdateGetLatest();

        // discard all cached index blocks
        // to avoid data inconsistency with other writers
        handle->bhandle->discardBlocks();

        // create a new dirty update entry if previous one exists
        // (if we don't this, we cannot identify which block on
        //  dirty copy or actual file is more recent during the WAL flushing.)

        // on dirty wal flush, create a new dirty update entry
        // although there is no previous immutable dirty updates.

        if (*prev_node || dirty_wal_flush) {
            *new_node = handle->file->dirtyUpdateNewNode();
            // sync dirty root nodes
            FileMgr::dirtyUpdateGetRoot(*prev_node,
                                        dirty_idtree_root, dirty_seqtree_root);
        }
        handle->bhandle->setDirtyUpdate(*prev_node);
        handle->bhandle->setDirtyUpdateWriter(*new_node);

        // assign dirty root nodes to FDB handle
        _fdb_import_dirty_root(handle, *dirty_idtree_root, *dirty_seqtree_root);
    }
}

// 1. get dirty root from FDB handle,
// 2. update corresponding dirty update entry,
// 3. make new_node immutable, and close previous immutable node
INLINE void _fdb_dirty_update_finalize(FdbKvsHandle *handle,
                                       struct filemgr_dirty_update_node *prev_node,
                                       struct filemgr_dirty_update_node *new_node,
                                       bid_t *dirty_idtree_root,
                                       bid_t *dirty_seqtree_root,
                                       bool commit)
{
    // Note: please see the comments in _fdb_dirty_update_ready().
    if (ver_btreev2_format(handle->file->getVersion())) {
        // B+tree V2
        if (commit) {
            // commit: set dirty root to BLK_NOT_FOUND
            handle->file->dirtyUpdateSetRootV2(BLK_NOT_FOUND,
                                               BLK_NOT_FOUND);
        } else {
            // Dirty WAL flush

            // write updated index nodes
            handle->trie->writeDirtyNodes();
            if (handle->config.seqtree_opt == FDB_SEQTREE_USE) {
                if (handle->config.multi_kv_instances) {
                    handle->seqtrie->writeDirtyNodes();
                } else {
                    handle->seqtreeV2->writeDirtyNodes();
                }
            }

            handle->bnodeMgr->moveDirtyNodesToBcache();
            BnodeCacheMgr::get()->flush(handle->file);
            handle->bnodeMgr->markEndOfIndexBlocks();

            // set new dirty root info
            _fdb_export_dirty_root(handle, dirty_idtree_root, dirty_seqtree_root);
            handle->file->dirtyUpdateSetRootV2(*dirty_idtree_root,
                                               *dirty_seqtree_root);

        }
    } else {
        // Old B+tree
        // read dirty root nodes from FDB handle
        _fdb_export_dirty_root(handle, dirty_idtree_root, dirty_seqtree_root);
        // assign dirty root nodes to dirty update entry
        if (new_node) {
            FileMgr::dirtyUpdateSetRoot(new_node,
                                        *dirty_idtree_root, *dirty_seqtree_root);
        }
        // clear dirty update setting in bhandle
        handle->bhandle->clearDirtyUpdate();
        // finalize new_node
        if (new_node) {
            handle->file->dirtyUpdateSetImmutable(prev_node, new_node);
        }
        // close previous immutable node
        if (prev_node) {
            FileMgr::dirtyUpdateCloseNode(prev_node);
        }
        if (commit) {
            // write back new_node's dirty blocks
            handle->file->dirtyUpdateCommit(new_node, &handle->log_callback);
        } else {
            // if this update set is still dirty,
            // discard all cached index blocks to avoid data inconsistency.
            handle->bhandle->discardBlocks();
        }
    }
}

#ifdef __cplusplus
}
#endif

#endif
