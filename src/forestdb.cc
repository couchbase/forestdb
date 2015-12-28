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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <time.h>
#if !defined(WIN32) && !defined(_WIN32)
#include <sys/time.h>
#endif

#include "libforestdb/forestdb.h"
#include "fdb_internal.h"
#include "filemgr.h"
#include "hbtrie.h"
#include "list.h"
#include "btree.h"
#include "btree_kv.h"
#include "btree_var_kv_ops.h"
#include "docio.h"
#include "btreeblock.h"
#include "common.h"
#include "wal.h"
#include "snapshot.h"
#include "filemgr_ops.h"
#include "configuration.h"
#include "internal_types.h"
#include "bgflusher.h"
#include "compactor.h"
#include "memleak.h"
#include "time_utils.h"
#include "timing.h"
#include "system_resource_stats.h"
#include "version.h"
#include "staleblock.h"

#ifdef __DEBUG
#ifndef __DEBUG_FDB
    #undef DBG
    #undef DBGCMD
    #undef DBGSW
    #define DBG(...)
    #define DBGCMD(...)
    #define DBGSW(n, ...)
#endif
#endif

#ifdef _TRACE_HANDLES
struct avl_tree open_handles;
static spin_t open_handle_lock;
static int _fdb_handle_cmp(struct avl_node *a, struct avl_node *b, void *aux)
{
    struct _fdb_kvs_handle *aa, *bb;
    aa = _get_entry(a, struct _fdb_kvs_handle, avl_trace);
    bb = _get_entry(b, struct _fdb_kvs_handle, avl_trace);
    return (aa > bb) ? 1 : -1;
}
#endif

static volatile uint8_t fdb_initialized = 0;
static volatile uint8_t fdb_open_inprog = 0;
#ifdef SPIN_INITIALIZER
static spin_t initial_lock = SPIN_INITIALIZER;
#else
static volatile unsigned int initial_lock_status = 0;
static spin_t initial_lock;
#endif

static fdb_status _fdb_wal_snapshot_func(void *handle, fdb_doc *doc,
                                         uint64_t offset);

INLINE int _cmp_uint64_t_endian_safe(void *key1, void *key2, void *aux)
{
    (void) aux;
    uint64_t a,b;
    a = *(uint64_t*)key1;
    b = *(uint64_t*)key2;
    a = _endian_decode(a);
    b = _endian_decode(b);
    return _CMP_U64(a, b);
}

size_t _fdb_readkey_wrap(void *handle, uint64_t offset, void *buf)
{
    keylen_t keylen;
    offset = _endian_decode(offset);
    docio_read_doc_key((struct docio_handle *)handle, offset, &keylen, buf);
    return keylen;
}

size_t _fdb_readseq_wrap(void *handle, uint64_t offset, void *buf)
{
    int size_id, size_seq, size_chunk;
    fdb_seqnum_t _seqnum;
    struct docio_object doc;
    struct docio_handle *dhandle = (struct docio_handle *)handle;

    size_id = sizeof(fdb_kvs_id_t);
    size_seq = sizeof(fdb_seqnum_t);
    size_chunk = dhandle->file->config->chunksize;
    memset(&doc, 0, sizeof(struct docio_object));

    offset = _endian_decode(offset);
    docio_read_doc_key_meta((struct docio_handle *)handle, offset, &doc,
                            true);
    buf2buf(size_chunk, doc.key, size_id, buf);
    _seqnum = _endian_encode(doc.seqnum);
    memcpy((uint8_t*)buf + size_id, &_seqnum, size_seq);

    free(doc.key);
    free(doc.meta);

    return size_id + size_seq;
}

int _fdb_custom_cmp_wrap(void *key1, void *key2, void *aux)
{
    int is_key1_inf, is_key2_inf;
    uint8_t *keystr1 = alca(uint8_t, FDB_MAX_KEYLEN_INTERNAL);
    uint8_t *keystr2 = alca(uint8_t, FDB_MAX_KEYLEN_INTERNAL);
    size_t keylen1, keylen2;
    btree_cmp_args *args = (btree_cmp_args *)aux;
    fdb_custom_cmp_variable cmp = (fdb_custom_cmp_variable)args->aux;

    is_key1_inf = _is_inf_key(key1);
    is_key2_inf = _is_inf_key(key2);
    if (is_key1_inf && is_key2_inf) { // both are infinite
        return 0;
    } else if (!is_key1_inf && is_key2_inf) { // key2 is infinite
        return -1;
    } else if (is_key1_inf && !is_key2_inf) { // key1 is infinite
        return 1;
    }

    _get_var_key(key1, (void*)keystr1, &keylen1);
    _get_var_key(key2, (void*)keystr2, &keylen2);

    if (keylen1 == 0 && keylen2 == 0) {
        return 0;
    } else if (keylen1 ==0 && keylen2 > 0) {
        return -1;
    } else if (keylen1 > 0 && keylen2 == 0) {
        return 1;
    }

    return cmp(keystr1, keylen1, keystr2, keylen2);
}

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
                      char **old_filename)
{
    size_t offset = 0;
    uint16_t new_filename_len;
    uint16_t old_filename_len;

    seq_memcpy(trie_root_bid, (uint8_t *)header_buf + offset,
               sizeof(bid_t), offset);
    *trie_root_bid = _endian_decode(*trie_root_bid);

    seq_memcpy(seq_root_bid, (uint8_t *)header_buf + offset,
               sizeof(bid_t), offset);
    *seq_root_bid = _endian_decode(*seq_root_bid);

    if (ver_staletree_support(version)) {
        seq_memcpy(stale_root_bid, (uint8_t *)header_buf + offset,
                   sizeof(bid_t), offset);
        *stale_root_bid = _endian_decode(*stale_root_bid);
    } else {
        *stale_root_bid = BLK_NOT_FOUND;
    }

    seq_memcpy(ndocs, (uint8_t *)header_buf + offset,
               sizeof(uint64_t), offset);
    *ndocs = _endian_decode(*ndocs);
    if (ver_is_atleast_v2(version)) {
        seq_memcpy(ndeletes, (uint8_t *)header_buf + offset,
                   sizeof(uint64_t), offset);
        *ndeletes = _endian_decode(*ndeletes);
    } else {
        *ndeletes = 0;
    }

    seq_memcpy(nlivenodes, (uint8_t *)header_buf + offset,
               sizeof(uint64_t), offset);
    *nlivenodes = _endian_decode(*nlivenodes);

    seq_memcpy(datasize, (uint8_t *)header_buf + offset,
               sizeof(uint64_t), offset);
    *datasize = _endian_decode(*datasize);

    seq_memcpy(last_wal_flush_hdr_bid, (uint8_t *)header_buf + offset,
               sizeof(uint64_t), offset);
    *last_wal_flush_hdr_bid = _endian_decode(*last_wal_flush_hdr_bid);

    seq_memcpy(kv_info_offset, (uint8_t *)header_buf + offset,
               sizeof(uint64_t), offset);
    *kv_info_offset = _endian_decode(*kv_info_offset);

    seq_memcpy(header_flags, (uint8_t *)header_buf + offset,
               sizeof(uint64_t), offset);
    *header_flags = _endian_decode(*header_flags);

    seq_memcpy(&new_filename_len, (uint8_t *)header_buf + offset,
               sizeof(new_filename_len), offset);
    new_filename_len = _endian_decode(new_filename_len);
    seq_memcpy(&old_filename_len, (uint8_t *)header_buf + offset,
               sizeof(old_filename_len), offset);
    old_filename_len = _endian_decode(old_filename_len);
    if (new_filename_len) {
        *new_filename = (char*)((uint8_t *)header_buf + offset);
    } else {
        *new_filename = NULL;
    }
    offset += new_filename_len;
    if (old_filename && old_filename_len) {
        *old_filename = (char *) malloc(old_filename_len);
        seq_memcpy(*old_filename,
                   (uint8_t *)header_buf + offset,
                   old_filename_len, offset);
    }
}

// read the revnum of the given header of BID
INLINE filemgr_header_revnum_t _fdb_get_header_revnum(fdb_kvs_handle *handle, bid_t bid)
{
    uint8_t *buf = alca(uint8_t, handle->file->blocksize);
    uint64_t version;
    size_t header_len;
    fdb_seqnum_t seqnum;
    filemgr_header_revnum_t revnum = 0;
    fdb_status fs;

    fs = filemgr_fetch_header(handle->file, bid, buf, &header_len,
                              &seqnum, &revnum, NULL, &version, NULL,
                              &handle->log_callback);
    if (fs != FDB_RESULT_SUCCESS) {
        return 0;
    }
    return revnum;
}

INLINE filemgr_header_revnum_t _fdb_get_bmp_revnum(fdb_kvs_handle *handle, bid_t bid)
{
    uint8_t *buf = alca(uint8_t, handle->file->blocksize);
    uint64_t version, bmp_revnum = 0;
    size_t header_len;
    fdb_seqnum_t seqnum;
    filemgr_header_revnum_t revnum;
    fdb_status fs;

    fs = filemgr_fetch_header(handle->file, bid, buf, &header_len,
                              &seqnum, &revnum, NULL, &version, &bmp_revnum,
                              &handle->log_callback);
    if (fs != FDB_RESULT_SUCCESS) {
        return 0;
    }
    return bmp_revnum;
}

INLINE void _fdb_restore_wal(fdb_kvs_handle *handle,
                             fdb_restore_mode_t mode,
                             bid_t hdr_bid,
                             fdb_kvs_id_t kv_id_req)
{
    struct filemgr *file = handle->file;
    uint32_t blocksize = handle->file->blocksize;
    uint64_t last_wal_flush_hdr_bid = handle->last_wal_flush_hdr_bid;
    uint64_t hdr_off = hdr_bid * FDB_BLOCKSIZE;
    uint64_t offset = 0; //assume everything from first block needs restoration
    uint64_t filesize = filemgr_get_pos(handle->file);
    uint64_t doc_scan_limit;
    uint64_t start_bmp_revnum, stop_bmp_revnum;
    uint64_t cur_bmp_revnum = (uint64_t)-1;
    bid_t next_doc_block = BLK_NOT_FOUND;
    err_log_callback *log_callback;

    if (!hdr_off) { // Nothing to do if we don't have a header block offset
        return;
    }

    if (last_wal_flush_hdr_bid != BLK_NOT_FOUND) {
        offset = (last_wal_flush_hdr_bid + 1) * blocksize;
    }

    // If a valid last header was retrieved and it matches the current header
    // OR if WAL already had entries populated, then no crash recovery needed
    if (hdr_off == offset || hdr_bid == last_wal_flush_hdr_bid ||
        (!handle->shandle && wal_get_size(file) &&
            mode != FDB_RESTORE_KV_INS)) {
        return;
    }

    if (mode == FDB_RESTORE_NORMAL && !handle->shandle) {
        // for normal WAL restore, set status to dirty
        wal_set_dirty_status(handle->file, FDB_WAL_DIRTY);
    }

    // Temporarily disable the error logging callback as there are false positive
    // checksum errors in docio_read_doc.
    // TODO: Need to adapt docio_read_doc to separate false checksum errors.
    log_callback = handle->dhandle->log_callback;
    handle->dhandle->log_callback = NULL;

    if (!handle->shandle) {
        filemgr_mutex_lock(file);
    }

    start_bmp_revnum = _fdb_get_bmp_revnum(handle, last_wal_flush_hdr_bid);
    stop_bmp_revnum= _fdb_get_bmp_revnum(handle, hdr_bid);
    cur_bmp_revnum = start_bmp_revnum;

    // A: reused blocks during the 1st block reclaim (bmp_revnum: 1)
    // B: reused blocks during the 2nd block reclaim (bmp_revnum: 2)
    // otherwise: live block (bmp_revnum: 0)
    //  1 2   3    4    5 6  7  8   9  10
    // +-------------------------------------------+
    // |  BBBBAAAAABBBBB  AAABBB    AAA            |
    // +-------------------------------------------+
    //              ^                     ^
    //              hdr_bid               last_wal_flush
    //
    // scan order: 1 -> 5 -> 8 -> 10 -> 3 -> 6 -> 9 -> 2 -> 4 -> 7
    // iteration #1: scan docs with bmp_revnum==0 in [last_wal_flush ~ filesize]
    // iteration #2: scan docs with bmp_revnum==1 in [0 ~ filesize]
    // iteration #3: scan docs with bmp_revnum==2 in [0 ~ hdr_bid]

    do {
        if (cur_bmp_revnum > stop_bmp_revnum) {
            break;
        } else if (cur_bmp_revnum == stop_bmp_revnum) {

            if (handle->file->sb &&
                handle->file->sb->last_hdr_bid != BLK_NOT_FOUND) {
                hdr_off = (handle->file->sb->last_hdr_bid+1) * blocksize;
            }

            doc_scan_limit = hdr_off;
            if (offset >= hdr_off) {
                break;
            }
        } else {
            doc_scan_limit = filesize;
        }

        if (!docio_check_buffer(handle->dhandle, offset / blocksize,
                                cur_bmp_revnum)) {
            // not a document block .. move to next block
        } else {
            do {
                struct docio_object doc;
                uint64_t _offset;
                uint64_t doc_offset;
                memset(&doc, 0, sizeof(doc));
                _offset = docio_read_doc(handle->dhandle, offset, &doc, true);
                if (_offset == offset) { // reached unreadable doc, skip block
                    break;
                } else if (_offset < offset) {
                    // If more than one writer is appending docs concurrently,
                    // they have their own doc block linked list and doc blocks
                    // may not be consecutive. For example,
                    //
                    // Writer 1): 100 -> 102 -> 2 -> 4     | commit
                    // Writer 2):    101 - > 103 -> 3 -> 5 |
                    //
                    // In this case, if we read doc BID 102, then 'offset' will jump
                    // to doc BID 2, without reading BID 103.
                    //
                    // To address this issue, in case that 'offset' decreases,
                    // remember the next doc block, and follow the doc linked list
                    // first. After the linked list ends, 'offset' cursor will be
                    // reset to 'next_doc_block'.
                    next_doc_block = (offset / blocksize) + 1;
                }
                if (doc.key || (doc.length.flag & DOCIO_TXN_COMMITTED)) {
                    // check if the doc is transactional or not, and
                    // also check if the doc contains system info
                    if (!(doc.length.flag & DOCIO_TXN_DIRTY) &&
                        !(doc.length.flag & DOCIO_SYSTEM)) {
                        if (doc.length.flag & DOCIO_TXN_COMMITTED) {
                            // commit mark .. read doc offset
                            doc_offset = doc.doc_offset;
                            // read the previously skipped doc
                            docio_read_doc(handle->dhandle, doc_offset, &doc, true);
                            if (doc.key == NULL) { // doc read error
                                free(doc.meta);
                                free(doc.body);
                                offset = _offset;
                                continue;
                            }
                        } else {
                            doc_offset = offset;
                        }

                        // If say a snapshot is taken on a db handle after
                        // rollback, then skip WAL items after rollback point
                        if (handle->config.seqtree_opt == FDB_SEQTREE_USE &&
                            (mode == FDB_RESTORE_KV_INS || !handle->kvs) &&
                            doc.seqnum > handle->seqnum) {
                            free(doc.key);
                            free(doc.meta);
                            free(doc.body);
                            offset = _offset;
                            continue;
                        }

                        // restore document
                        fdb_doc wal_doc;
                        wal_doc.keylen = doc.length.keylen;
                        wal_doc.bodylen = doc.length.bodylen;
                        wal_doc.key = doc.key;
                        wal_doc.seqnum = doc.seqnum;
                        wal_doc.deleted = doc.length.flag & DOCIO_DELETED;

                        if (!handle->shandle) {
                            wal_doc.metalen = doc.length.metalen;
                            wal_doc.meta = doc.meta;
                            wal_doc.size_ondisk = _fdb_get_docsize(doc.length);

                            if (handle->kvs) {
                                // check seqnum before insert
                                fdb_kvs_id_t kv_id;
                                fdb_seqnum_t kv_seqnum;
                                buf2kvid(handle->config.chunksize,
                                         wal_doc.key, &kv_id);

                                if (handle->config.seqtree_opt == FDB_SEQTREE_USE) {
                                    kv_seqnum = fdb_kvs_get_seqnum(handle->file, kv_id);
                                } else {
                                    kv_seqnum = SEQNUM_NOT_USED;
                                }
                                if (doc.seqnum <= kv_seqnum &&
                                        ((mode == FDB_RESTORE_KV_INS &&
                                            kv_id == kv_id_req) ||
                                         (mode == FDB_RESTORE_NORMAL)) ) {
                                    // if mode is NORMAL, restore all items
                                    // if mode is KV_INS, restore items matching ID
                                    wal_insert(&file->global_txn, file,
                                               &wal_doc, doc_offset,
                                               WAL_INS_WRITER);
                                }
                            } else {
                                wal_insert(&file->global_txn, file,
                                           &wal_doc, doc_offset,
                                           WAL_INS_WRITER);
                            }
                            if (doc.key) free(doc.key);
                        } else {
                            // snapshot
                            if (handle->kvs) {
                                fdb_kvs_id_t kv_id;
                                buf2kvid(handle->config.chunksize,
                                         wal_doc.key, &kv_id);
                                if (kv_id == handle->kvs->id) {
                                    // snapshot: insert ID matched documents only
                                    snap_insert(handle->shandle,
                                                &wal_doc, doc_offset);
                                } else {
                                    free(doc.key);
                                }
                            } else {
                                snap_insert(handle->shandle, &wal_doc, doc_offset);
                            }
                        }
                        free(doc.meta);
                        free(doc.body);
                        offset = _offset;
                    } else {
                        // skip transactional document or system document
                        free(doc.key);
                        free(doc.meta);
                        free(doc.body);
                        offset = _offset;
                        // do not break.. read next doc
                    }
                } else {
                    free(doc.key);
                    free(doc.meta);
                    free(doc.body);
                    offset = _offset;
                    break;
                }
            } while (offset + sizeof(struct docio_length) < doc_scan_limit);
        }

        if (next_doc_block != BLK_NOT_FOUND) {
            offset = next_doc_block * blocksize;
            next_doc_block = BLK_NOT_FOUND;
        } else {
            offset = ((offset / blocksize) + 1) * blocksize;
        }
        if (ver_superblock_support(handle->file->version) &&
            offset >= filesize) {
            // circular scan
            offset = blocksize * handle->file->sb->config->num_sb;
            cur_bmp_revnum++;
        }
    } while(true);

    // wal commit
    if (!handle->shandle) {
        wal_commit(&file->global_txn, file, NULL, &handle->log_callback);
        filemgr_mutex_unlock(file);
    }
    handle->dhandle->log_callback = log_callback;
}

INLINE fdb_status _fdb_recover_compaction(fdb_kvs_handle *handle,
                                          const char *new_filename)
{
    fdb_kvs_handle new_db;
    fdb_config config = handle->config;
    struct filemgr *new_file;

    memset(&new_db, 0, sizeof(new_db));
    new_db.log_callback.callback = handle->log_callback.callback;
    new_db.log_callback.ctx_data = handle->log_callback.ctx_data;
    config.flags |= FDB_OPEN_FLAG_RDONLY;
    new_db.fhandle = handle->fhandle;
    new_db.kvs_config = handle->kvs_config;
    fdb_status status = _fdb_open(&new_db, new_filename,
                                  FDB_AFILENAME, &config);
    if (status != FDB_RESULT_SUCCESS) {
        return fdb_log(&handle->log_callback, status,
                       "Error in opening a partially compacted file '%s' for recovery.",
                       new_filename);
    }

    new_file = new_db.file;

    if (new_file->old_filename &&
        !strncmp(new_file->old_filename, handle->file->filename,
                 FDB_MAX_FILENAME_LEN)) {
        struct filemgr *old_file = handle->file;
        // If new file has a recorded old_filename then it means that
        // compaction has completed successfully. Mark self for deletion
        filemgr_mutex_lock(new_file);

        status = btreeblk_end(handle->bhandle);
        if (status != FDB_RESULT_SUCCESS) {
            filemgr_mutex_unlock(new_file);
            _fdb_close(&new_db);
            return status;
        }
        btreeblk_free(handle->bhandle);
        free(handle->bhandle);
        handle->bhandle = new_db.bhandle;

        docio_free(handle->dhandle);
        free(handle->dhandle);
        handle->dhandle = new_db.dhandle;

        hbtrie_free(handle->trie);
        free(handle->trie);
        handle->trie = new_db.trie;

        wal_shutdown(handle->file);
        handle->file = new_file;

        if (handle->config.seqtree_opt == FDB_SEQTREE_USE) {
            if (handle->kvs) {
                // multi KV instance mode
                hbtrie_free(handle->seqtrie);
                free(handle->seqtrie);
                if (new_db.config.seqtree_opt == FDB_SEQTREE_USE) {
                    handle->seqtrie = new_db.seqtrie;
                }
            } else {
                free(handle->seqtree->kv_ops);
                free(handle->seqtree);
                if (new_db.config.seqtree_opt == FDB_SEQTREE_USE) {
                    handle->seqtree = new_db.seqtree;
                }
            }
        }
        handle->staletree = new_db.staletree;

        filemgr_mutex_unlock(new_file);
        if (new_db.kvs) {
            fdb_kvs_info_free(&new_db);
        }
        // remove self: WARNING must not close this handle if snapshots
        // are yet to open this file
        filemgr_remove_pending(old_file, new_db.file, &new_db.log_callback);
        filemgr_close(old_file, 0, handle->filename, &handle->log_callback);
        free(new_db.filename);
        return FDB_RESULT_FAIL_BY_COMPACTION;
    }

    // As the new file is partially compacted, it should be removed upon close.
    // Just in-case the new file gets opened before removal, point it to the old
    // file to ensure availability of data.
    filemgr_remove_pending(new_db.file, handle->file, &handle->log_callback);
    _fdb_close(&new_db);

    return FDB_RESULT_SUCCESS;
}

LIBFDB_API
fdb_status fdb_init(fdb_config *config)
{
    fdb_config _config;
    compactor_config c_config;
    bgflusher_config bgf_config;
    struct filemgr_config f_config;

    if (config) {
        if (validate_fdb_config(config)) {
            _config = *config;
        } else {
            return FDB_RESULT_INVALID_CONFIG;
        }
    } else {
        _config = get_default_config();
    }

    // global initialization
    // initialized only once at first time
    if (!fdb_initialized) {
#ifdef _TRACE_HANDLES
        spin_init(&open_handle_lock);
        avl_init(&open_handles, NULL);
#endif

#ifndef SPIN_INITIALIZER
        // Note that only Windows passes through this routine
        if (InterlockedCompareExchange(&initial_lock_status, 1, 0) == 0) {
            // atomically initialize spin lock only once
            spin_init(&initial_lock);
            initial_lock_status = 2;
        } else {
            // the others .. wait until initializing 'initial_lock' is done
            while (initial_lock_status != 2) {
                Sleep(1);
            }
        }
#endif

    }
    spin_lock(&initial_lock);
    if (!fdb_initialized) {
#if !defined(_ANDROID_) && !defined(__ANDROID__)
        // Some Android devices (e.g., Nexus 6) return incorrect RAM size.
        // We temporarily disable validity checking of block cache size
        // on Android platform at this time.
        double ram_size = (double) get_memory_size();
        if (ram_size * BCACHE_MEMORY_THRESHOLD < (double) _config.buffercache_size) {
            spin_unlock(&initial_lock);
            return FDB_RESULT_TOO_BIG_BUFFER_CACHE;
        }
#endif
        // initialize file manager and block cache
        f_config.blocksize = _config.blocksize;
        f_config.ncacheblock = _config.buffercache_size / _config.blocksize;
        filemgr_init(&f_config);
        filemgr_set_lazy_file_deletion(true,
                                       compactor_register_file_removing,
                                       compactor_is_file_removed);
        if (ver_superblock_support(ver_get_latest_magic())) {
            struct sb_ops sb_ops = {sb_init, sb_get_default_config,
                                    sb_read_latest, sb_alloc_block,
                                    sb_bmp_is_writable, sb_bmp_is_active_block,
                                    sb_get_bmp_revnum, sb_get_min_live_revnum,
                                    sb_free};
            filemgr_set_sb_operation(sb_ops);
            sb_bmp_mask_init();
        }

        // initialize compaction daemon
        c_config.sleep_duration = _config.compactor_sleep_duration;
        c_config.num_threads = _config.num_compactor_threads;
        compactor_init(&c_config);
        // initialize background flusher daemon
        // Temporarily disable background flushers until blockcache contention
        // issue is resolved.
        bgf_config.num_threads = 0; //_config.num_bgflusher_threads;
        bgflusher_init(&bgf_config);

        fdb_initialized = 1;
    }
    fdb_open_inprog++;
    spin_unlock(&initial_lock);

    return FDB_RESULT_SUCCESS;
}

LIBFDB_API
fdb_config fdb_get_default_config(void) {
    return get_default_config();
}

LIBFDB_API
fdb_kvs_config fdb_get_default_kvs_config(void) {
    return get_default_kvs_config();
}

LIBFDB_API
fdb_status fdb_open(fdb_file_handle **ptr_fhandle,
                    const char *filename,
                    fdb_config *fconfig)
{
#ifdef _MEMPOOL
    mempool_init();
#endif

    fdb_config config;
    fdb_file_handle *fhandle;
    fdb_kvs_handle *handle;

    if (fconfig) {
        if (validate_fdb_config(fconfig)) {
            config = *fconfig;
        } else {
            return FDB_RESULT_INVALID_CONFIG;
        }
    } else {
        config = get_default_config();
    }

    fhandle = (fdb_file_handle*)calloc(1, sizeof(fdb_file_handle));
    if (!fhandle) { // LCOV_EXCL_START
        return FDB_RESULT_ALLOC_FAIL;
    } // LCOV_EXCL_STOP

    handle = (fdb_kvs_handle *) calloc(1, sizeof(fdb_kvs_handle));
    if (!handle) { // LCOV_EXCL_START
        free(fhandle);
        return FDB_RESULT_ALLOC_FAIL;
    } // LCOV_EXCL_STOP

    atomic_init_uint8_t(&handle->handle_busy, 0);
    handle->shandle = NULL;
    handle->kvs_config = get_default_kvs_config();

    fdb_status fs = fdb_init(fconfig);
    if (fs != FDB_RESULT_SUCCESS) {
        free(handle);
        free(fhandle);
        return fs;
    }
    fdb_file_handle_init(fhandle, handle);

    fs = _fdb_open(handle, filename, FDB_VFILENAME, &config);
    if (fs == FDB_RESULT_SUCCESS) {
        *ptr_fhandle = fhandle;
        filemgr_fhandle_add(handle->file, fhandle);
    } else {
        *ptr_fhandle = NULL;
        free(handle);
        fdb_file_handle_free(fhandle);
    }
    spin_lock(&initial_lock);
    fdb_open_inprog--;
    spin_unlock(&initial_lock);
    return fs;
}

LIBFDB_API
fdb_status fdb_open_custom_cmp(fdb_file_handle **ptr_fhandle,
                               const char *filename,
                               fdb_config *fconfig,
                               size_t num_functions,
                               char **kvs_names,
                               fdb_custom_cmp_variable *functions)
{
#ifdef _MEMPOOL
    mempool_init();
#endif

    fdb_config config;
    fdb_file_handle *fhandle;
    fdb_kvs_handle *handle;

    if (fconfig) {
        if (validate_fdb_config(fconfig)) {
            config = *fconfig;
        } else {
            return FDB_RESULT_INVALID_CONFIG;
        }
    } else {
        config = get_default_config();
    }

    if (config.multi_kv_instances == false) {
        // single KV instance mode does not support customized cmp function
        return FDB_RESULT_INVALID_CONFIG;
    }

    fhandle = (fdb_file_handle*)calloc(1, sizeof(fdb_file_handle));
    if (!fhandle) { // LCOV_EXCL_START
        return FDB_RESULT_ALLOC_FAIL;
    } // LCOV_EXCL_STOP

    handle = (fdb_kvs_handle *) calloc(1, sizeof(fdb_kvs_handle));
    if (!handle) { // LCOV_EXCL_START
        free(fhandle);
        return FDB_RESULT_ALLOC_FAIL;
    } // LCOV_EXCL_STOP

    atomic_init_uint8_t(&handle->handle_busy, 0);
    handle->shandle = NULL;
    handle->kvs_config = get_default_kvs_config();

    fdb_status fs = fdb_init(fconfig);
    if (fs != FDB_RESULT_SUCCESS) {
        free(handle);
        free(fhandle);
        return fs;
    }
    fdb_file_handle_init(fhandle, handle);

    // insert kvs_names and functions into fhandle's list
    fdb_file_handle_parse_cmp_func(fhandle, num_functions,
                                   kvs_names, functions);

    fs = _fdb_open(handle, filename, FDB_VFILENAME, &config);
    if (fs == FDB_RESULT_SUCCESS) {
        *ptr_fhandle = fhandle;
        filemgr_fhandle_add(handle->file, fhandle);
    } else {
        *ptr_fhandle = NULL;
        free(handle);
        fdb_file_handle_free(fhandle);
    }
    spin_lock(&initial_lock);
    fdb_open_inprog--;
    spin_unlock(&initial_lock);
    return fs;
}

fdb_status fdb_open_for_compactor(fdb_file_handle **ptr_fhandle,
                                  const char *filename,
                                  fdb_config *fconfig,
                                  struct list *cmp_func_list)
{
#ifdef _MEMPOOL
    mempool_init();
#endif

    fdb_file_handle *fhandle;
    fdb_kvs_handle *handle;

    fhandle = (fdb_file_handle*)calloc(1, sizeof(fdb_file_handle));
    if (!fhandle) { // LCOV_EXCL_START
        return FDB_RESULT_ALLOC_FAIL;
    } // LCOV_EXCL_STOP

    handle = (fdb_kvs_handle *) calloc(1, sizeof(fdb_kvs_handle));
    if (!handle) { // LCOV_EXCL_START
        free(fhandle);
        return FDB_RESULT_ALLOC_FAIL;
    } // LCOV_EXCL_STOP

    atomic_init_uint8_t(&handle->handle_busy, 0);
    handle->shandle = NULL;

    fdb_file_handle_init(fhandle, handle);
    if (cmp_func_list && list_begin(cmp_func_list)) {
        fdb_file_handle_clone_cmp_func_list(fhandle, cmp_func_list);
    }
    fdb_status fs = _fdb_open(handle, filename, FDB_VFILENAME, fconfig);
    if (fs == FDB_RESULT_SUCCESS) {
        *ptr_fhandle = fhandle;
        filemgr_fhandle_add(handle->file, fhandle);
    } else {
        *ptr_fhandle = NULL;
        free(handle);
        fdb_file_handle_free(fhandle);
    }
    return fs;
}

LIBFDB_API
fdb_status fdb_snapshot_open(fdb_kvs_handle *handle_in,
                             fdb_kvs_handle **ptr_handle, fdb_seqnum_t seqnum)
{
#ifdef _MEMPOOL
    mempool_init();
#endif

    fdb_config config = handle_in->config;
    fdb_kvs_config kvs_config = handle_in->kvs_config;
    fdb_kvs_handle *handle;
    fdb_status fs;
    filemgr *file;
    file_status_t fstatus = FILE_NORMAL;
    LATENCY_STAT_START();

    if (!handle_in || !ptr_handle) {
        return FDB_RESULT_INVALID_ARGS;
    }

    // Sequence trees are a must for snapshot creation
    if (handle_in->config.seqtree_opt != FDB_SEQTREE_USE) {
        return FDB_RESULT_INVALID_CONFIG;
    }

fdb_snapshot_open_start:
    if (!handle_in->shandle) {
        fdb_check_file_reopen(handle_in, &fstatus);
        fdb_sync_db_header(handle_in);
        file = handle_in->file;

        if (handle_in->kvs && handle_in->kvs->type == KVS_SUB) {
            handle_in->seqnum = fdb_kvs_get_seqnum(file,
                                                   handle_in->kvs->id);
        } else {
            handle_in->seqnum = filemgr_get_seqnum(file);
        }
    } else {
        file = handle_in->file;
    }

    // if the max sequence number seen by this handle is lower than the
    // requested snapshot marker, it means the snapshot is not yet visible
    // even via the current fdb_kvs_handle
    if (seqnum != FDB_SNAPSHOT_INMEM && seqnum > handle_in->seqnum) {
        return FDB_RESULT_NO_DB_INSTANCE;
    }

    handle = (fdb_kvs_handle *) calloc(1, sizeof(fdb_kvs_handle));
    if (!handle) { // LCOV_EXCL_START
        return FDB_RESULT_ALLOC_FAIL;
    } // LCOV_EXCL_STOP

    atomic_init_uint8_t(&handle->handle_busy, 0);
    handle->log_callback = handle_in->log_callback;
    handle->max_seqnum = seqnum;
    handle->fhandle = handle_in->fhandle;

    config.flags |= FDB_OPEN_FLAG_RDONLY;
    // do not perform compaction for snapshot
    config.compaction_mode = FDB_COMPACTION_MANUAL;

    // If cloning an existing snapshot handle, then rewind indexes
    // to its last DB header and point its avl tree to existing snapshot's tree
    bool clone_snapshot = false;
    if (handle_in->shandle) {
        handle->last_hdr_bid = handle_in->last_hdr_bid; // do fast rewind
        if (snap_clone(handle_in->shandle, handle_in->max_seqnum,
                   &handle->shandle, seqnum) == FDB_RESULT_SUCCESS) {
            handle->max_seqnum = FDB_SNAPSHOT_INMEM; // temp value to skip WAL
            clone_snapshot = true;
        }
    }

    if (!handle->shandle) {
        handle->shandle = (struct snap_handle *) calloc(1, sizeof(snap_handle));
        if (!handle->shandle) { // LCOV_EXCL_START
            free(handle);
            return FDB_RESULT_ALLOC_FAIL;
        } // LCOV_EXCL_STOP
        snap_init(handle->shandle, handle_in);
    }

    if (handle_in->kvs) {
        // sub-handle in multi KV instance mode
        if (clone_snapshot) {
            fs = _fdb_kvs_clone_snapshot(handle_in, handle);
        } else {
            fs = _fdb_kvs_open(handle_in->kvs->root,
                              &config, &kvs_config, file,
                              file->filename,
                              _fdb_kvs_get_name(handle_in, file),
                              handle);
        }
    } else {
        if (clone_snapshot) {
            fs = _fdb_clone_snapshot(handle_in, handle);
        } else {
            fs = _fdb_open(handle, file->filename, FDB_AFILENAME, &config);
        }
    }

    if (fs == FDB_RESULT_SUCCESS) {
        if (seqnum == FDB_SNAPSHOT_INMEM &&
            !handle_in->shandle) {
            fdb_seqnum_t upto_seq = seqnum;
            // In-memory snapshot
            wal_snapshot(handle->file, (void *)handle->shandle,
                         handle_in->txn, &upto_seq, _fdb_wal_snapshot_func);
            // set seqnum based on handle type (multikv or default)
            if (handle_in->kvs && handle_in->kvs->id > 0) {
                handle->max_seqnum =
                    _fdb_kvs_get_seqnum(handle->file->kv_header,
                                        handle_in->kvs->id);
            } else {
                handle->max_seqnum = filemgr_get_seqnum(handle->file);
            }

            // synchronize dirty root nodes if exist
            if (filemgr_dirty_root_exist(handle->file)) {
                bid_t dirty_idtree_root, dirty_seqtree_root;
                filemgr_mutex_lock(handle->file);
                filemgr_get_dirty_root(handle->file,
                                       &dirty_idtree_root, &dirty_seqtree_root);
                if (dirty_idtree_root != BLK_NOT_FOUND) {
                    handle->trie->root_bid = dirty_idtree_root;
                }
                if (handle->config.seqtree_opt == FDB_SEQTREE_USE) {
                    if (dirty_seqtree_root != BLK_NOT_FOUND) {
                        if (handle->kvs) {
                            handle->seqtrie->root_bid = dirty_seqtree_root;
                        } else {
                            btree_init_from_bid(handle->seqtree,
                                                handle->seqtree->blk_handle,
                                                handle->seqtree->blk_ops,
                                                handle->seqtree->kv_ops,
                                                handle->seqtree->blksize,
                                                dirty_seqtree_root);
                        }
                    }
                }
                btreeblk_discard_blocks(handle->bhandle);
                btreeblk_create_dirty_snapshot(handle->bhandle);
                filemgr_mutex_unlock(handle->file);
            }
        } else if (clone_snapshot) {
            // Snapshot is created on the other snapshot handle

            handle->max_seqnum = handle_in->seqnum;

            if (seqnum == FDB_SNAPSHOT_INMEM) {
                // in-memory snapshot
                // Clone dirty root nodes from the source snapshot by incrementing
                // their ref counters
                handle->trie->root_bid = handle_in->trie->root_bid;
                if (handle->config.seqtree_opt == FDB_SEQTREE_USE) {
                    if (handle->kvs) {
                        handle->seqtrie->root_bid = handle_in->seqtrie->root_bid;
                    } else {
                        handle->seqtree->root_bid = handle_in->seqtree->root_bid;
                    }
                }
                btreeblk_discard_blocks(handle->bhandle);
                btreeblk_clone_dirty_snapshot(handle->bhandle,
                                              handle_in->bhandle);
            }
        }
        *ptr_handle = handle;
    } else {
        *ptr_handle = NULL;
        snap_close(handle->shandle);
        free(handle);
        // If compactor thread had finished compaction just before this routine
        // calls _fdb_open, then it is possible that the snapshot's DB header
        // is only present in the new_file. So we must retry the snapshot
        // open attempt IFF _fdb_open indicates FDB_RESULT_NO_DB_INSTANCE..
        if (fs == FDB_RESULT_NO_DB_INSTANCE && fstatus == FILE_COMPACT_OLD) {
            if (filemgr_get_file_status(file) == FILE_REMOVED_PENDING) {
                goto fdb_snapshot_open_start;
            }
        }
    }
    LATENCY_STAT_END(file, FDB_LATENCY_SNAPSHOTS);
    return fs;
}

static fdb_status _fdb_reset(fdb_kvs_handle *handle, fdb_kvs_handle *handle_in);

LIBFDB_API
fdb_status fdb_rollback(fdb_kvs_handle **handle_ptr, fdb_seqnum_t seqnum)
{
#ifdef _MEMPOOL
    mempool_init();
#endif

    fdb_config config;
    fdb_kvs_handle *handle_in, *handle;
    fdb_status fs;
    fdb_seqnum_t old_seqnum;

    if (!handle_ptr) {
        return FDB_RESULT_INVALID_ARGS;
    }

    handle_in = *handle_ptr;
    config = handle_in->config;

    if (handle_in->kvs) {
        return fdb_kvs_rollback(handle_ptr, seqnum);
    }

    // Sequence trees are a must for rollback
    if (handle_in->config.seqtree_opt != FDB_SEQTREE_USE) {
        return FDB_RESULT_INVALID_CONFIG;
    }

    if (handle_in->config.flags & FDB_OPEN_FLAG_RDONLY) {
        return fdb_log(&handle_in->log_callback, FDB_RESULT_RONLY_VIOLATION,
                       "Warning: Rollback is not allowed on the read-only DB file '%s'.",
                       handle_in->file->filename);
    }

    if (!atomic_cas_uint8_t(&handle_in->handle_busy, 0, 1)) {
        return FDB_RESULT_HANDLE_BUSY;
    }

    filemgr_mutex_lock(handle_in->file);
    filemgr_set_rollback(handle_in->file, 1); // disallow writes operations
    // All transactions should be closed before rollback
    if (wal_txn_exists(handle_in->file)) {
        filemgr_set_rollback(handle_in->file, 0);
        filemgr_mutex_unlock(handle_in->file);
        atomic_cas_uint8_t(&handle_in->handle_busy, 1, 0);
        return FDB_RESULT_FAIL_BY_TRANSACTION;
    }

    // If compaction is running, wait until it is aborted.
    // TODO: Find a better way of waiting for the compaction abortion.
    unsigned int sleep_time = 10000; // 10 ms.
    file_status_t fstatus = filemgr_get_file_status(handle_in->file);
    while (fstatus == FILE_COMPACT_OLD) {
        filemgr_mutex_unlock(handle_in->file);
        decaying_usleep(&sleep_time, 1000000);
        filemgr_mutex_lock(handle_in->file);
        fstatus = filemgr_get_file_status(handle_in->file);
    }
    if (fstatus == FILE_REMOVED_PENDING) {
        filemgr_mutex_unlock(handle_in->file);
        fdb_check_file_reopen(handle_in, NULL);
    } else {
        filemgr_mutex_unlock(handle_in->file);
    }

    fdb_sync_db_header(handle_in);

    // if the max sequence number seen by this handle is lower than the
    // requested snapshot marker, it means the snapshot is not yet visible
    // even via the current fdb_kvs_handle
    if (seqnum > handle_in->seqnum) {
        filemgr_set_rollback(handle_in->file, 0); // allow mutations
        atomic_cas_uint8_t(&handle_in->handle_busy, 1, 0);
        return FDB_RESULT_NO_DB_INSTANCE;
    }

    handle = (fdb_kvs_handle *) calloc(1, sizeof(fdb_kvs_handle));
    if (!handle) { // LCOV_EXCL_START
        atomic_cas_uint8_t(&handle_in->handle_busy, 1, 0);
        return FDB_RESULT_ALLOC_FAIL;
    } // LCOV_EXCL_STOP

    atomic_init_uint8_t(&handle->handle_busy, 0);
    handle->log_callback = handle_in->log_callback;
    handle->fhandle = handle_in->fhandle;
    if (seqnum == 0) {
        fs = _fdb_reset(handle, handle_in);
    } else {
        handle->max_seqnum = seqnum;
        fs = _fdb_open(handle, handle_in->file->filename, FDB_AFILENAME,
                       &config);
    }

    filemgr_set_rollback(handle_in->file, 0); // allow mutations
    if (fs == FDB_RESULT_SUCCESS) {
        // rollback the file's sequence number
        filemgr_mutex_lock(handle_in->file);
        old_seqnum = filemgr_get_seqnum(handle_in->file);
        filemgr_set_seqnum(handle_in->file, seqnum);
        filemgr_mutex_unlock(handle_in->file);

        fs = _fdb_commit(handle, FDB_COMMIT_NORMAL,
                !(handle_in->config.durability_opt & FDB_DRB_ASYNC));
        if (fs == FDB_RESULT_SUCCESS) {
            if (handle_in->txn) {
                handle->txn = handle_in->txn;
                handle_in->txn = NULL;
            }
            handle_in->fhandle->root = handle;
            _fdb_close_root(handle_in);
            handle->max_seqnum = 0;
            handle->seqnum = seqnum;
            *handle_ptr = handle;
        } else {
            // cancel the rolling-back of the sequence number
            filemgr_mutex_lock(handle_in->file);
            filemgr_set_seqnum(handle_in->file, old_seqnum);
            filemgr_mutex_unlock(handle_in->file);
            free(handle);
            atomic_cas_uint8_t(&handle_in->handle_busy, 1, 0);
        }
    } else {
        free(handle);
        atomic_cas_uint8_t(&handle_in->handle_busy, 1, 0);
    }

    return fs;
}

LIBFDB_API
fdb_status fdb_rollback_all(fdb_file_handle *fhandle,
                            fdb_snapshot_marker_t marker)
{
#ifdef _MEMPOOL
    mempool_init();
#endif

    fdb_config config;
    fdb_kvs_handle *super_handle;
    fdb_kvs_handle rhandle;
    fdb_kvs_handle *handle = &rhandle;
    struct filemgr *file;
    fdb_kvs_config kvs_config;
    fdb_status fs;
    err_log_callback log_callback;
    struct kvs_info *kvs;
    struct snap_handle shandle; // dummy snap handle

    if (!fhandle) {
        return FDB_RESULT_INVALID_ARGS;
    }

    super_handle = fhandle->root;
    kvs = super_handle->kvs;

    // fdb_rollback_all cannot be allowed when there are kv store instances
    // still open, because we do not have means of invalidating open kv handles
    // which may not be present in the rollback point
    if (kvs && _fdb_kvs_is_busy(fhandle)) {
        return FDB_RESULT_KV_STORE_BUSY;
    }
    file = super_handle->file;
    config = super_handle->config;
    kvs_config = super_handle->kvs_config;
    log_callback = super_handle->log_callback;

    // Sequence trees are a must for rollback
    if (super_handle->config.seqtree_opt != FDB_SEQTREE_USE) {
        return FDB_RESULT_INVALID_CONFIG;
    }

    if (super_handle->config.flags & FDB_OPEN_FLAG_RDONLY) {
        return fdb_log(&super_handle->log_callback, FDB_RESULT_RONLY_VIOLATION,
                       "Warning: Rollback is not allowed on the read-only DB file '%s'.",
                       super_handle->file->filename);
    }

    filemgr_mutex_lock(super_handle->file);
    filemgr_set_rollback(super_handle->file, 1); // disallow writes operations
    // All transactions should be closed before rollback
    if (wal_txn_exists(super_handle->file)) {
        filemgr_set_rollback(super_handle->file, 0);
        filemgr_mutex_unlock(super_handle->file);
        return FDB_RESULT_FAIL_BY_TRANSACTION;
    }

    // If compaction is running, wait until it is aborted.
    // TODO: Find a better way of waiting for the compaction abortion.
    unsigned int sleep_time = 10000; // 10 ms.
    file_status_t fstatus = filemgr_get_file_status(super_handle->file);
    while (fstatus == FILE_COMPACT_OLD) {
        filemgr_mutex_unlock(super_handle->file);
        decaying_usleep(&sleep_time, 1000000);
        filemgr_mutex_lock(super_handle->file);
        fstatus = filemgr_get_file_status(super_handle->file);
    }
    if (fstatus == FILE_REMOVED_PENDING) {
        filemgr_mutex_unlock(super_handle->file);
        fdb_check_file_reopen(super_handle, NULL);
    } else {
        filemgr_mutex_unlock(super_handle->file);
    }

    fdb_sync_db_header(super_handle);
    // Shutdown WAL discarding entries from all KV Stores..
    fs = wal_shutdown(super_handle->file);
    if (fs != FDB_RESULT_SUCCESS) {
        return fs;
    }

    memset(handle, 0, sizeof(fdb_kvs_handle));
    memset(&shandle, 0, sizeof(struct snap_handle));
    handle->log_callback = log_callback;
    handle->fhandle = fhandle;
    handle->last_hdr_bid = (bid_t)marker; // Fast rewind on open
    handle->max_seqnum = FDB_SNAPSHOT_INMEM; // Prevent WAL restore on open
    handle->shandle = &shandle; // a dummy handle to prevent WAL restore
    if (kvs) {
        fdb_kvs_header_free(file); // KV header will be recreated below.
        handle->kvs = kvs; // re-use super_handle's kvs info
        handle->kvs_config = kvs_config;
    }
    handle->config = config;

    fs = _fdb_open(handle, file->filename, FDB_AFILENAME, &config);

    if (handle->config.multi_kv_instances) {
        filemgr_mutex_lock(handle->file);
        fdb_kvs_header_create(handle->file);
        fdb_kvs_header_read(handle->file->kv_header, handle->dhandle, handle->kv_info_offset,
                            handle->file->version, false);
        filemgr_mutex_unlock(handle->file);
    }

    filemgr_set_rollback(file, 0); // allow mutations
    handle->shandle = NULL; // just a dummy handle never allocated

    if (fs == FDB_RESULT_SUCCESS) {
        fdb_seqnum_t old_seqnum;
        // Restore WAL for all KV instances...
        _fdb_restore_wal(handle, FDB_RESTORE_NORMAL, (bid_t)marker, 0);

        // rollback the file's sequence number
        filemgr_mutex_lock(file);
        old_seqnum = filemgr_get_seqnum(file);
        filemgr_set_seqnum(file, handle->seqnum);
        filemgr_mutex_unlock(file);

        fs = _fdb_commit(handle, FDB_COMMIT_NORMAL,
                         !(handle->config.durability_opt & FDB_DRB_ASYNC));
        if (fs == FDB_RESULT_SUCCESS) {
            _fdb_close(super_handle);
            *super_handle = *handle;
        } else {
            filemgr_mutex_lock(file);
            filemgr_set_seqnum(file, old_seqnum);
            filemgr_mutex_unlock(file);
        }
    } else { // Rollback failed, restore KV header
        fdb_kvs_header_create(file);
        fdb_kvs_header_read(file->kv_header, super_handle->dhandle,
                            super_handle->kv_info_offset, ver_get_latest_magic(),
                            false);
    }

    return fs;
}

static void _fdb_init_file_config(const fdb_config *config,
                                  struct filemgr_config *fconfig) {
    fconfig->blocksize = config->blocksize;
    fconfig->ncacheblock = config->buffercache_size / config->blocksize;
    fconfig->chunksize = config->chunksize;

    fconfig->options = 0x0;
    if (config->flags & FDB_OPEN_FLAG_CREATE) {
        fconfig->options |= FILEMGR_CREATE;
    }
    if (config->flags & FDB_OPEN_FLAG_RDONLY) {
        fconfig->options |= FILEMGR_READONLY;
    }
    if (!(config->durability_opt & FDB_DRB_ASYNC)) {
        fconfig->options |= FILEMGR_SYNC;
    }

    fconfig->flag = 0x0;
    if ((config->durability_opt & FDB_DRB_ODIRECT) &&
        config->buffercache_size) {
        fconfig->flag |= _ARCH_O_DIRECT;
    }

    fconfig->prefetch_duration = config->prefetch_duration;
    fconfig->num_wal_shards = config->num_wal_partitions;
    fconfig->num_bcache_shards = config->num_bcache_partitions;
    fconfig->encryption_key = config->encryption_key;
    atomic_store_uint64_t(&fconfig->block_reusing_threshold,
                          config->block_reusing_threshold);
    atomic_store_uint64_t(&fconfig->num_keeping_headers, config->num_keeping_headers);
}

fdb_status _fdb_clone_snapshot(fdb_kvs_handle *handle_in,
                               fdb_kvs_handle *handle_out)
{
    fdb_status status;

    handle_out->config = handle_in->config;
    handle_out->kvs_config = handle_in->kvs_config;
    handle_out->fileops = handle_in->fileops;
    handle_out->file = handle_in->file;
    // Note that the file ref count will be decremented when the cloned snapshot
    // is closed through filemgr_close().
    filemgr_incr_ref_count(handle_out->file);

    if (handle_out->filename) {
        handle_out->filename = (char *)realloc(handle_out->filename,
                                               strlen(handle_in->filename)+1);
    } else {
        handle_out->filename = (char*)malloc(strlen(handle_in->filename)+1);
    }
    strcpy(handle_out->filename, handle_in->filename);

    // initialize the docio handle.
    handle_out->dhandle = (struct docio_handle *)
        calloc(1, sizeof(struct docio_handle));
    handle_out->dhandle->log_callback = &handle_out->log_callback;
    docio_init(handle_out->dhandle, handle_out->file,
               handle_out->config.compress_document_body);

    // initialize the btree block handle.
    handle_out->btreeblkops = btreeblk_get_ops();
    handle_out->bhandle = (struct btreeblk_handle *)
        calloc(1, sizeof(struct btreeblk_handle));
    handle_out->bhandle->log_callback = &handle_out->log_callback;
    btreeblk_init(handle_out->bhandle, handle_out->file, handle_out->file->blocksize);

    handle_out->dirty_updates = handle_in->dirty_updates;
    handle_out->cur_header_revnum = handle_in->cur_header_revnum;
    handle_out->last_wal_flush_hdr_bid = handle_in->last_wal_flush_hdr_bid;
    handle_out->kv_info_offset = handle_in->kv_info_offset;
    handle_out->shandle->stat = handle_in->shandle->stat;
    handle_out->op_stats = handle_in->op_stats;

    // initialize the trie handle
    handle_out->trie = (struct hbtrie *)malloc(sizeof(struct hbtrie));
    hbtrie_init(handle_out->trie, handle_out->config.chunksize, OFFSET_SIZE,
                handle_out->file->blocksize,
                handle_in->trie->root_bid, // Source snapshot's trie root bid
                (void *)handle_out->bhandle, handle_out->btreeblkops,
                (void *)handle_out->dhandle, _fdb_readkey_wrap);
    // set aux for cmp wrapping function
    hbtrie_set_leaf_height_limit(handle_out->trie, 0xff);
    hbtrie_set_leaf_cmp(handle_out->trie, _fdb_custom_cmp_wrap);

    if (handle_out->kvs) {
        hbtrie_set_map_function(handle_out->trie, fdb_kvs_find_cmp_chunk);
    }

    if (handle_out->config.seqtree_opt == FDB_SEQTREE_USE) {
        handle_out->seqnum = handle_in->seqnum;

        if (handle_out->config.multi_kv_instances) {
            // multi KV instance mode .. HB+trie
            handle_out->seqtrie = (struct hbtrie *)malloc(sizeof(struct hbtrie));
            hbtrie_init(handle_out->seqtrie, sizeof(fdb_kvs_id_t), OFFSET_SIZE,
                        handle_out->file->blocksize,
                        handle_in->seqtrie->root_bid, // Source snapshot's seqtrie root bid
                        (void *)handle_out->bhandle, handle_out->btreeblkops,
                        (void *)handle_out->dhandle, _fdb_readseq_wrap);

        } else {
            // single KV instance mode .. normal B+tree
            struct btree_kv_ops *seq_kv_ops =
                (struct btree_kv_ops *)malloc(sizeof(struct btree_kv_ops));
            seq_kv_ops = btree_kv_get_kb64_vb64(seq_kv_ops);
            seq_kv_ops->cmp = _cmp_uint64_t_endian_safe;

            handle_out->seqtree = (struct btree*)malloc(sizeof(struct btree));
            // Init the seq tree using the root bid of the source snapshot.
            btree_init_from_bid(handle_out->seqtree, (void *)handle_out->bhandle,
                                handle_out->btreeblkops, seq_kv_ops,
                                handle_out->config.blocksize,
                                handle_in->seqtree->root_bid);
        }
    } else{
        handle_out->seqtree = NULL;
    }

    status = btreeblk_end(handle_out->bhandle);
    if (status != FDB_RESULT_SUCCESS) {
        const char *msg = "Snapshot clone operation fails due to the errors in "
            "btreeblk_end() in a database file '%s'\n";
        fdb_log(&handle_in->log_callback, status, msg, handle_in->file->filename);
    }

#ifdef _TRACE_HANDLES
    spin_lock(&open_handle_lock);
    avl_insert(&open_handles, &handle_out->avl_trace, _fdb_handle_cmp);
    spin_unlock(&open_handle_lock);
#endif
    return status;
}

fdb_status _fdb_open(fdb_kvs_handle *handle,
                     const char *filename,
                     fdb_filename_mode_t filename_mode,
                     const fdb_config *config)
{
    struct filemgr_config fconfig;
    struct kvs_stat stat, empty_stat;
    bid_t trie_root_bid = BLK_NOT_FOUND;
    bid_t seq_root_bid = BLK_NOT_FOUND;
    bid_t stale_root_bid = BLK_NOT_FOUND;
    fdb_seqnum_t seqnum = 0;
    filemgr_header_revnum_t header_revnum = 0;
    filemgr_header_revnum_t latest_header_revnum = 0;
    fdb_seqtree_opt_t seqtree_opt = config->seqtree_opt;
    uint64_t ndocs = 0;
    uint64_t ndeletes = 0;
    uint64_t datasize = 0;
    uint64_t deltasize = 0;
    uint64_t last_wal_flush_hdr_bid = BLK_NOT_FOUND;
    uint64_t kv_info_offset = BLK_NOT_FOUND;
    uint64_t version;
    uint64_t header_flags = 0;
    uint8_t header_buf[FDB_BLOCKSIZE];
    char *compacted_filename = NULL;
    char *prev_filename = NULL;
    size_t header_len = 0;
    bool multi_kv_instances = config->multi_kv_instances;

    uint64_t nlivenodes = 0;
    bid_t hdr_bid = 0; // initialize to zero for in-memory snapshot
    char actual_filename[FDB_MAX_FILENAME_LEN];
    char virtual_filename[FDB_MAX_FILENAME_LEN];
    char *target_filename = NULL;
    fdb_status status;

    if (filename == NULL) {
        return FDB_RESULT_INVALID_ARGS;
    }
    if (strlen(filename) > (FDB_MAX_FILENAME_LEN - 8)) {
        // filename (including path) length is supported up to
        // (FDB_MAX_FILENAME_LEN - 8) bytes.
        return FDB_RESULT_TOO_LONG_FILENAME;
    }

    if (filename_mode == FDB_VFILENAME &&
        !compactor_is_valid_mode(filename, (fdb_config *)config)) {
        return FDB_RESULT_INVALID_COMPACTION_MODE;
    }

    _fdb_init_file_config(config, &fconfig);

    if (filename_mode == FDB_VFILENAME) {
        compactor_get_actual_filename(filename, actual_filename,
                                      config->compaction_mode, &handle->log_callback);
    } else {
        strcpy(actual_filename, filename);
    }

    if ( config->compaction_mode == FDB_COMPACTION_MANUAL ||
         (config->compaction_mode == FDB_COMPACTION_AUTO   &&
          filename_mode == FDB_VFILENAME) ) {
        // 1) manual compaction mode, OR
        // 2) auto compaction mode + 'filename' is virtual filename
        // -> copy 'filename'
        target_filename = (char *)filename;
    } else {
        // otherwise (auto compaction mode + 'filename' is actual filename)
        // -> copy 'virtual_filename'
        compactor_get_virtual_filename(filename, virtual_filename);
        target_filename = virtual_filename;
    }

    // If the user is requesting legacy CRC pass that down to filemgr
    if(config->flags & FDB_OPEN_WITH_LEGACY_CRC) {
        fconfig.options |= FILEMGR_CREATE_CRC32;
    }

    handle->fileops = get_filemgr_ops();
    filemgr_open_result result = filemgr_open((char *)actual_filename,
                                              handle->fileops,
                                              &fconfig, &handle->log_callback);
    if (result.rv != FDB_RESULT_SUCCESS) {
        return (fdb_status) result.rv;
    }
    handle->file = result.file;

    if (config->compaction_mode == FDB_COMPACTION_MANUAL &&
        strcmp(filename, actual_filename)) {
        // It is in-place compacted file if
        // 1) compaction mode is manual, and
        // 2) actual filename is different to the filename given by user.
        // In this case, set the in-place compaction flag.
        filemgr_set_in_place_compaction(handle->file, true);
    }
    if (filemgr_is_in_place_compaction_set(handle->file)) {
        // This file was in-place compacted.
        // set 'handle->filename' to the original filename to trigger file renaming
        compactor_get_virtual_filename(filename, virtual_filename);
        target_filename = virtual_filename;
    }

    if (handle->filename) {
        handle->filename = (char *)realloc(handle->filename,
                                           strlen(target_filename)+1);
    } else {
        handle->filename = (char*)malloc(strlen(target_filename)+1);
    }
    strcpy(handle->filename, target_filename);

    // If cloning from a snapshot handle, fdb_snapshot_open would have already
    // set handle->last_hdr_bid to the block id of required header, so rewind..
    if (handle->shandle && handle->last_hdr_bid) {
        status = filemgr_fetch_header(handle->file, handle->last_hdr_bid,
                                      header_buf, &header_len, &seqnum,
                                      &latest_header_revnum, &deltasize, &version,
                                      NULL, &handle->log_callback);
        if (status != FDB_RESULT_SUCCESS) {
            free(handle->filename);
            handle->filename = NULL;
            filemgr_close(handle->file, false, handle->filename,
                              &handle->log_callback);
            return status;
        }
    } else { // Normal open
        filemgr_get_header(handle->file, header_buf, &header_len,
                           &handle->last_hdr_bid, &seqnum, &latest_header_revnum);
        version = handle->file->version;
    }

    // initialize the docio handle so kv headers may be read
    handle->dhandle = (struct docio_handle *)
                      calloc(1, sizeof(struct docio_handle));
    handle->dhandle->log_callback = &handle->log_callback;
    docio_init(handle->dhandle, handle->file, config->compress_document_body);

    // fetch previous superblock bitmap info if exists
    // (this should be done after 'handle->dhandle' is initialized)
    if (handle->file->sb) {
        status = sb_bmp_fetch_doc(handle);
        if (status != FDB_RESULT_SUCCESS) {
            docio_free(handle->dhandle);
            free(handle->dhandle);
            free(handle->filename);
            handle->filename = NULL;
            filemgr_close(handle->file, false, handle->filename,
                              &handle->log_callback);
            return status;
        }
    }


    if (header_len > 0) {
        fdb_fetch_header(version, header_buf, &trie_root_bid, &seq_root_bid,
                         &stale_root_bid, &ndocs, &ndeletes, &nlivenodes,
                         &datasize, &last_wal_flush_hdr_bid, &kv_info_offset,
                         &header_flags, &compacted_filename, &prev_filename);
        // use existing setting for seqtree_opt
        if (header_flags & FDB_FLAG_SEQTREE_USE) {
            seqtree_opt = FDB_SEQTREE_USE;
        } else {
            seqtree_opt = FDB_SEQTREE_NOT_USE;
        }
        // Retrieve seqnum for multi-kv mode
        if (handle->kvs && handle->kvs->id > 0) {
            if (kv_info_offset != BLK_NOT_FOUND) {
                if (!handle->file->kv_header) {
                    struct kvs_header *kv_header;
                    _fdb_kvs_header_create(&kv_header);
                    // KV header already exists but not loaded .. read & import
                    fdb_kvs_header_read(kv_header, handle->dhandle,
                                        kv_info_offset, version, false);
                    if (!filemgr_set_kv_header(handle->file, kv_header,
                                          fdb_kvs_header_free, false)) {
                        _fdb_kvs_header_free(kv_header);
                    }
                }
                seqnum = _fdb_kvs_get_seqnum(handle->file->kv_header,
                                             handle->kvs->id);
            } else { // no kv_info offset, ok to set seqnum to zero
                seqnum = 0;
            }
        }
        // other flags
        if (header_flags & FDB_FLAG_ROOT_INITIALIZED) {
            handle->fhandle->flags |= FHANDLE_ROOT_INITIALIZED;
        }
        if (header_flags & FDB_FLAG_ROOT_CUSTOM_CMP) {
            handle->fhandle->flags |= FHANDLE_ROOT_CUSTOM_CMP;
        }
        // use existing setting for multi KV instance mode
        if (kv_info_offset == BLK_NOT_FOUND) {
            multi_kv_instances = false;
        } else {
            multi_kv_instances = true;
        }
    }

    handle->config = *config;
    handle->config.seqtree_opt = seqtree_opt;
    handle->config.multi_kv_instances = multi_kv_instances;

    if (handle->shandle && handle->max_seqnum == FDB_SNAPSHOT_INMEM) {
        // Either an in-memory snapshot or cloning from an existing snapshot..
        hdr_bid = 0; // This prevents _fdb_restore_wal() as incoming handle's
                     // *_open() should have already restored it
    } else { // Persisted snapshot or file rollback..

        // get the BID of the latest block
        // (it is OK if the block is not a DB header)
        bool dirty_data_exists = false;
        struct superblock *sb = handle->file->sb;

        if (sb && sb->bmp) {
            dirty_data_exists = false;
            if (sb->last_hdr_bid != BLK_NOT_FOUND) {
                // add 1 since we subtract 1 from 'hdr_bid' below soon
                hdr_bid = sb->last_hdr_bid + 1;
                if (sb->cur_alloc_bid != hdr_bid) {
                    // seq number has been increased since the last commit
                    seqnum = fdb_kvs_get_committed_seqnum(handle);
                }
            } else {
                hdr_bid = BLK_NOT_FOUND;
            }
        } else {
            hdr_bid = filemgr_get_pos(handle->file) / FDB_BLOCKSIZE;
            dirty_data_exists = (hdr_bid > handle->last_hdr_bid);
        }

        if (hdr_bid == BLK_NOT_FOUND ||
            (sb && hdr_bid <= sb->config->num_sb)) {
            hdr_bid = 0;
        } else if (hdr_bid > 0) {
            --hdr_bid;
        }

        if (handle->max_seqnum) {
            struct kvs_stat stat_ori;
            // backup original stats
            if (handle->kvs) {
                _kvs_stat_get(handle->file, handle->kvs->id, &stat_ori);
            } else {
                _kvs_stat_get(handle->file, 0, &stat_ori);
            }

            if (dirty_data_exists){
                // uncommitted data exists beyond the last DB header
                // get the last committed seq number
                fdb_seqnum_t seq_commit;
                seq_commit = fdb_kvs_get_committed_seqnum(handle);
                if (seq_commit == 0 || seq_commit < handle->max_seqnum) {
                    // In case, snapshot_open is attempted with latest uncommitted
                    // sequence number
                    header_len = 0;
                } else if (seq_commit == handle->max_seqnum) {
                    // snapshot/rollback on the latest commit header
                    seqnum = seq_commit; // skip file reverse scan
                }
                hdr_bid = filemgr_get_header_bid(handle->file);
            }
            // Reverse scan the file to locate the DB header with seqnum marker
            while (header_len && seqnum != handle->max_seqnum) {
                hdr_bid = filemgr_fetch_prev_header(handle->file, hdr_bid,
                                          header_buf, &header_len, &seqnum,
                                          &header_revnum, NULL, &version, NULL,
                                          &handle->log_callback);
                if (header_len == 0) {
                    continue; // header doesn't exist
                }
                fdb_fetch_header(version, header_buf, &trie_root_bid,
                                 &seq_root_bid, &stale_root_bid,
                                 &ndocs, &ndeletes, &nlivenodes,
                                 &datasize, &last_wal_flush_hdr_bid,
                                 &kv_info_offset, &header_flags,
                                 &compacted_filename, NULL);
                handle->last_hdr_bid = hdr_bid;

                if (!handle->kvs || handle->kvs->id == 0) {
                    // single KVS mode OR default KVS
                    if (!handle->shandle) {
                        // rollback
                        struct kvs_stat stat_dst;
                        _kvs_stat_get(handle->file, 0, &stat_dst);
                        stat_dst.ndocs = ndocs;
                        stat_dst.ndeletes = ndeletes;
                        stat_dst.datasize = datasize;
                        stat_dst.nlivenodes = nlivenodes;
                        stat_dst.deltasize = deltasize;
                        _kvs_stat_set(handle->file, 0, stat_dst);
                    }
                    continue;
                }

                uint64_t doc_offset;
                struct kvs_header *kv_header;
                struct docio_object doc;

                _fdb_kvs_header_create(&kv_header);
                memset(&doc, 0, sizeof(struct docio_object));
                doc_offset = docio_read_doc(handle->dhandle,
                                            kv_info_offset, &doc, true);

                if (doc_offset == kv_info_offset) {
                    header_len = 0; // fail
                    _fdb_kvs_header_free(kv_header);
                } else {
                    _fdb_kvs_header_import(kv_header, doc.body,
                                           doc.length.bodylen, version, false);
                    // get local sequence number for the KV instance
                    seqnum = _fdb_kvs_get_seqnum(kv_header,
                                                 handle->kvs->id);
                    if (!handle->shandle) {
                        // rollback: replace kv_header stats
                        // read from the current header's kv_header
                        struct kvs_stat stat_src, stat_dst;
                        _kvs_stat_get_kv_header(kv_header,
                                                handle->kvs->id,
                                                &stat_src);
                        _kvs_stat_get(handle->file,
                                      handle->kvs->id,
                                      &stat_dst);
                        // update ndocs, datasize, nlivenodes
                        // into the current file's kv_header
                        // Note: stats related to WAL should not be updated
                        //       at this time. They will be adjusted through
                        //       discard & restore routines below.
                        stat_dst.ndocs = stat_src.ndocs;
                        stat_dst.datasize = stat_src.datasize;
                        stat_dst.nlivenodes = stat_src.nlivenodes;
                        _kvs_stat_set(handle->file,
                                      handle->kvs->id,
                                      stat_dst);
                    }
                    _fdb_kvs_header_free(kv_header);
                    free_docio_object(&doc, 1, 1, 1);
                }
            }
            if (!header_len) { // Marker MUST match that of DB commit!
                // rollback original stats
                if (handle->kvs) {
                    _kvs_stat_get(handle->file, handle->kvs->id, &stat_ori);
                } else {
                    _kvs_stat_get(handle->file, 0, &stat_ori);
                }

                docio_free(handle->dhandle);
                free(handle->dhandle);
                free(handle->filename);
                free(prev_filename);
                handle->filename = NULL;
                filemgr_close(handle->file, false, handle->filename,
                              &handle->log_callback);
                return FDB_RESULT_NO_DB_INSTANCE;
            }

            if (!handle->shandle) { // Rollback mode, destroy file WAL..
                if (handle->config.multi_kv_instances) {
                    // multi KV instance mode
                    // clear only WAL items belonging to the instance
                    wal_close_kv_ins(handle->file,
                                     (handle->kvs)?(handle->kvs->id):(0));
                } else {
                    wal_shutdown(handle->file);
                }
            }
        } else { // snapshot to sequence number 0 requested..
            if (handle->shandle) { // fdb_snapshot_open API call
                if (seqnum) {
                    // Database currently has a non-zero seq number,
                    // but the snapshot was requested with a seq number zero.
                    docio_free(handle->dhandle);
                    free(handle->dhandle);
                    free(handle->filename);
                    free(prev_filename);
                    handle->filename = NULL;
                    filemgr_close(handle->file, false, handle->filename,
                                  &handle->log_callback);
                    return FDB_RESULT_NO_DB_INSTANCE;
                }
            } // end of zero max_seqnum but non-rollback check
        } // end of zero max_seqnum check
    } // end of durable snapshot locating

    handle->btreeblkops = btreeblk_get_ops();
    handle->bhandle = (struct btreeblk_handle *)
                      calloc(1, sizeof(struct btreeblk_handle));
    handle->bhandle->log_callback = &handle->log_callback;

    handle->dirty_updates = 0;

    if (handle->config.compaction_buf_maxsize == 0) {
        handle->config.compaction_buf_maxsize = FDB_COMP_BUF_MINSIZE;
    }

    btreeblk_init(handle->bhandle, handle->file, handle->file->blocksize);

    if (header_revnum && !filemgr_is_rollback_on(handle->file)) {
        // only for snapshot (excluding rollback)
        handle->cur_header_revnum = header_revnum;
    } else {
        handle->cur_header_revnum = latest_header_revnum;
    }
    handle->last_wal_flush_hdr_bid = last_wal_flush_hdr_bid;

    memset(&empty_stat, 0x0, sizeof(empty_stat));
    _kvs_stat_get(handle->file, 0, &stat);
    if (!memcmp(&stat, &empty_stat, sizeof(stat))) { // first open
        // sync (default) KVS stat with DB header
        stat.nlivenodes = nlivenodes;
        stat.ndocs = ndocs;
        stat.datasize = datasize;
        _kvs_stat_set(handle->file, 0, stat);
    }

    handle->kv_info_offset = kv_info_offset;
    if (handle->config.multi_kv_instances && !handle->shandle) {
        // multi KV instance mode
        filemgr_mutex_lock(handle->file);
        if (kv_info_offset == BLK_NOT_FOUND) {
            // there is no KV header .. create & initialize
            fdb_kvs_header_create(handle->file);
            // TODO: If another handle is opened before the first header is appended,
            // an unnecessary KV info doc is appended. We need to address it.
            kv_info_offset = fdb_kvs_header_append(handle);
        } else if (handle->file->kv_header == NULL) {
            // KV header already exists but not loaded .. read & import
            fdb_kvs_header_create(handle->file);
            fdb_kvs_header_read(handle->file->kv_header, handle->dhandle,
                                kv_info_offset, version, false);
        }
        filemgr_mutex_unlock(handle->file);

        // validation check for key order of all KV stores
        if (handle == handle->fhandle->root) {
            fdb_status fs = fdb_kvs_cmp_check(handle);
            if (fs != FDB_RESULT_SUCCESS) { // cmp function mismatch
                docio_free(handle->dhandle);
                free(handle->dhandle);
                btreeblk_free(handle->bhandle);
                free(handle->bhandle);
                free(handle->filename);
                handle->filename = NULL;
                filemgr_close(handle->file, false, handle->filename,
                              &handle->log_callback);
                return fs;
            }
        }
    }
    handle->kv_info_offset = kv_info_offset;

    if (handle->kv_info_offset != BLK_NOT_FOUND &&
        handle->kvs == NULL) {
        // multi KV instance mode .. turn on config flag
        handle->config.multi_kv_instances = true;
        // only super handle can be opened using fdb_open(...)
        fdb_kvs_info_create(NULL, handle, handle->file, NULL);
    }

    if (handle->shandle) { // Populate snapshot stats..
        if (kv_info_offset == BLK_NOT_FOUND) { // Single KV mode
            memset(&handle->shandle->stat, 0x0,
                    sizeof(handle->shandle->stat));
            handle->shandle->stat.ndocs = ndocs;
            handle->shandle->stat.datasize = datasize;
            handle->shandle->stat.nlivenodes = nlivenodes;
        } else { // Multi KV instance mode, populate specific kv stats
            memset(&handle->shandle->stat, 0x0,
                    sizeof(handle->shandle->stat));
            _kvs_stat_get(handle->file, handle->kvs->id,
                    &handle->shandle->stat);
            // Since wal is restored below, we have to reset
            // wal stats to zero.
            handle->shandle->stat.wal_ndeletes = 0;
            handle->shandle->stat.wal_ndocs = 0;
        }
    }

    // initialize pointer to the global operational stats of this KV store
    handle->op_stats = filemgr_get_ops_stats(handle->file, handle->kvs);
    if (!handle->op_stats) {
        const char *msg = "Database open fails due to the error in retrieving "
            "the global operational stats of KV store in a database file '%s'\n";
        fdb_log(&handle->log_callback, FDB_RESULT_OPEN_FAIL, msg,
                handle->file->filename);
        return FDB_RESULT_OPEN_FAIL;
    }

    handle->trie = (struct hbtrie *)malloc(sizeof(struct hbtrie));
    hbtrie_init(handle->trie, config->chunksize, OFFSET_SIZE,
                handle->file->blocksize, trie_root_bid,
                (void *)handle->bhandle, handle->btreeblkops,
                (void *)handle->dhandle, _fdb_readkey_wrap);
    // set aux for cmp wrapping function
    hbtrie_set_leaf_height_limit(handle->trie, 0xff);
    hbtrie_set_leaf_cmp(handle->trie, _fdb_custom_cmp_wrap);

    if (handle->kvs) {
        hbtrie_set_map_function(handle->trie, fdb_kvs_find_cmp_chunk);
    }

    if (handle->config.seqtree_opt == FDB_SEQTREE_USE) {
        handle->seqnum = seqnum;

        if (handle->config.multi_kv_instances) {
            // multi KV instance mode .. HB+trie
            handle->seqtrie = (struct hbtrie *)malloc(sizeof(struct hbtrie));
            hbtrie_init(handle->seqtrie, sizeof(fdb_kvs_id_t), OFFSET_SIZE,
                        handle->file->blocksize, seq_root_bid,
                        (void *)handle->bhandle, handle->btreeblkops,
                        (void *)handle->dhandle, _fdb_readseq_wrap);

        } else {
            // single KV instance mode .. normal B+tree
            struct btree_kv_ops *seq_kv_ops =
                (struct btree_kv_ops *)malloc(sizeof(struct btree_kv_ops));
            seq_kv_ops = btree_kv_get_kb64_vb64(seq_kv_ops);
            seq_kv_ops->cmp = _cmp_uint64_t_endian_safe;

            handle->seqtree = (struct btree*)malloc(sizeof(struct btree));
            if (seq_root_bid == BLK_NOT_FOUND) {
                btree_init(handle->seqtree, (void *)handle->bhandle,
                           handle->btreeblkops, seq_kv_ops,
                           handle->config.blocksize, sizeof(fdb_seqnum_t),
                           OFFSET_SIZE, 0x0, NULL);
             }else{
                 btree_init_from_bid(handle->seqtree, (void *)handle->bhandle,
                                     handle->btreeblkops, seq_kv_ops,
                                     handle->config.blocksize, seq_root_bid);
             }
        }
    }else{
        handle->seqtree = NULL;
    }

    // Stale-block tree (supported since V3)
    // this tree is independent to multi/single KVS mode option
    if (ver_staletree_support(handle->file->version)) {
        // normal B+tree
        struct btree_kv_ops *stale_kv_ops =
            (struct btree_kv_ops *)calloc(1, sizeof(struct btree_kv_ops));
        stale_kv_ops = btree_kv_get_kb64_vb64(stale_kv_ops);
        stale_kv_ops->cmp = _cmp_uint64_t_endian_safe;

        handle->staletree = (struct btree*)calloc(1, sizeof(struct btree));
        if (stale_root_bid == BLK_NOT_FOUND) {
            btree_init(handle->staletree, (void *)handle->bhandle,
                       handle->btreeblkops, stale_kv_ops,
                       handle->config.blocksize, sizeof(filemgr_header_revnum_t),
                       OFFSET_SIZE, 0x0, NULL);
         }else{
            btree_init_from_bid(handle->staletree, (void *)handle->bhandle,
                                handle->btreeblkops, stale_kv_ops,
                                handle->config.blocksize, stale_root_bid);
         }
    } else {
        handle->staletree = NULL;
    }

    if (handle->config.multi_kv_instances && handle->max_seqnum) {
        // restore only docs belonging to the KV instance
        // handle->kvs should not be NULL
        _fdb_restore_wal(handle, FDB_RESTORE_KV_INS,
                         hdr_bid, (handle->kvs)?(handle->kvs->id):(0));
    } else {
        // normal restore
        _fdb_restore_wal(handle, FDB_RESTORE_NORMAL, hdr_bid, 0);
    }

    if (compacted_filename &&
        filemgr_get_file_status(handle->file) == FILE_NORMAL &&
        !(config->flags & FDB_OPEN_FLAG_RDONLY)) { // do not recover read-only
        _fdb_recover_compaction(handle, compacted_filename);
    }

    if (prev_filename) {
        if (!handle->shandle && strcmp(prev_filename, handle->file->filename)) {
            // record the old filename into the file handle of current file
            // and REMOVE old file on the first open
            // WARNING: snapshots must have been opened before this call
            if (filemgr_update_file_status(handle->file,
                                           filemgr_get_file_status(handle->file),
                                           prev_filename)) {
                // Open the old file with read-only mode.
                // (Temporarily disable log callback at this time since
                //  the old file might be already removed.)
                fconfig.options = FILEMGR_READONLY;
                filemgr_open_result result = filemgr_open(prev_filename,
                                                          handle->fileops,
                                                          &fconfig,
                                                          NULL);
                if (result.file) {
                    filemgr_remove_pending(result.file, handle->file,
                                           &handle->log_callback);
                    filemgr_close(result.file, 0, handle->filename,
                                  &handle->log_callback);
                }
            } else {
                free(prev_filename);
            }
        } else {
            free(prev_filename);
        }
    }

    status = btreeblk_end(handle->bhandle);
    if (status != FDB_RESULT_SUCCESS) {
        return status;
    }

    // do not register read-only handles
    if (!(config->flags & FDB_OPEN_FLAG_RDONLY)) {
        if (config->compaction_mode == FDB_COMPACTION_AUTO) {
            status = compactor_register_file(handle->file,
                                             (fdb_config *)config,
                                             &handle->log_callback);
        }
        if (status == FDB_RESULT_SUCCESS) {
            status = bgflusher_register_file(handle->file,
                                             (fdb_config *)config,
                                             &handle->log_callback);
        }
    }

#ifdef _TRACE_HANDLES
    spin_lock(&open_handle_lock);
    avl_insert(&open_handles, &handle->avl_trace, _fdb_handle_cmp);
    spin_unlock(&open_handle_lock);
#endif
    return status;
}

LIBFDB_API
fdb_status fdb_set_log_callback(fdb_kvs_handle *handle,
                                fdb_log_callback log_callback,
                                void *ctx_data)
{
    handle->log_callback.callback = log_callback;
    handle->log_callback.ctx_data = ctx_data;
    return FDB_RESULT_SUCCESS;
}

LIBFDB_API
void fdb_set_fatal_error_callback(fdb_fatal_error_callback err_callback)
{
    fatal_error_callback = err_callback;
}

LIBFDB_API
fdb_status fdb_doc_create(fdb_doc **doc, const void *key, size_t keylen,
                          const void *meta, size_t metalen,
                          const void *body, size_t bodylen)
{
    if (doc == NULL || keylen > FDB_MAX_KEYLEN ||
        metalen > FDB_MAX_METALEN || bodylen > FDB_MAX_BODYLEN) {
        return FDB_RESULT_INVALID_ARGS;
    }

    *doc = (fdb_doc*)calloc(1, sizeof(fdb_doc));
    if (*doc == NULL) { // LCOV_EXCL_START
        return FDB_RESULT_ALLOC_FAIL;
    } // LCOV_EXCL_STOP

    (*doc)->seqnum = SEQNUM_NOT_USED;

    if (key && keylen > 0) {
        (*doc)->key = (void *)malloc(keylen);
        if ((*doc)->key == NULL) { // LCOV_EXCL_START
            return FDB_RESULT_ALLOC_FAIL;
        } // LCOV_EXCL_STOP
        memcpy((*doc)->key, key, keylen);
        (*doc)->keylen = keylen;
    } else {
        (*doc)->key = NULL;
        (*doc)->keylen = 0;
    }

    if (meta && metalen > 0) {
        (*doc)->meta = (void *)malloc(metalen);
        if ((*doc)->meta == NULL) { // LCOV_EXCL_START
            return FDB_RESULT_ALLOC_FAIL;
        } // LCOV_EXCL_STOP
        memcpy((*doc)->meta, meta, metalen);
        (*doc)->metalen = metalen;
    } else {
        (*doc)->meta = NULL;
        (*doc)->metalen = 0;
    }

    if (body && bodylen > 0) {
        (*doc)->body = (void *)malloc(bodylen);
        if ((*doc)->body == NULL) { // LCOV_EXCL_START
            return FDB_RESULT_ALLOC_FAIL;
        } // LCOV_EXCL_STOP
        memcpy((*doc)->body, body, bodylen);
        (*doc)->bodylen = bodylen;
    } else {
        (*doc)->body = NULL;
        (*doc)->bodylen = 0;
    }

    return FDB_RESULT_SUCCESS;
}

LIBFDB_API
fdb_status fdb_doc_update(fdb_doc **doc,
                          const void *meta, size_t metalen,
                          const void *body, size_t bodylen)
{
    if (doc == NULL ||
        metalen > FDB_MAX_METALEN || bodylen > FDB_MAX_BODYLEN) {
        return FDB_RESULT_INVALID_ARGS;
    }
    if (*doc == NULL) {
        return FDB_RESULT_INVALID_ARGS;
    }

    if (meta && metalen > 0) {
        // free previous metadata
        free((*doc)->meta);
        // allocate new metadata
        (*doc)->meta = (void *)malloc(metalen);
        if ((*doc)->meta == NULL) { // LCOV_EXCL_START
            return FDB_RESULT_ALLOC_FAIL;
        } // LCOV_EXCL_STOP
        memcpy((*doc)->meta, meta, metalen);
        (*doc)->metalen = metalen;
    }

    if (body && bodylen > 0) {
        // free previous body
        free((*doc)->body);
        // allocate new body
        (*doc)->body = (void *)malloc(bodylen);
        if ((*doc)->body == NULL) { // LCOV_EXCL_START
            return FDB_RESULT_ALLOC_FAIL;
        } // LCOV_EXCL_STOP
        memcpy((*doc)->body, body, bodylen);
        (*doc)->bodylen = bodylen;
    }

    (*doc)->seqnum = SEQNUM_NOT_USED;
    return FDB_RESULT_SUCCESS;
}

LIBFDB_API
void fdb_doc_set_seqnum(fdb_doc *doc,
                        const fdb_seqnum_t seqnum)
{
    doc->seqnum = seqnum;
    if (seqnum != SEQNUM_NOT_USED) {
        doc->flags |= FDB_CUSTOM_SEQNUM; // fdb_set will now use above seqnum
    } else { // reset custom seqnum flag, fdb_set will now generate new seqnum
        doc->flags &= ~FDB_CUSTOM_SEQNUM;
    }
}

// doc MUST BE allocated by malloc
LIBFDB_API
fdb_status fdb_doc_free(fdb_doc *doc)
{
    if (doc) {
        free(doc->key);
        free(doc->meta);
        free(doc->body);
        free(doc);
    }
    return FDB_RESULT_SUCCESS;
}

INLINE uint64_t _fdb_wal_get_old_offset(void *voidhandle,
                                        struct wal_item *item)
{
    fdb_kvs_handle *handle = (fdb_kvs_handle *)voidhandle;
    uint64_t old_offset = 0;

    hbtrie_find_offset(handle->trie,
                       item->header->key,
                       item->header->keylen,
                       (void*)&old_offset);
    btreeblk_end(handle->bhandle);
    old_offset = _endian_decode(old_offset);

    return old_offset;
}

INLINE fdb_status _fdb_wal_snapshot_func(void *handle, fdb_doc *doc,
                                         uint64_t offset) {

    return snap_insert((struct snap_handle *)handle, doc, offset);
}


// A stale sequence number entry that can be purged from the sequence tree
// during the WAL flush.
struct wal_stale_seq_entry {
    fdb_kvs_id_t kv_id;
    fdb_seqnum_t seqnum;
    struct avl_node avl_entry;
};

// Delta changes in KV store stats during the WAL flush
struct wal_kvs_delta_stat {
    fdb_kvs_id_t kv_id;
    int64_t nlivenodes;
    int64_t ndocs;
    int64_t ndeletes;
    int64_t datasize;
    int64_t deltasize;
    struct avl_node avl_entry;
};

INLINE int _fdb_seq_entry_cmp(struct avl_node *a, struct avl_node *b, void *aux)
{
    (void) aux;
    struct wal_stale_seq_entry *entry1 = _get_entry(a, struct wal_stale_seq_entry,
                                                    avl_entry);
    struct wal_stale_seq_entry *entry2 = _get_entry(b, struct wal_stale_seq_entry,
                                                    avl_entry);
    if (entry1->kv_id < entry2->kv_id) {
        return -1;
    } else if (entry1->kv_id > entry2->kv_id) {
        return 1;
    } else {
        return _CMP_U64(entry1->seqnum, entry2->seqnum);
    }
}


// Compare function to sort KVS delta stat entries in the AVL tree during WAL flush
INLINE int _kvs_delta_stat_cmp(struct avl_node *a, struct avl_node *b, void *aux)
{
    (void) aux;
    struct wal_kvs_delta_stat *stat1 = _get_entry(a, struct wal_kvs_delta_stat,
                                                  avl_entry);
    struct wal_kvs_delta_stat *stat2 = _get_entry(b, struct wal_kvs_delta_stat,
                                                  avl_entry);
    if (stat1->kv_id < stat2->kv_id) {
        return -1;
    } else if (stat1->kv_id > stat2->kv_id) {
        return 1;
    } else {
        return 0;
    }
}

INLINE void _fdb_wal_flush_seq_purge(void *dbhandle,
                                     struct avl_tree *stale_seqnum_list,
                                     struct avl_tree *kvs_delta_stats)
{
    fdb_seqnum_t _seqnum;
    int64_t nlivenodes;
    int64_t ndeltanodes;
    int64_t delta;
    uint8_t kvid_seqnum[sizeof(fdb_kvs_id_t) + sizeof(fdb_seqnum_t)];
    struct wal_stale_seq_entry *seq_entry;
    struct wal_kvs_delta_stat *delta_stat;
    struct wal_kvs_delta_stat kvs_delta_query;

    fdb_kvs_handle *handle = (fdb_kvs_handle *)dbhandle;
    struct avl_node *node = avl_first(stale_seqnum_list);
    while (node) {
        seq_entry = _get_entry(node, struct wal_stale_seq_entry, avl_entry);
        node = avl_next(node);
        nlivenodes = handle->bhandle->nlivenodes;
        ndeltanodes = handle->bhandle->ndeltanodes;
        _seqnum = _endian_encode(seq_entry->seqnum);
        if (handle->kvs) {
            // multi KV instance mode .. HB+trie
            kvid2buf(sizeof(fdb_kvs_id_t), seq_entry->kv_id, kvid_seqnum);
            memcpy(kvid_seqnum + sizeof(fdb_kvs_id_t), &_seqnum, sizeof(fdb_seqnum_t));
            hbtrie_remove(handle->seqtrie, (void*)kvid_seqnum,
                          sizeof(fdb_kvs_id_t) + sizeof(fdb_seqnum_t));
        } else {
            btree_remove(handle->seqtree, (void*)&_seqnum);
        }
        btreeblk_end(handle->bhandle);

        kvs_delta_query.kv_id = seq_entry->kv_id;
        avl_node *delta_stat_node = avl_search(kvs_delta_stats,
                                               &kvs_delta_query.avl_entry,
                                               _kvs_delta_stat_cmp);
        if (delta_stat_node) {
            delta_stat = _get_entry(delta_stat_node, struct wal_kvs_delta_stat,
                                    avl_entry);
            delta = handle->bhandle->nlivenodes - nlivenodes;
            delta_stat->nlivenodes += delta;
            delta = handle->bhandle->ndeltanodes - ndeltanodes;
            delta *= handle->config.blocksize;
            delta_stat->deltasize += delta;
        }
        avl_remove(stale_seqnum_list, &seq_entry->avl_entry);
        free(seq_entry);
    }
}

INLINE void _fdb_wal_flush_kvs_delta_stats(struct filemgr *file,
                                           struct avl_tree *kvs_delta_stats)
{
    struct avl_node *node;
    struct wal_kvs_delta_stat *delta_stat;
    node = avl_first(kvs_delta_stats);
    while (node) {
        delta_stat = _get_entry(node, struct wal_kvs_delta_stat, avl_entry);
        node = avl_next(node);
        _kvs_stat_update_attr(file, delta_stat->kv_id,
                              KVS_STAT_DATASIZE, delta_stat->datasize);
        _kvs_stat_update_attr(file, delta_stat->kv_id,
                              KVS_STAT_NDOCS, delta_stat->ndocs);
        _kvs_stat_update_attr(file, delta_stat->kv_id,
                              KVS_STAT_NDELETES, delta_stat->ndeletes);
        _kvs_stat_update_attr(file, delta_stat->kv_id,
                              KVS_STAT_NLIVENODES, delta_stat->nlivenodes);
        _kvs_stat_update_attr(file, delta_stat->kv_id,
                              KVS_STAT_DELTASIZE, delta_stat->deltasize);
        avl_remove(kvs_delta_stats, &delta_stat->avl_entry);
        free(delta_stat);
    }
}

INLINE fdb_status _fdb_wal_flush_func(void *voidhandle,
                                      struct wal_item *item,
                                      struct avl_tree *stale_seqnum_list,
                                      struct avl_tree *kvs_delta_stats)
{
    hbtrie_result hr;
    fdb_kvs_handle *handle = (fdb_kvs_handle *)voidhandle;
    fdb_seqnum_t _seqnum;
    fdb_kvs_id_t kv_id;
    fdb_status fs = FDB_RESULT_SUCCESS;
    uint8_t *var_key = alca(uint8_t, handle->config.chunksize);
    int size_id, size_seq;
    uint8_t *kvid_seqnum;
    uint64_t old_offset, _offset;
    int64_t delta;
    struct docio_object _doc;
    struct filemgr *file = handle->dhandle->file;

    memset(var_key, 0, handle->config.chunksize);
    if (handle->kvs) {
        buf2kvid(handle->config.chunksize, item->header->key, &kv_id);
    } else {
        kv_id = 0;
    }

    struct wal_kvs_delta_stat *kvs_delta_stat;
    struct wal_kvs_delta_stat kvs_delta_query;
    kvs_delta_query.kv_id = kv_id;
    avl_node *delta_stat_node = avl_search(kvs_delta_stats, &kvs_delta_query.avl_entry,
                                           _kvs_delta_stat_cmp);
    if (delta_stat_node) {
        kvs_delta_stat = _get_entry(delta_stat_node, struct wal_kvs_delta_stat,
                                    avl_entry);
    } else {
        kvs_delta_stat = (struct wal_kvs_delta_stat *)
            calloc(1, sizeof(struct wal_kvs_delta_stat));
        kvs_delta_stat->kv_id = kv_id;
        avl_insert(kvs_delta_stats, &kvs_delta_stat->avl_entry, _kvs_delta_stat_cmp);
    }

    int64_t nlivenodes = handle->bhandle->nlivenodes;
    int64_t ndeltanodes = handle->bhandle->ndeltanodes;

    if (item->action == WAL_ACT_INSERT ||
        item->action == WAL_ACT_LOGICAL_REMOVE) {
        _offset = _endian_encode(item->offset);

        hr = hbtrie_insert(handle->trie,
                           item->header->key,
                           item->header->keylen,
                           (void *)&_offset,
                           (void *)&old_offset);

        fs = btreeblk_end(handle->bhandle);
        if (fs != FDB_RESULT_SUCCESS) {
            return fs;
        }
        old_offset = _endian_decode(old_offset);

        if (handle->config.seqtree_opt == FDB_SEQTREE_USE) {
            _seqnum = _endian_encode(item->seqnum);
            if (handle->kvs) {
                // multi KV instance mode .. HB+trie
                uint64_t old_offset_local;

                size_id = sizeof(fdb_kvs_id_t);
                size_seq = sizeof(fdb_seqnum_t);
                kvid_seqnum = alca(uint8_t, size_id + size_seq);
                kvid2buf(size_id, kv_id, kvid_seqnum);
                memcpy(kvid_seqnum + size_id, &_seqnum, size_seq);
                hbtrie_insert(handle->seqtrie, kvid_seqnum, size_id + size_seq,
                              (void *)&_offset, (void *)&old_offset_local);
            } else {
                btree_insert(handle->seqtree, (void *)&_seqnum,
                             (void *)&_offset);
            }
            fs = btreeblk_end(handle->bhandle);
            if (fs != FDB_RESULT_SUCCESS) {
                return fs;
            }
        }

        delta = handle->bhandle->nlivenodes - nlivenodes;
        kvs_delta_stat->nlivenodes += delta;
        delta = handle->bhandle->ndeltanodes - ndeltanodes;
        delta *= handle->config.blocksize;
        kvs_delta_stat->deltasize += delta;

        if (hr == HBTRIE_RESULT_SUCCESS) {
            if (item->action == WAL_ACT_INSERT) {
                ++kvs_delta_stat->ndocs;
            } else { // inserted a logical deleted doc into main index
                ++kvs_delta_stat->ndeletes;
            }
            kvs_delta_stat->datasize += item->doc_size;
            kvs_delta_stat->deltasize += item->doc_size;
        } else { // update or logical delete
            // This block is already cached when we call HBTRIE_INSERT.
            // No additional block access.
            char dummy_key[FDB_MAX_KEYLEN];
            _doc.meta = _doc.body = NULL;
            _doc.key = &dummy_key;
            _offset = docio_read_doc_key_meta(handle->dhandle, old_offset,
                                              &_doc, true);
            free(_doc.meta);
            filemgr_mark_stale(file, old_offset, _fdb_get_docsize(_doc.length));

            if (!(_doc.length.flag & DOCIO_DELETED)) {//prev doc was not deleted
                if (item->action == WAL_ACT_LOGICAL_REMOVE) { // now deleted
                    --kvs_delta_stat->ndocs;
                    ++kvs_delta_stat->ndeletes;
                } // else no change (prev doc was insert, now just an update)
            } else { // prev doc in main index was a logically deleted doc
                if (item->action == WAL_ACT_INSERT) { // now undeleted
                    ++kvs_delta_stat->ndocs;
                    --kvs_delta_stat->ndeletes;
                } // else no change (prev doc was deleted, now re-deleted)
            }

            delta = (int)item->doc_size - (int)_fdb_get_docsize(_doc.length);
            kvs_delta_stat->datasize += delta;
            if (handle->last_hdr_bid * handle->config.blocksize < old_offset) {
                kvs_delta_stat->deltasize += delta;
            } else {
                kvs_delta_stat->deltasize += (int)item->doc_size;
            }

            // Avoid duplicates (remove previous sequence number)
            if (handle->config.seqtree_opt == FDB_SEQTREE_USE) {
                struct wal_stale_seq_entry *entry = (struct wal_stale_seq_entry *)
                    calloc(1, sizeof(struct wal_stale_seq_entry));
                entry->kv_id = kv_id;
                entry->seqnum = _doc.seqnum;
                avl_insert(stale_seqnum_list, &entry->avl_entry, _fdb_seq_entry_cmp);
            }
        }
    } else {
        // Immediate remove
        old_offset = item->old_offset;
        hr = hbtrie_remove(handle->trie, item->header->key,
                           item->header->keylen);
        fs = btreeblk_end(handle->bhandle);
        if (fs != FDB_RESULT_SUCCESS) {
            return fs;
        }

        if (hr == HBTRIE_RESULT_SUCCESS) {
            // This block is already cached when we call _fdb_wal_get_old_offset
            // No additional block access should be done.
            char dummy_key[FDB_MAX_KEYLEN];
            _doc.meta = _doc.body = NULL;
            _doc.key = &dummy_key;
            _offset = docio_read_doc_key_meta(handle->dhandle, old_offset,
                                              &_doc, true);
            free(_doc.meta);
            filemgr_mark_stale(file, old_offset, _fdb_get_docsize(_doc.length));

            // Reduce the total number of docs by one
            --kvs_delta_stat->ndocs;
            if (_doc.length.flag & DOCIO_DELETED) {//prev deleted doc is dropped
                --kvs_delta_stat->ndeletes;
            }

            // Reduce the total datasize by size of previously present doc
            delta = -(int)_fdb_get_docsize(_doc.length);
            kvs_delta_stat->datasize += delta;
            // if multiple wal flushes happen before commit, then it's possible
            // that this doc deleted was inserted & flushed after last commit
            // In this case we need to update the deltasize too which tracks
            // the amount of new data inserted between commits.
            if (handle->last_hdr_bid * handle->config.blocksize < old_offset) {
                kvs_delta_stat->deltasize += delta;
            }

            // remove sequence number for the removed doc
            if (handle->config.seqtree_opt == FDB_SEQTREE_USE) {
                struct wal_stale_seq_entry *entry = (struct wal_stale_seq_entry *)
                    calloc(1, sizeof(struct wal_stale_seq_entry));
                entry->kv_id = kv_id;
                entry->seqnum = _doc.seqnum;
                avl_insert(stale_seqnum_list, &entry->avl_entry, _fdb_seq_entry_cmp);
            }

            // Update index size to new size after the remove operation
            delta = handle->bhandle->nlivenodes - nlivenodes;
            kvs_delta_stat->nlivenodes += delta;

            // ndeltanodes measures number of new index nodes created due to
            // this hbtrie_remove() operation
            delta = (int)handle->bhandle->ndeltanodes - ndeltanodes;
            delta *= handle->config.blocksize;
            kvs_delta_stat->deltasize += delta;
        }
    }
    return FDB_RESULT_SUCCESS;
}

void fdb_sync_db_header(fdb_kvs_handle *handle)
{
    uint64_t cur_revnum = filemgr_get_header_revnum(handle->file);
    if (handle->cur_header_revnum != cur_revnum) {
        void *header_buf = NULL;
        size_t header_len;
        bid_t hdr_bid;
        filemgr_header_revnum_t revnum;

        header_buf = filemgr_get_header(handle->file, NULL, &header_len,
                                        &hdr_bid, NULL, &revnum);
        if (header_len > 0) {
            uint64_t header_flags, dummy64, version;
            bid_t idtree_root;
            bid_t new_seq_root;
            bid_t new_stale_root;
            char *compacted_filename;
            char *prev_filename = NULL;

            version = handle->file->version;
            handle->last_hdr_bid = hdr_bid;
            handle->cur_header_revnum = revnum;

            fdb_fetch_header(version, header_buf, &idtree_root,
                             &new_seq_root, &new_stale_root, &dummy64,
                             &dummy64, &dummy64,
                             &dummy64, &handle->last_wal_flush_hdr_bid,
                             &handle->kv_info_offset, &header_flags,
                             &compacted_filename, &prev_filename);

            if (handle->dirty_updates) {
                // discard all cached writable b+tree nodes
                // to avoid data inconsistency with other writers
                btreeblk_discard_blocks(handle->bhandle);
            }

            handle->trie->root_bid = idtree_root;

            if (handle->config.seqtree_opt == FDB_SEQTREE_USE) {
                if (new_seq_root != handle->seqtree->root_bid) {
                    if (handle->config.multi_kv_instances) {
                        handle->seqtrie->root_bid = new_seq_root;
                    } else {
                        btree_init_from_bid(handle->seqtree,
                                            handle->seqtree->blk_handle,
                                            handle->seqtree->blk_ops,
                                            handle->seqtree->kv_ops,
                                            handle->seqtree->blksize,
                                            new_seq_root);
                    }
                }
            }

            if (ver_staletree_support(version)) {
                btree_init_from_bid(handle->staletree,
                                    handle->staletree->blk_handle,
                                    handle->staletree->blk_ops,
                                    handle->staletree->kv_ops,
                                    handle->staletree->blksize,
                                    new_stale_root);
            } else {
                handle->staletree = NULL;
            }

            if (prev_filename) {
                free(prev_filename);
            }

            handle->dirty_updates = 0;
            if (handle->kvs) {
                // multiple KV instance mode AND sub handle
                handle->seqnum = fdb_kvs_get_seqnum(handle->file,
                                                    handle->kvs->id);
            } else {
                // super handle OR single KV instance mode
                handle->seqnum = filemgr_get_seqnum(handle->file);
            }
        } else {
            handle->last_hdr_bid = filemgr_get_header_bid(handle->file);
        }

        if (header_buf) {
            free(header_buf);
        }
    }
}

fdb_status fdb_check_file_reopen(fdb_kvs_handle *handle, file_status_t *status)
{
    bool fhandle_ret;
    fdb_status fs = FDB_RESULT_SUCCESS;
    file_status_t fstatus = filemgr_get_file_status(handle->file);
    // check whether the compaction is done
    if (fstatus == FILE_REMOVED_PENDING) {
        uint64_t ndocs, ndeletes, datasize, nlivenodes, last_wal_flush_hdr_bid;
        uint64_t kv_info_offset, header_flags;
        size_t header_len;
        char *new_filename;
        uint8_t *buf = alca(uint8_t, handle->config.blocksize);
        bid_t trie_root_bid, seq_root_bid, stale_root_bid;
        fdb_config config = handle->config;

        // close the current file and newly open the new file
        if (handle->config.compaction_mode == FDB_COMPACTION_AUTO) {
            // compaction daemon mode .. just close and then open
            char filename[FDB_MAX_FILENAME_LEN];
            strcpy(filename, handle->filename);

            // We don't need to maintain fhandle list for the old file
            // as there will be no more mutation on the file.
            fhandle_ret = filemgr_fhandle_remove(handle->file, handle->fhandle);
            fs = _fdb_close(handle);
            if (fs != FDB_RESULT_SUCCESS) {
                if (fhandle_ret) {
                    filemgr_fhandle_add(handle->file, handle->fhandle);
                }
                return fs;
            }

            fs = _fdb_open(handle, filename, FDB_VFILENAME, &config);
            if (fs != FDB_RESULT_SUCCESS) {
                return fs;
            }
            filemgr_fhandle_add(handle->file, handle->fhandle);

        } else {
            filemgr_get_header(handle->file, buf, &header_len, NULL, NULL, NULL);
            fdb_fetch_header(handle->file->version, buf,
                             &trie_root_bid, &seq_root_bid, &stale_root_bid,
                             &ndocs, &ndeletes, &nlivenodes, &datasize,
                             &last_wal_flush_hdr_bid,
                             &kv_info_offset, &header_flags,
                             &new_filename, NULL);

            fhandle_ret = filemgr_fhandle_remove(handle->file, handle->fhandle);
            fs = _fdb_close(handle);
            if (fs != FDB_RESULT_SUCCESS) {
                if (fhandle_ret) {
                    filemgr_fhandle_add(handle->file, handle->fhandle);
                }
                return fs;
            }

            fs = _fdb_open(handle, new_filename, FDB_AFILENAME, &config);
            if (fs != FDB_RESULT_SUCCESS) {
                return fs;
            }
            filemgr_fhandle_add(handle->file, handle->fhandle);
        }
    }
    if (status) {
        *status = fstatus;
    }
    return fs;
}

static bool _fdb_sync_dirty_root(fdb_kvs_handle *handle)
{
    bool locked = false;
    bid_t dirty_idtree_root, dirty_seqtree_root;

    if (handle->shandle) {
        // skip snapshot
        return locked;
    }

    if ( ( handle->dirty_updates ||
           filemgr_dirty_root_exist(handle->file) )  &&
         filemgr_get_header_bid(handle->file) == handle->last_hdr_bid ) {
        // 1) { a) dirty WAL flush by this handle exists OR
        //      b) dirty WAL flush by other handle exists } AND
        // 2) no commit was performed yet.
        // grab lock for writer
        filemgr_mutex_lock(handle->file);
        locked = true;

        // get dirty root nodes
        filemgr_get_dirty_root(handle->file,
                               &dirty_idtree_root, &dirty_seqtree_root);
        if (dirty_idtree_root != BLK_NOT_FOUND) {
            handle->trie->root_bid = dirty_idtree_root;
        }
        if (handle->config.seqtree_opt == FDB_SEQTREE_USE) {
            if (dirty_seqtree_root != BLK_NOT_FOUND) {
                if (handle->kvs) {
                    handle->seqtrie->root_bid = dirty_seqtree_root;
                } else {
                    btree_init_from_bid(handle->seqtree,
                                        handle->seqtree->blk_handle,
                                        handle->seqtree->blk_ops,
                                        handle->seqtree->kv_ops,
                                        handle->seqtree->blksize,
                                        dirty_seqtree_root);
                }
            }
        }
        btreeblk_discard_blocks(handle->bhandle);
    }
    return locked;
}

LIBFDB_API
fdb_status fdb_get(fdb_kvs_handle *handle, fdb_doc *doc)
{
    uint64_t offset, _offset;
    struct docio_object _doc;
    struct filemgr *wal_file = NULL;
    struct docio_handle *dhandle;
    fdb_status wr;
    hbtrie_result hr = HBTRIE_RESULT_FAIL;
    fdb_txn *txn;
    fdb_doc doc_kv;
    LATENCY_STAT_START();

    if (!handle || !doc || !doc->key || doc->keylen == 0 ||
        doc->keylen > FDB_MAX_KEYLEN ||
        (handle->kvs_config.custom_cmp &&
            doc->keylen > handle->config.blocksize - HBTRIE_HEADROOM)) {
        return FDB_RESULT_INVALID_ARGS;
    }

    if (!atomic_cas_uint8_t(&handle->handle_busy, 0, 1)) {
        return FDB_RESULT_HANDLE_BUSY;
    }

    doc_kv = *doc;

    if (handle->kvs) {
        // multi KV instance mode
        int size_chunk = handle->config.chunksize;
        doc_kv.keylen = doc->keylen + size_chunk;
        doc_kv.key = alca(uint8_t, doc_kv.keylen);
        kvid2buf(size_chunk, handle->kvs->id, doc_kv.key);
        memcpy((uint8_t*)doc_kv.key + size_chunk, doc->key, doc->keylen);
    }

    if (!handle->shandle) {
        fdb_check_file_reopen(handle, NULL);

        wal_file = handle->file;
        dhandle = handle->dhandle;

        txn = handle->fhandle->root->txn;
        if (!txn) {
            txn = &wal_file->global_txn;
        }
        if (handle->kvs) {
            wr = wal_find(txn, wal_file, &doc_kv, &offset);
        } else {
            wr = wal_find(txn, wal_file, doc, &offset);
        }
        fdb_sync_db_header(handle);
    } else {
        if (handle->kvs) {
            wr = snap_find(handle->shandle, &doc_kv, &offset);
        } else {
            wr = snap_find(handle->shandle, doc, &offset);
        }
        dhandle = handle->dhandle;
    }

    atomic_incr_uint64_t(&handle->op_stats->num_gets);

    if (wr == FDB_RESULT_KEY_NOT_FOUND) {
        bool locked = _fdb_sync_dirty_root(handle);

        if (handle->kvs) {
            hr = hbtrie_find(handle->trie, doc_kv.key, doc_kv.keylen,
                             (void *)&offset);
        } else {
            hr = hbtrie_find(handle->trie, doc->key, doc->keylen,
                             (void *)&offset);
        }
        btreeblk_end(handle->bhandle);
        offset = _endian_decode(offset);

        if (locked) {
            // grab lock for writer if there are dirty updates
            filemgr_mutex_unlock(handle->file);
        }
    }

    if ((wr == FDB_RESULT_SUCCESS && offset != BLK_NOT_FOUND) ||
         hr != HBTRIE_RESULT_FAIL) {
        bool alloced_meta = doc->meta ? false : true;
        bool alloced_body = doc->body ? false : true;
        if (handle->kvs) {
            _doc.key = doc_kv.key;
            _doc.length.keylen = doc_kv.keylen;
            doc->deleted = doc_kv.deleted; // update deleted field if wal_find
        } else {
            _doc.key = doc->key;
            _doc.length.keylen = doc->keylen;
        }
        _doc.meta = doc->meta;
        _doc.body = doc->body;

        if (wr == FDB_RESULT_SUCCESS && doc->deleted) {
            atomic_cas_uint8_t(&handle->handle_busy, 1, 0);
            return FDB_RESULT_KEY_NOT_FOUND;
        }

        _offset = docio_read_doc(dhandle, offset, &_doc, true);
        if (_offset == offset) {
            atomic_cas_uint8_t(&handle->handle_busy, 1, 0);
            return FDB_RESULT_KEY_NOT_FOUND;
        }

        if (_doc.length.keylen != doc_kv.keylen ||
            _doc.length.flag & DOCIO_DELETED) {
            free_docio_object(&_doc, 0, alloced_meta, alloced_body);
            atomic_cas_uint8_t(&handle->handle_busy, 1, 0);
            return FDB_RESULT_KEY_NOT_FOUND;
        }

        doc->seqnum = _doc.seqnum;
        doc->metalen = _doc.length.metalen;
        doc->bodylen = _doc.length.bodylen;
        doc->meta = _doc.meta;
        doc->body = _doc.body;
        doc->deleted = _doc.length.flag & DOCIO_DELETED;
        doc->size_ondisk = _fdb_get_docsize(_doc.length);
        doc->offset = offset;

        LATENCY_STAT_END(handle->file, FDB_LATENCY_GETS);
        atomic_cas_uint8_t(&handle->handle_busy, 1, 0);
        return FDB_RESULT_SUCCESS;
    }

    atomic_cas_uint8_t(&handle->handle_busy, 1, 0);
    return FDB_RESULT_KEY_NOT_FOUND;
}

// search document metadata using key
LIBFDB_API
fdb_status fdb_get_metaonly(fdb_kvs_handle *handle, fdb_doc *doc)
{
    uint64_t offset;
    struct docio_object _doc;
    struct docio_handle *dhandle;
    struct filemgr *wal_file = NULL;
    fdb_status wr;
    hbtrie_result hr = HBTRIE_RESULT_FAIL;
    fdb_txn *txn;
    fdb_doc doc_kv;
    LATENCY_STAT_START();

    if (!handle || !doc || !doc->key ||
        doc->keylen == 0 || doc->keylen > FDB_MAX_KEYLEN ||
        (handle->kvs_config.custom_cmp &&
            doc->keylen > handle->config.blocksize - HBTRIE_HEADROOM)) {
        return FDB_RESULT_INVALID_ARGS;
    }

    doc_kv = *doc;

    if (!atomic_cas_uint8_t(&handle->handle_busy, 0, 1)) {
        return FDB_RESULT_HANDLE_BUSY;
    }

    if (handle->kvs) {
        // multi KV instance mode
        int size_chunk = handle->config.chunksize;
        doc_kv.keylen = doc->keylen + size_chunk;
        doc_kv.key = alca(uint8_t, doc_kv.keylen);
        kvid2buf(size_chunk, handle->kvs->id, doc_kv.key);
        memcpy((uint8_t*)doc_kv.key + size_chunk, doc->key, doc->keylen);
    }

    if (!handle->shandle) {
        fdb_check_file_reopen(handle, NULL);

        wal_file = handle->file;
        dhandle = handle->dhandle;

        txn = handle->fhandle->root->txn;
        if (!txn) {
            txn = &wal_file->global_txn;
        }
        if (handle->kvs) {
            wr = wal_find(txn, wal_file, &doc_kv, &offset);
        } else {
            wr = wal_find(txn, wal_file, doc, &offset);
        }
        fdb_sync_db_header(handle);
    } else {
        if (handle->kvs) {
            wr = snap_find(handle->shandle, &doc_kv, &offset);
        } else {
            wr = snap_find(handle->shandle, doc, &offset);
        }
        dhandle = handle->dhandle;
    }

    atomic_incr_uint64_t(&handle->op_stats->num_gets);

    if (wr == FDB_RESULT_KEY_NOT_FOUND) {
        bool locked = _fdb_sync_dirty_root(handle);

        if (handle->kvs) {
            hr = hbtrie_find(handle->trie, doc_kv.key, doc_kv.keylen,
                             (void *)&offset);
        } else {
            hr = hbtrie_find(handle->trie, doc->key, doc->keylen,
                             (void *)&offset);
        }
        btreeblk_end(handle->bhandle);
        offset = _endian_decode(offset);

        if (locked) {
            filemgr_mutex_unlock(handle->file);
        }
    }

    if ((wr == FDB_RESULT_SUCCESS && offset != BLK_NOT_FOUND) ||
         hr != HBTRIE_RESULT_FAIL) {
        if (handle->kvs) {
            _doc.key = doc_kv.key;
            _doc.length.keylen = doc_kv.keylen;
        } else {
            _doc.key = doc->key;
            _doc.length.keylen = doc->keylen;
        }
        bool alloced_meta = doc->meta ? false : true;
        _doc.meta = doc->meta;
        _doc.body = doc->body;

        uint64_t body_offset = docio_read_doc_key_meta(dhandle, offset, &_doc,
                                                       true);
        if (body_offset == offset){
            atomic_cas_uint8_t(&handle->handle_busy, 1, 0);
            return FDB_RESULT_KEY_NOT_FOUND;
        }

        if (_doc.length.keylen != doc_kv.keylen) {
            free_docio_object(&_doc, 0, alloced_meta, 0);
            atomic_cas_uint8_t(&handle->handle_busy, 1, 0);
            return FDB_RESULT_KEY_NOT_FOUND;
        }

        doc->seqnum = _doc.seqnum;
        doc->metalen = _doc.length.metalen;
        doc->bodylen = _doc.length.bodylen;
        doc->meta = _doc.meta;
        doc->body = _doc.body;
        doc->deleted = _doc.length.flag & DOCIO_DELETED;
        doc->size_ondisk = _fdb_get_docsize(_doc.length);
        doc->offset = offset;

        LATENCY_STAT_END(handle->file, FDB_LATENCY_GETS);
        atomic_cas_uint8_t(&handle->handle_busy, 1, 0);
        return FDB_RESULT_SUCCESS;
    }

    atomic_cas_uint8_t(&handle->handle_busy, 1, 0);
    return FDB_RESULT_KEY_NOT_FOUND;
}

// search document using sequence number
LIBFDB_API
fdb_status fdb_get_byseq(fdb_kvs_handle *handle, fdb_doc *doc)
{
    uint64_t offset, _offset;
    struct docio_object _doc;
    struct docio_handle *dhandle;
    struct filemgr *wal_file = NULL;
    fdb_status wr;
    btree_result br = BTREE_RESULT_FAIL;
    fdb_seqnum_t _seqnum;
    fdb_txn *txn;
    LATENCY_STAT_START();

    if (!handle || !doc || doc->seqnum == SEQNUM_NOT_USED) {
        return FDB_RESULT_INVALID_ARGS;
    }

    // Sequence trees are a must for byseq operations
    if (handle->config.seqtree_opt != FDB_SEQTREE_USE) {
        return FDB_RESULT_INVALID_CONFIG;
    }

    if (!atomic_cas_uint8_t(&handle->handle_busy, 0, 1)) {
        return FDB_RESULT_HANDLE_BUSY;
    }

    if (!handle->shandle) {
        fdb_check_file_reopen(handle, NULL);

        wal_file = handle->file;
        dhandle = handle->dhandle;

        txn = handle->fhandle->root->txn;
        if (!txn) {
            txn = &wal_file->global_txn;
        }
        // prevent searching by key in WAL if 'doc' is not empty
        size_t key_len = doc->keylen;
        doc->keylen = 0;
        if (handle->kvs) {
            wr = wal_find_kv_id(txn, wal_file, handle->kvs->id, doc, &offset);
        } else {
            wr = wal_find(txn, wal_file, doc, &offset);
        }
        doc->keylen = key_len;
        fdb_sync_db_header(handle);
    } else {
        wr = snap_find(handle->shandle, doc, &offset);
        dhandle = handle->dhandle;
    }

    atomic_incr_uint64_t(&handle->op_stats->num_gets);

    if (wr == FDB_RESULT_KEY_NOT_FOUND) {
        bool locked = _fdb_sync_dirty_root(handle);

        _seqnum = _endian_encode(doc->seqnum);
        if (handle->kvs) {
            int size_id, size_seq;
            uint8_t *kv_seqnum;
            hbtrie_result hr;
            fdb_kvs_id_t _kv_id;

            _kv_id = _endian_encode(handle->kvs->id);
            size_id = sizeof(fdb_kvs_id_t);
            size_seq = sizeof(fdb_seqnum_t);
            kv_seqnum = alca(uint8_t, size_id + size_seq);
            memcpy(kv_seqnum, &_kv_id, size_id);
            memcpy(kv_seqnum + size_id, &_seqnum, size_seq);
            hr = hbtrie_find(handle->seqtrie, (void *)kv_seqnum,
                             size_id + size_seq, (void *)&offset);
            br = (hr == HBTRIE_RESULT_SUCCESS)?(BTREE_RESULT_SUCCESS):(br);
        } else {
            br = btree_find(handle->seqtree, (void *)&_seqnum, (void *)&offset);
        }
        btreeblk_end(handle->bhandle);
        offset = _endian_decode(offset);

        if (locked) {
            filemgr_mutex_unlock(handle->file);
        }
    }

    if ((wr == FDB_RESULT_SUCCESS && offset != BLK_NOT_FOUND) ||
         br != BTREE_RESULT_FAIL) {
        bool alloc_key, alloc_meta, alloc_body;
        if (!handle->kvs) { // single KVS mode
            _doc.key = doc->key;
            _doc.length.keylen = doc->keylen;
            alloc_key = doc->key ? false : true;
        } else {
            _doc.key = NULL;
            alloc_key = true;
        }
        alloc_meta = doc->meta ? false : true;
        _doc.meta = doc->meta;
        alloc_body = doc->body ? false : true;
        _doc.body = doc->body;

        if (wr == FDB_RESULT_SUCCESS && doc->deleted) {
            atomic_cas_uint8_t(&handle->handle_busy, 1, 0);
            return FDB_RESULT_KEY_NOT_FOUND;
        }

        _offset = docio_read_doc(dhandle, offset, &_doc, true);
        if (_offset == offset) {
            atomic_cas_uint8_t(&handle->handle_busy, 1, 0);
            return FDB_RESULT_KEY_NOT_FOUND;
        }

        if (_doc.length.flag & DOCIO_DELETED) {
            atomic_cas_uint8_t(&handle->handle_busy, 1, 0);
            free_docio_object(&_doc, alloc_key, alloc_meta, alloc_body);
            return FDB_RESULT_KEY_NOT_FOUND;
        }

        doc->seqnum = _doc.seqnum;
        if (handle->kvs) {
            int size_chunk = handle->config.chunksize;
            doc->keylen = _doc.length.keylen - size_chunk;
            if (doc->key) { // doc->key is given by user
                memcpy(doc->key, (uint8_t*)_doc.key + size_chunk, doc->keylen);
                free_docio_object(&_doc, 1, 0, 0);
            } else {
                doc->key = _doc.key;
                memmove(doc->key, (uint8_t*)doc->key + size_chunk, doc->keylen);
            }
        } else {
            doc->keylen = _doc.length.keylen;
            doc->key = _doc.key;
        }
        doc->metalen = _doc.length.metalen;
        doc->bodylen = _doc.length.bodylen;
        doc->meta = _doc.meta;
        doc->body = _doc.body;
        doc->deleted = _doc.length.flag & DOCIO_DELETED;
        doc->size_ondisk = _fdb_get_docsize(_doc.length);
        doc->offset = offset;

        atomic_cas_uint8_t(&handle->handle_busy, 1, 0);
        LATENCY_STAT_END(handle->file, FDB_LATENCY_GETS);
        return FDB_RESULT_SUCCESS;
    }

    atomic_cas_uint8_t(&handle->handle_busy, 1, 0);
    return FDB_RESULT_KEY_NOT_FOUND;
}

// search document metadata using sequence number
LIBFDB_API
fdb_status fdb_get_metaonly_byseq(fdb_kvs_handle *handle, fdb_doc *doc)
{
    uint64_t offset;
    struct docio_object _doc;
    struct docio_handle *dhandle;
    struct filemgr *wal_file = NULL;
    fdb_status wr;
    btree_result br = BTREE_RESULT_FAIL;
    fdb_seqnum_t _seqnum;
    fdb_txn *txn = handle->fhandle->root->txn;

    if (!handle || !doc || doc->seqnum == SEQNUM_NOT_USED) {
        return FDB_RESULT_INVALID_ARGS;
    }

    // Sequence trees are a must for byseq operations
    if (handle->config.seqtree_opt != FDB_SEQTREE_USE) {
        return FDB_RESULT_INVALID_CONFIG;
    }

    if (!atomic_cas_uint8_t(&handle->handle_busy, 0, 1)) {
        return FDB_RESULT_HANDLE_BUSY;
    }

    if (!handle->shandle) {
        fdb_check_file_reopen(handle, NULL);

        wal_file = handle->file;
        dhandle = handle->dhandle;

        if (!txn) {
            txn = &wal_file->global_txn;
        }
        // prevent searching by key in WAL if 'doc' is not empty
        size_t key_len = doc->keylen;
        doc->keylen = 0;
        if (handle->kvs) {
            wr = wal_find_kv_id(txn, wal_file, handle->kvs->id, doc, &offset);
        } else {
            wr = wal_find(txn, wal_file, doc, &offset);
        }
        doc->keylen = key_len;
        fdb_sync_db_header(handle);
    } else {
        wr = snap_find(handle->shandle, doc, &offset);
        dhandle = handle->dhandle;
    }

    atomic_incr_uint64_t(&handle->op_stats->num_gets);

    if (wr == FDB_RESULT_KEY_NOT_FOUND) {
        bool locked = _fdb_sync_dirty_root(handle);

        _seqnum = _endian_encode(doc->seqnum);
        if (handle->kvs) {
            int size_id, size_seq;
            uint8_t *kv_seqnum;
            hbtrie_result hr;
            fdb_kvs_id_t _kv_id;

            _kv_id = _endian_encode(handle->kvs->id);
            size_id = sizeof(fdb_kvs_id_t);
            size_seq = sizeof(fdb_seqnum_t);
            kv_seqnum = alca(uint8_t, size_id + size_seq);
            memcpy(kv_seqnum, &_kv_id, size_id);
            memcpy(kv_seqnum + size_id, &_seqnum, size_seq);
            hr = hbtrie_find(handle->seqtrie, (void *)kv_seqnum,
                             size_id + size_seq, (void *)&offset);
            br = (hr == HBTRIE_RESULT_SUCCESS)?(BTREE_RESULT_SUCCESS):(br);
        } else {
            br = btree_find(handle->seqtree, (void *)&_seqnum, (void *)&offset);
        }
        btreeblk_end(handle->bhandle);
        offset = _endian_decode(offset);

        if (locked) {
            filemgr_mutex_unlock(handle->file);
        }
    }

    if ((wr == FDB_RESULT_SUCCESS && offset != BLK_NOT_FOUND) ||
         br != BTREE_RESULT_FAIL) {
        bool alloc_key, alloc_meta;
        if (!handle->kvs) { // single KVS mode
            _doc.key = doc->key;
            _doc.length.keylen = doc->keylen;
            alloc_key = doc->key ? false : true;
        } else {
            _doc.key = NULL;
            alloc_key = true;
        }
        _doc.meta = doc->meta;
        alloc_meta = doc->meta ? false : true;
        _doc.body = doc->body;

        uint64_t body_offset = docio_read_doc_key_meta(dhandle, offset, &_doc,
                                                       true);
        if (body_offset == offset) {
            atomic_cas_uint8_t(&handle->handle_busy, 1, 0);
            return FDB_RESULT_KEY_NOT_FOUND;
        }
        if (doc->seqnum != _doc.seqnum) {
            free_docio_object(&_doc, alloc_key, alloc_meta, false);
            atomic_cas_uint8_t(&handle->handle_busy, 1, 0);
            return FDB_RESULT_KEY_NOT_FOUND;
        }

        if (handle->kvs) {
            int size_chunk = handle->config.chunksize;
            doc->keylen = _doc.length.keylen - size_chunk;
            if (doc->key) { // doc->key is given by user
                memcpy(doc->key, (uint8_t*)_doc.key + size_chunk, doc->keylen);
                free_docio_object(&_doc, 1, 0, 0);
            } else {
                doc->key = _doc.key;
                memmove(doc->key, (uint8_t*)doc->key + size_chunk, doc->keylen);
            }
        } else {
            doc->keylen = _doc.length.keylen;
            doc->key = _doc.key;
        }
        doc->metalen = _doc.length.metalen;
        doc->bodylen = _doc.length.bodylen;
        doc->meta = _doc.meta;
        doc->body = _doc.body;
        doc->deleted = _doc.length.flag & DOCIO_DELETED;
        doc->size_ondisk = _fdb_get_docsize(_doc.length);
        doc->offset = offset;

        atomic_cas_uint8_t(&handle->handle_busy, 1, 0);
        return FDB_RESULT_SUCCESS;
    }

    atomic_cas_uint8_t(&handle->handle_busy, 1, 0);
    return FDB_RESULT_KEY_NOT_FOUND;
}

static uint8_t equal_docs(fdb_doc *doc, struct docio_object *_doc) {
    uint8_t rv = 1;
    // Compare a seq num if seq tree is enabled.
    if (doc->seqnum != SEQNUM_NOT_USED) {
        if (doc->seqnum != _doc->seqnum) {
            free(_doc->key);
            free(_doc->meta);
            free(_doc->body);
            _doc->key = _doc->meta = _doc->body = NULL;
            rv = 0;
        }
    } else { // Compare key and metadata
        if ((doc->key && memcmp(doc->key, _doc->key, doc->keylen)) ||
            (doc->meta && memcmp(doc->meta, _doc->meta, doc->metalen))) {
            free(_doc->key);
            free(_doc->meta);
            free(_doc->body);
            _doc->key = _doc->meta = _doc->body = NULL;
            rv = 0;
        }
    }
    return rv;
}

INLINE void _remove_kv_id(fdb_kvs_handle *handle, struct docio_object *doc)
{
    size_t size_chunk = handle->config.chunksize;
    doc->length.keylen -= size_chunk;
    memmove(doc->key, (uint8_t*)doc->key + size_chunk, doc->length.keylen);
}

// Retrieve a doc's metadata and body with a given doc offset in the database file.
LIBFDB_API
fdb_status fdb_get_byoffset(fdb_kvs_handle *handle, fdb_doc *doc)
{
    uint64_t offset = doc->offset;
    struct docio_object _doc;

    if (!offset || offset == BLK_NOT_FOUND) {
        return FDB_RESULT_INVALID_ARGS;
    }

    if (!atomic_cas_uint8_t(&handle->handle_busy, 0, 1)) {
        return FDB_RESULT_HANDLE_BUSY;
    }

    atomic_incr_uint64_t(&handle->op_stats->num_gets);
    memset(&_doc, 0, sizeof(struct docio_object));

    uint64_t _offset = docio_read_doc(handle->dhandle, offset, &_doc, true);
    if (_offset == offset) {
        atomic_cas_uint8_t(&handle->handle_busy, 1, 0);
        return FDB_RESULT_KEY_NOT_FOUND;
    } else {
        if (handle->kvs) {
            fdb_kvs_id_t kv_id;
            buf2kvid(handle->config.chunksize, _doc.key, &kv_id);
            if (kv_id != handle->kvs->id) {
                atomic_cas_uint8_t(&handle->handle_busy, 1, 0);
                free_docio_object(&_doc, 1, 1, 1);
                return FDB_RESULT_KEY_NOT_FOUND;
            }
            _remove_kv_id(handle, &_doc);
        }
        if (!equal_docs(doc, &_doc)) {
            free_docio_object(&_doc, 1, 1, 1);
            atomic_cas_uint8_t(&handle->handle_busy, 1, 0);
            return FDB_RESULT_KEY_NOT_FOUND;
        }
    }

    doc->seqnum = _doc.seqnum;
    doc->keylen = _doc.length.keylen;
    doc->metalen = _doc.length.metalen;
    doc->bodylen = _doc.length.bodylen;
    if (doc->key) {
        free(_doc.key);
    } else {
        doc->key = _doc.key;
    }
    if (doc->meta) {
        free(_doc.meta);
    } else {
        doc->meta = _doc.meta;
    }
    if (doc->body) {
        if (_doc.length.bodylen > 0) {
            memcpy(doc->body, _doc.body, _doc.length.bodylen);
        }
        free(_doc.body);
    } else {
        doc->body = _doc.body;
    }
    doc->deleted = _doc.length.flag & DOCIO_DELETED;
    doc->size_ondisk = _fdb_get_docsize(_doc.length);
    if (handle->kvs) {
        // Since _doc.length was adjusted in _remove_kv_id(),
        // we need to compensate it.
        doc->size_ondisk += handle->config.chunksize;
    }

    if (_doc.length.flag & DOCIO_DELETED) {
        atomic_cas_uint8_t(&handle->handle_busy, 1, 0);
        return FDB_RESULT_KEY_NOT_FOUND;
    }

    atomic_cas_uint8_t(&handle->handle_busy, 1, 0);
    return FDB_RESULT_SUCCESS;
}

INLINE uint64_t _fdb_get_wal_threshold(fdb_kvs_handle *handle)
{
    return handle->config.wal_threshold;
}

LIBFDB_API
fdb_status fdb_set(fdb_kvs_handle *handle, fdb_doc *doc)
{
    uint64_t offset;
    struct docio_object _doc;
    struct filemgr *file;
    struct docio_handle *dhandle;
    struct timeval tv;
    bool txn_enabled = false;
    bool sub_handle = false;
    bool wal_flushed = false;
    bool immediate_remove = false;
    file_status_t fstatus;
    fdb_txn *txn = handle->fhandle->root->txn;
    fdb_status wr = FDB_RESULT_SUCCESS;
    LATENCY_STAT_START();

    if (handle->config.flags & FDB_OPEN_FLAG_RDONLY) {
        return fdb_log(&handle->log_callback, FDB_RESULT_RONLY_VIOLATION,
                       "Warning: SET is not allowed on the read-only DB file '%s'.",
                       handle->file->filename);
    }

    if ( doc->key == NULL || doc->keylen == 0 ||
        doc->keylen > FDB_MAX_KEYLEN ||
        (doc->metalen > 0 && doc->meta == NULL) ||
        (doc->bodylen > 0 && doc->body == NULL) ||
        (handle->kvs_config.custom_cmp &&
            doc->keylen > handle->config.blocksize - HBTRIE_HEADROOM)) {
        return FDB_RESULT_INVALID_ARGS;
    }

    if (!atomic_cas_uint8_t(&handle->handle_busy, 0, 1)) {
        return FDB_RESULT_HANDLE_BUSY;
    }

    _doc.length.keylen = doc->keylen;
    _doc.length.metalen = doc->metalen;
    _doc.length.bodylen = doc->deleted ? 0 : doc->bodylen;
    _doc.key = doc->key;
    _doc.meta = doc->meta;
    _doc.body = doc->deleted ? NULL : doc->body;

    if (handle->kvs) {
        // multi KV instance mode
        // allocate more (temporary) space for key, to store ID number
        int size_chunk = handle->config.chunksize;
        _doc.length.keylen = doc->keylen + size_chunk;
        _doc.key = alca(uint8_t, _doc.length.keylen);
        // copy ID
        kvid2buf(size_chunk, handle->kvs->id, _doc.key);
        // copy key
        memcpy((uint8_t*)_doc.key + size_chunk, doc->key, doc->keylen);

        if (handle->kvs->type == KVS_SUB) {
            sub_handle = true;
        } else {
            sub_handle = false;
        }
    }

fdb_set_start:
    fdb_check_file_reopen(handle, NULL);

    size_t throttling_delay = filemgr_get_throttling_delay(handle->file);
    if (throttling_delay) {
        usleep(throttling_delay);
    }

    filemgr_mutex_lock(handle->file);
    fdb_sync_db_header(handle);

    if (filemgr_is_rollback_on(handle->file)) {
        filemgr_mutex_unlock(handle->file);
        atomic_cas_uint8_t(&handle->handle_busy, 1, 0);
        return FDB_RESULT_FAIL_BY_ROLLBACK;
    }

    file = handle->file;
    dhandle = handle->dhandle;

    fstatus = filemgr_get_file_status(file);
    if (fstatus == FILE_REMOVED_PENDING) {
        // we must not write into this file
        // file status was changed by other thread .. start over
        filemgr_mutex_unlock(file);
        goto fdb_set_start;
    }

    if (sub_handle) {
        // multiple KV instance mode AND sub handle
        if (doc->seqnum != SEQNUM_NOT_USED &&
            doc->flags & FDB_CUSTOM_SEQNUM) { // User specified own seqnum
            doc->flags &= ~FDB_CUSTOM_SEQNUM; // clear flag for fdb_doc reuse
        } else {
            doc->seqnum = fdb_kvs_get_seqnum(file, handle->kvs->id) + 1;
        }
        if (handle->seqnum < doc->seqnum) { // keep handle's seqnum the highest
            handle->seqnum = doc->seqnum;
            fdb_kvs_set_seqnum(file, handle->kvs->id, handle->seqnum);
        }
    } else {
        // super handle OR single KV instance mode
        if (doc->seqnum != SEQNUM_NOT_USED &&
            doc->flags & FDB_CUSTOM_SEQNUM) { // User specified own seqnum
            doc->flags &= ~FDB_CUSTOM_SEQNUM; // clear flag for fdb_doc reuse
        } else {
            doc->seqnum = filemgr_get_seqnum(file) + 1;
        }
        if (handle->seqnum < doc->seqnum) { // keep handle's seqnum the highest
            handle->seqnum = doc->seqnum;
            filemgr_set_seqnum(file, handle->seqnum);
        }
    }
    _doc.seqnum = doc->seqnum;

    if (doc->deleted) {
        // set timestamp
        gettimeofday(&tv, NULL);
        _doc.timestamp = (timestamp_t)tv.tv_sec;
    } else {
        _doc.timestamp = 0;
    }

    if (txn) {
        txn_enabled = true;
    }

    offset = docio_append_doc(dhandle, &_doc, doc->deleted, txn_enabled);
    if (offset == BLK_NOT_FOUND) {
        filemgr_mutex_unlock(file);
        atomic_cas_uint8_t(&handle->handle_busy, 1, 0);
        return FDB_RESULT_WRITE_FAIL;
    }

    if (doc->deleted && !handle->config.purging_interval) {
        // immediately remove from hbtrie upon WAL flush
        immediate_remove = true;
    }

    doc->size_ondisk = _fdb_get_docsize(_doc.length);
    doc->offset = offset;
    if (!txn) {
        txn = &file->global_txn;
    }
    if (handle->kvs) {
        // multi KV instance mode
        fdb_doc kv_ins_doc = *doc;
        kv_ins_doc.key = _doc.key;
        kv_ins_doc.keylen = _doc.length.keylen;
        if (!immediate_remove) {
            wal_insert(txn, file, &kv_ins_doc, offset, WAL_INS_WRITER);
        } else {
            wal_immediate_remove(txn, file, &kv_ins_doc, offset, WAL_INS_WRITER);
        }
    } else {
        if (!immediate_remove) {
            wal_insert(txn, file, doc, offset, WAL_INS_WRITER);
        } else {
            wal_immediate_remove(txn, file, doc, offset, WAL_INS_WRITER);
        }
    }

    if (wal_get_dirty_status(file)== FDB_WAL_CLEAN) {
        wal_set_dirty_status(file, FDB_WAL_DIRTY);
    }

    if (handle->config.auto_commit &&
        wal_get_num_flushable(file) > _fdb_get_wal_threshold(handle)) {
        // we don't need dirty WAL flushing in auto commit mode
        // (_fdb_commit() is internally called at the end of this function)
        wal_flushed = true;

    } else if (handle->config.wal_flush_before_commit) {

        bid_t dirty_idtree_root = BLK_NOT_FOUND;
        bid_t dirty_seqtree_root = BLK_NOT_FOUND;

        if (!txn_enabled) {
            handle->dirty_updates = 1;
        }

        // MUST ensure that 'file' is always 'handle->file',
        // because this routine will not be executed during compaction.
        filemgr_get_dirty_root(file, &dirty_idtree_root, &dirty_seqtree_root);

        // other concurrent writer flushed WAL before commit,
        // sync root node of each tree
        if (dirty_idtree_root != BLK_NOT_FOUND) {
            handle->trie->root_bid = dirty_idtree_root;
        }
        if (handle->config.seqtree_opt == FDB_SEQTREE_USE &&
            dirty_seqtree_root != BLK_NOT_FOUND) {
            if (handle->kvs) {
                handle->seqtrie->root_bid = dirty_seqtree_root;
            } else {
                btree_init_from_bid(handle->seqtree,
                                    handle->seqtree->blk_handle,
                                    handle->seqtree->blk_ops,
                                    handle->seqtree->kv_ops,
                                    handle->seqtree->blksize,
                                    dirty_seqtree_root);
            }
        }

        if (wal_get_num_flushable(file) > _fdb_get_wal_threshold(handle)) {
            union wal_flush_items flush_items;

            // discard all cached writable blocks
            // to avoid data inconsistency with other writers
            btreeblk_discard_blocks(handle->bhandle);

            // commit only for non-transactional WAL entries
            wr = wal_commit(&file->global_txn, file, NULL, &handle->log_callback);
            if (wr != FDB_RESULT_SUCCESS) {
                filemgr_mutex_unlock(file);
                atomic_cas_uint8_t(&handle->handle_busy, 1, 0);
                return wr;
            }

            wr = wal_flush(file, (void *)handle,
                           _fdb_wal_flush_func, _fdb_wal_get_old_offset,
                           _fdb_wal_flush_seq_purge, _fdb_wal_flush_kvs_delta_stats,
                           &flush_items);
            if (wr != FDB_RESULT_SUCCESS) {
                filemgr_mutex_unlock(file);
                atomic_cas_uint8_t(&handle->handle_busy, 1, 0);
                return wr;
            }
            wal_set_dirty_status(file, FDB_WAL_PENDING);
            // it is ok to release flushed items becuase
            // these items are not actually committed yet.
            // they become visible after fdb_commit is invoked.
            wal_release_flushed_items(file, &flush_items);

            // sync new root node
            dirty_idtree_root = handle->trie->root_bid;
            if (handle->config.seqtree_opt == FDB_SEQTREE_USE) {
                if (handle->kvs) {
                    dirty_seqtree_root = handle->seqtrie->root_bid;
                } else {
                    dirty_seqtree_root = handle->seqtree->root_bid;
                }
            }
            filemgr_set_dirty_root(file,
                                   dirty_idtree_root,
                                   dirty_seqtree_root);

            wal_flushed = true;
            btreeblk_reset_subblock_info(handle->bhandle);
        }
    }

    filemgr_mutex_unlock(file);

    LATENCY_STAT_END(file, FDB_LATENCY_SETS);

    if (!doc->deleted) {
        atomic_incr_uint64_t(&handle->op_stats->num_sets);
    }

    if (wal_flushed && handle->config.auto_commit) {
        atomic_cas_uint8_t(&handle->handle_busy, 1, 0);
        return _fdb_commit(handle->fhandle->root, FDB_COMMIT_NORMAL,
                           false); // asynchronous commit only
    }
    atomic_cas_uint8_t(&handle->handle_busy, 1, 0);
    return FDB_RESULT_SUCCESS;
}

LIBFDB_API
fdb_status fdb_del(fdb_kvs_handle *handle, fdb_doc *doc)
{
    if (handle->config.flags & FDB_OPEN_FLAG_RDONLY) {
        return fdb_log(&handle->log_callback, FDB_RESULT_RONLY_VIOLATION,
                       "Warning: DEL is not allowed on the read-only DB file '%s'.",
                       handle->file->filename);
    }

    if (doc->key == NULL || doc->keylen == 0 ||
        doc->keylen > FDB_MAX_KEYLEN ||
        (handle->kvs_config.custom_cmp &&
            doc->keylen > handle->config.blocksize - HBTRIE_HEADROOM)) {
        return FDB_RESULT_INVALID_ARGS;
    }

    doc->deleted = true;
    fdb_doc _doc;
    _doc = *doc;
    _doc.bodylen = 0;
    _doc.body = NULL;

    atomic_incr_uint64_t(&handle->op_stats->num_dels);

    return fdb_set(handle, &_doc);
}

static uint64_t _fdb_export_header_flags(fdb_kvs_handle *handle)
{
    uint64_t rv = 0;
    if (handle->config.seqtree_opt == FDB_SEQTREE_USE) {
        // seq tree is used
        rv |= FDB_FLAG_SEQTREE_USE;
    }
    if (handle->fhandle->flags & FHANDLE_ROOT_INITIALIZED) {
        // the default KVS is once opened
        rv |= FDB_FLAG_ROOT_INITIALIZED;
    }
    if (handle->fhandle->flags & FHANDLE_ROOT_CUSTOM_CMP) {
        // the default KVS is based on custom key order
        rv |= FDB_FLAG_ROOT_CUSTOM_CMP;
    }
    return rv;
}

uint64_t fdb_set_file_header(fdb_kvs_handle *handle, bool inc_revnum)
{
    /*
    <ForestDB header>
    [offset]: (description)
    [     0]: BID of root node of root B+Tree of HB+Trie: 8 bytes
    [     8]: BID of root node of seq B+Tree: 8 bytes (0xFF.. if not used)
    [    16]: BID of root node of stale block B+Tree: 8 bytes (since V3)
    [    24]: # of live documents: 8 bytes
    [    32]: # of deleted documents: 8 bytes (version specific)
    [    40]: # of live B+Tree nodes: 8 bytes
    [    48]: Data size (byte): 8 bytes
    [    56]: BID of the DB header created when last WAL flush: 8 bytes
    [    64]: Offset of the document containing KV instances' info: 8 bytes
    [    72]: Header flags: 8 bytes
    [    80]: Size of newly compacted target file name : 2 bytes
    [    82]: Size of old file name before compaction :  2 bytes
    [    84]: File name of newly compacted file : x bytes
    [  84+x]: File name of old file before compcation : y bytes
    [84+x+y]: CRC32: 4 bytes
    total size (header's length): 88+x+y bytes

    Note: the list of functions that need to be modified
          if the header structure is changed:

        fdb_fetch_header() and associated callers in forestdb.cc
        ver_get_new_filename_off() in version.cc
        _fdb_redirect_header() in forestdb.cc
        filemgr_destroy_file() in filemgr.cc
        print_header() in dump_common.cc
        decode_dblock() and dblock in forestdb_hexamine.cc
        fdb_get_reusable_block() in staleblock.cc
    */

    uint8_t *buf = alca(uint8_t, handle->config.blocksize);
    uint16_t new_filename_len = 0;
    uint16_t old_filename_len = 0;
    uint16_t _edn_safe_16;
    uint32_t crc;
    uint64_t _edn_safe_64;
    size_t offset = 0;
    struct filemgr *cur_file;
    struct kvs_stat stat;

    cur_file = handle->file;

    // hb+trie or idtree root bid
    _edn_safe_64 = _endian_encode(handle->trie->root_bid);
    seq_memcpy(buf + offset, &_edn_safe_64, sizeof(handle->trie->root_bid), offset);

    if (handle->config.seqtree_opt == FDB_SEQTREE_USE) {
        // b+tree root bid
        _edn_safe_64 = _endian_encode(handle->seqtree->root_bid);
        seq_memcpy(buf + offset, &_edn_safe_64,
            sizeof(handle->seqtree->root_bid), offset);
    } else {
        memset(buf + offset, 0xff, sizeof(uint64_t));
        offset += sizeof(uint64_t);
    }

    // stale block tree root bid (V3)
    if (ver_staletree_support(handle->file->version)) {
        _edn_safe_64 = _endian_encode(handle->staletree->root_bid);
        seq_memcpy(buf + offset, &_edn_safe_64,
                   sizeof(handle->staletree->root_bid), offset);
    }

    // get stat
    _kvs_stat_get(cur_file, 0, &stat);

    // # docs
    _edn_safe_64 = _endian_encode(stat.ndocs);
    seq_memcpy(buf + offset, &_edn_safe_64, sizeof(_edn_safe_64), offset);

    // # deleted docs
    _edn_safe_64 = _endian_encode(stat.ndeletes);
    seq_memcpy(buf + offset, &_edn_safe_64, sizeof(_edn_safe_64), offset);

    // # live nodes
    _edn_safe_64 = _endian_encode(stat.nlivenodes);
    seq_memcpy(buf + offset, &_edn_safe_64,
               sizeof(_edn_safe_64), offset);
    // data size
    _edn_safe_64 = _endian_encode(stat.datasize);
    seq_memcpy(buf + offset, &_edn_safe_64, sizeof(_edn_safe_64), offset);

    // last header bid
    _edn_safe_64 = _endian_encode(handle->last_wal_flush_hdr_bid);
    seq_memcpy(buf + offset, &_edn_safe_64,
               sizeof(handle->last_wal_flush_hdr_bid), offset);
    // kv info offset
    _edn_safe_64 = _endian_encode(handle->kv_info_offset);
    seq_memcpy(buf + offset, &_edn_safe_64,
               sizeof(handle->kv_info_offset), offset);
    // header flags
    _edn_safe_64 = _fdb_export_header_flags(handle);
    _edn_safe_64 = _endian_encode(_edn_safe_64);
    seq_memcpy(buf + offset, &_edn_safe_64,
               sizeof(_edn_safe_64), offset);

    // size of newly compacted target file name
    if (handle->file->new_file) {
        new_filename_len = strlen(handle->file->new_file->filename) + 1;
    }
    _edn_safe_16 = _endian_encode(new_filename_len);
    seq_memcpy(buf + offset, &_edn_safe_16, sizeof(new_filename_len), offset);

    // size of old filename before compaction
    if (handle->file->old_filename) {
        old_filename_len = strlen(handle->file->old_filename) + 1;
    }
    _edn_safe_16 = _endian_encode(old_filename_len);
    seq_memcpy(buf + offset, &_edn_safe_16, sizeof(old_filename_len), offset);

    if (new_filename_len) {
        seq_memcpy(buf + offset, handle->file->new_file->filename,
                   new_filename_len, offset);
    }

    if (old_filename_len) {
        seq_memcpy(buf + offset, handle->file->old_filename,
                   old_filename_len, offset);
    }

    // crc32
    crc = get_checksum(buf, offset, handle->file->crc_mode);
    crc = _endian_encode(crc);
    seq_memcpy(buf + offset, &crc, sizeof(crc), offset);

    return filemgr_update_header(handle->file, buf, offset, inc_revnum);
}

static
char *_fdb_redirect_header(struct filemgr *old_file, uint8_t *buf,
                           filemgr* new_file) {
    uint16_t old_compact_filename_len; // size of existing old_filename in buf
    uint16_t new_compact_filename_len; // size of existing new_filename in buf
    uint16_t new_filename_len = strlen(new_file->filename) + 1;
    uint16_t new_filename_len_enc = _endian_encode(new_filename_len);
    uint32_t crc;
    size_t crc_offset;
    size_t new_fnamelen_off = ver_get_new_filename_off(old_file->version);
    size_t new_fname_off = new_fnamelen_off + 4;
    size_t offset = new_fnamelen_off;
    char *old_filename;
    // Read existing DB header's size of newly compacted filename
    seq_memcpy(&new_compact_filename_len, buf + offset, sizeof(uint16_t),
               offset);
    new_compact_filename_len = _endian_decode(new_compact_filename_len);

    // Read existing DB header's size of filename before its compaction
    seq_memcpy(&old_compact_filename_len, buf + offset, sizeof(uint16_t),
               offset);
    old_compact_filename_len = _endian_decode(old_compact_filename_len);

    // Update DB header's size of newly compacted filename to redirected one
    memcpy(buf + new_fnamelen_off, &new_filename_len_enc, sizeof(uint16_t));

    // Copy over existing DB header's old_filename to its new location
    old_filename = (char*)buf + offset + new_filename_len;
    if (new_compact_filename_len != new_filename_len) {
        memmove(old_filename, buf + offset + new_compact_filename_len,
                old_compact_filename_len);
    }
    // Update the DB header's new_filename to the redirected one
    memcpy(buf + new_fname_off, new_file->filename, new_filename_len);
    // Compute the DB header's new crc32 value
    crc_offset = new_fname_off + new_filename_len + old_compact_filename_len;
    crc = get_checksum(buf, crc_offset, new_file->crc_mode);
    crc = _endian_encode(crc);
    // Update the DB header's new crc32 value
    memcpy(buf + crc_offset, &crc, sizeof(crc));
    // If the DB header indicated an old_filename, return it
    return old_compact_filename_len ? old_filename : NULL;
}

static fdb_status _fdb_append_commit_mark(void *voidhandle, uint64_t offset)
{
    uint64_t marker_offset;
    fdb_kvs_handle *handle = (fdb_kvs_handle *)voidhandle;
    struct docio_handle *dhandle;

    dhandle = handle->dhandle;
    marker_offset = docio_append_commit_mark(dhandle, offset);
    if (marker_offset == BLK_NOT_FOUND) {
        return FDB_RESULT_WRITE_FAIL;
    }
    // Note: Since transaction commit marker is used only for crash recovery
    // (or WAL reconstruction), we can mark it as stale immediately. Stale regions
    // by those markers will be inserted into stale-tree at the next WAL flushing
    // commit, thus will be reclaimed when the corresponding commit header
    // becomes unreachable. After that, those commit markers becomes unnecessary
    // for both crash recovery and WAL restore.
    filemgr_mark_stale(handle->file, marker_offset, DOCIO_COMMIT_MARK_SIZE);
    return FDB_RESULT_SUCCESS;
}

LIBFDB_API
fdb_status fdb_commit(fdb_file_handle *fhandle, fdb_commit_opt_t opt)
{
    return _fdb_commit(fhandle->root, opt,
            !(fhandle->root->config.durability_opt & FDB_DRB_ASYNC));
}

fdb_status _fdb_commit(fdb_kvs_handle *handle, fdb_commit_opt_t opt, bool sync)
{
    uint64_t cur_bmp_revnum;
    fdb_txn *txn = handle->fhandle->root->txn;
    fdb_txn *earliest_txn;
    file_status_t fstatus;
    fdb_status fs = FDB_RESULT_SUCCESS;
    bool wal_flushed = false;
    bid_t dirty_idtree_root, dirty_seqtree_root;
    union wal_flush_items flush_items;
    fdb_status wr = FDB_RESULT_SUCCESS;
    LATENCY_STAT_START();

    if (handle->kvs) {
        if (handle->kvs->type == KVS_SUB) {
            // deny commit on sub handle
            return FDB_RESULT_INVALID_HANDLE;
        }
    }
    if (handle->config.flags & FDB_OPEN_FLAG_RDONLY) {
        return fdb_log(&handle->log_callback, FDB_RESULT_RONLY_VIOLATION,
                       "Warning: Commit is not allowed on the read-only DB file '%s'.",
                       handle->file->filename);
    }

fdb_commit_start:
    fdb_check_file_reopen(handle, NULL);
    filemgr_mutex_lock(handle->file);
    fdb_sync_db_header(handle);

    if (filemgr_is_rollback_on(handle->file)) {
        filemgr_mutex_unlock(handle->file);
        return FDB_RESULT_FAIL_BY_ROLLBACK;
    }

    fstatus = filemgr_get_file_status(handle->file);
    if (fstatus == FILE_REMOVED_PENDING) {
        // we must not commit this file
        // file status was changed by other thread .. start over
        filemgr_mutex_unlock(handle->file);
        goto fdb_commit_start;
    }

    fs = btreeblk_end(handle->bhandle);
    if (fs != FDB_RESULT_SUCCESS) {
        filemgr_mutex_unlock(handle->file);
        return fs;
    }

    // commit wal
    if (txn) {
        // transactional updates
        wr = wal_commit(txn, handle->file, _fdb_append_commit_mark,
                        &handle->log_callback);
        if (wr != FDB_RESULT_SUCCESS) {
            filemgr_mutex_unlock(handle->file);
            return wr;
        }
        if (wal_get_dirty_status(handle->file)== FDB_WAL_CLEAN) {
            wal_set_dirty_status(handle->file, FDB_WAL_DIRTY);
        }
    } else {
        // non-transactional updates
        wal_commit(&handle->file->global_txn, handle->file, NULL,
                   &handle->log_callback);
    }

    // sync dirty root nodes
    filemgr_get_dirty_root(handle->file, &dirty_idtree_root,
                           &dirty_seqtree_root);
    if (dirty_idtree_root != BLK_NOT_FOUND) {
        handle->trie->root_bid = dirty_idtree_root;
    }
    if (handle->config.seqtree_opt == FDB_SEQTREE_USE &&
        dirty_seqtree_root != BLK_NOT_FOUND) {
        if (handle->kvs) {
            handle->seqtrie->root_bid = dirty_seqtree_root;
        } else {
            btree_init_from_bid(handle->seqtree,
                                handle->seqtree->blk_handle,
                                handle->seqtree->blk_ops,
                                handle->seqtree->kv_ops,
                                handle->seqtree->blksize,
                                dirty_seqtree_root);
        }
    }

    if (handle->dirty_updates) {
        // discard all cached writable b+tree nodes
        // to avoid data inconsistency with other writers
        btreeblk_discard_blocks(handle->bhandle);
    }

    if (wal_get_num_flushable(handle->file) > _fdb_get_wal_threshold(handle) ||
        wal_get_dirty_status(handle->file) == FDB_WAL_PENDING ||
        opt & FDB_COMMIT_MANUAL_WAL_FLUSH) {
        // wal flush when
        // 1. wal size exceeds threshold
        // 2. wal is already flushed before commit
        //    (in this case, flush the rest of entries)
        // 3. user forces to manually flush wal

        wr = wal_flush(handle->file, (void *)handle,
                       _fdb_wal_flush_func, _fdb_wal_get_old_offset,
                       _fdb_wal_flush_seq_purge, _fdb_wal_flush_kvs_delta_stats,
                       &flush_items);
        if (wr != FDB_RESULT_SUCCESS) {
            filemgr_mutex_unlock(handle->file);
            return wr;
        }
        wal_set_dirty_status(handle->file, FDB_WAL_CLEAN);
        wal_flushed = true;
    }

    // Note: Appending KVS header must be done after flushing WAL
    //       because KVS stats info is updated during WAL flushing.
    if (handle->kvs) {
        // multi KV instance mode .. append up-to-date KV header
        handle->kv_info_offset = fdb_kvs_header_append(handle);
    }

    if (wal_flushed) {
        fdb_gather_stale_blocks(handle,
                                filemgr_get_header_revnum(handle->file)+1,
                                handle->last_hdr_bid,
                                handle->kv_info_offset,
                                filemgr_get_seqnum(handle->file),
                                NULL);
    }

    // Note: Getting header BID must be done after
    //       all other data are written into the file!!
    //       Or, header BID inconsistency will occur (it will
    //       point to wrong block).
    handle->last_hdr_bid = filemgr_alloc(handle->file, &handle->log_callback);
    cur_bmp_revnum = sb_get_bmp_revnum(handle->file);

    if (wal_get_dirty_status(handle->file) == FDB_WAL_CLEAN) {
        earliest_txn = wal_earliest_txn(handle->file,
                                        (txn)?(txn):(&handle->file->global_txn));
        if (earliest_txn) {
            filemgr_header_revnum_t last_revnum;
            last_revnum = _fdb_get_header_revnum(handle, handle->last_wal_flush_hdr_bid);
            // there exists other transaction that is not committed yet
            if (last_revnum < earliest_txn->prev_revnum) {
                handle->last_wal_flush_hdr_bid = earliest_txn->prev_hdr_bid;
            }
        } else {
            // there is no other transaction .. now WAL is empty
            handle->last_wal_flush_hdr_bid = handle->last_hdr_bid;
        }
    }

    // file header should be set after stale-block tree is updated.
    handle->cur_header_revnum = fdb_set_file_header(handle, true);

    if (txn == NULL) {
        // update global_txn's previous header BID
        handle->file->global_txn.prev_hdr_bid = handle->last_hdr_bid;
        // reset TID (this is thread-safe as filemgr_mutex is grabbed)
        handle->file->global_txn.prev_revnum = handle->cur_header_revnum;
    }

    if (handle->file->sb) {
        // sync superblock
        sb_update_header(handle);
        if (sb_check_sync_period(handle) && wal_flushed) {
            sb_decision_t decision;
            bool block_reclaimed = false;

            decision = sb_check_block_reusing(handle);
            if (decision == SBD_RECLAIM) {
                // gather reusable blocks
                btreeblk_discard_blocks(handle->bhandle);
                block_reclaimed = sb_reclaim_reusable_blocks(handle);
                if (block_reclaimed) {
                    sb_bmp_append_doc(handle);
                }
            } else if (decision == SBD_RESERVE) {
                // reserve reusable blocks
                btreeblk_discard_blocks(handle->bhandle);
                block_reclaimed = sb_reserve_next_reusable_blocks(handle);
                if (block_reclaimed) {
                    sb_rsv_append_doc(handle);
                }
            } else if (decision == SBD_SWITCH) {
                // switch reserved reusable blocks
                btreeblk_discard_blocks(handle->bhandle);
                sb_switch_reserved_blocks(handle->file);
            }
            // header should be updated one more time
            // since block reclaiming or stale block gathering changes root nodes
            // of each tree. but at this time we don't increase header revision number.
            handle->cur_header_revnum = fdb_set_file_header(handle, false);
            sb_update_header(handle);
            sb_sync_circular(handle);
            // reset allocation counter for next reclaim check
            sb_reset_num_alloc(handle);
        } else {
            // update superblock for every commit
            sb_sync_circular(handle);
        }
    }

    // file commit
    fs = filemgr_commit_bid(handle->file, handle->last_hdr_bid,
                            cur_bmp_revnum, sync, &handle->log_callback);
    if (wal_flushed) {
        wal_release_flushed_items(handle->file, &flush_items);
    }

    handle->dirty_updates = 0;
    filemgr_mutex_unlock(handle->file);

    LATENCY_STAT_END(handle->file, FDB_LATENCY_COMMITS);
    atomic_incr_uint64_t(&handle->op_stats->num_commits);
    return fs;
}

static fdb_status _fdb_commit_and_remove_pending(fdb_kvs_handle *handle,
                                           struct filemgr *old_file,
                                           struct filemgr *new_file)
{
    // Note: new_file == handle->file

    fdb_txn *earliest_txn;
    bool wal_flushed = false;
    bid_t dirty_idtree_root, dirty_seqtree_root;
    union wal_flush_items flush_items;
    fdb_status status = FDB_RESULT_SUCCESS;
    struct filemgr *very_old_file;

    btreeblk_end(handle->bhandle);

    // sync dirty root nodes
    filemgr_get_dirty_root(new_file, &dirty_idtree_root, &dirty_seqtree_root);
    if (dirty_idtree_root != BLK_NOT_FOUND) {
        handle->trie->root_bid = dirty_idtree_root;
    }
    if (handle->config.seqtree_opt == FDB_SEQTREE_USE &&
        dirty_seqtree_root != BLK_NOT_FOUND) {
        if (handle->kvs) {
            handle->seqtrie->root_bid = dirty_seqtree_root;
        } else {
            btree_init_from_bid(handle->seqtree,
                                handle->seqtree->blk_handle,
                                handle->seqtree->blk_ops,
                                handle->seqtree->kv_ops,
                                handle->seqtree->blksize,
                                dirty_seqtree_root);
        }
    }

    wal_commit(&new_file->global_txn, new_file, NULL, &handle->log_callback);
    if (wal_get_num_flushable(new_file)) {
        // flush wal if not empty
        wal_flush(new_file, (void *)handle,
                  _fdb_wal_flush_func, _fdb_wal_get_old_offset,
                  _fdb_wal_flush_seq_purge, _fdb_wal_flush_kvs_delta_stats,
                  &flush_items);
        wal_set_dirty_status(new_file, FDB_WAL_CLEAN);
        wal_flushed = true;
    } else if (wal_get_size(new_file) == 0) {
        // empty WAL
        wal_set_dirty_status(new_file, FDB_WAL_CLEAN);
    }

    // Note: Appending KVS header must be done after flushing WAL
    //       because KVS stats info is updated during WAL flushing.
    if (handle->kvs) {
        // multi KV instance mode .. append up-to-date KV header
        handle->kv_info_offset = fdb_kvs_header_append(handle);
    }

    fdb_gather_stale_blocks(handle,
                            filemgr_get_header_revnum(handle->file)+1,
                            filemgr_get_header_bid(handle->file),
                            handle->kv_info_offset,
                            filemgr_get_seqnum(handle->file),
                            NULL);
    handle->last_hdr_bid = filemgr_get_next_alloc_block(new_file);
    if (wal_get_dirty_status(new_file) == FDB_WAL_CLEAN) {
        earliest_txn = wal_earliest_txn(new_file,
                                        &new_file->global_txn);
        if (earliest_txn) {
            // there exists other transaction that is not committed yet
            if (handle->last_wal_flush_hdr_bid < earliest_txn->prev_hdr_bid) {
                handle->last_wal_flush_hdr_bid = earliest_txn->prev_hdr_bid;
            }
        } else {
            // there is no other transaction .. now WAL is empty
            handle->last_wal_flush_hdr_bid = handle->last_hdr_bid;
        }
    }

    // update global_txn's previous header BID
    new_file->global_txn.prev_hdr_bid = handle->last_hdr_bid;
    // file header should be set after stale-block tree is updated.
    handle->cur_header_revnum = fdb_set_file_header(handle, true);
    if (handle->file->sb) {
        // sync superblock
        sb_update_header(handle);
        sb_sync_circular(handle);
    }
    status = filemgr_commit(new_file,
                            !(handle->config.durability_opt & FDB_DRB_ASYNC),
                            &handle->log_callback);
    if (status != FDB_RESULT_SUCCESS) {
        filemgr_mutex_unlock(old_file);
        filemgr_mutex_unlock(new_file);
        return status;
    }

    if (wal_flushed) {
        wal_release_flushed_items(new_file, &flush_items);
    }

    compactor_switch_file(old_file, new_file, &handle->log_callback);
    do { // Find all files pointing to old_file and redirect them to new file..
        very_old_file = filemgr_search_stale_links(old_file);
        if (very_old_file) {
            filemgr_redirect_old_file(very_old_file, new_file,
                                      _fdb_redirect_header);
            filemgr_commit(very_old_file,
                           !(handle->config.durability_opt & FDB_DRB_ASYNC),
                           &handle->log_callback);
            // I/O errors here are not propogated since this is best-effort
            // Since filemgr_search_stale_links() will have opened the file
            // we must close it here to ensure decrement of ref counter
            filemgr_close(very_old_file, 1, very_old_file->filename,
                          &handle->log_callback);
        }
    } while (very_old_file);

    // Migrate the operational statistics to the new_file, because
    // from this point onward all callers will re-open new_file
    handle->op_stats = filemgr_migrate_op_stats(old_file, new_file, handle->kvs);
    fdb_assert(handle->op_stats, 0, 0);
#ifdef _LATENCY_STATS
    // Migrate latency stats from old file to new file..
    filemgr_migrate_latency_stats(old_file, new_file);
#endif // _LATENCY_STATS

    // Mark the old file as "remove_pending".
    // Note that a file deletion will be pended until there is no handle
    // referring the file.
    filemgr_remove_pending(old_file, new_file, &handle->log_callback);
    // This mutex was acquired by the caller (i.e., _fdb_compact_file()).
    filemgr_mutex_unlock(old_file);

    // After compaction is done, we don't need to maintain
    // fhandle list in superblock.
    filemgr_fhandle_remove(old_file, handle->fhandle);

    // Don't clean up the buffer cache entries for the old file.
    // They will be cleaned up later.
    filemgr_close(old_file, 0, handle->filename, &handle->log_callback);

    filemgr_mutex_unlock(new_file);

    atomic_incr_uint64_t(&handle->op_stats->num_compacts);

    if (handle->config.compaction_cb &&
        handle->config.compaction_cb_mask & FDB_CS_COMPLETE) {
        handle->config.compaction_cb(handle->fhandle, FDB_CS_COMPLETE,
                                     NULL, NULL, BLK_NOT_FOUND, BLK_NOT_FOUND,
                                     handle->config.compaction_cb_ctx);
    }
    return status;
}

INLINE int _fdb_cmp_uint64_t(const void *key1, const void *key2)
{
    uint64_t a,b;
    // must ensure that key1 and key2 are pointers to uint64_t values
    a = deref64(key1);
    b = deref64(key2);

#ifdef __BIT_CMP
    return _CMP_U64(a, b);

#else
    if (a < b) {
        return -1;
    } else if (a > b) {
        return 1;
    } else {
        return 0;
    }
#endif
}

static fdb_status _fdb_move_wal_docs(fdb_kvs_handle *handle,
                                     bid_t start_bid,
                                     bid_t stop_bid,
                                     struct filemgr *new_file,
                                     struct hbtrie *new_trie,
                                     struct btree *new_idtree,
                                     struct btree *new_seqtree,
                                     struct btree *new_staletree,
                                     struct docio_handle *new_dhandle,
                                     struct btreeblk_handle *new_bhandle)
{
    struct timeval tv;
    timestamp_t cur_timestamp;
    fdb_kvs_handle new_handle;
    uint32_t blocksize = handle->file->blocksize;
    uint64_t offset; // starting point
    uint64_t new_offset;
    uint64_t stop_offset = stop_bid * blocksize; // stopping point
    uint64_t n_moved_docs = 0;
    uint64_t filesize = filemgr_get_pos(handle->file);
    uint64_t doc_scan_limit;
    uint64_t start_bmp_revnum, stop_bmp_revnum;
    uint64_t cur_bmp_revnum = (uint64_t)-1;
    fdb_compact_decision decision;
    err_log_callback *log_callback;
    fdb_status fs = FDB_RESULT_SUCCESS;

    gettimeofday(&tv, NULL);
    cur_timestamp = tv.tv_sec;

    if (start_bid == BLK_NOT_FOUND || start_bid == stop_bid) {
        return fs;
    } else {
        offset = (start_bid + 1) * blocksize;
    }

    // TODO: Need to adapt docio_read_doc to separate false checksum errors.
    log_callback = handle->dhandle->log_callback;
    handle->dhandle->log_callback = NULL;

    start_bmp_revnum = _fdb_get_bmp_revnum(handle, start_bid);
    stop_bmp_revnum= _fdb_get_bmp_revnum(handle, stop_bid);
    cur_bmp_revnum = start_bmp_revnum;

    do {
        // The fundamental logic is same to that in WAL restore process.
        // Please refer to comments in _fdb_restore_wal().
         if (cur_bmp_revnum == stop_bmp_revnum && offset >= stop_offset) {
             break;
        }
        if (cur_bmp_revnum == stop_bmp_revnum) {
            doc_scan_limit = stop_offset;
        } else {
            doc_scan_limit = filesize;
        }

        if (!docio_check_buffer(handle->dhandle, offset / blocksize,
                                cur_bmp_revnum)) {
            // not a document block .. move to next block
        } else {
            uint64_t offset_original = offset;
            do {
                fdb_doc wal_doc;
                uint8_t deleted;
                struct docio_object doc;
                uint64_t _offset;
                memset(&doc, 0, sizeof(doc));
                _offset = docio_read_doc(handle->dhandle, offset, &doc, true);
                if (!doc.key && !(doc.length.flag & DOCIO_TXN_COMMITTED)) {
                    // No more documents in this block, break go to next block
                    free(doc.key);
                    free(doc.meta);
                    free(doc.body);
                    offset = _offset;
                    break;
                }
                // check if the doc is transactional or not, and
                // also check if the doc contains system info
                if (doc.length.flag & DOCIO_TXN_DIRTY ||
                    doc.length.flag & DOCIO_SYSTEM) {
                    // skip transactional document or system document
                    free(doc.key);
                    free(doc.meta);
                    free(doc.body);
                    offset = _offset;
                    continue;
                    // do not break.. read next doc
                }
                if (doc.length.flag & DOCIO_TXN_COMMITTED) {
                    // commit mark .. read the previously skipped doc
                    docio_read_doc(handle->dhandle, doc.doc_offset, &doc, true);
                    if (doc.key == NULL) { // doc read error
                        free(doc.meta);
                        free(doc.body);
                        offset = _offset;
                        continue;
                    }
                }

                // If a rollback was requested on this file, skip
                // any db items written past the rollback point
                if (!handle->kvs) {
                    if (doc.seqnum > handle->seqnum) {
                        free(doc.key);
                        free(doc.meta);
                        free(doc.body);
                        offset = _offset;
                        continue;
                    }
                } else {
                    // check seqnum before insert
                    fdb_kvs_id_t kv_id;
                    fdb_seqnum_t kv_seqnum;
                    buf2kvid(handle->config.chunksize, doc.key, &kv_id);

                    if (handle->config.seqtree_opt == FDB_SEQTREE_USE) {
                        kv_seqnum = fdb_kvs_get_seqnum(handle->file, kv_id);
                    } else {
                        kv_seqnum = SEQNUM_NOT_USED;
                    }
                    // Only pick up items written before any rollback
                    if (doc.seqnum > kv_seqnum) {
                        free(doc.key);
                        free(doc.meta);
                        free(doc.body);
                        offset = _offset;
                        continue;
                    }
                }
                deleted = doc.length.flag & DOCIO_DELETED;
                wal_doc.keylen = doc.length.keylen;
                wal_doc.metalen = doc.length.metalen;
                wal_doc.bodylen = doc.length.bodylen;
                wal_doc.key = doc.key;
                wal_doc.meta = doc.meta;
                wal_doc.seqnum = doc.seqnum;
                wal_doc.deleted = deleted;
                wal_doc.size_ondisk = _fdb_get_docsize(doc.length);
                // If user has specified a callback for move doc then
                // the decision on to whether or not the document is moved
                // into new file will rest completely on the return value
                // from the callback
                if (handle->config.compaction_cb &&
                    handle->config.compaction_cb_mask & FDB_CS_MOVE_DOC) {
                    size_t key_offset;
                    const char *kvs_name = _fdb_kvs_extract_name_off(handle,
                                                   wal_doc.key, &key_offset);
                    wal_doc.keylen -= key_offset;
                    wal_doc.key = (void *)((uint8_t*)wal_doc.key + key_offset);
                    decision = handle->config.compaction_cb(
                               handle->fhandle, FDB_CS_MOVE_DOC,
                               kvs_name, &wal_doc, offset, BLK_NOT_FOUND,
                               handle->config.compaction_cb_ctx);
                    wal_doc.key = (void *)((uint8_t*)wal_doc.key - key_offset);
                    wal_doc.keylen += key_offset;
                } else {
                    // compare timestamp
                    if (!deleted ||
                        (cur_timestamp < doc.timestamp +
                         handle->config.purging_interval &&
                         deleted)) {
                        // re-write the document to new file when
                        // 1. the document is not deleted
                        // 2. the document is logically deleted but
                        //    its timestamp isn't overdue
                        decision = FDB_CS_KEEP_DOC;
                    } else {
                        decision = FDB_CS_DROP_DOC;
                    }
                }
                if (decision == FDB_CS_KEEP_DOC) {
                    // Re-Write Document to new_file based on decision above
                    new_offset = docio_append_doc(new_dhandle, &doc, deleted, 0);
                    if (new_offset == BLK_NOT_FOUND) {
                        free(doc.key);
                        free(doc.meta);
                        free(doc.body);
                        return FDB_RESULT_WRITE_FAIL;
                    }
                } else {
                    new_offset = BLK_NOT_FOUND;
                }

                wal_insert(&new_file->global_txn,
                           new_file, &wal_doc, new_offset,
                           WAL_INS_COMPACT_PHASE1);

                n_moved_docs++;
                free(doc.key);
                free(doc.meta);
                free(doc.body);
                offset = _offset;
            } while (offset + sizeof(struct docio_length) < doc_scan_limit);

            // Due to non-consecutive doc blocks, offset value may decrease
            // and cause an infinite loop. To avoid this issue, we have to
            // restore the last offset value if offset value is decreased.
            if (offset < offset_original) {
                offset = offset_original;
            }
        }

        offset = ((offset / blocksize) + 1) * blocksize;
        if (ver_superblock_support(handle->file->version) &&
            offset >= filesize && cur_bmp_revnum < stop_bmp_revnum) {
            // circular scan
            offset = blocksize * handle->file->sb->config->num_sb;
            cur_bmp_revnum++;
        }
    } while(true);

    // wal flush into new file so all documents are reflected in its main index
    if (n_moved_docs) {
        union wal_flush_items flush_items;
        new_handle = *handle;
        new_handle.file = new_file;
        new_handle.trie = new_trie;
        if (handle->kvs) {
            new_handle.seqtrie = (struct hbtrie *)new_seqtree;
        } else {
            new_handle.seqtree = new_seqtree;
        }
        new_handle.staletree = new_staletree;
        new_handle.dhandle = new_dhandle;
        new_handle.bhandle = new_bhandle;

        wal_flush(new_file, (void*)&new_handle,
                  _fdb_wal_flush_func, _fdb_wal_get_old_offset,
                  _fdb_wal_flush_seq_purge, _fdb_wal_flush_kvs_delta_stats,
                  &flush_items);
        wal_set_dirty_status(new_file, FDB_WAL_PENDING);
        wal_release_flushed_items(new_file, &flush_items);
    }

    handle->dhandle->log_callback = log_callback;
    return fs;
}

static uint64_t _fdb_calculate_throttling_delay(uint64_t n_moved_docs,
                                                struct timeval tv)
{
    uint64_t elapsed_us, delay_us;
    struct timeval cur_tv, gap;

    if (n_moved_docs == 0) {
        return 0;
    }

    gettimeofday(&cur_tv, NULL);
    gap = _utime_gap(tv, cur_tv);
    elapsed_us = (uint64_t)gap.tv_sec * 1000000 + gap.tv_usec;
    // Set writer's delay = 2x of compactor's delay per doc
    // For example,
    // 1) if compactor's speed is 10,000 docs/sec,
    // 2) then the average delay per doc is 100 us.
    // 3) In this case, we set the writer sleep delay to 200 (= 2*100) us.
    // To avoid quick fluctuation of writer's delay,
    // we use the entire average speed of compactor, not an instant speed.
    delay_us = elapsed_us * 2 / n_moved_docs;
    if (delay_us > 1000) { // Limit the max delay to 1ms
        delay_us = 1000;
    }

    return delay_us;
}

INLINE void _fdb_adjust_prob(size_t cur_ratio, size_t *prob, size_t max_prob)
{
    if (cur_ratio < FDB_COMP_RATIO_MIN) {
        // writer is slower than the minimum speed
        // decrease the probability variable
        if ((*prob) >= FDB_COMP_PROB_UNIT_DEC) {
            (*prob) -= FDB_COMP_PROB_UNIT_DEC;
        } else {
            *prob = 0;
        }
    }

    if (cur_ratio > FDB_COMP_RATIO_MAX) {
        // writer is faster than the maximum speed
        if (cur_ratio > 200) {
            // writer is at least twice faster than compactor!
            // double the probability variable
            if (*prob == 0) {
                *prob = FDB_COMP_PROB_UNIT_INC;
            }
            (*prob) += (*prob);
        } else {
            // increase the probability variable
            (*prob) += FDB_COMP_PROB_UNIT_INC;
        }

        if (*prob > max_prob) {
            *prob = max_prob;
        }
    }
}

INLINE void _fdb_update_block_distance(bid_t writer_curr_bid,
                                       bid_t compactor_curr_bid,
                                       bid_t *writer_prev_bid,
                                       bid_t *compactor_prev_bid,
                                       size_t *prob,
                                       size_t max_prob)
{
    bid_t writer_bid_gap = writer_curr_bid - (*writer_prev_bid);
    bid_t compactor_bid_gap = compactor_curr_bid - (*compactor_prev_bid);

    if (compactor_bid_gap) {
        // throughput ratio of writer / compactor (percentage)
        size_t cur_ratio = writer_bid_gap*100 / compactor_bid_gap;
        // adjust probability
        _fdb_adjust_prob(cur_ratio, prob, max_prob);
    }
    *writer_prev_bid = writer_curr_bid;
    *compactor_prev_bid = compactor_curr_bid;
}

#ifdef _COW_COMPACTION
// Warning: This api assumes writer cannot access newly compacted file until
// compaction is complete. If this behavior changes to interleave writer with
// compactor in new file, this function must be modified!
static fdb_status _fdb_compact_clone_docs(fdb_kvs_handle *handle,
                                          struct filemgr *new_file,
                                          struct hbtrie *new_trie,
                                          struct btree *new_idtree,
                                          struct btree *new_seqtree,
                                          struct btree *new_staletree,
                                          struct docio_handle *new_dhandle,
                                          struct btreeblk_handle *new_bhandle,
                                          size_t *prob)
{
    uint8_t deleted;
    uint64_t offset, _offset;
    uint64_t old_offset, new_offset;
    uint64_t *offset_array;
    uint64_t src_bid, dst_bid, contiguous_bid;
    uint64_t clone_len;
    uint64_t n_moved_docs = 0;
    uint32_t blocksize;
    size_t i, c, rv;
    size_t offset_array_max;
    hbtrie_result hr;
    struct docio_object doc, *_doc;
    struct hbtrie_iterator it;
    struct timeval tv;
    fdb_doc wal_doc;
    fdb_kvs_handle new_handle;
    bid_t compactor_curr_bid, writer_curr_bid;
    bid_t compactor_prev_bid, writer_prev_bid;
    bool locked = false;

    timestamp_t cur_timestamp;
    fdb_status fs = FDB_RESULT_SUCCESS;
    blocksize = handle->file->config->blocksize;

    compactor_prev_bid = 0;
    writer_prev_bid = filemgr_get_pos(handle->file) /
                      handle->file->config->blocksize;

    // Init AIO buffer, callback, event instances.
    struct async_io_handle *aio_handle_ptr = NULL;
    struct async_io_handle aio_handle;
    aio_handle.queue_depth = ASYNC_IO_QUEUE_DEPTH;
    aio_handle.block_size = handle->file->config->blocksize;
    aio_handle.fd = handle->file->fd;
    if (handle->file->ops->aio_init(&aio_handle) == FDB_RESULT_SUCCESS) {
        aio_handle_ptr = &aio_handle;
    }
    if (handle->config.compaction_cb &&
        handle->config.compaction_cb_mask & FDB_CS_BEGIN) {
        handle->config.compaction_cb(handle->fhandle, FDB_CS_BEGIN, NULL, NULL,
                                     0, 0, handle->config.compaction_cb_ctx);
    }

    gettimeofday(&tv, NULL);
    cur_timestamp = tv.tv_sec;

    new_handle = *handle;
    new_handle.file = new_file;
    new_handle.trie = new_trie;
    if (handle->kvs) {
        new_handle.seqtrie = (struct hbtrie *)new_seqtree;
    } else {
        new_handle.seqtree = new_seqtree;
    }
    new_handle.staletree = new_staletree;
    new_handle.dhandle = new_dhandle;
    new_handle.bhandle = new_bhandle;

    _doc = (struct docio_object *)
        calloc(FDB_COMP_BATCHSIZE, sizeof(struct docio_object));
    offset_array_max = FDB_COMP_BATCHSIZE / sizeof(uint64_t);
    offset_array = (uint64_t*)malloc(sizeof(uint64_t) * offset_array_max);

    c = old_offset = new_offset = 0;

    hr = hbtrie_iterator_init(handle->trie, &it, NULL, 0);

    while( hr != HBTRIE_RESULT_FAIL ) {

        hr = hbtrie_next_value_only(&it, (void*)&offset);
        fs = btreeblk_end(handle->bhandle);
        if (fs != FDB_RESULT_SUCCESS) {
            free(_doc);
            hbtrie_iterator_free(&it);
            free(offset_array);
            return fs;
        }
        offset = _endian_decode(offset);

        if ( hr != HBTRIE_RESULT_FAIL ) {
            // add to offset array
            offset_array[c] = offset;
            c++;
        }

        // if array exceeds the threshold, OR
        // there's no next item (hr == HBTRIE_RESULT_FAIL),
        // sort and move the documents in the array
        if (c >= offset_array_max ||
            (c > 0 && hr == HBTRIE_RESULT_FAIL)) {
            // quick sort
            qsort(offset_array, c, sizeof(uint64_t), _fdb_cmp_uint64_t);

            size_t num_batch_reads =
            docio_batch_read_docs(handle->dhandle, &offset_array[0],
                    _doc, c, FDB_COMP_MOVE_UNIT,
                    (size_t) (-1), // We are not reading the value portion
                    aio_handle_ptr, true);
            if (num_batch_reads == (size_t) -1 || num_batch_reads != c) {
                fs = FDB_RESULT_COMPACTION_FAIL;
                break;
            }
            src_bid = offset_array[0] / blocksize;
            contiguous_bid = src_bid;
            clone_len = 0;
            docio_reset(new_dhandle);
            dst_bid = filemgr_get_pos(new_file) / blocksize;
            if (filemgr_get_pos(new_file) % blocksize) {
                dst_bid = dst_bid + 1; // adjust to start of next block
            } // else This means destination file position is already
              // at a block boundary, no need to adjust to next block start

            // 1) read all document key, meta in offset_array, and
            // 2) flush WAL periodically
            for (i = 0; i < c; ++i) {
                uint64_t _bid;
                fdb_compact_decision decision;
                doc = _doc[i];
                // === read docs from the old file ===
                offset = offset_array[i];
                _bid = offset / blocksize;
                _offset = offset + _fdb_get_docsize(doc.length);
                deleted = doc.length.flag & DOCIO_DELETED;
                wal_doc.keylen = doc.length.keylen;
                wal_doc.metalen = doc.length.metalen;
                wal_doc.bodylen = doc.length.bodylen;
                wal_doc.key = doc.key;
                wal_doc.seqnum = doc.seqnum;

                wal_doc.deleted = deleted;
                // If user has specified a callback for move doc then
                // the decision on to whether or not the document is moved
                // into new file will rest completely on the return value
                // from the callback
                if (handle->config.compaction_cb &&
                    handle->config.compaction_cb_mask & FDB_CS_MOVE_DOC) {
                    size_t key_offset;
                    const char *kvs_name = _fdb_kvs_extract_name_off(handle,
                                                     wal_doc.key, &key_offset);
                    wal_doc.keylen -= key_offset;
                    wal_doc.key = (void *)((uint8_t*)wal_doc.key + key_offset);
                    decision = handle->config.compaction_cb(
                               handle->fhandle, FDB_CS_MOVE_DOC,
                               kvs_name, &wal_doc, _offset, BLK_NOT_FOUND,
                               handle->config.compaction_cb_ctx);
                    wal_doc.key = (void *)((uint8_t*)wal_doc.key - key_offset);
                    wal_doc.keylen += key_offset;
                } else {
                    // compare timestamp
                    // 1. the document is not deleted
                    // 2. the document is logically deleted but
                    //    its timestamp isn't overdue
                    if (!deleted ||
                        (cur_timestamp < doc.timestamp +
                                     handle->config.purging_interval &&
                        deleted)) {
                        decision = FDB_CS_KEEP_DOC;
                    } else {
                        decision = FDB_CS_DROP_DOC;
                    }
                }

                if (decision == FDB_CS_KEEP_DOC) { // Clone doc to new file
                    if (_bid - contiguous_bid > 1) {
                        // Non-Contiguous copy range hit!
                        // Perform file range copy over existing blocks
                        fs = filemgr_copy_file_range(handle->file, new_file,
                                                     src_bid, dst_bid,
                                                     1 + clone_len);
                        if (fs != FDB_RESULT_SUCCESS) {
                            break;
                        }

                        dst_bid = dst_bid + 1 + clone_len;

                        // reset start block id, contiguous bid & len for
                        src_bid = _bid; // .. next round of file range copy
                        contiguous_bid = src_bid;
                        clone_len = 0;
                    } else if (_bid == contiguous_bid + 1) {
                        contiguous_bid = _bid; // next contiguous block
                        ++clone_len;
                    } // else the document is from the same block as previous

                    // compute document's offset in new_file
                    new_offset = (dst_bid + clone_len) * blocksize
                               + (offset % blocksize);

                    // Adjust contiguous_bid & clone_len if doc spans 1+ blocks
                    if (_offset / blocksize > offset / blocksize) {
                        uint64_t more_blocks = _offset / blocksize
                                             - offset / blocksize;
                        contiguous_bid = _offset / blocksize;
                        clone_len += more_blocks;
                    }

                    old_offset = offset;
                    wal_doc.offset = new_offset;
                    wal_doc.size_ondisk= _fdb_get_docsize(doc.length);

                    wal_insert(&new_file->global_txn,
                               new_file, &wal_doc, new_offset,
                               WAL_INS_COMPACT_PHASE1);
                    ++n_moved_docs;
                } // if non-deleted or deleted-but-not-yet-purged doc check
                free(doc.key);
                free(doc.meta);

                if (handle->config.compaction_cb &&
                    handle->config.compaction_cb_mask & FDB_CS_BATCH_MOVE) {
                    handle->config.compaction_cb(handle->fhandle,
                                                 FDB_CS_BATCH_MOVE, NULL, NULL,
                                                 old_offset, new_offset,
                                                 handle->config.compaction_cb_ctx);
                }
            } // repeat until no more offset in the offset_array

            // copy out the last set of contiguous blocks
            fs = filemgr_copy_file_range(handle->file, new_file, src_bid,
                                         dst_bid, 1 + clone_len);
            if (fs != FDB_RESULT_SUCCESS) {
                break;
            }
            // === flush WAL entries by compactor ===
            if (wal_get_num_flushable(new_file) > 0) {
                uint64_t delay_us = _fdb_calculate_throttling_delay(n_moved_docs, tv);
                // We intentionally try to slow down the normal writer if
                // the compactor can't catch up with the writer. This is a
                // short-term approach and we plan to address this issue without
                // sacrificing the writer's performance soon.
                rv = (size_t)random(100);
                if (rv < *prob) {
                    // Set the sleep time for the normal writer
                    // according to the current speed of compactor
                    filemgr_set_throttling_delay(handle->file, delay_us);
                    locked = true;
                } else {
                    locked = false;
                }
                union wal_flush_items flush_items;
                wal_flush_by_compactor(new_file, (void*)&new_handle,
                                       _fdb_wal_flush_func,
                                       _fdb_wal_get_old_offset,
                                       _fdb_wal_flush_seq_purge,
                                       _fdb_wal_flush_kvs_delta_stats,
                                       &flush_items);
                wal_set_dirty_status(new_file, FDB_WAL_PENDING);
                wal_release_flushed_items(new_file, &flush_items);
                if (locked) {
                    filemgr_set_throttling_delay(handle->file, 0);
                }

                if (handle->config.compaction_cb &&
                    handle->config.compaction_cb_mask & FDB_CS_FLUSH_WAL) {
                    handle->config.compaction_cb(handle->fhandle,
                                                 FDB_CS_FLUSH_WAL, NULL, NULL,
                                                 old_offset, new_offset,
                                                 handle->config.compaction_cb_ctx);
                }
            }

            writer_curr_bid = filemgr_get_pos(handle->file) /
                              handle->file->config->blocksize;
            compactor_curr_bid = filemgr_get_pos(new_file) /
                                 new_file->config->blocksize;
            _fdb_update_block_distance(writer_curr_bid, compactor_curr_bid,
                    &writer_prev_bid, &compactor_prev_bid,
                    prob, handle->config.max_writer_lock_prob);

            // If the rollback operation is issued, abort the compaction task.
            if (filemgr_is_rollback_on(handle->file)) {
                fs = FDB_RESULT_FAIL_BY_ROLLBACK;
                break;
            }
            if (filemgr_is_compaction_cancellation_requested(handle->file)) {
                fs = FDB_RESULT_COMPACTION_CANCELLATION;
                break;
            }

            c = 0; // reset offset_array
        } // end of if (array exceeded threshold || no more docs in trie)
        if (fs == FDB_RESULT_FAIL_BY_ROLLBACK ||
            fs == FDB_RESULT_COMPACTION_CANCELLATION) {
            break;
        }
    } // end of while (hr != HBTRIE_RESULT_FAIL) (forall items in trie)

    free(_doc);
    hbtrie_iterator_free(&it);
    free(offset_array);

    if (handle->config.compaction_cb &&
        handle->config.compaction_cb_mask & FDB_CS_END) {
        handle->config.compaction_cb(handle->fhandle, FDB_CS_END,
                                     NULL, NULL, old_offset, new_offset,
                                     handle->config.compaction_cb_ctx);
    }

    return fs;
}
#endif // _COW_COMPACTION

static fdb_status _fdb_compact_move_docs(fdb_kvs_handle *handle,
                                         struct filemgr *new_file,
                                         struct hbtrie *new_trie,
                                         struct btree *new_idtree,
                                         struct btree *new_seqtree,
                                         struct btree *new_staletree,
                                         struct docio_handle *new_dhandle,
                                         struct btreeblk_handle *new_bhandle,
                                         size_t *prob,
                                         bool clone_docs)
{
    uint8_t deleted;
    uint64_t window_size;
    uint64_t offset;
    uint64_t old_offset, new_offset;
    uint64_t *offset_array;
    uint64_t n_moved_docs;
    size_t i, j, c, count, rv;
    size_t offset_array_max;
    hbtrie_result hr;
    struct docio_object *doc;
    struct hbtrie_iterator it;
    struct timeval tv;
    fdb_doc wal_doc;
    fdb_kvs_handle new_handle;
    timestamp_t cur_timestamp;
    fdb_status fs = FDB_RESULT_SUCCESS;

    bid_t compactor_curr_bid, writer_curr_bid;
    bid_t compactor_prev_bid, writer_prev_bid;
    bool locked = false;

#ifdef _COW_COMPACTION
    if (clone_docs) {
        if (!filemgr_is_cow_supported(handle->file, new_file)) {
            return FDB_RESULT_COMPACTION_FAIL;
        }
        return _fdb_compact_clone_docs(handle, new_file, new_trie,
                                       new_idtree, new_seqtree, new_staletree, new_dhandle,
                                       new_bhandle, prob);
    }
#else
    (void)clone_docs;
#endif // _COW_COMPACTION

    compactor_prev_bid = 0;
    writer_prev_bid = filemgr_get_pos(handle->file) /
                      handle->file->config->blocksize;

    // Init AIO buffer, callback, event instances.
    struct async_io_handle *aio_handle_ptr = NULL;
    struct async_io_handle aio_handle;
    aio_handle.queue_depth = ASYNC_IO_QUEUE_DEPTH;
    aio_handle.block_size = handle->file->config->blocksize;
    aio_handle.fd = handle->file->fd;
    if (handle->file->ops->aio_init(&aio_handle) == FDB_RESULT_SUCCESS) {
        aio_handle_ptr = &aio_handle;
    }

    if (handle->config.compaction_cb &&
        handle->config.compaction_cb_mask & FDB_CS_BEGIN) {
        handle->config.compaction_cb(handle->fhandle, FDB_CS_BEGIN, NULL, NULL,
                                     0, 0, handle->config.compaction_cb_ctx);
    }

    gettimeofday(&tv, NULL);
    cur_timestamp = tv.tv_sec;

    new_handle = *handle;
    new_handle.file = new_file;
    new_handle.trie = new_trie;
    if (handle->kvs) {
        new_handle.seqtrie = (struct hbtrie *)new_seqtree;
    } else {
        new_handle.seqtree = new_seqtree;
    }
    new_handle.staletree = new_staletree;
    new_handle.dhandle = new_dhandle;
    new_handle.bhandle = new_bhandle;

    // 1/10 of the block cache size or
    // if block cache is disabled, set to the minimum size
    window_size = handle->config.buffercache_size / 10;
    if (window_size < FDB_COMP_BUF_MINSIZE) {
        window_size = FDB_COMP_BUF_MINSIZE;
    } else if (window_size > FDB_COMP_BUF_MAXSIZE) {
        window_size = FDB_COMP_BUF_MAXSIZE;
    }
    fdb_file_info db_info;
    if (fdb_get_file_info(handle->fhandle, &db_info) == FDB_RESULT_SUCCESS) {
        uint64_t doc_offset_mem = db_info.doc_count * sizeof(uint64_t);
        if (doc_offset_mem < window_size) {
            // Offsets of all the docs can be sorted with the buffer whose size
            // is num_of_docs * sizeof(offset)
            window_size = doc_offset_mem < FDB_COMP_BUF_MINSIZE ?
                FDB_COMP_BUF_MINSIZE : doc_offset_mem;
        }
    }

    offset_array_max = window_size / sizeof(uint64_t);
    offset_array = (uint64_t*)malloc(sizeof(uint64_t) * offset_array_max);

    doc = (struct docio_object *)
        calloc(FDB_COMP_BATCHSIZE, sizeof(struct docio_object));
    c = count = n_moved_docs = old_offset = new_offset = 0;

    hr = hbtrie_iterator_init(handle->trie, &it, NULL, 0);

    while( hr != HBTRIE_RESULT_FAIL ) {

        hr = hbtrie_next_value_only(&it, (void*)&offset);
        fs = btreeblk_end(handle->bhandle);
        if (fs != FDB_RESULT_SUCCESS) {
            break;
        }
        offset = _endian_decode(offset);

        if ( hr != HBTRIE_RESULT_FAIL ) {
            // add to offset array
            offset_array[c] = offset;
            c++;
        }

        // if array exceeds the threshold, OR
        // there's no next item (hr == HBTRIE_RESULT_FAIL),
        // sort and move the documents in the array
        if (c > offset_array_max ||
            (c > 0 && hr == HBTRIE_RESULT_FAIL)) {
            // Sort offsets to minimize random accesses.
            qsort(offset_array, c, sizeof(uint64_t), _fdb_cmp_uint64_t);

            // 1) read all documents in offset_array, and
            // 2) move them into the new file.
            // 3) flush WAL periodically
            i = 0;
            do {
                // === read docs from the old file ===
                size_t start_idx = i;
                size_t num_batch_reads =
                    docio_batch_read_docs(handle->dhandle, &offset_array[start_idx],
                                          doc, c - start_idx,
                                          FDB_COMP_MOVE_UNIT, FDB_COMP_BATCHSIZE,
                                          aio_handle_ptr, false);
                if (num_batch_reads == (size_t) -1) {
                    fs = FDB_RESULT_COMPACTION_FAIL;
                    break;
                }
                i += num_batch_reads;

                // === write docs into the new file ===
                for (j=0; j<num_batch_reads; ++j) {
                    fdb_compact_decision decision;
                    if (!doc[j].key) {
                        continue;
                    }

                    deleted = doc[j].length.flag & DOCIO_DELETED;
                    wal_doc.keylen = doc[j].length.keylen;
                    wal_doc.metalen = doc[j].length.metalen;
                    wal_doc.bodylen = doc[j].length.bodylen;
                    wal_doc.key = doc[j].key;
                    wal_doc.seqnum = doc[j].seqnum;
                    wal_doc.deleted = deleted;
                    wal_doc.meta = doc[j].meta;

                    // If user has specified a callback for move doc then
                    // the decision on to whether or not the document is moved
                    // into new file will rest completely on the return value
                    // from the callback
                    if (handle->config.compaction_cb &&
                        handle->config.compaction_cb_mask & FDB_CS_MOVE_DOC) {
                        size_t key_offset;
                        const char *kvs_name = _fdb_kvs_extract_name_off(handle,
                                                      wal_doc.key, &key_offset);
                        wal_doc.keylen -= key_offset;
                        wal_doc.key = (void *)((uint8_t*)wal_doc.key
                                    + key_offset);
                        decision = handle->config.compaction_cb(
                                   handle->fhandle, FDB_CS_MOVE_DOC,
                                   kvs_name, &wal_doc,
                                   offset_array[start_idx + j],
                                   BLK_NOT_FOUND,
                                   handle->config.compaction_cb_ctx);
                        wal_doc.key = (void *)((uint8_t*)wal_doc.key
                                    - key_offset);
                        wal_doc.keylen += key_offset;
                    } else {
                        // compare timestamp
                        if (!deleted ||
                            (cur_timestamp < doc[j].timestamp +
                             handle->config.purging_interval &&
                             deleted)) {
                            // re-write the document to new file when
                            // 1. the document is not deleted
                            // 2. the document is logically deleted but
                            //    its timestamp isn't overdue
                            decision = FDB_CS_KEEP_DOC;
                        } else {
                            decision = FDB_CS_DROP_DOC;
                        }
                    }
                    if (decision == FDB_CS_KEEP_DOC) {
                        new_offset = docio_append_doc(new_dhandle, &doc[j],
                                                      deleted, 0);
                        old_offset = offset_array[start_idx + j];

                        wal_doc.body = doc[j].body;
                        wal_doc.size_ondisk= _fdb_get_docsize(doc[j].length);
                        wal_doc.offset = new_offset;

                        wal_insert(&new_file->global_txn,
                                   new_file, &wal_doc, new_offset,
                                   WAL_INS_COMPACT_PHASE1);
                        n_moved_docs++;
                    }
                    free(doc[j].key);
                    free(doc[j].meta);
                    free(doc[j].body);
                    doc[j].key = doc[j].meta = doc[j].body = NULL;
                }

                if (handle->config.compaction_cb &&
                    handle->config.compaction_cb_mask & FDB_CS_BATCH_MOVE) {
                    handle->config.compaction_cb(handle->fhandle,
                                                 FDB_CS_BATCH_MOVE, NULL, NULL,
                                                 old_offset, new_offset,
                                                 handle->config.compaction_cb_ctx);
                }

                // === flush WAL entries by compactor ===
                if (wal_get_num_flushable(new_file) > 0) {
                    uint64_t delay_us;
                    delay_us = _fdb_calculate_throttling_delay(n_moved_docs, tv);

                    // Note that we don't need to grab a lock on the new file
                    // during the compaction because the new file is only accessed
                    // by the compactor.
                    // However, we intentionally try to slow down the normal writer if
                    // the compactor can't catch up with the writer. This is a
                    // short-term approach and we plan to address this issue without
                    // sacrificing the writer's performance soon.
                    rv = (size_t)random(100);
                    if (rv < *prob) {
                        // Set the sleep time for the normal writer
                        // according to the current speed of compactor
                        filemgr_set_throttling_delay(handle->file, delay_us);
                        locked = true;
                    } else {
                        locked = false;
                    }
                    union wal_flush_items flush_items;
                    wal_flush_by_compactor(new_file, (void*)&new_handle,
                                           _fdb_wal_flush_func,
                                           _fdb_wal_get_old_offset,
                                           _fdb_wal_flush_seq_purge,
                                           _fdb_wal_flush_kvs_delta_stats,
                                           &flush_items);
                    wal_set_dirty_status(new_file, FDB_WAL_PENDING);
                    wal_release_flushed_items(new_file, &flush_items);
                    if (locked) {
                        filemgr_set_throttling_delay(handle->file, 0);
                    }

                    if (handle->config.compaction_cb &&
                        handle->config.compaction_cb_mask & FDB_CS_FLUSH_WAL) {
                        handle->config.compaction_cb(handle->fhandle,
                                                     FDB_CS_FLUSH_WAL, NULL, NULL,
                                                     old_offset, new_offset,
                                                     handle->config.compaction_cb_ctx);
                    }
                }

                writer_curr_bid = filemgr_get_pos(handle->file) /
                                  handle->file->config->blocksize;
                compactor_curr_bid = filemgr_get_pos(new_file) / new_file->config->blocksize;
                _fdb_update_block_distance(writer_curr_bid, compactor_curr_bid,
                                           &writer_prev_bid, &compactor_prev_bid,
                                           prob, handle->config.max_writer_lock_prob);

                // If the rollback operation is issued, abort the compaction task.
                if (filemgr_is_rollback_on(handle->file)) {
                    fs = FDB_RESULT_FAIL_BY_ROLLBACK;
                    break;
                }
                if (filemgr_is_compaction_cancellation_requested(handle->file)) {
                    fs = FDB_RESULT_COMPACTION_CANCELLATION;
                    break;
                }

                // repeat until no more offset in the offset_array
            } while (i < c);
            // reset offset_array
            c = 0;
        }
        if (fs != FDB_RESULT_SUCCESS) {
            break;
        }
    }

    hbtrie_iterator_free(&it);
    free(offset_array);
    free(doc);

    if (aio_handle_ptr) {
        handle->file->ops->aio_destroy(aio_handle_ptr);
    }

    if (handle->config.compaction_cb &&
        handle->config.compaction_cb_mask & FDB_CS_END) {
        handle->config.compaction_cb(handle->fhandle, FDB_CS_END,
                                     NULL, NULL, old_offset, new_offset,
                                     handle->config.compaction_cb_ctx);
    }

    return fs;
}

static fdb_status
_fdb_compact_move_docs_upto_marker(fdb_kvs_handle *rhandle,
                                   struct filemgr *new_file,
                                   struct hbtrie *new_trie,
                                   struct btree *new_idtree,
                                   struct btree *new_seqtree,
                                   struct btree *new_staletree,
                                   struct docio_handle *new_dhandle,
                                   struct btreeblk_handle *new_bhandle,
                                   bid_t marker_bid,
                                   bid_t last_hdr_bid,
                                   fdb_seqnum_t last_seq,
                                   size_t *prob,
                                   bool clone_docs)
{
    size_t header_len = 0;
    bid_t old_hdr_bid = 0;
    fdb_seqnum_t old_seqnum = 0;
    filemgr_header_revnum_t old_hdr_revnum = 0;
    filemgr_header_revnum_t last_hdr_revnum, marker_revnum;
    filemgr_header_revnum_t last_wal_hdr_revnum;
    err_log_callback *log_callback = &rhandle->log_callback;
    uint64_t version;
    fdb_status fs;

    last_hdr_revnum = _fdb_get_header_revnum(rhandle, last_hdr_bid);
    marker_revnum = _fdb_get_header_revnum(rhandle, marker_bid);
    if (last_hdr_revnum == 0 || marker_revnum == 0){
        return FDB_RESULT_NO_DB_INSTANCE;
    }

    if (last_hdr_revnum < marker_revnum) {
        return FDB_RESULT_NO_DB_INSTANCE;
    } else if (last_hdr_bid == marker_bid) {
        // compact_upto marker is the same as the latest commit header.
        return _fdb_compact_move_docs(rhandle, new_file, new_trie, new_idtree,
                                      new_seqtree, new_staletree, new_dhandle, new_bhandle,
                                      prob, clone_docs);
    }

    old_hdr_bid = last_hdr_bid;
    old_seqnum = last_seq;
    old_hdr_revnum = last_hdr_revnum;

    while (marker_revnum < old_hdr_revnum) {
        old_hdr_bid = filemgr_fetch_prev_header(rhandle->file,
                                                old_hdr_bid, NULL, &header_len,
                                                &old_seqnum, &old_hdr_revnum, NULL, &version,
                                                NULL, log_callback);
        if (!header_len) { // LCOV_EXCL_START
            return FDB_RESULT_READ_FAIL;
        } // LCOV_EXCL_STOP

        if (old_hdr_bid < marker_bid) { // gone past the snapshot marker.
            return FDB_RESULT_NO_DB_INSTANCE;
        }
    }

    // First, move all the docs belonging to a given marker to the new file.
    fdb_kvs_handle handle, new_handle;
    struct snap_handle shandle;
    struct kvs_info kvs;
    fdb_kvs_config kvs_config = rhandle->kvs_config;
    fdb_config config = rhandle->config;
    struct filemgr *file = rhandle->file;
    bid_t last_wal_hdr_bid;

    memset(&handle, 0, sizeof(fdb_kvs_handle));
    memset(&shandle, 0, sizeof(struct snap_handle));
    memset(&kvs, 0, sizeof(struct kvs_info));
    // Setup a temporary handle to look like a snapshot of the old_file
    // at the compaction marker.
    handle.last_hdr_bid = old_hdr_bid; // Fast rewind on open
    handle.max_seqnum = FDB_SNAPSHOT_INMEM; // Prevent WAL restore on open
    handle.shandle = &shandle;
    handle.fhandle = rhandle->fhandle;
    atomic_init_uint8_t(&handle.handle_busy, 0);
    if (rhandle->kvs) {
        handle.kvs = &kvs;
        _fdb_kvs_init_root(&handle, file);
    }
    handle.log_callback = *log_callback;
    handle.config = config;
    handle.kvs_config = kvs_config;
    handle.cur_header_revnum = old_hdr_revnum;

    config.flags |= FDB_OPEN_FLAG_RDONLY;
    // do not perform compaction for snapshot
    config.compaction_mode = FDB_COMPACTION_MANUAL;
    if (rhandle->kvs) {
        // sub-handle in multi KV instance mode
        fs = _fdb_kvs_open(NULL,
                           &config, &kvs_config, file,
                           file->filename,
                           NULL,
                           &handle);
    } else {
        fs = _fdb_open(&handle, file->filename, FDB_AFILENAME, &config);
    }
    if (fs != FDB_RESULT_SUCCESS) {
        return fs;
    }

    // Set the old_file's sequence numbers into the header of a new_file
    // so they gets migrated correctly for the fdb_set_file_header below.
    filemgr_set_seqnum(new_file, old_seqnum);
    if (rhandle->kvs) {
        // Copy the old file's sequence numbers to the new file.
        fdb_kvs_header_read(new_file->kv_header, handle.dhandle,
                            handle.kv_info_offset, version, true);
        // Reset KV stats as they are updated while moving documents below.
        fdb_kvs_header_reset_all_stats(new_file);
    }

    // Move all docs from old file to new file
    fs = _fdb_compact_move_docs(&handle, new_file, new_trie, new_idtree,
                                new_seqtree, new_staletree, new_dhandle, new_bhandle,
                                prob, clone_docs);
    if (fs != FDB_RESULT_SUCCESS) {
        btreeblk_end(handle.bhandle);
        _fdb_close(&handle);
        return fs;
    }

    // Restore docs between [last WAL flush header] ~ [compact_upto marker]
    last_wal_hdr_bid = handle.last_wal_flush_hdr_bid;
    if (last_wal_hdr_bid == BLK_NOT_FOUND) {
        // WAL has not been flushed ever
        last_wal_hdr_bid = 0; // scan from the beginning
        last_wal_hdr_revnum = 0;
    } else {
        last_wal_hdr_revnum = _fdb_get_header_revnum(rhandle, last_wal_hdr_bid);
    }

    if (last_wal_hdr_revnum < old_hdr_revnum) {
        fs = _fdb_move_wal_docs(&handle,
                                last_wal_hdr_bid,
                                old_hdr_bid,
                                new_file, new_trie, new_idtree,
                                new_seqtree, new_staletree,
                                new_dhandle,
                                new_bhandle);
        if (fs != FDB_RESULT_SUCCESS) {
            btreeblk_end(handle.bhandle);
            _fdb_close(&handle);
            return fs;
        }
    }

    // Note that WAL commit and flush are already done in fdb_compact_move_docs() AND
    // fdb_move_wal_docs().
    wal_set_dirty_status(new_file, FDB_WAL_CLEAN);

    // Initialize a KVS handle for a new file.
    new_handle = handle;
    new_handle.file = new_file;
    new_handle.dhandle = new_dhandle;
    new_handle.bhandle = new_bhandle;
    new_handle.trie = new_trie;
    new_handle.kv_info_offset = BLK_NOT_FOUND;

    // Note: Appending KVS header must be done after flushing WAL
    //       because KVS stats info is updated during WAL flushing.
    if (new_handle.kvs) {
        // multi KV instance mode .. append up-to-date KV header
        new_handle.kv_info_offset = fdb_kvs_header_append(&new_handle);
        new_handle.seqtrie = (struct hbtrie *) new_seqtree;
    } else {
        new_handle.seqtree = new_seqtree;
    }
    new_handle.staletree = new_staletree;

    new_handle.last_hdr_bid = filemgr_get_pos(new_handle.file) /
                              new_handle.file->blocksize;
    new_handle.last_wal_flush_hdr_bid = new_handle.last_hdr_bid; // WAL was flushed
    new_handle.cur_header_revnum = fdb_set_file_header(&new_handle, true);

    // Commit a new file.
    fs = filemgr_commit(new_handle.file, false, // asynchronous commit is ok
                        log_callback);
    btreeblk_end(handle.bhandle);
    handle.shandle = NULL;
    _fdb_close(&handle);
    return fs;
}

#ifdef _COW_COMPACTION
// WARNING: caller must ensure n_buf > 0!
INLINE void _fdb_clone_batched_delta(fdb_kvs_handle *handle,
                                     fdb_kvs_handle *new_handle,
                                     struct docio_object *doc,
                                     uint64_t *old_offset_array,
                                     uint64_t n_buf,
                                     bool got_lock,
                                     size_t *prob,
                                     uint64_t delay_us)

{
    uint64_t i;
    uint64_t doc_offset = 0;
    struct filemgr *file = handle->file;
    struct filemgr *new_file = new_handle->file;
    uint64_t src_bid, dst_bid, contiguous_bid;
    uint64_t clone_len;
    uint32_t blocksize = handle->file->blocksize;
    bool locked = false;
    fdb_status fs = FDB_RESULT_SUCCESS;

    clone_len = 0;
    src_bid = old_offset_array[0] / blocksize;
    contiguous_bid = src_bid;
    dst_bid = filemgr_get_pos(new_file) / blocksize;
    if (filemgr_get_pos(new_file) % blocksize) {
        dst_bid = dst_bid + 1; // adjust to start of next block
    } // else This means destination file position is already
     // at a block boundary, no need to adjust to next block start
    for (i=0; i<n_buf; ++i) {
        uint64_t _bid;
        fdb_doc wal_doc;
        uint64_t offset = old_offset_array[i];
        uint64_t end_offset = offset + _fdb_get_docsize(doc[i].length);
        _bid = offset / blocksize;
        if (_bid - contiguous_bid > 1) {
            // Non-Contiguous copy range hit!
            // Perform file range copy over existing blocks
            // IF AND ONLY IF block is evicted to disk!.....
            fs = filemgr_copy_file_range(file, new_file, src_bid, dst_bid,
                                         1 + clone_len);
            if (fs != FDB_RESULT_SUCCESS) {
                break;
            }
            docio_reset(new_handle->dhandle);
            dst_bid = dst_bid + 1 + clone_len;

            // reset start block id, contiguous bid & len for
            src_bid = _bid; // .. next round of file range copy
            contiguous_bid = src_bid;
            clone_len = 0;
        } else if (_bid == contiguous_bid + 1) {
            contiguous_bid = _bid; // next contiguous block
            ++clone_len;
        } // else the document is from the same block as previous

        // compute document's offset in new_file
        doc_offset = (dst_bid + clone_len) * blocksize
                   + (offset % blocksize);

        // Adjust contiguous_bid & clone_len if doc spans 1+ blocks
        if (end_offset / blocksize > offset / blocksize) {
            contiguous_bid = end_offset / blocksize;
            clone_len += end_offset / blocksize - offset / blocksize;
        }
        // insert into the new file's WAL
        wal_doc.keylen = doc[i].length.keylen;
        wal_doc.bodylen = doc[i].length.bodylen;
        wal_doc.key = doc[i].key;
        wal_doc.seqnum = doc[i].seqnum;
        wal_doc.deleted = doc[i].length.flag & DOCIO_DELETED;
        wal_doc.metalen = doc[i].length.metalen;
        wal_doc.meta = doc[i].meta;
        wal_doc.size_ondisk = _fdb_get_docsize(doc[i].length);
        if (handle->config.compaction_cb &&
            handle->config.compaction_cb_mask & FDB_CS_MOVE_DOC) {
            if (locked) {
                filemgr_mutex_unlock(handle->file);
            }
            size_t key_offset;
            const char *kvs_name = _fdb_kvs_extract_name_off(handle,
                                                 wal_doc.key, &key_offset);
            wal_doc.keylen -= key_offset;
            wal_doc.key = (void *)((uint8_t*)wal_doc.key + key_offset);
            handle->config.compaction_cb(handle->fhandle, FDB_CS_MOVE_DOC,
                                         kvs_name, &wal_doc,
                                         old_offset_array[i],
                                         doc_offset,
                                         handle->config.compaction_cb_ctx);
            wal_doc.key = (void *)((uint8_t*)wal_doc.key - key_offset);
            wal_doc.keylen += key_offset;
            if (locked) {
                filemgr_mutex_lock(handle->file);
            }
        }

        wal_insert(&new_file->global_txn, new_file, &wal_doc, doc_offset,
                   WAL_INS_COMPACT_PHASE2);

        // free
        free(doc[i].key);
        free(doc[i].meta);
        free(doc[i].body);
    }

    // copy out the last set of contiguous blocks
    fs = filemgr_copy_file_range(file, new_file, src_bid, dst_bid,
                                 1 + clone_len);
    docio_reset(new_handle->dhandle);

    if (!got_lock) {
        // We intentionally try to slow down the normal writer if
        // the compactor can't catch up with the writer. This is a
        // short-term approach and we plan to address this issue without
        // sacrificing the writer's performance soon.
        size_t rv = (size_t)random(100);
        if (rv < *prob && delay_us) {
            // Set the sleep time for the normal writer
            // according to the current speed of compactor.
            filemgr_set_throttling_delay(handle->file, delay_us);
            locked = true;
        }
    }

    // WAL flush
    union wal_flush_items flush_items;
    wal_commit(&new_handle->file->global_txn, new_handle->file, NULL, &handle->log_callback);
    wal_flush(new_handle->file, (void*)new_handle,
              _fdb_wal_flush_func,
              _fdb_wal_get_old_offset,
              _fdb_wal_flush_seq_purge, _fdb_wal_flush_kvs_delta_stats,
              &flush_items);
    wal_set_dirty_status(new_handle->file, FDB_WAL_PENDING);
    wal_release_flushed_items(new_handle->file, &flush_items);

    if (locked) {
        filemgr_set_throttling_delay(handle->file, 0);
    }

    if (handle->config.compaction_cb &&
        handle->config.compaction_cb_mask & FDB_CS_FLUSH_WAL) {
        handle->config.compaction_cb(
            handle->fhandle, FDB_CS_FLUSH_WAL, NULL, NULL,
            old_offset_array[i], doc_offset,
            handle->config.compaction_cb_ctx);
    }
}
#endif // _COW_COMPACTION

INLINE void _fdb_append_batched_delta(fdb_kvs_handle *handle,
                                      fdb_kvs_handle *new_handle,
                                      struct docio_object *doc,
                                      uint64_t *old_offset_array,
                                      uint64_t n_buf,
                                      bool clone_docs,
                                      bool got_lock,
                                      size_t *prob,
                                      uint64_t delay_us)
{
    uint64_t i;
    uint64_t doc_offset = 0;
    bool locked = false;
    struct timeval tv;
    timestamp_t cur_timestamp;

#ifdef _COW_COMPACTION
    if (clone_docs) {
        // Copy on write is a file-system / disk optimization, so it can't be
        // invoked if the blocks of the old-file have not been synced to disk
        bool flushed_blocks = (!got_lock || // blocks before committed DB header
                !handle->file->config->ncacheblock); // buffer cache is disabled
        if (flushed_blocks &&
            filemgr_is_cow_supported(handle->file, new_handle->file)) {
            _fdb_clone_batched_delta(handle, new_handle, doc,
                                     old_offset_array, n_buf, got_lock, prob, delay_us);
            return; // TODO: return status from function above
        }
    }
#endif // _COW_COMPACTION

    gettimeofday(&tv, NULL);
    cur_timestamp  = tv.tv_sec;
    for (i=0; i<n_buf; ++i) {
        bool deleted = doc[i].length.flag & DOCIO_DELETED;
        fdb_compact_decision decision;
        fdb_doc wal_doc;
        wal_doc.keylen = doc[i].length.keylen;
        wal_doc.bodylen = doc[i].length.bodylen;
        wal_doc.key = doc[i].key;
        wal_doc.seqnum = doc[i].seqnum;
        wal_doc.deleted = deleted;
        wal_doc.metalen = doc[i].length.metalen;
        wal_doc.meta = doc[i].meta;
        wal_doc.size_ondisk = _fdb_get_docsize(doc[i].length);
        if (handle->config.compaction_cb &&
            handle->config.compaction_cb_mask & FDB_CS_MOVE_DOC) {
            if (got_lock) {
                filemgr_mutex_unlock(handle->file);
            }
            size_t key_offset;
            const char *kvs_name = _fdb_kvs_extract_name_off(handle,
                                                wal_doc.key, &key_offset);
            wal_doc.keylen -= key_offset;
            wal_doc.key = (void *)((uint8_t*)wal_doc.key + key_offset);
            decision = handle->config.compaction_cb(
                       handle->fhandle, FDB_CS_MOVE_DOC,
                       kvs_name, &wal_doc, old_offset_array[i],
                       BLK_NOT_FOUND, handle->config.compaction_cb_ctx);
            wal_doc.key = (void *)((uint8_t*)wal_doc.key - key_offset);
            wal_doc.keylen += key_offset;
            if (got_lock) {
                filemgr_mutex_lock(handle->file);
            }
        } else {
            bool deleted = doc[i].length.flag & DOCIO_DELETED;
            if (!deleted || (cur_timestamp < doc[i].timestamp +
                             handle->config.purging_interval &&
                             deleted)) {
                decision = FDB_CS_KEEP_DOC;
            } else {
                decision = FDB_CS_DROP_DOC;
            }
        }
        if (decision == FDB_CS_KEEP_DOC) {
            // append into the new file
            doc_offset = docio_append_doc(new_handle->dhandle, &doc[i],
                                        doc[i].length.flag & DOCIO_DELETED, 0);
        } else {
            doc_offset = BLK_NOT_FOUND;
        }
        // insert into the new file's WAL
        wal_insert(&new_handle->file->global_txn, new_handle->file, &wal_doc,
                   doc_offset, WAL_INS_COMPACT_PHASE2);

        // free
        free(doc[i].key);
        free(doc[i].meta);
        free(doc[i].body);
    }

    if (!got_lock) {
        // We intentionally try to slow down the normal writer if
        // the compactor can't catch up with the writer. This is a
        // short-term approach and we plan to address this issue without
        // sacrificing the writer's performance soon.
        size_t rv = (size_t)random(100);
        if (rv < *prob && delay_us) {
            // Set the sleep time for the normal writer
            // according to the current speed of compactor.
            filemgr_set_throttling_delay(handle->file, delay_us);
            locked = true;
        }
    }

    // WAL flush
    union wal_flush_items flush_items;
    wal_commit(&new_handle->file->global_txn, new_handle->file, NULL, &handle->log_callback);
    wal_flush(new_handle->file, (void*)new_handle,
              _fdb_wal_flush_func,
              _fdb_wal_get_old_offset,
              _fdb_wal_flush_seq_purge, _fdb_wal_flush_kvs_delta_stats,
              &flush_items);
    wal_set_dirty_status(new_handle->file, FDB_WAL_PENDING);
    wal_release_flushed_items(new_handle->file, &flush_items);

    if (locked) {
        filemgr_set_throttling_delay(handle->file, 0);
    }

    if (handle->config.compaction_cb &&
        handle->config.compaction_cb_mask & FDB_CS_FLUSH_WAL) {
        handle->config.compaction_cb(
            handle->fhandle, FDB_CS_FLUSH_WAL, NULL, NULL,
            old_offset_array[i], doc_offset,
            handle->config.compaction_cb_ctx);
    }
}

static fdb_status _fdb_compact_move_delta(fdb_kvs_handle *handle,
                                          struct filemgr *new_file,
                                          struct hbtrie *new_trie,
                                          struct btree *new_idtree,
                                          struct btree *new_seqtree,
                                          struct btree *new_staletree,
                                          struct docio_handle *new_dhandle,
                                          struct btreeblk_handle *new_bhandle,
                                          bid_t begin_hdr, bid_t end_hdr,
                                          bool compact_upto,
                                          bool clone_docs,
                                          bool got_lock,
                                          bool last_loop,
                                          size_t *prob)
{
    uint64_t offset, offset_end;
    uint64_t old_offset, new_offset;
    uint64_t sum_docsize, n_moved_docs;
    uint64_t *old_offset_array;
    uint64_t file_limit = end_hdr * handle->file->blocksize;
    uint64_t doc_scan_limit;
    uint64_t start_bmp_revnum, stop_bmp_revnum;
    uint64_t cur_bmp_revnum = (uint64_t)-1;
    size_t c;
    size_t blocksize = handle->file->config->blocksize;
    struct timeval tv;
    struct docio_object *doc;
    fdb_kvs_handle new_handle;
    timestamp_t cur_timestamp;
    fdb_status fs = FDB_RESULT_SUCCESS;
    err_log_callback *log_callback;
    uint8_t *hdr_buf = alca(uint8_t, blocksize);

    bid_t compactor_bid_prev, writer_bid_prev;
    bid_t compactor_curr_bid, writer_curr_bid;
    bool distance_updated = false;

    if (handle->config.compaction_cb &&
        handle->config.compaction_cb_mask & FDB_CS_BEGIN) {
        handle->config.compaction_cb(handle->fhandle, FDB_CS_BEGIN, NULL, NULL,
                                     0, 0, handle->config.compaction_cb_ctx);
    }

    // Temporarily disable log callback function
    log_callback = handle->dhandle->log_callback;
    handle->dhandle->log_callback = NULL;

    gettimeofday(&tv, NULL);
    cur_timestamp = tv.tv_sec;
    (void)cur_timestamp;

    new_handle = *handle;
    new_handle.file = new_file;
    new_handle.trie = new_trie;
    if (handle->kvs) {
        new_handle.seqtrie = (struct hbtrie *)new_seqtree;
    } else {
        new_handle.seqtree = new_seqtree;
    }
    new_handle.staletree = new_staletree;
    new_handle.dhandle = new_dhandle;
    new_handle.bhandle = new_bhandle;
    new_handle.kv_info_offset = BLK_NOT_FOUND;

    doc = (struct docio_object *)
          malloc(sizeof(struct docio_object) * FDB_COMP_BATCHSIZE);
    old_offset_array = (uint64_t*)malloc(sizeof(uint64_t) * FDB_COMP_BATCHSIZE);
    c = old_offset = new_offset = sum_docsize = n_moved_docs = 0;
    offset = (begin_hdr+1) * blocksize;
    offset_end = (end_hdr+1) * blocksize;

    compactor_bid_prev = offset / blocksize;
    writer_bid_prev = (filemgr_get_pos(handle->file) / blocksize);

    start_bmp_revnum = _fdb_get_bmp_revnum(handle, begin_hdr);
    if (last_loop) {
        // if last loop, 'end_hdr' may not be a header block .. just linear scan
        stop_bmp_revnum = start_bmp_revnum;
    } else {
        stop_bmp_revnum= _fdb_get_bmp_revnum(handle, end_hdr);
    }
    cur_bmp_revnum = start_bmp_revnum;
    if (stop_bmp_revnum < start_bmp_revnum) {
        // this can happen at the end of delta moving
        // (since end_hdr is just a non-existing file position)
        stop_bmp_revnum = start_bmp_revnum;
    }

    do {
        // Please refer to comments in _fdb_restore_wal().
        // The fundamental logic is similar to that in WAL restore process,
        // but scanning is limited to 'end_hdr', not the current file size.
        if (cur_bmp_revnum == stop_bmp_revnum && offset >= offset_end) {
            break;
        }
        if (cur_bmp_revnum == stop_bmp_revnum) {
            doc_scan_limit = offset_end;
        } else {
            doc_scan_limit = file_limit;
        }

        if (!docio_check_buffer(handle->dhandle, offset / blocksize,
                                cur_bmp_revnum)) {
            if (compact_upto &&
                filemgr_is_commit_header(handle->dhandle->readbuffer, blocksize)) {
                // Read the KV sequence numbers from the old file's commit header
                // and copy them into the new_file.
                size_t len = 0;
                uint64_t version;
                fdb_seqnum_t seqnum = 0;
                uint64_t local_bmp_revnum;

                fs = filemgr_fetch_header(handle->file, offset / blocksize,
                                          hdr_buf, &len, &seqnum, NULL, NULL,
                                          &version, &local_bmp_revnum, NULL);
                if (fs != FDB_RESULT_SUCCESS) {
                    // Invalid and corrupted header.
                    free(doc);
                    free(old_offset_array);
                    fdb_log(log_callback, fs,
                            "A commit header with block id (%" _F64 ") in the file '%s'"
                            " seems corrupted!",
                            offset / blocksize, handle->file->filename);
                    return fs;
                }

                if (local_bmp_revnum != cur_bmp_revnum) {
                    // different version of superblock BMP revnum
                    // we have to ignore this header to preserve the
                    // order of header sequence.
                    goto move_delta_next_loop;
                }

                filemgr_set_seqnum(new_file, seqnum);
                if (new_handle.kvs) {
                    uint64_t dummy64;
                    uint64_t kv_info_offset;
                    char *compacted_filename = NULL;
                    fdb_fetch_header(version, hdr_buf, &dummy64, &dummy64,
                                     &dummy64, &dummy64, &dummy64, &dummy64,
                                     &dummy64, &dummy64,
                                     &kv_info_offset, &dummy64,
                                     &compacted_filename, NULL);

                    fdb_kvs_header_read(new_file->kv_header, handle->dhandle,
                                        kv_info_offset, version, true);
                }

                // As this block is a commit header, flush the WAL and write
                // the commit header to the new file.
                if (c) {
                    uint64_t delay_us;
                    delay_us = _fdb_calculate_throttling_delay(n_moved_docs, tv);
                    // TODO: return error code from this function...
                    _fdb_append_batched_delta(handle, &new_handle, doc,
                                              old_offset_array, c, clone_docs,
                                              got_lock, prob, delay_us);
                    c = sum_docsize = 0;
                }
                btreeblk_end(handle->bhandle);

                if (new_handle.kvs) {
                    // multi KV instance mode .. append up-to-date KV header
                    new_handle.kv_info_offset = fdb_kvs_header_append(&new_handle);
                }
                new_handle.last_hdr_bid = filemgr_get_next_alloc_block(new_file);
                new_handle.last_wal_flush_hdr_bid = new_handle.last_hdr_bid;
                new_handle.cur_header_revnum = fdb_set_file_header(&new_handle, true);
                fdb_gather_stale_blocks(&new_handle,
                                        filemgr_get_header_revnum(new_file)+1,
                                        new_handle.last_hdr_bid,
                                        new_handle.kv_info_offset,
                                        filemgr_get_seqnum(new_file),
                                        NULL);
                // If synchrouns commit is enabled, then disable it temporarily for each
                // commit header as synchronous commit is not required in the new file
                // during the compaction.
                fs = filemgr_commit(new_file, false, log_callback);
                if (fs != FDB_RESULT_SUCCESS) {
                    free(doc);
                    free(old_offset_array);
                    fdb_log(log_callback, fs,
                            "Commit failure on a new file '%s' during the compaction!",
                            new_file->filename);
                    return fs;
                }
            }

        } else {
            uint64_t offset_original = offset;
            do {
                uint64_t _offset;
                uint64_t doc_offset;
                memset(&doc[c], 0, sizeof(struct docio_object));
                _offset = docio_read_doc(handle->dhandle, offset, &doc[c], true);
                if (_offset == offset) { // reached unreadable doc, skip block
                    break;
                }
                if (doc[c].key || (doc[c].length.flag & DOCIO_TXN_COMMITTED)) {
                    // check if the doc is transactional or not, and
                    // also check if the doc contains system info
                    if (!(doc[c].length.flag & DOCIO_TXN_DIRTY) &&
                        !(doc[c].length.flag & DOCIO_SYSTEM)) {
                        if (doc[c].length.flag & DOCIO_TXN_COMMITTED) {
                            // commit mark .. read doc offset
                            doc_offset = doc[c].doc_offset;
                            // read the previously skipped doc
                            docio_read_doc(handle->dhandle, doc_offset, &doc[c], true);
                            if (doc[c].key == NULL) { // doc read error
                                free(doc[c].meta);
                                free(doc[c].body);
                                offset = _offset;
                                continue;
                            }
                        }

                        old_offset_array[c] = offset;
                        sum_docsize += _fdb_get_docsize(doc[c].length);
                        c++;
                        n_moved_docs++;
                        offset = _offset;

                        if (sum_docsize >= FDB_COMP_MOVE_UNIT ||
                            c >= FDB_COMP_BATCHSIZE) {

                            uint64_t delay_us;
                            delay_us = _fdb_calculate_throttling_delay(n_moved_docs, tv);

                            // append batched docs & flush WAL
                            // TODO: return error code from this function
                            _fdb_append_batched_delta(handle, &new_handle, doc,
                                                      old_offset_array, c, clone_docs,
                                                      got_lock, prob, delay_us);
                            c = sum_docsize = 0;
                            writer_curr_bid = filemgr_get_pos(handle->file) / blocksize;
                            compactor_curr_bid = offset / blocksize;
                            _fdb_update_block_distance(writer_curr_bid, compactor_curr_bid,
                                                       &writer_bid_prev, &compactor_bid_prev,
                                                       prob,
                                                       handle->config.max_writer_lock_prob);
                            distance_updated = true;
                        }

                    } else {
                        // dirty transaction doc OR system doc
                        free(doc[c].key);
                        free(doc[c].meta);
                        free(doc[c].body);
                        offset = _offset;
                        // do not break.. read next doc
                    }
                } else {
                    // not a normal document
                    free(doc[c].key);
                    free(doc[c].meta);
                    free(doc[c].body);
                    offset = _offset;
                    break;
                }
            } while (offset + sizeof(struct docio_length) < doc_scan_limit);

            // Due to non-consecutive doc blocks, offset value may decrease
            // and cause an infinite loop. To avoid this issue, we have to
            // restore the last offset value if offset value is decreased.
            if (offset < offset_original) {
                offset = offset_original;
            }
        }

move_delta_next_loop:
        offset = ((offset / blocksize) + 1) * blocksize;
        if (ver_superblock_support(handle->file->version) &&
            offset >= file_limit && cur_bmp_revnum < stop_bmp_revnum) {
            // circular scan
            offset = blocksize * handle->file->sb->config->num_sb;
            cur_bmp_revnum++;
        }
    } while (true);

    // final append & WAL flush
    if (c) {
        uint64_t delay_us;
        delay_us = _fdb_calculate_throttling_delay(n_moved_docs, tv);

        _fdb_append_batched_delta(handle, &new_handle, doc,
                                  old_offset_array, c, clone_docs, got_lock,
                                  prob, delay_us);
        if (!distance_updated) {
            // Probability was not updated since the amount of delta was not big
            // enough. We need to update it at least once for each iteration.
            writer_curr_bid = filemgr_get_pos(handle->file) / blocksize;
            compactor_curr_bid = offset / blocksize;
            _fdb_update_block_distance(writer_curr_bid, compactor_curr_bid,
                                       &writer_bid_prev, &compactor_bid_prev,
                                       prob, handle->config.max_writer_lock_prob);
        }
    }

    if (handle->config.compaction_cb &&
        handle->config.compaction_cb_mask & FDB_CS_END) {
        handle->config.compaction_cb(handle->fhandle, FDB_CS_END,
                                     NULL, NULL, old_offset, new_offset,
                                     handle->config.compaction_cb_ctx);
    }

    handle->dhandle->log_callback = log_callback;

    free(doc);
    free(old_offset_array);

    return fs;
}


static uint64_t _fdb_doc_move(void *dbhandle,
                              void *void_new_dhandle,
                              struct wal_item *item,
                              fdb_doc *fdoc)
{
    uint8_t deleted;
    uint64_t new_offset;
    fdb_kvs_handle *handle = (fdb_kvs_handle*)dbhandle;
    struct docio_handle *new_dhandle = (struct docio_handle*)void_new_dhandle;
    struct docio_object doc;

    // read doc from old file
    doc.key = NULL;
    doc.meta = NULL;
    doc.body = NULL;
    docio_read_doc(handle->dhandle, item->offset, &doc, true);

    // append doc into new file
    deleted = doc.length.flag & DOCIO_DELETED;
    fdoc->keylen = doc.length.keylen;
    fdoc->metalen = doc.length.metalen;
    fdoc->bodylen = doc.length.bodylen;
    fdoc->key = doc.key;
    fdoc->seqnum = doc.seqnum;

    fdoc->meta = doc.meta;
    fdoc->body = doc.body;
    fdoc->size_ondisk= _fdb_get_docsize(doc.length);
    fdoc->deleted = deleted;

    new_offset = docio_append_doc(new_dhandle, &doc, deleted, 1);
    return new_offset;
}

fdb_status _fdb_compact_file_checks(fdb_kvs_handle *handle,
                                    const char *new_filename)
{
    // if the file is already compacted by other thread
    if (filemgr_get_file_status(handle->file) != FILE_NORMAL ||
        handle->file->new_file) {
        // update handle and return
        fdb_check_file_reopen(handle, NULL);
        fdb_sync_db_header(handle);

        return FDB_RESULT_COMPACTION_FAIL;
    }

    if (handle->kvs) {
        if (handle->kvs->type == KVS_SUB) {
            // deny compaction on sub handle
            return FDB_RESULT_INVALID_HANDLE;
        }
    }

    // invalid filename
    if (!new_filename) {
        return FDB_RESULT_INVALID_ARGS;
    }
    if (strlen(new_filename) > FDB_MAX_FILENAME_LEN - 8) {
        return FDB_RESULT_TOO_LONG_FILENAME;
    }
    if (!strcmp(new_filename, handle->file->filename)) {
        return FDB_RESULT_INVALID_ARGS;
    }
    if (filemgr_is_rollback_on(handle->file)) {
        return FDB_RESULT_FAIL_BY_ROLLBACK;
    }

    return FDB_RESULT_SUCCESS;
}

static void _fdb_cleanup_compact_err(fdb_kvs_handle *handle,
                                     struct filemgr *new_file,
                                     bool cleanup_cache,
                                     bool got_lock,
                                     struct btreeblk_handle *new_bhandle,
                                     struct docio_handle *new_dhandle,
                                     struct hbtrie *new_trie,
                                     struct hbtrie *new_seqtrie,
                                     struct btree *new_seqtree,
                                     struct btree *new_staletree)
{
    filemgr_set_compaction_state(new_file, NULL, FILE_REMOVED_PENDING);
    if (got_lock) {
        filemgr_mutex_unlock(new_file);
    }
    filemgr_fhandle_remove(new_file, handle->fhandle);
    filemgr_close(new_file, cleanup_cache, new_file->filename,
                  &handle->log_callback);
    // Free all the resources allocated in this function.
    btreeblk_free(new_bhandle);
    free(new_bhandle);
    docio_free(new_dhandle);
    free(new_dhandle);
    hbtrie_free(new_trie);
    free(new_trie);
    if (handle->config.seqtree_opt == FDB_SEQTREE_USE) {
        if (handle->kvs) {
            hbtrie_free(new_seqtrie);
            free(new_seqtrie);
        } else {
            free(new_seqtree);
        }
    }
    free(new_staletree);
}

static fdb_status _fdb_reset(fdb_kvs_handle *handle, fdb_kvs_handle *handle_in)
{
    struct filemgr_config fconfig;
    struct btreeblk_handle *new_bhandle;
    struct docio_handle *new_dhandle;
    struct hbtrie *new_trie = NULL;
    struct btree *new_seqtree = NULL, *old_seqtree;
    struct btree *new_staletree = NULL, *old_staletree;
    struct hbtrie *new_seqtrie = NULL;
    struct kvs_stat kvs_stat;
    filemgr_open_result result;
    size_t filename_len;
    // Copy the incoming handle into the handle that is being reset
    *handle = *handle_in;

    atomic_init_uint8_t(&handle->handle_busy, 0);

    filename_len = strlen(handle->filename)+1;
    handle->filename = (char *) malloc(filename_len);
    if (!handle->filename) { // LCOV_EXCL_START
        return FDB_RESULT_ALLOC_FAIL;
    } // LCOV_EXCL_STOP
    strcpy(handle->filename, handle_in->filename);

    // create new hb-trie and related handles
    new_bhandle = (struct btreeblk_handle *)calloc(1, sizeof(struct btreeblk_handle));
    if (!new_bhandle) { // LCOV_EXCL_START
        return FDB_RESULT_ALLOC_FAIL;
    } // LCOV_EXCL_STOP
    new_bhandle->log_callback = &handle->log_callback;
    new_dhandle = (struct docio_handle *)calloc(1, sizeof(struct docio_handle));
    if (!new_dhandle) { // LCOV_EXCL_START
        free(new_bhandle);
        free(handle->filename);
        return FDB_RESULT_ALLOC_FAIL;
    } // LCOV_EXCL_STOP
    new_dhandle->log_callback = &handle->log_callback;

    docio_init(new_dhandle, handle->file,
               handle->config.compress_document_body);
    btreeblk_init(new_bhandle, handle->file, handle->file->blocksize);

    new_trie = (struct hbtrie *)malloc(sizeof(struct hbtrie));
    if (!new_trie) { // LCOV_EXCL_START
        free(handle->filename);
        free(new_bhandle);
        free(new_dhandle);
        return FDB_RESULT_ALLOC_FAIL;
    } // LCOV_EXCL_STOP
    hbtrie_init(new_trie, handle->trie->chunksize, handle->trie->valuelen,
                handle->file->blocksize, BLK_NOT_FOUND,
                (void *)new_bhandle, handle->btreeblkops,
                (void*)new_dhandle, _fdb_readkey_wrap);

    hbtrie_set_leaf_cmp(new_trie, _fdb_custom_cmp_wrap);
    // set aux
    new_trie->flag = handle->trie->flag;
    new_trie->leaf_height_limit = handle->trie->leaf_height_limit;
    new_trie->map = handle->trie->map;

    if (handle->config.seqtree_opt == FDB_SEQTREE_USE) {
        // if we use sequence number tree
        if (handle->kvs) { // multi KV instance mode
            new_seqtrie = (struct hbtrie *)calloc(1, sizeof(struct hbtrie));
            if (!new_seqtrie) { // LCOV_EXCL_START
                free(handle->filename);
                free(new_bhandle);
                free(new_dhandle);
                free(new_trie);
                return FDB_RESULT_ALLOC_FAIL;
            } // LCOV_EXCL_STOP

            hbtrie_init(new_seqtrie, sizeof(fdb_kvs_id_t),
                        OFFSET_SIZE, handle->file->blocksize, BLK_NOT_FOUND,
                        (void *)new_bhandle, handle->btreeblkops,
                        (void *)new_dhandle, _fdb_readseq_wrap);
        } else {
            // single KV instance mode .. normal B+tree
            struct btree_kv_ops *seq_kv_ops =
                (struct btree_kv_ops *)malloc(sizeof(struct btree_kv_ops));
            seq_kv_ops = btree_kv_get_kb64_vb64(seq_kv_ops);
            seq_kv_ops->cmp = _cmp_uint64_t_endian_safe;
            if (!seq_kv_ops) { // LCOV_EXCL_START
                free(handle->filename);
                free(new_bhandle);
                free(new_dhandle);
                free(new_trie);
                return FDB_RESULT_ALLOC_FAIL;
            } // LCOV_EXCL_STOP

            new_seqtree = (struct btree *)calloc(1, sizeof(struct btree));
            if (!new_seqtree) { // LCOV_EXCL_START
                free(handle->filename);
                free(new_bhandle);
                free(new_dhandle);
                free(new_trie);
                free(seq_kv_ops);
                return FDB_RESULT_ALLOC_FAIL;
            } // LCOV_EXCL_STOP

            old_seqtree = handle->seqtree;

            btree_init(new_seqtree, (void *)new_bhandle,
                       old_seqtree->blk_ops, seq_kv_ops,
                       old_seqtree->blksize, old_seqtree->ksize,
                       old_seqtree->vsize, 0x0, NULL);
        }
    }

    if (ver_staletree_support(ver_get_latest_magic())) {
        struct btree_kv_ops *stale_kv_ops =
            (struct btree_kv_ops *)malloc(sizeof(struct btree_kv_ops));
        if (!stale_kv_ops) { // LCOV_EXCL_START
            free(handle->filename);
            free(new_bhandle);
            free(new_dhandle);
            free(new_trie);
            if (!handle->kvs) {
                free(new_seqtree->kv_ops);
            }
            return FDB_RESULT_ALLOC_FAIL;
        } // LCOV_EXCL_STOP

        stale_kv_ops = btree_kv_get_kb64_vb64(stale_kv_ops);
        stale_kv_ops->cmp = _cmp_uint64_t_endian_safe;

        old_staletree = handle->staletree;
        new_staletree = (struct btree*)calloc(1, sizeof(struct btree));

        btree_init(new_staletree, (void *)new_bhandle,
                   old_staletree->blk_ops, stale_kv_ops,
                   old_staletree->blksize, old_staletree->ksize,
                   old_staletree->vsize, 0x0, NULL);
    }

    // Switch over to the empty index structs in handle
    handle->bhandle = new_bhandle;
    handle->dhandle = new_dhandle;
    handle->trie = new_trie;
    if (handle->config.seqtree_opt == FDB_SEQTREE_USE) {
        if (handle->kvs) {
            handle->seqtrie = new_seqtrie;
        } else {
            handle->seqtree = new_seqtree;
        }
    }
    handle->staletree = new_staletree;

    // set filemgr configuration
    _fdb_init_file_config(&handle->config, &fconfig);
    fconfig.options |= FILEMGR_CREATE;

    // open same file again, so the root kv handle can be redirected to this
    result = filemgr_open((char *)handle->filename,
                           handle->fileops,
                           &fconfig,
                           &handle->log_callback);
    if (result.rv != FDB_RESULT_SUCCESS) { // LCOV_EXCL_START
        filemgr_mutex_unlock(handle->file);
        free(handle->filename);
        free(new_bhandle);
        free(new_dhandle);
        free(new_trie);
        free(handle->seqtrie);
        return (fdb_status) result.rv;
    } // LCOV_EXCL_STOP

    // Shutdown WAL
    wal_shutdown(handle->file);

    // reset in-memory stats and values
    handle->seqnum = 0;
    memset(&kvs_stat, 0, sizeof(struct kvs_stat));
    _kvs_stat_set(handle->file, handle->kvs ? handle->kvs->id : 0, kvs_stat);

    return FDB_RESULT_SUCCESS;
}

fdb_status _fdb_compact_file(fdb_kvs_handle *handle,
                             struct filemgr *new_file,
                             struct btreeblk_handle *new_bhandle,
                             struct docio_handle *new_dhandle,
                             struct hbtrie *new_trie,
                             struct hbtrie *new_seqtrie,
                             struct btree *new_seqtree,
                             struct btree *new_staletree,
                             bid_t marker_bid,
                             bool clone_docs);

fdb_status fdb_compact_file(fdb_file_handle *fhandle,
                            const char *new_filename,
                            bool in_place_compaction,
                            bid_t marker_bid,
                            bool clone_docs,
                            const fdb_encryption_key *new_encryption_key)
{
    struct filemgr *new_file;
    struct filemgr_config fconfig;
    struct btreeblk_handle *new_bhandle;
    struct docio_handle *new_dhandle;
    struct hbtrie *new_trie = NULL;
    struct btree *new_seqtree = NULL, *old_seqtree;
    struct btree *new_staletree = NULL;
    struct hbtrie *new_seqtrie = NULL;
    fdb_kvs_handle *handle = fhandle->root;
    fdb_status status;
    LATENCY_STAT_START();

    // prevent update to the target file
    filemgr_mutex_lock(handle->file);

    status = _fdb_compact_file_checks(handle, new_filename);
    if (status != FDB_RESULT_SUCCESS) {
        filemgr_mutex_unlock(handle->file);
        return status;
    }

    // sync handle
    fdb_sync_db_header(handle);

    // set filemgr configuration
    _fdb_init_file_config(&handle->config, &fconfig);
    fconfig.options |= FILEMGR_CREATE;
    if (new_encryption_key) {
        fconfig.encryption_key = *new_encryption_key;
    }

    // open new file
    filemgr_open_result result = filemgr_open((char *)new_filename,
                                              handle->fileops,
                                              &fconfig,
                                              &handle->log_callback);
    if (result.rv != FDB_RESULT_SUCCESS) {
        filemgr_mutex_unlock(handle->file);
        return (fdb_status) result.rv;
    }

    new_file = result.file;
    fdb_assert(new_file, handle, fconfig.options);

    filemgr_fhandle_add(new_file, handle->fhandle);

    filemgr_set_in_place_compaction(new_file, in_place_compaction);
    // prevent update to the new_file
    filemgr_mutex_lock(new_file);

    // create new hb-trie and related handles
    new_bhandle = (struct btreeblk_handle *)calloc(1, sizeof(struct btreeblk_handle));
    new_bhandle->log_callback = &handle->log_callback;
    new_dhandle = (struct docio_handle *)calloc(1, sizeof(struct docio_handle));
    new_dhandle->log_callback = &handle->log_callback;

    docio_init(new_dhandle, new_file, handle->config.compress_document_body);
    btreeblk_init(new_bhandle, new_file, new_file->blocksize);

    new_trie = (struct hbtrie *)malloc(sizeof(struct hbtrie));
    hbtrie_init(new_trie, handle->trie->chunksize, handle->trie->valuelen,
                new_file->blocksize, BLK_NOT_FOUND,
                (void *)new_bhandle, handle->btreeblkops,
                (void*)new_dhandle, _fdb_readkey_wrap);

    hbtrie_set_leaf_cmp(new_trie, _fdb_custom_cmp_wrap);
    // set aux
    new_trie->flag = handle->trie->flag;
    new_trie->leaf_height_limit = handle->trie->leaf_height_limit;
    new_trie->map = handle->trie->map;

    if (handle->config.seqtree_opt == FDB_SEQTREE_USE) {
        // if we use sequence number tree
        if (handle->kvs) { // multi KV instance mode
            new_seqtrie = (struct hbtrie *)calloc(1, sizeof(struct hbtrie));

            hbtrie_init(new_seqtrie, sizeof(fdb_kvs_id_t),
                        OFFSET_SIZE, new_file->blocksize, BLK_NOT_FOUND,
                        (void *)new_bhandle, handle->btreeblkops,
                        (void *)new_dhandle, _fdb_readseq_wrap);
        } else {
            new_seqtree = (struct btree *)calloc(1, sizeof(struct btree));
            old_seqtree = handle->seqtree;

            btree_init(new_seqtree, (void *)new_bhandle,
                       old_seqtree->blk_ops, old_seqtree->kv_ops,
                       old_seqtree->blksize, old_seqtree->ksize,
                       old_seqtree->vsize, 0x0, NULL);
        }
    }

    // stale-block tree
    if (ver_staletree_support(ver_get_latest_magic())) {
        struct btree_kv_ops *stale_kv_ops;
        if (handle->staletree) {
            stale_kv_ops = handle->staletree->kv_ops;
        } else {
            // this happens when the old file's version is older than V3.
            stale_kv_ops = (struct btree_kv_ops*)calloc(1, sizeof(struct btree_kv_ops));
            stale_kv_ops = btree_kv_get_kb64_vb64(stale_kv_ops);
            stale_kv_ops->cmp = _cmp_uint64_t_endian_safe;
        }

        new_staletree = (struct btree*)calloc(1, sizeof(struct btree));
        btree_init(new_staletree, (void *)new_bhandle,
                   handle->btreeblkops, stale_kv_ops,
                   handle->config.blocksize, sizeof(filemgr_header_revnum_t),
                   OFFSET_SIZE, 0x0, NULL);
    } else {
        new_staletree = NULL;
    }

    status = _fdb_compact_file(handle, new_file, new_bhandle, new_dhandle,
                             new_trie, new_seqtrie, new_seqtree, new_staletree,
                             marker_bid, clone_docs);
    LATENCY_STAT_END(fhandle->root->file, FDB_LATENCY_COMPACTS);
    return status;
}

fdb_status _fdb_compact_file(fdb_kvs_handle *handle,
                             struct filemgr *new_file,
                             struct btreeblk_handle *new_bhandle,
                             struct docio_handle *new_dhandle,
                             struct hbtrie *new_trie,
                             struct hbtrie *new_seqtrie,
                             struct btree *new_seqtree,
                             struct btree *new_staletree,
                             bid_t marker_bid,
                             bool clone_docs)
{
    union wal_flush_items flush_items;
    char *old_filename = NULL;
    size_t old_filename_len = 0;
    struct filemgr *old_file;
    struct btree *new_idtree = NULL;
    bid_t dirty_idtree_root, dirty_seqtree_root;
    fdb_seqnum_t seqnum;
    uint64_t new_file_kv_info_offset = BLK_NOT_FOUND;

    // Copy the old file's seqnum to the new file.
    // (KV instances' seq numbers will be copied along with the KV header)
    // Note that the sequence numbers and KV header data in the new file will be
    // corrected in _fdb_compact_move_docs_upto_marker() for compact_upto case
    // (i.e., marker_bid != -1).
    seqnum = filemgr_get_seqnum(handle->file);
    filemgr_set_seqnum(new_file, seqnum);
    if (handle->kvs) {
        // multi KV instance mode .. copy KV header data to new file
        fdb_kvs_header_copy(handle, new_file, new_dhandle,
                            &new_file_kv_info_offset, true);
    }

    // sync dirty root nodes
    filemgr_get_dirty_root(handle->file, &dirty_idtree_root,
                           &dirty_seqtree_root);
    if (dirty_idtree_root != BLK_NOT_FOUND) {
        handle->trie->root_bid = dirty_idtree_root;
    }
    if (handle->config.seqtree_opt == FDB_SEQTREE_USE &&
        dirty_seqtree_root != BLK_NOT_FOUND) {
        if (handle->kvs) {
            handle->seqtrie->root_bid = dirty_seqtree_root;
        } else {
            btree_init_from_bid(handle->seqtree,
                                handle->seqtree->blk_handle,
                                handle->seqtree->blk_ops,
                                handle->seqtree->kv_ops,
                                handle->seqtree->blksize,
                                dirty_seqtree_root);
        }
    }

    // flush WAL and set DB header
    wal_commit(&handle->file->global_txn, handle->file, NULL, &handle->log_callback);
    wal_flush(handle->file, (void*)handle,
              _fdb_wal_flush_func, _fdb_wal_get_old_offset,
              _fdb_wal_flush_seq_purge, _fdb_wal_flush_kvs_delta_stats,
              &flush_items);
    wal_set_dirty_status(handle->file, FDB_WAL_CLEAN);

    // mark name of new file in old file
    filemgr_set_compaction_state(handle->file, new_file, FILE_COMPACT_OLD);

    // Note: Appending KVS header must be done after flushing WAL
    //       because KVS stats info is updated during WAL flushing.
    if (handle->kvs) {
        // multi KV instance mode .. append up-to-date KV header
        handle->kv_info_offset = fdb_kvs_header_append(handle);
    }

    sb_return_reusable_blocks(handle);

    // last header should be appended at the end of the file
    handle->last_hdr_bid = filemgr_get_pos(handle->file) / handle->file->blocksize;
    handle->last_wal_flush_hdr_bid = handle->last_hdr_bid;

    handle->cur_header_revnum = fdb_set_file_header(handle, true);
    btreeblk_end(handle->bhandle);

    // Commit the current file handle to record the compaction filename
    fdb_status fs = filemgr_commit(handle->file,
                    !(handle->config.durability_opt & FDB_DRB_ASYNC),
                    &handle->log_callback);
    wal_release_flushed_items(handle->file, &flush_items);
    if (fs != FDB_RESULT_SUCCESS) {
        filemgr_set_compaction_state(handle->file, NULL, FILE_NORMAL);
        filemgr_mutex_unlock(handle->file);
        filemgr_mutex_unlock(new_file);
        _fdb_cleanup_compact_err(handle, new_file, true, true, new_bhandle,
                                 new_dhandle, new_trie, new_seqtrie,
                                 new_seqtree, new_staletree);
        return fs;
    }

    if (handle->file->sb) {
        // sync superblock
        sb_update_header(handle);
        sb_sync_circular(handle);
    }

    // Mark new file as newly compacted
    filemgr_update_file_status(new_file, FILE_COMPACT_NEW, NULL);
    filemgr_mutex_unlock(handle->file);
    filemgr_mutex_unlock(new_file);

    // now compactor & another writer can be interleaved
    bid_t last_hdr = 0;
    bid_t cur_hdr = 0;
    // probability variable for blocking writer thread
    // value range: 0 (do not block writer) to 100 (always block writer)
    size_t prob = 0;

    struct btree *target_seqtree = new_seqtree;
    if (handle->kvs) {
        target_seqtree = (struct btree*)new_seqtrie;
    }

    if (marker_bid != BLK_NOT_FOUND) {
        fs = _fdb_compact_move_docs_upto_marker(handle, new_file, new_trie,
                                                new_idtree, target_seqtree, new_staletree,
                                                new_dhandle, new_bhandle,
                                                marker_bid,
                                                handle->last_hdr_bid, seqnum,
                                                &prob, clone_docs);
        cur_hdr = marker_bid; // Move delta documents from the compaction marker.
    } else {
        fs = _fdb_compact_move_docs(handle, new_file, new_trie, new_idtree,
                                    target_seqtree, new_staletree, new_dhandle,
                                    new_bhandle, &prob, clone_docs);
        cur_hdr = handle->last_hdr_bid;
    }

    if (fs != FDB_RESULT_SUCCESS) {
        filemgr_set_compaction_state(handle->file, NULL, FILE_NORMAL);

        btreeblk_reset_subblock_info(new_bhandle);
        _fdb_cleanup_compact_err(handle, new_file, true, false, new_bhandle,
                                 new_dhandle, new_trie, new_seqtrie,
                                 new_seqtree, new_staletree);

        return fs;
    }

    // The first phase is done. Now move delta documents.
    bool escape = false;
    bool compact_upto = false;
    if (marker_bid != (bid_t) -1) {
        compact_upto = true;
    }

    if (!prob) {
        // If the current probability is zero after the first phase of compaction,
        // then start the second phase of compaction with 20% of probability to allow
        // compaciton to catch up with the writer in case their throughputs remains
        // the same approximately during the entire compaction period. Otherwise,
        // the compaction might not be able to catch up and run forever.
        prob = 20;
    }

    bool file_switched = false; // bg flusher file

    // It is guaranteed that new delta updates during the compaction are not written
    // in reused blocks, but are appended at the end of file. This minimizes code
    // changes in delta migration routine.
    do {
        last_hdr = cur_hdr;
        // get up-to-date header BID of the old file
        fdb_sync_db_header(handle);
        cur_hdr = handle->last_hdr_bid;

        bool got_lock = false;
        if (last_hdr == cur_hdr) {
            // All *committed* delta documents are synchronized.
            // However, there can be uncommitted documents written after the
            // latest commit. They also should be moved.
            // But at this time, we should grab the old file's lock to prevent
            // any additional updates on it.
            // Also stop flushing blocks from old file in favor of new file
            if (!file_switched) {
                bgflusher_switch_file(handle->file, new_file,
                                      &handle->log_callback);
                file_switched = true;
            }
            filemgr_mutex_lock(handle->file);
            got_lock = true;

            bid_t last_bid;
            last_bid = (filemgr_get_pos(handle->file) / handle->config.blocksize) - 1;
            if (cur_hdr < last_bid) {
                // move delta one more time
                cur_hdr = last_bid;
                escape = true;
            } else {
                break;
            }
        }

        fs = _fdb_compact_move_delta(handle, new_file, new_trie, new_idtree,
                                     target_seqtree, new_staletree, new_dhandle,
                                     new_bhandle, last_hdr, cur_hdr,
                                     compact_upto, clone_docs, got_lock, escape, &prob);
        if (fs != FDB_RESULT_SUCCESS) {
            filemgr_set_compaction_state(handle->file, NULL, FILE_NORMAL);

            if (got_lock) {
                filemgr_mutex_unlock(handle->file);
            }
            btreeblk_reset_subblock_info(new_bhandle);
            _fdb_cleanup_compact_err(handle, new_file, true, false,
                                     new_bhandle, new_dhandle, new_trie,
                                     new_seqtrie, new_seqtree, new_staletree);

            // failure in compaction means switch back to old file
            if (file_switched) {
                bgflusher_switch_file(new_file, handle->file,
                                      &handle->log_callback);
            }

            return fs;
        }

        if (escape) {
            break;
        }
    } while (last_hdr < cur_hdr);

    filemgr_mutex_lock(new_file);

    // As we moved uncommitted non-transactional WAL items,
    // commit & flush those items. Now WAL contains only uncommitted
    // transactional items (or empty), so it is ready to migrate ongoing
    // transactions.
    wal_commit(&handle->file->global_txn, handle->file, NULL, &handle->log_callback);
    wal_flush(handle->file, (void*)handle,
              _fdb_wal_flush_func, _fdb_wal_get_old_offset,
              _fdb_wal_flush_seq_purge, _fdb_wal_flush_kvs_delta_stats,
              &flush_items);
    btreeblk_end(handle->bhandle);
    wal_release_flushed_items(handle->file, &flush_items);
    // reset last_wal_flush_hdr_bid
    handle->last_wal_flush_hdr_bid = BLK_NOT_FOUND;

    // copy old file's seqnum to new file (do this again due to delta)
    seqnum = filemgr_get_seqnum(handle->file);
    filemgr_set_seqnum(new_file, seqnum);
    if (handle->kvs) {
        // copy seqnums of non-default KV stores
        fdb_kvs_header_copy(handle, new_file, new_dhandle, NULL, false);
    }

    // migrate uncommitted transactional items to new file
    wal_txn_migration((void*)handle, (void*)new_dhandle,
                      handle->file, new_file, _fdb_doc_move);

    // final block cache flush for the old file
    filemgr_sync(handle->file, false, &handle->log_callback);

    old_file = handle->file;
    handle->file = new_file;
    handle->kv_info_offset = new_file_kv_info_offset;

    btreeblk_free(handle->bhandle);
    free(handle->bhandle);
    handle->bhandle = new_bhandle;

    docio_free(handle->dhandle);
    free(handle->dhandle);
    handle->dhandle = new_dhandle;

    hbtrie_free(handle->trie);
    free(handle->trie);
    handle->trie = new_trie;

    handle->config.encryption_key = new_file->encryption.key;

    if (handle->config.seqtree_opt == FDB_SEQTREE_USE) {
        if (handle->kvs) {
            hbtrie_free(handle->seqtrie);
            free(handle->seqtrie);
            handle->seqtrie = new_seqtrie;
        } else {
            free(handle->seqtree);
            handle->seqtree = new_seqtree;
        }
    }

    // we don't need to free 'staletree->kv_ops'
    // as it is re-used by'new_staletree'.
    free(handle->staletree);
    handle->staletree = new_staletree;

    old_filename_len = strlen(old_file->filename) + 1;
    old_filename = (char *) malloc(old_filename_len);
    strncpy(old_filename, old_file->filename, old_filename_len);
    if(filemgr_update_file_status(new_file, FILE_NORMAL, old_filename) == 0) {
        free(old_filename);
    }

    // Atomically perform
    // 1) commit new file
    // 2) set remove pending flag of the old file
    // 3) close the old file
    // Note that both old_file's lock and new_file's lock are still acquired.
    return _fdb_commit_and_remove_pending(handle, old_file, new_file);
}

static fdb_status _fdb_compact(fdb_file_handle *fhandle,
                               const char *new_filename,
                               fdb_snapshot_marker_t marker,
                               bool clone_docs,
                               const fdb_encryption_key *new_encryption_key)
{
    fdb_kvs_handle *handle = fhandle->root;
    bool in_place_compaction = false;
    char nextfile[FDB_MAX_FILENAME_LEN];
    fdb_status fs;

    if (handle->config.compaction_mode == FDB_COMPACTION_MANUAL) {
        // manual compaction
        if (!new_filename) { // In-place compaction.
            in_place_compaction = true;
            compactor_get_next_filename(handle->file->filename, nextfile);
            new_filename = nextfile;
        }
        fs = fdb_compact_file(fhandle, new_filename, in_place_compaction,
                              (bid_t)marker, clone_docs, new_encryption_key);
    } else { // auto compaction mode.
        bool ret;
        // set compaction flag
        ret = compactor_switch_compaction_flag(handle->file, true);
        if (!ret) {
            // the file is already being compacted by other thread
            return FDB_RESULT_FILE_IS_BUSY;
        }
        // get next filename
        compactor_get_next_filename(handle->file->filename, nextfile);
        fs = fdb_compact_file(fhandle, nextfile, in_place_compaction,
                              (bid_t)marker, clone_docs, new_encryption_key);
        // clear compaction flag
        ret = compactor_switch_compaction_flag(handle->file, false);
        (void)ret;
    }
    return fs;
}

LIBFDB_API
fdb_status fdb_compact(fdb_file_handle *fhandle,
                       const char *new_filename)
{
    return _fdb_compact(fhandle, new_filename, BLK_NOT_FOUND, false, NULL);
}

LIBFDB_API
fdb_status fdb_compact_with_cow(fdb_file_handle *fhandle,
                                const char *new_filename)
{
    return _fdb_compact(fhandle, new_filename, BLK_NOT_FOUND, true, NULL);
}

LIBFDB_API
fdb_status fdb_compact_upto(fdb_file_handle *fhandle,
                            const char *new_filename,
                            fdb_snapshot_marker_t marker)
{
    if (!fhandle || !fhandle->root) {
        return FDB_RESULT_INVALID_ARGS;
    }
    if (fhandle->root->config.seqtree_opt != FDB_SEQTREE_USE) {
        return FDB_RESULT_INVALID_HANDLE;
    }

    return _fdb_compact(fhandle, new_filename, marker, false, NULL);
}

LIBFDB_API
fdb_status fdb_compact_upto_with_cow(fdb_file_handle *fhandle,
                                  const char *new_filename,
                                  fdb_snapshot_marker_t marker)
{
    if (!fhandle || !fhandle->root) {
        return FDB_RESULT_INVALID_ARGS;
    }
    if (fhandle->root->config.seqtree_opt != FDB_SEQTREE_USE) {
        return FDB_RESULT_INVALID_HANDLE;
    }

    return _fdb_compact(fhandle, new_filename, marker, true, NULL);
}

LIBFDB_API
fdb_status fdb_rekey(fdb_file_handle *fhandle,
                     fdb_encryption_key new_key)
{
    return _fdb_compact(fhandle, NULL, BLK_NOT_FOUND, false, &new_key);
}

LIBFDB_API
fdb_status fdb_switch_compaction_mode(fdb_file_handle *fhandle,
                                      fdb_compaction_mode_t mode,
                                      size_t new_threshold)
{
    int ret;
    fdb_status fs;
    fdb_kvs_handle *handle = fhandle->root;
    fdb_config config;
    char vfilename[FDB_MAX_FILENAME_LEN];
    char filename[FDB_MAX_FILENAME_LEN];
    char metafile[FDB_MAX_FILENAME_LEN];

    if (!handle || new_threshold > 100) {
        return FDB_RESULT_INVALID_ARGS;
    }

    config = handle->config;
    if (handle->config.compaction_mode != mode) {
        if (filemgr_get_ref_count(handle->file) > 1) {
            // all the other handles referring this file should be closed
            return FDB_RESULT_FILE_IS_BUSY;
        }
        /* TODO: In current code, we assume that all the other handles referring
         * the same database file should be closed before calling this API and
         * any open API calls should not be made until the completion of this API.
         */

        if (handle->config.compaction_mode == FDB_COMPACTION_AUTO) {
            // 1. deregister from compactor (by calling fdb_close)
            // 2. remove [filename].meta
            // 3. rename [filename].[n] as [filename]

            // set compaction flag to avoid auto compaction.
            // we will not clear this flag again becuase this file will be
            // deregistered by calling _fdb_close().
            if (compactor_switch_compaction_flag(handle->file, true) == false) {
                return FDB_RESULT_FILE_IS_BUSY;
            }

            strcpy(vfilename, handle->filename);
            strcpy(filename, handle->file->filename);
            fs = _fdb_close(handle);
            if (fs != FDB_RESULT_SUCCESS) {
                return fs;
            }
            sprintf(metafile, "%s.meta", vfilename);
            if ((ret = remove(metafile)) < 0) {
                return FDB_RESULT_FILE_REMOVE_FAIL;
            }
            if ((ret = rename(filename, vfilename)) < 0) {
                return FDB_RESULT_FILE_RENAME_FAIL;
            }
            config.compaction_mode = FDB_COMPACTION_MANUAL;
            fs = _fdb_open(handle, vfilename, FDB_VFILENAME, &config);
            if (fs != FDB_RESULT_SUCCESS) {
                return fs;
            }
        } else if (handle->config.compaction_mode == FDB_COMPACTION_MANUAL) {
            // 1. rename [filename] as [filename].rev_num
            strcpy(vfilename, handle->file->filename);
            compactor_get_next_filename(handle->file->filename, filename);
            fs = _fdb_close(handle);
            if (fs != FDB_RESULT_SUCCESS) {
                return fs;
            }
            if ((ret = rename(vfilename, filename) < 0)) {
                return FDB_RESULT_FILE_RENAME_FAIL;
            }
            config.compaction_mode = FDB_COMPACTION_AUTO;
            config.compaction_threshold = new_threshold;
            fs = _fdb_open(handle, vfilename, FDB_VFILENAME, &config);
            if (fs != FDB_RESULT_SUCCESS) {
                return fs;
            }

        } else {
            return FDB_RESULT_INVALID_ARGS;
        }
    } else {
        if (handle->config.compaction_mode == FDB_COMPACTION_AUTO) {
            // change compaction threshold of the existing file
            compactor_change_threshold(handle->file, new_threshold);
        }
    }
    return FDB_RESULT_SUCCESS;
}

LIBFDB_API
fdb_status fdb_set_daemon_compaction_interval(fdb_file_handle *fhandle,
                                              size_t interval)
{
    if (!fhandle || !fhandle->root) {
        return FDB_RESULT_INVALID_ARGS;
    }

    fdb_kvs_handle *handle = fhandle->root;

    if (handle->config.compaction_mode == FDB_COMPACTION_AUTO) {
        return compactor_set_compaction_interval(handle->file, interval);
    } else {
        return FDB_RESULT_INVALID_CONFIG;
    }
}

LIBFDB_API
fdb_status fdb_close(fdb_file_handle *fhandle)
{
    fdb_status fs;
    if (!fhandle) {
        return FDB_RESULT_INVALID_ARGS;
    }

    if (fhandle->root->config.auto_commit &&
        filemgr_get_ref_count(fhandle->root->file) == 1) {
        // auto commit mode & the last handle referring the file
        // commit file before close
        fs = fdb_commit(fhandle, FDB_COMMIT_NORMAL);
        if (fs != FDB_RESULT_SUCCESS) {
            return fs;
        }
    }

    filemgr_fhandle_remove(fhandle->root->file, fhandle);
    fs = _fdb_close_root(fhandle->root);
    if (fs == FDB_RESULT_SUCCESS) {
        fdb_file_handle_close_all(fhandle);
        fdb_file_handle_free(fhandle);
    } else {
        filemgr_fhandle_add(fhandle->root->file, fhandle);
    }
    return fs;
}

fdb_status _fdb_close_root(fdb_kvs_handle *handle)
{
    fdb_status fs;

    if (!handle) {
        return FDB_RESULT_SUCCESS;
    }
    if (handle->kvs) {
        if (handle->kvs->type == KVS_SUB) {
            return fdb_kvs_close(handle);
        } else if (handle->kvs->type == KVS_ROOT) {
            // close all sub-handles
            fs = fdb_kvs_close_all(handle);
            if (fs != FDB_RESULT_SUCCESS) {
                return fs;
            }
        }
    }
    if (handle->txn) {
        _fdb_abort_transaction(handle);
    }

    if (handle->file->sb) {
        // sync superblock before close
        fdb_sync_db_header(handle);
        sb_update_header(handle);
        sb_sync_circular(handle);
    }

    fs = _fdb_close(handle);
    if (fs == FDB_RESULT_SUCCESS) {
        fdb_kvs_info_free(handle);
        free(handle);
    }
    return fs;
}

fdb_status _fdb_close(fdb_kvs_handle *handle)
{
    fdb_status fs;
    if (!(handle->config.flags & FDB_OPEN_FLAG_RDONLY)) {
        if (handle->config.compaction_mode == FDB_COMPACTION_AUTO) {
            // read-only file is not registered in compactor
            compactor_deregister_file(handle->file);
        }
        bgflusher_deregister_file(handle->file);
    }

    btreeblk_end(handle->bhandle);
    btreeblk_free(handle->bhandle);

    fs = filemgr_close(handle->file, handle->config.cleanup_cache_onclose,
                                  handle->filename, &handle->log_callback);
    if (fs != FDB_RESULT_SUCCESS) {
        return fs;
    }
    docio_free(handle->dhandle);
    hbtrie_free(handle->trie);
    free(handle->trie);

    if (handle->config.seqtree_opt == FDB_SEQTREE_USE) {
        if (handle->kvs) {
            // multi KV instance mode
            hbtrie_free(handle->seqtrie);
            free(handle->seqtrie);
        } else {
            free(handle->seqtree->kv_ops);
            free(handle->seqtree);
        }
    }

    if (handle->staletree) {
        free(handle->staletree->kv_ops);
        free(handle->staletree);
    }

    free(handle->bhandle);
    free(handle->dhandle);
    if (handle->shandle) {
        snap_close(handle->shandle);
    }
    if (handle->filename) {
        free(handle->filename);
        handle->filename = NULL;
    }

#ifdef _TRACE_HANDLES
    spin_lock(&open_handle_lock);
    avl_remove(&open_handles, &handle->avl_trace);
    spin_unlock(&open_handle_lock);
#endif
    return fs;
}

LIBFDB_API
fdb_status fdb_destroy(const char *fname,
                       fdb_config *fdbconfig)
{
#ifdef _MEMPOOL
    mempool_init();
#endif

    fdb_config config;
    struct filemgr_config fconfig;
    fdb_status status = FDB_RESULT_SUCCESS;
    char *filename = (char *)alca(uint8_t, FDB_MAX_FILENAME_LEN);

    if (fdbconfig) {
        if (validate_fdb_config(fdbconfig)) {
            config = *fdbconfig;
        } else {
            return FDB_RESULT_INVALID_CONFIG;
        }
    } else {
        config = get_default_config();
    }

    strncpy(filename, fname, FDB_MAX_FILENAME_LEN);

    if (!compactor_is_valid_mode(filename, &config)) {
        status = FDB_RESULT_INVALID_COMPACTION_MODE;
        return status;
    }

    _fdb_init_file_config(&config, &fconfig);

    filemgr_mutex_openlock(&fconfig);

    // Destroy file whose name is exactly matched.
    // In auto compaction mode, exact matching file name will not exist in
    // file system, so we allow failure returned by this function.
    status = filemgr_destroy_file(filename, &fconfig, NULL);
    if (status != FDB_RESULT_SUCCESS &&
        config.compaction_mode != FDB_COMPACTION_AUTO) {
        filemgr_mutex_openunlock();
        return status;
    }

    if (config.compaction_mode == FDB_COMPACTION_AUTO) {
        // Destroy all files whose prefix is matched.
        status = compactor_destroy_file(filename, &config);
        if (status != FDB_RESULT_SUCCESS) {
            filemgr_mutex_openunlock();
            return status;
        }
    }

    filemgr_mutex_openunlock();

    return status;
}

LIBFDB_API
fdb_status fdb_get_latency_stats(fdb_file_handle *fhandle,
                                 fdb_latency_stat *stat,
                                 fdb_latency_stat_type type)
{
    if (!fhandle || !stat ||!fhandle->root || type >= FDB_LATENCY_NUM_STATS) {
        return FDB_RESULT_INVALID_ARGS;
    }
    if (!fhandle->root->file) {
        return FDB_RESULT_FILE_NOT_OPEN;
    }
#ifdef _LATENCY_STATS
    filemgr_get_latency_stat(fhandle->root->file, type, stat);
#endif // _LATENCY_STATS
    return FDB_RESULT_SUCCESS;
}

LIBFDB_API
const char *fdb_latency_stat_name(fdb_latency_stat_type type)
{
    return filemgr_latency_stat_name(type);
}

// roughly estimate the space occupied db handle HANDLE
LIBFDB_API
size_t fdb_estimate_space_used(fdb_file_handle *fhandle)
{
    size_t ret = 0;
    size_t datasize;
    size_t nlivenodes;
    fdb_kvs_handle *handle = NULL;
    struct filemgr *file;

    if (!fhandle) {
        return 0;
    }

    handle = fhandle->root;

    fdb_check_file_reopen(handle, NULL);
    fdb_sync_db_header(handle);

    file = handle->file;

    datasize = _kvs_stat_get_sum(file, KVS_STAT_DATASIZE);
    nlivenodes = _kvs_stat_get_sum(file, KVS_STAT_NLIVENODES);

    ret = datasize;
    ret += nlivenodes * handle->config.blocksize;
    ret += wal_get_datasize(handle->file);

    return ret;
}

LIBFDB_API
size_t fdb_estimate_space_used_from(fdb_file_handle *fhandle,
                                    fdb_snapshot_marker_t marker)
{
    uint64_t deltasize;
    size_t ret = 0;
    fdb_kvs_handle *handle;
    struct filemgr *file;
    bid_t hdr_bid = BLK_NOT_FOUND, prev_bid;
    size_t header_len;
    uint8_t header_buf[FDB_BLOCKSIZE];
    bid_t trie_root_bid = BLK_NOT_FOUND;
    bid_t seq_root_bid = BLK_NOT_FOUND;
    bid_t stale_root_bid = BLK_NOT_FOUND;
    uint64_t ndocs;
    uint64_t ndeletes;
    uint64_t nlivenodes;
    uint64_t datasize;
    uint64_t last_wal_flush_hdr_bid;
    uint64_t kv_info_offset;
    uint64_t header_flags;
    uint64_t version;
    char *compacted_filename;
    fdb_seqnum_t seqnum;
    file_status_t fstatus;
    fdb_status status;

    if (!fhandle || !marker) {
        return 0;
    }
    handle = fhandle->root;
    if (!handle->file) {
        fdb_log(&handle->log_callback, FDB_RESULT_FILE_NOT_OPEN,
                "File not open.");
        return 0;
    }

    fdb_check_file_reopen(handle, &fstatus);
    fdb_sync_db_header(handle);

    // Start loading from current header
    file = handle->file;
    header_len = handle->file->header.size;

    // Reverse scan the file only summing up the delta.....
    while (marker <= hdr_bid) {
        if (hdr_bid == BLK_NOT_FOUND) {
            hdr_bid = handle->last_hdr_bid;
            status = filemgr_fetch_header(file, hdr_bid,
                                          header_buf, &header_len, NULL, NULL,
                                          &deltasize, &version, NULL,
                                          &handle->log_callback);
        } else {
            prev_bid = filemgr_fetch_prev_header(file, hdr_bid,
                                                 header_buf, &header_len,
                                                 &seqnum, NULL, &deltasize, &version,
                                                 NULL, &handle->log_callback);
            hdr_bid = prev_bid;
        }
        if (status != FDB_RESULT_SUCCESS) {
            fdb_log(&handle->log_callback, status,
                    "Failure to fetch DB header.");
            return 0;
        }
        if (header_len == 0) {
            status = FDB_RESULT_KV_STORE_NOT_FOUND; // can't work without header
            fdb_log(&handle->log_callback, status, "Failure to find DB header.");
            return 0;
        }

        fdb_fetch_header(version, header_buf, &trie_root_bid, &seq_root_bid,
                         &stale_root_bid, &ndocs, &ndeletes, &nlivenodes, &datasize,
                         &last_wal_flush_hdr_bid, &kv_info_offset,
                         &header_flags, &compacted_filename, NULL);
        if (marker == hdr_bid) { // for the oldest header, sum up full values
            ret += datasize;
            ret += nlivenodes * handle->config.blocksize;
            break;
        } else { // for headers upto oldest header, sum up only deltas..
            ret += deltasize; // root kv store or single kv instance mode
            if (kv_info_offset != BLK_NOT_FOUND) { // Multi kv instance mode..
                uint64_t doc_offset;
                struct docio_object doc;
                memset(&doc, 0, sizeof(struct docio_object));
                doc_offset = docio_read_doc(handle->dhandle, kv_info_offset,
                                            &doc, true);
                if (doc_offset == kv_info_offset) {
                    fdb_log(&handle->log_callback, FDB_RESULT_READ_FAIL,
                            "Read failure estimate_space_used.");
                    return 0;
                }
                ret += _kvs_stat_get_sum_attr(doc.body, version,
                                              KVS_STAT_DELTASIZE);

                free_docio_object(&doc, 1, 1, 1);
            }
        }
    }

    return ret;
}

LIBFDB_API
fdb_status fdb_get_file_info(fdb_file_handle *fhandle, fdb_file_info *info)
{
    uint64_t ndocs, ndeletes;
    fdb_kvs_handle *handle;

    if (!fhandle || !info) {
        return FDB_RESULT_INVALID_ARGS;
    }
    handle = fhandle->root;

    fdb_check_file_reopen(handle, NULL);
    fdb_sync_db_header(handle);

    if (handle->config.compaction_mode == FDB_COMPACTION_AUTO) {
        // compaction daemon mode
        info->filename = handle->filename;
    } else {
        info->filename = handle->file->filename;
    }

    if (handle->shandle) {
        // handle for snapshot
    } else {
        info->new_filename = NULL;
    }

    // Note that doc_count includes the number of WAL entries, which might
    // incur an incorrect estimation. However, after the WAL flush, the doc
    // counter becomes consistent. We plan to devise a new way of tracking
    // the number of docs in a database instance.
    size_t wal_docs = wal_get_num_docs(handle->file);
    size_t wal_deletes = wal_get_num_deletes(handle->file);
    size_t wal_n_inserts = wal_docs - wal_deletes;

    ndocs = _kvs_stat_get_sum(handle->file, KVS_STAT_NDOCS);

    if (ndocs + wal_n_inserts < wal_deletes) {
        info->doc_count = 0;
    } else {
        if (ndocs) {
            info->doc_count = ndocs + wal_n_inserts - wal_deletes;
        } else {
            info->doc_count = wal_n_inserts;
        }
    }

    ndeletes = _kvs_stat_get_sum(handle->file, KVS_STAT_NDELETES);
    if (ndeletes) { // not accurate since some ndeletes may be wal_deletes
        info->deleted_count = ndeletes + wal_deletes;
    } else { // this is accurate since it reflects only wal_ndeletes
        info->deleted_count = wal_deletes;
    }

    info->space_used = fdb_estimate_space_used(fhandle);
    info->file_size = filemgr_get_pos(handle->file);

    // Get the number of KV store instances in a given ForestDB file.
    struct kvs_header *kv_header = handle->file->kv_header;
    size_t num = 1; // default KV store.
    if (kv_header) {
        spin_lock(&kv_header->lock);
        num += kv_header->num_kv_stores;
        spin_unlock(&kv_header->lock);
    }
    info->num_kv_stores = num;

    return FDB_RESULT_SUCCESS;
}

LIBFDB_API
fdb_status fdb_get_all_snap_markers(fdb_file_handle *fhandle,
                                    fdb_snapshot_info_t **markers_out,
                                    uint64_t *num_markers)
{
    fdb_kvs_handle *handle;
    bid_t hdr_bid;
    size_t header_len;
    uint8_t header_buf[FDB_BLOCKSIZE];
    bid_t trie_root_bid = BLK_NOT_FOUND;
    bid_t seq_root_bid = BLK_NOT_FOUND;
    bid_t stale_root_bid = BLK_NOT_FOUND;
    uint64_t ndocs;
    uint64_t ndeletes;
    uint64_t nlivenodes;
    uint64_t datasize;
    uint64_t last_wal_flush_hdr_bid;
    uint64_t kv_info_offset;
    uint64_t header_flags;
    uint64_t version;
    char *compacted_filename;
    fdb_seqnum_t seqnum;
    fdb_snapshot_info_t *markers;
    int i;
    uint64_t size, array_size;
    file_status_t fstatus;
    filemgr_header_revnum_t revnum;
    fdb_status status = FDB_RESULT_SUCCESS;

    if (!fhandle || !markers_out || !num_markers) {
        return FDB_RESULT_INVALID_ARGS;
    }
    handle = fhandle->root;
    if (!handle->file) {
        return FDB_RESULT_FILE_NOT_OPEN;
    }

    fdb_check_file_reopen(handle, &fstatus);
    fdb_sync_db_header(handle);

    // There are as many DB headers in a file as the file's header revision num
    array_size = handle->cur_header_revnum - sb_get_min_live_revnum(handle->file);
    if (!array_size) {
        return FDB_RESULT_NO_DB_INSTANCE;
    }
    markers = (fdb_snapshot_info_t *)calloc(array_size, sizeof(fdb_snapshot_info_t));
    if (!markers) { // LCOV_EXCL_START
        return FDB_RESULT_ALLOC_FAIL;
    } // LCOV_EXCL_STOP

    // Start loading from current header
    seqnum = handle->seqnum;
    hdr_bid = handle->last_hdr_bid;
    header_len = handle->file->header.size;
    size = 0;

    // Reverse scan the file to locate the DB header with seqnum marker
    for (i = 0; header_len; ++i, ++size) {
        if (i == 0) {
            status = filemgr_fetch_header(handle->file, handle->last_hdr_bid,
                                          header_buf, &header_len, NULL,
                                          &revnum, NULL, &version, NULL,
                                          &handle->log_callback);
        } else {
            if ((uint64_t)i >= array_size) {
                header_len = 0;
                continue;
            }
            hdr_bid = filemgr_fetch_prev_header(handle->file, hdr_bid,
                                                header_buf, &header_len,
                                                &seqnum, &revnum, NULL, &version,
                                                NULL, &handle->log_callback);
        }
        if (header_len == 0) {
            continue; // header doesn't exist, terminate iteration
        }
        if (ver_superblock_support(version) &&
            revnum < handle->file->sb->min_live_hdr_revnum) {
            continue; // eariler than the last block reclaiming
        }

        fdb_fetch_header(version, header_buf,
                         &trie_root_bid, &seq_root_bid, &stale_root_bid,
                         &ndocs, &ndeletes, &nlivenodes, &datasize,
                         &last_wal_flush_hdr_bid, &kv_info_offset,
                         &header_flags, &compacted_filename, NULL);
        markers[i].marker = (fdb_snapshot_marker_t)hdr_bid;
        if (kv_info_offset == BLK_NOT_FOUND) { // Single kv instance mode
            markers[i].num_kvs_markers = 1;
            markers[i].kvs_markers = (fdb_kvs_commit_marker_t *)malloc(
                                            sizeof(fdb_kvs_commit_marker_t));
            if (!markers[i].kvs_markers) { // LCOV_EXCL_START
                fdb_free_snap_markers(markers, i);
                return FDB_RESULT_ALLOC_FAIL;
            } // LCOV_EXCL_STOP
            markers[i].kvs_markers->seqnum = seqnum;
            markers[i].kvs_markers->kv_store_name = NULL;
        } else { // Multi kv instance mode
            uint64_t doc_offset;
            struct docio_object doc;
            memset(&doc, 0, sizeof(struct docio_object));
            doc_offset = docio_read_doc(handle->dhandle, kv_info_offset, &doc,
                                        true);
            if (doc_offset == kv_info_offset) {
                fdb_free_snap_markers(markers, i);
                return FDB_RESULT_READ_FAIL;
            }
            status = _fdb_kvs_get_snap_info(doc.body, version,
                                            &markers[i]);
            if (status != FDB_RESULT_SUCCESS) { // LCOV_EXCL_START
                fdb_free_snap_markers(markers, i);
                return status;
            } // LCOV_EXCL_STOP
            if (seqnum) {
                // default KVS has been used
                // add the default KVS info
                int idx = markers[i].num_kvs_markers - 1;
                markers[i].kvs_markers[idx].seqnum = seqnum;
                markers[i].kvs_markers[idx].kv_store_name = NULL;
            } else {
                // do not count default KVS .. decrease it by one.
                markers[i].num_kvs_markers--;
            }
            free_docio_object(&doc, 1, 1, 1);
        }
    }

    *markers_out = markers;
    *num_markers = size ? size - 1 : 0;

    return status;
}

LIBFDB_API
fdb_status fdb_free_snap_markers(fdb_snapshot_info_t *markers, uint64_t size) {
    uint64_t i;
    int64_t kvs_idx;
    if (!markers || !size) {
        return FDB_RESULT_INVALID_ARGS;
    }
    for (i = 0; i < size; ++i) {
        kvs_idx = markers[i].num_kvs_markers;
        if (kvs_idx) {
            for (kvs_idx = kvs_idx - 1; kvs_idx >=0; --kvs_idx) {
                free(markers[i].kvs_markers[kvs_idx].kv_store_name);
            }
            free(markers[i].kvs_markers);
        }
    }
    free(markers);
    return FDB_RESULT_SUCCESS;
}

LIBFDB_API
size_t fdb_get_buffer_cache_used() {
    if (!fdb_initialized) {
        return 0;
    }

    return (size_t) filemgr_get_bcache_used_space();
}

LIBFDB_API
fdb_status fdb_cancel_compaction(fdb_file_handle *fhandle)
{
    if (!fhandle) {
        return FDB_RESULT_INVALID_ARGS;
    }

    fdb_kvs_handle *super_handle = fhandle->root;

    filemgr_mutex_lock(super_handle->file);
    filemgr_set_cancel_compaction(super_handle->file, true);

    // TODO: Find a better way of cacncelling the ongoing compaction task.
    unsigned int sleep_time = 10000; // 10 ms.
    file_status_t fstatus = filemgr_get_file_status(super_handle->file);
    while (fstatus == FILE_COMPACT_OLD) {
        filemgr_mutex_unlock(super_handle->file);
        decaying_usleep(&sleep_time, 1000000);
        filemgr_mutex_lock(super_handle->file);
        fstatus = filemgr_get_file_status(super_handle->file);
    }
    filemgr_set_cancel_compaction(super_handle->file, false);
    filemgr_mutex_unlock(super_handle->file);
    return FDB_RESULT_SUCCESS;
}

LIBFDB_API
fdb_status fdb_set_block_reusing_params(fdb_file_handle *fhandle,
                                        size_t block_reusing_threshold,
                                        size_t num_keeping_headers)
{
    if (!fhandle || !fhandle->root) {
        return FDB_RESULT_INVALID_ARGS;
    }
    filemgr *file = fhandle->root->file;
    atomic_store_uint64_t(&file->config->block_reusing_threshold,
                          block_reusing_threshold);
    atomic_store_uint64_t(&file->config->num_keeping_headers, num_keeping_headers);
    return FDB_RESULT_SUCCESS;
}

LIBFDB_API
fdb_status fdb_shutdown()
{
    fdb_status ret = FDB_RESULT_SUCCESS;
    if (fdb_initialized) {

#ifndef SPIN_INITIALIZER
        // Windows: check if spin lock is already destroyed.
        if (InterlockedCompareExchange(&initial_lock_status, 1, 2) == 2) {
            spin_lock(&initial_lock);
        } else {
            // ForestDB is already shut down
            return ret;
        }
#else
        spin_lock(&initial_lock);
#endif

        if (!fdb_initialized) {
            // ForestDB is already shut down
#ifdef SPIN_INITIALIZER
            spin_unlock(&initial_lock);
#endif
            return ret;
        }
        if (fdb_open_inprog) {
            spin_unlock(&initial_lock);
            return FDB_RESULT_FILE_IS_BUSY;
        }
        compactor_shutdown();
        bgflusher_shutdown();
        ret = filemgr_shutdown();
        if (ret == FDB_RESULT_SUCCESS) {
#ifdef _MEMPOOL
            mempool_shutdown();
#endif
            fdb_initialized = 0;
            spin_unlock(&initial_lock);
#ifndef SPIN_INITIALIZER
            spin_destroy(&initial_lock);
            initial_lock_status = 0;
#endif
        } else { // some file may be still open...
            spin_unlock(&initial_lock);
        }
    }
    return ret;
}

void _fdb_dump_handle(fdb_kvs_handle *h) {
    fprintf(stderr, "filename: %s\n", h->filename);

    fprintf(stderr, "config: chunksize %d\n", h->config.chunksize);
    fprintf(stderr, "config: blocksize %d\n", h->config.blocksize);
    fprintf(stderr, "config: buffercache_size %" _F64 "\n",
           h->config.buffercache_size);
    fprintf(stderr, "config: wal_threshold %" _F64 "\n",
            h->config.wal_threshold);
    fprintf(stderr, "config: wal_flush_before_commit %d\n",
           h->config.wal_flush_before_commit);
    fprintf(stderr, "config: purging_interval %d\n", h->config.purging_interval);
    fprintf(stderr, "config: seqtree_opt %d\n", h->config.seqtree_opt);
    fprintf(stderr, "config: durability_opt %d\n", h->config.durability_opt);
    fprintf(stderr, "config: open_flags %x\n", h->config.flags);
    fprintf(stderr, "config: compaction_buf_maxsize %d\n",
           h->config.compaction_buf_maxsize);
    fprintf(stderr, "config: cleanup_cache_onclose %d\n",
           h->config.cleanup_cache_onclose);
    fprintf(stderr, "config: compress body %d\n",
           h->config.compress_document_body);
    fprintf(stderr, "config: compaction_mode %d\n", h->config.compaction_mode);
    fprintf(stderr, "config: compaction_threshold %d\n",
           h->config.compaction_threshold);
    fprintf(stderr, "config: compactor_sleep_duration %" _F64"\n",
           h->config.compactor_sleep_duration);

    fprintf(stderr, "kvs_config: Create if missing = %d\n",
           h->kvs_config.create_if_missing);

    fprintf(stderr, "kvs: id = %" _F64 "\n", h->kvs->id);
    fprintf(stderr, "kvs: type = %d\n", h->kvs->type);
    fprintf(stderr, "kvs: root_handle %p\n", (void *)h->kvs->root);

    fprintf(stderr, "fdb_file_handle: %p\n", (void *)h->fhandle);
    fprintf(stderr, "fhandle: root %p\n", (void*)h->fhandle->root);
    fprintf(stderr, "fhandle: flags %p\n", (void *)h->fhandle->flags);

    fprintf(stderr, "hbtrie: %p\n", (void *)h->trie);
    fprintf(stderr, "hbtrie: chunksize %u\n", h->trie->chunksize);
    fprintf(stderr, "hbtrie: valuelen %u\n", h->trie->valuelen);
    fprintf(stderr, "hbtrie: flag %x\n", h->trie->flag);
    fprintf(stderr, "hbtrie: leaf_height_limit %u\n",
           h->trie->leaf_height_limit);
    fprintf(stderr, "hbtrie: root_bid %p\n", (void *)h->trie->root_bid);
    fprintf(stderr, "hbtrie: root_bid %p\n", (void *)h->trie->root_bid);

    fprintf(stderr, "seqtrie: %p\n", (void *)h->seqtrie);
    fprintf(stderr, "seqtrie: chunksize %u\n", h->seqtrie->chunksize);
    fprintf(stderr, "seqtrie: valuelen %u\n", h->seqtrie->valuelen);
    fprintf(stderr, "seqtrie: flag %x\n", h->seqtrie->flag);
    fprintf(stderr, "seqtrie: leaf_height_limit %u\n",
           h->seqtrie->leaf_height_limit);
    fprintf(stderr, "seqtrie: root_bid %" _F64 "\n", h->seqtrie->root_bid);
    fprintf(stderr, "seqtrie: root_bid %" _F64 "\n", h->seqtrie->root_bid);

    fprintf(stderr, "file: filename %s\n", h->file->filename);
    fprintf(stderr, "file: ref_count %d\n", h->file->ref_count);
    fprintf(stderr, "file: fflags %x\n", h->file->fflags);
    fprintf(stderr, "file: blocksize %d\n", h->file->blocksize);
    fprintf(stderr, "file: fd %d\n", h->file->fd);
    fprintf(stderr, "file: pos %" _F64"\n", atomic_get_uint64_t(&h->file->pos));
    fprintf(stderr, "file: status %d\n", atomic_get_uint8_t(&h->file->status));
    fprintf(stderr, "file: config: blocksize %d\n", h->file->config->blocksize);
    fprintf(stderr, "file: config: ncacheblock %d\n",
           h->file->config->ncacheblock);
    fprintf(stderr, "file: config: flag %d\n", h->file->config->flag);
    fprintf(stderr, "file: config: chunksize %d\n", h->file->config->chunksize);
    fprintf(stderr, "file: config: options %x\n", h->file->config->options);
    fprintf(stderr, "file: config: prefetch_duration %" _F64 "\n",
           h->file->config->prefetch_duration);
    fprintf(stderr, "file: config: num_wal_shards %d\n",
           h->file->config->num_wal_shards);
    fprintf(stderr, "file: config: num_bcache_shards %d\n",
           h->file->config->num_bcache_shards);
    fprintf(stderr, "file: new_file %p\n", (void *)h->file->new_file);
    fprintf(stderr, "file: old_filename %p\n", (void *)h->file->old_filename);
    fprintf(stderr, "file: fnamedic_item: bcache %p\n",
            (void *)h->file->bcache);
    fprintf(stderr, "file: global_txn: handle %p\n",
            (void *)h->file->global_txn.handle);
    fprintf(stderr, "file: global_txn: prev_hdr_bid %" _F64 "\n",
           h->file->global_txn.prev_hdr_bid);
    fprintf(stderr, "file: global_txn: isolation %d\n",
           h->file->global_txn.isolation);
    fprintf(stderr, "file: in_place_compaction: %d\n",
           h->file->in_place_compaction);
    fprintf(stderr, "file: kvs_header: %" _F64 "\n",
            h->file->kv_header->id_counter);

    fprintf(stderr, "docio_handle: %p\n", (void*)h->dhandle);
    fprintf(stderr, "dhandle: file: filename %s\n",
            h->dhandle->file->filename);
    fprintf(stderr, "dhandle: curblock %" _F64 "\n", h->dhandle->curblock);
    fprintf(stderr, "dhandle: curpos %d\n", h->dhandle->curpos);
    fprintf(stderr, "dhandle: cur_bmp_revnum_hash %d\n", h->dhandle->cur_bmp_revnum_hash);
    fprintf(stderr, "dhandle: lastbid %" _F64 "\n", h->dhandle->lastbid);
    fprintf(stderr, "dhandle: readbuffer %p\n", h->dhandle->readbuffer);
    fprintf(stderr, "dhandle: %s\n",
           h->dhandle->compress_document_body ? "compress" : "don't compress");
    fprintf(stderr, "new_dhandle %p\n", (void *)h->dhandle);

    fprintf(stderr, "btreeblk_handle bhanlde %p\n", (void *)h->bhandle);
    fprintf(stderr, "bhandle: nodesize %d\n", h->bhandle->nodesize);
    fprintf(stderr, "bhandle: nnodeperblock %d\n", h->bhandle->nnodeperblock);
    fprintf(stderr, "bhandle: nlivenodes %" _F64 "\n", h->bhandle->nlivenodes);
    fprintf(stderr, "bhandle: file %s\n", h->bhandle->file->filename);
    fprintf(stderr, "bhandle: nsb %d\n", h->bhandle->nsb);

    fprintf(stderr, "multi_kv_instances: %d\n", h->config.multi_kv_instances);
    fprintf(stderr, "prefetch_duration: %" _F64"\n",
            h->config.prefetch_duration);
    fprintf(stderr, "cur_header_revnum: %" _F64 "\n", h->cur_header_revnum);
    fprintf(stderr, "last_hdr_bid: %" _F64 "\n", h->last_hdr_bid);
    fprintf(stderr, "last_wal_flush_hdr_bid: %" _F64 "\n",
           h->last_wal_flush_hdr_bid);
    fprintf(stderr, "kv_info_offset: %" _F64 "\n", h->kv_info_offset);

    fprintf(stderr, "snap_handle: %p\n", (void *)h->shandle);
    if (h->shandle) {
        fprintf(stderr, "shandle: ref_cnt %d\n", h->shandle->ref_cnt);
        fprintf(stderr, "shandle: type %d\n", h->shandle->type);
        fprintf(stderr, "shandle: kvs_stat: nlivenodes %" _F64 "\n",
               h->shandle->stat.nlivenodes);
        fprintf(stderr, "shandle: kvs_stat: ndocs %" _F64 "\n",
               h->shandle->stat.ndocs);
        fprintf(stderr, "shandle: kvs_stat: datasize %" _F64 "\n",
               h->shandle->stat.datasize);
        fprintf(stderr, "shandle: kvs_stat: wal_ndocs %" _F64 "\n",
               h->shandle->stat.wal_ndocs);
        fprintf(stderr, "shandle: kvs_stat: wal_ndeletes %" _F64 "\n",
               h->shandle->stat.wal_ndeletes);
    }
    fprintf(stderr, "seqnum: %" _F64 "\n", h->seqnum);
    fprintf(stderr, "max_seqnum: %" _F64 "\n", h->max_seqnum);

    fprintf(stderr, "txn: %p\n", (void *)h->txn);
    if (h->txn) {
        fprintf(stderr, "txn: handle %p\n", (void *)h->txn->handle);
        fprintf(stderr, "txn: prev_hdr_bid %" _F64" \n", h->txn->prev_hdr_bid);
        fprintf(stderr, "txn: isolation %d\n", h->txn->isolation);
    }
    fprintf(stderr, "dirty_updates %d\n", h->dirty_updates);
}

void _fdb_dump_handles(void) {
#ifdef _TRACE_HANDLES
    struct avl_node *h = NULL;
    int n = 0;
    spin_lock(&open_handle_lock);
    h = avl_first(&open_handles);
    while(h) {
        fdb_kvs_handle *handle = _get_entry(h, fdb_kvs_handle, avl_trace);
        n++;
        fprintf(stderr, "--------%d-Dumping Handle %p---------\n", n, handle);
        _fdb_dump_handle(handle);
        h = avl_next(h);
    }
    spin_unlock(&open_handle_lock);
#endif
}
