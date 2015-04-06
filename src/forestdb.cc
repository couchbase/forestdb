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
#include "compactor.h"
#include "memleak.h"
#include "time_utils.h"

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
    docio_read_doc_key_meta((struct docio_handle *)handle, offset, &doc);
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

    seq_memcpy(ndocs, (uint8_t *)header_buf + offset,
               sizeof(uint64_t), offset);
    *ndocs = _endian_decode(*ndocs);

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

INLINE size_t _fdb_get_docsize(struct docio_length len);

typedef enum {
    FDB_RESTORE_NORMAL,
    FDB_RESTORE_KV_INS,
} fdb_restore_mode_t;

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
    err_log_callback *log_callback;

    if (!hdr_off) { // Nothing to do if we don't have a header block offset
        return;
    }

    filemgr_mutex_lock(file);
    if (last_wal_flush_hdr_bid != BLK_NOT_FOUND) {
        offset = (last_wal_flush_hdr_bid + 1) * blocksize;
    }

    // If a valid last header was retrieved and it matches the current header
    // OR if WAL already had entries populated, then no crash recovery needed
    if (hdr_off <= offset ||
        (!handle->shandle && wal_get_size(file) &&
            mode != FDB_RESTORE_KV_INS)) {
        filemgr_mutex_unlock(file);
        return;
    }

    // Temporarily disable the error logging callback as there are false positive
    // checksum errors in docio_read_doc.
    // TODO: Need to adapt docio_read_doc to separate false checksum errors.
    log_callback = handle->dhandle->log_callback;
    handle->dhandle->log_callback = NULL;

    for (; offset < hdr_off;
        offset = ((offset / blocksize) + 1) * blocksize) { // next block's off
        if (!docio_check_buffer(handle->dhandle, offset / blocksize)) {
            continue;
        } else {
            do {
                struct docio_object doc;
                uint64_t _offset;
                uint64_t doc_offset;
                memset(&doc, 0, sizeof(doc));
                _offset = docio_read_doc(handle->dhandle, offset, &doc);
                if (_offset == offset) { // reached unreadable doc, skip block
                    break;
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
                            docio_read_doc(handle->dhandle, doc_offset, &doc);
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
                                               &wal_doc, doc_offset, 0, 0);
                                }
                            } else {
                                wal_insert(&file->global_txn, file,
                                           &wal_doc, doc_offset, 0, 0);
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
            } while (offset + sizeof(struct docio_length) < hdr_off);
        }
    }
    // wal commit
    if (!handle->shandle) {
        wal_commit(&file->global_txn, file, NULL);
    }
    filemgr_mutex_unlock(file);
    handle->dhandle->log_callback = log_callback;
}

// restore the documents in NEW_FILENAME (corrupted file during compaction)
// into the file referred by HANDLE
INLINE fdb_status _fdb_recover_compaction(fdb_kvs_handle *handle,
                                          const char *new_filename)
{
    uint64_t offset = 0;
    uint32_t blocksize = handle->config.blocksize;
    fdb_kvs_handle new_db;
    fdb_config config = handle->config;
    struct filemgr *new_file;
    struct docio_handle dhandle;

    memset(&new_db, 0, sizeof(new_db));
    new_db.log_callback.callback = handle->log_callback.callback;
    new_db.log_callback.ctx_data = handle->log_callback.ctx_data;
    // Disable the error logging callback as there are false positive
    // checksum errors in docio_read_doc.
    // TODO: Need to adapt docio_read_doc to separate false checksum errors.
    dhandle.log_callback = NULL;
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

    // remove temporary wal_index files if exist
    filemgr_scan_remove_keystr_files(new_file);

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

        filemgr_mutex_unlock(new_file);
        if (new_db.kvs) {
            fdb_kvs_info_free(&new_db);
        }
        // remove self: WARNING must not close this handle if snapshots
        // are yet to open this file
        filemgr_remove_pending(old_file, new_db.file);
        filemgr_close(old_file, 0, handle->filename, &handle->log_callback);
        free(new_db.filename);
        return FDB_RESULT_FAIL_BY_COMPACTION;
    }
    docio_init(&dhandle, new_file, config.compress_document_body);

    for (offset = 0; offset < filemgr_get_pos(new_file);
        offset = ((offset/blocksize)+1) * blocksize) {

        if (!docio_check_buffer(&dhandle, offset/blocksize)) {
            // this block is not for documents
            continue;

        } else {
            do {
                struct docio_object doc;
                uint64_t _offset;
                uint64_t doc_offset;
                memset(&doc, 0, sizeof(doc));
                _offset = docio_read_doc(&dhandle, offset, &doc);
                if ((doc.key || (doc.length.flag & DOCIO_TXN_COMMITTED)) &&
                    docio_check_compact_doc(&dhandle, &doc)) {
                    // Check if the doc is transactional or contains system info.
                    if (!(doc.length.flag & DOCIO_TXN_DIRTY) &&
                        !(doc.length.flag & DOCIO_SYSTEM)) {
                        if (doc.length.flag & DOCIO_TXN_COMMITTED) {
                            // commit mark .. read doc offset
                            doc_offset = doc.doc_offset;
                            // read the previously skipped doc
                            docio_read_doc(handle->dhandle, doc_offset, &doc);
                            if (doc.key == NULL) {
                                // doc read error
                                if (doc.key) free(doc.key);
                                if (doc.meta) free(doc.meta);
                                if (doc.body) free(doc.body);
                                offset = _offset;
                                continue;
                            }
                        }

                        // this document was interleaved during compaction
                        fdb_doc wal_doc;
                        wal_doc.keylen = doc.length.keylen;
                        wal_doc.metalen = doc.length.metalen;
                        wal_doc.bodylen = doc.length.bodylen;
                        wal_doc.key = doc.key;
                        wal_doc.seqnum = doc.seqnum;

                        wal_doc.meta = doc.meta;
                        wal_doc.body = doc.body;
                        wal_doc.deleted = doc.length.flag & DOCIO_DELETED;

                        fdb_set(handle, &wal_doc);

                        free(doc.key);
                        free(doc.meta);
                        free(doc.body);
                        offset = _offset;
                    } else {
                        if (doc.length.flag & DOCIO_SYSTEM) {
                            // KV instances header
                            // free existing KV header of handle->file
                            if (handle->file->kv_header) {
                                handle->file->free_kv_header(handle->file);
                            }
                            fdb_kvs_header_create(handle->file);
                            // read from 'dhandle' (new file),
                            // and import into 'handle->file' (old_file)
                            fdb_kvs_header_read(handle->file, &dhandle, offset);
                            // write KV header in 'handle->file'
                            // using 'handle->dhandle'
                            fdb_kvs_header_append(handle->file, handle->dhandle);
                        }
                        // otherwise, skip but do not break.. read next doc
                        free(doc.key);
                        free(doc.meta);
                        free(doc.body);
                        offset = _offset;
                    }
                } else {
                    free(doc.key);
                    free(doc.meta);
                    free(doc.body);
                    offset = _offset;
                    break;
                }
            } while (offset + sizeof(struct docio_length) < filemgr_get_pos(new_file));
        }
    }

    docio_free(&dhandle);
    if (new_db.kvs) {
        fdb_kvs_info_free(&new_db);
    }
    _fdb_close(&new_db);
    _fdb_commit(handle, FDB_COMMIT_NORMAL);

    return FDB_RESULT_SUCCESS;
}

LIBFDB_API
fdb_status fdb_init(fdb_config *config)
{
    fdb_config _config;
    compactor_config c_config;
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
        // initialize file manager and block cache
        f_config.blocksize = _config.blocksize;
        f_config.ncacheblock = _config.buffercache_size / _config.blocksize;
        filemgr_init(&f_config);

        // initialize compaction daemon
        c_config.sleep_duration = _config.compactor_sleep_duration;
        compactor_init(&c_config);

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

    handle->shandle = NULL;
    handle->kvs_config = get_default_kvs_config();

    fdb_init(fconfig);
    fdb_file_handle_init(fhandle, handle);

    fdb_status fs = _fdb_open(handle, filename, FDB_VFILENAME, &config);
    if (fs == FDB_RESULT_SUCCESS) {
        *ptr_fhandle = fhandle;
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

    handle->shandle = NULL;
    handle->kvs_config = get_default_kvs_config();

    fdb_init(fconfig);
    fdb_file_handle_init(fhandle, handle);

    // insert kvs_names and functions into fhandle's list
    fdb_file_handle_parse_cmp_func(fhandle, num_functions,
                                   kvs_names, functions);

    fdb_status fs = _fdb_open(handle, filename, FDB_VFILENAME, &config);
    if (fs == FDB_RESULT_SUCCESS) {
        *ptr_fhandle = fhandle;
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
    handle->shandle = NULL;

    fdb_file_handle_init(fhandle, handle);
    if (cmp_func_list) {
        fdb_file_handle_clone_cmp_func_list(fhandle, cmp_func_list);
    }
    fdb_status fs = _fdb_open(handle, filename, FDB_VFILENAME, fconfig);
    if (fs == FDB_RESULT_SUCCESS) {
        *ptr_fhandle = fhandle;
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
    bool compaction_inprog = false;
    if (!handle_in || !ptr_handle) {
        return FDB_RESULT_INVALID_ARGS;
    }

    // Sequence trees are a must for snapshot creation
    if (handle_in->config.seqtree_opt != FDB_SEQTREE_USE) {
        return FDB_RESULT_INVALID_CONFIG;
    }

    if (!handle_in->shandle) {
        fdb_check_file_reopen(handle_in, &fstatus);
        if (fstatus == FILE_COMPACT_OLD) { // If file is undergoing compaction
            fdb_seqnum_t last_seqnum;
            file = handle_in->file; // pick old_file for main index
            // get old file's last seqnum
            if (handle_in->kvs && handle_in->kvs->type == KVS_SUB) {
                last_seqnum = fdb_kvs_get_seqnum(file, handle_in->kvs->id);
            } else {
                last_seqnum = filemgr_get_seqnum(file);
            }
            if (last_seqnum < seqnum) {
                // req.seqnum is greater than the last seqnum of old file:
                // pick new_file for WAL so all writes made after
                // the point where compator and writers began to interleave are
                // copied into the snapshot
                compaction_inprog = true;
            }
        } else { // in case compaction had completed, open new_file directly
            fdb_link_new_file(handle_in);
            fdb_sync_db_header(handle_in);
            if (handle_in->new_file == NULL) {
                file = handle_in->file;
            } else {
                file = handle_in->new_file;
            }
            if (handle_in->kvs && handle_in->kvs->type == KVS_SUB) {
                handle_in->seqnum = fdb_kvs_get_seqnum(file,
                                                       handle_in->kvs->id);
            } else {
                handle_in->seqnum = filemgr_get_seqnum(file);
            }
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

    handle->log_callback = handle_in->log_callback;
    if (compaction_inprog) { // this is to prevent restoration of old_file's WAL
        handle->max_seqnum = FDB_SNAPSHOT_INMEM; // pick new_file's WAL instead
    } else {
        handle->max_seqnum = seqnum;
    }
    handle->fhandle = handle_in->fhandle;

    config.flags |= FDB_OPEN_FLAG_RDONLY;
    // do not perform compaction for snapshot
    config.compaction_mode = FDB_COMPACTION_MANUAL;

    // If cloning an existing snapshot handle, then rewind indexes
    // to its last DB header and point its avl tree to existing snapshot's tree
    if (handle_in->shandle) {
        handle->last_hdr_bid = handle_in->last_hdr_bid; // do fast rewind
        if (snap_clone(handle_in->shandle, handle_in->max_seqnum,
                   &handle->shandle, seqnum) == FDB_RESULT_SUCCESS) {
            handle->max_seqnum = FDB_SNAPSHOT_INMEM; // temp value to skip WAL
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
        fs = _fdb_kvs_open(handle_in->kvs->root,
                              &config, &kvs_config, file,
                              file->filename,
                              _fdb_kvs_get_name(handle_in,
                                                   file),
                              handle);
    } else {
        fs = _fdb_open(handle, file->filename, FDB_AFILENAME, &config);
    }

    if (fs == FDB_RESULT_SUCCESS) {
        if ((seqnum == FDB_SNAPSHOT_INMEM || compaction_inprog) &&
            !handle_in->shandle) {
            fdb_seqnum_t upto_seq = seqnum;
            if (compaction_inprog && seqnum != FDB_SNAPSHOT_INMEM) {
                // Compaction in progress AND commit-based snapshot

                // Persistent snapshot requested in the middle of compaction..
                handle->shandle->type = FDB_SNAP_COMPACTION;
                wal_snapshot(handle->file->new_file, (void *)handle->shandle,
                             handle_in->txn, &upto_seq, _fdb_wal_snapshot_func);
                // If new_file's WAL did have items, check to see that the
                // highest number read corresponds to a committed sequence no
                if (upto_seq && seqnum != upto_seq) {
                    if (fdb_kvs_close(handle) != FDB_RESULT_SUCCESS) {
                        free(handle);
                    }
                    *ptr_handle = NULL;
                    return FDB_RESULT_NO_DB_INSTANCE;
                }
                // link new file for WAL
                fdb_link_new_file_enforce(handle);
                handle->max_seqnum = seqnum;
            } else {
                // In-memory snapshot

                if (compaction_inprog && handle->file->new_file) {
                    // Compaction is in progress.
                    // copy WAL entries in the new file
                    handle->shandle->type = FDB_SNAP_COMPACTION;
                    wal_snapshot(handle->file->new_file, (void *)handle->shandle,
                                 handle_in->txn, &upto_seq, _fdb_wal_snapshot_func);
                    fdb_link_new_file_enforce(handle);
                    if (upto_seq) {
                        // At least one WAL entry in the new file is copied
                        handle->max_seqnum = upto_seq;
                    } else {
                        // no new entry in the new file .. get old file's seqnum
                        if (handle_in->kvs && handle_in->kvs->id > 0) {
                            handle->max_seqnum =
                                _fdb_kvs_get_seqnum(handle->file->kv_header,
                                                    handle_in->kvs->id);
                        } else {
                            handle->max_seqnum = filemgr_get_seqnum(handle->file);
                        }
                    }
                } else {
                    // No concurrent compaction
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
                                handle->seqtree->root_bid = dirty_seqtree_root;
                            }
                        }
                    }
                    btreeblk_discard_blocks(handle->bhandle);
                    btreeblk_create_dirty_snapshot(handle->bhandle);
                    filemgr_mutex_unlock(handle->file);
                }
            }
        } else if (handle->max_seqnum == FDB_SNAPSHOT_INMEM) {
            // Snapshot is created on the other snapshot handle

            handle->max_seqnum = handle_in->seqnum;

            if (seqnum == FDB_SNAPSHOT_INMEM) {
                // in-memory snapshot
                filemgr_mutex_lock(handle->file);
                // copy dirty root nodes from the source snapshot
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
                filemgr_mutex_unlock(handle->file);
            }
        }
        *ptr_handle = handle;
    } else {
        *ptr_handle = NULL;
        snap_close(handle->shandle);
        free(handle);
    }
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

    // if the max sequence number seen by this handle is lower than the
    // requested snapshot marker, it means the snapshot is not yet visible
    // even via the current fdb_kvs_handle
    if (seqnum > handle_in->seqnum) {
        return FDB_RESULT_NO_DB_INSTANCE;
    }

    filemgr_mutex_lock(handle_in->file);
    filemgr_set_rollback(handle_in->file, 1); // disallow writes operations
    // All transactions should be closed before rollback
    if (wal_txn_exists(handle_in->file)) {
        filemgr_set_rollback(handle_in->file, 0);
        filemgr_mutex_unlock(handle_in->file);
        return FDB_RESULT_FAIL_BY_TRANSACTION;
    }

    // If compaction is running, wait until it is aborted.
    // TODO: Find a better way of waiting for the compaction abortion.
    unsigned int sleep_time = 10000; // 10 ms.
    file_status_t fstatus = filemgr_get_file_status(handle_in->file);
    while (fstatus == FILE_COMPACT_OLD || fstatus == FILE_COMPACT_INPROG) {
        filemgr_mutex_unlock(handle_in->file);
        decaying_usleep(&sleep_time, 1000000);
        filemgr_mutex_lock(handle_in->file);
        fstatus = filemgr_get_file_status(handle_in->file);
    }
    if (fstatus == FILE_REMOVED_PENDING) {
        filemgr_mutex_unlock(handle_in->file);
        fdb_check_file_reopen(handle_in, NULL);
        fdb_sync_db_header(handle_in);
    } else {
        filemgr_mutex_unlock(handle_in->file);
    }

    handle = (fdb_kvs_handle *) calloc(1, sizeof(fdb_kvs_handle));
    if (!handle) { // LCOV_EXCL_START
        return FDB_RESULT_ALLOC_FAIL;
    } // LCOV_EXCL_STOP

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

        fs = _fdb_commit(handle, FDB_COMMIT_NORMAL);
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
        }
    } else {
        free(handle);
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
    fdb_seqnum_t seqnum = 0;
    fdb_seqtree_opt_t seqtree_opt = config->seqtree_opt;
    uint64_t ndocs = 0;
    uint64_t datasize = 0;
    uint64_t last_wal_flush_hdr_bid = BLK_NOT_FOUND;
    uint64_t kv_info_offset = BLK_NOT_FOUND;
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
                                      config->compaction_mode);
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

    if (handle->filename) {
        handle->filename = (char *)realloc(handle->filename,
                                           strlen(target_filename)+1);
    } else {
        handle->filename = (char*)malloc(strlen(target_filename)+1);
    }
    strcpy(handle->filename, target_filename);

    handle->fileops = get_filemgr_ops();
    filemgr_open_result result = filemgr_open((char *)actual_filename,
                                              handle->fileops,
                                              &fconfig, &handle->log_callback);
    if (result.rv != FDB_RESULT_SUCCESS) {
        free(handle->filename);
        handle->filename = NULL;
        return (fdb_status) result.rv;
    }

    handle->file = result.file;
    filemgr_mutex_lock(handle->file);
    // If cloning from a snapshot handle, fdb_snapshot_open would have already
    // set handle->last_hdr_bid to the block id of required header, so rewind..
    if (handle->shandle && handle->last_hdr_bid) {
        status = filemgr_fetch_header(handle->file, handle->last_hdr_bid,
                                      header_buf, &header_len,
                                      &handle->log_callback);
        if (status != FDB_RESULT_SUCCESS) {
            filemgr_mutex_unlock(handle->file);
            free(handle->filename);
            handle->filename = NULL;
            filemgr_close(handle->file, false, handle->filename,
                              &handle->log_callback);
            return status;
        }
    } else { // Normal open
        filemgr_get_header(handle->file, header_buf, &header_len);
        handle->last_hdr_bid = filemgr_get_header_bid(handle->file);
    }

    // initialize the docio handle so kv headers may be read
    handle->dhandle = (struct docio_handle *)
                      calloc(1, sizeof(struct docio_handle));
    handle->dhandle->log_callback = &handle->log_callback;
    docio_init(handle->dhandle, handle->file, config->compress_document_body);

    if (header_len > 0) {
        fdb_fetch_header(header_buf, &trie_root_bid,
                         &seq_root_bid, &ndocs, &nlivenodes,
                         &datasize, &last_wal_flush_hdr_bid, &kv_info_offset,
                         &header_flags, &compacted_filename, &prev_filename);
        // use existing setting for seqtree_opt
        if (header_flags & FDB_FLAG_SEQTREE_USE) {
            seqtree_opt = FDB_SEQTREE_USE;
        } else {
            seqtree_opt = FDB_SEQTREE_NOT_USE;
        }
        // set seqnum based on handle type (multikv or default)
        if (handle->kvs && handle->kvs->id > 0) {
            if (kv_info_offset != BLK_NOT_FOUND) {
                if (!handle->file->kv_header) {
                    fdb_kvs_header_create(handle->file);
                    // KV header already exists but not loaded .. read & import
                    fdb_kvs_header_read(handle->file, handle->dhandle,
                                        kv_info_offset);
                }
                seqnum = _fdb_kvs_get_seqnum(handle->file->kv_header,
                                             handle->kvs->id);
            } else { // no kv_info offset, ok to set seqnum to zero
                seqnum = 0;
            }
        } else {
            seqnum = filemgr_get_seqnum(handle->file);
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

    handle->new_file = NULL;
    handle->new_dhandle = NULL;

    if (handle->shandle && handle->max_seqnum == FDB_SNAPSHOT_INMEM) {
        // Either an in-memory snapshot or cloning from an existing snapshot..
        filemgr_mutex_unlock(handle->file);
        hdr_bid = 0; // This prevents _fdb_restore_wal() as incoming handle's
                     // *_open() should have already restored it
    } else { // Persisted snapshot or file rollback..
        filemgr_mutex_unlock(handle->file);

        hdr_bid = filemgr_get_pos(handle->file) / FDB_BLOCKSIZE;
        hdr_bid = hdr_bid ? --hdr_bid : 0;
        if (handle->max_seqnum) {
            struct kvs_stat stat_ori;
            // backup original stats
            if (handle->kvs) {
                _kvs_stat_get(handle->file, handle->kvs->id, &stat_ori);
            } else {
                _kvs_stat_get(handle->file, 0, &stat_ori);
            }

            if (handle->max_seqnum == seqnum &&
                hdr_bid > handle->last_hdr_bid){
                // In case, snapshot_open is attempted with latest uncommitted
                // sequence number
                header_len = 0;
            }
            // Reverse scan the file to locate the DB header with seqnum marker
            while (header_len && seqnum != handle->max_seqnum) {
                hdr_bid = filemgr_fetch_prev_header(handle->file, hdr_bid,
                                          header_buf, &header_len, &seqnum,
                                          &handle->log_callback);
                if (header_len == 0) {
                    continue; // header doesn't exist
                }
                fdb_fetch_header(header_buf, &trie_root_bid,
                                 &seq_root_bid, &ndocs, &nlivenodes,
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
                        stat_dst.datasize = datasize;
                        stat_dst.nlivenodes = nlivenodes;
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
                                            kv_info_offset, &doc);

                if (doc_offset == kv_info_offset) {
                    header_len = 0; // fail
                    _fdb_kvs_header_free(kv_header);
                } else {
                    _fdb_kvs_header_import(kv_header, doc.body,
                                           doc.length.bodylen);
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

    handle->cur_header_revnum = filemgr_get_header_revnum(handle->file);
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

    if (handle->config.multi_kv_instances) {
        // multi KV instance mode
        filemgr_mutex_lock(handle->file);
        if (kv_info_offset == BLK_NOT_FOUND) {
            // there is no KV header .. create & initialize
            fdb_kvs_header_create(handle->file);
            kv_info_offset = fdb_kvs_header_append(handle->file, handle->dhandle);
        } else if (handle->file->kv_header == NULL) {
            // KV header already exists but not loaded .. read & import
            fdb_kvs_header_create(handle->file);
            fdb_kvs_header_read(handle->file, handle->dhandle, kv_info_offset);
        }

        // validation check for key order of all KV stores
        if (handle == handle->fhandle->root) {
            fdb_status fs = fdb_kvs_cmp_check(handle);
            filemgr_mutex_unlock(handle->file);
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
        } else {
            filemgr_mutex_unlock(handle->file);
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
        !handle->shandle) { // do not do compaction recovery on snapshots
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
                fconfig.options = FILEMGR_READONLY;
                filemgr_open_result result = filemgr_open(prev_filename,
                                                          handle->fileops,
                                                          &fconfig,
                                                          &handle->log_callback);
                if (result.file) {
                    filemgr_remove_pending(result.file, handle->file);
                    filemgr_close(result.file, 0, handle->filename,
                                  &handle->log_callback);
                }
            }
        } else {
            free(prev_filename);
        }
    }

    status = btreeblk_end(handle->bhandle);
    fdb_assert(status == FDB_RESULT_SUCCESS, status, handle);

    // do not register read-only handles
    if (!(config->flags & FDB_OPEN_FLAG_RDONLY) &&
        config->compaction_mode == FDB_COMPACTION_AUTO) {
        status = compactor_register_file(handle->file, (fdb_config *)config,
                                         handle->fhandle->cmp_func_list);
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

    (*doc)->size_ondisk = 0;
    (*doc)->deleted = false;

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

    return FDB_RESULT_SUCCESS;
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

INLINE fdb_status _fdb_wal_flush_func(void *voidhandle, struct wal_item *item)
{
    hbtrie_result hr;
    fdb_kvs_handle *handle = (fdb_kvs_handle *)voidhandle;
    fdb_seqnum_t _seqnum;
    fdb_kvs_id_t kv_id;
    fdb_status fs = FDB_RESULT_SUCCESS;
    uint8_t *var_key = alca(uint8_t, handle->config.chunksize);
    uint64_t old_offset, _offset;
    int delta, r;
    struct filemgr *file = handle->dhandle->file;
    struct kvs_stat stat;

    memset(var_key, 0, handle->config.chunksize);
    if (handle->kvs) {
        buf2kvid(handle->config.chunksize, item->header->key, &kv_id);
    } else {
        kv_id = 0;
    }

    if (item->action == WAL_ACT_INSERT ||
        item->action == WAL_ACT_LOGICAL_REMOVE) {
        _offset = _endian_encode(item->offset);

        r = _kvs_stat_get(file, kv_id, &stat);
        if (r != 0) {
            // KV store corresponding to kv_id is already removed
            // skip this item
            return FDB_RESULT_SUCCESS;
        }
        handle->bhandle->nlivenodes = stat.nlivenodes;

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
                int size_id, size_seq;
                uint8_t *kvid_seqnum;
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

        delta = (int)handle->bhandle->nlivenodes - (int)stat.nlivenodes;
        _kvs_stat_update_attr(file, kv_id, KVS_STAT_NLIVENODES, delta);

        if (hr == HBTRIE_RESULT_SUCCESS) {
            if (item->action == WAL_ACT_INSERT) {
                _kvs_stat_update_attr(file, kv_id, KVS_STAT_NDOCS, 1);
            }
            _kvs_stat_update_attr(file, kv_id, KVS_STAT_DATASIZE,
                                  item->doc_size);
        } else { // update or logical delete
            struct docio_length len;
            // This block is already cached when we call HBTRIE_INSERT.
            // No additional block access.
            len = docio_read_doc_length(handle->dhandle, old_offset);

            if (!(len.flag & DOCIO_DELETED)) {
                if (item->action == WAL_ACT_LOGICAL_REMOVE) {
                    _kvs_stat_update_attr(file, kv_id, KVS_STAT_NDOCS, -1);
                }
            } else {
                if (item->action == WAL_ACT_INSERT) {
                    _kvs_stat_update_attr(file, kv_id, KVS_STAT_NDOCS, 1);
                }
            }

            delta = (int)item->doc_size - (int)_fdb_get_docsize(len);
            _kvs_stat_update_attr(file, kv_id, KVS_STAT_DATASIZE, delta);
        }
    } else {
        // Immediate remove
        // LCOV_EXCL_START
        hr = hbtrie_remove(handle->trie, item->header->key,
                           item->header->keylen);
        fs = btreeblk_end(handle->bhandle);
        if (fs != FDB_RESULT_SUCCESS) {
            return fs;
        }

        if (handle->config.seqtree_opt == FDB_SEQTREE_USE) {
            _seqnum = _endian_encode(item->seqnum);
            btree_remove(handle->seqtree, (void*)&_seqnum);
            fs = btreeblk_end(handle->bhandle);
            if (fs != FDB_RESULT_SUCCESS) {
                return fs;
            }
        }

        if (hr == HBTRIE_RESULT_SUCCESS) {
            _kvs_stat_update_attr(file, kv_id, KVS_STAT_NDOCS, -1);
            delta = -(int)item->doc_size;
            _kvs_stat_update_attr(file, kv_id, KVS_STAT_DATASIZE, delta);
        }
        // LCOV_EXCL_STOP
    }
    return FDB_RESULT_SUCCESS;
}

void fdb_sync_db_header(fdb_kvs_handle *handle)
{
    uint64_t cur_revnum = filemgr_get_header_revnum(handle->file);
    if (handle->cur_header_revnum != cur_revnum) {
        void *header_buf = NULL;
        size_t header_len;

        handle->last_hdr_bid = filemgr_get_header_bid(handle->file);
        header_buf = filemgr_get_header(handle->file, NULL, &header_len);
        if (header_len > 0) {
            uint64_t header_flags, dummy64;
            bid_t idtree_root;
            bid_t new_seq_root;
            char *compacted_filename;
            char *prev_filename = NULL;

            fdb_fetch_header(header_buf, &idtree_root,
                             &new_seq_root,
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

            if (prev_filename) {
                free(prev_filename);
            }

            handle->cur_header_revnum = cur_revnum;
            handle->dirty_updates = 0;
        }
        if (header_buf) {
            free(header_buf);
        }
    }
}

fdb_status fdb_check_file_reopen(fdb_kvs_handle *handle, file_status_t *status)
{
    fdb_status fs = FDB_RESULT_SUCCESS;
    file_status_t fstatus = filemgr_get_file_status(handle->file);
    // check whether the compaction is done
    if (fstatus == FILE_REMOVED_PENDING) {
        uint64_t ndocs, datasize, nlivenodes, last_wal_flush_hdr_bid;
        uint64_t kv_info_offset, header_flags;
        size_t header_len;
        char *new_filename;
        char *prev_filename = NULL;
        uint8_t *buf = alca(uint8_t, handle->config.blocksize);
        bid_t trie_root_bid, seq_root_bid;
        fdb_config config = handle->config;

        if (handle->new_file) {
            // compacted new file is already opened
            // close the old file
            filemgr_close(handle->file, handle->config.cleanup_cache_onclose,
                          handle->filename, &handle->log_callback);
            // close old docio handle
            docio_free(handle->dhandle);
            free(handle->dhandle);
            // close btree block handle
            fs = btreeblk_end(handle->bhandle);
            btreeblk_free(handle->bhandle);

            // switch to new file & docio handle
            handle->file = handle->new_file;
            handle->new_file = NULL;
            handle->dhandle = handle->new_dhandle;
            handle->new_dhandle = NULL;

            btreeblk_init(handle->bhandle, handle->file, handle->config.blocksize);

            // read new file's header
            handle->last_hdr_bid = filemgr_get_header_bid(handle->file);
            filemgr_get_header(handle->file, buf, &header_len);
            fdb_fetch_header(buf,
                             &trie_root_bid, &seq_root_bid,
                             &ndocs, &nlivenodes, &datasize, &last_wal_flush_hdr_bid,
                             &kv_info_offset, &header_flags,
                             &new_filename, &prev_filename);

            // reset trie (id-tree)
            handle->trie->root_bid = trie_root_bid;
            handle->trie->btreeblk_handle = handle->bhandle;
            handle->trie->doc_handle = handle->dhandle;

            // reset seq tree
            if (handle->config.seqtree_opt == FDB_SEQTREE_USE) {
                if (handle->config.multi_kv_instances) {
                    // multi KV instance mode
                    handle->seqtrie->root_bid = seq_root_bid;
                    handle->seqtrie->btreeblk_handle = handle->bhandle;
                    handle->seqtrie->doc_handle = handle->dhandle;
                } else {
                    if (seq_root_bid != BLK_NOT_FOUND) {
                        btree_init_from_bid(handle->seqtree, (void *)handle->bhandle,
                                            handle->seqtree->blk_ops,
                                            handle->seqtree->kv_ops,
                                            handle->config.blocksize,
                                            seq_root_bid);
                    } else {
                        btree_init(handle->seqtree, (void *)handle->bhandle,
                                   handle->seqtree->blk_ops,
                                   handle->seqtree->kv_ops,
                                   handle->config.blocksize,
                                   sizeof(fdb_seqnum_t),
                                   OFFSET_SIZE, 0x0, NULL);
                    }
                }
            }

            // the others
            handle->cur_header_revnum = filemgr_get_header_revnum(handle->file);
            handle->last_wal_flush_hdr_bid = last_wal_flush_hdr_bid;
            handle->kv_info_offset = kv_info_offset;
            handle->dirty_updates = 0;

            if (prev_filename) {
                free(prev_filename);
            }

            // note that we don't need to call 'compactor_deregister_file'
            // because the old file is already removed when compaction is complete.
            if (!(config.flags & FDB_OPEN_FLAG_RDONLY) &&
                config.compaction_mode == FDB_COMPACTION_AUTO) {
                fs = compactor_register_file(handle->file, &config,
                                             handle->fhandle->cmp_func_list);
            }

        } else {
            // close the current file and newly open the new file
            if (handle->config.compaction_mode == FDB_COMPACTION_AUTO) {
                // compaction daemon mode .. just close and then open
                char filename[FDB_MAX_FILENAME_LEN];
                strcpy(filename, handle->filename);
                fs = _fdb_close(handle);
                fdb_assert(fs == FDB_RESULT_SUCCESS, fs, handle);
                fs = _fdb_open(handle, filename, FDB_VFILENAME, &config);
                fdb_assert(fs == FDB_RESULT_SUCCESS, fs, handle);

            } else {
                filemgr_get_header(handle->file, buf, &header_len);
                fdb_fetch_header(buf,
                                 &trie_root_bid, &seq_root_bid,
                                 &ndocs, &nlivenodes, &datasize, &last_wal_flush_hdr_bid,
                                 &kv_info_offset, &header_flags,
                                 &new_filename, NULL);
                fs = _fdb_close(handle);
                fdb_assert(fs == FDB_RESULT_SUCCESS, fs, handle);
                fs = _fdb_open(handle, new_filename, FDB_AFILENAME, &config);
                fdb_assert(fs == FDB_RESULT_SUCCESS, fs, handle);
            }
        }
    }
    if (status) {
        *status = fstatus;
    }
    return fs;
}

INLINE void _fdb_link_new_file(fdb_kvs_handle *handle)
{
    fdb_assert(handle->file->new_file, handle, handle->file);

    // open new file and new dhandle
    filemgr_open_result result = filemgr_open(handle->file->new_file->filename,
                                              handle->fileops, handle->file->config,
                                              &handle->log_callback);
    handle->new_file = result.file;
    handle->new_dhandle = (struct docio_handle *)
                          calloc(1, sizeof(struct docio_handle));
    handle->new_dhandle->log_callback = &handle->log_callback;
    docio_init(handle->new_dhandle,
               handle->new_file,
               handle->config.compress_document_body);
}

void fdb_link_new_file(fdb_kvs_handle *handle)
{
    // check whether this file is being compacted
    if (!handle->new_file &&
        filemgr_get_file_status(handle->file) == FILE_COMPACT_OLD) {
        _fdb_link_new_file(handle);
    }
}

void fdb_link_new_file_enforce(fdb_kvs_handle *handle)
{
    if (!handle->new_file) {
        _fdb_link_new_file(handle);
    }
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
                    handle->seqtree->root_bid = dirty_seqtree_root;
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
    fdb_doc doc_kv = *doc;

    if (!handle || !doc || !doc->key || doc->keylen == 0 ||
        doc->keylen > FDB_MAX_KEYLEN ||
        (handle->kvs_config.custom_cmp &&
            doc->keylen > handle->config.blocksize - HBTRIE_HEADROOM)) {
        return FDB_RESULT_INVALID_ARGS;
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
        fdb_link_new_file(handle);
        fdb_sync_db_header(handle);

        if (handle->new_file == NULL) {
            wal_file = handle->file;
        }else{
            wal_file = handle->new_file;
        }
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
    } else {
        if (handle->kvs) {
            wr = snap_find(handle->shandle, &doc_kv, &offset);
        } else {
            wr = snap_find(handle->shandle, doc, &offset);
        }
        if (wr != FDB_RESULT_SUCCESS ||
            handle->shandle->type == FDB_SNAP_NORMAL) {
            dhandle = handle->dhandle;
        } else { // FDB_SNAP_COMPACTION
            dhandle = handle->new_dhandle;
        }
    }

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
    } else {
        if (wal_file == handle->new_file && !handle->shandle) {
            dhandle = handle->new_dhandle;
        }
    }

    if (wr == FDB_RESULT_SUCCESS || hr != HBTRIE_RESULT_FAIL) {
        if (handle->kvs) {
            _doc.key = doc_kv.key;
            _doc.length.keylen = doc_kv.keylen;
        } else {
            _doc.key = doc->key;
            _doc.length.keylen = doc->keylen;
        }
        _doc.meta = doc->meta;
        _doc.body = doc->body;

        if (wr == FDB_RESULT_SUCCESS && doc->deleted) {
            return FDB_RESULT_KEY_NOT_FOUND;
        }

        _offset = docio_read_doc(dhandle, offset, &_doc);
        if (_offset == offset) {
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

        if (_doc.length.keylen != doc_kv.keylen ||
            _doc.length.flag & DOCIO_DELETED) {
            return FDB_RESULT_KEY_NOT_FOUND;
        }

        return FDB_RESULT_SUCCESS;
    }

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
    fdb_doc doc_kv = *doc;

    if (!handle || !doc || !doc->key ||
        doc->keylen == 0 || doc->keylen > FDB_MAX_KEYLEN ||
        (handle->kvs_config.custom_cmp &&
            doc->keylen > handle->config.blocksize - HBTRIE_HEADROOM)) {
        return FDB_RESULT_INVALID_ARGS;
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
        fdb_link_new_file(handle);
        fdb_sync_db_header(handle);

        if (handle->new_file == NULL) {
            wal_file = handle->file;
        }else{
            wal_file = handle->new_file;
        }
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
    } else {
        if (handle->kvs) {
            wr = snap_find(handle->shandle, &doc_kv, &offset);
        } else {
            wr = snap_find(handle->shandle, doc, &offset);
        }
        if (wr != FDB_RESULT_SUCCESS ||
            handle->shandle->type == FDB_SNAP_NORMAL) {
            dhandle = handle->dhandle;
        } else { // FDB_SNAP_COMPACTION
            dhandle = handle->new_dhandle;
        }
    }

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
    } else {
        if (wal_file == handle->new_file && !handle->shandle) {
            dhandle = handle->new_dhandle;
        }
    }

    if (wr == FDB_RESULT_SUCCESS || hr != HBTRIE_RESULT_FAIL) {
        if (handle->kvs) {
            _doc.key = doc_kv.key;
            _doc.length.keylen = doc_kv.keylen;
        } else {
            _doc.key = doc->key;
            _doc.length.keylen = doc->keylen;
        }
        _doc.meta = doc->meta;
        _doc.body = doc->body;

        uint64_t body_offset = docio_read_doc_key_meta(dhandle, offset, &_doc);
        if (body_offset == offset){
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

        if (_doc.length.keylen != doc_kv.keylen) {
            return FDB_RESULT_KEY_NOT_FOUND;
        }

        return FDB_RESULT_SUCCESS;
    }

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

    if (!handle || !doc || doc->seqnum == SEQNUM_NOT_USED) {
        return FDB_RESULT_INVALID_ARGS;
    }

    // Sequence trees are a must for byseq operations
    if (handle->config.seqtree_opt != FDB_SEQTREE_USE) {
        return FDB_RESULT_INVALID_CONFIG;
    }

    if (!handle->shandle) {
        fdb_check_file_reopen(handle, NULL);
        fdb_link_new_file(handle);
        fdb_sync_db_header(handle);

        if (handle->new_file == NULL) {
            wal_file = handle->file;
        }else{
            wal_file = handle->new_file;
        }
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
    } else {
        wr = snap_find(handle->shandle, doc, &offset);
        if (wr != FDB_RESULT_SUCCESS ||
            handle->shandle->type == FDB_SNAP_NORMAL) {
            dhandle = handle->dhandle;
        } else { // FDB_SNAP_COMPACTION
            dhandle = handle->new_dhandle;
        }
    }

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
    } else {
        if (wal_file == handle->new_file && !handle->shandle) {
            dhandle = handle->new_dhandle;
        }
    }

    if (wr == FDB_RESULT_SUCCESS || br != BTREE_RESULT_FAIL) {
        if (!handle->kvs) { // single KVS mode
            _doc.key = doc->key;
            _doc.length.keylen = doc->keylen;
        } else {
            _doc.key = NULL;
        }
        _doc.meta = doc->meta;
        _doc.body = doc->body;

        if (wr == FDB_RESULT_SUCCESS && doc->deleted) {
            return FDB_RESULT_KEY_NOT_FOUND;
        }

        _offset = docio_read_doc(dhandle, offset, &_doc);
        if (_offset == offset) {
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

        if (_doc.length.flag & DOCIO_DELETED) {
            return FDB_RESULT_KEY_NOT_FOUND;
        }

        fdb_assert(doc->seqnum == _doc.seqnum, doc->seqnum, _doc.seqnum);

        return FDB_RESULT_SUCCESS;
    }

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

    if (!handle->shandle) {
        fdb_check_file_reopen(handle, NULL);
        fdb_link_new_file(handle);
        fdb_sync_db_header(handle);

        if (handle->new_file == NULL) {
            wal_file = handle->file;
        } else {
            wal_file = handle->new_file;
        }
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
    } else {
        wr = snap_find(handle->shandle, doc, &offset);
        if (wr != FDB_RESULT_SUCCESS ||
            handle->shandle->type == FDB_SNAP_NORMAL) {
            dhandle = handle->dhandle;
        } else { // FDB_SNAP_COMPACTION
            dhandle = handle->new_dhandle;
        }
    }

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
    } else {
        if (wal_file == handle->new_file && !handle->shandle) {
            dhandle = handle->new_dhandle;
        }
    }

    if (wr == FDB_RESULT_SUCCESS || br != BTREE_RESULT_FAIL) {
        if (!handle->kvs) { // single KVS mode
            _doc.key = doc->key;
            _doc.length.keylen = doc->keylen;
        } else {
            _doc.key = NULL;
        }
        _doc.meta = doc->meta;
        _doc.body = doc->body;

        uint64_t body_offset = docio_read_doc_key_meta(dhandle, offset, &_doc);
        if (body_offset == offset) {
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

        fdb_assert(doc->seqnum == _doc.seqnum, doc->seqnum, _doc.seqnum);

        return FDB_RESULT_SUCCESS;
    }

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

    if (!offset) {
        return FDB_RESULT_INVALID_ARGS;
    }

    memset(&_doc, 0, sizeof(struct docio_object));

    uint64_t _offset = docio_read_doc(handle->dhandle, offset, &_doc);
    if (_offset == offset) {
        if (handle->new_dhandle && !handle->shandle) {
            // Look up the new file being compacted
            _offset = docio_read_doc(handle->new_dhandle, offset, &_doc);
            if (_offset == offset) {
                return FDB_RESULT_KEY_NOT_FOUND;
            }
            if (handle->kvs) {
                _remove_kv_id(handle, &_doc);
            }
            if (!equal_docs(doc, &_doc)) {
                free_docio_object(&_doc, 1, 1, 1);
                return FDB_RESULT_KEY_NOT_FOUND;
            }
        } else {
            return FDB_RESULT_KEY_NOT_FOUND;
        }
    } else {
        if (handle->kvs) {
            _remove_kv_id(handle, &_doc);
        }
        if (!equal_docs(doc, &_doc)) {
            free_docio_object(&_doc, 1, 1, 1);
            if (handle->new_dhandle && !handle->shandle) {
                // Look up the new file being compacted
                _offset = docio_read_doc(handle->new_dhandle, offset, &_doc);
                if (_offset == offset) {
                    return FDB_RESULT_KEY_NOT_FOUND;
                }
                if (handle->kvs) {
                    _remove_kv_id(handle, &_doc);
                }
                if (!equal_docs(doc, &_doc)) {
                    free_docio_object(&_doc, 1, 1, 1);
                    return FDB_RESULT_KEY_NOT_FOUND;
                }
            } else {
                return FDB_RESULT_KEY_NOT_FOUND;
            }
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
        return FDB_RESULT_KEY_NOT_FOUND;
    }

    return FDB_RESULT_SUCCESS;
}

static uint64_t _fdb_get_wal_threshold(fdb_kvs_handle *handle)
{
    if (filemgr_get_file_status(handle->file) == FILE_COMPACT_NEW) {
        return wal_get_size(handle->file);
    }
    return handle->config.wal_threshold;
}

LIBFDB_API
fdb_status fdb_set(fdb_kvs_handle *handle, fdb_doc *doc)
{
    int mmap_alloc = 0;
    uint64_t offset;
    struct docio_object _doc;
    struct filemgr *file;
    struct docio_handle *dhandle;
    struct timeval tv;
    bool txn_enabled = false;
    bool sub_handle = false;
    bool wal_flushed = false;
    file_status_t fstatus;
    fdb_txn *txn = handle->fhandle->root->txn;
    fdb_status wr = FDB_RESULT_SUCCESS;

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
    filemgr_mutex_lock(handle->file);
    fdb_sync_db_header(handle);
    fdb_link_new_file(handle);

    if (filemgr_is_rollback_on(handle->file)) {
        filemgr_mutex_unlock(handle->file);
        return FDB_RESULT_FAIL_BY_ROLLBACK;
    }

    if (handle->new_file == NULL) {
        file = handle->file;
        dhandle = handle->dhandle;
    } else {
        // compaction is being performed and new file exists
        // relay lock
        filemgr_mutex_lock(handle->new_file);
        filemgr_mutex_unlock(handle->file);
        file = handle->new_file;
        dhandle = handle->new_dhandle;
    }

    fstatus = filemgr_get_file_status(file);
    if (!(fstatus == FILE_NORMAL ||
          fstatus == FILE_COMPACT_NEW ||
          fstatus == FILE_COMPACT_INPROG)) {
        // we must not write into this file
        // file status was changed by other thread .. start over
        filemgr_mutex_unlock(file);
        goto fdb_set_start;
    }

    if (sub_handle) {
        // multiple KV instance mode AND sub handle
        handle->seqnum = fdb_kvs_get_seqnum(file, handle->kvs->id) + 1;
        fdb_kvs_set_seqnum(file, handle->kvs->id, handle->seqnum);
    } else {
        // super handle OR single KV instnace mode
        handle->seqnum = filemgr_get_seqnum(file) + 1;
        filemgr_set_seqnum(file, handle->seqnum);
    }
    _doc.seqnum = doc->seqnum = handle->seqnum;

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
    if (dhandle == handle->new_dhandle) {
        offset = docio_append_doc_compact(dhandle, &_doc, doc->deleted, txn_enabled);
    } else {
        offset = docio_append_doc(dhandle, &_doc, doc->deleted, txn_enabled);
    }
    if (offset == BLK_NOT_FOUND) {
        filemgr_mutex_unlock(file);
        return FDB_RESULT_WRITE_FAIL;
    }

    doc->size_ondisk = _fdb_get_docsize(_doc.length);
    doc->offset = offset;
    if (!txn) {
        txn = &file->global_txn;
    }
    if (file == handle->new_file &&
        filemgr_get_file_status(file) == FILE_COMPACT_NEW) {
        // compaction is in progress
        mmap_alloc = 1;
    }
    if (handle->kvs) {
        // multi KV instance mode
        fdb_doc kv_ins_doc = *doc;
        kv_ins_doc.key = _doc.key;
        kv_ins_doc.keylen = _doc.length.keylen;
        wal_insert(txn, file, &kv_ins_doc, offset, 0, mmap_alloc);
    } else {
        wal_insert(txn, file, doc, offset, 0, mmap_alloc);
    }

    if (wal_get_dirty_status(file)== FDB_WAL_CLEAN) {
        wal_set_dirty_status(file, FDB_WAL_DIRTY);
    }

    if ((handle->config.wal_flush_before_commit ||
         handle->config.auto_commit) &&
        filemgr_get_file_status(handle->file) == FILE_NORMAL) {
        bid_t dirty_idtree_root, dirty_seqtree_root;

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
                handle->seqtree->root_bid = dirty_seqtree_root;
            }
        }

        if (wal_get_num_flushable(file) > _fdb_get_wal_threshold(handle)) {
            struct avl_tree flush_items;

            // discard all cached writable blocks
            // to avoid data inconsistency with other writers
            btreeblk_discard_blocks(handle->bhandle);

            // commit only for non-transactional WAL entries
            wr = wal_commit(&file->global_txn, file, NULL);
            if (wr != FDB_RESULT_SUCCESS) {
                filemgr_mutex_unlock(file);
                return wr;
            }
            wr = wal_flush(file, (void *)handle,
                      _fdb_wal_flush_func, _fdb_wal_get_old_offset,
                      &flush_items);
            if (wr != FDB_RESULT_SUCCESS) {
                filemgr_mutex_unlock(file);
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

    if (wal_flushed && handle->config.auto_commit) {
        return fdb_commit(handle->fhandle, FDB_COMMIT_NORMAL);
    }
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

uint64_t fdb_set_file_header(fdb_kvs_handle *handle)
{
    /*
    <ForestDB header>
    [offset]: (description)
    [     0]: BID of root node of root B+Tree of HB+Trie: 8 bytes
    [     8]: BID of root node of seq B+Tree: 8 bytes (0xFF.. if not used)
    [    16]: # of live documents: 8 bytes
    [    24]: # of live B+Tree nodes: 8 bytes
    [    32]: Data size (byte): 8 bytes
    [    40]: BID of the DB header created when last WAL flush: 8 bytes
    [    48]: Offset of the document containing KV instances' info: 8 bytes
    [    56]: Header flags: 8 bytes
    [    64]: Size of newly compacted target file name : 2 bytes
    [    66]: Size of old file name before compaction :  2 bytes
    [    68]: File name of newly compacted file : x bytes
    [  68+x]: File name of old file before compcation : y bytes
    [68+x+y]: CRC32: 4 bytes
    total size (header's length): 72+x+y bytes

    Note: the list of functions that need to be modified
          if the header structure is changed:

        _fdb_redirect_header() in forestdb.cc
        filemgr_destory_file() in filemgr.cc
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

    // get stat
    _kvs_stat_get(cur_file, 0, &stat);

    // # docs
    _edn_safe_64 = _endian_encode(stat.ndocs);
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
    crc = chksum(buf, offset);
    crc = _endian_encode(crc);
    seq_memcpy(buf + offset, &crc, sizeof(crc), offset);

    return filemgr_update_header(handle->file, buf, offset);
}

static
char *_fdb_redirect_header(uint8_t *buf, char *new_filename,
                                 uint16_t new_filename_len) {
    uint16_t old_compact_filename_len; // size of existing old_filename in buf
    uint16_t new_compact_filename_len; // size of existing new_filename in buf
    uint16_t new_filename_len_enc = _endian_encode(new_filename_len);
    uint32_t crc;
    size_t crc_offset;
    size_t offset = 64;
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
    memcpy(buf + 64, &new_filename_len_enc, sizeof(uint16_t));

    // Copy over existing DB header's old_filename to its new location
    old_filename = (char*)buf + offset + new_filename_len;
    if (new_compact_filename_len != new_filename_len) {
        memmove(old_filename, buf + offset + new_compact_filename_len,
                old_compact_filename_len);
    }
    // Update the DB header's new_filename to the redirected one
    memcpy(buf + 68, new_filename, new_filename_len);
    // Compute the DB header's new crc32 value
    crc_offset = 68 + new_filename_len + old_compact_filename_len;
    crc = chksum(buf, crc_offset);
    crc = _endian_encode(crc);
    // Update the DB header's new crc32 value
    memcpy(buf + crc_offset, &crc, sizeof(crc));
    // If the DB header indicated an old_filename, return it
    return old_compact_filename_len ? old_filename : NULL;
}

static fdb_status _fdb_append_commit_mark(void *voidhandle, uint64_t offset)
{
    fdb_kvs_handle *handle = (fdb_kvs_handle *)voidhandle;
    struct docio_handle *dhandle;

    if (handle->new_file) {
        dhandle = handle->new_dhandle;
    } else {
        dhandle = handle->dhandle;
    }
    if (docio_append_commit_mark(dhandle, offset) == BLK_NOT_FOUND) {
        return FDB_RESULT_WRITE_FAIL;
    }
    return FDB_RESULT_SUCCESS;
}

LIBFDB_API
fdb_status fdb_commit(fdb_file_handle *fhandle, fdb_commit_opt_t opt)
{
    return _fdb_commit(fhandle->root, opt);
}

fdb_status _fdb_commit(fdb_kvs_handle *handle, fdb_commit_opt_t opt)
{
    fdb_txn *txn = handle->fhandle->root->txn;
    fdb_txn *earliest_txn;
    fdb_status fs = FDB_RESULT_SUCCESS;
    bool wal_flushed = false;
    bid_t dirty_idtree_root, dirty_seqtree_root;
    struct avl_tree flush_items;
    fdb_status wr = FDB_RESULT_SUCCESS;

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

    fdb_check_file_reopen(handle, NULL);

    filemgr_mutex_lock(handle->file);
    fdb_sync_db_header(handle);
    fdb_link_new_file(handle);

    if (filemgr_is_rollback_on(handle->file)) {
        filemgr_mutex_unlock(handle->file);
        return FDB_RESULT_FAIL_BY_ROLLBACK;
    }

    if (handle->new_file) {
        // HANDLE->FILE is undergoing compaction ..
        // just do fsync to HANDLE->NEW_FILE

        // relay lock
        filemgr_mutex_lock(handle->new_file);
        filemgr_mutex_unlock(handle->file);

        if (txn) {
            // transactional updates
            wr = wal_commit(txn, handle->new_file, _fdb_append_commit_mark);
            if (wr != FDB_RESULT_SUCCESS) {
                filemgr_mutex_unlock(handle->new_file);
                return wr;
            }
        } else {
            // non-transactional updates
            wal_commit(&handle->new_file->global_txn, handle->new_file, NULL);
        }

        fs = filemgr_sync(handle->new_file, &handle->log_callback);

        filemgr_mutex_unlock(handle->new_file);
    } else {
        // normal case
        fs = btreeblk_end(handle->bhandle);
        if (fs != FDB_RESULT_SUCCESS) {
            filemgr_mutex_unlock(handle->file);
            return fs;
        }

        // commit wal
        if (txn) {
            // transactional updates
            wr = wal_commit(txn, handle->file, _fdb_append_commit_mark);
            if (wr != FDB_RESULT_SUCCESS) {
                filemgr_mutex_unlock(handle->file);
                return wr;
            }
            if (wal_get_dirty_status(handle->file)== FDB_WAL_CLEAN) {
                wal_set_dirty_status(handle->file, FDB_WAL_DIRTY);
            }
        } else {
            // non-transactional updates
            wal_commit(&handle->file->global_txn, handle->file, NULL);
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
                handle->seqtree->root_bid = dirty_seqtree_root;
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
            handle->kv_info_offset = fdb_kvs_header_append(handle->file,
                                                           handle->dhandle);
        }

        // Note: Getting header BID must be done after
        //       all other data are written into the file!!
        //       Or, header BID inconsistency will occur (it will
        //       point to wrong block).
        handle->last_hdr_bid = filemgr_get_next_alloc_block(handle->file);
        if (wal_get_dirty_status(handle->file) == FDB_WAL_CLEAN) {
            earliest_txn = wal_earliest_txn(handle->file,
                                            (txn)?(txn):(&handle->file->global_txn));
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

        fdb_assert(handle->last_wal_flush_hdr_bid == BLK_NOT_FOUND ||
               handle->last_wal_flush_hdr_bid <= handle->last_hdr_bid,
               handle->last_wal_flush_hdr_bid, handle->last_hdr_bid);

        if (txn == NULL) {
            // update global_txn's previous header BID
            handle->file->global_txn.prev_hdr_bid = handle->last_hdr_bid;
        }

        handle->cur_header_revnum = fdb_set_file_header(handle);
        fs = filemgr_commit(handle->file, &handle->log_callback);
        if (wal_flushed) {
            wal_release_flushed_items(handle->file, &flush_items);
        }

        btreeblk_reset_subblock_info(handle->bhandle);

        handle->dirty_updates = 0;
        filemgr_mutex_unlock(handle->file);
    }

    return fs;
}

static fdb_status _fdb_commit_and_remove_pending(fdb_kvs_handle *handle,
                                           struct filemgr *old_file,
                                           struct filemgr *new_file)
{
    fdb_txn *earliest_txn;
    bool wal_flushed = false;
    bid_t dirty_idtree_root, dirty_seqtree_root;
    struct avl_tree flush_items;
    fdb_status status = FDB_RESULT_SUCCESS;
    struct filemgr *very_old_file;

    do { // Find all files pointing to old_file and redirect them to new file..
        very_old_file = filemgr_search_stale_links(old_file);
        if (very_old_file) {
            filemgr_redirect_old_file(very_old_file, new_file,
                                      _fdb_redirect_header);
            filemgr_commit(very_old_file, &handle->log_callback);
            // I/O errors here are not propogated since this is best-effort
            // Since filemgr_search_stale_links() will have opened the file
            // we must close it here to ensure decrement of ref counter
            filemgr_close(very_old_file, 1, very_old_file->filename,
                          &handle->log_callback);
        }
    } while (very_old_file);

    filemgr_mutex_lock(handle->file);

    btreeblk_end(handle->bhandle);

    // sync dirty root nodes
    filemgr_get_dirty_root(handle->file, &dirty_idtree_root, &dirty_seqtree_root);
    if (dirty_idtree_root != BLK_NOT_FOUND) {
        handle->trie->root_bid = dirty_idtree_root;
    }
    if (handle->config.seqtree_opt == FDB_SEQTREE_USE &&
        dirty_seqtree_root != BLK_NOT_FOUND) {
        if (handle->kvs) {
            handle->seqtrie->root_bid = dirty_seqtree_root;
        } else {
            handle->seqtree->root_bid = dirty_seqtree_root;
        }
    }

    wal_commit(&handle->file->global_txn, handle->file, NULL);
    if (wal_get_num_flushable(handle->file)) {
        // flush wal if not empty
        wal_flush(handle->file, (void *)handle,
                  _fdb_wal_flush_func, _fdb_wal_get_old_offset, &flush_items);
        wal_set_dirty_status(handle->file, FDB_WAL_CLEAN);
        wal_flushed = true;
    } else if (wal_get_size(handle->file) == 0) {
        // empty WAL
        wal_set_dirty_status(handle->file, FDB_WAL_CLEAN);
    }

    // Note: Appending KVS header must be done after flushing WAL
    //       because KVS stats info is updated during WAL flushing.
    if (handle->kvs) {
        // multi KV instance mode .. append up-to-date KV header
        handle->kv_info_offset = fdb_kvs_header_append(handle->file,
                                                       handle->dhandle);
    }

    handle->last_hdr_bid = filemgr_get_next_alloc_block(handle->file);
    if (wal_get_dirty_status(handle->file) == FDB_WAL_CLEAN) {
        earliest_txn = wal_earliest_txn(handle->file,
                                        &handle->file->global_txn);
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
    handle->file->global_txn.prev_hdr_bid = handle->last_hdr_bid;

    handle->cur_header_revnum = fdb_set_file_header(handle);
    status = filemgr_commit(handle->file, &handle->log_callback);
    if (status != FDB_RESULT_SUCCESS) {
        filemgr_mutex_unlock(handle->file);
        return status;
    }

    if (wal_flushed) {
        wal_release_flushed_items(handle->file, &flush_items);
    }
    wal_release_keystr_files(handle->file);

    // Mark the old file as "remove_pending".
    // Note that a file deletion will be pended until there is no handle
    // referring the file.
    filemgr_remove_pending(old_file, new_file);

    // Don't clean up the buffer cache entries for the old file.
    // They will be cleaned up later.
    filemgr_close(old_file, 0, handle->filename, &handle->log_callback);

    filemgr_mutex_unlock(handle->file);
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
                                     struct hbtrie *new_seqtrie,
                                     struct btree *new_seqtree,
                                     struct docio_handle *new_dhandle,
                                     struct btreeblk_handle *new_bhandle)
{
    struct timeval tv;
    fdb_kvs_handle new_handle;
    timestamp_t cur_timestamp;
    uint32_t blocksize = handle->file->blocksize;
    uint64_t offset; // starting point
    uint64_t new_offset;
    uint64_t stop_offset = stop_bid * blocksize; // stopping point
    uint64_t n_moved_docs = 0;
    err_log_callback *log_callback;
    fdb_status fs = FDB_RESULT_SUCCESS;

    if (start_bid == BLK_NOT_FOUND || start_bid == stop_bid) {
        return fs;
    } else {
        offset = (start_bid + 1) * blocksize;
    }

    gettimeofday(&tv, NULL);
    cur_timestamp = tv.tv_sec;

    // TODO: Need to adapt docio_read_doc to separate false checksum errors.
    log_callback = handle->dhandle->log_callback;
    handle->dhandle->log_callback = NULL;

    for (; offset < stop_offset;
        offset = ((offset / blocksize) + 1) * blocksize) { // next block's off
        if (!docio_check_buffer(handle->dhandle, offset / blocksize)) {
            continue;
        } else {
            do {
                fdb_doc wal_doc;
                uint8_t deleted;
                struct docio_object doc;
                uint64_t _offset;
                memset(&doc, 0, sizeof(doc));
                _offset = docio_read_doc(handle->dhandle, offset, &doc);
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
                    docio_read_doc(handle->dhandle, doc.doc_offset, &doc);
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
                // compare timestamp
                // Do not re-write the document to new file if
                // 1. the document is deleted OR
                // 2. the document is not logically deleted but
                //    its timestamp is overdue
                deleted = doc.length.flag & DOCIO_DELETED;
                if (deleted && cur_timestamp >= doc.timestamp
                                + handle->config.purging_interval) {
                    free(doc.key);
                    free(doc.meta);
                    free(doc.body);
                    offset = _offset;
                    continue;
                }
                // Re-Write Document to the new file
                new_offset = docio_append_doc(new_dhandle, &doc, deleted, 0);
                if (new_offset == BLK_NOT_FOUND) {
                    free(doc.key);
                    free(doc.meta);
                    free(doc.body);
                    return FDB_RESULT_WRITE_FAIL;
                }

                // Restore the document into the WAL section of new file..
                wal_doc.keylen = doc.length.keylen;
                wal_doc.metalen = doc.length.metalen;
                wal_doc.bodylen = doc.length.bodylen;
                wal_doc.key = doc.key;
                wal_doc.meta = doc.meta;
                wal_doc.seqnum = doc.seqnum;
                wal_doc.deleted = deleted;
                wal_doc.size_ondisk = _fdb_get_docsize(doc.length);

                // In order to avoid that
                // doc with same key (but newer one) is inserted into WAL again
                // (wal_insert by compactor will ignore duplicated doc),
                // we insert the document into WAL as a normal writer.
                // Note that there is no cuncurrent writer since
                // filemgr_mutex is already being held by the caller function.
                wal_insert(&new_file->global_txn,
                           new_file, &wal_doc, new_offset, 0, 0);

                n_moved_docs++;
                free(doc.key);
                free(doc.meta);
                free(doc.body);
                offset = _offset;
            } while (offset + sizeof(struct docio_length) < stop_offset);
        }
    }

    // wal flush into new file so all documents are reflected in its main index
    if (n_moved_docs) {
        struct avl_tree flush_items;
        new_handle = *handle;
        new_handle.file = new_file;
        new_handle.trie = new_trie;
        new_handle.idtree = new_idtree;
        if (handle->kvs) {
            new_handle.seqtrie = new_seqtrie;
        } else {
            new_handle.seqtree = new_seqtree;
        }
        new_handle.dhandle = new_dhandle;
        new_handle.bhandle = new_bhandle;

        wal_commit(&new_file->global_txn, new_file, NULL);
        wal_flush(new_file, (void*)&new_handle,
                  _fdb_wal_flush_func, _fdb_wal_get_old_offset,
                  &flush_items);
        wal_set_dirty_status(new_file, FDB_WAL_PENDING);
        wal_release_flushed_items(new_file, &flush_items);
    }

    return fs;
}

static fdb_status _fdb_compact_move_docs(fdb_kvs_handle *handle,
                                         struct filemgr *new_file,
                                         struct hbtrie *new_trie,
                                         struct btree *new_idtree,
                                         struct btree *new_seqtree,
                                         struct docio_handle *new_dhandle,
                                         struct btreeblk_handle *new_bhandle,
                                         bool got_lock)
{
    uint8_t deleted;
    uint64_t window_size;
    uint64_t offset, _offset;
    uint64_t old_offset, new_offset;
    uint64_t *offset_array, *old_offset_array;
    uint64_t n_moved_docs, n_buf, n_docs_in_wal;
    uint64_t sum_docsize;
    size_t i, j, c, count;
    size_t offset_array_max;
    hbtrie_result hr;
    struct docio_object *doc;
    struct hbtrie_iterator it;
    struct timeval tv;
    fdb_doc wal_doc;
    fdb_kvs_handle new_handle;
    timestamp_t cur_timestamp;
    fdb_status fs = FDB_RESULT_SUCCESS;

    if (handle->config.compaction_cb &&
        handle->config.compaction_cb_mask & FDB_CS_BEGIN) {
        handle->config.compaction_cb(handle->fhandle, FDB_CS_BEGIN, NULL, 0, 0,
                                     handle->config.compaction_cb_ctx);
    }

    gettimeofday(&tv, NULL);
    cur_timestamp = tv.tv_sec;

    new_handle = *handle;
    new_handle.file = new_file;
    new_handle.trie = new_trie;
    new_handle.idtree = new_idtree;
    if (handle->kvs) {
        new_handle.seqtrie = (struct hbtrie *)new_seqtree;
    } else {
        new_handle.seqtree = new_seqtree;
    }
    new_handle.dhandle = new_dhandle;
    new_handle.bhandle = new_bhandle;

    // 1/10 of the block cache size
    // if block cache is disabled, set to the minimum size
    window_size = handle->config.buffercache_size / 10;
    if (window_size < FDB_COMP_BUF_MINSIZE) {
        window_size = FDB_COMP_BUF_MINSIZE;
    } else if (window_size > FDB_COMP_BUF_MAXSIZE) {
        window_size = FDB_COMP_BUF_MAXSIZE;
    }

    offset_array_max = window_size / sizeof(uint64_t);
    offset_array = (uint64_t*)malloc(sizeof(uint64_t) * offset_array_max);

    doc = (struct docio_object *)
          malloc(sizeof(struct docio_object) * FDB_COMP_BATCHSIZE);
    old_offset_array = (uint64_t*)malloc(sizeof(uint64_t) * FDB_COMP_BATCHSIZE);
    c = count = n_moved_docs = old_offset = new_offset = 0;

    hr = hbtrie_iterator_init(handle->trie, &it, NULL, 0);

    while( hr != HBTRIE_RESULT_FAIL ) {

        hr = hbtrie_next_value_only(&it, (void*)&offset);
        fs = btreeblk_end(handle->bhandle);
        if (fs != FDB_RESULT_SUCCESS) {
            hbtrie_iterator_free(&it);
            free(offset_array);
            free(old_offset_array);
            free(doc);
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

            // 1) read all documents in offset_array, and
            // 2) move them into the new file.
            // 3) flush WAL periodically
            n_moved_docs = n_docs_in_wal = i = 0;
            do {
                // === read docs from the old file ===
                sum_docsize = n_buf = 0;
                do {
                    offset = offset_array[i++];
                    memset(&doc[n_buf], 0x0, sizeof(struct docio_object));

                    _offset = docio_read_doc(handle->dhandle, offset, &doc[n_buf]);
                    if (_offset == offset) {
                        // read fail, skip this doc
                        continue;
                    }
                    old_offset_array[n_buf] = offset;
                    sum_docsize += _fdb_get_docsize(doc[n_buf].length);
                    n_buf++;
                    // escape when
                    // 1) sum of doc size exceeds the move unit, OR
                    // 2) # docs exceeds the batch size, OR
                    // 3) no more offset in the offset_array
                } while (sum_docsize < FDB_COMP_MOVE_UNIT &&
                         n_buf < FDB_COMP_BATCHSIZE       &&
                         i < c);

                // === write docs into the new file ===
                if (!got_lock) {
                    filemgr_mutex_lock(new_file);
                }
                for (j=0; j<n_buf; ++j) {
                    // compare timestamp
                    deleted = doc[j].length.flag & DOCIO_DELETED;
                    if (!deleted ||
                        (cur_timestamp < doc[j].timestamp +
                                         handle->config.purging_interval &&
                         deleted)) {
                        // re-write the document to new file when
                        // 1. the document is not deleted
                        // 2. the document is logically deleted but
                        //    its timestamp isn't overdue
                        new_offset = docio_append_doc(new_dhandle, &doc[j],
                                                      deleted, 0);
                        old_offset = old_offset_array[j];

                        wal_doc.keylen = doc[j].length.keylen;
                        wal_doc.metalen = doc[j].length.metalen;
                        wal_doc.bodylen = doc[j].length.bodylen;
                        wal_doc.key = doc[j].key;
                        wal_doc.seqnum = doc[j].seqnum;

                        wal_doc.meta = doc[j].meta;
                        wal_doc.body = doc[j].body;
                        wal_doc.size_ondisk= _fdb_get_docsize(doc[j].length);
                        wal_doc.deleted = deleted;
                        wal_doc.offset = new_offset;

                        wal_insert(&new_file->global_txn,
                                   new_file, &wal_doc, new_offset, 1, 0);
                        n_moved_docs++;
                        n_docs_in_wal++;

                        if (handle->config.compaction_cb &&
                            handle->config.compaction_cb_mask & FDB_CS_MOVE_DOC) {
                            if (!got_lock) {
                                filemgr_mutex_unlock(new_file);
                            }
                            handle->config.compaction_cb(
                                handle->fhandle, FDB_CS_MOVE_DOC,
                                &wal_doc, old_offset, new_offset,
                                handle->config.compaction_cb_ctx);
                            if (!got_lock) {
                                filemgr_mutex_lock(new_file);
                            }
                        }
                    }
                    free(doc[j].key);
                    free(doc[j].meta);
                    free(doc[j].body);
                }
                if (!got_lock) {
                    filemgr_mutex_unlock(new_file);
                }
                if (handle->config.compaction_cb &&
                    handle->config.compaction_cb_mask & FDB_CS_BATCH_MOVE) {
                    handle->config.compaction_cb(handle->fhandle,
                                                 FDB_CS_BATCH_MOVE, NULL,
                                                 old_offset, new_offset,
                                                 handle->config.compaction_cb_ctx);
                }

                // === flush WAL entries by compactor ===
                // flush WAL when
                // 1) # docs in WAL exceeds the threshold, OR
                // 2) there is no more offset in offset_array
                if ( (n_docs_in_wal > FDB_COMP_WAL_FLUSH || i >= c)  &&
                      wal_get_num_flushable(new_file) > 0 ) {

                    struct avl_tree flush_items;
                    wal_flush_by_compactor(new_file, (void*)&new_handle,
                                           _fdb_wal_flush_func,
                                           _fdb_wal_get_old_offset,
                                           &flush_items);
                    wal_set_dirty_status(new_file, FDB_WAL_PENDING);
                    wal_release_flushed_items(new_file, &flush_items);
                    n_docs_in_wal = 0;

                    if (handle->config.compaction_cb &&
                        handle->config.compaction_cb_mask & FDB_CS_FLUSH_WAL) {
                        handle->config.compaction_cb(handle->fhandle,
                                                     FDB_CS_FLUSH_WAL, NULL,
                                                     old_offset, new_offset,
                                                     handle->config.compaction_cb_ctx);
                    }
                }

                // If the rollback operation is issued, abort the compaction task.
                if (filemgr_is_rollback_on(handle->file)) {
                    fs = FDB_RESULT_FAIL_BY_ROLLBACK;
                    break;
                }

                // repeat until no more offset in the offset_array
            } while (i < c);
            // reset offset_array
            c = 0;
        }
        if (fs == FDB_RESULT_FAIL_BY_ROLLBACK) {
            break;
        }
    }

    hbtrie_iterator_free(&it);
    free(offset_array);
    free(old_offset_array);
    free(doc);

    if (handle->config.compaction_cb &&
        handle->config.compaction_cb_mask & FDB_CS_END) {
        handle->config.compaction_cb(handle->fhandle, FDB_CS_END,
                                     NULL, old_offset, new_offset,
                                     handle->config.compaction_cb_ctx);
    }

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
    docio_read_doc(handle->dhandle, item->offset, &doc);

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
        handle->new_file || handle->file->new_file) {
        // update handle and return
        fdb_check_file_reopen(handle, NULL);
        fdb_link_new_file(handle);
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
                                     struct btree *new_seqtree)
{
    filemgr_set_compaction_state(new_file, NULL, FILE_REMOVED_PENDING);
    if (got_lock) {
        filemgr_mutex_unlock(new_file);
    }
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
}

static fdb_status _fdb_reset(fdb_kvs_handle *handle, fdb_kvs_handle *handle_in)
{
    struct filemgr_config fconfig;
    struct btreeblk_handle *new_bhandle;
    struct docio_handle *new_dhandle;
    struct hbtrie *new_trie = NULL;
    struct btree *new_seqtree = NULL, *old_seqtree;
    struct hbtrie *new_seqtrie = NULL;
    struct kvs_stat kvs_stat;
    filemgr_open_result result;
    size_t filename_len;
    // Copy the incoming handle into the handle that is being reset
    *handle = *handle_in;

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

    // set filemgr configuration
    fconfig.blocksize = handle->config.blocksize;
    fconfig.ncacheblock = handle->config.buffercache_size / handle->config.blocksize;
    fconfig.chunksize = handle->config.chunksize;
    fconfig.options = FILEMGR_CREATE;
    fconfig.num_wal_shards = handle->config.num_wal_partitions;
    fconfig.flag = 0x0;
    if ((handle->config.durability_opt & FDB_DRB_ODIRECT) &&
         handle->config.buffercache_size) {
        fconfig.flag |= _ARCH_O_DIRECT;
    }
    if (!(handle->config.durability_opt & FDB_DRB_ASYNC)) {
        fconfig.options |= FILEMGR_SYNC;
    }

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
                             struct btree *new_seqtree);


fdb_status fdb_compact_file(fdb_file_handle *fhandle,
                            const char *new_filename,
                            bool in_place_compaction)
{
    struct filemgr *new_file;
    struct filemgr_config fconfig;
    struct btreeblk_handle *new_bhandle;
    struct docio_handle *new_dhandle;
    struct hbtrie *new_trie = NULL;
    struct btree *new_seqtree = NULL, *old_seqtree;
    struct hbtrie *new_seqtrie = NULL;
    fdb_kvs_handle *handle = fhandle->root;
    fdb_status status;

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
    fconfig.blocksize = handle->config.blocksize;
    fconfig.ncacheblock = handle->config.buffercache_size / handle->config.blocksize;
    fconfig.chunksize = handle->config.chunksize;
    fconfig.options = FILEMGR_CREATE;
    fconfig.num_wal_shards = handle->config.num_wal_partitions;
    fconfig.num_bcache_shards = handle->config.num_bcache_partitions;
    fconfig.flag = 0x0;
    if ((handle->config.durability_opt & FDB_DRB_ODIRECT) &&
        handle->config.buffercache_size) {
        fconfig.flag |= _ARCH_O_DIRECT;
    }
    if (!(handle->config.durability_opt & FDB_DRB_ASYNC)) {
        fconfig.options |= FILEMGR_SYNC;
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

    return _fdb_compact_file(handle, new_file, new_bhandle, new_dhandle,
                             new_trie, new_seqtrie, new_seqtree);
}

fdb_status _fdb_compact_file(fdb_kvs_handle *handle,
                             struct filemgr *new_file,
                             struct btreeblk_handle *new_bhandle,
                             struct docio_handle *new_dhandle,
                             struct hbtrie *new_trie,
                             struct hbtrie *new_seqtrie,
                             struct btree *new_seqtree)

{
    struct avl_tree flush_items;
    char *old_filename = NULL;
    size_t old_filename_len = 0;
    struct filemgr *old_file;
    struct btree *new_idtree = NULL;
    bid_t dirty_idtree_root, dirty_seqtree_root;
    fdb_seqnum_t seqnum;

    // copy old file's seqnum to new file
    // (KV instances' seq numbers will be copied along with KV header)
    seqnum = filemgr_get_seqnum(handle->file);
    filemgr_set_seqnum(new_file, seqnum);

    if (handle->kvs) {
        // multi KV instance mode .. copy KV header data to new file
        fdb_kvs_header_copy(handle, new_file, new_dhandle);
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
            handle->seqtree->root_bid = dirty_seqtree_root;
        }
    }

    // flush WAL and set DB header
    wal_commit(&handle->file->global_txn, handle->file, NULL);
    wal_flush(handle->file, (void*)handle,
              _fdb_wal_flush_func, _fdb_wal_get_old_offset, &flush_items);
    wal_set_dirty_status(handle->file, FDB_WAL_CLEAN);

    // migrate uncommitted transaction items to new file
    wal_txn_migration((void*)handle, (void*)new_dhandle,
                      handle->file, new_file, _fdb_doc_move);
    // mark name of new file in old file
    filemgr_set_compaction_state(handle->file, new_file, FILE_COMPACT_OLD);

    handle->last_hdr_bid = filemgr_get_pos(handle->file) / handle->file->blocksize;
    handle->last_wal_flush_hdr_bid = handle->last_hdr_bid;

    handle->cur_header_revnum = fdb_set_file_header(handle);
    btreeblk_end(handle->bhandle);

    // Commit the current file handle to record the compaction filename
    fdb_status fs = filemgr_commit(handle->file, &handle->log_callback);
    wal_release_flushed_items(handle->file, &flush_items);
    if (fs != FDB_RESULT_SUCCESS) {
        filemgr_set_compaction_state(handle->file, NULL, FILE_NORMAL);
        filemgr_mutex_unlock(handle->file);
        _fdb_cleanup_compact_err(handle, new_file, true, true, new_bhandle,
                                 new_dhandle, new_trie, new_seqtrie,
                                 new_seqtree);
        return fs;
    }

    // reset last_wal_flush_hdr_bid
    handle->last_wal_flush_hdr_bid = BLK_NOT_FOUND;

    // Mark new file as newly compacted
    filemgr_update_file_status(new_file, FILE_COMPACT_NEW, NULL);
    filemgr_mutex_unlock(handle->file);
    filemgr_mutex_unlock(new_file);
    // now compactor & another writer can be interleaved

    if (handle->kvs) {
        fs = _fdb_compact_move_docs(handle, new_file, new_trie, new_idtree,
                                    (struct btree*)new_seqtrie, new_dhandle,
                                    new_bhandle, false /* not got file lock*/);
    } else {
        fs = _fdb_compact_move_docs(handle, new_file, new_trie, new_idtree,
                                    new_seqtree, new_dhandle, new_bhandle,
                                    false /*not holding file lock*/);
    }

    if (fs != FDB_RESULT_SUCCESS) {
        filemgr_set_compaction_state(handle->file, NULL, FILE_NORMAL);

        _fdb_cleanup_compact_err(handle, new_file, false, false, new_bhandle,
                                 new_dhandle, new_trie, new_seqtrie,
                                 new_seqtree);
        return fs;
    }

    filemgr_mutex_lock(new_file);

    old_file = handle->file;
    compactor_switch_file(old_file, new_file);
    handle->file = new_file;

    btreeblk_free(handle->bhandle);
    free(handle->bhandle);
    handle->bhandle = new_bhandle;

    docio_free(handle->dhandle);
    free(handle->dhandle);
    handle->dhandle = new_dhandle;

    hbtrie_free(handle->trie);
    free(handle->trie);
    handle->trie = new_trie;

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

    old_filename_len = strlen(old_file->filename) + 1;
    old_filename = (char *) malloc(old_filename_len);
    strncpy(old_filename, old_file->filename, old_filename_len);
    filemgr_update_file_status(new_file, FILE_NORMAL, old_filename);

    // allow update to new_file
    filemgr_mutex_unlock(new_file);

    // atomically perform
    // 1) commit new file
    // 2) set remove pending flag of the old file
    // 3) close the old file
    return _fdb_commit_and_remove_pending(handle, old_file, new_file);
}

LIBFDB_API
fdb_status fdb_compact(fdb_file_handle *fhandle,
                       const char *new_filename)
{
    fdb_kvs_handle *handle = fhandle->root;

    if (handle->config.compaction_mode == FDB_COMPACTION_MANUAL) {
        // manual compaction
        bool in_place_compaction = false;
        char nextfile[FDB_MAX_FILENAME_LEN];
        if (!new_filename) { // In-place compaction.
            in_place_compaction = true;
            compactor_get_next_filename(handle->file->filename, nextfile);
            new_filename = nextfile;
        }
        return fdb_compact_file(fhandle, new_filename, in_place_compaction);

    } else { // auto compaction mode.
        bool ret;
        char nextfile[FDB_MAX_FILENAME_LEN];
        fdb_status fs;
        // set compaction flag
        ret = compactor_switch_compaction_flag(handle->file, true);
        if (!ret) {
            // the file is already being compacted by other thread
            return FDB_RESULT_FILE_IS_BUSY;
        }
        // get next filename
        compactor_get_next_filename(handle->file->filename, nextfile);
        fs = fdb_compact_file(fhandle, nextfile, false);
        // clear compaction flag
        ret = compactor_switch_compaction_flag(handle->file, false);
        (void)ret;
        return fs;
    }
}

fdb_status fdb_compact_file_upto(fdb_file_handle *fhandle,
                                 const char *new_filename,
                                 bool in_place_compaction,
                                 bid_t marker)
{
    struct filemgr *new_file = NULL;
    struct filemgr_config fconfig;
    struct btreeblk_handle *new_bhandle;
    struct docio_handle *new_dhandle;
    struct hbtrie *new_trie = NULL;
    struct btree *new_idtree = NULL;
    struct btree *new_seqtree = NULL;
    struct hbtrie *new_seqtrie = NULL;
    fdb_kvs_handle *rhandle = fhandle->root;
    size_t header_len = 0;
    bid_t last_wal_hdr_bid;
    bid_t last_hdr_bid;
    bid_t latest_hdr_bid;
    int hdr_array_len;
    int hdr_idx;
    fdb_seqnum_t seqnum;
    struct hdr_info_t {
        bid_t bid;
        fdb_seqnum_t _seqnum;
    } *hdr_info;
    err_log_callback *log_callback = &rhandle->log_callback;
    bool got_lock = true;
    fdb_status fs;

    // Grab locks only for error checks..
    filemgr_mutex_lock(rhandle->file);
    fs = _fdb_compact_file_checks(rhandle, new_filename);
    if (fs != FDB_RESULT_SUCCESS) {
        filemgr_mutex_unlock(rhandle->file);
        return fs;
    }

    hdr_info = (struct hdr_info_t *) malloc(sizeof(struct hdr_info_t));
    hdr_array_len = 1;

catch_up_compaction:
    // sync handle
    fdb_sync_db_header(rhandle);
    last_hdr_bid = filemgr_get_header_bid(rhandle->file);
    hdr_idx = 0;
    hdr_info[0].bid = last_hdr_bid;
    // Also cache the seqnums since these values need to be migrated from the
    // old_file to the new_file if we are in single KV instance mode compaction
    hdr_info[0]._seqnum = filemgr_get_seqnum(rhandle->file);

    if (marker < hdr_info[hdr_idx].bid) {
        // Mark the current file as compaction_inprog so that any other calls
        // attempting to compact this file will fail
        filemgr_update_file_status(rhandle->file, FILE_COMPACT_INPROG, NULL);
        // Allow mutations to happen on old file while compaction is in-prog
        // This means new headers may be created between now and the calls below
        filemgr_mutex_unlock(rhandle->file);
        got_lock = false;
    }
    while (marker < hdr_info[hdr_idx].bid) {
        bid_t prev_hdr_bid = filemgr_fetch_prev_header(rhandle->file,
                              hdr_info[hdr_idx].bid, NULL, &header_len,
                              &seqnum, log_callback);
        if (!header_len) { // LCOV_EXCL_START
            free(hdr_info);
            return FDB_RESULT_READ_FAIL;
        } // LCOV_EXCL_STOP

        ++hdr_idx;
        if (hdr_idx >= hdr_array_len) { // grow the vector of header bids
            hdr_array_len *= 2;
            hdr_info = (struct hdr_info_t *) realloc(hdr_info,
                                    hdr_array_len * sizeof(struct hdr_info_t));
        }
        hdr_info[hdr_idx].bid = prev_hdr_bid;
        // caching the seqnums saves us from an extra DB header fetch call
        // while migrating docs in single kv instance mode
        hdr_info[hdr_idx]._seqnum = seqnum;
        if (prev_hdr_bid < marker) { // gone past the snapshot marker?!
            free(hdr_info);
            return FDB_RESULT_NO_DB_INSTANCE;
        }
    }

    if (!new_file) { // Do only once - Setup new_file for compaction..
        // Initial setup for New File
        fconfig.blocksize = rhandle->config.blocksize;
        fconfig.ncacheblock = rhandle->config.buffercache_size /
                              rhandle->config.blocksize;
        fconfig.chunksize = rhandle->config.chunksize;
        fconfig.options = FILEMGR_CREATE;
        fconfig.flag = 0x0;
        if ((rhandle->config.durability_opt & FDB_DRB_ODIRECT) &&
            rhandle->config.buffercache_size) {
            fconfig.flag |= _ARCH_O_DIRECT;
        }
        if (!(rhandle->config.durability_opt & FDB_DRB_ASYNC)) {
            fconfig.options |= FILEMGR_SYNC;
        }
        fconfig.num_wal_shards = rhandle->config.num_wal_partitions;
        fconfig.num_bcache_shards = rhandle->config.num_bcache_partitions;

        // open new file
        filemgr_open_result result = filemgr_open((char *)new_filename,
                                                  rhandle->fileops,
                                                  &fconfig,
                                                  log_callback);
        if (result.rv != FDB_RESULT_SUCCESS) {
            if (got_lock) {
                filemgr_mutex_unlock(rhandle->file);
            }
            free(hdr_info);
            return (fdb_status) result.rv;
        }

        new_file = result.file;
        fdb_assert(new_file, fhandle, fconfig.options);

        filemgr_set_in_place_compaction(new_file, in_place_compaction);
        // GRAB FILE LOCK: prevent any update to the new_file
        filemgr_mutex_lock(new_file);
        // create new hb-trie and related handles
        new_bhandle = (struct btreeblk_handle *)calloc(1,
                                               sizeof(struct btreeblk_handle));
        new_bhandle->log_callback = log_callback;
        new_dhandle = (struct docio_handle *)calloc(1,
                                                  sizeof(struct docio_handle));
        new_dhandle->log_callback = log_callback;

        docio_init(new_dhandle, new_file,
                   rhandle->config.compress_document_body);
        btreeblk_init(new_bhandle, new_file, new_file->blocksize);

        new_trie = (struct hbtrie *)malloc(sizeof(struct hbtrie));
        hbtrie_init(new_trie, rhandle->trie->chunksize, rhandle->trie->valuelen,
                new_file->blocksize, BLK_NOT_FOUND,
                (void *)new_bhandle, rhandle->btreeblkops,
                (void*)new_dhandle, _fdb_readkey_wrap);

        hbtrie_set_leaf_cmp(new_trie, _fdb_custom_cmp_wrap);
        // set aux
        new_trie->flag = rhandle->trie->flag;
        new_trie->leaf_height_limit = rhandle->trie->leaf_height_limit;
        new_trie->map = rhandle->trie->map;

        if (rhandle->config.seqtree_opt == FDB_SEQTREE_USE) {
            // if we use sequence number tree
            if (rhandle->kvs) { // multi KV instance mode
                new_seqtrie = (struct hbtrie *)calloc(1, sizeof(struct hbtrie));

                hbtrie_init(new_seqtrie, sizeof(fdb_kvs_id_t),
                        OFFSET_SIZE, new_file->blocksize, BLK_NOT_FOUND,
                        (void *)new_bhandle, rhandle->btreeblkops,
                        (void *)new_dhandle, _fdb_readseq_wrap);

            } else {
                struct btree *old_seqtree;
                new_seqtree = (struct btree *)calloc(1, sizeof(struct btree));
                old_seqtree = rhandle->seqtree;

                btree_init(new_seqtree, (void *)new_bhandle,
                           old_seqtree->blk_ops, old_seqtree->kv_ops,
                           old_seqtree->blksize, old_seqtree->ksize,
                           old_seqtree->vsize, 0x0, NULL);
            }
        }
        // Mark new file as newly compacted
        filemgr_update_file_status(new_file, FILE_COMPACT_NEW, NULL);
    }
    // Now we repeat the compaction process from marker header to most recent..
    for (; hdr_idx; --hdr_idx) {
        fdb_kvs_handle handle;
        struct snap_handle shandle;
        struct kvs_info kvs;
        fdb_kvs_config kvs_config = rhandle->kvs_config;
        fdb_config config = rhandle->config;
        struct filemgr *file = rhandle->file;
        struct hbtrie *tmp_trie;
        struct hbtrie *tmp_seqtrie;
        struct btree *tmp_seqtree;
        memset(&handle, 0, sizeof(fdb_kvs_handle));
        memset(&shandle, 0, sizeof(struct snap_handle));
        memset(&kvs, 0, sizeof(struct kvs_info));
        // Setup a temporary DB handle to look like a snapshot of the old_file
        // at the current snapshot marker
        handle.last_hdr_bid = hdr_info[hdr_idx].bid; // Fast rewind on open
        handle.max_seqnum = FDB_SNAPSHOT_INMEM; // Prevent WAL restore on open
        handle.shandle = &shandle;
        handle.fhandle = fhandle;
        if (rhandle->kvs) {
            handle.kvs = &kvs;
            _fdb_kvs_init_root(&handle, file);
        }
        handle.log_callback = *log_callback;

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
            free(hdr_info);
            return fs;
        }

        // Set cached old_file's sequence number into header of new_file
        // so it gets migrated correctly for the fdb_set_file_header below
        filemgr_set_seqnum(new_file, hdr_info[hdr_idx]._seqnum);

        if (handle.kvs) {
            // Reset all header stats as we are about to load new data into
            // the file and do a wal_flush which will update all stats..
            // copy KV header data in 'handle' to new file
            fdb_kvs_header_create(new_file);
            // read from 'handle->dhandle', and import into 'new_file'
            // This will fetch kvs_name, kv_id of all the instance
            fdb_kvs_header_read(new_file, handle.dhandle,
                                handle.kv_info_offset);
            // Since we are about to migrate all the docs of all kv instance
            // the stats will be populated at the time of wal_flush, so
            // for correct stats, ensure that they are reset to 0 first
            fdb_kvs_header_reset_all_stats(new_file);
        }

        // Move all docs from old file to new file
        if (handle.kvs) {
            fs = _fdb_compact_move_docs(&handle, new_file, new_trie, new_idtree,
                    (struct btree*)new_seqtrie, new_dhandle,
                    new_bhandle, true /* already holding new_file lock*/);
        } else {
            fs = _fdb_compact_move_docs(&handle, new_file, new_trie, new_idtree,
                    new_seqtree, new_dhandle, new_bhandle,
                    true /*already holding new_file lock*/);
        }
        if (fs != FDB_RESULT_SUCCESS) {
            _fdb_cleanup_compact_err(&handle, new_file, true, true, new_bhandle,
                                     new_dhandle, new_trie, new_seqtrie,
                                     new_seqtree);
            free(hdr_info);
            return fs;
        }
        // Restore docs between [last WAL flush header] ~ [current header]
        //                      [last_wal_hdr_idx]      ~ [hdr_idx]
        // if and only if (last_wal_hdr_idx != hdr_idx)
        last_wal_hdr_bid = handle.last_wal_flush_hdr_bid;
        if (last_wal_hdr_bid == BLK_NOT_FOUND) {
            // WAL has not been flushed ever
            last_wal_hdr_bid = 0; // scan from the beginning
        }
        if (last_wal_hdr_bid < hdr_info[hdr_idx].bid) {
            fs = _fdb_move_wal_docs(&handle,
                                    last_wal_hdr_bid,
                                    hdr_info[hdr_idx].bid,
                                    new_file, new_trie, new_idtree,
                                    new_seqtrie, new_seqtree,
                                    new_dhandle,
                                    new_bhandle);
            if (fs != FDB_RESULT_SUCCESS) {
                _fdb_cleanup_compact_err(&handle, new_file, true, true, new_bhandle,
                                         new_dhandle, new_trie, new_seqtrie,
                                         new_seqtree);
                free(hdr_info);
                return fs;
            }
        }
        // Set handle's file as new_file
        handle.file = new_file;

        // Note: Appending KVS header must be done after flushing WAL
        //       because KVS stats info is updated during WAL flushing.
        if (handle.kvs) {
            // multi KV instance mode .. append up-to-date KV header
            handle.kv_info_offset = fdb_kvs_header_append(new_file,
                                                          new_dhandle);
            tmp_seqtrie = handle.seqtrie;
            handle.seqtrie = new_seqtrie;
        } else {
            tmp_seqtree = handle.seqtree;
            handle.seqtree = new_seqtree;
        }

        // flush WAL and set DB header
        wal_commit(&new_file->global_txn, new_file, NULL);
        wal_set_dirty_status(new_file, FDB_WAL_CLEAN);
        // Setup current handle to look just like a snapshot of the
        // old_file except that it is meant for the new_file
        // This is done so that fdb_set_file_header() will reflect
        // correct values into the new_file
        tmp_trie = handle.trie;
        // Set handle's trie as new_trie
        handle.trie = new_trie;

        handle.last_hdr_bid = filemgr_get_pos(new_file) / new_file->blocksize;
        handle.last_wal_flush_hdr_bid = handle.last_hdr_bid; // WAL was flushed
        handle.cur_header_revnum = fdb_set_file_header(&handle);
        btreeblk_end(handle.bhandle);

        // Commit the current file handle to record the compaction filename
        fdb_status fs = filemgr_commit(handle.file, log_callback);
        if (fs != FDB_RESULT_SUCCESS) {
            _fdb_cleanup_compact_err(&handle, new_file, true, true, new_bhandle,
                                     new_dhandle, new_trie, new_seqtrie,
                                     new_seqtree);
            free(hdr_info);
            return fs;
        }

        // Restore & close this DB handle with its allocated pointers
        // to free up the structs allocated by the _fdb_open call
        handle.file = file;
        handle.trie = tmp_trie;
        if (handle.kvs) {
            handle.seqtrie = tmp_seqtrie;
            fdb_kvs_header_free(new_file); // it will be recreated if needed
        } else {
            handle.seqtree = tmp_seqtree;
        }
        handle.shandle = NULL;
        _fdb_close(&handle);
    }

    // Re-acquire source file lock if final DB header of compaction..
    if (marker < hdr_info[hdr_idx].bid) {
        if (!got_lock) {
            filemgr_mutex_lock(rhandle->file); // Re-acquire file lock & repeat
            got_lock = true;
        }
        latest_hdr_bid = filemgr_get_header_bid(rhandle->file);
        if (last_hdr_bid < latest_hdr_bid) {
            // A new header was written while compaction was still in progress
            marker = last_hdr_bid; // Set marker to previous latest DB hdr
            // Need to repeat above steps to catch up to remaining headers
            goto catch_up_compaction;
        } // else reached the latest DB header, proceed with regular compaction
    }

    free(hdr_info);
    return _fdb_compact_file(rhandle, new_file, new_bhandle, new_dhandle,
                             new_trie, new_seqtrie, new_seqtree);
}

LIBFDB_API
fdb_status fdb_compact_upto(fdb_file_handle *fhandle,
                            const char *new_filename,
                            fdb_snapshot_marker_t marker)
{
    fdb_kvs_handle *handle = fhandle->root;
    bool in_place_compaction = false;
    char nextfile[FDB_MAX_FILENAME_LEN];

    if (handle->config.seqtree_opt != FDB_SEQTREE_USE) {
        return FDB_RESULT_INVALID_HANDLE;
    }

    if (!new_filename) { // In-place compaction.
        in_place_compaction = true;
        compactor_get_next_filename(handle->file->filename, nextfile);
        new_filename = nextfile;
    }

    return fdb_compact_file_upto(fhandle, new_filename, in_place_compaction,
                                 (bid_t)marker);
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
            // 1. deregieter from compactor (by calling fdb_close)
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
fdb_status fdb_close(fdb_file_handle *fhandle)
{
    fdb_status fs;

    if (fhandle->root->config.auto_commit &&
        filemgr_get_ref_count(fhandle->root->file) == 1) {
        // auto commit mode & the last handle referring the file
        // commit file before close
        fs = fdb_commit(fhandle, FDB_COMMIT_NORMAL);
        if (fs != FDB_RESULT_SUCCESS) {
            return fs;
        }
    }

    fs = _fdb_close_root(fhandle->root);
    if (fs == FDB_RESULT_SUCCESS) {
        fdb_file_handle_close_all(fhandle);
        fdb_file_handle_free(fhandle);
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
    if (!(handle->config.flags & FDB_OPEN_FLAG_RDONLY) &&
        handle->config.compaction_mode == FDB_COMPACTION_AUTO) {
        // read-only file is not registered in compactor
        compactor_deregister_file(handle->file);
    }

    btreeblk_end(handle->bhandle);
    btreeblk_free(handle->bhandle);

    fs = filemgr_close(handle->file, handle->config.cleanup_cache_onclose,
                                  handle->filename, &handle->log_callback);
    if (fs != FDB_RESULT_SUCCESS) {
        return fs;
    }
    docio_free(handle->dhandle);
    if (handle->new_file) {
        fs = filemgr_close(handle->new_file,
                           handle->config.cleanup_cache_onclose,
                           handle->filename, &handle->log_callback);
        if (fs != FDB_RESULT_SUCCESS) {
            return fs;
        }
        docio_free(handle->new_dhandle);
        free(handle->new_dhandle);
        handle->new_file = NULL;
        handle->new_dhandle = NULL;
    }

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

    status = filemgr_destroy_file(filename, &fconfig, NULL);
    if (status != FDB_RESULT_SUCCESS) {
        filemgr_mutex_openunlock();
        return status;
    }

    if (config.compaction_mode == FDB_COMPACTION_AUTO) {
        status = compactor_destroy_file(filename, &config);
        if (status != FDB_RESULT_SUCCESS) {
            filemgr_mutex_openunlock();
            return status;
        }
    }

    filemgr_mutex_openunlock();

    return status;
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
        return FDB_RESULT_INVALID_ARGS;
    }

    handle = fhandle->root;

    fdb_check_file_reopen(handle, NULL);
    fdb_link_new_file(handle);
    fdb_sync_db_header(handle);

    file = (handle->new_file)?(handle->new_file):(handle->file);

    datasize = _kvs_stat_get_sum(file, KVS_STAT_DATASIZE);
    nlivenodes = _kvs_stat_get_sum(file, KVS_STAT_NLIVENODES);

    ret = datasize;
    ret += nlivenodes * handle->config.blocksize;
    ret += wal_get_datasize(handle->file);

    return ret;
}

LIBFDB_API
fdb_status fdb_get_file_info(fdb_file_handle *fhandle, fdb_file_info *info)
{
    uint64_t ndocs;
    fdb_kvs_handle *handle;

    if (!fhandle || !info) {
        return FDB_RESULT_INVALID_ARGS;
    }
    handle = fhandle->root;

    fdb_check_file_reopen(handle, NULL);
    fdb_link_new_file(handle);
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
        if (handle->new_file) {
            info->new_filename = handle->new_file->filename;
        } else {
            info->new_filename = NULL;
        }
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

    info->space_used = fdb_estimate_space_used(fhandle);
    info->file_size = filemgr_get_pos(handle->file);

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
    uint64_t ndocs;
    uint64_t nlivenodes;
    uint64_t datasize;
    uint64_t last_wal_flush_hdr_bid;
    uint64_t kv_info_offset;
    uint64_t header_flags;
    char *compacted_filename;
    fdb_seqnum_t seqnum;
    fdb_snapshot_info_t *markers;
    int i;
    uint64_t size;
    file_status_t fstatus;
    fdb_status status = FDB_RESULT_SUCCESS;

    if (!fhandle || !markers_out || !num_markers) {
        return FDB_RESULT_INVALID_ARGS;
    }
    handle = fhandle->root;
    if (!handle->file) {
        return FDB_RESULT_FILE_NOT_OPEN;
    }

    fdb_check_file_reopen(handle, &fstatus);
    if (fstatus == FILE_REMOVED_PENDING) { // Link to new file IFF compaction
        fdb_link_new_file(handle);         // completed successfully
        fdb_sync_db_header(handle);
    }

    // There are as many DB headers in a file as the file's header revision num
    size = handle->cur_header_revnum;
    if (!size) {
        return FDB_RESULT_NO_DB_INSTANCE;
    }
    markers = (fdb_snapshot_info_t *)calloc(size, sizeof(fdb_snapshot_info_t));
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
        if (i == 0 ) {
            filemgr_get_header(handle->file, header_buf, &header_len);
        } else {
            hdr_bid = filemgr_fetch_prev_header(handle->file, hdr_bid,
                                                header_buf, &header_len,
                                                &seqnum, &handle->log_callback);
        }
        if (header_len == 0) {
            continue; // header doesn't exist, terminate iteration
        }

        fdb_fetch_header(header_buf, &trie_root_bid, &seq_root_bid, &ndocs,
                         &nlivenodes, &datasize, &last_wal_flush_hdr_bid,
                         &kv_info_offset, &header_flags, &compacted_filename,
                         NULL);
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
            doc_offset = docio_read_doc(handle->dhandle, kv_info_offset, &doc);
            if (doc_offset == kv_info_offset) {
                fdb_free_snap_markers(markers, i);
                return FDB_RESULT_READ_FAIL;
            }
            status = _fdb_kvs_get_snap_info(doc.body, &markers[i]);
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
    int64_t i, kvs_idx;
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
fdb_status fdb_shutdown()
{
    if (fdb_initialized) {
        spin_lock(&initial_lock);
        if (fdb_open_inprog) {
            spin_unlock(&initial_lock);
            return FDB_RESULT_FILE_IS_BUSY;
        }
        compactor_shutdown();
        filemgr_shutdown();
#ifdef _MEMPOOL
        mempool_shutdown();
#endif

        fdb_initialized = 0;
        spin_unlock(&initial_lock);
    }
    return FDB_RESULT_SUCCESS;
}

void _fdb_dump_handle(fdb_kvs_handle *h) {
    fprintf(stderr, "filename: %s\n", h->filename);

    fprintf(stderr, "config: chunksize %d\n", h->config.chunksize);
    fprintf(stderr, "config: blocksize %d\n", h->config.blocksize);
    fprintf(stderr, "config: buffercache_size %llu\n",
           h->config.buffercache_size);
    fprintf(stderr, "config: wal_threshold %llu\n", h->config.wal_threshold);
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
    fprintf(stderr, "config: compactor_sleep_duration %llu\n",
           h->config.compactor_sleep_duration);

    fprintf(stderr, "kvs_config: Create if missing = %d\n",
           h->kvs_config.create_if_missing);

    fprintf(stderr, "kvs: id = %llu\n", h->kvs->id);
    fprintf(stderr, "kvs: type = %d\n", h->kvs->type);
    fprintf(stderr, "kvs: root_handle %p\n", h->kvs->root);

    fprintf(stderr, "fdb_file_handle: %p\n", h->fhandle);
    fprintf(stderr, "fhandle: root %p\n", h->fhandle->root);
    fprintf(stderr, "fhandle: flags %llx\n", h->fhandle->flags);

    fprintf(stderr, "hbtrie: %p\n", h->trie);
    fprintf(stderr, "hbtrie: chunksize %u\n", h->trie->chunksize);
    fprintf(stderr, "hbtrie: valuelen %u\n", h->trie->valuelen);
    fprintf(stderr, "hbtrie: flag %x\n", h->trie->flag);
    fprintf(stderr, "hbtrie: leaf_height_limit %u\n",
           h->trie->leaf_height_limit);
    fprintf(stderr, "hbtrie: root_bid %llu\n", h->trie->root_bid);
    fprintf(stderr, "hbtrie: root_bid %llu\n", h->trie->root_bid);
    fprintf(stderr, "hbtrie: readkey %p\n", h->trie->readkey);

    fprintf(stderr, "idtree: %p\n", h->idtree);

    fprintf(stderr, "seqtrie: %p\n", h->seqtrie);
    fprintf(stderr, "seqtrie: chunksize %u\n", h->seqtrie->chunksize);
    fprintf(stderr, "seqtrie: valuelen %u\n", h->seqtrie->valuelen);
    fprintf(stderr, "seqtrie: flag %x\n", h->seqtrie->flag);
    fprintf(stderr, "seqtrie: leaf_height_limit %u\n",
           h->seqtrie->leaf_height_limit);
    fprintf(stderr, "seqtrie: root_bid %llu\n", h->seqtrie->root_bid);
    fprintf(stderr, "seqtrie: root_bid %llu\n", h->seqtrie->root_bid);
    fprintf(stderr, "seqtrie: readkey %p\n", h->seqtrie->readkey);

    fprintf(stderr, "file: filename %s\n", h->file->filename);
    fprintf(stderr, "file: ref_count %d\n", h->file->ref_count);
    fprintf(stderr, "file: fflags %x\n", h->file->fflags);
    fprintf(stderr, "file: blocksize %d\n", h->file->blocksize);
    fprintf(stderr, "file: fd %d\n", h->file->fd);
    fprintf(stderr, "file: pos %llu\n", h->file->pos.val);
    fprintf(stderr, "file: status %d\n", h->file->status.val);
    fprintf(stderr, "file: config: blocksize %d\n", h->file->config->blocksize);
    fprintf(stderr, "file: config: ncacheblock %d\n",
           h->file->config->ncacheblock);
    fprintf(stderr, "file: config: flag %d\n", h->file->config->flag);
    fprintf(stderr, "file: config: chunksize %d\n", h->file->config->chunksize);
    fprintf(stderr, "file: config: options %x\n", h->file->config->options);
    fprintf(stderr, "file: config: prefetch_duration %llu\n",
           h->file->config->prefetch_duration);
    fprintf(stderr, "file: config: num_wal_shards %d\n",
           h->file->config->num_wal_shards);
    fprintf(stderr, "file: config: num_bcache_shards %d\n",
           h->file->config->num_bcache_shards);
    fprintf(stderr, "file: new_file %p\n", h->file->new_file);
    fprintf(stderr, "file: old_filename %p\n", h->file->old_filename);
    fprintf(stderr, "file: fnamedic_item: bcache %p\n", h->file->bcache);
    fprintf(stderr, "file: global_txn: handle %p\n", h->file->global_txn.handle);
    fprintf(stderr, "file: global_txn: prev_hdr_bid %llu\n",
           h->file->global_txn.prev_hdr_bid);
    fprintf(stderr, "file: global_txn: isolation %d\n",
           h->file->global_txn.isolation);
    fprintf(stderr, "file: in_place_compaction: %d\n",
           h->file->in_place_compaction);
    fprintf(stderr, "file: kvs_header: %llu\n", h->file->kv_header->id_counter);

    fprintf(stderr, "new_file: %p\n", h->new_file);

    fprintf(stderr, "docio_handle: %p\n", h->dhandle);
    fprintf(stderr, "dhandle: file: filename %s\n", h->dhandle->file->filename);
    fprintf(stderr, "dhandle: curblock %llu\n", h->dhandle->curblock);
    fprintf(stderr, "dhandle: curpos %d\n", h->dhandle->curpos);
    fprintf(stderr, "dhandle: lastbid %llu\n", h->dhandle->lastbid);
    fprintf(stderr, "dhandle: readbuffer %p\n", h->dhandle->readbuffer);
    fprintf(stderr, "dhandle: %s\n",
           h->dhandle->compress_document_body ? "compress" : "don't compress");
    fprintf(stderr, "new_dhandle %p\n", h->dhandle);

    fprintf(stderr, "btreeblk_handle bhanlde %p\n", h->bhandle);
    fprintf(stderr, "bhandle: nodesize %d\n", h->bhandle->nodesize);
    fprintf(stderr, "bhandle: nnodeperblock %d\n", h->bhandle->nnodeperblock);
    fprintf(stderr, "bhandle: nlivenodes %llu\n", h->bhandle->nlivenodes);
    fprintf(stderr, "bhandle: file %s\n", h->bhandle->file->filename);
    fprintf(stderr, "bhandle: nsb %d\n", h->bhandle->nsb);

    fprintf(stderr, "multi_kv_instances: %d\n", h->config.multi_kv_instances);
    fprintf(stderr, "prefetch_duration: %llu\n", h->config.prefetch_duration);
    fprintf(stderr, "cur_header_revnum: %llu\n", h->cur_header_revnum);
    fprintf(stderr, "last_hdr_bid: %llu\n", h->last_hdr_bid);
    fprintf(stderr, "last_wal_flush_hdr_bid: %llu\n",
           h->last_wal_flush_hdr_bid);
    fprintf(stderr, "kv_info_offset: %llu\n", h->kv_info_offset);

    fprintf(stderr, "snap_handle: %p\n", h->shandle);
    if (h->shandle) {
        fprintf(stderr, "shandle: ref_cnt %d\n", h->shandle->ref_cnt);
        fprintf(stderr, "shandle: type %d\n", h->shandle->type);
        fprintf(stderr, "shandle: kvs_stat: nlivenodes %llu\n",
               h->shandle->stat.nlivenodes);
        fprintf(stderr, "shandle: kvs_stat: ndocs %llu\n",
               h->shandle->stat.ndocs);
        fprintf(stderr, "shandle: kvs_stat: datasize %llu\n",
               h->shandle->stat.datasize);
        fprintf(stderr, "shandle: kvs_stat: wal_ndocs %llu\n",
               h->shandle->stat.wal_ndocs);
        fprintf(stderr, "shandle: kvs_stat: wal_ndeletes %llu\n",
               h->shandle->stat.wal_ndeletes);
    }
    fprintf(stderr, "seqnum: %llu\n", h->seqnum);
    fprintf(stderr, "max_seqnum: %llu\n", h->max_seqnum);

    fprintf(stderr, "txn: %p\n", h->txn);
    if (h->txn) {
        fprintf(stderr, "txn: handle %p\n", h->txn->handle);
        fprintf(stderr, "txn: prev_hdr_bid %llu\n", h->txn->prev_hdr_bid);
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
        fprintf(stderr, "--------%d-Dumping Handle %p----------\n", n, handle);
        _fdb_dump_handle(handle);
        h = avl_next(h);
    }
    spin_unlock(&open_handle_lock);
#endif
}
