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

static volatile uint8_t fdb_initialized = 0;
#ifdef SPIN_INITIALIZER
static spin_t initial_lock = SPIN_INITIALIZER;
#else
static volatile unsigned int initial_lock_status = 0;
static spin_t initial_lock;
#endif

static const uint16_t OFFSET_SIZE = sizeof(uint64_t);

static fdb_status _fdb_open(fdb_handle *handle,
                            const char *filename,
                            const fdb_config *config);

static fdb_status _fdb_close(fdb_handle *handle);

static wal_result _fdb_wal_snapshot_func(void *handle, fdb_doc *doc,
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

INLINE size_t _fdb_readkey_wrap(void *handle, uint64_t offset, void *buf)
{
    keylen_t keylen;
    offset = _endian_decode(offset);
    docio_read_doc_key((struct docio_handle *)handle, offset, &keylen, buf);
    return keylen;
}

// convert (prefix) btree cmp function -> user's custom compare function (fixed)
static int _fdb_cmp_fixed_wrap(void *key1, void *key2, void *aux)
{
    fdb_handle *handle = (fdb_handle*)aux;
    return handle->config.cmp_fixed(key1, key2);
}

// convert (prefix) btree cmp function -> user's custom compare function (variable)
static int _fdb_cmp_variable_wrap(void *key1, void *key2, void *aux)
{
    uint8_t *keystr1 = alca(uint8_t, FDB_MAX_KEYLEN);
    uint8_t *keystr2 = alca(uint8_t, FDB_MAX_KEYLEN);
    size_t keylen1, keylen2;
    fdb_handle *handle = (fdb_handle*)aux;

    _get_var_key(key1, (void*)keystr1, &keylen1);
    _get_var_key(key2, (void*)keystr2, &keylen2);

    if (keylen1 == 0 && keylen2 == 0) {
        return 0;
    } else if (keylen1 ==0 && keylen2 > 0) {
        return -1;
    } else if (keylen1 > 0 && keylen2 == 0) {
        return 1;
    }

    return handle->config.cmp_variable(keystr1, keylen1, keystr2, keylen2);
}

void fdb_fetch_header(void *header_buf,
                      bid_t *trie_root_bid,
                      bid_t *seq_root_bid,
                      uint64_t *ndocs,
                      uint64_t *nlivenodes,
                      uint64_t *datasize,
                      uint64_t *last_wal_flush_hdr_bid,
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

    seq_memcpy(&new_filename_len, (uint8_t *)header_buf + offset,
               sizeof(new_filename_len), offset);
    new_filename_len = _endian_decode(new_filename_len);
    seq_memcpy(&old_filename_len, (uint8_t *)header_buf + offset,
               sizeof(old_filename_len), offset);
    old_filename_len = _endian_decode(old_filename_len);
    if (new_filename_len) {
        *new_filename = (char*)((uint8_t *)header_buf + offset);
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

INLINE void _fdb_restore_wal(fdb_handle *handle, bid_t hdr_bid)
{
    struct filemgr *file = handle->file;
    uint32_t blocksize = handle->file->blocksize;
    uint64_t last_wal_flush_hdr_bid = handle->last_wal_flush_hdr_bid;
    uint64_t hdr_off = hdr_bid * FDB_BLOCKSIZE;
    uint64_t offset = 0; //assume everything from first block needs restoration

    if (!hdr_off) { // Nothing to do if we don't have a header block offset
        return;
    }

    filemgr_mutex_lock(file);
    if (last_wal_flush_hdr_bid != BLK_NOT_FOUND) {
        offset = (last_wal_flush_hdr_bid + 1) * blocksize;
    }

    // If a valid last header was retrieved and it matches the current header
    // OR if WAL already had entries populated, then no crash recovery needed
    if (hdr_off <= offset || (!handle->shandle && wal_get_size(file))) {
        filemgr_mutex_unlock(file);
        return;
    }

    if (handle->shandle) {
        snap_init(handle->shandle, handle);
    }

    // Temporarily disable the error logging callback as there are false positive
    // checksum errors in docio_read_doc.
    // TODO: Need to adapt docio_read_doc to separate false checksum errors.
    err_log_callback *log_callback = handle->dhandle->log_callback;
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
                if (doc.key || (doc.length.flag & DOCIO_TXN_COMMITTED)) {
                    // check if the doc is transactional or not
                    if (!(doc.length.flag & DOCIO_TXN_DIRTY)) {
                        if (doc.length.flag & DOCIO_TXN_COMMITTED) {
                            // commit mark .. read doc offset
                            uint64_t _offset_temp;
                            doc_offset = doc.doc_offset;
                            // read the previously skipped doc
                            _offset_temp = docio_read_doc(handle->dhandle,
                                                          doc_offset, &doc);
                            if (doc.key == NULL) {
                                // doc read error
                                free(doc.key);
                                free(doc.meta);
                                free(doc.body);
                                offset = _offset;
                                continue;
                            }
                        } else {
                            doc_offset = offset;
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

                            wal_insert(&file->global_txn, file, &wal_doc, doc_offset);
                            if (doc.key) free(doc.key);
                        } else {
                            snap_insert(handle->shandle, &wal_doc, doc_offset);
                        }
                        free(doc.meta);
                        free(doc.body);
                        offset = _offset;
                    } else {
                        // skip transactional document once
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
INLINE fdb_status _fdb_recover_compaction(fdb_handle *handle,
                                          const char *new_filename)
{
    uint64_t offset = 0;
    uint32_t blocksize = handle->config.blocksize;
    fdb_handle new_db;
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
    fdb_status status = _fdb_open(&new_db, new_filename, &config);
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
        handle->ndocs = new_db.ndocs;
        handle->datasize = new_db.datasize;

        btreeblk_end(handle->bhandle);
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
            free(handle->seqtree->kv_ops);
            free(handle->seqtree);
            if (new_db.config.seqtree_opt == FDB_SEQTREE_USE) {
                handle->seqtree = new_db.seqtree;
            }
        }

        filemgr_mutex_unlock(new_file);
        // remove self: WARNING must not close this handle if snapshots
        // are yet to open this file
        filemgr_remove_pending(old_file, new_db.file);
        filemgr_close(old_file, 0, handle->filename, &handle->log_callback);
        free(new_db.filename);
        return FDB_RESULT_FAIL;
    }
    docio_init(&dhandle, new_file, config.compress_document_body);

    for (offset = 0; offset < new_file->pos;
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
                    // check if the doc is transactional or not
                    if (!(doc.length.flag & DOCIO_TXN_DIRTY)) {
                        if (doc.length.flag & DOCIO_TXN_COMMITTED) {
                            // commit mark .. read doc offset
                            uint64_t _offset_temp;
                            doc_offset = doc.doc_offset;
                            // read the previously skipped doc
                            _offset_temp = docio_read_doc(handle->dhandle,
                                                          doc_offset, &doc);
                            if (doc.key == NULL) {
                                // doc read error
                                if (doc.key) free(doc.key);
                                if (doc.meta) free(doc.meta);
                                if (doc.body) free(doc.body);
                                offset = _offset;
                                continue;
                            }
                        } else {
                            doc_offset = offset;
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
                        // skip transactional document once
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
            } while (offset + sizeof(struct docio_length) < new_file->pos);
        }
    }

    docio_free(&dhandle);
    _fdb_close(&new_db);
    fdb_commit(handle, FDB_COMMIT_NORMAL);

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
        spin_unlock(&initial_lock);
    }
    return FDB_RESULT_SUCCESS;
}

LIBFDB_API
fdb_config fdb_get_default_config(void) {
    return get_default_config();
}

LIBFDB_API
fdb_status fdb_open(fdb_handle **ptr_handle,
                    const char *filename,
                    fdb_config *fconfig)
{
#ifdef _MEMPOOL
    mempool_init();
#endif

    fdb_config config;

    if (fconfig) {
        if (validate_fdb_config(fconfig)) {
            config = *fconfig;
        } else {
            return FDB_RESULT_INVALID_CONFIG;
        }
    } else {
        config = get_default_config();
    }

    fdb_handle *handle = (fdb_handle *) calloc(1, sizeof(fdb_handle));
    if (!handle) {
        return FDB_RESULT_ALLOC_FAIL;
    }

    config.cmp_fixed = NULL;
    config.cmp_variable = NULL;
    handle->shandle = NULL;

    fdb_init(fconfig);

    fdb_status fs = _fdb_open(handle, filename, &config);
    if (fs == FDB_RESULT_SUCCESS) {
        *ptr_handle = handle;
    } else {
        *ptr_handle = NULL;
        free(handle);
    }
    return fs;
}

fdb_status fdb_open_for_compactor(fdb_handle **ptr_handle,
                                  const char *filename,
                                  fdb_config *config)
{
#ifdef _MEMPOOL
    mempool_init();
#endif

    fdb_handle *handle = (fdb_handle *) calloc(1, sizeof(fdb_handle));
    if (!handle) {
        return FDB_RESULT_ALLOC_FAIL;
    }
    handle->shandle = NULL;

    fdb_status fs = _fdb_open(handle, filename, config);
    if (fs == FDB_RESULT_SUCCESS) {
        *ptr_handle = handle;
    } else {
        *ptr_handle = NULL;
        free(handle);
    }
    return fs;
}

LIBFDB_API
fdb_status fdb_open_cmp_fixed(fdb_handle **ptr_handle,
                              const char *filename,
                              fdb_config *fconfig)
{
#ifdef _MEMPOOL
    mempool_init();
#endif

    fdb_config config;

    if (fconfig) {
        if (validate_fdb_config(fconfig) &&
            fconfig->cmp_fixed) {
            config = *fconfig;
        } else {
            return FDB_RESULT_INVALID_CONFIG;
        }
    } else {
        return FDB_RESULT_INVALID_ARGS;
    }

    fdb_handle *handle = (fdb_handle *) calloc(1, sizeof(fdb_handle));
    if (!handle) {
        return FDB_RESULT_ALLOC_FAIL;
    }

    config.cmp_variable = NULL;
    handle->shandle = NULL;

    fdb_init(fconfig);

    fdb_status fs = _fdb_open(handle, filename, &config);
    if (fs == FDB_RESULT_SUCCESS) {
        *ptr_handle = handle;
    } else {
        *ptr_handle = NULL;
        free(handle);
    }
    return fs;
}

LIBFDB_API
fdb_status fdb_open_cmp_variable(fdb_handle **ptr_handle,
                                 const char *filename,
                                 fdb_config *fconfig)
{
#ifdef _MEMPOOL
    mempool_init();
#endif

    fdb_config config;

    if (fconfig) {
        if (validate_fdb_config(fconfig) &&
            fconfig->cmp_variable) {
            config = *fconfig;
        } else {
            return FDB_RESULT_INVALID_CONFIG;
        }
    } else {
        return FDB_RESULT_INVALID_ARGS;
    }

    fdb_handle *handle = (fdb_handle *) calloc(1, sizeof(fdb_handle));
    if (!handle) {
        return FDB_RESULT_ALLOC_FAIL;
    }

    config.cmp_fixed = NULL;
    handle->shandle = NULL;

    if (config.chunksize < sizeof(void *)) {
        // chunk size should be equal to or larger than 'sizeof(void*)'
        config.chunksize = sizeof(void *);
    }

    fdb_init(fconfig);

    fdb_status fs = _fdb_open(handle, filename, &config);
    if (fs == FDB_RESULT_SUCCESS) {
        *ptr_handle = handle;
    } else {
        *ptr_handle = NULL;
        free(handle);
    }
    return fs;
}

LIBFDB_API
fdb_status fdb_snapshot_open(fdb_handle *handle_in, fdb_handle **ptr_handle,
                             fdb_seqnum_t seqnum)
{
#ifdef _MEMPOOL
    mempool_init();
#endif

    fdb_config config = handle_in->config;
    fdb_handle *handle;
    fdb_status fs;
    filemgr *file;
    if (!handle_in || !ptr_handle) {
        return FDB_RESULT_INVALID_ARGS;
    }

    // Sequence trees are a must for snapshot creation
    if (handle_in->config.seqtree_opt != FDB_SEQTREE_USE) {
        return FDB_RESULT_INVALID_CONFIG;
    }

    if (!handle_in->shandle) {
        fdb_check_file_reopen(handle_in);
        fdb_link_new_file(handle_in);
        fdb_sync_db_header(handle_in);
        if (handle_in->new_file == NULL) {
            file = handle_in->file;
        } else{
            file = handle_in->new_file;
        }
        handle_in->seqnum = filemgr_get_seqnum(file);
    } else {
        file = handle_in->file;
    }

    // if the max sequence number seen by this handle is lower than the
    // requested snapshot marker, it means the snapshot is not yet visible
    // even via the current fdb_handle
    if (seqnum != FDB_SNAPSHOT_INMEM && seqnum > handle_in->seqnum) {
        return FDB_RESULT_NO_DB_INSTANCE;
    }

    handle = (fdb_handle *) calloc(1, sizeof(fdb_handle));
    if (!handle) {
        return FDB_RESULT_ALLOC_FAIL;
    }

    handle->log_callback = handle_in->log_callback;
    handle->shandle = (struct snap_handle *) calloc(1, sizeof(snap_handle));
    if (!handle->shandle) {
        free(handle);
        return FDB_RESULT_ALLOC_FAIL;
    }
    handle->max_seqnum = seqnum;

    config.flags |= FDB_OPEN_FLAG_RDONLY;
    // do not perform compaction for snapshot
    config.compaction_mode = FDB_COMPACTION_MANUAL;
    fs = _fdb_open(handle, file->filename, &config);

    if (fs == FDB_RESULT_SUCCESS) {
        if (seqnum == FDB_SNAPSHOT_INMEM) {
            snap_init(handle->shandle, handle);
            wal_snapshot(handle->file, (void *)handle->shandle,
                    handle_in->txn,
                    _fdb_wal_snapshot_func);
        }
        *ptr_handle = handle;
    } else {
        *ptr_handle = NULL;
        free(handle->shandle);
        free(handle);
    }
    return fs;
}

LIBFDB_API
fdb_status fdb_rollback(fdb_handle **handle_ptr, fdb_seqnum_t seqnum)
{
#ifdef _MEMPOOL
    mempool_init();
#endif

    fdb_config config;
    fdb_handle *handle_in, *handle;
    fdb_status fs;
    fdb_seqnum_t old_seqnum;

    if (!handle_ptr || !seqnum) {
        return FDB_RESULT_INVALID_ARGS;
    }

    handle_in = *handle_ptr;
    config = handle_in->config;

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
    // even via the current fdb_handle
    if (seqnum > handle_in->seqnum) {
        return FDB_RESULT_NO_DB_INSTANCE;
    }

    handle = (fdb_handle *) calloc(1, sizeof(fdb_handle));
    if (!handle) {
        return FDB_RESULT_ALLOC_FAIL;
    }

    filemgr_set_rollback(handle_in->file, 1); // disallow writes operations
    // All transactions should be closed before rollback
    if (wal_txn_exists(handle_in->file)) {
        filemgr_set_rollback(handle_in->file, 0);
        free(handle);
        return FDB_RESULT_FAIL_BY_TRANSACTION;
    }
    // There should be no compaction on the file
    if (filemgr_get_file_status(handle_in->file) != FILE_NORMAL) {
        filemgr_set_rollback(handle_in->file, 0);
        free(handle);
        return FDB_RESULT_FAIL_BY_COMPACTION;
    }

    handle->log_callback = handle_in->log_callback;
    handle->max_seqnum = seqnum;

    fs = _fdb_open(handle, handle_in->file->filename, &config);
    filemgr_set_rollback(handle_in->file, 0); // allow mutations

    if (fs == FDB_RESULT_SUCCESS) {
        // rollback the file's sequence number
        filemgr_mutex_lock(handle_in->file);
        old_seqnum = filemgr_get_seqnum(handle_in->file);
        filemgr_set_seqnum(handle_in->file, seqnum);
        filemgr_mutex_unlock(handle_in->file);

        fs = fdb_commit(handle, FDB_COMMIT_NORMAL);
        if (fs == FDB_RESULT_SUCCESS) {
            if (handle_in->txn) {
                handle->txn = handle_in->txn;
                handle_in->txn = NULL;
            }
            fdb_close(handle_in);
            handle->max_seqnum = 0;
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
    fconfig->flag = 0x0;
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
    if (config->durability_opt & FDB_DRB_ODIRECT) {
        fconfig->flag |= _ARCH_O_DIRECT;
    }
}

static fdb_status _fdb_open(fdb_handle *handle,
                            const char *filename,
                            const fdb_config *config)
{
    struct filemgr_config fconfig;
    struct btree_kv_ops *main_kv_ops;
    bid_t trie_root_bid = BLK_NOT_FOUND;
    bid_t seq_root_bid = BLK_NOT_FOUND;
    fdb_seqnum_t seqnum = 0;
    fdb_seqtree_opt_t seqtree_opt = config->seqtree_opt;
    uint64_t ndocs = 0;
    uint64_t datasize = 0;
    uint64_t last_wal_flush_hdr_bid = BLK_NOT_FOUND;
    uint8_t header_buf[FDB_BLOCKSIZE];
    char *compacted_filename = NULL;
    char *prev_filename = NULL;
    size_t header_len = 0;

    uint64_t nlivenodes = 0;
    bid_t hdr_bid = 0; // initialize to zero for in-memory snapshot
    char actual_filename[FDB_MAX_FILENAME_LEN];

    if (filename == NULL) {
        return FDB_RESULT_INVALID_ARGS;
    }
    if (strlen(filename) > (FDB_MAX_FILENAME_LEN - 8)) {
        // filename (including path) length is supported up to
        // (FDB_MAX_FILENAME_LEN - 8) bytes.
        return FDB_RESULT_TOO_LONG_FILENAME;
    }

    if (!compactor_is_valid_mode(filename, (fdb_config *)config)) {
        return FDB_RESULT_INVALID_COMPACTION_MODE;
    }

    _fdb_init_file_config(config, &fconfig);

    compactor_get_actual_filename(filename, actual_filename,
                                  config->compaction_mode);
    if (handle->filename) {
        handle->filename = (char *)realloc(handle->filename, strlen(filename)+1);
    } else {
        handle->filename = (char*)malloc(strlen(filename)+1);
    }
    strcpy(handle->filename, filename);

    handle->fileops = get_filemgr_ops();
    filemgr_open_result result = filemgr_open((char *)actual_filename, handle->fileops,
                                              &fconfig, &handle->log_callback);
    if (result.rv != FDB_RESULT_SUCCESS) {
        free(handle->filename);
        handle->filename = NULL;
        return (fdb_status) result.rv;
    }

    handle->file = result.file;
    filemgr_mutex_lock(handle->file);
    filemgr_fetch_header(handle->file, header_buf, &header_len);
    handle->last_hdr_bid = filemgr_get_header_bid(handle->file);
    if (header_len > 0) {
        fdb_fetch_header(header_buf, &trie_root_bid,
                         &seq_root_bid, &ndocs, &nlivenodes,
                         &datasize, &last_wal_flush_hdr_bid,
                         &compacted_filename, &prev_filename);
        // use existing setting
        if (seq_root_bid == BLK_NOT_FOUND) {
            seqtree_opt = FDB_SEQTREE_NOT_USE;
        } else {
            seqtree_opt = FDB_SEQTREE_USE;
        }
        seqnum = filemgr_get_seqnum(handle->file);
    }

    if (handle->shandle && handle->max_seqnum == FDB_SNAPSHOT_INMEM) {
        handle->max_seqnum = seqnum;
        filemgr_mutex_unlock(handle->file);
        hdr_bid = 0; // This prevents _fdb_restore_wal() as incoming handle's
                     // fdb_open() should have already restored it
    } else {
        filemgr_mutex_unlock(handle->file);

        hdr_bid = filemgr_get_pos(handle->file) / FDB_BLOCKSIZE;
        hdr_bid = hdr_bid ? --hdr_bid : 0;
        if (handle->max_seqnum) {
            // Reverse scan the file to locate the DB header with seqnum marker
            while (header_len && seqnum != handle->max_seqnum) {
                hdr_bid = filemgr_fetch_prev_header(handle->file, hdr_bid,
                        header_buf, &header_len, &seqnum,
                        &handle->log_callback);

                if (header_len > 0) {
                    fdb_fetch_header(header_buf, &trie_root_bid,
                                     &seq_root_bid, &ndocs, &nlivenodes,
                                     &datasize, &last_wal_flush_hdr_bid,
                                     &compacted_filename, NULL);
                    handle->last_hdr_bid = hdr_bid;
                }
            }
            if (!header_len) { // Marker MUST match that of DB commit!
                free(handle->filename);
                handle->filename = NULL;
                filemgr_close(handle->file, false, handle->filename,
                        &handle->log_callback);
                return FDB_RESULT_NO_DB_INSTANCE;
            }

            if (!handle->shandle) { // Rollback mode, destroy file WAL..
                wal_shutdown(handle->file);
            }
        } else {
            if (handle->shandle) { // fdb_snapshot_open API call
                if (seqnum) {
                    // Database currently has a non-zero seq number, but the
                    // snapshot was requested with a seq number zero.
                    free(handle->filename);
                    handle->filename = NULL;
                    filemgr_close(handle->file, false, handle->filename,
                            &handle->log_callback);
                    return FDB_RESULT_NO_DB_INSTANCE;
                }
            } // end of zero max_seqnum but non-rollback check
        } // end of zero max_seqnum check
    } // end of durable snapshot locating

    handle->btreeblkops = btreeblk_get_ops();
    handle->bhandle = (struct btreeblk_handle *)calloc(1, sizeof(struct btreeblk_handle));
    handle->bhandle->log_callback = &handle->log_callback;
    handle->dhandle = (struct docio_handle *)calloc(1, sizeof(struct docio_handle));
    handle->dhandle->log_callback = &handle->log_callback;

    handle->config = *config;
    handle->config.seqtree_opt = seqtree_opt;
    handle->last_wal_flush_hdr_bid = BLK_NOT_FOUND;

    handle->new_file = NULL;
    handle->new_dhandle = NULL;

    handle->dirty_updates = 0;

    if (handle->config.compaction_buf_maxsize == 0) {
        handle->config.compaction_buf_maxsize = FDB_COMP_BUF_MAXSIZE;
    }

    docio_init(handle->dhandle, handle->file, config->compress_document_body);
    btreeblk_init(handle->bhandle, handle->file, handle->file->blocksize);

    handle->cur_header_revnum = filemgr_get_header_revnum(handle->file);
    handle->ndocs = ndocs;
    handle->bhandle->nlivenodes = nlivenodes;
    handle->datasize = datasize;
    handle->last_wal_flush_hdr_bid = last_wal_flush_hdr_bid;

    if (!handle->config.cmp_variable) {
        handle->idtree = NULL;
        handle->trie = (struct hbtrie *)malloc(sizeof(struct hbtrie));
        hbtrie_init(handle->trie, config->chunksize, OFFSET_SIZE,
            handle->file->blocksize, trie_root_bid, (void *)handle->bhandle,
            handle->btreeblkops, (void *)handle->dhandle, _fdb_readkey_wrap);
        handle->trie->aux = NULL;

        main_kv_ops = handle->trie->btree_kv_ops;

        if (handle->config.cmp_fixed) {
            // custom compare function for fixed size key
            // keep using hb+trie but replace the cmp function
            main_kv_ops->cmp = _fdb_cmp_fixed_wrap;
            // set aux for cmp wrapping function
            handle->trie->aux = (void*)handle;
        }

    } else {
        // custom compare function for variable length key
        // use a single b-tree instead of hb+trie
        handle->trie = NULL;
        handle->idtree = (struct btree*)malloc(sizeof(struct btree));

        main_kv_ops = (struct btree_kv_ops*)malloc(sizeof(struct btree_kv_ops));
        main_kv_ops = _get_var_kv_ops(main_kv_ops);
        main_kv_ops->cmp = _fdb_cmp_variable_wrap;

        // initialize or load b-tree
        if (trie_root_bid == BLK_NOT_FOUND) {
            btree_init(handle->idtree, (void *)handle->bhandle, handle->btreeblkops,
                main_kv_ops, handle->config.blocksize, handle->config.chunksize,
                OFFSET_SIZE, 0x0, NULL);
        } else {
            btree_init_from_bid(handle->idtree, (void *)handle->bhandle,
                handle->btreeblkops, main_kv_ops, handle->config.blocksize, trie_root_bid);
        }
        // set aux for cmp wrapping function
        handle->idtree->aux = (void*)handle;
    }

    if (handle->config.seqtree_opt == FDB_SEQTREE_USE) {
        handle->seqnum = seqnum;
        struct btree_kv_ops *seq_kv_ops =
            (struct btree_kv_ops *)malloc(sizeof(struct btree_kv_ops));
        //memcpy(seq_kv_ops, main_kv_ops, sizeof(struct btree_kv_ops));
        seq_kv_ops = btree_kv_get_kb64_vb64(seq_kv_ops);
        seq_kv_ops->cmp = _cmp_uint64_t_endian_safe;

        handle->seqtree = (struct btree*)malloc(sizeof(struct btree));
        if (seq_root_bid == BLK_NOT_FOUND) {
            btree_init(handle->seqtree, (void *)handle->bhandle, handle->btreeblkops,
                seq_kv_ops, handle->config.blocksize, sizeof(fdb_seqnum_t),
                OFFSET_SIZE, 0x0, NULL);
         }else{
             btree_init_from_bid(handle->seqtree, (void *)handle->bhandle,
                handle->btreeblkops, seq_kv_ops, handle->config.blocksize, seq_root_bid);
         }
    }else{
        handle->seqtree = NULL;
    }

    _fdb_restore_wal(handle, hdr_bid);

    if (compacted_filename &&
        filemgr_get_file_status(handle->file) == FILE_NORMAL &&
        !handle->shandle) { // do not do compaction recovery on snapshots
        _fdb_recover_compaction(handle, compacted_filename);
    }

    if (prev_filename && !handle->shandle) {
        if (strcmp(prev_filename, handle->file->filename)) {
            // record the old filename into the file handle of current file
            // and REMOVE old file on the first open
            // WARNING: snapshots must have been opened before this call
            if (filemgr_update_file_status(handle->file, handle->file->status,
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

    btreeblk_end(handle->bhandle);

    // do not register read-only handles
    if (!(config->flags & FDB_OPEN_FLAG_RDONLY) &&
        config->compaction_mode == FDB_COMPACTION_AUTO) {
        compactor_register_file(handle->file, (fdb_config *)config);
    }

    return FDB_RESULT_SUCCESS;
}

LIBFDB_API
fdb_status fdb_set_log_callback(fdb_handle *handle,
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
    if (*doc == NULL) {
        return FDB_RESULT_ALLOC_FAIL;
    }

    (*doc)->seqnum = 0;

    if (key && keylen > 0) {
        (*doc)->key = (void *)malloc(keylen);
        if ((*doc)->key == NULL) {
            return FDB_RESULT_ALLOC_FAIL;
        }
        memcpy((*doc)->key, key, keylen);
        (*doc)->keylen = keylen;
    } else {
        (*doc)->key = NULL;
        (*doc)->keylen = 0;
    }

    if (meta && metalen > 0) {
        (*doc)->meta = (void *)malloc(metalen);
        if ((*doc)->meta == NULL) {
            return FDB_RESULT_ALLOC_FAIL;
        }
        memcpy((*doc)->meta, meta, metalen);
        (*doc)->metalen = metalen;
    } else {
        (*doc)->meta = NULL;
        (*doc)->metalen = 0;
    }

    if (body && bodylen > 0) {
        (*doc)->body = (void *)malloc(bodylen);
        if ((*doc)->body == NULL) {
            return FDB_RESULT_ALLOC_FAIL;
        }
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
        if ((*doc)->meta == NULL) {
            return FDB_RESULT_ALLOC_FAIL;
        }
        memcpy((*doc)->meta, meta, metalen);
        (*doc)->metalen = metalen;
    }

    if (body && bodylen > 0) {
        // free previous body
        free((*doc)->body);
        // allocate new body
        (*doc)->body = (void *)malloc(bodylen);
        if ((*doc)->body == NULL) {
            return FDB_RESULT_ALLOC_FAIL;
        }
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
    fdb_handle *handle = (fdb_handle *)voidhandle;
    uint8_t *var_key = alca(uint8_t, handle->config.chunksize);
    uint64_t old_offset = 0;
    hbtrie_result hr;
    btree_result br;

    if (!handle->config.cmp_variable) {
        hr = hbtrie_find_offset(handle->trie,
                                item->header->key,
                                item->header->keylen,
                                (void*)&old_offset);
    } else {
        _set_var_key(var_key, item->header->key, item->header->keylen);
        br = btree_find(handle->idtree, var_key, (void*)&old_offset);
        _free_var_key(var_key);
    }
    btreeblk_end(handle->bhandle);
    old_offset = _endian_decode(old_offset);

    return old_offset;
}

INLINE wal_result _fdb_wal_snapshot_func(void *handle, fdb_doc *doc,
                                         uint64_t offset) {
    return snap_insert((struct snap_handle *)handle, doc, offset);
}

INLINE void _fdb_wal_flush_func(void *voidhandle, struct wal_item *item)
{
    hbtrie_result hr;
    btree_result br;
    fdb_handle *handle = (fdb_handle *)voidhandle;
    fdb_seqnum_t _seqnum;
    uint8_t *var_key = alca(uint8_t, handle->config.chunksize);
    uint64_t old_offset, _offset;

    memset(var_key, 0, handle->config.chunksize);

    if (item->action == WAL_ACT_INSERT || item->action == WAL_ACT_LOGICAL_REMOVE) {
        _offset = _endian_encode(item->offset);

        if (!handle->config.cmp_variable) {
            hr = hbtrie_insert(handle->trie,
                               item->header->key,
                               item->header->keylen,
                               (void *)&_offset,
                               (void *)&old_offset);
        } else {
            _set_var_key(var_key, item->header->key, item->header->keylen);
            br = btree_find(handle->idtree, var_key, (void *)&old_offset);
            br = btree_insert(handle->idtree, var_key, (void *)&_offset);
            _free_var_key(var_key);

            if (br == BTREE_RESULT_SUCCESS) {
                hr = HBTRIE_RESULT_SUCCESS;
            } else if (br == BTREE_RESULT_UPDATE) {
                hr = HBTRIE_RESULT_UPDATE;
            } else {
                hr = HBTRIE_RESULT_FAIL;
            }
        }
        btreeblk_end(handle->bhandle);
        old_offset = _endian_decode(old_offset);

        if (handle->config.seqtree_opt == FDB_SEQTREE_USE) {
            _seqnum = _endian_encode(item->seqnum);
            br = btree_insert(handle->seqtree, (void *)&_seqnum, (void *)&_offset);
            btreeblk_end(handle->bhandle);
        }

        if (hr == HBTRIE_RESULT_SUCCESS) {
            if (item->action == WAL_ACT_INSERT) {
                ++handle->ndocs;
            }
            handle->datasize += item->doc_size;
        } else { // update or logical delete
            struct docio_length len;
            // This block is already cached when we call HBTRIE_INSERT.
            // No additional block access.
            len = docio_read_doc_length(handle->dhandle, old_offset);

            if (!(len.flag & DOCIO_DELETED)) {
                if (item->action == WAL_ACT_LOGICAL_REMOVE) {
                    --handle->ndocs;
                }
            } else {
                if (item->action == WAL_ACT_INSERT) {
                    ++handle->ndocs;
                }
            }

            handle->datasize -= _fdb_get_docsize(len);
            handle->datasize += item->doc_size;
        }
    } else {
        // Immediate remove
        if (!handle->config.cmp_variable) {
            hr = hbtrie_remove(handle->trie, item->header->key, item->header->keylen);
        } else {
            _set_var_key(var_key, item->header->key, item->header->keylen);
            br = btree_remove(handle->idtree, var_key);
            _free_var_key(var_key);

            hr = (br == BTREE_RESULT_FAIL)?(HBTRIE_RESULT_FAIL):
                                           (HBTRIE_RESULT_SUCCESS);
        }
        btreeblk_end(handle->bhandle);

        if (handle->config.seqtree_opt == FDB_SEQTREE_USE) {
            _seqnum = _endian_encode(item->seqnum);
            br = btree_remove(handle->seqtree, (void*)&_seqnum);
            btreeblk_end(handle->bhandle);
        }

        if (hr == HBTRIE_RESULT_SUCCESS) {
            --handle->ndocs;
            handle->datasize -= item->doc_size;
        }
    }
}

void fdb_sync_db_header(fdb_handle *handle)
{
    uint64_t cur_revnum = filemgr_get_header_revnum(handle->file);
    if (handle->cur_header_revnum != cur_revnum) {
        void *header_buf = NULL;
        size_t header_len;

        handle->last_hdr_bid = filemgr_get_header_bid(handle->file);
        header_buf = filemgr_fetch_header(handle->file, NULL, &header_len);
        if (header_len > 0) {
            bid_t idtree_root;
            bid_t new_seq_root;
            char *compacted_filename;
            char *prev_filename = NULL;

            fdb_fetch_header(header_buf, &idtree_root,
                             &new_seq_root,
                             &handle->ndocs, &handle->bhandle->nlivenodes,
                             &handle->datasize, &handle->last_wal_flush_hdr_bid,
                             &compacted_filename, &prev_filename);

            if (!handle->config.cmp_variable) {
                handle->trie->root_bid = idtree_root;
            } else {
                btree_init_from_bid(
                    handle->idtree, handle->idtree->blk_handle,
                    handle->idtree->blk_ops, handle->idtree->kv_ops,
                    handle->idtree->blksize, idtree_root);
            }

            if (handle->config.seqtree_opt == FDB_SEQTREE_USE) {
                if (new_seq_root != handle->seqtree->root_bid) {
                    btree_init_from_bid(
                                        handle->seqtree, handle->seqtree->blk_handle,
                                        handle->seqtree->blk_ops, handle->seqtree->kv_ops,
                                        handle->seqtree->blksize, new_seq_root);
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

void fdb_check_file_reopen(fdb_handle *handle)
{
    // check whether the compaction is done
    if (filemgr_get_file_status(handle->file) == FILE_REMOVED_PENDING) {
        uint64_t ndocs, datasize, nlivenodes, last_wal_flush_hdr_bid;
        size_t header_len;
        char *new_filename;
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
            btreeblk_end(handle->bhandle);
            btreeblk_free(handle->bhandle);

            // switch to new file & docio handle
            handle->file = handle->new_file;
            handle->new_file = NULL;
            handle->dhandle = handle->new_dhandle;
            handle->new_dhandle = NULL;

            btreeblk_init(handle->bhandle, handle->file, handle->config.blocksize);

            // read new file's header
            filemgr_fetch_header(handle->file, buf, &header_len);
            fdb_fetch_header(buf,
                             &trie_root_bid, &seq_root_bid,
                             &ndocs, &nlivenodes, &datasize, &last_wal_flush_hdr_bid,
                             &new_filename, NULL);

            // reset trie (id-tree)
            if (!handle->config.cmp_variable) {
                handle->trie->root_bid = trie_root_bid;
                handle->trie->btreeblk_handle = handle->bhandle;
                handle->trie->doc_handle = handle->dhandle;
            } else {
                if (trie_root_bid != BLK_NOT_FOUND) {
                    btree_init_from_bid(handle->idtree, (void *)handle->bhandle,
                                        handle->idtree->blk_ops,
                                        handle->idtree->kv_ops,
                                        handle->config.blocksize,
                                        trie_root_bid);
                } else {
                    btree_init(handle->idtree, (void *)handle->bhandle,
                               handle->idtree->blk_ops,
                               handle->idtree->kv_ops,
                               handle->config.blocksize,
                               handle->config.chunksize,
                               OFFSET_SIZE, 0x0, NULL);
                }
            }

            // reset seq tree
            if (handle->config.seqtree_opt == FDB_SEQTREE_USE) {
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

            // the others
            handle->cur_header_revnum = filemgr_get_header_revnum(handle->file);
            handle->ndocs = ndocs;
            handle->bhandle->nlivenodes = nlivenodes;
            handle->datasize = datasize;
            handle->dirty_updates = 0;

            // note that we don't need to call 'compactor_deregister_file'
            // because the old file is already removed when compaction is complete.
            if (!(config.flags & FDB_OPEN_FLAG_RDONLY) &&
                config.compaction_mode == FDB_COMPACTION_AUTO) {
                compactor_register_file(handle->file, &config);
            }

        } else {
            // close the current file and newly open the new file
            if (handle->config.compaction_mode == FDB_COMPACTION_AUTO) {
                // compaction daemon mode .. just close and then open
                char filename[FDB_MAX_FILENAME_LEN];
                strcpy(filename, handle->filename);
                _fdb_close(handle);
                _fdb_open(handle, filename, &config);

            } else {
                filemgr_fetch_header(handle->file, buf, &header_len);
                fdb_fetch_header(buf,
                                 &trie_root_bid, &seq_root_bid,
                                 &ndocs, &nlivenodes, &datasize, &last_wal_flush_hdr_bid,
                                 &new_filename, NULL);
                _fdb_close(handle);
                _fdb_open(handle, new_filename, &config);
            }
        }
    }
}

void fdb_link_new_file(fdb_handle *handle)
{
    // check whether this file is being compacted
    if (filemgr_get_file_status(handle->file) == FILE_COMPACT_OLD &&
        handle->new_file == NULL) {
        assert(handle->file->new_file);

        // open new file and new dhandle
        filemgr_open_result result = filemgr_open(handle->file->new_file->filename,
                                                  handle->fileops, handle->file->config,
                                                  &handle->log_callback);
        handle->new_file = result.file;
        handle->new_dhandle = (struct docio_handle *) calloc(1, sizeof(struct docio_handle));
        handle->new_dhandle->log_callback = &handle->log_callback;
        docio_init(handle->new_dhandle,
                   handle->new_file,
                   handle->config.compress_document_body);
    }
}

LIBFDB_API
fdb_status fdb_get(fdb_handle *handle, fdb_doc *doc)
{
    uint64_t offset, _offset;
    struct docio_object _doc;
    struct filemgr *wal_file;
    struct docio_handle *dhandle;
    wal_result wr;
    hbtrie_result hr = HBTRIE_RESULT_FAIL;
    fdb_txn *txn = handle->txn;

    if (doc->key == NULL || doc->keylen == 0 || doc->keylen > FDB_MAX_KEYLEN) {
        return FDB_RESULT_INVALID_ARGS;
    }

    if (!handle->shandle) {
        fdb_check_file_reopen(handle);
        fdb_link_new_file(handle);
        fdb_sync_db_header(handle);

        if (handle->new_file == NULL) {
            wal_file = handle->file;
        }else{
            wal_file = handle->new_file;
        }
        handle->seqnum = filemgr_get_seqnum(wal_file);
        dhandle = handle->dhandle;

        if (!txn) {
            txn = &wal_file->global_txn;
        }
        wr = wal_find(txn, wal_file, doc, &offset);
    } else {
        wr = snap_find(handle->shandle, doc, &offset);
        dhandle = handle->dhandle;
    }

    if (wr == WAL_RESULT_FAIL) {
        bool locked = false;
        bid_t dirty_idtree_root, dirty_seqtree_root;

        if (handle->dirty_updates) {
            // grab lock for writer if there are dirty updates
            filemgr_mutex_lock(handle->file);
            locked = true;

            // get dirty root nodes
            filemgr_get_dirty_root(handle->file, &dirty_idtree_root, &dirty_seqtree_root);
            if (dirty_idtree_root != BLK_NOT_FOUND) {
                handle->trie->root_bid = dirty_idtree_root;
            }
            if (handle->config.seqtree_opt == FDB_SEQTREE_USE) {
                if (dirty_seqtree_root != BLK_NOT_FOUND) {
                    handle->seqtree->root_bid = dirty_seqtree_root;
                }
            }
        }

        if (!handle->config.cmp_variable) {
            hr = hbtrie_find(handle->trie, doc->key, doc->keylen, (void *)&offset);
        } else {
            // custom compare function for variable length key
            uint8_t *var_key = alca(uint8_t, handle->config.chunksize);
            _set_var_key((void *)var_key, doc->key, doc->keylen);
            btree_result br = btree_find(handle->idtree, (void*)var_key, (void *)&offset);
            _free_var_key((void *)var_key);

            hr = (br == BTREE_RESULT_FAIL)?(HBTRIE_RESULT_FAIL):
                                           (HBTRIE_RESULT_SUCCESS);
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

    if (wr != WAL_RESULT_FAIL || hr != HBTRIE_RESULT_FAIL) {
        _doc.key = doc->key;
        _doc.length.keylen = doc->keylen;
        _doc.meta = doc->meta;
        _doc.body = doc->body;

        if (wr == WAL_RESULT_SUCCESS && doc->deleted) {
            return FDB_RESULT_KEY_NOT_FOUND;
        }

        _offset = docio_read_doc(dhandle, offset, &_doc);
        if (_offset == offset) {
            return FDB_RESULT_KEY_NOT_FOUND;
        }

        doc->seqnum = _doc.seqnum;
        doc->metalen = _doc.length.metalen;
        doc->bodylen = _doc.length.bodylen;
        doc->key = _doc.key;
        doc->meta = _doc.meta;
        doc->body = _doc.body;
        doc->deleted = _doc.length.flag & DOCIO_DELETED;
        doc->size_ondisk = _fdb_get_docsize(_doc.length);
        doc->offset = offset;

        if (_doc.length.keylen != doc->keylen || _doc.length.flag & DOCIO_DELETED) {
            return FDB_RESULT_KEY_NOT_FOUND;
        }

        return FDB_RESULT_SUCCESS;
    }

    return FDB_RESULT_KEY_NOT_FOUND;
}

// search document metadata using key
LIBFDB_API
fdb_status fdb_get_metaonly(fdb_handle *handle, fdb_doc *doc)
{
    uint64_t offset;
    struct docio_object _doc;
    struct docio_handle *dhandle;
    struct filemgr *wal_file;
    wal_result wr;
    hbtrie_result hr;
    fdb_txn *txn;

    if (handle == NULL || doc == NULL || doc->key == NULL ||
        doc->keylen == 0 || doc->keylen > FDB_MAX_KEYLEN) {
        return FDB_RESULT_INVALID_ARGS;
    }

    txn = handle->txn;

    if (!handle->shandle) {
        fdb_check_file_reopen(handle);
        fdb_link_new_file(handle);
        fdb_sync_db_header(handle);

        if (handle->new_file == NULL) {
            wal_file = handle->file;
        }else{
            wal_file = handle->new_file;
        }
        dhandle = handle->dhandle;

        if (!txn) {
            txn = &wal_file->global_txn;
        }
        wr = wal_find(txn, wal_file, doc, &offset);
    } else {
        wr = snap_find(handle->shandle, doc, &offset);
        dhandle = handle->dhandle;
    }

    if (wr == WAL_RESULT_FAIL) {
        bool locked = false;
        bid_t dirty_idtree_root, dirty_seqtree_root;

        if (handle->dirty_updates) {
            // grab lock for writer if there are dirty updates
            filemgr_mutex_lock(handle->file);
            locked = true;

            // get dirty root nodes
            filemgr_get_dirty_root(handle->file, &dirty_idtree_root, &dirty_seqtree_root);
            if (dirty_idtree_root != BLK_NOT_FOUND) {
                handle->trie->root_bid = dirty_idtree_root;
            }
            if (handle->config.seqtree_opt == FDB_SEQTREE_USE) {
                if (dirty_seqtree_root != BLK_NOT_FOUND) {
                    handle->seqtree->root_bid = dirty_seqtree_root;
                }
            }
        }

        if (!handle->config.cmp_variable) {
            hr = hbtrie_find(handle->trie, doc->key, doc->keylen, (void *)&offset);
        } else {
            // custom compare function for variable length key
            uint8_t *var_key = alca(uint8_t, handle->config.chunksize);
            _set_var_key((void *)var_key, doc->key, doc->keylen);
            btree_result br = btree_find(handle->idtree, (void*)var_key, (void *)&offset);
            _free_var_key((void *)var_key);

            hr = (br == BTREE_RESULT_FAIL)?(HBTRIE_RESULT_FAIL):
                                           (HBTRIE_RESULT_SUCCESS);
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

    if (wr != WAL_RESULT_FAIL || hr != HBTRIE_RESULT_FAIL) {
        _doc.key = doc->key;
        _doc.length.keylen = doc->keylen;
        _doc.meta = _doc.body = NULL;

        uint64_t body_offset = docio_read_doc_key_meta(dhandle, offset, &_doc);
        if (body_offset == offset){
            return FDB_RESULT_KEY_NOT_FOUND;
        }

        doc->seqnum = _doc.seqnum;
        doc->metalen = _doc.length.metalen;
        doc->bodylen = _doc.length.bodylen;
        doc->key = _doc.key;
        doc->meta = _doc.meta;
        doc->body = _doc.body;
        doc->deleted = _doc.length.flag & DOCIO_DELETED;
        doc->size_ondisk = _fdb_get_docsize(_doc.length);
        doc->offset = offset;

        if (_doc.length.keylen != doc->keylen) {
            return FDB_RESULT_KEY_NOT_FOUND;
        }

        return FDB_RESULT_SUCCESS;
    }

    return FDB_RESULT_KEY_NOT_FOUND;
}

// search document using sequence number
LIBFDB_API
fdb_status fdb_get_byseq(fdb_handle *handle, fdb_doc *doc)
{
    uint64_t offset, _offset;
    struct docio_object _doc;
    struct docio_handle *dhandle;
    struct filemgr *wal_file;
    wal_result wr;
    btree_result br = BTREE_RESULT_FAIL;
    fdb_seqnum_t _seqnum;
    fdb_txn *txn = handle->txn;

    if (doc->seqnum == SEQNUM_NOT_USED) {
        return FDB_RESULT_INVALID_ARGS;
    }

    // Sequence trees are a must for byseq operations
    if (handle->config.seqtree_opt != FDB_SEQTREE_USE) {
        return FDB_RESULT_INVALID_CONFIG;
    }

    if (!handle->shandle) {
        fdb_check_file_reopen(handle);
        fdb_link_new_file(handle);
        fdb_sync_db_header(handle);

        if (handle->new_file == NULL) {
            wal_file = handle->file;
        }else{
            wal_file = handle->new_file;
        }
        dhandle = handle->dhandle;

        if (!txn) {
            txn = &wal_file->global_txn;
        }
        wr = wal_find(txn, wal_file, doc, &offset);
    } else {
        wr = snap_find(handle->shandle, doc, &offset);
        dhandle = handle->dhandle;
    }

    if (wr == WAL_RESULT_FAIL) {
        bool locked = false;
        bid_t dirty_idtree_root, dirty_seqtree_root;

        if (handle->dirty_updates) {
            // grab lock for writer if there are dirty updates
            filemgr_mutex_lock(handle->file);
            locked = true;

            // get dirty root nodes
            filemgr_get_dirty_root(handle->file, &dirty_idtree_root, &dirty_seqtree_root);
            if (dirty_idtree_root != BLK_NOT_FOUND) {
                handle->trie->root_bid = dirty_idtree_root;
            }
            if (handle->config.seqtree_opt == FDB_SEQTREE_USE) {
                if (dirty_seqtree_root != BLK_NOT_FOUND) {
                    handle->seqtree->root_bid = dirty_seqtree_root;
                }
            }
        }

        _seqnum = _endian_encode(doc->seqnum);
        br = btree_find(handle->seqtree, (void *)&_seqnum, (void *)&offset);
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

    if (wr != WAL_RESULT_FAIL || br != BTREE_RESULT_FAIL) {
        _doc.key = doc->key;
        _doc.meta = doc->meta;
        _doc.body = doc->body;

        if (wr == WAL_RESULT_SUCCESS && doc->deleted) {
            return FDB_RESULT_KEY_NOT_FOUND;
        }

        _offset = docio_read_doc(dhandle, offset, &_doc);
        if (_offset == offset) {
            return FDB_RESULT_KEY_NOT_FOUND;
        }

        doc->seqnum = _doc.seqnum;
        doc->keylen = _doc.length.keylen;
        doc->metalen = _doc.length.metalen;
        doc->bodylen = _doc.length.bodylen;
        doc->key = _doc.key;
        doc->meta = _doc.meta;
        doc->body = _doc.body;
        doc->deleted = _doc.length.flag & DOCIO_DELETED;
        doc->size_ondisk = _fdb_get_docsize(_doc.length);
        doc->offset = offset;

        if (_doc.length.flag & DOCIO_DELETED) {
            return FDB_RESULT_KEY_NOT_FOUND;
        }

        assert(doc->seqnum == _doc.seqnum);

        return FDB_RESULT_SUCCESS;
    }

    return FDB_RESULT_KEY_NOT_FOUND;
}

// search document metadata using sequence number
LIBFDB_API
fdb_status fdb_get_metaonly_byseq(fdb_handle *handle, fdb_doc *doc)
{
    uint64_t offset;
    struct docio_object _doc;
    struct docio_handle *dhandle;
    struct filemgr *wal_file;
    wal_result wr;
    btree_result br;
    fdb_seqnum_t _seqnum;
    fdb_txn *txn = handle->txn;

    if (doc->seqnum == SEQNUM_NOT_USED) {
        return FDB_RESULT_INVALID_ARGS;
    }

    // Sequence trees are a must for byseq operations
    if (handle->config.seqtree_opt != FDB_SEQTREE_USE) {
        return FDB_RESULT_INVALID_CONFIG;
    }

    if (!handle->shandle) {
        fdb_check_file_reopen(handle);
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
        wr = wal_find(txn, wal_file, doc, &offset);
    } else {
        wr = snap_find(handle->shandle, doc, &offset);
        dhandle = handle->dhandle;
    }

    if (wr == WAL_RESULT_FAIL) {
        bool locked = false;
        bid_t dirty_idtree_root, dirty_seqtree_root;

        if (handle->dirty_updates) {
            // grab lock for writer if there are dirty updates
            filemgr_mutex_lock(handle->file);
            locked = true;

            // get dirty root nodes
            filemgr_get_dirty_root(handle->file, &dirty_idtree_root, &dirty_seqtree_root);
            if (dirty_idtree_root != BLK_NOT_FOUND) {
                handle->trie->root_bid = dirty_idtree_root;
            }
            if (handle->config.seqtree_opt == FDB_SEQTREE_USE) {
                if (dirty_seqtree_root != BLK_NOT_FOUND) {
                    handle->seqtree->root_bid = dirty_seqtree_root;
                }
            }
        }

        _seqnum = _endian_encode(doc->seqnum);
        br = btree_find(handle->seqtree, (void *)&_seqnum, (void *)&offset);
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

    if (wr != WAL_RESULT_FAIL || br != BTREE_RESULT_FAIL) {
        _doc.key = doc->key;
        _doc.meta = _doc.body = NULL;

        uint64_t body_offset = docio_read_doc_key_meta(dhandle, offset, &_doc);
        if (body_offset == offset) {
            return FDB_RESULT_KEY_NOT_FOUND;
        }

        doc->keylen = _doc.length.keylen;
        doc->metalen = _doc.length.metalen;
        doc->bodylen = _doc.length.bodylen;
        doc->key = _doc.key;
        doc->meta = _doc.meta;
        doc->body = _doc.body;
        doc->deleted = _doc.length.flag & DOCIO_DELETED;
        doc->size_ondisk = _fdb_get_docsize(_doc.length);
        doc->offset = offset;

        assert(doc->seqnum == _doc.seqnum);

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

// Retrieve a doc's metadata and body with a given doc offset in the database file.
LIBFDB_API
fdb_status fdb_get_byoffset(fdb_handle *handle, fdb_doc *doc)
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
            if (!equal_docs(doc, &_doc)) {
                free_docio_object(&_doc, 1, 1, 1);
                return FDB_RESULT_KEY_NOT_FOUND;
            }
        } else {
            return FDB_RESULT_KEY_NOT_FOUND;
        }
    } else {
        if (!equal_docs(doc, &_doc)) {
            free_docio_object(&_doc, 1, 1, 1);
            if (handle->new_dhandle && !handle->shandle) {
                // Look up the new file being compacted
                _offset = docio_read_doc(handle->new_dhandle, offset, &_doc);
                if (_offset == offset) {
                    return FDB_RESULT_KEY_NOT_FOUND;
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

    if (_doc.length.flag & DOCIO_DELETED) {
        return FDB_RESULT_KEY_NOT_FOUND;
    }

    return FDB_RESULT_SUCCESS;
}

static uint64_t _fdb_get_wal_threshold(fdb_handle *handle)
{
    if (filemgr_get_file_status(handle->file) == FILE_COMPACT_NEW) {
        return wal_get_size(handle->file);
    }
    return handle->config.wal_threshold;
}

LIBFDB_API
fdb_status fdb_set(fdb_handle *handle, fdb_doc *doc)
{
    uint64_t offset;
    struct docio_object _doc;
    struct filemgr *file;
    struct docio_handle *dhandle;
    struct timeval tv;
    bool txn_enabled = false;
    fdb_txn *txn = handle->txn;

    if (handle->config.flags & FDB_OPEN_FLAG_RDONLY) {
        return fdb_log(&handle->log_callback, FDB_RESULT_RONLY_VIOLATION,
                       "Warning: SET is not allowed on the read-only DB file '%s'.",
                       handle->file->filename);
    }

    if ( doc->key == NULL || doc->keylen == 0 || doc->keylen > FDB_MAX_KEYLEN ||
        (doc->metalen > 0 && doc->meta == NULL) ||
        (doc->bodylen > 0 && doc->body == NULL)) {
        return FDB_RESULT_INVALID_ARGS;
    }

    file = handle->file;

    _doc.length.keylen = doc->keylen;
    _doc.length.metalen = doc->metalen;
    _doc.length.bodylen = doc->deleted ? 0 : doc->bodylen;
    _doc.key = doc->key;
    _doc.meta = doc->meta;
    _doc.body = doc->deleted ? NULL : doc->body;

fdb_set_start:
    fdb_check_file_reopen(handle);
    fdb_sync_db_header(handle);

    if (handle->new_file == NULL) {
        file = handle->file;
        dhandle = handle->dhandle;
        filemgr_mutex_lock(file);

        fdb_link_new_file(handle);
        if (handle->new_file) {
            // compaction is being performed and new file exists
            // relay lock
            filemgr_mutex_lock(handle->new_file);
            filemgr_mutex_unlock(handle->file);
            // reset FILE and DHANDLE
            file = handle->new_file;
            dhandle = handle->new_dhandle;
        }
    } else {
        file = handle->new_file;
        dhandle = handle->new_dhandle;
        filemgr_mutex_lock(file);
    }

    if (filemgr_is_rollback_on(file)) {
        filemgr_mutex_unlock(file);
        return FDB_RESULT_FAIL_BY_ROLLBACK;
    }

    if (!(file->status == FILE_NORMAL ||
          file->status == FILE_COMPACT_NEW)) {
        // we must not write into this file
        // file status was changed by other thread .. start over
        filemgr_mutex_unlock(file);
        goto fdb_set_start;
    }

    if (handle->config.seqtree_opt == FDB_SEQTREE_USE) {
        handle->seqnum = filemgr_get_seqnum(file) + 1;
        filemgr_set_seqnum(file, handle->seqnum);
        _doc.seqnum = doc->seqnum = handle->seqnum;
    } else{
        _doc.seqnum = SEQNUM_NOT_USED;
    }

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
    wal_insert(txn, file, doc, offset);

    if (wal_get_dirty_status(file)== FDB_WAL_CLEAN) {
        wal_set_dirty_status(file, FDB_WAL_DIRTY);
    }

    if (handle->config.wal_flush_before_commit &&
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
            handle->seqtree->root_bid = dirty_seqtree_root;
        }

        if (wal_get_num_flushable(file) > _fdb_get_wal_threshold(handle)) {
            struct avl_tree flush_items;

            // commit only for non-transactional WAL entries
            wal_commit(&file->global_txn, file, NULL);
            wal_flush(file, (void *)handle,
                      _fdb_wal_flush_func, _fdb_wal_get_old_offset, &flush_items);
            wal_set_dirty_status(file, FDB_WAL_PENDING);
            // it is ok to release flushed items becuase
            // these items are not actually committed yet.
            // they become visible after fdb_commit is invoked.
            wal_release_flushed_items(file, &flush_items);

            // sync new root node
            dirty_idtree_root = handle->trie->root_bid;
            if (handle->config.seqtree_opt == FDB_SEQTREE_USE) {
                dirty_seqtree_root = handle->seqtree->root_bid;
            }
            filemgr_set_dirty_root(file,
                                   dirty_idtree_root,
                                   dirty_seqtree_root);
        }
    }

    filemgr_mutex_unlock(file);

    return FDB_RESULT_SUCCESS;
}

LIBFDB_API
fdb_status fdb_del(fdb_handle *handle, fdb_doc *doc)
{
    if (handle->config.flags & FDB_OPEN_FLAG_RDONLY) {
        return fdb_log(&handle->log_callback, FDB_RESULT_RONLY_VIOLATION,
                       "Warning: DEL is not allowed on the read-only DB file '%s'.",
                       handle->file->filename);
    }

    if (doc->key == NULL || doc->keylen == 0 || doc->keylen > FDB_MAX_KEYLEN) {
        return FDB_RESULT_INVALID_ARGS;
    }

    doc->deleted = true;
    fdb_doc _doc;
    _doc = *doc;
    _doc.bodylen = 0;
    _doc.body = NULL;
    return fdb_set(handle, &_doc);
}

static uint64_t _fdb_set_file_header(fdb_handle *handle)
{
    /*
    <ForestDB header>
    [offset]: (content)
    [     0]: BID of root node of root B+Tree of HB+Trie: 8 bytes
    [     8]: BID of root node of seq B+Tree: 8 bytes (0xFF.. if not used)
    [    16]: # of live documents: 8 bytes
    [    24]: # of live B+Tree nodes: 8 bytes
    [    32]: Data size (byte): 8 bytes
    [    40]: BID of the DB header created when last WAL flush: 8 bytes
    [    48]: Size of newly compacted target file name : 2 bytes
    [    50]: Size of old file name before compaction :  2 bytes
    [    52]: File name of newly compacted file : x bytes
    [  52+x]: File name of old file before compcation : y bytes
    [52+x+y]: CRC32: 4 bytes
    total size (header's length): 56+x+y bytes
    */
    uint8_t *buf = alca(uint8_t, handle->config.blocksize);
    uint16_t new_filename_len = 0;
    uint16_t old_filename_len = 0;
    uint16_t _edn_safe_16;
    uint32_t crc;
    uint64_t _edn_safe_64;
    size_t offset = 0;
    struct filemgr *cur_file;

    cur_file = (handle->file->new_file)?(handle->file->new_file):
                                        (handle->file);

    // hb+trie or idtree root bid
    if (!handle->config.cmp_variable) {
        _edn_safe_64 = _endian_encode(handle->trie->root_bid);
    } else {
        _edn_safe_64 = _endian_encode(handle->idtree->root_bid);
    }
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

    // # docs
    _edn_safe_64 = _endian_encode(handle->ndocs);
    seq_memcpy(buf + offset, &_edn_safe_64, sizeof(handle->ndocs), offset);
    // # live nodes
    _edn_safe_64 = _endian_encode(handle->bhandle->nlivenodes);
    seq_memcpy(buf + offset, &_edn_safe_64,
               sizeof(handle->bhandle->nlivenodes), offset);
    // data size
    _edn_safe_64 = _endian_encode(handle->datasize);
    seq_memcpy(buf + offset, &_edn_safe_64, sizeof(handle->datasize), offset);
    // last header bid
    _edn_safe_64 = _endian_encode(handle->last_wal_flush_hdr_bid);
    seq_memcpy(buf + offset, &_edn_safe_64,
               sizeof(handle->last_wal_flush_hdr_bid), offset);

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

static void _fdb_append_commit_mark(void *voidhandle, uint64_t offset)
{
    fdb_handle *handle = (fdb_handle *)voidhandle;
    struct filemgr *file;
    struct docio_handle *dhandle;

    if (handle->new_file) {
        file = handle->new_file;
        dhandle = handle->new_dhandle;
    } else {
        file = handle->file;
        dhandle = handle->dhandle;
    }
    docio_append_commit_mark(dhandle, offset);
}

LIBFDB_API
fdb_status fdb_commit(fdb_handle *handle, fdb_commit_opt_t opt)
{
    fdb_txn *txn = handle->txn;
    fdb_txn *earliest_txn;
    fdb_status fs = FDB_RESULT_SUCCESS;
    bool wal_flushed = false;
    bid_t dirty_idtree_root, dirty_seqtree_root;
    struct avl_tree flush_items;

    if (handle->config.flags & FDB_OPEN_FLAG_RDONLY) {
        return fdb_log(&handle->log_callback, FDB_RESULT_RONLY_VIOLATION,
                       "Warning: Commit is not allowed on the read-only DB file '%s'.",
                       handle->file->filename);
    }

    fdb_check_file_reopen(handle);
    fdb_sync_db_header(handle);

    filemgr_mutex_lock(handle->file);
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
            wal_commit(txn, handle->new_file, _fdb_append_commit_mark);
        } else {
            // non-transactional updates
            wal_commit(&handle->new_file->global_txn, handle->new_file, NULL);
        }

        fs = filemgr_sync(handle->new_file, &handle->log_callback);

        filemgr_mutex_unlock(handle->new_file);
    } else {
        // normal case
        btreeblk_end(handle->bhandle);

        // commit wal
        if (txn) {
            // transactional updates
            wal_commit(txn, handle->file, _fdb_append_commit_mark);
            if (wal_get_dirty_status(handle->file)== FDB_WAL_CLEAN) {
                wal_set_dirty_status(handle->file, FDB_WAL_DIRTY);
            }
        } else {
            // non-transactional updates
            wal_commit(&handle->file->global_txn, handle->file, NULL);
        }

        // sync dirty root nodes
        filemgr_get_dirty_root(handle->file, &dirty_idtree_root, &dirty_seqtree_root);
        if (dirty_idtree_root != BLK_NOT_FOUND) {
            handle->trie->root_bid = dirty_idtree_root;
        }
        if (handle->config.seqtree_opt == FDB_SEQTREE_USE &&
            dirty_seqtree_root != BLK_NOT_FOUND) {
            handle->seqtree->root_bid = dirty_seqtree_root;
        }

        if (wal_get_num_flushable(handle->file) > _fdb_get_wal_threshold(handle) ||
            wal_get_dirty_status(handle->file) == FDB_WAL_PENDING ||
            opt & FDB_COMMIT_MANUAL_WAL_FLUSH) {
            // wal flush when
            // 1. wal size exceeds threshold
            // 2. wal is already flushed before commit
            //    (in this case, flush the rest of entries)
            // 3. user forces to manually flush wal
            wal_flush(handle->file, (void *)handle,
                      _fdb_wal_flush_func, _fdb_wal_get_old_offset,
                      &flush_items);
            wal_set_dirty_status(handle->file, FDB_WAL_CLEAN);
            wal_flushed = true;
        }

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

        if (txn == NULL) {
            // update global_txn's previous header BID
            handle->file->global_txn.prev_hdr_bid = handle->last_hdr_bid;
        }

        handle->cur_header_revnum = _fdb_set_file_header(handle);
        fs = filemgr_commit(handle->file, &handle->log_callback);
        if (wal_flushed) {
            wal_release_flushed_items(handle->file, &flush_items);
        }

        handle->dirty_updates = 0;
        filemgr_mutex_unlock(handle->file);
    }

    return fs;
}

static void _fdb_commit_and_remove_pending(fdb_handle *handle,
                                           struct filemgr *old_file,
                                           struct filemgr *new_file)
{
    fdb_txn *earliest_txn;
    bool wal_flushed = false;
    bid_t dirty_idtree_root, dirty_seqtree_root;
    struct avl_tree flush_items;

    filemgr_mutex_lock(handle->file);

    btreeblk_end(handle->bhandle);

    // sync dirty root nodes
    filemgr_get_dirty_root(handle->file, &dirty_idtree_root, &dirty_seqtree_root);
    if (dirty_idtree_root != BLK_NOT_FOUND) {
        handle->trie->root_bid = dirty_idtree_root;
    }
    if (handle->config.seqtree_opt == FDB_SEQTREE_USE &&
        dirty_seqtree_root != BLK_NOT_FOUND) {
        handle->seqtree->root_bid = dirty_seqtree_root;
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

    handle->last_hdr_bid = filemgr_get_next_alloc_block(handle->file);
    if (wal_get_dirty_status(handle->file) == FDB_WAL_CLEAN) {
        earliest_txn = wal_earliest_txn(handle->file, &handle->file->global_txn);
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

    handle->cur_header_revnum = _fdb_set_file_header(handle);
    filemgr_commit(handle->file, &handle->log_callback);

    if (wal_flushed) {
        wal_release_flushed_items(handle->file, &flush_items);
    }

    // Mark the old file as "remove_pending".
    // Note that a file deletion will be pended until there is no handle
    // referring the file.
    filemgr_remove_pending(old_file, new_file);

    // Don't clean up the buffer cache entries for the old file.
    // They will be cleaned up later.
    filemgr_close(old_file, 0, handle->filename, &handle->log_callback);

    filemgr_mutex_unlock(handle->file);
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

INLINE void _fdb_compact_move_docs(fdb_handle *handle,
                                   struct filemgr *new_file,
                                   struct hbtrie *new_trie,
                                   struct btree *new_idtree,
                                   struct btree *new_seqtree,
                                   struct docio_handle *new_dhandle,
                                   struct btreeblk_handle *new_bhandle,
                                   uint64_t *count_out,
                                   uint64_t *new_datasize_out)
{
    uint8_t *var_key = alca(uint8_t, handle->config.chunksize);
    uint8_t deleted;
    uint64_t offset;
    uint64_t new_offset;
    uint64_t *offset_array;
    uint64_t n_moved_docs;
    size_t i, j, c, count;
    size_t offset_array_max;
    hbtrie_result hr;
    btree_result br;
    struct docio_object doc[FDB_COMPACTION_BATCHSIZE];
    struct hbtrie_iterator it;
    struct btree_iterator bit;
    struct timeval tv;
    fdb_doc wal_doc;
    fdb_handle new_handle;
    timestamp_t cur_timestamp;

    gettimeofday(&tv, NULL);
    cur_timestamp = tv.tv_sec;

    new_handle = *handle;
    new_handle.file = new_file;
    new_handle.trie = new_trie;
    new_handle.idtree = new_idtree;
    new_handle.seqtree = new_seqtree;
    new_handle.dhandle = new_dhandle;
    new_handle.bhandle = new_bhandle;
    new_handle.ndocs = 0;
    new_handle.datasize = 0;

    offset_array_max =
        handle->config.compaction_buf_maxsize / sizeof(uint64_t);
    offset_array = (uint64_t*)malloc(sizeof(uint64_t) * offset_array_max);
    c = count = n_moved_docs = 0;

    if (!handle->config.cmp_variable) {
        hr = hbtrie_iterator_init(handle->trie, &it, NULL, 0);
    } else {
        // custom compare function for variable length key
        br = btree_iterator_init(handle->idtree, &bit, NULL);
        hr = (br == BTREE_RESULT_FAIL)?(HBTRIE_RESULT_FAIL):
                                       (HBTRIE_RESULT_SUCCESS);
        memset(var_key, 0, handle->config.chunksize);
    }

    while( hr != HBTRIE_RESULT_FAIL ) {

        if (!handle->config.cmp_variable) {
            hr = hbtrie_next_value_only(&it, (void*)&offset);
        } else {
            br = btree_next(&bit, (void*)var_key, (void*)&offset);
            _free_var_key(var_key);
            hr = (br == BTREE_RESULT_FAIL)?(HBTRIE_RESULT_FAIL):
                                           (HBTRIE_RESULT_SUCCESS);
        }
        btreeblk_end(handle->bhandle);
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

            for (i=0; i<c; i+=FDB_COMPACTION_BATCHSIZE) {
                for(j=i; j<MIN(c, i+FDB_COMPACTION_BATCHSIZE); ++j){
                    offset = offset_array[j];

                    doc[j-i].key = NULL;
                    doc[j-i].meta = NULL;
                    doc[j-i].body = NULL;
                    docio_read_doc(handle->dhandle, offset, &doc[j-i]);
                }

                filemgr_mutex_lock(new_file);
                for(j=i; j<MIN(c, i+FDB_COMPACTION_BATCHSIZE); ++j){
                    // compare timestamp
                    deleted = doc[j-i].length.flag & DOCIO_DELETED;
                    if (!deleted ||
                        (cur_timestamp < doc[j-i].timestamp + handle->config.purging_interval &&
                         deleted)) {
                        // re-write the document to new file when
                        // 1. the document is not deleted
                        // 2. the document is logically deleted but
                        //    its timestamp isn't overdue
                        new_offset = docio_append_doc(new_dhandle, &doc[j-i], deleted, 0);

                        wal_doc.keylen = doc[j-i].length.keylen;
                        wal_doc.metalen = doc[j-i].length.metalen;
                        wal_doc.bodylen = doc[j-i].length.bodylen;
                        wal_doc.key = doc[j-i].key;
                        wal_doc.seqnum = doc[j-i].seqnum;

                        wal_doc.meta = doc[j-i].meta;
                        wal_doc.body = doc[j-i].body;
                        wal_doc.size_ondisk= _fdb_get_docsize(doc[j-i].length);
                        wal_doc.deleted = deleted;

                        wal_insert_by_compactor(&new_file->global_txn,
                                                new_file, &wal_doc, new_offset);
                        n_moved_docs++;

                    }
                    free(doc[j-i].key);
                    free(doc[j-i].meta);
                    free(doc[j-i].body);
                }
                filemgr_mutex_unlock(new_file);
            }
            // reset to zero
            c=0;
            count++;

            // wal flush
            if (wal_get_num_flushable(new_file) > 0) {
                struct avl_tree flush_items;
                wal_flush_by_compactor(new_file, (void*)&new_handle,
                                       _fdb_wal_flush_func,
                                       _fdb_wal_get_old_offset,
                                       &flush_items);
                wal_set_dirty_status(new_file, FDB_WAL_PENDING);
                wal_release_flushed_items(new_file, &flush_items);
                n_moved_docs = 0;
            }
        }
    }
    // *(count_out) can be smaller than handle->ndocs
    // when there are new updates by other writers
    // so that wal have to be flushed one more time.
    *(count_out) = new_handle.ndocs;
    *(new_datasize_out) = new_handle.datasize;

    if (!handle->config.cmp_variable) {
        hr = hbtrie_iterator_free(&it);
    } else {
        br = btree_iterator_free(&bit);
    }
    free(offset_array);
}

static uint64_t _fdb_doc_move(void *dbhandle,
                              void *void_new_dhandle,
                              struct wal_item *item,
                              fdb_doc *fdoc)
{
    uint8_t deleted;
    uint64_t new_offset;
    fdb_handle *handle = (fdb_handle*)dbhandle;
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

fdb_status fdb_compact_file(fdb_handle *handle,
                            const char *new_filename,
                            bool in_place_compaction)
{
    struct filemgr *new_file, *old_file;
    struct filemgr_config fconfig;
    struct btreeblk_handle *new_bhandle;
    struct docio_handle *new_dhandle;
    struct hbtrie *new_trie = NULL;
    struct btree *new_idtree = NULL;
    struct btree *new_seqtree, *old_seqtree;
    struct avl_tree flush_items;
    char *old_filename = NULL;
    size_t old_filename_len = 0;
    uint64_t count, new_datasize;
    fdb_seqnum_t seqnum;

    // prevent update to the target file
    filemgr_mutex_lock(handle->file);

    // if the file is already compacted by other thread
    if (filemgr_get_file_status(handle->file) != FILE_NORMAL ||
        handle->new_file || handle->file->new_file) {
        // update handle and return
        filemgr_mutex_unlock(handle->file);
        fdb_check_file_reopen(handle);
        fdb_link_new_file(handle);
        fdb_sync_db_header(handle);

        return FDB_RESULT_COMPACTION_FAIL;
    }

    // invalid filename
    if (!new_filename) {
        filemgr_mutex_unlock(handle->file);
        return FDB_RESULT_INVALID_ARGS;
    }
    if (strlen(new_filename) > FDB_MAX_FILENAME_LEN - 8) {
        filemgr_mutex_unlock(handle->file);
        return FDB_RESULT_TOO_LONG_FILENAME;
    }
    if (!strcmp(new_filename, handle->file->filename)) {
        filemgr_mutex_unlock(handle->file);
        return FDB_RESULT_INVALID_ARGS;
    }
    if (filemgr_is_rollback_on(handle->file)) {
        filemgr_mutex_unlock(handle->file);
        return FDB_RESULT_FAIL_BY_ROLLBACK;
    }

    // sync handle
    fdb_sync_db_header(handle);

    // set filemgr configuration
    fconfig.blocksize = handle->config.blocksize;
    fconfig.ncacheblock = handle->config.buffercache_size / handle->config.blocksize;
    fconfig.options = FILEMGR_CREATE;
    fconfig.flag = 0x0;
    if (handle->config.durability_opt & FDB_DRB_ODIRECT) {
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
    assert(new_file);

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

    if (!handle->config.cmp_variable) {
        new_trie = (struct hbtrie *)malloc(sizeof(struct hbtrie));
        hbtrie_init(new_trie, handle->trie->chunksize, handle->trie->valuelen,
                    new_file->blocksize, BLK_NOT_FOUND,
                    (void *)new_bhandle, handle->btreeblkops,
                    (void*)new_dhandle, _fdb_readkey_wrap);

        if (handle->config.cmp_fixed) {
            // custom compare function for fixed size key
            new_trie->btree_kv_ops->cmp = _fdb_cmp_fixed_wrap;
        }
        // set aux
        new_trie->aux = handle->trie->aux;
        new_trie->flag = handle->trie->flag;
        new_trie->leaf_height_limit = handle->trie->leaf_height_limit;
    } else {
        // custom compare function for variable length key
        new_idtree = (struct btree*)malloc(sizeof(struct btree));
        btree_init(new_idtree, (void *)new_bhandle,
                   handle->btreeblkops, handle->idtree->kv_ops,
                   handle->config.blocksize, handle->config.chunksize,
                   OFFSET_SIZE, 0x0, NULL);
        // set aux
        new_idtree->aux = (void*)handle;
    }

    if (handle->config.seqtree_opt == FDB_SEQTREE_USE) {
        // if we use sequence number tree
        new_seqtree = (struct btree *)malloc(sizeof(struct btree));
        old_seqtree = handle->seqtree;

        btree_init(new_seqtree, (void *)new_bhandle,
                   old_seqtree->blk_ops, old_seqtree->kv_ops,
                   old_seqtree->blksize, old_seqtree->ksize,
                   old_seqtree->vsize, 0x0, NULL);

        // copy old file's seqnum to new file
        seqnum = filemgr_get_seqnum(handle->file);
        filemgr_set_seqnum(new_file, seqnum);
    }

    count = new_datasize = 0;

    // flush WAL and set DB header
    wal_commit(&handle->file->global_txn, handle->file, NULL);
    wal_flush(handle->file, (void*)handle,
              _fdb_wal_flush_func, _fdb_wal_get_old_offset, &flush_items);
    wal_set_dirty_status(handle->file, FDB_WAL_CLEAN);

    // migrate uncommitted transaction items to new file
    wal_txn_migration((void*)handle, (void*)new_dhandle,
                      handle->file, new_file, _fdb_doc_move);

    // mark name of new file in old file
    filemgr_set_compaction_old(handle->file, new_file);

    handle->last_hdr_bid = (handle->file->pos) / handle->file->blocksize;
    handle->last_wal_flush_hdr_bid = handle->last_hdr_bid;

    handle->cur_header_revnum = _fdb_set_file_header(handle);
    btreeblk_end(handle->bhandle);

    // Commit the current file handle to record the compaction filename
    fdb_status fs = filemgr_commit(handle->file, &handle->log_callback);
    wal_release_flushed_items(handle->file, &flush_items);
    if (fs != FDB_RESULT_SUCCESS) {
        filemgr_mutex_unlock(handle->file);
        filemgr_mutex_unlock(new_file);
        return fs;
    }

    // reset last_wal_flush_hdr_bid
    handle->last_wal_flush_hdr_bid = BLK_NOT_FOUND;

    // Mark new file as newly compacted
    filemgr_update_file_status(new_file, FILE_COMPACT_NEW, NULL);
    filemgr_mutex_unlock(handle->file);
    filemgr_mutex_unlock(new_file);
    // now compactor & another writer can be interleaved

    _fdb_compact_move_docs(handle, new_file, new_trie, new_idtree, new_seqtree,
                           new_dhandle, new_bhandle, &count, &new_datasize);

    filemgr_mutex_lock(new_file);
    handle->ndocs = count;
    handle->datasize = new_datasize;

    old_file = handle->file;
    compactor_switch_file(old_file, new_file);
    handle->file = new_file;

    btreeblk_free(handle->bhandle);
    free(handle->bhandle);
    handle->bhandle = new_bhandle;

    docio_free(handle->dhandle);
    free(handle->dhandle);
    handle->dhandle = new_dhandle;

    if (!handle->config.cmp_variable) {
        hbtrie_free(handle->trie);
        free(handle->trie);
        handle->trie = new_trie;
    } else {
        free(handle->idtree);
        handle->idtree = new_idtree;
    }

    if (handle->config.seqtree_opt == FDB_SEQTREE_USE) {
        free(handle->seqtree);
        handle->seqtree = new_seqtree;
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
    _fdb_commit_and_remove_pending(handle, old_file, new_file);

    return FDB_RESULT_SUCCESS;
}

LIBFDB_API
fdb_status fdb_compact(fdb_handle *handle, const char *new_filename)
{
    if (handle->config.compaction_mode == FDB_COMPACTION_MANUAL) {
        // manual compaction
        bool in_place_compaction = false;
        char nextfile[FDB_MAX_FILENAME_LEN];
        if (!new_filename) { // In-place compaction.
            in_place_compaction = true;
            compactor_get_next_filename(handle->file->filename, nextfile);
            new_filename = nextfile;
        }
        return fdb_compact_file(handle, new_filename, in_place_compaction);

    } else if (handle->config.compaction_mode == FDB_COMPACTION_AUTO) {
        // auto compaction
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
        fs = fdb_compact_file(handle, nextfile, false);
        if (fs == FDB_RESULT_SUCCESS) {
            // compaction succeeded
            // clear compaction flag
            ret = compactor_switch_compaction_flag(handle->file, false);
            return fs;
        }
        // compaction failed
        // clear compaction flag
        ret = compactor_switch_compaction_flag(handle->file, false);
        return fs;
    }
    return FDB_RESULT_MANUAL_COMPACTION_FAIL;
}

LIBFDB_API
fdb_status fdb_switch_compaction_mode(fdb_handle *handle,
                                      fdb_compaction_mode_t mode,
                                      size_t new_threshold)
{
    int ret;
    fdb_status fs;
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
            fs = _fdb_open(handle, vfilename, &config);
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
            fs = _fdb_open(handle, vfilename, &config);
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
fdb_status fdb_close(fdb_handle *handle)
{
    if (!handle) {
        return FDB_RESULT_SUCCESS;
    }
    if (handle->txn) {
        fdb_abort_transaction(handle);
    }

    fdb_status fs = _fdb_close(handle);
    if (fs == FDB_RESULT_SUCCESS) {
        free(handle);
    }
    return fs;
}

static fdb_status _fdb_close(fdb_handle *handle)
{
    if (!(handle->config.flags & FDB_OPEN_FLAG_RDONLY) &&
        handle->config.compaction_mode == FDB_COMPACTION_AUTO) {
        // read-only file is not registered in compactor
        compactor_deregister_file(handle->file);
    }

    fdb_status fs = filemgr_close(handle->file, handle->config.cleanup_cache_onclose,
                                  handle->filename, &handle->log_callback);
    if (fs != FDB_RESULT_SUCCESS) {
        return fs;
    }
    docio_free(handle->dhandle);
    if (handle->new_file) {
        fs = filemgr_close(handle->new_file, handle->config.cleanup_cache_onclose,
                           handle->filename, &handle->log_callback);
        if (fs != FDB_RESULT_SUCCESS) {
            return fs;
        }
        docio_free(handle->new_dhandle);
        free(handle->new_dhandle);
        handle->new_file = NULL;
        handle->new_dhandle = NULL;
    }

    btreeblk_end(handle->bhandle);
    btreeblk_free(handle->bhandle);

    if (!handle->config.cmp_variable) {
        hbtrie_free(handle->trie);
        free(handle->trie);
    } else {
        free(handle->idtree->kv_ops);
        free(handle->idtree);
    }

    if (handle->config.seqtree_opt == FDB_SEQTREE_USE) {
        free(handle->seqtree->kv_ops);
        free(handle->seqtree);
    }

    free(handle->bhandle);
    free(handle->dhandle);
    if (handle->shandle) {
        snap_close(handle->shandle);
        free(handle->shandle);
    }
    if (handle->filename) {
        free(handle->filename);
        handle->filename = NULL;
    }
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
size_t fdb_estimate_space_used(fdb_handle *handle)
{
    size_t ret = 0;

    fdb_check_file_reopen(handle);
    fdb_link_new_file(handle);
    fdb_sync_db_header(handle);

    ret += handle->datasize;
    ret += handle->bhandle->nlivenodes * handle->config.blocksize;

    ret += wal_get_datasize(handle->file);

    return ret;
}

LIBFDB_API
fdb_status fdb_get_dbinfo(fdb_handle *handle, fdb_info *info)
{
    if (!handle || !info) {
        return FDB_RESULT_INVALID_ARGS;
    }

    fdb_check_file_reopen(handle);
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
        // return MAX_SEQNUM instead of the file's sequence number
        info->last_seqnum = handle->max_seqnum;
    } else {
        if (handle->new_file) {
            info->new_filename = handle->new_file->filename;
            filemgr_mutex_lock(handle->new_file);
            info->last_seqnum = filemgr_get_seqnum(handle->new_file);
            filemgr_mutex_unlock(handle->new_file);
        } else {
            info->new_filename = NULL;
            filemgr_mutex_lock(handle->file);
            info->last_seqnum = filemgr_get_seqnum(handle->file);
            filemgr_mutex_unlock(handle->file);
        }
    }

    // Note that doc_count includes the number of WAL entries, which might
    // incur an incorrect estimation. However, after the WAL flush, the doc
    // counter becomes consistent. We plan to devise a new way of tracking
    // the number of docs in a database instance.
    size_t wal_docs = wal_get_num_docs(handle->file);
    size_t wal_deletes = wal_get_num_deletes(handle->file);
    size_t wal_n_inserts = wal_docs - wal_deletes;
    if (handle->ndocs + wal_n_inserts < wal_deletes) {
        info->doc_count = 0;
    } else {
        if (handle->ndocs) {
            info->doc_count = handle->ndocs + wal_n_inserts - wal_deletes;
        } else {
            info->doc_count = wal_n_inserts;
        }
    }

    info->space_used = fdb_estimate_space_used(handle);
    info->file_size = filemgr_get_pos(handle->file);

    return FDB_RESULT_SUCCESS;
}

LIBFDB_API
fdb_status fdb_shutdown()
{
    compactor_shutdown();
    filemgr_shutdown();
#ifdef _MEMPOOL
    mempool_shutdown();
#endif

    fdb_initialized = 0;
    return FDB_RESULT_SUCCESS;
}
