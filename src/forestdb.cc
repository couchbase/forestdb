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
#include "filemgr.h"
#include "hbtrie.h"
#include "btree.h"
#include "btree_kv.h"
#include "btree_var_kv_ops.h"
#include "docio.h"
#include "btreeblock.h"
#include "common.h"
#include "wal.h"
#include "snapshot.h"
#include "filemgr_ops.h"
#include "crc32.h"
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

static const uint16_t OFFSET_SIZE = sizeof(uint64_t);

static fdb_status _fdb_open(fdb_handle *handle,
                            const char *filename,
                            const fdb_config *config);

static fdb_status _fdb_close(fdb_handle *handle);

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
int _fdb_cmp_fixed_wrap(void *key1, void *key2, void *aux)
{
    fdb_handle *handle = (fdb_handle*)aux;
    return handle->config.cmp_fixed(key1, key2);
}

// convert (prefix) btree cmp function -> user's custom compare function (variable)
int _fdb_cmp_variable_wrap(void *key1, void *key2, void *aux)
{
    uint8_t *keystr1 = alca(uint8_t, FDB_MAX_KEYLEN);
    uint8_t *keystr2 = alca(uint8_t, FDB_MAX_KEYLEN);
    size_t keylen1, keylen2;
    fdb_handle *handle = (fdb_handle*)aux;

    _get_var_key(key1, (void*)keystr1, &keylen1);
    _get_var_key(key2, (void*)keystr2, &keylen2);

    return handle->config.cmp_variable(keystr1, keylen1, keystr2, keylen2);
}

void _fdb_fetch_header(void *header_buf,
                       bid_t *trie_root_bid,
                       bid_t *seq_root_bid,
                       uint64_t *ndocs,
                       uint64_t *nlivenodes,
                       uint64_t *datasize,
                       uint64_t *last_header_bid,
                       char **new_filename,
                       char **old_filename)
{
    size_t offset = 0;
    uint8_t new_filename_len;
    uint8_t old_filename_len;

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

    seq_memcpy(last_header_bid, (uint8_t *)header_buf + offset,
               sizeof(uint64_t), offset);
    *last_header_bid = _endian_decode(*last_header_bid);

    seq_memcpy(&new_filename_len, (uint8_t *)header_buf + offset,
               sizeof(uint8_t), offset);
    seq_memcpy(&old_filename_len, (uint8_t *)header_buf + offset,
               sizeof(uint8_t), offset);
    if (new_filename_len) {
        *new_filename = (char*)((uint8_t *)header_buf + offset);
    }
    offset += FDB_MAX_FILENAME_LEN;
    if (old_filename && old_filename_len) {
        *old_filename = (char *) malloc(old_filename_len);
        seq_memcpy(*old_filename, (uint8_t *)header_buf + offset +
                   new_filename_len, old_filename_len, offset);
    }
}

INLINE size_t _fdb_get_docsize(struct docio_length len);
INLINE void _fdb_restore_wal(fdb_handle *handle, bid_t hdr_bid)
{
    struct filemgr *file = handle->file;
    uint32_t blocksize = handle->file->blocksize;
    uint64_t last_header_bid = handle->last_header_bid;
    uint64_t hdr_off = hdr_bid * FDB_BLOCKSIZE;
    uint64_t offset = 0; //assume everything from first block needs restoration

    filemgr_mutex_lock(file);
    if (last_header_bid != BLK_NOT_FOUND) {
        offset = (last_header_bid + 1) * blocksize;
    }

    // If a valid last header was retrieved and it matches the current header
    // OR if WAL already had entries populated, then no crash recovery needed
    if (!hdr_off || hdr_off <= offset ||
        (!handle->shandle && wal_get_size(file))) {
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
                memset(&doc, 0, sizeof(doc));
                _offset = docio_read_doc(handle->dhandle, offset, &doc);
                if (doc.key) {
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

                        wal_insert(file, &wal_doc, offset);
                        if (doc.key) free(doc.key);
                    } else {
                        snap_insert(handle->shandle, &wal_doc, offset);
                    }
                    if (doc.meta) free(doc.meta);
                    if (doc.body) free(doc.body);
                    offset = _offset;
                } else {
                    if (doc.key) free(doc.key);
                    if (doc.meta) free(doc.meta);
                    if (doc.body) free(doc.body);
                    offset = _offset;
                    break;
                }
            } while (offset + sizeof(struct docio_length) < hdr_off);
        }
    }
    filemgr_mutex_unlock(file);
    handle->dhandle->log_callback = log_callback;
}

// restore the documents in NEW_FILENAME (corrupted file during compaction)
// into the file referred by HANDLE
INLINE fdb_status _fdb_recover_compaction(fdb_handle *handle,
                                          const char *new_filename)
{
    bid_t bid = 0;
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
        if (handle->log_callback.callback) {
            char msg[1024];
            sprintf(msg, "Error in opening a partially compacted file '%s' "
                    "for recovery.", new_filename);
            handle->log_callback.callback(status, msg, handle->log_callback.ctx_data);
        }
        return status;
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
        filemgr_close(old_file, 0, &handle->log_callback);
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
                memset(&doc, 0, sizeof(doc));
                _offset = docio_read_doc(&dhandle, offset, &doc);
                if (doc.key && docio_check_compact_doc(&dhandle, &doc)) {
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

                    if (doc.key) free(doc.key);
                    if (doc.meta) free(doc.meta);
                    if (doc.body) free(doc.body);
                    offset = _offset;
                } else {
                    if (doc.key) free(doc.key);
                    if (doc.meta) free(doc.meta);
                    if (doc.body) free(doc.body);
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
    compactor_config c_config;

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

    c_config.sleep_duration = fconfig->compactor_sleep_duration;
    compactor_init(&c_config);

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
    compactor_config c_config;

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

    c_config.sleep_duration = fconfig->compactor_sleep_duration;
    compactor_init(&c_config);

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
    compactor_config c_config;

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

    c_config.sleep_duration = fconfig->compactor_sleep_duration;
    compactor_init(&c_config);

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
    if (!handle_in || !ptr_handle) {
        return FDB_RESULT_INVALID_ARGS;
    }

    // Sequence trees are a must for snapshot creation
    if (handle_in->config.seqtree_opt != FDB_SEQTREE_USE) {
        return FDB_RESULT_INVALID_ARGS;
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

    handle->log_callback = handle_in->log_callback;
    handle->shandle = (struct snap_handle *) calloc(1, sizeof(snap_handle));
    if (!handle->shandle) {
        return FDB_RESULT_ALLOC_FAIL;
    }
    handle->max_seqnum = seqnum;

    config.flags |= FDB_OPEN_FLAG_RDONLY;
    // do not perform compaction for snapshot
    config.compaction_mode = FDB_COMPACTION_MANUAL;
    fs = _fdb_open(handle, handle_in->file->filename, &config);

    if (fs == FDB_RESULT_SUCCESS) {
        *ptr_handle = handle;
    } else {
        *ptr_handle = NULL;
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

static fdb_status _fdb_open(fdb_handle *handle,
                            const char *filename,
                            const fdb_config *config)
{
    struct filemgr_config fconfig;
    struct btree_kv_ops *main_kv_ops;
    bid_t trie_root_bid = BLK_NOT_FOUND;
    bid_t seq_root_bid = BLK_NOT_FOUND;
    fdb_seqnum_t seqnum = 0;
    uint64_t ndocs = 0;
    uint64_t datasize = 0;
    uint64_t last_header_bid = BLK_NOT_FOUND;
    uint8_t header_buf[FDB_BLOCKSIZE];
    char *compacted_filename = NULL;
    char *prev_filename = NULL;
    size_t header_len = 0;

    bid_t prev_trie_root_bid = BLK_NOT_FOUND;
    bid_t prev_seq_root_bid = BLK_NOT_FOUND;
    fdb_seqnum_t prev_seqnum = 0;
    uint64_t prev_ndocs = 0;
    uint64_t nlivenodes = 0;
    uint64_t prev_datasize = 0;
    uint64_t prev_last_header_bid = 0;
    bid_t hdr_bid;
    char actual_filename[256];

    fconfig.blocksize = config->blocksize;
    fconfig.ncacheblock = config->buffercache_size / config->blocksize;
    fconfig.flag = 0x0;
    fconfig.options = 0x0;
    if (config->flags & FDB_OPEN_FLAG_CREATE) {
        fconfig.options |= FILEMGR_CREATE;
    }
    if (config->flags & FDB_OPEN_FLAG_RDONLY) {
        fconfig.options |= FILEMGR_READONLY;
    }
    if (!(config->durability_opt & FDB_DRB_ASYNC)) {
        fconfig.options |= FILEMGR_SYNC;
    }
    if (config->durability_opt & FDB_DRB_ODIRECT) {
        fconfig.flag |= _ARCH_O_DIRECT;
    }

    if (!compactor_is_valid_mode(filename, (fdb_config *)config)) {
        return FDB_RESULT_INVALID_COMPACTION_MODE;
    }

    if (config->compaction_mode == FDB_COMPACTION_AUTO) {
        // auto compaction mode
        compactor_get_actual_filename(filename, actual_filename);
        if (handle->filename) {
            handle->filename = (char *)realloc(handle->filename, strlen(filename)+1);
        } else {
            handle->filename = (char*)malloc(strlen(filename)+1);
        }
        strcpy(handle->filename, filename);
    } else {
        // manual compaction mode
        strcpy(actual_filename, filename);
        handle->filename = NULL;
    }

    handle->fileops = get_filemgr_ops();
    filemgr_open_result result = filemgr_open((char *)actual_filename, handle->fileops,
                                              &fconfig, &handle->log_callback);
    if (result.rv != FDB_RESULT_SUCCESS) {
        return (fdb_status) result.rv;
    }

    handle->file = result.file;
    filemgr_mutex_lock(handle->file);
    filemgr_fetch_header(handle->file, header_buf, &header_len);
    if (header_len > 0) {
        _fdb_fetch_header(header_buf, &trie_root_bid,
                &seq_root_bid, &ndocs, &nlivenodes,
                &datasize, &last_header_bid,
                &compacted_filename, &prev_filename);
        seqnum = filemgr_get_seqnum(handle->file);
    }
    filemgr_mutex_unlock(handle->file);

    hdr_bid = filemgr_get_pos(handle->file) / FDB_BLOCKSIZE;
    hdr_bid = hdr_bid ? --hdr_bid : 0;
    if (handle->max_seqnum) { // Given Marker, reverse scan file..
        while (header_len && seqnum != handle->max_seqnum) {
            hdr_bid = filemgr_fetch_prev_header(handle->file, hdr_bid,
                                      header_buf, &header_len, &seqnum,
                                      &handle->log_callback);

            if (header_len > 0) {
                _fdb_fetch_header(header_buf, &trie_root_bid,
                        &seq_root_bid, &ndocs, &nlivenodes,
                        &datasize, &last_header_bid,
                        &compacted_filename, NULL);
            }
        }
        if (!header_len) { // Marker MUST match that of DB commit!
            return FDB_RESULT_NO_DB_INSTANCE;
        }

        if (!handle->shandle) { // Rollback mode, destroy file WAL..
            wal_shutdown(handle->file);
        }
    } else {
        if (handle->shandle) { // fdb_snapshot_open API call
            if (seqnum) {
                // Database currently has a non-zero seq number, but the snapshot was
                // requested with a seq number zero.
                return FDB_RESULT_NO_DB_INSTANCE;
            }
        }
    }

    handle->btreeblkops = btreeblk_get_ops();
    handle->bhandle = (struct btreeblk_handle *)calloc(1, sizeof(struct btreeblk_handle));
    handle->bhandle->log_callback = &handle->log_callback;
    handle->dhandle = (struct docio_handle *)calloc(1, sizeof(struct docio_handle));
    handle->dhandle->log_callback = &handle->log_callback;

    handle->config = *config;
    handle->last_header_bid = BLK_NOT_FOUND;

    handle->new_file = NULL;
    handle->new_dhandle = NULL;

    if (handle->config.compaction_buf_maxsize == 0) {
        handle->config.compaction_buf_maxsize = FDB_COMP_BUF_MAXSIZE;
    }

    docio_init(handle->dhandle, handle->file, config->compress_document_body);
    btreeblk_init(handle->bhandle, handle->file, handle->file->blocksize);

    handle->cur_header_revnum = filemgr_get_header_revnum(handle->file);
    handle->ndocs = ndocs;
    handle->bhandle->nlivenodes = nlivenodes;
    handle->datasize = datasize;
    handle->last_header_bid = last_header_bid;

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
                    filemgr_close(result.file, 0, &handle->log_callback);
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
    if (doc == NULL) {
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
    if (doc == NULL) {
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
        hr = hbtrie_find_offset(handle->trie, item->key, item->keylen,
                                (void*)&old_offset);
    } else {
        _set_var_key(var_key, item->key, item->keylen);
        br = btree_find(handle->idtree, var_key, (void*)&old_offset);
        _free_var_key(var_key);
    }
    btreeblk_end(handle->bhandle);
    old_offset = _endian_decode(old_offset);

    return old_offset;
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
            hr = hbtrie_insert(handle->trie, item->key, item->keylen,
                (void *)&_offset, (void *)&old_offset);
        } else {
            _set_var_key(var_key, item->key, item->keylen);
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
            hr = hbtrie_remove(handle->trie, item->key, item->keylen);
        } else {
            _set_var_key(var_key, item->key, item->keylen);
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

void _fdb_sync_db_header(fdb_handle *handle)
{
    uint64_t cur_revnum = filemgr_get_header_revnum(handle->file);
    if (handle->cur_header_revnum != cur_revnum) {
        void *header_buf = NULL;
        size_t header_len;

        header_buf = filemgr_fetch_header(handle->file, NULL, &header_len);
        if (header_len > 0) {
            bid_t idtree_root;
            bid_t new_seq_root;
            char *compacted_filename;
            char *prev_filename = NULL;

            _fdb_fetch_header(header_buf, &idtree_root,
                              &new_seq_root,
                              &handle->ndocs, &handle->bhandle->nlivenodes,
                              &handle->datasize, &handle->last_header_bid,
                              &compacted_filename, &prev_filename);

            if (!handle->config.cmp_variable) {
                handle->trie->root_bid = idtree_root;
            } else {
                btree_init_from_bid(
                    handle->idtree, handle->idtree->blk_handle,
                    handle->idtree->blk_ops, handle->idtree->kv_ops,
                    handle->idtree->blksize, idtree_root);
            }

            if (new_seq_root != handle->seqtree->root_bid) {
                btree_init_from_bid(
                    handle->seqtree, handle->seqtree->blk_handle,
                    handle->seqtree->blk_ops, handle->seqtree->kv_ops,
                    handle->seqtree->blksize, new_seq_root);
            }

            if (prev_filename) {
                free(prev_filename);
            }

            handle->cur_header_revnum = cur_revnum;
        }
        if (header_buf) {
            free(header_buf);
        }
    }
}

void _fdb_check_file_reopen(fdb_handle *handle)
{
    // check whether the compaction is done
    if (filemgr_get_file_status(handle->file) == FILE_REMOVED_PENDING) {
        uint64_t dummy;
        uint64_t ndocs, datasize, nlivenodes, last_header_bid;
        size_t header_len;
        char *new_filename;
        uint8_t *buf = alca(uint8_t, BLK_DBHEADER_SIZE);
        bid_t trie_root_bid, seq_root_bid;
        fdb_config config = handle->config;

        if (handle->new_file) {
            // compacted new file is already opened
            // close the old file
            filemgr_close(handle->file, handle->config.cleanup_cache_onclose,
                          &handle->log_callback);
            // close old docio handle
            docio_free(handle->dhandle);
            free(handle->dhandle);
            // close btree block handle
            btreeblk_end(handle->bhandle);

            // switch to new file & docio handle
            handle->file = handle->new_file;
            handle->new_file = NULL;
            handle->dhandle = handle->new_dhandle;
            handle->new_dhandle = NULL;

            // read new file's header
            filemgr_fetch_header(handle->file, buf, &header_len);
            _fdb_fetch_header(buf,
                              &trie_root_bid, &seq_root_bid,
                              &ndocs, &nlivenodes, &datasize, &last_header_bid,
                              &new_filename, NULL);

            // reset btree block handle's file
            handle->bhandle->file = handle->file;

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
                char filename[256];
                strcpy(filename, handle->filename);
                _fdb_close(handle);
                _fdb_open(handle, filename, &config);

            } else {
                filemgr_fetch_header(handle->file, buf, &header_len);
                _fdb_fetch_header(buf,
                                  &trie_root_bid, &seq_root_bid,
                                  &ndocs, &nlivenodes, &datasize, &last_header_bid,
                                  &new_filename, NULL);
                _fdb_close(handle);
                _fdb_open(handle, new_filename, &config);
            }
        }
    }
}

void _fdb_link_new_file(fdb_handle *handle)
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
    void *header_buf;
    size_t header_len;
    uint64_t offset, _offset;
    struct docio_object _doc;
    struct filemgr *wal_file;
    struct docio_handle *dhandle;
    wal_result wr;
    hbtrie_result hr = HBTRIE_RESULT_FAIL;

    if (doc->key == NULL || doc->keylen == 0) {
        return FDB_RESULT_INVALID_ARGS;
    }

    if (!handle->shandle) {
        _fdb_check_file_reopen(handle);
        _fdb_link_new_file(handle);
        _fdb_sync_db_header(handle);

        if (handle->new_file == NULL) {
            wal_file = handle->file;
        }else{
            wal_file = handle->new_file;
        }
        dhandle = handle->dhandle;

        wr = wal_find(wal_file, doc, &offset);
    } else {
        wr = snap_find(handle->shandle, doc, &offset);
        dhandle = handle->dhandle;
    }

    if (wr == WAL_RESULT_FAIL) {
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

    if (doc->key == NULL || doc->keylen == 0) {
        return FDB_RESULT_INVALID_ARGS;
    }

    if (!handle->shandle) {
        _fdb_check_file_reopen(handle);
        _fdb_link_new_file(handle);
        _fdb_sync_db_header(handle);

        if (handle->new_file == NULL) {
            wal_file = handle->file;
        }else{
            wal_file = handle->new_file;
        }
        dhandle = handle->dhandle;

        wr = wal_find(wal_file, doc, &offset);
    } else {
        wr = snap_find(handle->shandle, doc, &offset);
        dhandle = handle->dhandle;
    }

    if (wr == WAL_RESULT_FAIL) {
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

    if (doc->seqnum == SEQNUM_NOT_USED) {
        return FDB_RESULT_INVALID_ARGS;
    }

    if (!handle->shandle) {
        _fdb_check_file_reopen(handle);
        _fdb_link_new_file(handle);
        _fdb_sync_db_header(handle);

        if (handle->new_file == NULL) {
            wal_file = handle->file;
        }else{
            wal_file = handle->new_file;
        }
        dhandle = handle->dhandle;

        wr = wal_find(wal_file, doc, &offset);
    } else {
        wr = snap_find(handle->shandle, doc, &offset);
        dhandle = handle->dhandle;
    }

    if (wr == WAL_RESULT_FAIL) {
        _seqnum = _endian_encode(doc->seqnum);
        br = btree_find(handle->seqtree, (void *)&_seqnum, (void *)&offset);
        btreeblk_end(handle->bhandle);
        offset = _endian_decode(offset);
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

    if (doc->seqnum == SEQNUM_NOT_USED) {
        return FDB_RESULT_INVALID_ARGS;
    }

    if (!handle->shandle) {
        _fdb_check_file_reopen(handle);
        _fdb_link_new_file(handle);
        _fdb_sync_db_header(handle);

        if (handle->new_file == NULL) {
            wal_file = handle->file;
        } else {
            wal_file = handle->new_file;
        }
        dhandle = handle->dhandle;

        wr = wal_find(wal_file, doc, &offset);
    } else {
        wr = snap_find(handle->shandle, doc, &offset);
        dhandle = handle->dhandle;
    }

    if (wr == WAL_RESULT_FAIL) {
        _seqnum = _endian_encode(doc->seqnum);
        br = btree_find(handle->seqtree, (void *)&_seqnum, (void *)&offset);
        btreeblk_end(handle->bhandle);
        offset = _endian_decode(offset);
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
                return FDB_RESULT_KEY_NOT_FOUND;
            }
        } else {
            return FDB_RESULT_KEY_NOT_FOUND;
        }
    } else {
        if (!equal_docs(doc, &_doc)) {
            if (handle->new_dhandle && !handle->shandle) {
                // Look up the new file being compacted
                _offset = docio_read_doc(handle->new_dhandle, offset, &_doc);
                if (_offset == offset) {
                    return FDB_RESULT_KEY_NOT_FOUND;
                }
                if (!equal_docs(doc, &_doc)) {
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

uint64_t _fdb_get_wal_threshold(fdb_handle *handle)
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

    if (handle->config.flags & FDB_OPEN_FLAG_RDONLY) {
        if (handle->log_callback.callback) {
            char msg[1024];
            sprintf(msg, "Warning: SET is not allowed on the read-only DB file '%s'.",
                    handle->file->filename);
            handle->log_callback.callback(FDB_RESULT_RONLY_VIOLATION, msg,
                                          handle->log_callback.ctx_data);
        }
        return FDB_RESULT_RONLY_VIOLATION;
    }

    if ( (doc->key == NULL) || (doc->keylen == 0) ||
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
    _fdb_check_file_reopen(handle);
    _fdb_sync_db_header(handle);

    if (handle->new_file == NULL) {
        file = handle->file;
        dhandle = handle->dhandle;
        filemgr_mutex_lock(file);

        _fdb_link_new_file(handle);
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

    if (dhandle == handle->new_dhandle) {
        offset = docio_append_doc_compact(dhandle, &_doc, doc->deleted);
    } else {
        offset = docio_append_doc(dhandle, &_doc, doc->deleted);
    }
    if (offset == BLK_NOT_FOUND) {
        filemgr_mutex_unlock(file);
        return FDB_RESULT_WRITE_FAIL;
    }

    doc->size_ondisk = _fdb_get_docsize(_doc.length);
    doc->offset = offset;
    wal_insert(file, doc, offset);

    if (wal_get_dirty_status(file)== FDB_WAL_CLEAN) {
        wal_set_dirty_status(file, FDB_WAL_DIRTY);
    }

    if (handle->config.wal_flush_before_commit &&
            filemgr_get_file_status(handle->file) == FILE_NORMAL &&
            wal_get_size(file) > _fdb_get_wal_threshold(handle)) {
        wal_flush(file, (void *)handle,
                  _fdb_wal_flush_func, _fdb_wal_get_old_offset);
        wal_set_dirty_status(file, FDB_WAL_PENDING);
    }

    filemgr_mutex_unlock(file);
    return FDB_RESULT_SUCCESS;
}

LIBFDB_API
fdb_status fdb_del(fdb_handle *handle, fdb_doc *doc)
{
    if (handle->config.flags & FDB_OPEN_FLAG_RDONLY) {
        if (handle->log_callback.callback) {
            char msg[1024];
            sprintf(msg, "Warning: DEL is not allowed on the read-only DB file '%s'.",
                    handle->file->filename);
            handle->log_callback.callback(FDB_RESULT_RONLY_VIOLATION, msg,
                                          handle->log_callback.ctx_data);
        }
        return FDB_RESULT_RONLY_VIOLATION;
    }

    if ((doc->key == NULL) || (doc->keylen == 0)) {
        return FDB_RESULT_INVALID_ARGS;
    }

    doc->deleted = true;
    fdb_doc _doc;
    _doc = *doc;
    return fdb_set(handle, &_doc);
}

uint64_t _fdb_set_file_header(fdb_handle *handle)
{
    /*
    <ForestDB header>
    [0000]: BID of root node of root B+Tree of HB+Trie: 8 bytes
    [0008]: BID of root node of seq B+Tree: 8 bytes (optional)
    [0016]: # of live documents: 8 bytes
    [0024]: # of live B+Tree nodes: 8 bytes
    [0032]: Data size (byte): 8 bytes
    [0040]: File offset of the DB header created when last WAL flush: 8 bytes
    [0048]: Size of newly compacted target file name : 1 byte
    [0049]: Size of old file name before compaction :  1 byte
    [0050]: File name of newly compacted file : 256 bytes
    [0306]: File name of old file before compcation : 256 bytes
    [0562]: CRC32: 4 bytes
    [total size: 566 bytes] BLK_DBHEADER_SIZE must be incremented on new fields
    */
    uint8_t buf[BLK_DBHEADER_SIZE];
    uint32_t crc;
    uint64_t _edn_safe_64;
    size_t offset = 0;
    size_t new_filename_len = 0;
    size_t old_filename_len = 0;
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
    }else{
        memset(buf + offset, 0, sizeof(uint64_t));
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
    _edn_safe_64 = _endian_encode(handle->last_header_bid);
    seq_memcpy(buf + offset, &_edn_safe_64,
        sizeof(handle->last_header_bid), offset);

    // size of newly compacted target file name
    if (handle->file->new_file) {
        new_filename_len = strlen(handle->file->new_file->filename) + 1;
    }
    seq_memcpy(buf + offset, &new_filename_len, 1, offset);

    // size of old filename before compaction
    if (handle->file->old_filename) {
        old_filename_len = strlen(handle->file->old_filename) + 1;
    }
    seq_memcpy(buf + offset, &old_filename_len, 1, offset);

    if (new_filename_len) {
        memcpy(buf + offset, handle->file->new_file->filename,
               new_filename_len);
        offset += new_filename_len;
    }
    memset(buf + offset, 0, FDB_MAX_FILENAME_LEN - new_filename_len);
    offset += (FDB_MAX_FILENAME_LEN - new_filename_len);

    if (old_filename_len) {
        memcpy(buf + offset, handle->file->old_filename,
               old_filename_len);
        offset += old_filename_len;
    }
    memset(buf + offset, 0, FDB_MAX_FILENAME_LEN - old_filename_len);
    offset += (FDB_MAX_FILENAME_LEN - old_filename_len);

    // crc32
    crc = crc32_8(buf, offset, 0);
    crc = _endian_encode(crc);
    seq_memcpy(buf + offset, &crc, sizeof(crc), offset);

    return filemgr_update_header(handle->file, buf, offset);
}

LIBFDB_API
fdb_status fdb_commit(fdb_handle *handle, fdb_commit_opt_t opt)
{
    fdb_status fs = FDB_RESULT_SUCCESS;
    if (handle->config.flags & FDB_OPEN_FLAG_RDONLY) {
        if (handle->log_callback.callback) {
            char msg[1024];
            sprintf(msg, "Warning: Commit is not allowed on the read-only DB file '%s'.",
                    handle->file->filename);
            handle->log_callback.callback(FDB_RESULT_RONLY_VIOLATION, msg,
                                          handle->log_callback.ctx_data);
        }
        return FDB_RESULT_RONLY_VIOLATION;
    }

    filemgr_mutex_lock(handle->file);

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

        fs = filemgr_sync(handle->new_file, &handle->log_callback);
        filemgr_mutex_unlock(handle->new_file);
    } else {
        // normal case
        btreeblk_end(handle->bhandle);
        if (wal_get_size(handle->file) > _fdb_get_wal_threshold(handle) ||
            wal_get_dirty_status(handle->file) == FDB_WAL_PENDING ||
            opt & FDB_COMMIT_MANUAL_WAL_FLUSH) {
            // wal flush when
            // 1. wal size exceeds threshold
            // 2. wal is already flushed before commit (in this case flush the rest of entries)
            // 3. user forces to manually flush wal
            wal_flush(handle->file, (void *)handle,
                      _fdb_wal_flush_func, _fdb_wal_get_old_offset);
            wal_set_dirty_status(handle->file, FDB_WAL_CLEAN);
        }else{
            // otherwise just commit wal
            wal_commit(handle->file);
        }

        if (wal_get_dirty_status(handle->file) == FDB_WAL_CLEAN) {
            handle->last_header_bid = filemgr_get_next_alloc_block(handle->file);
        }
        handle->cur_header_revnum = _fdb_set_file_header(handle);
        fs = filemgr_commit(handle->file, &handle->log_callback);

        filemgr_mutex_unlock(handle->file);
    }
    return fs;
}

void _fdb_commit_and_remove_pending(fdb_handle *handle,
                                    struct filemgr *old_file,
                                    struct filemgr *new_file)
{
    filemgr_mutex_lock(handle->file);

    btreeblk_end(handle->bhandle);

    if (wal_get_size(handle->file)) {
        // flush wal if not empty
        wal_flush(handle->file, (void *)handle,
                  _fdb_wal_flush_func, _fdb_wal_get_old_offset);
        wal_set_dirty_status(handle->file, FDB_WAL_CLEAN);
    }

    if (wal_get_dirty_status(handle->file) == FDB_WAL_CLEAN) {
        handle->last_header_bid = filemgr_get_next_alloc_block(handle->file);
    }
    handle->cur_header_revnum = _fdb_set_file_header(handle);
    filemgr_commit(handle->file, &handle->log_callback);

    // remove the old file
    // and this will be pended until there is no handle referring the file
    filemgr_remove_pending(old_file, new_file);

    // Don't clean up the buffer cache entries for the old file.
    // They will be cleaned up later.
    filemgr_close(old_file, 0, &handle->log_callback);

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
    uint8_t *k = alca(uint8_t, HBTRIE_MAX_KEYLEN);
    uint8_t *var_key = alca(uint8_t, handle->config.chunksize);
    uint8_t deleted;
    uint64_t offset;
    uint64_t new_offset;
    uint64_t *offset_array;
    size_t i, j, c, count;
    size_t offset_array_max;
    size_t keylen;
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
    c = count = 0;

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
                        new_offset = docio_append_doc(new_dhandle, &doc[j-i], deleted);

                        wal_doc.keylen = doc[j-i].length.keylen;
                        wal_doc.metalen = doc[j-i].length.metalen;
                        wal_doc.bodylen = doc[j-i].length.bodylen;
                        wal_doc.key = doc[j-i].key;
                        wal_doc.seqnum = doc[j-i].seqnum;

                        wal_doc.meta = doc[j-i].meta;
                        wal_doc.body = doc[j-i].body;
                        wal_doc.size_ondisk= _fdb_get_docsize(doc[j-i].length);
                        wal_doc.deleted = deleted;

                        wal_insert_by_compactor(new_file, &wal_doc, new_offset);

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
            if (wal_get_size(new_file) > 0) {
                wal_flush(new_file, (void*)&new_handle,
                          _fdb_wal_flush_func,
                          _fdb_wal_get_old_offset);
                wal_set_dirty_status(new_file, FDB_WAL_PENDING);
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

fdb_status _fdb_compact(fdb_handle *handle,
                        const char *new_filename)
{
    struct filemgr *new_file, *old_file;
    struct filemgr_config fconfig;
    struct btreeblk_handle *new_bhandle;
    struct docio_handle *new_dhandle;
    struct hbtrie *new_trie = NULL;
    struct btree *new_idtree = NULL;
    struct btree *new_seqtree, *old_seqtree;
    char *old_filename = NULL;
    struct hbtrie_iterator it;
    struct docio_object doc;
    uint8_t k[HBTRIE_MAX_KEYLEN];
    size_t keylen;
    size_t old_filename_len = 0;
    uint64_t offset, new_offset, *offset_arr, i, count, new_datasize;
    fdb_seqnum_t seqnum;

    // prevent update to the target file
    filemgr_mutex_lock(handle->file);

    // if the file is already compacted by other thread
    if (filemgr_get_file_status(handle->file) != FILE_NORMAL) {
        // update handle and return
        filemgr_mutex_unlock(handle->file);
        _fdb_check_file_reopen(handle);
        _fdb_link_new_file(handle);
        _fdb_sync_db_header(handle);

        return FDB_RESULT_COMPACTION_FAIL;
    }

    // invalid filename
    if (!new_filename) {
        filemgr_mutex_unlock(handle->file);
        return FDB_RESULT_INVALID_ARGS;
    }
    if (!strcmp(new_filename, handle->file->filename)) {
        filemgr_mutex_unlock(handle->file);
        return FDB_RESULT_INVALID_ARGS;
    }

    if (filemgr_is_rollback_on(handle->file)) {
        filemgr_mutex_unlock(handle->file);
        return FDB_RESULT_FAIL_BY_ROLLBACK;
    }

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
        return (fdb_status) result.rv;
    }

    new_file = result.file;
    assert(new_file);

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

    // mark name of new file in old file
    filemgr_set_compaction_old(handle->file, new_file);
    // flush WAL and set DB header
    wal_flush(handle->file, (void*)handle,
              _fdb_wal_flush_func, _fdb_wal_get_old_offset);
    wal_set_dirty_status(handle->file, FDB_WAL_CLEAN);
    handle->last_header_bid = (handle->file->pos) / handle->file->blocksize;
    handle->cur_header_revnum = _fdb_set_file_header(handle);
    btreeblk_end(handle->bhandle);
    assert(handle->file->status == FILE_COMPACT_OLD);
    // Commit the current file handle to record the compaction filename
    fdb_status fs = filemgr_commit(handle->file, &handle->log_callback);
    if (fs != FDB_RESULT_SUCCESS) {
        return fs;
    }

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
        return _fdb_compact(handle, new_filename);

    } else if (handle->config.compaction_mode == FDB_COMPACTION_AUTO) {
        // auto compaction
        bool ret;
        char nextfile[256];
        fdb_status fs;
        // set compaction flag
        ret = compactor_switch_compaction_flag(handle->file, true);
        if (!ret) {
            // the file is already being compacted by other thread
            return FDB_RESULT_FILE_IS_BUSY;
        }
        // get next filename
        compactor_get_next_filename(handle->file->filename, nextfile);
        fs = _fdb_compact(handle, nextfile);
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
    char vfilename[256];
    char filename[256];
    char metafile[256];

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
            // 1. rename [filename] as [filename].0
            strcpy(vfilename, handle->file->filename);
            sprintf(filename, "%s.0", handle->file->filename);
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
                                  &handle->log_callback);
    if (fs != FDB_RESULT_SUCCESS) {
        return fs;
    }
    docio_free(handle->dhandle);
    if (handle->new_file) {
        fs = filemgr_close(handle->new_file, handle->config.cleanup_cache_onclose,
                           &handle->log_callback);
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

// roughly estimate the space occupied db handle HANDLE
LIBFDB_API
size_t fdb_estimate_space_used(fdb_handle *handle)
{
    size_t ret = 0;

    _fdb_check_file_reopen(handle);
    _fdb_link_new_file(handle);
    _fdb_sync_db_header(handle);

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

    _fdb_check_file_reopen(handle);
    _fdb_link_new_file(handle);
    _fdb_sync_db_header(handle);

    if (handle->filename) {
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
    size_t wal_size = wal_get_size(handle->file);
    size_t wal_deletes = wal_get_num_deletes(handle->file);
    size_t wal_insert = wal_size - wal_deletes;
    if (handle->ndocs + wal_insert < wal_deletes) {
        info->doc_count = 0;
    } else {
        if (handle->ndocs) {
            info->doc_count = handle->ndocs + wal_insert - wal_deletes;
        } else {
            info->doc_count = wal_insert;
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

    return FDB_RESULT_SUCCESS;
}
