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

#include "libforestdb/forestdb.h"
#include "filemgr.h"
#include "hbtrie.h"
#include "btree.h"
#include "btree_kv.h"
#include "docio.h"
#include "btreeblock.h"
#include "common.h"
#include "wal.h"
#include "filemgr_ops.h"
#include "crc32.h"
#include "configuration.h"

#include "memleak.h"

#ifdef __DEBUG
#ifndef __DEBUG_FDB
    #undef DBG
    #undef DBGCMD
    #undef DBGSW
    #define DBG(...)
    #define DBGCMD(...)
    #define DBGSW(n, ...)
#else
    static int compact_count=0;
#endif
#endif

#ifdef __FDB_SEQTREE
    #define SEQTREE(...) __VA_ARGS__
#else
    #define SEQTREE(...)
#endif

static fdb_status _fdb_open(fdb_handle *handle,
                            const char *filename,
                            const fdb_config *config);

INLINE size_t _fdb_readkey_wrap(void *handle, uint64_t offset, void *buf)
{
    keylen_t keylen;
    docio_read_doc_key((struct docio_handle *)handle, offset, &keylen, buf);
    return keylen;
}

INLINE void _fdb_fetch_header(
    void *header_buf,
    size_t header_len,
    bid_t *trie_root_bid,
    bid_t *seq_root_bid,
    fdb_seqnum_t *seqnum,
    uint64_t *ndocs,
    uint64_t *datasize,
    uint64_t *last_header_bid,
    char **new_filename,
    char **old_filename)
{
    size_t offset = 0;
    uint8_t new_filename_len;
    uint8_t old_filename_len;
    seq_memcpy(trie_root_bid, (uint8_t *)header_buf + offset, sizeof(bid_t), offset);
    seq_memcpy(seq_root_bid, (uint8_t *)header_buf + offset, sizeof(bid_t), offset);
    seq_memcpy(seqnum, (uint8_t *)header_buf + offset, sizeof(fdb_seqnum_t), offset);
    seq_memcpy(ndocs, (uint8_t *)header_buf + offset, sizeof(uint64_t), offset);
    seq_memcpy(datasize, (uint8_t *)header_buf + offset, sizeof(uint64_t), offset);
    seq_memcpy(last_header_bid, (uint8_t *)header_buf + offset,
        sizeof(uint64_t), offset);
    seq_memcpy(&new_filename_len, (uint8_t *)header_buf + offset, sizeof(uint8_t),
        offset);
    seq_memcpy(&old_filename_len, (uint8_t *)header_buf + offset, sizeof(uint8_t),
        offset);
    if (new_filename_len) {
        *new_filename = (char*)((uint8_t *)header_buf + offset);
    }
    offset += FDB_MAX_FILENAME_LEN;
    if (old_filename_len) {
        *old_filename = (char *) malloc(old_filename_len);
        seq_memcpy(*old_filename, (uint8_t *)header_buf + offset + new_filename_len,
                   old_filename_len, offset);
    }
}

INLINE void _fdb_restore_wal(fdb_handle *handle)
{
    struct filemgr *file = handle->file;
    uint32_t blocksize = handle->file->blocksize;
    uint64_t last_header_bid = handle->last_header_bid;
    uint64_t header_blk_pos = file->pos ? file->pos - blocksize : 0;
    uint64_t offset = 0; //assume everything from first block needs restoration

    filemgr_mutex_lock(file);
    if (last_header_bid != BLK_NOT_FOUND) {
        offset = (last_header_bid + 1) * blocksize;
    }

    // If a valid last header was retrieved and it matches the current header
    // OR if WAL already had entries populated, then no crash recovery needed
    if (!header_blk_pos || header_blk_pos <= offset || wal_get_size(file)) {
        filemgr_mutex_unlock(file);
        return;
    }

    for (; offset < header_blk_pos;
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
                    wal_doc.metalen = doc.length.metalen;
                    wal_doc.bodylen = doc.length.bodylen;
                    wal_doc.key = doc.key;
#ifdef __FDB_SEQTREE
                    wal_doc.seqnum = doc.seqnum;
#endif
                    wal_doc.meta = doc.meta;
                    wal_insert(file, &wal_doc, offset);
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
            } while (offset + sizeof(struct docio_length) < header_blk_pos);
        }
    }
    filemgr_mutex_unlock(file);
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

    config.flags |= FDB_OPEN_FLAG_RDONLY;
    fdb_status status = _fdb_open(&new_db, new_filename, &config);
    if (status != FDB_RESULT_SUCCESS) {
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
#ifdef __FDB_SEQTREE
        if (handle->config.seqtree_opt == FDB_SEQTREE_USE) {
            free(handle->seqtree);
            if (new_db.config.seqtree_opt == FDB_SEQTREE_USE) {
                handle->seqtree = new_db.seqtree;
            }
        }
#endif
        // remove self: WARNING must not close this handle if snapshots
        // are yet to open this file
        filemgr_remove_pending(old_file, new_db.file);
        filemgr_close(old_file, 0);
        return FDB_RESULT_FAIL;
    }
    docio_init(&dhandle, new_file);

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
#ifdef __FDB_SEQTREE
                    wal_doc.seqnum = doc.seqnum;
#endif
                    wal_doc.meta = doc.meta;
                    wal_doc.body = doc.body;

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
    fdb_close(&new_db);
    fdb_commit(handle);

    return FDB_RESULT_SUCCESS;
}

LIBFDB_API
fdb_status fdb_set_custom_cmp(fdb_handle *handle, fdb_custom_cmp cmp_func)
{
    // set custom compare function
    handle->trie->btree_kv_ops->cmp = cmp_func;
    handle->cmp_func = cmp_func;
    return FDB_RESULT_SUCCESS;
}

LIBFDB_API
fdb_status fdb_open(fdb_handle *handle,
                    const char *filename,
                    fdb_open_flags flags,
                    const char *fdb_config_file)
{
#ifdef _MEMPOOL
    mempool_init();
#endif

    fdb_config config;
    parse_fdb_config(fdb_config_file, &config);
    config.flags = flags;

    return _fdb_open(handle, filename, &config);
}

static fdb_status _fdb_open(fdb_handle *handle,
                            const char *filename,
                            const fdb_config *config)
{
    struct filemgr_config fconfig;
    bid_t trie_root_bid = BLK_NOT_FOUND;
    bid_t seq_root_bid = BLK_NOT_FOUND;
    fdb_seqnum_t seqnum = 0;
    uint8_t header_buf[FDB_BLOCKSIZE];
    char *compacted_filename = NULL;
    char *prev_filename = NULL;
    size_t header_len = 0;

    fconfig.blocksize = config->blocksize;
    fconfig.ncacheblock = config->buffercache_size / config->blocksize;
    fconfig.flag = 0x0;
    fconfig.options = 0x0;
    if (config->flags & FDB_OPEN_FLAG_RDONLY) {
        fconfig.options |= FILEMGR_READONLY;
    }
    if (config->durability_opt & FDB_DRB_ASYNC) {
        fconfig.options |= FILEMGR_ASYNC;
    }
    if (config->durability_opt & FDB_DRB_ODIRECT) {
        fconfig.flag |= _ARCH_O_DIRECT;
    }

    handle->fileops = get_filemgr_ops();
    handle->file = filemgr_open((char *)filename, handle->fileops, &fconfig);
    if (!handle->file) {
        return FDB_RESULT_OPEN_FAIL;
    }
    handle->btreeblkops = btreeblk_get_ops();
    handle->trie = (struct hbtrie *)malloc(sizeof(struct hbtrie));
    handle->bhandle = (struct btreeblk_handle *)malloc(sizeof(struct btreeblk_handle));
    handle->dhandle = (struct docio_handle *)malloc(sizeof(struct docio_handle));
    handle->config = *config;
    handle->btree_fanout = fconfig.blocksize / (config->chunksize + config->offsetsize);
    handle->last_header_bid = BLK_NOT_FOUND;
    handle->cmp_func = NULL;

    handle->new_file = NULL;
    handle->new_dhandle = NULL;

    handle->datasize = handle->ndocs = 0;

    if (handle->config.compaction_buf_maxsize == 0) {
        handle->config.compaction_buf_maxsize = FDB_COMP_BUF_MAXSIZE;
    }

    if (!wal_is_initialized(handle->file)) {
        wal_init(handle->file, FDB_WAL_NBUCKET);
    }

    docio_init(handle->dhandle, handle->file);
    btreeblk_init(handle->bhandle, handle->file, handle->file->blocksize);

    filemgr_fetch_header(handle->file, header_buf, &header_len);
    if (header_len > 0) {
        _fdb_fetch_header(header_buf, header_len, &trie_root_bid, &seq_root_bid, &seqnum,
            &handle->ndocs, &handle->datasize, &handle->last_header_bid,
            &compacted_filename, &prev_filename);
    }
    handle->cur_header_revnum = filemgr_get_header_revnum(handle->file);

    hbtrie_init(handle->trie, config->chunksize, config->offsetsize,
        handle->file->blocksize, trie_root_bid, (void *)handle->bhandle,
        handle->btreeblkops, (void *)handle->dhandle, _fdb_readkey_wrap);

#ifdef __FDB_SEQTREE
    if (handle->config.seqtree_opt == FDB_SEQTREE_USE) {
        handle->seqnum = seqnum;
        struct btree_kv_ops *kv_ops = (struct btree_kv_ops *)malloc(sizeof(struct btree_kv_ops));
        memcpy(kv_ops, handle->trie->btree_kv_ops, sizeof(struct btree_kv_ops));
        kv_ops->cmp = _cmp_uint64_t;

        handle->seqtree = (struct btree*)malloc(sizeof(struct btree));
        if (seq_root_bid == BLK_NOT_FOUND) {
            btree_init(handle->seqtree, (void *)handle->bhandle, handle->btreeblkops,
                kv_ops, handle->trie->btree_nodesize, sizeof(fdb_seqnum_t),
                handle->trie->valuelen, 0x0, NULL);
         }else{
             btree_init_from_bid(handle->seqtree, (void *)handle->bhandle,
                handle->btreeblkops, kv_ops, handle->trie->btree_nodesize, seq_root_bid);
         }
    }else{
        handle->seqtree = NULL;
    }
#endif

    _fdb_restore_wal(handle);

    if (compacted_filename &&
        filemgr_get_file_status(handle->file) == FILE_NORMAL) {
        _fdb_recover_compaction(handle, compacted_filename);
    }

    if (prev_filename) {
        // record the old filename into the file handle of current file
        // and REMOVE old file on the first open
        // WARNING: snapshots must have been opened before this call
        if (filemgr_update_file_status(handle->file, handle->file->status,
                                       prev_filename)) {
            struct filemgr_config fconfig;
            uint32_t blocksize = handle->config.blocksize;
            memset(&fconfig, 0, sizeof(struct filemgr_config));
            fconfig.blocksize = blocksize;
            fconfig.options |= FILEMGR_READONLY;
            struct filemgr *old_file = filemgr_open(prev_filename,
                                                    handle->fileops,
                                                    &fconfig);
            if (old_file) {
                filemgr_remove_pending(old_file, handle->file);
                filemgr_close(old_file, 0);
            }
        }
    }

    btreeblk_end(handle->bhandle);

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

    *doc = (fdb_doc*)malloc(sizeof(fdb_doc));
    if (*doc == NULL) {
        return FDB_RESULT_ALLOC_FAIL;
    }

#ifdef __FDB_SEQTREE
    (*doc)->seqnum = SEQNUM_NOT_USED;
#endif

    if (key && keylen > 0) {
        (*doc)->key = (void *)malloc(keylen);
        if ((*doc)->key == NULL) {
            return FDB_RESULT_ALLOC_FAIL;
        }
        memcpy((*doc)->key, key, keylen);
        (*doc)->keylen = keylen;
    } else{
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
    } else{
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
    } else{
        (*doc)->body = NULL;
        (*doc)->bodylen = 0;
    }

    (*doc)->deleted = 0;

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
    if (doc->key) free(doc->key);
    if (doc->meta) free(doc->meta);
    if (doc->body) free(doc->body);
    free(doc);
    return FDB_RESULT_SUCCESS;
}

INLINE size_t _fdb_get_docsize(struct docio_length len)
{
    size_t ret =
        len.keylen +
        len.metalen +
        len.bodylen +
        sizeof(struct docio_length);

    #ifdef __FDB_SEQTREE
        ret += sizeof(fdb_seqnum_t);
    #endif

    #ifdef __CRC32
        ret += sizeof(uint32_t);
    #endif

    return ret;
}

INLINE uint64_t _fdb_wal_get_old_offset(void *voidhandle,
                                        struct wal_item *item)
{
    fdb_handle *handle = (fdb_handle *)voidhandle;
    uint64_t old_offset = 0;
    hbtrie_result hr;

    hr = hbtrie_find_offset(handle->trie, item->key, item->keylen,
                            (void*)&old_offset);
    btreeblk_end(handle->bhandle);
    return old_offset;
}

INLINE void _fdb_wal_flush_func(void *voidhandle, struct wal_item *item)
{
    hbtrie_result hr;
    btree_result br;
    fdb_handle *handle = (fdb_handle *)voidhandle;
    uint64_t old_offset;

    if (item->action == WAL_ACT_INSERT || item->action == WAL_ACT_LOGICAL_REMOVE) {
        hr = hbtrie_insert(handle->trie, item->key, item->keylen,
            (void *)&item->offset, (void *)&old_offset);
        btreeblk_end(handle->bhandle);

        SEQTREE(
            if (handle->config.seqtree_opt == FDB_SEQTREE_USE) {
                br = btree_insert(handle->seqtree, (void *)&item->seqnum, (void *)&item->offset);
                btreeblk_end(handle->bhandle);
            }
        );

        if (hr == HBTRIE_RESULT_SUCCESS) {
            handle->ndocs++;
            handle->datasize += item->doc_size;
        }else{
            // update
            struct docio_length len;
            // this block is already cached when we call HBTRIE_INSERT .. no additional block access
            len = docio_read_doc_length(handle->dhandle, old_offset);
            handle->datasize -= _fdb_get_docsize(len);

            handle->datasize += item->doc_size;
        }
    } else {
        // Immediate remove
        hr = hbtrie_remove(handle->trie, item->key, item->keylen);
        btreeblk_end(handle->bhandle);

        SEQTREE(
            if (handle->config.seqtree_opt == FDB_SEQTREE_USE) {
                br = btree_remove(handle->seqtree, (void*)&item->seqnum);
                btreeblk_end(handle->bhandle);
            }
        );

        if (hr == HBTRIE_RESULT_SUCCESS) {
            handle->ndocs--;
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
            bid_t new_seq_root;
            char *compacted_filename;
            char *prev_filename = NULL;
            _fdb_fetch_header(header_buf, header_len,
                &handle->trie->root_bid, &new_seq_root, &handle->seqnum,
                &handle->ndocs, &handle->datasize, &handle->last_header_bid,
                &compacted_filename, &prev_filename);
            if (new_seq_root != handle->seqtree->root_bid) {
                btree_init_from_bid(
                    handle->seqtree, handle->seqtree->blk_handle,
                    handle->seqtree->blk_ops, handle->seqtree->kv_ops,
                    handle->seqtree->blksize, new_seq_root);
            }
            if (prev_filename) {
                free(prev_filename);
            }
        }
        if (header_buf) {
            free(header_buf);
        }
    }
}

void _fdb_check_file_reopen(fdb_handle *handle)
{
    if (filemgr_get_file_status(handle->file) == FILE_REMOVED_PENDING) {

        assert(handle->file->new_file);

        struct filemgr *new_file = handle->file->new_file;
        fdb_config config = handle->config;

        fdb_close(handle);
        _fdb_open(handle, new_file->filename, &config);
    }

    if (filemgr_get_file_status(handle->file) == FILE_COMPACT_OLD &&
        handle->new_file == NULL) {
        assert(handle->file->new_file);

        // open new file and new dhandle
        handle->new_file = filemgr_open(handle->file->new_file->filename,
            handle->fileops, handle->file->config);
        handle->new_dhandle = (struct docio_handle *)malloc(sizeof(struct docio_handle));
        docio_init(handle->new_dhandle, handle->new_file);
    }
}

LIBFDB_API
fdb_status fdb_get(fdb_handle *handle, fdb_doc *doc)
{
    void *header_buf;
    size_t header_len;
    uint64_t offset;
    struct docio_object _doc;
    struct filemgr *wal_file;
    struct docio_handle *dhandle;
    wal_result wr;
    hbtrie_result hr = HBTRIE_RESULT_FAIL;

    if (doc->key == NULL || doc->keylen == 0) {
        return FDB_RESULT_INVALID_ARGS;
    }

    _fdb_check_file_reopen(handle);
    _fdb_sync_db_header(handle);

    if (handle->new_file == NULL) {
        wal_file = handle->file;
    }else{
        wal_file = handle->file->new_file;
    }
    dhandle = handle->dhandle;

    wr = wal_find(wal_file, doc, &offset);

    if (wr == WAL_RESULT_FAIL) {
        hr = hbtrie_find(handle->trie, doc->key, doc->keylen, (void *)&offset);
        btreeblk_end(handle->bhandle);
    } else {
        if (wal_file == handle->new_file) {
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

        if (docio_read_doc(dhandle, offset, &_doc) == offset) {
            return FDB_RESULT_KEY_NOT_FOUND;
        }

        if (_doc.length.keylen != doc->keylen || _doc.length.bodylen == 0) {
            return FDB_RESULT_KEY_NOT_FOUND;
        }

        doc->seqnum = _doc.seqnum;
        doc->metalen = _doc.length.metalen;
        doc->bodylen = _doc.length.bodylen;
        doc->key = _doc.key;
        doc->meta = _doc.meta;
        doc->body = _doc.body;

        return FDB_RESULT_SUCCESS;
    }

    return FDB_RESULT_KEY_NOT_FOUND;
}

// search document metadata using key
LIBFDB_API
fdb_status fdb_get_metaonly(fdb_handle *handle, fdb_doc *doc, uint64_t *body_offset)
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

    _fdb_check_file_reopen(handle);
    _fdb_sync_db_header(handle);

    if (handle->new_file == NULL) {
        wal_file = handle->file;
    }else{
        wal_file = handle->file->new_file;
    }
    dhandle = handle->dhandle;

    wr = wal_find(wal_file, doc, &offset);

    if (wr == WAL_RESULT_FAIL) {
        hr = hbtrie_find(handle->trie, doc->key, doc->keylen, (void *)&offset);
        btreeblk_end(handle->bhandle);
    } else {
        if (wal_file == handle->new_file) {
            dhandle = handle->new_dhandle;
        }
    }

    if (wr != WAL_RESULT_FAIL || hr != HBTRIE_RESULT_FAIL) {
        _doc.key = doc->key;
        _doc.length.keylen = doc->keylen;
        _doc.meta = _doc.body = NULL;

        if (wr == WAL_RESULT_SUCCESS && doc->deleted) {
            return FDB_RESULT_KEY_NOT_FOUND;
        }

        *body_offset = docio_read_doc_key_meta(dhandle, offset, &_doc);
        if (*body_offset == offset){
            return FDB_RESULT_KEY_NOT_FOUND;
        }

        if (_doc.length.keylen != doc->keylen || _doc.length.bodylen == 0) {
            return FDB_RESULT_KEY_NOT_FOUND;
        }

        doc->seqnum = _doc.seqnum;
        doc->metalen = _doc.length.metalen;
        doc->bodylen = _doc.length.bodylen;
        doc->key = _doc.key;
        doc->meta = _doc.meta;
        doc->body = _doc.body;

        return FDB_RESULT_SUCCESS;
    }

    return FDB_RESULT_KEY_NOT_FOUND;
}

#ifdef __FDB_SEQTREE

// search document using sequence number
LIBFDB_API
fdb_status fdb_get_byseq(fdb_handle *handle, fdb_doc *doc)
{
    uint64_t offset;
    struct docio_object _doc;
    struct docio_handle *dhandle;
    struct filemgr *wal_file;
    wal_result wr;
    btree_result br = BTREE_RESULT_FAIL;

    if (doc->seqnum == SEQNUM_NOT_USED) {
        return FDB_RESULT_INVALID_ARGS;
    }

    _fdb_check_file_reopen(handle);
    _fdb_sync_db_header(handle);

    if (handle->new_file == NULL) {
        wal_file = handle->file;
    }else{
        wal_file = handle->file->new_file;
    }
    dhandle = handle->dhandle;

    wr = wal_find(wal_file, doc, &offset);

    if (wr == WAL_RESULT_FAIL) {
        br = btree_find(handle->seqtree, (void *)&doc->seqnum, (void *)&offset);
        btreeblk_end(handle->bhandle);
    } else {
        if (wal_file == handle->new_file) {
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

        if (docio_read_doc(dhandle, offset, &_doc) == offset) {
            return FDB_RESULT_KEY_NOT_FOUND;
        }

        if (_doc.length.bodylen == 0) {
            return FDB_RESULT_KEY_NOT_FOUND;
        }

        assert(doc->seqnum == _doc.seqnum);

        doc->keylen = _doc.length.keylen;
        doc->metalen = _doc.length.metalen;
        doc->bodylen = _doc.length.bodylen;
        doc->key = _doc.key;
        doc->meta = _doc.meta;
        doc->body = _doc.body;

        return FDB_RESULT_SUCCESS;
    }

    return FDB_RESULT_KEY_NOT_FOUND;
}

// search document metadata using sequence number
LIBFDB_API
fdb_status fdb_get_metaonly_byseq(fdb_handle *handle, fdb_doc *doc, uint64_t *body_offset)
{
    uint64_t offset;
    struct docio_object _doc;
    struct docio_handle *dhandle;
    struct filemgr *wal_file;
    wal_result wr;
    btree_result br;

    if (doc->seqnum == SEQNUM_NOT_USED) {
        return FDB_RESULT_INVALID_ARGS;
    }

    _fdb_check_file_reopen(handle);
    _fdb_sync_db_header(handle);

    if (handle->new_file == NULL) {
        wal_file = handle->file;
    }else{
        wal_file = handle->file->new_file;
    }
    dhandle = handle->dhandle;

    wr = wal_find(wal_file, doc, &offset);

    if (wr == WAL_RESULT_FAIL) {
        br = btree_find(handle->seqtree, (void *)&doc->seqnum, (void *)&offset);
        btreeblk_end(handle->bhandle);
    } else {
        if (wal_file == handle->new_file) {
            dhandle = handle->new_dhandle;
        }
    }

    if (wr != WAL_RESULT_FAIL || br != BTREE_RESULT_FAIL) {
        _doc.key = doc->key;
        _doc.meta = _doc.body = NULL;

        if (wr == WAL_RESULT_SUCCESS && doc->deleted) {
            return FDB_RESULT_KEY_NOT_FOUND;
        }

        *body_offset = docio_read_doc_key_meta(dhandle, offset, &_doc);
        if (*body_offset == offset) {
            return FDB_RESULT_KEY_NOT_FOUND;
        }

        if (_doc.length.bodylen == 0) {
            return FDB_RESULT_KEY_NOT_FOUND;
        }

        assert(doc->seqnum == _doc.seqnum);

        doc->keylen = _doc.length.keylen;
        doc->metalen = _doc.length.metalen;
        doc->bodylen = _doc.length.bodylen;
        doc->key = _doc.key;
        doc->meta = _doc.meta;
        doc->body = _doc.body;

        return FDB_RESULT_SUCCESS;
    }

    return FDB_RESULT_KEY_NOT_FOUND;
}
#endif

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

    if (handle->config.flags & FDB_OPEN_FLAG_RDONLY) {
        return FDB_RESULT_RONLY_VIOLATION;
    }

    if ( (doc->key == NULL) || (doc->keylen == 0) ||
        (doc->metalen > 0 && doc->meta == NULL) ||
        (doc->bodylen > 0 && doc->body == NULL)) {
        return FDB_RESULT_INVALID_ARGS;
    }

    file = handle->file;

    _fdb_check_file_reopen(handle);
    _fdb_sync_db_header(handle);

    _doc.length.keylen = doc->keylen;
    _doc.length.metalen = doc->metalen;
    _doc.length.bodylen = doc->bodylen;
    _doc.key = doc->key;

#ifdef __FDB_SEQTREE
    if (handle->config.seqtree_opt == FDB_SEQTREE_USE) {
        //_doc.seqnum = doc->seqnum;
        _doc.seqnum = doc->seqnum = handle->seqnum++;
    }else{
        _doc.seqnum = SEQNUM_NOT_USED;
    }
#endif

    _doc.meta = doc->meta;
    _doc.body = doc->body;

    if (handle->new_file == NULL) {
        file = handle->file;
        dhandle = handle->dhandle;
        filemgr_mutex_lock(file);
    } else {
        file = handle->new_file;
        dhandle = handle->new_dhandle;
        filemgr_mutex_lock(file);
        filemgr_mutex_unlock(handle->file);
    }

    if (dhandle == handle->new_dhandle) {
        offset = docio_append_doc_compact(dhandle, &_doc);
    } else {
        offset = docio_append_doc(dhandle, &_doc);
    }
    wal_insert(file, doc, offset);

    if (wal_get_dirty_status(file)== FDB_WAL_CLEAN) {
        wal_set_dirty_status(file, FDB_WAL_DIRTY);
    }

#ifdef __WAL_FLUSH_BEFORE_COMMIT
    if (wal_get_size(file) > _fdb_get_wal_threshold(handle)) {
        wal_flush(file, (void *)handle,
                  _fdb_wal_flush_func, _fdb_wal_get_old_offset);
        wal_set_dirty_status(file, FDB_WAL_PENDING);
    }
#endif

    filemgr_mutex_unlock(file);
    return FDB_RESULT_SUCCESS;
}

LIBFDB_API
fdb_status fdb_del(fdb_handle *handle, fdb_doc *doc)
{
    if (handle->config.flags & FDB_OPEN_FLAG_RDONLY) {
        return FDB_RESULT_RONLY_VIOLATION;
    }

    if ((doc->key == NULL) || (doc->keylen == 0)) {
        return FDB_RESULT_INVALID_ARGS;
    }

    fdb_doc _doc;
    _doc = *doc;
    _doc.body = NULL;
    _doc.bodylen = 0;
    return fdb_set(handle, &_doc);
}

uint64_t _fdb_set_file_header(fdb_handle *handle)
{
    /*
    <ForestDB header>
    [0000]: BID of root node of root B+Tree of HB+Trie: 8 bytes
    [0008]: BID of root node of seq B+Tree: 8 bytes (optional)
    [0016]: the current DB sequence number: 8 bytes (optional)
    [0024]: # of live documents: 8 bytes
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
    size_t offset = 0;
    uint32_t crc;
    size_t new_filename_len = 0;
    size_t old_filename_len = 0;

    // hb+trie root bid
    seq_memcpy(buf + offset, &handle->trie->root_bid, sizeof(handle->trie->root_bid), offset);

#ifdef __FDB_SEQTREE
    if (handle->config.seqtree_opt == FDB_SEQTREE_USE) {
        // b+tree root bid
        seq_memcpy(buf + offset, &handle->seqtree->root_bid,
            sizeof(handle->seqtree->root_bid), offset);
        // sequence number
        seq_memcpy(buf + offset, &handle->seqnum, sizeof(handle->seqnum), offset);
    }else{
        memset(buf + offset, 0, sizeof(uint64_t) + sizeof(handle->seqnum));
        offset += sizeof(uint64_t) + sizeof(handle->seqnum);
    }
#else
    memset(buf + offset, 0, sizeof(uint64_t) + sizeof(handle->seqnum));
    offset += sizeof(uint64_t) + sizeof(handle->seqnum);
#endif

    // # docs
    seq_memcpy(buf + offset, &handle->ndocs, sizeof(handle->ndocs), offset);
    // data size
    seq_memcpy(buf + offset, &handle->datasize, sizeof(handle->datasize), offset);
    // last header bid
    seq_memcpy(buf + offset, &handle->last_header_bid,
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
    seq_memcpy(buf + offset, &crc, sizeof(crc), offset);

    return filemgr_update_header(handle->file, buf, offset);
}

LIBFDB_API
fdb_status fdb_commit(fdb_handle *handle)
{
    fdb_status fs = FDB_RESULT_SUCCESS;
    if (handle->config.flags & FDB_OPEN_FLAG_RDONLY) {
        return FDB_RESULT_RONLY_VIOLATION;
    }

    filemgr_mutex_lock(handle->file);

    if (handle->new_file) {
        // HANDLE->FILE is undergoing compaction ..
        // just do fsync to HANDLE->NEW_FILE

        // relay lock
        filemgr_mutex_lock(handle->new_file);
        filemgr_mutex_unlock(handle->file);

        fs = filemgr_sync(handle->new_file);
        filemgr_mutex_unlock(handle->new_file);
    } else {
        // normal case
        btreeblk_end(handle->bhandle);
        if (wal_get_size(handle->file) > _fdb_get_wal_threshold(handle) ||
            wal_get_dirty_status(handle->file) == FDB_WAL_PENDING) {
            // wal flush when
            // 1. wal size exceeds threshold
            // 2. wal is already flushed before commit (in this case flush the rest of entries)
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
        fs = filemgr_commit(handle->file);

        filemgr_mutex_unlock(handle->file);
    }
    return fs;
}

INLINE int _fdb_cmp_uint64_t(const void *key1, const void *key2)
{
#ifdef __BIT_CMP

    uint64_t a,b;
    a = *(uint64_t*)key1;
    b = *(uint64_t*)key2;
    return _CMP_U64(a, b);

#else

    if (*a<*b) return -1;
    if (*a>*b) return 1;
    return 0;

#endif
}

INLINE void _fdb_compact_move_docs(fdb_handle *handle,
                              struct filemgr *new_file,
                              struct hbtrie *new_trie,
                              struct btree *new_seqtree,
                              struct docio_handle *new_dhandle,
                              struct btreeblk_handle *new_bhandle,
                              uint64_t *count_out,
                              uint64_t *new_datasize_out)
{
    uint8_t *k = alca(uint8_t, HBTRIE_MAX_KEYLEN);
    uint64_t offset;
    uint64_t new_offset;
    uint64_t *offset_array;
    size_t i, c, count;
    size_t offset_array_max;
    size_t keylen;
    hbtrie_result hr;
    struct docio_object doc;
    struct hbtrie_iterator it;
    fdb_doc wal_doc;
    fdb_handle new_handle;

    new_handle = *handle;
    new_handle.trie = new_trie;
    new_handle.seqtree = new_seqtree;
    new_handle.dhandle = new_dhandle;
    new_handle.bhandle = new_bhandle;
    new_handle.ndocs = 0;
    new_handle.datasize = 0;

    offset_array_max =
        handle->config.compaction_buf_maxsize / sizeof(uint64_t);
    offset_array = (uint64_t*)malloc(sizeof(uint64_t) * offset_array_max);
    c = count = 0;
    hr = hbtrie_iterator_init(handle->trie, &it, NULL, 0);

    while( hr != HBTRIE_RESULT_FAIL ) {

        hr = hbtrie_next_value_only(&it, (void*)&offset);
        btreeblk_end(handle->bhandle);

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

            for (i=0; i<c; ++i) {
                offset = offset_array[i];

                doc.key = k;
                doc.meta = NULL;
                doc.body = NULL;
                docio_read_doc(handle->dhandle, offset, &doc);

                // re-write to new file
                filemgr_mutex_lock(new_file);
                new_offset = docio_append_doc(new_dhandle, &doc);

                wal_doc.keylen = doc.length.keylen;
                wal_doc.metalen = doc.length.metalen;
                wal_doc.bodylen = doc.length.bodylen;
                wal_doc.key = doc.key;
#ifdef __FDB_SEQTREE
                wal_doc.seqnum = doc.seqnum;
#endif
                wal_doc.meta = doc.meta;
                wal_doc.body = doc.body;

                wal_insert_by_compactor(new_file, &wal_doc, new_offset);

                filemgr_mutex_unlock(new_file);
                free(doc.meta);
                free(doc.body);
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
    *(count_out) = new_handle.ndocs;
    *(new_datasize_out) = new_handle.datasize;

    hr = hbtrie_iterator_free(&it);
    free(offset_array);
}

LIBFDB_API
fdb_status fdb_compact(fdb_handle *handle, const char *new_filename)
{
    struct filemgr *new_file, *old_file;
    struct filemgr_config fconfig;
    struct btreeblk_handle *new_bhandle;
    struct docio_handle *new_dhandle;
    struct hbtrie *new_trie;
    struct btree *new_seqtree, *old_seqtree;
    char *old_filename = NULL;
    struct hbtrie_iterator it;
    struct btree_iterator bit;
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
        _fdb_sync_db_header(handle);

        return FDB_RESULT_COMPACTION_FAIL;
    }

    // invalid filename
    if (!strcmp(new_filename, handle->file->filename)) {
        filemgr_mutex_unlock(handle->file);
        return FDB_RESULT_INVALID_ARGS;
    }

    // set filemgr configuration
    fconfig.blocksize = handle->config.blocksize;
    fconfig.ncacheblock = handle->config.buffercache_size / handle->config.blocksize;
    fconfig.options = 0x0;
    fconfig.flag = 0x0;
    if (handle->config.durability_opt & FDB_DRB_ODIRECT) {
        fconfig.flag |= _ARCH_O_DIRECT;
    }
    if (handle->config.durability_opt & FDB_DRB_ASYNC) {
        fconfig.options |= FILEMGR_ASYNC;
    }

    // open new file
    new_file = filemgr_open((char *)new_filename, handle->fileops, &fconfig);
    assert(new_file);

    // prevent update to the new_file
    filemgr_mutex_lock(new_file);


    // create new hb-trie and related handles
    new_bhandle = (struct btreeblk_handle *)malloc(sizeof(struct btreeblk_handle));
    new_dhandle = (struct docio_handle *)malloc(sizeof(struct docio_handle));
    new_trie = (struct hbtrie *)malloc(sizeof(struct hbtrie));

    wal_init(new_file, handle->config.wal_threshold);
    docio_init(new_dhandle, new_file);
    btreeblk_init(new_bhandle, new_file, new_file->blocksize);
    hbtrie_init(new_trie, handle->trie->chunksize, handle->trie->valuelen,
        new_file->blocksize, BLK_NOT_FOUND, (void *)new_bhandle,
        handle->btreeblkops, (void*)new_dhandle, _fdb_readkey_wrap);
    if (handle->cmp_func) {
        new_trie->btree_kv_ops->cmp = handle->cmp_func;
    }
    new_trie->flag = handle->trie->flag;
    new_trie->leaf_height_limit = handle->trie->leaf_height_limit;


#ifdef __FDB_SEQTREE
    if (handle->config.seqtree_opt == FDB_SEQTREE_USE) {
        // if we use sequence number tree
        new_seqtree = (struct btree *)malloc(sizeof(struct btree));
        old_seqtree = handle->seqtree;

        btree_init(new_seqtree, (void *)new_bhandle, old_seqtree->blk_ops,
            old_seqtree->kv_ops, old_seqtree->blksize, old_seqtree->ksize, old_seqtree->vsize,
            0x0, NULL);
    }
#endif

    count = new_datasize = 0;

    // mark name of new file in old file
    filemgr_set_compaction_old(handle->file, new_file);
    // flush WAL and set DB header
    wal_flush(handle->file, (void*)handle,
        _fdb_wal_flush_func, _fdb_wal_get_old_offset);
    wal_set_dirty_status(handle->file, FDB_WAL_CLEAN);
    handle->last_header_bid =
        (handle->file->pos) / handle->file->blocksize;
    handle->cur_header_revnum = _fdb_set_file_header(handle);
    btreeblk_end(handle->bhandle);
    assert(handle->file->status == FILE_COMPACT_OLD);
    // Commit the current file handle to record the compaction filename
    fdb_status fs = filemgr_commit(handle->file);
    if (fs != FDB_RESULT_SUCCESS) {
        return fs;
    }

    // Mark new file as newly compacted
    filemgr_update_file_status(new_file, FILE_COMPACT_NEW, NULL);
    filemgr_mutex_unlock(handle->file);
    filemgr_mutex_unlock(new_file);
    // now compactor & another writer can be interleaved

    _fdb_compact_move_docs(handle, new_file, new_trie, new_seqtree,
                           new_dhandle, new_bhandle, &count, &new_datasize);

    filemgr_mutex_lock(new_file);
    handle->ndocs = count;
    handle->datasize = new_datasize;

    old_file = handle->file;
    // Don't clean up the buffer cache entries for the old file.
    // They will be cleaned up later.
    filemgr_close(old_file, 0);
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

#ifdef __FDB_SEQTREE
    if (handle->config.seqtree_opt == FDB_SEQTREE_USE) {
        free(handle->seqtree);
        handle->seqtree = new_seqtree;
    }
#endif

    old_filename_len = strlen(old_file->filename) + 1;
    old_filename = (char *) malloc(old_filename_len);
    strncpy(old_filename, old_file->filename, old_filename_len);
    filemgr_update_file_status(new_file, FILE_NORMAL, old_filename);

    // allow update to new_file
    filemgr_mutex_unlock(new_file);

    // commit new file
    fdb_commit(handle);

    wal_shutdown(old_file);

    // removing file is pended until there is no handle referring the file
    filemgr_remove_pending(old_file, new_file);

    return FDB_RESULT_SUCCESS;
}

// manually flush WAL entries into index
LIBFDB_API
fdb_status fdb_flush_wal(fdb_handle *handle)
{
    if (handle->config.flags & FDB_OPEN_FLAG_RDONLY) {
        return FDB_RESULT_RONLY_VIOLATION;
    }

    filemgr_mutex_lock(handle->file);

    if (wal_get_size(handle->file) > 0) {
        wal_flush(handle->file, (void*)handle,
                  _fdb_wal_flush_func, _fdb_wal_get_old_offset);
        wal_set_dirty_status(handle->file, FDB_WAL_PENDING);
    }

    filemgr_mutex_unlock(handle->file);
    return FDB_RESULT_SUCCESS;
}

LIBFDB_API
fdb_status fdb_close(fdb_handle *handle)
{
    fdb_status fs = filemgr_close(handle->file, handle->config.cleanup_cache_onclose);
    if (fs != FDB_RESULT_SUCCESS) {
        return fs;
    }
    docio_free(handle->dhandle);
    if (handle->new_file) {
        fs = filemgr_close(handle->new_file, handle->config.cleanup_cache_onclose);
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
    hbtrie_free(handle->trie);
    free(handle->trie);
#ifdef __FDB_SEQTREE
    if (handle->config.seqtree_opt == FDB_SEQTREE_USE) {
        free(handle->seqtree->kv_ops);
        free(handle->seqtree);
    }
#endif
    free(handle->bhandle);
    free(handle->dhandle);
    return FDB_RESULT_SUCCESS;
}

// roughly estimate the space occupied db handle HANDLE
LIBFDB_API
size_t fdb_estimate_space_used(fdb_handle *handle)
{
    size_t ret = 0;
    size_t fanout = handle->btree_fanout;
#ifdef __UTREE
    fanout = fanout / 3;
#endif

    ret += handle->datasize;
    // hb-trie size (estimated as worst case)
    ret += (handle->ndocs / (fanout * 3 / 4)) * handle->config.blocksize;
    // b-tree size (estimated as worst case)
    ret += (handle->ndocs / (fanout * 3 / 4)) * handle->config.blocksize;

    ret += wal_get_datasize(handle->file);

    return ret;
}

LIBFDB_API
fdb_status fdb_shutdown()
{
    filemgr_shutdown();
#ifdef _MEMPOOL
    mempool_shutdown();
#endif

    return FDB_RESULT_SUCCESS;
}


