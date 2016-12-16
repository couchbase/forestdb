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
#include "fdb_engine.h"
#include "fdb_internal.h"
#include "file_handle.h"
#include "filemgr.h"
#include "hbtrie.h"
#include "list.h"
#include "breakpad.h"
#include "btree.h"
#include "btree_new.h"
#include "btree_kv.h"
#include "btree_var_kv_ops.h"
#include "docio.h"
#include "executorpool.h"
#include "btreeblock.h"
#include "bnodemgr.h"
#include "common.h"
#include "wal.h"
#include "filemgr_ops.h"
#include "configuration.h"
#include "internal_types.h"
#include "bgflusher.h"
#include "compaction.h"
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


std::atomic<FdbEngine *> FdbEngine::instance(nullptr);
std::mutex FdbEngine::instanceMutex;
volatile size_t FdbEngine::fdbOpenInProg(0);

int _cmp_uint64_t_endian_safe(void *key1, void *key2, void *aux)
{
    (void) aux;
    uint64_t a,b;
    a = *(uint64_t*)key1;
    b = *(uint64_t*)key2;
    a = _endian_decode(a);
    b = _endian_decode(b);
    return _CMP_U64(a, b);
}

size_t _fdb_readkey_wrap(void *handle,
                         uint64_t offset,
                         void *req_key,
                         void *chunk,
                         size_t curchunkno,
                         void *buf)
{
    (void)req_key;
    (void)chunk;
    (void)curchunkno;
    fdb_status fs;
    keylen_t keylen;
    DocioHandle *dhandle = reinterpret_cast<DocioHandle*>(handle);

    offset = _endian_decode(offset);
    fs = dhandle->readDocKey_Docio(offset, &keylen, buf);
    if (fs == FDB_RESULT_SUCCESS) {
        return keylen;
    } else {
        const char *msg = "readDocKey_Docio error: read failure on "
            "offset %" _F64 " in a database file '%s' "
            ": FDB status %d, lastbid 0x%" _X64 ", "
            "curblock 0x%" _X64 ", curpos 0x%x\n";
        fdb_log(NULL, FDB_RESULT_READ_FAIL, msg, offset,
                dhandle->getFile()->getFileName(), fs, dhandle->getLastBid(),
                dhandle->getCurBlock(), dhandle->getCurPos());
        dbg_print_buf(dhandle->getReadBuffer(),
                      dhandle->getFile()->getBlockSize(),
                      true, 16);
        return 0;
    }
}

size_t _fdb_readseq_wrap(void *handle,
                         uint64_t offset,
                         void *req_key,
                         void *chunk,
                         size_t curchunkno,
                         void *buf)
{
    int size_id, size_seq, size_chunk;
    fdb_seqnum_t _seqnum;
    struct docio_object doc;
    DocioHandle *dhandle = reinterpret_cast<DocioHandle *>(handle);

    size_id = sizeof(fdb_kvs_id_t);
    size_seq = sizeof(fdb_seqnum_t);
    size_chunk = dhandle->getFile()->getConfig()->getChunkSize();

    if ( req_key && chunk &&
         size_seq == size_chunk &&
         curchunkno == 1 ) {
        // if the sizes of sequence number and chunk are the same
        // and the current chunk is in the second level,
        // then we can return sequence number without reading doc.

        // Note: at the time that 'readKey' is called, all previous chunks are
        // already checked as correct, so we can copy KVS ID from 'req_key'.
        memcpy((uint8_t*)buf, req_key, size_id);
        memcpy((uint8_t*)buf + size_id, chunk, size_seq);
        return size_id + size_seq;
    }

    // Other case happens when there is only one document in a KVS;
    // the unique sequence number will be indexed by KVS ID.
    // In this case, we need to read a doc.
    memset(&doc, 0, sizeof(struct docio_object));

    offset = _endian_decode(offset);
    if (dhandle->readDocKeyMeta_Docio(offset, &doc, true) <= 0) {
        return 0;
    }
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
    BTreeKVOps *kv_ops = args->kv_ops;

    is_key1_inf = kv_ops->isInfVarKey(key1);
    is_key2_inf = kv_ops->isInfVarKey(key2);
    if (is_key1_inf && is_key2_inf) { // both are infinite
        return 0;
    } else if (!is_key1_inf && is_key2_inf) { // key2 is infinite
        return -1;
    } else if (is_key1_inf && !is_key2_inf) { // key1 is infinite
        return 1;
    }

    kv_ops->getVarKey(key1, (void*)keystr1, keylen1);
    kv_ops->getVarKey(key2, (void*)keystr2, keylen2);

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
    if (ver_is_atleast_magic_001(version)) {
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

void fdb_dummy_log_callback(int err_code, const char *err_msg, void *ctx_data)
{
    (void)err_code;
    (void)err_msg;
    (void)ctx_data;
    return;
}

INLINE void _fdb_restore_wal(FdbKvsHandle *handle,
                             fdb_restore_mode_t mode,
                             bid_t hdr_bid,
                             fdb_kvs_id_t kv_id_req)
{
    FileMgr *file = handle->file;
    uint32_t blocksize = handle->file->getBlockSize();
    uint64_t last_wal_flush_hdr_bid = handle->last_wal_flush_hdr_bid;
    uint64_t hdr_off = hdr_bid * FDB_BLOCKSIZE;
    uint64_t offset = 0; //assume everything from first block needs restoration
    uint64_t filesize = handle->file->getPos();
    uint64_t doc_scan_limit;
    uint64_t start_bmp_revnum, stop_bmp_revnum;
    uint64_t cur_bmp_revnum = (uint64_t)-1;
    bid_t next_doc_block = BLK_NOT_FOUND;
    struct _fdb_key_cmp_info cmp_info;
    Wal *wal = file->getWal();
    ErrLogCallback *log_callback;

    if (mode == FDB_RESTORE_NORMAL && !handle->shandle &&
        !wal->tryRestore_Wal()) { // Atomically try to restore WAL
        // Some other thread or previous open had successfully initialized WAL
        // We can simply return here
        return;
    }

    if (!hdr_off) { // Nothing to do if we don't have a header block offset
        return;
    }

    if (last_wal_flush_hdr_bid != BLK_NOT_FOUND) {
        offset = (last_wal_flush_hdr_bid + 1) * blocksize;
    }

    // If a valid last header was retrieved and it matches the current header
    if (hdr_off == offset || hdr_bid == last_wal_flush_hdr_bid) {
        return; // No WAL section in the file
    }

    if (mode == FDB_RESTORE_NORMAL && !handle->shandle) {
        // for normal WAL restore, set status to dirty
        // (only when the previous status is clean or dirty)
        wal->setDirtyStatus_Wal(FDB_WAL_DIRTY, true);
    }

    // Temporarily disable the error logging callback as there are false positive
    // checksum errors in readDoc_Docio.
    // TODO: Need to adapt readDoc_Docio to separate false checksum errors.
    ErrLogCallback dummy_cb;
    log_callback = handle->dhandle->getLogCallback();
    dummy_cb.setCallback(fdb_dummy_log_callback);
    dummy_cb.setCtxData(NULL);
    handle->dhandle->setLogCallback(&dummy_cb);

    if (!handle->shandle) {
        file->mutexLock();
    }
    cmp_info.kvs_config = handle->kvs_config;
    cmp_info.kvs = handle->kvs;

    start_bmp_revnum = handle->file->getSbBmpRevnum(last_wal_flush_hdr_bid);
    stop_bmp_revnum= handle->file->getSbBmpRevnum(hdr_bid);
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

            bid_t sb_last_hdr_bid = BLK_NOT_FOUND;
            if (handle->file->getSb()) {
                sb_last_hdr_bid = handle->file->getSb()->getLastHdrBid();
            }
            if (!handle->shandle && handle->file->getSb() &&
                sb_last_hdr_bid != BLK_NOT_FOUND) {
                hdr_off = (sb_last_hdr_bid+1) * blocksize;
            }

            doc_scan_limit = hdr_off;
            if (offset >= hdr_off) {
                break;
            }
        } else {
            doc_scan_limit = filesize;
        }

        if (!handle->dhandle->checkBuffer_Docio(offset / blocksize,
                                cur_bmp_revnum)) {
            // not a document block .. move to next block
        } else {
            do {
                struct docio_object doc;
                int64_t _offset;
                uint64_t doc_offset;
                memset(&doc, 0, sizeof(doc));
                _offset = handle->dhandle->readDoc_Docio(offset, &doc, true);
                if (_offset <= 0) { // reached unreadable doc, skip block
                    // TODO: Need to have this function return fdb_status, so that
                    // WAL restore operation should fail if offset < 0
                    break;
                } else if ((uint64_t)_offset < offset) {
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
                            if (handle->dhandle->readDoc_Docio(doc_offset,
                                        &doc, true) <= 0) {
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

                        // If say a snapshot is taken on a db handle after
                        // rollback, then skip WAL items after rollback point
                        if ((mode == FDB_RESTORE_KV_INS || !handle->kvs) &&
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

                                kv_seqnum = fdb_kvs_get_seqnum(handle->file, kv_id);
                                if (doc.seqnum <= kv_seqnum &&
                                        ((mode == FDB_RESTORE_KV_INS &&
                                            kv_id == kv_id_req) ||
                                         (mode == FDB_RESTORE_NORMAL)) ) {
                                    // if mode is NORMAL, restore all items
                                    // if mode is KV_INS, restore items matching ID
                                    wal->insert_Wal(file->getGlobalTxn(),
                                                    &cmp_info,
                                                    &wal_doc, doc_offset,
                                                    WAL_INS_WRITER);
                                }
                            } else {
                                wal->insert_Wal(file->getGlobalTxn(), &cmp_info,
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
                                if (kv_id == handle->kvs->getKvsId()) {
                                    // snapshot: insert ID matched documents only
                                    handle->shandle->snapInsertDoc(&wal_doc,
                                                                   doc_offset);
                                } else {
                                    free(doc.key);
                                }
                            } else {
                                handle->shandle->snapInsertDoc(&wal_doc,
                                                               doc_offset);
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
        if (ver_superblock_support(handle->file->getVersion()) &&
            offset >= filesize) {
            // circular scan
            SuperblockBase *sb = handle->file->getSb();
            if (sb) {
                offset = blocksize * sb->getConfig().num_sb;
                cur_bmp_revnum++;
            }
        }
    } while(true);

    // wal commit
    if (!handle->shandle) {
        wal->commit_Wal(file->getGlobalTxn(), NULL, &handle->log_callback);
        file->mutexUnlock();
    }
    handle->dhandle->setLogCallback(log_callback);
}

INLINE fdb_status _fdb_recover_compaction(FdbKvsHandle *handle,
                                          const char *new_filename)
{
    FdbKvsHandle new_db;
    fdb_config config = handle->config;
    FileMgr *new_file;

    // As partially compacted file may contain various errors,
    // we temporarily disable log callback for compaction recovery.
    new_db.log_callback.setCallback(nullptr);
    config.flags |= FDB_OPEN_FLAG_RDONLY;
    new_db.fhandle = handle->fhandle;
    new_db.kvs_config = handle->kvs_config;
    fdb_status status = FdbEngine::getInstance()->openFdb(&new_db, new_filename,
                                                          FDB_AFILENAME, &config);
    if (status != FDB_RESULT_SUCCESS) {
        return fdb_log(&handle->log_callback, status,
                       "Error in opening a partially compacted file '%s' for recovery.",
                       new_filename);
    }

    new_file = new_db.file;

    if (!new_file->getOldFileName().empty() &&
        !strncmp(new_file->getOldFileName().c_str(), handle->file->getFileName(),
                 FDB_MAX_FILENAME_LEN)) {
        FileMgr *old_file = handle->file;
        // If new file has a recorded old_filename then it means that
        // compaction has completed successfully. Mark self for deletion
        new_file->mutexLock();

        bool is_btree_v2 = ver_btreev2_format(handle->file->getVersion());
        if (is_btree_v2) {
            handle->bnodeMgr->releaseCleanNodes();
            delete handle->bnodeMgr;
            handle->bnodeMgr = new_db.bnodeMgr;
        } else {
            status = handle->bhandle->flushBuffer();
            if (status != FDB_RESULT_SUCCESS) {
                new_file->mutexUnlock();
                FdbEngine::getInstance()->closeKVHandle(&new_db);
                return status;
            }
            delete handle->bhandle;
            handle->bhandle = new_db.bhandle;
        }

        delete handle->dhandle;
        handle->dhandle = new_db.dhandle;

        delete handle->trie;
        handle->trie = new_db.trie;

        handle->file->getWal()->shutdown_Wal(&handle->log_callback);
        handle->file = new_file;

        if (handle->config.seqtree_opt == FDB_SEQTREE_USE) {
            if (handle->kvs) {
                // multi KV instance mode
                delete handle->seqtrie;
                if (new_db.config.seqtree_opt == FDB_SEQTREE_USE) {
                    handle->seqtrie = new_db.seqtrie;
                }
            } else {
                if (is_btree_v2) {
                    delete handle->seqtreeV2;
                    handle->seqtreeV2 = nullptr;
                } else {
                    delete handle->seqtree->getKVOps();
                    delete handle->seqtree;
                    handle->seqtree = nullptr;
                }
                if (new_db.config.seqtree_opt == FDB_SEQTREE_USE) {
                    if (is_btree_v2) {
                        handle->seqtreeV2 = new_db.seqtreeV2;
                    } else {
                        handle->seqtree = new_db.seqtree;
                    }
                }
            }
        }
        if (is_btree_v2) {
            handle->staletreeV2 = new_db.staletreeV2;
        } else {
            handle->staletree = new_db.staletree;
        }

        new_file->mutexUnlock();
        // remove self: WARNING must not close this handle if snapshots
        // are yet to open this file
        FileMgr::removePending(old_file, new_db.file, &new_db.log_callback);
        FileMgr::close(old_file, false, handle->filename.c_str(), &handle->log_callback);
        return FDB_RESULT_FAIL_BY_COMPACTION;
    }

    // As the new file is partially compacted, it should be removed upon close.
    // Just in-case the new file gets opened before removal, point it to the old
    // file to ensure availability of data.
    FileMgr::removePending(new_db.file, handle->file, &handle->log_callback);
    FdbEngine::getInstance()->closeKVHandle(&new_db);

    return FDB_RESULT_SUCCESS;
}

static void standard_sb_init(FileMgr *file) {
    struct sb_config sconfig = SuperblockBase::getDefaultConfig();
    SuperblockBase *sb = new Superblock(file, sconfig);
    file->setSb(sb);
}

LIBFDB_API
fdb_status fdb_init(fdb_config *config)
{
    return FdbEngine::init(config);
}

LIBFDB_API
fdb_config fdb_get_default_config(void) {
    return FdbEngine::getDefaultConfig();
}

LIBFDB_API
fdb_kvs_config fdb_get_default_kvs_config(void) {
    return FdbEngine::getDefaultKvsConfig();
}

LIBFDB_API
fdb_filemgr_ops_t* fdb_get_default_file_ops(void) {
    return FdbEngine::getDefaultFileOps();
}

LIBFDB_API
fdb_status fdb_fetch_handle_stats(fdb_kvs_handle *handle,
                                  fdb_handle_stats_cb callback,
                                  void *ctx)
{
    return FdbEngine::fetchHandleStats(handle, callback, ctx);
}

LIBFDB_API
fdb_status fdb_open(fdb_file_handle **ptr_fhandle,
                    const char *filename,
                    fdb_config *fconfig)
{
    fdb_config config;

    if (fconfig) {
        if (FdbEngine::validateFdbConfig(*fconfig)) {
            config = *fconfig;
        } else {
            return FDB_RESULT_INVALID_CONFIG;
        }
    } else {
        config = FdbEngine::getDefaultConfig();
    }

    FdbEngine::incrOpenInProgCounter();
    fdb_status fs = FdbEngine::init(&config);
    if (fs != FDB_RESULT_SUCCESS) {
        FdbEngine::decrOpenInProgCounter();
        return fs;
    }

    fs = FDB_RESULT_ENGINE_NOT_INSTANTIATED;
    FdbEngine *fdb_engine = FdbEngine::getInstance();
    if (fdb_engine) {
        fs = fdb_engine->openFile(ptr_fhandle, filename, config);
    }
    FdbEngine::decrOpenInProgCounter();
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
    fdb_config config;

    if (fconfig) {
        if (FdbEngine::validateFdbConfig(*fconfig)) {
            config = *fconfig;
        } else {
            return FDB_RESULT_INVALID_CONFIG;
        }
    } else {
        config = FdbEngine::getDefaultConfig();
    }

    FdbEngine::incrOpenInProgCounter();
    fdb_status fs = FdbEngine::init(&config);
    if (fs != FDB_RESULT_SUCCESS) {
        FdbEngine::decrOpenInProgCounter();
        return fs;
    }

    fs = FDB_RESULT_ENGINE_NOT_INSTANTIATED;
    FdbEngine *fdb_engine = FdbEngine::getInstance();
    if (fdb_engine) {
        fs = fdb_engine->openFileWithCustomCmp(ptr_fhandle, filename, config,
                                               num_functions, kvs_names, functions);
    }
    FdbEngine::decrOpenInProgCounter();
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
    FdbKvsHandle *handle;

    handle = new FdbKvsHandle();
    if (!handle) { // LCOV_EXCL_START
        return FDB_RESULT_ALLOC_FAIL;
    } // LCOV_EXCL_STOP

    fhandle = new FdbFileHandle(handle);
    if (!fhandle) { // LCOV_EXCL_START
        delete handle;
        return FDB_RESULT_ALLOC_FAIL;
    } // LCOV_EXCL_STOP

    handle->initBusy();
    handle->shandle = NULL;

    if (cmp_func_list && list_begin(cmp_func_list)) {
        fhandle->setCmpFunctionList(cmp_func_list);
    }
    fdb_status fs = FdbEngine::getInstance()->openFdb(handle, filename,
                                                      FDB_VFILENAME, fconfig);
    if (fs == FDB_RESULT_SUCCESS) {
        *ptr_fhandle = fhandle;
        handle->file->fhandleAdd(fhandle);
    } else {
        *ptr_fhandle = NULL;
        delete handle;
        delete fhandle;
    }
    return fs;
}

LIBFDB_API
fdb_status fdb_snapshot_open(FdbKvsHandle *handle_in,
                             FdbKvsHandle **ptr_handle, fdb_seqnum_t seqnum)
{
    FdbEngine *fdb_engine = FdbEngine::getInstance();
    if (fdb_engine) {
        return fdb_engine->openSnapshot(handle_in, ptr_handle, seqnum);
    }
    return FDB_RESULT_ENGINE_NOT_INSTANTIATED;
}

static fdb_status _fdb_reset(FdbKvsHandle *handle, FdbKvsHandle *handle_in);

LIBFDB_API
fdb_status fdb_rollback(FdbKvsHandle **handle_ptr, fdb_seqnum_t seqnum)
{
    FdbEngine *fdb_engine = FdbEngine::getInstance();
    if (fdb_engine) {
        return fdb_engine->rollback(handle_ptr, seqnum);
    }
    return FDB_RESULT_ENGINE_NOT_INSTANTIATED;
}

LIBFDB_API
fdb_status fdb_rollback_all(fdb_file_handle *fhandle,
                            fdb_snapshot_marker_t marker)
{
    FdbEngine *fdb_engine = FdbEngine::getInstance();
    if (fdb_engine) {
        return fdb_engine->rollbackAll(fhandle, marker);
    }
    return FDB_RESULT_ENGINE_NOT_INSTANTIATED;
}

fdb_status _fdb_clone_snapshot(FdbKvsHandle *handle_in,
                               FdbKvsHandle *handle_out)
{
    fdb_status status;

    handle_out->config = handle_in->config;
    handle_out->kvs_config = handle_in->kvs_config;
    handle_out->fileops = handle_in->fileops;
    handle_out->file = handle_in->file;
    // Note that the file ref count will be decremented when the cloned snapshot
    // is closed through FileMgr::close().
    handle_out->file->incrRefCount();

    handle_out->filename = handle_in->filename;

    // initialize the docio handle.
    handle_out->dhandle = new DocioHandle(handle_out->file,
                              handle_out->config.compress_document_body,
                              &handle_out->log_callback);

    if (ver_btreev2_format(handle_out->file->getVersion())) {
        // initialize the Bnode Manager
        handle_out->bnodeMgr = new BnodeMgr();
        handle_out->bnodeMgr->setFile(handle_out->file);
        handle_out->bnodeMgr->setLogCallback(&handle_out->log_callback);
        // initialize the trie handle based on BtreeV2 format
        handle_out->trie = new HBTrie(handle_out->config.chunksize,
                                      handle_out->file->getBlockSize(),
                                      // Source snapshot's trie root address..
                                      handle_in->trie->getRootAddr(),
                                      handle_out->bnodeMgr,
                                      handle_out->file);
        if (handle_out->kvs) {
            handle_out->trie->setCmpFuncCB(FdbEngine::getCmpFuncCB);
        }
    } else {
        // initialize the btree block handle.
        handle_out->bhandle = new BTreeBlkHandle(handle_out->file,
                                              handle_out->file->getBlockSize());
        handle_out->bhandle->setLogCallback(&handle_out->log_callback);
        // initialize the trie handle
        handle_out->trie = new HBTrie(handle_out->config.chunksize, OFFSET_SIZE,
                                      handle_out->file->getBlockSize(),
                                      // Source snapshot's trie root bid..
                                      handle_in->trie->getRootBid(),
                                      handle_out->bhandle,
                                      (void *)handle_out->dhandle,
                                      _fdb_readkey_wrap);
        // set aux for cmp wrapping function
        handle_out->trie->setLeafHeightLimit(0xff);
        handle_out->trie->setLeafCmp(_fdb_custom_cmp_wrap);
        if (handle_out->kvs) {
            handle_out->trie->setMapFunction(fdb_kvs_find_cmp_chunk);
        }
    }

    handle_out->dirty_updates = handle_in->dirty_updates;
    handle_out->cur_header_revnum = handle_in->cur_header_revnum.load();
    handle_out->last_wal_flush_hdr_bid = handle_in->last_wal_flush_hdr_bid;
    handle_out->kv_info_offset = handle_in->kv_info_offset;
    handle_out->op_stats = handle_in->op_stats;
    handle_out->seqnum = handle_in->seqnum;
    if (handle_out->config.seqtree_opt == FDB_SEQTREE_USE) {
        if (handle_out->config.multi_kv_instances) {
            if (ver_btreev2_format(handle_out->file->getVersion())) {
                // multi KV instance mode .. HB+trie with BtreeV2
                handle_out->seqtrie = new HBTrie(sizeof(fdb_kvs_id_t),
                                                 handle_out->file->getBlockSize(),
                                                 /*Source snapshot's seqtrie root bid*/
                                                 handle_in->seqtrie->getRootAddr(),
                                                 handle_out->bnodeMgr, handle_out->file);
            } else {
                // multi KV instance mode .. HB+trie
                handle_out->seqtrie = new HBTrie(sizeof(fdb_kvs_id_t),
                                                 OFFSET_SIZE,
                                                 handle_out->file->getBlockSize(),
                                                 /*Source snapshot's seqtrie root bid*/
                                                 handle_in->seqtrie->getRootBid(),
                                                 handle_out->bhandle,
                                                 (void *)handle_out->dhandle,
                                                 _fdb_readseq_wrap);
            }
        } else {
            if (ver_btreev2_format(handle_out->file->getVersion())) {
                handle_out->seqtreeV2 = new BtreeV2();
                handle_out->seqtreeV2->setBMgr(handle_out->bnodeMgr);
                handle_out->seqtreeV2->initFromAddr(handle_in->seqtreeV2->getRootAddr());
            } else {
                // single KV instance mode .. normal B+tree
                BTreeKVOps *seq_kv_ops = new FixedKVOps(8, 8, _cmp_uint64_t_endian_safe);

                // Init the seq tree using the root bid of the source snapshot.
                handle_out->seqtree = new BTree(handle_out->bhandle, seq_kv_ops,
                                                handle_out->config.blocksize,
                                                handle_in->seqtree->getRootBid());
            }
        }
    } else{
        handle_out->seqtree = NULL;
    }

    if (ver_btreev2_format(handle_out->file->getVersion())) {
        handle_out->bnodeMgr->releaseCleanNodes();
        status = FDB_RESULT_SUCCESS;
    } else {
        status = handle_out->bhandle->flushBuffer();
    }
    if (status != FDB_RESULT_SUCCESS) {
        const char *msg = "Snapshot clone operation fails due to the errors in "
            "btreeblk_end() in a database file '%s'\n";
        fdb_log(&handle_in->log_callback, status, msg,
                handle_in->file->getFileName());
    }

    return status;
}

static void _fdb_cleanup_open_err(fdb_kvs_handle *handle)
{
    bool is_btree_v2 = ver_btreev2_format(handle->file->getVersion());

    delete handle->trie;

    if (handle->config.seqtree_opt == FDB_SEQTREE_USE) {
        if (handle->kvs) {
            // multi KV instance mode
            delete handle->seqtrie;
        } else {
            if (is_btree_v2) {
                delete handle->seqtreeV2;
            } else {
                delete handle->seqtree->getKVOps();
                delete handle->seqtree;
            }
        }
    }

    if (is_btree_v2) {
        delete handle->staletreeV2;
        delete handle->bnodeMgr;
    } else {
        if (handle->staletree) {
            delete handle->staletree->getKVOps();
            delete handle->staletree;
        }
        delete handle->bhandle;
    }

    delete handle->dhandle;

    FileMgr::close(handle->file, handle->config.cleanup_cache_onclose,
                   handle->filename.c_str(), &handle->log_callback);
}

LIBFDB_API
fdb_status fdb_set_log_callback(FdbKvsHandle *handle,
                                fdb_log_callback log_callback,
                                void *ctx_data)
{
    FdbEngine *fdb_engine = FdbEngine::getInstance();
    if (fdb_engine) {
        return fdb_engine->setLogCallback(handle, log_callback, ctx_data);
    }
    return FDB_RESULT_ENGINE_NOT_INSTANTIATED;
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
    if (doc) {
        doc->seqnum = seqnum;
        if (seqnum != SEQNUM_NOT_USED) {
            doc->flags |= FDB_CUSTOM_SEQNUM; // fdb_set will now use above seqnum
        } else { // reset custom seqnum flag, fdb_set will now generate new seqnum
            doc->flags &= ~FDB_CUSTOM_SEQNUM;
        }
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

void fdb_sync_db_header(FdbKvsHandle *handle)
{
    uint64_t cur_revnum = handle->file->getHeaderRevnum();
    if (handle->cur_header_revnum != cur_revnum) {
        void *header_buf = NULL;
        size_t header_len;
        bid_t hdr_bid;
        filemgr_header_revnum_t revnum;

        header_buf = handle->file->getHeader(NULL, &header_len,
                                             &hdr_bid, NULL, &revnum);
        if (header_len > 0) {
            uint64_t header_flags, dummy64, version;
            bid_t idtree_root;
            bid_t new_seq_root;
            bid_t new_stale_root;
            char *compacted_filename;
            char *prev_filename = NULL;

            version = handle->file->getVersion();
            handle->last_hdr_bid = hdr_bid;
            handle->cur_header_revnum = revnum;

            bool is_btree_v2 = ver_btreev2_format(version);

            fdb_fetch_header(version, header_buf, &idtree_root,
                             &new_seq_root, &new_stale_root, &dummy64,
                             &dummy64, &dummy64,
                             &dummy64, &handle->last_wal_flush_hdr_bid,
                             &handle->kv_info_offset, &header_flags,
                             &compacted_filename, &prev_filename);

            if (!is_btree_v2 && handle->dirty_updates) {
                // discard all cached writable b+tree nodes
                // to avoid data inconsistency with other writers
                handle->bhandle->discardBlocks();
            }

            if (is_btree_v2) {
                BtreeNodeAddr root_addr(idtree_root);
                handle->trie->setRootAddr(root_addr);
            } else {
                handle->trie->setRootBid(idtree_root);
            }

            if (handle->config.seqtree_opt == FDB_SEQTREE_USE) {
                if (new_seq_root != handle->seqtree->getRootBid()) {
                    if (handle->config.multi_kv_instances) {
                        if (is_btree_v2) {
                            BtreeNodeAddr root_addr(new_seq_root);
                            handle->seqtrie->setRootAddr(root_addr);
                        } else {
                            handle->seqtrie->setRootBid(new_seq_root);
                        }
                    } else {
                        if (is_btree_v2) {
                            BtreeNodeAddr root_addr(new_seq_root);
                            handle->seqtreeV2->initFromAddr(root_addr);
                        } else {
                            handle->seqtree->initFromBid(handle->seqtree->getBhandle(),
                                                         handle->seqtree->getKVOps(),
                                                         handle->seqtree->getBlkSize(),
                                                         new_seq_root);
                        }
                    }
                }
            }

            if (ver_staletree_support(version)) {
                if (is_btree_v2) {
                    BtreeNodeAddr root_addr(new_stale_root);
                    handle->staletreeV2->initFromAddr(root_addr);
                } else {
                    handle->staletree->initFromBid(handle->staletree->getBhandle(),
                                                   handle->staletree->getKVOps(),
                                                   handle->staletree->getBlkSize(),
                                                   new_stale_root);
                }
            } else {
                if (is_btree_v2) {
                    handle->staletreeV2 = NULL;
                } else {
                    handle->staletree = NULL;
                }
            }

            if (prev_filename) {
                free(prev_filename);
            }

            handle->dirty_updates = 0;
            if (handle->kvs) {
                // multiple KV instance mode AND sub handle
                handle->seqnum = fdb_kvs_get_seqnum(handle->file,
                                                    handle->kvs->getKvsId());
            } else {
                // super handle OR single KV instance mode
                handle->seqnum = handle->file->getSeqnum();
            }
        } else {
            handle->last_hdr_bid = handle->file->getHeaderBid();
        }

        if (header_buf) {
            free(header_buf);
        }
    } else {
        if (handle == handle->fhandle->getRootHandle()) {
            // MB-20091: Commits use root handle that points to default kv store
            // The same default KV Store can have a different user-level handle.
            // To ensure that the root handle which will do the commit always
            // remains updated with the latest sequence number generated by the
            // user KVS Handle, we must always update the root handle's seqnum
            // even if there are no new commit headers to sync up in the file.
            handle->seqnum = handle->file->getSeqnum();
        }
    }
}

fdb_status fdb_check_file_reopen(FdbKvsHandle *handle, file_status_t *status)
{
    bool fhandle_ret;
    fdb_status fs = FDB_RESULT_SUCCESS;
    file_status_t fMgrStatus = handle->file->getFileStatus();
    // check whether the compaction is done
    if (fMgrStatus == FILE_REMOVED_PENDING) {
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
            strcpy(filename, handle->filename.c_str());

            // We don't need to maintain fhandle list for the old file
            // as there will be no more mutation on the file.
            fhandle_ret = handle->file->fhandleRemove(handle->fhandle);
            fs = FdbEngine::getInstance()->closeKVHandle(handle);
            if (fs != FDB_RESULT_SUCCESS) {
                if (fhandle_ret) {
                    handle->file->fhandleAdd(handle->fhandle);
                }
                return fs;
            }

            fs = FdbEngine::getInstance()->openFdb(handle, filename,
                                                   FDB_VFILENAME, &config);
            if (fs != FDB_RESULT_SUCCESS) {
                return fs;
            }
            handle->file->fhandleAdd(handle->fhandle);

        } else {
            handle->file->getHeader(buf, &header_len, NULL, NULL, NULL);
            fdb_fetch_header(handle->file->getVersion(), buf,
                             &trie_root_bid, &seq_root_bid, &stale_root_bid,
                             &ndocs, &ndeletes, &nlivenodes, &datasize,
                             &last_wal_flush_hdr_bid,
                             &kv_info_offset, &header_flags,
                             &new_filename, NULL);

            fhandle_ret = handle->file->fhandleRemove(handle->fhandle);
            fs = FdbEngine::getInstance()->closeKVHandle(handle);
            if (fs != FDB_RESULT_SUCCESS) {
                if (fhandle_ret) {
                    handle->file->fhandleAdd(handle->fhandle);
                }
                return fs;
            }

            fs = FdbEngine::getInstance()->openFdb(handle, new_filename,
                                                   FDB_AFILENAME, &config);
            if (fs != FDB_RESULT_SUCCESS) {
                return fs;
            }
            handle->file->fhandleAdd(handle->fhandle);
        }
    }
    if (status) {
        *status = fMgrStatus;
    }
    return fs;
}

static void _fdb_sync_dirty_root(FdbKvsHandle *handle)
{
    if (handle->shandle) {
        // snapshot doesn't update root info for both old and V2 B+tree
        return;
    }

    bid_t dirty_idtree_root = BLK_NOT_FOUND;
    bid_t dirty_seqtree_root = BLK_NOT_FOUND;

    if (ver_btreev2_format(handle->file->getVersion())) {
        // B+tree V2
        handle->file->dirtyUpdateGetRootV2(dirty_idtree_root, dirty_seqtree_root);
        _fdb_import_dirty_root(handle, dirty_idtree_root, dirty_seqtree_root);
    } else {
        // old B+tree
        struct filemgr_dirty_update_node *dirty_update;
        dirty_update = handle->file->dirtyUpdateGetLatest();
        handle->bhandle->setDirtyUpdate(dirty_update);

        if (dirty_update) {
            FileMgr::dirtyUpdateGetRoot(dirty_update, &dirty_idtree_root,
                                        &dirty_seqtree_root);
            _fdb_import_dirty_root(handle, dirty_idtree_root, dirty_seqtree_root);
            handle->bhandle->discardBlocks();
        }
    }
}

static void _fdb_release_dirty_root(FdbKvsHandle *handle)
{
    if (!ver_btreev2_format(handle->file->getVersion()) && !handle->shandle) {
        struct filemgr_dirty_update_node *dirty_update;
        dirty_update = handle->bhandle->getDirtyUpdate();
        if (dirty_update) {
            FileMgr::dirtyUpdateCloseNode(dirty_update);
            handle->bhandle->clearDirtyUpdate();
        }
    }
}

LIBFDB_API
fdb_status fdb_get(FdbKvsHandle *handle, fdb_doc *doc)
{
    FdbEngine *fdb_engine = FdbEngine::getInstance();
    if (fdb_engine) {
        return fdb_engine->get(handle, doc, /*metaOnly*/false);
    }
    return FDB_RESULT_ENGINE_NOT_INSTANTIATED;
}

// search document metadata using key
LIBFDB_API
fdb_status fdb_get_metaonly(FdbKvsHandle *handle, fdb_doc *doc)
{
    FdbEngine *fdb_engine = FdbEngine::getInstance();
    if (fdb_engine) {
        return fdb_engine->get(handle, doc, /*metaOnly*/true);
    }
    return FDB_RESULT_ENGINE_NOT_INSTANTIATED;
}

// search document using sequence number
LIBFDB_API
fdb_status fdb_get_byseq(FdbKvsHandle *handle, fdb_doc *doc)
{
    FdbEngine *fdb_engine = FdbEngine::getInstance();
    if (fdb_engine) {
        return fdb_engine->getBySeq(handle, doc, /*metaOnly*/false);
    }
    return FDB_RESULT_ENGINE_NOT_INSTANTIATED;
}

// search document metadata using sequence number
LIBFDB_API
fdb_status fdb_get_metaonly_byseq(FdbKvsHandle *handle, fdb_doc *doc)
{
    FdbEngine *fdb_engine = FdbEngine::getInstance();
    if (fdb_engine) {
        return fdb_engine->getBySeq(handle, doc, /*metaOnly*/true);
    }
    return FDB_RESULT_ENGINE_NOT_INSTANTIATED;
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

INLINE void _remove_kv_id(FdbKvsHandle *handle, struct docio_object *doc)
{
    size_t size_chunk = handle->config.chunksize;
    doc->length.keylen -= size_chunk;
    memmove(doc->key, (uint8_t*)doc->key + size_chunk, doc->length.keylen);
}

// Retrieve a doc's metadata and body with a given doc offset in the database file.
LIBFDB_API
fdb_status fdb_get_byoffset(FdbKvsHandle *handle, fdb_doc *doc)
{
    FdbEngine *fdb_engine = FdbEngine::getInstance();
    if (fdb_engine) {
        return fdb_engine->getByOffset(handle, doc);
    }
    return FDB_RESULT_ENGINE_NOT_INSTANTIATED;
}

INLINE uint64_t _fdb_get_wal_threshold(FdbKvsHandle *handle)
{
    return handle->config.wal_threshold;
}

LIBFDB_API
fdb_status fdb_set(FdbKvsHandle *handle, fdb_doc *doc)
{
    FdbEngine *fdb_engine = FdbEngine::getInstance();
    if (fdb_engine) {
        return fdb_engine->set(handle, doc);
    }
    return FDB_RESULT_ENGINE_NOT_INSTANTIATED;
}

LIBFDB_API
fdb_status fdb_del(FdbKvsHandle *handle, fdb_doc *doc)
{
    FdbEngine *fdb_engine = FdbEngine::getInstance();
    if (fdb_engine) {
        return fdb_engine->del(handle, doc);
    }
    return FDB_RESULT_ENGINE_NOT_INSTANTIATED;
}

static uint64_t _fdb_export_header_flags(FdbKvsHandle *handle)
{
    uint64_t rv = 0;
    if (handle->config.seqtree_opt == FDB_SEQTREE_USE) {
        // seq tree is used
        rv |= FDB_FLAG_SEQTREE_USE;
    }
    if (handle->fhandle->getFlags() & FHANDLE_ROOT_INITIALIZED) {
        // the default KVS is once opened
        rv |= FDB_FLAG_ROOT_INITIALIZED;
    }
    if (handle->fhandle->getFlags() & FHANDLE_ROOT_CUSTOM_CMP) {
        // the default KVS is based on custom key order
        rv |= FDB_FLAG_ROOT_CUSTOM_CMP;
    }
    return rv;
}

uint64_t fdb_set_file_header(FdbKvsHandle *handle)
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
        FileMgr::destroyFile() in filemgr.cc
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
    FileMgr *cur_file;
    KvsStat stat;

    cur_file = handle->file;
    bool is_btree_v2 = ver_btreev2_format(cur_file->getVersion());

    // hb+trie or idtree root bid
    uint64_t _root_address;
    if (is_btree_v2) {
        _root_address = handle->trie->getRootAddr().offset;
    } else {
        _root_address = handle->trie->getRootBid();
    }
    _edn_safe_64 = _endian_encode(_root_address);
    seq_memcpy(buf + offset, &_edn_safe_64, sizeof(_edn_safe_64), offset);

    if (handle->config.seqtree_opt == FDB_SEQTREE_USE) {
        if (handle->kvs) {
            // multi KVS mode: hb+trie root bid
            if (is_btree_v2) {
                _root_address = handle->seqtrie->getRootAddr().offset;
            } else {
                _root_address = handle->seqtrie->getRootBid();
            }
        } else {
            // single KVS mode: b+tree root bid
            if (is_btree_v2) {
                _root_address = handle->seqtreeV2->getRootAddr().offset;
            } else {
                _root_address = handle->seqtree->getRootBid();
            }
        }
        _edn_safe_64 = _endian_encode(_root_address);
        seq_memcpy(buf + offset, &_edn_safe_64, sizeof(_edn_safe_64), offset);
    } else {
        memset(buf + offset, 0xff, sizeof(uint64_t));
        offset += sizeof(uint64_t);
    }

    // stale block tree root bid (MAGIC_002)
    if (ver_staletree_support(handle->file->getVersion())) {
        if (is_btree_v2) {
            _root_address = handle->staletreeV2->getRootAddr().offset;
        } else {
            _root_address = handle->staletree->getRootBid();
        }
        _edn_safe_64 = _endian_encode(_root_address);
        seq_memcpy(buf + offset, &_edn_safe_64, sizeof(_edn_safe_64), offset);
    }

    // get stat
    cur_file->getKvsStatOps()->statGet(0, &stat);

    // # docs
    _edn_safe_64 = _endian_encode(stat.ndocs);
    seq_memcpy(buf + offset, &_edn_safe_64, sizeof(_edn_safe_64), offset);

    // # deleted docs (since MAGIC_001)
    if (ver_is_atleast_magic_001(handle->file->getVersion())) {
        _edn_safe_64 = _endian_encode(stat.ndeletes);
        seq_memcpy(buf + offset, &_edn_safe_64, sizeof(_edn_safe_64), offset);
    }

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
    if (!handle->file->getNewFileName().empty()) {
        new_filename_len = handle->file->getNewFileName().length() + 1;
    }

    _edn_safe_16 = _endian_encode(new_filename_len);
    seq_memcpy(buf + offset, &_edn_safe_16, sizeof(new_filename_len), offset);

    // size of old filename before compaction
    if (!handle->file->getOldFileName().empty()) {
        old_filename_len = handle->file->getOldFileName().length() + 1;
    }
    _edn_safe_16 = _endian_encode(old_filename_len);
    seq_memcpy(buf + offset, &_edn_safe_16, sizeof(old_filename_len), offset);

    if (new_filename_len) {
        seq_memcpy(buf + offset, handle->file->getNewFileName().data(),
                   new_filename_len, offset);
    }

    if (old_filename_len) {
        seq_memcpy(buf + offset, handle->file->getOldFileName().c_str(),
                   old_filename_len, offset);
    }

    // crc32
    crc = get_checksum(buf, offset, handle->file->getCrcMode());
    crc = _endian_encode(crc);
    seq_memcpy(buf + offset, &crc, sizeof(crc), offset);

    return handle->file->updateHeader(buf, offset);
}

static fdb_status _fdb_append_commit_mark(void *voidhandle, uint64_t offset)
{
    uint64_t marker_offset;
    FdbKvsHandle *handle = reinterpret_cast<FdbKvsHandle *>(voidhandle);
    DocioHandle *dhandle;

    dhandle = handle->dhandle;
    marker_offset = dhandle->appendCommitMark_Docio(offset);
    if (marker_offset == BLK_NOT_FOUND) {
        return FDB_RESULT_WRITE_FAIL;
    }
    // Note: Since transaction commit marker is used only for crash recovery
    // (or WAL reconstruction), we can mark it as stale immediately. Stale regions
    // by those markers will be inserted into stale-tree at the next WAL flushing
    // commit, thus will be reclaimed when the corresponding commit header
    // becomes unreachable. After that, those commit markers becomes unnecessary
    // for both crash recovery and WAL restore.
    handle->file->markDocStale(marker_offset, DOCIO_COMMIT_MARK_SIZE);
    return FDB_RESULT_SUCCESS;
}

LIBFDB_API
fdb_status fdb_commit(fdb_file_handle *fhandle, fdb_commit_opt_t opt)
{
    FdbEngine *fdb_engine = FdbEngine::getInstance();
    if (fdb_engine) {
        return fdb_engine->commit(fhandle, opt);
    }
    return FDB_RESULT_ENGINE_NOT_INSTANTIATED;
}

static fdb_status _fdb_reset(FdbKvsHandle *handle, FdbKvsHandle *handle_in)
{
    FileMgrConfig fconfig;
    bool useBtreeV2 = ver_btreev2_format(handle_in->file->getVersion());
    KvsStat kvs_stat;
    filemgr_open_result result;
    BtreeNodeAddr rootAddr; // Initialized to BLK_NOT_FOUND by constructor
    // Copy the incoming handle into the handle that is being reset
    *handle = *handle_in;
    // Now selectively set some of the re-initialized structures to nullptr..
    handle->resetIOHandles();

    handle->initBusy();

    handle->filename = handle_in->filename;

    handle->dhandle = new DocioHandle(handle->file,
                                      handle->config.compress_document_body,
                                      &handle->log_callback);
    if (!handle->dhandle) { // LCOV_EXCL_START
        return handle->freeIOHandles(useBtreeV2);
    } // LCOV_EXCL_STOP

    if (useBtreeV2) {
        handle->bnodeMgr = new BnodeMgr();
        if (!handle->bnodeMgr) { // LCOV_EXCL_START
            return FDB_RESULT_ALLOC_FAIL;
        } // LCOV_EXCL_STOP
        handle->bnodeMgr->setFile(handle->file);
        handle->bnodeMgr->setLogCallback(&handle->log_callback);

        handle->trie = new HBTrie(handle_in->trie->getChunkSize(),
                                  handle_in->file->getBlockSize(), rootAddr,
                                  handle->bnodeMgr, handle->file);
        if (!handle->trie) { // LCOV_EXCL_START
            return handle->freeIOHandles(useBtreeV2);
        } // LCOV_EXCL_STOP
        if (handle->kvs) {
            handle->trie->setCmpFuncCB(FdbEngine::getCmpFuncCB);
        }
    } else {
        // create new hb-trie and related handles
        handle->bhandle = new BTreeBlkHandle(handle_in->file,
                                             handle_in->file->getBlockSize());
        if (!handle->bhandle) { // LCOV_EXCL_START
            return handle->freeIOHandles(useBtreeV2);
        } // LCOV_EXCL_STOP
        handle->bhandle->setLogCallback(&handle->log_callback);

        handle->trie = new HBTrie(handle_in->trie->getChunkSize(),
                                  handle_in->trie->getValueLen(),
                                  handle_in->file->getBlockSize(),BLK_NOT_FOUND,
                                  handle->bhandle, (void*)handle->dhandle,
                                  _fdb_readkey_wrap);

        if (!handle->trie) { // LCOV_EXCL_START
            return handle->freeIOHandles(useBtreeV2);
        } // LCOV_EXCL_STOP
        handle->trie->setLeafCmp(_fdb_custom_cmp_wrap);
        handle->trie->setLeafHeightLimit(handle_in->trie->getLeafHeightLimit());
        if (handle->kvs) {
            handle->trie->setMapFunction(handle_in->trie->getMapFunction());
        }
    }

    if (handle_in->config.seqtree_opt == FDB_SEQTREE_USE) {
        // if we use sequence number tree
        if (handle->kvs) { // multi KV instance mode
            if (useBtreeV2) { // use new BtreeV2 format..
                handle->seqtrie = new HBTrie(sizeof(fdb_kvs_id_t),
                                             handle->file->getBlockSize(),
                                             rootAddr, handle->bnodeMgr,
                                             handle->file);
                if (!handle->seqtrie) { // LCOV_EXCL_START
                    return handle->freeIOHandles(useBtreeV2);
                } // LCOV_EXCL_STOP
            } else { // initialized trie with old format of Btree ..
                handle->seqtrie = new HBTrie(sizeof(fdb_kvs_id_t),
                                             OFFSET_SIZE,
                                             handle->file->getBlockSize(),
                                             BLK_NOT_FOUND, handle->bhandle,
                                             (void *)handle->dhandle,
                                             _fdb_readseq_wrap);
                if (!handle->seqtrie) { // LCOV_EXCL_START
                    return handle->freeIOHandles(useBtreeV2);
                } // LCOV_EXCL_STOP
            }
        } else {// single KV instance mode .. normal B+tree
            if (useBtreeV2) { // use new BtreeV2 format..
                handle->seqtreeV2 = new BtreeV2();
                if (!handle->seqtreeV2) { // LCOV_EXCL_START
                    return handle->freeIOHandles(useBtreeV2);
                } // LCOV_EXCL_STOP
                handle->seqtreeV2->setBMgr(handle->bnodeMgr);
                handle->seqtreeV2->init();
            } else { // use older style B+Tree..
                BTreeKVOps *seq_kv_ops = new FixedKVOps(8, 8,
                            _cmp_uint64_t_endian_safe);
                if (!seq_kv_ops) { // LCOV_EXCL_START
                    return handle->freeIOHandles(useBtreeV2);
                } // LCOV_EXCL_STOP
                BTree *old_seqtree = handle_in->seqtree;
                handle->seqtree = new BTree(handle->bhandle, seq_kv_ops,
                                            old_seqtree->getBlkSize(),
                                            old_seqtree->getKSize(),
                                            old_seqtree->getVSize(),
                                            0x0, NULL);
                if (!handle->seqtree) { // LCOV_EXCL_START
                    delete seq_kv_ops;
                    return handle->freeIOHandles(useBtreeV2);
                } // LCOV_EXCL_STOP
            }
        } // end of single kv instance mode check
    }

    if (ver_staletree_support(handle_in->file->getVersion())) {
        if (useBtreeV2) {
            handle->staletreeV2 = new BtreeV2();
            if (!handle->staletreeV2) { // LCOV_EXCL_START
                return handle->freeIOHandles(useBtreeV2);
            } // LCOV_EXCL_STOP
            handle->staletreeV2->setBMgr(handle->bnodeMgr);
            handle->staletreeV2->init();
        } else {
            BTreeKVOps *stale_kv_ops = new FixedKVOps(8, 8, _cmp_uint64_t_endian_safe);

            if (!stale_kv_ops) { // LCOV_EXCL_START
                return handle->freeIOHandles(useBtreeV2);
            } // LCOV_EXCL_STOP
            BTree *old_staletree = handle_in->staletree;
            handle->staletree = new BTree(handle->bhandle, stale_kv_ops,
                                          old_staletree->getBlkSize(),
                                          old_staletree->getKSize(),
                                          old_staletree->getVSize(),
                                          0x0, NULL);
            if (!handle->staletree) {
                delete stale_kv_ops;
                return handle->freeIOHandles(useBtreeV2);
            }
        }
    }

    // set filemgr configuration
    FdbEngine::initFileConfig(&handle->config, &fconfig);
    fconfig.addOptions(FILEMGR_CREATE);

    // open same file again, so the root kv handle can be redirected to this
    result = FileMgr::open(handle->filename,
                           handle->fileops,
                           &fconfig,
                           &handle->log_callback);
    if (result.rv != FDB_RESULT_SUCCESS) { // LCOV_EXCL_START
        handle->file->mutexUnlock();
        handle->freeIOHandles(useBtreeV2);
        return (fdb_status) result.rv;
    } // LCOV_EXCL_STOP

    // Shutdown WAL
    handle->file->getWal()->shutdown_Wal(&handle->log_callback);

    // reset in-memory stats and values
    handle->seqnum = 0;
    handle->file->getKvsStatOps()->statSet(handle->kvs ? handle->kvs->getKvsId() : 0,
                                     kvs_stat);

    return FDB_RESULT_SUCCESS;
}

LIBFDB_API
fdb_status fdb_compact(fdb_file_handle *fhandle,
                       const char *new_filename)
{
    FdbEngine *fdb_engine = FdbEngine::getInstance();
    if (fdb_engine) {
        return fdb_engine->compact(fhandle, new_filename, BLK_NOT_FOUND, false, NULL);
    }
    return FDB_RESULT_ENGINE_NOT_INSTANTIATED;
}

LIBFDB_API
fdb_status fdb_compact_with_cow(fdb_file_handle *fhandle,
                                const char *new_filename)
{
    FdbEngine *fdb_engine = FdbEngine::getInstance();
    if (fdb_engine) {
        return fdb_engine->compact(fhandle, new_filename, BLK_NOT_FOUND, true, NULL);
    }
    return FDB_RESULT_ENGINE_NOT_INSTANTIATED;
}

LIBFDB_API
fdb_status fdb_compact_upto(fdb_file_handle *fhandle,
                            const char *new_filename,
                            fdb_snapshot_marker_t marker)
{
    FdbEngine *fdb_engine = FdbEngine::getInstance();
    if (fdb_engine) {
        return fdb_engine->compact(fhandle, new_filename, marker, false, NULL);
    }
    return FDB_RESULT_ENGINE_NOT_INSTANTIATED;
}

LIBFDB_API
fdb_status fdb_compact_upto_with_cow(fdb_file_handle *fhandle,
                                  const char *new_filename,
                                  fdb_snapshot_marker_t marker)
{
    FdbEngine *fdb_engine = FdbEngine::getInstance();
    if (fdb_engine) {
        return fdb_engine->compact(fhandle, new_filename, marker, true, NULL);
    }
    return FDB_RESULT_ENGINE_NOT_INSTANTIATED;
}

LIBFDB_API
fdb_status fdb_rekey(fdb_file_handle *fhandle,
                     fdb_encryption_key new_key)
{
    FdbEngine *fdb_engine = FdbEngine::getInstance();
    if (fdb_engine) {
        return fdb_engine->reKey(fhandle, new_key);
    }
    return FDB_RESULT_ENGINE_NOT_INSTANTIATED;
}

LIBFDB_API
fdb_status fdb_switch_compaction_mode(fdb_file_handle *fhandle,
                                      fdb_compaction_mode_t mode,
                                      size_t new_threshold)
{
    FdbEngine *fdb_engine = FdbEngine::getInstance();
    if (fdb_engine) {
        return fdb_engine->switchCompactionMode(fhandle, mode, new_threshold);
    }
    return FDB_RESULT_ENGINE_NOT_INSTANTIATED;
}

LIBFDB_API
fdb_status fdb_set_daemon_compaction_interval(fdb_file_handle *fhandle,
                                              size_t interval)
{
    FdbEngine *fdb_engine = FdbEngine::getInstance();
    if (fdb_engine) {
        return fdb_engine->setDaemonCompactionInterval(fhandle, interval);
    }
    return FDB_RESULT_ENGINE_NOT_INSTANTIATED;
}

LIBFDB_API
fdb_status fdb_close(fdb_file_handle *fhandle)
{
    FdbEngine *fdb_engine = FdbEngine::getInstance();
    if (fdb_engine) {
        return fdb_engine->closeFile(fhandle);
    }
    return FDB_RESULT_ENGINE_NOT_INSTANTIATED;
}

LIBFDB_API
fdb_status fdb_destroy(const char *fname,
                       fdb_config *fdbconfig)
{
    return FdbEngine::destroyFile(fname, fdbconfig);
}

LIBFDB_API
fdb_status fdb_get_latency_stats(fdb_file_handle *fhandle,
                                 fdb_latency_stat *stats,
                                 fdb_latency_stat_type type)
{
    FdbEngine *fdb_engine = FdbEngine::getInstance();
    if (fdb_engine) {
        return fdb_engine->getLatencyStats(fhandle, stats, type);
    }
    return FDB_RESULT_ENGINE_NOT_INSTANTIATED;
}

LIBFDB_API
fdb_status fdb_get_latency_histogram(fdb_file_handle *fhandle,
                                     char **stats,
                                     size_t *stats_length,
                                     fdb_latency_stat_type type)
{
    FdbEngine *fdb_engine = FdbEngine::getInstance();
    if (fdb_engine) {
        return fdb_engine->getLatencyHistogram(fhandle, stats, stats_length, type);
    }
    return FDB_RESULT_ENGINE_NOT_INSTANTIATED;
}

LIBFDB_API
const char *fdb_latency_stat_name(fdb_latency_stat_type type)
{
    return FdbEngine::getLatencyStatName(type);
}

// roughly estimate the space occupied db handle HANDLE
LIBFDB_API
size_t fdb_estimate_space_used(fdb_file_handle *fhandle)
{
    FdbEngine *fdb_engine = FdbEngine::getInstance();
    if (fdb_engine) {
        return fdb_engine->estimateSpaceUsed(fhandle);
    }
    return 0;
}

LIBFDB_API
size_t fdb_estimate_space_used_from(fdb_file_handle *fhandle,
                                    fdb_snapshot_marker_t marker)
{
    FdbEngine *fdb_engine = FdbEngine::getInstance();
    if (fdb_engine) {
        return fdb_engine->estimateSpaceUsedFrom(fhandle, marker);
    }
    return 0;
}

LIBFDB_API
fdb_status fdb_get_file_info(fdb_file_handle *fhandle, fdb_file_info *info)
{
    FdbEngine *fdb_engine = FdbEngine::getInstance();
    if (fdb_engine) {
        return fdb_engine->getFileInfo(fhandle, info);
    }
    return FDB_RESULT_ENGINE_NOT_INSTANTIATED;
}

LIBFDB_API
fdb_status fdb_get_all_snap_markers(fdb_file_handle *fhandle,
                                    fdb_snapshot_info_t **markers_out,
                                    uint64_t *num_markers)
{
    FdbEngine *fdb_engine = FdbEngine::getInstance();
    if (fdb_engine) {
        return fdb_engine->getAllSnapMarkers(fhandle, markers_out, num_markers);
    }
    return FDB_RESULT_ENGINE_NOT_INSTANTIATED;
}

LIBFDB_API
fdb_status fdb_free_snap_markers(fdb_snapshot_info_t *markers, uint64_t size) {
    FdbEngine *fdb_engine = FdbEngine::getInstance();
    if (fdb_engine) {
        return fdb_engine->freeSnapMarkers(markers, size);
    }
    return FDB_RESULT_ENGINE_NOT_INSTANTIATED;
}

LIBFDB_API
size_t fdb_get_buffer_cache_used() {
    FdbEngine *fdb_engine = FdbEngine::getInstance();
    if (fdb_engine) {
        return fdb_engine->getBufferCacheUsed();
    }
    return 0;
}

LIBFDB_API
fdb_status fdb_cancel_compaction(fdb_file_handle *fhandle)
{
    FdbEngine *fdb_engine = FdbEngine::getInstance();
    if (fdb_engine) {
        return fdb_engine->cancelCompaction(fhandle);
    }
    return FDB_RESULT_ENGINE_NOT_INSTANTIATED;
}

LIBFDB_API
fdb_status fdb_set_block_reusing_params(fdb_file_handle *fhandle,
                                        size_t block_reusing_threshold,
                                        size_t num_keeping_headers)
{
    FdbEngine *fdb_engine = FdbEngine::getInstance();
    if (fdb_engine) {
        return fdb_engine->setBlockReusingParams(fhandle, block_reusing_threshold,
                                                 num_keeping_headers);
    }
    return FDB_RESULT_ENGINE_NOT_INSTANTIATED;
}

LIBFDB_API
fdb_status fdb_shutdown()
{
    return FdbEngine::destroyInstance();
}

LIBFDB_API
const char* fdb_get_lib_version()
{
    return FdbEngine::getLibVersion();
}

LIBFDB_API
const char* fdb_get_file_version(fdb_file_handle *fhandle)
{
    FdbEngine *fdb_engine = FdbEngine::getInstance();
    if (fdb_engine) {
        return fdb_engine->getFileVersion(fhandle);
    }
    return nullptr;
}

FdbEngine::FdbEngine(const fdb_config &config) {
   // Initialize breakpad
   _dbg_handle_crashes(config.breakpad_minidump_dir);
}

fdb_status FdbEngine::init(fdb_config *config) {
    FdbEngine* tmp = instance.load();

    if (tmp == nullptr) {
        // Ensure two threads don't both create an instance.
        LockHolder lock(instanceMutex);
        tmp = instance.load();
        if (tmp == nullptr) {
            fdb_config _config;
            // Check if all the configs are valid
            if (config) {
                if (FdbEngine::validateFdbConfig(*config)) {
                    _config = *config;
                } else {
                    return FDB_RESULT_INVALID_CONFIG;
                }
            } else {
                _config = get_default_config();
            }

#if !defined(_ANDROID_) && !defined(__ANDROID__)
            // Some Android devices (e.g., Nexus 6) return incorrect RAM size.
            // We temporarily disable validity checking of block cache size
            // on Android platform at this time.
            double ram_size = (double) get_memory_size();
            if (ram_size * BCACHE_MEMORY_THRESHOLD < (double) _config.buffercache_size) {
                return FDB_RESULT_TOO_BIG_BUFFER_CACHE;
            }
#endif

            compactor_config c_config;
            bgflusher_config bgf_config;
            threadpool_config thrd_config;
            FileMgrConfig f_config;

            // Initialize file manager configs and global block cache
            f_config.setBlockSize(_config.blocksize);
            f_config.setNcacheBlock(_config.buffercache_size / _config.blocksize);
            f_config.setSeqtreeOpt(_config.seqtree_opt);
            FileMgr::init(&f_config);
            FileMgr::setLazyFileDeletion(true,
                                         compactor_register_file_removing,
                                         compactor_is_file_removed);
            if (ver_superblock_support(ver_get_latest_magic())) {
                FileMgr::setSbInitializer(standard_sb_init);
                Superblock::initBmpMask();
            }

            // Initialize compaction daemon manager
            c_config.sleep_duration = _config.compactor_sleep_duration;
            c_config.num_threads = _config.num_compactor_threads;
            CompactionManager::init(c_config);
            // Initialize background flusher daemon
            // Temporarily disable background flushers until blockcache contention
            // issue is resolved.
            bgf_config.num_threads = 0; //_config.num_bgflusher_threads;
            BgFlusher::createBgFlusher(&bgf_config);
            // Initialize HBtrie's memory pool
            HBTrie::initMemoryPool(get_num_cores(), _config.buffercache_size);

            thrd_config.num_threads = _config.num_background_threads;
            ExecutorPool::initExPool(thrd_config);
            tmp = new FdbEngine(_config);
            instance.store(tmp);
        }
    }
    return FDB_RESULT_SUCCESS;
}

FdbEngine* FdbEngine::getInstance() {
    return instance.load();
}

FdbEngine::~FdbEngine() {
#ifdef _MEMPOOL
    mempool_shutdown();
#endif
    _dbg_destroy_altstack();
}

fdb_status FdbEngine::destroyInstance() {
    LockHolder lock(instanceMutex);
    FdbEngine* tmp = instance.load();
    if (tmp != nullptr) {
        if (tmp->getOpenInProgCounter()) {
            return FDB_RESULT_FILE_IS_BUSY;
        }
        CompactionManager::destroyInstance();
        BgFlusher::destroyBgFlusher();
        fdb_status ret = FileMgr::shutdown();
        if (ret == FDB_RESULT_SUCCESS) {
            if (!ExecutorPool::shutdown()) {
                // Open taskables
                return FDB_RESULT_FILE_IS_BUSY;
            }
            // Shutdown HBtrie's memory pool
            HBTrie::shutdownMemoryPool();
            delete tmp;
            instance = nullptr;
        } else {
            return ret;
        }
    }
    return FDB_RESULT_SUCCESS;
}

void FdbEngine::initFileConfig(const fdb_config *config,
                               FileMgrConfig *fconfig) {
    fconfig->setBlockSize(config->blocksize);
    fconfig->setNcacheBlock(config->buffercache_size / config->blocksize);
    fconfig->setChunkSize(config->chunksize);

    fconfig->addOptions(0x0);
    fconfig->setSeqtreeOpt(config->seqtree_opt);

    if (config->flags & FDB_OPEN_FLAG_CREATE) {
        fconfig->addOptions(FILEMGR_CREATE);
    }
    if (config->flags & FDB_OPEN_FLAG_RDONLY) {
        fconfig->addOptions(FILEMGR_READONLY);
    }
    if (!(config->durability_opt & FDB_DRB_ASYNC)) {
        fconfig->addOptions(FILEMGR_SYNC);
    }

    fconfig->setFlag(0x0);
    if ((config->durability_opt & FDB_DRB_ODIRECT) &&
        config->buffercache_size) {
        fconfig->addFlag(_ARCH_O_DIRECT);
    }

    fconfig->setPrefetchDuration(config->prefetch_duration);
    fconfig->setNumWalShards(config->num_wal_partitions);
    fconfig->setNumBcacheShards(config->num_bcache_partitions);
    fconfig->setEncryptionKey(config->encryption_key);
    fconfig->setBlockReusingThreshold(config->block_reusing_threshold);
    fconfig->setNumKeepingHeaders(config->num_keeping_headers);
}

fdb_status FdbEngine::openFile(FdbFileHandle **ptr_fhandle,
                               const char *filename,
                               fdb_config &config) {
#ifdef _MEMPOOL
    mempool_init();
#endif

    FdbFileHandle *fhandle;
    FdbKvsHandle *handle;
    LATENCY_STAT_START();

    handle = new FdbKvsHandle();
    if (!handle) { // LCOV_EXCL_START
        return FDB_RESULT_ALLOC_FAIL;
    } // LCOV_EXCL_STOP

    fhandle = new FdbFileHandle(handle);
    if (!fhandle) { // LCOV_EXCL_START
        delete handle;
        return FDB_RESULT_ALLOC_FAIL;
    } // LCOV_EXCL_STOP

    handle->initBusy();
    handle->shandle = NULL;
    handle->kvs_config = getDefaultKvsConfig();

    fdb_status fs = openFdb(handle, filename, FDB_VFILENAME, &config);
    if (fs == FDB_RESULT_SUCCESS) {
        *ptr_fhandle = fhandle;
        handle->file->fhandleAdd(fhandle);
        LATENCY_STAT_END(handle->file, FDB_LATENCY_OPEN);
    } else {
        *ptr_fhandle = NULL;
        delete handle;
        delete fhandle;
    }
    return fs;
}

fdb_status FdbEngine::openFileWithCustomCmp(FdbFileHandle **ptr_fhandle,
                                            const char *filename,
                                            fdb_config &config,
                                            size_t num_functions,
                                            char **kvs_names,
                                            fdb_custom_cmp_variable *functions) {
#ifdef _MEMPOOL
    mempool_init();
#endif

    FdbFileHandle *fhandle;
    FdbKvsHandle *handle;

    if (config.multi_kv_instances == false) {
        // single KV instance mode does not support customized cmp function
        return FDB_RESULT_INVALID_CONFIG;
    }

    handle = new FdbKvsHandle();
    if (!handle) { // LCOV_EXCL_START
        return FDB_RESULT_ALLOC_FAIL;
    } // LCOV_EXCL_STOP

    fhandle = new FdbFileHandle(handle);
    if (!fhandle) { // LCOV_EXCL_START
        delete handle;
        return FDB_RESULT_ALLOC_FAIL;
    } // LCOV_EXCL_STOP

    handle->initBusy();
    handle->shandle = NULL;
    handle->kvs_config = getDefaultKvsConfig();

    // insert kvs_names and functions into fhandle's list
    fhandle->setCmpFunctionList(num_functions, kvs_names, functions);

    fdb_status fs = openFdb(handle, filename, FDB_VFILENAME, &config);
    if (fs == FDB_RESULT_SUCCESS) {
        *ptr_fhandle = fhandle;
        handle->file->fhandleAdd(fhandle);
    } else {
        *ptr_fhandle = NULL;
        delete handle;
        delete fhandle;
    }
    return fs;
}

fdb_status FdbEngine::openFdb(FdbKvsHandle *handle,
                              const char *filename,
                              fdb_filename_mode_t filename_mode,
                              const fdb_config *config)
{
    FileMgrConfig fconfig;
    KvsStat stat, empty_stat;
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
    bool locked = false;

    uint64_t nlivenodes = 0;
    bid_t hdr_bid = 0; // initialize to zero for in-memory snapshot
    bid_t last_hdr_bid;
    std::string filename_str(filename);
    std::string actual_filename;
    std::string virtual_filename;
    std::string target_filename;
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
        !CompactionManager::getInstance()->isValidCompactionMode(filename_str,
                                                                 *config)) {
        return FDB_RESULT_INVALID_COMPACTION_MODE;
    }

    FdbEngine::initFileConfig(config, &fconfig);

    if (filename_mode == FDB_VFILENAME) {
        actual_filename =
            CompactionManager::getInstance()->getActualFileName(filename_str,
                                                                config->compaction_mode,
                                                                &handle->log_callback);
    } else {
        actual_filename = filename_str;
    }

    if ( config->compaction_mode == FDB_COMPACTION_MANUAL ||
         (config->compaction_mode == FDB_COMPACTION_AUTO   &&
          filename_mode == FDB_VFILENAME) ) {
        // 1) manual compaction mode, OR
        // 2) auto compaction mode + 'filename' is virtual filename
        // -> copy 'filename'
        target_filename = filename_str;
    } else {
        // otherwise (auto compaction mode + 'filename' is actual filename)
        // -> copy 'virtual_filename'
        virtual_filename =
            CompactionManager::getInstance()->getVirtualFileName(filename_str);
        target_filename = virtual_filename;
    }

    // If the user is requesting legacy CRC pass that down to filemgr
    if(config->flags & FDB_OPEN_WITH_LEGACY_CRC) {
        fconfig.addOptions(FILEMGR_CREATE_CRC32);
    }

    if (config->custom_file_ops) {
        handle->fileops = config->custom_file_ops;
    } else {
        handle->fileops = get_filemgr_ops();
    }
    filemgr_open_result result = FileMgr::open(actual_filename,
                                               handle->fileops,
                                               &fconfig, &handle->log_callback);
    if (result.rv != FDB_RESULT_SUCCESS) {
        return (fdb_status) result.rv;
    }
    handle->file = result.file;

    if (config->compaction_mode == FDB_COMPACTION_MANUAL &&
        strcmp(filename, actual_filename.c_str())) {
        // It is in-place compacted file if
        // 1) compaction mode is manual, and
        // 2) actual filename is different to the filename given by user.
        // In this case, set the in-place compaction flag.
        handle->file->setInPlaceCompaction(true);
    }
    if (handle->file->isInPlaceCompactionSet()) {
        // This file was in-place compacted.
        // set 'handle->filename' to the original filename to trigger file renaming
        virtual_filename =
            CompactionManager::getInstance()->getVirtualFileName(filename_str);
        target_filename = virtual_filename;
    }

    handle->filename = target_filename;

    // If cloning from a snapshot handle, fdb_snapshot_open would have already
    // set handle->last_hdr_bid to the block id of required header, so rewind..
    last_hdr_bid = handle->last_hdr_bid.load(std::memory_order_relaxed);
    if (handle->shandle && last_hdr_bid) {
        status = handle->file->fetchHeader(last_hdr_bid,
                                           header_buf, &header_len, &seqnum,
                                           &latest_header_revnum, &deltasize,
                                           &version, NULL,
                                           &handle->log_callback);
        if (status != FDB_RESULT_SUCCESS) {
            FileMgr::close(handle->file, false, NULL,
                           &handle->log_callback);
            return status;
        }
    } else { // Normal open
        handle->file->getHeader(header_buf, &header_len,
                                &last_hdr_bid, &seqnum,
                                &latest_header_revnum);
        handle->last_hdr_bid.store(last_hdr_bid, std::memory_order_relaxed);
        version = handle->file->getVersion();
    }

    // initialize the docio handle so kv headers may be read
    handle->dhandle = new DocioHandle(handle->file, config->compress_document_body,
                                      &handle->log_callback);

    // fetch previous superblock bitmap info if exists
    // (this should be done after 'handle->dhandle' is initialized)
    SuperblockBase *sb = handle->file->getSb();
    if (sb) {
        status = sb->readBmpDoc(handle);
        if (status != FDB_RESULT_SUCCESS) {
            delete handle->dhandle;
            FileMgr::close(handle->file, false, NULL,
                           &handle->log_callback);
            return status;
        }
    }


    do {
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
            if (handle->kvs && handle->kvs->getKvsId() > 0) {
                if (kv_info_offset != BLK_NOT_FOUND) {
                    if (!handle->file->getKVHeader()) {
                        KvsHeader *kv_header;
                        _fdb_kvs_header_create(&kv_header);
                        // KV header already exists but not loaded .. read & import
                        fdb_kvs_header_read(kv_header, handle->dhandle,
                                            kv_info_offset, version, false);
                        if (!handle->file->setKVHeader(kv_header,
                                                       fdb_kvs_header_free)) {
                            _fdb_kvs_header_free(kv_header);
                        }
                    }
                    seqnum = _fdb_kvs_get_seqnum(handle->file->getKVHeader_UNLOCKED(),
                                                 handle->kvs->getKvsId());
                } else { // no kv_info offset, ok to set seqnum to zero
                    seqnum = 0;
                }
            }
            // other flags
            if (header_flags & FDB_FLAG_ROOT_INITIALIZED) {
                handle->fhandle->setFlags(handle->fhandle->getFlags() |
                                          FHANDLE_ROOT_INITIALIZED);
            }
            if (header_flags & FDB_FLAG_ROOT_CUSTOM_CMP) {
                handle->fhandle->setFlags(handle->fhandle->getFlags() |
                                          FHANDLE_ROOT_CUSTOM_CMP);
            }
            // use existing setting for multi KV instance mode
            if (kv_info_offset == BLK_NOT_FOUND) {
                multi_kv_instances = false;
            } else {
                multi_kv_instances = true;
            }
        }

        if (!header_len && stale_root_bid == BLK_NOT_FOUND) {
            // This only happens on the first open (creation) call of a new DB file.
            // (snapshot_open cannot get into this cluase.)
            //
            // When root BID of stale-tree (or seq-tree if enabled) is not set, then
            // a new root node is created in this function call. However, if other
            // thread calls commit() at the same time, then the root node cannot be
            // written back into the file as its BID is not writable anymore.
            //
            // To avoid this issue, we grab file lock just once at here.
            handle->file->mutexLock();
            locked = true;

            // Reload DB header as other thread may append the first header at the
            // same time.
            handle->file->getHeader(header_buf, &header_len,
                                    &last_hdr_bid, &seqnum,
                                    &latest_header_revnum);
            handle->last_hdr_bid.store(last_hdr_bid, std::memory_order_relaxed);
            if (header_len) {
                // header creation racing .. unlock and re-fetch it
                locked = false;
                handle->file->mutexUnlock();
                free(prev_filename);
                continue;
            }
        }
        break;
    } while (true);

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
        SuperblockBase *sb = handle->file->getSb();

        if (sb && sb->bmpExists()) {
            dirty_data_exists = false;
            bid_t sb_last_hdr_bid = sb->getLastHdrBid();
            if (sb_last_hdr_bid != BLK_NOT_FOUND) {
                // add 1 since we subtract 1 from 'hdr_bid' below soon
                hdr_bid = sb_last_hdr_bid + 1;
                if (sb->getCurAllocBid() != hdr_bid) {
                    // seq number has been increased since the last commit
                    seqnum = fdb_kvs_get_committed_seqnum(handle);
                }
            } else {
                hdr_bid = BLK_NOT_FOUND;
            }
        } else {
            hdr_bid = handle->file->getPos() / FDB_BLOCKSIZE;
            dirty_data_exists = (hdr_bid >
                         handle->last_hdr_bid.load(std::memory_order_relaxed));
        }

        if (hdr_bid == BLK_NOT_FOUND ||
            (sb && hdr_bid <= sb->getConfig().num_sb)) {
            hdr_bid = 0;
        } else if (hdr_bid > 0) {
            --hdr_bid;
        }

        if (handle->max_seqnum) {
            KvsStat stat_ori;
            // backup original stats
            if (handle->kvs) {
                handle->file->getKvsStatOps()->statGet(handle->kvs->getKvsId(), &stat_ori);
            } else {
                handle->file->getKvsStatOps()->statGet(0, &stat_ori);
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
                hdr_bid = handle->file->getHeaderBid();
            }
            // Reverse scan the file to locate the DB header with seqnum marker
            header_revnum = latest_header_revnum;
            while (header_len && seqnum != handle->max_seqnum) {
                hdr_bid = handle->file->fetchPrevHeader(hdr_bid, header_buf,
                                                        &header_len, &seqnum,
                                                        &header_revnum, NULL,
                                                        &version, NULL,
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
                handle->last_hdr_bid.store(hdr_bid, std::memory_order_relaxed);

                if (!handle->kvs || handle->kvs->getKvsId() == 0) {
                    // single KVS mode OR default KVS
                    if (!handle->shandle) {
                        // rollback
                        KvsStat stat_dst;
                        handle->file->getKvsStatOps()->statGet(0, &stat_dst);
                        stat_dst.ndocs = ndocs;
                        stat_dst.ndeletes = ndeletes;
                        stat_dst.datasize = datasize;
                        stat_dst.nlivenodes = nlivenodes;
                        stat_dst.deltasize = deltasize;
                        handle->file->getKvsStatOps()->statSet(0, stat_dst);
                    }
                    continue;
                }

                int64_t doc_offset;
                KvsHeader *kv_header;
                struct docio_object doc;

                _fdb_kvs_header_create(&kv_header);
                memset(&doc, 0, sizeof(struct docio_object));
                doc_offset = handle->dhandle->readDoc_Docio(kv_info_offset,
                                                             &doc, true);

                if (doc_offset <= 0) {
                    header_len = 0; // fail
                    _fdb_kvs_header_free(kv_header);
                } else {
                    _fdb_kvs_header_import(kv_header, doc.body,
                                           doc.length.bodylen, version, false);
                    // get local sequence number for the KV instance
                    seqnum = _fdb_kvs_get_seqnum(kv_header,
                                                 handle->kvs->getKvsId());
                    if (!handle->shandle) {
                        // rollback: replace kv_header stats
                        // read from the current header's kv_header
                        KvsStat stat_src, stat_dst;
                        KvsStatOperations::statGetKvHeader(kv_header,
                                                           handle->kvs->getKvsId(),
                                                           &stat_src);
                        handle->file->getKvsStatOps()->statGet(handle->kvs->getKvsId(),
                                                         &stat_dst);
                        // update ndocs, datasize, nlivenodes
                        // into the current file's kv_header
                        // Note: stats related to WAL should not be updated
                        //       at this time. They will be adjusted through
                        //       discard & restore routines below.
                        stat_dst.ndocs = stat_src.ndocs;
                        stat_dst.datasize = stat_src.datasize;
                        stat_dst.nlivenodes = stat_src.nlivenodes;
                        handle->file->getKvsStatOps()->statSet(handle->kvs->getKvsId(),
                                                         stat_dst);
                    }
                    _fdb_kvs_header_free(kv_header);
                    free_docio_object(&doc, true, true, true);
                }
            }

            uint64_t sb_min_live_revnum = 0;
            if (sb) {
                sb_min_live_revnum = sb->getMinLiveHdrRevnum();
            }
            if (header_len && // header exists
                config->block_reusing_threshold > 0 && // block reuse is enabled
                config->block_reusing_threshold < 100 &&
                header_revnum < sb_min_live_revnum) {
                // cannot perform rollback/snapshot beyond the last live header
                header_len = 0;
            }

            if (!header_len) { // Marker MUST match that of DB commit!
                // rollback original stats
                if (handle->kvs) {
                    handle->file->getKvsStatOps()->statGet(handle->kvs->getKvsId(), &stat_ori);
                } else {
                    handle->file->getKvsStatOps()->statGet(0, &stat_ori);
                }

                if (locked) {
                    handle->file->mutexUnlock();
                }
                delete handle->dhandle;
                free(prev_filename);
                FileMgr::close(handle->file, false, NULL,
                               &handle->log_callback);
                return FDB_RESULT_NO_DB_INSTANCE;
            }

            if (!handle->shandle) { // Rollback mode, destroy file WAL..
                if (handle->config.multi_kv_instances) {
                    // multi KV instance mode
                    // clear only WAL items belonging to the instance
                    handle->file->getWal()->closeKvs_Wal(
                                     (handle->kvs) ? handle->kvs->getKvsId() : 0,
                                     &handle->log_callback);
                } else {
                    handle->file->getWal()->shutdown_Wal(&handle->log_callback);
                }
            }
        } else { // snapshot to sequence number 0 requested..
            if (handle->shandle) { // fdb_snapshot_open API call
                if (seqnum) {
                    // Database currently has a non-zero seq number,
                    // but the snapshot was requested with a seq number zero.
                    if (locked) {
                        handle->file->mutexUnlock();
                    }
                    delete handle->dhandle;
                    free(prev_filename);
                    FileMgr::close(handle->file, false, NULL,
                                   &handle->log_callback);
                    return FDB_RESULT_NO_DB_INSTANCE;
                }
            } // end of zero max_seqnum but non-rollback check
        } // end of zero max_seqnum check
    } // end of durable snapshot locating

    bool is_btree_v2 = ver_btreev2_format(version);
    if (is_btree_v2) {
        // BtreeV2 uses a BnodeManager instead of BtreeBlockHandle
        handle->bnodeMgr = new BnodeMgr();
        handle->bnodeMgr->setFile(handle->file);
        handle->bnodeMgr->setLogCallback(&handle->log_callback);
    } else {
        handle->bhandle = new BTreeBlkHandle(handle->file,
                                             handle->file->getBlockSize());
        handle->bhandle->setLogCallback(&handle->log_callback);
    }

    handle->dirty_updates = 0;

    if (handle->config.compaction_buf_maxsize == 0) {
        handle->config.compaction_buf_maxsize = FDB_COMP_BUF_MINSIZE;
    }

    handle->cur_header_revnum = latest_header_revnum;
    if (header_revnum) {
        if (handle->file->isRollbackOn()) {
            // rollback mode
            // set rollback header revnum
            handle->rollback_revnum = header_revnum;
        } else {
            // snapshot mode (only for snapshot)
            handle->cur_header_revnum = header_revnum;
        }
    }
    handle->last_wal_flush_hdr_bid = last_wal_flush_hdr_bid;

    memset(&empty_stat, 0x0, sizeof(empty_stat));
    handle->file->getKvsStatOps()->statGet(0, &stat);
    if (!memcmp(&stat, &empty_stat, sizeof(stat))) { // first open
        // sync (default) KVS stat with DB header
        stat.nlivenodes = nlivenodes;
        stat.ndocs = ndocs;
        stat.datasize = datasize;
        handle->file->getKvsStatOps()->statSet(0, stat);
    }

    handle->kv_info_offset = kv_info_offset;
    if (handle->config.multi_kv_instances && !handle->shandle) {
        // multi KV instance mode
        if (!locked) {
            handle->file->mutexLock();
        }
        if (kv_info_offset == BLK_NOT_FOUND) {
            // there is no KV header .. create & initialize
            fdb_kvs_header_create(handle->file);
            // TODO: If another handle is opened before the first header is appended,
            // an unnecessary KV info doc is appended. We need to address it.
            kv_info_offset = fdb_kvs_header_append(handle);
        } else if (handle->file->getKVHeader_UNLOCKED() == NULL) {
            // KV header already exists but not loaded .. read & import
            fdb_kvs_header_create(handle->file);
            fdb_kvs_header_read(handle->file->getKVHeader_UNLOCKED(), handle->dhandle,
                                kv_info_offset, version, false);
        }
        if (!locked) {
            handle->file->mutexUnlock();
        }

        // validation check for key order of all KV stores
        if (handle == handle->fhandle->getRootHandle()) {
            fdb_status fs = fdb_kvs_cmp_check(handle);
            if (fs != FDB_RESULT_SUCCESS) { // cmp function mismatch
                if (locked) {
                    handle->file->mutexUnlock();
                }
                delete handle->dhandle;
                if (is_btree_v2) {
                    delete handle->bnodeMgr;
                } else {
                    delete handle->bhandle;
                }
                free(prev_filename);
                FileMgr::close(handle->file, false, NULL,
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
        handle->initRootHandle();
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
            handle->file->getKvsStatOps()->statGet(handle->kvs->getKvsId(),
                                                   &handle->shandle->stat);
            // Since wal is restored below, we have to reset
            // wal stats to zero.
            handle->shandle->stat.wal_ndeletes = 0;
            handle->shandle->stat.wal_ndocs = 0;
        }
    }

    // initialize pointer to the global operational stats of this KV store
    handle->op_stats = handle->file->getKvsStatOps()->getOpsStats(handle->kvs);
    if (!handle->op_stats) {
        const char *msg = "Database open fails due to the error in retrieving "
            "the global operational stats of KV store in a database file '%s'\n";
        fdb_log(&handle->log_callback, FDB_RESULT_OPEN_FAIL, msg,
                handle->file->getFileName());
        free(prev_filename);
        _fdb_cleanup_open_err(handle);
        return FDB_RESULT_OPEN_FAIL;
    }

    if (is_btree_v2) {
        BtreeNodeAddr rootAddr(trie_root_bid);
        handle->trie = new HBTrie(config->chunksize,
                                  handle->file->getBlockSize(), rootAddr,
                                  handle->bnodeMgr, handle->file);
        if (handle->kvs) {
            handle->trie->setCmpFuncCB(FdbEngine::getCmpFuncCB);
        }
    } else {
        handle->trie = new HBTrie(config->chunksize, OFFSET_SIZE,
                                  handle->file->getBlockSize(), trie_root_bid,
                                  handle->bhandle,
                                  (void *)handle->dhandle, _fdb_readkey_wrap);
        // set aux for cmp wrapping function
        handle->trie->setLeafHeightLimit(0xff);
        handle->trie->setLeafCmp(_fdb_custom_cmp_wrap);
        if (handle->kvs) {
            handle->trie->setMapFunction(fdb_kvs_find_cmp_chunk);
        }
    }

    handle->seqnum = seqnum;
    if (handle->config.seqtree_opt == FDB_SEQTREE_USE) {
        if (handle->config.multi_kv_instances) {
            if (is_btree_v2) {
                BtreeNodeAddr rootAddr(seq_root_bid);
                // multi KV instance mode .. HB+trie using BtreeV2
                handle->seqtrie = new HBTrie(sizeof(fdb_kvs_id_t),
                                      handle->file->getBlockSize(), rootAddr,
                                      handle->bnodeMgr, handle->file);
            } else {
                // multi KV instance mode .. HB+trie
                handle->seqtrie = new HBTrie(sizeof(fdb_kvs_id_t), OFFSET_SIZE,
                                    handle->file->getBlockSize(), seq_root_bid,
                                    handle->bhandle,
                                    (void *)handle->dhandle,
                                    _fdb_readseq_wrap);
            }

        } else {// single KV instance mode .. normal B+tree
            if (is_btree_v2) {
                handle->seqtreeV2 = new BtreeV2();
                handle->seqtreeV2->setBMgr(handle->bnodeMgr);
                BtreeNodeAddr rootOffset(seq_root_bid);
                handle->seqtreeV2->initFromAddr(rootOffset);
            } else {
                BTreeKVOps *seq_kv_ops = new FixedKVOps(8, 8,
                                             _cmp_uint64_t_endian_safe);

                handle->seqtree = new BTree();
                if (seq_root_bid == BLK_NOT_FOUND) {
                    handle->seqtree->init(handle->bhandle, seq_kv_ops,
                                          handle->config.blocksize,
                                          sizeof(fdb_seqnum_t), OFFSET_SIZE,
                                          0x0, NULL);
                } else {
                    handle->seqtree->initFromBid(handle->bhandle, seq_kv_ops,
                            handle->config.blocksize, seq_root_bid);
                }
            }
        }
    } else {
        handle->seqtree = NULL;
    }

    // Stale-block tree (supported since MAGIC_002)
    // this tree is independent to multi/single KVS mode option
    if (ver_staletree_support(version)) {
        if (is_btree_v2) {
            // new B+treeV2
            handle->staletreeV2 = new BtreeV2();
            handle->staletreeV2->setBMgr(handle->bnodeMgr);
            if (stale_root_bid == BLK_NOT_FOUND) {
                handle->staletreeV2->init();
            } else {
                BtreeNodeAddr staleRootOffset(stale_root_bid);
                handle->staletreeV2->initFromAddr(staleRootOffset);
                // prefetch stale info into memory
                // (as stale_root_bid != BLK_NOT_FOUND,
                //  we don't need to worry about file's mutex.)
                handle->file->getStaleData()->loadInmemStaleInfo(handle);
            }
        } else {
            // normal B+tree
            BTreeKVOps *stale_kv_ops = new FixedKVOps(8, 8,
                                           _cmp_uint64_t_endian_safe);
            handle->staletree = new BTree();
            if (stale_root_bid == BLK_NOT_FOUND) {
                handle->staletree->init(handle->bhandle, stale_kv_ops,
                                        handle->config.blocksize,
                                        sizeof(filemgr_header_revnum_t),
                                        OFFSET_SIZE, 0x0, NULL);
            } else {
                handle->staletree->initFromBid(handle->bhandle, stale_kv_ops,
                        handle->config.blocksize, stale_root_bid);
                // prefetch stale info into memory
                // (as stale_root_bid != BLK_NOT_FOUND,
                //  we don't need to worry about file's mutex.)
                handle->file->getStaleData()->loadInmemStaleInfo(handle);
            }
        }
    } else {
        handle->staletree = NULL;
    }

    if (is_btree_v2) {
        handle->bnodeMgr->releaseCleanNodes();
    } else {
        status = handle->bhandle->flushBuffer();
    }

    if (status != FDB_RESULT_SUCCESS) {
        if (locked) {
            handle->file->mutexUnlock();
        }
        free(prev_filename);
        _fdb_cleanup_open_err(handle);
        return status;
    }

    if (locked) {
        // As this is a first open (creation) call of the file,
        // append the first commit header
        uint64_t cur_bmp_revnum = 0;
        if (handle->file->getSb()) {
            cur_bmp_revnum = handle->file->getSb()->getBmpRevnum();
        }
        handle->last_hdr_bid = handle->file->alloc_FileMgr(&handle->log_callback);
        handle->cur_header_revnum = fdb_set_file_header(handle);
        handle->file->commitBid(handle->last_hdr_bid.load(std::memory_order_relaxed),
                           cur_bmp_revnum,
                           !(handle->config.durability_opt & FDB_DRB_ASYNC),
                           &handle->log_callback);
        if (!is_btree_v2) {
            handle->bhandle->resetSubblockInfo();
        }

        handle->file->mutexUnlock();
    }

    if (handle->config.multi_kv_instances && handle->max_seqnum) {
        // restore only docs belonging to the KV instance
        // handle->kvs should not be NULL
        _fdb_restore_wal(handle, FDB_RESTORE_KV_INS,
                         hdr_bid, (handle->kvs) ? handle->kvs->getKvsId() : 0);
    } else {
        // normal restore
        _fdb_restore_wal(handle, FDB_RESTORE_NORMAL, hdr_bid, 0);
    }

    if (compacted_filename &&
        handle->file->getFileStatus() == FILE_NORMAL &&
        !(config->flags & FDB_OPEN_FLAG_RDONLY)) { // do not recover read-only
        _fdb_recover_compaction(handle, compacted_filename);
    }

    if (prev_filename) {
        if (!handle->shandle &&
            strcmp(prev_filename, handle->file->getFileName())) {
            // record the old filename into the file handle of current file
            // and REMOVE old file on the first open
            // WARNING: snapshots must have been opened before this call
            if (handle->file->updateFileStatus(handle->file->getFileStatus(),
                                               prev_filename)) {
                // Open the old file with read-only mode.
                // (Temporarily disable log callback at this time since
                //  the old file might be already removed.)
                ErrLogCallback dummy_cb(fdb_dummy_log_callback, NULL);
                fconfig.setOptions(FILEMGR_READONLY);
                filemgr_open_result result = FileMgr::open(
                                                    std::string(prev_filename),
                                                    handle->fileops,
                                                    &fconfig,
                                                    &dummy_cb);
                if (result.file) {
                    FileMgr::removePending(result.file, handle->file,
                                           &handle->log_callback);
                    FileMgr::close(result.file, false, handle->filename.c_str(),
                                   &handle->log_callback);
                }
            }
        }
        free(prev_filename);
    }

    // do not register read-only handles
    if (!(config->flags & FDB_OPEN_FLAG_RDONLY)) {
        if (config->compaction_mode == FDB_COMPACTION_AUTO) {
            status = CompactionManager::getInstance()->registerFile(handle->file,
                                                                    (fdb_config *)config,
                                                                    &handle->log_callback);
        }
        if (status == FDB_RESULT_SUCCESS) {
            BgFlusher *bgf = BgFlusher::getBgfInstance();
            if (bgf) {
                status = bgf->registerFile_BgFlusher(handle->file,
                                                     (fdb_config *)config,
                                                     &handle->log_callback);
            }
        }
    }
    if (status != FDB_RESULT_SUCCESS) {
        _fdb_cleanup_open_err(handle);
    }

    return status;
}

fdb_status FdbEngine::setLogCallback(FdbKvsHandle *handle,
                                     fdb_log_callback log_callback,
                                     void *ctx_data) {
    if (!handle) {
        return FDB_RESULT_INVALID_HANDLE;
    }

    handle->log_callback.setCallback(log_callback);
    handle->log_callback.setCtxData(ctx_data);
    return FDB_RESULT_SUCCESS;
}

fdb_status FdbEngine::get(FdbKvsHandle *handle, fdb_doc *doc,
                          bool metaOnly)
{
    uint64_t offset;
    struct docio_object _doc;
    DocioHandle *dhandle;
    FileMgr *wal_file = NULL;
    struct _fdb_key_cmp_info cmp_info;
    fdb_status wr;
    hbtrie_result hr = HBTRIE_RESULT_FAIL;
    fdb_txn *txn;
    fdb_doc doc_kv;
    LATENCY_STAT_START();

    if (!handle) {
        return FDB_RESULT_INVALID_HANDLE;
    }

    if (!doc || !doc->key ||
        doc->keylen == 0 || doc->keylen > FDB_MAX_KEYLEN ||
        (handle->kvs_config.custom_cmp &&
            doc->keylen > handle->config.blocksize - HBTRIE_HEADROOM)) {
        return FDB_RESULT_INVALID_ARGS;
    }

    if (!BEGIN_HANDLE_BUSY(handle)) {
        return FDB_RESULT_HANDLE_BUSY;
    }

    doc_kv = *doc;

    if (handle->kvs) {
        // multi KV instance mode
        int size_chunk = handle->config.chunksize;
        doc_kv.keylen = doc->keylen + size_chunk;
        doc_kv.key = alca(uint8_t, doc_kv.keylen);
        kvid2buf(size_chunk, handle->kvs->getKvsId(), doc_kv.key);
        memcpy((uint8_t*)doc_kv.key + size_chunk, doc->key, doc->keylen);
    }

    if (!handle->shandle) {
        wr = fdb_check_file_reopen(handle, NULL);
        if (wr != FDB_RESULT_SUCCESS) {
            END_HANDLE_BUSY(handle);
            return wr;
        }

        txn = handle->fhandle->getRootHandle()->txn;
        if (!txn) {
            txn = handle->file->getGlobalTxn();
        }
    } else {
        txn = handle->shandle->snap_txn;
    }

    cmp_info.kvs_config = handle->kvs_config;
    cmp_info.kvs = handle->kvs;
    wal_file = handle->file;
    dhandle = handle->dhandle;

    if (handle->kvs) {
        wr = wal_file->getWal()->find_Wal(txn, &cmp_info, handle->shandle, &doc_kv,
                                     &offset);
    } else {
        wr = wal_file->getWal()->find_Wal(txn, &cmp_info, handle->shandle, doc,
                                     &offset);
    }

    if (!handle->shandle) {
        fdb_sync_db_header(handle);
    }

    handle->op_stats->num_gets++;

    if (wr == FDB_RESULT_KEY_NOT_FOUND) {
        _fdb_sync_dirty_root(handle);

        // as 'offset' is located at the beginning of doc_meta,
        // we can use it for legacy code as well.
        DocMetaForIndex doc_meta;
        if (handle->kvs) {
            hr = handle->trie->find(doc_kv.key, doc_kv.keylen, &doc_meta);
        } else {
            hr = handle->trie->find(doc->key, doc->keylen, &doc_meta);
        }

        if (ver_btreev2_format(handle->file->getVersion())) {
            handle->bnodeMgr->releaseCleanNodes();
        } else {
            handle->bhandle->flushBuffer();
        }
        doc_meta.decode();
        offset = doc_meta.offset;

        _fdb_release_dirty_root(handle);
    }

    if ((wr == FDB_RESULT_SUCCESS && offset != BLK_NOT_FOUND) ||
        hr == HBTRIE_RESULT_SUCCESS) {

        bool alloced_meta = doc->meta ? false : true;
        bool alloced_body = (metaOnly || doc->body) ? false : true;

        if (handle->kvs) {
            _doc.key = doc_kv.key;
            _doc.length.keylen = doc_kv.keylen;
            if (!metaOnly) {
                doc->deleted = doc_kv.deleted; // update deleted field if wal_find
            }
        } else {
            _doc.key = doc->key;
            _doc.length.keylen = doc->keylen;
        }

        _doc.meta = doc->meta;
        _doc.body = doc->body;

        if (!metaOnly && wr == FDB_RESULT_SUCCESS && doc->deleted) {
            END_HANDLE_BUSY(handle);
            return FDB_RESULT_KEY_NOT_FOUND;
        }

        int64_t _offset = 0;
        if (metaOnly) {
            _offset = dhandle->readDocKeyMeta_Docio(offset, &_doc, true);
        } else {
            _offset = dhandle->readDoc_Docio(offset, &_doc, true);
        }

        if (_offset <= 0) {
            END_HANDLE_BUSY(handle);
            return _offset < 0 ? (fdb_status)_offset : FDB_RESULT_KEY_NOT_FOUND;
        }

        if ((_doc.length.keylen != doc_kv.keylen) ||
            (!metaOnly && (_doc.length.flag & DOCIO_DELETED))) {
            free_docio_object(&_doc, false, alloced_meta, alloced_body);
            END_HANDLE_BUSY(handle);
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
        END_HANDLE_BUSY(handle);
        return FDB_RESULT_SUCCESS;
    }

    END_HANDLE_BUSY(handle);
    return FDB_RESULT_KEY_NOT_FOUND;
}

fdb_status FdbEngine::getBySeq(FdbKvsHandle *handle,
                               fdb_doc *doc,
                               bool metaOnly)
{
    uint64_t offset;
    struct docio_object _doc;
    DocioHandle *dhandle;
    FileMgr *wal_file = NULL;
    fdb_status wr;
    btree_result br = BTREE_RESULT_FAIL;
    fdb_seqnum_t _seqnum;
    fdb_txn *txn;
    struct _fdb_key_cmp_info cmp_info;
    LATENCY_STAT_START();

    if (!handle) {
        return FDB_RESULT_INVALID_HANDLE;
    }

    if (!doc || doc->seqnum == SEQNUM_NOT_USED) {
        return FDB_RESULT_INVALID_ARGS;
    }

    // Sequence trees are a must for byseq operations
    if (handle->config.seqtree_opt != FDB_SEQTREE_USE) {
        return FDB_RESULT_INVALID_CONFIG;
    }

    if (!BEGIN_HANDLE_BUSY(handle)) {
        return FDB_RESULT_HANDLE_BUSY;
    }

    if (!handle->shandle) {
        wr = fdb_check_file_reopen(handle, NULL);
        if (wr != FDB_RESULT_SUCCESS) {
            END_HANDLE_BUSY(handle);
            return wr;
        }

        txn = handle->fhandle->getRootHandle()->txn;
        if (!txn) {
            txn = handle->file->getGlobalTxn();
        }
    } else {
        txn = handle->shandle->snap_txn;
    }

    cmp_info.kvs_config = handle->kvs_config;
    cmp_info.kvs = handle->kvs;
    wal_file = handle->file;
    dhandle = handle->dhandle;

    // prevent searching by key in WAL if 'doc' is not empty
    size_t key_len = doc->keylen;
    doc->keylen = 0;
    if (handle->kvs) {
        wr = wal_file->getWal()->findWithKvid_Wal(txn, handle->kvs->getKvsId(),
                                             &cmp_info,
                                             handle->shandle, doc, &offset);
    } else {
        wr = wal_file->getWal()->find_Wal(txn, &cmp_info, handle->shandle, doc, &offset);
    }

    doc->keylen = key_len;
    if (!handle->shandle) {
        fdb_sync_db_header(handle);
    }

    handle->op_stats->num_gets++;

    if (wr == FDB_RESULT_KEY_NOT_FOUND) {
        _fdb_sync_dirty_root(handle);

        _seqnum = _endian_encode(doc->seqnum);
        if (handle->kvs) {
            int size_id, size_seq;
            uint8_t *kv_seqnum;
            hbtrie_result hr;
            fdb_kvs_id_t _kv_id;

            _kv_id = _endian_encode(handle->kvs->getKvsId());
            size_id = sizeof(fdb_kvs_id_t);
            size_seq = sizeof(fdb_seqnum_t);
            kv_seqnum = alca(uint8_t, size_id + size_seq);
            memcpy(kv_seqnum, &_kv_id, size_id);
            memcpy(kv_seqnum + size_id, &_seqnum, size_seq);
            hr = handle->seqtrie->find((void *)kv_seqnum, size_id + size_seq,
                                       (void *)&offset);
            br = (hr == HBTRIE_RESULT_SUCCESS)?(BTREE_RESULT_SUCCESS):(br);
        } else {
            br = handle->seqtree->find((void *)&_seqnum, (void *)&offset);
        }
        if (ver_btreev2_format(handle->file->getVersion())) {
            handle->bnodeMgr->releaseCleanNodes();
        } else {
            handle->bhandle->flushBuffer();
        }
        offset = _endian_decode(offset);

        _fdb_release_dirty_root(handle);
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
        alloc_body = (metaOnly || doc->body) ? false : true;
        _doc.body = doc->body;

        if (!metaOnly && wr == FDB_RESULT_SUCCESS && doc->deleted) {
            END_HANDLE_BUSY(handle);
            return FDB_RESULT_KEY_NOT_FOUND;
        }

        int64_t _offset = 0;
        if (metaOnly) {
            _offset = dhandle->readDocKeyMeta_Docio(offset, &_doc, true);
        } else {
            _offset = dhandle->readDoc_Docio(offset, &_doc, true);
        }

        if (_offset <= 0) {
            END_HANDLE_BUSY(handle);
            return _offset < 0 ? (fdb_status)_offset : FDB_RESULT_KEY_NOT_FOUND;
        }

        if ((metaOnly && doc->seqnum != _doc.seqnum) ||
            (!metaOnly && (_doc.length.flag & DOCIO_DELETED))) {
            END_HANDLE_BUSY(handle);
            free_docio_object(&_doc, alloc_key, alloc_meta, alloc_body);
            return FDB_RESULT_KEY_NOT_FOUND;
        }

        doc->seqnum = _doc.seqnum;

        if (handle->kvs) {
            int size_chunk = handle->config.chunksize;
            doc->keylen = _doc.length.keylen - size_chunk;
            if (doc->key) { // doc->key is given by user
                memcpy(doc->key, (uint8_t*)_doc.key + size_chunk, doc->keylen);
                free_docio_object(&_doc, true, false, false);
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

        END_HANDLE_BUSY(handle);
        LATENCY_STAT_END(handle->file, FDB_LATENCY_GETS);
        return FDB_RESULT_SUCCESS;
    }

    END_HANDLE_BUSY(handle);
    return FDB_RESULT_KEY_NOT_FOUND;
}

fdb_status FdbEngine::getByOffset(FdbKvsHandle *handle, fdb_doc *doc)
{
    if (!handle) {
        return FDB_RESULT_INVALID_HANDLE;
    }

    if (!doc) {
        return FDB_RESULT_INVALID_ARGS;
    }

    uint64_t offset = doc->offset;
    struct docio_object _doc;

    if (!offset || offset == BLK_NOT_FOUND) {
        return FDB_RESULT_INVALID_ARGS;
    }

    if (!BEGIN_HANDLE_BUSY(handle)) {
        return FDB_RESULT_HANDLE_BUSY;
    }

    handle->op_stats->num_gets++;
    memset(&_doc, 0, sizeof(struct docio_object));

    int64_t _offset = handle->dhandle->readDoc_Docio(offset, &_doc, true);
    if (_offset <= 0 || !_doc.key || (_doc.length.flag & DOCIO_TXN_COMMITTED)) {
        END_HANDLE_BUSY(handle);
        return _offset < 0 ? (fdb_status)_offset : FDB_RESULT_KEY_NOT_FOUND;
    } else {
        if (handle->kvs) {
            fdb_kvs_id_t kv_id;
            buf2kvid(handle->config.chunksize, _doc.key, &kv_id);
            if (kv_id != handle->kvs->getKvsId()) {
                END_HANDLE_BUSY(handle);
                free_docio_object(&_doc, true, true, true);
                return FDB_RESULT_KEY_NOT_FOUND;
            }
            _remove_kv_id(handle, &_doc);
        }
        if (!equal_docs(doc, &_doc)) {
            free_docio_object(&_doc, true, true, true);
            END_HANDLE_BUSY(handle);
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
        END_HANDLE_BUSY(handle);
        return FDB_RESULT_KEY_NOT_FOUND;
    }
    END_HANDLE_BUSY(handle);

    return FDB_RESULT_SUCCESS;
}

fdb_status FdbEngine::set(FdbKvsHandle *handle, fdb_doc *doc)
{
    if (!handle) {
        return FDB_RESULT_INVALID_HANDLE;
    }

    uint64_t offset;
    struct docio_object _doc;
    FileMgr *file;
    DocioHandle *dhandle;
    struct timeval tv;
    bool txn_enabled = false;
    bool sub_handle = false;
    bool wal_flushed = false;
    bool immediate_remove = false;
    file_status_t fMgrStatus;
    fdb_txn *txn = handle->fhandle->getRootHandle()->txn;
    struct _fdb_key_cmp_info cmp_info;
    fdb_status wr = FDB_RESULT_SUCCESS;
    LATENCY_STAT_START();

    if (handle->config.flags & FDB_OPEN_FLAG_RDONLY) {
        return fdb_log(&handle->log_callback, FDB_RESULT_RONLY_VIOLATION,
                       "Warning: SET is not allowed on the read-only DB file '%s'.",
                       handle->file->getFileName());
    }

    if (!doc || doc->key == NULL ||
        doc->keylen == 0 || doc->keylen > FDB_MAX_KEYLEN ||
        (doc->metalen > 0 && doc->meta == NULL) ||
        (doc->bodylen > 0 && doc->body == NULL) ||
        (handle->kvs_config.custom_cmp &&
            doc->keylen > handle->config.blocksize - HBTRIE_HEADROOM)) {
        return FDB_RESULT_INVALID_ARGS;
    }

    if (!BEGIN_HANDLE_BUSY(handle)) {
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
        kvid2buf(size_chunk, handle->kvs->getKvsId(), _doc.key);
        // copy key
        memcpy((uint8_t*)_doc.key + size_chunk, doc->key, doc->keylen);

        if (handle->kvs->getKvsType() == KVS_SUB) {
            sub_handle = true;
        } else {
            sub_handle = false;
        }
    }

fdb_set_start:
    wr = fdb_check_file_reopen(handle, NULL);
    if (wr != FDB_RESULT_SUCCESS) {
        END_HANDLE_BUSY(handle);
        return wr;
    }

    size_t throttling_delay = handle->file->getThrottlingDelay();
    if (throttling_delay) {
        usleep(throttling_delay);
    }

    cmp_info.kvs_config = handle->kvs_config;
    cmp_info.kvs = handle->kvs;

    handle->file->mutexLock();
    fdb_sync_db_header(handle);

    if (handle->file->isRollbackOn()) {
        handle->file->mutexUnlock();
        END_HANDLE_BUSY(handle);
        return FDB_RESULT_FAIL_BY_ROLLBACK;
    }

    file = handle->file;
    dhandle = handle->dhandle;

    fMgrStatus = file->getFileStatus();
    if (fMgrStatus == FILE_REMOVED_PENDING) {
        // we must not write into this file
        // file status was changed by other thread .. start over
        file->mutexUnlock();
        goto fdb_set_start;
    }

    if (sub_handle) {
        // multiple KV instance mode AND sub handle
        fdb_seqnum_t kv_seqnum = fdb_kvs_get_seqnum(file,
                                                    handle->kvs->getKvsId());
        if (doc->seqnum != SEQNUM_NOT_USED &&
            doc->flags & FDB_CUSTOM_SEQNUM) { // User specified own seqnum
            if (kv_seqnum < doc->seqnum) { // track highest seqnum in handle,kv
                handle->seqnum = doc->seqnum;
                fdb_kvs_set_seqnum(file, handle->kvs->getKvsId(),
                                   handle->seqnum);
            }
            doc->flags &= ~FDB_CUSTOM_SEQNUM; // clear flag for fdb_doc reuse
        } else { // normal monotonically increasing sequence numbers..
            doc->seqnum = ++kv_seqnum;
            handle->seqnum = doc->seqnum; // keep handle's seqnum the highest
            fdb_kvs_set_seqnum(file, handle->kvs->getKvsId(), handle->seqnum);
        }
    } else {
        fdb_seqnum_t kv_seqnum = file->getSeqnum();
        // super handle OR single KV instance mode
        if (doc->seqnum != SEQNUM_NOT_USED &&
            doc->flags & FDB_CUSTOM_SEQNUM) { // User specified own seqnum
            if (kv_seqnum < doc->seqnum) { // track highest seqnum in handle,kv
                handle->seqnum = doc->seqnum;
                file->setSeqnum(handle->seqnum);
            }
            doc->flags &= ~FDB_CUSTOM_SEQNUM; // clear flag for fdb_doc reuse
        } else { // normal monotonically increasing sequence numbers..
            doc->seqnum = ++kv_seqnum;
            handle->seqnum = doc->seqnum;
            file->setSeqnum(handle->seqnum);
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

    offset = dhandle->appendDoc_Docio(&_doc, doc->deleted, txn_enabled);
    if (offset == BLK_NOT_FOUND) {
        file->mutexUnlock();
        END_HANDLE_BUSY(handle);
        return FDB_RESULT_WRITE_FAIL;
    }

    if (doc->deleted && !handle->config.purging_interval) {
        // immediately remove from hbtrie upon WAL flush
        immediate_remove = true;
    }

    doc->size_ondisk = _fdb_get_docsize(_doc.length);
    doc->offset = offset;
    if (!txn) {
        txn = file->getGlobalTxn();
    }
    if (handle->kvs) {
        // multi KV instance mode
        fdb_doc kv_ins_doc = *doc;
        kv_ins_doc.key = _doc.key;
        kv_ins_doc.keylen = _doc.length.keylen;
        if (!immediate_remove) {
            file->getWal()->insert_Wal(txn, &cmp_info, &kv_ins_doc, offset,
                       WAL_INS_WRITER);
        } else {
            file->getWal()->immediateRemove_Wal(txn, &cmp_info, &kv_ins_doc, offset,
                                 WAL_INS_WRITER);
        }
    } else {
        if (!immediate_remove) {
            file->getWal()->insert_Wal(txn, &cmp_info, doc, offset, WAL_INS_WRITER);
        } else {
            file->getWal()->immediateRemove_Wal(txn, &cmp_info, doc, offset,
                                           WAL_INS_WRITER);
        }
    }

    if (file->getWal()->getDirtyStatus_Wal() == FDB_WAL_CLEAN) {
        file->getWal()->setDirtyStatus_Wal(FDB_WAL_DIRTY);
    }

    if (handle->config.auto_commit &&
        file->getWal()->getNumFlushable_Wal() > _fdb_get_wal_threshold(handle)) {
        // we don't need dirty WAL flushing in auto commit mode
        // (commitWithKVHandle is internally called at the end of this function)
        wal_flushed = true;

    } else if (handle->config.wal_flush_before_commit) {

        bid_t dirty_idtree_root = BLK_NOT_FOUND;
        bid_t dirty_seqtree_root = BLK_NOT_FOUND;

        if (!txn_enabled) {
            handle->dirty_updates = 1;
        }

        if (file->getWal()->getNumFlushable_Wal() > _fdb_get_wal_threshold(handle)) {
            union wal_flush_items flush_items;

            // commit only for non-transactional WAL entries
            wr = file->getWal()->commit_Wal(file->getGlobalTxn(), NULL,
                                            &handle->log_callback);
            if (wr != FDB_RESULT_SUCCESS) {
                file->mutexUnlock();
                END_HANDLE_BUSY(handle);
                return wr;
            }

            struct filemgr_dirty_update_node *prev_node = NULL, *new_node = NULL;

            _fdb_dirty_update_ready(handle, &prev_node, &new_node,
                                    &dirty_idtree_root, &dirty_seqtree_root, true);

            wr = file->getWal()->flush_Wal((void *)handle,
                                           WalFlushCallbacks::flushItem,
                                           WalFlushCallbacks::getOldOffset,
                                           WalFlushCallbacks::purgeSeqTreeEntry,
                                           WalFlushCallbacks::updateKvsDeltaStats,
                                           &flush_items);

            bool is_btree_v2 = ver_btreev2_format(handle->file->getVersion());
            if (wr != FDB_RESULT_SUCCESS) {
                if (!is_btree_v2) {
                    handle->bhandle->clearDirtyUpdate();
                    FileMgr::dirtyUpdateCloseNode(prev_node);
                    handle->file->dirtyUpdateRemoveNode(new_node);
                }
                file->mutexUnlock();
                END_HANDLE_BUSY(handle);
                return wr;
            }

            _fdb_dirty_update_finalize(handle, prev_node, new_node,
                                       &dirty_idtree_root, &dirty_seqtree_root, false);

            file->getWal()->setDirtyStatus_Wal(FDB_WAL_PENDING);
            // it is ok to release flushed items becuase
            // these items are not actually committed yet.
            // they become visible after fdb_commit is invoked.
            file->getWal()->releaseFlushedItems_Wal(&flush_items);

            wal_flushed = true;
            if (!is_btree_v2) {
                handle->bhandle->resetSubblockInfo();
            }
        }
    }

    file->mutexUnlock();

    LATENCY_STAT_END(file, FDB_LATENCY_SETS);

    if (!doc->deleted) {
        handle->op_stats->num_sets++;
    }

    if (wal_flushed && handle->config.auto_commit) {
        END_HANDLE_BUSY(handle);
        return commitWithKVHandle(handle->fhandle->getRootHandle(), FDB_COMMIT_NORMAL,
                                  false); // asynchronous commit only
    }
    END_HANDLE_BUSY(handle);

    return FDB_RESULT_SUCCESS;
}

fdb_status FdbEngine::del(FdbKvsHandle *handle, fdb_doc *doc)
{
    if (!handle) {
        return FDB_RESULT_INVALID_HANDLE;
    }

    if (!doc) {
        return FDB_RESULT_INVALID_ARGS;
    }

    if (handle->config.flags & FDB_OPEN_FLAG_RDONLY) {
        return fdb_log(&handle->log_callback, FDB_RESULT_RONLY_VIOLATION,
                       "Warning: DEL is not allowed on the read-only DB file '%s'.",
                       handle->file->getFileName());
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

    handle->op_stats->num_dels++;

    return set(handle, &_doc);
}

fdb_status FdbEngine::commit(FdbFileHandle *fhandle, fdb_commit_opt_t opt)
{
    if (!fhandle) {
        return FDB_RESULT_INVALID_HANDLE;
    }

    bool sync = !(fhandle->getRootHandle()->config.durability_opt & FDB_DRB_ASYNC);
    return commitWithKVHandle(fhandle->getRootHandle(), opt, sync);
}

fdb_status FdbEngine::commitWithKVHandle(FdbKvsHandle *handle,
                                         fdb_commit_opt_t opt,
                                         bool sync)
{
    if (!handle) {
        return FDB_RESULT_INVALID_HANDLE;
    }

    uint64_t cur_bmp_revnum;
    fdb_txn *txn = handle->fhandle->getRootHandle()->txn;
    fdb_txn *earliest_txn;
    file_status_t fMgrStatus;
    fdb_status fs = FDB_RESULT_SUCCESS;
    bool wal_flushed = false;
    bid_t dirty_idtree_root = BLK_NOT_FOUND;
    bid_t dirty_seqtree_root = BLK_NOT_FOUND;
    union wal_flush_items flush_items;
    fdb_status wr = FDB_RESULT_SUCCESS;
    LATENCY_STAT_START();

    if (handle->kvs) {
        if (handle->kvs->getKvsType() == KVS_SUB) {
            // deny commit on sub handle
            return FDB_RESULT_INVALID_HANDLE;
        }
    }
    if (handle->config.flags & FDB_OPEN_FLAG_RDONLY) {
        return fdb_log(&handle->log_callback, FDB_RESULT_RONLY_VIOLATION,
                       "Warning: Commit is not allowed on the read-only DB file '%s'.",
                       handle->file->getFileName());
    }

    if (!BEGIN_HANDLE_BUSY(handle)) {
        return FDB_RESULT_HANDLE_BUSY;
    }

fdb_commit_start:
    wr = fdb_check_file_reopen(handle, NULL);
    if (wr != FDB_RESULT_SUCCESS) {
        END_HANDLE_BUSY(handle);
        return wr;
    }

    handle->file->mutexLock();
    fdb_sync_db_header(handle);

    if (handle->file->isRollbackOn()) {
        handle->file->mutexUnlock();
        END_HANDLE_BUSY(handle);
        return FDB_RESULT_FAIL_BY_ROLLBACK;
    }

    fMgrStatus = handle->file->getFileStatus();
    if (fMgrStatus == FILE_REMOVED_PENDING) {
        // we must not commit this file
        // file status was changed by other thread .. start over
        handle->file->mutexUnlock();
        goto fdb_commit_start;
    }

    if (ver_btreev2_format(handle->file->getVersion())) {
        handle->bnodeMgr->releaseCleanNodes();
    } else {
        fs = handle->bhandle->flushBuffer();
        if (fs != FDB_RESULT_SUCCESS) {
            handle->file->mutexUnlock();
            END_HANDLE_BUSY(handle);
            return fs;
        }
    }
    // commit wal
    if (txn) {
        // transactional updates
        wr = handle->file->getWal()->commit_Wal(txn, _fdb_append_commit_mark,
                                                &handle->log_callback);
        if (wr != FDB_RESULT_SUCCESS) {
            handle->file->mutexUnlock();
            END_HANDLE_BUSY(handle);
            return wr;
        }
        if (handle->file->getWal()->getDirtyStatus_Wal()== FDB_WAL_CLEAN) {
            handle->file->getWal()->setDirtyStatus_Wal(FDB_WAL_DIRTY);
        }
    } else {
        // non-transactional updates
        handle->file->getWal()->commit_Wal(handle->file->getGlobalTxn(), NULL,
                                           &handle->log_callback);
    }

    bool btreev2 = ver_btreev2_format(handle->file->getVersion());

    if (handle->file->getWal()->getNumFlushable_Wal() > _fdb_get_wal_threshold(handle) ||
        handle->file->getWal()->getDirtyStatus_Wal() == FDB_WAL_PENDING ||
        opt & FDB_COMMIT_MANUAL_WAL_FLUSH) {
        // wal flush when
        // 1. wal size exceeds threshold
        // 2. wal is already flushed before commit
        //    (in this case, flush the rest of entries)
        // 3. user forces to manually flush wal

        struct filemgr_dirty_update_node *prev_node = NULL, *new_node = NULL;

        _fdb_dirty_update_ready(handle, &prev_node, &new_node,
                                &dirty_idtree_root, &dirty_seqtree_root, false);

        wr = handle->file->getWal()->flush_Wal((void *)handle,
                                               WalFlushCallbacks::flushItem,
                                               WalFlushCallbacks::getOldOffset,
                                               WalFlushCallbacks::purgeSeqTreeEntry,
                                               WalFlushCallbacks::updateKvsDeltaStats,
                                               &flush_items);

        if (wr != FDB_RESULT_SUCCESS) {
            if (!btreev2) {
                handle->bhandle->clearDirtyUpdate();
                FileMgr::dirtyUpdateCloseNode(prev_node);
                handle->file->dirtyUpdateRemoveNode(new_node);
            }
            handle->file->mutexUnlock();
            END_HANDLE_BUSY(handle);
            return wr;
        }
        handle->file->getWal()->setDirtyStatus_Wal(FDB_WAL_CLEAN);
        wal_flushed = true;

        _fdb_dirty_update_finalize(handle, prev_node, new_node,
                                   &dirty_idtree_root, &dirty_seqtree_root, true);
    }

    // Note: Appending KVS header must be done after flushing WAL
    //       because KVS stats info is updated during WAL flushing.
    if (handle->kvs) {
        // multi KV instance mode .. append up-to-date KV header
        handle->kv_info_offset = fdb_kvs_header_append(handle);
    }

    filemgr_header_revnum_t next_revnum;
    next_revnum = handle->file->getHeaderRevnum() + 1;

    if (handle->rollback_revnum) {
        // if this commit is called by rollback API,
        // remove all stale-tree entries related to the rollback
        handle->file->getStaleData()->rollbackStaleBlocks(handle, next_revnum);
        handle->rollback_revnum = 0;
    }

    if (wal_flushed) {
        handle->file->getStaleData()->gatherRegions(handle, next_revnum,
                                                    handle->last_hdr_bid,
                                                    handle->kv_info_offset,
                                                    handle->file->getSeqnum(),
                                                    false);
        if (btreev2) {
            // write/flush all index nodes at once
            handle->trie->writeDirtyNodes();
            if (handle->config.seqtree_opt == FDB_SEQTREE_USE) {
                if (handle->config.multi_kv_instances) {
                    handle->seqtrie->writeDirtyNodes();
                } else {
                    handle->seqtreeV2->writeDirtyNodes();
                }
            }
            handle->staletreeV2->writeDirtyNodes();
            handle->bnodeMgr->moveDirtyNodesToBcache();
            BnodeCacheMgr::get()->flush(handle->file);
            handle->bnodeMgr->markEndOfIndexBlocks();
        }
    }

    SuperblockBase *sb = handle->file->getSb();
    // Note: Getting header BID must be done after
    //       all other data are written into the file!!
    //       Or, header BID inconsistency will occur (it will
    //       point to wrong block).
    handle->last_hdr_bid = handle->file->alloc_FileMgr(&handle->log_callback);
    if (sb) {
        cur_bmp_revnum = sb->getBmpRevnum();
    } else {
        cur_bmp_revnum = 0;
    }

    if (handle->file->getWal()->getDirtyStatus_Wal() == FDB_WAL_CLEAN) {
        earliest_txn = handle->file->getWal()->getEarliestTxn_Wal(
                                        (txn)?(txn):(handle->file->getGlobalTxn()));
        if (earliest_txn) {
            filemgr_header_revnum_t last_revnum;
            last_revnum = handle->file->getHeaderRevnum(handle->last_wal_flush_hdr_bid);
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
    handle->cur_header_revnum = fdb_set_file_header(handle);

    if (txn == NULL) {
        // update global_txn's previous header BID
        handle->file->getGlobalTxn()->prev_hdr_bid = handle->last_hdr_bid;
        // reset TID (this is thread-safe as filemgr_mutex is grabbed)
        handle->file->getGlobalTxn()->prev_revnum = handle->cur_header_revnum;
    }

    if (sb) {
        // sync superblock
        sb->updateHeader(handle);
        if (sb->checkSyncPeriod() && wal_flushed) {
            sb_decision_t decision;
            bool block_reclaimed = false;

            decision = sb->checkBlockReuse(handle);
            if (decision == SBD_RECLAIM) {
                // gather reusable blocks
                if (!btreev2) {
                    handle->bhandle->discardBlocks();
                }
                block_reclaimed = sb->reclaimReusableBlocks(handle);
                if (block_reclaimed) {
                    sb->appendBmpDoc(handle);
                }
            } else if (decision == SBD_RESERVE) {
                // reserve reusable blocks
                if (!btreev2) {
                    handle->bhandle->discardBlocks();
                }
                block_reclaimed = sb->reserveNextReusableBlocks(handle);
                if (block_reclaimed) {
                    sb->appendRsvBmpDoc(handle);
                }
            } else if (decision == SBD_SWITCH) {
                // switch reserved reusable blocks
                if (!btreev2) {
                    handle->bhandle->discardBlocks();
                }
                sb->switchReservedBlocks();
            }

            if (btreev2 && decision != SBD_NONE) {
                handle->staletreeV2->writeDirtyNodes();
                handle->bnodeMgr->moveDirtyNodesToBcache();
                BnodeCacheMgr::get()->flush(handle->file);
                handle->bnodeMgr->markEndOfIndexBlocks();
            }

            // header should be updated one more time
            // since block reclaiming or stale block gathering changes root nodes
            // of each tree. but at this time we don't increase header revision number.
            handle->cur_header_revnum = fdb_set_file_header(handle);
            sb->updateHeader(handle);
            sb->syncCircular(handle);
            // reset allocation counter for next reclaim check
            sb->resetNumAlloc();
        } else {
            // update superblock for every commit
            sb->syncCircular(handle);
        }
    }

    // file commit
    fs = handle->file->commitBid(handle->last_hdr_bid,
                                 cur_bmp_revnum, sync,
                                 &handle->log_callback);
    if (wal_flushed) {
        handle->file->getWal()->releaseFlushedItems_Wal(&flush_items);
    }

    if (!btreev2) {
        handle->bhandle->resetSubblockInfo();
    }

    handle->dirty_updates = 0;
    handle->file->mutexUnlock();

    LATENCY_STAT_END(handle->file, FDB_LATENCY_COMMITS);
    handle->op_stats->num_commits++;
    END_HANDLE_BUSY(handle);
    return fs;
}

fdb_status FdbEngine::openSnapshot(FdbKvsHandle *handle_in,
                                   FdbKvsHandle **ptr_handle,
                                   fdb_seqnum_t seqnum)
{
#ifdef _MEMPOOL
    mempool_init();
#endif

    if (!handle_in || !ptr_handle) {
        return FDB_RESULT_INVALID_HANDLE;
    }

    fdb_config config = handle_in->config;
    fdb_kvs_config kvs_config = handle_in->kvs_config;
    fdb_kvs_id_t kv_id = 0;
    FdbKvsHandle *handle;
    fdb_txn *txn = NULL;
    fdb_status fs = FDB_RESULT_SUCCESS;
    FileMgr *file;
    file_status_t fMgrStatus = FILE_NORMAL;
    Snapshot dummy_shandle; // temporary snapshot handle
    struct _fdb_key_cmp_info cmp_info;
    LATENCY_STAT_START();

fdb_snapshot_open_start:
    if (!handle_in->shandle) {
        fs = fdb_check_file_reopen(handle_in, &fMgrStatus);
        if (fs != FDB_RESULT_SUCCESS) {
            return fs;
        }
        fdb_sync_db_header(handle_in);
        file = handle_in->file;

        if (handle_in->kvs && handle_in->kvs->getKvsType() == KVS_SUB) {
            handle_in->seqnum = fdb_kvs_get_seqnum(file,
                                                   handle_in->kvs->getKvsId());
        } else {
            handle_in->seqnum = file->getSeqnum();
        }
    } else {
        file = handle_in->file;
    }

    // if the max sequence number seen by this handle is lower than the
    // requested snapshot marker, it means the snapshot is not yet visible
    // even via the current FdbKvsHandle
    if (seqnum != FDB_SNAPSHOT_INMEM && seqnum > handle_in->seqnum) {
        return FDB_RESULT_NO_DB_INSTANCE;
    }

    handle = new FdbKvsHandle();
    if (!handle) { // LCOV_EXCL_START
        return FDB_RESULT_ALLOC_FAIL;
    } // LCOV_EXCL_STOP

    handle->initBusy();
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
        handle->last_hdr_bid = handle_in->last_hdr_bid.load(); // do fast rewind
        fs = file->getWal()->snapshotClone_Wal(handle_in->shandle,
                                               &handle->shandle, seqnum);
        if (fs == FDB_RESULT_SUCCESS) {
            clone_snapshot = true;
            handle->max_seqnum = FDB_SNAPSHOT_INMEM; // temp value to skip WAL
        } else {
            fdb_log(&handle_in->log_callback, fs,
                    "Warning: Snapshot clone at sequence number %" _F64
                    "does not match its snapshot handle %" _F64
                    "in file '%s'.", seqnum, handle_in->seqnum,
                    file->getFileName());
            delete handle;
            return fs;
        }
    }

    cmp_info.kvs_config = handle_in->kvs_config;
    cmp_info.kvs = handle_in->kvs;

    if (!handle->shandle) {
        txn = handle_in->fhandle->getRootHandle()->txn;
        if (!txn) {
            txn = file->getGlobalTxn();
        }
        if (handle_in->kvs) {
            kv_id = handle_in->kvs->getKvsId();
        }
        if (seqnum == FDB_SNAPSHOT_INMEM) {
            // tmp value to denote snapshot & not rollback to _fdb_open
            handle->shandle = &dummy_shandle; // dummy
        } else {
            fs = file->getWal()->snapshotOpenPersisted_Wal(seqnum,
                                                      &cmp_info, txn,
                                                      &handle->shandle);
        }
        if (fs != FDB_RESULT_SUCCESS) {
            delete handle;
            return fs;
        }
    }

    if (handle_in->kvs) {
        // sub-handle in multi KV instance mode
        if (clone_snapshot) {
            fs = _fdb_kvs_clone_snapshot(handle_in, handle);
        } else {
            fs = openKvs(handle_in->kvs->getRootHandle(),
                         &config, &kvs_config, file,
                         file->getFileName(),
                         _fdb_kvs_get_name(handle_in, file),
                         handle);
        }
    } else {
        if (clone_snapshot) {
            fs = _fdb_clone_snapshot(handle_in, handle);
        } else {
            fs = openFdb(handle, file->getFileName(), FDB_AFILENAME, &config);
        }
    }

    if (fs == FDB_RESULT_SUCCESS) {
        if (seqnum == FDB_SNAPSHOT_INMEM &&
            !handle_in->shandle) {
            handle->max_seqnum = handle_in->seqnum;

            if (!ver_btreev2_format(handle->file->getVersion())) {
                // synchronize dirty root nodes if exist
                bid_t dirty_idtree_root = BLK_NOT_FOUND;
                bid_t dirty_seqtree_root = BLK_NOT_FOUND;
                struct filemgr_dirty_update_node *dirty_update;

                dirty_update = handle->file->dirtyUpdateGetLatest();
                handle->bhandle->setDirtyUpdate(dirty_update);

                if (dirty_update) {
                    FileMgr::dirtyUpdateGetRoot(dirty_update, &dirty_idtree_root,
                                                &dirty_seqtree_root);
                    _fdb_import_dirty_root(handle, dirty_idtree_root,
                                           dirty_seqtree_root);
                    handle->bhandle->discardBlocks();
                }
            }
            // Having synced the dirty root, make an in-memory WAL snapshot
#ifdef _MVCC_WAL_ENABLE
            fs = file->getWal()->snapshotOpen_Wal(txn, kv_id, handle->seqnum,
                                                  &cmp_info, &handle->shandle);
#else
            fs = file->getWal()->snapshotOpenPersisted_Wal(handle->seqnum,
                                                      &cmp_info, txn,
                                                      &handle->shandle);
            if (fs == FDB_RESULT_SUCCESS) {
                fs = file->getWal()->copy2Snapshot_Wal(handle->shandle,
                                                  (bool)handle_in->kvs);
            }
            (void)kv_id;
#endif // _MVCC_WAL_ENABLE
        } else if (clone_snapshot) {
            // Snapshot is created on the other snapshot handle

            handle->max_seqnum = handle_in->seqnum;

            if (seqnum == FDB_SNAPSHOT_INMEM) {
                // in-memory snapshot
                // Clone dirty root nodes from the source snapshot by incrementing
                // their ref counters
                bool is_btree_v2 = ver_btreev2_format(handle->file->getVersion());
                if (is_btree_v2) {
                    handle->trie->setRootAddr(handle_in->trie->getRootAddr());
                } else {
                    handle->trie->setRootBid(handle_in->trie->getRootBid());
                }
                if (handle->config.seqtree_opt == FDB_SEQTREE_USE) {
                    if (handle->kvs) {
                        if (is_btree_v2) {
                            handle->seqtrie->setRootAddr(handle_in->seqtrie->getRootAddr());
                        } else {
                            handle->seqtrie->setRootBid(handle_in->seqtrie->getRootBid());
                        }
                    } else {
                        if (is_btree_v2) {
                            handle->seqtreeV2->initFromAddr(
                                handle_in->seqtreeV2->getRootAddr());
                        } else {
                            handle->seqtree->setRootBid(handle_in->seqtree->getRootBid());
                        }
                    }
                }
                if (!is_btree_v2) {
                    handle->bhandle->discardBlocks();

                    // increase ref count for dirty update
                    struct filemgr_dirty_update_node *dirty_update;
                    dirty_update = handle_in->bhandle->getDirtyUpdate();
                    FileMgr::dirtyUpdateIncRefCount(dirty_update);
                    handle->bhandle->setDirtyUpdate(dirty_update);
                }
            }
        }
        *ptr_handle = handle;
    } else {
        *ptr_handle = NULL;
        if (clone_snapshot || seqnum != FDB_SNAPSHOT_INMEM) {
            handle->file->getWal()->snapshotClose_Wal(handle->shandle);
        }
        delete handle;

        // If compactor thread had finished compaction just before this routine
        // calls _fdb_open, then it is possible that the snapshot's DB header
        // is only present in the new_file. So we must retry the snapshot
        // open attempt IFF _fdb_open indicates FDB_RESULT_NO_DB_INSTANCE..
        if (fs == FDB_RESULT_NO_DB_INSTANCE && fMgrStatus == FILE_COMPACT_OLD) {
            if (file->getFileStatus() == FILE_REMOVED_PENDING) {
                goto fdb_snapshot_open_start;
            }
        }
    }

    if (handle_in->shandle) {
        LATENCY_STAT_END(file, FDB_LATENCY_SNAP_CLONE);
    } else if (seqnum == FDB_SNAPSHOT_INMEM) {
        LATENCY_STAT_END(file, FDB_LATENCY_SNAP_INMEM);
    } else {
        LATENCY_STAT_END(file, FDB_LATENCY_SNAP_DUR);
    }
    return fs;
}

fdb_status FdbEngine::rollback(FdbKvsHandle **handle_ptr, fdb_seqnum_t seqnum)
{
#ifdef _MEMPOOL
    mempool_init();
#endif

    fdb_config config;
    FdbKvsHandle *handle_in, *handle;
    fdb_status fs;
    fdb_seqnum_t old_seqnum;

    if (!handle_ptr) {
        return FDB_RESULT_INVALID_HANDLE;
    }

    handle_in = *handle_ptr;

    if (!handle_in) {
        return FDB_RESULT_INVALID_HANDLE;
    }

    config = handle_in->config;

    if (handle_in->kvs) {
        return rollbackKvs(handle_ptr, seqnum);
    }

    if (handle_in->config.flags & FDB_OPEN_FLAG_RDONLY) {
        return fdb_log(&handle_in->log_callback, FDB_RESULT_RONLY_VIOLATION,
                       "Warning: Rollback is not allowed on the read-only DB file '%s'.",
                       handle_in->file->getFileName());
    }

    if (!BEGIN_HANDLE_BUSY(handle_in)) {
        return FDB_RESULT_HANDLE_BUSY;
    }

    handle_in->file->mutexLock();
    handle_in->file->setRollback(1); // disallow writes operations
    // All transactions should be closed before rollback
    if (handle_in->file->getWal()->doesTxnExist_Wal()) {
        handle_in->file->setRollback(0);
        handle_in->file->mutexUnlock();
        END_HANDLE_BUSY(handle_in);
        return FDB_RESULT_FAIL_BY_TRANSACTION;
    }

    // If compaction is running, wait until it is aborted.
    // TODO: Find a better way of waiting for the compaction abortion.
    unsigned int sleep_time = 10000; // 10 ms.
    file_status_t fMgrStatus = handle_in->file->getFileStatus();
    while (fMgrStatus == FILE_COMPACT_OLD) {
        handle_in->file->mutexUnlock();
        decaying_usleep(&sleep_time, 1000000);
        handle_in->file->mutexLock();
        fMgrStatus = handle_in->file->getFileStatus();
    }
    if (fMgrStatus == FILE_REMOVED_PENDING) {
        handle_in->file->mutexUnlock();
        fs = fdb_check_file_reopen(handle_in, NULL);
        if (fs != FDB_RESULT_SUCCESS) {
            END_HANDLE_BUSY(handle_in);
            return fs;
        }
    } else {
        handle_in->file->mutexUnlock();
    }

    fdb_sync_db_header(handle_in);

    // if the max sequence number seen by this handle is lower than the
    // requested snapshot marker, it means the snapshot is not yet visible
    // even via the current FdbKvsHandle
    if (seqnum > handle_in->seqnum) {
        handle_in->file->setRollback(0); // allow mutations
        END_HANDLE_BUSY(handle_in);
        return FDB_RESULT_NO_DB_INSTANCE;
    }

    handle = new FdbKvsHandle();
    if (!handle) { // LCOV_EXCL_START
        END_HANDLE_BUSY(handle_in);
        return FDB_RESULT_ALLOC_FAIL;
    } // LCOV_EXCL_STOP

    handle->initBusy();
    handle->log_callback = handle_in->log_callback;
    handle->fhandle = handle_in->fhandle;
    if (seqnum == 0) {
        fs = _fdb_reset(handle, handle_in);
    } else {
        handle->max_seqnum = seqnum;
        fs = openFdb(handle, handle_in->file->getFileName(), FDB_AFILENAME, &config);
    }

    handle_in->file->setRollback(0); // allow mutations
    if (fs == FDB_RESULT_SUCCESS) {
        // rollback the file's sequence number
        handle_in->file->mutexLock();
        old_seqnum = handle_in->file->getSeqnum();
        handle_in->file->setSeqnum(seqnum);
        handle_in->file->mutexUnlock();

        bool sync = !(handle_in->config.durability_opt & FDB_DRB_ASYNC);
        fs = commitWithKVHandle(handle, FDB_COMMIT_MANUAL_WAL_FLUSH, sync);
        if (fs == FDB_RESULT_SUCCESS) {
            if (handle_in->txn) {
                handle->txn = handle_in->txn;
                handle_in->txn = NULL;
            }
            closeKvsInternal(handle_in);
            // Link this handle into the file..
            handle->fhandle->createNLinkKVHandle(handle);
            delete handle_in;
            handle->max_seqnum = 0;
            handle->seqnum = seqnum;
            *handle_ptr = handle;
        } else {
            // cancel the rolling-back of the sequence number
            handle_in->file->mutexLock();
            handle_in->file->setSeqnum(old_seqnum);
            handle_in->file->mutexUnlock();
            delete handle;
            END_HANDLE_BUSY(handle_in);
        }
    } else {
        delete handle;
        END_HANDLE_BUSY(handle_in);
    }

    return fs;
}

fdb_status FdbEngine::rollbackAll(FdbFileHandle *fhandle,
                                  fdb_snapshot_marker_t marker)
{
#ifdef _MEMPOOL
    mempool_init();
#endif

    fdb_config config;
    FdbKvsHandle *super_handle;
    FdbKvsHandle rhandle;
    FdbKvsHandle *handle = &rhandle;
    FileMgr *file;
    fdb_kvs_config kvs_config;
    fdb_status fs;
    ErrLogCallback log_callback;
    KvsInfo *kvs;
    Snapshot shandle; // temporary snapshot handle

    if (!fhandle) {
        return FDB_RESULT_INVALID_HANDLE;
    }

    super_handle = fhandle->getRootHandle();
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

    if (super_handle->config.flags & FDB_OPEN_FLAG_RDONLY) {
        return fdb_log(&super_handle->log_callback, FDB_RESULT_RONLY_VIOLATION,
                       "Warning: Rollback is not allowed on the read-only DB file '%s'.",
                       super_handle->file->getFileName());
    }

    super_handle->file->mutexLock();
    super_handle->file->setRollback(1); // disallow writes operations
    // All transactions should be closed before rollback
    if (super_handle->file->getWal()->doesTxnExist_Wal()) {
        super_handle->file->setRollback(0);
        super_handle->file->mutexUnlock();
        return FDB_RESULT_FAIL_BY_TRANSACTION;
    }

    // If compaction is running, wait until it is aborted.
    // TODO: Find a better way of waiting for the compaction abortion.
    unsigned int sleep_time = 10000; // 10 ms.
    file_status_t fMgrStatus = super_handle->file->getFileStatus();
    while (fMgrStatus == FILE_COMPACT_OLD) {
        super_handle->file->mutexUnlock();
        decaying_usleep(&sleep_time, 1000000);
        super_handle->file->mutexLock();
        fMgrStatus = super_handle->file->getFileStatus();
    }
    if (fMgrStatus == FILE_REMOVED_PENDING) {
        super_handle->file->mutexUnlock();
        fs = fdb_check_file_reopen(super_handle, NULL);
        if (fs != FDB_RESULT_SUCCESS) {
            return fs;
        }
    } else {
        super_handle->file->mutexUnlock();
    }

    fdb_sync_db_header(super_handle);
    // Shutdown WAL discarding entries from all KV Stores..
    fs = super_handle->file->getWal()->shutdown_Wal(&super_handle->log_callback);
    if (fs != FDB_RESULT_SUCCESS) {
        return fs;
    }

    handle->log_callback = log_callback;
    handle->fhandle = fhandle;
    handle->last_hdr_bid = (bid_t)marker; // Fast rewind on open
    handle->max_seqnum = FDB_SNAPSHOT_INMEM; // Prevent WAL restore on open
    handle->shandle = &shandle; // a dummy handle to prevent WAL restore
    if (kvs) {
        fdb_kvs_header_free(file); // KV header will be recreated below.
        handle->kvs = new KvsInfo(*kvs); // re-use super_handle's kvs info
        handle->kvs_config = kvs_config;
    }
    handle->config = config;

    fs = openFdb(handle, file->getFileName(), FDB_AFILENAME, &config);

    if (handle->config.multi_kv_instances) {
        handle->file->mutexLock();
        fdb_kvs_header_create(handle->file);
        fdb_kvs_header_read(handle->file->getKVHeader_UNLOCKED(), handle->dhandle,
                            handle->kv_info_offset,
                            handle->file->getVersion(), false);
        handle->file->mutexUnlock();
    }

    file->setRollback(0); // allow mutations
    handle->shandle = NULL; // just a dummy handle never allocated

    if (fs == FDB_RESULT_SUCCESS) {
        fdb_seqnum_t old_seqnum;
        // Restore WAL for all KV instances...
        _fdb_restore_wal(handle, FDB_RESTORE_NORMAL, (bid_t)marker, 0);

        // rollback the file's sequence number
        file->mutexLock();
        old_seqnum = file->getSeqnum();
        file->setSeqnum(handle->seqnum);
        file->mutexUnlock();

        bool sync = !(handle->config.durability_opt & FDB_DRB_ASYNC);
        fs = commitWithKVHandle(handle, FDB_COMMIT_NORMAL, sync);
        if (fs == FDB_RESULT_SUCCESS) {
            closeKVHandle(super_handle);
            *super_handle = *handle;
        } else {
            file->mutexLock();
            file->setSeqnum(old_seqnum);
            file->mutexUnlock();
        }
    } else { // Rollback failed, restore KV header
        fdb_kvs_header_create(file);
        fdb_kvs_header_read(file->getKVHeader_UNLOCKED(), super_handle->dhandle,
                            super_handle->kv_info_offset,
                            ver_get_latest_magic(),
                            false);
    }

    return fs;
}

fdb_status FdbEngine::compact(FdbFileHandle *fhandle,
                              const char *new_filename,
                              fdb_snapshot_marker_t marker,
                              bool clone_docs,
                              const fdb_encryption_key *new_encryption_key)
{
    if (!fhandle || !fhandle->getRootHandle()) {
        return FDB_RESULT_INVALID_HANDLE;
    }

    FdbKvsHandle *handle = fhandle->getRootHandle();
    bool in_place_compaction = false;
    std::string filename_str(handle->file->getFileName());
    std::string nextfile;
    fdb_status fs;

    if (!BEGIN_HANDLE_BUSY(handle)) {
        return FDB_RESULT_HANDLE_BUSY;
    }

    if (handle->config.compaction_mode == FDB_COMPACTION_MANUAL) {
        // manual compaction
        if (!new_filename) { // In-place compaction.
            in_place_compaction = true;
            nextfile = CompactionManager::getInstance()->getNextFileName(filename_str);
            new_filename = nextfile.c_str();
        }
        fs = Compaction::compactFile(fhandle, new_filename, in_place_compaction,
                                     (bid_t)marker, clone_docs, new_encryption_key);
    } else { // auto compaction mode.
        bool ret;
        // set compaction flag
        ret = CompactionManager::getInstance()->switchCompactionFlag(handle->file,
                                                                     true);
        if (!ret) {
            END_HANDLE_BUSY(handle);
            // the file is already being compacted by other thread
            return FDB_RESULT_FILE_IS_BUSY;
        }
        // get next filename
        nextfile = CompactionManager::getInstance()->getNextFileName(filename_str);
        fs = Compaction::compactFile(fhandle, nextfile.c_str(), in_place_compaction,
                                     (bid_t)marker, clone_docs, new_encryption_key);
        // clear compaction flag
        ret = CompactionManager::getInstance()->switchCompactionFlag(handle->file,
                                                                     false);
        (void)ret;
    }
    END_HANDLE_BUSY(handle);
    return fs;
}

fdb_status FdbEngine::cancelCompaction(FdbFileHandle *fhandle)
{
    if (!fhandle) {
        return FDB_RESULT_INVALID_HANDLE;
    }

    FdbKvsHandle *super_handle = fhandle->getRootHandle();

    super_handle->file->mutexLock();
    super_handle->file->setCancelCompaction(true);

    // TODO: Find a better way of cacncelling the ongoing compaction task.
    unsigned int sleep_time = 10000; // 10 ms.
    file_status_t fMgrStatus = super_handle->file->getFileStatus();
    while (fMgrStatus == FILE_COMPACT_OLD) {
        super_handle->file->mutexUnlock();
        decaying_usleep(&sleep_time, 1000000);
        super_handle->file->mutexLock();
        fMgrStatus = super_handle->file->getFileStatus();
    }
    super_handle->file->setCancelCompaction(false);
    super_handle->file->mutexUnlock();
    return FDB_RESULT_SUCCESS;
}

fdb_status FdbEngine::setDaemonCompactionInterval(FdbFileHandle *fhandle,
                                                  size_t interval)
{
    if (!fhandle || !fhandle->getRootHandle()) {
        return FDB_RESULT_INVALID_HANDLE;
    }

    FdbKvsHandle *handle = fhandle->getRootHandle();

    if (handle->config.compaction_mode == FDB_COMPACTION_AUTO) {
        return CompactionManager::getInstance()->setCompactionInterval(handle->file,
                                                                       interval);
    } else {
        return FDB_RESULT_INVALID_CONFIG;
    }
}

fdb_status FdbEngine::reKey(FdbFileHandle *fhandle,
                            fdb_encryption_key new_key)
{
    return compact(fhandle, NULL, BLK_NOT_FOUND, false, &new_key);
}

size_t FdbEngine::getBufferCacheUsed() {
    return (size_t) FileMgr::getBcacheUsedSpace();
}

size_t FdbEngine::estimateSpaceUsedInternal(FdbKvsHandle *handle)
{
    size_t ret = 0;
    size_t datasize;
    size_t nlivenodes;
    FileMgr *file = handle->file;

    datasize = file->getKvsStatOps()->statGetSum(KVS_STAT_DATASIZE);
    nlivenodes = file->getKvsStatOps()->statGetSum(KVS_STAT_NLIVENODES);

    ret = datasize;
    ret += nlivenodes * handle->config.blocksize;
    ret += handle->file->getWal()->getDataSize_Wal();

    return ret;
}

size_t FdbEngine::estimateSpaceUsed(FdbFileHandle *fhandle)
{
    FdbKvsHandle *handle = NULL;

    if (!fhandle) {
        return 0;
    }

    handle = fhandle->getRootHandle();

    fdb_status fs = fdb_check_file_reopen(handle, NULL);
    if (fs != FDB_RESULT_SUCCESS) {
        return 0;
    }

    fdb_sync_db_header(handle);
    return estimateSpaceUsedInternal(handle);
}

size_t FdbEngine::estimateSpaceUsedFrom(FdbFileHandle *fhandle,
                                        fdb_snapshot_marker_t marker)
{
    uint64_t deltasize;
    size_t ret = 0;
    FdbKvsHandle *handle;
    FileMgr *file;
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
    file_status_t fMgrStatus;
    fdb_status status;

    if (!fhandle || !marker) {
        return 0;
    }
    handle = fhandle->getRootHandle();
    if (!handle->file) {
        fdb_log(&handle->log_callback, FDB_RESULT_FILE_NOT_OPEN,
                "File not open.");
        return 0;
    }

    status = fdb_check_file_reopen(handle, &fMgrStatus);
    if (status != FDB_RESULT_SUCCESS) {
        return 0;
    }
    fdb_sync_db_header(handle);

    // Start loading from current header
    file = handle->file;
    header_len = handle->file->accessHeader()->size;

    // Reverse scan the file only summing up the delta.....
    while (marker <= hdr_bid) {
        if (hdr_bid == BLK_NOT_FOUND) {
            hdr_bid = handle->last_hdr_bid;
            status = file->fetchHeader(hdr_bid, header_buf, &header_len, NULL,
                                       NULL, &deltasize, &version, NULL,
                                       &handle->log_callback);
        } else {
            prev_bid = file->fetchPrevHeader(hdr_bid, header_buf, &header_len,
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
                int64_t doc_offset;
                struct docio_object doc;
                memset(&doc, 0, sizeof(struct docio_object));
                doc_offset = handle->dhandle->readDoc_Docio(kv_info_offset,
                                            &doc, true);
                if (doc_offset <= 0) {
                    fdb_log(&handle->log_callback, (fdb_status) doc_offset,
                            "Read failure estimate_space_used.");
                    return 0;
                }
                ret += _kvs_stat_get_sum_attr(doc.body, version,
                                              KVS_STAT_DELTASIZE);

                free_docio_object(&doc, true, true, true);
            }
        }
    }

    return ret;
}

fdb_status FdbEngine::getFileInfo(FdbFileHandle *fhandle, fdb_file_info *info)
{
    uint64_t ndocs, ndeletes;
    FdbKvsHandle *handle;
    fdb_status status = FDB_RESULT_SUCCESS;

    if (!fhandle) {
        return FDB_RESULT_INVALID_HANDLE;
    }

    if (!info) {
        return FDB_RESULT_INVALID_ARGS;
    }
    handle = fhandle->getRootHandle();

    status = fdb_check_file_reopen(handle, NULL);
    if (status != FDB_RESULT_SUCCESS) {
        return status;
    }

    fdb_sync_db_header(handle);

    if (handle->config.compaction_mode == FDB_COMPACTION_AUTO) {
        // compaction daemon mode
        info->filename = handle->filename.c_str();
    } else {
        info->filename = handle->file->getFileName();
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
    size_t wal_docs = handle->file->getWal()->getNumDocs_Wal();
    size_t wal_deletes = handle->file->getWal()->getNumDeletes_Wal();
    size_t wal_n_inserts = wal_docs - wal_deletes;

    ndocs = handle->file->getKvsStatOps()->statGetSum(KVS_STAT_NDOCS);

    if (ndocs + wal_n_inserts < wal_deletes) {
        info->doc_count = 0;
    } else {
        if (ndocs) {
            info->doc_count = ndocs + wal_n_inserts - wal_deletes;
        } else {
            info->doc_count = wal_n_inserts;
        }
    }

    ndeletes = handle->file->getKvsStatOps()->statGetSum(KVS_STAT_NDELETES);
    if (ndeletes) { // not accurate since some ndeletes may be wal_deletes
        info->deleted_count = ndeletes + wal_deletes;
    } else { // this is accurate since it reflects only wal_ndeletes
        info->deleted_count = wal_deletes;
    }

    info->space_used = estimateSpaceUsed(fhandle);
    info->file_size = handle->file->getPos();

    // Get the number of KV store instances in a given ForestDB file.
    KvsHeader *kv_header = handle->file->getKVHeader_UNLOCKED();
    size_t num = 1; // default KV store.
    if (kv_header) {
        spin_lock(&kv_header->lock);
        num += kv_header->num_kv_stores;
        spin_unlock(&kv_header->lock);
    }
    info->num_kv_stores = num;

    return status;
}

fdb_status FdbEngine::getLatencyStats(FdbFileHandle *fhandle,
                                      fdb_latency_stat *stat,
                                      fdb_latency_stat_type type)
{
    if (!fhandle || !fhandle->getRootHandle()) {
        return FDB_RESULT_INVALID_HANDLE;
    }

    if (!stat || type >= FDB_LATENCY_NUM_STATS) {
        return FDB_RESULT_INVALID_ARGS;
    }

    if (!fhandle->getRootHandle()->file) {
        return FDB_RESULT_FILE_NOT_OPEN;
    }

#ifdef _LATENCY_STATS
    LatencyStats::get(fhandle->getRootHandle()->file, type, stat);
#endif // _LATENCY_STATS

    return FDB_RESULT_SUCCESS;
}

fdb_status FdbEngine::getLatencyHistogram(FdbFileHandle *fhandle,
                                          char **stats,
                                          size_t *stats_length,
                                          fdb_latency_stat_type type)
{
    if (!fhandle || !fhandle->getRootHandle()) {
        return FDB_RESULT_INVALID_HANDLE;
    }

    if (!stats || type >= FDB_LATENCY_NUM_STATS) {
        return FDB_RESULT_INVALID_ARGS;
    }

    if (!fhandle->getRootHandle()->file){
        return FDB_RESULT_FILE_NOT_OPEN;
    }

#if defined(_LATENCY_STATS) && defined(_PLATFORM_LIB_AVAILABLE)
    LatencyStats::getHistogram(fhandle->getRootHandle()->file, type,
                               stats, stats_length);
#else
    *stats = nullptr;
    *stats_length = 0;
#endif

    return FDB_RESULT_SUCCESS;
}

const char* FdbEngine::getLatencyStatName(fdb_latency_stat_type type)
{
    return FileMgr::getLatencyStatName(type);
}

fdb_status FdbEngine::getAllSnapMarkers(FdbFileHandle *fhandle,
                                        fdb_snapshot_info_t **markers_out,
                                        uint64_t *num_markers)
{
    FdbKvsHandle *handle;
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
    file_status_t fMgrStatus;
    filemgr_header_revnum_t revnum;
    fdb_status status = FDB_RESULT_SUCCESS;

    if (!fhandle) {
        return FDB_RESULT_INVALID_HANDLE;
    }

    if (!markers_out || !num_markers) {
        return FDB_RESULT_INVALID_ARGS;
    }

    handle = fhandle->getRootHandle();
    if (!handle->file) {
        return FDB_RESULT_FILE_NOT_OPEN;
    }

    status = fdb_check_file_reopen(handle, &fMgrStatus);
    if (status != FDB_RESULT_SUCCESS) {
        return status;
    }
    fdb_sync_db_header(handle);

    SuperblockBase *sb = handle->file->getSb();
    uint64_t sb_min_live_revnum = 0;
    if (sb) {
        sb_min_live_revnum = sb->getMinLiveHdrRevnum();
    }

    // There are as many DB headers in a file as the file's header revision num
    array_size = handle->cur_header_revnum - sb_min_live_revnum;
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
    header_len = handle->file->accessHeader()->size;
    size = 0;

    uint64_t num_keeping_headers = handle->file->getConfig()->getNumKeepingHeaders();

    // Reverse scan the file to locate the DB header with seqnum marker
    for (i = 0; header_len; ++i, ++size) {
        if (handle->config.block_reusing_threshold > 0 &&
            handle->config.block_reusing_threshold < 100 &&
            size >= num_keeping_headers) {
            // if block reuse is enabled,
            // do not allow to scan beyond the config parameter
            break;
        }

        if (i == 0) {
            status = handle->file->fetchHeader(handle->last_hdr_bid,
                                               header_buf, &header_len, NULL,
                                               &revnum, NULL, &version, NULL,
                                               &handle->log_callback);
        } else {
            if ((uint64_t)i >= array_size) {
                break;
            }
            hdr_bid = handle->file->fetchPrevHeader(hdr_bid, header_buf,
                                                    &header_len, &seqnum,
                                                    &revnum, NULL, &version,
                                                    NULL, &handle->log_callback);
        }
        if (header_len == 0) {
            break; // header doesn't exist, terminate iteration
        }
        if (ver_superblock_support(version) &&
            revnum < sb_min_live_revnum) {
            break; // eariler than the last block reclaiming
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
                freeSnapMarkers(markers, i);
                return FDB_RESULT_ALLOC_FAIL;
            } // LCOV_EXCL_STOP
            markers[i].kvs_markers->seqnum = seqnum;
            markers[i].kvs_markers->kv_store_name = NULL;
        } else { // Multi kv instance mode
            int64_t doc_offset;
            struct docio_object doc;
            memset(&doc, 0, sizeof(struct docio_object));
            doc_offset = handle->dhandle->readDoc_Docio(kv_info_offset, &doc,
                                                         true);
            if (doc_offset <= 0) {
                freeSnapMarkers(markers, i);
                return doc_offset < 0 ? (fdb_status) doc_offset : FDB_RESULT_READ_FAIL;
            }
            status = _fdb_kvs_get_snap_info(doc.body, version,
                                            &markers[i]);
            if (status != FDB_RESULT_SUCCESS) { // LCOV_EXCL_START
                freeSnapMarkers(markers, i);
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
            free_docio_object(&doc, true, true, true);
        }
    }

    *num_markers = size;

    if (size == 0) {
        // No Snap Markers found
        freeSnapMarkers(markers, array_size);
        return FDB_RESULT_NO_DB_INSTANCE;
    }

    *markers_out = markers;

    return status;
}

fdb_status FdbEngine::freeSnapMarkers(fdb_snapshot_info_t *markers,
                                      uint64_t size) {
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
        }
        free(markers[i].kvs_markers);
    }
    free(markers);
    return FDB_RESULT_SUCCESS;
}

fdb_status FdbEngine::switchCompactionMode(FdbFileHandle *fhandle,
                                           fdb_compaction_mode_t mode,
                                           size_t new_threshold)
{
    if (!fhandle || !fhandle->getRootHandle()) {
        return FDB_RESULT_INVALID_HANDLE;
    }

    int ret;
    fdb_status fs;
    FdbKvsHandle *handle = fhandle->getRootHandle();
    fdb_config config;
    char vfilename[FDB_MAX_FILENAME_LEN];
    char filename[FDB_MAX_FILENAME_LEN];
    char metafile[FDB_MAX_FILENAME_LEN];

    if (new_threshold > 100) {
        return FDB_RESULT_INVALID_ARGS;
    }

    config = handle->config;
    if (handle->config.compaction_mode != mode) {
        if (handle->file->getRefCount() > 1) {
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
            // deregistered by calling closeKVHandle().
            if (CompactionManager::getInstance()->switchCompactionFlag(handle->file, true)
                == false) {
                return FDB_RESULT_FILE_IS_BUSY;
            }

            strcpy(vfilename, handle->filename.c_str());
            strcpy(filename, handle->file->getFileName());
            fs = closeKVHandle(handle);
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
            fs = openFdb(handle, vfilename, FDB_VFILENAME, &config);
            if (fs != FDB_RESULT_SUCCESS) {
                return fs;
            }
        } else if (handle->config.compaction_mode == FDB_COMPACTION_MANUAL) {
            // 1. rename [filename] as [filename].rev_num
            std::string filename_str(handle->file->getFileName());
            strcpy(vfilename, filename_str.c_str());
            std::string nextfile = CompactionManager::getInstance()->
                getNextFileName(filename_str);
            fs = closeKVHandle(handle);
            if (fs != FDB_RESULT_SUCCESS) {
                return fs;
            }
            if ((ret = rename(vfilename, nextfile.c_str())) < 0) {
                return FDB_RESULT_FILE_RENAME_FAIL;
            }
            config.compaction_mode = FDB_COMPACTION_AUTO;
            config.compaction_threshold = new_threshold;
            fs = openFdb(handle, vfilename, FDB_VFILENAME, &config);
            if (fs != FDB_RESULT_SUCCESS) {
                return fs;
            }

        } else {
            return FDB_RESULT_INVALID_ARGS;
        }
    } else {
        if (handle->config.compaction_mode == FDB_COMPACTION_AUTO) {
            // change compaction threshold of the existing file
            CompactionManager::getInstance()->setCompactionThreshold(handle->file,
                                                                     new_threshold);
        }
    }
    return FDB_RESULT_SUCCESS;
}

fdb_status FdbEngine::closeFile(FdbFileHandle *fhandle)
{
    if (!fhandle) {
        return FDB_RESULT_INVALID_HANDLE;
    }

    fdb_status fs;
    FdbKvsHandle *handle = fhandle->getRootHandle();
    FileMgr *file = handle->file;
    if (handle->config.auto_commit && file->getRefCount() == 1) {
        // auto commit mode & the last handle referring the file
        // commit file before close
        if (file->getWal()->getDirtyStatus_Wal() == FDB_WAL_DIRTY) {
            // Since auto-commit ensures WAL flushed commit, if WAL is dirty
            // then it means that there is uncommitted data present
            fs = commit(fhandle, FDB_COMMIT_MANUAL_WAL_FLUSH);
            if (fs != FDB_RESULT_SUCCESS) {
                return fs;
            }
        }
    }

    file->fhandleRemove(fhandle);
    fs = closeRootHandle(handle);
    if (fs == FDB_RESULT_SUCCESS) {
        fhandle->closeAllKVHandles();
        delete fhandle;
    } else {
        file->fhandleAdd(fhandle);
    }
    return fs;
}

fdb_status FdbEngine::closeRootHandle(FdbKvsHandle *handle)
{
    fdb_status fs;

    if (!handle) {
        return FDB_RESULT_SUCCESS;
    }
    if (handle->kvs) {
        if (handle->kvs->getKvsType() == KVS_SUB) {
            return closeKvs(handle);
        } else if (handle->kvs->getKvsType() == KVS_ROOT) {
            // close all sub-handles
            fs = handle->fhandle->closeAllKVHandles();
            if (fs != FDB_RESULT_SUCCESS) {
                return fs;
            }
        }
    }
    if (handle->txn) {
        abortTransaction(handle->fhandle);
    }

    SuperblockBase *sb = handle->file->getSb();
    if (sb && !(handle->config.flags & FDB_OPEN_FLAG_RDONLY)) {
        // sync superblock before close (only for writable handles)
        fdb_sync_db_header(handle);
        bool updated = sb->updateHeader(handle);
        if (updated) {
            sb->syncCircular(handle);
        }
    }

    fs = closeKVHandle(handle);
    if (fs == FDB_RESULT_SUCCESS) {
        delete handle;
    }
    return fs;
}

fdb_status FdbEngine::closeKVHandle(FdbKvsHandle *handle)
{
    fdb_status fs;
    if (!(handle->config.flags & FDB_OPEN_FLAG_RDONLY)) {
        if (handle->config.compaction_mode == FDB_COMPACTION_AUTO) {
            // read-only file is not registered in compactor
            CompactionManager::getInstance()->deregisterFile(handle->file);
        }
        BgFlusher *bgf = BgFlusher::getBgfInstance();
        if (bgf) {
            bgf->deregisterFile_BgFlusher(handle->file);
        }
    }

    bool is_btree_v2 = ver_btreev2_format(handle->file->getVersion());
    if (is_btree_v2) {
        handle->bnodeMgr->releaseCleanNodes();
    } else {
        handle->bhandle->flushBuffer();
    }

    if (handle->shandle) { // must close wal_snapshot before file
        handle->file->getWal()->snapshotClose_Wal(handle->shandle);
        if (!is_btree_v2) {
            FileMgr::dirtyUpdateCloseNode(handle->bhandle->getDirtyUpdate());
            handle->bhandle->clearDirtyUpdate();
        }
    }

    fs = FileMgr::close(handle->file, handle->config.cleanup_cache_onclose,
                        handle->filename.c_str(), &handle->log_callback);
    if (fs != FDB_RESULT_SUCCESS) {
        return fs;
    }
    delete handle->trie;

    if (handle->config.seqtree_opt == FDB_SEQTREE_USE) {
        if (handle->kvs) {
            // multi KV instance mode
            delete handle->seqtrie;
        } else {
            if (is_btree_v2) {
                delete handle->seqtreeV2;
            } else {
                delete handle->seqtree->getKVOps();
                delete handle->seqtree;
            }
        }
    }

    if (is_btree_v2) {
        delete handle->staletreeV2;
    } else {
        if (handle->staletree) {
            delete handle->staletree->getKVOps();
            delete handle->staletree;
        }
    }

    if (is_btree_v2) {
        delete handle->bnodeMgr;
    } else {
        delete handle->bhandle;
    }
    delete handle->dhandle;

    return fs;
}

fdb_status FdbEngine::destroyFile(const char *fname,
                                  fdb_config *fdbconfig)
{
#ifdef _MEMPOOL
    mempool_init();
#endif

    fdb_config config;
    FileMgrConfig fconfig;
    fdb_status status = FDB_RESULT_SUCCESS;
    std::string filename(fname);

    if (fdbconfig) {
        if (FdbEngine::validateFdbConfig(*fdbconfig)) {
            config = *fdbconfig;
        } else {
            return FDB_RESULT_INVALID_CONFIG;
        }
    } else {
        config = get_default_config();
    }

    if (!CompactionManager::getInstance()->isValidCompactionMode(filename,config)) {
        status = FDB_RESULT_INVALID_COMPACTION_MODE;
        return status;
    }

    FdbEngine::initFileConfig(&config, &fconfig);

    FileMgr::mutexOpenlock(&fconfig);

    // Destroy the file whose name is exactly matched.
    // In auto compaction mode, exact matching file name does not exist in
    // the file system, so we allow failure returned by this function.
    status = FileMgr::destroyFile(filename, &fconfig, NULL);
    if (status != FDB_RESULT_SUCCESS &&
        config.compaction_mode != FDB_COMPACTION_AUTO) {
        FileMgr::mutexOpenunlock();
        return status;
    }

    if (config.compaction_mode == FDB_COMPACTION_AUTO) {
        // Destroy all files whose prefix is matched in the auto compaction mode.
        status = CompactionManager::getInstance()->destroyFile(filename, config);
        if (status != FDB_RESULT_SUCCESS) {
            FileMgr::mutexOpenunlock();
            return status;
        }
    }

    FileMgr::mutexOpenunlock();

    return status;
}

fdb_status FdbEngine::setBlockReusingParams(FdbFileHandle *fhandle,
                                            size_t block_reusing_threshold,
                                            size_t num_keeping_headers)
{
    if (!fhandle || !fhandle->getRootHandle()) {
        return FDB_RESULT_INVALID_HANDLE;
    }
    FileMgr *file = fhandle->getRootHandle()->file;
    file->getConfig()->setBlockReusingThreshold(block_reusing_threshold);
    file->getConfig()->setNumKeepingHeaders(num_keeping_headers);
    return FDB_RESULT_SUCCESS;
}

const char* FdbEngine::getLibVersion()
{
    return FORESTDB_VERSION;
}

const char* FdbEngine::getFileVersion(fdb_file_handle *fhandle)
{
    if (!fhandle || !fhandle->getRootHandle()) {
        return "Error: file not opened yet!!!";
    }
    return ver_get_version_string(fhandle->getRootHandle()->file->getVersion());
}

fdb_filemgr_ops_t* FdbEngine::getDefaultFileOps(void) {
    return (fdb_filemgr_ops_t *) get_filemgr_ops();
}

fdb_status FdbEngine::fetchHandleStats(fdb_kvs_handle *handle,
                                       fdb_handle_stats_cb stat_callback,
                                       void *ctx) {
    if (!handle) {
        return FDB_RESULT_INVALID_HANDLE;
    } else if (!handle->file) {
        return FDB_RESULT_FILE_NOT_OPEN;
    }

    stat_callback(handle, "Num_wal_shards",
                  static_cast<uint64_t>(handle->file->getConfig()->getNumWalShards()),
                  ctx);
    stat_callback(handle, "Num_bcache_shards",
                  static_cast<uint64_t>(handle->file->getConfig()->getNumBcacheShards()),
                  ctx);
    stat_callback(handle, "Block_cache_hits",
                  static_cast<uint64_t>(handle->file->fetchBlockCacheHits()),
                  ctx);
    stat_callback(handle, "Block_cache_misses",
                  static_cast<uint64_t>(handle->file->fetchBlockCacheMisses()),
                  ctx);
    stat_callback(handle, "Block_cache_num_items",
                  handle->file->getBCacheItems(),
                  ctx);
    stat_callback(handle, "Block_cache_num_victims",
                  handle->file->getBCacheVictims(),
                  ctx);
    stat_callback(handle, "Block_cache_num_immutables",
                  handle->file->getBCacheImmutables(),
                  ctx);

    return FDB_RESULT_SUCCESS;
}

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

// A stale sequence number entry that can be purged from the sequence tree
// during the WAL flush.
struct wal_stale_seq_entry {
    fdb_kvs_id_t kv_id;
    fdb_seqnum_t seqnum;
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

fdb_status WalFlushCallbacks::flushItem(void *dbhandle,
                                        struct wal_item *item,
                                        struct avl_tree *stale_seqnum_list,
                                        struct avl_tree *kvs_delta_stats)
{
    hbtrie_result hr;
    FdbKvsHandle *handle = reinterpret_cast<FdbKvsHandle *>(dbhandle);
    fdb_seqnum_t _seqnum;
    fdb_kvs_id_t kv_id = 0;
    fdb_status fs = FDB_RESULT_SUCCESS;
    uint8_t *var_key = alca(uint8_t, handle->config.chunksize);
    int size_id, size_seq;
    uint8_t *kvid_seqnum;
    uint64_t old_offset;
    int64_t _offset;
    int64_t delta;
    struct docio_object _doc;
    FileMgr *file = handle->dhandle->getFile();
    bool btreev2 = ver_btreev2_format(handle->file->getVersion());

    memset(var_key, 0, handle->config.chunksize);
    if (handle->kvs) {
        buf2kvid(handle->config.chunksize, item->header->key, &kv_id);
    } else {
        kv_id = 0;
    }

    struct wal_kvs_delta_stat *kvs_delta_stat;
    struct wal_kvs_delta_stat kvs_delta_query;
    kvs_delta_query.kv_id = kv_id;
    avl_node *delta_stat_node = avl_search(kvs_delta_stats,
                                           &kvs_delta_query.avl_entry,
                                           _kvs_delta_stat_cmp);
    if (delta_stat_node) {
        kvs_delta_stat = _get_entry(delta_stat_node, struct wal_kvs_delta_stat,
                                    avl_entry);
    } else {
        kvs_delta_stat = (struct wal_kvs_delta_stat *)
            calloc(1, sizeof(struct wal_kvs_delta_stat));
        kvs_delta_stat->kv_id = kv_id;
        avl_insert(kvs_delta_stats, &kvs_delta_stat->avl_entry,
                   _kvs_delta_stat_cmp);
    }

    int64_t nlivenodes = 0;
    int64_t ndeltanodes = 0;
    if (btreev2) {
        nlivenodes = handle->bnodeMgr->getNLiveNodes();
        ndeltanodes = handle->bnodeMgr->getNDeltaNodes();
    } else {
        nlivenodes = handle->bhandle->getNLiveNodes();
        ndeltanodes = handle->bhandle->getNDeltaNodes();
    }

    if (item->action == WAL_ACT_INSERT ||
        item->action == WAL_ACT_LOGICAL_REMOVE) {
        _offset = _endian_encode(item->offset);
        DocMetaForIndex old_meta;

        if (btreev2) {
            uint8_t meta_flag = (item->action == WAL_ACT_REMOVE)?
                                FDB_DOC_META_DELETED : 0x0;
            DocMetaForIndex doc_meta(item->offset,
                                     item->seqnum,
                                     item->doc_size,
                                     meta_flag);
            doc_meta.encode();
            handle->trie->insert_vlen(item->header->key, item->header->keylen,
                                 &doc_meta, doc_meta.size(),
                                 &old_meta, nullptr);
            handle->bnodeMgr->releaseCleanNodes();
            old_meta.decode();
            old_offset = old_meta.offset;
        } else {
            old_offset = BLK_NOT_FOUND;
            handle->trie->insert(item->header->key, item->header->keylen,
                                 (void *)&_offset, (void *)&old_offset);
            fs = handle->bhandle->flushBuffer();
            if (fs != FDB_RESULT_SUCCESS) {
                return fs;
            }
            old_offset = _endian_decode(old_offset);
        }

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
                handle->seqtrie->insert(kvid_seqnum, size_id + size_seq,
                                        (void *)&_offset, (void *)&old_offset_local);
            } else {
                handle->seqtree->insert((void *)&_seqnum, (void *)&_offset);
            }

            if (btreev2) {
                handle->bnodeMgr->releaseCleanNodes();
            } else {
                fs = handle->bhandle->flushBuffer();
                if (fs != FDB_RESULT_SUCCESS) {
                    return fs;
                }
            }
        }

        if (btreev2) {
            delta = handle->bnodeMgr->getNLiveNodes() - nlivenodes;
            kvs_delta_stat->nlivenodes += delta;
            delta = handle->bnodeMgr->getNDeltaNodes() - ndeltanodes;
            delta *= handle->config.blocksize;
        } else {
            delta = handle->bhandle->getNLiveNodes() - nlivenodes;
            kvs_delta_stat->nlivenodes += delta;
            delta = handle->bhandle->getNDeltaNodes() - ndeltanodes;
            delta *= handle->config.blocksize;
        }
        kvs_delta_stat->deltasize += delta;

        if (old_offset == BLK_NOT_FOUND) {
            if (item->action == WAL_ACT_INSERT) {
                ++kvs_delta_stat->ndocs;
            } else { // inserted a logical deleted doc into main index
                ++kvs_delta_stat->ndeletes;
            }
            kvs_delta_stat->datasize += item->doc_size;
            kvs_delta_stat->deltasize += item->doc_size;
        } else { // update or logical delete

            uint64_t old_seqnum = SEQNUM_NOT_USED;
            uint32_t old_doc_size = 0;
            bool is_old_doc_deleted = false;

            // B-tree V2: read doc meta from hb+trie directly.
            // otherwise: read doc meta from doc block.
            if (btreev2) {
                old_seqnum = old_meta.seqnum;
                old_doc_size = old_meta.onDiskSize;
                is_old_doc_deleted = old_meta.isDeleted();
            } else {
                // This block is already cached when we call HBTRIE_INSERT.
                // No additional block access.
                char dummy_key[FDB_MAX_KEYLEN];
                _doc.meta = _doc.body = NULL;
                _doc.key = &dummy_key;
                _offset = handle->dhandle->readDocKeyMeta_Docio(old_offset,
                                                  &_doc, true);
                if (_offset < 0) {
                    return (fdb_status) _offset;
                } else if (_offset == 0) {
                    // Note that this is not an error as old_offset is pointing to
                    // the zero-filled region in a document block.
                    return FDB_RESULT_KEY_NOT_FOUND;
                }
                free(_doc.meta);

                old_seqnum = _doc.seqnum;
                old_doc_size = _fdb_get_docsize(_doc.length);
                is_old_doc_deleted = _doc.length.flag & DOCIO_DELETED;
            }

            file->markDocStale(old_offset, old_doc_size);

            if (!is_old_doc_deleted) {//prev doc was not deleted
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
            delta = (int)item->doc_size - (int)old_doc_size;
            kvs_delta_stat->datasize += delta;
            bid_t last_hdr = handle->last_hdr_bid.load(std::memory_order_relaxed);
            if (last_hdr * handle->config.blocksize < old_offset) {
                kvs_delta_stat->deltasize += delta;
            } else {
                kvs_delta_stat->deltasize += (int)item->doc_size;
            }

            // Avoid duplicates (remove previous sequence number)
            if (handle->config.seqtree_opt == FDB_SEQTREE_USE) {
                struct wal_stale_seq_entry *entry = (struct wal_stale_seq_entry *)
                    calloc(1, sizeof(struct wal_stale_seq_entry));
                entry->kv_id = kv_id;
                entry->seqnum = old_seqnum;
                avl_insert(stale_seqnum_list, &entry->avl_entry,
                           _fdb_seq_entry_cmp);
            }

        }
    } else {
        // Immediate remove
        DocMetaForIndex old_meta;
        size_t old_meta_size;
        if (btreev2) {
            hr = handle->trie->remove_vlen(item->header->key, item->header->keylen,
                                           &old_meta, &old_meta_size);
            handle->bnodeMgr->releaseCleanNodes();

            old_meta.decode();
            old_offset = old_meta.offset;
        } else {
            old_offset = item->old_offset;
            hr = handle->trie->remove(item->header->key, item->header->keylen);
            fs = handle->bhandle->flushBuffer();
            if (fs != FDB_RESULT_SUCCESS) {
                return fs;
            }
        }

        if (hr == HBTRIE_RESULT_SUCCESS) {
            uint64_t old_seqnum = SEQNUM_NOT_USED;
            uint32_t old_doc_size = 0;
            bool is_old_doc_deleted = false;

            // B-tree V2: read doc meta from hb+trie directly.
            // otherwise: read doc meta from doc block.
            if (btreev2) {
                old_seqnum = old_meta.seqnum;
                old_doc_size = old_meta.onDiskSize;
                is_old_doc_deleted = old_meta.isDeleted();
            } else {
                // This block is already cached when we call HBTRIE_INSERT.
                // No additional block access.
                char dummy_key[FDB_MAX_KEYLEN];
                _doc.meta = _doc.body = NULL;
                _doc.key = &dummy_key;
                _offset = handle->dhandle->readDocKeyMeta_Docio(old_offset,
                                                  &_doc, true);
                if (_offset < 0) {
                    return (fdb_status) _offset;
                } else if (_offset == 0) {
                    // Note that this is not an error as old_offset is pointing to
                    // the zero-filled region in a document block.
                    return FDB_RESULT_KEY_NOT_FOUND;
                }
                free(_doc.meta);

                old_seqnum = _doc.seqnum;
                old_doc_size = _fdb_get_docsize(_doc.length);
                is_old_doc_deleted = _doc.length.flag & DOCIO_DELETED;
            }

            file->markDocStale(old_offset, old_doc_size);

            // Reduce the total number of docs by one
            --kvs_delta_stat->ndocs;
            if (is_old_doc_deleted) {//prev deleted doc is dropped
                --kvs_delta_stat->ndeletes;
            }

            // Reduce the total datasize by size of previously present doc
            delta = -(int)old_doc_size;
            kvs_delta_stat->datasize += delta;
            // if multiple wal flushes happen before commit, then it's possible
            // that this doc deleted was inserted & flushed after last commit
            // In this case we need to update the deltasize too which tracks
            // the amount of new data inserted between commits.
            bid_t last_hdr = handle->last_hdr_bid.load(std::memory_order_relaxed);
            if (last_hdr * handle->config.blocksize < old_offset) {
                kvs_delta_stat->deltasize += delta;
            }

            // remove sequence number for the removed doc
            if (handle->config.seqtree_opt == FDB_SEQTREE_USE) {
                struct wal_stale_seq_entry *entry = (struct wal_stale_seq_entry *)
                    calloc(1, sizeof(struct wal_stale_seq_entry));
                entry->kv_id = kv_id;
                entry->seqnum = old_seqnum;
                avl_insert(stale_seqnum_list, &entry->avl_entry, _fdb_seq_entry_cmp);
            }

            // Update index size to new size after the remove operation
            if (btreev2) {
                delta = handle->bnodeMgr->getNLiveNodes() - nlivenodes;
            } else {
                delta = handle->bhandle->getNLiveNodes() - nlivenodes;
            }
            kvs_delta_stat->nlivenodes += delta;

            // ndeltanodes measures number of new index nodes created due to
            // this hbtrie_remove() operation
            if (btreev2) {
                delta = handle->bnodeMgr->getNDeltaNodes() - ndeltanodes;
            } else {
                delta = handle->bhandle->getNDeltaNodes() - ndeltanodes;
            }
            // TODO: delta size should be estimated differently for a new btree format.
            delta *= handle->config.blocksize;
            kvs_delta_stat->deltasize += delta;
        }
    }
    return FDB_RESULT_SUCCESS;
}

uint64_t WalFlushCallbacks::getOldOffset(void *dbhandle,
                                         struct wal_item *item)
{
    FdbKvsHandle *handle = reinterpret_cast<FdbKvsHandle *>(dbhandle);
    uint64_t old_offset = 0;

    if (item->action == WAL_ACT_REMOVE) {
        // For immediate remove, old_offset value is critical
        // so that we should get an exact value.
        handle->trie->find(item->header->key,
                           item->header->keylen,
                           (void*)&old_offset);
    } else {
        handle->trie->findOffset(item->header->key,
                                 item->header->keylen,
                                 (void*)&old_offset);
    }
    if (ver_btreev2_format(handle->file->getVersion())) {
        handle->bnodeMgr->releaseCleanNodes();
    } else {
        handle->bhandle->flushBuffer();
    }
    old_offset = _endian_decode(old_offset);

    return old_offset;
}

void WalFlushCallbacks::purgeSeqTreeEntry(void *dbhandle,
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

    FdbKvsHandle *handle = reinterpret_cast<FdbKvsHandle *>(dbhandle);
    bool btreev2 = ver_btreev2_format(handle->file->getVersion());

    struct avl_node *node = avl_first(stale_seqnum_list);
    while (node) {
        seq_entry = _get_entry(node, struct wal_stale_seq_entry, avl_entry);
        node = avl_next(node);
        if (btreev2) {
            nlivenodes = handle->bnodeMgr->getNLiveNodes();
            ndeltanodes = handle->bnodeMgr->getNDeltaNodes();
        } else {
            nlivenodes = handle->bhandle->getNLiveNodes();
            ndeltanodes = handle->bhandle->getNDeltaNodes();
        }
        _seqnum = _endian_encode(seq_entry->seqnum);
        if (handle->kvs) {
            // multi KV instance mode .. HB+trie
            kvid2buf(sizeof(fdb_kvs_id_t), seq_entry->kv_id, kvid_seqnum);
            memcpy(kvid_seqnum + sizeof(fdb_kvs_id_t), &_seqnum, sizeof(fdb_seqnum_t));
            handle->seqtrie->remove((void*)kvid_seqnum,
                                    sizeof(fdb_kvs_id_t) + sizeof(fdb_seqnum_t));
        } else {
            handle->seqtree->remove((void*)&_seqnum);
        }

        if (ver_btreev2_format(handle->file->getVersion())) {
            handle->bnodeMgr->releaseCleanNodes();
        } else {
            handle->bhandle->flushBuffer();
        }

        kvs_delta_query.kv_id = seq_entry->kv_id;
        avl_node *delta_stat_node = avl_search(kvs_delta_stats,
                                               &kvs_delta_query.avl_entry,
                                               _kvs_delta_stat_cmp);
        if (delta_stat_node) {
            delta_stat = _get_entry(delta_stat_node, struct wal_kvs_delta_stat,
                                    avl_entry);
            if (btreev2) {
                delta = handle->bnodeMgr->getNLiveNodes() - nlivenodes;
                delta_stat->nlivenodes += delta;
                delta = handle->bnodeMgr->getNDeltaNodes() - ndeltanodes;
                delta *= handle->config.blocksize;
            } else {
                delta = handle->bhandle->getNLiveNodes() - nlivenodes;
                delta_stat->nlivenodes += delta;
                delta = handle->bhandle->getNDeltaNodes() - ndeltanodes;
                delta *= handle->config.blocksize;
            }
            delta_stat->deltasize += delta;
        }
        avl_remove(stale_seqnum_list, &seq_entry->avl_entry);
        free(seq_entry);
    }
}

void WalFlushCallbacks::updateKvsDeltaStats(FileMgr *file,
                                            struct avl_tree *kvs_delta_stats)
{
    struct avl_node *node;
    struct wal_kvs_delta_stat *delta_stat;
    node = avl_first(kvs_delta_stats);
    while (node) {
        delta_stat = _get_entry(node, struct wal_kvs_delta_stat, avl_entry);
        node = avl_next(node);
        file->getKvsStatOps()->statUpdateAttr(delta_stat->kv_id,
                              KVS_STAT_DATASIZE, delta_stat->datasize);
        file->getKvsStatOps()->statUpdateAttr(delta_stat->kv_id,
                              KVS_STAT_NDOCS, delta_stat->ndocs);
        file->getKvsStatOps()->statUpdateAttr(delta_stat->kv_id,
                              KVS_STAT_NDELETES, delta_stat->ndeletes);
        file->getKvsStatOps()->statUpdateAttr(delta_stat->kv_id,
                              KVS_STAT_NLIVENODES, delta_stat->nlivenodes);
        file->getKvsStatOps()->statUpdateAttr(delta_stat->kv_id,
                              KVS_STAT_DELTASIZE, delta_stat->deltasize);
        avl_remove(kvs_delta_stats, &delta_stat->avl_entry);
        free(delta_stat);
    }
}

void _fdb_dump_handle(FdbKvsHandle *h) {
    fprintf(stderr, "filename: %s\n", h->filename.c_str());

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

    fprintf(stderr, "kvs: id = %" _F64 "\n", h->kvs->getKvsId());
    fprintf(stderr, "kvs: type = %d\n", h->kvs->getKvsType());
    fprintf(stderr, "kvs: root_handle %p\n", (void *)h->kvs->getRootHandle());

    fprintf(stderr, "fdb_file_handle: %p\n", (void *)h->fhandle);
    fprintf(stderr, "fhandle: root %p\n", (void*)h->fhandle->getRootHandle());
    fprintf(stderr, "fhandle: flags %p\n", (void *)h->fhandle->getFlags());

    fprintf(stderr, "hbtrie: %p\n", (void *)h->trie);
    fprintf(stderr, "hbtrie: chunksize %u\n", h->trie->getChunkSize());
    fprintf(stderr, "hbtrie: valuelen %u\n", h->trie->getValueLen());
    fprintf(stderr, "hbtrie: flag %x\n", h->trie->getFlag());
    fprintf(stderr, "hbtrie: leaf_height_limit %u\n",
           h->trie->getLeafHeightLimit());
    fprintf(stderr, "hbtrie: root_bid %p\n", (void *)h->trie->getRootBid());
    fprintf(stderr, "hbtrie: root_bid %p\n", (void *)h->trie->getRootBid());

    fprintf(stderr, "seqtrie: %p\n", (void *)h->seqtrie);
    fprintf(stderr, "seqtrie: chunksize %u\n", h->seqtrie->getChunkSize());
    fprintf(stderr, "seqtrie: valuelen %u\n", h->seqtrie->getValueLen());
    fprintf(stderr, "seqtrie: flag %x\n", h->seqtrie->getFlag());
    fprintf(stderr, "seqtrie: leaf_height_limit %u\n",
            h->seqtrie->getLeafHeightLimit());
    if (ver_btreev2_format(h->file->getVersion())) {
        fprintf(stderr, "seqtrie: root_offset %" _F64 "\n",
                h->seqtrie->getRootAddr().offset);
    } else {
        fprintf(stderr, "seqtrie: root_bid %" _F64 "\n", h->seqtrie->getRootBid());
    }

    fprintf(stderr, "file: getFileName() %s\n", h->file->getFileName());
    fprintf(stderr, "file: refCount %d\n", h->file->getRefCount_UNLOCKED());
    fprintf(stderr, "file: fMgrFlags %x\n", h->file->getFlags());
    fprintf(stderr, "file: blockSize %d\n", h->file->getBlockSize());
    fprintf(stderr, "file: fd %d\n", handle_to_fd(h->file->getFopsHandle()));
    fprintf(stderr, "file: lastPos %" _F64"\n", h->file->getPos());
    fprintf(stderr, "file: fMgrStatus %d\n", h->file->getFileStatus());
    fprintf(stderr, "file: config: blocksize %d\n", h->file->getConfig()->getBlockSize());
    fprintf(stderr, "file: config: ncacheblock %d\n",
            h->file->getConfig()->getNcacheBlock());
    fprintf(stderr, "file: config: flag %d\n", h->file->getConfig()->getFlag());
    fprintf(stderr, "file: config: chunksize %d\n", h->file->getConfig()->getChunkSize());
    fprintf(stderr, "file: config: options %x\n", h->file->getConfig()->getOptions());
    fprintf(stderr, "file: config: prefetch_duration %" _F64 "\n",
            h->file->getConfig()->getPrefetchDuration());
    fprintf(stderr, "file: config: num_wal_shards %d\n",
            h->file->getConfig()->getNumWalShards());
    fprintf(stderr, "file: config: num_bcache_shards %d\n",
            h->file->getConfig()->getNumBcacheShards());
    fprintf(stderr, "file: oldFileName %s\n", h->file->getOldFileName().empty()
                                                ? "nil"
                                                : h->file->getOldFileName().c_str());
    fprintf(stderr, "file: oldFileName %s\n", h->file->getOldFileName().empty()
                                                ? "nil"
                                                : h->file->getNewFileName().c_str());
    fprintf(stderr, "file: FileBlockCache: bcache %p\n",
            (void *)h->file->getBCache());
    fprintf(stderr, "file: globalTxn: handle %p\n",
            (void *)h->file->getGlobalTxn()->handle);
    fprintf(stderr, "file: globalTxn: prev_hdr_bid %" _F64 "\n",
            h->file->getGlobalTxn()->prev_hdr_bid);
    fprintf(stderr, "file: globalTxn: isolation %d\n",
            h->file->getGlobalTxn()->isolation);
    fprintf(stderr, "file: inPlaceCompaction: %d\n",
            h->file->isInPlaceCompactionSet());
    fprintf(stderr, "file: kvHeader: %" _F64 "\n",
            h->file->getKVHeader_UNLOCKED()->id_counter);

    fprintf(stderr, "docio_handle: %p\n", (void*)h->dhandle);
    fprintf(stderr, "dhandle: file: filename %s\n",
            h->dhandle->getFile()->getFileName());
    fprintf(stderr, "dhandle: curblock %" _F64 "\n", h->dhandle->getCurBlock());
    fprintf(stderr, "dhandle: curpos %d\n", h->dhandle->getCurPos());
    fprintf(stderr, "dhandle: cur_bmp_revnum_hash %d\n", h->dhandle->getCurBmpRevnumHash());
    fprintf(stderr, "dhandle: lastbid %" _F64 "\n", h->dhandle->getLastBid());
    fprintf(stderr, "dhandle: readbuffer %p\n", h->dhandle->getReadBuffer());
    fprintf(stderr, "dhandle: %s\n",
           h->dhandle->isDocBodyCompressed()? "compress" : "don't compress");
    fprintf(stderr, "new_dhandle %p\n", (void *)h->dhandle);

    if (ver_btreev2_format(h->file->getVersion())) {
        fprintf(stderr, "BnodeMgr %p\n", (void *)h->bnodeMgr);
        fprintf(stderr, "BnodeMgr: nlivenodes %" _F64 "\n", h->bnodeMgr->getNLiveNodes());
        fprintf(stderr, "BnodeMgr: file %s\n", h->bnodeMgr->getFile()->getFileName());
    } else {
        fprintf(stderr, "btreeblk_handle bhanlde %p\n", (void *)h->bhandle);
        fprintf(stderr, "bhandle: nodesize %d\n", h->bhandle->getNodeSize());
        fprintf(stderr, "bhandle: nnodeperblock %d\n", h->bhandle->getNNodePerBlock());
        fprintf(stderr, "bhandle: nlivenodes %" _F64 "\n", h->bhandle->getNLiveNodes());
        fprintf(stderr, "bhandle: file %s\n", h->bhandle->getFile()->getFileName());
        fprintf(stderr, "bhandle: nsb %d\n", h->bhandle->getNSubblocks());
    }

    fprintf(stderr, "multi_kv_instances: %d\n", h->config.multi_kv_instances);
    fprintf(stderr, "prefetch_duration: %" _F64"\n",
            h->config.prefetch_duration);
    fprintf(stderr, "cur_header_revnum: %" _F64 "\n",
            h->cur_header_revnum.load());
    fprintf(stderr, "last_hdr_bid: %" _F64 "\n", h->last_hdr_bid.load());
    fprintf(stderr, "last_wal_flush_hdr_bid: %" _F64 "\n",
            h->last_wal_flush_hdr_bid);
    fprintf(stderr, "kv_info_offset: %" _F64 "\n", h->kv_info_offset);

    fprintf(stderr, "snap_handle: %p\n", (void *)h->shandle);
    if (h->shandle) {
        fprintf(stderr, "shandle: ref_cnt %" _F64 "\n",
                h->shandle->ref_cnt_kvs.load());
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
