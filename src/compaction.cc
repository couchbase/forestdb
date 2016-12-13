/* -*- Mode: C++; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2016 Couchbase, Inc
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

#include "bgflusher.h"
#include "btree.h"
#include "btree_new.h"
#include "bnodemgr.h"
#include "btreeblock.h"
#include "btree_kv.h"
#include "compaction.h"
#include "compactor.h"
#include "docio.h"
#include "fdb_engine.h"
#include "fdb_internal.h"
#include "filemgr.h"
#include "hbtrie.h"
#include "version.h"
#include "wal.h"

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

static
char *_fdb_redirect_header(FileMgr *old_file, uint8_t *buf,
                           FileMgr *new_file) {
    uint16_t old_compact_filename_len; // size of existing old_filename in buf
    uint16_t new_compact_filename_len; // size of existing new_filename in buf
    uint16_t new_filename_len = new_file->getFileNameLen() + 1;
    uint16_t new_filename_len_enc = _endian_encode(new_filename_len);
    uint32_t crc;
    size_t crc_offset;
    size_t new_fnamelen_off = ver_get_new_filename_off(old_file->getVersion());
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
    memcpy(buf + new_fname_off, new_file->getFileName(), new_filename_len);
    // Compute the DB header's new crc32 value
    crc_offset = new_fname_off + new_filename_len + old_compact_filename_len;
    crc = get_checksum(buf, crc_offset, new_file->getCrcMode());
    crc = _endian_encode(crc);
    // Update the DB header's new crc32 value
    memcpy(buf + crc_offset, &crc, sizeof(crc));
    // If the DB header indicated an old_filename, return it
    return old_compact_filename_len ? old_filename : NULL;
}

static int64_t _fdb_doc_move(void *dbhandle,
                             void *void_new_dhandle,
                             struct wal_item *item,
                             fdb_doc *fdoc)
{
    uint8_t deleted;
    uint64_t new_offset;
    int64_t _offset;
    FdbKvsHandle *handle = reinterpret_cast<FdbKvsHandle*>(dbhandle);
    DocioHandle *new_dhandle = reinterpret_cast<DocioHandle*>(void_new_dhandle);
    struct docio_object doc;

    // read doc from old file
    doc.key = NULL;
    doc.meta = NULL;
    doc.body = NULL;
    _offset = handle->dhandle->readDoc_Docio(item->offset, &doc, true);
    if (_offset <= 0) {
        return _offset;
    }

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

    new_offset = new_dhandle->appendDoc_Docio(&doc, deleted, 1);
    return new_offset;
}

fdb_status Compaction::compactFile(FdbFileHandle *fhandle,
                                   const char *new_filename,
                                   bool in_place_compaction,
                                   bid_t marker_bid,
                                   bool clone_docs,
                                   const fdb_encryption_key *new_encryption_key)
{
    Compaction compaction;
    FileMgrConfig fconfig;
    FdbKvsHandle *handle = fhandle->getRootHandle();
    fdb_status status;
    LATENCY_STAT_START();

    // Prevent updates to the current file
    handle->file->mutexLock();

    // Check if the current file can be compacted or not
    status = checkCompactionReadiness(handle, new_filename);
    if (status != FDB_RESULT_SUCCESS) {
        handle->file->mutexUnlock();
        return status;
    }

    // sync handle for the current file
    fdb_sync_db_header(handle);

    // Set filemgr configurations for a new file
    FdbEngine::initFileConfig(&handle->config, &fconfig);
    fconfig.addOptions(FILEMGR_CREATE);
    fconfig.addOptions(FILEMGR_EXCL_CREATE); // Fail if the file already exists
    if (new_encryption_key) {
        fconfig.setEncryptionKey(*new_encryption_key);
    }

    // Create a new file for compaction
    status = compaction.createFile(new_filename, fconfig,
                                   in_place_compaction, handle);
    if (status != FDB_RESULT_SUCCESS) {
        handle->file->mutexUnlock();
        return status;
    }

    // Prevent updates to the new file for compaction
    compaction.fileMgr->mutexLock();

    union wal_flush_items flush_items;
    FileMgr *old_file;
    bid_t dirty_idtree_root = BLK_NOT_FOUND;
    bid_t dirty_seqtree_root = BLK_NOT_FOUND;
    fdb_seqnum_t seqnum;
    uint64_t new_file_kv_info_offset = BLK_NOT_FOUND;
    struct filemgr_dirty_update_node *prev_node = NULL, *new_node = NULL;
    SuperblockBase *sb = handle->file->getSb();

    // Complete the following operations in the current file to prepare the
    // compaction:

    // (1) Copy the current file's seqnum to the new file.
    //     (KV instances' seq numbers will be copied along with the KV header)
    //     Note that the sequence numbers and KV header data in the new file will be
    //     corrected in Compaction::copyDocsUptoMarker() for compact_upto case
    //     (i.e., marker_bid != -1).
    seqnum = handle->file->getSeqnum();
    compaction.fileMgr->setSeqnum(seqnum);
    if (handle->kvs) {
        // multi KV instance mode .. copy KV header data to the new file
        fdb_kvs_header_copy(handle, compaction.fileMgr, compaction.docHandle,
                            &new_file_kv_info_offset, true);
    }

    _fdb_dirty_update_ready(handle, &prev_node, &new_node,
                            &dirty_idtree_root, &dirty_seqtree_root, false);

    // (2) Flush the WAL and set the DB header in the current file.
    handle->file->getWal()->commit_Wal(handle->file->getGlobalTxn(), NULL,
                                       &handle->log_callback);
    handle->file->getWal()->flush_Wal((void*)handle,
                                      WalFlushCallbacks::flushItem,
                                      WalFlushCallbacks::getOldOffset,
                                      WalFlushCallbacks::purgeSeqTreeEntry,
                                      WalFlushCallbacks::updateKvsDeltaStats,
                                      &flush_items);
    handle->file->getWal()->setDirtyStatus_Wal(FDB_WAL_CLEAN);

    _fdb_dirty_update_finalize(handle, prev_node, new_node,
                               &dirty_idtree_root, &dirty_seqtree_root, true);

    // (3) Mark the new file's name in the current file.
    FileMgr::setCompactionState(handle->file, compaction.fileMgr, FILE_COMPACT_OLD);

    // (4) Appending KVS header must be done after flushing WAL
    //     because KVS stats info is updated during WAL flushing.
    if (handle->kvs) {
        // multi KV instance mode .. append up-to-date KV header
        handle->kv_info_offset = fdb_kvs_header_append(handle);
    }

    if (sb) {
        sb->returnReusableBlocks(handle);
    }

    // (5) The new header should be appended at the end of the current file
    handle->last_hdr_bid = handle->file->getNextAllocBlock();
    handle->last_wal_flush_hdr_bid = handle->last_hdr_bid;
    handle->cur_header_revnum = fdb_set_file_header(handle);

    if (ver_btreev2_format(handle->file->getVersion())) {
        // (6) Release the reference counts on all Btree nodes of old file so
        // that they may be evicted in case of memory pressure.
        handle->bnodeMgr->releaseCleanNodes();
    } else {
        // (6) Flush all the dirty blocks of the current file
        handle->bhandle->flushBuffer();
    }
    if (ver_btreev2_format(compaction.fileMgr->getVersion())) {
        // Since compaction would have filled up the BnodeCache with many
        // entries, we can release the reference counts on them so that they
        // may be evicted in case of memory pressure.
        compaction.bnodeMgr->releaseCleanNodes();
    } else {
        // Flush dirty blocks of the new file too..
        // Note that we should flush 'bhandle' of the new file too, since it now
        // contains a dirty block for the new root node.
        compaction.btreeHandle->flushBuffer();
    }

    // (7) Commit the current file
    fdb_status fs = handle->file->commit_FileMgr(
                    !(handle->config.durability_opt & FDB_DRB_ASYNC),
                    &handle->log_callback);
    handle->file->getWal()->releaseFlushedItems_Wal(&flush_items);
    if (fs != FDB_RESULT_SUCCESS) {
        FileMgr::setCompactionState(handle->file, NULL, FILE_NORMAL);
        handle->file->mutexUnlock();
        compaction.fileMgr->mutexUnlock();
        compaction.cleanUpCompactionErr(handle);
        return fs;
    }

    if (ver_btreev2_format(handle->file->getVersion())) {
        // (8) Reset the sub-block and update the superblock in the current file
        handle->bhandle->resetSubblockInfo();
    }
    if (sb) {
        // sync superblock
        sb->updateHeader(handle);
        sb->syncCircular(handle);
    }

    // Mark the new file as newly being compacted
    compaction.fileMgr->updateFileStatus(FILE_COMPACT_NEW, NULL);

    // Acquire cur_hdr's block ID within this lock, ensuring the correct
    // last_hdr_bid is recorded. This addresses MB-20040, where continuous
    // commits caused _fdb_compact_move_docs (which invokes fdb_get_file_info)
    // to move the last_hdr_bid (with fdb_sync_db_header), causing compaction
    // to skip moving some of the delta items from the old_file to the new_file.
    bid_t cur_hdr = handle->last_hdr_bid;
    bid_t last_hdr = 0;

    // Release the locks on the current and new files, so that compactor &
    // writers can be running concurrently.
    handle->file->mutexUnlock();
    compaction.fileMgr->mutexUnlock();

    // probability variable for blocking writer thread
    // value range: 0 (do not block writer) to 100 (always block writer)
    size_t prob = 0;

    // From now, copy all the active blocks from the current file to the new file.
    if (marker_bid != BLK_NOT_FOUND) {
        fs = compaction.copyDocsUptoMarker(handle, marker_bid,
                                           handle->last_hdr_bid, seqnum,
                                           &prob, clone_docs);
        cur_hdr = marker_bid; // Move delta documents from the compaction marker.
    } else {
        fs = compaction.copyDocs(handle, &prob, clone_docs);
    }

    if (fs != FDB_RESULT_SUCCESS) {
        FileMgr::setCompactionState(handle->file, NULL, FILE_NORMAL);
        compaction.cleanUpCompactionErr(handle);
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
                BgFlusher *bgf = BgFlusher::getBgfInstance();
                if (bgf) {
                    bgf->switchFile_BgFlusher(handle->file, compaction.fileMgr,
                                              &handle->log_callback);
                }
                file_switched = true;
            }
            handle->file->mutexLock();
            got_lock = true;

            bid_t last_bid = handle->file->getNextAllocBlock() - 1;
            if (cur_hdr < last_bid) {
                // move delta one more time
                cur_hdr = last_bid;
                escape = true;
            } else {
                break;
            }
        }

        fs = compaction.copyDelta(handle, last_hdr, cur_hdr,
                                  compact_upto, clone_docs, got_lock, escape, &prob);
        if (fs != FDB_RESULT_SUCCESS) {
            FileMgr::setCompactionState(handle->file, NULL, FILE_NORMAL);

            if (got_lock) {
                handle->file->mutexUnlock();
            }
            compaction.cleanUpCompactionErr(handle);

            // failure in compaction means switch back to old file
            if (file_switched) {
                BgFlusher *bgf = BgFlusher::getBgfInstance();
                if (bgf) {
                    bgf->switchFile_BgFlusher(compaction.fileMgr, handle->file,
                                              &handle->log_callback);
                }
            }

            return fs;
        }

        if (escape) {
            break;
        }
    } while (last_hdr < cur_hdr);

    compaction.fileMgr->mutexLock();

    // As we moved uncommitted non-transactional WAL items,
    // commit & flush those items. Now WAL contains only uncommitted
    // transactional items (or empty), so it is ready to migrate ongoing
    // transactions.
    _fdb_dirty_update_ready(handle, &prev_node, &new_node,
                            &dirty_idtree_root, &dirty_seqtree_root, false);

    handle->file->getWal()->commit_Wal(handle->file->getGlobalTxn(), NULL,
                                       &handle->log_callback);
    handle->file->getWal()->flush_Wal((void*)handle,
                                      WalFlushCallbacks::flushItem,
                                      WalFlushCallbacks::getOldOffset,
                                      WalFlushCallbacks::purgeSeqTreeEntry,
                                      WalFlushCallbacks::updateKvsDeltaStats,
                                      &flush_items);
    if (ver_btreev2_format(handle->file->getVersion())) {
        handle->bnodeMgr->releaseCleanNodes();
    } else {
        handle->bhandle->flushBuffer();
    }

    _fdb_dirty_update_finalize(handle, prev_node, new_node,
                               &dirty_idtree_root, &dirty_seqtree_root, true);

    handle->file->getWal()->releaseFlushedItems_Wal(&flush_items);

    // copy old file's seqnum to new file (do this again due to delta)
    seqnum = handle->file->getSeqnum();
    compaction.fileMgr->setSeqnum(seqnum);
    if (handle->kvs) {
        // copy seqnums of non-default KV stores
        fdb_kvs_header_copy(handle, compaction.fileMgr, compaction.docHandle, NULL, false);
    }

    // migrate uncommitted transactional items to new file
    Wal::migrateUncommittedTxns_Wal((void*)handle, (void*) compaction.docHandle,
                                    handle->file, compaction.fileMgr, _fdb_doc_move);

    // last commit of the current file
    // (we must do this due to potential dirty WAL flush
    //  during the last loop of delta move; new index root node
    //  should be stored in the DB header).
    handle->cur_header_revnum = fdb_set_file_header(handle);
    if (sb) {
        // sync superblock
        sb->updateHeader(handle);
        sb->syncCircular(handle);
    }
    fs = handle->file->commit_FileMgr(false, &handle->log_callback);
    if (fs != FDB_RESULT_SUCCESS) {
        FileMgr::setCompactionState(handle->file, NULL, FILE_NORMAL);
        handle->file->mutexUnlock();
        compaction.fileMgr->mutexUnlock();
        compaction.cleanUpCompactionErr(handle);
        if (file_switched) {
            BgFlusher *bgf = BgFlusher::getBgfInstance();
            if (bgf) {
                bgf->switchFile_BgFlusher(compaction.fileMgr, handle->file,
                                          &handle->log_callback);
            }
        }
        return fs;
    }

    // reset last_wal_flush_hdr_bid
    handle->last_wal_flush_hdr_bid = BLK_NOT_FOUND;

    old_file = handle->file;
    handle->file = compaction.fileMgr;
    handle->kv_info_offset = new_file_kv_info_offset;

    if (ver_btreev2_format(old_file->getVersion())) {
        delete handle->bnodeMgr;
    } else {
        delete handle->bhandle;
    }
    if (ver_btreev2_format(compaction.fileMgr->getVersion())) {
        handle->bnodeMgr = compaction.bnodeMgr;
    } else {
        handle->bhandle = compaction.btreeHandle;
    }

    delete handle->dhandle;
    handle->dhandle = compaction.docHandle;

    delete handle->trie;
    handle->trie = compaction.keyTrie;
    // Since compaction is successful, delete old KVOps of the old file..
    delete compaction.oldFileStaleOps; // NULL if not applicable

    handle->config.encryption_key = compaction.fileMgr->getEncryption()->key;

    if (handle->config.seqtree_opt == FDB_SEQTREE_USE) {
        if (handle->kvs) {
            delete handle->seqtrie;
            handle->seqtrie = compaction.seqTrie;
        } else {
            if (ver_btreev2_format(old_file->getVersion())) {
                delete handle->seqtreeV2; // if old file was in BtreeV2
            } else {
                delete handle->seqtree;
            }
            if (ver_btreev2_format(compaction.fileMgr->getVersion())) {
                handle->seqtreeV2 = compaction.seqTreeV2;
            } else {
                handle->seqtree = compaction.seqTree;
            }
        }
    }

    // we don't need to free 'kv_ops'
    // as it is re-used by'new_staletree'.
    if (ver_btreev2_format(old_file->getVersion())) {
        delete handle->staletreeV2;
    } else {
        delete handle->staletree;
    }
    if (ver_btreev2_format(compaction.fileMgr->getVersion())) {
        handle->staletreeV2 = compaction.staleTreeV2;
    } else {
        handle->staletree = compaction.staleTree;
    }

    compaction.fileMgr->updateFileStatus(FILE_NORMAL, old_file->getFileName());

    // Atomically perform
    // 1) commit new file
    // 2) set remove pending flag of the old file
    // 3) close the old file
    // Note that both old_file's lock and new_file's lock are still acquired.
    status = compaction.commitAndRemovePending(handle, old_file);
    if (status != FDB_RESULT_SUCCESS) {
        FileMgr::setCompactionState(old_file, NULL, FILE_NORMAL);
    }

    LATENCY_STAT_END(fhandle->getRootHandle()->file, FDB_LATENCY_COMPACTS);
    return status;
}

fdb_status Compaction::checkCompactionReadiness(FdbKvsHandle *handle,
                                                const char *new_filename)
{
    // First of all, update the handle for the case
    // that compaction by other thread is already done
    // (REMOVED_PENDING status).
    fdb_status fs = fdb_check_file_reopen(handle, NULL);
    if (fs != FDB_RESULT_SUCCESS) {
        return fs;
    }
    fdb_sync_db_header(handle);

    // if the file is already compacted by other thread
    if (handle->file->getFileStatus() != FILE_NORMAL ||
        !handle->file->getNewFileName().empty()) {
        // update handle and return
        fs = fdb_check_file_reopen(handle, NULL);
        if (fs != FDB_RESULT_SUCCESS) {
            return fs;
        }
        fdb_sync_db_header(handle);

        return FDB_RESULT_COMPACTION_FAIL;
    }

    if (handle->kvs) {
        if (handle->kvs->getKvsType() == KVS_SUB) {
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
    if (!strcmp(new_filename, handle->file->getFileName())) {
        return FDB_RESULT_INVALID_ARGS;
    }
    if (handle->file->isRollbackOn()) {
        return FDB_RESULT_FAIL_BY_ROLLBACK;
    }

    return FDB_RESULT_SUCCESS;
}

fdb_status Compaction::createFile(const std::string file_name,
                                  FileMgrConfig &fconfig,
                                  bool in_place_compaction,
                                  FdbKvsHandle *handle) {
    // Open a new file for compaction
    filemgr_open_result result = FileMgr::open(file_name,
                                               handle->fileops,
                                               &fconfig,
                                               &handle->log_callback);
    if (result.rv != FDB_RESULT_SUCCESS) {
        return (fdb_status) result.rv;
    }

    fileMgr = result.file;
    if (fileMgr == NULL) {
        return FDB_RESULT_OPEN_FAIL;
    }

    fileMgr->fhandleAdd(handle->fhandle);
    fileMgr->setInPlaceCompaction(in_place_compaction);

    docHandle = new DocioHandle(fileMgr,
                                handle->config.compress_document_body,
                                &handle->log_callback);

    // create new hb-trie and related handles
    if (ver_btreev2_format(fileMgr->getVersion())) {
        bnodeMgr = new BnodeMgr();
        bnodeMgr->setFile(fileMgr);
        bnodeMgr->setLogCallback(&handle->log_callback);
        BtreeNodeAddr rootAddr;
        keyTrie = new HBTrie(handle->trie->getChunkSize(),
                             fileMgr->getBlockSize(),
                             rootAddr, bnodeMgr, fileMgr);
        if (handle->kvs) {
            keyTrie->setCmpFuncCB(FdbEngine::getCmpFuncCB);
        }
    } else {
        btreeHandle = new BTreeBlkHandle(fileMgr, fileMgr->getBlockSize());
        btreeHandle->setLogCallback(&handle->log_callback);
        keyTrie = new HBTrie(handle->trie->getChunkSize(),
                             handle->trie->getValueLen(),
                             fileMgr->getBlockSize(), BLK_NOT_FOUND,
                             btreeHandle, (void*)docHandle, _fdb_readkey_wrap);
        keyTrie->setLeafCmp(_fdb_custom_cmp_wrap);
        keyTrie->setLeafHeightLimit(handle->trie->getLeafHeightLimit());
        if (handle->kvs) {
            keyTrie->setMapFunction(handle->trie->getMapFunction());
        }
    }

    if (handle->config.seqtree_opt == FDB_SEQTREE_USE) {
        // if we use sequence number tree
        if (handle->kvs) { // multi KV instance mode
            if (ver_btreev2_format(fileMgr->getVersion())) {
                BtreeNodeAddr rootAddr;
                seqTrie = new HBTrie(sizeof(fdb_kvs_id_t),
                                     fileMgr->getBlockSize(),
                                     rootAddr, bnodeMgr, fileMgr);
            } else {
                seqTrie = new HBTrie(sizeof(fdb_kvs_id_t),
                                     OFFSET_SIZE, fileMgr->getBlockSize(),
                                     BLK_NOT_FOUND, btreeHandle,
                                     (void *)docHandle, _fdb_readseq_wrap);
            }
        } else { // single KV instance mode
            if (ver_btreev2_format(fileMgr->getVersion())) { // New Btree V2
                seqTreeV2 = new BtreeV2();
                seqTreeV2->setBMgr(bnodeMgr);
                seqTreeV2->init();
            } else { // use older btree format
                BTree *old_seqtree = handle->seqtree;
                seqTree = new BTree(btreeHandle, old_seqtree->getKVOps(),
                                    old_seqtree->getBlkSize(), old_seqtree->getKSize(),
                                    old_seqtree->getVSize(), 0x0, NULL);
            }
        }
    }

    // stale-block tree
    if (ver_staletree_support(fileMgr->getVersion())) {
        if (ver_btreev2_format(fileMgr->getVersion())) { // New Btree V2
            staleTreeV2 = new BtreeV2();
            staleTreeV2->setBMgr(bnodeMgr);
            staleTreeV2->init();
            // In old Btree format, we "move" the fileKVOps from old Btree
            // to the Btree in the new file. So while migrating from old format
            // to new format, we must simply free the old fileKVOps on success
            if (!ver_btreev2_format(handle->file->getVersion())) {
                if (handle->staletree) {// Migrating from MAGIC_002 => MAGIC_003
                    // Stash and Free this on successful compaction only
                    oldFileStaleOps = handle->staletree->getKVOps();
                }
            }
        } else { // Retain the old BTree format into the new file on compaction
            BTreeKVOps *stale_kv_ops;
            if (handle->staletree) {
                stale_kv_ops = handle->staletree->getKVOps();
            } else {
                // this happens when the current file's version is older than MAGIC_002.
                stale_kv_ops = new FixedKVOps(8, 8, _cmp_uint64_t_endian_safe);
            }
            staleTree = new BTree(btreeHandle, stale_kv_ops, handle->config.blocksize,
                                  sizeof(filemgr_header_revnum_t), OFFSET_SIZE,
                                  0x0, NULL);
        }
    } else {
        staleTree = NULL;
    }

    return FDB_RESULT_SUCCESS;
}

void Compaction::cleanUpCompactionErr(FdbKvsHandle *handle) {
    if (!ver_btreev2_format(fileMgr->getVersion())) {
        btreeHandle->resetSubblockInfo();
    }
    FileMgr::setCompactionState(fileMgr, NULL, FILE_REMOVED_PENDING);
    fileMgr->fhandleRemove(handle->fhandle);
    uint64_t fileVersion = fileMgr->getVersion();
    FileMgr::close(fileMgr, true /* clean up cache */, fileMgr->getFileName(),
                   &handle->log_callback);

    // Free all the resources allocated.
    if (ver_btreev2_format(fileVersion)) {
        delete bnodeMgr;
        if (handle->config.seqtree_opt == FDB_SEQTREE_USE) {
            if (handle->kvs) {
                delete seqTrie;
            } else {
                delete seqTreeV2;
            }
        }
        delete staleTreeV2;
    } else {
        delete btreeHandle;
        if (handle->config.seqtree_opt == FDB_SEQTREE_USE) {
            if (handle->kvs) {
                delete seqTrie;
            } else {
                delete seqTree;
            }
        }
        delete staleTree;
    }
    delete docHandle;
    delete keyTrie;
}

fdb_status Compaction::copyDocsUptoMarker(FdbKvsHandle *rhandle,
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
    ErrLogCallback *log_callback = &rhandle->log_callback;
    uint64_t version = 0;
    fdb_status fs;

    last_hdr_revnum = rhandle->file->getHeaderRevnum(last_hdr_bid);
    marker_revnum = rhandle->file->getHeaderRevnum(marker_bid);
    if (last_hdr_revnum == 0 || marker_revnum == 0){
        return FDB_RESULT_NO_DB_INSTANCE;
    }

    if (last_hdr_revnum < marker_revnum) {
        return FDB_RESULT_NO_DB_INSTANCE;
    } else if (last_hdr_bid == marker_bid) {
        // compact_upto marker is the same as the latest commit header.
        return copyDocs(rhandle, prob, clone_docs);
    }

    old_hdr_bid = last_hdr_bid;
    old_seqnum = last_seq;
    old_hdr_revnum = last_hdr_revnum;

    while (marker_revnum < old_hdr_revnum) {
        old_hdr_bid = rhandle->file->fetchPrevHeader(old_hdr_bid, NULL,
                                                     &header_len, &old_seqnum,
                                                     &old_hdr_revnum, NULL,
                                                     &version, NULL,
                                                     log_callback);
        if (!header_len) { // LCOV_EXCL_START
            return FDB_RESULT_READ_FAIL;
        } // LCOV_EXCL_STOP

        if (rhandle->config.block_reusing_threshold > 0 &&
            rhandle->config.block_reusing_threshold < 100) {
            // block reuse is enabled
            SuperblockBase *sb = rhandle->file->getSb();
            uint64_t sb_min_live_revnum = 0;
            if (sb) {
                sb_min_live_revnum = sb->getMinLiveHdrRevnum();
            }
            if (old_hdr_revnum < sb_min_live_revnum) {
                // gone past the last live header
                return FDB_RESULT_NO_DB_INSTANCE;
            }
        } else {
            // block reuse is disabled
            if (old_hdr_bid < marker_bid) {
                // gone past the snapshot marker
                return FDB_RESULT_NO_DB_INSTANCE;
            }
        }
    }

    // First, move all the docs belonging to a given marker to the new file.
    FdbKvsHandle handle, new_handle;
    Snapshot shandle; // temporary snapshot handle
    KvsInfo kvs;
    fdb_kvs_config kvs_config = rhandle->kvs_config;
    fdb_config config = rhandle->config;
    FileMgr *file = rhandle->file;
    bid_t last_wal_hdr_bid;

    // Setup a temporary handle to look like a snapshot of the old_file
    // at the compaction marker.
    handle.last_hdr_bid = old_hdr_bid; // Fast rewind on open
    handle.max_seqnum = FDB_SNAPSHOT_INMEM; // Prevent WAL restore on open
    handle.shandle = &shandle;
    handle.fhandle = rhandle->fhandle;
    handle.initBusy();
    if (rhandle->kvs) {
        handle.file = file;
        handle.initRootHandle();
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
        fs = FdbEngine::getInstance()->openKvs(NULL,
                                               &config, &kvs_config, file,
                                               file->getFileName(),
                                               NULL,
                                               &handle);
    } else {
        fs = FdbEngine::getInstance()->openFdb(&handle, file->getFileName(),
                                               FDB_AFILENAME, &config);
    }
    if (fs != FDB_RESULT_SUCCESS) {
        return fs;
    }

    // Set the current file's sequence numbers into the header of the new file
    // so they gets migrated correctly for the fdb_set_file_header below.
    fileMgr->setSeqnum(old_seqnum);
    if (rhandle->kvs) {
        // Copy the current file's sequence numbers to the new file.
        fdb_kvs_header_read(fileMgr->getKVHeader_UNLOCKED(), handle.dhandle,
                            handle.kv_info_offset, version, true);
        // Reset KV stats as they are updated while moving documents below.
        fdb_kvs_header_reset_all_stats(file);
    }

    // Move all docs from the current file to the new file
    fs = copyDocs(&handle, prob, clone_docs);
    if (fs != FDB_RESULT_SUCCESS) {
        if (ver_btreev2_format(handle.file->getVersion())) {
            handle.bnodeMgr->releaseCleanNodes();
        } else {
            handle.bhandle->flushBuffer();
        }
        FdbEngine::getInstance()->closeKVHandle(&handle);
        return fs;
    }

    // Restore docs between [last WAL flush header] ~ [compact_upto marker]
    last_wal_hdr_bid = handle.last_wal_flush_hdr_bid;
    if (last_wal_hdr_bid == BLK_NOT_FOUND) {
        // WAL has not been flushed ever
        last_wal_hdr_bid = 0; // scan from the beginning
        last_wal_hdr_revnum = 0;
    } else {
        last_wal_hdr_revnum = rhandle->file->getHeaderRevnum(last_wal_hdr_bid);
    }

    if (last_wal_hdr_revnum < old_hdr_revnum) {
        fs = copyWalDocs(&handle, last_wal_hdr_bid, old_hdr_bid);
        if (fs != FDB_RESULT_SUCCESS) {
            if (ver_btreev2_format(handle.file->getVersion())) {
                handle.bnodeMgr->releaseCleanNodes();
            } else {
                handle.bhandle->flushBuffer();
            }
            FdbEngine::getInstance()->closeKVHandle(&handle);
            return fs;
        }
    }

    // Note that WAL commit and flush are already done in fdb_compact_move_docs() AND
    // fdb_move_wal_docs().
    fileMgr->getWal()->setDirtyStatus_Wal(FDB_WAL_CLEAN);

    // Initialize a KVS handle for a new file.
    new_handle = handle;
    new_handle.file = fileMgr;
    new_handle.dhandle = docHandle;
    if (ver_btreev2_format(fileMgr->getVersion())) {
        new_handle.bnodeMgr = bnodeMgr;
    } else {
        new_handle.bhandle = btreeHandle;
    }
    new_handle.trie = keyTrie;
    new_handle.kv_info_offset = BLK_NOT_FOUND;

    // Note: Appending KVS header must be done after flushing WAL
    //       because KVS stats info is updated during WAL flushing.
    if (new_handle.kvs) {
        // multi KV instance mode .. append up-to-date KV header
        new_handle.kv_info_offset = fdb_kvs_header_append(&new_handle);
        new_handle.seqtrie = seqTrie;
    } else {
        if (ver_btreev2_format(fileMgr->getVersion())) {
            new_handle.seqtreeV2 = seqTreeV2;
        } else {
            new_handle.seqtree = seqTree;
        }

    }
    if (ver_btreev2_format(fileMgr->getVersion())) {
        new_handle.staletreeV2 = staleTreeV2;
    } else {
        new_handle.staletree = staleTree;
    }

    new_handle.last_hdr_bid = new_handle.file->getNextAllocBlock();
    new_handle.last_wal_flush_hdr_bid = new_handle.last_hdr_bid; // WAL was flushed
    new_handle.cur_header_revnum = fdb_set_file_header(&new_handle);

    // Commit a new file.
    fs = new_handle.file->commit_FileMgr(false, // asynchronous commit is ok
                                         log_callback);

    if (ver_btreev2_format(fileMgr->getVersion())) {
        handle.bnodeMgr->releaseCleanNodes();
    } else {
        handle.bhandle->flushBuffer();
        new_handle.bhandle->resetSubblockInfo();
    }

    handle.shandle = NULL;
    FdbEngine::getInstance()->closeKVHandle(&handle);
    return fs;
}

fdb_status Compaction::copyWalDocs(FdbKvsHandle *handle,
                                   bid_t start_bid,
                                   bid_t stop_bid)
{
    struct timeval tv;
    timestamp_t cur_timestamp;
    FdbKvsHandle new_handle;
    uint32_t blocksize = handle->file->getBlockSize();
    uint64_t offset; // starting point
    uint64_t new_offset;
    uint64_t stop_offset = stop_bid * blocksize; // stopping point
    uint64_t n_moved_docs = 0;
    uint64_t filesize = handle->file->getPos();
    uint64_t doc_scan_limit;
    uint64_t start_bmp_revnum, stop_bmp_revnum;
    uint64_t cur_bmp_revnum = (uint64_t)-1;
    struct _fdb_key_cmp_info cmp_info;
    fdb_compact_decision decision;
    ErrLogCallback *log_callback;
    fdb_status fs = FDB_RESULT_SUCCESS;

    gettimeofday(&tv, NULL);
    cur_timestamp = tv.tv_sec;

    if (start_bid == BLK_NOT_FOUND || start_bid == stop_bid) {
        return fs;
    } else {
        offset = (start_bid + 1) * blocksize;
    }

    // TODO: Need to adapt readDoc_Docio to separate false checksum errors.
    log_callback = handle->dhandle->getLogCallback();
    handle->dhandle->setLogCallback(NULL);
    cmp_info.kvs_config = handle->kvs_config;
    cmp_info.kvs = handle->kvs;

    start_bmp_revnum = handle->file->getSbBmpRevnum(start_bid);
    stop_bmp_revnum= handle->file->getSbBmpRevnum(stop_bid);
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

        if (!handle->dhandle->checkBuffer_Docio(offset / blocksize,
                                cur_bmp_revnum)) {
            // not a document block .. move to next block
        } else {
            uint64_t offset_original = offset;
            do {
                fdb_doc wal_doc;
                uint8_t deleted;
                struct docio_object doc;
                int64_t _offset;
                memset(&doc, 0, sizeof(doc));
                _offset = handle->dhandle->readDoc_Docio(offset, &doc, true);
                if (_offset < 0) {
                    // Read error
                    free(doc.key);
                    free(doc.meta);
                    free(doc.body);
                    if (ver_non_consecutive_doc(handle->file->getVersion())) {
                        // Since MAGIC_002: should terminate the compaction.
                        return (fdb_status) _offset;
                    } else {
                        // MAGIC_000, 001: due to garbage (allocated but not written)
                        // block, false alarm should be tolerable.
                        break;
                    }
                }
                if (_offset == 0 ||
                    (!doc.key && !(doc.length.flag & DOCIO_TXN_COMMITTED))) {
                    // No more documents in this block, break and move to the next block
                    if (doc.key) {
                        free(doc.key);
                    }
                    free(doc.meta);
                    free(doc.body);
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
                    _offset = handle->dhandle->readDoc_Docio(doc.doc_offset,
                                                              &doc, true);
                    if (_offset <= 0) { // doc read error
                        // Should terminate the compaction
                        free(doc.key);
                        free(doc.meta);
                        free(doc.body);
                        return _offset < 0 ?
                            (fdb_status) _offset : FDB_RESULT_KEY_NOT_FOUND;
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

                    kv_seqnum = fdb_kvs_get_seqnum(handle->file, kv_id);
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
                    auto curApi = handle->suspendBusy();
                    decision = handle->config.compaction_cb(
                               handle->fhandle, FDB_CS_MOVE_DOC,
                               kvs_name, &wal_doc, offset, BLK_NOT_FOUND,
                               handle->config.compaction_cb_ctx);
                    handle->resumeBusy(curApi);
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
                    new_offset = docHandle->appendDoc_Docio(&doc, deleted, 0);
                    if (new_offset == BLK_NOT_FOUND) {
                        free(doc.key);
                        free(doc.meta);
                        free(doc.body);
                        return FDB_RESULT_WRITE_FAIL;
                    }
                } else {
                    new_offset = BLK_NOT_FOUND;
                }

                fileMgr->getWal()->insert_Wal(fileMgr->getGlobalTxn(), &cmp_info,
                                              &wal_doc, new_offset,
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
        if (ver_superblock_support(handle->file->getVersion()) &&
            offset >= filesize && cur_bmp_revnum < stop_bmp_revnum) {
            // circular scan
            offset = blocksize * handle->file->getSb()->getConfig().num_sb;
            cur_bmp_revnum++;
        }
    } while(true);

    // wal flush into new file so all documents are reflected in its main index
    if (n_moved_docs) {
        union wal_flush_items flush_items;
        new_handle = *handle;
        new_handle.file = fileMgr;
        new_handle.trie = keyTrie;
        new_handle.dhandle = docHandle;
        if (ver_btreev2_format(fileMgr->getVersion())) { // use BtreeV2
            if (handle->kvs) {
                new_handle.seqtrie = seqTrie;
            } else {
                new_handle.seqtreeV2 = seqTreeV2;
            }
            new_handle.staletreeV2 = staleTreeV2;
            new_handle.bnodeMgr = bnodeMgr;
        } else { // initialize the handle with older BTree format..
            if (handle->kvs) {
                new_handle.seqtrie = seqTrie;
            } else {
                new_handle.seqtree = seqTree;
            }
            new_handle.staletree = staleTree;
            new_handle.bhandle = btreeHandle;
        }

        fileMgr->getWal()->flush_Wal((void*) &new_handle,
                                     WalFlushCallbacks::flushItem,
                                     WalFlushCallbacks::getOldOffset,
                                     WalFlushCallbacks::purgeSeqTreeEntry,
                                     WalFlushCallbacks::updateKvsDeltaStats,
                                     &flush_items);
        fileMgr->getWal()->setDirtyStatus_Wal(FDB_WAL_PENDING);
        fileMgr->getWal()->releaseFlushedItems_Wal(&flush_items);
    }

    handle->dhandle->setLogCallback(log_callback);
    return fs;
}

fdb_status Compaction::copyDocs(FdbKvsHandle *handle,
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
    HBTrieIterator *it;
    struct timeval tv;
    struct _fdb_key_cmp_info cmp_info;
    fdb_doc wal_doc;
    FdbKvsHandle new_handle;
    timestamp_t cur_timestamp;
    fdb_status fs = FDB_RESULT_SUCCESS;

    bid_t compactor_curr_bid, writer_curr_bid;
    bid_t compactor_prev_bid, writer_prev_bid;
    bool locked = false;

#ifdef _COW_COMPACTION
    if (clone_docs) {
        if (!FileMgr::isCowSupported(handle->file, fileMgr)) {
            return FDB_RESULT_COMPACTION_FAIL;
        }
        return cloneDocs(handle, prob);
    }
#else
    (void)clone_docs;
#endif // _COW_COMPACTION

    compactor_prev_bid = 0;
    writer_prev_bid = handle->file->getPos() /
                      handle->file->getConfig()->getBlockSize();

    // Init AIO buffer, callback, event instances.
    struct async_io_handle *aio_handle_ptr = NULL;
    struct async_io_handle aio_handle;
    aio_handle.queue_depth = ASYNC_IO_QUEUE_DEPTH;
    aio_handle.block_size = handle->file->getConfig()->getBlockSize();
    aio_handle.fops_handle = handle->file->getFopsHandle();
    if (handle->file->getOps()->aio_init(handle->file->getFopsHandle(),
                                         &aio_handle) == FDB_RESULT_SUCCESS) {
        aio_handle_ptr = &aio_handle;
    }

    if (handle->config.compaction_cb &&
        handle->config.compaction_cb_mask & FDB_CS_BEGIN) {
        auto curApi = handle->suspendBusy();
        handle->config.compaction_cb(handle->fhandle, FDB_CS_BEGIN, NULL, NULL,
                                     0, 0, handle->config.compaction_cb_ctx);
        handle->resumeBusy(curApi);
    }

    gettimeofday(&tv, NULL);
    cur_timestamp = tv.tv_sec;

    cmp_info.kvs_config = handle->kvs_config;
    cmp_info.kvs = handle->kvs;

    new_handle = *handle;
    new_handle.file = fileMgr;
    new_handle.trie = keyTrie;
    new_handle.dhandle = docHandle;
    if (ver_btreev2_format(fileMgr->getVersion())) { // use BtreeV2
        if (handle->kvs) {
            new_handle.seqtrie = seqTrie;
        } else {
            new_handle.seqtreeV2 = seqTreeV2;
        }
        new_handle.staletreeV2 = staleTreeV2;
        new_handle.bnodeMgr = bnodeMgr;
    } else { // initialize the handle with older BTree format..
        if (handle->kvs) {
            new_handle.seqtrie = seqTrie;
        } else {
            new_handle.seqtree = seqTree;
        }
        new_handle.staletree = staleTree;
        new_handle.bhandle = btreeHandle;
    }

    // 1/10 of the block cache size or
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
        calloc(FDB_COMP_BATCHSIZE, sizeof(struct docio_object));
    c = count = n_moved_docs = old_offset = new_offset = 0;

    it = new HBTrieIterator();
    hr = it->init(handle->trie, NULL, 0);

    while( hr == HBTRIE_RESULT_SUCCESS ) {

        hr = it->nextValueOnly((void*)&offset);
        if (ver_btreev2_format(handle->file->getVersion())) {
            handle->bnodeMgr->releaseCleanNodes();
        } else {
            fs = handle->bhandle->flushBuffer();
            if (fs != FDB_RESULT_SUCCESS) {
                break;
            }
        }
        offset = _endian_decode(offset);

        if ( hr == HBTRIE_RESULT_SUCCESS ) {
            // add to offset array
            offset_array[c] = offset;
            c++;
        }

        // if array exceeds the threshold, OR
        // there's no next item (hr == HBTRIE_RESULT_FAIL),
        // sort and move the documents in the array
        if (c >= offset_array_max ||
            (c > 0 && hr != HBTRIE_RESULT_SUCCESS)) {
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
                    handle->dhandle->batchReadDocs_Docio(&offset_array[start_idx],
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
                        auto curApi = handle->suspendBusy();
                        decision = handle->config.compaction_cb(
                                   handle->fhandle, FDB_CS_MOVE_DOC,
                                   kvs_name, &wal_doc,
                                   offset_array[start_idx + j],
                                   BLK_NOT_FOUND,
                                   handle->config.compaction_cb_ctx);
                        handle->resumeBusy(curApi);
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
                        new_offset = docHandle->appendDoc_Docio(&doc[j],
                                                                deleted, 0);
                        old_offset = offset_array[start_idx + j];

                        wal_doc.body = doc[j].body;
                        wal_doc.size_ondisk= _fdb_get_docsize(doc[j].length);
                        wal_doc.offset = new_offset;

                        fileMgr->getWal()->insert_Wal(fileMgr->getGlobalTxn(),
                                                      &cmp_info, &wal_doc,
                                                      new_offset,
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
                    auto curApi = handle->suspendBusy();
                    handle->config.compaction_cb(handle->fhandle,
                                                 FDB_CS_BATCH_MOVE, NULL, NULL,
                                                 old_offset, new_offset,
                                                 handle->config.compaction_cb_ctx);
                    handle->resumeBusy(curApi);
                }

                // === flush WAL entries by compactor ===
                if (fileMgr->getWal()->getNumFlushable_Wal() > 0) {
                    uint64_t delay_us;
                    delay_us = calculateWriteThrottlingDelay(n_moved_docs, tv);

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
                        handle->file->setThrottlingDelay(delay_us);
                        locked = true;
                    } else {
                        locked = false;
                    }
                    union wal_flush_items flush_items;
                    fileMgr->getWal()->flushByCompactor_Wal((void*)&new_handle,
                                                    WalFlushCallbacks::flushItem,
                                                    WalFlushCallbacks::getOldOffset,
                                                    WalFlushCallbacks::purgeSeqTreeEntry,
                                                    WalFlushCallbacks::updateKvsDeltaStats,
                                                    &flush_items);
                    fileMgr->getWal()->setDirtyStatus_Wal(FDB_WAL_PENDING);
                    fileMgr->getWal()->releaseFlushedItems_Wal(&flush_items);
                    if (locked) {
                        handle->file->setThrottlingDelay(0);
                    }

                    if (handle->config.compaction_cb &&
                        handle->config.compaction_cb_mask & FDB_CS_FLUSH_WAL) {
                        auto curApi = handle->suspendBusy();
                        handle->config.compaction_cb(handle->fhandle,
                                                     FDB_CS_FLUSH_WAL, NULL,
                                                     NULL,
                                                     old_offset, new_offset,
                                                     handle->
                                                     config.compaction_cb_ctx);
                        handle->resumeBusy(curApi);
                    }
                }

                writer_curr_bid = handle->file->getPos() /
                                  handle->file->getConfig()->getBlockSize();
                compactor_curr_bid = fileMgr->getPos()
                                   / fileMgr->getConfig()->getBlockSize();
                updateWriteThrottlingProb(writer_curr_bid, compactor_curr_bid,
                                          &writer_prev_bid,
                                          &compactor_prev_bid,
                                          prob,
                                          handle->config.max_writer_lock_prob);

                // If the rollback operation is issued, abort the compaction task.
                if (handle->file->isRollbackOn()) {
                    fs = FDB_RESULT_FAIL_BY_ROLLBACK;
                    break;
                }
                if (handle->file->isCompactionCancellationRequested()) {
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

    delete it;
    free(offset_array);
    free(doc);

    if (aio_handle_ptr) {
        handle->file->getOps()->aio_destroy(handle->file->getFopsHandle(),
                                            aio_handle_ptr);
    }

    if (handle->config.compaction_cb &&
        handle->config.compaction_cb_mask & FDB_CS_END) {
        auto curApi = handle->suspendBusy();
        handle->config.compaction_cb(handle->fhandle, FDB_CS_END,
                                     NULL, NULL, old_offset, new_offset,
                                     handle->config.compaction_cb_ctx);
        handle->resumeBusy(curApi);
    }

    return fs;
}

#ifdef _COW_COMPACTION
// Warning: This api assumes writer cannot access newly compacted file until
// compaction is complete. If this behavior changes to interleave writer with
// compactor in new file, this function must be modified!
fdb_status Compaction::cloneDocs(FdbKvsHandle *handle, size_t *prob)
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
    HBTrieIterator *it;
    struct timeval tv;
    fdb_doc wal_doc;
    FdbKvsHandle new_handle;
    bid_t compactor_curr_bid, writer_curr_bid;
    bid_t compactor_prev_bid, writer_prev_bid;
    struct _fdb_key_cmp_info cmp_info;
    bool locked = false;

    timestamp_t cur_timestamp;
    fdb_status fs = FDB_RESULT_SUCCESS;
    blocksize = handle->file->getConfig()->getBlockSize();

    compactor_prev_bid = 0;
    writer_prev_bid = handle->file->getPos() /
                      handle->file->getConfig()->getBlockSize();

    // Init AIO buffer, callback, event instances.
    struct async_io_handle *aio_handle_ptr = NULL;
    struct async_io_handle aio_handle;
    aio_handle.queue_depth = ASYNC_IO_QUEUE_DEPTH;
    aio_handle.block_size = handle->file->getConfig()->getBlockSize();
    aio_handle.fops_handle = handle->file->getFopsHandle();
    if (handle->file->getOps()->aio_init(handle->file->getFopsHandle(),
                                         &aio_handle)== FDB_RESULT_SUCCESS) {
        aio_handle_ptr = &aio_handle;
    }
    if (handle->config.compaction_cb &&
        handle->config.compaction_cb_mask & FDB_CS_BEGIN) {
        auto curApi = handle->suspendBusy();
        handle->config.compaction_cb(handle->fhandle, FDB_CS_BEGIN, NULL, NULL,
                                     0, 0, handle->config.compaction_cb_ctx);
        handle->resumeBusy(curApi);
    }

    gettimeofday(&tv, NULL);
    cur_timestamp = tv.tv_sec;

    cmp_info.kvs_config = handle->kvs_config;
    cmp_info.kvs = handle->kvs;

    new_handle = *handle;
    new_handle.file = fileMgr;
    new_handle.trie = keyTrie;
    new_handle.dhandle = docHandle;
    if (ver_btreev2_format(fileMgr->getVersion())) { // use BtreeV2
        if (handle->kvs) {
            new_handle.seqtrie = seqTrie;
        } else {
            new_handle.seqtreeV2 = seqTreeV2;
        }
        new_handle.staletreeV2 = staleTreeV2;
        new_handle.bnodeMgr = bnodeMgr;
    } else { // initialize the handle with older BTree format..
        if (handle->kvs) {
            new_handle.seqtrie = seqTrie;
        } else {
            new_handle.seqtree = seqTree;
        }
        new_handle.staletree = staleTree;
        new_handle.bhandle = btreeHandle;
    }

    _doc = (struct docio_object *)
        calloc(FDB_COMP_BATCHSIZE, sizeof(struct docio_object));
    offset_array_max = FDB_COMP_BATCHSIZE / sizeof(uint64_t);
    offset_array = (uint64_t*)malloc(sizeof(uint64_t) * offset_array_max);

    c = old_offset = new_offset = 0;

    it = new HBTrieIterator();
    hr = it->init(handle->trie, NULL, 0);

    while( hr == HBTRIE_RESULT_SUCCESS ) {

        it->nextValueOnly((void*)&offset);
        if (ver_btreev2_format(handle->file->getVersion())) {
            handle->bnodeMgr->releaseCleanNodes();
        } else {
            fs = handle->bhandle->flushBuffer();
            if (fs != FDB_RESULT_SUCCESS) {
                free(_doc);
                delete it;
                free(offset_array);
                return fs;
            }
        }
        offset = _endian_decode(offset);

        if ( hr == HBTRIE_RESULT_SUCCESS ) {
            // add to offset array
            offset_array[c] = offset;
            c++;
        }

        // if array exceeds the threshold, OR
        // there's no next item (hr == HBTRIE_RESULT_FAIL),
        // sort and move the documents in the array
        if (c >= offset_array_max ||
            (c > 0 && hr != HBTRIE_RESULT_SUCCESS)) {
            // quick sort
            qsort(offset_array, c, sizeof(uint64_t), _fdb_cmp_uint64_t);

            size_t num_batch_reads =
            handle->dhandle->batchReadDocs_Docio(&offset_array[0],
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
            docHandle->reset_Docio();
            dst_bid = fileMgr->getPos() / blocksize;
            if (fileMgr->getPos() % blocksize) {
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
                    auto curApi = handle->suspendBusy();
                    decision = handle->config.compaction_cb(
                               handle->fhandle, FDB_CS_MOVE_DOC,
                               kvs_name, &wal_doc, _offset, BLK_NOT_FOUND,
                               handle->config.compaction_cb_ctx);
                    handle->resumeBusy(curApi);
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
                        fs = FileMgr::copyFileRange(handle->file, fileMgr,
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

                    fileMgr->getWal()->insert_Wal(fileMgr->getGlobalTxn(), &cmp_info,
                                                  &wal_doc, new_offset,
                                                  WAL_INS_COMPACT_PHASE1);
                    ++n_moved_docs;
                } // if non-deleted or deleted-but-not-yet-purged doc check
                free(doc.key);
                free(doc.meta);

                if (handle->config.compaction_cb &&
                    handle->config.compaction_cb_mask & FDB_CS_BATCH_MOVE) {
                    auto curApi = handle->suspendBusy();
                    handle->config.compaction_cb(handle->fhandle,
                                                 FDB_CS_BATCH_MOVE, NULL, NULL,
                                                 old_offset, new_offset,
                                                 handle->config.compaction_cb_ctx);
                    handle->resumeBusy(curApi);
                }
            } // repeat until no more offset in the offset_array

            // copy out the last set of contiguous blocks
            fs = FileMgr::copyFileRange(handle->file, fileMgr, src_bid,
                                        dst_bid, 1 + clone_len);
            if (fs != FDB_RESULT_SUCCESS) {
                break;
            }
            // === flush WAL entries by compactor ===
            if (fileMgr->getWal()->getNumFlushable_Wal() > 0) {
                uint64_t delay_us = calculateWriteThrottlingDelay(n_moved_docs, tv);
                // We intentionally try to slow down the normal writer if
                // the compactor can't catch up with the writer. This is a
                // short-term approach and we plan to address this issue without
                // sacrificing the writer's performance soon.
                rv = (size_t)random(100);
                if (rv < *prob) {
                    // Set the sleep time for the normal writer
                    // according to the current speed of compactor
                    handle->file->setThrottlingDelay(delay_us);
                    locked = true;
                } else {
                    locked = false;
                }
                union wal_flush_items flush_items;
                fileMgr->getWal()->flushByCompactor_Wal((void*)&new_handle,
                                       WalFlushCallbacks::flushItem,
                                       WalFlushCallbacks::getOldOffset,
                                       WalFlushCallbacks::purgeSeqTreeEntry,
                                       WalFlushCallbacks::updateKvsDeltaStats,
                                       &flush_items);
                fileMgr->getWal()->setDirtyStatus_Wal(FDB_WAL_PENDING);
                fileMgr->getWal()->releaseFlushedItems_Wal(&flush_items);
                if (locked) {
                    handle->file->setThrottlingDelay(0);
                }

                if (handle->config.compaction_cb &&
                    handle->config.compaction_cb_mask & FDB_CS_FLUSH_WAL) {
                    auto curApi = handle->suspendBusy();
                    handle->config.compaction_cb(handle->fhandle,
                                                 FDB_CS_FLUSH_WAL, NULL, NULL,
                                                 old_offset, new_offset,
                                                 handle->config.compaction_cb_ctx);
                    handle->resumeBusy(curApi);
                }
            }

            writer_curr_bid = handle->file->getPos() /
                              handle->file->getConfig()->getBlockSize();
            compactor_curr_bid = fileMgr->getPos() /
                                 fileMgr->getConfig()->getBlockSize();
            updateWriteThrottlingProb(writer_curr_bid, compactor_curr_bid,
                                      &writer_prev_bid, &compactor_prev_bid,
                                      prob, handle->config.max_writer_lock_prob);

            // If the rollback operation is issued, abort the compaction task.
            if (handle->file->isRollbackOn()) {
                fs = FDB_RESULT_FAIL_BY_ROLLBACK;
                break;
            }
            if (handle->file->isCompactionCancellationRequested()) {
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
    delete it;
    free(offset_array);

    if (handle->config.compaction_cb &&
        handle->config.compaction_cb_mask & FDB_CS_END) {
        auto curApi = handle->suspendBusy();
        handle->config.compaction_cb(handle->fhandle, FDB_CS_END,
                                     NULL, NULL, old_offset, new_offset,
                                     handle->config.compaction_cb_ctx);
        handle->resumeBusy(curApi);
    }

    return fs;
}
#endif // _COW_COMPACTION

fdb_status Compaction::copyDelta(FdbKvsHandle *handle,
                                 bid_t begin_hdr,
                                 bid_t end_hdr,
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
    uint64_t file_limit = end_hdr * handle->file->getBlockSize();
    uint64_t doc_scan_limit;
    uint64_t start_bmp_revnum, stop_bmp_revnum;
    uint64_t cur_bmp_revnum = static_cast<uint64_t>(-1);
    size_t c;
    size_t blocksize = handle->file->getConfig()->getBlockSize();
    struct timeval tv;
    struct docio_object *doc;
    FdbKvsHandle new_handle;
    timestamp_t cur_timestamp;
    fdb_status fs = FDB_RESULT_SUCCESS;
    ErrLogCallback *log_callback;
    uint8_t *hdr_buf = alca(uint8_t, blocksize);

    bid_t compactor_bid_prev, writer_bid_prev;
    bid_t compactor_curr_bid, writer_curr_bid;
    bool distance_updated = false;

    if (handle->config.compaction_cb &&
        handle->config.compaction_cb_mask & FDB_CS_BEGIN) {
        auto curApi = handle->suspendBusy();
        handle->config.compaction_cb(handle->fhandle, FDB_CS_BEGIN, NULL, NULL,
                                     0, 0, handle->config.compaction_cb_ctx);
        handle->resumeBusy(curApi);
    }

    // Temporarily disable log callback function
    log_callback = handle->dhandle->getLogCallback();
    handle->dhandle->setLogCallback(NULL);

    gettimeofday(&tv, NULL);
    cur_timestamp = tv.tv_sec;
    (void)cur_timestamp;

    new_handle = *handle;
    new_handle.file = fileMgr;
    new_handle.trie = keyTrie;
    new_handle.dhandle = docHandle;
    if (ver_btreev2_format(fileMgr->getVersion())) { // use BtreeV2
        if (handle->kvs) {
            new_handle.seqtrie = seqTrie;
        } else {
            new_handle.seqtreeV2 = seqTreeV2;
        }
        new_handle.staletreeV2 = staleTreeV2;
        new_handle.bnodeMgr = bnodeMgr;
    } else { // initialize the handle with older BTree format..
        if (handle->kvs) {
            new_handle.seqtrie = seqTrie;
        } else {
            new_handle.seqtree = seqTree;
        }
        new_handle.staletree = staleTree;
        new_handle.bhandle = btreeHandle;
    }
    new_handle.kv_info_offset = BLK_NOT_FOUND;

    doc = (struct docio_object *)
          malloc(sizeof(struct docio_object) * FDB_COMP_BATCHSIZE);
    old_offset_array = (uint64_t*) malloc(sizeof(uint64_t) * FDB_COMP_BATCHSIZE);
    c = old_offset = new_offset = sum_docsize = n_moved_docs = 0;
    offset = (begin_hdr+1) * blocksize;
    offset_end = (end_hdr+1) * blocksize;

    compactor_bid_prev = offset / blocksize;
    writer_bid_prev = (handle->file->getPos() / blocksize);

    start_bmp_revnum = handle->file->getSbBmpRevnum(begin_hdr);
    if (last_loop) {
        // if last loop, 'end_hdr' may not be a header block .. just linear scan
        stop_bmp_revnum = start_bmp_revnum;
    } else {
        stop_bmp_revnum= handle->file->getSbBmpRevnum(end_hdr);
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

        if (!handle->dhandle->checkBuffer_Docio(offset / blocksize,
                                                cur_bmp_revnum)) {
            if (compact_upto &&
                FileMgr::isCommitHeader(handle->dhandle->getReadBuffer(),
                                        blocksize)) {
                // Read the KV sequence numbers from the old file's commit header
                // and copy them into the new_file.
                size_t len = 0;
                uint64_t version;
                fdb_seqnum_t seqnum = 0;
                uint64_t local_bmp_revnum;

                fs = handle->file->fetchHeader(offset / blocksize,
                                               hdr_buf, &len, &seqnum,
                                               NULL, NULL, &version,
                                               &local_bmp_revnum, NULL);
                if (fs != FDB_RESULT_SUCCESS) {
                    // Invalid and corrupted header.
                    free(doc);
                    free(old_offset_array);
                    fdb_log(log_callback, fs,
                            "A commit header with block id (%" _F64 ") in the file '%s'"
                            " seems corrupted!",
                            offset / blocksize, handle->file->getFileName());
                    return fs;
                }

                if (local_bmp_revnum != cur_bmp_revnum) {
                    // different version of superblock BMP revnum
                    // we have to ignore this header to preserve the
                    // order of header sequence.
                    goto move_delta_next_loop;
                }

                fileMgr->setSeqnum(seqnum);
                if (new_handle.kvs) {
                    uint64_t dummy64;
                    uint64_t kv_info_offset;
                    char *compacted_filename = NULL;
                    fdb_fetch_header(version, hdr_buf, &dummy64, &dummy64,
                                     &dummy64, &dummy64, &dummy64, &dummy64,
                                     &dummy64, &dummy64,
                                     &kv_info_offset, &dummy64,
                                     &compacted_filename, NULL);

                    fdb_kvs_header_read(fileMgr->getKVHeader_UNLOCKED(), handle->dhandle,
                                        kv_info_offset, version, true);
                }

                // As this block is a commit header, flush the WAL and write
                // the commit header to the new file.
                if (c) {
                    uint64_t delay_us;
                    delay_us = calculateWriteThrottlingDelay(n_moved_docs, tv);
                    // TODO: return error code from this function...
                    appendBatchedDelta(handle, &new_handle, doc,
                                       old_offset_array, c, clone_docs,
                                       got_lock, prob, delay_us);
                    c = sum_docsize = 0;
                }
                if (ver_btreev2_format(handle->file->getVersion())) {
                    handle->bnodeMgr->releaseCleanNodes();
                } else {
                    handle->bhandle->flushBuffer();
                }

                if (new_handle.kvs) {
                    // multi KV instance mode .. append up-to-date KV header
                    new_handle.kv_info_offset = fdb_kvs_header_append(&new_handle);
                }

                // Note: calling fdb_gather_stale_blocks() MUST be called BEFORE
                // calling FileMgr::getNextAllocBlock(), because the system doc for
                // stale block info should be written BEFORE 'new_handle.last_hdr_bid'.
                new_handle.file->getStaleData()->gatherRegions(&new_handle,
                                                    fileMgr->getHeaderRevnum() + 1,
                                                    new_handle.last_hdr_bid,
                                                    new_handle.kv_info_offset,
                                                    fileMgr->getSeqnum(),
                                                    false );
                new_handle.last_hdr_bid = fileMgr->getNextAllocBlock();
                new_handle.last_wal_flush_hdr_bid = new_handle.last_hdr_bid;
                new_handle.cur_header_revnum = fdb_set_file_header(&new_handle);
                // If synchrouns commit is enabled, then disable it temporarily for each
                // commit header as synchronous commit is not required in the new file
                // during the compaction.
                fs = fileMgr->commit_FileMgr(false, log_callback);
                if (fs != FDB_RESULT_SUCCESS) {
                    free(doc);
                    free(old_offset_array);
                    fdb_log(log_callback, fs,
                            "Commit failure on a new file '%s' during the compaction!",
                            fileMgr->getFileName());
                    return fs;
                }
                if (!ver_btreev2_format(fileMgr->getVersion())) {
                    new_handle.bhandle->resetSubblockInfo();
                }
            }

        } else {
            bool first_doc_in_block = true;
            uint64_t offset_original = offset;
            ErrLogCallback *original_cb;
            ErrLogCallback dummy_cb;

            original_cb = handle->dhandle->getLogCallback();
            dummy_cb.setCallback(fdb_dummy_log_callback);
            dummy_cb.setCtxData(NULL);

            do {
                int64_t _offset;
                uint64_t doc_offset;
                memset(&doc[c], 0, sizeof(struct docio_object));

                if (first_doc_in_block) {
                    // if we read this doc block first time (offset 0),
                    // checksum error should be tolerable.
                    handle->dhandle->setLogCallback(&dummy_cb);
                } else {
                    handle->dhandle->setLogCallback(original_cb);
                }

                _offset = handle->dhandle->readDoc_Docio(offset, &doc[c], true);
                if (_offset < 0) {
                    // Read error

                    // NOTE: during the delta phase of compact_upto(),
                    // following case can happen:
                    // (this is also explained in _fdb_restore_wal())

                    // Writer handles W1 and W2
                    // W1: write docs consecutively in BID 101, 102, 4, 5
                    // W2: write docs consecutively in BID 103, 104, 6, 7

                    // Note that consecutive doc blocks are linked using doc block's
                    // meta section.

                    // In this case, after we scan blocks 101 and 102, then jump to
                    // BID 4 following the linked list. But we should not miss BID
                    // 103 and 104, so we remember the last offset (i.e.,
                    // offset_original), BID 102 in this case. After we read BID
                    // 4 and 5, the linked list ends. Then we return back to BID 102,
                    // and start to scan from BID 103.

                    // However, after scanning BID 103, 104, 6, and 7, then we try
                    // to read BID 105, but BID 105 is not a document block. So
                    // the cursor moves to the first block in the bitmap in a
                    // circular manner, BID 4 in this case. But BID 4 is an
                    // intermediate block of the series of consecutive doc blocks
                    // (101, 102, 4, 5), so reading a doc from offset 0 of BID 4
                    // will cause checksum error.

                    // Hence, we need to tolerate this kinds of doc read errors.

                    // Note that BID 4, 5, 6, 7 are already read, so just ignoring
                    // those doc blocks will not cause any problem.

                    if (ver_non_consecutive_doc(handle->file->getVersion()) &&
                        !first_doc_in_block) {
                        // Since MAGIC_002: should terminate the compaction.
                        for (size_t i = 0; i <= c; ++i) {
                            free(doc[i].key);
                            free(doc[i].meta);
                            free(doc[i].body);
                        }
                        free(doc);
                        free(old_offset_array);
                        return (fdb_status) offset;
                    } else {
                        // MAGIC_000, 001: due to garbage (allocated but not written)
                        // block, false alarm should be tolerable.
                        break;
                    }
                } else if (_offset == 0) { // Reach zero-filled sub-block and skip it
                    break;
                }

                if ((uint64_t)_offset < offset) {
                    // due to circular reuse, cursor moves to the front of the file.
                    // remember the last offset before moving the cursor.
                    offset_original = offset;
                }

                first_doc_in_block = false;

                if (doc[c].key || (doc[c].length.flag & DOCIO_TXN_COMMITTED)) {
                    // check if the doc is transactional or not, and
                    // also check if the doc contains system info
                    if (!(doc[c].length.flag & DOCIO_TXN_DIRTY) &&
                        !(doc[c].length.flag & DOCIO_SYSTEM)) {
                        if (doc[c].length.flag & DOCIO_TXN_COMMITTED) {
                            // commit mark .. read doc offset
                            doc_offset = doc[c].doc_offset;
                            // read the previously skipped doc
                            int64_t off = handle->dhandle->readDoc_Docio(doc_offset,
                                                     &doc[c], true);
                            if (off <= 0) { // doc read error
                                // Should terminate the compaction
                                for (size_t i = 0; i <= c; ++i) {
                                    free(doc[i].key);
                                    free(doc[i].meta);
                                    free(doc[i].body);
                                }
                                free(doc);
                                free(old_offset_array);
                                return off < 0 ?
                                    (fdb_status)off : FDB_RESULT_KEY_NOT_FOUND;
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
                            delay_us = calculateWriteThrottlingDelay(n_moved_docs, tv);

                            // append batched docs & flush WAL
                            // TODO: return error code from this function
                            appendBatchedDelta(handle, &new_handle, doc,
                                               old_offset_array, c, clone_docs,
                                               got_lock, prob, delay_us);
                            c = sum_docsize = 0;
                            writer_curr_bid = handle->file->getPos() / blocksize;
                            compactor_curr_bid = offset / blocksize;
                            updateWriteThrottlingProb(
                                writer_curr_bid, compactor_curr_bid,
                                &writer_bid_prev, &compactor_bid_prev,
                                prob, handle->config.max_writer_lock_prob);
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

                // If the rollback operation is issued, abort the compaction task.
                if (handle->file->isRollbackOn()) {
                    fs = FDB_RESULT_FAIL_BY_ROLLBACK;
                    break;
                }
                if (handle->file->isCompactionCancellationRequested()) {
                    fs = FDB_RESULT_COMPACTION_CANCELLATION;
                    break;
                }

            } while (offset + sizeof(struct docio_length) < doc_scan_limit);

            if (fs == FDB_RESULT_FAIL_BY_ROLLBACK ||
                fs == FDB_RESULT_COMPACTION_CANCELLATION) {
                // abort compaction
                for (size_t i = 0; i < c; ++i) {
                    free(doc[i].key);
                    free(doc[i].meta);
                    free(doc[i].body);
                }
                free(doc);
                free(old_offset_array);
                return fs;
            }

            // Due to non-consecutive doc blocks, offset value may decrease
            // and cause an infinite loop. To avoid this issue, we have to
            // restore the last offset value if offset value is decreased.
            if (offset < offset_original) {
                offset = offset_original;
            }
        }

move_delta_next_loop:
        offset = ((offset / blocksize) + 1) * blocksize;
        if (ver_superblock_support(handle->file->getVersion()) &&
            offset >= file_limit && cur_bmp_revnum < stop_bmp_revnum) {
            // circular scan
            offset = blocksize * handle->file->getSb()->getConfig().num_sb;
            cur_bmp_revnum++;
        }
    } while (true);

    // final append & WAL flush
    if (c) {
        uint64_t delay_us;
        delay_us = calculateWriteThrottlingDelay(n_moved_docs, tv);

        appendBatchedDelta(handle, &new_handle, doc,
                           old_offset_array, c, clone_docs, got_lock,
                           prob, delay_us);
        if (!distance_updated) {
            // Probability was not updated since the amount of delta was not big
            // enough. We need to update it at least once for each iteration.
            writer_curr_bid = handle->file->getPos() / blocksize;
            compactor_curr_bid = offset / blocksize;
            updateWriteThrottlingProb(writer_curr_bid, compactor_curr_bid,
                                      &writer_bid_prev, &compactor_bid_prev,
                                      prob, handle->config.max_writer_lock_prob);
        }
    }

    if (handle->config.compaction_cb &&
        handle->config.compaction_cb_mask & FDB_CS_END) {
        auto curApi = handle->suspendBusy();
        handle->config.compaction_cb(handle->fhandle, FDB_CS_END,
                                     NULL, NULL, old_offset, new_offset,
                                     handle->config.compaction_cb_ctx);
        handle->resumeBusy(curApi);
    }

    handle->dhandle->setLogCallback(log_callback);

    free(doc);
    free(old_offset_array);

    return fs;
}

void Compaction::appendBatchedDelta(FdbKvsHandle *handle,
                                    FdbKvsHandle *new_handle,
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
    struct _fdb_key_cmp_info cmp_info;
    timestamp_t cur_timestamp;

#ifdef _COW_COMPACTION
    if (clone_docs) {
        // Copy on write is a file-system / disk optimization, so it can't be
        // invoked if the blocks of the old-file have not been synced to disk
        bool flushed_blocks = (!got_lock || // blocks before committed DB header
                !handle->file->getConfig()->getNcacheBlock()); // buffer cache is disabled
        if (flushed_blocks &&
            FileMgr::isCowSupported(handle->file, new_handle->file)) {
            cloneBatchedDelta(handle, new_handle, doc,
                              old_offset_array, n_buf, got_lock, prob, delay_us);
            return; // TODO: return status from function above
        }
    }
#endif // _COW_COMPACTION

    cmp_info.kvs_config = handle->kvs_config;
    cmp_info.kvs = handle->kvs;

    gettimeofday(&tv, NULL);
    cur_timestamp  = tv.tv_sec;
    for (i = 0; i < n_buf; ++i) {
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
                handle->file->mutexUnlock();
            }
            size_t key_offset;
            const char *kvs_name = _fdb_kvs_extract_name_off(handle,
                                                wal_doc.key, &key_offset);
            wal_doc.keylen -= key_offset;
            wal_doc.key = (void *)((uint8_t*)wal_doc.key + key_offset);
            auto curApi = handle->suspendBusy();
            decision = handle->config.compaction_cb(
                       handle->fhandle, FDB_CS_MOVE_DOC,
                       kvs_name, &wal_doc, old_offset_array[i],
                       BLK_NOT_FOUND, handle->config.compaction_cb_ctx);
            handle->resumeBusy(curApi);
            wal_doc.key = (void *)((uint8_t*)wal_doc.key - key_offset);
            wal_doc.keylen += key_offset;
            if (got_lock) {
                handle->file->mutexLock();
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
            doc_offset = new_handle->dhandle->appendDoc_Docio(&doc[i],
                                        doc[i].length.flag & DOCIO_DELETED, 0);
        } else {
            doc_offset = BLK_NOT_FOUND;
        }
        // insert into the new file's WAL
        new_handle->file->getWal()->insert_Wal(new_handle->file->getGlobalTxn(),
                                               &cmp_info, &wal_doc, doc_offset,
                                               WAL_INS_COMPACT_PHASE2);

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
            handle->file->setThrottlingDelay(delay_us);
            locked = true;
        }
    }

    // WAL flush
    union wal_flush_items flush_items;
    new_handle->file->getWal()->commit_Wal(new_handle->file->getGlobalTxn(), NULL,
                                           &handle->log_callback);
    new_handle->file->getWal()->flush_Wal((void*)new_handle,
                                          WalFlushCallbacks::flushItem,
                                          WalFlushCallbacks::getOldOffset,
                                          WalFlushCallbacks::purgeSeqTreeEntry,
                                          WalFlushCallbacks::updateKvsDeltaStats,
                                          &flush_items);
    new_handle->file->getWal()->setDirtyStatus_Wal(FDB_WAL_PENDING);
    new_handle->file->getWal()->releaseFlushedItems_Wal(&flush_items);

    if (locked) {
        handle->file->setThrottlingDelay(0);
    }

    if (handle->config.compaction_cb &&
        handle->config.compaction_cb_mask & FDB_CS_FLUSH_WAL) {
        auto curApi = handle->suspendBusy();
        handle->config.compaction_cb(
            handle->fhandle, FDB_CS_FLUSH_WAL, NULL, NULL,
            old_offset_array[i-1], doc_offset,
            handle->config.compaction_cb_ctx);
        handle->resumeBusy(curApi);
    }
}

#ifdef _COW_COMPACTION
// WARNING: caller must ensure n_buf > 0!
void Compaction::cloneBatchedDelta(FdbKvsHandle *handle,
                                   FdbKvsHandle *new_handle,
                                   struct docio_object *doc,
                                   uint64_t *old_offset_array,
                                   uint64_t n_buf,
                                   bool got_lock,
                                   size_t *prob,
                                   uint64_t delay_us)

{
    uint64_t i;
    uint64_t doc_offset = 0;
    FileMgr *file = handle->file;
    FileMgr *new_file = new_handle->file;
    uint64_t src_bid, dst_bid, contiguous_bid;
    uint64_t clone_len;
    uint32_t blocksize = handle->file->getBlockSize();
    struct _fdb_key_cmp_info cmp_info;
    bool locked = false;
    fdb_status fs = FDB_RESULT_SUCCESS;

    cmp_info.kvs_config = handle->kvs_config;
    cmp_info.kvs = handle->kvs;

    clone_len = 0;
    src_bid = old_offset_array[0] / blocksize;
    contiguous_bid = src_bid;
    dst_bid = new_file->getPos() / blocksize;
    if (new_file->getPos() % blocksize) {
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
            fs = FileMgr::copyFileRange(file, new_file, src_bid, dst_bid,
                                        1 + clone_len);
            if (fs != FDB_RESULT_SUCCESS) {
                break;
            }
            new_handle->dhandle->reset_Docio();
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
                handle->file->mutexUnlock();
            }
            size_t key_offset;
            const char *kvs_name = _fdb_kvs_extract_name_off(handle,
                                                 wal_doc.key, &key_offset);
            wal_doc.keylen -= key_offset;
            auto curApi = handle->suspendBusy();
            handle->config.compaction_cb(handle->fhandle, FDB_CS_MOVE_DOC,
                                         kvs_name, &wal_doc,
                                         old_offset_array[i],
                                         doc_offset,
                                         handle->config.compaction_cb_ctx);
            handle->resumeBusy(curApi);
            wal_doc.key = (void *)((uint8_t*)wal_doc.key - key_offset);
            wal_doc.keylen += key_offset;
            if (locked) {
                handle->file->mutexLock();
            }
        }

        new_file->getWal()->insert_Wal(new_file->getGlobalTxn(), &cmp_info,
                                       &wal_doc, doc_offset,
                                       WAL_INS_COMPACT_PHASE2);

        // free
        free(doc[i].key);
        free(doc[i].meta);
        free(doc[i].body);
    }

    // copy out the last set of contiguous blocks
    FileMgr::copyFileRange(file, new_file, src_bid, dst_bid, 1 + clone_len);
    new_handle->dhandle->reset_Docio();

    if (!got_lock) {
        // We intentionally try to slow down the normal writer if
        // the compactor can't catch up with the writer. This is a
        // short-term approach and we plan to address this issue without
        // sacrificing the writer's performance soon.
        size_t rv = (size_t)random(100);
        if (rv < *prob && delay_us) {
            // Set the sleep time for the normal writer
            // according to the current speed of compactor.
            handle->file->setThrottlingDelay(delay_us);
            locked = true;
        }
    }

    // WAL flush
    union wal_flush_items flush_items;
    new_handle->file->getWal()->commit_Wal(new_handle->file->getGlobalTxn(),
                                           NULL, &handle->log_callback);
    new_handle->file->getWal()->flush_Wal((void*)new_handle,
                                          WalFlushCallbacks::flushItem,
                                          WalFlushCallbacks::getOldOffset,
                                          WalFlushCallbacks::purgeSeqTreeEntry,
                                          WalFlushCallbacks::updateKvsDeltaStats,
                                          &flush_items);
    new_handle->file->getWal()->setDirtyStatus_Wal(FDB_WAL_PENDING);
    new_handle->file->getWal()->releaseFlushedItems_Wal(&flush_items);

    if (locked) {
        handle->file->setThrottlingDelay(0);
    }

    if (handle->config.compaction_cb &&
        handle->config.compaction_cb_mask & FDB_CS_FLUSH_WAL) {
        uint64_t array_idx = i > 0 ? i - 1 : 0;
        auto curApi = handle->suspendBusy();
        handle->config.compaction_cb(
            handle->fhandle, FDB_CS_FLUSH_WAL, NULL, NULL,
            old_offset_array[array_idx], doc_offset,
            handle->config.compaction_cb_ctx);
        handle->resumeBusy(curApi);
    }
}
#endif // _COW_COMPACTION

fdb_status Compaction::commitAndRemovePending(FdbKvsHandle *handle,
                                              FileMgr *old_file)
{
    fdb_txn *earliest_txn;
    bool wal_flushed = false;
    bid_t dirty_idtree_root = BLK_NOT_FOUND;
    bid_t dirty_seqtree_root = BLK_NOT_FOUND;
    union wal_flush_items flush_items;
    fdb_status status = FDB_RESULT_SUCCESS;
    FileMgr *new_file = handle->file;
    FileMgr *very_old_file;

    if (ver_btreev2_format(handle->file->getVersion())) {
        handle->bnodeMgr->releaseCleanNodes();
    } else {
        handle->bhandle->flushBuffer();
    }

    // sync dirty root nodes
    struct filemgr_dirty_update_node *prev_node = NULL, *new_node = NULL;

    _fdb_dirty_update_ready(handle, &prev_node, &new_node,
                            &dirty_idtree_root, &dirty_seqtree_root, false);

    new_file->getWal()->commit_Wal(new_file->getGlobalTxn(), NULL,
                                   &handle->log_callback);
    if (new_file->getWal()->getNumFlushable_Wal()) {
        // flush wal if not empty
        new_file->getWal()->flush_Wal((void *)handle,
                                      WalFlushCallbacks::flushItem,
                                      WalFlushCallbacks::getOldOffset,
                                      WalFlushCallbacks::purgeSeqTreeEntry,
                                      WalFlushCallbacks::updateKvsDeltaStats,
                                      &flush_items);
        new_file->getWal()->setDirtyStatus_Wal(FDB_WAL_CLEAN);
        wal_flushed = true;
    } else if (new_file->getWal()->getSize_Wal() == 0) {
        // empty WAL
        new_file->getWal()->setDirtyStatus_Wal(FDB_WAL_CLEAN);
    }

    _fdb_dirty_update_finalize(handle, prev_node, new_node,
                               &dirty_idtree_root, &dirty_seqtree_root, true);

    // Note: Appending KVS header must be done after flushing WAL
    //       because KVS stats info is updated during WAL flushing.
    if (handle->kvs) {
        // multi KV instance mode .. append up-to-date KV header
        handle->kv_info_offset = fdb_kvs_header_append(handle);
    }

    new_file->getStaleData()->gatherRegions(handle,
                                            new_file->getHeaderRevnum() + 1,
                                            new_file->getHeaderBid(),
                                            handle->kv_info_offset,
                                            new_file->getSeqnum(),
                                            false);
    handle->last_hdr_bid = new_file->getNextAllocBlock();
    if (new_file->getWal()->getDirtyStatus_Wal() == FDB_WAL_CLEAN) {
        earliest_txn = new_file->getWal()->getEarliestTxn_Wal(new_file->getGlobalTxn());
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
    new_file->getGlobalTxn()->prev_hdr_bid = handle->last_hdr_bid;
    // file header should be set after stale-block tree is updated.
    handle->cur_header_revnum = fdb_set_file_header(handle);

    SuperblockBase *sb = new_file->getSb();
    if (sb) {
        // sync superblock
        sb->updateHeader(handle);
        sb->syncCircular(handle);
    }
    status = new_file->commit_FileMgr(
                              !(handle->config.durability_opt & FDB_DRB_ASYNC),
                              &handle->log_callback);
    if (status != FDB_RESULT_SUCCESS) {
        old_file->mutexUnlock();
        new_file->mutexUnlock();
        return status;
    }

    if (wal_flushed) {
        new_file->getWal()->releaseFlushedItems_Wal(&flush_items);
    }

    CompactionManager::getInstance()->switchFile(old_file, new_file,
                                                 &handle->log_callback);
    do { // Find all files pointing to old_file and redirect them to new file..
        very_old_file = old_file->searchStaleLinks();
        if (very_old_file) {
            FileMgr::redirectOldFile(very_old_file, new_file,
                                     _fdb_redirect_header);
            very_old_file->commit_FileMgr(
                           !(handle->config.durability_opt & FDB_DRB_ASYNC),
                           &handle->log_callback);
            // I/O errors here are not propogated since this is best-effort
            // Since FileMgr::searchStaleLinks() will have opened the file
            // we must close it here to ensure decrement of ref counter
            FileMgr::close(very_old_file, true, very_old_file->getFileName(),
                           &handle->log_callback);
        }
    } while (very_old_file);

    // Migrate the operational statistics to the new_file, because
    // from this point onward all callers will re-open new_file
    handle->op_stats = KvsStatOperations::migrateOpStats(old_file, new_file);
    fdb_assert(handle->op_stats, 0, 0);
#ifdef _LATENCY_STATS
    // Migrate latency stats from old file to new file..
    LatencyStats::migrate(old_file, new_file);
#endif // _LATENCY_STATS

    // Mark the old file as "remove_pending".
    // Note that a file deletion will be pended until there is no handle
    // referring the file.
    FileMgr::removePending(old_file, new_file, &handle->log_callback);
    // This mutex was acquired by the caller (i.e., FdbEngine::compactFile).
    old_file->mutexUnlock();

    // After compaction is done, we don't need to maintain
    // fhandle list in superblock.
    old_file->fhandleRemove(handle->fhandle);

    // Don't clean up the buffer cache entries for the old file.
    // They will be cleaned up later.
    FileMgr::close(old_file, false, handle->filename.c_str(), &handle->log_callback);

    if (!ver_btreev2_format(handle->file->getVersion())) {
        handle->bhandle->resetSubblockInfo();
    }

    new_file->mutexUnlock();

    handle->op_stats->num_compacts++;

    if (handle->config.compaction_cb &&
        handle->config.compaction_cb_mask & FDB_CS_COMPLETE) {
        auto curApi = handle->suspendBusy();
        handle->config.compaction_cb(handle->fhandle, FDB_CS_COMPLETE,
                                     NULL, NULL, BLK_NOT_FOUND, BLK_NOT_FOUND,
                                     handle->config.compaction_cb_ctx);
        handle->resumeBusy(curApi);
    }
    return status;
}

uint64_t Compaction::calculateWriteThrottlingDelay(uint64_t n_moved_docs,
                                                   struct timeval start_timestamp)
{
    uint64_t elapsed_us, delay_us;
    struct timeval cur_tv, gap;

    if (n_moved_docs == 0) {
        return 0;
    }

    gettimeofday(&cur_tv, NULL);
    gap = _utime_gap(start_timestamp, cur_tv);
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

void Compaction::adjustWriteThrottlingProb(size_t cur_ratio, size_t *prob,
                                           size_t max_prob)
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

void Compaction::updateWriteThrottlingProb(bid_t writer_curr_bid,
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
        adjustWriteThrottlingProb(cur_ratio, prob, max_prob);
    }
    *writer_prev_bid = writer_curr_bid;
    *compactor_prev_bid = compactor_curr_bid;
}
