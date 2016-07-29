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

#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "libforestdb/forestdb.h"
#include "fdb_engine.h"
#include "fdb_internal.h"
#include "file_handle.h"
#include "internal_types.h"
#include "filemgr.h"
#include "common.h"
#include "list.h"
#include "wal.h"
#include "memleak.h"

// Global static variables
static std::atomic<uint64_t> transaction_id(0); // unique & monotonically increasing

LIBFDB_API
fdb_status fdb_begin_transaction(fdb_file_handle *fhandle,
                                 fdb_isolation_level_t isolation_level)
{
    if (!fhandle || !fhandle->getRootHandle()) {
        return FDB_RESULT_INVALID_HANDLE;
    }

    file_status_t fstatus;
    FdbKvsHandle *handle = fhandle->getRootHandle();
    FileMgr *file;

    if (handle->txn) {
        // transaction already exists
        return FDB_RESULT_TRANSACTION_FAIL;
    }
    if (handle->kvs) {
        if (handle->kvs->getKvsType() == KVS_SUB) {
            // deny transaction on sub handle
            return FDB_RESULT_INVALID_HANDLE;
        }
    }

    uint8_t cond = 0;
    if (!handle->handle_busy.compare_exchange_strong(cond, 1)) {
        return FDB_RESULT_HANDLE_BUSY;
    }

    do { // repeat until file status is not REMOVED_PENDING
        fdb_check_file_reopen(handle, NULL);
        handle->file->mutexLock();
        fdb_sync_db_header(handle);

        cond = 1;
        if (handle->file->isRollbackOn()) {
            // deny beginning transaction during rollback
            handle->file->mutexUnlock();
            handle->handle_busy.compare_exchange_strong(cond, 0);
            return FDB_RESULT_FAIL_BY_ROLLBACK;
        }

        file = handle->file;
        fstatus = file->getFileStatus();
        if (fstatus == FILE_REMOVED_PENDING) {
            // we must not create transaction on this file
            // file status was changed by other thread .. start over
            file->mutexUnlock();
        }
    } while (fstatus == FILE_REMOVED_PENDING);

    handle->txn = (fdb_txn*)malloc(sizeof(fdb_txn));
    handle->txn->wrapper = (struct wal_txn_wrapper *)
                           malloc(sizeof(struct wal_txn_wrapper));
    handle->txn->wrapper->txn = handle->txn;
    handle->txn->handle = handle;
    handle->txn->txn_id = ++transaction_id;
    if (handle->file->getFileStatus() != FILE_COMPACT_OLD) {
        // keep previous header's BID
        handle->txn->prev_hdr_bid = handle->last_hdr_bid;
    } else {
        // if file status is COMPACT_OLD,
        // then this transaction will work on new file, and
        // there is no previous header until the compaction is done.
        handle->txn->prev_hdr_bid = BLK_NOT_FOUND;
    }
    handle->txn->prev_revnum = handle->cur_header_revnum;
    handle->txn->items = (struct list *)malloc(sizeof(struct list));
    handle->txn->isolation = isolation_level;
    list_init(handle->txn->items);
    file->getWal()->addTransaction_Wal(handle->txn);

    file->mutexUnlock();

    cond = 1;
    handle->handle_busy.compare_exchange_strong(cond, 0);
    return FDB_RESULT_SUCCESS;
}

LIBFDB_API
fdb_status fdb_abort_transaction(fdb_file_handle *fhandle)
{
    if (!fhandle) {
        return FDB_RESULT_INVALID_HANDLE;
    }

    return _fdb_abort_transaction(fhandle->getRootHandle());
}

fdb_status _fdb_abort_transaction(FdbKvsHandle *handle)
{
    if (!handle) {
        return FDB_RESULT_INVALID_HANDLE;
    }

    file_status_t fstatus;
    FileMgr *file;

    if (handle->txn == NULL) {
        // there is no transaction started
        return FDB_RESULT_TRANSACTION_FAIL;
    }
    if (handle->kvs) {
        if (handle->kvs->getKvsType() == KVS_SUB) {
            // deny transaction on sub handle
            return FDB_RESULT_INVALID_HANDLE;
        }
    }

    uint8_t cond = 0;
    if (!handle->handle_busy.compare_exchange_strong(cond, 1)) {
        return FDB_RESULT_HANDLE_BUSY;
    }

    do { // repeat until file status is not REMOVED_PENDING
        fdb_check_file_reopen(handle, NULL);

        file = handle->file;
        file->mutexLock();
        fdb_sync_db_header(handle);

        fstatus = file->getFileStatus();
        if (fstatus == FILE_REMOVED_PENDING) {
            // we must not abort transaction on this file
            // file status was changed by other thread .. start over
            file->mutexUnlock();
        }
    } while (fstatus == FILE_REMOVED_PENDING);

    file->getWal()->discardTxnEntries_Wal(handle->txn);
    file->getWal()->removeTransaction_Wal(handle->txn);

    free(handle->txn->items);
    free(handle->txn->wrapper);
    free(handle->txn);
    handle->txn = NULL;

    file->mutexUnlock();

    cond = 1;
    handle->handle_busy.compare_exchange_strong(cond, 0);
    return FDB_RESULT_SUCCESS;
}

LIBFDB_API
fdb_status fdb_end_transaction(fdb_file_handle *fhandle,
                               fdb_commit_opt_t opt)
{
    if (!fhandle || !fhandle->getRootHandle()) {
        return FDB_RESULT_INVALID_HANDLE;
    }

    file_status_t fstatus;
    FdbKvsHandle *handle = fhandle->getRootHandle();
    FileMgr *file;

    if (handle->txn == NULL) {
        // there is no transaction started
        return FDB_RESULT_TRANSACTION_FAIL;
    }
    if (handle->kvs) {
        if (handle->kvs->getKvsType() == KVS_SUB) {
            // deny transaction on sub handle
            return FDB_RESULT_INVALID_HANDLE;
        }
    }

    fdb_status fs = FDB_RESULT_SUCCESS;
    if (list_begin(handle->txn->items)) {
        bool sync = !(handle->config.durability_opt & FDB_DRB_ASYNC);
        fs = FdbEngine::getInstance()->commitWithKVHandle(handle, opt,
                                                          sync);
    }

    if (fs == FDB_RESULT_SUCCESS) {

        do { // repeat until file status is not REMOVED_PENDING
            fdb_check_file_reopen(handle, NULL);

            file = handle->file;
            file->mutexLock();
            fdb_sync_db_header(handle);

            fstatus = file->getFileStatus();
            if (fstatus == FILE_REMOVED_PENDING) {
                // we must not commit transaction on this file
                // file status was changed by other thread .. start over
                file->mutexUnlock();
            }
        } while (fstatus == FILE_REMOVED_PENDING);

        file->getWal()->removeTransaction_Wal(handle->txn);

        free(handle->txn->items);
        free(handle->txn->wrapper);
        free(handle->txn);
        handle->txn = NULL;

        file->mutexUnlock();
    }

    return fs;
}
