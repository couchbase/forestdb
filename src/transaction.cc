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
#include <assert.h>
#include <stdint.h>

#include "libforestdb/forestdb.h"
#include "fdb_internal.h"
#include "internal_types.h"
#include "filemgr.h"
#include "common.h"
#include "list.h"
#include "wal.h"
#include "memleak.h"

LIBFDB_API
fdb_status fdb_begin_transaction(fdb_handle *handle,
                                 fdb_isolation_level_t isolation_level)
{
    struct filemgr *file;

    if (handle->txn) {
        // transaction already exists
        return FDB_RESULT_TRANSACTION_FAIL;
    }
    if (filemgr_is_rollback_on(handle->file)) {
        // deny beginning transaction during rollback
        return FDB_RESULT_FAIL_BY_ROLLBACK;
    }

    fdb_check_file_reopen(handle);
    fdb_sync_db_header(handle);
    if (handle->new_file == NULL) {
        file = handle->file;
        filemgr_mutex_lock(file);

        fdb_link_new_file(handle);
        if (handle->new_file) {
            // compaction is being performed and new file exists
            // relay lock
            filemgr_mutex_lock(handle->new_file);
            filemgr_mutex_unlock(handle->file);
            // reset FILE
            file = handle->new_file;
        }
    } else {
        file = handle->new_file;
        filemgr_mutex_lock(file);
    }

    handle->txn = (fdb_txn*)malloc(sizeof(fdb_txn));
    handle->txn->wrapper = (struct wal_txn_wrapper *)
                           malloc(sizeof(struct wal_txn_wrapper));
    handle->txn->wrapper->txn = handle->txn;
    handle->txn->handle = handle;
    if (filemgr_get_file_status(handle->file) != FILE_COMPACT_OLD) {
        // keep previous header's BID
        handle->txn->prev_hdr_bid = handle->last_hdr_bid;
    } else {
        // if file status is COMPACT_OLD,
        // then this transaction will work on new file, and
        // there is no previous header until the compaction is done.
        handle->txn->prev_hdr_bid = BLK_NOT_FOUND;
    }
    handle->txn->items = (struct list *)malloc(sizeof(struct list));
    handle->txn->isolation = isolation_level;
    list_init(handle->txn->items);
    wal_add_transaction(file, handle->txn);

    filemgr_mutex_unlock(file);

    return FDB_RESULT_SUCCESS;
}

LIBFDB_API
fdb_status fdb_abort_transaction(fdb_handle *handle)
{
    struct filemgr *file;

    if (handle->txn == NULL) {
        // there is no transaction started
        return FDB_RESULT_TRANSACTION_FAIL;
    }

    fdb_check_file_reopen(handle);
    fdb_sync_db_header(handle);
    if (handle->new_file == NULL) {
        file = handle->file;
        filemgr_mutex_lock(file);

        fdb_link_new_file(handle);
        if (handle->new_file) {
            // compaction is being performed and new file exists
            // relay lock
            filemgr_mutex_lock(handle->new_file);
            filemgr_mutex_unlock(handle->file);
            // reset FILE
            file = handle->new_file;
        }
    } else {
        file = handle->new_file;
        filemgr_mutex_lock(file);
    }

    wal_discard(file, handle->txn);
    wal_remove_transaction(file, handle->txn);

    free(handle->txn->items);
    free(handle->txn->wrapper);
    free(handle->txn);
    handle->txn = NULL;

    filemgr_mutex_unlock(file);

    return FDB_RESULT_SUCCESS;
}

LIBFDB_API
fdb_status fdb_end_transaction(fdb_handle *handle, fdb_commit_opt_t opt)
{
    struct filemgr *file;

    if (handle->txn == NULL) {
        // there is no transaction started
        return FDB_RESULT_TRANSACTION_FAIL;
    }

    fdb_status fs = FDB_RESULT_SUCCESS;
    if (list_begin(handle->txn->items)) {
        fs = fdb_commit(handle, opt);
    }

    if (fs == FDB_RESULT_SUCCESS) {
        fdb_check_file_reopen(handle);
        fdb_sync_db_header(handle);
        if (handle->new_file == NULL) {
            file = handle->file;
            filemgr_mutex_lock(file);

            fdb_link_new_file(handle);
            if (handle->new_file) {
                // compaction is being performed and new file exists
                // relay lock
                filemgr_mutex_lock(handle->new_file);
                filemgr_mutex_unlock(handle->file);
                // reset FILE
                file = handle->new_file;
            }
        } else {
            file = handle->new_file;
            filemgr_mutex_lock(file);
        }

        wal_remove_transaction(file, handle->txn);

        free(handle->txn->items);
        free(handle->txn->wrapper);
        free(handle->txn);
        handle->txn = NULL;

        filemgr_mutex_unlock(file);
    }
    return fs;
}
