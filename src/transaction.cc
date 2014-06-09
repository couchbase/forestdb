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
#include "internal_types.h"
#include "common.h"
#include "list.h"
#include "wal.h"
#include "memleak.h"

LIBFDB_API
fdb_status fdb_begin_transaction(fdb_handle *handle,
                                 fdb_isolation_level_t isolation_level)
{
    if (handle->txn) {
        // transaction already exists
        return FDB_RESULT_TRANSACTION_FAIL;
    }
    handle->txn = (fdb_txn*)malloc(sizeof(fdb_txn));
    handle->txn->handle = handle;
    handle->txn->items = (struct list *)malloc(sizeof(struct list));
    handle->txn->isolation = isolation_level;
    list_init(handle->txn->items);

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

    file = (handle->new_file)?(handle->new_file):(handle->file);
    wal_discard(handle->txn, file);

    free(handle->txn->items);
    free(handle->txn);
    handle->txn = NULL;

    return FDB_RESULT_SUCCESS;
}

LIBFDB_API
fdb_status fdb_end_transaction(fdb_handle *handle, fdb_commit_opt_t opt) {
    if (handle->txn == NULL) {
        // there is no transaction started
        return FDB_RESULT_TRANSACTION_FAIL;
    }

    fdb_status fs = FDB_RESULT_SUCCESS;
    if (list_begin(handle->txn->items)) {
        fs = fdb_commit(handle, opt);
    }
    if (fs == FDB_RESULT_SUCCESS) {
        free(handle->txn->items);
        free(handle->txn);
        handle->txn = NULL;
    }
    return fs;
}
