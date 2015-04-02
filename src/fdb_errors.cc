/* -*- Mode: C++; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2014 Couchbase, Inc
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
#include "libforestdb/forestdb.h"
#include "fdb_internal.h"

LIBFDB_API
const char* fdb_error_msg(fdb_status err_code)
{
    switch (err_code)
    {
        case FDB_RESULT_SUCCESS:
            return "success";

        case FDB_RESULT_INVALID_ARGS:
            return "invalid arguments";

        case FDB_RESULT_OPEN_FAIL:
            return "error opening file";

        case FDB_RESULT_NO_SUCH_FILE:
            return "no such file";

        case FDB_RESULT_WRITE_FAIL:
            return "error writing to file";

        case FDB_RESULT_READ_FAIL:
            return "error reading from file";

        case FDB_RESULT_CLOSE_FAIL:
            return "error closing a file";

        case FDB_RESULT_COMMIT_FAIL:
            return "commit operation failed";

        case FDB_RESULT_ALLOC_FAIL:
            return "failed to allocate memory";

        case FDB_RESULT_KEY_NOT_FOUND:
            return "key not found";

        case FDB_RESULT_RONLY_VIOLATION:
            return "database is read-only";

        case FDB_RESULT_COMPACTION_FAIL:
            return "compaction operation failed";

        case FDB_RESULT_ITERATOR_FAIL:
            return "iterator operation failed";

        case FDB_RESULT_SEEK_FAIL:
            return "seek failure";

        case FDB_RESULT_FSYNC_FAIL:
            return "fsync failure";

        case FDB_RESULT_CHECKSUM_ERROR:
            return "checksum error";

        case FDB_RESULT_FILE_CORRUPTION:
            return "data corruption in file";

        case FDB_RESULT_COMPRESSION_FAIL:
            return "document compression failure";

        case FDB_RESULT_NO_DB_INSTANCE:
            return "database instance not found";

        case FDB_RESULT_FAIL_BY_ROLLBACK:
            return "operation failed due to rollback";

        case FDB_RESULT_INVALID_CONFIG:
            return "invalid configuration";

        case FDB_RESULT_MANUAL_COMPACTION_FAIL:
            return "manual compaction failed";

       case FDB_RESULT_INVALID_COMPACTION_MODE:
            return "invalid compaction mode";

        case FDB_RESULT_FILE_IS_BUSY:
            return "file handle is busy";

        case FDB_RESULT_FILE_REMOVE_FAIL:
            return "file removal operation failed";

        case FDB_RESULT_FILE_RENAME_FAIL:
            return "file rename operation failed";

        case FDB_RESULT_TRANSACTION_FAIL:
            return "transaction operation failed";

        case FDB_RESULT_FAIL_BY_TRANSACTION:
            return "operation failed due to active transaction";

        case FDB_RESULT_FAIL_BY_COMPACTION:
            return "operation failed due to active compaction";

        case FDB_RESULT_TOO_LONG_FILENAME:
            return "filename is too long";

        case FDB_RESULT_INVALID_HANDLE:
            return "ForestDB handle is invalid";

        case FDB_RESULT_KV_STORE_NOT_FOUND:
            return "KV store not found in database";

        case FDB_RESULT_KV_STORE_BUSY:
            return "there is an active open handle on the kvstore";

        case FDB_RESULT_INVALID_KV_INSTANCE_NAME:
            return "same KV instance name already exists";

        case FDB_RESULT_INVALID_CMP_FUNCTION:
            return "custom compare function is assigned incorrectly";

        case FDB_RESULT_IN_USE_BY_COMPACTOR:
            return "file is in use by compactor, retry later";

        case FDB_RESULT_FILE_NOT_OPEN:
            return "this operations needs an opened file handle";

        default:
            return "unknown error";
    }
}
