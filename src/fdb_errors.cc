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
#include "fdb_engine.h"
#include "fdb_internal.h"

LIBFDB_API
const char* fdb_error_msg(fdb_status err_code)
{
    return FdbEngine::getErrorMsg(err_code);
}

const char* FdbEngine::getErrorMsg(fdb_status err_code)
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

        case FDB_RESULT_TOO_BIG_BUFFER_CACHE:
            return "Buffer cache is too large to be configured and cannot "
                   "exceed 80% of physical memory";

        case FDB_RESULT_NO_DB_HEADERS:
            return "No commit headers found in a database file";

        case FDB_RESULT_HANDLE_BUSY:
            return "Forestdb Handle is being used by another thread";

        case FDB_RESULT_AIO_NOT_SUPPORTED:
            return "Asynchronous I/O is not supported in the current OS";

        case FDB_RESULT_AIO_INIT_FAIL:
            return "Asynchronous I/O init fails";

        case FDB_RESULT_AIO_SUBMIT_FAIL:
            return "Asynchronous I/O init fails";

        case FDB_RESULT_AIO_GETEVENTS_FAIL:
            return "Fail to read asynchronous I/O events from the completion queue";

        case FDB_RESULT_CRYPTO_ERROR:
            return "Encryption error";

        case FDB_RESULT_COMPACTION_CANCELLATION:
            return "Compaction canceled";

        case FDB_RESULT_SB_INIT_FAIL:
            return "Superblock initialization failed";

        case FDB_RESULT_SB_RACE_CONDITION:
            return "DB file is modified during superblock initialization";

        case FDB_RESULT_SB_READ_FAIL:
            return "Superblock is corrupted";

        case FDB_RESULT_FILE_VERSION_NOT_SUPPORTED:
            return "This version of DB file is not supported";


        // All the error codes below correspond to errno values in Linux, OSX,
        // and Windows, which can happen in file opeations.

        case FDB_RESULT_EPERM:
            return "A file operation is not permitted";
        case FDB_RESULT_EIO:
            return "A physical I/O error has occurred";
        case FDB_RESULT_ENXIO:
            return "No such device or address error";
        case FDB_RESULT_EBADF:
            return "Not a valid file descriptor";
        case FDB_RESULT_ENOMEM:
            return "Insufficient memory was available";
        case FDB_RESULT_EACCESS:
            return "File access permission was denied";
        case FDB_RESULT_EFAULT:
            return "Outside the process's accessible address space";
        case FDB_RESULT_EEXIST:
            return "A file name already exists in the file system";
        case FDB_RESULT_ENODEV:
            return "No corresponding device exists";
        case FDB_RESULT_ENOTDIR:
            return "A directory component in a file path name is not a directory";
        case FDB_RESULT_EISDIR:
            return "A file path name refers to a directory";
        case FDB_RESULT_EINVAL:
            return "Arguments to a file operation are not valid";
        case FDB_RESULT_ENFILE:
            return "The system-wide limit on the total number of open files has "
                   "been reached";
        case FDB_RESULT_EMFILE:
            return "The per-process limit on the number of open file descriptors "
                   "has been reached";
        case FDB_RESULT_EFBIG:
            return "A file is too large to be opened";
        case FDB_RESULT_ENOSPC:
            return "No space left on device";
        case FDB_RESULT_EROFS:
            return "A file on a read-only filesystem and write access was requested";
        case FDB_RESULT_EOPNOTSUPP:
            return "A file operation is not supported";
        case FDB_RESULT_ENOBUFS:
            return "Insufficient buffer space was available in the system to perform "
                   "a operation";
        case FDB_RESULT_ELOOP:
            return "Too many symbolic links were encountered in resolving a file path name";
        case FDB_RESULT_ENAMETOOLONG:
            return "A file path name was too long";
        case FDB_RESULT_EOVERFLOW:
            return "A file is too large to be opened";
        case FDB_RESULT_EAGAIN:
            return "Resource temporarily unavailable";
        case FDB_RESULT_CANCELLED:
            return "Execution cancelled";
        case FDB_RESULT_ENGINE_NOT_INSTANTIATED:
            return "ForestDB engine not instantiated yet";
        case FDB_RESULT_LOG_FILE_NOT_FOUND:
            return "Log file not found";
        case FDB_RESULT_LOCK_FAIL:
            return "Unable to acquire/release lock";

        default:
            return "unknown error";
    }
}
