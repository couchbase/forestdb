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

#ifndef _FDB_ERRORS_H
#define _FDB_ERRORS_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Status values returned by calling ForestDB APIs.
 */
typedef enum {
    /**
     * ForestDB operation success.
     */
    FDB_RESULT_SUCCESS = 0,
    /**
     * Invalid parameters to ForestDB APIs.
     */
    FDB_RESULT_INVALID_ARGS = -1,
    /**
     * Database open operation fails.
     */
    FDB_RESULT_OPEN_FAIL = -2,
    /**
     * Database file not found.
     */
    FDB_RESULT_NO_SUCH_FILE = -3,
    /**
     * Database write operation fails.
     */
    FDB_RESULT_WRITE_FAIL = -4,
    /**
     * Database read operation fails.
     */
    FDB_RESULT_READ_FAIL = -5,
    /**
     * Database close operation fails.
     */
    FDB_RESULT_CLOSE_FAIL = -6,
    /**
     * Database commit operation fails.
     */
    FDB_RESULT_COMMIT_FAIL = -7,
    /**
     * Memory allocation fails.
     */
    FDB_RESULT_ALLOC_FAIL = -8,
    /**
     * A key not found in database.
     */
    FDB_RESULT_KEY_NOT_FOUND = -9,
    /**
     * Read-only access violation.
     */
    FDB_RESULT_RONLY_VIOLATION = -10,
    /**
     * Database compaction fails.
     */
    FDB_RESULT_COMPACTION_FAIL = -11,
    /**
     * Database iterator operation fails.
     */
    FDB_RESULT_ITERATOR_FAIL = -12,
    /**
     * ForestDB I/O seek failure.
     */
    FDB_RESULT_SEEK_FAIL = -13,
    /**
     * ForestDB I/O fsync failure.
     */
    FDB_RESULT_FSYNC_FAIL = -14,
    /**
     * ForestDB I/O checksum error.
     */
    FDB_RESULT_CHECKSUM_ERROR = -15,
    /**
     * ForestDB I/O file corruption.
     */
    FDB_RESULT_FILE_CORRUPTION = -16,
    /**
     * ForestDB I/O compression error.
     */
    FDB_RESULT_COMPRESSION_FAIL = -17,
    /**
     * A database instance with a given sequence number was not found.
     */
    FDB_RESULT_NO_DB_INSTANCE = -18,
    /**
     * Requested FDB operation failed as rollback is currently being executed.
     */
    FDB_RESULT_FAIL_BY_ROLLBACK = -19,
    /**
     * ForestDB config value is invalid.
     */
    FDB_RESULT_INVALID_CONFIG = -20,
    /**
     * Try to perform manual compaction when compaction daemon is enabled.
     */
    FDB_RESULT_MANUAL_COMPACTION_FAIL = -21,
    /**
     * Open a file with invalid compaction mode.
     */
    FDB_RESULT_INVALID_COMPACTION_MODE = -22,
    /**
     * Operation cannot be performed as file handle has not been closed.
     */
    FDB_RESULT_FILE_IS_BUSY = -23,
    /**
     * Database file remove operation fails.
     */
    FDB_RESULT_FILE_REMOVE_FAIL = -24,
    /**
     * Database file rename operation fails.
     */
    FDB_RESULT_FILE_RENAME_FAIL = -25,
    /**
     * Transaction operation fails.
     */
    FDB_RESULT_TRANSACTION_FAIL = -26,
    /**
     * Requested FDB operation failed due to active transactions.
     */
    FDB_RESULT_FAIL_BY_TRANSACTION = -27,
    /**
     * Requested FDB operation failed due to an active compaction task.
     */
    FDB_RESULT_FAIL_BY_COMPACTION = -28,
    /**
     * Filename is too long.
     */
    FDB_RESULT_TOO_LONG_FILENAME = -29,
    /**
     * Passed ForestDB handle is Invalid.
     */
    FDB_RESULT_INVALID_HANDLE = -30,
    /**
     * A KV store not found in database.
     */
    FDB_RESULT_KV_STORE_NOT_FOUND = -31,
    /**
     * There is an opened handle of the KV store.
     */
    FDB_RESULT_KV_STORE_BUSY = -32,
    /**
     * Same KV instance name already exists.
     */
    FDB_RESULT_INVALID_KV_INSTANCE_NAME = -33,
    /**
     * Custom compare function is assigned incorrectly.
     */
    FDB_RESULT_INVALID_CMP_FUNCTION = -34,
    /**
     * DB file can't be destroyed as the file is being compacted.
     * Please retry in sometime.
     */
    FDB_RESULT_IN_USE_BY_COMPACTOR = -35,
    /**
     * DB file used in this operation has not been opened
     */
    FDB_RESULT_FILE_NOT_OPEN = -36
} fdb_status;

#ifdef __cplusplus
}
#endif

#endif
