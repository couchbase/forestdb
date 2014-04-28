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
     * General database opertion fails.
     */
    FDB_RESULT_FAIL = -100
} fdb_status;

#ifdef __cplusplus
}
#endif

#endif
