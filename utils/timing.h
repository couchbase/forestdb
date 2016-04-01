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

//#define __DEBUG_E2E
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#if !defined(WIN32) && !defined(_WIN32)
#include <unistd.h>
#endif
#include "time_utils.h"

#ifdef __cplusplus
extern "C" {
#endif

// Forestdb APIs wrappers where time taken in nano secs is returned on success

static const long int ERR_NS = 0xFFFFFFFF;
ts_nsec timed_fdb_get(fdb_kvs_handle *kv, fdb_doc *doc);
ts_nsec timed_fdb_set(fdb_kvs_handle *kv, fdb_doc *doc);
ts_nsec timed_fdb_delete(fdb_kvs_handle *kv, fdb_doc *doc);
ts_nsec timed_fdb_compact(fdb_file_handle *fhandle);
ts_nsec timed_fdb_commit(fdb_file_handle *fhandle, bool walflush);
ts_nsec timed_fdb_snapshot(fdb_kvs_handle *kv, fdb_kvs_handle **snap_kv);
ts_nsec timed_fdb_iterator_init(fdb_kvs_handle *kv, fdb_iterator **it);
ts_nsec timed_fdb_iterator_get(fdb_iterator *it, fdb_doc **doc);
ts_nsec timed_fdb_iterator_next(fdb_iterator *it);
ts_nsec timed_fdb_iterator_close(fdb_iterator *it);
ts_nsec timed_fdb_kvs_close(fdb_kvs_handle *kv);
ts_nsec timed_fdb_close(fdb_file_handle *fhandle);
ts_nsec timed_fdb_shutdown();

#ifdef __cplusplus
}
#endif
