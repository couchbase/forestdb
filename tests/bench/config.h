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

#include "libforestdb/forestdb.h"

#if defined(WIN32)
#include <windows.h>
#else
#include <unistd.h>
#include <sys/time.h>
#endif


//#define __DEBUG_E2E

#ifdef __cplusplus
extern "C" {
#endif

static const char BENCHDB_NAME[] = "fdb_bench_dbfile";
static const char BENCHKV_NAME[] = "fdb_bench_kv";
static const int  NDOCS = 10000;
static const int  CACHESIZE = 4096;

// stats
static const char ST_SET[] = "set";
static const char ST_GET[] = "get";
static const char ST_DELETE[] = "delete";
static const char ST_COMPACT[] = "compact";
static const char ST_COMMIT_WAL[] = "commit_wal";
static const char ST_COMMIT_NORM[] = "commit_norm";
static const char ST_KV_CLOSE[] = "kv_close";
static const char ST_SNAP_OPEN[] = "snap_open";
static const char ST_SNAP_CLOSE[] = "snap_close";
static const char ST_ITR_INIT[] = "iterator_init";
static const char ST_ITR_GET[] = "iterator_get";
static const char ST_ITR_NEXT[] = "iterator_next";
static const char ST_ITR_CLOSE[] = "iterator_close";
static const char ST_FILE_CLOSE[] = "file_close";
static const char ST_SHUTDOWN[] = "shutdown";

uint64_t resolution_nsec();
uint64_t timestamp();

#ifdef __cplusplus
}
#endif
