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

#ifdef __sun
#include <alloca.h>
#endif

#include <libforestdb/forestdb.h>

#include <string>
#include <vector>

#include "stat_aggregator.h"

//#define __DEBUG_E2E

#ifdef __cplusplus
extern "C" {
#endif

static const char BENCHDB_NAME[] = "fdb_bench_dbfile";
static const char BENCHKV_NAME[] = "fdb_bench_kv";
static const int  KEY_SIZE = 16;
static const int  PERMUTED_BYTES = 4;

// custom stats
static const char ST_ITR_INIT[] = "iterator_init";
static const char ST_ITR_GET[] = "iterator_get";
static const char ST_ITR_NEXT[] = "iterator_next";
static const char ST_ITR_CLOSE[] = "iterator_close";

struct reader_context {
    fdb_kvs_handle *handle;
    stat_history_t *stat_itr_init;
    stat_history_t *stat_itr_get;
    stat_history_t *stat_itr_next;
    stat_history_t *stat_itr_close;
};

#define alca(type, n) ((type*)alloca(sizeof(type) * (n)))

#ifdef __cplusplus
}
#endif
