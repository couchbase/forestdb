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

#ifndef _JSAHN_COMMON_H
#define _JSAHN_COMMON_H

#include <stdlib.h>
#include <stdint.h>
#include <assert.h>
#if !defined(__APPLE__)
#include <malloc.h>
#endif

#include "option.h"
#include "arch.h"
#include "debug.h"
#include "bitwise_utils.h"
#include "time_utils.h"

#ifndef _MEMPOOL
    #define mempool_alloc malloc
    #define mempool_free free
#endif

#define _MEMORY_OVERRIDE

#define alca(type, n) ((type*)alloca(sizeof(type) * (n)))

#define seq_memcpy(dest, src, size, offset_var) \
    memcpy(dest, src, size); \
    offset_var += size

typedef uint64_t bid_t;
#define BLK_NOT_FOUND (UINT64_C(0xffffffffffffffff))

typedef uint8_t file_status_t;
enum{
    FILE_NORMAL = 0,
    FILE_COMPACT_OLD_SCAN = 1,
    FILE_COMPACT_OLD = 2,
    FILE_COMPACT_NEW = 3,
    FILE_CLOSED = 4,
    FILE_REMOVED_PENDING = 5,
};

#define BLK_MARKER_BNODE (0xff)
#define BLK_MARKER_DBHEADER (0xee)
#define BLK_MARKER_DOC (0xdd)
#define BLK_MARKER_SIZE (1)
#define BLK_DBHEADER_SIZE (566)
#define FDB_MAX_FILENAME_LEN (256)

#define randomize() srand((unsigned)time(NULL))
#define random(num) ((rand())%(num))

#define random_custom(prev, num) (prev) = ((prev)+811)&((num)-1)

#endif
