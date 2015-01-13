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
#include "crc32.h"
#include "adler32.h"

#ifndef _MEMPOOL
    #define mempool_alloc malloc
    #define mempool_free free
#endif

#define _MEMORY_OVERRIDE

#define alca(type, n) ((type*)alloca(sizeof(type) * (n)))

#define seq_memcpy(dest, src, size, offset_var) \
    memcpy(dest, src, size); \
    offset_var += size

#ifdef __CHECKSUM_ADLER32
#define chksum(data, len) adler32(1, (uint8_t*)(data), len)
#define chksum_scd(data, len, prev) adler32(prev, (uint8_t*)(data), len)
#define chksum_last8(data, len) adler32_last8(1, (uint8_t*)(data), len)
#else
#define chksum(data, len) crc32_8((void*)(data), len, 0)
#define chksum_scd(data, len, prev) crc32_8((void*)(data), len, prev)
#define chksum_last8(data, len) crc32_8_last8((void*)(data), len, 0)
#endif

typedef uint64_t bid_t;
#define BLK_NOT_FOUND (UINT64_C(0xffffffffffffffff))

typedef uint8_t file_status_t;
enum{
    FILE_NORMAL = 0,
    FILE_COMPACT_OLD = 1,
    FILE_COMPACT_NEW = 2,
    FILE_CLOSED = 3,
    FILE_REMOVED_PENDING = 4,
};

#define BLK_MARKER_BNODE (0xff)
#define BLK_MARKER_DBHEADER (0xee)
#define BLK_MARKER_DOC (0xdd)
#define BLK_MARKER_SIZE (1)

#define randomize() srand((unsigned)time(NULL))
#define random(num) ((rand())%(num))

#define random_custom(prev, num) (prev) = ((prev)+811)&((num)-1)

#endif
