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

#undef NDEBUG
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
    // No compaction now or before or in progress
    FILE_NORMAL = 0,
    // fdb_compact_upto() begun but not reached latest header - use old_file
    FILE_COMPACT_INPROG = 1,
    // fdb_compact has begun - switch to using the new_file for new fdb_set()s
    FILE_COMPACT_OLD = 2,
    // this is a new file in the compaction process
    FILE_COMPACT_NEW = 3,
    // all open handles on the file has been closed
    FILE_CLOSED = 4,
    // compaction completed successfully, and file needs to be removed once all
    // open handles refering to this file are closed or switched to new_file
    FILE_REMOVED_PENDING = 5,
};

#define BLK_MARKER_BNODE (0xff)
#define BLK_MARKER_DBHEADER (0xee)
#define BLK_MARKER_DOC (0xdd)
#define BLK_MARKER_SIZE (1)

#define randomize() srand((unsigned)time(NULL))
#define random(num) ((rand())%(num))

#define random_custom(prev, num) (prev) = ((prev)+811)&((num)-1)

void _dbg_assert(int line, const char *file, uint64_t val, uint64_t expected);

#ifdef _TRACE_HANDLES
# ifndef _UNIT_TESTS
void _fdb_dump_handles(void);
#  define fdb_assert(cond, val, expected)\
   if (!(cond)) { \
     _dbg_assert(__LINE__, __FILE__, (uint64_t)(val), (uint64_t)(expected));\
     _fdb_dump_handles();\
     assert(cond);\
   }
# else // !_UNIT_TESTS
#   define fdb_assert(cond, val, expected) assert(cond)
# endif // !_UNIT_TESTS
#else // if !_TRACE_HANDLES
#  define fdb_assert(cond, val, expected)\
   if (!(cond)) { \
     _dbg_assert(__LINE__, __FILE__, (uint64_t)(val), (uint64_t)(expected));\
     assert(cond);\
   }
#endif // _TRACE_HANDLES
#endif
