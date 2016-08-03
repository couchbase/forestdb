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

#if !defined(__APPLE__) && !defined(__FreeBSD__)
#include <malloc.h>
#endif

#include "option.h"
#include "arch.h"
#include "debug.h"
#include "bitwise_utils.h"

// Stolen from http://google-styleguide.googlecode.com/svn/trunk/cppguide.xml
// A macro to disallow the copy constructor and operator= functions
// This should be used in the private: declarations for a class
#define DISALLOW_COPY_AND_ASSIGN(TypeName)      \
    TypeName(const TypeName&);                  \
    void operator=(const TypeName&)

#define DISALLOW_ASSIGN(TypeName)               \
    void operator=(const TypeName&)

#ifndef _MEMPOOL
    #define mempool_alloc malloc
    #define mempool_free free
#endif

#define _MEMORY_OVERRIDE

#define alca(type, n) ((type*)alloca(sizeof(type) * (n)))

#define seq_memcpy(dest, src, size, offset_var) \
    memcpy(dest, src, size); \
    offset_var += size

typedef uint64_t hrtime_t;
typedef uint64_t bid_t;
#define BLK_NOT_FOUND (UINT64_C(0xffffffffffffffff))

typedef uint8_t file_status_t;
enum{
    // No compaction now or before or in progress
    FILE_NORMAL = 0,
    // fdb_compact has begun - switch to using the new_file for new fdb_set()s
    FILE_COMPACT_OLD = 1,
    // this is a new file in the compaction process
    FILE_COMPACT_NEW = 2,
    // all open handles on the file has been closed
    FILE_CLOSED = 3,
    // compaction completed successfully, and file needs to be removed once all
    // open handles refering to this file are closed or switched to new_file
    FILE_REMOVED_PENDING = 4,
};

#define BLK_MARKER_BNODE (0xff)
#define BLK_MARKER_DBHEADER (0xee)
#define BLK_MARKER_DOC (0xdd)
#define BLK_MARKER_SB (0xcc) // superblock
#define BLK_MARKER_SIZE (1)
#define DOCBLK_META_SIZE (16)
#define BMP_REVNUM_MASK 0xffff

struct docblk_meta {
    bid_t next_bid;
    uint16_t sb_bmp_revnum_hash;
    uint8_t reserved[5];
    uint8_t marker;
};

#define randomize() srand((unsigned)time(NULL))
#define random(num) ((rand())%(num))

#define random_custom(prev, num) (prev) = ((prev)+811)&((num)-1)


/* Custom assert */

void fdb_assert_die(const char* expression, const char* file, int line,
                    uint64_t val, uint64_t expected);

#define fdb_assert(cond, val, expected)   \
    ((void)((cond) ? (void)0 : fdb_assert_die(#cond, __FILE__, __LINE__,\
                                              (uint64_t)(val), (uint64_t)(expected))))

#endif // _JSAHN_COMMON_H
