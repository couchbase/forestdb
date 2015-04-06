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

#ifndef _JSAHN_OPTION_H
#define _JSAHN_OPTION_H

//#include "mempool.h"

#define SEQNUM_NOT_USED (UINT64_C(0xffffffffffffffff))
#define DEFAULT_KVS_NAME "default"

#define __FDB_BCACHE_USE
#ifdef __FDB_BCACHE_USE
    //#define __FDB_SORTED_COMPACTION
#endif
#define FDB_SECTOR_SIZE (512)

//#define DOCIO_BLOCK_ALIGN
#define DOCIO_LEN_STRUCT_ALIGN

//#define __RAW_BLOCK

#define __CRC32
#ifdef __CRC32
    #define BTREE_CRC_OFFSET (8)
    #define BTREE_CRC_FIELD_LEN (8)
    #define BTREE_LEVEL_OFFSET (2)
    //#define __CHECKSUM_ADLER32
#endif

#define __BIT_CMP

#define __ENDIAN_SAFE

//#define __DEBUG_FDB
//#define __DEBUG_WAL
//#define __DEBUG_HBTRIE
//#define __DEBUG_BTREE
//#define __DEBUG_BTREEBLOCK
//#define __DEBUG_BCACHE
//#define __DEBUG_FILEMGR
//#define __DEBUG_COUCHBENCH

#define FDB_BLOCKSIZE (4096)
#define FDB_WAL_NBUCKET (4099) // a prime number
#define FDB_MAX_FILENAME_LEN (1024)
#define FDB_MAX_KVINS_NAME_LEN (65536)
#define FDB_WAL_THRESHOLD (4*1024)
#define FDB_WAL_MIN_MMAP_FILESIZE (16777216) // 16 MB
#define FDB_WAL_MAX_MMAP_FILESIZE (1073741824) // 1 GB
#define FDB_COMP_BUF_MINSIZE (4194304) // 4 MB, 512K offsets
#define FDB_COMP_BUF_MAXSIZE (1073741824) // 1 GB, 128M offsets
#define FDB_COMP_BATCHSIZE (4096) // 4K docs
#define FDB_COMP_MOVE_UNIT (4194304) // 4 MB
#define FDB_COMP_WAL_FLUSH (1048576) // 1M docs
#define FDB_COMPACTOR_SLEEP_DURATION (15)
#define FDB_DEFAULT_COMPACTION_THRESHOLD (30)

#define BCACHE_NBUCKET (4099) // a prime number
#define BCACHE_NDICBUCKET (4099) // a prime number
#define BCACHE_FLUSH_UNIT (1048576) // 1MB
#define BCACHE_EVICT_UNIT (1)
#define BCACHE_RANDOM_VICTIM_UNIT (2)
#define __BCACHE_SECOND_CHANCE
#define __BCACHE_RANDOM_VICTIM

#define FILEMGR_PREFETCH_UNIT (4194304) // 4MB
#define __FILEMGR_MUTEX_LOCK
#define __FILEMGR_DATA_PARTIAL_LOCK
//#define __FILEMGR_DATA_MUTEX_LOCK

#define __BTREEBLK_BLOCKPOOL
#define __BTREEBLK_SUBBLOCK
//#define __BTREEBLK_READ_TREE // not used now, for future use
#define BTREEBLK_AGE_LIMIT (10)
#define BTREEBLK_MIN_SUBBLOCK (128)
//#define __BTREEBLK_CACHE
#ifdef __BTREEBLK_CACHE
    #define BTREEBLK_CACHE_LIMIT (8)
#endif

//#define __UTREE
#ifdef __UTREE
    #define __UTREE_HEADER_SIZE (16)
    #undef BTREE_CRC_OFFSET
    #define BTREE_CRC_OFFSET (__UTREE_HEADER_SIZE+8)
#endif

// WAL parition sizes
#define DEFAULT_NUM_WAL_PARTITIONS (11) // a prime number
#define MAX_NUM_WAL_PARTITIONS (512)

// Buffer cache partition size
#define DEFAULT_NUM_BCACHE_PARTITIONS (11) // a prime number
#define MAX_NUM_BCACHE_PARTITIONS (512)

#endif
