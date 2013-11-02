#ifndef _JSAHN_OPTION_H
#define _JSAHN_OPTION_H

//#include "mempool.h"

typedef uint64_t fdb_seqnum_t;
#define SEQNUM_NOT_USED (0xffffffffffffffff)


#define __FDB_SEQTREE
#define __FDB_BCACHE_USE
#ifdef __FDB_BCACHE_USE
    #define __FDB_SORTED_COMPACTION
#endif
#define FDB_SECTOR_SIZE (512)

#define __MEMORY_ALIGN

//#define DOCIO_BLOCK_ALIGN

//#define __RAW_BLOCK

#define __CRC32

#define __BIT_CMP

#define __WAL_KEY_COPY
#define __WAL_FLUSH_BEFORE_COMMIT

//#define __DEBUG_FDB
//#define __DEBUG_WAL
//#define __DEBUG_HBTRIE
//#define __DEBUG_BTREE
//#define __DEBUG_BTREEBLOCK
//#define __DEBUG_BCACHE
//#define __DEBUG_FILEMGR
//#define __DEBUG_COUCHBENCH

#define FDB_BLOCKSIZE (4096)
// MUST BE a power of 2
#define FDB_WAL_NBUCKET (64*1024)
#define FDB_MAX_KEYLEN (256)
#define FDB_WAL_THRESHOLD (64*1024)

// MUST BE a power of 2
#define BCACHE_NBUCKET (1024*1024)
#define BCACHE_NDICBUCKET (4096)
#define BCACHE_FLUSH_UNIT (256*1024)
#define BCACHE_EVICT_RATIO (3)
#define BCACHE_REAR_COUNT (4)

#define FILEMGR_BULK_READ (16)

#define __BTREEBLK_CACHE
#define BTREEBLK_CACHE_LIMIT (8)

#endif
