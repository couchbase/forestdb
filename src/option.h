#ifndef _JSAHN_OPTION_H
#define _JSAHN_OPTION_H

#include "mempool.h"

#define __FDB_SEQTREE

#define __MEMORY_ALIGN

//#define DOCIO_BLOCK_ALIGN

//#define __RAW_BLOCK
#define __O_DIRECT
#define __SYNC

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

#define FDB_BLOCKSIZE (4096)
// MUST BE a power of 2
#define FDB_WAL_NBUCKET (262144)

// MUST BE a power of 2
#define BCACHE_NBUCKET (256*1024)
#define BCACHE_NDICBUCKET (4096)
#define BCACHE_FLUSH_UNIT (524288)

#define __BTREEBLK_CACHE
#define BTREEBLK_CACHE_LIMIT (16)

#endif
