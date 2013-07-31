#ifndef _JSAHN_OPTION_H
#define _JSAHN_OPTION_H

#include "mempool.h"

#define __MEMORY_ALIGN

//#define __O_DIRECT

#define __BIT_CMP

//#define __WAL_KEY_COPY
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
#define FDB_WAL_NBUCKET (1048576)

// MUST BE a power of 2
#define BCACHE_NBUCKET (65536)
#define BCACHE_NDICBUCKET (4096)
#define BCACHE_FLUSH_UNIT (262144)

#endif
