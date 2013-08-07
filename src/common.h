/*
 * Copyright 2013 Jung-Sang Ahn <jungsang.ahn@gmail.com>.
 * All Rights Reserved.
 */

#ifndef _JSAHN_COMMON_H
#define _JSAHN_COMMON_H

#include <time.h>
#include <sys/time.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>

#include "option.h"

#ifndef _MEMPOOL
	#define mempool_alloc malloc
	#define mempool_free free
#endif

static struct timespec _ntime_gap(struct timespec a, struct timespec b) 
{
	struct timespec ret;
	if (b.tv_nsec >= a.tv_nsec) {
		ret.tv_nsec = b.tv_nsec - a.tv_nsec;
		ret.tv_sec = b.tv_sec - a.tv_sec;
	}else{
		ret.tv_nsec = 1000000000 + b.tv_nsec - a.tv_nsec;
		ret.tv_sec = b.tv_sec - a.tv_sec - 1;
	}
	return ret;
}

static struct timeval _utime_gap(struct timeval a, struct timeval b) 
{
	struct timeval ret;
	if (b.tv_usec >= a.tv_usec) {
		ret.tv_usec = b.tv_usec - a.tv_usec;
		ret.tv_sec = b.tv_sec - a.tv_sec;
	}else{
		ret.tv_usec = 1000000 + b.tv_usec - a.tv_usec;
		ret.tv_sec = b.tv_sec - a.tv_sec - 1;
	}
	return ret;
}

#ifdef __APPLE__
	#define INLINE extern inline

	#define _F64 "lld"
	#define _FSEC "ld"
	#define _FUSEC "d"

	#ifndef spin_t
	// spinlock
	#include <libkern/OSAtomic.h>
	#define spin_t OSSpinLock
	#define spin_lock(arg) OSSpinLockLock(arg)
	#define spin_unlock(arg) OSSpinLockUnlock(arg)
	#define SPIN_INITIALIZER 0
	#endif
	
#elif __linux
	#define INLINE __inline

	#define _F64 "ld"
	#define _FSEC "ld"
	#define _FUSEC "ld"

	#ifndef spin_t
	// spinlock
	#include <pthread.h>
	#define spin_t pthread_spinlock_t
	#define spin_lock(arg) pthread_spin_lock(arg)
	#define spin_unlock(arg) pthread_spin_unlock(arg)
	#define SPIN_INITIALIZER 1
	#endif
	
#else
	#define INLINE make_error
#endif

#define MAX(a,b) (((a)>(b))?(a):(b))
#define MIN(a,b) (((a)<(b))?(a):(b))
#define CHK_POW2(v) (!((uint64_t)v & ((uint64_t)v - 0x1)))

#define seq_memcpy(dest, src, size, offset_var) \
	memcpy(dest, src, size); \
	offset_var += size

typedef uint64_t bid_t;
#define BLK_NOT_FOUND 0xffffffffffffffff


#define randomize() srand((unsigned)time(NULL))
#define random(num) ((rand())%(num))

//#define _BNODE_COMP
//#define _DOC_COMP

#ifdef __DEBUG
	#include <stdio.h>
	#define DBG(args...) fprintf(stderr, args)
	#define DBGCMD(command...) command
#else
	#define DBG(args...)
	#define DBGCMD(command...)
#endif


#define bitswap64(v)	\
	((((v) & 0xff00000000000000ULL) >> 56) \
	| (((v) & 0x00ff000000000000ULL) >> 40) \
	| (((v) & 0x0000ff0000000000ULL) >> 24) \
	| (((v) & 0x000000ff00000000ULL) >>  8) \
	| (((v) & 0x00000000ff000000ULL) <<  8) \
	| (((v) & 0x0000000000ff0000ULL) << 24) \
	| (((v) & 0x000000000000ff00ULL) << 40) \
	| (((v) & 0x00000000000000ffULL) << 56))

#define bitswap32(v)	\
	((((v) & 0xff000000) >> 24) \
	| (((v) & 0x00ff0000) >> 8) \
	| (((v) & 0x0000ff00) << 8) \
	| (((v) & 0x000000ff) << 24))


// can be faster under O3 optimization
#ifdef __BIT_CMP

// 64-bit sign mask
#define _64_SM (0x8000000000000000)
// 32-bit sign mask
#define _32_SM (0x80000000)
// 32-bit value mask
#define _32_M (0xffffffff)

// 64-bit sign bit check
#define _64_SC(a,b) ((uint64_t)(((a) & _64_SM)^((b) & _64_SM))>>63)
// 64-bit sign bit check and convert to 32-bit
#define _64_SC_32(a,b) ((uint64_t)(((a) & _64_SM)^((b) & _64_SM))>>32)

// 32-bit sign bit check
#define _32_SC(a,b) ((uint32_t)(((a) & _32_SM)^((b) & _32_SM))>>31)

#define _U64_V(ptr) ( *(uint64_t*)(ptr) )
#define _U32_V(ptr) ( *(uint32_t*)(ptr) )

// check whether V is non-zero or not (return 1 when non-zero, otherwise 0)
#define _NZ(v) (( (v) | (~(v) + 1)) >> 31) & 0x1
#define _NZ_64(v) (( (v) | (~(v) + 1)) >> 63) & 0x1

// convert 64-bit value to 32-bit value preserving sign bit (but not value)
//#define _CSB(v) ( ((v)>>32) | (((v)&_32_M)>>1) | ((v)&0x1) )
#define _CSB(v) ( ((v)>>32) | _NZ_64((uint64_t)v) )

// map from (32-bit signed integer){neg, 0, pos} to {-1, 0, 1}
#define _CS(v) ((~(((v) & _32_SM)>>31)+1) | _NZ(v))
#define _MAP(v) (int32_t)(_CS((uint32_t)v))

#define _CMP_U32(a, b) \
	(int32_t)( _CSB((int64_t)(a)-(int64_t)(b)) )
#define _CMP_U32_P(a, b) _CMP_U32(_U32_V(a), _U32_V(b))

#define _CMP_U64(a, b) \
	(int32_t) ( \
	( (_64_SC(a,b)-1) & _CSB((a)-(b)) ) | /* a and b have same sign */ \
	( (_64_SC_32(a,b) | _64_SC(a,b)) & ( (((b) & _64_SM) >> 32) | 0x1))) /* a and b have different sign */
#define _CMP_U64_P(a, b) _CMP_U64(_U64_V(a), _U64_V(b))

#endif

#endif


