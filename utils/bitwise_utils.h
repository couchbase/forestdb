#ifndef _JSAHN_BITWISE_UTILS_H
#define _JSAHN_BITWISE_UTILS_H

#ifndef INT64_C
#define INT64_C(c) (c ## LL)
#define UINT64_C(c) (c ## ULL)
#endif

#define MAX(a,b) (((a)>(b))?(a):(b))
#define MIN(a,b) (((a)<(b))?(a):(b))
#define CHK_POW2(v) (!((uint64_t)v & ((uint64_t)v - 0x1)))

#ifndef bitswap64
#define bitswap64(v)    \
    ( (((v) & 0xff00000000000000ULL) >> 56) \
    | (((v) & 0x00ff000000000000ULL) >> 40) \
    | (((v) & 0x0000ff0000000000ULL) >> 24) \
    | (((v) & 0x000000ff00000000ULL) >>  8) \
    | (((v) & 0x00000000ff000000ULL) <<  8) \
    | (((v) & 0x0000000000ff0000ULL) << 24) \
    | (((v) & 0x000000000000ff00ULL) << 40) \
    | (((v) & 0x00000000000000ffULL) << 56) )
#endif

#ifndef bitswap32
#define bitswap32(v)    \
    ( (((v) & 0xff000000) >> 24) \
    | (((v) & 0x00ff0000) >>  8) \
    | (((v) & 0x0000ff00) <<  8) \
    | (((v) & 0x000000ff) << 24) )
#endif

#ifndef bitswap16
#define bitswap16(v)    \
    ( (((v) & 0xff00) >> 8) \
    | (((v) & 0x00ff) << 8) )
#endif

// can be faster under O3 optimization
//#ifdef __BIT_CMP

// 64-bit sign mask
#define _64_SM (UINT64_C(0x8000000000000000))
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
#define _NZ(v) ( (( (v) | (~(v) + 1)) >> 31) & 0x1 )
#define _NZ_64(v) ( (( (v) | (~(v) + 1)) >> 63) & 0x1 )

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

//#endif

#endif
