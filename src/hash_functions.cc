/* -*- Mode: C++; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * Hash Functions
 * (C) 2013  Jung-Sang Ahn <jungsang.ahn@gmail.com>
 */

#include "hash_functions.h"
#include "common.h"

// djb2 hashing using last LEN digits in VALUE
uint32_t hash_djb2(uint8_t *value, int len)
{
    unsigned hash = 5381;
    while(len--){
        hash = ((hash << 5) + hash) + *((uint8_t*)value + len);
    }
    return hash;
}

uint32_t hash_djb2_last8(uint8_t *value, int len)
{
    int min = MIN(len, 8), c;
    unsigned hash = 5381;
    c = min;
    while(c--){
        hash = ((hash << 5) + hash) + *((uint8_t*)value + (len - min) + c);
    }
    return hash;
}

// LCOV_EXCL_START
uint32_t hash_uint_modular(uint64_t value, uint64_t mod)
{
    return value % mod;
}
// LCOV_EXCL_STOP

// LCOV_EXCL_START
uint32_t hash_shuffle_2uint(uint64_t a, uint64_t b)
{
    uint32_t c;

    a ^= bitswap64(a ^ UINT64_C(0xffffffffffffffff));
    b ^= bitswap64(b ^ UINT64_C(0xffffffffffffffff));

    a = (a & 0xffff) ^ ((a & 0xffff0000) >> 16) ^
        ((a & UINT64_C(0xffff00000000)) >> 32) ^
        ((a & UINT64_C(0xffff000000000000)) >> 48);
    b = (b & 0xffff) ^ ((b & 0xffff0000) >> 16) ^
        ((b & UINT64_C(0xffff00000000)) >> 32) ^
        ((b & UINT64_C(0xffff000000000000)) >> 48);

    c = (((a & 0x0000000f) << 0) |
        ((b & 0x0000000f) << 4) |
        ((a & 0x000000f0) << 4) |
        ((b & 0x000000f0) << 8) |
        ((a & 0x00000f00) << 8) |
        ((b & 0x00000f00) << 12) |
        ((a & 0x0000f000) << 12) |
        ((b & 0x0000f000) << 16));

    return (((c << 5) + c) << 5) + c;
}
// LCOV_EXCL_STOP

