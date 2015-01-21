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

#ifndef _JSAHN_BTREE_KV_H
#define _JSAHN_BTREE_KV_H

#include <stdio.h>
#include <stdint.h>
#include "common.h"

#ifdef __cplusplus
extern "C" {
#endif

INLINE uint32_t deref32(const void *ptr)
{
#ifdef _ALIGN_MEM_ACCESS
    // 4-byte align check (rightmost 2 bits must be '00')
    if ( (size_t)ptr & 0x3 ) {
        uint32_t value;
        memcpy(&value, ptr, sizeof(uint32_t));
        return value;
    }
#endif
    return *(uint32_t*)ptr;
}

INLINE uint64_t deref64(const void *ptr)
{
#ifdef _ALIGN_MEM_ACCESS
    // 8-byte align check (rightmost 3 bits must be '000')
    // Not sure whether 8-byte integer should be aligned in
    // 8-byte boundary or just 4-byte boundary.
    if ( (size_t)ptr & 0x7 ) {
        uint64_t value;
        memcpy(&value, ptr, sizeof(uint64_t));
        return value;
    }
#endif
    return *(uint64_t*)ptr;
}

struct btree_kv_ops;
struct btree_kv_ops * btree_kv_get_ku64_vu64();
struct btree_kv_ops * btree_kv_get_ku32_vu64();
struct btree_kv_ops * btree_kv_get_kb64_vb64(struct btree_kv_ops *kv_ops);
struct btree_kv_ops * btree_kv_get_kb32_vb64(struct btree_kv_ops *kv_ops);
struct btree_kv_ops * btree_kv_get_kbn_vb64(struct btree_kv_ops *kv_ops);

#ifdef __cplusplus
}
#endif

#endif
