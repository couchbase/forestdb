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

#include "btree.h"

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

/**
 * B+tree key-value operation class for fixed chunk key.
 */
class FixedKVOps : public BTreeKVOps {
public:
    FixedKVOps();
    FixedKVOps(size_t _ksize, size_t _vsize);
    FixedKVOps(size_t _ksize, size_t _vsize, btree_cmp_func _cmp_func);

    virtual ~FixedKVOps() { }

    void init(size_t _ksize, size_t _vsize, btree_cmp_func _cmp_func);

    void getKV(struct bnode *node, idx_t idx, void *key, void *value);
    void setKV(struct bnode *node, idx_t idx, void *key, void *value);
    void insKV(struct bnode *node, idx_t idx, void *key, void *value);
    void copyKV(struct bnode *node_dst,
                struct bnode *node_src,
                idx_t dst_idx,
                idx_t src_idx,
                idx_t len);
    size_t getDataSize(struct bnode *node,
                       void *new_minkey,
                       void *key_arr,
                       void *value_arr,
                       size_t len);
    size_t getKVSize(void *key, void *value);
    void initKVVar(void *key, void *value);
    void freeKVVar(void *key, void *value) { }
    void setKey(void *dst, void *src);
    void setValue(void *dst, void *src);
    idx_t getNthIdx(struct bnode *node, idx_t num, idx_t den);
    void getNthSplitter(struct bnode *prev_node,
                        struct bnode *node,
                        void *key);

    void setVarKey(void *key, void *str, size_t len) { }
    void setInfVarKey(void *key) { }
    bool isInfVarKey(void *key) { return false; }
    void getVarKey(void *key, void *strbuf, size_t& len) { }
    void freeVarKey(void *key) { }
};

#ifdef __cplusplus
}
#endif

#endif
