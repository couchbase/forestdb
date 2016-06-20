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

#include <stdlib.h>
#include <string.h>

#include "btree_kv.h"
#include "memleak.h"


int cmpBinary32(void *key1, void *key2, void *aux)
{
    (void) aux;

#ifdef __BIT_CMP
    uint32_t a,b;
    a = _endian_encode(deref32(key1));
    b = _endian_encode(deref32(key2));
    return _CMP_U32(a, b);
#else
    return memcmp(key1, key2, 8);
#endif
}

int cmpBinary64(void *key1, void *key2, void *aux)
{
    (void) aux;

#ifdef __BIT_CMP
    uint64_t a,b;
    a = _endian_encode(deref64(key1));
    b = _endian_encode(deref64(key2));
    return _CMP_U64(a, b);
#else
    return memcmp(key1, key2, 8);
#endif
}

int cmpBinaryGeneral(void *key1, void *key2, void *aux)
{
    btree_cmp_args *args = (btree_cmp_args *)aux;
    return memcmp(key1, key2, args->chunksize);
}

FixedKVOps::FixedKVOps() {
    init(8, 8, NULL);
}

FixedKVOps::FixedKVOps(size_t _ksize, size_t _vsize)
{
    init(_ksize, _vsize, NULL);
}

FixedKVOps::FixedKVOps(size_t _ksize, size_t _vsize, btree_cmp_func _cmp_func)
{
    init(_ksize, _vsize, _cmp_func);
}

void FixedKVOps::init(size_t _ksize, size_t _vsize, btree_cmp_func _cmp_func)
{
    ksize = _ksize;
    vsize = _vsize;
    if (_cmp_func) {
        cmp_func = _cmp_func;
    } else {
        if (_ksize == 4) {
            cmp_func = cmpBinary32;
        } else if (_ksize == 8) {
            cmp_func = cmpBinary64;
        } else {
            cmp_func = cmpBinaryGeneral;
        }
    }
}

void FixedKVOps::getKV(struct bnode *node, idx_t idx, void *key, void *value)
{
    void *ptr = (uint8_t *)node->data + (idx * (ksize+vsize));

    memcpy(key, ptr, ksize);
    if (value) {
        memcpy(value, (uint8_t *)ptr + ksize, vsize);
    }
}

void FixedKVOps::setKV(struct bnode *node, idx_t idx, void *key, void *value)
{
    void *ptr = (uint8_t *)node->data + (idx * (ksize+vsize));

    memcpy(ptr, key, ksize);
    memcpy((uint8_t *)ptr + ksize, value, vsize);
}

void FixedKVOps::insKV(struct bnode *node, idx_t idx, void *key, void *value)
{
    int kvsize;
    void *ptr;

    kvsize = ksize + vsize;
    ptr = node->data;

    if (key && value) {
        // insert
        memmove( (uint8_t *)ptr + (idx+1)*kvsize,
                 (uint8_t *)ptr + idx*kvsize,
                 (node->nentry - idx)*kvsize );
        memcpy((uint8_t *)ptr + idx*kvsize, key, ksize);
        memcpy((uint8_t *)ptr + idx*kvsize + ksize, value, vsize);
    } else {
        // remove
        memmove( (uint8_t *)ptr + idx*kvsize,
                 (uint8_t *)ptr + (idx+1)*kvsize,
                 (node->nentry - (idx+1))*kvsize );
    }
}

void FixedKVOps::copyKV(struct bnode *node_dst,
                        struct bnode *node_src,
                        idx_t dst_idx,
                        idx_t src_idx,
                        idx_t len)
{
    int kvsize;
    void *ptr_src, *ptr_dst;

    if (node_dst == node_src) {
        return;
    }

    kvsize = ksize + vsize;

    ptr_src = node_src->data;
    ptr_dst = node_dst->data;

    memcpy( (uint8_t *)ptr_dst + kvsize * dst_idx,
            (uint8_t *)ptr_src + kvsize * src_idx,
            kvsize * len );
}

size_t FixedKVOps::getDataSize(struct bnode *node,
                               void *new_minkey,
                               void *key_arr,
                               void *value_arr,
                               size_t len)
{
    return node->nentry * (ksize + vsize) +
           ( (key_arr && value_arr) ? ((ksize + vsize) * len) : (0) );
}

size_t FixedKVOps::getKVSize(void *key, void *value)
{
    return ( ((uint8_t *)key)   ? (ksize) : (0) ) +
           ( ((uint8_t *)value) ? (vsize) : (0) );
}

void FixedKVOps::initKVVar(void *key, void *value)
{
    if (key) {
        memset(key, 0x0, ksize);
    }
    if (value) {
        memset(value, 0x0, vsize);
    }
}

void FixedKVOps::setKey(void *dst, void *src)
{
    memcpy(dst, src, ksize);
}

void FixedKVOps::setValue(void *dst, void *src)
{
    memcpy(dst, src, vsize);
}

idx_t FixedKVOps::getNthIdx(struct bnode *node, idx_t num, idx_t den)
{
    size_t rem = node->nentry - (int)(node->nentry / den) * den;
    return (node->nentry / den) * num + ((num < rem)?(num):(rem));
}

void FixedKVOps::getNthSplitter(struct bnode *prev_node,
                                struct bnode *node,
                                void *key)
{
    // always return the first key of the NODE
    memcpy(key, node->data, ksize);
}

