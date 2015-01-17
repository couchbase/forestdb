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

#include "btree.h"
#include "btree_kv.h"
#include "memleak.h"

INLINE void _get_kv(struct bnode *node, idx_t idx, void *key, void *value)
{
    int ksize, vsize;
    void *ptr;
    _get_kvsize(node->kvsize, ksize, vsize);
    ptr = (uint8_t *)node->data + (idx * (ksize+vsize));

    memcpy(key, ptr, ksize);
    if (value) {
        memcpy(value, (uint8_t *)ptr + ksize, vsize);
    }
}

INLINE void _set_kv(struct bnode *node, idx_t idx, void *key, void *value)
{
    int ksize, vsize;
    void *ptr;
    _get_kvsize(node->kvsize, ksize, vsize);
    ptr = (uint8_t *)node->data + (idx * (ksize+vsize));

    memcpy(ptr, key, ksize);
    memcpy((uint8_t *)ptr + ksize, value, vsize);
}

INLINE void _ins_kv(struct bnode *node, idx_t idx, void *key, void *value)
{
    int ksize, vsize, kvsize;
    void *ptr;
    _get_kvsize(node->kvsize, ksize, vsize);
    kvsize = ksize + vsize;
    ptr = node->data;

    if (key && value) {
        // insert
        memmove(
            (uint8_t *)ptr + (idx+1)*kvsize,
            (uint8_t *)ptr + idx*kvsize,
            (node->nentry - idx)*kvsize);
        memcpy((uint8_t *)ptr + idx*kvsize, key, ksize);
        memcpy((uint8_t *)ptr + idx*kvsize + ksize, value, vsize);
    }else{
        // remove
        memmove(
            (uint8_t *)ptr + idx*kvsize,
            (uint8_t *)ptr + (idx+1)*kvsize,
            (node->nentry - (idx+1))*kvsize);
    }
}

INLINE void _copy_kv(
    struct bnode *node_dst, struct bnode *node_src, idx_t dst_idx, idx_t src_idx, idx_t len)
{
    int ksize, vsize, kvsize;
    void *ptr_src, *ptr_dst;

    if (node_dst == node_src) {
        return;
    }

    _get_kvsize(node_src->kvsize, ksize, vsize);
    kvsize = ksize + vsize;

    ptr_src = node_src->data;
    ptr_dst = node_dst->data;

    memcpy(
        (uint8_t *)ptr_dst + kvsize * dst_idx,
        (uint8_t *)ptr_src + kvsize * src_idx,
        kvsize * len);
}

INLINE size_t _get_data_size(
    struct bnode *node, void *new_minkey, void *key_arr, void *value_arr, size_t len)
{
    int ksize, vsize;
    _get_kvsize(node->kvsize, ksize, vsize);
    return node->nentry * (ksize + vsize) + ((key_arr && value_arr)?((ksize + vsize)*len):0);
}

INLINE size_t _get_kv_size(struct btree *tree, void *key, void *value)
{
    return (((uint8_t *)key) ? tree->ksize : 0) + (((uint8_t *)value) ? tree->vsize : 0);
}

INLINE void _init_kv_var(struct btree *tree, void *key, void *value)
{
    if (key) memset(key, 0, tree->ksize);
    if (value) memset(value, 0, tree->vsize);
}

INLINE void _set_key(struct btree *tree, void *dst, void *src)
{
    memcpy(dst, src, tree->ksize);
}

INLINE void _set_value(struct btree *tree, void *dst, void *src)
{
    memcpy(dst, src, tree->vsize);
}

INLINE void _get_nth_idx(struct bnode *node, idx_t num, idx_t den, idx_t *idx)
{
    size_t rem = node->nentry - (int)(node->nentry / den) * den;
    *idx = (node->nentry / den) * num + ((num < rem)?(num):(rem));
}

INLINE void _get_nth_splitter(struct bnode *prev_node, struct bnode *node, void *key)
{
    int ksize, vsize;

    _get_kvsize(node->kvsize, ksize, vsize);
    // always return the first key of the NODE
    memcpy(key, node->data, ksize);
}

INLINE bid_t _value_to_bid_64(void *value)
{
    return *((bid_t *)value);
}

INLINE void* _bid_to_value_64(bid_t *bid)
{
    return (void *)bid;
}

INLINE int _cmp_uint32_t(void *key1, void *key2, void *aux)
{
    (void) aux;
    uint32_t a, b;
    a = deref32(key1);
    b = deref32(key2);

#ifdef __BIT_CMP
    return _CMP_U32(a, b);
#else
    if (a < b) {
        return -1;
    } else if (a > b) {
        return 1;
    } else {
        return 0;
    }
#endif
}

INLINE int _cmp_uint64_t(void *key1, void *key2, void *aux)
{
    (void) aux;
    uint64_t a,b;
    a = deref64(key1);
    b = deref64(key2);

#ifdef __BIT_CMP
    return _CMP_U64(a, b);
#else
    if (a < b) {
        return -1;
    } else if (a > b) {
        return 1;
    } else {
        return 0;
    }
#endif
}

INLINE int _cmp_binary32(void *key1, void *key2, void *aux)
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

INLINE int _cmp_binary64(void *key1, void *key2, void *aux)
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

INLINE int _cmp_binary_general(void *key1, void *key2, void *aux)
{
    btree_cmp_args *args = (btree_cmp_args *)aux;
    return memcmp(key1, key2, args->chunksize);
}

// key: uint64_t, value: uint64_t
static struct btree_kv_ops kv_ops_ku64_vu64 = {
    _get_kv, _set_kv, _ins_kv, _copy_kv, _get_data_size, _get_kv_size, _init_kv_var, NULL,
    _set_key, _set_value, _get_nth_idx, _get_nth_splitter,
    _cmp_uint64_t, _value_to_bid_64, _bid_to_value_64};

static struct btree_kv_ops kv_ops_ku32_vu64 = {
    _get_kv, _set_kv, _ins_kv, _copy_kv, _get_data_size, _get_kv_size, _init_kv_var, NULL,
    _set_key, _set_value, _get_nth_idx, _get_nth_splitter,
    _cmp_uint32_t, _value_to_bid_64, _bid_to_value_64};

struct btree_kv_ops * btree_kv_get_ku64_vu64()
{
    return &kv_ops_ku64_vu64;
}

struct btree_kv_ops * btree_kv_get_ku32_vu64()
{
    return &kv_ops_ku32_vu64;
}

struct btree_kv_ops * btree_kv_get_kb64_vb64(struct btree_kv_ops *kv_ops)
{
    struct btree_kv_ops *btree_kv_ops;
    if (kv_ops) {
        btree_kv_ops = kv_ops;
    }else{
        btree_kv_ops = (struct btree_kv_ops *)malloc(sizeof(struct btree_kv_ops));
    }

    btree_kv_ops->get_kv = _get_kv;
    btree_kv_ops->set_kv = _set_kv;
    btree_kv_ops->ins_kv = _ins_kv;
    btree_kv_ops->copy_kv = _copy_kv;
    btree_kv_ops->set_key = _set_key;
    btree_kv_ops->set_value = _set_value;
    btree_kv_ops->get_data_size = _get_data_size;
    btree_kv_ops->get_kv_size = _get_kv_size;
    btree_kv_ops->init_kv_var = _init_kv_var;
    btree_kv_ops->free_kv_var = NULL;

    btree_kv_ops->get_nth_idx = _get_nth_idx;
    btree_kv_ops->get_nth_splitter = _get_nth_splitter;

    btree_kv_ops->cmp = _cmp_binary64;

    btree_kv_ops->bid2value = _bid_to_value_64;
    btree_kv_ops->value2bid = _value_to_bid_64;

    return btree_kv_ops;
}

struct btree_kv_ops * btree_kv_get_kb32_vb64(struct btree_kv_ops *kv_ops)
{
    struct btree_kv_ops *btree_kv_ops;
    if (kv_ops) {
        btree_kv_ops = kv_ops;
    }else{
        btree_kv_ops = (struct btree_kv_ops *)malloc(sizeof(struct btree_kv_ops));
    }

    btree_kv_ops->get_kv = _get_kv;
    btree_kv_ops->set_kv = _set_kv;
    btree_kv_ops->ins_kv = _ins_kv;
    btree_kv_ops->copy_kv = _copy_kv;
    btree_kv_ops->set_key = _set_key;
    btree_kv_ops->set_value = _set_value;
    btree_kv_ops->get_data_size = _get_data_size;
    btree_kv_ops->get_kv_size = _get_kv_size;
    btree_kv_ops->init_kv_var = _init_kv_var;
    btree_kv_ops->free_kv_var = NULL;

    btree_kv_ops->get_nth_idx = _get_nth_idx;
    btree_kv_ops->get_nth_splitter = _get_nth_splitter;

    btree_kv_ops->cmp = _cmp_binary32;

    btree_kv_ops->bid2value = _bid_to_value_64;
    btree_kv_ops->value2bid = _value_to_bid_64;

    return btree_kv_ops;
}

struct btree_kv_ops * btree_kv_get_kbn_vb64(struct btree_kv_ops *kv_ops)
{
    struct btree_kv_ops *btree_kv_ops;
    if (kv_ops) {
        btree_kv_ops = kv_ops;
    }else{
        btree_kv_ops = (struct btree_kv_ops *)malloc(sizeof(struct btree_kv_ops));
    }

    btree_kv_ops->get_kv = _get_kv;
    btree_kv_ops->set_kv = _set_kv;
    btree_kv_ops->ins_kv = _ins_kv;
    btree_kv_ops->copy_kv = _copy_kv;
    btree_kv_ops->set_key = _set_key;
    btree_kv_ops->set_value = _set_value;
    btree_kv_ops->get_data_size = _get_data_size;
    btree_kv_ops->get_kv_size = _get_kv_size;
    btree_kv_ops->init_kv_var = _init_kv_var;
    btree_kv_ops->free_kv_var = NULL;

    btree_kv_ops->get_nth_idx = _get_nth_idx;
    btree_kv_ops->get_nth_splitter = _get_nth_splitter;

    btree_kv_ops->cmp = _cmp_binary_general;

    btree_kv_ops->bid2value = _bid_to_value_64;
    btree_kv_ops->value2bid = _value_to_bid_64;

    return btree_kv_ops;
}


