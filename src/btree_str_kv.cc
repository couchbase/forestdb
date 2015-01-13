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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "btree.h"
#include "btree_str_kv.h"

#include "memleak.h"

typedef uint16_t key_len_t;

/*
n-byte  keylen   vsize   ...
[keylen][key ...][value][keylen][key ...][value]
*/

static void _get_str_kv(struct bnode *node, idx_t idx, void *key, void *value)
{
    int ksize, vsize, i;
    void *key_ptr, *ptr;
    key_len_t keylen, _keylen;
    size_t offset;

    _get_kvsize(node->kvsize, ksize, vsize);
    ksize = sizeof(void *);

    ptr = node->data;
    offset = 0;
    // linear search
    for (i=0;i<idx;++i){
        memcpy(&_keylen, (uint8_t*)ptr+offset, sizeof(key_len_t));
        keylen = _endian_decode(_keylen);
        offset += sizeof(key_len_t)+keylen + vsize;
    }

    // if KEY already points to previous key, then free it
    memcpy(&key_ptr, key, ksize);
    if (key_ptr) {
        free(key_ptr);
    }

    // allocate space for key
    memcpy(&_keylen, (uint8_t*)ptr+offset, sizeof(key_len_t));
    keylen = _endian_decode(_keylen);
    key_ptr = (void*)malloc(sizeof(key_len_t) + keylen);

    // copy key
    memcpy(key_ptr, &_keylen, sizeof(key_len_t));
    memcpy((uint8_t*)key_ptr + sizeof(key_len_t),
           (uint8_t*)ptr+offset+sizeof(key_len_t), keylen);
    // copy key pointer
    memcpy(key, &key_ptr, ksize);
    // copy value
    if (value) {
        memcpy(value, (uint8_t*)ptr + offset + sizeof(key_len_t) + keylen, vsize);
    }
}

static void _set_str_kv(struct bnode *node, idx_t idx, void *key, void *value)
{
    int ksize, vsize, i;
    void *key_ptr, *ptr;
    key_len_t keylen, keylen_ins, keylen_idx;
    key_len_t _keylen, _keylen_ins;
    size_t offset, offset_idx, offset_next, next_len;

    _get_kvsize(node->kvsize, ksize, vsize);
    ksize = sizeof(void *);

    ptr = node->data;
    offset = keylen = 0;
    // linear search
    for (i=0;i<idx;++i){
        memcpy(&_keylen, (uint8_t*)ptr+offset, sizeof(key_len_t));
        keylen = _endian_decode(_keylen);
        offset += sizeof(key_len_t)+keylen + vsize;
    }
    offset_idx = offset;

    // copy key info from KEY
    memcpy(&key_ptr, key, ksize);
    memcpy(&_keylen_ins, key_ptr, sizeof(key_len_t));
    keylen_ins = _endian_decode(_keylen_ins);

    if (keylen_ins != keylen && idx+2 <= node->nentry) {
        // we have to move idx+1 ~ nentry KVs to appropriate position
        next_len = 0;
        for (i=idx;i<node->nentry;++i){
            memcpy(&_keylen, (uint8_t*)ptr + offset, sizeof(key_len_t));
            keylen = _endian_decode(_keylen);

            if (i==idx) keylen_idx = keylen;
            if (i>idx) next_len += sizeof(key_len_t) + keylen + vsize;
            if (i == idx+1) offset_next = offset;

            offset += sizeof(key_len_t) + keylen + vsize;
        }
        // move
        memmove((uint8_t*)ptr + offset_next + (keylen_ins - keylen_idx),
            (uint8_t*)ptr + offset_next, next_len);
    }

    // copy key into the node
    memcpy((uint8_t*)ptr + offset_idx, key_ptr, sizeof(key_len_t) + keylen_ins);
    // copy value
    memcpy((uint8_t*)ptr + offset_idx + sizeof(key_len_t) + keylen_ins, value, vsize);
}

static void _ins_str_kv(struct bnode *node, idx_t idx, void *key, void *value)
{
    int ksize, vsize, i;
    void *key_ptr, *ptr;
    key_len_t keylen, keylen_ins;
    key_len_t _keylen, _keylen_ins;
    size_t offset, offset_idx, offset_next = 0, next_len;

    _get_kvsize(node->kvsize, ksize, vsize);
    ksize = sizeof(void *);

    ptr = node->data;
    offset = 0;
    // linear search
    for (i=0;i<idx;++i){
        memcpy(&_keylen, (uint8_t*)ptr+offset, sizeof(key_len_t));
        keylen = _endian_encode(_keylen);
        offset += sizeof(key_len_t)+keylen + vsize;
    }
    offset_idx = offset;

    if (key && value) {
        // insert

        // copy key info from KEY
        memcpy(&key_ptr, key, ksize);
        memcpy(&_keylen_ins, key_ptr, sizeof(key_len_t));
        keylen_ins = _endian_decode(_keylen_ins);

        // we have to move idx ~ nentry KVs to (next) appropriate position
        next_len = 0;
        for (i=idx;i<node->nentry;++i){
            memcpy(&_keylen, (uint8_t*)ptr + offset, sizeof(key_len_t));
            keylen = _endian_decode(_keylen);
            next_len += sizeof(key_len_t) + keylen + vsize;
            offset += sizeof(key_len_t) + keylen + vsize;
        }

        memmove(
            (uint8_t*)ptr + offset_idx + sizeof(key_len_t) + keylen_ins + vsize,
            (uint8_t*)ptr + offset_idx, next_len);

        // copy key into the node
        memcpy((uint8_t*)ptr + offset_idx, key_ptr, sizeof(key_len_t) + keylen_ins);
        // copy value
        memcpy((uint8_t*)ptr + offset_idx + sizeof(key_len_t) + keylen_ins,
               value, vsize);
    }else{
        // we have to move idx+1 ~ nentry KVs to appropriate position
        next_len = 0;
        for (i=idx;i<node->nentry;++i){
            memcpy(&_keylen, (uint8_t*)ptr + offset, sizeof(key_len_t));
            keylen = _endian_decode(_keylen);
            if (i>idx) next_len += sizeof(key_len_t) + keylen + vsize;
            if (i == idx+1) offset_next = offset;
            offset += sizeof(key_len_t) + keylen + vsize;
        }
        // remove
        memmove((uint8_t*)ptr + offset_idx, (uint8_t*)ptr + offset_next,
                 next_len);
    }
}

static void _copy_str_kv(struct bnode *node_dst,
                         struct bnode *node_src,
                         idx_t dst_idx,
                         idx_t src_idx,
                         idx_t len)
{
    int i;
    int ksize, vsize;
    void *ptr_src, *ptr_dst;
    key_len_t keylen, _keylen;
    size_t src_offset, src_len, dst_offset;

    if (node_dst == node_src) return;

    _get_kvsize(node_src->kvsize, ksize, vsize);

    ptr_src = node_src->data;
    ptr_dst = node_dst->data;

    // calculate offset of 0 ~ src_idx-1
    src_offset = 0;
    for (i=0;i<src_idx;++i){
        memcpy(&_keylen, (uint8_t*)ptr_src + src_offset, sizeof(key_len_t));
        keylen = _endian_decode(_keylen);
        src_offset += sizeof(key_len_t) + keylen + vsize;
    }

    // calculate offset of 0 ~ dst_idx-1
    dst_offset = 0;
    for (i=0;i<dst_idx;++i){
        memcpy(&_keylen, (uint8_t*)ptr_dst + dst_offset, sizeof(key_len_t));
        keylen = _endian_decode(_keylen);
        dst_offset += sizeof(key_len_t) + keylen + vsize;
    }

     // calculate data length to be copied
    src_len = 0;
    for (i=src_idx ; i<src_idx+len ; ++i){
        memcpy(&_keylen, (uint8_t*)ptr_src + src_offset + src_len, sizeof(key_len_t));
        keylen = _endian_decode(_keylen);
        src_len += sizeof(key_len_t) + keylen + vsize;
    }

    // copy
    memcpy((uint8_t*)ptr_dst + dst_offset, (uint8_t*)ptr_src + src_offset, src_len);
}

static size_t _get_str_kv_size(struct btree *tree, void *key, void *value)
{
    void *key_ptr;
    key_len_t keylen, _keylen;

    if (key) {
        memcpy(&key_ptr, key, sizeof(void *));
        memcpy(&_keylen, key_ptr, sizeof(key_len_t));
        keylen = _endian_decode(_keylen);
    }

    return ((key)?(sizeof(key_len_t) + keylen):0) + ((value)?tree->vsize:0);
}

static size_t _get_str_data_size(
    struct bnode *node, void *new_minkey, void *key_arr, void *value_arr, size_t len)
{
    int ksize, vsize, i;
    void *ptr, *key_ptr;
    size_t offset, size;
    key_len_t keylen, _keylen;

    _get_kvsize(node->kvsize, ksize, vsize);
    ksize = sizeof(void *);

    ptr = node->data;
    offset = size = 0;

    for (i=0;i<node->nentry;++i){
        memcpy(&_keylen, (uint8_t*)ptr + offset, sizeof(key_len_t));
        keylen = _endian_decode(_keylen);
        offset += sizeof(key_len_t) + keylen + vsize;

        if (new_minkey && i==0) {
            // if the minimum key should be replaced to NEW_MINKEY
            memcpy(&key_ptr, new_minkey, ksize);
            memcpy(&_keylen, key_ptr, sizeof(key_len_t));
            keylen = _endian_decode(_keylen);
        }
        size += sizeof(key_len_t) + keylen + vsize;
    }

    if (key_arr && value_arr && len > 0) {
        for (i=0;i<len;++i){
            memcpy(&key_ptr, (uint8_t*)key_arr + ksize*i, ksize);
            memcpy(&_keylen, key_ptr, sizeof(key_len_t));
            keylen = _endian_decode(_keylen);
            size += sizeof(key_len_t) + keylen + vsize;
        }
    }

    return size;
}

INLINE void _init_str_kv_var(struct btree *tree, void *key, void *value)
{
    if (key) memset(key, 0, sizeof(void *));
    if (value) memset(value, 0, tree->vsize);
}

static void _free_str_kv_var(struct btree *tree, void *key, void *value)
{
    void *key_ptr;

    memcpy(&key_ptr, key, sizeof(void *));
    if (key_ptr) {
        free(key_ptr);
        key_ptr = NULL;
        memcpy(key, &key_ptr, sizeof(void *));
    }
}

static void _set_str_key(struct btree *tree, void *dst, void *src)
{
    void *key_ptr_old, *key_ptr_new;
    key_len_t keylen_new, _keylen_new, inflen, keylen_alloc;
    size_t size_key = sizeof(key_len_t);

    memset(&inflen, 0xff, sizeof(inflen));

    memcpy(&key_ptr_new, src, sizeof(void *));
    memcpy(&_keylen_new, key_ptr_new, size_key);
    keylen_new = _endian_decode(_keylen_new);

    // free previous key (if exist)
    memcpy(&key_ptr_old, dst, sizeof(void *));
    if (key_ptr_old) {
        free(key_ptr_old);
    }

    keylen_alloc = (keylen_new == inflen)?(0):(keylen_new);
    key_ptr_old = (void*)malloc(size_key + keylen_alloc);
    // copy keylen
    memcpy(key_ptr_old, key_ptr_new, size_key);
    if (keylen_alloc) {
        memcpy((uint8_t*)key_ptr_old + size_key,
               (uint8_t*)key_ptr_new + size_key, keylen_new);
    }
    memcpy(dst, &key_ptr_old, sizeof(void *));
}

INLINE void _set_str_value(struct btree *tree, void *dst, void *src)
{
    memcpy(dst, src, tree->vsize);
}

INLINE void _get_str_nth_idx(struct bnode *node, idx_t num,
                             idx_t den, idx_t *idx)
{
    size_t rem = node->nentry - (int)(node->nentry / den) * den;
    *idx = (int)(node->nentry / den) * num + ((num < rem)?(num):(rem));
}

INLINE void _get_str_nth_splitter(struct bnode *prev_node,
                                  struct bnode *node, void *key)
{
    // always return the smallest key of 'node'
    _get_str_kv(node, 0, key, NULL);
}

void btree_str_kv_set_key(void *key, void *str, size_t len)
{
    void *key_ptr;
    key_len_t keylen = len;
    key_len_t _keylen;

    key_ptr = (void *)malloc(sizeof(key_len_t) + keylen);
    _keylen = _endian_encode(keylen);
    memcpy(key_ptr, &_keylen, sizeof(key_len_t));
    memcpy((uint8_t*)key_ptr + sizeof(key_len_t), str, keylen);
    memcpy(key, &key_ptr, sizeof(void *));
}

// create an infinite key that is larger than any other keys
// LCOV_EXCL_START
void btree_str_kv_set_inf_key(void *key)
{
    void *key_ptr;
    key_len_t keylen;
    key_len_t _keylen;

    // just containing length (0xff..) info
    key_ptr = (void *)malloc(sizeof(key_len_t));
    memset(&keylen, 0xff, sizeof(key_len_t));
    _keylen = _endian_encode(keylen);
    memcpy(key_ptr, &_keylen, sizeof(key_len_t));
    memcpy(key, &key_ptr, sizeof(void *));
}
// LCOV_EXCL_STOP

// return true if KEY is infinite key
// LCOV_EXCL_START
int btree_str_kv_is_inf_key(void *key)
{
    void *key_ptr;
    key_len_t keylen, inflen;
    key_len_t _keylen;

    memset(&inflen, 0xff, sizeof(key_len_t));
    memcpy(&key_ptr, key, sizeof(void *));
    if (key_ptr) {
        memcpy(&_keylen, key_ptr, sizeof(key_len_t));
        keylen = _endian_decode(_keylen);
        if (keylen == inflen) {
            return 1;
        }
    }
    return 0;
}
// LCOV_EXCL_STOP

void btree_str_kv_get_key(void *key, void *strbuf, size_t *len)
{
    void *key_ptr;
    key_len_t keylen, inflen;
    key_len_t _keylen;

    memset(&inflen, 0xff, sizeof(key_len_t));

    memcpy(&key_ptr, key, sizeof(void *));
    if (key_ptr) {
        memcpy(&_keylen, key_ptr, sizeof(key_len_t));
        keylen = _endian_decode(_keylen);

        memcpy(strbuf, (uint8_t*)key_ptr + sizeof(key_len_t), keylen);
        *len = keylen;
    } else {
        *len = 0;
    }
}

void btree_str_kv_free_key(void *key)
{
    void *key_ptr;
    memcpy(&key_ptr, key, sizeof(void *));
    if (key_ptr) free(key_ptr);
    key_ptr = NULL;
    memcpy(key, &key_ptr, sizeof(void *));
}

INLINE bid_t _str_value_to_bid_64(void *value)
{
    return *((bid_t *)value);
}

INLINE void* _str_bid_to_value_64(bid_t *bid)
{
    return (void *)bid;
}

int _cmp_str64(void *key1, void *key2, void* aux)
{
    (void) aux;
    void *key_ptr1, *key_ptr2;
    key_len_t keylen1, keylen2, inflen;
    key_len_t _keylen1, _keylen2;

    memcpy(&key_ptr1, key1, sizeof(void *));
    memcpy(&key_ptr2, key2, sizeof(void *));

    if (key_ptr1 == NULL && key_ptr2 == NULL) {
        return 0;
    } else if (key_ptr1 == NULL) {
        return -1;
    } else if (key_ptr2 == NULL) {
        return 1;
    }

    memcpy(&_keylen1, key_ptr1, sizeof(key_len_t));
    memcpy(&_keylen2, key_ptr2, sizeof(key_len_t));
    keylen1 = _endian_decode(_keylen1);
    keylen2 = _endian_decode(_keylen2);

    memset(&inflen, 0xff, sizeof(key_len_t));
    if (keylen1 == inflen) {
        return 1;
    } else if (keylen2 == inflen) {
        return -1;
    }

    if (keylen1 == keylen2) {
        return memcmp((uint8_t*)key_ptr1 + sizeof(key_len_t),
                      (uint8_t*)key_ptr2 + sizeof(key_len_t), keylen1);
    }else{
        key_len_t len = MIN(keylen1, keylen2);
        int cmp = memcmp((uint8_t*)key_ptr1 + sizeof(key_len_t),
                         (uint8_t*)key_ptr2 + sizeof(key_len_t), len);
        if (cmp != 0) return cmp;
        else {
            return (int)((int)keylen1 - (int)keylen2);
        }
    }
}

struct btree_kv_ops * btree_str_kv_get_kb64_vb64(struct btree_kv_ops *kv_ops)
{
    struct btree_kv_ops *btree_kv_ops;
    if (kv_ops) {
        btree_kv_ops = kv_ops;
    }else{
        btree_kv_ops = (struct btree_kv_ops *)malloc(sizeof(struct btree_kv_ops));
    }

    btree_kv_ops->get_kv = _get_str_kv;
    btree_kv_ops->set_kv = _set_str_kv;
    btree_kv_ops->ins_kv = _ins_str_kv;
    btree_kv_ops->copy_kv = _copy_str_kv;
    btree_kv_ops->set_key = _set_str_key;
    btree_kv_ops->set_value = _set_str_value;
    btree_kv_ops->get_data_size = _get_str_data_size;
    btree_kv_ops->get_kv_size = _get_str_kv_size;
    btree_kv_ops->init_kv_var = _init_str_kv_var;
    btree_kv_ops->free_kv_var = _free_str_kv_var;

    btree_kv_ops->get_nth_idx = _get_str_nth_idx;
    btree_kv_ops->get_nth_splitter = _get_str_nth_splitter;

    btree_kv_ops->cmp = _cmp_str64;

    btree_kv_ops->bid2value = _str_bid_to_value_64;
    btree_kv_ops->value2bid = _str_value_to_bid_64;

    return btree_kv_ops;
}
