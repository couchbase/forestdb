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
#include "btree_prefix_kv.h"
#include "memleak.h"

typedef uint16_t key_len_t;

/*
n-byte     p_len   n-byte  keylen   vsize   ...
[prefixlen][prefix][keylen][key ...][value][keylen][key ...][value]
*/

INLINE void _get_prefix_kv(struct bnode *node, idx_t idx, void *key, void *value)
{
    int ksize, vsize, i;
    void *key_ptr, *ptr, *prefix;
    key_len_t keylen, prefix_len, temp_keylen;
    key_len_t _keylen, _prefix_len, _temp_keylen;
    size_t offset;

    _get_kvsize(node->kvsize, ksize, vsize);
    ksize = sizeof(void *);
    ptr = node->data;
    offset = 0;

    // prefix fetch
    prefix_len = 0;
    prefix = NULL;
    if (node->level == 1) {
        if (node->nentry > 0) {
            memcpy(&_prefix_len, ptr, sizeof(key_len_t));
            prefix_len = _endian_decode(_prefix_len);
            offset += sizeof(key_len_t) + prefix_len;
            prefix = (uint8_t*)ptr + sizeof(key_len_t);
        }
    }

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
    key_ptr = (void*)malloc(sizeof(key_len_t) + keylen + prefix_len);

    // copy keylen
    temp_keylen = keylen + prefix_len;
    _temp_keylen = _endian_encode(temp_keylen);
    memcpy(key_ptr, &_temp_keylen, sizeof(key_len_t));
    // copy prefix
    if (prefix_len > 0) {
        memcpy((uint8_t*)key_ptr + sizeof(key_len_t), prefix, prefix_len);
    }
    // copy rest of key
    memcpy((uint8_t*)key_ptr + sizeof(key_len_t) + prefix_len,
           (uint8_t*)ptr + offset + sizeof(key_len_t),
           keylen);
    // copy key pointer
    memcpy(key, &key_ptr, ksize);
    // copy value
    if (value) {
        memcpy(value,
               (uint8_t*)ptr + offset + sizeof(key_len_t) + keylen,
               vsize);
    }
}

INLINE void _get_common_prefix(
    void *str1, key_len_t str1len, void *str2, key_len_t str2len, key_len_t *len_out)
{
    key_len_t min = (str1len<str2len)?(str1len):(str2len);
    *len_out = 0;
    for (*len_out=0 ; *len_out<min ; ++(*len_out)){
        if ( *((uint8_t*)str1 + (*len_out)) != *((uint8_t*)str2 + (*len_out)) ) {
            return;
        }
    }
}

#define BUFFERSIZE (FDB_BLOCKSIZE)

typedef enum {
    ARR_OVERWRITE,
    ARR_INSERT,
    ARR_REMOVE,
    ARR_NONE
} arrange_option_t ;

INLINE void _arrange_prefix(
    struct bnode *node,
    key_len_t nentry,
    void *prefix,
    key_len_t prefix_len,
    key_len_t new_prefix_len,
    idx_t idx,
    void *key_ptr,
    key_len_t keylen_ins,
    void *value,
    arrange_option_t arrange_option)
{
    size_t ksize, vsize;
    void *buffer, *ptr;
    key_len_t temp_keylen, keylen;
    key_len_t _temp_keylen, _keylen, _new_prefix_len;
    size_t offset, offset_buffer, i;

    _get_kvsize(node->kvsize, ksize, vsize);
    ksize = sizeof(void *);
    ptr = node->data;

    buffer = (void *)alca(uint8_t, BUFFERSIZE);
    offset_buffer = offset = 0;

    // copy new prefix to buffer
    _new_prefix_len = _endian_encode(new_prefix_len);
    memcpy(buffer, &_new_prefix_len, sizeof(key_len_t));
    memcpy((uint8_t*)buffer + sizeof(key_len_t),
           (uint8_t*)key_ptr + sizeof(key_len_t), new_prefix_len);
    offset_buffer += sizeof(key_len_t) + new_prefix_len;

    // read previous prefix in the node
    memcpy(&_keylen, ptr, sizeof(key_len_t));
    keylen = _endian_decode(_keylen);
    offset += sizeof(key_len_t) + keylen;

    for (i=0 ; i< ((idx < nentry)?(nentry):(idx+1)) ; ++i){

        if ( (arrange_option == ARR_INSERT || arrange_option == ARR_OVERWRITE) && i == idx) {
            // copy idx (new key value)
            temp_keylen = keylen_ins - new_prefix_len;
            _temp_keylen = _endian_encode(temp_keylen);
            memcpy((uint8_t*)buffer + offset_buffer,
                   &_temp_keylen, sizeof(key_len_t));
            memcpy((uint8_t*)buffer + offset_buffer + sizeof(key_len_t),
                   (uint8_t*)key_ptr + sizeof(key_len_t) + new_prefix_len,
                   temp_keylen);
            memcpy((uint8_t*)buffer + offset_buffer +
                             sizeof(key_len_t) + temp_keylen,
                   value, vsize);
            offset_buffer += sizeof(key_len_t) + temp_keylen + vsize;
        }

        if ( (arrange_option == ARR_OVERWRITE && i != idx) ||
            (arrange_option == ARR_INSERT && i<nentry) ||
            (arrange_option == ARR_REMOVE && i != idx) ||
            arrange_option == ARR_NONE) {

            // copy keylen + alpha
            memcpy(&_keylen, (uint8_t*)ptr + offset, sizeof(key_len_t));
            keylen = _endian_decode(_keylen);
            temp_keylen = keylen + (prefix_len - new_prefix_len);

            _temp_keylen = _endian_encode(temp_keylen);
            memcpy((uint8_t*)buffer + offset_buffer,
                   &_temp_keylen, sizeof(key_len_t));
            if (new_prefix_len < prefix_len) {
                // when prefix is shrinked
                // copy skipped prefix
                memcpy((uint8_t*)buffer + offset_buffer + sizeof(key_len_t),
                       (uint8_t*)prefix + new_prefix_len,
                       (prefix_len - new_prefix_len));
                // copy rest of key + value
                memcpy((uint8_t*)buffer + offset_buffer + sizeof(key_len_t) +
                                 (prefix_len - new_prefix_len),
                       (uint8_t*)ptr + offset + sizeof(key_len_t),
                       keylen + vsize);
            }else{
                // when prefix gets longer
                // copy part of key + value
                memcpy((uint8_t*)buffer + offset_buffer + sizeof(key_len_t),
                       (uint8_t*)ptr + offset + sizeof(key_len_t) +
                                 (new_prefix_len - prefix_len),
                       keylen - (new_prefix_len - prefix_len) + vsize);
            }

            offset_buffer += sizeof(key_len_t) + temp_keylen + vsize;
            offset += sizeof(key_len_t) + keylen + vsize;
        }else if (arrange_option == ARR_REMOVE && i == idx) {
            // copy keylen and skip
            memcpy(&_keylen, (uint8_t*)ptr + offset, sizeof(key_len_t));
            keylen = _endian_decode(_keylen);
            offset += sizeof(key_len_t) + keylen + vsize;
        }
    }

    // swap buffer <-> node->data
    memcpy(ptr, buffer, offset_buffer);
}

INLINE void _set_prefix_kv(struct bnode *node, idx_t idx, void *key, void *value)
{
    int ksize, vsize, i;
    void *prefix, *key_ptr, *ptr, *first_key, *last_key;
    key_len_t prefix_len, keylen, keylen_ins, keylen_idx = 0;
    key_len_t _prefix_len, _keylen, _keylen_ins, _temp_keylen;
    key_len_t new_prefix_len, temp_keylen, first_keylen, last_keylen;
    size_t offset, offset_idx, offset_next, next_len;

    _get_kvsize(node->kvsize, ksize, vsize);
    ksize = sizeof(void *);
    ptr = node->data;
    offset = offset_idx = 0;

    // prefix fetch
    prefix_len = 0;
    prefix = NULL;
    if (node->level == 1) {
        if (node->nentry > 0) {
            memcpy(&_prefix_len, ptr, sizeof(key_len_t));
            prefix_len = _endian_decode(_prefix_len);
            offset += sizeof(key_len_t) + prefix_len;
            prefix = (uint8_t*)ptr + sizeof(key_len_t);
        }
    }
    offset_idx = offset;

    // linear search
    first_key = last_key = NULL;
    first_keylen = last_keylen = next_len = 0;
    for (i=0;i<node->nentry;++i){
        memcpy(&_keylen, (uint8_t*)ptr+offset, sizeof(key_len_t));
        keylen = _endian_decode(_keylen);

        if (i==0) {
            first_key = (uint8_t*)ptr + offset + sizeof(key_len_t);
            first_keylen = keylen;
        }
        if (i==node->nentry-1) {
            last_key = (uint8_t*)ptr + offset + sizeof(key_len_t);
            last_keylen = keylen;
        }

        if (i>idx) next_len += sizeof(key_len_t) + keylen + vsize;
        if (i==idx) keylen_idx = keylen;
        if (i == idx+1) offset_next = offset;

        offset += sizeof(key_len_t)+keylen + vsize;
        if (i<idx) offset_idx = offset;
    }

    // copy key info from KEY
    memcpy(&key_ptr, key, ksize);
    memcpy(&_keylen_ins, key_ptr, sizeof(key_len_t));
    keylen_ins = _endian_decode(_keylen_ins);

    if ((idx ==0 || idx >= node->nentry-1) &&
        node->nentry > 0 && node->level == 1) {
        // get common prefix between the first entry and the last entry
        void *comp_key;
        key_len_t comp_keylen;

        if (idx == 0) {
            // KEY and the last key
            comp_keylen = prefix_len + last_keylen;
            comp_key = (void*)malloc(comp_keylen);
            if (prefix_len) {
                memcpy(comp_key, prefix, prefix_len);
            }
            memcpy((uint8_t*)comp_key + prefix_len, last_key, last_keylen);
        }else{
            // KEY and the first key
            comp_keylen = prefix_len + first_keylen;
            comp_key = (void*)malloc(comp_keylen);
            if (prefix_len) {
                memcpy(comp_key, prefix, prefix_len);
            }
            memcpy((uint8_t*)comp_key + prefix_len, first_key, first_keylen);
        }
        _get_common_prefix((uint8_t*)key_ptr + sizeof(key_len_t),
                           keylen_ins, comp_key, comp_keylen, &new_prefix_len);
        free(comp_key);

        if (new_prefix_len != prefix_len) {
            // prefix is modified .. we have to modify all entries in the node
            _arrange_prefix(node, node->nentry, prefix, prefix_len, new_prefix_len,
                idx, key_ptr, keylen_ins, value, ARR_OVERWRITE);
            return;
        }
    } else {
        // if there is no entry && level == 1 .. set the first key as prefix (excluding the last byte)
        if (node->nentry == 0 && node->level == 1) {
            prefix = (uint8_t*)key_ptr + sizeof(key_len_t);
            prefix_len = keylen_ins - 1;

            _prefix_len = _endian_encode(prefix_len);
            memcpy(ptr, &_prefix_len, sizeof(key_len_t));
            memcpy((uint8_t*)ptr + sizeof(key_len_t), prefix, prefix_len);
            offset_idx += sizeof(key_len_t) + prefix_len;
        }
    }

    temp_keylen = keylen_ins - prefix_len;
    if ( temp_keylen != keylen_idx && idx+2 <= node->nentry) {
        // we have to move idx+1 ~ nentry KVs to appropriate position
        memmove((uint8_t*)ptr + offset_next + (temp_keylen - keylen_idx),
                (uint8_t*)ptr + offset_next, next_len);
    }

    // copy key into the node
    _temp_keylen = _endian_encode(temp_keylen);
    memcpy((uint8_t*)ptr + offset_idx, &_temp_keylen, sizeof(key_len_t));
    memcpy((uint8_t*)ptr + offset_idx + sizeof(key_len_t),
           (uint8_t*)key_ptr + sizeof(key_len_t) + prefix_len,
           temp_keylen);
    // copy value
    memcpy((uint8_t*)ptr + offset_idx + sizeof(key_len_t) + temp_keylen,
           value, vsize);
}

INLINE void _ins_prefix_kv(struct bnode *node, idx_t idx, void *key, void *value)
{
    int ksize, vsize, i;
    void *key_ptr, *ptr, *prefix, *first_key, *last_key;
    key_len_t keylen, keylen_ins, prefix_len;
    key_len_t _keylen, _keylen_ins, _prefix_len, _temp_keylen, _new_prefix_len;
    key_len_t first_keylen, last_keylen, temp_keylen, new_prefix_len;
    size_t offset, offset_idx, offset_next, next_len;

    _get_kvsize(node->kvsize, ksize, vsize);
    ksize = sizeof(void *);
    ptr = node->data;
    offset = offset_idx = offset_next = 0;
    key_ptr = NULL;
    keylen_ins = 0;

    // prefix fetch
    prefix_len = 0;
    prefix = NULL;
    if (node->level == 1) {
        if (node->nentry > 0) {
            memcpy(&_prefix_len, ptr, sizeof(key_len_t));
            prefix_len = _endian_decode(_prefix_len);
            offset += sizeof(key_len_t) + prefix_len;
            prefix = (uint8_t*)ptr + sizeof(key_len_t);
        }
    }
    offset_idx = offset;

    // linear search
    first_key = last_key = NULL;
    first_keylen = last_keylen = next_len = 0;
    for (i=0;i<node->nentry;++i){
        memcpy(&_keylen, (uint8_t*)ptr+offset, sizeof(key_len_t));
        keylen = _endian_decode(_keylen);

        if (key && value) {
            // insert
            if (i==0) {
                first_key = (uint8_t*)ptr + offset + sizeof(key_len_t);
                first_keylen = keylen;
            }
            if (i==node->nentry-1 && key && value) {
                last_key = (uint8_t*)ptr + offset + sizeof(key_len_t);
                last_keylen = keylen;
            }
        }else{
            // remove
            if ((i==1 && idx == 0) || (i==0 && idx > 0)) {
                first_key = (uint8_t*)ptr + offset + sizeof(key_len_t);
                first_keylen = keylen;
            }
            if ((i==node->nentry-2 && idx == node->nentry-1) ||
             (i==node->nentry-1 && idx < node->nentry-1)) {
                last_key = (uint8_t*)ptr + offset + sizeof(key_len_t);
                last_keylen = keylen;
            }
        }

        if (i >= idx) next_len += sizeof(key_len_t) + keylen + vsize;
        if (i == idx+1) offset_next = offset;

        offset += sizeof(key_len_t)+keylen + vsize;
        if (i<idx) offset_idx = offset;
    }

    if (key && value) {
        // insert

        // copy key info from KEY
        memcpy(&key_ptr, key, ksize);
        memcpy(&_keylen_ins, key_ptr, sizeof(key_len_t));
        keylen_ins = _endian_decode(_keylen_ins);

        if ((idx ==0 || idx >= node->nentry) &&
            node->nentry > 0 && node->level == 1) {
            void *comp_key;
            key_len_t comp_keylen;

            // KEY and the last key
            comp_keylen = prefix_len + last_keylen;
            comp_key = (void*)malloc(comp_keylen);
            if (prefix_len) {
                memcpy(comp_key, prefix, prefix_len);
            }
            memcpy((uint8_t*)comp_key + prefix_len, last_key, last_keylen);

            _get_common_prefix((uint8_t*)key_ptr + sizeof(key_len_t),
                               keylen_ins, comp_key,
                               comp_keylen, &new_prefix_len);
            free(comp_key);

            if (new_prefix_len != prefix_len) {
                // prefix is modified .. we have to modify all entries in the node
                _arrange_prefix(node, node->nentry, prefix, prefix_len,
                                new_prefix_len, idx, key_ptr, keylen_ins,
                                value, ARR_INSERT);
                return;
            }
        }

        // we have to move idx ~ nentry KVs to (next) appropriate position
        temp_keylen = keylen_ins - prefix_len;
        memmove((uint8_t*)ptr + offset_idx + sizeof(key_len_t) +
                          temp_keylen + vsize,
                (uint8_t*)ptr + offset_idx, next_len);

        // copy key into the node
        _temp_keylen = _endian_encode(temp_keylen);
        memcpy((uint8_t*)ptr + offset_idx, &_temp_keylen, sizeof(key_len_t));
        memcpy((uint8_t*)ptr + offset_idx + sizeof(key_len_t),
               (uint8_t*)key_ptr + sizeof(key_len_t) + prefix_len,
               temp_keylen);
        // copy value
        memcpy((uint8_t*)ptr + offset_idx + sizeof(key_len_t) + temp_keylen,
               value, vsize);

    }else{
        if ((idx ==0 || idx >= node->nentry-1) &&
            node->nentry > 0 && node->level == 1) {
            // get common prefix between the first entry and the last entry
            void *comp_key;

            _get_common_prefix(first_key, first_keylen,
                               last_key, last_keylen, &new_prefix_len);

            if (new_prefix_len > 0) {
                // prefix is modified ..
                // we have to modify all entries in the node
                comp_key = (void*)malloc(sizeof(key_len_t) +
                                         prefix_len + new_prefix_len);
                _new_prefix_len = _endian_encode(new_prefix_len);
                memcpy(comp_key, &_new_prefix_len, sizeof(key_len_t));
                memcpy((uint8_t*)comp_key + sizeof(key_len_t),
                       prefix, prefix_len);
                memcpy((uint8_t*)comp_key + sizeof(key_len_t) + prefix_len,
                       first_key, new_prefix_len);
                new_prefix_len = prefix_len + new_prefix_len;

                _arrange_prefix(node, node->nentry,
                                prefix, prefix_len, new_prefix_len,
                                idx, comp_key, new_prefix_len,
                                value, ARR_REMOVE);
                free(comp_key);
                return;
            }
        }
        // we have to move idx+1 ~ nentry KVs to appropriate position
        memmove((uint8_t*)ptr + offset_idx,
                (uint8_t*)ptr + offset_next,
                next_len - (offset_next - offset_idx));
    }
}

INLINE void _copy_prefix_kv(struct bnode *node_dst,
                            struct bnode *node_src,
                            idx_t dst_idx,
                            idx_t src_idx,
                            idx_t len)
{
    int i;
    int ksize, vsize;
    void *ptr_src, *ptr_dst;
    void *prefix_src, *prefix_dst;
    void *first_key, *last_key;
    key_len_t keylen, new_prefix_len, temp_keylen;
    key_len_t prefix_src_len, prefix_dst_len, first_keylen, last_keylen;
    key_len_t _keylen, _prefix_src_len, _comp_keylen;
    key_len_t _prefix_dst_len, _temp_keylen;
    size_t src_offset, src_len, dst_offset;

    // not support when dst_idx != 0
    assert(dst_idx == 0);

    //if (node_src == node_dst) return;

    _get_kvsize(node_src->kvsize, ksize, vsize);
    ksize = sizeof(void *);

    ptr_src = node_src->data;
    ptr_dst = node_dst->data;

    prefix_src = prefix_dst = NULL;
    prefix_src_len = prefix_dst_len = 0;

    // prefix fetch
    src_offset = 0;
    if (node_src->level == 1) {
        if (node_src->nentry > 0) {
            memcpy(&_prefix_src_len, ptr_src, sizeof(key_len_t));
            prefix_src_len = _endian_decode(_prefix_src_len);
            src_offset += sizeof(key_len_t) + prefix_src_len;
            prefix_src = (uint8_t*)ptr_src + sizeof(key_len_t);
        }
    }

    // calculate offset of 0 ~ src_idx-1
    for (i=0;i<src_idx;++i){
        memcpy(&_keylen, (uint8_t*)ptr_src + src_offset, sizeof(key_len_t));
        keylen = _endian_decode(_keylen);
        src_offset += sizeof(key_len_t) + keylen + vsize;
    }

    // calculate data length to be copied & check common prefix among entries to be copied
    src_len = 0;
    for (i=src_idx ; i<src_idx+len ; ++i){
        memcpy(&_keylen, (uint8_t*)ptr_src + src_offset + src_len,
               sizeof(key_len_t));
        keylen = _endian_decode(_keylen);
        if (i==src_idx) {
            first_key = (uint8_t*)ptr_src + src_offset + src_len +
                                  sizeof(key_len_t);
            first_keylen = keylen;
        }
        if (i==src_idx+len-1) {
            last_key = (uint8_t*)ptr_src + src_offset + src_len +
                                 sizeof(key_len_t);
            last_keylen = keylen;
        }
        src_len += sizeof(key_len_t) + keylen + vsize;
    }

    dst_offset = 0;
    if (node_src->level == 1) {
        _get_common_prefix(first_key, first_keylen,
                           last_key, last_keylen, &new_prefix_len);

        if (node_dst == node_src) {
            if (new_prefix_len > 0) {

                void *comp_key;
                key_len_t comp_keylen;

                // KEY and the last key
                comp_keylen = prefix_src_len + last_keylen;
                comp_key = (void*)malloc(sizeof(key_len_t) + comp_keylen);
                _comp_keylen = _endian_encode(comp_keylen);
                memcpy(comp_key, &_comp_keylen, sizeof(key_len_t));
                if (prefix_src_len) {
                    memcpy((uint8_t*)comp_key + sizeof(key_len_t),
                           prefix_src, prefix_src_len);
                }
                memcpy((uint8_t*)comp_key + sizeof(key_len_t) +
                                 prefix_src_len,
                       last_key, last_keylen);

                _arrange_prefix(node_dst, len, prefix_src, prefix_src_len,
                                prefix_src_len + new_prefix_len, 0,
                                comp_key, comp_keylen, NULL, ARR_NONE);

                free(comp_key);
            }

            return;
        }

        if (new_prefix_len > 0) {
            prefix_dst_len = prefix_src_len + new_prefix_len;
            // copy original prefix
            _prefix_dst_len = _endian_encode(prefix_dst_len);
            memcpy((uint8_t*)ptr_dst + dst_offset,
                   &_prefix_dst_len, sizeof(key_len_t));
            memcpy((uint8_t*)ptr_dst + dst_offset + sizeof(key_len_t),
                   prefix_src, prefix_src_len);
            // copy rest of prefix
            memcpy((uint8_t*)ptr_dst + dst_offset +
                             sizeof(key_len_t) + prefix_src_len,
                   first_key, new_prefix_len);
            dst_offset += sizeof(key_len_t) + prefix_src_len + new_prefix_len;
            // copy entries
            src_len = 0;
            for (i=src_idx ; i<src_idx+len ; ++i){
                memcpy(&_keylen, (uint8_t*)ptr_src + src_offset + src_len,
                       sizeof(key_len_t));
                keylen = _endian_decode(_keylen);

                // copy key + value
                temp_keylen = keylen - new_prefix_len;
                _temp_keylen = _endian_encode(temp_keylen);
                memcpy((uint8_t*)ptr_dst + dst_offset, &_temp_keylen,
                       sizeof(key_len_t));
                memcpy((uint8_t*)ptr_dst + dst_offset + sizeof(key_len_t),
                       (uint8_t*)ptr_src + src_offset + src_len +
                                 sizeof(key_len_t) + new_prefix_len,
                       temp_keylen + vsize);
                dst_offset += sizeof(key_len_t) + temp_keylen + vsize;

                src_len += sizeof(key_len_t) + keylen + vsize;
            }
            return;
        }else{
            // copy original prefix
            _prefix_src_len = _endian_encode(prefix_src_len);
            memcpy((uint8_t*)ptr_dst + dst_offset, &_prefix_src_len,
                   sizeof(key_len_t));
            memcpy((uint8_t*)ptr_dst + dst_offset + sizeof(key_len_t),
                   prefix_src, prefix_src_len);
            dst_offset += sizeof(key_len_t) + prefix_src_len;
        }
    }

    // calculate offset of 0 ~ dst_idx-1
    for (i=0;i<dst_idx;++i){
        memcpy(&_keylen, (uint8_t*)ptr_dst + dst_offset, sizeof(key_len_t));
        keylen = _endian_decode(_keylen);
        dst_offset += sizeof(key_len_t) + keylen + vsize;
    }

    // copy
    memcpy((uint8_t*)ptr_dst + dst_offset,
           (uint8_t*)ptr_src + src_offset, src_len);
}

INLINE size_t _get_prefix_kv_size(struct btree *tree, void *key, void *value)
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

INLINE size_t _get_prefix_data_size(
    struct bnode *node, void *new_minkey, void *key_arr, void *value_arr, size_t len)
{
    int ksize, vsize, i;
    void *ptr, *key_ptr, *prefix;
    size_t offset, offset_ins, size, ret;
    key_len_t keylen, prefix_len, new_prefix_len;
    key_len_t _keylen, _prefix_len;

    _get_kvsize(node->kvsize, ksize, vsize);
    ksize = sizeof(void*);
    ptr = node->data;
    offset = size = 0;

    // prefix fetch
    prefix_len = 0;
    prefix = NULL;
    if (node->level == 1) {
        if (node->nentry > 0) {
            memcpy(&_prefix_len, ptr, sizeof(key_len_t));
            prefix_len = _endian_decode(_prefix_len);
            offset += sizeof(key_len_t) + prefix_len;
            prefix = (uint8_t*)ptr + sizeof(key_len_t);
        }
    }
    new_prefix_len = prefix_len;
    size = offset;

    for (i=0;i<node->nentry;++i){
        memcpy(&_keylen, (uint8_t*)ptr + offset, sizeof(key_len_t));
        keylen = _endian_decode(_keylen);
        offset += sizeof(key_len_t) + keylen + vsize;

        if (new_minkey && i==0) {
            // if the minimum key should be replaced to NEW_MINKEY
            memcpy(&key_ptr, new_minkey, ksize);
            memcpy(&_keylen, key_ptr, sizeof(key_len_t));
            keylen = _endian_decode(_keylen);
            if (node->level == 1 && prefix_len > 0) {
                _get_common_prefix(prefix, new_prefix_len,
                                   (uint8_t*)key_ptr + sizeof(key_len_t),
                                   keylen, &new_prefix_len);
            }
        }
        size += sizeof(key_len_t) + keylen + vsize;
    }

    offset_ins = 0;
    if (key_arr && value_arr && len > 0) {
        for (i=0;i<len;++i){
            memcpy(&key_ptr, (uint8_t*)key_arr + ksize*i, ksize);
            memcpy(&_keylen, key_ptr, sizeof(key_len_t));
            keylen = _endian_decode(_keylen);
            if (node->level == 1 && prefix_len > 0) {
                _get_common_prefix(
                    prefix, new_prefix_len,
                    (uint8_t*)key_ptr + sizeof(key_len_t), keylen,
                    &new_prefix_len);
            }
            offset_ins += sizeof(key_len_t) + keylen + vsize;
        }
    }

    ret = (size + (prefix_len-new_prefix_len)*node->nentry) +
        (offset_ins - len*new_prefix_len) - (prefix_len - new_prefix_len);
    if (new_minkey) {
        ret -= new_prefix_len;
    }
    return ret;
}

INLINE void _init_prefix_kv_var(struct btree *tree, void *key, void *value)
{
    if (key) memset(key, 0, sizeof(void *));
    if (value) memset(value, 0, tree->vsize);
}

INLINE void _free_prefix_kv_var(struct btree *tree, void *key, void *value)
{
    void *key_ptr;

    memcpy(&key_ptr, key, sizeof(void *));
    if (key_ptr) {
        free(key_ptr);
        key_ptr = NULL;
        memcpy(key, &key_ptr, sizeof(void *));
    }
}

INLINE void _set_prefix_key(struct btree *tree, void *dst, void *src)
{
    void *key_ptr_old, *key_ptr_new;
    key_len_t keylen_new, _keylen_new;

    memcpy(&key_ptr_new, src, sizeof(void *));
    memcpy(&_keylen_new, key_ptr_new, sizeof(key_len_t));
    keylen_new = _endian_decode(_keylen_new);

    // free previous key (if exist)
    memcpy(&key_ptr_old, dst, sizeof(void *));
    if (key_ptr_old) {
        free(key_ptr_old);
    }
    key_ptr_old = (void*)malloc(sizeof(key_len_t) + keylen_new);
    memcpy(key_ptr_old, key_ptr_new, sizeof(key_len_t) + keylen_new);
    memcpy(dst, &key_ptr_old, sizeof(void *));
}

INLINE void _set_prefix_value(struct btree *tree, void *dst, void *src)
{
    memcpy(dst, src, tree->vsize);
}

INLINE void _get_prefix_nth_idx(struct bnode *node,
                                idx_t num,
                                idx_t den,
                                idx_t *idx)
{
    size_t rem = node->nentry - (int)(node->nentry / den) * den;
    *idx = (int)(node->nentry / den) * num + ((num < rem)?(num):(rem));
}

void btree_prefix_kv_set_key(void *key, void *str, size_t len)
{
    void *key_ptr;
    key_len_t _keylen, keylen = len;

    key_ptr = (void *)malloc(sizeof(key_len_t) + keylen);
    _keylen = _endian_encode(keylen);
    memcpy(key_ptr, &_keylen, sizeof(key_len_t));
    memcpy((uint8_t*)key_ptr + sizeof(key_len_t), str, keylen);
    memcpy(key, &key_ptr, sizeof(void *));
}

void btree_prefix_kv_get_key(void *key, void *strbuf, size_t *len)
{
    void *key_ptr;
    key_len_t keylen, _keylen;

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

void btree_prefix_kv_free_key(void *key)
{
    void *key_ptr;
    memcpy(&key_ptr, key, sizeof(void *));
    if (key_ptr) free(key_ptr);
    key_ptr = NULL;
    memcpy(key, &key_ptr, sizeof(void *));
}

INLINE void _get_prefix_nth_splitter(struct bnode *prev_node, struct bnode *node, void *key)
{
    int ksize, vsize;
    _get_kvsize(node->kvsize, ksize, vsize);
    ksize = sizeof(void *);

    uint8_t *key1 = alca(uint8_t, ksize);
    uint8_t *key2 = alca(uint8_t, ksize);
    void *key1_ptr, *key2_ptr;
    key_len_t key1_len, key2_len, prefix_len;
    key_len_t _key1_len, _key2_len;

    key1_len = key2_len = 0;
    memset(key1, 0, ksize);
    memset(key2, 0, ksize);

    _get_prefix_kv(prev_node, prev_node->nentry-1, key1, NULL);
    _get_prefix_kv(node, 0, key2, NULL);

    memcpy(&key1_ptr, key1, sizeof(void *));
    memcpy(&key2_ptr, key2, sizeof(void *));
    memcpy(&_key1_len, key1_ptr, sizeof(key_len_t));
    key1_len = _endian_decode(_key1_len);
    memcpy(&_key2_len, key2_ptr, sizeof(key_len_t));
    key2_len = _endian_decode(_key2_len);

    _get_common_prefix(
       (uint8_t*)key1_ptr + sizeof(key_len_t), key1_len,
       (uint8_t*)key2_ptr + sizeof(key_len_t), key2_len, &prefix_len);

    if (key) {
        btree_prefix_kv_free_key(key);
    }
    btree_prefix_kv_set_key(key,
                            (uint8_t*)key2_ptr + sizeof(key_len_t),
                            prefix_len+1);
    btree_prefix_kv_free_key(key1);
    btree_prefix_kv_free_key(key2);
}

INLINE bid_t _prefix_value_to_bid_64(void *value)
{
    return *((bid_t *)value);
}

INLINE void* _prefix_bid_to_value_64(bid_t *bid)
{
    return (void *)bid;
}

INLINE int _cmp_prefix64(void *key1, void *key2, void *aux)
{
    void *key_ptr1, *key_ptr2;
    key_len_t keylen1, keylen2;
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
    keylen1 = _endian_decode(_keylen1);
    memcpy(&_keylen2, key_ptr2, sizeof(key_len_t));
    keylen2 = _endian_decode(_keylen2);

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

struct btree_kv_ops * btree_prefix_kv_get_kb64_vb64(struct btree_kv_ops *kv_ops)
{
    struct btree_kv_ops *btree_kv_ops;
    if (kv_ops) {
        btree_kv_ops = kv_ops;
    }else{
        btree_kv_ops = (struct btree_kv_ops *)malloc(sizeof(struct btree_kv_ops));
    }

    btree_kv_ops->get_kv = _get_prefix_kv;
    btree_kv_ops->set_kv = _set_prefix_kv;
    btree_kv_ops->ins_kv = _ins_prefix_kv;
    btree_kv_ops->copy_kv = _copy_prefix_kv;
    btree_kv_ops->set_key = _set_prefix_key;
    btree_kv_ops->set_value = _set_prefix_value;
    btree_kv_ops->get_data_size = _get_prefix_data_size;
    btree_kv_ops->get_kv_size = _get_prefix_kv_size;
    btree_kv_ops->init_kv_var = _init_prefix_kv_var;
    btree_kv_ops->free_kv_var = _free_prefix_kv_var;

    btree_kv_ops->get_nth_idx = _get_prefix_nth_idx;
    btree_kv_ops->get_nth_splitter = _get_prefix_nth_splitter;

    btree_kv_ops->cmp = _cmp_prefix64;

    btree_kv_ops->bid2value = _prefix_bid_to_value_64;
    btree_kv_ops->value2bid = _prefix_value_to_bid_64;

    return btree_kv_ops;
}


