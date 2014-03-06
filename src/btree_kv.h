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

#include <stdint.h>
#include "common.h"

/*
INLINE void _get_kv(struct bnode *node, idx_t idx, void *key, void *value);
INLINE void _set_kv(struct bnode *node, idx_t idx, void *key, void *value);
INLINE void _move_kv(struct bnode *node, idx_t src_idx, idx_t dst_idx, idx_t len);
INLINE void _copy_kv(
    struct bnode *node_src, struct bnode *node_dst, idx_t src_idx, idx_t dst_idx, idx_t len);
INLINE void _init_kv_var(struct btree *tree, void *key, void *value);

INLINE size_t _get_data_size(struct bnode *node);
INLINE size_t _get_kv_size(struct btree *tree, void *key, void *value);

INLINE void _set_key(struct btree *tree, void *dst, void *src);
INLINE void _set_value(struct btree *tree, void *dst, void *src);
INLINE bid_t _value_to_bid_64(void *value);
INLINE void* _bid_to_value_64(bid_t *bid);
INLINE int _cmp_int32_t(void *key1, void *key2);
INLINE int _cmp_uint32_t(void *key1, void *key2);
INLINE int _cmp_uint64_t(void *key1, void *key2);
INLINE int _cmp_binary32(void *key1, void *key2);
INLINE int _cmp_binary64(void *key1, void *key2);
*/
INLINE int _cmp_uint64_t(void *key1, void *key2);

struct btree_kv_ops;
struct btree_kv_ops * btree_kv_get_ku64_vu64();
struct btree_kv_ops * btree_kv_get_kb64_vb64(struct btree_kv_ops *kv_ops);
struct btree_kv_ops * btree_kv_get_kb32_vb64(struct btree_kv_ops *kv_ops);



#endif
