/*
 * Copyright 2013 Jung-Sang Ahn <jungsang.ahn@gmail.com>.
 * All Rights Reserved.
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

struct btree_kv_ops * btree_kv_get_ku64_vu64();

struct btree_kv_ops * btree_kv_get_kb64_vb64(struct btree_kv_ops *kv_ops);
struct btree_kv_ops * btree_kv_get_kb32_vb64(struct btree_kv_ops *kv_ops);



#endif
