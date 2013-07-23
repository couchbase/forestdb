/*
 * Copyright 2013 Jung-Sang Ahn <jungsang.ahn@gmail.com>.
 * All Rights Reserved.
 */

#ifndef _JSAHN_BTREE_KV_H
#define _JSAHN_BTREE_KV_H

#include <stdint.h>

#include "common.h"

#define _get_kvsize(kvsize, ksize, vsize) \
	(ksize) = ((kvsize) & 0xf0) >> 4;	\
	(vsize) = ((kvsize) & 0x0f)

#define __ksize(kvsize) (((kvsize) & 0xf0) >> 4)
#define __vsize(kvsize) (((kvsize) & 0x0f))


INLINE void _get_kv(struct bnode *node, idx_t idx, void *key, void *value);
INLINE void _set_kv(struct bnode *node, idx_t idx, void *key, void *value);
INLINE bid_t _value_to_bid_64(void *value);
INLINE void* _bid_to_value_64(bid_t *bid);
INLINE int _cmp_int32_t(void *key1, void *key2);
INLINE int _cmp_uint32_t(void *key1, void *key2);
INLINE int _cmp_uint64_t(void *key1, void *key2);
INLINE int _cmp_binary64(void *key1, void *key2);


struct btree_kv_ops * btree_kv_get_ku64_vu64();

#endif
