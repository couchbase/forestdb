/*
 * Copyright 2013 Jung-Sang Ahn <jungsang.ahn@gmail.com>.
 * All Rights Reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "btree.h"
#include "btree_kv.h"


INLINE void _get_kv(struct bnode *node, idx_t idx, void *key, void *value)
{
/*
	int ksize, vsize;

	_get_kvsize(node->kvsize, ksize, vsize);

	memcpy(key, node->data + (idx * (ksize+vsize)), ksize);
	memcpy(value, node->data + (idx * (ksize+vsize)) + ksize, vsize);
	*/
	memcpy(key, 
		node->data + (idx * (__ksize(node->kvsize)+__vsize(node->kvsize))), 
		__ksize(node->kvsize));
	memcpy(value, 
		node->data + (idx * (__ksize(node->kvsize)+__vsize(node->kvsize))) + __ksize(node->kvsize), 
		__vsize(node->kvsize));
}

INLINE void _set_kv(struct bnode *node, idx_t idx, void *key, void *value)
{
/*
	int ksize, vsize;

	_get_kvsize(node->kvsize, ksize, vsize);

	memcpy(node->data + (idx * (ksize+vsize)), key, ksize);
	memcpy(node->data + (idx * (ksize+vsize)) + ksize, value, vsize);
	*/
	memcpy(node->data + (idx * (__ksize(node->kvsize)+__vsize(node->kvsize))), 
		key, __ksize(node->kvsize));
	memcpy(node->data + (idx * (__ksize(node->kvsize)+__vsize(node->kvsize))) + __ksize(node->kvsize), 
		value, __vsize(node->kvsize));
}

INLINE bid_t _value_to_bid_64(void *value)
{
	return *((bid_t *)value);
}

INLINE void* _bid_to_value_64(bid_t *bid)
{
	return (void *)bid;
}

INLINE int _cmp_int32_t(void *key1, void *key2)
{
	int32_t *a,*b;
	a = (int32_t*)key1;
	b = (int32_t*)key2;
	if (*a<*b) return -1;
	if (*a>*b) return 1;
	return 0;	
}

INLINE int _cmp_uint32_t(void *key1, void *key2)
{
	uint32_t *a,*b;
	a = (uint32_t*)key1;
	b = (uint32_t*)key2;
	if (*a<*b) return -1;
	if (*a>*b) return 1;
	return 0;	
}

INLINE int _cmp_uint64_t(void *key1, void *key2)
{
	uint64_t *a,*b;
	a = (uint64_t*)key1;
	b = (uint64_t*)key2;
	if (*a<*b) return -1;
	if (*a>*b) return 1;
	return 0;	
}

INLINE int _cmp_char64(void *key1, void *key2)
{
	return strncmp((char*)key1, (char*)key2, 8);
}

INLINE int _cmp_binary32(void *key1, void *key2)
{
	#ifdef __BIT_CMP
		return _CMP_U32( bitswap32(*(uint32_t*)key1), bitswap32(*(uint32_t*)key2));
	#else
		return memcmp(key1, key2, 8);
	#endif
}

INLINE int _cmp_binary64(void *key1, void *key2)
{
	#ifdef __BIT_CMP
		return _CMP_U64( bitswap64(*(uint64_t*)key1), bitswap64(*(uint64_t*)key2));
	#else
		return memcmp(key1, key2, 8);
	#endif
	
	//return memcmp(key1, key2, 8);
	/*
	if ( bitswap64(*(uint64_t*)key1) < bitswap64(*(uint64_t*)key2) ) return -1;
	else if ( bitswap64(*(uint64_t*)key1) > bitswap64(*(uint64_t*)key2) ) return 1;
	else return 0;*/
	//return _CMP_U64( bitswap64(*(uint64_t*)key1), bitswap64(*(uint64_t*)key2));
}

// key: uint64_t, value: uint64_t
static struct btree_kv_ops kv_ops_ku64_vu64 = {
	_get_kv, _set_kv, _cmp_uint64_t, _value_to_bid_64, _bid_to_value_64};

static struct btree_kv_ops kv_ops_ku32_vu64 = {
	_get_kv, _set_kv, _cmp_uint32_t, _value_to_bid_64, _bid_to_value_64};

struct btree_kv_ops * btree_kv_get_ku64_vu64() 
{
	return &kv_ops_ku64_vu64;
}

struct btree_kv_ops * btree_kv_get_ku32_vu64()
{
	return &kv_ops_ku32_vu64;
}


