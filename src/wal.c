/*
 * Copyright 2013 Jung-Sang Ahn <jungsang.ahn@gmail.com>.
 * All Rights Reserved.
 */

#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdint.h>

#include "filemgr.h"
#include "common.h"
#include "hash.h"
#include "docio.h"
#include "wal.h"
#include "hash_functions.h"
#include "hbtrie.h"

//#define __DEBUG_WAL
#ifdef __DEBUG
#ifndef __DEBUG_WAL
	#undef DBG
	#undef DBGCMD
	#define DBG(args...)
	#define DBGCMD(command...)
#endif
#endif

struct wal_item{
	void *key;
	wal_item_action action;
	keylen_t keylen;
	uint64_t offset;
	struct hash_elem hash_elem;
	struct list_elem list_elem;
};

INLINE uint32_t _wal_hash(struct hash *hash, struct hash_elem *e)
{
	struct wal_item *item = _get_entry(e, struct wal_item, hash_elem);
	return hash_djb2(item->key, MIN(8, item->keylen)) & ((uint64_t)hash->nbuckets - 1);
}

INLINE int _wal_cmp(struct hash_elem *a, struct hash_elem *b)
{
	keylen_t minkeylen;
	struct wal_item *aa, *bb;
	aa = _get_entry(a, struct wal_item, hash_elem);
	bb = _get_entry(b, struct wal_item, hash_elem);
	if (aa->keylen != bb->keylen) return 1;
	return memcmp(aa->key, bb->key, aa->keylen);
}

wal_result wal_init(struct filemgr *file, int nbucket)
{
	file->wal->size = 0;
	hash_init(&file->wal->hash, nbucket, _wal_hash, _wal_cmp);
	list_init(&file->wal->list);
	return WAL_RESULT_SUCCESS;
}

wal_result wal_insert(struct filemgr *file, void *key, size_t keylen, uint64_t offset)
{
	struct wal_item *item;
	struct wal_item query;
	struct hash_elem *e;
	query.key = key;
	query.keylen = keylen;
	e = hash_find(&file->wal->hash, &query.hash_elem);
	if (e) {
		item = _get_entry(e, struct wal_item, hash_elem);
		item->offset = offset;
		item->action = WAL_ACT_INSERT;
	}else{
		item = (struct wal_item *)malloc(sizeof(struct wal_item));
		item->keylen = keylen;
		item->key = (void *)malloc(item->keylen);
		memcpy(item->key, key, item->keylen);
		item->action = WAL_ACT_INSERT;
		item->offset = offset;
		hash_insert(&file->wal->hash, &item->hash_elem);
		list_push_front(&file->wal->list, &item->list_elem);
		file->wal->size++;
	}
	return WAL_RESULT_SUCCESS;
}

wal_result wal_find(struct filemgr *file, void *key, size_t keylen, uint64_t *offset)
{
	struct wal_item *item;
	struct wal_item query;
	struct hash_elem *e;
	query.key = key;
	query.keylen = keylen;
	e = hash_find(&file->wal->hash, &query.hash_elem);
	if (e) {
		item = _get_entry(e, struct wal_item, hash_elem);
		if (item->action == WAL_ACT_INSERT) {
			*offset = item->offset;
			return WAL_RESULT_SUCCESS;
		}
	}
	return WAL_RESULT_FAIL;	
}

wal_result wal_remove(struct filemgr *file, void *key, size_t keylen)
{
	struct wal_item *item;
	struct wal_item query;
	struct hash_elem *e;
	query.key = key;
	query.keylen = keylen;
	e = hash_find(&file->wal->hash, &query.hash_elem);
	if (e) {
		item = _get_entry(e, struct wal_item, hash_elem);
		if (item->action == WAL_ACT_INSERT) {
			item->action = WAL_ACT_REMOVE;
		}
	}else{
		item = (struct wal_item *)malloc(sizeof(struct wal_item));
		item->keylen = keylen;
		item->key = (void *)malloc(item->keylen);
		memcpy(item->key, key, item->keylen);
		item->action = WAL_ACT_REMOVE;
		hash_insert(&file->wal->hash, &item->hash_elem);
		list_push_front(&file->wal->list, &item->list_elem);
		file->wal->size++;		
	}
	return WAL_RESULT_SUCCESS;
}

wal_result wal_flush(struct filemgr *file, void *dbhandle, wal_flush_func *func)
{
	int i;
	struct list_elem *e;
	struct hash_elem *h;
	struct wal_item *item;

	/*
	for (i=0;i<file->wal->hash.nbuckets;++i){
		e = list_begin(file->wal->hash.buckets + i);
		while(e) {
			h = _get_entry(e, struct hash_elem, list_elem);
			item = _get_entry(h, struct wal_item, hash_elem);
			e = list_remove(file->wal->hash.buckets + i, e);
			func(dbhandle, item->key, item->keylen, item->offset, item->action);

			free(item->key);
			free(item);
		}
	}*/

	e = list_begin(&file->wal->list);
	while(e){
		item = _get_entry(e, struct wal_item, list_elem);
		e = list_remove(&file->wal->list, e);
		hash_remove(&file->wal->hash, &item->hash_elem);
		func(dbhandle, item->key, item->keylen, item->offset, item->action);
		free(item->key);
		free(item);
	}
	file->wal->size = 0;

	return WAL_RESULT_SUCCESS;
}

size_t wal_get_size(struct filemgr *file) 
{
	return file->wal->size;
}


