/*
 * Copyright 2013 Jung-Sang Ahn <jungsang.ahn@gmail.com>.
 * All Rights Reserved.
 */

#ifndef _JSAHN_WAL_H
#define _JSAHN_WAL_H

#include <stdint.h>
#include "hash.h"
#include "list.h"


typedef enum {
	WAL_ACT_INSERT,
	WAL_ACT_REMOVE
} wal_item_action;

typedef enum {
	WAL_RESULT_SUCCESS,
	WAL_RESULT_FAIL
} wal_result;

typedef void wal_flush_func(void *dbhandle, void *key, int keylen, uint64_t offset, wal_item_action action);

struct wal {
	size_t size;
	struct hash hash;
	struct list list;
};

wal_result wal_init(struct filemgr *file, int nbucket);
wal_result wal_insert(struct filemgr *file, void *key, size_t keylen, uint64_t offset);
wal_result wal_find(struct filemgr *file, void *key, size_t keylen, uint64_t *offset);
wal_result wal_remove(struct filemgr *file, void *key, size_t keylen);
wal_result wal_flush(struct filemgr *file, void *dbhandle, wal_flush_func *func);
size_t wal_get_size(struct filemgr *file) ;

#endif
