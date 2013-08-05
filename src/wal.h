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
	struct hash hash_bykey;
	#ifdef __FDB_SEQTREE
		struct hash hash_byseq;
	#endif
	struct list list;
};

typedef struct fdb_doc_struct fdb_doc;

wal_result wal_init(struct filemgr *file, int nbucket);
wal_result wal_insert(struct filemgr *file, fdb_doc *doc, uint64_t offset);
wal_result wal_find(struct filemgr *file, fdb_doc *doc, uint64_t *offset);
wal_result wal_remove(struct filemgr *file, fdb_doc *doc);
wal_result wal_flush(struct filemgr *file, void *dbhandle, wal_flush_func *func);
size_t wal_get_size(struct filemgr *file) ;

#endif
