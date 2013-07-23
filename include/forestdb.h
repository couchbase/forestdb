/*
 * Copyright 2013 Jung-Sang Ahn <jungsang.ahn@gmail.com>.
 * All Rights Reserved.
 */

#ifndef _JSAHN_FDB_H
#define _JSAHN_FDB_H

typedef enum {
	FDB_RESULT_SUCCESS,
	FDB_RESULT_FAIL,
	FDB_RESULT_INVALID_ARGS
} fdb_status;

typedef struct {
	size_t chunksize;
	size_t offsetsize;
	size_t buffercache_size;
	size_t wal_threshold;
	unsigned char flag;
} fdb_config;

typedef struct {
	size_t keylen;
	size_t metalen;
	size_t bodylen;
	void *key;
	void *meta;
	void *body;
} fdb_doc;

struct hbtrie;
struct filemgr;
struct btreeblk_handle;
struct docio_handle;
struct btree_blk_ops;

typedef struct {
	struct hbtrie *trie;
	struct filemgr *file;
	struct docio_handle *dhandle;
	struct btreeblk_handle *bhandle;
	struct btree_blk_ops *btreeblkops;
	struct filemgr_ops *fileops;
	fdb_config config;
} fdb_handle;

fdb_status fdb_open(fdb_handle *handle, char *filename, fdb_config config);
fdb_status fdb_get(fdb_handle *handle, fdb_doc *doc);
fdb_status fdb_set(fdb_handle *handle, fdb_doc *doc);
fdb_status fdb_commit(fdb_handle *handle);
fdb_status fdb_close(fdb_handle *handle);


#endif
