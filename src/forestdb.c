/*
 * Copyright 2013 Jung-Sang Ahn <jungsang.ahn@gmail.com>.
 * All Rights Reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "filemgr.h"
#include "hbtrie.h"
#include "docio.h"
#include "btreeblock.h"
#include "forestdb.h"
#include "common.h"
#include "wal.h"
#include "filemgr_ops_linux.h"

#define _FDB_BLOCKSIZE (4096)
#define _FDB_WAL_NBUCKET (1024)

INLINE size_t _fdb_readkey_wrap(void *handle, uint64_t offset, void *buf)
{
	keylen_t keylen;
	docio_read_doc_key((struct docio_handle *)handle, offset, &keylen, buf);
	return keylen;
}

fdb_status fdb_open(fdb_handle *handle, char *filename, fdb_config config)
{
	struct filemgr_config fconfig;
	bid_t trie_root_bid = BLK_NOT_FOUND;

	fconfig.blocksize = _FDB_BLOCKSIZE;
	fconfig.ncacheblock = config.buffercache_size / _FDB_BLOCKSIZE;
	fconfig.flag = 0x0;
	handle->fileops = get_linux_filemgr_ops();
	handle->btreeblkops = btreeblk_get_ops();
	handle->file = filemgr_open(filename, handle->fileops, fconfig);
	handle->trie = (struct hbtrie *)malloc(sizeof(struct hbtrie));
	handle->bhandle = (struct btreeblk_handle *)malloc(sizeof(struct btreeblk_handle));
	handle->dhandle = (struct docio_handle *)malloc(sizeof(struct docio_handle));
	handle->config = config;

	wal_init(handle->file, _FDB_WAL_NBUCKET);
	docio_init(handle->dhandle, handle->file);
	btreeblk_init(handle->bhandle, handle->file, handle->file->blocksize);

	if (handle->file->header.size > 0 && handle->file->header.data) {
		memcpy(&trie_root_bid, handle->file->header.data, sizeof(bid_t));
	}
	hbtrie_init(handle->trie, config.chunksize, config.offsetsize, handle->file->blocksize, trie_root_bid, 
		handle->bhandle, handle->btreeblkops, handle->dhandle, _fdb_readkey_wrap);

	return FDB_RESULT_SUCCESS;
}

fdb_status fdb_get(fdb_handle *handle, fdb_doc *doc)
{
	uint64_t offset;
	struct docio_object _doc;
	wal_result wr;
	hbtrie_result hr;
	
	if ( (doc->key == NULL) || (doc->keylen == 0) ||
		(doc->metalen > 0 && doc->meta == NULL) || 
		(doc->bodylen > 0 && doc->body == NULL)) return FDB_RESULT_INVALID_ARGS;
	
	_doc.key = doc->key;
	_doc.meta = doc->meta;
	_doc.body = doc->body;

	wr = wal_find(handle->file, doc->key, doc->keylen, &offset);

	if (wr == WAL_RESULT_FAIL) {
		hr = hbtrie_find(handle->trie, doc->key, doc->keylen, &offset);
	}

	if (wr == WAL_RESULT_SUCCESS || hr == HBTRIE_RESULT_SUCCESS) {
		docio_read_doc(handle->dhandle, offset, &_doc);
		doc->keylen = _doc.length.keylen;
		doc->metalen = _doc.length.metalen;
		doc->bodylen = _doc.length.bodylen;
		return FDB_RESULT_SUCCESS;
	}

	return FDB_RESULT_FAIL;
}

fdb_status fdb_set(fdb_handle *handle, fdb_doc *doc)
{
	uint64_t offset;
	struct docio_object _doc;
	
	if ( (doc->key == NULL) || (doc->keylen == 0) ||
		(doc->metalen > 0 && doc->meta == NULL) || 
		(doc->bodylen > 0 && doc->body == NULL)) return FDB_RESULT_INVALID_ARGS;
	
	_doc.length.keylen = doc->keylen;
	_doc.length.metalen = doc->metalen;
	_doc.length.bodylen = doc->bodylen;
	_doc.key = doc->key;
	_doc.meta = doc->meta;
	_doc.body = doc->body;

	if (_doc.body) {
		offset = docio_append_doc(handle->dhandle, &_doc);
		wal_insert(handle->file, _doc.key, _doc.length.keylen, offset);
	}else{
		//remove
		wal_remove(handle->file, _doc.key, _doc.length.keylen);
	}

	/*
	if (wal_get_size(handle->file) > 1024) {
		wal_flush(handle->file, (void *)handle, _fdb_wal_flush_func);
	}*/
	return FDB_RESULT_SUCCESS;
}

void _fdb_wal_flush_func(void *voidhandle, void *key, int keylen, uint64_t offset, wal_item_action action)
{
	fdb_handle *handle = (fdb_handle *)voidhandle;
	if (action == WAL_ACT_INSERT) {
		hbtrie_insert(handle->trie, key, keylen, &offset);
		btreeblk_end(handle->bhandle);
	}else{
		hbtrie_remove(handle->trie, key, keylen);
		btreeblk_end(handle->bhandle);
	}
}

fdb_status fdb_commit(fdb_handle *handle)
{
	btreeblk_end(handle->bhandle);
	if (wal_get_size(handle->file) > handle->config.wal_threshold) {
		wal_flush(handle->file, handle, _fdb_wal_flush_func);
	}
	filemgr_commit(handle->file);
	return FDB_RESULT_SUCCESS;
}

void _fdb_set_file_header(fdb_handle *handle)
{
	uint8_t buf[16];
	memcpy(buf, &handle->trie->root_bid, sizeof(handle->trie->root_bid));
	memcpy(buf + sizeof(handle->trie->root_bid), &handle->trie->root_bid, sizeof(handle->trie->root_bid));
	filemgr_update_header(handle->file, buf, 16);
}

fdb_status fdb_close(fdb_handle *handle)
{
	btreeblk_end(handle->bhandle);
	wal_flush(handle->file, handle, _fdb_wal_flush_func);
	filemgr_commit(handle->file);
	_fdb_set_file_header(handle);
	filemgr_close(handle->file);
	free(handle->trie);
	free(handle->bhandle);
	free(handle->dhandle);
	return FDB_RESULT_SUCCESS;
}

