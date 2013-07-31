/*
 * Copyright 2013 Jung-Sang Ahn <jungsang.ahn@gmail.com>.
 * All Rights Reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <assert.h>

#include "filemgr.h"
#include "hash_functions.h"
#include "blockcache.h"
#include "wal.h"

#ifdef __DEBUG
#ifndef __DEBUG_FILEMGR
	#undef DBG
	#undef DBGCMD
	#define DBG(args...)
	#define DBGCMD(command...)
#endif
#endif

// NBUCKET must be power of 2
#define NBUCKET (1024)
#define FILEMGR_MAGIC (0xbeefbeef)
#define NBUF (32)

// global static variables
static spin_t initial_lock = SPIN_INITIALIZER;
static int filemgr_initialized = 0;
static struct filemgr_config global_config;
static struct hash hash;

static size_t filemgr_sys_pagesize;
void *temp_buf[NBUF];

uint32_t _file_hash(struct hash *hash, struct hash_elem *e)
{
	struct filemgr *file = _get_entry(e, struct filemgr, e);
	int len = strlen(file->filename);
	int offset = MIN(len, 8);
	return hash_djb2(file->filename + (len - offset), offset) & ((unsigned)(NBUCKET-1));
}

int _file_cmp(struct hash_elem *a, struct hash_elem *b)
{
	struct filemgr *aa, *bb;
	aa = _get_entry(a, struct filemgr, e);
	bb = _get_entry(b, struct filemgr, e);
	return strcmp(aa->filename, bb->filename);
}

void filemgr_init(struct filemgr_config config)
{
	int i, ret;

 	spin_lock(&initial_lock);
	if (!filemgr_initialized) {
		global_config = config;

		if (global_config.ncacheblock > 0) 
			bcache_init(global_config.ncacheblock, global_config.blocksize);
		
		hash_init(&hash, NBUCKET, _file_hash, _file_cmp);

		filemgr_sys_pagesize = sysconf(_SC_PAGESIZE);

		for (i=0;i<NBUF;++i){
			ret = posix_memalign(&temp_buf[i], filemgr_sys_pagesize, global_config.blocksize);
		}
			
		filemgr_initialized = 1;
	}
	spin_unlock(&initial_lock);
}

void _filemgr_read_header(struct filemgr *file)
{
	uint32_t magic;
	uint16_t len;
	file->ops->pread(file->fd, &magic, sizeof(magic), file->pos - sizeof(magic));
	if (magic == FILEMGR_MAGIC) {
		file->ops->pread(file->fd, &len, sizeof(len), file->pos - sizeof(magic) - sizeof(len));
		file->header.data = (void *)malloc(len);
		file->ops->pread(file->fd, file->header.data, len, file->pos - len - sizeof(magic) - sizeof(len));
		file->header.size = len;

		file->pos -= len + sizeof(magic) + sizeof(len);
		file->last_commit = file->pos;
	}
}

struct filemgr * filemgr_open(char *filename, struct filemgr_ops *ops, struct filemgr_config config)
{
	struct filemgr *file, query;
	struct hash_elem *e;
	
	// global initialization
	// initialized only once at first time
	if (!filemgr_initialized)
		filemgr_init(config);

	// check whether file is already opened or not
	query.filename = filename;
	e = hash_find(&hash, &query.e);

	if (e) {
		// already opened
		file = _get_entry(e, struct filemgr, e);
		DBG("already opened %s\n", file->filename);
	}else{
		// open
		file = (struct filemgr*)malloc(sizeof(struct filemgr));
		file->filename_len = strlen(filename);
		file->filename = (char*)malloc(file->filename_len + 1);
		file->wal = (struct wal *)malloc(sizeof(struct wal));
		strcpy(file->filename, filename);
		file->ops = ops;
		#ifdef __O_DIRECT
			file->fd = file->ops->open(
				file->filename, O_RDWR | O_CREAT | O_DIRECT | config.flag, 0666);
		#else
			file->fd = file->ops->open(
				file->filename, O_RDWR | O_CREAT | config.flag, 0666);
		#endif
		file->blocksize = global_config.blocksize;
		file->pos = file->last_commit = file->ops->goto_eof(file->fd);
		if (file->pos % file->blocksize != 0) {
			// read header
			_filemgr_read_header(file);
		}else{
			file->header.size = 0;
			file->header.data = NULL;
		}
		file->lock = SPIN_INITIALIZER;
		
		hash_insert(&hash, &file->e);
	}

	return file;
}

void filemgr_update_header(struct filemgr *file, void *buf, size_t len)
{
	if (file->header.data == NULL) {
		file->header.data = (void *)malloc(len);
	}else if (file->header.size < len){
		file->header.data = (void *)realloc(file->header.data, len);
	}
	memcpy(file->header.data, buf, len);
	file->header.size = len;
}

void filemgr_close(struct filemgr *file)
{
	if (global_config.ncacheblock > 0) {
		bcache_flush(file);
	}

	if (file->header.size > 0 && file->header.data) {
		uint16_t header_len = file->header.size;
		uint32_t magic = FILEMGR_MAGIC;
		file->ops->pwrite(file->fd, file->header.data, header_len, file->pos);
		file->ops->pwrite(file->fd, &header_len, sizeof(header_len), file->pos + header_len);
		file->ops->pwrite(file->fd, &magic, sizeof(magic), file->pos + header_len + sizeof(header_len));
		free(file->header.data);
	}

	file->ops->close(file->fd);
	hash_remove(&hash, &file->e);
	hash_free(&file->wal->hash);
	free(file->wal);
	free(file->filename);
	free(file);
}

void _filemgr_free_func(struct hash_elem *h)
{
	struct filemgr *file = _get_entry(h, struct filemgr, e);
	filemgr_close(file);
}

void filemgr_free()
{
	spin_lock(&initial_lock);

	hash_free_active(&hash, _filemgr_free_func);
	bcache_free();
	filemgr_initialized = 0;
	
	spin_unlock(&initial_lock);
}

bid_t filemgr_get_next_alloc_block(struct filemgr *file)
{
	bid_t bid = file->pos / file->blocksize;
	return bid;
}

bid_t filemgr_alloc(struct filemgr *file)
{
	spin_lock(&file->lock);
	bid_t bid = file->pos / file->blocksize;
	file->pos += file->blocksize;
	spin_unlock(&file->lock);
	
	return bid;
}

void filemgr_alloc_multiple(struct filemgr *file, int nblock, bid_t *begin, bid_t *end)
{
	spin_lock(&file->lock);
	*begin = file->pos / file->blocksize;
	*end = *begin + nblock - 1;
	file->pos += file->blocksize * nblock;
	spin_unlock(&file->lock);
}

void filemgr_read(struct filemgr *file, bid_t bid, void *buf)
{
	uint64_t pos = bid * file->blocksize;
	assert(pos < file->pos);

	if (global_config.ncacheblock > 0) {
		int r = 	bcache_read(file, bid, buf);
		if (r == 0) 	{
			file->ops->pread(file->fd, buf, file->blocksize, pos);
			bcache_write(file, bid, buf, BCACHE_CLEAN);
		}
	}else{	
		file->ops->pread(file->fd, buf, file->blocksize, pos);
	}
}

void filemgr_write_offset(struct filemgr *file, bid_t bid, uint64_t offset, uint64_t len, void *buf)
{
	uint64_t pos = bid * file->blocksize + offset;
	assert(pos >= file->last_commit);

	if (global_config.ncacheblock > 0) {
		if (len == file->blocksize) {
			// write entire block .. we don't need to read previous block
			bcache_write(file, bid, buf, BCACHE_DIRTY);
		}else {
			// write partially .. we have to read previous contents of the block
			#ifdef __MEMORY_ALIGN
				void *_buf = temp_buf[0];
			#else
				uint8_t _buf[file->blocksize];
			#endif
	
			int r = bcache_read(file, bid, _buf);
			memcpy(_buf + offset, buf, len);
			bcache_write(file, bid, _buf, BCACHE_DIRTY);
		}
	}else{
		file->ops->pwrite(file->fd, buf, len, pos);
	}
}

void filemgr_write(struct filemgr *file, bid_t bid, void *buf)
{
	filemgr_write_offset(file, bid, 0, file->blocksize, buf);
}

int filemgr_is_writable(struct filemgr *file, bid_t bid)
{
	uint64_t pos = bid * file->blocksize;
	return (pos >= file->last_commit && pos < file->pos);
}

void filemgr_remove_from_cache(struct filemgr *file)
{
	if (global_config.ncacheblock > 0) {
		bcache_remove_file(file);
	}
}

void filemgr_commit(struct filemgr *file)
{

	if (global_config.ncacheblock > 0) {
		bcache_flush(file);
	}
	
	DBGCMD(
		struct timeval _a_,_b_,_r_;
		gettimeofday(&_a_, NULL);
	)

	#ifndef __O_DIRECT
		file->ops->fdatasync(file->fd);
	#endif

	DBGCMD(
		gettimeofday(&_b_, NULL);
		_r_ = _utime_gap(_a_,_b_);
	)
	DBG("fdatasync, %"_FSEC".%06"_FUSEC" sec elapsed.\n", 
		_r_.tv_sec, _r_.tv_usec);

	// race condition?
	file->last_commit = file->pos;
}


