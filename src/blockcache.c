/*
 * Copyright 2013 Jung-Sang Ahn <jungsang.ahn@gmail.com>.
 * All Rights Reserved.
 */

#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "hash_functions.h"
#include "common.h"
#include "hash.h"
#include "list.h"
#include "rbwrap.h"
#include "blockcache.h"

//#define __DEBUG_BCACHE
#ifdef __DEBUG
#ifndef __DEBUG_BCACHE
	#undef DBG
	#undef DBGCMD
	#define DBG(args...)
	#define DBGCMD(command...)

	static uint64_t _read_miss, _read_hit, _write_miss, _write_hit, _evict;
#endif
#endif

// MUST BE a power of 2
#define NBUCKET (65536)
#define NDICBUCKET (4096)

static struct list freelist;
static struct list cleanlist;
static struct list dirtylist;
static struct hash hash;
static struct hash fnamedic;
static int bcache_blocksize;


struct fnamedic_item {
	char *filename;
	uint32_t hash;
	struct filemgr *curfile;
	struct bcache_item *lastitem;	// caching purpose
	struct hash_elem hash_elem;
};

struct bcache_item {
	bid_t bid;
	void *addr;
	struct fnamedic_item *fname;
	struct list *list;
	struct hash_elem hash_elem;
	struct list_elem list_elem;
};

static struct hash_elem *fname_cache = NULL;

INLINE uint32_t _fname_hash(struct hash *hash, struct hash_elem *e)
{
	struct fnamedic_item *item = _get_entry(e, struct fnamedic_item, hash_elem);
	int len = strlen(item->filename);
	int offset = MIN(len, 8);
	return hash_djb2(item->filename + (len - offset), offset) & ((unsigned)(NDICBUCKET-1));
}

INLINE int _fname_cmp(struct hash_elem *a, struct hash_elem *b) 
{
	struct fnamedic_item *aa, *bb;
	aa = _get_entry(a, struct fnamedic_item, hash_elem);
	bb = _get_entry(b, struct fnamedic_item, hash_elem);
	return strcmp(aa->filename, bb->filename);
}

INLINE uint32_t _bcache_hash(struct hash *hash, struct hash_elem *e)
{
	struct bcache_item *item = _get_entry(e, struct bcache_item, hash_elem);
	//return hash_shuffle_2uint(item->bid, item->fname->hash) & (NBUCKET-1); 
	return (item->bid + item->fname->hash) & (NBUCKET-1);
}

INLINE int _bcache_cmp(struct hash_elem *a, struct hash_elem *b)
{
	int rvalue_map[3] = {-1, 0, 1};
	int cmp_fname;
	struct bcache_item *aa, *bb;
	aa = _get_entry(a, struct bcache_item, hash_elem);
	bb = _get_entry(b, struct bcache_item, hash_elem);

	rvalue_map[1] = _CMP_U64(aa->bid, bb->bid);
	
/*
	if (aa->fname == bb->fname) {
		if (aa->bid == bb->bid) return 0;
		else if (aa->bid < bb->bid) return -1;
		else return 1;
	}else if (aa->fname < bb->fname) return -1;
	else return 1;*/

	#ifdef __BIT_CMP
		cmp_fname = _CMP_U64((uint64_t)aa->fname, (uint64_t)bb->fname);
		cmp_fname = _MAP(cmp_fname) + 1;
		return rvalue_map[cmp_fname];

	#else
		if (aa->fname < bb->fname) return -1;
		else if (aa->fname > bb->fname) return 1;
		else {
			if (aa->bid == bb->bid) return 0;
			else if (aa->bid < bb->bid) return -1;
			else return 1;
		}
		
	#endif

}

int bcache_read(struct filemgr *file, bid_t bid, void *buf)
{
	struct hash_elem *h;
	struct bcache_item *item;
	struct bcache_item query;
	struct fnamedic_item fname;

	// lookup filename first
	fname.filename = file->filename;
	h = hash_find(&fnamedic, &fname.hash_elem);

	if (h) {
		query.bid = bid;
		query.fname = _get_entry(h, struct fnamedic_item, hash_elem);
		query.fname->curfile = file;

		h = NULL;
		if (query.fname->lastitem) {
			if (query.bid == query.fname->lastitem->bid) {
				h = &query.fname->lastitem->hash_elem;
			}
		}
		if (h == NULL) {
			h = hash_find(&hash, &query.hash_elem);
		}

		if (h) {
			item = _get_entry(h, struct bcache_item, hash_elem);
			//DBG("bcache_read hit file %s bid %"_F64" in %s\n", file->filename, bid, (item->list==&dirtylist)?"dirtylist":"cleanlist");
			memcpy(buf, item->addr, bcache_blocksize);

			list_remove(item->list, &item->list_elem);
			list_push_front(item->list, &item->list_elem);

			query.fname->lastitem = item;

			return bcache_blocksize;
		}
	}

	//DBG("bcache_read miss file %s bid %"_F64"\n", file->filename, bid);
	return 0;
}

struct list_elem * _bcache_evict(struct filemgr *file)
{
	struct list_elem *e;
	struct bcache_item *item;
	struct hash_elem *h;
	struct fnamedic_item query, *fname_item = NULL;

	e = list_pop_back(&cleanlist);

	if (e == NULL) {
		// no item in clean list			
		e = list_pop_back(&dirtylist);
		item = _get_entry(e, struct bcache_item, list_elem);

		assert(item->fname);
		assert(item->fname->curfile); // dirtyblock from closed file must not exist
		
		item->fname->curfile->ops->pwrite(
			item->fname->curfile->fd, item->addr, item->fname->curfile->blocksize, 
			item->bid * item->fname->curfile->blocksize);
	}

	item = _get_entry(e, struct bcache_item, list_elem);
	if (fname_item) {
		if (fname_item->lastitem == item) fname_item->lastitem = NULL;
	}

	hash_remove(&hash, &item->hash_elem);
	item->list = &freelist;
	list_push_back(item->list, &item->list_elem);

	return &item->list_elem;
}

int bcache_write(struct filemgr *file, bid_t bid, void *buf, int dirty)
{
	struct hash_elem *h;
	struct list_elem *e;
	struct bcache_item *item;
	struct bcache_item query;
	struct fnamedic_item fname, *fname_new;

	// lookup filename first
	fname.filename = file->filename;
	h = hash_find(&fnamedic, &fname.hash_elem);

	if (h == NULL) {
		int len = strlen(file->filename);
		fname_new = (struct fnamedic_item *)malloc(sizeof(struct fnamedic_item));
		fname_new->filename = (char *)malloc(len+1);
		strcpy(fname_new->filename, file->filename);
		fname_new->hash = hash_djb2(fname_new->filename + len, len);
		fname_new->lastitem = NULL;

		hash_insert(&fnamedic, &fname_new->hash_elem);
		h = &fname_new->hash_elem;
	}

	query.bid = bid;
	query.fname = _get_entry(h, struct fnamedic_item, hash_elem);
	query.fname->curfile = file;

	h = NULL;
	if (query.fname->lastitem) {
		if (query.bid == query.fname->lastitem->bid) {
			h = &query.fname->lastitem->hash_elem;
		}
	}
	if (h == NULL) {
		h = hash_find(&hash, &query.hash_elem);
	}

	if (h == NULL) {
		// cache miss
		e = list_begin(&freelist);
		if (e == NULL) 
			e = _bcache_evict(file);
		
		item = _get_entry(e, struct bcache_item, list_elem);
		item->bid = bid;
		item->fname = query.fname;
		hash_insert(&hash, &item->hash_elem);
		
	}else{
		item = _get_entry(h, struct bcache_item, hash_elem);
	}
	
	memcpy(item->addr, buf, bcache_blocksize);

	list_remove(item->list, &item->list_elem);

	if (dirty) item->list = &dirtylist;
	else item->list = &cleanlist;
	
	list_push_front(item->list, &item->list_elem);
	query.fname->lastitem = item;

	return bcache_blocksize;
}

//#define _BCACHE_SORTED_FLUSH
#ifdef _BCACHE_SORTED_FLUSH

struct bcache_rb {
	struct bcache_item *item;
	struct rb_node rb;
	struct list_elem e;
};

int _bcache_rb_cmp(struct rb_node *a, struct rb_node *b)
{
	struct bcache_rb *aa, *bb;
	aa = _get_entry(a, struct bcache_rb, rb);
	bb = _get_entry(b, struct bcache_rb, rb);
	if (aa->item->bid < bb->item->bid) return -1;
	else if (aa->item->bid > bb->item->bid) return 1;
	else return 0;
}

#endif

void bcache_flush(struct filemgr *file)
{
	struct hash_elem *h;
	struct list_elem *e;
	struct bcache_item *item;
#ifdef _BCACHE_SORTED_FLUSH
	struct list flushlist;
	struct rb_node *r;
	struct rb_root root;
	struct bcache_rb *rb;
#endif
	struct fnamedic_item fname, *fname_item;

	// lookup filename first
	fname.filename = file->filename;
	h = hash_find(&fnamedic, &fname.hash_elem);

	if (h) {
		// file exists
		fname_item = _get_entry(h, struct fnamedic_item, hash_elem);
		
	#ifdef _BCACHE_SORTED_FLUSH
		rbwrap_init(&root);
		list_init(&flushlist);
	#endif
		
		e = list_begin(&dirtylist);
		while(e){
			item = _get_entry(e, struct bcache_item, list_elem);

			if (item->fname == fname_item) {
				e = list_remove(&dirtylist, e);

			#ifdef _BCACHE_SORTED_FLUSH
				rb = (struct bcache_rb *)malloc(sizeof(struct bcache_rb));
				rb->item = item;
				rbwrap_insert(&root, &rb->rb, _bcache_rb_cmp);
				list_push_front(&flushlist, &rb->e);
			#else
				file->ops->pwrite(file->fd, item->addr, file->blocksize, item->bid * file->blocksize);	
			#endif

				item->list = &cleanlist;
				list_push_front(item->list, &item->list_elem);
			}
		}

	#ifdef _BCACHE_SORTED_FLUSH
		r = rb_first(&root);
		while(r) {
			rb = _get_entry(r, struct bcache_rb, rb);
			r = rb_next(r);
	
			file->ops->pwrite(file->fd, rb->item->addr, file->blocksize, rb->item->bid * file->blocksize);
		}
		e = list_begin(&flushlist);
		while(e) {
			rb = _get_entry(e, struct bcache_rb, e);
			e = list_remove(&flushlist, e);
			free(rb);
		}
	#endif

		fname_item->curfile = NULL;
	}
}

void bcache_init(int nblock, int blocksize)
{
	DBGCMD(
		struct timeval a,b,r;
		gettimeofday(&a, NULL);
	)

	int i;
	struct bcache_item *item;

	list_init(&freelist);
	list_init(&cleanlist);
	list_init(&dirtylist);
	hash_init(&hash, NBUCKET, _bcache_hash, _bcache_cmp);
	hash_init(&fnamedic, NDICBUCKET, _fname_hash, _fname_cmp);
	bcache_blocksize = blocksize;

	for (i=0;i<nblock;++i){
		item = (struct bcache_item *)malloc(sizeof(struct bcache_item));
		item->addr = malloc(blocksize);
		item->bid = BLK_NOT_FOUND;
		item->list = &freelist;
		item->fname = NULL;

		list_push_front(item->list, &item->list_elem);
		//hash_insert(&hash, &item->hash_elem);
	}

	DBGCMD(
		gettimeofday(&b, NULL);
		r = _utime_gap(a,b);
	)
	DBG("bcache init. %d * %d bytes blocks, %"_FSEC".%06"_FUSEC" sec elapsed.\n", nblock, blocksize, r.tv_sec, r.tv_usec);
}

void _bcache_free_bcache_item(struct hash_elem *h)
{
	struct bcache_item *item = _get_entry(h, struct bcache_item, hash_elem);
	free(item->addr);
	free(item);
}

void _bcache_free_fnamedic(struct hash_elem *h)
{
	struct fnamedic_item *item = _get_entry(h, struct fnamedic_item, hash_elem);
	free(item->filename);
	free(item);
}

void __bcache_check_bucket_length()
{
	struct list_elem *e;
	int i,c;
	FILE *fp = fopen("./bcache_hash_log.txt","w");
	for (i=0;i<hash.nbuckets;++i) {
		c=0;
		e = list_begin(hash.buckets + i);
		while(e) {
			c++;
			e = list_next(e);
		}
		if (c>0)
			fprintf(fp, "%d %d\n",i,c);
	}
	fclose(fp);
}

void bcache_free()
{
	struct bcache_item *item;
	struct list_elem *e;

	//__bcache_check_bucket_length();

	e = list_begin(&freelist);
	while(e) {
		item = _get_entry(e, struct bcache_item, list_elem);
		e = list_remove(&freelist, e);
		free(item->addr);
		free(item);
	}
	hash_free_active(&hash, _bcache_free_bcache_item);
	hash_free_active(&fnamedic, _bcache_free_fnamedic);
}

