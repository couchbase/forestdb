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

#ifdef __DEBUG
#ifndef __DEBUG_BCACHE
    #undef DBG
    #undef DBGCMD
    #define DBG(args...)
    #define DBGCMD(command...)
#else
    static uint64_t _dirty = 0;
#endif
#endif


static struct list freelist;
static struct list cleanlist;
static struct list dirtylist;

// hash table for lookup blocks using their BID
static struct hash hash;
// hash table for filename
static struct hash fnamedic;

static int bcache_blocksize;
static size_t bcache_flush_unit;
static size_t bcache_sys_pagesize;

//uint8_t global_buf[BCACHE_FLUSH_UNIT];
void *global_buf;

struct fnamedic_item {
    char *filename;
    uint16_t filename_len;
    
    uint32_t hash;

    // current opened filemgr instance (can be changed on-the-fly when file is closed and re-opened)
    struct filemgr *curfile;
    // cache last accessed bcache_item (if hit, we can bypass hash retrieval)
    struct bcache_item *lastitem;
    struct hash_elem hash_elem;
    struct rb_root rbtree;
};

struct bcache_item {
    // BID
    bid_t bid;
    // contents address
    void *addr;
    struct fnamedic_item *fname;
    // pointer of the list to which this item belongs
    struct list *list;
    // hash elem for lookup hash table
    struct hash_elem hash_elem;
    // list elem for {free, clean, dirty} lists
    struct list_elem list_elem;
};

struct dirty_item {
    struct bcache_item *item;
    struct rb_node rb;
};

static struct hash_elem *fname_cache = NULL;

INLINE int _dirty_cmp(struct rb_node *a, struct rb_node *b, void *aux)
{
    struct dirty_item *aa, *bb;
    aa = _get_entry(a, struct dirty_item, rb);
    bb = _get_entry(b, struct dirty_item, rb);
    
    #ifdef __BIT_CMP
        return _CMP_U64(aa->item->bid , bb->item->bid);
    
    #else
        if (aa->item->bid < bb->item->bid) return -1;
        else if (aa->item->bid > bb->item->bid) return 1;
        else return 0;
    
    #endif
}

INLINE uint32_t _fname_hash(struct hash *hash, struct hash_elem *e)
{
    struct fnamedic_item *item = _get_entry(e, struct fnamedic_item, hash_elem);
    //int len = strlen(item->filename);
    int len = item->filename_len;
    int offset = MIN(len, 8);
    return hash_djb2(item->filename + (len - offset), offset) & ((unsigned)(BCACHE_NDICBUCKET-1));
}

INLINE int _fname_cmp(struct hash_elem *a, struct hash_elem *b) 
{
    size_t len;
    struct fnamedic_item *aa, *bb;
    aa = _get_entry(a, struct fnamedic_item, hash_elem);
    bb = _get_entry(b, struct fnamedic_item, hash_elem);


    if (aa->filename_len == bb->filename_len) return memcmp(aa->filename, bb->filename, aa->filename_len);
    else {
        len = MIN(aa->filename_len , bb->filename_len);
        int cmp = memcmp(aa->filename, bb->filename, len);
        if (cmp != 0) return cmp;
        else {
            return (aa->filename_len - bb->filename_len);
        }
    }
/*
    if (aa->filename_len != bb->filename_len) return ((int)aa->filename_len - (int)bb->filename_len);
    else return memcmp(aa->filename, bb->filename, aa->filename_len);*/
}

INLINE uint32_t _bcache_hash(struct hash *hash, struct hash_elem *e)
{
    struct bcache_item *item = _get_entry(e, struct bcache_item, hash_elem);
    //return hash_shuffle_2uint(item->bid, item->fname->hash) & (BCACHE_NBUCKET-1); 
    //return (item->bid + item->fname->hash) & ((uint32_t)BCACHE_NBUCKET-1);
    return (item->bid) & ((uint32_t)BCACHE_NBUCKET-1);
}

INLINE int _bcache_cmp(struct hash_elem *a, struct hash_elem *b)
{
    #ifdef __BIT_CMP
        int rvalue_map[3] = {-1, 0, 1};
        int cmp_fname;
    #endif
    
    struct bcache_item *aa, *bb;
    aa = _get_entry(a, struct bcache_item, hash_elem);
    bb = _get_entry(b, struct bcache_item, hash_elem);

    #ifdef __BIT_CMP
        rvalue_map[1] = _CMP_U64(aa->bid, bb->bid);
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

void __bcache_check_bucket_length()
{
    #ifdef _HASH_RBTREE
    #else
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
    fname.filename_len = file->filename_len;
    h = hash_find(&fnamedic, &fname.hash_elem);

    if (h) {
        // file exists
        query.bid = bid;
        query.fname = _get_entry(h, struct fnamedic_item, hash_elem);
        query.fname->curfile = file;

        h = NULL;
        if (query.fname->lastitem) {
            if (query.bid == query.fname->lastitem->bid) {
                // if BID is same as that of the last accessed block
                // directly get hash_elem without retrieving hash table
                h = &query.fname->lastitem->hash_elem;
            }
        }
        if (h == NULL) {
            h = hash_find(&hash, &query.hash_elem);
        }

        if (h) {
            item = _get_entry(h, struct bcache_item, hash_elem);
            memcpy(buf, item->addr, bcache_blocksize);

            // move the item at the head of the list (LRU)
            list_remove(item->list, &item->list_elem);
            list_push_front(item->list, &item->list_elem);

            // set lastitem
            query.fname->lastitem = item;

            return bcache_blocksize;
        }
    }

    // does not exist .. cache miss
    return 0;
}

void _bcache_evict_dirty(struct fnamedic_item *fname_item, int sync)
{
    // get oldest dirty block
    void *buf;
    struct list_elem *e;
    struct rb_node *r;
    struct dirty_item *ditem;
    int count, ret;
    bid_t start_bid, prev_bid;

    // scan and gather rb-tree items sequentially
    if (sync) {
        #ifdef __MEMORY_ALIGN
            ret = posix_memalign(&buf, bcache_sys_pagesize, bcache_flush_unit);
            //buf = global_buf;
        #else
            buf = (void *)malloc(bcache_flush_unit);
        #endif
        //assert(ret == 0);
    }
    
    prev_bid = start_bid = BLK_NOT_FOUND;
    count = 0;
    
    r = rb_first(&fname_item->rbtree);
    while(r) {
        ditem = _get_entry(r, struct dirty_item, rb);
        // if BID of next dirty block is not consecutive .. stop
        if (ditem->item->bid != prev_bid + 1 && prev_bid != BLK_NOT_FOUND && sync) break;
        if (start_bid == BLK_NOT_FOUND) start_bid = ditem->item->bid;

        prev_bid = ditem->item->bid;
        r = rb_next(r);

        // remove from rb-tree
        rb_erase(&ditem->rb, &fname_item->rbtree);
        // remove from dirtylist
        list_remove(ditem->item->list, &ditem->item->list_elem);

        if (sync)
            memcpy(buf + count*bcache_blocksize, ditem->item->addr, bcache_blocksize);

        // insert into cleanlist
        ditem->item->list = &cleanlist;
        list_push_front(ditem->item->list, &ditem->item->list_elem);
        count++;

        DBGCMD(_dirty--);
        mempool_free(ditem);
        
        if (count*bcache_blocksize >= bcache_flush_unit && sync) break;        

        //r = rb_first(&fname_item->rbtree);
    }

    // synchronize
    if (sync) {
        ret = fname_item->curfile->ops->pwrite(
            fname_item->curfile->fd, buf, count * bcache_blocksize, start_bid * bcache_blocksize);    
        assert(ret != 0);
        free(buf);
    }
}

struct list_elem * _bcache_evict(struct filemgr *file)
{
    struct list_elem *e;
    struct bcache_item *item;
    struct hash_elem *h;
    struct fnamedic_item query, *fname_item = NULL;

    // evict clean block
    e = list_pop_back(&cleanlist);

    if (e == NULL) {
        // when there is no item in clean list .. evict dirty block
        e = list_end(&dirtylist);
        item = _get_entry(e, struct bcache_item, list_elem);
        
        _bcache_evict_dirty(item->fname, 1);
        
        e = list_pop_back(&cleanlist);

    }

    item = _get_entry(e, struct bcache_item, list_elem);
    fname_item = item->fname;
    
    if (fname_item) {
        // clear the last accessed block if hit
        if (fname_item->lastitem == item) fname_item->lastitem = NULL;
    }

    // remove from hash and insert into freelist
    hash_remove(&hash, &item->hash_elem);
    item->list = &freelist;
    list_push_back(item->list, &item->list_elem);

    return &item->list_elem;
}

struct fnamedic_item * _fname_create(struct filemgr *file) {
    struct fnamedic_item *fname_new;
    fname_new = (struct fnamedic_item *)malloc(sizeof(struct fnamedic_item));

    fname_new->filename_len = strlen(file->filename);
    fname_new->filename = (char *)malloc(fname_new->filename_len + 1);
    //memcpy(fname_new->filename, file->filename, fname_new->filename_len);
    strcpy(fname_new->filename, file->filename);
    fname_new->filename[fname_new->filename_len] = 0;

    // calculate hash value
    fname_new->hash = hash_djb2(
        fname_new->filename + fname_new->filename_len, fname_new->filename_len);
    fname_new->lastitem = NULL;

    // initialize rb-tree
    rbwrap_init(&fname_new->rbtree, NULL);

    // insert into fname dictionary
    hash_insert(&fnamedic, &fname_new->hash_elem);

    return fname_new;    
}

void _fname_free(struct fnamedic_item *fname)
{
    struct rb_node *r;
    struct dirty_item *item;
    
    // remove from fname dictionary hash table
    hash_remove(&fnamedic, &fname->hash_elem);

    // remove all associated rbtree nodes;
    r = rb_first(&fname->rbtree);
    while(r) {
        item = _get_entry(r, struct dirty_item, rb);
        r = rb_next(r);
        rb_erase(&item->rb, &fname->rbtree);
        free(item);
    }

    free(fname->filename);
    free(fname);
}

int bcache_write(struct filemgr *file, bid_t bid, void *buf, bcache_dirty_t dirty)
{
    struct hash_elem *h;
    struct list_elem *e;
    struct bcache_item *item;
    struct bcache_item query;
    struct fnamedic_item fname, *fname_new;

    // lookup filename first
    fname.filename = file->filename;
    fname.filename_len = file->filename_len;
    h = hash_find(&fnamedic, &fname.hash_elem);

    if (h == NULL) {
        // filename doesn't exist in filename dictionary .. create
        fname_new = _fname_create(file);
        h = &fname_new->hash_elem;
    }

    query.bid = bid;
    query.fname = _get_entry(h, struct fnamedic_item, hash_elem);
    query.fname->curfile = file;

    h = NULL;
    if (query.fname->lastitem) {
        if (query.bid == query.fname->lastitem->bid) {
            // hit last accessed BID
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

    if (dirty == BCACHE_DIRTY) {
        if (item->list != &dirtylist) {
            struct dirty_item *ditem;

            item->list = &dirtylist;
            DBGCMD(_dirty++;)
                
            ditem = (struct dirty_item *)mempool_alloc(sizeof(struct dirty_item));
            ditem->item = item;
            rbwrap_insert(&item->fname->rbtree, &ditem->rb, _dirty_cmp);
        }
    }else{ 
        item->list = &cleanlist;
    }
    
    list_push_front(item->list, &item->list_elem);
    query.fname->lastitem = item;

    return bcache_blocksize;
}

// remove all dirty blocks of the FILE (they are only removed and not written back)
void bcache_remove_file(struct filemgr *file)
{
    struct hash_elem *h;
    struct list_elem *e;
    struct bcache_item *item;
    struct fnamedic_item fname, *fname_item;
    DBGCMD(
        struct timeval _a_,_b_,_rr_;
        gettimeofday(&_a_, NULL);
        size_t total=0, count=0;
    );

    // lookup filename first
    fname.filename = file->filename;
    fname.filename_len = file->filename_len;
    h = hash_find(&fnamedic, &fname.hash_elem);

    if (h) {
        // file exists
        fname_item = _get_entry(h, struct fnamedic_item, hash_elem);

        while(rb_first(&fname_item->rbtree)) {    
            _bcache_evict_dirty(fname_item, 0);
        }

        // remove from hash table and memory
        _fname_free(fname_item);
    }

    DBGCMD(
        gettimeofday(&_b_, NULL);
        _rr_ = _utime_gap(_a_,_b_);        
    );
    DBG("bcache_remove_file %s, total %"_F64" count %"_F64", %"_FSEC".%06"_FUSEC" sec elapsed.\n", 
        file->filename, total, count, _rr_.tv_sec, _rr_.tv_usec);

}

// flush and sycnrhonize all dirty blocks of the FILE
void bcache_flush(struct filemgr *file)
{
    struct hash_elem *h;
    struct list_elem *e;
    struct bcache_item *item;
    struct fnamedic_item fname, *fname_item;
    DBGCMD(
        struct timeval _a_,_b_,_rr_;
        gettimeofday(&_a_, NULL);
        size_t total=0, count=0;
    );

    //DBGCMD( __bcache_check_bucket_length() );

    // lookup filename first
    fname.filename = file->filename;
    fname.filename_len = file->filename_len;
    h = hash_find(&fnamedic, &fname.hash_elem);

    if (h) {
        // file exists
        fname_item = _get_entry(h, struct fnamedic_item, hash_elem);

        while(rb_first(&fname_item->rbtree)) {    
            _bcache_evict_dirty(fname_item, 1);
        }

        fname_item->curfile = NULL;
    }

    DBGCMD(
        gettimeofday(&_b_, NULL);
        _rr_ = _utime_gap(_a_,_b_);        
    );
    
    DBG("bcache_flush file %s, total %"_F64" count %"_F64", %"_FSEC".%06"_FUSEC" sec elapsed.\n", 
        file->filename, total, count, _rr_.tv_sec, _rr_.tv_usec);
}

void bcache_init(int nblock, int blocksize)
{
    DBGCMD(
        struct timeval _a_,_b_,_r_;
        gettimeofday(&_a_, NULL);
    )

    int i, ret;
    struct bcache_item *item;

    list_init(&freelist);
    list_init(&cleanlist);
    list_init(&dirtylist);
    hash_init(&hash, BCACHE_NBUCKET, _bcache_hash, _bcache_cmp);
    hash_init(&fnamedic, BCACHE_NDICBUCKET, _fname_hash, _fname_cmp);
    
    bcache_blocksize = blocksize;
    bcache_flush_unit = BCACHE_FLUSH_UNIT;
    bcache_sys_pagesize = sysconf(_SC_PAGESIZE);

    DBG("kernel page size %"_F64"\n", bcache_sys_pagesize);

    for (i=0;i<nblock;++i){
        item = (struct bcache_item *)malloc(sizeof(struct bcache_item));
        #ifdef __MEMORY_ALIGN
            ret = posix_memalign(&item->addr, bcache_sys_pagesize, blocksize);
        #else
            item->addr = (void *)malloc(blocksize);
        #endif
        
        item->bid = BLK_NOT_FOUND;
        item->list = &freelist;
        item->fname = NULL;

        list_push_front(item->list, &item->list_elem);
        //hash_insert(&hash, &item->hash_elem);
    }

    ret = posix_memalign(&global_buf, bcache_sys_pagesize, BCACHE_FLUSH_UNIT);

    DBGCMD(
        gettimeofday(&_b_, NULL);
        _r_ = _utime_gap(_a_,_b_);
    );
    DBG("bcache init. %d * %d bytes blocks, %"_FSEC".%06"_FUSEC" sec elapsed.\n", 
        nblock, blocksize, _r_.tv_sec, _r_.tv_usec);
}

INLINE void _bcache_free_bcache_item(struct hash_elem *h)
{
    struct bcache_item *item = _get_entry(h, struct bcache_item, hash_elem);
    free(item->addr);
    free(item);
}

INLINE void _bcache_free_fnamedic(struct hash_elem *h)
{
    struct fnamedic_item *item = _get_entry(h, struct fnamedic_item, hash_elem);
    free(item->filename);
    free(item);
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

