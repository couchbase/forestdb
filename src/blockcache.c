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
#include "crc32.h"

#ifdef __DEBUG
#ifndef __DEBUG_BCACHE
    #undef DBG
    #undef DBGCMD
    #undef DBGSW
    #define DBG(args...)
    #define DBGCMD(command...)
    #define DBGSW(n, command...) 
#endif
static uint64_t _dirty = 0;
#endif

static struct list freelist;
static struct list cleanlist;
static struct list dirtylist;
static uint64_t nfree, nclean, ndirty;
static uint64_t bcache_nblock;

// hash table for lookup blocks using their BID
static struct hash bhash;
// hash table for filename
static struct hash fnamedic;

static int bcache_blocksize;
static size_t bcache_flush_unit;
static size_t bcache_sys_pagesize;

struct fnamedic_item {
    char *filename;
    uint16_t filename_len;
    uint32_t hash;
    //file_status_t status;

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

#ifdef __DEBUG
uint64_t _gn(struct list *list)
{
    uint64_t c = 0;
    struct list_elem *e;
    e = list_begin(list);
    while(e) {
        c++;
        e = list_next(e);
    }
    return c;
}
void _pl(struct list *list, uint64_t begin, uint64_t n)
{
    uint64_t c = 0;
    struct list_elem *e;
    struct bcache_item *item;
    char fname_buf[256];
    uint8_t marker;
    
    e = list_begin(list);
    while(e) {
        if (begin <= c && c < begin+n) {
            item = _get_entry(e, struct bcache_item, list_elem);
            memcpy(fname_buf, item->fname->filename, item->fname->filename_len);
            fname_buf[item->fname->filename_len] = 0;
            memcpy(&marker, item->addr + 4095, 1);
            printf("#%"_F64": BID %"_F64", marker 0x%x, file %s\n", c, item->bid, marker, fname_buf);
        }
        c++;
        e = list_next(e);
    }
}
#endif

INLINE void _bcache_count(struct list *list, int delta)
{
    if (list == &cleanlist) nclean += delta;
    else if (list == &dirtylist) ndirty += delta;
    else if (list == &freelist) nfree += delta;
    else assert(0);
}

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
    //int len = item->filename_len;
    //int offset = MIN(len, 8);
    return item->hash & ((unsigned)(BCACHE_NDICBUCKET-1));
    //return hash_djb2(item->filename + (len - offset), offset) & ((unsigned)(BCACHE_NDICBUCKET-1));
    //return crc32_8(item->filename + (len - offset), offset, 0) & ((unsigned)(BCACHE_NDICBUCKET-1));
}

INLINE int _fname_cmp(struct hash_elem *a, struct hash_elem *b) 
{
    size_t len;
    struct fnamedic_item *aa, *bb;
    aa = _get_entry(a, struct fnamedic_item, hash_elem);
    bb = _get_entry(b, struct fnamedic_item, hash_elem);


    if (aa->filename_len == bb->filename_len) {
        return memcmp(aa->filename, bb->filename, aa->filename_len);
    }else {
        len = MIN(aa->filename_len , bb->filename_len);
        int cmp = memcmp(aa->filename, bb->filename, len);
        if (cmp != 0) return cmp;
        else {
            return (int)((int)aa->filename_len - (int)bb->filename_len);
        }
    }
}

INLINE uint32_t _bcache_hash(struct hash *hash, struct hash_elem *e)
{
    struct bcache_item *item = _get_entry(e, struct bcache_item, hash_elem);
    //return hash_shuffle_2uint(item->bid, item->fname->hash) & (BCACHE_NBUCKET-1); 
    return (item->bid + item->fname->hash) & ((uint32_t)BCACHE_NBUCKET-1);
    //return (item->bid) & ((uint32_t)BCACHE_NBUCKET-1);
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
        cmp_fname = _CMP_U64((uint64_t)aa->fname->hash, (uint64_t)bb->fname->hash);
        cmp_fname = _MAP(cmp_fname) + 1;
        return rvalue_map[cmp_fname];

    #else

        if (aa->fname->hash < bb->fname->hash) return -1;
        else if (aa->fname->hash > bb->fname->hash) return 1;
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
        for (i=0;i<bhash.nbuckets;++i) {
            c=0;
            e = list_begin(bhash.buckets + i);
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

INLINE void _file_to_fname_query(struct filemgr *file, struct fnamedic_item *fname)
{
    fname->filename = file->filename;
    fname->filename_len = file->filename_len;
    //fname.hash = hash_djb2_last8(fname.filename, fname.filename_len);
    fname->hash = crc32_8_last8(fname->filename, fname->filename_len, 0);
}

int bcache_read(struct filemgr *file, bid_t bid, void *buf)
{
    struct hash_elem *h;
    struct bcache_item *item;
    struct bcache_item query;
    struct fnamedic_item fname;

    // lookup filename first
    _file_to_fname_query(file, &fname);
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
            h = hash_find(&bhash, &query.hash_elem);
        }

        if (h) {
            item = _get_entry(h, struct bcache_item, hash_elem);
            assert(item->fname->curfile == file);
            memcpy(buf, item->addr, bcache_blocksize);

            // move the item at the head of the list (LRU) when the file is not undergoing compaction
            if (item->fname->curfile->status != FILE_COMPACT_OLD) {
                list_remove(item->list, &item->list_elem);
                list_push_front(item->list, &item->list_elem);
            }

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
    void *ptr = NULL;
    uint8_t marker = 0x0;

    // scan and gather rb-tree items sequentially
    if (sync) {
        #ifdef __MEMORY_ALIGN
            ret = posix_memalign(&buf, FDB_SECTOR_SIZE, bcache_flush_unit);
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

        ptr = ditem->item->addr;
        marker = *((uint8_t*)(ptr) + bcache_blocksize-1);

        // remove from rb-tree
        rb_erase(&ditem->rb, &fname_item->rbtree);
        // remove from dirtylist
        list_remove(ditem->item->list, &ditem->item->list_elem);
        _bcache_count(ditem->item->list, -1);

        if (sync) {
            #ifdef __CRC32
                if (marker == BLK_MARKER_BNODE ) {
                    // b-tree node .. calculate crc32 and put it into 8th byte of the block
                    memset(ptr + 8, 0xff, sizeof(void *));
                    uint32_t crc = crc32_8(ptr, bcache_blocksize, 0);
                    memcpy(ptr + 8, &crc, sizeof(crc));
                }
            #endif
            memcpy(buf + count*bcache_blocksize, ditem->item->addr, bcache_blocksize);
        }

        // when the file is undergoing compaction, blocks for documents are discarded
        if ( (sync && fname_item->curfile->status != FILE_COMPACT_OLD) || 
              (sync && fname_item->curfile->status == FILE_COMPACT_OLD && marker == BLK_MARKER_BNODE) ) {
            // insert into cleanlist
            ditem->item->list = &cleanlist;
            list_push_front(ditem->item->list, &ditem->item->list_elem);
            _bcache_count(ditem->item->list, 1);
        }else{
            // not committed dirty blocks of closed file .. just remove?
            if (ditem->item == fname_item->lastitem) {
                fname_item->lastitem = NULL;
            }
            
            hash_remove(&bhash, &ditem->item->hash_elem);
            ditem->item->list = &freelist;
            list_push_front(ditem->item->list, &ditem->item->list_elem);
            _bcache_count(ditem->item->list, 1);
        }
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

        #ifdef __O_DIRECT
            fname_item->curfile->last_commit = (start_bid + count) * bcache_blocksize;
        #endif
    }
}

struct list_elem * _bcache_evict(struct filemgr *file)
{
    struct list_elem *e;
    struct bcache_item *item;
    struct hash_elem *h;
    struct fnamedic_item query, *fname_item = NULL;
    size_t ratio;

    if (ndirty > 0) {
        ratio = nclean / ndirty;
    }else{
        ratio = 0xffffffff;
    }

    if ( ratio >= BCACHE_EVICT_RATIO ) {
        // evict clean block
        e = list_pop_back(&cleanlist);
        if (e == NULL) {
            // when there is no item in clean list .. evict dirty block
            e = list_end(&dirtylist);
            item = _get_entry(e, struct bcache_item, list_elem);

            //if (item->fname->curfile->status != FILE_COMPACT_NEW) {
                _bcache_evict_dirty(item->fname, 1);
            /*}else{
                while(rb_first(&item->fname->rbtree)) {    
                    _bcache_evict_dirty(item->fname, 1);
                }            
            }*/
            e = list_pop_back(&cleanlist);
        }
    }else{
        // directly evict dirty block
        e = list_end(&dirtylist);
        item = _get_entry(e, struct bcache_item, list_elem);
        
        _bcache_evict_dirty(item->fname, 1);
        e = list_pop_back(&cleanlist);
    }

    item = _get_entry(e, struct bcache_item, list_elem);
    _bcache_count(item->list, -1);
    fname_item = item->fname;
    
    if (fname_item) {
        // clear the last accessed block if hit
        if (fname_item->lastitem == item) fname_item->lastitem = NULL;
    }

    // remove from hash and insert into freelist
    hash_remove(&bhash, &item->hash_elem);
    item->list = &freelist;
    list_push_front(item->list, &item->list_elem);
    _bcache_count(item->list, 1);

    return &item->list_elem;
}

struct fnamedic_item * _fname_create(struct filemgr *file) {
    struct fnamedic_item *fname_new;
    fname_new = (struct fnamedic_item *)malloc(sizeof(struct fnamedic_item));

    fname_new->filename_len = strlen(file->filename);
    fname_new->filename = (char *)malloc(fname_new->filename_len + 1);
    memcpy(fname_new->filename, file->filename, fname_new->filename_len);
    //strcpy(fname_new->filename, file->filename);
    fname_new->filename[fname_new->filename_len] = 0;

    // calculate hash value
    //fname_new->hash = hash_djb2_last8(fname_new->filename, fname_new->filename_len);
    fname_new->hash = crc32_8_last8(fname_new->filename, fname_new->filename_len, 0);
    fname_new->lastitem = NULL;
    //fname_new->status = FILE_NORMAL;

    // initialize rb-tree
    rbwrap_init(&fname_new->rbtree, NULL);

    // insert into fname dictionary
    hash_insert(&fnamedic, &fname_new->hash_elem);

    return fname_new;    
}

/*
void bcache_update_file_status(struct filemgr *file, file_status_t status)
{
    struct fnamedic_item fname, *fname_item;
    struct hash_elem *h;

    _file_to_fname_query(file, &fname);
    h = hash_find(&fnamedic, &fname.hash_elem);
    if (h) {
        // already exist
        fname_item = _get_entry(h, struct fnamedic_item, hash_elem);
    }else{
        // create new
        fname_item = _fname_create(file);
    }
    fname_item->status = status;
}*/

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
    uint8_t marker;

    // lookup filename first
    _file_to_fname_query(file, &fname);
    h = hash_find(&fnamedic, &fname.hash_elem);

    if (h == NULL) {
        // filename doesn't exist in filename dictionary .. create
        fname_new = _fname_create(file);
        h = &fname_new->hash_elem;
    }

    query.bid = bid;
    query.fname = _get_entry(h, struct fnamedic_item, hash_elem);
    query.fname->curfile = file;

    DBGCMD(
        if (dirty) {
            struct dirty_item *da, *db;
            struct rb_node *r;
            r = rb_first(&query.fname->rbtree);
            if (r) {
                da = _get_entry(r, struct dirty_item, rb);
                r = rb_last(&query.fname->rbtree);
                db = _get_entry(r, struct dirty_item, rb);
                if (bid+1 < da->item->bid || bid > db->item->bid+1) {
                    DBG("hole ..."); char asdf = getc(stdin);
                    DBG("continue\n");
                }
            }
        }
        );


    h = NULL;
    if (query.fname->lastitem) {
        if (query.bid == query.fname->lastitem->bid) {
            // hit last accessed BID
            h = &query.fname->lastitem->hash_elem;
        }
    }

    if (h == NULL) {
        h = hash_find(&bhash, &query.hash_elem);
    }

    if (h == NULL) {
        // cache miss
        e = list_begin(&freelist);
        if (e == NULL) 
            e = _bcache_evict(file);
        
        item = _get_entry(e, struct bcache_item, list_elem);
        assert(item->list == &freelist);
        item->bid = bid;
        item->fname = query.fname;
        hash_insert(&bhash, &item->hash_elem);
        
    }else{
        item = _get_entry(h, struct bcache_item, hash_elem);
    }

    memcpy(item->addr, buf, bcache_blocksize);

    list_remove(item->list, &item->list_elem);
    _bcache_count(item->list, -1);

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

    marker = *((uint8_t*)(item->addr) + bcache_blocksize-1);
    if ( item->fname->curfile->status != FILE_COMPACT_OLD || 
         (item->fname->curfile->status == FILE_COMPACT_OLD && marker == BLK_MARKER_BNODE) ) {
        list_push_front(item->list, &item->list_elem);
    }else{
        /* size_t count = 0;
        e = list_end(item->list);
        while(e && count < BCACHE_REAR_COUNT) {
            e = list_prev(e);
            count++;
        }
        if (e) {
            list_insert_before(item->list, e, &item->list_elem);
        }else{*/
            list_push_back(item->list, &item->list_elem);
        //}
    }
    _bcache_count(item->list, 1);
    query.fname->lastitem = item;

    return bcache_blocksize;
}

int bcache_write_partial(struct filemgr *file, bid_t bid, void *buf, size_t offset, size_t len)
{
    struct hash_elem *h;
    struct list_elem *e;
    struct bcache_item *item;
    struct bcache_item query;
    struct fnamedic_item fname, *fname_new;
    uint8_t marker;

    // lookup filename first
    _file_to_fname_query(file, &fname);
    h = hash_find(&fnamedic, &fname.hash_elem);

    if (h == NULL) {
        // filename doesn't exist in filename dictionary .. create
        fname_new = _fname_create(file);
        h = &fname_new->hash_elem;
    }

    query.bid = bid;
    query.fname = _get_entry(h, struct fnamedic_item, hash_elem);
    query.fname->curfile = file;
    DBGCMD(
        if (1) {
            struct dirty_item *da, *db;
            struct rb_node *r;
            r = rb_first(&query.fname->rbtree);
            if (r) {
                da = _get_entry(r, struct dirty_item, rb);
                r = rb_last(&query.fname->rbtree);
                db = _get_entry(r, struct dirty_item, rb);
                if (bid+1 < da->item->bid || bid > db->item->bid+1) {
                    DBG("hole ..."); char asdf = getc(stdin);
                    DBG("continue\n");
                }
            }
        }
        );

    h = NULL;
    if (query.fname->lastitem) {
        if (query.bid == query.fname->lastitem->bid) {
            // hit last accessed BID
            h = &query.fname->lastitem->hash_elem;
        }
    }
    if (h == NULL) {
        h = hash_find(&bhash, &query.hash_elem);
    }

    if (h == NULL) {
        // cache miss .. partial write fail .. return 0
        return 0;
        
    }else{
        item = _get_entry(h, struct bcache_item, hash_elem);
    }
    
    memcpy(item->addr + offset, buf, len);

    list_remove(item->list, &item->list_elem);
    _bcache_count(item->list, -1);

    if (item->list != &dirtylist) {
        struct dirty_item *ditem;

        item->list = &dirtylist;
        DBGCMD(_dirty++;)
            
        ditem = (struct dirty_item *)mempool_alloc(sizeof(struct dirty_item));
        ditem->item = item;
        rbwrap_insert(&item->fname->rbtree, &ditem->rb, _dirty_cmp);
    }
    
    marker = *((uint8_t*)(item->addr) + bcache_blocksize-1);
    if ( item->fname->curfile->status != FILE_COMPACT_OLD || 
         (item->fname->curfile->status == FILE_COMPACT_OLD && marker == BLK_MARKER_BNODE) ) {
        list_push_front(item->list, &item->list_elem);
    }else{
        /*size_t count = 0;
        e = list_end(item->list);
        while(e && count < BCACHE_REAR_COUNT) {
            e = list_prev(e);
            count++;
        }
        if (e) {
            list_insert_before(item->list, e, &item->list_elem);
        }else{*/
            list_push_back(item->list, &item->list_elem);
        //}
    }
    _bcache_count(item->list, 1);
    query.fname->lastitem = item;

    return len;
}


// remove all dirty blocks of the FILE (they are only discarded and not written back)
void bcache_remove_dirty_blocks(struct filemgr *file)
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
    _file_to_fname_query(file, &fname);
    fname.hash = crc32_8_last8(fname.filename, fname.filename_len, 0);
    h = hash_find(&fnamedic, &fname.hash_elem);

    if (h) {
        // file exists
        fname_item = _get_entry(h, struct fnamedic_item, hash_elem);

        while(rb_first(&fname_item->rbtree)) {    
            _bcache_evict_dirty(fname_item, 0);
        }
    }

    DBGCMD(
        gettimeofday(&_b_, NULL);
        _rr_ = _utime_gap(_a_,_b_);        
    );
}

// remove all clean blocks of the FILE
void bcache_remove_clean_blocks(struct filemgr *file)
{
    struct list_elem *e;
    struct hash_elem *h;
    struct bcache_item *item;
    struct fnamedic_item *fname_item, fname;

    _file_to_fname_query(file, &fname);    
    h = hash_find(&fnamedic, &fname.hash_elem);

    if (h) {
        fname_item = _get_entry(h, struct fnamedic_item, hash_elem);
        
        e = list_begin(&cleanlist);
        while(e){
            item = _get_entry(e, struct bcache_item, list_elem);
            if (item->fname == fname_item) {
                if (item == fname_item->lastitem) {
                    fname_item->lastitem = NULL;
                }

                e = list_remove(&cleanlist, e);
                _bcache_count(&cleanlist, -1);
                hash_remove(&bhash, &item->hash_elem);

                item->list = &freelist;
                list_push_front(item->list, &item->list_elem);
                _bcache_count(item->list, 1);
            }else{
                e = list_next(e);
            }
        }    
    }
}

// remove file from filename dictionary
// MUST sure that there is no dirty block belongs to this FILE (or memory leak occurs)
void bcache_remove_file(struct filemgr *file)
{
    struct hash_elem *h;
    struct fnamedic_item *fname_item, fname;

    _file_to_fname_query(file, &fname);
    h = hash_find(&fnamedic, &fname.hash_elem);

    if (h) {
        fname_item = _get_entry(h, struct fnamedic_item, hash_elem);
        assert(fname_item->rbtree.rb_node == NULL);
        _fname_free(fname_item);
    }    
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
    _file_to_fname_query(file, &fname);
    h = hash_find(&fnamedic, &fname.hash_elem);

    if (h) {
        // file exists
        fname_item = _get_entry(h, struct fnamedic_item, hash_elem);

        while(rb_first(&fname_item->rbtree)) {    
            _bcache_evict_dirty(fname_item, 1);
        }
    }

    DBGCMD(
        gettimeofday(&_b_, NULL);
        _rr_ = _utime_gap(_a_,_b_);        
    );
    
}

void bcache_init(int nblock, int blocksize)
{
    DBGCMD(
        struct timeval _a_,_b_,_r_;
        gettimeofday(&_a_, NULL);
    )

    int i, ret;
    struct bcache_item *item;
    struct list_elem *e;

    list_init(&freelist);
    list_init(&cleanlist);
    list_init(&dirtylist);
    nfree = nclean = ndirty = 0;
    hash_init(&bhash, BCACHE_NBUCKET, _bcache_hash, _bcache_cmp);
    hash_init(&fnamedic, BCACHE_NDICBUCKET, _fname_hash, _fname_cmp);
    
    bcache_blocksize = blocksize;
    bcache_flush_unit = BCACHE_FLUSH_UNIT;
    bcache_sys_pagesize = sysconf(_SC_PAGESIZE);
    bcache_nblock = nblock;

    for (i=0;i<nblock;++i){
        item = (struct bcache_item *)malloc(sizeof(struct bcache_item));
        
        item->bid = BLK_NOT_FOUND;
        item->list = &freelist;
        item->fname = NULL;

        list_push_front(item->list, &item->list_elem);
        _bcache_count(item->list, 1);
        //hash_insert(&bhash, &item->hash_elem);
    }
    e = list_begin(&freelist);
    while(e){
        item = _get_entry(e, struct bcache_item, list_elem);
        #ifdef __MEMORY_ALIGN
            ret = posix_memalign(&item->addr, FDB_SECTOR_SIZE, blocksize);
        #else
            item->addr = (void *)malloc(blocksize);
        #endif        
        e = list_next(e);
    }

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
    hash_free_active(&bhash, _bcache_free_bcache_item);
    hash_free_active(&fnamedic, _bcache_free_fnamedic);
}

