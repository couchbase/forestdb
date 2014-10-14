/* -*- Mode: C++; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2010 Couchbase, Inc
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 */

#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "hash_functions.h"
#include "common.h"
#include "hash.h"
#include "list.h"
#include "blockcache.h"
#include "avltree.h"

#include "memleak.h"

#ifdef __DEBUG
#ifndef __DEBUG_BCACHE
    #undef DBG
    #undef DBGCMD
    #undef DBGSW
    #define DBG(...)
    #define DBGCMD(...)
    #define DBGSW(n, ...)
#endif
static uint64_t _dirty = 0;
#endif

// global lock
static spin_t bcache_lock;
static size_t fnames;

// hash table for filename
static struct hash fnamedic;

// free block list
static size_t freelist_count=0;
static struct list freelist;
static spin_t freelist_lock;

// file structure list
static struct list file_lru, file_empty;
static spin_t filelist_lock;

//static struct list cleanlist, dirtylist;
//static uint64_t nfree, nclean, ndirty;
static uint64_t bcache_nblock;

static int bcache_blocksize;
static size_t bcache_flush_unit;

struct fnamedic_item {
    char *filename;
    uint16_t filename_len;
    uint32_t hash;

    // current opened filemgr instance (can be changed on-the-fly when file is closed and re-opened)
    struct filemgr *curfile;

    // list for clean blocks
    struct list cleanlist;
    // red-black tree for dirty blocks
    struct avl_tree tree;
    // hash table for block lookup
    struct hash hashtable;

    // list elem for FILE_LRU
    struct list_elem le;    // offset -96
    // current list poitner (FILE_LRU or FILE_EMPTY)
    struct list *curlist;
    // hash elem for FNAMEDIC
    struct hash_elem hash_elem;

    spin_t lock;
    uint64_t nvictim;
    uint32_t nitems;
};

#define BCACHE_DIRTY (0x1)
#define BCACHE_FREE (0x4)

struct bcache_item {
    // BID
    bid_t bid;
    // contents address
    void *addr;
    struct fnamedic_item *fname;
    // pointer of the list to which this item belongs
    //struct list *list;
    // hash elem for lookup hash table
    struct hash_elem hash_elem;
    // list elem for {free, clean, dirty} lists
    struct list_elem list_elem;     // offset -48
    // flag
    uint8_t flag;
    // score
    uint8_t score;
    // spin lock
    spin_t lock;

};

struct dirty_item {
    struct bcache_item *item;
    struct avl_node avl;
};

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
    char fname_buf[FDB_MAX_FILENAME_LEN];
    uint8_t marker;

    e = list_begin(list);
    while(e) {
        if (begin <= c && c < begin+n) {
            item = _get_entry(e, struct bcache_item, list_elem);
            memcpy(fname_buf, item->fname->filename, item->fname->filename_len);
            fname_buf[item->fname->filename_len] = 0;
            memcpy(&marker, ((uint8_t *)item->addr) + 4095, 1);
            printf("#%" _F64 ": BID %" _F64 ", marker 0x%x, file %s\n", c, item->bid, marker, fname_buf);
        }
        c++;
        e = list_next(e);
    }
}
#endif

INLINE int _dirty_cmp(struct avl_node *a, struct avl_node *b, void *aux)
{
    struct dirty_item *aa, *bb;
    aa = _get_entry(a, struct dirty_item, avl);
    bb = _get_entry(b, struct dirty_item, avl);

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
    return item->hash & ((unsigned)(BCACHE_NDICBUCKET-1));
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
    return (item->bid) & ((uint32_t)BCACHE_NBUCKET-1);
}

INLINE int _bcache_cmp(struct hash_elem *a, struct hash_elem *b)
{
    struct bcache_item *aa, *bb;
    aa = _get_entry(a, struct bcache_item, hash_elem);
    bb = _get_entry(b, struct bcache_item, hash_elem);

    #ifdef __BIT_CMP

        return _CMP_U64(aa->bid, bb->bid);

    #else

        if (aa->bid == bb->bid) return 0;
        else if (aa->bid < bb->bid) return -1;
        else return 1;

    #endif
}

void _bcache_move_fname_list(struct fnamedic_item *fname, struct list *list)
{
    file_status_t fs;

    spin_lock(&filelist_lock);

    if (fname->curlist != list) {
        if (list == &file_lru) {
            fnames++;
        } else {
            fnames--;
        }
    }

    if (fname->curlist) list_remove(fname->curlist, &fname->le);
    if (list) {
        fs = filemgr_get_file_status(fname->curfile);

        if (list == &file_lru && fs == FILE_COMPACT_OLD) {
            // insert compact old file always at the tail of LRU
            list_push_back(list, &fname->le);
        }else{
            list_push_front(list, &fname->le);
        }
    }
    fname->curlist = list;

    spin_unlock(&filelist_lock);
}

#define _list_empty(list) (((list).head) == NULL)
#define _tree_empty(tree) (((tree).root) == NULL)

struct fnamedic_item *_bcache_get_victim()
{
    struct list_elem *e = NULL, *prev;

    spin_lock(&filelist_lock);

#ifdef __BCACHE_RANDOM_VICTIM
    size_t i, r;

    if (fnames > BCACHE_RANDOM_VICTIM_UNIT){
        r = rand() % BCACHE_RANDOM_VICTIM_UNIT;
    }else{
        r = 0;
    }
    e = prev = list_end(&file_lru);

    for (i=0;i<r;++i){
        if (e == NULL) {
            e = prev;
            break;
        }
        prev = e;
        e = list_prev(e);
    }

#else
    e = list_end(&file_lru);
#endif

    if (e==NULL) {
        e = list_begin(&file_empty);

        while (e) {
            struct fnamedic_item *fname = _get_entry(e, struct fnamedic_item, le);
            if (!(_list_empty(fname->cleanlist) && _tree_empty(fname->tree))) {
                break;
            }
            e = list_next(e);
        }
    }

    spin_unlock(&filelist_lock);

    if (e) {
        return _get_entry(e, struct fnamedic_item, le);
    }
    return NULL;
}

struct bcache_item *_bcache_alloc_freeblock()
{
    struct list_elem *e = NULL;
    struct bcache_item *item;

    spin_lock(&freelist_lock);
    e = list_pop_front(&freelist);
    if (e) freelist_count--;
    spin_unlock(&freelist_lock);

    if (e) {
        item = _get_entry(e, struct bcache_item, list_elem);
        return item;
    }
    return NULL;
}

void _bcache_release_freeblock(struct bcache_item *item)
{
    spin_lock(&freelist_lock);
    item->flag = BCACHE_FREE;
    item->score = 0;
    list_push_front(&freelist, &item->list_elem);
    freelist_count++;
    spin_unlock(&freelist_lock);
}

// flush a bunch of dirty blocks (BCACHE_FLUSH_UNIT) & make then as clean
//2 FNAME_LOCK is already acquired by caller (of the caller)
void _bcache_evict_dirty(struct fnamedic_item *fname_item, int sync)
{
    // get oldest dirty block
    void *buf = NULL;
    struct list_elem *prevhead;
    struct avl_node *a;
    struct dirty_item *ditem;
    int count;
    ssize_t ret;
    bid_t start_bid, prev_bid;
    void *ptr = NULL;
    uint8_t marker = 0x0;

    // scan and gather rb-tree items sequentially
    if (sync) {
        malloc_align(buf, FDB_SECTOR_SIZE, bcache_flush_unit);
    }

    prev_bid = start_bid = BLK_NOT_FOUND;
    count = 0;

    // traverse rb-tree in a sequential order
    a = avl_first(&fname_item->tree);
    while(a) {
        ditem = _get_entry(a, struct dirty_item, avl);

        // if BID of next dirty block is not consecutive .. stop
        if (ditem->item->bid != prev_bid + 1 && prev_bid != BLK_NOT_FOUND && sync) break;
        // set START_BID if this is the first loop
        if (start_bid == BLK_NOT_FOUND) start_bid = ditem->item->bid;

        // set PREV_BID and go to next block
        prev_bid = ditem->item->bid;
        a = avl_next(a);

        spin_lock(&ditem->item->lock);
        // set PTR and get block MARKER
        ptr = ditem->item->addr;
        marker = *((uint8_t*)(ptr) + bcache_blocksize-1);

        ditem->item->flag &= ~(BCACHE_DIRTY);
        if (sync) {
            // copy to buffer
#ifdef __CRC32
            if (marker == BLK_MARKER_BNODE ) {
                // b-tree node .. calculate crc32 and put it into the block
                memset((uint8_t *)(ptr) + BTREE_CRC_OFFSET, 0xff, BTREE_CRC_FIELD_LEN);
                uint32_t crc = chksum(ptr, bcache_blocksize);
                crc = _endian_encode(crc);
                memcpy((uint8_t *)(ptr) + BTREE_CRC_OFFSET, &crc, sizeof(crc));
            }
#endif
            memcpy((uint8_t *)(buf) + count*bcache_blocksize, ditem->item->addr,
                   bcache_blocksize);
        }

        // remove from rb-tree
        avl_remove(&fname_item->tree, &ditem->avl);
        // move to clean list
        prevhead = fname_item->cleanlist.head;
        list_push_front(&fname_item->cleanlist, &ditem->item->list_elem);

        assert(!(ditem->item->flag & BCACHE_FREE));
        assert(ditem->item->list_elem.prev == NULL && prevhead == ditem->item->list_elem.next);
        spin_unlock(&ditem->item->lock);

        mempool_free(ditem);

        // if we have to sync the dirty block, and
        // the size of dirty blocks exceeds the BCACHE_FLUSH_UNIT
        count++;
        if (count*bcache_blocksize >= bcache_flush_unit && sync) break;
    }

    // synchronize
    if (sync && count>0) {
        // TODO: we MUST NOT directly call file->ops
        ret = fname_item->curfile->ops->pwrite(
            fname_item->curfile->fd, buf, count * bcache_blocksize, start_bid * bcache_blocksize);

        assert(ret == count * bcache_blocksize);
        free_align(buf);
    }
}

// perform eviction
struct list_elem * _bcache_evict(struct fnamedic_item *curfile)
{
    size_t n_evict;
    struct list_elem *e = NULL;
    struct bcache_item *item;
    struct fnamedic_item *victim = NULL;

    spin_lock(&bcache_lock);

    while(victim == NULL) {
        // select victim file (the tail of FILE_LRU)
        victim = _bcache_get_victim();
        while(victim) {
            spin_lock(&victim->lock);

            // check whether this file has at least one block to be evictied
            if (!_list_empty(victim->cleanlist) || !_tree_empty(victim->tree)) {
                // select this file as victim
                break;
            }else{
                // empty file
                // move this file to empty list (it is ok that this was already moved to empty list by other thread)
                _bcache_move_fname_list(victim, &file_empty);
                spin_unlock(&victim->lock);

                victim = NULL;
            }
        }
    }
    assert(victim);
    spin_unlock(&bcache_lock);

    victim->nvictim++;

    // select victim clean block of the victim file
    n_evict = 0;
    while(n_evict < BCACHE_EVICT_UNIT) {

#ifdef __BCACHE_SECOND_CHANCE
        while(1) {
            // repeat until zero-score item is found
            e = list_pop_back(&victim->cleanlist);
            while (e == NULL) {
                // when the victim file has no clean block .. evict dirty block
                _bcache_evict_dirty(victim, 1);

                // pop back from cleanlist
                e = list_pop_back(&victim->cleanlist);
            }

            item = _get_entry(e, struct bcache_item, list_elem);
            if (item->score == 0) {
                break;
            } else {
                // give second chance to the item
                item->score--;
                list_push_front(&victim->cleanlist, &item->list_elem);
            }
        }
#else
        e = list_pop_back(&victim->cleanlist);
        while (e == NULL) {
            // when the victim file has no clean block .. evict dirty block
            _bcache_evict_dirty(victim, 1);

            // pop back from cleanlist
            e = list_pop_back(&victim->cleanlist);
        }
        item = _get_entry(e, struct bcache_item, list_elem);
#endif

        victim->nitems--;

        spin_lock(&item->lock);

        // remove from hash and insert into freelist
        hash_remove(&victim->hashtable, &item->hash_elem);

        // add to freelist
        _bcache_release_freeblock(item);
        n_evict++;

        spin_unlock(&item->lock);

        if (victim->nitems == 0) {
            break;
        }
    }

    // check whether the victim file has no cached block
    if (_list_empty(victim->cleanlist) && _tree_empty(victim->tree)) {
        // remove from FILE_LRU and insert into FILE_EMPTY
        _bcache_move_fname_list(victim, &file_empty);
    }

    spin_unlock(&victim->lock);

    return &item->list_elem;
}

struct fnamedic_item * _fname_create(struct filemgr *file) {
    // TODO: we MUST NOT directly read file sturcture

    struct fnamedic_item *fname_new;
    fname_new = (struct fnamedic_item *)malloc(sizeof(struct fnamedic_item));

    fname_new->filename_len = strlen(file->filename);
    fname_new->filename = (char *)malloc(fname_new->filename_len + 1);
    memcpy(fname_new->filename, file->filename, fname_new->filename_len);
    //strcpy(fname_new->filename, file->filename);
    fname_new->filename[fname_new->filename_len] = 0;

    // calculate hash value
    fname_new->hash = chksum((void *)fname_new->filename,
                             fname_new->filename_len);
    spin_init(&fname_new->lock);
    fname_new->curlist = NULL;
    fname_new->curfile = file;
    fname_new->nvictim = 0;
    fname_new->nitems = 0;

    // initialize tree
    avl_init(&fname_new->tree, NULL);
    // initialize clean list
    list_init(&fname_new->cleanlist);
    // initialize hash table
    hash_init(&fname_new->hashtable, BCACHE_NBUCKET, _bcache_hash, _bcache_cmp);

    // insert into fname dictionary
    hash_insert(&fnamedic, &fname_new->hash_elem);
    file->bcache = fname_new;

    return fname_new;
}

void _fname_free(struct fnamedic_item *fname)
{
    // remove from corresponding list
    _bcache_move_fname_list(fname, NULL);

    // tree must be empty
    assert(_tree_empty(fname->tree));

    // clean list must be empty
    assert(_list_empty(fname->cleanlist));

    // free hash
    hash_free(&fname->hashtable);

    free(fname->filename);
    spin_destroy(&fname->lock);
}

INLINE void _bcache_set_score(struct bcache_item *item)
{
#ifdef __CRC32
    uint8_t marker;

    // set PTR and get block MARKER
    marker = *((uint8_t*)(item->addr) + bcache_blocksize-1);
    if (marker == BLK_MARKER_BNODE ) {
        // b-tree node .. set item's score to 1
        item->score = 1;
    } else {
        item->score = 0;
    }
#endif
}

int bcache_read(struct filemgr *file, bid_t bid, void *buf)
{
    struct hash_elem *h;
    struct bcache_item *item;
    struct bcache_item query;
    struct fnamedic_item *fname;

    spin_lock(&bcache_lock);
    fname = file->bcache;
    spin_unlock(&bcache_lock);

    if (fname) {
        // file exists
        // set query
        query.bid = bid;
        query.fname = fname;
        query.fname->curfile = file;

        // relay lock
        spin_lock(&fname->lock);

        // move the file to the head of FILE_LRU
        _bcache_move_fname_list(fname, &file_lru);

        // search BHASH
        h = hash_find(&fname->hashtable, &query.hash_elem);
        if (h) {
            // cache hit
            item = _get_entry(h, struct bcache_item, hash_elem);
            assert(item->fname == fname);
            spin_lock(&item->lock);

            assert(!(item->flag & BCACHE_FREE));

            // move the item to the head of list if the block is clean (don't care if the block is dirty)
            if (!(item->flag & BCACHE_DIRTY)) {
                list_remove(&item->fname->cleanlist, &item->list_elem);
                list_push_front(&item->fname->cleanlist, &item->list_elem);
            }

            // relay lock
            spin_unlock(&fname->lock);

            memcpy(buf, item->addr, bcache_blocksize);
            _bcache_set_score(item);

            spin_unlock(&item->lock);

            return bcache_blocksize;
        }else {
            // cache miss
            spin_unlock(&fname->lock);
        }
    }

    // does not exist .. cache miss
    return 0;
}

void bcache_invalidate_block(struct filemgr *file, bid_t bid)
{
    struct hash_elem *h;
    struct bcache_item *item;
    struct bcache_item query;
    struct fnamedic_item *fname;

    fname = file->bcache;
    if (fname) {
        // file exists
        // set query
        query.bid = bid;
        query.fname = fname;
        query.fname->curfile = file;

        // relay lock
        spin_lock(&fname->lock);

        // move the file to the head of FILE_LRU
        _bcache_move_fname_list(fname, &file_lru);

        // search BHASH
        h = hash_find(&fname->hashtable, &query.hash_elem);
        if (h) {
            // cache hit
            item = _get_entry(h, struct bcache_item, hash_elem);
            assert(item->fname == fname);
            spin_lock(&item->lock);

            assert(!(item->flag & BCACHE_FREE));

            fname->nitems--;

            if (!(item->flag & BCACHE_DIRTY)) {
                // only for clean blocks
                // remove from hash and insert into freelist
                hash_remove(&fname->hashtable, &item->hash_elem);
                // remove from clean list
                list_remove(&item->fname->cleanlist, &item->list_elem);

                // add to freelist
                _bcache_release_freeblock(item);

                // check whether the victim file has no cached block
                if (_list_empty(fname->cleanlist) && _tree_empty(fname->tree)) {
                    // remove from FILE_LRU and insert into FILE_EMPTY
                    _bcache_move_fname_list(fname, &file_empty);
                }
            }

            spin_unlock(&item->lock);
            spin_unlock(&fname->lock);
        }else {
            // cache miss
            spin_unlock(&fname->lock);
        }
    }

    // does not exist .. cache miss
}

int bcache_write(struct filemgr *file, bid_t bid, void *buf, bcache_dirty_t dirty)
{
    struct hash_elem *h = NULL;
    struct bcache_item *item;
    struct bcache_item query;
    struct fnamedic_item *fname_new;

    spin_lock(&bcache_lock);
    fname_new = file->bcache;
    if (fname_new == NULL) {
        // filename doesn't exist in filename dictionary .. create
        fname_new = _fname_create(file);
    }
    spin_unlock(&bcache_lock);

    // acquire lock
    spin_lock(&fname_new->lock);

    // move to the head of FILE_LRU
    _bcache_move_fname_list(fname_new, &file_lru);

    // set query
    query.bid = bid;
    query.fname = fname_new;
    query.fname->curfile = file;

    // search hash table
    h = hash_find(&fname_new->hashtable, &query.hash_elem);
    if (h == NULL) {
        // cache miss
        // get a free block
        while ((item = _bcache_alloc_freeblock()) == NULL) {
            // no free block .. perform eviction
            spin_unlock(&fname_new->lock);

            _bcache_evict(fname_new);

            spin_lock(&fname_new->lock);
        }

        // re-search hash table
        h = hash_find(&fname_new->hashtable, &query.hash_elem);
        if (h == NULL) {
            // insert into hash table
            item->bid = bid;
            item->fname = fname_new;
            item->flag = BCACHE_FREE;
            hash_insert(&fname_new->hashtable, &item->hash_elem);
            h = &item->hash_elem;
            spin_lock(&item->lock);
        }else{
            // insert into freelist again
            _bcache_release_freeblock(item);
            item = _get_entry(h, struct bcache_item, hash_elem);
            spin_lock(&item->lock);
        }
    }else{
        item = _get_entry(h, struct bcache_item, hash_elem);
        spin_lock(&item->lock);
    }

    assert(h);

    if (item->flag & BCACHE_FREE) {
        fname_new->nitems++;
    }

    // remove from the list if the block is in clean list
    if (!(item->flag & BCACHE_DIRTY) && !(item->flag & BCACHE_FREE)) {
        list_remove(&fname_new->cleanlist, &item->list_elem);
    }
    item->flag &= ~BCACHE_FREE;

    if (dirty == BCACHE_REQ_DIRTY) {
        // DIRTY request
        // to avoid re-insert already existing item into tree
        if (!(item->flag & BCACHE_DIRTY)) {
            // dirty block
            // insert into tree
            struct dirty_item *ditem;

            ditem = (struct dirty_item *)mempool_alloc(sizeof(struct dirty_item));
            ditem->item = item;

            avl_insert(&item->fname->tree, &ditem->avl, _dirty_cmp);
        }
        item->flag |= BCACHE_DIRTY;
    }else{
        // CLEAN request
        // insert into clean list only when it was originally clean
        if (!(item->flag & BCACHE_DIRTY)) {
            list_push_front(&item->fname->cleanlist, &item->list_elem);
            item->flag &= ~(BCACHE_DIRTY);
        }
    }

    spin_unlock(&fname_new->lock);

    memcpy(item->addr, buf, bcache_blocksize);
    _bcache_set_score(item);

    spin_unlock(&item->lock);

    return bcache_blocksize;
}

int bcache_write_partial(struct filemgr *file, bid_t bid, void *buf, size_t offset, size_t len)
{
    struct hash_elem *h;
    struct bcache_item *item;
    struct bcache_item query;
    struct fnamedic_item *fname_new;

    spin_lock(&bcache_lock);
    fname_new = file->bcache;
    if (fname_new == NULL) {
        // filename doesn't exist in filename dictionary .. create
        fname_new = _fname_create(file);
    }
    spin_unlock(&bcache_lock);

    // relay lock
    spin_lock(&fname_new->lock);

    // set query
    query.bid = bid;
    query.fname = fname_new;
    query.fname->curfile = file;

    // search hash table
    h = hash_find(&fname_new->hashtable, &query.hash_elem);
    if (h == NULL) {
        // cache miss .. partial write fail .. return 0
        spin_unlock(&fname_new->lock);
        return 0;

    }else{
        // cache hit .. get the block
        item = _get_entry(h, struct bcache_item, hash_elem);
    }

    // move to the head of FILE_LRU
    _bcache_move_fname_list(fname_new, &file_lru);

    spin_lock(&item->lock);

    assert(!(item->flag & BCACHE_FREE));

    // check whether this is dirty block
    // to avoid re-insert already existing item into tree
    if (!(item->flag & BCACHE_DIRTY)) {
        // this block was clean block
        struct dirty_item *ditem;

        // remove from clean list
        list_remove(&item->fname->cleanlist, &item->list_elem);

        ditem = (struct dirty_item *)mempool_alloc(sizeof(struct dirty_item));
        ditem->item = item;

        // insert into tree
        avl_insert(&item->fname->tree, &ditem->avl, _dirty_cmp);
    }

    // always set this block as dirty
    item->flag |= BCACHE_DIRTY;

    spin_unlock(&fname_new->lock);

    memcpy((uint8_t *)(item->addr) + offset, buf, len);
    _bcache_set_score(item);

    spin_unlock(&item->lock);

    return len;
}

// remove all dirty blocks of the FILE (they are only discarded and not written back)
void bcache_remove_dirty_blocks(struct filemgr *file)
{
    struct fnamedic_item *fname_item;

    fname_item = file->bcache;

    if (fname_item) {
        // acquire lock
        spin_lock(&fname_item->lock);

        // remove all dirty block
        while(!_tree_empty(fname_item->tree)) {
            _bcache_evict_dirty(fname_item, 0);
        }

        // check whether the victim file is empty
        if (_list_empty(fname_item->cleanlist) && _tree_empty(fname_item->tree)) {
            // remove from FILE_LRU and insert into FILE_EMPTY
            _bcache_move_fname_list(fname_item, &file_empty);
        }

        spin_unlock(&fname_item->lock);
    }
}

// remove all clean blocks of the FILE
void bcache_remove_clean_blocks(struct filemgr *file)
{
    struct list_elem *e;
    struct bcache_item *item;
    struct fnamedic_item *fname_item;

    fname_item = file->bcache;

    if (fname_item) {
        // acquire lock
        spin_lock(&fname_item->lock);

        // remove all clean blocks
        e = list_begin(&fname_item->cleanlist);
        while(e){
            item = _get_entry(e, struct bcache_item, list_elem);
            spin_lock(&item->lock);

            // remove from clean list
            e = list_remove(&fname_item->cleanlist, e);
            // remove from hash table
            hash_remove(&fname_item->hashtable, &item->hash_elem);
            // insert into free list
            _bcache_release_freeblock(item);
            spin_unlock(&item->lock);
        }

        // check whether the victim file is empty
        if (_list_empty(fname_item->cleanlist) && _tree_empty(fname_item->tree)) {
            // remove from FILE_LRU and insert into FILE_EMPTY
            _bcache_move_fname_list(fname_item, &file_empty);
        }

        spin_unlock(&fname_item->lock);
    }
}

// remove file from filename dictionary
// MUST sure that there is no dirty block belongs to this FILE (or memory leak occurs)
void bcache_remove_file(struct filemgr *file)
{
    struct fnamedic_item *fname_item;

    fname_item = file->bcache;

    if (fname_item) {
        // acquire lock
        spin_lock(&bcache_lock);
        spin_lock(&fname_item->lock);
        assert(_tree_empty(fname_item->tree));
        assert(_list_empty(fname_item->cleanlist));

        // remove from fname dictionary hash table
        hash_remove(&fnamedic, &fname_item->hash_elem);
        spin_unlock(&bcache_lock);

        _fname_free(fname_item);

        spin_unlock(&fname_item->lock);

        free(fname_item);
    }
}

// flush and synchronize all dirty blocks of the FILE
// dirty blocks will be changed to clean blocks (not discarded)
void bcache_flush(struct filemgr *file)
{
    struct fnamedic_item *fname_item;

    fname_item = file->bcache;

    if (fname_item) {
        // acquire lock
        spin_lock(&fname_item->lock);

        while(!_tree_empty(fname_item->tree)) {
            _bcache_evict_dirty(fname_item, 1);
        }

        spin_unlock(&fname_item->lock);
    }
}

void bcache_init(int nblock, int blocksize)
{
    int i;
    struct bcache_item *item;
    struct list_elem *e;

    list_init(&freelist);
    list_init(&file_lru);
    list_init(&file_empty);

    hash_init(&fnamedic, BCACHE_NDICBUCKET, _fname_hash, _fname_cmp);

    bcache_blocksize = blocksize;
    bcache_flush_unit = BCACHE_FLUSH_UNIT;
    bcache_nblock = nblock;
    spin_init(&bcache_lock);
    spin_init(&freelist_lock);
    spin_init(&filelist_lock);
    fnames = 0;

    for (i=0;i<nblock;++i){
        item = (struct bcache_item *)malloc(sizeof(struct bcache_item));

        item->bid = BLK_NOT_FOUND;
        item->fname = NULL;
        item->flag = 0x0 | BCACHE_FREE;
        spin_init(&item->lock);
        item->score = 0;

        list_push_front(&freelist, &item->list_elem);
        freelist_count++;
        //hash_insert(&bhash, &item->hash_elem);
    }
    e = list_begin(&freelist);
    while(e){
        item = _get_entry(e, struct bcache_item, list_elem);
        item->addr = (void *)malloc(bcache_blocksize);
        e = list_next(e);
    }

}

void bcache_print_items()
{
    int n=1;
    size_t sw=0;
    size_t nfiles, nitems, nfileitems, nclean, ndirty;
    size_t scores[100], i, scores_local[100];
    size_t docs, bnodes;
    size_t docs_local, bnodes_local;
    uint8_t *ptr;

    nfiles = nitems = nfileitems = nclean = ndirty = 0;
    docs = bnodes = 0;
    memset(scores, 0, sizeof(size_t)*100);

    struct fnamedic_item *fname;
    struct bcache_item *item;
    struct dirty_item *dirty;
    struct list_elem *e, *ee;
    struct avl_node *a;

    e = list_begin(&file_lru);
    printf(" === Block cache statistics summary ===\n");
    printf("%3s %20s (%6s)(%6s)(c%6s d%6s)",
        "No", "Filename", "#Pages", "#Evict", "Clean", "Dirty");
#ifdef __CRC32
    printf("%6s%6s", "Doc", "Node");
#endif
    for (i=0;i<=n;++i) {
        printf("   [%d] ", (int)i);
    }
    printf("\n");

scan:
    while(e){
        fname = _get_entry(e, struct fnamedic_item, le);
        ee = list_begin(&fname->cleanlist);
        a = avl_first(&fname->tree);
        memset(scores_local, 0, sizeof(size_t)*100);
        nfileitems = nclean = ndirty = 0;
        docs_local = bnodes_local = 0;

        while(ee){
            item = _get_entry(ee, struct bcache_item, list_elem);
            scores[item->score]++;
            scores_local[item->score]++;
            nitems++;
            nfileitems++;
            nclean++;
#ifdef __CRC32
            ptr = (uint8_t*)item->addr + bcache_blocksize - 1;
            switch (*ptr) {
                case BLK_MARKER_BNODE:
                    bnodes_local++;
                    break;
                case BLK_MARKER_DOC:
                    docs_local++;
                    break;
            }
#endif
            ee = list_next(ee);
        }
        while(a){
            dirty = _get_entry(a, struct dirty_item, avl);
            item = dirty->item;
            scores[item->score]++;
            scores_local[item->score]++;
            nitems++;
            nfileitems++;
            ndirty++;
#ifdef __CRC32
            ptr = (uint8_t*)item->addr + bcache_blocksize - 1;
            switch (*ptr) {
                case BLK_MARKER_BNODE:
                    bnodes_local++;
                    break;
                case BLK_MARKER_DOC:
                    docs_local++;
                    break;
            }
#endif
            a = avl_next(a);
        }

        printf("%3d %20s (%6d)(%6d)(c%6d d%6d)", (int)nfiles+1, fname->filename,
            (int)fname->nitems, (int)fname->nvictim, (int)nclean, (int)ndirty);
        printf("%6d%6d", (int)docs_local, (int)bnodes_local);
        for (i=0;i<=n;++i){
            printf("%6d ", (int)scores_local[i]);
        }
        printf("\n");

        docs += docs_local;
        bnodes += bnodes_local;

        nfiles++;
        e = list_next(e);
    }
    printf(" ===\n");
    if (sw == 0){
        e = list_begin(&file_empty);
        sw=1;
        goto scan;
    }

    printf("%d files %d items\n", (int)nfiles, (int)nitems);
    for (i=0;i<=n;++i){
        printf("[%d]: %d\n", (int)i, (int)scores[i]);
    }
    printf("Documents: %d blocks\n", (int)docs);
    printf("Index nodes: %d blocks\n", (int)bnodes);
}

INLINE void _bcache_free_bcache_item(struct hash_elem *h)
{
    struct bcache_item *item = _get_entry(h, struct bcache_item, hash_elem);
    free(item->addr);
    spin_destroy(&item->lock);
    free(item);
}

INLINE void _bcache_free_fnamedic(struct hash_elem *h)
{
    struct fnamedic_item *item = _get_entry(h, struct fnamedic_item, hash_elem);
    hash_free_active(&item->hashtable, _bcache_free_bcache_item);

    _bcache_move_fname_list(item, NULL);

    free(item->filename);
    free(item);
}

void bcache_shutdown()
{
    struct bcache_item *item;
    struct list_elem *e;

    e = list_begin(&freelist);
    while(e) {
        item = _get_entry(e, struct bcache_item, list_elem);
        e = list_remove(&freelist, e);
        free(item->addr);
        spin_destroy(&item->lock);
        free(item);
    }

    spin_lock(&bcache_lock);
    hash_free_active(&fnamedic, _bcache_free_fnamedic);
    spin_unlock(&bcache_lock);

    spin_destroy(&bcache_lock);
    spin_destroy(&freelist_lock);
    spin_destroy(&filelist_lock);
}

