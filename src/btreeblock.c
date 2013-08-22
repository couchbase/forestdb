/*
 * Copyright 2013 Jung-Sang Ahn <jungsang.ahn@gmail.com>.
 * All Rights Reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <snappy-c.h>

#include "common.h"
#include "btreeblock.h"
#include "crc32.h"

#ifdef __DEBUG
#ifndef __DEBUG_BTREEBLOCK
    #undef DBG
    #undef DBGCMD
    #undef DBGSW
    #define DBG(args...)
    #define DBGCMD(command...)
    #define DBGSW(n, command...) 
#endif
#endif

#define BTREEBLK_COE_BIT (2)
#define BTREEBLK_COE (1<<BTREEBLK_COE_BIT)

typedef uint16_t compsize_t;

struct btreeblk_block {
    bid_t bid;
    uint32_t pos;
    uint8_t dirty;
#ifdef _BNODE_COMP
    compsize_t *compsize;
    compsize_t *uncompsize;
#endif
    void *addr;
    struct list_elem e;
};

#ifdef _BNODE_COMP
    static size_t coe = BTREEBLK_COE_BIT;
#else
    static size_t coe = 0;
#endif

void * btreeblk_alloc(void *voidhandle, bid_t *bid)
{
    struct btreeblk_handle *handle = (struct btreeblk_handle *)voidhandle;
    struct list_elem *e = list_end(&handle->alc_list);
    struct btreeblk_block *block;
    uint32_t curpos;
    int ret;

    if (e) {
        block = _get_entry(e, struct btreeblk_block, e);
        if (block->pos <= (handle->file->blocksize << coe) - (handle->nodesize << coe)) {
            if (filemgr_is_writable(handle->file, block->bid)) {
                curpos = block->pos;
                block->pos += (handle->nodesize << coe);
                *bid = block->bid * handle->nnodeperblock + curpos / (handle->nodesize << coe);
                return (block->addr + curpos);
            }
        }
    }
    // allocate new block from file manager
    block = (struct btreeblk_block *)mempool_alloc(sizeof(struct btreeblk_block));
    #ifdef _BNODE_COMP
        block->compsize = (compsize_t *)malloc(sizeof(compsize_t) * handle->nnodeperblock);
        block->uncompsize = (compsize_t *)malloc(sizeof(compsize_t) * handle->nnodeperblock);
        memset(block->compsize, 0, handle->nnodeperblock * sizeof(compsize_t));
        memset(block->uncompsize, 0, handle->nnodeperblock * sizeof(compsize_t));
    #endif
    //block->addr = (void *)mempool_alloc(handle->file->blocksize << coe);
    ret = posix_memalign(&block->addr, FDB_SECTOR_SIZE, handle->file->blocksize << coe);
#ifdef __CRC32
    memset(block->addr + handle->nodesize - BLK_MARKER_SIZE, BLK_MARKER_BNODE, BLK_MARKER_SIZE);
#endif    
    block->pos = handle->nodesize << coe ;
    block->bid = filemgr_alloc(handle->file);
    block->dirty = 1;
    // btree bid differs to filemgr bid
    *bid = block->bid * handle->nnodeperblock;
    list_push_back(&handle->alc_list, &block->e);
    
    return block->addr;
}

#ifdef _BNODE_COMP

INLINE _btreeblk_read_and_uncomp(struct btreeblk_handle *handle, struct btreeblk_block *block)
{
    int i;
    uint8_t buf[handle->file->blocksize];
    size_t buflen;
    
    filemgr_read(handle->file, block->bid, buf);

    for (i=0;i<handle->nnodeperblock;++i) {
        // read compressed size of the node first (at the end of each node)
        buflen = handle->nodesize << coe;
        memcpy(block->compsize + i, buf + (i+1)*handle->nodesize - sizeof(compsize_t), sizeof(compsize_t));
        snappy_uncompress(buf + i*handle->nodesize, *(block->compsize + i), 
            block->addr + i*buflen, &buflen);
        *(block->uncompsize + i) = buflen;
    }
}

INLINE _btreeblk_comp_and_write(struct btreeblk_handle *handle, struct btreeblk_block *block)
{
    int i;
    uint8_t buf[handle->file->blocksize << (coe+1)];
    size_t buflen;;
    
    for (i=0;i<handle->nnodeperblock;++i) {
        // read compressed size of the node first (at the end of each node)
        //buflen = handle->nodesize - sizeof(compsize_t);
        buflen = snappy_max_compressed_length(*(block->uncompsize + i));
        snappy_compress(block->addr + i*(handle->nodesize<<coe), *(block->uncompsize + i),
            buf + i*handle->nodesize, &buflen);
        *(block->compsize + i) = buflen;
        assert(buflen <= handle->nodesize - sizeof(compsize_t));
        memcpy(buf + (i+1)*handle->nodesize - sizeof(compsize_t), block->compsize + i, sizeof(compsize_t));
    }

    filemgr_write(handle->file, block->bid, buf);
}

#endif

#ifdef __BTREEBLK_CACHE

INLINE struct btreeblk_block *_btreeblk_find_recycle_bin(struct btreeblk_handle *handle, bid_t bid)
{
    struct list_elem *elm = NULL;
    struct btreeblk_block *block;
    size_t idx = bid & (BTREEBLK_CACHE_LIMIT-1);

    if (handle->cache[idx]) {
        if (handle->cache[idx]->bid == bid) {
            block = handle->cache[idx];
            handle->cache[idx] = NULL;
            handle->bin_size--;
            list_remove(&handle->recycle_bin, &block->e);
            return block;
        }
    }
    
    elm = list_begin(&handle->recycle_bin);
    while(elm){
        block = _get_entry(elm, struct btreeblk_block, e);
        if (block->bid == bid) {
            handle->bin_size--;
            list_remove(&handle->recycle_bin, elm);
            return block;
        }
        elm = list_next(elm);
    }

    return NULL;
}

INLINE void _btreeblk_dump_recycle_bin(struct btreeblk_handle *handle, struct btreeblk_block *block)
{
    size_t idx = block->bid & (BTREEBLK_CACHE_LIMIT-1);
    handle->bin_size++;
    list_push_front(&handle->recycle_bin, &block->e);
    handle->cache[idx] = block;
}

INLINE void _btreeblk_empty_recycle_bin(struct btreeblk_handle *handle)
{
    size_t count = 0;
    size_t idx;
    struct list_elem *elm = NULL;
    struct btreeblk_block *block;

    if (handle->bin_size <= BTREEBLK_CACHE_LIMIT) return;

    elm = list_end(&handle->recycle_bin);
    while(elm){
        if (++count > (handle->bin_size - BTREEBLK_CACHE_LIMIT)) {
            break;
        }else{
            block = _get_entry(elm, struct btreeblk_block, e);
            idx = block->bid & (BTREEBLK_CACHE_LIMIT-1);

            elm = list_remove_reverse(&handle->recycle_bin, elm);

            if (handle->cache[idx] == block) {
                handle->cache[idx] = NULL;
            }
            //mempool_free(block->addr);
            free(block->addr);
            mempool_free(block);
        }
    }

    handle->bin_size = BTREEBLK_CACHE_LIMIT;
}

#endif

void * btreeblk_read(void *voidhandle, bid_t bid)
{
    struct list_elem *elm = NULL;
    struct btreeblk_block *block = NULL, *cached_block;
    struct btreeblk_handle *handle = (struct btreeblk_handle *)voidhandle;
    bid_t filebid = bid / handle->nnodeperblock;
    int offset = bid % handle->nnodeperblock;
    int ret;

    // check whether the block is in current lists
    // read list (clean)
    for (elm = list_begin(&handle->read_list); elm; elm = list_next(elm)) {
        block = _get_entry(elm, struct btreeblk_block, e);
        if (block->bid == filebid) {
            return block->addr + (handle->nodesize << coe) * offset;
        }
    }
    // allocation list (dirty)
    for (elm = list_begin(&handle->alc_list); elm; elm = list_next(elm)) {
        block = _get_entry(elm, struct btreeblk_block, e);
        if (block->bid == filebid &&
            block->pos >= (handle->nodesize << coe) * offset) {
            return block->addr + (handle->nodesize << coe) * offset;
        }
    }

    // there is no block in lists
#ifdef __BTREEBLK_CACHE
    // first find simple cache
    
    cached_block = _btreeblk_find_recycle_bin(handle, filebid);
    if ( cached_block ) {
        block = cached_block;
        block->dirty = 0;
        block->pos = (handle->file->blocksize << coe);
        list_push_front(&handle->read_list, &block->e);
        return block->addr + (handle->nodesize << coe) * offset;
    }
#endif

    // if miss, read from file and add item into read list
    block = (struct btreeblk_block *)mempool_alloc(sizeof(struct btreeblk_block));
#ifdef _BNODE_COMP
    block->compsize = (compsize_t *)malloc(sizeof(compsize_t) * handle->nnodeperblock);
    block->uncompsize = (compsize_t *)malloc(sizeof(compsize_t) * handle->nnodeperblock);
#endif
    block->pos = (handle->file->blocksize << coe);
    block->bid = filebid;
    block->dirty = 0;

    //block->addr = (void *)mempool_alloc(handle->file->blocksize << coe);
    ret = posix_memalign(&block->addr, FDB_SECTOR_SIZE, handle->file->blocksize << coe);
#ifdef _BNODE_COMP
    // uncompress
    _btreeblk_read_and_uncomp(handle, block);
#else
    filemgr_read(handle->file, block->bid, block->addr);
#endif
    
    list_push_front(&handle->read_list, &block->e);

    return block->addr + (handle->nodesize << coe) * offset;
}

void * btreeblk_move(void *voidhandle, bid_t bid, bid_t *new_bid)
{
    struct btreeblk_handle *handle = (struct btreeblk_handle *)voidhandle;
    struct btreeblk_block *block = NULL;    
    void *old_addr, *new_addr;

    old_addr = btreeblk_read(voidhandle, bid);
    new_addr = btreeblk_alloc(voidhandle, new_bid);

    // move
    memcpy(new_addr, old_addr, (handle->nodesize << coe));

    return new_addr;
}

int btreeblk_is_writable(void *voidhandle, bid_t bid)
{
    struct btreeblk_handle *handle = (struct btreeblk_handle *)voidhandle;
    bid_t filebid = bid / handle->nnodeperblock;

    return filemgr_is_writable(handle->file, filebid);
}

void btreeblk_set_dirty(void *voidhandle, bid_t bid)
{
    struct btreeblk_handle *handle = (struct btreeblk_handle *)voidhandle;
    struct list_elem *e;
    struct btreeblk_block *block;
    bid_t filebid = bid / handle->nnodeperblock;

    e = list_begin(&handle->read_list);
    while(e){
        block = _get_entry(e, struct btreeblk_block, e);
        if (block->bid == filebid) {
            block->dirty = 1;
            break;
        }
        e = list_next(e);
    }
}

INLINE void _btreeblk_free_dirty_block(struct btreeblk_handle *handle, struct btreeblk_block *block)
{
    #ifdef _BNODE_COMP
        free(block->compsize);
        free(block->uncompsize);            
    #endif

    #ifdef __BTREEBLK_CACHE
        _btreeblk_dump_recycle_bin(handle, block);
    #else                
        //mempool_free(block->addr);
        free(block->addr);
        mempool_free(block);
    #endif
}

INLINE void _btreeblk_write_dirty_block(struct btreeblk_handle *handle, struct btreeblk_block *block)
{
    //2 MUST BE modified to support multiple nodes in a block

    /*
#ifdef __CRC32
    size_t offset = offsetof(struct bnode, data);
    void *dataptr = block->addr + offset;
    uint32_t crc32 = crc32_8(block->addr, handle->file->blocksize, 0);
    memcpy(block->addr + offset, &crc32, sizeof(crc32));
    if (sizeof(void *) > 4) {
        memset(block->addr + offset + sizeof(crc32), 0xff, sizeof(void *) - sizeof(crc32));
    }
#endif*/
    
    filemgr_write(handle->file, block->bid, block->addr);
    /*
#ifdef __CRC32
    // rollback original pointer value
    memcpy(block->addr + offset, &dataptr, sizeof(void *));
#endif*/
}

void btreeblk_operation_end(void *voidhandle)
{
    // flush and write all items in allocation list
    struct btreeblk_handle *handle = (struct btreeblk_handle *)voidhandle;
    struct list_elem *e;
    struct btreeblk_block *block, **cached_block;
    int writable, dumped = 0;

    // write and free items in allocation list
    e = list_begin(&handle->alc_list);
    while(e){
        block = _get_entry(e, struct btreeblk_block, e);
        writable = filemgr_is_writable(handle->file, block->bid);
        if (writable) { 
            #ifndef _BNODE_COMP
                _btreeblk_write_dirty_block(handle, block);
            #else
                // compress
                _btreeblk_comp_and_write(handle, block);
            #endif
        }else{
            assert(0);
        }

        if (block->pos + (handle->nodesize << coe) > (handle->file->blocksize << coe) || !writable) {
            e = list_remove(&handle->alc_list, e);
            _btreeblk_free_dirty_block(handle, block);
            dumped = 1;
            
        }else {
            // reserve the block when there is enough space and the block is writable
            e = list_next(e);
        }
    }
    // free items in read list
    e = list_begin(&handle->read_list);
    while(e){
        block = _get_entry(e, struct btreeblk_block, e);
        e = list_remove(&handle->read_list, e);

        if (block->dirty) {
            // write back only when the block is modified
            #ifndef _BNODE_COMP
                _btreeblk_write_dirty_block(handle, block);
            #else
                // compress
                _btreeblk_comp_and_write(handle, block);
            #endif
        }

        _btreeblk_free_dirty_block(handle, block);
        dumped = 1;
        
    }    

    #ifdef __BTREEBLK_CACHE
        if (dumped) _btreeblk_empty_recycle_bin(handle);
    #endif
}

#ifdef _BNODE_COMP

//2 TODO: MUST BE optimized: btree_set_uncomp_size, btreeblk_comp_size
void btreeblk_set_uncomp_size(void *voidhandle, bid_t bid, size_t uncomp_size)
{
    struct list_elem *e;
    struct btreeblk_block *block = NULL;
    struct btreeblk_handle *handle = (struct btreeblk_handle *)voidhandle;
    bid_t filebid = bid / handle->nnodeperblock;
    int offset = bid % handle->nnodeperblock;
    size_t buflen = handle->file->blocksize << coe;
    uint8_t buf[buflen];

    // check whether the block is in current lists
    // allocation list (dirty)
    for ( e = list_begin(&handle->alc_list) ; e ; e = list_next(e) ) {
        block = _get_entry(e, struct btreeblk_block, e);
        if (block->bid == filebid) {
            *(block->uncompsize + offset) = uncomp_size;
            return;
        }
    }
    // read list (clean)
    for ( e = list_begin(&handle->read_list) ; e ; e = list_next(e) ) {
        block = _get_entry(e, struct btreeblk_block, e);
        if (block->bid == filebid) {
            *(block->uncompsize + offset) = uncomp_size;
            return;
        }
    }
}

size_t btreeblk_comp_size(void *voidhandle, bid_t bid)
{
    struct list_elem *e;
    struct btreeblk_block *block = NULL;
    struct btreeblk_handle *handle = (struct btreeblk_handle *)voidhandle;
    bid_t filebid = bid / handle->nnodeperblock;
    int offset = bid % handle->nnodeperblock;
    size_t buflen = handle->file->blocksize << (coe+1);
    uint8_t buf[buflen];

    // check whether the block is in current lists
    // allocation list (dirty)
    for ( e = list_begin(&handle->alc_list) ; e ; e = list_next(e) ) {
        block = _get_entry(e, struct btreeblk_block, e);
        if (block->bid == filebid) {
            snappy_compress(block->addr + offset*(handle->nodesize<<coe), *(block->uncompsize + offset),
                buf, &buflen);
            return buflen + sizeof(compsize_t);
        }
    }
    // read list (clean)
    for ( e = list_begin(&handle->read_list) ; e ; e = list_next(e) ) {
        block = _get_entry(e, struct btreeblk_block, e);
        if (block->bid == filebid) {
            snappy_compress(block->addr + offset*(handle->nodesize<<coe), *(block->uncompsize + offset),
                buf, &buflen);
            return buflen + sizeof(compsize_t);
        }
    }

    return 0;
}

#endif

#ifdef _BNODE_COMP
struct btree_blk_ops btreeblk_ops = {
    btreeblk_alloc,
    btreeblk_read,
    btreeblk_move,
    btreeblk_is_writable,
    btreeblk_set_dirty,
    NULL,
    btreeblk_set_uncomp_size,
    btreeblk_comp_size
};
#else
struct btree_blk_ops btreeblk_ops = {
    btreeblk_alloc,
    btreeblk_read,
    btreeblk_move,
    btreeblk_is_writable,
    btreeblk_set_dirty,
    NULL
};
#endif

struct btree_blk_ops *btreeblk_get_ops()
{
    return &btreeblk_ops;
}

void btreeblk_init(struct btreeblk_handle *handle, struct filemgr *file, int nodesize)
{
    int i;

    handle->file = file;
    handle->nodesize = nodesize;
    handle->nnodeperblock = handle->file->blocksize / handle->nodesize;
    list_init(&handle->alc_list);
    list_init(&handle->read_list);

    #ifdef __BTREEBLK_CACHE
        handle->bin_size = 0;
        list_init(&handle->recycle_bin);
        for (i=0;i<BTREEBLK_CACHE_LIMIT;++i){
            handle->cache[i] = NULL;
        }
    #endif

    DBG("block size %d, btree node size %d\n", handle->file->blocksize, handle->nodesize);
}

void btreeblk_end(struct btreeblk_handle *handle)
{
    int dumped = 0;
    struct list_elem *e;
    struct btreeblk_block *block, **cached_block;

    // flush all dirty items
    btreeblk_operation_end((void *)handle);

    // remove all items in lists
    e = list_begin(&handle->alc_list);
    while(e) {
        block = _get_entry(e, struct btreeblk_block, e);
        e = list_remove(&handle->alc_list, e);

        _btreeblk_free_dirty_block(handle, block);
        dumped = 1;
    }

    #ifdef __BTREEBLK_CACHE
        if (dumped) _btreeblk_empty_recycle_bin(handle);
    #endif
}


