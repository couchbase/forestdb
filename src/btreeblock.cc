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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common.h"
#include "btreeblock.h"
#include "crc32.h"

#include "memleak.h"

#ifdef __DEBUG
#ifndef __DEBUG_BTREEBLOCK
    #undef DBG
    #undef DBGCMD
    #undef DBGSW
    #define DBG(...)
    #define DBGCMD(...)
    #define DBGSW(n, ...)
#endif
#endif

struct btreeblk_addr{
    void *addr;
    struct list_elem le;
};

struct btreeblk_block {
    bid_t bid;
    uint32_t pos;
    uint8_t dirty;
    void *addr;
    struct list_elem le;
#ifdef __BTREEBLK_BLOCKPOOL
    struct btreeblk_addr *addr_item;
#endif
};

INLINE void _btreeblk_get_aligned_block(
    struct btreeblk_handle *handle, struct btreeblk_block *block)
{
#ifdef __BTREEBLK_BLOCKPOOL
    struct list_elem *e;

    e = list_pop_front(&handle->blockpool);
    if (e) {
        block->addr_item = _get_entry(e, struct btreeblk_addr, le);
        block->addr = block->addr_item->addr;
        return;
    }
    // no free addr .. create
    block->addr_item = (struct btreeblk_addr *)mempool_alloc(sizeof(struct btreeblk_addr));
#endif

    malloc_align(block->addr, FDB_SECTOR_SIZE, handle->file->blocksize);
}

INLINE void _btreeblk_free_aligned_block(
    struct btreeblk_handle *handle, struct btreeblk_block *block)
{
#ifdef __BTREEBLK_BLOCKPOOL
    assert(block->addr_item);
    // sync addr & insert into pool
    block->addr_item->addr = block->addr;
    list_push_front(&handle->blockpool, &block->addr_item->le);
    block->addr_item = NULL;
    return;

#endif

    free_align(block->addr);
}

void * btreeblk_alloc(void *voidhandle, bid_t *bid)
{
    struct btreeblk_handle *handle = (struct btreeblk_handle *)voidhandle;
    struct list_elem *e = list_end(&handle->alc_list);
    struct btreeblk_block *block;
    uint32_t curpos;
    int ret;

    if (e) {
        block = _get_entry(e, struct btreeblk_block, le);
        if (block->pos <= (handle->file->blocksize) - (handle->nodesize)) {
            if (filemgr_is_writable(handle->file, block->bid)) {
                curpos = block->pos;
                block->pos += (handle->nodesize);
                *bid = block->bid * handle->nnodeperblock + curpos /
                       (handle->nodesize);
                return ((uint8_t *)block->addr + curpos);
            }
        }
    }

    // allocate new block from file manager
    block = (struct btreeblk_block *)mempool_alloc(sizeof(struct btreeblk_block));
    _btreeblk_get_aligned_block(handle, block);
    block->pos = handle->nodesize;
    block->bid = filemgr_alloc(handle->file, handle->log_callback);
    block->dirty = 1;

#ifdef __CRC32
    memset((uint8_t *)block->addr + handle->nodesize - BLK_MARKER_SIZE,
           BLK_MARKER_BNODE, BLK_MARKER_SIZE);
#endif

    // btree bid differs to filemgr bid
    *bid = block->bid * handle->nnodeperblock;
    list_push_back(&handle->alc_list, &block->le);

    handle->nlivenodes++;

    return block->addr;
}

#ifdef __ENDIAN_SAFE
INLINE void _btreeblk_encode(struct btreeblk_handle *handle,
    struct btreeblk_block *block)
{
    size_t i, n, offset;
    void *addr;
    struct bnode *node;
    struct bnode **node_arr;

    for (offset=0; offset<handle->nnodeperblock; ++offset) {
        addr = (uint8_t*)block->addr + (handle->nodesize) * offset;
        node_arr = btree_get_bnode_array(addr, &n);
        for (i=0;i<n;++i){
            node = node_arr[i];
            node->flag = _endian_encode(node->flag);
            node->level = _endian_encode(node->level);
            node->nentry = _endian_encode(node->nentry);
        }
        free(node_arr);
    }
}
INLINE void _btreeblk_decode(struct btreeblk_handle *handle,
    struct btreeblk_block *block)
{
    size_t i, n, offset;
    void *addr;
    struct bnode *node;
    struct bnode **node_arr;

    for (offset=0; offset<handle->nnodeperblock; ++offset) {
        addr = (uint8_t*)block->addr + (handle->nodesize) * offset;
        node_arr = btree_get_bnode_array(addr, &n);
        for (i=0;i<n;++i){
            node = node_arr[i];
            node->flag = _endian_decode(node->flag);
            node->level = _endian_decode(node->level);
            node->nentry = _endian_decode(node->nentry);
        }
        free(node_arr);
    }
}
#else
#define _btreeblk_encode(a,b)
#define _btreeblk_decode(a,b)
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
        block = _get_entry(elm, struct btreeblk_block, le);
        if (block->bid == filebid) {
            return (uint8_t *)block->addr + (handle->nodesize) * offset;
        }
    }
    // allocation list (dirty)
    for (elm = list_begin(&handle->alc_list); elm; elm = list_next(elm)) {
        block = _get_entry(elm, struct btreeblk_block, le);
        if (block->bid == filebid &&
            block->pos >= (handle->nodesize) * offset) {
            return (uint8_t *)block->addr + (handle->nodesize) * offset;
        }
    }

    // there is no block in lists

    // if miss, read from file and add item into read list
    block = (struct btreeblk_block *)mempool_alloc(sizeof(struct btreeblk_block));
    block->pos = (handle->file->blocksize);
    block->bid = filebid;
    block->dirty = 0;

    _btreeblk_get_aligned_block(handle, block);
    filemgr_read(handle->file, block->bid, block->addr, handle->log_callback);
    _btreeblk_decode(handle, block);

    list_push_front(&handle->read_list, &block->le);

    return (uint8_t *)block->addr + (handle->nodesize) * offset;
}

void * btreeblk_move(void *voidhandle, bid_t bid, bid_t *new_bid)
{
    struct btreeblk_handle *handle = (struct btreeblk_handle *)voidhandle;
    struct btreeblk_block *block = NULL;
    void *old_addr, *new_addr;

    old_addr = btreeblk_read(voidhandle, bid);
    new_addr = btreeblk_alloc(voidhandle, new_bid);
    handle->nlivenodes--;

    // move
    memcpy(new_addr, old_addr, (handle->nodesize));

    filemgr_invalidate_block(handle->file, bid);

    return new_addr;
}

void btreeblk_remove(void *voidhandle, bid_t bid)
{
    struct btreeblk_handle *handle = (struct btreeblk_handle *)voidhandle;
    handle->nlivenodes--;

    filemgr_invalidate_block(handle->file, bid);
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
        block = _get_entry(e, struct btreeblk_block, le);
        if (block->bid == filebid) {
            block->dirty = 1;
            break;
        }
        e = list_next(e);
    }
}

INLINE void _btreeblk_free_dirty_block(
            struct btreeblk_handle *handle,
            struct btreeblk_block *block)
{
    _btreeblk_free_aligned_block(handle, block);
    mempool_free(block);
}

INLINE void _btreeblk_write_dirty_block(
            struct btreeblk_handle *handle,
            struct btreeblk_block *block)
{
    //2 MUST BE modified to support multiple nodes in a block

    _btreeblk_encode(handle, block);
    filemgr_write(handle->file, block->bid, block->addr, handle->log_callback);
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
        block = _get_entry(e, struct btreeblk_block, le);
        writable = filemgr_is_writable(handle->file, block->bid);
        if (writable) {
            _btreeblk_write_dirty_block(handle, block);
        }else{
            assert(0);
        }

        if (block->pos + (handle->nodesize) > (handle->file->blocksize) || !writable) {
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
        block = _get_entry(e, struct btreeblk_block, le);
        e = list_remove(&handle->read_list, e);

        if (block->dirty) {
            // write back only when the block is modified
            _btreeblk_write_dirty_block(handle, block);
        }

        _btreeblk_free_dirty_block(handle, block);
        dumped = 1;

    }

}

struct btree_blk_ops btreeblk_ops = {
    btreeblk_alloc,
    btreeblk_read,
    btreeblk_move,
    btreeblk_remove,
    btreeblk_is_writable,
    btreeblk_set_dirty,
    NULL
};

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
    handle->nlivenodes = 0;

    list_init(&handle->alc_list);
    list_init(&handle->read_list);

#ifdef __BTREEBLK_BLOCKPOOL
    list_init(&handle->blockpool);
#endif

    DBG("block size %d, btree node size %d\n", handle->file->blocksize, handle->nodesize);
}

// shutdown
void btreeblk_free(struct btreeblk_handle *handle)
{
#ifdef __BTREEBLK_BLOCKPOOL
    struct list_elem *e;
    struct btreeblk_addr *item;

    e = list_begin(&handle->blockpool);
    while(e){
        item = _get_entry(e, struct btreeblk_addr, le);
        e = list_next(e);

        free_align(item->addr);
        mempool_free(item);
    }
#endif
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
        block = _get_entry(e, struct btreeblk_block, le);
        e = list_remove(&handle->alc_list, e);

        _btreeblk_free_dirty_block(handle, block);
        dumped = 1;
    }
}


