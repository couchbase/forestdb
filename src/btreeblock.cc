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
    int sb_no;
    uint32_t pos;
    uint8_t dirty;
    uint8_t age;
    void *addr;
    struct list_elem le;
    struct avl_node avl;
#ifdef __BTREEBLK_BLOCKPOOL
    struct btreeblk_addr *addr_item;
#endif
};

static int _btreeblk_bid_cmp(struct avl_node *a, struct avl_node *b, void *aux)
{
    bid_t aa_bid, bb_bid;
    struct btreeblk_block *aa, *bb;
    aa = _get_entry(a, struct btreeblk_block, avl);
    bb = _get_entry(b, struct btreeblk_block, avl);
    aa_bid = aa->bid;
    bb_bid = bb->bid;

#ifdef __BIT_CMP
    return _CMP_U64(aa_bid, bb_bid);
#else
    if (aa->bid < bb->bid) {
        return -1;
    } else if (aa->bid > bb->bid) {
        return 1;
    } else {
        return 0;
    }
#endif
}

INLINE void _btreeblk_get_aligned_block(struct btreeblk_handle *handle,
                                        struct btreeblk_block *block)
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
    block->addr_item = (struct btreeblk_addr *)
                       mempool_alloc(sizeof(struct btreeblk_addr));
#endif

    malloc_align(block->addr, FDB_SECTOR_SIZE, handle->file->blocksize);
}

INLINE void _btreeblk_free_aligned_block(struct btreeblk_handle *handle,
                                         struct btreeblk_block *block)
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

// LCOV_EXCL_START
INLINE int is_subblock(bid_t subbid)
{
    uint8_t flag;
    flag = (subbid >> (8 * (sizeof(bid_t)-2))) & 0x00ff;
    return flag;
}
// LCOV_EXCL_STOP

INLINE void bid2subbid(bid_t bid, size_t subblock_no, size_t idx, bid_t *subbid)
{
    bid_t flag;
    // to distinguish subblock_no==0 to non-subblock
    subblock_no++;
    flag = (subblock_no << 5) | idx;
    *subbid = bid | (flag << (8 * (sizeof(bid_t)-2)));
}
INLINE void subbid2bid(bid_t subbid, size_t *subblock_no, size_t *idx, bid_t *bid)
{
    uint8_t flag;
    flag = (subbid >> (8 * (sizeof(bid_t)-2))) & 0x00ff;
    *subblock_no = flag >> 5;
    // to distinguish subblock_no==0 to non-subblock
    *subblock_no -= 1;
    *idx = flag & (0x20 - 0x01);
    *bid = ((bid_t)(subbid << 16)) >> 16;
}

INLINE void * _btreeblk_alloc(void *voidhandle, bid_t *bid, int sb_no)
{
    struct btreeblk_handle *handle = (struct btreeblk_handle *)voidhandle;
    struct list_elem *e = list_end(&handle->alc_list);
    struct btreeblk_block *block;
    uint32_t curpos;

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
    block->sb_no = sb_no;
    block->pos = handle->nodesize;
    block->bid = filemgr_alloc(handle->file, handle->log_callback);
    block->dirty = 1;
    block->age = 0;

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
void * btreeblk_alloc(void *voidhandle, bid_t *bid) {
    return _btreeblk_alloc(voidhandle, bid, -1);
}


#ifdef __ENDIAN_SAFE
INLINE void _btreeblk_encode(struct btreeblk_handle *handle,
                             struct btreeblk_block *block)
{
    size_t i, nsb, sb_size, offset;
    void *addr;
    struct bnode *node;

    for (offset=0; offset<handle->nnodeperblock; ++offset) {
        if (block->sb_no > -1) {
            nsb = handle->sb[block->sb_no].nblocks;
            sb_size = handle->sb[block->sb_no].sb_size;
        } else {
            nsb = 1;
            sb_size = 0;
        }

        for (i=0;i<nsb;++i) {
            addr = (uint8_t*)block->addr +
                   (handle->nodesize) * offset +
                   sb_size * i;
#ifdef _BTREE_HAS_MULTIPLE_BNODES
            size_t j, n;
            struct bnode **node_arr;
            node_arr = btree_get_bnode_array(addr, &n);
            for (j=0;j<n;++j){
                node = node_arr[j];
                node->kvsize = _endian_encode(node->kvsize);
                node->flag = _endian_encode(node->flag);
                node->level = _endian_encode(node->level);
                node->nentry = _endian_encode(node->nentry);
            }
            free(node_arr);
#else
            node = btree_get_bnode(addr);
            node->kvsize = _endian_encode(node->kvsize);
            node->flag = _endian_encode(node->flag);
            node->level = _endian_encode(node->level);
            node->nentry = _endian_encode(node->nentry);
#endif
        }
    }
}
INLINE void _btreeblk_decode(struct btreeblk_handle *handle,
                             struct btreeblk_block *block)
{
    size_t i, nsb, sb_size, offset;
    void *addr;
    struct bnode *node;

    for (offset=0; offset<handle->nnodeperblock; ++offset) {
        if (block->sb_no > -1) {
            nsb = handle->sb[block->sb_no].nblocks;
            sb_size = handle->sb[block->sb_no].sb_size;
        } else {
            nsb = 1;
            sb_size = 0;
        }

        for (i=0;i<nsb;++i) {
            addr = (uint8_t*)block->addr +
                   (handle->nodesize) * offset +
                   sb_size * i;
#ifdef _BTREE_HAS_MULTIPLE_BNODES
            size_t j, n;
            struct bnode **node_arr;
            node_arr = btree_get_bnode_array(addr, &n);
            for (j=0;j<n;++j){
                node = node_arr[j];
                node->kvsize = _endian_decode(node->kvsize);
                node->flag = _endian_decode(node->flag);
                node->level = _endian_decode(node->level);
                node->nentry = _endian_decode(node->nentry);
            }
            free(node_arr);
#else
            node = btree_get_bnode(addr);
            node->kvsize = _endian_decode(node->kvsize);
            node->flag = _endian_decode(node->flag);
            node->level = _endian_decode(node->level);
            node->nentry = _endian_decode(node->nentry);
#endif
        }
    }
}
#else
#define _btreeblk_encode(a,b)
#define _btreeblk_decode(a,b)
#endif

INLINE void _btreeblk_free_dirty_block(struct btreeblk_handle *handle,
                                       struct btreeblk_block *block);

INLINE void * _btreeblk_read(void *voidhandle, bid_t bid, int sb_no)
{
    struct list_elem *elm = NULL;
    struct btreeblk_block *block = NULL;
    struct btreeblk_handle *handle = (struct btreeblk_handle *)voidhandle;
    bid_t _bid, filebid;
    int subblock;
    int offset;
    size_t sb, idx;

    sb = idx = 0;
    subbid2bid(bid, &sb, &idx, &_bid);
    subblock = is_subblock(bid);
    filebid = _bid / handle->nnodeperblock;
    offset = _bid % handle->nnodeperblock;

    // check whether the block is in current lists
    // read list (clean or dirty)
#ifdef __BTREEBLK_READ_TREE
    // AVL-tree
    // check first 3 elements in the list first,
    // and then retrieve AVL-tree
    size_t count = 0;
    for (elm = list_begin(&handle->read_list);
         (elm && count < 3); elm = list_next(elm)) {
        block = _get_entry(elm, struct btreeblk_block, le);
        if (block->bid == filebid) {
            block->age = 0;
            // move the elements to the front
            list_remove(&handle->read_list, &block->le);
            list_push_front(&handle->read_list, &block->le);
            if (subblock) {
                return (uint8_t *)block->addr +
                       (handle->nodesize) * offset +
                       handle->sb[sb].sb_size * idx;
            } else {
                return (uint8_t *)block->addr +
                       (handle->nodesize) * offset;
            }
        }
        count++;
    }

    struct btreeblk_block query;
    query.bid = filebid;
    struct avl_node *a;
    a = avl_search(&handle->read_tree, &query.avl, _btreeblk_bid_cmp);
    if (a) { // cache hit
        block = _get_entry(a, struct btreeblk_block, avl);
        block->age = 0;
        // move the elements to the front
        list_remove(&handle->read_list, &block->le);
        list_push_front(&handle->read_list, &block->le);
        if (subblock) {
            return (uint8_t *)block->addr +
                   (handle->nodesize) * offset +
                   handle->sb[sb].sb_size * idx;
        } else {
            return (uint8_t *)block->addr +
                   (handle->nodesize) * offset;
        }
    }
#else
    // list
    for (elm = list_begin(&handle->read_list); elm; elm = list_next(elm)) {
        block = _get_entry(elm, struct btreeblk_block, le);
        if (block->bid == filebid) {
            block->age = 0;
            if (subblock) {
                return (uint8_t *)block->addr +
                       (handle->nodesize) * offset +
                       handle->sb[sb].sb_size * idx;
            } else {
                return (uint8_t *)block->addr +
                       (handle->nodesize) * offset;
            }
        }
    }
#endif

    // allocation list (dirty)
    for (elm = list_begin(&handle->alc_list); elm; elm = list_next(elm)) {
        block = _get_entry(elm, struct btreeblk_block, le);
        if (block->bid == filebid &&
            block->pos >= (handle->nodesize) * offset) {
            block->age = 0;
            if (subblock) {
                return (uint8_t *)block->addr +
                       (handle->nodesize) * offset +
                       handle->sb[sb].sb_size * idx;
            } else {
                return (uint8_t *)block->addr +
                       (handle->nodesize) * offset;
            }
        }
    }

    // there is no block in lists
    // if miss, read from file and add item into read list
    block = (struct btreeblk_block *)mempool_alloc(sizeof(struct btreeblk_block));
    block->sb_no = (subblock)?(sb):(sb_no);
    block->pos = (handle->file->blocksize);
    block->bid = filebid;
    block->dirty = 0;
    block->age = 0;

    _btreeblk_get_aligned_block(handle, block);

    struct avl_node *dirty_avl = NULL;
    if (handle->dirty_snapshot) { // dirty snapshot exists
        // check whether the requested block exists
        struct btreeblk_block query;
        query.bid = block->bid;
        dirty_avl = avl_search(handle->dirty_snapshot, &query.avl, _btreeblk_bid_cmp);
    }

    if (dirty_avl) { // dirty block exists in the snapshot
        // copy block
        struct btreeblk_block *dirty_block;
        dirty_block = _get_entry(dirty_avl, struct btreeblk_block, avl);
        memcpy(block->addr, dirty_block->addr, handle->file->blocksize);
    } else {
        if (filemgr_read(handle->file, block->bid, block->addr,
                         handle->log_callback) != FDB_RESULT_SUCCESS) {
            _btreeblk_free_aligned_block(handle, block);
            mempool_free(block);
            return NULL;
        }
    }
    _btreeblk_decode(handle, block);

    list_push_front(&handle->read_list, &block->le);
#ifdef __BTREEBLK_READ_TREE
    avl_insert(&handle->read_tree, &block->avl, _btreeblk_bid_cmp);
#endif

    if (subblock) {
        return (uint8_t *)block->addr +
               (handle->nodesize) * offset +
               handle->sb[sb].sb_size * idx;
    } else {
        return (uint8_t *)block->addr + (handle->nodesize) * offset;
    }
}

void * btreeblk_read(void *voidhandle, bid_t bid)
{
    return _btreeblk_read(voidhandle, bid, -1);
}

void btreeblk_set_dirty(void *voidhandle, bid_t bid);
void * btreeblk_move(void *voidhandle, bid_t bid, bid_t *new_bid)
{
    struct btreeblk_handle *handle = (struct btreeblk_handle *)voidhandle;
    void *old_addr, *new_addr;
    bid_t _bid, _new_bid;
    int i, subblock;
    size_t sb, idx, new_idx;

    old_addr = new_addr = NULL;
    sb = idx = 0;
    subbid2bid(bid, &sb, &idx, &_bid);
    subblock = is_subblock(bid);

    if (!subblock) {
        // normal block
        old_addr = btreeblk_read(voidhandle, bid);
        new_addr = btreeblk_alloc(voidhandle, new_bid);
        handle->nlivenodes--;

        // move
        memcpy(new_addr, old_addr, (handle->nodesize));

        filemgr_invalidate_block(handle->file, bid);
        return new_addr;
    } else {
        // subblock
        if (handle->sb[sb].bid == _bid) {
            //2 case 1
            // current subblock set is not writable
            // move all of them
            old_addr = _btreeblk_read(voidhandle, _bid, sb);
            new_addr = _btreeblk_alloc(voidhandle, &_new_bid, sb);
            handle->nlivenodes--;
            handle->sb[sb].bid = _new_bid;
            bid2subbid(_new_bid, sb, idx, new_bid);
            btreeblk_set_dirty(voidhandle, handle->sb[sb].bid);

            // move
            memcpy(new_addr, old_addr, (handle->nodesize));

            filemgr_invalidate_block(handle->file, _bid);
            return (uint8_t*)new_addr + handle->sb[sb].sb_size * idx;
        } else {
            //2 case 2
            // move only the target subblock
            // into current subblock set (no allocation is required)
            old_addr = _btreeblk_read(voidhandle, _bid, sb);

            new_idx = handle->sb[sb].nblocks;
            for (i=0;i<handle->sb[sb].nblocks;++i){
                if (handle->sb[sb].bitmap[i] == 0) {
                    new_idx = i;
                    break;
                }
            }
            if (new_idx == handle->sb[sb].nblocks ||
                !filemgr_is_writable(handle->file, handle->sb[sb].bid)) {
                // case 2-1
                // no free slot OR not writable
                // allocate new block
                new_addr = _btreeblk_alloc(voidhandle, &_new_bid, sb);
                handle->nlivenodes--;
                handle->sb[sb].bid = _new_bid;
                memset(handle->sb[sb].bitmap, 0, handle->sb[sb].nblocks);
                new_idx = 0;
            } else {
                // case 2-2
                // append to the current block
                new_addr = _btreeblk_read(voidhandle, handle->sb[sb].bid, sb);
            }

            handle->sb[sb].bitmap[new_idx] = 1;
            bid2subbid(handle->sb[sb].bid, sb, new_idx, new_bid);
            btreeblk_set_dirty(voidhandle, handle->sb[sb].bid);

            // move
            memcpy((uint8_t*)new_addr + handle->sb[sb].sb_size * new_idx,
                   (uint8_t*)old_addr + handle->sb[sb].sb_size * idx,
                   handle->sb[sb].sb_size);

            return (uint8_t*)new_addr + handle->sb[sb].sb_size * new_idx;
        }
    }
}

// LCOV_EXCL_START
void btreeblk_remove(void *voidhandle, bid_t bid)
{
    struct btreeblk_handle *handle = (struct btreeblk_handle *)voidhandle;
    bid_t _bid;
    int i, subblock, nitems;
    size_t sb, idx;

    sb = idx = 0;
    subbid2bid(bid, &sb, &idx, &_bid);
    subblock = is_subblock(bid);

    if (subblock) {
        // subblock
        if (handle->sb[sb].bid == _bid) {
            // erase bitmap
            handle->sb[sb].bitmap[idx] = 0;
            // if all slots are empty, invalidate the block
            nitems = 0;
            for (i=0;i<handle->sb[sb].nblocks;++i){
                if (handle->sb[sb].bitmap) {
                    nitems++;
                }
            }
            if (nitems == 0) {
                handle->sb[sb].bid = BLK_NOT_FOUND;
                handle->nlivenodes--;
                filemgr_invalidate_block(handle->file, _bid);
            }
        }
    } else {
        // normal block
        handle->nlivenodes--;
        filemgr_invalidate_block(handle->file, bid);
    }
}
// LCOV_EXCL_STOP

int btreeblk_is_writable(void *voidhandle, bid_t bid)
{
    struct btreeblk_handle *handle = (struct btreeblk_handle *)voidhandle;
    bid_t _bid;
    bid_t filebid;
    size_t sb, idx;

    sb = idx = 0;
    subbid2bid(bid, &sb, &idx, &_bid);
    filebid = _bid / handle->nnodeperblock;

    return filemgr_is_writable(handle->file, filebid);
}

void btreeblk_set_dirty(void *voidhandle, bid_t bid)
{
    struct btreeblk_handle *handle = (struct btreeblk_handle *)voidhandle;
    struct list_elem *e;
    struct btreeblk_block *block;
    bid_t _bid;
    bid_t filebid;
    size_t sb, idx;

    sb = idx = 0;
    subbid2bid(bid, &sb, &idx, &_bid);
    filebid = _bid / handle->nnodeperblock;

#ifdef __BTREEBLK_READ_TREE
    // AVL-tree
    struct btreeblk_block query;
    query.bid = filebid;
    struct avl_node *a;
    a = avl_search(&handle->read_tree, &query.avl, _btreeblk_bid_cmp);
    if (a) {
        block = _get_entry(a, struct btreeblk_block, avl);
        block->dirty = 1;
    }
#else
    // list
    e = list_begin(&handle->read_list);
    while(e){
        block = _get_entry(e, struct btreeblk_block, le);
        if (block->bid == filebid) {
            block->dirty = 1;
            break;
        }
        e = list_next(e);
    }
#endif
}

static void _btreeblk_set_sb_no(void *voidhandle, bid_t bid, int sb_no)
{
    struct btreeblk_handle *handle = (struct btreeblk_handle *)voidhandle;
    struct list_elem *e;
    struct btreeblk_block *block;
    bid_t _bid;
    bid_t filebid;
    size_t sb, idx;

    sb = idx = 0;
    subbid2bid(bid, &sb, &idx, &_bid);
    filebid = _bid / handle->nnodeperblock;

    e = list_begin(&handle->alc_list);
    while(e){
        block = _get_entry(e, struct btreeblk_block, le);
        if (block->bid == filebid) {
            block->sb_no = sb_no;
            return;
        }
        e = list_next(e);
    }

#ifdef __BTREEBLK_READ_TREE
    // AVL-tree
    struct btreeblk_block query;
    query.bid = filebid;
    struct avl_node *a;
    a = avl_search(&handle->read_tree, &query.avl, _btreeblk_bid_cmp);
    if (a) {
        block = _get_entry(a, struct btreeblk_block, avl);
        block->sb_no = sb_no;
    }
#else
    // list
    e = list_begin(&handle->read_list);
    while(e){
        block = _get_entry(e, struct btreeblk_block, le);
        if (block->bid == filebid) {
            block->sb_no = sb_no;
            return;
        }
        e = list_next(e);
    }
#endif
}

size_t btreeblk_get_size(void *voidhandle, bid_t bid)
{
    bid_t _bid;
    size_t sb, idx;
    struct btreeblk_handle *handle = (struct btreeblk_handle *)voidhandle;

    if (is_subblock(bid) && bid != BLK_NOT_FOUND) {
        subbid2bid(bid, &sb, &idx, &_bid);
        return handle->sb[sb].sb_size;
    } else {
        return handle->nodesize;
    }
}

void * btreeblk_alloc_sub(void *voidhandle, bid_t *bid)
{
    int i;
    void *addr;
    struct btreeblk_handle *handle = (struct btreeblk_handle *)voidhandle;

    if (handle->nsb == 0) {
        return btreeblk_alloc(voidhandle, bid);
    }

    // check current block is available
    if (handle->sb[0].bid != BLK_NOT_FOUND) {
        if (filemgr_is_writable(handle->file, handle->sb[0].bid)) {
            // check if there is an empty slot
            for (i=0;i<handle->sb[0].nblocks;++i){
                if (handle->sb[0].bitmap[i] == 0) {
                    // return subblock
                    handle->sb[0].bitmap[i] = 1;
                    bid2subbid(handle->sb[0].bid, 0, i, bid);
                    addr = _btreeblk_read(voidhandle, handle->sb[0].bid, 0);
                    btreeblk_set_dirty(voidhandle, handle->sb[0].bid);
                    return (void*)
                           ((uint8_t*)addr +
                            handle->sb[0].sb_size * i);
                }
            }
        }
    }

    // existing subblock cannot be used .. give it up & allocate new one
    addr = _btreeblk_alloc(voidhandle, &handle->sb[0].bid, 0);
    memset(handle->sb[0].bitmap, 0, handle->sb[0].nblocks);
    i = 0;
    handle->sb[0].bitmap[i] = 1;
    bid2subbid(handle->sb[0].bid, 0, i, bid);
    return (void*)((uint8_t*)addr + handle->sb[0].sb_size * i);
}

void * btreeblk_enlarge_node(void *voidhandle,
                             bid_t old_bid,
                             size_t req_size,
                             bid_t *new_bid)
{
    int i;
    bid_t bid;
    size_t src_sb, src_idx, src_nitems;
    size_t dst_sb, dst_idx, dst_nitems;
    void *src_addr, *dst_addr;
    struct btreeblk_handle *handle = (struct btreeblk_handle *)voidhandle;

    if (!is_subblock(old_bid)) {
        return NULL;
    }
    src_addr = dst_addr = NULL;
    subbid2bid(old_bid, &src_sb, &src_idx, &bid);

    dst_sb = 0;
    // find sublock that can accommodate req_size
    for (i=src_sb+1; i<handle->nsb; ++i){
        if (handle->sb[i].sb_size > req_size) {
            dst_sb = i;
            break;
        }
    }

    src_nitems = 0;
    for (i=0;i<handle->sb[src_sb].nblocks;++i){
        if (handle->sb[src_sb].bitmap[i]) {
            src_nitems++;
        }
    }

    dst_nitems = 0;
    if (dst_sb > 0) {
        dst_idx = handle->sb[dst_sb].nblocks;
        for (i=0;i<handle->sb[dst_sb].nblocks;++i){
            if (handle->sb[dst_sb].bitmap[i]) {
                dst_nitems++;
            } else if (dst_idx == handle->sb[dst_sb].nblocks) {
                dst_idx = i;
            }
        }
    }

    if (dst_nitems == 0) {
        // destination block is empty
        dst_idx = 0;
        if (src_nitems == 1) {
            //2 case 1
            // if there's only one subblock in the source block,
            // then switch source block to destination block
            src_addr = _btreeblk_read(voidhandle, bid, src_sb);
            if (filemgr_is_writable(handle->file, bid) &&
                bid == handle->sb[src_sb].bid) {
                // case 1-1
                dst_addr = src_addr;
                if (dst_sb > 0) {
                    handle->sb[dst_sb].bid = handle->sb[src_sb].bid;
                } else {
                    *new_bid = handle->sb[src_sb].bid;
                }
                btreeblk_set_dirty(voidhandle, handle->sb[src_sb].bid);
                // we MUST change block->sb_no value since subblock is switched.
                // dst_sb == 0: regular block, otherwise: sub-block
                _btreeblk_set_sb_no(voidhandle, handle->sb[src_sb].bid,
                                    ((dst_sb)?(dst_sb):(-1)));
            } else {
                // case 1-2
                // if the source block is not writable, allocate new one
                if (dst_sb > 0) {
                    dst_addr = _btreeblk_alloc(voidhandle,
                                               &handle->sb[dst_sb].bid, dst_sb);
                } else {
                    // normal (whole) block
                    dst_addr = btreeblk_alloc(voidhandle, new_bid);
                }
            }

            if (src_idx > 0 || dst_addr != src_addr) {
                // move node to the beginning of the block
                memmove(dst_addr,
                        (uint8_t*)src_addr + handle->sb[src_sb].sb_size * src_idx,
                        handle->sb[src_sb].sb_size);
            }
            if (dst_sb > 0) {
                handle->sb[dst_sb].bitmap[dst_idx] = 1;
            }
            if (bid == handle->sb[src_sb].bid) {
                // remove existing source block info
                handle->sb[src_sb].bid = BLK_NOT_FOUND;
                memset(handle->sb[src_sb].bitmap, 0,
                       handle->sb[src_sb].nblocks);
            }

        } else {
            //2 case 2
            // if there are more than one slubblocks in the source block,
            // then allocate destination block and move the target subblock
            src_addr = _btreeblk_read(voidhandle, bid, src_sb);

            if (dst_sb > 0) {
                // case 2-1
                dst_addr = _btreeblk_alloc(voidhandle, &handle->sb[dst_sb].bid, dst_sb);
                memcpy((uint8_t*)dst_addr + handle->sb[dst_sb].sb_size * dst_idx,
                       (uint8_t*)src_addr + handle->sb[src_sb].sb_size * src_idx,
                       handle->sb[src_sb].sb_size);
                handle->sb[dst_sb].bitmap[dst_idx] = 1;
            } else {
                // case 2-2: normal (whole) block
                dst_addr = btreeblk_alloc(voidhandle, new_bid);
                memcpy((uint8_t*)dst_addr,
                       (uint8_t*)src_addr + handle->sb[src_sb].sb_size * src_idx,
                       handle->sb[src_sb].sb_size);
            }
            if (bid == handle->sb[src_sb].bid) {
                handle->sb[src_sb].bitmap[src_idx] = 0;
            }
        }
    } else {
        //2 case 3
        // destination block exists (always happens when subblock)
        src_addr = _btreeblk_read(voidhandle, bid, src_sb);
        if (filemgr_is_writable(handle->file, handle->sb[dst_sb].bid) &&
            dst_idx != handle->sb[dst_sb].nblocks) {
            // case 3-1
            dst_addr = _btreeblk_read(voidhandle, handle->sb[dst_sb].bid, dst_sb);
            btreeblk_set_dirty(voidhandle, handle->sb[dst_sb].bid);
        } else {
            // case 3-2: allocate new destination block
            dst_addr = _btreeblk_alloc(voidhandle, &handle->sb[dst_sb].bid, dst_sb);
            memset(handle->sb[dst_sb].bitmap, 0, handle->sb[dst_sb].nblocks);
            dst_idx = 0;
        }

        memcpy((uint8_t*)dst_addr + handle->sb[dst_sb].sb_size * dst_idx,
               (uint8_t*)src_addr + handle->sb[src_sb].sb_size * src_idx,
               handle->sb[src_sb].sb_size);
        handle->sb[dst_sb].bitmap[dst_idx] = 1;
        if (bid == handle->sb[src_sb].bid) {
            handle->sb[src_sb].bitmap[src_idx] = 0;
        }
    }

    if (dst_sb > 0) {
        // sub block
        bid2subbid(handle->sb[dst_sb].bid, dst_sb, dst_idx, new_bid);
        return (uint8_t*)dst_addr + handle->sb[dst_sb].sb_size * dst_idx;
    } else {
        // whole block
        return dst_addr;
    }
}

INLINE void _btreeblk_free_dirty_block(struct btreeblk_handle *handle,
                                       struct btreeblk_block *block)
{
    _btreeblk_free_aligned_block(handle, block);
    mempool_free(block);
}

INLINE fdb_status _btreeblk_write_dirty_block(struct btreeblk_handle *handle,
                                        struct btreeblk_block *block)
{
    fdb_status status;
    //2 MUST BE modified to support multiple nodes in a block

    _btreeblk_encode(handle, block);
    status = filemgr_write(handle->file, block->bid, block->addr,
                           handle->log_callback);
    _btreeblk_decode(handle, block);
    return status;
}

fdb_status btreeblk_operation_end(void *voidhandle)
{
    // flush and write all items in allocation list
    struct btreeblk_handle *handle = (struct btreeblk_handle *)voidhandle;
    struct list_elem *e;
    struct btreeblk_block *block;
    int writable;
    fdb_status status = FDB_RESULT_SUCCESS;

    // write and free items in allocation list
    e = list_begin(&handle->alc_list);
    while(e){
        block = _get_entry(e, struct btreeblk_block, le);
        writable = filemgr_is_writable(handle->file, block->bid);
        if (writable) {
            status = _btreeblk_write_dirty_block(handle, block);
            if (status != FDB_RESULT_SUCCESS) {
                return status;
            }
        }else{
            assert(0);
        }

        if (block->pos + (handle->nodesize) > (handle->file->blocksize) || !writable) {
            // remove from alc_list and insert into read list
            e = list_remove(&handle->alc_list, &block->le);
            block->dirty = 0;
            list_push_front(&handle->read_list, &block->le);
#ifdef __BTREEBLK_READ_TREE
            avl_insert(&handle->read_tree, &block->avl, _btreeblk_bid_cmp);
#endif
        }else {
            // reserve the block when there is enough space and the block is writable
            e = list_next(e);
        }
    }

    // free items in read list
#ifdef __BTREEBLK_READ_TREE
    // AVL-tree
    struct avl_node *a;
    a = avl_first(&handle->read_tree);
    while (a) {
        block = _get_entry(a, struct btreeblk_block, avl);
        a = avl_next(a);

        if (block->dirty) {
            // write back only when the block is modified
            status = _btreeblk_write_dirty_block(handle, block);
            if (status != FDB_RESULT_SUCCESS) {
                return status;
            }
            block->dirty = 0;
        }

        if (block->age >= BTREEBLK_AGE_LIMIT) {
            list_remove(&handle->read_list, &block->le);
            avl_remove(&handle->read_tree, &block->avl);
            _btreeblk_free_dirty_block(handle, block);
        } else {
            block->age++;
        }
    }
#else
    // list
    e = list_begin(&handle->read_list);
    while(e){
        block = _get_entry(e, struct btreeblk_block, le);

        if (block->dirty) {
            // write back only when the block is modified
            status = _btreeblk_write_dirty_block(handle, block);
            if (status != FDB_RESULT_SUCCESS) {
                return status;
            }
            block->dirty = 0;
        }

        if (block->age >= BTREEBLK_AGE_LIMIT) {
            e = list_remove(&handle->read_list, &block->le);
            _btreeblk_free_dirty_block(handle, block);
        } else {
            block->age++;
            e = list_next(e);
        }
    }
#endif
    return status;
}

void btreeblk_discard_blocks(struct btreeblk_handle *handle)
{
    // discard all writable blocks in the read list
    struct list_elem *e;
    struct btreeblk_block *block;

    // free items in read list
#ifdef __BTREEBLK_READ_TREE
    // AVL-tree
    struct avl_node *a;
    a = avl_first(&handle->read_tree);
    while (a) {
        block = _get_entry(a, struct btreeblk_block, avl);
        a = avl_next(a);

        list_remove(&handle->read_list, &block->le);
        avl_remove(&handle->read_tree, &block->avl);
        _btreeblk_free_dirty_block(handle, block);
    }
#else
    // list
    e = list_begin(&handle->read_list);
    while(e){
        block = _get_entry(e, struct btreeblk_block, le);
        e = list_next(&block->le);

        list_remove(&handle->read_list, &block->le);
        _btreeblk_free_dirty_block(handle, block);
    }
#endif
}

// Create snapshots for dirty B+tree nodes
// Note that filemgr_mutex MUST be grabbed by the caller
fdb_status btreeblk_create_dirty_snapshot(struct btreeblk_handle *handle)
{
    int cmp;
    uint8_t *marker;
    bid_t dirty_bid, commit_bid, cur_bid;
    fdb_status fs;
    struct btreeblk_block *block = NULL;

    if (handle->dirty_snapshot) { //already exists
        return FDB_RESULT_SUCCESS;
    }
    handle->dirty_snapshot = (struct avl_tree*)calloc(1, sizeof(struct avl_tree));

    marker = alca(uint8_t, BLK_MARKER_SIZE);
    memset(marker, BLK_MARKER_BNODE, BLK_MARKER_SIZE);

    avl_init(handle->dirty_snapshot, NULL);

    // get last dirty block BID
    dirty_bid = (handle->file->pos.val / handle->file->blocksize) - 1;
    // get the BID of the right next block of the last committed block
    commit_bid = (handle->file->last_commit.val / handle->file->blocksize);

    block = (struct btreeblk_block*)
            calloc(1, sizeof(struct btreeblk_block));
    malloc_align(block->addr, FDB_SECTOR_SIZE, handle->file->blocksize);

    // scan dirty blocks
    // TODO: we need to devise more efficient way than scanning
    for (cur_bid = commit_bid; cur_bid <= dirty_bid; cur_bid++) {
        // read block from file (most dirty blocks may be cached)
        block->bid = cur_bid;
        if ((fs = filemgr_read(handle->file, block->bid, block->addr,
                         handle->log_callback)) != FDB_RESULT_SUCCESS) {
            free_align(block->addr);
            free(block);
            return fs;
        }
        // check if the block is for btree node
        cmp = memcmp((uint8_t *)block->addr +
                                handle->file->blocksize - BLK_MARKER_SIZE,
                     marker, BLK_MARKER_SIZE);
        if (cmp == 0) { // this is btree block
            // insert into AVL-tree
            avl_insert(handle->dirty_snapshot, &block->avl, _btreeblk_bid_cmp);
            // alloc new block
            block = (struct btreeblk_block*)
                    calloc(1, sizeof(struct btreeblk_block));
            malloc_align(block->addr, FDB_SECTOR_SIZE, handle->file->blocksize);
        }
    }

    // free unused block
    free_align(block->addr);
    free(block);

    return FDB_RESULT_SUCCESS;
}

void btreeblk_clone_dirty_snapshot(struct btreeblk_handle *dst,
                                   struct btreeblk_handle *src)
{
    struct avl_node *a;
    struct btreeblk_block *block, *block_copy;

    // return if source handle's dirty snapshot doesn't exist, OR
    // destination handle's dirty snapshot already exists.
    if (!src->dirty_snapshot ||
        dst->dirty_snapshot) {
        return;
    }

    dst->dirty_snapshot = (struct avl_tree*)calloc(1, sizeof(struct avl_tree));
    avl_init(dst->dirty_snapshot, NULL);

    a = avl_first(src->dirty_snapshot);
    while (a) {
        block = _get_entry(a, struct btreeblk_block, avl);
        a = avl_next(&block->avl);

        // alloc new block
        block_copy = (struct btreeblk_block*)
                     calloc(1, sizeof(struct btreeblk_block));
        malloc_align(block_copy->addr, FDB_SECTOR_SIZE, src->file->blocksize);
        memcpy(block_copy->addr, block->addr, src->file->blocksize);
        block_copy->bid = block->bid;

        // insert into dst handle's AVL-tree
        avl_insert(dst->dirty_snapshot, &block_copy->avl, _btreeblk_bid_cmp);
    }
}

void btreeblk_free_dirty_snapshot(struct btreeblk_handle *handle)
{
    struct avl_node *a;
    struct btreeblk_block *block;

    if (!handle->dirty_snapshot) {
        return;
    }

    a = avl_first(handle->dirty_snapshot);
    while (a) {
        block = _get_entry(a, struct btreeblk_block, avl);
        a = avl_next(&block->avl);
        avl_remove(handle->dirty_snapshot, &block->avl);
        free_align(block->addr);
        free(block);
    }
    free(handle->dirty_snapshot);
    handle->dirty_snapshot = NULL;
}

#ifdef __BTREEBLK_SUBBLOCK
struct btree_blk_ops btreeblk_ops = {
    btreeblk_alloc,
    btreeblk_alloc_sub,
    btreeblk_enlarge_node,
    btreeblk_read,
    btreeblk_move,
    btreeblk_remove,
    btreeblk_is_writable,
    btreeblk_get_size,
    btreeblk_set_dirty,
    NULL
};
#else
struct btree_blk_ops btreeblk_ops = {
    btreeblk_alloc,
    NULL,
    NULL,
    btreeblk_read,
    btreeblk_move,
    btreeblk_remove,
    btreeblk_is_writable,
    btreeblk_get_size,
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
    uint32_t _nodesize;

    handle->file = file;
    handle->nodesize = nodesize;
    handle->nnodeperblock = handle->file->blocksize / handle->nodesize;
    handle->nlivenodes = 0;
    handle->dirty_snapshot = NULL;

    list_init(&handle->alc_list);
    list_init(&handle->read_list);
#ifdef __BTREEBLK_READ_TREE
    avl_init(&handle->read_tree, NULL);
#endif

#ifdef __BTREEBLK_BLOCKPOOL
    list_init(&handle->blockpool);
#endif

#ifdef __BTREEBLK_SUBBLOCK
    // compute # subblock sets
    _nodesize = BTREEBLK_MIN_SUBBLOCK;
    for (i=0; (_nodesize < nodesize && i<5); ++i){
        _nodesize = _nodesize << 1;
    }
    handle->nsb = i;
    if (i) {
        handle->sb = (struct btreeblk_subblocks*)
                     malloc(sizeof(struct btreeblk_subblocks) * handle->nsb);
        // initialize each subblock set
        _nodesize = BTREEBLK_MIN_SUBBLOCK;
        for (i=0;i<handle->nsb;++i){
            handle->sb[i].bid = BLK_NOT_FOUND;
            handle->sb[i].sb_size = _nodesize;
            handle->sb[i].nblocks = nodesize / _nodesize;
            handle->sb[i].bitmap = (uint8_t*)malloc(handle->sb[i].nblocks);
            memset(handle->sb[i].bitmap, 0, handle->sb[i].nblocks);
            _nodesize = _nodesize << 1;
        }
    } else {
        handle->sb = NULL;
    }
#endif
}

void btreeblk_reset_subblock_info(struct btreeblk_handle *handle)
{
    int i;
    // initialize each subblock set
    for (i=0;i<handle->nsb;++i){
        handle->sb[i].bid = BLK_NOT_FOUND;
        memset(handle->sb[i].bitmap, 0, handle->sb[i].nblocks);
    }

}

// shutdown
void btreeblk_free(struct btreeblk_handle *handle)
{
    struct list_elem *e;
    struct btreeblk_block *block;

    // free all blocks in alc list
    e = list_begin(&handle->alc_list);
    while(e) {
        block = _get_entry(e, struct btreeblk_block, le);
        e = list_remove(&handle->alc_list, &block->le);
        _btreeblk_free_dirty_block(handle, block);
    }

    // free all blocks in read list
#ifdef __BTREEBLK_READ_TREE
    // AVL tree
    struct avl_node *a;
    a = avl_first(&handle->read_tree);
    while (a) {
        block = _get_entry(a, struct btreeblk_block, avl);
        a = avl_next(a);
        avl_remove(&handle->read_tree, &block->avl);
        _btreeblk_free_dirty_block(handle, block);
    }
#else
    // linked list
    e = list_begin(&handle->read_list);
    while(e) {
        block = _get_entry(e, struct btreeblk_block, le);
        e = list_remove(&handle->read_list, &block->le);
        _btreeblk_free_dirty_block(handle, block);
    }
#endif

#ifdef __BTREEBLK_BLOCKPOOL
    // free all blocks in the block pool
    struct btreeblk_addr *item;

    e = list_begin(&handle->blockpool);
    while(e){
        item = _get_entry(e, struct btreeblk_addr, le);
        e = list_next(e);

        free_align(item->addr);
        mempool_free(item);
    }
#endif

#ifdef __BTREEBLK_SUBBLOCK
    int i;
    for (i=0;i<handle->nsb;++i){
        free(handle->sb[i].bitmap);
    }
    free(handle->sb);
#endif

    // free dirty snapshot if exist
    btreeblk_free_dirty_snapshot(handle);
}

fdb_status btreeblk_end(struct btreeblk_handle *handle)
{
    struct list_elem *e;
    struct btreeblk_block *block;
    fdb_status status = FDB_RESULT_SUCCESS;

    // flush all dirty items
    status = btreeblk_operation_end((void *)handle);
    if (status != FDB_RESULT_SUCCESS) {
        return status;
    }

    // remove all items in lists
    e = list_begin(&handle->alc_list);
    while(e) {
        block = _get_entry(e, struct btreeblk_block, le);
        e = list_remove(&handle->alc_list, &block->le);

        block->dirty = 0;
        list_push_front(&handle->read_list, &block->le);
#ifdef __BTREEBLK_READ_TREE
        avl_insert(&handle->read_tree, &block->avl, _btreeblk_bid_cmp);
#endif
    }
    return status;
}
