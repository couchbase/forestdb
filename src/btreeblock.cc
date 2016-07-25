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
#include "fdb_internal.h"
#include "btree.h"

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
#ifdef __BTREEBLK_READ_TREE
    struct avl_node avl;
#endif
#ifdef __BTREEBLK_BLOCKPOOL
    struct btreeblk_addr *addr_item;
#endif
};

#ifdef __BTREEBLK_READ_TREE
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
#endif

BTreeBlkHandle::BTreeBlkHandle(FileMgr *_file, uint32_t _nodesize)
    : nodesize(_nodesize), file(_file)
{
    uint32_t i;
    uint32_t _sub_nodesize;

    nnodeperblock = _file->getBlockSize() / _nodesize;
    nlivenodes = 0;
    ndeltanodes = 0;
    dirty_update = NULL;
    dirty_update_writer = NULL;

    list_init(&alc_list);
    list_init(&read_list);

#ifdef __BTREEBLK_READ_TREE
    avl_init(&read_tree, NULL);
#endif

#ifdef __BTREEBLK_BLOCKPOOL
    list_init(&blockpool);
#endif

#ifdef __BTREEBLK_SUBBLOCK
    // compute # subblock sets
    _sub_nodesize = BTREEBLK_MIN_SUBBLOCK;
    for (i=0; (_sub_nodesize < _nodesize && i<5); ++i){
        _sub_nodesize = _sub_nodesize << 1;
    }
    n_subblocks = i;
    if (i) {
        subblock = (struct btreeblk_subblocks*)
                     malloc(sizeof(struct btreeblk_subblocks) * n_subblocks);
        // initialize each subblock set
        _sub_nodesize = BTREEBLK_MIN_SUBBLOCK;
        for (i=0;i<n_subblocks;++i){
            subblock[i].bid = BLK_NOT_FOUND;
            subblock[i].sb_size = _sub_nodesize;
            subblock[i].nblocks = _nodesize / _sub_nodesize;
            subblock[i].bitmap = (uint8_t*)malloc(subblock[i].nblocks);
            memset(subblock[i].bitmap, 0, subblock[i].nblocks);
            _sub_nodesize = _sub_nodesize << 1;
        }
    } else {
        subblock = NULL;
    }
#endif
}

BTreeBlkHandle::~BTreeBlkHandle()
{
    struct list_elem *e;
    struct btreeblk_block *block;

    // free all blocks in alc list
    e = list_begin(&alc_list);
    while(e) {
        block = _get_entry(e, struct btreeblk_block, le);
        e = list_remove(&alc_list, &block->le);
        freeDirtyBlock(block);
    }

    // free all blocks in read list
#ifdef __BTREEBLK_READ_TREE
    // AVL tree
    struct avl_node *a;
    a = avl_first(&read_tree);
    while (a) {
        block = _get_entry(a, struct btreeblk_block, avl);
        a = avl_next(a);
        avl_remove(&read_tree, &block->avl);
        freeDirtyBlock(block);
    }
#else
    // linked list
    e = list_begin(&read_list);
    while(e) {
        block = _get_entry(e, struct btreeblk_block, le);
        e = list_remove(&read_list, &block->le);
        freeDirtyBlock(block);
    }
#endif

#ifdef __BTREEBLK_BLOCKPOOL
    // free all blocks in the block pool
    struct btreeblk_addr *item;

    e = list_begin(&blockpool);
    while(e){
        item = _get_entry(e, struct btreeblk_addr, le);
        e = list_next(e);

        free_align(item->addr);
        mempool_free(item);
    }
#endif

#ifdef __BTREEBLK_SUBBLOCK
    uint32_t i;
    for (i=0;i<n_subblocks;++i){
        free(subblock[i].bitmap);
    }
    free(subblock);
#endif
}

void BTreeBlkHandle::getAlignedBlock(struct btreeblk_block *block)
{
#ifdef __BTREEBLK_BLOCKPOOL
    struct list_elem *e;

    e = list_pop_front(&blockpool);
    if (e) {
        block->addr_item = _get_entry(e, struct btreeblk_addr, le);
        block->addr = block->addr_item->addr;
        return;
    }
    // no free addr .. create
    block->addr_item = (struct btreeblk_addr *)
                       mempool_alloc(sizeof(struct btreeblk_addr));
#endif

    malloc_align(block->addr, FDB_SECTOR_SIZE, file->getBlockSize());
}

void BTreeBlkHandle::freeAlignedBlock(struct btreeblk_block *block)
{
#ifdef __BTREEBLK_BLOCKPOOL
    if (!block->addr_item) {
        // TODO: Need to log the corresponding error message.
        return;
    }
    // sync addr & insert into pool
    block->addr_item->addr = block->addr;
    list_push_front(&blockpool, &block->addr_item->le);
    block->addr_item = NULL;
    return;

#endif

    free_align(block->addr);
}

void BTreeBlkHandle::freeDirtyBlock(struct btreeblk_block *block)
{
    freeAlignedBlock(block);
    mempool_free(block);
}

fdb_status BTreeBlkHandle::writeDirtyBlock(struct btreeblk_block *block)
{
    fdb_status status;
    //2 MUST BE modified to support multiple nodes in a block

    encodeBlock(block);
    if (dirty_update_writer) {
        // dirty update is in-progress
        status = file->writeDirty(block->bid, block->addr,
                                  dirty_update_writer,
                                  log_callback);
    } else {
        // normal write into file
        status = file->write_FileMgr(block->bid, block->addr,
                                     log_callback);
    }
    if (status != FDB_RESULT_SUCCESS) {
        fdb_log(log_callback, status,
                "Failed to write the B+-Tree block (block id: %" _F64
                ", block address: %p)", block->bid, block->addr);
    }
    decodeBlock(block);
    return status;
}

void * BTreeBlkHandle::_alloc(bid_t& bid, int sb_no)
{
    struct list_elem *e = list_end(&alc_list);
    struct btreeblk_block *block;
    uint32_t curpos;

    if (e) {
        block = _get_entry(e, struct btreeblk_block, le);
        if (block->pos <= (file->getBlockSize()) - (nodesize)) {
            if (file->isWritable(block->bid)) {
                curpos = block->pos;
                block->pos += (nodesize);
                bid = (block->bid * nnodeperblock) + (curpos / nodesize);
                return ((uint8_t *)block->addr + curpos);
            }
        }
    }

    // allocate new block from file manager
    block = (struct btreeblk_block *)mempool_alloc(sizeof(struct btreeblk_block));
    getAlignedBlock(block);
    if (sb_no != -1) {
        // If this block is used as a sub-block container,
        // fill it with zero bytes for easy identifying
        // which region is allocated and which region is not.
        memset(block->addr, 0x0, nodesize);
    }
    block->sb_no = sb_no;
    block->pos = nodesize;
    block->bid = file->alloc_FileMgr(log_callback);
    block->dirty = 1;
    block->age = 0;

    // If a block is allocated but not written back into file (due to
    // various reasons), the corresponding byte offset in the file is filled
    // with garbage data so that it causes various unexpected behaviors.
    // To avoid this issue, populate block cache for the given BID before use it.
    uint8_t marker = BLK_MARKER_BNODE;
    file->writeOffset(block->bid, file->getBlockSize() - 1,
                      1, &marker, false, log_callback);

#ifdef __CRC32
    memset((uint8_t *)block->addr + nodesize - BLK_MARKER_SIZE,
           BLK_MARKER_BNODE, BLK_MARKER_SIZE);
#endif

    // btree bid differs to filemgr bid
    bid = block->bid * nnodeperblock;
    list_push_back(&alc_list, &block->le);

    nlivenodes++;
    ndeltanodes++;

    return block->addr;
}

void * BTreeBlkHandle::alloc(bid_t& bid)
{
    // 'sb_no == -1' means a regular block
    return _alloc(bid, -1);
}

void BTreeBlkHandle::encodeBlock(struct btreeblk_block *block)
{
#ifdef __ENDIAN_SAFE

    size_t i, nsb, sb_size, offset;
    void *addr;
    struct bnode *node;

    for (offset = 0; offset < nnodeperblock; ++offset) {
        if (block->sb_no > -1) {
            nsb = subblock[block->sb_no].nblocks;
            sb_size = subblock[block->sb_no].sb_size;
        } else {
            nsb = 1;
            sb_size = 0;
        }

        for (i=0;i<nsb;++i) {
            addr = (uint8_t*)block->addr +
                   nodesize * offset +
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
#else // _BTREE_HAS_MULTIPLE_BNODES
            node = btree_get_bnode(addr);
            node->kvsize = _endian_encode(node->kvsize);
            node->flag = _endian_encode(node->flag);
            node->level = _endian_encode(node->level);
            node->nentry = _endian_encode(node->nentry);
#endif // _BTREE_HAS_MULTIPLE_BNODES
        }
    }

#endif // __ENDIAN_SAFE
}

void BTreeBlkHandle::decodeBlock(struct btreeblk_block *block)
{
#ifdef __ENDIAN_SAFE

    size_t i, nsb, sb_size, offset;
    void *addr;
    struct bnode *node;

    for (offset=0; offset<nnodeperblock; ++offset) {
        if (block->sb_no > -1) {
            nsb = subblock[block->sb_no].nblocks;
            sb_size = subblock[block->sb_no].sb_size;
        } else {
            nsb = 1;
            sb_size = 0;
        }

        for (i=0;i<nsb;++i) {
            addr = (uint8_t*)block->addr +
                   nodesize * offset +
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
#else // _BTREE_HAS_MULTIPLE_BNODES
            node = btree_get_bnode(addr);
            node->kvsize = _endian_decode(node->kvsize);
            node->flag = _endian_decode(node->flag);
            node->level = _endian_decode(node->level);
            node->nentry = _endian_decode(node->nentry);
#endif // _BTREE_HAS_MULTIPLE_BNODES
        }
    }

#endif // __ENDIAN_SAFE
}

void * BTreeBlkHandle::_read(bid_t bid, int sb_no)
{
    struct list_elem *elm = NULL;
    struct btreeblk_block *block = NULL;
    bid_t _bid, filebid;
    bool subblock_mode;
    int offset;
    size_t sb, idx;

    sb = idx = 0;
    subbid2bid(bid, sb, idx, _bid);
    subblock_mode = isSubblock(bid);
    filebid = _bid / nnodeperblock;
    offset = _bid % nnodeperblock;

    // check whether the block is in current lists
    // read list (clean or dirty)
#ifdef __BTREEBLK_READ_TREE
    // AVL-tree
    // check first 3 elements in the list first,
    // and then retrieve AVL-tree
    size_t count = 0;
    for (elm = list_begin(&read_list);
         (elm && count < 3); elm = list_next(elm)) {
        block = _get_entry(elm, struct btreeblk_block, le);
        if (block->bid == filebid) {
            block->age = 0;
            // move the elements to the front
            list_remove(&read_list, &block->le);
            list_push_front(&read_list, &block->le);
            if (subblock_mode) {
                return (uint8_t *)block->addr +
                       nodesize * offset +
                       subblock[sb].sb_size * idx;
            } else {
                return (uint8_t *)block->addr +
                       nodesize * offset;
            }
        }
        count++;
    }

    struct btreeblk_block query;
    query.bid = filebid;
    struct avl_node *a;
    a = avl_search(&read_tree, &query.avl, _btreeblk_bid_cmp);
    if (a) { // cache hit
        block = _get_entry(a, struct btreeblk_block, avl);
        block->age = 0;
        // move the elements to the front
        list_remove(&read_list, &block->le);
        list_push_front(&read_list, &block->le);
        if (subblock_mode) {
            return (uint8_t *)block->addr +
                   nodesize * offset +
                   subblock[sb].sb_size * idx;
        } else {
            return (uint8_t *)block->addr +
                   nodesize * offset;
        }
    }
#else
    // list
    for (elm = list_begin(&read_list); elm; elm = list_next(elm)) {
        block = _get_entry(elm, struct btreeblk_block, le);
        if (block->bid == filebid) {
            block->age = 0;
            if (subblock_mode) {
                return (uint8_t *)block->addr +
                       nodesize * offset +
                       subblock[sb].sb_size * idx;
            } else {
                return (uint8_t *)block->addr +
                       nodesize * offset;
            }
        }
    }
#endif

    // allocation list (dirty)
    for (elm = list_begin(&alc_list); elm; elm = list_next(elm)) {
        block = _get_entry(elm, struct btreeblk_block, le);
        if (block->bid == filebid &&
            block->pos >= (nodesize) * offset) {
            block->age = 0;
            if (subblock_mode) {
                return (uint8_t *)block->addr +
                       nodesize * offset +
                       subblock[sb].sb_size * idx;
            } else {
                return (uint8_t *)block->addr +
                       nodesize * offset;
            }
        }
    }

    // there is no block in lists
    // if miss, read from file and add item into read list
    block = (struct btreeblk_block *)mempool_alloc(sizeof(struct btreeblk_block));
    block->sb_no = (subblock_mode)?(sb):(sb_no);
    block->pos = file->getBlockSize();
    block->bid = filebid;
    block->dirty = 0;
    block->age = 0;

    getAlignedBlock(block);

    fdb_status status;
    if (dirty_update || dirty_update_writer) {
        // read from the given dirty update entry
        status = file->readDirty(block->bid, block->addr,
                                 dirty_update, dirty_update_writer,
                                 log_callback, true);
    } else {
        // normal read
        status = file->read_FileMgr(block->bid, block->addr,
                                    log_callback, true);
    }
    if (status != FDB_RESULT_SUCCESS) {
        fdb_log(log_callback, status,
                "Failed to read the B+-Tree block (block id: %" _F64
                ", block address: %p)", block->bid, block->addr);
        freeAlignedBlock(block);
        mempool_free(block);
        return NULL;
    }

    decodeBlock(block);

    list_push_front(&read_list, &block->le);
#ifdef __BTREEBLK_READ_TREE
    avl_insert(&read_tree, &block->avl, _btreeblk_bid_cmp);
#endif

    if (subblock_mode) {
        return (uint8_t *)block->addr +
               nodesize * offset +
               subblock[sb].sb_size * idx;
    } else {
        return (uint8_t *)block->addr + nodesize * offset;
    }
}

void * BTreeBlkHandle::read(bid_t bid)
{
    return _read(bid, -1);
}

void * BTreeBlkHandle::move(bid_t bid, bid_t& new_bid)
{
    void *old_addr, *new_addr;
    bid_t _bid, _new_bid;
    int i;
    bool subblock_mode;
    size_t sb, idx, new_idx;

    old_addr = new_addr = NULL;
    sb = idx = 0;
    subbid2bid(bid, sb, idx, _bid);
    subblock_mode = isSubblock(bid);

    if (!subblock_mode) {
        // normal block
        old_addr = read(bid);
        new_addr = alloc(new_bid);
        nlivenodes--;

        // move
        memcpy(new_addr, old_addr, nodesize);

        // the entire block becomes stale
        addStaleBlock(bid * nodesize, nodesize);
        return new_addr;

    } else {
        // subblock

        // move the target subblock
        // into the current subblock set
        old_addr = _read(_bid, sb);

        new_idx = subblock[sb].nblocks;
        for (i=0 ; i<subblock[sb].nblocks ; ++i){
            if (subblock[sb].bitmap[i] == 0) {
                new_idx = i;
                break;
            }
        }
        if (subblock[sb].bid == BLK_NOT_FOUND ||
            new_idx == subblock[sb].nblocks ||
            !file->isWritable(subblock[sb].bid)) {
            // There is no free slot in the parent block, OR
            // the parent block is not writable.

            // Mark all unused subblocks in the current parent block as stale
            if (subblock[sb].bid != BLK_NOT_FOUND) {
                for (i=0; i<subblock[sb].nblocks; ++i) {
                    if (subblock[sb].bitmap[i] == 0) {
                        addStaleBlock( (subblock[sb].bid * nodesize) +
                                           (i * subblock[sb].sb_size),
                                       subblock[sb].sb_size);
                    }
                }
            }

            // Allocate new parent block.
            new_addr = _alloc(_new_bid, sb);
            nlivenodes--;
            subblock[sb].bid = _new_bid;
            memset(subblock[sb].bitmap, 0, subblock[sb].nblocks);
            new_idx = 0;
        } else {
            // just append to the current block
            new_addr = _read(subblock[sb].bid, sb);
        }

        subblock[sb].bitmap[new_idx] = 1;
        bid2subbid(subblock[sb].bid, sb, new_idx, new_bid);
        setDirty(subblock[sb].bid);

        // move
        memcpy((uint8_t*)new_addr + subblock[sb].sb_size * new_idx,
               (uint8_t*)old_addr + subblock[sb].sb_size * idx,
               subblock[sb].sb_size);

        // Also mark the target (old) subblock as stale
        addStaleBlock( (_bid * nodesize) + (idx * subblock[sb].sb_size),
                       subblock[sb].sb_size);

        return (uint8_t*)new_addr + subblock[sb].sb_size * new_idx;
    }
}

void BTreeBlkHandle::remove(bid_t bid)
{
    bid_t _bid;
    int i, nitems;
    bool subblock_mode;
    size_t sb, idx;

    sb = idx = 0;
    subbid2bid(bid, sb, idx, _bid);
    subblock_mode = isSubblock(bid);

    if (subblock_mode) {
        // subblock
        if (subblock[sb].bid == _bid) {
            // erase bitmap
            subblock[sb].bitmap[idx] = 0;
            // if all slots are empty, invalidate the block
            nitems = 0;
            for (i = 0 ; i < subblock[sb].nblocks ; ++i){
                if (subblock[sb].bitmap) {
                    nitems++;
                }
            }
            if (nitems == 0) {
                subblock[sb].bid = BLK_NOT_FOUND;
                nlivenodes--;
                addStaleBlock(_bid * nodesize, nodesize);
            }
        }
    } else {
        // normal block
        nlivenodes--;
        addStaleBlock(_bid * nodesize, nodesize);
    }
}

bool BTreeBlkHandle::isWritable(bid_t bid)
{
    bid_t _bid;
    bid_t filebid;
    size_t sb, idx;

    sb = idx = 0;
    subbid2bid(bid, sb, idx, _bid);
    filebid = _bid / nnodeperblock;

    return file->isWritable(filebid);
}

void BTreeBlkHandle::setDirty(bid_t bid)
{
    struct list_elem *e;
    struct btreeblk_block *block;
    bid_t _bid;
    bid_t filebid;
    size_t sb, idx;

    sb = idx = 0;
    subbid2bid(bid, sb, idx, _bid);
    filebid = _bid / nnodeperblock;

#ifdef __BTREEBLK_READ_TREE
    // AVL-tree
    struct btreeblk_block query;
    query.bid = filebid;
    struct avl_node *a;
    a = avl_search(&read_tree, &query.avl, _btreeblk_bid_cmp);
    if (a) {
        block = _get_entry(a, struct btreeblk_block, avl);
        block->dirty = 1;
    }
#else
    // list
    e = list_begin(&read_list);
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

void BTreeBlkHandle::setSBNo(bid_t bid, int sb_no)
{
    struct list_elem *e;
    struct btreeblk_block *block;
    bid_t _bid;
    bid_t filebid;
    size_t sb, idx;

    sb = idx = 0;
    subbid2bid(bid, sb, idx, _bid);
    filebid = _bid / nnodeperblock;

    e = list_begin(&alc_list);
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
    a = avl_search(&read_tree, &query.avl, _btreeblk_bid_cmp);
    if (a) {
        block = _get_entry(a, struct btreeblk_block, avl);
        block->sb_no = sb_no;
    }
#else
    // list
    e = list_begin(&read_list);
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

size_t BTreeBlkHandle::getBlockSize(bid_t bid)
{
    bid_t _bid;
    size_t sb, idx;

    if (isSubblock(bid) && bid != BLK_NOT_FOUND) {
        subbid2bid(bid, sb, idx, _bid);
        return subblock[sb].sb_size;
    } else {
        return nodesize;
    }
}

void * BTreeBlkHandle::allocSub(bid_t& bid)
{
    int i;
    void *addr;

    if (n_subblocks == 0) {
        return alloc(bid);
    }

    // check current block is available
    if (subblock[0].bid != BLK_NOT_FOUND) {
        if (file->isWritable(subblock[0].bid)) {
            // check if there is an empty slot
            for (i=0 ; i<subblock[0].nblocks ; ++i){
                if (subblock[0].bitmap[i] == 0) {
                    // return subblock
                    subblock[0].bitmap[i] = 1;
                    bid2subbid(subblock[0].bid, 0, i, bid);
                    addr = _read(subblock[0].bid, 0);
                    setDirty(subblock[0].bid);
                    return ((uint8_t*)addr + subblock[0].sb_size * i);
                }
            }
        } else {
            // we have to mark all unused slots as stale
            size_t idx;
            for (idx = 0 ; idx < subblock[0].nblocks ; ++idx) {
                if (subblock[0].bitmap[idx] == 0) {
                    addStaleBlock( (subblock[0].bid * nodesize) +
                                       (idx * subblock[0].sb_size),
                                   subblock[0].sb_size);
                }
            }
        }
    }

    // existing subblock cannot be used .. give it up & allocate new one
    addr = _alloc(subblock[0].bid, 0);
    memset(subblock[0].bitmap, 0, subblock[0].nblocks);
    i = 0;
    subblock[0].bitmap[i] = 1;
    bid2subbid(subblock[0].bid, 0, i, bid);
    return (void*)((uint8_t*)addr + subblock[0].sb_size * i);
}

void * BTreeBlkHandle::enlargeNode(bid_t old_bid,
                                   size_t req_size,
                                   bid_t& new_bid)
{
    uint32_t i;
    bid_t bid;
    size_t src_sb, src_idx, src_nitems;
    size_t dst_sb, dst_idx, dst_nitems;
    void *src_addr, *dst_addr;

    if (!isSubblock(old_bid)) {
        return NULL;
    }
    src_addr = dst_addr = NULL;
    subbid2bid(old_bid, src_sb, src_idx, bid);

    dst_sb = 0;
    // find sublock that can accommodate req_size
    for (i = src_sb+1 ; i < n_subblocks ; ++i){
        if (subblock[i].sb_size > req_size) {
            dst_sb = i;
            break;
        }
    }

    src_nitems = 0;
    for (i = 0 ; i < subblock[src_sb].nblocks ; ++i){
        if (subblock[src_sb].bitmap[i]) {
            src_nitems++;
        }
    }

    dst_nitems = 0;
    if (dst_sb > 0) {
        dst_idx = subblock[dst_sb].nblocks;
        for (i = 0 ; i < subblock[dst_sb].nblocks ; ++i){
            if (subblock[dst_sb].bitmap[i]) {
                dst_nitems++;
            } else if (dst_idx == subblock[dst_sb].nblocks) {
                dst_idx = i;
            }
        }
    }

    if (dst_nitems == 0) {
        // destination block is empty
        dst_idx = 0;
        if (src_nitems == 1 &&
            bid == subblock[src_sb].bid &&
            file->isWritable(bid)) {
            //2 case 1
            // if there's only one subblock in the source block, and
            // the source block is still writable and allocable,
            // then switch source block to destination block
            src_addr = _read(bid, src_sb);
            dst_addr = src_addr;
            if (dst_sb > 0) {
                subblock[dst_sb].bid = subblock[src_sb].bid;
            } else {
                new_bid = subblock[src_sb].bid;
            }
            setDirty(subblock[src_sb].bid);
            // we MUST change block->sb_no value since subblock is switched.
            // dst_sb == 0: regular block, otherwise: sub-block
            setSBNo( subblock[src_sb].bid, ((dst_sb) ? (dst_sb) : (-1)) );

            if (src_idx > 0 || dst_addr != src_addr) {
                // move node to the beginning of the block
                memmove(dst_addr,
                        (uint8_t*)src_addr + subblock[src_sb].sb_size * src_idx,
                        subblock[src_sb].sb_size);
            }
            if (dst_sb > 0) {
                subblock[dst_sb].bitmap[dst_idx] = 1;
            }
            if (bid == subblock[src_sb].bid) {
                // remove existing source block info
                subblock[src_sb].bid = BLK_NOT_FOUND;
                memset(subblock[src_sb].bitmap, 0,
                       subblock[src_sb].nblocks);
            }

        } else {
            //2 case 2
            // if there are more than one subblock in the source block,
            // or no more subblock is allocable from the current source block,
            // then allocate a new destination block and move the target subblock only.
            src_addr = _read(bid, src_sb);

            if (dst_sb > 0) {
                // case 2-1: enlarged block will be also a subblock
                dst_addr = _alloc(subblock[dst_sb].bid, dst_sb);
                memcpy((uint8_t*)dst_addr + subblock[dst_sb].sb_size * dst_idx,
                       (uint8_t*)src_addr + subblock[src_sb].sb_size * src_idx,
                       subblock[src_sb].sb_size);
                subblock[dst_sb].bitmap[dst_idx] = 1;
            } else {
                // case 2-2: enlarged block will be a regular block
                dst_addr = alloc(new_bid);
                memcpy((uint8_t*)dst_addr,
                       (uint8_t*)src_addr + subblock[src_sb].sb_size * src_idx,
                       subblock[src_sb].sb_size);
            }

            // Mark the source subblock as stale.
            if (bid == subblock[src_sb].bid) {
                // The current source block may be still allocable.
                // Remove the corresponding bitmap from the source bitmap.
                // All unused subblocks will be marked as stale when this block
                // becomes immutable.
                subblock[src_sb].bitmap[src_idx] = 0;

                // TODO: what if FDB handle is closed without fdb_commit() ?
            } else if (bid != BLK_NOT_FOUND) {
                // The current source block will not be used for allocation anymore.
                // Mark the corresponding subblock as stale.
                addStaleBlock( (bid * nodesize) + (src_idx * subblock[src_sb].sb_size),
                               subblock[src_sb].sb_size );
            }
        }
    } else {
        //2 case 3
        // destination block exists
        // (happens only when the destination block is
        //  a parent block of subblock set)
        src_addr = _read(bid, src_sb);
        if (file->isWritable(subblock[dst_sb].bid) &&
            dst_idx != subblock[dst_sb].nblocks) {
            // case 3-1
            dst_addr = _read(subblock[dst_sb].bid, dst_sb);
            setDirty(subblock[dst_sb].bid);
        } else {
            // case 3-2: allocate new destination block
            dst_addr = _alloc(subblock[dst_sb].bid, dst_sb);
            memset(subblock[dst_sb].bitmap, 0, subblock[dst_sb].nblocks);
            dst_idx = 0;
        }

        memcpy( (uint8_t*)dst_addr + subblock[dst_sb].sb_size * dst_idx,
                (uint8_t*)src_addr + subblock[src_sb].sb_size * src_idx,
                subblock[src_sb].sb_size );
        subblock[dst_sb].bitmap[dst_idx] = 1;

        // Mark the source subblock as stale.
        if (bid == subblock[src_sb].bid) {
            // The current source block may be still allocable.
            // Remove the corresponding bitmap from the source bitmap.
            // All unused subblocks will be marked as stale when this block
            // becomes immutable.
            subblock[src_sb].bitmap[src_idx] = 0;
        } else if (subblock[src_sb].bid != BLK_NOT_FOUND) {
            // The current source block will not be used for allocation anymore.
            // Mark the corresponding subblock as stale.
            addStaleBlock( (bid * nodesize) + (src_idx * subblock[src_sb].sb_size) ,
                           subblock[src_sb].sb_size );
        }
    }

    if (dst_sb > 0) {
        // sub block
        bid2subbid(subblock[dst_sb].bid, dst_sb, dst_idx, new_bid);
        return (uint8_t*)dst_addr + subblock[dst_sb].sb_size * dst_idx;
    } else {
        // whole block
        return dst_addr;
    }
}

fdb_status BTreeBlkHandle::_flushBuffer()
{
    // flush and write all items in allocation list
    struct list_elem *e;
    struct btreeblk_block *block;
    int writable;
    fdb_status status = FDB_RESULT_SUCCESS;

    // write and free items in allocation list
    e = list_begin(&alc_list);
    while(e){
        block = _get_entry(e, struct btreeblk_block, le);
        writable = file->isWritable(block->bid);
        if (writable) {
            status = writeDirtyBlock(block);
            if (status != FDB_RESULT_SUCCESS) {
                return status;
            }
        } else {
            return FDB_RESULT_WRITE_FAIL;
        }

        if (block->pos + nodesize > file->getBlockSize() || !writable) {
            // remove from alc_list and insert into read list
            e = list_remove(&alc_list, &block->le);
            block->dirty = 0;
            list_push_front(&read_list, &block->le);
#ifdef __BTREEBLK_READ_TREE
            avl_insert(&read_tree, &block->avl, _btreeblk_bid_cmp);
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
    a = avl_first(&read_tree);
    while (a) {
        block = _get_entry(a, struct btreeblk_block, avl);
        a = avl_next(a);

        if (block->dirty) {
            // write back only when the block is modified
            status = writeDirtyBlock(block);
            if (status != FDB_RESULT_SUCCESS) {
                return status;
            }
            block->dirty = 0;
        }

        if (block->age >= BTREEBLK_AGE_LIMIT) {
            list_remove(&read_list, &block->le);
            avl_remove(&read_tree, &block->avl);
            freeDirtyBlock(block);
        } else {
            block->age++;
        }
    }
#else
    // list
    e = list_begin(&read_list);
    while(e){
        block = _get_entry(e, struct btreeblk_block, le);

        if (block->dirty) {
            // write back only when the block is modified
            status = writeDirtyBlock(block);
            if (status != FDB_RESULT_SUCCESS) {
                return status;
            }
            block->dirty = 0;
        }

        if (block->age >= BTREEBLK_AGE_LIMIT) {
            e = list_remove(&read_list, &block->le);
            freeDirtyBlock(block);
        } else {
            block->age++;
            e = list_next(e);
        }
    }
#endif

    return status;
}

void BTreeBlkHandle::discardBlocks()
{
    // discard all writable blocks in the read list
    struct list_elem *e;
    struct btreeblk_block *block;

    // free items in read list
#ifdef __BTREEBLK_READ_TREE
    // AVL-tree
    struct avl_node *a;
    a = avl_first(&read_tree);
    while (a) {
        block = _get_entry(a, struct btreeblk_block, avl);
        a = avl_next(a);

        list_remove(&read_list, &block->le);
        avl_remove(&read_tree, &block->avl);
        freeDirtyBlock(block);
    }
#else
    // list
    e = list_begin(&read_list);
    while(e){
        block = _get_entry(e, struct btreeblk_block, le);
        e = list_next(&block->le);

        list_remove(&read_list, &block->le);
        freeDirtyBlock(block);
    }
#endif
}

void BTreeBlkHandle::resetSubblockInfo()
{
#ifdef __BTREEBLK_SUBBLOCK
    uint32_t sb_no, idx;

    for (sb_no = 0 ; sb_no < n_subblocks ; ++sb_no){
        if (subblock[sb_no].bid != BLK_NOT_FOUND) {
            // first of all, make all unused subblocks as stale
            for (idx = 0 ; idx < subblock[sb_no].nblocks ; ++idx) {
                if (subblock[sb_no].bitmap[idx] == 0) {
                    addStaleBlock( (subblock[sb_no].bid * nodesize) +
                                       (idx * subblock[sb_no].sb_size),
                                   subblock[sb_no].sb_size );
                }
            }
            subblock[sb_no].bid = BLK_NOT_FOUND;
        }
        // clear all info in each subblock set
        memset(subblock[sb_no].bitmap, 0, subblock[sb_no].nblocks);
    }
#endif
}

fdb_status BTreeBlkHandle::flushBuffer()
{
    struct list_elem *e;
    struct btreeblk_block *block;
    fdb_status status = FDB_RESULT_SUCCESS;

    // flush all dirty items
    status = _flushBuffer();
    if (status != FDB_RESULT_SUCCESS) {
        return status;
    }

    // remove all items in lists
    e = list_begin(&alc_list);
    while(e) {
        block = _get_entry(e, struct btreeblk_block, le);
        e = list_remove(&alc_list, &block->le);

        block->dirty = 0;
        list_push_front(&read_list, &block->le);
#ifdef __BTREEBLK_READ_TREE
        avl_insert(&read_tree, &block->avl, _btreeblk_bid_cmp);
#endif
    }
    return status;
}

void BTreeBlkHandle::operationEnd()
{
    // do nothing for now
}


