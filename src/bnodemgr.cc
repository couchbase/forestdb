/* -*- Mode: C++; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2016 Couchbase, Inc
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
#include <unordered_map>

#include "libforestdb/forestdb.h"
#include "fdb_engine.h"
#include "fdb_internal.h"
#include "internal_types.h"
#include "bnode.h"
#include "bnodemgr.h"


static const size_t block_meta_size = sizeof(IndexBlkMeta);

BnodeMgr::BnodeMgr() :
    file(nullptr),
    curBid(BLK_NOT_FOUND),
    curOffset(0),
    logCallback(nullptr),
    nlivenodes(0),
    ndeltanodes(0)
{ }

BnodeMgr::~BnodeMgr()
{
    Bnode *bnode;
    for (auto &entry: dirtyNodes) {
        bnode = entry;
        delete bnode;
    }
}

void BnodeMgr::setFile(FileMgr *_file)
{
    file = _file;
}

void BnodeMgr::addDirtyNode(Bnode* bnode)
{
    dirtyNodes.insert( bnode );
}

void BnodeMgr::removeDirtyNode(Bnode* bnode)
{
    dirtyNodes.erase( bnode );
}

Bnode* BnodeMgr::getMutableNodeFromClean(Bnode* clean_bnode)
{
    Bnode* bnode_out;
    fdb_status ret = BnodeCacheMgr::get()->invalidateBnode(file, clean_bnode);

    // make the region of previous clean node as stale.
    markBnodeStale(clean_bnode);

    if (ret == FDB_RESULT_SUCCESS) {
        // clean node is ejected from cache.
        // now we can modify it as a dirty node without cloning.
        releaseCleanNode(clean_bnode);
        clean_bnode->setCurOffset(BLK_NOT_FOUND);
        clean_bnode->clearBidList();
        bnode_out = clean_bnode;
    } else {
        // clean node cannot be ejected.
        // make a dirty clone of the node.
        bnode_out = clean_bnode->cloneNode();
    }
    addDirtyNode(bnode_out);

    return bnode_out;
}

void BnodeMgr::markBnodeStale(Bnode *bnode)
{
    size_t arr_size = bnode->getBidListSize();
    size_t i;
    size_t blocksize = file->getBlockSize();
    uint64_t node_offset = bnode->getCurOffset();
    size_t node_size = bnode->getNodeSize();

    if (arr_size == 1) {
        // the node is written in a single block
        if (node_offset + node_size + sizeof(IndexBlkMeta) == blocksize) {
            // there is no more data but index meta in the block
            //  => include index meta area.
            file->addStaleRegion(node_offset, node_size + sizeof(IndexBlkMeta));
        } else {
            file->addStaleRegion(node_offset, node_size);
        }
        return;
    }

    // if an index node is written over multiple blocks
    // its stale region can be as follows:
    // (this is exactly the same with that for document blocks).

    // (M: index block meta, 16 bytes)
    //          +----------------+
    // block 0: |         //////M|
    //          +----------------+
    //          +----------------+
    // block 1: |///////////////M|
    //          +----------------+
    //          +----------------+
    // block 2: |//////         M|
    //          +----------------+
    //
    // block 0 (first block)       : (blocksize - offset) becomes stale.
    // block 1 (intermediate block): the entire block becomes stale.
    // block 2 (last block)        : rest space becomes stale.
    //  * rest space: bnode length - (stale region size of block 0~1) +
    //                block meta size * (# blocks - 1).
    //    => due to index block meta at the end of each block,
    //       we should add the sum of block meta size.
    //
    // example) blocksize = 100, block meta size = 10,
    //          bnode offset = 50, bnode length = 200
    //
    // block 0: 50 ~ 100 becomes stale (bnode data: 40, stale size: 50 (including meta)).
    // block 1: 0 ~ 100 becomes stale (bnode data: 90, stale size: 100 (including meta)).
    // block 2: 0 ~ 70 becomes stale (bnode data: 70, stale size: 70).
    //          where 70 = 200 - (50 + 100) + (10 * 2);

    for (i=0; i<arr_size; ++i) {
        if (i==0) {
            // the first block
            file->addStaleRegion(node_offset, blocksize - (node_offset % blocksize));
        } else if (i < arr_size - 1) {
            // intermediate block => entire block
            file->addStaleRegion(bnode->getBidFromList(i) * blocksize, blocksize);
        } else {
            // the last block
            size_t rest_size = node_size;
            rest_size += sizeof(IndexBlkMeta) * (arr_size - 1); // meta size
            rest_size -= (blocksize - (node_offset % blocksize)); // first block
            rest_size -= (blocksize * (arr_size - 2)); // intermediate blocks
            file->addStaleRegion(bnode->getBidFromList(i) * blocksize, rest_size);
        }
    }
}

Bnode* BnodeMgr::readNode(uint64_t offset)
{
    Bnode* bnode_out;

    int ret = BnodeCacheMgr::get()->read(file, &bnode_out, offset);
    if (ret <= 0) {
        fdb_log(logCallback, static_cast<fdb_status>(ret),
                "Failed to read the B+tree index node at "
                "offset %" _F64 " in a file %s",
                offset, file->getFileName());
        return nullptr;
    }
    bnode_out->setCurOffset(offset);

    if (cleanNodes.find(bnode_out) != cleanNodes.end()) {
        // Same clean node already exists in the current BnodeMgr,
        // so we should not increase its ref count once again.
        // => decrease the ref count that was increased by BnodeCache.
        bnode_out->decRefCount();
    } else {
        cleanNodes.insert( bnode_out );
    }

    return bnode_out;
}

uint64_t BnodeMgr::assignDirtyNodeOffset( Bnode *bnode )
{
    size_t blocksize = file->getBlockSize();
    size_t blocksize_avail = blocksize - block_meta_size;
    size_t nodesize = bnode->getNodeSize();
    uint64_t offset;

    if ( curBid == BLK_NOT_FOUND ||
         !file->isWritable( curBid ) ||
         curOffset + 4 > blocksize_avail ) {
        // allocate a new block if
        // 1) first block has not been allocated yet, OR
        // 2) the latest block (curBid) is not writable, OR
        // 3) remaining space is smaller than 4 bytes
        //    => to ensure that at least the first 4 bytes of an index node
        //       is written in the same block, to fetch the size of node
        //       (stored in the first 4 bytes) easily.
        curBid = file->alloc_FileMgr(nullptr);
        curOffset = 0;
    }

    offset = curBid * blocksize + curOffset;
    size_t room = blocksize_avail - curOffset;

    bnode->clearBidList();
    if ( room >= nodesize ) {
        // we don't need to allocate more blocks
        curOffset += nodesize;
        bnode->addBidList(curBid);
        return offset;
    }

    // otherwise .. allocate more blocks.
    size_t n_blocks;
    size_t remaining_size;

    remaining_size = nodesize - room;
    bnode->addBidList(curBid);

    // e.g.) when blocksize_avail = 1000,
    // remaining_size 1 ~ 1000: 1 block
    // remaining_size 1001 ~ 2000: 2 blocks ...
    n_blocks = ( (remaining_size-1) / blocksize_avail ) + 1;

    size_t i;
    for (i=0; i<n_blocks; ++i) {
        curBid = file->alloc_FileMgr(nullptr);
        bnode->addBidList(curBid);
    }

    if (remaining_size == blocksize_avail) {
        // no available space in the current block.
        // we should allocate a new block in the next turn.
        curOffset = remaining_size;
        curBid = BLK_NOT_FOUND;
    } else {
        curOffset = remaining_size % blocksize_avail;
    }

    return offset;
}

void BnodeMgr::markEndOfIndexBlocks()
{
    // mark the rest of space of the current block as stale
    size_t blocksize = file->getBlockSize();
    file->addStaleRegion(curBid * blocksize + curOffset, blocksize - curOffset);

    // add block marker
    BnodeCacheMgr::get()->addLastBlockMeta(file, curBid);
}

void BnodeMgr::moveDirtyNodesToBcache()
{
    int ret;
    for (auto &entry: dirtyNodes) {
        entry->fitMemSpaceToNodeSize();
        ret = BnodeCacheMgr::get()->write(file, entry, entry->getCurOffset());
        if (ret <= 0) {
            fdb_log(logCallback, static_cast<fdb_status>(ret),
                    "Failed to write the B+tree index node at "
                    "offset %" _F64 " in a file %s",
                    entry->getCurOffset(), file->getFileName());
        }
        // Note: we should not delete 'bnode' here
        //       as they will be relesed by cache during ejection.
    }
    dirtyNodes.clear();

    // BnodeMgr doesn't need to flush BnodeCache here:
    // it will be done in ForestDB-level functions.
}

void BnodeMgr::releaseCleanNode( Bnode *bnode )
{
    bnode->decRefCount();
    cleanNodes.erase( bnode );
}

void BnodeMgr::releaseCleanNodes()
{
    for (auto &entry: cleanNodes) {
        entry->decRefCount();
    }
    cleanNodes.clear();
}


