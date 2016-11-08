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
    bCache(nullptr),
    file(nullptr),
    curBid(BLK_NOT_FOUND),
    curOffset(0),
    logCallback(nullptr)
{ }

BnodeMgr::~BnodeMgr()
{
    Bnode *bnode;
    for (auto &entry: dirtyNodes) {
        bnode = entry;
        delete bnode;
    }
}

void BnodeMgr::setFile(FileMgr *_file, BnodeCacheMgr *_bcache)
{
    file = _file;
    bCache = _bcache;
}

void BnodeMgr::addDirtyNode(Bnode* bnode)
{
    dirtyNodes.insert( bnode );
}

void BnodeMgr::removeDirtyNode(Bnode* bnode)
{
    dirtyNodes.erase( bnode );
}

Bnode* BnodeMgr::readNode(uint64_t offset)
{
    Bnode* bnode_out;

    int ret = bCache->read(file, &bnode_out, offset);
    if (ret <= 0) {
        fdb_log(logCallback, static_cast<fdb_status>(ret),
                "Failed to read the B+tree index node at "
                "offset %" _F64 " in a file %s",
                offset, file->getFileName());
        return nullptr;
    }
    bnode_out->setCurOffset(offset);
    cleanNodes.insert( bnode_out );

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
    curOffset = remaining_size % blocksize_avail;

    return offset;
}

void BnodeMgr::flushDirtyNodes()
{
    int ret;
    for (auto &entry: dirtyNodes) {
        ret = bCache->write(file, entry, entry->getCurOffset());
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
    bCache->flush(file);
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


