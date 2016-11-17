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

#pragma once

#include <unordered_map>

#include "common.h"
#include "avltree.h"
#include "atomic.h"
#include "filemgr.h"
#include "bnode.h"
#include "bnodecache.h"



/**
 * B+tree node manager class definition.
 */
class BnodeMgr {
public:
    BnodeMgr();

    ~BnodeMgr();

    FileMgr* getFile() const {
        return file;
    }
    void setFile(FileMgr *_file);

    void setLogCallback(ErrLogCallback *_log_callback) {
        logCallback = _log_callback;
    }

    ErrLogCallback * getLogCallback() {
        return logCallback;
    }

    /**
     * Add a dirty node to 'dirtyNodes' set.
     *
     * @param bnode Pointer to dirty node.
     */
    void addDirtyNode(Bnode* bnode);

    /**
     * Remove the given dirty node from 'dirtyNodes' set.
     *
     * @param bnode Pointer to dirty node.
     */
    void removeDirtyNode(Bnode* bnode);

    /**
     * Make given clean node writable.
     * If other thread is currently accessing the same clean node,
     * create a dirty clone of the node. If the clean node is being
     * accessed by the caller thread only, then directly switch the
     * clean node as dirty.
     *
     * @param clean_bnode Pointer to clean node.
     * @return Writable dirty node.
     */
    Bnode* getMutableNodeFromClean(Bnode* clean_bnode);

    /**
     * Read a B+tree node corresponding to the given offset.
     * This API first searches the in-memory cache, and then read the DB
     * file on cache miss.
     *
     * @param offset File offset of the index node to read.
     * @return Bnode class instance.
     */
    Bnode* readNode(uint64_t offset);

    /**
     * Calculate and assign a DB file offset, where the given dirty node
     * will be written back. Note that 16-byte meta data is added for
     * each index block, and it is also included in the offset calculation.
     *
     * @param bnode Pointer to dirty node.
     * @return Offset where the dirty node will be written.
     */
    uint64_t assignDirtyNodeOffset( Bnode *bnode );

    /**
     * Flush all dirty nodes into B+tree node cache.
     */
    void flushDirtyNodes();

    /**
     * Decrease the reference counter of the given clean node, to make it
     * ejectable from the cache.
     *
     * @param bnode Pointer to
     */
    void releaseCleanNode( Bnode *bnode );

    /**
     * Decrease reference counters of all present clean nodes.
     */
    void releaseCleanNodes();

private:
    // FileMgr instance.
    FileMgr *file;
    // Set of clean nodes that are currently accessed by the B+tree.
    std::unordered_set<Bnode*> cleanNodes;
    // Set of dirty nodes that are created in the current batch.
    std::unordered_set<Bnode*> dirtyNodes;
    // Latest block ID for dirty node allocation.
    bid_t curBid;
    // Latest offset in the latest block 'curBid'.
    size_t curOffset;
    // Error log callback function.
    ErrLogCallback *logCallback;
};

