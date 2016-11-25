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

#ifndef _JSAHN_BTREEBLOCK_H
#define _JSAHN_BTREEBLOCK_H

#include "filemgr.h"
#include "list.h"
#include "avltree.h"
#include "libforestdb/fdb_errors.h"

#ifdef __cplusplus
extern "C" {
#endif

struct btreeblk_block;

struct btreeblk_subblocks{
    bid_t bid;
    uint32_t sb_size;
    uint16_t nblocks;
    uint8_t *bitmap;
};

class BTreeBlkHandle {
public:
    BTreeBlkHandle(FileMgr *_file, uint32_t _nodesize);

    ~BTreeBlkHandle();

    /**
     * Allocate an index block.
     *
     * @param bid Reference to block ID that will be allocated as a result of this
     *        API call.
     */
    void * alloc(bid_t& bid);

    /**
     * Read an index block.
     */
    void * read(bid_t bid);

    /**
     * Move an index block to another block.
     *
     * @param bid Target block ID.
     * @param bid Reference to new block ID that will be allocated as a result of
     *        this API call.
     */
    void * move(bid_t bid, bid_t& new_bid);

    /**
     * Remove an index block.
     */
    void remove(bid_t bid);

    /**
     * Return true if the given block is writable.
     */
    bool isWritable(bid_t bid);

    /**
     * Set dirty flag for the given block.
     */
    void setDirty(bid_t bid);

    /**
     * Get actual block size.
     */
    size_t getBlockSize(bid_t bid);

    /**
     * Allocate a sub index block.
     *
     * @param bid Reference to block ID that will be allocated as a result of
     *        this API call.
     */
    void * allocSub(bid_t& bid);

    /**
     * Enlarge the size of a given sub index block to the requested size.
     *
     * @param old_bid Target block ID.
     * @param req_size Requested block size.
     * @param new_bid Reference to block ID that will be allocated as a result of
     *        this API call.
     */
    void * enlargeNode(bid_t old_bid,
                       size_t req_size,
                       bid_t& new_bid);

    /**
     * Discard all writable blocks in the buffer.
     */
    void discardBlocks();

    /**
     * Clear all the current sub block allocation info, to prevent allocating a
     * new sub block in existing (i.e., already used for other sub blocks) block.
     */
    void resetSubblockInfo();

    /**
     * Write all dirty index blocks into disk, and flush read buffer.
     */
    fdb_status flushBuffer();

    /**
     * Reserved API that will be called at the end of each tree operation.
     */
    void operationEnd();

    inline void setDirtyUpdate(struct filemgr_dirty_update_node *node)
    {
        dirty_update = node;
    }

    inline void setDirtyUpdateWriter(struct filemgr_dirty_update_node *node)
    {
        dirty_update_writer = node;
    }

    inline void clearDirtyUpdate()
    {
        dirty_update = dirty_update_writer = NULL;
    }

    inline struct filemgr_dirty_update_node* getDirtyUpdate()
    {
        return dirty_update;
    }

    void setLogCallback(ErrLogCallback *_log_callback) {
        log_callback = _log_callback;
    }

    ErrLogCallback * getLogCallback() {
        return log_callback;
    }

    int64_t getNLiveNodes() const {
        return nlivenodes;
    }

    void setNLiveNodes(int64_t _nlivenodes) {
        nlivenodes = _nlivenodes;
    }

    int64_t getNDeltaNodes() const {
        return ndeltanodes;
    }

    void setNDeltaNodes(int64_t _ndeltanodes) {
        ndeltanodes = _ndeltanodes;
    }

    uint32_t getNodeSize() const {
        return nodesize;
    }

    uint16_t getNNodePerBlock() const {
        return nnodeperblock;
    }

    FileMgr *getFile() const {
        return file;
    }

    uint32_t getNSubblocks() const {
        return n_subblocks;
    }

    struct btreeblk_subblocks * getSubblockArray() const {
        return subblock;
    }

private:
    uint32_t nodesize;
    uint16_t nnodeperblock;
    int64_t nlivenodes;
    int64_t ndeltanodes;
    struct list alc_list;
    struct list read_list;
    FileMgr *file;
    ErrLogCallback *log_callback;

#ifdef __BTREEBLK_READ_TREE
    struct avl_tree read_tree;
#endif
#ifdef __BTREEBLK_BLOCKPOOL
    struct list blockpool;
#endif

#ifdef __BTREEBLK_CACHE
    uint16_t bin_size;
    struct list recycle_bin;
    struct btreeblk_block *cache[BTREEBLK_CACHE_LIMIT];
#endif

    uint32_t n_subblocks;
    struct btreeblk_subblocks *subblock;
    // dirty update entry for read
    struct filemgr_dirty_update_node *dirty_update;
    // dirty update entry for the current WAL flushing
    struct filemgr_dirty_update_node *dirty_update_writer;

    void getAlignedBlock(struct btreeblk_block *block);
    void freeAlignedBlock(struct btreeblk_block *block);
    void freeDirtyBlock(struct btreeblk_block *block);
    fdb_status writeDirtyBlock(struct btreeblk_block *block);

    /**
     * True if given block is a sub index block.
     */
    inline bool isSubblock(bid_t subbid)
    {
        uint8_t flag;
        flag = (subbid >> (8 * (sizeof(bid_t)-2))) & 0x00ff;
        return flag;
    }

    /**
     * Convert a combination of block ID, sub block type number (indicates the type
     * size of sub block), and sub block index number (indicates the index number of
     * the sub block among the sub blocks in the same regular block) into a
     * manufactured block ID.
     *
     * @param bid Block ID.
     * @param subblock_no Sub block type number.
     * @param idx Sub block index number.
     * @param subbid Reference to block ID as a result of this API call.
     */
    inline void bid2subbid(bid_t bid, size_t subblock_no, size_t idx, bid_t& subbid)
    {
        bid_t flag;
        // to distinguish subblock_no==0 to non-subblock
        subblock_no++;
        flag = (subblock_no << 5) | idx;
        subbid = bid | (flag << (8 * (sizeof(bid_t)-2)));
    }

    /**
     * Extract block ID, sub block type number and sub block index number from a
     * manufactured block ID.
     *
     * @param subbid (Manufactured) block ID.
     * @param subblock_no Sub block type number as a result of this API call.
     * @param idx Sub block index number
     * @param bid Reference to block ID as a result of this API call.
     */
    inline void subbid2bid(bid_t subbid, size_t& subblock_no, size_t& idx, bid_t& bid)
    {
        uint8_t flag;
        flag = (subbid >> (8 * (sizeof(bid_t)-2))) & 0x00ff;
        subblock_no = flag >> 5;
        // to distinguish subblock_no==0 to non-subblock
        subblock_no -= 1;
        idx = flag & (0x20 - 0x01);
        bid = ((bid_t)(subbid << 16)) >> 16;
    }

    void * _alloc(bid_t& bid, int sb_no);

    /**
     * Endian-safe encode all sub blocks belonging to the given regular block
     */
    void encodeBlock(struct btreeblk_block *block);

    /**
     * Endian-safe decode all sub blocks belonging to the given regular block
     */
    void decodeBlock(struct btreeblk_block *block);

    void * _read(bid_t bid, int sb_no);

    inline void addStaleBlock(uint64_t pos, uint32_t len)
    {
        file->addStaleRegion(pos, len);
    }

    void setSBNo(bid_t bid, int sb_no);

    fdb_status _flushBuffer();
};


#ifdef __cplusplus
}
#endif

#endif
