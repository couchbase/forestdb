/* -*- Mode: C++; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2015 Couchbase, Inc
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

#ifndef _FDB_STALEBLOCK_H
#define _FDB_STALEBLOCK_H

#include "libforestdb/fdb_types.h"
#include "libforestdb/fdb_errors.h"
#include "common.h"

#include <list>
#include <map>

#include "filemgr.h"
#include "avltree.h"

struct reusable_block {
    bid_t bid;
    bid_t count;
};

typedef struct {
    size_t n_blocks;
    struct reusable_block *blocks;
} reusable_block_list;

typedef struct {
    filemgr_header_revnum_t revnum;
    bid_t bid;
} stale_header_info;


// in-memory structure for stale info
// (corresponding to a system doc)
class StaleInfoEntry {
public:
    StaleInfoEntry() : ctx(nullptr), offset(0), doclen(0), ctxlen(0), comp_ctxlen(0) { }

    // document body
    void *ctx;
    // document offset
    uint64_t offset;
    // actual document length on disk
    uint64_t doclen;
    // length of 'ctx'
    uint32_t ctxlen;
    // length of compressed 'ctx'
    uint32_t comp_ctxlen;
};

// in-memory structure for stale info
// (corresponding to a commit, an entry of StaleInfoTree)
class StaleInfoCommit {
public:
    // commit revision number
    filemgr_header_revnum_t revnum;
    // list of system docs (there will be more than one doc)
    std::list<StaleInfoEntry *> infoList;
};

/**
 * Skeleton class for StaleDataManager. It does nothing.
 * This class is used only when Stale Block related code is not compiled with
 * filemgr layer.
 */
class StaleDataManagerBase {
public:
    StaleDataManagerBase() : file(nullptr) { }
    virtual ~StaleDataManagerBase() { }

    virtual void addStaleRegion(uint64_t pos, size_t len) { }
    virtual void markDocStale(uint64_t offset, size_t doclen) { }
    virtual struct stale_regions getActualStaleRegionsofDoc(uint64_t offset,
                                                            size_t doclen) {
        struct stale_regions ret;
        ret.n_regions = 0;
        ret.regions = NULL;
        return ret;
    }
    virtual void loadInmemStaleInfo(FdbKvsHandle *handle) { }

    virtual void gatherRegions(FdbKvsHandle *handle,
                               filemgr_header_revnum_t revnum,
                               bid_t prev_hdr,
                               uint64_t kv_info_offset,
                               fdb_seqnum_t seqnum,
                               bool from_mergetree) { }

    virtual reusable_block_list getReusableBlocks(FdbKvsHandle *handle,
                                               stale_header_info stale_header) {
        reusable_block_list ret;
        ret.n_blocks = 0;
        ret.blocks = nullptr;
        return ret;
    }
    virtual void rollbackStaleBlocks(FdbKvsHandle *handle,
                                   filemgr_header_revnum_t cur_revnum) { }

protected:
    // corresponding filemgr instance
    FileMgr *file;
    // temporary in-memory list of stale blocks
    std::list<stale_data*> staleList;
    // in-memory clone of system docs for reusable block info
    // (they are pointed to by stale-block-tree)
    std::map<filemgr_header_revnum_t, StaleInfoCommit *> staleInfoTree;
    // temporary tree for merging stale regions
    std::map<uint64_t, stale_data*>mergeTree;
    // indicates if staleInfoTree is loaded or not
    std::atomic<bool> staleInfoTreeLoaded;
};

/**
 * Actual stale data management class definition.
 */
class StaleDataManager : public StaleDataManagerBase {
public:
    // Constructor
    StaleDataManager(FileMgr *_file);
    // Destructor
    ~StaleDataManager();

    /**
     * Add an item into stale-block list of the given 'file'.
     *
     * @param pos Byte offset to the beginning of the stale region.
     * @param len Length of the stale region.
     * @return void.
     */
    void addStaleRegion(uint64_t pos, size_t len);

    /**
     * Mark the given document over the region {offset, length} as stale.
     * This function automatically calculates the additional space used for block
     * markers or block mata data, by internally calling getActualStaleLengthofDoc().
     *
     * @param offset Byte offset to the beginning of the document.
     * @param doclen Logical length of the document.
     * @return void.
     */
    void markDocStale(uint64_t offset, size_t doclen);

    /**
     * Calculate the actual space (including block markers) used for the given document
     * data, and return the list of regions to be marked as stale (if the given document
     * is not physically consecutive, more than one regions will be returned).
     *
     * @param offset Byte offset to the beginning of the document.
     * @param doclen Logical length of the document.
     * @return List of stale regions.
     */
    struct stale_regions getActualStaleRegionsofDoc(uint64_t offset,
                                                    size_t doclen);

    /**
     * Load all system documents pointed to by stale tree into memory.
     *
     * @param handle Pointer to ForestDB KV store handle.
     * @return void.
     */
    void loadInmemStaleInfo(FdbKvsHandle *handle);

    /**
     * Gather stale region info from stale list and store it as a system doc.
     *
     * @param handle Pointer to ForestDB KV store handle.
     * @param revnum Header revision number that will be stored as a key in stale tree.
     * @param prev_hdr Currently up-to-date header BID.
     * @param kv_info_offset Currently up-to-date KVS header doc offset.
     * @param seqnum Currently up-to-date seq number of the default KVS.
     * @param from_mergetree If true, gather stale regions from merge-tree
     *        (which contains remaining items after block reclaim) instead of stale
     *        list.
     * @return void.
     */
    void gatherRegions(FdbKvsHandle *handle,
                       filemgr_header_revnum_t revnum,
                       bid_t prev_hdr,
                       uint64_t kv_info_offset,
                       fdb_seqnum_t seqnum,
                       bool from_mergetree) {
        gatherRegions( handle, revnum, prev_hdr, kv_info_offset, seqnum,
                       staleList.end(), from_mergetree );
    }

    /**
     * Gather and merge all stale regions up to 'stale_header', and then return the list
     * of reusable blocks.
     *
     * @param handle Pointer to ForestDB KV store handle.
     * @param stale_header Revision number and block ID of a header. All stale regions
     *        corresponding to commit headers whose seq number is equal to or smaller
     *        than that of 'stale_header' are gathered and merged for block reusing.
     * @return List of reusable blocks.
     */
    reusable_block_list getReusableBlocks(FdbKvsHandle *handle,
                                          stale_header_info stale_header);

    /**
     * Remove all stale-tree entries since the rollback point.
     *
     * @param handle Pointer to ForestDB KV store handle.
     * @param cur_revnum Revision number of the header that will be appended next.
     * @return void.
     */
    void rollbackStaleBlocks(FdbKvsHandle *handle,
                                   filemgr_header_revnum_t cur_revnum);

private:
    /**
     * Get the actual length of the given doc, including the meta data of blocks,
     * block markers, etc.
     *
     * @param offset Byte offset to the beginning of the document.
     * @param doclen Logical length of the document.
     * @return Actual length of the document.
     */
    size_t getActualStaleLengthofDoc(uint64_t offset, size_t doclen);

    /**
     * Add the given stale region info (from system document) into in-memory
     * stale info tree.
     *
     * @param revnum Revision number of the commit corresponding to stale regions.
     * @param doc Pointer to the document object to be added.
     * @param doc_offset Byte offset of the document.
     * @param system_doc_only If true, add a stale region caused by the system
     *        document itself.
     * @return void.
     */
    void addInmemStaleInfo(filemgr_header_revnum_t revnum,
                           struct docio_object *doc,
                           uint64_t doc_offset,
                           bool system_doc_only);

    /**
     * Read and fetch the given stale info and insert the data into 'Merge tree'.
     *
     * @param ctx Stale data info, from the body of a system document.
     * @param mergetree Pointer to Merge tree.
     * @param prev_offset_out Reference to the place where previous system
     *        document offset will be stored.
     * @param prev_hdr_out Reference to the place where previous commit header BID
     *        will be stored.
     * @return void.
     */
    void fetchStaleInfoDoc(void *ctx,
                           std::map<uint64_t, stale_data*> *mergetree,
                           uint64_t &prev_offset_out,
                           uint64_t &prev_hdr_out);

    /**
     * Insert the given region {position, length} into the given tree, and merge.
     *
     * @param item_pos Byte offset to the beginning of the region.
     * @param item_len Length of the region.
     * @return void.
     */
    void insertNmerge(std::map<uint64_t, stale_data*> *tree,
                      uint64_t item_pos,
                      uint32_t item_len);

    /**
     * Gather stale region info from stale list and store it as a system doc.
     *
     * @param handle Pointer to ForestDB KV store handle.
     * @param revnum Header revision number that will be stored as a key in stale tree.
     * @param prev_hdr Currently up-to-date header BID.
     * @param kv_info_offset Currently up-to-date KVS header doc offset.
     * @param seqnum Currently up-to-date seq number of the default KVS.
     * @param e_last Last (rightmost) stale region that should not be gathered at
     *        this time.
     * @param from_mergetree If true, gather stale regions from merge-tree
     *        (which contains remaining items after block reclaim) instead of stale
     *        list.
     * @return void.
     */
    void gatherRegions(FdbKvsHandle *handle,
                       filemgr_header_revnum_t revnum,
                       bid_t prev_hdr,
                       uint64_t kv_info_offset,
                       fdb_seqnum_t seqnum,
                       std::list<stale_data*>::iterator e_last,
                       bool from_mergetree);

    void clearStaleList();
    void clearStaleInfoTree();
    void clearMergeTree();
};

#endif /* _FDB_STALEBLOCK_H */

