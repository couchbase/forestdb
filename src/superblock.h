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

#ifndef _FDB_SUPERBLOCK_H
#define _FDB_SUPERBLOCK_H

#include "libforestdb/fdb_types.h"
#include "libforestdb/fdb_errors.h"
#include "common.h"

#include "filemgr.h"
#include "avltree.h"
#include "atomic.h"
#include "docio.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Reusable block reclaim logic decision.
 */
typedef enum {
    /**
     * Do nothing.
     */
    SBD_NONE = 0,
    /**
     * Reclaim reusable blocks and update the bitmap immediately.
     */
    SBD_RECLAIM = 1,
    /**
     * Reclaim reusable blocks but reserve them for the next round.
     */
    SBD_RESERVE = 2,
    /**
     * Discard the current bitmap and take the reserved bitmap.
     */
    SBD_SWITCH = 3
} sb_decision_t;

/**
 * Superblock config options that are passed to sb_init() API.
 */
struct sb_config {
    /**
     * Number of superblocks that are concurrently maintained for crash recovery.
     */
    uint8_t num_sb;
};

/**
 * Reserved bitmap is destroyed or not initialized.
 */
#define SB_RSV_VOID (0x0)
/**
 * Reserved bitmap is being initialized (not ready to use).
 */
#define SB_RSV_INITIALIZING (0x1)
/**
 * Reserved bitmap is being written into the DB file.
 */
#define SB_RSV_WRITING (0x2)
/**
 * Reserved bitmap is now available.
 */
#define SB_RSV_READY (0xffff)

/**
 * Pre-reclaimed reusable block bitmap info.
 * Each attribute is same as that in superblock.
 */
struct sb_rsv_bmp {
    /**
     * Revision number of the reserved bitmap.
     */
    uint64_t bmpRevnum;
    /**
     * Number of bits in the bitmap. Each bit represents a block.
     */
    uint64_t bmpSize;
    /**
     * Pointer to the bitmap.
     */
    uint8_t *bmp;
    /**
     * Bitmap index for fast searching of next reusable block.
     */
    struct avl_tree bmpIdx;
    /**
     * Pointer to array of bitmap document offsets, where a bitmap document is a
     * system documents containing a part of the bitmap.
     */
    bid_t *bmpDocOffset;
    /**
     * Pointer to array of bitmap document in-memory objects.
     */
    struct docio_object *bmpDocs;
    /**
     * Number of bitmap documents.
     */
    uint64_t numBmpDocs;
    /**
     * Current number of free blocks in the bitmap.
     */
    uint64_t numFreeBlocks;
    /**
     * BID of a block to be allocated next time.
     */
    bid_t curAllocBid;
    /**
     * Revision number of the oldest header that is not reclaimed yet and is currently
     * active in the file.
     */
    uint64_t minLiveHdrRevnum;
    /**
     * BID of the oldest header that is not reclaimed yet and is currently active in the
     * file.
     */
    bid_t minLiveHdrBid;
    /**
     * Status of the reserved bitmap.
     */
    std::atomic<uint32_t> status;
};

/**
 * Skeleton class for Superblock; it does nothing.
 * This class is used only when Superblock related code is not compiled with
 * filemgr layer.
 * As a future work, this class will be used for old version files which do not
 * contain superblocks. Then we don't need to do NULL pointer check for each
 * superblock operation.
 *
 * Note: following functions should be adapted
 *       if this structure is changed:
 *       _sb_init()
 *       _sb_copy()
 */
class SuperblockBase {
public:
    SuperblockBase() :
        file(nullptr), bmpRevnum(0), bmpSize(0), bmp(nullptr), bmpRCount(0),
        bmpWCount(0), bmpPrevSize(0), bmpPrev(nullptr), bmpDocOffset(nullptr),
        bmpDocs(nullptr), numBmpDocs(0), numInitFreeBlocks(0),
        numFreeBlocks(0), rsvBmp(nullptr), curAllocBid(BLK_NOT_FOUND),
        lastHdrBid(BLK_NOT_FOUND), minLiveHdrRevnum(0),
        minLiveHdrBid(BLK_NOT_FOUND), lastHdrRevnum(0), numAlloc(0)
    {
        spin_init(&bmpLock);
        avl_init(&bmpIdx, NULL);
        spin_init(&lock);
    }

    virtual ~SuperblockBase() { }

    SuperblockBase& operator=(const SuperblockBase& src) {
        file = src.file;
        config = src.config;
        revnum.store(src.revnum);
        bmpRevnum.store(src.bmpRevnum.load());
        bmpSize.store(src.bmpSize.load());
        bmp.store(src.bmp.load(std::memory_order_relaxed), std::memory_order_relaxed);
        bmpRCount.store(src.bmpRCount.load());
        bmpWCount.store(src.bmpWCount.load());
        spin_init(&bmpLock);
        bmpPrevSize = src.bmpPrevSize;
        bmpPrev = src.bmpPrev;
        bmpIdx = src.bmpIdx;
        bmpDocOffset = src.bmpDocOffset;
        bmpDocs = src.bmpDocs;
        numBmpDocs = src.numBmpDocs;
        numInitFreeBlocks = src.numInitFreeBlocks;
        numFreeBlocks = src.numFreeBlocks;
        rsvBmp = src.rsvBmp;
        curAllocBid.store(src.curAllocBid.load());
        lastHdrBid.store(src.lastHdrBid.load());
        minLiveHdrRevnum = src.minLiveHdrRevnum;
        minLiveHdrBid = src.minLiveHdrBid;
        lastHdrRevnum.store(src.lastHdrRevnum.load());
        numAlloc = src.numAlloc;
        spin_init(&lock);
        return *this;
    }

    struct sb_config getConfig() const {
        return config;
    }

    uint64_t getRevnum() const {
        return revnum.load();
    }

    uint64_t getBmpRevnum() const {
        return bmpRevnum.load();
    }

    uint64_t getBmpSize() const {
        return bmpSize.load();
    }

    void* getBmp() const {
        return bmp.load();
    }

    uint64_t getBmpRCount() const {
        return bmpRCount.load();
    }

    uint64_t getBmpWCount() const {
        return bmpWCount.load();
    }

    uint64_t getBmpPrevSize() const {
        return bmpPrevSize;
    }

    void* getBmpPrev() const {
        return bmpPrev;
    }

    struct avl_tree getBmpIdx() const {
        return bmpIdx;
    }

    bid_t *getBmpDocOffset() const {
        return bmpDocOffset;
    }

    struct docio_object *getBmpDocs() const {
        return bmpDocs;
    }

    uint64_t getNumBmpDocs() const {
        return numBmpDocs;
    }

    uint64_t getNumInitFreeBlocks() const {
        return numInitFreeBlocks;
    }

    uint64_t getNumFreeBlocks() const {
        return numFreeBlocks;
    }

    struct sb_rsv_bmp* getRsvBmp() const {
        return rsvBmp;
    }

    uint64_t getCurAllocBid() const {
        return curAllocBid.load();
    }

    uint64_t getLastHdrBid() const {
        return lastHdrBid.load();
    }

    uint64_t getMinLiveHdrRevnum() const {
        return minLiveHdrRevnum;
    }

    uint64_t getMinLiveHdrBid() const {
        return minLiveHdrBid;
    }

    uint64_t getLastHdrRevnum() const {
        return lastHdrRevnum.load();
    }

    uint64_t getNumAlloc() const {
        return numAlloc;
    }

    void resetNumAlloc()
    {
        numAlloc = 0;
    }

    virtual fdb_status init(ErrLogCallback *log_callback) {
        return FDB_RESULT_SUCCESS;
    }

    static struct sb_config getDefaultConfig() {
        struct sb_config ret;
        ret.num_sb = SB_DEFAULT_NUM_SUPERBLOCKS;
        return ret;
    }

    virtual fdb_status readLatest(ErrLogCallback *log_callback) {
        return FDB_RESULT_SUCCESS;
    }

    virtual bid_t allocBlock() {
        return BLK_NOT_FOUND;
    }

    virtual bool isWritable(bid_t bid) {
        return false;
    }

    inline bool bmpExists()
    {
        if (bmpSize.load()) {
            return true;
        }
        return false;
    }

    virtual void appendBmpDoc(FdbKvsHandle *handle) { }
    virtual void appendRsvBmpDoc(FdbKvsHandle *handle) { }
    virtual fdb_status readBmpDoc(FdbKvsHandle *handle) {
        return FDB_RESULT_SUCCESS;
    }

    virtual bool checkSyncPeriod() {
        return false;
    }
    virtual bool updateHeader(FdbKvsHandle *handle) {
        return false;
    }
    virtual fdb_status syncCircular(FdbKvsHandle *handle) {
        return FDB_RESULT_SUCCESS;
    }
    virtual sb_decision_t checkBlockReuse(FdbKvsHandle *handle) {
        return SBD_NONE;
    }

    virtual bool reclaimReusableBlocks(FdbKvsHandle *handle) {
        return false;
    }
    virtual bool reserveNextReusableBlocks(FdbKvsHandle *handle) {
        return false;
    }
    virtual void returnReusableBlocks(FdbKvsHandle *handle) { }
    virtual bool switchReservedBlocks() {
        return false;
    }

protected:
    /**
     * Corresponding file structure.
     */
    FileMgr *file;
    /**
     * Superblock configuration.
     */
    struct sb_config config;
    /**
     * Current revision number of superblock. This value increases whenever superblock
     * is written back into file.
     */
    std::atomic<uint64_t> revnum;
    /**
     * Current revision number of bitmap in superblock. This value increases whenever
     * ForestDB reclaims stale blocks and accordingly bitmap is updated.
     */
    std::atomic<uint64_t> bmpRevnum;
    /**
     * Number of bits in the bitmap. Each bit represents a block.
     */
    std::atomic<uint64_t> bmpSize;
    /**
     * Pointer to the bitmap.
     */
    std::atomic<uint8_t *> bmp;
    /**
     * Reference counter for bitmap readers.
     */
    std::atomic<uint64_t> bmpRCount;
    /**
     * Reference counter for bitmap writers.
     */
    std::atomic<uint64_t> bmpWCount;
    /**
     * Lock for bitmap modification.
     */
    spin_t bmpLock;
    /**
     * Number of bits in the previous bitmap. Each bit represents a block.
     */
    uint64_t bmpPrevSize;
    /**
     * Pointer to the previous (previous bitmap revnum) bitmap.
     */
    uint8_t *bmpPrev;
    /**
     * Bitmap index for fast searching of next reusable block.
     */
    struct avl_tree bmpIdx;
    /**
     * Pointer to array of bitmap document offsets, where a bitmap document is a
     * system documents containing a part of the bitmap.
     */
    bid_t *bmpDocOffset;
    /**
     * Pointer to array of bitmap document in-memory objects.
     */
    struct docio_object *bmpDocs;
    /**
     * Number of bitmap documents.
     */
    uint64_t numBmpDocs;
    /**
     * Initial number of free blocks in the bitmap right after the bitmap is updated.
     */
    uint64_t numInitFreeBlocks;
    /**
     * Current number of free blocks in the bitmap.
     */
    uint64_t numFreeBlocks;
    /**
     * Reserved bitmap for the next round block reuse.
     */
    struct sb_rsv_bmp *rsvBmp;
    /**
     * BID of a block to be allocated next time.
     */
    std::atomic<uint64_t> curAllocBid;
    /**
     * BID of the last header.
     */
    std::atomic<uint64_t> lastHdrBid;
    /**
     * Revision number of the oldest header that is not reclaimed yet and is currently
     * active in the file.
     */
    uint64_t minLiveHdrRevnum;
    /**
     * BID of the oldest header that is not reclaimed yet and is currently active in the
     * file.
     */
    bid_t minLiveHdrBid;
    /**
     * Revision number of the last header.
     */
    std::atomic<uint64_t> lastHdrRevnum;
    /**
     * Number of allocated blocks since the last superblock sync.
     */
    uint64_t numAlloc;
    /**
     * Lock for superblock initialization.
     */
    spin_t lock;
};

/**
 * Actual superblock class definition.
 */
class Superblock : public SuperblockBase {
public:
    // Default constructor
    Superblock();

    // Constructor with FileMgr and config.
    Superblock(FileMgr *_file, struct sb_config _sconfig);

    // Destructor
    ~Superblock();

    /**
     * Initialize bitmap masks for bitmap operations.
     *
     * @return void.
     */
    static void initBmpMask();

    /**
     * Initialize superblock instance.
     *
     * @param log_callback Pointer to log callback function.
     * @return FDB_RESULT_SUCCESS on success.
     */
    fdb_status init(ErrLogCallback * log_callback);

    /**
     * Read all superblocks and take the most recent superblock.
     *
     * @param file Pointer to filemgr handle.
     * @param sconfig Superblock configuration.
     * @param log_callback Pointer to log callback function.
     * @return FDB_RESULT_SUCCESS on success.
     */
    fdb_status readLatest(ErrLogCallback *log_callback);

    /**
     * Allocate a free block by referring the bitmap in superblock,
     * in a circular manner.
     *
     * @return ID of the allocated block. BLK_NOT_FOUND if there is no free block
     *         in the bitmap.
     */
    bid_t allocBlock();

    /**
     * Investigate if the given block is writable.
     *
     * @param bid ID of block.
     * @return True if the block is writable.
     */
    bool isWritable(bid_t bid);

    /**
     * Create system docs for bitmap and append them into the file.
     *
     * @param handle Pointer to ForestDB KV store handle.
     * @return void.
     */
    void appendBmpDoc(FdbKvsHandle *handle);

    /**
     * Create system docs for reserved bitmap and append them into the file.
     *
     * @param handle Pointer to ForestDB KV store handle.
     * @return void.
     */
    void appendRsvBmpDoc(FdbKvsHandle *handle);

    /**
     * Read bitmap docs from file and reconstruct bitmap.
     *
     * @param handle Pointer to ForestDB KV store handle.
     * @return FDB_RESULT_SUCCESS on success.
     */
    fdb_status readBmpDoc(FdbKvsHandle *handle);

    /**
     * Check if superblock needs to be written back into the file.
     *
     * @return True if superblock meets the sync period.
     */
    bool checkSyncPeriod();

    /**
     * Update in-memory data of superblock using current header info.
     *
     * @param handle Pointer to ForestDB KV store handle.
     * @return True if superblock is updated.
     */
    bool updateHeader(FdbKvsHandle *handle);

    /**
     * Write back superblock info into the file.
     *
     * @param handle Pointer to ForestDB KV store handle.
     * @return FDB_RESULT_SUCCESS on success.
     */
    fdb_status syncCircular(FdbKvsHandle *handle);

    /**
     * Check if superblock needs to be written back into the file.
     *
     * @param handle Pointer to ForestDB KV store handle.
     * @return True if superblock meets the sync period.
     */
    sb_decision_t checkBlockReuse(FdbKvsHandle *handle);

    /**
     * Reclaim stale blocks and update the in-memory structure of bitmap in superblock.
     *
     * @param handle Pointer to ForestDB KV store handle.
     * @return True if block reclaiming succeeded.
     */
    bool reclaimReusableBlocks(FdbKvsHandle *handle);

    /**
     * Switch reserved blocks to currently being used blocks.
     *
     * @param file Pointer to file manager handle.
     * @return True if switching succeeded.
     */
    bool switchReservedBlocks();

    /**
     * Reclaim stale blocks for the next round block reuse and create an in-memory
     * structure for the reserved bitmap array.
     *
     * @param handle Pointer to ForestDB KV store handle.
     * @return True if block reclaiming succeeded.
     */
    bool reserveNextReusableBlocks(FdbKvsHandle *handle);

    /**
     * Restore all remaining reusable blocks including reserved blocks
     * into stale tree again.
     *
     * @param handle Pointer to ForestDB KV store handle.
     * @return void.
     */
    void returnReusableBlocks(FdbKvsHandle *handle);

private:
    void _init(FileMgr *_file, struct sb_config sconfig);
    void _free();

    /**
     * Write a superblock with the given ID.
     *
     * @param file Pointer to filemgr handle.
     * @param sb_no Superblock ID.
     * @param log_callback Pointer to log callback function.
     * @return FDB_RESULT_SUCCESS on success.
     */
    fdb_status writeSb(size_t sb_no, ErrLogCallback * log_callback);
    fdb_status readGivenNum(size_t sb_no, ErrLogCallback *log_callback);

    void beginBmpBarrier();
    void endBmpBarrier();
    void beginBmpChange();
    void endBmpChange();

    static void updateBmp(uint8_t *bmp, bid_t bid, uint64_t len, int mode);

    /**
     * Set bitmap bits for the given blocks.
     *
     * @param bmp Pointer to bitmap array.
     * @param bid Starting BID.
     * @param len Number of blocks.
     * @return void.
     */
    static void setBmp(uint8_t *bmp, bid_t bid, uint64_t len);

    /**
     * Clear bitmap bits for the given blocks.
     *
     * @param bmp Pointer to bitmap array.
     * @param bid Starting BID.
     * @param len Number of blocks.
     * @return void.
     */
    static void clearBmp(uint8_t *bmp, bid_t bid, uint64_t len);

    /**
     * Add the given block region into bitmap index.
     *
     * @param target_idx Pointer to bitmap index.
     * @param bid Starting BID.
     * @param count Number of blocks.
     * @return void.
     */
    static void addBmpIdx(struct avl_tree *target_idx, bid_t bid, bid_t count);

    /**
     * Free the given bitmap index and its elements.
     *
     * @param target_idx Pointer to bitmap index.
     * @return void.
     */
    static void freeBmpIdx(struct avl_tree *target_idx);

    /**
     * Construct a bitmap index from the given bitmap array.
     *
     * @param target_idx Pointer to bitmap index.
     * @param src_bmp Pointer to bitmap array.
     * @param src_bmp_size Size of the bitmap array.
     * @param start_bid Block ID corresponding to the first non-zero bit in the array.
     * @return void.
     */
    static void constructBmpIdx(struct avl_tree *target_idx,
                               uint8_t *src_bmp,
                               uint64_t src_bmp_size,
                               bid_t start_bid);

    /**
     * Convert the given bitmap array size to the number of system documents for
     * bitmap.
     *
     * @param bmp_size Size of the bitmap array.
     * @return Number of system documents for bitmap.
     */
    inline static size_t bmpSizeToNumDocs(uint64_t bmp_size);

    /**
     * Check if the bit corresponding to the given block is set or not.
     *
     * @param bid Block ID.
     * @return True if the bitmap is set.
     */
    inline static bool isBmpSet(uint8_t *bmp, bid_t bid);

    /**
     * Free all resources for the reserved bitmap structure.
     *
     * @param rsv Pointer to the reserved bitmap structure.
     * @return void.
     */
    static void freeRsv(struct sb_rsv_bmp *rsv);

};

#ifdef __cplusplus
}
#endif

#endif /* _FDB_SUPERBLOCK_H */

