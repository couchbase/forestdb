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

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

#include "libforestdb/forestdb.h"
#include "fdb_engine.h"
#include "superblock.h"
#include "staleblock.h"
#include "btreeblock.h"
#include "list.h"
#include "fdb_internal.h"
#include "version.h"
#include "blockcache.h"

#include "memleak.h"

/*
 * << super block structure >>
 *
 * 0x00 [file version (magic number)]:           8 bytes
 * 0x08 [super block revision number]:           8 bytes
 * 0x10 [bitmap revision number]:                8 bytes
 * 0x18 [BID for next allocation]:               8 bytes
 * 0x20 [last header BID]:                       8 bytes
 * 0x28 [last header revnum]:                    8 bytes
 * 0x30 [min active header revnum]:              8 bytes
 * 0x38 [min active header BID]:                 8 bytes
 * 0x40 [# initial free blocks in the bitmap]:   8 bytes
 * 0x48 [# free blocks in the bitmap]:           8 bytes
 * 0x50 [bitmap size]:                           8 bytes
 * 0x58 [reserved bitmap size (0 if not exist)]: 8 bytes
 * 0x60 ... [bitmap doc offset]:                 8 bytes each
 *      [CRC32]:                                 4 bytes
 * ...
 *      [block marker]:                          1 byte
 */


/*
 * << basic mask >>
 * 0: 10000000
 * 1: 01000000
 *    ...
 * 7: 00000001
 */
static uint8_t bmp_basic_mask[8];
/*
 * << 2d mask >>
 * bmp_2d_mask[pos][len]
 *
 * 0,1: 10000000
 * 0,2: 11000000
 * 0,3: 11100000
 *    ...
 * 1,1: 01000000
 * 1,2: 01100000
 *    ...
 * 3,1: 00010000
 * 3,2: 00011000
 *    ...
 * 6,1: 00000010
 * 6,2: 00000011
 * 7,1: 00000001
 */
static uint8_t bmp_2d_mask[8][9];


// x % 8
#define mod8(x) ((x) & 0x7)
// x / 8
#define div8(x) ((x) >> 3)
// rounding down (to the nearest 8)
#define rd8(x) (((x) >> 3) << 3)

struct bmp_idx_node {
    uint64_t id;
    struct avl_node avl;
};

INLINE int _bmp_idx_cmp(struct avl_node *a, struct avl_node *b, void *aux)
{
    struct bmp_idx_node *aa, *bb;
    aa = _get_entry(a, struct bmp_idx_node, avl);
    bb = _get_entry(b, struct bmp_idx_node, avl);

#ifdef __BIT_CMP
    return _CMP_U64(aa->id, bb->id);
#else
    if (aa->id < bb->id) {
        return -1;
    } else if (aa->id > bb->id) {
        return 1;
    } else {
        return 0;
    }
#endif
}

Superblock::Superblock(FileMgr *_file, struct sb_config _sconfig) {
    _init(_file, _sconfig);
}

Superblock::~Superblock() {
    _free();
}

void Superblock::_init(FileMgr *_file, struct sb_config sconfig) {
    file = _file;
    config = sconfig;
    revnum = 0;
    bmpRevnum = 0;
    bmpSize = 0;
    bmp = NULL;
    bmpRCount = 0;
    bmpWCount = 0;
    spin_init(&bmpLock);
    bmpPrevSize = 0;
    bmpPrev = NULL;
    bmpDocOffset = NULL;
    bmpDocs = NULL;
    numBmpDocs = 0;
    numInitFreeBlocks = 0;
    numFreeBlocks = 0;
    curAllocBid = BLK_NOT_FOUND;
    lastHdrBid = BLK_NOT_FOUND;
    minLiveHdrRevnum = 0;
    minLiveHdrBid = BLK_NOT_FOUND;
    lastHdrRevnum = 0;
    numAlloc = 0;
    rsvBmp = NULL;
    avl_init(&bmpIdx, NULL);
    spin_init(&lock);
}

fdb_status Superblock::init(ErrLogCallback * log_callback)
{
    size_t i;
    bid_t sb_bid;
    fdb_status fs;

    // exit if superblock is already initialized.
    if (revnum) {
        return FDB_RESULT_SUCCESS;
    }
    // no data should be written in the file before initialization of superblock.
    if (file->getPos() > 0) {
        return FDB_RESULT_SB_INIT_FAIL;
    }

    // initialize staleData instance if not exist
    if (!file->getStaleData()) {
        file->setStaleData(new StaleDataManager(file));
    }

    file->setVersion(ver_get_latest_magic());

    // write initial superblocks
    for (i=0; i<config.num_sb; ++i) {
        // allocate
        sb_bid = file->alloc_FileMgr(log_callback);
        if (sb_bid != i) {
            // other data was written during sb_write .. error
            fs = FDB_RESULT_SB_RACE_CONDITION;
            fdb_log(log_callback, fs,
                    "Other writer interfered during sb_write (number: %" _F64 ")",
                    static_cast<uint64_t>(i));
            return fs;
        }

        fs = writeSb(i, log_callback);
        if (fs != FDB_RESULT_SUCCESS) {
            return fs;
        }
    }

    return FDB_RESULT_SUCCESS;
}

fdb_status Superblock::readLatest(ErrLogCallback *log_callback)
{
    size_t i, max_sb_no = config.num_sb;
    uint64_t max_revnum = 0;
    uint64_t revnum_limit = static_cast<uint64_t>(-1);
    fdb_status fs;
    std::vector<Superblock *> sb_arr;
    //Superblock **sb_arr = new Superblock*[config.num_sb];

    // initialize staleData instance if not exist
    if (!file->getStaleData()) {
        file->setStaleData(new StaleDataManager(file));
    }

    if (revnum) {
        // Superblock is already read previously.
        // This means that there are some problems with the current superblock
        // so that we have to read another candidate.

        // Note: 'sb->revnum' denotes the revnum of next superblock to be
        // written, so we need to subtract 1 from it to get the revnum of
        // the current superblock successfully read from the file.
        revnum_limit = revnum.load() - 1;
        _free();
    }

    // read all superblocks
    for (i=0; i<config.num_sb; ++i) {
        sb_arr.push_back(new Superblock(file, config));
        fs = sb_arr[i]->readGivenNum(i, log_callback);

        uint64_t cur_revnum = sb_arr[i]->getRevnum();
        if (fs == FDB_RESULT_SUCCESS &&
            cur_revnum >= max_revnum &&
            cur_revnum < revnum_limit) {
            max_sb_no = i;
            max_revnum = cur_revnum;
        }
    }

    if (max_sb_no == config.num_sb) {
        // all superblocks are broken
        fs = FDB_RESULT_SB_READ_FAIL;
        for (i=0; i<config.num_sb; ++i) {
            delete sb_arr[i];
        }
        // no readable superblock
        // (if not corrupted, it may be a normal old version file)
        return fs;
    }

    // re-read the target superblock
    readGivenNum(max_sb_no, log_callback);

    // set last commit position
    if (curAllocBid.load() != BLK_NOT_FOUND) {
        file->setLastCommit(curAllocBid.load() * file->getConfig()->getBlockSize());
    } else {
        // otherwise, last_commit == file->pos
        // (already set by FileMgr::open() function)
    }

    revnum++;
    avl_init(&bmpIdx, NULL);

    // free temporary superblocks
    for (i=0; i<config.num_sb; ++i) {
        delete sb_arr[i];
    }

    return FDB_RESULT_SUCCESS;
}

void Superblock::initBmpMask()
{
    // preset masks to speed up bitmap set/clear operations
    size_t i, pos, len;
    for (i=0; i<8; ++i) {
        bmp_basic_mask[i] = (uint8_t)(0x1 << (7-i));
    }
    for (pos=0; pos<8; ++pos) {
        for (len=0; len<9; ++len) {
            bmp_2d_mask[pos][len] = 0x0;
            if (len != 0 && pos+len <= 8) {
                for (i=0; i<len; ++i) {
                    bmp_2d_mask[pos][len] |= bmp_basic_mask[pos+i];
                }
            }
        }
    }
}

void Superblock::_free()
{
    if (rsvBmp) {
        rsvBmp->status = SB_RSV_VOID;
        freeBmpIdx(&rsvBmp->bmpIdx);
        freeRsv(rsvBmp);
        free(rsvBmp);
    }
    freeBmpIdx(&bmpIdx);

    free(bmp);
    free(bmpPrev);
    free(bmpDocOffset);
    // note that each docio object doesn't need to be freed
    // as key/body fields point to static memory regions.
    free(bmpDocs);
    spin_destroy(&lock);

    bmp = NULL;
    bmpDocOffset = NULL;
    bmpDocs = NULL;
}

fdb_status Superblock::readGivenNum(size_t sb_no,
                                    ErrLogCallback *log_callback)
{
    ssize_t r;
    int real_blocksize = file->getBlockSize();
    int blocksize = file->getBlockSize() - BLK_MARKER_SIZE;
    size_t i, num_docs;
    uint8_t *buf = alca(uint8_t, real_blocksize);
    uint32_t crc_file, crc, _crc;
    uint64_t enc_u64, version, offset, dummy64;
    fdb_status fs;
    struct sb_rsv_bmp *rsv = NULL;

    memset(buf, 0x0, real_blocksize);
    offset = 0;

    // directly read a block bypassing block cache
    r = file->readBlock(buf, sb_no);
    if (r != real_blocksize) {
        char errno_msg[512];
        file->getOps()->get_errno_str(file->getFopsHandle(), errno_msg, 512);
        fs = FDB_RESULT_SB_READ_FAIL;
        fdb_log(log_callback, fs,
                "Failed to read the superblock: "
                "file read failure (SB No.: %" _F64 "), %s",
                static_cast<uint64_t>(sb_no), errno_msg);
        return fs;
    }

    // block marker check
    if (buf[blocksize] != BLK_MARKER_SB) {
        fs = FDB_RESULT_SB_READ_FAIL;
        fdb_log(log_callback, fs,
                "Failed to read the superblock: "
                "incorrect block marker (marker: %x, SB No.: %" _F64 "). "
                "Note: this message might be a false alarm if upgrade is running.",
                buf[blocksize], static_cast<uint64_t>(sb_no));
        return fs;
    }

    // magic number
    memcpy(&enc_u64, buf + offset, sizeof(enc_u64));
    offset += sizeof(enc_u64);
    version = _endian_decode(enc_u64);

    // version check
    if (!ver_superblock_support(version)) {
        fs = FDB_RESULT_SB_READ_FAIL;
        fdb_log(log_callback, fs,
                "Failed to read the superblock: "
                "not supported version (magic: %" _F64 ", SB No.: %" _F64 ")",
                version, static_cast<uint64_t>(sb_no));
        return fs;
    }

    // revision number
    memcpy(&enc_u64, buf + offset, sizeof(enc_u64));
    offset += sizeof(enc_u64);
    revnum = _endian_decode(enc_u64);

    // bitmap's revision number
    memcpy(&enc_u64, buf + offset, sizeof(enc_u64));
    offset += sizeof(enc_u64);
    bmpRevnum = _endian_decode(enc_u64);

    // curAllocBid
    memcpy(&enc_u64, buf + offset, sizeof(enc_u64));
    offset += sizeof(enc_u64);
    curAllocBid = _endian_decode(enc_u64);

    // last header bid
    memcpy(&enc_u64, buf + offset, sizeof(enc_u64));
    offset += sizeof(enc_u64);
    lastHdrBid = _endian_decode(enc_u64);

    // last header rev number
    memcpy(&enc_u64, buf + offset, sizeof(enc_u64));
    offset += sizeof(enc_u64);
    lastHdrRevnum = _endian_decode(enc_u64);

    // minimum active header revnum
    memcpy(&enc_u64, buf + offset, sizeof(enc_u64));
    offset += sizeof(enc_u64);
    minLiveHdrRevnum = _endian_decode(enc_u64);

    // minimum active header BID
    memcpy(&enc_u64, buf + offset, sizeof(enc_u64));
    offset += sizeof(enc_u64);
    minLiveHdrBid = _endian_decode(enc_u64);

    // # initial free blocks
    memcpy(&enc_u64, buf + offset, sizeof(enc_u64));
    offset += sizeof(enc_u64);
    numInitFreeBlocks = _endian_decode(enc_u64);

    // # free blocks
    memcpy(&enc_u64, buf + offset, sizeof(enc_u64));
    offset += sizeof(enc_u64);
    numFreeBlocks = _endian_decode(enc_u64);

    // bitmap size
    uint64_t sb_bmp_size;
    memcpy(&enc_u64, buf + offset, sizeof(enc_u64));
    offset += sizeof(enc_u64);
    sb_bmp_size = _endian_decode(enc_u64);
    bmpSize = sb_bmp_size;

    // reserved bitmap size
    memcpy(&enc_u64, buf + offset, sizeof(enc_u64));
    offset += sizeof(enc_u64);
    dummy64 = _endian_decode(enc_u64);
    if (dummy64) {
        // reserved bitmap array exists
        rsv = (struct sb_rsv_bmp*)calloc(1, sizeof(struct sb_rsv_bmp));
        rsv->bmp = NULL;
        rsv->bmpSize = dummy64;
        rsv->curAllocBid = BLK_NOT_FOUND;
        rsv->status = SB_RSV_INITIALIZING;
    }

    // temporarily set bitmap array to NULL
    // (it will be allocated by fetching function)
    bmp = NULL;

    numBmpDocs = num_docs = bmpSizeToNumDocs(sb_bmp_size);
    if (num_docs) {
        bmpDocOffset = (bid_t*)calloc(num_docs, sizeof(bid_t));
        bmpDocs = (struct docio_object*)
                       calloc(num_docs, sizeof(struct docio_object));
    }

    // read doc offsets
    for (i=0; i<num_docs; ++i) {
        memcpy(&enc_u64, buf + offset, sizeof(enc_u64));
        offset += sizeof(enc_u64);
        bmpDocOffset[i] = _endian_decode(enc_u64);
    }

    // read reserved bmp docs if exist
    if (rsv) {
        rsv->numBmpDocs = num_docs = bmpSizeToNumDocs(rsv->bmpSize);
        if (rsv->numBmpDocs) {
            rsv->bmpDocOffset = (bid_t*)calloc(num_docs, sizeof(bid_t));
            rsv->bmpDocs = (struct docio_object*)
                            calloc(num_docs, sizeof(struct docio_object));
        }

        // read doc offsets
        for (i=0; i<num_docs; ++i) {
            memcpy(&enc_u64, buf + offset, sizeof(enc_u64));
            offset += sizeof(enc_u64);
            rsv->bmpDocOffset[i] = _endian_decode(enc_u64);
        }
        rsvBmp = rsv;
    }

    // CRC
    crc = get_checksum(buf, offset, file->getCrcMode());
    memcpy(&_crc, buf + offset, sizeof(_crc));
    crc_file = _endian_decode(_crc);
    if (crc != crc_file) {
        free(bmpDocOffset);
        free(bmpDocs);
        bmpDocOffset = NULL;
        bmpDocs = NULL;

        fs = FDB_RESULT_SB_READ_FAIL;
        fdb_log(log_callback, fs,
                "Failed to read the superblock: "
                "not supported version (magic: %" _F64 ", SB No.: %" _F64 ")",
                version, static_cast<uint64_t>(sb_no));
        return fs;
    }

    return FDB_RESULT_SUCCESS;
}

void Superblock::beginBmpBarrier()
{
    bmpRCount++;
    if (bmpWCount.load()) {
        // now bmp pointer & related variables are being changed.
        // decrease count and grab lock until the change is done.
        bmpRCount--;
        spin_lock(&bmpLock);

        // got control: means that change is done.
        // re-increase the count
        bmpRCount++;
        spin_unlock(&bmpLock);
    }
}

void Superblock::endBmpBarrier()
{
    bmpRCount--;
}

void Superblock::beginBmpChange()
{
    // grab lock and increase writer count
    // now new readers cannot increase the reader count
    // (note that there is always one bitmap writer at a time)
    spin_lock(&bmpLock);
    bmpWCount++;

    // wait until previous BMP readers terminate
    // (they are very short bitmap accessing routines so that
    //  will not take long time).
    size_t spin = 0;
    while (bmpRCount.load()) {
       if (++spin > 64) {
#ifdef HAVE_SCHED_H
            sched_yield();
#elif _MSC_VER
            SwitchToThread();
#endif
       }
    }

    // now 1) all previous readers terminated
    //     2) new readers will be blocked
}

void Superblock::endBmpChange()
{
    bmpWCount--;
    spin_unlock(&bmpLock);
    // now resume all pending readers
}

bool Superblock::switchReservedBlocks()
{
    size_t i;
    struct sb_rsv_bmp *rsv = rsvBmp;

    // reserved block should exist
    if (!rsv) {
        return false;
    }
    // should be in a normal status
    uint32_t cond = SB_RSV_READY;
    if (!rsv->status.compare_exchange_strong(cond, SB_RSV_VOID)) {
        return false;
    }
    // now status becomes 'VOID' so that rsvBmp is not available.

    // mark stale previous system docs
    if (bmpDocOffset) {
        for (i=0; i<numBmpDocs; ++i) {
            file->markDocStale(bmpDocOffset[i],
                            _fdb_get_docsize(bmpDocs[i].length));
        }

        free(bmpDocOffset);
        free(bmpDocs);
        bmpDocOffset = NULL;
        bmpDocs = NULL;
    }

    // should flush all dirty blocks in cache
    file->sync_FileMgr(false, NULL);

    // free current bitmap idx
    freeBmpIdx(&bmpIdx);

    // temporarily keep current bitmap
    beginBmpChange();
    uint8_t *old_prev_bmp = NULL;
    if (bmpPrev) {
        old_prev_bmp = bmpPrev;
    }
    bmpPrev = bmp;
    bmpPrevSize = bmpSize.load();

    // copy all pointers from rsv to sb
    bmpRevnum = rsv->bmpRevnum;
    bmpSize.store(rsv->bmpSize);
    bmp = rsv->bmp;
    bmpIdx = rsv->bmpIdx;
    bmpDocOffset = rsv->bmpDocOffset;
    bmpDocs = rsv->bmpDocs;
    numBmpDocs = rsv->numBmpDocs;
    numFreeBlocks = numInitFreeBlocks = rsv->numFreeBlocks;
    curAllocBid.store(rsv->curAllocBid);
    minLiveHdrRevnum = rsv->minLiveHdrRevnum;
    minLiveHdrBid = rsv->minLiveHdrBid;
    endBmpChange();

    free(old_prev_bmp);
    free(rsvBmp);
    rsvBmp = NULL;

    return true;
}

bid_t Superblock::allocBlock()
{
    uint64_t i, node_idx, node_off, bmp_idx_no, bmp_off;
    bid_t ret = BLK_NOT_FOUND;
    struct avl_node *a;
    struct bmp_idx_node *item, query;

    numAlloc++;
sb_alloc_start_over:
    if (!bmpExists()) {
        // no bitmap
        return BLK_NOT_FOUND;
    }

    if (numFreeBlocks == 0) {
        bool switched = false;
        if (rsvBmp) {
            switched = switchReservedBlocks();
        }
        if (switched) {
            goto sb_alloc_start_over;
        } else {
            curAllocBid = BLK_NOT_FOUND;
            return BLK_NOT_FOUND;
        }
    }

    ret = curAllocBid.load();
    numFreeBlocks--;

    if (numFreeBlocks == 0) {
        bool switched = false;
        if (rsvBmp) {
            switched = switchReservedBlocks();
        }
        if (!switched) {
            curAllocBid = BLK_NOT_FOUND;
        }
        return ret;
    }

    // find allocable block in the same bmp idx node
    node_idx = ret >> 8;
    node_off = (ret & 0xff)+1;
    do {
        for (i=node_off; i<256; ++i) {
            bmp_idx_no = div8(i) + (node_idx * 32);
            bmp_off = mod8(i);

            if ((bmp_idx_no * 8 + bmp_off) >= bmpSize.load()) {
                break;
            }

            if (bmp[bmp_idx_no] & bmp_basic_mask[bmp_off]) {
                curAllocBid.store(bmp_idx_no * 8 + bmp_off);
                return ret;
            }
        }

        // current bmp_node does not include any free block .. remove
        query.id = node_idx;
        a = avl_search(&bmpIdx, &query.avl, _bmp_idx_cmp);
        if (a) {
            item = _get_entry(a, struct bmp_idx_node, avl);
            avl_remove(&bmpIdx, a);
            free(item);
        }

        // get next allocable bmp_node
        a = avl_first(&bmpIdx);
        if (!a) {
            // no more free bmp_node
            numFreeBlocks = 0;
            bool switched = false;
            if (rsvBmp) {
                switched = switchReservedBlocks();
            }
            if (!switched) {
                curAllocBid = BLK_NOT_FOUND;
            }
            break;
        }
        item = _get_entry(a, struct bmp_idx_node, avl);
        node_idx = item->id;
        node_off = 0;
    } while (true);

    return ret;
}

bool Superblock::isWritable(bid_t bid)
{
    if (bid < config.num_sb) {
        // superblocks are always writable
        return true;
    }

    bool ret = false;
    bid_t last_commit = file->getLastCommit() / file->getBlockSize();
    uint64_t lw_bmp_revnum = file->getLastWritableBmpRevnum();

    beginBmpBarrier();

    uint8_t *sb_bmp = bmp;
    if (bmpRevnum.load() == lw_bmp_revnum) {
        // Same bitmap revision number: there are 2 possible cases
        //
        // (1) normal case
        //               writable blocks
        //            <---->          <--->
        // +-------------------------------------------+
        // |       xxxxxxxxx          xxxxxxxxxx       | (x: reused blocks)
        // +-------------------------------------------+
        //            ^                   ^
        //            last_commit         cur_alloc
        //
        // (2) when file size grows after block reusing
        //                                   writable blocks
        //                             <------->       <--------->
        // +-------------------------------------------+---------+
        // |       xxxxxxxxx          xxxxxxxxxx       |         |
        // +-------------------------------------------+---------+
        //                             ^               ^         ^
        //                             last_commit     bmpSize  cur_alloc

        if (bid < bmpSize.load()) {
            // BID is in the bitmap .. check if bitmap is set.
            if (isBmpSet(sb_bmp, bid) &&
                bid < curAllocBid.load() &&
                bid >= last_commit) {
                ret = true;
            }
        } else {
            // BID is out-of-range of the bitmap
            if (bid >= last_commit) {
                ret = true;
            }
        }
    } else {
        // Different bitmap revision number: there are also 2 possible cases
        //
        // (1) normal case
        //     writable blocks                 writable blocks
        //         <---->                          <--->
        // +-------------------------------------------+
        // |       xxxxxxxxx          xxxxxxxxxx       |
        // +-------------------------------------------+
        //              ^                          ^
        //              cur_alloc                  last_commit
        //
        // (2) when file size grows after block reusing
        //         writable blocks             writable blocks
        //      <---->       <------>      <-----------x--------->
        // +-------------------------------------------+---------+
        // |    xxxxxx       xxxxxxxx                  |         |
        // +-------------------------------------------+---------+
        //                                 ^           ^         ^
        //                                 last_commit bmpSize  cur_alloc

        // the block is writable if
        // 1) BID >= last_commit OR
        // 2) BID < curAllocBid AND corresponding bitmap is set.
        if (bid >= last_commit) {
            // if prev_bmp exists, last commit position is still located on the
            // previous bitmap (since prev_bmp is released when a commit is invoked
            // in the new bitmap).
            // So in this case, we have to check both previous/current bitmaps.
            //
            // (1: previous bitmap (sb->bmpPrev), 2: current bitmap (sb->bmp))
            //
            //        writable blocks          writable blocks
            //    <-->      <---->   <-->          <> <> <>
            // +-------------------------------------------+
            // |  2222 1111 222222   2222   111111111 22 11|
            // +-------------------------------------------+
            //                                     ^
            //                                     last_commit
            if (bmpPrev) {
                if (bid < bmpPrevSize &&
                    isBmpSet(bmpPrev, bid)) {
                    ret = true;
                }
                if (bid < bmpSize.load() &&
                    isBmpSet(sb_bmp, bid)) {
                    ret = true;
                }
                if (bid >= bmpSize.load()) {
                    // blocks newly allocated beyond the bitmap size:
                    // always writable
                    ret = true;
                }
            } else {
                // bmpPrev doesn't exist even though bmpRevnum is different
                // this happens on the first block reclaim only
                // so all blocks whose 'BID >= last_commit' are writable.
                ret = true;
            }
        }

        if (bid < bmpSize.load() &&
            bid < curAllocBid.load() &&
            isBmpSet(sb_bmp, bid)) {
            // 'curAllocBid' is always smaller than 'bmpSize'
            // except for the case 'curAllocBid == BLK_NOT_FOUND'
            ret = true;
        }
    }

    endBmpBarrier();

    return ret;
}


fdb_status Superblock::writeSb(size_t sb_no,
                    ErrLogCallback * log_callback)
{
    ssize_t r;
    int real_blocksize = file->getBlockSize();
    int blocksize = file->getBlockSize() - BLK_MARKER_SIZE;
    uint8_t *buf = alca(uint8_t, real_blocksize);
    uint32_t crc, _crc;
    uint64_t enc_u64;
    uint64_t num_docs;
    size_t i, offset;
    fdb_status fs;

    memset(buf, 0x0, real_blocksize);

    offset = 0;
    // magic number
    enc_u64 = _endian_encode(file->getVersion());
    memcpy(buf + offset, &enc_u64, sizeof(enc_u64));
    offset += sizeof(enc_u64);

    // revision number
    uint64_t sb_revnum = revnum.load();
    enc_u64 = _endian_encode(sb_revnum);
    memcpy(buf + offset, &enc_u64, sizeof(enc_u64));
    offset += sizeof(enc_u64);

    // bitmap's revision number
    enc_u64 = _endian_encode(bmpRevnum.load());
    memcpy(buf + offset, &enc_u64, sizeof(enc_u64));
    offset += sizeof(enc_u64);

    // curAllocBid
    bid_t sb_cur_alloc_bid = curAllocBid.load();
    enc_u64 = _endian_encode(sb_cur_alloc_bid);
    memcpy(buf + offset, &enc_u64, sizeof(enc_u64));
    offset += sizeof(enc_u64);

    // last header bid
    bid_t sb_last_hdr_bid = lastHdrBid.load();
    enc_u64 = _endian_encode(sb_last_hdr_bid);
    memcpy(buf + offset, &enc_u64, sizeof(enc_u64));
    offset += sizeof(enc_u64);

    // last header rev number
    uint64_t sb_last_hdr_revnum = lastHdrRevnum.load();
    enc_u64 = _endian_encode(sb_last_hdr_revnum);
    memcpy(buf + offset, &enc_u64, sizeof(enc_u64));
    offset += sizeof(enc_u64);

    // minimum active header revnum
    enc_u64 = _endian_encode(minLiveHdrRevnum);
    memcpy(buf + offset, &enc_u64, sizeof(enc_u64));
    offset += sizeof(enc_u64);

    // minimum active header BID
    enc_u64 = _endian_encode(minLiveHdrBid);
    memcpy(buf + offset, &enc_u64, sizeof(enc_u64));
    offset += sizeof(enc_u64);

    // # initial free blocks
    enc_u64 = _endian_encode(numInitFreeBlocks);
    memcpy(buf + offset, &enc_u64, sizeof(enc_u64));
    offset += sizeof(enc_u64);

    // # free blocks
    enc_u64 = _endian_encode(numFreeBlocks);
    memcpy(buf + offset, &enc_u64, sizeof(enc_u64));
    offset += sizeof(enc_u64);

    // bitmap size
    uint64_t sb_bmp_size = bmpSize.load();
    enc_u64 = _endian_encode(sb_bmp_size);
    memcpy(buf + offset, &enc_u64, sizeof(enc_u64));
    offset += sizeof(enc_u64);

    bool rsv_bmp_enabled = false;

    uint32_t cond = SB_RSV_READY;
    if (rsvBmp &&
        rsvBmp->status.compare_exchange_strong(cond, SB_RSV_WRITING) ) {
        rsv_bmp_enabled = true;
        // status becomes 'WRITING' so that switching will be postponed.
        // note that 'rsvBmp' is not currently used yet so that
        // it won't block any other tasks except for switching.
    }

    // reserved bitmap size (0 if not exist)
    if (rsv_bmp_enabled) {
        enc_u64 = _endian_encode(rsvBmp->bmpSize);
    } else {
        enc_u64 = 0;
    }
    memcpy(buf + offset, &enc_u64, sizeof(enc_u64));
    offset += sizeof(enc_u64);

    // bitmap doc offsets
    num_docs = bmpSizeToNumDocs(sb_bmp_size);
    for (i=0; i<num_docs; ++i) {
        enc_u64 = _endian_encode(bmpDocOffset[i]);
        memcpy(buf + offset, &enc_u64, sizeof(enc_u64));
        offset += sizeof(enc_u64);
    }

    // reserved bitmap doc offsets
    if (rsv_bmp_enabled) {
        num_docs = bmpSizeToNumDocs(rsvBmp->bmpSize);
        for (i=0; i<num_docs; ++i) {
            enc_u64 = _endian_encode(rsvBmp->bmpDocOffset[i]);
            memcpy(buf + offset, &enc_u64, sizeof(enc_u64));
            offset += sizeof(enc_u64);
        }

        rsvBmp->status = SB_RSV_READY;
    }

    // CRC
    crc = get_checksum(buf, offset, file->getCrcMode());
    _crc = _endian_encode(crc);
    memcpy(buf + offset, &_crc, sizeof(_crc));

    // set block marker
    memset(buf + blocksize, BLK_MARKER_SB, BLK_MARKER_SIZE);

    // directly write a block bypassing block cache
    r = file->writeBlocks(buf, 1, sb_no);
    if (r != real_blocksize) {
        char errno_msg[512];
        file->getOps()->get_errno_str(file->getFopsHandle(), errno_msg, 512);
        fs = FDB_RESULT_SB_RACE_CONDITION;
        fdb_log(log_callback, fs,
                "Failed to write the superblock (number: %" _F64 "), %s",
                static_cast<uint64_t>(sb_no), errno_msg);
        return fs;
    }

    // increase superblock's revision number
    revnum++;

    return FDB_RESULT_SUCCESS;
}


void Superblock::appendBmpDoc(FdbKvsHandle *handle)
{
    // == write bitmap into system docs ==
    // calculate # docs (1MB by default)
    // (1MB bitmap covers 32GB DB file)
    size_t i;
    uint64_t num_docs;
    char doc_key[64];

    // mark stale if previous doc offset exists
    if (bmpDocOffset) {
        for (i=0; i<numBmpDocs; ++i) {
            file->markDocStale(bmpDocOffset[i], _fdb_get_docsize(bmpDocs[i].length));
        }

        free(bmpDocOffset);
        free(bmpDocs);
        bmpDocOffset = NULL;
        bmpDocs = NULL;
    }

    uint64_t sb_bmp_size = bmpSize.load();
    numBmpDocs = num_docs = bmpSizeToNumDocs(sb_bmp_size);
    if (num_docs) {
        bmpDocOffset = (bid_t*)calloc(num_docs, sizeof(bid_t));
        bmpDocs = (struct docio_object*)calloc(num_docs,
                   sizeof(struct docio_object));
    }

    // bitmap doc offsets
    for (i=0; i<num_docs; ++i) {
        // append a system doc for bitmap chunk
        memset(&bmpDocs[i], 0x0, sizeof(struct docio_object));
        sprintf(doc_key, "bitmap_%" _F64 "_%d", bmpRevnum.load(), (int)i);
        bmpDocs[i].key = (void*)doc_key;
        bmpDocs[i].meta = NULL;
        bmpDocs[i].body = bmp + (i * SB_MAX_BITMAP_DOC_SIZE);

        bmpDocs[i].length.keylen = (keylen_t)strlen(doc_key)+1;
        bmpDocs[i].length.metalen = 0;
        if (i == num_docs - 1) {
            // the last doc
            bmpDocs[i].length.bodylen =
                (sb_bmp_size / 8) % SB_MAX_BITMAP_DOC_SIZE;
        } else {
            // otherwise: 1MB
            bmpDocs[i].length.bodylen = SB_MAX_BITMAP_DOC_SIZE;
        }
        bmpDocs[i].seqnum = 0;
        bmpDocOffset[i] =
            handle->dhandle->appendSystemDoc_Docio(&bmpDocs[i]);
    }
}

void Superblock::appendRsvBmpDoc(FdbKvsHandle *handle)
{
    size_t i;
    uint64_t num_docs;
    char doc_key[64];
    struct sb_rsv_bmp *rsv = NULL;

    rsv = rsvBmp;
    if (!rsv || rsv->status.load() != SB_RSV_INITIALIZING) {
        return;
    }

    rsv->numBmpDocs = num_docs = bmpSizeToNumDocs(rsv->bmpSize);
    if (num_docs) {
        rsv->bmpDocOffset = (bid_t*)calloc(num_docs, sizeof(bid_t));
        rsv->bmpDocs = (struct docio_object*)
                        calloc(num_docs, sizeof(struct docio_object));
    }

    // bitmap doc offsets
    for (i=0; i<num_docs; ++i) {
        // append a system doc for bitmap chunk
        memset(&rsv->bmpDocs[i], 0x0, sizeof(struct docio_object));
        sprintf(doc_key, "bitmap_%" _F64 "_%d", rsv->bmpRevnum, (int)i);
        rsv->bmpDocs[i].key = (void*)doc_key;
        rsv->bmpDocs[i].meta = NULL;
        rsv->bmpDocs[i].body = rsv->bmp + (i * SB_MAX_BITMAP_DOC_SIZE);

        rsv->bmpDocs[i].length.keylen = (keylen_t)strlen(doc_key)+1;
        rsv->bmpDocs[i].length.metalen = 0;
        if (i == num_docs - 1) {
            // the last doc
            rsv->bmpDocs[i].length.bodylen =
                (rsv->bmpSize / 8) % SB_MAX_BITMAP_DOC_SIZE;
        } else {
            // otherwise: 1MB
            rsv->bmpDocs[i].length.bodylen = SB_MAX_BITMAP_DOC_SIZE;
        }
        rsv->bmpDocs[i].seqnum = 0;
        rsv->bmpDocOffset[i] =
            handle->dhandle->appendSystemDoc_Docio(&rsv->bmpDocs[i]);
    }

    // now 'rsvBmp' is available.
    rsv->status = SB_RSV_READY;
}

fdb_status Superblock::readBmpDoc(FdbKvsHandle *handle)
{
    // == read bitmap from system docs ==
    size_t i;
    uint64_t num_docs;
    int64_t r_offset;
    char doc_key[64];
    struct sb_rsv_bmp *rsv = NULL;

    // skip if previous bitmap exists OR
    // there is no bitmap to be fetched (fast screening)
    if (bmp.load(std::memory_order_relaxed) ||
        bmpSize.load() == 0) {
        return FDB_RESULT_SUCCESS;
    }

    spin_lock(&lock);

    // check once again if superblock is already initialized
    // while the thread was blocked by the lock.
    if (bmp.load(std::memory_order_relaxed)) {
        spin_unlock(&lock);
        return FDB_RESULT_SUCCESS;
    }

    uint64_t sb_bmp_size = bmpSize.load();
    numBmpDocs = num_docs = bmpSizeToNumDocs(sb_bmp_size);
    if (!num_docs) {
        spin_unlock(&lock);
        return FDB_RESULT_SUCCESS;
    }

    free(bmp);
    bmp = (uint8_t*)calloc(1, (sb_bmp_size+7) / 8);

    for (i=0; i<num_docs; ++i) {
        memset(&bmpDocs[i], 0x0, sizeof(struct docio_object));
        // pre-allocated buffer for key
        bmpDocs[i].key = (void*)doc_key;
        // directly point to the bitmap
        bmpDocs[i].body = bmp + (i * SB_MAX_BITMAP_DOC_SIZE);

        r_offset = handle->dhandle->readDoc_Docio(bmpDocOffset[i],
                                                  &bmpDocs[i], true);
        if (r_offset <= 0) {
            // read fail
            free(bmp);
            bmp = NULL;

            spin_unlock(&lock);
            return r_offset < 0 ? (fdb_status) r_offset : FDB_RESULT_SB_READ_FAIL;
        }
    }

    constructBmpIdx(&bmpIdx, bmp, sb_bmp_size,
                       curAllocBid.load());

    rsv = rsvBmp;
    if (rsv && rsv->status.load() == SB_RSV_INITIALIZING) {
        // reserved bitmap exists
        rsv->numBmpDocs = num_docs = bmpSizeToNumDocs(rsv->bmpSize);
        if (!num_docs) {
            spin_unlock(&lock);
            return FDB_RESULT_SUCCESS;
        }

        rsv->bmp = (uint8_t*)calloc(1, (rsv->bmpSize+7) / 8);

        for (i=0; i<num_docs; ++i) {

            memset(&rsv->bmpDocs[i], 0x0, sizeof(struct docio_object));
            // pre-allocated buffer for key
            rsv->bmpDocs[i].key = (void*)doc_key;
            // directly point to the (reserved) bitmap
            rsv->bmpDocs[i].body = rsv->bmp + (i * SB_MAX_BITMAP_DOC_SIZE);

            r_offset = handle->dhandle->readDoc_Docio(rsv->bmpDocOffset[i],
                                                      &rsv->bmpDocs[i], true);
            if (r_offset <= 0) {
                // read fail
                free(rsv->bmp);
                free(bmp);
                rsv->bmp = bmp = NULL;

                spin_unlock(&lock);
                return r_offset < 0 ? (fdb_status) r_offset : FDB_RESULT_SB_READ_FAIL;
            }
        }

        constructBmpIdx(&rsv->bmpIdx, rsv->bmp, rsv->bmpSize, 0);
        rsv->status = SB_RSV_READY;
    }

    spin_unlock(&lock);
    return FDB_RESULT_SUCCESS;
}

bool Superblock::checkSyncPeriod()
{
    if (numAlloc * file->getBlockSize() > SB_SYNC_PERIOD) {
        return true;
    }
    return false;
}

bool Superblock::updateHeader(FdbKvsHandle *handle)
{
    bool ret = false;

    if ((lastHdrBid.load() != handle->last_hdr_bid) &&
        (lastHdrRevnum.load() < handle->cur_header_revnum)) {

        lastHdrBid = handle->last_hdr_bid.load();
        lastHdrRevnum.store(handle->cur_header_revnum.load());

        uint64_t lw_revnum = handle->file->getLastWritableBmpRevnum();
        if (lw_revnum == bmpRevnum.load() &&
            bmpPrev) {
            free(bmpPrev);
            bmpPrev = NULL;
        }
        ret = true;
    }

    return ret;
}

fdb_status Superblock::syncCircular(FdbKvsHandle *handle)
{
    uint64_t sb_revnum;
    fdb_status fs;

    sb_revnum = revnum.load();
    fs = writeSb(sb_revnum % config.num_sb,
                  &handle->log_callback);
    return fs;
}

// Do not call any public api that would sync db header to any uncommitted
// header.
sb_decision_t Superblock::checkBlockReuse(FdbKvsHandle *handle)

{
    // start block reusing when
    // 1) if blocks are not reused yet in this file:
    //    when file size becomes larger than the threshold
    // 2) otherwise:
    //    when # free blocks decreases under the threshold

    uint64_t live_datasize;
    uint64_t filesize;
    uint64_t ratio;

    if (file->getFileStatus() != FILE_NORMAL) {
        // being compacted file does not allow block reusing
        return SBD_NONE;
    }

    uint64_t block_reusing_threshold =
                        file->getConfig()->getBlockReusingThreshold();
    if (block_reusing_threshold == 0 || block_reusing_threshold >= 100) {
        // circular block reusing is disabled
        return SBD_NONE;
    }

    filesize = file->getPos();
    if (filesize < SB_MIN_BLOCK_REUSING_FILESIZE) {
        return SBD_NONE;
    }

    // at least # keeping headers should exist
    // since the last block reusing
    if (handle->cur_header_revnum <=
        minLiveHdrRevnum + file->getConfig()->getNumKeepingHeaders()) {
        return SBD_NONE;
    }

    live_datasize = FdbEngine::getInstance()->estimateSpaceUsedInternal(handle);
    if (filesize == 0 || live_datasize == 0 ||
        live_datasize > filesize) {
        return SBD_NONE;
    }

    ratio = (filesize - live_datasize) * 100 / filesize;

    if (ratio > block_reusing_threshold) {
        if (!bmpExists()) {
            // block reusing has not been started yet
            return SBD_RECLAIM;
        } else {
            // stale blocks are already being reused before
            if (numFreeBlocks == 0) {
                if (rsvBmp) {
                    // reserved bitmap exists
                    return SBD_SWITCH;
                } else {
                    // re-reclaim
                    return SBD_RECLAIM;
                }
            } else if ( (numFreeBlocks * 100 <
                         numInitFreeBlocks * SB_PRE_RECLAIM_RATIO)) {
                if ( numInitFreeBlocks * file->getConfig()->getBlockSize()
                         > SB_MIN_BLOCK_REUSING_FILESIZE )  {
                    return SBD_RESERVE;
                }
            }
        }
    }

    return SBD_NONE;
}

bool Superblock::reclaimReusableBlocks(FdbKvsHandle *handle)
{
    size_t i;
    uint64_t num_blocks, bmp_size_byte;
    stale_header_info sheader;
    reusable_block_list blist;

    // should flush all dirty blocks in cache
    file->sync_FileMgr(false, &handle->log_callback);

    sheader = fdb_get_smallest_active_header(handle);
    if (sheader.bid == BLK_NOT_FOUND) {
        return false;
    }

    // get reusable block list
    blist = file->getStaleData()->getReusableBlocks(handle, sheader);

    // update superblock's bitmap
    uint8_t *new_bmp = NULL, *old_bmp = NULL;
    num_blocks = file->getPos() / file->getBlockSize();
    // 8 bitmaps per byte
    bmp_size_byte = (num_blocks+7) / 8;
    fdb_assert(num_blocks >= SB_DEFAULT_NUM_SUPERBLOCKS,
               num_blocks, SB_DEFAULT_NUM_SUPERBLOCKS);
    new_bmp = (uint8_t*)calloc(1, bmp_size_byte);

    // free pre-existing bmp index
    freeBmpIdx(&bmpIdx);

    for (i=0; i<blist.n_blocks; ++i) {
        setBmp(new_bmp, blist.blocks[i].bid, blist.blocks[i].count);
        if (i==0 && curAllocBid.load() == BLK_NOT_FOUND) {
            curAllocBid.store(blist.blocks[i].bid);
        }
        numFreeBlocks += blist.blocks[i].count;
        // add info for supplementary bmp index
        addBmpIdx(&bmpIdx, blist.blocks[i].bid, blist.blocks[i].count);
    }
    free(blist.blocks);

    beginBmpChange();
    old_bmp = bmp.load(std::memory_order_relaxed);
    bmp.store(new_bmp, std::memory_order_relaxed);
    bmpSize = num_blocks;
    minLiveHdrRevnum = sheader.revnum;
    minLiveHdrBid = sheader.bid;
    bmpRevnum++;
    numInitFreeBlocks = numFreeBlocks;
    endBmpChange();
    free(old_bmp);

    return true;
}

bool Superblock::reserveNextReusableBlocks(FdbKvsHandle *handle)
{
    size_t i;
    uint64_t num_blocks, bmp_size_byte;
    stale_header_info sheader;
    reusable_block_list blist;
    struct sb_rsv_bmp *rsv = NULL;

    if (rsvBmp) {
        // next bitmap already reclaimed
        return false;
    }

    sheader = fdb_get_smallest_active_header(handle);
    if (sheader.bid == BLK_NOT_FOUND) {
        return false;
    }

    // get reusable block list
    blist = file->getStaleData()->getReusableBlocks(handle, sheader);

    // calculate bitmap size
    num_blocks = file->getPos() / file->getBlockSize();
    bmp_size_byte = (num_blocks+7) / 8;
    if (num_blocks) {
        rsv = (struct sb_rsv_bmp*)calloc(1, sizeof(struct sb_rsv_bmp));
        rsv->bmp = (uint8_t*)calloc(1, bmp_size_byte);
        rsv->curAllocBid = BLK_NOT_FOUND;

        // the initial status is 'INITIALIZING' so that 'rsvBmp' is not
        // available until executing sb_rsv_append_doc().
        rsv->status = SB_RSV_INITIALIZING;
        avl_init(&rsv->bmpIdx, NULL);
        rsv->bmpSize = num_blocks;

        for (i=0; i<blist.n_blocks; ++i) {
            setBmp(rsv->bmp, blist.blocks[i].bid, blist.blocks[i].count);
            if (i==0 && rsv->curAllocBid == BLK_NOT_FOUND) {
                rsv->curAllocBid = blist.blocks[i].bid;
            }
            rsv->numFreeBlocks += blist.blocks[i].count;
            addBmpIdx(&rsv->bmpIdx, blist.blocks[i].bid, blist.blocks[i].count);
        }
        free(blist.blocks);

        rsv->minLiveHdrRevnum = sheader.revnum;
        rsv->minLiveHdrBid = sheader.bid;
        rsv->bmpRevnum = bmpRevnum+1;
        rsvBmp = rsv;
    }

    return true;
}

void Superblock::returnReusableBlocks(FdbKvsHandle *handle)
{
    uint64_t node_id;
    bid_t cur;
    struct sb_rsv_bmp *rsv;
    struct avl_node *a;
    struct bmp_idx_node *item, query;

    // re-insert all remaining bitmap into stale list
    uint64_t sb_bmp_size = bmpSize.load();
    for (cur = curAllocBid.load(); cur < sb_bmp_size; ++cur) {
        if (isBmpSet(bmp, cur)) {
            file->addStaleRegion(cur, 1);
        }

        if ((cur % 256) == 0 && cur > 0) {
            // node ID changes
            // remove & free current bmp node
            node_id = cur / 256;
            query.id = node_id - 1;
            a = avl_search(&bmpIdx, &query.avl, _bmp_idx_cmp);
            if (a) {
                item = _get_entry(a, struct bmp_idx_node, avl);
                avl_remove(&bmpIdx, a);
                free(item);
            }

            // move to next bmp node
            do {
                a = avl_first(&bmpIdx);
                if (a) {
                    item = _get_entry(a, struct bmp_idx_node, avl);
                    if (item->id <= node_id) {
                        avl_remove(&bmpIdx, a);
                        free(item);
                        continue;
                    }
                    cur = item->id * 256;
                    break;
                }

                // no more reusable block
                cur = sb_bmp_size;
                break;
            } while (true);
        }
    }
    numFreeBlocks = 0;
    curAllocBid.store(BLK_NOT_FOUND);

    // do the same work for the reserved blocks if exist
    rsv = rsvBmp;
    uint32_t cond = SB_RSV_READY;
    if (rsv && rsv->status.compare_exchange_strong(cond, SB_RSV_VOID)) {

        for (cur = rsv->curAllocBid; cur < rsv->bmpSize; ++cur) {
            if (isBmpSet(rsv->bmp, cur)) {
                file->addStaleRegion(cur, 1);
            }

            if ((cur % 256) == 0 && cur > 0) {
                // node ID changes
                // remove & free current bmp node
                node_id = cur / 256;
                query.id = node_id - 1;
                a = avl_search(&rsv->bmpIdx, &query.avl, _bmp_idx_cmp);
                if (a) {
                    item = _get_entry(a, struct bmp_idx_node, avl);
                    avl_remove(&rsv->bmpIdx, a);
                    free(item);
                }

                // move to next bmp node
                do {
                    a = avl_first(&rsv->bmpIdx);
                    if (a) {
                        item = _get_entry(a, struct bmp_idx_node, avl);
                        if (item->id <= node_id) {
                            avl_remove(&rsv->bmpIdx, a);
                            free(item);
                            continue;
                        }
                        cur = item->id * 256;
                        break;
                    }

                    // no more reusable block
                    cur = rsv->bmpSize;
                    break;
                } while (true);
            }
        }
        rsv->numFreeBlocks = 0;
        rsv->curAllocBid = BLK_NOT_FOUND;

        freeBmpIdx(&rsv->bmpIdx);
        freeRsv(rsv);
        free(rsv);
        rsvBmp = NULL;
    }

    // re-store into stale tree using next header's revnum
    filemgr_header_revnum_t revnum = handle->cur_header_revnum;
    file->getStaleData()->gatherRegions(handle, revnum + 1,
                                                BLK_NOT_FOUND,
                                                BLK_NOT_FOUND, 0, false );
}

void Superblock::updateBmp(uint8_t *target_bmp, bid_t bid, uint64_t len, int mode)
{
    // mode==0: bitmap clear
    // mode==1: bitmap set

    uint64_t front_pos, front_len, rear_pos, rear_len;
    uint64_t mid_pos, mid_len;

    //      front_len        rear_len
    //      <->              <-->
    // 00000111 | 11111111 | 11110000
    //      ^     <------> mid
    //      front_pos

    front_pos = bid;
    front_len = 8 - mod8(front_pos);

    if (front_len >= len) {
        front_len = len;
        rear_pos = rear_len = mid_pos = mid_len = 0;
    } else {
        rear_pos = rd8(bid + len);
        rear_len = mod8(bid + len);

        mid_pos = bid + front_len;
        mid_len = len - front_len - rear_len;
    }

    // front bitmaps
    if (front_len) {
        if (mode) {
            target_bmp[div8(front_pos)] |= bmp_2d_mask[mod8(front_pos)][front_len];
        } else {
            target_bmp[div8(front_pos)] &= ~bmp_2d_mask[mod8(front_pos)][front_len];
        }
    }
    // rear bitmaps
    if (rear_len) {
        if (mode) {
            target_bmp[div8(rear_pos)] |= bmp_2d_mask[mod8(rear_pos)][rear_len];
        } else {
            target_bmp[div8(rear_pos)] &= ~bmp_2d_mask[mod8(rear_pos)][rear_len];
        }
    }

    // mid bitmaps
    uint8_t mask = (mode)?(0xff):(0x0);
    if (mid_len == 8) {
        // 8 bitmaps (1 byte)
        target_bmp[div8(mid_pos)] = mask;
    } else if (mid_len < 64) {
        // 16 ~ 56 bitmaps (2 ~ 7 bytes)
        size_t i;
        for (i=0; i<mid_len; i+=8) {
            target_bmp[div8(mid_pos+i)] = mask;
        }
    } else {
        // larger than 64 bitmaps (8 bytes)
        memset(target_bmp + div8(mid_pos), mask, div8(mid_len));
    }
}

void Superblock::setBmp(uint8_t *target_bmp, bid_t bid, uint64_t len)
{
    updateBmp(target_bmp, bid, len, 1);
}

void Superblock::clearBmp(uint8_t *target_bmp, bid_t bid, uint64_t len)
{
    updateBmp(target_bmp, bid, len, 0);
}

void Superblock::addBmpIdx(struct avl_tree *target_idx, bid_t bid, bid_t count)
{
    bid_t cur, start_id, stop_id;
    struct avl_node *a;
    struct bmp_idx_node *item, query;

    // 256 blocks per node
    start_id = bid >> 8;
    stop_id = (bid+count-1) >> 8;

    for (cur=start_id; cur<=stop_id; ++cur) {
        query.id = cur;
        a = avl_search(target_idx, &query.avl, _bmp_idx_cmp);
        if (a) {
            // already exists .. do nothing
        } else {
            // create a node
            item = (struct bmp_idx_node*)calloc(1, sizeof(struct bmp_idx_node));
            item->id = query.id;
            avl_insert(target_idx, &item->avl, _bmp_idx_cmp);
        }
    }
}

void Superblock::freeBmpIdx(struct avl_tree *target_idx)
{
    // free all supplemental bmp idx nodes
    struct avl_node *a;
    struct bmp_idx_node *item;
    a = avl_first(target_idx);
    while (a) {
        item = _get_entry(a, struct bmp_idx_node, avl);
        a = avl_next(a);
        avl_remove(target_idx, &item->avl);
        free(item);
    }
}

void Superblock::constructBmpIdx(struct avl_tree *target_idx,
                               uint8_t *src_bmp,
                               uint64_t src_bmp_size,
                               bid_t start_bid)
{
    uint64_t i, node_idx;
    uint64_t *bmp64 = (uint64_t*)src_bmp;
    struct bmp_idx_node *item;

    if (start_bid == BLK_NOT_FOUND) {
        start_bid = 0;
    }

    // Since a single byte includes 8 bitmaps, an 8-byte integer contains 64 bitmaps.
    // By converting bitmap array to uint64_t array, we can quickly verify if a
    // 64-bitmap-group has at least one non-zero bit or not.
    for (i=start_bid/64; i<src_bmp_size/64; ++i) {
        // in this loop, 'i' denotes bitmap group number.
        node_idx = i/4;
        if (bmp64[i]) {
            item = (struct bmp_idx_node *)calloc(1, sizeof(struct bmp_idx_node));
            item->id = node_idx;
            avl_insert(target_idx, &item->avl, _bmp_idx_cmp);
            // skip other bitmaps in the same bitmap index node
            // (1 bitmap index node == 4 bitmap groups == 256 bitmaps)
            i = (node_idx+1)*4;
        }
    }

    // If there are remaining bitmaps, check if they are non-zero or not one by one.
    if (src_bmp_size % 64) {
        uint8_t off;
        uint64_t idx, start;

        start = (src_bmp_size/64)*64;
        if (start < start_bid) {
            start = start_bid;
        }

        for (i=start; i<src_bmp_size; ++i) {
            // in this loop, 'i' denotes bitmap number (i.e., BID).
            idx = div8(i);
            off = mod8(i);
            if (src_bmp[idx] & bmp_basic_mask[off]) {
                node_idx = i >> 8;
                item = (struct bmp_idx_node *)calloc(1, sizeof(struct bmp_idx_node));
                item->id = node_idx;
                avl_insert(target_idx, &item->avl, _bmp_idx_cmp);
                i = (node_idx+1)*256;
            }
        }
    }
}

size_t Superblock::bmpSizeToNumDocs(uint64_t bmp_size)
{
    if (bmp_size) {
        // 8 bitmaps per byte
        uint64_t num_bits_per_doc = 8 * SB_MAX_BITMAP_DOC_SIZE;
        return (bmp_size + num_bits_per_doc - 1) / num_bits_per_doc;
    } else {
        return 0;
    }
}

bool Superblock::isBmpSet(uint8_t *bmp, bid_t bid)
{
    return (bmp[div8(bid)] & bmp_basic_mask[mod8(bid)]);
}


void Superblock::freeRsv(struct sb_rsv_bmp *rsv)
{
    free(rsv->bmp);
    free(rsv->bmpDocOffset);
    free(rsv->bmpDocs);
}

