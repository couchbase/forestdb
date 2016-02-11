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

static void _add_bmp_idx(struct avl_tree *bmp_idx, bid_t bid, bid_t count)
{
    bid_t cur, start_id, stop_id;
    struct avl_node *a;
    struct bmp_idx_node *item, query;

    // 256 blocks per node
    start_id = bid >> 8;
    stop_id = (bid+count-1) >> 8;

    for (cur=start_id; cur<=stop_id; ++cur) {
        query.id = cur;
        a = avl_search(bmp_idx, &query.avl, _bmp_idx_cmp);
        if (a) {
            // already exists .. do nothing
        } else {
            // create a node
            item = (struct bmp_idx_node*)calloc(1, sizeof(struct bmp_idx_node));
            item->id = query.id;
            avl_insert(bmp_idx, &item->avl, _bmp_idx_cmp);
        }
    }
}

static void _free_bmp_idx(struct avl_tree *bmp_idx)
{
    // free all supplemental bmp idx nodes
    struct avl_node *a;
    struct bmp_idx_node *item;
    a = avl_first(bmp_idx);
    while (a) {
        item = _get_entry(a, struct bmp_idx_node, avl);
        a = avl_next(a);
        avl_remove(bmp_idx, &item->avl);
        free(item);
    }
}

static void _construct_bmp_idx(struct avl_tree *bmp_idx,
                               uint8_t *bmp,
                               uint64_t bmp_size,
                               bid_t start_bid)
{
    uint64_t i, node_idx;
    uint64_t *bmp64 = (uint64_t*)bmp;
    struct bmp_idx_node *item;

    if (start_bid == BLK_NOT_FOUND) {
        start_bid = 0;
    }

    // Since a single byte includes 8 bitmaps, an 8-byte integer contains 64 bitmaps.
    // By converting bitmap array to uint64_t array, we can quickly verify if a
    // 64-bitmap-group has at least one non-zero bit or not.
    for (i=start_bid/64; i<bmp_size/64; ++i) {
        // in this loop, 'i' denotes bitmap group number.
        node_idx = i/4;
        if (bmp64[i]) {
            item = (struct bmp_idx_node *)calloc(1, sizeof(struct bmp_idx_node));
            item->id = node_idx;
            avl_insert(bmp_idx, &item->avl, _bmp_idx_cmp);
            // skip other bitmaps in the same bitmap index node
            // (1 bitmap index node == 4 bitmap groups == 256 bitmaps)
            i = (node_idx+1)*4;
        }
    }

    // If there are remaining bitmaps, check if they are non-zero or not one by one.
    if (bmp_size % 64) {
        uint8_t idx, off;
        uint64_t start;

        start = (bmp_size/64)*64;
        if (start < start_bid) {
            start = start_bid;
        }

        for (i=start; i<bmp_size; ++i) {
            // in this loop, 'i' denotes bitmap number (i.e., BID).
            idx = div8(i);
            off = mod8(i);
            if (bmp[idx] & bmp_basic_mask[off]) {
                node_idx = i >> 8;
                item = (struct bmp_idx_node *)calloc(1, sizeof(struct bmp_idx_node));
                item->id = node_idx;
                avl_insert(bmp_idx, &item->avl, _bmp_idx_cmp);
                i = (node_idx+1)*256;
            }
        }
    }
}

INLINE size_t _bmp_size_to_num_docs(uint64_t bmp_size)
{
    if (bmp_size) {
        // 8 bitmaps per byte
        uint64_t num_bits_per_doc = 8 * SB_MAX_BITMAP_DOC_SIZE;
        return (bmp_size + num_bits_per_doc - 1) / num_bits_per_doc;
    } else {
        return 0;
    }
}

INLINE bool _is_bmp_set(uint8_t *bmp, bid_t bid)
{
    return (bmp[div8(bid)] & bmp_basic_mask[mod8(bid)]);
}

void sb_bmp_append_doc(fdb_kvs_handle *handle)
{
    // == write bitmap into system docs ==
    // calculate # docs (1MB by default)
    // (1MB bitmap covers 32GB DB file)
    size_t i;
    uint64_t num_docs;
    char doc_key[64];
    struct superblock *sb = handle->file->sb;

    // mark stale if previous doc offset exists
    if (sb->bmp_doc_offset) {
        for (i=0; i<sb->num_bmp_docs; ++i) {
            filemgr_mark_stale(handle->file, sb->bmp_doc_offset[i],
                _fdb_get_docsize(sb->bmp_docs[i].length));
        }

        free(sb->bmp_doc_offset);
        free(sb->bmp_docs);
        sb->bmp_doc_offset = NULL;
        sb->bmp_docs = NULL;
    }

    sb->num_bmp_docs = num_docs = _bmp_size_to_num_docs(sb->bmp_size);
    if (num_docs) {
        sb->bmp_doc_offset = (bid_t*)calloc(num_docs, sizeof(bid_t));
        sb->bmp_docs = (struct docio_object*)
                       calloc(num_docs, sizeof(struct docio_object));
    }

    // bitmap doc offsets
    for (i=0; i<num_docs; ++i) {
        // append a system doc for bitmap chunk
        memset(&sb->bmp_docs[i], 0x0, sizeof(struct docio_object));
        sprintf(doc_key, "bitmap_%" _F64 "_%d", sb->bmp_revnum, (int)i);
        sb->bmp_docs[i].key = (void*)doc_key;
        sb->bmp_docs[i].meta = NULL;
        sb->bmp_docs[i].body = sb->bmp + (i * SB_MAX_BITMAP_DOC_SIZE);

        sb->bmp_docs[i].length.keylen = strlen(doc_key)+1;
        sb->bmp_docs[i].length.metalen = 0;
        if (i == num_docs - 1) {
            // the last doc
            sb->bmp_docs[i].length.bodylen =
                (sb->bmp_size / 8) % SB_MAX_BITMAP_DOC_SIZE;
        } else {
            // otherwise: 1MB
            sb->bmp_docs[i].length.bodylen = SB_MAX_BITMAP_DOC_SIZE;
        }
        sb->bmp_docs[i].seqnum = 0;
        sb->bmp_doc_offset[i] =
            docio_append_doc_system(handle->dhandle, &sb->bmp_docs[i]);
    }
}

void sb_rsv_append_doc(fdb_kvs_handle *handle)
{
    size_t i;
    uint64_t num_docs;
    char doc_key[64];
    struct superblock *sb = handle->file->sb;
    struct sb_rsv_bmp *rsv = NULL;

    if (!sb) {
        return;
    }

    rsv = sb->rsv_bmp;
    if (!rsv ||
        atomic_get_uint32_t(&rsv->status) != SB_RSV_INITIALIZING) {
        return;
    }

    rsv->num_bmp_docs = num_docs = _bmp_size_to_num_docs(rsv->bmp_size);
    if (num_docs) {
        rsv->bmp_doc_offset = (bid_t*)calloc(num_docs, sizeof(bid_t));
        rsv->bmp_docs = (struct docio_object*)
                        calloc(num_docs, sizeof(struct docio_object));
    }

    // bitmap doc offsets
    for (i=0; i<num_docs; ++i) {
        // append a system doc for bitmap chunk
        memset(&rsv->bmp_docs[i], 0x0, sizeof(struct docio_object));
        sprintf(doc_key, "bitmap_%" _F64 "_%d", rsv->bmp_revnum, (int)i);
        rsv->bmp_docs[i].key = (void*)doc_key;
        rsv->bmp_docs[i].meta = NULL;
        rsv->bmp_docs[i].body = rsv->bmp + (i * SB_MAX_BITMAP_DOC_SIZE);

        rsv->bmp_docs[i].length.keylen = strlen(doc_key)+1;
        rsv->bmp_docs[i].length.metalen = 0;
        if (i == num_docs - 1) {
            // the last doc
            rsv->bmp_docs[i].length.bodylen =
                (rsv->bmp_size / 8) % SB_MAX_BITMAP_DOC_SIZE;
        } else {
            // otherwise: 1MB
            rsv->bmp_docs[i].length.bodylen = SB_MAX_BITMAP_DOC_SIZE;
        }
        rsv->bmp_docs[i].seqnum = 0;
        rsv->bmp_doc_offset[i] =
            docio_append_doc_system(handle->dhandle, &rsv->bmp_docs[i]);
    }

    // now 'rsv_bmp' is available.
    atomic_store_uint32_t(&rsv->status, SB_RSV_READY);
}

fdb_status sb_bmp_fetch_doc(fdb_kvs_handle *handle)
{
    // == read bitmap from system docs ==
    size_t i;
    uint64_t num_docs, r_offset;
    char doc_key[64];
    struct superblock *sb = handle->file->sb;
    struct sb_rsv_bmp *rsv = NULL;

    // skip if previous bitmap exists
    if (sb->bmp) {
        return FDB_RESULT_SUCCESS;
    }

    sb->num_bmp_docs = num_docs = _bmp_size_to_num_docs(sb->bmp_size);
    if (!num_docs) {
        return FDB_RESULT_SUCCESS;
    }

    free(sb->bmp);
    sb->bmp = (uint8_t*)calloc(1, (sb->bmp_size+7) / 8);

    for (i=0; i<num_docs; ++i) {
        memset(&sb->bmp_docs[i], 0x0, sizeof(struct docio_object));
        // pre-allocated buffer for key
        sb->bmp_docs[i].key = (void*)doc_key;
        // directly point to the bitmap
        sb->bmp_docs[i].body = sb->bmp + (i * SB_MAX_BITMAP_DOC_SIZE);

        r_offset = docio_read_doc(handle->dhandle, sb->bmp_doc_offset[i],
                                  &sb->bmp_docs[i], true);
        if (r_offset == sb->bmp_doc_offset[i]) {
            // read fail
            free(sb->bmp);
            sb->bmp = NULL;
            return FDB_RESULT_SB_READ_FAIL;
        }
    }

    _construct_bmp_idx(&sb->bmp_idx, sb->bmp, sb->bmp_size, sb->cur_alloc_bid);

    rsv = sb->rsv_bmp;
    if (rsv && atomic_get_uint32_t(&rsv->status) == SB_RSV_INITIALIZING) {
        // reserved bitmap exists
        rsv->num_bmp_docs = num_docs = _bmp_size_to_num_docs(rsv->bmp_size);
        if (!num_docs) {
            return FDB_RESULT_SUCCESS;
        }

        rsv->bmp = (uint8_t*)calloc(1, (rsv->bmp_size+7) / 8);

        for (i=0; i<num_docs; ++i) {

            memset(&rsv->bmp_docs[i], 0x0, sizeof(struct docio_object));
            // pre-allocated buffer for key
            rsv->bmp_docs[i].key = (void*)doc_key;
            // directly point to the (reserved) bitmap
            rsv->bmp_docs[i].body = rsv->bmp + (i * SB_MAX_BITMAP_DOC_SIZE);

            r_offset = docio_read_doc(handle->dhandle, rsv->bmp_doc_offset[i],
                                      &rsv->bmp_docs[i], true);
            if (r_offset == rsv->bmp_doc_offset[i]) {
                // read fail
                free(rsv->bmp);
                free(sb->bmp);
                rsv->bmp = sb->bmp = NULL;
                return FDB_RESULT_SB_READ_FAIL;
            }
        }

        _construct_bmp_idx(&rsv->bmp_idx, rsv->bmp, rsv->bmp_size, 0);
        atomic_store_uint32_t(&rsv->status, SB_RSV_READY);
    }

    return FDB_RESULT_SUCCESS;
}

bool sb_check_sync_period(fdb_kvs_handle *handle)
{
    struct superblock *sb = handle->file->sb;

    if (sb && sb->num_alloc * handle->file->blocksize > SB_SYNC_PERIOD) {
        return true;
    }
    return false;
}

void sb_update_header(fdb_kvs_handle *handle)
{
    if (handle->file->sb) {
        handle->file->sb->last_hdr_bid = handle->last_hdr_bid;
        handle->file->sb->last_hdr_revnum = handle->cur_header_revnum;

        uint64_t lc_revnum = atomic_get_uint64_t(&handle->file->last_commit_bmp_revnum);
        if (lc_revnum == handle->file->sb->bmp_revnum &&
            handle->file->sb->bmp_prev) {
            free(handle->file->sb->bmp_prev);
            handle->file->sb->bmp_prev = NULL;
        }
    }
}

void sb_reset_num_alloc(fdb_kvs_handle *handle)
{
    if (handle->file->sb) {
        handle->file->sb->num_alloc = 0;
    }
}

fdb_status sb_sync_circular(fdb_kvs_handle *handle)
{
    fdb_status fs;
    fs = sb_write(handle->file,
                  handle->file->sb->revnum % handle->file->sb->config->num_sb,
                  &handle->log_callback);
    return fs;
}

sb_decision_t sb_check_block_reusing(fdb_kvs_handle *handle)

{
    // start block reusing when
    // 1) if blocks are not reused yet in this file:
    //    when file size becomes larger than the threshold
    // 2) otherwise:
    //    when # free blocks decreases under the threshold

    uint64_t live_datasize;
    uint64_t filesize;
    uint64_t ratio;
    struct superblock *sb = handle->file->sb;

    if (!sb) {
        return SBD_NONE;
    }

    if (filemgr_get_file_status(handle->file) != FILE_NORMAL) {
        // being compacted file does not allow block reusing
        return SBD_NONE;
    }

    uint64_t block_reusing_threshold =
        atomic_get_uint64_t(&handle->file->config->block_reusing_threshold);
    if (block_reusing_threshold == 0 || block_reusing_threshold >= 100) {
        // circular block reusing is disabled
        return SBD_NONE;
    }

    filesize = filemgr_get_pos(handle->file);
    if (filesize < SB_MIN_BLOCK_REUSING_FILESIZE) {
        return SBD_NONE;
    }

    // at least # keeping headers should exist
    // since the last block reusing
    if (handle->cur_header_revnum <=
        sb->min_live_hdr_revnum +
        atomic_get_uint64_t(&handle->file->config->num_keeping_headers)) {
        return SBD_NONE;
    }

    live_datasize = fdb_estimate_space_used(handle->fhandle);
    if (filesize == 0 || live_datasize == 0 ||
        live_datasize > filesize) {
        return SBD_NONE;
    }

    ratio = (filesize - live_datasize) * 100 / filesize;

    if (ratio > block_reusing_threshold) {
        if (sb->bmp == NULL) {
            // block reusing has not been started yet
            return SBD_RECLAIM;
        } else {
            // stale blocks are already being reused before
            if (sb->num_free_blocks == 0) {
                if (sb->rsv_bmp) {
                    // reserved bitmap exists
                    return SBD_SWITCH;
                } else {
                    // re-reclaim
                    return SBD_RECLAIM;
                }
            } else if ( (sb->num_free_blocks * 100 <
                         sb->num_init_free_blocks * SB_PRE_RECLAIM_RATIO)) {
                if (sb->num_init_free_blocks * handle->file->config->blocksize >
                    SB_MIN_BLOCK_REUSING_FILESIZE)  {
                    return SBD_RESERVE;
                }
            }
        }
    }

    return SBD_NONE;
}

bool sb_reclaim_reusable_blocks(fdb_kvs_handle *handle)
{
    size_t i;
    uint64_t num_blocks, bmp_size_byte;
    stale_header_info sheader;
    reusable_block_list blist;
    struct superblock *sb = handle->file->sb;

    // should flush all dirty blocks in cache
    filemgr_sync(handle->file, false, &handle->log_callback);

    sheader = fdb_get_smallest_active_header(handle);
    if (sheader.bid == BLK_NOT_FOUND) {
        return false;
    }

    // get reusable block list
    blist = fdb_get_reusable_block(handle, sheader);

    // update superblock's bitmap
    num_blocks = filemgr_get_pos(handle->file) / handle->file->blocksize;
    // 8 bitmaps per byte
    bmp_size_byte = (num_blocks+7) / 8;
    if (num_blocks) {
        if (sb->bmp == NULL) {
            sb->bmp = (uint8_t*)calloc(1, bmp_size_byte);
        } else {
            if (sb->bmp_size != num_blocks) {
                sb->bmp = (uint8_t*)realloc(sb->bmp, bmp_size_byte);
            }
            // clear previous bitmap (including newly allocated region) to zero
            sb_bmp_clear(sb->bmp, 0, num_blocks);
        }
    }
    sb->bmp_size = num_blocks;

    // free pre-existing bmp index
    _free_bmp_idx(&sb->bmp_idx);

    for (i=0; i<blist.n_blocks; ++i) {
        sb_bmp_set(sb->bmp, blist.blocks[i].bid, blist.blocks[i].count);
        if (i==0 && sb->cur_alloc_bid == BLK_NOT_FOUND) {
            sb->cur_alloc_bid = blist.blocks[i].bid;
        }
        sb->num_free_blocks += blist.blocks[i].count;
        // add info for supplementary bmp index
        _add_bmp_idx(&sb->bmp_idx, blist.blocks[i].bid, blist.blocks[i].count);
    }
    free(blist.blocks);

    sb->min_live_hdr_revnum = sheader.revnum;
    sb->min_live_hdr_bid = sheader.bid;
    sb->bmp_revnum++;
    sb->num_init_free_blocks = sb->num_free_blocks;

    return true;
}

bool sb_reserve_next_reusable_blocks(fdb_kvs_handle *handle)
{
    size_t i;
    uint64_t num_blocks, bmp_size_byte;
    stale_header_info sheader;
    reusable_block_list blist;
    struct superblock *sb = handle->file->sb;
    struct sb_rsv_bmp *rsv = NULL;

    if (sb->rsv_bmp) {
        // next bitmap already reclaimed
        return false;
    }

    sheader = fdb_get_smallest_active_header(handle);
    if (sheader.bid == BLK_NOT_FOUND) {
        return false;
    }

    // get reusable block list
    blist = fdb_get_reusable_block(handle, sheader);

    // calculate bitmap size
    num_blocks = filemgr_get_pos(handle->file) / handle->file->blocksize;
    bmp_size_byte = (num_blocks+7) / 8;
    if (num_blocks) {
        rsv = (struct sb_rsv_bmp*)calloc(1, sizeof(struct sb_rsv_bmp));
        rsv->bmp = (uint8_t*)calloc(1, bmp_size_byte);
        rsv->cur_alloc_bid = BLK_NOT_FOUND;

        // the initial status is 'INITIALIZING' so that 'rsv_bmp' is not
        // available until executing sb_rsv_append_doc().
        atomic_init_uint32_t(&rsv->status, SB_RSV_INITIALIZING);
        avl_init(&rsv->bmp_idx, NULL);
        rsv->bmp_size = num_blocks;

        for (i=0; i<blist.n_blocks; ++i) {
            sb_bmp_set(rsv->bmp, blist.blocks[i].bid, blist.blocks[i].count);
            if (i==0 && rsv->cur_alloc_bid == BLK_NOT_FOUND) {
                rsv->cur_alloc_bid = blist.blocks[i].bid;
            }
            rsv->num_free_blocks += blist.blocks[i].count;
            _add_bmp_idx(&rsv->bmp_idx, blist.blocks[i].bid, blist.blocks[i].count);
        }
        free(blist.blocks);

        rsv->min_live_hdr_revnum = sheader.revnum;
        rsv->min_live_hdr_bid = sheader.bid;
        rsv->bmp_revnum = sb->bmp_revnum+1;
        sb->rsv_bmp = rsv;
    }

    return true;
}

static void _rsv_free(struct sb_rsv_bmp *rsv);
void sb_return_reusable_blocks(fdb_kvs_handle *handle)
{
    uint64_t node_id;
    bid_t cur;
    struct superblock *sb = handle->file->sb;
    struct sb_rsv_bmp *rsv;
    struct avl_node *a;
    struct bmp_idx_node *item, query;

    if (!sb) {
        // we don't need to do this.
        return;
    }

    // re-insert all remaining bitmap into stale list
    for (cur = sb->cur_alloc_bid; cur < sb->bmp_size; ++cur) {
        if (_is_bmp_set(sb->bmp, cur)) {
            filemgr_add_stale_block(handle->file, cur, 1);
        }

        if ((cur % 256) == 0 && cur > 0) {
            // node ID changes
            // remove & free current bmp node
            node_id = cur / 256;
            query.id = node_id - 1;
            a = avl_search(&sb->bmp_idx, &query.avl, _bmp_idx_cmp);
            if (a) {
                item = _get_entry(a, struct bmp_idx_node, avl);
                avl_remove(&sb->bmp_idx, a);
                free(item);
            }

            // move to next bmp node
            do {
                a = avl_first(&sb->bmp_idx);
                if (a) {
                    item = _get_entry(a, struct bmp_idx_node, avl);
                    if (item->id <= node_id) {
                        avl_remove(&sb->bmp_idx, a);
                        free(item);
                        continue;
                    }
                    cur = item->id * 256;
                    break;
                }

                // no more reusable block
                cur = sb->bmp_size;
                break;
            } while (true);
        }
    }
    sb->num_free_blocks = 0;
    sb->cur_alloc_bid = BLK_NOT_FOUND;

    // do the same work for the reserved blocks if exist
    rsv = sb->rsv_bmp;
    if (rsv &&
        atomic_cas_uint32_t(&rsv->status, SB_RSV_READY, SB_RSV_VOID)) {

        for (cur = rsv->cur_alloc_bid; cur < rsv->bmp_size; ++cur) {
            if (_is_bmp_set(rsv->bmp, cur)) {
                filemgr_add_stale_block(handle->file, cur, 1);
            }

            if ((cur % 256) == 0 && cur > 0) {
                // node ID changes
                // remove & free current bmp node
                node_id = cur / 256;
                query.id = node_id - 1;
                a = avl_search(&rsv->bmp_idx, &query.avl, _bmp_idx_cmp);
                if (a) {
                    item = _get_entry(a, struct bmp_idx_node, avl);
                    avl_remove(&rsv->bmp_idx, a);
                    free(item);
                }

                // move to next bmp node
                do {
                    a = avl_first(&rsv->bmp_idx);
                    if (a) {
                        item = _get_entry(a, struct bmp_idx_node, avl);
                        if (item->id <= node_id) {
                            avl_remove(&rsv->bmp_idx, a);
                            free(item);
                            continue;
                        }
                        cur = item->id * 256;
                        break;
                    }

                    // no more reusable block
                    cur = rsv->bmp_size;
                    break;
                } while (true);
            }
        }
        rsv->num_free_blocks = 0;
        rsv->cur_alloc_bid = BLK_NOT_FOUND;

        _free_bmp_idx(&rsv->bmp_idx);
        _rsv_free(rsv);
        free(rsv);
        sb->rsv_bmp = NULL;
    }

    // re-store into stale tree using next header's revnum
    filemgr_header_revnum_t revnum = handle->cur_header_revnum;
    fdb_gather_stale_blocks(handle, revnum+1, BLK_NOT_FOUND, BLK_NOT_FOUND, 0, NULL);
}

void sb_bmp_mask_init()
{
    // preset masks to speed up bitmap set/clear operations
    size_t i, pos, len;
    for (i=0; i<8; ++i) {
        bmp_basic_mask[i] = 0x1 << (7-i);
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

INLINE void _sb_bmp_update(uint8_t *bmp, bid_t bid, uint64_t len, int mode)
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
            bmp[div8(front_pos)] |= bmp_2d_mask[mod8(front_pos)][front_len];
        } else {
            bmp[div8(front_pos)] &= ~bmp_2d_mask[mod8(front_pos)][front_len];
        }
    }
    // rear bitmaps
    if (rear_len) {
        if (mode) {
            bmp[div8(rear_pos)] |= bmp_2d_mask[mod8(rear_pos)][rear_len];
        } else {
            bmp[div8(rear_pos)] &= ~bmp_2d_mask[mod8(rear_pos)][rear_len];
        }
    }

    // mid bitmaps
    uint8_t mask = (mode)?(0xff):(0x0);
    if (mid_len == 8) {
        // 8 bitmaps (1 byte)
        bmp[div8(mid_pos)] = mask;
    } else if (mid_len < 64) {
        // 16 ~ 56 bitmaps (2 ~ 7 bytes)
        size_t i;
        for (i=0; i<mid_len; i+=8) {
            bmp[div8(mid_pos+i)] = mask;
        }
    } else {
        // larger than 64 bitmaps (8 bytes)
        memset(bmp + div8(mid_pos), mask, div8(mid_len));
    }
}

void sb_bmp_set(uint8_t *bmp, bid_t bid, uint64_t len)
{
    _sb_bmp_update(bmp, bid, len, 1);
}

void sb_bmp_clear(uint8_t *bmp, bid_t bid, uint64_t len)
{
    _sb_bmp_update(bmp, bid, len, 0);
}

bool sb_switch_reserved_blocks(struct filemgr *file)
{
    size_t i;
    struct superblock *sb = file->sb;
    struct sb_rsv_bmp *rsv = sb->rsv_bmp;

    // reserved block should exist
    if (!rsv) {
        return false;
    }
    // should be in a normal status
    if (!atomic_cas_uint32_t(&rsv->status, SB_RSV_READY, SB_RSV_VOID)) {
        return false;
    }
    // now status becomes 'VOID' so that rsv_bmp is not available.

    // mark stale previous system docs
    if (sb->bmp_doc_offset) {
        for (i=0; i<sb->num_bmp_docs; ++i) {
            filemgr_mark_stale(file, sb->bmp_doc_offset[i],
                _fdb_get_docsize(sb->bmp_docs[i].length));
        }

        free(sb->bmp_doc_offset);
        free(sb->bmp_docs);
        sb->bmp_doc_offset = NULL;
        sb->bmp_docs = NULL;
    }

    // should flush all dirty blocks in cache
    filemgr_sync(file, false, NULL);

    // free current bitmap idx
    _free_bmp_idx(&sb->bmp_idx);
    // temporarily keep current bitmap
    if (sb->bmp_prev) {
        free(sb->bmp_prev);
    }
    sb->bmp_prev = sb->bmp;
    sb->bmp_prev_size = sb->bmp_size;

    // copy all pointers from rsv to sb
    sb->bmp_revnum = rsv->bmp_revnum;
    sb->bmp_size = rsv->bmp_size;
    sb->bmp = rsv->bmp;
    sb->bmp_idx = rsv->bmp_idx;
    sb->bmp_doc_offset = rsv->bmp_doc_offset;
    sb->bmp_docs = rsv->bmp_docs;
    sb->num_bmp_docs = rsv->num_bmp_docs;
    sb->num_free_blocks = sb->num_init_free_blocks = rsv->num_free_blocks;
    sb->cur_alloc_bid = rsv->cur_alloc_bid;
    sb->min_live_hdr_revnum = rsv->min_live_hdr_revnum;
    sb->min_live_hdr_bid = rsv->min_live_hdr_bid;

    free(sb->rsv_bmp);
    sb->rsv_bmp = NULL;

    return true;
}

bid_t sb_alloc_block(struct filemgr *file)
{
    uint64_t i, node_idx, node_off, bmp_idx, bmp_off;
    bid_t ret = BLK_NOT_FOUND;
    struct superblock *sb = file->sb;
    struct avl_node *a;
    struct bmp_idx_node *item, query;

    sb->num_alloc++;
sb_alloc_start_over:
    if (!sb->bmp) {
        // no bitmap
        return BLK_NOT_FOUND;
    }

    if (sb->num_free_blocks == 0) {
        bool switched = false;
        if (sb->rsv_bmp) {
            switched = sb_switch_reserved_blocks(file);
        }
        if (switched) {
            goto sb_alloc_start_over;
        } else {
            sb->cur_alloc_bid = BLK_NOT_FOUND;
            return BLK_NOT_FOUND;
        }
    }

    ret = sb->cur_alloc_bid;
    sb->num_free_blocks--;

    if (sb->num_free_blocks == 0) {
        bool switched = false;
        if (sb->rsv_bmp) {
            switched = sb_switch_reserved_blocks(file);
        }
        if (!switched) {
            sb->cur_alloc_bid = BLK_NOT_FOUND;
        }
        return ret;
    }

    // find allocable block in the same bmp idx node
    node_idx = ret >> 8;
    node_off = (ret & 0xff)+1;
    do {
        for (i=node_off; i<256; ++i) {
            bmp_idx = div8(i) + (node_idx * 32);
            bmp_off = mod8(i);

            if (bmp_idx*8 + bmp_off >= sb->bmp_size) {
                break;
            }

            if (sb->bmp[bmp_idx] & bmp_basic_mask[bmp_off]) {
                sb->cur_alloc_bid = bmp_idx*8 + bmp_off;
                return ret;
            }
        }

        // current bmp_node does not include any free block .. remove
        query.id = node_idx;
        a = avl_search(&sb->bmp_idx, &query.avl, _bmp_idx_cmp);
        if (a) {
            item = _get_entry(a, struct bmp_idx_node, avl);
            avl_remove(&sb->bmp_idx, a);
            free(item);
        }

        // get next allocable bmp_node
        a = avl_first(&sb->bmp_idx);
        if (!a) {
            // no more free bmp_node
            sb->num_free_blocks = 0;
            bool switched = false;
            if (sb->rsv_bmp) {
                switched = sb_switch_reserved_blocks(file);
            }
            if (!switched) {
                sb->cur_alloc_bid = BLK_NOT_FOUND;
            }
            break;
        }
        item = _get_entry(a, struct bmp_idx_node, avl);
        node_idx = item->id;
        node_off = 0;
    } while (true);

    return ret;
}

bool sb_bmp_is_writable(struct filemgr *file, bid_t bid)
{
    if (bid < file->sb->config->num_sb) {
        // superblocks are always writable
        return true;
    }

    bid_t last_commit = atomic_get_uint64_t(&file->last_commit) / file->blocksize;
    uint64_t lc_bmp_revnum = atomic_get_uint64_t(&file->last_commit_bmp_revnum);
    struct superblock *sb = file->sb;

    if (sb->bmp_revnum == lc_bmp_revnum) {
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
        //                             last_commit     bmp_size  cur_alloc

        if (bid < sb->bmp_size) {
            // BID is in the bitmap .. check if bitmap is set.
            if (_is_bmp_set(sb->bmp, bid) &&
                bid < sb->cur_alloc_bid && bid >= last_commit) {
                return true;
            }
        } else {
            // BID is out-of-range of the bitmap
            if (bid >= last_commit) {
                return true;
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
        //                                 last_commit bmp_size  cur_alloc

        // the block is writable if
        // 1) BID >= last_commit OR
        // 2) BID < cur_alloc_bid AND corresponding bitmap is set.
        if (bid >= last_commit) {
            // if prev_bmp exists, last commit position is still located on the
            // previous bitmap (since prev_bmp is released when a commit is invoked
            // in the new bitmap).
            // So in this case, we have to check both previous/current bitmaps.
            //
            // (1: previous bitmap (sb->bmp_prev), 2: current bitmap (sb->bmp))
            //
            //        writable blocks          writable blocks
            //    <-->      <---->   <-->          <> <> <>
            // +-------------------------------------------+
            // |  2222 1111 222222   2222   111111111 22 11|
            // +-------------------------------------------+
            //                                     ^
            //                                     last_commit
            if (sb->bmp_prev && bid < sb->bmp_prev_size) {
                if (_is_bmp_set(sb->bmp_prev, bid) ||
                    _is_bmp_set(sb->bmp, bid)) {
                    return true;
                }
            } else {
                return true;
            }
        }
        if (_is_bmp_set(sb->bmp, bid) &&
            bid < sb->cur_alloc_bid) {
            return true;
        } else {
            return false;
        }
    }

    return false;
}

bool sb_bmp_is_active_block(struct filemgr *file, bid_t bid)
{
    if (file->sb->bmp) {
        if (bid < file->sb->bmp_size) {
            return !_is_bmp_set(file->sb->bmp, bid);
        } else {
            // out-of-range .. always valid
            // (this block is allocated after bitmap is created)
            return true;
        }
    } else {
        // always valid
        return true;
    }
}

fdb_status sb_write(struct filemgr *file, size_t sb_no,
                    err_log_callback * log_callback)
{
    int r;
    int real_blocksize = file->blocksize;
    int blocksize = file->blocksize - BLK_MARKER_SIZE;
    uint8_t *buf = alca(uint8_t, real_blocksize);
    uint32_t crc, _crc;
    uint64_t enc_u64;
    uint64_t num_docs;
    size_t i, offset;
    fdb_status fs;

    memset(buf, 0x0, real_blocksize);

    offset = 0;
    // magic number
    enc_u64 = _endian_encode(file->version);
    memcpy(buf + offset, &enc_u64, sizeof(enc_u64));
    offset += sizeof(enc_u64);

    // revision number
    enc_u64 = _endian_encode(file->sb->revnum);
    memcpy(buf + offset, &enc_u64, sizeof(enc_u64));
    offset += sizeof(enc_u64);

    // bitmap's revision number
    enc_u64 = _endian_encode(file->sb->bmp_revnum);
    memcpy(buf + offset, &enc_u64, sizeof(enc_u64));
    offset += sizeof(enc_u64);

    // cur_alloc_bid
    enc_u64 = _endian_encode(file->sb->cur_alloc_bid);
    memcpy(buf + offset, &enc_u64, sizeof(enc_u64));
    offset += sizeof(enc_u64);

    // last header bid
    enc_u64 = _endian_encode(file->sb->last_hdr_bid);
    memcpy(buf + offset, &enc_u64, sizeof(enc_u64));
    offset += sizeof(enc_u64);

    // last header rev number
    enc_u64 = _endian_encode(file->sb->last_hdr_revnum);
    memcpy(buf + offset, &enc_u64, sizeof(enc_u64));
    offset += sizeof(enc_u64);

    // minimum active header revnum
    enc_u64 = _endian_encode(file->sb->min_live_hdr_revnum);
    memcpy(buf + offset, &enc_u64, sizeof(enc_u64));
    offset += sizeof(enc_u64);

    // minimum active header BID
    enc_u64 = _endian_encode(file->sb->min_live_hdr_bid);
    memcpy(buf + offset, &enc_u64, sizeof(enc_u64));
    offset += sizeof(enc_u64);

    // # initial free blocks
    enc_u64 = _endian_encode(file->sb->num_init_free_blocks);
    memcpy(buf + offset, &enc_u64, sizeof(enc_u64));
    offset += sizeof(enc_u64);

    // # free blocks
    enc_u64 = _endian_encode(file->sb->num_free_blocks);
    memcpy(buf + offset, &enc_u64, sizeof(enc_u64));
    offset += sizeof(enc_u64);

    // bitmap size
    enc_u64 = _endian_encode(file->sb->bmp_size);
    memcpy(buf + offset, &enc_u64, sizeof(enc_u64));
    offset += sizeof(enc_u64);

    bool rsv_bmp_enabled = false;

    if ( file->sb->rsv_bmp &&
         atomic_cas_uint32_t(&file->sb->rsv_bmp->status,
                             SB_RSV_READY, SB_RSV_WRITING) ) {
        rsv_bmp_enabled = true;
        // status becomes 'WRITING' so that switching will be postponed.
        // note that 'rsv_bmp' is not currently used yet so that
        // it won't block any other tasks except for switching.
    }

    // reserved bitmap size (0 if not exist)
    if (rsv_bmp_enabled) {
        enc_u64 = _endian_encode(file->sb->rsv_bmp->bmp_size);
    } else {
        enc_u64 = 0;
    }
    memcpy(buf + offset, &enc_u64, sizeof(enc_u64));
    offset += sizeof(enc_u64);

    // bitmap doc offsets
    num_docs = _bmp_size_to_num_docs(file->sb->bmp_size);
    for (i=0; i<num_docs; ++i) {
        enc_u64 = _endian_encode(file->sb->bmp_doc_offset[i]);
        memcpy(buf + offset, &enc_u64, sizeof(enc_u64));
        offset += sizeof(enc_u64);
    }

    // reserved bitmap doc offsets
    if (rsv_bmp_enabled) {
        num_docs = _bmp_size_to_num_docs(file->sb->rsv_bmp->bmp_size);
        for (i=0; i<num_docs; ++i) {
            enc_u64 = _endian_encode(file->sb->rsv_bmp->bmp_doc_offset[i]);
            memcpy(buf + offset, &enc_u64, sizeof(enc_u64));
            offset += sizeof(enc_u64);
        }

        atomic_store_uint32_t(&file->sb->rsv_bmp->status, SB_RSV_READY);
    }

    // CRC
    crc = get_checksum(buf, offset, file->crc_mode);
    _crc = _endian_encode(crc);
    memcpy(buf + offset, &_crc, sizeof(_crc));

    // set block marker
    memset(buf + blocksize, BLK_MARKER_SB, BLK_MARKER_SIZE);

    // directly write a block bypassing block cache
    r = file->ops->pwrite(file->fd, buf, real_blocksize, sb_no * real_blocksize);
    if (r != real_blocksize) {
        char errno_msg[512];
        file->ops->get_errno_str(errno_msg, 512);
        fs = FDB_RESULT_SB_RACE_CONDITION;
        fdb_log(log_callback, fs,
                "Failed to write the superblock (number: %" _F64 "), %s",
                sb_no, errno_msg);
        return fs;
    }

    // increase superblock's revision number
    file->sb->revnum++;

    return FDB_RESULT_SUCCESS;
}

static fdb_status _sb_read_given_no(struct filemgr *file,
                                    size_t sb_no,
                                    struct superblock *sb,
                                    err_log_callback *log_callback)
{
    int r;
    int real_blocksize = file->blocksize;
    int blocksize = file->blocksize - BLK_MARKER_SIZE;
    size_t i, num_docs;
    uint8_t *buf = alca(uint8_t, real_blocksize);
    uint32_t crc_file, crc, _crc;
    uint64_t enc_u64, version, offset, dummy64;
    fdb_status fs;
    struct sb_rsv_bmp *rsv = NULL;

    memset(buf, 0x0, real_blocksize);
    offset = 0;

    // directly read a block bypassing block cache
    r = file->ops->pread(file->fd, buf, real_blocksize, sb_no * real_blocksize);
    if (r != real_blocksize) {
        char errno_msg[512];
        file->ops->get_errno_str(errno_msg, 512);
        fs = FDB_RESULT_SB_READ_FAIL;
        fdb_log(log_callback, fs,
                "Failed to read the superblock: file read failure (SB No.: %" _F64 "), %s",
                sb_no, errno_msg);
        return fs;
    }

    // block marker check
    if (buf[blocksize] != BLK_MARKER_SB) {
        fs = FDB_RESULT_SB_READ_FAIL;
        fdb_log(log_callback, fs,
                "Failed to read the superblock: "
                "incorrect block marker (marker: %x, SB No.: %" _F64 ")",
                buf[blocksize], sb_no);
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
                version, sb_no);
        return fs;
    }

    // revision number
    memcpy(&enc_u64, buf + offset, sizeof(enc_u64));
    offset += sizeof(enc_u64);
    sb->revnum = _endian_decode(enc_u64);

    // bitmap's revision number
    memcpy(&enc_u64, buf + offset, sizeof(enc_u64));
    offset += sizeof(enc_u64);
    sb->bmp_revnum = _endian_decode(enc_u64);

    // cur_alloc_bid
    memcpy(&enc_u64, buf + offset, sizeof(enc_u64));
    offset += sizeof(enc_u64);
    sb->cur_alloc_bid = _endian_decode(enc_u64);

    // last header bid
    memcpy(&enc_u64, buf + offset, sizeof(enc_u64));
    offset += sizeof(enc_u64);
    sb->last_hdr_bid = _endian_decode(enc_u64);

    // last header rev number
    memcpy(&enc_u64, buf + offset, sizeof(enc_u64));
    offset += sizeof(enc_u64);
    sb->last_hdr_revnum = _endian_decode(enc_u64);

    // minimum active header revnum
    memcpy(&enc_u64, buf + offset, sizeof(enc_u64));
    offset += sizeof(enc_u64);
    sb->min_live_hdr_revnum = _endian_decode(enc_u64);

    // minimum active header BID
    memcpy(&enc_u64, buf + offset, sizeof(enc_u64));
    offset += sizeof(enc_u64);
    sb->min_live_hdr_bid = _endian_decode(enc_u64);

    // # initial free blocks
    memcpy(&enc_u64, buf + offset, sizeof(enc_u64));
    offset += sizeof(enc_u64);
    sb->num_init_free_blocks = _endian_decode(enc_u64);

    // # free blocks
    memcpy(&enc_u64, buf + offset, sizeof(enc_u64));
    offset += sizeof(enc_u64);
    sb->num_free_blocks = _endian_decode(enc_u64);

    // bitmap size
    memcpy(&enc_u64, buf + offset, sizeof(enc_u64));
    offset += sizeof(enc_u64);
    sb->bmp_size = _endian_decode(enc_u64);

    // reserved bitmap size
    memcpy(&enc_u64, buf + offset, sizeof(enc_u64));
    offset += sizeof(enc_u64);
    dummy64 = _endian_decode(enc_u64);
    if (dummy64) {
        // reserved bitmap array exists
        rsv = (struct sb_rsv_bmp*)calloc(1, sizeof(struct sb_rsv_bmp));
        rsv->bmp = NULL;
        rsv->bmp_size = dummy64;
        rsv->cur_alloc_bid = BLK_NOT_FOUND;
        atomic_init_uint32_t(&rsv->status, SB_RSV_INITIALIZING);
    }

    // temporarily set bitmap array to NULL
    // (it will be allocated by fetching function)
    sb->bmp = NULL;

    sb->num_bmp_docs = num_docs = _bmp_size_to_num_docs(sb->bmp_size);
    if (num_docs) {
        sb->bmp_doc_offset = (bid_t*)calloc(num_docs, sizeof(bid_t));
        sb->bmp_docs = (struct docio_object*)
                       calloc(num_docs, sizeof(struct docio_object));
    }

    // read doc offsets
    for (i=0; i<num_docs; ++i) {
        memcpy(&enc_u64, buf + offset, sizeof(enc_u64));
        offset += sizeof(enc_u64);
        sb->bmp_doc_offset[i] = _endian_decode(enc_u64);
    }

    // read reserved bmp docs if exist
    if (rsv) {
        rsv->num_bmp_docs = num_docs = _bmp_size_to_num_docs(rsv->bmp_size);
        if (rsv->num_bmp_docs) {
            rsv->bmp_doc_offset = (bid_t*)calloc(num_docs, sizeof(bid_t));
            rsv->bmp_docs = (struct docio_object*)
                            calloc(num_docs, sizeof(struct docio_object));
        }

        // read doc offsets
        for (i=0; i<num_docs; ++i) {
            memcpy(&enc_u64, buf + offset, sizeof(enc_u64));
            offset += sizeof(enc_u64);
            rsv->bmp_doc_offset[i] = _endian_decode(enc_u64);
        }
    }

    // CRC
    crc = get_checksum(buf, offset, file->crc_mode);
    memcpy(&_crc, buf + offset, sizeof(_crc));
    crc_file = _endian_decode(_crc);
    if (crc != crc_file) {
        free(sb->bmp_doc_offset);
        free(sb->bmp_docs);
        sb->bmp_doc_offset = NULL;
        sb->bmp_docs = NULL;

        fs = FDB_RESULT_SB_READ_FAIL;
        fdb_log(log_callback, fs,
                "Failed to read the superblock: "
                "not supported version (magic: %" _F64 ", SB No.: %" _F64 ")",
                version, sb_no);
        return fs;
    }

    return FDB_RESULT_SUCCESS;
}

static void _rsv_free(struct sb_rsv_bmp *rsv)
{
    free(rsv->bmp);
    free(rsv->bmp_doc_offset);
    free(rsv->bmp_docs);
    atomic_destroy_uint32_t(&rsv->status);
}

static void _sb_free(struct superblock *sb)
{
    if (sb->rsv_bmp) {
        atomic_store_uint32_t(&sb->rsv_bmp->status, SB_RSV_VOID);
        _free_bmp_idx(&sb->rsv_bmp->bmp_idx);
        _rsv_free(sb->rsv_bmp);
        free(sb->rsv_bmp);
    }
    _free_bmp_idx(&sb->bmp_idx);

    free(sb->bmp);
    free(sb->bmp_prev);
    free(sb->bmp_doc_offset);
    // note that each docio object doesn't need to be freed
    // as key/body fields point to static memory regions.
    free(sb->bmp_docs);
    free(sb->config);

    sb->bmp = NULL;
    sb->bmp_doc_offset = NULL;
    sb->bmp_docs = NULL;
    sb->config = NULL;
}

void _sb_init(struct superblock *sb, struct sb_config sconfig)
{
    *sb->config = sconfig;
    sb->revnum = 0;
    sb->bmp_revnum = 0;
    sb->bmp_size = 0;
    sb->bmp = NULL;
    sb->bmp_prev_size = 0;
    sb->bmp_prev = NULL;
    sb->bmp_doc_offset = NULL;
    sb->bmp_docs = NULL;
    sb->num_init_free_blocks = 0;
    sb->num_free_blocks = 0;
    sb->cur_alloc_bid = BLK_NOT_FOUND;
    sb->last_hdr_bid = BLK_NOT_FOUND;
    sb->min_live_hdr_revnum = 0;
    sb->min_live_hdr_bid = BLK_NOT_FOUND;
    sb->last_hdr_revnum = 0;
    sb->num_alloc = 0;
    sb->rsv_bmp = NULL;
    avl_init(&sb->bmp_idx, NULL);
}

fdb_status sb_read_latest(struct filemgr *file,
                          struct sb_config sconfig,
                          err_log_callback *log_callback)
{
    size_t i, max_sb_no = sconfig.num_sb;
    uint64_t max_revnum = 0;
    fdb_status fs;
    struct superblock *sb_arr;

    sb_arr = alca(struct superblock,
                  sconfig.num_sb * sizeof(struct superblock));
    memset(sb_arr, 0x0, sconfig.num_sb * sizeof(struct superblock));

    // read all superblocks
    for (i=0; i<sconfig.num_sb; ++i) {
        sb_arr[i].config = (struct sb_config*)calloc(1, sizeof(struct sb_config));
        _sb_init(&sb_arr[i], sconfig);
        fs = _sb_read_given_no(file, i, &sb_arr[i], log_callback);
        if (fs == FDB_RESULT_SUCCESS &&
            sb_arr[i].revnum >= max_revnum) {
            max_sb_no = i;
            max_revnum = sb_arr[i].revnum;
        }
    }

    if (max_sb_no == sconfig.num_sb) {
        // all superblocks are broken
        fs = FDB_RESULT_SB_READ_FAIL;
        for (i=0; i<sconfig.num_sb; ++i) {
            _sb_free(&sb_arr[i]);
        }
        // no readable superblock
        // (if not corrupted, it may be a normal old version file)
        return fs;
    }

    file->sb = (struct superblock*)calloc(1, sizeof(struct superblock));
    *file->sb = sb_arr[max_sb_no];

    // set last commit position
    if (file->sb->cur_alloc_bid != BLK_NOT_FOUND) {
        atomic_store_uint64_t(&file->last_commit,
                              file->sb->cur_alloc_bid * file->config->blocksize);
    } else {
        // otherwise, last_commit == file->pos
        // (already set by filemgr_open() function)
    }

    file->sb->revnum++;
    avl_init(&file->sb->bmp_idx, NULL);

    // free the other superblocks
    for (i=0; i<sconfig.num_sb; ++i) {
        if (i != max_sb_no) {
            _sb_free(&sb_arr[i]);
        }
    }

    return FDB_RESULT_SUCCESS;
}

uint64_t sb_get_bmp_revnum(struct filemgr *file)
{
    if (file->sb) {
        return file->sb->bmp_revnum;
    } else {
        return 0;
    }
}

filemgr_header_revnum_t sb_get_min_live_revnum(struct filemgr *file)
{
    if (file->sb) {
        return file->sb->min_live_hdr_revnum;
    } else {
        return 0;
    }
}

uint64_t sb_get_num_free_blocks(struct filemgr *file)
{
    if (file->sb) {
        return file->sb->num_free_blocks;
    } else {
        return 0;
    }
}

struct sb_config sb_get_default_config()
{
    struct sb_config ret;
    ret.num_sb = SB_DEFAULT_NUM_SUPERBLOCKS;
    return ret;
}

fdb_status sb_init(struct filemgr *file, struct sb_config sconfig,
                   err_log_callback * log_callback)
{
    size_t i;
    bid_t sb_bid;
    fdb_status fs;

    // exit if superblock already exists.
    if (file->sb) {
        return FDB_RESULT_SUCCESS;
    }
    // no data should be written in the file before initialization of superblock.
    if (filemgr_get_pos(file) > 0) {
        return FDB_RESULT_SB_INIT_FAIL;
    }

    file->sb = (struct superblock*)calloc(1, sizeof(struct superblock));
    file->sb->config = (struct sb_config*)calloc(1, sizeof(struct sb_config));
    file->version = ver_get_latest_magic();
    _sb_init(file->sb, sconfig);

    // write initial superblocks
    for (i=0; i<file->sb->config->num_sb; ++i) {
        // allocate
        sb_bid = filemgr_alloc(file, log_callback);
        if (sb_bid != i) {
            // other data was written during sb_write .. error
            fs = FDB_RESULT_SB_RACE_CONDITION;
            fdb_log(log_callback, fs,
                    "Other writer interfered during sb_write (number: %" _F64 ")",
                    i);
            free(file->sb->config);
            free(file->sb);
            return fs;
        }

        fs = sb_write(file, i, log_callback);
        if (fs != FDB_RESULT_SUCCESS) {
            return fs;
        }
    }

    return FDB_RESULT_SUCCESS;
}

fdb_status sb_free(struct filemgr *file)
{
    if (file->sb) {
        _sb_free(file->sb);
        free(file->sb);
        file->sb = NULL;
    }

    return FDB_RESULT_SUCCESS;
}


