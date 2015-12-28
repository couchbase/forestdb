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

#include "staleblock.h"
#include "btreeblock.h"
#include "list.h"
#include "docio.h"
#include "fdb_internal.h"
#include "version.h"
#include "time_utils.h"

#include "memleak.h"

void fdb_gather_stale_blocks(fdb_kvs_handle *handle,
                             filemgr_header_revnum_t revnum,
                             bid_t prev_hdr,
                             uint64_t kv_info_offset,
                             fdb_seqnum_t seqnum,
                             struct list_elem *e_last)
{
    int64_t delta;
    int r;
    uint32_t count = 0;
    uint32_t offset = 0, count_location;
    uint32_t bufsize = 8192;
    uint32_t _count, _len;
    uint64_t _pos, _kv_info_offset;
    uint8_t *buf = NULL;
    bid_t doc_offset, _doc_offset;
    bid_t _prev_hdr;
    bool gather_staleblocks = true;
    filemgr_header_revnum_t _revnum;
    fdb_seqnum_t _seqnum;
    struct kvs_stat stat;

    /*
     * << stale block system doc structure >>
     * [previous doc offset]: 8 bytes (0xffff.. if not exist)
     * [previous header BID]: 8 bytes (0xffff.. if not exist)
     * [KVS info doc offset]: 8 bytes (0xffff.. if not exist)
     * [Default KVS seqnum]:  8 bytes
     * [# items]:             4 bytes
     * ---
     * [position]:            8 bytes
     * [length]:              4 bytes
     * ...
     */

    if (filemgr_get_stale_list(handle->file)) {
        struct list_elem *e;
        struct stale_data *item;

        r = _kvs_stat_get(handle->file, 0, &stat);
        handle->bhandle->nlivenodes = stat.nlivenodes;
        handle->bhandle->ndeltanodes = stat.nlivenodes;
        (void)r;

        buf = (uint8_t *)calloc(1, bufsize);
        _revnum = _endian_encode(revnum);

        // initial previous doc offset
        memset(buf, 0xff, sizeof(bid_t));
        count_location = sizeof(bid_t);

        // previous header BID
        if (prev_hdr == 0 || prev_hdr == BLK_NOT_FOUND) {
            // does not exist
            memset(&_prev_hdr, 0xff, sizeof(_prev_hdr));
        } else {
            _prev_hdr = _endian_encode(prev_hdr);
        }
        memcpy(buf + sizeof(bid_t), &_prev_hdr, sizeof(bid_t));
        count_location += sizeof(bid_t);

        // KVS info doc offset
        _kv_info_offset = _endian_encode(kv_info_offset);
        memcpy(buf + count_location, &_kv_info_offset, sizeof(uint64_t));
        count_location += sizeof(uint64_t);

        // default KVS seqnum
        _seqnum = _endian_encode(seqnum);
        memcpy(buf + count_location, &_seqnum, sizeof(fdb_seqnum_t));
        count_location += sizeof(fdb_seqnum_t);
        count_location += sizeof(count);

        while(gather_staleblocks) {
            // reserve space for
            // prev offset (8), prev header (8), kv_info_offset (8), seqnum (8), count (4)
            offset = count_location;

            if (e_last) {
                e = list_next(e_last);
            } else {
                e = list_begin(handle->file->stale_list);
            }
            while (e) {
                item = _get_entry(e, struct stale_data, le);

                if (handle->staletree) {
                    count++;

                    _pos = _endian_encode(item->pos);
                    _len = _endian_encode(item->len);

                    memcpy(buf + offset, &_pos, sizeof(_pos));
                    offset += sizeof(_pos);
                    memcpy(buf + offset, &_len, sizeof(_len));
                    offset += sizeof(_len);

                    if (offset + sizeof(_pos) + sizeof(_len) >= bufsize) {
                        bufsize *= 2;
                        buf = (uint8_t*)realloc(buf, bufsize);
                    }
                }

                e = list_remove(handle->file->stale_list, e);
                free(item);
            }

            gather_staleblocks = false;
            if (count) {
                char *doc_key = alca(char, 32);
                struct docio_object doc;

                // store count
                _count = _endian_encode(count);
                memcpy(buf + count_location - sizeof(_count), &_count, sizeof(_count));

                // append a system doc
                memset(&doc, 0x0, sizeof(doc));
                // add one to 'revnum' to get the next revision number
                // (note that filemgr_mutex() is grabbed so that no other thread
                //  will change the 'revnum').
                sprintf(doc_key, "stale_blocks_%" _F64, revnum);
                doc.key = (void*)doc_key;
                doc.meta = NULL;
                doc.body = buf;
                doc.length.keylen = strlen(doc_key) + 1;
                doc.length.metalen = 0;
                doc.length.bodylen = offset;
                doc.seqnum = 0;
                doc_offset = docio_append_doc_system(handle->dhandle, &doc);

                // insert into stale-block tree
                _doc_offset = _endian_encode(doc_offset);
                btree_insert(handle->staletree, (void *)&_revnum, (void *)&_doc_offset);
                btreeblk_end(handle->bhandle);
                btreeblk_reset_subblock_info(handle->bhandle);

                if (list_begin(filemgr_get_stale_list(handle->file))) {
                    // updating stale tree brings another stale blocks.
                    // recursively update until there is no more stale block.

                    // note that infinite loop will not occur because
                    // 1) all updated index blocks for stale tree are still writable
                    // 2) incoming keys for stale tree (revnum) are monotonic
                    //    increasing order; most recently allocated node will be
                    //    updated again.

                    count = 0;
                    // save previous doc offset
                    memcpy(buf, &_doc_offset, sizeof(_doc_offset));

                    // gather once again
                    gather_staleblocks = true;
                }
            }
        } // gather stale blocks

        delta = handle->bhandle->nlivenodes - stat.nlivenodes;
        _kvs_stat_update_attr(handle->file, 0, KVS_STAT_NLIVENODES, delta);
        delta = handle->bhandle->ndeltanodes - stat.nlivenodes;
        delta *= handle->config.blocksize;
        _kvs_stat_update_attr(handle->file, 0, KVS_STAT_DELTASIZE, delta);

        free(buf);
    } else {
        btreeblk_reset_subblock_info(handle->bhandle);
    }
}

static int _reusable_offset_cmp(struct avl_node *a, struct avl_node *b, void *aux)
{
    struct stale_data *aa, *bb;
    aa = _get_entry(a, struct stale_data, avl);
    bb = _get_entry(b, struct stale_data, avl);
    return _CMP_U64(aa->pos, bb->pos);
}

static void _insert_n_merge(struct avl_tree *tree,
                            uint64_t item_pos,
                            uint32_t item_len)
{
    struct stale_data query, *item;
    struct avl_node *avl;

    // retrieve the tree first
    query.pos = item_pos;
    avl = avl_search(tree, &query.avl, _reusable_offset_cmp);
    if (avl) {
        // same offset already exists
        item = _get_entry(avl, struct stale_data, avl);
        // choose longer length
        if (item->len < item_len) {
            item->len = item_len;
        }
    } else {
        // does not exist .. create a new item
        item = (struct stale_data*)
               calloc(1, sizeof(struct stale_data));
        item->pos = item_pos;
        item->len = item_len;
        avl_insert(tree, &item->avl, _reusable_offset_cmp);
    }

    // check prev/next item to see if they can be merged
    struct avl_node *p_avl, *n_avl;
    struct stale_data*p_item, *n_item;
    p_avl = avl_prev(&item->avl);
    if (p_avl) {
        p_item = _get_entry(p_avl, struct stale_data, avl);
        if (p_item->pos + p_item->len >= item->pos) {

            if (p_item->pos + p_item->len >= item->pos + item->len) {
                // 'item' is included in p_item .. simply remove it
                // (do nothing)
            } else {
                // overlapping (or consecutive) .. merge two items
                p_item->len += item->len +
                               (item->pos - p_item->pos - p_item->len);
            }
            // remove current item
            avl_remove(tree, &item->avl);
            free(item);
            item = p_item;
        }
    }

    n_avl = avl_next(&item->avl);
    if (n_avl) {
        n_item = _get_entry(n_avl, struct stale_data, avl);
        if (item->pos + item->len >= n_item->pos) {

            if (item->pos + item->len >= n_item->pos + n_item->len) {
                // 'n_item' is included in 'item' .. simply remove it
                // (do nothing)
            } else {
                // overlapping (or consecutive) .. merge two items
                item->len += n_item->len +
                             (n_item->pos - item->pos - item->len);
            }
            // remove next item
            avl_remove(tree, &n_item->avl);
            free(n_item);
        }
    }
}

reusable_block_list fdb_get_reusable_block(fdb_kvs_handle *handle,
                                           stale_header_info stale_header)
{
    int64_t delta;
    int r;
    uint8_t keybuf[64];
    uint32_t i;
    uint32_t count, _count, item_len;
    uint32_t n_revnums, max_revnum_array = 256;
    uint64_t pos, item_pos;
    btree_iterator bit;
    btree_result br;
    filemgr_header_revnum_t revnum_upto, prev_revnum = 0;
    filemgr_header_revnum_t revnum = 0, _revnum;
    filemgr_header_revnum_t *revnum_array;
    bid_t offset, _offset, r_offset, prev_offset;
    bid_t prev_hdr = BLK_NOT_FOUND, _prev_hdr;
    struct docio_object doc;
    struct avl_tree tree;
    struct avl_node *avl;
    struct stale_data *item;
    struct list_elem *e, *e_last;
    struct kvs_stat stat;

    revnum_upto = stale_header.revnum;

    r = _kvs_stat_get(handle->file, 0, &stat);
    handle->bhandle->nlivenodes = stat.nlivenodes;
    handle->bhandle->ndeltanodes = stat.nlivenodes;
    (void)r;

    avl_init(&tree, NULL);
    revnum_array = (filemgr_header_revnum_t *)
                   calloc(max_revnum_array, sizeof(filemgr_header_revnum_t));
    n_revnums = 0;

    // remember the last stale list item to be preserved
    e_last = list_end(handle->file->stale_list);

    // scan stale-block tree and get all stale regions
    // corresponding to commit headers whose seq number is
    // equal to or smaller than 'revnum_upto'
    btree_iterator_init(handle->staletree, &bit, NULL);
    do {
        br = btree_next(&bit, (void*)&_revnum, (void*)&_offset);
        btreeblk_end(handle->bhandle);
        if (br != BTREE_RESULT_SUCCESS) {
            break;
        }

        prev_revnum = revnum;
        revnum = _endian_decode(_revnum);
        if (revnum > revnum_upto) {
            revnum = prev_revnum;
            break;
        }

        revnum_array[n_revnums++] = revnum;
        if (n_revnums >= max_revnum_array) {
            max_revnum_array *= 2;
            revnum_array = (filemgr_header_revnum_t *)
                           realloc(revnum_array, max_revnum_array *
                               sizeof(filemgr_header_revnum_t));
        }
        offset = _endian_decode(_offset);

        while (offset != BLK_NOT_FOUND) {
            memset(&doc, 0x0, sizeof(doc));
            // pre-allocated buffer for key
            doc.key = (void*)keybuf;

            r_offset = docio_read_doc(handle->dhandle, offset, &doc, true);
            if (r_offset == offset) {
                // read fail .. escape
                offset = BLK_NOT_FOUND;
                continue;
            }
            pos = 0;

            // get previous doc offset
            memcpy(&_offset, doc.body, sizeof(_offset));
            prev_offset = _endian_decode(_offset);
            pos += sizeof(_offset);

            // get previous header BID
            memcpy(&_prev_hdr, (uint8_t*)doc.body + pos, sizeof(_prev_hdr));
            prev_hdr = _endian_decode(_prev_hdr);
            (void)prev_hdr;
            pos += sizeof(_prev_hdr);

            // Skip kv_info_offset and default KVS's seqnum
            pos += sizeof(uint64_t) + sizeof(fdb_seqnum_t);

            // get count;
            memcpy(&_count, (uint8_t*)doc.body + pos, sizeof(_count));
            count = _endian_decode(_count);
            pos += sizeof(_count);

            // get a stale region and insert/merge into tree
            for (i=0;i<count;++i) {
                memcpy(&item_pos, (uint8_t*)doc.body + pos, sizeof(item_pos));
                item_pos = _endian_decode(item_pos);
                pos += sizeof(item_pos);

                memcpy(&item_len, (uint8_t*)doc.body + pos, sizeof(item_len));
                item_len = _endian_decode(item_len);
                pos += sizeof(item_len);

                _insert_n_merge(&tree, item_pos, item_len);
            }

            // also insert/merge the system doc region
            size_t length = _fdb_get_docsize(doc.length);
            struct stale_regions sr;

            sr = filemgr_actual_stale_regions(handle->file, offset, length);

            if (sr.n_regions > 1) {
                for (i=0; i<sr.n_regions; ++i){
                    _insert_n_merge(&tree, sr.regions[i].pos, sr.regions[i].len);
                }
                free(sr.regions);
            } else {
                _insert_n_merge(&tree, sr.region.pos, sr.region.len);
            }

            // We don't need to free 'meta' as it will be NULL.
            free(doc.body);

            offset = prev_offset;
        }
    } while (true);
    btree_iterator_free(&bit);

    // remove merged commit headers
    for (i=0; i<n_revnums; ++i) {
        _revnum = _endian_encode(revnum_array[i]);
        btree_remove(handle->staletree, (void*)&_revnum);
        btreeblk_end(handle->bhandle);
    }

    delta = handle->bhandle->nlivenodes - stat.nlivenodes;
    _kvs_stat_update_attr(handle->file, 0, KVS_STAT_NLIVENODES, delta);
    delta = handle->bhandle->ndeltanodes - stat.nlivenodes;
    delta *= handle->config.blocksize;
    _kvs_stat_update_attr(handle->file, 0, KVS_STAT_DELTASIZE, delta);

    // gather stale blocks generated by removing b+tree entries
    if (e_last) {
        e = list_next(e_last);
    } else {
        e = list_begin(handle->file->stale_list);
    }
    while (e) {
        item = _get_entry(e, struct stale_data, le);
        e = list_remove(handle->file->stale_list, e);

        _insert_n_merge(&tree, item->pos, item->len);
        free(item);
    }

    // now merge stale regions as large as possible
    size_t n_blocks =0 ;
    size_t blocksize = handle->file->blocksize;
    uint32_t max_blocks = 256;
    uint32_t front_margin;
    reusable_block_list ret;
    struct reusable_block *blocks_arr;

    blocks_arr = (struct reusable_block*)
        calloc(max_blocks, sizeof(struct reusable_block));

    avl = avl_first(&tree);
    while (avl) {
        item = _get_entry(avl, struct stale_data, avl);
        avl = avl_next(avl);

        // A stale region can be represented as follows:
        //
        //  block x-1 |   block x  |  block x+1 |  block x+2
        //  -----+----+------------+------------+--------+----
        //   ... |  A |      B     |      C     |    D   | ...
        //  -----+----+------------+------------+--------+----
        //
        // Only segment 'B' and 'C' can be reusable, and the other segments
        // (i.e., 'A' and 'D') should be re-inserted into stale-block tree.

        if (item->len < blocksize) {
            // whole region is smaller than a block .. skip this item
            //       |    block    |  ...
            //  -----+---+-----+---+-------
            //   ... |   |/////|   |  ...
            //  -----+---+-----+---+-------
            continue;
        }

        //            <------------ item_len ------------>
        //  block x-1 |   block x  |  block x+1 |  block x+2
        //  -----+----+------------+------------+--------+----
        //   ... |  A |      B     |      C     |    D   | ...
        //  -----+----+------------+------------+--------+----
        //            ^
        //            item_pos
        if (item->pos % blocksize) {
            front_margin = blocksize - item->pos % blocksize;
        } else {
            front_margin = 0;
        }
        item_pos = item->pos + front_margin;
        item_len = item->len - front_margin;

        if (item_len < blocksize) {
            // Remaining length is smaller than a block. This means that there
            // is no reusable block in this region (even though the region size is
            // bigger than a block size) .. skip this item.
            //
            //       |   block x   |  block x+1  | ...
            //  -----+------+------+-------+-----+----
            //   ... |      |//////|///////|     | ...
            //  -----+------+------+-------+-----+----
            continue;
        }

        // calculate # blocks and add to 'blocks'
        blocks_arr[n_blocks].bid = item_pos / blocksize;
        blocks_arr[n_blocks].count = item_len / blocksize;
        n_blocks += 1;
        if (n_blocks >= max_blocks) {
            max_blocks *= 2;
            blocks_arr = (struct reusable_block*)
                realloc(blocks_arr, max_blocks * sizeof(struct reusable_block));
        }

        if (front_margin) {
            // adjust the existing item to indicate 'A' in above example
            item->len = front_margin;
        } else {
            // exactly aligned .. remove this item
            avl_remove(&tree, &item->avl);
            free(item);
        }

        uint32_t remaining_len;
        remaining_len = item_len % blocksize;
        if (remaining_len) {
            // add a new item for the remaining region ('D' in above example)
            struct stale_data *new_item;
            new_item = (struct stale_data *)
                       calloc(1, sizeof(struct stale_data));
            new_item->pos = (blocks_arr[n_blocks-1].bid + blocks_arr[n_blocks-1].count)
                            * blocksize;
            new_item->len = remaining_len;
            avl_insert(&tree, &new_item->avl, _reusable_offset_cmp);
            avl = avl_next(&new_item->avl);
        }
    }

    // insert remaining items into stale list again
    avl = avl_first(&tree);
    while (avl) {
        item = _get_entry(avl, struct stale_data, avl);
        avl = avl_next(avl);
        avl_remove(&tree, &item->avl);

        list_push_back(handle->file->stale_list, &item->le);
    }
    // re-write stale tree using the last revnum as a key
    // in this case, only stale regions newly generated by this function are gathered,
    // and prev_hdr is set to BLK_NOT_FOUND, as corresponding seq numbers are already removed.
    fdb_gather_stale_blocks(handle, revnum, BLK_NOT_FOUND, BLK_NOT_FOUND, 0, e_last);

    free(revnum_array);

    ret.n_blocks = n_blocks;
    ret.blocks = blocks_arr;
    return ret;
}

