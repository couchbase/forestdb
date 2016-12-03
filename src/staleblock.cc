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

#ifdef _DOC_COMP
#include "snappy-c.h"
#endif

#include "memleak.h"

static bool compress_inmem_stale_info = true;

void StaleDataManager::addInmemStaleInfo(filemgr_header_revnum_t revnum,
                                     struct docio_object *doc,
                                     uint64_t doc_offset,
                                     bool system_doc_only)
{
    int ret;
    size_t buflen = 0;
    StaleInfoCommit *item;
    StaleInfoEntry *entry;

    // search using revnum first
    auto cur = staleInfoTree.find(revnum);
    if (cur != staleInfoTree.end()) {
        // already exist
        item = cur->second;
    } else {
        // not exist .. create a new one and insert into tree
        item = new StaleInfoCommit();
        item->revnum = revnum;
        staleInfoTree.insert(std::make_pair(item->revnum, item));
        staleInfoTreeLoaded.store(true, std::memory_order_relaxed);
    }

    entry = new StaleInfoEntry();

    if (!system_doc_only) {
#ifdef _DOC_COMP
        if (compress_inmem_stale_info) {
            buflen = snappy_max_compressed_length(doc->length.bodylen);;
            entry->ctx = (void *)calloc(1, buflen);
            ret = snappy_compress((char*)doc->body, doc->length.bodylen,
                (char*)entry->ctx, &buflen);
            if (ret != 0) {
                fdb_log(NULL, FDB_RESULT_COMPRESSION_FAIL,
                    "(fdb_add_inmem_stale_info) "
                    "Compression error from a database file '%s'"
                    ": return value %d, header revnum %" _F64 ", "
                    "doc offset %" _F64 "\n",
                    file->getFileName(), ret, revnum, doc_offset);
                if (cur == staleInfoTree.end()) {
                    // 'item' is allocated in this function call.
                    staleInfoTree.erase(item->revnum);
                    delete item;
                }
                delete entry;
                return;
            }
        } else {
            buflen = doc->length.bodylen;
            entry->ctx = (void *)calloc(1, buflen);
            memcpy(entry->ctx, doc->body, doc->length.bodylen);
        }
#else
        buflen = doc->length.bodylen;
        entry->ctx = (void *)calloc(1, buflen);
        memcpy(entry->ctx, doc->body, doc->length.bodylen);
#endif

        entry->ctxlen = doc->length.bodylen;

    } else {
        // when 'system_doc_only' flag is set, just set to NULL.
        // we need the doc's length and offset info only.
        entry->ctx = NULL;
        entry->ctxlen = 0;
    }

    entry->comp_ctxlen = buflen;
    entry->doclen = _fdb_get_docsize(doc->length);
    entry->offset = doc_offset;
    item->infoList.push_back(entry);
}

void StaleDataManager::loadInmemStaleInfo(FdbKvsHandle *handle)
{
    uint8_t keybuf[64];
    int64_t ret;
    bid_t offset, _offset, prev_offset;
    filemgr_header_revnum_t revnum, _revnum;
    // For old btree iteration
    BTreeIterator *bit = nullptr;
    // For new btree iteration
    BtreeIteratorV2 *bit_v2 = nullptr;

    struct docio_object doc;
    bool expected = false;

    if (!staleInfoTreeLoaded.compare_exchange_strong(expected, true)) {
        // stale info is already loaded (fast screening without mutex)
        return;
    }

    // first open of the DB file
    // should grab mutex to avoid race with other writer
    file->mutexLock();

    bool is_btree_v2 = ver_btreev2_format(handle->file->getVersion());
    if (is_btree_v2) {
        bit_v2 = new BtreeIteratorV2(handle->staletreeV2);
    } else {
        bit = new BTreeIterator(handle->staletree, nullptr);
    }

    do {
        if (is_btree_v2) {
            BtreeKvPair kv_pair = bit_v2->getKvBT();
            if (!kv_pair.key) {
                break;
            }
            _revnum = *(static_cast<filemgr_header_revnum_t *>(kv_pair.key));
            _offset = *(static_cast<bid_t *>(kv_pair.value));
        } else {
            btree_result br = bit->next((void*)&_revnum, (void*)&_offset);
            handle->bhandle->flushBuffer();
            if (br != BTREE_RESULT_SUCCESS) {
                break;
            }
        }

        revnum = _endian_decode(_revnum);
        offset = _endian_decode(_offset);

        while (offset != BLK_NOT_FOUND) {
            memset(&doc, 0x0, sizeof(doc));
            // pre-allocated buffer for key
            doc.key = (void*)keybuf;

            ret = handle->dhandle->readDoc_Docio(offset, &doc, true);
            if (ret <= 0) {
                // read fail .. escape
                fdb_log(NULL, (fdb_status)ret,
                    "Error in reading a stale region info document "
                    "from a database file '%s'"
                    ": revnum %" _F64 ", offset %" _F64 "\n",
                    file->getFileName(), revnum, offset);
                offset = BLK_NOT_FOUND;
                continue;
            }

            addInmemStaleInfo(revnum, &doc, offset, false);

            // fetch previous doc offset
            memcpy(&_offset, doc.body, sizeof(_offset));
            prev_offset = _endian_decode(_offset);

            // We don't need to free 'meta' as it will be NULL.
            free(doc.body);

            offset = prev_offset;
        }
        if (is_btree_v2 && bit_v2->nextBT() != BnodeIteratorResult::SUCCESS) {
            break;
        }
    } while (true);

    if (is_btree_v2) {
        delete bit_v2;
    } else {
        delete bit;
    }

    file->mutexUnlock();
}

void StaleDataManager::gatherRegions(FdbKvsHandle *handle,
                             filemgr_header_revnum_t revnum,
                             bid_t prev_hdr,
                             uint64_t kv_info_offset,
                             fdb_seqnum_t seqnum,
                             std::list<stale_data*>::iterator e_last,
                             bool from_mergetree)
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
    bool first_loop = true;
    filemgr_header_revnum_t _revnum;
    fdb_seqnum_t _seqnum;
    KvsStat stat;

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

    struct stale_data *item;
    std::map<uint64_t, stale_data*>::iterator cur;
    std::list<stale_data*>::iterator list_cur;

    bool btreev2 = ver_btreev2_format(handle->file->getVersion());

    r = handle->file->getKvsStatOps()->statGet(0, &stat);
    if (btreev2) {
        handle->bnodeMgr->setNLiveNodes(stat.nlivenodes);
        handle->bnodeMgr->setNDeltaNodes(stat.nlivenodes);
    } else {
        handle->bhandle->setNLiveNodes(stat.nlivenodes);
        handle->bhandle->setNDeltaNodes(stat.nlivenodes);
    }
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
        // prev offset (8), prev header (8), kv_info_offset (8),
        // seqnum (8), count (4)
        offset = count_location;

        if (first_loop && from_mergetree) {
            // gather from mergetree
            cur = mergeTree.begin();
            while ( cur != mergeTree.end() ) {
                item = cur->second;

                if (handle->staletree || handle->staletreeV2) {
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


                // If 'from_mergetree' flag is set, it means that this
                // function is called at the end of fdb_get_reusable_block(),
                // and those items are remaining (non-reusable) regions after
                // picking up reusable blocks from 'mergetree'.

                // In the previous implementation, those items are converted
                // and stored as a system document. The document is re-read in
                // the next block reclaim, and then we reconstruct 'mergetree'
                // from the document; this is unnecessary duplicated overhead.

                // As an optimization, we can simply keep those items in
                // 'mergetree' and use them in the next block reclaim, without
                // reading the corresponding system document; this also reduces
                // the commit latency much. Instead, to minimize memory
                // consumption, we don't need to maintain in-memory copy of the
                // system doc corresponding to the remaining items in the
                // 'mergetree', that will be created below.

                // do not remove the item
                cur++;
            }
        } else {
            // gater from stale_list
            if ( e_last != staleList.end() ) {
                // start from some point, not the beginning
                list_cur = std::next(e_last);
            } else {
                list_cur = staleList.begin();
            }
            while ( list_cur != staleList.end() ) {
                item = *list_cur;

                if (handle->staletree || handle->staletreeV2) {
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

                list_cur = staleList.erase(list_cur);
                free(item);
            }
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
            doc.body = buf;
            doc.length.keylen = strlen(doc_key) + 1;
            doc.length.metalen = 0;
            doc.length.bodylen = offset;
            doc.seqnum = 0;
            doc_offset = handle->dhandle->appendSystemDoc_Docio(&doc);

            // insert into stale-block tree
            _doc_offset = _endian_encode(doc_offset);
            if (btreev2) {
                BtreeKvPair kv((void *)&_revnum, sizeof(uint64_t),
                    (void *)&_doc_offset, sizeof(uint64_t));
                handle->staletreeV2->insert(kv);
                handle->bnodeMgr->releaseCleanNodes();
            } else {
                handle->staletree->insert((void *)&_revnum, (void *)&_doc_offset);
                handle->bhandle->flushBuffer();
                handle->bhandle->resetSubblockInfo();
            }

            if (from_mergetree && first_loop) {
                // if from_mergetree flag is set and this is the first loop,
                // stale regions in this document are already in mergetree
                // so skip adding them into in-memory stale info tree.

                // however, the system doc itself should be marked as stale
                // when the doc is reclaimed, thus we instead add a dummy entry
                // that containing doc offset, length info only.
                addInmemStaleInfo(revnum, &doc, doc_offset, true);
            } else {
                // add the doc into in-memory stale info tree
                addInmemStaleInfo(revnum, &doc, doc_offset, false);
            }

            if ( !staleList.empty() ) {
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

        first_loop = false;
    } // gather stale blocks

    if (btreev2) {
        delta = handle->bnodeMgr->getNLiveNodes() - stat.nlivenodes;
        handle->file->getKvsStatOps()->statUpdateAttr(0, KVS_STAT_NLIVENODES, delta);
        delta = handle->bnodeMgr->getNDeltaNodes() - stat.nlivenodes;
        delta *= handle->config.blocksize;
    } else {
        delta = handle->bhandle->getNLiveNodes() - stat.nlivenodes;
        handle->file->getKvsStatOps()->statUpdateAttr(0, KVS_STAT_NLIVENODES, delta);
        delta = handle->bhandle->getNDeltaNodes() - stat.nlivenodes;
        delta *= handle->config.blocksize;
    }
    handle->file->getKvsStatOps()->statUpdateAttr(0, KVS_STAT_DELTASIZE, delta);

    free(buf);
}

void StaleDataManager::insertNmerge(std::map<uint64_t, stale_data*> *tree,
                                    uint64_t item_pos,
                                    uint32_t item_len)
{
    struct stale_data *item;
    std::map<uint64_t, stale_data*>::iterator cur, prev, next;
    std::pair<std::map<uint64_t, stale_data*>::iterator, bool> ret;

    // retrieve the tree first
    cur = tree->find(item_pos);
    if ( cur != tree->end() ) {
        // same offset already exists
        item = cur->second;
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

        ret = tree->insert(std::make_pair(item->pos, item));
        cur = ret.first;
    }

    // check prev/next item to see if they can be merged
    struct stale_data*p_item, *n_item;

    if (cur != tree->begin()) {
        // std::prev(tree->begin()) will cause undefined behavior.
        prev = std::prev(cur);
    } else {
        prev = tree->end();
    }
    if ( prev != tree->end() ) {
        p_item = prev->second;

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
            tree->erase(cur);
            free(item);
            item = p_item;
            cur = prev;
        }
    }

    next = std::next(cur);
    if ( next != tree->end() ) {
        n_item = next->second;

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
            tree->erase(next);
            free(n_item);
        }
    }
}

// Parse & fetch stale regions from the buffer 'ctx', which is the body of
// a stale info system document (from either in-memory stale-block-tree or
// on-disk stale-block-tree). After fetching, insert those regions
// into 'mergetree'.
void StaleDataManager::fetchStaleInfoDoc(void *ctx,
                                  std::map<uint64_t, stale_data*> *mergetree,
                                  uint64_t &prev_offset_out,
                                  uint64_t &prev_hdr_out)
{
    uint32_t i, count, _count, item_len;
    uint64_t pos;
    uint64_t item_pos;

    pos = 0;

    // get previous doc offset
    memcpy(&prev_offset_out, ctx, sizeof(prev_offset_out));
    prev_offset_out = _endian_decode(prev_offset_out);
    pos += sizeof(prev_offset_out);

    // get previous header BID
    memcpy(&prev_hdr_out, (uint8_t*)ctx + pos, sizeof(prev_hdr_out));
    prev_hdr_out = _endian_decode(prev_hdr_out);
    (void)prev_hdr_out;
    pos += sizeof(prev_hdr_out);

    // Skip kv_info_offset and default KVS's seqnum
    pos += sizeof(uint64_t) + sizeof(fdb_seqnum_t);

    // get count;
    memcpy(&_count, (uint8_t*)ctx + pos, sizeof(_count));
    count = _endian_decode(_count);
    pos += sizeof(_count);

    // get a stale region and insert/merge into tree
    for (i=0;i<count;++i) {
        memcpy(&item_pos, (uint8_t*)ctx + pos, sizeof(item_pos));
        item_pos = _endian_decode(item_pos);
        pos += sizeof(item_pos);

        memcpy(&item_len, (uint8_t*)ctx + pos, sizeof(item_len));
        item_len = _endian_decode(item_len);
        pos += sizeof(item_len);

        insertNmerge(mergetree, item_pos, item_len);
    }
}

reusable_block_list StaleDataManager::getReusableBlocks(FdbKvsHandle *handle,
                                           stale_header_info stale_header)
{
    int64_t delta;
    int r;
    uint8_t keybuf[64];
    uint32_t i;
    uint32_t item_len;
    uint32_t n_revnums, max_revnum_array = 256;
    uint64_t item_pos;
    // For old btree iteration
    BTreeIterator *bit = nullptr;
    // For new btree iteration
    BtreeIteratorV2 *bit_v2 = nullptr;

    filemgr_header_revnum_t revnum_upto, prev_revnum = 0;
    filemgr_header_revnum_t revnum = 0, _revnum;
    filemgr_header_revnum_t *revnum_array;
    bid_t offset, _offset, prev_offset;
    bid_t prev_hdr = BLK_NOT_FOUND;
    bool stale_tree_scan = true;
    struct docio_object doc;
    std::map<uint64_t, stale_data*> *mergetree = &mergeTree;
    struct stale_data *item;
    KvsStat stat;

    std::map<filemgr_header_revnum_t, StaleInfoCommit *>::iterator prev_commit, cur_commit;
    std::list<stale_data*>::iterator cur_stalelist, last_stalelist;

    revnum_upto = stale_header.revnum;

    r = handle->file->getKvsStatOps()->statGet(0, &stat);
    (void)r;
    bool is_btree_v2 = ver_btreev2_format(handle->file->getVersion());
    if (is_btree_v2) {
        handle->bnodeMgr->setNLiveNodes(stat.nlivenodes);
        handle->bnodeMgr->setNDeltaNodes(stat.nlivenodes);
    } else {
        handle->bhandle->setNLiveNodes(stat.nlivenodes);
        handle->bhandle->setNDeltaNodes(stat.nlivenodes);
    }

    revnum_array = (filemgr_header_revnum_t *)
                   calloc(max_revnum_array, sizeof(filemgr_header_revnum_t));
    n_revnums = 0;

    // remember the last stale list item to be preserved
    if ( staleList.empty() ) {
        last_stalelist = staleList.end();
    } else {
        last_stalelist = std::prev(staleList.end());
    }

    if (!staleInfoTree.empty()) {
        // if in-memory stale info exists
        void *uncomp_buf = NULL;
        int r;
        size_t uncomp_buflen = 128*1024; // 128 KB by default;
        StaleInfoCommit *commit;
        StaleInfoEntry *entry;

        stale_tree_scan = false;

        if (compress_inmem_stale_info) {
            uncomp_buf = (void*)calloc(1, uncomp_buflen);
        }

        cur_commit = staleInfoTree.begin();
        while (cur_commit != staleInfoTree.end()) {
            commit = cur_commit->second;
            prev_commit = cur_commit++;

            prev_revnum = revnum;
            revnum = commit->revnum;
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

            staleInfoTree.erase(prev_commit);

            auto cur_entry = commit->infoList.begin();
            while ( cur_entry != commit->infoList.end() ) {
                entry = *cur_entry;
                cur_entry = commit->infoList.erase(cur_entry);

                if (entry->ctx) {
#ifdef _DOC_COMP
                    if (compress_inmem_stale_info) {
                        // uncompression
                        if (uncomp_buflen < entry->ctxlen) {
                            uncomp_buflen = entry->ctxlen;
                            uncomp_buf = (void*)realloc(uncomp_buf, uncomp_buflen);
                        }
                        size_t len = uncomp_buflen;
                        r = snappy_uncompress((char*)entry->ctx, entry->comp_ctxlen,
                                              (char*)uncomp_buf, &len);
                        if (r != 0) {
                            fdb_log(NULL, FDB_RESULT_COMPRESSION_FAIL,
                                "(fdb_get_reusable_block) "
                                "Uncompression error from a database file '%s'"
                                ": return value %d, header revnum %" _F64 ", "
                                "doc offset %" _F64 "\n",
                                handle->file->getFileName(), r, revnum,
                                entry->offset);
                            free(uncomp_buf);
                            free(revnum_array);

                            reusable_block_list ret;
                            ret.n_blocks = 0;
                            ret.blocks = NULL;

                            return ret;
                        }

                        // fetch the context
                        fetchStaleInfoDoc(uncomp_buf, mergetree,
                                              prev_offset, prev_hdr);
                    } else {
                        fetchStaleInfoDoc(entry->ctx, mergetree,
                                              prev_offset, prev_hdr);
                    }
#else
                    fetchStaleInfoDoc(entry->ctx, mergetree, prev_offset, prev_hdr);
#endif
                }

                // also insert/merge the system doc region
                struct stale_regions sr;
                sr = getActualStaleRegionsofDoc(entry->offset, entry->doclen);

                if (sr.n_regions > 1) {
                    for (i=0; i<sr.n_regions; ++i){
                        insertNmerge(mergetree, sr.regions[i].pos, sr.regions[i].len);
                    }
                    free(sr.regions);
                } else {
                    insertNmerge(mergetree, sr.region.pos, sr.region.len);
                }

                free(entry->ctx);
                delete entry;
            }

            delete commit;
        }
        free(uncomp_buf);
    }

    if (stale_tree_scan) {
        // scan stale-block tree and get all stale regions
        // corresponding to commit headers whose seq number is
        // equal to or smaller than 'revnum_upto'
        if (is_btree_v2) {
            bit_v2 = new BtreeIteratorV2(handle->staletreeV2);
        } else {
            bit = new BTreeIterator(handle->staletree, nullptr);
        }

        do {
            if (is_btree_v2) {
                BtreeKvPair kv_pair = bit_v2->getKvBT();
                if (!kv_pair.key) {
                    break;
                }
                _revnum = *(static_cast<filemgr_header_revnum_t *>(kv_pair.key));
                _offset = *(static_cast<bid_t *>(kv_pair.value));
            } else {
                btree_result br = bit->next((void*)&_revnum, (void*)&_offset);
                handle->bhandle->flushBuffer();
                if (br != BTREE_RESULT_SUCCESS) {
                    break;
                }
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

                if (handle->dhandle->readDoc_Docio(offset, &doc, true) <= 0) {
                    // read fail .. escape
                    offset = BLK_NOT_FOUND;
                    continue;
                }

                fetchStaleInfoDoc(doc.body, mergetree, prev_offset, prev_hdr);

                // also insert/merge the system doc region
                size_t length = _fdb_get_docsize(doc.length);
                struct stale_regions sr;
                sr = getActualStaleRegionsofDoc(offset, length);

                if (sr.n_regions > 1) {
                    for (i=0; i<sr.n_regions; ++i){
                        insertNmerge(mergetree, sr.regions[i].pos, sr.regions[i].len);
                    }
                    free(sr.regions);
                } else {
                    insertNmerge(mergetree, sr.region.pos, sr.region.len);
                }

                // We don't need to free 'meta' as it will be NULL.
                free(doc.body);

                offset = prev_offset;
            }

            if (is_btree_v2 && bit_v2->nextBT() != BnodeIteratorResult::SUCCESS) {
                break;
            }
        } while (true);

        if (is_btree_v2) {
            delete bit_v2;
        } else {
            delete bit;
        }
    }

    // remove merged commit headers
    for (i=0; i<n_revnums; ++i) {
        _revnum = _endian_encode(revnum_array[i]);
        if (is_btree_v2) {
            BtreeKvPair kv((void *)&_revnum, /* key */
                           sizeof(uint64_t), /* key length */
                           nullptr, /* value */
                           0); /* value length */
            handle->staletreeV2->remove(kv);
            handle->bnodeMgr->releaseCleanNodes();
        } else {
            handle->staletree->remove((void*)&_revnum);
            handle->bhandle->flushBuffer();
        }
    }

    if (is_btree_v2) {
        delta = handle->bnodeMgr->getNLiveNodes() - stat.nlivenodes;
    } else {
        delta = handle->bhandle->getNLiveNodes() - stat.nlivenodes;
    }
    handle->file->getKvsStatOps()->statUpdateAttr(0, KVS_STAT_NLIVENODES, delta);
    if (is_btree_v2) {
        delta = handle->bnodeMgr->getNDeltaNodes() - stat.nlivenodes;
    } else {
        delta = handle->bhandle->getNDeltaNodes() - stat.nlivenodes;
    }
    // TODO: Delta size should be estimated differently for a new btree format
    delta *= handle->config.blocksize;
    handle->file->getKvsStatOps()->statUpdateAttr(0, KVS_STAT_DELTASIZE, delta);

    // gather stale blocks generated by removing b+tree entries
    if ( last_stalelist != staleList.end() ) {
        cur_stalelist = std::next(last_stalelist);
    } else {
        cur_stalelist = staleList.begin();
    }
    while ( cur_stalelist != staleList.end() ) {
        item = *cur_stalelist;
        cur_stalelist = staleList.erase(cur_stalelist);

        insertNmerge(mergetree, item->pos, item->len);
        free(item);
    }

    // now merge stale regions as large as possible
    size_t n_blocks =0 ;
    size_t blocksize = handle->file->getBlockSize();
    uint32_t max_blocks = 256;
    uint32_t front_margin;
    reusable_block_list ret;
    struct reusable_block *blocks_arr;
    std::map<uint64_t, stale_data*>::iterator cur_mergetree, prev_mergetree;
    std::pair<std::map<uint64_t, stale_data*>::iterator, bool> ret_map;

    blocks_arr = (struct reusable_block*)
        calloc(max_blocks, sizeof(struct reusable_block));

    cur_mergetree = mergetree->begin();
    while ( cur_mergetree != mergetree->end() ) {
        item = cur_mergetree->second;
        prev_mergetree = cur_mergetree++;

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
            mergetree->erase(prev_mergetree);
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

            ret_map = mergetree->insert( std::make_pair(new_item->pos, new_item) );
            prev_mergetree = ret_map.first;
            cur_mergetree = std::next(prev_mergetree);
        }
    }

    // re-write stale tree using the last revnum as a key
    // in this case, only stale regions newly generated by this function are gathered,
    // and prev_hdr is set to BLK_NOT_FOUND, as corresponding seq numbers are
    // already removed.

    // however, do not remove the remaining items in the merge-tree and continue to
    // merge them in the next block reclaim.
    gatherRegions(handle, revnum, BLK_NOT_FOUND, BLK_NOT_FOUND, 0, last_stalelist, true);

    free(revnum_array);

    ret.n_blocks = n_blocks;
    ret.blocks = blocks_arr;
    return ret;
}

void StaleDataManager::rollbackStaleBlocks(FdbKvsHandle *handle,
                               filemgr_header_revnum_t cur_revnum)
{
    filemgr_header_revnum_t i, _revnum;
    StaleInfoCommit *commit, query;
    StaleInfoEntry *entry;

    if (handle->rollback_revnum == 0) {
        return;
    }

    bool is_btree_v2 = ver_btreev2_format(handle->file->getVersion());
    // remove from on-disk stale-tree
    for (i = handle->rollback_revnum; i < cur_revnum; ++i) {
        _revnum = _endian_encode(i);
        if (is_btree_v2) {
            BtreeKvPair kv((void *)&_revnum, /* key */
                           sizeof(uint64_t), /* key length */
                           nullptr, /* value */
                           0); /* value length */
            handle->staletreeV2->remove(kv);
            handle->bnodeMgr->releaseCleanNodes();
        } else {
            handle->staletree->remove((void*)&_revnum);
            handle->bhandle->flushBuffer();
        }
    }

    // also remove from in-memory stale-tree
    auto cur_commit = staleInfoTree.find(handle->rollback_revnum);
    if (cur_commit == staleInfoTree.end()) {
        cur_commit = staleInfoTree.upper_bound(handle->rollback_revnum);
    }

    while (cur_commit != staleInfoTree.end()) {
        commit = cur_commit->second;
        cur_commit = staleInfoTree.erase(cur_commit);

        auto cur_entry = commit->infoList.begin();
        while ( cur_entry != commit->infoList.end() ) {
            entry = *cur_entry;
            cur_entry = commit->infoList.erase(cur_entry);

            free(entry->ctx);
            delete entry;
        }

        delete commit;
    }
}

StaleDataManager::StaleDataManager(FileMgr *_file)
{
    file = _file;
    staleInfoTreeLoaded = false;
}

StaleDataManager::~StaleDataManager()
{
    clearStaleList();
    clearStaleInfoTree();
    clearMergeTree();
}

void StaleDataManager::addStaleRegion(uint64_t pos, size_t len)
{
    struct stale_data *item;

    if ( !staleList.empty() ) {
        item = staleList.back();
        if (item->pos + item->len == pos) {
            // merge if consecutive item
            item->len += len;
            return;
        }
    }

    item = (struct stale_data*)calloc(1, sizeof(struct stale_data));
    item->pos = pos;
    item->len = len;
    staleList.push_back(item);
}

size_t StaleDataManager::getActualStaleLengthofDoc(uint64_t offset, size_t doclen)
{
    size_t actual_len;
    bid_t start_bid, end_bid;

    start_bid = offset / file->getBlockSize();
    end_bid = (offset + doclen) / file->getBlockSize();

    actual_len = doclen + (end_bid - start_bid);
    if ((offset + actual_len) % file->getBlockSize() ==
        file->getBlockSize() - 1) {
        actual_len += 1;
    }

    return actual_len;
}

struct stale_regions StaleDataManager::getActualStaleRegionsofDoc(uint64_t offset,
                                                                  size_t doclen)
{
    uint8_t *buf = alca(uint8_t, file->getBlockSize());
    size_t remaining = doclen;
    size_t real_blocksize = file->getBlockSize();
    size_t blocksize = real_blocksize;
    size_t cur_pos, space_in_block, count;
    bid_t cur_bid;
    bool non_consecutive = ver_non_consecutive_doc(file->getVersion());
    struct docblk_meta blk_meta;
    struct stale_regions ret;
    struct stale_data *arr = NULL, *cur_region;

    if (non_consecutive) {
        blocksize -= DOCBLK_META_SIZE;

        cur_bid = offset / file->getBlockSize();
        // relative position in the block 'cur_bid'
        cur_pos = offset % file->getBlockSize();

        count = 0;
        while (remaining) {
            if (count == 1) {
                // more than one stale region .. allocate array
                size_t arr_size = (doclen / blocksize) + 2;
                arr = (struct stale_data *)calloc(arr_size, sizeof(struct stale_data));
                arr[0] = ret.region;
                ret.regions = arr;
            }

            if (count == 0) {
                // Since n_regions will be 1 in most cases,
                // we do not allocate heap memory when 'n_regions==1'.
                cur_region = &ret.region;
            } else {
                cur_region = &ret.regions[count];
            }
            cur_region->pos = (cur_bid * real_blocksize) + cur_pos;

            // subtract data size in the current block
            space_in_block = blocksize - cur_pos;
            if (space_in_block <= remaining) {
                // rest of the current block (including block meta)
                cur_region->len = real_blocksize - cur_pos;
                remaining -= space_in_block;
            } else {
                cur_region->len = remaining;
                remaining = 0;
            }
            count++;

            if (remaining) {
                // get next BID
                file->read_FileMgr(cur_bid, (void *)buf, NULL, true);
                memcpy(&blk_meta, buf + blocksize, sizeof(blk_meta));
                cur_bid = _endian_decode(blk_meta.next_bid);
                cur_pos = 0; // beginning of the block
            }
        }
        ret.n_regions = count;

    } else {
        // doc blocks are consecutive .. always return a single region.
        ret.n_regions = 1;
        ret.region.pos = offset;
        ret.region.len = getActualStaleLengthofDoc(offset, doclen);
    }

    return ret;
}

void StaleDataManager::markDocStale(uint64_t offset, size_t doclen)
{
    if (doclen) {
        size_t i;
        struct stale_regions sr;

        sr = getActualStaleRegionsofDoc(offset, doclen);

        if (sr.n_regions > 1) {
            for (i=0; i<sr.n_regions; ++i){
                addStaleRegion(sr.regions[i].pos, sr.regions[i].len);
            }
            free(sr.regions);
        } else if (sr.n_regions == 1) {
            addStaleRegion(sr.region.pos, sr.region.len);
        }
    }
}

void StaleDataManager::clearStaleList()
{
    struct stale_data *item;

    auto cur = staleList.begin();
    while ( cur != staleList.end() ) {
        item = *cur;
        cur = staleList.erase(cur);
        free(item);
    }
}

void StaleDataManager::clearStaleInfoTree()
{
    StaleInfoCommit *commit;
    StaleInfoEntry *entry;

    auto cur_commit = staleInfoTree.begin();
    while (cur_commit != staleInfoTree.end()) {
        commit = cur_commit->second;
        cur_commit = staleInfoTree.erase(cur_commit);

        auto cur_entry = commit->infoList.begin();
        while (cur_entry != commit->infoList.end()) {
            entry = *cur_entry;
            cur_entry = commit->infoList.erase(cur_entry);
            free(entry->ctx);
            delete entry;
        }
        delete commit;
    }
}

void StaleDataManager::clearMergeTree()
{
    struct stale_data *entry;

    auto cur = mergeTree.begin();
    while (cur != mergeTree.end()) {
        entry = cur->second;
        cur = mergeTree.erase(cur);
        free(entry);
    }
}

