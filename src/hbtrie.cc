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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "hbtrie.h"
#include "list.h"
#include "btree.h"
#include "btree_kv.h"
#include "btree_prefix_kv.h"

#include "memleak.h"

#ifdef __DEBUG
#ifndef __DEBUG_HBTRIE
    #undef DBG
    #undef DBGCMD
    #undef DBGSW
    #define DBG(...)
    #define DBGCMD(...)
    #define DBGSW(n, ...)
#endif
#endif

#define HBTRIE_EOK (0xF0)

#define CHUNK_FLAG (0x8000)
typedef uint16_t chunkno_t;
struct hbtrie_meta {
    chunkno_t chunkno;
    uint16_t prefix_len;
    void *value;
    void *prefix;
};

#define _l2c(trie, len) ( ( (len) + ((trie)->chunksize-1) ) / (trie)->chunksize )

// MUST return same value to '_get_nchunk(_hbtrie_reform_key(RAWKEY))'
INLINE int _get_nchunk_raw(struct hbtrie *trie, void *rawkey, int rawkeylen)
{
    return _l2c(trie, rawkeylen) + 1;
}

INLINE int _get_nchunk(struct hbtrie *trie, void *key, int keylen)
{
    return (keylen-1) / trie->chunksize + 1;
}

int _hbtrie_reform_key(struct hbtrie *trie, void *rawkey,
                       int rawkeylen, void *outkey)
{
    int outkeylen;
    int nchunk;
    int i;
    uint8_t EOK = HBTRIE_EOK;
    uint8_t rsize;
    uint64_t *ptr64;

    nchunk = _get_nchunk_raw(trie, rawkey, rawkeylen);
    outkeylen = nchunk * trie->chunksize;

    for (i=0; i<nchunk; ++i) {
        if (i < nchunk-2) {
            // full chunk
            memcpy((uint8_t*)outkey + i * trie->chunksize,
                   (uint8_t*)rawkey + i * trie->chunksize,
                   trie->chunksize);
        } else if (i == nchunk-2) {
            // just before the last chunk
            rsize = rawkeylen % trie->chunksize;
            if (rsize == 0) {
                memcpy((uint8_t*)outkey + i * trie->chunksize,
                       (uint8_t*)rawkey + i * trie->chunksize,
                       trie->chunksize);
            } else {
                memcpy((uint8_t*)outkey + i * trie->chunksize,
                       (uint8_t*)rawkey + i * trie->chunksize, rsize);
                memset((uint8_t*)outkey + i * trie->chunksize + rsize,
                       0, trie->chunksize - rsize);
            }
        } else {
            // the last(rightmost) chunk .. this is dummy chunk
            // add 'last chunk length'
            // at the last byte of the last chunk

            memset((uint8_t*)outkey + i * trie->chunksize,
                   0, trie->chunksize - 1);
            memset((uint8_t*)outkey + (i+1) * trie->chunksize - 1,
                   rsize, 1);
        }
    }

    return outkeylen;
}

// this function only returns (raw) key length
int _hbtrie_reform_key_reverse(struct hbtrie *trie,
                               void *key,
                               int keylen)
{
    uint8_t rsize;
    rsize = *((uint8_t*)key + keylen - 1);

    if (rsize == 0) {
        return keylen - trie->chunksize;
    } else {
        // rsize: 1~7
        return keylen - (trie->chunksize * 2) + rsize;
    }
}

#define _get_leaf_kv_ops btree_prefix_kv_get_kb64_vb64
#define _get_leaf_key btree_prefix_kv_get_key
#define _set_leaf_key btree_prefix_kv_set_key
#define _free_leaf_key btree_prefix_kv_free_key

void hbtrie_init(struct hbtrie *trie, int chunksize, int valuelen,
                 int btree_nodesize, bid_t root_bid, void *btreeblk_handle,
                 struct btree_blk_ops *btree_blk_ops, void *doc_handle,
                 hbtrie_func_readkey *readkey)
{
    struct btree_kv_ops *btree_kv_ops, *btree_leaf_kv_ops;

    trie->chunksize = chunksize;
    trie->valuelen = valuelen;
    trie->btree_nodesize = btree_nodesize;
    trie->btree_blk_ops = btree_blk_ops;
    trie->btreeblk_handle = btreeblk_handle;
    trie->doc_handle = doc_handle;
    trie->root_bid = root_bid;
    trie->flag = 0x0;
    trie->leaf_height_limit = 0;

    // assign key-value operations
    btree_kv_ops = (struct btree_kv_ops *)malloc(sizeof(struct btree_kv_ops));
    btree_leaf_kv_ops = (struct btree_kv_ops *)malloc(sizeof(struct btree_kv_ops));

    assert(chunksize == 4 || chunksize == 8);
    assert(valuelen == 8);
    assert(chunksize >= sizeof(void *));

    if (chunksize == 8 && valuelen == 8){
        btree_kv_ops = btree_kv_get_kb64_vb64(btree_kv_ops);
        btree_leaf_kv_ops = btree_prefix_kv_get_kb64_vb64(btree_leaf_kv_ops);
    }else if (chunksize == 4 && valuelen == 8) {
        btree_kv_ops = btree_kv_get_kb32_vb64(btree_kv_ops);
        btree_leaf_kv_ops = btree_prefix_kv_get_kb64_vb64(btree_leaf_kv_ops);
    }

    trie->btree_kv_ops = btree_kv_ops;
    trie->btree_leaf_kv_ops = btree_leaf_kv_ops;
    trie->readkey = readkey;
}

void hbtrie_free(struct hbtrie *trie)
{
    free(trie->btree_kv_ops);
    free(trie->btree_leaf_kv_ops);
}

void hbtrie_set_flag(struct hbtrie *trie, uint8_t flag)
{
    trie->flag = flag;
    if (trie->leaf_height_limit == 0) {
        trie->leaf_height_limit = 1;
    }
}

void hbtrie_set_leaf_height_limit(struct hbtrie *trie, uint8_t limit)
{
    trie->leaf_height_limit = limit;
}

// IMPORTANT: hbmeta doesn't have own allocated memory space (pointers only)
void _hbtrie_fetch_meta(struct hbtrie *trie, int metasize,
                        struct hbtrie_meta *hbmeta, void *buf)
{
    // read hbmeta from buf
    int offset = 0;
    uint32_t valuelen = 0;

    memcpy(&hbmeta->chunkno, buf, sizeof(hbmeta->chunkno));
    offset += sizeof(hbmeta->chunkno);

    memcpy(&valuelen, (uint8_t*)buf+offset, sizeof(trie->valuelen));
    offset += sizeof(trie->valuelen);

    if (valuelen > 0) {
        hbmeta->value = (uint8_t*)buf + offset;
        offset += trie->valuelen;
    } else {
        hbmeta->value = NULL;
    }

    if (metasize - offset > 0) {
        //memcpy(hbmeta->prefix, buf+offset, metasize - offset);
        hbmeta->prefix = (uint8_t*)buf + offset;
        hbmeta->prefix_len = metasize - offset;
    } else {
        hbmeta->prefix = NULL;
        hbmeta->prefix_len = 0;
    }
}

typedef enum {
    HBMETA_NORMAL,
    HBMETA_LEAF,
} hbmeta_opt;
void _hbtrie_store_meta(struct hbtrie *trie,
                        metasize_t *metasize,
                        chunkno_t chunkno,
                        hbmeta_opt opt,
                        void *prefix,
                        int prefixlen,
                        void *value,
                        void *buf)
{
    // write hbmeta to buf
    *metasize = 0;

    if (opt == HBMETA_LEAF) {
        chunkno |= CHUNK_FLAG;
    }
    memcpy(buf, &chunkno, sizeof(chunkno));
    *metasize += sizeof(chunkno);

    if (value) {
        memcpy((uint8_t*)buf + *metasize,
               &trie->valuelen, sizeof(trie->valuelen));
        *metasize += sizeof(trie->valuelen);
        memcpy((uint8_t*)buf + *metasize,
               value, trie->valuelen);
        *metasize += trie->valuelen;
    }else{
        memset((uint8_t*)buf + *metasize, 0x0, sizeof(trie->valuelen));
        *metasize += sizeof(trie->valuelen);
    }

    if (prefixlen > 0) {
        memcpy((uint8_t*)buf + *metasize, prefix, prefixlen);
        *metasize += prefixlen;
    }
}

INLINE int _hbtrie_find_diff_chunk(struct hbtrie *trie,
                                   void *key1,
                                   void *key2,
                                   int start_chunk,
                                   int end_chunk)
{
    int i;
    for (i=start_chunk; i < end_chunk; ++i) {
        if (memcmp((uint8_t*)key1 + trie->chunksize*i,
                   (uint8_t*)key2 + trie->chunksize*i,
                   trie->chunksize)) {
             return i;
        }
    }
    return i;
}

//3 little endian
INLINE void _hbtrie_set_msb(struct hbtrie *trie, void *value)
{
    *((uint8_t*)value + (trie->valuelen-1)) |= (uint8_t)0x80;
}

INLINE void _hbtrie_clear_msb(struct hbtrie *trie, void *value)
{
    *((uint8_t*)value + (trie->valuelen-1)) &= ~((uint8_t)0x80);
}

INLINE int _hbtrie_is_msb_set(struct hbtrie *trie, void *value)
{
    return *((uint8_t*)value + (trie->valuelen-1)) & ((uint8_t)0x80);
}

struct btreelist_item {
    struct btree btree;
    chunkno_t chunkno;
    bid_t child_rootbid;
    struct list_elem e;
    uint8_t leaf;
};

struct btreeit_item {
    struct btree_iterator btree_it;
    chunkno_t chunkno;
    struct list_elem le;
    uint8_t leaf;
};

#define _is_leaf_btree(chunkno) ((chunkno) & CHUNK_FLAG)
#define _get_chunkno(chunkno) ((chunkno) & (~(CHUNK_FLAG)))

hbtrie_result hbtrie_iterator_init(
    struct hbtrie *trie, struct hbtrie_iterator *it, void *initial_key, size_t keylen)
{
    it->trie = *trie;
    it->curkey = (void *)malloc(HBTRIE_MAX_KEYLEN);
    memset(it->curkey, 0, HBTRIE_MAX_KEYLEN);

    if (initial_key) {
        it->keylen = _hbtrie_reform_key(trie, initial_key, keylen, it->curkey);
    }else{
        it->keylen = 0;
    }
    list_init(&it->btreeit_list);

    return HBTRIE_RESULT_SUCCESS;
}

hbtrie_result hbtrie_iterator_free(struct hbtrie_iterator *it)
{
    struct list_elem *e;
    struct btreeit_item *item;
    e = list_begin(&it->btreeit_list);
    while(e){
        item = _get_entry(e, struct btreeit_item, le);
        e = list_remove(&it->btreeit_list, e);
        btree_iterator_free(&item->btree_it);
        mempool_free(item);
    }
    if (it->curkey) free(it->curkey);
    return HBTRIE_RESULT_SUCCESS;
}

// recursive function
#define HBTRIE_PREFIX_MATCH_ONLY (0x1)
hbtrie_result _hbtrie_next(struct hbtrie_iterator *it,
                           struct btreeit_item *item,
                           void *key_buf,
                           size_t *keylen,
                           void *value_buf,
                           uint8_t flag)
{
    struct hbtrie *trie = &it->trie;
    struct list_elem *e;
    struct btreeit_item *item_new;
    struct btree btree;
    hbtrie_result hr = HBTRIE_RESULT_FAIL;
    btree_result br;
    struct hbtrie_meta hbmeta;
    struct btree_meta bmeta;
    void *chunk;
    uint8_t *k = alca(uint8_t, trie->chunksize);
    uint8_t *v = alca(uint8_t, trie->valuelen);
    bid_t bid;
    uint64_t offset;

    if (item == NULL) {
        // this happens only when first call
        // create iterator for root b-tree
        if (it->trie.root_bid == BLK_NOT_FOUND) return HBTRIE_RESULT_FAIL;
        // set current chunk (key for b-tree)
        chunk = it->curkey;
        // load b-tree
        btree_init_from_bid(
            &btree, trie->btreeblk_handle, trie->btree_blk_ops, trie->btree_kv_ops,
            trie->btree_nodesize, trie->root_bid);

        item = (struct btreeit_item *)mempool_alloc(sizeof(struct btreeit_item));
        item->chunkno = 0;
        item->leaf = 0;

        br = btree_iterator_init(&btree, &item->btree_it, chunk);
        if (br == BTREE_RESULT_FAIL) return HBTRIE_RESULT_FAIL;

        list_push_back(&it->btreeit_list, &item->le);
    }

    e = list_next(&item->le);
    if (e) {
        // if next sub b-tree exists
        item_new = _get_entry(e, struct btreeit_item, le);
        hr = _hbtrie_next(it, item_new, key_buf, keylen, value_buf, flag);
        if (hr == HBTRIE_RESULT_SUCCESS) return hr;
        it->keylen = (item->chunkno+1) * trie->chunksize;
    }

    while(hr == HBTRIE_RESULT_FAIL) {
        // get key-value from current b-tree iterator
        memset(k, 0, trie->chunksize);
        br = btree_next(&item->btree_it, k, v);
        if (item->leaf) {
            _free_leaf_key(k);
        } else {
            chunk = (uint8_t*)it->curkey + item->chunkno * trie->chunksize;
            if (item->btree_it.btree.kv_ops->cmp(k, chunk) != 0) {
                // not exact match key .. the rest of string is not necessary anymore
                it->keylen = (item->chunkno+1) * trie->chunksize;
            }
        }

        if (br == BTREE_RESULT_FAIL) {
            // no more KV pair in the b-tree
            btree_iterator_free(&item->btree_it);
            list_remove(&it->btreeit_list, &item->le);
            mempool_free(item);
            return HBTRIE_RESULT_FAIL;
        }

        // check whether v points to doc or sub b-tree
        if (_hbtrie_is_msb_set(trie, v)) {
            // MSB is set -> sub b-tree

            // load sub b-tree and create new iterator for the b-tree
            _hbtrie_clear_msb(trie, v);
            bid = trie->btree_kv_ops->value2bid(v);
            btree_init_from_bid(
                &btree, trie->btreeblk_handle, trie->btree_blk_ops, trie->btree_kv_ops,
                trie->btree_nodesize, bid);

            // get sub b-tree's chunk number
            bmeta.data = (void *)mempool_alloc(trie->btree_nodesize);
            bmeta.size = btree_read_meta(&btree, bmeta.data);
            _hbtrie_fetch_meta(trie, bmeta.size, &hbmeta, bmeta.data);

            item_new = (struct btreeit_item *)mempool_alloc(sizeof(struct btreeit_item));
            if (_is_leaf_btree(hbmeta.chunkno)) {
                btree.kv_ops = trie->btree_leaf_kv_ops;
                item_new->leaf = 1;
            } else {
                item_new->leaf = 0;
            }
            hbmeta.chunkno = _get_chunkno(hbmeta.chunkno);
            item_new->chunkno = hbmeta.chunkno;

            if ( (item_new->chunkno+1)*trie->chunksize <= it->keylen ) {
                // happen only once for the first call (for each level of b-trees)
                chunk = (uint8_t*)it->curkey +
                        item_new->chunkno*trie->chunksize;
            }else{
                // chunk number of the b-tree is longer than current iterator's key
                // set smallest key
                chunk = NULL;
            }

            if (item_new->leaf && chunk) {
                uint8_t *k_temp = alca(uint8_t, trie->chunksize);
                _set_leaf_key(k_temp, chunk,
                    it->keylen - (item_new->chunkno * trie->chunksize));
                btree_iterator_init(&btree, &item_new->btree_it, k_temp);
                _free_leaf_key(k_temp);
            } else {
                btree_iterator_init(&btree, &item_new->btree_it, chunk);
            }
            list_push_back(&it->btreeit_list, &item_new->le);

            if (hbmeta.value && chunk == NULL) {
                // NULL key exists .. the smallest key in this tree .. return first
                offset = trie->btree_kv_ops->value2bid(hbmeta.value);
                if (!(flag & HBTRIE_PREFIX_MATCH_ONLY)) {
                    *keylen = trie->readkey(trie->doc_handle, offset, key_buf);
                    it->keylen = _hbtrie_reform_key(trie, key_buf, *keylen, it->curkey);
                }
                memcpy(value_buf, &offset, trie->valuelen);
                hr = HBTRIE_RESULT_SUCCESS;
            } else {
                hr = _hbtrie_next(it, item_new, key_buf, keylen, value_buf, flag);
            }
            mempool_free(bmeta.data);
            if (hr == HBTRIE_RESULT_SUCCESS)
                return hr;

            // fail searching .. get back to parent tree
            // (this happens when the initial key is greater than
            // the largest key in the current tree (ITEM_NEW) ..
            // so return back to ITEM and retrieve next child)
            it->keylen = (item->chunkno+1) * trie->chunksize;

        }else{
            // MSB is not set -> doc
            // read entire key and return the doc offset
            offset = trie->btree_kv_ops->value2bid(v);
            if (!(flag & HBTRIE_PREFIX_MATCH_ONLY)) {
                *keylen = trie->readkey(trie->doc_handle, offset, key_buf);
                it->keylen = _hbtrie_reform_key(trie, key_buf, *keylen, it->curkey);
            }
            memcpy(value_buf, &offset, trie->valuelen);

            return HBTRIE_RESULT_SUCCESS;
        }
    }
    return HBTRIE_RESULT_FAIL;
}

hbtrie_result hbtrie_next(struct hbtrie_iterator *it,
                          void *key_buf,
                          size_t *keylen,
                          void *value_buf)
{
    hbtrie_result hr;

    if (it->curkey == NULL) return HBTRIE_RESULT_FAIL;

    struct list_elem *e = list_begin(&it->btreeit_list);
    struct btreeit_item *item = NULL;
    if (e) item = _get_entry(e, struct btreeit_item, le);

    hr = _hbtrie_next(it, item, key_buf, keylen, value_buf, 0x0);
    if (hr == HBTRIE_RESULT_FAIL) {
        // this iterator reaches the end of hb-trie
        free(it->curkey);
        it->curkey = NULL;
    }
    return hr;
}

hbtrie_result hbtrie_next_value_only(struct hbtrie_iterator *it,
                                 void *value_buf)
{
    hbtrie_result hr;

    if (it->curkey == NULL) return HBTRIE_RESULT_FAIL;

    struct list_elem *e = list_begin(&it->btreeit_list);
    struct btreeit_item *item = NULL;
    if (e) item = _get_entry(e, struct btreeit_item, le);

    hr = _hbtrie_next(it, item, NULL, 0, value_buf, HBTRIE_PREFIX_MATCH_ONLY);
    if (hr == HBTRIE_RESULT_FAIL) {
        // this iterator reaches the end of hb-trie
        free(it->curkey);
        it->curkey = NULL;
    }
    return hr;
}

void _hbtrie_btree_cascaded_update(
    struct hbtrie *trie, struct list *btreelist, void *key, int free_opt)
{
    bid_t bid_new;
    btree_result r;
    struct btreelist_item *btreeitem, *btreeitem_child;
    struct list_elem *e, *e_child;

    e = e_child = NULL;

    //3 cascaded update of each b-tree from leaf to root
    e_child = list_end(btreelist);
    if (e_child) e = list_prev(e_child);

    while(e && e_child) {
        btreeitem = _get_entry(e, struct btreelist_item, e);
        btreeitem_child = _get_entry(e_child, struct btreelist_item, e);

        if (btreeitem->child_rootbid != btreeitem_child->btree.root_bid) {
            // root node of child sub-tree has been moved to another block -> update parent sub-tree
            bid_new = btreeitem_child->btree.root_bid;
            _hbtrie_set_msb(trie, (void *)&bid_new);
            r = btree_insert(&btreeitem->btree,
                    (uint8_t*)key + btreeitem->chunkno * trie->chunksize,
                    (void *)&bid_new);
        }
        e_child = e;
        e = list_prev(e);
    }

    // update trie root bid
    if (e) {
        btreeitem = _get_entry(e, struct btreelist_item, e);
        trie->root_bid = btreeitem->btree.root_bid;
    }else if (e_child) {
        btreeitem = _get_entry(e_child, struct btreelist_item, e);
        trie->root_bid = btreeitem->btree.root_bid;
    }else {
        assert(0);
    }

    if (free_opt) {
        // free all items on list
        e = list_begin(btreelist);
        while(e) {
            btreeitem = _get_entry(e, struct btreelist_item, e);
            e = list_remove(btreelist, e);
            mempool_free(btreeitem);
        }
    }
}

hbtrie_result _hbtrie_find(struct hbtrie *trie, void *key, int keylen,
                           void *valuebuf, struct list *btreelist, uint8_t flag)
{
    int nchunk;
    int rawkeylen;
    int prevchunkno, curchunkno, cpt_node = 0;
    struct btree *btree = NULL;
    struct btree btree_static;
    btree_result r;
    metasize_t metasize;
    struct hbtrie_meta hbmeta;
    struct btree_meta meta;
    struct btreelist_item *btreeitem = NULL;
    uint8_t *k = alca(uint8_t, trie->chunksize);
    uint8_t *buf = alca(uint8_t, trie->btree_nodesize);
    uint8_t *btree_value = alca(uint8_t, trie->valuelen);
    void *chunk = NULL;
    bid_t bid_new;
    nchunk = _get_nchunk(trie, key, keylen);

    meta.data = buf;
    prevchunkno = curchunkno = 0;

    if (btreelist) {
        list_init(btreelist);
        btreeitem = (struct btreelist_item *)mempool_alloc(sizeof(struct btreelist_item));
        list_push_back(btreelist, &btreeitem->e);
        btree = &btreeitem->btree;
    } else {
        btree = &btree_static;
    }

    if (trie->root_bid == BLK_NOT_FOUND) {
        // retrieval fail
        return HBTRIE_RESULT_FAIL;
    } else {
        // read from root_bid
        r = btree_init_from_bid(btree, trie->btreeblk_handle, trie->btree_blk_ops,
                                trie->btree_kv_ops, trie->btree_nodesize,
                                trie->root_bid);
        assert(btree->ksize == trie->chunksize && btree->vsize == trie->valuelen);
    }

    while (curchunkno < nchunk) {
        // get current chunk number
        meta.size = btree_read_meta(btree, meta.data);
        _hbtrie_fetch_meta(trie, meta.size, &hbmeta, meta.data);
        prevchunkno = curchunkno;
        if (_is_leaf_btree(hbmeta.chunkno)) {
            cpt_node = 1;
            hbmeta.chunkno = _get_chunkno(hbmeta.chunkno);
            btree->kv_ops = trie->btree_leaf_kv_ops;
        }
        curchunkno = hbmeta.chunkno;

        if (btreelist) {
            btreeitem->chunkno = curchunkno;
            btreeitem->leaf = cpt_node;
        }

        //3 check whether there are skipped prefixes.
        if (curchunkno - prevchunkno > 1) {
            assert(hbmeta.prefix != NULL);
            // prefix comparison (find the first different chunk)
            int diffchunkno = _hbtrie_find_diff_chunk(
                trie, hbmeta.prefix,
                (uint8_t*)key + trie->chunksize * (prevchunkno+1),
                0, curchunkno - (prevchunkno+1));
            if (diffchunkno < curchunkno - (prevchunkno+1)) {
                // prefix does not match -> retrieval fail
                return HBTRIE_RESULT_FAIL;
            }
        }

        //3 search b-tree using current chunk (or postfix)
        rawkeylen = _hbtrie_reform_key_reverse(trie, key, keylen);
        if ((cpt_node && rawkeylen == curchunkno * trie->chunksize) ||
            (!cpt_node && nchunk == curchunkno)) {
            // KEY is exactly same as tree's prefix .. return value in metasection
            memcpy(valuebuf, hbmeta.value, trie->valuelen);
            return HBTRIE_RESULT_SUCCESS;
        } else {
            chunk = (uint8_t*)key + curchunkno*trie->chunksize;
            if (cpt_node) {
                // leaf b-tree
                size_t rawchunklen =
                    _hbtrie_reform_key_reverse(trie, chunk,
                    (nchunk-curchunkno)*trie->chunksize);

                _set_leaf_key(k, chunk, rawchunklen);
                r = btree_find(btree, k, btree_value);
                _free_leaf_key(k);
            } else {
                r = btree_find(btree, chunk, btree_value);
            }
        }

        if (r == BTREE_RESULT_FAIL) {
            // retrieval fail
            return HBTRIE_RESULT_FAIL;
        } else {
            // same chunk exists -> check whether the value points to sub-tree or document
            // check MSB
            if (_hbtrie_is_msb_set(trie, btree_value)) {
                // this is BID of b-tree node (by clearing MSB)
                _hbtrie_clear_msb(trie, btree_value);
                bid_new = trie->btree_kv_ops->value2bid(btree_value);

                if (btreelist) {
                    btreeitem->child_rootbid = bid_new;
                    btreeitem = (struct btreelist_item *)
                                mempool_alloc(sizeof(struct btreelist_item));
                    list_push_back(btreelist, &btreeitem->e);
                    btree = &btreeitem->btree;
                }

                // fetch sub-tree
                r = btree_init_from_bid(btree, trie->btreeblk_handle, trie->btree_blk_ops,
                                        trie->btree_kv_ops, trie->btree_nodesize, bid_new);
            } else {
                // this is offset of document (as it is)
                // read entire key
                uint8_t *docrawkey = alca(uint8_t, HBTRIE_MAX_KEYLEN);
                uint8_t *dockey = alca(uint8_t, HBTRIE_MAX_KEYLEN);
                uint32_t docrawkeylen, dockeylen;
                uint64_t offset;
                int docnchunk, minchunkno, diffchunkno;

                // get offset value from btree_value
                offset = trie->btree_kv_ops->value2bid(btree_value);
                if (!(flag & HBTRIE_PREFIX_MATCH_ONLY)) {
                    // read entire key
                    docrawkeylen = trie->readkey(trie->doc_handle, offset, docrawkey);
                    dockeylen = _hbtrie_reform_key(trie, docrawkey, docrawkeylen, dockey);

                    // find first different chunk
                    docnchunk = _get_nchunk(trie, dockey, dockeylen);

                    if (docnchunk == nchunk) {
                        diffchunkno = _hbtrie_find_diff_chunk(trie, key,
                                            dockey, curchunkno, nchunk);
                        if (diffchunkno == nchunk) {
                            // success
                            memcpy(valuebuf, btree_value, trie->valuelen);
                            return HBTRIE_RESULT_SUCCESS;
                        }
                    }
                    return HBTRIE_RESULT_FAIL;
                } else {
                    // just return value
                    memcpy(valuebuf, btree_value, trie->valuelen);
                    return HBTRIE_RESULT_SUCCESS;
                }
            }
        }
    }

    return HBTRIE_RESULT_FAIL;
}

hbtrie_result hbtrie_find(struct hbtrie *trie, void *rawkey,
                          int rawkeylen, void *valuebuf)
{
    int nchunk = _get_nchunk_raw(trie, rawkey, rawkeylen);
    uint8_t *key = alca(uint8_t, nchunk * trie->chunksize);
    int keylen;

    keylen = _hbtrie_reform_key(trie, rawkey, rawkeylen, key);
    return _hbtrie_find(trie, key, keylen, valuebuf, NULL, 0x0);
}

hbtrie_result hbtrie_find_offset(struct hbtrie *trie, void *rawkey,
                        int rawkeylen, void *valuebuf)
{
    int nchunk = _get_nchunk_raw(trie, rawkey, rawkeylen);
    uint8_t *key = alca(uint8_t, nchunk * trie->chunksize);
    int keylen;

    keylen = _hbtrie_reform_key(trie, rawkey, rawkeylen, key);
    return _hbtrie_find(trie, key, keylen, valuebuf, NULL,
        HBTRIE_PREFIX_MATCH_ONLY);
}

hbtrie_result hbtrie_remove(struct hbtrie *trie, void *rawkey, int rawkeylen)
{
    int nchunk = _get_nchunk_raw(trie, rawkey, rawkeylen);
    int keylen;
    uint8_t *key = alca(uint8_t, nchunk * trie->chunksize);
    uint8_t *valuebuf = alca(uint8_t, trie->valuelen);
    hbtrie_result r;
    btree_result br;
    struct list btreelist;
    struct btreelist_item *btreeitem;
    struct list_elem *e;

    keylen = _hbtrie_reform_key(trie, rawkey, rawkeylen, key);

    r = _hbtrie_find(trie, key, keylen, valuebuf, &btreelist, 0x0);

    if (r == HBTRIE_RESULT_SUCCESS) {
        e = list_end(&btreelist);
        assert(e);

        btreeitem = _get_entry(e, struct btreelist_item, e);
        if ((btreeitem->leaf && rawkeylen == btreeitem->chunkno * trie->chunksize) ||
            (!(btreeitem->leaf) && nchunk == btreeitem->chunkno)) {
            // key is exactly same as b-tree's prefix .. remove from metasection
            metasize_t metasize;
            struct hbtrie_meta hbmeta;
            struct btree_meta meta;
            hbmeta_opt opt;
            uint8_t *buf = alca(uint8_t, trie->btree_nodesize);

            meta.data = buf;
            meta.size = btree_read_meta(&btreeitem->btree, meta.data);
            _hbtrie_fetch_meta(trie, meta.size, &hbmeta, meta.data);

            opt = (_is_leaf_btree(hbmeta.chunkno))?(HBMETA_LEAF):(HBMETA_NORMAL);

            // remove value from metasection
            _hbtrie_store_meta(
                    trie, &meta.size, _get_chunkno(hbmeta.chunkno), opt,
                    hbmeta.prefix, hbmeta.prefix_len, NULL, buf);
            btree_update_meta(&btreeitem->btree, &meta);
        } else {
            if (btreeitem->leaf) {
                // leaf b-tree
                uint8_t *k = alca(uint8_t, trie->chunksize);
                _set_leaf_key(k, key + btreeitem->chunkno * trie->chunksize,
                    rawkeylen - btreeitem->chunkno * trie->chunksize);
                br = btree_remove(&btreeitem->btree, k);
                _free_leaf_key(k);
            } else {
                // normal b-tree
                br = btree_remove(&btreeitem->btree, key + trie->chunksize * btreeitem->chunkno);
            }
            //assert(br != BTREE_RESULT_FAIL);
            if (br == BTREE_RESULT_FAIL) r = HBTRIE_RESULT_FAIL;
        }
    }

    _hbtrie_btree_cascaded_update(trie, &btreelist, key, 1);
    return r;
}


struct _key_item {
    size_t keylen;
    void *key;
    void *value;
    struct list_elem le;
};

void _hbtrie_extend_leaf_tree(
    struct hbtrie *trie,
    struct list *btreelist,
    struct btreelist_item *btreeitem,
    void *pre_str,
    size_t pre_str_len)
{
    struct list keys;
    struct list_elem *e;
    struct _key_item *item, *smallest = NULL;
    struct btree_iterator it;
    struct btree new_btree;
    struct btree_meta meta;
    struct hbtrie_meta hbmeta;
    btree_result br;
    void *prefix = NULL, *meta_value = NULL;
    uint8_t *key_str = alca(uint8_t, HBTRIE_MAX_KEYLEN);
    uint8_t *key_buf = alca(uint8_t, trie->chunksize);
    uint8_t *value_buf = alca(uint8_t, trie->valuelen);
    uint8_t *buf = alca(uint8_t, trie->btree_nodesize);
    size_t keylen, minchunkno = 0, rawkeylen, chunksize;

    chunksize = trie->chunksize;

    // fetch metadata
    meta.data = buf;
    meta.size = btree_read_meta(&btreeitem->btree, meta.data);
    _hbtrie_fetch_meta(trie, meta.size, &hbmeta, meta.data);

    // scan all keys
    list_init(&keys);
    memset(key_buf, 0, chunksize);
    minchunkno = 0;

    br = btree_iterator_init(&btreeitem->btree, &it, NULL);
    while (br == BTREE_RESULT_SUCCESS) {
        // get key
        if ((br = btree_next(&it, key_buf, value_buf)) ==
            BTREE_RESULT_FAIL) break;

        _get_leaf_key(key_buf, key_str, &keylen);
        _free_leaf_key(key_buf);

        // insert into list
        item = (struct _key_item *)malloc(sizeof(struct _key_item));

        item->key = (void *)malloc(keylen);
        item->keylen = keylen;
        memcpy(item->key, key_str, keylen);

        item->value = (void *)malloc(trie->valuelen);
        memcpy(item->value, value_buf, trie->valuelen);

        list_push_back(&keys, &item->le);

        if (hbmeta.value == NULL) {
            // check common prefix
            if (prefix == NULL) {
                // initialize
                prefix = item->key;
                minchunkno = _l2c(trie, item->keylen);
            } else {
                // update the length of common prefix
                minchunkno = _hbtrie_find_diff_chunk(
                    trie, prefix, item->key, 0,
                    MIN(_l2c(trie, item->keylen), minchunkno));
            }

            // update smallest (shortest) key
            if (smallest == NULL) {
                smallest = item;
            } else {
                if (item->keylen < smallest->keylen)
                    smallest = item;
            }
        }
    }
    btree_iterator_free(&it);

    // construct new (non-leaf) b-tree
    if (hbmeta.value) {
        // insert tree's prefix into the list
        item = (struct _key_item *)malloc(sizeof(struct _key_item));

        item->key = NULL;
        item->keylen = 0;

        item->value = (void *)malloc(trie->valuelen);
        memcpy(item->value, hbmeta.value, trie->valuelen);

        list_push_back(&keys, &item->le);

        meta_value = smallest = NULL;
    } else {
        if (smallest) {
            if (minchunkno > 0 &&
                _get_nchunk_raw(trie, smallest->key, smallest->keylen) ==
                    minchunkno) {
                meta_value = smallest->value;
            } else {
                smallest = NULL;
            }
        }
    }
    _hbtrie_store_meta(
            trie, &meta.size, _get_chunkno(hbmeta.chunkno) + minchunkno,
            HBMETA_NORMAL, prefix, minchunkno * chunksize, meta_value, buf);

    btree_init(&new_btree, trie->btreeblk_handle, trie->btree_blk_ops,
        trie->btree_kv_ops, trie->btree_nodesize, chunksize, trie->valuelen,
        0x0, &meta);

    // reset BTREEITEM
    btreeitem->btree = new_btree;
    btreeitem->chunkno = _get_chunkno(hbmeta.chunkno) + minchunkno;
    btreeitem->leaf = 0;

    _hbtrie_btree_cascaded_update(trie, btreelist, pre_str, 0);

    // insert all keys
    memcpy(key_str, pre_str, pre_str_len);
    e = list_begin(&keys);
    while (e) {
        item = _get_entry(e, struct _key_item, le);
        if (item != smallest) {
            if (item->keylen > 0) {
                memcpy(key_str + pre_str_len, item->key, item->keylen);
            }
            hbtrie_insert(trie, key_str, pre_str_len + item->keylen,
                item->value, value_buf);
        }

        e = list_remove(&keys, e);
        if (item->key) {
            free(item->key);
        }
        free(item->value);
        free(item);
    }

}

hbtrie_result hbtrie_insert(struct hbtrie *trie, void *rawkey, int rawkeylen,
            void *value, void *oldvalue_out)
{
    /*
    <insertion cases>
    1. normal insert: there is no creation of new b-tree
    2. replacing doc to new b-tree: a doc (which has same prefix) already exists
        2-1. b-tree has file offset to doc in its metadata, and the other doc is inserted into the tree
        2-2. two docs are inserted into the new b-tree
    3. create new b-tree between existing b-trees: when prefix mismatches
    */

    int nchunk;
    int keylen;
    int prevchunkno, curchunkno;
    int cpt_node = 0;
    uint8_t *k = alca(uint8_t, trie->chunksize);

    struct list btreelist;
    struct list_elem *e;
    //struct btree btree, btree_new;
    struct btreelist_item *btreeitem, *btreeitem_new;
    hbtrie_result ret_result = HBTRIE_RESULT_SUCCESS;
    btree_result r;
    struct btree_kv_ops *kv_ops;

    metasize_t metasize;
    struct hbtrie_meta hbmeta;
    struct btree_meta meta;
    hbmeta_opt opt;

    nchunk = _get_nchunk_raw(trie, rawkey, rawkeylen);

    uint8_t *key = alca(uint8_t, nchunk * trie->chunksize);
    uint8_t *buf = alca(uint8_t, trie->btree_nodesize);
    uint8_t *btree_value = alca(uint8_t, trie->valuelen);
    void *chunk, *chunk_new;
    bid_t bid_new;

    meta.data = buf;
    prevchunkno = curchunkno = 0;
    keylen = _hbtrie_reform_key(trie, rawkey, rawkeylen, key);

    list_init(&btreelist);
    // btreeitem for root btree
    btreeitem = (struct btreelist_item*)mempool_alloc(sizeof(struct btreelist_item));
    list_push_back(&btreelist, &btreeitem->e);

    if (trie->root_bid == BLK_NOT_FOUND) {
        // create root b-tree
        _hbtrie_store_meta(trie, &meta.size, 0, HBMETA_NORMAL, NULL, 0, NULL, buf);
        r = btree_init(
            &btreeitem->btree, trie->btreeblk_handle, trie->btree_blk_ops, trie->btree_kv_ops,
            trie->btree_nodesize, trie->chunksize, trie->valuelen, 0x0, &meta);
    }else{
        // read from root_bid
        r = btree_init_from_bid(
            &btreeitem->btree, trie->btreeblk_handle, trie->btree_blk_ops, trie->btree_kv_ops,
            trie->btree_nodesize, trie->root_bid);
    }

    while(curchunkno < nchunk){
        // get current chunk number
        meta.size = btree_read_meta(&btreeitem->btree, meta.data);
        _hbtrie_fetch_meta(trie, meta.size, &hbmeta, meta.data);
        prevchunkno = curchunkno;
        if (_is_leaf_btree(hbmeta.chunkno)) {
            cpt_node = 1;
            hbmeta.chunkno = _get_chunkno(hbmeta.chunkno);
            btreeitem->btree.kv_ops = trie->btree_leaf_kv_ops;
        }
        btreeitem->chunkno = curchunkno = hbmeta.chunkno;

        //3 check whether there is skipped prefix
        if (curchunkno - prevchunkno > 1) {
            // prefix comparison (find the first different chunk)
            int diffchunkno = _hbtrie_find_diff_chunk(
                trie, hbmeta.prefix, key + trie->chunksize * (prevchunkno+1),
                0, curchunkno - (prevchunkno+1));
            if (diffchunkno < curchunkno - (prevchunkno+1)) {
                //3 3. create sub-tree between parent and child tree

                // metadata (prefix) update in btreeitem->btree
                int new_prefixlen = trie->chunksize * (curchunkno - (prevchunkno + diffchunkno + 1) - 1);
                if (new_prefixlen > 0) {
                    uint8_t *new_prefix = alca(uint8_t, new_prefixlen);
                    memcpy(new_prefix,
                           (uint8_t*)hbmeta.prefix +
                               trie->chunksize * (diffchunkno + 1),
                           new_prefixlen);
                    _hbtrie_store_meta(trie, &meta.size, curchunkno, HBMETA_NORMAL,
                        new_prefix, new_prefixlen, hbmeta.value, buf);
                }else{
                    _hbtrie_store_meta(trie, &meta.size, curchunkno, HBMETA_NORMAL,
                        NULL, 0, hbmeta.value, buf);
                }
                btree_update_meta(&btreeitem->btree, &meta);

                // split prefix and create new sub-tree
                _hbtrie_store_meta(
                        trie, &meta.size, prevchunkno + diffchunkno + 1, HBMETA_NORMAL,
                        hbmeta.prefix, diffchunkno * trie->chunksize, NULL, buf);

                // new b-tree
                btreeitem_new = (struct btreelist_item *)mempool_alloc(sizeof(struct btreelist_item));
                btreeitem_new->chunkno = prevchunkno + diffchunkno + 1;
                r = btree_init(
                        &btreeitem_new->btree, trie->btreeblk_handle, trie->btree_blk_ops, trie->btree_kv_ops,
                        trie->btree_nodesize, trie->chunksize, trie->valuelen, 0x0, &meta);
                list_insert_before(&btreelist, &btreeitem->e, &btreeitem_new->e);

                // key
                chunk_new = key + (prevchunkno + diffchunkno + 1) * trie->chunksize;
                r = btree_insert(&btreeitem_new->btree, chunk_new, value);
                // existing btree
                chunk_new = (uint8_t*)hbmeta.prefix +
                            diffchunkno * trie->chunksize;
                btreeitem_new->child_rootbid = bid_new = btreeitem->btree.root_bid;
                // set MSB
                _hbtrie_set_msb(trie, (void*)&bid_new);
                r = btree_insert(&btreeitem_new->btree, chunk_new, (void*)&bid_new);

                break;
            }
        }

        //3 search b-tree using current chunk
        if ((cpt_node && rawkeylen == curchunkno * trie->chunksize) ||
            (!cpt_node && nchunk == curchunkno)) {
            // KEY is exactly same as tree's prefix .. insert into metasection
            _hbtrie_store_meta(
                    trie, &meta.size, curchunkno, (cpt_node)?(HBMETA_LEAF):(HBMETA_NORMAL),
                    hbmeta.prefix, (curchunkno-prevchunkno - 1)*trie->chunksize,
                    value, buf);
            btree_update_meta(&btreeitem->btree, &meta);
            break;
        } else {
            chunk = key + curchunkno*trie->chunksize;
            if (cpt_node) {
                // leaf b-tree
                _set_leaf_key(k, chunk, rawkeylen - curchunkno*trie->chunksize);
                r = btree_find(&btreeitem->btree, k, btree_value);
                _free_leaf_key(k);
            } else {
                r = btree_find(&btreeitem->btree, chunk, btree_value);
            }
        }

        if (r == BTREE_RESULT_FAIL) {
            //3 1. normal insert: same chunk does not exist -> just insert

            if (cpt_node) {
                // leaf b-tree
                size_t btree_height = btreeitem->btree.height;

                _set_leaf_key(k, chunk, rawkeylen - curchunkno*trie->chunksize);
                r = btree_insert(&btreeitem->btree, k, value);
                _free_leaf_key(k);

                if (btreeitem->btree.height > trie->leaf_height_limit) {
                    // height growth .. extend!
                    _hbtrie_extend_leaf_tree(trie, &btreelist, btreeitem,
                        key, curchunkno * trie->chunksize);
                }

            } else {
                r = btree_insert(&btreeitem->btree, chunk, value);
            }

            break;

        }else{
            // same chunk already exists -> check whether the value points to sub-tree or document
            // check MSB
            if (_hbtrie_is_msb_set(trie, btree_value)) {
                // this is BID of b-tree node (by clearing MSB)
                _hbtrie_clear_msb(trie, btree_value);
                bid_new = btreeitem->child_rootbid = trie->btree_kv_ops->value2bid(btree_value);
                //3 traverse to the sub-tree
                // fetch sub-tree
                btreeitem = (struct btreelist_item*)mempool_alloc(sizeof(struct btreelist_item));

                r = btree_init_from_bid(
                    &btreeitem->btree, trie->btreeblk_handle, trie->btree_blk_ops, trie->btree_kv_ops,
                    trie->btree_nodesize, bid_new);
                list_push_back(&btreelist, &btreeitem->e);

            }else{
                // this is offset of document (as it is)
                // create new sub-tree

                // read entire key
                uint8_t *docrawkey = alca(uint8_t, HBTRIE_MAX_KEYLEN);
                uint8_t *dockey = alca(uint8_t, HBTRIE_MAX_KEYLEN);
                uint32_t docrawkeylen, dockeylen, minrawkeylen;
                uint64_t offset;
                int docnchunk, minchunkno, newchunkno, diffchunkno;

                // get offset value from btree_value
                offset = trie->btree_kv_ops->value2bid(btree_value);
                // read entire key
                docrawkeylen = trie->readkey(trie->doc_handle, offset, docrawkey);
                dockeylen = _hbtrie_reform_key(trie, docrawkey, docrawkeylen, dockey);

                // find first different chunk
                docnchunk = _get_nchunk(trie, dockey, dockeylen);

                if (trie->flag & HBTRIE_FLAG_COMPACT) {
                    // optimization mode
                    newchunkno = curchunkno+1;
                    minchunkno = MIN(_l2c(trie, rawkeylen) , _l2c(trie, docrawkeylen));
                    minrawkeylen = MIN(rawkeylen, docrawkeylen);
                    diffchunkno =
                        _hbtrie_find_diff_chunk(trie, rawkey, docrawkey, curchunkno,
                            minchunkno - ((minrawkeylen%trie->chunksize == 0)?(0):(1)));
                    if (rawkeylen == docrawkeylen && diffchunkno+1 == minchunkno) {
                        if (!memcmp(rawkey, docrawkey, rawkeylen)) {
                            // same key
                            diffchunkno = minchunkno;
                        }
                    }
                    opt = HBMETA_LEAF;
                    kv_ops = trie->btree_leaf_kv_ops;
                } else {
                    // original mode
                    minchunkno = MIN(nchunk, docnchunk);
                    newchunkno = diffchunkno =
                        _hbtrie_find_diff_chunk(trie, key, dockey, curchunkno, minchunkno);
                    opt = HBMETA_NORMAL;
                    kv_ops = trie->btree_kv_ops;
                }

                // one key is substring of the other key
                if (minchunkno == diffchunkno && docnchunk == nchunk) {
                    //3 same key!! .. update the value

                    if (oldvalue_out) memcpy(oldvalue_out, btree_value, trie->valuelen);
                    if (cpt_node) {
                        // leaf b-tree
                        _set_leaf_key(k, chunk, rawkeylen - curchunkno*trie->chunksize);
                        r = btree_insert(&btreeitem->btree, k, value);
                        _free_leaf_key(k);
                    } else {
                        // normal b-tree
                        r = btree_insert(&btreeitem->btree, chunk, value);
                    }
                    ret_result = HBTRIE_RESULT_UPDATE;
                    break;

                }else if (minchunkno == diffchunkno && minchunkno == newchunkno) {
                    //3 2-1. create sub-tree
                    //4 which has file offset of one doc (sub-string) in its meta section,
                    //4 and insert the other doc (super-string) into the tree

                    void *key_long, *value_long;
                    void *key_short, *value_short;
                    size_t nchunk_long, rawkeylen_long;

                    if (docnchunk < nchunk) {
                        // dockey is substring of key
                        key_short = dockey;
                        value_short = btree_value;

                        key_long = key;
                        value_long = value;

                        nchunk_long = nchunk;
                        rawkeylen_long = rawkeylen;
                    }else{
                        // key is substring of dockey
                        key_short = key;
                        value_short = value;

                        key_long = dockey;
                        value_long = btree_value;

                        nchunk_long = docnchunk;
                        rawkeylen_long = docrawkeylen;
                    }

                    _hbtrie_store_meta(
                            trie, &meta.size, newchunkno, opt,
                            key + trie->chunksize * (curchunkno+1),
                            (newchunkno - (curchunkno+1)) * trie->chunksize, value_short, buf);

                    btreeitem_new = (struct btreelist_item *)mempool_alloc(sizeof(struct btreelist_item));
                    btreeitem_new->chunkno = newchunkno;
                    r = btree_init(
                            &btreeitem_new->btree, trie->btreeblk_handle,
                            trie->btree_blk_ops, kv_ops,
                            trie->btree_nodesize, trie->chunksize, trie->valuelen, 0x0, &meta);

                    list_push_back(&btreelist, &btreeitem_new->e);

                    chunk_new = (uint8_t*)key_long +
                                newchunkno * trie->chunksize;
                    if (trie->flag & HBTRIE_FLAG_COMPACT) {
                        // optimization mode
                        _set_leaf_key(k, chunk_new, rawkeylen_long - newchunkno*trie->chunksize);
                        r = btree_insert(&btreeitem_new->btree, k, value_long);
                        _free_leaf_key(k);
                    } else {
                        // normal mode
                        r = btree_insert(&btreeitem_new->btree, chunk_new, value_long);
                    }

                } else {
                    //3 2-2. create sub-tree
                    //4 and insert two docs into it
                    _hbtrie_store_meta(
                            trie, &meta.size, newchunkno, opt,
                            key + trie->chunksize * (curchunkno+1),
                            (newchunkno - (curchunkno+1)) * trie->chunksize, NULL, buf);

                    btreeitem_new = (struct btreelist_item *)mempool_alloc(sizeof(struct btreelist_item));
                    btreeitem_new->chunkno = newchunkno;
                    r = btree_init(
                            &btreeitem_new->btree, trie->btreeblk_handle,
                            trie->btree_blk_ops, kv_ops,
                            trie->btree_nodesize, trie->chunksize, trie->valuelen, 0x0, &meta);

                    list_push_back(&btreelist, &btreeitem_new->e);

                    // insert KEY
                    chunk_new = key + newchunkno * trie->chunksize;
                    if (trie->flag & HBTRIE_FLAG_COMPACT) {
                        // optimization mode
                        _set_leaf_key(k, chunk_new, rawkeylen - newchunkno*trie->chunksize);
                        r = btree_insert(&btreeitem_new->btree, k, value);
                        _free_leaf_key(k);
                    } else {
                        r = btree_insert(&btreeitem_new->btree, chunk_new, value);
                    }

                    // insert the original DOCKEY
                    chunk_new = dockey + newchunkno * trie->chunksize;
                    if (trie->flag & HBTRIE_FLAG_COMPACT) {
                        // optimization mode
                        _set_leaf_key(k, chunk_new, docrawkeylen - newchunkno*trie->chunksize);
                        r = btree_insert(&btreeitem_new->btree, k, btree_value);
                        _free_leaf_key(k);
                    } else {
                        r = btree_insert(&btreeitem_new->btree, chunk_new, btree_value);
                    }
                }

                // update previous (parent) b-tree
                bid_new = btreeitem->child_rootbid = btreeitem_new->btree.root_bid;
                // set MSB
                _hbtrie_set_msb(trie, (void *)&bid_new);
                // ASSUMPTION: parent b-tree always MUST be non-leaf b-tree
                r = btree_insert(&btreeitem->btree, chunk, (void*)&bid_new);

                break;

            } // MSB (b-tree or doc check)
        } // b-tree result success or fail
    } // while

    _hbtrie_btree_cascaded_update(trie, &btreelist, key, 1);

    return ret_result;
}



