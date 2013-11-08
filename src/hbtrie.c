/*
 * Copyright 2013 Jung-Sang Ahn <jungsang.ahn@gmail.com>.
 * All Rights Reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "hbtrie.h"
#include "list.h"
#include "btree.h"
#include "btree_kv.h"

#include "memleak.h"

#ifdef __DEBUG
#ifndef __DEBUG_HBTRIE
    #undef DBG
    #undef DBGCMD
    #undef DBGSW
    #define DBG(args...)
    #define DBGCMD(command...)
    #define DBGSW(n, command...) 
#endif
#endif

#define HBTRIE_EOK (0xf0)

struct hbtrie_meta {
    uint8_t chunkno;
    void *value;
    void *prefix;
};

INLINE int _get_nchunk_raw(struct hbtrie *trie, void *rawkey, int rawkeylen)
{
    return rawkeylen / trie->chunksize + 1;
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
    int rsize;
    int i;
    uint8_t EOK = HBTRIE_EOK;

    nchunk = _get_nchunk_raw(trie, rawkey, rawkeylen);
    outkeylen = nchunk * trie->chunksize;

    for (i=0; i<nchunk; ++i) {
        if (i < nchunk-1) {
            // full chunk
            memcpy(outkey + i * trie->chunksize, rawkey + i * trie->chunksize,
                   trie->chunksize);
        } else {
            // the last(rightmost) chunk
            memset(outkey + i * trie->chunksize, 0, trie->chunksize);
            rsize = rawkeylen % trie->chunksize;
            if (rsize) {
                memcpy(outkey + i * trie->chunksize,
                       rawkey + i * trie->chunksize, rsize);
            }
            // add EOK mark + last chunk length
            EOK |= (uint8_t)(rsize);
            memset(outkey + i * trie->chunksize + rsize, EOK, 1);
        }
    }

    return outkeylen;
}

void hbtrie_init(struct hbtrie *trie, int chunksize, int valuelen,
                 int btree_nodesize, bid_t root_bid, void *btreeblk_handle,
                 struct btree_blk_ops *btree_blk_ops, void *doc_handle,
                 hbtrie_func_readkey *readkey)
{
    struct btree_kv_ops *btree_kv_ops;

    trie->chunksize = chunksize;
    trie->valuelen = valuelen;
    trie->btree_nodesize = btree_nodesize;
    trie->btree_blk_ops = btree_blk_ops;
    trie->btreeblk_handle = btreeblk_handle;
    trie->doc_handle = doc_handle;
    trie->root_bid = root_bid;

    // assign key-value operations
    btree_kv_ops = (struct btree_kv_ops *)malloc(sizeof(struct btree_kv_ops));

    assert(chunksize == 4 || chunksize == 8);
    assert(valuelen == 8);
    
    if (chunksize == 8 && valuelen == 8){
        btree_kv_ops = btree_kv_get_kb64_vb64(btree_kv_ops);
    }else if (chunksize == 4 && valuelen == 8) {
        btree_kv_ops = btree_kv_get_kb32_vb64(btree_kv_ops);
    }

    trie->btree_kv_ops = btree_kv_ops;
    trie->readkey = readkey;
}

void hbtrie_free(struct hbtrie *trie)
{
    free(trie->btree_kv_ops);
}

//2 IMPORTANT: hbmeta doesn't have own allocated memory space (pointers only)
void _hbtrie_fetch_meta(struct hbtrie *trie, int metasize,
                        struct hbtrie_meta *hbmeta, void *buf)
{
    // read hbmeta from buf
    int offset = 0;
    uint32_t valuelen = 0;

    memcpy(&hbmeta->chunkno, buf, sizeof(hbmeta->chunkno));
    offset += sizeof(hbmeta->chunkno);

    memcpy(&valuelen, buf+offset, sizeof(trie->valuelen));
    offset += sizeof(trie->valuelen);

    if (valuelen > 0) {
        hbmeta->value = buf+offset;
        offset += trie->valuelen;
    } else {
        hbmeta->value = NULL;
    }

    if (metasize - offset > 0) {
        //memcpy(hbmeta->prefix, buf+offset, metasize - offset);
        hbmeta->prefix = buf+offset;
    } else {
        hbmeta->prefix = NULL;
    }
}

void _hbtrie_store_meta(
            struct hbtrie *trie, metasize_t *metasize, uint8_t chunkno, 
            void *prefix, int prefixlen, void *value, void *buf)
{
    // write hbmeta to buf
    *metasize = 0;    
    memcpy(buf, &chunkno, sizeof(chunkno));
    *metasize += sizeof(chunkno);
    
    if (value) {
        memcpy(buf + *metasize, &trie->valuelen, sizeof(trie->valuelen));
        *metasize += sizeof(trie->valuelen);
        memcpy(buf + *metasize, value, trie->valuelen);
        *metasize += trie->valuelen;
    }else{
        memset(buf + *metasize, 0x0, sizeof(trie->valuelen));
        *metasize += sizeof(trie->valuelen);
    }

    if (prefixlen > 0) {
        memcpy(buf + *metasize, prefix, prefixlen);
        *metasize += prefixlen;
    }
}

INLINE int _hbtrie_find_diff_chunk(struct hbtrie *trie, void *key1, void *key2, int nchunk)
{
    int i = 0;
    for (; i < nchunk; ++i) {
        if (strncmp(key1 + trie->chunksize*i , key2 + trie->chunksize*i , trie->chunksize)) {
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
    uint8_t chunkno;
    bid_t child_rootbid;
    struct list_elem e;
};

struct btreeit_item {
    struct btree_iterator btree_it;
    int chunkno;
    struct list_elem le;
};

hbtrie_result hbtrie_iterator_init(
    struct hbtrie *trie, struct hbtrie_iterator *it, void *initial_key, size_t keylen)
{
    it->trie = *trie;
    it->curkey = (void *)malloc(HBTRIE_MAX_KEYLEN);
    
    if (initial_key) {
        it->keylen = keylen;
        memcpy(it->curkey, initial_key, it->keylen);
    }else{
        it->keylen = 0;
        memset(it->curkey, 0, HBTRIE_MAX_KEYLEN);
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
    free(it->curkey);
    return HBTRIE_RESULT_SUCCESS;
}

// recursive function
hbtrie_result _hbtrie_next(
    struct hbtrie_iterator *it, struct btreeit_item *item, void *key_buf, size_t *keylen, void *value_buf)
{
    struct hbtrie *trie = &it->trie;
    struct list_elem *e;
    struct btreeit_item *item_new;
    struct btree btree;
    hbtrie_result hr;
    btree_result br;
    struct hbtrie_meta hbmeta;
    struct btree_meta bmeta;
    void *chunk;
    uint8_t k[trie->chunksize];
    uint8_t v[trie->valuelen];
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
        
        br = btree_iterator_init(&btree, &item->btree_it, chunk);
        if (br == BTREE_RESULT_FAIL) return HBTRIE_RESULT_FAIL;

        list_push_back(&it->btreeit_list, &item->le);
    }

    e = list_next(&item->le);
    if (e) {
        // if next sub b-tree exists
        item_new = _get_entry(e, struct btreeit_item, le);
        hr = _hbtrie_next(it, item_new, key_buf, keylen, value_buf);
        if (hr == HBTRIE_RESULT_SUCCESS) return hr;
    }

    // get key-value from current b-tree iterator
    br = btree_next(&item->btree_it, k, v);
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
        mempool_free(bmeta.data);
        
        item_new = (struct btreeit_item *)mempool_alloc(sizeof(struct btreeit_item));
        item_new->chunkno = hbmeta.chunkno;

        if ( (item_new->chunkno+1)*trie->chunksize <= it->keylen ) {
            chunk = it->curkey + item_new->chunkno*trie->chunksize;
        }else{
            // chunk number of the b-tree is longer than current iterator's key
            // set smallest key
            chunk = NULL;
        }

        btree_iterator_init(&btree, &item_new->btree_it, chunk);
        list_push_back(&it->btreeit_list, &item_new->le);

        hr = _hbtrie_next(it, item_new, key_buf, keylen, value_buf);
        return hr;
        
    }else{
        // MSB is not set -> doc
        // read entire key and return the doc offset
        offset = trie->btree_kv_ops->value2bid(v);
        *keylen = trie->readkey(trie->doc_handle, offset, key_buf);
        memcpy(it->curkey + item->chunkno*trie->chunksize, 
            key_buf + item->chunkno*trie->chunksize, trie->chunksize);
        memcpy(value_buf, &offset, trie->valuelen);

        return HBTRIE_RESULT_SUCCESS;
    }
}

hbtrie_result hbtrie_next(struct hbtrie_iterator *it, void *key_buf, size_t *keylen, void *value_buf)
{
    struct list_elem *e = list_begin(&it->btreeit_list);
    struct btreeit_item *item = NULL;
    if (e) item = _get_entry(e, struct btreeit_item, le);
    
    return _hbtrie_next(it, item, key_buf, keylen, value_buf);
}

void _hbtrie_btree_cascaded_update(struct hbtrie *trie, struct list *btreelist, void *key)
{
    bid_t bid_new;
    btree_result r;
    struct btreelist_item *btreeitem, *btreeitem_child;
    struct list_elem *e, *e_child;

    //3 cascaded update of each b-tree from leaf to root
    e_child = list_end(btreelist);
    if (e_child) e = list_prev(e_child);
    
    while(e && e_child) {
        btreeitem = _get_entry(e, struct btreelist_item, e);
        btreeitem_child = _get_entry(e_child, struct btreelist_item, e);

        if (btreeitem->child_rootbid != btreeitem_child->btree.root_bid) {
            // root node of child sub-tree has been moved to another block -> update parent sub-tree
            bid_new = btreeitem_child->btree.root_bid;
            _hbtrie_set_msb(trie, &bid_new);
            r = btree_insert(&btreeitem->btree, key + btreeitem->chunkno * trie->chunksize, &bid_new);
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

    // free all items on list
    e = list_begin(btreelist);
    while(e) {
        btreeitem = _get_entry(e, struct btreelist_item, e);
        e = list_remove(btreelist, e);
        mempool_free(btreeitem);
    }
}

hbtrie_result _hbtrie_find(struct hbtrie *trie, void *key, int keylen,
                           void *valuebuf, struct list *btreelist)
{
    int nchunk;
    //int keylen;
    int prevchunkno, curchunkno;

    struct btree *btree = NULL;
    struct btree btree_static;
    btree_result r;

    metasize_t metasize;
    struct hbtrie_meta hbmeta;
    struct btree_meta meta;
    struct btreelist_item *btreeitem = NULL;

    nchunk = _get_nchunk(trie, key, keylen);

    uint8_t buf[trie->btree_nodesize], btree_value[trie->valuelen];
    void *chunk = NULL;
    bid_t bid_new;

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
        curchunkno = hbmeta.chunkno;
        if (btreelist) {
            btreeitem->chunkno = curchunkno;
        }

        //3 check whether there are skipped prefixes.
        if (curchunkno - prevchunkno > 1) {
            assert(hbmeta.prefix != NULL);
            // prefix comparison (find the first different chunk)
            int diffchunkno = _hbtrie_find_diff_chunk(trie, hbmeta.prefix,
                                                      key + trie->chunksize * (prevchunkno+1),
                                                      curchunkno - (prevchunkno+1));
            if (diffchunkno < curchunkno - (prevchunkno+1)) {
                // prefix does not match -> retrieval fail
                return HBTRIE_RESULT_FAIL;
            }
        }

        //3 search b-tree using current chunk
        chunk = key + curchunkno * trie->chunksize;
        r = btree_find(btree, chunk, btree_value);

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
                uint8_t docrawkey[HBTRIE_MAX_KEYLEN], dockey[HBTRIE_MAX_KEYLEN];
                uint32_t docrawkeylen, dockeylen;
                uint64_t offset;
                int docnchunk, minchunkno, diffchunkno;

                // get offset value from btree_value
                offset = trie->btree_kv_ops->value2bid(btree_value);
                // read entire key
                docrawkeylen = trie->readkey(trie->doc_handle, offset, docrawkey);
                dockeylen = _hbtrie_reform_key(trie, docrawkey, docrawkeylen, dockey);

                // find first different chunk
                docnchunk = _get_nchunk(trie, dockey, dockeylen);

                if (docnchunk == nchunk) {
                    diffchunkno = _hbtrie_find_diff_chunk(trie, key, dockey, nchunk);
                    if (diffchunkno == nchunk) {
                        // success
                        memcpy(valuebuf, btree_value, trie->valuelen);
                        return HBTRIE_RESULT_SUCCESS;
                    }
                }
                return HBTRIE_RESULT_FAIL;
            }
        }
    }
 
    return HBTRIE_RESULT_FAIL;
}

hbtrie_result hbtrie_find(struct hbtrie *trie, void *rawkey,
                          int rawkeylen, void *valuebuf)
{
    int nchunk = _get_nchunk_raw(trie, rawkey, rawkeylen);
    uint8_t key[nchunk * trie->chunksize];
    int keylen;

    keylen = _hbtrie_reform_key(trie, rawkey, rawkeylen, key);
    return _hbtrie_find(trie, key, keylen, valuebuf, NULL);
}

hbtrie_result hbtrie_remove(struct hbtrie *trie, void *rawkey, int rawkeylen)
{
    int nchunk = _get_nchunk_raw(trie, rawkey, rawkeylen);
    uint8_t key[nchunk * trie->chunksize];
    int keylen;
    hbtrie_result r;
    btree_result br;
    struct list btreelist;
    struct btreelist_item *btreeitem;
    struct list_elem *e;
    uint8_t valuebuf[trie->valuelen];

    keylen = _hbtrie_reform_key(trie, rawkey, rawkeylen, key);

    r = _hbtrie_find(trie, key, keylen, valuebuf, &btreelist);

    if (r == HBTRIE_RESULT_SUCCESS) {
        e = list_end(&btreelist);
        assert(e);

        btreeitem = _get_entry(e, struct btreelist_item, e);
        br = btree_remove(&btreeitem->btree, key + trie->chunksize * btreeitem->chunkno);
        //assert(br != BTREE_RESULT_FAIL);
        if (br == BTREE_RESULT_FAIL) return HBTRIE_RESULT_FAIL;

        _hbtrie_btree_cascaded_update(trie, &btreelist, key);
    }

    return r;
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

    struct list btreelist;
    struct list_elem *e;
    //struct btree btree, btree_new;
    struct btreelist_item *btreeitem, *btreeitem_new;
    hbtrie_result ret_result = HBTRIE_RESULT_SUCCESS;
    btree_result r;

    metasize_t metasize;
    struct hbtrie_meta hbmeta;
    struct btree_meta meta;

    nchunk = _get_nchunk_raw(trie, rawkey, rawkeylen);

    uint8_t key[nchunk * trie->chunksize];
    uint8_t buf[trie->btree_nodesize], btree_value[trie->valuelen];
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
        // create b-tree
        _hbtrie_store_meta(trie, &meta.size, 0, NULL, 0, NULL, buf);
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
        btreeitem->chunkno = curchunkno = hbmeta.chunkno;

        //3 check whether there is skipped prefix
        if (curchunkno - prevchunkno > 1) {
            // prefix comparison (find the first different chunk)
            int diffchunkno = _hbtrie_find_diff_chunk(
                trie, hbmeta.prefix, key + trie->chunksize * (prevchunkno+1), curchunkno - (prevchunkno+1));
            if (diffchunkno < curchunkno - (prevchunkno+1)) {
                //3 3. create sub-tree between parent and child tree

                // metadata (prefix) update in btreeitem->btree
                int new_prefixlen = trie->chunksize * (curchunkno - (prevchunkno + diffchunkno + 1) - 1);
                if (new_prefixlen > 0) {
                    uint8_t new_prefix[new_prefixlen];
                    memcpy(new_prefix, hbmeta.prefix + trie->chunksize * (diffchunkno + 1), new_prefixlen);
                    _hbtrie_store_meta(trie, &meta.size, curchunkno, new_prefix, new_prefixlen, hbmeta.value, buf);
                }else{
                    _hbtrie_store_meta(trie, &meta.size, curchunkno, NULL, 0, hbmeta.value, buf);
                }
                btree_update_meta(&btreeitem->btree, &meta);

                // split prefix and create new sub-tree
                _hbtrie_store_meta(
                        trie, &meta.size, prevchunkno + diffchunkno + 1, 
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
                chunk_new = hbmeta.prefix + diffchunkno * trie->chunksize;
                btreeitem_new->child_rootbid = bid_new = btreeitem->btree.root_bid;
                // set MSB
                _hbtrie_set_msb(trie, &bid_new);
                r = btree_insert(&btreeitem_new->btree, chunk_new, &bid_new);

                break;
            }
        }

        //3 search b-tree using current chunk
        chunk = key + curchunkno*trie->chunksize;
        r = btree_find(&btreeitem->btree, chunk, btree_value);

        if (r == BTREE_RESULT_FAIL) {
            //3 1. normal insert: same chunk does not exist -> just insert
            r = btree_insert(&btreeitem->btree, chunk, value);
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
                uint8_t docrawkey[HBTRIE_MAX_KEYLEN], dockey[HBTRIE_MAX_KEYLEN];
                uint32_t docrawkeylen, dockeylen;
                uint64_t offset;
                int docnchunk, minchunkno, diffchunkno;

                // get offset value from btree_value
                offset = trie->btree_kv_ops->value2bid(btree_value);
                // read entire key
                docrawkeylen = trie->readkey(trie->doc_handle, offset, docrawkey);
                dockeylen = _hbtrie_reform_key(trie, docrawkey, docrawkeylen, dockey);
                
                // find first different chunk
                docnchunk = _get_nchunk(trie, dockey, dockeylen);
                minchunkno = MIN(nchunk, docnchunk);
                diffchunkno = _hbtrie_find_diff_chunk(trie, key, dockey, minchunkno);

                if (diffchunkno == minchunkno) {
                    // one key is substring of the other key
                    if (docnchunk == nchunk) {
                        //3 same key!!
                        if (oldvalue_out) memcpy(oldvalue_out, btree_value, trie->valuelen);
                        r = btree_insert(&btreeitem->btree, chunk, value);
                        ret_result = HBTRIE_RESULT_UPDATE;
                        break;
                        
                    }else{
                        //3 2-1. create sub-tree which has file offset of one doc in its meta section, 
                        //3 and the other doc is inserted into the tree
                        void *key_long, *value_long;
                        void *key_short, *value_short;

                        if (docnchunk < nchunk) {
                            // dockey is substring of key
                            key_short = dockey; 
                            value_short = btree_value;
                            key_long = key;
                            value_long = value;
                        }else{
                            // key is substring of dockey
                            key_short = key; 
                            value_short = value;
                            key_long = dockey; 
                            value_long = btree_value;
                        }

                        _hbtrie_store_meta(
                                trie, &meta.size, diffchunkno, 
                                key + trie->chunksize * (curchunkno+1), 
                                (diffchunkno - (curchunkno+1)) * trie->chunksize, value_short, buf);

                        btreeitem_new = (struct btreelist_item *)mempool_alloc(sizeof(struct btreelist_item));
                        btreeitem_new->chunkno = diffchunkno;
                        r = btree_init(
                                &btreeitem_new->btree, trie->btreeblk_handle, trie->btree_blk_ops, trie->btree_kv_ops, 
                                trie->btree_nodesize, trie->chunksize, trie->valuelen, 0x0, &meta);
                        //btreeitem->child_rootbid = btreeitem_new->btree.root_bid;
                        list_push_back(&btreelist, &btreeitem_new->e);

                        chunk_new = key_long + diffchunkno * trie->chunksize;
                        r = btree_insert(&btreeitem_new->btree, chunk_new, value_long);

                    }
                } else {
                    //3 2-2. create sub-tree and insert two docs into it
                    _hbtrie_store_meta(
                            trie, &meta.size, diffchunkno, 
                            key + trie->chunksize * (curchunkno+1), 
                            (diffchunkno - (curchunkno+1)) * trie->chunksize, NULL, buf);

                    btreeitem_new = (struct btreelist_item *)mempool_alloc(sizeof(struct btreelist_item));
                    btreeitem_new->chunkno = diffchunkno;
                    r = btree_init(
                            &btreeitem_new->btree, trie->btreeblk_handle, trie->btree_blk_ops, trie->btree_kv_ops, 
                            trie->btree_nodesize, trie->chunksize, trie->valuelen, 0x0, &meta);
                    //btreeitem->child_rootbid = btreeitem_new->btree.root_bid;
                    list_push_back(&btreelist, &btreeitem_new->e);
                    
                    chunk_new = key + diffchunkno * trie->chunksize;
                    r = btree_insert(&btreeitem_new->btree, chunk_new, value);
                    
                    chunk_new = dockey + diffchunkno * trie->chunksize;
                    r = btree_insert(&btreeitem_new->btree, chunk_new, btree_value);                    
                }

                // update previous (parent) b-tree
                bid_new = btreeitem->child_rootbid = btreeitem_new->btree.root_bid;
                // set MSB
                _hbtrie_set_msb(trie, &bid_new);
                r = btree_insert(&btreeitem->btree, chunk, &bid_new);

                break;

            }
            
        }
            
    }

    _hbtrie_btree_cascaded_update(trie, &btreelist, key);

    return ret_result;
}



