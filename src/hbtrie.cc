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

#include "hbtrie.h"
#include "list.h"
#include "btree.h"
#include "btree_kv.h"
#include "btree_fast_str_kv.h"
#include "internal_types.h"

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
    uint8_t rsize;
    size_t csize = trie->chunksize;

    nchunk = _get_nchunk_raw(trie, rawkey, rawkeylen);
    outkeylen = nchunk * csize;

    if (nchunk > 2) {
        // copy chunk[0] ~ chunk[nchunk-2]
        rsize = rawkeylen - ((nchunk - 2) * csize);
    } else {
        rsize = rawkeylen;
    }
    fdb_assert(rsize && rsize <= trie->chunksize, rsize, trie);
    memcpy((uint8_t*)outkey, (uint8_t*)rawkey, rawkeylen);

    if (rsize < csize) {
        // zero-fill rest space
        i = nchunk - 2;
        memset((uint8_t*)outkey + (i*csize) + rsize, 0x0, 2*csize - rsize);
    } else {
        // zero-fill the last chunk
        i = nchunk - 1;
        memset((uint8_t*)outkey + i * csize, 0x0, csize);
    }

    // assign rsize at the end of the outkey
    *((uint8_t*)outkey + outkeylen - 1) = rsize;

    return outkeylen;
}

// this function only returns (raw) key length
static int _hbtrie_reform_key_reverse(struct hbtrie *trie,
                                      void *key,
                                      int keylen)
{
    uint8_t rsize;
    rsize = *((uint8_t*)key + keylen - 1);
    fdb_assert(rsize, rsize, trie);

    if (rsize == trie->chunksize) {
        return keylen - trie->chunksize;
    } else {
        // rsize: 1 ~ chunksize-1
        return keylen - (trie->chunksize * 2) + rsize;
    }
}

#define _get_leaf_kv_ops btree_fast_str_kv_get_kb64_vb64
#define _get_leaf_key btree_fast_str_kv_get_key
#define _set_leaf_key btree_fast_str_kv_set_key
#define _set_leaf_inf_key btree_fast_str_kv_set_inf_key
#define _free_leaf_key btree_fast_str_kv_free_key

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
    trie->cmp_args.chunksize = chunksize;
    trie->cmp_args.aux = NULL;
    trie->aux = &trie->cmp_args;

    // assign key-value operations
    btree_kv_ops = (struct btree_kv_ops *)malloc(sizeof(struct btree_kv_ops));
    btree_leaf_kv_ops = (struct btree_kv_ops *)malloc(sizeof(struct btree_kv_ops));

    fdb_assert(valuelen == 8, valuelen, trie);
    fdb_assert(chunksize >= sizeof(void *), chunksize, trie);

    if (chunksize == 8 && valuelen == 8){
        btree_kv_ops = btree_kv_get_kb64_vb64(btree_kv_ops);
        btree_leaf_kv_ops = _get_leaf_kv_ops(btree_leaf_kv_ops);
    } else if (chunksize == 4 && valuelen == 8) {
        btree_kv_ops = btree_kv_get_kb32_vb64(btree_kv_ops);
        btree_leaf_kv_ops = _get_leaf_kv_ops(btree_leaf_kv_ops);
    } else {
        btree_kv_ops = btree_kv_get_kbn_vb64(btree_kv_ops);
        btree_leaf_kv_ops = _get_leaf_kv_ops(btree_leaf_kv_ops);
    }

    trie->btree_kv_ops = btree_kv_ops;
    trie->btree_leaf_kv_ops = btree_leaf_kv_ops;
    trie->readkey = readkey;
    trie->map = NULL;
    trie->last_map_chunk = (void *)malloc(chunksize);
    memset(trie->last_map_chunk, 0xff, chunksize); // set 0xffff...
}

void hbtrie_free(struct hbtrie *trie)
{
    free(trie->btree_kv_ops);
    free(trie->btree_leaf_kv_ops);
    free(trie->last_map_chunk);
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

void hbtrie_set_leaf_cmp(struct hbtrie *trie,
                         int (*cmp)(void *key1, void *key2, void* aux))
{
    trie->btree_leaf_kv_ops->cmp = cmp;
}

void hbtrie_set_map_function(struct hbtrie *trie,
                             hbtrie_cmp_map *map_func)
{
    trie->map = map_func;
}

// IMPORTANT: hbmeta doesn't have own allocated memory space (pointers only)
static void _hbtrie_fetch_meta(struct hbtrie *trie, int metasize,
                               struct hbtrie_meta *hbmeta, void *buf)
{
    // read hbmeta from buf
    int offset = 0;
    uint32_t valuelen = 0;

    memcpy(&hbmeta->chunkno, buf, sizeof(hbmeta->chunkno));
    hbmeta->chunkno = _endian_decode(hbmeta->chunkno);
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
/* << raw hbtrie meta structure >>
 * [Total meta length]: 2 bytes
 * [Chunk number]:      2 bytes
 * [Value length]:      1 bytes
 * [Value (optional)]:  x bytes
 * [Prefix (optional)]: y bytes
 */
static void _hbtrie_store_meta(struct hbtrie *trie,
                               metasize_t *metasize_out,
                               chunkno_t chunkno,
                               hbmeta_opt opt,
                               void *prefix,
                               int prefixlen,
                               void *value,
                               void *buf)
{
    chunkno_t _chunkno;

    // write hbmeta to buf
    *metasize_out = 0;

    if (opt == HBMETA_LEAF) {
        chunkno |= CHUNK_FLAG;
    }

    _chunkno = _endian_encode(chunkno);
    memcpy(buf, &_chunkno, sizeof(chunkno));
    *metasize_out += sizeof(chunkno);

    if (value) {
        memcpy((uint8_t*)buf + *metasize_out,
               &trie->valuelen, sizeof(trie->valuelen));
        *metasize_out += sizeof(trie->valuelen);
        memcpy((uint8_t*)buf + *metasize_out,
               value, trie->valuelen);
        *metasize_out += trie->valuelen;
    } else {
        memset((uint8_t*)buf + *metasize_out, 0x0, sizeof(trie->valuelen));
        *metasize_out += sizeof(trie->valuelen);
    }

    if (prefixlen > 0) {
        memcpy((uint8_t*)buf + *metasize_out, prefix, prefixlen);
        *metasize_out += prefixlen;
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

//3 ASSUMPTION: 'VALUE' should be based on same endian to hb+trie

#if defined(__ENDIAN_SAFE) || defined(_BIG_ENDIAN)
// endian safe option is turned on, OR,
// the architecture is based on big endian
INLINE void _hbtrie_set_msb(struct hbtrie *trie, void *value)
{
    *((uint8_t*)value) |= (uint8_t)0x80;
}
INLINE void _hbtrie_clear_msb(struct hbtrie *trie, void *value)
{
    *((uint8_t*)value) &= ~((uint8_t)0x80);
}
INLINE int _hbtrie_is_msb_set(struct hbtrie *trie, void *value)
{
    return *((uint8_t*)value) & ((uint8_t)0x80);
}
#else
// little endian
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
#endif

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

hbtrie_result hbtrie_iterator_init(struct hbtrie *trie,
                                   struct hbtrie_iterator *it,
                                   void *initial_key,
                                   size_t keylen)
{
    it->trie = *trie;

    // MUST NOT affect the original trie due to sharing the same memory segment
    it->trie.last_map_chunk = (void *)malloc(it->trie.chunksize);
    memset(it->trie.last_map_chunk, 0xff, it->trie.chunksize);

    it->curkey = (void *)malloc(HBTRIE_MAX_KEYLEN);

    if (initial_key) {
        it->keylen = _hbtrie_reform_key(trie, initial_key, keylen, it->curkey);
        fdb_assert(it->keylen < HBTRIE_MAX_KEYLEN, it->keylen, trie);
        memset((uint8_t*)it->curkey + it->keylen, 0, trie->chunksize);
    }else{
        it->keylen = 0;
        memset(it->curkey, 0, trie->chunksize);
    }
    list_init(&it->btreeit_list);
    it->flags = 0;

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
    free(it->trie.last_map_chunk);
    if (it->curkey) free(it->curkey);
    return HBTRIE_RESULT_SUCCESS;
}

// move iterator's cursor to the end of the key range.
// hbtrie_prev() call after hbtrie_last() will return the last key.
hbtrie_result hbtrie_last(struct hbtrie_iterator *it)
{
    struct hbtrie_iterator temp;

    temp = *it;
    hbtrie_iterator_free(it);

    it->trie = temp.trie;
    // MUST NOT affect the original trie due to sharing the same memory segment
    it->trie.last_map_chunk = (void *)malloc(it->trie.chunksize);
    memset(it->trie.last_map_chunk, 0xff, it->trie.chunksize);

    it->curkey = (void *)malloc(HBTRIE_MAX_KEYLEN);
    // init with the infinite (0xff..) key without reforming
    memset(it->curkey, 0xff, it->trie.chunksize);
    it->keylen = it->trie.chunksize;

    list_init(&it->btreeit_list);
    it->flags = 0;

    return HBTRIE_RESULT_SUCCESS;
}

// recursive function
#define HBTRIE_PREFIX_MATCH_ONLY (0x1)
#define HBTRIE_PARTIAL_MATCH (0x2)
static hbtrie_result _hbtrie_prev(struct hbtrie_iterator *it,
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
            &btree, trie->btreeblk_handle, trie->btree_blk_ops,
            trie->btree_kv_ops,
            trie->btree_nodesize, trie->root_bid);
        btree.aux = trie->aux;

        item = (struct btreeit_item *)mempool_alloc(sizeof(
                                                    struct btreeit_item));
        item->chunkno = 0;
        item->leaf = 0;

        br = btree_iterator_init(&btree, &item->btree_it, chunk);
        if (br == BTREE_RESULT_FAIL) return HBTRIE_RESULT_FAIL;

        list_push_back(&it->btreeit_list, &item->le);
    }

    e = list_next(&item->le);
    if (e) {
        // if prev sub b-tree exists
        item_new = _get_entry(e, struct btreeit_item, le);
        hr = _hbtrie_prev(it, item_new, key_buf, keylen, value_buf, flag);
        if (hr == HBTRIE_RESULT_SUCCESS) return hr;
        it->keylen = (item->chunkno+1) * trie->chunksize;
    }

    while (hr == HBTRIE_RESULT_FAIL) {
        // get key-value from current b-tree iterator
        memset(k, 0, trie->chunksize);
        br = btree_prev(&item->btree_it, k, v);
        if (item->leaf) {
            _free_leaf_key(k);
        } else {
            chunk = (uint8_t*)it->curkey + item->chunkno * trie->chunksize;
            if (item->btree_it.btree.kv_ops->cmp(k, chunk,
                    item->btree_it.btree.aux) != 0) {
                // not exact match key .. the rest of string is not necessary anymore
                it->keylen = (item->chunkno+1) * trie->chunksize;
                HBTRIE_ITR_SET_MOVED(it);
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
            bid = _endian_decode(bid);
            btree_init_from_bid(&btree, trie->btreeblk_handle,
                                trie->btree_blk_ops, trie->btree_kv_ops,
                                trie->btree_nodesize, bid);

            // get sub b-tree's chunk number
            bmeta.data = (void *)mempool_alloc(trie->btree_nodesize);
            bmeta.size = btree_read_meta(&btree, bmeta.data);
            _hbtrie_fetch_meta(trie, bmeta.size, &hbmeta, bmeta.data);

            item_new = (struct btreeit_item *)
                       mempool_alloc(sizeof(struct btreeit_item));
            if (_is_leaf_btree(hbmeta.chunkno)) {
                void *void_cmp;

                if (trie->map) { // custom cmp functions exist
                    if (!memcmp(trie->last_map_chunk, it->curkey, trie->chunksize)) {
                        // same custom function was used in the last call ..
                        // do nothing
                    } else {
                        // get cmp function corresponding to the key
                        void_cmp = trie->map(it->curkey, (void *)trie);
                        if (void_cmp) {
                            memcpy(trie->last_map_chunk, it->curkey, trie->chunksize);
                            // set aux for _fdb_custom_cmp_wrap()
                            trie->cmp_args.aux = void_cmp;
                            trie->aux = &trie->cmp_args;
                        }
                    }
                }

                btree.kv_ops = trie->btree_leaf_kv_ops;
                item_new->leaf = 1;
            } else {
                item_new->leaf = 0;
            }
            btree.aux = trie->aux;
            hbmeta.chunkno = _get_chunkno(hbmeta.chunkno);
            item_new->chunkno = hbmeta.chunkno;

            // Note: if user's key is exactly aligned to chunk size, then the
            //       dummy chunk will be a zero-filled value, and it is used
            //       as a key in the next level of B+tree. Hence, there will be
            //       no problem to assign the dummy chunk to the 'chunk' variable.
            if ( (item_new->chunkno+1) * trie->chunksize <= it->keylen) {
                // happen only once for the first call (for each level of b-trees)
                chunk = (uint8_t*)it->curkey +
                        item_new->chunkno*trie->chunksize;
                if (item->chunkno+1 < item_new->chunkno) {
                    // skipped prefix exists
                    // Note: all skipped chunks should be compared using the default
                    //       cmp function
                    int i, offset_meta, offset_key, chunkcmp;
                    for (i=item->chunkno+1; i<item_new->chunkno; ++i) {
                        offset_meta = trie->chunksize * (i - (item->chunkno+1));
                        offset_key = trie->chunksize * i;
                        chunkcmp = trie->btree_kv_ops->cmp(
                            (uint8_t*)it->curkey + offset_key,
                            (uint8_t*)hbmeta.prefix + offset_meta,
                            trie->aux);
                        if (chunkcmp < 0) {
                            // start_key's prefix is smaller than the skipped prefix
                            // we have to go back to parent B+tree and pick prev entry
                            mempool_free(bmeta.data);
                            mempool_free(item_new);
                            it->keylen = offset_key;
                            hr = HBTRIE_RESULT_FAIL;
                            HBTRIE_ITR_SET_MOVED(it);
                            break;
                        } else if (chunkcmp > 0) {
                            // start_key's prefix is gerater than the skipped prefix
                            // set largest key for next B+tree
                            chunk = alca(uint8_t, trie->chunksize);
                            memset(chunk, 0xff, trie->chunksize);
                            break;
                        }
                    }
                    if (chunkcmp < 0) {
                        // go back to parent B+tree
                        continue;
                    }
                }

            } else {
                // chunk number of the b-tree is shorter than current iterator's key
                if (!HBTRIE_ITR_IS_MOVED(it)) {
                    // The first prev call right after iterator init call.
                    // This means that the init key is smaller than
                    // the smallest key of the current tree, and larger than
                    // the largest key of the previous tree.
                    // So we have to go back to the parent tree, and
                    // return the largest key of the previous tree.
                    mempool_free(bmeta.data);
                    mempool_free(item_new);
                    it->keylen = (item->chunkno+1) * trie->chunksize;
                    HBTRIE_ITR_SET_MOVED(it);
                    continue;
                }
                // set largest key
                chunk = alca(uint8_t, trie->chunksize);
                memset(chunk, 0xff, trie->chunksize);
            }

            if (item_new->leaf && chunk) {
                uint8_t *k_temp = alca(uint8_t, trie->chunksize);
                size_t _leaf_keylen, _leaf_keylen_raw = 0;

                _leaf_keylen = it->keylen - (item_new->chunkno * trie->chunksize);
                if (_leaf_keylen) {
                    _leaf_keylen_raw = _hbtrie_reform_key_reverse(
                                           trie, chunk, _leaf_keylen);
                    _set_leaf_key(k_temp, chunk, _leaf_keylen_raw);
                    if (_leaf_keylen_raw) {
                        btree_iterator_init(&btree, &item_new->btree_it, k_temp);
                    } else {
                        btree_iterator_init(&btree, &item_new->btree_it, NULL);
                    }
                } else {
                    // set initial key as the largest key
                    // for reverse scan from the end of the B+tree
                    _set_leaf_inf_key(k_temp);
                    btree_iterator_init(&btree, &item_new->btree_it, k_temp);
                }
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
                    it->keylen = _hbtrie_reform_key(trie, key_buf, *keylen,
                                                    it->curkey);
                }
                memcpy(value_buf, &offset, trie->valuelen);
                hr = HBTRIE_RESULT_SUCCESS;
            } else {
                hr = _hbtrie_prev(it, item_new, key_buf, keylen, value_buf,
                                  flag);
            }
            mempool_free(bmeta.data);
            if (hr == HBTRIE_RESULT_SUCCESS)
                return hr;

            // fail searching .. get back to parent tree
            // (this happens when the initial key is smaller than
            // the smallest key in the current tree (ITEM_NEW) ..
            // so return back to ITEM and retrieve next child)
            it->keylen = (item->chunkno+1) * trie->chunksize;
            HBTRIE_ITR_SET_MOVED(it);

        } else {
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

hbtrie_result hbtrie_prev(struct hbtrie_iterator *it,
                          void *key_buf,
                          size_t *keylen,
                          void *value_buf)
{
    hbtrie_result hr;

    if (HBTRIE_ITR_IS_REV(it) && HBTRIE_ITR_IS_FAILED(it)) {
        return HBTRIE_RESULT_FAIL;
    }

    struct list_elem *e = list_begin(&it->btreeit_list);
    struct btreeit_item *item = NULL;
    if (e) item = _get_entry(e, struct btreeit_item, le);

    hr = _hbtrie_prev(it, item, key_buf, keylen, value_buf, 0x0);
    HBTRIE_ITR_SET_REV(it);
    if (hr == HBTRIE_RESULT_SUCCESS) {
        HBTRIE_ITR_CLR_FAILED(it);
        HBTRIE_ITR_SET_MOVED(it);
    } else {
        HBTRIE_ITR_SET_FAILED(it);
    }
    return hr;
}

// recursive function
static hbtrie_result _hbtrie_next(struct hbtrie_iterator *it,
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
        btree.aux = trie->aux;

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
            if (item->btree_it.btree.kv_ops->cmp(k, chunk,
                    item->btree_it.btree.aux) != 0) {
                // not exact match key .. the rest of string is not necessary anymore
                it->keylen = (item->chunkno+1) * trie->chunksize;
                HBTRIE_ITR_SET_MOVED(it);
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
            bid = _endian_decode(bid);
            btree_init_from_bid(&btree, trie->btreeblk_handle,
                                trie->btree_blk_ops, trie->btree_kv_ops,
                                trie->btree_nodesize, bid);

            // get sub b-tree's chunk number
            bmeta.data = (void *)mempool_alloc(trie->btree_nodesize);
            bmeta.size = btree_read_meta(&btree, bmeta.data);
            _hbtrie_fetch_meta(trie, bmeta.size, &hbmeta, bmeta.data);

            item_new = (struct btreeit_item *)
                       mempool_alloc(sizeof(struct btreeit_item));
            if (_is_leaf_btree(hbmeta.chunkno)) {
                void *void_cmp;

                if (trie->map) { // custom cmp functions exist
                    if (!memcmp(trie->last_map_chunk, it->curkey, trie->chunksize)) {
                        // same custom function was used in the last call ..
                        // do nothing
                    } else {
                        // get cmp function corresponding to the key
                        void_cmp = trie->map(it->curkey, (void *)trie);
                        if (void_cmp) {
                            memcpy(trie->last_map_chunk, it->curkey, trie->chunksize);
                            // set aux for _fdb_custom_cmp_wrap()
                            trie->cmp_args.aux = void_cmp;
                            trie->aux = &trie->cmp_args;
                        }
                    }
                }

                btree.kv_ops = trie->btree_leaf_kv_ops;
                item_new->leaf = 1;
            } else {
                item_new->leaf = 0;
            }
            btree.aux = trie->aux;
            hbmeta.chunkno = _get_chunkno(hbmeta.chunkno);
            item_new->chunkno = hbmeta.chunkno;

            // Note: if user's key is exactly aligned to chunk size, then the
            //       dummy chunk will be a zero-filled value, and it is used
            //       as a key in the next level of B+tree. Hence, there will be
            //       no problem to assign the dummy chunk to the 'chunk' variable.
            if ( (item_new->chunkno+1) * trie->chunksize <= it->keylen) {
                // happen only once for the first call (for each level of b-trees)
                chunk = (uint8_t*)it->curkey +
                        item_new->chunkno*trie->chunksize;
                if (item->chunkno+1 < item_new->chunkno) {
                    // skipped prefix exists
                    // Note: all skipped chunks should be compared using the default
                    //       cmp function
                    int i, offset_meta, offset_key, chunkcmp;
                    for (i=item->chunkno+1; i<item_new->chunkno; ++i) {
                        offset_meta = trie->chunksize * (i - (item->chunkno+1));
                        offset_key = trie->chunksize * i;
                        chunkcmp = trie->btree_kv_ops->cmp(
                            (uint8_t*)it->curkey + offset_key,
                            (uint8_t*)hbmeta.prefix + offset_meta,
                            trie->aux);
                        if (chunkcmp < 0) {
                            // start_key's prefix is smaller than the skipped prefix
                            // set smallest key for next B+tree
                            it->keylen = offset_key;
                            chunk = NULL;
                            break;
                        } else if (chunkcmp > 0) {
                            // start_key's prefix is gerater than the skipped prefix
                            // we have to go back to parent B+tree and pick next entry
                            mempool_free(bmeta.data);
                            mempool_free(item_new);
                            it->keylen = offset_key;
                            hr = HBTRIE_RESULT_FAIL;
                            HBTRIE_ITR_SET_MOVED(it);
                            break;
                        }
                    }
                    if (chunkcmp > 0) {
                        // go back to parent B+tree
                        continue;
                    }
                }
            }else{
                // chunk number of the b-tree is longer than current iterator's key
                // set smallest key
                chunk = NULL;
            }

            if (item_new->leaf && chunk) {
                uint8_t *k_temp = alca(uint8_t, trie->chunksize);
                size_t _leaf_keylen, _leaf_keylen_raw = 0;

                _leaf_keylen = it->keylen - (item_new->chunkno * trie->chunksize);
                if (_leaf_keylen > 0) {
                    _leaf_keylen_raw = _hbtrie_reform_key_reverse(
                                           trie, chunk, _leaf_keylen);
                }
                if (_leaf_keylen_raw) {
                    _set_leaf_key(k_temp, chunk, _leaf_keylen_raw);
                    btree_iterator_init(&btree, &item_new->btree_it, k_temp);
                    _free_leaf_key(k_temp);
                } else {
                    btree_iterator_init(&btree, &item_new->btree_it, NULL);
                }
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

    if (HBTRIE_ITR_IS_FWD(it) && HBTRIE_ITR_IS_FAILED(it)) {
        return HBTRIE_RESULT_FAIL;
    }

    struct list_elem *e = list_begin(&it->btreeit_list);
    struct btreeit_item *item = NULL;
    if (e) item = _get_entry(e, struct btreeit_item, le);

    hr = _hbtrie_next(it, item, key_buf, keylen, value_buf, 0x0);
    HBTRIE_ITR_SET_FWD(it);
    if (hr == HBTRIE_RESULT_SUCCESS) {
        HBTRIE_ITR_CLR_FAILED(it);
        HBTRIE_ITR_SET_MOVED(it);
    } else {
        HBTRIE_ITR_SET_FAILED(it);
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

static void _hbtrie_free_btreelist(struct list *btreelist)
{
    struct btreelist_item *btreeitem;
    struct list_elem *e;

    // free all items on list
    e = list_begin(btreelist);
    while(e) {
        btreeitem = _get_entry(e, struct btreelist_item, e);
        e = list_remove(btreelist, e);
        mempool_free(btreeitem);
    }
}

static void _hbtrie_btree_cascaded_update(struct hbtrie *trie,
                                          struct list *btreelist,
                                          void *key,
                                          int free_opt)
{
    bid_t bid_new, _bid;
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
            // root node of child sub-tree has been moved to another block
            // update parent sub-tree
            bid_new = btreeitem_child->btree.root_bid;
            _bid = _endian_encode(bid_new);
            _hbtrie_set_msb(trie, (void *)&_bid);
            btree_insert(&btreeitem->btree,
                    (uint8_t*)key + btreeitem->chunkno * trie->chunksize,
                    (void *)&_bid);
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
        fdb_assert(0, trie, e_child);
    }

    if (free_opt) {
        _hbtrie_free_btreelist(btreelist);
    }
}

static hbtrie_result _hbtrie_find(struct hbtrie *trie, void *key, int keylen,
                                  void *valuebuf, struct list *btreelist, uint8_t flag)
{
    int nchunk;
    int rawkeylen;
    int prevchunkno, curchunkno, cpt_node = 0;
    struct btree *btree = NULL;
    struct btree btree_static;
    btree_result r;
    struct hbtrie_meta hbmeta;
    struct btree_meta meta;
    struct btreelist_item *btreeitem = NULL;
    uint8_t *k = alca(uint8_t, trie->chunksize);
    uint8_t *buf = alca(uint8_t, trie->btree_nodesize);
    uint8_t *btree_value = alca(uint8_t, trie->valuelen);
    void *chunk = NULL;
    void *void_cmp;
    bid_t bid_new;
    nchunk = _get_nchunk(trie, key, keylen);

    meta.data = buf;
    curchunkno = 0;

    if (trie->map) { // custom cmp functions exist
        if (!memcmp(trie->last_map_chunk, key, trie->chunksize)) {
            // same custom function was used in the last call .. do nothing
        } else {
            // get cmp function corresponding to the key
            void_cmp = trie->map(key, (void *)trie);
            if (void_cmp) { // custom cmp function matches .. turn on leaf b+tree mode
                memcpy(trie->last_map_chunk, key, trie->chunksize);
                // set aux for _fdb_custom_cmp_wrap()
                trie->cmp_args.aux = void_cmp;
                trie->aux = &trie->cmp_args;
            }
        }
    }

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
        if (r != BTREE_RESULT_SUCCESS) {
            return HBTRIE_RESULT_FAIL;
        }
        btree->aux = trie->aux;
        fdb_assert(btree->ksize == trie->chunksize &&
                   btree->vsize == trie->valuelen,
                   btree->ksize, btree->vsize);
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
            fdb_assert(hbmeta.prefix != NULL, hbmeta.prefix, trie);
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
            // same chunk exists
            if (flag & HBTRIE_PARTIAL_MATCH &&
                curchunkno + 1 == nchunk - 1) {
                // partial match mode & the last meaningful chunk
                // return btree value
                memcpy(valuebuf, btree_value, trie->valuelen);
                return HBTRIE_RESULT_SUCCESS;
            }

            // check whether the value points to sub-tree or document
            // check MSB
            if (_hbtrie_is_msb_set(trie, btree_value)) {
                // this is BID of b-tree node (by clearing MSB)
                _hbtrie_clear_msb(trie, btree_value);
                bid_new = trie->btree_kv_ops->value2bid(btree_value);
                bid_new = _endian_decode(bid_new);

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
                if (r != BTREE_RESULT_SUCCESS) {
                    return HBTRIE_RESULT_FAIL;
                }
                btree->aux = trie->aux;
            } else {
                // this is offset of document (as it is)
                // read entire key
                uint8_t *docrawkey = alca(uint8_t, HBTRIE_MAX_KEYLEN);
                uint8_t *dockey = alca(uint8_t, HBTRIE_MAX_KEYLEN);
                uint32_t docrawkeylen, dockeylen;
                uint64_t offset;
                int docnchunk, diffchunkno;

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

hbtrie_result hbtrie_find_partial(struct hbtrie *trie, void *rawkey,
                                  int rawkeylen, void *valuebuf)
{
    int nchunk = _get_nchunk_raw(trie, rawkey, rawkeylen);
    uint8_t *key = alca(uint8_t, nchunk * trie->chunksize);
    int keylen;

    keylen = _hbtrie_reform_key(trie, rawkey, rawkeylen, key);
    return _hbtrie_find(trie, key, keylen, valuebuf, NULL,
                        HBTRIE_PARTIAL_MATCH);
}

INLINE hbtrie_result _hbtrie_remove(struct hbtrie *trie,
                                    void *rawkey, int rawkeylen,
                                    uint8_t flag)
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

    r = _hbtrie_find(trie, key, keylen, valuebuf, &btreelist, flag);

    if (r == HBTRIE_RESULT_SUCCESS) {
        e = list_end(&btreelist);
        fdb_assert(e, trie, flag);

        btreeitem = _get_entry(e, struct btreelist_item, e);
        if ( (btreeitem->leaf && rawkeylen ==
                 btreeitem->chunkno * trie->chunksize) ||
             (!(btreeitem->leaf) && nchunk == btreeitem->chunkno) ) {
            // key is exactly same as b-tree's prefix .. remove from metasection
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
                br = btree_remove(&btreeitem->btree,
                                  key + trie->chunksize * btreeitem->chunkno);
            }
            //assert(br != BTREE_RESULT_FAIL);
            if (br == BTREE_RESULT_FAIL) r = HBTRIE_RESULT_FAIL;
        }
        _hbtrie_btree_cascaded_update(trie, &btreelist, key, 1);
    } else {
        // key (to be removed) not found
        // no update occurred .. we don't need to update b-trees on the path
        // just free the btreelist
        _hbtrie_free_btreelist(&btreelist);
    }

    return r;
}

hbtrie_result hbtrie_remove(struct hbtrie *trie,
                            void *rawkey,
                            int rawkeylen)
{
    return _hbtrie_remove(trie, rawkey, rawkeylen, 0x0);
}

hbtrie_result hbtrie_remove_partial(struct hbtrie *trie,
                                    void *rawkey,
                                    int rawkeylen)
{
    return _hbtrie_remove(trie, rawkey, rawkeylen,
                          HBTRIE_PARTIAL_MATCH);
}

struct _key_item {
    size_t keylen;
    void *key;
    void *value;
    struct list_elem le;
};

static void _hbtrie_extend_leaf_tree(struct hbtrie *trie,
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
    size_t keylen, minchunkno = 0, chunksize;

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
    new_btree.aux = trie->aux;

    // reset BTREEITEM
    btreeitem->btree = new_btree;
    btreeitem->chunkno = _get_chunkno(hbmeta.chunkno) + minchunkno;
    btreeitem->leaf = 0;

    _hbtrie_btree_cascaded_update(trie, btreelist, pre_str, 1);

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

// suppose that VALUE and OLDVALUE_OUT are based on the same endian in hb+trie
#define HBTRIE_PARTIAL_UPDATE (0x1)
INLINE hbtrie_result _hbtrie_insert(struct hbtrie *trie,
                                    void *rawkey, int rawkeylen,
                                    void *value, void *oldvalue_out,
                                    uint8_t flag)
{
    /*
    <insertion cases>
    1. normal insert: there is no creation of new b-tree
    2. replacing doc by new b-tree: a doc (which has same prefix) already exists
        2-1. a new b-tree that has file offset to a doc in its metadata
             is created, and the other doc is inserted into the tree
        2-2. two docs are inserted into the new b-tree
    3. create new b-tree between existing b-trees: when prefix mismatches
    */

    int nchunk;
    int keylen;
    int prevchunkno, curchunkno;
    int cpt_node = 0;
    int leaf_cond = 0;
    uint8_t *k = alca(uint8_t, trie->chunksize);

    struct list btreelist;
    //struct btree btree, btree_new;
    struct btreelist_item *btreeitem, *btreeitem_new;
    hbtrie_result ret_result = HBTRIE_RESULT_SUCCESS;
    btree_result r;
    struct btree_kv_ops *kv_ops;

    struct hbtrie_meta hbmeta;
    struct btree_meta meta;
    hbmeta_opt opt;
    void *void_cmp;

    nchunk = _get_nchunk_raw(trie, rawkey, rawkeylen);

    uint8_t *key = alca(uint8_t, nchunk * trie->chunksize);
    uint8_t *buf = alca(uint8_t, trie->btree_nodesize);
    uint8_t *btree_value = alca(uint8_t, trie->valuelen);
    void *chunk, *chunk_new;
    bid_t bid_new, _bid;

    meta.data = buf;
    curchunkno = 0;
    keylen = _hbtrie_reform_key(trie, rawkey, rawkeylen, key);
    (void)keylen;

    if (trie->map) { // custom cmp functions exist
        if (!memcmp(trie->last_map_chunk, key, trie->chunksize)) {
            // same custom function was used in the last call .. leaf b+tree
            leaf_cond = 1;
        } else {
            // get cmp function corresponding to the key
            void_cmp = trie->map(key, (void *)trie);
            if (void_cmp) {
                // custom cmp function matches .. turn on leaf b+tree mode
                leaf_cond = 1;
                memcpy(trie->last_map_chunk, key, trie->chunksize);
                // set aux for _fdb_custom_cmp_wrap()
                trie->cmp_args.aux = void_cmp;
                trie->aux = &trie->cmp_args;
            }
        }
    }

    list_init(&btreelist);
    // btreeitem for root btree
    btreeitem = (struct btreelist_item*)
                mempool_alloc(sizeof(struct btreelist_item));
    list_push_back(&btreelist, &btreeitem->e);

    if (trie->root_bid == BLK_NOT_FOUND) {
        // create root b-tree
        _hbtrie_store_meta(trie, &meta.size, 0, HBMETA_NORMAL,
                           NULL, 0, NULL, buf);
        r = btree_init(&btreeitem->btree, trie->btreeblk_handle,
                       trie->btree_blk_ops, trie->btree_kv_ops,
                       trie->btree_nodesize, trie->chunksize,
                       trie->valuelen, 0x0, &meta);
        if (r != BTREE_RESULT_SUCCESS) {
            return HBTRIE_RESULT_FAIL;
        }
    } else {
        // read from root_bid
        r = btree_init_from_bid(&btreeitem->btree, trie->btreeblk_handle,
                                trie->btree_blk_ops, trie->btree_kv_ops,
                                trie->btree_nodesize, trie->root_bid);
        if (r != BTREE_RESULT_SUCCESS) {
            return HBTRIE_RESULT_FAIL;
        }
    }
    btreeitem->btree.aux = trie->aux;

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
            int diffchunkno = _hbtrie_find_diff_chunk(trie, hbmeta.prefix,
                                  key + trie->chunksize * (prevchunkno+1),
                                  0, curchunkno - (prevchunkno+1));
            if (diffchunkno < curchunkno - (prevchunkno+1)) {
                //3 3. create sub-tree between parent and child tree

                // metadata (prefix) update in btreeitem->btree
                int new_prefixlen = trie->chunksize *
                                    (curchunkno - (prevchunkno+1) -
                                        (diffchunkno+1));
                // backup old prefix
                int old_prefixlen = hbmeta.prefix_len;
                uint8_t *old_prefix = alca(uint8_t, old_prefixlen);
                memcpy(old_prefix, hbmeta.prefix, old_prefixlen);

                if (new_prefixlen > 0) {
                    uint8_t *new_prefix = alca(uint8_t, new_prefixlen);
                    memcpy(new_prefix,
                           (uint8_t*)hbmeta.prefix +
                               trie->chunksize * (diffchunkno + 1),
                           new_prefixlen);
                    _hbtrie_store_meta(trie, &meta.size, curchunkno,
                                       HBMETA_NORMAL, new_prefix,
                                       new_prefixlen, hbmeta.value, buf);
                } else {
                    _hbtrie_store_meta(trie, &meta.size, curchunkno,
                                       HBMETA_NORMAL, NULL, 0,
                                       hbmeta.value, buf);
                }
                // update metadata for old b-tree
                btree_update_meta(&btreeitem->btree, &meta);

                // split prefix and create new sub-tree
                _hbtrie_store_meta(trie, &meta.size,
                                   prevchunkno + diffchunkno + 1,
                                   HBMETA_NORMAL, old_prefix,
                                   diffchunkno * trie->chunksize, NULL, buf);

                // create new b-tree
                btreeitem_new = (struct btreelist_item *)
                                mempool_alloc(sizeof(struct btreelist_item));
                btreeitem_new->chunkno = prevchunkno + diffchunkno + 1;
                r = btree_init(&btreeitem_new->btree, trie->btreeblk_handle,
                               trie->btree_blk_ops, trie->btree_kv_ops,
                               trie->btree_nodesize, trie->chunksize,
                               trie->valuelen, 0x0, &meta);
                if (r != BTREE_RESULT_SUCCESS) {
                    return HBTRIE_RESULT_FAIL;
                }
                btreeitem_new->btree.aux = trie->aux;
                list_insert_before(&btreelist, &btreeitem->e,
                                   &btreeitem_new->e);

                // insert chunk for 'key'
                chunk_new = key + (prevchunkno + diffchunkno + 1) *
                                  trie->chunksize;
                r = btree_insert(&btreeitem_new->btree, chunk_new, value);
                if (r == BTREE_RESULT_FAIL) {
                    return HBTRIE_RESULT_FAIL;
                }
                // insert chunk for existing btree
                chunk_new = (uint8_t*)old_prefix + diffchunkno *
                                                   trie->chunksize;
                bid_new = btreeitem->btree.root_bid;
                btreeitem_new->child_rootbid = bid_new;
                // set MSB
                _bid = _endian_encode(bid_new);
                _hbtrie_set_msb(trie, (void*)&_bid);
                r = btree_insert(&btreeitem_new->btree,
                                 chunk_new, (void*)&_bid);
                if (r == BTREE_RESULT_FAIL) {
                    return HBTRIE_RESULT_FAIL;
                }

                break;
            }
        }

        //3 search b-tree using current chunk
        if ((cpt_node && rawkeylen == curchunkno * trie->chunksize) ||
            (!cpt_node && nchunk == curchunkno)) {
            // KEY is exactly same as tree's prefix .. insert into metasection
            _hbtrie_store_meta(trie, &meta.size, curchunkno,
                               (cpt_node)?(HBMETA_LEAF):(HBMETA_NORMAL),
                               hbmeta.prefix,
                               (curchunkno-prevchunkno - 1) * trie->chunksize,
                               value, buf);
            btree_update_meta(&btreeitem->btree, &meta);
            break;
        } else {
            chunk = key + curchunkno*trie->chunksize;
            if (cpt_node) {
                // leaf b-tree
                _set_leaf_key(k, chunk,
                              rawkeylen - curchunkno*trie->chunksize);
                r = btree_find(&btreeitem->btree, k, btree_value);
                _free_leaf_key(k);
            } else {
                r = btree_find(&btreeitem->btree, chunk, btree_value);
            }
        }

        if (r == BTREE_RESULT_FAIL) {
            //3 1. normal insert: same chunk does not exist -> just insert
            if (flag & HBTRIE_PARTIAL_UPDATE) {
                // partial update doesn't allow inserting a new key
                ret_result = HBTRIE_RESULT_FAIL;
                break; // while loop
            }

            if (cpt_node) {
                // leaf b-tree
                _set_leaf_key(k, chunk,
                              rawkeylen - curchunkno*trie->chunksize);
                r = btree_insert(&btreeitem->btree, k, value);
                if (r == BTREE_RESULT_FAIL) {
                    _free_leaf_key(k);
                    ret_result = HBTRIE_RESULT_FAIL;
                    break; // while loop
                }
                _free_leaf_key(k);

                if (btreeitem->btree.height > trie->leaf_height_limit) {
                    // height growth .. extend!
                    _hbtrie_extend_leaf_tree(trie, &btreelist, btreeitem,
                        key, curchunkno * trie->chunksize);
                    return ret_result;
                }
            } else {
                r = btree_insert(&btreeitem->btree, chunk, value);
                if (r == BTREE_RESULT_FAIL) {
                    ret_result = HBTRIE_RESULT_FAIL;
                }
            }
            break; // while loop
        }

        // same chunk already exists
        if (flag & HBTRIE_PARTIAL_UPDATE &&
            curchunkno + 1 == nchunk - 1) {
            // partial update mode & the last meaningful chunk
            // update the local btree value
            if (oldvalue_out) {
                memcpy(oldvalue_out, btree_value, trie->valuelen);
            }
            // assume that always normal b-tree
            r = btree_insert(&btreeitem->btree, chunk, value);
            if (r == BTREE_RESULT_FAIL) {
                ret_result = HBTRIE_RESULT_FAIL;
            } else {
                ret_result = HBTRIE_RESULT_UPDATE;
            }
            break;
        }

        // check whether the value points to sub-tree or document
        // check MSB
        if (_hbtrie_is_msb_set(trie, btree_value)) {
            // this is BID of b-tree node (by clearing MSB)
            _hbtrie_clear_msb(trie, btree_value);
            bid_new = trie->btree_kv_ops->value2bid(btree_value);
            bid_new = _endian_decode(bid_new);
            btreeitem->child_rootbid = bid_new;
            //3 traverse to the sub-tree
            // fetch sub-tree
            btreeitem = (struct btreelist_item*)
                        mempool_alloc(sizeof(struct btreelist_item));

            r = btree_init_from_bid(&btreeitem->btree,
                                    trie->btreeblk_handle,
                                    trie->btree_blk_ops,
                                    trie->btree_kv_ops,
                                    trie->btree_nodesize, bid_new);
            if (r == BTREE_RESULT_FAIL) {
                ret_result = HBTRIE_RESULT_FAIL;
            }
            btreeitem->btree.aux = trie->aux;
            list_push_back(&btreelist, &btreeitem->e);
            continue;
        }

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

        if (trie->flag & HBTRIE_FLAG_COMPACT || leaf_cond) {
            // optimization mode
            // Note: custom cmp function doesn't support key
            //       longer than a block size.
            newchunkno = curchunkno+1;
            minchunkno = MIN(_l2c(trie, rawkeylen), _l2c(trie, docrawkeylen));
            minrawkeylen = MIN(rawkeylen, docrawkeylen);
            diffchunkno = _hbtrie_find_diff_chunk(trie, rawkey, docrawkey,
                curchunkno, minchunkno -
                            ((minrawkeylen%trie->chunksize == 0)?(0):(1)));
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
                _hbtrie_find_diff_chunk(trie, key, dockey,
                                        curchunkno, minchunkno);
            opt = HBMETA_NORMAL;
            kv_ops = trie->btree_kv_ops;
        }

        // one key is substring of the other key
        if (minchunkno == diffchunkno && docnchunk == nchunk) {
            //3 same key!! .. update the value
            if (oldvalue_out) {
                memcpy(oldvalue_out, btree_value, trie->valuelen);
            }
            if (cpt_node) {
                // leaf b-tree
                _set_leaf_key(k, chunk,
                              rawkeylen - curchunkno*trie->chunksize);
                r = btree_insert(&btreeitem->btree, k, value);
                _free_leaf_key(k);
            } else {
                // normal b-tree
                r = btree_insert(&btreeitem->btree, chunk, value);
            }
            if (r == BTREE_RESULT_FAIL) {
                ret_result = HBTRIE_RESULT_FAIL;
            } else {
                ret_result = HBTRIE_RESULT_UPDATE;
            }
            break;
        }

        // different key
        while (trie->btree_nodesize > HBTRIE_HEADROOM &&
               (newchunkno - curchunkno) * trie->chunksize >
                   trie->btree_nodesize - HBTRIE_HEADROOM) {
            // prefix is too long .. we have to split it
            fdb_assert(opt == HBMETA_NORMAL, opt, trie);
            int midchunkno;
            midchunkno = curchunkno +
                        (trie->btree_nodesize - HBTRIE_HEADROOM) /
                            trie->chunksize;
            _hbtrie_store_meta(trie, &meta.size, midchunkno, opt,
                               key + trie->chunksize * (curchunkno+1),
                               (midchunkno - (curchunkno+1)) *
                                   trie->chunksize,
                               NULL, buf);

            btreeitem_new = (struct btreelist_item *)
                            mempool_alloc(sizeof(struct btreelist_item));
            btreeitem_new->chunkno = midchunkno;
            r = btree_init(&btreeitem_new->btree,
                           trie->btreeblk_handle,
                           trie->btree_blk_ops, kv_ops,
                           trie->btree_nodesize, trie->chunksize,
                           trie->valuelen, 0x0, &meta);
            if (r == BTREE_RESULT_FAIL) {
                return HBTRIE_RESULT_FAIL;
            }
            btreeitem_new->btree.aux = trie->aux;
            btreeitem_new->child_rootbid = BLK_NOT_FOUND;
            list_push_back(&btreelist, &btreeitem_new->e);

            // insert new btree's bid into the previous btree
            bid_new = btreeitem_new->btree.root_bid;
            btreeitem->child_rootbid = bid_new;
            _bid = _endian_encode(bid_new);
            _hbtrie_set_msb(trie, (void *)&_bid);
            r = btree_insert(&btreeitem->btree, chunk, &_bid);
            if (r == BTREE_RESULT_FAIL) {
                ret_result = HBTRIE_RESULT_FAIL;
                break;
            }

            // switch & go to the next tree
            chunk = (uint8_t*)key +
                    midchunkno * trie->chunksize;
            curchunkno = midchunkno;
            btreeitem = btreeitem_new;
        }
        if (ret_result == HBTRIE_RESULT_FAIL) {
            break;
        }

        if (minchunkno == diffchunkno && minchunkno == newchunkno) {
            //3 2-1. create sub-tree
            // that containing file offset of one doc (sub-string)
            // in its meta section, and insert the other doc
            // (super-string) into the tree

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
            } else {
                // key is substring of dockey
                key_short = key;
                value_short = value;

                key_long = dockey;
                value_long = btree_value;

                nchunk_long = docnchunk;
                rawkeylen_long = docrawkeylen;
            }
            (void)key_short;
            (void)nchunk_long;

            _hbtrie_store_meta(trie, &meta.size, newchunkno, opt,
                               key + trie->chunksize * (curchunkno+1),
                               (newchunkno - (curchunkno+1)) *
                                   trie->chunksize,
                               value_short, buf);

            btreeitem_new = (struct btreelist_item *)
                            mempool_alloc(sizeof(struct btreelist_item));
            btreeitem_new->chunkno = newchunkno;
            r = btree_init(&btreeitem_new->btree,
                           trie->btreeblk_handle,
                           trie->btree_blk_ops, kv_ops,
                           trie->btree_nodesize, trie->chunksize,
                           trie->valuelen, 0x0, &meta);
            if (r == BTREE_RESULT_FAIL) {
                ret_result = HBTRIE_RESULT_FAIL;
                break;
            }
            btreeitem_new->btree.aux = trie->aux;

            list_push_back(&btreelist, &btreeitem_new->e);

            chunk_new = (uint8_t*)key_long +
                        newchunkno * trie->chunksize;

            if (opt == HBMETA_LEAF) {
                // optimization mode
                _set_leaf_key(k, chunk_new, rawkeylen_long -
                                  newchunkno*trie->chunksize);
                r = btree_insert(&btreeitem_new->btree, k, value_long);
                if (r == BTREE_RESULT_FAIL) {
                    ret_result = HBTRIE_RESULT_FAIL;
                }
                _free_leaf_key(k);
            } else {
                // normal mode
                r = btree_insert(&btreeitem_new->btree,
                                 chunk_new, value_long);
                if (r == BTREE_RESULT_FAIL) {
                    ret_result = HBTRIE_RESULT_FAIL;
                }
            }

        } else {
            //3 2-2. create sub-tree
            // and insert two docs into it
            _hbtrie_store_meta(trie, &meta.size, newchunkno, opt,
                               key + trie->chunksize * (curchunkno+1),
                               (newchunkno - (curchunkno+1)) * trie->chunksize,
                               NULL, buf);

            btreeitem_new = (struct btreelist_item *)
                            mempool_alloc(sizeof(struct btreelist_item));
            btreeitem_new->chunkno = newchunkno;
            r = btree_init(&btreeitem_new->btree, trie->btreeblk_handle,
                           trie->btree_blk_ops, kv_ops,
                           trie->btree_nodesize, trie->chunksize,
                           trie->valuelen, 0x0, &meta);
            if (r == BTREE_RESULT_FAIL) {
                ret_result = HBTRIE_RESULT_FAIL;
            }
            btreeitem_new->btree.aux = trie->aux;

            list_push_back(&btreelist, &btreeitem_new->e);
            // insert KEY
            chunk_new = key + newchunkno * trie->chunksize;
            if (opt == HBMETA_LEAF) {
                // optimization mode
                _set_leaf_key(k, chunk_new,
                              rawkeylen - newchunkno*trie->chunksize);
                r = btree_insert(&btreeitem_new->btree, k, value);
                _free_leaf_key(k);
            } else {
                r = btree_insert(&btreeitem_new->btree, chunk_new, value);
            }
            if (r == BTREE_RESULT_FAIL) {
                ret_result = HBTRIE_RESULT_FAIL;
            }

            // insert the original DOCKEY
            chunk_new = dockey + newchunkno * trie->chunksize;
            if (opt == HBMETA_LEAF) {
                // optimization mode
                _set_leaf_key(k, chunk_new,
                              docrawkeylen - newchunkno*trie->chunksize);
                r = btree_insert(&btreeitem_new->btree, k, btree_value);
                _free_leaf_key(k);
            } else {
                r = btree_insert(&btreeitem_new->btree,
                                 chunk_new, btree_value);
            }
            if (r == BTREE_RESULT_FAIL) {
                ret_result = HBTRIE_RESULT_FAIL;
            }
        }

        // update previous (parent) b-tree
        bid_new = btreeitem_new->btree.root_bid;
        btreeitem->child_rootbid = bid_new;

        // set MSB
        _bid = _endian_encode(bid_new);
        _hbtrie_set_msb(trie, (void *)&_bid);
        // ASSUMPTION: parent b-tree always MUST be non-leaf b-tree
        r = btree_insert(&btreeitem->btree, chunk, (void*)&_bid);
        if (r == BTREE_RESULT_FAIL) {
            ret_result = HBTRIE_RESULT_FAIL;
        }

        break;
    } // while

    _hbtrie_btree_cascaded_update(trie, &btreelist, key, 1);

    return ret_result;
}

hbtrie_result hbtrie_insert(struct hbtrie *trie,
                            void *rawkey, int rawkeylen,
                            void *value, void *oldvalue_out) {
    return _hbtrie_insert(trie, rawkey, rawkeylen, value, oldvalue_out, 0x0);
}

hbtrie_result hbtrie_insert_partial(struct hbtrie *trie,
                                    void *rawkey, int rawkeylen,
                                    void *value, void *oldvalue_out) {
    return _hbtrie_insert(trie, rawkey, rawkeylen,
                          value, oldvalue_out, HBTRIE_PARTIAL_UPDATE);
}
