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

#define CHUNK_FLAG (0x8000)
typedef uint16_t chunkno_t;
struct hbtrie_meta {
    chunkno_t chunkno;
    uint16_t prefix_len;
    void *value;
    void *prefix;
};

typedef enum {
    HBMETA_NORMAL,
    HBMETA_LEAF,
} hbmeta_opt;

struct btreelist_item {
    BTree *btree;
    chunkno_t chunkno;
    bid_t child_rootbid;
    struct list_elem e;
    uint8_t leaf;
};

struct btreeit_item {
    BTreeIterator *btree_it;
    chunkno_t chunkno;
    struct list_elem le;
    uint8_t leaf;
};

#define _is_leaf_btree(chunkno) ((chunkno) & CHUNK_FLAG)
#define _get_chunkno(chunkno) ((chunkno) & (~(CHUNK_FLAG)))

#define HBTRIE_PREFIX_MATCH_ONLY (0x1)
#define HBTRIE_PARTIAL_MATCH (0x2)

#define HBTRIE_PARTIAL_UPDATE (0x1)

#define HBTRIE_MEMPOOL_MIN_BINS 4

MemoryPool* HBTrie::hbtrieMP(nullptr);

int HBTrie::reformKey(void *rawkey, int rawkeylen, void *keyout)
{
    int outkeylen;
    int nchunk;
    int i;
    uint8_t rsize;
    size_t csize = chunksize;

    nchunk = getNchunkRaw(rawkey, rawkeylen);
    outkeylen = nchunk * csize;

    if (nchunk > 2) {
        // copy chunk[0] ~ chunk[nchunk-2]
        rsize = rawkeylen - ((nchunk - 2) * csize);
    } else {
        rsize = rawkeylen;
    }
    fdb_assert(rsize && rsize <= chunksize, rsize, this);
    memcpy((uint8_t*)keyout, (uint8_t*)rawkey, rawkeylen);

    if (rsize < csize) {
        // zero-fill rest space
        i = nchunk - 2;
        memset((uint8_t*)keyout + (i*csize) + rsize, 0x0, 2*csize - rsize);
    } else {
        // zero-fill the last chunk
        i = nchunk - 1;
        memset((uint8_t*)keyout + i * csize, 0x0, csize);
    }

    // assign rsize at the end of the keyout
    *((uint8_t*)keyout + outkeylen - 1) = rsize;

    return outkeylen;
}

// this function only returns (raw) key length
int HBTrie::reformKeyReverse(void *key, int keylen)
{
    uint8_t rsize;
    rsize = *((uint8_t*)key + keylen - 1);
    fdb_assert(rsize, rsize, this);

    if (rsize == chunksize) {
        return keylen - chunksize;
    } else {
        // rsize: 1 ~ chunksize-1
        return keylen - (chunksize * 2) + rsize;
    }
}

HBTrie::HBTrie() :
    chunksize(0), valuelen(0), flag(0x0), leaf_height_limit(0), btree_nodesize(0),
    root_bid(0), btreeblk_handle(NULL), doc_handle(NULL),
    btree_kv_ops(NULL), btree_leaf_kv_ops(NULL), readkey(NULL), map(NULL),
    last_map_chunk(NULL)
{
    aux = &cmp_args;
}

HBTrie::HBTrie(HBTrie *_trie)
{
    init(_trie->getChunkSize(), _trie->getValueLen(),
         _trie->getBtreeNodeSize(), _trie->getRootBid(),
         _trie->getBtreeBlkHandle(), _trie->getDocHandle(),
         _trie->getReadKey());
}

HBTrie::HBTrie(int _chunksize, int _valuelen, int _btree_nodesize, bid_t _root_bid,
    BTreeBlkHandle* _btreeblk_handle, void* _doc_handle, hbtrie_func_readkey* _readkey)
{
    init(_chunksize, _valuelen, _btree_nodesize, _root_bid,
         _btreeblk_handle, _doc_handle, _readkey);
}

HBTrie::~HBTrie()
{
    delete btree_kv_ops;
    delete btree_leaf_kv_ops;
    freeLastMapChunk();
}

void HBTrie::init(int _chunksize, int _valuelen, int _btree_nodesize, bid_t _root_bid,
                  BTreeBlkHandle* _btreeblk_handle, void* _doc_handle, hbtrie_func_readkey* _readkey)
{
    chunksize = _chunksize;
    valuelen = _valuelen;
    btree_nodesize = _btree_nodesize;
    root_bid = _root_bid;
    btreeblk_handle = _btreeblk_handle;
    doc_handle = _doc_handle;
    readkey = _readkey;
    flag = 0x0;
    leaf_height_limit = 0;
    map = NULL;

    // assign key-value operations
    fdb_assert(valuelen == 8, valuelen, this);
    fdb_assert((size_t)chunksize >= sizeof(void *), chunksize, this);

    BTreeKVOps *_btree_kv_ops, *_btree_leaf_kv_ops;

    _btree_kv_ops = new FixedKVOps(chunksize, valuelen);
    _btree_leaf_kv_ops = new FastStrKVOps(chunksize, valuelen);

    cmp_args.chunksize = _chunksize;
    cmp_args.aux = NULL;
    cmp_args.kv_ops = _btree_leaf_kv_ops;
    aux = &cmp_args;

    btree_kv_ops = _btree_kv_ops;
    btree_leaf_kv_ops = _btree_leaf_kv_ops;
    allocLastMapChunk();
}

bool HBTrie::setLastMapChunk(void *key)
{
    hbtrie_cmp_func *void_cmp;
    bool ret = false;
    if (map) { // custom cmp functions exist
        if (!memcmp(last_map_chunk, key, chunksize)) {
            // same custom function was used in the last call .. leaf b+tree
            ret = true;
        } else {
            // get cmp function corresponding to the key
            void_cmp = map(key, (void *)this);
            if (void_cmp) {
                // custom cmp function matches .. turn on leaf b+tree mode
                ret = true;
                memcpy(last_map_chunk, key, chunksize);
                // set aux for _fdb_custom_cmp_wrap()
                cmp_args.aux = void_cmp;
                aux = &cmp_args;
            }
        }
    }

    return ret;
}

/* << raw hbtrie meta structure >>
 * [Total meta length]: 2 bytes
 * [Chunk number]:      2 bytes
 * [Value length]:      1 bytes
 * [Value (optional)]:  x bytes
 * [Prefix (optional)]: y bytes
 */

// IMPORTANT: hbmeta doesn't have own allocated memory space (pointers only)
void HBTrie::fetchMeta(int metasize, struct hbtrie_meta *hbmeta, void *buf)
{
    // read hbmeta from buf
    int offset = 0;
    uint32_t vlen = 0;

    if (!hbmeta || !buf) {
        if (hbmeta) {
            memset(hbmeta, 0x0, sizeof(struct hbtrie_meta));
        }
        return;
    }

    memcpy(&hbmeta->chunkno, buf, sizeof(hbmeta->chunkno));
    hbmeta->chunkno = _endian_decode(hbmeta->chunkno);
    offset += sizeof(hbmeta->chunkno);

    memcpy(&vlen, (uint8_t*)buf+offset, sizeof(valuelen));
    offset += sizeof(valuelen);

    if (vlen > 0) {
        hbmeta->value = (uint8_t*)buf + offset;
        offset += valuelen;
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

void HBTrie::storeMeta(metasize_t& metasize_out,
                       chunkno_t chunkno,
                       hbmeta_opt opt,
                       void *prefix,
                       int prefixlen,
                       void *value,
                       void *buf)
{
    chunkno_t _chunkno;

    // write hbmeta to buf
    metasize_out = 0;

    if (opt == HBMETA_LEAF) {
        chunkno |= CHUNK_FLAG;
    }

    _chunkno = _endian_encode(chunkno);
    memcpy(buf, &_chunkno, sizeof(chunkno));
    metasize_out += sizeof(chunkno);

    if (value) {
        memcpy((uint8_t*)buf + metasize_out,
               &valuelen, sizeof(valuelen));
        metasize_out += sizeof(valuelen);
        memcpy((uint8_t*)buf + metasize_out,
               value, valuelen);
        metasize_out += valuelen;
    } else {
        memset((uint8_t*)buf + metasize_out, 0x0, sizeof(valuelen));
        metasize_out += sizeof(valuelen);
    }

    if (prefixlen > 0) {
        memcpy((uint8_t*)buf + metasize_out, prefix, prefixlen);
        metasize_out += prefixlen;
    }
}

int HBTrie::findDiffChunk(void *key1,
                          void *key2,
                          int start_chunk,
                          int end_chunk)
{
    int i;

    if (!key1 || !key2) {
        return 0;
    }

    for (i=start_chunk; i < end_chunk; ++i) {
        if (memcmp((uint8_t*)key1 + chunksize*i,
                   (uint8_t*)key2 + chunksize*i,
                   chunksize)) {
            return i;
        }
    }
    return i;
}

//3 ASSUMPTION: 'VALUE' should be based on same endian to hb+trie
inline void HBTrie::valueSetMsb(void *value)
{
#if defined(__ENDIAN_SAFE) || defined(_BIG_ENDIAN)
    // big endian
    *((uint8_t*)value) |= (uint8_t)0x80;
#else
    // little endian
    *((uint8_t*)value + (valuelen-1)) |= (uint8_t)0x80;
#endif
}
inline void HBTrie::valueClearMsb(void *value)
{
#if defined(__ENDIAN_SAFE) || defined(_BIG_ENDIAN)
    // big endian
    *((uint8_t*)value) &= ~((uint8_t)0x80);
#else
    // little endian
    *((uint8_t*)value + (valuelen-1)) &= ~((uint8_t)0x80);
#endif
}
inline bool HBTrie::valueIsMsbSet(void *value)
{
#if defined(__ENDIAN_SAFE) || defined(_BIG_ENDIAN)
    // big endian
    return *((uint8_t*)value) & ((uint8_t)0x80);
#else
    // little endian
    return *((uint8_t*)value + (valuelen-1)) & ((uint8_t)0x80);
#endif
}

void HBTrie::freeBtreeList(struct list *btreelist)
{
    struct btreelist_item *btreeitem;
    struct list_elem *e;

    // free all items on list
    e = list_begin(btreelist);
    while(e) {
        btreeitem = _get_entry(e, struct btreelist_item, e);
        e = list_remove(btreelist, e);
        delete btreeitem->btree;
        mempool_free(btreeitem);
    }
}

void HBTrie::btreeCascadedUpdate(struct list *btreelist,
                                 void *key)
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

        if (btreeitem->child_rootbid != btreeitem_child->btree->getRootBid()) {
            // root node of child sub-tree has been moved to another block
            // update parent sub-tree
            bid_new = btreeitem_child->btree->getRootBid();
            _bid = _endian_encode(bid_new);
            valueSetMsb((void *)&_bid);
            btreeitem->btree->insert((uint8_t*)key + btreeitem->chunkno * chunksize,
                                     (void *)&_bid);
        }
        e_child = e;
        e = list_prev(e);
    }

    // update trie root bid
    if (e) {
        btreeitem = _get_entry(e, struct btreelist_item, e);
        root_bid = btreeitem->btree->getRootBid();
    } else if (e_child) {
        btreeitem = _get_entry(e_child, struct btreelist_item, e);
        root_bid = btreeitem->btree->getRootBid();
    } else {
        fdb_assert(0, this, e_child);
    }

    freeBtreeList(btreelist);
}

hbtrie_result HBTrie::_find(void *key, int keylen, void *valuebuf,
                            struct list *btreelist, uint8_t flag)
{
    int nchunk;
    int rawkeylen;
    int prevchunkno, curchunkno, cpt_node = 0;
    BTree *btree = NULL;
    BTree btree_static;
    btree_result r;
    struct hbtrie_meta hbmeta;
    struct btree_meta meta;
    struct btreelist_item *btreeitem = NULL;
    uint8_t *k = alca(uint8_t, chunksize);
    uint8_t *buf = alca(uint8_t, btree_nodesize);
    uint8_t *btree_value = alca(uint8_t, valuelen);
    void *chunk = NULL;
    bid_t bid_new;
    nchunk = getNchunk(key, keylen);

    meta.data = buf;
    curchunkno = 0;

    setLastMapChunk(key);

    if (btreelist) {
        list_init(btreelist);
        btreeitem = (struct btreelist_item *)
                    mempool_alloc(sizeof(struct btreelist_item));
        // Note that this instance will be released in freeBtreeList().
        btreeitem->btree = new BTree();
        list_push_back(btreelist, &btreeitem->e);
        btree = btreeitem->btree;
    } else {
        btree = &btree_static;
    }

    if (root_bid == BLK_NOT_FOUND) {
        // retrieval fail
        return HBTRIE_RESULT_FAIL;
    } else {
        // read from root_bid
        r = btree->initFromBid(btreeblk_handle, btree_kv_ops, btree_nodesize, root_bid);
        if (r != BTREE_RESULT_SUCCESS) {
            return HBTRIE_RESULT_FAIL;
        }
        btree->setAux(aux);
        if (btree->getKSize() != chunksize || btree->getVSize() != valuelen) {
            if (((chunksize << 4) | valuelen) == btree->getKSize()) {
                // this is an old meta format
                return HBTRIE_RESULT_INDEX_VERSION_NOT_SUPPORTED;
            }
            // B+tree root node is corrupted.
            return HBTRIE_RESULT_INDEX_CORRUPTED;
        }
    }

    while (curchunkno < nchunk) {
        // get current chunk number
        meta.size = btree->readMeta(meta.data);
        fetchMeta(meta.size, &hbmeta, meta.data);
        prevchunkno = curchunkno;
        if (_is_leaf_btree(hbmeta.chunkno)) {
            cpt_node = 1;
            hbmeta.chunkno = _get_chunkno(hbmeta.chunkno);
            btree->setKVOps(btree_leaf_kv_ops);
        }
        curchunkno = hbmeta.chunkno;

        if (btreelist) {
            btreeitem->chunkno = curchunkno;
            btreeitem->leaf = cpt_node;
        }

        //3 check whether there are skipped prefixes.
        if (curchunkno - prevchunkno > 1) {
            fdb_assert(hbmeta.prefix != NULL, hbmeta.prefix, this);
            // prefix comparison (find the first different chunk)
            int diffchunkno =
                findDiffChunk(hbmeta.prefix,
                              (uint8_t*)key + chunksize * (prevchunkno+1),
                              0, curchunkno - (prevchunkno+1));
            if (diffchunkno < curchunkno - (prevchunkno+1)) {
                // prefix does not match -> retrieval fail
                return HBTRIE_RESULT_FAIL;
            }
        }

        //3 search b-tree using current chunk (or postfix)
        rawkeylen = reformKeyReverse(key, keylen);
        if ((cpt_node && rawkeylen == curchunkno * chunksize) ||
            (!cpt_node && nchunk == curchunkno)) {
            // KEY is exactly same as tree's prefix .. return value in metasection
            if (hbmeta.value && valuelen > 0) {
                memcpy(valuebuf, hbmeta.value, valuelen);
            }
            return HBTRIE_RESULT_SUCCESS;
        } else {
            chunk = (uint8_t*)key + curchunkno * chunksize;
            if (cpt_node) {
                // leaf b-tree
                size_t rawchunklen =
                    reformKeyReverse(chunk, (nchunk-curchunkno) * chunksize);

                setLeafKey(k, chunk, rawchunklen);
                r = btree->find(k, btree_value);
                freeLeafKey(k);
            } else {
                r = btree->find(chunk, btree_value);
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
                memcpy(valuebuf, btree_value, valuelen);
                return HBTRIE_RESULT_SUCCESS;
            }

            // check whether the value points to sub-tree or document
            // check MSB
            if (valueIsMsbSet(btree_value)) {
                // this is BID of b-tree node (by clearing MSB)
                valueClearMsb(btree_value);
                bid_new = btree_kv_ops->value2bid(btree_value);
                bid_new = _endian_decode(bid_new);

                if (btreelist) {
                    btreeitem->child_rootbid = bid_new;
                    btreeitem = (struct btreelist_item *)
                                mempool_alloc(sizeof(struct btreelist_item));
                    btreeitem->btree = new BTree();
                    list_push_back(btreelist, &btreeitem->e);
                    btree = btreeitem->btree;
                }

                // fetch sub-tree
                r = btree->initFromBid(btreeblk_handle, btree_kv_ops,
                                       btree_nodesize, bid_new);
                if (r != BTREE_RESULT_SUCCESS) {
                    return HBTRIE_RESULT_FAIL;
                }
                btree->setAux(aux);
            } else {
                // this is offset of document (as it is), read entire key

                uint8_t *docrawkey = nullptr, *dockey = nullptr;
                const int rawkey_buffer_index = allocateBuffer(&docrawkey);
                const int key_buffer_index = allocateBuffer(&dockey);
                uint32_t docrawkeylen, dockeylen;
                uint64_t offset;
                int docnchunk, diffchunkno;

                hbtrie_result result = HBTRIE_RESULT_SUCCESS;

                // get offset value from btree_value
                offset = btree_kv_ops->value2bid(btree_value);
                if (!(flag & HBTRIE_PREFIX_MATCH_ONLY)) {
                    // read entire key
                    docrawkeylen = readkey( doc_handle, offset,
                                            key, chunk, curchunkno, docrawkey );
                    dockeylen = reformKey(docrawkey, docrawkeylen, dockey);

                    // find first different chunk
                    docnchunk = getNchunk(dockey, dockeylen);

                    if (docnchunk == nchunk) {
                        diffchunkno = findDiffChunk(key, dockey, curchunkno, nchunk);
                        if (diffchunkno == nchunk) {
                            // success
                            memcpy(valuebuf, btree_value, valuelen);
                        } else {
                            result = HBTRIE_RESULT_FAIL;
                        }
                    } else {
                        result = HBTRIE_RESULT_FAIL;
                    }
                } else {
                    // just return value
                    memcpy(valuebuf, btree_value, valuelen);
                }

                deallocateBuffer(&docrawkey, rawkey_buffer_index);
                deallocateBuffer(&dockey, key_buffer_index);

                return result;
            }
        }
    }

    return HBTRIE_RESULT_FAIL;
}

hbtrie_result HBTrie::find(void *rawkey, int rawkeylen, void *valuebuf)
{
    int nchunk = getNchunkRaw(rawkey, rawkeylen);
    uint8_t *key = alca(uint8_t, nchunk * chunksize);
    int keylen;

    keylen = reformKey(rawkey, rawkeylen, key);
    return _find(key, keylen, valuebuf, NULL, 0x0);
}

hbtrie_result HBTrie::findOffset(void *rawkey, int rawkeylen, void *valuebuf)
{
    int nchunk = getNchunkRaw(rawkey, rawkeylen);
    uint8_t *key = alca(uint8_t, nchunk * chunksize);
    int keylen;

    keylen = reformKey(rawkey, rawkeylen, key);
    return _find(key, keylen, valuebuf, NULL, HBTRIE_PREFIX_MATCH_ONLY);
}

hbtrie_result HBTrie::findPartial(void *rawkey, int rawkeylen, void *valuebuf)
{
    int nchunk = getNchunkRaw(rawkey, rawkeylen);
    uint8_t *key = alca(uint8_t, nchunk * chunksize);
    int keylen;

    keylen = reformKey(rawkey, rawkeylen, key);
    return _find(key, keylen, valuebuf, NULL, HBTRIE_PARTIAL_MATCH);
}


hbtrie_result HBTrie::_remove(void *rawkey, int rawkeylen, uint8_t flag)
{
    int nchunk = getNchunkRaw(rawkey, rawkeylen);
    int keylen;
    uint8_t *key = alca(uint8_t, nchunk * chunksize);
    uint8_t *valuebuf = alca(uint8_t, valuelen);
    hbtrie_result r;
    btree_result br = BTREE_RESULT_SUCCESS;
    struct list btreelist;
    struct btreelist_item *btreeitem;
    struct list_elem *e;

    keylen = reformKey(rawkey, rawkeylen, key);

    r = _find(key, keylen, valuebuf, &btreelist, flag);

    if (r == HBTRIE_RESULT_SUCCESS) {
        e = list_end(&btreelist);
        fdb_assert(e, this, flag);

        btreeitem = _get_entry(e, struct btreelist_item, e);
        if (btreeitem &&
            ((btreeitem->leaf && rawkeylen == btreeitem->chunkno * chunksize) ||
             (!(btreeitem->leaf) && nchunk == btreeitem->chunkno)) ) {
            // key is exactly same as b-tree's prefix .. remove from meta section
            struct hbtrie_meta hbmeta;
            struct btree_meta meta;
            hbmeta_opt opt;
            uint8_t *buf = alca(uint8_t, btree_nodesize);

            meta.data = buf;
            meta.size = btreeitem->btree->readMeta(meta.data);
            fetchMeta(meta.size, &hbmeta, meta.data);

            opt = (_is_leaf_btree(hbmeta.chunkno))?(HBMETA_LEAF):(HBMETA_NORMAL);

            // remove value from metasection
            storeMeta(meta.size, _get_chunkno(hbmeta.chunkno), opt,
                      hbmeta.prefix, hbmeta.prefix_len, NULL, buf);
            btreeitem->btree->updateMeta(&meta);
        } else {
            if (btreeitem && btreeitem->leaf) {
                // leaf b-tree
                uint8_t *k = alca(uint8_t, chunksize);
                setLeafKey(k, key + btreeitem->chunkno * chunksize,
                    rawkeylen - btreeitem->chunkno * chunksize);
                br = btreeitem->btree->remove(k);
                freeLeafKey(k);
            } else if (btreeitem) {
                // normal b-tree
                br = btreeitem->btree->remove(key + chunksize * btreeitem->chunkno);
            }
            if (br == BTREE_RESULT_FAIL) {
                r = HBTRIE_RESULT_FAIL;
            }
        }
        btreeCascadedUpdate(&btreelist, key);
    } else {
        // key (to be removed) not found
        // no update occurred .. we don't need to update b-trees on the path
        // just free the btreelist
        freeBtreeList(&btreelist);
    }

    return r;
}

hbtrie_result HBTrie::remove(void *rawkey, int rawkeylen)
{
    return _remove(rawkey, rawkeylen, 0x0);
}

hbtrie_result HBTrie::removePartial(void *rawkey, int rawkeylen)
{
    return _remove(rawkey, rawkeylen, HBTRIE_PARTIAL_MATCH);
}

void HBTrie::extendLeafTree(struct list *btreelist,
                            struct btreelist_item *btreeitem,
                            void *pre_str,
                            size_t pre_str_len)
{
    struct list keys;
    struct list_elem *e;
    struct _key_item *item, *smallest = NULL;
    BTreeIterator *it;
    BTree *new_btree;
    struct btree_meta meta;
    struct hbtrie_meta hbmeta;
    btree_result br;
    void *prefix = NULL, *meta_value = NULL;
    uint8_t *key_str = (uint8_t *) malloc(HBTRIE_MAX_KEYLEN);
    uint8_t *key_buf = alca(uint8_t, chunksize);
    uint8_t *value_buf = alca(uint8_t, valuelen);
    uint8_t *buf = alca(uint8_t, btree_nodesize);
    size_t keylen, minchunkno = 0;

    // fetch metadata
    meta.data = buf;
    meta.size = btreeitem->btree->readMeta(meta.data);
    fetchMeta(meta.size, &hbmeta, meta.data);

    // scan all keys
    list_init(&keys);
    memset(key_buf, 0, chunksize);
    minchunkno = 0;

    it = new BTreeIterator();
    br = it->init(btreeitem->btree, NULL);
    while (br == BTREE_RESULT_SUCCESS) {
        // get key
        if ((br = it->next(key_buf, value_buf)) == BTREE_RESULT_FAIL) {
            break;
        }

        getLeafKey(key_buf, key_str, keylen);
        freeLeafKey(key_buf);

        // insert into list
        item = (struct _key_item *)malloc(sizeof(struct _key_item));

        item->key = (void *)malloc(keylen);
        item->keylen = keylen;
        memcpy(item->key, key_str, keylen);

        item->value = (void *)malloc(valuelen);
        memcpy(item->value, value_buf, valuelen);

        list_push_back(&keys, &item->le);

        if (hbmeta.value == NULL) {
            // check common prefix
            if (prefix == NULL) {
                // initialize
                prefix = item->key;
                minchunkno = _len2chunk(item->keylen);
            } else {
                // update the length of common prefix
                minchunkno =
                    findDiffChunk(prefix, item->key, 0,
                                  MIN(_len2chunk(item->keylen), minchunkno));
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
    delete it;

    // construct new (non-leaf) b-tree
    if (hbmeta.value) {
        // insert tree's prefix into the list
        item = (struct _key_item *)malloc(sizeof(struct _key_item));

        item->key = NULL;
        item->keylen = 0;

        item->value = (void *)malloc(valuelen);
        memcpy(item->value, hbmeta.value, valuelen);

        list_push_back(&keys, &item->le);

        meta_value = smallest = NULL;
    } else {
        if (smallest) {
            if (minchunkno > 0 &&
                (size_t)getNchunkRaw(smallest->key, smallest->keylen) == minchunkno) {
                meta_value = smallest->value;
            } else {
                smallest = NULL;
            }
        }
    }
    storeMeta(meta.size, _get_chunkno(hbmeta.chunkno) + minchunkno,
              HBMETA_NORMAL, prefix, minchunkno * chunksize, meta_value, buf);

    new_btree = new BTree(btreeblk_handle, btree_kv_ops, btree_nodesize,
                          chunksize, valuelen, 0x0, &meta);
    new_btree->setAux(aux);

    // reset BTREEITEM
    btreeitem->btree = new_btree;
    btreeitem->chunkno = _get_chunkno(hbmeta.chunkno) + minchunkno;
    btreeitem->leaf = 0;

    btreeCascadedUpdate(btreelist, pre_str);

    // insert all keys
    memcpy(key_str, pre_str, pre_str_len);
    e = list_begin(&keys);
    while (e) {
        item = _get_entry(e, struct _key_item, le);
        if (item != smallest) {
            if (item->keylen > 0) {
                memcpy(key_str + pre_str_len, item->key, item->keylen);
            }
            insert(key_str, pre_str_len + item->keylen, item->value, value_buf);
        }

        e = list_remove(&keys, e);
        if (item->key) {
            free(item->key);
        }
        free(item->value);
        free(item);
    }

    free(key_str);
}

hbtrie_result HBTrie::_insert(void *rawkey, int rawkeylen,
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
    bool leaf_cond = false;
    uint8_t *k = alca(uint8_t, chunksize);

    struct list btreelist;
    //struct btree btree, btree_new;
    struct btreelist_item *btreeitem, *btreeitem_new;
    hbtrie_result ret_result = HBTRIE_RESULT_SUCCESS;
    btree_result r;
    BTreeKVOps *kv_ops;

    struct hbtrie_meta hbmeta;
    struct btree_meta meta;
    hbmeta_opt opt;

    nchunk = getNchunkRaw(rawkey, rawkeylen);

    uint8_t *key = alca(uint8_t, nchunk * chunksize);
    uint8_t *buf = alca(uint8_t, btree_nodesize);
    uint8_t *btree_value = alca(uint8_t, valuelen);
    void *chunk, *chunk_new;
    bid_t bid_new, _bid;

    meta.data = buf;
    curchunkno = 0;
    keylen = reformKey(rawkey, rawkeylen, key);
    (void)keylen;

    leaf_cond = setLastMapChunk(key);

    list_init(&btreelist);
    // btreeitem for root btree
    btreeitem = (struct btreelist_item*)
                mempool_alloc(sizeof(struct btreelist_item));
    btreeitem->btree = new BTree();
    list_push_back(&btreelist, &btreeitem->e);

    if (root_bid == BLK_NOT_FOUND) {
        // create root b-tree
        storeMeta(meta.size, 0, HBMETA_NORMAL,
                  NULL, 0, NULL, buf);
        r = btreeitem->btree->init(btreeblk_handle, btree_kv_ops, btree_nodesize,
                                   chunksize, valuelen, 0x0, &meta);
        if (r != BTREE_RESULT_SUCCESS) {
            freeBtreeList(&btreelist);
            return HBTRIE_RESULT_FAIL;
        }
    } else {
        // read from root_bid
        r = btreeitem->btree->initFromBid(btreeblk_handle, btree_kv_ops,
                                          btree_nodesize, root_bid);
        if (r != BTREE_RESULT_SUCCESS) {
            freeBtreeList(&btreelist);
            return HBTRIE_RESULT_FAIL;
        }
        if (btreeitem->btree->getKSize() != chunksize ||
            btreeitem->btree->getVSize() != valuelen) {
            if (((chunksize << 4) | valuelen) == btreeitem->btree->getKSize()) {
                // this is an old meta format
                freeBtreeList(&btreelist);
                return HBTRIE_RESULT_INDEX_VERSION_NOT_SUPPORTED;
            }
            // B+tree root node is corrupted.
            freeBtreeList(&btreelist);
            return HBTRIE_RESULT_INDEX_CORRUPTED;
        }
    }
    btreeitem->btree->setAux(aux);

    // set 'oldvalue_out' to 0xff..
    if (oldvalue_out) {
        memset(oldvalue_out, 0xff, valuelen);
    }

    uint8_t *docrawkey = nullptr, *dockey = nullptr;
    const int rawkey_buffer_index = allocateBuffer(&docrawkey);
    const int key_buffer_index = allocateBuffer(&dockey);

    while (curchunkno < nchunk) {
        // get current chunk number
        meta.size = btreeitem->btree->readMeta(meta.data);
        fetchMeta(meta.size, &hbmeta, meta.data);
        prevchunkno = curchunkno;
        if (_is_leaf_btree(hbmeta.chunkno)) {
            cpt_node = 1;
            hbmeta.chunkno = _get_chunkno(hbmeta.chunkno);
            btreeitem->btree->setKVOps(btree_leaf_kv_ops);
        }
        btreeitem->chunkno = curchunkno = hbmeta.chunkno;

        //3 check whether there is skipped prefix
        if (curchunkno - prevchunkno > 1) {
            // prefix comparison (find the first different chunk)
            int diffchunkno =
                findDiffChunk(hbmeta.prefix, key + chunksize * (prevchunkno+1),
                              0, curchunkno - (prevchunkno+1));
            if (diffchunkno < curchunkno - (prevchunkno+1)) {
                //3 3. create sub-tree between parent and child tree

                // metadata (prefix) update in btreeitem->btree
                int new_prefixlen = chunksize *
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
                               chunksize * (diffchunkno + 1),
                           new_prefixlen);
                    storeMeta(meta.size, curchunkno,
                              HBMETA_NORMAL, new_prefix,
                              new_prefixlen, hbmeta.value, buf);
                } else {
                    storeMeta(meta.size, curchunkno,
                              HBMETA_NORMAL, NULL, 0,
                              hbmeta.value, buf);
                }
                // update metadata for old b-tree
                btreeitem->btree->updateMeta(&meta);

                // split prefix and create new sub-tree
                storeMeta(meta.size, prevchunkno + diffchunkno + 1,
                          HBMETA_NORMAL, old_prefix,
                          diffchunkno * chunksize, NULL, buf);

                // create new b-tree
                btreeitem_new = (struct btreelist_item *)
                                mempool_alloc(sizeof(struct btreelist_item));
                btreeitem_new->btree = new BTree();
                btreeitem_new->chunkno = prevchunkno + diffchunkno + 1;
                list_insert_before(&btreelist, &btreeitem->e,
                                   &btreeitem_new->e);

                r = btreeitem_new->btree->init(btreeblk_handle, btree_kv_ops,
                                               btree_nodesize, chunksize, valuelen,
                                               0x0, &meta);
                if (r != BTREE_RESULT_SUCCESS) {
                    deallocateBuffer(&docrawkey, rawkey_buffer_index);
                    deallocateBuffer(&dockey, key_buffer_index);
                    freeBtreeList(&btreelist);
                    return HBTRIE_RESULT_FAIL;
                }
                btreeitem_new->btree->setAux(aux);

                // insert chunk for 'key'
                chunk_new = key + (prevchunkno + diffchunkno + 1) *
                                  chunksize;
                r = btreeitem_new->btree->insert(chunk_new, value);
                if (r == BTREE_RESULT_FAIL) {
                    deallocateBuffer(&docrawkey, rawkey_buffer_index);
                    deallocateBuffer(&dockey, key_buffer_index);
                    freeBtreeList(&btreelist);
                    return HBTRIE_RESULT_FAIL;
                }
                // insert chunk for existing btree
                chunk_new = (uint8_t*)old_prefix + diffchunkno *
                                                   chunksize;
                bid_new = btreeitem->btree->getRootBid();
                btreeitem_new->child_rootbid = bid_new;
                // set MSB
                _bid = _endian_encode(bid_new);
                valueSetMsb((void*)&_bid);
                r = btreeitem_new->btree->insert(chunk_new, (void*)&_bid);
                if (r == BTREE_RESULT_FAIL) {
                    deallocateBuffer(&docrawkey, rawkey_buffer_index);
                    deallocateBuffer(&dockey, key_buffer_index);
                    freeBtreeList(&btreelist);
                    return HBTRIE_RESULT_FAIL;
                }

                break;
            }
        }

        //3 search b-tree using current chunk
        if ((cpt_node && rawkeylen == curchunkno * chunksize) ||
            (!cpt_node && nchunk == curchunkno)) {
            // KEY is exactly same as tree's prefix .. insert into metasection
            storeMeta(meta.size, curchunkno,
                      (cpt_node)?(HBMETA_LEAF):(HBMETA_NORMAL),
                      hbmeta.prefix,
                      (curchunkno-prevchunkno - 1) * chunksize,
                      value, buf);
            btreeitem->btree->updateMeta(&meta);
            break;
        } else {
            chunk = key + curchunkno*chunksize;
            if (cpt_node) {
                // leaf b-tree
                setLeafKey(k, chunk,
                              rawkeylen - curchunkno*chunksize);
                r = btreeitem->btree->find(k, btree_value);
                freeLeafKey(k);
            } else {
                r = btreeitem->btree->find(chunk, btree_value);
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
                setLeafKey(k, chunk, rawkeylen - curchunkno*chunksize);
                r = btreeitem->btree->insert(k, value);
                if (r == BTREE_RESULT_FAIL) {
                    freeLeafKey(k);
                    ret_result = HBTRIE_RESULT_FAIL;
                    break; // while loop
                }
                freeLeafKey(k);

                if (btreeitem->btree->getHeight() > leaf_height_limit) {
                    // height growth .. extend!
                    // btreelist is cleared out within extendLeafTree when
                    // btreeCascacdedUpdate is invoked.
                    extendLeafTree(&btreelist, btreeitem, key, curchunkno * chunksize);
                    deallocateBuffer(&docrawkey, rawkey_buffer_index);
                    deallocateBuffer(&dockey, key_buffer_index);
                    return ret_result;
                }
            } else {
                r = btreeitem->btree->insert(chunk, value);
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
                memcpy(oldvalue_out, btree_value, valuelen);
            }
            // assume that always normal b-tree
            r = btreeitem->btree->insert(chunk, value);
            if (r == BTREE_RESULT_FAIL) {
                ret_result = HBTRIE_RESULT_FAIL;
            } else {
                ret_result = HBTRIE_RESULT_SUCCESS;
            }
            break;
        }

        // check whether the value points to sub-tree or document
        // check MSB
        if (valueIsMsbSet(btree_value)) {
            // this is BID of b-tree node (by clearing MSB)
            valueClearMsb(btree_value);
            bid_new = btree_kv_ops->value2bid(btree_value);
            bid_new = _endian_decode(bid_new);
            btreeitem->child_rootbid = bid_new;
            //3 traverse to the sub-tree
            // fetch sub-tree
            btreeitem = (struct btreelist_item*)
                        mempool_alloc(sizeof(struct btreelist_item));
            btreeitem->btree = new BTree();

            r = btreeitem->btree->initFromBid(btreeblk_handle, btree_kv_ops,
                                              btree_nodesize, bid_new);
            if (r == BTREE_RESULT_FAIL) {
                ret_result = HBTRIE_RESULT_FAIL;
            }
            btreeitem->btree->setAux(aux);
            list_push_back(&btreelist, &btreeitem->e);
            continue;
        }

        // this is offset of document (as it is)
        // create new sub-tree

        uint32_t docrawkeylen, dockeylen, minrawkeylen;
        uint64_t offset;
        int docnchunk, minchunkno, newchunkno, diffchunkno;

        // get offset value from btree_value
        offset = btree_kv_ops->value2bid(btree_value);

        // read entire key
        docrawkeylen = readkey( doc_handle, offset,
                                key, chunk, curchunkno, docrawkey );
        dockeylen = reformKey(docrawkey, docrawkeylen, dockey);

        // find first different chunk
        docnchunk = getNchunk(dockey, dockeylen);

        if (flag & HBTRIE_FLAG_COMPACT || leaf_cond) {
            // optimization mode
            // Note: custom cmp function doesn't support key
            //       longer than a block size.

            // newchunkno doesn't matter to leaf B+tree,
            // since leaf B+tree can't create sub-tree.
            newchunkno = curchunkno+1;
            minchunkno = MIN(_len2chunk(rawkeylen),
                             _len2chunk((int)docrawkeylen));
            minrawkeylen = MIN(rawkeylen, (int)docrawkeylen);

            if (curchunkno == 0) {
                // root B+tree
                int endchunk = minchunkno - ((minrawkeylen % chunksize == 0)?(0):(1));
                diffchunkno = findDiffChunk(rawkey, docrawkey,
                                            curchunkno, endchunk);
                if (rawkeylen == (int)docrawkeylen && diffchunkno+1 == minchunkno) {
                    if (!memcmp(rawkey, docrawkey, rawkeylen)) {
                        // same key
                        diffchunkno = minchunkno;
                    }
                }
            } else {
                // diffchunkno also doesn't matter to leaf B+tree,
                // since leaf B+tree is not based on a lexicographical key order.
                // Hence, we set diffchunkno to minchunkno iff two keys are
                // identified as the same key by the custom compare function.
                // Otherwise, diffchunkno is always set to curchunkno.
                uint8_t *k_doc = alca(uint8_t, chunksize);
                setLeafKey(k, chunk,
                              rawkeylen - curchunkno*chunksize);
                setLeafKey(k_doc, (uint8_t*)docrawkey + curchunkno*chunksize,
                              docrawkeylen - curchunkno*chunksize);
                if (btree_leaf_kv_ops->cmp(k, k_doc, aux) == 0) {
                    // same key
                    diffchunkno = minchunkno;
                    docnchunk = nchunk;
                } else {
                    // different key
                    diffchunkno = curchunkno;
                }
                freeLeafKey(k);
                freeLeafKey(k_doc);
            }
            opt = HBMETA_LEAF;
            kv_ops = btree_leaf_kv_ops;
        } else {
            // original mode
            minchunkno = MIN(nchunk, docnchunk);
            newchunkno = diffchunkno =
                findDiffChunk(key, dockey, curchunkno, minchunkno);
            opt = HBMETA_NORMAL;
            kv_ops = btree_kv_ops;
        }

        // one key is substring of the other key
        if (minchunkno == diffchunkno && docnchunk == nchunk) {
            //3 same key!! .. update the value
            if (oldvalue_out) {
                memcpy(oldvalue_out, btree_value, valuelen);
            }
            if (cpt_node) {
                // leaf b-tree
                setLeafKey(k, chunk,
                              rawkeylen - curchunkno*chunksize);
                r = btreeitem->btree->insert(k, value);
                freeLeafKey(k);
            } else {
                // normal b-tree
                r = btreeitem->btree->insert(chunk, value);
            }
            if (r == BTREE_RESULT_FAIL) {
                ret_result = HBTRIE_RESULT_FAIL;
            } else {
                ret_result = HBTRIE_RESULT_SUCCESS;
            }
            break;
        }

        // different key
        while (btree_nodesize > HBTRIE_HEADROOM &&
               (newchunkno - curchunkno) * chunksize >
                   (int)btree_nodesize - HBTRIE_HEADROOM) {
            // prefix is too long .. we have to split it
            fdb_assert(opt == HBMETA_NORMAL, opt, this);
            int midchunkno;
            midchunkno = curchunkno +
                        (btree_nodesize - HBTRIE_HEADROOM) / chunksize;
            storeMeta(meta.size, midchunkno, opt, key + chunksize * (curchunkno+1),
                      (midchunkno - (curchunkno+1)) * chunksize, NULL, buf);

            btreeitem_new = (struct btreelist_item *)
                            mempool_alloc(sizeof(struct btreelist_item));
            btreeitem_new->btree = new BTree();
            btreeitem_new->chunkno = midchunkno;
            list_push_back(&btreelist, &btreeitem_new->e);

            r = btreeitem_new->btree->init(btreeblk_handle, kv_ops, btree_nodesize,
                                           chunksize, valuelen, 0x0, &meta);
            if (r == BTREE_RESULT_FAIL) {
                deallocateBuffer(&docrawkey, rawkey_buffer_index);
                deallocateBuffer(&dockey, key_buffer_index);
                freeBtreeList(&btreelist);
                return HBTRIE_RESULT_FAIL;
            }
            btreeitem_new->btree->setAux(aux);
            btreeitem_new->child_rootbid = BLK_NOT_FOUND;

            // insert new btree's bid into the previous btree
            bid_new = btreeitem_new->btree->getRootBid();
            btreeitem->child_rootbid = bid_new;
            _bid = _endian_encode(bid_new);
            valueSetMsb((void *)&_bid);
            r = btreeitem->btree->insert(chunk, &_bid);
            if (r == BTREE_RESULT_FAIL) {
                ret_result = HBTRIE_RESULT_FAIL;
                break;
            }

            // switch & go to the next tree
            chunk = (uint8_t*)key + midchunkno * chunksize;
            curchunkno = midchunkno;
            btreeitem = btreeitem_new;
        }
        if (ret_result != HBTRIE_RESULT_SUCCESS) {
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

            storeMeta(meta.size, newchunkno, opt, key + chunksize * (curchunkno+1),
                      (newchunkno - (curchunkno+1)) * chunksize, value_short, buf);

            btreeitem_new = (struct btreelist_item *)
                            mempool_alloc(sizeof(struct btreelist_item));
            btreeitem_new->btree = new BTree();
            btreeitem_new->chunkno = newchunkno;
            r = btreeitem_new->btree->init(btreeblk_handle, kv_ops, btree_nodesize,
                                           chunksize, valuelen, 0x0, &meta);
            list_push_back(&btreelist, &btreeitem_new->e);
            if (r == BTREE_RESULT_FAIL) {
                ret_result = HBTRIE_RESULT_FAIL;
                break;
            }
            btreeitem_new->btree->setAux(aux);

            chunk_new = (uint8_t*)key_long + newchunkno * chunksize;

            if (opt == HBMETA_LEAF) {
                // optimization mode
                setLeafKey(k, chunk_new, rawkeylen_long - newchunkno*chunksize);
                r = btreeitem_new->btree->insert(k, value_long);
                if (r == BTREE_RESULT_FAIL) {
                    ret_result = HBTRIE_RESULT_FAIL;
                }
                freeLeafKey(k);
            } else {
                // normal mode
                r = btreeitem_new->btree->insert(chunk_new, value_long);
                if (r == BTREE_RESULT_FAIL) {
                    ret_result = HBTRIE_RESULT_FAIL;
                }
            }

        } else {
            //3 2-2. create sub-tree
            // and insert two docs into it
            storeMeta(meta.size, newchunkno, opt, key + chunksize * (curchunkno+1),
                      (newchunkno - (curchunkno+1)) * chunksize, NULL, buf);

            btreeitem_new = (struct btreelist_item *)
                            mempool_alloc(sizeof(struct btreelist_item));
            btreeitem_new->btree = new BTree();
            btreeitem_new->chunkno = newchunkno;
            list_push_back(&btreelist, &btreeitem_new->e);

            r = btreeitem_new->btree->init(btreeblk_handle, kv_ops, btree_nodesize,
                                           chunksize, valuelen, 0x0, &meta);
            if (r == BTREE_RESULT_FAIL) {
                ret_result = HBTRIE_RESULT_FAIL;
            }
            btreeitem_new->btree->setAux(aux);

            // insert KEY
            chunk_new = key + newchunkno * chunksize;
            if (opt == HBMETA_LEAF) {
                // optimization mode
                setLeafKey(k, chunk_new, rawkeylen - newchunkno*chunksize);
                r = btreeitem_new->btree->insert(k, value);
                freeLeafKey(k);
            } else {
                r = btreeitem_new->btree->insert(chunk_new, value);
            }
            if (r == BTREE_RESULT_FAIL) {
                ret_result = HBTRIE_RESULT_FAIL;
            }

            // insert the original DOCKEY
            chunk_new = dockey + newchunkno * chunksize;
            if (opt == HBMETA_LEAF) {
                // optimization mode
                setLeafKey(k, chunk_new, docrawkeylen - newchunkno*chunksize);
                r = btreeitem_new->btree->insert(k, btree_value);
                freeLeafKey(k);
            } else {
                r = btreeitem_new->btree->insert(chunk_new, btree_value);
            }
            if (r == BTREE_RESULT_FAIL) {
                ret_result = HBTRIE_RESULT_FAIL;
            }
        }

        // update previous (parent) b-tree
        bid_new = btreeitem_new->btree->getRootBid();
        btreeitem->child_rootbid = bid_new;

        // set MSB
        _bid = _endian_encode(bid_new);
        valueSetMsb((void *)&_bid);
        // ASSUMPTION: parent b-tree always MUST be non-leaf b-tree
        r = btreeitem->btree->insert(chunk, (void*)&_bid);
        if (r == BTREE_RESULT_FAIL) {
            ret_result = HBTRIE_RESULT_FAIL;
        }

        break;
    } // while

    deallocateBuffer(&docrawkey, rawkey_buffer_index);
    deallocateBuffer(&dockey, key_buffer_index);

    // btreelist is cleaned up as part of btreeCascadedUpdate
    btreeCascadedUpdate(&btreelist, key);

    return ret_result;
}

hbtrie_result HBTrie::insert(void *rawkey, int rawkeylen,
                     void *value, void *oldvalue_out)
{
    return _insert(rawkey, rawkeylen, value, oldvalue_out, 0x0);
}

hbtrie_result HBTrie::insertPartial(void *rawkey, int rawkeylen,
                            void *value, void *oldvalue_out)
{
    return _insert(rawkey, rawkeylen, value, oldvalue_out, HBTRIE_PARTIAL_UPDATE);
}

size_t HBTrie::readKey(uint64_t offset, void *buf)
{
    // TODO: support seq-iterator can be executed without reading doc block
    return readkey(doc_handle, offset, NULL, NULL, 0, buf);
}

void HBTrie::initMemoryPool(size_t num_cores, uint64_t buffercache_size)
{
    /**
     * Allocate number of bins in the memory pool based on the
     * number of cores on the machine, and the buffer cache
     * size:
     *  - 2x the number of cores if buffer cache is default or greater
     *  - 75% the number of cores if buffer cache is less than default
     *    with a minimum number of 4.
     *
     * For example:
     * (1) with a 40 core machine, default buffer cache
     *      Number of bins: 2 * 40 = 30
     *      Memory consumption: 80 * 65536 / (1024 * 1024) = 5MB
     * (2) with a 4 core machine, buffer cache less than default
     *      Number of bins: std::max(HBTRIE_MEMPOOL_MIN_BINS,
     *                               0.75 * 4) = 4
     *      Memory consumption: 4 * 65536 / (1024 * 1024) = 0.25MB
     */
    int num_bins = 0;
    if (buffercache_size >= 134217728 /*default:128MB*/) {
        num_bins = static_cast<int>(2 * num_cores);
    } else {
        num_bins = std::max(HBTRIE_MEMPOOL_MIN_BINS,
                            static_cast<int>(0.75 * num_cores));
    }
    hbtrieMP = new MemoryPool(num_bins, HBTRIE_MAX_KEYLEN);
}

void HBTrie::shutdownMemoryPool()
{
    if (hbtrieMP) {
        delete hbtrieMP;
    }
}

const int HBTrie::allocateBuffer(uint8_t **buf) {
    if (hbtrieMP) {
        int index = hbtrieMP->fetchBlock(buf);
        if (index >= 0) {
            return index;
        }
    }
    *buf = (uint8_t *) malloc(HBTRIE_MAX_KEYLEN);
    return -1;
}

void HBTrie::deallocateBuffer(uint8_t **buf, int index) {
    if (hbtrieMP && index >= 0) {
        hbtrieMP->returnBlock(index);
    } else {
        free(*buf);
    }
}

HBTrieIterator::HBTrieIterator() :
    trie(), curkey(NULL), keylen(0), flags(0)
{
    list_init(&btreeit_list);
}

HBTrieIterator::HBTrieIterator(HBTrie* _trie, void *_initial_key, size_t _keylen) :
    trie(), curkey(NULL), keylen(0), flags(0)
{
    init(_trie, _initial_key, _keylen);
}

HBTrieIterator::~HBTrieIterator()
{
    struct list_elem *e;
    struct btreeit_item *item;
    BTree *btree;

    e = list_begin(&btreeit_list);
    while(e) {
        item = _get_entry(e, struct btreeit_item, le);
        e = list_remove(&btreeit_list, e);
        btree = item->btree_it->getBTree();
        delete item->btree_it;
        delete btree;
        mempool_free(item);
    }
    if (curkey) {
        free(curkey);
    }

    delete trie;
}

hbtrie_result HBTrieIterator::init(HBTrie* _trie, void *_initial_key, size_t _keylen)
{
    trie = new HBTrie(_trie);

    curkey = (void *)malloc(HBTRIE_MAX_KEYLEN);

    if (_initial_key) {
        keylen = trie->reformKey(_initial_key, _keylen, curkey);
        if (keylen >= HBTRIE_MAX_KEYLEN) {
            free(curkey);
            delete trie;

            DBG("Error: HBTrie iterator init fails because the init key length %d is "
                "greater than the max key length %d\n", keylen, HBTRIE_MAX_KEYLEN);
            return HBTRIE_RESULT_FAIL;
        }
        memset((uint8_t*)curkey + keylen, 0, trie->getChunkSize());
    }else{
        keylen = 0;
        memset(curkey, 0, trie->getChunkSize());
    }
    list_init(&btreeit_list);
    flags = 0x0;

    return HBTRIE_RESULT_SUCCESS;
}

// Recursive function
hbtrie_result HBTrieIterator::_prev(struct btreeit_item *item,
                                    void *key_buf,
                                    size_t& keylen_out,
                                    void *value_buf,
                                    uint8_t flag)
{
    struct list_elem *e;
    struct btreeit_item *item_new;
    BTree *btree;
    hbtrie_result hr = HBTRIE_RESULT_FAIL;
    btree_result br;
    struct hbtrie_meta hbmeta;
    struct btree_meta bmeta;
    void *chunk;
    uint8_t chunksize = trie->getChunkSize();
    uint8_t valuelen = trie->getValueLen();
    uint8_t *k = alca(uint8_t, chunksize);
    uint8_t *v = alca(uint8_t, valuelen);
    memset(k, 0, chunksize);
    memset(k, 0, valuelen);
    bid_t bid;
    uint64_t offset;

    if (item == NULL) {
        // this happens only when first call
        // create iterator for root b-tree
        if (trie->getRootBid() == BLK_NOT_FOUND) return HBTRIE_RESULT_FAIL;
        // set current chunk (key for b-tree)
        chunk = curkey;
        // load b-tree
        // Note that this instance will be inserted into btreeit_list, and
        // will be freed in the destructor of HBTrieIterator.
        btree = new BTree(trie->getBtreeBlkHandle(), trie->getBtreeKvOps(),
                          trie->getBtreeNodeSize(), trie->getRootBid());
        btree->setAux(trie->getAux());
        if (btree->getKSize() != chunksize || btree->getVSize() != valuelen) {
            if (((chunksize << 4) | valuelen) == btree->getKSize()) {
                // this is an old meta format
                delete btree;
                return HBTRIE_RESULT_INDEX_VERSION_NOT_SUPPORTED;
            }
            // B+tree root node is corrupted.
            delete btree;
            return HBTRIE_RESULT_INDEX_CORRUPTED;
        }

        item = (struct btreeit_item *)mempool_alloc(sizeof(
                                                    struct btreeit_item));
        item->btree_it = new BTreeIterator();
        item->chunkno = 0;
        item->leaf = 0;

        br = item->btree_it->init(btree, chunk);
        if (br == BTREE_RESULT_FAIL) {
            delete btree;
            return HBTRIE_RESULT_FAIL;
        }

        list_push_back(&btreeit_list, &item->le);
        // now we don't need to release 'btree' instance in this function.
    }

    e = list_next(&item->le);
    if (e) {
        // if prev sub b-tree exists
        item_new = _get_entry(e, struct btreeit_item, le);
        hr = _prev(item_new, key_buf, keylen_out, value_buf, flag);
        if (hr == HBTRIE_RESULT_SUCCESS) {
            return hr;
        }
        keylen = (item->chunkno+1) * chunksize;
    }

    while (hr != HBTRIE_RESULT_SUCCESS) {
        // get key-value from current b-tree iterator
        memset(k, 0, chunksize);
        br = item->btree_it->prev(k, v);
        if (item->leaf) {
            freeLeafKey(k);
        } else {
            chunk = (uint8_t*)curkey + item->chunkno * chunksize;
            if (item->btree_it->getBTreeKVOps()->cmp(k, chunk,
                    item->btree_it->getBTreeAux()) != 0) {
                // not exact match key .. the rest of string is not necessary anymore
                keylen = (item->chunkno+1) * chunksize;
                flagsSetMoved();
            }
        }

        if (br == BTREE_RESULT_FAIL) {
            // no more KV pair in the b-tree
            BTree *_btree = item->btree_it->getBTree();
            delete item->btree_it;
            delete _btree;
            list_remove(&btreeit_list, &item->le);
            mempool_free(item);
            return HBTRIE_RESULT_FAIL;
        }

        // check whether v points to doc or sub b-tree
        if (trie->valueIsMsbSet(v)) {
            // MSB is set -> sub b-tree

            // load sub b-tree and create new iterator for the b-tree
            trie->valueClearMsb(v);
            bid = trie->getBtreeKvOps()->value2bid(v);
            bid = _endian_decode(bid);
            // it will be inserted into item_new, and will be freed in
            // the destructor of HBTrieIterator.
            btree = new BTree(trie->getBtreeBlkHandle(),
                              trie->getBtreeKvOps(), trie->getBtreeNodeSize(), bid);

            // get sub b-tree's chunk number
            bmeta.data = (void *)mempool_alloc(trie->getBtreeNodeSize());
            bmeta.size = btree->readMeta(bmeta.data);
            trie->fetchMeta(bmeta.size, &hbmeta, bmeta.data);

            item_new = (struct btreeit_item *)
                       mempool_alloc(sizeof(struct btreeit_item));
            if (_is_leaf_btree(hbmeta.chunkno)) {
                trie->setLastMapChunk(curkey);
                btree->setKVOps(trie->getBtreeLeafKvOps());
                item_new->leaf = 1;
            } else {
                item_new->leaf = 0;
            }
            btree->setAux(trie->getAux());
            hbmeta.chunkno = _get_chunkno(hbmeta.chunkno);
            item_new->chunkno = hbmeta.chunkno;

            // Note: if user's key is exactly aligned to chunk size, then the
            //       dummy chunk will be a zero-filled value, and it is used
            //       as a key in the next level of B+tree. Hence, there will be
            //       no problem to assign the dummy chunk to the 'chunk' variable.
            if ( (unsigned)((item_new->chunkno+1) * chunksize) <= keylen ) {
                // happen only once for the first call (for each level of b-trees)
                chunk = (uint8_t*)curkey + item_new->chunkno * chunksize;
                if (item->chunkno+1 < item_new->chunkno) {
                    // skipped prefix exists
                    // Note: all skipped chunks should be compared using the default
                    //       cmp function
                    int i, offset_meta = 0, offset_key = 0, chunkcmp = 0;
                    for (i=item->chunkno+1; i<item_new->chunkno; ++i) {
                        offset_meta = chunksize * (i - (item->chunkno+1));
                        offset_key = chunksize * i;
                        chunkcmp = trie->getBtreeKvOps()->cmp(
                            (uint8_t*)curkey + offset_key,
                            (uint8_t*)hbmeta.prefix + offset_meta,
                            trie->getAux());
                        if (chunkcmp < 0) {
                            // start_key's prefix is smaller than the skipped prefix
                            // we have to go back to parent B+tree and pick prev entry
                            mempool_free(bmeta.data);
                            mempool_free(item_new);
                            delete btree;
                            keylen = offset_key;
                            hr = HBTRIE_RESULT_FAIL;
                            flagsSetMoved();
                            break;
                        } else if (chunkcmp > 0 && chunksize > 0) {
                            // start_key's prefix is gerater than the skipped prefix
                            // set largest key for next B+tree
                            chunk = alca(uint8_t, chunksize);
                            memset(chunk, 0xff, chunksize);
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
                if (!flagsIsMoved()) {
                    // The first prev call right after iterator init call.
                    // This means that the init key is smaller than
                    // the smallest key of the current tree, and larger than
                    // the largest key of the previous tree.
                    // So we have to go back to the parent tree, and
                    // return the largest key of the previous tree.
                    mempool_free(bmeta.data);
                    mempool_free(item_new);
                    delete btree;
                    keylen = (item->chunkno + 1) * chunksize;
                    flagsSetMoved();
                    continue;
                }
                // set largest key
                chunk = alca(uint8_t, chunksize);
                memset(chunk, 0xff, chunksize);
            }

            item_new->btree_it = new BTreeIterator();
            if (item_new->leaf && chunk && chunksize > 0) {
                uint8_t *k_temp = alca(uint8_t, chunksize);
                size_t _leaf_keylen, _leaf_keylen_raw = 0;

                _leaf_keylen = keylen - (item_new->chunkno * chunksize);
                if (_leaf_keylen) {
                    trie->reformKeyReverse(chunk, _leaf_keylen);
                    setLeafKey(k_temp, chunk, _leaf_keylen_raw);
                    if (_leaf_keylen_raw) {
                        item_new->btree_it->init(btree, k_temp);
                    } else {
                        item_new->btree_it->init(btree, NULL);
                    }
                } else {
                    // set initial key as the largest key
                    // for reverse scan from the end of the B+tree
                    setLeafInfKey(k_temp);
                    item_new->btree_it->init(btree, k_temp);
                }
                freeLeafKey(k_temp);
            } else {
                item_new->btree_it->init(btree, chunk);
            }
            list_push_back(&btreeit_list, &item_new->le);

            if (hbmeta.value && chunk == NULL) {
                // NULL key exists .. the smallest key in this tree .. return first
                offset = trie->getBtreeKvOps()->value2bid(hbmeta.value);
                if (!(flag & HBTRIE_PREFIX_MATCH_ONLY)) {
                    keylen_out = trie->readKey(offset, key_buf);
                    keylen = trie->reformKey(key_buf, keylen_out, curkey);
                }
                memcpy(value_buf, &offset, valuelen);
                hr = HBTRIE_RESULT_SUCCESS;
            } else {
                hr = _prev(item_new, key_buf, keylen_out, value_buf, flag);
            }
            mempool_free(bmeta.data);
            if (hr == HBTRIE_RESULT_SUCCESS)
                return hr;

            // fail searching .. get back to parent tree
            // (this happens when the initial key is smaller than
            // the smallest key in the current tree (ITEM_NEW) ..
            // so return back to ITEM and retrieve next child)
            keylen = (item->chunkno+1) * chunksize;
            flagsSetMoved();

        } else {
            // MSB is not set -> doc
            // read entire key and return the doc offset
            offset = trie->getBtreeKvOps()->value2bid(v);
            if (!(flag & HBTRIE_PREFIX_MATCH_ONLY)) {
                keylen_out = trie->readKey(offset, key_buf);
                keylen = trie->reformKey(key_buf, keylen_out, curkey);
            }
            memcpy(value_buf, &offset, valuelen);

            return HBTRIE_RESULT_SUCCESS;
        }
    }
    return HBTRIE_RESULT_FAIL;
}

hbtrie_result HBTrieIterator::prev(void *key_buf, size_t& keylen_out, void *value_buf)
{
    hbtrie_result hr;

    if (flagsIsRev() && flagsIsFailed()) {
        return HBTRIE_RESULT_FAIL;
    }

    struct list_elem *e = list_begin(&btreeit_list);
    struct btreeit_item *item = NULL;
    if (e) item = _get_entry(e, struct btreeit_item, le);

    hr = _prev(item, key_buf, keylen_out, value_buf, 0x0);
    flagsSetRev();
    if (hr == HBTRIE_RESULT_SUCCESS) {
        flagsClrFailed();
        flagsSetMoved();
    } else {
        flagsSetFailed();
    }
    return hr;
}

hbtrie_result HBTrieIterator::_next(struct btreeit_item *item,
                                    void *key_buf,
                                    size_t& keylen_out,
                                    void *value_buf,
                                    uint8_t flag)
{
    struct list_elem *e;
    struct btreeit_item *item_new;
    BTree *btree;
    hbtrie_result hr = HBTRIE_RESULT_FAIL;
    btree_result br;
    struct hbtrie_meta hbmeta;
    struct btree_meta bmeta;
    void *chunk;
    uint8_t chunksize = trie->getChunkSize();
    uint8_t valuelen = trie->getValueLen();
    uint8_t *k = alca(uint8_t, chunksize);
    uint8_t *v = alca(uint8_t, valuelen);
    bid_t bid;
    uint64_t offset;

    if (item == NULL) {
        // this happens only when first call
        // create iterator for root b-tree
        if (trie->getRootBid() == BLK_NOT_FOUND) return HBTRIE_RESULT_FAIL;
        // set current chunk (key for b-tree)
        chunk = curkey;
        // load b-tree
        // Note that this instance will be inserted into btreeit_list, and
        // will be freed in the destructor of HBTrieIterator.
        btree = new BTree(trie->getBtreeBlkHandle(), trie->getBtreeKvOps(),
                          trie->getBtreeNodeSize(), trie->getRootBid());
        btree->setAux(trie->getAux());
        if (btree->getKSize() != chunksize || btree->getVSize() != valuelen) {
            if (((chunksize << 4) | valuelen) == btree->getKSize()) {
                // this is an old meta format
                delete btree;
                return HBTRIE_RESULT_INDEX_VERSION_NOT_SUPPORTED;
            }
            // B+tree root node is corrupted.
            delete btree;
            return HBTRIE_RESULT_INDEX_CORRUPTED;
        }

        item = (struct btreeit_item *)mempool_alloc(sizeof(struct btreeit_item));
        item->chunkno = 0;
        item->leaf = 0;
        item->btree_it = new BTreeIterator();

        br = item->btree_it->init(btree, chunk);
        if (br == BTREE_RESULT_FAIL) return HBTRIE_RESULT_FAIL;

        list_push_back(&btreeit_list, &item->le);
    }

    e = list_next(&item->le);
    if (e) {
        // if next sub b-tree exists
        item_new = _get_entry(e, struct btreeit_item, le);
        hr = _next(item_new, key_buf, keylen_out, value_buf, flag);
        if (hr != HBTRIE_RESULT_SUCCESS) {
            keylen = (item->chunkno+1) * chunksize;
        }
    }

    while (hr != HBTRIE_RESULT_SUCCESS) {
        // get key-value from current b-tree iterator
        memset(k, 0, chunksize);
        br = item->btree_it->next(k, v);
        if (item->leaf) {
            freeLeafKey(k);
        } else {
            chunk = (uint8_t*)curkey + item->chunkno * chunksize;
            if (item->btree_it->getBTreeKVOps()->cmp(k, chunk,
                    item->btree_it->getBTreeAux()) != 0) {
                // not exact match key .. the rest of string is not necessary anymore
                keylen = (item->chunkno+1) * chunksize;
                flagsSetMoved();
            }
        }

        if (br == BTREE_RESULT_FAIL) {
            // no more KV pair in the b-tree
            BTree *_btree = item->btree_it->getBTree();
            delete item->btree_it;
            delete _btree;
            list_remove(&btreeit_list, &item->le);
            mempool_free(item);
            return HBTRIE_RESULT_FAIL;
        }

        if (flag & HBTRIE_PARTIAL_MATCH) {
            // in partial match mode, we don't read actual doc key,
            // and just store & return indexed part of key.
            memcpy((uint8_t*)curkey + item->chunkno * chunksize, k, chunksize);
        }

        // check whether v points to doc or sub b-tree
        if (trie->valueIsMsbSet(v)) {
            // MSB is set -> sub b-tree

            // load sub b-tree and create new iterator for the b-tree
            trie->valueClearMsb(v);
            bid = trie->getBtreeKvOps()->value2bid(v);
            bid = _endian_decode(bid);
            // it will be inserted into item_new, and will be freed in
            // the destructor of HBTrieIterator.
            btree = new BTree(trie->getBtreeBlkHandle(),
                              trie->getBtreeKvOps(), trie->getBtreeNodeSize(), bid);

            // get sub b-tree's chunk number
            bmeta.data = (void *)mempool_alloc(trie->getBtreeNodeSize());
            bmeta.size = btree->readMeta(bmeta.data);
            trie->fetchMeta(bmeta.size, &hbmeta, bmeta.data);

            item_new = (struct btreeit_item *)
                       mempool_alloc(sizeof(struct btreeit_item));
            if (_is_leaf_btree(hbmeta.chunkno)) {
                trie->setLastMapChunk(curkey);
                btree->setKVOps(trie->getBtreeLeafKvOps());
                item_new->leaf = 1;
            } else {
                item_new->leaf = 0;
            }
            btree->setAux(trie->getAux());
            hbmeta.chunkno = _get_chunkno(hbmeta.chunkno);
            item_new->chunkno = hbmeta.chunkno;

            // Note: if user's key is exactly aligned to chunk size, then the
            //       dummy chunk will be a zero-filled value, and it is used
            //       as a key in the next level of B+tree. Hence, there will be
            //       no problem to assign the dummy chunk to the 'chunk' variable.
            if ( (unsigned)((item_new->chunkno+1) * chunksize) <= keylen) {
                // happen only once for the first call (for each level of b-trees)
                chunk = (uint8_t*)curkey + item_new->chunkno*chunksize;
                if (item->chunkno+1 < item_new->chunkno) {
                    // skipped prefix exists
                    // Note: all skipped chunks should be compared using the default
                    //       cmp function
                    int i, offset_meta = 0, offset_key = 0, chunkcmp = 0;
                    for (i=item->chunkno+1; i<item_new->chunkno; ++i) {
                        offset_meta = chunksize * (i - (item->chunkno+1));
                        offset_key = chunksize * i;
                        chunkcmp = trie->getBtreeKvOps()->cmp(
                            (uint8_t*)curkey + offset_key,
                            (uint8_t*)hbmeta.prefix + offset_meta,
                            trie->getAux());
                        if (chunkcmp < 0) {
                            // start_key's prefix is smaller than the skipped prefix
                            // set smallest key for next B+tree
                            keylen = offset_key;
                            chunk = NULL;
                            break;
                        } else if (chunkcmp > 0) {
                            // start_key's prefix is gerater than the skipped prefix
                            // we have to go back to parent B+tree and pick next entry
                            mempool_free(bmeta.data);
                            mempool_free(item_new);
                            delete btree;
                            keylen = offset_key;
                            hr = HBTRIE_RESULT_FAIL;
                            flagsSetMoved();
                            break;
                        }
                    }
                    if (chunkcmp > 0) {
                        // go back to parent B+tree
                        continue;
                    }
                }
            } else {
                // chunk number of the b-tree is longer than current iterator's key
                // set smallest key
                chunk = NULL;
            }

            item_new->btree_it = new BTreeIterator();
            if (item_new->leaf && chunk && chunksize > 0) {
                uint8_t *k_temp = alca(uint8_t, chunksize);
                memset(k_temp, 0, chunksize * sizeof(uint8_t));
                size_t _leaf_keylen, _leaf_keylen_raw = 0;

                _leaf_keylen = keylen - (item_new->chunkno * chunksize);
                if (_leaf_keylen > 0) {
                    _leaf_keylen_raw = trie->reformKeyReverse(chunk, _leaf_keylen);
                }
                if (_leaf_keylen_raw) {
                    setLeafKey(k_temp, chunk, _leaf_keylen_raw);
                    item_new->btree_it->init(btree, k_temp);
                    freeLeafKey(k_temp);
                } else {
                    item_new->btree_it->init(btree, NULL);
                }
            } else {
                bool null_btree_init_key = false;
                if (!flagsIsMoved() && chunk && chunksize > 0 &&
                    ((uint64_t)item_new->chunkno+1) * chunksize == keylen) {
                    // Next chunk is the last chunk of the current iterator key
                    // (happens only on iterator_init(), it internally calls next()).
                    uint8_t *k_temp = alca(uint8_t, chunksize);
                    memset(k_temp, 0x0, chunksize);
                    k_temp[chunksize - 1] = chunksize;
                    if (!memcmp(k_temp, chunk, chunksize)) {
                        // Extra chunk is same to the specific pattern
                        // ([0x0] [0x0] ... [trie->chunksize])
                        // which means that given iterator key is exactly aligned
                        // to chunk size and shorter than the position of the
                        // next chunk.
                        // To guarantee lexicographical order between
                        // NULL and zero-filled key (NULL < 0x0000...),
                        // we should init btree iterator with NULL key.
                        null_btree_init_key = true;
                    }
                }
                if (null_btree_init_key) {
                    item_new->btree_it->init(btree, NULL);
                } else {
                    item_new->btree_it->init(btree, chunk);
                }
            }
            list_push_back(&btreeit_list, &item_new->le);

            if (hbmeta.value && chunk == NULL) {
                // NULL key exists .. the smallest key in this tree .. return first
                offset = trie->getBtreeKvOps()->value2bid(hbmeta.value);
                if (flag & HBTRIE_PARTIAL_MATCH) {
                    // return indexed key part only
                    keylen_out = (item->chunkno+1) * chunksize;
                    memcpy(key_buf, curkey, keylen_out);
                } else if (!(flag & HBTRIE_PREFIX_MATCH_ONLY)) {
                    // read entire key from doc's meta
                    keylen_out = trie->readKey(offset, key_buf);
                    keylen = trie->reformKey(key_buf, keylen_out, curkey);
                }
                memcpy(value_buf, &offset, valuelen);
                hr = HBTRIE_RESULT_SUCCESS;
            } else {
                hr = _next(item_new, key_buf, keylen_out, value_buf, flag);
            }
            mempool_free(bmeta.data);
            if (hr == HBTRIE_RESULT_SUCCESS) {
                return hr;
            }

            // fail searching .. get back to parent tree
            // (this happens when the initial key is greater than
            // the largest key in the current tree (ITEM_NEW) ..
            // so return back to ITEM and retrieve next child)
            keylen = (item->chunkno+1) * chunksize;

        } else {
            // MSB is not set -> doc
            // read entire key and return the doc offset
            offset = trie->getBtreeKvOps()->value2bid(v);
            if (flag & HBTRIE_PARTIAL_MATCH) {
                // return indexed key part only
                keylen_out = (item->chunkno+1) * chunksize;
                memcpy(key_buf, curkey, keylen_out);
            } else if (!(flag & HBTRIE_PREFIX_MATCH_ONLY)) {
                // read entire key from doc's meta
                keylen_out = trie->readKey(offset, key_buf);
                keylen = trie->reformKey(key_buf, keylen_out, curkey);
            }
            memcpy(value_buf, &offset, valuelen);

            return HBTRIE_RESULT_SUCCESS;
        }
    }

    return hr;
}

hbtrie_result HBTrieIterator::next(void *key_buf,
                                   size_t& keylen_out,
                                   void *value_buf)
{
    hbtrie_result hr;

    if (flagsIsFwd() && flagsIsFailed()) {
        return HBTRIE_RESULT_FAIL;
    }

    struct list_elem *e = list_begin(&btreeit_list);
    struct btreeit_item *item = NULL;
    if (e) item = _get_entry(e, struct btreeit_item, le);

    hr = _next(item, key_buf, keylen_out, value_buf, 0x0);
    flagsSetFwd();
    if (hr == HBTRIE_RESULT_SUCCESS) {
        flagsClrFailed();
        flagsSetMoved();
    } else {
        flagsSetFailed();
    }
    return hr;

}

hbtrie_result HBTrieIterator::nextPartial(void *key_buf,
                                          size_t& keylen_out,
                                          void *value_buf)
{
    hbtrie_result hr;

    if (flagsIsFwd() && flagsIsFailed()) {
        return HBTRIE_RESULT_FAIL;
    }

    struct list_elem *e = list_begin(&btreeit_list);
    struct btreeit_item *item = NULL;
    if (e) item = _get_entry(e, struct btreeit_item, le);

    hr = _next(item, key_buf, keylen_out, value_buf, HBTRIE_PARTIAL_MATCH);
    flagsSetFwd();
    if (hr == HBTRIE_RESULT_SUCCESS) {
        flagsClrFailed();
        flagsSetMoved();
    } else {
        flagsSetFailed();
    }
    return hr;

}

hbtrie_result HBTrieIterator::nextValueOnly(void *value_buf)
{
    size_t keylen_temp = 0;
    hbtrie_result hr;

    if (curkey == NULL) {
        return HBTRIE_RESULT_FAIL;
    }

    struct list_elem *e = list_begin(&btreeit_list);
    struct btreeit_item *item = NULL;
    if (e) item = _get_entry(e, struct btreeit_item, le);

    hr = _next(item, NULL, keylen_temp, value_buf, HBTRIE_PREFIX_MATCH_ONLY);
    if (hr != HBTRIE_RESULT_SUCCESS) {
        // this iterator reaches the end of hb-trie
        free(curkey);
        curkey = NULL;
    }
    return hr;
}

// move iterator's cursor to the end of the key range.
// hbtrie_prev() call after hbtrie_last() will return the last key.
hbtrie_result HBTrieIterator::last()
{
    // free btreeit_list
    struct list_elem *e;
    struct btreeit_item *item;
    BTree *btree;

    e = list_begin(&btreeit_list);
    while(e) {
        item = _get_entry(e, struct btreeit_item, le);
        e = list_remove(&btreeit_list, e);
        btree = item->btree_it->getBTree();
        delete item->btree_it;
        delete btree;
        mempool_free(item);
    }

    // reset last_map_chunk to 0xff..
    trie->resetLastMapChunk();

    // init 'curkey'with the infinite (0xff..) key without reforming
    memset(curkey, 0xff, trie->getChunkSize());
    keylen = trie->getChunkSize();

    list_init(&btreeit_list);
    flags = 0x0;

    return HBTRIE_RESULT_SUCCESS;
}

