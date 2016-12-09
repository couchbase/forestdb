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
#include "btreeblock.h"
#include "btree_new.h"
#include "btree_kv.h"
#include "btree_fast_str_kv.h"
#include "internal_types.h"
#include "version.h"
#include "fdb_internal.h"

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

typedef enum {
    HBMETA_NORMAL,
    HBMETA_LEAF,
} hbmeta_opt;

struct btreelist_item {
    struct list_elem e;
    BTree btree;
    bid_t child_rootbid;
    chunkno_t chunkno;
    uint8_t leaf;
};

struct btreeit_item {
    struct list_elem le;
    BTree btree;
    BTreeIterator *btree_it;
    chunkno_t chunkno;
    uint8_t leaf;
};
#define _is_leaf_btree(chunkno) (chunkno & CUSTOM_COMPARE_MODE)
#define _get_chunkno(chunkno) (chunkno & ~CUSTOM_COMPARE_MODE)

#define HBTRIE_PREFIX_MATCH_ONLY (0x1)
#define HBTRIE_PARTIAL_MATCH (0x2)

#define HBTRIE_PARTIAL_UPDATE (0x1)

#define HBTRIE_MEMPOOL_MIN_BINS 4

const size_t HBTrie::HV_SIZE(9);
const size_t HBTrie::HV_BUF_MAX_SIZE(256);
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
    root_bid(0), rootAddr(), btreeblk_handle(NULL), fileHB(NULL), doc_handle(NULL),
    btree_kv_ops(NULL), btree_leaf_kv_ops(NULL), readkey(NULL), map(NULL),
    last_map_chunk(NULL), getCmpFuncCB(nullptr)
{
    aux = &cmp_args;
}

HBTrie::HBTrie(HBTrie *_trie)
{
    initTrie(_trie->getChunkSize(), _trie->getValueLen(),
             _trie->getBtreeNodeSize(), _trie->getRootBid(),
             _trie->getRootAddr(), _trie->getBtreeBlkHandle(),
             _trie->getFileMgr(), _trie->getDocHandle(),
             _trie->getReadKey());
}

HBTrie::HBTrie(int _chunksize, int _valuelen, int _btree_nodesize,
               bid_t _root_bid, BTreeBlkHandle* _btreeblk_handle,
               void* _doc_handle, hbtrie_func_readkey* _readkey)
{
    initTrie(_chunksize, _valuelen, _btree_nodesize, _root_bid, BtreeNodeAddr(),
             _btreeblk_handle, _btreeblk_handle->getFile(), _doc_handle,
             _readkey);
}

HBTrie::HBTrie(int _chunksize, int _btree_nodesize,
               BtreeNodeAddr _root_addr, BnodeMgr* _bnodeMgr, FileMgr *_file)
{
    initTrie(_chunksize, HV_SIZE, _btree_nodesize, BLK_NOT_FOUND,
             _root_addr, _bnodeMgr, _file, nullptr, nullptr);
    rootAddr = _root_addr;
}

HBTrie::~HBTrie()
{
    delete btree_kv_ops;
    delete btree_leaf_kv_ops;
    freeLastMapChunk();
}

void HBTrie::initTrie(int _chunksize, int _valuelen, int _btree_nodesize,
                      bid_t _root_bid, BtreeNodeAddr _root_addr,
                      void* _btreestorage_handle,
                      FileMgr *_file, void* _doc_handle,
                      hbtrie_func_readkey* _readkey)
{
    chunksize = _chunksize;
    valuelen = _valuelen;
    btree_nodesize = _btree_nodesize;
    root_bid = _root_bid;
    rootAddr = _root_addr;
    fileHB = _file;
    if (!_doc_handle) {
        bnodeMgr = reinterpret_cast<BnodeMgr *>(_btreestorage_handle);
        doc_handle = nullptr;
    } else {
        btreeblk_handle = reinterpret_cast<BTreeBlkHandle *>(_btreestorage_handle);
        doc_handle = _doc_handle;
    }
    readkey = _readkey;
    flag = 0x0;
    leaf_height_limit = 0;
    map = NULL;
    getCmpFuncCB = nullptr;

    // assign key-value operations
    if (ver_btreev2_format(fileHB->getVersion())) {
        fdb_assert(valuelen == HV_SIZE, valuelen, this);
    } else {
        fdb_assert(valuelen == 8, valuelen, this);
    }
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

    if (!hbmeta || !buf) {
        if (hbmeta) {
            memset(hbmeta, 0x0, sizeof(struct hbtrie_meta));
        }
        return;
    }

    memcpy(&hbmeta->chunkno, buf, sizeof(hbmeta->chunkno));
    hbmeta->chunkno = _endian_decode(hbmeta->chunkno);
    offset += sizeof(hbmeta->chunkno);

    memcpy(&hbmeta->value_len, (uint8_t*)buf+offset, sizeof(hbmeta->value_len));
    offset += sizeof(hbmeta->value_len);

    if (hbmeta->value_len > 0) {
        hbmeta->value = (uint8_t*)buf + offset;
        offset += hbmeta->value_len;
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

metasize_t HBTrie::estMetaSize(void *value,
                               uint8_t value_len,
                               uint16_t prefix_len)
{
    metasize_t metasize_out = 0;

    // chunk number
    metasize_out += sizeof(chunkno_t);

    // value length
    metasize_out += sizeof(value_len);
    if (value) {
        // meta section includes value
        // (there is a key which is exactly the same with the
        //  prefix of this tree).
        // => add value length.
        metasize_out += value_len;
    }

    // prefix length
    metasize_out += prefix_len;

    return metasize_out;
}

void HBTrie::storeMeta(metasize_t& metasize_out,
                       chunkno_t chunkno,
                       hbmeta_opt opt,
                       void *prefix,
                       int prefixlen,
                       void *value,
                       uint8_t value_length,
                       void *buf)
{
    chunkno_t _chunkno;

    // write hbmeta to buf
    metasize_out = 0;

    if (opt == HBMETA_LEAF) {
        chunkno |= CUSTOM_COMPARE_MODE;
    }

    _chunkno = _endian_encode(chunkno);
    memcpy(buf, &_chunkno, sizeof(chunkno));
    metasize_out += sizeof(chunkno);

    if (value) {
        memcpy((uint8_t*)buf + metasize_out,
               &value_length, sizeof(value_length));
        metasize_out += sizeof(value_length);
        memcpy((uint8_t*)buf + metasize_out,
               value, value_length);
        metasize_out += value_length;
    } else {
        memset((uint8_t*)buf + metasize_out, 0x0, sizeof(value_length));
        metasize_out += sizeof(value_length);
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

        if (btreeitem->child_rootbid != btreeitem_child->btree.getRootBid()) {
            // root node of child sub-tree has been moved to another block
            // update parent sub-tree
            bid_new = btreeitem_child->btree.getRootBid();
            _bid = _endian_encode(bid_new);
            valueSetMsb((void *)&_bid);
            btreeitem->btree.insert((uint8_t*)key + btreeitem->chunkno * chunksize,
                                     (void *)&_bid);
        }
        e_child = e;
        e = list_prev(e);
    }

    // update trie root bid
    if (e) {
        btreeitem = _get_entry(e, struct btreelist_item, e);
        root_bid = btreeitem->btree.getRootBid();
    } else if (e_child) {
        btreeitem = _get_entry(e_child, struct btreelist_item, e);
        root_bid = btreeitem->btree.getRootBid();
    } else {
        fdb_assert(0, this, e_child);
    }

    freeBtreeList(btreelist);
}

hbtrie_result HBTrie::writeDirtyNodes()
{
    if (!rootAddr.isDirty) {
        // root node is clean
        //  => there was no update.
        return HBTRIE_RESULT_SUCCESS;
    }

    // load b+tree from the addr
    BtreeV2Result br;
    BtreeV2 root_btree;
    root_btree.setBMgr(bnodeMgr);
    br = root_btree.initFromAddr(rootAddr);
    if (br != BtreeV2Result::SUCCESS) {
        return HBTRIE_RESULT_FAIL;
    }

    br = root_btree.writeDirtyNodes(true);
    if (br == BtreeV2Result::SUCCESS) {
        rootAddr = root_btree.getRootAddr();
    }
    return convertBtreeResult(br);
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
        list_push_back(btreelist, &btreeitem->e);
        btree = &btreeitem->btree;
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
                    list_push_back(btreelist, &btreeitem->e);
                    btree = &btreeitem->btree;
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

// Recursive function.
hbtrie_result HBTrie::_findV2(void *rawkey,
                              size_t rawkeylen,
                              void *given_valuebuf,
                              size_t *value_len_out,
                              HBTrieV2Args args,
                              HBTrieV2Rets& rets,
                              bool remove_key)
{
    size_t cur_chunk_no = 0;
    uint8_t hv_buf[HV_BUF_MAX_SIZE];

    BtreeV2 cur_btree;
    BtreeV2Meta bmeta;
    BtreeV2Result br;
    hbtrie_result hr;

    //struct btree btree, btree_new;
    struct hbtrie_meta hbmeta;

    // read from root
    cur_btree.setBMgr(bnodeMgr);
    br = cur_btree.initFromAddr(args.rootAddr);
    if (br != BtreeV2Result::SUCCESS) {
        return HBTRIE_RESULT_FAIL;
    }

    MPWrapper meta_buffer;
    meta_buffer.allocate();
    bmeta = BtreeV2Meta(cur_btree.getMetaSize(), meta_buffer.getAddr());
    cur_btree.readMeta(bmeta);
    fetchMeta(bmeta.size, &hbmeta, bmeta.ctx);

    cur_chunk_no = hbmeta.chunkno;
    if (cur_chunk_no) {
        // If this is not the root B+tree (cur_chunk_no > 0),
        // set custom cmp function if exists.
        // Note that root B+tree does not use custom cmp function,
        // since it stores KVS ID which always should be in a
        // lexicographical order.
        cur_btree.setCmpFunc(getCmpFuncForGivenKey(rawkey));
    }

    // check if there is a skipped prefix.
    if (cur_chunk_no > args.prevChunkNo + 1) {
        // compare with prefix in the meta section
        void *prefix_from_rawkey = static_cast<uint8_t*>(rawkey) +
                                   ((args.prevChunkNo+1) * chunksize);
        if (memcmp(prefix_from_rawkey, hbmeta.prefix, hbmeta.prefix_len)) {
            // prefix mismatch, return fail
            return HBTRIE_RESULT_FAIL;
        }
    }

    if (rawkeylen == cur_chunk_no * chunksize) {
        // given key is exactly same as the current b+tree's prefix
        // return the value in meta section
        if (!hbmeta.value) {
            // value is NULL, which implies key not found.
            return HBTRIE_RESULT_FAIL;
        }

        if (given_valuebuf) {
            HBTrieValue hv_meta(hbmeta.value, hbmeta.value_len);
            hv_meta.toBinaryWithoutFlags(given_valuebuf);
            if (value_len_out) {
                *value_len_out = hv_meta.sizeWithoutFlags();
            }
        }

        if (remove_key) {
            // remove the value in the meta section
            metasize_t metasize = 0;
            MPWrapper new_meta_buffer;
            new_meta_buffer.allocate();

            storeMeta( metasize, cur_chunk_no, HBMETA_NORMAL,
                       hbmeta.prefix, hbmeta.prefix_len,
                       nullptr, 0, new_meta_buffer.getAddr() );
            cur_btree.updateMeta(BtreeV2Meta(metasize, new_meta_buffer.getAddr()));
            rets.rootAddr = cur_btree.getRootAddr();
        }
        return HBTRIE_RESULT_SUCCESS;
    }

    // search the current b+tree
    void *chunk = static_cast<uint8_t*>(rawkey) + (cur_chunk_no * chunksize);

    // e.g.) chunksize = 8, rawkeylen = 11
    // 1) if cur_chunk_no = 1,
    //    => cur_chunklen = 3 (rest of string)
    // 2) if cur_chunk_no = 0,
    //    => cur_chunklen = 8 (regular chunk size)
    size_t suffix_len = rawkeylen - (cur_chunk_no * chunksize);
    size_t cur_chunklen = std::min(suffix_len, static_cast<size_t>(chunksize));
    MPWrapper key_buffer;

    BtreeKvPair kv_from_btree;
    // If custom cmp function is assigned, we cannot split the key
    // into multiple chunks as it is not in a lexicographical order.
    // So there are always 2-levels of trees in custom cmp mode:
    // chunk 0 (KVS ID) and chunk 1 (actual key).
    // We directly compare the entire key in this case.
    if (cur_chunklen < chunksize || cur_btree.getCmpFunc()) {
        // if suffix length is smaller than a chunk size, OR
        // custom cmp mode
        //  => no sub-tree related processes, just find an exact match key.
        kv_from_btree = BtreeKvPair(chunk, suffix_len, hv_buf, 0);
        br = cur_btree.find(kv_from_btree, false);
    } else {
        // if suffix length is equal to or longer than a chunk size
        //  => find any key whose prefix is same to the chunk.
        //     e.g.) chunk = 'aa'
        //           find aa, aaa, aab, aac ...
        key_buffer.allocate();
        memcpy(key_buffer.getAddr(), chunk, chunksize);
        kv_from_btree = BtreeKvPair(key_buffer.getAddr(), chunksize, hv_buf, 0);
        br = cur_btree.findGreaterOrEqual(kv_from_btree, false);
    }

    if (br != BtreeV2Result::SUCCESS) {
        // key not found.
        return HBTRIE_RESULT_FAIL;
    }

    HBTrieValue hv_from_btree(kv_from_btree.value, kv_from_btree.valuelen);

    // if the length of key from btree is chunksize,
    // check if it points to sub-tree.
    if (hv_from_btree.isSubtree()) {
        BtreeNodeAddr next_root;
        if (hv_from_btree.isDirtyRoot()) {
            // dirty root node => offset is memory address
            next_root = BtreeNodeAddr(BLK_NOT_FOUND, hv_from_btree.getChildPtr());
        } else {
            // clean root node
            next_root = BtreeNodeAddr(hv_from_btree.getOffset(), nullptr );
        }

        HBTrieV2Args next_args(cur_chunk_no, next_root);
        HBTrieV2Rets local_rets;
        hr = _findV2(rawkey, rawkeylen,
                     given_valuebuf, value_len_out,
                     next_args, local_rets, remove_key);

        if (hr == HBTRIE_RESULT_SUCCESS && remove_key) {
            if (next_root != local_rets.rootAddr) {
                // child B+tree's root node has been changed.
                if (local_rets.rootAddr.isEmpty) {
                    // child B+tree becomes empty => remove {key, ptr} pair.
                    br = cur_btree.remove(kv_from_btree);
                } else {
                    // otherwise => update {key, ptr} pair
                    HBTrieValue hv_new_ptr(local_rets.rootAddr);
                    kv_from_btree = BtreeKvPair(kv_from_btree.key, kv_from_btree.keylen,
                                                hv_new_ptr.toBinary(hv_buf), hv_new_ptr.size());
                    br = cur_btree.insert(kv_from_btree);
                }
                hr = convertBtreeResult(br);
            }
            rets.rootAddr = cur_btree.getRootAddr();
        }
        return hr;
    }

    // otherwise, compare key
    if (kv_from_btree.keylen == suffix_len &&
        !memcmp(chunk, kv_from_btree.key, suffix_len)) {
        // same key
        HBTrieValue hv_from_btree(kv_from_btree.value, kv_from_btree.valuelen);

        if (given_valuebuf) {
            hv_from_btree.toBinaryWithoutFlags(given_valuebuf);
            if (value_len_out) {
                *value_len_out = hv_from_btree.sizeWithoutFlags();
            }
        }

        if (remove_key) {
            // remove the key
            br = cur_btree.remove(kv_from_btree);
            rets.rootAddr = cur_btree.getRootAddr();
            return convertBtreeResult(br);
        } else {
            return HBTRIE_RESULT_SUCCESS;
        }
    }

    // otherwise, key not found
    return HBTRIE_RESULT_FAIL;
}

hbtrie_result HBTrie::find(void *rawkey, int rawkeylen, void *valuebuf)
{
    if (ver_btreev2_format(fileHB->getVersion())) {
        // V2 format
        return find_vlen(rawkey, rawkeylen,
                         valuebuf, nullptr);
    }

    int nchunk = getNchunkRaw(rawkey, rawkeylen);
    uint8_t *key = alca(uint8_t, nchunk * chunksize);
    int keylen;

    keylen = reformKey(rawkey, rawkeylen, key);
    return _find(key, keylen, valuebuf, NULL, 0x0);
}

hbtrie_result HBTrie::find_vlen(void *rawkey, int rawkeylen,
                                void *valuebuf, size_t *value_len_out)
{
    // V2 format is a must for this API
    if (!ver_btreev2_format(fileHB->getVersion())) {
        return HBTRIE_RESULT_FAIL;
    }

    if (rootAddr.isEmpty) {
        // empty HB+trie, fail
        return HBTRIE_RESULT_FAIL;
    }
    HBTrieV2Args args(0, rootAddr);
    HBTrieV2Rets rets;
    return _findV2(rawkey, rawkeylen,
                   valuebuf, value_len_out,
                   args, rets, false);
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
            meta.size = btreeitem->btree.readMeta(meta.data);
            fetchMeta(meta.size, &hbmeta, meta.data);

            opt = (_is_leaf_btree(hbmeta.chunkno))?(HBMETA_LEAF):(HBMETA_NORMAL);

            // remove value from metasection
            storeMeta(meta.size, _get_chunkno(hbmeta.chunkno), opt,
                      hbmeta.prefix, hbmeta.prefix_len, NULL, 0, buf);
            btreeitem->btree.updateMeta(&meta);
        } else {
            if (btreeitem && btreeitem->leaf) {
                // leaf b-tree
                uint8_t *k = alca(uint8_t, chunksize);
                setLeafKey(k, key + btreeitem->chunkno * chunksize,
                    rawkeylen - btreeitem->chunkno * chunksize);
                br = btreeitem->btree.remove(k);
                freeLeafKey(k);
            } else if (btreeitem) {
                // normal b-tree
                br = btreeitem->btree.remove(key + chunksize * btreeitem->chunkno);
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
    if (ver_btreev2_format(fileHB->getVersion())) {
        return remove_vlen(rawkey, rawkeylen, nullptr, nullptr);
    }

    return _remove(rawkey, rawkeylen, 0x0);
}

hbtrie_result HBTrie::remove_vlen(void *rawkey, int rawkeylen,
                                  void *valuebuf, size_t *value_len_out)
{
    // V2 format is a must
    if (rootAddr.isEmpty) {
        // empty HB+trie, fail
        return HBTRIE_RESULT_FAIL;
    }
    HBTrieV2Args args(0, rootAddr);
    HBTrieV2Rets rets;
    hbtrie_result hr = _findV2(rawkey, rawkeylen, valuebuf, value_len_out,
                               args, rets, true);
    if (hr == HBTRIE_RESULT_SUCCESS) {
        rootAddr = rets.rootAddr;
    }
    return hr;
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
    meta.size = btreeitem->btree.readMeta(meta.data);
    fetchMeta(meta.size, &hbmeta, meta.data);

    // scan all keys
    list_init(&keys);
    memset(key_buf, 0, chunksize);
    minchunkno = 0;

    it = new BTreeIterator();
    br = it->init(&btreeitem->btree, NULL);
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
              HBMETA_NORMAL, prefix, minchunkno * chunksize, meta_value, valuelen, buf);

    // reset BTREEITEM
    btreeitem->btree.init(btreeblk_handle, btree_kv_ops, btree_nodesize,
                          chunksize, valuelen, 0x0, &meta);
    btreeitem->btree.setAux(aux);

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
    list_push_back(&btreelist, &btreeitem->e);

    if (root_bid == BLK_NOT_FOUND) {
        // create root b-tree
        storeMeta(meta.size, 0, HBMETA_NORMAL,
                  NULL, 0, NULL, 0, buf);
        r = btreeitem->btree.init(btreeblk_handle, btree_kv_ops, btree_nodesize,
                                  chunksize, valuelen, 0x0, &meta);
        if (r != BTREE_RESULT_SUCCESS) {
            freeBtreeList(&btreelist);
            return HBTRIE_RESULT_FAIL;
        }
    } else {
        // read from root_bid
        r = btreeitem->btree.initFromBid(btreeblk_handle, btree_kv_ops,
                                         btree_nodesize, root_bid);
        if (r != BTREE_RESULT_SUCCESS) {
            freeBtreeList(&btreelist);
            return HBTRIE_RESULT_FAIL;
        }
        if (btreeitem->btree.getKSize() != chunksize ||
            btreeitem->btree.getVSize() != valuelen) {
            if (((chunksize << 4) | valuelen) == btreeitem->btree.getKSize()) {
                // this is an old meta format
                freeBtreeList(&btreelist);
                return HBTRIE_RESULT_INDEX_VERSION_NOT_SUPPORTED;
            }
            // B+tree root node is corrupted.
            freeBtreeList(&btreelist);
            return HBTRIE_RESULT_INDEX_CORRUPTED;
        }
    }
    btreeitem->btree.setAux(aux);

    // set 'oldvalue_out' to 0xff..
    if (oldvalue_out) {
        memset(oldvalue_out, 0xff, valuelen);
    }

    uint8_t *docrawkey = nullptr, *dockey = nullptr;
    const int rawkey_buffer_index = allocateBuffer(&docrawkey);
    const int key_buffer_index = allocateBuffer(&dockey);

    while (curchunkno < nchunk) {
        // get current chunk number
        meta.size = btreeitem->btree.readMeta(meta.data);
        fetchMeta(meta.size, &hbmeta, meta.data);
        prevchunkno = curchunkno;
        if (_is_leaf_btree(hbmeta.chunkno)) {
            cpt_node = 1;
            hbmeta.chunkno = _get_chunkno(hbmeta.chunkno);
            btreeitem->btree.setKVOps(btree_leaf_kv_ops);
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
                              new_prefixlen, hbmeta.value, hbmeta.value_len, buf);
                } else {
                    storeMeta(meta.size, curchunkno,
                              HBMETA_NORMAL, NULL, 0,
                              hbmeta.value, hbmeta.value_len, buf);
                }
                // update metadata for old b-tree
                btreeitem->btree.updateMeta(&meta);

                // split prefix and create new sub-tree
                storeMeta(meta.size, prevchunkno + diffchunkno + 1,
                          HBMETA_NORMAL, old_prefix,
                          diffchunkno * chunksize, NULL, 0, buf);

                // create new b-tree
                btreeitem_new = (struct btreelist_item *)
                                mempool_alloc(sizeof(struct btreelist_item));
                btreeitem_new->chunkno = prevchunkno + diffchunkno + 1;
                list_insert_before(&btreelist, &btreeitem->e,
                                   &btreeitem_new->e);

                r = btreeitem_new->btree.init(btreeblk_handle, btree_kv_ops,
                                              btree_nodesize, chunksize, valuelen,
                                              0x0, &meta);
                if (r != BTREE_RESULT_SUCCESS) {
                    deallocateBuffer(&docrawkey, rawkey_buffer_index);
                    deallocateBuffer(&dockey, key_buffer_index);
                    freeBtreeList(&btreelist);
                    return HBTRIE_RESULT_FAIL;
                }
                btreeitem_new->btree.setAux(aux);

                // insert chunk for 'key'
                chunk_new = key + (prevchunkno + diffchunkno + 1) *
                                  chunksize;
                r = btreeitem_new->btree.insert(chunk_new, value);
                if (r == BTREE_RESULT_FAIL) {
                    deallocateBuffer(&docrawkey, rawkey_buffer_index);
                    deallocateBuffer(&dockey, key_buffer_index);
                    freeBtreeList(&btreelist);
                    return HBTRIE_RESULT_FAIL;
                }
                // insert chunk for existing btree
                chunk_new = (uint8_t*)old_prefix + diffchunkno *
                                                   chunksize;
                bid_new = btreeitem->btree.getRootBid();
                btreeitem_new->child_rootbid = bid_new;
                // set MSB
                _bid = _endian_encode(bid_new);
                valueSetMsb((void*)&_bid);
                r = btreeitem_new->btree.insert(chunk_new, (void*)&_bid);
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
                      value, valuelen, buf);
            btreeitem->btree.updateMeta(&meta);
            break;
        } else {
            chunk = key + curchunkno*chunksize;
            if (cpt_node) {
                // leaf b-tree
                setLeafKey(k, chunk,
                              rawkeylen - curchunkno*chunksize);
                r = btreeitem->btree.find(k, btree_value);
                freeLeafKey(k);
            } else {
                r = btreeitem->btree.find(chunk, btree_value);
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
                r = btreeitem->btree.insert(k, value);
                if (r == BTREE_RESULT_FAIL) {
                    freeLeafKey(k);
                    ret_result = HBTRIE_RESULT_FAIL;
                    break; // while loop
                }
                freeLeafKey(k);

                if (btreeitem->btree.getHeight() > leaf_height_limit) {
                    // height growth .. extend!
                    // btreelist is cleared out within extendLeafTree when
                    // btreeCascacdedUpdate is invoked.
                    extendLeafTree(&btreelist, btreeitem, key, curchunkno * chunksize);
                    deallocateBuffer(&docrawkey, rawkey_buffer_index);
                    deallocateBuffer(&dockey, key_buffer_index);
                    return ret_result;
                }
            } else {
                r = btreeitem->btree.insert(chunk, value);
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
            r = btreeitem->btree.insert(chunk, value);
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

            r = btreeitem->btree.initFromBid(btreeblk_handle, btree_kv_ops,
                                             btree_nodesize, bid_new);
            if (r == BTREE_RESULT_FAIL) {
                ret_result = HBTRIE_RESULT_FAIL;
            }
            btreeitem->btree.setAux(aux);
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
                r = btreeitem->btree.insert(k, value);
                freeLeafKey(k);
            } else {
                // normal b-tree
                r = btreeitem->btree.insert(chunk, value);
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
                      (midchunkno - (curchunkno+1)) * chunksize, NULL, 0, buf);

            btreeitem_new = (struct btreelist_item *)
                            mempool_alloc(sizeof(struct btreelist_item));
            btreeitem_new->chunkno = midchunkno;
            list_push_back(&btreelist, &btreeitem_new->e);

            r = btreeitem_new->btree.init(btreeblk_handle, kv_ops, btree_nodesize,
                                          chunksize, valuelen, 0x0, &meta);
            if (r == BTREE_RESULT_FAIL) {
                deallocateBuffer(&docrawkey, rawkey_buffer_index);
                deallocateBuffer(&dockey, key_buffer_index);
                freeBtreeList(&btreelist);
                return HBTRIE_RESULT_FAIL;
            }
            btreeitem_new->btree.setAux(aux);
            btreeitem_new->child_rootbid = BLK_NOT_FOUND;

            // insert new btree's bid into the previous btree
            bid_new = btreeitem_new->btree.getRootBid();
            btreeitem->child_rootbid = bid_new;
            _bid = _endian_encode(bid_new);
            valueSetMsb((void *)&_bid);
            r = btreeitem->btree.insert(chunk, &_bid);
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
                      (newchunkno - (curchunkno+1)) * chunksize, value_short, valuelen, buf);

            btreeitem_new = (struct btreelist_item *)
                            mempool_alloc(sizeof(struct btreelist_item));
            btreeitem_new->chunkno = newchunkno;
            r = btreeitem_new->btree.init(btreeblk_handle, kv_ops, btree_nodesize,
                                          chunksize, valuelen, 0x0, &meta);
            list_push_back(&btreelist, &btreeitem_new->e);
            if (r == BTREE_RESULT_FAIL) {
                ret_result = HBTRIE_RESULT_FAIL;
                break;
            }
            btreeitem_new->btree.setAux(aux);

            chunk_new = (uint8_t*)key_long + newchunkno * chunksize;

            if (opt == HBMETA_LEAF) {
                // optimization mode
                setLeafKey(k, chunk_new, rawkeylen_long - newchunkno*chunksize);
                r = btreeitem_new->btree.insert(k, value_long);
                if (r == BTREE_RESULT_FAIL) {
                    ret_result = HBTRIE_RESULT_FAIL;
                }
                freeLeafKey(k);
            } else {
                // normal mode
                r = btreeitem_new->btree.insert(chunk_new, value_long);
                if (r == BTREE_RESULT_FAIL) {
                    ret_result = HBTRIE_RESULT_FAIL;
                }
            }

        } else {
            //3 2-2. create sub-tree
            // and insert two docs into it
            storeMeta(meta.size, newchunkno, opt, key + chunksize * (curchunkno+1),
                      (newchunkno - (curchunkno+1)) * chunksize, NULL, 0, buf);

            btreeitem_new = (struct btreelist_item *)
                            mempool_alloc(sizeof(struct btreelist_item));
            btreeitem_new->chunkno = newchunkno;
            list_push_back(&btreelist, &btreeitem_new->e);

            r = btreeitem_new->btree.init(btreeblk_handle, kv_ops, btree_nodesize,
                                          chunksize, valuelen, 0x0, &meta);
            if (r == BTREE_RESULT_FAIL) {
                ret_result = HBTRIE_RESULT_FAIL;
            }
            btreeitem_new->btree.setAux(aux);

            // insert KEY
            chunk_new = key + newchunkno * chunksize;
            if (opt == HBMETA_LEAF) {
                // optimization mode
                setLeafKey(k, chunk_new, rawkeylen - newchunkno*chunksize);
                r = btreeitem_new->btree.insert(k, value);
                freeLeafKey(k);
            } else {
                r = btreeitem_new->btree.insert(chunk_new, value);
            }
            if (r == BTREE_RESULT_FAIL) {
                ret_result = HBTRIE_RESULT_FAIL;
            }

            // insert the original DOCKEY
            chunk_new = dockey + newchunkno * chunksize;
            if (opt == HBMETA_LEAF) {
                // optimization mode
                setLeafKey(k, chunk_new, docrawkeylen - newchunkno*chunksize);
                r = btreeitem_new->btree.insert(k, btree_value);
                freeLeafKey(k);
            } else {
                r = btreeitem_new->btree.insert(chunk_new, btree_value);
            }
            if (r == BTREE_RESULT_FAIL) {
                ret_result = HBTRIE_RESULT_FAIL;
            }
        }

        // update previous (parent) b-tree
        bid_new = btreeitem_new->btree.getRootBid();
        btreeitem->child_rootbid = bid_new;

        // set MSB
        _bid = _endian_encode(bid_new);
        valueSetMsb((void *)&_bid);
        // ASSUMPTION: parent b-tree always MUST be non-leaf b-tree
        r = btreeitem->btree.insert(chunk, (void*)&_bid);
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

hbtrie_result HBTrie::convertBtreeResult(BtreeV2Result br) {
    if (br == BtreeV2Result::SUCCESS) {
        return HBTRIE_RESULT_SUCCESS;
    } else {
        return HBTRIE_RESULT_FAIL;
    }
}

hbtrie_result HBTrie::setLocalReturnValue(hbtrie_result hr,
                                          BtreeV2& cur_btree,
                                          HBTrieV2Rets& rets)
{
    if (hr == HBTRIE_RESULT_SUCCESS) {
        rets.rootAddr = cur_btree.getRootAddr();
    }
    return hr;
}

btree_new_cmp_func* HBTrie::getCmpFuncForGivenKey(void *rawkey)
{
    btree_new_cmp_func *cmp_func = nullptr;

    if (getCmpFuncCB) {
        // get KVS ID from the first chunk
        uint64_t kvs_id;
        // the reason why we call this function is because
        // chunk size is variable (4~64 bytes).
        buf2kvid(chunksize, rawkey, &kvs_id);

        auto entry = cmpFuncMap.find(kvs_id);
        if (entry == cmpFuncMap.end()) {
            // KVS ID doesn't exist in the map
            //  => we should reflect the latest info.
            cmp_func = getCmpFuncCB(this, kvs_id, nullptr);
            cmpFuncMap.insert(std::make_pair(kvs_id, cmp_func));
        } else {
            cmp_func = entry->second;
        }
    }
    return cmp_func;
}

// Recursive function.
hbtrie_result HBTrie::_insertV2(void *rawkey, size_t rawkeylen,
                                void *given_value, size_t given_value_len,
                                void *oldvalue_out, size_t *oldvalue_len_out,
                                HBTrieV2Args args,
                                HBTrieV2Rets& rets,
                                uint8_t flag )
{
    // < insertion cases in HB+trie >
    //
    // 1. normal insert:
    //   => insert into an existing sub-tree, without changing hierarchy.
    //
    // 2. replace a doc with a new sub-tree:
    //   => a doc (whose prefix is same) already exists.
    //   => let's say one key as A, the other key as B, and their
    //      common prefix as P.
    //
    //  2-1. one key is a sub-string of the others:
    //    e.g.) chunksize: 4, A: abcd, B: abcd1234, P: abcd, so A==P.
    //    => create a sub-tree for P (abcd), store the value of A in its meta
    //       section, and insert rest of string of B (1234) into the sub-tree.
    //
    //  2-2. otherwise:
    //    e.g.) chunksize: 4, A: abcd1234, B: abcd4567, P: abcd
    //    => create a sub-tree for P (abcd), and insert rest of strings
    //       (1234 and 4567) into the sub-tree.
    //
    // 3. create a new sub-tree between existing two sub-trees:
    //   => let's say a parent sub-tree X for chunk 0, and its child sub-tree Y
    //      for chunk 2, so there is a skipped prefix for chunk 1.
    //   e.g.) chunksize: 4, key: aaaabbbbcccc
    //   => tree X points to tree Y using chunk 0 (aaaa),
    //      tree Y stores the key using chunk 2 (cccc), and
    //      chunk 1 (bbbb) is stored in the meta section of tree Y.
    //   => if we insert another key aaaadddd, then
    //      create a new sub-tree Z for chunk 1,
    //      insert 'dddd' into Z, and
    //      insert 'bbbb' which points to existing tree Y into Z.
    //

    size_t cur_chunk_no = 0;
    uint8_t hv_buf[HV_BUF_MAX_SIZE];
    BtreeV2 cur_btree;
    BtreeV2Meta bmeta;
    BtreeV2Result br;
    hbtrie_result hr;
    struct hbtrie_meta hbmeta;

    // read from root
    cur_btree.setBMgr(bnodeMgr);
    br = cur_btree.initFromAddr(args.rootAddr);
    if (br != BtreeV2Result::SUCCESS) {
        return HBTRIE_RESULT_FAIL;
    }

    MPWrapper meta_buffer;
    meta_buffer.allocate();
    bmeta = BtreeV2Meta(cur_btree.getMetaSize(), meta_buffer.getAddr());
    cur_btree.readMeta(bmeta);
    fetchMeta(bmeta.size, &hbmeta, bmeta.ctx);

    cur_chunk_no = hbmeta.chunkno;
    if (cur_chunk_no) {
        // If this is not the root B+tree (cur_chunk_no > 0),
        // set custom cmp function if exists.
        // Note that root B+tree does not use custom cmp function,
        // since it stores KVS ID which always should be in a
        // lexicographical order.
        cur_btree.setCmpFunc(getCmpFuncForGivenKey(rawkey));
    }

    // check if there is a skipped prefix.
    if (cur_chunk_no > args.prevChunkNo + 1) {
        // it means that there is a skipped prefix
        // between parent sub-tree and child sub-tree.

        // check if prefix is identical.
        size_t prefix_start_pos = (args.prevChunkNo + 1) * chunksize;
        if (hbmeta.prefix_len + prefix_start_pos > rawkeylen ||
            memcmp(hbmeta.prefix,
                   static_cast<uint8_t*>(rawkey) + prefix_start_pos,
                   hbmeta.prefix_len)) {

            // prefix mismatch, CASE 3.
            HBTrieInsV2Args ins_args(args, cur_btree, hbmeta, cur_chunk_no);
            return _insertV2Case3(rawkey, rawkeylen,
                                  given_value, given_value_len,
                                  oldvalue_out, oldvalue_len_out,
                                  ins_args, rets, flag);
        }
    }

    if (rawkeylen == cur_chunk_no * chunksize) {
        // given key is exactly same as the current b+tree's prefix
        // insert the value into the meta section.
        metasize_t metasize;
        MPWrapper new_meta_buffer;
        new_meta_buffer.allocate();

        HBTrieValue hb_value_meta;
        if (given_value_len != sizeof(uint64_t)) {
            // document meta
            hb_value_meta = HBTrieValue(HV_DOC | HV_VLEN_DATA,
                                        given_value, given_value_len);
        } else {
            // document offset
            hb_value_meta = HBTrieValue(HV_DOC, given_value);
        }

        storeMeta( metasize, cur_chunk_no, HBMETA_NORMAL,
                   hbmeta.prefix, hbmeta.prefix_len,
                   hb_value_meta.toBinary(hv_buf),
                   hb_value_meta.size(),
                   new_meta_buffer.getAddr() );
        cur_btree.updateMeta(BtreeV2Meta(metasize, new_meta_buffer.getAddr()));
        hr = HBTRIE_RESULT_SUCCESS;
        return setLocalReturnValue(hr, cur_btree, rets);
    }

    void *chunk = static_cast<uint8_t*>(rawkey) + (cur_chunk_no * chunksize);

    // e.g.) chunksize = 8, rawkeylen = 11
    // 1) if cur_chunk_no = 1,
    //    => cur_chunklen = 3 (rest of string)
    // 2) if cur_chunk_no = 0,
    //    => cur_chunklen = 8 (regular chunk size)
    size_t suffix_len = rawkeylen - (cur_chunk_no * chunksize);
    size_t cur_chunklen = std::min(suffix_len, static_cast<size_t>(chunksize));
    MPWrapper key_buffer;


    BtreeKvPair kv_from_btree;
    // If custom cmp function is assigned, we cannot split the key
    // into multiple chunks as it is not in a lexicographical order.
    // So there are always 2-levels of trees in custom cmp mode:
    // chunk 0 (KVS ID) and chunk 1 (actual key).
    // We directly compare the entire key in this case.
    if (cur_chunklen < chunksize || cur_btree.getCmpFunc()) {
        // if suffix length is smaller than a chunk size, OR
        // custom cmp mode
        //  => no sub-tree related processes, just find an exact match key.
        kv_from_btree = BtreeKvPair(chunk, suffix_len, hv_buf, 0);
        br = cur_btree.find(kv_from_btree, false);
    } else {
        // if suffix length is equal to or longer than a chunk size
        //  => find any key whose prefix is same to the chunk.
        //     e.g.) chunk = 'aa'
        //           find aa, aaa, aab, aac ...
        key_buffer.allocate();
        memcpy(key_buffer.getAddr(), chunk, chunksize);
        kv_from_btree = BtreeKvPair(key_buffer.getAddr(), chunksize, hv_buf, 0);
        br = cur_btree.findGreaterOrEqual(kv_from_btree, false);

        if (br == BtreeV2Result::SUCCESS) {
            // check if chunk matches
            if ( kv_from_btree.keylen < chunksize ||
                 memcmp(chunk, kv_from_btree.key, chunksize) ) {
                // means that same chunk doesn't exist in the tree.
                br = BtreeV2Result::KEY_NOT_FOUND;
            }
        }
    }

    if (br != BtreeV2Result::SUCCESS) {
        // CASE 1: normal insert
        // insert rest suffix into the b+tree
        HBTrieValue hb_value; // document offset
        if (given_value_len != sizeof(uint64_t)) {
            // document meta
            hb_value = HBTrieValue(HV_DOC | HV_VLEN_DATA,
                                   given_value, given_value_len);
        } else {
            // document offset
            hb_value = HBTrieValue(HV_DOC, given_value);
        }

        BtreeKvPair kv_insert =
            BtreeKvPair(chunk, suffix_len, hb_value.toBinary(hv_buf), hb_value.size());
        br = cur_btree.insert(kv_insert);
        return setLocalReturnValue(convertBtreeResult(br), cur_btree, rets);
    }
    // otherwise, same chunk already exists.

    HBTrieValue hv_from_btree(kv_from_btree.value, kv_from_btree.valuelen);

    if (flag & HBTRIE_PARTIAL_UPDATE) {
        // partial update mode: just replace the value
        if (oldvalue_out) {
            hv_from_btree.toBinaryWithoutFlags(oldvalue_out);
        }
        if (oldvalue_len_out) {
            *oldvalue_len_out = hv_from_btree.sizeWithoutFlags();
        }

        HBTrieValue hv_new(HV_SUB_TREE, given_value);
        BtreeKvPair kv_insert =
            BtreeKvPair(kv_from_btree.key, kv_from_btree.keylen,
            hv_new.toBinary(hv_buf), hv_new.size());
        br = cur_btree.insert(kv_insert);
        return setLocalReturnValue(convertBtreeResult(br), cur_btree, rets);
    }

    // check if value points to sub b+tree
    if (hv_from_btree.isSubtree()) {
        BtreeNodeAddr next_root;
        if (hv_from_btree.isDirtyRoot()) {
            // dirty root node => offset is memory address
            next_root =
                BtreeNodeAddr(BLK_NOT_FOUND, hv_from_btree.getChildPtr());
        } else {
            // clean root node
            next_root = BtreeNodeAddr(hv_from_btree.getOffset(), nullptr );
        }

        HBTrieV2Args next_args(cur_chunk_no, next_root);
        HBTrieV2Rets local_rets;
        hr = _insertV2(rawkey, rawkeylen,
                       given_value, given_value_len,
                       oldvalue_out, oldvalue_len_out,
                       next_args, local_rets, flag);

        if (hr == HBTRIE_RESULT_SUCCESS &&
            next_root != local_rets.rootAddr) {
            // child B+tree's root node has been changed.
            //  => update {key, ptr} pair
            HBTrieValue hv_new_ptr(local_rets.rootAddr);
            kv_from_btree = BtreeKvPair(kv_from_btree.key, kv_from_btree.keylen,
                                        hv_new_ptr.toBinary(hv_buf), hv_new_ptr.size());
            br = cur_btree.insert(kv_from_btree);
            hr = convertBtreeResult(br);
        }
        return setLocalReturnValue(hr, cur_btree, rets);
    }
    // otherwise, value points to document

    if ( kv_from_btree.keylen == suffix_len &&
         !memcmp(kv_from_btree.key, chunk, suffix_len) ) {
        // exactly same key => update B+tree entry
        if (oldvalue_out) {
            hv_from_btree.toBinaryWithoutFlags(oldvalue_out);
        }
        if (oldvalue_len_out) {
            *oldvalue_len_out = hv_from_btree.sizeWithoutFlags();
        }

        HBTrieValue hv_new;
        if (given_value_len != sizeof(uint64_t)) {
            // document meta
            hv_new = HBTrieValue(HV_DOC | HV_VLEN_DATA,
                                 given_value, given_value_len);
        } else {
            // document offset
            hv_new = HBTrieValue(HV_DOC, given_value);
        }
        BtreeKvPair kv_insert(kv_from_btree.key, kv_from_btree.keylen,
                              hv_new.toBinary(hv_buf), hv_new.size());
        br = cur_btree.insert(kv_insert);
        return setLocalReturnValue(convertBtreeResult(br), cur_btree, rets);
    }

    // not exact matching key, only chunk part is same.
    //  => CASE 2.
    HBTrieInsV2Args ins_args(args, cur_btree, hbmeta, cur_chunk_no,
                             suffix_len, kv_from_btree);
    return _insertV2Case2(rawkey, rawkeylen,
                          given_value, given_value_len,
                          oldvalue_out, oldvalue_len_out,
                          ins_args, rets, flag);
}

hbtrie_result HBTrie::_insertV2Case2(void *rawkey, size_t rawkeylen,
                                     void *given_value, size_t given_value_len,
                                     void *oldvalue_out, size_t *oldvalue_len_out,
                                     HBTrieInsV2Args& ins_args,
                                     HBTrieV2Rets& rets,
                                     uint8_t flag)
{
    //                               prefix     first_diff
    //                               <---->     v
    // key: xxxxxx xxxxxx ... xxxxxx xxxxxx xxxxxx xxxx
    //      ^      ^          ^             ^
    //      chunk0 chunk1     cur_chunk     next_chunk

    // find first different location between two keys
    // Note: 'kv_from_btree.key' is not a full key since prefix is skipped,
    //       so it starts from the current chunk.
    //       'rawkey' is a full key starts from chunk 0.

    BtreeV2& cur_btree = ins_args.curTree;
    size_t cur_chunk_no = ins_args.curChunkNo;
    size_t suffix_len = ins_args.suffixLen;
    BtreeKvPair kv_from_btree = ins_args.kvFromBtree;
    BtreeV2Result br;
    uint8_t hv_buf[HV_BUF_MAX_SIZE];

    void *chunk = static_cast<uint8_t*>(rawkey) + (cur_chunk_no * chunksize);

    size_t first_diff = (cur_chunk_no+1) * chunksize;
    size_t cur_chunk_pos = cur_chunk_no * chunksize;

    size_t shorter_len = std::min(static_cast<size_t>(kv_from_btree.keylen),
                                  suffix_len);
    for (; first_diff < cur_chunk_pos+shorter_len; ++first_diff) {
        if (*(static_cast<uint8_t*>(kv_from_btree.key) + first_diff - cur_chunk_pos)
            != *(static_cast<uint8_t*>(rawkey) + first_diff)) {
            break;
        }
    }
    size_t next_chunk_no = first_diff / chunksize;
    size_t next_chunk_pos = next_chunk_no * chunksize;
    size_t prefix_len = (next_chunk_no - cur_chunk_no - 1) * chunksize;

    // create next b-tree
    BtreeV2 next_btree;
    metasize_t metasize = 0;

    if (shorter_len == prefix_len + chunksize) {
        // CASE 2-1.
        //  => create a new sub-tree and insert longer key into it.
        //     value for shorter key is stored in the meta section of the tree.
        BtreeKvPair long_key;
        HBTrieValue hv_metasection;
        // since 'hv_buf' will be used for 'long_key' we need one more buffer.
        uint8_t hv_buf_meta[HV_BUF_MAX_SIZE];
        // calculate meta size using temporary buffer.
        // (contents of buffer doesn't matter for size)
        MPWrapper new_meta_buffer;
        new_meta_buffer.allocate();

        // insert short key into meta section
        if (kv_from_btree.keylen > suffix_len) {
            // short: given key, long: existing key
            if (given_value_len != sizeof(uint64_t)) {
                // document meta
                hv_metasection = HBTrieValue(HV_DOC | HV_VLEN_DATA,
                                             given_value, given_value_len);
            } else {
                // document offset
                hv_metasection = HBTrieValue(HV_DOC, given_value);
            }
            long_key = BtreeKvPair(static_cast<uint8_t*>(kv_from_btree.key) +
                                       (prefix_len + chunksize),
                                   kv_from_btree.keylen - (prefix_len + chunksize),
                                   kv_from_btree.value, kv_from_btree.valuelen);
        } else {
            // short: existing key, long: given key
            hv_metasection = HBTrieValue(kv_from_btree.value, kv_from_btree.valuelen);

            HBTrieValue hv_new;
            if (given_value_len != sizeof(uint64_t)) {
                // document meta
                hv_new = HBTrieValue(HV_DOC | HV_VLEN_DATA,
                                     given_value, given_value_len);
            } else {
                // document offset
                hv_new = HBTrieValue(HV_DOC, given_value);
            }
            long_key = BtreeKvPair(static_cast<uint8_t*>(rawkey) + next_chunk_pos,
                                   rawkeylen - next_chunk_pos,
                                   hv_new.toBinary(hv_buf), hv_new.size());
        }
        storeMeta( metasize, next_chunk_no, HBMETA_NORMAL,
                   static_cast<uint8_t*>(chunk) + chunksize,
                   prefix_len, hv_metasection.toBinary(hv_buf_meta),
                   hv_metasection.size(),
                   new_meta_buffer.getAddr() );

        next_btree.init();
        next_btree.setBMgr(bnodeMgr);

        br = next_btree.updateMeta(BtreeV2Meta(metasize, new_meta_buffer.getAddr()));
        if (br != BtreeV2Result::SUCCESS) {
            return setLocalReturnValue(convertBtreeResult(br), cur_btree, rets);
        }

        // insert long key into the new sub tree
        br = next_btree.insert(long_key);
        if (br != BtreeV2Result::SUCCESS) {
            return setLocalReturnValue(convertBtreeResult(br), cur_btree, rets);
        }
    } else {
        // otherwise: CASE 2-2.
        //   both (given key, found key) are longer than a chunk size.
        //   create a new sub-tree and insert two keys into it.

        // check if custom cmp function exists
        btree_new_cmp_func *cmp_func = getCmpFuncForGivenKey(rawkey);
        MPWrapper new_meta_buffer;
        new_meta_buffer.allocate();
        storeMeta( metasize, next_chunk_no, HBMETA_NORMAL,
                   static_cast<uint8_t*>(chunk) + chunksize,
                   prefix_len, nullptr, 0, new_meta_buffer.getAddr() );

        next_btree.init();
        next_btree.setBMgr(bnodeMgr);
        next_btree.setCmpFunc(cmp_func);

        br = next_btree.updateMeta(BtreeV2Meta(metasize, new_meta_buffer.getAddr()));
        if (br != BtreeV2Result::SUCCESS) {
            return setLocalReturnValue(convertBtreeResult(br), cur_btree, rets);
        }

        // insert two keys
        // 1) kv_from_btree.key (existing key in the current tree)
        BtreeKvPair existing_kv(static_cast<uint8_t*>(kv_from_btree.key) +
                                    (prefix_len + chunksize),
                                kv_from_btree.keylen - (prefix_len + chunksize),
                                kv_from_btree.value, kv_from_btree.valuelen);
        br = next_btree.insert(existing_kv);
        if (br != BtreeV2Result::SUCCESS) {
            return setLocalReturnValue(convertBtreeResult(br), cur_btree, rets);
        }

        // 2) rawkey (given by caller)
        HBTrieValue hv_new;
        if (given_value_len != sizeof(uint64_t)) {
            // document meta
            hv_new = HBTrieValue(HV_DOC | HV_VLEN_DATA,
                                 given_value, given_value_len);
        } else {
            // document offset
            hv_new = HBTrieValue(HV_DOC, given_value);
        }
        BtreeKvPair given_kv(static_cast<uint8_t*>(rawkey) + next_chunk_pos,
                             rawkeylen - next_chunk_pos,
                             hv_new.toBinary(hv_buf), hv_new.size());
        br = next_btree.insert(given_kv);
        if (br != BtreeV2Result::SUCCESS) {
            return setLocalReturnValue(convertBtreeResult(br), cur_btree, rets);
        }
    }

    // insert {current chunk, new b+tree root} pair
    // into the current btree
    BtreeNodeAddr new_addr = next_btree.getRootAddr();
    HBTrieValue new_tree_hv(new_addr);
    BtreeKvPair new_tree_kv(chunk, chunksize, new_tree_hv.toBinary(hv_buf), new_tree_hv.size());
    br = cur_btree.insert(new_tree_kv);
    if (br != BtreeV2Result::SUCCESS) {
        return setLocalReturnValue(convertBtreeResult(br), cur_btree, rets);
    }

    if (kv_from_btree.keylen != chunksize &&
        !memcmp(new_tree_kv.key, kv_from_btree.key, new_tree_kv.keylen)) {
        // if existing key was a suffix (whose length is not a chunksize),
        // remove existing key in the current B+tree
        // (to avoid the tree being destroyed, we should call
        //  remove() after insert() is invoked.)
        br = cur_btree.remove(kv_from_btree);
        if (br != BtreeV2Result::SUCCESS) {
            return setLocalReturnValue(convertBtreeResult(br), cur_btree, rets);
        }
    }

    return setLocalReturnValue(convertBtreeResult(br), cur_btree, rets);

}

hbtrie_result HBTrie::_insertV2Case3(void *rawkey, size_t rawkeylen,
                                     void *given_value, size_t given_value_len,
                                     void *oldvalue_out, size_t *oldvalue_len_out,
                                     HBTrieInsV2Args& ins_args,
                                     HBTrieV2Rets& rets,
                                     uint8_t flag)
{
    //               skipped prefix (old prefix for cur_tree)
    //                        <------------------>
    //           prefix for new_tree        new prefix for cur_tree
    //                        <---->        <---->
    // key: xxxxxx ... xxxxxx xxxxxx xxxxxx xxxxxx xxxxxx
    //      ^          ^             ^             ^
    //      chunk0     prevChunkNo   diff_chunk    cur_chunk_no
    //                               (new_tree)      (cur_tree)

    HBTrieV2Args& args = ins_args.callerArgs;
    BtreeV2& cur_btree = ins_args.curTree;
    hbtrie_meta& hbmeta = ins_args.hbMeta;
    size_t cur_chunk_no = ins_args.curChunkNo;
    BtreeV2Result br;

    // 1) find first different chunk
    size_t prefix_start_pos = (args.prevChunkNo + 1) * chunksize;
    size_t first_diff = prefix_start_pos;
    size_t cur_chunk_pos = cur_chunk_no * chunksize;
    for (; first_diff < cur_chunk_pos; ++first_diff) {
        if (*(static_cast<uint8_t*>(hbmeta.prefix) +
                first_diff - prefix_start_pos) !=
            *(static_cast<uint8_t*>(rawkey) + first_diff)) {
            break;
        }
    }
    size_t diff_chunk = first_diff / chunksize;

    // 2) create a new sub-tree for 'diff_chunk'
    BtreeV2 new_tree;
    MPWrapper new_meta_buffer;
    metasize_t new_metasize;

    new_meta_buffer.allocate();
    size_t prefix_len_new_tree = diff_chunk * chunksize - prefix_start_pos;

    if (hbmeta.prefix_len + prefix_start_pos == rawkeylen) {
        // given key is exactly same as the new tree's prefix
        //  => store value in the meta section
        HBTrieValue meta_value_new_tree;
        if (given_value_len != sizeof(uint64_t)) {
            // document meta
            meta_value_new_tree = HBTrieValue(HV_DOC | HV_VLEN_DATA,
                                              given_value, given_value_len);
        } else {
            // document offset
            meta_value_new_tree = HBTrieValue(HV_DOC, given_value);
        }

        uint8_t meta_value_buf_new_tree[HV_BUF_MAX_SIZE];
        storeMeta( new_metasize, diff_chunk, HBMETA_NORMAL,
                   static_cast<uint8_t*>(hbmeta.prefix),
                   prefix_len_new_tree,
                   meta_value_new_tree.toBinary(meta_value_buf_new_tree),
                   meta_value_new_tree.size(),
                   new_meta_buffer.getAddr() );
    } else {
        // otherwise => empty value
        storeMeta( new_metasize, diff_chunk, HBMETA_NORMAL,
                   static_cast<uint8_t*>(hbmeta.prefix),
                   prefix_len_new_tree, nullptr, 0,
                   new_meta_buffer.getAddr() );
    }

    new_tree.init();
    new_tree.setBMgr(bnodeMgr);

    br = new_tree.updateMeta(BtreeV2Meta(new_metasize,
                                         new_meta_buffer.getAddr()));
    if (br != BtreeV2Result::SUCCESS) {
        return setLocalReturnValue(convertBtreeResult(br), cur_btree, rets);
    }

    // 3) adjust old child tree (cur_tree) prefix
    size_t prefix_len_cur_tree = (cur_chunk_no - diff_chunk - 1) * chunksize;
    storeMeta( new_metasize, cur_chunk_no, HBMETA_NORMAL,
               static_cast<uint8_t*>(hbmeta.prefix) +
                   prefix_len_new_tree + chunksize,
               prefix_len_cur_tree,
               hbmeta.value,
               hbmeta.value_len,
               new_meta_buffer.getAddr() );
    cur_btree.updateMeta(BtreeV2Meta(new_metasize,
                                     new_meta_buffer.getAddr()));

    // 4) insert old child tree (cur_tree) into the new tree.
    void *chunk_old_tree = static_cast<uint8_t*>(hbmeta.prefix) +
                           prefix_len_new_tree;
    BtreeKvPair new_kv;
    HBTrieValue new_hv(cur_btree.getRootAddr());
    uint8_t new_hv_buf[HV_BUF_MAX_SIZE];
    new_kv = BtreeKvPair(static_cast<uint8_t*>(chunk_old_tree), chunksize,
                         new_hv.toBinary(new_hv_buf), new_hv.size());
    br = new_tree.insert(new_kv);
    if (br != BtreeV2Result::SUCCESS) {
        return setLocalReturnValue(convertBtreeResult(br), new_tree, rets);
    }

    // 5) insert suffix of rawkey into the new tree.
    void *chunk_rawkey = static_cast<uint8_t*>(rawkey) + diff_chunk * chunksize;
    size_t suffix_len = rawkeylen - diff_chunk * chunksize;
    if (given_value_len != sizeof(uint64_t)) {
        // document meta
        new_hv = HBTrieValue(HV_DOC | HV_VLEN_DATA,
                             given_value, given_value_len);
    } else {
        // document offset
        new_hv = HBTrieValue(HV_DOC, given_value);
    }

    new_kv = BtreeKvPair(static_cast<uint8_t*>(chunk_rawkey), suffix_len,
                         new_hv.toBinary(new_hv_buf), new_hv.size());
    br = new_tree.insert(new_kv);
    return setLocalReturnValue(convertBtreeResult(br), new_tree, rets);
}

hbtrie_result HBTrie::insert(void *rawkey, int rawkeylen,
                     void *value, void *oldvalue_out)
{
    if (ver_btreev2_format(fileHB->getVersion())) {
        // V2 format
        size_t oldvalue_len_out_local;
        return insert_vlen(rawkey, rawkeylen,
                           value, sizeof(uint64_t),
                           oldvalue_out, &oldvalue_len_out_local);
    }
    return _insert(rawkey, rawkeylen, value, oldvalue_out, 0x0);
}

hbtrie_result HBTrie::insert_vlen(void *rawkey,
                                  size_t rawkeylen,
                                  void *value,
                                  size_t value_len,
                                  void *oldvalue_out,
                                  size_t *oldvalue_len_out)
{
    // V2 format is a must for this API
    if (!ver_btreev2_format(fileHB->getVersion())) {
        return HBTRIE_RESULT_FAIL;
    }

    if (rootAddr.isEmpty) {
        // create root b-tree
        BtreeV2 cur_btree;
        BtreeV2Result br;

        metasize_t metasize = 0;
        MPWrapper meta_buffer;
        meta_buffer.allocate();
        storeMeta( metasize, 0, HBMETA_NORMAL,
                   nullptr, 0, nullptr, 0, meta_buffer.getAddr() );

        cur_btree.init();
        cur_btree.setBMgr(bnodeMgr);

        br = cur_btree.updateMeta(BtreeV2Meta(metasize, meta_buffer.getAddr()));
        if ( br != BtreeV2Result::SUCCESS ) {
            return HBTRIE_RESULT_FAIL;
        }
        rootAddr = cur_btree.getRootAddr();
    }
    HBTrieV2Args args(0, rootAddr);
    HBTrieV2Rets rets;
    hbtrie_result hr = _insertV2(rawkey, rawkeylen,
                                 value, value_len,
                                 oldvalue_out, oldvalue_len_out,
                                 args, rets, 0x0);
    if (hr == HBTRIE_RESULT_SUCCESS) {
        rootAddr = rets.rootAddr;
    }
    return hr;
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

    e = list_begin(&btreeit_list);
    while(e) {
        item = _get_entry(e, struct btreeit_item, le);
        e = list_remove(&btreeit_list, e);
        delete item->btree_it;
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

        item = (struct btreeit_item *)mempool_alloc(sizeof(
                                                    struct btreeit_item));

        // load b-tree
        // Note that this instance will be inserted into btreeit_list, and
        // will be freed in the destructor of HBTrieIterator.
        item->btree.initFromBid(trie->getBtreeBlkHandle(), trie->getBtreeKvOps(),
                                trie->getBtreeNodeSize(), trie->getRootBid());
        item->btree.setAux(trie->getAux());
        if (item->btree.getKSize() != chunksize || item->btree.getVSize() != valuelen) {
            if (((chunksize << 4) | valuelen) == item->btree.getKSize()) {
                // this is an old meta format
                mempool_free(item);
                return HBTRIE_RESULT_INDEX_VERSION_NOT_SUPPORTED;
            }
            // B+tree root node is corrupted.
            mempool_free(item);
            return HBTRIE_RESULT_INDEX_CORRUPTED;
        }

        item->btree_it = new BTreeIterator();
        item->chunkno = 0;
        item->leaf = 0;

        br = item->btree_it->init(&item->btree, chunk);
        if (br == BTREE_RESULT_FAIL) {
            mempool_free(item);
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
            delete item->btree_it;
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

            item_new = (struct btreeit_item *)
                       mempool_alloc(sizeof(struct btreeit_item));

            item_new->btree.initFromBid(trie->getBtreeBlkHandle(),
                                        trie->getBtreeKvOps(),
                                        trie->getBtreeNodeSize(), bid);

            // get sub b-tree's chunk number
            bmeta.data = (void *)mempool_alloc(trie->getBtreeNodeSize());
            bmeta.size = item_new->btree.readMeta(bmeta.data);
            trie->fetchMeta(bmeta.size, &hbmeta, bmeta.data);

            if (_is_leaf_btree(hbmeta.chunkno)) {
                trie->setLastMapChunk(curkey);
                item_new->btree.setKVOps(trie->getBtreeLeafKvOps());
                item_new->leaf = 1;
            } else {
                item_new->leaf = 0;
            }
            item_new->btree.setAux(trie->getAux());
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
                        item_new->btree_it->init(&item_new->btree, k_temp);
                    } else {
                        item_new->btree_it->init(&item_new->btree, NULL);
                    }
                } else {
                    // set initial key as the largest key
                    // for reverse scan from the end of the B+tree
                    setLeafInfKey(k_temp);
                    item_new->btree_it->init(&item_new->btree, k_temp);
                }
                freeLeafKey(k_temp);
            } else {
                item_new->btree_it->init(&item_new->btree, chunk);
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
        if (trie->getRootBid() == BLK_NOT_FOUND) {
            return HBTRIE_RESULT_FAIL;
        }
        // set current chunk (key for b-tree)
        chunk = curkey;

        item = (struct btreeit_item *)mempool_alloc(sizeof(struct btreeit_item));

        // load b-tree
        // Note that this instance will be inserted into btreeit_list, and
        // will be freed in the destructor of HBTrieIterator.
        item->btree.initFromBid(trie->getBtreeBlkHandle(), trie->getBtreeKvOps(),
                                trie->getBtreeNodeSize(), trie->getRootBid());
        item->btree.setAux(trie->getAux());
        if (item->btree.getKSize() != chunksize || item->btree.getVSize() != valuelen) {
            if (((chunksize << 4) | valuelen) == item->btree.getKSize()) {
                // this is an old meta format
                mempool_free(item);
                return HBTRIE_RESULT_INDEX_VERSION_NOT_SUPPORTED;
            }
            // B+tree root node is corrupted.
            mempool_free(item);
            return HBTRIE_RESULT_INDEX_CORRUPTED;
        }

        item->chunkno = 0;
        item->leaf = 0;
        item->btree_it = new BTreeIterator();

        br = item->btree_it->init(&item->btree, chunk);
        if (br == BTREE_RESULT_FAIL) {
            mempool_free(item);
            return HBTRIE_RESULT_FAIL;
        }

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
            delete item->btree_it;
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

            item_new = (struct btreeit_item *)
                       mempool_alloc(sizeof(struct btreeit_item));
            item_new->btree.initFromBid(trie->getBtreeBlkHandle(),
                                        trie->getBtreeKvOps(),
                                        trie->getBtreeNodeSize(), bid);

            // get sub b-tree's chunk number
            bmeta.data = (void *)mempool_alloc(trie->getBtreeNodeSize());
            bmeta.size = item_new->btree.readMeta(bmeta.data);
            trie->fetchMeta(bmeta.size, &hbmeta, bmeta.data);

            if (_is_leaf_btree(hbmeta.chunkno)) {
                trie->setLastMapChunk(curkey);
                item_new->btree.setKVOps(trie->getBtreeLeafKvOps());
                item_new->leaf = 1;
            } else {
                item_new->leaf = 0;
            }
            item_new->btree.setAux(trie->getAux());
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
                    item_new->btree_it->init(&item_new->btree, k_temp);
                    freeLeafKey(k_temp);
                } else {
                    item_new->btree_it->init(&item_new->btree, NULL);
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
                    item_new->btree_it->init(&item_new->btree, NULL);
                } else {
                    item_new->btree_it->init(&item_new->btree, chunk);
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

