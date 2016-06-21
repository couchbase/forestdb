/* -*- Mode: C++; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * Generic B+Tree
 * (C) 2013  Jung-Sang Ahn <jungsang.ahn@gmail.com>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common.h"
#include "list.h"
#include "btree.h"
#include "btreeblock.h"

#ifdef __DEBUG
    #include "memleak.h"
#ifndef __DEBUG_BTREE
    #undef DBG
    #undef DBGCMD
    #undef DBGSW
    #define DBG(...)
    #define DBGCMD(...)
    #define DBGSW(n, ...)
#endif
#endif

#define METASIZE_ALIGN_UNIT (16)
#ifdef METASIZE_ALIGN_UNIT
    #define _metasize_align(size) \
        (((( (size + sizeof(metasize_t)) + (METASIZE_ALIGN_UNIT-1)) \
            / METASIZE_ALIGN_UNIT) * METASIZE_ALIGN_UNIT) - sizeof(metasize_t))
#else
    #define _metasize_align(size) (size)
#endif

INLINE int is_subblock(bid_t subbid)
{
    uint8_t flag;
    flag = (subbid >> (8 * (sizeof(bid_t)-2))) & 0x00ff;
    return flag;
}

INLINE struct bnode *_fetch_bnode(void *addr, uint16_t level)
{
    struct bnode *node = NULL;

    node = (struct bnode *)addr;

    if (!(node->flag & BNODE_MASK_METADATA)) {
        // no metadata
        node->data = (uint8_t *)addr + sizeof(struct bnode);
    } else {
        // metadata
        metasize_t metasize;
        memcpy(&metasize, (uint8_t *)addr + sizeof(struct bnode), sizeof(metasize_t));
        metasize = _endian_decode(metasize);
        node->data = (uint8_t *)addr + sizeof(struct bnode) + sizeof(metasize_t) +
                     _metasize_align(metasize);
    }
    return node;
}

#ifdef _BTREE_HAS_MULTIPLE_BNODES
struct bnode ** btree_get_bnode_array(void *addr, size_t *nnode_out)
{
    // original b+tree always has only a single node per block
    struct bnode **ret;
    *nnode_out = 1;
    ret = (struct bnode **)malloc(sizeof(struct bnode*) * (*nnode_out));
    ret[0] = _fetch_bnode(addr, 0);

    return ret;
}
#else
struct bnode * btree_get_bnode(void *addr)
{
    return _fetch_bnode(addr, 0);
}
#endif

struct kv_ins_item {
    void *key;
    void *value;
    struct list_elem le;
};

BTree::BTree(BTreeBlkHandle *_bhandle,
             BTreeKVOps *_kv_ops,
             uint32_t _nodesize,
             uint8_t _ksize,
             uint8_t _vsize,
             bnode_flag_t _flag,
             struct btree_meta *_meta)
{
    init(_bhandle, _kv_ops, _nodesize, _ksize, _vsize, _flag, _meta);
}

BTree::BTree(BTreeBlkHandle *_bhandle,
             BTreeKVOps *_kv_ops,
             uint32_t _nodesize,
             bid_t _root_bid)
{
    initFromBid(_bhandle, _kv_ops, _nodesize, _root_bid);
}

BTree::~BTree()
{
    // do nothing

    // Note: if something is freed in this destructor,
    // then we need to adapt BTreeIterator() constructor
    // to allocate a separate instance for BTree, instead
    // of just pointing to the existing BTree instance.
}

btree_result BTree::init(BTreeBlkHandle *_bhandle,
                         BTreeKVOps *_kv_ops,
                         uint32_t _nodesize,
                         uint8_t _ksize,
                         uint8_t _vsize,
                         bnode_flag_t _flag,
                         struct btree_meta *_meta)
{
    void *addr;
    size_t min_nodesize = 0;

    root_flag = BNODE_MASK_ROOT | _flag;
    bhandle = _bhandle;
    kv_ops = _kv_ops;
    height = 1;
    blksize = _nodesize;
    ksize = _ksize;
    vsize = _vsize;
    if (_meta) {
        root_flag |= BNODE_MASK_METADATA;
        min_nodesize = sizeof(struct bnode) + _metasize_align(_meta->size) +
                       sizeof(metasize_t) + BLK_MARKER_SIZE;
    } else {
        min_nodesize = sizeof(struct bnode) + BLK_MARKER_SIZE;
    }

    if (min_nodesize > blksize) {
        // too large metadata .. init fail
        return BTREE_RESULT_FAIL;
    }

    // create the first root node
#ifdef __BTREEBLK_SUBBLOCK

    addr = bhandle->allocSub(root_bid);
    if (_meta) {
        // check if the initial node size including metadata is
        // larger than the subblock size
        size_t subblock_size;
        subblock_size = bhandle->getBlockSize(root_bid);
        if (subblock_size < min_nodesize) {
            addr = bhandle->enlargeNode(root_bid, min_nodesize, root_bid);
        }
    }

#else

    addr = bhandle->alloc(root_bid);

#endif

    initNode(addr, root_flag, BNODE_MASK_ROOT, _meta);

    return BTREE_RESULT_SUCCESS;
}

struct bnode* BTree::initNode(void *addr,
                              bnode_flag_t flag,
                              uint16_t level,
                              struct btree_meta *meta)
{
    struct bnode *node;
    void *node_addr;
    metasize_t _size;

    node_addr = addr;

    node = (struct bnode *)node_addr;
    node->kvsize = ksize<<8 | vsize;
    node->nentry = 0;
    node->level = level;
    node->flag = flag;

    if ((flag & BNODE_MASK_METADATA) && meta) {
        _size = _endian_encode(meta->size);
        memcpy( (uint8_t *)node_addr + sizeof(struct bnode),
                &_size, sizeof(metasize_t) );
        memcpy( (uint8_t *)node_addr + sizeof(struct bnode) + sizeof(metasize_t),
                meta->data, meta->size );
        node->data = (uint8_t *)node_addr + sizeof(struct bnode) + sizeof(metasize_t) +
                     _metasize_align(meta->size);
    } else {
        node->data = (uint8_t *)node_addr + sizeof(struct bnode);
    }

    return node;
}

btree_result BTree::initFromBid(BTreeBlkHandle *_bhandle,
                                BTreeKVOps *_kv_ops,
                                uint32_t _nodesize,
                                bid_t _root_bid)
{
    void *addr;
    struct bnode *root;

    bhandle = _bhandle;
    kv_ops = _kv_ops;
    blksize = _nodesize;
    root_bid = _root_bid;

    addr = bhandle->read(root_bid);
    root = _fetch_bnode(addr, 0);

    root_flag = root->flag;
    height = root->level;
    _get_kvsize(root->kvsize, ksize, vsize);

    return BTREE_RESULT_SUCCESS;
}

int BTree::getBNodeSize(struct bnode *node,
                        void *new_minkey,
                        void *key_arr,
                        void *value_arr,
                        size_t len)
{
    int nodesize = 0;

    if (node->flag & BNODE_MASK_METADATA) {
        metasize_t size;
        memcpy(&size, (uint8_t *)node + sizeof(struct bnode), sizeof(metasize_t));
        size = _endian_decode(size);
        nodesize = sizeof(struct bnode) +
                   kv_ops->getDataSize(node, new_minkey, key_arr, value_arr, len) +
                   _metasize_align(size) +
                   sizeof(metasize_t);
    } else {
        nodesize = sizeof(struct bnode) +
                   kv_ops->getDataSize(node, new_minkey, key_arr, value_arr, len);
    }

    return nodesize;
}

struct kv_ins_item* BTree::createKVInsItem(void *key, void *value)
{
    struct kv_ins_item *item;
    item = (struct kv_ins_item*)malloc(sizeof(struct kv_ins_item));
    item->key = (void *)malloc(ksize);
    item->value = (void *)malloc(vsize);

    kv_ops->initKVVar(item->key, item->value);
    if (key) {
        kv_ops->setKey(item->key, key);
    }
    if (value) {
        kv_ops->setValue(item->value, value);
    }
    return item;
}

void BTree::freeKVInsItem(struct kv_ins_item *item)
{
    free(item->key);
    free(item->value);
    free(item);
}


bool BTree::checkBNodeSize(bid_t bid,
                           struct bnode *node,
                           void* new_minkey,
                           struct list* kv_ins_list,
                           size_t& size_out)
{
    size_t nitem;
    size_t cursize;
    size_t nodesize;
    struct list_elem *e;
    struct kv_ins_item *item;

    nodesize = bhandle->getBlockSize(bid);
#ifdef __CRC32
    nodesize -= BLK_MARKER_SIZE;
#endif

    nitem = 0;
    if (kv_ins_list) {
        e = list_begin(kv_ins_list);
        while(e){
            nitem++;
            e = list_next(e);
        }
    }

    if (nitem > 1) {
        int i;
        void *key_arr, *value_arr;

        key_arr = (void*)malloc(ksize * nitem);
        value_arr = (void*)malloc(vsize * nitem);

        i = 0;
        e = list_begin(kv_ins_list);
        while(e){
            item = _get_entry(e, struct kv_ins_item, le);
            memcpy((uint8_t *)key_arr + ksize * i, item->key, ksize);
            memcpy((uint8_t *)value_arr + ksize * i, item->value, ksize);
            i++;
            e = list_next(e);
        }
        cursize = getBNodeSize(node, new_minkey, key_arr, value_arr, nitem);

        free(key_arr);
        free(value_arr);
    } else if (nitem == 1) {
        e = list_begin(kv_ins_list);
        item = _get_entry(e, struct kv_ins_item, le);
        cursize = getBNodeSize(node, new_minkey, item->key, item->value, 1);
    } else {
        /* nitem should never be negative due to size_t */
        fdb_assert(nitem == 0, nitem, this);
        cursize = getBNodeSize(node, new_minkey, NULL, NULL, 0);
    }

    size_out = cursize;
    return ( cursize <= nodesize );
}

size_t BTree::getNSplitNode(bid_t bid, struct bnode *node, size_t size)
{
    size_t headersize;
    size_t dataspace;
    size_t nodesize;
    size_t nnode = 0;

    nodesize = bhandle->getBlockSize(bid);
#ifdef __CRC32
    nodesize -= BLK_MARKER_SIZE;
#endif

    if (node->flag & BNODE_MASK_METADATA) {
        metasize_t size;
        memcpy(&size, (uint8_t *)node + sizeof(struct bnode), sizeof(metasize_t));
        size = _endian_decode(size);
        headersize = sizeof(struct bnode) + _metasize_align(size) + sizeof(metasize_t);
    } else {
        headersize = sizeof(struct bnode);
    }

    dataspace = nodesize - headersize;
    // round up
    nnode = ((size - headersize) + (dataspace-1)) / dataspace;

    return nnode;
}

metasize_t BTree::readMeta(void *buf)
{
    void *addr;
    void *ptr;
    metasize_t size;
    struct bnode *node;

    addr = bhandle->read(root_bid);
    node = _fetch_bnode(addr, height);
    if (node->flag & BNODE_MASK_METADATA) {
        ptr = ((uint8_t *)node) + sizeof(struct bnode);
        memcpy(&size, (uint8_t *)ptr, sizeof(metasize_t));
        size = _endian_decode(size);
        memcpy(buf, (uint8_t *)ptr + sizeof(metasize_t), size);
    } else {
        size = 0;
    }

    return size;
}

void BTree::updateMeta(struct btree_meta *meta)
{
    void *addr;
    void *ptr;
    metasize_t metasize, _metasize;
    metasize_t old_metasize = (metasize_t)(-1);
    struct bnode *node;

    // read root node
    addr = bhandle->read(root_bid);
    node = _fetch_bnode(addr, height);

    ptr = ((uint8_t *)node) + sizeof(struct bnode);

    if (node->flag & BNODE_MASK_METADATA) {
        memcpy(&old_metasize, ptr, sizeof(metasize_t));
        old_metasize = _endian_decode(old_metasize);
    }

    if (meta) {
        metasize = meta->size;

        // new meta size cannot be larger than old meta size
        fdb_assert(metasize <= old_metasize, metasize, old_metasize);
        (void)metasize;

        // overwrite
        if (meta->size > 0) {
            _metasize = _endian_encode(metasize);
            memcpy(ptr, &_metasize, sizeof(metasize_t));
            memcpy((uint8_t *)ptr + sizeof(metasize_t), meta->data, metasize);
            node->flag |= BNODE_MASK_METADATA;
        } else {
            // clear the flag
            node->flag &= ~BNODE_MASK_METADATA;
        }
        // move kv-pairs (only if meta size is changed)
        if (_metasize_align(metasize) < _metasize_align(old_metasize)){
            memmove( (uint8_t *)ptr + sizeof(metasize_t) + _metasize_align(metasize),
                     node->data,
                     kv_ops->getDataSize(node, NULL, NULL, NULL, 0) );
            node->data = (uint8_t *)node->data -
                         ( _metasize_align(old_metasize) - _metasize_align(metasize) );
        }

    } else {
        if (node->flag & BNODE_MASK_METADATA) {
            // existing metadata is removed
            memmove(ptr, node->data, kv_ops->getDataSize(node, NULL, NULL, NULL, 0));
            node->data = (uint8_t *)node->data -
                         ( _metasize_align(old_metasize) + sizeof(metasize_t) );
            // clear the flag
            node->flag &= ~BNODE_MASK_METADATA;
        }
    }

    if (!bhandle->isWritable(root_bid)) {
        // already flushed block -> cannot overwrite, we have to move to new block
        bhandle->move(root_bid, root_bid);
    } else {
        bhandle->setDirty(root_bid);
    }
}

/*
return index# of largest key equal or smaller than KEY
example)
node: [2 4 6 8]
key: 5
largest key equal or smaller than KEY: 4
return: 1 (index# of the key '4')
*/
idx_t BTree::findEntry(struct bnode *node, void *key)
{
    idx_t start, end, middle, temp;
    uint8_t *k = alca(uint8_t, ksize);
    int cmp;

#ifdef __BIT_CMP
    // for fast assign without branch
    idx_t *_map1[3] = {&end, &start, &start};
    idx_t *_map2[3] = {&temp, &end, &temp};
#endif

    kv_ops->initKVVar(k, NULL);

    // binary search
    start = middle = 0;
    end = node->nentry;

    if (end > 0) {
        // compare with smallest key
        kv_ops->getKV(node, 0, k, NULL);
        // smaller than smallest key
        if (kv_ops->cmp(key, k, aux) < 0) {
            kv_ops->freeKVVar(k, NULL);
            return BTREE_IDX_NOT_FOUND;
        }

        // compare with largest key
        kv_ops->getKV(node, end-1, k, NULL);
        // larger than largest key
        if (kv_ops->cmp(key, k, aux) >= 0) {
            kv_ops->freeKVVar(k, NULL);
            return end-1;
        }

        // binary search
        while(start+1 < end) {
            middle = (start + end) >> 1;

            // get key at middle
            kv_ops->getKV(node, middle, k, NULL);
            cmp = kv_ops->cmp(key, k, aux);

#ifdef __BIT_CMP
            cmp = _MAP(cmp) + 1;
            *_map1[cmp] = middle;
            *_map2[cmp] = 0;
#else
            if (cmp < 0) {
                end = middle;
            } else if (cmp > 0) {
                start = middle;
            } else {
                kv_ops->freeKVVar(k, NULL);
                return middle;
            }
#endif
        }
        kv_ops->freeKVVar(k, NULL);
        return start;
    }

    kv_ops->freeKVVar(k, NULL);
    return BTREE_IDX_NOT_FOUND;
}

idx_t BTree::addEntry(struct bnode *node, void *key, void *value)
{
    idx_t idx, idx_insert;
    uint8_t *k = alca(uint8_t, ksize);

    kv_ops->initKVVar(k, NULL);

    if (node->nentry > 0) {
        idx = findEntry(node, key);

        if (idx == BTREE_IDX_NOT_FOUND) idx_insert = 0;
        else {
            kv_ops->getKV(node, idx, k, NULL);
            if (!kv_ops->cmp(key, k, aux)) {
                // if same key already exists -> update its value
                kv_ops->setKV(node, idx, key, value);
                kv_ops->freeKVVar(k, NULL);
                return idx;
            } else {
                idx_insert = idx+1;
            }
        }

        if (idx_insert < node->nentry) {

            /*
            shift [idx+1, nentry) key-value pairs to right
            example)
            idx = 1 (i.e. idx_insert = 2)
            [2 4 6 8] -> [2 4 _ 6 8]
            return 2
            */
            kv_ops->insKV(node, idx_insert, key, value);
        }else{
            kv_ops->setKV(node, idx_insert, key, value);
        }

    } else {
        idx_insert = 0;
        // add at idx_insert
        kv_ops->setKV(node, idx_insert, key, value);
    }

    // add at idx_insert
    node->nentry++;

    kv_ops->freeKVVar(k, NULL);
    return idx_insert;
}

idx_t BTree::removeEntry(struct bnode *node, void *key)
{
    idx_t idx;

    if (node->nentry > 0) {
        idx = findEntry(node, key);

        if (idx == BTREE_IDX_NOT_FOUND) return idx;

        /*
        shift [idx+1, nentry) key-value pairs to left
        example)
        idx = 2
        [2 4 6 8 10] -> [2 4 8 10]
        return 2
        */
        kv_ops->insKV(node, idx, NULL, NULL);

        node->nentry--;

        return idx;

    } else {
        return BTREE_IDX_NOT_FOUND;
    }
}

btree_result BTree::getKeyRange(idx_t num, idx_t den, void *key_begin, void *key_end)
{
    void *addr;
    uint8_t *k = alca(uint8_t, ksize);
    uint8_t *v = alca(uint8_t, vsize);
    idx_t idx_begin, idx_end, idx;
    bid_t bid;
    struct bnode *root, *node;
    uint64_t _num, _den, _nentry, resolution, mask, _idx_begin, _idx_end;

    if (num >= den) {
        // TODO: Need to log the corresponding error message
        return BTREE_RESULT_FAIL;
    }
    resolution = 1<<4; mask = resolution-1;

    kv_ops->initKVVar(k, v);
    _num = (uint64_t)num * resolution;
    _den = (uint64_t)den * resolution;

    // get root node
    addr = bhandle->read(root_bid);
    root = _fetch_bnode(addr, height);
    _nentry = (uint64_t)root->nentry * resolution;

    if (height == 1) {
        kv_ops->getKV(root, ((num+0) * root->nentry / den)-0, key_begin, NULL);
        kv_ops->getKV(root, ((num+1) * root->nentry / den)-1, key_end, NULL);
    }else{
        _idx_begin = (_num * _nentry / _den);
        _idx_end = ((_num+resolution) * _nentry / _den)-1;

        idx_begin = _idx_begin / resolution;
        idx_end = (_idx_end / resolution);
        if (idx_end >= root->nentry) idx_end = root->nentry-1;

        // get first child node (for KEY_BEGIN)
        kv_ops->getKV(root, idx_begin, k, v);
        bid = kv_ops->value2bid(v);
        bid = _endian_decode(bid);
        addr = bhandle->read(bid);
        node = _fetch_bnode(addr, height-1);

        idx = ((_idx_begin & mask) * (node->nentry-1) / (resolution-1));
        kv_ops->getKV(node, idx, key_begin, NULL);

        // get second child node (for KEY_END)
        if (idx_end != idx_begin) {
            kv_ops->getKV(root, idx_end, k, v);
            bid = kv_ops->value2bid(v);
            bid = _endian_decode(bid);
            addr = bhandle->read(bid);
            node = _fetch_bnode(addr, height-1);
        }

        idx = ((_idx_end & mask) * (node->nentry-1) / (resolution-1));
        kv_ops->getKV(node, idx, key_end, NULL);
    }

    kv_ops->freeKVVar(k, v);
    return BTREE_RESULT_SUCCESS;
}

btree_result BTree::find(void *key, void *value_buf)
{
    void *addr;
    uint8_t *k = alca(uint8_t, ksize);
    uint8_t *v = alca(uint8_t, vsize);
    idx_t *idx = alca(idx_t, height);
    bid_t *bid = alca(bid_t, height);
    struct bnode **node = alca(struct bnode *, height);
    int i;

    kv_ops->initKVVar(k, v);

    // set root
    bid[height-1] = root_bid;

    for (i = height-1 ; i>=0 ; --i) {
        // read block using bid
        addr = bhandle->read(bid[i]);
        // fetch node structure from block
        node[i] = _fetch_bnode(addr, i+1);

        // lookup key in current node
        idx[i] = findEntry(node[i], key);

        if (idx[i] == BTREE_IDX_NOT_FOUND) {
            // not found .. return NULL
            bhandle->operationEnd();
            kv_ops->freeKVVar(k, v);
            return BTREE_RESULT_FAIL;
        }

        kv_ops->getKV(node[i], idx[i], k, v);

        if (i>0) {
            // index (non-leaf) node
            // get bid of child node from value
            bid[i-1] = kv_ops->value2bid(v);
            bid[i-1] = _endian_decode(bid[i-1]);
        } else {
            // leaf node
            // return (address of) value if KEY == k
            if (!kv_ops->cmp(key, k, aux)) {
                kv_ops->setValue(value_buf, v);
            } else {
                bhandle->operationEnd();
                kv_ops->freeKVVar(k, v);
                return BTREE_RESULT_FAIL;
            }
        }
    }

    bhandle->operationEnd();
    kv_ops->freeKVVar(k, v);
    return BTREE_RESULT_SUCCESS;
}

int BTree::splitNode(void *key, struct bnode **node, bid_t *bid, idx_t *idx,
                     int i, struct list *kv_ins_list, size_t nsplitnode,
                     void *k, void *v, int8_t *modified, int8_t *minkey_replace,
                     int8_t *ins)
{
    void *addr;
    size_t nnode = nsplitnode;
    size_t j;
    int *nentry = alca(int, nnode);
    memset(nentry, 0, nnode * sizeof(int));
    bid_t _bid;
    bid_t *new_bid = alca(bid_t, nnode);
    memset(new_bid, 0, nnode * sizeof(bid_t));
    idx_t *split_idx = alca(idx_t, nnode+1);
    memset(split_idx, 0, (nnode + 1) * sizeof(idx_t));
    idx_t *idx_ins = alca(idx_t, height);
    memset(idx_ins, 0, height * sizeof(idx_t));
    struct list_elem *e;
    struct bnode **new_node = alca(struct bnode *, nnode);
    memset(new_node, 0, nnode * sizeof(struct bnode*));
    struct kv_ins_item *kv_item = NULL;

    // allocate new block(s)
    new_node[0] = node[i];
    for (j = 1 ; j < nnode ; ++j){
        addr = bhandle->alloc(new_bid[j]);
        new_node[j] = initNode(addr, 0x0, node[i]->level, NULL);
    }

    // calculate # entry
    for (j = 0 ; j < nnode+1 ; ++j){
        split_idx[j] = kv_ops->getNthIdx(node[i], j, nnode);
        if (j > 0) {
            nentry[j-1] = split_idx[j] - split_idx[j-1];
        }
    }

    // copy kv-pairs to new node(s)
    for (j = 1 ; j < nnode ; ++j){
        kv_ops->copyKV(new_node[j], node[i], 0, split_idx[j], nentry[j]);
    }
    j = 0;
    kv_ops->copyKV(new_node[j], node[i], 0, split_idx[j], nentry[j]);

    // header
    for (j = 0 ; j < nnode ; ++j){
        new_node[j]->nentry = nentry[j];
    }
    modified[i] = 1;

    if (ins[i]) {
        // insert kv-pair(s) to appropriate node
        e = list_begin(&kv_ins_list[i]);
        while(e) {
            kv_item = _get_entry(e, struct kv_ins_item, le);

            idx_ins[i] = BTREE_IDX_NOT_FOUND;
            for (j=1;j<nnode;++j){
                kv_ops->getKV(new_node[j], 0, k, v);
                if (kv_ops->cmp(kv_item->key, k, aux) < 0) {
                    idx_ins[i] = addEntry(new_node[j-1], kv_item->key, kv_item->value);
                    break;
                }
            }
            if (idx_ins[i] == BTREE_IDX_NOT_FOUND) {
                // insert into the last split node
                idx_ins[i] = addEntry(new_node[nnode-1], kv_item->key, kv_item->value);
            }
            e = list_next(e);
        }
    }
    if (minkey_replace[i]){
        // replace the minimum key in the (first split) node to KEY
        kv_ops->getKV(new_node[0], idx[i], k, v);
        kv_ops->setKV(new_node[0], idx[i], key, v);
    }

    if (i+1 < height) {
        // non-root node
        // reserve kv-pair (i.e. splitters) to be inserted into parent node
        for (j = 1 ; j < nnode ; ++j){
            _bid = _endian_encode(new_bid[j]);
            kv_item = createKVInsItem(NULL, (void *)&_bid);
            kv_ops->getNthSplitter(new_node[j-1], new_node[j], kv_item->key);
            list_push_back(&kv_ins_list[i+1], &kv_item->le);
        }
        ins[i+1] = 1;

    } else {
        //2 root node -> height grow up
        // allocate new block for new root node
        bid_t new_root_bid;
        struct bnode *new_root;
        uint8_t *buf = alca(uint8_t, blksize);
        struct btree_meta meta;

        meta.size = readMeta(buf);
        meta.data = buf;
        // remove metadata section of existing node
        // (this node is not root anymore)
        updateMeta(NULL);

        height++;

        addr = bhandle->alloc(new_root_bid);
        if (meta.size > 0) {
            new_root = initNode(addr, root_flag, node[i]->level + 1, &meta);
        } else {
            new_root = initNode(addr, root_flag, node[i]->level + 1, NULL);
        }

        // clear old root node flag
        node[i]->flag &= ~BNODE_MASK_ROOT;
        node[i]->flag &= ~BNODE_MASK_SEQTREE;
        // change root bid
        root_bid = new_root_bid;

        // move the former node if not dirty
        if (!bhandle->isWritable(bid[i])) {
            addr = bhandle->move(bid[i], bid[i]);
            node[i] = _fetch_bnode(addr, i+1);
        } else {
            bhandle->setDirty(bid[i]);
        }

        // insert kv-pairs pointing to their child nodes
        // original (i.e. the first node)
        kv_ops->getKV(node[i], 0, k, v);
        _bid = _endian_encode(bid[i]);
        addEntry(new_root, k, kv_ops->bid2value(&_bid));

        // the others
        for (j=1;j<nnode;++j){
            //btree->kv_ops->get_kv(new_node[j], 0, k, v);
            kv_ops->getNthSplitter(new_node[j-1], new_node[j], k);
            _bid = _endian_encode(new_bid[j]);
            addEntry(new_root, k, kv_ops->bid2value(&_bid));
        }

        return 1;
    } // height growup

    return 0;
}

int BTree::moveModifiedNode(void *key, struct bnode **node, bid_t *bid,
                            idx_t *idx, int i, struct list *kv_ins_list,
                            void *k, void *v, int8_t *modified, int8_t *minkey_replace,
                            int8_t *ins, int8_t *moved)
{
    void *addr;

    // get new bid[i]
    addr = bhandle->move(bid[i], bid[i]);
    (void)addr;
    moved[i] = 1;

    if (i+1 == height)
        // if moved node is root node
        root_bid = bid[i];

    return 0;
}

btree_result BTree::insert(void *key, void *value)
{
    void *addr;
    size_t nsplitnode = 1;
    uint8_t *k = alca(uint8_t, ksize);
    uint8_t *v = alca(uint8_t, vsize);
    // index# and block ID for each level
    idx_t *idx = alca(idx_t, height);
    bid_t *bid = alca(bid_t, height);
    bid_t _bid;
    // flags
    int8_t *modified = alca(int8_t, height);
    int8_t *moved = alca(int8_t, height);
    int8_t *ins = alca(int8_t, height);
    int8_t *minkey_replace = alca(int8_t, height);
    int8_t height_growup;

    // key, value to be inserted
    struct list *kv_ins_list = alca(struct list, height);
    struct kv_ins_item *kv_item;
    struct list_elem *e;

    // index# where kv is inserted
    idx_t *idx_ins = alca(idx_t, height);
    struct bnode **node = alca(struct bnode *, height);
    int i, j, _is_update = 0;

    // initialize flags
    for (i =0 ; i < height ; ++i) {
        moved[i] = modified[i] = ins[i] = minkey_replace[i] = 0;
    }
    height_growup = 0;

    // initialize temporary variables
    kv_ops->initKVVar(k, v);
    for (i = 0 ; i < height ; ++i){
        list_init(&kv_ins_list[i]);
    }

    // copy key-value pair to be inserted into leaf node
    kv_item = createKVInsItem(key, value);
    list_push_back(&kv_ins_list[0], &kv_item->le);

    ins[0] = 1;

    // set root node
    bid[height-1] = root_bid;

    // find path from root to leaf
    for (i = height-1 ; i >= 0 ; --i){
        // read block using bid
        addr = bhandle->read(bid[i]);
        // fetch node structure from block
        node[i] = _fetch_bnode(addr, i+1);

        // lookup key in current node
        idx[i] = findEntry(node[i], key);

        if (i > 0) {
            // index (non-leaf) node
            if (idx[i] == BTREE_IDX_NOT_FOUND) {
                // KEY is smaller than the smallest key in this node ..
                // just follow the smallest key
                idx[i] = 0;
            }

            // get bid of child node from value
            kv_ops->getKV(node[i], idx[i], k, v);
            bid[i-1] = kv_ops->value2bid(v);
            bid[i-1] = _endian_decode(bid[i-1]);
        }else{
            // leaf node .. do nothing
        }
    }

    // cascaded insert from leaf to root
    for (i = 0 ; i < height ; ++i){

        if (idx[i] != BTREE_IDX_NOT_FOUND)
            kv_ops->getKV(node[i], idx[i], k, NULL);

        if (i > 0) {
            // in case of index node
            // when KEY is smaller than smallest key in index node
            if (idx[i] == 0 && kv_ops->cmp(key, k, aux) < 0) {
                // change node's smallest key
                minkey_replace[i] = 1;
            }

            // when child node is moved to new block
            if (moved[i-1]) {
                // replace the bid (value)
                _bid = _endian_encode(bid[i-1]);
                kv_ops->setKV(node[i], idx[i], k, kv_ops->bid2value(&_bid));
                modified[i] = 1;
            }
        }

        if (ins[i] || minkey_replace[i]) {
            // there is a key-value pair to be inserted into this (level of)
            // node check whether btree node space is enough to add new
            // key-value pair or not, OR action is not insertion but update
            // (key_ins exists in current node)
            _is_update = 0;
            size_t nodesize;
            void *new_minkey = (minkey_replace[i])?(key):(NULL);

            if (i==0) {
                e = list_begin(&kv_ins_list[i]);
                kv_item = _get_entry(e, struct kv_ins_item, le);
                _is_update = ( idx[i] != BTREE_IDX_NOT_FOUND  &&
                               !kv_ops->cmp(kv_item->key, k, aux) );
            }

check_node:
            int _size_check = checkBNodeSize(bid[i], node[i], new_minkey,
                                             &kv_ins_list[i], nodesize);

            if (_size_check || _is_update ) {
                //2 enough space
                if (ins[i]) {
                    // insert key/value pair(s)
                    // insert all kv pairs on list
                    e = list_begin(&kv_ins_list[i]);
                    while(e) {
                        kv_item = _get_entry(e, struct kv_ins_item, le);
                        idx_ins[i] = addEntry(node[i], kv_item->key, kv_item->value);
                        e = list_next(e);
                    }
                }
                if (minkey_replace[i]) {
                    // replace the minimum key in the node to KEY
                    kv_ops->getKV(node[i], idx[i], k, v);
                    kv_ops->setKV(node[i], idx[i], key, v);
                }
                modified[i] = 1;

            } else {
                //2 not enough
                // first check if the node can be enlarged
                if (is_subblock(bid[i])) {
                    bid_t new_bid;
                    addr = bhandle->enlargeNode(bid[i], nodesize, new_bid);
                    if (addr) {
                        // the node can be enlarged .. fetch the enlarged node
                        moved[i] = 1;
                        bid[i] = new_bid;
                        node[i] = _fetch_bnode(addr, i+1);
                        if (i+1 == height) {
                            // if moved node is root node
                            root_bid = bid[i];
                        }
                        // start over
                        goto check_node;
                    }
                }

                //otherwise, split the node
                nsplitnode = getNSplitNode(BLK_NOT_FOUND, node[i], nodesize);
                // force the node split when the node size of new layout is
                // larger than the current node size
                if (nsplitnode == 1) {
                    nsplitnode = 2;
                }

                height_growup = splitNode(key, node, bid, idx, i, kv_ins_list,
                                          nsplitnode, k, v, modified,
                                          minkey_replace, ins);
            } // split
        } // insert

        if (height_growup) {
            break;
        }

        if (modified[i]) {
            //2 when the node is modified
            if (!bhandle->isWritable(bid[i])) {
                // not writable .. already flushed block -> cannot overwrite,
                // we have to move to new block
                height_growup = moveModifiedNode(key, node, bid, idx, i,
                    kv_ins_list, k, v,
                    modified, minkey_replace, ins, moved);

                if (height_growup) {
                    break;
                }
            } else {
                // writable .. just set dirty to write back into storage
                bhandle->setDirty(bid[i]);
            } // is writable
        } // is modified
    } // for loop

    // release temporary resources
    bhandle->operationEnd();
    kv_ops->freeKVVar(k, v);

    for (j=0 ; j < ( (height_growup) ? (height-1) : (height) ) ; ++j){
        e = list_begin(&kv_ins_list[j]);
        while(e) {
            kv_item = _get_entry(e, struct kv_ins_item, le);
            e = list_remove(&kv_ins_list[j], e);

            kv_ops->freeKVVar(kv_item->key, kv_item->value);
            freeKVInsItem(kv_item);
        }
    }

    if (_is_update) {
        return BTREE_RESULT_UPDATE;
    } else {
        return BTREE_RESULT_SUCCESS;
    }
}

btree_result BTree::remove(void *key)
{
    void *addr;
    uint8_t *k = alca(uint8_t, ksize);
    uint8_t *v= alca(uint8_t, vsize);
    uint8_t *kk = alca(uint8_t, ksize);
    uint8_t *vv = alca(uint8_t, vsize);
    // index# and block ID for each level
    idx_t *idx = alca(idx_t, height);
    bid_t *bid= alca(bid_t, height);
    bid_t _bid;
    // flags
    int8_t *modified = alca(int8_t, height);
    int8_t *moved = alca(int8_t, height);
    int8_t *rmv = alca(int8_t, height);
    // index# of removed key
    idx_t *idx_rmv = alca(idx_t, height);
    struct bnode **node = alca(struct bnode *, height);
    int i;

    // initialize flags
    for (i = 0 ; i < height ; ++i) {
        moved[i] = modified[i] = rmv[i] = 0;
    }
    kv_ops->initKVVar(k, v);
    kv_ops->initKVVar(kk, vv);

    rmv[0] = 1;

    // set root
    bid[height-1] = root_bid;

    // find path from root to leaf
    for (i = height-1 ; i >= 0 ; --i) {
        // read block using bid
        addr = bhandle->read(bid[i]);
        // fetch node structure from block
        node[i] = _fetch_bnode(addr, i+1);

        // lookup key in current node
        idx[i] = findEntry(node[i], key);

        if (idx[i] == BTREE_IDX_NOT_FOUND) {
            // not found
            bhandle->operationEnd();
            kv_ops->freeKVVar(k, v);
            kv_ops->freeKVVar(kk, vv);
            return BTREE_RESULT_FAIL;
        }

        kv_ops->getKV(node[i], idx[i], k, v);

        if (i>0) {
            // index (non-leaf) node
            // get bid of child node from value
            bid[i-1] = kv_ops->value2bid(v);
            bid[i-1] = _endian_decode(bid[i-1]);
        } else {
            // leaf node .. do nothing
        }
    }

    // cascaded remove from leaf to root
    for (i = 0 ; i < height ; ++i){
        // in case of index node
        if (i > 0) {
            kv_ops->getKV(node[i], idx[i], k, v);

            // when child node's smallest key is changed due to remove
              if (node[i-1]->nentry > 0) {
                kv_ops->getKV(node[i-1], 0, kk, vv);
                if (kv_ops->cmp(kk, k, aux)) {
                    // change current node's corresponding key
                    kv_ops->setKV(node[i], idx[i], kk, v);
                    kv_ops->setKey(k, kk);
                    modified[i] = 1;
                }
            }

            // when child node is moved to new block
            if (moved[i-1]) {
                // replace the bid (value)
                _bid = _endian_encode(bid[i-1]);
                kv_ops->setKV(node[i], idx[i], k, kv_ops->bid2value(&_bid));
                modified[i] = 1;
            }
        }

        if (rmv[i]) {
            // there is a key-value pair to be removed
            kv_ops->getKV(node[i], idx[i], k, v);
            idx_rmv[i] = removeEntry(node[i], k);
            modified[i] = 1;

            // remove the node when
            // 1. non-root node has no kv-pair or
            // 2. root node has less or equal than one kv-pair
            if ( ( (node[i]->nentry <  1 && i+1 <  height) ||
                   (node[i]->nentry <= 1 && i+1 == height) ) &&
                 height > 1 ) {
                // remove the node
                bhandle->remove(bid[i]);
                if (i+1 < height) {
                    // if non-root node
                    rmv[i+1] = 1;
                } else {
                    // if root node, shrink the height

                    // allocate new block for new root node
                    uint8_t *buf = alca(uint8_t, blksize);
                    uint32_t nodesize = 0, new_rootsize = 0;
                    bid_t child_bid, new_root_bid;
                    struct bnode *new_root, *child;
                    struct btree_meta meta;

                    // read the child node
                    kv_ops->getKV(node[i], 0, k, v);
                    child_bid = kv_ops->value2bid(v);
                    child_bid = _endian_decode(child_bid);
                    addr = bhandle->read(child_bid);
                    child = _fetch_bnode(addr, height);

                    nodesize = bhandle->getBlockSize(child_bid);
#ifdef __CRC32
                    nodesize -= BLK_MARKER_SIZE;
#endif

                    // estimate the new root node size including metadata
                    meta.size = readMeta(buf);
                    meta.data = buf;

                    if (meta.size) {
                        new_rootsize += _metasize_align(meta.size) +
                                        sizeof(metasize_t);
                    }
                    new_rootsize += kv_ops->getDataSize(child, NULL, NULL, NULL, 0);
                    new_rootsize += sizeof(struct bnode);

                    if (new_rootsize < nodesize) {
                        // new root node has enough space for metadata .. shrink height
                        height--;

                        // allocate a new node with the given meta
                        addr = bhandle->alloc(new_root_bid);
                        initNode(addr, root_flag, height, &meta);
                        new_root = _fetch_bnode(addr, height);

                        // copy all entries
                        kv_ops->copyKV(new_root, child, 0, 0, child->nentry);
                        new_root->nentry = child->nentry;
                        // invalidate chlid node
                        bhandle->remove(child_bid);

                        root_bid = new_root_bid;

                        // as the old node is invalidated,
                        // we don't need to move it.
                        modified[i] = 0;
                    }
                }
            }
        }

        if (modified[i]) {
            // when node is modified
            if (!bhandle->isWritable(bid[i])) {
                // already flushed block -> cannot overwrite, so
                // we have to move to new block
                // get new bid[i]
                addr = bhandle->move(bid[i], bid[i]);
                node[i] = _fetch_bnode(addr, i+1);
                moved[i] = 1;

                if (i+1 == height)
                    // if moved node is root node
                    root_bid = bid[i];

            }else{
                bhandle->setDirty(bid[i]);
            }

        }
    }

    bhandle->operationEnd();
    kv_ops->freeKVVar(k, v);
    kv_ops->freeKVVar(kk, vv);
    return BTREE_RESULT_SUCCESS;
}

BTreeIterator::BTreeIterator(BTree *_btree, void *_initial_key)
{
    init(_btree, _initial_key);
}

BTreeIterator::~BTreeIterator()
{
    int i;
    btree->getKVOps()->freeKVVar(curkey, NULL);
    free(curkey);
    free(bid_arr);
    free(idx_arr);
    for (i = 0 ; i < btree->getHeight() ; ++i){
        if (node_arr[i]) {
            free(addr_arr[i]);
        }
    }
    free(node_arr);
    free(addr_arr);
    // set btree instance to null to avoid delete it
    // ('btree' is just pointing to existing instance
    //  so we should avoid free it here.)
    btree = nullptr;
}

btree_result BTreeIterator::init(BTree *_btree, void *_initial_key)
{
    int i;
    uint16_t btree_height = _btree->getHeight();
    BTreeKVOps *kv_ops = _btree->getKVOps();

    // just pointing to the existing btree
    btree = _btree;
    curkey = (void *)calloc(1, btree->getKSize());
    kv_ops->initKVVar(curkey, NULL);
    if (_initial_key) {
        // set initial key if exists
        kv_ops->setKey(curkey, _initial_key);
    } else {
        // NULL initial key .. set minimum key (start from leftmost key)
        // Note: replaced by kv_ops->init_kv_var above
    }
    bid_arr = (bid_t*)calloc(btree_height, sizeof(bid_t));
    idx_arr = (idx_t*)calloc(btree_height, sizeof(idx_t));
    node_arr = (struct bnode **)calloc(btree_height, sizeof(struct bnode *));
    addr_arr = (void**)calloc(btree_height, sizeof(void*));

    for (i=0;i<btree_height;++i){
        bid_arr[i] = BTREE_BLK_NOT_FOUND;
        idx_arr[i] = BTREE_IDX_NOT_FOUND;
        node_arr[i] = NULL;
        addr_arr[i] = NULL;
    }
    bid_arr[btree_height-1] = btree->getRootBid();
    flags = 0;

    return BTREE_RESULT_SUCCESS;
}

btree_result BTreeIterator::_prev(void *key_buf, void *value_buf, int depth)
{
    int i;
    uint8_t *k = alca(uint8_t, btree->getKSize());
    uint8_t *v = alca(uint8_t, btree->getVSize());
    void *addr;
    struct bnode *node;
    BTreeKVOps *kv_ops = btree->getKVOps();
    btree_result r;

    kv_ops->initKVVar(k, v);

    if (node_arr[depth] == NULL){
        size_t blksize;
        addr = btree->getBhandle()->read(bid_arr[depth]);
        addr_arr[depth] = (void *)mempool_alloc(btree->getBlkSize());
        blksize = btree->getBhandle()->getBlockSize(bid_arr[depth]);
        memcpy(addr_arr[depth], addr, blksize);
        node_arr[depth] = _fetch_bnode(addr_arr[depth], depth+1);
    }
    node = _fetch_bnode(addr_arr[depth], depth+1);
    //assert(node->level == depth+1);

    if (node->nentry <= 0) {
        kv_ops->freeKVVar(k, v);
        if (node_arr[depth] != NULL) {
            mempool_free(addr_arr[depth]);
        }
        node_arr[depth] = NULL;
        addr_arr[depth] = NULL;
        return BTREE_RESULT_FAIL;
    }

    if (idx_arr[depth] == BTREE_IDX_NOT_FOUND) {
        // curkey: lastly returned key
        idx_arr[depth] = btree->findEntry(node, curkey);
        if (idx_arr[depth] == BTREE_IDX_NOT_FOUND) {
            idx_arr[depth] = 0;
           // it->idx[depth] = node->nentry - 1;
        }
        kv_ops->getKV(node, idx_arr[depth], key_buf, value_buf);
        if (kv_ops->cmp(curkey, key_buf, btree->getAux()) < 0 &&
            depth == 0) {
            // in leaf node, prev key must be smaller than current key
            idx_arr[depth] = idx_arr[depth] ? idx_arr[depth] - 1
                                            : BTREE_IDX_NOT_FOUND;
        } // else return the value at idx[depth] at this turn
    }

    if (flagsIsFwd() && depth ==0) {
        if (idx_arr[depth] >= 2) {
            idx_arr[depth] -= 2;
        } else {
            // out-of-bounds
            idx_arr[depth] = node->nentry; // ending condition
            // we have to reset flag because _btree_prev will recursively
            // visit the left leaf node.
            flagsSetNone();
        }
    }

    if (idx_arr[depth] >= node->nentry) { // reused nentry for ending iteration
        // out of bound .. go up to parent node
        idx_arr[depth] = BTREE_IDX_NOT_FOUND; // reset for btree_next
        if (node_arr[depth] != NULL) {
            mempool_free(addr_arr[depth]);
        }
        node_arr[depth] = NULL;
        addr_arr[depth] = NULL;

        kv_ops->freeKVVar(k, v);
        return BTREE_RESULT_FAIL;
    }

    if (depth > 0) {
        // index node
        if (node_arr[depth-1] == NULL) {
            kv_ops->getKV(node, idx_arr[depth], k, v);
            bid_arr[depth-1] = kv_ops->value2bid(v);
            bid_arr[depth-1] = _endian_decode(bid_arr[depth-1]);
        }
        r = _prev(key_buf, value_buf, depth-1);

        if (r == BTREE_RESULT_FAIL) {
            // move index to left
            idx_arr[depth] = idx_arr[depth] ? idx_arr[depth] - 1
                                            : node->nentry; // ending condition

            if (idx_arr[depth] >= node->nentry){
                // out of bound .. go up to parent node
                idx_arr[depth] = BTREE_IDX_NOT_FOUND;
                if (node_arr[depth] != NULL) {
                    mempool_free(addr_arr[depth]);
                }
                node_arr[depth] = NULL;
                addr_arr[depth] = NULL;

                kv_ops->freeKVVar(k, v);
                return BTREE_RESULT_FAIL;
            } else {
                kv_ops->getKV(node, idx_arr[depth], k, v);
                bid_arr[depth-1] = kv_ops->value2bid(v);
                bid_arr[depth-1] = _endian_decode(bid_arr[depth-1]);
                // reset child index
                for (i=depth-1; i>=0; --i) {
                    idx_arr[i] = BTREE_IDX_NOT_FOUND;
                    if (node_arr[i] != NULL) {
                        mempool_free(addr_arr[i]);
                    }
                    node_arr[i] = NULL;
                    addr_arr[i] = NULL;
                }
                // retry
                r = _prev(key_buf, value_buf, depth-1);
            }
        }
        kv_ops->freeKVVar(k, v);
        return r;
    } else {
        // leaf node
        kv_ops->getKV(node, idx_arr[depth], key_buf, value_buf);
        kv_ops->setKey(curkey, key_buf);
        idx_arr[depth] = idx_arr[depth] ? (idx_arr[depth] - 1) :
                                          (node->nentry); // condition for ending
        kv_ops->freeKVVar(k, v);
        return BTREE_RESULT_SUCCESS;
    }
}

btree_result BTreeIterator::prev(void *key_buf, void *value_buf)
{
    btree_result br = _prev(key_buf, value_buf, btree->getHeight()-1);
    if (br == BTREE_RESULT_SUCCESS) {
        flagsSetRev();
    } else {
        flagsSetNone();
    }
    return br;
}

btree_result BTreeIterator::_next(void *key_buf, void *value_buf, int depth)
{
    int i;
    uint8_t *k = alca(uint8_t, btree->getKSize());
    uint8_t *v = alca(uint8_t, btree->getVSize());
    void *addr;
    struct bnode *node;
    BTreeKVOps *kv_ops = btree->getKVOps();
    btree_result r;

    kv_ops->initKVVar(k, v);

    if (node_arr[depth] == NULL){
        size_t blksize;
        addr = btree->getBhandle()->read(bid_arr[depth]);
        addr_arr[depth] = (void *)mempool_alloc(btree->getBlkSize());
        blksize = btree->getBhandle()->getBlockSize(bid_arr[depth]);
        memcpy(addr_arr[depth], addr, blksize);
        node_arr[depth] = _fetch_bnode(addr_arr[depth], depth+1);
    }
    node = _fetch_bnode(addr_arr[depth], depth+1);

    if (node->nentry <= 0) {
        kv_ops->freeKVVar(k, v);
        if (node_arr[depth] != NULL) {
            mempool_free(addr_arr[depth]);
        }
        node_arr[depth] = NULL;
        addr_arr[depth] = NULL;
        return BTREE_RESULT_FAIL;
    }

    if (idx_arr[depth] == BTREE_IDX_NOT_FOUND) {
        // curkey: lastly returned key
        idx_arr[depth] = btree->findEntry(node, curkey);
        if (idx_arr[depth] == BTREE_IDX_NOT_FOUND) {
            idx_arr[depth] = 0;
        }
        kv_ops->getKV(node, idx_arr[depth], key_buf, value_buf);
        if (kv_ops->cmp(curkey, key_buf, btree->getAux()) > 0 &&
            depth == 0) {
            // in leaf node, next key must be larger than previous key
            // (i.e. it->curkey)
            idx_arr[depth]++;
        }
    }

    if (flagsIsRev() && depth == 0) {
        if (idx_arr[depth] >= node->nentry) {
            // 'idx' becomes out-of-bounds by previous btree_prev() call.
            // this means that the last returned entry was the smallest entry.
            // set idx to the second smallest entry.
            idx_arr[depth] = 1;
        } else {
            idx_arr[depth] += 2;
        }
    }

    if (idx_arr[depth] >= node->nentry) {
        // out of bound .. go up to parent node
        idx_arr[depth] = BTREE_IDX_NOT_FOUND; // reset for btree_prev
        if (node_arr[depth] != NULL) {
            mempool_free(addr_arr[depth]);
        }
        node_arr[depth] = NULL;
        addr_arr[depth] = NULL;

        kv_ops->freeKVVar(k, v);
        return BTREE_RESULT_FAIL;
    }

    if (depth > 0) {
        // index node
        if (node_arr[depth-1] == NULL) {
            kv_ops->getKV(node, idx_arr[depth], k, v);
            bid_arr[depth-1] = kv_ops->value2bid(v);
            bid_arr[depth-1] = _endian_decode(bid_arr[depth-1]);
        }
        r = _next(key_buf, value_buf, depth-1);

        if (r == BTREE_RESULT_FAIL) {
            // move index to right
            idx_arr[depth]++;

            if (idx_arr[depth] >= node->nentry){
                // out of bound .. go up to parent node
                idx_arr[depth] = BTREE_IDX_NOT_FOUND;
                if (node_arr[depth] != NULL) {
                    mempool_free(addr_arr[depth]);
                }
                node_arr[depth] = NULL;
                addr_arr[depth] = NULL;

                kv_ops->freeKVVar(k, v);
                return BTREE_RESULT_FAIL;
            }else{
                kv_ops->getKV(node, idx_arr[depth], k, v);
                bid_arr[depth-1] = kv_ops->value2bid(v);
                bid_arr[depth-1] = _endian_decode(bid_arr[depth-1]);
                // reset child index
                for (i=depth-1; i>=0; --i) {
                    idx_arr[i] = 0;
                    if (node_arr[i] != NULL) {
                        mempool_free(addr_arr[i]);
                    }
                    node_arr[i] = NULL;
                    addr_arr[i] = NULL;
                }
                // retry
                r = _next(key_buf, value_buf, depth-1);
            }
        }
        kv_ops->freeKVVar(k, v);
        return r;
    }else{
        // leaf node
        kv_ops->getKV(node, idx_arr[depth], key_buf, value_buf);
        //memcpy(it->curkey, key_buf, btree->ksize);
        kv_ops->setKey(curkey, key_buf);
        idx_arr[depth]++;
        kv_ops->freeKVVar(k, v);
        return BTREE_RESULT_SUCCESS;
    }
}

btree_result BTreeIterator::next(void *key_buf, void *value_buf)
{
    btree_result br = _next(key_buf, value_buf, btree->getHeight()-1);
    if (br == BTREE_RESULT_SUCCESS) {
        flagsSetFwd();
    } else {
        flagsSetNone();
    }
    return br;
}

