/* -*- Mode: C++; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * Generic B+Tree
 * (C) 2013  Jung-Sang Ahn <jungsang.ahn@gmail.com>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "btree.h"
#include "common.h"

#include "list.h"

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

INLINE struct bnode *_fetch_bnode(struct btree *btree, void *addr, uint16_t level)
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
    ret[0] = _fetch_bnode(NULL, addr, 0);

    return ret;
}
#else
struct bnode * btree_get_bnode(void *addr)
{
    return _fetch_bnode(NULL, addr, 0);
}
#endif

INLINE int _bnode_size(
    struct btree *btree, struct bnode *node, void *new_minkey, void *key_arr, void *value_arr, size_t len)
{
    int nodesize = 0;

    if (node->flag & BNODE_MASK_METADATA) {
        metasize_t size;
        memcpy(&size, (uint8_t *)node + sizeof(struct bnode), sizeof(metasize_t));
        size = _endian_decode(size);
        nodesize =
            sizeof(struct bnode) +
            btree->kv_ops->get_data_size(node, new_minkey, key_arr, value_arr, len) +
            _metasize_align(size) + sizeof(metasize_t);
    }else{
        nodesize =
            sizeof(struct bnode) +
            btree->kv_ops->get_data_size(node, new_minkey, key_arr, value_arr, len);
    }

    return nodesize;
}

struct kv_ins_item {
    void *key;
    void *value;
    struct list_elem le;
};

INLINE struct kv_ins_item * _kv_ins_item_create(
    struct btree *btree, void *key, void *value)
{
    struct kv_ins_item *item;
    item = (struct kv_ins_item*)malloc(sizeof(struct kv_ins_item));
    item->key = (void *)malloc(btree->ksize);
    item->value = (void *)malloc(btree->vsize);

    if (btree->kv_ops->init_kv_var) {
        btree->kv_ops->init_kv_var(btree, item->key, item->value);
    }
    if (key) {
        btree->kv_ops->set_key(btree, item->key, key);
    }
    if (value) {
        btree->kv_ops->set_value(btree, item->value, value);
    }
    return item;
}

INLINE void _kv_ins_item_free(struct kv_ins_item *item){
    free(item->key);
    free(item->value);
    free(item);
}

INLINE int _bnode_size_check(
    struct btree *btree, bid_t bid, struct bnode *node,
    void *new_minkey, struct list *kv_ins_list, size_t *size_out)
{
    size_t nitem;
    size_t cursize;
    size_t nodesize;
    struct list_elem *e;
    struct kv_ins_item *item;

    nodesize = btree->blk_ops->blk_get_size(btree->blk_handle, bid);
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

        key_arr = (void*)malloc(btree->ksize * nitem);
        value_arr = (void*)malloc(btree->vsize * nitem);

        i = 0;
        e = list_begin(kv_ins_list);
        while(e){
            item = _get_entry(e, struct kv_ins_item, le);
            memcpy((uint8_t *)key_arr + btree->ksize * i, item->key, btree->ksize);
            memcpy((uint8_t *)value_arr + btree->ksize * i, item->value, btree->ksize);
            i++;
            e = list_next(e);
        }
        cursize = _bnode_size(btree, node, new_minkey, key_arr, value_arr, nitem);

        free(key_arr);
        free(value_arr);
    }else if (nitem == 1) {
        e = list_begin(kv_ins_list);
        item = _get_entry(e, struct kv_ins_item, le);
        cursize = _bnode_size(btree, node, new_minkey, item->key, item->value, 1);
    } else {
        /* nitem should never be negative due to size_t */
        fdb_assert(nitem == 0, nitem, btree);
        cursize = _bnode_size(btree, node, new_minkey, NULL, NULL, 0);
    }

    *size_out = cursize;
    return ( cursize <= nodesize );
}

INLINE struct bnode * _btree_init_node(
    struct btree *btree, bid_t bid, void *addr, bnode_flag_t flag, uint16_t level, struct btree_meta *meta)
{
    struct bnode *node;
    void *node_addr;
    metasize_t _size;

    node_addr = addr;

    node = (struct bnode *)node_addr;
    node->kvsize = btree->ksize<<8 | btree->vsize;
    node->nentry = 0;
    node->level = level;
    node->flag = flag;

    if ((flag & BNODE_MASK_METADATA) && meta) {
        _size = _endian_encode(meta->size);
        memcpy((uint8_t *)node_addr + sizeof(struct bnode), &_size, sizeof(metasize_t));
        memcpy((uint8_t *)node_addr + sizeof(struct bnode) + sizeof(metasize_t),
               meta->data, meta->size);
        node->data = (uint8_t *)node_addr + sizeof(struct bnode) + sizeof(metasize_t) +
                     _metasize_align(meta->size);
    }else{
        node->data = (uint8_t *)node_addr + sizeof(struct bnode);
    }

    return node;
}

INLINE size_t _btree_get_nsplitnode(struct btree *btree, bid_t bid, struct bnode *node, size_t size)
{
    size_t headersize, dataspace;
    size_t nodesize;
    size_t nnode = 0;

    nodesize = btree->blk_ops->blk_get_size(btree->blk_handle, bid);
#ifdef __CRC32
    nodesize -= BLK_MARKER_SIZE;
#endif

    if (node->flag & BNODE_MASK_METADATA) {
        metasize_t size;
        memcpy(&size, (uint8_t *)node + sizeof(struct bnode), sizeof(metasize_t));
        size = _endian_decode(size);
        headersize = sizeof(struct bnode) + _metasize_align(size) + sizeof(metasize_t);
    }else{
        headersize = sizeof(struct bnode);
    }

    dataspace = nodesize - headersize;
    // round up
    nnode = ((size - headersize) + (dataspace-1)) / dataspace;

    return nnode;
}

metasize_t btree_read_meta(struct btree *btree, void *buf)
{
    void *addr;
    void *ptr;
    metasize_t size;
    struct bnode *node;

    addr = btree->blk_ops->blk_read(btree->blk_handle, btree->root_bid);
    node = _fetch_bnode(btree, addr, btree->height);
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

void btree_update_meta(struct btree *btree, struct btree_meta *meta)
{
    void *addr;
    void *ptr;
    metasize_t metasize, _metasize;
    metasize_t old_metasize;
    struct bnode *node;

    // read root node
    addr = btree->blk_ops->blk_read(btree->blk_handle, btree->root_bid);
    node = _fetch_bnode(btree, addr, btree->height);

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
        }else{
            // clear the flag
            node->flag &= ~BNODE_MASK_METADATA;
        }
        // move kv-pairs (only if meta size is changed)
        if (_metasize_align(metasize) < _metasize_align(old_metasize)){
            memmove(
                (uint8_t *)ptr + sizeof(metasize_t) + _metasize_align(metasize),
                node->data,
                btree->kv_ops->get_data_size(node, NULL, NULL, NULL, 0));
            node->data = (uint8_t *)node->data - (_metasize_align(old_metasize) -
                         _metasize_align(metasize));
        }

    }else {
        if (node->flag & BNODE_MASK_METADATA) {
            // existing metadata is removed
            memmove(ptr, node->data, btree->kv_ops->get_data_size(node,
                                                    NULL, NULL, NULL, 0));
            node->data = (uint8_t *)node->data - (_metasize_align(old_metasize) +
                         sizeof(metasize_t));
            // clear the flag
            node->flag &= ~BNODE_MASK_METADATA;
        }
    }

    if (!btree->blk_ops->blk_is_writable(btree->blk_handle, btree->root_bid)) {
        // already flushed block -> cannot overwrite, we have to move to new block
        btree->blk_ops->blk_move(btree->blk_handle, btree->root_bid,
                                &btree->root_bid);
    }else{
        btree->blk_ops->blk_set_dirty(btree->blk_handle, btree->root_bid);
    }
}

btree_result btree_init_from_bid(struct btree *btree, void *blk_handle,
                                 struct btree_blk_ops *blk_ops,
                                 struct btree_kv_ops *kv_ops,
                                 uint32_t nodesize, bid_t root_bid)
{
    void *addr;
    struct bnode *root;

    btree->blk_ops = blk_ops;
    btree->blk_handle = blk_handle;
    btree->kv_ops = kv_ops;
    btree->blksize = nodesize;
    btree->root_bid = root_bid;

    addr = btree->blk_ops->blk_read(btree->blk_handle, btree->root_bid);
    root = _fetch_bnode(btree, addr, 0);

    btree->root_flag = root->flag;
    btree->height = root->level;
    _get_kvsize(root->kvsize, btree->ksize, btree->vsize);

    return BTREE_RESULT_SUCCESS;
}

btree_result btree_init(
        struct btree *btree, void *blk_handle,
        struct btree_blk_ops *blk_ops,     struct btree_kv_ops *kv_ops,
        uint32_t nodesize, uint8_t ksize, uint8_t vsize,
        bnode_flag_t flag, struct btree_meta *meta)
{
    void *addr;
    size_t min_nodesize = 0;

    btree->root_flag = BNODE_MASK_ROOT | flag;
    btree->blk_ops = blk_ops;
    btree->blk_handle = blk_handle;
    btree->kv_ops = kv_ops;
    btree->height = 1;
    btree->blksize = nodesize;
    btree->ksize = ksize;
    btree->vsize = vsize;
    if (meta) {
        btree->root_flag |= BNODE_MASK_METADATA;
        min_nodesize = sizeof(struct bnode) + _metasize_align(meta->size) +
                       sizeof(metasize_t) + BLK_MARKER_SIZE;
    } else {
        min_nodesize = sizeof(struct bnode) + BLK_MARKER_SIZE;
    }

    if (min_nodesize > btree->blksize) {
        // too large metadata .. init fail
        return BTREE_RESULT_FAIL;
    }

    // create the first root node
    if (btree->blk_ops->blk_alloc_sub && btree->blk_ops->blk_enlarge_node) {
        addr = btree->blk_ops->blk_alloc_sub(btree->blk_handle, &btree->root_bid);
        if (meta) {
            // check if the initial node size including metadata is
            // larger than the subblock size
            size_t subblock_size;
            subblock_size = btree->blk_ops->blk_get_size(btree->blk_handle,
                                                         btree->root_bid);
            if (subblock_size < min_nodesize) {
                addr = btree->blk_ops->blk_enlarge_node(btree->blk_handle,
                                                        btree->root_bid,
                                                        min_nodesize,
                                                        &btree->root_bid);
            }
        }
    } else {
        addr = btree->blk_ops->blk_alloc (btree->blk_handle, &btree->root_bid);
    }
    _btree_init_node(btree, btree->root_bid, addr,
                     btree->root_flag, BNODE_MASK_ROOT, meta);

    return BTREE_RESULT_SUCCESS;
}

/*
return index# of largest key equal or smaller than KEY
example)
node: [2 4 6 8]
key: 5
largest key equal or smaller than KEY: 4
return: 1 (index# of the key '4')
*/
static idx_t _btree_find_entry(struct btree *btree, struct bnode *node, void *key)
{
    idx_t start, end, middle, temp;
    uint8_t *k = alca(uint8_t, btree->ksize);
    int cmp;
    #ifdef __BIT_CMP
        idx_t *_map1[3] = {&end, &start, &start};
        idx_t *_map2[3] = {&temp, &end, &temp};
    #endif

    if (btree->kv_ops->init_kv_var) btree->kv_ops->init_kv_var(btree, k, NULL);

    start = middle = 0;
    end = node->nentry;

    if (end > 0) {
        // compare with smallest key
        btree->kv_ops->get_kv(node, 0, k, NULL);
        // smaller than smallest key
        if (btree->kv_ops->cmp(key, k, btree->aux) < 0) {
            if (btree->kv_ops->free_kv_var) btree->kv_ops->free_kv_var(btree, k, NULL);
            return BTREE_IDX_NOT_FOUND;
        }

        // compare with largest key
        btree->kv_ops->get_kv(node, end-1, k, NULL);
        // larger than largest key
        if (btree->kv_ops->cmp(key, k, btree->aux) >= 0) {
            if (btree->kv_ops->free_kv_var) btree->kv_ops->free_kv_var(btree, k, NULL);
            return end-1;
        }

        // binary search
        while(start+1 < end) {
            middle = (start + end) >> 1;

            // get key at middle
            btree->kv_ops->get_kv(node, middle, k, NULL);
            cmp = btree->kv_ops->cmp(key, k, btree->aux);

            #ifdef __BIT_CMP
                cmp = _MAP(cmp) + 1;
                *_map1[cmp] = middle;
                *_map2[cmp] = 0;
            #else
                if (cmp < 0) end = middle;
                else if (cmp > 0) start = middle;
                else {
                    if (btree->kv_ops->free_kv_var) btree->kv_ops->free_kv_var(btree, k, NULL);
                    return middle;
                }
            #endif
        }
        if (btree->kv_ops->free_kv_var) btree->kv_ops->free_kv_var(btree, k, NULL);
        return start;
    }

    if (btree->kv_ops->free_kv_var) btree->kv_ops->free_kv_var(btree, k, NULL);
    return BTREE_IDX_NOT_FOUND;
}

static idx_t _btree_add_entry(struct btree *btree, struct bnode *node, void *key, void *value)
{
    idx_t idx, idx_insert;
    uint8_t *k = alca(uint8_t, btree->ksize);

    if (btree->kv_ops->init_kv_var) btree->kv_ops->init_kv_var(btree, k, NULL);

    if (node->nentry > 0) {
        idx = _btree_find_entry(btree, node, key);

        if (idx == BTREE_IDX_NOT_FOUND) idx_insert = 0;
        else {
            btree->kv_ops->get_kv(node, idx, k, NULL);
            if (!btree->kv_ops->cmp(key, k, btree->aux)) {
                // if same key already exists -> update its value
                btree->kv_ops->set_kv(node, idx, key, value);
                if (btree->kv_ops->free_kv_var) btree->kv_ops->free_kv_var(btree, k, NULL);
                return idx;
            }else{
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
            btree->kv_ops->ins_kv(node, idx_insert, key, value);
        }else{
            btree->kv_ops->set_kv(node, idx_insert, key, value);
        }

    }else{
        idx_insert = 0;
        // add at idx_insert
        btree->kv_ops->set_kv(node, idx_insert, key, value);
    }

    // add at idx_insert
    node->nentry++;

    if (btree->kv_ops->free_kv_var) btree->kv_ops->free_kv_var(btree, k, NULL);
    return idx_insert;
}

static idx_t _btree_remove_entry(struct btree *btree, struct bnode *node, void *key)
{
    idx_t idx;

    if (node->nentry > 0) {
        idx = _btree_find_entry(btree, node, key);

        if (idx == BTREE_IDX_NOT_FOUND) return idx;

        /*
        shift [idx+1, nentry) key-value pairs to left
        example)
        idx = 2
        [2 4 6 8 10] -> [2 4 8 10]
        return 2
        */
        btree->kv_ops->ins_kv(node, idx, NULL, NULL);

        node->nentry--;

        return idx;

    }else{
        return BTREE_IDX_NOT_FOUND;
    }
}

static void _btree_print_node(struct btree *btree, int depth,
                              bid_t bid, btree_print_func func)
{
    int i;
    uint8_t *k = alca(uint8_t, btree->ksize);
    uint8_t *v = alca(uint8_t, btree->vsize);
    void *addr;
    bid_t _bid;
    struct bnode *node;

    if (btree->kv_ops->init_kv_var) btree->kv_ops->init_kv_var(btree, k, v);

    addr = btree->blk_ops->blk_read(btree->blk_handle, bid);
    node = _fetch_bnode(btree, addr, depth);

    fprintf(stderr, "[d:%d n:%d f:%x b:%" _F64 " ", node->level, node->nentry, node->flag, bid);

    for (i=0;i<node->nentry;++i){
        btree->kv_ops->get_kv(node, i, k, v);
        _bid = btree->kv_ops->value2bid(v);
        _bid = _endian_decode(_bid);
        func(btree, k, (void*)&_bid);
    }
    fprintf(stderr, "]\n");
    if (depth > 1) {
        for (i=0;i<node->nentry;++i){
            btree->kv_ops->get_kv(node, i, k, v);
            _bid = btree->kv_ops->value2bid(v);
            _bid = _endian_decode(_bid);
            _btree_print_node(btree, depth-1, _bid, func);
        }
    }

    if (btree->kv_ops->free_kv_var) btree->kv_ops->free_kv_var(btree, k, v);
}

void btree_print_node(struct btree *btree, btree_print_func func)
{
    fprintf(stderr, "tree height: %d\n", btree->height);
    _btree_print_node(btree, btree->height, btree->root_bid, func);
}

btree_result btree_get_key_range(
    struct btree *btree, idx_t num, idx_t den, void *key_begin, void *key_end)
{
    void *addr;
    uint8_t *k = alca(uint8_t, btree->ksize);
    uint8_t *v = alca(uint8_t, btree->vsize);
    idx_t idx_begin, idx_end, idx;
    bid_t bid;
    struct bnode *root, *node;
    uint64_t _num, _den, _nentry, resolution, mask, _idx_begin, _idx_end;

    fdb_assert(num < den, num, den);
    resolution = 1<<4; mask = resolution-1;

    if (btree->kv_ops->init_kv_var) btree->kv_ops->init_kv_var(btree, k, v);
    _num = (uint64_t)num * resolution;
    _den = (uint64_t)den * resolution;

    // get root node
    addr = btree->blk_ops->blk_read(btree->blk_handle, btree->root_bid);
    root = _fetch_bnode(btree, addr, btree->height);
    _nentry = (uint64_t)root->nentry * resolution;

    if (btree->height == 1) {
        btree->kv_ops->get_kv(root, ((num+0) * root->nentry / den)-0, key_begin, NULL);
        btree->kv_ops->get_kv(root, ((num+1) * root->nentry / den)-1, key_end, NULL);
    }else{
        _idx_begin = (_num * _nentry / _den);
        _idx_end = ((_num+resolution) * _nentry / _den)-1;

        idx_begin = _idx_begin / resolution;
        idx_end = (_idx_end / resolution);
        if (idx_end >= root->nentry) idx_end = root->nentry-1;

        // get first child node (for KEY_BEGIN)
        btree->kv_ops->get_kv(root, idx_begin, k, v);
        bid = btree->kv_ops->value2bid(v);
        bid = _endian_decode(bid);
        addr = btree->blk_ops->blk_read(btree->blk_handle, bid);
        node = _fetch_bnode(btree, addr, btree->height-1);

        idx = ((_idx_begin & mask) * (node->nentry-1) / (resolution-1));
        btree->kv_ops->get_kv(node, idx, key_begin, NULL);

        // get second child node (for KEY_END)
        if (idx_end != idx_begin) {
            btree->kv_ops->get_kv(root, idx_end, k, v);
            bid = btree->kv_ops->value2bid(v);
            bid = _endian_decode(bid);
            addr = btree->blk_ops->blk_read(btree->blk_handle, bid);
            node = _fetch_bnode(btree, addr, btree->height-1);
        }

        idx = ((_idx_end & mask) * (node->nentry-1) / (resolution-1));
        btree->kv_ops->get_kv(node, idx, key_end, NULL);
    }

    if (btree->kv_ops->free_kv_var) btree->kv_ops->free_kv_var(btree, k, v);
    return BTREE_RESULT_SUCCESS;
}

btree_result btree_find(struct btree *btree, void *key, void *value_buf)
{
    void *addr;
    uint8_t *k = alca(uint8_t, btree->ksize);
    uint8_t *v = alca(uint8_t, btree->vsize);
    idx_t *idx = alca(idx_t, btree->height);
    bid_t *bid = alca(bid_t, btree->height);
    struct bnode **node = alca(struct bnode *, btree->height);
    int i;

    if (btree->kv_ops->init_kv_var) btree->kv_ops->init_kv_var(btree, k, v);

    // set root
    bid[btree->height-1] = btree->root_bid;

    for (i=btree->height-1; i>=0; --i) {
        // read block using bid
        addr = btree->blk_ops->blk_read(btree->blk_handle, bid[i]);
        // fetch node structure from block
        node[i] = _fetch_bnode(btree, addr, i+1);

        // lookup key in current node
        idx[i] = _btree_find_entry(btree, node[i], key);

        if (idx[i] == BTREE_IDX_NOT_FOUND) {
            // not found .. return NULL
            if (btree->blk_ops->blk_operation_end)
                btree->blk_ops->blk_operation_end(btree->blk_handle);
            if (btree->kv_ops->free_kv_var) btree->kv_ops->free_kv_var(btree, k, v);
            return BTREE_RESULT_FAIL;
        }

        btree->kv_ops->get_kv(node[i], idx[i], k, v);

        if (i>0) {
            // index (non-leaf) node
            // get bid of child node from value
            bid[i-1] = btree->kv_ops->value2bid(v);
            bid[i-1] = _endian_decode(bid[i-1]);
        }else{
            // leaf node
            // return (address of) value if KEY == k
            if (!btree->kv_ops->cmp(key, k, btree->aux)) {
                btree->kv_ops->set_value(btree, value_buf, v);
            }else{
                if (btree->blk_ops->blk_operation_end)
                    btree->blk_ops->blk_operation_end(btree->blk_handle);
                if (btree->kv_ops->free_kv_var) {
                    btree->kv_ops->free_kv_var(btree, k, v);
                }
                return BTREE_RESULT_FAIL;
            }
        }
    }
    if (btree->blk_ops->blk_operation_end) {
        btree->blk_ops->blk_operation_end(btree->blk_handle);
    }
    if (btree->kv_ops->free_kv_var) btree->kv_ops->free_kv_var(btree, k, v);
    return BTREE_RESULT_SUCCESS;
}

static int _btree_split_node(
    struct btree *btree, void *key, struct bnode **node, bid_t *bid, idx_t *idx, int i,
    struct list *kv_ins_list, size_t nsplitnode, void *k, void *v,
    int8_t *modified, int8_t *minkey_replace, int8_t *ins)
{
    void *addr;
    size_t nnode = nsplitnode;
    int j, *nentry = alca(int, nnode);
    bid_t _bid;
    bid_t *new_bid = alca(bid_t, nnode);
    idx_t *split_idx = alca(idx_t, nnode+1);
    idx_t *idx_ins = alca(idx_t, btree->height);
    struct list_elem *e;
    struct bnode **new_node = alca(struct bnode *, nnode);
    struct kv_ins_item *kv_item;

    // allocate new block(s)
    new_node[0] = node[i];
    for (j=1;j<nnode;++j){
        addr = btree->blk_ops->blk_alloc(btree->blk_handle, &new_bid[j]);
        new_node[j] = _btree_init_node(btree, new_bid[j], addr, 0x0,
                                       node[i]->level, NULL);
    }

    // calculate # entry
    for (j=0;j<nnode+1;++j){
        btree->kv_ops->get_nth_idx(node[i], j, nnode, &split_idx[j]);
        if (j>0) {
            nentry[j-1] = split_idx[j] - split_idx[j-1];
        }
    }

    // copy kv-pairs to new node(s)
    for (j=1;j<nnode;++j){
        btree->kv_ops->copy_kv(new_node[j], node[i], 0, split_idx[j],
                               nentry[j]);
    }
    j = 0;
    btree->kv_ops->copy_kv(new_node[j], node[i], 0, split_idx[j], nentry[j]);

    // header
    for (j=0;j<nnode;++j){
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
                btree->kv_ops->get_kv(new_node[j], 0, k, v);
                if (btree->kv_ops->cmp(kv_item->key, k, btree->aux) < 0) {
                    idx_ins[i] =
                        _btree_add_entry(btree, new_node[j-1], kv_item->key,
                                         kv_item->value);
                    break;
                }
            }
            if (idx_ins[i] == BTREE_IDX_NOT_FOUND) {
                // insert into the last split node
                idx_ins[i] =
                    _btree_add_entry(btree, new_node[nnode-1], kv_item->key,
                                     kv_item->value);
            }
            e = list_next(e);
        }
    }
    if (minkey_replace[i]){
        // replace the minimum key in the (first split) node to KEY
        btree->kv_ops->get_kv(new_node[0], idx[i], k, v);
        btree->kv_ops->set_kv(new_node[0], idx[i], key, v);
    }

    if (i+1 < btree->height) {
        // non-root node
        // reserve kv-pair (i.e. splitters) to be inserted into parent node
        for (j=1; j<nnode; ++j){
            _bid = _endian_encode(new_bid[j]);
            kv_item = _kv_ins_item_create(btree, NULL, (void *)&_bid);
            btree->kv_ops->get_nth_splitter(new_node[j-1], new_node[j],
                                            kv_item->key);
            list_push_back(&kv_ins_list[i+1], &kv_item->le);
        }
        ins[i+1] = 1;

    }else{
        //2 root node -> height grow up
        // allocate new block for new root node
        bid_t new_root_bid;
        struct bnode *new_root;
        uint8_t *buf = alca(uint8_t, btree->blksize);
        struct btree_meta meta;

        meta.size = btree_read_meta(btree, buf);
        meta.data = buf;
        // remove metadata section of existing node
        // (this node is not root anymore)
        btree_update_meta(btree, NULL);

        btree->height++;

        addr = btree->blk_ops->blk_alloc(btree->blk_handle, &new_root_bid);
        if (meta.size > 0)
            new_root =
                _btree_init_node(
                    btree, new_root_bid, addr, btree->root_flag,
                    node[i]->level + 1, &meta);
        else
            new_root =
                _btree_init_node(
                    btree, new_root_bid, addr, btree->root_flag,
                    node[i]->level + 1, NULL);

        // clear old root node flag
        node[i]->flag &= ~BNODE_MASK_ROOT;
        node[i]->flag &= ~BNODE_MASK_SEQTREE;
        // change root bid
        btree->root_bid = new_root_bid;

        // move the former node if not dirty
        if (!btree->blk_ops->blk_is_writable(btree->blk_handle, bid[i])) {
            addr = btree->blk_ops->blk_move(btree->blk_handle, bid[i], &bid[i]);
            node[i] = _fetch_bnode(btree, addr, i+1);
        }else{
            btree->blk_ops->blk_set_dirty(btree->blk_handle, bid[i]);
        }

        // insert kv-pairs pointing to their child nodes
        // original (i.e. the first node)
        btree->kv_ops->get_kv(node[i], 0, k, v);
        _bid = _endian_encode(bid[i]);
        _btree_add_entry(btree, new_root, k, btree->kv_ops->bid2value(&_bid));

        // the others
        for (j=1;j<nnode;++j){
            //btree->kv_ops->get_kv(new_node[j], 0, k, v);
            btree->kv_ops->get_nth_splitter(new_node[j-1], new_node[j], k);
            _bid = _endian_encode(new_bid[j]);
            _btree_add_entry(btree, new_root, k,
                             btree->kv_ops->bid2value(&_bid));
        }

        return 1;
    } // height growup

    return 0;
}

static int _btree_move_modified_node(
    struct btree *btree, void *key, struct bnode **node, bid_t *bid,
    idx_t *idx, int i,
    struct list *kv_ins_list, void *k, void *v,
    int8_t *modified, int8_t *minkey_replace, int8_t *ins, int8_t *moved)
{
    void *addr;

    // get new bid[i]
    addr = btree->blk_ops->blk_move(btree->blk_handle, bid[i], &bid[i]);
    (void)addr;
    //node[i] = _fetch_bnode(btree, addr, i+1);
    moved[i] = 1;

    if (i+1 == btree->height)
        // if moved node is root node
        btree->root_bid = bid[i];

    return 0;
}

btree_result btree_insert(struct btree *btree, void *key, void *value)
{
    void *addr;
    size_t nsplitnode = 1;
    uint8_t *k = alca(uint8_t, btree->ksize);
    uint8_t *v = alca(uint8_t, btree->vsize);
    // index# and block ID for each level
    idx_t *idx = alca(idx_t, btree->height);
    bid_t *bid = alca(bid_t, btree->height);
    bid_t _bid;
    // flags
    int8_t *modified = alca(int8_t, btree->height);
    int8_t *moved = alca(int8_t, btree->height);
    int8_t *ins = alca(int8_t, btree->height);
    int8_t *minkey_replace = alca(int8_t, btree->height);
    int8_t height_growup;

    // key, value to be inserted
    struct list *kv_ins_list = alca(struct list, btree->height);
    struct kv_ins_item *kv_item;
    struct list_elem *e;

    // index# where kv is inserted
    idx_t *idx_ins = alca(idx_t, btree->height);
    struct bnode **node = alca(struct bnode *, btree->height);
    int i, j, _is_update = 0;

    // initialize flags
    for (i=0;i<btree->height;++i) {
        moved[i] = modified[i] = ins[i] = minkey_replace[i] = 0;
    }
    height_growup = 0;

    // initialize temporary variables
    if (btree->kv_ops->init_kv_var) {
        btree->kv_ops->init_kv_var(btree, k, v);
        for (i=0;i<btree->height;++i){
            list_init(&kv_ins_list[i]);
        }
    }

    // copy key-value pair to be inserted into leaf node
    kv_item = _kv_ins_item_create(btree, key, value);
    list_push_back(&kv_ins_list[0], &kv_item->le);

    ins[0] = 1;

    // set root node
    bid[btree->height-1] = btree->root_bid;

    // find path from root to leaf
    for (i=btree->height-1; i>=0; --i){
        // read block using bid
        addr = btree->blk_ops->blk_read(btree->blk_handle, bid[i]);
        // fetch node structure from block
        node[i] = _fetch_bnode(btree, addr, i+1);

        // lookup key in current node
        idx[i] = _btree_find_entry(btree, node[i], key);

        if (i > 0) {
            // index (non-leaf) node
            if (idx[i] == BTREE_IDX_NOT_FOUND)
                // KEY is smaller than the smallest key in this node ..
                // just follow the smallest key
                idx[i] = 0;

            // get bid of child node from value
            btree->kv_ops->get_kv(node[i], idx[i], k, v);
            bid[i-1] = btree->kv_ops->value2bid(v);
            bid[i-1] = _endian_decode(bid[i-1]);
        }else{
            // leaf node .. do nothing
        }
    }

    // cascaded insert from leaf to root
    for (i=0;i<btree->height;++i){

        if (idx[i] != BTREE_IDX_NOT_FOUND)
            btree->kv_ops->get_kv(node[i], idx[i], k, NULL);

        if (i > 0) {
            // in case of index node
            // when KEY is smaller than smallest key in index node
            if (idx[i] == 0 && btree->kv_ops->cmp(key, k, btree->aux) < 0) {
                // change node's smallest key
                minkey_replace[i] = 1;
            }

            // when child node is moved to new block
            if (moved[i-1]) {
                // replace the bid (value)
                _bid = _endian_encode(bid[i-1]);
                btree->kv_ops->set_kv(node[i], idx[i], k,
                                      btree->kv_ops->bid2value(&_bid));
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
                _is_update =
                    (idx[i] != BTREE_IDX_NOT_FOUND &&
                     !btree->kv_ops->cmp(kv_item->key, k, btree->aux));
            }

        check_node:;
            int _size_check =
                _bnode_size_check(btree, bid[i], node[i], new_minkey,
                                  &kv_ins_list[i], &nodesize);

            if (_size_check || _is_update ) {
                //2 enough space
                if (ins[i]) {
                    // insert key/value pair(s)
                    // insert all kv pairs on list
                    e = list_begin(&kv_ins_list[i]);
                    while(e) {
                        kv_item = _get_entry(e, struct kv_ins_item, le);
                        idx_ins[i] = _btree_add_entry(btree, node[i],
                                                 kv_item->key, kv_item->value);
                        e = list_next(e);
                    }
                }
                if (minkey_replace[i]) {
                    // replace the minimum key in the node to KEY
                    btree->kv_ops->get_kv(node[i], idx[i], k, v);
                    btree->kv_ops->set_kv(node[i], idx[i], key, v);
                }
                modified[i] = 1;

            }else{
                //2 not enough
                // first check if the node can be enlarged
                if (btree->blk_ops->blk_enlarge_node &&
                    is_subblock(bid[i])) {
                    bid_t new_bid;
                    addr = btree->blk_ops->blk_enlarge_node(btree->blk_handle,
                        bid[i], nodesize, &new_bid);
                    if (addr) {
                        // the node can be enlarged .. fetch the enlarged node
                        moved[i] = 1;
                        bid[i] = new_bid;
                        node[i] = _fetch_bnode(btree, addr, i+1);
                        if (i+1 == btree->height) {
                            // if moved node is root node
                            btree->root_bid = bid[i];
                        }
                        // start over
                        goto check_node;
                    }
                }

                //otherwise, split the node
                nsplitnode = _btree_get_nsplitnode(btree, BLK_NOT_FOUND,
                                                   node[i], nodesize);
                // force the node split when the node size of new layout is
                // larger than the current node size
                if (nsplitnode == 1) nsplitnode = 2;

                height_growup = _btree_split_node(
                    btree, key, node, bid, idx, i,
                    kv_ins_list, nsplitnode, k, v,
                    modified, minkey_replace, ins);
            } // split
        } // insert

        if (height_growup) break;

        if (modified[i]) {
            //2 when the node is modified
            if (!btree->blk_ops->blk_is_writable(btree->blk_handle, bid[i])) {
                // not writable .. already flushed block -> cannot overwrite,
                // we have to move to new block
                height_growup = _btree_move_modified_node(
                    btree, key, node, bid, idx, i,
                    kv_ins_list, k, v,
                    modified, minkey_replace, ins, moved);

                if (height_growup) break;
            }else{
                // writable .. just set dirty to write back into storage
                btree->blk_ops->blk_set_dirty(btree->blk_handle, bid[i]);
            } // is writable
        } // is modified
    } // for loop

    // release temporary resources
    if (btree->blk_ops->blk_operation_end) {
        btree->blk_ops->blk_operation_end(btree->blk_handle);
    }
    if (btree->kv_ops->free_kv_var) btree->kv_ops->free_kv_var(btree, k, v);

    for (j=0; j < ((height_growup)?(btree->height-1):(btree->height)); ++j){
        e = list_begin(&kv_ins_list[j]);
        while(e) {
            kv_item = _get_entry(e, struct kv_ins_item, le);
            e = list_remove(&kv_ins_list[j], e);

            if (btree->kv_ops->free_kv_var) {
                btree->kv_ops->free_kv_var(btree, kv_item->key, kv_item->value);
            }
            _kv_ins_item_free(kv_item);
        }
    }

    if (_is_update) {
        return BTREE_RESULT_UPDATE;
    }else{
        return BTREE_RESULT_SUCCESS;
    }
}

btree_result btree_remove(struct btree *btree, void *key)
{
    void *addr;
    uint8_t *k = alca(uint8_t, btree->ksize);
    uint8_t *v= alca(uint8_t, btree->vsize);
    uint8_t *kk = alca(uint8_t, btree->ksize);
    uint8_t *vv = alca(uint8_t, btree->vsize);
    // index# and block ID for each level
    idx_t *idx = alca(idx_t, btree->height);
    bid_t *bid= alca(bid_t, btree->height);
    bid_t _bid;
    // flags
    int8_t *modified = alca(int8_t, btree->height);
    int8_t *moved = alca(int8_t, btree->height);
    int8_t *rmv = alca(int8_t, btree->height);
    // index# of removed key
    idx_t *idx_rmv = alca(idx_t, btree->height);
    struct bnode **node = alca(struct bnode *, btree->height);
    int i;

    // initialize flags
    for (i=0;i<btree->height;++i) {
        moved[i] = modified[i] = rmv[i] = 0;
    }
    if (btree->kv_ops->init_kv_var) {
        btree->kv_ops->init_kv_var(btree, k, v);
        btree->kv_ops->init_kv_var(btree, kk, vv);
    }

    rmv[0] = 1;

    // set root
    bid[btree->height-1] = btree->root_bid;

    // find path from root to leaf
    for (i=btree->height-1; i>=0; --i) {
        // read block using bid
        addr = btree->blk_ops->blk_read(btree->blk_handle, bid[i]);
        // fetch node structure from block
        node[i] = _fetch_bnode(btree, addr, i+1);

        // lookup key in current node
        idx[i] = _btree_find_entry(btree, node[i], key);

        if (idx[i] == BTREE_IDX_NOT_FOUND) {
            // not found
            if (btree->blk_ops->blk_operation_end)
                btree->blk_ops->blk_operation_end(btree->blk_handle);
            if (btree->kv_ops->free_kv_var) {
                btree->kv_ops->free_kv_var(btree, k, v);
                btree->kv_ops->free_kv_var(btree, kk, vv);
            }
            return BTREE_RESULT_FAIL;
        }

        btree->kv_ops->get_kv(node[i], idx[i], k, v);

        if (i>0) {
            // index (non-leaf) node
            // get bid of child node from value
            bid[i-1] = btree->kv_ops->value2bid(v);
            bid[i-1] = _endian_decode(bid[i-1]);
        }else{
            // leaf node
        }
    }

    // cascaded remove from leaf to root
    for (i=0;i<btree->height;++i){
        // in case of index node
        if (i > 0) {
            btree->kv_ops->get_kv(node[i], idx[i], k, v);

            // when child node's smallest key is changed due to remove
              if (node[i-1]->nentry > 0) {
                btree->kv_ops->get_kv(node[i-1], 0, kk, vv);
                if (btree->kv_ops->cmp(kk, k, btree->aux)) {
                    // change current node's corresponding key
                    btree->kv_ops->set_kv(node[i], idx[i], kk, v);
                    //memcpy(k, kk, btree->ksize);
                    btree->kv_ops->set_key(btree, k, kk);
                    modified[i] = 1;
                }
            }

            // when child node is moved to new block
            if (moved[i-1]) {
                // replace the bid (value)
                _bid = _endian_encode(bid[i-1]);
                btree->kv_ops->set_kv(node[i], idx[i], k,
                                      btree->kv_ops->bid2value(&_bid));
                modified[i] = 1;
            }
        }

        if (rmv[i]) {
            // there is a key-value pair to be removed
            btree->kv_ops->get_kv(node[i], idx[i], k, v);
            idx_rmv[i] = _btree_remove_entry(btree, node[i], k);
            modified[i] = 1;

            /*
            remove the node when
            1. non-root node has no kv-pair or
            2. root node has less or equal than one kv-pair
            */
            if (((node[i]->nentry < 1 && i+1 < btree->height) ||
                (node[i]->nentry <= 1 && i+1 == btree->height)) &&
                btree->height > 1) {
                // remove the node
                btree->blk_ops->blk_remove(btree->blk_handle, bid[i]);
                if (i+1 < btree->height) {
                    // if non-root node
                    rmv[i+1] = 1;
                }else{
                    // if root node
                    btree->height--;
                    btree->kv_ops->get_kv(node[i], 0, k, v);
                    btree->root_bid = btree->kv_ops->value2bid(v);
                    btree->root_bid = _endian_decode(btree->root_bid);
                }
            }
        }

        if (modified[i]) {
            // when node is modified
            if (!btree->blk_ops->blk_is_writable(btree->blk_handle, bid[i])) {
                // already flushed block -> cannot overwrite, so
                // we have to move to new block
                // get new bid[i]
                addr = btree->blk_ops->blk_move(btree->blk_handle, bid[i],
                                                &bid[i]);
                node[i] = _fetch_bnode(btree, addr, i+1);
                moved[i] = 1;

                if (i+1 == btree->height)
                    // if moved node is root node
                    btree->root_bid = bid[i];

            }else{
                btree->blk_ops->blk_set_dirty(btree->blk_handle, bid[i]);
            }

        }
    }

    if (btree->blk_ops->blk_operation_end) {
        btree->blk_ops->blk_operation_end(btree->blk_handle);
    }
    if (btree->kv_ops->free_kv_var) {
        btree->kv_ops->free_kv_var(btree, k, v);
        btree->kv_ops->free_kv_var(btree, kk, vv);
    }
    return BTREE_RESULT_SUCCESS;
}

// LCOV_EXCL_START
btree_result btree_operation_end(struct btree *btree)
{
    if (btree->blk_ops->blk_operation_end) {
        btree->blk_ops->blk_operation_end(btree->blk_handle);
    }
    return BTREE_RESULT_SUCCESS;
}
// LCOV_EXCL_STOP

btree_result btree_iterator_init(struct btree *btree,
                                 struct btree_iterator *it, void *initial_key)
{
    int i;

    it->btree = *btree;
    it->curkey = (void *)mempool_alloc(btree->ksize);
    if (btree->kv_ops->init_kv_var) {
        btree->kv_ops->init_kv_var(btree, it->curkey, NULL);
    }
    if (initial_key) {
        // set initial key if exists
        //memcpy(it->curkey, initial_key, btree->ksize);
        btree->kv_ops->set_key(btree, it->curkey, initial_key);
    }else{
        // NULL initial key .. set minimum key (start from leftmost key)
        // replaced by kv_ops->init_kv_var
        //memset(it->curkey, 0, btree->ksize);
    }
    it->bid = (bid_t*)mempool_alloc(sizeof(bid_t) * btree->height);
    it->idx = (idx_t*)mempool_alloc(sizeof(idx_t) * btree->height);
    it->node = (struct bnode **)mempool_alloc(sizeof(struct bnode *)
                                                              * btree->height);
    it->addr = (void**)mempool_alloc(sizeof(void*) * btree->height);

    for (i=0;i<btree->height;++i){
        it->bid[i] = BTREE_BLK_NOT_FOUND;
        it->idx[i] = BTREE_IDX_NOT_FOUND;
        it->node[i] = NULL;
        it->addr[i] = NULL;
    }
    it->bid[btree->height-1] = btree->root_bid;
    it->flags = 0;

    return BTREE_RESULT_SUCCESS;
}

btree_result btree_iterator_free(struct btree_iterator *it)
{
    int i;
    if (it->btree.kv_ops->free_kv_var) {
        it->btree.kv_ops->free_kv_var(&it->btree, it->curkey, NULL);
    }
    mempool_free(it->curkey);
    mempool_free(it->bid);
    mempool_free(it->idx);
    for (i=0;i<it->btree.height;++i){
        if (it->node[i]) mempool_free(it->addr[i]);
    }
    mempool_free(it->node);
    mempool_free(it->addr);
    return BTREE_RESULT_SUCCESS;
}

static btree_result _btree_prev(struct btree_iterator *it, void *key_buf,
                                void *value_buf, int depth)
{
    struct btree *btree;
    btree = &it->btree;
    int i;
    uint8_t *k = alca(uint8_t, btree->ksize);
    uint8_t *v = alca(uint8_t, btree->vsize);
    void *addr;
    struct bnode *node;
    btree_result r;

    if (it->btree.kv_ops->init_kv_var) {
        it->btree.kv_ops->init_kv_var(&it->btree, k, v);
    }

    if (it->node[depth] == NULL){
        size_t blksize;
        addr = btree->blk_ops->blk_read(btree->blk_handle, it->bid[depth]);
        it->addr[depth] = (void *)mempool_alloc(btree->blksize);
        blksize = btree->blk_ops->blk_get_size(btree->blk_handle,
                                               it->bid[depth]);
        memcpy(it->addr[depth], addr, blksize);
        it->node[depth] = _fetch_bnode(&it->btree, it->addr[depth], depth+1);
    }
    node = _fetch_bnode(&it->btree, it->addr[depth], depth+1);
    //assert(node->level == depth+1);

    if (node->nentry <= 0) {
        if (it->btree.kv_ops->free_kv_var) {
            it->btree.kv_ops->free_kv_var(&it->btree, k, v);
        }
        if (it->node[depth] != NULL) mempool_free(it->addr[depth]);
        it->node[depth] = NULL;
        it->addr[depth] = NULL;
        return BTREE_RESULT_FAIL;
    }

    if (it->idx[depth] == BTREE_IDX_NOT_FOUND) {
        // curkey: lastly returned key
        it->idx[depth] = _btree_find_entry(btree, node, it->curkey);
        if (it->idx[depth] == BTREE_IDX_NOT_FOUND) {
            it->idx[depth] = 0;
           // it->idx[depth] = node->nentry - 1;
        }
        btree->kv_ops->get_kv(node, it->idx[depth], key_buf, value_buf);
        if (btree->kv_ops->cmp(it->curkey, key_buf, btree->aux) < 0 &&
            depth == 0) {
            // in leaf node, prev key must be smaller than current key
            it->idx[depth] = it->idx[depth] ? it->idx[depth] - 1
                                            : BTREE_IDX_NOT_FOUND;
        } // else return the value at idx[depth] at this turn
    }

    if (BTREE_ITR_IS_FWD(it) && depth ==0) {
        if (it->idx[depth] >= 2) {
            it->idx[depth] -= 2;
        } else {
            // out-of-bounds
            it->idx[depth] = node->nentry; // ending condition
            // we have to reset flag because _btree_prev will recursively
            // visit the left leaf node.
            BTREE_ITR_SET_NONE(it);
        }
    }

    if (it->idx[depth] >= node->nentry) { // reused nentry for ending iteration
        // out of bound .. go up to parent node
        it->idx[depth] = BTREE_IDX_NOT_FOUND; // reset for btree_next
        if (it->node[depth] != NULL) mempool_free(it->addr[depth]);
        it->node[depth] = NULL;
        it->addr[depth] = NULL;

        if (it->btree.kv_ops->free_kv_var) {
            it->btree.kv_ops->free_kv_var(&it->btree, k, v);
        }
        return BTREE_RESULT_FAIL;
    }

    if (depth > 0) {
        // index node
        if (it->node[depth-1] == NULL) {
            btree->kv_ops->get_kv(node, it->idx[depth], k, v);
            it->bid[depth-1] = btree->kv_ops->value2bid(v);
            it->bid[depth-1] = _endian_decode(it->bid[depth-1]);
        }
        r = _btree_prev(it, key_buf, value_buf, depth-1);

        if (r == BTREE_RESULT_FAIL) {
            // move index to left
            it->idx[depth] = it->idx[depth] ? it->idx[depth] - 1
                                            : node->nentry; // ending condition

            if (it->idx[depth] >= node->nentry){
                // out of bound .. go up to parent node
                it->idx[depth] = BTREE_IDX_NOT_FOUND;
                if (it->node[depth] != NULL) mempool_free(it->addr[depth]);
                it->node[depth] = NULL;
                it->addr[depth] = NULL;

                if (it->btree.kv_ops->free_kv_var) {
                    it->btree.kv_ops->free_kv_var(&it->btree, k, v);
                }
                return BTREE_RESULT_FAIL;
            }else{
                btree->kv_ops->get_kv(node, it->idx[depth], k, v);
                it->bid[depth-1] = btree->kv_ops->value2bid(v);
                it->bid[depth-1] = _endian_decode(it->bid[depth-1]);
                // reset child index
                for (i=depth-1; i>=0; --i) {
                    it->idx[i] = BTREE_IDX_NOT_FOUND;
                    if (it->node[i] != NULL) mempool_free(it->addr[i]);
                    it->node[i] = NULL;
                    it->addr[i] = NULL;
                }
                // retry
                r = _btree_prev(it, key_buf, value_buf, depth-1);
            }
        }
        if (it->btree.kv_ops->free_kv_var) {
            it->btree.kv_ops->free_kv_var(&it->btree, k, v);
        }
        return r;
    }else{
        // leaf node
        btree->kv_ops->get_kv(node, it->idx[depth], key_buf, value_buf);
        //memcpy(it->curkey, key_buf, btree->ksize);
        btree->kv_ops->set_key(btree, it->curkey, key_buf);
        it->idx[depth] = it->idx[depth] ? it->idx[depth] - 1
                                        : node->nentry; // condition for ending
        if (it->btree.kv_ops->free_kv_var) {
            it->btree.kv_ops->free_kv_var(&it->btree, k, v);
        }
        return BTREE_RESULT_SUCCESS;
    }
}

btree_result btree_prev(struct btree_iterator *it, void *key_buf,
                        void *value_buf)
{
    btree_result br = _btree_prev(it, key_buf, value_buf, it->btree.height-1);
    if (br == BTREE_RESULT_SUCCESS) {
        BTREE_ITR_SET_REV(it);
    } else {
        BTREE_ITR_SET_NONE(it);
    }
    return br;
}

static btree_result _btree_next(struct btree_iterator *it, void *key_buf,
                                void *value_buf, int depth)
{
    struct btree *btree;
    btree = &it->btree;
    int i;
    uint8_t *k = alca(uint8_t, btree->ksize);
    uint8_t *v = alca(uint8_t, btree->vsize);
    void *addr;
    struct bnode *node;
    btree_result r;

    if (it->btree.kv_ops->init_kv_var) {
        it->btree.kv_ops->init_kv_var(&it->btree, k, v);
    }

    if (it->node[depth] == NULL){
        size_t blksize;
        addr = btree->blk_ops->blk_read(btree->blk_handle, it->bid[depth]);
        it->addr[depth] = (void *)mempool_alloc(btree->blksize);
        blksize = btree->blk_ops->blk_get_size(btree->blk_handle,
                                               it->bid[depth]);
        memcpy(it->addr[depth], addr, blksize);
        it->node[depth] = _fetch_bnode(&it->btree, it->addr[depth], depth+1);
    }
    node = _fetch_bnode(&it->btree, it->addr[depth], depth+1);
    //assert(node->level == depth+1);

    if (node->nentry <= 0) {
        if (it->btree.kv_ops->free_kv_var) it->btree.kv_ops->free_kv_var(
                                                             &it->btree, k, v);
        if (it->node[depth] != NULL) mempool_free(it->addr[depth]);
        it->node[depth] = NULL;
        it->addr[depth] = NULL;
        return BTREE_RESULT_FAIL;
    }

    if (it->idx[depth] == BTREE_IDX_NOT_FOUND) {
        // curkey: lastly returned key
        it->idx[depth] = _btree_find_entry(btree, node, it->curkey);
        if (it->idx[depth] == BTREE_IDX_NOT_FOUND) {
            it->idx[depth] = 0;
        }
        btree->kv_ops->get_kv(node, it->idx[depth], key_buf, value_buf);
        if (btree->kv_ops->cmp(it->curkey, key_buf, btree->aux) > 0 &&
            depth == 0) {
            // in leaf node, next key must be larger than previous key
            // (i.e. it->curkey)
            it->idx[depth]++;
        }
    }

    if (BTREE_ITR_IS_REV(it) && depth == 0) {
        if (it->idx[depth] >= node->nentry) {
            // 'idx' becomes out-of-bounds by previous btree_prev() call.
            // this means that the last returned entry was the smallest entry.
            // set idx to the second smallest entry.
            it->idx[depth] = 1;
        } else {
            it->idx[depth] += 2;
        }
    }

    if (it->idx[depth] >= node->nentry) {
        // out of bound .. go up to parent node
        it->idx[depth] = BTREE_IDX_NOT_FOUND; // reset for btree_prev
        if (it->node[depth] != NULL) mempool_free(it->addr[depth]);
        it->node[depth] = NULL;
        it->addr[depth] = NULL;

        if (it->btree.kv_ops->free_kv_var) {
            it->btree.kv_ops->free_kv_var(&it->btree, k, v);
        }
        return BTREE_RESULT_FAIL;
    }

    if (depth > 0) {
        // index node
        if (it->node[depth-1] == NULL) {
            btree->kv_ops->get_kv(node, it->idx[depth], k, v);
            it->bid[depth-1] = btree->kv_ops->value2bid(v);
            it->bid[depth-1] = _endian_decode(it->bid[depth-1]);
        }
        r = _btree_next(it, key_buf, value_buf, depth-1);

        if (r == BTREE_RESULT_FAIL) {
            // move index to right
            it->idx[depth]++;

            if (it->idx[depth] >= node->nentry){
                // out of bound .. go up to parent node
                it->idx[depth] = BTREE_IDX_NOT_FOUND;
                if (it->node[depth] != NULL) mempool_free(it->addr[depth]);
                it->node[depth] = NULL;
                it->addr[depth] = NULL;

                if (it->btree.kv_ops->free_kv_var) {
                    it->btree.kv_ops->free_kv_var(&it->btree, k, v);
                }
                return BTREE_RESULT_FAIL;
            }else{
                btree->kv_ops->get_kv(node, it->idx[depth], k, v);
                it->bid[depth-1] = btree->kv_ops->value2bid(v);
                it->bid[depth-1] = _endian_decode(it->bid[depth-1]);
                // reset child index
                for (i=depth-1; i>=0; --i) {
                    it->idx[i] = 0;
                    if (it->node[i] != NULL) mempool_free(it->addr[i]);
                    it->node[i] = NULL;
                    it->addr[i] = NULL;
                }
                // retry
                r = _btree_next(it, key_buf, value_buf, depth-1);
            }
        }
        if (it->btree.kv_ops->free_kv_var) {
            it->btree.kv_ops->free_kv_var(&it->btree, k, v);
        }
        return r;
    }else{
        // leaf node
        btree->kv_ops->get_kv(node, it->idx[depth], key_buf, value_buf);
        //memcpy(it->curkey, key_buf, btree->ksize);
        btree->kv_ops->set_key(btree, it->curkey, key_buf);
        it->idx[depth]++;
        if (it->btree.kv_ops->free_kv_var) {
            it->btree.kv_ops->free_kv_var(&it->btree, k, v);
        }
        return BTREE_RESULT_SUCCESS;
    }
}

btree_result btree_next(struct btree_iterator *it, void *key_buf,
                        void *value_buf)
{
    btree_result br = _btree_next(it, key_buf, value_buf, it->btree.height-1);
    if (br == BTREE_RESULT_SUCCESS) {
        BTREE_ITR_SET_FWD(it);
    } else {
        BTREE_ITR_SET_NONE(it);
    }
    return br;
}

