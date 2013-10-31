/*
 * Copyright 2013 Jung-Sang Ahn <jungsang.ahn@gmail.com>.
 * All Rights Reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "btree.h"
#include "common.h"

//#define BTREE_MULTI_SPLIT
#ifdef BTREE_MULTI_SPLIT
    #include "list.h"
#endif

#ifdef __DEBUG
    #include "memleak.h"
#ifndef __DEBUG_BTREE
    #undef DBG
    #undef DBGCMD
    #undef DBGSW
    #define DBG(args...)
    #define DBGCMD(command...)
    #define DBGSW(n, command...) 
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

INLINE struct bnode *_fetch_bnode(void *addr)
{
    struct bnode *node = (struct bnode *)addr;
    if (!(node->flag & BNODE_MASK_METADATA)) {
        // no metadata
        node->data = addr + sizeof(struct bnode);
    } else {
        // metadata
        metasize_t metasize;
        memcpy(&metasize, addr + sizeof(struct bnode), sizeof(metasize_t));        
        node->data = addr + sizeof(struct bnode) + sizeof(metasize_t) + _metasize_align(metasize);
    }
    return node;
}

INLINE int _bnode_size(
    struct btree *btree, struct bnode *node, void *key_arr, void *value_arr, size_t len)
{
    int nodesize = 0;
    
    if (node->flag & BNODE_MASK_METADATA) {
        metasize_t size;
        memcpy(&size, (void *)node + sizeof(struct bnode), sizeof(metasize_t));
        nodesize = sizeof(struct bnode) + btree->kv_ops->get_data_size(node, key_arr, value_arr, len) + 
            _metasize_align(size) + sizeof(metasize_t);
    }else{
        nodesize = sizeof(struct bnode) + btree->kv_ops->get_data_size(node, key_arr, value_arr, len);
    }

    return nodesize;
}

// return true if there is enough space to insert one or more kv-pair into the NODE
#ifdef BTREE_MULTI_SPLIT

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

        btree->kv_ops->init_kv_var(btree, item->key, item->value);
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
        struct btree *btree, struct bnode *node, struct list *kv_ins_list, size_t *size_out) 
    {
        size_t nitem;
        size_t cursize;
        size_t nodesize = btree->blksize;
        struct list_elem *e;
        struct kv_ins_item *item;

        #ifdef __CRC32
            nodesize -= BLK_MARKER_SIZE;
        #endif

        nitem = 0;
        e = list_begin(kv_ins_list);
        while(e){
            nitem++;
            e = list_next(e);
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
                memcpy(key_arr + btree->ksize * i, item->key, btree->ksize);
                memcpy(value_arr + btree->ksize * i, item->value, btree->ksize);
                e = list_next(e);
            }
            cursize = _bnode_size(btree, node, key_arr, value_arr, nitem);

            free(key_arr);
            free(value_arr);            
        }else if (nitem == 1) {
            e = list_begin(kv_ins_list);
            item = _get_entry(e, struct kv_ins_item, le);            
            cursize = _bnode_size(btree, node, item->key, item->value, 1);        
        }else if (nitem == 0) {
            cursize = _bnode_size(btree, node, NULL, NULL, 0);
        }

        *size_out = cursize;
        return ( cursize <= nodesize );
    }

#else

    INLINE int _bnode_size_check(
        struct btree *btree, struct bnode *node, void *key, void *value, size_t *size_out) 
    {
        size_t nodesize = btree->blksize;
        #ifdef __CRC32
            nodesize -= BLK_MARKER_SIZE;
        #endif

        *size_out = _bnode_size(btree, node, key, value, 1);
        return ( *size_out <= nodesize );
    }

#endif

INLINE struct bnode * _btree_init_node(
    struct btree *btree, void *addr, bnode_flag_t flag, uint16_t level, struct btree_meta *meta)
{
    struct bnode *node = (struct bnode *)addr;
    
    node->kvsize = btree->ksize<<4 | btree->vsize;
    node->nentry = 0;
    node->level = level;
    node->flag = flag;
    if ((flag & BNODE_MASK_METADATA) && meta) {
        memcpy(addr + sizeof(struct bnode), &meta->size, sizeof(metasize_t));
        memcpy(addr + sizeof(struct bnode) + sizeof(metasize_t), meta->data, meta->size);
        node->data = addr + sizeof(struct bnode) + sizeof(metasize_t) + _metasize_align(meta->size);
    }else{
        node->data = addr + sizeof(struct bnode);
    }

#ifdef __CRC32
    memset(addr + btree->blksize - BLK_MARKER_SIZE, BLK_MARKER_BNODE, BLK_MARKER_SIZE);
#endif

    return node;
}

metasize_t btree_read_meta(struct btree *btree, void *buf)
{
    void *addr;
    void *ptr;
    metasize_t size;
    struct bnode *node;

    addr = btree->blk_ops->blk_read(btree->blk_handle, btree->root_bid);
    node = _fetch_bnode(addr);
    if (node->flag & BNODE_MASK_METADATA) {
        ptr = addr + sizeof(struct bnode);
        memcpy(&size, ptr, sizeof(metasize_t));
        memcpy(buf, ptr + sizeof(metasize_t), size);
    } else {
        size = 0;
    }

    return size;
}

void btree_update_meta(struct btree *btree, struct btree_meta *meta)
{
    void *addr;
    void *ptr;
    metasize_t metasize;
    metasize_t old_metasize;
    struct bnode *node;
    bid_t new_bid;

    // read root node
    addr = btree->blk_ops->blk_read(btree->blk_handle, btree->root_bid);
    node = _fetch_bnode(addr);

    ptr = addr + sizeof(struct bnode);
    metasize = old_metasize = 0;
    
    if (node->flag & BNODE_MASK_METADATA) {
        memcpy(&old_metasize, ptr, sizeof(metasize_t));
    }

    if (meta) {
        metasize = meta->size;

        // new meta size cannot be larger than old meta size
        assert(metasize <= old_metasize);

        // overwrite
        if (meta->size > 0) {
            memcpy(ptr, &metasize, sizeof(metasize_t));
            memcpy(ptr + sizeof(metasize_t), meta->data, metasize);
            node->flag |= BNODE_MASK_METADATA;
        }else{
            // clear the flag
            node->flag &= ~BNODE_MASK_METADATA;
        }
        // move kv-pairs (only if meta size is changed)
        if (_metasize_align(metasize) < _metasize_align(old_metasize)){
            memmove(
                ptr + sizeof(metasize_t) + _metasize_align(metasize), 
                node->data, 
                btree->kv_ops->get_data_size(node, NULL, NULL, 0));
            node->data -= (_metasize_align(old_metasize) - _metasize_align(metasize));
        }

    }else {
        if (node->flag & BNODE_MASK_METADATA) {
            // existing metadata is removed
            memmove(ptr, node->data, btree->kv_ops->get_data_size(node, NULL, NULL, 0));
            node->data -= (_metasize_align(old_metasize) + sizeof(metasize_t));
            // clear the flag
            node->flag &= ~BNODE_MASK_METADATA;
        }
    }

    if (!btree->blk_ops->blk_is_writable(btree->blk_handle, btree->root_bid)) {
        // already flushed block -> cannot overwrite, we have to move to new block
        addr = btree->blk_ops->blk_move(btree->blk_handle, btree->root_bid, &btree->root_bid);
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
    root = _fetch_bnode(addr);

#ifdef _BNODE_COMP
    btree->blk_ops->blk_set_uncomp_size(btree->blk_handle, btree->root_bid,
                                        _bnode_size(btree, root));
#endif

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
    struct bnode *root;

    btree->root_flag = BNODE_MASK_ROOT | flag;
    btree->blk_ops = blk_ops;
    btree->blk_handle = blk_handle;
    btree->kv_ops = kv_ops;
    btree->height = 1;
    btree->blksize = nodesize;
    btree->ksize = ksize;
    btree->vsize = vsize;
    if (meta) btree->root_flag |= BNODE_MASK_METADATA;

    // create the first root node
    addr = btree->blk_ops->blk_alloc(btree->blk_handle, &btree->root_bid);
    root = _btree_init_node(btree, addr, btree->root_flag, BNODE_MASK_ROOT, meta);
    #ifdef _BNODE_COMP
        btree->blk_ops->blk_set_uncomp_size(btree->blk_handle, btree->root_bid, _bnode_size(btree, root));
    #endif

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
idx_t _btree_find_entry(struct btree *btree, struct bnode *node, void *key)
{
    idx_t start, end, middle, temp;
    uint8_t k[btree->ksize];
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
        if (btree->kv_ops->cmp(key, k) < 0) {
            if (btree->kv_ops->free_kv_var) btree->kv_ops->free_kv_var(btree, k, NULL);
            return BTREE_IDX_NOT_FOUND;
        }
        
        // compare with largest key
        btree->kv_ops->get_kv(node, end-1, k, NULL);
        // larger than largest key
        if (btree->kv_ops->cmp(key, k) >= 0) {
            if (btree->kv_ops->free_kv_var) btree->kv_ops->free_kv_var(btree, k, NULL);
            return end-1;
        }

        // binary search
        while(start+1 < end) {
            middle = (start + end) >> 1;

            // get key at middle
            btree->kv_ops->get_kv(node, middle, k, NULL);
            cmp = btree->kv_ops->cmp(key, k);

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

idx_t _btree_add_entry(struct btree *btree, struct bnode *node, void *key, void *value)
{
    idx_t idx, idx_insert;
    void *ptr;
    uint8_t k[btree->ksize];

    if (btree->kv_ops->init_kv_var) btree->kv_ops->init_kv_var(btree, k, NULL);
    
    if (node->nentry > 0) {
        idx = _btree_find_entry(btree, node, key);

        if (idx == BTREE_IDX_NOT_FOUND) idx_insert = 0;
        else {
            btree->kv_ops->get_kv(node, idx, k, NULL);
            if (!btree->kv_ops->cmp(key, k)) { 
                // if same key already exists -> update its value
                btree->kv_ops->set_kv(node, idx, key, value);
                if (btree->kv_ops->free_kv_var) btree->kv_ops->free_kv_var(btree, k, NULL);
                return idx;
            }else{
                idx_insert = idx+1;        
            }
        }

        if (idx_insert < node->nentry) {
            ptr = node->data;

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

idx_t _btree_remove_entry(struct btree *btree, struct bnode *node, void *key)
{
    idx_t idx;
    void *ptr;
    
    if (node->nentry > 0) {
        idx = _btree_find_entry(btree, node, key);

        if (idx == BTREE_IDX_NOT_FOUND) return idx;

        ptr = node->data;

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

void _btree_print_node(struct btree *btree, int depth, bid_t bid, btree_print_func func)
{
    int i;
    uint8_t k[btree->ksize], v[btree->vsize];
    void *addr;
    struct bnode *node;
    struct bnode *child;

    if (btree->kv_ops->init_kv_var) btree->kv_ops->init_kv_var(btree, k, v);

    addr = btree->blk_ops->blk_read(btree->blk_handle, bid);
    node = _fetch_bnode(addr);

    fprintf(stderr, "[d:%d n:%d f:%x b:%"_F64" ", node->level, node->nentry, node->flag, bid);

    for (i=0;i<node->nentry;++i){
        btree->kv_ops->get_kv(node, i, k, v);
        func(btree, k, v);
    }
    fprintf(stderr, "]\n");
    if (depth > 1) {
        for (i=0;i<node->nentry;++i){
            btree->kv_ops->get_kv(node, i, k, v);
            _btree_print_node(btree, depth-1, btree->kv_ops->value2bid(v), func);
        }
    }

    if (btree->kv_ops->free_kv_var) btree->kv_ops->free_kv_var(btree, k, v);
}

void btree_print_node(struct btree *btree, btree_print_func func)
{
    void *addr;

    fprintf(stderr, "tree height: %d\n", btree->height);
    _btree_print_node(btree, btree->height, btree->root_bid, func);
}

INLINE size_t _btree_get_nsplitnode(struct btree *btree, struct bnode *node, size_t size)
{
    size_t headersize, dataspace;
    size_t nodesize = btree->blksize;
    size_t nnode = 0;

    #ifdef __CRC32
        nodesize -= BLK_MARKER_SIZE;
    #endif
        
    if (node->flag & BNODE_MASK_METADATA) {
        metasize_t size;
        memcpy(&size, (void *)node + sizeof(struct bnode), sizeof(metasize_t));
        headersize = sizeof(struct bnode) + _metasize_align(size) + sizeof(metasize_t);
    }else{
        headersize = sizeof(struct bnode);
    }

    dataspace = nodesize - headersize;
    // round up
    nnode = ((size - headersize) + (dataspace-1)) / dataspace;

    return nnode;
}

btree_result btree_find(struct btree *btree, void *key, void *value_buf)
{
    void *addr;
    uint8_t k[btree->ksize], v[btree->vsize];
    idx_t idx[btree->height];
    bid_t bid[btree->height];
    struct bnode *node[btree->height];
    int i;

    if (btree->kv_ops->init_kv_var) btree->kv_ops->init_kv_var(btree, k, v);

    // set root
    bid[btree->height-1] = btree->root_bid;

    for (i=btree->height-1; i>=0; --i) {
        // read block using bid
        addr = btree->blk_ops->blk_read(btree->blk_handle, bid[i]);
        // fetch node structure from block
        node[i] = _fetch_bnode(addr);

        // lookup key in current node
        idx[i] = _btree_find_entry(btree, node[i], key);

        if (idx[i] == BTREE_IDX_NOT_FOUND) {
            // not found .. return NULL
            if (btree->blk_ops->blk_operation_end) btree->blk_ops->blk_operation_end(btree->blk_handle);
            if (btree->kv_ops->free_kv_var) btree->kv_ops->free_kv_var(btree, k, v);
            return BTREE_RESULT_FAIL;
        }

        btree->kv_ops->get_kv(node[i], idx[i], k, v);

        if (i>0) {
            // index (non-leaf) node
            // get bid of child node from value
            bid[i-1] = btree->kv_ops->value2bid(v);
        }else{
            // leaf node
            // return (address of) value if KEY == k
            if (!btree->kv_ops->cmp(key, k)) {
                btree->kv_ops->set_value(btree, value_buf, v);
            }else{
                if (btree->blk_ops->blk_operation_end) btree->blk_ops->blk_operation_end(btree->blk_handle);
                if (btree->kv_ops->free_kv_var) btree->kv_ops->free_kv_var(btree, k, v);
                return BTREE_RESULT_FAIL;
            }
        }
    }
    if (btree->blk_ops->blk_operation_end) btree->blk_ops->blk_operation_end(btree->blk_handle);
    if (btree->kv_ops->free_kv_var) btree->kv_ops->free_kv_var(btree, k, v);
    return BTREE_RESULT_SUCCESS;
}

btree_result btree_insert(struct btree *btree, void *key, void *value)
{
    void *addr; 
    uint8_t k[btree->ksize], v[btree->vsize];
    // index# and block ID for each level
    idx_t idx[btree->height];
    bid_t bid[btree->height];
    // flags
    int8_t modified[btree->height], moved[btree->height], ins[btree->height];

    // key, value to be inserted
#ifdef BTREE_MULTI_SPLIT
    struct list kv_ins_list[btree->height];
    struct kv_ins_item *kv_item;
    struct list_elem *e;
#else
    uint8_t key_ins[btree->height][btree->ksize];
    uint8_t value_ins[btree->height][btree->vsize];
#endif

    // index# where kv is inserted
    idx_t idx_ins[btree->height];
    struct bnode *node[btree->height];
    int i, j;

    // initialize flags
    for (i=0;i<btree->height;++i) moved[i] = modified[i] = ins[i] = 0;

    // initialize temporary variables    
    if (btree->kv_ops->init_kv_var) {
        btree->kv_ops->init_kv_var(btree, k, v);
        for (i=0;i<btree->height;++i){
            #ifdef BTREE_MULTI_SPLIT
                list_init(&kv_ins_list[i]);
            #else
                btree->kv_ops->init_kv_var(btree, key_ins[i], value_ins[i]);
            #endif
        }
    }

    // copy key-value pair to be inserted into leaf node
    #ifdef BTREE_MULTI_SPLIT
        kv_item = _kv_ins_item_create(btree, key, value);
        list_push_back(&kv_ins_list[0], &kv_item->le);
    #else
        btree->kv_ops->set_key(btree, key_ins[0], key);
        btree->kv_ops->set_value(btree, value_ins[0], value);
    #endif    
    
    ins[0] = 1;

    // set root node
    bid[btree->height-1] = btree->root_bid;

    // find path from root to leaf
    for (i=btree->height-1; i>=0; --i){
        // read block using bid
        addr = btree->blk_ops->blk_read(btree->blk_handle, bid[i]);
        // fetch node structure from block
        node[i] = _fetch_bnode(addr);
        
        // lookup key in current node
        idx[i] = _btree_find_entry(btree, node[i], key);

        if (i > 0) {
            // index (non-leaf) node
            if (idx[i] == BTREE_IDX_NOT_FOUND)
                // KEY is smaller than the smallest key in this node .. just follow the smallest key
                idx[i] = 0;

            // get bid of child node from value
            btree->kv_ops->get_kv(node[i], idx[i], k, v);
            bid[i-1] = btree->kv_ops->value2bid(v);            
        }else{
            // leaf node .. do nothing
        }
    }

    // cascaded insert from leaf to root
    for (i=0;i<btree->height;++i){
        
        if (idx[i] != BTREE_IDX_NOT_FOUND)
            btree->kv_ops->get_kv(node[i], idx[i], k, v);

        if (i > 0) {
            // in case of index node
            // when KEY is smaller than smallest key in index node
            if (idx[i] == 0 && btree->kv_ops->cmp(key, k) < 0) {
                // change node's smallest key
                btree->kv_ops->set_kv(node[i], idx[i], key, v);
                //memcpy(k, key, btree->ksize);
                btree->kv_ops->set_key(btree, k, key);
                modified[i] = 1;
            }

            // when child node is moved to new block
            if (moved[i-1]) {
                // replace the bid (value)
                btree->kv_ops->set_kv(node[i], idx[i], k, btree->kv_ops->bid2value(&bid[i-1]));
                modified[i] = 1;
            }
        }        

        if (ins[i]) {
            // there is a key-value pair to be inserted into this (level of) node
        
            // check whether btree node space is enough to add new key-value pair or not, OR
            // action is not insertion but update (key_ins exists in current node)
            int is_update = 0;
            if (i==0) {
                #ifdef BTREE_MULTI_SPLIT
                    e = list_begin(&kv_ins_list[i]);
                    kv_item = _get_entry(e, struct kv_ins_item, le);
                    is_update = 
                        (idx[i] != BTREE_IDX_NOT_FOUND && !btree->kv_ops->cmp(kv_item->key, k));
                #else
                    is_update = 
                        (idx[i] != BTREE_IDX_NOT_FOUND && !btree->kv_ops->cmp(key_ins[i], k));
                #endif
            }

            size_t nodesize;            
            #ifndef _BNODE_COMP
                #ifdef BTREE_MULTI_SPLIT
                    int _size_check = _bnode_size_check(btree, node[i], &kv_ins_list[i], &nodesize);
                #else
                    int _size_check = _bnode_size_check(btree, node[i], key_ins[i], value_ins[i], &nodesize);
                #endif
            #else
                size_t compsize = btree->blk_ops->blk_comp_size(btree->blk_handle, bid[i]);
                int _size_check = (compsize + 2*(btree->ksize + btree->vsize) <= btree->blksize);
                
            #endif
            
            if (_size_check || is_update ) {
                // enough .. insert
                #ifdef BTREE_MULTI_SPLIT
                    // insert all kv pairs on list
                    e = list_begin(&kv_ins_list[i]);
                    while(e) {
                        kv_item = _get_entry(e, struct kv_ins_item, le);
                        idx_ins[i] = _btree_add_entry(btree, node[i], kv_item->key, kv_item->value);
                        e = list_next(e);
                    }                        
                #else
                    idx_ins[i] = _btree_add_entry(btree, node[i], key_ins[i], value_ins[i]);
                #endif
                
                modified[i] = 1;
                
            }else {
                // not enough .. split the node
                size_t nnode = _btree_get_nsplitnode(btree, node[i], nodesize);
                bid_t new_bid[nnode];
                struct bnode *new_node[nnode];
                idx_t split_idx[nnode+1];
                int nentry[nnode];

                // allocate new block(s)
                new_node[0] = node[i];
                for (j=1;j<nnode;++j){
                    addr = btree->blk_ops->blk_alloc(btree->blk_handle, &new_bid[j]);
                    new_node[j] = _btree_init_node(btree, addr, 0x0, node[i]->level, NULL);
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
                    btree->kv_ops->copy_kv(new_node[j], node[i], 0, split_idx[j], nentry[j]);
                }
                j = 0;
                btree->kv_ops->copy_kv(new_node[j], node[i], 0, split_idx[j], nentry[j]);

                // header
                for (j=0;j<nnode;++j){
                    new_node[j]->nentry = nentry[j];
                }

                modified[i] = 1;

                // insert kv-pair(s) to appropriate node
                #ifdef BTREE_MULTI_SPLIT
                    e = list_begin(&kv_ins_list[i]);
                    while(e) {
                        kv_item = _get_entry(e, struct kv_ins_item, le);

                        idx_ins[i] = BTREE_IDX_NOT_FOUND;
                        for (j=1;j<nnode;++j){
                            btree->kv_ops->get_kv(new_node[j], 0, k, v);
                            if (btree->kv_ops->cmp(kv_item->key, k) < 0) {
                                idx_ins[i] = _btree_add_entry(btree, new_node[j-1], kv_item->key, kv_item->value);
                                break;
                            }
                        }
                        if (idx_ins[i] == BTREE_IDX_NOT_FOUND) {
                            // insert into the last split node
                            idx_ins[i] = _btree_add_entry(btree, new_node[nnode-1], kv_item->key, kv_item->value);
                        }
                        e = list_next(e);
                    }
                #else
                    btree->kv_ops->get_kv(new_node[1], 0, k, v);
                    if (btree->kv_ops->cmp(key_ins[i], k) < 0) {
                        idx_ins[i] = _btree_add_entry(btree, node[i], key_ins[i], value_ins[i]);
                    }else{
                        _btree_add_entry(btree, new_node[1], key_ins[i], value_ins[i]);
                    }
                #endif
                
                #ifdef _BNODE_COMP
                    btree->blk_ops->blk_set_uncomp_size(btree->blk_handle, new_bid, _bnode_size(btree, new_node));
                #endif

                if (i+1 < btree->height) {
                    // non-root node
                    // reserve kv-pair (i.e. splitters) to be inserted into parent node
                    #ifdef BTREE_MULTI_SPLIT
                        for (j=1; j<nnode; ++j){
                            kv_item = _kv_ins_item_create(btree, NULL, &new_bid[j]);
                            btree->kv_ops->get_nth_splitter(new_node[j-1], new_node[j], kv_item->key);
                            list_push_back(&kv_ins_list[i+1], &kv_item->le);
                        }
                    #else
                        btree->kv_ops->get_nth_splitter(new_node[0], new_node[1], key_ins[i+1]);
                        //btree->kv_ops->set_key(btree, key_ins[i+1], k);
                        btree->kv_ops->set_value(btree, value_ins[i+1], &new_bid[1]);
                    #endif
                    ins[i+1] = 1;
                    
                }else{
                    // root node -> height grow up
                    // allocate new block for new root node
                    bid_t new_root_bid;
                    struct bnode *new_root;
                    uint8_t buf[btree->blksize];
                    struct btree_meta meta;

                    meta.size = btree_read_meta(btree, buf);
                    meta.data = buf;
                    // remove metadata section of existing node (this node is not root anymore)
                    btree_update_meta(btree, NULL);
                    
                    addr = btree->blk_ops->blk_alloc(btree->blk_handle, &new_root_bid);
                    if (meta.size > 0) 
                        new_root = _btree_init_node(btree, addr, btree->root_flag, node[i]->level + 1, &meta);
                    else
                        new_root = _btree_init_node(btree, addr, btree->root_flag, node[i]->level + 1, NULL);
                    
                    // clear old root node flag
                    node[i]->flag &= ~BNODE_MASK_ROOT;
                    node[i]->flag &= ~BNODE_MASK_SEQTREE;
                    // change root bid
                    btree->root_bid = new_root_bid;
                    
                    // move the former node if not dirty
                    if (!btree->blk_ops->blk_is_writable(btree->blk_handle, bid[i])) {
                        addr = btree->blk_ops->blk_move(btree->blk_handle, bid[i], &bid[i]);
                        node[i] = _fetch_bnode(addr);
                    }else{
                        btree->blk_ops->blk_set_dirty(btree->blk_handle, bid[i]);
                    }
                    
                    // insert kv-pairs pointing to their child nodes
                    // original (i.e. the first node)
                    btree->kv_ops->get_kv(node[i], 0, k, v);
                    _btree_add_entry(btree, new_root, k, btree->kv_ops->bid2value(&bid[i]));
                    // the others
                    for (j=1;j<nnode;++j){
                        //btree->kv_ops->get_kv(new_node[j], 0, k, v);
                        btree->kv_ops->get_nth_splitter(new_node[j-1], new_node[j], k);
                        _btree_add_entry(btree, new_root, k, btree->kv_ops->bid2value(&new_bid[j]));
                    }

                    #ifdef _BNODE_COMP
                        btree->blk_ops->blk_set_uncomp_size(btree->blk_handle, bid[i], _bnode_size(btree, node[i]));
                        btree->blk_ops->blk_set_uncomp_size(btree->blk_handle, new_root_bid, 
                            _bnode_size(btree, new_root));
                    #endif

                    btree->height++;

                    if (btree->blk_ops->blk_operation_end) btree->blk_ops->blk_operation_end(btree->blk_handle);    
                    if (btree->kv_ops->free_kv_var) {
                        btree->kv_ops->free_kv_var(btree, k, v);
                        for (j=0;j<btree->height-1;++j){
                            #ifdef BTREE_MULTI_SPLIT
                                e = list_begin(&kv_ins_list[j]);
                                while(e) {
                                    kv_item = _get_entry(e, struct kv_ins_item, le);
                                    e = list_remove(&kv_ins_list[j], e);

                                    btree->kv_ops->free_kv_var(btree, kv_item->key, kv_item->value);
                                    _kv_ins_item_free(kv_item);
                                }
                            #else
                                btree->kv_ops->free_kv_var(btree, key_ins[j], value_ins[j]);
                            #endif
                        }
                    }
                    return BTREE_RESULT_SUCCESS;
                }    
            }
        }

        if (modified[i]) {
            // when node is modified            
            if (!btree->blk_ops->blk_is_writable(btree->blk_handle, bid[i])) {
                // already flushed block -> cannot overwrite, we have to move to new block
                // get new bid[i]
                addr = btree->blk_ops->blk_move(btree->blk_handle, bid[i], &bid[i]);
                node[i] = _fetch_bnode(addr);
                moved[i] = 1;

                if (i+1 == btree->height) 
                    // if moved node is root node
                    btree->root_bid = bid[i];
            }else{
                btree->blk_ops->blk_set_dirty(btree->blk_handle, bid[i]);
            }
            
            #ifdef _BNODE_COMP
                btree->blk_ops->blk_set_uncomp_size(btree->blk_handle, bid[i], _bnode_size(btree, node[i]));
            #endif
        }
        
    }

    if (btree->blk_ops->blk_operation_end) btree->blk_ops->blk_operation_end(btree->blk_handle);
    if (btree->kv_ops->free_kv_var) {
        btree->kv_ops->free_kv_var(btree, k, v);
        for (j=0;j<btree->height;++j){
            #ifdef BTREE_MULTI_SPLIT
                e = list_begin(&kv_ins_list[j]);
                while(e) {
                    kv_item = _get_entry(e, struct kv_ins_item, le);
                    e = list_remove(&kv_ins_list[j], e);                    

                    btree->kv_ops->free_kv_var(btree, kv_item->key, kv_item->value);
                    _kv_ins_item_free(kv_item);
                }
            #else
                btree->kv_ops->free_kv_var(btree, key_ins[j], value_ins[j]);
            #endif
        }
    }
    return BTREE_RESULT_SUCCESS;
    
}

btree_result btree_remove(struct btree *btree, void *key)
{
    void *addr;
    uint8_t k[btree->ksize], v[btree->vsize];
    uint8_t kk[btree->ksize], vv[btree->vsize];
    // index# and block ID for each level
    idx_t idx[btree->height];
    bid_t bid[btree->height];
    // flags
    int8_t modified[btree->height], moved[btree->height], rmv[btree->height];
    // index# of removed key
    idx_t idx_rmv[btree->height];
    struct bnode *node[btree->height];
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
        node[i] = _fetch_bnode(addr);

        // lookup key in current node
        idx[i] = _btree_find_entry(btree, node[i], key);

        if (idx[i] == BTREE_IDX_NOT_FOUND) {
            // not found
            if (btree->blk_ops->blk_operation_end) btree->blk_ops->blk_operation_end(btree->blk_handle);
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
                if (btree->kv_ops->cmp(kk, k)) {
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
                btree->kv_ops->set_kv(node[i], idx[i], k, btree->kv_ops->bid2value(&bid[i-1]));
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
            if ((node[i]->nentry < 1 && i+1 < btree->height) || (node[i]->nentry <= 1 && i+1 == btree->height)) {
                // remove the node
                if (i+1 < btree->height) {
                    // if non-root node
                    rmv[i+1] = 1;
                }else{
                    // if root node
                    btree->height--;
                    btree->kv_ops->get_kv(node[i], 0, k, v);
                    btree->root_bid = btree->kv_ops->value2bid(v);
                }
            }
        }

        if (modified[i]) {
            // when node is modified            
            if (!btree->blk_ops->blk_is_writable(btree->blk_handle, bid[i])) {
                // already flushed block -> cannot overwrite, we have to move to new block
                // get new bid[i]
                addr = btree->blk_ops->blk_move(btree->blk_handle, bid[i], &bid[i]);
                node[i] = _fetch_bnode(addr);
                moved[i] = 1;

                if (i+1 == btree->height) 
                    // if moved node is root node
                    btree->root_bid = bid[i];
            }else{
                btree->blk_ops->blk_set_dirty(btree->blk_handle, bid[i]);
            }
            
            #ifdef _BNODE_COMP
                btree->blk_ops->blk_set_uncomp_size(btree->blk_handle, bid[i], _bnode_size(btree, node[i]));
            #endif
        }        
    }

    if (btree->blk_ops->blk_operation_end) btree->blk_ops->blk_operation_end(btree->blk_handle);
    if (btree->kv_ops->free_kv_var) {
        btree->kv_ops->free_kv_var(btree, k, v);
        btree->kv_ops->free_kv_var(btree, kk, vv);                
    }
    return BTREE_RESULT_SUCCESS;
}

btree_result btree_operation_end(struct btree *btree)
{
    if (btree->blk_ops->blk_operation_end) btree->blk_ops->blk_operation_end(btree->blk_handle);
    return BTREE_RESULT_SUCCESS;
}

btree_result btree_iterator_init(struct btree *btree, struct btree_iterator *it, void *initial_key)
{
    int i;
    
    it->btree = *btree;
    it->curkey = (void *)mempool_alloc(btree->ksize);
    if (btree->kv_ops->init_kv_var) btree->kv_ops->init_kv_var(btree, it->curkey, NULL);
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
    it->node = (struct bnode **)mempool_alloc(sizeof(struct bnode *) * btree->height);
    for (i=0;i<btree->height;++i){
        it->bid[i] = BTREE_BLK_NOT_FOUND;
        it->idx[i] = BTREE_IDX_NOT_FOUND;
        it->node[i] = NULL;
    }
    it->bid[btree->height-1] = btree->root_bid;
    
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
        if (it->node[i]) mempool_free(it->node[i]);
    }
    mempool_free(it->node);
    return BTREE_RESULT_SUCCESS;
}

btree_result _btree_next(struct btree_iterator *it, void *key_buf, void *value_buf, int depth)
{
    struct btree *btree;
    btree = &it->btree;
    int i;
    uint8_t k[btree->ksize], v[btree->vsize];
    void *addr, *addr_cpy;
    struct bnode *node;
    btree_result r;

    if (it->btree.kv_ops->init_kv_var) {
        it->btree.kv_ops->init_kv_var(&it->btree, k, v);
    }

    if (it->node[depth] == NULL){
        addr = btree->blk_ops->blk_read(btree->blk_handle, it->bid[depth]);
        addr_cpy = (void *)mempool_alloc(btree->blksize);
        memcpy(addr_cpy, addr, btree->blksize);
        it->node[depth] = _fetch_bnode(addr_cpy);
    }
    node = _fetch_bnode(it->node[depth]);
    //assert(node->level == depth+1);

    if (node->nentry <= 0) {
        if (it->btree.kv_ops->free_kv_var) it->btree.kv_ops->free_kv_var(&it->btree, k, v);
        return BTREE_RESULT_FAIL;
    }
    
    if (it->idx[depth] == BTREE_IDX_NOT_FOUND) {
        // curkey: lastly returned key
        it->idx[depth] = _btree_find_entry(btree, node, it->curkey);
        if (it->idx[depth] == BTREE_IDX_NOT_FOUND) {
            it->idx[depth] = 0;
        }
        btree->kv_ops->get_kv(node, it->idx[depth], key_buf, value_buf);
        if (btree->kv_ops->cmp(it->curkey, key_buf) > 0 && depth == 0) {
            // in leaf node, next key must be larger than previous key (i.e. it->curkey)
            it->idx[depth]++;
        }
    }

    if (it->idx[depth] >= node->nentry) {
        // out of bound .. go up to parent node
        it->idx[depth] = 0;
        if (it->node[depth]) mempool_free(it->node[depth]);
        it->node[depth] = NULL;
        
        if (it->btree.kv_ops->free_kv_var) it->btree.kv_ops->free_kv_var(&it->btree, k, v);
        return BTREE_RESULT_FAIL;
    }

    if (depth > 0) {
        // index node
        if (it->node[depth-1] == NULL) {
            btree->kv_ops->get_kv(node, it->idx[depth], k, v);
            it->bid[depth-1] = btree->kv_ops->value2bid(v);
        }
        r = _btree_next(it, key_buf, value_buf, depth-1);
        
        if (r == BTREE_RESULT_FAIL) {
            // move index to right
            it->idx[depth]++;
            
            if (it->idx[depth] >= node->nentry){
                // out of bound .. go up to parent node
                it->idx[depth] = 0;
                if (it->node[depth]) mempool_free(it->node[depth]);
                it->node[depth] = NULL;
                if (it->btree.kv_ops->free_kv_var) it->btree.kv_ops->free_kv_var(&it->btree, k, v);
                return BTREE_RESULT_FAIL;
            }else{
                btree->kv_ops->get_kv(node, it->idx[depth], k, v);
                it->bid[depth-1] = btree->kv_ops->value2bid(v);
                // reset child index
                for (i=depth-1; i>=0; --i) {
                    it->idx[i] = 0;
                    if (it->node[i]) mempool_free(it->node[i]);
                    it->node[i] = NULL;
                }
                // retry
                r = _btree_next(it, key_buf, value_buf, depth-1);
            }
        }
        if (it->btree.kv_ops->free_kv_var) it->btree.kv_ops->free_kv_var(&it->btree, k, v);
        return r;
    }else{
        // leaf node
        btree->kv_ops->get_kv(node, it->idx[depth], key_buf, value_buf);
        //memcpy(it->curkey, key_buf, btree->ksize);
        btree->kv_ops->set_key(btree, it->curkey, key_buf);
        it->idx[depth]++;
        if (it->btree.kv_ops->free_kv_var) it->btree.kv_ops->free_kv_var(&it->btree, k, v);
        return BTREE_RESULT_SUCCESS;
    }
}

btree_result btree_next(struct btree_iterator *it, void *key_buf, void *value_buf)
{
    btree_result br = _btree_next(it, key_buf, value_buf, it->btree.height-1);
    return br;
}
