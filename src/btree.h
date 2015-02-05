/* -*- Mode: C++; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * Generic B+Tree
 * (C) 2013  Jung-Sang Ahn <jungsang.ahn@gmail.com>
 */

#ifndef _JSAHN_BTREE_H
#define _JSAHN_BTREE_H

#include <stdint.h>
#include "common.h"

#ifdef __cplusplus
extern "C" {
#endif

#define _get_kvsize(kvsize, ksize, vsize) \
    (ksize) = ((kvsize) & 0xff00) >> 8;    \
    (vsize) = ((kvsize) & 0x00ff)
#define __ksize(kvsize) (((kvsize) & 0xff00) >> 8)
#define __vsize(kvsize) (((kvsize) & 0x00ff))

#define BTREE_BLK_NOT_FOUND BLK_NOT_FOUND

typedef enum {
    BTREE_RESULT_SUCCESS,
    BTREE_RESULT_UPDATE,
    BTREE_RESULT_FAIL
} btree_result;

//#define _BTREE_32BIT_IDX
#ifdef _BTREE_32BIT_IDX
    typedef uint32_t idx_t;
    #define BTREE_IDX_NOT_FOUND 0xffffffff
#else
    typedef uint16_t idx_t;
    #define BTREE_IDX_NOT_FOUND 0xffff
#endif

typedef uint16_t bnode_flag_t;

struct bnode{
    uint16_t kvsize;
    bnode_flag_t flag;
    uint16_t level;
    idx_t nentry;
    // BTREE_CRC_OFFSET in option.h must be modified if this offset is changed.
    union {
        // array of key value pair ([k1][v1][k2][v2]...)
        void *data;
        // The size of this union should be 8 bytes
        // even though sizeof(void*) is 4 bytes
        // BTREE_CRC_FIELD_LEN in option.h must be modified if the size of this
        // union is changed.
        uint64_t dummy;
    };
};
#define BNODE_MASK_ROOT 0x1
#define BNODE_MASK_METADATA 0x2
#define BNODE_MASK_SEQTREE 0x4

typedef uint16_t metasize_t;
struct btree_meta{
    metasize_t size;
    void *data;
};

typedef void* voidref;
typedef struct bnode* bnoderef;

struct btree_blk_ops {
    voidref (*blk_alloc)(void *handle, bid_t *bid);
    voidref (*blk_alloc_sub)(void *handle, bid_t *bid);
    voidref (*blk_enlarge_node)(void *voidhandle, bid_t old_bid,
                                size_t req_size, bid_t *new_bid);
    voidref (*blk_read)(void *handle, bid_t bid);
    voidref (*blk_move)(void *handle, bid_t bid, bid_t *new_bid);
    void (*blk_remove)(void *handle, bid_t bid);
    int (*blk_is_writable)(void *handle, bid_t bid);
    size_t (*blk_get_size)(void *handle, bid_t bid);
    void (*blk_set_dirty)(void *handle, bid_t bid);
    void (*blk_operation_end)(void *handle); // optional
};

struct btree {
    uint8_t ksize;
    uint8_t vsize;
    uint16_t height;
    uint32_t blksize;
    bid_t root_bid;
    void *blk_handle;
    struct btree_blk_ops *blk_ops;
    struct btree_kv_ops *kv_ops;
    bnode_flag_t root_flag;
    void *aux;

#ifdef __UTREE
    uint16_t leafsize;
#endif
};

typedef struct {
    void *aux;
    uint8_t chunksize;
} btree_cmp_args ;

struct btree_kv_ops {
    void (*get_kv)(struct bnode *node, idx_t idx, void *key, void *value);
    void (*set_kv)(struct bnode *node, idx_t idx, void *key, void *value);
    void (*ins_kv)(struct bnode *node, idx_t idx, void *key, void *value);
    void (*copy_kv)(struct bnode *node_dst, struct bnode *node_src, idx_t dst_idx, idx_t src_idx, idx_t len);

    // return node size after inserting list of key/value pairs
    size_t (*get_data_size)(struct bnode *node, void *new_minkey, void *key_arr, void *value_arr, size_t len);
    // return (actual) key value size
    size_t (*get_kv_size)(struct btree *tree, void *key, void *value);

    void (*init_kv_var)(struct btree *tree, void *key, void *value);
    void (*free_kv_var)(struct btree *tree, void *key, void *value);

    void (*set_key)(struct btree *tree, void *dst, void *src);
    void (*set_value)(struct btree *tree, void *dst, void *src);

    void (*get_nth_idx)(struct bnode *node, idx_t num, idx_t den, idx_t *idx);
    //void (*get_nth_splitter)(struct bnode *node, idx_t num, idx_t den, void *key);
    void (*get_nth_splitter)(struct bnode *prev_node, struct bnode *node, void *key);

    int (*cmp)(void *key1, void *key2, void* aux);
    bid_t (*value2bid)(void *value);
    voidref (*bid2value)(bid_t *bid);
};

struct btree_iterator {
    struct btree btree;
    void *curkey;
    bid_t *bid;
    idx_t *idx;
    struct bnode **node;
    void **addr;
    uint8_t flags;
#define BTREE_ITERATOR_NONE 0x00
#define BTREE_ITERATOR_FWD  0x01
#define BTREE_ITERATOR_REV  0x02
#define BTREE_ITERATOR_NONE_MASK  0x03
};

#define BTREE_ITR_SET_NONE(iterator) \
    ((iterator)->flags &= ~BTREE_ITERATOR_NONE_MASK)
#define BTREE_ITR_IS_REV(iterator) \
    ((iterator)->flags & BTREE_ITERATOR_REV)
#define BTREE_ITR_IS_FWD(iterator) \
    ((iterator)->flags & BTREE_ITERATOR_FWD)
#define BTREE_ITR_SET_REV(iterator) \
    do {\
        BTREE_ITR_SET_NONE(iterator);\
        (iterator)->flags |= BTREE_ITERATOR_REV;\
    }while (0)
#define BTREE_ITR_SET_FWD(iterator) \
    do {\
        BTREE_ITR_SET_NONE(iterator);\
        (iterator)->flags |= BTREE_ITERATOR_FWD;\
    }while (0)

typedef void btree_print_func(struct btree *btree, void *key, void *value);
void btree_print_node(struct btree *btree, btree_print_func func);

//#define _BTREE_HAS_MULTIPLE_BNODES
#ifdef _BTREE_HAS_MULTIPLE_BNODES
struct bnode ** btree_get_bnode_array(void *addr, size_t *nnode_out);
#else
struct bnode * btree_get_bnode(void *addr);
#endif
metasize_t btree_read_meta(struct btree *btree, void *buf);
void btree_update_meta(struct btree *btree, struct btree_meta *meta);
btree_result btree_init_from_bid(
        struct btree *btree, void *blk_handle,
        struct btree_blk_ops *blk_ops,     struct btree_kv_ops *kv_ops,
        uint32_t nodesize, bid_t root_bid);
btree_result btree_init(
        struct btree *btree, void *blk_handle,
        struct btree_blk_ops *blk_ops,     struct btree_kv_ops *kv_ops,
        uint32_t nodesize, uint8_t ksize, uint8_t vsize,
        bnode_flag_t flag, struct btree_meta *meta);

btree_result btree_iterator_init(struct btree *btree, struct btree_iterator *it, void *initial_key);
btree_result btree_iterator_free(struct btree_iterator *it);
btree_result btree_next(struct btree_iterator *it, void *key_buf, void *value_buf);
btree_result btree_prev(struct btree_iterator *it, void *key_buf, void *value_buf);

btree_result btree_get_key_range(
    struct btree *btree, idx_t num, idx_t den, void *key_begin, void *key_end);

btree_result btree_find(struct btree *btree, void *key, void *value_buf);
btree_result btree_insert(struct btree *btree, void *key, void *value);
btree_result btree_remove(struct btree *btree, void *key);
btree_result btree_operation_end(struct btree *btree);

#ifdef __cplusplus
}
#endif

#endif
