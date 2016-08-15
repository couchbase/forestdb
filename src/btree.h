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

typedef struct bnode* bnoderef;
typedef int btree_cmp_func(void *key1, void *key2, void *aux);

/**
 * B+tree key-value operation wrapper class definition.
 * Actual operation class will inherit this class.
 */
class BTreeKVOps {
public:
    // Destructor
    virtual ~BTreeKVOps() { }

    // Initialize
    virtual void init(size_t _ksize, size_t _vsize, btree_cmp_func _cmp_func) {
        ksize = _ksize;
        vsize = _vsize;
        cmp_func = _cmp_func;
    }

    // Set default custom comparison function
    virtual void setCmpFunc(btree_cmp_func _cmp_func) {
        cmp_func = _cmp_func;
    }
    // Get the current comparison function
    virtual btree_cmp_func *getCmpFunc() const {
        return cmp_func;
    }

    // set key size
    virtual void setKSize(size_t _ksize) {
        ksize = _ksize;
    }
    // set value size
    virtual void setVSize(size_t _vsize) {
        vsize = _vsize;
    }

    /**
     * Get a key-value pair at a specific position in a B+tree node.
     *
     * @param node Pointer to the B+tree node.
     * @param idx Index number of the required key-value pair.
     * @param key Pointer to key buffer.
     * @param value Pointer to value buffer.
     */
    virtual void getKV(struct bnode *node, idx_t idx, void *key, void *value) = 0;

    /**
     * Assign a key-value pair at a specific position in a B+tree node.
     * The key-value pair already existing at the position will be overwritten.
     *
     * @param node Pointer to the B+tree node.
     * @param idx Index number where the key-value pair will be stored.
     * @param key Pointer to key buffer.
     * @param value Pointer to value buffer.
     */
    virtual void setKV(struct bnode *node, idx_t idx, void *key, void *value) = 0;

    /**
     * Insert a key-value pair at a specific position in a B+tree node.
     * Existing key-value pairs will be shifted so that there will be no overwrite.
     *
     * @param node Pointer to the B+tree node.
     * @param idx Index number where the key-value pair will be stored.
     * @param key Pointer to key buffer.
     * @param value Pointer to value buffer.
     */
    virtual void insKV(struct bnode *node, idx_t idx, void *key, void *value) = 0;

    /**
     * Copy a set of key-value pairs from the source node to the destination node.
     *
     * @param node_dst Pointer to the destination B+tree node.
     * @param node_src Pointer to the source B+tree node.
     * @param dst_idx Index number in the destination node where the copied
     *        key-value pair will be stored.
     * @param src_idx Index number in the source node where the target key-value
     *        pair is located.
     * @param len Number of key-value pairs.
     */
    virtual void copyKV(struct bnode *node_dst,
                        struct bnode *node_src,
                        idx_t dst_idx,
                        idx_t src_idx,
                        idx_t len) = 0;
    /**
     * Calculate the actual used space of a given node.
     *
     * @param node Pointer to the B+tree node.
     * @param new_minkey New smallest key in the node. NULL if smallest key does not
     *        change.
     * @param key_arr Array of keys that will be newly inserted into the node.
     * @param key_arr Array of values that will be newly inserted into the node.
     * @param len Size of the array.
     * @return Actual used space
     */
    virtual size_t getDataSize(struct bnode *node,
                               void *new_minkey,
                               void *key_arr,
                               void *value_arr,
                               size_t len) = 0;
    /**
     * Calculate the size of a key-value pair.
     *
     * @param key Pointer to key buffer.
     * @param value Pointer to value buffer.
     * @return Key-value pair size
     */
    virtual size_t getKVSize(void *key, void *value) = 0;
    /**
     * Initialize a key-value pair
     */
    virtual void initKVVar(void *key, void *value) = 0;
    /**
     * Free a key-value pair
     */
    virtual void freeKVVar(void *key, void *value) = 0;
    /**
     * Copy key from 'src' to 'dst'
     */
    virtual void setKey(void *dst, void *src) = 0;
    /**
     * Copy value from 'src' to 'dst'
     */
    virtual void setValue(void *dst, void *src) = 0;

    /**
     * Get the index number of the starting entry which is copied into 'num'-th
     * node when a B+tree node is split into 'den' nodes.
     */
    virtual idx_t getNthIdx(struct bnode *node, idx_t num, idx_t den) = 0;
    /**
     * Get a key that needs to be inserted into a parent node, when a B+tree node
     * is split into 'prev_node' and 'node'.
     */
    virtual void getNthSplitter(struct bnode *prev_node,
                                struct bnode *node,
                                void *key) { }
    inline virtual int cmp(void *key1, void *key2, void *aux) {
        return cmp_func(key1, key2, aux);
    }
    /**
     * Convert value buffer contents to block ID.
     */
    inline bid_t value2bid(void *value) {
        return *((bid_t *)value);
    }
    /**
     * Convert block ID to value buffer contents.
     */
    inline void* bid2value(bid_t *bid) {
        return (void *)bid;
    }

    /**
     * Assign a variable-length string to 'key'.
     */
    virtual void setVarKey(void *key, void *str, size_t len) = 0;
    /**
     * Assign an infinite key (which is grater than any other keys) to 'key'.
     */
    virtual void setInfVarKey(void *key) = 0;
    /**
     * Return true if 'key' is an infinite key.
     */
    virtual bool isInfVarKey(void *key) = 0;
    /**
     * Get a variable length string from 'key'.
     */
    virtual void getVarKey(void *key, void *strbuf, size_t& len) = 0;
    /**
     * Free 'key'.
     */
    virtual void freeVarKey(void *key) = 0;

protected:
    size_t ksize;
    size_t vsize;
    btree_cmp_func *cmp_func;
};

class BTreeBlkHandle;

/**
 * B+tree handle definition.
 */
class BTree {
public:
    // Default constructor.
    BTree() :
        ksize(0), vsize(0), height(0), blksize(0), bhandle(nullptr), kv_ops(nullptr),
        root_flag(0x0), aux(nullptr) { }

    // Constructor for creating a new B+tree.
    BTree(BTreeBlkHandle *_bhandle,
          BTreeKVOps *_kv_ops,
          uint32_t _nodesize,
          uint8_t _ksize,
          uint8_t _vsize,
          bnode_flag_t _flag,
          struct btree_meta *_meta);

    // Constructor for loading existing B+tree.
    BTree(BTreeBlkHandle *_bhandle,
          BTreeKVOps *_kv_ops,
          uint32_t _nodesize,
          bid_t _root_bid);

    // Destructor.
    ~BTree();

    // Create a new B+tree.
    btree_result init(BTreeBlkHandle *_bhandle,
                      BTreeKVOps *_kv_ops,
                      uint32_t _nodesize,
                      uint8_t _ksize,
                      uint8_t _vsize,
                      bnode_flag_t _flag,
                      struct btree_meta *_meta);

    // Load existing B+tree from the given BID.
    btree_result initFromBid(BTreeBlkHandle *_bhandle,
                             BTreeKVOps *_kv_ops,
                             uint32_t _nodesize,
                             bid_t _root_bid);

    // Read meta data in the root node.
    metasize_t readMeta(void *buf);
    // Update meta data in the root node.
    void updateMeta(struct btree_meta *meta);

    // Find the given key in the B+tree 'node', and return its index number.
    idx_t findEntry(struct bnode *node, void *key);
    // Add the given key into the B+tree 'node', and return its index number.
    idx_t addEntry(struct bnode *node, void *key, void *value);
    // Remove the given key from the B+tree 'node', and return its index number.
    idx_t removeEntry(struct bnode *node, void *key);

    /**
     * Get start key and end key of 'num'-th sub-tree, if we split the B+tree into
     * 'den' sub-trees.
     */
    btree_result getKeyRange(idx_t num, idx_t den, void *key_begin, void *key_end);

    // Get the value for the given key.
    btree_result find(void *key, void *value_buf);
    // Insert the given key-value pair.
    btree_result insert(void *key, void *value);
    // Remove the given key.
    btree_result remove(void *key);

    uint8_t getKSize() const {
        return ksize;
    }
    uint8_t getVSize() const {
        return vsize;
    }
    uint16_t getHeight() const {
        return height;
    }
    uint32_t getBlkSize() const {
        return blksize;
    }
    bid_t getRootBid() const {
        return root_bid;
    }
    void setRootBid(bid_t bid) {
        root_bid = bid;
    }
    BTreeBlkHandle* getBhandle() const {
        return bhandle;
    }
    BTreeKVOps* getKVOps() const {
        return kv_ops;
    }
    void setKVOps(BTreeKVOps *_kv_ops) {

        kv_ops = _kv_ops;
    }
    void* getAux() const {
        return aux;
    }
    void setAux(void *_aux) {
        aux = _aux;
    }

private:
    uint8_t ksize;
    uint8_t vsize;
    uint16_t height;
    uint32_t blksize;
    bid_t root_bid;
    BTreeBlkHandle *bhandle;
    BTreeKVOps *kv_ops;
    bnode_flag_t root_flag;
    void *aux;
#ifdef __UTREE
    uint16_t leafsize;
#endif

    // Initialize a new node.
    struct bnode* initNode(void *addr,
                           bnode_flag_t flag,
                           uint16_t level,
                           struct btree_meta *meta);
    /**
     * Get the actual used space of the given node, after new key-value pairs are
     * inserted into the node.
     *
     * @param node B+tree node.
     * @param new_minkey New smallest key in the node if changed.
     * @param key_arr Array of keys to be added.
     * @param value_arr Array of values to be added.
     * @param len Size of the array.
     */
    int getBNodeSize(struct bnode *node,
                     void *new_minkey,
                     void *key_arr,
                     void *value_arr,
                     size_t len);

    // Create a new key-value pair item for internal insertion process.
    struct kv_ins_item* createKVInsItem(void *key, void *value);
    // Free the key-value pair item for insertion.
    void freeKVInsItem(struct kv_ins_item *item);

    /**
     * Check if the given node needs to be split (return false) or not (return true).
     *
     * @param bid Block ID of the node.
     * @param node B+tree node.
     * @param new_minkey New smallest key in the node if changed.
     * @param kv_ins_list List of key-value pairs to be inserted.
     * @param size_out Reference to the actual size of given node.
     */
    bool checkBNodeSize(bid_t bid,
                        struct bnode *node,
                        void* new_minkey,
                        struct list* kv_ins_list,
                        size_t& size_out);

    /**
     * Get the number of new nodes to be created if the given node is split.
     *
     * @param bid Block ID of the node.
     * @param node B+tree node.
     * @param size Actual size of the given node.
     */
    size_t getNSplitNode(bid_t bid, struct bnode *node, size_t size);

    // Internal function for split.
    int splitNode(void *key, struct bnode **node, bid_t *bid, idx_t *idx,
                  int i, struct list *kv_ins_list, size_t nsplitnode,
                  void *k, void *v, int8_t *modified, int8_t *minkey_replace,
                  int8_t *ins);

    // Move a node if the old block is not writable anymore.
    int moveModifiedNode(void *key, struct bnode **node, bid_t *bid,
                         idx_t *idx, int i, struct list *kv_ins_list,
                         void *k, void *v, int8_t *modified, int8_t *minkey_replace,
                         int8_t *ins, int8_t *moved);
};

typedef struct {
    btree_cmp_func *aux;
    BTreeKVOps *kv_ops;
    uint8_t chunksize;
} btree_cmp_args ;

#define BTREE_ITERATOR_NONE 0x00
#define BTREE_ITERATOR_FWD  0x01
#define BTREE_ITERATOR_REV  0x02
#define BTREE_ITERATOR_NONE_MASK  0x03

/**
 * B+tree iterator handle definition.
 */
class BTreeIterator {
public:
    // Default constructor.
    BTreeIterator() :
        btree(nullptr), curkey(nullptr), bid_arr(nullptr), idx_arr(nullptr),
        node_arr(nullptr), addr_arr(nullptr), flags(0x0) { }

    // Constructor with the initial key.
    BTreeIterator(BTree *_btree, void *_initial_key);

    // Destructor.
    ~BTreeIterator();

    // Initialize the iterator with the given initial key.
    btree_result init(BTree *_btree, void *_initial_key);

    // Move cursor to the previous key.
    btree_result prev(void *key_buf, void *value_buf);

    // Move cursor to the next key.
    btree_result next(void *key_buf, void *value_buf);

    BTree* getBTree() const {
        return btree;
    }
    BTreeKVOps* getBTreeKVOps() const {
        return btree->getKVOps();
    }
    void* getBTreeAux() const {
        return btree->getAux();
    }

private:
    BTree *btree;
    void *curkey;
    bid_t *bid_arr;
    idx_t *idx_arr;
    struct bnode **node_arr;
    void **addr_arr;
    uint8_t flags;

    btree_result _prev(void *key_buf, void *value_buf, int depth);
    btree_result _next(void *key_buf, void *value_buf, int depth);

    void flagsSetNone() {
        flags &= ~BTREE_ITERATOR_NONE_MASK;
    }
    bool flagsIsRev() {
        return flags & BTREE_ITERATOR_REV;
    }
    bool flagsIsFwd() {
        return flags & BTREE_ITERATOR_FWD;
    }
    void flagsSetRev() {
        flagsSetNone();
        flags |= BTREE_ITERATOR_REV;
    }
    void flagsSetFwd() {
        flagsSetNone();
        flags |= BTREE_ITERATOR_FWD;
    }
};

//#define _BTREE_HAS_MULTIPLE_BNODES
#ifdef _BTREE_HAS_MULTIPLE_BNODES
struct bnode ** btree_get_bnode_array(void *addr, size_t *nnode_out);
#else
struct bnode * btree_get_bnode(void *addr);
#endif

#ifdef __cplusplus
}
#endif

#endif
