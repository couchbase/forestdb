/* -*- Mode: C++; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2016 Couchbase, Inc
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

#pragma once

#include <map>
#include <list>
#include <unordered_set>
#include <vector>

#include "common.h"
#include "avltree.h"
#include "atomic.h"
#include "list.h"

class Bnode;

/**
 * Basic unit of key-value pair used in Bnode (BsArray) and Btree.
 */
struct BsaItem {
    // Default constructor. Create an empty item.
    BsaItem() :
        key(nullptr), value(nullptr), isValueChildPtr(false),
        keylen(0), valuelen(0),
        idx(0), pos(static_cast<uint32_t>(-1))
    { }

    // Create a {key, binary data value} pair.
    BsaItem( void* _key, size_t _keylen, void* _value, size_t _valuelen ) :
        key(_key), value(_value), isValueChildPtr(false),
        keylen(_keylen), valuelen(_valuelen),
        idx(0), pos(static_cast<uint32_t>(-1))
    { }

    // Create a {key, pointer} pair.
    BsaItem( void* _key, size_t _keylen, void* _child_ptr ) :
        key(_key), value(_child_ptr), isValueChildPtr(true),
        keylen(_keylen), valuelen(8),
        idx(0), pos(static_cast<uint32_t>(-1))
    { }

    // Create an item that only key-field is assigned.
    BsaItem( void* _key, size_t _keylen ) :
        key(_key), value(nullptr), isValueChildPtr(false),
        keylen(_keylen), valuelen(0),
        idx(0), pos(static_cast<uint32_t>(-1))
    { }

    // Return on-disk size of the given key-value pair.
    uint32_t getSize() {
        return sizeof(keylen) + sizeof(valuelen) + keylen + valuelen;
    }

    // Check if given item is empty.
    bool isEmpty() {
        if (!key && pos == static_cast<uint32_t>(-1)) {
            return true;
        }
        return false;
    }

    // Key.
    void *key;
    // Value. Can be a binary data, or pointer to a child node.
    void *value;
    // Flag that indicates if 'value' is pointer or binary data.
    bool isValueChildPtr;
    // Length of key.
    uint16_t keylen;
    // Length of value.
    uint16_t valuelen;
    // Index number of the item.
    uint16_t idx;
    // Memory offset of the item, in a sorted array.
    uint32_t pos;
};

/**
 * Meta data structure for key-value pair in BsArray.
 */
struct BsaKvMeta {
    // Position of key-value pair.
    uint32_t kvPos;
    // Boolean flag indicates if corresponding key-value pair
    // contains the pointer to a dirty inner child node (true),
    // otherwise false.
    bool isPtr;
    // Boolean flag indicates if corresponding key-value pair
    // contains the pointer to a dirty root node of next level child
    // tree (true), otherwise false. Since the pointer to the next root
    // node is treated as a (wrapped) value in B+tree level, 'isPtr'
    // value will not be set to true together.
    bool isDirtyChildTree;
};

enum class BsaItrType {
    // Traverse all items.
    NORMAL,
    // Traverse dirty child B+tree node only (items 'isPtr == true').
    // Due to characteristics of B+tree, dirty child node is
    // pointed to by intermediate node (level>1) only.
    DIRTY_BTREE_NODE_ONLY,
    // In HB+trie mode, traverse the dirty root node of next level
    // tree only (items 'isDirtyChildTree == true')
    // Due to characteristics of B+tree, the root node of next level
    // child tree is pointed to by leaf node (level==1) only.
    DIRTY_CHILD_TREE_ONLY
};

/**
 * Sorted array implementation.
 *
 * Overall structure of 'dataArray':
 *
 * | <--                  arrayCapacity                --> |
 * |      |  <---        kvDataSize      --->  |           |
 * +------+-------+-------+-----------+--------+-----------+
 * | meta |  KV 0 |  KV 1 |    ...    | KV n-1 |   empty   |
 * +------+-------+-------+-----------+--------+-----------+
 *        ^
 *     arrayBaseOffset
 *
 * Note: 'dataArray' contains raw key-value data including meta,
 *       that can be directly written into DB file.
 *       All values in 'dataArray' are encoded in an endian-safe way.
 *
 * kvMeta[i].kvPos: location of KV i, excluding the memory region for 'meta'.
 *                  'kvPos' value starts from zero.
 *   e.g.)
 *   arrayBaseOffset = 15
 *   kvMeta[0].kvPos = 0
 *   kvMeta[1].kvPos = 20
 * then, 'KV 0' is located at dataArray+15,
 * and   'KV 1' is located at dataArray+15+20.
 *
 * kvMeta[i].isPtr: boolean flag that indicates if
 *                  KV i contains pointer (true) or binary data (false).
 *
 */
class BsArray {
public:
    BsArray();
    ~BsArray();

    void setAux(void *_aux) {
        aux = _aux;
    }
    void* getAux() const {
        return aux;
    }
    void* getDataArray() const {
        return dataArray;
    }
    uint32_t getBaseOffset() const {
        return arrayBaseOffset;
    }
    std::vector<BsaKvMeta>& getKvMeta() {
        return kvMeta;
    }

    uint32_t getArrayCapacity() const {
        return arrayCapacity;
    }

    size_t getKvMetaMemConsumption() {
        size_t capacity = kvMeta.capacity();
        return capacity * sizeof(BsaKvMeta);
    }

    uint32_t getArraySize() const {
        return kvDataSize;
    }
    void setArraySize(uint32_t _array_size) {
        kvDataSize = _array_size;
    }
    void setNumElems(uint32_t _num_elems) {
        // resize kvMeta
        kvMeta.resize(_num_elems);
    }
    size_t getNumElems() const {
        return kvMeta.size();
    }

    /**
     * Change 'dataArray' to given buffer.
     *
     * @param new_buffer Pointer to the new buffer.
     * @param capacity Size of the new buffer.
     */
    void setDataArrayBuffer(void *new_buffer, uint32_t capacity) {
        // release existing buffer
        free(dataArray);
        dataArray = new_buffer;
        arrayCapacity = capacity;
    }

    /**
     * Adjust 'arrayBaseOffset' value, and resize 'dataArray' if necessary.
     *
     * @param _new_base New base offset.
     */
    void adjustBaseOffset(uint32_t _new_base);

    /**
     * Get the first key-value pair in the array.
     * If 'mode' is DIRTY_BTREE_NODE_ONLY, return the first key-value pair that
     * contains the pointer to the dirty child node (i.e., 'isPtr' is set).
     * If 'mode' is DIRTY_CHILD_TREE_ONLY, return the first key-value pair that
     * contains the pointer to the dirty child subtree on HB+trie hierarchy (i.e.,
     * 'isDirtyChildTree' is set).
     *
     * @param mode Option for getting key-pointer pair.
     * @return First key-value pair.
     */
    BsaItem first(BsaItrType mode = BsaItrType::NORMAL);

    /**
     * Get the last key-value pair in the array.
     * If 'mode' is DIRTY_BTREE_NODE_ONLY, return the last key-value pair that
     * contains the pointer to the dirty child node (i.e., 'isPtr' is set).
     * If 'mode' is DIRTY_CHILD_TREE_ONLY, return the last key-value pair that
     * contains the pointer to the dirty child subtree on HB+trie hierarchy (i.e.,
     * 'isDirtyChildTree' is set).
     *
     * @param mode Option for getting key-pointer pair.
     * @return Last key-value pair.
     */
    BsaItem last(BsaItrType mode = BsaItrType::NORMAL);

    /**
     * Get the previous key-value pair of the given pair.
     * If 'mode' is DIRTY_BTREE_NODE_ONLY, return the first previous key-value pair
     * that contains the pointer to the dirty child node (i.e., 'isPtr' is set).
     * If 'mode' is DIRTY_CHILD_TREE_ONLY, return the first previous key-value pair
     * that contains the pointer to the dirty child subtree on HB+trie hierarchy
     * (i.e., 'isDirtyChildTree' is set).
     *
     * @param mode Option for getting key-pointer pair.
     * @return Previous key-value pair.
     */
    BsaItem prev(BsaItem& cur, BsaItrType mode = BsaItrType::NORMAL);

    /**
     * Get the next key-value pair of the given pair.
     * If 'mode' is DIRTY_BTREE_NODE_ONLY, return the first next key-value pair that
     * contains the pointer to dirty child node (i.e., 'isPtr' is set).
     * If 'mode' is DIRTY_CHILD_TREE_ONLY, return the first next key-value pair
     * that contains the pointer to dirty child subtree on HB+trie hierarchy (i.e.,
     * 'isDirtyChildTree' is set).
     *
     * @param mode Option for getting key-pointer pair.
     * @return Next key-value pair.
     */
    BsaItem next(BsaItem& cur, BsaItrType mode = BsaItrType::NORMAL);

    /**
     * Find key-value pair for the given key.
     * If 'smaller_key' is set and exact key does not exist, then return
     * the greatest key-value pair that smaller than the given key.
     *
     * @param key Key to find.
     * @param smaler_key Flag to return smaller key.
     * @return Key-value pair found.
     */
    BsaItem find(BsaItem& key, bool smaller_key = false);

    /**
     * Find key-value pair for the given key.
     * If exact key does not exist, then return the greatest key-value
     * pair that smaller than the given key.
     *
     * @param key Key to find.
     * @return Key-value pair found.
     */
    BsaItem findSmallerOrEqual(BsaItem& key);

    /**
     * Find key-value pair for the given key.
     * If exact key does not exist, then return the smallest key-value
     * pair that greater than the given key.
     *
     * @param key Key to find.
     * @return Key-value pair found.
     */
    BsaItem findGreaterOrEqual(BsaItem& key);

    /**
     * Insert a key-value pair into the array.
     *
     * @param item Key-value pair to insert.
     * @return Inserted key-value pair on success,
     *         'NotFound' item on failure.
     */
    BsaItem insert(BsaItem& item);

    /**
     * Remove a key-value pair from the array.
     *
     * @param item Key-value pair to remove.
     * @return Removed key-value pair on success,
     *         'NotFound' item on failure.
     */
    BsaItem remove(BsaItem& item);

    /**
     * Copy a (partial) set of key-value pairs from the source array,
     * and construct 'kvMeta'.
     *
     * @param src_array Source array.
     * @param start_item First key-value pair to be copied.
     * @param end_item Last key-value pair to be copied.
     */
    void copyFromOtherArray(BsArray& src_array,
                            BsaItem& start_item,
                            BsaItem& end_item);

    /**
     * Construct 'kvMeta' array for the current 'dataArray'.
     *
     * @param kv_data_size Key-value pair data size to construct.
     * @param num_elems Number of key-value pairs.
     * @param reset_isptr Flag to reset kvMeta[].isPtr value.
     *        If false, all kvMeta[].isPtr will be set to false.
     */
    void constructKvMetaArray(uint32_t kv_data_size,
                              uint32_t num_elems,
                              bool reset_isptr);

    /**
     * Lessen the allocated memory space for 'dataArray' and 'kvMeta'
     * to fit into the actual array size.
     */
    void fitArrayAndKvMetaCapacity();

private:

    /**
     * Fetch a key-value pair for the given index number.
     *
     * @param idx Index number to fetch.
     * @return Key-value pair.
     */
    BsaItem fetchItem(uint32_t idx);

    /**
     * Write given key-value pair into the given position of the array.
     *
     * @param item Key-value pair to write.
     * @param position Offset where the key-value pair will be written.
     */
    void writeItem(BsaItem item, uint32_t position);

    /**
     * Overwrite or insert given key-value pair at given index in the array.
     *
     * example: overwrite == false
     * idx = 2
     * [2 4 6 8] -> [2 4 _ 6 8]
     * and then insert 'item' into the blank position.
     *
     * example: overwrite == true
     * idx = 2
     * [2 4 6 8] -> [2 4 _ 8]
     * and then overwrite 'item' into the blank position.
     *
     * @param item Key-value pair to write.
     * @param idx Index number where key-value pair will be written or inserted.
     * @param overwrite Flag that indicates if 'item' will be written over
     *        existing item or not.
     */
    BsaItem addToArray(BsaItem item, uint32_t idx, bool overwrite);

    /**
     * Adjust 'dataArray' size if necessary.
     *
     * @param gap Delta value of the array size.
     */
    void adjustArrayCapacity(int gap);

    // Memory segment for array.
    void* dataArray;
    // Auxiliary data (used for custom comparison function).
    void* aux;
    // Data size for key-value pairs only.
    // Does not include the size of meta data (i.e., arrayBaseOffset).
    uint32_t kvDataSize;
    // Base offset of the array
    // (start position of list of key-value pairs).
    uint32_t arrayBaseOffset;
    // Size of memory segment for 'dataArray'.
    uint32_t arrayCapacity;
    // Array for meta data of key-value pairs.
    std::vector<BsaKvMeta> kvMeta;
};


enum class BnodeResult {
    // Succeeded.
    SUCCESS,
    // Key field is not given.
    EMPTY_KEY,
    // Value fiend is not given.
    EMPTY_VALUE,
    // Both pointer to child node and value are assigned.
    // They cannot co-exist for a single key.
    DUPLICATE_VALUE,
    // Key does not exist.
    KEY_NOT_FOUND,
    // Node is already populated.
    NODE_IS_NOT_EMPTY,
    // Buffer is not valid.
    INVALID_BUFFER,
    // Invalid parameters.
    INVALID_ARGS,
    // The same key already exists.
    EXISTING_KEY
};

/**
 * Definition of variable-length key comparison function.
 */
typedef int btree_new_cmp_func(void *key1, size_t keylen1,
                               void *key2, size_t keylen2);

/**
 * Report error on given Bnode.
 *
 * @param bnode Pointer to Bnode.
 * @param error_no ForestDB error number.
 * @param msg Error message.
 */
void logBnodeErr(Bnode *bnode, fdb_status error_no, const char *msg);

class Bnode {
    friend class BnodeIterator;

public:
    Bnode();
    ~Bnode();

    /**
     * Check if given parameters are correct.
     *
     * @param key Key string.
     * @param keylen Length of key.
     * @param value Value string.
     * @param valuelen Length of value.
     * @param ptr Pointer to child B+tree node.
     * @param value_check Flag to check 'value' and 'ptr' or not.
     * @return SUCCESS on success.
     */
    inline BnodeResult inputSanityCheck( void *key,
                                         size_t keylen,
                                         void *value,
                                         size_t valuelen,
                                         Bnode *ptr,
                                         bool value_check = false );

    size_t getNodeSize() const {
        return nodeSize;
    }
    void setNodeSize(uint32_t _node_size) {
        nodeSize = _node_size;
    }

    size_t getMemConsumption() {
        size_t ret = 0;
        ret += sizeof(*this);
        // space for kvArr.dataArray
        ret += kvArr.getArrayCapacity();
        // spcae for kvArr.kvMeta
        ret += kvArr.getKvMetaMemConsumption();
        // space for bidList
        ret += bidList.capacity() * sizeof(bid_t);
        return ret;
    }

    size_t getLevel() const {
        return level;
    }
    void setLevel(size_t _level) {
        level = static_cast<uint16_t>(_level);
    }

    size_t getNentry() const {
        return nentry;
    }
    void setNentry(uint16_t _nentry) {
        nentry = _nentry;
    }

    uint32_t getFlags() const {
        return flags;
    }
    void setFlags(uint32_t _flags) {
        flags = _flags;
    }

    size_t getMetaSize() const {
        return metaSize;
    }

    void* getMeta() const {
        // meta data position is always fixed
        return static_cast<uint8_t*>(kvArr.getDataArray()) +
               Bnode::getDiskSpaceOfEmptyNode();
    }

    uint64_t getRefCount() const {
        return refCount.load();
    }

    uint64_t incRefCount() {
        return ++refCount;
    }

    uint64_t decRefCount() {
        if ( !refCount ) {
            // This function is declared separately so that decRefCount() can still
            // be inlined which is the most common path.
            logBnodeErr(this, FDB_RESULT_READ_FAIL,
                        "ref count is already zero");
            return refCount;
        }
        return --refCount;
    }

    uint64_t getCurOffset() const {
        return curOffset;
    }
    void setCurOffset(uint64_t _offset) {
        curOffset = _offset;
    }

    btree_new_cmp_func *getCmpFunc() const {
        return cmpFunc;
    }
    void setCmpFunc(btree_new_cmp_func *_func) {
        cmpFunc = _func;
        if (cmpFunc) {
            kvArr.setAux(this);
        } else {
            kvArr.setAux(nullptr);
        }
    }

    BsArray& getKvArr() {
        return kvArr;
    }

    void addBidList(bid_t bid) {
        bidList.push_back(bid);
    }
    bid_t getBidFromList(size_t idx) {
        return bidList[idx];
    }
    size_t getBidListSize() const {
        return bidList.size();
    }
    void clearBidList() {
        bidList.clear();
    }

    /**
     * Update meta data section.
     *
     * @param new_meta New meta data.
     * @param meta_size Size of new meta data.
     */
    void setMeta( void* new_meta,
                  size_t meta_size );

    /**
     * Clear meta data section.
     */
    void clearMeta();

    /**
     * Insert a key-value pair into the B+tree node.
     *
     * @param key Key string.
     * @param keylen Length of key.
     * @param value Value string.
     * @param valuelen Length of value.
     * @param child_ptr Pointer to child B+tree node.
     * @param inc_nentry Flag to update internal stats or not.
     * @return SUCCESS on success.
     */
    BnodeResult addKv( void *key,
                       size_t keylen,
                       void *value,
                       size_t valuelen,
                       Bnode *child_ptr,
                       bool inc_nentry );

    /**
     * Find a value corresponding to the given key.
     *
     * @param key Key string.
     * @param keylen Length of key.
     * @param value_out Value string to be returned.
     * @param valuelen_out Length of value to be returned.
     * @param ptr_out Pointer to child B+tree node to be returned.
     * @return SUCCESS on success.
     */
    BnodeResult findKv( void *key,
                        size_t keylen,
                        void*& value_out,
                        size_t& valuelen_out,
                        Bnode*& ptr_out );

    /**
     * Find a key-value pair instance corresponding to the given key.
     *
     * @param key Key string.
     * @param keylen Length of key.
     * @return Key-value pair instance.
     */
    BsaItem findKv( void *key,
                    size_t keylen );

    /**
     * Find a key-value pair instance whose key is smaller than or
     * equal to the given key.
     *
     * @param key Key string.
     * @param keylen Length of key.
     * @param return_smallest Flag that decides the behavior when neither
     *        exact key nor key smaller than the given key exists.
     *        If the flag is true, this function returns the smallest
     *        key in the node, if not, returns NULL.
     * @return Key-value pair instance.
     */
    BsaItem findKvSmallerOrEqual( void *key,
                                  size_t keylen,
                                  bool return_smallest = false );

    /**
     * Find a key-value pair instance whose key is greater than or
     * equal to the given key.
     *
     * @param key Key string.
     * @param keylen Length of key.
     * @param return_greatest If true, return the greater key when given key
     *        is greater than the greatest key, instead of NULL.
     * @return Key-value pair instance.
     */
    BsaItem findKvGreaterOrEqual( void *key,
                                  size_t keylen,
                                  bool return_greatest = false );

    /**
     * Get the smallest key in the node.
     *
     * @param key Key string to be returned.
     * @param keylen Length of key to be returned.
     * @return SUCCESS on success.
     */
    BnodeResult findMinKey( void*& key,
                            size_t& keylen );

    /**
     * Get the largest key in the node.
     *
     * @param key Key string to be returned.
     * @param keylen Length of key to be returned.
     * @return SUCCESS on success.
     */
    BnodeResult findMaxKey( void*& key,
                            size_t& keylen );

    /**
     * Remove a key-value pair.
     *
     * @param keylen Length of key.
     * @param key Key string.
     * @return SUCCESS on success.
     */
    BnodeResult removeKv( void *key,
                          size_t keylen );

    /**
     * Split the node into multiple new nodes.
     *
     * @param nodesize_limit Maximum size that a single node can grow.
     * @param new_nodes Pointer to list that new nodes will be inserted.
     * @return SUCCESS on success.
     */
    BnodeResult splitNode( size_t nodesize_limit,
                           std::list<Bnode *>& new_nodes );

    /**
     * Create a clone of the given node.
     *
     * @return New node created as a result of this function call.
     */
    Bnode * cloneNode();

    /**
     * Convert logical B+tree node structure to raw binary data.
     * To avoid unnecessary memcpy() overhead, it directly returns
     * the buffer address kept in the node. So caller function should not
     * destroy the memory region after use. It will be freed when the
     * node is destroyed.
     *
     * @return Pointer to the memory address of raw binary data.
     */
    void* exportRaw();

    /**
     * Construct logical B+tree node structure from raw binary data.
     * To avoid unnecessary memcpy() overhead, given memory region is
     * kept in the node and the node directly points to the key-value data
     * in the memory region. The memory region is freed when the node is
     * destroyed.
     *
     * @param buf Memory area containing raw data.
     * @param buf_size Size of 'buf'.
     * @return SUCCESS on success.
     */
    BnodeResult importRaw( void *buf,
                           uint32_t buf_size );

    /**
     * Lessen allocated memory space to fit into the actual node size.
     */
    void fitMemSpaceToNodeSize();

    /**
     * For debugging-purpose, print out a list of key-value pairs in the node.
     *
     * @param start_idx Start index number of key-value pair to be printed out.
     * @param num_to_print Number of key-value pairs to be printed out.
     */
    void DBG_printNode(size_t start_idx, size_t num_to_print = 1);

    /**
     * Read raw B+tree node data size from the given buffer.
     *
     * @param buf Memory area containing raw data.
     * @return Size of raw B+tree node data.
     */
    static size_t readNodeSize(void *buf);

    /**
     * Return the disk space of an empty B+tree node.
     *
     * @return Disk space of an empty B+tree node.
     */
    static size_t getDiskSpaceOfEmptyNode() {
        return sizeof(uint32_t) + // nodeSize
               sizeof(uint16_t) + // level
               sizeof(uint16_t) + // nentry
               sizeof(uint32_t) + // flags
               sizeof(uint16_t);  // metaSize
    }

    // list elem for {clean} list
    struct list_elem list_elem;

private:
    /**
     * During split, create a new node and migrate a set of entries from the
     * source node to the new node.
     *
     * @param cur_num_elems Number of entries to be migrated.
     * @param new_nodes List of new nodes created.
     * @param first_kvp First key-value pair to be migrated.
     * @param last_kvp Last key-value pair to be migrated.
     */
    void migrateEntries( size_t cur_num_elems,
                         std::list<Bnode *>& new_nodes,
                         BsaItem first_kvp,
                         BsaItem last_kvp );

    // Disk space of B+tree node.
    uint32_t nodeSize;
    // Flags
    uint32_t flags;
    // Level of B+tree node. When the height of tree is n, the level of root
    // node is n, while that of leaf node is 1.
    uint16_t level;
    // Number of key-value pairs.
    uint16_t nentry;
    // Meta data size.
    uint16_t metaSize;
    // Sorted array containing key-value pairs and meta data.
    BsArray kvArr;
    // Reference counter for the given node. If this value is not zero, the node
    // must not be ejected from the cache.
    std::atomic<uint64_t> refCount;
    // File offset where this node is written. If this node is dirty so that
    // has not been flushed yet, the value is BLK_NOT_FOUND.
    std::atomic<uint64_t> curOffset;
    // List of block IDs where this node is written.
    // Note that blocks cannot be consecutive due to CBR.
    std::vector<bid_t> bidList;
    // Key comparison function. Lexicographical order by default.
    btree_new_cmp_func *cmpFunc;
};



enum class BnodeIteratorResult {
    // Succeeded.
    SUCCESS,
    // No more next/prev entry.
    NO_MORE_ENTRY,
    // Target B+tree node for the iterator is not valid.
    INVALID_NODE
};

class BnodeIterator {
public:
    BnodeIterator(Bnode *_bnode);

    /**
     * Create an iterator with the given start key.
     * At the beginning, iterator points to the smallest key greater
     * than the start key.
     */
    BnodeIterator( Bnode *_bnode,
                   void *start_key,
                   size_t start_keylen );

    ~BnodeIterator() {
    }

    Bnode *getBnode() const {
        return bnode;
    }

    /**
     * Move the cursor to the given key.
     * If exact key does not exist, start with the smallest key greater than
     * the given key.
     *
     * @param key Key string.
     * @param keylen Length of key.
     * @return SUCCESS on success.
     */
    BnodeIteratorResult seekGreaterOrEqual( void *key,
                                            size_t keylen );

    /**
     * Move the cursor to the given key.
     * If exact key does not exist, start with the greatest key smaller than
     * the given key.
     *
     * @param key Key string.
     * @param keylen Length of key.
     * @return SUCCESS on success.
     */
    BnodeIteratorResult seekSmallerOrEqual( void *key,
                                            size_t keylen );

    /**
     * Move the cursor to the first key.
     *
     * @return SUCCESS on success.
     */
    BnodeIteratorResult begin();

    /**
     * Move the cursor to the last key.
     *
     * @return SUCCESS on success.
     */
    BnodeIteratorResult end();

    /**
     * Get key-value pair instance of the current cursor.
     *
     * @return Current key-value pair instance.
     */
    BsaItem getKv() const {
        return curKvp;
    }

    /**
     * Move the cursor to the previous position.
     *
     * @return SUCCESS on success.
     */
    BnodeIteratorResult prev();

    /**
     * Move the cursor to the next position.
     *
     * @return SUCCESS on success.
     */
    BnodeIteratorResult next();

    /**
     * Returns the bnode of this iterator
     * @return the bnode of this iterator
     */
    Bnode *getIteratorBnode() const {
        return bnode;
    }

private:
    // B+tree node to iterate.
    Bnode *bnode;
    // Current key-value pair.
    BsaItem curKvp;
};


