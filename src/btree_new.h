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
#include <vector>

#include "common.h"
#include "avltree.h"
#include "atomic.h"
#include "bnodemgr.h"
#include "bnode.h"

enum class BtreeV2Result {
    // Succeeded.
    SUCCESS,
    // Key does not exist.
    KEY_NOT_FOUND,
    // Tree is empty.
    EMPTY_BTREE,
};

struct BtreeV2Meta {
    BtreeV2Meta() :
        size(0), ctx(nullptr) { }
    BtreeV2Meta(uint32_t _size, void* _ctx) :
        size(_size), ctx(_ctx) { }

    // Size of meta data.
    uint32_t size;
    // Meta data.
    void* ctx;
};

struct BtreeNodeAddr {
    BtreeNodeAddr() :
        offset(BLK_NOT_FOUND),
        isDirty(false),
        isEmpty(true)
    { }

    BtreeNodeAddr( uint64_t _offset, Bnode* _ptr = nullptr ) {
        if (_offset == BLK_NOT_FOUND) {
            if (_ptr) {
                // point to dirty node
                ptr = _ptr;
                isDirty = true;
                isEmpty = false;
            } else {
                // empty pointer
                offset = _offset;
                isDirty = false;
                isEmpty = true;
            }
        } else {
            offset = _offset;
            isDirty = false;
            isEmpty = false;
        }
    }
    BtreeNodeAddr( BsaItem _item ) {
        if ( _item.value ) {
            if ( _item.isValueChildPtr ) {
                // pointer value
                ptr = static_cast<Bnode*>(_item.value);
                isDirty = true;
                isEmpty = false;
            } else {
                // binary data value
                offset = *(reinterpret_cast<uint64_t*>(_item.value));
                offset = _endian_decode(offset);
                isDirty = false;
                isEmpty = false;
            }
        } else {
            // empty pointer
            offset = BLK_NOT_FOUND;
            isDirty = false;
            isEmpty = true;
        }
    }

    bool operator==(const BtreeNodeAddr &other) const {
        return (other.isDirty == isDirty &&
                other.isEmpty == isEmpty &&
                other.offset == offset);
    }
    bool operator!=(const BtreeNodeAddr &other) const {
        return !operator==(other);
    }

    union {
        // Offset of node (if clean).
        uint64_t offset;
        // Pointer to node (if dirty).
        Bnode *ptr;
    };
    // Flag that indicates if target node is dirty or not.
    bool isDirty;
    // Flag that indicates if target node is empty or not.
    bool isEmpty;
};

/**
 * B+tree key-value pair structure definition.
 */
struct BtreeKvPair {
    BtreeKvPair() { }
    BtreeKvPair( void *_key,   uint32_t _keylen,
                 void *_value, uint32_t _valuelen ) :
        key(_key), value(_value), keylen(_keylen), valuelen(_valuelen) { }
    BtreeKvPair( const BsaItem &kv ) :
        key(kv.key), value(kv.value), keylen(kv.keylen), valuelen(kv.valuelen){}

    // Key.
    void *key;
    // Value.
    void *value;
    // Length of key.
    uint32_t keylen;
    // Length of value.
    uint32_t valuelen;
};

/**
 * B+tree variable-length key definition.
 */
struct BtreeKey {
    BtreeKey() { }
    BtreeKey( void *_data, uint64_t _len ) :
        data(_data), length(_len)
    { }
    BtreeKey( BsaItem _item ) :
        data(_item.key), length(_item.keylen)
    { }

    // Data.
    void *data;
    // Length of data.
    uint32_t length;
};

struct NodeActionItem;

class BtreeV2 {
    friend class BtreeIteratorV2;
public:
    BtreeV2();

    ~BtreeV2();

    void setBMgr(BnodeMgr *_bnode_mgr) {
        bMgr = _bnode_mgr;
    }

    void setCmpFunc(btree_new_cmp_func *_func) {
        cmpFunc = _func;
    }
    btree_new_cmp_func* getCmpFunc() const {
        return cmpFunc;
    }

    uint64_t getNentry() const {
        return nentry;
    }
    uint16_t getHeight() const {
        return height;
    }
    uint64_t getRootOffset() const {
        return rootAddr.offset;
    }
    BtreeNodeAddr getRootAddr() const {
        return rootAddr;
    }

    /**
     * Initialize B+tree.
     */
    BtreeV2Result init();

    /**
     * Load existing B+tree for the given root node offset or pointer.
     *
     * @param root_addr Offset (clean) or pointer (dirty) of the root node.
     * @return SUCCESS on success.
     */
    BtreeV2Result initFromAddr( BtreeNodeAddr root_addr );

    /**
     * Update the meta data of B+tree. Given meta data is stored in the
     * meta data section in the root node.
     *
     * @param meta New meta data.
     * @return SUCCESS on success.
     */
    BtreeV2Result updateMeta( BtreeV2Meta meta );

    /**
     * Get the meta data size of B+tree from the root node.
     *
     * @return Meta data size.
     */
    uint32_t getMetaSize();

    /**
     * Read the meta data of B+tree from the root node.
     *
     * @param meta Reference to meta data to be retrned.
     * @return SUCCESS on success.
     */
    BtreeV2Result readMeta( BtreeV2Meta& meta );

    /**
     * Insert a set of key-value pairs into the tree.
     * Note that all pairs MUST be sorted in a key order.
     *
     * @param kv_list List of key-value pairs to insert.
     * @return SUCCESS on success.
     */
    BtreeV2Result insertMulti( std::vector<BtreeKvPair>& kv_list );

    /**
     * Insert a single key-value pair into the tree.
     *
     * @param kv Key-value pair to insert.
     * @return SUCCESS on success.
     */
    BtreeV2Result insert( BtreeKvPair kv );

    /**
     * Remove a set of key-value pairs from the tree.
     * Note that all pairs MUST be sorted in a key order.
     *
     * @param kv_list List of key-value pairs to remove.
     * @return SUCCESS on success.
     */
    BtreeV2Result removeMulti( std::vector<BtreeKvPair>& kv_list );

    /**
     * Remove a single key-value pair from the tree.
     *
     * @param kv Key-value pair to remove.
     * @return SUCCESS on success.
     */
    BtreeV2Result remove( BtreeKvPair kv );

    /**
     * Get value for the given key.
     *
     * @param kv Key-value pair to find. Value field will be assigned as a result
     *        of this API call.
     * @param allocate_memory Flag that enables allocation of memory for value.
     *        If true, this function will allocate a new memory for 'value_out',
     *        and caller function should free it after use.
     *        If false, caller function should pass existing memory region
     *        that value will be copied.
     * @return SUCCESS on success.
     */
    BtreeV2Result find( BtreeKvPair& kv,
                        bool allocate_memory = false );

    /**
     * Get key-value pair whose key is smaller than or equal to the given key.
     *
     * @param kv Key-value pair to find. Both key and value field will be
     *        assigned as a result of this API call.
     * @param allocate_memory If true, new memory for key and value will be
     *        allocated.
     * @return SUCCESS on success.
     */
    BtreeV2Result findSmallerOrEqual(BtreeKvPair& kv,
                                     bool allocate_memory = false);

    /**
     * Get key-value pair whose key is greater than or equal to the given key.
     *
     * @param kv Key-value pair to find. Both key and value field will be
     *        assigned as a result of this API call.
     * @param allocate_memory If true, new memory for key and value will be
     *        allocated.
     * @return SUCCESS on success.
     */
    BtreeV2Result findGreaterOrEqual(BtreeKvPair& kv,
                                     bool allocate_memory = false);

    /**
     * Assign offsets for all currently present dirty nodes.
     * Note that dirty nodes are referenced by pointer (i.e., memory address)
     * by parent nodes. Once their offsets are finalized, corresponding entries
     * in their parent nodes need to replace their memory pointers with offsets.
     * And those nodes are treated as clean since then.
     *
     * @param visit_child_tree If true, visit child sub-tree on HB+trie
     *        hiearachy as well.
     * @return SUCCESS on success.
     */
    BtreeV2Result writeDirtyNodes(bool visit_child_tree = false);

    /**
     * Convert given value to offset.
     *
     * @param value Pointer to value.
     * @return Offset.
     */
    static uint64_t value2offset( void* value ) {
        if (value) {
            uint64_t offset = *(reinterpret_cast<uint64_t*>(value));
            offset = _endian_decode(offset);
            return offset;
        } else {
            return BLK_NOT_FOUND;
        }
    }

    /**
     * Convert value in the given key-value pair instance to offset.
     *
     * @param kvp Key-value pair instance.
     * @return Offset.
     */
    static uint64_t value2offset( BsaItem kvp ) {
        if (!kvp.isValueChildPtr) {
            // binary data
            return value2offset(kvp.value);
        }
        // otherwise: pointer
        return BLK_NOT_FOUND;
    }

private:
    enum class FindOption {
        // exact match (default).
        EQUAL,
        // return greatest key smaller than or equal to the query.
        SMALLER_OR_EQUAL,
        // return smallest key greater than or equal to the query.
        GREATER_OR_EQUAL
    };


    /**
     * Get Bnode instance for the root node.
     * If the root node is dirty, directly return the existing pointer.
     * If clean, read the node using the offset.
     *
     * @return Bnode instance.
     */
    Bnode* getRootNode();

    /**
     * Get limit of node size for the given level (n: root node, 1: leaf node).
     *
     * @param level Level of node.
     * @return Limit of node size.
     */
    size_t getNodeSizeLimit( size_t level );

    /**
     * Execute action items that are returned as results of child node modification.
     *
     * @param node Node that will execute action items.
     * @param actions List of action items.
     */
    void doActionItems( Bnode *node,
                        std::list<NodeActionItem *>& actions );

    /**
     * Create a new root node, and make the current root node as a child of the
     * new root node. It will increase the height of tree by 1.
     * This function is triggered by the split of the current root node.
     *
     * @param actions List of action items for the new root node.
     */
    void growHeight( std::list<NodeActionItem*>& actions );

    /**
     * Get rid of the current root node, and make its (unique) child node as
     * a new root node. It will decrease the height of tree by 1.
     * This function is triggered when the current root node has only one child.
     */
    void shrinkHeight();

    /**
     * Internal recursive function for find operation.
     *
     * @param kv Key-value pair to find. Value field will be assigned as a result
     *        of this API call.
     * @param node_addr File offset (clean) or pointer (dirty) to the current node.
     * @param allocate_memory Flag for memory allocation.
     * @return SUCCESS on success.
     */
    BtreeV2Result _find( BtreeKvPair& kv,
                         BtreeNodeAddr node_addr,
                         bool allocate_memory,
                         FindOption opt );

    /**
     * Internal recursive function for insert operation.
     *
     * @param kv_list List of key-value pairs to insert.
     * @param parent_node Pointer to parent node.
     * @param ref_key Key that parent node points to the current node.
     * @param node_addr File offset (clean) or pointer (dirty) to the current node.
     * @param start_idx Starting index number of keys, values, .. arrays, that
     *        the current node needs to cover.
     * @param end_idx Last index number of keys, values, .. arrays, that
     *        the current node needs to cover.
     * @param parent_actions List of action items that the parent node should do
     *        as a result of this function call.
     * @return SUCCESS on success.
     */
    BtreeV2Result _insert( std::vector<BtreeKvPair>& kv_list,
                           Bnode *parent_node,
                           BtreeKey ref_key,
                           BtreeNodeAddr node_addr,
                           size_t start_idx,
                           size_t end_idx,
                           std::list<NodeActionItem*>& parent_actions );

    /**
     * Internal recursive function for remove operation.
     *
     * @param kv_list List of key-value pairs to remove.
     * @param parent_node Pointer to parent node.
     * @param ref_key Key that parent node points to the current node.
     * @param node_addr File offset (clean) or pointer (dirty) to the current node.
     * @param start_idx Starting index number of keys and keylens arrays, that
     *        the current node needs to cover.
     * @param end_idx Last index number of keys and keylens arrays, that
     *        the current node needs to cover.
     * @param parent_actions List of action items that the parent node should do
     *        as a result of this function call.
     * @return SUCCESS on success.
     */
    BtreeV2Result _remove( std::vector<BtreeKvPair>& kv_list,
                           Bnode *parent_node,
                           BtreeKey ref_key,
                           BtreeNodeAddr node_addr,
                           size_t start_idx,
                           size_t end_idx,
                           std::list<NodeActionItem*>& parent_actions );

    /**
     * Internal recursive function for writeDirtyNodes operation.
     *
     * @param cur_node Pointer to the current node.
     * @param visit_child_tree If true, visit child sub-tree on HB+trie
     *        hiearachy as well.
     * @return SUCCESS on success.
     */
    BtreeV2Result _writeDirtyNodes(Bnode *cur_node,
                                   bool visit_child_tree);

    // Bnode manager instance.
    BnodeMgr *bMgr;
    // Height of tree.
    uint16_t height;
    // File offset (clean) or pointer (dirty) to the root node.
    BtreeNodeAddr rootAddr;
    // Number of entries in the tree.
    uint64_t nentry;
    // Custom comparison function (nullptr if not assigned).
    btree_new_cmp_func *cmpFunc;
};

class BtreeIteratorV2 {
public:
    BtreeIteratorV2(BtreeV2 *_btree);

    /**
     * Create an iterator with the given start key.
     * At the beginning, iterator points to the smallest key greater
     * than or equal to the start key.
     */
    BtreeIteratorV2(BtreeV2 *_btree,
                    void *start_key,
                    size_t start_keylen );

    ~BtreeIteratorV2();

    /**
     * Move the cursor to the given key.
     * If exact key does not exist, start with the smallest key greater than
     * the given key.
     *
     * @param key Key string.
     * @param keylen Length of key.
     * @return SUCCESS on success.
     */
    BnodeIteratorResult seekGreaterOrEqualBT(void *key,
                                             size_t keylen);

    /**
     * Move the cursor to the given key.
     * If exact key does not exist, start with the greatest key smaller than
     * the given key.
     *
     * @param key Key string.
     * @param keylen Length of key.
     * @return SUCCESS on success.
     */
    BnodeIteratorResult seekSmallerOrEqualBT(void *key,
                                             size_t keylen);

    /**
     * Move the cursor to the first key.
     *
     * @return SUCCESS on success.
     */
    BnodeIteratorResult beginBT();

    /**
     * Move the cursor to the last key.
     *
     * @return SUCCESS on success.
     */
    BnodeIteratorResult endBT();

    /**
     * Get key-value pair instance of the current cursor.
     *
     * @return Pointer to the current key-value pair instance.
     */
    BtreeKvPair getKvBT();

    /**
     * Move the cursor to the previous position.
     *
     * @return SUCCESS on success.
     */
    BnodeIteratorResult prevBT();

    /**
     * Move the cursor to the next position.
     *
     * @return SUCCESS on success.
     */
    BnodeIteratorResult nextBT();

    /**
     * Returns the Btree of this iterator.
     * @return btree of iterator.
     */
    BtreeV2 *getBtree() const {
        return btree;
    }

private:

    // B+tree node to iterate.
    BtreeV2 *btree;
    /**
     *     BtreeV2          BnodeIterators     BtreeV2           BnodeIterators
     *     [root] <----------bnodeItrs[1]      [root] <----------bnodeItrs[1]
     *      /  \                      | |       /  \                      | |
     *     /    \                     | |      /    \                     | |
     * [leafA] [leafB]   /---bnodeItrs[0]   [leafA] [leafB]<-----bnodeItrs[0]
     *   ^               |
     *   |_______________/
     * (bnodeItrs at index 0 pointed at leafA) (Same bnodeItrs[0] now at leafB)
     */
    // Cursors inside Bnode at each level
    BnodeIterator *bnodeItrs;
    // Result of last iterator movement. This is needed since getBT() should
    // fail if nextBT(), prevBT() etc fail.
    BnodeIteratorResult lastResult;

    /**
     * Recursively descend from root to leaf to expected key as in diagram above
     * @param node_offset - disk offset where bnode is located
     * @param key - input key to match with a smaller or equal key in Btree
     * @param keylen - length of input key to match
     * @return BnodeIteratorResult::SUCCESS or appropriate error on failure
     */
    BnodeIteratorResult seekSmallerOrEqualRecursiveBT(uint64_t node_offset,
                                                      void *key,
                                                      size_t keylen);
    /**
     * Recursively descend from root to leaf to expected key as in diagram above
     * @param node_offset - disk offset where bnode is located
     * @param key - input key to match with a greater or equal key in Btree
     * @param keylen - length of input key to match
     * @return BnodeIteratorResult::SUCCESS or appropriate error on failure
     */
    BnodeIteratorResult seekGreaterOrEqualRecursiveBT(uint64_t node_offset,
                                                      void *key,
                                                      size_t keylen);
    /**
     * Recursively descend from root to leaf to smallest key as in diagram above
     * @param node_offset - disk offset where bnode is located
     * @return BnodeIteratorResult::SUCCESS or appropriate error on failure
     */
    BnodeIteratorResult beginRecursiveBT(uint64_t node_offset);
    /**
     * Recursively descend from root to leaf to largest key as in diagram above
     * @param node_offset - disk offset where bnode is located
     * @return BnodeIteratorResult::SUCCESS or appropriate error on failure
     */
    BnodeIteratorResult endRecursiveBT(uint64_t node_offset);
    /**
     * Recursively iterate up and or down the Tree to previous key in Btree
     * @param level - starting level to iterate
     * @return BnodeIteratorResult::SUCCESS or appropriate error on failure
     */
    BnodeIteratorResult prevRecursiveBT(uint16_t level);
    /**
     * Recursively iterate up and or down the Tree to next key in Btree
     * @param level - starting level to iterate
     * @return BnodeIteratorResult::SUCCESS or appropriate error on failure
     */
    BnodeIteratorResult nextRecursiveBT(uint16_t level);

    /**
     * Read a B+Tree node if and only if it wasn't already read before
     * If reading an unseen Bnode, release reference on the old bnode
     * Cache the newly read bnode into the btreeItrs at its level.
     * @param node - Node at given node_offset, may be cached or read afresh
     * @param node_offset - Disk offset to read the bnode from
     * @return BnodeIteratorResult::SUCCESS or BnodeIteratorResult::INVALID_NODE
     */
    BnodeIteratorResult fetchBnode(Bnode * &node, uint64_t node_offset);
};
