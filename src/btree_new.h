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
    // Size of meta data.
    uint32_t size;
    // Meta data.
    void* ctx;
};

struct BtreeNodeAddr {
    BtreeNodeAddr( uint64_t _offset, Bnode* _ptr ) {
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
        key(_key), value(_value), keylen(_keylen), valuelen(_valuelen)
    { }

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
public:
    BtreeV2();

    ~BtreeV2();

    void setBMgr(BnodeMgr *_bnode_mgr) {
        bMgr = _bnode_mgr;
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

    /**
     * Initialize B+tree.
     */
    BtreeV2Result init();

    /**
     * Load existing B+tree for the given root node offset.
     *
     * @param root_offset Offset of the root node.
     * @return SUCCESS on success.
     */
    BtreeV2Result initFromOffset( uint64_t root_offset );

    /**
     * Update the meta data of B+tree. Given meta data is stored in the
     * meta data section in the root node.
     *
     * @param meta New meta data.
     * @return SUCCESS on success.
     */
    BtreeV2Result updateMeta( BtreeV2Meta meta );

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
     * Assign offsets for all currently present dirty nodes.
     * Note that dirty nodes are referenced by pointer (i.e., memory address)
     * by parent nodes. Once their offsets are finalized, corresponding entries
     * in their parent nodes need to replace their memory pointers with offsets.
     * And those nodes are treated as clean since then.
     *
     * @return SUCCESS on success.
     */
    BtreeV2Result writeDirtyNodes();

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
    // Bnode manager instance.
    BnodeMgr *bMgr;
    // Height of tree.
    uint16_t height;
    // File offset (clean) or pointer (dirty) to the root node.
    BtreeNodeAddr rootAddr;
    // Number of entries in the tree.
    uint64_t nentry;

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
                         bool allocate_memory );

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
     * @return SUCCESS on success.
     */
    BtreeV2Result _writeDirtyNodes( Bnode *cur_node );

};

