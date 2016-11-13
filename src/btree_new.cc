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

#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "libforestdb/forestdb.h"
#include "fdb_engine.h"
#include "fdb_internal.h"
#include "internal_types.h"
#include "btree_new.h"

/**
 * Action type for NodeActionItem structure.
 */
enum class NodeActionType {
    // Add a new key-value pair (or update the value of an existing key).
    ADD,
    // Remove an existing key-value pair.
    REMOVE,
    // Replace an existing key with a new key, preserving its value.
    REPLACE_KEY,
};

/**
 * Definition of action item for B+tree node.
 *
 * During the recursive modification of append-only B+tree from the
 * leaf node to the root node, updates of a child node incur some
 * changes of its parent node. Those changes are defined as instances
 * of NodeActionItem structure.
 */
struct NodeActionItem {
    NodeActionItem() :
        type(NodeActionType::ADD),
        key(nullptr),
        key_aux(nullptr),
        value(nullptr),
        child_ptr(nullptr),
        keylen(0),
        keylen_aux(0),
        valuelen(0)
    { }

    ~NodeActionItem() {
        free(key);
        free(key_aux);
        free(value);
    }

    /**
     * Note: Key and value do not have their own memory, but point to
     *       existing memory in sorted array, thus we need to allocate a
     *       separate memory blobs for each action items, since
     *       sorted array may change during performing action items.
     */

    /**
     * Set current action item to REPLACE_KEY.
     *
     * @param old_key Existing key to be replaced.
     * @param old_keylen Length of existing key.
     * @param new_key New key.
     * @param new_keylen Length of new key.
     */
    void setReplaceKey( void *old_key, size_t old_keylen,
                        void *new_key, size_t new_keylen ) {
        type = NodeActionType::REPLACE_KEY;

        key = malloc(old_keylen);
        memcpy(key, old_key, old_keylen);
        keylen = old_keylen;

        key_aux = malloc(new_keylen);
        memcpy(key_aux, new_key, new_keylen);
        keylen_aux = new_keylen;

        value = child_ptr = nullptr;
        valuelen = 0;
    }

    /**
     * Set current action item to ADD.
     *
     * @param _key Key to be added or updated.
     * @param _keylen Length of key.
     * @param _value Value to be added or updated.
     * @param _valuelen Length of value.
     * @param _child_ptr Pointer to child node.
     *        Used when the key points to a dirty child node.
     */
    void setAddKey( void *_key, size_t _keylen,
                    void *_value, size_t _valuelen, Bnode* _child_ptr ) {
        type = NodeActionType::ADD;

        key = malloc(_keylen);
        memcpy(key, _key, _keylen);
        keylen = _keylen;
        key_aux = nullptr;
        keylen_aux = 0;

        if (_value) {
            value = malloc(_valuelen);
            memcpy(value, _value, _valuelen);
            valuelen = _valuelen;
        } else {
            value = nullptr;
            valuelen = 0;
        }
        child_ptr = _child_ptr;
    }

    /**
     * Set current action item to REMOVE.
     *
     * @param _key Key to be removed.
     * @param _keylen Length of key.
     */
    void setRemoveKey( void *_key, size_t _keylen ) {
        type = NodeActionType::REMOVE;
        key = malloc(_keylen);
        memcpy(key, _key, _keylen);
        keylen = _keylen;
        key_aux = nullptr;
        keylen_aux = 0;
        value = nullptr;
        valuelen = 0;
        child_ptr = nullptr;
    }

    // Action type.
    NodeActionType type;
    // Pointer to key.
    void *key;
    // Pointer to auxiliary key (for REPLACE_KEY type).
    void *key_aux;
    // Pointer to value.
    void *value;
    // Pointer to dirty child node.
    Bnode *child_ptr;
    // Length of key.
    size_t keylen;
    // Length of auxiliary key.
    size_t keylen_aux;
    // Length of value.
    size_t valuelen;
};


BtreeV2::BtreeV2() :
    rootAddr(BLK_NOT_FOUND, nullptr)
{
    init();
}

BtreeV2::~BtreeV2() {
}

BtreeV2Result BtreeV2::init()
{
    bMgr = nullptr;
    rootAddr = BtreeNodeAddr(BLK_NOT_FOUND, nullptr);
    nentry = 0;
    height = 1;

    return BtreeV2Result::SUCCESS;
}

BtreeV2Result BtreeV2::initFromAddr(BtreeNodeAddr root_addr)
{
    if (root_addr.isEmpty) {
        return init();
    }

    rootAddr = root_addr;
    if (!rootAddr.isDirty) {
        // clean root node
        Bnode *root = bMgr->readNode(rootAddr.offset);
        height = root->getLevel();
        // TODO: reading / storing 'nentry' from / to the root node .
        bMgr->releaseCleanNode(root);
        return BtreeV2Result::SUCCESS;
    } else {
        // dirty root node
        height = rootAddr.ptr->getLevel();
        return BtreeV2Result::SUCCESS;
    }
}

size_t BtreeV2::getNodeSizeLimit( size_t level )
{
    // TODO: make it configurable.
    // Maybe we can set larger node size limit for higher level.
    // e.g.) level 1: 1024
    //       level 2: 4096
    //       level 3: 8192
    //       ...
    // It will lessen the overall tree height,
    // although leaf node size becomes smaller.
    if ( level == 1 ) {
        return 1024;
    } else {
        return 4096;
    }
}

BtreeV2Result BtreeV2::updateMeta( BtreeV2Meta meta )
{
    Bnode *node;

    if ( rootAddr.isEmpty ) {
        // It means that B+tree has not been populated yet.
        // Allocate the first root node.
        node = new Bnode();
        bMgr->addDirtyNode( node );
    } else {
        if ( rootAddr.isDirty ) {
            // Dirty node .. use it as is
            node = rootAddr.ptr;
        } else {
            // Clean node .. read from file,
            Bnode *clean_node = bMgr->readNode( rootAddr.offset );

            // And make a new writable dirty root node.
            node = bMgr->getMutableNodeFromClean(clean_node);

        }
    }

    rootAddr = BtreeNodeAddr(BLK_NOT_FOUND, node);
    node->setMeta(meta.ctx, meta.size);

    return BtreeV2Result::SUCCESS;
}

Bnode* BtreeV2::getRootNode()
{
    if ( rootAddr.isDirty ) {
        // dirty node .. use the pointer.
        return rootAddr.ptr;
    } else {
        // clean node .. read from file.
        return bMgr->readNode( rootAddr.offset );
    }
}

uint32_t BtreeV2::getMetaSize()
{

    Bnode *node;
    uint32_t ret = 0;

    if ( rootAddr.isEmpty ) {
        // B+tree has not been populated yet.
        return ret;
    }

    node = getRootNode();
    ret = node->getMetaSize();
    if ( !rootAddr.isDirty ) {
        bMgr->releaseCleanNode(node);
    }

    return ret;
}

BtreeV2Result BtreeV2::readMeta( BtreeV2Meta& meta )
{
    Bnode *node;

    if ( rootAddr.isEmpty ) {
        // B+tree has not been populated yet.
        return BtreeV2Result::EMPTY_BTREE;
    }

    node = getRootNode();
    meta.size = node->getMetaSize();
    memcpy(meta.ctx, node->getMeta(), meta.size);
    if ( !rootAddr.isDirty ) {
        bMgr->releaseCleanNode(node);
    }

    return BtreeV2Result::SUCCESS;
}

BtreeV2Result BtreeV2::insertMulti( std::vector<BtreeKvPair>& kv_list )
{
    BtreeV2Result br = BtreeV2Result::SUCCESS;
    std::list<NodeActionItem *> parent_actions;
    BtreeNodeAddr addr = rootAddr;
    BtreeKey empty_key(nullptr, 0);

    br = _insert( kv_list, nullptr, empty_key, addr,
                  0, kv_list.size() - 1, parent_actions );

    if ( parent_actions.size() ) {
        // need to increase the height.
        growHeight( parent_actions );
    }

    return br;
}

BtreeV2Result BtreeV2::insert( BtreeKvPair kv )
{
    std::vector<BtreeKvPair> kv_list(1, kv);

    return insertMulti( kv_list );
}

BtreeV2Result BtreeV2::_insert( std::vector<BtreeKvPair>& kv_list,
                                Bnode *parent_node,
                                BtreeKey ref_key,
                                BtreeNodeAddr node_addr,
                                size_t start_idx,
                                size_t end_idx,
                                std::list<NodeActionItem*>& parent_actions )
{
    // 1) fetch the node from offset (clean) or ptr (dirty).
    Bnode *node = nullptr;
    NodeActionItem *na_item = nullptr;
    void *min_key = nullptr;
    size_t min_keylen = 0;

    if ( node_addr.isEmpty ) {
        // It means that B+tree has not been populated yet.
        // Allocate the first root node.
        node = new Bnode();
        bMgr->addDirtyNode( node );
    } else {
        if ( node_addr.isDirty ) {
            // Dirty node .. use it as is
            node = node_addr.ptr;
        } else {
            // Clean node .. read from file,
            Bnode *clean_node = bMgr->readNode( node_addr.offset );

            // And make a new writable dirty node.
            node = bMgr->getMutableNodeFromClean(clean_node);

            if (parent_node) {
                // Replace value in the parent node with
                // pointer (to the new dirty node).
                na_item = new NodeActionItem();
                na_item->setAddKey(ref_key.data, ref_key.length, nullptr, 0, node);
                parent_actions.push_back(na_item);
            }
        }
    }

    // Now, 'node' is a writable dirty node.

    size_t i;
    if ( node->getLevel() > 1 ) {
        // 2) if intermediate node:
        //    recursively call this function for each child node.
        BsaItem kvp, kvp_prev;
        size_t last_idx = start_idx;
        std::list<NodeActionItem*> local_actions;

        // Call _insert() function for the proper range of key-value pairs
        //
        // Example)
        // keys in the current node: {10, 20, 30, 40, 50}
        // key array (kv_list): {5, 11, 12, 30, 31, 32, 45}
        //
        // In this case, we call
        // _insert( child node for '10' ) for kv_list[0] ~ kv_list[2],
        // _insert( child node for '30' ) for kv_list[3] ~ kv_list[5], and
        // _insert( child node for '40' ) for kv_list[6].

        for (i=start_idx; i<=end_idx; ++i) {
            kvp = node->findKvSmallerOrEqual(kv_list[i].key, kv_list[i].keylen, true);
            if (i == start_idx) {
                // skip the first iteration to assign 'kvp_prev'.
            } else if (kvp_prev.idx != kvp.idx) {
                // call _insert() for last_idx ~ i-1
                BtreeNodeAddr next_addr( kvp_prev );
                BtreeKey next_key( kvp_prev );

                _insert( kv_list, node, next_key, next_addr,
                         last_idx, i-1, local_actions );

                last_idx = i;
            }
            kvp_prev = kvp;
        }

        // finally call _insert() for last_idx ~ end_idx
        BtreeNodeAddr next_addr( kvp );
        BtreeKey next_key( kvp );

        _insert( kv_list, node, next_key, next_addr,
                 last_idx, end_idx, local_actions );

        // execute the local action items
        if ( local_actions.size() ) {
            doActionItems(node, local_actions);
        }

    } else {
        // 3) if leaf node:
        //    insert KV pairs of the given range.
        size_t prev_nentry;
        for (i=start_idx; i<=end_idx; ++i) {
            prev_nentry = node->getNentry();
            node->addKv( kv_list[i].key, kv_list[i].keylen,
                         kv_list[i].value, kv_list[i].valuelen,
                         nullptr, true );

            if (prev_nentry < node->getNentry()) {
                // it means that a new key is inserted.
                nentry++;
            }
        }
    }

    // 4) split if necessary
    std::list<Bnode*> new_nodes;
    size_t nodesize_limit = getNodeSizeLimit(node->getLevel());
    if (node->getNodeSize() > nodesize_limit) {
        node->splitNode(nodesize_limit, new_nodes);
    }

    // 5) add 'parent action' for the parent node.

    // a) check if smallest key in the node has been changed:
    //    => change the corresponding key (i.e., ref_key) in the parent node.
    node->findMinKey(min_key, min_keylen);
    if ( parent_node &&
         ( ref_key.length != min_keylen ||
           memcmp(ref_key.data, min_key, ref_key.length) ) ) {
        // The smallest key of the current node has been changed.
        // Which means that the reference key in the parent node needs to be
        // changed as well.
        na_item = new NodeActionItem();
        na_item->setReplaceKey(ref_key.data, ref_key.length, min_key, min_keylen);
        parent_actions.push_back(na_item);
    }

    // b) if split happened:
    //    => add new keys (for the new nodes) into the parent node.
    //    => and also register new nodes to BnodeManager.
    if ( new_nodes.size() ) {
        Bnode *cur_node;
        for (auto &entry: new_nodes) {
            cur_node = entry;
            if (cur_node != node) {
                bMgr->addDirtyNode(cur_node);
            }

            // Get the smallest key and add (or update) {min_key, ptr} pair
            // into the parent node.
            cur_node->findMinKey(min_key, min_keylen);
            na_item = new NodeActionItem();
            na_item->setAddKey(min_key, min_keylen, nullptr, 0, cur_node);
            parent_actions.push_back(na_item);
        }

        // do the same thing for the current node
        node->findMinKey(min_key, min_keylen);
        na_item = new NodeActionItem();
        na_item->setAddKey(min_key, min_keylen, nullptr, 0, node);
        parent_actions.push_back(na_item);
    }

    // if root node, adapt B+tree info
    if ( node->getLevel() == height ) {
        rootAddr = BtreeNodeAddr(BLK_NOT_FOUND, node);
    }

    return BtreeV2Result::SUCCESS;
}

BtreeV2Result BtreeV2::removeMulti( std::vector<BtreeKvPair>& kv_list )
{
    BtreeV2Result br = BtreeV2Result::SUCCESS;
    std::list<NodeActionItem *> parent_actions;
    BtreeNodeAddr node_addr = rootAddr;
    BtreeKey empty_key(nullptr, 0);

    br = _remove( kv_list, nullptr, empty_key, node_addr,
                  0, kv_list.size() - 1, parent_actions );

    if ( rootAddr.isDirty &&
         rootAddr.ptr->getNentry() == 1 && height >= 2) {
        // The root node contains only one entry.
        // We need to decrease the height (only when height >= 2).
        shrinkHeight();
    }

    return br;
}

BtreeV2Result BtreeV2::remove( BtreeKvPair kv )
{
    std::vector<BtreeKvPair> kv_list(1, kv);

    return removeMulti(kv_list);
}

BtreeV2Result BtreeV2::_remove( std::vector<BtreeKvPair>& kv_list,
                                Bnode *parent_node,
                                BtreeKey ref_key,
                                BtreeNodeAddr node_addr,
                                size_t start_idx,
                                size_t end_idx,
                                std::list<NodeActionItem*>& parent_actions )
{
    // 1) fetch the node from offset (clean) or ptr (dirty).
    Bnode *node = nullptr;
    NodeActionItem *na_item = nullptr;
    void *min_key = nullptr;
    size_t min_keylen = 0;

    if ( node_addr.isEmpty ) {
        // It means that B+tree has not been populated yet,
        // and there is no entry to be removed.
        return BtreeV2Result::KEY_NOT_FOUND;
    } else {
        if ( node_addr.isDirty ) {
            // Dirty node .. use it as is
            node = node_addr.ptr;
        } else {
            // Clean node .. read from file,
            Bnode *clean_node = bMgr->readNode( node_addr.offset );

            // And make a new writable dirty node.
            node = bMgr->getMutableNodeFromClean(clean_node);

            if (parent_node) {
                // Replace value in the parent node with
                // pointer (to the new dirty node).
                na_item = new NodeActionItem();
                na_item->setAddKey(ref_key.data, ref_key.length, nullptr, 0, node);
                parent_actions.push_back(na_item);
            }
        }
    }

    // Now, 'node' is a writable dirty node.

    size_t i;
    if ( node->getLevel() > 1 ) {
        // 2) if intermediate node:
        //    recursively call this function for each child node.
        BsaItem kvp, kvp_prev;
        size_t last_idx = start_idx;
        std::list<NodeActionItem*> local_actions;

        // Same mechanism as that in _insert(). Please see explanations in it.

        for (i=start_idx; i<=end_idx; ++i) {
            kvp = node->findKvSmallerOrEqual(kv_list[i].key, kv_list[i].keylen, true);
            if (i == start_idx) {
                // skip the first iteration to assign 'kvp_prev'.
            } else if (kvp_prev.idx != kvp.idx) {
                // call _remove() for last_idx ~ i-1
                BtreeNodeAddr next_addr( kvp_prev );
                BtreeKey next_key( kvp_prev );

                _remove( kv_list, node, next_key, next_addr,
                         last_idx, i-1, local_actions );

                last_idx = i;
            }
            kvp_prev = kvp;
        }

        // finally call _remove() for last_idx ~ end_idx
        BtreeNodeAddr next_addr( kvp );
        BtreeKey next_key( kvp );

        _remove( kv_list, node, next_key, next_addr,
                 last_idx, end_idx, local_actions );

        // execute local action items
        if ( local_actions.size() ) {
            doActionItems(node, local_actions);
        }

    } else {
        // 3) if leaf node:
        //    remove KV pairs of the given range.
        for (i=start_idx; i<=end_idx; ++i) {
            BnodeResult br = node->removeKv( kv_list[i].key, kv_list[i].keylen );
            if (br == BnodeResult::SUCCESS) {
                nentry--;
            }
        }
    }

    // 4) remove the node if it becomes empty
    if ( !node->getNentry() ) {
        bMgr->removeDirtyNode( node );

        if (parent_node) {
            // remove the pointer in the parent node.
            // (only when parent node exists)
            na_item = new NodeActionItem();
            na_item->setRemoveKey(ref_key.data, ref_key.length);
            parent_actions.push_back(na_item);
        }

        if ( node->getLevel() == height ) {
            // if this is a root node,
            // it means that now B+tree doesn't have any entries.
            // Reset the B+tree info.
            init();
        }

        delete node;
        return BtreeV2Result::SUCCESS;
    }

    // 5) check if smallest key in the node has been changed:
    //    => change the corresponding key in the parent node.
    node->findMinKey(min_key, min_keylen);
    if ( parent_node &&
         ( ref_key.length != min_keylen ||
           memcmp(ref_key.data, min_key, ref_key.length) ) ) {
        // The smallest key of the current node has been changed.
        // Which means that the reference key in the parent node needs to be
        // changed as well.
        na_item = new NodeActionItem();
        na_item->setReplaceKey(ref_key.data, ref_key.length, min_key, min_keylen);
        parent_actions.push_back(na_item);
    }

    // if root node, adapt B+tree info
    if ( node->getLevel() == height ) {
        rootAddr = BtreeNodeAddr(BLK_NOT_FOUND, node);
    }

    return BtreeV2Result::SUCCESS;
}

BtreeV2Result BtreeV2::find( BtreeKvPair& kv,
                             bool allocate_memory )
{
    BtreeV2Result br = BtreeV2Result::SUCCESS;
    BtreeNodeAddr node_addr = rootAddr;

    br = _find(kv, node_addr, allocate_memory, FindOption::EQUAL);

    return br;
}

BtreeV2Result BtreeV2::findSmallerOrEqual(BtreeKvPair& kv,
                                          bool allocate_memory)
{
    return _find(kv, rootAddr, allocate_memory, FindOption::SMALLER_OR_EQUAL);
}

BtreeV2Result BtreeV2::findGreaterOrEqual(BtreeKvPair& kv,
                                          bool allocate_memory)
{
    return _find(kv, rootAddr, allocate_memory, FindOption::GREATER_OR_EQUAL);
}

BtreeV2Result BtreeV2::_find( BtreeKvPair& kv,
                              BtreeNodeAddr node_addr,
                              bool allocate_memory,
                              FindOption opt )
{
    Bnode *node;

    if ( node_addr.isEmpty ) {
        // B+tree has not been populated yet.
        return BtreeV2Result::KEY_NOT_FOUND;
    } else {
        if ( node_addr.isDirty ) {
            // dirty node .. use the pointer.
            node = node_addr.ptr;
        } else {
            // clean node .. read from file.
            node = bMgr->readNode( node_addr.offset );
        }
    }

    BsaItem kvp;
    if ( node->getLevel() > 1 ) {
        // intermediate node
        kvp = node->findKvSmallerOrEqual(kv.key, kv.keylen);
        if ( kvp.isEmpty() ) {
            // not found
            return BtreeV2Result::KEY_NOT_FOUND;
        }
        // recursive call
        BtreeNodeAddr next_addr( kvp );
        return _find( kv, next_addr, allocate_memory, opt );
    }

    // leaf node
    bool exact_match = true;
    kvp = node->findKv(kv.key, kv.keylen);
    if ( kvp.isEmpty() ) {
        // not found
        exact_match = false;
        if ( opt == FindOption::SMALLER_OR_EQUAL ) {
            kvp = node->findKvSmallerOrEqual(kv.key, kv.keylen);
        } else if ( opt == FindOption::GREATER_OR_EQUAL ) {
            kvp = node->findKvGreaterOrEqual(kv.key, kv.keylen);
        }

        if ( kvp.isEmpty() ) {
            return BtreeV2Result::KEY_NOT_FOUND;
        }
    }

    if ( allocate_memory ) {
        kv.value = malloc(kvp.valuelen);
    }
    memcpy(kv.value, kvp.value, kvp.valuelen);
    kv.valuelen = kvp.valuelen;

    if (opt != FindOption::EQUAL && !exact_match) {
        // if not exact match option and not exact match key,
        // copy key as well.
        if (allocate_memory) {
            kv.key = malloc(kvp.keylen);
        }
        memcpy(kv.key, kvp.key, kvp.keylen);
        kv.keylen = kvp.keylen;
    }

    return BtreeV2Result::SUCCESS;
}

void BtreeV2::doActionItems( Bnode *node,
                             std::list<NodeActionItem *>& actions )
{
    NodeActionItem *na_item;
    for (auto &entry: actions) {
        na_item = entry;

        if (na_item->type == NodeActionType::ADD) {
            // add (or update if exists) key/value pair.
            node->addKv( na_item->key, na_item->keylen,
                         na_item->value, na_item->valuelen, na_item->child_ptr,
                         true );
        } else if (na_item->type == NodeActionType::REMOVE) {
            // remove key/value pair.
            node->removeKv( na_item->key, na_item->keylen );
        } else {
            // replace existing key with new one.
            BsaItem kvp = node->findKv( na_item->key, na_item->keylen );

            // alloc & copy value as 'kvp' points to existing memory
            // and it can be destroyed by removeKv() call below.
            void *value_rsv = nullptr;
            size_t valuelen_rsv = 0;
            if (!kvp.isValueChildPtr) {
                value_rsv = malloc(kvp.valuelen);
                memcpy(value_rsv, kvp.value, kvp.valuelen);
                valuelen_rsv = kvp.valuelen;
            }

            node->removeKv( kvp.key, kvp.keylen );

            if (kvp.isValueChildPtr) {
                // pointer value
                node->addKv( na_item->key_aux, na_item->keylen_aux,
                             nullptr, 0, static_cast<Bnode*>(kvp.value),
                             true );
            } else {
                // binary data value
                node->addKv( na_item->key_aux, na_item->keylen_aux,
                             value_rsv, valuelen_rsv, nullptr,
                             true );
                free(value_rsv);
            }
        }

        delete na_item;
    }
}

void BtreeV2::growHeight(std::list<NodeActionItem*>& actions)
{
    // 1) create a new root node
    Bnode *new_root = new Bnode();
    Bnode *old_root = rootAddr.ptr;
    bMgr->addDirtyNode( new_root );
    new_root->setLevel( height+1 );

    // 2) execute action items
    doActionItems(new_root, actions);

    // 3) move existing meta data
    //    from the old root to the new root
    new_root->setMeta( old_root->getMeta(), old_root->getMetaSize() );
    old_root->clearMeta();

    // 4) modify the B+tree info
    height = new_root->getLevel();
    rootAddr = BtreeNodeAddr(BLK_NOT_FOUND, new_root);
}

void BtreeV2::shrinkHeight()
{
    // 1) Replace the root node with its unique child.
    void *min_key;
    size_t min_keylen;
    BsaItem kvp;
    Bnode *old_root = nullptr;
    Bnode *new_root = nullptr;
    BnodeResult br;

    old_root = rootAddr.ptr;
    br = old_root->findMinKey(min_key, min_keylen);
    if (br != BnodeResult::SUCCESS) {
        // existing root node is already empty;
        // it means that now B+tree is empty.
        init();
        return;
    }
    kvp = old_root->findKv(min_key, min_keylen);

    if ( kvp.isValueChildPtr ) {
        // dirty child node
        new_root = static_cast<Bnode*>(kvp.value);
    } else {
        // clean child node .. read and make a dirty clone
        Bnode *clean_node;
        uint64_t offset = BtreeV2::value2offset( kvp );
        clean_node = bMgr->readNode( offset );

        new_root = bMgr->getMutableNodeFromClean(clean_node);
    }
    rootAddr = BtreeNodeAddr(BLK_NOT_FOUND, new_root);

    // 3) move existing meta data
    //    from the old root to the new root
    new_root->setMeta( old_root->getMeta(), old_root->getMetaSize() );
    old_root->clearMeta();

    bMgr->removeDirtyNode(old_root);
    delete old_root;

    // 2) modify the B+tree info
    height = new_root->getLevel();
}

BtreeV2Result BtreeV2::writeDirtyNodes()
{
    if ( !rootAddr.isDirty ) {
        // root node is clean
        // which means that no update has been served.
        return BtreeV2Result::SUCCESS;
    }

    // start from the root node recursively
    BtreeV2Result br = _writeDirtyNodes( rootAddr.ptr );

    // now root node becomes clean
    rootAddr = BtreeNodeAddr(rootAddr.ptr->getCurOffset(), nullptr);

    bMgr->flushDirtyNodes();

    return br;
}

BtreeV2Result BtreeV2::_writeDirtyNodes( Bnode *cur_node )
{
    BtreeV2Result br;

    if (cur_node->getLevel() > 1) {
        // intermediate node
        // 1) traverse dirty child nodes
        // 2) replace ptr to offset

        BsArray& kvArr = cur_node->getKvArr();
        BsaItem kvp = kvArr.first(true);
        uint64_t child_offset;

        while ( !kvp.isEmpty() ) {
            Bnode *child_node = static_cast<Bnode*>(kvp.value);
            br = _writeDirtyNodes( child_node );
            if (br != BtreeV2Result::SUCCESS) {
                return br;
            }

            child_offset = child_node->getCurOffset();
            child_offset = _endian_encode( child_offset );

            BsaItem item = BsaItem(kvp.key, kvp.keylen, (void*)&child_offset, sizeof(child_offset));
            kvArr.insert(item);

            kvp = kvArr.next(kvp, true);
        }
    }

    // assign offset for itself
    uint64_t offset = bMgr->assignDirtyNodeOffset(cur_node);
    cur_node->setCurOffset(offset);

    return BtreeV2Result::SUCCESS;
}
