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

#include "common.h"
#include "avltree.h"
#include "atomic.h"

class Bnode;

/**
 * Definition of Key-value pair structure that will be indexed
 * inside each B+tree node.
 */
struct BtreeKv {

    BtreeKv() :
        key(nullptr), value(nullptr), keylen(0), valuelen(0),
        existing_memory(true), child_ptr(nullptr) { }

    BtreeKv( void* _key,
             size_t _keylen,
             void* _value,
             size_t _valuelen,
             Bnode* _child_ptr,
             bool _existing_memory ) {
        keylen = static_cast<uint16_t>(_keylen);
        valuelen = static_cast<uint16_t>(_valuelen);
        existing_memory = _existing_memory;
        if (_existing_memory) {
            key = _key;
        } else {
            key = (void*)malloc(keylen);
            memcpy(key, _key, keylen);
        }
        if (valuelen) {
            if (_existing_memory) {
                value = _value;
            } else {
                value = (void*)malloc(valuelen);
                memcpy(value, _value, valuelen);
            }
        } else {
            value = nullptr;
        }
        child_ptr = _child_ptr;
    }

    ~BtreeKv() {
        if (!existing_memory) {
            free(key);
            free(value);
        }
    }

    /**
     * Return the raw binary data size of the key-value pair.
     *
     * @return Raw data size.
     */
    size_t getKvSize() {
        size_t ret = 0;
        ret += sizeof(keylen);
        ret += sizeof(valuelen);
        ret += keylen;
        if (value) {
            ret += valuelen;
        } else {
            // it points to other node: 8 bytes offset
            ret += sizeof(uint64_t);
        }
        return ret;
    }

    // AVL-tree element.
    struct avl_node avl;
    // Key string,
    void* key;
    // Value string.
    void* value;
    // Length of key.
    uint16_t keylen;
    // Length of value.
    uint16_t valuelen;
    // Flag that indicates if key and value are pointing to the existing
    // memory, or pointing to the memory blobs allocated when the key-value
    // pair is created.
    bool existing_memory;
    // Pointer to child B+tree node if this key-value pair is in
    // an intermediate node.
    Bnode *child_ptr;
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
    INVALID_BUFFER
};

class Bnode {
public:
    Bnode() :
        flags(0),
        level(1),
        nentry(0),
        metaSize(0),
        metaExistingMemory(false),
        meta(nullptr),
        refCount(0),
        curOffset(BLK_NOT_FOUND)
    {
        nodeSize = sizeof(nodeSize) +
                   sizeof(level)    +
                   sizeof(nentry)   +
                   sizeof(flags)    +
                   sizeof(metaSize);
        avl_init(&kvIdx, NULL);
    }
    ~Bnode();

    /**
     * Check if given parameters are correct.
     *
     * @param keylen Length of key.
     * @param key Key string.
     * @param valuelen Length of value.
     * @param value Value string.
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

    size_t getLevel() const {
        return level;
    }

    size_t getNentry() const {
        return nentry;
    }

    uint32_t getFlags() const {
        return flags;
    }

    size_t getMetaSize() const {
        return metaSize;
    }

    void* getMeta() const {
        return meta;
    }

    uint64_t getRefCount() const {
        return refCount.load();
    }

    uint64_t incRefCount() {
        return ++refCount;
    }

    uint64_t decRefCount() {
        return --refCount;
    }

    uint64_t getCurOffset() const {
        return curOffset;
    }

    /**
     * Update meta data section.
     *
     * @param new_meta New meta data.
     * @param meta_size Size of new meta data.
     * @param use_existing_memory If true, new memory blob will not be allocated
     *        and B+tree node will just point to 'new_meta'.
     */
    void setMeta( void* new_meta,
                  size_t meta_size,
                  bool use_existing_memory = false );

    /**
     * Insert a key-value pair into the B+tree node.
     *
     * @param keylen Length of key.
     * @param key Key string.
     * @param valuelen Length of value.
     * @param value Value string.
     * @param child_ptr Pointer to child B+tree node.
     * @param inc_nentry Flag to update internal stats or not.
     * @param use_existing_memory If true, new memory blob will not be allocated
     *        and B+tree node will just point to 'key' and 'value'.
     * @return SUCCESS on success.
     */
    BnodeResult addKv( void *key,
                       size_t keylen,
                       void *value,
                       size_t valuelen,
                       Bnode *child_ptr,
                       bool inc_nentry,
                       bool use_existing_memory = false );

    /**
     * Find a value corresponding to the given key.
     *
     * @param keylen Length of key.
     * @param key Key string.
     * @param valuelen_out Length of value to be returned.
     * @param value_out Value string to be returned.
     * @param ptr_out Pointer to child B+tree node to be returned.
     * @return SUCCESS on success.
     */
    BnodeResult findKv( void *key,
                        size_t keylen,
                        void*& value_out,
                        size_t& valuelen_out,
                        Bnode*& ptr_out );

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
     * Convert logical B+tree node structure to raw binary data.
     *
     * @param buf Memory area that raw data will be stored.
     * @return SUCCESS on success.
     */
    BnodeResult exportRaw(void *buf);

    /**
     * Construct logical B+tree node structure from raw binary data.
     *
     * @param buf Memory area containing raw data.
     * @param use_existing_memory If true, B+tree node will not allocate
     *        new memory blobs but just point to the data in 'buf'.
     * @return SUCCESS on success.
     */
    BnodeResult importRaw(void *buf, bool use_existing_memory = false);

    /**
     * Read raw B+tree node data size from the given buffer.
     *
     * @param buf Memory area containing raw data.
     * @return Size of raw B+tree node data.
     */
    static size_t readNodeSize(void *buf);

private:
    // Size of B+tree node.
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
    // Flag indicating if meta data points to existing memory.
    bool metaExistingMemory;
    // AVL-tree index for key-value pair.
    avl_tree kvIdx;
    // Meta data
    void* meta;
    // Reference counter for the given node. If this value is not zero, the node
    // must not be ejected from the cache.
    std::atomic<uint64_t> refCount;
    // File offset where this node is written. If this node is dirty so that
    // has not been flushed yet, the value is BLK_NOT_FOUND.
    uint64_t curOffset;
};
