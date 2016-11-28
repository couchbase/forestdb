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
#include "bnode.h"
#include "hbtrie.h"


Bnode::Bnode() :
    nodeSize( Bnode::getDiskSpaceOfEmptyNode() ),
    flags(0),
    level(1),
    nentry(0),
    metaSize(0),
    refCount(0),
    curOffset(BLK_NOT_FOUND),
    cmpFunc(nullptr)
{
    list_elem.prev = list_elem.next = nullptr;
    kvArr.adjustBaseOffset( nodeSize );
}

Bnode::~Bnode()
{ }

BnodeResult Bnode::inputSanityCheck( void *key,
                                     size_t keylen,
                                     void *value,
                                     size_t valuelen,
                                     Bnode *ptr,
                                     bool value_check )
{
    if (!keylen || !key) {
        // key should be spcified.
        return BnodeResult::EMPTY_KEY;
    }
    if (value_check) {
        if ((!valuelen || !value) && !ptr) {
            // either value or ptr should be specified.
            return BnodeResult::EMPTY_VALUE;
        }
        if (value && ptr) {
            // value and ptr cannot co-exist
            return BnodeResult::DUPLICATE_VALUE;
        }
    }
    return BnodeResult::SUCCESS;
}

void Bnode::setMeta( void* new_meta,
                     size_t meta_size )
{
    if (metaSize != meta_size) {
        int gap = meta_size - metaSize;

        // should adapt on-disk node size
        nodeSize += gap;
        // update meta data size
        metaSize = meta_size;
        // also adapt array base offset
        kvArr.adjustBaseOffset( kvArr.getBaseOffset() + gap );
    }

    // meta data position is always fixed
    void *meta = (uint8_t*)kvArr.getDataArray() + Bnode::getDiskSpaceOfEmptyNode();
    memcpy(meta, new_meta, meta_size);
}

void Bnode::clearMeta()
{
    nodeSize -= metaSize;
    kvArr.adjustBaseOffset( kvArr.getBaseOffset() - metaSize );
    metaSize = 0;
}

BnodeResult Bnode::addKv( void *key,
                          size_t keylen,
                          void *value,
                          size_t valuelen,
                          Bnode *child_ptr,
                          bool inc_nentry )
{
    BnodeResult ret = inputSanityCheck(key, keylen, value, valuelen, child_ptr);
    if (ret != BnodeResult::SUCCESS) {
        return ret;
    }

    BsaItem query(key, keylen);
    BsaItem item = kvArr.find( query );

    if (!item.isEmpty()) {
        // same key already exists .. just update value only
        nodeSize -= item.valuelen;

        if (value) {
            // binary data value
            nodeSize += valuelen;
            item = BsaItem(key, keylen, value, valuelen);
        } else {
            // pointer to child node
            nodeSize += sizeof(uint64_t);
            item = BsaItem(key, keylen, child_ptr);
        }
        kvArr.insert( item );
        return BnodeResult::SUCCESS;
    }

    if (value) {
        // binary data value
        item = BsaItem(key, keylen, value, valuelen);
    } else {
        // pointer to child node
        item = BsaItem(key, keylen, child_ptr);
    }
    kvArr.insert( item );

    if (inc_nentry) {
        nentry++;
        nodeSize += item.getSize();
    }

    return BnodeResult::SUCCESS;
}

BnodeResult Bnode::findKv( void *key,
                           size_t keylen,
                           void*& value_out,
                           size_t& valuelen_out,
                           Bnode*& ptr_out )
{
    BnodeResult ret = inputSanityCheck(key, keylen, NULL, 0, NULL, false);
    if (ret != BnodeResult::SUCCESS) {
        return ret;
    }

    BsaItem query(key, keylen);
    BsaItem item = kvArr.find( query );

    if (item.isEmpty()) {
        return BnodeResult::KEY_NOT_FOUND;
    }

    if (item.isValueChildPtr) {
        // pointer
        valuelen_out = 0;
        value_out = nullptr;
        ptr_out = static_cast<Bnode*>(item.value);
    } else {
        // binary data
        valuelen_out = item.valuelen;
        value_out = item.value;
    }

    return BnodeResult::SUCCESS;
}

BsaItem Bnode::findKv( void *key,
                        size_t keylen )
{
    BnodeResult ret = inputSanityCheck(key, keylen, NULL, 0, NULL, false);
    if (ret != BnodeResult::SUCCESS) {
        BsaItem not_found;
        return not_found;
    }

    BsaItem query(key, keylen);
    return kvArr.find( query );
}

BsaItem Bnode::findKvSmallerOrEqual( void *key,
                                     size_t keylen,
                                     bool return_smallest )
{
    BnodeResult ret = inputSanityCheck(key, keylen, NULL, 0, NULL, false);
    if (ret != BnodeResult::SUCCESS) {
        BsaItem not_found;
        return not_found;
    }

    BsaItem query(key, keylen);
    BsaItem item = kvArr.findSmallerOrEqual( query );

    if (item.isEmpty()) {
        if (return_smallest) {
            // given key is smaller than the smallest key.
            // return the first element.
            return kvArr.first();
        }
    }
    return item;
}

BsaItem Bnode::findKvGreaterOrEqual( void *key,
                                     size_t keylen,
                                     bool return_greatest )
{
    BnodeResult ret = inputSanityCheck(key, keylen, NULL, 0, NULL, false);
    if (ret != BnodeResult::SUCCESS) {
        BsaItem not_found;
        return not_found;
    }

    BsaItem query(key, keylen);
    BsaItem item = kvArr.findGreaterOrEqual( query );

    if (item.isEmpty()) {
        if (return_greatest) {
            // given key is greater than the greatest key.
            // return the last element.
            return kvArr.last();
        }
    }
    return item;
}

BnodeResult Bnode::findMinKey( void*& key,
                               size_t& keylen )
{
    BsaItem item = kvArr.first();

    if (item.isEmpty()) {
        return BnodeResult::KEY_NOT_FOUND;
    }

    key = item.key;
    keylen = item.keylen;
    return BnodeResult::SUCCESS;
}

BnodeResult Bnode::findMaxKey( void*& key,
                               size_t& keylen )
{
    BsaItem item = kvArr.last();

    if (item.isEmpty()) {
        return BnodeResult::KEY_NOT_FOUND;
    }

    key = item.key;
    keylen = item.keylen;
    return BnodeResult::SUCCESS;
}

BnodeResult Bnode::removeKv( void *key,
                             size_t keylen )
{
    BnodeResult ret = inputSanityCheck(key, keylen, NULL, 0, NULL, false);
    if (ret != BnodeResult::SUCCESS) {
        return ret;
    }

    BsaItem query(key, keylen);
    BsaItem item = kvArr.remove( query );

    if ( item.isEmpty() ) {
        return BnodeResult::KEY_NOT_FOUND;
    }

    nentry--;
    nodeSize -= item.getSize();

    return BnodeResult::SUCCESS;
}

void Bnode::migrateEntries( size_t cur_num_elems,
                            std::list<Bnode *>& new_nodes,
                            BsaItem first_kvp,
                            BsaItem last_kvp )
{
    // allocate next new node
    Bnode *bnode = new Bnode();
    bnode->setLevel(level);
    bnode->setCmpFunc(cmpFunc);
    new_nodes.push_back(bnode);

    // copy first_kvp ~ last_kvp
    bnode->getKvArr().copyFromOtherArray(this->getKvArr(), first_kvp, last_kvp);
    bnode->setNentry(cur_num_elems);
    nentry -= cur_num_elems;

    int64_t new_datasize = static_cast<int64_t>(last_kvp.pos) -
                           first_kvp.pos + last_kvp.getSize();
    bnode->setNodeSize(bnode->getNodeSize() + new_datasize);
    nodeSize -= new_datasize;

}

BnodeResult Bnode::splitNode( size_t nodesize_limit,
                              std::list<Bnode *>& new_nodes )
{
    // Split the current node into 'n' nodes.
    // Note that if the current node is dirty, the node is still mutable
    // so that we don't need to allocate a new node for the first few entries;
    // but just use the current node as the 1st split node. As a result, the
    // first few entries don't need to be moved to other node.
    //
    // e.g.)
    // current node: {0, 1, 2, 3, 4, 5}
    // we are going to split it into 3 nodes:
    //
    // < when current node is clean >
    // => create 3 new nodes.
    //      current node: {0, 1, 2, 3, 4, 5} (immutable, will be ejected later)
    //      [1st node] new node 1:   {0, 1}
    //      [2nd node] new node 2:   {2, 3}
    //      [3rd node] new node 3:   {4, 5}
    //
    // < when current node is dirty >
    // => create 2 new nodes.
    //      [1st node] current node: {0, 1} (0 and 1 are not moved)
    //      [2nd node] new node 1:   {2, 3}
    //      [3rd node] new node 2:   {4, 5}

    // Split the current node into several new nodes.
    bool skip_first_entry_set = false;
    size_t num_nodes = 0;

    size_t est_num_nodes = (nodeSize / nodesize_limit) + 1;
    size_t est_split_nodesize = nodeSize / est_num_nodes;

    if ( est_num_nodes < 2 ||
         nentry < 4 ) {
        // At least 2 nodes should be created after split,
        // and each split node should contain at least 2 entries.
        return BnodeResult::SUCCESS;
    }

    // if the current node is dirty, then
    // first entry set can remain in the current node.
    if ( curOffset == BLK_NOT_FOUND ) {
        skip_first_entry_set = true;
    }

    BsaItem kvp, prev_kvp, first_kvp;
    size_t cur_nodesize = Bnode::getDiskSpaceOfEmptyNode() + metaSize;
    size_t cur_num_elems = 0;

    uint32_t new_array_size = 0;
    uint32_t new_num_elems = 0;

    kvp = first_kvp = kvArr.first();
    while ( !kvp.isEmpty() ) {
        if (cur_num_elems == 0) {
            first_kvp = kvp;
        }
        cur_num_elems++;

        // Note: each split node should contain at least 2 entries,
        // although it exceeds the node size limit.
        cur_nodesize += kvp.getSize();
        if ( cur_nodesize > est_split_nodesize &&
             cur_num_elems > 1 ) {

            // if the current node is dirty, then
            // first entry set (when num_nodes == 0, first_kvp ~ kvp) can
            // remain in the current node.
            if ( num_nodes == 0 && skip_first_entry_set ) {
                new_array_size = kvp.pos - first_kvp.pos + kvp.getSize();
                new_num_elems = cur_num_elems;
            } else {
                // Otherwise, migrate them to new nodes.
                migrateEntries( cur_num_elems, new_nodes, first_kvp, kvp );
            }

            num_nodes++;
            cur_nodesize = Bnode::getDiskSpaceOfEmptyNode() + metaSize;
            cur_num_elems = 0;
        }
        prev_kvp = kvp;
        kvp = kvArr.next(kvp);
    }

    if (cur_num_elems) {
        // final copy of first_kvp ~ prev_kvp
        migrateEntries( cur_num_elems, new_nodes, first_kvp, prev_kvp );
    }

    if (skip_first_entry_set) {
        // adjust array size and num elems for this node
        kvArr.setArraySize( new_array_size );
        kvArr.setNumElems( new_num_elems );
    }

    return BnodeResult::SUCCESS;
}

Bnode* Bnode::cloneNode()
{
    Bnode *dst = new Bnode();
    // meta data position is always fixed
    void *meta = (uint8_t*)kvArr.getDataArray() + Bnode::getDiskSpaceOfEmptyNode();

    // copy level, flags, and meta data
    dst->setLevel(level);
    dst->setFlags(flags);
    dst->setMeta(meta, metaSize);
    dst->setCmpFunc(cmpFunc);

    // copy all key-value pair instances
    BsArray& src_arr = this->getKvArr();
    BsaItem first_kvp = src_arr.first();
    BsaItem last_kvp = src_arr.last();
    dst->getKvArr().copyFromOtherArray(src_arr, first_kvp, last_kvp);
    dst->setNentry(nentry);
    dst->setNodeSize(nodeSize);

    return dst;
}

void* Bnode::exportRaw()
{
    uint8_t *ptr = static_cast<uint8_t*>(kvArr.getDataArray());
    uint16_t enc16;
    uint32_t enc32;
    size_t offset = 0;

    // node size
    enc32 = _endian_encode(nodeSize);
    memcpy(ptr + offset, &enc32, sizeof(enc32));
    offset += sizeof(enc32);

    // level (root:n, leaf:1)
    enc16 = _endian_encode(level);
    memcpy(ptr + offset, &enc16, sizeof(enc16));
    offset += sizeof(enc16);

    // # entry
    enc16 = _endian_encode(nentry);
    memcpy(ptr + offset, &enc16, sizeof(enc16));
    offset += sizeof(enc16);

    // flags
    enc32 = _endian_encode(flags);
    memcpy(ptr + offset, &enc32, sizeof(enc32));
    offset += sizeof(enc32);

    // metadata size
    enc16 = _endian_encode(metaSize);
    memcpy(ptr + offset, &enc16, sizeof(enc16));

    return ptr;
}

BnodeResult Bnode::importRaw(void *buf,
                             uint32_t buf_size)
{
    // bnode should be empty
    if ( kvArr.getArraySize() ) {
        return BnodeResult::NODE_IS_NOT_EMPTY;
    }

    if ( !buf ) {
        return BnodeResult::INVALID_BUFFER;
    }

    uint8_t *ptr = static_cast<uint8_t*>(buf);
    uint16_t enc16;
    uint32_t enc32;
    size_t offset = 0;

    kvArr.setDataArrayBuffer(buf, buf_size);

    // node size
    enc32 = *( reinterpret_cast<uint32_t*>(ptr + offset) );
    offset += sizeof(enc32);
    nodeSize = _endian_decode(enc32);

    // level
    enc16 = *( reinterpret_cast<uint16_t*>(ptr + offset) );
    offset += sizeof(enc16);
    level = _endian_decode(enc16);

    // # entry
    enc16 = *( reinterpret_cast<uint16_t*>(ptr + offset) );
    offset += sizeof(enc16);
    nentry = _endian_decode(enc16);

    // flags
    enc32 = *( reinterpret_cast<uint32_t*>(ptr + offset) );
    offset += sizeof(enc32);
    flags = _endian_decode(enc32);

    // metadata size
    enc16 = *( reinterpret_cast<uint16_t*>(ptr + offset) );
    offset += sizeof(enc16);
    metaSize = _endian_decode(enc16);

    // metadata
    offset += metaSize;

    // adjust base offset
    kvArr.adjustBaseOffset(offset);

    // construct array from the existing buffer
    kvArr.constructKvMetaArray(nodeSize - offset, nentry, true);

    return BnodeResult::SUCCESS;
}

size_t Bnode::readNodeSize(void *buf)
{
    // read the first 4 bytes
    uint32_t enc32 = *( reinterpret_cast<uint32_t*>(buf) );
    return _endian_decode(enc32);
}

void Bnode::fitMemSpaceToNodeSize()
{
    kvArr.fitArrayAndKvMetaCapacity();
    bidList.shrink_to_fit();
}

void Bnode::DBG_printNode(size_t start_idx, size_t num_to_print)
{
    size_t i = 0;
    BsaItem kvp;
    kvp = kvArr.first();
    while (!kvp.isEmpty()) {
        if (i >= start_idx + num_to_print) {
            break;
        }

        if (i >= start_idx) {
            printf("[%d] %.*s, ", (int)i, (int)kvp.keylen, (char*)kvp.key);
            if (kvp.isValueChildPtr) {
                printf("PTR 0x%" _X64 " ", (uint64_t)kvp.value);
            } else {
                if (level == 1) {
                    printf("%.*s ", (int)kvp.valuelen, (char*)kvp.value);
                } else {
                    uint64_t offset = *(reinterpret_cast<uint64_t*>(kvp.value));
                    offset = _endian_decode(offset);
                    printf("OFF 0x%" _X64 " ", offset);
                }
            }
        }

        i++;
        kvp = kvArr.next(kvp);
    }
}

void logBnodeErr(Bnode *bnode, fdb_status error_no, const char *msg) {
    if (!bnode || !msg) {
        return;
    }
    fdb_log(nullptr, error_no,
            "Warning: on bnode (at offset: %s), %s.",
            std::to_string(bnode->getCurOffset()).c_str(), msg);
}



BnodeIterator::BnodeIterator(Bnode *_bnode) : bnode(_bnode),
                                              curKvp()
{
    // start with the first key.
    begin();
}

BnodeIterator::BnodeIterator( Bnode *_bnode,
                              void *start_key,
                              size_t start_keylen ) : bnode(_bnode),
                                                      curKvp()
{
    // start with equal to or greater than 'start_key'.
    seekGreaterOrEqual(start_key, start_keylen);
}

BnodeIteratorResult BnodeIterator::seekGreaterOrEqual( void *key,
                                                       size_t keylen )
{
    if (!bnode) {
        return BnodeIteratorResult::INVALID_NODE;
    }

    BsaItem query(key, keylen);
    curKvp = bnode->kvArr.findGreaterOrEqual( query );
    if ( curKvp.isEmpty() ) {
        return BnodeIteratorResult::NO_MORE_ENTRY;
    }
    return BnodeIteratorResult::SUCCESS;
}

BnodeIteratorResult BnodeIterator::seekSmallerOrEqual( void *key,
                                                       size_t keylen )
{
    if (!bnode) {
        return BnodeIteratorResult::INVALID_NODE;
    }

    BsaItem query(key, keylen);
    curKvp = bnode->kvArr.findSmallerOrEqual( query );
    if ( curKvp.isEmpty() ) {
        return BnodeIteratorResult::NO_MORE_ENTRY;
    }
    return BnodeIteratorResult::SUCCESS;
}

BnodeIteratorResult BnodeIterator::begin()
{
    if (!bnode) {
        return BnodeIteratorResult::INVALID_NODE;
    }

    curKvp = bnode->kvArr.first();
    if ( curKvp.isEmpty() ) {
        return BnodeIteratorResult::NO_MORE_ENTRY;
    }
    return BnodeIteratorResult::SUCCESS;
}

BnodeIteratorResult BnodeIterator::end()
{
    if (!bnode) {
        return BnodeIteratorResult::INVALID_NODE;
    }

    curKvp = bnode->kvArr.last();
    if ( curKvp.isEmpty() ) {
        return BnodeIteratorResult::NO_MORE_ENTRY;
    }
    return BnodeIteratorResult::SUCCESS;
}

BnodeIteratorResult BnodeIterator::prev()
{
    curKvp = bnode->kvArr.prev( curKvp );
    if ( curKvp.isEmpty() ) {
        return BnodeIteratorResult::NO_MORE_ENTRY;
    }
    return BnodeIteratorResult::SUCCESS;
}

BnodeIteratorResult BnodeIterator::next()
{
    curKvp = bnode->kvArr.next( curKvp );
    if ( curKvp.isEmpty() ) {
        return BnodeIteratorResult::NO_MORE_ENTRY;
    }
    return BnodeIteratorResult::SUCCESS;
}


INLINE int BsaCmp(BsaItem& aa, BsaItem& bb, void *aux)
{
    if (aux) {
        // custom compare function is defined
        Bnode *bnode = reinterpret_cast<Bnode*>(aux);
        btree_new_cmp_func *func = bnode->getCmpFunc();
        return func(aa.key, aa.keylen, bb.key, bb.keylen);
    } else {
        // lexicographical order
        if (aa.keylen == bb.keylen) {
            return memcmp(aa.key, bb.key, aa.keylen);
        } else {
            size_t len = MIN(aa.keylen, bb.keylen);
            int cmp = memcmp(aa.key, bb.key, len);
            if (cmp != 0) {
                return cmp;
            } else {
                return static_cast<int>( static_cast<int>(aa.keylen) -
                                         static_cast<int>(bb.keylen) );
            }
        }
    }
}


BsArray::BsArray() :
    aux(nullptr), kvDataSize(0), arrayBaseOffset(0)
{
    arrayCapacity = 32; // minimum blob size for malloc
    dataArray = malloc(arrayCapacity);
}

BsArray::~BsArray() {
    free(dataArray);
}

void BsArray::adjustBaseOffset(uint32_t _new_base)
{
    int gap = _new_base - arrayBaseOffset;

    if (gap) {
        adjustArrayCapacity(gap);
        if (kvDataSize) {
            memmove((uint8_t*)dataArray + _new_base,
                    (uint8_t*)dataArray + arrayBaseOffset,
                    kvDataSize);
        }
        arrayBaseOffset = _new_base;
    }
}

BsaItem BsArray::first(BsaItrType mode) {
    BsaItem not_found;
    size_t num_elems = kvMeta.size();

    if (!num_elems) {
        // no item in array
        return not_found;
    }

    if (mode != BsaItrType::NORMAL) {
        uint32_t i;
        for (i=0; i<num_elems; ++i) {
            if (mode == BsaItrType::DIRTY_BTREE_NODE_ONLY && kvMeta[i].isPtr) {
                return fetchItem(i);
            } else if (mode == BsaItrType::DIRTY_CHILD_TREE_ONLY &&
                kvMeta[i].isDirtyChildTree) {
                return fetchItem(i);
            }
        }
        return not_found;
    }

    return fetchItem(0);
}

BsaItem BsArray::last(BsaItrType mode) {
    BsaItem not_found;
    size_t num_elems = kvMeta.size();

    if (!num_elems) {
        // no item in array
        return not_found;
    }

    if (mode != BsaItrType::NORMAL) {
        int i;
        for (i=static_cast<int>(num_elems)-1; i>=0; --i) {
            if (mode == BsaItrType::DIRTY_BTREE_NODE_ONLY && kvMeta[i].isPtr) {
                return fetchItem(i);
            } else if (mode == BsaItrType::DIRTY_CHILD_TREE_ONLY &&
                kvMeta[i].isDirtyChildTree) {
                return fetchItem(i);
            }
        }
        return not_found;
    }

    return fetchItem(num_elems - 1);
}

BsaItem BsArray::prev(BsaItem& cur, BsaItrType mode) {
    BsaItem not_found;
    if ( cur.idx == 0 ) {
        // no previous item
        return not_found;
    }

    if (mode != BsaItrType::NORMAL) {
        int i;
        for (i=static_cast<int>(cur.idx)-1; i>=0; --i) {
            if (mode == BsaItrType::DIRTY_BTREE_NODE_ONLY && kvMeta[i].isPtr) {
                return fetchItem(i);
            } else if (mode == BsaItrType::DIRTY_CHILD_TREE_ONLY &&
                kvMeta[i].isDirtyChildTree) {
                return fetchItem(i);
            }
        }
        return not_found;
    }

    return fetchItem(cur.idx - 1);
}

BsaItem BsArray::next(BsaItem& cur, BsaItrType mode) {
    BsaItem not_found;
    size_t num_elems = kvMeta.size();

    if ( cur.idx == num_elems - 1 ) {
        // no next item
        return not_found;
    }

    if (mode != BsaItrType::NORMAL) {
        uint32_t i;
        for (i=cur.idx+1; i<num_elems; ++i) {
            if (mode == BsaItrType::DIRTY_BTREE_NODE_ONLY && kvMeta[i].isPtr) {
                return fetchItem(i);
            } else if (mode == BsaItrType::DIRTY_CHILD_TREE_ONLY &&
                kvMeta[i].isDirtyChildTree) {
                return fetchItem(i);
            }
        }
        return not_found;
    }

    return fetchItem(cur.idx + 1);
}

BsaItem BsArray::find(BsaItem& key, bool smaller_key)
{
    int cmp;
    uint32_t start = 0, middle = 0, end= 0;
    BsaItem cur;
    BsaItem not_found;

    // empty check
    end = kvMeta.size();
    if (!end) {
        return not_found;
    }

    // 1) compare with the smallest key
    cur = fetchItem(0);
    cmp = BsaCmp(key, cur, aux);
    if (cmp < 0) {
        // no smaller key
        return not_found;
    } else if (cmp == 0) {
        // smallest key
        return cur;
    }

    // 2) compare with the greatest key
    cur = fetchItem(end-1);
    cmp = BsaCmp(key, cur, aux);
    if (!smaller_key && cmp > 0) {
        // greater than greater key && exact key option
        return not_found;
    } else if (cmp == 0) {
        // return the greatest key
        return cur;
    }

    // 3) now do binary search
    while (start+1 < end) {
        middle = (start + end) >> 1;

        // get key at middle
        cur = fetchItem(middle);
        cmp = BsaCmp(key, cur, aux);
        if (cmp < 0) {
            // given key < middle
            end = middle;
        } else if (cmp > 0) {
            // middle < given key
            start = middle;
        } else {
            // exact key found
            return cur;
        }
    }

    // 4) exact key not found
    //    => return key at 'start' on 'smaller_key' option.
    if (smaller_key) {
        cur = fetchItem(start);
        return cur;
    }
    return not_found;
}

/**
 * return the greatest key equal to or smaller than the given key
 * example)
 * node: [2 4 6 8]
 * key: 5
 * greatest key equal to or smaller than 'key': 4
 * return: 4
 */
BsaItem BsArray::findSmallerOrEqual(BsaItem& key) {
    return find(key, true);
}

BsaItem BsArray::findGreaterOrEqual(BsaItem& key) {
    BsaItem cur = find(key, true);
    if ( cur.isEmpty() ) {
        // it means that given key is smaller than the smallest key.
        // => return the first entry.
        return first();
    }
    if (!BsaCmp(key, cur, aux)) {
        // exact match, return it.
        return cur;
    }
    // smaller item, return next KV.
    return next(cur);
}

BsaItem BsArray::insert(BsaItem& item) {
    BsaItem not_found;
    BsaItem existing_item;
    BsaItem ret;

    if (!kvMeta.size()) {
        // empty array .. insert without searching
        return addToArray(item, 0, false);
    }

    existing_item = findSmallerOrEqual(item);
    if (existing_item.isEmpty()) {
        // 'item' is smaller than the smallest key
        // insert at idx 0
        ret = addToArray(item, 0, false);
    } else {
        if ( !BsaCmp(item, existing_item, aux) ) {
            // same key => overwrite
            ret = addToArray(item, existing_item.idx, true);
        } else {
            // otherwise => insert right next to the existing item
            ret = addToArray(item, existing_item.idx+1, false);
        }
    }

    return ret;
}
BsaItem BsArray::remove(BsaItem& item) {
    BsaItem not_found;
    size_t num_elems = kvMeta.size();

    if (!num_elems) {
        // empty array
        return not_found;
    }

    BsaItem existing_item = find(item);
    if (existing_item.isEmpty()) {
        return not_found;
    } else {
        // left shift [idx+1 ~ num_elems]
        uint32_t pos = existing_item.pos;
        // including base offset
        uint32_t pos_actual = pos + arrayBaseOffset;
        uint32_t len = existing_item.getSize();

        if (static_cast<uint32_t>(existing_item.idx+1) < num_elems ) {
            memmove( (uint8_t*)dataArray + pos_actual,
                     (uint8_t*)dataArray + pos_actual + len,
                     kvDataSize - (pos + len) );

            // adjust kvPos properly
            for (uint32_t i = existing_item.idx+1; i<num_elems; ++i) {
                kvMeta[i].kvPos -= len;
            }
        }

        // erase element at 'existing_item.idx'.
        kvMeta.erase(kvMeta.begin() + existing_item.idx);

        kvDataSize -= len;
    }

    return existing_item;
}

void BsArray::copyFromOtherArray(BsArray& src_array,
                                 BsaItem& start_item,
                                 BsaItem& end_item)
{
    std::vector<BsaKvMeta>& src_kv_meta = src_array.getKvMeta();

    uint32_t num_elems = end_item.idx - start_item.idx + 1;
    uint32_t data_size_to_copy = end_item.pos - start_item.pos + end_item.getSize();

    adjustArrayCapacity(data_size_to_copy);

    // copy 'dataArray' from source
    uint8_t *dst_ptr = static_cast<uint8_t*>(dataArray) +
                       arrayBaseOffset;
    uint8_t *src_ptr = static_cast<uint8_t*>(src_array.getDataArray()) +
                       src_array.getBaseOffset();
    memcpy(dst_ptr, src_ptr + start_item.pos, data_size_to_copy);

    // copy kvMeta from source
    // Only 'isPtr' part is valid; 'kvPos' part will be updated
    // in constructKvMetaArray() below.

    // resize kvMeta
    setNumElems(num_elems);
    std::copy(src_kv_meta.begin() + start_item.idx,
              src_kv_meta.begin() + start_item.idx + num_elems,
              kvMeta.begin());

    constructKvMetaArray(data_size_to_copy, num_elems, false);
}

void BsArray::constructKvMetaArray(uint32_t kv_data_size,
                                   uint32_t num_elems,
                                   bool reset_isptr)
{
    uint32_t i;
    uint32_t offset = arrayBaseOffset;
    uint8_t *ptr = static_cast<uint8_t*>(dataArray);

    kvDataSize = kv_data_size;

    // resize kvMeta
    setNumElems(num_elems);

    uint16_t keylen_local, valuelen_local;
    for (i=0; i<num_elems; ++i) {
        kvMeta[i].kvPos = offset - arrayBaseOffset;
        if (reset_isptr) {
            kvMeta[i].isPtr = false;
        }

        keylen_local = *(reinterpret_cast<uint16_t*>(ptr+offset));
        keylen_local = _endian_decode(keylen_local);
        offset += sizeof(keylen_local);

        valuelen_local = *(reinterpret_cast<uint16_t*>(ptr+offset));
        valuelen_local = _endian_decode(valuelen_local);
        offset += sizeof(valuelen_local);

        offset += keylen_local;

        if (valuelen_local == HBTrie::getHvSize() &&
            HBTrie::isDirtyChildTree(ptr+offset)) {
            // points to a dirty child b+tree root node.
            kvMeta[i].isDirtyChildTree = true;
        } else {
            kvMeta[i].isDirtyChildTree = false;
        }

        offset += valuelen_local;
    }
}

BsaItem BsArray::fetchItem(uint32_t idx) {
    BsaItem ret;
    uint32_t offset = 0;

    ret.pos = kvMeta[idx].kvPos;
    uint8_t *ptr = (uint8_t*)dataArray + arrayBaseOffset + ret.pos;

    uint16_t keylen_local, valuelen_local;
    keylen_local = *(reinterpret_cast<uint16_t*>(ptr+offset));
    ret.keylen = _endian_decode(keylen_local);
    offset += sizeof(keylen_local);

    valuelen_local = *(reinterpret_cast<uint16_t*>(ptr+offset));
    ret.valuelen = _endian_decode(valuelen_local);
    offset += sizeof(valuelen_local);

    ret.key = ptr + offset;
    offset += ret.keylen;

    if (kvMeta[idx].isPtr) {
        // value is pointer
        uint64_t addr;
        memcpy(&addr, ptr + offset, sizeof(addr));
        ret.value = reinterpret_cast<void*>(addr);
        ret.isValueChildPtr = true;
    } else {
        // value is binary data
        ret.value = ptr + offset;
        ret.isValueChildPtr = false;
    }

    ret.idx = idx;

    return ret;
}

void BsArray::writeItem(BsaItem item, uint32_t position) {
    uint32_t offset = 0;
    uint16_t keylen_local, valuelen_local;
    uint8_t *ptr = (uint8_t*)dataArray + arrayBaseOffset + position;

    keylen_local = _endian_encode(item.keylen);
    memcpy(ptr + offset, &keylen_local, sizeof(keylen_local));
    offset += sizeof(keylen_local);

    valuelen_local = _endian_encode(item.valuelen);
    memcpy(ptr + offset, &valuelen_local, sizeof(valuelen_local));
    offset += sizeof(valuelen_local);

    // as 'item.key' is a pointer, it may point to the same key..
    // in that case, we don't need to call memcpy().
    if (ptr + offset != item.key) {
        memcpy(ptr + offset, item.key, item.keylen);
    }
    offset += item.keylen;

    if (item.isValueChildPtr) {
        // store pointer address directly
        // (don't need to do endian encoding as it is just in-memory data)
        uint64_t addr = reinterpret_cast<uint64_t>(item.value);
        memcpy(ptr + offset, &addr, sizeof(addr));
    } else {
        memcpy(ptr + offset, item.value, item.valuelen);
    }
}

BsaItem BsArray::addToArray(BsaItem item, uint32_t idx, bool overwrite) {
    uint32_t offset = 0;
    uint32_t new_item_len = item.getSize();
    uint32_t existing_item_len = 0;
    BsaItem existing_item, left_item;
    size_t num_elems = kvMeta.size();

    // calculate the offset where the item will be copied.
    if ( num_elems ) {
        if (idx < num_elems) {
            // adding at existing item's position
            // (which means that existing item needs to be shifted)
            // where 'existing item' means that previous item
            // whose position is same to 'idx'.
            existing_item = fetchItem(idx);
            existing_item_len = existing_item.getSize();
            offset = existing_item.pos;
        } else {
            // adding at the end of the array
            // we don't need to consider existing_item_len.
            left_item = fetchItem(idx-1);
            offset = left_item.pos + left_item.getSize();
        }
    }

    // shift memory if necessary
    // 1) if insertion, always right shift.
    // 2) if overwrite, only when item size is different.
    int gap = 0;
    if ( !overwrite ) {
        // insertion
        gap = new_item_len;
    } else if ( overwrite && existing_item_len != new_item_len ) {
        // overwrite && item size is different
        gap = static_cast<int64_t>(new_item_len) - existing_item_len;
    }

    // data array capacity check
    adjustArrayCapacity(gap);

    // shift 'dataArray'
    if ( gap && idx < num_elems ) {
        uint32_t offset_total = arrayBaseOffset + offset;
        uint32_t amount = kvDataSize - offset;

        if ( overwrite ) {
            // exclude existing item
            offset_total += existing_item_len;
            amount -= existing_item_len;
        }

        memmove( (uint8_t*)dataArray + offset_total + gap,
                 (uint8_t*)dataArray + offset_total,
                 amount );
        // adjust kvPos offsets
        for (uint32_t i = idx; i<num_elems; ++i) {
            kvMeta[i].kvPos += gap;
        }
    }

    writeItem(item, offset);

    if (overwrite) {
        // overwrite
        kvMeta[idx].kvPos = offset;
        kvMeta[idx].isPtr = item.isValueChildPtr;
    } else {
        // insert at 'idx'
        BsaKvMeta new_meta_entry;
        new_meta_entry.kvPos = offset;
        new_meta_entry.isPtr = item.isValueChildPtr;
        kvMeta.insert(kvMeta.begin() + idx, new_meta_entry);
    }
    kvDataSize += gap;

    item.idx = idx;
    item.pos = offset;

    if (item.valuelen == HBTrie::getHvSize() &&
        HBTrie::isDirtyChildTree(item.value)) {
        kvMeta[idx].isDirtyChildTree = true;
    } else {
        kvMeta[idx].isDirtyChildTree = false;
    }

    return item;
}

void BsArray::adjustArrayCapacity(int gap) {
    if (arrayBaseOffset + kvDataSize + gap > arrayCapacity) {
        arrayCapacity = arrayBaseOffset + kvDataSize + gap;
        dataArray = realloc(dataArray, arrayCapacity);
    }
}

void BsArray::fitArrayAndKvMetaCapacity()
{
    if (arrayCapacity > arrayBaseOffset + kvDataSize) {
        arrayCapacity = arrayBaseOffset + kvDataSize;
        dataArray = realloc(dataArray, arrayCapacity);
    }
    kvMeta.shrink_to_fit();
}


