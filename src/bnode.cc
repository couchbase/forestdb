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

INLINE int _bnode_cmp(avl_node *a, struct avl_node *b, void *aux)
{
    BtreeKv *aa, *bb;
    aa = _get_entry(a, BtreeKv, avl);
    bb = _get_entry(b, BtreeKv, avl);

    if (aa->keylen == bb->keylen) {
        return memcmp(aa->key, bb->key, aa->keylen);
    } else {
        size_t len = MIN(aa->keylen, bb->keylen);
        int cmp = memcmp(aa->key, bb->key, len);
        if (cmp != 0) {
            return cmp;
        } else {
            return static_cast<int>( static_cast<int>(aa->keylen) -
                                     static_cast<int>(bb->keylen) );
        }
    }
}

Bnode::~Bnode()
{
    BtreeKv *kvp;
    auto entry = avl_first(&kvIdx);
    while (entry) {
        kvp = _get_entry(entry, BtreeKv, avl);
        entry = avl_next(entry);
        avl_remove(&kvIdx, &kvp->avl);

        delete kvp;
    }

    if (!metaExistingMemory) {
        free(meta);
    }
}

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
                     size_t meta_size,
                     bool use_existing_memory )
{
    if (meta && !metaExistingMemory) {
        free(meta);
    }

    metaExistingMemory = use_existing_memory;
    if (metaExistingMemory) {
        meta = new_meta;
    } else {
        meta = (void*)malloc(meta_size);
        memcpy(meta, new_meta, meta_size);
    }
}

BnodeResult Bnode::addKv( void *key,
                          size_t keylen,
                          void *value,
                          size_t valuelen,
                          Bnode *child_ptr,
                          bool inc_nentry,
                          bool use_existing_memory )
{
    BnodeResult ret = inputSanityCheck(key, keylen, value, valuelen, child_ptr);
    if (ret != BnodeResult::SUCCESS) {
        return ret;
    }

    BtreeKv *kvp = new BtreeKv( key, keylen,
                                value, valuelen,
                                child_ptr, use_existing_memory);

    avl_insert(&kvIdx, &kvp->avl, _bnode_cmp);

    if (inc_nentry) {
        nentry++;
        nodeSize += kvp->getKvSize();
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

    BtreeKv *kvp, query;
    query.key = key;
    query.keylen = keylen;
    auto entry = avl_search(&kvIdx, &query.avl, _bnode_cmp);
    if (!entry) {
        return BnodeResult::KEY_NOT_FOUND;
    }
    kvp = _get_entry(entry, BtreeKv, avl);
    valuelen_out = kvp->valuelen;
    value_out = kvp->value;
    ptr_out = kvp->child_ptr;

    return BnodeResult::SUCCESS;
}

BnodeResult Bnode::removeKv( void *key,
                             size_t keylen )
{
    BnodeResult ret = inputSanityCheck(key, keylen, NULL, 0, NULL, false);
    if (ret != BnodeResult::SUCCESS) {
        return ret;
    }

    BtreeKv *kvp, query;
    query.key = key;
    query.keylen = keylen;
    auto entry = avl_search(&kvIdx, &query.avl, _bnode_cmp);
    if (!entry) {
        return BnodeResult::KEY_NOT_FOUND;
    }
    kvp = _get_entry(entry, BtreeKv, avl);
    avl_remove(&kvIdx, entry);

    nentry--;
    nodeSize -= kvp->getKvSize();
    delete kvp;

    return BnodeResult::SUCCESS;
}

BnodeResult Bnode::exportRaw(void *buf)
{
    if ( !buf ) {
        return BnodeResult::INVALID_BUFFER;
    }

    uint8_t *ptr = static_cast<uint8_t*>(buf);
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
    offset += sizeof(enc16);

    // metadata
    memcpy(ptr + offset, meta, metaSize);
    offset += metaSize;

    // KV pairs
    BtreeKv *kvp;
    auto entry = avl_first(&kvIdx);
    while (entry) {
        kvp = _get_entry(entry, BtreeKv, avl);
        entry = avl_next(entry);

        // keylen
        enc16 = _endian_encode(kvp->keylen);
        memcpy(ptr + offset, &enc16, sizeof(enc16));
        offset += sizeof(enc16);

        // valuelen
        enc16 = _endian_encode(kvp->valuelen);
        memcpy(ptr + offset, &enc16, sizeof(enc16));
        offset += sizeof(enc16);

        // key
        memcpy(ptr + offset, kvp->key, kvp->keylen);
        offset += kvp->keylen;

        // value
        memcpy(ptr + offset, kvp->value, kvp->valuelen);
        offset += kvp->valuelen;
    }

    return BnodeResult::SUCCESS;
}

BnodeResult Bnode::importRaw(void *buf, bool use_existing_memory)
{
    // bnode should be empty
    if (avl_first(&kvIdx)) {
        return BnodeResult::NODE_IS_NOT_EMPTY;
    }

    if ( !buf ) {
        return BnodeResult::INVALID_BUFFER;
    }

    uint8_t *ptr = static_cast<uint8_t*>(buf);
    uint16_t enc16;
    uint32_t enc32;
    size_t offset = 0;

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
    if (use_existing_memory) {
        meta = ptr + offset;
    } else {
        meta = (void *)malloc(metaSize);
        memcpy(meta, ptr + offset, metaSize);
    }
    metaExistingMemory = use_existing_memory;
    offset += metaSize;

    // KV pairs
    uint16_t keylen, valuelen;
    void *key, *value;
    int i;

    for (i=0; i<nentry; ++i) {
        keylen = *( reinterpret_cast<uint16_t*>(ptr + offset) );
        keylen = _endian_decode(keylen);
        offset += sizeof(uint16_t);

        valuelen = *( reinterpret_cast<uint16_t*>(ptr + offset) );
        valuelen = _endian_decode(valuelen);
        offset += sizeof(uint16_t);

        key = static_cast<void *>(ptr + offset);
        value = static_cast<void *>(ptr + offset + keylen);
        offset += keylen;
        offset += valuelen;

        addKv(key, keylen, value, valuelen, nullptr, false, use_existing_memory);
    }

    return BnodeResult::SUCCESS;
}

size_t Bnode::readNodeSize(void *buf)
{
    // read the first 4 bytes
    uint32_t enc32 = *( reinterpret_cast<uint32_t*>(buf) );
    return _endian_decode(enc32);
}


BnodeIterator::BnodeIterator(Bnode *_bnode)
{
    bnode = _bnode;
    // start with the first key.
    begin();
}

BnodeIterator::BnodeIterator( Bnode *_bnode,
                              void *start_key,
                              size_t start_keylen )
{
    bnode = _bnode;
    // start with equal to or greater than 'start_key'.
    seekGreaterOrEqual(start_key, start_keylen);
}

BnodeIteratorResult BnodeIterator::fetchKvp( avl_node *entry )
{
    if (!entry) {
        curKvp = nullptr;
        return BnodeIteratorResult::NO_MORE_ENTRY;
    }

    curKvp = _get_entry(entry, BtreeKv, avl);
    return BnodeIteratorResult::SUCCESS;
}

BnodeIteratorResult BnodeIterator::seekGreaterOrEqual( void *key,
                                                       size_t keylen )
{
    if (!bnode) {
        return BnodeIteratorResult::INVALID_NODE;
    }

    BtreeKv query;
    query.key = key;
    query.keylen = keylen;

    auto entry = avl_search_greater(&bnode->kvIdx, &query.avl, _bnode_cmp);
    return fetchKvp(entry);
}

BnodeIteratorResult BnodeIterator::seekSmallerOrEqual( void *key,
                                                       size_t keylen )
{
    if (!bnode) {
        return BnodeIteratorResult::INVALID_NODE;
    }

    BtreeKv query;
    query.key = key;
    query.keylen = keylen;

    auto entry = avl_search_smaller(&bnode->kvIdx, &query.avl, _bnode_cmp);
    return fetchKvp(entry);
}

BnodeIteratorResult BnodeIterator::begin()
{
    if (!bnode) {
        return BnodeIteratorResult::INVALID_NODE;
    }

    auto entry = avl_first(&bnode->kvIdx);
    return fetchKvp(entry);
}

BnodeIteratorResult BnodeIterator::end()
{
    if (!bnode) {
        return BnodeIteratorResult::INVALID_NODE;
    }

    auto entry = avl_last(&bnode->kvIdx);
    return fetchKvp(entry);
}

BnodeIteratorResult BnodeIterator::prev()
{
    auto entry = avl_prev( &curKvp->avl );
    return fetchKvp(entry);
}

BnodeIteratorResult BnodeIterator::next()
{
    auto entry = avl_next( &curKvp->avl );
    return fetchKvp(entry);
}



