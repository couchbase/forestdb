/* -*- Mode: C++; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2010 Couchbase, Inc
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

#ifndef _JSAHN_HBTRIE_H
#define _JSAHN_HBTRIE_H

#include "common.h"
#include "btree.h"
#include "list.h"

#ifdef __cplusplus
extern "C" {
#endif

#define HBTRIE_MAX_KEYLEN (FDB_MAX_KEYLEN_INTERNAL+16)
#define HBTRIE_HEADROOM (256)

#define _len2chunk(len) (( (len) + (chunksize-1) ) / chunksize)

typedef uint16_t chunkno_t;

typedef size_t hbtrie_func_readkey(void *handle, uint64_t offset, void *buf);
typedef int hbtrie_cmp_func(void *key1, void *key2, void* aux);
// a function pointer to a routine that returns a function pointer
typedef hbtrie_cmp_func *hbtrie_cmp_map(void *chunk, void *aux);

typedef enum {
    /**
     * HB+trie operation success.
     */
    HBTRIE_RESULT_SUCCESS,
    /**
     * Meta data in index node is corrupted.
     */
    HBTRIE_RESULT_INDEX_CORRUPTED,
    /**
     * Meta data format is too old.
     */
    HBTRIE_RESULT_INDEX_VERSION_NOT_SUPPORTED,
    /**
     * HB+trie operation fails.
     */
    HBTRIE_RESULT_FAIL
} hbtrie_result;

#define HBTRIE_FLAG_COMPACT (0x01)
struct btree_blk_ops;
struct btree_kv_ops;

/**
 * HB+trie handle definition.
 */
class HBTrie {
public:
    HBTrie();

    HBTrie(HBTrie *_trie);

    HBTrie(int _chunksize, int _valuelen, int _btree_nodesize, bid_t _root_bid,
           BTreeBlkHandle* _btreeblk_handle, void* _doc_handle, hbtrie_func_readkey* _readkey);

    ~HBTrie();

    void init(int _chunksize, int _valuelen, int _btree_nodesize, bid_t _root_bid,
              BTreeBlkHandle* _btreeblk_handle, void* _doc_handle, hbtrie_func_readkey* _readkey);

    void allocLastMapChunk() {
        last_map_chunk = (void *)malloc(chunksize);
        memset(last_map_chunk, 0xff, chunksize); // set 0xffff...
    }

    void* getLastMapChunk() const {
        return last_map_chunk;
    }

    bool setLastMapChunk(void *key);

    void resetLastMapChunk() {
        memset(last_map_chunk, 0xff, chunksize); // set 0xffff...
    }

    void freeLastMapChunk() {
        free(last_map_chunk);
    }

    void setRootBid(bid_t _root_bid) {
        root_bid = _root_bid;
    }

    bid_t getRootBid() const {
        return root_bid;
    }

    uint8_t getChunkSize() const {
        return chunksize;
    }

    uint8_t getValueLen() const {
        return valuelen;
    }

    BTreeBlkHandle* getBtreeBlkHandle() const {
        return btreeblk_handle;
    }

    void* getDocHandle() const {
        return doc_handle;
    }

    BTreeKVOps* getBtreeKvOps() const {
        return btree_kv_ops;
    }

    BTreeKVOps* getBtreeLeafKvOps() const {
        return btree_leaf_kv_ops;
    }

    uint32_t getBtreeNodeSize() const {
        return btree_nodesize;
    }

    void* getAux() const {
        return aux;
    }

    hbtrie_func_readkey* getReadKey() const {
        return readkey;
    }

    void setFlag(uint8_t _flag) {
        flag = _flag;
    }

    uint8_t getFlag() const {
        return flag;
    }

    void setLeafHeightLimit(uint8_t _limit) {
        leaf_height_limit = _limit;
    }

    uint8_t getLeafHeightLimit() const {
        return leaf_height_limit;
    }

    void setLeafCmp(btree_cmp_func* _cmp) {
        btree_leaf_kv_ops->setCmpFunc(_cmp);
    }

    void setMapFunction(hbtrie_cmp_map* _map_func) {
        map = _map_func;
    }

    hbtrie_cmp_map *getMapFunction() const {
        return map;
    }

    inline void valueSetMsb(void *value);
    inline void valueClearMsb(void *value);
    inline bool valueIsMsbSet(void *value);

    /**
     * Fetch the attributes in 'hbmeta' from 'buf'.
     *
     * @param metasize Length of 'buf'.
     * @param hbmeta Pointer to meta data structure.
     * @param buf Pointer to the raw buffer to be read.
     * @return void.
     */
    void fetchMeta(int metasize, struct hbtrie_meta *hbmeta, void *buf);

    int reformKey(void *rawkey, int rawkeylen, void *keyout);
    int reformKeyReverse(void *key, int keylen);

    hbtrie_result find(void *rawkey, int rawkeylen, void *valuebuf);
    hbtrie_result findOffset(void *rawkey, int rawkeylen, void *valuebuf);
    hbtrie_result findPartial(void *rawkey, int rawkeylen, void *valuebuf);

    hbtrie_result remove(void *rawkey, int rawkeylen);
    hbtrie_result removePartial(void *rawkey, int rawkeylen);

    hbtrie_result insert(void *rawkey, int rawkeylen,
                         void *value, void *oldvalue_out);
    hbtrie_result insertPartial(void *rawkey, int rawkeylen,
                                void *value, void *oldvalue_out);

    /**
     * Read the key of a document which is located at 'offset'.
     * This function internally calls 'trie->readkey' callback function.
     *
     * @param offset Offset of the document.
     * @param buf Pointer to buffer where the key is read.
     * @return Length of the key.
     */
    size_t readKey(uint64_t offset, void *buf);

private:
    typedef enum {
        HBMETA_NORMAL,
        HBMETA_LEAF,
    } hbmeta_opt;

    struct _key_item {
        size_t keylen;
        void *key;
        void *value;
        struct list_elem le;
    };

    uint8_t chunksize;
    uint8_t valuelen;
    uint8_t flag;
    uint8_t leaf_height_limit;
    uint32_t btree_nodesize;
    bid_t root_bid;
    BTreeBlkHandle *btreeblk_handle;
    void *doc_handle;
    void *aux;

    BTreeKVOps *btree_kv_ops;
    BTreeKVOps *btree_leaf_kv_ops;
    hbtrie_func_readkey *readkey;
    hbtrie_cmp_map *map;
    btree_cmp_args cmp_args;
    void *last_map_chunk;

    inline int getNchunkRaw(void *rawkey, int rawkeylen) const
    {
        return _len2chunk(rawkeylen) + 1;
    }

    inline int getNchunk(void *key, int keylen) const
    {
        return (keylen-1) / chunksize + 1;
    }

    /**
     * Store HB+trie meta data in a raw buffer.
     *
     * @param metasize_out Reference to a length of meta data size.
     * @param chunkno Chunk number of the HB+trie.
     * @param opt Meta data option.
     * @param prefix Skipped common prefix.
     * @param prefixlen Length of skipped common prefix.
     * @param value Value for the key which exactly matches common prefix.
     * @return void.
     */
    void storeMeta(metasize_t& metasize_out,
                   chunkno_t chunkno,
                   hbmeta_opt opt,
                   void *prefix,
                   int prefixlen,
                   void *value,
                   void *buf);

    /**
     * Find the first different chunk between given two keys.
     *
     * @param key1 First key.
     * @param key2 Second key.
     * @param start_chunk Chunk number where comparison begins.
     * @param end_chunk Chunk number where comparison ends.
     * @return First different chunk number.
     */
    int findDiffChunk(void *key1,
                      void *key2,
                      int start_chunk,
                      int end_chunk);

    /**
     * Free all B+tree instances.
     *
     * @param btreelist List for B+tree instances.
     * @return void.
     */
    void freeBtreeList(struct list *btreelist);

    /**
     * Free all B+tree instances.
     *
     * @param btreelist List for B+tree instances.
     * @return void.
     */
    void btreeCascadedUpdate(struct list *btreelist,
                             void *key);

    hbtrie_result _find(void *key, int keylen, void *valuebuf,
                        struct list *btreelist, uint8_t flag);

    hbtrie_result _remove(void *rawkey, int rawkeylen, uint8_t flag);

    /**
     * Extend given leaf B+tree (using variable-length key) so as to convert it
     * to a set of regular sub B+trees (using fixed-chunk key) of a HB+trie.
     * Note that this method is called only when 'leaf_height_limit' is greater
     * than zero, but current ForestDB does not use this functionality.
     *
     * @param btreelist List for B+tree instances.
     * @param btreeitem B+tree instance to be extended.
     * @param pre_str Prefix of the B+tree to be extended.
     * @param pre_str_len Length of the prefix.
     * @return void.
     */
    void extendLeafTree(struct list *btreelist,
                        struct btreelist_item *btreeitem,
                        void *pre_str,
                        size_t pre_str_len);

    hbtrie_result _insert(void *rawkey, int rawkeylen,
                          void *value, void *oldvalue_out,
                          uint8_t flag);


    inline void getLeafKey(void *key, void *str, size_t& len)
    {
        btree_leaf_kv_ops->getVarKey(key, str, len);
    }

    inline void setLeafKey(void *key, void *str, size_t len)
    {
        btree_leaf_kv_ops->setVarKey(key, str, len);
    }

    inline void setInfVarKey(void *key)
    {
        btree_leaf_kv_ops->setInfVarKey(key);
    }

    inline void freeLeafKey(void *key)
    {
        btree_leaf_kv_ops->freeVarKey(key);
    }

};

#define HBTRIE_ITERATOR_REV    0x01
#define HBTRIE_ITERATOR_FAILED 0x02
#define HBTRIE_ITERATOR_MOVED  0x04

/**
 * HB+trie iterator handle definition.
 */
class HBTrieIterator {
public:
    HBTrieIterator();

    HBTrieIterator(HBTrie* _trie, void *_initial_key, size_t _keylen);

    ~HBTrieIterator();

    hbtrie_result init(HBTrie* _trie, void *_initial_key, size_t _keylen);

    /**
     * Get previous key.
     *
     * @param key_buf Pointer to the buffer where key will be read.
     * @param keylen_out Reference to the length of the key.
     * @param key_buf Pointer to the buffer where value will be read.
     * @return HBTRIE_RESULT_SUCCESS on success.
     */
    hbtrie_result prev(void *key_buf, size_t& keylen_out, void *value_buf);

    /**
     * Get next key.
     *
     * @param key_buf Pointer to the buffer where key will be read.
     * @param keylen_out Reference to the length of the key.
     * @param value_buf Pointer to the buffer where value will be read.
     * @return HBTRIE_RESULT_SUCCESS on success.
     */
    hbtrie_result next(void *key_buf, size_t& keylen_out, void *value_buf);
    /**
     * Get next key. This API does not return the entire key but the sub-string
     * indexed by HB+trie only.
     *
     * @param key_buf Pointer to the buffer where key will be read.
     * @param keylen_out Reference to the length of the key.
     * @param value_buf Pointer to the buffer where value will be read.
     * @return HBTRIE_RESULT_SUCCESS on success.
     */
    hbtrie_result nextPartial(void *key_buf, size_t& keylen_out, void *value_buf);
    /**
     * Get next value only.
     *
     * @param value_buf Pointer to the buffer where value will be read.
     * @return HBTRIE_RESULT_SUCCESS on success.
     */
    hbtrie_result nextValueOnly(void *value_buf);
    /**
     * Move the iterator cursor to the end of the key space.
     *
     * @return HBTRIE_RESULT_SUCCESS on success.
     */
    hbtrie_result last();

private:
    HBTrie *trie;
    struct list btreeit_list;
    void *curkey;
    size_t keylen;
    uint8_t flags;

    hbtrie_result _prev(struct btreeit_item *item,
                        void *key_buf,
                        size_t& keylen_out,
                        void *value_buf,
                        uint8_t flag);

    hbtrie_result _next(struct btreeit_item *item,
                        void *key_buf,
                        size_t& keylen_out,
                        void *value_buf,
                        uint8_t flag);

    inline bool flagsIsRev() {
        return (flags & HBTRIE_ITERATOR_REV);
    }

    inline bool flagsIsFwd() {
        return !(flags & HBTRIE_ITERATOR_REV);
    }

    inline void flagsSetRev() {
        flags |= HBTRIE_ITERATOR_REV;
    }

    inline void flagsSetFwd() {
        flags &= ~HBTRIE_ITERATOR_REV;
    }

    inline bool flagsIsFailed() {
        return (flags & HBTRIE_ITERATOR_FAILED);
    }

    inline void flagsSetFailed() {
        flags |= HBTRIE_ITERATOR_FAILED;
    }

    inline void flagsClrFailed() {
        flags &= ~HBTRIE_ITERATOR_FAILED;
    }

    inline bool flagsIsMoved() {
        return (flags & HBTRIE_ITERATOR_MOVED);
    }

    inline void flagsSetMoved() {
        flags |= HBTRIE_ITERATOR_MOVED;
    }

    inline void getLeafKey(void *key, void *str, size_t& len)
    {
        trie->getBtreeLeafKvOps()->getVarKey(key, str, len);
    }

    inline void setLeafKey(void *key, void *str, size_t len)
    {
        trie->getBtreeLeafKvOps()->setVarKey(key, str, len);
    }

    inline void setLeafInfKey(void *key)
    {
        trie->getBtreeLeafKvOps()->setInfVarKey(key);
    }

    inline void freeLeafKey(void *key)
    {
        trie->getBtreeLeafKvOps()->freeVarKey(key);
    }

};

#ifdef __cplusplus
}
#endif

#endif
