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
#include "btree_new.h"
#include "list.h"
#include "memory_pool.h"

#include <unordered_map>

#ifdef __cplusplus
extern "C" {
#endif

#define HBTRIE_MAX_KEYLEN (FDB_MAX_KEYLEN_INTERNAL+16)
#define HBTRIE_HEADROOM (256)

#define _len2chunk(len) (( (len) + (chunksize-1) ) / chunksize)


typedef uint16_t chunkno_t;

// Flag that indicates if given B+tree is based on
// custom compare function or not.
#define CUSTOM_COMPARE_MODE (0x8000)

struct hbtrie_meta {
    bool isCustomCmpBtree() {
        return chunkno & CUSTOM_COMPARE_MODE;
    }

    chunkno_t chunkno;
    uint16_t prefix_len;
    uint8_t value_len;
    void *value;
    void *prefix;
};


/**
 * Callback function for HB+trie, to fetch the entire full key string.
 *
 * @param handle DocIO handle.
 * @param offset Offset of document (pure value from the node, not endian decoded).
 * @param req_key Key to be found, inserted, or removed, requested by user.
 * @param chunk Current chunk.
 * @param curchunkno Current chunk number.
 * @param buf Buffer that the full key will be returned.
 * @return Length of key.
 */
typedef size_t hbtrie_func_readkey(void *handle,
                                   uint64_t offset,
                                   void *req_key,
                                   void *chunk,
                                   size_t curchunkno,
                                   void *buf);
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
class FileMgr;
class BnodeMgr;


// Flag that HBTrieValue contains a sub B+tree root offset.
#define HV_SUB_TREE (0x80)
// Flag that root node of sub B+tree is dirty.
#define HV_DIRTY_ROOT (0x40)
// Flag that HBTrieValue contains a variable-length data,
// which is greater than 8 bytes.
#define HV_VLEN_DATA (0x20)
// Flag that HBTrieValue contains a document offset.
#define HV_DOC (0x0)

/**
 * Wrapper for HB+trie internal value.
 *
 * it can contain
 *   document offset                               (flags == 0x00)
 *   document metadata including disk offset       (flags == 0x00 | 0x20)
 *   disk offset of clean root node of sub-tree    (flags == 0x80)
 *   memory pointer of dirty root node of sub-tree (flags == 0x80 | 0x40)
 */
class HBTrieValue {
public:
    // default constructor
    HBTrieValue() :
        flags(0x0), valueLen(0), offset(0x0), binary(nullptr) { }

    // directly assign offset integer and flags
    HBTrieValue(uint8_t _flags, uint64_t _offset) :
        flags(_flags), valueLen(sizeof(offset)),
        offset(_offset), binary(nullptr) { }

    // assign offset from (encoded) binary data given by caller
    HBTrieValue(uint8_t _flags, void *encoded_offset) :
        flags(_flags), valueLen(sizeof(offset)), binary(nullptr)
    {
        offset = *(reinterpret_cast<uint64_t*>(encoded_offset));
        offset = _endian_decode(offset);
    }

    // assign variable-length value data given by caller
    HBTrieValue(uint8_t _flags,
                void *_value,
                size_t _value_len) :
        flags(_flags), valueLen(sizeof(offset)), offset(0), binary(nullptr)
    {
        if (flags & HV_VLEN_DATA) {
            // variable-length binary data
            binary = _value;
            valueLen = _value_len;
        } else {
            // otherwise: 8-byte offset
            offset = *(reinterpret_cast<uint64_t*>(_value));
            offset = _endian_decode(offset);
        }
    }

    // assign offset (or pointer) using node addr info
    HBTrieValue(BtreeNodeAddr _addr) :
        valueLen(sizeof(offset)), binary(nullptr) {
        flags = HV_SUB_TREE;
        if (_addr.isDirty) {
            // dirty node (store pointer address)
            offset = reinterpret_cast<uint64_t>(_addr.ptr);
            flags |= HV_DIRTY_ROOT;
        } else {
            // clean node (store offset)
            offset = _addr.offset;
        }
    }

    // parse & import variable-length data from raw HB+trie binary
    HBTrieValue(void* value_from_hbtrie, size_t value_len_from_hbtrie) :
        valueLen(sizeof(offset)), offset(0), binary(nullptr) {
        uint8_t *ptr = reinterpret_cast<uint8_t*>(value_from_hbtrie);
        flags = *ptr;
        if (flags & HV_VLEN_DATA) {
            // variable-length data
            valueLen = value_len_from_hbtrie - sizeof(flags);
            binary = ptr + sizeof(flags);
        } else {
            // offset
            offset = *( reinterpret_cast<uint64_t*>(ptr+sizeof(flags)) );
            offset = _endian_decode(offset);
        }
    }

    // export to raw binary including flags
    // (9 bytes, for internal use inside HB+trie)
    void *toBinary(void *buf) {
        if (!buf) {
            return nullptr;
        }
        uint8_t *ptr8 = static_cast<uint8_t*>(buf);
        *ptr8 = flags;
        if (flags & HV_VLEN_DATA) {
            memcpy(ptr8+sizeof(flags), binary, valueLen);
        } else {
            // offset
            uint64_t *ptr64 = reinterpret_cast<uint64_t*>(ptr8+sizeof(flags));
            *ptr64 = _endian_encode(offset);
        }
        return buf;
    }

    // export to raw binary excluding flags
    // (8 bytes, for return value outside HB+trie)
    void *toBinaryWithoutFlags(void *buf) {
        if (!buf) {
            return nullptr;
        }
        if (flags & HV_VLEN_DATA) {
            // variable-length data
            memcpy(buf, binary, valueLen);
        } else {
            // 8-byte offset
            uint64_t *ptr64 = reinterpret_cast<uint64_t*>(buf);
            *ptr64 = _endian_encode(offset);
        }
        return buf;
    }

    bool isSubtree() {
        return flags & HV_SUB_TREE;
    }

    bool isDirtyRoot() {
        return flags & HV_DIRTY_ROOT;
    }

    bool isVlenData() {
        return flags & HV_VLEN_DATA;
    }

    uint64_t getOffset() const {
        return offset;
    }
    Bnode* getChildPtr() const {
        return reinterpret_cast<Bnode*>(offset);
    }

    size_t size() const {
        return sizeof(flags)+valueLen;
    }
    size_t sizeWithoutFlags() const {
        return valueLen;
    }

private:
    // Flags
    uint8_t flags;
    // Value length (8 bytes if value is offset or pointer);
    uint8_t valueLen;
    // Offset (or pointer) to document or child B+tree.
    uint64_t offset;
    // Variable-length binary data if value is not an offset.
    void *binary;
};


/**
 * Parameters for BtreeV2 related funcitons.
 */
struct HBTrieV2Args {
    HBTrieV2Args() :
        prevChunkNo(0), rootAddr() { }

    HBTrieV2Args(size_t _prev_chunk_no, BtreeNodeAddr _root_addr) :
        prevChunkNo(_prev_chunk_no), rootAddr(_root_addr) { }

    // Previous (caller) function's chunk number.
    size_t prevChunkNo;
    // Current (callee) function's B+tree root info.
    BtreeNodeAddr rootAddr;
};

/**
 * Parameters for sub-functions of insertV2.
 */
struct HBTrieInsV2Args {
    HBTrieInsV2Args(HBTrieV2Args& _caller_args,
                    BtreeV2& _cur_tree,
                    hbtrie_meta& _hbmeta,
                    size_t _cur_chunk_no) :
        callerArgs(_caller_args),
        curTree(_cur_tree),
        hbMeta(_hbmeta),
        curChunkNo(_cur_chunk_no),
        suffixLen(0),
        kvFromBtree() { }

    HBTrieInsV2Args(HBTrieV2Args& _caller_args,
                    BtreeV2& _cur_tree,
                    hbtrie_meta& _hbmeta,
                    size_t _cur_chunk_no,
                    size_t _suffix_len,
                    BtreeKvPair _kv_from_btree) :
        callerArgs(_caller_args),
        curTree(_cur_tree),
        hbMeta(_hbmeta),
        curChunkNo(_cur_chunk_no),
        suffixLen(_suffix_len),
        kvFromBtree(_kv_from_btree) { }

    // Parameters given by caller function.
    HBTrieV2Args& callerArgs;
    // Current B+tree.
    BtreeV2& curTree;
    // Current B+tree's meta data.
    hbtrie_meta& hbMeta;
    // Current chunk number.
    size_t curChunkNo;
    // Suffix length of the given key.
    size_t suffixLen;
    // Existing key from the current B+tree.
    BtreeKvPair kvFromBtree;
};

/**
 * Return values for BtreeV2 related recursive funcitons.
 *
 * Note that this structure is used as a local return value for parent function
 * on the recursive call stack. For example, parent tree itself should be
 * updated when its child tree has been changed after the recursive function
 * call, then we can get the child node's updates using this structure from the
 * callee function.
 */
struct HBTrieV2Rets {
    HBTrieV2Rets() :
        rootAddr() { }

    HBTrieV2Rets(BtreeNodeAddr _root_addr) :
        rootAddr(_root_addr) { }

    // Current (callee) B+tree root info.
    BtreeNodeAddr rootAddr;
};

// A callback function that returns custom compare function pointer
// corresponding to the given KVS ID.
typedef btree_new_cmp_func* HBTrieV2GetCmpFunc(HBTrie *hbtrie,
                                               uint64_t kvs_id,
                                               void *aux);

/**
 * HB+trie handle definition.
 */
class HBTrie {
public:
    HBTrie();

    HBTrie(HBTrie *_trie);

    HBTrie(int _chunksize, int _valuelen, int _btree_nodesize, bid_t _root_bid,
           BTreeBlkHandle* _btreeblk_handle, void* _doc_handle,
           hbtrie_func_readkey* _readkey);

    HBTrie(int _chunksize, int _btree_nodesize,
           BtreeNodeAddr _root_addr, BnodeMgr* _bnodeMgr, FileMgr *_file);

    ~HBTrie();

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

    BtreeNodeAddr getRootAddr() const {
        return rootAddr;
    }

    void setRootAddr(BtreeNodeAddr _root_addr) {
        rootAddr = _root_addr;
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

    BnodeMgr *getBnodeMgr() const {
        return bnodeMgr;
    }

    FileMgr *getFileMgr() const {
        return fileHB;
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

    void setCmpFuncCB(HBTrieV2GetCmpFunc *cb_func) {
        getCmpFuncCB = cb_func;
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
    hbtrie_result find_vlen(void *rawkey, int rawkeylen,
                            void *valuebuf, size_t *value_len_out);
    hbtrie_result findOffset(void *rawkey, int rawkeylen, void *valuebuf);
    hbtrie_result findPartial(void *rawkey, int rawkeylen, void *valuebuf);

    hbtrie_result remove(void *rawkey, int rawkeylen);
    hbtrie_result removePartial(void *rawkey, int rawkeylen);
    hbtrie_result remove_vlen(void *rawkey, int rawkeylen,
                              void *valuebuf, size_t *value_len_out);

    hbtrie_result insert(void *rawkey, int rawkeylen,
                         void *value, void *oldvalue_out);
    hbtrie_result insert_vlen(void *rawkey,
                              size_t rawkeylen,
                              void *value,
                              size_t value_len,
                              void *oldvalue_out,
                              size_t *oldvalue_len_out);
    hbtrie_result insertPartial(void *rawkey, int rawkeylen,
                                void *value, void *oldvalue_out);

    /**
     * Recursively write all dirty nodes in the HB+trie.
     *
     * @return HBTRIE_RESULT_SUCCESS on success.
     */
    hbtrie_result writeDirtyNodes();

    /**
     * Read the key of a document which is located at 'offset'.
     * This function internally calls 'trie->readkey' callback function.
     *
     * @param offset Offset of the document.
     * @param buf Pointer to buffer where the key is read.
     * @return Length of the key.
     */
    size_t readKey(uint64_t offset, void *buf);

    /**
     * Initializes a global memory pool whose reusable memory bins
     * will be used to temporarily store raw keys.
     */
    static void initMemoryPool(size_t num_cores, uint64_t buffercache_size);

    /**
     * Deallocates all the memory from the pool.
     */
    static void shutdownMemoryPool();

    /**
     * Assigns a preallocated fixed size memory bin to the buffer.
     * If in the case of no available memory bins, memory is allocated
     * for the buffer on the stack, and on the heap just for windows as
     * stack overflow issues are sometimes seen (due to smaller stack
     * size).
     *
     * Returns the index of the memory bin assigned (used for deallocation),
     * if in case memory was allocated, index will be -1.
     */
    static const int allocateBuffer(uint8_t **buf);

    /**
     * Returns the bin at the specific index to the memory pool in case of
     * a non-negative index. If index is negative (-1), the memory is
     * freed (only for windows).
     */
    static void deallocateBuffer(uint8_t **buf, int index);

    /**
     * Return the size of HB+trie internal value.
     *
     * @return Size of HB+trie internal value.
     */
    static size_t getHvSize() {
        return HV_SIZE;
    }

    /**
     * Check if given HB+trie internal value is a pointer to a dirty child tree.
     *
     * @param value HB+trie internal value.
     * @return True if dirty child tree.
     */
    static bool isDirtyChildTree(void *value) {
        // get the first 1 byte.
        uint8_t flag = *(static_cast<uint8_t*>(value));
        uint8_t mask = HV_SUB_TREE | HV_DIRTY_ROOT;
        return flag == mask;
    }

private:
    // HB+trie internal value size (9 bytes)
    static const size_t HV_SIZE;
    // Max size of the buffer for HB+trie internal value (256 bytes)
    static const size_t HV_BUF_MAX_SIZE;

    // Memory Pool
    static MemoryPool* hbtrieMP;

    /**
     * Wrapper class for allocateBuffer()/deallocateBuffer().
     */
    class MPWrapper {
    public:
        MPWrapper() :
            buffer(nullptr), idx(-1) { }
        ~MPWrapper() {
            if (buffer) {
                deallocateBuffer(&buffer, idx);
            }
        }

        void allocate() {
            idx = allocateBuffer(&buffer);
        }
        uint8_t *getAddr() const {
            return buffer;
        }

    private:
        uint8_t *buffer;
        int idx;
    };

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
    // root node BID for old format.
    bid_t root_bid;
    // root offset (or pointer) for V2 format.
    BtreeNodeAddr rootAddr;
    union {
        BTreeBlkHandle *btreeblk_handle;
        BnodeMgr *bnodeMgr;
    };
    FileMgr *fileHB;
    void *doc_handle;
    void *aux;

    BTreeKVOps *btree_kv_ops;
    BTreeKVOps *btree_leaf_kv_ops;
    hbtrie_func_readkey *readkey;
    hbtrie_cmp_map *map;
    btree_cmp_args cmp_args;
    void *last_map_chunk;

    /**
     * Local map of {KVS ID, assigned custom compare function pointer}.
     * If given KVS doesn't use custom compare function, then 'nullptr' is
     * stored.
     * However, a new KVS can be added at the runtime, and we should
     * reflect the new KVS custom compare function info into 'cmpFuncMap'.
     * In that case, we invoke 'getCmpFuncCB' below, get the new
     * custom function info, and insert the pair into the map.
     */
    std::unordered_map<uint64_t, btree_new_cmp_func*> cmpFuncMap;

    /**
     * Callback function given by ForestDB handle.
     * It returns custom compare function corresponding to the given
     * first chunk, which stores KVS ID.
     */
    HBTrieV2GetCmpFunc *getCmpFuncCB;


    /**
     * Internal common HBTrie constructor initialization
     */
    void initTrie(int _chunksize, int _valuelen, int _btree_nodesize,
                  bid_t _root_bid, BtreeNodeAddr _root_addr,
                  void* _btreestorage_handle,
                  FileMgr *_file, void* _doc_handle,
                  hbtrie_func_readkey* _readkey);

    inline int getNchunkRaw(void *rawkey, int rawkeylen) const
    {
        return _len2chunk(rawkeylen) + 1;
    }

    inline int getNchunk(void *key, int keylen) const
    {
        return (keylen-1) / chunksize + 1;
    }

    /**
     * Estimate B+tree meta data size for given value and prefix length.
     *
     * @param value Value that will be stored in the meta section of B+tree.
     * @param value_len Length of value that will be stored in the meta
     *        section of B+tree.
     * @param prefix_len Length of prefix that will be stored in the meta
     *        section of B+tree.
     * @return Size of meta data.
     */
    metasize_t estMetaSize(void *value,
                           uint8_t value_len,
                           uint16_t prefix_len);

    /**
     * Store HB+trie meta data in a raw buffer.
     *
     * @param metasize_out Reference to a length of meta data size.
     * @param chunkno Chunk number of the HB+trie.
     * @param opt Meta data option.
     * @param prefix Skipped common prefix.
     * @param prefixlen Length of skipped common prefix.
     * @param value Value for the key which exactly matches common prefix.
     * @param value_length Length of value.
     * @return void.
     */
    void storeMeta(metasize_t& metasize_out,
                   chunkno_t chunkno,
                   hbmeta_opt opt,
                   void *prefix,
                   int prefixlen,
                   void *value,
                   uint8_t value_length,
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

    /**
     * Internal retrieval function based on BtreeV2.
     *
     * @param rawkey Key to find.
     * @param rawkeylen Length of key.
     * @param given_valuebuf Buffer that value will be returned as a result
     *        of this API call.
     * @param value_len_out Length of value that will be returned as a result
     *        of this API call.
     * @param args Additional parameters.
     * @param rets Local return value to the parent function on the
     *        recursive stack.
     * @param remove_key Flag to remove the found key.
     * @return HBTRIE_RESULT_SUCCESS on success.
     */
    hbtrie_result _findV2(void *rawkey,
                          size_t rawkeylen,
                          void *given_valuebuf,
                          size_t *value_len_out,
                          HBTrieV2Args args,
                          HBTrieV2Rets& rets,
                          bool remove_key);

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

    /**
     * Convert local B+tree result and return corresponding HB+trie result.
     *
     * @param br B+tree operation result.
     * @return HBTRIE_RESULT_SUCCESS on success.
     */
    hbtrie_result convertBtreeResult(BtreeV2Result br);

    /**
     * Set HBTrieV2Rets (third param) value to the root address of
     * the current tree (second param), if hr (first param) is SUCCESS.
     *
     * @param hr HB+trie operation result.
     * @param cur_btree Current B+tree.
     * @param rets Local return value to caller.
     * @return Given result value.
     */
    hbtrie_result setLocalReturnValue(hbtrie_result hr,
                                      BtreeV2& cur_btree,
                                      HBTrieV2Rets& rets);

    /**
     * Get custom compare function corresponding to the KVS ID
     * that is located at the beginning of the given key.
     * If there is no assigned custom function, then return nullptr.
     *
     * @param rawkey Key.
     * @return Custom compare function pointer.
     */
    btree_new_cmp_func* getCmpFuncForGivenKey(void *rawkey);

    /**
     * Internal insertion function based on BtreeV2.
     *
     * @param rawkey Key to insert.
     * @param rawkeylen Length of key.
     * @param given_value Value to insert.
     * @param given_value_len Length of value to insert.
     * @param oldvalue_out Old value that will be returned as a result of
     *        API call.
     * @param oldvalue_len_out Length of old value that will be returned as a
     *        result of API call.
     * @param args Additional parameters.
     * @param rets Local return value to the parent function on the
     *        recursive stack.
     * @param flag Insertion option.
     * @return HBTRIE_RESULT_SUCCESS on success.
     */
    hbtrie_result _insertV2(void *rawkey, size_t rawkeylen,
                            void *given_value, size_t given_value_len,
                            void *oldvalue_out, size_t *oldvalue_len_out,
                            HBTrieV2Args args,
                            HBTrieV2Rets& rets,
                            uint8_t flag);

    /**
     * Internal insertion function for the case 2 described in _insertV2().
     *
     * @param rawkey Key to insert.
     * @param rawkeylen Length of key.
     * @param given_value Value to insert.
     * @param given_value_len Length of value to insert.
     * @param oldvalue_out Old value that will be returned as a result of
     *        API call.
     * @param oldvalue_len_out Length of old value that will be returned as a
     *        result of API call.
     * @param ins_args Additional parameters for insertion.
     * @param rets Local return value to the parent function on the
     *        recursive stack.
     * @param flag Insertion option.
     * @return HBTRIE_RESULT_SUCCESS on success.
     */
    hbtrie_result _insertV2Case2(void *rawkey, size_t rawkeylen,
                                 void *given_value, size_t given_value_len,
                                 void *oldvalue_out, size_t *oldvalue_len_out,
                                 HBTrieInsV2Args& ins_args,
                                 HBTrieV2Rets& rets,
                                 uint8_t flag);

    /**
     * Internal insertion function for the case 3 described in _insertV2().
     *
     * @param rawkey Key to insert.
     * @param rawkeylen Length of key.
     * @param given_value Value to insert.
     * @param given_value_len Length of value to insert.
     * @param oldvalue_out Old value that will be returned as a result of
     *        API call.
     * @param oldvalue_len_out Length of old value that will be returned as a
     *        result of API call.
     * @param ins_args Additional parameters for insertion.
     * @param rets Local return value to the parent function on the
     *        recursive stack.
     * @param flag Insertion option.
     * @return HBTRIE_RESULT_SUCCESS on success.
     */
    hbtrie_result _insertV2Case3(void *rawkey, size_t rawkeylen,
                                 void *given_value, size_t given_value_len,
                                 void *oldvalue_out, size_t *oldvalue_len_out,
                                 HBTrieInsV2Args& ins_args,
                                 HBTrieV2Rets& rets,
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
