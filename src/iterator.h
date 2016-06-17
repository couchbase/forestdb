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

struct avl_tree;
struct avl_node;

class FdbKvsHandle;
class HBTrieIterator;
class BTreeIterator;

/**
 * ForestDB iterator cursor movement direction
 */
typedef uint8_t fdb_iterator_dir_t;
enum {
    /**
     * Iterator cursor default.
     */
    FDB_ITR_DIR_NONE = 0x00,
    /**
     * Iterator cursor moving forward
     */
    FDB_ITR_FORWARD = 0x01,
    /**
     * Iterator cursor moving backwards
     */
    FDB_ITR_REVERSE = 0x02
};

/**
 * ForestDB iterator status
 */
typedef uint8_t fdb_iterator_status_t;
enum {
    /**
     * The last returned doc was retrieved from the main index.
     */
    FDB_ITR_IDX = 0x00,
    /**
     * The last returned doc was retrieved from the WAL.
     */
    FDB_ITR_WAL = 0x01
};

/**
 * ForestDB iterator direction
 */
typedef uint8_t itr_seek_t;
enum {
    ITR_SEEK_PREV = 0x00,
    ITR_SEEK_NEXT = 0x01
};

/**
 * ForestDB iterator structure definition.
 */
class FdbIterator {
public:
    /* Fetches the iterator's kv store handle */
    FdbKvsHandle* getHandle() {
        return iterHandle;
    }

    /* Fetches the current key pointed to by the iterator */
    void* getIterKey() {
        return iterKey;
    }

    /* To initialize a regular iterator */
    static fdb_status initIterator(FdbKvsHandle *handle,
                                   fdb_iterator **ptr_iterator,
                                   const void *start_key,
                                   size_t start_keylen,
                                   const void *end_key,
                                   size_t end_keylen,
                                   fdb_iterator_opt_t opt);

    /* To initialize a sequence iterator */
    static fdb_status initSeqIterator(FdbKvsHandle *handle,
                                      fdb_iterator **ptr_iterator,
                                      const fdb_seqnum_t start_seq,
                                      const fdb_seqnum_t end_seq,
                                      fdb_iterator_opt_t opt);

    /* To close & delete an iterator */
    static fdb_status destroyIterator(fdb_iterator *iterator);

    /* Moves the iterator to specified key */
    fdb_status seek(const void *seek_key, const size_t seek_keylen,
                    const fdb_iterator_seek_opt_t seek_pref);

    /* Moves the iterator to smallest key */
    fdb_status seekToMin();

    /* Moves the iterator to largest key or sequence number*/
    fdb_status seekToMax();

    /* Moves the iterator backward by one */
    fdb_status iterateToPrev();

    /* Moves the iterator forward by one */
    fdb_status iterateToNext();

    /* Gets the item pointed to by the iterator */
    fdb_status get(fdb_doc **doc, bool metaOnly);

private:
    /* Constructor for regular iterator */
    FdbIterator(FdbKvsHandle *_handle,
                bool snapshoted_handle,
                const void *start_key,
                size_t start_keylen,
                const void *end_key,
                size_t end_keylen,
                fdb_iterator_opt_t opt);

    /* Constructor for sequence iterator */
    FdbIterator(FdbKvsHandle *_handle,
                bool snapshoted_handle,
                const fdb_seqnum_t start_seq,
                const fdb_seqnum_t end_seq,
                fdb_iterator_opt_t opt);

    /* Destructor */
    ~FdbIterator();

    /* Operation for a regular iterator to move forward/backward
       based on seek_type */
    fdb_status iterate(itr_seek_t seek_type);

    bool validateRangeLimits(void *ret_key, const size_t ret_keylen);

    /* Operation for a regular iterator to seek to largest key */
    fdb_status seekToMaxKey();

    /* Operation for a sequence iterator to seek to largest sequence number */
    fdb_status seekToMaxSeq();

    /* Operation for a sequence iterator to move backward */
    fdb_status iterateSeqPrev();

    /* Operation for a sequence iterator to move forward */
    fdb_status iterateSeqNext();

    // ForestDB KV store handle
    FdbKvsHandle *iterHandle;
    // Was this iterator created on an pre-existing snapshot handle
    bool snapshotHandle;
    // HB+Trie iterator instance
    HBTrieIterator *hbtrieIterator;
    // B+Tree iterator for sequence number iteration
    BTreeIterator *seqtreeIterator;
    // HB+Trie iterator for sequence number iteration (for multiple KV instance mode)
    HBTrieIterator *seqtrieIterator;
    // Current seqnum pointed by the iterator.
    fdb_seqnum_t seqNum;
    // WAL Iterator to iterate over the shared sharded global WAL
    WalItr *walIterator;
    // Cursor instance of WAL iterator.
    struct wal_item *treeCursor;
    // Unique starting AVL node indicating the WAL iterator's start node.
    struct wal_item *treeCursorStart;
    // Previous position of WAL cursor.
    struct wal_item *treeCursorPrev;
    // Iterator start key.
    void *startKey;
    union {
        // Iterator start seqnum.
        fdb_seqnum_t startSeqnum;
        // Start key length.
        size_t startKeylen;
    };
    // Iterator end key.
    void *endKey;
    union {
        // Iterator end seqnum.
        fdb_seqnum_t endSeqnum;
        // End key length.
        size_t endKeylen;
    };
    // Iterator option.
    fdb_iterator_opt_t iterOpt;
    // Iterator cursor direction status.
    fdb_iterator_dir_t iterDirection;
    // The last returned document info.
    fdb_iterator_status_t iterStatus;
    // Current key pointed by the iterator.
    void *iterKey;
    // Length of key pointed by the iterator.
    size_t iterKeylen;
    // Key offset.
    uint64_t iterOffset;
    // Doc IO handle instance to the correct file.
    DocioHandle *dHandle;
    // Cursor offset to key, meta and value on disk
    uint64_t getOffset;
};

