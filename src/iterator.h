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
 * ForestDB iterator structure definition.
 */
class FdbIterator {
public:
    FdbIterator(bool use_sequence_tree)
        : handle(nullptr), hbtrie_iterator(nullptr),
          seqtree_iterator(nullptr), seqtrie_iterator(nullptr),
          _seqnum(0), wal_itr(nullptr), tree_cursor(nullptr),
          tree_cursor_start(nullptr), tree_cursor_prev(nullptr),
          start_key(nullptr), end_key(nullptr),
          opt(FDB_ITR_NONE), direction(FDB_ITR_DIR_NONE),
          status(0x00), snapshot_handle(false), _key(nullptr),
          _keylen(0), _offset(0), _dhandle(nullptr), _get_offset(0)
    {
        if (use_sequence_tree) {
            start_seqnum = 0;
            end_seqnum = 0;
        } else {
            start_keylen = 0;
            end_keylen = 0;
        }
    }

    ~FdbIterator() { }

    /**
     * ForestDB KV store handle.
     */
    FdbKvsHandle *handle;
    /**
     * HB+Trie iterator instance.
     */
    HBTrieIterator *hbtrie_iterator;
    /**
     * B+Tree iterator for sequence number iteration
     */
    BTreeIterator *seqtree_iterator;
    /**
     * HB+Trie iterator for sequence number iteration
     * (for multiple KV instance mode)
     */
    HBTrieIterator *seqtrie_iterator;
    /**
     * Current seqnum pointed by the iterator.
     */
    fdb_seqnum_t _seqnum;
    /**
     * WAL Iterator to iterate over the shared sharded global WAL
     */
    WalItr *wal_itr;
    /**
     * Cursor instance of WAL iterator.
     */
    struct wal_item *tree_cursor;
    /**
     * Unique starting AVL node indicating the WAL iterator's start node.
     */
    struct wal_item *tree_cursor_start;
    /**
     * Previous position of WAL cursor.
     */
    struct wal_item *tree_cursor_prev;
    /**
     * Iterator start key.
     */
    void *start_key;
    union {
        /**
         * Iterator start seqnum.
         */
        fdb_seqnum_t start_seqnum;
        /**
         * Start key length.
         */
        size_t start_keylen;
    };
    /**
     * Iterator end key.
     */
    void *end_key;
    union {
        /**
         * Iterator end seqnum.
         */
        fdb_seqnum_t end_seqnum;
        /**
         * End key length.
         */
        size_t end_keylen;
    };
    /**
     * Iterator option.
     */
    fdb_iterator_opt_t opt;
    /**
     * Iterator cursor direction status.
     */
    fdb_iterator_dir_t direction;
    /**
     * The last returned document info.
     */
    fdb_iterator_status_t status;
    /**
     * Was this iterator created on an pre-existing snapshot handle
     */
    bool snapshot_handle;
    /**
     * Current key pointed by the iterator.
     */
    void *_key;
    /**
     * Length of key pointed by the iterator.
     */
    size_t _keylen;
    /**
     * Key offset.
     */
    uint64_t _offset;
    /**
     * Doc IO handle instance to the correct file.
     */
    DocioHandle *_dhandle;
    /**
     * Cursor offset to key, meta and value on disk
     */
    uint64_t _get_offset;
};

