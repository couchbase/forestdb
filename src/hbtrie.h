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

typedef size_t hbtrie_func_readkey(void *handle, uint64_t offset, void *buf);
typedef int hbtrie_cmp_func(void *key1, void *key2, void* aux);
typedef voidref hbtrie_cmp_map(void *chunk, void *aux);

typedef enum {
    HBTRIE_RESULT_SUCCESS,
    HBTRIE_RESULT_UPDATE,
    HBTRIE_RESULT_FAIL
} hbtrie_result;

#define HBTRIE_FLAG_COMPACT (0x01)
struct btree_blk_ops;
struct btree_kv_ops;
struct hbtrie {
    uint8_t chunksize;
    uint8_t valuelen;
    uint8_t flag;
    uint8_t leaf_height_limit;
    uint32_t btree_nodesize;
    bid_t root_bid;
    void *btreeblk_handle;
    void *doc_handle;
    void *aux;

    struct btree_blk_ops *btree_blk_ops;
    struct btree_kv_ops *btree_kv_ops;
    struct btree_kv_ops *btree_leaf_kv_ops;
    hbtrie_func_readkey *readkey;
    hbtrie_cmp_map *map;
    btree_cmp_args cmp_args;
    void *last_map_chunk;
};

struct hbtrie_iterator {
    struct hbtrie trie;
    struct list btreeit_list;
    void *curkey;
    size_t keylen;
    uint8_t flags;
#define HBTRIE_ITERATOR_REV    0x01
#define HBTRIE_ITERATOR_FAILED 0x02
#define HBTRIE_ITERATOR_MOVED  0x04
};

#define HBTRIE_ITR_IS_REV(iterator) \
    ((iterator)->flags & HBTRIE_ITERATOR_REV)
#define HBTRIE_ITR_IS_FWD(iterator) \
    (!((iterator)->flags & HBTRIE_ITERATOR_REV))
#define HBTRIE_ITR_SET_REV(iterator) \
    ((iterator)->flags |= HBTRIE_ITERATOR_REV)
#define HBTRIE_ITR_SET_FWD(iterator) \
    ((iterator)->flags &= ~HBTRIE_ITERATOR_REV)
#define HBTRIE_ITR_IS_FAILED(iterator) \
    ((iterator)->flags & HBTRIE_ITERATOR_FAILED)
#define HBTRIE_ITR_SET_FAILED(iterator) \
    ((iterator)->flags |= HBTRIE_ITERATOR_FAILED)
#define HBTRIE_ITR_CLR_FAILED(iterator) \
    ((iterator)->flags &= ~HBTRIE_ITERATOR_FAILED)
#define HBTRIE_ITR_IS_MOVED(iterator) \
    ((iterator)->flags & HBTRIE_ITERATOR_MOVED)
#define HBTRIE_ITR_SET_MOVED(iterator) \
    ((iterator)->flags |= HBTRIE_ITERATOR_MOVED)

int _hbtrie_reform_key(struct hbtrie *trie, void *rawkey, int rawkeylen, void *outkey);
void hbtrie_get_chunk(struct hbtrie *trie,
                      void *key,
                      int keylen,
                      int chunkno,
                      void *out);

void hbtrie_init(struct hbtrie *trie,
                 int chunksize,
                 int valuelen,
                 int btree_nodesize,
                 bid_t root_bid,
                 void *btreeblk_handle,
                 struct btree_blk_ops *btree_blk_ops,
                 void *doc_handle,
                 hbtrie_func_readkey *readkey);
void hbtrie_free(struct hbtrie *trie);

void hbtrie_set_flag(struct hbtrie *trie, uint8_t flag);
void hbtrie_set_leaf_height_limit(struct hbtrie *trie, uint8_t limit);
void hbtrie_set_leaf_cmp(struct hbtrie *trie,
                         int (*cmp)(void *key1, void *key2, void* aux));
void hbtrie_set_map_function(struct hbtrie *trie,
                             hbtrie_cmp_map *map_func);

hbtrie_result hbtrie_iterator_init(struct hbtrie *trie,
                                   struct hbtrie_iterator *it,
                                   void *initial_key,
                                   size_t keylen);
hbtrie_result hbtrie_iterator_free(struct hbtrie_iterator *it);
hbtrie_result hbtrie_last(struct hbtrie_iterator *it);
hbtrie_result hbtrie_prev(struct hbtrie_iterator *it,
                          void *key_buf,
                          size_t *keylen,
                          void *value_buf);
hbtrie_result hbtrie_next(struct hbtrie_iterator *it,
                          void *key_buf,
                          size_t *keylen,
                          void *value_buf);
hbtrie_result hbtrie_next_value_only(struct hbtrie_iterator *it,
                                 void *value_buf);

hbtrie_result hbtrie_find(struct hbtrie *trie,
                          void *rawkey,
                          int rawkeylen,
                          void *valuebuf);
hbtrie_result hbtrie_find_offset(struct hbtrie *trie,
                                 void *rawkey,
                                 int rawkeylen,
                                 void *valuebuf);
hbtrie_result hbtrie_find_partial(struct hbtrie *trie, void *rawkey,
                                  int rawkeylen, void *valuebuf);

hbtrie_result hbtrie_remove(struct hbtrie *trie, void *rawkey, int rawkeylen);
hbtrie_result hbtrie_remove_partial(struct hbtrie *trie,
                                    void *rawkey,
                                    int rawkeylen);
hbtrie_result hbtrie_insert(struct hbtrie *trie,
                            void *rawkey,
                            int rawkeylen,
                            void *value,
                            void *oldvalue_out);
hbtrie_result hbtrie_insert_partial(struct hbtrie *trie,
                                    void *rawkey, int rawkeylen,
                                    void *value, void *oldvalue_out);

#ifdef __cplusplus
}
#endif

#endif
