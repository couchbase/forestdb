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

#ifndef _JSAHN_BTREE_FAST_STR_KV_H
#define _JSAHN_BTREE_FAST_STR_KV_H

#include <stdint.h>
#include "common.h"

#include "btree.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * B+tree key-value operation class for variable-length string key.
 * Note that it can be also used for custom (non-lexicographical) order operations.
 */
class FastStrKVOps : public BTreeKVOps {
public:
    FastStrKVOps();
    FastStrKVOps(size_t _ksize, size_t _vsize);
    FastStrKVOps(size_t _ksize, size_t _vsize, btree_cmp_func _cmp_func);

    virtual ~FastStrKVOps() { }

    void init(size_t _ksize, size_t _vsize, btree_cmp_func _cmp_func);

    void getKV(struct bnode *node, idx_t idx, void *key, void *value);
    void setKV(struct bnode *node, idx_t idx, void *key, void *value);
    void insKV(struct bnode *node, idx_t idx, void *key, void *value);
    void copyKV(struct bnode *node_dst,
                struct bnode *node_src,
                idx_t dst_idx,
                idx_t src_idx,
                idx_t len);
    size_t getDataSize(struct bnode *node,
                       void *new_minkey,
                       void *key_arr,
                       void *value_arr,
                       size_t len);
    size_t getKVSize(void *key, void *value);
    void initKVVar(void *key, void *value);
    void freeKVVar(void *key, void *value);
    void setKey(void *dst, void *src);
    void setValue(void *dst, void *src);
    idx_t getNthIdx(struct bnode *node, idx_t num, idx_t den);
    void getNthSplitter(struct bnode *prev_node,
                        struct bnode *node,
                        void *key);

    void setVarKey(void *key, void *str, size_t len);
    void setInfVarKey(void *key);
    bool isInfVarKey(void *key);
    void getVarKey(void *key, void *strbuf, size_t& len);
    void freeVarKey(void *key);
};


#ifdef __cplusplus
}
#endif

#endif
