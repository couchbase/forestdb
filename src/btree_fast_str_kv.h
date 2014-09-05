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

#ifdef __cplusplus
extern "C" {
#endif

void btree_fast_str_kv_set_key(void *key, void *str, size_t len);
void btree_fast_str_kv_set_inf_key(void *key);
int btree_fast_str_kv_is_inf_key(void *key);
void btree_fast_str_kv_get_key(void *key, void *strbuf, size_t *len);
void btree_fast_str_kv_free_key(void *key);

struct btree_kv_ops;
struct btree_kv_ops *btree_fast_str_kv_get_kb64_vb64(struct btree_kv_ops *kv_ops);

#ifdef __cplusplus
}
#endif

#endif
