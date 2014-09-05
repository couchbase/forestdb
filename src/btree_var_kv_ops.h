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

 #ifndef _FDB_BTREE_VAR_KV_OPS
#define _FDB_BTREE_VAR_KV_OPS

#include "btree_fast_str_kv.h"
#define _get_var_kv_ops btree_fast_str_kv_get_kb64_vb64
#define _get_var_key btree_fast_str_kv_get_key
#define _set_var_key btree_fast_str_kv_set_key
#define _set_var_inf_key btree_fast_str_kv_set_inf_key
#define _is_inf_key btree_fast_str_kv_is_inf_key
#define _free_var_key btree_fast_str_kv_free_key

#endif
