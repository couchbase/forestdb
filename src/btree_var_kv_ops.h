#ifndef _FDB_BTREE_VAR_KV_OPS
#define _FDB_BTREE_VAR_KV_OPS

#include "btree_prefix_kv.h"
#define _get_var_kv_ops btree_prefix_kv_get_kb64_vb64
#define _get_var_key btree_prefix_kv_get_key
#define _set_var_key btree_prefix_kv_set_key
#define _free_var_key btree_prefix_kv_free_key

#endif
