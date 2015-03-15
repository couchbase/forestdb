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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>

#include "libforestdb/forestdb.h"
#include "common.h"
#include "internal_types.h"
#include "btree_var_kv_ops.h"
#include "hbtrie.h"

#include "memleak.h"

#ifdef __DEBUG
#ifndef __DEBUG_FDB
    #undef DBG
    #undef DBGCMD
    #undef DBGSW
    #define DBG(...)
    #define DBGCMD(...)
    #define DBGSW(n, ...)
#endif
#endif

LIBFDB_API
fdb_status fdb_get_kv(fdb_kvs_handle *handle,
                      void *key, size_t keylen,
                      void **value_out, size_t *valuelen_out)
{
    fdb_doc *doc = NULL;
    fdb_status fs;

    if (key == NULL || keylen == 0 || keylen > FDB_MAX_KEYLEN ||
        value_out == NULL || valuelen_out == NULL ||
        (handle->kvs_config.custom_cmp &&
            keylen > handle->config.blocksize - HBTRIE_HEADROOM)) {
        return FDB_RESULT_INVALID_ARGS;
    }

    fs = fdb_doc_create(&doc, key, keylen, NULL, 0, NULL, 0);
    if (fs != FDB_RESULT_SUCCESS) {
        if (doc) { // LCOV_EXCL_START
            fdb_doc_free(doc);
        }
        return fs;
    } // LCOV_EXCL_STOP

    fs = fdb_get(handle, doc);
    if (fs != FDB_RESULT_SUCCESS) {
        if (doc) {
            fdb_doc_free(doc);
        }
        return fs;
    }

    *value_out = doc->body;
    *valuelen_out = doc->bodylen;
    if (doc->key) free(doc->key);
    if (doc->meta) free(doc->meta);
    free(doc);

    return fs;
}

LIBFDB_API
fdb_status fdb_set_kv(fdb_kvs_handle *handle,
                      void *key, size_t keylen,
                      void *value, size_t valuelen)
{
    fdb_doc *doc;
    fdb_status fs;

    if (key == NULL || keylen == 0 || keylen > FDB_MAX_KEYLEN ||
        (handle->kvs_config.custom_cmp &&
            keylen > handle->config.blocksize - HBTRIE_HEADROOM)) {
        return FDB_RESULT_INVALID_ARGS;
    }

    fs = fdb_doc_create(&doc, key, keylen, NULL, 0, value, valuelen);
    if (fs != FDB_RESULT_SUCCESS) {
        if (doc) { // LCOV_EXCL_START
            fdb_doc_free(doc);
        }
        return fs;
    } // LCOV_EXCL_STOP

    fs = fdb_set(handle, doc);
    if (fs != FDB_RESULT_SUCCESS) {
        if (doc) {
            fdb_doc_free(doc);
        }
        return fs;
    }
    fdb_doc_free(doc);

    return fs;
}

LIBFDB_API
fdb_status fdb_del_kv(fdb_kvs_handle *handle,
                      void *key, size_t keylen)
{
    fdb_doc *doc;
    fdb_status fs;

    if (key == NULL || keylen == 0 || keylen > FDB_MAX_KEYLEN ||
        (handle->kvs_config.custom_cmp &&
            keylen > handle->config.blocksize - HBTRIE_HEADROOM)) {
        return FDB_RESULT_INVALID_ARGS;
    }

    fs = fdb_doc_create(&doc, key, keylen, NULL, 0, NULL, 0);
    if (fs != FDB_RESULT_SUCCESS) {
        if (doc) { // LCOV_EXCL_START
            fdb_doc_free(doc);
        }
        return fs;
    } // LCOV_EXCL_STOP

    fs = fdb_del(handle, doc);
    if (fs != FDB_RESULT_SUCCESS) {
        fdb_doc_free(doc);
        return fs;
    }
    fdb_doc_free(doc);

    return fs;
}

LIBFDB_API
fdb_status fdb_free_block(void *ptr)
{
    free(ptr);
    return FDB_RESULT_SUCCESS;
}

