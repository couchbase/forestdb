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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "fdb_engine.h"
#include "fdb_internal.h"
#include "filemgr.h"
#include "file_handle.h"
#include "kvs_handle.h"


FdbFileHandle::FdbFileHandle() :
    root(NULL), handles(NULL), cmpFuncList(NULL), flags(0) {
    spin_init(&lock);
}

FdbFileHandle::FdbFileHandle(FdbKvsHandle *_root) : root(_root) {
    root->fhandle = this;
    handles = (struct list*) calloc(1, sizeof(struct list));
    cmpFuncList = NULL;
    flags = 0x0;
    spin_init(&lock);
}

FdbFileHandle::~FdbFileHandle() {
    free(handles);
    spin_destroy(&lock);

    if (cmpFuncList) {
        struct list_elem *e;
        struct cmp_func_node *cmp_node;
        e = list_begin(cmpFuncList);
        while (e) {
            cmp_node = _get_entry(e, struct cmp_func_node, le);
            e = list_remove(cmpFuncList, &cmp_node->le);
            free(cmp_node->kvs_name);
            free(cmp_node);
        }
        free(cmpFuncList);
    }
}

fdb_custom_cmp_variable FdbFileHandle::getCmpFunctionByName(char *kvs_name) {
    struct list_elem *e;
    struct cmp_func_node *cmp_node;

    if (!cmpFuncList) {
        return NULL;
    }

    e = list_begin(cmpFuncList);
    while (e) {
        cmp_node = _get_entry(e, struct cmp_func_node, le);
        if (kvs_name == NULL ||
            !strcmp(kvs_name, DEFAULT_KVS_NAME)) {
            if (cmp_node->kvs_name == NULL ||
                !strcmp(cmp_node->kvs_name, DEFAULT_KVS_NAME)) { // default KVS
                return cmp_node->func;
            }
        } else if (cmp_node->kvs_name &&
                   !strcmp(cmp_node->kvs_name, kvs_name)) {
            return cmp_node->func;
        }
        e = list_next(&cmp_node->le);
    }
    return NULL;
}

void FdbFileHandle::setCmpFunctionList(size_t n_func,
                                       char **kvs_names,
                                       fdb_custom_cmp_variable *functions) {
    size_t i;
    struct cmp_func_node *node;

    if (cmpFuncList || /* already exist */
        n_func == 0 || !kvs_names || !functions) {
        return;
    }

    cmpFuncList = (struct list*) calloc(1, sizeof(struct list));
    list_init(cmpFuncList);

    for (i = 0; i < n_func; ++i){
        node = (struct cmp_func_node*) calloc(1, sizeof(struct cmp_func_node));
        if (kvs_names[i]) {
            node->kvs_name = (char*) calloc(1, strlen(kvs_names[i])+1);
            strcpy(node->kvs_name, kvs_names[i]);
        } else {
            // NULL .. default KVS
            node->kvs_name = NULL;
        }
        node->func = functions[i];
        list_push_back(cmpFuncList, &node->le);
    }
}

void FdbFileHandle::setCmpFunctionList(struct list *cmp_func_list) {
    struct list_elem *e;
    struct cmp_func_node *src, *dst;

    if (cmpFuncList || /* already exist */
        !cmp_func_list) {
        return;
    }

    cmpFuncList = (struct list*) calloc(1, sizeof(struct list));
    list_init(cmpFuncList);

    e = list_begin(cmp_func_list);
    while (e) {
        src = _get_entry(e, struct cmp_func_node, le);
        dst = (struct cmp_func_node*) calloc(1, sizeof(struct cmp_func_node));
        if (src->kvs_name) {
            dst->kvs_name = (char*) calloc(1, strlen(src->kvs_name)+1);
            strcpy(dst->kvs_name, src->kvs_name);
        } else {
            dst->kvs_name = NULL; // default KVS
        }
        dst->func = src->func;
        list_push_back(cmpFuncList, &dst->le);
        e = list_next(&src->le);
    }
}

void FdbFileHandle::addCmpFunction(char *kvs_name,
                                   fdb_custom_cmp_variable cmp_func) {
    struct cmp_func_node *node;

    // create list if not exist
    if (!cmpFuncList) {
        cmpFuncList = (struct list*) calloc(1, sizeof(struct list));
        list_init(cmpFuncList);
    }

    node = (struct cmp_func_node*) calloc(1, sizeof(struct cmp_func_node));
    if (kvs_name) {
        node->kvs_name = (char*) calloc(1, strlen(kvs_name)+1);
        strcpy(node->kvs_name, kvs_name);
    } else {
        // default KVS
        node->kvs_name = NULL;
    }
    node->func = cmp_func;
    list_push_back(cmpFuncList, &node->le);
}

struct kvs_opened_node *FdbFileHandle::createNLinkKVHandle(FdbKvsHandle *handle) {
    //TODO: replace this calloc with new operator as future C++ refactoring
    struct kvs_opened_node *opened_node = (struct kvs_opened_node *)
        calloc(1, sizeof(struct kvs_opened_node));
    opened_node->handle = handle;
    handle->node = opened_node;
    addKVHandle(&opened_node->le);
    return opened_node;
}

bool FdbFileHandle::activateRootHandle(const char *kvs_name, fdb_kvs_config &config) {
    bool rv = false;

    spin_lock(&lock);
    if (!(flags & FHANDLE_ROOT_OPENED)) {
        fdb_custom_cmp_variable default_kvs_cmp;
        root->kvs_config = config;

        if (root->file->getKVHeader_UNLOCKED()) {
            // search fhandle's custom cmp func list first
            default_kvs_cmp = getCmpFunctionByName((char *) kvs_name);

            spin_lock(&root->file->getKVHeader_UNLOCKED()->lock);
            root->file->getKVHeader_UNLOCKED()->default_kvs_cmp = default_kvs_cmp;

            if (root->file->getKVHeader_UNLOCKED()->default_kvs_cmp == NULL &&
                root->kvs_config.custom_cmp) {
                // follow kvs_config's custom cmp next
                root->file->getKVHeader_UNLOCKED()->default_kvs_cmp = root->kvs_config.custom_cmp;
                addCmpFunction(NULL, root->kvs_config.custom_cmp);
            }

            if (root->file->getKVHeader_UNLOCKED()->default_kvs_cmp) {
                root->file->getKVHeader_UNLOCKED()->custom_cmp_enabled = 1;
                flags |= FHANDLE_ROOT_CUSTOM_CMP;
            }
            spin_unlock(&root->file->getKVHeader_UNLOCKED()->lock);
        }

        flags |= FHANDLE_ROOT_INITIALIZED;
        flags |= FHANDLE_ROOT_OPENED;
        rv = true;
    }
    spin_unlock(&lock);

    return rv;
}

fdb_status FdbFileHandle::closeAllKVHandles() {
    fdb_status fs;
    struct list_elem *e;
    struct kvs_opened_node *node;

    spin_lock(&lock);
    e = list_begin(handles);
    while (e) {
        node = _get_entry(e, struct kvs_opened_node, le);
        e = list_remove(handles, e);
        fs = FdbEngine::getInstance()->closeKVHandle(node->handle);
        if (fs != FDB_RESULT_SUCCESS) {
            spin_unlock(&lock);
            return fs;
        }
        delete node->handle;
        free(node);
    }
    spin_unlock(&lock);
    return FDB_RESULT_SUCCESS;
}

bool FdbFileHandle::checkAnyActiveKVHandle(fdb_kvs_id_t kv_id) {
    struct list_elem *e;
    struct kvs_opened_node *opened_node;

    spin_lock(&lock);
    e = list_begin(handles);
    while (e) {
        opened_node = _get_entry(e, struct kvs_opened_node, le);
        if ((opened_node->handle->kvs && opened_node->handle->kvs->getKvsId() == kv_id) ||
            (kv_id == 0 && opened_node->handle->kvs == NULL)) // single KVS mode
        {
            // there is an opened handle
            spin_unlock(&lock);
            return true;
        }
        e = list_next(e);
    }
    spin_unlock(&lock);

    return false;
}

bool FdbFileHandle::isKVHandleListEmpty() {
    spin_lock(&lock);
    if (list_begin(handles) != NULL) {
        spin_unlock(&lock);
        return false;
    }
    spin_unlock(&lock);

    return true;
}

stale_header_info FdbFileHandle::getOldestActiveHeader() {
    stale_header_info oldest_header;
    struct list_elem *e;
    struct kvs_opened_node *item;

    oldest_header.revnum = static_cast<filemgr_header_revnum_t>(-1);
    oldest_header.bid = BLK_NOT_FOUND;

    spin_lock(&lock);
    // check all opened KVS handles belonging to the file handle
    e = list_begin(handles);
    while (e) {
        item = _get_entry(e, struct kvs_opened_node, le);
        e = list_next(e);
        if (!item->handle->shandle) {
            // Only consider active snapshot handles since non-snapshot handles
            // will get synced upon their next forestdb api call.
            // This prevents "lazy" non-snapshot handles from holding up stale
            // block reclaim.
            // TODO: Consider syncing up all non-snapshot handles to latest hdr
            // instead of discarding them here (may need KVS handle-level locks)
            continue;
        }
        if (item->handle->cur_header_revnum < oldest_header.revnum) {
            oldest_header.revnum = item->handle->cur_header_revnum;
            oldest_header.bid = item->handle->last_hdr_bid;
        }
    }
    spin_unlock(&lock);

    return oldest_header;
}
