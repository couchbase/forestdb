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

#include <stdint.h>

#include "arch.h"
#include "common.h"
#include "internal_types.h"
#include "list.h"
#include "staleblock.h"

class FdbKvsHandle;

// list element for custom cmp functions in FdbFileHandle
struct cmp_func_node {
    char *kvs_name;
    fdb_custom_cmp_variable func;
    struct list_elem le;
};

// list element for opened KV store handles
// (in-memory data: managed by the file handle)
struct kvs_opened_node {
    FdbKvsHandle *handle;
    struct list_elem le;
};

#define FHANDLE_ROOT_OPENED (0x1)
#define FHANDLE_ROOT_INITIALIZED (0x2)
#define FHANDLE_ROOT_CUSTOM_CMP (0x4)

/**
 * ForestDB file handle definition.
 */
class FdbFileHandle {
public:
    FdbFileHandle();

    FdbFileHandle(FdbKvsHandle *_root);

    ~FdbFileHandle();

    FdbKvsHandle* getRootHandle() const {
        return root;
    }

    struct list *getHandleList() const {
        return handles;
    }

    struct list *getCmpFunctionList() const {
        return cmpFuncList;
    }

    fdb_custom_cmp_variable getCmpFunctionByName(char *kvs_name);

    uint64_t getFlags() const {
        return flags;
    }

    void setRootHandle(FdbKvsHandle* _root) {
        root = _root;
    }

    void setFlags(uint64_t _flags) {
        spin_lock(&lock);
        flags = _flags;
        spin_unlock(&lock);
    }

    void setCmpFunctionList(size_t n_func,
                            char **kvs_names,
                            fdb_custom_cmp_variable *functions);

    void setCmpFunctionList(struct list *cmp_func_list);

    void addCmpFunction(char *kvs_name,
                        fdb_custom_cmp_variable cmp_func);

    void addKVHandle(struct list_elem *kv_handle) {
        spin_lock(&lock);
        list_push_back(handles, kv_handle);
        spin_unlock(&lock);
    }

    /**
     * Create new node for 'handle' & link it in the file's list of KVS handles
     */
    struct kvs_opened_node *createNLinkKVHandle(FdbKvsHandle *handle);

    void removeKVHandle(struct list_elem *kv_handle) {
        spin_lock(&lock);
        list_remove(handles, kv_handle);
        spin_unlock(&lock);
    }

    bool activateRootHandle(const char *kvs_name, fdb_kvs_config &config);

    fdb_status closeAllKVHandles();

    /**
     * Check if any handle for a given KV store Id is still active.
     *
     * @param kv_id Id of a given KV store
     * @return true if there is at least one active handle for a given KV store Id.
     */
    bool checkAnyActiveKVHandle(fdb_kvs_id_t kv_id);

    /**
     * Check if the KV handle list is empty or not.
     *
     * @return true if the KV handle list is empty.
     */
    bool isKVHandleListEmpty();

    /**
     * Return the oldest stable commit header that is still being accessed by
     * any KV store handles created with this file handle.
     */
    stale_header_info getOldestActiveHeader();

private:
    /**
     * The root KV store handle.
     */
    FdbKvsHandle *root;
    /**
     * List of opened default KV store handles
     * (except for the root handle).
     */
    struct list *handles;
    /**
     * List of custom compare functions assigned by user
     */
    struct list *cmpFuncList;
    /**
     * Flags for the file handle.
     */
    uint64_t flags;
    /**
     * Spin lock for the file handle.
     */
    spin_t lock;

    DISALLOW_COPY_AND_ASSIGN(FdbFileHandle);
};

