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

#include <stdlib.h>
#include <string.h>

#include "libforestdb/forestdb.h"
#include "common.h"
#include "internal_types.h"
#include "fdb_internal.h"
#include "configuration.h"
#include "avltree.h"
#include "list.h"
#include "docio.h"
#include "filemgr.h"
#include "wal.h"
#include "hbtrie.h"
#include "btreeblock.h"
#include "snapshot.h"
#include "version.h"
#include "staleblock.h"

#include "memleak.h"
#include "time_utils.h"

static const char *default_kvs_name = DEFAULT_KVS_NAME;

// list element for opened KV store handles
// (in-memory data: managed by the file handle)
struct kvs_opened_node {
    fdb_kvs_handle *handle;
    struct list_elem le;
};

// list element for custom cmp functions in fhandle
struct cmp_func_node {
    char *kvs_name;
    fdb_custom_cmp_variable func;
    struct list_elem le;
};

static int _kvs_cmp_name(struct avl_node *a, struct avl_node *b, void *aux)
{
    struct kvs_node *aa, *bb;
    aa = _get_entry(a, struct kvs_node, avl_name);
    bb = _get_entry(b, struct kvs_node, avl_name);
    return strcmp(aa->kvs_name, bb->kvs_name);
}

static int _kvs_cmp_id(struct avl_node *a, struct avl_node *b, void *aux)
{
    struct kvs_node *aa, *bb;
    aa = _get_entry(a, struct kvs_node, avl_id);
    bb = _get_entry(b, struct kvs_node, avl_id);

    if (aa->id < bb->id) {
        return -1;
    } else if (aa->id > bb->id) {
        return 1;
    } else {
        return 0;
    }
}

static bool _fdb_kvs_any_handle_opened(fdb_file_handle *fhandle,
                                       fdb_kvs_id_t kv_id)
{
    struct filemgr *file = fhandle->root->file;
    struct avl_node *a;
    struct list_elem *e;
    struct filemgr_fhandle_idx_node *fhandle_node;
    struct kvs_opened_node *opened_node;
    fdb_file_handle *file_handle;

    spin_lock(&file->fhandle_idx_lock);
    a = avl_first(&file->fhandle_idx);
    while (a) {
        fhandle_node = _get_entry(a, struct filemgr_fhandle_idx_node, avl);
        a = avl_next(a);
        file_handle = (fdb_file_handle *) fhandle_node->fhandle;
        spin_lock(&file_handle->lock);
        e = list_begin(file_handle->handles);
        while (e) {
            opened_node = _get_entry(e, struct kvs_opened_node, le);
            if ((opened_node->handle->kvs && opened_node->handle->kvs->id == kv_id) ||
                (kv_id == 0 && opened_node->handle->kvs == NULL)) // single KVS mode
            {
                // there is an opened handle
                spin_unlock(&file_handle->lock);
                spin_unlock(&file->fhandle_idx_lock);
                return true;
            }
            e = list_next(e);
        }
        spin_unlock(&file_handle->lock);
    }
    spin_unlock(&file->fhandle_idx_lock);

    return false;
}

void fdb_file_handle_init(fdb_file_handle *fhandle,
                           fdb_kvs_handle *root)
{
    fhandle->root = root;
    fhandle->flags = 0x0;
    root->fhandle = fhandle;
    fhandle->handles = (struct list*)calloc(1, sizeof(struct list));
    fhandle->cmp_func_list = NULL;
    spin_init(&fhandle->lock);
}

void fdb_file_handle_close_all(fdb_file_handle *fhandle)
{
    struct list_elem *e;
    struct kvs_opened_node *node;

    spin_lock(&fhandle->lock);
    e = list_begin(fhandle->handles);
    while (e) {
        node = _get_entry(e, struct kvs_opened_node, le);
        e = list_next(e);
        _fdb_close(node->handle);
        free(node->handle);
        free(node);
    }
    spin_unlock(&fhandle->lock);
}

void fdb_file_handle_parse_cmp_func(fdb_file_handle *fhandle,
                                    size_t n_func,
                                    char **kvs_names,
                                    fdb_custom_cmp_variable *functions)
{
    uint64_t i;
    struct cmp_func_node *node;

    if (n_func == 0 || !kvs_names || !functions) {
        return;
    }

    fhandle->cmp_func_list = (struct list*)calloc(1, sizeof(struct list));
    list_init(fhandle->cmp_func_list);

    for (i=0;i<n_func;++i){
        node = (struct cmp_func_node*)calloc(1, sizeof(struct cmp_func_node));
        if (kvs_names[i]) {
            node->kvs_name = (char*)calloc(1, strlen(kvs_names[i])+1);
            strcpy(node->kvs_name, kvs_names[i]);
        } else {
            // NULL .. default KVS
            node->kvs_name = NULL;
        }
        node->func = functions[i];
        list_push_back(fhandle->cmp_func_list, &node->le);
    }
}

// clone all items in cmp_func_list to fhandle->cmp_func_list
void fdb_file_handle_clone_cmp_func_list(fdb_file_handle *fhandle,
                                         struct list *cmp_func_list)
{
    struct list_elem *e;
    struct cmp_func_node *src, *dst;

    if (fhandle->cmp_func_list || /* already exist */
        !cmp_func_list) {
        return;
    }

    fhandle->cmp_func_list = (struct list*)calloc(1, sizeof(struct list));
    list_init(fhandle->cmp_func_list);

    e = list_begin(cmp_func_list);
    while (e) {
        src = _get_entry(e, struct cmp_func_node, le);
        dst = (struct cmp_func_node*)calloc(1, sizeof(struct cmp_func_node));
        if (src->kvs_name) {
            dst->kvs_name = (char*)calloc(1, strlen(src->kvs_name)+1);
            strcpy(dst->kvs_name, src->kvs_name);
        } else {
            dst->kvs_name = NULL; // default KVS
        }
        dst->func = src->func;
        list_push_back(fhandle->cmp_func_list, &dst->le);
        e = list_next(&src->le);
    }
}

void fdb_file_handle_add_cmp_func(fdb_file_handle *fhandle,
                                  char *kvs_name,
                                  fdb_custom_cmp_variable cmp_func)
{
    struct cmp_func_node *node;

    // create list if not exist
    if (!fhandle->cmp_func_list) {
        fhandle->cmp_func_list = (struct list*)calloc(1, sizeof(struct list));
        list_init(fhandle->cmp_func_list);
    }

    node = (struct cmp_func_node*)calloc(1, sizeof(struct cmp_func_node));
    if (kvs_name) {
        node->kvs_name = (char*)calloc(1, strlen(kvs_name)+1);
        strcpy(node->kvs_name, kvs_name);
    } else {
        // default KVS
        node->kvs_name = NULL;
    }
    node->func = cmp_func;
    list_push_back(fhandle->cmp_func_list, &node->le);
}

void fdb_cmp_func_list_from_filemgr(struct filemgr *file, struct list *cmp_func_list)
{
    if (!file || !file->kv_header || !cmp_func_list) {
        return;
    }

    struct cmp_func_node *node;

    spin_lock(&file->kv_header->lock);
    // Default KV store cmp function
    if (file->kv_header->default_kvs_cmp) {
        node = (struct cmp_func_node*)calloc(1, sizeof(struct cmp_func_node));
        node->func = file->kv_header->default_kvs_cmp;
        node->kvs_name = NULL;
        list_push_back(cmp_func_list, &node->le);
    }

    // Rest of KV stores
    struct kvs_node *kvs_node;
    struct avl_node *a = avl_first(file->kv_header->idx_name);
    while (a) {
        kvs_node = _get_entry(a, struct kvs_node, avl_name);
        a = avl_next(a);
        node = (struct cmp_func_node*)calloc(1, sizeof(struct cmp_func_node));
        node->func = kvs_node->custom_cmp;
        node->kvs_name = (char*)calloc(1, strlen(kvs_node->kvs_name)+1);
        strcpy(node->kvs_name, kvs_node->kvs_name);
        list_push_back(cmp_func_list, &node->le);
    }
    spin_unlock(&file->kv_header->lock);
}

void fdb_free_cmp_func_list(struct list *cmp_func_list)
{
    if (!cmp_func_list) {
        return;
    }

    struct cmp_func_node *cmp_node;
    struct list_elem *e = list_begin(cmp_func_list);
    while (e) {
        cmp_node = _get_entry(e, struct cmp_func_node, le);
        e = list_remove(cmp_func_list, &cmp_node->le);
        free(cmp_node->kvs_name);
        free(cmp_node);
    }
}

static void _free_cmp_func_list(fdb_file_handle *fhandle)
{
    struct list_elem *e;
    struct cmp_func_node *cmp_node;

    if (!fhandle->cmp_func_list) {
        return;
    }

    e = list_begin(fhandle->cmp_func_list);
    while (e) {
        cmp_node = _get_entry(e, struct cmp_func_node, le);
        e = list_remove(fhandle->cmp_func_list, &cmp_node->le);

        free(cmp_node->kvs_name);
        free(cmp_node);
    }
    free(fhandle->cmp_func_list);
    fhandle->cmp_func_list = NULL;
}

void fdb_file_handle_free(fdb_file_handle *fhandle)
{
    free(fhandle->handles);
    _free_cmp_func_list(fhandle);
    spin_destroy(&fhandle->lock);
    free(fhandle);
}

fdb_status fdb_kvs_cmp_check(fdb_kvs_handle *handle)
{
    int ori_flag;
    fdb_file_handle *fhandle = handle->fhandle;
    fdb_custom_cmp_variable ori_custom_cmp;
    struct filemgr *file = handle->file;
    struct cmp_func_node *cmp_node;
    struct kvs_node *kvs_node, query;
    struct list_elem *e;
    struct avl_node *a;

    spin_lock(&file->kv_header->lock);
    ori_flag = file->kv_header->custom_cmp_enabled;
    ori_custom_cmp = file->kv_header->default_kvs_cmp;

    if (fhandle->cmp_func_list) {
        handle->kvs_config.custom_cmp = NULL;

        e = list_begin(fhandle->cmp_func_list);
        while (e) {
            cmp_node = _get_entry(e, struct cmp_func_node, le);
            if (cmp_node->kvs_name == NULL ||
                    !strcmp(cmp_node->kvs_name, default_kvs_name)) { // default KVS
                handle->kvs_config.custom_cmp = cmp_node->func;
                file->kv_header->default_kvs_cmp = cmp_node->func;
                file->kv_header->custom_cmp_enabled = 1;
            } else {
                // search by name
                query.kvs_name = cmp_node->kvs_name;
                a = avl_search(file->kv_header->idx_name,
                               &query.avl_name,
                               _kvs_cmp_name);
                if (a) { // found
                    kvs_node = _get_entry(a, struct kvs_node, avl_name);
                    if (!kvs_node->custom_cmp) {
                        kvs_node->custom_cmp = cmp_node->func;
                    }
                    file->kv_header->custom_cmp_enabled = 1;
                }
            }
            e = list_next(&cmp_node->le);
        }
    }

    // first check the default KVS
    // 1. root handle has not been opened yet: don't care
    // 2. root handle was opened before: must match the flag
    if (fhandle->flags & FHANDLE_ROOT_INITIALIZED) {
        if (fhandle->flags & FHANDLE_ROOT_CUSTOM_CMP &&
            handle->kvs_config.custom_cmp == NULL) {
            // custom cmp function was assigned before,
            // but no custom cmp function is assigned
            file->kv_header->custom_cmp_enabled = ori_flag;
            file->kv_header->default_kvs_cmp = ori_custom_cmp;
            spin_unlock(&file->kv_header->lock);
            const char *kvs_name = _fdb_kvs_get_name(handle, handle->file);
            if (!kvs_name) {
                kvs_name = DEFAULT_KVS_NAME;
            }
            return fdb_log(&handle->log_callback, FDB_RESULT_INVALID_CMP_FUNCTION,
                           "Error! Tried to open a KV store '%s', which was created with "
                           "custom compare function enabled, without passing the same "
                           "custom compare function.", kvs_name);
        }
        if (!(fhandle->flags & FHANDLE_ROOT_CUSTOM_CMP) &&
              handle->kvs_config.custom_cmp) {
            // custom cmp function was not assigned before,
            // but custom cmp function is assigned from user
            file->kv_header->custom_cmp_enabled = ori_flag;
            file->kv_header->default_kvs_cmp = ori_custom_cmp;
            spin_unlock(&file->kv_header->lock);
            const char *kvs_name = _fdb_kvs_get_name(handle, handle->file);
            if (!kvs_name) {
                kvs_name = DEFAULT_KVS_NAME;
            }
            return fdb_log(&handle->log_callback, FDB_RESULT_INVALID_CMP_FUNCTION,
                           "Error! Tried to open a KV store '%s', which was created without "
                           "custom compare function, by passing custom compare function.",
                    kvs_name);
        }
    }

    // next check other KVSs
    a = avl_first(file->kv_header->idx_name);
    while (a) {
        kvs_node = _get_entry(a, struct kvs_node, avl_name);
        a = avl_next(a);

        if (kvs_node->flags & KVS_FLAG_CUSTOM_CMP &&
            kvs_node->custom_cmp == NULL) {
            // custom cmp function was assigned before,
            // but no custom cmp function is assigned
            file->kv_header->custom_cmp_enabled = ori_flag;
            file->kv_header->default_kvs_cmp = ori_custom_cmp;
            spin_unlock(&file->kv_header->lock);
            const char *kvs_name = _fdb_kvs_get_name(handle, handle->file);
            if (!kvs_name) {
                kvs_name = DEFAULT_KVS_NAME;
            }
            return fdb_log(&handle->log_callback, FDB_RESULT_INVALID_CMP_FUNCTION,
                           "Error! Tried to open a KV store '%s', which was created with "
                           "custom compare function enabled, without passing the same "
                           "custom compare function.", kvs_name);
        }
        if (!(kvs_node->flags & KVS_FLAG_CUSTOM_CMP) &&
              kvs_node->custom_cmp) {
            // custom cmp function was not assigned before,
            // but custom cmp function is assigned from user
            file->kv_header->custom_cmp_enabled = ori_flag;
            file->kv_header->default_kvs_cmp = ori_custom_cmp;
            spin_unlock(&file->kv_header->lock);
            const char *kvs_name = _fdb_kvs_get_name(handle, handle->file);
            if (!kvs_name) {
                kvs_name = DEFAULT_KVS_NAME;
            }
            return fdb_log(&handle->log_callback, FDB_RESULT_INVALID_CMP_FUNCTION,
                           "Error! Tried to open a KV store '%s', which was created without "
                           "custom compare function, by passing custom compare function.",
                           kvs_name);
        }
    }

    spin_unlock(&file->kv_header->lock);
    return FDB_RESULT_SUCCESS;
}

fdb_custom_cmp_variable fdb_kvs_find_cmp_name(fdb_kvs_handle *handle,
                                              char *kvs_name)
{
    fdb_file_handle *fhandle;
    struct list_elem *e;
    struct cmp_func_node *cmp_node;

    fhandle = handle->fhandle;
    if (!fhandle->cmp_func_list) {
        return NULL;
    }

    e = list_begin(fhandle->cmp_func_list);
    while (e) {
        cmp_node = _get_entry(e, struct cmp_func_node, le);
        if (kvs_name == NULL ||
            !strcmp(kvs_name, default_kvs_name)) {
            if (cmp_node->kvs_name == NULL ||
                !strcmp(cmp_node->kvs_name, default_kvs_name)) { // default KVS
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

hbtrie_cmp_func *fdb_kvs_find_cmp_chunk(void *chunk, void *aux)
{
    fdb_kvs_id_t kv_id;
    struct hbtrie *trie = (struct hbtrie *)aux;
    struct btreeblk_handle *bhandle;
    struct filemgr *file;
    struct avl_node *a;
    struct kvs_node query, *node;

    bhandle = (struct btreeblk_handle*)trie->btreeblk_handle;
    file = bhandle->file;

    if (!file->kv_header->custom_cmp_enabled) {
        return NULL;
    }

    buf2kvid(trie->chunksize, chunk, &kv_id);

    // search by id
    if (kv_id > 0) {
        query.id = kv_id;
        spin_lock(&file->kv_header->lock);
        a = avl_search(file->kv_header->idx_id, &query.avl_id, _kvs_cmp_id);
        spin_unlock(&file->kv_header->lock);

        if (a) {
            node = _get_entry(a, struct kvs_node, avl_id);
            return (hbtrie_cmp_func *)node->custom_cmp;
        }
    } else {
        // root handle
        return (hbtrie_cmp_func *)file->kv_header->default_kvs_cmp;
    }
    return NULL;
}

void _fdb_kvs_init_root(fdb_kvs_handle *handle, struct filemgr *file) {
    handle->kvs->type = KVS_ROOT;
    handle->kvs->root = handle->fhandle->root;
    // super handle's ID is always 0
    handle->kvs->id = 0;
    // force custom cmp function
    spin_lock(&file->kv_header->lock);
    handle->kvs_config.custom_cmp = file->kv_header->default_kvs_cmp;
    spin_unlock(&file->kv_header->lock);
}

void fdb_kvs_info_create(fdb_kvs_handle *root_handle,
                         fdb_kvs_handle *handle,
                         struct filemgr *file,
                         const char *kvs_name)
{
    struct kvs_node query, *kvs_node;
    struct kvs_opened_node *opened_node;
    struct avl_node *a;

    handle->kvs = (struct kvs_info*)calloc(1, sizeof(struct kvs_info));

    if (root_handle == NULL) {
        // 'handle' is a super handle
        _fdb_kvs_init_root(handle, file);
    } else {
        // 'handle' is a sub handle (i.e., KV instance in a DB instance)
        handle->kvs->type = KVS_SUB;
        handle->kvs->root = root_handle;

        if (kvs_name) {
            spin_lock(&file->kv_header->lock);
            query.kvs_name = (char*)kvs_name;
            a = avl_search(file->kv_header->idx_name, &query.avl_name,
                           _kvs_cmp_name);
            if (a == NULL) {
                // KV instance name is not found
                free(handle->kvs);
                handle->kvs = NULL;
                spin_unlock(&file->kv_header->lock);
                return;
            }
            kvs_node = _get_entry(a, struct kvs_node, avl_name);
            handle->kvs->id = kvs_node->id;
            // force custom cmp function
            handle->kvs_config.custom_cmp = kvs_node->custom_cmp;
            spin_unlock(&file->kv_header->lock);
        } else {
            // snapshot of the root handle
            handle->kvs->id = 0;
        }

        opened_node = (struct kvs_opened_node *)
               calloc(1, sizeof(struct kvs_opened_node));
        opened_node->handle = handle;

        handle->node = opened_node;
        spin_lock(&root_handle->fhandle->lock);
        list_push_back(root_handle->fhandle->handles, &opened_node->le);
        spin_unlock(&root_handle->fhandle->lock);
    }
}

void fdb_kvs_info_free(fdb_kvs_handle *handle)
{
    if (handle->kvs == NULL) {
        return;
    }

    free(handle->kvs);
    handle->kvs = NULL;
}

void _fdb_kvs_header_create(struct kvs_header **kv_header_ptr)
{
    struct kvs_header *kv_header;

    kv_header = (struct kvs_header *)calloc(1, sizeof(struct kvs_header));
    *kv_header_ptr = kv_header;

    // KV ID '0' is reserved for default KV instance (super handle)
    kv_header->id_counter = 1;
    kv_header->default_kvs_cmp = NULL;
    kv_header->custom_cmp_enabled = 0;
    kv_header->idx_name = (struct avl_tree*)malloc(sizeof(struct avl_tree));
    kv_header->idx_id = (struct avl_tree*)malloc(sizeof(struct avl_tree));
    kv_header->num_kv_stores = 0;
    avl_init(kv_header->idx_name, NULL);
    avl_init(kv_header->idx_id, NULL);
    spin_init(&kv_header->lock);
}

void fdb_kvs_header_create(struct filemgr *file)
{
    if (file->kv_header) {
        return; // already exist
    }

    _fdb_kvs_header_create(&file->kv_header);
    file->free_kv_header = fdb_kvs_header_free;
}

void fdb_kvs_header_reset_all_stats(struct filemgr *file)
{
    struct avl_node *a;
    struct kvs_node *node;
    struct kvs_header *kv_header = file->kv_header;

    spin_lock(&kv_header->lock);
    a = avl_first(kv_header->idx_id);
    while (a) {
        node = _get_entry(a, struct kvs_node, avl_id);
        a = avl_next(&node->avl_id);
        memset(&node->stat, 0x0, sizeof(node->stat));
    }
    spin_unlock(&kv_header->lock);
}

void fdb_kvs_header_copy(fdb_kvs_handle *handle,
                         struct filemgr *new_file,
                         struct docio_handle *new_dhandle,
                         uint64_t *new_file_kv_info_offset,
                         bool create_new)
{
    struct avl_node *a, *aa;
    struct kvs_node *node_old, *node_new;

    if (create_new) {
        struct kvs_header *kv_header;
        // copy KV header data in 'handle' to new file
        _fdb_kvs_header_create(&kv_header);
        // read from 'handle->dhandle', and import into 'new_file'
        fdb_kvs_header_read(kv_header, handle->dhandle,
                            handle->kv_info_offset, ver_get_latest_magic(), false);

        // write KV header in 'new_file' using 'new_dhandle'
        uint64_t new_kv_info_offset;
        fdb_kvs_handle new_handle;
        new_handle.file = new_file;
        new_handle.dhandle = new_dhandle;
        new_handle.kv_info_offset = BLK_NOT_FOUND;
        new_kv_info_offset = fdb_kvs_header_append(&new_handle);
        if (new_file_kv_info_offset) {
            *new_file_kv_info_offset = new_kv_info_offset;
        }

        if (!filemgr_set_kv_header(new_file, kv_header, fdb_kvs_header_free,
                                   false)) { // LCOV_EXCL_START
            _fdb_kvs_header_free(kv_header);
        } // LCOV_EXCL_STOP
        fdb_kvs_header_reset_all_stats(new_file);
    }

    spin_lock(&handle->file->kv_header->lock);
    spin_lock(&new_file->kv_header->lock);
    // copy all in-memory custom cmp function pointers & seqnums
    new_file->kv_header->default_kvs_cmp =
        handle->file->kv_header->default_kvs_cmp;
    new_file->kv_header->custom_cmp_enabled =
        handle->file->kv_header->custom_cmp_enabled;
    a = avl_first(handle->file->kv_header->idx_id);
    while (a) {
        node_old = _get_entry(a, struct kvs_node, avl_id);
        aa = avl_search(new_file->kv_header->idx_id,
                        &node_old->avl_id, _kvs_cmp_id);
        assert(aa); // MUST exist
        node_new = _get_entry(aa, struct kvs_node, avl_id);
        node_new->custom_cmp = node_old->custom_cmp;
        node_new->seqnum = node_old->seqnum;
        node_new->op_stat = node_old->op_stat;
        a = avl_next(a);
    }
    spin_unlock(&new_file->kv_header->lock);
    spin_unlock(&handle->file->kv_header->lock);
}

// export KV header info to raw data
static void _fdb_kvs_header_export(struct kvs_header *kv_header,
                                   void **data, size_t *len)
{
    /* << raw data structure >>
     * [# KV instances]:        8 bytes
     * [current KV ID counter]: 8 bytes
     * ---
     * [name length]:           2 bytes
     * [instance name]:         x bytes
     * [instance ID]:           8 bytes
     * [sequence number]:       8 bytes
     * [# live index nodes]:    8 bytes
     * [# docs]:                8 bytes
     * [data size]:             8 bytes
     * [flags]:                 8 bytes
     * [delta size]:            8 bytes
     * [# deleted docs]:        8 bytes
     * ...
     *    Please note that if the above format is changed, please also change...
     *    _fdb_kvs_get_snap_info()
     *    _fdb_kvs_header_import()
     *    _kvs_stat_get_sum_doc()
     *    _kvs_stat_get_sum_attr
     */

    int size = 0;
    int offset = 0;
    uint16_t name_len, _name_len;
    uint64_t c = 0;
    uint64_t _n_kv, _kv_id, _flags;
    uint64_t _nlivenodes, _ndocs, _datasize, _ndeletes;
    int64_t _deltasize;
    fdb_kvs_id_t _id_counter;
    fdb_seqnum_t _seqnum;
    struct kvs_node *node;
    struct avl_node *a;

    if (kv_header == NULL) {
        *data = NULL;
        *len = 0;
        return ;
    }

    spin_lock(&kv_header->lock);

    // pre-scan to estimate the size of data
    size += sizeof(uint64_t);
    size += sizeof(fdb_kvs_id_t);
    a = avl_first(kv_header->idx_name);
    while(a) {
        node = _get_entry(a, struct kvs_node, avl_name);
        c++;
        size += sizeof(uint16_t); // length
        size += strlen(node->kvs_name)+1; // name
        size += sizeof(node->id); // ID
        size += sizeof(node->seqnum); // seq number
        size += sizeof(node->stat.nlivenodes); // # live index nodes
        size += sizeof(node->stat.ndocs); // # docs
        size += sizeof(node->stat.datasize); // data size
        size += sizeof(node->flags); // flags
        size += sizeof(node->stat.deltasize); // delta size since commit
        size += sizeof(node->stat.ndeletes); // # deleted docs
        a = avl_next(a);
    }

    *data = (void *)malloc(size);

    // # KV instances
    _n_kv = _endian_encode(c);
    memcpy((uint8_t*)*data + offset, &_n_kv, sizeof(_n_kv));
    offset += sizeof(_n_kv);

    // ID counter
    _id_counter = _endian_encode(kv_header->id_counter);
    memcpy((uint8_t*)*data + offset, &_id_counter, sizeof(_id_counter));
    offset += sizeof(_id_counter);

    a = avl_first(kv_header->idx_name);
    while(a) {
        node = _get_entry(a, struct kvs_node, avl_name);

        // name length
        name_len = strlen(node->kvs_name)+1;
        _name_len = _endian_encode(name_len);
        memcpy((uint8_t*)*data + offset, &_name_len, sizeof(_name_len));
        offset += sizeof(_name_len);

        // name
        memcpy((uint8_t*)*data + offset, node->kvs_name, name_len);
        offset += name_len;

        // KV ID
        _kv_id = _endian_encode(node->id);
        memcpy((uint8_t*)*data + offset, &_kv_id, sizeof(_kv_id));
        offset += sizeof(_kv_id);

        // seq number
        _seqnum = _endian_encode(node->seqnum);
        memcpy((uint8_t*)*data + offset, &_seqnum, sizeof(_seqnum));
        offset += sizeof(_seqnum);

        // # live index nodes
        _nlivenodes = _endian_encode(node->stat.nlivenodes);
        memcpy((uint8_t*)*data + offset, &_nlivenodes, sizeof(_nlivenodes));
        offset += sizeof(_nlivenodes);

        // # docs
        _ndocs = _endian_encode(node->stat.ndocs);
        memcpy((uint8_t*)*data + offset, &_ndocs, sizeof(_ndocs));
        offset += sizeof(_ndocs);

        // datasize
        _datasize = _endian_encode(node->stat.datasize);
        memcpy((uint8_t*)*data + offset, &_datasize, sizeof(_datasize));
        offset += sizeof(_datasize);

        // flags
        _flags = _endian_encode(node->flags);
        memcpy((uint8_t*)*data + offset, &_flags, sizeof(_flags));
        offset += sizeof(_flags);

        // # delta index nodes + docsize created after last commit
        _deltasize = _endian_encode(node->stat.deltasize);
        memcpy((uint8_t*)*data + offset, &_deltasize, sizeof(_deltasize));
        offset += sizeof(_deltasize);

        // # deleted documents
        _ndeletes = _endian_encode(node->stat.ndeletes);
        memcpy((uint8_t*)*data + offset, &_ndeletes, sizeof(_ndeletes));
        offset += sizeof(_ndeletes);

        a = avl_next(a);
    }

    *len = size;

    spin_unlock(&kv_header->lock);
}

void _fdb_kvs_header_import(struct kvs_header *kv_header,
                            void *data, size_t len, uint64_t version,
                            bool only_seq_nums)
{
    uint64_t i, offset = 0;
    uint16_t name_len, _name_len;
    uint64_t n_kv, _n_kv, kv_id, _kv_id, flags, _flags;
    uint64_t _nlivenodes, _ndocs, _datasize, _ndeletes;
    int64_t _deltasize;
    bool is_deltasize;
    fdb_kvs_id_t id_counter, _id_counter;
    fdb_seqnum_t seqnum, _seqnum;
    struct kvs_node *node;

    // # KV instances
    memcpy(&_n_kv, (uint8_t*)data + offset, sizeof(_n_kv));
    offset += sizeof(_n_kv);
    n_kv = _endian_decode(_n_kv);

    // ID counter
    memcpy(&_id_counter, (uint8_t*)data + offset, sizeof(_id_counter));
    offset += sizeof(_id_counter);
    id_counter = _endian_decode(_id_counter);

    spin_lock(&kv_header->lock);
    kv_header->id_counter = id_counter;

    // Version control
    if (!ver_is_atleast_v2(version)) {
        is_deltasize = false;
        _deltasize = 0;
        _ndeletes = 0;
    } else {
        is_deltasize = true;
    }

    for (i=0;i<n_kv;++i){
        // name length
        uint64_t name_offset;
        memcpy(&_name_len, (uint8_t*)data + offset, sizeof(_name_len));
        offset += sizeof(_name_len);
        name_offset = offset;
        name_len = _endian_decode(_name_len);

        // name
        offset += name_len;

        // KV ID
        memcpy(&_kv_id, (uint8_t*)data + offset, sizeof(_kv_id));
        offset += sizeof(_kv_id);
        kv_id = _endian_decode(_kv_id);

        // Search if a given KV header node exists or not.
        struct kvs_node query;
        query.id = kv_id;
        struct avl_node *a = avl_search(kv_header->idx_id, &query.avl_id,
                                        _kvs_cmp_id);
        if (a) {
            node = _get_entry(a, struct kvs_node, avl_id);
        } else {
            node = (struct kvs_node *)calloc(1, sizeof(struct kvs_node));
            node->kvs_name = (char *)malloc(name_len);
            memcpy(node->kvs_name, (uint8_t*)data + name_offset, name_len);
            node->id = kv_id;
            _init_op_stats(&node->op_stat);
        }

        // seq number
        memcpy(&_seqnum, (uint8_t*)data + offset, sizeof(_seqnum));
        offset += sizeof(_seqnum);
        seqnum = _endian_decode(_seqnum);
        node->seqnum = seqnum;

        // # live index nodes
        memcpy(&_nlivenodes, (uint8_t*)data + offset, sizeof(_nlivenodes));
        offset += sizeof(_nlivenodes);

        // # docs
        memcpy(&_ndocs, (uint8_t*)data + offset, sizeof(_ndocs));
        offset += sizeof(_ndocs);

        // datasize
        memcpy(&_datasize, (uint8_t*)data + offset, sizeof(_datasize));
        offset += sizeof(_datasize);

        // flags
        memcpy(&_flags, (uint8_t*)data + offset, sizeof(_flags));
        offset += sizeof(_flags);
        flags = _endian_decode(_flags);

        if (is_deltasize) {
            // delta document + index size since previous commit
            memcpy(&_deltasize, (uint8_t*)data + offset,
                   sizeof(_deltasize));
            offset += sizeof(_deltasize);
            memcpy(&_ndeletes, (uint8_t*)data + offset,
                   sizeof(_ndeletes));
            offset += sizeof(_ndeletes);
        }

        if (!only_seq_nums) {
            node->stat.nlivenodes = _endian_decode(_nlivenodes);
            node->stat.ndocs = _endian_decode(_ndocs);
            node->stat.datasize = _endian_decode(_datasize);
            node->stat.deltasize = _endian_decode(_deltasize);
            node->stat.ndeletes = _endian_decode(_ndeletes);
            node->flags = flags;
            node->custom_cmp = NULL;
        }

        if (!a) { // Insert a new KV header node if not exist.
            avl_insert(kv_header->idx_name, &node->avl_name, _kvs_cmp_name);
            avl_insert(kv_header->idx_id, &node->avl_id, _kvs_cmp_id);
            ++kv_header->num_kv_stores;
        }
    }
    spin_unlock(&kv_header->lock);
}

fdb_status _fdb_kvs_get_snap_info(void *data, uint64_t version,
                                  fdb_snapshot_info_t *snap_info)
{
    int i, offset = 0, sizeof_skipped_segments;
    uint16_t name_len, _name_len;
    int64_t n_kv, _n_kv;
    bool is_deltasize;
    fdb_seqnum_t _seqnum;
    // Version control
    if (!ver_is_atleast_v2(version)) {
        is_deltasize = false;
    } else {
        is_deltasize = true;
    }

    // # KV instances
    memcpy(&_n_kv, (uint8_t*)data + offset, sizeof(_n_kv));
    offset += sizeof(_n_kv);
    // since n_kv doesn't count the default KVS, increase it by 1.
    n_kv = _endian_decode(_n_kv) + 1;
    assert(n_kv); // Must have at least one kv instance
    snap_info->kvs_markers = (fdb_kvs_commit_marker_t *)malloc(
                                   (n_kv) * sizeof(fdb_kvs_commit_marker_t));
    if (!snap_info->kvs_markers) { // LCOV_EXCL_START
        return FDB_RESULT_ALLOC_FAIL;
    } // LCOV_EXCL_STOP

    snap_info->num_kvs_markers = n_kv;

    // Skip over ID counter
    offset += sizeof(fdb_kvs_id_t);

    sizeof_skipped_segments = sizeof(uint64_t) // seqnum will be the last read
                            + sizeof(uint64_t) // skip over nlivenodes
                            + sizeof(uint64_t) // skip over ndocs
                            + sizeof(uint64_t) // skip over datasize
                            + sizeof(uint64_t); // skip over flags
    if (is_deltasize) {
        sizeof_skipped_segments += sizeof(uint64_t); // skip over deltasize
        sizeof_skipped_segments += sizeof(uint64_t); // skip over ndeletes
    }

    for (i = 0; i < n_kv-1; ++i){
        fdb_kvs_commit_marker_t *info = &snap_info->kvs_markers[i];
        // Read the kv store name length
        memcpy(&_name_len, (uint8_t*)data + offset, sizeof(_name_len));
        offset += sizeof(_name_len);
        name_len = _endian_decode(_name_len);

        // Retrieve the KV Store name
        info->kv_store_name = (char *)malloc(name_len); // TODO: cleanup if err
        memcpy(info->kv_store_name, (uint8_t*)data + offset, name_len);
        offset += name_len;

        // Skip over KV ID
        offset += sizeof(uint64_t);

        // Retrieve the KV Store Commit Sequence number
        memcpy(&_seqnum, (uint8_t*)data + offset, sizeof(_seqnum));
        info->seqnum = _endian_decode(_seqnum);

        // Skip over seqnum, nlivenodes, ndocs, datasize, flags etc onto next..
        offset += sizeof_skipped_segments;
    }

    return FDB_RESULT_SUCCESS;
}

uint64_t _kvs_stat_get_sum_attr(void *data, uint64_t version,
                                kvs_stat_attr_t attr)
{
    uint64_t ret = 0;
    int i, offset = 0;
    uint16_t name_len, _name_len;
    int64_t n_kv, _n_kv;
    bool is_deltasize;
    uint64_t nlivenodes, ndocs, datasize, flags;
    int64_t deltasize;

    // Version control
    if (!ver_is_atleast_v2(version)) {
        is_deltasize = false;
    } else {
        is_deltasize = true;
    }

    // # KV instances
    memcpy(&_n_kv, (uint8_t*)data + offset, sizeof(_n_kv));
    offset += sizeof(_n_kv);
    // since n_kv doesn't count the default KVS, increase it by 1.
    n_kv = _endian_decode(_n_kv) + 1;
    assert(n_kv); // Must have at least one kv instance

    // Skip over ID counter
    offset += sizeof(fdb_kvs_id_t);

    for (i = 0; i < n_kv-1; ++i){
        // Read the kv store name length and skip over the length
        memcpy(&_name_len, (uint8_t*)data + offset, sizeof(_name_len));
        offset += sizeof(_name_len);
        name_len = _endian_decode(_name_len);

        // Skip over the KV Store name
        offset += name_len;

        // Skip over KV ID
        offset += sizeof(uint64_t);

        // Skip over KV store seqnum
        offset += sizeof(uint64_t);

        // pick just the attribute requested, skipping over rest..
        if (attr == KVS_STAT_NLIVENODES) {
            memcpy(&nlivenodes, (uint8_t *)data + offset, sizeof(nlivenodes));
            ret += _endian_decode(nlivenodes);
            // skip over nlivenodes just read
            offset += sizeof(nlivenodes);
            // skip over ndocs, datasize, flags (and deltasize, ndeletes)
            offset += sizeof(nlivenodes) + sizeof(ndocs) + sizeof(datasize)
                   + sizeof(flags) + (is_deltasize ? sizeof(deltasize)*2 : 0);
        } else if (attr == KVS_STAT_DATASIZE) {
            offset += sizeof(nlivenodes) + sizeof(ndocs);
            memcpy(&datasize, (uint8_t *)data + offset, sizeof(datasize));
            ret += _endian_decode(datasize);
            // skip over datasize, flags (and deltasize, ndeletes)
            offset += sizeof(datasize) + sizeof(flags)
                   + (is_deltasize ? sizeof(deltasize)*2 : 0);
        } else if (attr == KVS_STAT_DELTASIZE) {
            if (is_deltasize) {
                offset += sizeof(nlivenodes) + sizeof(ndocs) + sizeof (datasize)
                        + sizeof(flags);
                memcpy(&deltasize, (uint8_t *)data + offset, sizeof(deltasize));
                ret += _endian_decode(deltasize);
                // skip over datasize, flags (and deltasize)
                offset += sizeof(deltasize)*2; // and ndeletes
            }
        } else { // Attribute fetched not implemented yet..
            fdb_assert(false, 0, attr); // Implement fetch for this attribute
        }
    }

    return ret;
}

uint64_t fdb_kvs_header_append(fdb_kvs_handle *handle)
{
    char *doc_key = alca(char, 32);
    void *data;
    size_t len;
    uint64_t kv_info_offset, prev_offset;
    struct docio_object doc;
    struct docio_length doc_len;
    struct filemgr *file = handle->file;
    struct docio_handle *dhandle = handle->dhandle;

    _fdb_kvs_header_export(file->kv_header, &data, &len);

    prev_offset = handle->kv_info_offset;

    memset(&doc, 0, sizeof(struct docio_object));
    sprintf(doc_key, "KV_header");
    doc.key = (void *)doc_key;
    doc.meta = NULL;
    doc.body = data;
    doc.length.keylen = strlen(doc_key) + 1;
    doc.length.metalen = 0;
    doc.length.bodylen = len;
    doc.seqnum = 0;
    kv_info_offset = docio_append_doc_system(dhandle, &doc);
    free(data);

    if (prev_offset != BLK_NOT_FOUND) {
        doc_len = docio_read_doc_length(handle->dhandle, prev_offset);
        // mark stale
        filemgr_mark_stale(handle->file, prev_offset, _fdb_get_docsize(doc_len));
    }

    return kv_info_offset;
}

void fdb_kvs_header_read(struct kvs_header *kv_header,
                         struct docio_handle *dhandle,
                         uint64_t kv_info_offset,
                         uint64_t version,
                         bool only_seq_nums)
{
    uint64_t offset;
    struct docio_object doc;

    memset(&doc, 0, sizeof(struct docio_object));
    offset = docio_read_doc(dhandle, kv_info_offset, &doc, true);

    if (offset == kv_info_offset) {
        fdb_log(dhandle->log_callback, FDB_RESULT_READ_FAIL,
                "Failed to read a KV header with the offset %" _F64 " from a "
                "database file '%s'", kv_info_offset, dhandle->file->filename);
        return;
    }

    _fdb_kvs_header_import(kv_header, doc.body, doc.length.bodylen,
                           version, only_seq_nums);
    free_docio_object(&doc, 1, 1, 1);
}

fdb_seqnum_t _fdb_kvs_get_seqnum(struct kvs_header *kv_header,
                                 fdb_kvs_id_t id)
{
    fdb_seqnum_t seqnum;
    struct kvs_node query, *node;
    struct avl_node *a;

    spin_lock(&kv_header->lock);
    query.id = id;
    a = avl_search(kv_header->idx_id, &query.avl_id, _kvs_cmp_id);
    if (a) {
        node = _get_entry(a, struct kvs_node, avl_id);
        seqnum = node->seqnum;
    } else {
        // not existing KV ID.
        // this is necessary for _fdb_restore_wal()
        // not to restore documents in deleted KV store.
        seqnum = 0;
    }
    spin_unlock(&kv_header->lock);

    return seqnum;
}

fdb_seqnum_t fdb_kvs_get_seqnum(struct filemgr *file,
                                fdb_kvs_id_t id)
{
    if (id == 0) {
        // default KV instance
        return filemgr_get_seqnum(file);
    }

    return _fdb_kvs_get_seqnum(file->kv_header, id);
}

fdb_seqnum_t fdb_kvs_get_committed_seqnum(fdb_kvs_handle *handle)
{
    uint8_t *buf;
    uint64_t dummy64;
    uint64_t version;
    uint64_t kv_info_offset;
    size_t len;
    bid_t hdr_bid;
    fdb_seqnum_t seqnum = SEQNUM_NOT_USED;
    fdb_kvs_id_t id = 0;
    char *compacted_filename = NULL;
    struct filemgr *file = handle->file;

    buf = alca(uint8_t, file->config->blocksize);

    if (handle->kvs && handle->kvs->id > 0) {
        id = handle->kvs->id;
    }

    hdr_bid = filemgr_get_header_bid(file);
    if (hdr_bid == BLK_NOT_FOUND) {
        // header doesn't exist
        return 0;
    }

    // read header
    filemgr_fetch_header(file, hdr_bid, buf, &len, &seqnum, NULL, NULL,
                         &version, NULL, &handle->log_callback);
    if (id > 0) { // non-default KVS
        // read last KVS header
        fdb_fetch_header(version, buf, &dummy64, &dummy64,
                         &dummy64, &dummy64, &dummy64, &dummy64,
                         &dummy64, &dummy64,
                         &kv_info_offset, &dummy64,
                         &compacted_filename, NULL);

        uint64_t doc_offset;
        struct kvs_header *kv_header;
        struct docio_object doc;

        _fdb_kvs_header_create(&kv_header);
        memset(&doc, 0, sizeof(struct docio_object));
        doc_offset = docio_read_doc(handle->dhandle,
                                    kv_info_offset, &doc, true);

        if (doc_offset == kv_info_offset) {
            // fail
            _fdb_kvs_header_free(kv_header);
            return 0;

        } else {
            _fdb_kvs_header_import(kv_header, doc.body,
                                   doc.length.bodylen, version, false);
            // get local sequence number for the KV instance
            seqnum = _fdb_kvs_get_seqnum(kv_header,
                                         handle->kvs->id);
            _fdb_kvs_header_free(kv_header);
            free_docio_object(&doc, 1, 1, 1);
        }
    }
    return seqnum;
}

LIBFDB_API
fdb_status fdb_get_kvs_seqnum(fdb_kvs_handle *handle, fdb_seqnum_t *seqnum)
{
    if (!handle) {
        return FDB_RESULT_INVALID_HANDLE;
    }
    if (!seqnum) {
        return FDB_RESULT_INVALID_ARGS;
    }

    if (!atomic_cas_uint8_t(&handle->handle_busy, 0, 1)) {
        return FDB_RESULT_HANDLE_BUSY;
    }

    if (handle->shandle) {
        // handle for snapshot
        // return MAX_SEQNUM instead of the file's sequence number
        *seqnum = handle->max_seqnum;
    } else {
        fdb_check_file_reopen(handle, NULL);
        fdb_sync_db_header(handle);

        struct filemgr *file;
        file = handle->file;

        if (handle->kvs == NULL ||
            handle->kvs->id == 0) {
            filemgr_mutex_lock(file);
            *seqnum = filemgr_get_seqnum(file);
            filemgr_mutex_unlock(file);
        } else {
            *seqnum = fdb_kvs_get_seqnum(file, handle->kvs->id);
        }
    }
    atomic_cas_uint8_t(&handle->handle_busy, 1, 0);
    return FDB_RESULT_SUCCESS;
}

void fdb_kvs_set_seqnum(struct filemgr *file,
                           fdb_kvs_id_t id,
                           fdb_seqnum_t seqnum)
{
    struct kvs_header *kv_header = file->kv_header;
    struct kvs_node query, *node;
    struct avl_node *a;

    if (id == 0) {
        // default KV instance
        filemgr_set_seqnum(file, seqnum);
        return;
    }

    spin_lock(&kv_header->lock);
    query.id = id;
    a = avl_search(kv_header->idx_id, &query.avl_id, _kvs_cmp_id);
    node = _get_entry(a, struct kvs_node, avl_id);
    node->seqnum = seqnum;
    spin_unlock(&kv_header->lock);
}

void _fdb_kvs_header_free(struct kvs_header *kv_header)
{
    struct kvs_node *node;
    struct avl_node *a;

    a = avl_first(kv_header->idx_name);
    while (a) {
        node = _get_entry(a, struct kvs_node, avl_name);
        a = avl_next(a);
        avl_remove(kv_header->idx_name, &node->avl_name);

        free(node->kvs_name);
        free(node);
    }
    free(kv_header->idx_name);
    free(kv_header->idx_id);
    free(kv_header);
}

void fdb_kvs_header_free(struct filemgr *file)
{
    if (file->kv_header == NULL) {
        return;
    }

    _fdb_kvs_header_free(file->kv_header);
    file->kv_header = NULL;
}

static fdb_status _fdb_kvs_create(fdb_kvs_handle *root_handle,
                                  const char *kvs_name,
                                  fdb_kvs_config *kvs_config)
{
    int kv_ins_name_len;
    fdb_status fs = FDB_RESULT_SUCCESS;
    struct avl_node *a;
    struct filemgr *file;
    struct kvs_node *node, query;
    struct kvs_header *kv_header;

    if (root_handle->config.multi_kv_instances == false) {
        // cannot open KV instance under single DB instance mode
        return fdb_log(&root_handle->log_callback, FDB_RESULT_INVALID_CONFIG,
                       "Cannot open or create KV store instance '%s' because multi-KV "
                       "store instance mode is disabled.",
                       kvs_name ? kvs_name : DEFAULT_KVS_NAME);
    }
    if (root_handle->kvs->type != KVS_ROOT) {
        return fdb_log(&root_handle->log_callback, FDB_RESULT_INVALID_HANDLE,
                       "Cannot open or create KV store instance '%s' because the handle "
                       "doesn't support multi-KV sotre instance mode.",
                       kvs_name ? kvs_name : DEFAULT_KVS_NAME);
    }

fdb_kvs_create_start:
    fdb_check_file_reopen(root_handle, NULL);
    filemgr_mutex_lock(root_handle->file);
    fdb_sync_db_header(root_handle);

    if (filemgr_is_rollback_on(root_handle->file)) {
        filemgr_mutex_unlock(root_handle->file);
        return FDB_RESULT_FAIL_BY_ROLLBACK;
    }

    file = root_handle->file;

    file_status_t fstatus = filemgr_get_file_status(file);
    if (fstatus == FILE_REMOVED_PENDING) {
        // we must not write into this file
        // file status was changed by other thread .. start over
        filemgr_mutex_unlock(file);
        goto fdb_kvs_create_start;
    }

    kv_header = file->kv_header;
    spin_lock(&kv_header->lock);

    // find existing KV instance
    // search by name
    query.kvs_name = (char*)kvs_name;
    a = avl_search(kv_header->idx_name, &query.avl_name, _kvs_cmp_name);
    if (a) { // KV name already exists
        spin_unlock(&kv_header->lock);
        filemgr_mutex_unlock(file);
        return fdb_log(&root_handle->log_callback, FDB_RESULT_INVALID_KV_INSTANCE_NAME,
                       "Failed to create KV Store '%s' as it already exists.",
                       kvs_name ? kvs_name : DEFAULT_KVS_NAME);
    }

    // create a kvs_node and insert
    node = (struct kvs_node *)calloc(1, sizeof(struct kvs_node));
    node->id = kv_header->id_counter++;
    node->seqnum = 0;
    node->flags = 0x0;
    _init_op_stats(&node->op_stat);
    // search fhandle's custom cmp func list first
    node->custom_cmp = fdb_kvs_find_cmp_name(root_handle,
                                             (char *)kvs_name);
    if (node->custom_cmp == NULL && kvs_config->custom_cmp) {
        // follow kvs_config's custom cmp next
        node->custom_cmp = kvs_config->custom_cmp;
        // if custom cmp function is given by user but
        // there is no corresponding function in fhandle's list
        // add it into the list
        fdb_file_handle_add_cmp_func(root_handle->fhandle,
                                     (char*)kvs_name,
                                     kvs_config->custom_cmp);
    }
    if (node->custom_cmp) { // custom cmp function is used
        node->flags |= KVS_FLAG_CUSTOM_CMP;
        kv_header->custom_cmp_enabled = 1;
    }
    kv_ins_name_len = strlen(kvs_name)+1;
    node->kvs_name = (char *)malloc(kv_ins_name_len);
    strcpy(node->kvs_name, kvs_name);

    avl_insert(kv_header->idx_name, &node->avl_name, _kvs_cmp_name);
    avl_insert(kv_header->idx_id, &node->avl_id, _kvs_cmp_id);
    ++kv_header->num_kv_stores;
    spin_unlock(&kv_header->lock);

    // if compaction is in-progress,
    // create a same kvs_node for the new file
    if (file->new_file &&
        filemgr_get_file_status(file) == FILE_COMPACT_OLD) {
        struct kvs_node *node_new;
        struct kvs_header *kv_header_new;

        kv_header_new = file->new_file->kv_header;
        node_new = (struct kvs_node*)calloc(1, sizeof(struct kvs_node));
        *node_new = *node;
        node_new->kvs_name = (char*)malloc(kv_ins_name_len);
        strcpy(node_new->kvs_name, kvs_name);

        // insert into new file's kv_header
        spin_lock(&kv_header_new->lock);
        if (node->custom_cmp) {
            kv_header_new->custom_cmp_enabled = 1;
        }
        avl_insert(kv_header_new->idx_name, &node_new->avl_name, _kvs_cmp_name);
        avl_insert(kv_header_new->idx_id, &node_new->avl_id, _kvs_cmp_id);
        spin_unlock(&kv_header_new->lock);
    }

    // sync dirty root nodes
    bid_t dirty_idtree_root, dirty_seqtree_root;
    filemgr_get_dirty_root(root_handle->file, &dirty_idtree_root, &dirty_seqtree_root);
    if (dirty_idtree_root != BLK_NOT_FOUND) {
        root_handle->trie->root_bid = dirty_idtree_root;
    }
    if (root_handle->config.seqtree_opt == FDB_SEQTREE_USE &&
        dirty_seqtree_root != BLK_NOT_FOUND) {
        if (root_handle->kvs) {
            root_handle->seqtrie->root_bid = dirty_seqtree_root;
        } else {
            btree_init_from_bid(root_handle->seqtree,
                                root_handle->seqtree->blk_handle,
                                root_handle->seqtree->blk_ops,
                                root_handle->seqtree->kv_ops,
                                root_handle->seqtree->blksize,
                                dirty_seqtree_root);
        }
    }

    // append system doc
    root_handle->kv_info_offset = fdb_kvs_header_append(root_handle);

    // if no compaction is being performed, append header and commit
    if (root_handle->file == file) {
        root_handle->cur_header_revnum = fdb_set_file_header(root_handle, true);
        fs = filemgr_commit(root_handle->file,
                !(root_handle->config.durability_opt & FDB_DRB_ASYNC),
                 &root_handle->log_callback);
    }

    filemgr_mutex_unlock(file);

    return fs;
}

// this function just returns pointer
char* _fdb_kvs_get_name(fdb_kvs_handle *handle, struct filemgr *file)
{
    struct kvs_node *node, query;
    struct avl_node *a;

    if (handle->kvs == NULL) {
        // single KV instance mode
        return NULL;
    }

    query.id = handle->kvs->id;
    if (query.id == 0) { // default KV instance
        return NULL;
    }
    spin_lock(&file->kv_header->lock);
    a = avl_search(file->kv_header->idx_id, &query.avl_id, _kvs_cmp_id);
    if (a) {
        node = _get_entry(a, struct kvs_node, avl_id);
        spin_unlock(&file->kv_header->lock);
        return node->kvs_name;
    }
    spin_unlock(&file->kv_header->lock);
    return NULL;
}

// this function just returns pointer to kvs_name & offset to user key
const char* _fdb_kvs_extract_name_off(fdb_kvs_handle *handle, void *keybuf,
                                      size_t *key_offset)
{
    struct kvs_node *node, query;
    struct avl_node *a;
    fdb_kvs_id_t kv_id;
    struct filemgr *file = handle->file;

    if (!handle->kvs) { // single KV instance mode
        *key_offset = 0;
        return DEFAULT_KVS_NAME;
    }

    *key_offset = handle->config.chunksize;
    buf2kvid(*key_offset, keybuf, &kv_id);
    query.id = kv_id;
    if (query.id == 0) { // default KV instance in multi kvs mode
        return default_kvs_name;
    }
    spin_lock(&file->kv_header->lock);
    a = avl_search(file->kv_header->idx_id, &query.avl_id, _kvs_cmp_id);
    if (a) {
        node = _get_entry(a, struct kvs_node, avl_id);
        const char *kvs_name = node->kvs_name;
        spin_unlock(&file->kv_header->lock);
        return kvs_name;
    }
    spin_unlock(&file->kv_header->lock);
    return NULL;
}

fdb_status _fdb_kvs_clone_snapshot(fdb_kvs_handle *handle_in,
                                   fdb_kvs_handle *handle_out)
{
    fdb_status fs;
    fdb_kvs_handle *root_handle = handle_in->kvs->root;

    if (!handle_out->kvs) {
        // create kvs_info
        handle_out->kvs = (struct kvs_info*)calloc(1, sizeof(struct kvs_info));
        handle_out->kvs->type = handle_in->kvs->type;
        handle_out->kvs->id = handle_in->kvs->id;
        handle_out->kvs->root = root_handle;
        handle_out->kvs_config.custom_cmp = handle_in->kvs_config.custom_cmp;

        struct kvs_opened_node *opened_node = (struct kvs_opened_node *)
            calloc(1, sizeof(struct kvs_opened_node));
        opened_node->handle = handle_out;
        handle_out->node = opened_node;

        spin_lock(&root_handle->fhandle->lock);
        list_push_back(root_handle->fhandle->handles, &opened_node->le);
        spin_unlock(&root_handle->fhandle->lock);
    }

    fs = _fdb_clone_snapshot(handle_in, handle_out);
    if (fs != FDB_RESULT_SUCCESS) {
        if (handle_out->node) {
            spin_lock(&root_handle->fhandle->lock);
            list_remove(root_handle->fhandle->handles, &handle_out->node->le);
            spin_unlock(&root_handle->fhandle->lock);
            free(handle_out->node);
        }
        free(handle_out->kvs);
    }
    return fs;
}

// 1) allocate memory & create 'handle->kvs'
//    by calling fdb_kvs_info_create().
//      -> this will allocate a corresponding node and
//         insert it into fhandle->handles list.
// 2) if matching KVS name doesn't exist, create it.
// 3) call _fdb_open().
fdb_status _fdb_kvs_open(fdb_kvs_handle *root_handle,
                         fdb_config *config,
                         fdb_kvs_config *kvs_config,
                         struct filemgr *file,
                         const char *filename,
                         const char *kvs_name,
                         fdb_kvs_handle *handle)
{
    fdb_status fs;

    if (handle->kvs == NULL) {
        // create kvs_info
        fdb_kvs_info_create(root_handle, handle, file, kvs_name);
    }

    if (handle->kvs == NULL) {
        // KV instance name is not found
        if (!kvs_config->create_if_missing) {
            return fdb_log(&root_handle->log_callback, FDB_RESULT_INVALID_KV_INSTANCE_NAME,
                           "Failed to open KV store '%s' because it doesn't exist.",
                           kvs_name ? kvs_name : DEFAULT_KVS_NAME);
        }
        if (root_handle->config.flags == FDB_OPEN_FLAG_RDONLY) {
            return fdb_log(&root_handle->log_callback, FDB_RESULT_RONLY_VIOLATION,
                           "Failed to create KV store '%s' because the KV store's handle "
                           "is read-only.", kvs_name ? kvs_name : DEFAULT_KVS_NAME);
        }

        // create
        fs = _fdb_kvs_create(root_handle, kvs_name, kvs_config);
        if (fs != FDB_RESULT_SUCCESS) { // create fail
            return FDB_RESULT_INVALID_KV_INSTANCE_NAME;
        }
        // create kvs_info again
        fdb_kvs_info_create(root_handle, handle, file, kvs_name);
        if (handle->kvs == NULL) { // fail again
            return fdb_log(&root_handle->log_callback, FDB_RESULT_INVALID_KV_INSTANCE_NAME,
                           "Failed to create KV store '%s' because the KV store's handle "
                           "is read-only.", kvs_name ? kvs_name : DEFAULT_KVS_NAME);
        }
    }
    fs = _fdb_open(handle, filename, FDB_AFILENAME, config);
    if (fs != FDB_RESULT_SUCCESS) {
        if (handle->node) {
            spin_lock(&root_handle->fhandle->lock);
            list_remove(root_handle->fhandle->handles, &handle->node->le);
            spin_unlock(&root_handle->fhandle->lock);
            free(handle->node);
        } // 'handle->node == NULL' happens only during rollback
        free(handle->kvs);
    }
    return fs;
}

// 1) identify whether the requested KVS is default or non-default.
// 2) if the requested KVS is default,
//   2-1) if no KVS handle is opened yet from this fhandle,
//        -> return the root handle.
//   2-2) if the root handle is already opened,
//        -> allocate memory for handle, and call _fdb_open().
//        -> 'handle->kvs' will be created in _fdb_open(),
//           since it is treated as a default handle.
//        -> allocate a corresponding node and insert it into
//           fhandle->handles list.
// 3) if the requested KVS is non-default,
//    -> allocate memory for handle, and call _fdb_kvs_open().
LIBFDB_API
fdb_status fdb_kvs_open(fdb_file_handle *fhandle,
                        fdb_kvs_handle **ptr_handle,
                        const char *kvs_name,
                        fdb_kvs_config *kvs_config)
{
    fdb_kvs_handle *handle;
    fdb_config config;
    fdb_status fs;
    fdb_kvs_handle *root_handle;
    fdb_kvs_config config_local;
    struct filemgr *file = NULL;
    struct filemgr *latest_file = NULL;

    if (!fhandle) {
        return FDB_RESULT_INVALID_HANDLE;
    }
    root_handle = fhandle->root;
    config = root_handle->config;

    if (kvs_config) {
        if (validate_fdb_kvs_config(kvs_config)) {
            config_local = *kvs_config;
        } else {
            return FDB_RESULT_INVALID_CONFIG;
        }
    } else {
        config_local = get_default_kvs_config();
    }

    fdb_check_file_reopen(root_handle, NULL);
    fdb_sync_db_header(root_handle);

    file = root_handle->file;
    latest_file = root_handle->file;

    if (kvs_name == NULL || !strcmp(kvs_name, default_kvs_name)) {
        // return the default KV store handle
        spin_lock(&fhandle->lock);
        if (!(fhandle->flags & FHANDLE_ROOT_OPENED)) {
            // the root handle is not opened yet
            // just return the root handle
            fdb_custom_cmp_variable default_kvs_cmp;

            root_handle->kvs_config = config_local;

            if (root_handle->file->kv_header) {
                // search fhandle's custom cmp func list first
                default_kvs_cmp = fdb_kvs_find_cmp_name(root_handle, (char *)kvs_name);

                spin_lock(&root_handle->file->kv_header->lock);
                root_handle->file->kv_header->default_kvs_cmp = default_kvs_cmp;

                if (root_handle->file->kv_header->default_kvs_cmp == NULL &&
                    root_handle->kvs_config.custom_cmp) {
                    // follow kvs_config's custom cmp next
                    root_handle->file->kv_header->default_kvs_cmp =
                        root_handle->kvs_config.custom_cmp;
                    fdb_file_handle_add_cmp_func(fhandle, NULL,
                                                 root_handle->kvs_config.custom_cmp);
                }

                if (root_handle->file->kv_header->default_kvs_cmp) {
                    root_handle->file->kv_header->custom_cmp_enabled = 1;
                    fhandle->flags |= FHANDLE_ROOT_CUSTOM_CMP;
                }
                spin_unlock(&root_handle->file->kv_header->lock);
            }

            *ptr_handle = root_handle;
            fhandle->flags |= FHANDLE_ROOT_INITIALIZED;
            fhandle->flags |= FHANDLE_ROOT_OPENED;
            fs = FDB_RESULT_SUCCESS;
            spin_unlock(&fhandle->lock);

        } else {
            // the root handle is already opened
            // open new default KV store handle
            spin_unlock(&fhandle->lock);
            handle = (fdb_kvs_handle*)calloc(1, sizeof(fdb_kvs_handle));
            handle->kvs_config = config_local;
            atomic_init_uint8_t(&handle->handle_busy, 0);

            if (root_handle->file->kv_header) {
                spin_lock(&root_handle->file->kv_header->lock);
                handle->kvs_config.custom_cmp =
                    root_handle->file->kv_header->default_kvs_cmp;
                spin_unlock(&root_handle->file->kv_header->lock);
            }

            handle->fhandle = fhandle;
            fs = _fdb_open(handle, file->filename, FDB_AFILENAME, &config);
            if (fs != FDB_RESULT_SUCCESS) {
                free(handle);
                *ptr_handle = NULL;
            } else {
                // insert into fhandle's list
                struct kvs_opened_node *node;
                node = (struct kvs_opened_node *)
                       calloc(1, sizeof(struct kvs_opened_node));
                node->handle = handle;
                spin_lock(&fhandle->lock);
                list_push_front(fhandle->handles, &node->le);
                spin_unlock(&fhandle->lock);

                handle->node = node;
                *ptr_handle = handle;
            }
        }
        return fs;
    }

    if (config.multi_kv_instances == false) {
        // cannot open KV instance under single DB instance mode
        return fdb_log(&root_handle->log_callback, FDB_RESULT_INVALID_CONFIG,
                       "Cannot open KV store instance '%s' because multi-KV "
                       "store instance mode is disabled.",
                       kvs_name ? kvs_name : DEFAULT_KVS_NAME);
    }
    if (root_handle->kvs->type != KVS_ROOT) {
        return fdb_log(&root_handle->log_callback, FDB_RESULT_INVALID_HANDLE,
                       "Cannot open KV store instance '%s' because the handle "
                       "doesn't support multi-KV sotre instance mode.",
                       kvs_name ? kvs_name : DEFAULT_KVS_NAME);
    }
    if (root_handle->shandle) {
        // cannot open KV instance from a snapshot
        return fdb_log(&root_handle->log_callback, FDB_RESULT_INVALID_ARGS,
                       "Not allowed to open KV store instance '%s' from the "
                       "snapshot handle.",
                       kvs_name ? kvs_name : DEFAULT_KVS_NAME);
    }

    handle = (fdb_kvs_handle *)calloc(1, sizeof(fdb_kvs_handle));
    if (!handle) { // LCOV_EXCL_START
        return FDB_RESULT_ALLOC_FAIL;
    } // LCOV_EXCL_STOP

    atomic_init_uint8_t(&handle->handle_busy, 0);
    handle->fhandle = fhandle;
    fs = _fdb_kvs_open(root_handle, &config, &config_local,
                       latest_file, file->filename, kvs_name, handle);
    if (fs == FDB_RESULT_SUCCESS) {
        *ptr_handle = handle;
    } else {
        *ptr_handle = NULL;
        free(handle);
    }
    return fs;
}

LIBFDB_API
fdb_status fdb_kvs_open_default(fdb_file_handle *fhandle,
                                fdb_kvs_handle **ptr_handle,
                                fdb_kvs_config *config)
{
    return fdb_kvs_open(fhandle, ptr_handle, NULL, config);
}

// 1) remove corresponding node from fhandle->handles list.
// 2) call _fdb_close().
static fdb_status _fdb_kvs_close(fdb_kvs_handle *handle)
{
    fdb_kvs_handle *root_handle = handle->kvs->root;
    fdb_status fs;

    if (handle->node) {
        spin_lock(&root_handle->fhandle->lock);
        list_remove(root_handle->fhandle->handles, &handle->node->le);
        spin_unlock(&root_handle->fhandle->lock);
        free(handle->node);
    } // 'handle->node == NULL' happens only during rollback

    fs = _fdb_close(handle);
    return fs;
}

// close all sub-KV store handles belonging to the root handle
fdb_status fdb_kvs_close_all(fdb_kvs_handle *root_handle)
{
    fdb_status fs;
    struct list_elem *e;
    struct kvs_opened_node *node;

    spin_lock(&root_handle->fhandle->lock);
    e = list_begin(root_handle->fhandle->handles);
    while (e) {
        node = _get_entry(e, struct kvs_opened_node, le);
        e = list_remove(root_handle->fhandle->handles, &node->le);
        fs = _fdb_close(node->handle);
        if (fs != FDB_RESULT_SUCCESS) {
            spin_unlock(&root_handle->fhandle->lock);
            return fs;
        }
        fdb_kvs_info_free(node->handle);
        free(node->handle);
        free(node);
    }
    spin_unlock(&root_handle->fhandle->lock);

    return FDB_RESULT_SUCCESS;
}

// 1) identify whether the requested handle is for default KVS or not.
// 2) if the requested handle is for the default KVS,
//   2-1) if the requested handle is the root handle,
//        -> just clear the OPENED flag.
//   2-2) if the requested handle is not the root handle,
//        -> call _fdb_close(),
//        -> free 'handle->kvs' by calling fdb_kvs_info_free(),
//        -> remove the corresponding node from fhandle->handles list,
//        -> free the memory for the handle.
// 3) if the requested handle is for non-default KVS,
//    -> call _fdb_kvs_close(),
//       -> this will remove the node from fhandle->handles list.
//    -> free 'handle->kvs' by calling fdb_kvs_info_free(),
//    -> free the memory for the handle.
LIBFDB_API
fdb_status fdb_kvs_close(fdb_kvs_handle *handle)
{
    fdb_status fs;

    if (!handle) {
        return FDB_RESULT_INVALID_HANDLE;
    }
    if (handle->num_iterators) {
        // There are still active iterators created from this handle
        return FDB_RESULT_KV_STORE_BUSY;
    }

    if (handle->shandle && handle->kvs == NULL) {
        // snapshot of the default KV store + single KV store mode
        // directly close handle
        // (snapshot of the other KV stores will be closed
        //  using _fdb_kvs_close(...) below)
        fs = _fdb_close(handle);
        if (fs == FDB_RESULT_SUCCESS) {
            free(handle);
        }
        return fs;
    }

    if (handle->kvs == NULL ||
        handle->kvs->type == KVS_ROOT) {
        // the default KV store handle

        if (handle->fhandle->root == handle) {
            // do nothing for root handle
            // the root handle will be closed with fdb_close() API call.
            spin_lock(&handle->fhandle->lock);
            handle->fhandle->flags &= ~FHANDLE_ROOT_OPENED; // remove flag
            spin_unlock(&handle->fhandle->lock);
            return FDB_RESULT_SUCCESS;

        } else {
            // the default KV store but not the root handle .. normally close
            spin_lock(&handle->fhandle->lock);
            fs = _fdb_close(handle);
            if (fs == FDB_RESULT_SUCCESS) {
                // remove from 'handles' list in the root node
                if (handle->kvs) {
                    fdb_kvs_info_free(handle);
                }
                list_remove(handle->fhandle->handles, &handle->node->le);
                spin_unlock(&handle->fhandle->lock);
                free(handle->node);
                free(handle);
            } else {
                spin_unlock(&handle->fhandle->lock);
            }
            return fs;
        }
    }

    if (handle->kvs && handle->kvs->root == NULL) {
        return FDB_RESULT_INVALID_ARGS;
    }
    fs = _fdb_kvs_close(handle);
    if (fs == FDB_RESULT_SUCCESS) {
        fdb_kvs_info_free(handle);
        free(handle);
    }
    return fs;
}

static
fdb_status _fdb_kvs_remove(fdb_file_handle *fhandle,
                           const char *kvs_name,
                           bool rollback_recreate)
{
    size_t size_chunk, size_id;
    uint8_t *_kv_id;
    fdb_status fs = FDB_RESULT_SUCCESS;
    fdb_kvs_id_t kv_id = 0;
    fdb_kvs_handle *root_handle;
    struct avl_node *a = NULL;
    struct filemgr *file;
    struct kvs_node *node, query;
    struct kvs_header *kv_header;

    if (!fhandle) {
        return FDB_RESULT_INVALID_HANDLE;
    }
    root_handle = fhandle->root;

    if (root_handle->config.multi_kv_instances == false) {
        // cannot remove the KV instance under single DB instance mode
        return FDB_RESULT_INVALID_CONFIG;
    }
    if (root_handle->kvs->type != KVS_ROOT) {
        return FDB_RESULT_INVALID_HANDLE;
    }

fdb_kvs_remove_start:
    if (!rollback_recreate) {
        fdb_check_file_reopen(root_handle, NULL);
        filemgr_mutex_lock(root_handle->file);
        fdb_sync_db_header(root_handle);

        if (filemgr_is_rollback_on(root_handle->file)) {
            filemgr_mutex_unlock(root_handle->file);
            return FDB_RESULT_FAIL_BY_ROLLBACK;
        }
    } else {
        filemgr_mutex_lock(root_handle->file);
    }

    file = root_handle->file;

    file_status_t fstatus = filemgr_get_file_status(file);
    if (fstatus == FILE_REMOVED_PENDING) {
        // we must not write into this file
        // file status was changed by other thread .. start over
        filemgr_mutex_unlock(file);
        goto fdb_kvs_remove_start;
    } else if (fstatus == FILE_COMPACT_OLD) {
        // Cannot remove existing KV store during compaction.
        // To remove a KV store, the corresponding first chunk in HB+trie
        // should be unlinked. This can be possible in the old file during
        // compaction, but impossible in the new file, since existing documents
        // (including docs belonging to the KV store to be removed) are being moved.
        filemgr_mutex_unlock(file);
        return FDB_RESULT_FAIL_BY_COMPACTION;
    }

    // find the kvs_node and remove

    // search by name to get ID
    if (kvs_name == NULL || !strcmp(kvs_name, default_kvs_name)) {
        if (!rollback_recreate) {
            // default KV store .. KV ID = 0
            kv_id = 0;
            if (_fdb_kvs_any_handle_opened(fhandle, kv_id)) {
                // there is an opened handle
                filemgr_mutex_unlock(file);
                return FDB_RESULT_KV_STORE_BUSY;
            }
        }
        // reset KVS stats (excepting for WAL stats)
        file->header.stat.ndocs = 0;
        file->header.stat.nlivenodes = 0;
        file->header.stat.datasize = 0;
        file->header.stat.deltasize = 0;

        // reset seqnum
        filemgr_set_seqnum(file, 0);
    } else {
        kv_header = file->kv_header;
        spin_lock(&kv_header->lock);
        query.kvs_name = (char*)kvs_name;
        a = avl_search(kv_header->idx_name, &query.avl_name, _kvs_cmp_name);
        if (a == NULL) { // KV name doesn't exist
            spin_unlock(&kv_header->lock);
            filemgr_mutex_unlock(file);
            return FDB_RESULT_KV_STORE_NOT_FOUND;
        }
        node = _get_entry(a, struct kvs_node, avl_name);
        kv_id = node->id;

        if (!rollback_recreate) {
            if (_fdb_kvs_any_handle_opened(fhandle, kv_id)) {
                // there is an opened handle
                spin_unlock(&kv_header->lock);
                filemgr_mutex_unlock(file);
                return FDB_RESULT_KV_STORE_BUSY;
            }

            avl_remove(kv_header->idx_name, &node->avl_name);
            avl_remove(kv_header->idx_id, &node->avl_id);
            --kv_header->num_kv_stores;
            spin_unlock(&kv_header->lock);

            kv_id = node->id;

            // free node
            free(node->kvs_name);
            free(node);
        } else {
            // reset all stats except for WAL
            node->stat.ndocs = 0;
            node->stat.nlivenodes = 0;
            node->stat.datasize = 0;
            node->stat.deltasize = 0;
            node->seqnum = 0;
            spin_unlock(&kv_header->lock);
        }
    }

    // discard all WAL entries
    wal_close_kv_ins(file, kv_id);

    // sync dirty root nodes
    bid_t dirty_idtree_root, dirty_seqtree_root;
    filemgr_get_dirty_root(root_handle->file, &dirty_idtree_root, &dirty_seqtree_root);
    if (dirty_idtree_root != BLK_NOT_FOUND) {
        root_handle->trie->root_bid = dirty_idtree_root;
    }
    if (root_handle->config.seqtree_opt == FDB_SEQTREE_USE &&
        dirty_seqtree_root != BLK_NOT_FOUND) {
        if (root_handle->kvs) {
            root_handle->seqtrie->root_bid = dirty_seqtree_root;
        } else {
            btree_init_from_bid(root_handle->seqtree,
                                root_handle->seqtree->blk_handle,
                                root_handle->seqtree->blk_ops,
                                root_handle->seqtree->kv_ops,
                                root_handle->seqtree->blksize,
                                dirty_seqtree_root);
        }
    }

    size_id = sizeof(fdb_kvs_id_t);
    size_chunk = root_handle->trie->chunksize;

    // remove from super handle's HB+trie
    _kv_id = alca(uint8_t, size_chunk);
    kvid2buf(size_chunk, kv_id, _kv_id);
    hbtrie_remove_partial(root_handle->trie, _kv_id, size_chunk);
    btreeblk_end(root_handle->bhandle);

    if (root_handle->config.seqtree_opt == FDB_SEQTREE_USE) {
        _kv_id = alca(uint8_t, size_id);
        kvid2buf(size_id, kv_id, _kv_id);
        hbtrie_remove_partial(root_handle->seqtrie, _kv_id, size_id);
        btreeblk_end(root_handle->bhandle);
    }

    // append system doc
    root_handle->kv_info_offset = fdb_kvs_header_append(root_handle);

    // if no compaction is being performed, append header and commit
    if (root_handle->file == file) {
        root_handle->cur_header_revnum = fdb_set_file_header(root_handle, true);
        fs = filemgr_commit(root_handle->file,
                !(root_handle->config.durability_opt & FDB_DRB_ASYNC),
                &root_handle->log_callback);
    }

    filemgr_mutex_unlock(file);

    return fs;
}

bool _fdb_kvs_is_busy(fdb_file_handle *fhandle)
{
    bool ret = false;
    struct filemgr *file = fhandle->root->file;
    struct avl_node *a;
    struct filemgr_fhandle_idx_node *fhandle_node;
    fdb_file_handle *file_handle;

    spin_lock(&file->fhandle_idx_lock);
    a = avl_first(&file->fhandle_idx);
    while (a) {
        fhandle_node = _get_entry(a, struct filemgr_fhandle_idx_node, avl);
        a = avl_next(a);
        file_handle = (fdb_file_handle *) fhandle_node->fhandle;
        spin_lock(&file_handle->lock);
        if (list_begin(file_handle->handles) != NULL) {
            ret = true;
            spin_unlock(&file_handle->lock);
            break;
        }
        spin_unlock(&file_handle->lock);
    }
    spin_unlock(&file->fhandle_idx_lock);

    return ret;
}

fdb_status fdb_kvs_rollback(fdb_kvs_handle **handle_ptr, fdb_seqnum_t seqnum)
{
    fdb_config config;
    fdb_kvs_config kvs_config;
    fdb_kvs_handle *handle_in, *handle, *super_handle;
    fdb_status fs;
    fdb_seqnum_t old_seqnum;
    fdb_file_handle *fhandle;
    char *kvs_name;

    if (!handle_ptr) {
        return FDB_RESULT_INVALID_ARGS;
    }

    handle_in = *handle_ptr;
    if (!handle_in->kvs) {
        return FDB_RESULT_INVALID_ARGS;
    }
    super_handle = handle_in->kvs->root;
    fhandle = handle_in->fhandle;
    config = handle_in->config;
    kvs_config = handle_in->kvs_config;

    // Sequence trees are a must for rollback
    if (handle_in->config.seqtree_opt != FDB_SEQTREE_USE) {
        return FDB_RESULT_INVALID_CONFIG;
    }

    if (handle_in->config.flags & FDB_OPEN_FLAG_RDONLY) {
        return fdb_log(&handle_in->log_callback,
                       FDB_RESULT_RONLY_VIOLATION,
                       "Warning: Rollback is not allowed on "
                       "the read-only DB file '%s'.",
                       handle_in->file->filename);
    }

    filemgr_mutex_lock(handle_in->file);
    filemgr_set_rollback(handle_in->file, 1); // disallow writes operations
    // All transactions should be closed before rollback
    if (wal_txn_exists(handle_in->file)) {
        filemgr_set_rollback(handle_in->file, 0);
        filemgr_mutex_unlock(handle_in->file);
        return FDB_RESULT_FAIL_BY_TRANSACTION;
    }

    // If compaction is running, wait until it is aborted.
    // TODO: Find a better way of waiting for the compaction abortion.
    unsigned int sleep_time = 10000; // 10 ms.
    file_status_t fstatus = filemgr_get_file_status(handle_in->file);
    while (fstatus == FILE_COMPACT_OLD) {
        filemgr_mutex_unlock(handle_in->file);
        decaying_usleep(&sleep_time, 1000000);
        filemgr_mutex_lock(handle_in->file);
        fstatus = filemgr_get_file_status(handle_in->file);
    }
    if (fstatus == FILE_REMOVED_PENDING) {
        filemgr_mutex_unlock(handle_in->file);
        fdb_check_file_reopen(handle_in, NULL);
    } else {
        filemgr_mutex_unlock(handle_in->file);
    }

    fdb_sync_db_header(handle_in);

    // if the max sequence number seen by this handle is lower than the
    // requested snapshot marker, it means the snapshot is not yet visible
    // even via the current fdb_kvs_handle
    if (seqnum > handle_in->seqnum) {
        filemgr_set_rollback(super_handle->file, 0); // allow mutations
        return FDB_RESULT_NO_DB_INSTANCE;
    }

    kvs_name = _fdb_kvs_get_name(handle_in, handle_in->file);
    if (seqnum == 0) { // Handle special case of rollback to zero..
        fs = _fdb_kvs_remove(fhandle, kvs_name, true /*recreate!*/);
        filemgr_set_rollback(super_handle->file, 0); // allow mutations
        return fs;
    }

    handle = (fdb_kvs_handle *) calloc(1, sizeof(fdb_kvs_handle));
    if (!handle) { // LCOV_EXCL_START
        filemgr_set_rollback(handle_in->file, 0); // allow mutations
        return FDB_RESULT_ALLOC_FAIL;
    } // LCOV_EXCL_STOP

    handle->max_seqnum = seqnum;
    handle->log_callback = handle_in->log_callback;
    handle->fhandle = fhandle;
    atomic_init_uint8_t(&handle->handle_busy, 0);

    if (handle_in->kvs->type == KVS_SUB) {
        fs = _fdb_kvs_open(handle_in->kvs->root,
                           &config,
                           &kvs_config,
                           handle_in->file,
                           handle_in->file->filename,
                           kvs_name,
                           handle);
    } else {
        fs = _fdb_open(handle, handle_in->file->filename,
                       FDB_AFILENAME, &config);
    }
    filemgr_set_rollback(handle_in->file, 0); // allow mutations

    if (fs == FDB_RESULT_SUCCESS) {
        // get KV instance's sub B+trees' root node BIDs
        // from both ID-tree and Seq-tree, AND
        // replace current handle's sub B+trees' root node BIDs
        // by old BIDs
        size_t size_chunk, size_id;
        bid_t id_root, seq_root, dummy;
        uint8_t *_kv_id;
        hbtrie_result hr;

        size_chunk = handle->trie->chunksize;
        size_id = sizeof(fdb_kvs_id_t);

        filemgr_mutex_lock(handle_in->file);

        // read root BID of the KV instance from the old handle
        // and overwrite into the current handle
        _kv_id = alca(uint8_t, size_chunk);
        kvid2buf(size_chunk, handle->kvs->id, _kv_id);
        hr = hbtrie_find_partial(handle->trie, _kv_id,
                                 size_chunk, &id_root);
        btreeblk_end(handle->bhandle);
        if (hr == HBTRIE_RESULT_SUCCESS) {
            hbtrie_insert_partial(super_handle->trie,
                                  _kv_id, size_chunk,
                                  &id_root, &dummy);
        } else { // No Trie info in rollback header.
                 // Erase kv store from super handle's main index.
            hbtrie_remove_partial(super_handle->trie, _kv_id, size_chunk);
        }
        btreeblk_end(super_handle->bhandle);

        // same as above for seq-trie
        _kv_id = alca(uint8_t, size_id);
        kvid2buf(size_id, handle->kvs->id, _kv_id);
        hr = hbtrie_find_partial(handle->seqtrie, _kv_id,
                                 size_id, &seq_root);
        btreeblk_end(handle->bhandle);
        if (hr == HBTRIE_RESULT_SUCCESS) {
            hbtrie_insert_partial(super_handle->seqtrie,
                                  _kv_id, size_id,
                                  &seq_root, &dummy);
        } else { // No seqtrie info in rollback header.
                 // Erase kv store from super handle's seqtrie index.
            hbtrie_remove_partial(super_handle->seqtrie, _kv_id, size_id);
        }
        btreeblk_end(super_handle->bhandle);

        old_seqnum = fdb_kvs_get_seqnum(handle_in->file,
                                        handle_in->kvs->id);
        fdb_kvs_set_seqnum(handle_in->file,
                           handle_in->kvs->id, seqnum);
        handle_in->seqnum = seqnum;
        filemgr_mutex_unlock(handle_in->file);

        fs = _fdb_commit(super_handle, FDB_COMMIT_NORMAL,
                         !(handle_in->config.durability_opt & FDB_DRB_ASYNC));
        if (fs == FDB_RESULT_SUCCESS) {
            _fdb_kvs_close(handle);
            *handle_ptr = handle_in;
            fdb_kvs_info_free(handle);
            free(handle);
        } else {
            // cancel the rolling-back of the sequence number
            fdb_log(&handle_in->log_callback, fs,
                    "Rollback failed due to a commit failure with a sequence "
                    "number %" _F64, seqnum);
            filemgr_mutex_lock(handle_in->file);
            fdb_kvs_set_seqnum(handle_in->file,
                               handle_in->kvs->id, old_seqnum);
            filemgr_mutex_unlock(handle_in->file);
            _fdb_kvs_close(handle);
            fdb_kvs_info_free(handle);
            free(handle);
        }
    } else {
        free(handle);
    }

    return fs;
}

LIBFDB_API
fdb_status fdb_kvs_remove(fdb_file_handle *fhandle,
                          const char *kvs_name)
{
    return _fdb_kvs_remove(fhandle, kvs_name, false);
}

LIBFDB_API
fdb_status fdb_get_kvs_info(fdb_kvs_handle *handle, fdb_kvs_info *info)
{
    uint64_t ndocs;
    uint64_t ndeletes;
    uint64_t wal_docs;
    uint64_t wal_deletes;
    uint64_t wal_n_inserts;
    uint64_t datasize;
    uint64_t nlivenodes;
    fdb_kvs_id_t kv_id;
    struct avl_node *a;
    struct filemgr *file;
    struct kvs_node *node, query;
    struct kvs_header *kv_header;
    struct kvs_stat stat;

    if (!handle || !info) {
        return FDB_RESULT_INVALID_ARGS;
    }

    if (!atomic_cas_uint8_t(&handle->handle_busy, 0, 1)) {
        return FDB_RESULT_HANDLE_BUSY;
    }

    if (!handle->shandle) { // snapshot handle should be immutable
        fdb_check_file_reopen(handle, NULL);
        fdb_sync_db_header(handle);
    }

    file = handle->file;

    if (handle->kvs == NULL) {
        info->name = default_kvs_name;
        kv_id = 0;

    } else {
        kv_header = file->kv_header;
        kv_id = handle->kvs->id;
        spin_lock(&kv_header->lock);

        query.id = handle->kvs->id;
        a = avl_search(kv_header->idx_id, &query.avl_id, _kvs_cmp_id);
        if (a) { // sub handle
            node = _get_entry(a, struct kvs_node, avl_id);
            info->name = (const char*)node->kvs_name;
        } else { // root handle
            info->name = default_kvs_name;
        }
        spin_unlock(&kv_header->lock);
    }

    if (handle->shandle) {
        // snapshot .. get its local stats
        snap_get_stat(handle->shandle, &stat);
    } else {
        _kvs_stat_get(file, kv_id, &stat);
    }
    ndocs = stat.ndocs;
    ndeletes = stat.ndeletes;
    wal_docs = stat.wal_ndocs;
    wal_deletes = stat.wal_ndeletes;
    wal_n_inserts = wal_docs - wal_deletes;

    if (ndocs + wal_n_inserts < wal_deletes) {
        info->doc_count = 0;
    } else {
        if (ndocs) { // not accurate since some ndocs may be in wal_n_inserts
            info->doc_count = ndocs + wal_n_inserts - wal_deletes;
        } else { // this is accurate
            info->doc_count = wal_n_inserts;
        }
    }

    if (ndeletes) { // not accurate since some ndeletes may be wal_n_deletes
        info->deleted_count = ndeletes + wal_deletes;
    } else { // this is accurate
        info->deleted_count = wal_deletes;
    }

    datasize = stat.datasize;
    nlivenodes = stat.nlivenodes;

    info->space_used = datasize;
    info->space_used += nlivenodes * handle->config.blocksize;
    info->file = handle->fhandle;

    atomic_cas_uint8_t(&handle->handle_busy, 1, 0);

    // This is another LIBFDB_API call, so handle is marked as free
    // in the line above before making this call
    fdb_get_kvs_seqnum(handle, &info->last_seqnum);

    return FDB_RESULT_SUCCESS;
}

LIBFDB_API
fdb_status fdb_get_kvs_ops_info(fdb_kvs_handle *handle, fdb_kvs_ops_info *info)
{
    fdb_kvs_id_t kv_id;
    struct filemgr *file;
    struct kvs_ops_stat stat;
    struct kvs_ops_stat root_stat;
    fdb_kvs_handle *root_handle = handle->fhandle->root;

    if (!handle || !info) {
        return FDB_RESULT_INVALID_ARGS;
    }

    // for snapshot handle do not reopen new file as user is interested in
    // reader stats from the old file
    if (!handle->shandle) {
        // always get stats from the latest file
        fdb_check_file_reopen(handle, NULL);
        fdb_sync_db_header(handle);
    }

    file = handle->file;

    if (handle->kvs == NULL) {
        kv_id = 0;
    } else {
        kv_id = handle->kvs->id;
    }

    _kvs_ops_stat_get(file, kv_id, &stat);

    if (root_handle != handle) {
        _kvs_ops_stat_get(file, 0, &root_stat);
    } else {
        root_stat = stat;
    }

    info->num_sets = atomic_get_uint64_t(&stat.num_sets);
    info->num_dels = atomic_get_uint64_t(&stat.num_dels);
    info->num_gets = atomic_get_uint64_t(&stat.num_gets);
    info->num_iterator_gets = atomic_get_uint64_t(&stat.num_iterator_gets);
    info->num_iterator_gets = atomic_get_uint64_t(&stat.num_iterator_gets);
    info->num_iterator_moves = atomic_get_uint64_t(&stat.num_iterator_moves);

    info->num_commits = atomic_get_uint64_t(&root_stat.num_commits);
    info->num_compacts = atomic_get_uint64_t(&root_stat.num_compacts);
    return FDB_RESULT_SUCCESS;
}

fdb_status fdb_get_kvs_name_list(fdb_file_handle *fhandle,
                                 fdb_kvs_name_list *kvs_name_list)
{
    size_t num, size, offset;
    char *ptr;
    char **segment;
    fdb_kvs_handle *root_handle;
    struct kvs_header *kv_header;
    struct kvs_node *node;
    struct avl_node *a;

    if (!fhandle || !kvs_name_list) {
        return FDB_RESULT_INVALID_ARGS;
    }

    root_handle = fhandle->root;
    kv_header = root_handle->file->kv_header;

    spin_lock(&kv_header->lock);
    // sum all lengths of KVS names first
    // (to calculate the size of memory segment to be allocated)
    num = 1;
    size = strlen(default_kvs_name) + 1;
    a = avl_first(kv_header->idx_id);
    while (a) {
        node = _get_entry(a, struct kvs_node, avl_id);
        a = avl_next(&node->avl_id);

        num++;
        size += strlen(node->kvs_name) + 1;
    }
    size += num * sizeof(char*);

    // allocate memory segment
    segment = (char**)calloc(1, size);
    kvs_name_list->num_kvs_names = num;
    kvs_name_list->kvs_names = segment;

    ptr = (char*)segment + num * sizeof(char*);
    offset = num = 0;

    // copy default KVS name
    strcpy(ptr + offset, default_kvs_name);
    segment[num] = ptr + offset;
    num++;
    offset += strlen(default_kvs_name) + 1;

    // copy the others
    a = avl_first(kv_header->idx_name);
    while (a) {
        node = _get_entry(a, struct kvs_node, avl_name);
        a = avl_next(&node->avl_name);

        strcpy(ptr + offset, node->kvs_name);
        segment[num] = ptr + offset;

        num++;
        offset += strlen(node->kvs_name) + 1;
    }

    spin_unlock(&kv_header->lock);

    return FDB_RESULT_SUCCESS;
}

LIBFDB_API
fdb_status fdb_free_kvs_name_list(fdb_kvs_name_list *kvs_name_list)
{
    if (!kvs_name_list) {
        return FDB_RESULT_INVALID_ARGS;
    }
    free(kvs_name_list->kvs_names);
    kvs_name_list->kvs_names = NULL;
    kvs_name_list->num_kvs_names = 0;

    return FDB_RESULT_SUCCESS;
}

stale_header_info fdb_get_smallest_active_header(fdb_kvs_handle *handle)
{
    uint8_t *hdr_buf = alca(uint8_t, handle->config.blocksize);
    size_t i, hdr_len;
    uint64_t n_headers;
    bid_t hdr_bid, last_wal_bid;
    filemgr_header_revnum_t hdr_revnum;
    filemgr_header_revnum_t cur_revnum;
    filemgr_magic_t magic;
    fdb_seqnum_t seqnum;
    fdb_file_handle *fhandle = NULL;
    stale_header_info ret;
    struct avl_node *a;
    struct filemgr_fhandle_idx_node *fhandle_node;
    struct list_elem *e;
    struct kvs_opened_node *item;

    ret.revnum = cur_revnum = handle->fhandle->root->cur_header_revnum;
    ret.bid = handle->fhandle->root->last_hdr_bid;

    spin_lock(&handle->file->fhandle_idx_lock);

    // check all opened file handles
    a = avl_first(&handle->file->fhandle_idx);
    while (a) {
        fhandle_node = _get_entry(a, struct filemgr_fhandle_idx_node, avl);
        a = avl_next(a);

        fhandle = (fdb_file_handle*)fhandle_node->fhandle;
        spin_lock(&fhandle->lock);
        // check all opened KVS handles belonging to the file handle
        e = list_begin(fhandle->handles);
        while (e) {

            item = _get_entry(e, struct kvs_opened_node, le);
            e = list_next(e);

            if (item->handle->cur_header_revnum < ret.revnum) {
                ret.revnum = item->handle->cur_header_revnum;
                ret.bid = item->handle->last_hdr_bid;
            }
        }
        spin_unlock(&fhandle->lock);
    }

    spin_unlock(&handle->file->fhandle_idx_lock);

    uint64_t num_keeping_headers =
        atomic_get_uint64_t(&handle->file->config->num_keeping_headers);
    if (num_keeping_headers) {
        // backward scan previous header info to keep more headers

        if (ret.bid == handle->last_hdr_bid) {
            // header in 'handle->last_hdr_bid' is not written into file yet!
            // we should start from the previous header
            hdr_bid = atomic_get_uint64_t(&handle->file->header.bid);
            hdr_revnum = handle->file->header.revnum;
        } else {
            hdr_bid = ret.bid;
            hdr_revnum = ret.revnum;
        }

        n_headers= num_keeping_headers;
        if (cur_revnum - hdr_revnum < n_headers) {
            n_headers = n_headers - (cur_revnum - hdr_revnum);
        } else {
            n_headers = 0;
        }

        for (i=0; i<n_headers; ++i) {
            hdr_bid = filemgr_fetch_prev_header(handle->file, hdr_bid,
                         hdr_buf, &hdr_len, &seqnum, &hdr_revnum, NULL,
                         &magic, NULL, &handle->log_callback);
            if (hdr_len) {
                ret.revnum = hdr_revnum;
                ret.bid = hdr_bid;
            } else {
                break;
            }
        }
    }

    // although we keep more headers from the oldest active header, we have to
    // preserve the last WAL flushing header from the target header for data
    // consistency.
    uint64_t dummy64;
    char *new_filename;

    filemgr_fetch_header(handle->file, ret.bid, hdr_buf, &hdr_len, &seqnum,
                         &hdr_revnum, NULL, &magic, NULL, &handle->log_callback);
    fdb_fetch_header(magic, hdr_buf, &dummy64, &dummy64, &dummy64, &dummy64,
                     &dummy64, &dummy64, &dummy64, &last_wal_bid, &dummy64,
                     &dummy64, &new_filename, NULL);

    if (last_wal_bid != BLK_NOT_FOUND) {
        filemgr_fetch_header(handle->file, last_wal_bid, hdr_buf, &hdr_len, &seqnum,
                             &hdr_revnum, NULL, &magic, NULL, &handle->log_callback);
        ret.bid = last_wal_bid;
        ret.revnum = hdr_revnum;
    } else {
        // WAL has not been flushed yet .. we cannot trigger block reusing
        ret.bid = BLK_NOT_FOUND;
        ret.revnum = 0;
    }

    return ret;
}

