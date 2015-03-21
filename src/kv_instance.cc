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
    int i;
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
            return FDB_RESULT_INVALID_CMP_FUNCTION;
        }
        if (!(fhandle->flags & FHANDLE_ROOT_CUSTOM_CMP) &&
              handle->kvs_config.custom_cmp) {
            // custom cmp function was not assigned before,
            // but custom cmp function is assigned from user
            file->kv_header->custom_cmp_enabled = ori_flag;
            file->kv_header->default_kvs_cmp = ori_custom_cmp;
            spin_unlock(&file->kv_header->lock);
            return FDB_RESULT_INVALID_CMP_FUNCTION;
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
            return FDB_RESULT_INVALID_CMP_FUNCTION;
        }
        if (!(kvs_node->flags & KVS_FLAG_CUSTOM_CMP) &&
              kvs_node->custom_cmp) {
            // custom cmp function was not assigned before,
            // but custom cmp function is assigned from user
            file->kv_header->custom_cmp_enabled = ori_flag;
            file->kv_header->default_kvs_cmp = ori_custom_cmp;
            spin_unlock(&file->kv_header->lock);
            return FDB_RESULT_INVALID_CMP_FUNCTION;
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

void * fdb_kvs_find_cmp_chunk(void *chunk, void *aux)
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
            return (void *)node->custom_cmp;
        }
    } else {
        // root handle
        return (void *)file->kv_header->default_kvs_cmp;
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
                         struct docio_handle *new_dhandle)
{
    struct avl_node *a, *aa;
    struct kvs_node *node_old, *node_new;

    // copy KV header data in 'handle' to new file
    fdb_kvs_header_create(new_file);
    // read from 'handle->dhandle', and import into 'new_file'
    fdb_kvs_header_read(new_file, handle->dhandle,
                           handle->kv_info_offset);
    // write KV header in 'new_file' using 'new_dhandle'
    handle->kv_info_offset = fdb_kvs_header_append(new_file,
                                                      new_dhandle);
    fdb_kvs_header_reset_all_stats(new_file);
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
     * ...
     */

    int size = 0;
    int offset = 0;
    uint16_t name_len, _name_len;
    uint64_t c = 0;
    uint64_t _n_kv, _kv_id, _flags;
    uint64_t _nlivenodes, _ndocs, _datasize;
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

        a = avl_next(a);
    }

    *len = size;

    spin_unlock(&kv_header->lock);
}

void _fdb_kvs_header_import(struct kvs_header *kv_header,
                               void *data, size_t len)
{
    int i, offset = 0;
    uint16_t name_len, _name_len;
    uint64_t n_kv, _n_kv, kv_id, _kv_id, flags, _flags;
    uint64_t _nlivenodes, _ndocs, _datasize;
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

    for (i=0;i<n_kv;++i){
        node = (struct kvs_node *)calloc(1, sizeof(struct kvs_node));

        // nname length
        memcpy(&_name_len, (uint8_t*)data + offset, sizeof(_name_len));
        offset += sizeof(_name_len);
        name_len = _endian_decode(_name_len);

        // name
        node->kvs_name = (char *)malloc(name_len);
        memcpy(node->kvs_name, (uint8_t*)data + offset, name_len);
        offset += name_len;

        // KV ID
        memcpy(&_kv_id, (uint8_t*)data + offset, sizeof(_kv_id));
        offset += sizeof(_kv_id);
        kv_id = _endian_decode(_kv_id);
        node->id = kv_id;

        // seq number
        memcpy(&_seqnum, (uint8_t*)data + offset, sizeof(_seqnum));
        offset += sizeof(_seqnum);
        seqnum = _endian_decode(_seqnum);
        node->seqnum = seqnum;

        // # live index nodes
        memcpy(&_nlivenodes, (uint8_t*)data + offset, sizeof(_nlivenodes));
        offset += sizeof(_nlivenodes);
        node->stat.nlivenodes = _endian_decode(_nlivenodes);

        // # docs
        memcpy(&_ndocs, (uint8_t*)data + offset, sizeof(_ndocs));
        offset += sizeof(_ndocs);
        node->stat.ndocs = _endian_decode(_ndocs);

        // datasize
        memcpy(&_datasize, (uint8_t*)data + offset, sizeof(_datasize));
        offset += sizeof(_datasize);
        node->stat.datasize = _endian_decode(_datasize);

        // flags
        memcpy(&_flags, (uint8_t*)data + offset, sizeof(_flags));
        offset += sizeof(_flags);
        flags = _endian_decode(_flags);
        node->flags = flags;

        // custom cmp function (in-memory attr)
        node->custom_cmp = NULL;

        avl_insert(kv_header->idx_name, &node->avl_name, _kvs_cmp_name);
        avl_insert(kv_header->idx_id, &node->avl_id, _kvs_cmp_id);
    }
    spin_unlock(&kv_header->lock);
}

fdb_status _fdb_kvs_get_snap_info(void *data,
                                  fdb_snapshot_info_t *snap_info)
{
    int i, offset = 0, sizeof_skipped_segments;
    uint16_t name_len, _name_len;
    int64_t n_kv, _n_kv;
    fdb_seqnum_t _seqnum;

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

        // Skip over seqnum, nlivenodes, ndocs, datasize and flags onto next..
        offset += sizeof_skipped_segments;
    }

    return FDB_RESULT_SUCCESS;
}

uint64_t fdb_kvs_header_append(struct filemgr *file,
                                  struct docio_handle *dhandle)
{
    char *doc_key = alca(char, 32);
    void *data;
    size_t len;
    uint64_t kv_info_offset;
    struct docio_object doc;

    _fdb_kvs_header_export(file->kv_header, &data, &len);

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

    return kv_info_offset;
}

void fdb_kvs_header_read(struct filemgr *file,
                            struct docio_handle *dhandle,
                            uint64_t kv_info_offset)
{
    uint64_t offset;
    struct docio_object doc;

    memset(&doc, 0, sizeof(struct docio_object));
    offset = docio_read_doc(dhandle, kv_info_offset, &doc);

    if (offset == kv_info_offset) {
        return;
    }

    _fdb_kvs_header_import(file->kv_header, doc.body, doc.length.bodylen);
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

LIBFDB_API
fdb_status fdb_get_kvs_seqnum(fdb_kvs_handle *handle, fdb_seqnum_t *seqnum)
{
    if (!handle) {
        return FDB_RESULT_INVALID_HANDLE;
    }
    if (!seqnum) {
        return FDB_RESULT_INVALID_ARGS;
    }

    if (handle->shandle) {
        // handle for snapshot
        // return MAX_SEQNUM instead of the file's sequence number
        *seqnum = handle->max_seqnum;
    } else {
        fdb_check_file_reopen(handle, NULL);
        fdb_link_new_file(handle);
        fdb_sync_db_header(handle);

        struct filemgr *file;
        if (handle->new_file) {
            file = handle->new_file;
        } else {
            file = handle->file;
        }

        if (handle->kvs == NULL ||
            handle->kvs->id == 0) {
            filemgr_mutex_lock(file);
            *seqnum = filemgr_get_seqnum(file);
            filemgr_mutex_unlock(file);
        } else {
            *seqnum = fdb_kvs_get_seqnum(file, handle->kvs->id);
        }
    }
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
    struct docio_handle *dhandle;
    struct kvs_node *node, query;
    struct kvs_header *kv_header;

    if (root_handle->config.multi_kv_instances == false) {
        // cannot open KV instance under single DB instance mode
        return FDB_RESULT_INVALID_CONFIG;
    }
    if (root_handle->kvs->type != KVS_ROOT) {
        return FDB_RESULT_INVALID_HANDLE;
    }

fdb_kvs_create_start:
    fdb_check_file_reopen(root_handle, NULL);
    filemgr_mutex_lock(root_handle->file);
    fdb_sync_db_header(root_handle);
    fdb_link_new_file(root_handle);

    if (filemgr_is_rollback_on(root_handle->file)) {
        filemgr_mutex_unlock(root_handle->file);
        return FDB_RESULT_FAIL_BY_ROLLBACK;
    }

    if (root_handle->new_file == NULL) {
        file = root_handle->file;
        dhandle = root_handle->dhandle;
    } else {
        // compaction is being performed and new file exists
        // relay lock
        filemgr_mutex_lock(root_handle->new_file);
        filemgr_mutex_unlock(root_handle->file);
        file = root_handle->new_file;
        dhandle = root_handle->new_dhandle;
    }

    file_status_t fstatus = filemgr_get_file_status(file);
    if (!(fstatus == FILE_NORMAL ||
          fstatus == FILE_COMPACT_NEW ||
          fstatus == FILE_COMPACT_INPROG)) {
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
        return FDB_RESULT_INVALID_KV_INSTANCE_NAME;
    }

    // create a kvs_node and insert
    node = (struct kvs_node *)calloc(1, sizeof(struct kvs_node));
    node->id = kv_header->id_counter++;
    node->seqnum = 0;
    node->flags = 0x0;
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
    spin_unlock(&kv_header->lock);

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
            root_handle->seqtree->root_bid = dirty_seqtree_root;
        }
    }

    // append system doc
    root_handle->kv_info_offset = fdb_kvs_header_append(file, dhandle);

    // if no compaction is being performed, append header and commit
    if (root_handle->file == file) {
        root_handle->cur_header_revnum = fdb_set_file_header(root_handle);
        fs = filemgr_commit(root_handle->file, &root_handle->log_callback);
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
    filemgr_mutex_lock(file);
    a = avl_search(file->kv_header->idx_id, &query.avl_id, _kvs_cmp_id);
    if (a) {
        node = _get_entry(a, struct kvs_node, avl_id);
        filemgr_mutex_unlock(file);
        return node->kvs_name;
    }
    filemgr_mutex_unlock(file);
    return NULL;
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
        filemgr_mutex_lock(file);
        fdb_kvs_info_create(root_handle, handle, file, kvs_name);
        filemgr_mutex_unlock(file);
    }

    if (handle->kvs == NULL) {
        // KV instance name is not found
        if (!kvs_config->create_if_missing) {
            return FDB_RESULT_INVALID_KV_INSTANCE_NAME;
        }
        if (root_handle->config.flags == FDB_OPEN_FLAG_RDONLY) {
            return FDB_RESULT_RONLY_VIOLATION;
        }

        // create
        fs = _fdb_kvs_create(root_handle, kvs_name, kvs_config);
        if (fs != FDB_RESULT_SUCCESS) { // create fail
            return FDB_RESULT_INVALID_KV_INSTANCE_NAME;
        }
        // create kvs_info again
        filemgr_mutex_lock(file);
        fdb_kvs_info_create(root_handle, handle, file, kvs_name);
        filemgr_mutex_unlock(file);
        if (handle->kvs == NULL) { // fail again
            return FDB_RESULT_INVALID_KV_INSTANCE_NAME;
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
    fdb_link_new_file(root_handle);
    fdb_sync_db_header(root_handle);
    if (root_handle->new_file == NULL ||
        filemgr_get_file_status(root_handle->file) == FILE_COMPACT_OLD) {
        // If the file is being compacted, new_file is incomplete yet
        // so that there is no DB header in the new_file.
        // Hence, we should open the old file.
        // Note: compaction recovery will not be triggered as the
        //       file's status is FILE_COMPACT_OLD.
        file = root_handle->file;
        // even though we open 'file' due to ongoing compaction,
        // KVS info should be retrieved from 'latest_file'.
        if (root_handle->new_file) {
            latest_file = root_handle->new_file;
        } else {
            latest_file = root_handle->file;
        }
    } else {
        file = latest_file = root_handle->new_file;
    }

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
        return FDB_RESULT_INVALID_CONFIG;
    }
    if (root_handle->kvs->type != KVS_ROOT) {
        return FDB_RESULT_INVALID_HANDLE;
    }
    if (root_handle->shandle) {
        // cannot open KV instance from a snapshot
        return FDB_RESULT_INVALID_ARGS;
    }

    handle = (fdb_kvs_handle *)calloc(1, sizeof(fdb_kvs_handle));
    if (!handle) { // LCOV_EXCL_START
        return FDB_RESULT_ALLOC_FAIL;
    } // LCOV_EXCL_STOP

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
    struct list_elem *e;
    struct filemgr *file;
    struct docio_handle *dhandle;
    struct kvs_node *node, query;
    struct kvs_header *kv_header;
    struct kvs_opened_node *opened_node;

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
        fdb_link_new_file(root_handle);

        if (filemgr_is_rollback_on(root_handle->file)) {
            filemgr_mutex_unlock(root_handle->file);
            return FDB_RESULT_FAIL_BY_ROLLBACK;
        }
    } else {
        filemgr_mutex_lock(root_handle->file);
    }

    if (root_handle->new_file == NULL) {
        file = root_handle->file;
        dhandle = root_handle->dhandle;
    } else {
        // compaction is being performed and new file exists
        // relay lock
        filemgr_mutex_lock(root_handle->new_file);
        filemgr_mutex_unlock(root_handle->file);
        file = root_handle->new_file;
        dhandle = root_handle->new_dhandle;
    }

    file_status_t fstatus = filemgr_get_file_status(file);
    if (!(fstatus == FILE_NORMAL ||
          fstatus == FILE_COMPACT_NEW ||
          fstatus == FILE_COMPACT_INPROG)) {
        // we must not write into this file
        // file status was changed by other thread .. start over
        filemgr_mutex_unlock(file);
        goto fdb_kvs_remove_start;
    }

    // find the kvs_node and remove

    // search by name to get ID
    spin_lock(&root_handle->fhandle->lock);

    if (kvs_name == NULL || !strcmp(kvs_name, default_kvs_name)) {
        if (!rollback_recreate) {
            // default KV store .. KV ID = 0
            kv_id = 0;
            e = list_begin(root_handle->fhandle->handles);
            while (e) {
                opened_node = _get_entry(e, struct kvs_opened_node, le);
                if ((opened_node->handle->kvs &&
                     opened_node->handle->kvs->id == kv_id) ||
                     opened_node->handle->kvs == NULL) // single KVS mode
                {
                    // there is an opened handle
                    spin_unlock(&root_handle->fhandle->lock);
                    filemgr_mutex_unlock(file);
                    return FDB_RESULT_KV_STORE_BUSY;
                }
                e = list_next(e);
            }
        }
        // reset KVS stats (excepting for WAL stats)
        file->header.stat.ndocs = 0;
        file->header.stat.nlivenodes = 0;
        file->header.stat.datasize = 0;
        // reset seqnum
        filemgr_set_seqnum(file, 0);
        spin_unlock(&root_handle->fhandle->lock);
    } else {
        kv_header = file->kv_header;
        spin_lock(&kv_header->lock);
        query.kvs_name = (char*)kvs_name;
        a = avl_search(kv_header->idx_name, &query.avl_name, _kvs_cmp_name);
        if (a == NULL) { // KV name doesn't exist
            spin_unlock(&kv_header->lock);
            spin_unlock(&root_handle->fhandle->lock);
            filemgr_mutex_unlock(file);
            return FDB_RESULT_KV_STORE_NOT_FOUND;
        }
        node = _get_entry(a, struct kvs_node, avl_name);
        kv_id = node->id;

        if (!rollback_recreate) {
            e = list_begin(root_handle->fhandle->handles);
            while (e) {
                opened_node = _get_entry(e, struct kvs_opened_node, le);
                if (opened_node->handle->kvs &&
                    opened_node->handle->kvs->id == kv_id) {
                    // there is an opened handle
                    spin_unlock(&kv_header->lock);
                    spin_unlock(&root_handle->fhandle->lock);
                    filemgr_mutex_unlock(file);
                    return FDB_RESULT_KV_STORE_BUSY;
                }
                e = list_next(e);
            }

            avl_remove(kv_header->idx_name, &node->avl_name);
            avl_remove(kv_header->idx_id, &node->avl_id);
            spin_unlock(&kv_header->lock);
            spin_unlock(&root_handle->fhandle->lock);

            kv_id = node->id;

            // free node
            free(node->kvs_name);
            free(node);
        } else {
            // reset all stats except for WAL
            node->stat.ndocs = 0;
            node->stat.nlivenodes = 0;
            node->stat.datasize = 0;
            node->seqnum = 0;
            spin_unlock(&kv_header->lock);
            spin_unlock(&root_handle->fhandle->lock);
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
            root_handle->seqtree->root_bid = dirty_seqtree_root;
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
    root_handle->kv_info_offset = fdb_kvs_header_append(file, dhandle);

    // if no compaction is being performed, append header and commit
    if (root_handle->file == file) {
        root_handle->cur_header_revnum = fdb_set_file_header(root_handle);
        fs = filemgr_commit(root_handle->file, &root_handle->log_callback);
    }

    filemgr_mutex_unlock(file);

    return fs;
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

    // if the max sequence number seen by this handle is lower than the
    // requested snapshot marker, it means the snapshot is not yet visible
    // even via the current fdb_kvs_handle
    if (seqnum > handle_in->seqnum) {
        return FDB_RESULT_NO_DB_INSTANCE;
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
    while (fstatus == FILE_COMPACT_OLD || fstatus == FILE_COMPACT_INPROG) {
        filemgr_mutex_unlock(handle_in->file);
        decaying_usleep(&sleep_time, 1000000);
        filemgr_mutex_lock(handle_in->file);
        fstatus = filemgr_get_file_status(handle_in->file);
    }
    if (fstatus == FILE_REMOVED_PENDING) {
        filemgr_mutex_unlock(handle_in->file);
        fdb_check_file_reopen(handle_in, NULL);
        fdb_sync_db_header(handle_in);
    } else {
        filemgr_mutex_unlock(handle_in->file);
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
            btreeblk_end(super_handle->bhandle);
        }

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
            btreeblk_end(super_handle->bhandle);
        }

        old_seqnum = fdb_kvs_get_seqnum(handle_in->file,
                                        handle_in->kvs->id);
        fdb_kvs_set_seqnum(handle_in->file,
                           handle_in->kvs->id, seqnum);
        handle_in->seqnum = seqnum;
        filemgr_mutex_unlock(handle_in->file);

        fs = _fdb_commit(super_handle, FDB_COMMIT_NORMAL);
        if (fs == FDB_RESULT_SUCCESS) {
            _fdb_kvs_close(handle);
            *handle_ptr = handle_in;
            fdb_kvs_info_free(handle);
            free(handle);
        } else {
            // cancel the rolling-back of the sequence number
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

    if (!handle->shandle) { // snapshot handle should be immutable
        fdb_check_file_reopen(handle, NULL);
        fdb_link_new_file(handle);
        fdb_sync_db_header(handle);
    }

    if (handle->new_file) {
        file = handle->new_file;
    } else {
        file = handle->file;
    }

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
    wal_docs = stat.wal_ndocs;
    wal_deletes = stat.wal_ndeletes;
    wal_n_inserts = wal_docs - wal_deletes;

    if (ndocs + wal_n_inserts < wal_deletes) {
        info->doc_count = 0;
    } else {
        if (ndocs) {
            info->doc_count = ndocs + wal_n_inserts - wal_deletes;
        } else {
            info->doc_count = wal_n_inserts;
        }
    }

    datasize = stat.datasize;
    nlivenodes = stat.nlivenodes;

    info->space_used = datasize;
    info->space_used += nlivenodes * handle->config.blocksize;

    fdb_get_kvs_seqnum(handle, &info->last_seqnum);

    info->file = handle->fhandle;
    return FDB_RESULT_SUCCESS;
}

LIBFDB_API
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
    if (root_handle->new_file) {
        kv_header = root_handle->new_file->kv_header;
    } else {
        kv_header = root_handle->file->kv_header;
    }

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
