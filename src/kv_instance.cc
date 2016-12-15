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
#include "fdb_engine.h"
#include "common.h"
#include "fdb_engine.h"
#include "internal_types.h"
#include "fdb_internal.h"
#include "file_handle.h"
#include "configuration.h"
#include "avltree.h"
#include "list.h"
#include "docio.h"
#include "filemgr.h"
#include "wal.h"
#include "hbtrie.h"
#include "btreeblock.h"
#include "version.h"
#include "staleblock.h"

#include "memleak.h"
#include "timing.h"
#include "time_utils.h"

static const char *default_kvs_name = DEFAULT_KVS_NAME;


int _kvs_cmp_name(struct avl_node *a, struct avl_node *b, void *aux)
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

void fdb_cmp_func_list_from_filemgr(FileMgr *file, struct list *cmp_func_list)
{
    if (!file || !file->getKVHeader_UNLOCKED() || !cmp_func_list) {
        return;
    }

    struct cmp_func_node *node;

    spin_lock(&file->getKVHeader_UNLOCKED()->lock);
    // Default KV store cmp function
    if (file->getKVHeader_UNLOCKED()->default_kvs_cmp) {
        node = (struct cmp_func_node*)calloc(1, sizeof(struct cmp_func_node));
        node->func = file->getKVHeader_UNLOCKED()->default_kvs_cmp;
        node->kvs_name = NULL;
        list_push_back(cmp_func_list, &node->le);
    }

    // Rest of KV stores
    struct kvs_node *kvs_node;
    struct avl_node *a = avl_first(file->getKVHeader_UNLOCKED()->idx_name);
    while (a) {
        kvs_node = _get_entry(a, struct kvs_node, avl_name);
        a = avl_next(a);
        node = (struct cmp_func_node*)calloc(1, sizeof(struct cmp_func_node));
        node->func = kvs_node->custom_cmp;
        node->kvs_name = (char*)calloc(1, strlen(kvs_node->kvs_name)+1);
        strcpy(node->kvs_name, kvs_node->kvs_name);
        list_push_back(cmp_func_list, &node->le);
    }
    spin_unlock(&file->getKVHeader_UNLOCKED()->lock);
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

fdb_status fdb_kvs_cmp_check(FdbKvsHandle *handle)
{
    int ori_flag;
    fdb_file_handle *fhandle = handle->fhandle;
    fdb_custom_cmp_variable ori_custom_cmp;
    FileMgr *file = handle->file;
    struct cmp_func_node *cmp_node;
    struct kvs_node *kvs_node, query;
    struct list_elem *e;
    struct avl_node *a;

    spin_lock(&file->getKVHeader_UNLOCKED()->lock);
    ori_flag = file->getKVHeader_UNLOCKED()->custom_cmp_enabled;
    ori_custom_cmp = file->getKVHeader_UNLOCKED()->default_kvs_cmp;

    if (fhandle->getCmpFunctionList()) {
        handle->kvs_config.custom_cmp = NULL;

        e = list_begin(fhandle->getCmpFunctionList());
        while (e) {
            cmp_node = _get_entry(e, struct cmp_func_node, le);
            if (cmp_node->kvs_name == NULL ||
                    !strcmp(cmp_node->kvs_name, default_kvs_name)) { // default KVS
                handle->kvs_config.custom_cmp = cmp_node->func;
                file->getKVHeader_UNLOCKED()->default_kvs_cmp = cmp_node->func;
                file->getKVHeader_UNLOCKED()->custom_cmp_enabled = 1;
            } else {
                // search by name
                query.kvs_name = cmp_node->kvs_name;
                a = avl_search(file->getKVHeader_UNLOCKED()->idx_name,
                               &query.avl_name,
                               _kvs_cmp_name);
                if (a) { // found
                    kvs_node = _get_entry(a, struct kvs_node, avl_name);
                    if (!kvs_node->custom_cmp) {
                        kvs_node->custom_cmp = cmp_node->func;
                    }
                    file->getKVHeader_UNLOCKED()->custom_cmp_enabled = 1;
                }
            }
            e = list_next(&cmp_node->le);
        }
    }

    // first check the default KVS
    // 1. root handle has not been opened yet: don't care
    // 2. root handle was opened before: must match the flag
    if (fhandle->getFlags() & FHANDLE_ROOT_INITIALIZED) {
        if (fhandle->getFlags() & FHANDLE_ROOT_CUSTOM_CMP &&
            handle->kvs_config.custom_cmp == NULL) {
            // custom cmp function was assigned before,
            // but no custom cmp function is assigned
            file->getKVHeader_UNLOCKED()->custom_cmp_enabled = ori_flag;
            file->getKVHeader_UNLOCKED()->default_kvs_cmp = ori_custom_cmp;
            spin_unlock(&file->getKVHeader_UNLOCKED()->lock);
            const char *kvs_name = _fdb_kvs_get_name(handle, handle->file);
            if (!kvs_name) {
                kvs_name = DEFAULT_KVS_NAME;
            }
            return fdb_log(&handle->log_callback, FDB_RESULT_INVALID_CMP_FUNCTION,
                           "Error! Tried to open a KV store '%s', which was created with "
                           "custom compare function enabled, without passing the same "
                           "custom compare function.", kvs_name);
        }
        if (!(fhandle->getFlags() & FHANDLE_ROOT_CUSTOM_CMP) &&
              handle->kvs_config.custom_cmp) {
            // custom cmp function was not assigned before,
            // but custom cmp function is assigned from user
            file->getKVHeader_UNLOCKED()->custom_cmp_enabled = ori_flag;
            file->getKVHeader_UNLOCKED()->default_kvs_cmp = ori_custom_cmp;
            spin_unlock(&file->getKVHeader_UNLOCKED()->lock);
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
    a = avl_first(file->getKVHeader_UNLOCKED()->idx_name);
    while (a) {
        kvs_node = _get_entry(a, struct kvs_node, avl_name);
        a = avl_next(a);

        if (kvs_node->flags & KVS_FLAG_CUSTOM_CMP &&
            kvs_node->custom_cmp == NULL) {
            // custom cmp function was assigned before,
            // but no custom cmp function is assigned
            file->getKVHeader_UNLOCKED()->custom_cmp_enabled = ori_flag;
            file->getKVHeader_UNLOCKED()->default_kvs_cmp = ori_custom_cmp;
            spin_unlock(&file->getKVHeader_UNLOCKED()->lock);
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
            file->getKVHeader_UNLOCKED()->custom_cmp_enabled = ori_flag;
            file->getKVHeader_UNLOCKED()->default_kvs_cmp = ori_custom_cmp;
            spin_unlock(&file->getKVHeader_UNLOCKED()->lock);
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

    spin_unlock(&file->getKVHeader_UNLOCKED()->lock);
    return FDB_RESULT_SUCCESS;
}

hbtrie_cmp_func *fdb_kvs_find_cmp_chunk(void *chunk, void *aux)
{
    fdb_kvs_id_t kv_id;
    HBTrie *trie = reinterpret_cast<HBTrie *>(aux);
    FileMgr *file;
    struct avl_node *a;
    struct kvs_node query, *node;

    file = trie->getFileMgr();

    if (!file->getKVHeader_UNLOCKED()->custom_cmp_enabled) {
        return NULL;
    }

    buf2kvid(trie->getChunkSize(), chunk, &kv_id);

    // search by id
    if (kv_id > 0) {
        query.id = kv_id;
        spin_lock(&file->getKVHeader_UNLOCKED()->lock);
        a = avl_search(file->getKVHeader_UNLOCKED()->idx_id, &query.avl_id, _kvs_cmp_id);
        spin_unlock(&file->getKVHeader_UNLOCKED()->lock);

        if (a) {
            node = _get_entry(a, struct kvs_node, avl_id);
            return (hbtrie_cmp_func *)node->custom_cmp;
        }
    } else {
        // root handle
        return (hbtrie_cmp_func *)file->getKVHeader_UNLOCKED()->default_kvs_cmp;
    }
    return NULL;
}

void _fdb_kvs_header_create(KvsHeader **kv_header_ptr)
{
    // KV ID '0' is reserved for default KV instance (super handle)
    KvsHeader *kv_header = new KvsHeader(1/*id_counter*/,
                                         0/*num_kv_stores*/);

    *kv_header_ptr = kv_header;
}

void fdb_kvs_header_create(FileMgr *file)
{
    file->acquireSpinLock();
    KvsHeader *kv_header = file->getKVHeader_UNLOCKED();
    if (kv_header) {
        file->releaseSpinLock();
        return; // already exists
    }

    _fdb_kvs_header_create(&kv_header);
    file->setKVHeader_UNLOCKED(kv_header);
    file->setFreeKVHeaderCB(fdb_kvs_header_free);
    file->releaseSpinLock();
}

void fdb_kvs_header_reset_all_stats(FileMgr *file)
{
    struct avl_node *a;
    struct kvs_node *node;
    KvsHeader *kv_header = file->getKVHeader_UNLOCKED();

    spin_lock(&kv_header->lock);
    a = avl_first(kv_header->idx_id);
    while (a) {
        node = _get_entry(a, struct kvs_node, avl_id);
        a = avl_next(&node->avl_id);
        memset(&node->stat, 0x0, sizeof(node->stat));
    }
    spin_unlock(&kv_header->lock);
}

void fdb_kvs_header_copy(FdbKvsHandle *handle,
                         FileMgr *new_file,
                         DocioHandle *new_dhandle,
                         uint64_t *new_file_kv_info_offset,
                         bool create_new)
{
    struct avl_node *a, *aa;
    struct kvs_node *node_old, *node_new;

    if (create_new) {
        KvsHeader *kv_header;
        // copy KV header data in 'handle' to new file
        _fdb_kvs_header_create(&kv_header);
        // read from 'handle->dhandle', and import into 'new_file'
        fdb_kvs_header_read(kv_header, handle->dhandle,
                            handle->kv_info_offset, handle->file->getVersion(), false);

        // write KV header in 'new_file' using 'new_dhandle'
        uint64_t new_kv_info_offset;
        FdbKvsHandle new_handle;
        new_handle.file = new_file;
        new_handle.dhandle = new_dhandle;
        new_handle.kv_info_offset = BLK_NOT_FOUND;
        new_kv_info_offset = fdb_kvs_header_append(&new_handle);
        if (new_file_kv_info_offset) {
            *new_file_kv_info_offset = new_kv_info_offset;
        }

        if (!new_file->setKVHeader(kv_header, fdb_kvs_header_free)) {
            // LCOV_EXCL_START
            _fdb_kvs_header_free(kv_header);
        } // LCOV_EXCL_STOP
        fdb_kvs_header_reset_all_stats(new_file);
    }

    spin_lock(&handle->file->getKVHeader_UNLOCKED()->lock);
    spin_lock(&new_file->getKVHeader_UNLOCKED()->lock);
    // copy all in-memory custom cmp function pointers & seqnums
    new_file->getKVHeader_UNLOCKED()->default_kvs_cmp =
        handle->file->getKVHeader_UNLOCKED()->default_kvs_cmp;
    new_file->getKVHeader_UNLOCKED()->custom_cmp_enabled =
        handle->file->getKVHeader_UNLOCKED()->custom_cmp_enabled;
    a = avl_first(handle->file->getKVHeader_UNLOCKED()->idx_id);
    while (a) {
        node_old = _get_entry(a, struct kvs_node, avl_id);
        aa = avl_search(new_file->getKVHeader_UNLOCKED()->idx_id,
                        &node_old->avl_id, _kvs_cmp_id);
        assert(aa); // MUST exist
        node_new = _get_entry(aa, struct kvs_node, avl_id);
        node_new->custom_cmp = node_old->custom_cmp;
        node_new->seqnum = node_old->seqnum;
        node_new->op_stat = node_old->op_stat;
        a = avl_next(a);
    }
    spin_unlock(&new_file->getKVHeader_UNLOCKED()->lock);
    spin_unlock(&handle->file->getKVHeader_UNLOCKED()->lock);
}

// export KV header info to raw data
static void _fdb_kvs_header_export(KvsHeader *kv_header,
                                   void **data, size_t *len, uint64_t version)
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
     * [delta size]:            8 bytes (since MAGIC_001)
     * [# deleted docs]:        8 bytes (since MAGIC_001)
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
        if (ver_is_atleast_magic_001(version)) {
            size += sizeof(node->stat.deltasize); // delta size since commit
            size += sizeof(node->stat.ndeletes); // # deleted docs
        }
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

        if (ver_is_atleast_magic_001(version)) {
            // # delta index nodes + docsize created after last commit
            _deltasize = _endian_encode(node->stat.deltasize);
            memcpy((uint8_t*)*data + offset, &_deltasize, sizeof(_deltasize));
            offset += sizeof(_deltasize);

            // # deleted documents
            _ndeletes = _endian_encode(node->stat.ndeletes);
            memcpy((uint8_t*)*data + offset, &_ndeletes, sizeof(_ndeletes));
            offset += sizeof(_ndeletes);
        }

        a = avl_next(a);
    }

    *len = size;

    spin_unlock(&kv_header->lock);
}

void _fdb_kvs_header_import(KvsHeader *kv_header,
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
    if (!ver_is_atleast_magic_001(version)) {
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
            node->op_stat.reset();
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
    if (!ver_is_atleast_magic_001(version)) {
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
    if (!ver_is_atleast_magic_001(version)) {
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

uint64_t fdb_kvs_header_append(FdbKvsHandle *handle)
{
    char *doc_key = alca(char, 32);
    void *data;
    size_t len;
    uint64_t kv_info_offset, prev_offset;
    struct docio_object doc;
    struct docio_length doc_len;
    FileMgr *file = handle->file;
    DocioHandle *dhandle = handle->dhandle;

    _fdb_kvs_header_export(file->getKVHeader_UNLOCKED(), &data, &len, file->getVersion());

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
    kv_info_offset = dhandle->appendSystemDoc_Docio(&doc);
    free(data);

    if (prev_offset != BLK_NOT_FOUND) {
        if (handle->dhandle->readDocLength_Docio(&doc_len, prev_offset)
            == FDB_RESULT_SUCCESS) {
            // mark stale
            handle->file->markDocStale(prev_offset,
                                    _fdb_get_docsize(doc_len));
        }
    }

    return kv_info_offset;
}

void fdb_kvs_header_read(KvsHeader *kv_header,
                         DocioHandle *dhandle,
                         uint64_t kv_info_offset,
                         uint64_t version,
                         bool only_seq_nums)
{
    int64_t offset;
    struct docio_object doc;

    memset(&doc, 0, sizeof(struct docio_object));
    offset = dhandle->readDoc_Docio(kv_info_offset, &doc, true);

    if (offset <= 0) {
        fdb_log(dhandle->getLogCallback(), (fdb_status) offset,
                "Failed to read a KV header with the offset %" _F64 " from a "
                "database file '%s'", kv_info_offset,
                dhandle->getFile()->getFileName());
        return;
    }

    _fdb_kvs_header_import(kv_header, doc.body, doc.length.bodylen,
                           version, only_seq_nums);
    free_docio_object(&doc, true, true, true);
}

fdb_seqnum_t fdb_kvs_get_committed_seqnum(FdbKvsHandle *handle)
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
    FileMgr *file = handle->file;

    buf = alca(uint8_t, file->getConfig()->getBlockSize());

    if (handle->kvs && handle->kvs->getKvsId() > 0) {
        id = handle->kvs->getKvsId();
    }

    hdr_bid = file->getHeaderBid();
    if (hdr_bid == BLK_NOT_FOUND) {
        // header doesn't exist
        return 0;
    }

    // read header
    file->fetchHeader(hdr_bid, buf, &len, &seqnum, NULL, NULL,
                      &version, NULL, &handle->log_callback);
    if (id > 0) { // non-default KVS
        // read last KVS header
        fdb_fetch_header(version, buf, &dummy64, &dummy64,
                         &dummy64, &dummy64, &dummy64, &dummy64,
                         &dummy64, &dummy64,
                         &kv_info_offset, &dummy64,
                         &compacted_filename, NULL);

        int64_t doc_offset;
        KvsHeader *kv_header;
        struct docio_object doc;

        _fdb_kvs_header_create(&kv_header);
        memset(&doc, 0, sizeof(struct docio_object));
        doc_offset = handle->dhandle->readDoc_Docio(kv_info_offset, &doc, true);

        if (doc_offset <= 0) {
            // fail
            _fdb_kvs_header_free(kv_header);
            return 0;

        } else {
            _fdb_kvs_header_import(kv_header, doc.body,
                                   doc.length.bodylen, version, false);
            // get local sequence number for the KV instance
            seqnum = _fdb_kvs_get_seqnum(kv_header,
                                         handle->kvs->getKvsId());
            _fdb_kvs_header_free(kv_header);
            free_docio_object(&doc, true, true, true);
        }
    }
    return seqnum;
}

LIBFDB_API
fdb_status fdb_get_kvs_seqnum(FdbKvsHandle *handle, fdb_seqnum_t *seqnum)
{
    FdbEngine *fdb_engine = FdbEngine::getInstance();
    if (fdb_engine) {
        return fdb_engine->getKvsSeqnum(handle, seqnum);
    }
    return FDB_RESULT_ENGINE_NOT_INSTANTIATED;
}

void fdb_kvs_set_seqnum(FileMgr *file,
                        fdb_kvs_id_t id,
                        fdb_seqnum_t seqnum)
{
    KvsHeader *kv_header = file->getKVHeader_UNLOCKED();
    struct kvs_node query, *node;
    struct avl_node *a;

    if (id == 0) {
        // default KV instance
        file->setSeqnum(seqnum);
        return;
    }

    spin_lock(&kv_header->lock);
    query.id = id;
    a = avl_search(kv_header->idx_id, &query.avl_id, _kvs_cmp_id);
    node = _get_entry(a, struct kvs_node, avl_id);
    node->seqnum = seqnum;
    spin_unlock(&kv_header->lock);
}

void _fdb_kvs_header_free(KvsHeader *kv_header)
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

    delete kv_header;
}

void fdb_kvs_header_free(FileMgr *file)
{
    file->acquireSpinLock();
    if (file->getKVHeader_UNLOCKED() == NULL) {
        file->releaseSpinLock();
        return;
    }

    _fdb_kvs_header_free(file->getKVHeader_UNLOCKED());
    file->setKVHeader_UNLOCKED(NULL);
    file->releaseSpinLock();
}

// this function just returns pointer
char* _fdb_kvs_get_name(FdbKvsHandle *handle, FileMgr *file)
{
    struct kvs_node *node, query;
    struct avl_node *a;

    if (handle->kvs == NULL) {
        // single KV instance mode
        return NULL;
    }

    query.id = handle->kvs->getKvsId();
    if (query.id == 0) { // default KV instance
        return NULL;
    }
    spin_lock(&file->getKVHeader_UNLOCKED()->lock);
    a = avl_search(file->getKVHeader_UNLOCKED()->idx_id, &query.avl_id, _kvs_cmp_id);
    if (a) {
        node = _get_entry(a, struct kvs_node, avl_id);
        spin_unlock(&file->getKVHeader_UNLOCKED()->lock);
        return node->kvs_name;
    }
    spin_unlock(&file->getKVHeader_UNLOCKED()->lock);
    return NULL;
}

// this function just returns pointer to kvs_name & offset to user key
const char* _fdb_kvs_extract_name_off(FdbKvsHandle *handle, void *keybuf,
                                      size_t *key_offset)
{
    struct kvs_node *node, query;
    struct avl_node *a;
    fdb_kvs_id_t kv_id;
    FileMgr *file = handle->file;

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
    spin_lock(&file->getKVHeader_UNLOCKED()->lock);
    a = avl_search(file->getKVHeader_UNLOCKED()->idx_id, &query.avl_id, _kvs_cmp_id);
    if (a) {
        node = _get_entry(a, struct kvs_node, avl_id);
        const char *kvs_name = node->kvs_name;
        spin_unlock(&file->getKVHeader_UNLOCKED()->lock);
        return kvs_name;
    }
    spin_unlock(&file->getKVHeader_UNLOCKED()->lock);
    return NULL;
}

fdb_status _fdb_kvs_clone_snapshot(FdbKvsHandle *handle_in,
                                   FdbKvsHandle *handle_out)
{
    fdb_status fs;
    FdbKvsHandle *root_handle = handle_in->kvs->getRootHandle();

    if (!handle_out->kvs) {
        // create kvs_info
        handle_out->kvs = new KvsInfo();
        handle_out->kvs->setKvsType(handle_in->kvs->getKvsType());
        handle_out->kvs->setKvsId(handle_in->kvs->getKvsId());
        handle_out->kvs->setRootHandle(root_handle);
        handle_out->kvs_config.custom_cmp = handle_in->kvs_config.custom_cmp;

        struct kvs_opened_node *opened_node = (struct kvs_opened_node *)
            calloc(1, sizeof(struct kvs_opened_node));
        opened_node->handle = handle_out;
        handle_out->node = opened_node;

        root_handle->fhandle->addKVHandle(&opened_node->le);
    }

    fs = _fdb_clone_snapshot(handle_in, handle_out);
    if (fs != FDB_RESULT_SUCCESS) {
        if (handle_out->node) {
            root_handle->fhandle->removeKVHandle(&handle_out->node->le);
            free(handle_out->node);
        }
    }
    return fs;
}

LIBFDB_API
fdb_status fdb_kvs_open(fdb_file_handle *fhandle,
                        FdbKvsHandle **ptr_handle,
                        const char *kvs_name,
                        fdb_kvs_config *kvs_config)
{
    FdbEngine *fdb_engine = FdbEngine::getInstance();
    if (fdb_engine) {
        return fdb_engine->openKvs(fhandle, ptr_handle, kvs_name, kvs_config);
    }
    return FDB_RESULT_ENGINE_NOT_INSTANTIATED;
}

LIBFDB_API
fdb_status fdb_kvs_open_default(fdb_file_handle *fhandle,
                                FdbKvsHandle **ptr_handle,
                                fdb_kvs_config *config)
{
    FdbEngine *fdb_engine = FdbEngine::getInstance();
    if (fdb_engine) {
        return fdb_engine->openDefaultKvs(fhandle, ptr_handle, config);
    }
    return FDB_RESULT_ENGINE_NOT_INSTANTIATED;
}

LIBFDB_API
fdb_status fdb_kvs_close(FdbKvsHandle *handle)
{
    FdbEngine *fdb_engine = FdbEngine::getInstance();
    if (fdb_engine) {
        return fdb_engine->closeKvs(handle);
    }
    return FDB_RESULT_ENGINE_NOT_INSTANTIATED;
}

bool _fdb_kvs_is_busy(fdb_file_handle *fhandle)
{
    bool ret = false;
    FileMgr *file = fhandle->getRootHandle()->file;
    struct avl_node *a;
    struct filemgr_fhandle_idx_node *fhandle_node;
    fdb_file_handle *file_handle;

    file->acquireHandleIdxLock();
    struct avl_tree *handle_idx = file->getHandleIdx();
    a = avl_first(handle_idx);
    while (a) {
        fhandle_node = _get_entry(a, struct filemgr_fhandle_idx_node, avl);
        a = avl_next(a);
        file_handle = (fdb_file_handle *) fhandle_node->fhandle;
        if (!file_handle->isKVHandleListEmpty()) {
            ret = true;
            break;
        }
    }
    file->releaseHandleIdxLock();

    return ret;
}

LIBFDB_API
fdb_status fdb_kvs_remove(fdb_file_handle *fhandle,
                          const char *kvs_name)
{
    FdbEngine *fdb_engine = FdbEngine::getInstance();
    if (fdb_engine) {
        return fdb_engine->removeKvs(fhandle, kvs_name);
    }
    return FDB_RESULT_ENGINE_NOT_INSTANTIATED;
}

LIBFDB_API
fdb_status fdb_get_kvs_info(FdbKvsHandle *handle, fdb_kvs_info *info)
{
    FdbEngine *fdb_engine = FdbEngine::getInstance();
    if (fdb_engine) {
        return fdb_engine->getKvsInfo(handle, info);
    }
    return FDB_RESULT_ENGINE_NOT_INSTANTIATED;
}

LIBFDB_API
fdb_status fdb_get_kvs_ops_info(FdbKvsHandle *handle, fdb_kvs_ops_info *info)
{
    FdbEngine *fdb_engine = FdbEngine::getInstance();
    if (fdb_engine) {
        return fdb_engine->getKvsOpsInfo(handle, info);
    }
    return FDB_RESULT_ENGINE_NOT_INSTANTIATED;
}

LIBFDB_API
fdb_status fdb_get_kvs_name_list(fdb_file_handle *fhandle,
                                 fdb_kvs_name_list *kvs_name_list)
{
    FdbEngine *fdb_engine = FdbEngine::getInstance();
    if (fdb_engine) {
        return fdb_engine->getKvsNameList(fhandle, kvs_name_list);
    }
    return FDB_RESULT_ENGINE_NOT_INSTANTIATED;
}

LIBFDB_API
fdb_status fdb_free_kvs_name_list(fdb_kvs_name_list *kvs_name_list)
{
    FdbEngine *fdb_engine = FdbEngine::getInstance();
    if (fdb_engine) {
        return fdb_engine->freeKvsNameList(kvs_name_list);
    }
    return FDB_RESULT_ENGINE_NOT_INSTANTIATED;
}

LIBFDB_API
fdb_seqnum_t fdb_get_available_rollback_seq(FdbKvsHandle *handle,
                                            uint64_t request_seqno) {
    FdbEngine *fdb_engine = FdbEngine::getInstance();
    if (fdb_engine) {
        return fdb_engine->getAvailableRollbackSeq(handle, request_seqno);
    }
    return 0;
}

stale_header_info fdb_get_smallest_active_header(FdbKvsHandle *handle)
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

    FdbKvsHandle *root_handle = handle->fhandle->getRootHandle();
    ret.revnum = cur_revnum = root_handle->cur_header_revnum;
    ret.bid = root_handle->last_hdr_bid;

    handle->file->acquireHandleIdxLock();

    // check all opened file handles
    struct avl_tree *handle_idx = handle->file->getHandleIdx();
    a = avl_first(handle_idx);
    while (a) {
        fhandle_node = _get_entry(a, struct filemgr_fhandle_idx_node, avl);
        a = avl_next(a);

        fhandle = (fdb_file_handle*) fhandle_node->fhandle;
        // check all opened KVS handles belonging to the file handle
        stale_header_info oldest_header = fhandle->getOldestActiveHeader();
        if (oldest_header.revnum < ret.revnum) {
            ret = oldest_header;
        }
    }

    handle->file->releaseHandleIdxLock();

    uint64_t num_keeping_headers = handle->file->getConfig()->getNumKeepingHeaders();
    if (num_keeping_headers) {
        // backward scan previous header info to keep more headers

        if (ret.bid == handle->last_hdr_bid) {
            // header in 'handle->last_hdr_bid' is not written into file yet!
            // we should start from the previous header and revnum
            hdr_bid = handle->file->accessHeader()->bid.load();
            hdr_revnum = handle->file->accessHeader()->revnum;
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
            hdr_bid = handle->file->fetchPrevHeader(hdr_bid, hdr_buf, &hdr_len,
                                                    &seqnum, &hdr_revnum, NULL,
                                                    &magic, NULL,
                                                    &handle->log_callback);
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

    handle->file->fetchHeader(ret.bid, hdr_buf, &hdr_len, &seqnum, &hdr_revnum,
                              NULL, &magic, NULL, &handle->log_callback);
    fdb_fetch_header(magic, hdr_buf, &dummy64, &dummy64, &dummy64, &dummy64,
                     &dummy64, &dummy64, &dummy64, &last_wal_bid, &dummy64,
                     &dummy64, &new_filename, NULL);

    if (last_wal_bid != BLK_NOT_FOUND) {
        handle->file->fetchHeader(last_wal_bid, hdr_buf, &hdr_len, &seqnum,
                                  &hdr_revnum, NULL, &magic, NULL,
                                  &handle->log_callback);
        ret.bid = last_wal_bid;
        ret.revnum = hdr_revnum;
    } else {
        // WAL has not been flushed yet .. we cannot trigger block reusing
        ret.bid = BLK_NOT_FOUND;
        ret.revnum = 0;
    }

    return ret;
}

fdb_status FdbEngine::getKvsInfo(FdbKvsHandle *handle, fdb_kvs_info *info)
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
    FileMgr *file;
    struct kvs_node *node, query;
    KvsHeader *kv_header;
    KvsStat stat;
    fdb_status status = FDB_RESULT_SUCCESS;

    if (!handle) {
        return FDB_RESULT_INVALID_HANDLE;
    }

    if (!info) {
        return FDB_RESULT_INVALID_ARGS;
    }

    if (!BEGIN_HANDLE_BUSY(handle)) {
        return FDB_RESULT_HANDLE_BUSY;
    }

    if (!handle->shandle) { // snapshot handle should be immutable
        status = fdb_check_file_reopen(handle, NULL);
        if (status != FDB_RESULT_SUCCESS) {
            END_HANDLE_BUSY(handle);
            return status;
        }
        fdb_sync_db_header(handle);
    }

    file = handle->file;

    if (handle->kvs == NULL) {
        info->name = default_kvs_name;
        kv_id = 0;

    } else {
        kv_header = file->getKVHeader_UNLOCKED();
        kv_id = handle->kvs->getKvsId();
        spin_lock(&kv_header->lock);

        query.id = handle->kvs->getKvsId();
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
        file->getWal()->getSnapStats_Wal(handle->shandle, &stat);
    } else {
        file->getKvsStatOps()->statGet(kv_id, &stat);
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

    END_HANDLE_BUSY(handle);

    // This is another LIBFDB_API call, so handle is marked as free
    // in the line above before making this call
    getKvsSeqnum(handle, &info->last_seqnum);

    return status;
}

fdb_status FdbEngine::getKvsOpsInfo(FdbKvsHandle *handle, fdb_kvs_ops_info *info)
{
    fdb_kvs_id_t kv_id;
    FileMgr *file;
    KvsOpsStat stat;
    KvsOpsStat root_stat;
    fdb_status status = FDB_RESULT_SUCCESS;

    if (!handle) {
        return FDB_RESULT_INVALID_HANDLE;
    }

    if (!info) {
        return FDB_RESULT_INVALID_ARGS;
    }

    FdbKvsHandle *root_handle = handle->fhandle->getRootHandle();

    // for snapshot handle do not reopen new file as user is interested in
    // reader stats from the old file
    if (!handle->shandle) {
        // always get stats from the latest file
        status = fdb_check_file_reopen(handle, NULL);
        if (status != FDB_RESULT_SUCCESS) {
            return status;
        }
        fdb_sync_db_header(handle);
    }

    file = handle->file;

    if (handle->kvs == NULL) {
        kv_id = 0;
    } else {
        kv_id = handle->kvs->getKvsId();
    }

    file->getKvsStatOps()->opsStatGet(kv_id, &stat);

    if (root_handle != handle) {
        file->getKvsStatOps()->opsStatGet(0, &root_stat);
    } else {
        root_stat = stat;
    }

    info->num_sets = stat.num_sets.load(std::memory_order_relaxed);
    info->num_dels = stat.num_dels.load(std::memory_order_relaxed);
    info->num_gets = stat.num_gets.load(std::memory_order_relaxed);
    info->num_iterator_gets = stat.num_iterator_gets.load(
                                                     std::memory_order_relaxed);
    info->num_iterator_moves = stat.num_iterator_moves.load(
                                                     std::memory_order_relaxed);

    info->num_commits = root_stat.num_commits.load(std::memory_order_relaxed);
    info->num_compacts = root_stat.num_compacts.load(std::memory_order_relaxed);
    return status;
}

fdb_status FdbEngine::getKvsSeqnum(FdbKvsHandle *handle, fdb_seqnum_t *seqnum)
{
    fdb_status status = FDB_RESULT_SUCCESS;
    if (!handle) {
        return FDB_RESULT_INVALID_HANDLE;
    }

    if (!seqnum) {
        return FDB_RESULT_INVALID_ARGS;
    }

    if (!BEGIN_HANDLE_BUSY(handle)) {
        return FDB_RESULT_HANDLE_BUSY;
    }

    if (handle->shandle) {
        // handle for snapshot
        // return MAX_SEQNUM instead of the file's sequence number
        *seqnum = handle->max_seqnum;
    } else {
        status = fdb_check_file_reopen(handle, NULL);
        if (status != FDB_RESULT_SUCCESS) {
            END_HANDLE_BUSY(handle);
            return status;
        }
        fdb_sync_db_header(handle);

        FileMgr *file;
        file = handle->file;

        if (handle->kvs == NULL ||
            handle->kvs->getKvsId() == 0) {
            file->mutexLock();
            *seqnum = file->getSeqnum();
            file->mutexUnlock();
        } else {
            *seqnum = fdb_kvs_get_seqnum(file, handle->kvs->getKvsId());
        }
    }

    END_HANDLE_BUSY(handle);
    return status;
}

fdb_status FdbEngine::getKvsNameList(FdbFileHandle *fhandle,
                                     fdb_kvs_name_list *kvs_name_list)
{
    size_t num, size, offset;
    char *ptr;
    char **segment;
    FdbKvsHandle *root_handle;
    KvsHeader *kv_header;
    struct kvs_node *node;
    struct avl_node *a;

    if (!fhandle) {
        return FDB_RESULT_INVALID_HANDLE;
    }

    if (!kvs_name_list) {
        return FDB_RESULT_INVALID_ARGS;
    }

    root_handle = fhandle->getRootHandle();
    kv_header = root_handle->file->getKVHeader_UNLOCKED();

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

fdb_seqnum_t FdbEngine::getAvailableRollbackSeq(FdbKvsHandle *handle,
                                                uint64_t request_seqno) {

    if (!handle) {
        // FDB_RESULT_INVALID_HANDLE;
        return (fdb_seqnum_t) 0;
    }

    if (request_seqno == 0) {
        // Avoid unnecessary fetching of snapshot markers
        return (fdb_seqnum_t) 0;
    }

    fdb_snapshot_info_t *markers;
    uint64_t marker_count;
    fdb_status status = FDB_RESULT_SUCCESS;

    // Fetch all available snapshot markers
    status = getAllSnapMarkers(handle->fhandle, &markers, &marker_count);
    if (status != FDB_RESULT_SUCCESS) {
        // No markers available / Allocation failure perhaps
        return (fdb_seqnum_t) 0;
    }

    const char *kvs_name = _fdb_kvs_get_name(handle, handle->file);
    fdb_seqnum_t rollback_seqno = 0;

    // Iterate over the retrieved markers to find the closest available
    // rollback sequence number to the request_seqno for the provided
    // KV store
    for (uint64_t i = 0; i < marker_count; ++i) {
        for (int64_t j = 0; j < markers[i].num_kvs_markers; ++j) {
            if (kvs_name == NULL) { // Default KVS
                if (markers[i].kvs_markers[j].kv_store_name == NULL) {
                    rollback_seqno = markers[i].kvs_markers[j].seqnum;
                    break;
                }
            } else if (strcmp(kvs_name,
                              markers[i].kvs_markers[j].kv_store_name) == 0) {
                rollback_seqno = markers[i].kvs_markers[j].seqnum;
                break;
            }
        }
        if (rollback_seqno <= request_seqno) {
            break;
        }
    }

    freeSnapMarkers(markers, marker_count);

    if (rollback_seqno > request_seqno) {
        // No header/marker available to rollback to
        rollback_seqno = 0;
    }

    return rollback_seqno;
}

fdb_status FdbEngine::freeKvsNameList(fdb_kvs_name_list *kvs_name_list)
{
    if (!kvs_name_list) {
        return FDB_RESULT_INVALID_ARGS;
    }

    free(kvs_name_list->kvs_names);
    kvs_name_list->kvs_names = NULL;
    kvs_name_list->num_kvs_names = 0;

    return FDB_RESULT_SUCCESS;
}

// 1) identify whether the requested KVS is default or non-default.
// 2) if the requested KVS is default,
//   2-1) As the root handle is already opened,
//        -> allocate memory for handle, and call FdbEngine::openFdb().
//        -> 'handle->kvs' will be created in FdbEngine::openFdb(),
//           since it is treated as a default handle.
//        -> allocate a corresponding node and insert it into
//           fhandle->handles list.
// 3) if the requested KVS is non-default,
//    -> allocate memory for handle, and call openKvs().
fdb_status FdbEngine::openKvs(FdbFileHandle *fhandle,
                              FdbKvsHandle **ptr_handle,
                              const char *kvs_name,
                              fdb_kvs_config *kvs_config)
{
    FdbKvsHandle *handle;
    fdb_config config;
    fdb_status fs;
    FdbKvsHandle *root_handle;
    fdb_kvs_config config_local;

    LATENCY_STAT_START();

    if (!fhandle || !fhandle->getRootHandle()) {
        return FDB_RESULT_INVALID_HANDLE;
    }

    root_handle = fhandle->getRootHandle();
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

    fs = fdb_check_file_reopen(root_handle, NULL);
    if (fs != FDB_RESULT_SUCCESS) {
        return fs;
    }
    fdb_sync_db_header(root_handle);

    if (kvs_name == NULL || !strcmp(kvs_name, default_kvs_name)) {
        fhandle->activateRootHandle(kvs_name, config_local);
        // open new default KV store handle
        handle = new FdbKvsHandle();
        handle->kvs_config = config_local;
        handle->initBusy();

        if (root_handle->file->getKVHeader_UNLOCKED()) {
            spin_lock(&root_handle->file->getKVHeader_UNLOCKED()->lock);
            handle->kvs_config.custom_cmp =
                root_handle->file->getKVHeader_UNLOCKED()->default_kvs_cmp;
            spin_unlock(&root_handle->file->getKVHeader_UNLOCKED()->lock);
        }

        handle->fhandle = fhandle;
        fs = openFdb(handle, root_handle->file->getFileName(),
                FDB_AFILENAME, &config);
        if (fs != FDB_RESULT_SUCCESS) {
            delete handle;
            *ptr_handle = NULL;
        } else {
            // insert into fhandle's list
            struct kvs_opened_node *node = (struct kvs_opened_node *)
                calloc(1, sizeof(struct kvs_opened_node));
            node->handle = handle;
            fhandle->addKVHandle(&node->le);
            handle->node = node;
            *ptr_handle = handle;
        }
        LATENCY_STAT_END(root_handle->file, FDB_LATENCY_KVS_OPEN);
        return fs;
    }

    if (config.multi_kv_instances == false) {
        // cannot open KV instance under single DB instance mode
        return fdb_log(&root_handle->log_callback, FDB_RESULT_INVALID_CONFIG,
                       "Cannot open KV store instance '%s' because multi-KV "
                       "store instance mode is disabled.",
                       kvs_name ? kvs_name : DEFAULT_KVS_NAME);
    }
    if (root_handle->kvs->getKvsType() != KVS_ROOT) {
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

    handle = new FdbKvsHandle();
    if (!handle) { // LCOV_EXCL_START
        return FDB_RESULT_ALLOC_FAIL;
    } // LCOV_EXCL_STOP

    handle->initBusy();
    handle->fhandle = fhandle;
    fs = openKvs(root_handle, &config, &config_local,
                 root_handle->file, root_handle->file->getFileName(),
                 kvs_name, handle);
    if (fs == FDB_RESULT_SUCCESS) {
        *ptr_handle = handle;
    } else {
        *ptr_handle = NULL;
        delete handle;
    }
    LATENCY_STAT_END(root_handle->file, FDB_LATENCY_KVS_OPEN);
    return fs;
}

fdb_status FdbEngine::openDefaultKvs(FdbFileHandle *fhandle,
                                     FdbKvsHandle **ptr_handle,
                                     fdb_kvs_config *config)
{
    return openKvs(fhandle, ptr_handle, NULL, config);
}

// 1) allocate memory & create 'handle->kvs'
//    by calling handle->createKvsInfo().
//      -> this will allocate a corresponding node and
//         insert it into fhandle->handles list.
// 2) if matching KVS name doesn't exist, create it.
// 3) call FdbEngine::openFdb.
fdb_status FdbEngine::openKvs(FdbKvsHandle *root_handle,
                              fdb_config *config,
                              fdb_kvs_config *kvs_config,
                              FileMgr *file,
                              const char *filename,
                              const char *kvs_name,
                              FdbKvsHandle *handle)
{
    fdb_status fs;

    if (handle->kvs == NULL) {
        // create kvs_info
        handle->file = file;
        handle->createKvsInfo(root_handle, kvs_name);
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

        // create the KV store
        fs = createKvs(root_handle, kvs_name, kvs_config);

        // If fs == INVALID_KV_INSTANCE_NAME, it means that the same KVS name already
        // exists. Since 'handle->kvs' was NULL at above if condition, the KVS might
        // be created by other concurrent thread. So we can tolerate this case and
        // try the creation of 'handle->kvs' again.
        if ( fs != FDB_RESULT_SUCCESS &&
             fs != FDB_RESULT_INVALID_KV_INSTANCE_NAME ) { // create fail
            return fs;
        }
        // create kvs_info again
        handle->createKvsInfo(root_handle, kvs_name);
        if (handle->kvs == NULL) { // fail again
            return fdb_log(&root_handle->log_callback, FDB_RESULT_INVALID_KV_INSTANCE_NAME,
                           "Failed to create KV store '%s' because the KV store's handle "
                           "is read-only.", kvs_name ? kvs_name : DEFAULT_KVS_NAME);
        }
    }
    fs = openFdb(handle, filename, FDB_AFILENAME, config);
    if (fs != FDB_RESULT_SUCCESS) {
        if (handle->node) {
            root_handle->fhandle->removeKVHandle(&handle->node->le);
            free(handle->node);
        } // 'handle->node == NULL' happens only during rollback
    }
    return fs;
}

fdb_status FdbEngine::rollbackKvs(FdbKvsHandle **handle_ptr, fdb_seqnum_t seqnum)
{
    fdb_config config;
    fdb_kvs_config kvs_config;
    FdbKvsHandle *handle_in, *handle, *super_handle;
    fdb_status fs;
    fdb_seqnum_t old_seqnum;
    fdb_file_handle *fhandle;
    char *kvs_name;

    if (!handle_ptr) {
        return FDB_RESULT_INVALID_HANDLE;
    }

    handle_in = *handle_ptr;

    if (!handle_in) {
        return FDB_RESULT_INVALID_HANDLE;
    }

    if (!handle_in->kvs) {
        return FDB_RESULT_INVALID_ARGS;
    }
    super_handle = handle_in->kvs->getRootHandle();
    fhandle = handle_in->fhandle;
    config = handle_in->config;
    kvs_config = handle_in->kvs_config;

    if (handle_in->config.flags & FDB_OPEN_FLAG_RDONLY) {
        return fdb_log(&handle_in->log_callback,
                       FDB_RESULT_RONLY_VIOLATION,
                       "Warning: Rollback is not allowed on "
                       "the read-only DB file '%s'.",
                       handle_in->file->getFileName());
    }

    handle_in->file->mutexLock();
    handle_in->file->setRollback(1); // disallow writes operations
    // All transactions should be closed before rollback
    if (handle_in->file->getWal()->doesTxnExist_Wal()) {
        handle_in->file->setRollback(0);
        handle_in->file->mutexUnlock();
        return FDB_RESULT_FAIL_BY_TRANSACTION;
    }

    // If compaction is running, wait until it is aborted.
    // TODO: Find a better way of waiting for the compaction abortion.
    unsigned int sleep_time = 10000; // 10 ms.
    file_status_t fMgrStatus = handle_in->file->getFileStatus();
    while (fMgrStatus == FILE_COMPACT_OLD) {
        handle_in->file->mutexUnlock();
        decaying_usleep(&sleep_time, 1000000);
        handle_in->file->mutexLock();
        fMgrStatus = handle_in->file->getFileStatus();
    }
    if (fMgrStatus == FILE_REMOVED_PENDING) {
        handle_in->file->mutexUnlock();
        fs = fdb_check_file_reopen(handle_in, NULL);
        if (fs != FDB_RESULT_SUCCESS) {
            return fs;
        }
    } else {
        handle_in->file->mutexUnlock();
    }

    fdb_sync_db_header(handle_in);

    // if the max sequence number seen by this handle is lower than the
    // requested snapshot marker, it means the snapshot is not yet visible
    // even via the current FdbKvsHandle
    if (seqnum > handle_in->seqnum) {
        super_handle->file->setRollback(0); // allow mutations
        return FDB_RESULT_NO_DB_INSTANCE;
    }

    kvs_name = _fdb_kvs_get_name(handle_in, handle_in->file);
    if (seqnum == 0) { // Handle special case of rollback to zero..
        fs = removeKvs(fhandle, kvs_name, true /*recreate!*/);
        super_handle->file->setRollback(0); // allow mutations
        return fs;
    }

    handle = new FdbKvsHandle();
    if (!handle) { // LCOV_EXCL_START
        handle_in->file->setRollback(0); // allow mutations
        return FDB_RESULT_ALLOC_FAIL;
    } // LCOV_EXCL_STOP

    handle->max_seqnum = seqnum;
    handle->log_callback = handle_in->log_callback;
    handle->fhandle = fhandle;
    handle->initBusy();

    if (handle_in->kvs->getKvsType() == KVS_SUB) {
        fs = openKvs(handle_in->kvs->getRootHandle(),
                     &config,
                     &kvs_config,
                     handle_in->file,
                     handle_in->file->getFileName(),
                     kvs_name,
                     handle);
    } else {
        fs = openFdb(handle, handle_in->file->getFileName(),
                     FDB_AFILENAME, &config);
    }
    handle_in->file->setRollback(0); // allow mutations

    if (fs == FDB_RESULT_SUCCESS) {
        // get KV instance's sub B+trees' root node BIDs
        // from both ID-tree and Seq-tree, AND
        // replace current handle's sub B+trees' root node BIDs
        // by old BIDs
        size_t size_chunk, size_id;
        bid_t id_root, seq_root, dummy;
        uint8_t *_kv_id;
        hbtrie_result hr;

        size_chunk = handle->trie->getChunkSize();
        size_id = sizeof(fdb_kvs_id_t);

        handle_in->file->mutexLock();

        // read root BID of the KV instance from the old handle
        // and overwrite into the current handle
        _kv_id = alca(uint8_t, size_chunk);
        kvid2buf(size_chunk, handle->kvs->getKvsId(), _kv_id);
        hr = handle->trie->findPartial(_kv_id, size_chunk, &id_root);

        bool is_btree_v2 = ver_btreev2_format(handle->file->getVersion());
        if (is_btree_v2) {
            handle->bnodeMgr->releaseCleanNodes();
        } else {
            handle->bhandle->flushBuffer();
        }

        if (hr == HBTRIE_RESULT_SUCCESS) {
            super_handle->trie->insertPartial(_kv_id, size_chunk, &id_root, &dummy);
        } else { // No Trie info in rollback header.
                 // Erase kv store from super handle's main index.
            super_handle->trie->removePartial(_kv_id, size_chunk);
        }
        if (is_btree_v2) {
            super_handle->bnodeMgr->releaseCleanNodes();
        } else {
            super_handle->bhandle->flushBuffer();
        }

        if (config.seqtree_opt == FDB_SEQTREE_USE) {
            // same as above for seq-trie
            _kv_id = alca(uint8_t, size_id);
            kvid2buf(size_id, handle->kvs->getKvsId(), _kv_id);
            hr = handle->seqtrie->findPartial(_kv_id, size_id, &seq_root);
            if (is_btree_v2) {
                handle->bnodeMgr->releaseCleanNodes();
            } else {
                handle->bhandle->flushBuffer();
            }
            if (hr == HBTRIE_RESULT_SUCCESS) {
                super_handle->seqtrie->insertPartial(_kv_id, size_id,
                                                     &seq_root, &dummy);
            } else { // No seqtrie info in rollback header.
                     // Erase kv store from super handle's seqtrie index.
                super_handle->seqtrie->removePartial(_kv_id, size_id);
            }
            if (is_btree_v2) {
                super_handle->bnodeMgr->releaseCleanNodes();
            } else {
                super_handle->bhandle->flushBuffer();
            }
        }

        old_seqnum = fdb_kvs_get_seqnum(handle_in->file,
                                        handle_in->kvs->getKvsId());
        fdb_kvs_set_seqnum(handle_in->file,
                           handle_in->kvs->getKvsId(), seqnum);
        handle_in->seqnum = seqnum;
        handle_in->file->mutexUnlock();

        super_handle->rollback_revnum = handle->rollback_revnum;
        bool sync = !(handle_in->config.durability_opt & FDB_DRB_ASYNC);
        fs = commitWithKVHandle(super_handle, FDB_COMMIT_MANUAL_WAL_FLUSH, sync);
        if (fs == FDB_RESULT_SUCCESS) {
            closeKvsInternal(handle);
            *handle_ptr = handle_in;
            delete handle;
        } else {
            // cancel the rolling-back of the sequence number
            fdb_log(&handle_in->log_callback, fs,
                    "Rollback failed due to a commit failure with a sequence "
                    "number %" _F64, seqnum);
            handle_in->file->mutexLock();
            fdb_kvs_set_seqnum(handle_in->file,
                               handle_in->kvs->getKvsId(), old_seqnum);
            handle_in->file->mutexUnlock();
            closeKvsInternal(handle);
            delete handle;
        }
    } else {
        delete handle;
    }

    return fs;
}

fdb_status FdbEngine::createKvs(FdbKvsHandle *root_handle,
                                const char *kvs_name,
                                fdb_kvs_config *kvs_config)
{
    int kv_ins_name_len;
    fdb_status fs = FDB_RESULT_SUCCESS;
    struct avl_node *a;
    FileMgr *file;
    struct kvs_node *node, query;
    KvsHeader *kv_header;

    if (root_handle->config.multi_kv_instances == false) {
        // cannot open KV instance under single DB instance mode
        return fdb_log(&root_handle->log_callback, FDB_RESULT_INVALID_CONFIG,
                       "Cannot open or create KV store instance '%s' because multi-KV "
                       "store instance mode is disabled.",
                       kvs_name ? kvs_name : DEFAULT_KVS_NAME);
    }
    if (root_handle->kvs->getKvsType() != KVS_ROOT) {
        return fdb_log(&root_handle->log_callback, FDB_RESULT_INVALID_HANDLE,
                       "Cannot open or create KV store instance '%s' because the handle "
                       "doesn't support multi-KV sotre instance mode.",
                       kvs_name ? kvs_name : DEFAULT_KVS_NAME);
    }

fdb_kvs_create_start:
    fs = fdb_check_file_reopen(root_handle, NULL);
    if (fs != FDB_RESULT_SUCCESS) {
        return fs;
    }
    root_handle->file->mutexLock();
    fdb_sync_db_header(root_handle);

    if (root_handle->file->isRollbackOn()) {
        root_handle->file->mutexUnlock();
        return FDB_RESULT_FAIL_BY_ROLLBACK;
    }

    file = root_handle->file;

    file_status_t fMgrStatus = file->getFileStatus();
    if (fMgrStatus == FILE_REMOVED_PENDING) {
        // we must not write into this file
        // file status was changed by other thread .. start over
        file->mutexUnlock();
        goto fdb_kvs_create_start;
    }

    kv_header = file->getKVHeader_UNLOCKED();
    spin_lock(&kv_header->lock);

    // find existing KV instance
    // search by name
    query.kvs_name = (char*)kvs_name;
    a = avl_search(kv_header->idx_name, &query.avl_name, _kvs_cmp_name);
    if (a) { // KV name already exists
        spin_unlock(&kv_header->lock);
        file->mutexUnlock();
        return fdb_log(&root_handle->log_callback, FDB_RESULT_INVALID_KV_INSTANCE_NAME,
                       "Failed to create KV Store '%s' as it already exists.",
                       kvs_name ? kvs_name : DEFAULT_KVS_NAME);
    }

    // create a kvs_node and insert
    node = (struct kvs_node *)calloc(1, sizeof(struct kvs_node));
    node->id = kv_header->id_counter++;
    node->seqnum = 0;
    node->flags = 0x0;
    node->op_stat.reset();
    // search fhandle's custom cmp func list first
    node->custom_cmp = root_handle->fhandle->getCmpFunctionByName((char *)kvs_name);
    if (node->custom_cmp == NULL && kvs_config->custom_cmp) {
        // follow kvs_config's custom cmp next
        node->custom_cmp = kvs_config->custom_cmp;
        // if custom cmp function is given by user but
        // there is no corresponding function in fhandle's list
        // add it into the list
        root_handle->fhandle->addCmpFunction((char*) kvs_name,
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
    if (file->getFileStatus() == FILE_COMPACT_OLD) {

        FileMgr *new_file = FileMgrMap::get()->fetchEntry(
                                                    file->getNewFileName());

        if (new_file) {
            struct kvs_node *node_new;
            KvsHeader *kv_header_new;

            kv_header_new = new_file->getKVHeader_UNLOCKED();
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
        } else {
            // new_file should have been found if compaction is in progress
            fdb_assert(new_file, new_file, nullptr);
        }
    }

    // since this function calls FileMgr::commit() and appends a new DB header,
    // we should finalize & flush the previous dirty update before commit.
    bid_t dirty_idtree_root = BLK_NOT_FOUND;
    bid_t dirty_seqtree_root = BLK_NOT_FOUND;
    struct filemgr_dirty_update_node *prev_node = NULL;
    struct filemgr_dirty_update_node *new_node = NULL;

    _fdb_dirty_update_ready(root_handle, &prev_node, &new_node,
                            &dirty_idtree_root, &dirty_seqtree_root, false);

    _fdb_dirty_update_finalize(root_handle, prev_node, new_node,
                               &dirty_idtree_root, &dirty_seqtree_root, true);

    // append system doc
    root_handle->kv_info_offset = fdb_kvs_header_append(root_handle);

    // if no compaction is being performed, append header and commit
    if (root_handle->file == file) {
        uint64_t cur_bmp_revnum = 0;
        if (file->getSb()) {
            cur_bmp_revnum = file->getSb()->getBmpRevnum();
        }
        root_handle->last_hdr_bid = file->alloc_FileMgr(&root_handle->log_callback);
        root_handle->cur_header_revnum = fdb_set_file_header(root_handle);
        fs = root_handle->file->commitBid(
                                root_handle->last_hdr_bid,
                                cur_bmp_revnum,
                                !(root_handle->config.durability_opt & FDB_DRB_ASYNC),
                                &root_handle->log_callback);
        if (!ver_btreev2_format(root_handle->file->getVersion())) {
            root_handle->bhandle->resetSubblockInfo();
        }
    }

    file->mutexUnlock();

    return fs;
}

// 1) identify whether the requested handle is for default KVS or not.
// 2) if the requested handle is for the default KVS,
//   2-1) the requested handle must not be the root handle,
//        -> call FdbEngine::getInstance()->closeKVHandle(),
//        -> remove the corresponding node from fhandle->handles list,
//        -> free the memory for the handle.
// 3) if the requested handle is for non-default KVS,
//    -> call FdbEngine::closeKvsInternal(),
//       -> this will remove the node from fhandle->handles list.
//    -> free the memory for the handle.
fdb_status FdbEngine::closeKvs(FdbKvsHandle *handle)
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
        //  using closeKvsInternal() below)
        fs = FdbEngine::getInstance()->closeKVHandle(handle);
        if (fs == FDB_RESULT_SUCCESS) {
            delete handle;
        }
        return fs;
    }

    if (handle->kvs == NULL ||
        handle->kvs->getKvsType() == KVS_ROOT) {
        // the default KV store handle

        fdb_assert(handle->fhandle->getRootHandle() != handle, handle,
                   handle->fhandle);
        // the default KV store but not the root handle .. normally close
        fs = FdbEngine::getInstance()->closeKVHandle(handle);
        if (fs == FDB_RESULT_SUCCESS) {
            // remove from 'handles' list in the root node
            handle->fhandle->removeKVHandle(&handle->node->le);
            free(handle->node);
            delete handle;
        }
        return fs;
    }

    if (handle->kvs && handle->kvs->getRootHandle() == NULL) {
        return FDB_RESULT_INVALID_ARGS;
    }
    fs = closeKvsInternal(handle);
    if (fs == FDB_RESULT_SUCCESS) {
        delete handle;
    }
    return fs;
}

// 1) remove corresponding node from fhandle->handles list.
// 2) call FdbEngine::getInstance()->closeKVHandle().
fdb_status FdbEngine::closeKvsInternal(FdbKvsHandle *handle)
{
    FdbKvsHandle *root_handle = handle->fhandle->getRootHandle();
    fdb_status fs;

    if (handle->node) {
        root_handle->fhandle->removeKVHandle(&handle->node->le);
        free(handle->node);
    } // 'handle->node == NULL' happens only during rollback

    fs = FdbEngine::getInstance()->closeKVHandle(handle);
    return fs;
}

fdb_status FdbEngine::removeKvs(fdb_file_handle *fhandle,
                                const char *kvs_name)
{
    return removeKvs(fhandle, kvs_name, false);
}

fdb_status FdbEngine::removeKvs(FdbFileHandle *fhandle,
                                const char *kvs_name,
                                bool rollback_recreate)
{
    size_t size_chunk, size_id;
    uint8_t *_kv_id;
    fdb_status fs = FDB_RESULT_SUCCESS;
    fdb_kvs_id_t kv_id = 0;
    FdbKvsHandle *root_handle;
    struct avl_node *a = NULL;
    FileMgr *file;
    struct kvs_node *node, query;
    KvsHeader *kv_header;

    if (!fhandle || !fhandle->getRootHandle()) {
        return FDB_RESULT_INVALID_HANDLE;
    }

    root_handle = fhandle->getRootHandle();

    if (root_handle->config.multi_kv_instances == false) {
        // cannot remove the KV instance under single DB instance mode
        return FDB_RESULT_INVALID_CONFIG;
    }
    if (root_handle->kvs->getKvsType() != KVS_ROOT) {
        return FDB_RESULT_INVALID_HANDLE;
    }

fdb_kvs_remove_start:
    fs = fdb_check_file_reopen(root_handle, NULL);
    if (fs != FDB_RESULT_SUCCESS) {
        return fs;
    }
    root_handle->file->mutexLock();
    fdb_sync_db_header(root_handle);

    if (!rollback_recreate) {
        if (root_handle->file->isRollbackOn()) {
            root_handle->file->mutexUnlock();
            return FDB_RESULT_FAIL_BY_ROLLBACK;
        }
    }

    file = root_handle->file;

    file_status_t fMgrStatus = file->getFileStatus();
    if (fMgrStatus == FILE_REMOVED_PENDING) {
        // we must not write into this file
        // file status was changed by other thread .. start over
        file->mutexUnlock();
        goto fdb_kvs_remove_start;
    } else if (fMgrStatus == FILE_COMPACT_OLD) {
        // Cannot remove existing KV store during compaction.
        // To remove a KV store, the corresponding first chunk in HB+trie
        // should be unlinked. This can be possible in the old file during
        // compaction, but impossible in the new file, since existing documents
        // (including docs belonging to the KV store to be removed) are being moved.
        file->mutexUnlock();
        return FDB_RESULT_FAIL_BY_COMPACTION;
    }

    // find the kvs_node and remove

    // search by name to get ID
    if (kvs_name == NULL || !strcmp(kvs_name, default_kvs_name)) {
        if (!rollback_recreate) {
            // default KV store .. KV ID = 0
            kv_id = 0;
            if (isAnyKvsHandleOpened(fhandle, kv_id)) {
                // there is an opened handle
                file->mutexUnlock();
                return FDB_RESULT_KV_STORE_BUSY;
            }
        }
        // reset KVS stats (excepting for WAL stats)
        file->accessHeader()->stat.ndocs = 0;
        file->accessHeader()->stat.nlivenodes = 0;
        file->accessHeader()->stat.datasize = 0;
        file->accessHeader()->stat.deltasize = 0;

        // reset seqnum
        file->setSeqnum(0);
    } else {
        kv_header = file->getKVHeader_UNLOCKED();
        spin_lock(&kv_header->lock);
        query.kvs_name = (char*)kvs_name;
        a = avl_search(kv_header->idx_name, &query.avl_name, _kvs_cmp_name);
        if (a == NULL) { // KV name doesn't exist
            spin_unlock(&kv_header->lock);
            file->mutexUnlock();
            return FDB_RESULT_KV_STORE_NOT_FOUND;
        }
        node = _get_entry(a, struct kvs_node, avl_name);
        kv_id = node->id;

        if (!rollback_recreate) {
            spin_unlock(&kv_header->lock);
            if (isAnyKvsHandleOpened(fhandle, kv_id)) {
                // there is an opened handle
                file->mutexUnlock();
                return FDB_RESULT_KV_STORE_BUSY;
            }
            spin_lock(&kv_header->lock);

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
    file->getWal()->closeKvs_Wal(kv_id, &root_handle->log_callback);

    bid_t dirty_idtree_root = BLK_NOT_FOUND;
    bid_t dirty_seqtree_root = BLK_NOT_FOUND;
    struct filemgr_dirty_update_node *prev_node = NULL, *new_node = NULL;

    _fdb_dirty_update_ready(root_handle, &prev_node, &new_node,
                            &dirty_idtree_root, &dirty_seqtree_root, false);

    size_id = sizeof(fdb_kvs_id_t);
    size_chunk = root_handle->trie->getChunkSize();

    // remove from super handle's HB+trie
    _kv_id = alca(uint8_t, size_chunk);
    kvid2buf(size_chunk, kv_id, _kv_id);
    root_handle->trie->removePartial(_kv_id, size_chunk);

    bool is_btree_v2 = ver_btreev2_format(root_handle->file->getVersion());
    if (is_btree_v2) {
        root_handle->bnodeMgr->releaseCleanNodes();
    } else {
        root_handle->bhandle->flushBuffer();
    }

    if (root_handle->config.seqtree_opt == FDB_SEQTREE_USE) {
        _kv_id = alca(uint8_t, size_id);
        kvid2buf(size_id, kv_id, _kv_id);
        root_handle->seqtrie->removePartial(_kv_id, size_id);
        if (is_btree_v2) {
            root_handle->bnodeMgr->releaseCleanNodes();
        } else {
            root_handle->bhandle->flushBuffer();
        }
    }

    _fdb_dirty_update_finalize(root_handle, prev_node, new_node,
                               &dirty_idtree_root, &dirty_seqtree_root, true);

    // append system doc
    root_handle->kv_info_offset = fdb_kvs_header_append(root_handle);

    // if no compaction is being performed, append header and commit
    if (root_handle->file == file) {
        uint64_t cur_bmp_revnum = 0;
        if (file->getSb()) {
            cur_bmp_revnum = file->getSb()->getBmpRevnum();
        }
        root_handle->last_hdr_bid = file->alloc_FileMgr(&root_handle->log_callback);
        root_handle->cur_header_revnum = fdb_set_file_header(root_handle);
        fs = root_handle->file->commitBid(
                                root_handle->last_hdr_bid,
                                cur_bmp_revnum,
                                !(root_handle->config.durability_opt & FDB_DRB_ASYNC),
                                &root_handle->log_callback);
        if (!is_btree_v2) {
            root_handle->bhandle->resetSubblockInfo();
        }
    }

    file->mutexUnlock();

    return fs;
}

bool FdbEngine::isAnyKvsHandleOpened(FdbFileHandle *fhandle,
                                     fdb_kvs_id_t kv_id)
{
    FileMgr *file = fhandle->getRootHandle()->file;
    struct avl_node *a;
    struct filemgr_fhandle_idx_node *fhandle_node;
    fdb_file_handle *file_handle;

    file->acquireHandleIdxLock();
    struct avl_tree *handle_idx = file->getHandleIdx();
    a = avl_first(handle_idx);
    while (a) {
        fhandle_node = _get_entry(a, struct filemgr_fhandle_idx_node, avl);
        a = avl_next(a);
        file_handle = (fdb_file_handle *) fhandle_node->fhandle;
        if (file_handle->checkAnyActiveKVHandle(kv_id)) {
            file->releaseHandleIdxLock();
            return true;
        }
    }
    file->releaseHandleIdxLock();

    return false;
}

btree_new_cmp_func* FdbEngine::getCmpFuncCB(HBTrie *hbtrie,
                                            uint64_t kvs_id,
                                            void *aux)
{
    (void)aux;
    FileMgr *file = hbtrie->getFileMgr();
    if (!file->getKVHeader_UNLOCKED()->custom_cmp_enabled) {
        // no custom compare function is assigned
        return NULL;
    }

    // search by id
    struct avl_node *a;
    struct kvs_node query, *node;
    if (kvs_id > 0) {
        query.id = kvs_id;
        spin_lock(&file->getKVHeader_UNLOCKED()->lock);
        a = avl_search(file->getKVHeader_UNLOCKED()->idx_id, &query.avl_id, _kvs_cmp_id);
        spin_unlock(&file->getKVHeader_UNLOCKED()->lock);

        if (a) {
            node = _get_entry(a, struct kvs_node, avl_id);
            return static_cast<btree_new_cmp_func*>(node->custom_cmp);
        }
    } else {
        // root handle
        return static_cast<btree_new_cmp_func*>(
               file->getKVHeader_UNLOCKED()->default_kvs_cmp);
    }
    return nullptr;
}

