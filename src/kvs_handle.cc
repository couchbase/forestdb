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

#include "libforestdb/forestdb.h"
#include "kvs_handle.h"
#include "file_handle.h"
#include "filemgr.h"

extern int _kvs_cmp_name(struct avl_node *a, struct avl_node *b, void *aux);

FdbKvsHandle::FdbKvsHandle() :
    kvs(NULL), op_stats(NULL), fhandle(NULL), trie(NULL), staletree(NULL),
    seqtree(NULL), file(NULL), dhandle(NULL), bhandle(NULL),
    fileops(NULL), log_callback(), cur_header_revnum(0), rollback_revnum(0),
    last_hdr_bid(0), last_wal_flush_hdr_bid(0), kv_info_offset(0), shandle(NULL),
    seqnum(0), max_seqnum(0), txn(NULL), handle_busy(0), dirty_updates(0),
    node(NULL), num_iterators(0) {

    memset(&kvs_config, 0, sizeof(kvs_config));
    memset(&config, 0, sizeof(config));
}

FdbKvsHandle::FdbKvsHandle(const FdbKvsHandle& kv_handle) {
    copyFromOtherHandle(kv_handle);
}

FdbKvsHandle::~FdbKvsHandle() {
    freeKvsInfo();
}

FdbKvsHandle& FdbKvsHandle::operator=(const FdbKvsHandle& kv_handle) {
    copyFromOtherHandle(kv_handle);
    return *this;
}

void FdbKvsHandle::freeKvsInfo() {
    if (kvs == NULL) {
        return;
    }
    delete kvs;
    kvs = NULL;
}

void FdbKvsHandle::initRootHandle() {
    if (!kvs) {
        kvs = new KvsInfo();
    }

    kvs->setKvsType(KVS_ROOT);
    kvs->setRootHandle(fhandle->getRootHandle());
    // super handle's ID is always 0
    kvs->setKvsId(0);
    // force custom cmp function
    spin_lock(&file->kv_header->lock);
    kvs_config.custom_cmp = file->kv_header->default_kvs_cmp;
    spin_unlock(&file->kv_header->lock);
}

void FdbKvsHandle::createKvsInfo(FdbKvsHandle *root_handle,
                                 const char *kvs_name) {
    struct kvs_node query, *kvs_node;
    struct kvs_opened_node *opened_node;
    struct avl_node *a;

    if (root_handle == NULL) {
        // This handle is a super handle
        initRootHandle();
    } else {
        if (!kvs) {
            kvs = new KvsInfo();
        }
        // This handle is a sub handle (i.e., KV instance in a DB instance)
        kvs->setKvsType(KVS_SUB);
        kvs->setRootHandle(root_handle);

        if (kvs_name) {
            spin_lock(&file->kv_header->lock);
            query.kvs_name = (char*)kvs_name;
            a = avl_search(file->kv_header->idx_name, &query.avl_name,
                           _kvs_cmp_name);
            if (a == NULL) {
                // KV instance name is not found
                freeKvsInfo();
                spin_unlock(&file->kv_header->lock);
                return;
            }
            kvs_node = _get_entry(a, struct kvs_node, avl_name);
            kvs->setKvsId(kvs_node->id);
            // force custom cmp function
            kvs_config.custom_cmp = kvs_node->custom_cmp;
            spin_unlock(&file->kv_header->lock);
        } else {
            // snapshot of the root handle
            kvs->setKvsId(0);
        }

        opened_node = (struct kvs_opened_node *)
            calloc(1, sizeof(struct kvs_opened_node));
        opened_node->handle = this;

        node = opened_node;
        root_handle->fhandle->addKVHandle(&opened_node->le);
    }
}

void FdbKvsHandle::copyFromOtherHandle(const FdbKvsHandle& kv_handle) {
    kvs_config = kv_handle.kvs_config;

    freeKvsInfo();
    if (kv_handle.kvs) {
        kvs = new KvsInfo(*kv_handle.kvs);
    }

    op_stats = kv_handle.op_stats;
    fhandle = kv_handle.fhandle;

    trie = kv_handle.trie;
    staletree = kv_handle.staletree;
    if (kv_handle.kvs) {
        seqtrie = kv_handle.seqtrie;
    } else {
        seqtree = kv_handle.seqtree;
    }

    file = kv_handle.file;
    dhandle = kv_handle.dhandle;
    bhandle = kv_handle.bhandle;
    fileops = kv_handle.fileops;

    config = kv_handle.config;
    log_callback = kv_handle.log_callback;

    cur_header_revnum.store(kv_handle.cur_header_revnum);
    rollback_revnum = kv_handle.rollback_revnum;
    last_hdr_bid = kv_handle.last_hdr_bid;
    last_wal_flush_hdr_bid = kv_handle.last_wal_flush_hdr_bid;
    kv_info_offset = kv_handle.kv_info_offset;

    shandle = kv_handle.shandle;
    seqnum = kv_handle.seqnum;
    max_seqnum = kv_handle.max_seqnum;
    filename = kv_handle.filename;
    txn = kv_handle.txn;

    handle_busy.store(kv_handle.handle_busy);
    dirty_updates = kv_handle.dirty_updates;
    node = kv_handle.node;
    num_iterators = kv_handle.num_iterators;
}
