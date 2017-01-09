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
#include "fdb_internal.h"
#include "version.h"

extern int _kvs_cmp_name(struct avl_node *a, struct avl_node *b, void *aux);

FdbKvsHandle::FdbKvsHandle() :
    kvs(NULL), op_stats(NULL), fhandle(NULL), trie(NULL), staletree(NULL),
    seqtree(NULL), file(NULL), dhandle(NULL), bhandle(NULL),
    fileops(NULL), log_callback(), cur_header_revnum(0), rollback_revnum(0),
    last_hdr_bid(0), last_wal_flush_hdr_bid(0), kv_info_offset(0), shandle(NULL),
    seqnum(0), max_seqnum(0), txn(NULL), dirty_updates(0),
    node(NULL), num_iterators(0), handle_busy(nullptr) {

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
    spin_lock(&file->getKVHeader()->lock);
    kvs_config.custom_cmp = file->getKVHeader()->default_kvs_cmp;
    spin_unlock(&file->getKVHeader()->lock);
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
            spin_lock(&file->getKVHeader()->lock);
            query.kvs_name = (char*)kvs_name;
            a = avl_search(file->getKVHeader()->idx_name, &query.avl_name,
                           _kvs_cmp_name);
            if (a == NULL) {
                // KV instance name is not found
                freeKvsInfo();
                spin_unlock(&file->getKVHeader()->lock);
                return;
            }
            kvs_node = _get_entry(a, struct kvs_node, avl_name);
            kvs->setKvsId(kvs_node->id);
            // force custom cmp function
            kvs_config.custom_cmp = kvs_node->custom_cmp;
            spin_unlock(&file->getKVHeader()->lock);
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
    file = kv_handle.file;

    freeKvsInfo();
    if (kv_handle.kvs) {
        kvs = new KvsInfo(*kv_handle.kvs);
    }

    op_stats = kv_handle.op_stats;
    fhandle = kv_handle.fhandle;

    trie = kv_handle.trie;
    if (ver_btreev2_format(file->getVersion())) {
        staletreeV2 = kv_handle.staletreeV2;
    } else {
        staletree = kv_handle.staletree;
    }
    if (kv_handle.kvs) {
        seqtrie = kv_handle.seqtrie;
    } else {
        if (ver_btreev2_format(file->getVersion())) {
            seqtreeV2 = kv_handle.seqtreeV2;
        } else {
            seqtree = kv_handle.seqtree;
        }
    }

    dhandle = kv_handle.dhandle;
    if (ver_btreev2_format(file->getVersion())) {
        bnodeMgr = kv_handle.bnodeMgr;
    } else {
        bhandle = kv_handle.bhandle;
    }
    fileops = kv_handle.fileops;

    config = kv_handle.config;
    log_callback = kv_handle.log_callback;

    cur_header_revnum.store(kv_handle.cur_header_revnum);
    rollback_revnum = kv_handle.rollback_revnum;
    last_hdr_bid.store(kv_handle.last_hdr_bid.load());
    last_wal_flush_hdr_bid = kv_handle.last_wal_flush_hdr_bid;
    kv_info_offset = kv_handle.kv_info_offset;

    shandle = kv_handle.shandle;
    seqnum = kv_handle.seqnum;
    max_seqnum = kv_handle.max_seqnum;
    filename = kv_handle.filename;
    txn = kv_handle.txn;

    dirty_updates = kv_handle.dirty_updates;
    node = kv_handle.node;
    num_iterators = kv_handle.num_iterators;
    handle_busy.store(kv_handle.handle_busy.load());
}

void FdbKvsHandle::resetIOHandles() {
    dhandle = nullptr;
    bnodeMgr = nullptr;
    trie = nullptr;
    seqtrie = nullptr;
    staletreeV2 = nullptr;
}

fdb_status FdbKvsHandle::freeIOHandles(bool useBtreeV2) { // LCOV_EXCL_START
    if (useBtreeV2) {
        delete bnodeMgr;
        delete dhandle;
        delete trie;
        if (kvs) {
            delete seqtrie;
        } else {
            delete seqtreeV2;
        }
        delete staletreeV2;
    } else {
        delete bhandle;
        delete dhandle;
        delete trie;
        if (kvs) {
            delete seqtrie;
        } else {
            if (seqtree) {
                delete seqtree->getKVOps();
                delete seqtree;
            }
        }
        if (staletree) {
            delete staletree->getKVOps();
            delete staletree;
        }
    }
    return FDB_RESULT_ALLOC_FAIL;
} // LCOV_EXCL_STOP

void FdbKvsHandle::initBusy() {
    handle_busy = nullptr;
}

bool FdbKvsHandle::beginBusy(func_name_t funcName) {
    func_name_t inverse = nullptr;
    if (handle_busy.compare_exchange_strong(inverse, funcName)) {
        return true;
    }
    func_name_t curFuncName = handle_busy.load();
    if (!curFuncName) {
        curFuncName = "(unknown)";// race condition; value lost before read
    }
    fdb_log(&log_callback, FDB_RESULT_HANDLE_BUSY,
            "%s() failed because handle %p is in use by %s()", funcName,
            reinterpret_cast<void *>(this), curFuncName);
    return false;
}

func_name_t FdbKvsHandle::suspendBusy(void) {
    func_name_t val = handle_busy.load();
    handle_busy.store(nullptr);
    return val;
}

bool FdbKvsHandle::resumeBusy(func_name_t funcName) {
    return beginBusy(funcName);
}

bool FdbKvsHandle::endBusy(func_name_t funcName) {
    // Windows does not provide constant __FUNCTION__ (i.e., funcName)
    // macro value, so it may have different memory address although
    // caller function names are the same.
    // Hence we always clear 'handle_busy' value regardless of its
    // current value.
#if defined(WIN32) || defined(_WIN32)
    (void)funcName;
    handle_busy.store(nullptr);
    return true;
#else
    func_name_t inverse = funcName;
    return handle_busy.compare_exchange_strong(inverse, nullptr);
#endif
}
