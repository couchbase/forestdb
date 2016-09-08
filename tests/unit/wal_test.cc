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

#include <map>
#include <mutex>
#include <sstream>
#include <string>
#include <vector>

#include "wal.h"
#include "filemgr.h"
#include "libforestdb/forestdb.h"
#include "test.h"
#include "fdb_engine.h"

void wal_basic_test()
{
    TEST_INIT();

    Wal *wal;
    FileMgr *file;
    struct _fdb_key_cmp_info cmp_info;
    KvsInfo def_kvs;

    FdbEngine::init(nullptr);
    int ndocs = 90000;
    FileMgrConfig config(4096, // block size
                         5, // number of buffercache blocks
                         0, // flag
                         8, // chunk size
                         FILEMGR_CREATE, // create if does not exist
                         FDB_SEQTREE_USE, // create and use sequence trees
                         0, // prefetch thread duration 0 = disabled
                         8, // num wal shards
                         0, // num block cache shards
                         FDB_ENCRYPTION_NONE, // encryption type
                         0x00, // encryption key size in bytes
                         0, // block reusing threshold
                         0); // num keeping headers
    cmp_info.kvs_config = fdb_get_default_kvs_config();
    cmp_info.kvs = &def_kvs;

    int i, r;
    char buf[32];
    memset(buf, 0, sizeof(buf));
    fdb_status s;

    r = system(SHELL_DEL" wal_testfile* > errorlog.txt");
    (void)r;

    std::string fname("./wal_testfile");

    filemgr_open_result result = FileMgr::open(fname, get_filemgr_ops(),
                                               &config, nullptr);
    file = result.file;
    wal = file->getWal();
    fdb_doc wal_doc;
    fdb_txn *txn = file->getGlobalTxn();

    for (i=0; i < ndocs; ++i) {
        sprintf(buf, "%08dkey%05d", 0, i);
        wal_doc.keylen = 16; // 8 bytes KVID + 8 bytes of key string
        wal_doc.bodylen = sizeof(i);
        wal_doc.key = &buf[0];
        wal_doc.seqnum = i;
        wal_doc.deleted = false;
        wal_doc.metalen = 0;
        wal_doc.meta = nullptr;
        wal_doc.size_ondisk = wal_doc.bodylen;
        wal_doc.flags = 0;
        union Wal::indexedValue value;
        value.offset = uint64_t(i);

        s = wal->insert_Wal(txn, &cmp_info,
                            &wal_doc,
                            value,
                            Wal::INS_BY_WRITER);
        TEST_CHK(s == FDB_RESULT_SUCCESS);

    }

    for (i=0; i < ndocs; ++i) {
        sprintf(buf, "%08dkey%05d", 0, i);
        wal_doc.keylen = 16; // 8 bytes KVID + 8 bytes of key string
        wal_doc.bodylen = sizeof(i);
        wal_doc.key = &buf[0];
        wal_doc.seqnum = SEQNUM_NOT_USED;
        wal_doc.deleted = false;
        wal_doc.flags = 0;
        union Wal::indexedValue value_out;

        s = wal->find_Wal(txn, &cmp_info, nullptr, &wal_doc,
                                     &value_out);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CHK(value_out.offset == uint64_t(i));
    }

    for (int i = FDB_LATENCY_WAL_INS; i < FDB_LATENCY_NUM_STATS; ++i) {
        fdb_latency_stat stat;
        memset(&stat, 0, sizeof(fdb_latency_stat));
        LatencyStats::get(file, fdb_latency_stat_type(i), &stat);
        fprintf(stderr, "%s:\t%u\t%u\t%u\t%" _F64 "\n",
                fdb_latency_stat_name(i),
                stat.lat_min, stat.lat_avg, stat.lat_max, stat.lat_count);
    }

    s = FileMgr::close(file,
                       true, // cleanup cache on close
                       fname.c_str(),
                       nullptr);

    TEST_CHK(s == FDB_RESULT_SUCCESS);

    FdbEngine::destroyInstance();
    TEST_RESULT("wal basic test");
}

void wal_ref_ptr_test()
{
    TEST_INIT();

    Wal *wal;
    FileMgr *file;
    struct _fdb_key_cmp_info cmp_info;
    KvsInfo def_kvs;

    FdbEngine::init(nullptr);
    int ndocs = 90000;
    FileMgrConfig config(4096, // block size
                         5, // number of buffercache blocks
                         0, // flag
                         8, // chunk size
                         FILEMGR_CREATE, // create if does not exist
                         FDB_SEQTREE_USE, // create and use sequence trees
                         0, // prefetch thread duration 0 = disabled
                         8, // num wal shards
                         0, // num block cache shards
                         FDB_ENCRYPTION_NONE, // encryption type
                         0x00, // encryption key size in bytes
                         0, // block reusing threshold
                         0); // num keeping headers
    cmp_info.kvs_config = fdb_get_default_kvs_config();
    cmp_info.kvs = &def_kvs;
    fdb_status s;
    int i, r;

    r = system(SHELL_DEL" wal_testfile* > errorlog.txt");
    (void)r;

    std::string fname("./wal_testfile");

    filemgr_open_result result = FileMgr::open(fname, get_filemgr_ops(),
                                               &config, NULL);
    file = result.file;
    wal = file->getWal();
    fdb_doc wal_doc;
    fdb_txn *txn = file->getGlobalTxn();

    // Allocate a big buffer and load just the keys into it..
    struct cldoc {
        char kv_id[8];
        char key[8];
    };
    struct cldoc *commit_log = new cldoc[ndocs];
    // Load all the keys into this big buffer...
    for (i=0; i < ndocs; ++i) { // load the buf with null terminated keys..
        sprintf((char *)&commit_log[i], "%08dke%05d", 0, i);
    }

    for (i=0; i < ndocs; ++i) {
        wal_doc.keylen = 16; // 8 bytes KVID + 8 bytes of key string
        wal_doc.bodylen = 0;
        wal_doc.key = &commit_log[i]; // simply point to the buffer position
        wal_doc.seqnum = i;
        wal_doc.deleted = false;
        wal_doc.metalen = 0;
        wal_doc.meta = nullptr;
        wal_doc.size_ondisk = wal_doc.bodylen;
        wal_doc.flags = FDB_DOC_MEMORY_SHARED; // Tell WAL to share key memory
        union Wal::indexedValue value;
        value.doc_ptr = &commit_log[i]; // no separate value, just point to key

        s = wal->insert_Wal(txn, &cmp_info, &wal_doc, value,
                            Wal::INS_BY_WRITER);
        TEST_CHK(s == FDB_RESULT_SUCCESS);

    }

    for (i=0; i < ndocs; ++i) {
        wal_doc.keylen = 16; // 8 bytes KVID + 8 bytes of key string
        wal_doc.key = &commit_log[i];
        wal_doc.seqnum = SEQNUM_NOT_USED;
        union Wal::indexedValue value_out;

        s = wal->find_Wal(txn, &cmp_info, nullptr, &wal_doc, &value_out);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CHK(wal_doc.flags & FDB_DOC_MEMORY_SHARED);
        TEST_CHK(value_out.doc_ptr == &commit_log[i]);
    }

    for (int i = FDB_LATENCY_WAL_INS; i < FDB_LATENCY_NUM_STATS; ++i) {
        fdb_latency_stat stat;
        memset(&stat, 0, sizeof(fdb_latency_stat));
        LatencyStats::get(file, fdb_latency_stat_type(i), &stat);
        fprintf(stderr, "%s:\t%u\t%u\t%u\t%" _F64 "\n",
                fdb_latency_stat_name(i),
                stat.lat_min, stat.lat_avg, stat.lat_max, stat.lat_count);
    }

    s = FileMgr::close(file,
                       true, // cleanup cache on close
                       fname.c_str(),
                       nullptr);

    TEST_CHK(s == FDB_RESULT_SUCCESS);
    delete [] commit_log;

    FdbEngine::destroyInstance();
    TEST_RESULT("wal reference pointer test");
}

int main() {

    wal_basic_test();
    wal_ref_ptr_test();

    return 0;
}
