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
#include <stdint.h>
#include <time.h>
#include<mutex>
#if !defined(WIN32) && !defined(_WIN32)
#include <unistd.h>
#endif

#include "libforestdb/forestdb.h"
#include "test.h"

#include "internal_types.h"
#include "functional_util.h"

void rollback_secondary_kvs()
{
    TEST_INIT();
    memleak_start();

    int r;
    void *value_out;
    size_t valuelen_out;

    fdb_status status;
    fdb_config fconfig = fdb_get_default_config();
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    fdb_file_handle *dbfile;
    fdb_kvs_handle *kv1, *kv2;

    r = system(SHELL_DEL" mvcc_test* > errorlog.txt");
    (void)r;

    fdb_open(&dbfile, "./mvcc_test1", &fconfig);
    fdb_kvs_open_default(dbfile, &kv1, &kvs_config);
    fdb_kvs_open_default(dbfile, &kv2, &kvs_config);

    // seq:2
    status = fdb_set_kv(kv1, (void *) "a", 1, (void *)"val-a", 5);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_set_kv(kv1, (void *) "b", 1, (void *)"val-b", 5);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);

    // seq:3
    status = fdb_set_kv(kv1, (void *) "b", 1, (void *)"val-v", 5);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);

    // seq:4
    status = fdb_del_kv(kv1, (void *)"a", 1);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);

    // get 'a' via kv2
    status = fdb_get_kv(kv2, (void *)"b", 1, &value_out, &valuelen_out);
    free(value_out);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // rollback seq:3 via kv2
    status = fdb_rollback(&kv2, 3);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    fdb_close(dbfile);
    fdb_shutdown();

    memleak_end();
    TEST_RESULT("rollback secondary kv");
}


void multi_version_test()
{
    TEST_INIT();

    memleak_start();

    int i, r;
    int n = 2;
    fdb_file_handle *dbfile, *dbfile_new;
    fdb_kvs_handle *db;
    fdb_kvs_handle *db_new;
    fdb_doc **doc = alca(fdb_doc*, n);
    fdb_doc *rdoc;
    fdb_status status;

    char keybuf[256], metabuf[256], bodybuf[256];

    // remove all previous mvcc_test files
    r = system(SHELL_DEL" mvcc_test* > errorlog.txt");
    (void)r;

    fdb_config fconfig = fdb_get_default_config();
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    fconfig.buffercache_size = 1048576;
    fconfig.wal_threshold = 1024;
    fconfig.flags = FDB_OPEN_FLAG_CREATE;
    fconfig.compaction_threshold = 0;

    // open db
    fdb_open(&dbfile, "./mvcc_test1", &fconfig);
    fdb_kvs_open_default(dbfile, &db, &kvs_config);
    status = fdb_set_log_callback(db, logCallbackFunc, (void *) "multi_version_test");
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // insert documents
    for (i=0;i<n;++i){
        sprintf(keybuf, "key%d", i);
        sprintf(metabuf, "meta%d", i);
        sprintf(bodybuf, "body%d", i);
        fdb_doc_create(&doc[i], (void*)keybuf, strlen(keybuf),
            (void*)metabuf, strlen(metabuf), (void*)bodybuf, strlen(bodybuf));
        fdb_set(db, doc[i]);
    }

    // commit
    fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);

    // open same db file using a new handle
    fdb_open(&dbfile_new, "./mvcc_test1", &fconfig);
    fdb_kvs_open_default(dbfile_new, &db_new, &kvs_config);
    status = fdb_set_log_callback(db_new, logCallbackFunc, (void *) "multi_version_test");
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // update documents using the old handle
    for (i=0;i<n;++i){
        sprintf(metabuf, "meta2%d", i);
        sprintf(bodybuf, "body2%d", i);
        fdb_doc_update(&doc[i], (void*)metabuf, strlen(metabuf),
            (void*)bodybuf, strlen(bodybuf));
        fdb_set(db, doc[i]);
    }

    // manually flush WAL and commit using the old handle
    fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);

    // retrieve documents using the old handle
    for (i=0;i<n;++i){
        // search by key
        fdb_doc_create(&rdoc, doc[i]->key, doc[i]->keylen, NULL, 0, NULL, 0);
        status = fdb_get(db, rdoc);

        TEST_CHK(status == FDB_RESULT_SUCCESS);
        TEST_CMP(rdoc->meta, doc[i]->meta, rdoc->metalen);
        TEST_CMP(rdoc->body, doc[i]->body, rdoc->bodylen);

        // free result document
        fdb_doc_free(rdoc);
    }

    // retrieve documents using the new handle
    for (i=0;i<n;++i){
        // search by key
        fdb_doc_create(&rdoc, doc[i]->key, doc[i]->keylen, NULL, 0, NULL, 0);
        status = fdb_get(db_new, rdoc);

        TEST_CHK(status == FDB_RESULT_SUCCESS);
        TEST_CMP(rdoc->meta, doc[i]->meta, rdoc->metalen);
        TEST_CMP(rdoc->body, doc[i]->body, rdoc->bodylen);

        // free result document
        fdb_doc_free(rdoc);
    }

    // close and re-open the new handle
    fdb_kvs_close(db_new);
    fdb_close(dbfile_new);
    fdb_open(&dbfile_new, "./mvcc_test1", &fconfig);
    fdb_kvs_open_default(dbfile_new, &db_new, &kvs_config);
    status = fdb_set_log_callback(db_new, logCallbackFunc, (void *) "multi_version_test");
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // retrieve documents using the new handle
    for (i=0;i<n;++i){
        // search by key
        fdb_doc_create(&rdoc, doc[i]->key, doc[i]->keylen, NULL, 0, NULL, 0);
        status = fdb_get(db_new, rdoc);

        TEST_CHK(status == FDB_RESULT_SUCCESS);
        // the new version of data should be read
        TEST_CMP(rdoc->meta, doc[i]->meta, rdoc->metalen);
        TEST_CMP(rdoc->body, doc[i]->body, rdoc->bodylen);

        // free result document
        fdb_doc_free(rdoc);
    }


    // free all documents
    for (i=0;i<n;++i){
        fdb_doc_free(doc[i]);
    }

    // close db file
    fdb_kvs_close(db);
    fdb_kvs_close(db_new);
    fdb_close(dbfile);
    fdb_close(dbfile_new);

    // free all resources
    fdb_shutdown();

    memleak_end();

    TEST_RESULT("multi version test");
}

void crash_recovery_test(bool walflush)
{
    TEST_INIT();

    memleak_start();

    int i, r;
    int n = 10;
    fdb_file_handle *dbfile;
    fdb_kvs_handle *db;
    fdb_doc **doc = alca(fdb_doc*, n);
    fdb_doc *rdoc;
    fdb_file_info file_info;
    uint64_t bid;
    const char *test_file = "./mvcc_test2";
    fdb_status status;

    char keybuf[256], metabuf[256], bodybuf[256];

    // remove previous mvcc_test files
    r = system(SHELL_DEL" mvcc_test* > errorlog.txt");
    (void)r;

    fdb_config fconfig = fdb_get_default_config();
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    fconfig.buffercache_size = 0;
    fconfig.seqtree_opt = FDB_SEQTREE_USE; // enable seqtree since get_byseq
    fconfig.wal_threshold = 1024;
    fconfig.flags = FDB_OPEN_FLAG_CREATE;
    fconfig.compaction_threshold = 0;

    // reopen db
    fdb_open(&dbfile, test_file, &fconfig);
    fdb_kvs_open_default(dbfile, &db, &kvs_config);
    status = fdb_set_log_callback(db, logCallbackFunc,
                                  (void *) "crash_recovery_test");
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // insert documents
    for (i=0;i<n;++i){
        sprintf(keybuf, "key%d", i);
        sprintf(metabuf, "meta%d", i);
        sprintf(bodybuf, "body%d", i);
        fdb_doc_create(&doc[i], (void*)keybuf, strlen(keybuf),
            (void*)metabuf, strlen(metabuf), (void*)bodybuf, strlen(bodybuf));
        fdb_set(db, doc[i]);
    }

    // commit
    if(walflush){
        status = fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
    } else {
        status = fdb_commit(dbfile, FDB_COMMIT_NORMAL);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
    }

    status = fdb_get_file_info(dbfile, &file_info);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    bid = file_info.file_size / fconfig.blocksize;

    // close the db
    fdb_kvs_close(db);
    fdb_close(dbfile);

    // Shutdown forest db in the middle of the test to simulate crash
    fdb_shutdown();

    // append 9K of non-block aligned garbage at end of file
    r = _disk_dump(test_file, bid * fconfig.blocksize,
                   (2 * fconfig.blocksize) + (fconfig.blocksize / 4));
    TEST_CHK(r >= 0);

    // reopen the same file
    status = fdb_open(&dbfile, test_file, &fconfig);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_kvs_open_default(dbfile, &db, &kvs_config);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_set_log_callback(db, logCallbackFunc,
                                  (void *) "crash_recovery_test");
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // retrieve documents
    for (i=0;i<n;++i){
        // search by key
        fdb_doc_create(&rdoc, doc[i]->key, doc[i]->keylen, NULL, 0, NULL, 0);
        status = fdb_get(db, rdoc);

        TEST_CHK(status == FDB_RESULT_SUCCESS);
        TEST_CMP(rdoc->meta, doc[i]->meta, rdoc->metalen);
        TEST_CMP(rdoc->body, doc[i]->body, rdoc->bodylen);

        // free result document
        fdb_doc_free(rdoc);
    }

    // retrieve documents by sequence number
    for (i=0;i<n;++i){
        // search by seq
        fdb_doc_create(&rdoc, NULL, 0, NULL, 0, NULL, 0);
        rdoc->seqnum = i + 1;
        status = fdb_get_byseq(db, rdoc);

        TEST_CHK(status == FDB_RESULT_SUCCESS);

        // free result document
        fdb_doc_free(rdoc);
    }

    // free all documents
    for (i=0;i<n;++i){
        fdb_doc_free(doc[i]);
    }

    // close db file
    fdb_kvs_close(db);
    fdb_close(dbfile);

    // free all resources
    fdb_shutdown();

    memleak_end();

    if(walflush){
        TEST_RESULT("crash recovery test - walflush");
    } else {
        TEST_RESULT("crash recovery test - normal flush");
    }
}

void snapshot_test()
{
    TEST_INIT();

    memleak_start();

    int i, r;
    int n = 20;
    int count;
    fdb_file_handle *dbfile;
    fdb_kvs_handle *db;
    fdb_kvs_handle *snap_db;
    fdb_seqnum_t snap_seq;
    fdb_doc **doc = alca(fdb_doc*, n);
    fdb_doc *rdoc = NULL;
    fdb_kvs_info kvs_info;
    fdb_status status;
    fdb_iterator *iterator;

    char keybuf[256], metabuf[256], bodybuf[256];

    // remove previous mvcc_test files
    r = system(SHELL_DEL" mvcc_test* > errorlog.txt");
    (void)r;

    fdb_config fconfig = fdb_get_default_config();
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    fconfig.buffercache_size = 0;
    fconfig.seqtree_opt = FDB_SEQTREE_USE; // enable seqtree since get_byseq
    fconfig.wal_threshold = 1024;
    fconfig.flags = FDB_OPEN_FLAG_CREATE;
    fconfig.compaction_threshold = 0;

    // remove previous mvcc_test files
    r = system(SHELL_DEL" mvcc_test* > errorlog.txt");
    (void)r;

    // open db
    status = fdb_open(&dbfile, "./mvcc_test1", &fconfig);
    fdb_kvs_open_default(dbfile, &db, &kvs_config);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // Create a snapshot from an empty database file
    status = fdb_snapshot_open(db, &snap_db, 0);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    // check if snapshot's sequence number is zero.
    fdb_get_kvs_info(snap_db, &kvs_info);
    TEST_CHK(kvs_info.last_seqnum == 0);
    // create an iterator on the snapshot for full range
    fdb_iterator_init(snap_db, &iterator, NULL, 0, NULL, 0, FDB_ITR_NONE);
    // Iterator should not return any items.
    status = fdb_iterator_get(iterator, &rdoc);
    TEST_CHK(status == FDB_RESULT_ITERATOR_FAIL);
    fdb_iterator_close(iterator);
    fdb_kvs_close(snap_db);

    // ------- Setup test ----------------------------------
    // insert documents of 0-4
    for (i=0; i<n/4; i++){
        sprintf(keybuf, "key%d", i);
        sprintf(metabuf, "meta%d", i);
        sprintf(bodybuf, "body%d", i);
        fdb_doc_create(&doc[i], (void*)keybuf, strlen(keybuf),
            (void*)metabuf, strlen(metabuf), (void*)bodybuf, strlen(bodybuf));
        fdb_set(db, doc[i]);
    }

    // commit with a manual WAL flush (these docs go into HB-trie)
    fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);

    // insert documents from 4 - 8
    for (; i < n/2 - 1; i++){
        sprintf(keybuf, "key%d", i);
        sprintf(metabuf, "meta%d", i);
        sprintf(bodybuf, "body%d", i);
        fdb_doc_create(&doc[i], (void*)keybuf, strlen(keybuf),
            (void*)metabuf, strlen(metabuf), (void*)bodybuf, strlen(bodybuf));
        fdb_set(db, doc[i]);
    }

    // We want to create:
    // |WALFlushHDR|Key-Value1|HDR|Key-Value2|SnapshotHDR|Key-Value1|HDR|
    // Insert doc 9 with a different value to test duplicate elimination..
    sprintf(keybuf, "key%d", i);
    sprintf(metabuf, "meta%d", i);
    sprintf(bodybuf, "Body%d", i);
    fdb_doc_create(&doc[i], (void*)keybuf, strlen(keybuf),
            (void*)metabuf, strlen(metabuf), (void*)bodybuf, strlen(bodybuf));
    fdb_set(db, doc[i]);

    // commit again without a WAL flush (last doc goes into the AVL tree)
    fdb_commit(dbfile, FDB_COMMIT_NORMAL);

    // Insert doc 9 now again with expected value..
    *(char *)doc[i]->body = 'b';
    fdb_set(db, doc[i]);
    // commit again without a WAL flush (these documents go into the AVL trees)
    fdb_commit(dbfile, FDB_COMMIT_NORMAL);

    // TAKE SNAPSHOT: pick up sequence number of a commit without a WAL flush
    snap_seq = doc[i]->seqnum;

    // Now re-insert doc 9 as another duplicate (only newer sequence number)
    fdb_set(db, doc[i]);
    // commit again without a WAL flush (last doc goes into the AVL tree)
    fdb_commit(dbfile, FDB_COMMIT_NORMAL);

    // insert documents from 10-14 into HB-trie
    for (++i; i < (n/2 + n/4); i++){
        sprintf(keybuf, "key%d", i);
        sprintf(metabuf, "meta%d", i);
        sprintf(bodybuf, "body%d", i);
        fdb_doc_create(&doc[i], (void*)keybuf, strlen(keybuf),
            (void*)metabuf, strlen(metabuf), (void*)bodybuf, strlen(bodybuf));
        fdb_set(db, doc[i]);
    }
    // manually flush WAL & commit
    fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);

    status = fdb_set_log_callback(db, logCallbackFunc,
                                  (void *) "snapshot_test");
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    // ---------- Snapshot tests begin -----------------------
    // Attempt to take snapshot with out-of-range marker..
    status = fdb_snapshot_open(db, &snap_db, 999999);
    TEST_CHK(status == FDB_RESULT_NO_DB_INSTANCE);

    // Init Snapshot of open file with saved document seqnum as marker
    status = fdb_snapshot_open(db, &snap_db, snap_seq);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // check snapshot's sequence number
    fdb_get_kvs_info(snap_db, &kvs_info);
    TEST_CHK(kvs_info.last_seqnum == snap_seq);

    // insert documents from 15 - 19 on file into the WAL
    for (; i < n; i++){
        sprintf(keybuf, "key%d", i);
        sprintf(metabuf, "meta%d", i);
        sprintf(bodybuf, "body%d", i);
        fdb_doc_create(&doc[i], (void*)keybuf, strlen(keybuf),
            (void*)metabuf, strlen(metabuf), (void*)bodybuf, strlen(bodybuf));
        fdb_set(db, doc[i]);
    }
    // commit without a WAL flush (This WAL must not affect snapshot)
    fdb_commit(dbfile, FDB_COMMIT_NORMAL);

    // create an iterator on the snapshot for full range
    fdb_iterator_init(snap_db, &iterator, NULL, 0, NULL, 0, FDB_ITR_NONE);

    // repeat until fail
    i=0;
    count=0;
    do {
        status = fdb_iterator_get(iterator, &rdoc);
        TEST_CHK(status == FDB_RESULT_SUCCESS);

        TEST_CMP(rdoc->key, doc[i]->key, rdoc->keylen);
        TEST_CMP(rdoc->meta, doc[i]->meta, rdoc->metalen);
        TEST_CMP(rdoc->body, doc[i]->body, rdoc->bodylen);

        fdb_doc_free(rdoc);
        rdoc = NULL;
        i ++;
        count++;
    } while (fdb_iterator_next(iterator) != FDB_RESULT_ITERATOR_FAIL);

    TEST_CHK(count==n/2); // Only unique items from the first half

    fdb_iterator_close(iterator);

    // create a sequence iterator on the snapshot for full range
    fdb_iterator_sequence_init(snap_db, &iterator, 0, 0, FDB_ITR_NONE);

    // repeat until fail
    i=0;
    count=0;
    do {
        status = fdb_iterator_get(iterator, &rdoc);
        TEST_CHK(status == FDB_RESULT_SUCCESS);

        TEST_CMP(rdoc->key, doc[i]->key, rdoc->keylen);
        TEST_CMP(rdoc->meta, doc[i]->meta, rdoc->metalen);
        TEST_CMP(rdoc->body, doc[i]->body, rdoc->bodylen);

        fdb_doc_free(rdoc);
        rdoc = NULL;
        i ++;
        count++;
    } while (fdb_iterator_next(iterator) != FDB_RESULT_ITERATOR_FAIL);

    TEST_CHK(count==n/2); // Only unique items from the first half

    fdb_iterator_close(iterator);

    // close db handle
    fdb_kvs_close(db);
    // close snapshot handle
    fdb_kvs_close(snap_db);
    // close db file
    fdb_close(dbfile);

    // free all documents
    for (i=0;i<n;++i){
        fdb_doc_free(doc[i]);
    }

    // 1. Open Database File
    status = fdb_open(&dbfile, "./mvcc_test2", &fconfig);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // 2. Open KV Store
    status = fdb_kvs_open(dbfile, &db, "kv2", &kvs_config);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // 2. Create Key 'a' and Commit
    status = fdb_set_kv(db, (void *) "a", 1, (void *)"val-a", 5);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_commit(dbfile, FDB_COMMIT_NORMAL);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // 3. Create Key 'b' and Commit
    status = fdb_set_kv(db, (void *)"b", 1, (void *)"val-b", 5);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_commit(dbfile, FDB_COMMIT_NORMAL);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // 4. Create Key 'c' and Commit
    status = fdb_set_kv(db, (void *)"c", 1, (void *)"val-c", 5);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_commit(dbfile, FDB_COMMIT_NORMAL);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // 5. Remember seqnum for opening snapshot
    status = fdb_get_kvs_info(db, &kvs_info);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    snap_seq = kvs_info.last_seqnum;

    // 6.  Create an iterator
    status = fdb_iterator_init(db, &iterator, (void *)"a", 1,
                               (void *)"c", 1, FDB_ITR_NONE);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // 7. Do a seek
    status = fdb_iterator_seek(iterator, (void *)"b", 1, FDB_ITR_SEEK_HIGHER);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // 8. Close the iterator
    status = fdb_iterator_close(iterator);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // 9. Open a snapshot at the same point
    status = fdb_snapshot_open(db, &snap_db, snap_seq);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // That works, now attempt to do exact same sequence on a snapshot
    // The snapshot is opened at the exact same place that the original
    // database handle should be at (last seq 3)

    // 10.  Create an iterator on snapshot
    status = fdb_iterator_init(snap_db, &iterator, (void *)"a", 1,
                               (void *)"c", 1, FDB_ITR_NONE);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // 11. Do a seek
    status = fdb_iterator_seek(iterator, (void *)"b", 1, FDB_ITR_SEEK_HIGHER);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // 12. Close the iterator
    status = fdb_iterator_close(iterator);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // close db handle
    fdb_kvs_close(db);
    // close snapshot handle
    fdb_kvs_close(snap_db);
    // close db file
    fdb_close(dbfile);

    // free all resources
    fdb_shutdown();

    memleak_end();

    TEST_RESULT("snapshot test");
}

void snapshot_stats_test()
{
    TEST_INIT();

    memleak_start();

    int i, r;
    int n = 20;
    fdb_file_handle *dbfile;
    fdb_kvs_handle *db;
    fdb_kvs_handle *snap_db;
    fdb_seqnum_t snap_seq;
    fdb_doc **doc = alca(fdb_doc*, n);
    fdb_kvs_info kvs_info;
    fdb_status status;

    char keybuf[256], metabuf[256], bodybuf[256];

    // remove previous mvcc_test files
    r = system(SHELL_DEL" mvcc_test* > errorlog.txt");
    (void)r;

    fdb_config fconfig = fdb_get_default_config();
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    fconfig.buffercache_size = 0;
    fconfig.wal_threshold = 1024;
    fconfig.flags = FDB_OPEN_FLAG_CREATE;
    fconfig.compaction_threshold = 0;

    // remove previous mvcc_test files
    r = system(SHELL_DEL" mvcc_test* > errorlog.txt");
    (void)r;

    // open db
    status = fdb_open(&dbfile, "./mvcc_test1", &fconfig);
    fdb_kvs_open_default(dbfile, &db, &kvs_config);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // ------- Setup test ----------------------------------
    // insert documents
    for (i=0; i<n; i++){
        sprintf(keybuf, "key%d", i);
        sprintf(metabuf, "meta%d", i);
        sprintf(bodybuf, "body%d", i);
        fdb_doc_create(&doc[i], (void*)keybuf, strlen(keybuf),
            (void*)metabuf, strlen(metabuf), (void*)bodybuf, strlen(bodybuf));
        fdb_set(db, doc[i]);
        fdb_doc_free(doc[i]);
    }

    // commit with a manual WAL flush (these docs go into HB-trie)
    fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);

    // retrieve the sequence number for a snapshot open
    status = fdb_get_kvs_info(db, &kvs_info);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    snap_seq = kvs_info.last_seqnum;

    status = fdb_set_log_callback(db, logCallbackFunc,
                                  (void *) "snapshot_stats_test");
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // Init Snapshot of open file with saved document seqnum as marker
    status = fdb_snapshot_open(db, &snap_db, snap_seq);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // check snapshot's sequence number
    fdb_get_kvs_info(snap_db, &kvs_info);
    TEST_CHK(kvs_info.last_seqnum == snap_seq);

    TEST_CHK(kvs_info.doc_count == (size_t)n);
    TEST_CHK(kvs_info.file == dbfile);

    // close snapshot handle
    fdb_kvs_close(snap_db);

    // Test stats by creating an in-memory snapshot
    status = fdb_snapshot_open(db, &snap_db, FDB_SNAPSHOT_INMEM);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // check snapshot's sequence number
    fdb_get_kvs_info(snap_db, &kvs_info);
    TEST_CHK(kvs_info.last_seqnum == snap_seq);

    TEST_CHK(kvs_info.doc_count == (size_t)n);
    TEST_CHK(kvs_info.file == dbfile);

    // close snapshot handle
    fdb_kvs_close(snap_db);

    // close db handle
    fdb_kvs_close(db);
    // close db file
    fdb_close(dbfile);

    // free all resources
    fdb_shutdown();

    memleak_end();

    TEST_RESULT("snapshot stats test");
}

void snapshot_with_uncomitted_data_test()
{
    TEST_INIT();

    int n = 10, value_len=32;
    int i, r, idx;
    char cmd[256];
    char key[256], *value;
    char keystr[] = "key%06d";
    char valuestr[] = "value%d";
    fdb_file_handle *db_file;
    fdb_kvs_handle *db0, *db1, *db2, *snap;
    fdb_config config;
    fdb_kvs_config kvs_config;
    fdb_kvs_info info;
    fdb_seqnum_t seqnum;
    fdb_status s; (void)s;

    sprintf(cmd, SHELL_DEL " mvcc_test* > errorlog.txt");
    r = system(cmd);
    (void)r;

    memleak_start();

    value = (char*)malloc(value_len);

    srand(1234);
    config = fdb_get_default_config();
    config.seqtree_opt = FDB_SEQTREE_USE;
    config.wal_flush_before_commit = true;
    config.multi_kv_instances = true;
    config.buffercache_size = 0*1024*1024;

    kvs_config = fdb_get_default_kvs_config();

    s = fdb_open(&db_file, "./mvcc_test9", &config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_kvs_open(db_file, &db0, NULL, &kvs_config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_kvs_open(db_file, &db1, "db1", &kvs_config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_kvs_open(db_file, &db2, "db2", &kvs_config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    // insert docs in all KV stores
    for (i=0;i<n;++i){
        idx = i;
        sprintf(key, keystr, idx);
        memset(value, 'x', value_len);
        memcpy(value + value_len - 6, "<end>", 6);
        sprintf(value, valuestr, idx);
        s = fdb_set_kv(db0, key, strlen(key)+1, value, value_len);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        s = fdb_set_kv(db1, key, strlen(key)+1, value, value_len);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        s = fdb_set_kv(db2, key, strlen(key)+1, value, value_len);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
    }
    // try to open snapshot before commit
    s = fdb_get_kvs_info(db0, &info);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_snapshot_open(db0, &snap, info.last_seqnum);
    TEST_CHK(s != FDB_RESULT_SUCCESS);

    s = fdb_get_kvs_info(db1, &info);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_snapshot_open(db1, &snap, info.last_seqnum);
    TEST_CHK(s != FDB_RESULT_SUCCESS);

    s = fdb_get_kvs_info(db2, &info);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_snapshot_open(db2, &snap, info.last_seqnum);
    TEST_CHK(s != FDB_RESULT_SUCCESS);

    s = fdb_commit(db_file, FDB_COMMIT_NORMAL);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    s = fdb_get_kvs_info(db1, &info);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    seqnum = info.last_seqnum;

    s = fdb_get_kvs_info(db2, &info);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    TEST_CHK(seqnum == info.last_seqnum);

    s = fdb_get_kvs_info(db0, &info);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    TEST_CHK(seqnum == info.last_seqnum);

    // now insert docs into default and db2 only, without commit
    for (i=0;i<n;++i){
        idx = i;
        sprintf(key, keystr, idx);
        memset(value, 'x', value_len);
        memcpy(value + value_len - 6, "<end>", 6);
        sprintf(value, valuestr, idx);
        s = fdb_set_kv(db0, key, strlen(key)+1, value, value_len);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        s = fdb_set_kv(db2, key, strlen(key)+1, value, value_len);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
    }

    // open snapshot on db1
    s = fdb_get_kvs_info(db1, &info);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    // latest (comitted) seqnum
    s = fdb_snapshot_open(db1, &snap, info.last_seqnum);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_kvs_close(snap);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    // open snapshot on db2
    s = fdb_get_kvs_info(db2, &info);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    // latest (uncomitted) seqnum
    s = fdb_snapshot_open(db2, &snap, info.last_seqnum);
    TEST_CHK(s != FDB_RESULT_SUCCESS);
    // committed seqnum
    s = fdb_snapshot_open(db2, &snap, seqnum);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_kvs_close(snap);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    // open snapshot on default KVS
    s = fdb_get_kvs_info(db0, &info);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    // latest (uncomitted) seqnum
    s = fdb_snapshot_open(db0, &snap, info.last_seqnum);
    TEST_CHK(s != FDB_RESULT_SUCCESS);
    // committed seqnum
    s = fdb_snapshot_open(db0, &snap, seqnum);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_kvs_close(snap);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    s = fdb_close(db_file);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_shutdown();
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    free(value);
    memleak_end();

    TEST_RESULT("snapshot with uncomitted data in other KVS test");
}

void in_memory_snapshot_test()
{
    TEST_INIT();

    memleak_start();

    int i, r;
    int n = 20;
    int count;
    fdb_file_handle *dbfile;
    fdb_kvs_handle *db;
    fdb_kvs_handle *snap_db;
    fdb_seqnum_t snap_seq;
    fdb_doc **doc = alca(fdb_doc*, n);
    fdb_doc *rdoc;
    fdb_kvs_info kvs_info;
    fdb_status status;
    fdb_iterator *iterator;

    char keybuf[256], metabuf[256], bodybuf[256];

    // remove previous mvcc_test files
    r = system(SHELL_DEL" mvcc_test* > errorlog.txt");
    (void)r;

    fdb_config fconfig = fdb_get_default_config();
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    fconfig.buffercache_size = 0;
    fconfig.wal_threshold = 1024;
    fconfig.flags = FDB_OPEN_FLAG_CREATE;
    fconfig.compaction_threshold = 0;

    // remove previous mvcc_test files
    r = system(SHELL_DEL" mvcc_test* > errorlog.txt");
    (void)r;

    // open db
    status = fdb_open(&dbfile, "./mvcc_test1", &fconfig);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_kvs_open_default(dbfile, &db, &kvs_config);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // Create a snapshot from an empty database file
    status = fdb_snapshot_open(db, &snap_db, 0);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    // check if snapshot's sequence number is zero.
    fdb_get_kvs_info(snap_db, &kvs_info);
    TEST_CHK(kvs_info.last_seqnum == 0);
    // create an iterator on the snapshot for full range
    fdb_iterator_init(snap_db, &iterator, NULL, 0, NULL, 0, FDB_ITR_NONE);
    // Iterator should not return any items.
    status = fdb_iterator_get(iterator, &rdoc);
    TEST_CHK(status == FDB_RESULT_ITERATOR_FAIL);
    fdb_iterator_close(iterator);
    fdb_kvs_close(snap_db);

    // ------- Setup test ----------------------------------
    // insert documents of 0-4
    for (i=0; i<n/4; i++){
        sprintf(keybuf, "key%d", i);
        sprintf(metabuf, "meta%d", i);
        sprintf(bodybuf, "body%d", i);
        fdb_doc_create(&doc[i], (void*)keybuf, strlen(keybuf),
            (void*)metabuf, strlen(metabuf), (void*)bodybuf, strlen(bodybuf));
        fdb_set(db, doc[i]);
    }

    // commit with a manual WAL flush (these docs go into HB-trie)
    fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);

    // insert documents from 5 - 8
    for (; i < n/2 - 1; i++){
        sprintf(keybuf, "key%d", i);
        sprintf(metabuf, "meta%d", i);
        sprintf(bodybuf, "body%d", i);
        fdb_doc_create(&doc[i], (void*)keybuf, strlen(keybuf),
            (void*)metabuf, strlen(metabuf), (void*)bodybuf, strlen(bodybuf));
        fdb_set(db, doc[i]);
    }

    // We want to create:
    // |WALFlushHDR|Key-Value1|HDR|Key-Value2|SnapshotHDR|Key-Value1|HDR|
    // Insert doc 9 with a different value to test duplicate elimination..
    sprintf(keybuf, "key%d", i);
    sprintf(metabuf, "meta%d", i);
    sprintf(bodybuf, "Body%d", i);
    fdb_doc_create(&doc[i], (void*)keybuf, strlen(keybuf),
            (void*)metabuf, strlen(metabuf), (void*)bodybuf, strlen(bodybuf));
    fdb_set(db, doc[i]);

    // commit again without a WAL flush (last doc goes into the AVL tree)
    fdb_commit(dbfile, FDB_COMMIT_NORMAL);

    // Insert doc 9 now again with expected value..
    *(char *)doc[i]->body = 'b';
    fdb_set(db, doc[i]);

    // TAKE SNAPSHOT: pick up sequence number of a commit without a WAL flush
    snap_seq = doc[i]->seqnum;

    // Creation of a snapshot with a sequence number that was taken WITHOUT a
    // commit must fail even if it from the latest document that was set...
    fdb_get_kvs_info(db, &kvs_info);
    status = fdb_snapshot_open(db, &snap_db, kvs_info.last_seqnum);
    TEST_CHK(status == FDB_RESULT_NO_DB_INSTANCE);

    // ---------- Snapshot tests begin -----------------------
    // Initialize an in-memory snapshot Without a Commit...
    // WAL items are not flushed...
    status = fdb_snapshot_open(db, &snap_db, FDB_SNAPSHOT_INMEM);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // commit again without a WAL flush (these documents go into the AVL trees)
    fdb_commit(dbfile, FDB_COMMIT_NORMAL);

    // Now re-insert doc 9 as another duplicate (only newer sequence number)
    fdb_set(db, doc[i]);

    // commit again without a WAL flush (last doc goes into the AVL tree)
    fdb_commit(dbfile, FDB_COMMIT_NORMAL);

    // insert documents from 10-14 into HB-trie
    for (++i; i < (n/2 + n/4); i++){
        sprintf(keybuf, "key%d", i);
        sprintf(metabuf, "meta%d", i);
        sprintf(bodybuf, "body%d", i);
        fdb_doc_create(&doc[i], (void*)keybuf, strlen(keybuf),
                (void*)metabuf, strlen(metabuf), (void*)bodybuf, strlen(bodybuf));
        fdb_set(db, doc[i]);
    }

    status = fdb_set_log_callback(db, logCallbackFunc,
                                  (void *) "in_memory_snapshot_test");
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // check snapshot's sequence number
    fdb_get_kvs_info(snap_db, &kvs_info);
    TEST_CHK(kvs_info.last_seqnum == snap_seq);

    // insert documents from 15 - 19 on file into the WAL
    for (; i < n; i++){
        sprintf(keybuf, "key%d", i);
        sprintf(metabuf, "meta%d", i);
        sprintf(bodybuf, "body%d", i);
        fdb_doc_create(&doc[i], (void*)keybuf, strlen(keybuf),
            (void*)metabuf, strlen(metabuf), (void*)bodybuf, strlen(bodybuf));
        fdb_set(db, doc[i]);
    }
    // commit without a WAL flush (This WAL must not affect snapshot)
    fdb_commit(dbfile, FDB_COMMIT_NORMAL);

    // create an iterator on the snapshot for full range
    fdb_iterator_init(snap_db, &iterator, NULL, 0, NULL, 0, FDB_ITR_NONE);

    // repeat until fail
    i=0;
    count=0;
    rdoc = NULL;
    do {
        status = fdb_iterator_get(iterator, &rdoc);
        TEST_CHK(status == FDB_RESULT_SUCCESS);

        TEST_CMP(rdoc->key, doc[i]->key, rdoc->keylen);
        TEST_CMP(rdoc->meta, doc[i]->meta, rdoc->metalen);
        TEST_CMP(rdoc->body, doc[i]->body, rdoc->bodylen);

        fdb_doc_free(rdoc);
        rdoc = NULL;
        i++;
        count++;
    } while (fdb_iterator_next(iterator) != FDB_RESULT_ITERATOR_FAIL);

    TEST_CHK(count==n/2); // Only unique items from the first half

    fdb_iterator_close(iterator);

    // close db handle
    fdb_kvs_close(db);
    // close snapshot handle
    fdb_kvs_close(snap_db);

    // close db file
    fdb_close(dbfile);

    // free all documents
    for (i=0;i<n;++i){
        fdb_doc_free(doc[i]);
    }

    // free all resources
    fdb_shutdown();

    memleak_end();

    TEST_RESULT("in-memory snapshot test");
}

void in_memory_snapshot_cleanup_test()
{
    TEST_INIT();

    memleak_start();

    int r;
    fdb_file_handle *dbfile;
    fdb_kvs_handle *db;
    fdb_kvs_handle *snap_db1, *snap_db2, *snap_db3;
    fdb_kvs_handle *psnap_db1, *psnap_db2, *psnap_db3;
    fdb_doc *doc = NULL;
    fdb_doc *rdoc;
    fdb_status status;

    char keybuf[32], metabuf[32], bodybuf[32];

    // remove previous mvcc_test files
    r = system(SHELL_DEL" mvcc_test* > errorlog.txt");
    (void)r;

    fdb_config fconfig = fdb_get_default_config();
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    fconfig.wal_threshold = 1024;
    fconfig.flags = FDB_OPEN_FLAG_CREATE;
    fconfig.compaction_threshold = 0;
    fconfig.block_reusing_threshold = 0;

    // remove previous mvcc_test files
    r = system(SHELL_DEL" mvcc_test* > errorlog.txt");
    (void)r;

    // open db
    status = fdb_open(&dbfile, "./mvcc_test1", &fconfig);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_kvs_open_default(dbfile, &db, &kvs_config);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    status = fdb_set_log_callback(db, logCallbackFunc,
                                  (void *) "in_memory_snapshot_cleanup_test");
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    sprintf(keybuf, "key");
    sprintf(metabuf, "meta");
    sprintf(bodybuf, "body");
    fdb_doc_create(&doc, (void*)keybuf, strlen(keybuf),
            (void*)metabuf, strlen(metabuf), (void*)bodybuf, strlen(bodybuf));
    fdb_set(db, doc);

    // commit without a WAL flush
    fdb_commit(dbfile, FDB_COMMIT_NORMAL);

    status = fdb_snapshot_open(db, &snap_db1, FDB_SNAPSHOT_INMEM);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    status = fdb_set(db, doc);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // commit without a WAL flush
    status = fdb_commit(dbfile, FDB_COMMIT_NORMAL);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    status = fdb_snapshot_open(db, &snap_db2, FDB_SNAPSHOT_INMEM);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    status = fdb_set(db, doc);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // commit without a WAL flush
    status = fdb_commit(dbfile, FDB_COMMIT_NORMAL);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    status = fdb_set(db, doc);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // commit without a WAL flush
    status = fdb_commit(dbfile, FDB_COMMIT_NORMAL);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    fdb_doc_free(doc);

    // Update doc with new Key
    char newKey[32];
    sprintf(newKey, "Key");
    fdb_doc_create(&doc, (void*)newKey, strlen(newKey),
            (void*)metabuf, strlen(metabuf), (void*)bodybuf, strlen(bodybuf));
    fdb_set(db, doc);

    status = fdb_snapshot_open(db, &snap_db3, FDB_SNAPSHOT_INMEM);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    fdb_doc_create(&rdoc, (void*)keybuf, strlen(keybuf), NULL, 0, NULL, 0);

    status = fdb_get(snap_db1, rdoc);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    status = fdb_get(snap_db2, rdoc);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    status = fdb_get(snap_db3, rdoc);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    fdb_doc_free(rdoc);

    status = fdb_snapshot_open(db, &psnap_db1, 1);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    status = fdb_snapshot_open(db, &psnap_db2, 2);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    status = fdb_snapshot_open(db, &psnap_db3, 3);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // close snapshot handle
    fdb_kvs_close(snap_db1);
    fdb_kvs_close(snap_db2);
    fdb_kvs_close(snap_db3);

    // commit without a WAL flush
    status = fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    fdb_kvs_close(psnap_db1);
    fdb_kvs_close(psnap_db2);
    fdb_kvs_close(psnap_db3);

    // close db handle
    fdb_kvs_close(db);

    // close db file
    fdb_close(dbfile);

    fdb_doc_free(doc);

    // free all resources
    fdb_shutdown();

    memleak_end();

    TEST_RESULT("in-memory snapshot cleanup test");
}

void in_memory_snapshot_on_dirty_hbtrie_test()
{
    TEST_INIT();

    int n = 300, value_len=32;
    int i, r, idx, c;
    char cmd[256];
    char key[256], *value;
    char keystr[] = "k%05d";
    char keystr2[] = "k%06d";
    char valuestr[] = "value%08d";
    fdb_file_handle *db_file;
    fdb_kvs_handle *db, *snap, *snap_clone;
    fdb_config config;
    fdb_kvs_config kvs_config;
    fdb_status s;
    fdb_iterator *fit, *fit_normal, *fit_clone;
    fdb_doc *doc;

    sprintf(cmd, SHELL_DEL " mvcc_test* > errorlog.txt");
    r = system(cmd);
    (void)r;

    memleak_start();

    value = (char*)malloc(value_len);

    config = fdb_get_default_config();
    config.durability_opt = FDB_DRB_ASYNC;
    config.seqtree_opt = FDB_SEQTREE_USE;
    config.wal_flush_before_commit = true;
    config.wal_threshold = n/5;
    config.multi_kv_instances = true;
    config.buffercache_size = 0;

    kvs_config = fdb_get_default_kvs_config();

    s = fdb_open(&db_file, "./mvcc_test", &config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_kvs_open(db_file, &db, "db", &kvs_config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    // write a few documents and commit & wal flush
    for (i=0;i<n/10;++i){
        idx = i;
        sprintf(key, keystr, idx);
        memset(value, 'x', value_len);
        memcpy(value + value_len - 6, "<end>", 6);
        sprintf(value, valuestr, idx);
        s = fdb_set_kv(db, key, strlen(key)+1, value, value_len);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
    }
    s = fdb_commit(db_file, FDB_COMMIT_MANUAL_WAL_FLUSH);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    // create an in-memory snapshot and its clone
    s = fdb_snapshot_open(db, &snap, FDB_SNAPSHOT_INMEM);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_snapshot_open(snap, &snap_clone, FDB_SNAPSHOT_INMEM);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    // write a number of documents in order to make WAL be flushed before commit
    for (i=n/10;i<n;++i){
        idx = i;
        sprintf(key, keystr, idx);
        memset(value, 'x', value_len);
        memcpy(value + value_len - 6, "<end>", 6);
        sprintf(value, valuestr, idx);
        s = fdb_set_kv(db, key, strlen(key)+1, value, value_len);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
    }

    void *v_out;
    size_t vlen_out;
    idx = n/10;
    sprintf(key, keystr, idx);
    s = fdb_get_kv(snap, key, strlen(key)+1, &v_out, &vlen_out);
    // should not be able to retrieve
    TEST_CHK(s != FDB_RESULT_SUCCESS);

    s = fdb_get_kv(snap_clone, key, strlen(key)+1, &v_out, &vlen_out);
    // should not be able to retrieve in also clone
    TEST_CHK(s != FDB_RESULT_SUCCESS);

    // close snapshot and its clone
    s = fdb_kvs_close(snap);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_kvs_close(snap_clone);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    // create an in-memory snapshot
    s = fdb_snapshot_open(db, &snap, FDB_SNAPSHOT_INMEM);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    s = fdb_iterator_init(snap, &fit, NULL, 0, NULL, 0, 0x0);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    c = 0;
    do {
        doc = NULL;
        s = fdb_iterator_get(fit, &doc);
        if (s != FDB_RESULT_SUCCESS) break;

        idx = c;
        sprintf(key, keystr, idx);
        memset(value, 'x', value_len);
        memcpy(value + value_len - 6, "<end>", 6);
        sprintf(value, valuestr, idx);
        TEST_CMP(doc->key, key, doc->keylen);
        TEST_CMP(doc->body, value, doc->bodylen);
        c++;
        fdb_doc_free(doc);
    } while(fdb_iterator_next(fit) == FDB_RESULT_SUCCESS);
    TEST_CHK(c == n);

    s = fdb_iterator_close(fit);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    // create a clone
    s = fdb_snapshot_open(snap, &snap_clone, FDB_SNAPSHOT_INMEM);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    // create iterators on snapshot and its clone
    s = fdb_iterator_init(snap, &fit, NULL, 0, NULL, 0, 0x0);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_iterator_init(snap_clone, &fit_clone, NULL, 0, NULL, 0, 0x0);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    // also create an iterator on a normal handle
    s = fdb_iterator_init(db, &fit_normal, NULL, 0, NULL, 0, 0x0);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    c = 0;
    do {
        doc = NULL;
        s = fdb_iterator_get(fit, &doc);
        if (s != FDB_RESULT_SUCCESS) break;

        idx = c;
        sprintf(key, keystr, idx);
        memset(value, 'x', value_len);
        memcpy(value + value_len - 6, "<end>", 6);
        sprintf(value, valuestr, idx);
        TEST_CMP(doc->key, key, doc->keylen);
        TEST_CMP(doc->body, value, doc->bodylen);
        c++;
        fdb_doc_free(doc);

        doc = NULL;
        s = fdb_iterator_get(fit, &doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(doc->key, key, doc->keylen);
        TEST_CMP(doc->body, value, doc->bodylen);
        fdb_doc_free(doc);

        if (c == n/5) {
            // insert new docs in the middle of iteration
            for (i=0; i<n*10; ++i){
                idx = i;
                sprintf(key, keystr2, idx);
                memset(value, 'x', value_len);
                memcpy(value + value_len - 6, "<end>", 6);
                sprintf(value, valuestr, idx);
                s = fdb_set_kv(db, key, strlen(key)+1, value, value_len);
                TEST_CHK(s == FDB_RESULT_SUCCESS);
            }
        }

        s = fdb_iterator_next(fit);
        // result should be same to clone
        if (s != FDB_RESULT_SUCCESS) {
            s = fdb_iterator_next(fit_clone);
            TEST_CHK(s != FDB_RESULT_SUCCESS);
        } else {
            s = fdb_iterator_next(fit_clone);
            TEST_CHK(s == FDB_RESULT_SUCCESS);
        }
    } while(s == FDB_RESULT_SUCCESS);
    TEST_CHK(c == n);

    // close iterators
    s = fdb_iterator_close(fit);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_iterator_close(fit_clone);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    // the results should be same in the normal iterator
    c = 0;
    do {
        doc = NULL;
        s = fdb_iterator_get(fit_normal, &doc);
        if (s != FDB_RESULT_SUCCESS) break;

        idx = c;
        sprintf(key, keystr, idx);
        memset(value, 'x', value_len);
        memcpy(value + value_len - 6, "<end>", 6);
        sprintf(value, valuestr, idx);
        TEST_CMP(doc->key, key, doc->keylen);
        TEST_CMP(doc->body, value, doc->bodylen);
        c++;
        fdb_doc_free(doc);
    } while(fdb_iterator_next(fit_normal) == FDB_RESULT_SUCCESS);
    TEST_CHK(c == n);

    s = fdb_iterator_close(fit_normal);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    s = fdb_kvs_close(snap);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    s = fdb_kvs_close(snap_clone);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    s = fdb_close(db_file);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_shutdown();
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    free(value);

    memleak_end();

    TEST_RESULT("in-memory snapshot on dirty HB+trie nodes test");
}


struct cb_inmem_snap_args {
    fdb_kvs_handle *handle;
    int n;
    int move_count;
    int value_len;
    char *keystr;
    char *valuestr;
};

static fdb_compact_decision cb_inmem_snap(fdb_file_handle *fhandle,
                            fdb_compaction_status status,
                            const char *kv_name,
                            fdb_doc *doc_in, uint64_t old_offset,
                            uint64_t new_offset,
                            void *ctx)
{
    TEST_INIT();
    int c, idx;
    char key[256], value[256];
    void *value_out;
    size_t valuelen;
    fdb_kvs_handle *snap;
    fdb_kvs_info info;
    fdb_iterator *fit;
    fdb_doc *doc;
    fdb_status s;
    fdb_compact_decision ret = FDB_CS_KEEP_DOC;
    struct cb_inmem_snap_args *args = (struct cb_inmem_snap_args *)ctx;
    (void)args;

    if (status == FDB_CS_MOVE_DOC) {
        TEST_CHK(kv_name);
        if (doc_in->deleted) {
            ret = FDB_CS_DROP_DOC;
        }
        args->move_count++;
        if (args->move_count == 2) {
            // open in-memory snapshot
            s = fdb_snapshot_open(args->handle, &snap, FDB_SNAPSHOT_INMEM);
            TEST_CHK(s == FDB_RESULT_SUCCESS);

            s = fdb_get_kvs_info(snap, &info);
            TEST_CHK(s == FDB_RESULT_SUCCESS);
            TEST_CHK(info.last_seqnum == (fdb_seqnum_t)args->n);

            s = fdb_iterator_init(snap, &fit, NULL, 0, NULL, 0, 0x0);
            TEST_CHK(s == FDB_RESULT_SUCCESS);

            c = 0;
            do {
                doc = NULL;
                s = fdb_iterator_get(fit, &doc);
                if (s != FDB_RESULT_SUCCESS) {
                    break;
                }
                idx = c;
                sprintf(key, args->keystr, idx);
                memset(value, 'x', args->value_len);
                memcpy(value + args->value_len - 6, "<end>", 6);
                sprintf(value, args->valuestr, idx);
                TEST_CMP(doc->key, key, doc->keylen);
                TEST_CMP(doc->body, value, doc->bodylen);

                c++;
                fdb_doc_free(doc);
            } while (fdb_iterator_next(fit) == FDB_RESULT_SUCCESS);
            TEST_CHK(c == args->n);

            s = fdb_iterator_close(fit);
            TEST_CHK(s == FDB_RESULT_SUCCESS);

            fdb_kvs_close(snap);

        } else if (args->move_count == 5) {
            // insert new doc
            sprintf(key, "new_key");
            sprintf(value, "new_value");
            s = fdb_set_kv(args->handle, (void*)key, strlen(key)+1, (void*)value, strlen(value)+1);
            TEST_CHK(s == FDB_RESULT_SUCCESS);

            // open in-memory snapshot
            s = fdb_snapshot_open(args->handle, &snap, FDB_SNAPSHOT_INMEM);
            TEST_CHK(s == FDB_RESULT_SUCCESS);

            s = fdb_get_kvs_info(snap, &info);
            TEST_CHK(s == FDB_RESULT_SUCCESS);
            TEST_CHK(info.last_seqnum == (fdb_seqnum_t)args->n+1);

            s = fdb_iterator_init(snap, &fit, NULL, 0, NULL, 0, 0x0);
            TEST_CHK(s == FDB_RESULT_SUCCESS);

            c = 0;
            do {
                doc = NULL;
                s = fdb_iterator_get(fit, &doc);
                if (s != FDB_RESULT_SUCCESS) {
                    break;
                }
                if (c < args->n) {
                    idx = c;
                    sprintf(key, args->keystr, idx);
                    memset(value, 'x', args->value_len);
                    memcpy(value + args->value_len - 6, "<end>", 6);
                    sprintf(value, args->valuestr, idx);
                    TEST_CMP(doc->key, key, doc->keylen);
                    TEST_CMP(doc->body, value, doc->bodylen);
                } else {
                    // new document
                    sprintf(key, "new_key");
                    sprintf(value, "new_value");
                    TEST_CMP(doc->key, key, doc->keylen);
                    TEST_CMP(doc->body, value, doc->bodylen);
                }

                c++;
                fdb_doc_free(doc);
            } while (fdb_iterator_next(fit) == FDB_RESULT_SUCCESS);
            TEST_CHK(c == args->n + 1);

            s = fdb_iterator_close(fit);
            TEST_CHK(s == FDB_RESULT_SUCCESS);

            s = fdb_get_kv(snap, (void*)key, strlen(key)+1, &value_out, &valuelen);
            TEST_CHK(s == FDB_RESULT_SUCCESS);
            TEST_CMP(value_out, value, valuelen);
            fdb_free_block(value_out);

            fdb_kvs_close(snap);
        }
    }
    return ret;
}

void in_memory_snapshot_compaction_test()
{
    TEST_INIT();

    int n = 10, value_len=32;
    int i, r, c, idx;
    char cmd[256];
    char key[256], *value;
    char keystr[] = "k%05d";
    char valuestr[] = "value%08d";
    void *value_out;
    size_t valuelen;
    fdb_file_handle *db_file;
    fdb_kvs_handle *db, *db2, *snap;
    fdb_config config;
    fdb_kvs_config kvs_config;
    fdb_kvs_info info;
    fdb_iterator *fit;
    fdb_doc *doc;
    fdb_status s;
    struct cb_inmem_snap_args cargs;

    sprintf(cmd, SHELL_DEL " mvcc_test* > errorlog.txt");
    r = system(cmd);
    (void)r;

    memleak_start();

    value = (char*)malloc(value_len);

    config = fdb_get_default_config();
    config.durability_opt = FDB_DRB_ASYNC;
    config.seqtree_opt = FDB_SEQTREE_USE;
    config.wal_flush_before_commit = true;
    config.wal_threshold = n/5;
    config.multi_kv_instances = true;
    config.buffercache_size = 0;
    config.compaction_cb = cb_inmem_snap;
    config.compaction_cb_mask = FDB_CS_MOVE_DOC;
    config.compaction_cb_ctx = &cargs;

    kvs_config = fdb_get_default_kvs_config();

    s = fdb_open(&db_file, "./mvcc_test", &config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_kvs_open(db_file, &db, "db", &kvs_config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    s = fdb_kvs_open(db_file, &db2, "db", &kvs_config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    cargs.handle = db2;
    cargs.move_count = 0;
    cargs.n = n;
    cargs.keystr = keystr;
    cargs.valuestr = valuestr;
    cargs.value_len = value_len;

    // write
    for (i=0;i<n;++i){
        idx = i;
        sprintf(key, keystr, idx);
        memset(value, 'x', value_len);
        memcpy(value + value_len - 6, "<end>", 6);
        sprintf(value, valuestr, idx);
        s = fdb_set_kv(db, key, strlen(key)+1, value, value_len);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
    }
    s = fdb_commit(db_file, FDB_COMMIT_MANUAL_WAL_FLUSH);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    s = fdb_compact(db_file, "./mvcc_test2");
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    // open in-memory snapshot
    s = fdb_snapshot_open(db, &snap, FDB_SNAPSHOT_INMEM);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    s = fdb_get_kvs_info(snap, &info);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    TEST_CHK(info.last_seqnum == (fdb_seqnum_t)n+1);

    s = fdb_iterator_init(snap, &fit, NULL, 0, NULL, 0, 0x0);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    c = 0;
    do {
        doc = NULL;
        s = fdb_iterator_get(fit, &doc);
        if (s != FDB_RESULT_SUCCESS) {
            break;
        }
        if (c < n) {
            idx = c;
            sprintf(key, keystr, idx);
            memset(value, 'x', value_len);
            memcpy(value + value_len - 6, "<end>", 6);
            sprintf(value, valuestr, idx);
            TEST_CMP(doc->key, key, doc->keylen);
            TEST_CMP(doc->body, value, doc->bodylen);
        } else {
            // new document
            sprintf(key, "new_key");
            sprintf(value, "new_value");
            TEST_CMP(doc->key, key, doc->keylen);
            TEST_CMP(doc->body, value, doc->bodylen);
        }

        c++;
        fdb_doc_free(doc);
    } while (fdb_iterator_next(fit) == FDB_RESULT_SUCCESS);
    TEST_CHK(c == n + 1);

    s = fdb_iterator_close(fit);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    s = fdb_get_kv(snap, (void*)key, strlen(key)+1, &value_out, &valuelen);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    TEST_CMP(value_out, value, valuelen);
    fdb_free_block(value_out);

    fdb_kvs_close(snap);

    s = fdb_close(db_file);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_shutdown();
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    free(value);

    memleak_end();

    TEST_RESULT("in-memory snapshot with concurrent compaction test");
}

void snapshot_clone_test()
{
    TEST_INIT();

    memleak_start();

    int i, r;
    int n = 20;
    int count;
    fdb_file_handle *dbfile;
    fdb_kvs_handle *db;
    fdb_kvs_handle *snap_db, *snap_inmem;
    fdb_kvs_handle *snap_db2, *snap_inmem2; // clones from stable & inmemory
    fdb_seqnum_t snap_seq;
    fdb_doc **doc = alca(fdb_doc*, n);
    fdb_doc *rdoc;
    fdb_kvs_info kvs_info;
    fdb_status status;
    fdb_iterator *iterator;

    char keybuf[256], metabuf[256], bodybuf[256];

    // remove previous mvcc_test files
    r = system(SHELL_DEL" mvcc_test* > errorlog.txt");
    (void)r;

    fdb_config fconfig = fdb_get_default_config();
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    fconfig.buffercache_size = 0;
    fconfig.wal_threshold = 1024;
    fconfig.seqtree_opt = FDB_SEQTREE_USE; // enable seqtree since get_byseq
    fconfig.flags = FDB_OPEN_FLAG_CREATE;
    fconfig.compaction_threshold = 0;

    // remove previous mvcc_test files
    r = system(SHELL_DEL" mvcc_test* > errorlog.txt");
    (void)r;

    // open db
    status = fdb_open(&dbfile, "./mvcc_test1", &fconfig);
    fdb_kvs_open_default(dbfile, &db, &kvs_config);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // Create a snapshot from an empty database file
    status = fdb_snapshot_open(db, &snap_db, 0);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    // check if snapshot's sequence number is zero.
    fdb_get_kvs_info(snap_db, &kvs_info);
    TEST_CHK(kvs_info.last_seqnum == 0);
    // create an iterator on the snapshot for full range
    fdb_iterator_init(snap_db, &iterator, NULL, 0, NULL, 0, FDB_ITR_NONE);
    // Iterator should not return any items.
    status = fdb_iterator_next(iterator);
    TEST_CHK(status == FDB_RESULT_ITERATOR_FAIL);
    fdb_iterator_close(iterator);
    fdb_kvs_close(snap_db);

    // ------- Setup test ----------------------------------
    // insert documents of 0-4
    for (i=0; i<n/4; i++){
        sprintf(keybuf, "key%d", i);
        sprintf(metabuf, "meta%d", i);
        sprintf(bodybuf, "body%d", i);
        fdb_doc_create(&doc[i], (void*)keybuf, strlen(keybuf),
            (void*)metabuf, strlen(metabuf), (void*)bodybuf, strlen(bodybuf));
        fdb_set(db, doc[i]);
    }

    // commit with a manual WAL flush (these docs go into HB-trie)
    fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);

    // insert documents from 4 - 8
    for (; i < n/2 - 1; i++){
        sprintf(keybuf, "key%d", i);
        sprintf(metabuf, "meta%d", i);
        sprintf(bodybuf, "body%d", i);
        fdb_doc_create(&doc[i], (void*)keybuf, strlen(keybuf),
            (void*)metabuf, strlen(metabuf), (void*)bodybuf, strlen(bodybuf));
        fdb_set(db, doc[i]);
    }

    // We want to create:
    // |WALFlushHDR|Key-Value1|HDR|Key-Value2|SnapshotHDR|Key-Value1|HDR|
    // Insert doc 9 with a different value to test duplicate elimination..
    sprintf(keybuf, "key%d", i);
    sprintf(metabuf, "meta%d", i);
    sprintf(bodybuf, "Body%d", i);
    fdb_doc_create(&doc[i], (void*)keybuf, strlen(keybuf),
            (void*)metabuf, strlen(metabuf), (void*)bodybuf, strlen(bodybuf));
    fdb_set(db, doc[i]);

    // commit again without a WAL flush (last doc goes into the AVL tree)
    fdb_commit(dbfile, FDB_COMMIT_NORMAL);

    // Insert doc 9 now again with expected value..
    *(char *)doc[i]->body = 'b';
    fdb_set(db, doc[i]);
    // commit again without a WAL flush (these documents go into the AVL trees)
    fdb_commit(dbfile, FDB_COMMIT_NORMAL);

    // TAKE SNAPSHOT: pick up sequence number of a commit without a WAL flush
    snap_seq = doc[i]->seqnum;

    // Initialize an in-memory snapshot Without a Commit...
    // WAL items are not flushed...
    status = fdb_snapshot_open(db, &snap_inmem, FDB_SNAPSHOT_INMEM);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // Now re-insert doc 9 as another duplicate (only newer sequence number)
    fdb_set(db, doc[i]);
    // commit again without a WAL flush (last doc goes into the AVL tree)
    fdb_commit(dbfile, FDB_COMMIT_NORMAL);

    // insert documents from 10-14 into HB-trie
    for (++i; i < (n/2 + n/4); i++){
        sprintf(keybuf, "key%d", i);
        sprintf(metabuf, "meta%d", i);
        sprintf(bodybuf, "body%d", i);
        fdb_doc_create(&doc[i], (void*)keybuf, strlen(keybuf),
            (void*)metabuf, strlen(metabuf), (void*)bodybuf, strlen(bodybuf));
        fdb_set(db, doc[i]);
    }
    // manually flush WAL & commit
    fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);

    status = fdb_set_log_callback(db, logCallbackFunc,
                                  (void *) "snapshot_clone_test");
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    // ---------- Snapshot tests begin -----------------------
    // Attempt to take snapshot with out-of-range marker..
    status = fdb_snapshot_open(db, &snap_db, 999999);
    TEST_CHK(status == FDB_RESULT_NO_DB_INSTANCE);

    // Init Snapshot of open file with saved document seqnum as marker
    status = fdb_snapshot_open(db, &snap_db, snap_seq);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // Clone a snapshot into another snapshot...
    status = fdb_snapshot_open(snap_db, &snap_db2, snap_seq);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // close snapshot handle
    status = fdb_kvs_close(snap_db);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // check snapshot's sequence number
    fdb_get_kvs_info(snap_db2, &kvs_info);
    TEST_CHK(kvs_info.last_seqnum == snap_seq);

    // insert documents from 15 - 19 on file into the WAL
    for (; i < n; i++){
        sprintf(keybuf, "key%d", i);
        sprintf(metabuf, "meta%d", i);
        sprintf(bodybuf, "body%d", i);
        fdb_doc_create(&doc[i], (void*)keybuf, strlen(keybuf),
            (void*)metabuf, strlen(metabuf), (void*)bodybuf, strlen(bodybuf));
        fdb_set(db, doc[i]);
    }
    // commit without a WAL flush (This WAL must not affect snapshot)
    fdb_commit(dbfile, FDB_COMMIT_NORMAL);

    // Clone the in-memory snapshot into another snapshot
    status = fdb_snapshot_open(snap_inmem, &snap_inmem2, FDB_SNAPSHOT_INMEM);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // Stable Snapshot Scan Tests..........
    // Retrieve metaonly by key from snapshot
    i = snap_seq + 1;
    fdb_doc_create(&rdoc, doc[i]->key, doc[i]->keylen, NULL, 0, NULL, 0);
    status = fdb_get_metaonly(snap_db2, rdoc);
    TEST_CHK(status == FDB_RESULT_KEY_NOT_FOUND);
    fdb_doc_free(rdoc);

    i = 5;
    fdb_doc_create(&rdoc, doc[i]->key, doc[i]->keylen, NULL, 0, NULL, 0);
    status = fdb_get_metaonly(snap_db2, rdoc);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    TEST_CMP(rdoc->key, doc[i]->key, doc[i]->keylen);
    TEST_CMP(rdoc->meta, doc[i]->meta, doc[i]->metalen);
    fdb_doc_free(rdoc);

    // Retrieve by seq from snapshot
    fdb_doc_create(&rdoc, NULL, 0, NULL, 0, NULL, 0);
    rdoc->seqnum = 6;
    status = fdb_get_byseq(snap_db2, rdoc);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    TEST_CMP(rdoc->key, doc[i]->key, rdoc->keylen);
    TEST_CMP(rdoc->body, doc[i]->body, rdoc->bodylen);
    fdb_doc_free(rdoc);
    rdoc = NULL;

    // create an iterator on the snapshot for full range
    fdb_iterator_init(snap_db2, &iterator, NULL, 0, NULL, 0, FDB_ITR_NONE);

    // repeat until fail
    i=0;
    count=0;
    do {
        status = fdb_iterator_get(iterator, &rdoc);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        TEST_CMP(rdoc->key, doc[i]->key, rdoc->keylen);
        TEST_CMP(rdoc->meta, doc[i]->meta, rdoc->metalen);
        TEST_CMP(rdoc->body, doc[i]->body, rdoc->bodylen);

        fdb_doc_free(rdoc);
        rdoc = NULL;
        i ++;
        count++;
    } while (fdb_iterator_next(iterator) == FDB_RESULT_SUCCESS);

    TEST_CHK(count==n/2); // Only unique items from the first half

    fdb_iterator_close(iterator);

    // create an iterator on the in-memory snapshot clone for full range
    fdb_iterator_init(snap_inmem2, &iterator, NULL, 0, NULL, 0, FDB_ITR_NONE);

    // repeat until fail
    i=0;
    count=0;
    do {
        status = fdb_iterator_get(iterator, &rdoc);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        TEST_CMP(rdoc->key, doc[i]->key, rdoc->keylen);
        TEST_CMP(rdoc->meta, doc[i]->meta, rdoc->metalen);
        TEST_CMP(rdoc->body, doc[i]->body, rdoc->bodylen);

        fdb_doc_free(rdoc);
        rdoc = NULL;
        i ++;
        count++;
    } while(fdb_iterator_next(iterator) == FDB_RESULT_SUCCESS);

    TEST_CHK(count==n/2); // Only unique items from the first half

    fdb_iterator_close(iterator);

    // close db handle
    fdb_kvs_close(db);
    // close the in-memory snapshot handle
    fdb_kvs_close(snap_inmem);
    // close the in-memory clone snapshot handle
    fdb_kvs_close(snap_inmem2);
    // close the clone snapshot handle
    fdb_kvs_close(snap_db2);
    // close db file
    fdb_close(dbfile);

    // free all documents
    for (i=0;i<n;++i){
        fdb_doc_free(doc[i]);
    }

    // free all resources
    fdb_shutdown();

    memleak_end();

    TEST_RESULT("snapshot clone test");
}

struct parallel_clone_t {
    fdb_doc **doc;
    fdb_kvs_handle *snap_db;
    int num_docs;
};

void *snap_clone_thread(void *args)
{
    struct parallel_clone_t *t = (struct parallel_clone_t *)args;
    fdb_kvs_handle *clone_db;
    fdb_iterator *iterator;
    fdb_doc *rdoc = NULL;
    fdb_doc **doc = t->doc;
    int i;
    int n = t->num_docs;
    fdb_status status;
    int count;
    TEST_INIT();

    status = fdb_snapshot_open(t->snap_db, &clone_db, FDB_SNAPSHOT_INMEM);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // create an iterator on the in-memory snapshot clone for full range
    fdb_iterator_init(clone_db, &iterator, NULL, 0, NULL, 0, FDB_ITR_NONE);

    // repeat until fail
    i=0;
    count=0;
    do {
        status = fdb_iterator_get(iterator, &rdoc);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        TEST_CMP(rdoc->key, doc[i]->key, rdoc->keylen);
        TEST_CMP(rdoc->body, doc[i]->body, rdoc->bodylen);

        fdb_doc_free(rdoc);
        rdoc = NULL;
        i ++;
        count++;
    } while(fdb_iterator_next(iterator) == FDB_RESULT_SUCCESS);

    TEST_CHK(count==n/2); // Only unique items from the first half

    fdb_iterator_close(iterator);

    fdb_kvs_close(clone_db);
    thread_exit(0);
    return NULL;
}

void snapshot_parallel_clone_test()
{
    TEST_INIT();

    memleak_start();

    int i, r;
    int num_cloners = 30; // parallel snapshot clone operations
    int n = 20480; // 10 dirty wal flushes at least
    fdb_file_handle *dbfile;
    fdb_kvs_handle *db;
    fdb_kvs_handle *snap_inmem;
    fdb_doc **doc = alca(fdb_doc*, n);
    thread_t *tid = alca(thread_t, num_cloners);
    void *thread_ret;
    fdb_status status;
    struct parallel_clone_t clone_data;

    char keybuf[256], bodybuf[256];

    // remove previous mvcc_test files
    r = system(SHELL_DEL" mvcc_test* > errorlog.txt");
    (void)r;

    fdb_config fconfig = fdb_get_default_config();
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    fconfig.buffercache_size = 0;
    fconfig.wal_threshold = 1024;
    fconfig.flags = FDB_OPEN_FLAG_CREATE;
    fconfig.compaction_threshold = 0;

    // remove previous mvcc_test files
    r = system(SHELL_DEL" mvcc_test* > errorlog.txt");
    (void)r;

    // open db
    status = fdb_open(&dbfile, "./mvcc_test1", &fconfig);
    fdb_kvs_open_default(dbfile, &db, &kvs_config);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    status = fdb_set_log_callback(db, logCallbackFunc,
                                  (void *) "snapshot_parallel_clone_test");
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    // ------- Setup test ----------------------------------
    for (i=0; i<n/2; i++){
        sprintf(keybuf, "key%5d", i);
        sprintf(bodybuf, "body%d", i);
        fdb_doc_create(&doc[i], (void*)keybuf, strlen(keybuf),
            NULL, 0, (void*)bodybuf, strlen(bodybuf));
        fdb_set(db, doc[i]);
    }

    // Initialize an in-memory snapshot Without a Commit...
    // WAL items are not flushed...
    status = fdb_snapshot_open(db, &snap_inmem, FDB_SNAPSHOT_INMEM);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    clone_data.doc = doc;
    clone_data.num_docs = n;
    clone_data.snap_db = snap_inmem;

    for (int j = num_cloners - 1; j>=0; --j) {
        thread_create(&tid[j], snap_clone_thread, &clone_data);
    }

    for (; i < n; i++){
        sprintf(keybuf, "key%5d", i);
        sprintf(bodybuf, "BODY%d", i);
        fdb_doc_create(&doc[i], (void*)keybuf, strlen(keybuf),
            NULL, 0, (void*)bodybuf, strlen(bodybuf));
        fdb_set(db, doc[i]);
    }
    // commit without a WAL flush (This WAL must not affect snapshot)
    fdb_commit(dbfile, FDB_COMMIT_NORMAL);

    for (int j = num_cloners - 1; j>=0; --j) {
        thread_join(tid[j], &thread_ret);
    }

    // close db handle
    fdb_kvs_close(db);
    // close the in-memory snapshot handle
    fdb_kvs_close(snap_inmem);
    // close db file
    fdb_close(dbfile);

    // free all documents
    for (i=0;i<n;++i){
        fdb_doc_free(doc[i]);
    }

    // free all resources
    fdb_shutdown();

    memleak_end();

    TEST_RESULT("snapshot parallel clone test");
}

void snapshot_markers_in_file_test(bool multi_kv)
{
    TEST_INIT();

    memleak_start();

    int i, r;
    int n = 20;
    int num_kvs = 4; // keep this the same as number of fdb_commit() calls
    fdb_file_handle *dbfile;
    fdb_kvs_handle **db = alca(fdb_kvs_handle *, num_kvs);
    fdb_doc **doc = alca(fdb_doc*, n);
    fdb_status status;
    fdb_snapshot_info_t *markers;
    uint64_t num_markers;

    char keybuf[256], metabuf[256], bodybuf[256];
    char kv_name[8];

    fdb_config fconfig = fdb_get_default_config();
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    fconfig.buffercache_size = 0;
    fconfig.wal_threshold = 1024;
    fconfig.flags = FDB_OPEN_FLAG_CREATE;
    fconfig.compaction_threshold = 0;
    fconfig.multi_kv_instances = multi_kv;
    // for creating the strict number of snapshots, disable block reusing
    fconfig.block_reusing_threshold = 0;

    // remove previous mvcc_test files
    r = system(SHELL_DEL" mvcc_test* > errorlog.txt");
    (void)r;

    // open db
    fdb_open(&dbfile, "./mvcc_test1", &fconfig);
    if (multi_kv) {
        for (r = 0; r < num_kvs; ++r) {
            sprintf(kv_name, "kv%d", r);
            fdb_kvs_open(dbfile, &db[r], kv_name, &kvs_config);
        }
    } else {
        num_kvs = 1;
        fdb_kvs_open_default(dbfile, &db[0], &kvs_config);
    }

   // ------- Setup test ----------------------------------
   // insert documents of 0-4
    for (i=0; i<n/4; i++){
        sprintf(keybuf, "key%d", i);
        sprintf(metabuf, "meta%d", i);
        sprintf(bodybuf, "body%d", i);
        fdb_doc_create(&doc[i], (void*)keybuf, strlen(keybuf),
            (void*)metabuf, strlen(metabuf), (void*)bodybuf, strlen(bodybuf));
        for (r = 0; r < num_kvs; ++r) {
            fdb_set(db[r], doc[i]);
        }
    }

    // commit with a manual WAL flush (these docs go into HB-trie)
    fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);

    // insert documents from 5 - 9
    for (; i < n/2; i++){
        sprintf(keybuf, "key%d", i);
        sprintf(metabuf, "meta%d", i);
        sprintf(bodybuf, "body%d", i);
        fdb_doc_create(&doc[i], (void*)keybuf, strlen(keybuf),
            (void*)metabuf, strlen(metabuf), (void*)bodybuf, strlen(bodybuf));
        for (r = 0; r < num_kvs; ++r) {
            fdb_set(db[r], doc[i]);
        }
    }

    // commit again without a WAL flush
    fdb_commit(dbfile, FDB_COMMIT_NORMAL);

    // insert documents from 10-14 into HB-trie
    for (; i < (n/2 + n/4); i++){
        sprintf(keybuf, "key%d", i);
        sprintf(metabuf, "meta%d", i);
        sprintf(bodybuf, "body%d", i);
        fdb_doc_create(&doc[i], (void*)keybuf, strlen(keybuf),
            (void*)metabuf, strlen(metabuf), (void*)bodybuf, strlen(bodybuf));
        for (r = 0; r < num_kvs; ++r) {
            fdb_set(db[r], doc[i]);
        }
    }
    // manually flush WAL & commit
    fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);

    // insert documents from 15 - 19 on file into the WAL
    for (; i < n; i++){
        sprintf(keybuf, "key%d", i);
        sprintf(metabuf, "meta%d", i);
        sprintf(bodybuf, "body%d", i);
        fdb_doc_create(&doc[i], (void*)keybuf, strlen(keybuf),
            (void*)metabuf, strlen(metabuf), (void*)bodybuf, strlen(bodybuf));
        for (r = 0; r < num_kvs; ++r) {
            fdb_set(db[r], doc[i]);
        }
    }
    // commit without a WAL flush
    fdb_commit(dbfile, FDB_COMMIT_NORMAL);

    for (r = 0; r < num_kvs; ++r) {
        status = fdb_set_log_callback(db[r], logCallbackFunc,
                                      (void *) "snapshot_markers_in_file");
        TEST_CHK(status == FDB_RESULT_SUCCESS);
    }

    status = fdb_get_all_snap_markers(dbfile, &markers, &num_markers);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    if (!multi_kv) {
        TEST_CHK(num_markers == 5);
        for (r = 0; r < num_kvs; ++r) {
            TEST_CHK(markers[r].num_kvs_markers == 1);
            TEST_CHK(markers[r].kvs_markers[0].seqnum
                     == (fdb_seqnum_t)(n - r*5));
        }
    } else {
        TEST_CHK(num_markers == 9);
        for (r = 0; r < num_kvs; ++r) {
            TEST_CHK(markers[r].num_kvs_markers == num_kvs);
            for (i = 0; i < num_kvs; ++i) {
                TEST_CHK(markers[r].kvs_markers[i].seqnum
                         == (fdb_seqnum_t)(n - r*5));
                sprintf(kv_name, "kv%d", i);
                TEST_CMP(markers[r].kvs_markers[i].kv_store_name, kv_name, 3);
            }
        }
    }

    status = fdb_free_snap_markers(markers, num_markers);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // close db file
    fdb_close(dbfile);

    // free all documents
    for (i=0;i<n;++i){
        fdb_doc_free(doc[i]);
    }

    // free all resources
    fdb_shutdown();

    memleak_end();

    sprintf(bodybuf, "snapshot markers in file test %s", multi_kv ?
                                                        "multiple kv mode:"
                                                      : "single kv mode:");
    TEST_RESULT(bodybuf);
}

void snapshot_without_seqtree(bool multi_kv)
{
    TEST_INIT();

    memleak_start();

    int i, j, r;
    int n = 10;
    int num_commits = 3, num_kvs = 3;
    fdb_file_handle *dbfile;
    fdb_kvs_handle **db = alca(fdb_kvs_handle *, num_kvs);
    fdb_doc **doc = alca(fdb_doc*, n);
    fdb_status status;
    fdb_snapshot_info_t *markers;
    uint64_t num_markers;

    char keybuf[256], metabuf[256], bodybuf[256];
    char kv_name[8];

    fdb_config fconfig = fdb_get_default_config();
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    fconfig.flags = FDB_OPEN_FLAG_CREATE;
    fconfig.multi_kv_instances = multi_kv;
    // for creating the strict number of snapshots, disable block reusing
    fconfig.block_reusing_threshold = 0;
    fconfig.seqtree_opt = FDB_SEQTREE_NOT_USE;

    // remove previous mvcc_test files
    r = system(SHELL_DEL" mvcc_test* > errorlog.txt");
    (void)r;

    // open db
    fdb_open(&dbfile, "./mvcc_test1", &fconfig);
    if (multi_kv) {
        for (r = 0; r < num_kvs; ++r) {
            sprintf(kv_name, "kv%d", r);
            fdb_kvs_open(dbfile, &db[r], kv_name, &kvs_config);
        }
    } else {
        num_kvs = 1;
        fdb_kvs_open_default(dbfile, &db[0], &kvs_config);
    }

    // Load documents mulitple times
    for (j=0; j < num_commits; ++j) {
        for (i=0; i<n; i++){
            sprintf(keybuf, "key%d", i);
            sprintf(metabuf, "meta-%d-%d", j, i);
            sprintf(bodybuf, "body-%d-%d", j, i);
            fdb_doc_create(&doc[i], (void*)keybuf, strlen(keybuf),
                           (void*)metabuf, strlen(metabuf), (void*)bodybuf, strlen(bodybuf));
            for (r = 0; r < num_kvs; ++r) {
                fdb_set(db[r], doc[i]);
            }
            fdb_doc_free(doc[i]);
        }
        if (j % 2 == 0) {
            fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);
        } else {
            fdb_commit(dbfile, FDB_COMMIT_NORMAL);
        }
    }

    status = fdb_get_all_snap_markers(dbfile, &markers, &num_markers);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    if (!multi_kv) {
        TEST_CHK(num_markers == 4);
        for (r = 0; r < num_kvs; ++r) {
            TEST_CHK(markers[r].num_kvs_markers == 1);
            TEST_CHK(markers[r].kvs_markers[0].seqnum
                     == (fdb_seqnum_t) (n * (num_commits - r)));
        }
    } else {
        TEST_CHK(num_markers == 7);
        for (r = 0; r < num_kvs; ++r) {
            TEST_CHK(markers[r].num_kvs_markers == num_kvs);
            for (i = 0; i < num_kvs; ++i) {
                TEST_CHK(markers[r].kvs_markers[i].seqnum
                         == (fdb_seqnum_t) (n * (num_commits - r)));
                sprintf(kv_name, "kv%d", i);
                TEST_CMP(markers[r].kvs_markers[i].kv_store_name, kv_name, 3);
            }
        }
    }

    fdb_kvs_handle *snap_db;
    fdb_iterator *iterator;
    fdb_doc *rdoc = NULL;
    // Open the snapshot with the snapshot markers from the second commit
    for (r = 0; r < num_kvs; ++r) {
        status = fdb_snapshot_open(db[r], &snap_db, markers[1].kvs_markers[r].seqnum);
        TEST_CHK(status == FDB_RESULT_SUCCESS);

        // Verify all the keys in the snapshot
        status = fdb_iterator_init(snap_db, &iterator, NULL, 0, NULL, 0, FDB_ITR_NONE);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        i=0;
        do {
            status = fdb_iterator_get(iterator, &rdoc);
            TEST_CHK(status == FDB_RESULT_SUCCESS);
            sprintf(keybuf, "key%d", i);
            sprintf(metabuf, "meta-1-%d", i);
            sprintf(bodybuf, "body-1-%d", i);
            TEST_CMP(rdoc->key, keybuf, rdoc->keylen);
            TEST_CMP(rdoc->meta, metabuf, rdoc->metalen);
            TEST_CMP(rdoc->body, bodybuf, rdoc->bodylen);
            fdb_doc_free(rdoc);
            rdoc = NULL;
            i++;
        } while (fdb_iterator_next(iterator) != FDB_RESULT_ITERATOR_FAIL);
        TEST_CHK(i==n);
        status = fdb_iterator_close(iterator);
        TEST_CHK(status == FDB_RESULT_SUCCESS);

        // Verify that a sequence-based iteration is not allowed.
        status = fdb_iterator_sequence_init(snap_db, &iterator, 0, 0, FDB_ITR_NONE);
        TEST_CHK(status != FDB_RESULT_SUCCESS);

        status = fdb_kvs_close(snap_db);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
    }

    status = fdb_free_snap_markers(markers, num_markers);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // close db file
    fdb_close(dbfile);

    // free all resources
    fdb_shutdown();

    memleak_end();

    sprintf(bodybuf, "snapshot without seqtree in %s",
            multi_kv ? "multiple kv mode:" : "single kv mode:");
    TEST_RESULT(bodybuf);
}

void snapshot_with_deletes_test()
{
    TEST_INIT();

    memleak_start();

    int i, r;
    int n = 10;
    fdb_file_handle *dbfile;
    fdb_kvs_handle *db;
    fdb_kvs_handle *snap_db;
    fdb_doc **doc = alca(fdb_doc*, n);
    fdb_doc *rdoc = NULL;
    fdb_kvs_info kvs_info;
    fdb_status status;
    fdb_iterator *iterator;

    char keybuf[256], metabuf[256], bodybuf[256];

    // remove previous mvcc_test files
    r = system(SHELL_DEL" mvcc_test* > errorlog.txt");
    (void)r;

    fdb_config fconfig = fdb_get_default_config();
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    fconfig.buffercache_size = 0;

    // remove previous mvcc_test files
    r = system(SHELL_DEL" mvcc_test* > errorlog.txt");
    (void)r;

    // open db
    status = fdb_open(&dbfile, "./mvcc_test1", &fconfig);
    fdb_kvs_open_default(dbfile, &db, &kvs_config);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    status = fdb_set_log_callback(db, logCallbackFunc,
                                  (void *) "snapshot_with_deletes_test");
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // ------- Setup test ----------------------------------
    // insert even documents into main index
    for (i=0; i<n; i = i + 2){
        sprintf(keybuf, "key%d", i);
        sprintf(metabuf, "meta%d", i);
        sprintf(bodybuf, "body%d", i);
        fdb_doc_create(&doc[i], (void*)keybuf, strlen(keybuf),
            (void*)metabuf, strlen(metabuf), (void*)bodybuf, strlen(bodybuf));
        fdb_set(db, doc[i]);
    }

    i = 7;
    sprintf(keybuf, "key%d", i);
    fdb_set_kv(db, keybuf, strlen(keybuf), NULL, 0);

    // commit with a manual WAL flush (these docs go into HB-trie)
    fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);

    // let odd documents be in WAL section
    for (i = 1; i < n; i = i + 2){
        sprintf(keybuf, "key%d", i);
        sprintf(metabuf, "meta%d", i);
        sprintf(bodybuf, "body%d", i);
        fdb_doc_create(&doc[i], (void*)keybuf, strlen(keybuf),
            (void*)metabuf, strlen(metabuf), (void*)bodybuf, strlen(bodybuf));
        fdb_set(db, doc[i]);
    }

    // Delete WAL doc 7
    i = 7;
    fdb_del(db, doc[i]);

    // Create an iterator on the live DB over full range
    fdb_iterator_init(db, &iterator, NULL, 0, NULL, 0, FDB_ITR_NONE);

    // attempt to seek to the deleted key7
    status = fdb_iterator_seek(iterator, doc[i]->key, doc[i]->keylen,
                               FDB_ITR_SEEK_HIGHER);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_iterator_get(iterator, &rdoc);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    i = 8; // The next higher document must be returned
    TEST_CMP(rdoc->key, doc[i]->key, rdoc->keylen);
    TEST_CMP(rdoc->meta, doc[i]->meta, rdoc->metalen);
    TEST_CMP(rdoc->body, doc[i]->body, rdoc->bodylen);

    fdb_doc_free(rdoc);
    rdoc = NULL;

    fdb_iterator_close(iterator);

    // Open an in-memory snapshot over live DB
    status = fdb_snapshot_open(db, &snap_db, FDB_SNAPSHOT_INMEM);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // check snapshot's sequence number
    fdb_get_kvs_info(snap_db, &kvs_info);
    TEST_CHK(kvs_info.last_seqnum == (fdb_seqnum_t)n+2);
    TEST_CHK(kvs_info.deleted_count == 1);

    // re-create an iterator on the snapshot for full range
    fdb_iterator_init(snap_db, &iterator, NULL, 0, NULL, 0, FDB_ITR_NONE);

    i = 7;
    // attempt to seek to the deleted key7
    status = fdb_iterator_seek(iterator, doc[i]->key, doc[i]->keylen,
                               FDB_ITR_SEEK_HIGHER);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_iterator_get(iterator, &rdoc);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    i = 8; // The next higher document must be returned
    TEST_CMP(rdoc->key, doc[i]->key, rdoc->keylen);
    TEST_CMP(rdoc->meta, doc[i]->meta, rdoc->metalen);
    TEST_CMP(rdoc->body, doc[i]->body, rdoc->bodylen);

    fdb_doc_free(rdoc);
    rdoc = NULL;

    fdb_iterator_close(iterator);

    // close db handle
    fdb_kvs_close(db);
    // close snapshot handle
    fdb_kvs_close(snap_db);
    // close db file
    fdb_close(dbfile);

    // free all documents
    for (i=0;i<n;++i){
        fdb_doc_free(doc[i]);
    }

    // free all resources
    fdb_shutdown();

    memleak_end();

    TEST_RESULT("snapshot with deletes test");
}

void rollback_forward_seqnum()
{

    TEST_INIT();
    memleak_start();

    int r;
    int i, n=100;
    int rb1_seqnum, rb2_seqnum;
    char keybuf[256];
    char setop[3];
    fdb_file_handle *dbfile;
    fdb_iterator *it;
    fdb_kvs_handle *kv1, *mirror_kv1;
    fdb_kvs_info info;
    fdb_config fconfig = fdb_get_default_config();
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    fdb_doc **doc = alca(fdb_doc*, n+1);
    fdb_doc *rdoc = NULL;
    fdb_status status;
    r = system(SHELL_DEL" mvcc_test* > errorlog.txt");
    (void)r;

    fconfig.wal_threshold = n;
    fconfig.seqtree_opt = FDB_SEQTREE_USE; // enable seqtree since get_byseq
    fconfig.flags = FDB_OPEN_FLAG_CREATE;
    fconfig.compaction_threshold = 0;
    fconfig.purging_interval = 5;
    fconfig.block_reusing_threshold = 0;

    fdb_open(&dbfile, "./mvcc_test1", &fconfig);
    fdb_kvs_open(dbfile, &kv1, "kv1", &kvs_config);
    fdb_kvs_open(dbfile, &mirror_kv1, NULL, &kvs_config);


    // set n docs within both dbs
    for(i=0;i<=n;++i){
        sprintf(keybuf, "key%d", i);
        fdb_doc_create(&doc[i], (void*)keybuf, strlen(keybuf),
            NULL, 0, NULL, 0);
        fdb_set(kv1, doc[i]);
        fdb_set_kv(mirror_kv1, keybuf, strlen(keybuf), setop, 3);
    } // last set should have caused a wal flush

    fdb_del(kv1, doc[n]);

    // commit and save seqnum1
    fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);
    fdb_get_kvs_info(kv1, &info);
    rb1_seqnum = info.last_seqnum;

    // delete all docs in kv1
    for(i=0;i<n;++i){
        fdb_del(kv1, doc[i]);
    }

    // commit and save seqnum2
    fdb_commit(dbfile, FDB_COMMIT_NORMAL);
    fdb_get_kvs_info(kv1, &info);
    rb2_seqnum = info.last_seqnum;

    // sets again
    for(i=0;i<n;++i){
        doc[i]->deleted = false;
        fdb_set(kv1, doc[i]);
    }

    // commit
    fdb_commit(dbfile, FDB_COMMIT_NORMAL);

    // rollback to first seqnum
    status = fdb_rollback(&kv1, rb1_seqnum);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    fdb_get_kvs_info(kv1, &info);
    TEST_CHK(info.deleted_count == 1);

    // rollback to second seqnum
    status = fdb_rollback(&kv1, rb2_seqnum);
    TEST_CHK(status == FDB_RESULT_NO_DB_INSTANCE);

    status = fdb_iterator_sequence_init(mirror_kv1, &it, 0, 0, FDB_ITR_NONE);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    do {
        status = fdb_iterator_get(it, &rdoc);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        if (rdoc->seqnum != (uint64_t)n+1) {
            status = fdb_get_metaonly_byseq(kv1, rdoc);
            TEST_CHK(status == FDB_RESULT_SUCCESS);
            TEST_CHK(rdoc->deleted == false);
        } else {
            status = fdb_get_metaonly(kv1, rdoc);
            TEST_CHK(status == FDB_RESULT_SUCCESS);
            TEST_CHK(rdoc->deleted == true);
        }
        fdb_doc_free(rdoc);
        rdoc = NULL;
    } while(fdb_iterator_next(it) != FDB_RESULT_ITERATOR_FAIL);

    for (i=0;i<=n;++i){
        fdb_doc_free(doc[i]);
    }
    fdb_iterator_close(it);
    fdb_kvs_close(kv1);
    fdb_close(dbfile);
    fdb_shutdown();
    memleak_end();

    TEST_RESULT("rollback forward seqnum");
}

void rollback_test(bool multi_kv)
{
    TEST_INIT();

    memleak_start();

    int i, r;
    int n = 20;
    int count;
    fdb_file_handle *dbfile, *dbfile_txn;
    fdb_kvs_handle *db, *db_txn;
    fdb_seqnum_t rollback_seq;
    fdb_doc **doc = alca(fdb_doc*, n);
    fdb_doc *rdoc = NULL;
    fdb_kvs_info kvs_info;
    fdb_status status;
    fdb_iterator *iterator;

    char keybuf[256], metabuf[256], bodybuf[256];

    // remove previous mvcc_test files
    r = system(SHELL_DEL" mvcc_test* > errorlog.txt");
    (void)r;

    fdb_config fconfig = fdb_get_default_config();
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    fconfig.buffercache_size = 0;
    fconfig.seqtree_opt = FDB_SEQTREE_USE; // enable seqtree since get_byseq
    fconfig.wal_threshold = 1024;
    fconfig.flags = FDB_OPEN_FLAG_CREATE;
    fconfig.compaction_threshold = 0;
    fconfig.multi_kv_instances = multi_kv;

    // remove previous mvcc_test files
    r = system(SHELL_DEL" mvcc_test* > errorlog.txt");
    (void)r;

    // open db
    fdb_open(&dbfile, "./mvcc_test1", &fconfig);
    if (multi_kv) {
        fdb_kvs_open_default(dbfile, &db, &kvs_config);
    } else {
        fdb_kvs_open(dbfile, &db, NULL, &kvs_config);
    }

   // ------- Setup test ----------------------------------
   // insert documents of 0-4
    for (i=0; i<n/4; i++){
        sprintf(keybuf, "key%d", i);
        sprintf(metabuf, "meta%d", i);
        sprintf(bodybuf, "body%d", i);
        fdb_doc_create(&doc[i], (void*)keybuf, strlen(keybuf),
            (void*)metabuf, strlen(metabuf), (void*)bodybuf, strlen(bodybuf));
        fdb_set(db, doc[i]);
    }

    // commit with a manual WAL flush (these docs go into HB-trie)
    fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);

    // insert documents from 4 - 9
    for (; i < n/2; i++){
        sprintf(keybuf, "key%d", i);
        sprintf(metabuf, "meta%d", i);
        sprintf(bodybuf, "body%d", i);
        fdb_doc_create(&doc[i], (void*)keybuf, strlen(keybuf),
            (void*)metabuf, strlen(metabuf), (void*)bodybuf, strlen(bodybuf));
        fdb_set(db, doc[i]);
    }

    // commit again without a WAL flush
    fdb_commit(dbfile, FDB_COMMIT_NORMAL);

    // ROLLBACK POINT: pick up sequence number of a commit without a WAL flush
    rollback_seq = doc[i-1]->seqnum;

    // insert documents from 10-14 into HB-trie
    for (; i < (n/2 + n/4); i++){
        sprintf(keybuf, "key%d", i);
        sprintf(metabuf, "meta%d", i);
        sprintf(bodybuf, "body%d", i);
        fdb_doc_create(&doc[i], (void*)keybuf, strlen(keybuf),
            (void*)metabuf, strlen(metabuf), (void*)bodybuf, strlen(bodybuf));
        fdb_set(db, doc[i]);
    }
    // manually flush WAL & commit
    fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);

    // insert documents from 15 - 19 on file into the WAL
    for (; i < n; i++){
        sprintf(keybuf, "key%d", i);
        sprintf(metabuf, "meta%d", i);
        sprintf(bodybuf, "body%d", i);
        fdb_doc_create(&doc[i], (void*)keybuf, strlen(keybuf),
            (void*)metabuf, strlen(metabuf), (void*)bodybuf, strlen(bodybuf));
        fdb_set(db, doc[i]);
    }
    // commit without a WAL flush
    fdb_commit(dbfile, FDB_COMMIT_NORMAL);

    status = fdb_set_log_callback(db, logCallbackFunc,
                                  (void *) "rollback_test");
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // ---------- Rollback tests begin -----------------------
    // We have DB file with 5 HB-trie docs, 5 unflushed WAL docs occuring twice
    // Attempt to rollback to out-of-range marker..
    status = fdb_rollback(&db, 999999);
    TEST_CHK(status == FDB_RESULT_NO_DB_INSTANCE);

    // Open another handle & begin transaction
    fdb_open(&dbfile_txn, "./mvcc_test1", &fconfig);
    if (multi_kv) {
        fdb_kvs_open_default(dbfile_txn, &db_txn, &kvs_config);
    } else {
        fdb_kvs_open(dbfile_txn, &db_txn, NULL, &kvs_config);
    }
    fdb_begin_transaction(dbfile_txn, FDB_ISOLATION_READ_COMMITTED);
    // Attempt to rollback while the transaction is active
    status =  fdb_rollback(&db, rollback_seq);
    // Must fail
    TEST_CHK(status == FDB_RESULT_FAIL_BY_TRANSACTION);
    fdb_abort_transaction(dbfile_txn);
    fdb_kvs_close(db_txn);
    fdb_close(dbfile_txn);

    // Rollback to saved marker from above
    status = fdb_rollback(&db, rollback_seq);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // check handle's sequence number
    fdb_get_kvs_info(db, &kvs_info);
    TEST_CHK(kvs_info.last_seqnum == rollback_seq);

    // Modify an item and update into the rollbacked file..
    i = n/2;
    *(char *)doc[i]->body = 'B';
    fdb_set(db, doc[i]);
    fdb_commit(dbfile, FDB_COMMIT_NORMAL);

    // create an iterator on the rollback for full range
    fdb_iterator_sequence_init(db, &iterator, 0, 0, FDB_ITR_NONE);

    // repeat until fail
    i=0;
    count=0;
    do {
        status = fdb_iterator_get(iterator, &rdoc);
        TEST_CHK(status == FDB_RESULT_SUCCESS);

        TEST_CMP(rdoc->key, doc[i]->key, rdoc->keylen);
        TEST_CMP(rdoc->meta, doc[i]->meta, rdoc->metalen);
        TEST_CMP(rdoc->body, doc[i]->body, rdoc->bodylen);

        fdb_doc_free(rdoc);
        rdoc = NULL;
        i ++;
        count++;
    } while (fdb_iterator_next(iterator) != FDB_RESULT_ITERATOR_FAIL);

    TEST_CHK(count==n/2 + 1); // Items from first half and newly set item

    fdb_iterator_close(iterator);

    // close db file
    fdb_kvs_close(db);
    fdb_close(dbfile);

    // free all documents
    for (i=0;i<n;++i){
        fdb_doc_free(doc[i]);
    }

    // free all resources
    fdb_shutdown();

    memleak_end();

    sprintf(bodybuf, "rollback test %s", multi_kv ? "multiple kv mode:"
                                                  : "single kv mode:");
    TEST_RESULT(bodybuf);
}



void rollback_and_snapshot_test()
{
    TEST_INIT();

    memleak_start();

    fdb_seqnum_t seqnum, rollback_seqnum;
    fdb_kvs_info kvs_info;
    fdb_status status;
    fdb_config config;
    fdb_kvs_config kvs_config;
    fdb_file_handle *dbfile;
    fdb_kvs_handle *db,  *snapshot;
    int r;

    // remove previous mvcc_test files
    r = system(SHELL_DEL" mvcc_test* > errorlog.txt");
    (void)r;

    // MB-12530 open db
    config = fdb_get_default_config();
    kvs_config = fdb_get_default_kvs_config();
    status = fdb_open(&dbfile, "mvcc_test", &config);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_kvs_open(dbfile, &db, NULL, &kvs_config);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // 2. Create Key 'a' and Commit
    status = fdb_set_kv(db, (void *) "a", 1, (void *)"val-a", 5);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_commit(dbfile, FDB_COMMIT_NORMAL);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    status = fdb_get_kvs_info(db, &kvs_info);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // 3. Create Key 'b' and Commit
    status = fdb_set_kv(db, (void *)"b", 1, (void *)"val-b", 5);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_commit(dbfile, FDB_COMMIT_NORMAL);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    status = fdb_get_kvs_info(db, &kvs_info);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    seqnum = kvs_info.last_seqnum;

    // 4.  Remember this as our rollback point
    rollback_seqnum = seqnum;

    // 5. Create Key 'c' and Commit
    status = fdb_set_kv(db, (void *)"c", 1,(void *) "val-c", 5);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_commit(dbfile, FDB_COMMIT_NORMAL);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    status = fdb_get_kvs_info(db, &kvs_info);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // 6. Rollback to rollback point (seq 2)
    status = fdb_rollback(&db, rollback_seqnum);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    status = fdb_get_kvs_info(db, &kvs_info);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    seqnum = kvs_info.last_seqnum;

    // 7. Verify that Key 'c' is not found
    void *val;
    size_t vallen;
    status = fdb_get_kv(db, (void *)"c", 1, &val, &vallen);
    TEST_CHK(status == FDB_RESULT_KEY_NOT_FOUND);

    // 8. Open a snapshot at the same point
    status = fdb_snapshot_open(db, &snapshot, seqnum);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // 9. Verify that Key 'c' is not found
    status = fdb_get_kv(snapshot, (void *)"c", 1, &val, &vallen);
    TEST_CHK(status == FDB_RESULT_KEY_NOT_FOUND);

    // close the snapshot db
    fdb_kvs_close(snapshot);

    // close db file
    fdb_close(dbfile);

    // free all resources
    fdb_shutdown();

    memleak_end();

    TEST_RESULT("rollback and snapshot test");
}

void rollback_ncommits()
{

    TEST_INIT();
    memleak_start();

    int r;
    int i, j, n=100;
    int ncommits=10;
    char keybuf[256];
    fdb_file_handle *dbfile;
    fdb_kvs_handle *kv1, *kv2;
    fdb_kvs_info info;
    fdb_config fconfig = fdb_get_default_config();
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    fdb_status status;
    r = system(SHELL_DEL" mvcc_test* > errorlog.txt");
    (void)r;

    fconfig.wal_threshold = 1024;
    fconfig.flags = FDB_OPEN_FLAG_CREATE;
    fconfig.compaction_threshold = 0;
    fconfig.block_reusing_threshold = 0;

    fdb_open(&dbfile, "./mvcc_test1", &fconfig);
    fdb_kvs_open(dbfile, &kv1, "kv1", &kvs_config);
    fdb_kvs_open(dbfile, &kv2, NULL, &kvs_config);


    for(j=0;j<ncommits;++j){

        // set n docs per commit
        for(i=0;i<n;++i){
            sprintf(keybuf, "key%02d%03d", j, i);
            fdb_set_kv(kv1, keybuf, strlen(keybuf), NULL, 0);
            fdb_set_kv(kv2, keybuf, strlen(keybuf), NULL, 0);
        }
        // alternate commit pattern
        if((j % 2) == 0){
            fdb_commit(dbfile, FDB_COMMIT_NORMAL);
        } else {
            fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);
        }

        // doc_count should match seqnum since they are unique
        fdb_get_kvs_info(kv1, &info);
        TEST_CHK(info.doc_count == info.last_seqnum);
    }

    // iteratively rollback 5 commits
     for(j=ncommits;j>0;--j){
        status = fdb_rollback(&kv1, j*n);
        TEST_CHK(status == FDB_RESULT_SUCCESS);

        // check rollback doc_count
        fdb_get_kvs_info(kv1, &info);
        TEST_CHK(info.doc_count == info.last_seqnum);
    }

    fdb_kvs_close(kv1);
    fdb_close(dbfile);
    fdb_shutdown();
    memleak_end();

    TEST_RESULT("rollback n commits");
}

void transaction_test()
{
    TEST_INIT();

    memleak_start();

    int i, r;
    int n = 10;
    fdb_file_handle *dbfile, *dbfile_txn1, *dbfile_txn2, *dbfile_txn3;
    fdb_kvs_handle *db, *db_txn1, *db_txn2, *db_txn3;
    fdb_doc **doc = alca(fdb_doc*, n);
    fdb_doc *rdoc;
    fdb_status status;

    char keybuf[256], metabuf[256], bodybuf[256];

    // remove previous mvcc_test files
    r = system(SHELL_DEL" mvcc_test* > errorlog.txt");
    (void)r;

    fdb_config fconfig = fdb_get_default_config();
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    fconfig.buffercache_size = 0;
    fconfig.wal_threshold = 1024;
    fconfig.flags = FDB_OPEN_FLAG_CREATE;
    fconfig.purging_interval = 0;
    fconfig.compaction_threshold = 0;

    // open db
    fdb_open(&dbfile, "mvcc_test1", &fconfig);
    fdb_kvs_open_default(dbfile, &db, &kvs_config);
    status = fdb_set_log_callback(db, logCallbackFunc,
                                  (void *) "transaction_test");
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // open db and begin transactions
    fdb_open(&dbfile_txn1, "mvcc_test1", &fconfig);
    fdb_open(&dbfile_txn2, "mvcc_test1", &fconfig);
    fdb_kvs_open_default(dbfile_txn1, &db_txn1, &kvs_config);
    fdb_kvs_open_default(dbfile_txn2, &db_txn2, &kvs_config);
    fdb_begin_transaction(dbfile_txn1, FDB_ISOLATION_READ_COMMITTED);
    fdb_begin_transaction(dbfile_txn2, FDB_ISOLATION_READ_COMMITTED);

    // insert half docs into txn1
    for (i=0;i<n/2;++i){
        sprintf(keybuf, "key%d", i);
        sprintf(metabuf, "meta%d", i);
        sprintf(bodybuf, "body%d", i);
        fdb_doc_create(&doc[i], (void*)keybuf, strlen(keybuf),
                                (void*)metabuf, strlen(metabuf),
                                (void*)bodybuf, strlen(bodybuf));
        fdb_set(db_txn1, doc[i]);
    }

    // insert other half docs into txn2
    for (i=n/2;i<n;++i){
        sprintf(keybuf, "key%d", i);
        sprintf(metabuf, "meta%d", i);
        sprintf(bodybuf, "body%d", i);
        fdb_doc_create(&doc[i], (void*)keybuf, strlen(keybuf),
                                (void*)metabuf, strlen(metabuf),
                                (void*)bodybuf, strlen(bodybuf));
        fdb_set(db_txn2, doc[i]);
    }

    // uncommitted docs should not be read by the other transaction that
    // doesn't allow uncommitted reads.
    for (i=0;i<n;++i){
        sprintf(keybuf, "key%d", i);
        fdb_doc_create(&rdoc, (void*)keybuf, strlen(keybuf), NULL, 0, NULL, 0);
        status = fdb_get(db_txn1, rdoc);
        if (i<n/2) {
            TEST_CHK(status == FDB_RESULT_SUCCESS);
        } else {
            TEST_CHK(status != FDB_RESULT_SUCCESS);
        }
        fdb_doc_free(rdoc);
    }

    // uncommitted docs can be read by the transaction that allows uncommitted reads.
    fdb_open(&dbfile_txn3, "mvcc_test1", &fconfig);
    fdb_kvs_open_default(dbfile_txn3, &db_txn3, &kvs_config);
    fdb_begin_transaction(dbfile_txn3, FDB_ISOLATION_READ_UNCOMMITTED);
    for (i=0;i<n;++i){
        sprintf(keybuf, "key%d", i);
        fdb_doc_create(&rdoc, (void*)keybuf, strlen(keybuf), NULL, 0, NULL, 0);
        status = fdb_get(db_txn3, rdoc);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        fdb_doc_free(rdoc);
    }
    fdb_end_transaction(dbfile_txn3, FDB_COMMIT_NORMAL);
    fdb_close(dbfile_txn3);

    // commit and end txn1
    fdb_end_transaction(dbfile_txn1, FDB_COMMIT_NORMAL);

    // uncommitted docs should not be read generally
    for (i=0;i<n;++i){
        sprintf(keybuf, "key%d", i);
        fdb_doc_create(&rdoc, (void*)keybuf, strlen(keybuf), NULL, 0, NULL, 0);
        status = fdb_get(db, rdoc);
        if (i<n/2) {
            TEST_CHK(status == FDB_RESULT_SUCCESS);
        } else {
            TEST_CHK(status != FDB_RESULT_SUCCESS);
        }
        fdb_doc_free(rdoc);
    }

    // read uncommitted docs using the same transaction
    for (i=0;i<n;++i){
        sprintf(keybuf, "key%d", i);
        fdb_doc_create(&rdoc, (void*)keybuf, strlen(keybuf), NULL, 0, NULL, 0);
        status = fdb_get(db_txn2, rdoc);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        fdb_doc_free(rdoc);
    }

    // abort txn2
    fdb_abort_transaction(dbfile_txn2);

    // close & re-open db file
    fdb_close(dbfile);
    fdb_open(&dbfile, "mvcc_test1", &fconfig);
    fdb_kvs_open_default(dbfile, &db, &kvs_config);
    status = fdb_set_log_callback(db, logCallbackFunc,
                                  (void *) "transaction_test");
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // uncommitted docs should not be read after reopening the file either
    for (i=0;i<n;++i){
        sprintf(keybuf, "key%d", i);
        fdb_doc_create(&rdoc, (void*)keybuf, strlen(keybuf), NULL, 0, NULL, 0);
        status = fdb_get(db, rdoc);
        if (i<n/2) {
            TEST_CHK(status == FDB_RESULT_SUCCESS);
        } else {
            TEST_CHK(status != FDB_RESULT_SUCCESS);
        }
        fdb_doc_free(rdoc);
    }

    // insert other half docs & commit
    for (i=n/2;i<n;++i){
        fdb_set(db, doc[i]);
    }
    fdb_commit(dbfile, FDB_COMMIT_NORMAL);

    // now all docs can be read generally
    for (i=0;i<n;++i){
        sprintf(keybuf, "key%d", i);
        fdb_doc_create(&rdoc, (void*)keybuf, strlen(keybuf), NULL, 0, NULL, 0);
        status = fdb_get(db, rdoc);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        fdb_doc_free(rdoc);
    }

    // begin transactions
    fdb_begin_transaction(dbfile_txn1, FDB_ISOLATION_READ_COMMITTED);
    fdb_begin_transaction(dbfile_txn2, FDB_ISOLATION_READ_COMMITTED);

    // concurrently update docs
    for (i=0;i<n;++i){
        sprintf(keybuf, "key%d", i);
        sprintf(metabuf, "meta%d", i);
        sprintf(bodybuf, "body%d_txn1", i);
        fdb_doc_create(&rdoc, (void*)keybuf, strlen(keybuf),
                                (void*)metabuf, strlen(metabuf),
                                (void*)bodybuf, strlen(bodybuf));
        fdb_set(db_txn1, rdoc);
        fdb_doc_free(rdoc);

        sprintf(bodybuf, "body%d_txn2", i);
        fdb_doc_create(&rdoc, (void*)keybuf, strlen(keybuf),
                                (void*)metabuf, strlen(metabuf),
                                (void*)bodybuf, strlen(bodybuf));
        fdb_set(db_txn2, rdoc);
        fdb_doc_free(rdoc);
    }

    // retrieve check
    for (i=0;i<n;++i){
        // general retrieval
        sprintf(keybuf, "key%d", i);
        fdb_doc_create(&rdoc, (void*)keybuf, strlen(keybuf), NULL, 0, NULL, 0);
        status = fdb_get(db, rdoc);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        TEST_CMP(rdoc->body, doc[i]->body, rdoc->bodylen);
        fdb_doc_free(rdoc);

        // get from txn1
        fdb_doc_create(&rdoc, (void*)keybuf, strlen(keybuf), NULL, 0, NULL, 0);
        status = fdb_get(db_txn1, rdoc);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        sprintf(bodybuf, "body%d_txn1", i);
        TEST_CMP(rdoc->body, bodybuf, rdoc->bodylen);
        fdb_doc_free(rdoc);

        // get from txn2
        fdb_doc_create(&rdoc, (void*)keybuf, strlen(keybuf), NULL, 0, NULL, 0);
        status = fdb_get(db_txn2, rdoc);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        sprintf(bodybuf, "body%d_txn2", i);
        TEST_CMP(rdoc->body, bodybuf, rdoc->bodylen);
        fdb_doc_free(rdoc);
    }

    // commit txn2 & retrieve check
    fdb_end_transaction(dbfile_txn2, FDB_COMMIT_NORMAL);
    for (i=0;i<n;++i){
        // general retrieval
        sprintf(keybuf, "key%d", i);
        fdb_doc_create(&rdoc, (void*)keybuf, strlen(keybuf), NULL, 0, NULL, 0);
        status = fdb_get(db, rdoc);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        sprintf(bodybuf, "body%d_txn2", i);
        TEST_CMP(rdoc->body, bodybuf, rdoc->bodylen);
        fdb_doc_free(rdoc);

        // get from txn1
        fdb_doc_create(&rdoc, (void*)keybuf, strlen(keybuf), NULL, 0, NULL, 0);
        status = fdb_get(db_txn1, rdoc);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        sprintf(bodybuf, "body%d_txn1", i);
        TEST_CMP(rdoc->body, bodybuf, rdoc->bodylen);
        fdb_doc_free(rdoc);
    }

    // commit txn1 & retrieve check
    fdb_end_transaction(dbfile_txn1, FDB_COMMIT_NORMAL);
    for (i=0;i<n;++i){
        // general retrieval
        sprintf(keybuf, "key%d", i);
        fdb_doc_create(&rdoc, (void*)keybuf, strlen(keybuf), NULL, 0, NULL, 0);
        status = fdb_get(db, rdoc);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        sprintf(bodybuf, "body%d_txn1", i);
        TEST_CMP(rdoc->body, bodybuf, rdoc->bodylen);
        fdb_doc_free(rdoc);
    }

    // begin new transaction
    fdb_begin_transaction(dbfile_txn1, FDB_ISOLATION_READ_COMMITTED);
    // update doc#5
    i = 5;
    sprintf(keybuf, "key%d", i);
    sprintf(metabuf, "meta%d", i);
    sprintf(bodybuf, "body%d_before_compaction", i);
    fdb_doc_create(&rdoc, (void*)keybuf, strlen(keybuf),
                            (void*)metabuf, strlen(metabuf),
                            (void*)bodybuf, strlen(bodybuf));
    fdb_set(db_txn1, rdoc);
    fdb_doc_free(rdoc);

    // do compaction
    fdb_compact(dbfile, "mvcc_test2");

    // retrieve doc#5
    // using txn1
    fdb_doc_create(&rdoc, (void*)keybuf, strlen(keybuf), NULL, 0, NULL, 0);
    status = fdb_get(db_txn1, rdoc);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    TEST_CMP(rdoc->body, bodybuf, rdoc->bodylen);
    fdb_doc_free(rdoc);

    // general retrieval
    fdb_doc_create(&rdoc, (void*)keybuf, strlen(keybuf), NULL, 0, NULL, 0);
    status = fdb_get(db, rdoc);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    sprintf(bodybuf, "body%d_txn1", i);
    TEST_CMP(rdoc->body, bodybuf, rdoc->bodylen);
    fdb_doc_free(rdoc);

    // commit transaction
    fdb_end_transaction(dbfile_txn1, FDB_COMMIT_NORMAL);
    // retrieve check
    for (i=0;i<n;++i){
        // general get
        sprintf(keybuf, "key%d", i);
        fdb_doc_create(&rdoc, (void*)keybuf, strlen(keybuf), NULL, 0, NULL, 0);
        status = fdb_get(db, rdoc);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        if (i != 5) {
            sprintf(bodybuf, "body%d_txn1", i);
        } else {
            sprintf(bodybuf, "body%d_before_compaction", i);
        }
        TEST_CMP(rdoc->body, bodybuf, rdoc->bodylen);
        fdb_doc_free(rdoc);
    }

    // close & re-open db file
    fdb_close(dbfile);
    fdb_open(&dbfile, "mvcc_test2", &fconfig);
    fdb_kvs_open_default(dbfile, &db, &kvs_config);
    status = fdb_set_log_callback(db, logCallbackFunc,
                                  (void *) "transaction_test");
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    // retrieve check again
    for (i=0;i<n;++i){
        // general get
        sprintf(keybuf, "key%d", i);
        fdb_doc_create(&rdoc, (void*)keybuf, strlen(keybuf), NULL, 0, NULL, 0);
        status = fdb_get(db, rdoc);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        if (i != 5) {
            sprintf(bodybuf, "body%d_txn1", i);
        } else {
            sprintf(bodybuf, "body%d_before_compaction", i);
        }
        TEST_CMP(rdoc->body, bodybuf, rdoc->bodylen);
        fdb_doc_free(rdoc);
    }

    // close db file
    fdb_close(dbfile);
    fdb_close(dbfile_txn1);
    fdb_close(dbfile_txn2);

    // free all documents
    for (i=0;i<n;++i){
        fdb_doc_free(doc[i]);
    }

    // free all resources
    fdb_shutdown();

    memleak_end();

    TEST_RESULT("transaction test");
}

void transaction_simple_api_test()
{
    TEST_INIT();

    memleak_start();

    int i, r;
    int n = 10;
    size_t valuelen;
    void *value;
    fdb_file_handle *dbfile, *dbfile_txn1, *dbfile_txn2;
    fdb_kvs_handle *db, *db_txn1, *db_txn2;
    fdb_status status;

    char keybuf[256], bodybuf[256];

    // remove previous mvcc_test files
    r = system(SHELL_DEL" mvcc_test* > errorlog.txt");
    (void)r;

    fdb_config fconfig = fdb_get_default_config();
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    fconfig.buffercache_size = 0;
    fconfig.wal_threshold = 1024;
    fconfig.flags = FDB_OPEN_FLAG_CREATE;
    fconfig.purging_interval = 0;
    fconfig.compaction_threshold = 0;

    // open db
    fdb_open(&dbfile, "./mvcc_test1", &fconfig);
    fdb_kvs_open_default(dbfile, &db, &kvs_config);
    status = fdb_set_log_callback(db, logCallbackFunc,
                                  (void *) "transaction_simple_api_test");
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // insert key-value pairs
    for (i=0;i<n;++i){
        sprintf(keybuf, "key%d", i);
        sprintf(bodybuf, "body%d", i);
        status = fdb_set_kv(db, keybuf, strlen(keybuf), bodybuf, strlen(bodybuf));
        TEST_CHK(status == FDB_RESULT_SUCCESS);
    }

    // commit
    fdb_commit(dbfile, FDB_COMMIT_NORMAL);

    // open db and begin transactions
    fdb_open(&dbfile_txn1, "./mvcc_test1", &fconfig);
    fdb_open(&dbfile_txn2, "./mvcc_test1", &fconfig);
    fdb_kvs_open_default(dbfile_txn1, &db_txn1, &kvs_config);
    fdb_kvs_open_default(dbfile_txn2, &db_txn2, &kvs_config);
    fdb_begin_transaction(dbfile_txn1, FDB_ISOLATION_READ_COMMITTED);
    fdb_begin_transaction(dbfile_txn2, FDB_ISOLATION_READ_COMMITTED);

    // concurrently update docs
    for (i=0;i<n;++i){
        sprintf(keybuf, "key%d", i);
        sprintf(bodybuf, "body%d_txn1", i);
        fdb_set_kv(db_txn1, keybuf, strlen(keybuf), bodybuf, strlen(bodybuf));

        sprintf(keybuf, "key%d", i);
        sprintf(bodybuf, "body%d_txn2", i);
        fdb_set_kv(db_txn2, keybuf, strlen(keybuf), bodybuf, strlen(bodybuf));
    }

    // retrieve key-value pairs
    for (i=0;i<n;++i){
        // general retrieval
        sprintf(keybuf, "key%d", i);
        sprintf(bodybuf, "body%d", i);
        status = fdb_get_kv(db, keybuf, strlen(keybuf), &value, &valuelen);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        TEST_CMP(value, bodybuf, valuelen);
        fdb_free_block(value);

        // txn1
        sprintf(keybuf, "key%d", i);
        sprintf(bodybuf, "body%d_txn1", i);
        status = fdb_get_kv(db_txn1, keybuf, strlen(keybuf), &value, &valuelen);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        TEST_CMP(value, bodybuf, valuelen);
        fdb_free_block(value);

        // txn2
        sprintf(keybuf, "key%d", i);
        sprintf(bodybuf, "body%d_txn2", i);
        status = fdb_get_kv(db_txn2, keybuf, strlen(keybuf), &value, &valuelen);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        TEST_CMP(value, bodybuf, valuelen);
        fdb_free_block(value);
    }

    // commit txn1
    fdb_end_transaction(dbfile_txn1, FDB_COMMIT_NORMAL);
    for (i=0;i<n;++i){
        // general retrieval
        sprintf(keybuf, "key%d", i);
        sprintf(bodybuf, "body%d_txn1", i);
        status = fdb_get_kv(db, keybuf, strlen(keybuf), &value, &valuelen);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        TEST_CMP(value, bodybuf, valuelen);
        status = fdb_free_block(value);
        TEST_CHK(status == FDB_RESULT_SUCCESS);

        // txn2
        sprintf(keybuf, "key%d", i);
        sprintf(bodybuf, "body%d_txn2", i);
        status = fdb_get_kv(db_txn2, keybuf, strlen(keybuf), &value, &valuelen);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        TEST_CMP(value, bodybuf, valuelen);
        fdb_free_block(value);
    }

    // commit txn2
    fdb_end_transaction(dbfile_txn2, FDB_COMMIT_NORMAL);
    for (i=0;i<n;++i){
        // general retrieval
        sprintf(keybuf, "key%d", i);
        sprintf(bodybuf, "body%d_txn2", i);
        status = fdb_get_kv(db, keybuf, strlen(keybuf), &value, &valuelen);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        TEST_CMP(value, bodybuf, valuelen);
        fdb_free_block(value);
    }

    // close db file
    fdb_close(dbfile);
    fdb_close(dbfile_txn1);
    fdb_close(dbfile_txn2);

    // free all resources
    fdb_shutdown();

    memleak_end();

    TEST_RESULT("transaction simple API test");
}

void *in_memory_snapshot_thread(void *args)
{

    TEST_INIT();

    fdb_kvs_handle *db = (fdb_kvs_handle *)args;
    fdb_kvs_handle *snap_db;
    fdb_iterator *fit;
    fdb_status status;
    fdb_doc *doc;
    char key[256], value[256];

    // Open in-memory snapshot
    status = fdb_snapshot_open(db, &snap_db, FDB_SNAPSHOT_INMEM);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // Iterate the in-memory snapshot
    status = fdb_iterator_init(snap_db, &fit, NULL, 0, NULL, 0, 0x0);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    int i = 0;
    do {
        doc = NULL;
        status = fdb_iterator_get(fit, &doc);
        if (status != FDB_RESULT_SUCCESS) {
            break;
        }
        sprintf(key, "key%d", i);
        sprintf(value, "body%d", i);
        TEST_CMP(doc->key, key, doc->keylen);
        TEST_CMP(doc->body, value, doc->bodylen);
        i++;
        fdb_doc_free(doc);
    } while(fdb_iterator_next(fit) == FDB_RESULT_SUCCESS);
    TEST_CHK(i == 10);

    status = fdb_iterator_close(fit);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_kvs_close(snap_db);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // shutdown
    thread_exit(0);
    return NULL;
}

void transaction_in_memory_snapshot_test()
{
    TEST_INIT();

    memleak_start();

    int i, r;
    int n = 10;
    fdb_file_handle *dbfile, *dbfile_txn1;
    fdb_kvs_handle *db, *db_txn1;
    fdb_status status;

    char keybuf[256], bodybuf[256];

    // remove previous mvcc_test files
    r = system(SHELL_DEL" mvcc_test* > errorlog.txt");
    (void)r;

    fdb_config fconfig = fdb_get_default_config();
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    fconfig.buffercache_size = 0;
    fconfig.wal_threshold = 1024;
    fconfig.flags = FDB_OPEN_FLAG_CREATE;
    fconfig.purging_interval = 0;
    fconfig.compaction_threshold = 0;

    // open db
    fdb_open(&dbfile, "./mvcc_test1", &fconfig);
    fdb_kvs_open_default(dbfile, &db, &kvs_config);
    status = fdb_set_log_callback(db, logCallbackFunc,
                                  (void *) "transaction_in_memory_snapshot_test");
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // insert the first set of key-value pairs
    for (i=0;i<n;++i){
        sprintf(keybuf, "key%d", i);
        sprintf(bodybuf, "body%d", i);
        status = fdb_set_kv(db, keybuf, strlen(keybuf), bodybuf,
                            strlen(bodybuf));
        TEST_CHK(status == FDB_RESULT_SUCCESS);
    }

    // commit
    fdb_commit(dbfile, FDB_COMMIT_NORMAL);

    // open db and begin a transaction
    fdb_open(&dbfile_txn1, "./mvcc_test1", &fconfig);
    fdb_kvs_open_default(dbfile_txn1, &db_txn1, &kvs_config);
    fdb_begin_transaction(dbfile_txn1, FDB_ISOLATION_READ_COMMITTED);

    // concurrently update docs
    for (i=10;i<10000;++i){
        sprintf(keybuf, "key%d", i);
        sprintf(bodybuf, "body%d_txn1", i);
        fdb_set_kv(db_txn1, keybuf, strlen(keybuf), bodybuf, strlen(bodybuf));
    }

    // Create in-memory snapshot thread
    thread_t tid;
    void *thread_ret;
    thread_create(&tid, in_memory_snapshot_thread, (void *)db);

    // commit txn1
    fdb_end_transaction(dbfile_txn1, FDB_COMMIT_NORMAL);

    thread_join(tid, &thread_ret);

    // close db file
    fdb_close(dbfile);
    fdb_close(dbfile_txn1);

    // free all resources
    fdb_shutdown();

    memleak_end();

    TEST_RESULT("transaction and in-memory snapshot interleaving test");
}

void transaction_post_commit_snapshot_test()
{
    TEST_INIT();

    memleak_start();

    int i, r;
    int n = 10;
    size_t valuelen;
    void *value;
    fdb_file_handle *dbfile, *dbfile_txn1;
    fdb_kvs_handle *db, *db_txn1;
    fdb_iterator *iterator;
    fdb_status status;

    char keybuf[16], bodybuf[16];

    // remove previous mvcc_test files
    r = system(SHELL_DEL" mvcc_test* > errorlog.txt");
    (void)r;

    fdb_config fconfig = fdb_get_default_config();
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    fconfig.buffercache_size = 0;

    // open db
    fdb_open(&dbfile, "./mvcc_test1", &fconfig);
    fdb_kvs_open_default(dbfile, &db, &kvs_config);
    status = fdb_set_log_callback(db, logCallbackFunc,
                          (void *) "transaction_post_commit_snapshot_test");
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // open db and begin transactions
    fdb_open(&dbfile_txn1, "./mvcc_test1", &fconfig);
    fdb_kvs_open_default(dbfile_txn1, &db_txn1, &kvs_config);

    status = fdb_begin_transaction(dbfile_txn1, FDB_ISOLATION_READ_COMMITTED);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // concurrently update docs
    for (i=0;i<n;++i){
        sprintf(keybuf, "key%d", i);
        sprintf(bodybuf, "body%d_txn1", i);
        fdb_set_kv(db_txn1, keybuf, strlen(keybuf), bodybuf, strlen(bodybuf));
    }

    // retrieve key-value pairs
    for (i=0;i<n;++i){
        // general retrieval
        sprintf(keybuf, "key%d", i);
        status = fdb_get_kv(db, keybuf, strlen(keybuf), &value, &valuelen);
        TEST_CHK(status == FDB_RESULT_KEY_NOT_FOUND);

        // txn1
        sprintf(keybuf, "key%d", i);
        sprintf(bodybuf, "body%d_txn1", i);
        status = fdb_get_kv(db_txn1, keybuf, strlen(keybuf), &value, &valuelen);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        TEST_CMP(value, bodybuf, valuelen);
        fdb_free_block(value);
    }

    // commit txn1
    status = fdb_end_transaction(dbfile_txn1, FDB_COMMIT_NORMAL);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    status = fdb_iterator_init(db, &iterator, NULL, 0, NULL, 0, FDB_ITR_NONE);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    i = 0;
    do {
        fdb_doc *rdoc = NULL;
        status = fdb_iterator_get(iterator, &rdoc);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        sprintf(keybuf, "key%d", i);
        TEST_CMP(rdoc->key, keybuf, rdoc->keylen);
        fdb_doc_free(rdoc);
        i++;

    } while (fdb_iterator_next(iterator) != FDB_RESULT_ITERATOR_FAIL);
    fdb_iterator_close(iterator);
    TEST_CHK(i == n);

    // close db file
    fdb_close(dbfile);
    fdb_close(dbfile_txn1);

    // free all resources
    fdb_shutdown();

    memleak_end();

    TEST_RESULT("transaction post commit snapshot test");
}

struct piterator_ctx {
    fdb_config *config;
    int num_docs;
    const char *filename;
    std::mutex lock;
};

void *parallel_iterator_thread(void *args)
{
    TEST_INIT();

    struct piterator_ctx *ctx = (struct piterator_ctx *)args;
    fdb_file_handle *dbfile;
    fdb_kvs_handle *db;
    fdb_kvs_handle *snap_db;
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    fdb_iterator *fit, *fit2;
    fdb_status status;
    fdb_seqnum_t snap_seqnum;
    int num_read = 0;
    fdb_doc *doc;
    char key[16];

    while (num_read < ctx->num_docs) {
        status = fdb_open(&dbfile, ctx->filename, ctx->config);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        status = fdb_kvs_open_default(dbfile, &db, &kvs_config);
        TEST_CHK(status == FDB_RESULT_SUCCESS);

        ctx->lock.lock();
        // Open in-memory snapshot
        status = fdb_snapshot_open(db, &snap_db, FDB_SNAPSHOT_INMEM);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        ctx->lock.unlock();

        fdb_get_kvs_seqnum(snap_db, &snap_seqnum);
        // Iterate the in-memory snapshot
        status = fdb_iterator_init(snap_db, &fit, 0, 0, 0, 0, FDB_ITR_NONE);
        fdb_iterator_sequence_init(snap_db, &fit2, 0, 0, FDB_ITR_NONE);

        if (status == FDB_RESULT_ITERATOR_FAIL) {
            continue;
        }
        int i = 0;
        while (status == FDB_RESULT_SUCCESS) {
            doc = NULL;
            status = fdb_iterator_get(fit, &doc);
            if (status != FDB_RESULT_SUCCESS) {
                break;
            }
            sprintf(key, "key%05d", i);
            TEST_CMP(doc->key, key, doc->keylen);
            TEST_CHK(doc->seqnum == static_cast<uint64_t>(i+1));
            // printf("Got %s seqnum %llu\n", key, doc->seqnum);
            fdb_doc_free(doc);
            doc = NULL;

            status = fdb_iterator_get(fit2, &doc);
            TEST_CHK(status == FDB_RESULT_SUCCESS);
            TEST_CMP(doc->key, key, doc->keylen);
            TEST_CHK(doc->seqnum == static_cast<uint64_t>(i+1));
            fdb_doc_free(doc);

            i++;
            status = fdb_iterator_next(fit);
            TEST_CHK(status == fdb_iterator_next(fit2));
        }
        TEST_CHK(snap_seqnum == static_cast<uint64_t>(i));
        num_read = snap_seqnum;

        status = fdb_iterator_close(fit);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        status = fdb_iterator_close(fit2);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        status = fdb_kvs_close(snap_db);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        status = fdb_kvs_close(db);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        status = fdb_close(dbfile);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
    }

    // shutdown
    thread_exit(0);
    return NULL;
}

void concurrent_writer_iterator_test()
{
    TEST_INIT();

    memleak_start();

    int i, r;
    int n = 100;
    int num_threads = 1;
    fdb_file_handle *dbfile;
    fdb_kvs_handle *db;
    fdb_status status;

    char keybuf[16];

    // remove previous mvcc_test files
    r = system(SHELL_DEL" mvcc_test* > errorlog.txt");
    (void)r;

    fdb_config fconfig = fdb_get_default_config();
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    fconfig.buffercache_size = 0;
    fconfig.flags = FDB_OPEN_FLAG_CREATE;
    fconfig.compaction_threshold = 0;
    fconfig.num_compactor_threads = 1;
    fconfig.seqtree_opt = FDB_SEQTREE_USE;

    // open db
    const char *test_filename = "./mvcc_test1";
    status = fdb_open(&dbfile, test_filename, &fconfig);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_kvs_open_default(dbfile, &db, &kvs_config);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_set_log_callback(db, logCallbackFunc,
                                  (void *) "concurrent_writer_iterator_test");
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    struct piterator_ctx ctx;
    ctx.config = &fconfig;
    ctx.num_docs = n;
    ctx.filename = test_filename;

    // Create parallel iterator threads
    thread_t *tid = alca(thread_t, num_threads);
    for (i = 0; i < num_threads; ++i) {
        thread_create(&tid[i], parallel_iterator_thread, (void *)&ctx);
    }

    // insert each key and trigger a WAL_FLUSH
    for (i=0;i<n;++i){
        ctx.lock.lock();
        sprintf(keybuf, "key%05d", i);
        status = fdb_set_kv(db, keybuf, strlen(keybuf)+1, NULL, 0);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        status = fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        ctx.lock.unlock();
    }

    for (i = 0; i < num_threads; ++i) {
        void *thread_ret;
        thread_join(tid[i], &thread_ret);
    }

    // close db file
    status = fdb_close(dbfile);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // free all resources
    status = fdb_shutdown();
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    memleak_end();

    TEST_RESULT("concurrent writer and iterator consistency test");
}

void rollback_prior_to_ops(bool walflush)
{

    TEST_INIT();
    memleak_start();

    int r;
    int i, j, n=100;
    int expected_doc_count = 0;
    int rb_seqnum;
    char keybuf[256], bodybuf[256];
    fdb_file_handle *dbfile;
    fdb_iterator *it;
    fdb_kvs_handle *kv1, *mirror_kv1;
    fdb_kvs_info info;
    fdb_config fconfig = fdb_get_default_config();
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    fdb_doc **doc = alca(fdb_doc*, n);
    fdb_doc *rdoc = NULL, *vdoc;
    fdb_status status;

    r = system(SHELL_DEL" mvcc_test* > errorlog.txt");
    (void)r;

    fconfig.wal_threshold = 1024;
    fconfig.seqtree_opt = FDB_SEQTREE_USE; // enable seqtree since get_byseq
    fconfig.flags = FDB_OPEN_FLAG_CREATE;
    fconfig.compaction_threshold = 10;
    fconfig.purging_interval = 1; // retain deletes until compaction

    fdb_open(&dbfile, "./mvcc_test1", &fconfig);
    fdb_kvs_open(dbfile, &kv1, "kv1", &kvs_config);

    if(walflush){
        fdb_kvs_open(dbfile, &mirror_kv1, NULL, &kvs_config);
    } else {
        fdb_kvs_open(dbfile, &mirror_kv1, "mirror", &kvs_config);
    }

    // set n docs
    for(i=0;i<n;++i){
        sprintf(keybuf, "key%d", i);
        fdb_doc_create(&doc[i], (void*)keybuf, strlen(keybuf),
            NULL, 0, NULL, 0);
        fdb_set(kv1, doc[i]);
        fdb_set(mirror_kv1, doc[i]);
        expected_doc_count++;
    }

    // commit
    fdb_commit(dbfile, FDB_COMMIT_NORMAL);

    // delete subset of recently loaded docs
    for(i=0;i<n/2;++i){
        fdb_del(kv1, doc[i]);
        fdb_del(mirror_kv1, doc[i]);
        expected_doc_count--;
        fdb_doc_free(doc[i]);
    }

    for(i=n/2;i<n;++i){
        fdb_doc_free(doc[i]);
    }

    // commit and save seqnum
    fdb_commit(dbfile, FDB_COMMIT_NORMAL);
    fdb_get_kvs_info(kv1, &info);
    TEST_CHK(info.doc_count == (size_t)expected_doc_count);
    rb_seqnum = info.last_seqnum;

    for (j=0;j<100;++j){
        // load some more docs but stop mirroring
        for(i=0;i<n;++i){
            sprintf(keybuf, "key%d", n+i);
            fdb_doc_create(&doc[i], (void*)keybuf, strlen(keybuf),
                NULL, 0, NULL, 0);
            fdb_set(kv1, doc[i]);
            if( n%2 == 0){
                fdb_del(kv1, doc[i]);
            }
            fdb_doc_free(doc[i]);
        }
    }

    // commit wal or normal
    if(walflush){
        fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);
    } else {
        fdb_commit(dbfile, FDB_COMMIT_NORMAL);
    }

    // rollback
    status = fdb_rollback(&kv1, rb_seqnum);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    fdb_get_kvs_info(kv1, &info);
    TEST_CHK(info.doc_count == (size_t)expected_doc_count);
    fdb_get_kvs_info(mirror_kv1, &info);
    TEST_CHK(info.doc_count == (size_t)expected_doc_count);

    status = fdb_iterator_sequence_init(mirror_kv1, &it, 0, 0, FDB_ITR_NONE);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    do {
        status = fdb_iterator_get_metaonly(it, &rdoc);
        TEST_CHK(status == FDB_RESULT_SUCCESS);

        fdb_doc_create(&vdoc, rdoc->key, rdoc->keylen,
                              rdoc->meta, rdoc->metalen,
                              rdoc->body, rdoc->bodylen);
        status = fdb_get(kv1, vdoc);
        if (rdoc->deleted){
            TEST_CHK(status == FDB_RESULT_KEY_NOT_FOUND);
        } else {
            TEST_CHK(status == FDB_RESULT_SUCCESS);
        }
        fdb_doc_free(rdoc);
        rdoc = NULL;
        fdb_doc_free(vdoc);
    } while (fdb_iterator_next(it) != FDB_RESULT_ITERATOR_FAIL);

    fdb_iterator_close(it);
    fdb_kvs_close(mirror_kv1);
    fdb_kvs_close(kv1);
    fdb_close(dbfile);
    fdb_shutdown();
    memleak_end();

    sprintf(bodybuf, "rollback prior to ops test %s",
            walflush ? "commit with wal flush:" : "normal commit:");
    TEST_RESULT(bodybuf);
}

struct cb_snapshot_args {
    fdb_kvs_handle *handle;
    int ndocs;
    int nupdates;
    int niterations;
};

static void _snapshot_check(fdb_kvs_handle *handle, int ndocs, int nupdates)
{
    TEST_INIT();
    int i, j, update_no;
    int commit_term = ndocs/2;
    char keybuf[256], bodybuf[256];
    char *value;
    size_t valuelen;
    fdb_kvs_handle *snap;
    fdb_status s;
    fdb_kvs_info info;

    // check last seqnum
    fdb_get_kvs_info(handle, &info);
    TEST_CHK(info.last_seqnum == (fdb_seqnum_t)commit_term * nupdates);

    // open snapshot for every 'commit_term' seq numbers
    for (i=0; i<nupdates; i++) {
        s = fdb_snapshot_open(handle, &snap, (i+1)*commit_term);
        TEST_CHK(s == FDB_RESULT_SUCCESS);

        for (j=0;j<ndocs;++j) {
            if (j < ndocs/2) {
                update_no = (i/2) * 2;
            } else {
                if (i == 0) {
                    break;
                }
                update_no = 1 + ((i-1)/2) * 2;
            }
            sprintf(keybuf, "key%04d", j);
            sprintf(bodybuf, "body%04d_update%d", j, update_no);
            s = fdb_get_kv(snap, keybuf, strlen(keybuf)+1,
                           (void**)&value, &valuelen);
            TEST_CHK(s == FDB_RESULT_SUCCESS);
            TEST_CMP(value, bodybuf, valuelen);
            fdb_free_block(value);
        }

        s = fdb_kvs_close(snap);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
    }
}

static void _snapshot_update_docs(fdb_file_handle *fhandle, struct cb_snapshot_args *args)
{
    int i;
    char keybuf[256], bodybuf[256];
    fdb_status s;
    TEST_INIT();

    // update (half) docs
    if (args->nupdates % 2 == 0) {
        // former half
        for (i=0; i<args->ndocs/2; ++i) {
            sprintf(keybuf, "key%04d", i);
            sprintf(bodybuf, "body%04d_update%d", i, args->nupdates);
            s = fdb_set_kv(args->handle, keybuf, strlen(keybuf)+1,
                           bodybuf, strlen(bodybuf)+1);
            TEST_CHK(s == FDB_RESULT_SUCCESS);
        }
    } else {
        // latter half
        for (i=args->ndocs/2 ; i<args->ndocs; ++i) {
            sprintf(keybuf, "key%04d", i);
            sprintf(bodybuf, "body%04d_update%d", i, args->nupdates);
            fdb_set_kv(args->handle, keybuf, strlen(keybuf)+1,
                           bodybuf, strlen(bodybuf)+1);
        }
    }
    s = fdb_commit(fhandle, FDB_COMMIT_NORMAL);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    args->nupdates++;
}

static fdb_compact_decision cb_snapshot(fdb_file_handle *fhandle,
        fdb_compaction_status status, const char *kv_name,
        fdb_doc *doc, uint64_t old_offset, uint64_t new_offset,
        void *ctx)
{
    struct cb_snapshot_args *args = (struct cb_snapshot_args *)ctx;
    TEST_INIT();

    if (--args->niterations >= 0) {
        TEST_CHK(!kv_name);
        if (status == FDB_CS_BEGIN) {
            // first verification
            _snapshot_check(args->handle, args->ndocs, args->nupdates);
            // update half docs
            _snapshot_update_docs(fhandle, args);
            // second verification
            _snapshot_check(args->handle, args->ndocs, args->nupdates);
        } else { // if (status == FDB_CS_END)
            // first verification
            _snapshot_check(args->handle, args->ndocs, args->nupdates);
            // update half docs
            _snapshot_update_docs(fhandle, args);
            // second verification
            _snapshot_check(args->handle, args->ndocs, args->nupdates);
        }
    }
    return 0;
}

void snapshot_concurrent_compaction_test()
{
    TEST_INIT();
    memleak_start();

    int i, j, idx, r;
    int n = 100;
    int commit_term = n/2;
    char keybuf[256], bodybuf[256];
    fdb_file_handle *dbfile;
    fdb_kvs_handle *db;
    fdb_status s;
    fdb_config fconfig = fdb_get_default_config();
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    struct cb_snapshot_args cb_args;

    memset(&cb_args, 0x0, sizeof(struct cb_snapshot_args));
    fconfig.wal_threshold = 128;
    fconfig.flags = FDB_OPEN_FLAG_CREATE;
    fconfig.compaction_cb = cb_snapshot;
    fconfig.compaction_cb_ctx = &cb_args;
    fconfig.compaction_cb_mask = FDB_CS_BEGIN |
                                 FDB_CS_END;

    // remove previous mvcc_test files
    r = system(SHELL_DEL" mvcc_test* > errorlog.txt");
    (void)r;

    // open db
    fdb_open(&dbfile, "./mvcc_test1", &fconfig);
    fdb_kvs_open(dbfile, &db, "db", &kvs_config);
    cb_args.handle = db;

    // write docs & commit for each n/2 doc updates
    for (i=0;i<n;++i){
        idx = i;
        j = i/commit_term;
        sprintf(keybuf, "key%04d", idx);
        sprintf(bodybuf, "body%04d_update%d", idx, j);
        s = fdb_set_kv(db, keybuf, strlen(keybuf)+1,
                           bodybuf, strlen(bodybuf)+1);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        if ((i+1)%commit_term == 0) {
            s = fdb_commit(dbfile, FDB_COMMIT_NORMAL);
            TEST_CHK(s == FDB_RESULT_SUCCESS);
        }
    }
    cb_args.ndocs = n;
    cb_args.nupdates = 2;
    cb_args.niterations = 10;

    _snapshot_check(db, cb_args.ndocs, cb_args.nupdates);

    s = fdb_compact(dbfile, "./mvcc_test2");
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    fdb_close(dbfile);
    fdb_shutdown();
    memleak_end();
    TEST_RESULT("snapshot with concurrent compaction test");
}

void rollback_to_zero_test(bool multi_kv)
{
    TEST_INIT();

    memleak_start();

    int i, r;
    int n = 20;
    int num_kvs = 4; // keep this the same as number of fdb_commit() calls
    fdb_file_handle *dbfile;
    fdb_kvs_handle **db = alca(fdb_kvs_handle *, num_kvs);
    fdb_doc **doc = alca(fdb_doc*, n);
    fdb_kvs_info info;
    fdb_status status;

    char keybuf[256], metabuf[256], bodybuf[256];
    char kv_name[8];

    // remove previous mvcc_test files
    r = system(SHELL_DEL" mvcc_test* > errorlog.txt");
    (void)r;

    fdb_config fconfig = fdb_get_default_config();
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    fconfig.buffercache_size = 0;
    fconfig.wal_threshold = 1024;
    fconfig.flags = FDB_OPEN_FLAG_CREATE;
    fconfig.compaction_threshold = 0;
    fconfig.multi_kv_instances = multi_kv;

    // open db
    fdb_open(&dbfile, "./mvcc_test1", &fconfig);

    if (multi_kv) {
        for (r = 0; r < num_kvs; ++r) {
            sprintf(kv_name, "kv%d", r);
            fdb_kvs_open(dbfile, &db[r], kv_name, &kvs_config);
        }
    } else {
        num_kvs = 1;
        fdb_kvs_open_default(dbfile, &db[0], &kvs_config);
    }

    for (r = 0; r < num_kvs; ++r) {
        status = fdb_set_log_callback(db[r], logCallbackFunc,
                                      (void *) "rollback_to_zero_test");
        TEST_CHK(status == FDB_RESULT_SUCCESS);
    }

   // ------- Setup test ----------------------------------
   // insert documents of 0-4
    for (i=0; i<n/4; i++){
        sprintf(keybuf, "key%d", i);
        sprintf(metabuf, "meta%d", i);
        sprintf(bodybuf, "body%d", i);
        fdb_doc_create(&doc[i], (void*)keybuf, strlen(keybuf),
            (void*)metabuf, strlen(metabuf), (void*)bodybuf, strlen(bodybuf));
        for (r = 0; r < num_kvs; ++r) {
            fdb_set(db[r], doc[i]);
        }
    }

    // commit with a manual WAL flush (these docs go into HB-trie)
    fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);

    // insert documents from 5 - 9
    for (; i < n/2; i++){
        sprintf(keybuf, "key%d", i);
        sprintf(metabuf, "meta%d", i);
        sprintf(bodybuf, "body%d", i);
        fdb_doc_create(&doc[i], (void*)keybuf, strlen(keybuf),
            (void*)metabuf, strlen(metabuf), (void*)bodybuf, strlen(bodybuf));
        for (r = 0; r < num_kvs; ++r) {
            fdb_set(db[r], doc[i]);
        }
    }

    // commit again without a WAL flush
    fdb_commit(dbfile, FDB_COMMIT_NORMAL);

    // insert documents from 10-14 into HB-trie
    for (; i < (n/2 + n/4); i++){
        sprintf(keybuf, "key%d", i);
        sprintf(metabuf, "meta%d", i);
        sprintf(bodybuf, "body%d", i);
        fdb_doc_create(&doc[i], (void*)keybuf, strlen(keybuf),
            (void*)metabuf, strlen(metabuf), (void*)bodybuf, strlen(bodybuf));
        for (r = 0; r < num_kvs; ++r) {
            fdb_set(db[r], doc[i]);
        }
    }
    // manually flush WAL & commit
    fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);

    // insert documents from 15 - 19 on file into the WAL
    for (; i < n; i++){
        sprintf(keybuf, "key%d", i);
        sprintf(metabuf, "meta%d", i);
        sprintf(bodybuf, "body%d", i);
        fdb_doc_create(&doc[i], (void*)keybuf, strlen(keybuf),
            (void*)metabuf, strlen(metabuf), (void*)bodybuf, strlen(bodybuf));
        for (r = 0; r < num_kvs; ++r) {
            fdb_set(db[r], doc[i]);
        }
    }
    // commit without a WAL flush
    fdb_commit(dbfile, FDB_COMMIT_NORMAL);

    if (!multi_kv) {
        status = fdb_rollback(&db[0], 0);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        status = fdb_get_kvs_info(db[0], &info);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        TEST_CHK(info.last_seqnum == 0);
        TEST_CHK(info.doc_count == 0);
        TEST_CHK(info.space_used == 0);
        status = fdb_get(db[0], doc[0]);
        TEST_CHK(status == FDB_RESULT_KEY_NOT_FOUND);
        status = fdb_set(db[0], doc[0]);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
    } else {
        for (r = 0; r < num_kvs; ++r) {
            status = fdb_rollback(&db[r], 0);
            TEST_CHK(status == FDB_RESULT_SUCCESS);
            status = fdb_get_kvs_info(db[r], &info);
            TEST_CHK(status == FDB_RESULT_SUCCESS);
            TEST_CHK(info.last_seqnum == 0);
            TEST_CHK(info.doc_count == 0);
            TEST_CHK(info.space_used == 0);
            status = fdb_get(db[r], doc[0]);
            TEST_CHK(status == FDB_RESULT_KEY_NOT_FOUND);
            // test normal operation after rollback
            status = fdb_set(db[r], doc[0]);
            TEST_CHK(status == FDB_RESULT_SUCCESS);
        }
    }

    // test normal operation after rollbacks manually flush WAL & commit
    status = fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // close db file
    fdb_close(dbfile);

    // free all documents
    for (i=0;i<n;++i){
        fdb_doc_free(doc[i]);
    }

    // free all resources
    fdb_shutdown();

    memleak_end();

    sprintf(bodybuf, "rollback to zero test %s", multi_kv ? "multiple kv mode:"
                                                          : "single kv mode:");
    TEST_RESULT(bodybuf);
}

void rollback_to_zero_after_compact_test(bool multi_kv)
{
    TEST_INIT();

    int i, r;
    const int n = 20;
    int num_kvs = 4; // keep this the same as number of fdb_commit() calls
    fdb_kvs_handle *db[4]; // same as num_kvs
    fdb_file_handle *dbfile, *dbfile_comp;
    fdb_doc *doc[n];
    fdb_kvs_info info;
    fdb_status status;

    char keybuf[64], metabuf[64], bodybuf[64];
    char kv_name[8];

    // remove previous mvcc_test files
    r = system(SHELL_DEL" mvcc_test* > errorlog.txt");
    (void)r;

    fdb_config fconfig = fdb_get_default_config();
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    fconfig.buffercache_size = 0;
    fconfig.wal_threshold = 1024;
    fconfig.flags = FDB_OPEN_FLAG_CREATE;
    fconfig.compaction_threshold = 0;
    fconfig.multi_kv_instances = multi_kv;

    // open db
    fdb_open(&dbfile, "./mvcc_test1", &fconfig);

    if (multi_kv) {
        for (r = 0; r < num_kvs; ++r) {
            sprintf(kv_name, "kv%d", r);
            fdb_kvs_open(dbfile, &db[r], kv_name, &kvs_config);
        }
    } else {
        num_kvs = 1;
        fdb_kvs_open_default(dbfile, &db[0], &kvs_config);
    }

    for (r = 0; r < num_kvs; ++r) {
        status = fdb_set_log_callback(db[r], logCallbackFunc,
                         (void *) "rollback_to_zero_after_compact_test");
        TEST_CHK(status == FDB_RESULT_SUCCESS);
    }

   // ------- Setup test ----------------------------------
   // insert documents of 0-4
    for (i=0; i<n/4; i++){
        sprintf(keybuf, "key%d", i);
        sprintf(metabuf, "meta%d", i);
        sprintf(bodybuf, "body%d", i);
        fdb_doc_create(&doc[i], (void*)keybuf, strlen(keybuf),
            (void*)metabuf, strlen(metabuf), (void*)bodybuf, strlen(bodybuf));
        for (r = 0; r < num_kvs; ++r) {
            fdb_set(db[r], doc[i]);
        }
    }

    // commit with a manual WAL flush (these docs go into HB-trie)
    fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);

    // insert documents from 5 - 9
    for (; i < n/2; i++){
        sprintf(keybuf, "key%d", i);
        sprintf(metabuf, "meta%d", i);
        sprintf(bodybuf, "body%d", i);
        fdb_doc_create(&doc[i], (void*)keybuf, strlen(keybuf),
            (void*)metabuf, strlen(metabuf), (void*)bodybuf, strlen(bodybuf));
        for (r = 0; r < num_kvs; ++r) {
            fdb_set(db[r], doc[i]);
        }
    }

    // commit again without a WAL flush
    fdb_commit(dbfile, FDB_COMMIT_NORMAL);

    // insert documents from 10-14 into HB-trie
    for (; i < (n/2 + n/4); i++){
        sprintf(keybuf, "key%d", i);
        sprintf(metabuf, "meta%d", i);
        sprintf(bodybuf, "body%d", i);
        fdb_doc_create(&doc[i], (void*)keybuf, strlen(keybuf),
            (void*)metabuf, strlen(metabuf), (void*)bodybuf, strlen(bodybuf));
        for (r = 0; r < num_kvs; ++r) {
            fdb_set(db[r], doc[i]);
        }
    }
    // manually flush WAL & commit
    fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);

    // insert documents from 15 - 19 on file into the WAL
    for (; i < n; i++){
        sprintf(keybuf, "key%d", i);
        sprintf(metabuf, "meta%d", i);
        sprintf(bodybuf, "body%d", i);
        fdb_doc_create(&doc[i], (void*)keybuf, strlen(keybuf),
            (void*)metabuf, strlen(metabuf), (void*)bodybuf, strlen(bodybuf));
        for (r = 0; r < num_kvs; ++r) {
            fdb_set(db[r], doc[i]);
        }
    }
    // commit without a WAL flush
    fdb_commit(dbfile, FDB_COMMIT_NORMAL);

    // open db
    status = fdb_open(&dbfile_comp, "./mvcc_test1", &fconfig);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    status = fdb_compact(dbfile_comp, "./mvcc_test2");
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    fdb_close(dbfile_comp);

    for (r = 0; r < num_kvs; ++r) {
        status = fdb_rollback(&db[r], 0);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        status = fdb_get_kvs_info(db[r], &info);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        TEST_CHK(info.last_seqnum == 0);
        TEST_CHK(info.doc_count == 0);
        TEST_CHK(info.space_used == 0);
        status = fdb_get(db[r], doc[0]);
        TEST_CHK(status == FDB_RESULT_KEY_NOT_FOUND);
        // test normal operation after rollback
        status = fdb_set(db[r], doc[0]);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
    }

    // test normal operation after rollbacks manually flush WAL & commit
    status = fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // close db file
    fdb_close(dbfile);

    // free all documents
    for (i=0;i<n;++i){
        fdb_doc_free(doc[i]);
    }

    // free all resources
    fdb_shutdown();

    sprintf(bodybuf, "rollback to zero after compact test %s",
            multi_kv ? "multiple kv mode:" : "single kv mode:");
    TEST_RESULT(bodybuf);
}

void rollback_to_wal_test(bool multi_kv)
{
    TEST_INIT();

    memleak_start();

    int i, r;
    int n = 300;
    int num_kvs = 1;
    fdb_file_handle *dbfile;
    fdb_kvs_handle **db = alca(fdb_kvs_handle *, num_kvs);
    fdb_kvs_handle *snap_db;
    fdb_doc **doc = alca(fdb_doc*, n);
    fdb_doc *rdoc;
    fdb_status status;

    char keybuf[256], metabuf[256], bodybuf[256];

    // remove previous mvcc_test files
    r = system(SHELL_DEL" mvcc_test* > errorlog.txt");
    (void)r;

    fdb_config fconfig = fdb_get_default_config();
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    fconfig.buffercache_size = 0;
    fconfig.wal_threshold = 256;
    fconfig.flags = FDB_OPEN_FLAG_CREATE;
    fconfig.compaction_threshold = 0;
    fconfig.multi_kv_instances = multi_kv;

    // open db
    fdb_open(&dbfile, "./mvcc_test8", &fconfig);

    fdb_kvs_open_default(dbfile, &db[0], &kvs_config);

    for (r = 0; r < num_kvs; ++r) {
        status = fdb_set_log_callback(db[r], logCallbackFunc,
                                      (void *) "rollback_to_wal_test");
        TEST_CHK(status == FDB_RESULT_SUCCESS);
    }

   // ------- Setup test ----------------------------------
    for (i=0; i<n; i++){
        sprintf(keybuf, "key%d", i);
        sprintf(metabuf, "meta%d", i);
        sprintf(bodybuf, "body%d", i);
        fdb_doc_create(&doc[i], (void*)keybuf, strlen(keybuf),
            (void*)metabuf, strlen(metabuf), (void*)bodybuf, strlen(bodybuf));
        fdb_set(db[0], doc[i]);
    } // after 256 items wal gets flushed before commit

    // commit normal but as wal was flushed, this will cause a wal flush again!
    fdb_commit(dbfile, FDB_COMMIT_NORMAL);

    // update first half documents again
    for (i = 0; i < n/2; i++){
        fdb_doc_free(doc[i]);
        sprintf(keybuf, "key%d", i);
        sprintf(metabuf, "META%d", i);
        sprintf(bodybuf, "BODY%d", i);
        fdb_doc_create(&doc[i], (void*)keybuf, strlen(keybuf),
            (void*)metabuf, strlen(metabuf), (void*)bodybuf, strlen(bodybuf));
        fdb_set(db[0], doc[i]);
    }

    // commit again, this time wal threshold not hit so no wal flush on commit
    fdb_commit(dbfile, FDB_COMMIT_NORMAL);

    // update remaining half documents
    for (; i < n; i++){
        fdb_doc_free(doc[i]);
        sprintf(keybuf, "key%d", i);
        sprintf(metabuf, "Meta%d", i);
        sprintf(bodybuf, "Body%d", i);
        fdb_doc_create(&doc[i], (void*)keybuf, strlen(keybuf),
            (void*)metabuf, strlen(metabuf), (void*)bodybuf, strlen(bodybuf));
        fdb_set(db[0], doc[i]);
    } // somewhere in this loop wal gets flushed before commit
    // normal commit results in wal flush
    fdb_commit(dbfile, FDB_COMMIT_NORMAL);

    status = fdb_rollback(&db[0], n + n/2);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    i = 1; // pick a document in the WAL section upon rollback
    fdb_doc_create(&rdoc, doc[i]->key, doc[i]->keylen, NULL, 0, NULL, 0);
    status = fdb_snapshot_open(db[0], &snap_db, n + n/2);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_get(snap_db, rdoc);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    TEST_CMP(rdoc->body, doc[i]->body, rdoc->bodylen);
    TEST_CHK(rdoc->seqnum == (fdb_seqnum_t)n + i + 1);
    fdb_doc_free(rdoc);
    fdb_kvs_close(snap_db);

    // close db file
    fdb_close(dbfile);

    // free all documents
    for (i=0;i<n;++i){
        fdb_doc_free(doc[i]);
    }

    // free all resources
    fdb_shutdown();

    memleak_end();

    sprintf(bodybuf, "rollback to wal test %s", multi_kv ? "multiple kv mode:"
                                                         : "single kv mode:");
    TEST_RESULT(bodybuf);
}

void rollback_all_test(bool multi_kv)
{
    TEST_INIT();

    memleak_start();

    int i, r;
    int n = 20;
    int num_kvs = 4; // keep this the same as number of fdb_commit() calls
    fdb_file_handle *dbfile;
    fdb_kvs_handle **db = alca(fdb_kvs_handle *, num_kvs);
    fdb_doc **doc = alca(fdb_doc*, n);
    fdb_kvs_info info;
    fdb_snapshot_info_t *markers;
    fdb_seqnum_t rollback_seq;
    uint64_t num_markers;
    fdb_status status;

    char keybuf[256], metabuf[256], bodybuf[256];
    char kv_name[8];

    // remove previous dummy files
    r = system(SHELL_DEL" mvcc_test* > errorlog.txt");
    (void)r;

    fdb_config fconfig = fdb_get_default_config();
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    fconfig.buffercache_size = 0;
    fconfig.wal_threshold = 1024;
    fconfig.flags = FDB_OPEN_FLAG_CREATE;
    fconfig.compaction_threshold = 0;
    fconfig.multi_kv_instances = multi_kv;
    fconfig.block_reusing_threshold = 0;

    fdb_open(&dbfile, "./mvcc_test6", &fconfig);
    if (multi_kv) {
        for (r = 0; r < num_kvs; ++r) {
            sprintf(kv_name, "kv%d", r);
            fdb_kvs_open(dbfile, &db[r], kv_name, &kvs_config);
        }
    } else {
        num_kvs = 1;
        fdb_kvs_open_default(dbfile, &db[0], &kvs_config);
    }

    for (r = 0; r < num_kvs; ++r) {
        status = fdb_set_log_callback(db[r], logCallbackFunc,
                                      (void *) "rollback_all_test");
        TEST_CHK(status == FDB_RESULT_SUCCESS);
    }

   // ------- Setup test ----------------------------------
   // insert documents of 0-4
    for (i=0; i<n/4; i++){
        sprintf(keybuf, "key%d", i);
        sprintf(metabuf, "meta%d", i);
        sprintf(bodybuf, "body%d", i);
        fdb_doc_create(&doc[i], (void*)keybuf, strlen(keybuf),
            (void*)metabuf, strlen(metabuf), (void*)bodybuf, strlen(bodybuf));
        for (r = 0; r < num_kvs; ++r) {
            fdb_set(db[r], doc[i]);
        }
    }

    // commit with a manual WAL flush (these docs go into HB-trie)
    fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);

    // insert documents from 5 - 9
    for (; i < n/2; i++){
        sprintf(keybuf, "key%d", i);
        sprintf(metabuf, "meta%d", i);
        sprintf(bodybuf, "body%d", i);
        fdb_doc_create(&doc[i], (void*)keybuf, strlen(keybuf),
            (void*)metabuf, strlen(metabuf), (void*)bodybuf, strlen(bodybuf));
        for (r = 0; r < num_kvs; ++r) {
            fdb_set(db[r], doc[i]);
        }
    }

    // commit again without a WAL flush
    fdb_commit(dbfile, FDB_COMMIT_NORMAL);

    // insert documents from 10-14 into HB-trie
    for (; i < (n/2 + n/4); i++){
        sprintf(keybuf, "key%d", i);
        sprintf(metabuf, "meta%d", i);
        sprintf(bodybuf, "body%d", i);
        fdb_doc_create(&doc[i], (void*)keybuf, strlen(keybuf),
            (void*)metabuf, strlen(metabuf), (void*)bodybuf, strlen(bodybuf));
        for (r = 0; r < num_kvs; ++r) {
            fdb_set(db[r], doc[i]);
        }
    }
    // manually flush WAL & commit
    fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);

    // insert documents from 15 - 19 on file into the WAL
    for (; i < n; i++){
        sprintf(keybuf, "key%d", i);
        sprintf(metabuf, "meta%d", i);
        sprintf(bodybuf, "body%d", i);
        fdb_doc_create(&doc[i], (void*)keybuf, strlen(keybuf),
            (void*)metabuf, strlen(metabuf), (void*)bodybuf, strlen(bodybuf));
        for (r = 0; r < num_kvs; ++r) {
            fdb_set(db[r], doc[i]);
        }
    }
    // commit without a WAL flush
    fdb_commit(dbfile, FDB_COMMIT_NORMAL);

    status = fdb_get_all_snap_markers(dbfile, &markers, &num_markers);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    if (multi_kv) {
        TEST_CHK(num_markers == 9);
    } else {
        TEST_CHK(num_markers == 5);
    }

    // rollback to 15
    i = 1;
    rollback_seq = (fdb_seqnum_t)(n - (i*5));
    status = fdb_rollback_all(dbfile, markers[i].marker);
    if (multi_kv) {
        // In multi-kv mode, we cannot rollback all instances,
        // without closing them first, since a rollback point
        // may end up invalidating open handles
        TEST_CHK(status == FDB_RESULT_KV_STORE_BUSY);

        for (r = 0; r < num_kvs; ++r) {
            fdb_kvs_close(db[r]);
        }

        fdb_file_handle *fhandle;
        fdb_kvs_handle *dbhandle;
        status = fdb_open(&fhandle, "./mvcc_test6", &fconfig);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        status = fdb_kvs_open(fhandle, &dbhandle, "kv0", &kvs_config);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        // Rollback again, but should fail again because there is a new handle created
        status = fdb_rollback_all(dbfile, markers[i].marker);
        TEST_CHK(status == FDB_RESULT_KV_STORE_BUSY);
        // Close the handle to have the rollback pass
        status = fdb_kvs_close(dbhandle);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        status = fdb_close(fhandle);
        TEST_CHK(status == FDB_RESULT_SUCCESS);

        status = fdb_rollback_all(dbfile, markers[i].marker);
    }

    TEST_CHK(status == FDB_RESULT_SUCCESS);

    if (multi_kv) {
        for (r = 0; r < num_kvs; ++r) {
            sprintf(kv_name, "kv%d", r);
            status = fdb_kvs_open(dbfile, &db[r], kv_name, &kvs_config);
            TEST_CHK(status == FDB_RESULT_SUCCESS);
            status = fdb_set_log_callback(db[r], logCallbackFunc,
                    (void *) "rollback_all_test");
            TEST_CHK(status == FDB_RESULT_SUCCESS);
        }
    }

    for (r = 0; r < num_kvs; ++r) {
        char *body;
        size_t bodylen;
        status = fdb_get_kvs_info(db[r], &info);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        TEST_CHK(info.last_seqnum == rollback_seq);
        TEST_CHK(info.doc_count == rollback_seq);
        status = fdb_get(db[r], doc[n - 1]);
        TEST_CHK(status == FDB_RESULT_KEY_NOT_FOUND);
        status = fdb_get_kv(db[r], doc[0]->key, doc[0]->keylen,
                            (void **)&body, &bodylen);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        TEST_CMP(doc[0]->body, body, bodylen);
        free(body);
    }

    // test normal operation after rollbacks manually flush WAL & commit
    for (r = 0; r < num_kvs; ++r) {
        status = fdb_set(db[r], doc[0]);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
    }
    status = fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // close db file
    fdb_close(dbfile);

    // free all documents
    for (i=0;i<n;++i){
        fdb_doc_free(doc[i]);
    }

    status = fdb_free_snap_markers(markers, num_markers);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // free all resources
    fdb_shutdown();

    memleak_end();

    sprintf(bodybuf, "rollback all test %s", multi_kv ? "multiple kv mode:"
                                                      : "single kv mode:");
    TEST_RESULT(bodybuf);
}

static fdb_compact_decision compaction_cb_count(fdb_file_handle *fhandle,
                            fdb_compaction_status status, const char *kv_name,
                            fdb_doc *doc, uint64_t old_offset,
                            uint64_t new_offset, void *ctx)
{
    int *count = (int *)ctx;
    TEST_INIT();
    TEST_CHK(status == FDB_CS_COMPLETE);
    TEST_CHK(!kv_name);
    *count = *count + 1;
    return 0;
}


void auto_compaction_snapshots_test()
{
    TEST_INIT();

    memleak_start();

    fdb_file_handle *file;
    fdb_kvs_handle *kvs, *snapshot;
    fdb_status status;
    fdb_config config;
    fdb_kvs_config kvs_config;
    fdb_seqnum_t seqnum;
    fdb_kvs_info info;
    fdb_doc *rdoc;
    int num_compactions = 0;
    char str[64];

    int i, r;

    r = system(SHELL_DEL" mvcc_test* > errorlog.txt");
    (void)r;

    // Open Database File
    config = fdb_get_default_config();
    config.compaction_mode = FDB_COMPACTION_AUTO;
    config.seqtree_opt = FDB_SEQTREE_USE; // enable seqtree since get_byseq
    config.compaction_cb = compaction_cb_count;
    config.compaction_cb_ctx = &num_compactions;
    config.compaction_cb_mask = FDB_CS_COMPLETE;
    config.compactor_sleep_duration=1;
    status = fdb_open(&file, "mvcc_test1", &config);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // Open KV Store
    kvs_config = fdb_get_default_kvs_config();
    status = fdb_kvs_open_default(file, &kvs, &kvs_config);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // Several kv pairs
    for(i=0;i<100000;i++) {
        sprintf(str, "%d", i);
        status = fdb_set_kv(kvs, str, strlen(str), (void*)"value", 5);
        TEST_CHK(status == FDB_RESULT_SUCCESS);

        // Every 10 Commit
        if (i % 10 == 0) {
            status = fdb_commit(file, FDB_COMMIT_NORMAL);
            TEST_CHK(status == FDB_RESULT_SUCCESS);
        }

        // Every 100 iterations Get Seq/Snapshot
        if (i % 100 == 0) {
            status = fdb_get_kvs_info(kvs, &info);
            TEST_CHK(status == FDB_RESULT_SUCCESS);
            seqnum = info.last_seqnum;
            // Open durable snapshot in the midst of compaction..
            status = fdb_snapshot_open(kvs, &snapshot, seqnum);
            TEST_CHK(status == FDB_RESULT_SUCCESS);
            // verify last doc set is captured in snapshot..
            fdb_doc_create(&rdoc, NULL, 0, NULL, 0, NULL, 0);
            rdoc->seqnum = seqnum;
            status = fdb_get_byseq(snapshot, rdoc);
            TEST_CHK(status == FDB_RESULT_SUCCESS);
            TEST_CMP(rdoc->key, str, strlen(str));
            // free result document
            fdb_doc_free(rdoc);
            status = fdb_kvs_close(snapshot);
            TEST_CHK(status == FDB_RESULT_SUCCESS);

            // Open in-memory snapshot and verify content
            status = fdb_snapshot_open(kvs, &snapshot, FDB_SNAPSHOT_INMEM);
            TEST_CHK(status == FDB_RESULT_SUCCESS);
            // verify last doc set is captured in snapshot..
            fdb_doc_create(&rdoc, NULL, 0, NULL, 0, NULL, 0);
            rdoc->seqnum = seqnum;
            status = fdb_get_byseq(snapshot, rdoc);
            TEST_CHK(status == FDB_RESULT_SUCCESS);
            TEST_CMP(rdoc->key, str, strlen(str));
            // free result document
            fdb_doc_free(rdoc);
            status = fdb_kvs_close(snapshot);
            TEST_CHK(status == FDB_RESULT_SUCCESS);
        }
    }

    status = fdb_close(file);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_shutdown();
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    memleak_end();

    sprintf(str, "auto compaction completed %d times with snapshots",
            num_compactions);
    TEST_RESULT(str);
}

void *rollback_during_ops_test(void * args)
{

    TEST_INIT();
    memleak_start();

    fdb_file_handle *file;
    fdb_kvs_handle *kvs;
    fdb_status status;
    fdb_config config;
    fdb_kvs_config kvs_config;
    fdb_kvs_info kvs_info;
    fdb_seqnum_t rollback_to;
    thread_t tid;
    void *thread_ret;
    bool walflush = true;
    char str[15];
    int i, r;
    int n = 10000;

    if (args == NULL)
    { // parent

        r = system(SHELL_DEL" mvcc_test* > errorlog.txt");
        (void)r;

        // Open Database File
        config = fdb_get_default_config();
        // disable block reusing for strict rollback
        config.block_reusing_threshold = 0;
        status = fdb_open(&file, "mvcc_test1", &config);
        TEST_CHK(status == FDB_RESULT_SUCCESS);

        // Open KV Store
        kvs_config = fdb_get_default_kvs_config();
        status = fdb_kvs_open_default(file, &kvs, &kvs_config);
        TEST_CHK(status == FDB_RESULT_SUCCESS);

        // set with commits
        for(i=1;i<=n;i++) {
            sprintf(str, "%d", i);
            status = fdb_set_kv(kvs, str, strlen(str), (void*)"value", 5);
            TEST_CHK(status == FDB_RESULT_SUCCESS);
            if(i%10==0){
                walflush = !walflush;
                if(walflush){
                    fdb_commit(file, FDB_COMMIT_MANUAL_WAL_FLUSH);
                } else {
                    fdb_commit(file, FDB_COMMIT_NORMAL);
                }
            }
        }

        fdb_commit(file, FDB_COMMIT_MANUAL_WAL_FLUSH);
        fdb_get_kvs_info(kvs, &kvs_info);
        TEST_CHK(kvs_info.last_seqnum == (uint64_t)n);

        // start rollback thread
        thread_create(&tid, rollback_during_ops_test, (void *)&n);

        // updates with commits
        for(i=1;i<=10000;i++) {
            sprintf(str, "%d", i);
            status = fdb_set_kv(kvs, str, strlen(str), (void*)"value", 5);
            if(status == FDB_RESULT_SUCCESS){ // set ok
                status = fdb_commit(file, FDB_COMMIT_MANUAL_WAL_FLUSH);
                if(status != FDB_RESULT_SUCCESS){
                    TEST_CHK(status == FDB_RESULT_FAIL_BY_ROLLBACK);
                }
            } else {
                TEST_CHK(status == FDB_RESULT_FAIL_BY_ROLLBACK);
            }
        }

        // join rollback thread
        thread_join(tid, &thread_ret);

        // set a keys commit and save seqnum
        status = fdb_set_kv(kvs,(void *)"key1", 4, (void*)"value", 5);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        status = fdb_commit(file, FDB_COMMIT_MANUAL_WAL_FLUSH);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        fdb_get_kvs_info(kvs, &kvs_info);
        rollback_to = kvs_info.last_seqnum;

        // 2 more sets
        status = fdb_set_kv(kvs,(void *)"key2", 4, (void*)"value", 5);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        status = fdb_set_kv(kvs,(void *)"key3", 4, (void*)"value", 5);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        status = fdb_commit(file, FDB_COMMIT_MANUAL_WAL_FLUSH);
        TEST_CHK(status == FDB_RESULT_SUCCESS);

        // rollback to last saved seqnum
        status = fdb_rollback(&kvs, rollback_to);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        fdb_get_kvs_info(kvs, &kvs_info);
        TEST_CHK(kvs_info.last_seqnum == rollback_to);

        fdb_close(file);
        fdb_shutdown();

        memleak_end();
        TEST_RESULT("rollback during ops test");
        return NULL;
    }

    // open new copy of dbfile and kvs
    config = fdb_get_default_config();
    // disable block reusing for strict rollback
    config.block_reusing_threshold = 0;
    status = fdb_open(&file, "mvcc_test1", &config);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    kvs_config = fdb_get_default_kvs_config();
    status = fdb_kvs_open_default(file, &kvs, &kvs_config);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // reverse set with rollbacks
    n = *((int *)args);
    for(i=n;i>1;i--){
        sprintf(str, "%d", i);
        status = fdb_set_kv(kvs, str, strlen(str), (void*)"value", 5);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        if(i%10 == 0){
            status = fdb_rollback(&kvs, i);
            TEST_CHK(status == FDB_RESULT_SUCCESS);
        }
    }

    fdb_close(file);
    // exit
    thread_exit(0);
    return NULL;

}

void in_memory_snapshot_rollback_test()
{

    TEST_INIT();
    memleak_start();

    int i, r;
    char str[15];
    fdb_file_handle *file;
    fdb_kvs_handle *kvs, *snap_db;
    fdb_iterator *iterator;
    fdb_status status;
    fdb_config config;
    fdb_doc *rdoc;
    fdb_kvs_config kvs_config;
    fdb_kvs_info kvs_info;
    fdb_seqnum_t c, rollback_to = 3;

    r = system(SHELL_DEL" mvcc_test* > errorlog.txt");
    (void)r;

    config = fdb_get_default_config();
    status = fdb_open(&file, "mvcc_test1", &config);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    kvs_config = fdb_get_default_kvs_config();
    status = fdb_kvs_open_default(file, &kvs, &kvs_config);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // set 3 keys commits
    for(i=1;i<=3;i++) {
        sprintf(str, "%d", i);
        status = fdb_set_kv(kvs, str, strlen(str), (void*)"value", 5);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
    }
    // commit  normal
    fdb_commit(file, FDB_COMMIT_NORMAL);

    // set 2 more and commit w/flush
    status = fdb_set_kv(kvs, (void *)"key4", 4, (void*)"value", 5);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_set_kv(kvs, (void *)"key5", 4, (void*)"value", 5);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_commit(file, FDB_COMMIT_MANUAL_WAL_FLUSH);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // rollback to 3
    status = fdb_rollback(&kvs, rollback_to);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    fdb_get_kvs_info(kvs, &kvs_info);
    TEST_CHK(kvs_info.last_seqnum == rollback_to);

    // take a in-mem snapshot and iterate over kvs
    status = fdb_snapshot_open(kvs, &snap_db, FDB_SNAPSHOT_INMEM);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    fdb_iterator_init(snap_db, &iterator, NULL, 0, NULL, 0, FDB_ITR_NONE);
    rdoc = NULL;
    c = 0;
    do {
        status = fdb_iterator_get(iterator, &rdoc);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        fdb_doc_free(rdoc);
        rdoc = NULL;
        c++;
    } while (fdb_iterator_next(iterator) != FDB_RESULT_ITERATOR_FAIL);
    TEST_CHK(c==rollback_to);

    fdb_iterator_close(iterator);
    fdb_kvs_close(snap_db);
    fdb_close(file);
    fdb_shutdown();

    memleak_end();
    TEST_RESULT("in-memory snapshot rollback test");
}

void rollback_drop_multi_files_kvs_test()
{
    TEST_INIT();
    memleak_start();

    int i, j, r;
    int vb;
    int n = 10;
    int n_files = 8;
    int n_kvs = 128;
    char keybuf[256], bodybuf[256];
    char fname[256];

    fdb_file_handle **dbfiles = alca(fdb_file_handle*, n_files);
    fdb_kvs_handle **kvs = alca(fdb_kvs_handle*, n_files*n_kvs);
    fdb_iterator *iterator;
    fdb_doc *rdoc;
    fdb_status status;

    // remove previous test files
    r = system(SHELL_DEL" mvcc_test* > errorlog.txt");
    (void)r;

    fdb_config fconfig = fdb_get_default_config();
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    fconfig.wal_threshold = 1024;
    fconfig.compaction_mode = FDB_COMPACTION_MANUAL;
    fconfig.durability_opt = FDB_DRB_ASYNC;

    // 1024 kvs via 128 per dbfile
    for(j=0;j<n_files;++j){
        sprintf(fname, "mvcc_test%d", j);
        status = fdb_open(&dbfiles[j], fname, &fconfig);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        for(i=0;i<n_kvs;++i){
            vb = j*n_kvs+i;
            sprintf(fname, "kvs%d", vb);
            status = fdb_kvs_open(dbfiles[j], &kvs[vb], fname, &kvs_config);
            TEST_CHK(status == FDB_RESULT_SUCCESS);
        }
    }

    // load across all kvs
    vb = n_files*n_kvs;
    for(i=0;i<vb;++i){
        for(j=0;j<n;++j){
            sprintf(keybuf, "key%08d", j);
            sprintf(bodybuf, "value%08d", j);
            status = fdb_set_kv(kvs[i], keybuf, strlen(keybuf)+1, bodybuf, strlen(bodybuf)+1);
            TEST_CHK(status == FDB_RESULT_SUCCESS);
        }
    }

    // commit
    for(j=0;j<n_files;++j){
        if((j%2)==0){
            status = fdb_commit(dbfiles[j], FDB_COMMIT_NORMAL);
            TEST_CHK(status == FDB_RESULT_SUCCESS);
        } else {
            status = fdb_commit(dbfiles[j], FDB_COMMIT_MANUAL_WAL_FLUSH);
            TEST_CHK(status == FDB_RESULT_SUCCESS);
        }
    }

    // delete all keys
    vb = n_files*n_kvs;
    for(i=0;i<vb;++i){
        for(j=0;j<n;++j){
            sprintf(keybuf, "key%08d", j);
            status = fdb_del_kv(kvs[i], keybuf, strlen(keybuf)+1);
            TEST_CHK(status == FDB_RESULT_SUCCESS);
        }
    }


    // commit again
    for(j=0;j<n_files;++j){
        if((j%2)==0){
            status = fdb_commit(dbfiles[j], FDB_COMMIT_NORMAL);
            TEST_CHK(status == FDB_RESULT_SUCCESS);
        } else {
            status = fdb_commit(dbfiles[j], FDB_COMMIT_MANUAL_WAL_FLUSH);
            TEST_CHK(status == FDB_RESULT_SUCCESS);
        }
    }

    // rollback some kvs to pre-delete commit
    for(i=0;i<vb;i+=64){
        status = fdb_rollback(&kvs[i], n);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
    }

    // drop some of the kvs
    for(j=0;j<n_files;++j){
        for(i=0;i<n_kvs;i+=n_kvs){
            vb = j*n_kvs+i;
            status = fdb_kvs_close(kvs[vb]);
            TEST_CHK(status == FDB_RESULT_SUCCESS);
            sprintf(fname, "kvs%d", vb);
            status = fdb_kvs_remove(dbfiles[j], fname);
            TEST_CHK(status == FDB_RESULT_SUCCESS);
        }
    }

    // commit
    for(j=0;j<n_files;++j){
        if((j%2)==0){
            status = fdb_commit(dbfiles[j], FDB_COMMIT_NORMAL);
            TEST_CHK(status == FDB_RESULT_SUCCESS);
        } else {
            status = fdb_commit(dbfiles[j], FDB_COMMIT_MANUAL_WAL_FLUSH);
            TEST_CHK(status == FDB_RESULT_SUCCESS);
        }
    }

    // custom compact
    for(j=0;j<n_files;++j){
        sprintf(fname, "mvcc_test_compact%d", j);
        status = fdb_compact(dbfiles[j], fname);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
    }


    // iterate specifically over dbs that have been rolled back but not dropped
    rdoc = NULL;
    for(i=0;i<vb;i+=64){
        if((vb%n_kvs)==0){ continue; }

        j=0;
        fdb_iterator_init(kvs[i], &iterator, NULL, 0, NULL, 0, FDB_ITR_NO_DELETES);
        do {
            // verify keys
            status = fdb_iterator_get(iterator, &rdoc);
            TEST_CHK(status == FDB_RESULT_SUCCESS);
            sprintf(keybuf, "key%08d", j);
            TEST_CHK(!strcmp(keybuf, (char *)rdoc->key));
            j++;
        } while(fdb_iterator_next(iterator) != FDB_RESULT_ITERATOR_FAIL);
        fdb_iterator_close(iterator);

        // should still get all keys
        TEST_CHK(j==n);
    }
    fdb_doc_free(rdoc);

    // cleanup
    for(j=0;j<n_files;++j){
        status = fdb_close(dbfiles[j]);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
    }

    fdb_shutdown();
    memleak_end();
    TEST_RESULT("open multi files kvs test");
}

void rollback_without_seqtree(bool multi_kv)
{
    TEST_INIT();

    memleak_start();

    int i, j, r;
    int n = 10;
    int num_commits = 5, num_kvs = 3;
    fdb_file_handle *dbfile;
    fdb_kvs_handle **db = alca(fdb_kvs_handle *, num_kvs);
    fdb_doc **doc = alca(fdb_doc*, n);
    fdb_status status;
    fdb_snapshot_info_t *markers;
    uint64_t num_markers;

    char keybuf[256], metabuf[256], bodybuf[256];
    char kv_name[8];

    fdb_config fconfig = fdb_get_default_config();
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    fconfig.flags = FDB_OPEN_FLAG_CREATE;
    fconfig.multi_kv_instances = multi_kv;
    // for creating the strict number of snapshots, disable block reusing
    fconfig.block_reusing_threshold = 0;
    fconfig.seqtree_opt = FDB_SEQTREE_NOT_USE;

    // remove previous mvcc_test files
    r = system(SHELL_DEL" mvcc_test* > errorlog.txt");
    (void)r;

    // open db
    fdb_open(&dbfile, "./mvcc_test1", &fconfig);
    if (multi_kv) {
        for (r = 0; r < num_kvs; ++r) {
            sprintf(kv_name, "kv%d", r);
            fdb_kvs_open(dbfile, &db[r], kv_name, &kvs_config);
        }
    } else {
        num_kvs = 1;
        fdb_kvs_open_default(dbfile, &db[0], &kvs_config);
    }

    // Load documents mulitple times
    for (j=0; j < num_commits; ++j) {
        for (i=0; i<n; i++){
            sprintf(keybuf, "key%d", i);
            sprintf(metabuf, "meta-%d-%d", j, i);
            sprintf(bodybuf, "body-%d-%d", j, i);
            fdb_doc_create(&doc[i], (void*)keybuf, strlen(keybuf),
                           (void*)metabuf, strlen(metabuf), (void*)bodybuf, strlen(bodybuf));
            for (r = 0; r < num_kvs; ++r) {
                fdb_set(db[r], doc[i]);
            }
            fdb_doc_free(doc[i]);
        }
        if (j % 2 == 0) {
            fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);
        } else {
            fdb_commit(dbfile, FDB_COMMIT_NORMAL);
        }
    }

    status = fdb_get_all_snap_markers(dbfile, &markers, &num_markers);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // Rollback the first KV store to the second commit point
    status = fdb_rollback(&db[0], markers[3].kvs_markers[0].seqnum);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    fdb_kvs_handle *snap_db;
    fdb_iterator *iterator;
    fdb_doc *rdoc = NULL;
    // Create an in-memory snapshot for each KV store and verify all the keys.
    for (r = 0; r < num_kvs; ++r) {
        status = fdb_snapshot_open(db[r], &snap_db, FDB_SNAPSHOT_INMEM);
        TEST_CHK(status == FDB_RESULT_SUCCESS);

        // Verify all the keys in the snapshot
        status = fdb_iterator_init(snap_db, &iterator, NULL, 0, NULL, 0, FDB_ITR_NONE);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        i=0;
        do {
            status = fdb_iterator_get(iterator, &rdoc);
            TEST_CHK(status == FDB_RESULT_SUCCESS);
            sprintf(keybuf, "key%d", i);
            if (r == 0) {
                // The first KV store should only have KV items from the second commit.
                sprintf(metabuf, "meta-1-%d", i);
                sprintf(bodybuf, "body-1-%d", i);
            } else {
                sprintf(metabuf, "meta-%d-%d", num_commits - 1, i);
                sprintf(bodybuf, "body-%d-%d", num_commits - 1, i);
            }
            TEST_CMP(rdoc->key, keybuf, rdoc->keylen);
            TEST_CMP(rdoc->meta, metabuf, rdoc->metalen);
            TEST_CMP(rdoc->body, bodybuf, rdoc->bodylen);
            fdb_doc_free(rdoc);
            rdoc = NULL;
            i++;
        } while (fdb_iterator_next(iterator) != FDB_RESULT_ITERATOR_FAIL);
        TEST_CHK(i==n);
        status = fdb_iterator_close(iterator);
        TEST_CHK(status == FDB_RESULT_SUCCESS);

        status = fdb_kvs_close(snap_db);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
    }

    // Close all the KV store handles
    for (r = 0; r < num_kvs; ++r) {
        status = fdb_kvs_close(db[r]);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
    }
    // Rollback all the KV stores to the second commit point
    status = fdb_rollback_all(dbfile, markers[3].marker);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    status = fdb_free_snap_markers(markers, num_markers);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // close db file
    fdb_close(dbfile);

    // free all resources
    fdb_shutdown();

    memleak_end();

    sprintf(bodybuf, "rollback without seqtree in %s",
            multi_kv ? "multiple kv mode:" : "single kv mode:");
    TEST_RESULT(bodybuf);
}

void tx_crash_recover_test()
{
    TEST_INIT();
    memleak_start();

    int i, r;
    char str[15];
    void *val;
    size_t vallen;

    fdb_file_handle *file;
    fdb_kvs_handle *kvs;
    fdb_status status;
    fdb_config config;
    fdb_kvs_config kvs_config;
    fdb_file_info file_info;
    uint64_t bid;
    const char *test_file = "./mvcc_test2";
    const char *test_file_c = "./mvcc_test3";

    r = system(SHELL_DEL" mvcc_test* > errorlog.txt");
    (void)r;

    config = fdb_get_default_config();
    status = fdb_open(&file, test_file, &config);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    kvs_config = fdb_get_default_kvs_config();
    status = fdb_kvs_open_default(file, &kvs, &kvs_config);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // set keys in transaction
    status = fdb_begin_transaction(file, FDB_ISOLATION_READ_UNCOMMITTED);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    for(i=0;i<10;i++){
        sprintf(str, "key%d", i);
        status = fdb_set_kv(kvs, str, strlen(str), (void*)"value", 5);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
    }
    status = fdb_end_transaction(file, FDB_COMMIT_MANUAL_WAL_FLUSH);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // custom compact
    fdb_compact(file, test_file_c);

    // begin a tx to delete keys
    status = fdb_begin_transaction(file, FDB_ISOLATION_READ_UNCOMMITTED);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    for(i=0;i<10;i++){
        sprintf(str, "key%d", i);
        status = fdb_del_kv(kvs, str, strlen(str));
        TEST_CHK(status == FDB_RESULT_SUCCESS);
    }

    status = fdb_get_file_info(file, &file_info);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    bid = file_info.file_size / config.blocksize;

    // simulate crash
    fdb_close(file);
    fdb_shutdown();

    // Now append 9K of non-block aligned garbage at the end of the file..
    r = _disk_dump(test_file_c, bid * config.blocksize,
                  (config.blocksize * 2) + (config.blocksize / 4));
    TEST_CHK(r >= 0);

    // also write non-block aligned garbage to old compact file
    r = _disk_dump(test_file, (bid + 2)*4*config.blocksize, config.blocksize/4);
    TEST_CHK(r >= 0);

    // reopen
    status = fdb_open(&file, test_file_c, &config);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    kvs_config = fdb_get_default_kvs_config();
    status = fdb_kvs_open_default(file, &kvs, &kvs_config);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // restart tx to delete keys
    status = fdb_begin_transaction(file, FDB_ISOLATION_READ_UNCOMMITTED);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    for(i=0;i<10;i++){
        sprintf(str, "key%d", i);
        status = fdb_del_kv(kvs, str, strlen(str));
        TEST_CHK(status == FDB_RESULT_SUCCESS);
    }

    // abort tx
    fdb_abort_transaction(file);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // keys from original tx should be recoverable
    for(i=0;i<10;i++){
       sprintf(str, "key%d", i);
       status = fdb_get_kv(kvs, str, strlen(str), &val, &vallen);
       TEST_CHK(status == FDB_RESULT_SUCCESS);
       free(val);
    }

    TEST_CHK(status == FDB_RESULT_SUCCESS);

    fdb_close(file);
    fdb_shutdown();
    memleak_end();
    TEST_RESULT("crash recover test");
}


void drop_kv_on_snap_iterator_test(){

    TEST_INIT();
    memleak_start();

    int r;

    fdb_status status;
    fdb_file_handle *f1;
    fdb_kvs_handle *kv, *kv2, *snap_kv;
    fdb_config fconfig = fdb_get_default_config();
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    fdb_doc *rdoc = NULL;
    fdb_iterator *iterator;

    r = system(SHELL_DEL" mvcc_test* > errorlog.txt");
    (void)r;

    fdb_open(&f1, "./mvcc_test1", &fconfig);
    fdb_kvs_open_default(f1, &kv2, &kvs_config);
    fdb_kvs_open(f1, &kv, "kv", &kvs_config);

    // write 2 seqno's
    status = fdb_set_kv(kv, (void *) "a", 1, NULL, 0);
    TEST_STATUS(status);
    status = fdb_set_kv(kv, (void *) "b", 1, NULL, 0);
    TEST_STATUS(status);
    fdb_commit(f1, FDB_COMMIT_MANUAL_WAL_FLUSH);

    // open snapshot
    status = fdb_snapshot_open(kv, &snap_kv, 2);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // open iterator on snapshot
    status = fdb_iterator_init(snap_kv, &iterator, NULL, 0, NULL, 0, FDB_ITR_NONE);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    status = fdb_kvs_close(snap_kv);
    TEST_CHK(status != FDB_RESULT_SUCCESS);

    // close kvs
    status = fdb_kvs_close(kv);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // drop kvs
    status = fdb_kvs_remove(f1, "kv");
    TEST_CHK(status != FDB_RESULT_SUCCESS);

    status = fdb_iterator_get(iterator, &rdoc);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    fdb_doc_free(rdoc);

    status = fdb_iterator_close(iterator);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_kvs_close(snap_kv);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_kvs_close(kv2);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_close(f1);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    fdb_shutdown();

    memleak_end();
    TEST_RESULT("drop kv other handle test");
}

int main(){

    concurrent_writer_iterator_test();
    in_memory_snapshot_cleanup_test();
    drop_kv_on_snap_iterator_test();
    rollback_secondary_kvs();
    multi_version_test();
#ifdef __CRC32
    crash_recovery_test(true);
    crash_recovery_test(false);
#endif
    snapshot_test();
    in_memory_snapshot_rollback_test();
    in_memory_snapshot_test();
    in_memory_snapshot_on_dirty_hbtrie_test();
    in_memory_snapshot_compaction_test();
    snapshot_clone_test();
    snapshot_parallel_clone_test();
    snapshot_stats_test();
    snapshot_with_uncomitted_data_test();
    snapshot_markers_in_file_test(true); // multi kv instance mode
    snapshot_markers_in_file_test(false); // single kv instance mode
    snapshot_with_deletes_test();
    snapshot_without_seqtree(true); // multi kv instance mode
    snapshot_without_seqtree(false); // single kv instance mode
    rollback_during_ops_test(NULL);
    rollback_forward_seqnum();
    rollback_test(false); // single kv instance mode
    rollback_test(true); // multi kv instance mode
    rollback_and_snapshot_test();
    rollback_ncommits();
    transaction_test();
    transaction_simple_api_test();
    transaction_in_memory_snapshot_test();
    transaction_post_commit_snapshot_test();
    rollback_prior_to_ops(true); // wal commit
    rollback_prior_to_ops(false); // normal commit
    snapshot_concurrent_compaction_test();
    rollback_to_zero_test(true); // multi kv instance mode
    rollback_to_zero_test(false); // single kv instance mode
    rollback_to_zero_after_compact_test(false); // single kv instance mode
    rollback_to_zero_after_compact_test(true); // multi kv instance mode
    rollback_all_test(true); // multi kv instance mode
    rollback_all_test(false); // single kv instance mode
    rollback_to_wal_test(true); // multi kv instance mode
    rollback_to_wal_test(false); // single kv instance mode
    rollback_drop_multi_files_kvs_test();
    rollback_without_seqtree(true); // multi kv instance mode
    rollback_without_seqtree(false); // single kv instance mode
    tx_crash_recover_test();
    auto_compaction_snapshots_test(); // test snapshots with auto-compaction

    return 0;
}
