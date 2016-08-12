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
#if !defined(WIN32) && !defined(_WIN32)
#include <unistd.h>
#endif

#include "libforestdb/forestdb.h"
#include "test.h"

#include "internal_types.h"
#include "functional_util.h"


void iterator_test()
{
    TEST_INIT();

    memleak_start();

    int i, r;
    int n = 10;
    fdb_file_handle *dbfile;
    fdb_kvs_handle *db, *kv1;;
    fdb_doc **doc = alca(fdb_doc*, n);
    fdb_doc *rdoc = NULL;
    fdb_status status;
    fdb_iterator *iterator;

    char keybuf[256], metabuf[256], bodybuf[256], temp[256];

    // remove  all previous iterator_test files
    r = system(SHELL_DEL" iterator_test* > errorlog.txt");
    (void)r;

    fdb_config fconfig = fdb_get_default_config();
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    fconfig.buffercache_size = 0;
    fconfig.wal_threshold = 1024;
    fconfig.flags = FDB_OPEN_FLAG_CREATE;
    fconfig.compaction_threshold = 0;
    fconfig.purging_interval = 1; // retain deletes before compaction

    // open db
    fdb_open(&dbfile, "./iterator_test1", &fconfig);
    fdb_kvs_open_default(dbfile, &db, &kvs_config);
    status = fdb_set_log_callback(db, logCallbackFunc,
                                  (void *) "iterator_test");
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // Create another KV store..
    status = fdb_kvs_open(dbfile, &kv1, "kv1", &kvs_config);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // insert using 'kv1' instance to ensure it does not interfere
    for (i=0;i<n;++i){
        sprintf(keybuf, "kEy%d", i);
        sprintf(metabuf, "mEta%d", i);
        sprintf(bodybuf, "bOdy%d", i);
        fdb_doc_create(&doc[i], (void*)keybuf, strlen(keybuf),
            (void*)metabuf, strlen(metabuf), (void*)bodybuf, strlen(bodybuf));
        status = fdb_set(kv1, doc[i]);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        fdb_doc_free(doc[i]);
    }

    // insert documents of even number
    for (i=0;i<n;i+=2){
        sprintf(keybuf, "key%d", i);
        sprintf(metabuf, "meta%d", i);
        sprintf(bodybuf, "body%d", i);
        fdb_doc_create(&doc[i], (void*)keybuf, strlen(keybuf),
            (void*)metabuf, strlen(metabuf), (void*)bodybuf, strlen(bodybuf));
        fdb_set(db, doc[i]);
    }
    // manually flush WAL & commit
    fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);

    // insert documents of odd number
    for (i=1;i<n;i+=2){
        sprintf(keybuf, "key%d", i);
        sprintf(metabuf, "meta%d", i);
        sprintf(bodybuf, "body%d", i);
        fdb_doc_create(&doc[i], (void*)keybuf, strlen(keybuf),
            (void*)metabuf, strlen(metabuf), (void*)bodybuf, strlen(bodybuf));
        fdb_set(db, doc[i]);
    }
    // commit without WAL flush
    fdb_commit(dbfile, FDB_COMMIT_NORMAL);

    // now even number docs are in hb-trie & odd number docs are in WAL

    // create an iterator for full range
    fdb_iterator_init(db, &iterator, NULL, 0, NULL, 0, FDB_ITR_NONE);

    // repeat until fail
    i=0;
    do {
        status = fdb_iterator_get(iterator, &rdoc);
        TEST_CHK(status == FDB_RESULT_SUCCESS);

        TEST_CMP(rdoc->key, doc[i]->key, rdoc->keylen);
        TEST_CMP(rdoc->meta, doc[i]->meta, rdoc->metalen);
        TEST_CMP(rdoc->body, doc[i]->body, rdoc->bodylen);

        fdb_doc_free(rdoc);
        rdoc = NULL;
        i++;
    } while (fdb_iterator_next(iterator) != FDB_RESULT_ITERATOR_FAIL);
    TEST_CHK(i==10);
    fdb_iterator_close(iterator);

    // create an iterator.
    fdb_iterator_init(db, &iterator, NULL, 0, NULL, 0, FDB_ITR_NONE);

    // repeat until fail
    i=0;
    do {
        // retrieve the next doc and get the byte offset of the returned doc
        status = fdb_iterator_get_metaonly(iterator, &rdoc);
        TEST_CHK(status == FDB_RESULT_SUCCESS);

        TEST_CHK(rdoc->offset != BLK_NOT_FOUND);
        TEST_CMP(rdoc->key, doc[i]->key, rdoc->keylen);
        TEST_CMP(rdoc->meta, doc[i]->meta, rdoc->metalen);
        TEST_CHK(rdoc->body == NULL);

        fdb_doc_free(rdoc);
        rdoc = NULL;
        i++;
    } while (fdb_iterator_next(iterator) != FDB_RESULT_ITERATOR_FAIL);
    TEST_CHK(i==10);
    fdb_iterator_close(iterator);

    // create another iterator starts from doc[3]
    sprintf(keybuf, "key%d", 3);
    fdb_iterator_init(db, &iterator, (void*)keybuf, strlen(keybuf), NULL, 0,
                      FDB_ITR_NONE);

    // repeat until fail
    i=3;
    do {
        status = fdb_iterator_get(iterator, &rdoc);
        TEST_CHK(status == FDB_RESULT_SUCCESS);

        TEST_CMP(rdoc->key, doc[i]->key, rdoc->keylen);
        TEST_CMP(rdoc->meta, doc[i]->meta, rdoc->metalen);
        TEST_CMP(rdoc->body, doc[i]->body, rdoc->bodylen);

        fdb_doc_free(rdoc);
        rdoc = NULL;
        i++;
    } while (fdb_iterator_next(iterator) != FDB_RESULT_ITERATOR_FAIL);
    TEST_CHK(i==10);
    fdb_iterator_close(iterator);

    // create another iterator for the range of doc[4] ~ doc[8]
    sprintf(keybuf, "key%d", 4);
    sprintf(temp, "key%d", 8);
    fdb_iterator_init(db, &iterator, (void*)keybuf, strlen(keybuf),
        (void*)temp, strlen(temp), FDB_ITR_NONE);

    // repeat until fail
    i=4;
    do {
        status = fdb_iterator_get(iterator, &rdoc);
        TEST_CHK(status == FDB_RESULT_SUCCESS);

        TEST_CMP(rdoc->key, doc[i]->key, rdoc->keylen);
        TEST_CMP(rdoc->meta, doc[i]->meta, rdoc->metalen);
        TEST_CMP(rdoc->body, doc[i]->body, rdoc->bodylen);

        fdb_doc_free(rdoc);
        rdoc = NULL;
        i++;
    } while (fdb_iterator_next(iterator) != FDB_RESULT_ITERATOR_FAIL);
    TEST_CHK(i==9);
    fdb_iterator_close(iterator);

    // create another iterator for the range of doc[5] ~ doc[7]
    fdb_iterator_init(db, &iterator, (void*)keybuf, strlen(keybuf),
        (void*)temp, strlen(temp), FDB_ITR_SKIP_MIN_KEY | FDB_ITR_SKIP_MAX_KEY);

    // repeat until fail
    i=5;
    do {
        status = fdb_iterator_get(iterator, &rdoc);
        TEST_CHK(status == FDB_RESULT_SUCCESS);

        TEST_CMP(rdoc->key, doc[i]->key, rdoc->keylen);
        TEST_CMP(rdoc->meta, doc[i]->meta, rdoc->metalen);
        TEST_CMP(rdoc->body, doc[i]->body, rdoc->bodylen);

        fdb_doc_free(rdoc);
        rdoc = NULL;
        i++;
    } while (fdb_iterator_next(iterator) != FDB_RESULT_ITERATOR_FAIL);
    TEST_CHK(i==8);
    fdb_iterator_close(iterator);

    // remove document #8 and #9
    fdb_doc_create(&rdoc, doc[8]->key, doc[8]->keylen, doc[8]->meta,
                   doc[8]->metalen, NULL, 0);
    status = fdb_del(db, rdoc);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    fdb_doc_free(rdoc);
    rdoc = NULL;
    fdb_doc_create(&rdoc, doc[9]->key, doc[9]->keylen, doc[9]->meta,
                   doc[9]->metalen, NULL, 0);
    status = fdb_del(db, rdoc);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    fdb_doc_free(rdoc);
    rdoc = NULL;
    // commit
    fdb_commit(dbfile, FDB_COMMIT_NORMAL);

    // create an iterator for full range
    fdb_iterator_init(db, &iterator, NULL, 0, NULL, 0, FDB_ITR_NONE);
    // repeat until fail
    i=0;
    do {
        status = fdb_iterator_get(iterator, &rdoc);
        TEST_CHK(status == FDB_RESULT_SUCCESS);

        TEST_CMP(rdoc->key, doc[i]->key, rdoc->keylen);
        TEST_CMP(rdoc->meta, doc[i]->meta, rdoc->metalen);
        if (i < 8) {
            TEST_CMP(rdoc->body, doc[i]->body, rdoc->bodylen);
        } else {
            TEST_CHK(rdoc->deleted == true);
        }

        fdb_doc_free(rdoc);
        rdoc = NULL;
        i++;
    } while (fdb_iterator_next(iterator) != FDB_RESULT_ITERATOR_FAIL);
    TEST_CHK(i==10);
    fdb_iterator_close(iterator);

    // create an iterator for full range, but no deletes.
    fdb_iterator_init(db, &iterator, NULL, 0, NULL, 0, FDB_ITR_NO_DELETES);
    // repeat until fail
    i=0;
    do {
        status = fdb_iterator_get(iterator, &rdoc);
        TEST_CHK(status == FDB_RESULT_SUCCESS);

        TEST_CMP(rdoc->key, doc[i]->key, rdoc->keylen);
        TEST_CMP(rdoc->meta, doc[i]->meta, rdoc->metalen);
        TEST_CMP(rdoc->body, doc[i]->body, rdoc->bodylen);

        fdb_doc_free(rdoc);
        rdoc = NULL;
        i++;
    } while (fdb_iterator_next(iterator) != FDB_RESULT_ITERATOR_FAIL);
    TEST_CHK(i==8);
    fdb_iterator_close(iterator);

    // create an iterator for range of doc[4] ~ doc[8], but no deletes.
    sprintf(keybuf, "key%d", 4);
    sprintf(temp, "key%d", 8);
    fdb_iterator_init(db, &iterator, keybuf, strlen(keybuf), temp, strlen(temp),
                      FDB_ITR_NO_DELETES);
    // repeat until fail
    i=4;
    do {
        status = fdb_iterator_get(iterator, &rdoc);
        TEST_CHK(status == FDB_RESULT_SUCCESS);

        TEST_CMP(rdoc->key, doc[i]->key, rdoc->keylen);
        TEST_CMP(rdoc->meta, doc[i]->meta, rdoc->metalen);
        TEST_CHK(rdoc->deleted == false);

        fdb_doc_free(rdoc);
        rdoc = NULL;
        i++;
    } while (fdb_iterator_next(iterator) != FDB_RESULT_ITERATOR_FAIL);
    TEST_CHK(i==8);
    fdb_iterator_close(iterator);

    // close kvs1 instance
    fdb_kvs_close(kv1);
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

    TEST_RESULT("iterator test");
}

void iterator_with_concurrent_updates_test()
{
    // unit test for MB-12287
    TEST_INIT();
    memleak_start();

    int i, n=10;
    int r;
    fdb_file_handle *dbfile;
    fdb_kvs_handle *db1, *db2, *db3;
    fdb_iterator *itr;
    fdb_config fconfig;
    fdb_kvs_config kvs_config;
    fdb_doc **doc = alca(fdb_doc*, n);
    fdb_doc *rdoc = NULL;
    fdb_status status;
    char keybuf[256], bodybuf[256];

    // remove previous iterator_test files
    r = system(SHELL_DEL" iterator_test* > errorlog.txt");
    (void)r;

    // open db1, db2, db3 on the same file
    fconfig = fdb_get_default_config();
    fconfig.seqtree_opt = FDB_SEQTREE_USE; // enable seqtree since get_byseq
    kvs_config = fdb_get_default_kvs_config();
    fdb_open(&dbfile, "./iterator_test1", &fconfig);

    fdb_kvs_open_default(dbfile, &db1, &kvs_config);
    status = fdb_set_log_callback(db1, logCallbackFunc,
                                  (void *) "iterator_concurrent_update_test");
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    fdb_kvs_open_default(dbfile, &db2, &kvs_config);
    status = fdb_set_log_callback(db2, logCallbackFunc,
                                  (void *) "iterator_concurrent_update_test");
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    fdb_kvs_open_default(dbfile, &db3, &kvs_config);
    status = fdb_set_log_callback(db3, logCallbackFunc,
                                  (void *) "iterator_concurrent_update_test");
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // insert docs using db1
    for (i=0;i<10;++i){
        sprintf(keybuf, "key%d", i);
        sprintf(bodybuf, "body%d", i);
        fdb_doc_create(&doc[i], (void*)keybuf, strlen(keybuf), NULL, 0,
                       (void*)bodybuf, strlen(bodybuf));
        fdb_set(db1, doc[i]);
    }
    fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);

    // create an iterator using db2
    fdb_iterator_init(db2, &itr, NULL, 0, NULL, 0, FDB_ITR_NONE);
    r = 0;
    do {
        status = fdb_iterator_get(itr, &rdoc);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        TEST_CMP(rdoc->key, doc[r]->key, rdoc->keylen);
        TEST_CMP(rdoc->body, doc[r]->body, rdoc->bodylen);
        r++;
        fdb_doc_free(rdoc);
        rdoc = NULL;
    } while (fdb_iterator_next(itr) == FDB_RESULT_SUCCESS);
    fdb_iterator_close(itr);
    TEST_CHK(r == n);

    // same for sequence number
    fdb_iterator_sequence_init(db3, &itr, 0, 0, FDB_ITR_NONE);
    r = 0;
    do {
        status = fdb_iterator_get(itr, &rdoc);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        r++;
        TEST_CHK(rdoc->seqnum == (fdb_seqnum_t)r);
        fdb_doc_free(rdoc);
        rdoc = NULL;
    } while (fdb_iterator_next(itr) == FDB_RESULT_SUCCESS);
    fdb_iterator_close(itr);
    TEST_CHK(r == n);

    fdb_close(dbfile);

    // free all documents
    for (i=0;i<n;++i){
        fdb_doc_free(doc[i]);
    }

    fdb_shutdown();

    memleak_end();
    TEST_RESULT("iterator with concurrent updates test");
}

void iterator_compact_uncommitted_db()
{
    TEST_INIT();
    memleak_start();

    int i, r;
    int n = 10;
    char keybuf[256], bodybuf[256];
    fdb_file_handle *dbfile;
    fdb_kvs_handle *db;
    fdb_status status;
    fdb_iterator *it;
    fdb_config fconfig = fdb_get_default_config();
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    fconfig.wal_threshold = 1024;
    fconfig.seqtree_opt = FDB_SEQTREE_USE; // enable seqtree since get_byseq
    fconfig.flags = FDB_OPEN_FLAG_CREATE;

    // remove previous iterator_test files
    r = system(SHELL_DEL" iterator_test* > errorlog.txt");
    (void)r;

    // open db
    fdb_open(&dbfile, "./iterator_test1", &fconfig);
    fdb_kvs_open(dbfile, &db, "db1", &kvs_config);


    // set docs
    for (i=0;i<n;++i){
        sprintf(keybuf, "key%d", i);
        sprintf(bodybuf, "body%d", i);
        fdb_set_kv(db, keybuf, strlen(keybuf),
                bodybuf, strlen(bodybuf));
    }

    // count number of iteratable docs
    status = fdb_iterator_sequence_init(db, &it, 0, 0, FDB_ITR_NONE);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    i=0;
    do { ++i; }
    while (fdb_iterator_next(it) != FDB_RESULT_ITERATOR_FAIL);
    fdb_iterator_close(it);
    TEST_CHK(i == n);

    // compact
    fdb_compact(dbfile, NULL);

    // set again
    for (i=0;i<n;++i){
        sprintf(keybuf, "key%d", i);
        sprintf(bodybuf, "body%d", i);
        fdb_set_kv(db, keybuf, strlen(keybuf),
                bodybuf, strlen(bodybuf));
    }

    // count number of iteratable docs
    status = fdb_iterator_sequence_init(db, &it, 0, 0, FDB_ITR_NONE);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    i=0;
    do { ++i; }
    while (fdb_iterator_next(it) != FDB_RESULT_ITERATOR_FAIL);
    fdb_iterator_close(it);
    TEST_CHK(i == n);


    fdb_kvs_close(db);
    fdb_close(dbfile);
    fdb_shutdown();

    memleak_end();
    TEST_RESULT("iterator compact uncommitted db");
}

void iterator_seek_test()
{
    TEST_INIT();

    memleak_start();

    int i, r;
    int n = 10;
    fdb_file_handle *dbfile;
    fdb_kvs_handle *db, *kv1;
    fdb_doc **doc = alca(fdb_doc*, n);
    fdb_doc *rdoc = NULL;
    fdb_status status;
    fdb_iterator *iterator;

    char keybuf[256], metabuf[256], bodybuf[256];

    // remove previous iterator_test files
    r = system(SHELL_DEL" iterator_test* > errorlog.txt");
    (void)r;

    fdb_config fconfig = fdb_get_default_config();
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    fconfig.buffercache_size = 0;
    fconfig.wal_threshold = 1024;
    fconfig.flags = FDB_OPEN_FLAG_CREATE;
    fconfig.compaction_threshold = 0;
    fconfig.purging_interval = 1; // retain deletes before compaction

    // open db
    fdb_open(&dbfile, "./iterator_test1", &fconfig);
    fdb_kvs_open_default(dbfile, &db, &kvs_config);
    status = fdb_set_log_callback(db, logCallbackFunc,
                                  (void *) "iterator_seek_test");
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // Create another KV store..
    status = fdb_kvs_open(dbfile, &kv1, "kv1", &kvs_config);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // insert using 'kv1' instance to ensure it does not interfere
    for (i=0;i<n;++i){
        sprintf(keybuf, "kEy%d", i);
        sprintf(metabuf, "mEta%d", i);
        sprintf(bodybuf, "bOdy%d", i);
        fdb_doc_create(&doc[i], (void*)keybuf, strlen(keybuf),
            (void*)metabuf, strlen(metabuf), (void*)bodybuf, strlen(bodybuf));
        status = fdb_set(kv1, doc[i]);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        fdb_doc_free(doc[i]);
    }

    // insert documents of odd number into the main (default) KV store handle
    for (i=1;i<n;i+=2){
        sprintf(keybuf, "key%d", i);
        sprintf(metabuf, "meta%d", i);
        sprintf(bodybuf, "body%d", i);
        fdb_doc_create(&doc[i], (void*)keybuf, strlen(keybuf),
            (void*)metabuf, strlen(metabuf), (void*)bodybuf, strlen(bodybuf));
        fdb_set(db, doc[i]);
    }
    // manually flush WAL & commit
    fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);

    // insert documents of even number
    for (i=0;i<n;i+=2){
        sprintf(keybuf, "key%d", i);
        sprintf(metabuf, "meta%d", i);
        sprintf(bodybuf, "body%d", i);
        fdb_doc_create(&doc[i], (void*)keybuf, strlen(keybuf),
            (void*)metabuf, strlen(metabuf), (void*)bodybuf, strlen(bodybuf));
        fdb_set(db, doc[i]);
    }
    // commit without WAL flush
    fdb_commit(dbfile, FDB_COMMIT_NORMAL);

    // now odd number docs are in hb-trie & even number docs are in WAL

    // create an iterator for full range
    fdb_iterator_init(db, &iterator, NULL, 0, NULL, 0, FDB_ITR_NONE);

    // seek current iterator to inside the WAL's avl tree..
    status = fdb_iterator_get(iterator, &rdoc);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    TEST_CMP(rdoc->key, doc[0]->key, rdoc->keylen);
    TEST_CMP(rdoc->meta, doc[0]->meta, rdoc->metalen);
    TEST_CMP(rdoc->body, doc[0]->body, rdoc->bodylen);
    fdb_doc_free(rdoc);
    rdoc = NULL;

    // seek forward to 2nd key ..
    i=2;
    status = fdb_iterator_seek(iterator, doc[i]->key, strlen(keybuf), 0);
    TEST_CHK(status != FDB_RESULT_ITERATOR_FAIL);
    status = fdb_iterator_get(iterator, &rdoc);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    TEST_CMP(rdoc->key, doc[i]->key, rdoc->keylen);
    TEST_CMP(rdoc->meta, doc[i]->meta, rdoc->metalen);
    TEST_CMP(rdoc->body, doc[i]->body, rdoc->bodylen);
    fdb_doc_free(rdoc);
    rdoc = NULL;

    // iterator should be able to proceed forward
    status = fdb_iterator_next(iterator);
    TEST_CHK(status != FDB_RESULT_ITERATOR_FAIL);
    status = fdb_iterator_get(iterator, &rdoc);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    i++;
    TEST_CMP(rdoc->key, doc[i]->key, rdoc->keylen);
    TEST_CMP(rdoc->meta, doc[i]->meta, rdoc->metalen);
    TEST_CMP(rdoc->body, doc[i]->body, rdoc->bodylen);
    fdb_doc_free(rdoc);
    rdoc = NULL;

    // seek forward to the last key.
    status = fdb_iterator_seek(iterator, doc[n-1]->key, strlen(keybuf), 0);
    TEST_CHK(status != FDB_RESULT_ITERATOR_FAIL);
    status = fdb_iterator_get(iterator, &rdoc);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    TEST_CMP(rdoc->key, doc[n-1]->key, rdoc->keylen);
    TEST_CMP(rdoc->meta, doc[n-1]->meta, rdoc->metalen);
    TEST_CMP(rdoc->body, doc[n-1]->body, rdoc->bodylen);
    fdb_doc_free(rdoc);
    rdoc = NULL;

    // seek backward to start key ..
    i = 0;
    status = fdb_iterator_seek(iterator, doc[i]->key, strlen(keybuf), 0);
    TEST_CHK(status != FDB_RESULT_ITERATOR_FAIL);
    status = fdb_iterator_get(iterator, &rdoc);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    TEST_CMP(rdoc->key, doc[i]->key, rdoc->keylen);
    TEST_CMP(rdoc->meta, doc[i]->meta, rdoc->metalen);
    TEST_CMP(rdoc->body, doc[i]->body, rdoc->bodylen);
    fdb_doc_free(rdoc);
    rdoc = NULL;

    // seek forward to key2 ..
    status = fdb_iterator_seek(iterator, doc[2]->key, strlen(keybuf), 0);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    i=2;
    do {
        status = fdb_iterator_get(iterator, &rdoc);
        TEST_CHK(status == FDB_RESULT_SUCCESS);

        TEST_CMP(rdoc->key, doc[i]->key, rdoc->keylen);
        TEST_CMP(rdoc->meta, doc[i]->meta, rdoc->metalen);
        TEST_CMP(rdoc->body, doc[i]->body, rdoc->bodylen);

        fdb_doc_free(rdoc);
        rdoc = NULL;
        i++;
    } while(fdb_iterator_next(iterator) != FDB_RESULT_ITERATOR_FAIL);
    TEST_CHK(i==10);

    // Seek backward again to a key in the trie...
    status = fdb_iterator_seek(iterator, doc[3]->key, strlen(keybuf), 0);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    i=3;
    do {
        status = fdb_iterator_get(iterator, &rdoc);
        TEST_CHK(status == FDB_RESULT_SUCCESS);

        TEST_CMP(rdoc->key, doc[i]->key, rdoc->keylen);
        TEST_CMP(rdoc->meta, doc[i]->meta, rdoc->metalen);
        TEST_CMP(rdoc->body, doc[i]->body, rdoc->bodylen);

        fdb_doc_free(rdoc);
        rdoc = NULL;
        i++;
    } while (fdb_iterator_next(iterator) != FDB_RESULT_ITERATOR_FAIL);
    TEST_CHK(i==10);

    fdb_iterator_close(iterator);

    // Test fdb_iterator_seek_to_max with key range
    // create an iterator for range of doc[4] ~ doc[8]
    sprintf(keybuf, "key%d", 4); // reuse buffer for start key
    sprintf(metabuf, "key%d", 8); // reuse buffer for end_key
    status = fdb_iterator_init(db, &iterator, keybuf, strlen(keybuf),
                      metabuf, strlen(metabuf),
                      FDB_ITR_NO_DELETES);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    i = 8;
    status = fdb_iterator_seek_to_max(iterator);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_iterator_get(iterator, &rdoc);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    TEST_CMP(rdoc->key, doc[i]->key, rdoc->keylen);
    TEST_CMP(rdoc->meta, doc[i]->meta, rdoc->metalen);
    TEST_CMP(rdoc->body, doc[i]->body, rdoc->bodylen);
    fdb_doc_free(rdoc);
    rdoc = NULL;

    // test fdb_iterator_seek_to_min
    i = 4;
    status = fdb_iterator_seek_to_min(iterator);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_iterator_get(iterator, &rdoc);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    TEST_CMP(rdoc->key, doc[i]->key, rdoc->keylen);
    TEST_CMP(rdoc->meta, doc[i]->meta, rdoc->metalen);
    TEST_CMP(rdoc->body, doc[i]->body, rdoc->bodylen);
    fdb_doc_free(rdoc);
    rdoc = NULL;

    status = fdb_iterator_close(iterator);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // Test fdb_iterator_seek_to_max over full range
    status = fdb_iterator_init(db, &iterator, NULL, 0, NULL, 0, FDB_ITR_NONE);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    i = n - 1;
    status = fdb_iterator_seek_to_max(iterator);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_iterator_get(iterator, &rdoc);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    TEST_CMP(rdoc->key, doc[i]->key, rdoc->keylen);
    TEST_CMP(rdoc->meta, doc[i]->meta, rdoc->metalen);
    TEST_CMP(rdoc->body, doc[i]->body, rdoc->bodylen);
    fdb_doc_free(rdoc);
    rdoc = NULL;

    // test fdb_iterator_seek_to_min
    i = 0;
    status = fdb_iterator_seek_to_min(iterator);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_iterator_get(iterator, &rdoc);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    TEST_CMP(rdoc->key, doc[i]->key, rdoc->keylen);
    TEST_CMP(rdoc->meta, doc[i]->meta, rdoc->metalen);
    TEST_CMP(rdoc->body, doc[i]->body, rdoc->bodylen);
    fdb_doc_free(rdoc);
    rdoc = NULL;

    // seek to max using a non-existent FFFF key
    if (status == FDB_RESULT_SUCCESS) {
        uint8_t *big_seek_key = alca(uint8_t, FDB_MAX_KEYLEN);
        memset(big_seek_key, 0xff, FDB_MAX_KEYLEN);
        status = fdb_iterator_seek(iterator, big_seek_key, FDB_MAX_KEYLEN,
                                   FDB_ITR_SEEK_LOWER);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        i = n - 1;
        status = fdb_iterator_get(iterator, &rdoc);
        TEST_CHK(status == FDB_RESULT_SUCCESS);

        TEST_CMP(rdoc->key, doc[i]->key, rdoc->keylen);
        TEST_CMP(rdoc->meta, doc[i]->meta, rdoc->metalen);
        TEST_CMP(rdoc->body, doc[i]->body, rdoc->bodylen);
        fdb_doc_free(rdoc);
        rdoc = NULL;
    }

    status = fdb_iterator_close(iterator);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // delete documents of even number so WAL only has deleted docs
    for (i=0;i<n;i+=2){
        status = fdb_del(db, doc[i]);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
    }
    // commit without WAL flush
    fdb_commit(dbfile, FDB_COMMIT_NORMAL);

    // create an iterator for full range
    fdb_iterator_init(db, &iterator, NULL, 0, NULL, 0, FDB_ITR_NONE);

    // seek forward to 2nd key ..
    rdoc = NULL;
    i=2;
    status = fdb_iterator_seek(iterator, doc[i]->key, strlen(keybuf), 0);
    TEST_CHK(status != FDB_RESULT_ITERATOR_FAIL);
    status = fdb_iterator_get(iterator, &rdoc);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    TEST_CMP(rdoc->key, doc[i]->key, rdoc->keylen);
    TEST_CMP(rdoc->meta, doc[i]->meta, rdoc->metalen);
    TEST_CMP(rdoc->body, doc[i]->body, rdoc->bodylen);
    fdb_doc_free(rdoc);
    rdoc = NULL;

    status = fdb_iterator_close(iterator);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // close the kvs kv1
    fdb_kvs_close(kv1);
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

    TEST_RESULT("iterator seek test");
}

void iterator_complete_test(int insert_opt, int delete_opt)
{
    TEST_INIT();

    int n = 30;
    int i, r, c;
    int *doc_status = alca(int, n+1); // 0:HB+trie, 1:WAL, 2:deleted
    char cmd[256];
    char key[256], value[256];
    char keystr[] = "key%06d";
    char keystr_mid[] = "key%06d+";
    char valuestr[] = "value%08d";
    char valuestr2[] = "value%08d(WAL)";
    fdb_file_handle *dbfile;
    fdb_kvs_handle *db, *db_prev, *db_next;
    fdb_config config;
    fdb_kvs_config kvs_config;
    fdb_doc *doc = NULL;
    fdb_iterator *fit;
    fdb_iterator_opt_t itr_opt;
    fdb_status s;
    uint64_t mask = 0x11111111111; //0x11111111111

    sprintf(cmd, SHELL_DEL " iterator_test*");
    r = system(cmd);
    (void)r;

    memleak_start();

    config = fdb_get_default_config();
    config.purging_interval = 1; // retain deletes before compaction
    kvs_config = fdb_get_default_kvs_config();
    s = fdb_open(&dbfile, "./iterator_test", &config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    s = fdb_kvs_open(dbfile, &db_prev, "prev KVS", &kvs_config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_kvs_open(dbfile, &db, "cur KVS", &kvs_config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_kvs_open(dbfile, &db_next, "next KVS", &kvs_config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    sprintf(key, "prev_key");
    sprintf(value, "prev_value");
    s = fdb_set_kv(db_prev, key, strlen(key)+1, value, strlen(value)+1);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    sprintf(key, "next_key");
    sprintf(value, "next_value");
    s = fdb_set_kv(db_next, key, strlen(key)+1, value, strlen(value)+1);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    sprintf(key, "next_key2");
    sprintf(value, "next_value2");
    s = fdb_set_kv(db_next, key, strlen(key)+1, value, strlen(value)+1);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    s = fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    if (insert_opt == 0) {
        // HB+trie contains all keys
        // WAL contains even number keys only
        for (i=0;i<n;++i){
            sprintf(key, keystr, (int)i);
            sprintf(value, valuestr, (int)i);
            s = fdb_set_kv(db, key, strlen(key)+1, value, strlen(value)+1);
            TEST_CHK(s == FDB_RESULT_SUCCESS);
            doc_status[i] = 0;
        }
        s = fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        if (delete_opt) {
            // remove doc #15
            i = 15;
            sprintf(key, keystr, (int)i);
            s = fdb_del_kv(db, key, strlen(key)+1);
            TEST_CHK(s == FDB_RESULT_SUCCESS);
            s = fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);
            TEST_CHK(s == FDB_RESULT_SUCCESS);
            doc_status[i] = 2;
        }

        for (i=0;i<n;i+=2){
            sprintf(key, keystr, (int)i);
            sprintf(value, valuestr2, (int)i);
            s = fdb_set_kv(db, key, strlen(key)+1, value, strlen(value)+1);
            TEST_CHK(s == FDB_RESULT_SUCCESS);
            doc_status[i] = 1;
        }
        s = fdb_commit(dbfile, FDB_COMMIT_NORMAL);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
    } else if (insert_opt == 1) {
        // HB+trie contains all keys
        // WAL contains odd number keys only
        for (i=0;i<n;++i){
            sprintf(key, keystr, (int)i);
            sprintf(value, valuestr, (int)i);
            s = fdb_set_kv(db, key, strlen(key)+1, value, strlen(value)+1);
            TEST_CHK(s == FDB_RESULT_SUCCESS);
            doc_status[i] = 0;
        }
        s = fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        for (i=1;i<n;i+=2){
            sprintf(key, keystr, (int)i);
            sprintf(value, valuestr2, (int)i);
            s = fdb_set_kv(db, key, strlen(key)+1, value, strlen(value)+1);
            TEST_CHK(s == FDB_RESULT_SUCCESS);
            doc_status[i] = 1;
        }
        if (delete_opt) {
            // remove doc #15
            i = 15;
            sprintf(key, keystr, (int)i);
            s = fdb_del_kv(db, key, strlen(key)+1);
            TEST_CHK(s == FDB_RESULT_SUCCESS);
            doc_status[i] = 2;
        }
        s = fdb_commit(dbfile, FDB_COMMIT_NORMAL);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
    } else if (insert_opt == 2) {
        // HB+trie contains odd number keys
        // WAL contains even number keys
        for (i=1;i<n;i+=2){
            sprintf(key, keystr, (int)i);
            sprintf(value, valuestr, (int)i);
            s = fdb_set_kv(db, key, strlen(key)+1, value, strlen(value)+1);
            TEST_CHK(s == FDB_RESULT_SUCCESS);
            doc_status[i] = 0;
        }
        s = fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        if (delete_opt) {
            // remove doc #15
            i = 15;
            sprintf(key, keystr, (int)i);
            s = fdb_del_kv(db, key, strlen(key)+1);
            TEST_CHK(s == FDB_RESULT_SUCCESS);
            s = fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);
            TEST_CHK(s == FDB_RESULT_SUCCESS);
            doc_status[i] = 2;
        }

        for (i=0;i<n;i+=2){
            sprintf(key, keystr, (int)i);
            sprintf(value, valuestr2, (int)i);
            s = fdb_set_kv(db, key, strlen(key)+1, value, strlen(value)+1);
            TEST_CHK(s == FDB_RESULT_SUCCESS);
            doc_status[i] = 1;
        }
        s = fdb_commit(dbfile, FDB_COMMIT_NORMAL);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
    } else if (insert_opt == 3) {
        // HB+trie contains even number keys
        // WAL contains odd number keys
        for (i=0;i<n;i+=2){
            sprintf(key, keystr, (int)i);
            sprintf(value, valuestr, (int)i);
            s = fdb_set_kv(db, key, strlen(key)+1, value, strlen(value)+1);
            TEST_CHK(s == FDB_RESULT_SUCCESS);
            doc_status[i] = 0;
        }
        s = fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        for (i=1;i<n;i+=2){
            sprintf(key, keystr, (int)i);
            sprintf(value, valuestr2, (int)i);
            s = fdb_set_kv(db, key, strlen(key)+1, value, strlen(value)+1);
            TEST_CHK(s == FDB_RESULT_SUCCESS);
            doc_status[i] = 1;
        }
        if (delete_opt) {
            // remove doc #15
            i = 15;
            sprintf(key, keystr, (int)i);
            s = fdb_del_kv(db, key, strlen(key)+1);
            TEST_CHK(s == FDB_RESULT_SUCCESS);
            doc_status[i] = 2;
        }
        s = fdb_commit(dbfile, FDB_COMMIT_NORMAL);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
    } else if (insert_opt == 4) {
        // HB+trie contains all keys
        // WAL is empty
        for (i=0;i<n;i+=1){
            sprintf(key, keystr, (int)i);
            sprintf(value, valuestr, (int)i);
            s = fdb_set_kv(db, key, strlen(key)+1, value, strlen(value)+1);
            TEST_CHK(s == FDB_RESULT_SUCCESS);
            doc_status[i] = 0;
        }
        s = fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        if (delete_opt) {
            // remove doc #15
            i = 15;
            sprintf(key, keystr, (int)i);
            s = fdb_del_kv(db, key, strlen(key)+1);
            TEST_CHK(s == FDB_RESULT_SUCCESS);
            doc_status[i] = 2;
        }
        s = fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
    } else if (insert_opt == 5) {
        // HB+trie is empty
        // WAL contains all keys
        for (i=0;i<n;i+=1){
            sprintf(key, keystr, (int)i);
            sprintf(value, valuestr, (int)i);
            s = fdb_set_kv(db, key, strlen(key)+1, value, strlen(value)+1);
            TEST_CHK(s == FDB_RESULT_SUCCESS);
            doc_status[i] = 0;
        }
        s = fdb_commit(dbfile, FDB_COMMIT_NORMAL);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        if (delete_opt) {
            // remove doc #15
            i = 15;
            sprintf(key, keystr, (int)i);
            s = fdb_del_kv(db, key, strlen(key)+1);
            TEST_CHK(s == FDB_RESULT_SUCCESS);
            doc_status[i] = 2;
        }
        s = fdb_commit(dbfile, FDB_COMMIT_NORMAL);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
    } else { // if (insert_opt == 6) {
        // Both HB+trie and WAL contains all keys
        for (i=0;i<n;++i){
            sprintf(key, keystr, (int)i);
            sprintf(value, valuestr, (int)i);
            s = fdb_set_kv(db, key, strlen(key)+1, value, strlen(value)+1);
            TEST_CHK(s == FDB_RESULT_SUCCESS);
            doc_status[i] = 0;
        }
        s = fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        for (i=0;i<n;i++){
            sprintf(key, keystr, (int)i);
            sprintf(value, valuestr2, (int)i);
            s = fdb_set_kv(db, key, strlen(key)+1, value, strlen(value)+1);
            TEST_CHK(s == FDB_RESULT_SUCCESS);
            doc_status[i] = 1;
        }
        if (delete_opt) {
            // remove doc #15
            i = 15;
            sprintf(key, keystr, (int)i);
            s = fdb_del_kv(db, key, strlen(key)+1);
            TEST_CHK(s == FDB_RESULT_SUCCESS);
            doc_status[i] = 2;
        }
        s = fdb_commit(dbfile, FDB_COMMIT_NORMAL);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
    }

    if (delete_opt) {
        itr_opt = FDB_ITR_NO_DELETES;
    } else {
        itr_opt = FDB_ITR_NONE;
    }

    s = fdb_iterator_init(db, &fit, NULL, 0, NULL, 0, itr_opt);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    if (mask & 0x1) {
        c = 0;
        do {
            s = fdb_iterator_get(fit, &doc);
            if (s != FDB_RESULT_SUCCESS) {
                if (s == FDB_RESULT_KEY_NOT_FOUND) {
                    continue;
                } else {
                    break;
                }
            }
            c += ((doc_status[c] == 2)?(1):(0));
            sprintf(value, (doc_status[c]==0)?(valuestr):(valuestr2), c);
            TEST_CMP(doc->body, value, doc->bodylen);
            fdb_doc_free(doc);
            doc = NULL;
            c++;
        } while (fdb_iterator_next(fit) != FDB_RESULT_ITERATOR_FAIL);
        TEST_CHK(c == n);
        while (fdb_iterator_prev(fit) != FDB_RESULT_ITERATOR_FAIL) {
            c--;
            s = fdb_iterator_get(fit, &doc);
            if (s != FDB_RESULT_SUCCESS) {
                if (s == FDB_RESULT_KEY_NOT_FOUND) {
                    continue;
                } else {
                    break;
                }
            }
            c -= ((doc_status[c] == 2)?(1):(0));
            sprintf(value, (doc_status[c]==0)?(valuestr):(valuestr2), c);
            TEST_CMP(doc->body, value, doc->bodylen);
            fdb_doc_free(doc);
            doc = NULL;
        }
        TEST_CHK(c == 0);
    }

    if (mask & 0x10) {
        for (i=0;i<n;++i){
            sprintf(key, keystr, (int)i);
            s = fdb_iterator_seek(fit, key, strlen(key)+1, 0x0);
            TEST_CHK(s == FDB_RESULT_SUCCESS);
            c = i;
            if (doc_status[c] == 2) {
                c++; // higher mode
            }
            do {
                s = fdb_iterator_get(fit, &doc);
                if (s != FDB_RESULT_SUCCESS) break;
                sprintf(key, keystr, (int)c);
                c += ((doc_status[c] == 2)?(1):(0));
                sprintf(value, (doc_status[c]==0)?(valuestr):(valuestr2), c);
                TEST_CMP(doc->body, value, doc->bodylen);
                fdb_doc_free(doc);
                doc = NULL;
                c++;
            } while (fdb_iterator_next(fit) != FDB_RESULT_ITERATOR_FAIL);
            TEST_CHK(c == n);
        }
    }

    if (mask & 0x100) {
        for (i=0;i<n;++i){
            sprintf(key, keystr, (int)i);
            s = fdb_iterator_seek(fit, key, strlen(key)+1, 0x0);
            TEST_CHK(s == FDB_RESULT_SUCCESS);
            c = i;
            if (doc_status[c] == 2) {
                c++; // higher mode
            }
            do {
                s = fdb_iterator_get(fit, &doc);
                if (s != FDB_RESULT_SUCCESS) break;
                sprintf(key, keystr, (int)c);
                c -= ((doc_status[c] == 2)?(1):(0));
                sprintf(value, (doc_status[c]==0)?(valuestr):(valuestr2), c);
                TEST_CMP(doc->body, value, doc->bodylen);
                fdb_doc_free(doc);
                doc = NULL;
                c--;
            } while (fdb_iterator_prev(fit) != FDB_RESULT_ITERATOR_FAIL);
            TEST_CHK(c == -1);
        }
    }

    if (mask & 0x1000) {
        for (i=0;i<n;++i){
            sprintf(key, keystr, (int)i);
            s = fdb_iterator_seek(fit, key, strlen(key)+1, FDB_ITR_SEEK_LOWER);
            TEST_CHK(s == FDB_RESULT_SUCCESS);
            c = i;
            if (doc_status[c] == 2) {
                c--; // lower mode
            }
            do {
                s = fdb_iterator_get(fit, &doc);
                if (s != FDB_RESULT_SUCCESS) break;
                sprintf(key, keystr, (int)c);
                c += ((doc_status[c] == 2)?(1):(0));
                sprintf(value, (doc_status[c]==0)?(valuestr):(valuestr2), c);
                TEST_CMP(doc->body, value, doc->bodylen);
                fdb_doc_free(doc);
                doc = NULL;
                c++;
            } while (fdb_iterator_next(fit) != FDB_RESULT_ITERATOR_FAIL);
            TEST_CHK(c == n);
        }
    }

    if (mask & 0x10000) {
        for (i=0;i<n;++i){
            sprintf(key, keystr, (int)i);
            s = fdb_iterator_seek(fit, key, strlen(key)+1, FDB_ITR_SEEK_LOWER);
            TEST_CHK(s == FDB_RESULT_SUCCESS);
            c = i;
            if (doc_status[c] == 2) {
                c--; // lower mode
            }
            do {
                s = fdb_iterator_get(fit, &doc);
                if (s != FDB_RESULT_SUCCESS) break;
                sprintf(key, keystr, (int)c);
                c -= ((doc_status[c] == 2)?(1):(0));
                sprintf(value, (doc_status[c]==0)?(valuestr):(valuestr2), c);
                TEST_CMP(doc->body, value, doc->bodylen);
                fdb_doc_free(doc);
                doc = NULL;
                c--;
            } while (fdb_iterator_prev(fit) != FDB_RESULT_ITERATOR_FAIL);
            TEST_CHK(c == -1);
        }
    }

    if (mask & 0x100000) {
        for (i=0;i<n;++i){
            sprintf(key, keystr_mid, (int)i);
            s = fdb_iterator_seek(fit, key, strlen(key)+1, 0x0);
            (void)s;
            c = i+1;
            if (doc_status[c] == 2) {
                c++; // higher mode
            }
            do {
                s = fdb_iterator_get(fit, &doc);
                if (s != FDB_RESULT_SUCCESS) break;
                sprintf(key, keystr_mid, (int)c);
                c += ((doc_status[c] == 2)?(1):(0));
                sprintf(value, (doc_status[c]==0)?(valuestr):(valuestr2), c);
                TEST_CMP(doc->body, value, doc->bodylen);
                fdb_doc_free(doc);
                doc = NULL;
                c++;
            } while (fdb_iterator_next(fit) != FDB_RESULT_ITERATOR_FAIL);
            TEST_CHK(c == n);
        }
    }

    if (mask & 0x1000000) {
        for (i=0;i<n;++i){
            sprintf(key, keystr_mid, (int)i);
            s = fdb_iterator_seek(fit, key, strlen(key)+1, 0x0);
            (void)s;
            c = i+1;
            if (doc_status[c] == 2) {
                c++; // higher mode
            }
            do {
                s = fdb_iterator_get(fit, &doc);
                if (s != FDB_RESULT_SUCCESS) break;
                sprintf(key, keystr_mid, (int)c);
                c -= ((doc_status[c] == 2)?(1):(0));
                sprintf(value, (doc_status[c]==0)?(valuestr):(valuestr2), c);
                TEST_CMP(doc->body, value, doc->bodylen);
                fdb_doc_free(doc);
                doc = NULL;
                c--;
            } while (fdb_iterator_prev(fit) != FDB_RESULT_ITERATOR_FAIL);
            if (i == n-1) {
                TEST_CHK(c == n);
            } else {
                TEST_CHK(c == -1);
            }
        }
    }

    if (mask & 0x10000000) {
        for (i=0;i<n;++i){
            sprintf(key, keystr_mid, (int)i);
            s = fdb_iterator_seek(fit, key, strlen(key)+1, FDB_ITR_SEEK_LOWER);
            TEST_CHK(s == FDB_RESULT_SUCCESS);
            c = i;
            if (doc_status[c] == 2) {
                c--; // lower mode
            }
            do {
                s = fdb_iterator_get(fit, &doc);
                if (s != FDB_RESULT_SUCCESS) break;
                sprintf(key, keystr_mid, (int)c);
                c += ((doc_status[c] == 2)?(1):(0));
                sprintf(value, (doc_status[c]==0)?(valuestr):(valuestr2), c);
                TEST_CMP(doc->body, value, doc->bodylen);
                fdb_doc_free(doc);
                doc = NULL;
                c++;
            } while (fdb_iterator_next(fit) != FDB_RESULT_ITERATOR_FAIL);
            TEST_CHK(c == n);
        }
    }

    if (mask & 0x100000000) {
        for (i=0;i<n;++i){
            sprintf(key, keystr_mid, (int)i);
            s = fdb_iterator_seek(fit, key, strlen(key)+1, FDB_ITR_SEEK_LOWER);
            TEST_CHK(s == FDB_RESULT_SUCCESS);
            c = i;
            if (doc_status[c] == 2) {
                c--; // lower mode
            }
            do {
                s = fdb_iterator_get(fit, &doc);
                if (s != FDB_RESULT_SUCCESS) break;
                sprintf(key, keystr_mid, (int)c);
                c -= ((doc_status[c] == 2)?(1):(0));
                sprintf(value, (doc_status[c]==0)?(valuestr):(valuestr2), c);
                TEST_CMP(doc->body, value, doc->bodylen);
                fdb_doc_free(doc);
                doc = NULL;
                c--;
            } while (fdb_iterator_prev(fit) != FDB_RESULT_ITERATOR_FAIL);
            TEST_CHK(c == -1);
        }
    }

    if (mask & 0x1000000000) {
        s = fdb_iterator_seek_to_min(fit);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        c = 0;
        do {
            s = fdb_iterator_get(fit, &doc);
            if (s != FDB_RESULT_SUCCESS) break;
            sprintf(key, keystr_mid, (int)c);
            c += ((doc_status[c] == 2)?(1):(0));
            sprintf(value, (doc_status[c]==0)?(valuestr):(valuestr2), c);
            TEST_CMP(doc->body, value, doc->bodylen);
            fdb_doc_free(doc);
            doc = NULL;
            c++;
        } while (fdb_iterator_next(fit) != FDB_RESULT_ITERATOR_FAIL);
        TEST_CHK(c == n);

        s = fdb_iterator_seek_to_max(fit);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        c = n-1;
        do {
            s = fdb_iterator_get(fit, &doc);
            if (s != FDB_RESULT_SUCCESS) break;
            sprintf(key, keystr_mid, (int)c);
            c -= ((doc_status[c] == 2)?(1):(0));
            sprintf(value, (doc_status[c]==0)?(valuestr):(valuestr2), c);
            TEST_CMP(doc->body, value, doc->bodylen);
            fdb_doc_free(doc);
            doc = NULL;
            c--;
        } while (fdb_iterator_prev(fit) != FDB_RESULT_ITERATOR_FAIL);
        TEST_CHK(c == -1);
    }
    s = fdb_iterator_close(fit);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    if (mask & 0x10000000000) {
        // create an iterator with an end key and skip max key option
        i = n/3*2;
        sprintf(key, keystr, (int)i);
        s = fdb_iterator_init(db, &fit, NULL, 0, key, strlen(key)+1,
                              FDB_ITR_SKIP_MAX_KEY);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        s = fdb_iterator_seek_to_max(fit);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        s = fdb_iterator_get(fit, &doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        c = i-1;
        sprintf(value, (doc_status[c]==0)?(valuestr):(valuestr2), c);
        TEST_CMP(doc->body, value, doc->bodylen);
        fdb_doc_free(doc);
        doc = NULL;
        s = fdb_iterator_close(fit);
        TEST_CHK(s == FDB_RESULT_SUCCESS);

        // create an iterator with an start key and skip min key option
        i = n/3;
        sprintf(key, keystr, (int)i);
        s = fdb_iterator_init(db, &fit, key, strlen(key)+1, NULL, 0,
                              FDB_ITR_SKIP_MIN_KEY);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        s = fdb_iterator_seek_to_min(fit);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        s = fdb_iterator_get(fit, &doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        c = i+1;
        sprintf(value, (doc_status[c]==0)?(valuestr):(valuestr2), c);
        TEST_CMP(doc->body, value, doc->bodylen);
        fdb_doc_free(doc);
        doc = NULL;
        s = fdb_iterator_close(fit);
        TEST_CHK(s == FDB_RESULT_SUCCESS);

        s = fdb_close(dbfile);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        s = fdb_shutdown();
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        memleak_end();
    }

    sprintf(cmd, "iterator complete test ");
    if (insert_opt == 0) {
        strcat(cmd, "(HB+trie: all, WAL: even");
    } else if (insert_opt == 1) {
        strcat(cmd, "(HB+trie: all, WAL: odd");
    } else if (insert_opt == 2) {
        strcat(cmd, "(HB+trie: odd, WAL: even");
    } else if (insert_opt == 3) {
        strcat(cmd, "(HB+trie: even, WAL: odd");
    } else if (insert_opt == 4) {
        strcat(cmd, "(HB+trie: all, WAL: empty");
    } else if (insert_opt == 5) {
        strcat(cmd, "(HB+trie: empty, WAL: all");
    } else if (insert_opt == 6) {
        strcat(cmd, "(HB+trie: all, WAL: all");
    }
    if (delete_opt) {
        strcat(cmd, ", doc deletion)");
    } else {
        strcat(cmd, ")");
    }
    TEST_RESULT(cmd);
}

void iterator_extreme_key_test()
{
    TEST_INIT();

    int n = 30;
    int i, r, c;
    char cmd[256];
    char key[256], value[256];
    char keyBuf[256], valueBuf[256];
    fdb_file_handle *dbfile;
    fdb_kvs_handle *db;
    fdb_config config;
    fdb_kvs_config kvs_config;
    fdb_doc *doc = NULL;
    fdb_iterator *fit;
    fdb_status s;

    sprintf(cmd, SHELL_DEL " iterator_test*");
    r = system(cmd);
    (void)r;

    memleak_start();

    config = fdb_get_default_config();
    kvs_config = fdb_get_default_kvs_config();
    s = fdb_open(&dbfile, "./iterator_test", &config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_kvs_open(dbfile, &db, NULL, &kvs_config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    memset(key, 0xff, 256);
    for (i=1;i<n;i+=1){
        sprintf(value, "0xff length %d", (int)i);
        fdb_set_kv(db, key, i, value, strlen(value)+1);
    }
    fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);

    // Pre-allocate iterator return document memory and re-use the same
    s = fdb_doc_create(&doc, NULL, 0, NULL, 0, NULL, 0);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    doc->key = &keyBuf[0];
    doc->meta = NULL;
    doc->body = &valueBuf[0];

    s = fdb_iterator_init(db, &fit, NULL, 0, NULL, 0, 0x0);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_iterator_seek_to_max(fit);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    c = n-1;
    while (s == FDB_RESULT_SUCCESS) {
        s = fdb_iterator_get(fit, &doc);
        if (s != FDB_RESULT_SUCCESS) {
            break;
        }
        sprintf(value, "0xff length %d", (int)c);
        TEST_CMP(doc->body, value, doc->bodylen);
        s = fdb_iterator_prev(fit);
        c--;
    }

    i = 8;
    c = i;
    s = fdb_iterator_seek(fit, key, i, FDB_ITR_SEEK_LOWER);
    while (s == FDB_RESULT_SUCCESS) {
        s = fdb_iterator_get(fit, &doc);
        if (s != FDB_RESULT_SUCCESS) {
            break;
        }
        sprintf(value, "0xff length %d", (int)c);
        TEST_CMP(doc->body, value, doc->bodylen);
        s = fdb_iterator_prev(fit);
        c--;
    }

    i = 8;
    c = i;
    s = fdb_iterator_seek(fit, key, i, FDB_ITR_SEEK_LOWER);
    while (s == FDB_RESULT_SUCCESS) {
        s = fdb_iterator_get(fit, &doc);
        if (s != FDB_RESULT_SUCCESS) {
            break;
        }
        sprintf(value, "0xff length %d", (int)c);
        TEST_CMP(doc->body, value, doc->bodylen);
        s = fdb_iterator_next(fit);
        c++;
    }

    s = fdb_iterator_close(fit);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    // Initialize iterator to an extreme non-existent end_key
    s = fdb_iterator_init(db, &fit, NULL, 0, key, 256, 0x0);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_iterator_seek_to_max(fit);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    c = n-1;
    while (s == FDB_RESULT_SUCCESS) {
        s = fdb_iterator_get(fit, &doc);
        if (s != FDB_RESULT_SUCCESS) {
            break;
        }
        sprintf(value, "0xff length %d", (int)c);
        TEST_CMP(doc->body, value, doc->bodylen);
        s = fdb_iterator_prev(fit);
        c--;
    }

    s = fdb_iterator_close(fit);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_close(dbfile);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    // Release pre-allocated iterator return document buffer space
    doc->key = NULL;
    doc->body = NULL;
    s = fdb_doc_free(doc);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    s = fdb_shutdown();
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    memleak_end();
    TEST_RESULT("iterator extreme key test");
}

void iterator_inmem_snapshot_seek_test(bool flush_wal)
{
    TEST_INIT();

    memleak_start();

    int i, r;
    int n = 5;
    fdb_file_handle *dbfile;
    fdb_kvs_handle *db;
    fdb_kvs_handle *snap_db;
    fdb_doc **doc = alca(fdb_doc*, n);
    fdb_doc *rdoc = NULL;
    fdb_status status;
    fdb_iterator *iterator;

    char keybuf[256], metabuf[256], bodybuf[256];

    // remove previous mvcc_test files
    r = system(SHELL_DEL" iterator_test* > errorlog.txt");
    (void)r;

    fdb_config fconfig = fdb_get_default_config();
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    fconfig.buffercache_size = 0;
    fconfig.wal_threshold = 1024;
    fconfig.flags = FDB_OPEN_FLAG_CREATE;
    fconfig.compaction_threshold = 0;

    // open db
    status = fdb_open(&dbfile, "./iterator_test1", &fconfig);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_kvs_open_default(dbfile, &db, &kvs_config);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // ------- Setup test ----------------------------------
    for (i=0; i<n; i++){
        sprintf(keybuf, "%c2",(char)i + 'a');
        sprintf(metabuf, "meta%d", i);
        sprintf(bodybuf, "body%d", i);
        fdb_doc_create(&doc[i], (void*)keybuf, strlen(keybuf),
            (void*)metabuf, strlen(metabuf), (void*)bodybuf, strlen(bodybuf));
        fdb_set(db, doc[i]);
    }

    if (flush_wal) {
        fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);
    } else {
        fdb_commit(dbfile, FDB_COMMIT_NORMAL);
    }
    // ---------- Snapshot tests begin -----------------------
    // WAL items are not flushed...
    status = fdb_snapshot_open(db, &snap_db, FDB_SNAPSHOT_INMEM);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    status = fdb_set_log_callback(db, logCallbackFunc,
                                  (void *) "iterator_inmem_snapshot_seek_test");
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // create an iterator on the snapshot for full range
    fdb_iterator_init(snap_db, &iterator, (void*)"b2", 2, (void*)"d2", 2,
                      FDB_ITR_NO_DELETES|
                      FDB_ITR_SKIP_MAX_KEY|
                      FDB_ITR_SKIP_MIN_KEY);

    // seek to non-existent key that happens to land on the start key which
    // should not be returned since we have passed ITR_SKIP_MIN_KEY
    status = fdb_iterator_seek(iterator, "c1", 2, FDB_ITR_SEEK_LOWER);
    TEST_CHK(status == FDB_RESULT_ITERATOR_FAIL);

    // seek to non-existent key that happens to land on the end key which
    // should not be returned since we have passed ITR_SKIP_MAX_KEY
    status = fdb_iterator_seek(iterator, "c3", 2, FDB_ITR_SEEK_HIGHER);
    TEST_CHK(status == FDB_RESULT_ITERATOR_FAIL);

    fdb_iterator_close(iterator);

    // create an iterator on the snapshot for full range
    fdb_iterator_init(snap_db, &iterator, (void*)"b3", 2, (void*)"d1", 2,
                      FDB_ITR_NO_DELETES|
                      FDB_ITR_SKIP_MAX_KEY|
                      FDB_ITR_SKIP_MIN_KEY);

    // seek to non-existent key that happens to land on key that is
    // smaller than the start key which should not be returned.
    status = fdb_iterator_seek(iterator, "c1", 2, FDB_ITR_SEEK_LOWER);
    TEST_CHK(status == FDB_RESULT_ITERATOR_FAIL);

    // seek to non-existent key that happens to be land on key larger than
    // end key which should not be returned.
    status = fdb_iterator_seek(iterator, "c3", 2, FDB_ITR_SEEK_HIGHER);
    TEST_CHK(status == FDB_RESULT_ITERATOR_FAIL);

    fdb_iterator_close(iterator);

    // create an iterator on the snapshot for just 3 items within range
    fdb_iterator_init(snap_db, &iterator, (void*)"b0", 2, (void*)"e2", 2,
                      FDB_ITR_NO_DELETES|
                      FDB_ITR_SKIP_MAX_KEY|
                      FDB_ITR_SKIP_MIN_KEY);

    // seek to max key but skip max key
    // should return a key for fdb_iterator_seek_to_max
    status = fdb_iterator_seek_to_max(iterator);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_iterator_get(iterator, &rdoc);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    TEST_CMP(rdoc->key, "d2", rdoc->keylen);
    fdb_doc_free(rdoc);
    rdoc = NULL;

    // But same attempt with regular seek to max key
    // no key should be returned since we want to skip max key
    status = fdb_iterator_seek(iterator, "e2", 2, FDB_ITR_SEEK_HIGHER);
    TEST_CHK(status == FDB_RESULT_ITERATOR_FAIL);

    // seek to min key but skip min key
    // should return a key for fdb_iterator_seek_to_min
    status = fdb_iterator_seek_to_min(iterator);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_iterator_get(iterator, &rdoc);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    TEST_CMP(rdoc->key, "c2", rdoc->keylen);
    fdb_doc_free(rdoc);

    // But same attempt with regular seek to min key
    // no key should be returned since we want to skip min key
    status = fdb_iterator_seek(iterator, "b0", 2, FDB_ITR_SEEK_LOWER);
    TEST_CHK(status == FDB_RESULT_ITERATOR_FAIL);

    // seek to key outside the range that happens to land on non-existent key
    // no key should be returned
    status = fdb_iterator_seek(iterator, "b0", 2, FDB_ITR_SEEK_LOWER);
    TEST_CHK(status == FDB_RESULT_ITERATOR_FAIL);

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

    TEST_RESULT("in-memory snapshot seek test");
}

void iterator_no_deletes_test()
{

    TEST_INIT();
    memleak_start();
    int i, r, n = 10;
    fdb_file_handle *dbfile;
    fdb_kvs_handle  *kv;
    char keybuf[256], bodybuf[256];
    fdb_doc **doc = alca(fdb_doc*, n);
    fdb_doc *rdoc = NULL;
    fdb_iterator *it;
    fdb_status status;

    // remove previous iterator_test files
    r = system(SHELL_DEL" iterator_test* > errorlog.txt");
    (void)r;

    fdb_config fconfig = fdb_get_default_config();
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    fconfig.wal_threshold = 1024;
    fconfig.flags = FDB_OPEN_FLAG_CREATE;
    fconfig.compaction_threshold = 0;

    // open db
    fdb_open(&dbfile, "./iterator_test", &fconfig);
    fdb_kvs_open(dbfile, &kv, "all_docs",  &kvs_config);

    // insert docs to kv
    for (i=0;i<n;++i){
        sprintf(keybuf, "key%d", i);
        sprintf(bodybuf, "body%d", i);
        fdb_doc_create(&doc[i], (void*)keybuf, strlen(keybuf), NULL, 0,
                       (void*)bodybuf, strlen(bodybuf));
        fdb_set(kv, doc[i]);
    }

    // delete all docs
    for (i=0;i<n;i++){
        status = fdb_del_kv(kv, doc[i]->key, doc[i]->keylen);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
    }

    // commit
    fdb_commit(dbfile, FDB_COMMIT_NORMAL);

    // set doc that was deleted
    status = fdb_set(kv, doc[2]);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // get doc from db and verify not-deleted
    fdb_doc_create(&rdoc, doc[2]->key, doc[2]->keylen, NULL, 0, NULL, 0);
    status = fdb_get(kv, rdoc);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    TEST_CHK(rdoc->deleted == false);
    fdb_doc_free(rdoc);
    rdoc = NULL;

    // iterate over all docs to retrieve undeleted key
    status = fdb_iterator_init(kv, &it, NULL, 0, NULL, 0, FDB_ITR_NO_DELETES);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_iterator_get(it, &rdoc);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    if (status == FDB_RESULT_SUCCESS){
        fdb_doc_free(rdoc);
    }
    fdb_iterator_close(it);

    for (i=0;i<n;++i){
        fdb_doc_free(doc[i]);
    }

    fdb_kvs_close(kv);
    fdb_close(dbfile);
    fdb_shutdown();

    memleak_end();
    TEST_RESULT("iterator no deletes test");
}

void iterator_set_del_docs_test()
{
    TEST_INIT();
    memleak_start();

    int r;
    int i, j, k, n=100;
    int expected_doc_count=0;
    char keybuf[256], metabuf[256], bodybuf[256];
    int val2;
    fdb_file_handle *dbfile;
    fdb_iterator *it;
    fdb_kvs_handle *kv1;
    fdb_kvs_info info;
    fdb_config fconfig = fdb_get_default_config();
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    fdb_doc **doc = alca(fdb_doc*, n);
    fdb_doc *vdoc;
    r = system(SHELL_DEL" iterator_test* > errorlog.txt");
    (void)r;

    fconfig.wal_threshold = 1024;
    fconfig.flags = FDB_OPEN_FLAG_CREATE;
    fconfig.compaction_threshold = 10;
    fconfig.purging_interval = 1; //retain deletes until compaction

    fdb_open(&dbfile, "./iterator_test1", &fconfig);
    fdb_kvs_open(dbfile, &kv1, "kv1", &kvs_config);

    for(k=0;k<20;++k){
        // set n docs
        for(i=0;i<n;++i){
            sprintf(keybuf, "key%02d%03d", k, i);
            sprintf(metabuf, "meta%02d%03d", k, i);
            sprintf(bodybuf, "body%02d%03d", k, i);
            fdb_doc_create(&doc[i], (void*)keybuf, strlen(keybuf),
                (void*)metabuf, strlen(metabuf), (void*)bodybuf, strlen(bodybuf));
            fdb_set(kv1, doc[i]);
            expected_doc_count++;
        }

        // commit
        fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);

        // delete subset of recently loaded docs
        for(j=n/4;j<n/2;j++){
            fdb_del(kv1, doc[j]);
            expected_doc_count--;
        }
        fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);

        fdb_get_kvs_info(kv1, &info);
        if(info.doc_count != (size_t)expected_doc_count){
            // test already failed further debugging check info
            fdb_iterator_init(kv1, &it, NULL, 0,
                              NULL, 0, FDB_ITR_NONE);
            val2=0;
            do {
                fdb_iterator_get(it, &vdoc);
                if (!vdoc->deleted){
                    val2++;
                }
                fdb_doc_free(vdoc);
            } while (fdb_iterator_next(it) != FDB_RESULT_ITERATOR_FAIL);
            fdb_iterator_close(it);
            printf("dbdocs(%d) expected(%d)\n", val2, expected_doc_count);
        }
        TEST_CHK(info.doc_count == (size_t)expected_doc_count);

        // preliminary cleanup
        for(i=0;i<n;++i){
            fdb_doc_free(doc[i]);
        }
    }

    fdb_kvs_close(kv1);
    fdb_close(dbfile);
    fdb_shutdown();
    memleak_end();

    TEST_RESULT("iterator set del docs");
}

void iterator_del_next_test()
{
    TEST_INIT();

    memleak_start();

    int i, r;
    int n = 10;
    fdb_file_handle *dbfile;
    fdb_kvs_handle *db;
    fdb_doc **doc = alca(fdb_doc*, n);
    fdb_doc pre_alloc_doc;
    fdb_doc *rdoc = &pre_alloc_doc;
    fdb_status status;
    fdb_iterator *iterator;

    char keybuf[256], metabuf[256], bodybuf[256];
    rdoc->key = keybuf;
    rdoc->meta = metabuf;
    rdoc->body = bodybuf;
    rdoc->flags = 0;

    // remove previous iterator_test files
    r = system(SHELL_DEL" iterator_test* > errorlog.txt");
    (void)r;

    fdb_config fconfig = fdb_get_default_config();
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    fconfig.buffercache_size = 0;
    fconfig.wal_threshold = 1024;
    fconfig.flags = FDB_OPEN_FLAG_CREATE;
    fconfig.compaction_threshold = 0;

    // open db
    fdb_open(&dbfile, "./iterator_test1", &fconfig);
    fdb_kvs_open(dbfile, &db, "kv1", &kvs_config);

    status = fdb_set_log_callback(db, logCallbackFunc,
                                  (void *) "iterator_del_next_test");
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // insert documents of even number
    for (i=0;i<n;i+=2){
        sprintf(keybuf, "key%d", i);
        sprintf(metabuf, "meta%d", i);
        sprintf(bodybuf, "body%d", i);
        fdb_doc_create(&doc[i], (void*)keybuf, strlen(keybuf),
            (void*)metabuf, strlen(metabuf), (void*)bodybuf, strlen(bodybuf));
        fdb_set(db, doc[i]);
    }
    // manually flush WAL & commit
    fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);

    // insert documents of odd number
    for (i=1;i<n;i+=2){
        sprintf(keybuf, "key%d", i);
        sprintf(metabuf, "meta%d", i);
        sprintf(bodybuf, "body%d", i);
        fdb_doc_create(&doc[i], (void*)keybuf, strlen(keybuf),
            (void*)metabuf, strlen(metabuf), (void*)bodybuf, strlen(bodybuf));
        fdb_set(db, doc[i]);
    }
    // commit without WAL flush
    fdb_commit(dbfile, FDB_COMMIT_NORMAL);

    // now even number docs are in hb-trie & odd number docs are in WAL

    // create an iterator for full range
    fdb_iterator_init(db, &iterator, NULL, 0, NULL, 0, FDB_ITR_NONE);

    // repeat until fail
    i=0;
    do {
        status = fdb_iterator_get(iterator, &rdoc);
        TEST_CHK(status == FDB_RESULT_SUCCESS);

        TEST_CMP(rdoc->key, doc[i]->key, rdoc->keylen);
        TEST_CMP(rdoc->meta, doc[i]->meta, rdoc->metalen);
        TEST_CMP(rdoc->body, doc[i]->body, rdoc->bodylen);
        // Delete the document to ensure that the iteration is not affected
        status = fdb_del(db, rdoc);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        status = fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        i++;
    } while (fdb_iterator_next(iterator) != FDB_RESULT_ITERATOR_FAIL);
    TEST_CHK(i==10);

    // go back to start and retry iteration (should not be affected by deletes)
    status = fdb_iterator_seek_to_min(iterator);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // repeat full iteration until fail
    i=0;
    do {
        status = fdb_iterator_get(iterator, &rdoc);
        TEST_CHK(status == FDB_RESULT_SUCCESS);

        TEST_CMP(rdoc->key, doc[i]->key, rdoc->keylen);
        TEST_CMP(rdoc->meta, doc[i]->meta, rdoc->metalen);
        TEST_CMP(rdoc->body, doc[i]->body, rdoc->bodylen);
        i++;
    } while (fdb_iterator_next(iterator) != FDB_RESULT_ITERATOR_FAIL);
    TEST_CHK(i==10);

    fdb_iterator_close(iterator);

    fdb_close(dbfile);
    fdb_shutdown();

    // free all documents
    for (i=0;i<n;++i){
        fdb_doc_free(doc[i]);
    }

    memleak_end();

    TEST_RESULT("iterator del next test");
}

void sequence_iterator_test()
{
    TEST_INIT();

    memleak_start();

    int i, r;
    int n = 10;
    int count;
    fdb_file_handle *dbfile;
    fdb_kvs_handle *db;
    fdb_doc **doc = alca(fdb_doc*, n);
    fdb_doc *rdoc = NULL;
    fdb_status status;
    fdb_iterator *iterator;

    char keybuf[256], metabuf[256], bodybuf[256];

    // remove previous iterator_test files
    r = system(SHELL_DEL" iterator_test* > errorlog.txt");
    (void)r;

    fdb_config fconfig = fdb_get_default_config();
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    fconfig.buffercache_size = 0;
    fconfig.wal_threshold = 1024;
    fconfig.flags = FDB_OPEN_FLAG_CREATE;
    fconfig.seqtree_opt = FDB_SEQTREE_USE; // enable seqtree since get_byseq
    fconfig.compaction_threshold = 0;
    fconfig.purging_interval = 1; // retain deletes until compaction

    // open db
    fdb_open(&dbfile, "./iterator_test1", &fconfig);
    fdb_kvs_open_default(dbfile, &db, &kvs_config);
    status = fdb_set_log_callback(db, logCallbackFunc,
                                  (void *) "sequence_iterator_test");
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // insert documents of even number
    for (i=0;i<n;i+=2){
        sprintf(keybuf, "key%d", i);
        sprintf(metabuf, "meta%d", i);
        sprintf(bodybuf, "body%d", i);
        fdb_doc_create(&doc[i], (void*)keybuf, strlen(keybuf),
            (void*)metabuf, strlen(metabuf), (void*)bodybuf, strlen(bodybuf));
        fdb_set(db, doc[i]);
    }
    // manually flush WAL & commit
    fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);

    // insert documents of odd number
    for (i=1;i<n;i+=2){
        sprintf(keybuf, "key%d", i);
        sprintf(metabuf, "meta%d", i);
        sprintf(bodybuf, "body%d", i);
        fdb_doc_create(&doc[i], (void*)keybuf, strlen(keybuf),
            (void*)metabuf, strlen(metabuf), (void*)bodybuf, strlen(bodybuf));
        fdb_set(db, doc[i]);
    }
    // commit without WAL flush
    fdb_commit(dbfile, FDB_COMMIT_NORMAL);

    // now even number docs are in hb-trie & odd number docs are in WAL

    // create an iterator over sequence number range over FULL RANGE
    fdb_iterator_sequence_init(db, &iterator, 0, 0, FDB_ITR_NONE);

    // repeat until fail
    i=0;
    count = 0;
    do {
        status = fdb_iterator_get(iterator, &rdoc);
        TEST_CHK(status == FDB_RESULT_SUCCESS);

        TEST_CMP(rdoc->key, doc[i]->key, rdoc->keylen);
        TEST_CMP(rdoc->meta, doc[i]->meta, rdoc->metalen);
        TEST_CMP(rdoc->body, doc[i]->body, rdoc->bodylen);

        fdb_doc_free(rdoc);
        rdoc = NULL;
        i = (i + 2 >= n) ? 1: i + 2; // by-seq, first come even docs, then odd
        count++;
    } while (fdb_iterator_next(iterator) != FDB_RESULT_ITERATOR_FAIL);
    TEST_CHK(count==n);
    fdb_iterator_close(iterator);

    // create an iterator over sequence number.
    fdb_iterator_sequence_init(db, &iterator, 0, 0, FDB_ITR_NONE);

    // repeat until fail
    i=0;
    count = 0;
    do {
        status = fdb_iterator_get_metaonly(iterator, &rdoc);
        TEST_CHK(status == FDB_RESULT_SUCCESS);

        TEST_CMP(rdoc->key, doc[i]->key, rdoc->keylen);
        TEST_CMP(rdoc->meta, doc[i]->meta, rdoc->metalen);
        TEST_CHK(rdoc->body == NULL);

        fdb_doc_free(rdoc);
        rdoc = NULL;
        i = (i + 2 >= n) ? 1: i + 2; // by-seq, first come even docs, then odd
        count++;
    } while (fdb_iterator_next(iterator) != FDB_RESULT_ITERATOR_FAIL);
    TEST_CHK(count==n);
    fdb_iterator_close(iterator);

    // create another iterator starts from seq number 2 and ends at 9
    fdb_iterator_sequence_init(db, &iterator, 2, 7, FDB_ITR_NONE);

    // repeat until fail
    i=2;
    count = 0;
    do {
        status = fdb_iterator_get(iterator, &rdoc);
        TEST_CHK(status == FDB_RESULT_SUCCESS);

        TEST_CMP(rdoc->key, doc[i]->key, rdoc->keylen);
        TEST_CMP(rdoc->meta, doc[i]->meta, rdoc->metalen);
        TEST_CMP(rdoc->body, doc[i]->body, rdoc->bodylen);

        fdb_doc_free(rdoc);
        rdoc = NULL;
        i = (i + 2 >= n) ? 1: i + 2; // by-seq, first come even docs, then odd
        count++;
    } while (fdb_iterator_next(iterator) != FDB_RESULT_ITERATOR_FAIL);
    TEST_CHK(count==6);
    fdb_iterator_close(iterator);
    // remove document #8 and #9
    fdb_doc_create(&rdoc, doc[8]->key, doc[8]->keylen, doc[8]->meta, doc[8]->metalen, NULL, 0);
    status = fdb_del(db, rdoc);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    fdb_doc_free(rdoc);
    rdoc = NULL;
    fdb_doc_create(&rdoc, doc[9]->key, doc[9]->keylen, doc[9]->meta, doc[9]->metalen, NULL, 0);
    status = fdb_del(db, rdoc);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    fdb_doc_free(rdoc);
    rdoc = NULL;
    // commit
    fdb_commit(dbfile, FDB_COMMIT_NORMAL);

    // create an iterator for full range
    fdb_iterator_sequence_init(db, &iterator, 0, 0, FDB_ITR_NONE);
    // repeat until fail
    i=0;
    count=0;
    do {
        status = fdb_iterator_get(iterator, &rdoc);
        TEST_CHK(status == FDB_RESULT_SUCCESS);

        if (count != 8 && count != 9) { // do not look validate key8 and key9
            TEST_CMP(rdoc->key, doc[i]->key, rdoc->keylen);
            TEST_CMP(rdoc->meta, doc[i]->meta, rdoc->metalen);
            TEST_CMP(rdoc->body, doc[i]->body, rdoc->bodylen);
        } else {
            TEST_CHK(rdoc->deleted == true);
        }

        fdb_doc_free(rdoc);
        rdoc = NULL;
        // Turn around when we hit 8 as the last items, key8 and key9 are gone
        i = (i + 2 >= 8) ? 1: i + 2; // by-seq, first come even docs, then odd
        count++;
    } while (fdb_iterator_next(iterator) != FDB_RESULT_ITERATOR_FAIL);
    TEST_CHK(count==10); // 10 items, with 2 deletions
    fdb_iterator_close(iterator);

    // create an iterator for full range, but no deletes.
    fdb_iterator_sequence_init(db, &iterator, 0, 0, FDB_ITR_NO_DELETES);
    // repeat until fail
    i=0;
    count=0;
    do {
        status = fdb_iterator_get(iterator, &rdoc);
        TEST_CHK(status == FDB_RESULT_SUCCESS);

        if (i != 8 && i != 9) { // key8 and key9 are deleted
            TEST_CMP(rdoc->key, doc[i]->key, rdoc->keylen);
            TEST_CMP(rdoc->meta, doc[i]->meta, rdoc->metalen);
            TEST_CMP(rdoc->body, doc[i]->body, rdoc->bodylen);
        }

        fdb_doc_free(rdoc);
        rdoc = NULL;
        i = (i + 2 >= 8) ? 1: i + 2; // by-seq, first come even docs, then odd
        count++;
    } while (fdb_iterator_next(iterator) != FDB_RESULT_ITERATOR_FAIL);
    TEST_CHK(count==8); // 10 items, with 2 deletions
    fdb_iterator_close(iterator);

    // Update first document and test for absence of duplicates
    *((char *)doc[0]->body) = 'K'; // update key0 to Key0
    fdb_set(db, doc[0]);
    fdb_commit(dbfile, FDB_COMMIT_NORMAL);

    fdb_iterator_sequence_init(db, &iterator, 0, 0, FDB_ITR_NO_DELETES);
    // repeat until fail
    i=2; // i == 0 should not appear until the end
    count=0;
    do {
        status = fdb_iterator_get(iterator, &rdoc);
        TEST_CHK(status == FDB_RESULT_SUCCESS);

        if (i != 8 && i != 9) { // key8 and key9 are deleted
            TEST_CMP(rdoc->key, doc[i]->key, rdoc->keylen);
            TEST_CMP(rdoc->meta, doc[i]->meta, rdoc->metalen);
            TEST_CMP(rdoc->body, doc[i]->body, rdoc->bodylen);
        }

        fdb_doc_free(rdoc);
        rdoc = NULL;
        i = (i + 2 >= 8) ? 1: i + 2; // by-seq, first come even docs, then odd
        if (count == 6) i = 0; // go back to test for i=0 at the end
        count++;
    } while (fdb_iterator_next(iterator) != FDB_RESULT_ITERATOR_FAIL);
    TEST_CHK(count==8); // 10 items, with 2 deletions
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

    TEST_RESULT("sequence iterator test");
}

void sequence_iterator_duplicate_test()
{
    // Unit test for MB-12225
    TEST_INIT();

    memleak_start();

    int i, r;
    int n = 100;
    int count;
    fdb_file_handle *dbfile;
    fdb_kvs_handle *db;
    fdb_doc **doc = alca(fdb_doc*, n);
    fdb_doc *rdoc = NULL;
    fdb_status status;
    fdb_iterator *iterator;
    fdb_seqnum_t seqnum;

    char keybuf[256], metabuf[256], bodybuf[256];

    // remove previous iterator_test files
    r = system(SHELL_DEL" iterator_test* > errorlog.txt");
    (void)r;

    fdb_config fconfig = fdb_get_default_config();
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    fconfig.buffercache_size = 0;
    fconfig.seqtree_opt = FDB_SEQTREE_USE; // enable seqtree since get_byseq
    fconfig.wal_threshold = 1024;
    fconfig.compaction_threshold = 0;
    fconfig.purging_interval = 1; // retain deletes until compaction

    // open db
    fdb_open(&dbfile, "./iterator_test1", &fconfig);
    fdb_kvs_open_default(dbfile, &db, &kvs_config);
    status = fdb_set_log_callback(db, logCallbackFunc,
                                  (void *) "sequence_iterator_test");
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // insert documents first time
    for (i=0;i<n;i++){
        sprintf(keybuf, "key%d", i);
        sprintf(metabuf, "meta%d", i);
        sprintf(bodybuf, "body%d(first)", i);
        fdb_doc_create(&doc[i], (void*)keybuf, strlen(keybuf),
            (void*)metabuf, strlen(metabuf), (void*)bodybuf, strlen(bodybuf));
        fdb_set(db, doc[i]);
    }
    // manually flush WAL & commit
    fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);

    // insert documents second time
    for (i=0;i<n;i++){
        sprintf(bodybuf, "body%d(second)", i);
        fdb_doc_update(&doc[i], NULL, 0, bodybuf, strlen(bodybuf));
        fdb_set(db, doc[i]);
    }
    // manually flush WAL & commit
    fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);

    // insert documents third time (only even number documents)
    for (i=0;i<n;i+=2){
        sprintf(bodybuf, "body%d(third)", i);
        fdb_doc_update(&doc[i], NULL, 0, bodybuf, strlen(bodybuf));
        fdb_set(db, doc[i]);
    }
    // commit without WAL flushing
    fdb_commit(dbfile, FDB_COMMIT_NORMAL);

    // create an iterator over sequence number
    fdb_iterator_sequence_init(db, &iterator, 0, 220, FDB_ITR_NONE);

    // repeat until fail
    count = 0;
    seqnum = 100;
    do {
        status = fdb_iterator_get(iterator, &rdoc);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        if (seqnum < 140) { // point where WAL range & trie range overlap ends!
            seqnum += 2; // WAL overlap with trie, get unique trie keys only
        } else { // beyond this even keys in trie are also in WAL but outside..
            seqnum ++; // the iteration range, so they can be sequentially got
        }

        if (seqnum <= 200) { // uptil WAL, unique trie items are returned...
            i = seqnum - 101;
            sprintf(bodybuf, "body%d(second)", i);
        } else { // once seqnum enters WAL range only WAL elements are returned..
            i = ((seqnum - 101) % n) * 2;
            sprintf(bodybuf, "body%d(third)", i);
        }
        TEST_CMP(rdoc->key, doc[i]->key, rdoc->keylen);
        TEST_CMP(rdoc->meta, doc[i]->meta, rdoc->metalen);
        TEST_CMP(rdoc->body, bodybuf, rdoc->bodylen);
        TEST_CHK(rdoc->seqnum == seqnum);

        count++;
        fdb_doc_free(rdoc);
        rdoc = NULL;
    } while (fdb_iterator_next(iterator) != FDB_RESULT_ITERATOR_FAIL);
    TEST_CHK(count==n); // since 220 > n all keys should be iterated
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

    TEST_RESULT("sequence iterator duplicate test");
}

// MB-16406
void sequence_iterator_range_test()
{
    TEST_INIT();

    memleak_start();

    int i, r;
    int n = 10;
    int count;
    fdb_file_handle *dbfile;
    fdb_kvs_handle *db;
    fdb_doc **doc = alca(fdb_doc*, n);
    fdb_doc *rdoc = NULL;
    fdb_status status;
    fdb_iterator *iterator;
    fdb_seqnum_t seqnum;

    char keybuf[256], metabuf[256], bodybuf[256];

    // remove previous iterator_test files
    r = system(SHELL_DEL" iterator_test* > errorlog.txt");
    (void)r;

    fdb_config fconfig = fdb_get_default_config();
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    fconfig.buffercache_size = 0;
    fconfig.seqtree_opt = FDB_SEQTREE_USE; // enable seqtree since get_byseq

    // open db
    fdb_open(&dbfile, "./iterator_test1", &fconfig);
    fdb_kvs_open_default(dbfile, &db, &kvs_config);
    status = fdb_set_log_callback(db, logCallbackFunc,
                                  (void *) "sequence_iterator_test");
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // insert docs
    for (i=0;i<n;i++){
        sprintf(keybuf, "key%d", i);
        sprintf(metabuf, "meta%d", i);
        sprintf(bodybuf, "body%d", i);
        fdb_doc_create(&doc[i], (void*)keybuf, strlen(keybuf),
                                (void*)metabuf, strlen(metabuf),
                                (void*)bodybuf, strlen(bodybuf));
        fdb_set(db, doc[i]);
    }
    // manually flush WAL & commit
    fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);

    // create a full range seq iterator
    status = fdb_iterator_sequence_init(db, &iterator, 0, 0, FDB_ITR_NONE);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // repeat until fail
    count = 0;
    do {
        status = fdb_iterator_get(iterator, &rdoc);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        i = count;
        seqnum = i+1;

        TEST_CMP(rdoc->key, doc[i]->key, rdoc->keylen);
        TEST_CMP(rdoc->meta, doc[i]->meta, rdoc->metalen);
        TEST_CMP(rdoc->body, doc[i]->body, rdoc->bodylen);
        TEST_CHK(rdoc->seqnum == seqnum);

        count++;
        fdb_doc_free(rdoc);
        rdoc = NULL;
    } while (fdb_iterator_next(iterator) != FDB_RESULT_ITERATOR_FAIL);
    TEST_CHK(count == n);
    fdb_iterator_close(iterator);

    // create a partial range seq iterator with the given max seq number
    status = fdb_iterator_sequence_init(db, &iterator, 0, n/2, FDB_ITR_NONE);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // repeat until fail
    count = 0;
    do {
        status = fdb_iterator_get(iterator, &rdoc);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        i = count;
        seqnum = i+1;

        TEST_CMP(rdoc->key, doc[i]->key, rdoc->keylen);
        TEST_CMP(rdoc->meta, doc[i]->meta, rdoc->metalen);
        TEST_CMP(rdoc->body, doc[i]->body, rdoc->bodylen);
        TEST_CHK(rdoc->seqnum == seqnum);

        count++;
        fdb_doc_free(rdoc);
        rdoc = NULL;
    } while (fdb_iterator_next(iterator) != FDB_RESULT_ITERATOR_FAIL);
    TEST_CHK(count == n/2);
    fdb_iterator_close(iterator);

    // create a partial range seq iterator with the given min seq number
    status = fdb_iterator_sequence_init(db, &iterator, (n/2)+1, 0, FDB_ITR_NONE);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // repeat until fail
    count = 0;
    do {
        status = fdb_iterator_get(iterator, &rdoc);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        i = count + n/2;
        seqnum = i+1;

        TEST_CMP(rdoc->key, doc[i]->key, rdoc->keylen);
        TEST_CMP(rdoc->meta, doc[i]->meta, rdoc->metalen);
        TEST_CMP(rdoc->body, doc[i]->body, rdoc->bodylen);
        TEST_CHK(rdoc->seqnum == seqnum);

        count++;
        fdb_doc_free(rdoc);
        rdoc = NULL;
    } while (fdb_iterator_next(iterator) != FDB_RESULT_ITERATOR_FAIL);
    TEST_CHK(count == n/2);
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

    TEST_RESULT("sequence iterator range test");
}

void reverse_sequence_iterator_test()
{
    TEST_INIT();

    memleak_start();

    int i, r, count;
    int n = 10;
    fdb_file_handle *dbfile;
    fdb_kvs_handle *db;
    fdb_doc **doc = alca(fdb_doc*, n);
    fdb_doc *rdoc = NULL;
    fdb_status status;
    fdb_iterator *iterator;

    char keybuf[256], metabuf[256], bodybuf[256];

    // remove previous iterator_test files
    r = system(SHELL_DEL" iterator_test* > errorlog.txt");
    (void)r;

    fdb_config fconfig = fdb_get_default_config();
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    fconfig.buffercache_size = 0;
    fconfig.seqtree_opt = FDB_SEQTREE_USE; // enable seqtree since get_byseq
    fconfig.wal_threshold = 1024;
    fconfig.flags = FDB_OPEN_FLAG_CREATE;
    fconfig.compaction_threshold = 0;

    // open db
    fdb_open(&dbfile, "./iterator_test1", &fconfig);
    fdb_kvs_open_default(dbfile, &db, &kvs_config);
    status = fdb_set_log_callback(db, logCallbackFunc,
                                  (void *) "reverse_sequence_iterator_test");
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // insert documents of even number
    for (i=0;i<n;i+=2){
        sprintf(keybuf, "key%d", i);
        sprintf(metabuf, "meta%d", i);
        sprintf(bodybuf, "body%d", i);
        fdb_doc_create(&doc[i], (void*)keybuf, strlen(keybuf),
            (void*)metabuf, strlen(metabuf), (void*)bodybuf, strlen(bodybuf));
        fdb_set(db, doc[i]);
    }
    // manually flush WAL & commit
    fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);

    // insert documents of odd number
    for (i=1;i<n;i+=2){
        sprintf(keybuf, "key%d", i);
        sprintf(metabuf, "meta%d", i);
        sprintf(bodybuf, "body%d", i);
        fdb_doc_create(&doc[i], (void*)keybuf, strlen(keybuf),
            (void*)metabuf, strlen(metabuf), (void*)bodybuf, strlen(bodybuf));
        fdb_set(db, doc[i]);
    }
    // commit without WAL flush
    fdb_commit(dbfile, FDB_COMMIT_NORMAL);

    // now even number docs are in hb-trie & odd number docs are in WAL

    // First test reverse sequence iteration as it only involves btrees
    // create an iterator over sequence number range over FULL RANGE
    fdb_iterator_sequence_init(db, &iterator, 0, 0, FDB_ITR_NONE);

    // move iterator forward up till middle...
    i=0;
    count = 0;
    do {
        status = fdb_iterator_get(iterator, &rdoc);
        TEST_CHK(status == FDB_RESULT_SUCCESS);

        TEST_CMP(rdoc->key, doc[i]->key, rdoc->keylen);
        TEST_CMP(rdoc->meta, doc[i]->meta, rdoc->metalen);
        TEST_CMP(rdoc->body, doc[i]->body, rdoc->bodylen);

        fdb_doc_free(rdoc);
        rdoc = NULL;
        count++;
        if (i + 2 >= n) break;
        i = i + 2; // by-seq, first come even docs, then odd
    } while (fdb_iterator_next(iterator) != FDB_RESULT_ITERATOR_FAIL);
    TEST_CHK(count==n/2);

    // Now test reverse sequence iterator from mid-way..

    i = i - 2;
    status = fdb_iterator_prev(iterator);
    TEST_CHK(status != FDB_RESULT_ITERATOR_FAIL);
    status = fdb_iterator_get(iterator, &rdoc);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    TEST_CMP(rdoc->key, doc[i]->key, rdoc->keylen);
    TEST_CMP(rdoc->meta, doc[i]->meta, rdoc->metalen);
    TEST_CMP(rdoc->body, doc[i]->body, rdoc->bodylen);

    fdb_doc_free(rdoc);
    rdoc = NULL;
    count++;

    // change direction to forward again...
    TEST_CHK(fdb_iterator_next(iterator) != FDB_RESULT_ITERATOR_FAIL);
    i = i + 2;
    do {
        status = fdb_iterator_get(iterator, &rdoc);
        TEST_CHK(status == FDB_RESULT_SUCCESS);

        TEST_CMP(rdoc->key, doc[i]->key, rdoc->keylen);
        TEST_CMP(rdoc->meta, doc[i]->meta, rdoc->metalen);
        TEST_CMP(rdoc->body, doc[i]->body, rdoc->bodylen);

        fdb_doc_free(rdoc);
        rdoc = NULL;
        i = (i + 2 >= n) ? 1 : i + 2;// by-seq, first come even docs, then odd
        count++;
    } while (fdb_iterator_next(iterator) != FDB_RESULT_ITERATOR_FAIL);

    TEST_CHK(count==n+2); // two items were double counted due to reverse

    // Reached End, now reverse iterate till start
    i = n - 1;
    count = n;
    status = fdb_iterator_prev(iterator);
    TEST_CHK(status != FDB_RESULT_ITERATOR_FAIL);
    do {
        status = fdb_iterator_get(iterator, &rdoc);
        TEST_CHK(status == FDB_RESULT_SUCCESS);

        TEST_CMP(rdoc->key, doc[i]->key, rdoc->keylen);
        TEST_CMP(rdoc->meta, doc[i]->meta, rdoc->metalen);
        TEST_CMP(rdoc->body, doc[i]->body, rdoc->bodylen);

        fdb_doc_free(rdoc);
        rdoc = NULL;
        i = (i - 2 < 0) ? n - 2 : i - 2;
        if (count) count--;
    } while (fdb_iterator_prev(iterator) != FDB_RESULT_ITERATOR_FAIL);
    TEST_CHK(count == 0);
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

    TEST_RESULT("reverse sequence iterator test");
}


void reverse_sequence_iterator_kvs_test()
{
    TEST_INIT();
    memleak_start();

    int i, r, count;
    int n = 10;
    fdb_file_handle *dbfile;
    fdb_kvs_handle *kv1, *kv2;
    fdb_doc **doc = alca(fdb_doc*, n);
    fdb_doc **doc2 = alca(fdb_doc*, n);
    fdb_doc *rdoc = NULL;
    fdb_status status;
    fdb_iterator *iterator;
    fdb_iterator *iterator2;

    char keybuf[256], metabuf[256], bodybuf[256];

    // remove previous iterator_test files
    r = system(SHELL_DEL" iterator_test* > errorlog.txt");
    (void)r;

    fdb_config fconfig = fdb_get_default_config();
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    fconfig.buffercache_size = 0;
    fconfig.seqtree_opt = FDB_SEQTREE_USE; // enable seqtree since get_byseq
    fconfig.wal_threshold = 1024;
    fconfig.flags = FDB_OPEN_FLAG_CREATE;
    fconfig.compaction_threshold = 0;

    // open db
    fdb_open(&dbfile, "./iterator_test1", &fconfig);
    fdb_kvs_open_default(dbfile, &kv1, &kvs_config);
    status = fdb_set_log_callback(kv1, logCallbackFunc,
                                  (void *) "reverse_sequence_iterator_kvs_test");
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // Create another KV store...
    status = fdb_kvs_open(dbfile, &kv2, "kv2", &kvs_config);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // to 'kv2' with entire range
    for (i=0;i<n;++i) {
        sprintf(keybuf, "kEy%d", i);
        sprintf(metabuf, "mEta%d", i);
        sprintf(bodybuf, "bOdy%d", i);
        fdb_doc_create(&doc2[i], (void*)keybuf, strlen(keybuf),
            (void*)metabuf, strlen(metabuf), (void*)bodybuf, strlen(bodybuf));
        status = fdb_set(kv2, doc2[i]);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
    }

    // insert kv1 documents of even number
    for (i=0;i<n;i+=2) {
        sprintf(keybuf, "key%d", i);
        sprintf(metabuf, "meta%d", i);
        sprintf(bodybuf, "body%d", i);
        fdb_doc_create(&doc[i], (void*)keybuf, strlen(keybuf),
            (void*)metabuf, strlen(metabuf), (void*)bodybuf, strlen(bodybuf));
        fdb_set(kv1, doc[i]);
    }

    // manually flush WAL & commit
    fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);

    // insert kv1 documents of odd number
    for (i=1;i<n;i+=2) {
        sprintf(keybuf, "key%d", i);
        sprintf(metabuf, "meta%d", i);
        sprintf(bodybuf, "body%d", i);
        fdb_doc_create(&doc[i], (void*)keybuf, strlen(keybuf),
            (void*)metabuf, strlen(metabuf), (void*)bodybuf, strlen(bodybuf));
        fdb_set(kv1, doc[i]);
    }
    // commit without WAL flush
    fdb_commit(dbfile, FDB_COMMIT_NORMAL);

    // iterate even docs on kv1
    status = fdb_iterator_sequence_init(kv1, &iterator, 0, 0, FDB_ITR_NONE);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    i=0;
    count = 0;
    while (1) {
        fdb_iterator_get(iterator, &rdoc);
        TEST_CHK(!memcmp(rdoc->key, doc[i]->key, rdoc->keylen));
        TEST_CHK(!memcmp(rdoc->meta, doc[i]->meta, rdoc->metalen));
        TEST_CHK(!memcmp(rdoc->body, doc[i]->body, rdoc->bodylen));
        fdb_doc_free(rdoc);
        rdoc = NULL;
        count++;
        if (i + 2 >= n) {
            break;
        }
        i = i + 2; // by-seq, first come even docs, then odd
        status = fdb_iterator_next(iterator);
        if (status == FDB_RESULT_ITERATOR_FAIL) break;
    }
    TEST_CHK(count==n/2);

    // iterate all docs over kv2
    status = fdb_iterator_sequence_init(kv2, &iterator2, 0, 0, FDB_ITR_NONE);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    while(1) {
        status = fdb_iterator_get(iterator2, &rdoc);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        fdb_doc_free(rdoc);
        rdoc = NULL;
        status = fdb_iterator_next(iterator2);
        if (status == FDB_RESULT_ITERATOR_FAIL) {
            break;
        }
    }

    // manually flush WAL & commit
    // iterators should be unaffected
    fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);

    // reverse iterate even docs over kv1
     i = n - 4;
    count = 0;
    while (1) {
        status = fdb_iterator_prev(iterator);
        if (status == FDB_RESULT_ITERATOR_FAIL) {
            break;
        }
        status = fdb_iterator_get(iterator, &rdoc);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        TEST_CHK(!memcmp(rdoc->key, doc[i]->key, rdoc->keylen));
        TEST_CHK(!memcmp(rdoc->meta, doc[i]->meta, rdoc->metalen));
        TEST_CHK(!memcmp(rdoc->body, doc[i]->body, rdoc->bodylen));
        fdb_doc_free(rdoc);
        rdoc = NULL;
        i-=2;
        count++;
    }

    TEST_CHK(count==4);
    fdb_iterator_close(iterator);

    i = n-1;
    count = 0;
    // reverse iterate all docs over kv2
    while (1) {
        status = fdb_iterator_prev(iterator2);
        if (status == FDB_RESULT_ITERATOR_FAIL) {
            break;
        }
        status = fdb_iterator_get(iterator2, &rdoc);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        TEST_CHK(!memcmp(rdoc->key, doc2[i]->key, rdoc->keylen));
        TEST_CHK(!memcmp(rdoc->meta, doc2[i]->meta, rdoc->metalen));
        TEST_CHK(!memcmp(rdoc->body, doc2[i]->body, rdoc->bodylen));
        fdb_doc_free(rdoc);
        rdoc = NULL;
        i--;
        count++;
    }
    TEST_CHK(count==n);
    fdb_iterator_close(iterator2);

    // re-open iterator after commit should return all docs for kv1
    i = 0;
    count = 0;
    status = fdb_iterator_sequence_init(kv1, &iterator, 0, 0, FDB_ITR_NONE);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    while (1) {
        status = fdb_iterator_get(iterator, &rdoc);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        TEST_CMP(rdoc->key, doc[i]->key, rdoc->keylen);
        TEST_CMP(rdoc->meta, doc[i]->meta, rdoc->metalen);
        TEST_CMP(rdoc->body, doc[i]->body, rdoc->bodylen);
        fdb_doc_free(rdoc);
        rdoc = NULL;
        if (i == 8) {
            i=1; // switch to odds
        } else {
            i+=2;
        }
        count++;
        status = fdb_iterator_next(iterator);
        if (status == FDB_RESULT_ITERATOR_FAIL) {
            break;
        }
    }
    TEST_CHK(count==n);
    fdb_iterator_close(iterator);

    // free all documents
    for (i=0;i<n;++i) {
        fdb_doc_free(doc[i]);
        fdb_doc_free(doc2[i]);
    }

    fdb_kvs_close(kv1);
    fdb_kvs_close(kv2);
    fdb_close(dbfile);

    fdb_shutdown();
    memleak_end();
    TEST_RESULT("reverse sequence iterator kvs test");

}

void reverse_iterator_test()
{
    TEST_INIT();

    memleak_start();

    int i, r;
    int n = 10;
    fdb_file_handle *dbfile;
    fdb_kvs_handle *db;
    fdb_doc **doc = alca(fdb_doc*, n);
    fdb_doc *rdoc = NULL;
    fdb_status status;
    fdb_iterator *iterator;

    char keybuf[256], metabuf[256], bodybuf[256];

    // remove previous iterator_test files
    r = system(SHELL_DEL" iterator_test* > errorlog.txt");
    (void)r;

    fdb_config fconfig = fdb_get_default_config();
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    fconfig.buffercache_size = 0;
    fconfig.wal_threshold = 1024;
    fconfig.flags = FDB_OPEN_FLAG_CREATE;
    fconfig.compaction_threshold = 0;

    // open db
    fdb_open(&dbfile, "./iterator_test1", &fconfig);
    fdb_kvs_open_default(dbfile, &db, &kvs_config);
    status = fdb_set_log_callback(db, logCallbackFunc,
                                  (void *) "reverse_iterator_test");
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // insert documents of even number
    for (i=0;i<n;i+=2){
        sprintf(keybuf, "key%d", i);
        sprintf(metabuf, "meta%d", i);
        sprintf(bodybuf, "body%d", i);
        fdb_doc_create(&doc[i], (void*)keybuf, strlen(keybuf),
            (void*)metabuf, strlen(metabuf), (void*)bodybuf, strlen(bodybuf));
        fdb_set(db, doc[i]);
    }
    // manually flush WAL & commit
    fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);

    // insert documents of odd number
    for (i=1;i<n;i+=2){
        sprintf(keybuf, "key%d", i);
        sprintf(metabuf, "meta%d", i);
        sprintf(bodybuf, "body%d", i);
        fdb_doc_create(&doc[i], (void*)keybuf, strlen(keybuf),
            (void*)metabuf, strlen(metabuf), (void*)bodybuf, strlen(bodybuf));
        fdb_set(db, doc[i]);
    }
    // commit without WAL flush
    fdb_commit(dbfile, FDB_COMMIT_NORMAL);

    // now even number docs are in hb-trie & odd number docs are in WAL

    // Reverse iteration over key range which involves hb-tries
    // create an iterator for full range
    fdb_iterator_init(db, &iterator, NULL, 0, NULL, 0, FDB_ITR_NONE);

    // first test forward iterator - repeat until fail
    i=0;
    do {
        status = fdb_iterator_get(iterator, &rdoc);
        TEST_CHK(status == FDB_RESULT_SUCCESS);

        TEST_CMP(rdoc->key, doc[i]->key, rdoc->keylen);
        TEST_CMP(rdoc->meta, doc[i]->meta, rdoc->metalen);
        TEST_CMP(rdoc->body, doc[i]->body, rdoc->bodylen);

        fdb_doc_free(rdoc);
        rdoc = NULL;
        i++;
    } while (fdb_iterator_next(iterator) != FDB_RESULT_ITERATOR_FAIL);
    TEST_CHK(i==10);

    // Now test reverse iterator..
    for (--i; fdb_iterator_prev(iterator) != FDB_RESULT_ITERATOR_FAIL; --i) {
        status = fdb_iterator_get(iterator, &rdoc);
        TEST_CHK(status == FDB_RESULT_SUCCESS);

        TEST_CMP(rdoc->key, doc[i]->key, rdoc->keylen);
        TEST_CMP(rdoc->meta, doc[i]->meta, rdoc->metalen);
        TEST_CMP(rdoc->body, doc[i]->body, rdoc->bodylen);

        fdb_doc_free(rdoc);
        rdoc = NULL;
        if (i == 5) break; // Change direction at half point
    }
    TEST_CHK(i == 5);

    // Mid-way reverse direction, again test forward iterator...
    i++;
    status = fdb_iterator_next(iterator);
    TEST_CHK(status != FDB_RESULT_ITERATOR_FAIL);
    status = fdb_iterator_get(iterator, &rdoc);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    TEST_CMP(rdoc->key, doc[i]->key, rdoc->keylen);
    TEST_CMP(rdoc->meta, doc[i]->meta, rdoc->metalen);
    TEST_CMP(rdoc->body, doc[i]->body, rdoc->bodylen);

    fdb_doc_free(rdoc);
    rdoc = NULL;

    // Mid-way reverse direction, again test forward iterator...
    i++;
    status = fdb_iterator_next(iterator);
    TEST_CHK(status != FDB_RESULT_ITERATOR_FAIL);
    status = fdb_iterator_get(iterator, &rdoc);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    TEST_CMP(rdoc->key, doc[i]->key, rdoc->keylen);
    TEST_CMP(rdoc->meta, doc[i]->meta, rdoc->metalen);
    TEST_CMP(rdoc->body, doc[i]->body, rdoc->bodylen);

    fdb_doc_free(rdoc);
    rdoc = NULL;

    // Again change direction and test reverse iterator..
    for (--i; fdb_iterator_prev(iterator) != FDB_RESULT_ITERATOR_FAIL; --i) {
        status = fdb_iterator_get(iterator, &rdoc);
        TEST_CHK(status == FDB_RESULT_SUCCESS);

        TEST_CMP(rdoc->key, doc[i]->key, rdoc->keylen);
        TEST_CMP(rdoc->meta, doc[i]->meta, rdoc->metalen);
        TEST_CMP(rdoc->body, doc[i]->body, rdoc->bodylen);

        fdb_doc_free(rdoc);
        rdoc = NULL;
    }
    TEST_CHK(i == -1);

    // Reached end - now test forward iterator...
    TEST_CHK(fdb_iterator_next(iterator) != FDB_RESULT_ITERATOR_FAIL);
    i++;
    do {
        status = fdb_iterator_get(iterator, &rdoc);
        TEST_CHK(status == FDB_RESULT_SUCCESS);

        TEST_CMP(rdoc->key, doc[i]->key, rdoc->keylen);
        TEST_CMP(rdoc->meta, doc[i]->meta, rdoc->metalen);
        TEST_CMP(rdoc->body, doc[i]->body, rdoc->bodylen);

        fdb_doc_free(rdoc);
        rdoc = NULL;
        i++;
    } while (fdb_iterator_next(iterator) != FDB_RESULT_ITERATOR_FAIL);
    TEST_CHK(i==10);

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

    TEST_RESULT("reverse iterator test");
}

void reverse_seek_to_max_nokey(void)
{
    TEST_INIT();

    memleak_start();

    int i, r;
    int n = 100;
    fdb_file_handle *dbfile;
    fdb_kvs_handle *db;
    fdb_doc **doc = alca(fdb_doc*, n);
    fdb_doc *rdoc;
    fdb_status status;
    fdb_iterator *iterator;

    char keybuf[16];

    // remove previous mvcc_test files
    r = system(SHELL_DEL" iterator_test* > errorlog.txt");
    (void)r;

    fdb_config fconfig = fdb_get_default_config();
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    fconfig.buffercache_size = 0;

    // open db
    status = fdb_open(&dbfile, "./iterator_test1", &fconfig);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_kvs_open_default(dbfile, &db, &kvs_config);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // ------- Setup test ----------------------------------
    for (i=0; i<n; i++){
        sprintf(keybuf, "doc-%03d", i);
        keybuf[7] = '\0';
        keybuf[8] = '\0';
        fdb_doc_create(&doc[i], (void*)keybuf, 10,
            NULL, 0, (void*)keybuf, 10);
        fdb_set(db, doc[i]);
    }

    fdb_commit(dbfile, FDB_COMMIT_NORMAL);

    status = fdb_set_log_callback(db, logCallbackFunc,
                                  (void *) "reverse_seek_to_max_nokey");
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    char temp1[10];
    strcpy(temp1, "doc-029b");
    // set range to have end key that does not exist
    status = fdb_iterator_init(db, &iterator,
                               doc[24]->key, 10,
                               (void*)temp1, 10,
                               FDB_ITR_NO_DELETES);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    status = fdb_iterator_seek_to_max(iterator);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    fdb_doc_create(&rdoc, NULL, 0, NULL, 0, NULL, 0);
    status = fdb_iterator_get(iterator, &rdoc);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    TEST_CMP(rdoc->key, "doc-029", 8);
    fdb_doc_free(rdoc);

    fdb_iterator_close(iterator);

    char temp2[10];
    strcpy(temp2, "doc-024b");
    // set range to have start key that does not exist
    status = fdb_iterator_init(db, &iterator,
                               (void*)temp2, 10,
                               doc[30]->key, 10,
                               FDB_ITR_NO_DELETES);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    status = fdb_iterator_seek_to_min(iterator);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    fdb_doc_create(&rdoc, NULL, 0, NULL, 0, NULL, 0);
    status = fdb_iterator_get(iterator, &rdoc);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    TEST_CMP(rdoc->key, "doc-025", 8);
    fdb_doc_free(rdoc);

    fdb_iterator_close(iterator);

    // close db handle
    fdb_kvs_close(db);

    // close db file
    fdb_close(dbfile);

    // free all documents
    for (i=0;i<n;++i){
        fdb_doc_free(doc[i]);
    }

    // free all resources
    fdb_shutdown();

    memleak_end();

    TEST_RESULT("reverse seek to max non-existent key test");
}

void iterator_seek_wal_only_test()
{
    TEST_INIT();

    memleak_start();

    int i, r;
    int n = 10;
    fdb_file_handle *dbfile;
    fdb_kvs_handle *db, *kv1;
    fdb_doc **doc = alca(fdb_doc*, n);
    fdb_doc *rdoc = NULL;
    fdb_status status;
    fdb_iterator *iterator;

    char keybuf[256], metabuf[256], bodybuf[256];

    // remove previous iterator_test files
    r = system(SHELL_DEL" iterator_test* > errorlog.txt");
    (void)r;

    fdb_config fconfig = fdb_get_default_config();
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    fconfig.buffercache_size = 0;
    fconfig.wal_threshold = 1024;
    fconfig.flags = FDB_OPEN_FLAG_CREATE;
    fconfig.compaction_threshold = 0;

    // open db
    fdb_open(&dbfile, "./iterator_test1", &fconfig);
    fdb_kvs_open_default(dbfile, &db, &kvs_config);
    status = fdb_set_log_callback(db, logCallbackFunc,
                                  (void *) "iterator_seek_wal_only_test");
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // Create another KV store..
    status = fdb_kvs_open(dbfile, &kv1, "kv1", &kvs_config);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // insert using 'kv1' instance to ensure it does not interfere
    for (i=0;i<n;++i){
        sprintf(keybuf, "kEy%d", i);
        sprintf(metabuf, "mEta%d", i);
        sprintf(bodybuf, "bOdy%d", i);
        fdb_doc_create(&doc[i], (void*)keybuf, strlen(keybuf),
            (void*)metabuf, strlen(metabuf), (void*)bodybuf, strlen(bodybuf));
        status = fdb_set(kv1, doc[i]);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        fdb_doc_free(doc[i]);
    }

    // insert all documents into WAL only
    for (i=0;i<n;++i){
        sprintf(keybuf, "key%d", i);
        sprintf(metabuf, "meta%d", i);
        sprintf(bodybuf, "body%d", i);
        fdb_doc_create(&doc[i], (void*)keybuf, strlen(keybuf),
            (void*)metabuf, strlen(metabuf), (void*)bodybuf, strlen(bodybuf));
        fdb_set(db, doc[i]);
    }
    // commit without WAL flush
    fdb_commit(dbfile, FDB_COMMIT_NORMAL);

    // create an iterator for full range
    fdb_iterator_init(db, &iterator, NULL, 0, NULL, 0, FDB_ITR_NONE);

    // seek current iterator to inside the WAL's avl tree..
    status = fdb_iterator_get(iterator, &rdoc);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    TEST_CMP(rdoc->key, doc[0]->key, rdoc->keylen);
    TEST_CMP(rdoc->meta, doc[0]->meta, rdoc->metalen);
    TEST_CMP(rdoc->body, doc[0]->body, rdoc->bodylen);
    fdb_doc_free(rdoc);
    rdoc = NULL;

    // seek forward to 2nd key ..
    i=2;
    status = fdb_iterator_seek(iterator, doc[i]->key, strlen(keybuf), 0);
    TEST_CHK(status != FDB_RESULT_ITERATOR_FAIL);
    status = fdb_iterator_get(iterator, &rdoc);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    TEST_CMP(rdoc->key, doc[i]->key, rdoc->keylen);
    TEST_CMP(rdoc->meta, doc[i]->meta, rdoc->metalen);
    TEST_CMP(rdoc->body, doc[i]->body, rdoc->bodylen);
    fdb_doc_free(rdoc);
    rdoc = NULL;

    // iterator should be able to proceed forward
    status = fdb_iterator_next(iterator);
    TEST_CHK(status != FDB_RESULT_ITERATOR_FAIL);
    status = fdb_iterator_get(iterator, &rdoc);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    i++;
    TEST_CMP(rdoc->key, doc[i]->key, rdoc->keylen);
    TEST_CMP(rdoc->meta, doc[i]->meta, rdoc->metalen);
    TEST_CMP(rdoc->body, doc[i]->body, rdoc->bodylen);
    fdb_doc_free(rdoc);
    rdoc = NULL;

    // seek forward to the last key.
    status = fdb_iterator_seek(iterator, doc[n-1]->key, strlen(keybuf), 0);
    TEST_CHK(status != FDB_RESULT_ITERATOR_FAIL);
    status = fdb_iterator_get(iterator, &rdoc);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    TEST_CMP(rdoc->key, doc[n-1]->key, rdoc->keylen);
    TEST_CMP(rdoc->meta, doc[n-1]->meta, rdoc->metalen);
    TEST_CMP(rdoc->body, doc[n-1]->body, rdoc->bodylen);
    fdb_doc_free(rdoc);
    rdoc = NULL;

    // seek backward to start key ..
    i = 0;
    status = fdb_iterator_seek(iterator, doc[i]->key, strlen(keybuf), 0);
    TEST_CHK(status != FDB_RESULT_ITERATOR_FAIL);
    status = fdb_iterator_get(iterator, &rdoc);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    TEST_CMP(rdoc->key, doc[i]->key, rdoc->keylen);
    TEST_CMP(rdoc->meta, doc[i]->meta, rdoc->metalen);
    TEST_CMP(rdoc->body, doc[i]->body, rdoc->bodylen);
    fdb_doc_free(rdoc);
    rdoc = NULL;

    // seek forward to key2 ..
    status = fdb_iterator_seek(iterator, doc[2]->key, strlen(keybuf), 0);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    i=2;
    do {
        status = fdb_iterator_get(iterator, &rdoc);
        TEST_CHK(status == FDB_RESULT_SUCCESS);

        TEST_CMP(rdoc->key, doc[i]->key, rdoc->keylen);
        TEST_CMP(rdoc->meta, doc[i]->meta, rdoc->metalen);
        TEST_CMP(rdoc->body, doc[i]->body, rdoc->bodylen);

        fdb_doc_free(rdoc);
        rdoc = NULL;
        i++;
    } while(fdb_iterator_next(iterator) != FDB_RESULT_ITERATOR_FAIL);
    TEST_CHK(i==10);

    // Seek backward again to a key...
    status = fdb_iterator_seek(iterator, doc[3]->key, strlen(keybuf), 0);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    i=3;
    do {
        status = fdb_iterator_get(iterator, &rdoc);
        TEST_CHK(status == FDB_RESULT_SUCCESS);

        TEST_CMP(rdoc->key, doc[i]->key, rdoc->keylen);
        TEST_CMP(rdoc->meta, doc[i]->meta, rdoc->metalen);
        TEST_CMP(rdoc->body, doc[i]->body, rdoc->bodylen);

        fdb_doc_free(rdoc);
        rdoc = NULL;
        i++;
    } while (fdb_iterator_next(iterator) != FDB_RESULT_ITERATOR_FAIL);
    TEST_CHK(i==10);

    fdb_iterator_close(iterator);

    // Test fdb_iterator_seek_to_max with key range
    // create an iterator for range of doc[4] ~ doc[8]
    sprintf(keybuf, "key%d", 4); // reuse buffer for start key
    sprintf(metabuf, "key%d", 8); // reuse buffer for end_key
    status = fdb_iterator_init(db, &iterator, keybuf, strlen(keybuf),
                      metabuf, strlen(metabuf),
                      FDB_ITR_NO_DELETES);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    i = 8;
    status = fdb_iterator_seek_to_max(iterator);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_iterator_get(iterator, &rdoc);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    TEST_CMP(rdoc->key, doc[i]->key, rdoc->keylen);
    TEST_CMP(rdoc->meta, doc[i]->meta, rdoc->metalen);
    TEST_CMP(rdoc->body, doc[i]->body, rdoc->bodylen);
    fdb_doc_free(rdoc);
    rdoc = NULL;

    // test fdb_iterator_seek_to_min
    i = 4;
    status = fdb_iterator_seek_to_min(iterator);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_iterator_get(iterator, &rdoc);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    TEST_CMP(rdoc->key, doc[i]->key, rdoc->keylen);
    TEST_CMP(rdoc->meta, doc[i]->meta, rdoc->metalen);
    TEST_CMP(rdoc->body, doc[i]->body, rdoc->bodylen);
    fdb_doc_free(rdoc);
    rdoc = NULL;

    status = fdb_iterator_close(iterator);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // Test fdb_iterator_seek_to_max over full range
    status = fdb_iterator_init(db, &iterator, NULL, 0, NULL, 0, FDB_ITR_NONE);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    i = n - 1;
    status = fdb_iterator_seek_to_max(iterator);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_iterator_get(iterator, &rdoc);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    TEST_CMP(rdoc->key, doc[i]->key, rdoc->keylen);
    TEST_CMP(rdoc->meta, doc[i]->meta, rdoc->metalen);
    TEST_CMP(rdoc->body, doc[i]->body, rdoc->bodylen);
    fdb_doc_free(rdoc);
    rdoc = NULL;

    // test fdb_iterator_seek_to_min
    i = 0;
    status = fdb_iterator_seek_to_min(iterator);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_iterator_get(iterator, &rdoc);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    TEST_CMP(rdoc->key, doc[i]->key, rdoc->keylen);
    TEST_CMP(rdoc->meta, doc[i]->meta, rdoc->metalen);
    TEST_CMP(rdoc->body, doc[i]->body, rdoc->bodylen);
    fdb_doc_free(rdoc);
    rdoc = NULL;

    status = fdb_iterator_close(iterator);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // close the kvs kv1
    fdb_kvs_close(kv1);
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

    TEST_RESULT("iterator seek wal only test");
}

void iterator_after_wal_threshold()
{
    TEST_INIT();
    memleak_start();

    int i, r;
    int n = 6;
    char keybuf[256], bodybuf[256];
    fdb_file_handle *dbfile;
    fdb_kvs_handle *db, *db2;
    fdb_doc *rdoc = NULL;
    fdb_status status;
    fdb_iterator *it;
    fdb_config fconfig = fdb_get_default_config();
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    fconfig.wal_threshold = 10;
    fconfig.flags = FDB_OPEN_FLAG_CREATE;
    fconfig.seqtree_opt = FDB_SEQTREE_USE; // enable seqtree since get_byseq

    // remove previous iterator_test files
    r = system(SHELL_DEL" iterator_test* > errorlog.txt");
    (void)r;

    // open db
    fdb_open(&dbfile, "./iterator_test1", &fconfig);
    fdb_kvs_open(dbfile, &db, "db1", &kvs_config);
    fdb_kvs_open(dbfile, &db2, "db2", &kvs_config);

    // write 600 docs
    for (i=0;i<n;++i){
        sprintf(keybuf, "key%d", i);
        sprintf(bodybuf, "body%d", i);
        fdb_set_kv(db, keybuf, strlen(keybuf), bodybuf, strlen(bodybuf));
    }

    // copy keys into another kv
    status = fdb_iterator_sequence_init(db, &it, 0, 0, FDB_ITR_NONE);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    do {
            status = fdb_iterator_get(it, &rdoc);
            TEST_CHK(status == FDB_RESULT_SUCCESS);
            status = fdb_set_kv(db2, rdoc->key, rdoc->keylen, NULL, 0);
            TEST_CHK(status == FDB_RESULT_SUCCESS);
            fdb_doc_free(rdoc);
            rdoc = NULL;
    } while (fdb_iterator_next(it) != FDB_RESULT_ITERATOR_FAIL);
    fdb_iterator_close(it);


    // verify read docs
    status = fdb_iterator_sequence_init(db, &it, 0, 0, FDB_ITR_NONE);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
     do {
            status = fdb_iterator_get(it, &rdoc);
            TEST_CHK(status == FDB_RESULT_SUCCESS);
            status = fdb_get(db, rdoc);
            TEST_CHK(status == FDB_RESULT_SUCCESS);
            fdb_doc_free(rdoc);
            rdoc = NULL;
    } while (fdb_iterator_next(it) != FDB_RESULT_ITERATOR_FAIL);
    fdb_iterator_close(it);

    fdb_kvs_close(db);
    fdb_kvs_close(db2);
    fdb_close(dbfile);
    fdb_shutdown();

    memleak_end();
    TEST_RESULT("iterator after wal threshold");
}

void iterator_manual_wal_flush()
{
    TEST_INIT();
    memleak_start();

    int r;
    unsigned char key1[] =       { 8,  5, 62, 62, 52, 50, 48, 49,
                                  45,  0,  6, 49,  0,  0,  0};
    unsigned char key2[] =       { 8,  5, 62, 62, 52, 50, 48, 49,
                                  49, 45,  0,  6, 49, 50,  0,  0,
                                   0};
    unsigned char start_key1[] = { 8,  5, 62, 62, 52, 49, 57, 57,
                                  57, 45,  0};
    unsigned char start_key2[] = { 8,  5, 62, 62, 52, 51, 52, 53,
                                  10, 20,  0};
    fdb_file_handle *dbfile;
    fdb_kvs_handle *db, *db2;
    fdb_doc *rdoc = NULL;
    fdb_status status;
    fdb_iterator *it;
    fdb_config fconfig = fdb_get_default_config();
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    fconfig.wal_threshold = 1024;
    fconfig.flags = FDB_OPEN_FLAG_CREATE;

    // remove previous iterator_test files
    r = system(SHELL_DEL" iterator_test* > errorlog.txt");
    (void)r;

    // open db
    fdb_open(&dbfile, "./iterator_test1", &fconfig);
    fdb_kvs_open(dbfile, &db, "db1", &kvs_config);
    fdb_kvs_open(dbfile, &db2, "db2", &kvs_config);

    fdb_set_kv(db, key1, sizeof(key1), NULL, 0);
    fdb_set_kv(db, key2, sizeof(key2), NULL, 0);

    // normal commit
    fdb_commit(dbfile, FDB_COMMIT_NORMAL);

    // start_key's skipped prefix is smaller than the common prefix
    status = fdb_iterator_init(db, &it, start_key1, sizeof(start_key1),
                               NULL, 0, FDB_ITR_NONE);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    do {
        status = fdb_iterator_get(it, &rdoc);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        fdb_doc_free(rdoc);
        rdoc = NULL;
    } while (fdb_iterator_next(it) != FDB_RESULT_ITERATOR_FAIL);
    fdb_iterator_close(it);

    // start_key's skipped prefix is gerater than the common prefix
    status = fdb_iterator_init(db, &it, start_key2, sizeof(start_key2),
                               NULL, 0, FDB_ITR_NONE);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_iterator_get(it, &rdoc);
    TEST_CHK(status != FDB_RESULT_SUCCESS);
    fdb_iterator_close(it);

    fdb_set_kv(db2, key1, sizeof(key1), NULL, 0);
    fdb_set_kv(db2, key2, sizeof(key2), NULL, 0);

    // manually flush WAL & commit
    fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);

    // start_key's skipped prefix is smaller than the common prefix
    status = fdb_iterator_init(db2, &it, start_key1, sizeof(start_key1),
                               NULL, 0, FDB_ITR_NONE);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    do {
        status = fdb_iterator_get(it, &rdoc);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        fdb_doc_free(rdoc);
        rdoc = NULL;
    } while (fdb_iterator_next(it) != FDB_RESULT_ITERATOR_FAIL);
    fdb_iterator_close(it);

    // start_key's skipped prefix is gerater than the common prefix
    status = fdb_iterator_init(db, &it, start_key2, sizeof(start_key2),
                               NULL, 0, FDB_ITR_NONE);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_iterator_get(it, &rdoc);
    TEST_CHK(status != FDB_RESULT_SUCCESS);
    fdb_iterator_close(it);

    // start_key's skipped prefix is smaller than the common prefix
    status = fdb_iterator_init(db2, &it, NULL, 0,
                               start_key1, sizeof(start_key1), FDB_ITR_NONE);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_iterator_seek(it, start_key1, sizeof(start_key1), FDB_ITR_SEEK_LOWER);
    TEST_CHK(status != FDB_RESULT_SUCCESS);
    fdb_iterator_close(it);

    // start_key's skipped prefix is gerater than the common prefix
    status = fdb_iterator_init(db, &it, NULL, 0,
                               start_key2, sizeof(start_key2), FDB_ITR_NONE);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_iterator_seek(it, start_key2, sizeof(start_key2), FDB_ITR_SEEK_LOWER);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_iterator_get(it, &rdoc);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    fdb_doc_free(rdoc);
    rdoc = NULL;
    while (fdb_iterator_prev(it) != FDB_RESULT_ITERATOR_FAIL) {
        status = fdb_iterator_get(it, &rdoc);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        fdb_doc_free(rdoc);
        rdoc = NULL;
    }
    fdb_iterator_close(it);

    fdb_close(dbfile);
    fdb_shutdown();

    memleak_end();
    TEST_RESULT("iterator manual wal flush");
}

void sequence_iterator_seek_test(bool multi_kv)
{
    TEST_INIT();

    memleak_start();

    int i, r;
    int n = 10;
    fdb_file_handle *dbfile;
    fdb_kvs_handle *db;
    fdb_doc **doc = alca(fdb_doc*, n);
    fdb_doc *rdoc = NULL;
    fdb_status status;
    fdb_iterator *iterator;

    char keybuf[256], metabuf[256], bodybuf[256];

    // remove previous iterator_test files
    r = system(SHELL_DEL" iterator_test* > errorlog.txt");
    (void)r;

    fdb_config fconfig = fdb_get_default_config();
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    fconfig.buffercache_size = 0;
    fconfig.wal_threshold = 1024;
    fconfig.seqtree_opt = FDB_SEQTREE_USE; // enable seqtree since get_byseq
    fconfig.flags = FDB_OPEN_FLAG_CREATE;
    fconfig.multi_kv_instances = multi_kv;
    fconfig.compaction_threshold = 0;

    // open db
    fdb_open(&dbfile, "./iterator_test7", &fconfig);
    if (multi_kv) {
        fdb_kvs_open(dbfile, &db, "kv1", &kvs_config);
    } else {
        fdb_kvs_open_default(dbfile, &db, &kvs_config);
    }
    status = fdb_set_log_callback(db, logCallbackFunc,
                                  (void *) "sequence_iterator_seek_test");
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // insert half the docs into main index
    for (i=0;i<n/2;++i){
        sprintf(keybuf, "key%d", i);
        sprintf(metabuf, "meta%d", i);
        sprintf(bodybuf, "body%d", i);
        fdb_doc_create(&doc[i], (void*)keybuf, strlen(keybuf),
            (void*)metabuf, strlen(metabuf), (void*)bodybuf, strlen(bodybuf));
        fdb_set(db, doc[i]);
    }
    // manually flush WAL & commit
    fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);

    // insert remaining half into WAL
    for (;i<n;++i){
        sprintf(keybuf, "key%d", i);
        sprintf(metabuf, "meta%d", i);
        sprintf(bodybuf, "body%d", i);
        fdb_doc_create(&doc[i], (void*)keybuf, strlen(keybuf),
            (void*)metabuf, strlen(metabuf), (void*)bodybuf, strlen(bodybuf));
        fdb_set(db, doc[i]);
    }
    // commit without WAL flush
    fdb_commit(dbfile, FDB_COMMIT_NORMAL);

    // create an iterator over sequence number range over FULL RANGE
    fdb_iterator_sequence_init(db, &iterator, 0, 0, FDB_ITR_NONE);
    status = fdb_iterator_seek_to_max(iterator);

    i = n - 1;
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    do {
        status = fdb_iterator_get(iterator, &rdoc);
        TEST_CHK(status == FDB_RESULT_SUCCESS);

        TEST_CMP(rdoc->key, doc[i]->key, rdoc->keylen);
        TEST_CMP(rdoc->meta, doc[i]->meta, rdoc->metalen);
        TEST_CMP(rdoc->body, doc[i]->body, rdoc->bodylen);

        fdb_doc_free(rdoc);
        rdoc = NULL;
        --i;
    } while (fdb_iterator_prev(iterator) != FDB_RESULT_ITERATOR_FAIL);
    fdb_iterator_close(iterator);

    // create an iterator over sequence number range over HALF RANGE
    fdb_iterator_sequence_init(db, &iterator, 0, 7, FDB_ITR_NONE);

    status = fdb_iterator_seek_to_max(iterator);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    i = 6;
    TEST_CHK(status != FDB_RESULT_ITERATOR_FAIL);
    do {
        status = fdb_iterator_get(iterator, &rdoc);
        TEST_CHK(status == FDB_RESULT_SUCCESS);

        TEST_CMP(rdoc->key, doc[i]->key, rdoc->keylen);
        TEST_CMP(rdoc->meta, doc[i]->meta, rdoc->metalen);
        TEST_CMP(rdoc->body, doc[i]->body, rdoc->bodylen);

        fdb_doc_free(rdoc);
        rdoc = NULL;
        --i;
    } while (fdb_iterator_prev(iterator) != FDB_RESULT_ITERATOR_FAIL);
    fdb_iterator_close(iterator);

    // create an iterator over sequence number range over HALF RANGE
    fdb_iterator_sequence_init(db, &iterator, 0, 7,
                               FDB_ITR_NONE|FDB_ITR_SKIP_MAX_KEY);

    status = fdb_iterator_seek_to_max(iterator);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    i = 5;
    TEST_CHK(status != FDB_RESULT_ITERATOR_FAIL);
    do {
        status = fdb_iterator_get(iterator, &rdoc);
        TEST_CHK(status == FDB_RESULT_SUCCESS);

        TEST_CMP(rdoc->key, doc[i]->key, rdoc->keylen);
        TEST_CMP(rdoc->meta, doc[i]->meta, rdoc->metalen);
        TEST_CMP(rdoc->body, doc[i]->body, rdoc->bodylen);

        fdb_doc_free(rdoc);
        rdoc = NULL;
        --i;
    } while (fdb_iterator_prev(iterator) != FDB_RESULT_ITERATOR_FAIL);
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

    TEST_RESULT("sequence iterator seek test");
}

void iterator_concurrent_compaction()
{
    TEST_INIT();
    memleak_start();

    int i, r;
    int n = 10;
    char keybuf[256], bodybuf[256];
    fdb_file_handle *dbfile, *dbfile2;
    fdb_kvs_handle *db, *db2;
    fdb_doc *rdoc = NULL;
    fdb_status status;
    fdb_iterator *it_id, *it_seq;
    fdb_config fconfig = fdb_get_default_config();
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    void *value_out;
    size_t valuelen_out;

    fconfig.wal_threshold = 1024;
    fconfig.seqtree_opt = FDB_SEQTREE_USE; // enable seqtree since get_byseq
    fconfig.flags = FDB_OPEN_FLAG_CREATE;

    // remove previous iterator_test files
    r = system(SHELL_DEL" iterator_test* > errorlog.txt");
    (void)r;

    // open db
    fdb_open(&dbfile, "./iterator_test1", &fconfig);
    fdb_kvs_open(dbfile, &db, "db", &kvs_config);

    // write docs
    for (i=0;i<n;++i){
        sprintf(keybuf, "key%d", i);
        sprintf(bodybuf, "body%d", i);
        fdb_set_kv(db, keybuf, strlen(keybuf), bodybuf, strlen(bodybuf));
    }
    fdb_commit(dbfile, FDB_COMMIT_NORMAL);

    fdb_open(&dbfile2, "./iterator_test1", &fconfig);
    fdb_kvs_open(dbfile2, &db2, "db", &kvs_config);

    fdb_compact(dbfile, "./iterator_test2");

    status = fdb_iterator_init(db2, &it_id, NULL, 0, NULL, 0, 0x0);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_iterator_sequence_init(db, &it_seq, 0, 0, 0x0);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // retrieve docs
    // now handle's header is updated
    for (i=0;i<n;++i){
        sprintf(keybuf, "key%d", i);
        fdb_get_kv(db, keybuf, strlen(keybuf), &value_out, &valuelen_out);
        fdb_free_block(value_out);
    }

    do {
        rdoc = NULL;
        status = fdb_iterator_get(it_id, &rdoc);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        fdb_doc_free(rdoc);
    } while (fdb_iterator_next(it_id) != FDB_RESULT_ITERATOR_FAIL);
    status = fdb_iterator_close(it_id);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    do {
        rdoc = NULL;
        status = fdb_iterator_get(it_seq, &rdoc);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        fdb_doc_free(rdoc);
    } while (fdb_iterator_next(it_seq) != FDB_RESULT_ITERATOR_FAIL);
    status = fdb_iterator_close(it_seq);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    fdb_close(dbfile);
    fdb_close(dbfile2);
    fdb_shutdown();

    memleak_end();
    TEST_RESULT("iterator with concurrent compaction test");
}

void iterator_offset_access_test()
{
    TEST_INIT();
    memleak_start();


    int i, r;
    int n = 1000;
    char keybuf[256], bodybuf[256];
    fdb_file_handle *dbfile;
    fdb_kvs_handle *db, *o_db;
    fdb_doc **doc = alca(fdb_doc*, n);
    fdb_doc *rdoc = NULL;
    fdb_status s;
    fdb_iterator *it;

    // remove  all previous iterator_test files
    r = system(SHELL_DEL" iterator_test* > errorlog.txt");
    (void)r;

    fdb_config fconfig = fdb_get_default_config();
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    fconfig.wal_threshold = 512;
    fconfig.buffercache_size = 4096;
    fconfig.flags = FDB_OPEN_FLAG_CREATE;
    fconfig.compaction_mode = FDB_COMPACTION_MANUAL;
    fconfig.purging_interval = 1; // retain deletes until compaction

    // open db
    s = fdb_open(&dbfile, "./iterator_test1", &fconfig);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_kvs_open(dbfile, &db, "DB", &kvs_config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_kvs_open(dbfile, &o_db,"ODB", &kvs_config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    // set docs
    for (i=0;i<n;++i){
        sprintf(keybuf, "key%d", i);
        sprintf(bodybuf, "body%d", i);
        fdb_doc_create(&doc[i], (void*)keybuf, strlen(keybuf),
            NULL, 0, (void*)bodybuf, strlen(bodybuf));
        s = fdb_set(db, doc[i]);
        TEST_CHK(s == FDB_RESULT_SUCCESS);

        // set in offset verification index
        s = fdb_set_kv(o_db, keybuf, strlen(keybuf),
                        &doc[i]->offset, sizeof(uint64_t));
        TEST_CHK(s == FDB_RESULT_SUCCESS);
    }

    s = fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    // delete some
     for (i=n/4;i<n/2;++i){
        sprintf(keybuf, "key%d", i);
        s = fdb_del_kv(db, (void*)keybuf, strlen(keybuf));
        TEST_CHK(s == FDB_RESULT_SUCCESS);
    }

    // update initial n/4 docs
    for (i=0;i<n/4;++i){
        sprintf(keybuf, "k0y%d", i);
        sprintf(bodybuf, "b0dy%d", i);
        fdb_doc_free(doc[i]);
        fdb_doc_create(&doc[i], (void*)keybuf, strlen(keybuf),
            NULL, 0, (void*)bodybuf, strlen(bodybuf));
        s = fdb_set(db, doc[i]);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
    }

    s = fdb_commit(dbfile, FDB_COMMIT_NORMAL);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    // create iterator with no deletes
    fdb_iterator_init(o_db, &it, NULL, 0, NULL, 0, FDB_ITR_NO_DELETES);

    // only 2nd half of docs should exist at original offset
    for (i=n/2;i<n;i+=10){

        // get by offset
        s = fdb_get_byoffset(db, doc[i]);
        TEST_CHK(s == FDB_RESULT_SUCCESS);

        // seek to in verificaiton db
        s = fdb_iterator_seek(it, doc[i]->key, doc[i]->keylen, 0);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        s = fdb_iterator_get(it, &rdoc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CHK(*((uint64_t *)rdoc->body) == doc[i]->offset);

        // delete
        s = fdb_del(db, doc[i]);
        TEST_CHK(s == FDB_RESULT_SUCCESS);

        // track new offset storing in doc[i]
        fdb_get_metaonly(db, doc[i]);
    }

    fdb_iterator_close(it);
    s = fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    // do some sets passed recorded offset
    for (i=0;i<n/4;++i){
        sprintf(keybuf, "k1y%d", i);
        sprintf(bodybuf, "b1dy%d", i);
        s = fdb_set_kv(db, keybuf, strlen(keybuf), bodybuf, strlen(bodybuf));
        TEST_CHK(s == FDB_RESULT_SUCCESS);
    }

    // known offsets exist between n/2 - n
    for (i=n/2;i<n;i+=10){

        // verify can get by offset from main db
        s = fdb_get_byoffset(db, doc[i]);
        TEST_CHK(s == FDB_RESULT_KEY_NOT_FOUND);

        // should be deleted now at new offset
        TEST_CHK(doc[i]->deleted == true);
    }

    for(i=0;i<n;++i){
        fdb_doc_free(doc[i]);
    }

    fdb_doc_free(rdoc);
    fdb_close(dbfile);
    fdb_shutdown();

    memleak_end();
    TEST_RESULT("iterator offset access test");
}

void iterator_deleted_doc_right_before_the_end_test()
{
    TEST_INIT();
    int i, r;
    fdb_file_handle *dbfile;
    fdb_kvs_handle *db;
    fdb_iterator *fit;
    fdb_doc *rdoc;
    fdb_config config;
    fdb_kvs_config kvs_config;
    fdb_status s; (void)s;
    char keybuf[256], valuebuf[256], cmd[256];

    memleak_start();

    config = fdb_get_default_config();
    config.buffercache_size = 0;
    kvs_config = fdb_get_default_kvs_config();

    sprintf(cmd, SHELL_DEL " %s*", "./itr_test");
    r = system(cmd); (void)r;

    fdb_open(&dbfile, "./itr_test", &config);
    fdb_kvs_open(dbfile, &db, NULL, &kvs_config);

    // insert 3 docs
    for (i=0;i<3;++i) {
        sprintf(keybuf, "k%06d\n", i);
        sprintf(valuebuf, "v%06d\n", i);
        fdb_set_kv(db, keybuf, 8, valuebuf, 8);
    }

    // delete the middle doc
    i = 1;
    sprintf(keybuf, "k%06d\n", i);
    fdb_del_kv(db, keybuf, 8);

    fdb_commit(dbfile, FDB_COMMIT_NORMAL);

    sprintf(keybuf, "a");
    sprintf(cmd, "z");
    s = fdb_iterator_init(db, &fit, keybuf, 1, cmd, 1, FDB_ITR_NO_DELETES);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    s = fdb_iterator_seek_to_max(fit);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    rdoc = NULL;
    s = fdb_iterator_get(fit, &rdoc);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    i = 2;
    sprintf(keybuf, "k%06d\n", i);
    TEST_CMP(rdoc->key, keybuf, 8);
    fdb_doc_free(rdoc);

    s = fdb_iterator_prev(fit);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    rdoc = NULL;
    s = fdb_iterator_get(fit, &rdoc);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    i = 0;
    sprintf(keybuf, "k%06d\n", i);
    TEST_CMP(rdoc->key, keybuf, 8);
    fdb_doc_free(rdoc);

    fdb_iterator_close(fit);

    // opposite case
    s = fdb_iterator_init(db, &fit, keybuf, 1, cmd, 1, FDB_ITR_NO_DELETES);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    s = fdb_iterator_seek_to_min(fit);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    rdoc = NULL;
    s = fdb_iterator_get(fit, &rdoc);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    i = 0;
    sprintf(keybuf, "k%06d\n", i);
    TEST_CMP(rdoc->key, keybuf, 8);
    fdb_doc_free(rdoc);

    s = fdb_iterator_next(fit);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    rdoc = NULL;
    s = fdb_iterator_get(fit, &rdoc);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    i = 2;
    sprintf(keybuf, "k%06d\n", i);
    TEST_CMP(rdoc->key, keybuf, 8);
    fdb_doc_free(rdoc);

    fdb_iterator_close(fit);

    fdb_close(dbfile);
    fdb_shutdown();

    memleak_end();

    TEST_RESULT("iterator deleted doc right before the end of iteration test");
}

void iterator_uncommited_seeks()
{
    TEST_INIT();

    int r;

    fdb_status status;
    fdb_kvs_handle *db;
    fdb_file_handle *dbfile;
    fdb_iterator *it;
    fdb_doc *rdoc;
    rdoc=NULL;

    memleak_start();

    fdb_config fconfig = fdb_get_default_config();
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();

    r = system(SHELL_DEL" iterator_test* > errorlog.txt");
    (void)r;
    TEST_STATUS(fdb_open(&dbfile, "./iterator_test1", &fconfig));
    TEST_STATUS(fdb_kvs_open_default(dbfile, &db, &kvs_config));

    fdb_set_kv(db, "a", 1, NULL, 0);
    fdb_set_kv(db, "b", 1, NULL, 0);
    fdb_set_kv(db, "c", 1, NULL, 0);

    status = fdb_iterator_init(db, &it, "b", 1, NULL, 0, FDB_ITR_NONE);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // to 'b'
    status = fdb_iterator_seek_to_min(it);
    TEST_STATUS(status);
    status = fdb_iterator_get(it, &rdoc);
    TEST_STATUS(status);
    TEST_CMP(rdoc->key, "b", 1);
    fdb_doc_free(rdoc);
    rdoc=NULL;

    // to 'c'
    status = fdb_iterator_seek_to_max(it);
    TEST_STATUS(status);
    status = fdb_iterator_get(it, &rdoc);
    TEST_STATUS(status);
    TEST_CMP(rdoc->key, "c", 1);
    fdb_doc_free(rdoc);
    rdoc=NULL;

    // to 'b'
    status = fdb_iterator_prev(it);
    TEST_STATUS(status);
    status = fdb_iterator_get(it, &rdoc);
    TEST_STATUS(status);
    TEST_CMP(rdoc->key, "b", 1);
    fdb_doc_free(rdoc);
    rdoc=NULL;

    // to 'c'
    status = fdb_iterator_next(it);
    TEST_STATUS(status);
    status = fdb_iterator_get(it, &rdoc);
    TEST_STATUS(status);
    TEST_CMP(rdoc->key, "c", 1);
    fdb_doc_free(rdoc);
    rdoc=NULL;

    fdb_iterator_close(it);

    fdb_close(dbfile);
    fdb_shutdown();
    memleak_end();
    TEST_RESULT("iterator single doc range");
}

void iterator_init_using_substring_test()
{
    // MB-18712
    TEST_INIT();
    memleak_start();

    int i, r;
    fdb_file_handle *dbfile;
    fdb_kvs_handle *db;
    fdb_iterator *fit;
    fdb_doc *rdoc;
    fdb_config config;
    fdb_kvs_config kvs_config;
    fdb_status s; (void)s;
    char valuebuf[256], cmd[256];

    config = fdb_get_default_config();
    config.buffercache_size = 0;
    kvs_config = fdb_get_default_kvs_config();

    sprintf(cmd, SHELL_DEL " %s*", "./iterator_test");
    r = system(cmd); (void)r;

    s = fdb_open(&dbfile, "./iterator_test1", &config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    s = fdb_kvs_open(dbfile, &db, NULL, &kvs_config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    uint8_t key1[] = {0x73, 0x37, 0x35, 0x34, 0x36, 0x32, 0x34, 0xff, 0x00, 0x00, 0x00};
    uint8_t key2[] = {0x73, 0x37, 0x35, 0x34, 0x36, 0x32, 0x34, 0xff, 0x00, 0x00, 0x01};
    // skey is a substring of key1
    uint8_t skey[] = {0x73, 0x37, 0x35, 0x34, 0x36, 0x32, 0x34, 0xff};
    uint8_t ekey[] = {0x73, 0x37, 0x35, 0x34, 0x36, 0x32, 0x34, 0xff, 0xff};

    sprintf(valuebuf, "key1");
    s = fdb_set_kv(db, key1, 11, valuebuf, 4);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    sprintf(valuebuf, "key2");
    s = fdb_set_kv(db, key2, 11, valuebuf, 4);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    s = fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    s = fdb_iterator_init(db, &fit, skey, 8, ekey, 9,
                          FDB_ITR_NO_DELETES | FDB_ITR_SKIP_MAX_KEY);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    i = 0;
    do {
        rdoc = NULL;
        s = fdb_iterator_get(fit, &rdoc);
        if (s != FDB_RESULT_SUCCESS) break;
        i++;
        fdb_doc_free(rdoc);
    } while (fdb_iterator_next(fit) == FDB_RESULT_SUCCESS);
    TEST_CHK(i == 2);

    s = fdb_iterator_close(fit);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    s = fdb_close(dbfile);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_shutdown();
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    memleak_end();

    TEST_RESULT("iterator init using substring test");
}

void iterator_seek_to_max_key_with_deletes_test() {
    TEST_INIT();
    memleak_start();

    int r;

    fdb_status status;
    fdb_kvs_handle *db;
    fdb_file_handle *dbfile;
    fdb_iterator *it = nullptr;
    fdb_doc *rdoc = nullptr;


    fdb_config fconfig = fdb_get_default_config();
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();

    r = system(SHELL_DEL" iterator_test* > errorlog.txt");
    (void)r;
    TEST_STATUS(fdb_open(&dbfile, "./iterator_test1", &fconfig));
    TEST_STATUS(fdb_kvs_open_default(dbfile, &db, &kvs_config));

    fdb_set_kv(db, "A", 1, NULL, 0);
    fdb_set_kv(db, "B", 1, NULL, 0);

    status = fdb_iterator_init(db, &it, "B", 1, "Bzz", 3, FDB_ITR_NONE);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    status = fdb_iterator_seek_to_max(it);
    TEST_STATUS(status);
    status = fdb_iterator_get(it, &rdoc);
    TEST_STATUS(status);
    TEST_CMP(rdoc->key, "B", 1);
    fdb_doc_free(rdoc);
    rdoc = nullptr;

    status = fdb_iterator_close(it);
    TEST_STATUS(status);
    it = nullptr;

    status = fdb_del_kv(db, "B", 1);
    TEST_STATUS(status);

    status = fdb_iterator_init(db, &it, "B", 1, "Bzz", 3, FDB_ITR_NONE);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_iterator_get(it, &rdoc);
    TEST_CHK(status == FDB_RESULT_ITERATOR_FAIL);

    status = fdb_iterator_seek_to_max(it);
    TEST_CHK(status == FDB_RESULT_ITERATOR_FAIL);

    status = fdb_iterator_close(it);
    TEST_STATUS(status);

    status = fdb_close(dbfile);
    TEST_STATUS(status);
    status = fdb_shutdown();
    TEST_STATUS(status);

    memleak_end();

    TEST_RESULT("iterator seek to max test");
}

void iterator_seek_to_min_key_with_deletes_test() {
    TEST_INIT();
    memleak_start();

    int r;

    fdb_status status;
    fdb_kvs_handle *db;
    fdb_file_handle *dbfile;
    fdb_iterator *it = nullptr;
    fdb_doc *rdoc = nullptr;


    fdb_config fconfig = fdb_get_default_config();
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();

    r = system(SHELL_DEL" iterator_test* > errorlog.txt");
    (void)r;
    TEST_STATUS(fdb_open(&dbfile, "./iterator_test1", &fconfig));
    TEST_STATUS(fdb_kvs_open_default(dbfile, &db, &kvs_config));

    fdb_set_kv(db, "B", 1, NULL, 0);
    fdb_set_kv(db, "C", 1, NULL, 0);

    status = fdb_del_kv(db, "B", 1);
    TEST_STATUS(status);

    status = fdb_iterator_init(db, &it, "A", 1, "B", 1, FDB_ITR_NONE);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_iterator_get(it, &rdoc);
    TEST_CHK(status == FDB_RESULT_ITERATOR_FAIL);

    status = fdb_iterator_seek_to_min(it);
    TEST_CHK(status == FDB_RESULT_ITERATOR_FAIL);

    status = fdb_iterator_close(it);
    TEST_STATUS(status);

    status = fdb_close(dbfile);
    TEST_STATUS(status);
    status = fdb_shutdown();
    TEST_STATUS(status);

    memleak_end();

    TEST_RESULT("iterator seek to max test");
}
int main(){
    iterator_test();
    iterator_with_concurrent_updates_test();
    iterator_compact_uncommitted_db();
    iterator_seek_test();
    for (int i = 0; i <= 6; ++i) {
        for (int j = 0; j < 2; ++j) {
            iterator_complete_test(i, j);
        }
    }
    iterator_extreme_key_test();
    iterator_inmem_snapshot_seek_test(false);
    iterator_inmem_snapshot_seek_test(true);
    iterator_no_deletes_test();
    iterator_set_del_docs_test();
    iterator_del_next_test();
    sequence_iterator_test();
    sequence_iterator_duplicate_test();
    sequence_iterator_range_test();
    reverse_seek_to_max_nokey();
    reverse_sequence_iterator_test();
    reverse_sequence_iterator_kvs_test();
    reverse_iterator_test();
    iterator_seek_wal_only_test();
    iterator_after_wal_threshold();
    iterator_manual_wal_flush();
    sequence_iterator_seek_test(true);
    sequence_iterator_seek_test(false);
    iterator_concurrent_compaction();
    iterator_offset_access_test();
    iterator_deleted_doc_right_before_the_end_test();
    iterator_uncommited_seeks();
    iterator_init_using_substring_test();
    iterator_seek_to_max_key_with_deletes_test();
    iterator_seek_to_min_key_with_deletes_test();
    return 0;
}
