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
#include <sys/types.h>
#include <sys/stat.h>
#endif

#include "libforestdb/forestdb.h"
#include "test.h"

#include "internal_types.h"
#include "wal.h"
#include "functional_util.h"
#include "file_handle.h"
#include "kvs_handle.h"

struct cb_args {
    int n_moved_docs;
    int n_batch_move;
    bool begin;
    bool end;
    bool wal_flush;
    fdb_kvs_handle *handle;
};

static fdb_compact_decision compaction_cb(fdb_file_handle *fhandle,
                            fdb_compaction_status status, const char *kv_name,
                            fdb_doc *doc, uint64_t old_offset,
                            uint64_t new_offset,
                            void *ctx)
{
    TEST_INIT();
    fdb_doc *rdoc;
    fdb_status s;
    fdb_compact_decision ret = FDB_CS_KEEP_DOC;
    struct cb_args *args = (struct cb_args *)ctx;

    (void) doc;
    (void) new_offset;

    if (status == FDB_CS_BEGIN) {
        args->begin = true;
    } else if (status == FDB_CS_END) {
        args->end = true;
    } else if (status == FDB_CS_FLUSH_WAL) {
        args->wal_flush = true;
    } else if (status == FDB_CS_MOVE_DOC) {
        if (doc->deleted) {
            ret = FDB_CS_DROP_DOC;
        }

        args->n_moved_docs++;
        fdb_doc_create(&rdoc, NULL, 0, NULL, 0, NULL, 0);
        rdoc->offset = old_offset;
        s = fdb_get_byoffset(args->handle, rdoc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        fdb_doc_free(rdoc);

        if (fhandle->getRootHandle()->config.multi_kv_instances) {
            TEST_CMP(kv_name, "db", 2);
        } else {
            TEST_CMP(kv_name, "default", 7);
        }
    } else { // FDB_CS_BATCH_MOVE
        args->n_batch_move++;
        fdb_doc_create(&rdoc, NULL, 0, NULL, 0, NULL, 0);
        rdoc->offset = old_offset;
        s = fdb_get_byoffset(args->handle, rdoc);
        TEST_CHK (s == FDB_RESULT_SUCCESS);
        fdb_doc_free(rdoc);
    }
    return ret;
}

void compaction_callback_test(bool multi_kv)
{
    TEST_INIT();
    memleak_start();

    int i, r;
    int n = 1000;
    char keybuf[256], bodybuf[256];
    fdb_file_handle *dbfile;
    fdb_kvs_handle *db;
    fdb_status s;
    fdb_config fconfig = fdb_get_default_config();
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    struct cb_args cb_args;

    memset(&cb_args, 0x0, sizeof(struct cb_args));
    fconfig.wal_threshold = 1024;
    fconfig.flags = FDB_OPEN_FLAG_CREATE;
    fconfig.compaction_cb = compaction_cb;
    fconfig.compaction_cb_ctx = &cb_args;
    fconfig.compaction_cb_mask = FDB_CS_BEGIN |
                                 FDB_CS_MOVE_DOC |
                                 FDB_CS_FLUSH_WAL |
                                 FDB_CS_END;
    fconfig.multi_kv_instances = multi_kv;

    // remove all previous compact_test files
    r = system(SHELL_DEL" compact_test* > errorlog.txt");
    (void)r;

    // open db
    fdb_open(&dbfile, "./compact_test1", &fconfig);
    if (multi_kv) {
        fdb_kvs_open(dbfile, &db, "db", &kvs_config);
    } else {
        fdb_kvs_open_default(dbfile, &db, &kvs_config);
    }
    cb_args.handle = db;

    // write docs
    for (i=0;i<n;++i){
        sprintf(keybuf, "key%04d", i);
        sprintf(bodybuf, "body%04d", i);
        s = fdb_set_kv(db, keybuf, strlen(keybuf), bodybuf, strlen(bodybuf));
        TEST_CHK(s == FDB_RESULT_SUCCESS);
    }
    s = fdb_commit(dbfile, FDB_COMMIT_NORMAL);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_compact(dbfile, "./compact_test2");
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    TEST_CHK(cb_args.n_moved_docs == n);
    TEST_CHK(cb_args.begin);
    TEST_CHK(cb_args.end);
    TEST_CHK(cb_args.wal_flush);
    fdb_close(dbfile);

    // open db without move doc
    memset(&cb_args, 0x0, sizeof(struct cb_args));
    fconfig.compaction_cb_mask = FDB_CS_BEGIN |
                                 FDB_CS_FLUSH_WAL |
                                 FDB_CS_END;
    fdb_open(&dbfile, "./compact_test2", &fconfig);

    if (multi_kv) {
        fdb_kvs_open(dbfile, &db, "db", &kvs_config);
    } else {
        fdb_kvs_open_default(dbfile, &db, &kvs_config);
    }
    cb_args.handle = db;
    s = fdb_compact(dbfile, "./compact_test3");
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    TEST_CHK(cb_args.n_moved_docs == 0);
    TEST_CHK(cb_args.begin);
    TEST_CHK(cb_args.end);
    TEST_CHK(cb_args.wal_flush);
    fdb_close(dbfile);

    // open db without wal_flush
    memset(&cb_args, 0x0, sizeof(struct cb_args));
    fconfig.compaction_cb_mask = FDB_CS_BEGIN |
                                 FDB_CS_MOVE_DOC |
                                 FDB_CS_END;
    fdb_open(&dbfile, "./compact_test3", &fconfig);
    if (multi_kv) {
        fdb_kvs_open(dbfile, &db, "db", &kvs_config);
    } else {
        fdb_kvs_open_default(dbfile, &db, &kvs_config);
    }
    cb_args.handle = db;
    s = fdb_compact(dbfile, "./compact_test4");
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    TEST_CHK(cb_args.n_moved_docs == n);
    TEST_CHK(cb_args.begin);
    TEST_CHK(cb_args.end);
    TEST_CHK(!cb_args.wal_flush);
    fdb_close(dbfile);

    // open db without begin/end
    memset(&cb_args, 0x0, sizeof(struct cb_args));
    fconfig.compaction_cb_mask = FDB_CS_MOVE_DOC |
                                 FDB_CS_FLUSH_WAL;
    fdb_open(&dbfile, "./compact_test4", &fconfig);
    if (multi_kv) {
        fdb_kvs_open(dbfile, &db, "db", &kvs_config);
    } else {
        fdb_kvs_open_default(dbfile, &db, &kvs_config);
    }
    cb_args.handle = db;
    s = fdb_compact(dbfile, "./compact_test5");
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    TEST_CHK(cb_args.n_moved_docs == n);
    TEST_CHK(!cb_args.begin);
    TEST_CHK(!cb_args.end);
    TEST_CHK(cb_args.wal_flush);
    fdb_close(dbfile);

    // open db with batch move
    memset(&cb_args, 0x0, sizeof(struct cb_args));
    fconfig.compaction_cb_mask = FDB_CS_BATCH_MOVE;
    fdb_open(&dbfile, "./compact_test5", &fconfig);
    if (multi_kv) {
        fdb_kvs_open(dbfile, &db, "db", &kvs_config);
    } else {
        fdb_kvs_open_default(dbfile, &db, &kvs_config);
    }
    cb_args.handle = db;
    s = fdb_compact(dbfile, "./compact_test6");
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    TEST_CHK(cb_args.n_moved_docs == 0);
    TEST_CHK(cb_args.n_batch_move && cb_args.n_batch_move <= n);
    TEST_CHK(!cb_args.begin);
    TEST_CHK(!cb_args.end);
    TEST_CHK(!cb_args.wal_flush);
    fdb_close(dbfile);

    fdb_shutdown();

    memleak_end();
    if (multi_kv) {
        TEST_RESULT("compaction callback function multi kv mode test");
    } else {
        TEST_RESULT("compaction callback function single kv mode test");
    }
}

void compact_wo_reopen_test()
{
    TEST_INIT();

    memleak_start();

    int i, r;
    int n = 3;
    fdb_file_handle *dbfile, *dbfile_new;
    fdb_kvs_handle *db;
    fdb_kvs_handle *db_new;
    fdb_doc **doc = alca(fdb_doc*, n);
    fdb_doc *rdoc;
    fdb_status status;

    char keybuf[256], metabuf[256], bodybuf[256];

    // remove previous compact_test files
    r = system(SHELL_DEL" compact_test* > errorlog.txt");
    (void)r;

    fdb_config fconfig = fdb_get_default_config();
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    fconfig.buffercache_size = 16777216;
    fconfig.wal_threshold = 1024;
    fconfig.flags = FDB_OPEN_FLAG_CREATE;
    fconfig.compaction_threshold = 0;

    // open db
    fdb_open(&dbfile, "./compact_test1", &fconfig);
    fdb_kvs_open_default(dbfile, &db, &kvs_config);
    status = fdb_set_log_callback(db, logCallbackFunc,
                                  (void *) "compact_wo_reopen_test");
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    fdb_open(&dbfile_new, "./compact_test1", &fconfig);
    fdb_kvs_open_default(dbfile_new, &db_new, &kvs_config);
    status = fdb_set_log_callback(db_new, logCallbackFunc,
                                  (void *) "compact_wo_reopen_test");
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

    // remove doc
    fdb_doc_create(&rdoc, doc[1]->key, doc[1]->keylen, doc[1]->meta, doc[1]->metalen, NULL, 0);
    rdoc->deleted = true;
    fdb_set(db, rdoc);
    fdb_doc_free(rdoc);

    // commit
    fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);

    // perform compaction using one handle
    fdb_compact(dbfile, (char *) "./compact_test2");

    // retrieve documents using the other handle without close/re-open
    for (i=0;i<n;++i){
        // search by key
        fdb_doc_create(&rdoc, doc[i]->key, doc[i]->keylen, NULL, 0, NULL, 0);
        status = fdb_get(db_new, rdoc);

        if (i != 1) {
            TEST_CHK(status == FDB_RESULT_SUCCESS);
            TEST_CMP(rdoc->meta, doc[i]->meta, rdoc->metalen);
            TEST_CMP(rdoc->body, doc[i]->body, rdoc->bodylen);
        }else{
            TEST_CHK(status == FDB_RESULT_KEY_NOT_FOUND);
        }

        // free result document
        fdb_doc_free(rdoc);
    }
    // check the other handle's filename
    fdb_file_info info;
    fdb_get_file_info(dbfile_new, &info);
    TEST_CHK(!strcmp("./compact_test2", info.filename));

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

    TEST_RESULT("compaction without reopen test");
}

void compact_with_reopen_test()
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

    char keybuf[256], metabuf[256], bodybuf[256], temp[256];

    // remove previous compact_test files
    r = system(SHELL_DEL" compact_test* > errorlog.txt");
    (void)r;

    fdb_config fconfig = fdb_get_default_config();
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    fconfig.buffercache_size = 16777216;
    fconfig.wal_threshold = 1024;
    fconfig.flags = FDB_OPEN_FLAG_CREATE;
    fconfig.compaction_threshold = 0;

    // open db
    fdb_open(&dbfile, "./compact_test1", &fconfig);
    fdb_kvs_open_default(dbfile, &db, &kvs_config);
    status = fdb_set_log_callback(db, logCallbackFunc,
                                  (void *) "compact_with_reopen_test");
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

    // remove doc
    fdb_doc_create(&rdoc, doc[1]->key, doc[1]->keylen, doc[1]->meta, doc[1]->metalen, NULL, 0);
    rdoc->deleted = true;
    fdb_set(db, rdoc);
    fdb_doc_free(rdoc);

    // commit
    fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);

    // perform compaction using one handle
    fdb_compact(dbfile, (char *) "./compact_test2");

    // close db file
    fdb_kvs_close(db);
    fdb_close(dbfile);

    r = system(SHELL_MOVE " compact_test2 compact_test1 > errorlog.txt");
    (void)r;
    fdb_open(&dbfile, "./compact_test1", &fconfig);
    fdb_kvs_open_default(dbfile, &db, &kvs_config);
    status = fdb_set_log_callback(db, logCallbackFunc,
                                  (void *) "compact_with_reopen_test");
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // retrieve documents using the other handle without close/re-open
    for (i=0;i<n;++i){
        // search by key
        fdb_doc_create(&rdoc, doc[i]->key, doc[i]->keylen, NULL, 0, NULL, 0);
        status = fdb_get(db, rdoc);

        if (i != 1) {
            TEST_CHK(status == FDB_RESULT_SUCCESS);
            TEST_CMP(rdoc->meta, doc[i]->meta, rdoc->metalen);
            TEST_CMP(rdoc->body, doc[i]->body, rdoc->bodylen);
        }else{
            TEST_CHK(status == FDB_RESULT_KEY_NOT_FOUND);
        }

        // free result document
        fdb_doc_free(rdoc);
    }
    // check the other handle's filename
    fdb_file_info info;
    fdb_get_file_info(dbfile, &info);
    TEST_CHK(!strcmp("./compact_test1", info.filename));

    // update documents
    for (i=0;i<n;++i){
        sprintf(metabuf, "newmeta%d", i);
        sprintf(bodybuf, "newbody%d_%s", i, temp);
        fdb_doc_update(&doc[i], (void *)metabuf, strlen(metabuf),
                       (void *)bodybuf, strlen(bodybuf));
        fdb_set(db, doc[i]);
    }

    // Open the database with another handle.
    fdb_file_handle *second_dbfile;
    fdb_kvs_handle *second_dbh;
    fdb_open(&second_dbfile, "./compact_test1", &fconfig);
    fdb_kvs_open_default(second_dbfile, &second_dbh, &kvs_config);
    status = fdb_set_log_callback(second_dbh, logCallbackFunc,
                                  (void *) "compact_with_reopen_test");
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    // In-place compactions with a handle still open on the first old file
    status = fdb_compact(dbfile, NULL);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    status = fdb_compact(dbfile, NULL);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // MB-12977: retest compaction again..
    status = fdb_compact(dbfile, NULL);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    fdb_kvs_close(db);
    fdb_close(dbfile);

    for (i=0;i<n;++i){
        // search by key
        fdb_doc_create(&rdoc, doc[i]->key, doc[i]->keylen, NULL, 0, NULL, 0);
        status = fdb_get(second_dbh, rdoc);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        TEST_CMP(rdoc->meta, doc[i]->meta, rdoc->metalen);
        TEST_CMP(rdoc->body, doc[i]->body, rdoc->bodylen);
        // free result document
        fdb_doc_free(rdoc);
    }

    // Open database with an original name.
    status = fdb_open(&dbfile, "./compact_test1", &fconfig);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_kvs_open_default(dbfile, &db, &kvs_config);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_set_log_callback(db, logCallbackFunc,
                                  (void *) "compact_with_reopen_test");
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    fdb_get_file_info(dbfile, &info);
    // The actual file name should be a compacted one.
    TEST_CHK(!strcmp("./compact_test1.3", info.filename));

    fdb_kvs_close(second_dbh);
    fdb_close(second_dbfile);

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

    fdb_compact(dbfile, NULL);
    fdb_kvs_close(db);
    fdb_close(dbfile);

    r = system(SHELL_MOVE " compact_test1 compact_test.fdb > errorlog.txt");
    (void)r;
    fdb_open(&dbfile, "./compact_test.fdb", &fconfig);
    fdb_kvs_open_default(dbfile, &db, &kvs_config);
    status = fdb_set_log_callback(db, logCallbackFunc,
                                  (void *) "compact_with_reopen_test");
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    // In-place compaction
    fdb_compact(dbfile, NULL);
    fdb_kvs_close(db);
    fdb_close(dbfile);
    // Open database with an original name.
    status = fdb_open(&dbfile, "./compact_test.fdb", &fconfig);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_kvs_open_default(dbfile, &db, &kvs_config);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_set_log_callback(db, logCallbackFunc,
                                  (void *) "compact_with_reopen_test");
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    fdb_get_file_info(dbfile, &info);
    TEST_CHK(!strcmp("./compact_test.fdb", info.filename));
    TEST_CHK(info.doc_count == 100);

    // free all documents
    for (i=0;i<n;++i){
        fdb_doc_free(doc[i]);
    }

    fdb_kvs_close(db);
    fdb_close(dbfile);

    // free all resources
    fdb_shutdown();

    memleak_end();

    TEST_RESULT("compaction with reopen test");
}

void compact_reopen_named_kvs()
{
    TEST_INIT();

    memleak_start();

    int i, r;
    int n = 100;
    int nkvdocs;
    fdb_file_handle *dbfile;
    fdb_kvs_handle *db;
    fdb_doc **doc = alca(fdb_doc*, n);
    fdb_status status;
    fdb_kvs_info kvs_info;

    char keybuf[256], metabuf[256], bodybuf[256];

    // remove previous compact_test files
    r = system(SHELL_DEL" compact_test* > errorlog.txt");
    (void)r;

    fdb_config fconfig = fdb_get_default_config();
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    fconfig.wal_threshold = 1024;
    fconfig.flags = FDB_OPEN_FLAG_CREATE;
    fconfig.compaction_threshold = 0;

    // open db
    fdb_open(&dbfile, "./compact_test1", &fconfig);
    fdb_kvs_open(dbfile, &db, "db",  &kvs_config);

    status = fdb_set_log_callback(db, logCallbackFunc,
                                  (void *) "compact_reopen_named_kvs");
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    for (i=0;i<n;++i){
        sprintf(keybuf, "key%d", i);
        sprintf(metabuf, "meta%d", i);
        sprintf(bodybuf, "body%d", i);
        fdb_doc_create(&doc[i], (void*)keybuf, strlen(keybuf),
            (void*)metabuf, strlen(metabuf), (void*)bodybuf, strlen(bodybuf));
        fdb_set(db, doc[i]);
    }

    // commit
    fdb_commit(dbfile, FDB_COMMIT_NORMAL);

    // compact
    fdb_compact(dbfile, NULL);

    // save ndocs
    fdb_get_kvs_info(db, &kvs_info);
    nkvdocs = kvs_info.doc_count;

    // close db file
    fdb_kvs_close(db);
    fdb_close(dbfile);

    // reopen
    fdb_open(&dbfile, "./compact_test1", &fconfig);
    fdb_kvs_open(dbfile, &db, "db",  &kvs_config);

    // verify kvs stats
    fdb_get_kvs_info(db, &kvs_info);
    TEST_CHK((uint64_t)nkvdocs == kvs_info.doc_count);

    fdb_kvs_close(db);
    fdb_close(dbfile);

    // free all documents
    for (i=0;i<n;++i){
        fdb_doc_free(doc[i]);
    }
    fdb_shutdown();

    memleak_end();

    TEST_RESULT("compact reopen named kvs");
}

void compact_reopen_with_iterator()
{
    TEST_INIT();

    memleak_start();

    int i, r;
    int n = 9;
    int count = 0;
    int nkvdocs;
    fdb_file_handle *dbfile, *compact_file;
    fdb_kvs_handle *db;
    fdb_doc **doc = alca(fdb_doc*, n);
    fdb_doc *rdoc = NULL;
    fdb_status status;
    fdb_kvs_info kvs_info;
    fdb_iterator *iterator;

    char keybuf[256], metabuf[256], bodybuf[256];

    // remove previous compact_test files
    r = system(SHELL_DEL" compact_test* > errorlog.txt");
    (void)r;

    fdb_config fconfig = fdb_get_default_config();
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    fconfig.wal_threshold = 1024;
    fconfig.flags = FDB_OPEN_FLAG_CREATE;
    fconfig.compaction_threshold = 0;

    // open db
    fdb_open(&dbfile, "./compact_test1", &fconfig);
    fdb_kvs_open(dbfile, &db, "db",  &kvs_config);

    status = fdb_set_log_callback(db, logCallbackFunc,
                                  (void *) "compact_reopen_with_iterator");
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    for (i=0;i<n;++i){
        sprintf(keybuf, "key%d", i);
        sprintf(metabuf, "meta%d", i);
        sprintf(bodybuf, "body%d", i);
        fdb_doc_create(&doc[i], (void*)keybuf, strlen(keybuf),
            (void*)metabuf, strlen(metabuf), (void*)bodybuf, strlen(bodybuf));
        fdb_set(db, doc[i]);
    }

    // commit
    fdb_commit(dbfile, FDB_COMMIT_NORMAL);

    // MB-13859: compact the file using a separate handle..
    fdb_open(&compact_file, "./compact_test1", &fconfig);
    // compact
    status = fdb_compact(compact_file, "./compact_test2");
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    // close file after compaction to make the new_file's ref count 0
    fdb_close(compact_file);

    i = 0;
    status = fdb_iterator_init(db, &iterator, NULL, 0, NULL, 0, FDB_ITR_NONE);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
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

    TEST_CHK(count==n);


    status = fdb_iterator_close(iterator);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // save ndocs
    fdb_get_kvs_info(db, &kvs_info);
    nkvdocs = kvs_info.doc_count;

    // close db file
    fdb_kvs_close(db);
    fdb_close(dbfile);

    // reopen
    fdb_open(&dbfile, "./compact_test2", &fconfig);
    fdb_kvs_open(dbfile, &db, "db",  &kvs_config);

    // verify kvs stats
    fdb_get_kvs_info(db, &kvs_info);
    TEST_CHK((uint64_t)nkvdocs == kvs_info.doc_count);

    fdb_kvs_close(db);
    fdb_close(dbfile);

    // free all documents
    for (i=0;i<n;++i){
        fdb_doc_free(doc[i]);
    }
    fdb_shutdown();

    memleak_end();

    TEST_RESULT("compact reopen with iterator");
}

void open_newfile_before_compact_done(void)
{
    TEST_INIT();

    memleak_start();

    int i, j, r;
    int n = 20;
    int num_kvs = 16;
    fdb_file_handle *dbfile, *illegalfile;
    fdb_kvs_handle **db = alca(fdb_kvs_handle *, num_kvs+1);
    fdb_doc **doc = alca(fdb_doc*, n);
    fdb_status status;

    char keybuf[32], metabuf[32], bodybuf[32];
    char kv_name[8];

    fdb_config fconfig = fdb_get_default_config();
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    fconfig.buffercache_size = 0;
    fconfig.wal_threshold = 50;
    fconfig.flags = FDB_OPEN_FLAG_CREATE;
    fconfig.compaction_threshold = 0;
    fconfig.block_reusing_threshold = 0;

    // remove previous compact_test files
    r = system(SHELL_DEL" compact_test* > errorlog.txt");
    (void)r;

    // open db
    fdb_open(&dbfile, "./compact_test1", &fconfig);
    for (r = 0; r < num_kvs; ++r) {
        sprintf(kv_name, "kv%d", r);
        fdb_kvs_open(dbfile, &db[r], kv_name, &kvs_config);
    }

   // ------- Setup test ----------------------------------
   // insert first quarter of documents
    for (i=0; i<n; i++){
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

    // Update first quarter of documents again overwriting previous update..
    for (j = 0; j < n; j++){
        for (r = 0; r < num_kvs; ++r) {
            fdb_set(db[r], doc[j]);
        }
    }

    // commit again without a WAL flush (some of these docs remain in WAL)
    fdb_commit(dbfile, FDB_COMMIT_NORMAL);

    for (r = 0; r < num_kvs; ++r) {
        status = fdb_set_log_callback(db[r], logCallbackFunc,
                                      (void *)"open_newfile_before_compact_done");
        TEST_CHK(status == FDB_RESULT_SUCCESS);
    }

    // It is illegal to open the new file before compaction is done in
    // manual compaction mode..
    status = fdb_open(&illegalfile, "./compact_test1.b", &fconfig);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    status = fdb_kvs_open(dbfile, &db[num_kvs], kv_name, &kvs_config);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    status = fdb_compact(dbfile, "./compact_test1.b");
    TEST_CHK(status == FDB_RESULT_EEXIST);

    fdb_kvs_close(db[num_kvs]);

    // close db file
    fdb_close(dbfile);
    fdb_close(illegalfile);

    // free all documents
    for (i=0;i<n;++i){
        fdb_doc_free(doc[i]);
    }

    // free all resources
    fdb_shutdown();

    memleak_end();

    TEST_RESULT("illegal new file opened before compaction done");
}

void estimate_space_upto_test(bool multi_kv)
{
    TEST_INIT();

    memleak_start();

    int i, j, r;
    int n = 300;
    int num_kvs = 4; // keep this the same as number of fdb_commit() calls
    fdb_file_handle *dbfile;
    fdb_kvs_handle **db = alca(fdb_kvs_handle *, num_kvs);
    fdb_doc **doc = alca(fdb_doc*, n);
    fdb_status status;
    fdb_snapshot_info_t *markers;
    uint64_t num_markers;
    size_t space_used;

    char keybuf[256], metabuf[256], bodybuf[256];
    char kv_name[8];

    fdb_config fconfig = fdb_get_default_config();
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    fconfig.buffercache_size = 0;
    fconfig.wal_threshold = 50;
    fconfig.flags = FDB_OPEN_FLAG_CREATE;
    fconfig.compaction_threshold = 0;
    fconfig.multi_kv_instances = multi_kv;
    fconfig.block_reusing_threshold = 0;

    // remove previous compact_test files
    r = system(SHELL_DEL" compact_test* > errorlog.txt");
    (void)r;

    // open db
    fdb_open(&dbfile, "./compact_test1", &fconfig);
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
   // insert first quarter of documents
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

    // insert second quarter of documents
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
    // Update first quarter of documents again..
    for (j = 0; j < n/4; j++){
        for (r = 0; r < num_kvs; ++r) {
            fdb_set(db[r], doc[j]);
        }
    }
    // Update first quarter of documents again overwriting previous update..
    for (j = 0; j < n/4; j++){
        for (r = 0; r < num_kvs; ++r) {
            fdb_set(db[r], doc[j]);
        }
    }

    // commit again without a WAL flush (some of these docs remain in WAL)
    fdb_commit(dbfile, FDB_COMMIT_NORMAL);

    // insert third quarter of documents
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
    // manually flush WAL & commit (these docs go into HB-trie)
    fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);

    // insert fourth quarter of documents
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
    // commit without a WAL flush (some of these docs remain in the WAL)
    fdb_commit(dbfile, FDB_COMMIT_NORMAL);

    for (r = 0; r < num_kvs; ++r) {
        status = fdb_set_log_callback(db[r], logCallbackFunc,
                                      (void *) "estimate_space_upto_test");
        TEST_CHK(status == FDB_RESULT_SUCCESS);
    }

    status = fdb_get_all_snap_markers(dbfile, &markers, &num_markers);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    if (!multi_kv) {
        size_t space_used2;
        TEST_CHK(num_markers == 5);
        space_used = fdb_estimate_space_used_from(dbfile, markers[1].marker);
        space_used2 = fdb_estimate_space_used_from(dbfile, markers[2].marker);
        TEST_CHK(space_used2 > space_used); // greater than space used by just 1
    } else {
        size_t space_used2;
        TEST_CHK(num_markers == 9);
        space_used = fdb_estimate_space_used_from(dbfile, markers[1].marker);
        space_used2 = fdb_estimate_space_used_from(dbfile, markers[2].marker);
        TEST_CHK(space_used2 > space_used); // greater than space used by just 1
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

    sprintf(bodybuf, "estimate space upto marker in file test %s", multi_kv ?
                                                           "multiple kv mode:"
                                                         : "single kv mode:");
    TEST_RESULT(bodybuf);
}

void compact_upto_test(bool multi_kv)
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
    fdb_kvs_handle *snapshot;
    uint64_t num_markers;

    char keybuf[256], metabuf[256], bodybuf[256];
    char kv_name[8];
    char compact_filename[32];

    fdb_config fconfig = fdb_get_default_config();
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    fconfig.buffercache_size = 0;
    fconfig.wal_threshold = 1024;
    fconfig.flags = FDB_OPEN_FLAG_CREATE;
    fconfig.compaction_threshold = 0;
    fconfig.multi_kv_instances = multi_kv;
    // since this test requires static number of markers,
    // disable block reusing
    fconfig.block_reusing_threshold = 0;

    // remove previous compact_test files
    r = system(SHELL_DEL" compact_test* > errorlog.txt");
    (void)r;

    // open db
    fdb_open(&dbfile, "./compact_test1", &fconfig);
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
                                      (void *) "compact_upto_test");
        TEST_CHK(status == FDB_RESULT_SUCCESS);
    }

    status = fdb_get_all_snap_markers(dbfile, &markers, &num_markers);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    if (!multi_kv) {
        TEST_CHK(num_markers == 5);
        for (r = 0; (uint64_t)r < num_markers; ++r) {
            TEST_CHK(markers[r].num_kvs_markers == 1);
            TEST_CHK(markers[r].kvs_markers[0].seqnum ==
                     (fdb_seqnum_t)(n - r*5));
        }
        r = 1; // Test compacting upto sequence number 15
        sprintf(compact_filename, "compact_test_compact%d", r);
        status = fdb_compact_upto(dbfile, compact_filename,
                                  markers[r].marker);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        // create a snapshot
        status = fdb_snapshot_open(db[0], &snapshot,
                                   markers[r].kvs_markers[0].seqnum);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        // close snapshot
        fdb_kvs_close(snapshot);
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
        i = r = 1;
        sprintf(compact_filename, "compact_test_compact%d", i);
        status = fdb_compact_upto(dbfile, compact_filename,
                markers[i].marker);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        // create a snapshot
        status = fdb_snapshot_open(db[r], &snapshot,
                markers[i].kvs_markers[r].seqnum);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        // close snapshot
        fdb_kvs_close(snapshot);
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

    sprintf(bodybuf, "compact upto marker in file test %s", multi_kv ?
                                                           "multiple kv mode:"
                                                         : "single kv mode:");
    TEST_RESULT(bodybuf);
}

void auto_recover_compact_ok_test()
{
    TEST_INIT();

    memleak_start();

    int i, r;
    int n = 3;
    fdb_file_handle *dbfile, *dbfile_new;
    fdb_kvs_handle *db;
    fdb_kvs_handle *db_new;
    fdb_doc **doc = alca(fdb_doc *, n);
    fdb_doc *rdoc;
    fdb_status status;

    char keybuf[256], metabuf[256], bodybuf[256];

    // remove previous compact_test files
    r = system(SHELL_DEL " compact_test* > errorlog.txt");
    (void)r;

    fdb_config fconfig = fdb_get_default_config();
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    fconfig.buffercache_size = 16777216;
    fconfig.wal_threshold = 1024;
    fconfig.flags = FDB_OPEN_FLAG_CREATE;
    fconfig.compaction_threshold = 0;

    // open db
    fdb_open(&dbfile, "./compact_test1", &fconfig);
    fdb_kvs_open_default(dbfile, &db, &kvs_config);
    status = fdb_set_log_callback(db, logCallbackFunc,
                                  (void *) "auto_recover_compact_ok_test");
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    fdb_open(&dbfile_new, "./compact_test1", &fconfig);
    fdb_kvs_open_default(dbfile_new, &db_new, &kvs_config);
    status = fdb_set_log_callback(db_new, logCallbackFunc,
                                  (void *) "auto_recover_compact_ok_test");
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // insert first two documents
    for (i=0;i<2;++i){
        sprintf(keybuf, "key%d", i);
        sprintf(metabuf, "meta%d", i);
        sprintf(bodybuf, "body%d", i);
        fdb_doc_create(&doc[i], (void*)keybuf, strlen(keybuf),
            (void*)metabuf, strlen(metabuf), (void*)bodybuf, strlen(bodybuf));
        fdb_set(db, doc[i]);
    }

    // remove second doc
    fdb_doc_create(&rdoc, doc[1]->key, doc[1]->keylen, doc[1]->meta, doc[1]->metalen, NULL, 0);
    rdoc->deleted = true;
    fdb_set(db, rdoc);
    fdb_doc_free(rdoc);

    // commit
    fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);

    // perform compaction using one handle
    fdb_compact(dbfile, (char *) "./compact_test2");

    // save the old file after compaction is done ..
    r = system(SHELL_COPY " compact_test1 compact_test11 > errorlog.txt");
    (void)r;

    // now insert third doc: it should go to the newly compacted file.
    sprintf(keybuf, "key%d", i);
    sprintf(metabuf, "meta%d", i);
    sprintf(bodybuf, "body%d", i);
    fdb_doc_create(&doc[i], (void*)keybuf, strlen(keybuf),
        (void*)metabuf, strlen(metabuf), (void*)bodybuf, strlen(bodybuf));
    fdb_set(db, doc[i]);

    // commit
    fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);

    // close both the db files ...
    fdb_kvs_close(db);
    fdb_kvs_close(db_new);
    fdb_close(dbfile);
    fdb_close(dbfile_new);

    // restore the old file after close is done ..
    r = system(SHELL_MOVE " compact_test11 compact_test1 > errorlog.txt");
    (void)r;

    // now open the old saved compacted file, it should automatically recover
    // and use the new file since compaction was done successfully
    fdb_open(&dbfile_new, "./compact_test1", &fconfig);
    fdb_kvs_open_default(dbfile_new, &db_new, &kvs_config);
    status = fdb_set_log_callback(db_new, logCallbackFunc,
                                  (void *) "auto_recover_compact_ok_test");
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // retrieve documents using the old handle and expect all 3 docs
    for (i=0;i<n;++i){
        // search by key
        fdb_doc_create(&rdoc, doc[i]->key, doc[i]->keylen, NULL, 0, NULL, 0);
        status = fdb_get(db_new, rdoc);

        if (i != 1) {
            TEST_CHK(status == FDB_RESULT_SUCCESS);
            TEST_CMP(rdoc->meta, doc[i]->meta, rdoc->metalen);
            TEST_CMP(rdoc->body, doc[i]->body, rdoc->bodylen);
        }else{
            TEST_CHK(status == FDB_RESULT_KEY_NOT_FOUND);
        }

        // free result document
        fdb_doc_free(rdoc);
    }
    // check this handle's filename it should point to newly compacted file
    fdb_file_info info;
    fdb_get_file_info(dbfile_new, &info);
    TEST_CHK(!strcmp("./compact_test2", info.filename));

    // close the file
    fdb_kvs_close(db_new);
    fdb_close(dbfile_new);

    // free all documents
    for (i=0;i<n;++i){
        fdb_doc_free(doc[i]);
    }

    // free all resources
    fdb_shutdown();

    memleak_end();

    TEST_RESULT("auto recovery after compaction test");
}

#if !defined(WIN32) && !defined(_WIN32)
static bool does_file_exist(const char *filename) {
    struct stat st;
    int result = stat(filename, &st);
    return result == 0;
}
#else
static bool does_file_exist(const char *filename) {
    return GetFileAttributes(filename) != INVALID_FILE_ATTRIBUTES;
}
#endif

void unlink_after_compaction_test()
{
    TEST_INIT();
    memleak_start();

    int i, r;
    int n = 10;
    fdb_file_handle *dbfile;
    fdb_kvs_handle *db, *snap;
    fdb_doc **doc = alca(fdb_doc *, n);
    fdb_doc *rdoc;
    fdb_status s;

    char keybuf[256], metabuf[256], bodybuf[256];

    // remove previous compact_test files
    r = system(SHELL_DEL " compact_test* > errorlog.txt");
    (void)r;

    fdb_config fconfig = fdb_get_default_config();
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    fconfig.buffercache_size = 16777216;
    fconfig.wal_threshold = 1024;
    fconfig.flags = FDB_OPEN_FLAG_CREATE;
    fconfig.compaction_threshold = 0;

    // open db
    fdb_open(&dbfile, "./compact_test1", &fconfig);
    fdb_kvs_open_default(dbfile, &db, &kvs_config);
    s = fdb_set_log_callback(db, logCallbackFunc,
                             (void *) "unlink_after_compaction_test");
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    // set docs
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

    // create a snapshot
    s = fdb_snapshot_open(db, &snap, n);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    // compaction
    s = fdb_compact(dbfile, "./compact_test2");
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    // retrieve check on the new file
    for (i=0;i<n;++i){
        fdb_doc_create(&rdoc, doc[i]->key, doc[i]->keylen, NULL, 0, NULL, 0);
        s = fdb_get(db, rdoc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        fdb_doc_free(rdoc);
    }

    // the old file should not be seen by user level application
#if !defined(WIN32) && !defined(_WIN32)
#ifndef _MSC_VER
    TEST_CHK(!does_file_exist("./compact_test1"));
#endif
#endif

    // retrieve check on the old file (snapshot)
    for (i=0;i<n;++i){
        fdb_doc_create(&rdoc, doc[i]->key, doc[i]->keylen, NULL, 0, NULL, 0);
        s = fdb_get(snap, rdoc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        fdb_doc_free(rdoc);
    }

    fdb_close(dbfile);

    fdb_shutdown();
    for (i=0; i<n; ++i){
        fdb_doc_free(doc[i]);
    }

    memleak_end();
    TEST_RESULT("unlink after compaction test");
}

void db_compact_overwrite()
{
    TEST_INIT();
    memleak_start();

    int i, r;
    int n = 30;
    fdb_file_handle *dbfile, *dbfile2;
    fdb_kvs_handle *db, *db2;
    fdb_doc **doc = alca(fdb_doc *, n);
    fdb_doc **doc2 = alca(fdb_doc *, 2*n);
    fdb_doc *rdoc;
    fdb_status status;
    fdb_config fconfig;
    fdb_kvs_info kvs_info;
    fdb_kvs_config kvs_config;

    char keybuf[256], metabuf[256], bodybuf[256];

    // remove previous compact_test files
    r = system(SHELL_DEL " compact_test* > errorlog.txt");
    (void)r;

    fconfig = fdb_get_default_config();
    kvs_config = fdb_get_default_kvs_config();
    fconfig.buffercache_size = 16777216;
    fconfig.wal_threshold = 1024;
    fconfig.flags = FDB_OPEN_FLAG_CREATE;
    fconfig.compaction_threshold = 0;

    // write to db1
    fdb_open(&dbfile, "./compact_test1", &fconfig);
    fdb_kvs_open(dbfile, &db, NULL, &kvs_config);
    status = fdb_set_log_callback(db, logCallbackFunc,
                                  (void *) "db_destroy_test");
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    for (i=0;i<n;++i){
        sprintf(keybuf, "key%d", i);
        sprintf(metabuf, "meta%d", i);
        sprintf(bodybuf, "body%d", i);
        fdb_doc_create(&doc[i], (void*)keybuf, strlen(keybuf),
            (void*)metabuf, strlen(metabuf), (void*)bodybuf, strlen(bodybuf));
        fdb_set(db, doc[i]);
    }
    fdb_commit(dbfile, FDB_COMMIT_NORMAL);

    // Open the empty db with future compact name
    fdb_open(&dbfile2, "./compact_test1.1", &fconfig);
    fdb_kvs_open(dbfile2, &db2, NULL, &kvs_config);
    status = fdb_set_log_callback(db2, logCallbackFunc,
                                  (void *) "db_destroy_test");
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    // write to db2
    for (i=0;i < 2*n;++i){
        sprintf(keybuf, "k2ey%d", i);
        sprintf(metabuf, "m2eta%d", i);
        sprintf(bodybuf, "b2ody%d", i);
        fdb_doc_create(&doc2[i], (void*)keybuf, strlen(keybuf),
            (void*)metabuf, strlen(metabuf), (void*)bodybuf, strlen(bodybuf));
        fdb_set(db2, doc2[i]);
    }
    fdb_commit(dbfile2, FDB_COMMIT_NORMAL);


    // verify db2 seqnum and close
    fdb_get_kvs_info(db2, &kvs_info);
    TEST_CHK(kvs_info.last_seqnum = 2*n);
    fdb_kvs_close(db2);
    fdb_close(dbfile2);

    // compact db1
    status = fdb_compact(dbfile, NULL);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // close db1
    fdb_kvs_close(db);
    fdb_close(dbfile);

    // reopen db1
    fdb_open(&dbfile, "./compact_test1", &fconfig);
    fdb_kvs_open(dbfile, &db, NULL, &kvs_config);
    status = fdb_set_log_callback(db, logCallbackFunc,
                                  (void *) "db_destroy_test");
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    // read db1
    for (i=0;i<n;++i){
        // search by key
        fdb_doc_create(&rdoc, doc[i]->key, doc[i]->keylen, NULL, 0, NULL, 0);
        status = fdb_get(db, rdoc);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        TEST_CHK(!memcmp(rdoc->meta, doc[i]->meta, rdoc->metalen));
        TEST_CHK(!memcmp(rdoc->body, doc[i]->body, rdoc->bodylen));
        // free result document
        fdb_doc_free(rdoc);
    }

    // reopen db2
    fdb_open(&dbfile2, "./compact_test1.1", &fconfig);
    fdb_kvs_open(dbfile2, &db2, NULL, &kvs_config);
    status = fdb_set_log_callback(db2, logCallbackFunc,
                                  (void *) "db_destroy_test");
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    fdb_get_kvs_info(db2, &kvs_info);
    TEST_CHK(kvs_info.last_seqnum = 2*n);

    // read db2
    for (i=0;i<2*n;++i){
        // search by key
        fdb_doc_create(&rdoc, doc2[i]->key, doc2[i]->keylen, NULL, 0, NULL, 0);
        status = fdb_get(db2, rdoc);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        TEST_CHK(!memcmp(rdoc->meta, doc2[i]->meta, rdoc->metalen));
        TEST_CHK(!memcmp(rdoc->body, doc2[i]->body, rdoc->bodylen));
        // free result document
        fdb_doc_free(rdoc);
    }

    // free all documents
    for (i=0;i<n;++i){
        fdb_doc_free(doc[i]);
        fdb_doc_free(doc2[i]);
    }
    for (i=n;i<2*n;++i){
        fdb_doc_free(doc2[i]);
    }

    fdb_kvs_close(db);
    fdb_close(dbfile);
    fdb_kvs_close(db2);
    fdb_close(dbfile2);


    fdb_shutdown();
    memleak_end();
    TEST_RESULT("compact overwrite");
}

void *db_compact_during_doc_delete(void *args)
{

    TEST_INIT();
    memleak_start();

    int i, r;
    int n = 100;
    fdb_file_handle *dbfile;
    fdb_kvs_handle *db;
    fdb_status status;
    fdb_config fconfig;
    fdb_kvs_config kvs_config;
    fdb_kvs_info kvs_info;
    thread_t tid;
    void *thread_ret;
    fdb_doc **doc = alca(fdb_doc*, n);
    char keybuf[256], metabuf[256], bodybuf[256];

    // init dbfile
    kvs_config = fdb_get_default_kvs_config();
    fconfig = fdb_get_default_config();
    fconfig.buffercache_size = 0;
    fconfig.wal_threshold = 1024;
    fconfig.compaction_threshold = 0;

    if (args == NULL)
    { // parent

        r = system(SHELL_DEL" compact_test* > errorlog.txt");
        (void)r;

        status = fdb_open(&dbfile, "./compact_test1", &fconfig);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        status = fdb_kvs_open_default(dbfile, &db, &kvs_config);
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

        fdb_commit(dbfile, FDB_COMMIT_NORMAL);
        // verify no docs remaining
        fdb_get_kvs_info(db, &kvs_info);
        TEST_CHK(kvs_info.doc_count == (uint64_t)n);

        // start deleting docs
        for (i=0;i<n;++i){
            fdb_del(db, doc[i]);
            if (i == n/2){
                // compact half-way
                thread_create(&tid, db_compact_during_doc_delete, (void *)dbfile);
            }
        }

        // join compactor
        thread_join(tid, &thread_ret);

        fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);

        // verify no docs remaining
        fdb_get_kvs_info(db, &kvs_info);
        TEST_CHK(kvs_info.doc_count == 0);

        // reopen
        fdb_kvs_close(db);
        fdb_close(dbfile);
        status = fdb_open(&dbfile, "./compact_test1", &fconfig);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        status = fdb_kvs_open_default(dbfile, &db, &kvs_config);
        TEST_CHK(status == FDB_RESULT_SUCCESS);

        fdb_get_kvs_info(db, &kvs_info);
        TEST_CHK(kvs_info.doc_count == 0);

        // cleanup
        for (i=0;i<n;++i){
            fdb_doc_free(doc[i]);
        }
        fdb_kvs_close(db);
        fdb_close(dbfile);
        fdb_shutdown();

        memleak_end();
        TEST_RESULT("multi thread client shutdown");
        return NULL;
    }

    // compaction thread enters here //
    status = fdb_open(&dbfile, "./compact_test1", &fconfig);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_compact(dbfile, NULL);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    fdb_close(dbfile);

    // shutdown
    thread_exit(0);
    return NULL;
}

void compaction_daemon_test(size_t time_sec)
{
    TEST_INIT();

    memleak_start();

    int i, r;
    int n = 10000;
    int compaction_threshold = 30;
    int escape = 0;
    fdb_file_handle *dbfile, *dbfile_less, *dbfile_non, *dbfile_manual, *dbfile_new;
    fdb_kvs_handle *db, *db_less, *db_non, *db_manual;
    fdb_kvs_handle *snapshot;
    fdb_doc **doc = alca(fdb_doc*, n);
    fdb_doc *rdoc;
    fdb_file_info info;
    fdb_status status;
    struct timeval ts_begin, ts_cur, ts_gap;

    char keybuf[256], metabuf[256], bodybuf[256];

    // remove previous compact_test files
    r = system(SHELL_DEL" compact_test* > errorlog.txt");
    (void)r;

    fdb_config fconfig = fdb_get_default_config();
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    fconfig.buffercache_size = 0;
    fconfig.wal_threshold = 1024;
    fconfig.flags = FDB_OPEN_FLAG_CREATE;
    fconfig.compaction_mode = FDB_COMPACTION_AUTO;
    fconfig.compaction_threshold = compaction_threshold;
    fconfig.compactor_sleep_duration = 1; // for quick test

    fconfig.num_compactor_threads = 0;
    status = fdb_open(&dbfile, "compact_test", &fconfig);
    TEST_CHK(status == FDB_RESULT_INVALID_CONFIG);

    fconfig.num_compactor_threads = DEFAULT_NUM_COMPACTOR_THREADS;
    // open db
    fdb_open(&dbfile, "compact_test", &fconfig);
    fdb_kvs_open_default(dbfile, &db, &kvs_config);
    status = fdb_set_log_callback(db, logCallbackFunc,
                                  (void *) "compaction_daemon_test");
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    // insert documents
    printf("Initialize..\n");
    for (i=0;i<n;++i){
        sprintf(keybuf, "key%04d", i);
        sprintf(metabuf, "meta%04d", i);
        sprintf(bodybuf, "body%04d", i);
        fdb_doc_create(&doc[i], (void*)keybuf, strlen(keybuf)+1,
            (void*)metabuf, strlen(metabuf)+1, (void*)bodybuf, strlen(bodybuf)+1);
        fdb_set(db, doc[i]);
    }
    // commit
    fdb_commit(dbfile, FDB_COMMIT_NORMAL);
    // close db file
    fdb_close(dbfile);

    // ---- basic retrieve test ------------------------
    // reopen db file
    status = fdb_open(&dbfile, "compact_test", &fconfig);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_kvs_open_default(dbfile, &db, &kvs_config);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_set_log_callback(db, logCallbackFunc,
                                  (void *) "compaction_daemon_test");
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    // check db filename
    fdb_get_file_info(dbfile, &info);
    TEST_CHK(!strcmp(info.filename, "compact_test"));

    // retrieve documents
    for (i=0;i<n;++i){
        sprintf(keybuf, "key%04d", i);
        fdb_doc_create(&rdoc, (void*)keybuf, strlen(keybuf)+1,
            NULL, 0, NULL, 0);
        status = fdb_get(db, rdoc);
        //printf("%s %s\n", rdoc->key, rdoc->body);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        TEST_CMP(rdoc->body, doc[i]->body, rdoc->bodylen);
        fdb_doc_free(rdoc);
    }

    // create a snapshot
    status = fdb_snapshot_open(db, &snapshot, n);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    // close snapshot
    fdb_kvs_close(snapshot);

    // close db file
    fdb_close(dbfile);

    // ---- handling when metafile is removed ------------
    // remove meta file
    r = system(SHELL_DEL" compact_test.meta > errorlog.txt");
    (void)r;
    // reopen db file
    status = fdb_open(&dbfile, "compact_test", &fconfig);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_kvs_open_default(dbfile, &db, &kvs_config);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_set_log_callback(db, logCallbackFunc,
                                  (void *) "compaction_daemon_test");
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    // retrieve documents
    for (i=0;i<n;++i){
        sprintf(keybuf, "key%04d", i);
        fdb_doc_create(&rdoc, (void*)keybuf, strlen(keybuf)+1,
            NULL, 0, NULL, 0);
        status = fdb_get(db, rdoc);
        //printf("%s %s\n", rdoc->key, rdoc->body);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        TEST_CMP(rdoc->body, doc[i]->body, rdoc->bodylen);
        fdb_doc_free(rdoc);
    }
    // close db file
    fdb_close(dbfile);

    // ---- handling when metafile points to non-exist file ------------
    // remove meta file
    r = system(SHELL_MOVE" compact_test.0 compact_test.23 > errorlog.txt");
    (void)r;
    // reopen db file
    status = fdb_open(&dbfile, "compact_test", &fconfig);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_kvs_open_default(dbfile, &db, &kvs_config);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_set_log_callback(db, logCallbackFunc,
                                  (void *) "compaction_daemon_test");
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    // retrieve documents
    for (i=0;i<n;++i){
        sprintf(keybuf, "key%04d", i);
        fdb_doc_create(&rdoc, (void*)keybuf, strlen(keybuf)+1,
            NULL, 0, NULL, 0);
        status = fdb_get(db, rdoc);
        //printf("%s %s\n", rdoc->key, rdoc->body);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        TEST_CMP(rdoc->body, doc[i]->body, rdoc->bodylen);
        fdb_doc_free(rdoc);
    }
    // close db file
    fdb_close(dbfile);

    // ---- compaction daemon test -------------------
    // db: DB instance to be compacted
    // db_less: DB instance to be compacted but with much lower update throughput
    // db_non: DB instance not to be compacted (auto compaction with threshold = 0)
    // db_manual: DB instance not to be compacted (manual compaction)

    // open & create db_less, db_non and db_manual
    status = fdb_open(&dbfile_less, "compact_test_less", &fconfig);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_kvs_open_default(dbfile_less, &db_less, &kvs_config);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    fconfig.compaction_threshold = 0;
    status = fdb_open(&dbfile_non, "compact_test_non", &fconfig);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_kvs_open_default(dbfile_non, &db_non, &kvs_config);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    fconfig.compaction_mode = FDB_COMPACTION_MANUAL;
    status = fdb_open(&dbfile_manual, "compact_test_manual", &fconfig);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_kvs_open_default(dbfile_manual, &db_manual, &kvs_config);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // reopen db file
    fconfig.compaction_threshold = 30;
    fconfig.compaction_mode = FDB_COMPACTION_AUTO;
    status = fdb_open(&dbfile, "compact_test", &fconfig);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_kvs_open_default(dbfile, &db, &kvs_config);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_set_log_callback(db, logCallbackFunc,
                                  (void *) "compaction_daemon_test");
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    // continuously update documents
    printf("wait for %d seconds..\n", (int)time_sec);
    gettimeofday(&ts_begin, NULL);
    while (!escape) {
        for (i=0;i<n;++i){
            // update db
            fdb_set(db, doc[i]);
            fdb_commit(dbfile, FDB_COMMIT_NORMAL);

            // update db_less (1/100 throughput)
            if (i%100 == 0){
                fdb_set(db_less, doc[i]);
                fdb_commit(dbfile_less, FDB_COMMIT_NORMAL);
            }

            // update db_non
            fdb_set(db_non, doc[i]);
            fdb_commit(dbfile_non, FDB_COMMIT_NORMAL);

            // update db_manual
            fdb_set(db_manual, doc[i]);
            fdb_commit(dbfile_manual, FDB_COMMIT_NORMAL);

            gettimeofday(&ts_cur, NULL);
            ts_gap = _utime_gap(ts_begin, ts_cur);
            if ((size_t)ts_gap.tv_sec >= time_sec) {
                escape = 1;
                break;
            }
        }
    }

    // Change the compaction interval to 60 secs.
    status = fdb_set_daemon_compaction_interval(dbfile, 60);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    // Change the compaction interval back to 1 sec.
    status = fdb_set_daemon_compaction_interval(dbfile, 1);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // perform manual compaction of auto-compact file
    status = fdb_compact(dbfile_non, NULL);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // perform manual compaction of manual-compact file
    status = fdb_compact(dbfile_manual, "compact_test_manual_compacted");
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // open compact_test_manual_compacted using new db handle
    fconfig.compaction_mode = FDB_COMPACTION_MANUAL;
    status = fdb_open(&dbfile_new, "compact_test_manual_compacted", &fconfig);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // try to switch compaction mode
    status = fdb_switch_compaction_mode(dbfile_manual, FDB_COMPACTION_AUTO, 30);
    TEST_CHK(status == FDB_RESULT_FILE_IS_BUSY);

    // close db_new
    status = fdb_close(dbfile_new);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // switch compaction mode of 'db_manual' from MANUAL to AUTO
    status = fdb_switch_compaction_mode(dbfile_manual, FDB_COMPACTION_AUTO, 10);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // change compaction value
    status = fdb_switch_compaction_mode(dbfile_manual, FDB_COMPACTION_AUTO, 30);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // close and open with auto-compact option
    status = fdb_close(dbfile_manual);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    fconfig.compaction_mode = FDB_COMPACTION_AUTO;
    status = fdb_open(&dbfile_manual, "compact_test_manual_compacted", &fconfig);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // switch compaction mode of 'db_non' from AUTO to MANUAL
    status = fdb_switch_compaction_mode(dbfile_non, FDB_COMPACTION_MANUAL, 0);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // close and open with manual-compact option
    status = fdb_close(dbfile_non);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    fconfig.compaction_mode = FDB_COMPACTION_MANUAL;
    status = fdb_open(&dbfile_non, "compact_test_non", &fconfig);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // Now perform one manual compaction on compact_test_non
    fdb_compact(dbfile_non, "compact_test_non.manual");

    // close all db files except compact_test_non
    fdb_close(dbfile);
    fdb_close(dbfile_less);
    fdb_close(dbfile_manual);

    // open manual compact file (compact_test_non) using auto compact mode
    fconfig.compaction_mode = FDB_COMPACTION_AUTO;
    status = fdb_open(&dbfile, "compact_test_non.manual", &fconfig);
    TEST_CHK(status == FDB_RESULT_INVALID_COMPACTION_MODE);

    // Attempt to destroy manual compact file using auto compact mode
    status = fdb_destroy("compact_test_non.manual", &fconfig);
    TEST_CHK(status == FDB_RESULT_INVALID_COMPACTION_MODE);

    // open auto copmact file (compact_test_manual_compacted) using manual compact mode
    fconfig.compaction_mode = FDB_COMPACTION_MANUAL;
    status = fdb_open(&dbfile, "compact_test_manual_compacted", &fconfig);
    TEST_CHK(status == FDB_RESULT_INVALID_COMPACTION_MODE);

    // Attempt to destroy auto copmact file using manual compact mode
    status = fdb_destroy("compact_test_manual_compacted", &fconfig);
    TEST_CHK(status == FDB_RESULT_INVALID_COMPACTION_MODE);

    // DESTROY auto copmact file with correct mode
    fconfig.compaction_mode = FDB_COMPACTION_AUTO;
    status = fdb_destroy("compact_test_manual_compacted", &fconfig);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // DESTROY manual compacted file with past version open!
    fconfig.compaction_mode = FDB_COMPACTION_MANUAL;
    status = fdb_destroy("compact_test_non.manual", &fconfig);
    TEST_CHK(status == FDB_RESULT_FILE_IS_BUSY);
    fdb_close(dbfile_non);

    // Simulate a database crash by doing a premature shutdown
    // Note that db_non was never closed properly
    status = fdb_shutdown();
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    status = fdb_destroy("compact_test_non.manual", &fconfig);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // Attempt to read-only auto compacted and destroyed file
    fconfig.flags = FDB_OPEN_FLAG_RDONLY;
    status = fdb_open(&dbfile, "./compact_test_manual_compacted", &fconfig);
    TEST_CHK(status == FDB_RESULT_NO_SUCH_FILE);

    status = fdb_open(&dbfile, "./compact_test_manual_compacted.meta", &fconfig);
    TEST_CHK(status == FDB_RESULT_NO_SUCH_FILE);

    // Attempt to read-only past version of manually compacted destroyed file
    status = fdb_open(&dbfile, "compact_test_non", &fconfig);
    TEST_CHK(status == FDB_RESULT_NO_SUCH_FILE);

    // Attempt to read-only current version of manually compacted destroyed file
    status = fdb_open(&dbfile, "compact_test_non.manual", &fconfig);
    TEST_CHK(status == FDB_RESULT_NO_SUCH_FILE);

    // free all documents
    for (i=0;i<n;++i){
        fdb_doc_free(doc[i]);
    }

    // free all resources
    fdb_shutdown();

    memleak_end();

    TEST_RESULT("compaction daemon test");
}

// MB-13117
void auto_compaction_with_concurrent_insert_test(size_t t_limit)
{
    TEST_INIT();

    memleak_start();

    int i, r;
    fdb_file_handle *file;
    fdb_kvs_handle *kvs;
    fdb_status status;
    fdb_config config;
    fdb_kvs_config kvs_config;
    struct timeval ts_begin, ts_cur, ts_gap;

    r = system(SHELL_DEL" compact_test* > errorlog.txt");
    (void)r;

    // Open Database File
    config = fdb_get_default_config();
    config.compaction_mode=FDB_COMPACTION_AUTO;
    config.compactor_sleep_duration = 1;
    status = fdb_open(&file, "compact_test", &config);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // Open KV Store
    kvs_config = fdb_get_default_kvs_config();
    status = fdb_kvs_open_default(file, &kvs, &kvs_config);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    gettimeofday(&ts_begin, NULL);
    printf("wait for %d seconds..\n", (int)t_limit);

    // Several kv pairs
    for(i=0;i<100000;i++) {
        char str[15];
        sprintf(str, "%d", i);
        status = fdb_set_kv(kvs, str, strlen(str), (void*)"value", 5);
        TEST_CHK(status == FDB_RESULT_SUCCESS);

        // Commit
        status = fdb_commit(file, FDB_COMMIT_NORMAL);
        TEST_CHK(status == FDB_RESULT_SUCCESS);

        gettimeofday(&ts_cur, NULL);
        ts_gap = _utime_gap(ts_begin, ts_cur);
        if ((size_t)ts_gap.tv_sec >= t_limit) {
            break;
        }
    }

    status = fdb_close(file);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_shutdown();
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    memleak_end();

    TEST_RESULT("auto compaction with concurrent insert test");
}

// lexicographically compares two variable-length binary streams
#define MIN(a,b) (((a)<(b))?(a):(b))
static int _compact_test_keycmp(void *key1, size_t keylen1,
                                void *key2, size_t keylen2)
{
    if (keylen1 == keylen2) {
        return memcmp(key1, key2, keylen1);
    }else {
        size_t len = MIN(keylen1, keylen2);
        int cmp = memcmp(key1, key2, len);
        if (cmp != 0) return cmp;
        else {
            return (int)((int)keylen1 - (int)keylen2);
        }
    }
}

void auto_compaction_with_custom_cmp_function()
{
    TEST_INIT();

    memleak_start();

    int i, r, n=10000;
    char keybuf[256], bodybuf[256];
    uint64_t max_filesize = 0;
    fdb_file_handle *file;
    fdb_kvs_handle *db1, *db2, *db3;
    fdb_status status;
    fdb_config config;
    fdb_kvs_config kvs_config;
    fdb_file_info file_info;
    char *kvs_names[] = {NULL};
    fdb_custom_cmp_variable functions[] = {_compact_test_keycmp};

    r = system(SHELL_DEL" compact_test* > errorlog.txt");
    (void)r;

    // Open Database File
    config = fdb_get_default_config();
    config.wal_threshold = 4096; // reset WAL threshold for correct file size estimation
    config.compaction_mode=FDB_COMPACTION_AUTO;
    config.compactor_sleep_duration = 1;
    config.compaction_threshold = 10;
    status = fdb_open_custom_cmp(&file, "compact_test", &config,
                                 1, kvs_names, functions);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // Open 2 KV Stores
    kvs_config = fdb_get_default_kvs_config();
    status = fdb_kvs_open_default(file, &db1, &kvs_config);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_kvs_open(file, &db2, "db", &kvs_config);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // initial load
    for(i=0;i<n;i++) {
        sprintf(keybuf, "key%06d", i);
        sprintf(bodybuf, "body%06d", i);
        status = fdb_set_kv(db1, keybuf, strlen(keybuf),
                                 bodybuf, strlen(bodybuf));
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        status = fdb_set_kv(db2, keybuf, strlen(keybuf),
                                 bodybuf, strlen(bodybuf));
        TEST_CHK(status == FDB_RESULT_SUCCESS);
    }

    // create one more KVS using custom cmp
    // it doesn't exist on the initial cmp_func list
    kvs_config.custom_cmp = _compact_test_keycmp;
    status = fdb_kvs_open(file, &db3, "db_custom", &kvs_config);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    i = 0;
    sprintf(keybuf, "key%06d", i);
    sprintf(bodybuf, "body%06d", i);
    status = fdb_set_kv(db3, keybuf, strlen(keybuf),
                             bodybuf, strlen(bodybuf));
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // Commit
    status = fdb_commit(file, FDB_COMMIT_NORMAL);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // update to trigger compaction
    for(i=0;i<n;i++) {
        sprintf(keybuf, "key%06d", i);
        sprintf(bodybuf, "body%06d", i);
        status = fdb_set_kv(db1, keybuf, strlen(keybuf),
                                 bodybuf, strlen(bodybuf));
        TEST_CHK(status == FDB_RESULT_SUCCESS);

        status = fdb_get_file_info(file, &file_info);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        if (file_info.file_size > max_filesize) {
            max_filesize = file_info.file_size;
        }
    }
    // Commit
    status = fdb_commit(file, FDB_COMMIT_NORMAL);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    status = fdb_get_file_info(file, &file_info);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    if (file_info.file_size > max_filesize) {
        max_filesize = file_info.file_size;
    }

    printf("wait for daemon compaction completion... (max file size: %" _F64 ")\n", max_filesize);
    while (true) {
        sleep(1);

        status = fdb_get_file_info(file, &file_info);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        if (file_info.file_size < max_filesize) {
            break;
        }
    }
    // should be compacted
    TEST_CHK(file_info.file_size < max_filesize);

    status = fdb_close(file);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_shutdown();
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    memleak_end();

    TEST_RESULT("auto compaction with custom comparison function");
}

struct cb_txn_args {
    fdb_file_handle *file;
    fdb_kvs_handle *handle;
    int ndocs;
    int nupdates;
    int done;
};

static int cb_txn(fdb_file_handle *fhandle,
                  fdb_compaction_status status, const char *kv_name,
                  fdb_doc *doc, uint64_t old_offset, uint64_t new_offset,
                  void *ctx)
{
    struct cb_txn_args *args = (struct cb_txn_args *)ctx;
    (void) fhandle;
    (void) doc;
    (void) old_offset;
    (void) new_offset;

    if (status == FDB_CS_END && !args->done) {
        int i;
        int n = 10;
        char keybuf[256], bodybuf[256];
        fdb_status s;

        // begin transaction
        fdb_begin_transaction(args->file, FDB_ISOLATION_READ_COMMITTED);
        // insert new docs, but do not end transaction
        for (i=0;i<n/2;++i){
            sprintf(keybuf, "txn%04d", i);
            sprintf(bodybuf, "txn_body%04d", i);
            s = fdb_set_kv(args->handle, keybuf, strlen(keybuf)+1,
                                         bodybuf, strlen(bodybuf)+1);
            (void)s;
        }
        args->done = 1;
    }

    return 0;
}

void compaction_with_concurrent_transaction_test()
{
    TEST_INIT();
    memleak_start();

    int i, r;
    int n = 10;
    size_t valuelen;
    char keybuf[256], bodybuf[256];
    fdb_file_handle *dbfile, *txn_file;
    fdb_kvs_handle *db, *txn;
    fdb_status s;
    fdb_config fconfig = fdb_get_default_config();
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    void *value;
    struct cb_txn_args cb_args;

    memset(&cb_args, 0x0, sizeof(struct cb_txn_args));
    fconfig.flags = FDB_OPEN_FLAG_CREATE;
    fconfig.compaction_cb = cb_txn;
    fconfig.compaction_cb_ctx = &cb_args;
    fconfig.compaction_cb_mask = FDB_CS_BEGIN |
                                 FDB_CS_END;

    // remove previous compact_test files
    r = system(SHELL_DEL" compact_test* > errorlog.txt");
    (void)r;

    // open db
    fdb_open(&dbfile, "./compact_test1", &fconfig);
    fdb_kvs_open(dbfile, &db, "db", &kvs_config);

    fdb_open(&txn_file, "./compact_test1", &fconfig);
    fdb_kvs_open(txn_file, &txn, "db", &kvs_config);
    cb_args.file = txn_file;
    cb_args.handle = txn;

    // write docs & commit
    for (i=0;i<n;++i){
        sprintf(keybuf, "key%04d", i);
        sprintf(bodybuf, "body%04d", i);
        s = fdb_set_kv(db, keybuf, strlen(keybuf)+1,
                           bodybuf, strlen(bodybuf)+1);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
    }
    s = fdb_commit(dbfile, FDB_COMMIT_NORMAL);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    cb_args.ndocs = n;
    cb_args.nupdates = 2;

    s = fdb_compact(dbfile, "./compact_test2");
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    // insert new docs through transaction
    for (i=n/2;i<n;++i){
        sprintf(keybuf, "txn%04d", i);
        sprintf(bodybuf, "txn_body%04d", i);
        s = fdb_set_kv(txn, keybuf, strlen(keybuf)+1,
                            bodybuf, strlen(bodybuf)+1);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
    }
    // all txn docs should be retrieved
    for (i=0;i<n;++i){
        sprintf(keybuf, "txn%04d", i);
        sprintf(bodybuf, "txn_body%04d", i);
        s = fdb_get_kv(txn, keybuf, strlen(keybuf)+1,
                            &value, &valuelen);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(value, bodybuf, valuelen);
        fdb_free_block(value);
    }
    s = fdb_end_transaction(txn_file, FDB_COMMIT_MANUAL_WAL_FLUSH);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    fdb_close(txn_file);

    s = fdb_compact(dbfile, "./compact_test3");
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    fdb_close(dbfile);
    fdb_shutdown();
    memleak_end();
    TEST_RESULT("compaction with concurrent transaction test");
}

struct cb_upt_args {
    fdb_file_handle *file;
    fdb_kvs_handle *handle;
    fdb_kvs_handle *handle2;
    int ndocs;
    int nupdates;
    int done;
    int nmoves;
};

static fdb_compact_decision cb_upt(fdb_file_handle *fhandle,
                                   fdb_compaction_status status,
                                   const char *kv_name,
                                   fdb_doc *doc, uint64_t old_offset,
                                   uint64_t new_offset,
                                   void *ctx)
{
    TEST_INIT();
    struct cb_upt_args *args = (struct cb_upt_args *)ctx;
    (void) fhandle;
    (void) doc;
    (void) old_offset;
    (void) new_offset;

    if (status == FDB_CS_MOVE_DOC) {
        int i, j;
        int n = 10;
        char keybuf[256], bodybuf[256];
        char keystr[] = "new%04d";
        char valuestr[] = "new_body%04d";
        fdb_status s;
        args->nmoves++;
        if (args->nmoves > n/2 && !args->done) {
            // verify if the key is stripped off its prefix
            fdb_doc tdoc;
            memset(&tdoc, 0, sizeof(fdb_doc));
            tdoc.key = doc->key;
            tdoc.keylen = doc->keylen;
            s = fdb_get(args->handle, &tdoc);
            TEST_CHK(s == FDB_RESULT_SUCCESS);
            free(tdoc.meta);
            free(tdoc.body);
            // insert new docs
            for (i=0;i<n/2;++i){
                sprintf(keybuf, keystr, i);
                sprintf(bodybuf, valuestr, i);
                s = fdb_set_kv(args->handle, keybuf, strlen(keybuf)+1,
                                             bodybuf, strlen(bodybuf)+1);
                TEST_CHK(s == FDB_RESULT_SUCCESS);
                s = fdb_commit(args->file, FDB_COMMIT_NORMAL);
                TEST_CHK(s == FDB_RESULT_SUCCESS);

                for (j=0; j<=i; ++j){
                    void *v_out;
                    size_t vlen_out;
                    sprintf(keybuf, keystr, i);
                    sprintf(bodybuf, valuestr, i);
                    s = fdb_get_kv(args->handle2, keybuf, strlen(keybuf)+1,
                        &v_out, &vlen_out);
                    TEST_CHK(s == FDB_RESULT_SUCCESS);
                    fdb_free_block(v_out);
                }
            }
            args->done = 1;
        } else if (args->nmoves > n && args->done == 1) {
            // the first phase is done. insert new docs.
            i = 0;
            sprintf(keybuf, "xxx%d", i);
            sprintf(bodybuf, "xxxvalue%d", i);
            s = fdb_set_kv(args->handle, keybuf, strlen(keybuf)+1,
                           bodybuf, strlen(bodybuf)+1);
            TEST_CHK(s == FDB_RESULT_SUCCESS);
            s = fdb_commit(args->file, FDB_COMMIT_NORMAL);
            TEST_CHK(s == FDB_RESULT_SUCCESS);
            i = 1;
            sprintf(keybuf, "xxx%d", i);
            sprintf(bodybuf, "xxxvalue%d", i);
            s = fdb_begin_transaction(args->file, FDB_ISOLATION_READ_COMMITTED);
            TEST_CHK(s == FDB_RESULT_SUCCESS);
            s = fdb_set_kv(args->handle, keybuf, strlen(keybuf)+1,
                           bodybuf, strlen(bodybuf)+1);
            TEST_CHK(s == FDB_RESULT_SUCCESS);
            s = fdb_end_transaction(args->file, FDB_COMMIT_NORMAL);
            TEST_CHK(s == FDB_RESULT_SUCCESS);
            args->done = 2;
        } else if (args->nmoves == (n*3/2 + 2) && args->done == 2) {
            // during the second-second phase,
            i = 1;
            sprintf(keybuf, "xxx%d", i);
            sprintf(bodybuf, "xxxvalue%d", i);
            s = fdb_begin_transaction(args->file, FDB_ISOLATION_READ_COMMITTED);
            TEST_CHK(s == FDB_RESULT_SUCCESS);
            s = fdb_set_kv(args->handle, keybuf, strlen(keybuf)+1,
                           bodybuf, strlen(bodybuf)+1);
            TEST_CHK(s == FDB_RESULT_SUCCESS);
            s = fdb_end_transaction(args->file, FDB_COMMIT_NORMAL);
            TEST_CHK(s == FDB_RESULT_SUCCESS);
            // insert new docs, and do not commit.
            for (i=0;i<2;++i){
                sprintf(keybuf, "zzz%d", i);
                sprintf(bodybuf, "zzzvalue%d", i);
                s = fdb_set_kv(args->handle, keybuf, strlen(keybuf)+1,
                                             bodybuf, strlen(bodybuf)+1);
                TEST_CHK(s == FDB_RESULT_SUCCESS);
            }
            args->done = 3;
        } else if (args->done == 3) {
            if (args->nmoves == n*3/2 + 2 // docs inserted after phase 1
                                + 3) { // 3 docs inserted in last phase above
                args->done = 4; // Don't do this for second fdb_compact() call
            }
        }
        TEST_CMP(kv_name, "db", 2);
    }

    return FDB_CS_KEEP_DOC;
}

void compaction_with_concurrent_update_test()
{
    TEST_INIT();
    memleak_start();

    int i, r;
    int n = 10;
    char keybuf[256], bodybuf[256];
    fdb_file_handle *dbfile, *dbfile2, *dbfile3;
    fdb_kvs_handle *db, *db2, *db3;
    fdb_status s;
    fdb_config fconfig = fdb_get_default_config();
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    fdb_kvs_info info;
    fdb_seqnum_t seqnum;
    struct cb_upt_args cb_args;
    void *value;
    size_t valuelen;

    memset(&cb_args, 0x0, sizeof(struct cb_upt_args));
    fconfig.flags = FDB_OPEN_FLAG_CREATE;
    fconfig.compaction_cb = cb_upt;
    fconfig.compaction_cb_ctx = &cb_args;
    fconfig.compaction_cb_mask = FDB_CS_BEGIN |
                                 FDB_CS_END | FDB_CS_MOVE_DOC;

    // remove previous compact_test files
    r = system(SHELL_DEL" compact_test* > errorlog.txt");
    (void)r;

    // open db
    fdb_open(&dbfile, "./compact_test1", &fconfig);
    fdb_kvs_open(dbfile, &db, "db", &kvs_config);

    fdb_open(&dbfile2, "./compact_test1", &fconfig);
    fdb_kvs_open(dbfile2, &db2, "db", &kvs_config);
    fdb_open(&dbfile3, "./compact_test1", &fconfig);
    fdb_kvs_open(dbfile3, &db3, "db", &kvs_config);

    cb_args.file = dbfile2;
    cb_args.handle = db2;
    cb_args.handle2 = db3;

    // write docs & commit
    for (i=0;i<n;++i){
        sprintf(keybuf, "key%04d", i);
        sprintf(bodybuf, "body%04d", i);
        s = fdb_set_kv(db, keybuf, strlen(keybuf)+1,
                           bodybuf, strlen(bodybuf)+1);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
    }
    s = fdb_commit(dbfile, FDB_COMMIT_NORMAL);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    cb_args.ndocs = n;
    cb_args.nupdates = 2;
    cb_args.nmoves = 0;

    s = fdb_compact(dbfile, "./compact_test2");
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    // insert new docs after compaction
    for (i=n/2;i<n;++i){
        sprintf(keybuf, "new%04d", i);
        sprintf(bodybuf, "new_body%04d", i);
        s = fdb_set_kv(db2, keybuf, strlen(keybuf)+1,
                            bodybuf, strlen(bodybuf)+1);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
    }
    // all interleaved docs should be retrieved
    // 1. inserted during the first phase of the compaction
    for (i=0;i<n;++i){
        sprintf(keybuf, "new%04d", i);
        sprintf(bodybuf, "new_body%04d", i);
        s = fdb_get_kv(db2, keybuf, strlen(keybuf)+1,
                            &value, &valuelen);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(value, bodybuf, valuelen);
        fdb_free_block(value);
    }
    // 2. inserted during the second phase of the compaction
    for (i=0; i<2; ++i) {
        sprintf(keybuf, "xxx%d", i);
        sprintf(bodybuf, "xxxvalue%d", i);
        s = fdb_get_kv(db2, keybuf, strlen(keybuf)+1,
                            &value, &valuelen);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(value, bodybuf, valuelen);
        fdb_free_block(value);

        sprintf(keybuf, "zzz%d", i);
        sprintf(bodybuf, "zzzvalue%d", i);
        s = fdb_get_kv(db2, keybuf, strlen(keybuf)+1,
                            &value, &valuelen);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(value, bodybuf, valuelen);
        fdb_free_block(value);
    }

    fdb_close(dbfile2);
    fdb_close(dbfile3);

    s = fdb_get_kvs_info(db, &info);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    seqnum = info.last_seqnum;

    cb_args.nmoves = 0;
    s = fdb_compact(dbfile, "./compact_test3");
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    s = fdb_get_kvs_info(db, &info);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    // No docs are inserted during the compaction.
    // Seqnum should be same.
    TEST_CHK(info.last_seqnum == seqnum);

    // insert the last document
    sprintf(keybuf, "last");
    sprintf(bodybuf, "last_value");
    s = fdb_set_kv(db, keybuf, strlen(keybuf)+1, bodybuf, strlen(bodybuf)+1);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_commit(dbfile, FDB_COMMIT_NORMAL);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    fdb_close(dbfile);
    fdb_shutdown();
    memleak_end();
    TEST_RESULT("compaction with concurrent update test");
}

static int compaction_del_cb(fdb_file_handle *fhandle,
                             fdb_compaction_status status,
                             const char *kv_name,
                             fdb_doc *doc, uint64_t old_offset,
                             uint64_t new_offset,
                             void *ctx)
{
    TEST_INIT();
    fdb_status s;
    fdb_file_handle *dbfile;
    fdb_kvs_handle *db = *(fdb_kvs_handle **)ctx;
    int i;
    int n = 10; // if changing this change caller function too
    char keybuf[256];
    (void) doc;
    (void) new_offset;
    (void) old_offset;

    if (status == FDB_CS_BEGIN) {
        TEST_CHK(false);
    } else if (status == FDB_CS_END) {
        TEST_CHK(!kv_name);
        if (db) { // At end of first phase, mutate more docs...
            s = fdb_open(&dbfile, "./compact_test1", &fhandle->getRootHandle()->config);
            TEST_CHK(s == FDB_RESULT_SUCCESS);
            fdb_kvs_open_default(dbfile, &db, &db->kvs_config);
            for (i = 0; i < n; ++i){
                sprintf(keybuf, "key%d", i);
                s = fdb_del_kv(db, keybuf, strlen(keybuf));
                TEST_CHK(s == FDB_RESULT_SUCCESS);
            }
            // Now insert and delete a bunch of keys (all in WAL)
            for (i = 0; i < n; ++i){
                sprintf(keybuf, "KEY%d", i);
                s = fdb_set_kv(db, keybuf, strlen(keybuf), NULL, 0);
                TEST_CHK(s == FDB_RESULT_SUCCESS);
                s = fdb_del_kv(db, keybuf, strlen(keybuf));
                TEST_CHK(s == FDB_RESULT_SUCCESS);
            }
            sprintf(keybuf, "key%d", i);
            s = fdb_set_kv(db, keybuf, strlen(keybuf), NULL, 0);
            TEST_CHK(s == FDB_RESULT_SUCCESS);
            s = fdb_commit(dbfile, FDB_COMMIT_NORMAL);
            TEST_CHK(s == FDB_RESULT_SUCCESS);
            fdb_close(dbfile);
            *(fdb_kvs_handle **)ctx = NULL; // Don't run in 2nd, 3rd phases
        }
    } else if (status == FDB_CS_FLUSH_WAL) {
        TEST_CHK(false);
    } else if (status == FDB_CS_MOVE_DOC) {
        TEST_CHK(false);
    } else { // FDB_CS_BATCH_MOVE
        TEST_CHK(false);
    }
    return 0;
}

void compact_deleted_doc_test()
{
    TEST_INIT();
    memleak_start();
    int i, r;
    int n = 10; // if changing this change the callback too
    fdb_file_handle *dbfile;
    fdb_kvs_handle *db, *cb_db;
    fdb_doc *rdoc;
    fdb_status s;
    char keybuf[256];
    void *value;
    size_t valuelen;

    // remove previous compact_test files
    r = system(SHELL_DEL " compact_test* > errorlog.txt");
    (void)r;

    fdb_config fconfig = fdb_get_default_config();
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    fconfig.multi_kv_instances = false;
    fconfig.flags = FDB_OPEN_FLAG_CREATE;

    fconfig.compaction_cb = compaction_del_cb;
    fconfig.compaction_cb_ctx = &cb_db;
    fconfig.compaction_cb_mask = FDB_CS_END;

    // open db
    fdb_open(&dbfile, "./compact_test1", &fconfig);
    fdb_kvs_open_default(dbfile, &db, &kvs_config);
    cb_db = db;

    for (i=0;i<n;++i){
        sprintf(keybuf, "key%d", i);
        s = fdb_set_kv(db, keybuf, strlen(keybuf),
                            (void*)"value", 5);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
    }
    fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);

    // At end of phase 1, all documents get deleted
    s = fdb_compact(dbfile, "compact_test2");
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    TEST_CHK(dbfile->getRootHandle()->file->getWal()->getNumFlushable_Wal() == 0);

    for (i=0;i<n;++i){
        sprintf(keybuf, "key%d", i);
        fdb_doc_create(&rdoc, keybuf, strlen(keybuf), NULL, 0, NULL, 0);
        s = fdb_get_metaonly(db, rdoc);
        TEST_CHK(s == FDB_RESULT_KEY_NOT_FOUND);
        fdb_doc_free(rdoc);
    }

    // documents inserted in the middle of phase 1 should be present
    sprintf(keybuf, "key%d", i);
    s = fdb_get_kv(db, keybuf, strlen(keybuf), &value, &valuelen);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    fdb_free_block(value);

    fdb_kvs_close(db);
    fdb_close(dbfile);
    fdb_shutdown();
    memleak_end();
    TEST_RESULT("compact deleted doc test");
}

void compact_upto_twice_test()
{
    TEST_INIT();
    memleak_start();
    int i, r;
    fdb_file_handle *dbfile;
    fdb_kvs_handle *db;
    fdb_snapshot_info_t *markers;
    fdb_status status;
    uint64_t num_markers;
    char keybuf[256];

    // remove previous compact_test files
    r = system(SHELL_DEL " compact_test* > errorlog.txt");
    (void)r;

    fdb_config fconfig = fdb_get_default_config();
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    fconfig.wal_threshold = 1024;
    fconfig.flags = FDB_OPEN_FLAG_CREATE;
    fconfig.block_reusing_threshold = 0;

    // open db
    fdb_open(&dbfile, "./compact_test1", &fconfig);
    fdb_kvs_open_default(dbfile, &db, &kvs_config);

    for (i=0;i<10;++i){
        sprintf(keybuf, "key%d", i);
        status = fdb_set_kv(db, keybuf, strlen(keybuf),
                            (void*)"value", 5);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);
    }

    // compact upto twice with incrementing seqnums
    status = fdb_get_all_snap_markers(dbfile, &markers,
                                      &num_markers);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_compact_upto(dbfile, NULL, markers[num_markers-1].marker);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_free_snap_markers(markers, num_markers);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // compact upto
    status = fdb_get_all_snap_markers(dbfile, &markers,
                                      &num_markers);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_compact_upto(dbfile, NULL, markers[num_markers-2].marker);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_free_snap_markers(markers, num_markers);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    fdb_close(dbfile);
    fdb_shutdown();
    memleak_end();
    TEST_RESULT("compact upto twice");
}

void wal_delete_compact_upto_test()
{
    TEST_INIT();
    memleak_start();
    int i, r;
    fdb_file_handle *dbfile;
    fdb_kvs_handle *db;
    fdb_snapshot_info_t *markers;
    fdb_status status;
    uint64_t num_markers;
    fdb_kvs_info kvs_info;
    char keybuf[256];
    void *value;
    size_t valuelen;

    // remove previous compact_test files
    r = system(SHELL_DEL " compact_test* > errorlog.txt");
    (void)r;

    fdb_config fconfig = fdb_get_default_config();
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    fconfig.wal_threshold = 19;
    fconfig.flags = FDB_OPEN_FLAG_CREATE;

    // open db
    fdb_open(&dbfile, "./compact_test5", &fconfig);
    fdb_kvs_open_default(dbfile, &db, &kvs_config);

    // insert a few keys...
    for (i=0;i<10;++i){
        sprintf(keybuf, "key%d", i);
        status = fdb_set_kv(db, keybuf, strlen(keybuf),
                            (void*)"value", 5);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
    }

    status = fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // insert keys such that last insert causes wal flush...
    for (; i<20;++i){
        sprintf(keybuf, "key%d", i);
        status = fdb_set_kv(db, keybuf, strlen(keybuf),
                            (void*)"value", 5);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
    }
    // Now delete half of the newly inserted keys
    for (i = 15; i < 20; ++i){
        sprintf(keybuf, "key%d", i);
        status = fdb_del_kv(db, keybuf, strlen(keybuf));
        TEST_CHK(status == FDB_RESULT_SUCCESS);
    }
    // Now deleted items are in the unflushed wal..
    status = fdb_commit(dbfile, FDB_COMMIT_NORMAL);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // Create another header for compact_upto()
    sprintf(keybuf, "key%d", i);
    status = fdb_set_kv(db, keybuf, strlen(keybuf),
            (void*)"value", 5);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_commit(dbfile, FDB_COMMIT_NORMAL);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // Get all snap markers..
    status = fdb_get_all_snap_markers(dbfile, &markers,
                                      &num_markers);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // compact upto the delete wal's marker...
    status = fdb_compact_upto(dbfile, NULL, markers[1].marker);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_free_snap_markers(markers, num_markers);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    status = fdb_get_kvs_info(db, &kvs_info);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // Deleted items should not be found..
    for (i = 15; i < 20; ++i){
        sprintf(keybuf, "key%d", i);
        status = fdb_get_kv(db, keybuf, strlen(keybuf), &value, &valuelen);
        TEST_CHK(status == FDB_RESULT_KEY_NOT_FOUND);
    }

    fdb_kvs_close(db);
    fdb_close(dbfile);
    fdb_shutdown();
    memleak_end();
    TEST_RESULT("compact upto with wal deletes test");
}

void compact_upto_post_snapshot_test()
{
    TEST_INIT();
    memleak_start();
    int i, r;
    fdb_file_handle *dbfile;
    fdb_kvs_handle *db, *snap_db;
    fdb_snapshot_info_t *markers;
    fdb_status status;
    fdb_iterator *iterator;
    fdb_doc *rdoc = NULL;
    fdb_kvs_info kvs_info;
    uint64_t num_markers;
    char keybuf[256];

    // remove previous compact_test files
    r = system(SHELL_DEL " compact_test* > errorlog.txt");
    (void)r;

    fdb_config fconfig = fdb_get_default_config();
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    fconfig.wal_threshold = 1024;
    fconfig.flags = FDB_OPEN_FLAG_CREATE;
    // prevent block reusing to keep snapshots
    fconfig.block_reusing_threshold = 0;

    // open db
    fdb_open(&dbfile, "./compact_test1", &fconfig);
    fdb_kvs_open_default(dbfile, &db, &kvs_config);

    for (i=0;i<10;++i){
        sprintf(keybuf, "key%d", i);
        status = fdb_set_kv(db, keybuf, strlen(keybuf),
                            (void*)"value", 5);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);
    }

    // check  db info
    status = fdb_get_kvs_info(db, &kvs_info);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    TEST_CHK(kvs_info.last_seqnum == 10);

    // open snapshot at seqnum 5
    status = fdb_snapshot_open(db, &snap_db, 5);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // check snap info
    status = fdb_get_kvs_info(snap_db, &kvs_info);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    TEST_CHK(kvs_info.last_seqnum == 5);


    // compact upto
    status = fdb_get_all_snap_markers(dbfile, &markers,
                                      &num_markers);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_compact_upto(dbfile, NULL, markers[5].marker);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_free_snap_markers(markers, num_markers);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // check db and snap info
    status = fdb_get_kvs_info(db, &kvs_info);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    TEST_CHK(kvs_info.last_seqnum == 10);
    status = fdb_get_kvs_info(snap_db, &kvs_info);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    TEST_CHK(kvs_info.last_seqnum == 5);


    // iterate over snapshot
    status = fdb_iterator_init(snap_db,
                               &iterator, NULL, 0, NULL, 0, FDB_ITR_NONE);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    i = 0;
    do {
        status = fdb_iterator_get(iterator, &rdoc);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        fdb_doc_free(rdoc);
        rdoc = NULL;
        i++;

        // check db and snap info
        status = fdb_get_kvs_info(db, &kvs_info);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        TEST_CHK(kvs_info.last_seqnum == 10);
        status = fdb_get_kvs_info(snap_db, &kvs_info);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        TEST_CHK(kvs_info.last_seqnum == 5);
    } while (fdb_iterator_next(iterator) != FDB_RESULT_ITERATOR_FAIL);

    TEST_CHK(i == 5);

    fdb_iterator_close(iterator);
    fdb_kvs_close(snap_db);
    fdb_close(dbfile);
    fdb_shutdown();
    memleak_end();
    TEST_RESULT("compact upto post snapshot test");
}

void compact_upto_overwrite_test(int opt)
{
    TEST_INIT();

    int n = 10, value_len=32;
    int i, r, idx, c;
    char cmd[256];
    char key[256], *value;
    char keystr[] = "key%06d";
    char valuestr[] = "value%08d";
    char valuestr2[] = "updated_value%08d";
    fdb_file_handle *db_file;
    fdb_kvs_handle *db, *snap;
    fdb_config config;
    fdb_kvs_config kvs_config;
    fdb_status s;
    fdb_kvs_info kvs_info;
    fdb_iterator *fit;
    fdb_doc *doc;
    fdb_snapshot_info_t *markers;
    fdb_seqnum_t seqnum;
    fdb_commit_opt_t commit_opt;
    uint64_t n_markers;

    sprintf(cmd, SHELL_DEL " compact_test* > errorlog.txt");
    r = system(cmd);
    (void)r;

    memleak_start();

    value = (char*)malloc(value_len);

    config = fdb_get_default_config();
    config.durability_opt = FDB_DRB_ASYNC;
    config.seqtree_opt = FDB_SEQTREE_USE;
    config.wal_flush_before_commit = true;
    config.multi_kv_instances = true;
    config.buffercache_size = 0;
    config.block_reusing_threshold = 0;

    commit_opt = (opt)?FDB_COMMIT_NORMAL:FDB_COMMIT_MANUAL_WAL_FLUSH;

    kvs_config = fdb_get_default_kvs_config();

    s = fdb_open(&db_file, "./compact_test", &config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_kvs_open(db_file, &db, "db", &kvs_config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    // === write ===
    for (i=0;i<n;++i){
        idx = i % (n/2);
        sprintf(key, keystr, idx);
        memset(value, 'x', value_len);
        memcpy(value + value_len - 6, "<end>", 6);
        if (i < (n/2)) {
            sprintf(value, valuestr, idx);
        } else {
            sprintf(value, valuestr2, idx);
        }
        s = fdb_set_kv(db, key, strlen(key)+1, value, value_len);
        TEST_CHK(s == FDB_RESULT_SUCCESS);

        if (opt == 2) {
            // HB+trie, WAL, HB+trie, WAL...
            commit_opt = (i%2)?FDB_COMMIT_NORMAL:FDB_COMMIT_MANUAL_WAL_FLUSH;
        } else if (opt == 3) {
            // WAL, HB+trie, WAL, HB+trie...
            commit_opt = (i%2)?FDB_COMMIT_MANUAL_WAL_FLUSH:FDB_COMMIT_NORMAL;
        }

        s = fdb_commit(db_file, commit_opt);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        s = fdb_get_kvs_info(db, &kvs_info);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
    }

    s = fdb_get_all_snap_markers(db_file, &markers, &n_markers);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    int upto = n_markers/2 - 1;
    s = fdb_compact_upto(db_file, "./compact_test2", markers[upto].marker);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    // iterating using snapshots with various seqnums
    for (i=n_markers-1; i>=0; --i) {
        seqnum = markers[i].kvs_markers->seqnum;

        s = fdb_snapshot_open(db, &snap, seqnum);
        if (i<=upto) {
            TEST_CHK(s == FDB_RESULT_SUCCESS);
        } else {
            // seqnum < (n/2) must fail
            TEST_CHK(s != FDB_RESULT_SUCCESS);
            continue;
        }

        s = fdb_iterator_init(snap, &fit, NULL, 0, NULL, 0, 0);
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
            if ((fdb_seqnum_t)c >= seqnum-(n/2)) {
                sprintf(value, valuestr, idx);
            } else {
                sprintf(value, valuestr2, idx);
            }
            TEST_CMP(doc->key, key, doc->keylen);
            TEST_CMP(doc->body, value, doc->bodylen);
            c++;
            fdb_doc_free(doc);
        } while(fdb_iterator_next(fit) == FDB_RESULT_SUCCESS);
        s = fdb_iterator_close(fit);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CHK(c == (n/2));

        s = fdb_kvs_close(snap);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
    }

    // iterating using the original handle
    s = fdb_iterator_init(db, &fit, NULL, 0, NULL, 0, 0);
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
        sprintf(value, valuestr2, idx);
        TEST_CMP(doc->key, key, doc->keylen);
        TEST_CMP(doc->body, value, doc->bodylen);
        c++;
        fdb_doc_free(doc);
    } while(fdb_iterator_next(fit) == FDB_RESULT_SUCCESS);
    s = fdb_iterator_close(fit);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    TEST_CHK(c == (n/2));

    s = fdb_free_snap_markers(markers, n_markers);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    free(value);
    s = fdb_close(db_file);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_shutdown();
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    memleak_end();

    sprintf(cmd, "compact upto overwrite test");
    if (opt == 0) {
        strcat(cmd, " (HB+trie)");
    } else if (opt == 1) {
        strcat(cmd, " (WAL)");
    } else if (opt == 2) {
        strcat(cmd, " (mixed, HB+trie/WAL)");
    } else if (opt == 3) {
        strcat(cmd, " (mixed, WAL/HB+trie)");
    }
    TEST_RESULT(cmd);
}
static int compaction_cb_get(fdb_file_handle *fhandle,
                         fdb_compaction_status status, const char *kv_name,
                         fdb_doc *doc, uint64_t old_offset,
                         uint64_t new_offset, void *ctx)
{
    TEST_INIT();
    fdb_status s;
    struct cb_args *args = (struct cb_args *)ctx;
    fdb_kvs_handle *snap_db;
    fdb_snapshot_info_t *markers;
    uint64_t num_markers;
    fdb_seqnum_t seqno;

    (void) doc;
    (void) old_offset;
    (void) new_offset;

    if (status == FDB_CS_MOVE_DOC) {
        TEST_CHK(kv_name);
    } else {
        TEST_CHK(!kv_name);
    }

    // use snap markers
    s = fdb_get_all_snap_markers(fhandle, &markers, &num_markers);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    seqno = markers[0].kvs_markers[0].seqnum;
    s = fdb_free_snap_markers(markers, num_markers);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    // snapshot open
    s = fdb_snapshot_open(args->handle, &snap_db, seqno);
    TEST_CHK(s==FDB_RESULT_SUCCESS);
    s = fdb_kvs_close(snap_db);
    TEST_CHK(s==FDB_RESULT_SUCCESS);
    return 0;
}

void compact_with_snapshot_open_test()
{
  TEST_INIT();
  memleak_start();

  int i, r;
  int n = 100000;
  char keybuf[256], bodybuf[256];
  fdb_file_handle *dbfile;
  fdb_kvs_handle *db, *db2, *snap_db;
  fdb_status s;
  fdb_config fconfig = fdb_get_default_config();
  fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
  struct cb_args cb_args;

  memset(&cb_args, 0x0, sizeof(struct cb_args));
  fconfig.wal_threshold = 1024;
  fconfig.flags = FDB_OPEN_FLAG_CREATE;
  fconfig.compaction_cb = compaction_cb_get;
  fconfig.compaction_cb_ctx = &cb_args;
  fconfig.compaction_cb_mask = FDB_CS_BEGIN |
                               FDB_CS_MOVE_DOC |
                               FDB_CS_FLUSH_WAL |
                               FDB_CS_END;
  // remove previous compact_test files
  r = system(SHELL_DEL" compact_test* > errorlog.txt");
  (void)r;

  // open two handles for kvs
  fdb_open(&dbfile, "./compact_test1", &fconfig);
  fdb_kvs_open(dbfile, &db, "db", &kvs_config);
  fdb_kvs_open(dbfile, &db2, "db", &kvs_config);
  for (i=0;i<n;++i){
      sprintf(keybuf, "key%04d", i);
      sprintf(bodybuf, "body%04d", i);
      s = fdb_set_kv(db, keybuf, strlen(keybuf), bodybuf, strlen(bodybuf));
      TEST_CHK(s == FDB_RESULT_SUCCESS);
  }


  // commit
  s = fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);
  TEST_CHK(s == FDB_RESULT_SUCCESS);

  // point compact callback handle to db2
  cb_args.handle = db2;

  // compact
  s = fdb_compact(dbfile, NULL);
  TEST_CHK(s == FDB_RESULT_SUCCESS);

  // open compaction end
  s = fdb_snapshot_open(db2, &snap_db, n);
  TEST_CHK(s == FDB_RESULT_SUCCESS);

  fdb_kvs_close(snap_db);
  s = fdb_close(dbfile);
  TEST_CHK(s == FDB_RESULT_SUCCESS);
  s = fdb_shutdown();
  TEST_CHK(s == FDB_RESULT_SUCCESS);
  TEST_RESULT("compact with snapshot_open test");
}

static int compaction_cb_markers(fdb_file_handle *fhandle,
                         fdb_compaction_status status, const char *kv_name,
                         fdb_doc *doc, uint64_t old_offset,
                         uint64_t new_offset, void *ctx)
{
    TEST_INIT();
    uint64_t i, j;
    fdb_status s;
    fdb_kvs_handle *db, *snap_db;
    fdb_snapshot_info_t *markers;
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    fdb_seqnum_t seqno;
    uint64_t num_markers;
    struct cb_args *args = (struct cb_args *)ctx;
    uint64_t n = (uint64_t) args->n_moved_docs;

    (void) status;
    (void) doc;
    (void) old_offset;
    (void) new_offset;

    // get snap markers
    s = fdb_get_all_snap_markers(fhandle, &markers, &num_markers);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    TEST_CHK(markers[0].num_kvs_markers == 5);
    seqno = markers[0].kvs_markers[0].seqnum;
    TEST_CHK(seqno == n);

    // snapshot open for each kvs for each marker
    for (j = 0; j < num_markers; ++j){
        for (i = 0; i < (uint64_t)markers[j].num_kvs_markers; ++i){
            // open kv for this marker
            fdb_kvs_open(fhandle, &db,
                         markers[j].kvs_markers[i].kv_store_name, &kvs_config);
            // snapshot the kv
            s = fdb_snapshot_open(db, &snap_db, seqno);
            TEST_CHK(s==FDB_RESULT_SUCCESS);

            s = fdb_kvs_close(snap_db);
            TEST_CHK(s==FDB_RESULT_SUCCESS);
            s = fdb_kvs_close(db);
            TEST_CHK(s==FDB_RESULT_SUCCESS);
        }
    }
    s = fdb_free_snap_markers(markers, num_markers);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    return 0;
}

void compact_with_snapshot_open_multi_kvs_test()
{
    TEST_INIT();
    memleak_start();

    int i, j, r;
    int n = 1000;
    char keybuf[256], bodybuf[256];
    fdb_file_handle *dbfile;
    fdb_kvs_handle *db1, *db2, *db3, *db4, *db5;
    fdb_status s;
    fdb_config fconfig = fdb_get_default_config();
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    struct cb_args cb_args;

    memset(&cb_args, 0x0, sizeof(struct cb_args));

    fconfig.wal_threshold = 1024;
    fconfig.flags = FDB_OPEN_FLAG_CREATE;
    fconfig.compaction_cb = compaction_cb_markers;
    fconfig.compaction_cb_ctx = &cb_args;
    fconfig.compaction_cb_mask = FDB_CS_BEGIN |
                                 FDB_CS_MOVE_DOC |
                                 FDB_CS_FLUSH_WAL |
                                 FDB_CS_END;

    // remove previous compact_test files
    r = system(SHELL_DEL" compact_test* > errorlog.txt");
    (void)r;

    // open two handles for kvs
    fdb_open(&dbfile, "./compact_test1", &fconfig);
    fdb_kvs_open(dbfile, &db1, "db1", &kvs_config);
    fdb_kvs_open(dbfile, &db2, "db2", &kvs_config);
    fdb_kvs_open(dbfile, &db3, "db3", &kvs_config);
    fdb_kvs_open(dbfile, &db4, "db4", &kvs_config);
    fdb_kvs_open(dbfile, &db5, "db5", &kvs_config);
    for (j=0;j<5;++j){
        for (i=0;i<n;++i){
            sprintf(keybuf, "key%04d", i);
            sprintf(bodybuf, "body%04d", i);
            fdb_set_kv(db1, keybuf, strlen(keybuf), bodybuf, strlen(bodybuf));
            fdb_set_kv(db2, keybuf, strlen(keybuf), bodybuf, strlen(bodybuf));
            fdb_set_kv(db3, keybuf, strlen(keybuf), bodybuf, strlen(bodybuf));
            fdb_set_kv(db4, keybuf, strlen(keybuf), bodybuf, strlen(bodybuf));
            fdb_set_kv(db5, keybuf, strlen(keybuf), bodybuf, strlen(bodybuf));
        }

        // commit
        s = fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);
        TEST_CHK(s == FDB_RESULT_SUCCESS);

        // compact
        cb_args.n_moved_docs = n*(j+1);
        s = fdb_compact(dbfile, NULL);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
    }

    s = fdb_close(dbfile);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_shutdown();
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    TEST_RESULT("compact with snapshot_open multi kvs test");
}


static std::atomic<uint8_t> cancel_test_signal_begin(0);
static std::atomic<uint8_t> cancel_test_signal_end(0);

static int cb_cancel_test(fdb_file_handle *fhandle,
                          fdb_compaction_status status, const char *kv_name,
                          fdb_doc *doc, uint64_t old_offset, uint64_t new_offset,
                          void *ctx)
{
    (void) fhandle;
    (void) kv_name;
    (void) doc;
    (void) old_offset;
    (void) new_offset;
    (void) ctx;

    if (status == FDB_CS_BEGIN) {
        cancel_test_signal_begin = 1;
    } else if (status == FDB_CS_END) {
        cancel_test_signal_end = 1;
    }

    return 0;
}

void *db_compact_during_compaction_cancellation(void *args)
{

    TEST_INIT();

    fdb_file_handle *dbfile;
    fdb_status status;
    fdb_config config;

    // Open Database File
    config = fdb_get_default_config();
    config.compaction_cb = cb_cancel_test;
    config.compaction_cb_ctx = NULL;
    config.compaction_cb_mask = FDB_CS_BEGIN | FDB_CS_END;

    status = fdb_open(&dbfile, "compact_test", &config);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    // compaction thread enters here
    status = fdb_compact(dbfile, NULL);
    TEST_CHK(status == FDB_RESULT_SUCCESS ||
             status == FDB_RESULT_COMPACTION_CANCELLATION ||
             status == FDB_RESULT_FAIL_BY_ROLLBACK);
    fdb_close(dbfile);

    // shutdown
    thread_exit(0);
    return NULL;
}

typedef enum {
    COMPACTION_CANCEL_MODE = 0,
    COMPACTION_ROLLBACK_MODE = 1
} compaction_test_mode;

void compaction_cancellation_test(compaction_test_mode mode)
{
    TEST_INIT();

    memleak_start();

    int i, r, n=100000;
    fdb_file_handle *file;
    fdb_kvs_handle *kvs;
    fdb_status status;
    fdb_config config;
    fdb_kvs_config kvs_config;

    r = system(SHELL_DEL" compact_test* > errorlog.txt");
    (void)r;

    // Open Database File
    config = fdb_get_default_config();
    status = fdb_open(&file, "compact_test", &config);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // Open KV Store
    kvs_config = fdb_get_default_kvs_config();
    status = fdb_kvs_open_default(file, &kvs, &kvs_config);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // Load kv pairs
    for(i=0;i<n;i++) {
        char str[15];
        sprintf(str, "%d", i);
        status = fdb_set_kv(kvs, str, strlen(str), (void*)"value", 5);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        // Commit every 100 SETs
        if (i % 100 == 0) {
            status = fdb_commit(file, FDB_COMMIT_NORMAL);
            TEST_CHK(status == FDB_RESULT_SUCCESS);
        }
    }

    thread_t tid;
    void *thread_ret;
    bool rollback_failed = false;

    thread_create(&tid, db_compact_during_compaction_cancellation, NULL);

    // wait until compaction begins
    while (!cancel_test_signal_begin) {
        usleep(1000); // Sleep for 1ms
    }

    if (mode == COMPACTION_ROLLBACK_MODE) {
        // append more mutations
        for(i=0;i<n/10;i++) {
            char str[15];
            sprintf(str, "%d", i);
            status = fdb_set_kv(kvs, str, strlen(str), (void*)"value", 5);
            TEST_CHK(status == FDB_RESULT_SUCCESS);
            // Commit every 100 SETs
            if (i % 100 == 0) {
                status = fdb_commit(file, FDB_COMMIT_NORMAL);
                TEST_CHK(status == FDB_RESULT_SUCCESS);
            }
        }
    }

    if (mode == COMPACTION_CANCEL_MODE) {
        // Cancel the compaction task
        status = fdb_cancel_compaction(file);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
    } else if (mode == COMPACTION_ROLLBACK_MODE) {
        // Rollback

        // wait until the 1st phase is done
        while (!cancel_test_signal_end) {
            usleep(1000); // Sleep for 1ms
        }

        status = fdb_rollback(&kvs, n/2 + 1);
        if (status != FDB_RESULT_SUCCESS) {
            // if compactor thread is done before reaching this line,
            // rollback may fail.
            rollback_failed = true;
        }
    }
    // join compactor
    thread_join(tid, &thread_ret);

    // if rollback failed, we don't need to compact the file again.
    if (!rollback_failed) {
        // Compact the database
        status = fdb_compact(file, NULL);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
    }

    char key[15];
    void *value;
    size_t val_size;

    for(i=0;i<n;i++) {
        sprintf(key, "%d", i);
        status = fdb_get_kv(kvs, key, strlen(key), &value, &val_size);
        if (mode == COMPACTION_CANCEL_MODE) {
            // compaction cancel mode: all docs should be retrieved
            TEST_CHK(status == FDB_RESULT_SUCCESS);
            fdb_free_block(value);
        } else if (mode == COMPACTION_ROLLBACK_MODE) {
            // rollback mode: only the first half docs should be retrieved
            if (i<=n/2 || rollback_failed) {
                // if rollback failed, all doc should be retrieved
                TEST_CHK(status == FDB_RESULT_SUCCESS);
                fdb_free_block(value);
            } else {
                TEST_CHK(status != FDB_RESULT_SUCCESS);
            }
        }
    }

    status = fdb_close(file);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_shutdown();
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    memleak_end();

    if (mode == COMPACTION_CANCEL_MODE) {
        TEST_RESULT("compaction cancellation test");
    } else if (mode == COMPACTION_ROLLBACK_MODE) {
        TEST_RESULT("rollback during the 2nd phase of compaction test");
    }
}

void compact_upto_with_circular_reuse_test()
{
    TEST_INIT();
    int batch=100, n_batch=64, n_dbs=3, i, j, r, k, idx;
    int n_repeat = 4;
    fdb_file_handle *dbfile;
    fdb_kvs_handle *db[3];
    fdb_config config;
    fdb_kvs_config kvs_config;
    fdb_doc *doc;
    fdb_status s; (void)s;
    char keybuf[256], valuebuf[512];

    memleak_start();

    // remove previous dummy files
    r = system(SHELL_DEL" compact_test* > errorlog.txt");
    (void)r;

    config = fdb_get_default_config();
    config.buffercache_size = 0;
    config.num_keeping_headers = 10;
    kvs_config = fdb_get_default_kvs_config();

    // create a file
    s = fdb_open(&dbfile, "compact_test", &config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    s = fdb_kvs_open(dbfile, &db[0], NULL, &kvs_config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    s = fdb_kvs_open(dbfile, &db[1], "db1", &kvs_config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    s = fdb_kvs_open(dbfile, &db[2], "db2", &kvs_config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    memset(valuebuf, 'x', 256);
    valuebuf[256] = 0;
    for (k=0; k<n_repeat; ++k) {
        for (r=0; r<n_batch; ++r) {
            for (j=1; j<n_dbs; ++j) {
                for (i=0; i<batch; ++i) {
                    idx = r*batch + i;
                    sprintf(keybuf, "k%06d", idx);
                    sprintf(valuebuf, "v%d_%04d_%d", j, idx, k);
                    s = fdb_doc_create(&doc, keybuf, 8, NULL, 0, valuebuf, 257);
                    TEST_CHK(s == FDB_RESULT_SUCCESS);
                    s = fdb_set(db[j], doc);
                    TEST_CHK(s == FDB_RESULT_SUCCESS);
                    s = fdb_doc_free(doc);
                    TEST_CHK(s == FDB_RESULT_SUCCESS);
                }
            }
            s = fdb_commit(dbfile, FDB_COMMIT_NORMAL);
            TEST_CHK(s == FDB_RESULT_SUCCESS);
        }
    }

    fdb_snapshot_info_t *markers_out;
    uint64_t num_markers;

    s = fdb_get_all_snap_markers(dbfile, &markers_out, &num_markers);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    // num_markers should be equal to or smaller than num_keeping_headers
    TEST_CHK(num_markers <= config.num_keeping_headers);

    s = fdb_compact_upto(dbfile, "compact_test_compact", markers_out[5].marker);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    s = fdb_free_snap_markers(markers_out, num_markers);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    // all docs should be retrieved correclty.
    k = n_repeat - 1;
    for (r=0; r<n_batch; ++r) {
        for (j=1; j<n_dbs; ++j) {
            for (i=0; i<batch; ++i) {
                idx = r*batch + i;
                sprintf(keybuf, "k%06d", idx);
                sprintf(valuebuf, "v%d_%04d_%d", j, idx, k);
                s = fdb_doc_create(&doc, keybuf, 8, NULL, 0, NULL, 0);
                TEST_CHK(s == FDB_RESULT_SUCCESS);
                s = fdb_get(db[j], doc);
                TEST_CHK(s == FDB_RESULT_SUCCESS);
                TEST_CMP(doc->body, valuebuf, doc->bodylen);
                s = fdb_doc_free(doc);
                TEST_CHK(s == FDB_RESULT_SUCCESS);
            }
        }
        s = fdb_commit(dbfile, FDB_COMMIT_NORMAL);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
    }

    s = fdb_close(dbfile);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    s = fdb_shutdown();
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    memleak_end();

    TEST_RESULT("compact upto with circular reuse test");
}

void compact_upto_last_wal_flush_bid_check()
{
    TEST_INIT();
    int i, j;
    int r;
    int ndocs=1000;
    int ncommit=20;
    fdb_file_handle *dbfile;
    fdb_kvs_handle *db;
    fdb_config config;
    fdb_kvs_config kvs_config;
    fdb_status s; (void)s;
    char keybuf[256], valuebuf[512];

    memleak_start();

    // remove previous dummy files
    r = system(SHELL_DEL" compact_test* > errorlog.txt");
    (void)r;

    config = fdb_get_default_config();
    config.num_keeping_headers = 20;
    kvs_config = fdb_get_default_kvs_config();

    // create a file
    s = fdb_open(&dbfile, "compact_test", &config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    s = fdb_kvs_open(dbfile, &db, "db", &kvs_config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    memset(valuebuf, 'x', 200);
    for (i=0; i<ncommit; ++i) {
        for (j=0; j<ndocs; ++j) {
            sprintf(keybuf, "k%06d", j);
            sprintf(valuebuf, "v%d_%04d", i, j);
            s = fdb_set_kv(db, keybuf, strlen(keybuf)+1, valuebuf, 200);
            TEST_CHK(s == FDB_RESULT_SUCCESS);
        }
        s = fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
    }

    fdb_snapshot_info_t *markers_out;
    uint64_t num_markers;

    s = fdb_get_all_snap_markers(dbfile, &markers_out, &num_markers);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    // compact_upto() will copy DB headers to be kept
    s = fdb_compact_upto(dbfile, "compact_test2", markers_out[15].marker);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    s = fdb_free_snap_markers(markers_out, num_markers);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    s = fdb_get_all_snap_markers(dbfile, &markers_out, &num_markers);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    // call compact_upto() again
    // copying the previous DB headers should be done correctly.
    s = fdb_compact_upto(dbfile, "compact_test3", markers_out[15].marker);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    s = fdb_free_snap_markers(markers_out, num_markers);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    s = fdb_close(dbfile);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    s = fdb_shutdown();
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    memleak_end();

    TEST_RESULT("compact upto last WAL flush bid check test");
}

int main(){
    int i;

    compact_deleted_doc_test();
    open_newfile_before_compact_done();
    compact_upto_test(false); // single kv instance in file
    compact_upto_test(true); // multiple kv instance in file
    compact_upto_last_wal_flush_bid_check();
    wal_delete_compact_upto_test();
    compact_upto_with_circular_reuse_test();
    for (i=0;i<4;++i) {
        compact_upto_overwrite_test(i);
    }
    compact_with_snapshot_open_multi_kvs_test();
    compact_with_snapshot_open_test();
    compact_upto_post_snapshot_test();
    compact_upto_twice_test();
    compaction_callback_test(true); // multi kv instance mode
    compaction_callback_test(false); // single kv instance mode
    compact_wo_reopen_test();
    compact_with_reopen_test();
#if !defined(THREAD_SANITIZER)
    compact_reopen_with_iterator();
#endif
    compact_reopen_named_kvs();
    estimate_space_upto_test(false); // single kv instance in file
    estimate_space_upto_test(true); // multiple kv instance in file
    // Since we call unlink() to the old file after compaction,
    // cloning old file after the compaction doesn't work anymore.
    // So we temporarily disable this test.
    //auto_recover_compact_ok_test();
    unlink_after_compaction_test();
    db_compact_overwrite();
    db_compact_during_doc_delete(NULL);
    compaction_with_concurrent_transaction_test();
    compaction_with_concurrent_update_test();
    auto_compaction_with_custom_cmp_function();
    compaction_daemon_test(20);
    auto_compaction_with_concurrent_insert_test(20);
    compaction_cancellation_test(COMPACTION_CANCEL_MODE);
    // Disable it temporarily until it is resolved.
    //compaction_cancellation_test(COMPACTION_ROLLBACK_MODE);

    return 0;
}

