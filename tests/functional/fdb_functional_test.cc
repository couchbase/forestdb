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

void basic_test()
{
    TEST_INIT();

    memleak_start();

    int i, r;
    int n = 10;
    fdb_file_handle *dbfile, *dbfile_rdonly;
    fdb_kvs_handle *db;
    fdb_kvs_handle *db_rdonly;
    fdb_doc **doc = alca(fdb_doc*, n);
    fdb_doc *rdoc = NULL;
    fdb_status status;

    char keybuf[256], metabuf[256], bodybuf[256];

    // remove previous dummy test files
    r = system(SHELL_DEL" dummy* > errorlog.txt");
    (void)r;

    fdb_config fconfig = fdb_get_default_config();
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    fconfig.wal_threshold = 1024;
    fconfig.compaction_threshold = 0;
    fconfig.purging_interval = 1;

    // Read-Write mode test without a create flag.
    fconfig.flags = 0;
    status = fdb_open(&dbfile, "./dummy1", &fconfig);
    TEST_CHK(status == FDB_RESULT_NO_SUCH_FILE);
    TEST_CHK(!strcmp(fdb_error_msg(status), "no such file"));

    // Read-Only mode test: Must not create new file.
    fconfig.flags = FDB_OPEN_FLAG_RDONLY;
    status = fdb_open(&dbfile, "./dummy1", &fconfig);
    TEST_CHK(status == FDB_RESULT_NO_SUCH_FILE);

    // Read-Only and Create mode: Must not create a new file.
    fconfig.flags = FDB_OPEN_FLAG_RDONLY | FDB_OPEN_FLAG_CREATE;
    status = fdb_open(&dbfile, "./dummy1", &fconfig);
    TEST_CHK(status == FDB_RESULT_INVALID_CONFIG);
    TEST_CHK(!strcmp(fdb_error_msg(status), "invalid configuration"));

    // open and close db with a create flag.
    fconfig.flags = FDB_OPEN_FLAG_CREATE;
    status = fdb_open(&dbfile, "./dummy1", &fconfig);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    TEST_CHK(!strcmp(fdb_error_msg(status), "success"));
    fdb_close(dbfile);

    // reopen db
    r = system(SHELL_DEL" dummy* > errorlog.txt");
    (void)r;
    fdb_open(&dbfile, "./dummy1",&fconfig);
    fdb_kvs_open_default(dbfile, &db, &kvs_config);
    status = fdb_set_log_callback(db, logCallbackFunc, (void *) "basic_test");
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

    // remove document #5
    fdb_doc_create(&rdoc, doc[5]->key, doc[5]->keylen, doc[5]->meta, doc[5]->metalen, NULL, 0);
    status = fdb_del(db, rdoc);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    fdb_doc_free(rdoc);
    rdoc = NULL;

    // commit
    fdb_commit(dbfile, FDB_COMMIT_NORMAL);

    // check the file info
    fdb_file_info info;
    fdb_get_file_info(dbfile, &info);
    TEST_CHK(info.doc_count == 9);
    TEST_CHK(info.deleted_count == 1);
    TEST_CHK(info.space_used > 0);
    TEST_CHK(info.num_kv_stores == 1);

    fdb_doc_create(&rdoc, doc[5]->key, doc[5]->keylen, NULL, 0, NULL, 0);
    status = fdb_get_metaonly(db, rdoc);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    TEST_CHK(rdoc->deleted == true);
    TEST_CMP(rdoc->meta, doc[5]->meta, rdoc->metalen);
    fdb_doc_free(rdoc);
    rdoc = NULL;

    // close the db
    fdb_kvs_close(db);
    fdb_close(dbfile);

    // reopen
    fdb_open(&dbfile, "./dummy1", &fconfig);
    fdb_kvs_open_default(dbfile, &db, &kvs_config);
    status = fdb_set_log_callback(db, logCallbackFunc, (void *) "basic_test");
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // update document #0 and #1
    for (i=0;i<2;++i){
        sprintf(metabuf, "meta2%d", i);
        sprintf(bodybuf, "body2%d", i);
        fdb_doc_update(&doc[i], (void *)metabuf, strlen(metabuf),
            (void *)bodybuf, strlen(bodybuf));
        fdb_set(db, doc[i]);
    }

    // commit
    fdb_commit(dbfile, FDB_COMMIT_NORMAL);

    // retrieve documents
    for (i=0;i<n;++i){
        // search by key
        fdb_doc_create(&rdoc, doc[i]->key, doc[i]->keylen, NULL, 0, NULL, 0);
        status = fdb_get(db, rdoc);

        if (i != 5) {
            // updated documents
            TEST_CHK(status == FDB_RESULT_SUCCESS);
            TEST_CMP(rdoc->meta, doc[i]->meta, rdoc->metalen);
            TEST_CMP(rdoc->body, doc[i]->body, rdoc->bodylen);
        } else {
            // removed document
            TEST_CHK(status == FDB_RESULT_KEY_NOT_FOUND);
            TEST_CHK(!strcmp(fdb_error_msg(status), "key not found"));
        }

        // free result document
        fdb_doc_free(rdoc);
        rdoc = NULL;
    }

    // do compaction
    fdb_compact(dbfile, (char *) "./dummy2");

    // retrieve documents after compaction
    for (i=0;i<n;++i){
        // search by key
        fdb_doc_create(&rdoc, doc[i]->key, doc[i]->keylen, NULL, 0, NULL, 0);
        status = fdb_get(db, rdoc);

        if (i != 5) {
            // updated documents
            TEST_CHK(status == FDB_RESULT_SUCCESS);
            TEST_CMP(rdoc->meta, doc[i]->meta, rdoc->metalen);
            TEST_CMP(rdoc->body, doc[i]->body, rdoc->bodylen);
        } else {
            // removed document
            TEST_CHK(status == FDB_RESULT_KEY_NOT_FOUND);
        }

        // free result document
        fdb_doc_free(rdoc);
        rdoc = NULL;
    }

    // retrieve documents by sequence number
    for (i=0; i < n+3; ++i){
        // search by seq
        fdb_doc_create(&rdoc, NULL, 0, NULL, 0, NULL, 0);
        rdoc->seqnum = i + 1;
        status = fdb_get_byseq(db, rdoc);
        if ( (i>=2 && i<=4) || (i>=6 && i<=9) || (i>=11 && i<=12)) {
            // updated documents
            TEST_CHK(status == FDB_RESULT_SUCCESS);
        } else {
            // removed document
            TEST_CHK(status == FDB_RESULT_KEY_NOT_FOUND);
        }

        // free result document
        fdb_doc_free(rdoc);
        rdoc = NULL;
    }

    // update document #5 with an empty doc body.
    fdb_doc_create(&rdoc, doc[5]->key, doc[5]->keylen, doc[5]->meta, doc[5]->metalen, NULL, 0);
    status = fdb_set(db, rdoc);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    fdb_doc_free(rdoc);
    rdoc = NULL;
    fdb_commit(dbfile, FDB_COMMIT_NORMAL);

    // Check document #5 with respect to metadata and doc body.
    fdb_doc_create(&rdoc, doc[5]->key, doc[5]->keylen, NULL, 0, NULL, 0);
    status = fdb_get(db, rdoc);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    TEST_CHK(memcmp(rdoc->meta, doc[5]->meta, rdoc->metalen) == 0);
    TEST_CHK(rdoc->body == NULL);
    TEST_CHK(rdoc->bodylen == 0);
    fdb_doc_free(rdoc);
    rdoc = NULL;

    // Read-Only mode test: Open succeeds if file exists, but disallow writes
    fconfig.flags = FDB_OPEN_FLAG_RDONLY;
    status = fdb_open(&dbfile_rdonly, "./dummy2", &fconfig);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_kvs_open_default(dbfile_rdonly, &db_rdonly, &kvs_config);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    fdb_doc_create(&rdoc, doc[0]->key, doc[0]->keylen, NULL, 0, NULL, 0);
    status = fdb_get(db_rdonly, rdoc);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    status = fdb_set_log_callback(db_rdonly, logCallbackFunc,
                                  (void *) "basic_test");
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    status = fdb_set(db_rdonly, doc[i]);
    TEST_CHK(status == FDB_RESULT_RONLY_VIOLATION);
    TEST_CHK(!strcmp(fdb_error_msg(status), "database is read-only"));

    status = fdb_commit(dbfile_rdonly, FDB_COMMIT_NORMAL);
    TEST_CHK(status == FDB_RESULT_RONLY_VIOLATION);

    fdb_doc_free(rdoc);
    rdoc = NULL;
    fdb_kvs_close(db_rdonly);
    fdb_close(dbfile_rdonly);

    // free all documents
    for (i=0;i<n;++i){
        fdb_doc_free(doc[i]);
    }

    // do one more compaction
    fdb_compact(dbfile, (char *) "./dummy3");

    // close db file
    fdb_kvs_close(db);
    fdb_close(dbfile);

    // free all resources
    fdb_shutdown();

    memleak_end();

    TEST_RESULT("basic test");
}

void set_get_max_keylen()
{
    TEST_INIT();
    memleak_start();

    int r;
    static const int len = FDB_MAX_KEYLEN;
    char keybuf[len];
    void *rvalue;
    size_t rvalue_len;
    static const char *achar = "a";

    fdb_status status;
    fdb_file_handle *dbfile;
    fdb_kvs_handle *db;
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    fdb_config fconfig = fdb_get_default_config();
    fconfig.chunksize = 16;


    r = system(SHELL_DEL" dummy* > errorlog.txt");
    (void)r;

    for (int i = 0; i < len; ++i) {
        keybuf[i] = *achar;
    }
    keybuf[len-1] = '\0';

    // open db
    status = fdb_open(&dbfile, "./dummy1", &fconfig);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_kvs_open_default(dbfile, &db, &kvs_config);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // set kv
    status = fdb_set_kv(db, keybuf, strlen(keybuf), NULL, 0);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // get NULL pointer
    status = fdb_get(db, NULL);
    TEST_CHK(status == FDB_RESULT_INVALID_ARGS);

    // get kv
    status = fdb_get_kv(db, keybuf, strlen(keybuf), &rvalue, &rvalue_len);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    fdb_close(dbfile);
    fdb_shutdown();

    memleak_end();
    TEST_RESULT("set get max keylen");
}

void config_test()
{
    TEST_INIT();

    memleak_start();

    fdb_file_handle *dbfile;
    fdb_kvs_handle *db;
    fdb_status status;
    fdb_config fconfig;
    fdb_kvs_config kvs_config;
    int nfiles = 4;
    int i;
    size_t bcache_space_used;
    char fname[256];

    // remove previous dummy test files
    int r = system(SHELL_DEL" dummy* > errorlog.txt");
    (void)r;

    bcache_space_used = fdb_get_buffer_cache_used();
    TEST_CHK(bcache_space_used == 0);

    fconfig = fdb_get_default_config();
    fconfig.buffercache_size= (uint64_t) -1;
    status = fdb_open(&dbfile, "./dummy1", &fconfig);
    TEST_CHK(status == FDB_RESULT_TOO_BIG_BUFFER_CACHE);

    fconfig = fdb_get_default_config();
    fconfig.max_writer_lock_prob = 120;
    status = fdb_open(&dbfile, "./dummy1", &fconfig);
    TEST_CHK(status == FDB_RESULT_INVALID_CONFIG);

    fconfig = fdb_get_default_config();
    kvs_config = fdb_get_default_kvs_config();
    for (i = nfiles; i; --i) {
        sprintf(fname, "dummy%d", i);
        status = fdb_open(&dbfile, fname, &fconfig);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        status = fdb_kvs_open(dbfile, &db, "justonekv", &kvs_config);
        TEST_CHK(status == FDB_RESULT_SUCCESS);

        bcache_space_used = fdb_get_buffer_cache_used();

        // Since V3 magic number, 7 blocks are used:
        // 4 superblocks + KV name header + Stale-tree root node + DB header
        TEST_CHK(bcache_space_used == fconfig.blocksize * 7);

        status = fdb_close(dbfile);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
    }

    status = fdb_open(&dbfile, fname, &fconfig);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_kvs_open(dbfile, &db, "justonekv", &kvs_config);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_set_kv(db, (void*)"key", 3, (void*)"body", 5);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    bcache_space_used = fdb_get_buffer_cache_used();

    // Since V3 magic number, 8 blocks are used:
    // 7 blocks created eariler + document block for KV pair
    TEST_CHK(bcache_space_used == fconfig.blocksize * 8);

    fdb_close(dbfile);

    fdb_shutdown();

    memleak_end();
    TEST_RESULT("forestdb config test");
}

void deleted_doc_get_api_test()
{
    TEST_INIT();
    memleak_start();

    int r;
    fdb_file_handle *dbfile;
    fdb_kvs_handle *db;
    fdb_doc _doc;
    fdb_doc *doc = &_doc;
    fdb_doc *rdoc;
    fdb_status status;
    fdb_config fconfig;
    fdb_kvs_config kvs_config;
    char keybuf[256], bodybuf[256];

    r = system(SHELL_DEL " dummy* > errorlog.txt");
    (void)r;

    memset(doc, 0, sizeof(fdb_doc));
    doc->key = &keybuf[0];
    doc->body = &bodybuf[0];
    doc->seqnum = SEQNUM_NOT_USED;

    // open dbfile
    fconfig = fdb_get_default_config();
    fconfig.purging_interval = 1;
    kvs_config = fdb_get_default_kvs_config();
    status = fdb_open(&dbfile, "./dummy1", &fconfig);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_kvs_open(dbfile, &db, NULL, &kvs_config);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    sprintf(keybuf, "key");
    sprintf(bodybuf, "body");
    doc->keylen = strlen(keybuf);
    doc->bodylen = strlen(bodybuf);
    status = fdb_set(db, doc);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // Commit the doc so it goes into main index
    status = fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // Delete the doc
    status = fdb_del(db, doc);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // Commit the doc with wal flush so the delete is appended into the file
    status = fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);
    TEST_CHK(status == FDB_RESULT_SUCCESS);


    fdb_doc_create(&rdoc, keybuf, doc->keylen, NULL, 0, NULL, 0);

    // Deleted document should be accessible via fdb_get_metaonly()
    status = fdb_get_metaonly(db, rdoc);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    TEST_CHK(rdoc->deleted);
    rdoc->deleted = false;

    // Deleted document should be accessible via fdb_get_metaonly_byseq()
    status = fdb_get_metaonly_byseq(db, rdoc);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    TEST_CHK(rdoc->deleted);
    rdoc->deleted = false;

    // Deleted document should be accessible via fdb_get_byoffset()
    // But the return code must be FDB_RESULT_KEY_NOT_FOUND!
    status = fdb_get_byoffset(db, rdoc);
    TEST_CHK(status == FDB_RESULT_KEY_NOT_FOUND);
    TEST_CHK(rdoc->deleted);
    rdoc->deleted = false;

    // Deleted document should NOT be accessible via fdb_get()
    status = fdb_get(db, rdoc);
    TEST_CHK(status == FDB_RESULT_KEY_NOT_FOUND);
    TEST_CHK(!rdoc->deleted);
    rdoc->deleted = false;

    status = fdb_get_byseq(db, rdoc);
    TEST_CHK(status == FDB_RESULT_KEY_NOT_FOUND);
    TEST_CHK(!rdoc->deleted);

    fdb_doc_free(rdoc);
    // close without commit
    status = fdb_kvs_close(db);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_close(dbfile);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    fdb_shutdown();
    memleak_end();
    TEST_RESULT("deleted doc get api test");
}

void deleted_doc_stat_test()
{
    TEST_INIT();
    memleak_start();

    int r;
    fdb_file_handle *dbfile;
    fdb_kvs_handle *db;
    fdb_doc _doc;
    fdb_doc *doc = &_doc;
    fdb_doc *rdoc;
    fdb_status status;
    fdb_config fconfig;
    fdb_file_info info;
    fdb_kvs_config kvs_config;
    char keybuf[256], bodybuf[256];

    r = system(SHELL_DEL " dummy* > errorlog.txt");
    (void)r;

    memset(doc, 0, sizeof(fdb_doc));
    doc->key = &keybuf[0];
    doc->body = &bodybuf[0];
    doc->seqnum = SEQNUM_NOT_USED;

    // open dbfile
    fconfig = fdb_get_default_config();
    fconfig.purging_interval = 0;
    kvs_config = fdb_get_default_kvs_config();
    status = fdb_open(&dbfile, "./dummy1", &fconfig);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_kvs_open(dbfile, &db, "main", &kvs_config);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    sprintf(keybuf, "K"); // This is necessary to set keysize to 2 bytes so
    sprintf(bodybuf, "body"); // it matches KV_header doc's keysize of 10
    doc->keylen = strlen(keybuf) + 1; // in multi-kv mode and hits MB-16491
    doc->bodylen = strlen(bodybuf) + 1;
    status = fdb_set(db, doc);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // Delete the doc
    status = fdb_del(db, doc);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // Fetch the doc back
    fdb_doc_create(&rdoc, doc->key, doc->keylen, NULL, 0, NULL, 0);
    status = fdb_get(db, rdoc);
    TEST_CHK(status == FDB_RESULT_KEY_NOT_FOUND);
    fdb_doc_free(rdoc);

    // check the file info
    fdb_get_file_info(dbfile, &info);
    TEST_CHK(info.doc_count == 0);

    status = fdb_commit(dbfile, FDB_COMMIT_NORMAL);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    // check the file info again after commit..
    fdb_get_file_info(dbfile, &info);
    TEST_CHK(info.doc_count == 0);

    status = fdb_kvs_close(db);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_close(dbfile);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    fdb_shutdown();
    memleak_end();
    TEST_RESULT("deleted doc stat test");
}

// MB-16312
void complete_delete_test()
{
    TEST_INIT();

    int i, r, n = 1000;
    fdb_file_handle *dbfile;
    fdb_kvs_handle *db;
    fdb_iterator *fit;
    fdb_config config;
    fdb_kvs_config kvs_config;
    fdb_status s; (void)s;
    char path[256];
    char keybuf[256], valuebuf[256];

    memleak_start();

    sprintf(path, "./dummy1");

    r = system(SHELL_DEL " dummy* > errorlog.txt");
    (void)r;

    config = fdb_get_default_config();
    config.buffercache_size = 0;
    kvs_config = fdb_get_default_kvs_config();

    fdb_open(&dbfile, path, &config);
    s = fdb_kvs_open(dbfile, &db, "db1", &kvs_config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    for (i=0;i<n;++i){
        sprintf(keybuf, "key%05d", i);
        sprintf(valuebuf, "value%05d", i);
        s = fdb_set_kv(db, keybuf, strlen(keybuf)+1, valuebuf, strlen(valuebuf)+1);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
    }
    fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);

    for (i=0;i<n;++i){
        sprintf(keybuf, "key%05d", i);
        sprintf(valuebuf, "value%05d", i);
        s = fdb_del_kv(db, keybuf, strlen(keybuf)+1);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
    }
    fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);

    s = fdb_iterator_init(db, &fit, NULL, 0, NULL, 0, FDB_ITR_NO_DELETES);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_iterator_close(fit);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    fdb_close(dbfile);
    fdb_shutdown();

    memleak_end();
    TEST_RESULT("complete delete");
}

void large_batch_write_no_commit_test()
{
    TEST_INIT();
    memleak_start();

    int i, r;
    int n = 500000;
    fdb_file_handle *dbfile;
    fdb_kvs_handle *db;
    fdb_doc **doc = (fdb_doc **) malloc(sizeof(fdb_doc *) * n);
    fdb_status status;
    fdb_config fconfig;
    fdb_kvs_config kvs_config;
    char keybuf[256], metabuf[256], bodybuf[256];

    r = system(SHELL_DEL " dummy* > errorlog.txt");
    (void)r;

    // open dbfile
    fconfig = fdb_get_default_config();
    kvs_config = fdb_get_default_kvs_config();
    status = fdb_open(&dbfile, "./dummy1", &fconfig);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_kvs_open(dbfile, &db, NULL, &kvs_config);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // Write 500K docs to eject and flush some dirty pages into disk.
    for (i=0;i<n;++i){
        sprintf(keybuf, "key%128d", i);
        sprintf(metabuf, "meta%128d", i);
        sprintf(bodybuf, "body%128d", i);
        fdb_doc_create(&doc[i], (void*)keybuf, strlen(keybuf),
            (void*)metabuf, strlen(metabuf), (void*)bodybuf, strlen(bodybuf));
        fdb_set(db, doc[i]);
        fdb_doc_free(doc[i]);
    }

    // close without commit
    status = fdb_kvs_close(db);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_close(dbfile);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    status = fdb_open(&dbfile, "./dummy1", &fconfig);
    TEST_CHK(status == FDB_RESULT_NO_DB_HEADERS ||
             status == FDB_RESULT_SUCCESS); // No dirty pages are flushed into disk.
    if (status == FDB_RESULT_SUCCESS) {
        status = fdb_close(dbfile);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
    }

    free(doc);
    fdb_shutdown();
    memleak_end();
    TEST_RESULT("large batch write test with no commits");
}

void set_get_meta_test()
{
    TEST_INIT();
    memleak_start();

    int r;
    char keybuf[256];
    fdb_file_handle *dbfile;
    fdb_kvs_handle *db;
    fdb_doc *rdoc;
    fdb_status status;
    fdb_config fconfig = fdb_get_default_config();
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    fconfig.wal_threshold = 1024;
    fconfig.purging_interval = 1;
    fconfig.flags = FDB_OPEN_FLAG_CREATE;

    // remove previous dummy files
    r = system(SHELL_DEL" dummy* > errorlog.txt");
    (void)r;

    // open db
    fdb_open(&dbfile, "./dummy1", &fconfig);
    fdb_kvs_open(dbfile, &db, "db1", &kvs_config);

    sprintf(keybuf, "key%d", 0);
    fdb_doc_create(&rdoc, keybuf, strlen(keybuf), NULL, 0, NULL, 0);
    fdb_set(db, rdoc);
    status = fdb_get(db, rdoc);
    assert(status == FDB_RESULT_SUCCESS);
    status = fdb_get_byoffset(db, rdoc);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_get_metaonly(db, rdoc);
    assert(status == FDB_RESULT_SUCCESS);
    status = fdb_get_metaonly_byseq(db, rdoc);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    fdb_del(db, rdoc);
    status = fdb_get(db, rdoc);
    assert(status == FDB_RESULT_KEY_NOT_FOUND);
    assert(rdoc->deleted == true);

    status = fdb_get_metaonly(db, rdoc);
    assert(status == FDB_RESULT_SUCCESS);
    assert(rdoc->deleted == true);

    status = fdb_get_metaonly_byseq(db, rdoc);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    assert(rdoc->deleted == true);

    status = fdb_get_byoffset(db, rdoc);
    TEST_CHK(status == FDB_RESULT_KEY_NOT_FOUND);
    assert(rdoc->deleted == true);


    fdb_doc_free(rdoc);
    fdb_kvs_close(db);
    fdb_close(dbfile);
    fdb_shutdown();

    memleak_end();
    TEST_RESULT("set get meta test");
}

void long_filename_test()
{
    TEST_INIT();
    memleak_start();

    int i, j, r;
    int n=15, m=1000;
    char keyword[] = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    char filename[4096], cmd[4096], temp[4096];
    fdb_file_handle *dbfile;
    fdb_kvs_handle *db;
    fdb_config config;
    fdb_kvs_config kvs_config;
    fdb_status s;
    size_t rvalue_len;
    char key[256], value[256];
    void *rvalue;

    config = fdb_get_default_config();
    kvs_config = fdb_get_default_kvs_config();
    sprintf(temp, SHELL_DMT"%s", keyword);

    // filename longer than 1024 bytes
    sprintf(filename, "%s", keyword);
    while (strlen(filename) < 1024) {
        strcat(filename, keyword);
    }
    s = fdb_open(&dbfile, filename, &config);
    TEST_CHK(s == FDB_RESULT_TOO_LONG_FILENAME);

    // make nested directories for long path
    // but shorter than 1024 bytes (windows: 256 bytes)
    sprintf(cmd, SHELL_RMDIR" %s", keyword);
    r = system(cmd);
    (void)r;
    for (i=0;i<n;++i) {
        sprintf(cmd, SHELL_MKDIR" %s", keyword);
        for (j=0;j<i;++j){
            strcat(cmd, temp);
        }
        if (strlen(cmd) > SHELL_MAX_PATHLEN) break;
        r = system(cmd);
        (void)r;
    }

    // create DB file
    sprintf(filename, "%s", keyword);
    for (j=0;j<i-1;++j){
        strcat(filename, temp);
    }
    strcat(filename, SHELL_DMT"dbfile");
    s = fdb_open(&dbfile, filename, &config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_kvs_open_default(dbfile, &db, &kvs_config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    // === write ===
    for (i=0;i<m;++i){
        sprintf(key, "key%08d", i);
        sprintf(value, "value%08d", i);
        s = fdb_set_kv(db, key, strlen(key)+1, value, strlen(value)+1);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
    }
    s = fdb_commit(dbfile, FDB_COMMIT_NORMAL);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    // === read ===
    for (i=0;i<m;++i){
        sprintf(key, "key%08d", i);
        s = fdb_get_kv(db, key, strlen(key)+1, &rvalue, &rvalue_len);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        fdb_free_block(rvalue);
    }

    s = fdb_kvs_close(db);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_close(dbfile);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_shutdown();
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    sprintf(cmd, SHELL_RMDIR" %s", keyword);
    r = system(cmd);
    (void)r;

    memleak_end();
    TEST_RESULT("long filename test");
}

void error_to_str_test()
{
    TEST_INIT();
    memleak_start();
    int i;
    const char *err_msg;

    for (i = FDB_RESULT_SUCCESS; i >= FDB_RESULT_LAST; --i) {
        err_msg = fdb_error_msg((fdb_status)i);
        // Verify that all error codes have corresponding error messages
        TEST_CHK(strcmp(err_msg, "unknown error"));
    }

    err_msg = fdb_error_msg((fdb_status)i);
    // Verify that the last error code has been checked
    TEST_CHK(!strcmp(err_msg, "unknown error"));

    memleak_end();
    TEST_RESULT("error to string message test");
}

void seq_tree_exception_test()
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
    fdb_iterator *it;

    char keybuf[256], metabuf[256], bodybuf[256];

    // remove previous dummy files
    r = system(SHELL_DEL" dummy* > errorlog.txt");
    (void)r;

    fdb_config fconfig = fdb_get_default_config();
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    fconfig.seqtree_opt = FDB_SEQTREE_NOT_USE;

    // open db
    fdb_open(&dbfile, "./dummy1", &fconfig);
    fdb_kvs_open_default(dbfile, &db, &kvs_config);
    status = fdb_set_log_callback(db, logCallbackFunc,
                                  (void *) "seq_tree_exception_test");
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // insert documents
    for (i=0;i<n;++i){
        sprintf(keybuf, "key%d", i);
        sprintf(metabuf, "meta%d", i);
        sprintf(bodybuf, "body%d", i);
        fdb_doc_create(&doc[i],
                       (void *)keybuf,  strlen(keybuf),
                       (void *)metabuf, strlen(metabuf),
                       (void *)bodybuf, strlen(bodybuf));
        fdb_set(db, doc[i]);
    }

    // commit
    fdb_commit(dbfile, FDB_COMMIT_NORMAL);

    status = fdb_compact(dbfile, NULL);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // close the db
    fdb_kvs_close(db);
    fdb_close(dbfile);

    // reopen with seq tree option
    fconfig.seqtree_opt = FDB_SEQTREE_USE;
    status = fdb_open(&dbfile, "./dummy1", &fconfig);
    // must succeed
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_kvs_open_default(dbfile, &db, &kvs_config);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_set_log_callback(db, logCallbackFunc,
                                  (void *) "seq_tree_exception_test");
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // search by seq
    fdb_doc_create(&rdoc, NULL, 0, NULL, 0, NULL, 0);
    rdoc->seqnum = 1;
    status = fdb_get_byseq(db, rdoc);
    // must fail
    TEST_CHK(status != FDB_RESULT_SUCCESS);

    // search meta by seq
    status = fdb_get_metaonly_byseq(db, rdoc);
    // must fail
    TEST_CHK(status != FDB_RESULT_SUCCESS);

    // init iterator by seq
    status = fdb_iterator_sequence_init(db , &it, 0, 0, FDB_ITR_NONE);
    // must fail
    TEST_CHK(status != FDB_RESULT_SUCCESS);

    // close db file
    fdb_kvs_close(db);
    fdb_close(dbfile);

    // free all documents
    free(rdoc);
    for (i=0;i<n;++i){
        fdb_doc_free(doc[i]);
    }

    // remove previous dummy files
    r = system(SHELL_DEL" dummy* > errorlog.txt");
    (void)r;

    // open db
    fconfig.seqtree_opt = FDB_SEQTREE_USE;
    fdb_open(&dbfile, "./dummy1", &fconfig);
    fdb_kvs_open_default(dbfile, &db, &kvs_config);
    status = fdb_set_log_callback(db, logCallbackFunc,
                                  (void *) "seq_tree_exception_test");
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // insert documents
    for (i=0;i<n;++i){
        sprintf(keybuf, "key%d", i);
        sprintf(metabuf, "meta%d", i);
        sprintf(bodybuf, "body%d", i);
        fdb_doc_create(&doc[i],
                       (void *)keybuf,  strlen(keybuf),
                       (void *)metabuf, strlen(metabuf),
                       (void *)bodybuf, strlen(bodybuf));
        fdb_set(db, doc[i]);
    }

    // commit
    fdb_commit(dbfile, FDB_COMMIT_NORMAL);

    // close the db
    fdb_kvs_close(db);
    fdb_close(dbfile);

    // reopen with an option disabling seq tree
    fconfig.seqtree_opt = FDB_SEQTREE_NOT_USE;
    status = fdb_open(&dbfile, "./dummy1", &fconfig);
    // must succeed
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_close(dbfile);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // free all documents
    for (i=0;i<n;++i){
        fdb_doc_free(doc[i]);
    }

    // free all resources
    fdb_shutdown();

    memleak_end();

    TEST_RESULT("sequence tree exception test");
}

void wal_commit_test()
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

    char keybuf[256], metabuf[256], bodybuf[256];

    // remove previous dummy files
    r = system(SHELL_DEL" dummy* > errorlog.txt");
    (void)r;

    fdb_config fconfig = fdb_get_default_config();
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    fconfig.buffercache_size = 0;
    fconfig.wal_threshold = 1024;
    fconfig.flags = FDB_OPEN_FLAG_CREATE;
    fconfig.compaction_threshold = 0;

    // open db
    fdb_open(&dbfile, "./dummy1", &fconfig);
    fdb_kvs_open_default(dbfile, &db, &kvs_config);
    status = fdb_set_log_callback(db, logCallbackFunc, (void *) "wal_commit_test");
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // insert half documents
    for (i=0;i<n/2;++i){
        sprintf(keybuf, "key%d", i);
        sprintf(metabuf, "meta%d", i);
        sprintf(bodybuf, "body%d", i);
        fdb_doc_create(&doc[i], (void *)keybuf, strlen(keybuf),
            (void*)metabuf, strlen(metabuf), (void*)bodybuf, strlen(bodybuf));
        fdb_set(db, doc[i]);
    }

    // commit
    fdb_commit(dbfile, FDB_COMMIT_NORMAL);

    // insert the other half documents
    for (i=n/2;i<n;++i){
        sprintf(keybuf, "key%d", i);
        sprintf(metabuf, "meta%d", i);
        sprintf(bodybuf, "body%d", i);
        fdb_doc_create(&doc[i], (void *)keybuf, strlen(keybuf),
            (void *)metabuf, strlen(metabuf), (void *)bodybuf, strlen(bodybuf));
        fdb_set(db, doc[i]);
    }

    // close the db
    fdb_kvs_close(db);
    fdb_close(dbfile);

    // reopen
    fdb_open(&dbfile, "./dummy1", &fconfig);
    fdb_kvs_open_default(dbfile, &db, &kvs_config);
    status = fdb_set_log_callback(db, logCallbackFunc, (void *) "wal_commit_test");
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // retrieve documents
    for (i=0;i<n;++i){
        // search by key
        fdb_doc_create(&rdoc, doc[i]->key, doc[i]->keylen, NULL, 0, NULL, 0);
        status = fdb_get(db, rdoc);

        if (i < n/2) {
            // committed documents
            TEST_CHK(status == FDB_RESULT_SUCCESS);
            TEST_CMP(rdoc->meta, doc[i]->meta, rdoc->metalen);
            TEST_CMP(rdoc->body, doc[i]->body, rdoc->bodylen);
        } else {
            // not committed document
            TEST_CHK(status == FDB_RESULT_KEY_NOT_FOUND);
        }

        // free result document
        fdb_doc_free(rdoc);
        rdoc = NULL;
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

    TEST_RESULT("WAL commit test");
}

void db_close_and_remove()
{

    TEST_INIT();
    memleak_start();

    int i, r;
    int n = 10;
    fdb_file_handle *dbfile;
    fdb_kvs_handle *db;
    fdb_doc **doc = alca(fdb_doc *, n);
    fdb_status status;
    fdb_config fconfig;
    fdb_kvs_config kvs_config;
    char keybuf[256], metabuf[256], bodybuf[256];

    r = system(SHELL_DEL " dummy* > errorlog.txt");
    (void)r;

    // open dbfile
    fconfig = fdb_get_default_config();
    kvs_config = fdb_get_default_kvs_config();
    fconfig.cleanup_cache_onclose = false;
    fdb_open(&dbfile, "./dummy1", &fconfig);
    fdb_kvs_open(dbfile, &db, NULL, &kvs_config);

    // write to db
    for (i=0;i<n;++i){
        sprintf(keybuf, "key%d", i);
        sprintf(metabuf, "meta%d", i);
        sprintf(bodybuf, "body%d", i);
        fdb_doc_create(&doc[i], (void*)keybuf, strlen(keybuf),
            (void*)metabuf, strlen(metabuf), (void*)bodybuf, strlen(bodybuf));
        fdb_set(db, doc[i]);
        fdb_doc_free(doc[i]);
    }
    status = fdb_commit(dbfile, FDB_COMMIT_NORMAL);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // close
    fdb_kvs_close(db);
    fdb_close(dbfile);

    // remove dbfile
    r = system(SHELL_DEL " dummy* > errorlog.txt");
    (void)r;

    // re-open read-only
    fconfig.flags = FDB_OPEN_FLAG_RDONLY;
    status = fdb_open(&dbfile, "./dummy1", &fconfig);
    TEST_CHK(status == FDB_RESULT_NO_SUCH_FILE);

    fdb_shutdown();
    memleak_end();
    TEST_RESULT("db close and remove");
}

void db_drop_test()
{
    TEST_INIT();

    memleak_start();

    int i, r;
    int n = 3;
    fdb_file_handle *dbfile;
    fdb_kvs_handle *db;
    fdb_doc **doc = alca(fdb_doc *, n);
    fdb_doc *rdoc = NULL;
    fdb_status status;

    char keybuf[256], metabuf[256], bodybuf[256];

    // remove previous dummy files
    r = system(SHELL_DEL " dummy* > errorlog.txt");
    (void)r;

    fdb_config fconfig = fdb_get_default_config();
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    fconfig.buffercache_size = 16777216;
    fconfig.wal_threshold = 1024;
    fconfig.flags = FDB_OPEN_FLAG_CREATE;
    fconfig.compaction_threshold = 0;

    // open db
    fdb_open(&dbfile, "./dummy1", &fconfig);
    fdb_kvs_open(dbfile, &db, NULL, &kvs_config);
    status = fdb_set_log_callback(db, logCallbackFunc,
                                  (void *) "db_drop_test");
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

    // commit
    fdb_commit(dbfile, FDB_COMMIT_NORMAL);
    fdb_kvs_close(db);
    fdb_close(dbfile);

    // Remove the database file manually.
    r = system(SHELL_DEL " dummy1 > errorlog.txt");
    (void)r;

    // Open the empty db with the same name.
    fdb_open(&dbfile, "./dummy1", &fconfig);
    fdb_kvs_open_default(dbfile, &db, &kvs_config);
    status = fdb_set_log_callback(db, logCallbackFunc,
                                  (void *) "db_drop_test");
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // now insert a new doc.
    sprintf(keybuf, "key%d", 0);
    sprintf(metabuf, "meta%d", 0);
    sprintf(bodybuf, "body%d", 0);
    fdb_doc_free(doc[0]);
    fdb_doc_create(&doc[0], (void*)keybuf, strlen(keybuf),
        (void*)metabuf, strlen(metabuf), (void*)bodybuf, strlen(bodybuf));
    fdb_set(db, doc[0]);

    // commit
    fdb_commit(dbfile, FDB_COMMIT_NORMAL);

    // search by key
    fdb_doc_create(&rdoc, doc[0]->key, doc[0]->keylen, NULL, 0, NULL, 0);
    status = fdb_get(db, rdoc);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    // Make sure that a doc seqnum starts with one.
    TEST_CHK(rdoc->seqnum == 1);

    fdb_kvs_close(db);
    fdb_close(dbfile);

    // free all documents
    fdb_doc_free(rdoc);
    rdoc = NULL;
    for (i=0;i<2;++i){
        fdb_doc_free(doc[i]);
    }

    // free all resources
    fdb_shutdown();

    memleak_end();

    TEST_RESULT("Database drop test");
}

void db_destroy_test()
{
    TEST_INIT();

    memleak_start();

    int i, r;
    int n = 30;
    fdb_file_handle *dbfile, *dbfile2;
    fdb_kvs_handle *db, *db2;
    fdb_doc **doc = alca(fdb_doc *, n);
    fdb_doc *rdoc = NULL;
    fdb_status status;
    fdb_config fconfig;
    fdb_kvs_config kvs_config;

    char keybuf[256], metabuf[256], bodybuf[256];

    // remove previous dummy files
    r = system(SHELL_DEL " dummy* > errorlog.txt");
    (void)r;

    fconfig = fdb_get_default_config();
    kvs_config = fdb_get_default_kvs_config();
    fconfig.buffercache_size = 16777216;
    fconfig.wal_threshold = 1024;
    fconfig.flags = FDB_OPEN_FLAG_CREATE;
    fconfig.compaction_threshold = 0;

    // open db
    fdb_open(&dbfile, "./dummy1", &fconfig);
    fdb_kvs_open(dbfile, &db, NULL, &kvs_config);
    status = fdb_set_log_callback(db, logCallbackFunc,
                                  (void *) "db_destroy_test");
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // insert 30 documents
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

    // Open the empty db with the same name.
    fdb_open(&dbfile2, "./dummy2", &fconfig);
    fdb_kvs_open(dbfile2, &db2, NULL, &kvs_config);
    status = fdb_set_log_callback(db2, logCallbackFunc,
                                  (void *) "db_destroy_test");
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    // insert 30 documents
    for (i=0;i<n;++i){
        fdb_set(db2, doc[i]);
    }

    // commit
    fdb_commit(dbfile2, FDB_COMMIT_NORMAL);

    // Only close db not db2 and try to destroy
    fdb_close(dbfile);

    status = fdb_destroy("./dummy2", &fconfig);
    TEST_CHK(status == FDB_RESULT_FILE_IS_BUSY);

    //Now close the open db file
    fdb_close(dbfile2);

    status = fdb_destroy("./dummy1", &fconfig);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // Open the same db with the same names.
    fdb_open(&dbfile, "./dummy1", &fconfig);
    fdb_kvs_open(dbfile, &db, NULL, &kvs_config);
    status = fdb_set_log_callback(db, logCallbackFunc,
                                  (void *) "db_destroy_test");
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // search by key
    fdb_doc_create(&rdoc, doc[0]->key, doc[0]->keylen, NULL, 0, NULL, 0);
    status = fdb_get(db, rdoc);
    TEST_CHK(status == FDB_RESULT_KEY_NOT_FOUND);
    fdb_close(dbfile);

    // free all documents
    fdb_doc_free(rdoc);
    rdoc = NULL;
    for (i=0;i<n;++i){
        fdb_doc_free(doc[i]);
    }

    // free all resources
    fdb_shutdown();

    memleak_end();

    TEST_RESULT("Database destroy test");
}

// Test for MB-16348
void db_destroy_test_full_path()
{
    TEST_INIT();

    memleak_start();
    randomize();

    int r;
    fdb_file_handle *dbfile;
    fdb_config config;
    fdb_status s;
    char path[256];
    char cmd[256];

    sprintf(path, "/tmp/fdb_destroy_test_%d", random(10000));

    sprintf(cmd, "rm -rf %s*", path);
    r = system(cmd); (void)r;

    config = fdb_get_default_config();
    config.compaction_mode = FDB_COMPACTION_AUTO;

    fdb_open(&dbfile, path, &config);
    fdb_close(dbfile);

    s = fdb_destroy(path, &config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    fdb_shutdown();

    memleak_end();

    TEST_RESULT("Database destroy (full path) test");
}

void operational_stats_test(bool multi_kv)
{
    TEST_INIT();

    memleak_start();

    int i, r;
    int n = 10;
    int num_kv = 4;
    fdb_file_handle *dbfile;
    fdb_kvs_handle **db = alca(fdb_kvs_handle*, num_kv);
    fdb_doc **doc = alca(fdb_doc*, n);
    fdb_doc real_doc;
    fdb_doc *rdoc = &real_doc;
    fdb_status status;
    fdb_iterator *iterator;
    fdb_kvs_ops_info info, rinfo;

    char keybuf[256], bodybuf[256];
    memset(&info, 0, sizeof(fdb_kvs_ops_info));
    memset(&real_doc, 0, sizeof(fdb_doc));
    real_doc.key = &keybuf;
    real_doc.body = &bodybuf;

    // remove previous dummy files
    r = system(SHELL_DEL" dummy* > errorlog.txt");
    (void)r;

    fdb_config fconfig = fdb_get_default_config();
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();

    fconfig.buffercache_size = 0;
    fconfig.wal_threshold = 1024;
    fconfig.flags = FDB_OPEN_FLAG_CREATE;
    fconfig.compaction_threshold = 0;
    fconfig.multi_kv_instances = multi_kv;
    r = 0;

    fdb_open(&dbfile, "./dummy1", &fconfig);
    if (multi_kv) {
        num_kv = 4;
        for (r = num_kv - 1; r >= 0; --r) {
            char tmp[16];
            sprintf(tmp, "kv%d", r);
            status = fdb_kvs_open(dbfile, &db[r], tmp, &kvs_config);
            TEST_CHK(status == FDB_RESULT_SUCCESS);
            status = fdb_set_log_callback(db[r], logCallbackFunc,
                                          (void *) "operational_stats_test");
            TEST_CHK(status == FDB_RESULT_SUCCESS);
        }
    } else {
        num_kv = 1;
        status = fdb_kvs_open_default(dbfile, &db[r], &kvs_config);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        status = fdb_set_log_callback(db[r], logCallbackFunc,
                (void *) "operational_stats_test");
        TEST_CHK(status == FDB_RESULT_SUCCESS);
    }

    for (i = 0; i < n; ++i){
        sprintf(keybuf, "key%d", i);
        sprintf(bodybuf, "body%d", i);
        fdb_doc_create(&doc[i], (void*)keybuf, strlen(keybuf) + 1, NULL, 0,
            (void*)bodybuf, strlen(bodybuf)+1);
        for (r = num_kv - 1; r >= 0; --r) {
            status = fdb_set(db[r], doc[i]);
            TEST_CHK(status == FDB_RESULT_SUCCESS);
            status = fdb_get_kvs_ops_info(db[r], &rinfo);
            TEST_CHK(status == FDB_RESULT_SUCCESS);
            info.num_sets = i + 1;
            TEST_CMP(&rinfo, &info, sizeof(fdb_kvs_ops_info));
        }
    }

    for (r = num_kv - 1; r >= 0; --r) {
        // range scan (before flushing WAL)
        fdb_iterator_init(db[r], &iterator, NULL, 0, NULL, 0, 0x0);
        i = 0;
        do {
            status = fdb_iterator_get(iterator, &rdoc);
            TEST_CHK(status == FDB_RESULT_SUCCESS);
            TEST_CMP(rdoc->key, doc[i]->key, rdoc->keylen);
            TEST_CMP(rdoc->body, doc[i]->body, rdoc->bodylen);
            status = fdb_get_kvs_ops_info(db[r], &rinfo);
            TEST_CHK(status == FDB_RESULT_SUCCESS);
            ++info.num_iterator_gets;
            ++info.num_iterator_moves;
            TEST_CMP(&rinfo, &info, sizeof(fdb_kvs_ops_info));
            ++i;
        } while(fdb_iterator_next(iterator) != FDB_RESULT_ITERATOR_FAIL);
        ++info.num_iterator_moves; // account for the last move that failed
        fdb_iterator_close(iterator);

        fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);
        ++info.num_commits;

        status = fdb_get_kvs_ops_info(db[r], &rinfo);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        TEST_CMP(&rinfo, &info, sizeof(fdb_kvs_ops_info));

        if (r) {
            info.num_iterator_gets = 0;
            info.num_iterator_moves = 0;
        }
    }

    ++info.num_compacts;
    // do compaction
    fdb_compact(dbfile, (char *) "./dummy2");

    status = fdb_get_kvs_ops_info(db[0], &rinfo);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    TEST_CMP(&rinfo, &info, sizeof(fdb_kvs_ops_info));

    for (i = 0; i < n; ++i){
        sprintf(keybuf, "key%d", i);
        for (r = num_kv - 1; r >= 0; --r) {
            if (i % 2 == 0) {
                if (i % 4 == 0) {
                    status = fdb_get_metaonly(db[r], rdoc);
                } else {
                    rdoc->seqnum = i + 1;
                    status = fdb_get_byseq(db[r], rdoc);
                }
            } else {
                status = fdb_get(db[r], rdoc);
            }
            TEST_CHK(status == FDB_RESULT_SUCCESS);
            status = fdb_get_kvs_ops_info(db[r], &rinfo);
            TEST_CHK(status == FDB_RESULT_SUCCESS);
            info.num_gets = i + 1;
            TEST_CMP(&rinfo, &info, sizeof(fdb_kvs_ops_info));
        }
    }
    // also get latency stats..
    for (int i = 0; i < FDB_LATENCY_NUM_STATS; ++i) {
        fdb_latency_stat stat;
        memset(&stat, 0, sizeof(fdb_latency_stat));
        status = fdb_get_latency_stats(dbfile, &stat, i);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        fprintf(stderr, "%d:\t%u\t%u\t%u\t%" _F64 "\n", i,
                stat.lat_max, stat.lat_avg, stat.lat_max, stat.lat_count);
    }

    fdb_close(dbfile);

    // free all documents
    for (i=0;i<n;++i){
        fdb_doc_free(doc[i]);
    }

    // free all resources
    fdb_shutdown();

    memleak_end();

    sprintf(bodybuf,"Operational stats test %s", multi_kv ?
            "multiple kv instances" : "single kv instance");
    TEST_RESULT(bodybuf);
}

struct work_thread_args{
    int tid;
    size_t nthreads;
    size_t ndocs;
    size_t writer;
    fdb_doc **doc;
    size_t time_sec;
    size_t nbatch;
    size_t compact_term;
    int *n_opened;
    int *filename_count;
    spin_t *filename_count_lock;
    size_t nops;
    fdb_config *config;
    fdb_kvs_config *kvs_config;
};

//#define FILENAME "./hdd/dummy"
#define FILENAME "dummy"

#define KSIZE (100)
#define VSIZE (100)
#define IDX_DIGIT (7)
#define IDX_DIGIT_STR "7"

void *_worker_thread(void *voidargs)
{
    TEST_INIT();

    struct work_thread_args *args = (struct work_thread_args *)voidargs;
    int i, c, commit_count, filename_count;
    struct timeval ts_begin, ts_cur, ts_gap;
    fdb_file_handle *dbfile;
    fdb_kvs_handle *db;
    fdb_status status;
    fdb_doc *rdoc = NULL;
    char temp[1024];

    char cnt_str[IDX_DIGIT+1];
    int cnt_int;

    filename_count = *args->filename_count;
    sprintf(temp, FILENAME"%d", filename_count);
    fdb_open(&dbfile, temp, args->config);
    fdb_kvs_open_default(dbfile, &db, args->kvs_config);
    status = fdb_set_log_callback(db, logCallbackFunc,
                                  (void *) "worker_thread");
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // wait until all other threads open the DB file.
    // (to avoid performing compaction before opening the file)
    spin_lock(args->filename_count_lock);
    *args->n_opened += 1;
    spin_unlock(args->filename_count_lock);
    do {
        spin_lock(args->filename_count_lock);
        if ((size_t)(*args->n_opened) == args->nthreads) {
            // all threads open the DB file
            spin_unlock(args->filename_count_lock);
            break;
        }
        spin_unlock(args->filename_count_lock);
        // sleep 1 sec
        sleep(1);
    } while (1);

    gettimeofday(&ts_begin, NULL);

    c = cnt_int = commit_count = 0;
    cnt_str[IDX_DIGIT] = 0;

    while (1){
        i = rand() % args->ndocs;
        fdb_doc_create(&rdoc, args->doc[i]->key, args->doc[i]->keylen, NULL, 0, NULL, 0);
        status = fdb_get(db, rdoc);

        TEST_CHK(status == FDB_RESULT_SUCCESS);
        TEST_CMP(rdoc->body, args->doc[i]->body, (IDX_DIGIT+1));

        if (args->writer) {
            // if writer,
            // copy and parse the counter in body
            memcpy(cnt_str, (uint8_t *)rdoc->body + (IDX_DIGIT+1), IDX_DIGIT);
            cnt_int = atoi(cnt_str);

            // increase and rephrase
            sprintf(cnt_str, "%0 " IDX_DIGIT_STR "d", ++cnt_int);
            memcpy((uint8_t *)rdoc->body + (IDX_DIGIT+1), cnt_str, IDX_DIGIT);

            // update and commit
            status = fdb_set(db, rdoc);
            TEST_CHK(status == FDB_RESULT_SUCCESS);

            if (args->nbatch > 0) {
                if (c % args->nbatch == 0) {
                    // commit for every NBATCH
                    fdb_commit(dbfile, FDB_COMMIT_NORMAL);
                    commit_count++;
                    fdb_file_info info;
                    fdb_get_file_info(dbfile, &info);
                    if (args->compact_term == (size_t)commit_count &&
                        args->compact_term > 0 &&
                        info.new_filename == NULL &&
                        args->tid == 0) {
                        // do compaction for every COMPACT_TERM batch
                        spin_lock(args->filename_count_lock);
                        *args->filename_count += 1;
                        filename_count = *args->filename_count;
                        spin_unlock(args->filename_count_lock);

                        sprintf(temp, FILENAME"%d", filename_count);

                        status = fdb_compact(dbfile, temp);
                        if (status != FDB_RESULT_SUCCESS) {
                            spin_lock(args->filename_count_lock);
                            *args->filename_count -= 1;
                            spin_unlock(args->filename_count_lock);
                        }

                        commit_count = 0;
                    }
                }
            }
        }
        fdb_doc_free(rdoc);
        rdoc = NULL;
        c++;

        gettimeofday(&ts_cur, NULL);
        ts_gap = _utime_gap(ts_begin, ts_cur);
        if ((size_t)ts_gap.tv_sec >= args->time_sec) break;
    }

    DBG("Thread #%d (%s) %d ops / %d seconds\n",
        args->tid, (args->writer)?("writer"):("reader"), c, (int)args->time_sec);
    args->nops = c;

    fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);

    fdb_kvs_close(db);
    fdb_close(dbfile);
    thread_exit(0);
    return NULL;
}

void multi_thread_test(
    size_t ndocs, size_t wal_threshold, size_t time_sec,
    size_t nbatch, size_t compact_term, size_t nwriters, size_t nreaders)
{
    TEST_INIT();

    size_t nwrites, nreads;
    int i, r;
    int n = nwriters + nreaders;;
    thread_t *tid = alca(thread_t, n);
    void **thread_ret = alca(void *, n);
    struct work_thread_args *args = alca(struct work_thread_args, n);
    struct timeval ts_begin, ts_cur, ts_gap;
    fdb_file_handle *dbfile;
    fdb_kvs_handle *db;
    fdb_doc **doc = alca(fdb_doc*, ndocs);
    fdb_status status;
    fdb_kvs_info kvs_info;

    int filename_count = 1;
    int n_opened = 0;
    spin_t filename_count_lock;
    spin_init(&filename_count_lock);

    char keybuf[1024], metabuf[1024], bodybuf[1024], temp[1024];

    // remove previous dummy files
    r = system(SHELL_DEL" " FILENAME "* > errorlog.txt");
    (void)r;

    fdb_config fconfig = fdb_get_default_config();
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    fconfig.buffercache_size = 16777216;
    fconfig.wal_threshold = 1024;
    fconfig.flags = FDB_OPEN_FLAG_CREATE;
    fconfig.compaction_threshold = 0;

    memleak_start();

    // initial population ===
    DBG("Initialize..\n");

    // open db
    sprintf(temp, FILENAME"%d", filename_count);
    fdb_open(&dbfile, temp, &fconfig);
    fdb_kvs_open_default(dbfile, &db, &kvs_config);
    status = fdb_set_log_callback(db, logCallbackFunc,
                                  (void *) "multi_thread_test");
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    gettimeofday(&ts_begin, NULL);

    // insert documents
    for (i = 0; (size_t)i < ndocs; ++i){
        _set_random_string_smallabt(temp, KSIZE - (IDX_DIGIT+1));
        sprintf(keybuf, "k%0" IDX_DIGIT_STR "d%s", i, temp);

        sprintf(metabuf, "m%0" IDX_DIGIT_STR "d", i);

        _set_random_string_smallabt(temp, VSIZE-(IDX_DIGIT*2+1));
        sprintf(bodybuf, "b%0" IDX_DIGIT_STR "d%0" IDX_DIGIT_STR "d%s", i, 0, temp);

        fdb_doc_create(&doc[i], (void*)keybuf, strlen(keybuf),
            (void*)metabuf, strlen(metabuf), (void*)bodybuf, strlen(bodybuf));
        fdb_set(db, doc[i]);
    }

    fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);

    gettimeofday(&ts_cur, NULL);
    ts_gap = _utime_gap(ts_begin, ts_cur);
    //DBG("%d.%09d seconds elapsed\n", (int)ts_gap.tv_sec, (int)ts_gap.tv_nsec);

    fdb_kvs_close(db);
    fdb_close(dbfile);
    // end of population ===

    // drop OS's page cache
    //r = system("free && sync && echo 3 > /proc/sys/vm/drop_caches && free");

    // create workers
    for (i=0;i<n;++i){
        args[i].tid = i;
        args[i].nthreads = n;
        args[i].writer = (((size_t)i<nwriters)?(1):(0));
        args[i].ndocs = ndocs;
        args[i].doc = doc;
        args[i].time_sec = time_sec;
        args[i].nbatch = nbatch;
        args[i].compact_term = compact_term;
        args[i].n_opened = &n_opened;
        args[i].filename_count = &filename_count;
        args[i].filename_count_lock = &filename_count_lock;
        args[i].config = &fconfig;
        args[i].kvs_config = &kvs_config;
        thread_create(&tid[i], _worker_thread, &args[i]);
    }

    printf("wait for %d seconds..\n", (int)time_sec);

    // wait for thread termination
    for (i=0;i<n;++i){
        thread_join(tid[i], &thread_ret[i]);
    }

    // free all documents
    for (i=0;(size_t)i<ndocs;++i){
        fdb_doc_free(doc[i]);
    }

    nwrites = nreads = 0;
    for (i=0;i<n;++i){
        if (args[i].writer) {
            nwrites += args[i].nops;
        } else {
            nreads += args[i].nops;
        }
    }
    printf("read: %.1f ops/sec\n", (double)nreads/time_sec);
    printf("write: %.1f ops/sec\n", (double)nwrites/time_sec);

    // check sequence number
    sprintf(temp, FILENAME"%d", filename_count);
    fdb_open(&dbfile, temp, &fconfig);
    fdb_kvs_open_default(dbfile, &db, &kvs_config);
    fdb_get_kvs_info(db, &kvs_info);
    TEST_CHK(kvs_info.last_seqnum == ndocs+nwrites);
    fdb_kvs_close(db);
    fdb_close(dbfile);

    // shutdown
    fdb_shutdown();

    memleak_end();

    TEST_RESULT("multi thread test");
}

void *multi_thread_client_shutdown(void *args)
{

    TEST_INIT();

    int i, r;
    int nclients;
    fdb_file_handle *tdbfile;
    fdb_status status;
    fdb_config fconfig;
    fdb_kvs_config kvs_config;
    thread_t *tid;
    void **thread_ret;

    if (args == NULL)
    { // parent
        memleak_start();

        r = system(SHELL_DEL" dummy* > errorlog.txt");
        (void)r;
        nclients = 2;
        tid = alca(thread_t, nclients);
        thread_ret = alca(void *, nclients);
        for (i=0;i<nclients;++i){
            thread_create(&tid[i], multi_thread_client_shutdown, (void *)&i);
        }
        for (i=0;i<nclients;++i){
            thread_join(tid[i], &thread_ret[i]);
        }

        memleak_end();
        TEST_RESULT("multi thread client shutdown");
        return NULL;
    }

    // threads enter here //

    fconfig = fdb_get_default_config();
    kvs_config = fdb_get_default_kvs_config();
    fconfig.wal_threshold = 1024;
    fconfig.compaction_threshold = 0;

    // open/close db
    status = fdb_open(&tdbfile, "./dummy1", &fconfig);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    TEST_CHK(fdb_close(tdbfile) == FDB_RESULT_SUCCESS);

    // shutdown
    fdb_shutdown();
    thread_exit(0);
    return NULL;
}

void *multi_thread_kvs_client(void *args)
{

    TEST_INIT();

    int i, j, r;
    int n = 50;
    int nclients = 20;
    int *tid_args = alca(int, nclients);
    char dbstr[256];
    char keybuf[256], metabuf[256], bodybuf[256];
    fdb_file_handle *dbfile;
    fdb_kvs_handle *tdb;
    fdb_kvs_handle **db = alca(fdb_kvs_handle*, nclients);
    fdb_doc **doc = alca(fdb_doc*, n);
    fdb_doc *rdoc = NULL;
    fdb_status status;
    fdb_config fconfig;
    fdb_kvs_config kvs_config;
    fdb_seqnum_t seqnum;
    thread_t *tid;
    void **thread_ret;

    if (args == NULL)
    { // parent
        memleak_start();

        r = system(SHELL_DEL" dummy* > errorlog.txt");
        (void)r;

        // init dbfile
        fconfig = fdb_get_default_config();
        fconfig.buffercache_size = 0;
        fconfig.wal_threshold = 1024;
        fconfig.compaction_threshold = 0;

        status = fdb_open(&dbfile, "./dummy1", &fconfig);
        TEST_CHK(status == FDB_RESULT_SUCCESS);

        tid = alca(thread_t, nclients);
        thread_ret = alca(void *, nclients);
        for (i=0;i<nclients;++i){
            sprintf(dbstr, "db%d", i);
            kvs_config = fdb_get_default_kvs_config();
            status = fdb_kvs_open(dbfile, &db[i], dbstr, &kvs_config);
            TEST_CHK(status == FDB_RESULT_SUCCESS);
            status = fdb_kvs_close(db[i]);
            TEST_CHK(status == FDB_RESULT_SUCCESS);
        }
        for (i=0;i<nclients;++i){
            tid_args[i] = i;
            thread_create(&tid[i], multi_thread_kvs_client,
                          (void *)&tid_args[i]);
        }
        for (i=0;i<nclients;++i){
            thread_join(tid[i], &thread_ret[i]);
        }

        status = fdb_commit(dbfile, FDB_COMMIT_NORMAL);
        TEST_CHK(status == FDB_RESULT_SUCCESS);

        // check threads updated kvs
        for (i=0; i<nclients; i++){
            sprintf(dbstr, "db%d", i);
            kvs_config = fdb_get_default_kvs_config();
            status = fdb_kvs_open(dbfile, &db[i], dbstr, &kvs_config);
            TEST_CHK(status == FDB_RESULT_SUCCESS);

            // verify seqnum
            status = fdb_get_kvs_seqnum(db[i], &seqnum);
            TEST_CHK(status == FDB_RESULT_SUCCESS);
            TEST_CHK(seqnum == (fdb_seqnum_t)n);

            for (j=0; j<n; j++){
                sprintf(keybuf, "key%d", j);
                sprintf(metabuf, "meta%d", j);
                sprintf(bodybuf, "body%d", j);
                fdb_doc_create(&rdoc, keybuf, strlen(keybuf),
                                      NULL, 0, NULL, 0);
                status = fdb_get(db[i], rdoc);
                TEST_CHK(status == FDB_RESULT_SUCCESS);
                TEST_CHK(!memcmp(rdoc->key, keybuf, strlen(keybuf)));
                TEST_CHK(!memcmp(rdoc->meta, metabuf, rdoc->metalen));
                TEST_CHK(!memcmp(rdoc->body, bodybuf, rdoc->bodylen));
                fdb_doc_free(rdoc);
            }
            status = fdb_kvs_close(db[i]);
            TEST_CHK(status == FDB_RESULT_SUCCESS);
        }

        status = fdb_close(dbfile);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        fdb_shutdown();
        memleak_end();
        TEST_RESULT("multi thread kvs client");
        return NULL;
    }

    // threads enter here //

    // open fhandle
    fconfig = fdb_get_default_config();
    status = fdb_open(&dbfile, "./dummy1", &fconfig);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // get kvs ID from args
    memcpy(&i, args, sizeof(int));
    sprintf(dbstr, "db%d", i);
    kvs_config = fdb_get_default_kvs_config();
    status = fdb_kvs_open(dbfile, &tdb, dbstr, &kvs_config);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // insert documents
    for (i=0;i<n;++i){
        sprintf(keybuf, "key%d", i);
        sprintf(metabuf, "meta%d", i);
        sprintf(bodybuf, "body%d", i);
        fdb_doc_create(&doc[i], (void*)keybuf, strlen(keybuf),
                                (void*)metabuf, strlen(metabuf),
                                (void*)bodybuf, strlen(bodybuf));
        status = fdb_set(tdb, doc[i]);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        fdb_doc_free(doc[i]);
    }
    status = fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    fdb_close(dbfile);
    return NULL;
}

void incomplete_block_test()
{
    TEST_INIT();

    memleak_start();

    int i, r;
    int n = 2;
    fdb_file_handle *dbfile;
    fdb_kvs_handle *db;
    fdb_doc **doc = alca(fdb_doc*, n);
    fdb_doc *rdoc = NULL;
    fdb_status status;

    char keybuf[256], metabuf[256], bodybuf[256];

    // remove previous dummy files
    r = system(SHELL_DEL" dummy* > errorlog.txt");
    (void)r;

    fdb_config fconfig = fdb_get_default_config();
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    fconfig.buffercache_size = 0;
    fconfig.wal_threshold = 1024;
    fconfig.flags = FDB_OPEN_FLAG_CREATE;
    fconfig.compaction_threshold = 0;

    // open db
    fdb_open(&dbfile, "./dummy1", &fconfig);
    fdb_kvs_open_default(dbfile, &db, &kvs_config);
    status = fdb_set_log_callback(db, logCallbackFunc,
                                  (void *) "incomplete_block_test");
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

    // retrieve documents
    for (i=0;i<n;++i){
        // search by key
        fdb_doc_create(&rdoc, doc[i]->key, doc[i]->keylen, NULL, 0, NULL, 0);
        status = fdb_get(db, rdoc);

        // updated documents
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        TEST_CMP(rdoc->meta, doc[i]->meta, rdoc->metalen);
        TEST_CMP(rdoc->body, doc[i]->body, rdoc->bodylen);

        // free result document
        fdb_doc_free(rdoc);
        rdoc = NULL;
    }

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

    TEST_RESULT("incomplete block test");
}


static int _cmp_double(void *key1, size_t keylen1, void *key2, size_t keylen2)
{
    double aa, bb;
    aa = *(double *)key1;
    bb = *(double *)key2;

    if (aa<bb) {
        return -1;
    } else if (aa>bb) {
        return 1;
    } else {
        return 0;
    }
}

void custom_compare_primitive_test()
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

    char keybuf[256], bodybuf[256];
    double key_double, key_double_prev;

    // remove previous dummy files
    r = system(SHELL_DEL" dummy* > errorlog.txt");
    (void)r;

    fdb_config fconfig = fdb_get_default_config();
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    fconfig.buffercache_size = 0;
    fconfig.wal_threshold = 1024;
    fconfig.flags = FDB_OPEN_FLAG_CREATE;
    fconfig.compaction_threshold = 0;
    fconfig.multi_kv_instances = true;

    kvs_config.custom_cmp = _cmp_double;

    // open db with custom compare function for double key type
    fdb_open(&dbfile, "./dummy1", &fconfig);
    fdb_kvs_open_default(dbfile, &db, &kvs_config);
    status = fdb_set_log_callback(db, logCallbackFunc,
                                  (void *) "custom_compare_primitive_test");
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    for (i=0;i<n;++i){
        key_double = 10000/(i*11.0);
        memcpy(keybuf, &key_double, sizeof(key_double));
        sprintf(bodybuf, "value: %d, %f", i, key_double);
        fdb_doc_create(&doc[i], (void*)keybuf, sizeof(key_double), NULL, 0,
            (void*)bodybuf, strlen(bodybuf)+1);
        fdb_set(db, doc[i]);
    }

    // range scan (before flushing WAL)
    fdb_iterator_init(db, &iterator, NULL, 0, NULL, 0, 0x0);
    key_double_prev = -1;
    do {
        status = fdb_iterator_get(iterator, &rdoc);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        memcpy(&key_double, rdoc->key, rdoc->keylen);
        TEST_CHK(key_double > key_double_prev);
        key_double_prev = key_double;
        fdb_doc_free(rdoc);
        rdoc = NULL;
    } while(fdb_iterator_next(iterator) != FDB_RESULT_ITERATOR_FAIL);
    fdb_iterator_close(iterator);

    fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);

    // range scan (after flushing WAL)
    fdb_iterator_init(db, &iterator, NULL, 0, NULL, 0, 0x0);
    key_double_prev = -1;
    do {
        status = fdb_iterator_get(iterator, &rdoc);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        memcpy(&key_double, rdoc->key, rdoc->keylen);
        TEST_CHK(key_double > key_double_prev);
        key_double_prev = key_double;
        fdb_doc_free(rdoc);
        rdoc = NULL;
    } while (fdb_iterator_next(iterator) != FDB_RESULT_ITERATOR_FAIL);
    fdb_iterator_close(iterator);

    // do compaction
    fdb_compact(dbfile, (char *) "./dummy2");

    // range scan (after compaction)
    fdb_iterator_init(db, &iterator, NULL, 0, NULL, 0, 0x0);
    key_double_prev = -1;
    do {
        status = fdb_iterator_get(iterator, &rdoc);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        memcpy(&key_double, rdoc->key, rdoc->keylen);
        TEST_CHK(key_double > key_double_prev);
        key_double_prev = key_double;
        fdb_doc_free(rdoc);
        rdoc = NULL;
    } while(fdb_iterator_next(iterator) != FDB_RESULT_ITERATOR_FAIL);
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

    TEST_RESULT("custom compare function for primitive key test");
}

static int _cmp_variable(void *key1, size_t keylen1, void *key2, size_t keylen2)
{
    // compare only 3rd~8th bytes (ignore the others)
    return memcmp((uint8_t*)key1+2, (uint8_t*)key2+2, 6);
}

void custom_compare_variable_test()
{
    TEST_INIT();

    memleak_start();

    int i, j, r;
    int n = 1000;
    int count;
    fdb_file_handle *dbfile;
    fdb_kvs_handle *db, *db2;
    fdb_doc **doc = alca(fdb_doc*, n);
    fdb_doc *rdoc = NULL;
    fdb_status status;
    fdb_iterator *iterator;

    size_t keylen = 16;
    size_t prev_keylen;
    char keybuf[256], bodybuf[256];
    char prev_key[256];

    // remove previous dummy files
    r = system(SHELL_DEL" dummy* > errorlog.txt");
    (void)r;

    fdb_config fconfig = fdb_get_default_config();
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    fconfig.buffercache_size = 0;
    fconfig.wal_threshold = 1024;
    fconfig.flags = FDB_OPEN_FLAG_CREATE;
    fconfig.compaction_threshold = 0;
    fconfig.multi_kv_instances = true;

    kvs_config.custom_cmp = _cmp_variable;

    // open db with custom compare function for variable length key type
    //fdb_open_cmp_variable(&dbfile, "./dummy1", &fconfig);
    fdb_open(&dbfile, "./dummy1", &fconfig);
    fdb_kvs_open_default(dbfile, &db, &kvs_config);
    status = fdb_set_log_callback(db, logCallbackFunc,
                                  (void *) "custom_compare_variable_test");
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    for (i=0;i<n;++i){
        for (j=0;j<2;++j){
            keybuf[j] = 'a' + rand()%('z'-'a');
        }
        sprintf(keybuf+2, "%06d", i);
        for (j=8;(size_t)j<keylen-1;++j){
            keybuf[j] = 'a' + rand()%('z'-'a');
        }
        keybuf[keylen-1] = 0;
        sprintf(bodybuf, "value: %d", i);
        fdb_doc_create(&doc[i], (void*)keybuf, keylen, NULL, 0,
            (void*)bodybuf, strlen(bodybuf)+1);
        fdb_set(db, doc[i]);
    }

    // point query
    for (i=0;i<n;++i){
        fdb_doc_create(&rdoc, doc[i]->key, doc[i]->keylen, NULL, 0, NULL, 0);
        status = fdb_get(db, rdoc);

        TEST_CHK(status == FDB_RESULT_SUCCESS);
        TEST_CHK(rdoc->bodylen == doc[i]->bodylen);
        TEST_CMP(rdoc->body, doc[i]->body, rdoc->bodylen);

        fdb_doc_free(rdoc);
        rdoc = NULL;
    }

    // range scan (before flushing WAL)
    fdb_iterator_init(db, &iterator, NULL, 0, NULL, 0, 0x0);
    sprintf(prev_key, "%016d", 0);
    count = 0;
    prev_keylen = 16;
    do {
        status = fdb_iterator_get(iterator, &rdoc);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        TEST_CHK(_cmp_variable(prev_key, prev_keylen, rdoc->key, rdoc->keylen) <= 0);
        prev_keylen = rdoc->keylen;
        memcpy(prev_key, rdoc->key, rdoc->keylen);
        fdb_doc_free(rdoc);
        rdoc = NULL;
        count++;
    } while (fdb_iterator_next(iterator) != FDB_RESULT_ITERATOR_FAIL);
    TEST_CHK(count == n);
    fdb_iterator_close(iterator);

    fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);

    // range scan (after flushing WAL)
    fdb_iterator_init(db, &iterator, NULL, 0, NULL, 0, 0x0);
    sprintf(prev_key, "%016d", 0);
    count = 0;
    prev_keylen = 16;
    do {
        status = fdb_iterator_get(iterator, &rdoc);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        TEST_CHK(_cmp_variable(prev_key, prev_keylen, rdoc->key, rdoc->keylen)
                 <= 0);
        prev_keylen = rdoc->keylen;
        memcpy(prev_key, rdoc->key, rdoc->keylen);
        fdb_doc_free(rdoc);
        rdoc = NULL;
        count++;
    } while (fdb_iterator_next(iterator) != FDB_RESULT_ITERATOR_FAIL);
    TEST_CHK(count == n);
    fdb_iterator_close(iterator);

    // do compaction
    fdb_compact(dbfile, (char *) "./dummy2");

    // range scan (after compaction)
    fdb_iterator_init(db, &iterator, NULL, 0, NULL, 0, 0x0);
    sprintf(prev_key, "%016d", 0);
    count = 0;
    prev_keylen = 16;
    do {
        status = fdb_iterator_get(iterator, &rdoc);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        TEST_CHK(_cmp_variable(prev_key, prev_keylen, rdoc->key, rdoc->keylen) <= 0);
        prev_keylen = rdoc->keylen;
        memcpy(prev_key, rdoc->key, rdoc->keylen);
        fdb_doc_free(rdoc);
        rdoc = NULL;
        count++;
    } while (fdb_iterator_next(iterator) != FDB_RESULT_ITERATOR_FAIL);
    TEST_CHK(count == n);
    fdb_iterator_close(iterator);

    // range scan by sequence
    fdb_iterator_sequence_init(db, &iterator, 0, 0, 0x0);
    count = 0;
    do { // forward
        status = fdb_iterator_get(iterator, &rdoc);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        fdb_doc_free(rdoc);
        rdoc = NULL;
        count++;
    } while (fdb_iterator_next(iterator) != FDB_RESULT_ITERATOR_FAIL);
    TEST_CHK(count == n);

    // Reverse direction
    for (; fdb_iterator_prev(iterator) != FDB_RESULT_ITERATOR_FAIL; --count) {
        status = fdb_iterator_get(iterator, &rdoc);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        fdb_doc_free(rdoc);
        rdoc = NULL;
    };
    TEST_CHK(count == 0);
    fdb_iterator_close(iterator);

    // open another handle
    kvs_config.custom_cmp = NULL;
    fdb_kvs_open_default(dbfile, &db2, &kvs_config);

    // point query
    for (i=0;i<n;++i){
        fdb_doc_create(&rdoc, doc[i]->key, doc[i]->keylen, NULL, 0, NULL, 0);
        status = fdb_get(db2, rdoc);

        TEST_CHK(status == FDB_RESULT_SUCCESS);
        TEST_CHK(rdoc->bodylen == doc[i]->bodylen);
        TEST_CMP(rdoc->body, doc[i]->body, rdoc->bodylen);

        fdb_doc_free(rdoc);
        rdoc = NULL;
    }

    // close db file
    fdb_kvs_close(db);
    fdb_kvs_close(db2);
    fdb_close(dbfile);

    // free all documents
    for (i=0;i<n;++i){
        fdb_doc_free(doc[i]);
    }

    // free all resources
    fdb_shutdown();

    memleak_end();

    TEST_RESULT("custom compare function for variable length key test");
}

/*
 * custom compare test with commit and compact
 *    eqkeys:  boolean to toggle whether bytes in
 *             comparision range are equal
 */
void custom_compare_commit_compact(bool eqkeys)
{
    TEST_INIT();

    memleak_start();

    int i, j, r;
    int count;
    int n = 10;
    static const int len = 1024;
    char keybuf[len];
    static const char *achar = "a";
    fdb_doc *rdoc = NULL;
    fdb_status status;
    fdb_file_handle *dbfile;
    fdb_kvs_handle *db;
    fdb_iterator *iterator;
    fdb_config fconfig = fdb_get_default_config();
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();

    // remove previous dummy files
    r = system(SHELL_DEL" dummy* > errorlog.txt");
    (void)r;

    fconfig.buffercache_size = 0;
    fconfig.wal_threshold = 1024;
    fconfig.flags = FDB_OPEN_FLAG_CREATE;
    fconfig.compaction_threshold = 0;
    fconfig.multi_kv_instances = true;

    kvs_config.custom_cmp = _cmp_variable;



    r = system(SHELL_DEL" dummy* > errorlog.txt");
    (void)r;


    // open db
    status = fdb_open(&dbfile, "./dummy1", &fconfig);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_kvs_open_default(dbfile, &db, &kvs_config);
    TEST_CHK(status == FDB_RESULT_SUCCESS);


    for (i=0;i<n;++i){
        if(eqkeys){
            sprintf(keybuf, "%d", i);
            for (j=1;j<len;++j) {
                keybuf[j] = *achar;
            }
        } else {
            sprintf(keybuf, "000%d", i);
            for (j=4;j<len;++j) {
                keybuf[j] = *achar;
            }
        }
        keybuf[len-1] = '\0';
        // set kv
        status = fdb_set_kv(db, keybuf, strlen(keybuf), NULL, 0);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
    }

    // compact pre & post commit
    fdb_compact(dbfile, NULL);
    fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);
    fdb_compact(dbfile, NULL);

    // scan after flush
    count = 0;
    fdb_iterator_init(db, &iterator, NULL, 0, NULL, 0, 0x0);
    do {
        status = fdb_iterator_get(iterator, &rdoc);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        fdb_doc_free(rdoc);
        rdoc = NULL;
        count++;
    } while (fdb_iterator_next(iterator) != FDB_RESULT_ITERATOR_FAIL);

    if (eqkeys) {
        // since the custom cmp function compares only 3rd~8th bytes,
        // all keys are identified as the same key.
        TEST_CHK(count == 1);
    } else {
        TEST_CHK(count == n);
    }

    fdb_iterator_close(iterator);

    fdb_close(dbfile);
    fdb_shutdown();

    memleak_end();
    TEST_RESULT("custom compare commit compact");

}

void custom_seqnum_test(bool multi_kv)
{
    TEST_INIT();

    memleak_start();

    int i, r;
    int n = 10;
    int num_kv = 4;
    fdb_file_handle *dbfile;
    fdb_kvs_handle **db = alca(fdb_kvs_handle*, num_kv);
    fdb_doc **doc = alca(fdb_doc*, n);
    fdb_doc real_doc;
    fdb_doc *rdoc = &real_doc;
    fdb_status status;
    fdb_iterator *iterator;

    char keybuf[256], bodybuf[256];
    memset(&real_doc, 0, sizeof(fdb_doc));
    real_doc.key = &keybuf;
    real_doc.body = &bodybuf;

    // remove previous dummy files
    r = system(SHELL_DEL" dummy* > errorlog.txt");
    (void)r;

    fdb_config fconfig = fdb_get_default_config();
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();

    fconfig.buffercache_size = 0;
    fconfig.wal_threshold = 1024;
    fconfig.flags = FDB_OPEN_FLAG_CREATE;
    fconfig.compaction_threshold = 0;
    fconfig.multi_kv_instances = multi_kv;
    r = 0;

    fdb_open(&dbfile, "./dummy1", &fconfig);
    if (multi_kv) {
        num_kv = 4;
        for (r = num_kv - 1; r >= 0; --r) {
            char tmp[16];
            sprintf(tmp, "kv%d", r);
            status = fdb_kvs_open(dbfile, &db[r], tmp, &kvs_config);
            TEST_CHK(status == FDB_RESULT_SUCCESS);
            status = fdb_set_log_callback(db[r], logCallbackFunc,
                                          (void *) "custom_seqnum_test");
            TEST_CHK(status == FDB_RESULT_SUCCESS);
        }
    } else {
        num_kv = 1;
        status = fdb_kvs_open_default(dbfile, &db[r], &kvs_config);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        status = fdb_set_log_callback(db[r], logCallbackFunc,
                (void *) "custom_seqnum_test");
        TEST_CHK(status == FDB_RESULT_SUCCESS);
    }

    for (i = 0; i < n/2; ++i){
        sprintf(keybuf, "key%d", i);
        sprintf(bodybuf, "body%d", i);
        fdb_doc_create(&doc[i], (void*)keybuf, strlen(keybuf) + 1, NULL, 0,
            (void*)bodybuf, strlen(bodybuf)+1);
        for (r = num_kv - 1; r >= 0; --r) {
            status = fdb_set(db[r], doc[i]);
            TEST_CHK(status == FDB_RESULT_SUCCESS);
        }
    }

    for (i = n/2; i < n; ++i){
        sprintf(keybuf, "key%d", i);
        sprintf(bodybuf, "body%d", i);
        fdb_doc_create(&doc[i], (void*)keybuf, strlen(keybuf) + 1, NULL, 0,
            (void*)bodybuf, strlen(bodybuf)+1);
        for (r = num_kv - 1; r >= 0; --r) {
            fdb_doc_set_seqnum(doc[i], (i+1)*2); // double seqnum instead of ++
            status = fdb_set(db[r], doc[i]);
            TEST_CHK(status == FDB_RESULT_SUCCESS);
        }
    }

    for (r = num_kv - 1; r >= 0; --r) {
        // range scan (before flushing WAL)
        fdb_iterator_init(db[r], &iterator, NULL, 0, NULL, 0, 0x0);
        i = 0;
        do {
            status = fdb_iterator_get(iterator, &rdoc);
            TEST_CHK(status == FDB_RESULT_SUCCESS);
            TEST_CMP(rdoc->key, doc[i]->key, rdoc->keylen);
            TEST_CMP(rdoc->body, doc[i]->body, rdoc->bodylen);
            ++i;
            if (i <= n/2) {
                TEST_CHK(rdoc->seqnum == (fdb_seqnum_t)i);
            } else {
                TEST_CHK(rdoc->seqnum == (fdb_seqnum_t)i*2);
            }
        } while(fdb_iterator_next(iterator) != FDB_RESULT_ITERATOR_FAIL);
        fdb_iterator_close(iterator);

        fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);
    }

    // do compaction
    fdb_compact(dbfile, (char *) "./dummy2");

    for (i = n/2; i < n; ++i){
        sprintf(keybuf, "key%d", i);
        for (r = num_kv - 1; r >= 0; --r) {
            rdoc->seqnum = (i + 1)*2;
            status = fdb_get_byseq(db[r], rdoc);
            TEST_CHK(status == FDB_RESULT_SUCCESS);
        }
    }

    fdb_close(dbfile);

    // free all documents
    for (i=0;i<n;++i){
        fdb_doc_free(doc[i]);
    }

    // free all resources
    fdb_shutdown();

    memleak_end();

    sprintf(bodybuf,"Custom sequence number test %s", multi_kv ?
            "multiple kv instances" : "single kv instance");
    TEST_RESULT(bodybuf);
}

void doc_compression_test()
{
    TEST_INIT();

    memleak_start();

    int i, r;
    int n = 10;
    int dummy_len = 32;
    fdb_file_handle *dbfile;
    fdb_kvs_handle *db;
    fdb_doc **doc = alca(fdb_doc*, n);
    fdb_doc *rdoc = NULL;
    fdb_status status;

    char keybuf[256], metabuf[256], bodybuf[256], temp[256];

    // remove previous dummy files
    r = system(SHELL_DEL" dummy* > errorlog.txt");
    (void)r;

    fdb_config fconfig = fdb_get_default_config();
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    fconfig.buffercache_size = 0;
    fconfig.wal_threshold = 1024;
    fconfig.flags = FDB_OPEN_FLAG_CREATE;
    fconfig.compress_document_body = true;
    fconfig.compaction_threshold = 0;
    fconfig.purging_interval = 1;

    // open db
    fdb_open(&dbfile, "./dummy1", &fconfig);
    fdb_kvs_open_default(dbfile, &db, &kvs_config);
    status = fdb_set_log_callback(db, logCallbackFunc,
                                  (void *) "doc_compression_test");
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // set dummy str
    memset(temp, 'a', dummy_len);
    temp[dummy_len]=0;

    // insert documents
    for (i=0;i<n;++i){
        sprintf(keybuf, "key%d", i);
        sprintf(metabuf, "meta%d", i);
        sprintf(bodybuf, "body%d_%s", i, temp);
        fdb_doc_create(&doc[i], (void*)keybuf, strlen(keybuf),
            (void*)metabuf, strlen(metabuf), (void*)bodybuf, strlen(bodybuf));
        fdb_set(db, doc[i]);
    }

    // remove document #5
    fdb_doc_create(&rdoc, doc[5]->key, doc[5]->keylen, doc[5]->meta, doc[5]->metalen, NULL, 0);
    status = fdb_del(db, rdoc);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    fdb_doc_free(rdoc);
    rdoc = NULL;

    // commit
    fdb_commit(dbfile, FDB_COMMIT_NORMAL);

    // close the db
    fdb_kvs_close(db);
    fdb_close(dbfile);

    // reopen
    fdb_open(&dbfile, "./dummy1", &fconfig);
    fdb_kvs_open_default(dbfile, &db, &kvs_config);
    status = fdb_set_log_callback(db, logCallbackFunc,
                                  (void *) "doc_compression_test");
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // update dummy str
    dummy_len = 64;
    memset(temp, 'b', dummy_len);
    temp[dummy_len]=0;

    // update document #0 and #1
    for (i=0;i<2;++i){
        sprintf(metabuf, "newmeta%d", i);
        sprintf(bodybuf, "newbody%d_%s", i, temp);
        fdb_doc_update(&doc[i], (void *)metabuf, strlen(metabuf),
            (void *)bodybuf, strlen(bodybuf));
        fdb_set(db, doc[i]);
    }

    // commit
    fdb_commit(dbfile, FDB_COMMIT_NORMAL);

    // retrieve documents
    for (i=0;i<n;++i){
        // search by key
        fdb_doc_create(&rdoc, doc[i]->key, doc[i]->keylen, NULL, 0, NULL, 0);
        status = fdb_get(db, rdoc);

        if (i != 5) {
            // updated documents
            TEST_CHK(status == FDB_RESULT_SUCCESS);
            TEST_CMP(rdoc->meta, doc[i]->meta, rdoc->metalen);
            TEST_CMP(rdoc->body, doc[i]->body, rdoc->bodylen);
        } else {
            // removed document
            TEST_CHK(status == FDB_RESULT_KEY_NOT_FOUND);
        }

        // free result document
        fdb_doc_free(rdoc);
        rdoc = NULL;
    }

    // do compaction
    fdb_compact(dbfile, (char *) "./dummy2");

    // retrieve documents after compaction
    for (i=0;i<n;++i){
        // search by key
        fdb_doc_create(&rdoc, doc[i]->key, doc[i]->keylen, NULL, 0, NULL, 0);
        status = fdb_get(db, rdoc);

        if (i != 5) {
            // updated documents
            TEST_CHK(status == FDB_RESULT_SUCCESS);
            TEST_CMP(rdoc->meta, doc[i]->meta, rdoc->metalen);
            TEST_CMP(rdoc->body, doc[i]->body, rdoc->bodylen);
        } else {
            // removed document
            TEST_CHK(status == FDB_RESULT_KEY_NOT_FOUND);
        }

        // free result document
        fdb_doc_free(rdoc);
        rdoc = NULL;
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

    TEST_RESULT("document compression test");
}

void read_doc_by_offset_test()
{
    TEST_INIT();
    memleak_start();

    int i, r;
    int n = 100;
    fdb_file_handle *dbfile;
    fdb_kvs_handle *db;
    fdb_doc **doc = alca(fdb_doc*, n);
    fdb_doc *rdoc, *rdoc1;
    fdb_status status;

    char keybuf[256], metabuf[256], bodybuf[256];

    // remove previous dummy files
    r = system(SHELL_DEL" dummy* > errorlog.txt");
    (void)r;

    fdb_config fconfig = fdb_get_default_config();
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    fconfig.buffercache_size = 0;
    fconfig.wal_threshold = 1024;
    fconfig.flags = FDB_OPEN_FLAG_CREATE;
    fconfig.purging_interval = 3600;
    fconfig.compaction_threshold = 0;

    // open db
    fdb_open(&dbfile, "./dummy1", &fconfig);
    fdb_kvs_open_default(dbfile, &db, &kvs_config);
    status = fdb_set_log_callback(db, logCallbackFunc,
                                  (void *) "read_doc_by_offset_test");
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
    fdb_commit(dbfile, FDB_COMMIT_NORMAL);

    // update documents from #0 to #49
    for (i=0;i<n/2;++i){
        sprintf(metabuf, "meta2%d", i);
        sprintf(bodybuf, "body2%d", i);
        fdb_doc_update(&doc[i], (void *)metabuf, strlen(metabuf),
            (void *)bodybuf, strlen(bodybuf));
        fdb_set(db, doc[i]);
    }

    // remove document #50
    fdb_doc_create(&rdoc, doc[50]->key, doc[50]->keylen, doc[50]->meta,
                   doc[50]->metalen, NULL, 0);
    status = fdb_del(db, rdoc);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    fdb_doc_free(rdoc);
    rdoc = NULL;

    // commit
    fdb_commit(dbfile, FDB_COMMIT_NORMAL);

    fdb_doc_create(&rdoc, doc[5]->key, doc[5]->keylen, NULL, 0, NULL, 0);
    status = fdb_get_metaonly(db, rdoc);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    TEST_CHK(rdoc->deleted == false);
    TEST_CMP(rdoc->meta, doc[5]->meta, rdoc->metalen);
    // Fetch #5 doc using its offset.
    status = fdb_get_byoffset(db, rdoc);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    TEST_CHK(rdoc->deleted == false);
    TEST_CMP(rdoc->meta, doc[5]->meta, rdoc->metalen);
    TEST_CMP(rdoc->body, doc[5]->body, rdoc->bodylen);

    // MB-13095
    fdb_doc_create(&rdoc1, NULL, 0, NULL, 0, NULL, 0);
    rdoc1->offset = rdoc->offset;
    status = fdb_get_byoffset(db, rdoc1);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    TEST_CMP(rdoc1->key, doc[5]->key, rdoc1->keylen);
    TEST_CMP(rdoc1->meta, doc[5]->meta, rdoc1->metalen);
    TEST_CMP(rdoc1->body, doc[5]->body, rdoc1->bodylen);

    fdb_doc_free(rdoc);
    rdoc = NULL;
    fdb_doc_free(rdoc1);

    // do compaction
    fdb_compact(dbfile, (char *) "./dummy2");

    fdb_doc_create(&rdoc, doc[50]->key, doc[50]->keylen, NULL, 0, NULL, 0);
    status = fdb_get_metaonly(db, rdoc);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    TEST_CHK(rdoc->deleted == true);
    TEST_CMP(rdoc->meta, doc[50]->meta, rdoc->metalen);
    // Fetch #50 doc using its offset.
    status = fdb_get_byoffset(db, rdoc);
    TEST_CHK(status == FDB_RESULT_KEY_NOT_FOUND);
    TEST_CHK(rdoc->deleted == true);
    fdb_doc_free(rdoc);
    rdoc = NULL;

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

    TEST_RESULT("read_doc_by_offset test");
}

void purge_logically_deleted_doc_test()
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

    char keybuf[256], metabuf[256], bodybuf[256];

    // remove previous dummy files
    r = system(SHELL_DEL" dummy* fdb_test_config.json > errorlog.txt");
    (void)r;

    fdb_config fconfig = fdb_get_default_config();
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    fconfig.buffercache_size = 0;
    fconfig.wal_threshold = 1024;
    fconfig.flags = FDB_OPEN_FLAG_CREATE;
    fconfig.purging_interval = 2;
    fconfig.compaction_threshold = 0;

    // open db
    fdb_open(&dbfile, "./dummy1", &fconfig);
    fdb_kvs_open_default(dbfile, &db, &kvs_config);
    status = fdb_set_log_callback(db, logCallbackFunc,
                                  (void *) "purge_logically_deleted_doc_test");
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

    // remove document #5
    fdb_doc_create(&rdoc, doc[5]->key, doc[5]->keylen, doc[5]->meta, doc[5]->metalen, NULL, 0);
    status = fdb_del(db, rdoc);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    fdb_doc_free(rdoc);
    rdoc = NULL;

    // commit
    fdb_commit(dbfile, FDB_COMMIT_NORMAL);

    // do compaction
    fdb_compact(dbfile, (char *) "./dummy2");

    // retrieve documents after compaction
    for (i=0;i<n;++i){
        // search by key
        fdb_doc_create(&rdoc, doc[i]->key, doc[i]->keylen, NULL, 0, NULL, 0);
        status = fdb_get(db, rdoc);

        if (i != 5) {
            // updated documents
            TEST_CHK(status == FDB_RESULT_SUCCESS);
            TEST_CMP(rdoc->meta, doc[i]->meta, rdoc->metalen);
            TEST_CMP(rdoc->body, doc[i]->body, rdoc->bodylen);
        } else {
            // removed document
            TEST_CHK(status == FDB_RESULT_KEY_NOT_FOUND);
        }
        // free result document
        fdb_doc_free(rdoc);
        rdoc = NULL;

        // retrieve metadata
        fdb_doc_create(&rdoc, doc[i]->key, doc[i]->keylen, NULL, 0, NULL, 0);
        status = fdb_get_metaonly(db, rdoc);
        if (i != 5) {
            TEST_CHK(status == FDB_RESULT_SUCCESS);
        } else {
            // If the above compaction takes longer than two secs (e.g., slow disk),
            // then, fdb_get_metaonly will return KEY_NOT_FOUND error.
            TEST_CHK(status == FDB_RESULT_SUCCESS ||
                     status == FDB_RESULT_KEY_NOT_FOUND);
        }
        fdb_doc_free(rdoc);
        rdoc = NULL;
    }

    printf("wait for 3 seconds..\n");
    sleep(3);

    // do one more compaction
    fdb_compact(dbfile, (char *) "./dummy3");

    // retrieve documents after compaction
    for (i=0;i<n;++i){
        // search by key
        fdb_doc_create(&rdoc, doc[i]->key, doc[i]->keylen, NULL, 0, NULL, 0);
        status = fdb_get(db, rdoc);

        if (i != 5) {
            // updated documents
            TEST_CHK(status == FDB_RESULT_SUCCESS);
            TEST_CMP(rdoc->meta, doc[i]->meta, rdoc->metalen);
            TEST_CMP(rdoc->body, doc[i]->body, rdoc->bodylen);
        } else {
            // removed document
            TEST_CHK(status == FDB_RESULT_KEY_NOT_FOUND);
        }
        // free result document
        fdb_doc_free(rdoc);
        rdoc = NULL;

        // retrieve metadata
        fdb_doc_create(&rdoc, doc[i]->key, doc[i]->keylen, NULL, 0, NULL, 0);
        status = fdb_get_metaonly(db, rdoc);
        if (i != 5) {
            TEST_CHK(status == FDB_RESULT_SUCCESS);
        } else {
            // logically deletec document must be purged during the compaction
            TEST_CHK(status == FDB_RESULT_KEY_NOT_FOUND);
        }
        fdb_doc_free(rdoc);
        rdoc = NULL;
    }

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

    TEST_RESULT("purge logically deleted doc test");
}

void api_wrapper_test()
{
    TEST_INIT();

    memleak_start();

    int i, r;
    int n = 10;
    size_t valuelen;
    void *value;
    fdb_file_handle *dbfile;
    fdb_kvs_handle *db;
    fdb_status status;

    char keybuf[256], bodybuf[256], temp[256];

    // remove previous dummy files
    r = system(SHELL_DEL" dummy* > errorlog.txt");
    (void)r;

    fdb_config fconfig = fdb_get_default_config();
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    fconfig.buffercache_size = 0;
    fconfig.wal_threshold = 1024;
    fconfig.flags = FDB_OPEN_FLAG_CREATE;
    fconfig.purging_interval = 0;
    fconfig.compaction_threshold = 0;

    // open db
    fdb_open(&dbfile, "./dummy1", &fconfig);
    fdb_kvs_open_default(dbfile, &db, &kvs_config);
    status = fdb_set_log_callback(db, logCallbackFunc,
                                  (void *) "api_wrapper_test");
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // error check
    status = fdb_set_kv(db, NULL, 0, NULL, 0);
    TEST_CHK(status == FDB_RESULT_INVALID_ARGS);

    // insert key-value pairs
    for (i=0;i<n;++i){
        sprintf(keybuf, "key%d", i);
        sprintf(bodybuf, "body%d", i);
        status = fdb_set_kv(db, keybuf, strlen(keybuf), bodybuf, strlen(bodybuf));
        TEST_CHK(status == FDB_RESULT_SUCCESS);
    }

    // remove key5
    sprintf(keybuf, "key%d", 5);
    status = fdb_del_kv(db, keybuf, strlen(keybuf));
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // error check
    status = fdb_del_kv(db, NULL, 0);
    TEST_CHK(status == FDB_RESULT_INVALID_ARGS);

    // retrieve key-value pairs
    for (i=0;i<n;++i){
        sprintf(keybuf, "key%d", i);
        status = fdb_get_kv(db, keybuf, strlen(keybuf), &value, &valuelen);

        if (i != 5) {
            // updated documents
            TEST_CHK(status == FDB_RESULT_SUCCESS);
            sprintf(temp, "body%d", i);
            TEST_CMP(value, temp, valuelen);
            fdb_free_block(value);
        } else {
            // removed document
            TEST_CHK(status == FDB_RESULT_KEY_NOT_FOUND);
        }
    }

    // error check
    status = fdb_get_kv(db, NULL, 0, &value, &valuelen);
    TEST_CHK(status == FDB_RESULT_INVALID_ARGS);

    status = fdb_get_kv(db, keybuf, strlen(keybuf), NULL, NULL);
    TEST_CHK(status == FDB_RESULT_INVALID_ARGS);

    // close db file
    fdb_kvs_close(db);
    fdb_close(dbfile);

    // free all resources
    fdb_shutdown();

    memleak_end();

    TEST_RESULT("API wrapper test");
}


void flush_before_commit_test()
{
    TEST_INIT();

    memleak_start();

    int i, r;
    int n = 30;
    fdb_file_handle *dbfile, *dbfile_txn;
    fdb_kvs_handle *db, *db_txn;
    fdb_doc **doc = alca(fdb_doc*, n);
    fdb_status status;

    char keybuf[256], metabuf[256], bodybuf[256];

    // remove previous dummy files
    r = system(SHELL_DEL" dummy* > errorlog.txt");
    (void)r;

    fdb_config fconfig = fdb_get_default_config();
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    fconfig.buffercache_size = 0;
    fconfig.wal_threshold = 5;
    fconfig.flags = FDB_OPEN_FLAG_CREATE;
    fconfig.purging_interval = 0;
    fconfig.compaction_threshold = 0;
    fconfig.wal_flush_before_commit = true;

    // open db
    fdb_open(&dbfile, "dummy1", &fconfig);
    fdb_open(&dbfile_txn, "dummy1", &fconfig);
    fdb_kvs_open_default(dbfile, &db, &kvs_config);
    fdb_kvs_open_default(dbfile_txn, &db_txn, &kvs_config);
    status = fdb_set_log_callback(db_txn, logCallbackFunc,
                                  (void *) "flush_before_commit_test");
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // create docs
    for (i=0;i<n;++i){
        sprintf(keybuf, "key%d", i);
        sprintf(metabuf, "meta%d", i);
        sprintf(bodybuf, "body%d", i);
        fdb_doc_create(&doc[i], (void*)keybuf, strlen(keybuf),
                                (void*)metabuf, strlen(metabuf),
                                (void*)bodybuf, strlen(bodybuf));
    }

    // non-transactional commit first, transactional commit next
    fdb_begin_transaction(dbfile_txn, FDB_ISOLATION_READ_COMMITTED);
    for (i=0;i<2;++i){
        fdb_set(db, doc[i]);
    }
    fdb_commit(dbfile, FDB_COMMIT_NORMAL);
    for (i=0;i<2;++i){
        fdb_set(db_txn, doc[i]);
    }
    fdb_end_transaction(dbfile_txn, FDB_COMMIT_NORMAL);
    fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);

    // transactional commit first, non-transactional commit next
    fdb_begin_transaction(dbfile_txn, FDB_ISOLATION_READ_COMMITTED);
    for (i=0;i<2;++i){
        fdb_set(db_txn, doc[i]);
    }
    fdb_end_transaction(dbfile_txn, FDB_COMMIT_NORMAL);
    for (i=0;i<2;++i){
        fdb_set(db, doc[i]);
    }
    fdb_commit(dbfile, FDB_COMMIT_NORMAL);
    fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);

    // concurrent update (non-txn commit first, txn commit next)
    fdb_begin_transaction(dbfile_txn, FDB_ISOLATION_READ_COMMITTED);
    for (i=0;i<2;++i){
        fdb_set(db_txn, doc[i]);
    }
    for (i=0;i<2;++i){
        fdb_set(db, doc[i]);
    }
    fdb_commit(dbfile, FDB_COMMIT_NORMAL);
    fdb_end_transaction(dbfile_txn, FDB_COMMIT_NORMAL);
    fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);

    // concurrent update (txn commit first, non-txn commit next)
    fdb_begin_transaction(dbfile_txn, FDB_ISOLATION_READ_COMMITTED);
    for (i=0;i<2;++i){
        fdb_set(db, doc[i]);
    }
    for (i=0;i<2;++i){
        fdb_set(db_txn, doc[i]);
    }
    fdb_end_transaction(dbfile_txn, FDB_COMMIT_NORMAL);
    fdb_commit(dbfile, FDB_COMMIT_NORMAL);
    fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);

    // begin transaction
    fdb_begin_transaction(dbfile_txn, FDB_ISOLATION_READ_COMMITTED);

    // insert docs using transaction
    for (i=0;i<10;++i){
        fdb_set(db_txn, doc[i]);
    }

    // insert docs without transaction
    for (i=10;i<20;++i){
        fdb_set(db, doc[i]);
    }

    // do compaction
    fdb_compact(dbfile, "dummy2");

    for (i=20;i<25;++i){
        fdb_set(db_txn, doc[i]);
    }
    // end transaction
    fdb_end_transaction(dbfile_txn, FDB_COMMIT_NORMAL);

    for (i=25;i<30;++i){
        fdb_set(db, doc[i]);
    }

    // close db file
    fdb_close(dbfile);
    fdb_close(dbfile_txn);

    // free all documents
    for (i=0;i<n;++i){
        fdb_doc_free(doc[i]);
    }

    // free all resources
    fdb_shutdown();

    memleak_end();

    TEST_RESULT("flush before commit test");
}

void flush_before_commit_multi_writers_test()
{
    TEST_INIT();

    memleak_start();

    int i, r;
    int n = 10;
    fdb_file_handle *dbfile1, *dbfile2;
    fdb_kvs_handle *db1, *db2;
    fdb_doc **doc = alca(fdb_doc*, n);
    fdb_doc *rdoc = NULL;
    fdb_status status;
    fdb_config fconfig;
    fdb_kvs_config kvs_config;

    char keybuf[256], metabuf[256], bodybuf[256];

    // remove previous dummy files
    r = system(SHELL_DEL" dummy* > errorlog.txt");
    (void)r;

    fconfig = fdb_get_default_config();
    fconfig.buffercache_size = 0;
    fconfig.wal_threshold = 8;
    fconfig.flags = FDB_OPEN_FLAG_CREATE;
    fconfig.purging_interval = 0;
    fconfig.compaction_threshold = 0;
    fconfig.wal_flush_before_commit = true;

    kvs_config = fdb_get_default_kvs_config();

    // open db
    fdb_open(&dbfile1, "dummy1", &fconfig);
    fdb_kvs_open(dbfile1, &db1, NULL, &kvs_config);

    // create & insert docs
    for (i=0;i<n;++i){
        sprintf(keybuf, "key%d", i);
        sprintf(metabuf, "meta%d", i);
        sprintf(bodybuf, "body%d", i);
        fdb_doc_create(&doc[i], (void*)keybuf, strlen(keybuf),
                                (void*)metabuf, strlen(metabuf),
                                (void*)bodybuf, strlen(bodybuf));
        fdb_set(db1, doc[i]);
    }
    fdb_commit(dbfile1, FDB_COMMIT_MANUAL_WAL_FLUSH);

    // open second writer
    fdb_open(&dbfile2, "dummy1", &fconfig);
    fdb_kvs_open(dbfile2, &db2, NULL, &kvs_config);

    for (i=0;i<n/2;++i){
        sprintf(metabuf, "meta2%d", i);
        sprintf(bodybuf, "body2%d(db2)", i);
        fdb_doc_update(&doc[i], (void *)metabuf, strlen(metabuf),
            (void *)bodybuf, strlen(bodybuf));
        fdb_set(db2, doc[i]);
    }
    for (i=n/2;i<n;++i){
        sprintf(metabuf, "meta2%d", i);
        sprintf(bodybuf, "body2%d(db1)", i);
        fdb_doc_update(&doc[i], (void *)metabuf, strlen(metabuf),
            (void *)bodybuf, strlen(bodybuf));
        fdb_set(db1, doc[i]);
    }

    // retrieve before commit
    for (i=0;i<n;++i){
        sprintf(keybuf, "key%d", i);
        sprintf(metabuf, "meta2%d", i);
        if (i < n/2) {
            sprintf(bodybuf, "body2%d(db2)", i);
        } else {
            sprintf(bodybuf, "body2%d(db1)", i);
        }
        // retrieve through db1
        fdb_doc_create(&rdoc, (void*)keybuf, strlen(keybuf),
                                NULL, 0, NULL, 0);
        status = fdb_get(db1, rdoc);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        TEST_CMP(metabuf, rdoc->meta, rdoc->metalen);
        TEST_CMP(bodybuf, rdoc->body, rdoc->bodylen);
        fdb_doc_free(rdoc);
        rdoc = NULL;

        // retrieve through db2
        fdb_doc_create(&rdoc, (void*)keybuf, strlen(keybuf),
                                NULL, 0, NULL, 0);
        status = fdb_get(db2, rdoc);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        TEST_CMP(metabuf, rdoc->meta, rdoc->metalen);
        TEST_CMP(bodybuf, rdoc->body, rdoc->bodylen);
        fdb_doc_free(rdoc);
        rdoc = NULL;
    }

    fdb_commit(dbfile1, FDB_COMMIT_NORMAL);
    fdb_commit(dbfile2, FDB_COMMIT_NORMAL);

    // retrieve after commit
    for (i=0;i<n;++i){
        sprintf(keybuf, "key%d", i);
        sprintf(metabuf, "meta2%d", i);
        if (i < n/2) {
            sprintf(bodybuf, "body2%d(db2)", i);
        } else {
            sprintf(bodybuf, "body2%d(db1)", i);
        }
        // retrieve through db1
        fdb_doc_create(&rdoc, (void*)keybuf, strlen(keybuf),
                                NULL, 0, NULL, 0);
        status = fdb_get(db1, rdoc);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        TEST_CMP(metabuf, rdoc->meta, rdoc->metalen);
        TEST_CMP(bodybuf, rdoc->body, rdoc->bodylen);
        fdb_doc_free(rdoc);
        rdoc = NULL;

        // retrieve through db2
        fdb_doc_create(&rdoc, (void*)keybuf, strlen(keybuf),
                                NULL, 0, NULL, 0);
        status = fdb_get(db2, rdoc);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        TEST_CMP(metabuf, rdoc->meta, rdoc->metalen);
        TEST_CMP(bodybuf, rdoc->body, rdoc->bodylen);
        fdb_doc_free(rdoc);
        rdoc = NULL;
    }

    // close db file
    fdb_close(dbfile1);
    fdb_close(dbfile2);

    // free all documents
    for (i=0;i<n;++i){
        fdb_doc_free(doc[i]);
    }

    // free all resources
    fdb_shutdown();

    memleak_end();

    TEST_RESULT("flush before commit with multi writers test");
}

void auto_commit_test()
{
    TEST_INIT();

    memleak_start();

    int i, r;
    int n = 5000;
    fdb_file_handle *dbfile;
    fdb_kvs_handle *db;
    fdb_status status;

    char key[256], value[256];
    void *value_out;
    size_t valuelen;

    // remove previous dummy files
    r = system(SHELL_DEL" dummy* > errorlog.txt");
    (void)r;

    fdb_config fconfig = fdb_get_default_config();
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    fconfig.buffercache_size = 0;
    fconfig.wal_threshold = 4096;
    fconfig.flags = FDB_OPEN_FLAG_CREATE;
    fconfig.durability_opt = FDB_DRB_ASYNC;
    fconfig.auto_commit = true;

    // open db
    status = fdb_open(&dbfile, "dummy1", &fconfig);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_kvs_open_default(dbfile, &db, &kvs_config);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // insert docs
    for (i=0;i<n;++i){
        sprintf(key, "key%d", i);
        sprintf(value, "body%d", i);
        status = fdb_set_kv(db, key, strlen(key)+1, value, strlen(value)+1);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
    }

    // retrieve check before close
    for (i=0;i<n;++i){
        sprintf(key, "key%d", i);
        sprintf(value, "body%d", i);
        status = fdb_get_kv(db, key, strlen(key)+1, &value_out, &valuelen);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        TEST_CMP(value_out, value, valuelen);
        fdb_free_block(value_out);
    }

    // close & reopen
    status = fdb_close(dbfile);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_open(&dbfile, "dummy1", &fconfig);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_kvs_open_default(dbfile, &db, &kvs_config);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // retrieve check again
    for (i=0;i<n;++i){
        sprintf(key, "key%d", i);
        sprintf(value, "body%d", i);
        status = fdb_get_kv(db, key, strlen(key)+1, &value_out, &valuelen);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        TEST_CMP(value_out, value, valuelen);
        fdb_free_block(value_out);
    }

    // free all resources
    status = fdb_close(dbfile);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    fdb_shutdown();

    memleak_end();

    TEST_RESULT("auto commit test");
}

void last_wal_flush_header_test()
{
    TEST_INIT();

    memleak_start();

    int i, r;
    int n = 30;
    fdb_file_handle *dbfile, *dbfile_txn1, *dbfile_txn2;
    fdb_kvs_handle *db, *db_txn1, *db_txn2;
    fdb_doc **doc = alca(fdb_doc*, n);
    fdb_doc *rdoc = NULL;
    fdb_status status;

    char keybuf[256], metabuf[256], bodybuf[256];

    // remove previous dummy files
    r = system(SHELL_DEL" dummy* > errorlog.txt");
    (void)r;

    fdb_config fconfig = fdb_get_default_config();
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    fconfig.buffercache_size = 0;
    fconfig.flags = FDB_OPEN_FLAG_CREATE;
    fconfig.purging_interval = 0;
    fconfig.compaction_threshold = 0;

    // open db
    fdb_open(&dbfile, "dummy1", &fconfig);
    fdb_open(&dbfile_txn1, "dummy1", &fconfig);
    fdb_kvs_open_default(dbfile, &db, &kvs_config);
    fdb_kvs_open_default(dbfile_txn1, &db_txn1, &kvs_config);

    // create docs
    for (i=0;i<n;++i){
        sprintf(keybuf, "key%d", i);
        sprintf(metabuf, "meta%d", i);
        sprintf(bodybuf, "body%d", i);
        fdb_doc_create(&doc[i], (void*)keybuf, strlen(keybuf),
                                (void*)metabuf, strlen(metabuf),
                                (void*)bodybuf, strlen(bodybuf));
    }

    // insert docs without transaction
    for (i=0;i<2;++i) {
        fdb_set(db, doc[i]);
    }
    // insert docs using transaction
    fdb_begin_transaction(dbfile_txn1, FDB_ISOLATION_READ_COMMITTED);
    for (i=2;i<4;++i){
        fdb_set(db_txn1, doc[i]);
    }
    // commit without transaction
    fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);

    // close & reopen db
    fdb_close(dbfile);
    fdb_close(dbfile_txn1);
    fdb_open(&dbfile, "dummy1", &fconfig);
    fdb_open(&dbfile_txn1, "dummy1", &fconfig);
    fdb_kvs_open_default(dbfile, &db, &kvs_config);
    fdb_kvs_open_default(dbfile_txn1, &db_txn1, &kvs_config);

    // retrieve check
    for (i=0;i<4;++i){
        fdb_doc_create(&rdoc, doc[i]->key, doc[i]->keylen, NULL, 0, NULL, 0);
        status = fdb_get(db, rdoc);
        if (i<2) {
            TEST_CHK(status == FDB_RESULT_SUCCESS);
        } else {
            TEST_CHK(status != FDB_RESULT_SUCCESS);
        }
        fdb_doc_free(rdoc);
        rdoc = NULL;
    }

    // insert docs using transaction
    fdb_begin_transaction(dbfile_txn1, FDB_ISOLATION_READ_COMMITTED);
    for (i=2;i<4;++i){
        fdb_set(db_txn1, doc[i]);
    }
    // insert docs without transaction
    for (i=4;i<6;++i){
        fdb_set(db, doc[i]);
    }
    fdb_end_transaction(dbfile_txn1, FDB_COMMIT_MANUAL_WAL_FLUSH);

    // close & reopen db
    fdb_close(dbfile);
    fdb_close(dbfile_txn1);
    fdb_open(&dbfile, "dummy1", &fconfig);
    fdb_open(&dbfile_txn1, "dummy1", &fconfig);
    fdb_kvs_open_default(dbfile, &db, &kvs_config);
    fdb_kvs_open_default(dbfile_txn1, &db_txn1, &kvs_config);

    // retrieve check
    for (i=0;i<6;++i){
        fdb_doc_create(&rdoc, doc[i]->key, doc[i]->keylen, NULL, 0, NULL, 0);
        status = fdb_get(db, rdoc);
        if (i<4) {
            TEST_CHK(status == FDB_RESULT_SUCCESS);
        } else {
            // doesn't matter
        }
        fdb_doc_free(rdoc);
        rdoc = NULL;
    }

    // insert docs without transaction
    for (i=4;i<6;++i) {
        fdb_set(db, doc[i]);
    }
    fdb_begin_transaction(dbfile_txn1, FDB_ISOLATION_READ_COMMITTED);
    for (i=6;i<8;++i) {
        fdb_set(db_txn1, doc[i]);
    }
    fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);

    // begin another transaction
    fdb_open(&dbfile_txn2, "dummy1", &fconfig);
    fdb_kvs_open_default(dbfile_txn2, &db_txn2, &kvs_config);
    fdb_begin_transaction(dbfile_txn2, FDB_ISOLATION_READ_COMMITTED);
    for (i=8;i<10;++i){
        fdb_set(db_txn2, doc[i]);
    }
    fdb_end_transaction(dbfile_txn2, FDB_COMMIT_MANUAL_WAL_FLUSH);

    // close & reopen db
    fdb_close(dbfile);
    fdb_close(dbfile_txn1);
    fdb_close(dbfile_txn2);
    fdb_open(&dbfile, "dummy1", &fconfig);
    fdb_kvs_open_default(dbfile, &db, &kvs_config);

    // retrieve check
    for (i=0;i<10;++i){
        fdb_doc_create(&rdoc, doc[i]->key, doc[i]->keylen, NULL, 0, NULL, 0);
        status = fdb_get(db, rdoc);
        if (i<6 || i>=8) {
            TEST_CHK(status == FDB_RESULT_SUCCESS);
        } else {
            TEST_CHK(status != FDB_RESULT_SUCCESS);
        }
        fdb_doc_free(rdoc);
        rdoc = NULL;
    }

    fdb_open(&dbfile_txn1, "dummy1", &fconfig);
    fdb_open(&dbfile_txn2, "dummy1", &fconfig);
    fdb_kvs_open_default(dbfile_txn1, &db_txn1, &kvs_config);
    fdb_kvs_open_default(dbfile_txn2, &db_txn2, &kvs_config);
    fdb_begin_transaction(dbfile_txn1, FDB_ISOLATION_READ_COMMITTED);

    fdb_set(db, doc[10]);
    fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);

    fdb_set(db, doc[11]);
    fdb_set(db_txn1, doc[12]);
    fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);

    fdb_set(db_txn1, doc[13]);
    fdb_begin_transaction(dbfile_txn2, FDB_ISOLATION_READ_COMMITTED);
    fdb_set(db_txn2, doc[14]);
    fdb_end_transaction(dbfile_txn1, FDB_COMMIT_MANUAL_WAL_FLUSH);

    fdb_set(db_txn2, doc[15]);
    fdb_set(db, doc[16]);
    fdb_end_transaction(dbfile_txn2, FDB_COMMIT_MANUAL_WAL_FLUSH);

    fdb_set(db, doc[17]);
    fdb_commit(dbfile, FDB_COMMIT_NORMAL);

    fdb_close(dbfile);
    fdb_close(dbfile_txn1);
    fdb_close(dbfile_txn2);
    fdb_open(&dbfile, "dummy1", &fconfig);
    fdb_kvs_open_default(dbfile, &db, &kvs_config);

    // retrieve check
    for (i=10;i<18;++i){
        fdb_doc_create(&rdoc, doc[i]->key, doc[i]->keylen, NULL, 0, NULL, 0);
        status = fdb_get(db, rdoc);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        fdb_doc_free(rdoc);
        rdoc = NULL;
    }

    fdb_open(&dbfile_txn1, "dummy1", &fconfig);
    fdb_kvs_open_default(dbfile_txn1, &db_txn1, &kvs_config);
    fdb_begin_transaction(dbfile_txn1, FDB_ISOLATION_READ_COMMITTED);
    fdb_set(db_txn1, doc[20]);

    fdb_compact(dbfile, "dummy2");

    fdb_end_transaction(dbfile_txn1, FDB_COMMIT_MANUAL_WAL_FLUSH);
    fdb_close(dbfile);
    fdb_close(dbfile_txn1);

    // free all documents
    for (i=0;i<n;++i){
        fdb_doc_free(doc[i]);
    }

    // free all resources
    fdb_shutdown();

    memleak_end();

    TEST_RESULT("last wal flush header test");
}

void long_key_test()
{
    TEST_INIT();
    memleak_start();

    int i, j, k, idx, r;
    int l=3, n=100, m=10;// l: # length groups, n: # prefixes, m: # postfixes
    int keylen_limit;
    fdb_file_handle *dbfile;
    fdb_kvs_handle *db;
    fdb_doc **doc = alca(fdb_doc*, l*n*m);
    fdb_doc *rdoc = NULL;
    fdb_status status;
    fdb_file_info info;

    char *keybuf;
    char metabuf[256], bodybuf[256], temp[256];

    // remove previous dummy files
    r = system(SHELL_DEL " dummy* > errorlog.txt");
    (void)r;

    fdb_config fconfig = fdb_get_default_config();
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    fconfig.flags = FDB_OPEN_FLAG_CREATE;
    fconfig.purging_interval = 0;
    fconfig.compaction_threshold = 0;
    fconfig.durability_opt = FDB_DRB_ASYNC;

    keybuf = alca(char, FDB_MAX_KEYLEN);

    // open db
    fdb_open(&dbfile, "dummy1", &fconfig);
    fdb_kvs_open_default(dbfile, &db, &kvs_config);

    // key structure:
    // <------------ <keylen_limit> bytes ------------->
    // <-- 8 bytes -->             <-- 8 bytes  -->< 1 >
    // [prefix number]____ ... ____[postfix number][ \0]
    // e.g.)
    // 00000001____ ... ____00000013[\0]

    // create docs
    for (k=0; k<l; ++k) {
        if (k == 0) {
            keylen_limit = 32768; // mid-length key
        } else if (k == 1) {
            keylen_limit = 8192; // short-length key
        } else {
            keylen_limit = FDB_MAX_KEYLEN; // max-length key
        }

        memset(keybuf, '_', keylen_limit-1);
        keybuf[keylen_limit-1] = 0;

        for (i=0;i<n;++i){
            // set prefix
            sprintf(temp, "%08d", i);
            memcpy(keybuf, temp, 8);
            for (j=0;j<m;++j){
                idx = k*n*m + i*m + j;
                // set postfix
                sprintf(temp, "%08d", j);
                memcpy(keybuf + (keylen_limit-1) - 8, temp, 8);
                sprintf(metabuf, "meta%d", idx);
                sprintf(bodybuf, "body%d", idx);
                fdb_doc_create(&doc[idx], (void*)keybuf, strlen(keybuf)+1,
                                          (void*)metabuf, strlen(metabuf)+1,
                                          (void*)bodybuf, strlen(bodybuf)+1);
            }
        }
    }

    // insert docs
    for (i=0;i<l*n*m;++i) {
        fdb_set(db, doc[i]);
    }
    fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);

    // doc count check
    fdb_get_file_info(dbfile, &info);
    TEST_CHK(info.doc_count == (size_t)l*n*m);

    // retrieval check
    for (i=0;i<l*n*m;++i){
        fdb_doc_create(&rdoc, doc[i]->key, doc[i]->keylen, NULL, 0, NULL, 0);
        status = fdb_get(db, rdoc);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        TEST_CMP(rdoc->key, doc[i]->key, rdoc->keylen);
        TEST_CMP(rdoc->meta, doc[i]->meta, rdoc->metalen);
        TEST_CMP(rdoc->body, doc[i]->body, rdoc->bodylen);
        fdb_doc_free(rdoc);
        rdoc = NULL;
    }

    fdb_close(dbfile);

    // free all documents
    for (i=0;i<l*n*m;++i){
        fdb_doc_free(doc[i]);
    }

    // free all resources
    fdb_shutdown();

    memleak_end();

    TEST_RESULT("long key test");
}

void open_multi_files_kvs_test()
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
    fdb_kvs_handle **snap_kvs = alca(fdb_kvs_handle*, n_files*n_kvs);
    fdb_iterator *iterator;
    fdb_doc *rdoc;
    fdb_kvs_info kvs_info;
    fdb_status status;

    // remove previous dummy test files
    r = system(SHELL_DEL" dummy* > errorlog.txt");
    (void)r;

    fdb_config fconfig = fdb_get_default_config();
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    fconfig.wal_threshold = 1024;
    fconfig.compaction_mode = FDB_COMPACTION_MANUAL;
    fconfig.durability_opt = FDB_DRB_ASYNC;

    // 1024 kvs via 128 per dbfile
    for(j=0;j<n_files;++j){
        sprintf(fname, "dummy%d", j);
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

    // snapshot 1 kvs per file
    for(i=0;i<vb;i+=n_kvs){
        fdb_get_kvs_info(kvs[i], &kvs_info);
        TEST_CHK(kvs_info.last_seqnum == (uint64_t)n);
        status = fdb_snapshot_open(kvs[i], &snap_kvs[i], kvs_info.last_seqnum);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
    }

    // compact default
    for(j=0;j<n_files;++j){
        status = fdb_compact(dbfiles[j], NULL);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
    }

    // iterate over snapshots
    rdoc = NULL;
    for(i=0;i<vb;i+=n_kvs){
        j=0;
        fdb_iterator_init(snap_kvs[i], &iterator, NULL, 0, NULL, 0, FDB_ITR_NONE);
        do {
            // verify keys
            status = fdb_iterator_get(iterator, &rdoc);
            TEST_CHK(status == FDB_RESULT_SUCCESS);
            sprintf(keybuf, "key%08d", j);
            TEST_CHK(!strcmp(keybuf, (char *)rdoc->key));
            j++;
        } while(fdb_iterator_next(iterator) != FDB_RESULT_ITERATOR_FAIL);
        fdb_iterator_close(iterator);
    }
    fdb_doc_free(rdoc);

    // delete all keys
    vb = n_files*n_kvs;
    for(i=0;i<vb;++i){
        for(j=0;j<n;++j){
            sprintf(keybuf, "key%08d", j);
            status = fdb_del_kv(kvs[i], keybuf, strlen(keybuf)+1);
            TEST_CHK(status == FDB_RESULT_SUCCESS);
        }
    }


    // custom compact
    for(j=0;j<n_files;++j){
        sprintf(fname, "dummy_compact%d", j);
        status = fdb_compact(dbfiles[j], fname);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
    }

    // iterate again over actual kvs with no deletes
    rdoc = NULL;
    for(i=0;i<vb;i+=n_kvs){
        status = fdb_iterator_init(kvs[i], &iterator, NULL, 0, NULL, 0, FDB_ITR_NO_DELETES);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        do {
            // verify keys
            status = fdb_iterator_get(iterator, &rdoc);
            TEST_CHK(status != FDB_RESULT_SUCCESS);
        } while(fdb_iterator_next(iterator) != FDB_RESULT_ITERATOR_FAIL);
        fdb_iterator_close(iterator);
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

void get_byoffset_diff_kvs_test()
{
    TEST_INIT();
    memleak_start();
    int r;
    uint64_t offset2;
    fdb_file_handle *dbfile;
    fdb_kvs_handle *db, *db2;
    fdb_doc *rdoc;
    fdb_status status;
    char keybuf[256], bodybuf[256];

    // remove previous dummy test files
    r = system(SHELL_DEL" dummy* > errorlog.txt");
    (void)r;

    fdb_config fconfig = fdb_get_default_config();
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();

    status = fdb_open(&dbfile, "./dummy1", &fconfig);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_kvs_open(dbfile, &db, "db", &kvs_config);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_kvs_open(dbfile, &db2, "db2", &kvs_config);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    sprintf(keybuf, "key%d", 0);
    sprintf(bodybuf, "body%d", 0);
    fdb_doc_create(&rdoc, keybuf, strlen(keybuf), NULL, 0,
                   bodybuf, strlen(bodybuf)+1);

    // set kv
    status = fdb_set(db, rdoc);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // set kv2
    sprintf((char *)rdoc->body, "bOdy%d", 0);
    status = fdb_set(db2, rdoc);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // save offsets
    status = fdb_get_metaonly(db, rdoc);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_get_metaonly(db2, rdoc);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    offset2=rdoc->offset;

    // attempt to get key by offset belonging to different kvs
    rdoc->offset = offset2;
    status = fdb_get_byoffset(db, rdoc);
    TEST_CHK(status == FDB_RESULT_KEY_NOT_FOUND);

    fdb_close(dbfile);
    fdb_doc_free(rdoc);
    fdb_shutdown();
    memleak_end();
    TEST_RESULT("get byoffset diff kvs");
}


void rekey_test()
{
    TEST_INIT();

    memleak_start();

    int i, r;
    int n = 10;
    size_t valuelen;
    void *value;
    fdb_file_handle *dbfile;
    fdb_kvs_handle *db;
    fdb_status status;

    char keybuf[256], bodybuf[256], temp[256];

    // remove previous dummy files
    r = system(SHELL_DEL" dummy* > errorlog.txt");
    (void)r;

    fdb_config fconfig = fdb_get_default_config();
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    fconfig.wal_threshold = 1024;
    fconfig.flags = FDB_OPEN_FLAG_CREATE;
    fconfig.purging_interval = 0;
    fconfig.compaction_threshold = 0;

    fconfig.encryption_key.algorithm = -1; // Bogus encryption
    memset(fconfig.encryption_key.bytes, 0x42, sizeof(fconfig.encryption_key.bytes));

    // open db
    fdb_open(&dbfile, "./dummy1", &fconfig);
    fdb_kvs_open_default(dbfile, &db, &kvs_config);
    status = fdb_set_log_callback(db, logCallbackFunc,
                                  (void *) "api_wrapper_test");
    TEST_STATUS(status);

    // error check
    status = fdb_set_kv(db, NULL, 0, NULL, 0);
    TEST_CHK(status == FDB_RESULT_INVALID_ARGS);

    // insert key-value pairs
    for (i=0;i<n;++i){
        sprintf(keybuf, "key%d", i);
        sprintf(bodybuf, "body%d", i);
        status = fdb_set_kv(db, keybuf, strlen(keybuf), bodybuf, strlen(bodybuf));
        TEST_STATUS(status);
    }

    // change the encryption key:
    fdb_encryption_key new_key;
    new_key.algorithm = -1; // Bogus encryption
    memset(new_key.bytes, 0xBD, sizeof(new_key.bytes));
    strcpy((char*)new_key.bytes, "bar");

    status = fdb_rekey(dbfile, new_key);
    TEST_STATUS(status);

    // close db file
    fdb_kvs_close(db);
    fdb_close(dbfile);

    // reopen db
    fconfig.encryption_key = new_key;
    status = fdb_open(&dbfile, "./dummy1", &fconfig);
    TEST_STATUS(status);
    status = fdb_kvs_open_default(dbfile, &db, &kvs_config);
    TEST_STATUS(status);
    status = fdb_set_log_callback(db, logCallbackFunc,
                                  (void *) "api_wrapper_test");
    TEST_STATUS(status);

    // retrieve key-value pairs
    for (i=0;i<n;++i){
        sprintf(keybuf, "key%d", i);
        status = fdb_get_kv(db, keybuf, strlen(keybuf), &value, &valuelen);

        // updated documents
        TEST_STATUS(status);
        sprintf(temp, "body%d", i);
        TEST_CMP(value, temp, valuelen);
        fdb_free_block(value);
    }

    // close db file
    fdb_kvs_close(db);
    fdb_close(dbfile);

    // free all resources
    fdb_shutdown();

    memleak_end();

    TEST_RESULT("encryption rekey test");
}

int main(){
    basic_test();
    set_get_max_keylen();
    config_test();
    deleted_doc_get_api_test();
    deleted_doc_stat_test();
    complete_delete_test();
    set_get_meta_test();
    get_byoffset_diff_kvs_test();
#if !defined(WIN32) && !defined(_WIN32)
#ifndef _MSC_VER
    long_filename_test(); // temporarily disable until windows is fixed
#endif
#endif
    error_to_str_test();
    seq_tree_exception_test();
    wal_commit_test();
    incomplete_block_test();
    custom_compare_primitive_test();
    custom_compare_variable_test();
    custom_compare_commit_compact(false);
    custom_compare_commit_compact(true);
    custom_seqnum_test(true); // multi-kv
    custom_seqnum_test(false); // single kv mode
    db_close_and_remove();
    db_drop_test();
    db_destroy_test();
#if !defined(WIN32) && !defined(_WIN32)
#ifndef _MSC_VER
    db_destroy_test_full_path(); // only for non-windows
#endif
#endif
    doc_compression_test();
    read_doc_by_offset_test();
    api_wrapper_test();
    flush_before_commit_test();
    flush_before_commit_multi_writers_test();
    auto_commit_test();
    last_wal_flush_header_test();
    long_key_test();
    large_batch_write_no_commit_test();
    multi_thread_client_shutdown(NULL);
    multi_thread_kvs_client(NULL);
    purge_logically_deleted_doc_test();
    operational_stats_test(false);
    operational_stats_test(true);
    multi_thread_test(40*1024, 1024, 20, 1, 100, 2, 6);
    open_multi_files_kvs_test();
    rekey_test();

    return 0;
}
