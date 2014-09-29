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

void _set_random_string(char *str, int len)
{
    str[len--] = 0;
    do {
        str[len] = '!' + random('~'-'!');
    } while(len--);
}

void _set_random_string_smallabt(char *str, int len)
{
    str[len--] = 0;
    do {
        str[len] = 'a' + random('z'-'a');
    } while(len--);
}

void logCallbackFunc(int err_code,
                     const char *err_msg,
                     void *pCtxData) {
    fprintf(stderr, "%s - error code: %d, error message: %s\n",
            (char *) pCtxData, err_code, err_msg);
}

void basic_test()
{
    TEST_INIT();

    memleak_start();

    int i, r;
    int n = 10;
    fdb_handle *db;
    fdb_handle *db_rdonly;
    fdb_doc **doc = alca(fdb_doc*, n);
    fdb_doc *rdoc;
    fdb_status status;

    char keybuf[256], metabuf[256], bodybuf[256], temp[256];

    // remove previous dummy files
    r = system(SHELL_DEL" dummy* > errorlog.txt");

    fdb_config fconfig = fdb_get_default_config();
    fconfig.wal_threshold = 1024;
    fconfig.compaction_threshold = 0;

    // Read-Write mode test without a create flag.
    fconfig.flags = 0;
    status = fdb_open(&db, "./dummy1", &fconfig);
    TEST_CHK(status == FDB_RESULT_NO_SUCH_FILE);

    // Read-Only mode test: Must not create new file.
    fconfig.flags = FDB_OPEN_FLAG_RDONLY;
    status = fdb_open(&db, "./dummy1", &fconfig);
    TEST_CHK(status == FDB_RESULT_NO_SUCH_FILE);

    // Read-Only and Create mode: Must not create a new file.
    fconfig.flags = FDB_OPEN_FLAG_RDONLY | FDB_OPEN_FLAG_CREATE;
    status = fdb_open(&db, "./dummy1", &fconfig);
    TEST_CHK(status == FDB_RESULT_INVALID_CONFIG);

    // open and close db with a create flag.
    fconfig.flags = FDB_OPEN_FLAG_CREATE;
    status = fdb_open(&db, "./dummy1", &fconfig);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    fdb_close(db);

    // reopen db
    fdb_open(&db, "./dummy1",&fconfig);
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

    // commit
    fdb_commit(db, FDB_COMMIT_NORMAL);

    // check the db info
    fdb_info info;
    fdb_get_dbinfo(db, &info);
    TEST_CHK(info.doc_count == 9);
    TEST_CHK(info.space_used > 0);

    fdb_doc_create(&rdoc, doc[5]->key, doc[5]->keylen, NULL, 0, NULL, 0);
    status = fdb_get_metaonly(db, rdoc);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    TEST_CHK(rdoc->deleted == true);
    TEST_CHK(!memcmp(rdoc->meta, doc[5]->meta, rdoc->metalen));
    fdb_doc_free(rdoc);

    // close the db
    fdb_close(db);

    // reopen
    fdb_open(&db, "./dummy1", &fconfig);
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
    fdb_commit(db, FDB_COMMIT_NORMAL);

    // retrieve documents
    for (i=0;i<n;++i){
        // search by key
        fdb_doc_create(&rdoc, doc[i]->key, doc[i]->keylen, NULL, 0, NULL, 0);
        status = fdb_get(db, rdoc);

        if (i != 5) {
            // updated documents
            TEST_CHK(status == FDB_RESULT_SUCCESS);
            TEST_CHK(!memcmp(rdoc->meta, doc[i]->meta, rdoc->metalen));
            TEST_CHK(!memcmp(rdoc->body, doc[i]->body, rdoc->bodylen));
        } else {
            // removed document
            TEST_CHK(status == FDB_RESULT_KEY_NOT_FOUND);
        }

        // free result document
        fdb_doc_free(rdoc);
    }

    // do compaction
    fdb_compact(db, (char *) "./dummy2");

    // retrieve documents after compaction
    for (i=0;i<n;++i){
        // search by key
        fdb_doc_create(&rdoc, doc[i]->key, doc[i]->keylen, NULL, 0, NULL, 0);
        status = fdb_get(db, rdoc);

        if (i != 5) {
            // updated documents
            TEST_CHK(status == FDB_RESULT_SUCCESS);
            TEST_CHK(!memcmp(rdoc->meta, doc[i]->meta, rdoc->metalen));
            TEST_CHK(!memcmp(rdoc->body, doc[i]->body, rdoc->bodylen));
        } else {
            // removed document
            TEST_CHK(status == FDB_RESULT_KEY_NOT_FOUND);
        }

        // free result document
        fdb_doc_free(rdoc);
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
    }

    // update document #5 with an empty doc body.
    fdb_doc_create(&rdoc, doc[5]->key, doc[5]->keylen, doc[5]->meta, doc[5]->metalen, NULL, 0);
    status = fdb_set(db, rdoc);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    fdb_doc_free(rdoc);
    fdb_commit(db, FDB_COMMIT_NORMAL);

    // Check document #5 with respect to metadata and doc body.
    fdb_doc_create(&rdoc, doc[5]->key, doc[5]->keylen, NULL, 0, NULL, 0);
    status = fdb_get(db, rdoc);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    TEST_CHK(memcmp(rdoc->meta, doc[5]->meta, rdoc->metalen) == 0);
    TEST_CHK(rdoc->body == NULL);
    TEST_CHK(rdoc->bodylen == 0);
    fdb_doc_free(rdoc);

    // Read-Only mode test: Open succeeds if file exists, but disallow writes
    fconfig.flags = FDB_OPEN_FLAG_RDONLY;
    status = fdb_open(&db_rdonly, "./dummy2", &fconfig);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    fdb_doc_create(&rdoc, doc[0]->key, doc[0]->keylen, NULL, 0, NULL, 0);
    status = fdb_get(db_rdonly, rdoc);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    status = fdb_set_log_callback(db_rdonly, logCallbackFunc,
                                  (void *) "basic_test");
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    status = fdb_set(db_rdonly, doc[i]);
    TEST_CHK(status == FDB_RESULT_RONLY_VIOLATION);

    status = fdb_commit(db_rdonly, FDB_COMMIT_NORMAL);
    TEST_CHK(status == FDB_RESULT_RONLY_VIOLATION);

    fdb_doc_free(rdoc);
    fdb_close(db_rdonly);

    // free all documents
    for (i=0;i<n;++i){
        fdb_doc_free(doc[i]);
    }

    // do one more compaction
    fdb_compact(db, (char *) "./dummy3");

    // close db file
    fdb_close(db);

    // free all resources
    fdb_shutdown();

    memleak_end();

    TEST_RESULT("basic test");
}

void long_filename_test()
{
    TEST_INIT();
    memleak_start();

    int i, j, r;
    int n=15, m=1000;
    char keyword[] = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    char filename[4096], cmd[4096], temp[4096];
    fdb_handle *db;
    fdb_config config;
    fdb_status s;
    size_t rvalue_len;
    char key[256], value[256];
    void *rvalue;

    config = fdb_get_default_config();
    sprintf(temp, SHELL_DMT"%s", keyword);

    // filename longer than 1024 bytes
    sprintf(filename, "%s", keyword);
    while (strlen(filename) < 1024) {
        strcat(filename, keyword);
    }
    s = fdb_open(&db, filename, &config);
    TEST_CHK(s == FDB_RESULT_TOO_LONG_FILENAME);

    // make nested directories for long path
    // but shorter than 1024 bytes (windows: 256 bytes)
    sprintf(cmd, SHELL_RMDIR" %s", keyword);
    r = system(cmd);
    for (i=0;i<n;++i) {
        sprintf(cmd, SHELL_MKDIR" %s", keyword);
        for (j=0;j<i;++j){
            strcat(cmd, temp);
        }
        if (strlen(cmd) > SHELL_MAX_PATHLEN) break;
        r = system(cmd);
    }

    // create DB file
    sprintf(filename, "%s", keyword);
    for (j=0;j<i-1;++j){
        strcat(filename, temp);
    }
    strcat(filename, SHELL_DMT"dbfile");
    s = fdb_open(&db, filename, &config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    // === write ===
    for (i=0;i<m;++i){
        sprintf(key, "key%08d", i);
        sprintf(value, "value%08d", i);
        s = fdb_set_kv(db, key, strlen(key)+1, value, strlen(value)+1);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
    }
    s = fdb_commit(db, FDB_COMMIT_NORMAL);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    // === read ===
    for (i=0;i<m;++i){
        sprintf(key, "key%08d", i);
        s = fdb_get_kv(db, key, strlen(key)+1, &rvalue, &rvalue_len);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        free(rvalue);
    }

    s = fdb_close(db);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_shutdown();

    sprintf(cmd, SHELL_RMDIR" %s", keyword);
    r = system(cmd);

    memleak_end();
    TEST_RESULT("long filename test");
}

void seq_tree_exception_test()
{
    TEST_INIT();

    memleak_start();

    int i, r;
    int n = 10;
    fdb_handle *db;
    fdb_doc **doc = alca(fdb_doc*, n);
    fdb_doc *rdoc;
    fdb_status status;
    fdb_iterator *it;

    char keybuf[256], metabuf[256], bodybuf[256], temp[256];

    // remove previous dummy files
    r = system(SHELL_DEL" dummy* > errorlog.txt");

    fdb_config fconfig = fdb_get_default_config();
    fconfig.seqtree_opt = FDB_SEQTREE_NOT_USE;

    // open db
    fdb_open(&db, "./dummy1", &fconfig);
    status = fdb_set_log_callback(db, logCallbackFunc,
                                  (void *) "seq_tree_exception_test");

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
    fdb_commit(db, FDB_COMMIT_NORMAL);

    // close the db
    fdb_close(db);

    // reopen with seq tree option
    fconfig.seqtree_opt = FDB_SEQTREE_USE;
    status = fdb_open(&db, "./dummy1", &fconfig);
    // must succeed
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_set_log_callback(db, logCallbackFunc,
                                  (void *) "seq_tree_exception_test");

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
    fdb_close(db);

    // free all documents
    free(rdoc);
    for (i=0;i<n;++i){
        fdb_doc_free(doc[i]);
    }

    // remove previous dummy files
    r = system(SHELL_DEL" dummy* > errorlog.txt");

    // open db
    fconfig.seqtree_opt = FDB_SEQTREE_USE;
    fdb_open(&db, "./dummy1", &fconfig);
    status = fdb_set_log_callback(db, logCallbackFunc,
                                  (void *) "seq_tree_exception_test");

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
    fdb_commit(db, FDB_COMMIT_NORMAL);

    // close the db
    fdb_close(db);

    // reopen with an option disabling seq tree
    fconfig.seqtree_opt = FDB_SEQTREE_NOT_USE;
    status = fdb_open(&db, "./dummy1", &fconfig);
    // must succeed
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_close(db);

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
    fdb_handle *db;
    fdb_doc **doc = alca(fdb_doc*, n);
    fdb_doc *rdoc;
    fdb_status status;

    char keybuf[256], metabuf[256], bodybuf[256], temp[256];

    // remove previous dummy files
    r = system(SHELL_DEL" dummy* > errorlog.txt");

    fdb_config fconfig = fdb_get_default_config();
    fconfig.buffercache_size = 0;
    fconfig.wal_threshold = 1024;
    fconfig.flags = FDB_OPEN_FLAG_CREATE;
    fconfig.compaction_threshold = 0;

    // open db
    fdb_open(&db, "./dummy1", &fconfig);
    status = fdb_set_log_callback(db, logCallbackFunc, (void *) "wal_commit_test");

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
    fdb_commit(db, FDB_COMMIT_NORMAL);

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
    fdb_close(db);

    // reopen
    fdb_open(&db, "./dummy1", &fconfig);
    status = fdb_set_log_callback(db, logCallbackFunc, (void *) "wal_commit_test");

    // retrieve documents
    for (i=0;i<n;++i){
        // search by key
        fdb_doc_create(&rdoc, doc[i]->key, doc[i]->keylen, NULL, 0, NULL, 0);
        status = fdb_get(db, rdoc);

        if (i < n/2) {
            // committed documents
            TEST_CHK(status == FDB_RESULT_SUCCESS);
            TEST_CHK(!memcmp(rdoc->meta, doc[i]->meta, rdoc->metalen));
            TEST_CHK(!memcmp(rdoc->body, doc[i]->body, rdoc->bodylen));
        } else {
            // not committed document
            TEST_CHK(status == FDB_RESULT_KEY_NOT_FOUND);
        }

        // free result document
        fdb_doc_free(rdoc);
    }

    // free all documents
    for (i=0;i<n;++i){
        fdb_doc_free(doc[i]);
    }

    // close db file
    fdb_close(db);

    // free all resources
    fdb_shutdown();

    memleak_end();

    TEST_RESULT("WAL commit test");
}

void multi_version_test()
{
    TEST_INIT();

    memleak_start();

    int i, r;
    int n = 2;
    fdb_handle *db;
    fdb_handle *db_new;
    fdb_doc **doc = alca(fdb_doc*, n);
    fdb_doc *rdoc;
    fdb_status status;

    char keybuf[256], metabuf[256], bodybuf[256], temp[256];

    // remove previous dummy files
    r = system(SHELL_DEL" dummy* > errorlog.txt");

    fdb_config fconfig = fdb_get_default_config();
    fconfig.buffercache_size = 1048576;
    fconfig.wal_threshold = 1024;
    fconfig.flags = FDB_OPEN_FLAG_CREATE;
    fconfig.compaction_threshold = 0;

    // open db
    fdb_open(&db, "./dummy1", &fconfig);
    status = fdb_set_log_callback(db, logCallbackFunc, (void *) "multi_version_test");

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
    fdb_commit(db, FDB_COMMIT_MANUAL_WAL_FLUSH);

    // open same db file using a new handle
    fdb_open(&db_new, "./dummy1", &fconfig);
    status = fdb_set_log_callback(db_new, logCallbackFunc, (void *) "multi_version_test");

    // update documents using the old handle
    for (i=0;i<n;++i){
        sprintf(metabuf, "meta2%d", i);
        sprintf(bodybuf, "body2%d", i);
        fdb_doc_update(&doc[i], (void*)metabuf, strlen(metabuf),
            (void*)bodybuf, strlen(bodybuf));
        fdb_set(db, doc[i]);
    }

    // manually flush WAL and commit using the old handle
    fdb_commit(db, FDB_COMMIT_MANUAL_WAL_FLUSH);

    // retrieve documents using the old handle
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

    // retrieve documents using the new handle
    for (i=0;i<n;++i){
        // search by key
        fdb_doc_create(&rdoc, doc[i]->key, doc[i]->keylen, NULL, 0, NULL, 0);
        status = fdb_get(db_new, rdoc);

        TEST_CHK(status == FDB_RESULT_SUCCESS);
        TEST_CHK(!memcmp(rdoc->meta, doc[i]->meta, rdoc->metalen));
        TEST_CHK(!memcmp(rdoc->body, doc[i]->body, rdoc->bodylen));

        // free result document
        fdb_doc_free(rdoc);
    }

    // close and re-open the new handle
    fdb_close(db_new);
    fdb_open(&db_new, "./dummy1", &fconfig);
    status = fdb_set_log_callback(db_new, logCallbackFunc, (void *) "multi_version_test");

    // retrieve documents using the new handle
    for (i=0;i<n;++i){
        // search by key
        fdb_doc_create(&rdoc, doc[i]->key, doc[i]->keylen, NULL, 0, NULL, 0);
        status = fdb_get(db_new, rdoc);

        TEST_CHK(status == FDB_RESULT_SUCCESS);
        // the new version of data should be read
        TEST_CHK(!memcmp(rdoc->meta, doc[i]->meta, rdoc->metalen));
        TEST_CHK(!memcmp(rdoc->body, doc[i]->body, rdoc->bodylen));

        // free result document
        fdb_doc_free(rdoc);
    }


    // free all documents
    for (i=0;i<n;++i){
        fdb_doc_free(doc[i]);
    }

    // close db file
    fdb_close(db);
    fdb_close(db_new);

    // free all resources
    fdb_shutdown();

    memleak_end();

    TEST_RESULT("multi version test");
}

void compact_wo_reopen_test()
{
    TEST_INIT();

    memleak_start();

    int i, r;
    int n = 3;
    fdb_handle *db;
    fdb_handle *db_new;
    fdb_doc **doc = alca(fdb_doc*, n);
    fdb_doc *rdoc;
    fdb_status status;

    char keybuf[256], metabuf[256], bodybuf[256], temp[256];

    // remove previous dummy files
    r = system(SHELL_DEL" dummy* > errorlog.txt");

    fdb_config fconfig = fdb_get_default_config();
    fconfig.buffercache_size = 16777216;
    fconfig.wal_threshold = 1024;
    fconfig.flags = FDB_OPEN_FLAG_CREATE;
    fconfig.compaction_threshold = 0;

    // open db
    fdb_open(&db, "./dummy1", &fconfig);
    status = fdb_set_log_callback(db, logCallbackFunc,
                                  (void *) "compact_wo_reopen_test");
    fdb_open(&db_new, "./dummy1", &fconfig);
    status = fdb_set_log_callback(db_new, logCallbackFunc,
                                  (void *) "compact_wo_reopen_test");

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
    fdb_commit(db, FDB_COMMIT_MANUAL_WAL_FLUSH);

    // perform compaction using one handle
    fdb_compact(db, (char *) "./dummy2");

    // retrieve documents using the other handle without close/re-open
    for (i=0;i<n;++i){
        // search by key
        fdb_doc_create(&rdoc, doc[i]->key, doc[i]->keylen, NULL, 0, NULL, 0);
        status = fdb_get(db_new, rdoc);

        if (i != 1) {
            TEST_CHK(status == FDB_RESULT_SUCCESS);
            TEST_CHK(!memcmp(rdoc->meta, doc[i]->meta, rdoc->metalen));
            TEST_CHK(!memcmp(rdoc->body, doc[i]->body, rdoc->bodylen));
        }else{
            TEST_CHK(status == FDB_RESULT_KEY_NOT_FOUND);
        }

        // free result document
        fdb_doc_free(rdoc);
    }
    // check the other handle's filename
    fdb_info info;
    fdb_get_dbinfo(db_new, &info);
    TEST_CHK(!strcmp("./dummy2", info.filename));

    // free all documents
    for (i=0;i<n;++i){
        fdb_doc_free(doc[i]);
    }

    // close db file
    fdb_close(db);
    fdb_close(db_new);

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
    fdb_handle *db;
    fdb_doc **doc = alca(fdb_doc*, n);
    fdb_doc *rdoc;
    fdb_status status;

    char keybuf[256], metabuf[256], bodybuf[256], temp[256];

    // remove previous dummy files
    r = system(SHELL_DEL" dummy* > errorlog.txt");

    fdb_config fconfig = fdb_get_default_config();
    fconfig.buffercache_size = 16777216;
    fconfig.wal_threshold = 1024;
    fconfig.flags = FDB_OPEN_FLAG_CREATE;
    fconfig.compaction_threshold = 0;

    // open db
    fdb_open(&db, "./dummy1", &fconfig);
    status = fdb_set_log_callback(db, logCallbackFunc,
                                  (void *) "compact_with_reopen_test");

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
    fdb_commit(db, FDB_COMMIT_MANUAL_WAL_FLUSH);

    // perform compaction using one handle
    fdb_compact(db, (char *) "./dummy2");

    // close db file
    fdb_close(db);

    r = system(SHELL_MOVE " dummy2 dummy1 > errorlog.txt");
    fdb_open(&db, "./dummy1", &fconfig);
    status = fdb_set_log_callback(db, logCallbackFunc,
                                  (void *) "compact_with_reopen_test");

    // retrieve documents using the other handle without close/re-open
    for (i=0;i<n;++i){
        // search by key
        fdb_doc_create(&rdoc, doc[i]->key, doc[i]->keylen, NULL, 0, NULL, 0);
        status = fdb_get(db, rdoc);

        if (i != 1) {
            TEST_CHK(status == FDB_RESULT_SUCCESS);
            TEST_CHK(!memcmp(rdoc->meta, doc[i]->meta, rdoc->metalen));
            TEST_CHK(!memcmp(rdoc->body, doc[i]->body, rdoc->bodylen));
        }else{
            TEST_CHK(status == FDB_RESULT_KEY_NOT_FOUND);
        }

        // free result document
        fdb_doc_free(rdoc);
    }
    // check the other handle's filename
    fdb_info info;
    fdb_get_dbinfo(db, &info);
    TEST_CHK(!strcmp("./dummy1", info.filename));

    // update documents
    for (i=0;i<n;++i){
        sprintf(metabuf, "newmeta%d", i);
        sprintf(bodybuf, "newbody%d_%s", i, temp);
        fdb_doc_update(&doc[i], (void *)metabuf, strlen(metabuf),
                       (void *)bodybuf, strlen(bodybuf));
        fdb_set(db, doc[i]);
    }

    // Open the database with another handle.
    fdb_handle *second_dbh;
    fdb_open(&second_dbh, "./dummy1", &fconfig);
    status = fdb_set_log_callback(second_dbh, logCallbackFunc,
                                  (void *) "compact_with_reopen_test");
    // In-place compaction
    fdb_compact(db, NULL);
    fdb_close(db);

    for (i=0;i<n;++i){
        // search by key
        fdb_doc_create(&rdoc, doc[i]->key, doc[i]->keylen, NULL, 0, NULL, 0);
        status = fdb_get(second_dbh, rdoc);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        TEST_CHK(!memcmp(rdoc->meta, doc[i]->meta, rdoc->metalen));
        TEST_CHK(!memcmp(rdoc->body, doc[i]->body, rdoc->bodylen));
        // free result document
        fdb_doc_free(rdoc);
    }

    // Open database with an original name.
    status = fdb_open(&db, "./dummy1", &fconfig);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_set_log_callback(db, logCallbackFunc,
                                  (void *) "compact_with_reopen_test");
    fdb_get_dbinfo(db, &info);
    // The actual file name should be a compacted one.
    TEST_CHK(!strcmp("./dummy1.1", info.filename));

    fdb_close(second_dbh);

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

    fdb_compact(db, NULL);
    fdb_close(db);

    r = system(SHELL_MOVE " dummy1 dummy.fdb > errorlog.txt");
    fdb_open(&db, "./dummy.fdb", &fconfig);
    status = fdb_set_log_callback(db, logCallbackFunc,
                                  (void *) "compact_with_reopen_test");
    // In-place compaction
    fdb_compact(db, NULL);
    fdb_close(db);
    // Open database with an original name.
    status = fdb_open(&db, "./dummy.fdb", &fconfig);
    status = fdb_set_log_callback(db, logCallbackFunc,
                                  (void *) "compact_with_reopen_test");
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    fdb_get_dbinfo(db, &info);
    TEST_CHK(!strcmp("./dummy.fdb", info.filename));
    TEST_CHK(info.doc_count == 100);

    // free all documents
    for (i=0;i<n;++i){
        fdb_doc_free(doc[i]);
    }

    fdb_close(db);

    // free all resources
    fdb_shutdown();

    memleak_end();

    TEST_RESULT("compaction with reopen test");
}

void auto_recover_compact_ok_test()
{
    TEST_INIT();

    memleak_start();

    int i, r;
    int n = 3;
    fdb_handle *db;
    fdb_handle *db_new;
    fdb_doc **doc = alca(fdb_doc *, n);
    fdb_doc *rdoc;
    fdb_status status;

    char keybuf[256], metabuf[256], bodybuf[256], temp[256];

    // remove previous dummy files
    r = system(SHELL_DEL " dummy* > errorlog.txt");

    fdb_config fconfig = fdb_get_default_config();
    fconfig.buffercache_size = 16777216;
    fconfig.wal_threshold = 1024;
    fconfig.flags = FDB_OPEN_FLAG_CREATE;
    fconfig.compaction_threshold = 0;

    // open db
    fdb_open(&db, "./dummy1", &fconfig);
    status = fdb_set_log_callback(db, logCallbackFunc,
                                  (void *) "auto_recover_compact_ok_test");
    fdb_open(&db_new, "./dummy1", &fconfig);
    status = fdb_set_log_callback(db_new, logCallbackFunc,
                                  (void *) "auto_recover_compact_ok_test");

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
    fdb_commit(db, FDB_COMMIT_MANUAL_WAL_FLUSH);

    // perform compaction using one handle
    fdb_compact(db, (char *) "./dummy2");

    // save the old file after compaction is done ..
    r = system(SHELL_COPY " dummy1 dummy11 > errorlog.txt");

    // now insert third doc: it should go to the newly compacted file.
    sprintf(keybuf, "key%d", i);
    sprintf(metabuf, "meta%d", i);
    sprintf(bodybuf, "body%d", i);
    fdb_doc_create(&doc[i], (void*)keybuf, strlen(keybuf),
        (void*)metabuf, strlen(metabuf), (void*)bodybuf, strlen(bodybuf));
    fdb_set(db, doc[i]);

    // commit
    fdb_commit(db, FDB_COMMIT_MANUAL_WAL_FLUSH);

    // close both the db files ...
    fdb_close(db);
    fdb_close(db_new);

    // restore the old file after close is done ..
    r = system(SHELL_MOVE " dummy11 dummy1 > errorlog.txt");

    // now open the old saved compacted file, it should automatically recover
    // and use the new file since compaction was done successfully
    fdb_open(&db_new, "./dummy1", &fconfig);
    status = fdb_set_log_callback(db_new, logCallbackFunc,
                                  (void *) "auto_recover_compact_ok_test");

    // retrieve documents using the old handle and expect all 3 docs
    for (i=0;i<n;++i){
        // search by key
        fdb_doc_create(&rdoc, doc[i]->key, doc[i]->keylen, NULL, 0, NULL, 0);
        status = fdb_get(db_new, rdoc);

        if (i != 1) {
            TEST_CHK(status == FDB_RESULT_SUCCESS);
            TEST_CHK(!memcmp(rdoc->meta, doc[i]->meta, rdoc->metalen));
            TEST_CHK(!memcmp(rdoc->body, doc[i]->body, rdoc->bodylen));
        }else{
            TEST_CHK(status == FDB_RESULT_KEY_NOT_FOUND);
        }

        // free result document
        fdb_doc_free(rdoc);
    }
    // check this handle's filename it should point to newly compacted file
    fdb_info info;
    fdb_get_dbinfo(db_new, &info);
    TEST_CHK(!strcmp("./dummy2", info.filename));

    // close the file
    fdb_close(db_new);

    // free all documents
    for (i=0;i<n;++i){
        fdb_doc_free(doc[i]);
    }

    // free all resources
    fdb_shutdown();

    memleak_end();

    TEST_RESULT("auto recovery after compaction test");
}

void db_drop_test()
{
    TEST_INIT();

    memleak_start();

    int i, r;
    int n = 3;
    fdb_handle *db;
    fdb_doc **doc = alca(fdb_doc *, n);
    fdb_doc *rdoc;
    fdb_status status;

    char keybuf[256], metabuf[256], bodybuf[256], temp[256];

    // remove previous dummy files
    r = system(SHELL_DEL " dummy* > errorlog.txt");

    fdb_config fconfig = fdb_get_default_config();
    fconfig.buffercache_size = 16777216;
    fconfig.wal_threshold = 1024;
    fconfig.flags = FDB_OPEN_FLAG_CREATE;
    fconfig.compaction_threshold = 0;

    // open db
    fdb_open(&db, "./dummy1", &fconfig);
    status = fdb_set_log_callback(db, logCallbackFunc,
                                  (void *) "db_drop_test");

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
    fdb_commit(db, FDB_COMMIT_NORMAL);
    fdb_close(db);

    // Remove the database file manually.
    r = system(SHELL_DEL " dummy1 > errorlog.txt");

    // Open the empty db with the same name.
    fdb_open(&db, "./dummy1", &fconfig);
    status = fdb_set_log_callback(db, logCallbackFunc,
                                  (void *) "db_drop_test");

    // now insert a new doc.
    sprintf(keybuf, "key%d", 0);
    sprintf(metabuf, "meta%d", 0);
    sprintf(bodybuf, "body%d", 0);
    fdb_doc_free(doc[0]);
    fdb_doc_create(&doc[0], (void*)keybuf, strlen(keybuf),
        (void*)metabuf, strlen(metabuf), (void*)bodybuf, strlen(bodybuf));
    fdb_set(db, doc[0]);

    // commit
    fdb_commit(db, FDB_COMMIT_NORMAL);

    // search by key
    fdb_doc_create(&rdoc, doc[0]->key, doc[0]->keylen, NULL, 0, NULL, 0);
    status = fdb_get(db, rdoc);
    // Make sure that a doc seqnum starts with one.
    assert(rdoc->seqnum == 1);

    fdb_close(db);

    // free all documents
    fdb_doc_free(rdoc);
    for (i=0;i<2;++i){
        fdb_doc_free(doc[i]);
    }

    // free all resources
    fdb_shutdown();

    memleak_end();

    TEST_RESULT("Database drop test");
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
    int i, r, k, c, commit_count, filename_count;
    struct timeval ts_begin, ts_cur, ts_gap;
    fdb_handle *db;
    fdb_status status;
    fdb_doc *rdoc;
    char temp[1024];

    char cnt_str[IDX_DIGIT+1];
    int cnt_int;

    filename_count = *args->filename_count;
    sprintf(temp, FILENAME"%d", filename_count);
    fdb_open(&db, temp, args->config);
    status = fdb_set_log_callback(db, logCallbackFunc,
                                  (void *) "worker_thread");

    // wait until all other threads open the DB file.
    // (to avoid performing compaction before opening the file)
    spin_lock(args->filename_count_lock);
    *args->n_opened += 1;
    spin_unlock(args->filename_count_lock);
    do {
        spin_lock(args->filename_count_lock);
        if (*args->n_opened == args->nthreads) {
            // all threads open the DB file
            spin_unlock(args->filename_count_lock);
            break;
        }
        spin_unlock(args->filename_count_lock);
        // sleep 1 sec
        sleep(1);
    } while(1);

    gettimeofday(&ts_begin, NULL);

    c = cnt_int = commit_count = 0;
    cnt_str[IDX_DIGIT] = 0;

    while(1){
        i = rand() % args->ndocs;
        fdb_doc_create(&rdoc, args->doc[i]->key, args->doc[i]->keylen, NULL, 0, NULL, 0);
        status = fdb_get(db, rdoc);

        assert(status == FDB_RESULT_SUCCESS);
        assert(!memcmp(rdoc->body, args->doc[i]->body, (IDX_DIGIT+1)));

        if (args->writer) {
            // if writer,
            // copy and parse the counter in body
            memcpy(cnt_str, (uint8_t *)rdoc->body + (IDX_DIGIT+1), IDX_DIGIT);
            cnt_int = atoi(cnt_str);

            // increase and rephrase
            sprintf(cnt_str, "%0"IDX_DIGIT_STR"d", ++cnt_int);
            memcpy((uint8_t *)rdoc->body + (IDX_DIGIT+1), cnt_str, IDX_DIGIT);

            // update and commit
            status = fdb_set(db, rdoc);

            if (args->nbatch > 0) {
                if (c % args->nbatch == 0) {
                    // commit for every NBATCH
                    fdb_commit(db, FDB_COMMIT_NORMAL);
                    commit_count++;
                    fdb_info info;
                    fdb_get_dbinfo(db, &info);
                    if (args->compact_term == commit_count &&
                        args->compact_term > 0 &&
                        info.new_filename == NULL &&
                        args->tid == 0) {
                        // do compaction for every COMPACT_TERM batch
                        spin_lock(args->filename_count_lock);
                        *args->filename_count += 1;
                        filename_count = *args->filename_count;
                        spin_unlock(args->filename_count_lock);

                        sprintf(temp, FILENAME"%d", filename_count);

                        status = fdb_compact(db, temp);
                        if (status != FDB_RESULT_SUCCESS) {
                            spin_lock(args->filename_count_lock);
                            *args->filename_count -= 1;
                            filename_count = *args->filename_count;
                            spin_unlock(args->filename_count_lock);
                        }

                        commit_count = 0;
                    }
                }
            }
        }
        fdb_doc_free(rdoc);
        c++;

        gettimeofday(&ts_cur, NULL);
        ts_gap = _utime_gap(ts_begin, ts_cur);
        if (ts_gap.tv_sec >= args->time_sec) break;
    }

    DBG("Thread #%d (%s) %d ops / %d seconds\n",
        args->tid, (args->writer)?("writer"):("reader"), c, (int)args->time_sec);
    args->nops = c;

    fdb_commit(db, FDB_COMMIT_MANUAL_WAL_FLUSH);

    fdb_close(db);
    thread_exit(0);
    return NULL;
}

void multi_thread_test(
    size_t ndocs, size_t wal_threshold, size_t time_sec,
    size_t nbatch, size_t compact_term, size_t nwriters, size_t nreaders)
{
    TEST_INIT();

    size_t nwrites, nreads;
    int i, r, idx_digit, temp_len;
    int n = nwriters + nreaders;;
    thread_t *tid = alca(thread_t, n);
    void **thread_ret = alca(void *, n);
    struct work_thread_args *args = alca(struct work_thread_args, n);
    struct timeval ts_begin, ts_cur, ts_gap;
    fdb_handle *db;
    fdb_handle *db_new;
    fdb_doc **doc = alca(fdb_doc*, ndocs);
    fdb_doc *rdoc;
    fdb_info info;
    fdb_status status;

    int filename_count = 1;
    int n_opened = 0;
    spin_t filename_count_lock;
    spin_init(&filename_count_lock);

    char keybuf[1024], metabuf[1024], bodybuf[1024], temp[1024];

    idx_digit = IDX_DIGIT;

    // remove previous dummy files
    r = system(SHELL_DEL" "FILENAME"* > errorlog.txt");

    fdb_config fconfig = fdb_get_default_config();
    fconfig.buffercache_size = 16777216;
    fconfig.wal_threshold = 1024;
    fconfig.flags = FDB_OPEN_FLAG_CREATE;
    fconfig.compaction_threshold = 0;

    memleak_start();

    // initial population ===
    DBG("Initialize..\n");

    // open db
    sprintf(temp, FILENAME"%d", filename_count);
    fdb_open(&db, temp, &fconfig);
    status = fdb_set_log_callback(db, logCallbackFunc,
                                  (void *) "multi_thread_test");

    gettimeofday(&ts_begin, NULL);

    // insert documents
    for (i=0;i<ndocs;++i){
        _set_random_string_smallabt(temp, KSIZE - (IDX_DIGIT+1));
        sprintf(keybuf, "k%0"IDX_DIGIT_STR"d%s", i, temp);

        sprintf(metabuf, "m%0"IDX_DIGIT_STR"d", i);

        _set_random_string_smallabt(temp, VSIZE-(IDX_DIGIT*2+1));
        sprintf(bodybuf, "b%0"IDX_DIGIT_STR"d%0"IDX_DIGIT_STR"d%s", i, 0, temp);

        fdb_doc_create(&doc[i], (void*)keybuf, strlen(keybuf),
            (void*)metabuf, strlen(metabuf), (void*)bodybuf, strlen(bodybuf));
        fdb_set(db, doc[i]);
    }

    fdb_commit(db, FDB_COMMIT_MANUAL_WAL_FLUSH);

    gettimeofday(&ts_cur, NULL);
    ts_gap = _utime_gap(ts_begin, ts_cur);
    //DBG("%d.%09d seconds elapsed\n", (int)ts_gap.tv_sec, (int)ts_gap.tv_nsec);

    fdb_close(db);
    // end of population ===

    // drop OS's page cache
    //r = system("free && sync && echo 3 > /proc/sys/vm/drop_caches && free");

    // create workers
    for (i=0;i<n;++i){
        args[i].tid = i;
        args[i].nthreads = n;
        args[i].writer = ((i<nwriters)?(1):(0));
        args[i].ndocs = ndocs;
        args[i].doc = doc;
        args[i].time_sec = time_sec;
        args[i].nbatch = nbatch;
        args[i].compact_term = compact_term;
        args[i].n_opened = &n_opened;
        args[i].filename_count = &filename_count;
        args[i].filename_count_lock = &filename_count_lock;
        args[i].config = &fconfig;
        thread_create(&tid[i], _worker_thread, &args[i]);
    }

    printf("wait for %d seconds..\n", (int)time_sec);

    // wait for thread termination
    for (i=0;i<n;++i){
        thread_join(tid[i], &thread_ret[i]);
    }

    // free all documents
    for (i=0;i<ndocs;++i){
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
    fdb_open(&db, temp, &fconfig);
    fdb_get_dbinfo(db, &info);
    TEST_CHK(info.last_seqnum == ndocs+nwrites);
    fdb_close(db);

    // shutdown
    fdb_shutdown();

    memleak_end();

    TEST_RESULT("multi thread test");
}

void crash_recovery_test()
{
    TEST_INIT();

    memleak_start();

    int i, r;
    int n = 10;
    fdb_handle *db;
    fdb_doc **doc = alca(fdb_doc*, n);
    fdb_doc *rdoc;
    fdb_status status;

    char keybuf[256], metabuf[256], bodybuf[256], temp[256];

    // remove previous dummy files
    r = system(SHELL_DEL" dummy* > errorlog.txt");

    fdb_config fconfig = fdb_get_default_config();
    fconfig.buffercache_size = 0;
    fconfig.wal_threshold = 1024;
    fconfig.flags = FDB_OPEN_FLAG_CREATE;
    fconfig.compaction_threshold = 0;

    // reopen db
    fdb_open(&db, "./dummy2", &fconfig);
    status = fdb_set_log_callback(db, logCallbackFunc,
                                  (void *) "crash_recovery_test");

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
    fdb_commit(db, FDB_COMMIT_NORMAL);

    // close the db
    fdb_close(db);

    // Shutdown forest db in the middle of the test to simulate crash
    fdb_shutdown();

    // Now append garbage at the end of the file for a few blocks
    r = system(
       "dd if=/dev/zero bs=4096 of=./dummy2 oseek=3 count=2 >> errorlog.txt");

    // Write 1024 bytes of non-block aligned garbage to end of file
    r = system(
       "dd if=/dev/zero bs=1024 of=./dummy2 oseek=20 count=1 >> errorlog.txt");

    // reopen the same file
    fdb_open(&db, "./dummy2", &fconfig);
    status = fdb_set_log_callback(db, logCallbackFunc,
                                  (void *) "crash_recovery_test");

    // retrieve documents
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
    fdb_close(db);

    // free all resources
    fdb_shutdown();

    memleak_end();

    TEST_RESULT("crash recovery test");
}

void incomplete_block_test()
{
    TEST_INIT();

    memleak_start();

    int i, r;
    int n = 2;
    fdb_handle *db;
    fdb_doc **doc = alca(fdb_doc*, n);
    fdb_doc *rdoc;
    fdb_status status;

    char keybuf[256], metabuf[256], bodybuf[256], temp[256];

    // remove previous dummy files
    r = system(SHELL_DEL" dummy* > errorlog.txt");

    fdb_config fconfig = fdb_get_default_config();
    fconfig.buffercache_size = 0;
    fconfig.wal_threshold = 1024;
    fconfig.flags = FDB_OPEN_FLAG_CREATE;
    fconfig.compaction_threshold = 0;

    // open db
    fdb_open(&db, "./dummy1", &fconfig);
    status = fdb_set_log_callback(db, logCallbackFunc,
                                  (void *) "incomplete_block_test");

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
        TEST_CHK(!memcmp(rdoc->meta, doc[i]->meta, rdoc->metalen));
        TEST_CHK(!memcmp(rdoc->body, doc[i]->body, rdoc->bodylen));

        // free result document
        fdb_doc_free(rdoc);
    }

    // close db file
    fdb_close(db);

    // free all documents
    for (i=0;i<n;++i){
        fdb_doc_free(doc[i]);
    }

    // free all resources
    fdb_shutdown();

    memleak_end();

    TEST_RESULT("incomplete block test");
}

void iterator_test()
{
    TEST_INIT();

    memleak_start();

    int i, r;
    int n = 10;
    uint64_t offset;
    fdb_handle *db;
    fdb_doc **doc = alca(fdb_doc*, n);
    fdb_doc *rdoc;
    fdb_status status;
    fdb_iterator *iterator;

    char keybuf[256], metabuf[256], bodybuf[256], temp[256];

    // remove previous dummy files
    r = system(SHELL_DEL" dummy* > errorlog.txt");

    fdb_config fconfig = fdb_get_default_config();
    fconfig.buffercache_size = 0;
    fconfig.wal_threshold = 1024;
    fconfig.flags = FDB_OPEN_FLAG_CREATE;
    fconfig.compaction_threshold = 0;

    // open db
    fdb_open(&db, "./dummy1", &fconfig);
    status = fdb_set_log_callback(db, logCallbackFunc,
                                  (void *) "iterator_test");

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
    fdb_commit(db, FDB_COMMIT_MANUAL_WAL_FLUSH);

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
    fdb_commit(db, FDB_COMMIT_NORMAL);

    // now even number docs are in hb-trie & odd number docs are in WAL

    // create an iterator for full range
    fdb_iterator_init(db, &iterator, NULL, 0, NULL, 0, FDB_ITR_NONE);

    // repeat until fail
    i=0;
    while(1){
        status = fdb_iterator_next(iterator, &rdoc);
        if (status == FDB_RESULT_ITERATOR_FAIL) break;

        TEST_CHK(!memcmp(rdoc->key, doc[i]->key, rdoc->keylen));
        TEST_CHK(!memcmp(rdoc->meta, doc[i]->meta, rdoc->metalen));
        TEST_CHK(!memcmp(rdoc->body, doc[i]->body, rdoc->bodylen));

        fdb_doc_free(rdoc);
        i++;
    };
    TEST_CHK(i==10);
    fdb_iterator_close(iterator);

    // create an iterator with metaonly option
    fdb_iterator_init(db, &iterator, NULL, 0, NULL, 0, FDB_ITR_METAONLY);

    // repeat until fail
    i=0;
    while(1){
        // retrieve the next doc and get the byte offset of the returned doc
        status = fdb_iterator_next_metaonly(iterator, &rdoc);
        if (status == FDB_RESULT_ITERATOR_FAIL) break;

        TEST_CHK(rdoc->offset != BLK_NOT_FOUND);
        TEST_CHK(!memcmp(rdoc->key, doc[i]->key, rdoc->keylen));
        TEST_CHK(!memcmp(rdoc->meta, doc[i]->meta, rdoc->metalen));
        TEST_CHK(rdoc->body == NULL);

        fdb_doc_free(rdoc);
        i++;
    };
    TEST_CHK(i==10);
    fdb_iterator_close(iterator);

    // create another iterator starts from doc[3]
    sprintf(keybuf, "key%d", 3);
    fdb_iterator_init(db, &iterator, (void*)keybuf, strlen(keybuf), NULL, 0, FDB_ITR_NONE);

    // repeat until fail
    i=3;
    while(1){
        status = fdb_iterator_next(iterator, &rdoc);
        if (status == FDB_RESULT_ITERATOR_FAIL) break;

        TEST_CHK(!memcmp(rdoc->key, doc[i]->key, rdoc->keylen));
        TEST_CHK(!memcmp(rdoc->meta, doc[i]->meta, rdoc->metalen));
        TEST_CHK(!memcmp(rdoc->body, doc[i]->body, rdoc->bodylen));

        fdb_doc_free(rdoc);
        i++;
    };
    TEST_CHK(i==10);
    fdb_iterator_close(iterator);

    // create another iterator for the range of doc[4] ~ doc[8]
    sprintf(keybuf, "key%d", 4);
    sprintf(temp, "key%d", 8);
    fdb_iterator_init(db, &iterator, (void*)keybuf, strlen(keybuf),
        (void*)temp, strlen(temp), FDB_ITR_NONE);

    // repeat until fail
    i=4;
    while(1){
        status = fdb_iterator_next(iterator, &rdoc);
        if (status == FDB_RESULT_ITERATOR_FAIL) break;

        TEST_CHK(!memcmp(rdoc->key, doc[i]->key, rdoc->keylen));
        TEST_CHK(!memcmp(rdoc->meta, doc[i]->meta, rdoc->metalen));
        TEST_CHK(!memcmp(rdoc->body, doc[i]->body, rdoc->bodylen));

        fdb_doc_free(rdoc);
        i++;
    };
    TEST_CHK(i==9);
    fdb_iterator_close(iterator);

    // remove document #8 and #9
    fdb_doc_create(&rdoc, doc[8]->key, doc[8]->keylen, doc[8]->meta, doc[8]->metalen, NULL, 0);
    status = fdb_del(db, rdoc);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    fdb_doc_free(rdoc);
    fdb_doc_create(&rdoc, doc[9]->key, doc[9]->keylen, doc[9]->meta, doc[9]->metalen, NULL, 0);
    status = fdb_del(db, rdoc);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    fdb_doc_free(rdoc);
    // commit
    fdb_commit(db, FDB_COMMIT_NORMAL);

    // create an iterator for full range
    fdb_iterator_init(db, &iterator, NULL, 0, NULL, 0, FDB_ITR_NONE);
    // repeat until fail
    i=0;
    while(1){
        status = fdb_iterator_next(iterator, &rdoc);
        if (status == FDB_RESULT_ITERATOR_FAIL) break;

        TEST_CHK(!memcmp(rdoc->key, doc[i]->key, rdoc->keylen));
        TEST_CHK(!memcmp(rdoc->meta, doc[i]->meta, rdoc->metalen));
        if (i < 8) {
            TEST_CHK(!memcmp(rdoc->body, doc[i]->body, rdoc->bodylen));
        } else {
            TEST_CHK(rdoc->deleted == true);
        }

        fdb_doc_free(rdoc);
        i++;
    };
    TEST_CHK(i==10);
    fdb_iterator_close(iterator);

    // create an iterator for full range, but no deletes.
    fdb_iterator_init(db, &iterator, NULL, 0, NULL, 0, FDB_ITR_NO_DELETES);
    // repeat until fail
    i=0;
    while(1){
        status = fdb_iterator_next(iterator, &rdoc);
        if (status == FDB_RESULT_ITERATOR_FAIL) break;

        TEST_CHK(!memcmp(rdoc->key, doc[i]->key, rdoc->keylen));
        TEST_CHK(!memcmp(rdoc->meta, doc[i]->meta, rdoc->metalen));
        TEST_CHK(!memcmp(rdoc->body, doc[i]->body, rdoc->bodylen));

        fdb_doc_free(rdoc);
        i++;
    };
    TEST_CHK(i==8);
    fdb_iterator_close(iterator);

    // create an iterator for range of doc[4] ~ doc[8], but metadata only and no deletes.
    sprintf(keybuf, "key%d", 4);
    sprintf(temp, "key%d", 8);
    fdb_iterator_init(db, &iterator, keybuf, strlen(keybuf), temp, strlen(temp),
                      FDB_ITR_METAONLY | FDB_ITR_NO_DELETES);
    // repeat until fail
    i=4;
    while(1){
        status = fdb_iterator_next(iterator, &rdoc);
        if (status == FDB_RESULT_ITERATOR_FAIL) break;

        TEST_CHK(!memcmp(rdoc->key, doc[i]->key, rdoc->keylen));
        TEST_CHK(!memcmp(rdoc->meta, doc[i]->meta, rdoc->metalen));
        TEST_CHK(rdoc->deleted == false);

        fdb_doc_free(rdoc);
        i++;
    };
    TEST_CHK(i==8);
    fdb_iterator_close(iterator);

    // close db file
    fdb_close(db);

    // free all documents
    for (i=0;i<n;++i){
        fdb_doc_free(doc[i]);
    }

    // free all resources
    fdb_shutdown();

    memleak_end();

    TEST_RESULT("iterator test");
}

void iterator_seek_test()
{
    TEST_INIT();

    memleak_start();

    int i, r;
    int n = 10;
    uint64_t offset;
    fdb_handle *db;
    fdb_doc **doc = alca(fdb_doc*, n);
    fdb_doc *rdoc;
    fdb_status status;
    fdb_iterator *iterator;

    char keybuf[256], metabuf[256], bodybuf[256], temp[256];

    // remove previous dummy files
    r = system(SHELL_DEL" dummy* > errorlog.txt");

    fdb_config fconfig = fdb_get_default_config();
    fconfig.buffercache_size = 0;
    fconfig.wal_threshold = 1024;
    fconfig.flags = FDB_OPEN_FLAG_CREATE;
    fconfig.compaction_threshold = 0;

    // open db
    fdb_open(&db, "./dummy1", &fconfig);
    status = fdb_set_log_callback(db, logCallbackFunc,
                                  (void *) "iterator_seek_test");

    // insert documents of odd number
    for (i=1;i<n;i+=2){
        sprintf(keybuf, "key%d", i);
        sprintf(metabuf, "meta%d", i);
        sprintf(bodybuf, "body%d", i);
        fdb_doc_create(&doc[i], (void*)keybuf, strlen(keybuf),
            (void*)metabuf, strlen(metabuf), (void*)bodybuf, strlen(bodybuf));
        fdb_set(db, doc[i]);
    }
    // manually flush WAL & commit
    fdb_commit(db, FDB_COMMIT_MANUAL_WAL_FLUSH);

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
    fdb_commit(db, FDB_COMMIT_NORMAL);

    // now odd number docs are in hb-trie & even number docs are in WAL

    // create an iterator for full range
    fdb_iterator_init(db, &iterator, NULL, 0, NULL, 0, FDB_ITR_NONE);

    // seek current iterator to inside the WAL's avl tree..
    status = fdb_iterator_next(iterator, &rdoc);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    TEST_CHK(!memcmp(rdoc->key, doc[0]->key, rdoc->keylen));
    TEST_CHK(!memcmp(rdoc->meta, doc[0]->meta, rdoc->metalen));
    TEST_CHK(!memcmp(rdoc->body, doc[0]->body, rdoc->bodylen));
    fdb_doc_free(rdoc);

    // seek forward to 2nd key ..
    status = fdb_iterator_seek(iterator, doc[2]->key, strlen(keybuf));
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // repeat until fail
    i=2;
    while(1){
        status = fdb_iterator_next(iterator, &rdoc);
        if (status == FDB_RESULT_ITERATOR_FAIL) break;

        TEST_CHK(!memcmp(rdoc->key, doc[i]->key, rdoc->keylen));
        TEST_CHK(!memcmp(rdoc->meta, doc[i]->meta, rdoc->metalen));
        TEST_CHK(!memcmp(rdoc->body, doc[i]->body, rdoc->bodylen));

        fdb_doc_free(rdoc);
        i++;
    };
    TEST_CHK(i==10);
    fdb_iterator_close(iterator);

    // close db file
    fdb_close(db);

    // free all documents
    for (i=0;i<n;++i){
        fdb_doc_free(doc[i]);
    }

    // free all resources
    fdb_shutdown();

    memleak_end();

    TEST_RESULT("iterator seek test");
}

void sequence_iterator_test()
{
    TEST_INIT();

    memleak_start();

    int i, r;
    int n = 10;
    int count;
    uint64_t offset;
    fdb_handle *db;
    fdb_doc **doc = alca(fdb_doc*, n);
    fdb_doc *rdoc;
    fdb_status status;
    fdb_iterator *iterator;

    char keybuf[256], metabuf[256], bodybuf[256], temp[256];

    // remove previous dummy files
    r = system(SHELL_DEL" dummy* > errorlog.txt");

    fdb_config fconfig = fdb_get_default_config();
    fconfig.buffercache_size = 0;
    fconfig.wal_threshold = 1024;
    fconfig.flags = FDB_OPEN_FLAG_CREATE;
    fconfig.compaction_threshold = 0;

    // open db
    fdb_open(&db, "./dummy1", &fconfig);
    status = fdb_set_log_callback(db, logCallbackFunc,
                                  (void *) "sequence_iterator_test");

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
    fdb_commit(db, FDB_COMMIT_MANUAL_WAL_FLUSH);

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
    fdb_commit(db, FDB_COMMIT_NORMAL);

    // now even number docs are in hb-trie & odd number docs are in WAL

    // create an iterator over sequence number range over FULL RANGE
    fdb_iterator_sequence_init(db, &iterator, 0, 0, FDB_ITR_NONE);

    // repeat until fail
    i=0;
    count = 0;
    while(1){
        status = fdb_iterator_next(iterator, &rdoc);
        if (status == FDB_RESULT_ITERATOR_FAIL) break;

        TEST_CHK(!memcmp(rdoc->key, doc[i]->key, rdoc->keylen));
        TEST_CHK(!memcmp(rdoc->meta, doc[i]->meta, rdoc->metalen));
        TEST_CHK(!memcmp(rdoc->body, doc[i]->body, rdoc->bodylen));

        fdb_doc_free(rdoc);
        i = (i + 2 >= n) ? 1: i + 2; // by-seq, first come even docs, then odd
        count++;
    };
    TEST_CHK(count==n);
    fdb_iterator_close(iterator);

    // create an iterator over sequence number with META ONLY
    fdb_iterator_sequence_init(db, &iterator, 0, 0, FDB_ITR_METAONLY);

    // repeat until fail
    i=0;
    count = 0;
    while(1){
        status = fdb_iterator_next_metaonly(iterator, &rdoc);
        if (status == FDB_RESULT_ITERATOR_FAIL) break;

        TEST_CHK(!memcmp(rdoc->key, doc[i]->key, rdoc->keylen));
        TEST_CHK(!memcmp(rdoc->meta, doc[i]->meta, rdoc->metalen));
        TEST_CHK(rdoc->body == NULL);

        fdb_doc_free(rdoc);
        i = (i + 2 >= n) ? 1: i + 2; // by-seq, first come even docs, then odd
        count++;
    };
    TEST_CHK(count==n);
    fdb_iterator_close(iterator);

    // create another iterator starts from seq number 2 and ends at 9
    fdb_iterator_sequence_init(db, &iterator, 2, 7, FDB_ITR_NONE);

    // repeat until fail
    i=2;
    count = 0;
    while(1){
        status = fdb_iterator_next(iterator, &rdoc);
        if (status == FDB_RESULT_ITERATOR_FAIL) break;

        TEST_CHK(!memcmp(rdoc->key, doc[i]->key, rdoc->keylen));
        TEST_CHK(!memcmp(rdoc->meta, doc[i]->meta, rdoc->metalen));
        TEST_CHK(!memcmp(rdoc->body, doc[i]->body, rdoc->bodylen));

        fdb_doc_free(rdoc);
        i = (i + 2 >= n) ? 1: i + 2; // by-seq, first come even docs, then odd
        count++;
    };
    TEST_CHK(count==6);
    fdb_iterator_close(iterator);
    // remove document #8 and #9
    fdb_doc_create(&rdoc, doc[8]->key, doc[8]->keylen, doc[8]->meta, doc[8]->metalen, NULL, 0);
    status = fdb_del(db, rdoc);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    fdb_doc_free(rdoc);
    fdb_doc_create(&rdoc, doc[9]->key, doc[9]->keylen, doc[9]->meta, doc[9]->metalen, NULL, 0);
    status = fdb_del(db, rdoc);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    fdb_doc_free(rdoc);
    // commit
    fdb_commit(db, FDB_COMMIT_NORMAL);

    // create an iterator for full range
    fdb_iterator_sequence_init(db, &iterator, 0, 0, FDB_ITR_NONE);
    // repeat until fail
    i=0;
    count=0;
    while(1){
        status = fdb_iterator_next(iterator, &rdoc);
        if (status == FDB_RESULT_ITERATOR_FAIL) break;

        if (count != 8 && count != 9) { // do not look validate key8 and key9
            TEST_CHK(!memcmp(rdoc->key, doc[i]->key, rdoc->keylen));
            TEST_CHK(!memcmp(rdoc->meta, doc[i]->meta, rdoc->metalen));
            TEST_CHK(!memcmp(rdoc->body, doc[i]->body, rdoc->bodylen));
        } else {
            TEST_CHK(rdoc->deleted == true);
        }

        fdb_doc_free(rdoc);
        // Turn around when we hit 8 as the last items, key8 and key9 are gone
        i = (i + 2 >= 8) ? 1: i + 2; // by-seq, first come even docs, then odd
        count++;
    };
    TEST_CHK(count==10); // 10 items, with 2 deletions
    fdb_iterator_close(iterator);

    // create an iterator for full range, but no deletes.
    fdb_iterator_sequence_init(db, &iterator, 0, 0, FDB_ITR_NO_DELETES);
    // repeat until fail
    i=0;
    count=0;
    while(1){
        status = fdb_iterator_next(iterator, &rdoc);
        if (status == FDB_RESULT_ITERATOR_FAIL) break;

        if (i != 8 && i != 9) { // key8 and key9 are deleted
            TEST_CHK(!memcmp(rdoc->key, doc[i]->key, rdoc->keylen));
            TEST_CHK(!memcmp(rdoc->meta, doc[i]->meta, rdoc->metalen));
            TEST_CHK(!memcmp(rdoc->body, doc[i]->body, rdoc->bodylen));
        }

        fdb_doc_free(rdoc);
        i = (i + 2 >= 8) ? 1: i + 2; // by-seq, first come even docs, then odd
        count++;
    };
    TEST_CHK(count==8); // 10 items, with 2 deletions
    fdb_iterator_close(iterator);

    // Update first document and test for absence of duplicates
    *((char *)doc[0]->body) = 'K'; // update key0 to Key0
    fdb_set(db, doc[0]);
    fdb_commit(db, FDB_COMMIT_NORMAL);

    fdb_iterator_sequence_init(db, &iterator, 0, 0, FDB_ITR_NO_DELETES);
    // repeat until fail
    i=2; // i == 0 should not appear until the end
    count=0;
    while(1){
        status = fdb_iterator_next(iterator, &rdoc);
        if (status == FDB_RESULT_ITERATOR_FAIL) break;

        if (i != 8 && i != 9) { // key8 and key9 are deleted
            TEST_CHK(!memcmp(rdoc->key, doc[i]->key, rdoc->keylen));
            TEST_CHK(!memcmp(rdoc->meta, doc[i]->meta, rdoc->metalen));
            TEST_CHK(!memcmp(rdoc->body, doc[i]->body, rdoc->bodylen));
        }

        fdb_doc_free(rdoc);
        i = (i + 2 >= 8) ? 1: i + 2; // by-seq, first come even docs, then odd
        if (count == 6) i = 0; // go back to test for i=0 at the end
        count++;
    };
    TEST_CHK(count==8); // 10 items, with 2 deletions
    fdb_iterator_close(iterator);

    // close db file
    fdb_close(db);

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
    uint64_t offset;
    fdb_handle *db;
    fdb_doc **doc = alca(fdb_doc*, n);
    fdb_doc *rdoc;
    fdb_status status;
    fdb_iterator *iterator;
    fdb_seqnum_t seqnum;

    char keybuf[256], metabuf[256], bodybuf[256], temp[256];

    // remove previous dummy files
    r = system(SHELL_DEL" dummy* > errorlog.txt");

    fdb_config fconfig = fdb_get_default_config();
    fconfig.buffercache_size = 0;
    fconfig.wal_threshold = 1024;
    fconfig.compaction_threshold = 0;

    // open db
    fdb_open(&db, "./dummy1", &fconfig);
    status = fdb_set_log_callback(db, logCallbackFunc,
                                  (void *) "sequence_iterator_test");

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
    fdb_commit(db, FDB_COMMIT_MANUAL_WAL_FLUSH);

    // insert documents second time
    for (i=0;i<n;i++){
        sprintf(bodybuf, "body%d(second)", i);
        fdb_doc_update(&doc[i], NULL, 0, bodybuf, strlen(bodybuf));
        fdb_set(db, doc[i]);
    }
    // manually flush WAL & commit
    fdb_commit(db, FDB_COMMIT_MANUAL_WAL_FLUSH);

    // insert documents third time (only even number documents)
    for (i=0;i<n;i+=2){
        sprintf(bodybuf, "body%d(third)", i);
        fdb_doc_update(&doc[i], NULL, 0, bodybuf, strlen(bodybuf));
        fdb_set(db, doc[i]);
    }
    // commit without WAL flushing
    fdb_commit(db, FDB_COMMIT_NORMAL);

    // create an iterator over sequence number
    fdb_iterator_sequence_init(db, &iterator, 0, 220, FDB_ITR_NONE);

    // repeat until fail
    i=0;
    count = 0;
    while(1){
        status = fdb_iterator_next(iterator, &rdoc);
        if (status == FDB_RESULT_ITERATOR_FAIL) break;
        if (count<50) {
            // HB+trie
            i = count*2 + 1;
            seqnum = 100 + (count+1)*2;
            sprintf(bodybuf, "body%d(second)", i);
        } else {
            // WAL
            i = (count-50)*2;
            seqnum = 200 + (count-50+1);
            sprintf(bodybuf, "body%d(third)", i);
        }

        TEST_CHK(!memcmp(rdoc->key, doc[i]->key, rdoc->keylen));
        TEST_CHK(!memcmp(rdoc->meta, doc[i]->meta, rdoc->metalen));
        TEST_CHK(!memcmp(rdoc->body, bodybuf, rdoc->bodylen));
        TEST_CHK(rdoc->seqnum == seqnum);

        count++;
        fdb_doc_free(rdoc);
    };
    TEST_CHK(count==70);
    fdb_iterator_close(iterator);

    // close db file
    fdb_close(db);
    // free all documents
    for (i=0;i<n;++i){
        fdb_doc_free(doc[i]);
    }
    // free all resources
    fdb_shutdown();

    memleak_end();

    TEST_RESULT("sequence iterator duplicate test");
}

void reverse_sequence_iterator_test()
{
    TEST_INIT();

    memleak_start();

    int i, r, count;
    int n = 10;
    uint64_t offset;
    fdb_handle *db;
    fdb_doc **doc = alca(fdb_doc*, n);
    fdb_doc *rdoc;
    fdb_status status;
    fdb_iterator *iterator;

    char keybuf[256], metabuf[256], bodybuf[256], temp[256];

    // remove previous dummy files
    r = system(SHELL_DEL" dummy* > errorlog.txt");

    fdb_config fconfig = fdb_get_default_config();
    fconfig.buffercache_size = 0;
    fconfig.wal_threshold = 1024;
    fconfig.flags = FDB_OPEN_FLAG_CREATE;
    fconfig.compaction_threshold = 0;

    // open db
    fdb_open(&db, "./dummy1", &fconfig);
    status = fdb_set_log_callback(db, logCallbackFunc,
                                  (void *) "reverse_sequence_iterator_test");

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
    fdb_commit(db, FDB_COMMIT_MANUAL_WAL_FLUSH);

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
    fdb_commit(db, FDB_COMMIT_NORMAL);

    // now even number docs are in hb-trie & odd number docs are in WAL

    // First test reverse sequence iteration as it only involves btrees
    // create an iterator over sequence number range over FULL RANGE
    fdb_iterator_sequence_init(db, &iterator, 0, 0, FDB_ITR_NONE);

    // move iterator forward up till middle...
    i=0;
    count = 0;
    while(1){
        status = fdb_iterator_next(iterator, &rdoc);
        if (status == FDB_RESULT_ITERATOR_FAIL) break;

        TEST_CHK(!memcmp(rdoc->key, doc[i]->key, rdoc->keylen));
        TEST_CHK(!memcmp(rdoc->meta, doc[i]->meta, rdoc->metalen));
        TEST_CHK(!memcmp(rdoc->body, doc[i]->body, rdoc->bodylen));

        fdb_doc_free(rdoc);
        count++;
        if (i + 2 >= n) break;
        i = i + 2; // by-seq, first come even docs, then odd
    };
    TEST_CHK(count==n/2);

    // Now test reverse sequence iterator from mid-way..

    i = i - 2;
    status = fdb_iterator_prev(iterator, &rdoc);
    TEST_CHK(status != FDB_RESULT_ITERATOR_FAIL);

    TEST_CHK(!memcmp(rdoc->key, doc[i]->key, rdoc->keylen));
    TEST_CHK(!memcmp(rdoc->meta, doc[i]->meta, rdoc->metalen));
    TEST_CHK(!memcmp(rdoc->body, doc[i]->body, rdoc->bodylen));

    fdb_doc_free(rdoc);
    count++;

    i = i + 2;
    while(1){
        status = fdb_iterator_next(iterator, &rdoc);
        if (status == FDB_RESULT_ITERATOR_FAIL) break;

        TEST_CHK(!memcmp(rdoc->key, doc[i]->key, rdoc->keylen));
        TEST_CHK(!memcmp(rdoc->meta, doc[i]->meta, rdoc->metalen));
        TEST_CHK(!memcmp(rdoc->body, doc[i]->body, rdoc->bodylen));

        fdb_doc_free(rdoc);
        i = (i + 2 >= n) ? 1 : i + 2;// by-seq, first come even docs, then odd
        count++;
    };

    TEST_CHK(count==n+2); // two items were double counted due to reverse

    // Reached End, now reverse iterate till start
    i = n - 1;
    count = n;
    while (1) {
       status = fdb_iterator_prev(iterator, &rdoc);
        if (status == FDB_RESULT_ITERATOR_FAIL) break;

        TEST_CHK(!memcmp(rdoc->key, doc[i]->key, rdoc->keylen));
        TEST_CHK(!memcmp(rdoc->meta, doc[i]->meta, rdoc->metalen));
        TEST_CHK(!memcmp(rdoc->body, doc[i]->body, rdoc->bodylen));

        fdb_doc_free(rdoc);
        i = (i - 2 < 0) ? n - 2 : i - 2;
        if (count) count--;
    }
    TEST_CHK(count == 0);
    fdb_iterator_close(iterator);

    // close db file
    fdb_close(db);

    // free all documents
    for (i=0;i<n;++i){
        fdb_doc_free(doc[i]);
    }

    // free all resources
    fdb_shutdown();

    memleak_end();

    TEST_RESULT("reverse sequence iterator test");
}

void reverse_iterator_test()
{
    TEST_INIT();

    memleak_start();

    int i, r, count;
    int n = 10;
    uint64_t offset;
    fdb_handle *db;
    fdb_doc **doc = alca(fdb_doc*, n);
    fdb_doc *rdoc;
    fdb_status status;
    fdb_iterator *iterator;

    char keybuf[256], metabuf[256], bodybuf[256], temp[256];

    // remove previous dummy files
    r = system(SHELL_DEL" dummy* > errorlog.txt");

    fdb_config fconfig = fdb_get_default_config();
    fconfig.buffercache_size = 0;
    fconfig.wal_threshold = 1024;
    fconfig.flags = FDB_OPEN_FLAG_CREATE;
    fconfig.compaction_threshold = 0;

    // open db
    fdb_open(&db, "./dummy1", &fconfig);
    status = fdb_set_log_callback(db, logCallbackFunc,
                                  (void *) "reverse_iterator_test");

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
    fdb_commit(db, FDB_COMMIT_MANUAL_WAL_FLUSH);

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
    fdb_commit(db, FDB_COMMIT_NORMAL);

    // now even number docs are in hb-trie & odd number docs are in WAL

    // Reverse iteration over key range which involves hb-tries
    // create an iterator for full range
    fdb_iterator_init(db, &iterator, NULL, 0, NULL, 0, FDB_ITR_NONE);

    // first test forward iterator - repeat until fail
    i=0;
    while(1){
        status = fdb_iterator_next(iterator, &rdoc);
        if (status == FDB_RESULT_ITERATOR_FAIL) break;

        TEST_CHK(!memcmp(rdoc->key, doc[i]->key, rdoc->keylen));
        TEST_CHK(!memcmp(rdoc->meta, doc[i]->meta, rdoc->metalen));
        TEST_CHK(!memcmp(rdoc->body, doc[i]->body, rdoc->bodylen));

        fdb_doc_free(rdoc);
        i++;
    };
    TEST_CHK(i==10);

    // Now test reverse iterator..
    i--;
    while (1) {
        status = fdb_iterator_prev(iterator, &rdoc);

        if (status == FDB_RESULT_ITERATOR_FAIL) break;

        TEST_CHK(!memcmp(rdoc->key, doc[i]->key, rdoc->keylen));
        TEST_CHK(!memcmp(rdoc->meta, doc[i]->meta, rdoc->metalen));
        TEST_CHK(!memcmp(rdoc->body, doc[i]->body, rdoc->bodylen));

        fdb_doc_free(rdoc);
        if (i == 5) break; // Change direction at half point
        i--;
    }
    TEST_CHK(i == 5);

    // Mid-way reverse direction, again test forward iterator...
    i++;
    status = fdb_iterator_next(iterator, &rdoc);
    TEST_CHK(status != FDB_RESULT_ITERATOR_FAIL);

    TEST_CHK(!memcmp(rdoc->key, doc[i]->key, rdoc->keylen));
    TEST_CHK(!memcmp(rdoc->meta, doc[i]->meta, rdoc->metalen));
    TEST_CHK(!memcmp(rdoc->body, doc[i]->body, rdoc->bodylen));

    fdb_doc_free(rdoc);

    // Mid-way reverse direction, again test forward iterator...
    i++;
    status = fdb_iterator_next(iterator, &rdoc);
    TEST_CHK(status != FDB_RESULT_ITERATOR_FAIL);

    TEST_CHK(!memcmp(rdoc->key, doc[i]->key, rdoc->keylen));
    TEST_CHK(!memcmp(rdoc->meta, doc[i]->meta, rdoc->metalen));
    TEST_CHK(!memcmp(rdoc->body, doc[i]->body, rdoc->bodylen));

    fdb_doc_free(rdoc);

    // Again change direction and test reverse iterator..
    i--;
    while (1) {
        status = fdb_iterator_prev(iterator, &rdoc);

        if (status == FDB_RESULT_ITERATOR_FAIL) break;

        TEST_CHK(!memcmp(rdoc->key, doc[i]->key, rdoc->keylen));
        TEST_CHK(!memcmp(rdoc->meta, doc[i]->meta, rdoc->metalen));
        TEST_CHK(!memcmp(rdoc->body, doc[i]->body, rdoc->bodylen));

        fdb_doc_free(rdoc);
        i--;
    }
    TEST_CHK(i == -1);

    // Reached end - now test forward iterator...
    i++;
    while(1){
        status = fdb_iterator_next(iterator, &rdoc);
        if (status == FDB_RESULT_ITERATOR_FAIL) break;

        TEST_CHK(!memcmp(rdoc->key, doc[i]->key, rdoc->keylen));
        TEST_CHK(!memcmp(rdoc->meta, doc[i]->meta, rdoc->metalen));
        TEST_CHK(!memcmp(rdoc->body, doc[i]->body, rdoc->bodylen));

        fdb_doc_free(rdoc);
        i++;
    };
    TEST_CHK(i==10);

    fdb_iterator_close(iterator);

    // close db file
    fdb_close(db);

    // free all documents
    for (i=0;i<n;++i){
        fdb_doc_free(doc[i]);
    }

    // free all resources
    fdb_shutdown();

    memleak_end();

    TEST_RESULT("reverse iterator test");
}

int _cmp_double(void *a, void *b)
{
    double aa, bb;
    aa = *(double *)a;
    bb = *(double *)b;

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
    uint64_t offset;
    fdb_handle *db;
    fdb_doc **doc = alca(fdb_doc*, n);
    fdb_doc *rdoc;
    fdb_status status;
    fdb_iterator *iterator;

    char keybuf[256], metabuf[256], bodybuf[256], temp[256];
    double key_double, key_double_prev;

    // remove previous dummy files
    r = system(SHELL_DEL" dummy* > errorlog.txt");

    fdb_config fconfig = fdb_get_default_config();
    fconfig.buffercache_size = 0;
    fconfig.wal_threshold = 1024;
    fconfig.flags = FDB_OPEN_FLAG_CREATE;
    fconfig.cmp_fixed = _cmp_double;
    fconfig.compaction_threshold = 0;

    // open db with custom compare function for double key type
    fdb_open_cmp_fixed(&db, "./dummy1", &fconfig);
    status = fdb_set_log_callback(db, logCallbackFunc,
                                  (void *) "custom_compare_primitive_test");

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
    while(1){
        if ( (status = fdb_iterator_next(iterator, &rdoc)) == FDB_RESULT_ITERATOR_FAIL)
            break;
        memcpy(&key_double, rdoc->key, rdoc->keylen);
        TEST_CHK(key_double > key_double_prev);
        key_double_prev = key_double;
        fdb_doc_free(rdoc);
    };
    fdb_iterator_close(iterator);

    fdb_commit(db, FDB_COMMIT_MANUAL_WAL_FLUSH);

    // range scan (after flushing WAL)
    fdb_iterator_init(db, &iterator, NULL, 0, NULL, 0, 0x0);
    key_double_prev = -1;
    while(1){
        if ( (status = fdb_iterator_next(iterator, &rdoc)) == FDB_RESULT_ITERATOR_FAIL)
            break;
        memcpy(&key_double, rdoc->key, rdoc->keylen);
        TEST_CHK(key_double > key_double_prev);
        key_double_prev = key_double;
        fdb_doc_free(rdoc);
    };
    fdb_iterator_close(iterator);

    // do compaction
    fdb_compact(db, (char *) "./dummy2");

    // range scan (after compaction)
    fdb_iterator_init(db, &iterator, NULL, 0, NULL, 0, 0x0);
    key_double_prev = -1;
    while(1){
        if ( (status = fdb_iterator_next(iterator, &rdoc)) == FDB_RESULT_ITERATOR_FAIL)
            break;
        memcpy(&key_double, rdoc->key, rdoc->keylen);
        TEST_CHK(key_double > key_double_prev);
        key_double_prev = key_double;
        fdb_doc_free(rdoc);
    };
    fdb_iterator_close(iterator);

    // close db file
    fdb_close(db);

    // free all documents
    for (i=0;i<n;++i){
        fdb_doc_free(doc[i]);
    }

    // free all resources
    fdb_shutdown();

    memleak_end();

    TEST_RESULT("custom compare function for primitive key test");
}

int _cmp_variable(void *key1, size_t keylen1, void *key2, size_t keylen2)
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
    uint64_t offset, count;
    fdb_handle *db;
    fdb_doc **doc = alca(fdb_doc*, n);
    fdb_doc *rdoc;
    fdb_status status;
    fdb_iterator *iterator;

    size_t keylen = 16;
    size_t prev_keylen;
    char keybuf[256], metabuf[256], bodybuf[256];
    char prev_key[256];

    // remove previous dummy files
    r = system(SHELL_DEL" dummy* > errorlog.txt");

    fdb_config fconfig = fdb_get_default_config();
    fconfig.buffercache_size = 0;
    fconfig.wal_threshold = 1024;
    fconfig.flags = FDB_OPEN_FLAG_CREATE;
    fconfig.cmp_variable = _cmp_variable;
    fconfig.compaction_threshold = 0;

    // open db with custom compare function for variable length key type
    fdb_open_cmp_variable(&db, "./dummy1", &fconfig);
    status = fdb_set_log_callback(db, logCallbackFunc,
                                  (void *) "custom_compare_variable_test");

    for (i=0;i<n;++i){
        for (j=0;j<2;++j){
            keybuf[j] = 'a' + rand()%('z'-'a');
        }
        sprintf(keybuf+2, "%06d", i);
        for (j=8;j<keylen-1;++j){
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
        TEST_CHK(!memcmp(rdoc->body, doc[i]->body, rdoc->bodylen));

        fdb_doc_free(rdoc);
    }

    // range scan (before flushing WAL)
    fdb_iterator_init(db, &iterator, NULL, 0, NULL, 0, 0x0);
    sprintf(prev_key, "%016d", 0);
    count = 0;
    prev_keylen = 16;
    while(1){
        if ( (status = fdb_iterator_next(iterator, &rdoc)) == FDB_RESULT_ITERATOR_FAIL)
            break;
        TEST_CHK(_cmp_variable(prev_key, prev_keylen, rdoc->key, rdoc->keylen) <= 0);
        prev_keylen = rdoc->keylen;
        memcpy(prev_key, rdoc->key, rdoc->keylen);
        fdb_doc_free(rdoc);
        count++;
    };
    TEST_CHK(count == n);
    fdb_iterator_close(iterator);

    fdb_commit(db, FDB_COMMIT_MANUAL_WAL_FLUSH);

    // range scan (after flushing WAL)
    fdb_iterator_init(db, &iterator, NULL, 0, NULL, 0, 0x0);
    sprintf(prev_key, "%016d", 0);
    count = 0;
    prev_keylen = 16;
    while(1){
        if ( (status = fdb_iterator_next(iterator, &rdoc)) == FDB_RESULT_ITERATOR_FAIL)
            break;
        TEST_CHK(_cmp_variable(prev_key, prev_keylen, rdoc->key, rdoc->keylen) <= 0);
        prev_keylen = rdoc->keylen;
        memcpy(prev_key, rdoc->key, rdoc->keylen);
        fdb_doc_free(rdoc);
        count++;
    };
    TEST_CHK(count == n);
    fdb_iterator_close(iterator);

    // do compaction
    fdb_compact(db, (char *) "./dummy2");

    // range scan (after compaction)
    fdb_iterator_init(db, &iterator, NULL, 0, NULL, 0, 0x0);
    sprintf(prev_key, "%016d", 0);
    count = 0;
    prev_keylen = 16;
    while(1){
        if ( (status = fdb_iterator_next(iterator, &rdoc)) == FDB_RESULT_ITERATOR_FAIL)
            break;
        TEST_CHK(_cmp_variable(prev_key, prev_keylen, rdoc->key, rdoc->keylen) <= 0);
        prev_keylen = rdoc->keylen;
        memcpy(prev_key, rdoc->key, rdoc->keylen);
        fdb_doc_free(rdoc);
        count++;
    };
    TEST_CHK(count == n);
    fdb_iterator_close(iterator);

    // close db file
    fdb_close(db);

    // free all documents
    for (i=0;i<n;++i){
        fdb_doc_free(doc[i]);
    }

    // free all resources
    fdb_shutdown();

    memleak_end();

    TEST_RESULT("custom compare function for variable length key test");
}

void snapshot_test()
{
    TEST_INIT();

    memleak_start();

    int i, r;
    int n = 20;
    int count;
    uint64_t offset;
    fdb_handle *db;
    fdb_handle *snap_db;
    fdb_seqnum_t snap_seq;
    fdb_doc **doc = alca(fdb_doc*, n);
    fdb_doc *rdoc;
    fdb_info info;
    fdb_status status;
    fdb_iterator *iterator;

    char keybuf[256], metabuf[256], bodybuf[256], temp[256];

    // remove previous dummy files
    r = system(SHELL_DEL" dummy* > errorlog.txt");

    fdb_config fconfig = fdb_get_default_config();
    fconfig.buffercache_size = 0;
    fconfig.wal_threshold = 1024;
    fconfig.flags = FDB_OPEN_FLAG_CREATE;
    fconfig.compaction_threshold = 0;

    // remove previous dummy files
    r = system(SHELL_DEL" dummy* > errorlog.txt");

    // open db
    status = fdb_open(&db, "./dummy1", &fconfig);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // Create a snapshot from an empty database file
    status = fdb_snapshot_open(db, &snap_db, 0);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    // check if snapshot's sequence number is zero.
    fdb_get_dbinfo(snap_db, &info);
    TEST_CHK(info.last_seqnum == 0);
    // create an iterator on the snapshot for full range
    fdb_iterator_init(snap_db, &iterator, NULL, 0, NULL, 0, FDB_ITR_NONE);
    // Iterator should not return any items.
    status = fdb_iterator_next(iterator, &rdoc);
    TEST_CHK(status == FDB_RESULT_ITERATOR_FAIL);
    fdb_iterator_close(iterator);
    fdb_close(snap_db);

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
    fdb_commit(db, FDB_COMMIT_MANUAL_WAL_FLUSH);

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
    fdb_commit(db, FDB_COMMIT_NORMAL);

    // Insert doc 9 now again with expected value..
    *(char *)doc[i]->body = 'b';
    fdb_set(db, doc[i]);
    // commit again without a WAL flush (these documents go into the AVL trees)
    fdb_commit(db, FDB_COMMIT_NORMAL);

    // TAKE SNAPSHOT: pick up sequence number of a commit without a WAL flush
    snap_seq = doc[i]->seqnum;

    // Now re-insert doc 9 as another duplicate (only newwer sequence number)
    fdb_set(db, doc[i]);
    // commit again without a WAL flush (last doc goes into the AVL tree)
    fdb_commit(db, FDB_COMMIT_NORMAL);

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
    fdb_commit(db, FDB_COMMIT_MANUAL_WAL_FLUSH);

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
    fdb_get_dbinfo(snap_db, &info);
    TEST_CHK(info.last_seqnum == snap_seq);

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
    fdb_commit(db, FDB_COMMIT_NORMAL);

    // create an iterator on the snapshot for full range
    fdb_iterator_init(snap_db, &iterator, NULL, 0, NULL, 0, FDB_ITR_NONE);

    // repeat until fail
    i=0;
    count=0;
    while(1){
        status = fdb_iterator_next(iterator, &rdoc);
        if (status == FDB_RESULT_ITERATOR_FAIL) break;

        TEST_CHK(!memcmp(rdoc->key, doc[i]->key, rdoc->keylen));
        TEST_CHK(!memcmp(rdoc->meta, doc[i]->meta, rdoc->metalen));
        TEST_CHK(!memcmp(rdoc->body, doc[i]->body, rdoc->bodylen));

        fdb_doc_free(rdoc);
        i ++;
        count++;
    }

    TEST_CHK(count==n/2); // Only unique items from the first half

    fdb_iterator_close(iterator);

    // close db file
    fdb_close(db);

    // close snapshot file
    fdb_close(snap_db);

    // free all documents
    for (i=0;i<n;++i){
        fdb_doc_free(doc[i]);
    }

    // free all resources
    fdb_shutdown();

    memleak_end();

    TEST_RESULT("snapshot test");
}

void rollback_test()
{
    TEST_INIT();

    memleak_start();

    int i, r;
    int n = 20;
    int count;
    uint64_t offset;
    fdb_handle *db, *db_txn;
    fdb_seqnum_t rollback_seq;
    fdb_doc **doc = alca(fdb_doc*, n);
    fdb_doc *rdoc;
    fdb_info info;
    fdb_status status;
    fdb_iterator *iterator;

    char keybuf[256], metabuf[256], bodybuf[256], temp[256];

    // remove previous dummy files
    r = system(SHELL_DEL" dummy* > errorlog.txt");

    fdb_config fconfig = fdb_get_default_config();
    fconfig.buffercache_size = 0;
    fconfig.wal_threshold = 1024;
    fconfig.flags = FDB_OPEN_FLAG_CREATE;
    fconfig.compaction_threshold = 0;

    // remove previous dummy files
    r = system(SHELL_DEL" dummy* > errorlog.txt");

    // open db
    fdb_open(&db, "./dummy1", &fconfig);

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
    fdb_commit(db, FDB_COMMIT_MANUAL_WAL_FLUSH);

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
    fdb_commit(db, FDB_COMMIT_NORMAL);

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
    fdb_commit(db, FDB_COMMIT_MANUAL_WAL_FLUSH);

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
    fdb_commit(db, FDB_COMMIT_NORMAL);

    status = fdb_set_log_callback(db, logCallbackFunc,
                                  (void *) "rollback_test");
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // ---------- Rollback tests begin -----------------------
    // We have DB file with 5 HB-trie docs, 5 unflushed WAL docs occuring twice
    // Attempt to rollback to out-of-range marker..
    status = fdb_rollback(&db, 999999);
    TEST_CHK(status == FDB_RESULT_NO_DB_INSTANCE);

    // Open another handle & begin transaction
    fdb_open(&db_txn, "./dummy1", &fconfig);
    fdb_begin_transaction(db_txn, FDB_ISOLATION_READ_COMMITTED);
    // Attempt to rollback while the transaction is active
    status =  fdb_rollback(&db, rollback_seq);
    // Must fail
    TEST_CHK(status == FDB_RESULT_FAIL_BY_TRANSACTION);
    fdb_abort_transaction(db_txn);
    fdb_close(db_txn);

    // Rollback to saved marker from above
    status = fdb_rollback(&db, rollback_seq);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // check handle's sequence number
    fdb_get_dbinfo(db, &info);
    TEST_CHK(info.last_seqnum == rollback_seq);

    // Modify an item and update into the rollbacked file..
    i = n/2;
    *(char *)doc[i]->body = 'B';
    fdb_set(db, doc[i]);
    fdb_commit(db, FDB_COMMIT_NORMAL);

    // create an iterator on the rollback for full range
    fdb_iterator_sequence_init(db, &iterator, 0, 0, FDB_ITR_NONE);

    // repeat until fail
    i=0;
    count=0;
    while(1){
        status = fdb_iterator_next(iterator, &rdoc);
        if (status == FDB_RESULT_ITERATOR_FAIL) break;

        TEST_CHK(!memcmp(rdoc->key, doc[i]->key, rdoc->keylen));
        TEST_CHK(!memcmp(rdoc->meta, doc[i]->meta, rdoc->metalen));
        TEST_CHK(!memcmp(rdoc->body, doc[i]->body, rdoc->bodylen));

        fdb_doc_free(rdoc);
        i ++;
        count++;
    }

    TEST_CHK(count==n/2 + 1); // Items from first half and newly set item

    fdb_iterator_close(iterator);

    // close db file
    fdb_close(db);

    // free all documents
    for (i=0;i<n;++i){
        fdb_doc_free(doc[i]);
    }

    // free all resources
    fdb_shutdown();

    memleak_end();

    TEST_RESULT("rollback test");
}

void doc_compression_test()
{
    TEST_INIT();

    memleak_start();

    int i, r;
    int n = 10;
    int dummy_len = 32;
    fdb_handle *db;
    fdb_doc **doc = alca(fdb_doc*, n);
    fdb_doc *rdoc;
    fdb_status status;

    char keybuf[256], metabuf[256], bodybuf[256], temp[256];

    // remove previous dummy files
    r = system(SHELL_DEL" dummy* > errorlog.txt");

    fdb_config fconfig = fdb_get_default_config();
    fconfig.buffercache_size = 0;
    fconfig.wal_threshold = 1024;
    fconfig.flags = FDB_OPEN_FLAG_CREATE;
    fconfig.compress_document_body = true;
    fconfig.compaction_threshold = 0;

    // open db
    fdb_open(&db, "./dummy1", &fconfig);
    status = fdb_set_log_callback(db, logCallbackFunc,
                                  (void *) "doc_compression_test");

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

    // commit
    fdb_commit(db, FDB_COMMIT_NORMAL);

    // close the db
    fdb_close(db);

    // reopen
    fdb_open(&db, "./dummy1", &fconfig);
    status = fdb_set_log_callback(db, logCallbackFunc,
                                  (void *) "doc_compression_test");

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
    fdb_commit(db, FDB_COMMIT_NORMAL);

    // retrieve documents
    for (i=0;i<n;++i){
        // search by key
        fdb_doc_create(&rdoc, doc[i]->key, doc[i]->keylen, NULL, 0, NULL, 0);
        status = fdb_get(db, rdoc);

        if (i != 5) {
            // updated documents
            TEST_CHK(status == FDB_RESULT_SUCCESS);
            TEST_CHK(!memcmp(rdoc->meta, doc[i]->meta, rdoc->metalen));
            TEST_CHK(!memcmp(rdoc->body, doc[i]->body, rdoc->bodylen));
        } else {
            // removed document
            TEST_CHK(status == FDB_RESULT_KEY_NOT_FOUND);
        }

        // free result document
        fdb_doc_free(rdoc);
    }

    // do compaction
    fdb_compact(db, (char *) "./dummy2");

    // retrieve documents after compaction
    for (i=0;i<n;++i){
        // search by key
        fdb_doc_create(&rdoc, doc[i]->key, doc[i]->keylen, NULL, 0, NULL, 0);
        status = fdb_get(db, rdoc);

        if (i != 5) {
            // updated documents
            TEST_CHK(status == FDB_RESULT_SUCCESS);
            TEST_CHK(!memcmp(rdoc->meta, doc[i]->meta, rdoc->metalen));
            TEST_CHK(!memcmp(rdoc->body, doc[i]->body, rdoc->bodylen));
        } else {
            // removed document
            TEST_CHK(status == FDB_RESULT_KEY_NOT_FOUND);
        }

        // free result document
        fdb_doc_free(rdoc);
    }

    // free all documents
    for (i=0;i<n;++i){
        fdb_doc_free(doc[i]);
    }

    // close db file
    fdb_close(db);

    // free all resources
    fdb_shutdown();

    memleak_end();

    TEST_RESULT("document compression test");
}

void read_doc_by_offset_test() {
	TEST_INIT();

    memleak_start();

    int i, r;
    int n = 100;
    fdb_handle *db;
    fdb_doc **doc = alca(fdb_doc*, n);
    fdb_doc *rdoc;
    fdb_status status;

    char keybuf[256], metabuf[256], bodybuf[256];

    // remove previous dummy files
    r = system(SHELL_DEL" dummy* > errorlog.txt");

    fdb_config fconfig = fdb_get_default_config();
    fconfig.buffercache_size = 0;
    fconfig.wal_threshold = 1024;
    fconfig.flags = FDB_OPEN_FLAG_CREATE;
    fconfig.purging_interval = 3600;
    fconfig.compaction_threshold = 0;

    // open db
    fdb_open(&db, "./dummy1", &fconfig);
    status = fdb_set_log_callback(db, logCallbackFunc,
                                  (void *) "read_doc_by_offset_test");

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
    fdb_commit(db, FDB_COMMIT_NORMAL);

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

    // commit
    fdb_commit(db, FDB_COMMIT_NORMAL);

    fdb_doc_create(&rdoc, doc[5]->key, doc[5]->keylen, NULL, 0, NULL, 0);
    status = fdb_get_metaonly(db, rdoc);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    TEST_CHK(rdoc->deleted == false);
    TEST_CHK(!memcmp(rdoc->meta, doc[5]->meta, rdoc->metalen));
    // Fetch #5 doc using its offset.
    status = fdb_get_byoffset(db, rdoc);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    TEST_CHK(rdoc->deleted == false);
    TEST_CHK(!memcmp(rdoc->meta, doc[5]->meta, rdoc->metalen));
    TEST_CHK(!memcmp(rdoc->body, doc[5]->body, rdoc->bodylen));
    fdb_doc_free(rdoc);

    // do compaction
    fdb_compact(db, (char *) "./dummy2");

    fdb_doc_create(&rdoc, doc[50]->key, doc[50]->keylen, NULL, 0, NULL, 0);
    status = fdb_get_metaonly(db, rdoc);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    TEST_CHK(rdoc->deleted == true);
    TEST_CHK(!memcmp(rdoc->meta, doc[50]->meta, rdoc->metalen));
    // Fetch #50 doc using its offset.
    status = fdb_get_byoffset(db, rdoc);
    TEST_CHK(status == FDB_RESULT_KEY_NOT_FOUND);
    TEST_CHK(rdoc->deleted == true);
    fdb_doc_free(rdoc);

    // free all documents
    for (i=0;i<n;++i){
        fdb_doc_free(doc[i]);
    }

    // close db file
    fdb_close(db);

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
    fdb_handle *db;
    fdb_handle *db_rdonly;
    fdb_doc **doc = alca(fdb_doc*, n);
    fdb_doc *rdoc;
    fdb_status status;

    char keybuf[256], metabuf[256], bodybuf[256], temp[256];

    // remove previous dummy files
    r = system(SHELL_DEL" dummy* fdb_test_config.json > errorlog.txt");

    fdb_config fconfig = fdb_get_default_config();
    fconfig.buffercache_size = 0;
    fconfig.wal_threshold = 1024;
    fconfig.flags = FDB_OPEN_FLAG_CREATE;
    fconfig.purging_interval = 2;
    fconfig.compaction_threshold = 0;

    // open db
    fdb_open(&db, "./dummy1", &fconfig);
    status = fdb_set_log_callback(db, logCallbackFunc,
                                  (void *) "purge_logically_deleted_doc_test");

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

    // commit
    fdb_commit(db, FDB_COMMIT_NORMAL);

    // do compaction
    fdb_compact(db, (char *) "./dummy2");

    // retrieve documents after compaction
    for (i=0;i<n;++i){
        // search by key
        fdb_doc_create(&rdoc, doc[i]->key, doc[i]->keylen, NULL, 0, NULL, 0);
        status = fdb_get(db, rdoc);

        if (i != 5) {
            // updated documents
            TEST_CHK(status == FDB_RESULT_SUCCESS);
            TEST_CHK(!memcmp(rdoc->meta, doc[i]->meta, rdoc->metalen));
            TEST_CHK(!memcmp(rdoc->body, doc[i]->body, rdoc->bodylen));
        } else {
            // removed document
            TEST_CHK(status == FDB_RESULT_KEY_NOT_FOUND);
        }
        // free result document
        fdb_doc_free(rdoc);

        // retrieve metadata
        // all documents including logically deleted document should exist
        fdb_doc_create(&rdoc, doc[i]->key, doc[i]->keylen, NULL, 0, NULL, 0);
        status = fdb_get_metaonly(db, rdoc);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        fdb_doc_free(rdoc);
    }

    printf("wait for 3 seconds..\n");
    sleep(3);

    // do one more compaction
    fdb_compact(db, (char *) "./dummy3");

    // retrieve documents after compaction
    for (i=0;i<n;++i){
        // search by key
        fdb_doc_create(&rdoc, doc[i]->key, doc[i]->keylen, NULL, 0, NULL, 0);
        status = fdb_get(db, rdoc);

        if (i != 5) {
            // updated documents
            TEST_CHK(status == FDB_RESULT_SUCCESS);
            TEST_CHK(!memcmp(rdoc->meta, doc[i]->meta, rdoc->metalen));
            TEST_CHK(!memcmp(rdoc->body, doc[i]->body, rdoc->bodylen));
        } else {
            // removed document
            TEST_CHK(status == FDB_RESULT_KEY_NOT_FOUND);
        }
        // free result document
        fdb_doc_free(rdoc);

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
    }

    // close db file
    fdb_close(db);

    // free all documents
    for (i=0;i<n;++i){
        fdb_doc_free(doc[i]);
    }

    // free all resources
    fdb_shutdown();

    memleak_end();

    TEST_RESULT("purge logically deleted doc test");
}

void compaction_daemon_test(size_t time_sec)
{
    TEST_INIT();

    memleak_start();

    int i, j, r;
    int n = 10000;
    int compaction_threshold = 30;
    int escape = 0;
    fdb_handle *db, *db_less, *db_non, *db_manual, *db_new;
    fdb_handle *snapshot;
    fdb_doc **doc = alca(fdb_doc*, n);
    fdb_doc *rdoc;
    fdb_info info;
    fdb_status status;
    struct timeval ts_begin, ts_cur, ts_gap;

    char keybuf[256], metabuf[256], bodybuf[256], temp[256];

    // remove previous dummy files
    r = system(SHELL_DEL" dummy* > errorlog.txt");

    fdb_config fconfig = fdb_get_default_config();
    fconfig.buffercache_size = 0;
    fconfig.wal_threshold = 1024;
    fconfig.flags = FDB_OPEN_FLAG_CREATE;
    fconfig.compaction_mode = FDB_COMPACTION_AUTO;
    fconfig.compaction_threshold = compaction_threshold;
    fconfig.compactor_sleep_duration = 1; // for quick test

    // open db
    fdb_open(&db, "dummy", &fconfig);
    status = fdb_set_log_callback(db, logCallbackFunc,
                                  (void *) "compaction_daemon_test");
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
    fdb_commit(db, FDB_COMMIT_NORMAL);
    // close db file
    fdb_close(db);

    // ---- basic retrieve test ------------------------
    // reopen db file
    status = fdb_open(&db, "dummy", &fconfig);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_set_log_callback(db, logCallbackFunc,
                                  (void *) "compaction_daemon_test");
    // check db filename
    fdb_get_dbinfo(db, &info);
    TEST_CHK(!strcmp(info.filename, "dummy"));

    // retrieve documents
    for (i=0;i<n;++i){
        sprintf(keybuf, "key%04d", i);
        fdb_doc_create(&rdoc, (void*)keybuf, strlen(keybuf)+1,
            NULL, 0, NULL, 0);
        status = fdb_get(db, rdoc);
        //printf("%s %s\n", rdoc->key, rdoc->body);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        TEST_CHK(!memcmp(rdoc->body, doc[i]->body, rdoc->bodylen));
        fdb_doc_free(rdoc);
    }

    // create a snapshot
    status = fdb_snapshot_open(db, &snapshot, n);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    // close snapshot
    fdb_close(snapshot);

    // close db file
    fdb_close(db);

    // ---- handling when metafile is removed ------------
    // remove meta file
    r = system(SHELL_DEL" dummy.meta > errorlog.txt");
    // reopen db file
    status = fdb_open(&db, "dummy", &fconfig);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_set_log_callback(db, logCallbackFunc,
                                  (void *) "compaction_daemon_test");
    // retrieve documents
    for (i=0;i<n;++i){
        sprintf(keybuf, "key%04d", i);
        fdb_doc_create(&rdoc, (void*)keybuf, strlen(keybuf)+1,
            NULL, 0, NULL, 0);
        status = fdb_get(db, rdoc);
        //printf("%s %s\n", rdoc->key, rdoc->body);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        TEST_CHK(!memcmp(rdoc->body, doc[i]->body, rdoc->bodylen));
        fdb_doc_free(rdoc);
    }
    // close db file
    fdb_close(db);

    // ---- handling when metafile points to non-exist file ------------
    // remove meta file
    r = system(SHELL_MOVE" dummy.0 dummy.23 > errorlog.txt");
    // reopen db file
    status = fdb_open(&db, "dummy", &fconfig);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_set_log_callback(db, logCallbackFunc,
                                  (void *) "compaction_daemon_test");
    // retrieve documents
    for (i=0;i<n;++i){
        sprintf(keybuf, "key%04d", i);
        fdb_doc_create(&rdoc, (void*)keybuf, strlen(keybuf)+1,
            NULL, 0, NULL, 0);
        status = fdb_get(db, rdoc);
        //printf("%s %s\n", rdoc->key, rdoc->body);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        TEST_CHK(!memcmp(rdoc->body, doc[i]->body, rdoc->bodylen));
        fdb_doc_free(rdoc);
    }
    // close db file
    fdb_close(db);

    // ---- compaction daemon test -------------------
    // db: DB instance to be compacted
    // db_less: DB instance to be compacted but with much lower update throughput
    // db_non: DB instance not to be compacted (auto compaction with threshold = 0)
    // db_manual: DB instance not to be compacted (manual compaction)

    // open & create db_less, db_non and db_manual
    status = fdb_open(&db_less, "dummy_less", &fconfig);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    fconfig.compaction_threshold = 0;
    status = fdb_open(&db_non, "dummy_non", &fconfig);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    fconfig.compaction_mode = FDB_COMPACTION_MANUAL;
    status = fdb_open(&db_manual, "dummy_manual", &fconfig);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // reopen db file
    fconfig.compaction_threshold = 30;
    fconfig.compaction_mode = FDB_COMPACTION_AUTO;
    status = fdb_open(&db, "dummy", &fconfig);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_set_log_callback(db, logCallbackFunc,
                                  (void *) "compaction_daemon_test");
    // continuously update documents
    printf("wait for %d seconds..\n", (int)time_sec);
    gettimeofday(&ts_begin, NULL);
    while(!escape) {
        for (i=0;i<n;++i){
            // update db
            fdb_set(db, doc[i]);
            fdb_commit(db, FDB_COMMIT_NORMAL);

            // update db_less (1/100 throughput)
            if (i%100 == 0){
                fdb_set(db_less, doc[i]);
                fdb_commit(db_less, FDB_COMMIT_NORMAL);
            }

            // update db_non
            fdb_set(db_non, doc[i]);
            fdb_commit(db_non, FDB_COMMIT_NORMAL);

            // update db_manual
            fdb_set(db_manual, doc[i]);
            fdb_commit(db_manual, FDB_COMMIT_NORMAL);

            gettimeofday(&ts_cur, NULL);
            ts_gap = _utime_gap(ts_begin, ts_cur);
            if (ts_gap.tv_sec >= time_sec) {
                escape = 1;
                break;
            }
        }
    }

    // perform manual compaction of auto-compact file
    status = fdb_compact(db_non, NULL);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // perform manual compaction of manual-compact file
    status = fdb_compact(db_manual, "dummy_manual_compacted");
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // open dummy_manual_compacted using new db handle
    fconfig.compaction_mode = FDB_COMPACTION_MANUAL;
    status = fdb_open(&db_new, "dummy_manual_compacted", &fconfig);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // try to switch compaction mode
    status = fdb_switch_compaction_mode(db_manual, FDB_COMPACTION_AUTO, 30);
    TEST_CHK(status == FDB_RESULT_FILE_IS_BUSY);

    // close db_new
    status = fdb_close(db_new);

    // switch compaction mode of 'db_manual' from MANUAL to AUTO
    status = fdb_switch_compaction_mode(db_manual, FDB_COMPACTION_AUTO, 30);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // close and open with auto-compact option
    status = fdb_close(db_manual);
    fconfig.compaction_mode = FDB_COMPACTION_AUTO;
    status = fdb_open(&db_manual, "dummy_manual_compacted", &fconfig);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // switch compaction mode of 'db_non' from AUTO to MANUAL
    status = fdb_switch_compaction_mode(db_non, FDB_COMPACTION_MANUAL, 0);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // close and open with manual-compact option
    status = fdb_close(db_non);
    fconfig.compaction_mode = FDB_COMPACTION_MANUAL;
    status = fdb_open(&db_non, "dummy_non", &fconfig);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // close db files
    fdb_close(db);
    fdb_close(db_less);
    fdb_close(db_non);
    fdb_close(db_manual);

    // open manual compact file (dummy_non) using auto compact mode
    fconfig.compaction_mode = FDB_COMPACTION_AUTO;
    status = fdb_open(&db, "dummy_non", &fconfig);
    TEST_CHK(status == FDB_RESULT_INVALID_COMPACTION_MODE);

    // open auto copmact file (dummy_manual_compacted) using manual compact mode
    fconfig.compaction_mode = FDB_COMPACTION_MANUAL;
    status = fdb_open(&db, "dummy_manual_compacted", &fconfig);
    TEST_CHK(status == FDB_RESULT_INVALID_COMPACTION_MODE);

    // free all documents
    for (i=0;i<n;++i){
        fdb_doc_free(doc[i]);
    }

    // free all resources
    fdb_shutdown();

    memleak_end();

    TEST_RESULT("compaction daemon test");
}

void api_wrapper_test()
{
    TEST_INIT();

    memleak_start();

    int i, r;
    int n = 10;
    size_t valuelen;
    void *value;
    fdb_handle *db;
    fdb_status status;

    char keybuf[256], bodybuf[256], temp[256];

    // remove previous dummy files
    r = system(SHELL_DEL" dummy* > errorlog.txt");

    fdb_config fconfig = fdb_get_default_config();
    fconfig.buffercache_size = 0;
    fconfig.wal_threshold = 1024;
    fconfig.flags = FDB_OPEN_FLAG_CREATE;
    fconfig.purging_interval = 0;
    fconfig.compaction_threshold = 0;

    // open db
    fdb_open(&db, "./dummy1", &fconfig);
    status = fdb_set_log_callback(db, logCallbackFunc,
                                  (void *) "api_wrapper_test");

    // error check
    status = fdb_set_kv(db, NULL, 0, NULL, 0);
    TEST_CHK(status == FDB_RESULT_INVALID_ARGS);

    // insert key-value pairs
    for (i=0;i<n;++i){
        sprintf(keybuf, "key%d", i);
        sprintf(bodybuf, "body%d", i);
        status = fdb_set_kv(db, keybuf, strlen(keybuf), bodybuf, strlen(bodybuf));
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
            TEST_CHK(!memcmp(value, temp, valuelen));
            free(value);
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
    fdb_close(db);

    // free all resources
    fdb_shutdown();

    memleak_end();

    TEST_RESULT("API wrapper test");
}

void transaction_test()
{
    TEST_INIT();

    memleak_start();

    int i, r;
    int n = 10;
    size_t valuelen;
    void *value;
    fdb_handle *db, *db_txn1, *db_txn2, *db_txn3;
    fdb_doc **doc = alca(fdb_doc*, n);
    fdb_doc *rdoc;
    fdb_status status;

    char keybuf[256], metabuf[256], bodybuf[256], temp[256];

    // remove previous dummy files
    r = system(SHELL_DEL" dummy* > errorlog.txt");

    fdb_config fconfig = fdb_get_default_config();
    fconfig.buffercache_size = 0;
    fconfig.wal_threshold = 1024;
    fconfig.flags = FDB_OPEN_FLAG_CREATE;
    fconfig.purging_interval = 0;
    fconfig.compaction_threshold = 0;

    // open db
    fdb_open(&db, "dummy1", &fconfig);
    status = fdb_set_log_callback(db, logCallbackFunc,
                                  (void *) "transaction_test");

    // open db and begin transactions
    fdb_open(&db_txn1, "dummy1", &fconfig);
    fdb_open(&db_txn2, "dummy1", &fconfig);
    fdb_begin_transaction(db_txn1, FDB_ISOLATION_READ_COMMITTED);
    fdb_begin_transaction(db_txn2, FDB_ISOLATION_READ_COMMITTED);

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
    fdb_open(&db_txn3, "dummy1", &fconfig);
    fdb_begin_transaction(db_txn3, FDB_ISOLATION_READ_UNCOMMITTED);
    for (i=0;i<n;++i){
        sprintf(keybuf, "key%d", i);
        fdb_doc_create(&rdoc, (void*)keybuf, strlen(keybuf), NULL, 0, NULL, 0);
        status = fdb_get(db_txn3, rdoc);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        fdb_doc_free(rdoc);
    }
    fdb_end_transaction(db_txn3, FDB_COMMIT_NORMAL);
    fdb_close(db_txn3);

    // commit and end txn1
    fdb_end_transaction(db_txn1, FDB_COMMIT_NORMAL);

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
    fdb_abort_transaction(db_txn2);

    // close & re-open db file
    fdb_close(db);
    fdb_open(&db, "dummy1", &fconfig);
    status = fdb_set_log_callback(db, logCallbackFunc,
                                  (void *) "transaction_test");

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
    fdb_commit(db, FDB_COMMIT_NORMAL);

    // now all docs can be read generally
    for (i=0;i<n;++i){
        sprintf(keybuf, "key%d", i);
        fdb_doc_create(&rdoc, (void*)keybuf, strlen(keybuf), NULL, 0, NULL, 0);
        status = fdb_get(db, rdoc);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        fdb_doc_free(rdoc);
    }

    // begin transactions
    fdb_begin_transaction(db_txn1, FDB_ISOLATION_READ_COMMITTED);
    fdb_begin_transaction(db_txn2, FDB_ISOLATION_READ_COMMITTED);

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
        TEST_CHK(!memcmp(rdoc->body, doc[i]->body, rdoc->bodylen));
        fdb_doc_free(rdoc);

        // get from txn1
        fdb_doc_create(&rdoc, (void*)keybuf, strlen(keybuf), NULL, 0, NULL, 0);
        status = fdb_get(db_txn1, rdoc);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        sprintf(bodybuf, "body%d_txn1", i);
        TEST_CHK(!memcmp(rdoc->body, bodybuf, rdoc->bodylen));
        fdb_doc_free(rdoc);

        // get from txn2
        fdb_doc_create(&rdoc, (void*)keybuf, strlen(keybuf), NULL, 0, NULL, 0);
        status = fdb_get(db_txn2, rdoc);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        sprintf(bodybuf, "body%d_txn2", i);
        TEST_CHK(!memcmp(rdoc->body, bodybuf, rdoc->bodylen));
        fdb_doc_free(rdoc);
    }

    // commit txn2 & retrieve check
    fdb_end_transaction(db_txn2, FDB_COMMIT_NORMAL);
    for (i=0;i<n;++i){
        // general retrieval
        sprintf(keybuf, "key%d", i);
        fdb_doc_create(&rdoc, (void*)keybuf, strlen(keybuf), NULL, 0, NULL, 0);
        status = fdb_get(db, rdoc);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        sprintf(bodybuf, "body%d_txn2", i);
        TEST_CHK(!memcmp(rdoc->body, bodybuf, rdoc->bodylen));
        fdb_doc_free(rdoc);

        // get from txn1
        fdb_doc_create(&rdoc, (void*)keybuf, strlen(keybuf), NULL, 0, NULL, 0);
        status = fdb_get(db_txn1, rdoc);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        sprintf(bodybuf, "body%d_txn1", i);
        TEST_CHK(!memcmp(rdoc->body, bodybuf, rdoc->bodylen));
        fdb_doc_free(rdoc);
    }

    // commit txn1 & retrieve check
    fdb_end_transaction(db_txn1, FDB_COMMIT_NORMAL);
    for (i=0;i<n;++i){
        // general retrieval
        sprintf(keybuf, "key%d", i);
        fdb_doc_create(&rdoc, (void*)keybuf, strlen(keybuf), NULL, 0, NULL, 0);
        status = fdb_get(db, rdoc);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        sprintf(bodybuf, "body%d_txn1", i);
        TEST_CHK(!memcmp(rdoc->body, bodybuf, rdoc->bodylen));
        fdb_doc_free(rdoc);
    }

    // begin new transaction
    fdb_begin_transaction(db_txn1, FDB_ISOLATION_READ_COMMITTED);
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
    fdb_compact(db, "dummy2");

    // retrieve doc#5
    // using txn1
    fdb_doc_create(&rdoc, (void*)keybuf, strlen(keybuf), NULL, 0, NULL, 0);
    status = fdb_get(db_txn1, rdoc);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    TEST_CHK(!memcmp(rdoc->body, bodybuf, rdoc->bodylen));
    fdb_doc_free(rdoc);

    // general retrieval
    fdb_doc_create(&rdoc, (void*)keybuf, strlen(keybuf), NULL, 0, NULL, 0);
    status = fdb_get(db, rdoc);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    sprintf(bodybuf, "body%d_txn1", i);
    TEST_CHK(!memcmp(rdoc->body, bodybuf, rdoc->bodylen));
    fdb_doc_free(rdoc);

    // commit transaction
    fdb_end_transaction(db_txn1, FDB_COMMIT_NORMAL);
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
        TEST_CHK(!memcmp(rdoc->body, bodybuf, rdoc->bodylen));
        fdb_doc_free(rdoc);
    }

    // close & re-open db file
    fdb_close(db);
    fdb_open(&db, "dummy2", &fconfig);
    status = fdb_set_log_callback(db, logCallbackFunc,
                                  (void *) "transaction_test");
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
        TEST_CHK(!memcmp(rdoc->body, bodybuf, rdoc->bodylen));
        fdb_doc_free(rdoc);
    }

    // close db file
    fdb_close(db);
    fdb_close(db_txn1);
    fdb_close(db_txn2);

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
    fdb_handle *db, *db_txn1, *db_txn2;
    fdb_status status;

    char keybuf[256], bodybuf[256], temp[256];

    // remove previous dummy files
    r = system(SHELL_DEL" dummy* > errorlog.txt");

    fdb_config fconfig = fdb_get_default_config();
    fconfig.buffercache_size = 0;
    fconfig.wal_threshold = 1024;
    fconfig.flags = FDB_OPEN_FLAG_CREATE;
    fconfig.purging_interval = 0;
    fconfig.compaction_threshold = 0;

    // open db
    fdb_open(&db, "./dummy1", &fconfig);
    status = fdb_set_log_callback(db, logCallbackFunc,
                                  (void *) "transaction_simple_api_test");

    // insert key-value pairs
    for (i=0;i<n;++i){
        sprintf(keybuf, "key%d", i);
        sprintf(bodybuf, "body%d", i);
        status = fdb_set_kv(db, keybuf, strlen(keybuf), bodybuf, strlen(bodybuf));
    }

    // commit
    fdb_commit(db, FDB_COMMIT_NORMAL);

    // open db and begin transactions
    fdb_open(&db_txn1, "./dummy1", &fconfig);
    fdb_open(&db_txn2, "./dummy1", &fconfig);
    fdb_begin_transaction(db_txn1, FDB_ISOLATION_READ_COMMITTED);
    fdb_begin_transaction(db_txn2, FDB_ISOLATION_READ_COMMITTED);

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
        TEST_CHK(!memcmp(value, bodybuf, valuelen));
        free(value);

        // txn1
        sprintf(keybuf, "key%d", i);
        sprintf(bodybuf, "body%d_txn1", i);
        status = fdb_get_kv(db_txn1, keybuf, strlen(keybuf), &value, &valuelen);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        TEST_CHK(!memcmp(value, bodybuf, valuelen));
        free(value);

        // txn2
        sprintf(keybuf, "key%d", i);
        sprintf(bodybuf, "body%d_txn2", i);
        status = fdb_get_kv(db_txn2, keybuf, strlen(keybuf), &value, &valuelen);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        TEST_CHK(!memcmp(value, bodybuf, valuelen));
        free(value);
    }

    // commit txn1
    fdb_end_transaction(db_txn1, FDB_COMMIT_NORMAL);
    for (i=0;i<n;++i){
        // general retrieval
        sprintf(keybuf, "key%d", i);
        sprintf(bodybuf, "body%d_txn1", i);
        status = fdb_get_kv(db, keybuf, strlen(keybuf), &value, &valuelen);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        TEST_CHK(!memcmp(value, bodybuf, valuelen));
        free(value);

        // txn2
        sprintf(keybuf, "key%d", i);
        sprintf(bodybuf, "body%d_txn2", i);
        status = fdb_get_kv(db_txn2, keybuf, strlen(keybuf), &value, &valuelen);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        TEST_CHK(!memcmp(value, bodybuf, valuelen));
        free(value);
    }

    // commit txn2
    fdb_end_transaction(db_txn2, FDB_COMMIT_NORMAL);
    for (i=0;i<n;++i){
        // general retrieval
        sprintf(keybuf, "key%d", i);
        sprintf(bodybuf, "body%d_txn2", i);
        status = fdb_get_kv(db, keybuf, strlen(keybuf), &value, &valuelen);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        TEST_CHK(!memcmp(value, bodybuf, valuelen));
        free(value);
    }

    // close db file
    fdb_close(db);
    fdb_close(db_txn1);
    fdb_close(db_txn2);

    // free all resources
    fdb_shutdown();

    memleak_end();

    TEST_RESULT("transaction simple API test");
}

void flush_before_commit_test()
{
    TEST_INIT();

    memleak_start();

    int i, r;
    int n = 30;
    size_t valuelen;
    void *value;
    fdb_handle *db, *db_txn;
    fdb_doc **doc = alca(fdb_doc*, n);
    fdb_doc *rdoc;
    fdb_status status;

    char keybuf[256], metabuf[256], bodybuf[256], temp[256];

    // remove previous dummy files
    r = system(SHELL_DEL" dummy* > errorlog.txt");

    fdb_config fconfig = fdb_get_default_config();
    fconfig.buffercache_size = 0;
    fconfig.wal_threshold = 5;
    fconfig.flags = FDB_OPEN_FLAG_CREATE;
    fconfig.purging_interval = 0;
    fconfig.compaction_threshold = 0;
    fconfig.wal_flush_before_commit = true;

    // open db
    fdb_open(&db, "dummy1", &fconfig);
    fdb_open(&db_txn, "dummy1", &fconfig);
    status = fdb_set_log_callback(db_txn, logCallbackFunc,
                                  (void *) "flush_before_commit_test");

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
    fdb_begin_transaction(db_txn, FDB_ISOLATION_READ_COMMITTED);
    for (i=0;i<2;++i){
        fdb_set(db, doc[i]);
    }
    fdb_commit(db, FDB_COMMIT_NORMAL);
    for (i=0;i<2;++i){
        fdb_set(db_txn, doc[i]);
    }
    fdb_end_transaction(db_txn, FDB_COMMIT_NORMAL);
    fdb_commit(db, FDB_COMMIT_MANUAL_WAL_FLUSH);

    // transactional commit first, non-transactional commit next
    fdb_begin_transaction(db_txn, FDB_ISOLATION_READ_COMMITTED);
    for (i=0;i<2;++i){
        fdb_set(db_txn, doc[i]);
    }
    fdb_end_transaction(db_txn, FDB_COMMIT_NORMAL);
    for (i=0;i<2;++i){
        fdb_set(db, doc[i]);
    }
    fdb_commit(db, FDB_COMMIT_NORMAL);
    fdb_commit(db, FDB_COMMIT_MANUAL_WAL_FLUSH);

    // concurrent update (non-txn commit first, txn commit next)
    fdb_begin_transaction(db_txn, FDB_ISOLATION_READ_COMMITTED);
    for (i=0;i<2;++i){
        fdb_set(db_txn, doc[i]);
    }
    for (i=0;i<2;++i){
        fdb_set(db, doc[i]);
    }
    fdb_commit(db, FDB_COMMIT_NORMAL);
    fdb_end_transaction(db_txn, FDB_COMMIT_NORMAL);
    fdb_commit(db, FDB_COMMIT_MANUAL_WAL_FLUSH);

    // concurrent update (txn commit first, non-txn commit next)
    fdb_begin_transaction(db_txn, FDB_ISOLATION_READ_COMMITTED);
    for (i=0;i<2;++i){
        fdb_set(db, doc[i]);
    }
    for (i=0;i<2;++i){
        fdb_set(db_txn, doc[i]);
    }
    fdb_end_transaction(db_txn, FDB_COMMIT_NORMAL);
    fdb_commit(db, FDB_COMMIT_NORMAL);
    fdb_commit(db, FDB_COMMIT_MANUAL_WAL_FLUSH);

    // begin transaction
    fdb_begin_transaction(db_txn, FDB_ISOLATION_READ_COMMITTED);

    // insert docs using transaction
    for (i=0;i<10;++i){
        fdb_set(db_txn, doc[i]);
    }

    // insert docs without transaction
    for (i=10;i<20;++i){
        fdb_set(db, doc[i]);
    }

    // do compaction
    fdb_compact(db, "dummy2");

    for (i=20;i<25;++i){
        fdb_set(db_txn, doc[i]);
    }
    // end transaction
    fdb_end_transaction(db_txn, FDB_COMMIT_NORMAL);

    for (i=25;i<30;++i){
        fdb_set(db, doc[i]);
    }

    // close db file
    fdb_close(db);
    fdb_close(db_txn);

    // free all documents
    for (i=0;i<n;++i){
        fdb_doc_free(doc[i]);
    }

    // free all resources
    fdb_shutdown();

    memleak_end();

    TEST_RESULT("flush before commit test");
}

void last_wal_flush_header_test()
{
    TEST_INIT();

    memleak_start();

    int i, r;
    int n = 30;
    size_t valuelen;
    void *value;
    fdb_handle *db, *db_txn1, *db_txn2;
    fdb_doc **doc = alca(fdb_doc*, n);
    fdb_doc *rdoc;
    fdb_status status;

    char keybuf[256], metabuf[256], bodybuf[256], temp[256];

    // remove previous dummy files
    r = system(SHELL_DEL" dummy* > errorlog.txt");

    fdb_config fconfig = fdb_get_default_config();
    fconfig.buffercache_size = 0;
    fconfig.flags = FDB_OPEN_FLAG_CREATE;
    fconfig.purging_interval = 0;
    fconfig.compaction_threshold = 0;

    // open db
    fdb_open(&db, "dummy1", &fconfig);
    fdb_open(&db_txn1, "dummy1", &fconfig);

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
    fdb_begin_transaction(db_txn1, FDB_ISOLATION_READ_COMMITTED);
    for (i=2;i<4;++i){
        fdb_set(db_txn1, doc[i]);
    }
    // commit without transaction
    fdb_commit(db, FDB_COMMIT_MANUAL_WAL_FLUSH);

    // close & reopen db
    fdb_close(db);
    fdb_close(db_txn1);
    fdb_open(&db, "dummy1", &fconfig);
    fdb_open(&db_txn1, "dummy1", &fconfig);

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
    }

    // insert docs using transaction
    fdb_begin_transaction(db_txn1, FDB_ISOLATION_READ_COMMITTED);
    for (i=2;i<4;++i){
        fdb_set(db_txn1, doc[i]);
    }
    // insert docs without transaction
    for (i=4;i<6;++i){
        fdb_set(db, doc[i]);
    }
    fdb_end_transaction(db_txn1, FDB_COMMIT_MANUAL_WAL_FLUSH);

    // close & reopen db
    fdb_close(db);
    fdb_close(db_txn1);
    fdb_open(&db, "dummy1", &fconfig);
    fdb_open(&db_txn1, "dummy1", &fconfig);

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
    }

    // insert docs without transaction
    for (i=4;i<6;++i) {
        fdb_set(db, doc[i]);
    }
    fdb_begin_transaction(db_txn1, FDB_ISOLATION_READ_COMMITTED);
    for (i=6;i<8;++i) {
        fdb_set(db_txn1, doc[i]);
    }
    fdb_commit(db, FDB_COMMIT_MANUAL_WAL_FLUSH);

    // begin another transaction
    fdb_open(&db_txn2, "dummy1", &fconfig);
    fdb_begin_transaction(db_txn2, FDB_ISOLATION_READ_COMMITTED);
    for (i=8;i<10;++i){
        fdb_set(db_txn2, doc[i]);
    }
    fdb_end_transaction(db_txn2, FDB_COMMIT_MANUAL_WAL_FLUSH);

    // close & reopen db
    fdb_close(db);
    fdb_close(db_txn1);
    fdb_close(db_txn2);
    fdb_open(&db, "dummy1", &fconfig);

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
    }

    fdb_open(&db_txn1, "dummy1", &fconfig);
    fdb_open(&db_txn2, "dummy1", &fconfig);
    fdb_begin_transaction(db_txn1, FDB_ISOLATION_READ_COMMITTED);

    fdb_set(db, doc[10]);
    fdb_commit(db, FDB_COMMIT_MANUAL_WAL_FLUSH);

    fdb_set(db, doc[11]);
    fdb_set(db_txn1, doc[12]);
    fdb_commit(db, FDB_COMMIT_MANUAL_WAL_FLUSH);

    fdb_set(db_txn1, doc[13]);
    fdb_begin_transaction(db_txn2, FDB_ISOLATION_READ_COMMITTED);
    fdb_set(db_txn2, doc[14]);
    fdb_end_transaction(db_txn1, FDB_COMMIT_MANUAL_WAL_FLUSH);

    fdb_set(db_txn2, doc[15]);
    fdb_set(db, doc[16]);
    fdb_end_transaction(db_txn2, FDB_COMMIT_MANUAL_WAL_FLUSH);

    fdb_set(db, doc[17]);
    fdb_commit(db, FDB_COMMIT_NORMAL);

    fdb_close(db);
    fdb_close(db_txn1);
    fdb_close(db_txn2);
    fdb_open(&db, "dummy1", &fconfig);

    // retrieve check
    for (i=10;i<18;++i){
        fdb_doc_create(&rdoc, doc[i]->key, doc[i]->keylen, NULL, 0, NULL, 0);
        status = fdb_get(db, rdoc);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        fdb_doc_free(rdoc);
    }

    fdb_open(&db_txn1, "dummy1", &fconfig);
    fdb_begin_transaction(db_txn1, FDB_ISOLATION_READ_COMMITTED);
    fdb_set(db_txn1, doc[20]);

    fdb_compact(db, "dummy2");

    fdb_end_transaction(db_txn1, FDB_COMMIT_MANUAL_WAL_FLUSH);
    fdb_close(db);
    fdb_close(db_txn1);

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

    int i, j, idx, r;
    int n=300, m=20; // n: # prefixes, m: # postfixes
    int keylen_limit = 3840; // need to modify if FDB_MAX_KEYLEN is changed
    size_t valuelen;
    void *value;
    fdb_handle *db;
    fdb_doc **doc = alca(fdb_doc*, n*m);
    fdb_doc *rdoc;
    fdb_status status;

    char *keybuf = alca(char, keylen_limit);
    char metabuf[256], bodybuf[256], temp[256];

    // remove previous dummy files
    r = system(SHELL_DEL" dummy* > errorlog.txt");

    fdb_config fconfig = fdb_get_default_config();
    fconfig.buffercache_size = 0;
    fconfig.flags = FDB_OPEN_FLAG_CREATE;
    fconfig.purging_interval = 0;
    fconfig.compaction_threshold = 0;

    // open db
    fdb_open(&db, "dummy1", &fconfig);

    // key structure:
    // <----------------- 3840 bytes ------------------>
    // <-- 8 bytes -->             <-- 8 bytes  -->< 1 >
    // [prefix number]____ ... ____[postfix number][ \0]
    // e.g.)
    // 00000001____ ... ____00000013[\0]

    // create docs
    for (i=0;i<keylen_limit-1;++i){
        keybuf[i] = '_';
    }
    keybuf[keylen_limit-1] = 0;

    for (i=0;i<n;++i){
        // set prefix
        sprintf(temp, "%08d", i);
        memcpy(keybuf, temp, 8);
        for (j=0;j<m;++j){
            idx = i*m + j;
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

    // insert docs
    for (i=0;i<n*m;++i) {
        fdb_set(db, doc[i]);
    }
    fdb_commit(db, FDB_COMMIT_MANUAL_WAL_FLUSH);

    // retrieval check
    for (i=0;i<n*m;++i){
        fdb_doc_create(&rdoc, doc[i]->key, doc[i]->keylen, NULL, 0, NULL, 0);
        status = fdb_get(db, rdoc);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        TEST_CHK(!memcmp(rdoc->key, doc[i]->key, rdoc->keylen));
        TEST_CHK(!memcmp(rdoc->meta, doc[i]->meta, rdoc->metalen));
        TEST_CHK(!memcmp(rdoc->body, doc[i]->body, rdoc->bodylen));
        fdb_doc_free(rdoc);
    }

    fdb_close(db);

    // free all documents
    for (i=0;i<n*m;++i){
        fdb_doc_free(doc[i]);
    }

    // free all resources
    fdb_shutdown();

    memleak_end();

    TEST_RESULT("long key test");
}

int main(){
    basic_test();
    long_filename_test();
    seq_tree_exception_test();
    wal_commit_test();
    multi_version_test();
    compact_wo_reopen_test();
    compact_with_reopen_test();
    auto_recover_compact_ok_test();
#ifdef __CRC32
    crash_recovery_test();
#endif
    incomplete_block_test();
    iterator_test();
    iterator_seek_test();
    sequence_iterator_test();
    sequence_iterator_duplicate_test();
    custom_compare_primitive_test();
    custom_compare_variable_test();
    snapshot_test();
    rollback_test();
    reverse_sequence_iterator_test();
    reverse_iterator_test();
    db_drop_test();
    doc_compression_test();
    read_doc_by_offset_test();
    api_wrapper_test();
    transaction_test();
    transaction_simple_api_test();
    flush_before_commit_test();
    last_wal_flush_header_test();
    long_key_test();
    purge_logically_deleted_doc_test();
    compaction_daemon_test(20);
    multi_thread_test(40*1024, 1024, 20, 1, 100, 2, 6);
    return 0;
}
