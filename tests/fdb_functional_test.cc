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
void _set_random_string(char *str, int len)
{
    str[len--] = 0;
    do {
        str[len] = '!' + random('~'-'!');
    } while (len--);
}

void _set_random_string_smallabt(char *str, int len)
{
    str[len--] = 0;
    do {
        str[len] = 'a' + random('z'-'a');
    } while (len--);
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
    fdb_file_handle *dbfile, *dbfile_rdonly;
    fdb_kvs_handle *db;
    fdb_kvs_handle *db_rdonly;
    fdb_doc **doc = alca(fdb_doc*, n);
    fdb_doc *rdoc;
    fdb_status status;

    char keybuf[256], metabuf[256], bodybuf[256];

    // remove previous dummy files
    r = system(SHELL_DEL" dummy* > errorlog.txt");
    (void)r;

    fdb_config fconfig = fdb_get_default_config();
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    fconfig.wal_threshold = 1024;
    fconfig.compaction_threshold = 0;

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

    // commit
    fdb_commit(dbfile, FDB_COMMIT_NORMAL);

    // check the file info
    fdb_file_info info;
    fdb_get_file_info(dbfile, &info);
    TEST_CHK(info.doc_count == 9);
    TEST_CHK(info.space_used > 0);

    fdb_doc_create(&rdoc, doc[5]->key, doc[5]->keylen, NULL, 0, NULL, 0);
    status = fdb_get_metaonly(db, rdoc);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    TEST_CHK(rdoc->deleted == true);
    TEST_CMP(rdoc->meta, doc[5]->meta, rdoc->metalen);
    fdb_doc_free(rdoc);

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
    fdb_commit(dbfile, FDB_COMMIT_NORMAL);

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
        free(rvalue);
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

    for (i = FDB_RESULT_SUCCESS; i >= FDB_RESULT_IN_USE_BY_COMPACTOR; --i) {
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
    fdb_doc *rdoc;
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
    fdb_doc *rdoc;
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

    // remove previous dummy files
    r = system(SHELL_DEL" dummy* > errorlog.txt");
    (void)r;

    fdb_config fconfig = fdb_get_default_config();
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    fconfig.buffercache_size = 1048576;
    fconfig.wal_threshold = 1024;
    fconfig.flags = FDB_OPEN_FLAG_CREATE;
    fconfig.compaction_threshold = 0;

    // open db
    fdb_open(&dbfile, "./dummy1", &fconfig);
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
    fdb_open(&dbfile_new, "./dummy1", &fconfig);
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
    fdb_open(&dbfile_new, "./dummy1", &fconfig);
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

    // remove previous dummy files
    r = system(SHELL_DEL" dummy* > errorlog.txt");
    (void)r;

    fdb_config fconfig = fdb_get_default_config();
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    fconfig.buffercache_size = 16777216;
    fconfig.wal_threshold = 1024;
    fconfig.flags = FDB_OPEN_FLAG_CREATE;
    fconfig.compaction_threshold = 0;

    // open db
    fdb_open(&dbfile, "./dummy1", &fconfig);
    fdb_kvs_open_default(dbfile, &db, &kvs_config);
    status = fdb_set_log_callback(db, logCallbackFunc,
                                  (void *) "compact_wo_reopen_test");
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    fdb_open(&dbfile_new, "./dummy1", &fconfig);
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
    fdb_compact(dbfile, (char *) "./dummy2");

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
    TEST_CHK(!strcmp("./dummy2", info.filename));

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

    // remove previous dummy files
    r = system(SHELL_DEL" dummy* > errorlog.txt");
    (void)r;

    fdb_config fconfig = fdb_get_default_config();
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    fconfig.buffercache_size = 16777216;
    fconfig.wal_threshold = 1024;
    fconfig.flags = FDB_OPEN_FLAG_CREATE;
    fconfig.compaction_threshold = 0;

    // open db
    fdb_open(&dbfile, "./dummy1", &fconfig);
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
    fdb_compact(dbfile, (char *) "./dummy2");

    // close db file
    fdb_kvs_close(db);
    fdb_close(dbfile);

    r = system(SHELL_MOVE " dummy2 dummy1 > errorlog.txt");
    (void)r;
    fdb_open(&dbfile, "./dummy1", &fconfig);
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
    fdb_file_handle *second_dbfile;
    fdb_kvs_handle *second_dbh;
    fdb_open(&second_dbfile, "./dummy1", &fconfig);
    fdb_kvs_open_default(second_dbfile, &second_dbh, &kvs_config);
    status = fdb_set_log_callback(second_dbh, logCallbackFunc,
                                  (void *) "compact_with_reopen_test");
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    // In-place compaction
    fdb_compact(dbfile, NULL);
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
    status = fdb_open(&dbfile, "./dummy1", &fconfig);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_kvs_open_default(dbfile, &db, &kvs_config);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_set_log_callback(db, logCallbackFunc,
                                  (void *) "compact_with_reopen_test");
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    fdb_get_file_info(dbfile, &info);
    // The actual file name should be a compacted one.
    TEST_CHK(!strcmp("./dummy1.1", info.filename));

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

    r = system(SHELL_MOVE " dummy1 dummy.fdb > errorlog.txt");
    (void)r;
    fdb_open(&dbfile, "./dummy.fdb", &fconfig);
    fdb_kvs_open_default(dbfile, &db, &kvs_config);
    status = fdb_set_log_callback(db, logCallbackFunc,
                                  (void *) "compact_with_reopen_test");
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    // In-place compaction
    fdb_compact(dbfile, NULL);
    fdb_kvs_close(db);
    fdb_close(dbfile);
    // Open database with an original name.
    status = fdb_open(&dbfile, "./dummy.fdb", &fconfig);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_kvs_open_default(dbfile, &db, &kvs_config);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_set_log_callback(db, logCallbackFunc,
                                  (void *) "compact_with_reopen_test");
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    fdb_get_file_info(dbfile, &info);
    TEST_CHK(!strcmp("./dummy.fdb", info.filename));
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
    fdb_kvs_open_default(dbfile, &db, &kvs_config);
    status = fdb_set_log_callback(db, logCallbackFunc,
                                  (void *) "auto_recover_compact_ok_test");
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    fdb_open(&dbfile_new, "./dummy1", &fconfig);
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
    fdb_compact(dbfile, (char *) "./dummy2");

    // save the old file after compaction is done ..
    r = system(SHELL_COPY " dummy1 dummy11 > errorlog.txt");
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
    r = system(SHELL_MOVE " dummy11 dummy1 > errorlog.txt");
    (void)r;

    // now open the old saved compacted file, it should automatically recover
    // and use the new file since compaction was done successfully
    fdb_open(&dbfile_new, "./dummy1", &fconfig);
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
    TEST_CHK(!strcmp("./dummy2", info.filename));

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

    // remove previous dummy files
    r = system(SHELL_DEL " dummy* > errorlog.txt");
    (void)r;

    fconfig = fdb_get_default_config();
    kvs_config = fdb_get_default_kvs_config();
    fconfig.buffercache_size = 16777216;
    fconfig.wal_threshold = 1024;
    fconfig.flags = FDB_OPEN_FLAG_CREATE;
    fconfig.compaction_threshold = 0;

    // write to db1
    fdb_open(&dbfile, "./dummy1", &fconfig);
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
    fdb_open(&dbfile2, "./dummy1.1", &fconfig);
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
    fdb_open(&dbfile, "./dummy1", &fconfig);
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
    fdb_open(&dbfile2, "./dummy1.1", &fconfig);
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
    fdb_doc *rdoc;
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
    fdb_doc *rdoc;
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
    for (i=0;i<n;++i){
        fdb_doc_free(doc[i]);
    }

    // free all resources
    fdb_shutdown();

    memleak_end();

    TEST_RESULT("Database destroy test");
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
    fdb_doc *rdoc;
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
        if (*args->n_opened == args->nthreads) {
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
        c++;

        gettimeofday(&ts_cur, NULL);
        ts_gap = _utime_gap(ts_begin, ts_cur);
        if (ts_gap.tv_sec >= args->time_sec) break;
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
    for (i=0;i<ndocs;++i){
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
        args[i].kvs_config = &kvs_config;
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
    memleak_start();

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
    memleak_start();

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
    fdb_doc *rdoc;
    fdb_status status;
    fdb_config fconfig;
    fdb_kvs_config kvs_config;
    fdb_seqnum_t seqnum;
    thread_t *tid;
    void **thread_ret;

    if (args == NULL)
    { // parent

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
            TEST_CHK(seqnum == n);

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
            }
            status = fdb_kvs_close(db[i]);
            TEST_CHK(status == FDB_RESULT_SUCCESS);
        }

        status = fdb_close(dbfile);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        memleak_end();
        fdb_shutdown();
        TEST_RESULT("multi thread kvs client");
        return NULL;
    }

    // threads enter here //

    // open fhandle
    fconfig = fdb_get_default_config();
    status = fdb_open(&dbfile, "./dummy1", &fconfig);

    // get kvs ID from args
    memcpy(&i, args, sizeof(int));
    sprintf(dbstr, "db%d", i);
    kvs_config = fdb_get_default_kvs_config();
    status = fdb_kvs_open(dbfile, &tdb, dbstr, &kvs_config);

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
    memleak_end();
    return NULL;
}

void crash_recovery_test()
{
    TEST_INIT();

    memleak_start();

    int i, r;
    int n = 10;
    fdb_file_handle *dbfile;
    fdb_kvs_handle *db;
    fdb_doc **doc = alca(fdb_doc*, n);
    fdb_doc *rdoc;
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

    // reopen db
    fdb_open(&dbfile, "./dummy2", &fconfig);
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
    fdb_commit(dbfile, FDB_COMMIT_NORMAL);

    // close the db
    fdb_kvs_close(db);
    fdb_close(dbfile);

    // Shutdown forest db in the middle of the test to simulate crash
    fdb_shutdown();

    // Now append garbage at the end of the file for a few blocks
    r = system(
       "dd if=/dev/zero bs=4096 of=./dummy2 oseek=3 count=2 >> errorlog.txt");
    (void)r;
    // Write 1024 bytes of non-block aligned garbage to end of file
    r = system(
       "dd if=/dev/zero bs=1024 of=./dummy2 oseek=20 count=1 >> errorlog.txt");
    (void)r;


    // reopen the same file
    fdb_open(&dbfile, "./dummy2", &fconfig);
    fdb_kvs_open_default(dbfile, &db, &kvs_config);
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

    TEST_RESULT("crash recovery test");
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
    fdb_doc *rdoc;
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

void iterator_test()
{
    TEST_INIT();

    memleak_start();

    int i, r;
    int n = 10;
    fdb_file_handle *dbfile;
    fdb_kvs_handle *db, *kv1;;
    fdb_doc **doc = alca(fdb_doc*, n);
    fdb_doc *rdoc;
    fdb_status status;
    fdb_iterator *iterator;

    char keybuf[256], metabuf[256], bodybuf[256], temp[256];

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
        i++;
    } while (fdb_iterator_next(iterator) != FDB_RESULT_ITERATOR_FAIL);
    TEST_CHK(i==9);
    fdb_iterator_close(iterator);

    // remove document #8 and #9
    fdb_doc_create(&rdoc, doc[8]->key, doc[8]->keylen, doc[8]->meta,
                   doc[8]->metalen, NULL, 0);
    status = fdb_del(db, rdoc);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    fdb_doc_free(rdoc);
    fdb_doc_create(&rdoc, doc[9]->key, doc[9]->keylen, doc[9]->meta,
                   doc[9]->metalen, NULL, 0);
    status = fdb_del(db, rdoc);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    fdb_doc_free(rdoc);
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

void iterator_complete_test(int insert_opt, int delete_opt)
{
    TEST_INIT();

    int n = 30;
    int i, r, c;
    int *doc_status = alca(int, n); // 0:HB+trie, 1:WAL, 2:deleted
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
    fdb_doc *doc;
    fdb_iterator *fit;
    fdb_iterator_opt_t itr_opt;
    fdb_status s;
    uint64_t mask = 0x11111111111; //0x11111111111

    sprintf(cmd, SHELL_DEL " dummy*");
    r = system(cmd);
    (void)r;

    memleak_start();

    config = fdb_get_default_config();
    kvs_config = fdb_get_default_kvs_config();
    s = fdb_open(&dbfile, "./dummy", &config);
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
        s = fdb_iterator_init(db, &fit, NULL, 0, key, strlen(key)+1, FDB_ITR_SKIP_MAX_KEY);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        s = fdb_iterator_seek_to_max(fit);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        s = fdb_iterator_get(fit, &doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        c = i-1;
        sprintf(value, (doc_status[c]==0)?(valuestr):(valuestr2), c);
        TEST_CMP(doc->body, value, doc->bodylen);
        fdb_doc_free(doc);
        s = fdb_iterator_close(fit);
        TEST_CHK(s == FDB_RESULT_SUCCESS);

        // create an iterator with an start key and skip min key option
        i = n/3;
        sprintf(key, keystr, (int)i);
        s = fdb_iterator_init(db, &fit, key, strlen(key)+1, NULL, 0, FDB_ITR_SKIP_MIN_KEY);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        s = fdb_iterator_seek_to_min(fit);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        s = fdb_iterator_get(fit, &doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        c = i+1;
        sprintf(value, (doc_status[c]==0)?(valuestr):(valuestr2), c);
        TEST_CMP(doc->body, value, doc->bodylen);
        fdb_doc_free(doc);
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
    fdb_file_handle *dbfile;
    fdb_kvs_handle *db;
    fdb_config config;
    fdb_kvs_config kvs_config;
    fdb_doc *doc;
    fdb_iterator *fit;
    fdb_status s;

    sprintf(cmd, SHELL_DEL " dummy*");
    r = system(cmd);
    (void)r;

    memleak_start();

    config = fdb_get_default_config();
    kvs_config = fdb_get_default_kvs_config();
    s = fdb_open(&dbfile, "./dummy", &config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_kvs_open(dbfile, &db, NULL, &kvs_config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    memset(key, 0xff, 256);
    for (i=1;i<n;i+=1){
        sprintf(value, "0xff length %d", (int)i);
        fdb_set_kv(db, key, i, value, strlen(value)+1);
    }
    fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);

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
        fdb_doc_free(doc);
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
        fdb_doc_free(doc);
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
        fdb_doc_free(doc);
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
        fdb_doc_free(doc);
        s = fdb_iterator_prev(fit);
        c--;
    }

    s = fdb_iterator_close(fit);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_close(dbfile);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    s = fdb_shutdown();
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    memleak_end();
    TEST_RESULT("iterator extreme key test");
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
    fdb_doc *rdoc;
    fdb_iterator *it;
    fdb_status status;

    // remove previous dummy files
    r = system(SHELL_DEL" dummy* > errorlog.txt");
    (void)r;

    fdb_config fconfig = fdb_get_default_config();
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    fconfig.wal_threshold = 1024;
    fconfig.flags = FDB_OPEN_FLAG_CREATE;
    fconfig.compaction_threshold = 0;

    // open db
    fdb_open(&dbfile, "./dummy", &fconfig);
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

    // iterate over all docs to retrieve undeleted key
    status = fdb_iterator_init(kv, &it, NULL, 0, NULL, 0, FDB_ITR_NO_DELETES);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_iterator_get(it, &rdoc);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    if(status == FDB_RESULT_SUCCESS){
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
    r = system(SHELL_DEL" dummy* > errorlog.txt");
    (void)r;

    fconfig.wal_threshold = 1024;
    fconfig.flags = FDB_OPEN_FLAG_CREATE;
    fconfig.compaction_threshold = 10;

    fdb_open(&dbfile, "./dummy1", &fconfig);
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
        if(info.doc_count != expected_doc_count){
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
        TEST_CHK(info.doc_count == expected_doc_count);

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
    fdb_doc *rdoc;
    fdb_status status;
    char keybuf[256], bodybuf[256];

    // remove previous dummy files
    r = system(SHELL_DEL" dummy* > errorlog.txt");
    (void)r;

    // open db1, db2, db3 on the same file
    fconfig = fdb_get_default_config();
    kvs_config = fdb_get_default_kvs_config();
    fdb_open(&dbfile, "./dummy1", &fconfig);

    fdb_kvs_open_default(dbfile, &db1, &kvs_config);
    status = fdb_set_log_callback(db1, logCallbackFunc,
                                  (void *) "iterator_seek_test");
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    fdb_kvs_open_default(dbfile, &db2, &kvs_config);
    status = fdb_set_log_callback(db2, logCallbackFunc,
                                  (void *) "iterator_seek_test");
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    fdb_kvs_open_default(dbfile, &db3, &kvs_config);
    status = fdb_set_log_callback(db3, logCallbackFunc,
                                  (void *) "iterator_seek_test");
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
        TEST_CHK(rdoc->seqnum == r);
        fdb_doc_free(rdoc);
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

void iterator_seek_test()
{
    TEST_INIT();

    memleak_start();

    int i, r;
    int n = 10;
    fdb_file_handle *dbfile;
    fdb_kvs_handle *db, *kv1;
    fdb_doc **doc = alca(fdb_doc*, n);
    fdb_doc *rdoc;
    fdb_status status;
    fdb_iterator *iterator;

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

    // seek forward to the last key.
    status = fdb_iterator_seek(iterator, doc[n-1]->key, strlen(keybuf), 0);
    TEST_CHK(status != FDB_RESULT_ITERATOR_FAIL);
    status = fdb_iterator_get(iterator, &rdoc);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    TEST_CMP(rdoc->key, doc[n-1]->key, rdoc->keylen);
    TEST_CMP(rdoc->meta, doc[n-1]->meta, rdoc->metalen);
    TEST_CMP(rdoc->body, doc[n-1]->body, rdoc->bodylen);
    fdb_doc_free(rdoc);

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
    }

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

void iterator_seek_wal_only_test()
{
    TEST_INIT();

    memleak_start();

    int i, r;
    int n = 10;
    fdb_file_handle *dbfile;
    fdb_kvs_handle *db, *kv1;
    fdb_doc **doc = alca(fdb_doc*, n);
    fdb_doc *rdoc;
    fdb_status status;
    fdb_iterator *iterator;

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

    // seek forward to the last key.
    status = fdb_iterator_seek(iterator, doc[n-1]->key, strlen(keybuf), 0);
    TEST_CHK(status != FDB_RESULT_ITERATOR_FAIL);
    status = fdb_iterator_get(iterator, &rdoc);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    TEST_CMP(rdoc->key, doc[n-1]->key, rdoc->keylen);
    TEST_CMP(rdoc->meta, doc[n-1]->meta, rdoc->metalen);
    TEST_CMP(rdoc->body, doc[n-1]->body, rdoc->bodylen);
    fdb_doc_free(rdoc);

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
    fdb_doc *rdoc;
    fdb_status status;
    fdb_iterator *iterator;

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
    fdb_doc_create(&rdoc, doc[9]->key, doc[9]->keylen, doc[9]->meta, doc[9]->metalen, NULL, 0);
    status = fdb_del(db, rdoc);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    fdb_doc_free(rdoc);
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
    fdb_doc *rdoc;
    fdb_status status;
    fdb_iterator *iterator;
    fdb_seqnum_t seqnum;

    char keybuf[256], metabuf[256], bodybuf[256];

    // remove previous dummy files
    r = system(SHELL_DEL" dummy* > errorlog.txt");
    (void)r;

    fdb_config fconfig = fdb_get_default_config();
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    fconfig.buffercache_size = 0;
    fconfig.wal_threshold = 1024;
    fconfig.compaction_threshold = 0;

    // open db
    fdb_open(&dbfile, "./dummy1", &fconfig);
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
    do {
        status = fdb_iterator_get(iterator, &rdoc);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
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

        TEST_CMP(rdoc->key, doc[i]->key, rdoc->keylen);
        TEST_CMP(rdoc->meta, doc[i]->meta, rdoc->metalen);
        TEST_CMP(rdoc->body, bodybuf, rdoc->bodylen);
        TEST_CHK(rdoc->seqnum == seqnum);

        count++;
        fdb_doc_free(rdoc);
    } while (fdb_iterator_next(iterator) != FDB_RESULT_ITERATOR_FAIL);
    TEST_CHK(count==70);
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

void reverse_sequence_iterator_test()
{
    TEST_INIT();

    memleak_start();

    int i, r, count;
    int n = 10;
    fdb_file_handle *dbfile;
    fdb_kvs_handle *db;
    fdb_doc **doc = alca(fdb_doc*, n);
    fdb_doc *rdoc;
    fdb_status status;
    fdb_iterator *iterator;

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

void reverse_iterator_test()
{
    TEST_INIT();

    memleak_start();

    int i, r;
    int n = 10;
    fdb_file_handle *dbfile;
    fdb_kvs_handle *db;
    fdb_doc **doc = alca(fdb_doc*, n);
    fdb_doc *rdoc;
    fdb_status status;
    fdb_iterator *iterator;

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

    // Again change direction and test reverse iterator..
    for (--i; fdb_iterator_prev(iterator) != FDB_RESULT_ITERATOR_FAIL; --i) {
        status = fdb_iterator_get(iterator, &rdoc);
        TEST_CHK(status == FDB_RESULT_SUCCESS);

        TEST_CMP(rdoc->key, doc[i]->key, rdoc->keylen);
        TEST_CMP(rdoc->meta, doc[i]->meta, rdoc->metalen);
        TEST_CMP(rdoc->body, doc[i]->body, rdoc->bodylen);

        fdb_doc_free(rdoc);
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
    fdb_doc *rdoc;
    fdb_status status;
    fdb_iterator *iterator;
    fdb_iterator *iterator2;

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
    fdb_iterator_sequence_init(kv1, &iterator, 0, 0, FDB_ITR_NONE);
    i=0;
    count = 0;
    while (1) {
        status = fdb_iterator_get(iterator, &rdoc);
        TEST_CHK(!memcmp(rdoc->key, doc[i]->key, rdoc->keylen));
        TEST_CHK(!memcmp(rdoc->meta, doc[i]->meta, rdoc->metalen));
        TEST_CHK(!memcmp(rdoc->body, doc[i]->body, rdoc->bodylen));
        fdb_doc_free(rdoc);
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
    fdb_iterator_sequence_init(kv2, &iterator2, 0, 0, FDB_ITR_NONE);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    while(1) {
        status = fdb_iterator_get(iterator2, &rdoc);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        fdb_doc_free(rdoc);
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
        i--;
        count++;
    }
    TEST_CHK(count==n);
    fdb_iterator_close(iterator2);

    // re-open iterator after commit should return all docs for kv1
    i = 0;
    count = 0;
    fdb_iterator_sequence_init(kv1, &iterator, 0, 0, FDB_ITR_NONE);
    while (1) {
        status = fdb_iterator_get(iterator, &rdoc);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        TEST_CHK(!memcmp(rdoc->key, doc[i]->key, rdoc->keylen));
        TEST_CHK(!memcmp(rdoc->meta, doc[i]->meta, rdoc->metalen));
        TEST_CHK(!memcmp(rdoc->body, doc[i]->body, rdoc->bodylen));
        fdb_doc_free(rdoc);
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
    fdb_doc *rdoc;
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
    uint64_t count;
    fdb_file_handle *dbfile;
    fdb_kvs_handle *db, *db2;
    fdb_doc **doc = alca(fdb_doc*, n);
    fdb_doc *rdoc;
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
        TEST_CMP(rdoc->body, doc[i]->body, rdoc->bodylen);

        fdb_doc_free(rdoc);
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
        count++;
    } while (fdb_iterator_next(iterator) != FDB_RESULT_ITERATOR_FAIL);
    TEST_CHK(count == n);

    // Reverse direction
    for (; fdb_iterator_prev(iterator) != FDB_RESULT_ITERATOR_FAIL; --count) {
        status = fdb_iterator_get(iterator, &rdoc);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        fdb_doc_free(rdoc);
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
    fdb_doc *rdoc;
    fdb_kvs_info kvs_info;
    fdb_status status;
    fdb_iterator *iterator;

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

    // remove previous dummy files
    r = system(SHELL_DEL" dummy* > errorlog.txt");
    (void)r;

    // open db
    status = fdb_open(&dbfile, "./dummy1", &fconfig);
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
    status = fdb_open(&dbfile, "./dummy2", &fconfig);
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

    // remove previous dummy files
    r = system(SHELL_DEL" dummy* > errorlog.txt");
    (void)r;

    fdb_config fconfig = fdb_get_default_config();
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    fconfig.buffercache_size = 0;
    fconfig.wal_threshold = 1024;
    fconfig.flags = FDB_OPEN_FLAG_CREATE;
    fconfig.compaction_threshold = 0;

    // remove previous dummy files
    r = system(SHELL_DEL" dummy* > errorlog.txt");
    (void)r;

    // open db
    status = fdb_open(&dbfile, "./dummy1", &fconfig);
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
    do {
        status = fdb_iterator_get(iterator, &rdoc);
        TEST_CHK(status == FDB_RESULT_SUCCESS);

        TEST_CMP(rdoc->key, doc[i]->key, rdoc->keylen);
        TEST_CMP(rdoc->meta, doc[i]->meta, rdoc->metalen);
        TEST_CMP(rdoc->body, doc[i]->body, rdoc->bodylen);

        fdb_doc_free(rdoc);
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

    // remove previous dummy files
    r = system(SHELL_DEL" dummy* > errorlog.txt");
    (void)r;

    fdb_config fconfig = fdb_get_default_config();
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    fconfig.buffercache_size = 0;
    fconfig.wal_threshold = 1024;
    fconfig.flags = FDB_OPEN_FLAG_CREATE;
    fconfig.compaction_threshold = 0;

    // remove previous dummy files
    r = system(SHELL_DEL" dummy* > errorlog.txt");
    (void)r;

    // open db
    status = fdb_open(&dbfile, "./dummy1", &fconfig);
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
                                  (void *) "snapshot_test");
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
    fdb_doc *rdoc;
    fdb_kvs_info kvs_info;
    fdb_status status;
    fdb_iterator *iterator;

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
    fconfig.multi_kv_instances = multi_kv;

    // remove previous dummy files
    r = system(SHELL_DEL" dummy* > errorlog.txt");
    (void)r;

    // open db
    fdb_open(&dbfile, "./dummy1", &fconfig);
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
    fdb_open(&dbfile_txn, "./dummy1", &fconfig);
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

void rollback_forward_seqnum(){

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
    fdb_doc **doc = alca(fdb_doc*, n);
    fdb_doc *rdoc;
    fdb_status status;
    r = system(SHELL_DEL" dummy* > errorlog.txt");
    (void)r;

    fconfig.wal_threshold = 1024;
    fconfig.flags = FDB_OPEN_FLAG_CREATE;
    fconfig.compaction_threshold = 0;

    fdb_open(&dbfile, "./dummy1", &fconfig);
    fdb_kvs_open(dbfile, &kv1, "kv1", &kvs_config);
    fdb_kvs_open(dbfile, &mirror_kv1, NULL, &kvs_config);


    // set n docs within both dbs
    for(i=0;i<n;++i){
        sprintf(keybuf, "key%d", i);
        fdb_doc_create(&doc[i], (void*)keybuf, strlen(keybuf),
            NULL, 0, NULL, 0);
        fdb_set(kv1, doc[i]);
        fdb_set_kv(mirror_kv1, keybuf, strlen(keybuf), setop, 3);
    }

    // commit and save seqnum1
    fdb_commit(dbfile, FDB_COMMIT_NORMAL);
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

    // rollback to second seqnum
    status = fdb_rollback(&kv1, rb2_seqnum);
    TEST_CHK(status == FDB_RESULT_NO_DB_INSTANCE);

    status = fdb_iterator_sequence_init(mirror_kv1, &it, 0, 0, FDB_ITR_NONE);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    do {
        status = fdb_iterator_get(it, &rdoc);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        status = fdb_get(kv1, rdoc);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        TEST_CHK(rdoc->deleted == false);
        fdb_doc_free(rdoc);
    } while(fdb_iterator_next(it) != FDB_RESULT_ITERATOR_FAIL);

    for (i=0;i<n;++i){
        fdb_doc_free(doc[i]);
    }
    fdb_iterator_close(it);
    fdb_kvs_close(kv1);
    fdb_close(dbfile);
    fdb_shutdown();
    memleak_end();

    TEST_RESULT("rollback forward seqnum");
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

    // remove previous dummy files
    r = system(SHELL_DEL" dummy* > errorlog.txt");
    (void)r;

    // MB-12530 open db
    config = fdb_get_default_config();
    kvs_config = fdb_get_default_kvs_config();
    status = fdb_open(&dbfile, "dummy", &config);
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
    fdb_doc *rdoc;
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
    fdb_doc *rdoc;
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
    fdb_doc_free(rdoc);

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
    fdb_doc *rdoc;
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

    // remove previous dummy files
    r = system(SHELL_DEL" dummy* > errorlog.txt");
    (void)r;

    fdb_config fconfig = fdb_get_default_config();
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    fconfig.buffercache_size = 0;
    fconfig.wal_threshold = 1024;
    fconfig.flags = FDB_OPEN_FLAG_CREATE;
    fconfig.compaction_mode = FDB_COMPACTION_AUTO;
    fconfig.compaction_threshold = compaction_threshold;
    fconfig.compactor_sleep_duration = 1; // for quick test

    // open db
    fdb_open(&dbfile, "dummy", &fconfig);
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
    status = fdb_open(&dbfile, "dummy", &fconfig);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_kvs_open_default(dbfile, &db, &kvs_config);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_set_log_callback(db, logCallbackFunc,
                                  (void *) "compaction_daemon_test");
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    // check db filename
    fdb_get_file_info(dbfile, &info);
    TEST_CHK(!strcmp(info.filename, "dummy"));

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
    r = system(SHELL_DEL" dummy.meta > errorlog.txt");
    (void)r;
    // reopen db file
    status = fdb_open(&dbfile, "dummy", &fconfig);
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
    r = system(SHELL_MOVE" dummy.0 dummy.23 > errorlog.txt");
    (void)r;
    // reopen db file
    status = fdb_open(&dbfile, "dummy", &fconfig);
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
    status = fdb_open(&dbfile_less, "dummy_less", &fconfig);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_kvs_open_default(dbfile_less, &db_less, &kvs_config);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    fconfig.compaction_threshold = 0;
    status = fdb_open(&dbfile_non, "dummy_non", &fconfig);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_kvs_open_default(dbfile_non, &db_non, &kvs_config);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    fconfig.compaction_mode = FDB_COMPACTION_MANUAL;
    status = fdb_open(&dbfile_manual, "dummy_manual", &fconfig);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_kvs_open_default(dbfile_manual, &db_manual, &kvs_config);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // reopen db file
    fconfig.compaction_threshold = 30;
    fconfig.compaction_mode = FDB_COMPACTION_AUTO;
    status = fdb_open(&dbfile, "dummy", &fconfig);
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
            if (ts_gap.tv_sec >= time_sec) {
                escape = 1;
                break;
            }
        }
    }

    // perform manual compaction of auto-compact file
    status = fdb_compact(dbfile_non, NULL);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // perform manual compaction of manual-compact file
    status = fdb_compact(dbfile_manual, "dummy_manual_compacted");
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // open dummy_manual_compacted using new db handle
    fconfig.compaction_mode = FDB_COMPACTION_MANUAL;
    status = fdb_open(&dbfile_new, "dummy_manual_compacted", &fconfig);
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
    status = fdb_open(&dbfile_manual, "dummy_manual_compacted", &fconfig);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // switch compaction mode of 'db_non' from AUTO to MANUAL
    status = fdb_switch_compaction_mode(dbfile_non, FDB_COMPACTION_MANUAL, 0);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // close and open with manual-compact option
    status = fdb_close(dbfile_non);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    fconfig.compaction_mode = FDB_COMPACTION_MANUAL;
    status = fdb_open(&dbfile_non, "dummy_non", &fconfig);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // Now perform one manual compaction on dummy_non
    fdb_compact(dbfile_non, "dummy_non.manual");

    // close all db files except dummy_non
    fdb_close(dbfile);
    fdb_close(dbfile_less);
    fdb_close(dbfile_manual);

    // open manual compact file (dummy_non) using auto compact mode
    fconfig.compaction_mode = FDB_COMPACTION_AUTO;
    status = fdb_open(&dbfile, "dummy_non.manual", &fconfig);
    TEST_CHK(status == FDB_RESULT_INVALID_COMPACTION_MODE);

    // Attempt to destroy manual compact file using auto compact mode
    status = fdb_destroy("dummy_non.manual", &fconfig);
    TEST_CHK(status == FDB_RESULT_INVALID_COMPACTION_MODE);

    // open auto copmact file (dummy_manual_compacted) using manual compact mode
    fconfig.compaction_mode = FDB_COMPACTION_MANUAL;
    status = fdb_open(&dbfile, "dummy_manual_compacted", &fconfig);
    TEST_CHK(status == FDB_RESULT_INVALID_COMPACTION_MODE);

    // Attempt to destroy auto copmact file using manual compact mode
    status = fdb_destroy("dummy_manual_compacted", &fconfig);
    TEST_CHK(status == FDB_RESULT_INVALID_COMPACTION_MODE);

    // DESTROY auto copmact file with correct mode
    fconfig.compaction_mode = FDB_COMPACTION_AUTO;
    status = fdb_destroy("dummy_manual_compacted", &fconfig);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // DESTROY manual compacted file with past version open!
    fconfig.compaction_mode = FDB_COMPACTION_MANUAL;
    status = fdb_destroy("dummy_non.manual", &fconfig);
    TEST_CHK(status == FDB_RESULT_FILE_IS_BUSY);

    // Simulate a database crash by doing a premature shutdown
    // Note that db_non was never closed properly
    status = fdb_shutdown();
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    status = fdb_destroy("dummy_non.manual", &fconfig);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // Attempt to read-only auto compacted and destroyed file
    fconfig.flags = FDB_OPEN_FLAG_RDONLY;
    status = fdb_open(&dbfile, "./dummy_manual_compacted", &fconfig);
    TEST_CHK(status == FDB_RESULT_NO_SUCH_FILE);

    status = fdb_open(&dbfile, "./dummy_manual_compacted.meta", &fconfig);
    TEST_CHK(status == FDB_RESULT_NO_SUCH_FILE);

    // Attempt to read-only past version of manually compacted destroyed file
    status = fdb_open(&dbfile, "dummy_non", &fconfig);
    TEST_CHK(status == FDB_RESULT_NO_SUCH_FILE);

    // Attempt to read-only current version of manually compacted destroyed file
    status = fdb_open(&dbfile, "dummy_non.manual", &fconfig);
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
    fdb_kvs_close(db);
    fdb_close(dbfile);

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
    fdb_file_handle *dbfile, *dbfile_txn1, *dbfile_txn2, *dbfile_txn3;
    fdb_kvs_handle *db, *db_txn1, *db_txn2, *db_txn3;
    fdb_doc **doc = alca(fdb_doc*, n);
    fdb_doc *rdoc;
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
    fconfig.purging_interval = 0;
    fconfig.compaction_threshold = 0;

    // open db
    fdb_open(&dbfile, "dummy1", &fconfig);
    fdb_kvs_open_default(dbfile, &db, &kvs_config);
    status = fdb_set_log_callback(db, logCallbackFunc,
                                  (void *) "transaction_test");
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // open db and begin transactions
    fdb_open(&dbfile_txn1, "dummy1", &fconfig);
    fdb_open(&dbfile_txn2, "dummy1", &fconfig);
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
    fdb_open(&dbfile_txn3, "dummy1", &fconfig);
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
    fdb_open(&dbfile, "dummy1", &fconfig);
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
    fdb_compact(dbfile, "dummy2");

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
    fdb_open(&dbfile, "dummy2", &fconfig);
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
    fdb_open(&dbfile_txn1, "./dummy1", &fconfig);
    fdb_open(&dbfile_txn2, "./dummy1", &fconfig);
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
        free(value);

        // txn1
        sprintf(keybuf, "key%d", i);
        sprintf(bodybuf, "body%d_txn1", i);
        status = fdb_get_kv(db_txn1, keybuf, strlen(keybuf), &value, &valuelen);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        TEST_CMP(value, bodybuf, valuelen);
        free(value);

        // txn2
        sprintf(keybuf, "key%d", i);
        sprintf(bodybuf, "body%d_txn2", i);
        status = fdb_get_kv(db_txn2, keybuf, strlen(keybuf), &value, &valuelen);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        TEST_CMP(value, bodybuf, valuelen);
        free(value);
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
        free(value);

        // txn2
        sprintf(keybuf, "key%d", i);
        sprintf(bodybuf, "body%d_txn2", i);
        status = fdb_get_kv(db_txn2, keybuf, strlen(keybuf), &value, &valuelen);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        TEST_CMP(value, bodybuf, valuelen);
        free(value);
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
        free(value);
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
    fdb_doc *rdoc;
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

        // retrieve through db2
        fdb_doc_create(&rdoc, (void*)keybuf, strlen(keybuf),
                                NULL, 0, NULL, 0);
        status = fdb_get(db2, rdoc);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        TEST_CMP(metabuf, rdoc->meta, rdoc->metalen);
        TEST_CMP(bodybuf, rdoc->body, rdoc->bodylen);
        fdb_doc_free(rdoc);
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

        // retrieve through db2
        fdb_doc_create(&rdoc, (void*)keybuf, strlen(keybuf),
                                NULL, 0, NULL, 0);
        status = fdb_get(db2, rdoc);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        TEST_CMP(metabuf, rdoc->meta, rdoc->metalen);
        TEST_CMP(bodybuf, rdoc->body, rdoc->bodylen);
        fdb_doc_free(rdoc);
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
        free(value_out);
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
        free(value_out);
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
    fdb_doc *rdoc;
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

    int i, j, idx, r;
    int n=300, m=20; // n: # prefixes, m: # postfixes
    int keylen_limit;
    fdb_file_handle *dbfile;
    fdb_kvs_handle *db;
    fdb_doc **doc = alca(fdb_doc*, n*m);
    fdb_doc *rdoc;
    fdb_status status;

    char *keybuf;
    char metabuf[256], bodybuf[256], temp[256];

    // remove previous dummy files
    r = system(SHELL_DEL" dummy* > errorlog.txt");
    (void)r;

    fdb_config fconfig = fdb_get_default_config();
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    fconfig.buffercache_size = 0;
    fconfig.flags = FDB_OPEN_FLAG_CREATE;
    fconfig.purging_interval = 0;
    fconfig.compaction_threshold = 0;

    keylen_limit = fconfig.blocksize - 256;
    keybuf = alca(char, keylen_limit);

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
    fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);

    // retrieval check
    for (i=0;i<n*m;++i){
        fdb_doc_create(&rdoc, doc[i]->key, doc[i]->keylen, NULL, 0, NULL, 0);
        status = fdb_get(db, rdoc);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        TEST_CMP(rdoc->key, doc[i]->key, rdoc->keylen);
        TEST_CMP(rdoc->meta, doc[i]->meta, rdoc->metalen);
        TEST_CMP(rdoc->body, doc[i]->body, rdoc->bodylen);
        fdb_doc_free(rdoc);
    }

    fdb_close(dbfile);

    // free all documents
    for (i=0;i<n*m;++i){
        fdb_doc_free(doc[i]);
    }

    // free all resources
    fdb_shutdown();

    memleak_end();

    TEST_RESULT("long key test");
}

// lexicographically compares two variable-length binary streams
#define MIN(a,b) (((a)<(b))?(a):(b))
static int _multi_kv_test_keycmp(void *key1, size_t keylen1, void *key2, size_t keylen2)
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

#define MULTI_KV_VAR_CMP (0x1)
void multi_kv_test(uint8_t opt)
{
    TEST_INIT();

    int n = 100;
    int i, r;
    char key[256], meta[256], value[256];
    char keystr[] = "key%06d";
    char metastr[] = "meta%06d";
    char metastr_kv[] = "meta%06d(kv)";
    char valuestr[] = "value%08d";
    char valuestr_kv[] = "value%08d (kv instance)";
    void *value_out;
    size_t valuelen;

    char *kvs_names[] = {NULL, (char*)"kv1"};
    fdb_custom_cmp_variable functions[] = {_multi_kv_test_keycmp,
                                           _multi_kv_test_keycmp};

    fdb_file_handle *dbfile;
    fdb_kvs_handle *db, *kv1;
    fdb_config config;
    fdb_kvs_config kvs_config;
    fdb_doc *doc;
    fdb_file_info file_info;
    fdb_kvs_info kvs_info;
    fdb_status s;

    sprintf(value, SHELL_DEL" dummy*");
    r = system(value);
    (void)r;

    memleak_start();

    config = fdb_get_default_config();
    kvs_config = fdb_get_default_kvs_config();
    config.multi_kv_instances = true;
    config.wal_threshold = 50;
    config.buffercache_size = 0;

    s = fdb_open(&dbfile, "./dummy", &config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    if (opt & MULTI_KV_VAR_CMP) {
        kvs_config.custom_cmp = _multi_kv_test_keycmp;
    }
    s = fdb_kvs_open_default(dbfile, &db, &kvs_config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    // insert using 'default' instance
    for (i=0;i<n;++i) {
        sprintf(key, keystr, i);
        sprintf(meta, metastr, i);
        sprintf(value, valuestr, i);
        fdb_doc_create(&doc, key, strlen(key)+1, meta,
                           strlen(meta)+1, value, strlen(value)+1);
        s = fdb_set(db, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        fdb_doc_free(doc);
    }

    // retrieve from WAL
    for (i=0;i<n;++i){
        // by key
        sprintf(key, keystr, i);
        sprintf(meta, metastr, i);
        sprintf(value, valuestr, i);
        s = fdb_get_kv(db, key, strlen(key)+1, &value_out, &valuelen);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(value, value_out, valuelen);
        free(value_out);

        // metaonly by key
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, NULL, 0);
        s = fdb_get_metaonly(db, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(doc->key, key, doc->keylen);
        TEST_CMP(doc->meta, meta, doc->metalen);
        fdb_doc_free(doc);

        // by seq
        fdb_doc_create(&doc, NULL, 0, NULL, 0, NULL, 0);
        doc->seqnum = i+1;
        s = fdb_get_byseq(db, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(doc->key, key, doc->keylen);
        TEST_CMP(doc->body, value, doc->bodylen);
        fdb_doc_free(doc);

        // metaonly by seq
        fdb_doc_create(&doc, NULL, 0, NULL, 0, NULL, 0);
        doc->seqnum = i+1;
        s = fdb_get_metaonly_byseq(db, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(doc->key, key, doc->keylen);
        TEST_CMP(doc->meta, meta, doc->metalen);
        fdb_doc_free(doc);
    }
    s = fdb_commit(dbfile, FDB_COMMIT_NORMAL);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    kvs_config.create_if_missing = false;
    s = fdb_kvs_open(dbfile, &kv1, "kv1", &kvs_config);
    TEST_CHK(s != FDB_RESULT_SUCCESS); // must fail

    kvs_config.create_if_missing = true;
    s = fdb_kvs_open(dbfile, &kv1, "kv1", &kvs_config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    // insert using 'kv1' instance
    for (i=0;i<n;++i){
        sprintf(key, keystr, i);
        sprintf(meta, metastr_kv, i);
        sprintf(value, valuestr_kv, i);
        fdb_doc_create(&doc, key, strlen(key)+1, meta,
                           strlen(meta)+1, value, strlen(value)+1);
        s = fdb_set(kv1, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        fdb_doc_free(doc);
    }

    // retrieve from WAL
    for (i=0;i<n;++i){
        // by key
        sprintf(key, keystr, i);
        sprintf(meta, metastr_kv, i);
        sprintf(value, valuestr_kv, i);
        s = fdb_get_kv(kv1, key, strlen(key)+1, &value_out, &valuelen);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(value, value_out, valuelen);
        free(value_out);

        // metaonly by key
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, NULL, 0);
        s = fdb_get_metaonly(kv1, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(doc->key, key, doc->keylen);
        TEST_CMP(doc->meta, meta, doc->metalen);
        fdb_doc_free(doc);

        // by seq
        fdb_doc_create(&doc, NULL, 0, NULL, 0, NULL, 0);
        doc->seqnum = i+1;
        s = fdb_get_byseq(kv1, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(doc->key, key, doc->keylen);
        TEST_CMP(doc->body, value, doc->bodylen);
        fdb_doc_free(doc);

        // metaonly by seq
        fdb_doc_create(&doc, NULL, 0, NULL, 0, NULL, 0);
        doc->seqnum = i+1;
        s = fdb_get_metaonly_byseq(kv1, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(doc->key, key, doc->keylen);
        TEST_CMP(doc->meta, meta, doc->metalen);
        fdb_doc_free(doc);
    }
    s = fdb_commit(dbfile, FDB_COMMIT_NORMAL);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    // retrieve from hb+trie
    for (i=0;i<n;++i){
        // ==== the default instance ====
        // by key
        sprintf(key, keystr, i);
        sprintf(meta, metastr, i);
        sprintf(value, valuestr, i);
        s = fdb_get_kv(db, key, strlen(key)+1, &value_out, &valuelen);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(value, value_out, valuelen);
        free(value_out);

        // metaonly by key
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, NULL, 0);
        s = fdb_get_metaonly(db, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(doc->key, key, doc->keylen);
        TEST_CMP(doc->meta, meta, doc->metalen);
        fdb_doc_free(doc);

        // by seq
        fdb_doc_create(&doc, NULL, 0, NULL, 0, NULL, 0);
        doc->seqnum = i+1;
        s = fdb_get_byseq(db, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(doc->key, key, doc->keylen);
        TEST_CMP(doc->body, value, doc->bodylen);
        fdb_doc_free(doc);

        // metaonly by seq
        fdb_doc_create(&doc, NULL, 0, NULL, 0, NULL, 0);
        doc->seqnum = i+1;
        s = fdb_get_metaonly_byseq(db, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(doc->key, key, doc->keylen);
        TEST_CMP(doc->meta, meta, doc->metalen);

        // by offset
        s = fdb_get_byoffset(db, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(doc->key, key, doc->keylen);
        TEST_CMP(doc->body, value, doc->bodylen);
        fdb_doc_free(doc);

        // ==== 'kv1' instance ====
        // by key
        sprintf(meta, metastr_kv, i);
        sprintf(value, valuestr_kv, i);
        s = fdb_get_kv(kv1, key, strlen(key)+1, &value_out, &valuelen);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(value, value_out, valuelen);
        free(value_out);

        // metaonly by key
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, NULL, 0);
        s = fdb_get_metaonly(kv1, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(doc->key, key, doc->keylen);
        TEST_CMP(doc->meta, meta, doc->metalen);
        fdb_doc_free(doc);

        // by seq
        fdb_doc_create(&doc, NULL, 0, NULL, 0, NULL, 0);
        doc->seqnum = i+1;
        s = fdb_get_byseq(kv1, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(doc->key, key, doc->keylen);
        TEST_CMP(doc->body, value, doc->bodylen);
        fdb_doc_free(doc);

        // metaonly by seq
        fdb_doc_create(&doc, NULL, 0, NULL, 0, NULL, 0);
        doc->seqnum = i+1;
        s = fdb_get_metaonly_byseq(kv1, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(doc->key, key, doc->keylen);
        TEST_CMP(doc->meta, meta, doc->metalen);

        // by offset
        s = fdb_get_byoffset(kv1, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(doc->key, key, doc->keylen);
        TEST_CMP(doc->body, value, doc->bodylen);
        fdb_doc_free(doc);
    }

    // info check
    s = fdb_get_file_info(dbfile, &file_info);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    TEST_CHK(file_info.doc_count == n*2);
    s = fdb_get_kvs_info(db, &kvs_info);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    TEST_CHK(kvs_info.doc_count == n);
    s = fdb_get_kvs_info(kv1, &kvs_info);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    TEST_CHK(kvs_info.doc_count == n);

    s = fdb_kvs_close(kv1);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_close(dbfile);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    if (opt & MULTI_KV_VAR_CMP) {
        s = fdb_open_custom_cmp(&dbfile, "./dummy", &config,
                                2, kvs_names, functions);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
    } else {
        s = fdb_open(&dbfile, "./dummy", &config);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
    }
    s = fdb_kvs_open(dbfile, &db, NULL, &kvs_config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_kvs_open(dbfile, &kv1, "kv1", &kvs_config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    // retrieve check after reopen
    for (i=0;i<n;++i){
        sprintf(key, keystr, i);
        sprintf(value, valuestr, i);
        s = fdb_get_kv(db, key, strlen(key)+1, &value_out, &valuelen);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(value, value_out, valuelen);
        free(value_out);

        sprintf(value, valuestr_kv, i);
        s = fdb_get_kv(kv1, key, strlen(key)+1, &value_out, &valuelen);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(value, value_out, valuelen);
        free(value_out);
    }
    // info check after reopen
    s = fdb_get_file_info(dbfile, &file_info);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    TEST_CHK(file_info.doc_count == n*2);
    s = fdb_get_kvs_info(db, &kvs_info);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    TEST_CHK(kvs_info.doc_count == n);
    s = fdb_get_kvs_info(kv1, &kvs_info);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    TEST_CHK(kvs_info.doc_count == n);

    s = fdb_compact(dbfile, "./dummy2");
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    // retrieve check after compaction
    for (i=0;i<n;++i){
        sprintf(key, keystr, i);
        sprintf(value, valuestr, i);
        s = fdb_get_kv(db, key, strlen(key)+1, &value_out, &valuelen);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(value, value_out, valuelen);
        free(value_out);

        sprintf(value, valuestr_kv, i);
        s = fdb_get_kv(kv1, key, strlen(key)+1, &value_out, &valuelen);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(value, value_out, valuelen);
        free(value_out);
    }
    // info check after compaction
    s = fdb_get_file_info(dbfile, &file_info);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    TEST_CHK(file_info.doc_count == n*2);
    s = fdb_get_kvs_info(db, &kvs_info);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    TEST_CHK(kvs_info.doc_count == n);
    s = fdb_get_kvs_info(kv1, &kvs_info);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    TEST_CHK(kvs_info.doc_count == n);

    // reopen using "default" KVS name
    fdb_kvs_close(db);
    s = fdb_kvs_open(dbfile, &db, "default", &kvs_config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    for (i=0;i<n;++i){
        sprintf(key, keystr, i);
        sprintf(value, valuestr, i);
        s = fdb_get_kv(db, key, strlen(key)+1, &value_out, &valuelen);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(value, value_out, valuelen);
        free(value_out);
    }

    s = fdb_kvs_remove(dbfile, "kv1");
    // must fail due to opened handle
    TEST_CHK(s != FDB_RESULT_SUCCESS);

    // closing super handle also closes all other sub-handles;
    s = fdb_close(dbfile);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    // re-open
    if (opt & MULTI_KV_VAR_CMP) {
        s = fdb_open_custom_cmp(&dbfile, "./dummy2", &config,
                                2, kvs_names, functions);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
    } else {
        s = fdb_open(&dbfile, "./dummy2", &config);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
    }

    // remove "kv1" instance
    s = fdb_kvs_remove(dbfile, "kv1");
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_kvs_open(dbfile, &db, "default", &kvs_config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_kvs_open(dbfile, &kv1, "kv1", &kvs_config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    for (i=0;i<n;++i){
        sprintf(key, keystr, i);
        sprintf(value, valuestr, i);
        s = fdb_get_kv(db, key, strlen(key)+1, &value_out, &valuelen);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(value, value_out, valuelen);
        free(value_out);

        s = fdb_get_kv(kv1, key, strlen(key)+1, &value_out, &valuelen);
        TEST_CHK(s != FDB_RESULT_SUCCESS);
    }
    s = fdb_kvs_close(db);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_kvs_close(kv1);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    // remove "default" instance
    s = fdb_kvs_remove(dbfile, "default");
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_kvs_open(dbfile, &db, "default", &kvs_config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    for (i=0;i<n;++i){
        sprintf(key, keystr, i);
        s = fdb_get_kv(db, key, strlen(key)+1, &value_out, &valuelen);
        TEST_CHK(s != FDB_RESULT_SUCCESS);
    }
    s = fdb_kvs_close(db);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    // remove the empty "kv1" instance
    s = fdb_kvs_remove(dbfile, "kv1");
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    s = fdb_close(dbfile);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    s = fdb_shutdown();
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    memleak_end();

    if (opt & MULTI_KV_VAR_CMP) {
        TEST_RESULT("multiple KV instances basic test "
                    "(custom key order)");
    } else {
        TEST_RESULT("multiple KV instances basic test");
    }
}

void multi_kv_iterator_key_test(uint8_t opt)
{
    TEST_INIT();

    int n = 100;
    int i, r;
    char key[256], value[256];
    char keystr[] = "key%06d";
    char valuestr[] = "value%08d(%s)";
    fdb_file_handle *dbfile;
    fdb_kvs_handle *db, *kv1, *kv2;
    fdb_config config;
    fdb_kvs_config kvs_config;
    fdb_doc *doc;
    fdb_iterator *it;
    fdb_status s;

    sprintf(value, SHELL_DEL" dummy*");
    r = system(value);
    (void)r;

    memleak_start();

    config = fdb_get_default_config();
    kvs_config = fdb_get_default_kvs_config();
    config.multi_kv_instances = true;
    config.wal_threshold = 1000;
    config.buffercache_size = 0;

    s = fdb_open(&dbfile, "./dummy", &config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    if (opt & MULTI_KV_VAR_CMP) {
        kvs_config.custom_cmp = _multi_kv_test_keycmp;
    }
    s = fdb_kvs_open(dbfile, &db, NULL, &kvs_config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_kvs_open(dbfile, &kv1, "kv1", &kvs_config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_kvs_open(dbfile, &kv2, "kv2", &kvs_config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    for (i=0;i<n;i+=2) {
        sprintf(key, keystr, i);
        sprintf(value, valuestr, i, "default");
        s = fdb_set_kv(db, key, strlen(key)+1, value, strlen(value)+1);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        sprintf(value, valuestr, i, "kv1");
        s = fdb_set_kv(kv1, key, strlen(key)+1, value, strlen(value)+1);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        sprintf(value, valuestr, i, "kv2");
        s = fdb_set_kv(kv2, key, strlen(key)+1, value, strlen(value)+1);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
    }
    fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);

    for (i=1;i<n;i+=2) {
        sprintf(key, keystr, i);
        sprintf(value, valuestr, i, "default");
        s = fdb_set_kv(db, key, strlen(key)+1, value, strlen(value)+1);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        sprintf(value, valuestr, i, "kv1");
        s = fdb_set_kv(kv1, key, strlen(key)+1, value, strlen(value)+1);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        sprintf(value, valuestr, i, "kv2");
        s = fdb_set_kv(kv2, key, strlen(key)+1, value, strlen(value)+1);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
    }
    fdb_commit(dbfile, FDB_COMMIT_NORMAL);

    // iterate in default KV instance
    i = 0;
    s = fdb_iterator_init(db, &it, NULL, 0, NULL, 0, FDB_ITR_NONE);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    do {
        s = fdb_iterator_get(it, &doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        sprintf(key, keystr, i);
        sprintf(value, valuestr, i, "default");
        TEST_CMP(doc->key, key, doc->keylen);
        TEST_CMP(doc->body, value, doc->bodylen);
        r = ((i%2 == 0)?(i/2):(50+i/2)) +1;
        TEST_CHK(doc->seqnum == r);
        fdb_doc_free(doc);
        i++;
    } while (fdb_iterator_next(it) == FDB_RESULT_SUCCESS);
    TEST_CHK(i == n);
    fdb_iterator_close(it);

    // iterate in kv1 instance
    i = 0;
    s = fdb_iterator_init(kv1, &it, NULL, 0, NULL, 0, FDB_ITR_NONE);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    do {
        s = fdb_iterator_get(it, &doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        sprintf(key, keystr, i);
        sprintf(value, valuestr, i, "kv1");
        TEST_CMP(doc->key, key, doc->keylen);
        TEST_CMP(doc->body, value, doc->bodylen);
        r = ((i%2 == 0)?(i/2):(50+i/2)) +1;
        TEST_CHK(doc->seqnum == r);
        fdb_doc_free(doc);
        i++;
    } while (fdb_iterator_next(it) == FDB_RESULT_SUCCESS);
    TEST_CHK(i == n);
    // reverse iterate in kv1 instance
    TEST_CHK(fdb_iterator_prev(it) == FDB_RESULT_SUCCESS);
    do {
        s = fdb_iterator_get(it, &doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        i--;
        sprintf(key, keystr, i);
        sprintf(value, valuestr, i, "kv1");
        TEST_CMP(doc->key, key, doc->keylen);
        TEST_CMP(doc->body, value, doc->bodylen);
        r = ((i%2 == 0)?(i/2):(50+i/2)) +1;
        TEST_CHK(doc->seqnum == r);
        fdb_doc_free(doc);
    } while (fdb_iterator_prev(it) == FDB_RESULT_SUCCESS);
    TEST_CHK(i == 0);
    fdb_iterator_close(it);

    // iterate in kv2 instance
    i = 0;
    s = fdb_iterator_init(kv2, &it, NULL, 0, NULL, 0, FDB_ITR_NONE);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    do {
        s = fdb_iterator_get(it, &doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        sprintf(key, keystr, i);
        sprintf(value, valuestr, i, "kv2");
        TEST_CMP(doc->key, key, doc->keylen);
        TEST_CMP(doc->body, value, doc->bodylen);
        fdb_doc_free(doc);
        i++;
    } while (fdb_iterator_next(it) == FDB_RESULT_SUCCESS);
    TEST_CHK(i == n);
    fdb_iterator_close(it);

    // partial iterate in kv1 instance
    i = 40;
    char key2[256];
    sprintf(key, keystr, 40);
    sprintf(key2, keystr, 59);
    s = fdb_iterator_init(kv1, &it, key, strlen(key)+1, key2, strlen(key2)+1,
                          FDB_ITR_NONE);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    do {
        s = fdb_iterator_get(it, &doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        sprintf(key, keystr, i);
        sprintf(value, valuestr, i, "kv1");
        TEST_CMP(doc->key, key, doc->keylen);
        TEST_CMP(doc->body, value, doc->bodylen);
        fdb_doc_free(doc);
        i++;
    } while (fdb_iterator_next(it) == FDB_RESULT_SUCCESS);
    TEST_CHK(i == 60);
    fdb_iterator_close(it);

    s = fdb_kvs_close(kv1);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_kvs_close(kv2);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_close(dbfile);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_shutdown();
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    memleak_end();

    if (opt & MULTI_KV_VAR_CMP) {
        TEST_RESULT("multiple KV instances iterator test "
                    "(custom key order)");
    } else {
        TEST_RESULT("multiple KV instances iterator test");
    }
}

void multi_kv_iterator_seq_test(uint8_t opt)
{
    TEST_INIT();

    int n = 100;
    int i, r;
    char key[256], value[256];
    char keystr[] = "key%06d";
    char valuestr[] = "value%08d(%s)";
    fdb_file_handle *dbfile;
    fdb_kvs_handle *db, *kv1, *kv2;
    fdb_config config;
    fdb_kvs_config kvs_config;
    fdb_doc *doc;
    fdb_iterator *it;
    fdb_status s;
    fdb_seqnum_t seqnum;

    sprintf(value, SHELL_DEL" dummy*");
    r = system(value);
    (void)r;

    memleak_start();

    config = fdb_get_default_config();
    kvs_config = fdb_get_default_kvs_config();
    config.multi_kv_instances = true;
    config.wal_threshold = 1000;
    config.buffercache_size = 0;

    s = fdb_open(&dbfile, "./dummy", &config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    if (opt & MULTI_KV_VAR_CMP) {
        kvs_config.custom_cmp = _multi_kv_test_keycmp;
    }
    s = fdb_kvs_open(dbfile, &db, NULL, &kvs_config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_kvs_open(dbfile, &kv1, "kv1", &kvs_config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_kvs_open(dbfile, &kv2, "kv2", &kvs_config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    // write documents first time
    for (i=0;i<n;++i){
        sprintf(key, keystr, i);
        sprintf(value, valuestr, i, "default");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, value, strlen(value)+1);
        s = fdb_set(db, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        fdb_doc_free(doc);
        sprintf(value, valuestr, i, "kv1");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, value, strlen(value)+1);
        s = fdb_set(kv1, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        fdb_doc_free(doc);
        sprintf(value, valuestr, i, "kv2");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, value, strlen(value)+1);
        s = fdb_set(kv2, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        fdb_doc_free(doc);
    }
    s = fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    // re-write documents
    for (i=0;i<n;++i){
        sprintf(key, keystr, i);
        sprintf(value, valuestr, i, "default_second");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, value, strlen(value)+1);
        s = fdb_set(db, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        fdb_doc_free(doc);
        sprintf(value, valuestr, i, "kv1_second");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, value, strlen(value)+1);
        s = fdb_set(kv1, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        fdb_doc_free(doc);
        sprintf(value, valuestr, i, "kv2_second");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, value, strlen(value)+1);
        s = fdb_set(kv2, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        fdb_doc_free(doc);
    }
    s = fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    // write third time (even number docs only)
    for (i=0;i<n;i+=2){
        sprintf(key, keystr, i);
        sprintf(value, valuestr, i, "default_third");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, value, strlen(value)+1);
        s = fdb_set(db, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        fdb_doc_free(doc);
        sprintf(value, valuestr, i, "kv1_third");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, value, strlen(value)+1);
        s = fdb_set(kv1, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        fdb_doc_free(doc);
        sprintf(value, valuestr, i, "kv2_third");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, value, strlen(value)+1);
        s = fdb_set(kv2, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        fdb_doc_free(doc);
    }
    s = fdb_commit(dbfile, FDB_COMMIT_NORMAL);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    // iterate in default KV instance
    i = 1;
    s = fdb_iterator_sequence_init(db, &it, 0, 0, FDB_ITR_NONE);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    while (fdb_iterator_next(it) == FDB_RESULT_SUCCESS) {
        i++;
    }
    TEST_CHK(i == n);
    fdb_iterator_close(it);

    // iterate in KV1
    i = 0;
    s = fdb_iterator_sequence_init(kv1, &it, 0, 0, FDB_ITR_NONE);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    do {
        s = fdb_iterator_get(it, &doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        if (i < 50) {
            r = i*2 + 1;
            seqnum = 100 + (i+1)*2;
            sprintf(value, valuestr, r, "kv1_second");
        } else {
            r = (i-50)*2;
            seqnum = 151 + i;
            sprintf(value, valuestr, r, "kv1_third");
        }
        sprintf(key, keystr, r);
        TEST_CMP(key, doc->key, doc->keylen);
        TEST_CMP(value, doc->body, doc->bodylen);
        TEST_CHK(doc->seqnum == seqnum);
        fdb_doc_free(doc);
        i++;
    } while (fdb_iterator_next(it) == FDB_RESULT_SUCCESS);
    TEST_CHK(i == n);
    // reverse iterate in KV1
    TEST_CHK(fdb_iterator_prev(it) == FDB_RESULT_SUCCESS);
    do {
        s = fdb_iterator_get(it, &doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        i--;
        if (i < 50) {
            r = i*2 + 1;
            seqnum = 100 + (i+1)*2;
            sprintf(value, valuestr, r, "kv1_second");
        } else {
            r = (i-50)*2;
            seqnum = 151 + i;
            sprintf(value, valuestr, r, "kv1_third");
        }
        sprintf(key, keystr, r);
        TEST_CMP(key, doc->key, doc->keylen);
        TEST_CMP(value, doc->body, doc->bodylen);
        TEST_CHK(doc->seqnum == seqnum);
        fdb_doc_free(doc);
    } while (fdb_iterator_prev(it) == FDB_RESULT_SUCCESS);
    TEST_CHK(i == 0);
    fdb_iterator_close(it);

    // iterate in KV2
    i = 0;
    s = fdb_iterator_sequence_init(kv2, &it, 0, 0, FDB_ITR_NONE);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    do {
        s = fdb_iterator_get(it, &doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        if (i < 50) {
            r = i*2 + 1;
            seqnum = 100 + (i+1)*2;
            sprintf(value, valuestr, r, "kv2_second");
        } else {
            r = (i-50)*2;
            seqnum = 151 + i;
            sprintf(value, valuestr, r, "kv2_third");
        }
        (void)seqnum;
        sprintf(key, keystr, r);
        fdb_doc_free(doc);
        i++;
    } while (fdb_iterator_next(it) == FDB_RESULT_SUCCESS);
    TEST_CHK(i == n);
    fdb_iterator_close(it);

    // partial iterate in KV1
    i = 0;
    s = fdb_iterator_sequence_init(kv1, &it, 150, 220, FDB_ITR_NONE);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    do {
        s = fdb_iterator_get(it, &doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        //printf("%d %s %s %d\n", i, (char*)doc->key, (char*)doc->body, (int)doc->seqnum);
        if (i<26) {
            r = 49 + i*2;
            seqnum = i*2 + 150;
            sprintf(value, valuestr, r, "kv1_second");
        } else {
            r = (i-26)*2;
            seqnum = 201 + (i-26);
            sprintf(value, valuestr, r, "kv1_third");
        }
        (void)seqnum;
        fdb_doc_free(doc);
        i++;
    } while (fdb_iterator_next(it) == FDB_RESULT_SUCCESS);
    TEST_CHK(i == 46);
    fdb_iterator_close(it);

    s = fdb_kvs_close(kv1);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_kvs_close(kv2);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_close(dbfile);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_shutdown();
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    memleak_end();

    if (opt & MULTI_KV_VAR_CMP) {
        TEST_RESULT("multiple KV instances sequence iterator test "
                    "(custom key order)");
    } else {
        TEST_RESULT("multiple KV instances sequence iterator test");
    }
}

void multi_kv_txn_test(uint8_t opt)
{
    TEST_INIT();

    int n = 100;
    int i, r;
    char key[256], value[256];
    char keystr[] = "key%06d";
    char valuestr[] = "value%08d(%s)";
    fdb_file_handle *dbfile, *dbfile_txn1;
    fdb_kvs_handle *db, *kv1, *kv2;
    fdb_kvs_handle *txn1, *txn1_kv1, *txn1_kv2;
    fdb_config config;
    fdb_kvs_config kvs_config;
    fdb_doc *doc;
    fdb_status s;

    char *kvs_names[] = {(char*)"default", (char*)"kv1", (char*)"kv2"};
    fdb_custom_cmp_variable functions[] = {_multi_kv_test_keycmp,
                                           _multi_kv_test_keycmp,
                                           _multi_kv_test_keycmp};

    sprintf(value, SHELL_DEL" dummy*");
    r = system(value);
    (void)r;

    memleak_start();

    config = fdb_get_default_config();
    kvs_config = fdb_get_default_kvs_config();
    config.multi_kv_instances = true;
    config.wal_threshold = 1000;
    config.buffercache_size = 0;

    s = fdb_open(&dbfile, "./dummy", &config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    if (opt & MULTI_KV_VAR_CMP) {
        kvs_config.custom_cmp = _multi_kv_test_keycmp;
    }
    s = fdb_kvs_open(dbfile, &db, NULL, &kvs_config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_kvs_open(dbfile, &kv1, "kv1", &kvs_config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_kvs_open(dbfile, &kv2, "kv2", &kvs_config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    // write documents first time
    for (i=0;i<n;++i){
        sprintf(key, keystr, i);
        sprintf(value, valuestr, i, "default");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, value, strlen(value)+1);
        s = fdb_set(db, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        fdb_doc_free(doc);
        sprintf(value, valuestr, i, "kv1");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, value, strlen(value)+1);
        s = fdb_set(kv1, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        fdb_doc_free(doc);
        sprintf(value, valuestr, i, "kv2");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, value, strlen(value)+1);
        s = fdb_set(kv2, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        fdb_doc_free(doc);
    }
    s = fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    // begin a transaction
    if (opt & MULTI_KV_VAR_CMP) {
        s = fdb_open_custom_cmp(&dbfile_txn1, "./dummy", &config,
                                3, kvs_names, functions);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
    } else {
        s = fdb_open(&dbfile_txn1, "./dummy", &config);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
    }
    s = fdb_kvs_open(dbfile_txn1, &txn1, NULL, &kvs_config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_kvs_open(dbfile_txn1, &txn1_kv1, "kv1", &kvs_config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_kvs_open(dbfile_txn1, &txn1_kv2, "kv2", &kvs_config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_begin_transaction(dbfile_txn1, FDB_ISOLATION_READ_COMMITTED);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    for (i=0;i<n;++i){
        sprintf(key, keystr, i);
        sprintf(value, valuestr, i, "default(txn)");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, value, strlen(value)+1);
        s = fdb_set(txn1, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        fdb_doc_free(doc);
        sprintf(value, valuestr, i, "kv1(txn)");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, value, strlen(value)+1);
        s = fdb_set(txn1_kv1, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        fdb_doc_free(doc);
        sprintf(value, valuestr, i, "kv2(txn)");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, value, strlen(value)+1);
        s = fdb_set(txn1_kv2, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        fdb_doc_free(doc);
    }

    // retrieve before commit (dirty read through the transaction)
    for (i=0;i<n;++i){
        sprintf(key, keystr, i);
        sprintf(value, valuestr, i, "default(txn)");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, NULL, 0);
        s = fdb_get(txn1, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(value, doc->body, doc->bodylen);
        fdb_doc_free(doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        sprintf(value, valuestr, i, "kv1(txn)");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, NULL, 0);
        s = fdb_get(txn1_kv1, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(value, doc->body, doc->bodylen);
        fdb_doc_free(doc);
        sprintf(value, valuestr, i, "kv2(txn)");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, NULL, 0);
        s = fdb_get(txn1_kv2, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(value, doc->body, doc->bodylen);
        fdb_doc_free(doc);
    }

    // retrieve before commit (isolation test)
    for (i=0;i<n;++i){
        sprintf(key, keystr, i);
        sprintf(value, valuestr, i, "default");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, NULL, 0);
        s = fdb_get(db, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(value, doc->body, doc->bodylen);
        fdb_doc_free(doc);
        sprintf(value, valuestr, i, "kv1");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, NULL, 0);
        s = fdb_get(kv1, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(value, doc->body, doc->bodylen);
        fdb_doc_free(doc);
        sprintf(value, valuestr, i, "kv2");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, NULL, 0);
        s = fdb_get(kv2, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(value, doc->body, doc->bodylen);
        fdb_doc_free(doc);
    }

    s = fdb_end_transaction(dbfile_txn1, FDB_COMMIT_NORMAL);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    // retrieve after commit (through the transaction)
    for (i=0;i<n;++i){
        sprintf(key, keystr, i);
        sprintf(value, valuestr, i, "default(txn)");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, NULL, 0);
        s = fdb_get(txn1, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(value, doc->body, doc->bodylen);
        fdb_doc_free(doc);
        sprintf(value, valuestr, i, "kv1(txn)");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, NULL, 0);
        s = fdb_get(txn1_kv1, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(value, doc->body, doc->bodylen);
        fdb_doc_free(doc);
        sprintf(value, valuestr, i, "kv2(txn)");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, NULL, 0);
        s = fdb_get(txn1_kv2, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(value, doc->body, doc->bodylen);
        fdb_doc_free(doc);
    }

    // retrieve after commit (isolation test)
    for (i=0;i<n;++i){
        sprintf(key, keystr, i);
        sprintf(value, valuestr, i, "default(txn)");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, NULL, 0);
        s = fdb_get(db, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(value, doc->body, doc->bodylen);
        fdb_doc_free(doc);
        sprintf(value, valuestr, i, "kv1(txn)");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, NULL, 0);
        s = fdb_get(kv1, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(value, doc->body, doc->bodylen);
        fdb_doc_free(doc);
        sprintf(value, valuestr, i, "kv2(txn)");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, NULL, 0);
        s = fdb_get(kv2, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(value, doc->body, doc->bodylen);
        fdb_doc_free(doc);
    }

    // reopen
    s = fdb_kvs_close(txn1_kv1);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_kvs_close(txn1_kv2);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_close(dbfile_txn1);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_kvs_close(kv1);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_kvs_close(kv2);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_close(dbfile);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    if (opt & MULTI_KV_VAR_CMP) {
        s = fdb_open_custom_cmp(&dbfile, "./dummy", &config,
                                3, kvs_names, functions);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
    } else {
        s = fdb_open(&dbfile, "./dummy", &config);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
    }
    s = fdb_kvs_open(dbfile, &db, NULL, &kvs_config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_kvs_open(dbfile, &kv1, "kv1", &kvs_config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_kvs_open(dbfile, &kv2, "kv2", &kvs_config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    // retrieve after reopen
    for (i=0;i<n;++i){
        sprintf(key, keystr, i);
        sprintf(value, valuestr, i, "default(txn)");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, NULL, 0);
        s = fdb_get(db, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(value, doc->body, doc->bodylen);
        fdb_doc_free(doc);
        sprintf(value, valuestr, i, "kv1(txn)");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, NULL, 0);
        s = fdb_get(kv1, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(value, doc->body, doc->bodylen);
        fdb_doc_free(doc);
        sprintf(value, valuestr, i, "kv2(txn)");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, NULL, 0);
        s = fdb_get(kv2, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(value, doc->body, doc->bodylen);
        fdb_doc_free(doc);
    }

    // begin a transaction
    if (opt & MULTI_KV_VAR_CMP) {
        s = fdb_open_custom_cmp(&dbfile_txn1, "./dummy", &config,
                                3, kvs_names, functions);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
    } else {
        s = fdb_open(&dbfile_txn1, "./dummy", &config);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
    }
    s = fdb_kvs_open(dbfile_txn1, &txn1, NULL, &kvs_config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_kvs_open(dbfile_txn1, &txn1_kv1, "kv1", &kvs_config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_kvs_open(dbfile_txn1, &txn1_kv2, "kv2", &kvs_config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_begin_transaction(dbfile_txn1, FDB_ISOLATION_READ_COMMITTED);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    for (i=0;i<n;++i){
        sprintf(key, keystr, i);
        sprintf(value, valuestr, i, "default(txn_abort)");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, value, strlen(value)+1);
        s = fdb_set(txn1, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        fdb_doc_free(doc);
        sprintf(value, valuestr, i, "kv1(txn_abort)");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, value, strlen(value)+1);
        s = fdb_set(txn1_kv1, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        fdb_doc_free(doc);
        sprintf(value, valuestr, i, "kv2(txn_abort)");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, value, strlen(value)+1);
        s = fdb_set(txn1_kv2, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        fdb_doc_free(doc);
    }

    // abort the transaction
    s = fdb_abort_transaction(dbfile_txn1);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    // reopen
    s = fdb_kvs_close(txn1_kv1);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_kvs_close(txn1_kv2);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_close(dbfile_txn1);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_kvs_close(kv1);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_kvs_close(kv2);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_close(dbfile);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    if (opt & MULTI_KV_VAR_CMP) {
        s = fdb_open_custom_cmp(&dbfile, "./dummy", &config,
                                3, kvs_names, functions);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
    } else {
        s = fdb_open(&dbfile, "./dummy", &config);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
    }
    s = fdb_kvs_open(dbfile, &db, NULL, &kvs_config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_kvs_open(dbfile, &kv1, "kv1", &kvs_config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_kvs_open(dbfile, &kv2, "kv2", &kvs_config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    // retrieve after reopen
    for (i=0;i<n;++i){
        sprintf(key, keystr, i);
        sprintf(value, valuestr, i, "default(txn)");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, NULL, 0);
        s = fdb_get(db, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(value, doc->body, doc->bodylen);
        fdb_doc_free(doc);
        sprintf(value, valuestr, i, "kv1(txn)");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, NULL, 0);
        s = fdb_get(kv1, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(value, doc->body, doc->bodylen);
        fdb_doc_free(doc);
        sprintf(value, valuestr, i, "kv2(txn)");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, NULL, 0);
        s = fdb_get(kv2, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(value, doc->body, doc->bodylen);
        fdb_doc_free(doc);
    }

    // get KVS names
    fdb_kvs_name_list kvs_name_list;
    s = fdb_get_kvs_name_list(dbfile, &kvs_name_list);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    TEST_CHK(kvs_name_list.num_kvs_names == 3);
    for (i=0;i<kvs_name_list.num_kvs_names;++i){
        TEST_CHK(!strcmp(kvs_name_list.kvs_names[i], kvs_names[i]));
    }
    fdb_free_kvs_name_list(&kvs_name_list);

    s = fdb_kvs_close(kv1);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_kvs_close(kv2);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_close(dbfile);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    s = fdb_shutdown();
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    memleak_end();

    if (opt & MULTI_KV_VAR_CMP) {
        TEST_RESULT("multiple KV instances transaction test "
                    "(custom key order)");
    } else {
        TEST_RESULT("multiple KV instances transaction test");
    }
}

void multi_kv_snapshot_test(uint8_t opt)
{
    TEST_INIT();

    int n = 100;
    int i, r;
    char key[256], value[256];
    char keystr[] = "key%06d";
    char valuestr[] = "value%08d(%s)";
    fdb_file_handle *dbfile;
    fdb_kvs_handle *db, *kv1, *kv2;
    fdb_kvs_handle *snap1, *snap2;
    fdb_seqnum_t seq1, seq2;
    fdb_config config;
    fdb_kvs_config kvs_config;
    fdb_doc *doc;
    fdb_status s;

    sprintf(value, SHELL_DEL" dummy*");
    r = system(value);
    (void)r;

    memleak_start();

    config = fdb_get_default_config();
    kvs_config = fdb_get_default_kvs_config();
    config.multi_kv_instances = true;
    config.wal_threshold = 1000;
    config.buffercache_size = 0;

    s = fdb_open(&dbfile, "./dummy", &config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    if (opt & MULTI_KV_VAR_CMP) {
        kvs_config.custom_cmp = _multi_kv_test_keycmp;
    }
    s = fdb_kvs_open(dbfile, &db, NULL, &kvs_config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_kvs_open(dbfile, &kv1, "kv1", &kvs_config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_kvs_open(dbfile, &kv2, "kv2", &kvs_config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    // write documents first time
    for (i=0;i<n;++i){
        sprintf(key, keystr, i);
        sprintf(value, valuestr, i, "default(commit1)");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, value, strlen(value)+1);
        s = fdb_set(db, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        fdb_doc_free(doc);
        sprintf(value, valuestr, i, "kv1(commit1)");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, value, strlen(value)+1);
        s = fdb_set(kv1, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        fdb_doc_free(doc);
        sprintf(value, valuestr, i, "kv2(commit1)");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, value, strlen(value)+1);
        s = fdb_set(kv2, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        fdb_doc_free(doc);
    }
    s = fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_get_kvs_seqnum(kv1, &seq1);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    // write documents second time
    for (i=0;i<n;++i){
        sprintf(key, keystr, i);
        sprintf(value, valuestr, i, "default(commit2)");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, value, strlen(value)+1);
        s = fdb_set(db, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        fdb_doc_free(doc);
        sprintf(value, valuestr, i, "kv1(commit2)");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, value, strlen(value)+1);
        s = fdb_set(kv1, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        fdb_doc_free(doc);
        sprintf(value, valuestr, i, "kv2(commit2)");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, value, strlen(value)+1);
        s = fdb_set(kv2, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        fdb_doc_free(doc);
    }
    s = fdb_commit(dbfile, FDB_COMMIT_NORMAL);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_get_kvs_seqnum(kv2, &seq2);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    // write documents third time
    for (i=0;i<n;++i){
        sprintf(key, keystr, i);
        sprintf(value, valuestr, i, "default(commit3)");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, value, strlen(value)+1);
        s = fdb_set(db, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        fdb_doc_free(doc);
        sprintf(value, valuestr, i, "kv1(commit3)");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, value, strlen(value)+1);
        s = fdb_set(kv1, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        fdb_doc_free(doc);
        sprintf(value, valuestr, i, "kv2(commit3)");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, value, strlen(value)+1);
        s = fdb_set(kv2, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        fdb_doc_free(doc);
    }
    s = fdb_commit(dbfile, FDB_COMMIT_NORMAL);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    // create snapshots
    s = fdb_snapshot_open(kv1, &snap1, seq1);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_snapshot_open(kv2, &snap2, seq2);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    // retrieve
    for (i=0;i<n;++i){
        sprintf(key, keystr, i);
        sprintf(value, valuestr, i, "kv1(commit3)");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, NULL, 0);
        s = fdb_get(kv1, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(value, doc->body, doc->bodylen);
        fdb_doc_free(doc);

        sprintf(value, valuestr, i, "kv2(commit3)");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, NULL, 0);
        s = fdb_get(kv2, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(value, doc->body, doc->bodylen);
        fdb_doc_free(doc);

        sprintf(value, valuestr, i, "kv1(commit1)");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, NULL, 0);
        s = fdb_get(snap1, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(value, doc->body, doc->bodylen);
        fdb_doc_free(doc);

        sprintf(value, valuestr, i, "kv2(commit2)");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, NULL, 0);
        s = fdb_get(snap2, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(value, doc->body, doc->bodylen);
        fdb_doc_free(doc);
    }

    s = fdb_kvs_close(snap1);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_kvs_close(snap2);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    s = fdb_kvs_close(kv1);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_kvs_close(kv2);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_close(dbfile);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    s = fdb_shutdown();
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    memleak_end();

    if (opt & MULTI_KV_VAR_CMP) {
        TEST_RESULT("multiple KV instances snapshot test "
                    "(custom key order)");
    } else {
        TEST_RESULT("multiple KV instances snapshot test");
    }
}

void multi_kv_rollback_test(uint8_t opt)
{
    TEST_INIT();

    int n = 100;
    int i, r;
    char key[256], value[256];
    char keystr[] = "key%06d";
    char valuestr[] = "value%08d(%s)";
    fdb_file_handle *dbfile;
    fdb_kvs_handle *db, *kv1, *kv2;
    fdb_seqnum_t seq1, seq2, seq3;
    fdb_config config;
    fdb_kvs_config kvs_config;
    fdb_doc *doc;
    fdb_status s;

    char *kvs_names[] = {NULL, (char*)"kv1", (char*)"kv2"};
    fdb_custom_cmp_variable functions[] = {_multi_kv_test_keycmp,
                                           _multi_kv_test_keycmp,
                                           _multi_kv_test_keycmp};

    sprintf(value, SHELL_DEL" dummy*");
    r = system(value);
    (void)r;

    memleak_start();

    config = fdb_get_default_config();
    kvs_config = fdb_get_default_kvs_config();
    config.multi_kv_instances = true;
    config.wal_threshold = 1000;
    config.buffercache_size = 0;

    if (opt & MULTI_KV_VAR_CMP) {
        s = fdb_open_custom_cmp(&dbfile, "./dummy", &config,
                                3, kvs_names, functions);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
    } else {
        s = fdb_open(&dbfile, "./dummy", &config);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
    }
    s = fdb_kvs_open(dbfile, &db, NULL, &kvs_config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_kvs_open(dbfile, &kv1, "kv1", &kvs_config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_kvs_open(dbfile, &kv2, "kv2", &kvs_config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    // write documents first time
    for (i=0;i<n;++i){
        sprintf(key, keystr, i);
        sprintf(value, valuestr, i, "default(commit1)");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, value, strlen(value)+1);
        s = fdb_set(db, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        fdb_doc_free(doc);
        sprintf(value, valuestr, i, "kv1(commit1)");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, value, strlen(value)+1);
        s = fdb_set(kv1, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        if (i%15 == 0) s = fdb_set(kv1, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        fdb_doc_free(doc);
        sprintf(value, valuestr, i, "kv2(commit1)");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, value, strlen(value)+1);
        s = fdb_set(kv2, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        if (i%27 == 0) s = fdb_set(kv2, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        fdb_doc_free(doc);
    }
    s = fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_get_kvs_seqnum(kv1, &seq1);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    // write documents second time
    for (i=0;i<n;++i){
        sprintf(key, keystr, i);
        sprintf(value, valuestr, i, "default(commit2)");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, value, strlen(value)+1);
        s = fdb_set(db, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        fdb_doc_free(doc);
        sprintf(value, valuestr, i, "kv1(commit2)");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, value, strlen(value)+1);
        s = fdb_set(kv1, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        if (i%15 == 0) s = fdb_set(kv1, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        fdb_doc_free(doc);
        sprintf(value, valuestr, i, "kv2(commit2)");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, value, strlen(value)+1);
        s = fdb_set(kv2, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        if (i%27 == 0) s = fdb_set(kv2, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        fdb_doc_free(doc);
    }
    s = fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_get_kvs_seqnum(db, &seq2);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    // write documents third time
    for (i=0;i<n;++i){
        sprintf(key, keystr, i);
        sprintf(value, valuestr, i, "default(commit3)");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, value, strlen(value)+1);
        s = fdb_set(db, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        fdb_doc_free(doc);
        sprintf(value, valuestr, i, "kv1(commit3)");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, value, strlen(value)+1);
        s = fdb_set(kv1, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        if (i%15 == 0) s = fdb_set(kv1, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        fdb_doc_free(doc);
        sprintf(value, valuestr, i, "kv2(commit3)");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, value, strlen(value)+1);
        s = fdb_set(kv2, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        if (i%27 == 0) s = fdb_set(kv2, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        fdb_doc_free(doc);
    }
    s = fdb_commit(dbfile, FDB_COMMIT_NORMAL);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_get_kvs_seqnum(kv2, &seq3);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    // write documents third time
    for (i=0;i<n;++i){
        sprintf(key, keystr, i);
        sprintf(value, valuestr, i, "default(commit4)");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, value, strlen(value)+1);
        s = fdb_set(db, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        fdb_doc_free(doc);
        sprintf(value, valuestr, i, "kv1(commit4)");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, value, strlen(value)+1);
        s = fdb_set(kv1, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        if (i%15 == 0) s = fdb_set(kv1, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        fdb_doc_free(doc);
        sprintf(value, valuestr, i, "kv2(commit4)");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, value, strlen(value)+1);
        s = fdb_set(kv2, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        if (i%27 == 0) s = fdb_set(kv2, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        fdb_doc_free(doc);
    }
    s = fdb_commit(dbfile, FDB_COMMIT_NORMAL);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    // rollback kv1 using seq1
    s = fdb_rollback(&kv1, seq1);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    // retrieve check
    for (i=0;i<n;++i){
        sprintf(key, keystr, i);
        sprintf(value, valuestr, i, "default(commit4)");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, NULL, 0);
        s = fdb_get(db, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(value, doc->body, doc->bodylen);
        fdb_doc_free(doc);
        sprintf(value, valuestr, i, "kv1(commit1)");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, NULL, 0);
        s = fdb_get(kv1, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(value, doc->body, doc->bodylen);
        fdb_doc_free(doc);
        sprintf(value, valuestr, i, "kv2(commit4)");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, NULL, 0);
        s = fdb_get(kv2, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(value, doc->body, doc->bodylen);
        fdb_doc_free(doc);
    }

    // rollback db using seq2
    s = fdb_rollback(&db, seq2);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    // retrieve check
    for (i=0;i<n;++i){
        sprintf(key, keystr, i);
        sprintf(value, valuestr, i, "default(commit2)");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, NULL, 0);
        s = fdb_get(db, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(value, doc->body, doc->bodylen);
        fdb_doc_free(doc);
        sprintf(value, valuestr, i, "kv1(commit1)");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, NULL, 0);
        s = fdb_get(kv1, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(value, doc->body, doc->bodylen);
        fdb_doc_free(doc);
        sprintf(value, valuestr, i, "kv2(commit4)");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, NULL, 0);
        s = fdb_get(kv2, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(value, doc->body, doc->bodylen);
        fdb_doc_free(doc);
    }

    // rollback db using seq3
    s = fdb_rollback(&kv2, seq3);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    // retrieve check
    for (i=0;i<n;++i){
        sprintf(key, keystr, i);
        sprintf(value, valuestr, i, "default(commit2)");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, NULL, 0);
        s = fdb_get(db, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(value, doc->body, doc->bodylen);
        fdb_doc_free(doc);
        sprintf(value, valuestr, i, "kv1(commit1)");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, NULL, 0);
        s = fdb_get(kv1, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(value, doc->body, doc->bodylen);
        fdb_doc_free(doc);
        sprintf(value, valuestr, i, "kv2(commit3)");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, NULL, 0);
        s = fdb_get(kv2, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(value, doc->body, doc->bodylen);
        fdb_doc_free(doc);
    }

    // close & re-open
    s = fdb_kvs_close(kv1);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_kvs_close(kv2);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_close(dbfile);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    if (opt & MULTI_KV_VAR_CMP) {
        s = fdb_open_custom_cmp(&dbfile, "./dummy", &config,
                                3, kvs_names, functions);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
    } else {
        s = fdb_open(&dbfile, "./dummy", &config);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
    }
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    fdb_kvs_open(dbfile, &db, NULL, &kvs_config);
    fdb_kvs_open(dbfile, &kv1, "kv1", &kvs_config);
    fdb_kvs_open(dbfile, &kv2, "kv2", &kvs_config);

    // retrieve check after re-open
    for (i=0;i<n;++i){
        sprintf(key, keystr, i);
        sprintf(value, valuestr, i, "default(commit2)");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, NULL, 0);
        s = fdb_get(db, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(value, doc->body, doc->bodylen);
        fdb_doc_free(doc);
        sprintf(value, valuestr, i, "kv1(commit1)");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, NULL, 0);
        s = fdb_get(kv1, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(value, doc->body, doc->bodylen);
        fdb_doc_free(doc);
        sprintf(value, valuestr, i, "kv2(commit3)");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, NULL, 0);
        s = fdb_get(kv2, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(value, doc->body, doc->bodylen);
        fdb_doc_free(doc);
    }

    fdb_kvs_close(kv1);
    fdb_kvs_close(kv2);
    fdb_close(dbfile);

    fdb_shutdown();

    memleak_end();

    if (opt & MULTI_KV_VAR_CMP) {
        TEST_RESULT("multiple KV instances rollback test "
                    "(custom key order)");
    } else {
        TEST_RESULT("multiple KV instances rollback test");
    }
}

void multi_kv_custom_cmp_test()
{
    TEST_INIT();

    int n = 1000;
    int i, r;
    char key[256], value[256];
    char keystr[] = "key%06d";
    char valuestr[] = "value%08d(%s)";
    fdb_file_handle *dbfile;
    fdb_kvs_handle *db, *kv1, *kv2;
    fdb_config config;
    fdb_kvs_config kvs_config;
    fdb_doc *doc;
    fdb_iterator *it;
    fdb_status s;

    sprintf(value, SHELL_DEL" dummy*");
    r = system(value);
    (void)r;

    memleak_start();

    config = fdb_get_default_config();
    kvs_config = fdb_get_default_kvs_config();
    config.multi_kv_instances = true;
    config.wal_threshold = 256;
    config.wal_flush_before_commit = false;
    config.buffercache_size = 0;

    s = fdb_open(&dbfile, "./dummy", &config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_kvs_open(dbfile, &db, NULL, &kvs_config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    // insert using 'default' instance
    for (i=0;i<n;++i) {
        sprintf(key, keystr, i);
        sprintf(value, valuestr, i, "default");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, value, strlen(value)+1);
        s = fdb_set(db, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        fdb_doc_free(doc);
    }
    s = fdb_commit(dbfile, FDB_COMMIT_NORMAL);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    // create 'kv1' using custom cmp function
    kvs_config.custom_cmp = _multi_kv_test_keycmp;
    s = fdb_kvs_open(dbfile, &kv1, "kv1", &kvs_config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    // insert using 'kv1' instance
    for (i=0;i<n;++i) {
        sprintf(key, keystr, i);
        sprintf(value, valuestr, i, "kv1_custom_cmp");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, value, strlen(value)+1);
        s = fdb_set(kv1, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        fdb_doc_free(doc);
    }
    s = fdb_commit(dbfile, FDB_COMMIT_NORMAL);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    // retrieve check
    for (i=0;i<n;++i) {
        sprintf(key, keystr, i);
        sprintf(value, valuestr, i, "default");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, NULL, 0);
        s = fdb_get(db, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(value, doc->body, doc->bodylen);
        fdb_doc_free(doc);

        sprintf(value, valuestr, i, "kv1_custom_cmp");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, NULL, 0);
        s = fdb_get(kv1, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(value, doc->body, doc->bodylen);
        fdb_doc_free(doc);
    }

    // close & reopen handles
    s = fdb_close(dbfile);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    kvs_config.custom_cmp = NULL;
    s = fdb_open(&dbfile, "./dummy", &config);
    TEST_CHK(s != FDB_RESULT_SUCCESS); // must fail

    { // retry with wrong cmp function
        char *kvs_names[] = {NULL};
        fdb_custom_cmp_variable functions[] = {_multi_kv_test_keycmp};
        s = fdb_open_custom_cmp(&dbfile, "./dummy", &config,
                                1, kvs_names, functions);
        TEST_CHK(s != FDB_RESULT_SUCCESS); // must fail
    }

    { // retry with correct function
        char *kvs_names[] = {(char*)"kv1"};
        fdb_custom_cmp_variable functions[] = {_multi_kv_test_keycmp};
        s = fdb_open_custom_cmp(&dbfile, "./dummy", &config,
                                1, kvs_names, functions);
        TEST_CHK(s == FDB_RESULT_SUCCESS); // must succeed this time
    }

    s = fdb_kvs_open(dbfile, &db, NULL, &kvs_config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_kvs_open(dbfile, &kv1, "kv1", &kvs_config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    // retrieve check
    for (i=0;i<n;++i) {
        sprintf(key, keystr, i);
        sprintf(value, valuestr, i, "default");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, NULL, 0);
        s = fdb_get(db, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(value, doc->body, doc->bodylen);
        fdb_doc_free(doc);

        sprintf(value, valuestr, i, "kv1_custom_cmp");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, NULL, 0);
        s = fdb_get(kv1, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(value, doc->body, doc->bodylen);
        fdb_doc_free(doc);
    }

    // create one more KV store
    kvs_config.custom_cmp = NULL;
    s = fdb_kvs_open(dbfile, &kv2, "kv2", &kvs_config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    // insert using 'kv2' instance
    for (i=0;i<n;++i) {
        sprintf(key, keystr, i);
        sprintf(value, valuestr, i, "kv2");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, value, strlen(value)+1);
        s = fdb_set(kv2, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        fdb_doc_free(doc);
    }
    s = fdb_commit(dbfile, FDB_COMMIT_NORMAL);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    // retrieve check
    for (i=0;i<n;++i) {
        sprintf(key, keystr, i);
        sprintf(value, valuestr, i, "default");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, NULL, 0);
        s = fdb_get(db, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(value, doc->body, doc->bodylen);
        fdb_doc_free(doc);

        sprintf(value, valuestr, i, "kv1_custom_cmp");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, NULL, 0);
        s = fdb_get(kv1, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(value, doc->body, doc->bodylen);
        fdb_doc_free(doc);

        sprintf(value, valuestr, i, "kv2");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, NULL, 0);
        s = fdb_get(kv2, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(value, doc->body, doc->bodylen);
        fdb_doc_free(doc);
    }

    // update all documents
    for (i=0;i<n;++i) {
        sprintf(key, keystr, i);
        sprintf(value, valuestr, i, "default(updated)");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, value, strlen(value)+1);
        s = fdb_set(db, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        fdb_doc_free(doc);

        sprintf(key, keystr, i);
        sprintf(value, valuestr, i, "kv1_custom_cmp(updated)");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, value, strlen(value)+1);
        s = fdb_set(kv1, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        fdb_doc_free(doc);

        sprintf(key, keystr, i);
        sprintf(value, valuestr, i, "kv2(updated)");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, value, strlen(value)+1);
        s = fdb_set(kv2, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        fdb_doc_free(doc);
    }
    // WAL flush at once
    s = fdb_commit(dbfile, FDB_COMMIT_NORMAL);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    // retrieve check
    for (i=0;i<n;++i) {
        sprintf(key, keystr, i);
        sprintf(value, valuestr, i, "default(updated)");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, NULL, 0);
        s = fdb_get(db, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(value, doc->body, doc->bodylen);
        fdb_doc_free(doc);

        sprintf(value, valuestr, i, "kv1_custom_cmp(updated)");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, NULL, 0);
        s = fdb_get(kv1, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(value, doc->body, doc->bodylen);
        fdb_doc_free(doc);

        sprintf(value, valuestr, i, "kv2(updated)");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, NULL, 0);
        s = fdb_get(kv2, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(value, doc->body, doc->bodylen);
        fdb_doc_free(doc);
    }

    // do compaction
    s = fdb_compact(dbfile, "./dummy2");
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    // retrieve check
    for (i=0;i<n;++i) {
        sprintf(key, keystr, i);
        sprintf(value, valuestr, i, "default(updated)");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, NULL, 0);
        s = fdb_get(db, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(value, doc->body, doc->bodylen);
        fdb_doc_free(doc);

        sprintf(value, valuestr, i, "kv1_custom_cmp(updated)");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, NULL, 0);
        s = fdb_get(kv1, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(value, doc->body, doc->bodylen);
        fdb_doc_free(doc);

        sprintf(value, valuestr, i, "kv2(updated)");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, NULL, 0);
        s = fdb_get(kv2, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(value, doc->body, doc->bodylen);
        fdb_doc_free(doc);
    }

    // create full iterator for 'kv1'
    i = 0;
    s = fdb_iterator_init(kv1, &it, NULL, 0, NULL, 0, FDB_ITR_NONE);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    do {
        s = fdb_iterator_get(it, &doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        sprintf(key, keystr, i);
        sprintf(value, valuestr, i, "kv1_custom_cmp(updated)");
        TEST_CMP(doc->key, key, doc->keylen);
        TEST_CMP(doc->body, value, doc->bodylen);
        fdb_doc_free(doc);
        i++;
    } while (fdb_iterator_next(it) == FDB_RESULT_SUCCESS);
    TEST_CHK(i == n);
    s = fdb_iterator_close(it);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    s = fdb_close(dbfile);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_shutdown();
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    memleak_end();

    TEST_RESULT("multiple KV instances custom comparison function test");
}

void multi_kv_fdb_open_custom_cmp_test()
{
    // Unit test for MB-12593
    TEST_INIT();

    int n = 1000;
    int i, r;
    char key[256], value[256];
    char keystr[] = "key%06d";
    char valuestr[] = "value%08d(%s)";
    fdb_file_handle *dbfile;
    fdb_kvs_handle *db, *kv1, *kv2;
    fdb_config config;
    fdb_kvs_config kvs_config;
    fdb_doc *doc;
    fdb_status s;

    char *kvs_names[] = {(char*)"default", (char*)"kv1", (char*)"kv2"};
    fdb_custom_cmp_variable functions[] = {_multi_kv_test_keycmp,
                                           _multi_kv_test_keycmp,
                                           NULL};

    sprintf(value, SHELL_DEL" dummy*");
    r = system(value);
    (void)r;

    memleak_start();

    config = fdb_get_default_config();
    kvs_config = fdb_get_default_kvs_config();
    config.multi_kv_instances = true;
    config.wal_threshold = 256;
    config.wal_flush_before_commit = false;
    config.buffercache_size = 0;

    s = fdb_open_custom_cmp(&dbfile, "./dummy", &config,
                            3, kvs_names, functions);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_kvs_open(dbfile, &db, NULL, &kvs_config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_kvs_open(dbfile, &kv1, "kv1", &kvs_config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    kvs_config.custom_cmp = _multi_kv_test_keycmp;
    s = fdb_kvs_open(dbfile, &kv2, "kv2", &kvs_config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    // insert using 'default' instance
    for (i=0;i<n;++i) {
        sprintf(key, keystr, i);
        sprintf(value, valuestr, i, "default");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, value, strlen(value)+1);
        s = fdb_set(db, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        fdb_doc_free(doc);
    }

    // insert using 'kv1' instance
    for (i=0;i<n;++i) {
        sprintf(key, keystr, i);
        sprintf(value, valuestr, i, "kv1_custom_cmp");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, value, strlen(value)+1);
        s = fdb_set(kv1, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        fdb_doc_free(doc);
    }

    // insert using 'kv2' instance
    for (i=0;i<n;++i) {
        sprintf(key, keystr, i);
        sprintf(value, valuestr, i, "kv2");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, value, strlen(value)+1);
        s = fdb_set(kv2, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        fdb_doc_free(doc);
    }
    s = fdb_commit(dbfile, FDB_COMMIT_NORMAL);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_close(dbfile);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    s = fdb_open(&dbfile, "./dummy", &config);
    TEST_CHK(s != FDB_RESULT_SUCCESS); // must fail

    s = fdb_open_custom_cmp(&dbfile, "./dummy", &config,
                            3, kvs_names, functions);
    TEST_CHK(s != FDB_RESULT_SUCCESS); // must fail

    functions[2] = _multi_kv_test_keycmp;
    s = fdb_open_custom_cmp(&dbfile, "./dummy", &config,
                            3, kvs_names, functions);
    TEST_CHK(s == FDB_RESULT_SUCCESS); // must succeed
    s = fdb_kvs_open(dbfile, &db, NULL, &kvs_config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_kvs_open(dbfile, &kv1, "kv1", &kvs_config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_kvs_open(dbfile, &kv2, "kv2", &kvs_config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    // retrieve check
    for (i=0;i<n;++i) {
        sprintf(key, keystr, i);
        sprintf(value, valuestr, i, "default");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, NULL, 0);
        s = fdb_get(db, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(value, doc->body, doc->bodylen);
        fdb_doc_free(doc);

        sprintf(value, valuestr, i, "kv1_custom_cmp");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, NULL, 0);
        s = fdb_get(kv1, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(value, doc->body, doc->bodylen);
        fdb_doc_free(doc);

        sprintf(value, valuestr, i, "kv2");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, NULL, 0);
        s = fdb_get(kv2, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(value, doc->body, doc->bodylen);
        fdb_doc_free(doc);
    }

    s = fdb_close(dbfile);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_shutdown();
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    memleak_end();

    TEST_RESULT("multiple KV instances fdb_open_custom_cmp test");
}

void multi_kv_use_existing_mode_test()
{
    TEST_INIT();

    int n = 1000;
    int i, r;
    char key[256], value[256];
    char keystr[] = "key%06d";
    char valuestr[] = "value%08d(%s)";
    fdb_file_handle *dbfile;
    fdb_kvs_handle *db;
    fdb_config config;
    fdb_kvs_config kvs_config;
    fdb_doc *doc;
    fdb_status s;

    sprintf(value, SHELL_DEL" dummy*");
    r = system(value);
    (void)r;

    memleak_start();

    config = fdb_get_default_config();
    kvs_config = fdb_get_default_kvs_config();
    config.wal_threshold = 256;
    config.buffercache_size = 0;

    // create DB file under multi KV instance mode
    config.multi_kv_instances = true;
    s = fdb_open(&dbfile, "./dummy_multi", &config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_kvs_open(dbfile, &db, NULL, &kvs_config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    // insert using 'default' instance
    for (i=0;i<n;++i) {
        sprintf(key, keystr, i);
        sprintf(value, valuestr, i, "default");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, value, strlen(value)+1);
        s = fdb_set(db, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        fdb_doc_free(doc);
    }

    s = fdb_commit(dbfile, FDB_COMMIT_NORMAL);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_close(dbfile);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    // open under single KV instance mode
    config.multi_kv_instances = false;
    s = fdb_open(&dbfile, "./dummy_multi", &config);
    TEST_CHK(s == FDB_RESULT_SUCCESS); // must succeed
    s = fdb_kvs_open(dbfile, &db, NULL, &kvs_config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    // retrieve check
    for (i=0;i<n;++i) {
        sprintf(key, keystr, i);
        sprintf(value, valuestr, i, "default");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, NULL, 0);
        s = fdb_get(db, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(value, doc->body, doc->bodylen);
        fdb_doc_free(doc);
    }

    s = fdb_close(dbfile);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    // create DB file under single KV instance mode
    config.multi_kv_instances = false;
    s = fdb_open(&dbfile, "./dummy_single", &config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_kvs_open(dbfile, &db, NULL, &kvs_config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    // insert using 'default' instance
    for (i=0;i<n;++i) {
        sprintf(key, keystr, i);
        sprintf(value, valuestr, i, "default");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, value, strlen(value)+1);
        s = fdb_set(db, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        fdb_doc_free(doc);
    }

    s = fdb_commit(dbfile, FDB_COMMIT_NORMAL);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_close(dbfile);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    // open under multi KV instance mode
    config.multi_kv_instances = true;
    s = fdb_open(&dbfile, "./dummy_single", &config);
    TEST_CHK(s == FDB_RESULT_SUCCESS); // must succeed
    s = fdb_kvs_open(dbfile, &db, NULL, &kvs_config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    // retrieve check
    for (i=0;i<n;++i) {
        sprintf(key, keystr, i);
        sprintf(value, valuestr, i, "default");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, NULL, 0);
        s = fdb_get(db, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(value, doc->body, doc->bodylen);
        fdb_doc_free(doc);
    }

    s = fdb_close(dbfile);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    s = fdb_shutdown();
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    memleak_end();

    TEST_RESULT("multiple KV instances use existing mode test");
}

void multi_kv_close_test()
{
    TEST_INIT();
    memleak_start();

    int i, r;
    int n = 10;
    fdb_file_handle *dbfile1;
    fdb_kvs_handle *db1, *db2, *db3, *db4, *db5;
    fdb_doc **doc = alca(fdb_doc*, n);
    fdb_doc *rdoc;
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
    fdb_kvs_open(dbfile1, &db1, "db1", &kvs_config);
    fdb_kvs_open(dbfile1, &db2, "db2", &kvs_config);
    fdb_kvs_open(dbfile1, &db3, "db3", &kvs_config);
    fdb_kvs_open(dbfile1, &db4, "db4", &kvs_config);
    fdb_kvs_open(dbfile1, &db5, "db5", &kvs_config);

    // insert documents
    for (i=0;i<n;++i){
        sprintf(keybuf, "key%d", i);
        sprintf(metabuf, "meta%d", i);
        sprintf(bodybuf, "body%d", i);
        fdb_doc_create(&doc[i], (void*)keybuf, strlen(keybuf),
            (void*)metabuf, strlen(metabuf), (void*)bodybuf, strlen(bodybuf));
        fdb_set(db1, doc[i]);
        fdb_set(db2, doc[i]);
        fdb_set(db3, doc[i]);
        fdb_set(db4, doc[i]);
        fdb_set(db5, doc[i]);
    }
    // close db3,4
    fdb_kvs_close(db3);
    fdb_kvs_close(db4);


    // insert documents
    for (i=0;i<n;++i){
        fdb_set(db1, doc[i]);
        fdb_set(db2, doc[i]);
        fdb_set(db5, doc[i]);
    }

    // remove db1
    fdb_kvs_close(db1);
    status = fdb_kvs_remove(dbfile1,"db1");
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // commit
    status = fdb_commit(dbfile1, FDB_COMMIT_NORMAL);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // remove db5
    fdb_kvs_close(db5);
    status = fdb_kvs_remove(dbfile1, "db5");
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // attempt to read from remaining open kvs
    for (i=0; i<n; i++){
        fdb_doc_create(&rdoc, doc[i]->key, doc[i]->keylen, NULL, 0, NULL, 0);
        status = fdb_get(db2, rdoc);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        fdb_doc_free(rdoc);
    }

    // close db2
    status = fdb_kvs_close(db2);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // free resources
    for (i=0; i<n; i++){
       status = fdb_doc_free(doc[i]);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
    }

    status = fdb_close(dbfile1);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_shutdown();
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    memleak_end();
    TEST_RESULT("multi KV close");
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

    if (args == NULL)
    { // parent

        r = system(SHELL_DEL" dummy* > errorlog.txt");
        (void)r;
        // init dbfile
        kvs_config = fdb_get_default_kvs_config();
        fconfig = fdb_get_default_config();
        fconfig.buffercache_size = 0;
        fconfig.wal_threshold = 1024;
        fconfig.compaction_threshold = 0;

        status = fdb_open(&dbfile, "./dummy1", &fconfig);
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
        TEST_CHK(kvs_info.doc_count == n);

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

        // verify no docs remaining
        fdb_get_kvs_info(db, &kvs_info);
        TEST_CHK(kvs_info.doc_count == 0);

        // reopen
        fdb_kvs_close(db);
        fdb_close(dbfile);
        status = fdb_open(&dbfile, "./dummy1", &fconfig);
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

    // threads enter here //
    dbfile = (fdb_file_handle *)args;
    status = fdb_compact(dbfile, NULL);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // shutdown
    thread_exit(0);
    return NULL;
}

int main(){
    int i, j;
    uint8_t opt;

    basic_test();
    long_filename_test();
    error_to_str_test();
    seq_tree_exception_test();
    wal_commit_test();
    multi_version_test();
    compact_wo_reopen_test();
    compact_with_reopen_test();
    auto_recover_compact_ok_test();
    db_compact_overwrite();
    db_close_and_remove();
    db_compact_during_doc_delete(NULL);
#ifdef __CRC32
    crash_recovery_test();
#endif
    incomplete_block_test();
    iterator_test();
    iterator_with_concurrent_updates_test();
    iterator_seek_test();
    for (i=0;i<=6;++i){
        for (j=0;j<2;++j){
            iterator_complete_test(i, j);
        }
    }
    iterator_extreme_key_test();
    iterator_no_deletes_test();
    iterator_set_del_docs_test();
    sequence_iterator_test();
    sequence_iterator_duplicate_test();
    custom_compare_primitive_test();
    custom_compare_variable_test();
    snapshot_test();
    in_memory_snapshot_test();
    snapshot_clone_test();
    rollback_forward_seqnum();
    rollback_test(false); // single kv instance mode
    rollback_test(true); // multi kv instance mode
    rollback_and_snapshot_test();
    reverse_sequence_iterator_test();
    reverse_sequence_iterator_kvs_test();
    reverse_iterator_test();
    iterator_seek_wal_only_test();
    db_drop_test();
    db_destroy_test();
    doc_compression_test();
    read_doc_by_offset_test();
    api_wrapper_test();
    transaction_test();
    transaction_simple_api_test();
    flush_before_commit_test();
    flush_before_commit_multi_writers_test();
    auto_commit_test();
    last_wal_flush_header_test();
    long_key_test();

    for (i=0;i<2;++i){
        opt = (i==0)?(0x0):(MULTI_KV_VAR_CMP);
        multi_kv_test(opt);
        multi_kv_iterator_key_test(opt);
        multi_kv_iterator_seq_test(opt);
        multi_kv_txn_test(opt);
        multi_kv_snapshot_test(opt);
        multi_kv_rollback_test(opt);
    }
    multi_kv_custom_cmp_test();
    multi_kv_fdb_open_custom_cmp_test();
    multi_kv_use_existing_mode_test();
    multi_kv_close_test();

    purge_logically_deleted_doc_test();
    compaction_daemon_test(20);
    multi_thread_test(40*1024, 1024, 20, 1, 100, 2, 6);
    multi_thread_client_shutdown(NULL);
    multi_thread_kvs_client(NULL);

    return 0;
}
