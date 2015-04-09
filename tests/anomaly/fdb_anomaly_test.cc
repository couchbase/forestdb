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
#include <errno.h>
#endif

#include "libforestdb/forestdb.h"
#include "test.h"
#include "filemgr_anomalous_ops.h"

void logCallbackFunc(int err_code,
                     const char *err_msg,
                     void *pCtxData) {
    fprintf(stderr, "%s - error code: %d, error message: %s\n",
            (char *) pCtxData, err_code, err_msg);
}

typedef struct fail_ctx_t {
    int num_fails;
    int num_ops;
    int start_failing_after;
} fail_ctx_t;

ssize_t pwrite_failure_cb(void *ctx) {
    fail_ctx_t *wctx = (fail_ctx_t *)ctx;
    wctx->num_ops++;
    if (wctx->num_ops > wctx->start_failing_after) {
        wctx->num_fails++;
        errno = -2;
        return (ssize_t)FDB_RESULT_WRITE_FAIL;
    }
    return (ssize_t)FDB_RESULT_SUCCESS;
}

void write_failure_test()
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
    int anomaly_hit = 0;

    char *keybuf;
    char metabuf[256], bodybuf[256], temp[256];
    // Get the default callbacks which result in normal operation for other ops
    struct anomalous_callbacks *write_fail_cb = get_default_anon_cbs();
    fail_ctx_t fail_ctx;
    memset(&fail_ctx, 0, sizeof(fail_ctx_t));
    // Modify the pwrite callback to redirect to test-specific function
    write_fail_cb->pwrite_cb = &pwrite_failure_cb;

    // remove previous anomaly_test files
    r = system(SHELL_DEL" anomaly_test* > errorlog.txt");
    (void)r;

    // Reset anomalous behavior stats..
    filemgr_ops_anomalous_init(write_fail_cb, &fail_ctx);

    // The number indicates the count after which all writes begin to fail
    // This number is unique to this test suite and can cause a segmentation
    // fault if the underlying fixed issue resurfaces
    fail_ctx.start_failing_after = 10112;

    fdb_config fconfig = fdb_get_default_config();
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    fconfig.buffercache_size = 0;
    fconfig.flags = FDB_OPEN_FLAG_CREATE;
    fconfig.purging_interval = 0;
    fconfig.compaction_threshold = 0;

    keylen_limit = fconfig.blocksize - 256;
    keybuf = alca(char, keylen_limit);

    // open db
    fdb_open(&dbfile, "anomaly_test1", &fconfig);
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
        if (status != FDB_RESULT_SUCCESS) {
            fdb_doc_free(rdoc);
            anomaly_hit = 1;
            break;
        }
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        TEST_CHK(!memcmp(rdoc->key, doc[i]->key, rdoc->keylen));
        TEST_CHK(!memcmp(rdoc->meta, doc[i]->meta, rdoc->metalen));
        TEST_CHK(!memcmp(rdoc->body, doc[i]->body, rdoc->bodylen));
        fdb_doc_free(rdoc);
    }
    TEST_CHK(anomaly_hit);

    fdb_close(dbfile);

    // free all documents
    for (i=0;i<n*m;++i){
        fdb_doc_free(doc[i]);
    }

    // free all resources
    fdb_shutdown();

    memleak_end();

    sprintf(temp, "write failure test: %d failures out of %d writes",
            fail_ctx.num_fails, fail_ctx.num_ops);

    TEST_RESULT(temp);
}

ssize_t pread_failure_cb(void *ctx) {
    fail_ctx_t *wctx = (fail_ctx_t *)ctx;
    wctx->num_ops++;
    if (wctx->num_ops > wctx->start_failing_after) {
        wctx->num_fails++;
        errno = -2;
        return (ssize_t)FDB_RESULT_READ_FAIL;
    }
    return (ssize_t)FDB_RESULT_SUCCESS;
}

void read_failure_test()
{
    TEST_INIT();

    memleak_start();

    int i, r;
    int n=300;
    int keylen_limit;
    fdb_file_handle *dbfile;
    fdb_kvs_handle *db;
    fdb_doc **doc = alca(fdb_doc*, n);
    fdb_doc *rdoc;
    fdb_status status;

    char *keybuf;
    char metabuf[256], bodybuf[256], temp[256];
    // Get the default callbacks which result in normal operation for other ops
    struct anomalous_callbacks *read_fail_cb = get_default_anon_cbs();
    fail_ctx_t fail_ctx;
    memset(&fail_ctx, 0, sizeof(fail_ctx_t));

    // Modify the pread callback to redirect to test-specific function
    read_fail_cb->pread_cb = &pread_failure_cb;

    // remove previous anomaly_test files
    r = system(SHELL_DEL" anomaly_test* > errorlog.txt");
    (void)r;

    // Reset anomalous behavior stats..
    filemgr_ops_anomalous_init(read_fail_cb, &fail_ctx);

    fail_ctx.start_failing_after = 1000; // some large value

    fdb_config fconfig = fdb_get_default_config();
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    fconfig.buffercache_size = 0;
    fconfig.flags = FDB_OPEN_FLAG_CREATE;
    fconfig.purging_interval = 0;
    fconfig.compaction_threshold = 0;

    keylen_limit = fconfig.blocksize - 256;
    keybuf = alca(char, keylen_limit);

    // open db
    status = fdb_open(&dbfile, "./anomaly_test1", &fconfig);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_kvs_open_default(dbfile, &db, &kvs_config);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    status = fdb_set_log_callback(db, logCallbackFunc,
                                  (void *) "read_failure_test");
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // insert documents
    for (i=0;i<n;++i){
        sprintf(keybuf, "key%d", i);
        sprintf(metabuf, "meta%d", i);
        sprintf(bodybuf, "body%d", i);
        fdb_doc_create(&doc[i], (void*)keybuf, strlen(keybuf),
            (void*)metabuf, strlen(metabuf), (void*)bodybuf, strlen(bodybuf));
        status = fdb_set(db, doc[i]);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
    }

    // commit
    status = fdb_commit(dbfile, FDB_COMMIT_NORMAL);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    fdb_kvs_close(db);
    fdb_close(dbfile);

    fail_ctx.start_failing_after = fail_ctx.num_ops; // immediately fail

    status = fdb_open(&dbfile, "./anomaly_test1", &fconfig);
    TEST_CHK(status == FDB_RESULT_READ_FAIL);

    fail_ctx.start_failing_after = fail_ctx.num_ops+1000; //normal operation

    status = fdb_open(&dbfile, "./anomaly_test1", &fconfig);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_kvs_open_default(dbfile, &db, &kvs_config);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    status = fdb_set_log_callback(db, logCallbackFunc,
                                  (void *) "read_failure_test");
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    fail_ctx.start_failing_after = fail_ctx.num_ops; // immediately fail
    i = 0;
    fdb_doc_create(&rdoc, doc[i]->key, doc[i]->keylen, NULL, 0, NULL, 0);
    status = fdb_get(db, rdoc);

    TEST_CHK(status == FDB_RESULT_KEY_NOT_FOUND);
    // free result document
    fdb_doc_free(rdoc);

    fail_ctx.start_failing_after = fail_ctx.num_ops+1000; //normal operation
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

    fdb_kvs_close(db);
    fdb_close(dbfile);

    // free all documents
    for (i=0;i<n;++i){
        fdb_doc_free(doc[i]);
    }

    // free all resources
    fdb_shutdown();

    memleak_end();

    sprintf(temp, "read failure test: %d failures out of %d reads",
            fail_ctx.num_fails, fail_ctx.num_ops);

    TEST_RESULT(temp);
}

int main(){

    write_failure_test();
    read_failure_test();

    return 0;
}
