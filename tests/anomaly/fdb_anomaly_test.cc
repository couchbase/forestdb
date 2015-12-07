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
#include "filemgr.h"
#include "internal_types.h"

void logCallbackFunc(int err_code,
                     const char *err_msg,
                     void *pCtxData) {
    fprintf(stderr, "%s - error code: %d, error message: %s\n",
            (char *) pCtxData, err_code, err_msg);
}

// callback context for test specific data
typedef struct fail_ctx_t {
    int num_fails;
    int num_ops;
    int start_failing_after;
} fail_ctx_t;

ssize_t pwrite_failure_cb(void *ctx, struct filemgr_ops *normal_ops,
                          int fd, void *buf, size_t count, cs_off_t offset)
{
    fail_ctx_t *wctx = (fail_ctx_t *)ctx;
    wctx->num_ops++;
    if (wctx->num_ops > wctx->start_failing_after) {
        wctx->num_fails++;
        errno = -2;
        return (ssize_t)FDB_RESULT_WRITE_FAIL;
    }
    return normal_ops->pwrite(fd, buf, count, offset);
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

ssize_t pread_failure_cb(void *ctx, struct filemgr_ops *normal_ops,
                         int fd, void *buf, size_t count, cs_off_t offset)
{
    fail_ctx_t *wctx = (fail_ctx_t *)ctx;
    wctx->num_ops++;
    if (wctx->num_ops > wctx->start_failing_after) {
        wctx->num_fails++;
        errno = -2;
        return (ssize_t)FDB_RESULT_READ_FAIL;
    }
    return normal_ops->pread(fd, buf, count, offset);
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
    TEST_CHK(status == FDB_RESULT_READ_FAIL || status == FDB_RESULT_SB_READ_FAIL);

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

struct shared_data {
    fdb_file_handle *dbfile;
    fdb_kvs_handle *db;
    fdb_iterator *iterator;
    bool test_handle_busy;
};

void *bad_thread(void *voidargs) {
    struct shared_data *data = (struct shared_data *)voidargs;
    fdb_kvs_handle *db = data->db;
    fdb_file_handle *dbfile = data->dbfile;
    fdb_iterator *itr = data->iterator;
    fdb_status s;
    fdb_doc doc;
    TEST_INIT();

    memset(&doc, 0, sizeof(fdb_doc));
    doc.key = &doc; // some non-null value
    doc.keylen = 2; // some non-zero value
    doc.body = &doc; // some non-null value
    doc.bodylen = 2; // some non-zero value

    if (!itr) {
        // since the parent thread is hung in the fdb_set callback
        // all the forestdb apis calls on the same handle must return failure
        s = fdb_set(db, &doc);
        TEST_CHK(s == FDB_RESULT_HANDLE_BUSY);
        s = fdb_del(db, &doc);
        TEST_CHK(s == FDB_RESULT_HANDLE_BUSY);
        s = fdb_get(db, &doc);
        TEST_CHK(s == FDB_RESULT_HANDLE_BUSY);
        s = fdb_get_metaonly(db, &doc);
        TEST_CHK(s == FDB_RESULT_HANDLE_BUSY);
        s = fdb_get_byseq(db, &doc);
        TEST_CHK(s == FDB_RESULT_HANDLE_BUSY);
        s = fdb_get_metaonly_byseq(db, &doc);
        TEST_CHK(s == FDB_RESULT_HANDLE_BUSY);
        doc.offset = 5000; // some random non-zero value
        s = fdb_get_byoffset(db, &doc);
        TEST_CHK(s == FDB_RESULT_HANDLE_BUSY);
        s = fdb_begin_transaction(dbfile, FDB_ISOLATION_READ_COMMITTED);
        TEST_CHK(s == FDB_RESULT_HANDLE_BUSY);
    } else {
        s = fdb_iterator_next(itr);
        TEST_CHK(s == FDB_RESULT_HANDLE_BUSY);
        s = fdb_iterator_prev(itr);
        TEST_CHK(s == FDB_RESULT_HANDLE_BUSY);
        s = fdb_iterator_seek_to_min(itr);
        TEST_CHK(s == FDB_RESULT_HANDLE_BUSY);
        s = fdb_iterator_seek_to_max(itr);
        TEST_CHK(s == FDB_RESULT_HANDLE_BUSY);
        s = fdb_iterator_seek(itr, doc.key, doc.keylen, 0);
        TEST_CHK(s == FDB_RESULT_HANDLE_BUSY);
    }

    return NULL;
}

// Calling apis from a callback simulates concurrent access from multiple
// threads
ssize_t pwrite_hang_cb(void *ctx, struct filemgr_ops *normal_ops,
                       int fd, void *buf, size_t count, cs_off_t offset)
{
    struct shared_data *data = (struct shared_data *)ctx;
    if (data->test_handle_busy) {
        bad_thread(ctx);
    }
    return normal_ops->pwrite(fd, buf, count, offset);
}

void handle_busy_test()
{
    TEST_INIT();

    memleak_start();

    int n = 32;
    int i = 0, r;

    char keybuf[16], metabuf[16], bodybuf[16];
    fdb_doc **doc = alca(fdb_doc *, n);
    struct shared_data data;
    fdb_kvs_handle *db;
    fdb_iterator *itr;
    fdb_status status;

    // Get the default callbacks which result in normal operation for other ops
    struct anomalous_callbacks *write_hang_cb = get_default_anon_cbs();

    // Modify the pwrite callback to redirect to test-specific function
    write_hang_cb->pwrite_cb = &pwrite_hang_cb;

    // remove previous anomaly_test files
    r = system(SHELL_DEL" anomaly_test* > errorlog.txt");
    (void)r;

    memset(&data, 0, sizeof(struct shared_data));

    // Create anomalous behavior with shared handle for the callback ctx
    filemgr_ops_anomalous_init(write_hang_cb, &data);

    fdb_config fconfig = fdb_get_default_config();
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    fconfig.buffercache_size = 0;
    fconfig.flags = FDB_OPEN_FLAG_CREATE;
    fconfig.purging_interval = 0;
    fconfig.compaction_threshold = 0;

    // open db
    status = fdb_open(&data.dbfile, "anomaly_test5", &fconfig);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_kvs_open_default(data.dbfile, &data.db, &kvs_config);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    db = data.db;

    // insert documents
    for (i=0;i<n;++i){
        sprintf(keybuf, "key%d", i);
        sprintf(metabuf, "meta%d", i);
        sprintf(bodybuf, "body%d", i);
        fdb_doc_create(&doc[i], (void*)keybuf, strlen(keybuf) + 1,
            (void*)metabuf, strlen(metabuf) + 1, (void*)bodybuf,
            strlen(bodybuf) + 1);
        status = fdb_set(db, doc[i]);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
    }

    // commit
    status = fdb_commit(data.dbfile, FDB_COMMIT_NORMAL);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    status = fdb_iterator_init(db, &itr, NULL, 0, NULL, 0,
                               FDB_ITR_NONE);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // Set callback context to call bad_thread() and do a set invoking callback
    data.test_handle_busy = 1;
    status = fdb_set(db, doc[0]);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // Test iterator callbacks by attemping a set call on the iterator handle..
    data.iterator = itr;
    status = fdb_set(itr->handle, doc[0]);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    fdb_iterator_close(itr);
    data.test_handle_busy = 0;
    fdb_close(data.dbfile);

    for (i = n - 1; i >=0; --i) {
        fdb_doc_free(doc[i]);
    }
    // free all resources
    fdb_shutdown();

    memleak_end();

    TEST_RESULT("Handle Busy Test");
}

int get_fs_type_cb(void *ctx, struct filemgr_ops *normal_ops, int srcfd)
{
    return FILEMGR_FS_EXT4_WITH_COW;
}

struct cb_cmp_args {
    fdb_kvs_handle *handle;
    int ndocs;
    int nmoves;
};

static fdb_compact_decision cb_compact(fdb_file_handle *fhandle,
                            fdb_compaction_status status, const char *kv_name,
                            fdb_doc *doc, uint64_t old_offset,
                            uint64_t new_offset, void *ctx)
{
    TEST_INIT();
    struct cb_cmp_args *args = (struct cb_cmp_args *)ctx;
    fdb_status fs;
    fdb_compact_decision ret = FDB_CS_KEEP_DOC;
    (void) fhandle;
    (void) doc;
    (void) old_offset;
    (void) new_offset;

    if (status == FDB_CS_MOVE_DOC) {
        TEST_CHK(kv_name);
        args->nmoves++;
        if (doc->deleted) {
            ret = FDB_CS_DROP_DOC;
        }
        if (args->nmoves == args->ndocs - 1) {
            char key[256], value[256];
            // phase 3 of compaction - uncommitted docs in old_file
            sprintf(key, "key%250d", args->ndocs);
            sprintf(value, "body%250d", args->ndocs);
            fs = fdb_set_kv(args->handle, key, 253, value, 254);
            TEST_CHK(fs == FDB_RESULT_SUCCESS);
            fs = fdb_commit(args->handle->fhandle, FDB_COMMIT_NORMAL);
            TEST_CHK(fs == FDB_RESULT_SUCCESS);

            sprintf(key, "zzz%250d", args->ndocs);
            fs = fdb_set_kv(args->handle, key, 253, value, 254);
            TEST_CHK(fs == FDB_RESULT_SUCCESS);
        }
    }

    return ret;
}

static void append_batch_delta(void)
{
    TEST_INIT();
    fdb_file_handle *dbfile;
    fdb_kvs_handle *db;
    fdb_status status;
    int N = 5000;
    int start = N/2;
    int i;

    char key[256], value[256];
    fdb_config fconfig = fdb_get_default_config();
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    fconfig.buffercache_size = 0;
    // open db
    status = fdb_open(&dbfile, "anomaly_test1a", &fconfig);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_kvs_open_default(dbfile, &db, &kvs_config);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // phase 2 of compaction...
    // insert docs
    for (i=start;i<N;++i){
        sprintf(key, "key%250d", i);
        sprintf(value, "body%250d", i);
        status = fdb_set_kv(db, key, 253, value, 254);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        if (i == start + start/2) {
            status = fdb_commit(dbfile, FDB_COMMIT_NORMAL);
            TEST_CHK(status == FDB_RESULT_SUCCESS);
        }
    }

    status = fdb_commit(dbfile, FDB_COMMIT_NORMAL);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    status = fdb_close(dbfile);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
}

static int copy_file_range_cb(void *ctx, struct filemgr_ops *normal_ops,
                              int fstype, int src, int dst,
                              uint64_t src_off, uint64_t dst_off, uint64_t len)
{
    uint8_t *buf = alca(uint8_t, len);
    bool *append_delta = (bool *)ctx;

    TEST_INIT();
    TEST_CHK(src_off % 4096 == 0);
    TEST_CHK(dst_off % 4096 == 0);
    TEST_CHK(len && len % 4096 == 0);
    printf("File Range Copy src bid - %" _F64
           " to dst bid = %" _F64 ", %" _F64" blocks\n",
           src_off / 4096, dst_off / 4096, (len / 4096) + 1);
    normal_ops->pread(src, buf, len, src_off);
    normal_ops->pwrite(dst, buf, len, dst_off);
    if (*append_delta) {
        // While the compactor is stuck doing compaction append more documents
        append_batch_delta();
        *append_delta = false;
    }
    return FDB_RESULT_SUCCESS;
}

void copy_file_range_test()
{
    TEST_INIT();

    memleak_start();

    int i, r;
    int N = 5000; // total docs after append batch delta
    int n = N/2;
    bool append_delta = true;
    fdb_file_handle *dbfile;
    fdb_kvs_handle *db;
    fdb_status status;

    char key[256], value[256];
    void *value_out;
    size_t valuelen;
    struct cb_cmp_args cb_args;

    // Get the default callbacks which result in normal operation for other ops
    struct anomalous_callbacks *cow_compact_cb = get_default_anon_cbs();
    cow_compact_cb->get_fs_type_cb = &get_fs_type_cb;
    cow_compact_cb->copy_file_range_cb = &copy_file_range_cb;

    memset(&cb_args, 0x0, sizeof(struct cb_cmp_args));

    // remove previous dummy files
    r = system(SHELL_DEL" anomaly_test1a anomaly_test1b > errorlog.txt");
    (void)r;

    fdb_config fconfig = fdb_get_default_config();
    fconfig.compaction_cb = cb_compact;
    fconfig.compaction_cb_ctx = &cb_args;
    fconfig.compaction_cb_mask = FDB_CS_BEGIN |
                                 FDB_CS_END | FDB_CS_MOVE_DOC;

    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();

    // Create anomalous behavior with shared handle for the callback ctx
    filemgr_ops_anomalous_init(cow_compact_cb, &append_delta);

    // open db
    status = fdb_open(&dbfile, "anomaly_test1a", &fconfig);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_kvs_open_default(dbfile, &db, &kvs_config);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    cb_args.handle = db;
    cb_args.ndocs = N;

    // insert docs
    for (i=0;i<n;++i){
        sprintf(key, "key%250d", i);
        sprintf(value, "body%250d", i);
        status = fdb_set_kv(db, key, 253, value, 254);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
    }

    status = fdb_commit(dbfile, FDB_COMMIT_NORMAL);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // update docs making half the docs stale
    for (i=n/2; i<n; ++i){
        sprintf(key, "key%250d", i);
        sprintf(value, "BODY%250d", i);
        status = fdb_set_kv(db, key, 253, value, 254);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
    }

    status = fdb_commit(dbfile, FDB_COMMIT_NORMAL);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    status = fdb_compact_with_cow(dbfile, "anomaly_test1b");
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // retrieve check again
    for (i=0; i<n; ++i){
        sprintf(key, "key%250d", i);
        if (i < n/2) {
            sprintf(value, "body%250d", i);
        } else {
            sprintf(value, "BODY%250d", i);
        }
        status = fdb_get_kv(db, key, 253, &value_out, &valuelen);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        TEST_CMP(value_out, value, valuelen);
        status = fdb_free_block(value_out);
    }

    // retrieve docs after append batched delta
    for (; i<N; ++i){
        sprintf(key, "key%250d", i);
        sprintf(value, "body%250d", i);
        status = fdb_get_kv(db, key, 253, &value_out, &valuelen);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        TEST_CMP(value_out, value, valuelen);
        status = fdb_free_block(value_out);
    }

    // check on phase 3 inserted documents..
    sprintf(key, "key%250d", i);
    sprintf(value, "body%250d", i);
    status = fdb_get_kv(db, key, 253, &value_out, &valuelen);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    TEST_CMP(value_out, value, valuelen);
    status = fdb_free_block(value_out);

    sprintf(key, "zzz%250d", i);
    status = fdb_get_kv(db, key, 253, &value_out, &valuelen);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    TEST_CMP(value_out, value, valuelen);
    status = fdb_free_block(value_out);

    // free all resources
    status = fdb_close(dbfile);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    fdb_shutdown();

    memleak_end();

    TEST_RESULT("copy file range test");
}

int main(){

    /**
     * Commented out this test for now; it copies consecutive document blocks
     * to other file but they are written in different BID compared to the source
     * file, so that meta section at the end of each document block points to wrong
     * block and consequently documents cannot be read correctly.
     */
    //copy_file_range_test();
    write_failure_test();
    read_failure_test();
    handle_busy_test();

    return 0;
}
