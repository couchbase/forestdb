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

#define TARGET_DOC_SIZE_IN_MB 256
#define KEY_LEN 16
#define BODY_LEN 1024
#define NUM_WRITERS 3
#define BUFFERCACHE_SIZE 0
#define MULTI_KV false

#define NUM_DOCS ((TARGET_DOC_SIZE_IN_MB * 1024 * 1024))\
                  / (KEY_LEN + 8 + BODY_LEN)

#define TEST_FILENAME "./big_file"

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
#include "arch.h"
#include "time_utils.h"
#include "atomic.h"
#include "functional_util.h"

struct writer_thread_args {
    int64_t docid_high;
    int64_t docid_low;
    int64_t batch_size;
    fdb_config config;
    fdb_kvs_config kvs_config;
    char test_file_name[256];
    char kv_store_name[16];
    fdb_commit_opt_t commit_opt;
};

void logCallbackFunc(int err_code,
                     const char *err_msg,
                     void *pCtxData) {
    fprintf(stderr, "%s - error code: %d, error message: %s\n",
            (char *) pCtxData, err_code, err_msg);
}

static void *_writer_thread(void *voidargs)
{
    TEST_INIT();

    struct writer_thread_args *args = (struct writer_thread_args *)voidargs;
    fdb_doc doc;
    char bigKeyBuf[KEY_LEN*2];
    char bigBodyBuf[BODY_LEN*2];
    fdb_file_handle *dbfile;
    fdb_kvs_handle *db;
    fdb_status status;
    fdb_config fconfig = args->config;
    fdb_kvs_config kvs_config = args->kvs_config;

    status = fdb_open(&dbfile, args->test_file_name, &fconfig);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    if (MULTI_KV) {
        status = fdb_kvs_open(dbfile, &db, args->kv_store_name, &kvs_config);
    } else {
        status = fdb_kvs_open_default(dbfile, &db, &kvs_config);
    }
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_set_log_callback(db, logCallbackFunc,
                                  (void *) args->test_file_name);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    memset(&doc, 0, sizeof(fdb_doc));
    doc.key = &bigKeyBuf[0];
    doc.keylen = KEY_LEN;
    doc.body = &bigBodyBuf[0];
    doc.bodylen = BODY_LEN;

    printf("\nWriter thread:load %" _F64 " docs from %" _F64 " to %" _F64 "\n",
           args->docid_high - args->docid_low, args->docid_low,
           args->docid_high);

    for (int j = args->docid_high - 1; j >= args->docid_low; --j) {
        char keyfmt[8], bodyfmt[8];
        sprintf(keyfmt, "%%%dd", KEY_LEN);
        sprintf(bigKeyBuf, keyfmt, j);
        sprintf(bodyfmt, "%%%dd", BODY_LEN);
        sprintf(bigBodyBuf, bodyfmt, j);
        status = fdb_set(db, &doc);
        TEST_CHK(status == FDB_RESULT_SUCCESS);

        // Commit based on batch-size set..
        if (j && j % args->batch_size == 0) {
            status = fdb_commit(dbfile, args->commit_opt);
            TEST_CHK(status == FDB_RESULT_SUCCESS);
        }
    }

    fdb_close(dbfile);

    thread_exit(0);
    return NULL;
}

// TEST MAIN:
// Writer keeps doing set without commit
void multi_writers(const char *test_name) {
    TEST_INIT();
    memleak_start();

    int num_writers = NUM_WRITERS;
    int writer_shard_size = NUM_DOCS / NUM_WRITERS;
    fdb_file_handle *dbfile;
    fdb_config fconfig;
    int r;
    fdb_status status;
    struct writer_thread_args *wargs = alca(struct writer_thread_args,
                                       num_writers);
    thread_t *tid = alca(thread_t, num_writers);
    void **thread_ret = alca(void *, num_writers);
    struct timeval ts_begin, ts_cur, ts_gap;

    // remove previous test files
    r = system(SHELL_DEL TEST_FILENAME "* > errorlog.txt");
    (void) r;

    printf("\nLoading %d docs %d key length %d bodylen."
           " Buffercache %" _F64 "MB. Target docsize %" _F64 "MB...",
            NUM_DOCS, KEY_LEN, BODY_LEN,
            BUFFERCACHE_SIZE ? (uint64_t)BUFFERCACHE_SIZE/ (1024 * 1024) : 0,
            (uint64_t)(KEY_LEN + BODY_LEN + 8) * NUM_DOCS / (1024 * 1024));
    gettimeofday(&ts_begin, NULL);

    fconfig = fdb_get_default_config();
    fconfig.multi_kv_instances = MULTI_KV;
    fconfig.buffercache_size = BUFFERCACHE_SIZE;
    fconfig.durability_opt = FDB_DRB_ODIRECT;
    status = fdb_open(&dbfile, TEST_FILENAME, &fconfig);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    for (int i = num_writers - 1; i >= 0; --i) {
        // Writer Thread Config:
        wargs[i].docid_low = i*writer_shard_size;
        wargs[i].docid_high = ((i + 1) * writer_shard_size) - 1;
        wargs[i].config = fconfig;
        wargs[i].kvs_config = fdb_get_default_kvs_config();
        wargs[i].batch_size = NUM_DOCS;
        wargs[i].commit_opt = FDB_COMMIT_MANUAL_WAL_FLUSH;
        sprintf(wargs[i].test_file_name, "%s", TEST_FILENAME);
        sprintf(wargs[i].kv_store_name, "kv_%d", i);

        thread_create(&tid[i], _writer_thread, &wargs[i]);
    }

    // wait for thread termination
    for (int i = 0; i < num_writers; ++i) {
        thread_join(tid[i], &thread_ret[i]);
    }

    status = fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    gettimeofday(&ts_cur, NULL);
    ts_gap = _utime_gap(ts_begin, ts_cur);

    printf("\nFile created %d docs loaded (keylen %d doclen %d) in %ldsec",
        NUM_DOCS, KEY_LEN, BODY_LEN, ts_gap.tv_sec);

    printf("\nStarting compaction...");
    printf("\n"); // flush stdio buffer
    gettimeofday(&ts_begin, NULL);

    status = fdb_compact(dbfile, TEST_FILENAME "2");
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    gettimeofday(&ts_cur, NULL);
    ts_gap = _utime_gap(ts_begin, ts_cur);

    printf("\nCompaction completed in %ld seconds\n", ts_gap.tv_sec);

    status = fdb_close(dbfile);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // shutdown
    status = fdb_shutdown();
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    memleak_end();
    TEST_RESULT(test_name);
}

int main() {
    multi_writers("Write big file then compact");
    return 0;
}
