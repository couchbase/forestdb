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

#define TARGET_DOC_SIZE_IN_MB 2048
#define MAX_KEY_LEN 200
#define BODY_LEN 10
#define NUM_WRITERS 8
#define BUFFERCACHE_SIZE (20*1024*1024)
#define MULTI_KV true

#define NUM_DOCS (((uint64_t)TARGET_DOC_SIZE_IN_MB * 1024 * 1024))\
                  / (MAX_KEY_LEN + 8 + BODY_LEN)

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

struct compactor_thread_args {
    volatile int num_files;
    fdb_config config;
};

void logCallbackFunc(int err_code,
                     const char *err_msg,
                     void *pCtxData) {
    fprintf(stderr, "%s - error code: %d, error message: %s\n",
            (char *) pCtxData, err_code, err_msg);
}

static void *_compactor_thread(void *voidargs)
{
    TEST_INIT();
    int revnum = 0;
    struct compactor_thread_args *args = (struct compactor_thread_args *)
                                         voidargs;
    usleep(2000);
    while(args->num_files) {
        int num_files = args->num_files;
        for (int i = 0; i < num_files; ++i) {
            char filename[256];
            fdb_status status;
            fdb_file_handle *dbfile;
            uint64_t num_markers;
            fdb_snapshot_info_t *markers;
            sprintf(filename, "%s_%d.%d", TEST_FILENAME, i, revnum);
            status = fdb_open(&dbfile, filename, &args->config);
            TEST_CHK(status == FDB_RESULT_SUCCESS);
            status = fdb_get_all_snap_markers(dbfile, &markers, &num_markers);
            if (status == FDB_RESULT_NO_DB_INSTANCE) {
                usleep(1000);
                fdb_close(dbfile);
                continue;
            }
            TEST_CHK(status == FDB_RESULT_SUCCESS);
            sprintf(filename, "%s_%d.%d", TEST_FILENAME, i, revnum+1);
            fdb_compact_upto(dbfile, filename,
                             num_markers > 5 ? markers[5].marker
                                             : markers[num_markers].marker);
            fdb_free_snap_markers(markers, num_markers);
            fdb_close(dbfile);
        }
        revnum++;
    }
    thread_exit(0);
    return NULL;
}

static void *_writer_thread(void *voidargs)
{
    TEST_INIT();

    struct writer_thread_args *args = (struct writer_thread_args *)voidargs;
    fdb_doc doc;
    char bigKeyBuf[MAX_KEY_LEN*2];
    char bigBodyBuf[BODY_LEN*2];
    fdb_file_handle *dbfile;
    fdb_kvs_handle *db, *db2;
    fdb_status status;
    fdb_config fconfig = args->config;
    fdb_kvs_config kvs_config = args->kvs_config;

    status = fdb_open(&dbfile, args->test_file_name, &fconfig);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    if (MULTI_KV) {
        char kv2[256];
        status = fdb_kvs_open(dbfile, &db, args->kv_store_name, &kvs_config);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        sprintf(kv2, "%s_back", args->kv_store_name);
        status = fdb_kvs_open(dbfile, &db2, kv2, &kvs_config);
    } else {
        status = fdb_kvs_open_default(dbfile, &db, &kvs_config);
    }
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_set_log_callback(db, logCallbackFunc,
                                  (void *) args->test_file_name);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    memset(&doc, 0, sizeof(fdb_doc));
    doc.key = &bigKeyBuf[0];
    doc.keylen = MAX_KEY_LEN;
    doc.body = &bigBodyBuf[0];
    doc.bodylen = BODY_LEN;

    printf("\nWriter thread:load %" _F64 " docs from %" _F64 " to %" _F64 "\n",
           args->docid_high - args->docid_low, args->docid_low,
           args->docid_high);

    for (int j = args->docid_high - 1; j >= args->docid_low; --j) {
        char keyfmt[8], bodyfmt[8];
        unsigned int rand_keylen = 1 + rand() % MAX_KEY_LEN;
        sprintf(keyfmt, "%%%dd", rand_keylen);
        sprintf(bigKeyBuf, keyfmt, j);
        sprintf(bodyfmt, "%%%dd", BODY_LEN);
        sprintf(bigBodyBuf, bodyfmt, j);
        doc.keylen = rand_keylen + 1;
        status = fdb_set(db, &doc);
        TEST_CHK(status == FDB_RESULT_SUCCESS);

        // insert into back index
        status = fdb_set(db2, &doc);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        // Commit based on batch-size set..
        if (j && j % args->batch_size == 0) {
            if (MULTI_KV) {
                char temp[256];
                sprintf(temp, "%s_meta", args->kv_store_name);
                fdb_kvs_handle *db3;
                status = fdb_kvs_open(dbfile, &db3, temp, &kvs_config);
                TEST_CHK(status == FDB_RESULT_SUCCESS);
                sprintf(bigKeyBuf, "foo");
                doc.keylen = 3;
                status = fdb_set(db3, &doc);
                TEST_CHK(status == FDB_RESULT_SUCCESS);
                fdb_kvs_close(db3);
            }
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
    int64_t writer_shard_size = NUM_DOCS / NUM_WRITERS;
    fdb_file_handle *dbfile;
    fdb_config fconfig;
    int r;
    fdb_status status;
    struct writer_thread_args *wargs = alca(struct writer_thread_args,
                                       num_writers);
    thread_t *tid = alca(thread_t, num_writers);
    thread_t *compactor_tid = alca(thread_t, 1);
    void **compactor_ret = alca(void *, 1);
    struct compactor_thread_args *cargs = alca(struct compactor_thread_args, 1);
    void **thread_ret = alca(void *, num_writers);
    struct timeval ts_begin, ts_cur, ts_gap;

    // remove previous test files
    r = system(SHELL_DEL TEST_FILENAME "* > errorlog.txt");
    (void) r;

    printf("\nLoading %" _F64 " docs %d key length %d bodylen."
           " Buffercache %" _F64 "MB. Target docsize %" _F64 "MB...",
            NUM_DOCS, MAX_KEY_LEN, BODY_LEN,
            BUFFERCACHE_SIZE ? (uint64_t)BUFFERCACHE_SIZE/ (1024 * 1024) : 0,
            (uint64_t)(MAX_KEY_LEN + BODY_LEN + 8) * NUM_DOCS / (1024 * 1024));
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
        wargs[i].batch_size = NUM_DOCS / 1000;
        wargs[i].commit_opt = FDB_COMMIT_MANUAL_WAL_FLUSH;
        sprintf(wargs[i].test_file_name, "%s_%d.0", TEST_FILENAME, i);
        sprintf(wargs[i].kv_store_name, "kv_%d", 0);

        thread_create(&tid[i], _writer_thread, &wargs[i]);
    }

    cargs->num_files = num_writers;
    cargs->config = fconfig;
    thread_create(compactor_tid, _compactor_thread, cargs);

    // wait for thread termination
    for (int i = 0; i < num_writers; ++i) {
        thread_join(tid[i], &thread_ret[i]);
    }
    cargs->num_files = 0; // ask compactor to stop
    thread_join(*compactor_tid, compactor_ret);

    status = fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    gettimeofday(&ts_cur, NULL);
    ts_gap = _utime_gap(ts_begin, ts_cur);

    printf("\nFile created %" _F64 " docs loaded (keylen %d doclen %d) in"
           "%ldsec", NUM_DOCS, MAX_KEY_LEN, BODY_LEN, ts_gap.tv_sec);

    printf("\nStarting compaction...");
    printf("\n"); // flush stdio buffer
    gettimeofday(&ts_begin, NULL);

    status = fdb_compact_with_cow(dbfile, TEST_FILENAME "2");
    if (status == FDB_RESULT_COMPACTION_FAIL) {
        status = fdb_compact(dbfile, TEST_FILENAME "2");
    }
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
