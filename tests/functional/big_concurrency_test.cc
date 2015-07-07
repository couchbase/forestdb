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
#include "arch.h"
#include "time_utils.h"
#include "atomic.h"
#include "functional_util.h"

#define KEY_LEN 256
#define NUM_FRUITS 26
#define PREFIX_LEN 11
#define TEST_FILENAME "./bigfile"

struct shared_data {
    static mutex_t sync_mutex;
    int inmem_snap_freq; // how often should snapshots be taken?
    int num_inmem_snaps; // how many outstanding snapshots should be there
    fdb_kvs_handle **inmem_snaps;
    fdb_seqnum_t *inmem_seqnum;
};

struct writer_thread_args {
    size_t ndocs;
    size_t batch_size;
    size_t clone_frequency;
    fdb_config config;
    fdb_kvs_config kvs_config;
    char test_file_name[256];
    fdb_commit_opt_t commit_opt;
    struct shared_data *test;
};

struct reader_thread_args {
    size_t ndocs;
    fdb_config config;
    fdb_kvs_config kvs_config;
    char *test_name;
    int check_body;
    struct shared_data *test;
};

void logCallbackFunc(int err_code,
                     const char *err_msg,
                     void *pCtxData) {
    fprintf(stderr, "%s - error code: %d, error message: %s\n",
            (char *) pCtxData, err_code, err_msg);
}

static const char prefixes[NUM_FRUITS][PREFIX_LEN] = {
    "apple_____",
    "banana____",
    "cherry____",
    "date______",
    "eggfruit__",
    "fig_______",
    "grape_____",
    "honeydew__",
    "incaberry_",
    "jackfruit_",
    "kiwi______",
    "lime______",
    "mango_____",
    "nectarine_",
    "orange____",
    "pineapple_",
    "quince____",
    "raspberry_",
    "sweetpea__",
    "tangerine_",
    "ugli______",
    "vanilla___",
    "walnut____",
    "xigua_____",
    "yam_______",
    "zucchini__"
};

void gen_key_fwd(int id, char *buf)
{
    memcpy(buf, prefixes[id % NUM_FRUITS], PREFIX_LEN);
    buf += PREFIX_LEN;
    *buf = '_';
    buf++;
    sprintf(buf, "%8d%8d%8d%8d%8d", id, id, id, id, id);
}

void gen_key_back(int id, char *buf)
{
    sprintf(buf, "%8d%8d%8d%8d%8d", id, id, id, id, id);
    buf += 9;
    memcpy(buf, prefixes[id % NUM_FRUITS], PREFIX_LEN);
}

static void *_writer_thread(void *voidargs)
{
    TEST_INIT();

    struct writer_thread_args *args = (struct writer_thread_args *)voidargs;
    fdb_doc *doc;
    int snap = 0;
    char bigKeyBuf[KEY_LEN];
    fdb_file_handle *dbfile;
    fdb_kvs_handle *db;
    fdb_kvs_handle *db2;
    fdb_doc *rdoc = NULL;
    fdb_status status;
    fdb_config fconfig = args->config;
    fdb_kvs_config kvs_config = args->kvs_config;

    status = fdb_open(&dbfile, args->test_file_name, &fconfig);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_kvs_open(dbfile, &db, "main", &kvs_config);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_kvs_open(dbfile, &db2, "back", &kvs_config);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_set_log_callback(db, logCallbackFunc,
                                  (void *) args->test_file_name);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    status = fdb_doc_create(&doc, NULL, 0, NULL, 0, NULL, 0);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    doc->key = &bigKeyBuf[0];
    doc->keylen = KEY_LEN;
    memset(bigKeyBuf, 0, KEY_LEN);

    for (int j = args->ndocs; j; --j) {
        gen_key_fwd(j, bigKeyBuf);
        status = fdb_set(db, doc);
        TEST_CHK(status == FDB_RESULT_SUCCESS);

        gen_key_back(j, bigKeyBuf);
        status = fdb_set(db, doc);
        TEST_CHK(status == FDB_RESULT_SUCCESS);

        // Commit based on batch-size set..
        if (j && j % args->batch_size == 0) {
            status = fdb_commit(dbfile, args->commit_opt);
            TEST_CHK(status == FDB_RESULT_SUCCESS);
        }
        // Take in-memory snapshot based on frequency set..
        if (j && j % args->test->inmem_snap_freq == 0) {
            snap = (snap + 1) % args->test->num_inmem_snaps;
            fdb_kvs_handle **snap_db = &args->test->inmem_snaps[snap];
            if (*snap_db) {
                fdb_kvs_close(*snap_db);
            }
            status = fdb_snapshot_open(db, snap_db, FDB_SNAPSHOT_INMEM);
            TEST_CHK(status == FDB_RESULT_SUCCESS);
            fdb_doc_create(&rdoc, bigKeyBuf, KEY_LEN, NULL, 0, NULL, 0);
            status = fdb_get(*snap_db, rdoc);
            TEST_CHK(status == FDB_RESULT_SUCCESS);
            fdb_doc_free(rdoc);
            rdoc = NULL;
        }
    }

    doc->key = NULL;
    fdb_doc_free(doc);
    fdb_close(dbfile);

    return NULL;
}

// TEST MAIN:
// Writer keeps doing set without commit, taking in-memory snapshots
void multi_file_write_with_inmem_snap(const char *test_name) {
    TEST_INIT();
    memleak_start();

    int num_writers = 4;
    int num_inmem_snaps = 4;
    int inmem_snap_freq = 10;
    int num_docs = NUM_FRUITS*1000;
    int r;
    fdb_status status;
    struct writer_thread_args *wargs = alca(struct writer_thread_args,
                                       num_writers);
    struct shared_data *test_data = alca(struct shared_data, num_writers);
    thread_t *tid = alca(thread_t, num_writers);
    void **thread_ret = alca(void *, num_writers);

    // remove previous test files
    r = system(SHELL_DEL TEST_FILENAME "* > errorlog.txt");
    (void) r;

    for (int i = num_writers - 1; i >= 0; --i) {
        // Writer Thread Config:
        wargs[i].ndocs = num_docs;
        wargs[i].config = fdb_get_default_config();
        wargs[i].config.buffercache_size = 0;
        wargs[i].kvs_config = fdb_get_default_kvs_config();
        wargs[i].batch_size = NUM_FRUITS*100;
        wargs[i].commit_opt = FDB_COMMIT_MANUAL_WAL_FLUSH;
        test_data[i].num_inmem_snaps = num_inmem_snaps;
        test_data[i].inmem_snap_freq = inmem_snap_freq;
        test_data[i].inmem_snaps = alca(fdb_kvs_handle *, num_inmem_snaps);
        for(int j = num_inmem_snaps - 1; j >=0; --j) {
            test_data[i].inmem_snaps[j] = NULL;
        }
        wargs[i].test = &test_data[i];
        wargs[i].clone_frequency = NUM_FRUITS*10;
        sprintf(wargs[i].test_file_name, "%s_%d", TEST_FILENAME, i);

        thread_create(&tid[i], _writer_thread, &wargs[i]);
    }

    // wait for thread termination
    for (int i = 0; i < num_writers; ++i) {
        thread_join(tid[i], &thread_ret[i]);
    }

    // shutdown
    status = fdb_shutdown();
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    memleak_end();
    TEST_RESULT(test_name);
}

int main() {
    multi_file_write_with_inmem_snap("4 writers with in-mem snapshots");
    return 0;
}
