/* -*- Mode: C++; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2016 Couchbase, Inc
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
#include <assert.h>

#include <algorithm>
#include <cmath>
#include <iterator>
#include <numeric>
#include <string>
#include <vector>

#include "config.h"
#include "timing.h"
#include "test.h"

#include <libforestdb/forestdb.h>

bool track_stat(stat_history_t *stat, uint64_t lat) {

    if (lat == (uint64_t)ERR_NS) {
      return false;
    }

    if (stat) {
        stat->latencies.push_back(lat);
        return true;
    } else {
        return false;
    }
}

void print_db_stats(fdb_file_handle **dbfiles, int nfiles) {

    int i, j;
    fdb_status status;
    fdb_latency_stat stat;
    int nstats = FDB_LATENCY_NUM_STATS;

    StatAggregator *sa = new StatAggregator(nstats, 1);

    for (i = 0; i < nstats; i++) {
        const char* name = fdb_latency_stat_name(i);
        sa->t_stats[i][0].name = name;

        for (j = 0; j < nfiles; j++) {
            memset(&stat, 0, sizeof(fdb_latency_stat));
            status = fdb_get_latency_stats(dbfiles[j], &stat, i);
            assert(status == FDB_RESULT_SUCCESS);

            if (stat.lat_count > 0) {
                sa->t_stats[i][0].latencies.push_back(stat.lat_avg);
            }
        }
    }
    (void)status;

    sa->aggregateAndPrintStats("FDB_STATS", nfiles, "µs");
    delete sa;
}

void str_gen(char *s, const int len) {

    int i = 0;
    static const char alphanum[] =
        "0123456789"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz";
    size_t n_ch = strlen(alphanum);

    if (len < 1){
        return;
    }

    // return same ordering of chars
    while (i < len) {
        s[i] = alphanum[i%n_ch];
        i++;
    }
    s[len-1] = '\0';
}

void swap(char *x, char *y) {

    char temp;
    temp = *x;
    *x = *y;
    *y = temp;
}

void permute(fdb_kvs_handle *kv, char *a, int l, int r) {

    int i;
    char keybuf[256], metabuf[256], bodybuf[1024];
    fdb_doc *doc = NULL;
    str_gen(bodybuf, 1024);

    if (l == r) {
        sprintf(keybuf, a, l);
        sprintf(metabuf, "meta%d", r);
        fdb_doc_create(&doc, (void*)keybuf, strlen(keybuf),
                       (void*)metabuf, strlen(metabuf),
                       (void*)bodybuf, strlen(bodybuf));
        fdb_set(kv, doc);
        fdb_doc_free(doc);
    } else {
        for (i = l; i <= r; i++) {
            swap((a+l), (a+i));
            permute(kv, a, l+1, r);
            swap((a+l), (a+i)); //backtrack
        }
    }
}

void sequential(fdb_kvs_handle *kv, int pos) {

    int i;
    char keybuf[256], metabuf[256], bodybuf[512];
    fdb_doc *doc = NULL;
    str_gen(bodybuf, 512);

    // load flat keys
    for (i = 0; i < 1000; i++){
        sprintf(keybuf, "%d_%dseqkey", pos, i);
        sprintf(metabuf, "meta%d", i);
        fdb_doc_create(&doc, (void*)keybuf, strlen(keybuf),
                       (void*)metabuf, strlen(metabuf),
                       (void*)bodybuf, strlen(bodybuf));
        fdb_set(kv, doc);
        fdb_doc_free(doc);
    }
}

void writer(fdb_kvs_handle *db, int pos) {

    char keybuf[KEY_SIZE];

    str_gen(keybuf, KEY_SIZE);
    permute(db, keybuf, 0, PERMUTED_BYTES);
    sequential(db, pos);
}

void reader(reader_context *ctx) {

    bool is_err;
    fdb_kvs_handle *db = ctx->handle;
    fdb_iterator *iterator;
    fdb_doc *doc = NULL, *rdoc = NULL;
    fdb_status status;

    track_stat(ctx->stat_itr_init,
               timed_fdb_iterator_init(db, &iterator));

    // repeat until fail
    do {
        // sum time of all gets
        track_stat(ctx->stat_itr_get, timed_fdb_iterator_get(iterator, &rdoc));

        // get from kv
        fdb_doc_create(&doc, rdoc->key, rdoc->keylen, NULL, 0, NULL, 0);
        status = fdb_get(db, doc);
        assert(status == FDB_RESULT_SUCCESS);

        fdb_doc_free(doc);
        doc = NULL;

        // kv get
        fdb_doc_free(rdoc);
        rdoc = NULL;

        is_err = track_stat(ctx->stat_itr_next,
                            timed_fdb_iterator_next(iterator));
    } while (!is_err);
    track_stat(ctx->stat_itr_close, timed_fdb_iterator_close(iterator));
    (void)status;
}

void deletes(fdb_kvs_handle *db, int pos) {

    int i;
    char keybuf[256];
    fdb_doc *doc = NULL;

    // deletes sequential docs
    for (i = 0; i < 1000; i++){
        sprintf(keybuf, "%d_%dseqkey", pos, i);
        fdb_doc_create(&doc, (void*)keybuf, strlen(keybuf), NULL, 0, NULL, 0);
        fdb_del(db, doc);
        fdb_doc_free(doc);
    }
}

void do_bench() {

    TEST_INIT();
    int i, j, r;
#if defined(THREAD_SANITIZER)
    int n_loops = 1;
#else
    int n_loops = 5;
#endif // #if defined(THREAD_SANITIZER)

    int n_kvs = 16;
    char cmd[64], fname[64], dbname[64];
    int n2_kvs = n_kvs * n_kvs;

    // file handlers
    fdb_status status;
    fdb_file_handle **dbfile = alca(fdb_file_handle*, n_kvs);
    fdb_kvs_handle **db = alca(fdb_kvs_handle*, n2_kvs);
    fdb_kvs_handle **snap_db = alca(fdb_kvs_handle*, n2_kvs);
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    fdb_config fconfig = fdb_get_default_config();

    // reader stats
    reader_context *ctx = alca(reader_context, n2_kvs);

    StatAggregator *sa = new StatAggregator(4, n2_kvs);

    for (i = 0; i < n2_kvs; ++i) {
        sa->t_stats[0][i].name.assign(ST_ITR_INIT);
        sa->t_stats[1][i].name.assign(ST_ITR_NEXT);
        sa->t_stats[2][i].name.assign(ST_ITR_GET);
        sa->t_stats[3][i].name.assign(ST_ITR_CLOSE);
        ctx[i].stat_itr_init = &sa->t_stats[0][i];
        ctx[i].stat_itr_next = &sa->t_stats[1][i];
        ctx[i].stat_itr_get = &sa->t_stats[2][i];
        ctx[i].stat_itr_close = &sa->t_stats[3][i];
    }

    sprintf(cmd, "rm bench* > errorlog.txt");
    r = system(cmd);
    (void)r;

    // setup
    fconfig.compaction_mode = FDB_COMPACTION_MANUAL;
    fconfig.auto_commit = false;
    fconfig.compactor_sleep_duration = 600;
    fconfig.prefetch_duration = 0;
    fconfig.num_compactor_threads = 1;
    fconfig.num_bgflusher_threads = 0;

    // open 16 dbfiles each with 16 kvs
    for (i = 0; i < n_kvs; ++i){
        sprintf(fname, "bench%d",i);
        status = fdb_open(&dbfile[i], fname, &fconfig);
        assert(status == FDB_RESULT_SUCCESS);

        for (j = i*n_kvs; j < (i*n_kvs + n_kvs); ++j){
            sprintf(dbname, "db%d",j);
            status = fdb_kvs_open(dbfile[i], &db[j],
                                  dbname, &kvs_config);
            assert(status == FDB_RESULT_SUCCESS);
        }
    }

    for (i = 0; i < 10; ++i){
        // generate initial commit headers
        for (i = 0; i < n_kvs; i++){
            status = fdb_commit(dbfile[i], FDB_COMMIT_MANUAL_WAL_FLUSH);
            assert(status == FDB_RESULT_SUCCESS);
        }
    }

    for (j = 0; j < n_loops; j++){

        // write to single file 1 kvs
        writer(db[0], 0);

        // reads from single file 1 kvs
        ctx[0].handle = db[0];
        reader(&ctx[0]);

        // snap iterator read
        status = fdb_snapshot_open(db[0], &snap_db[0],
                                   FDB_SNAPSHOT_INMEM);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        ctx[0].handle = snap_db[0];
        reader(&ctx[0]);

       // write/read/snap to single file 16 kvs
        for (i = 0;i < n_kvs; ++i){
            writer(db[i], i);
        }
        for (i = 0; i < n_kvs; ++i){
            deletes(db[i], i);
        }
        for (i = 0; i < n_kvs; ++i){
            ctx[i].handle = db[i];
            reader(&ctx[i]);
        }
        for (i = 0; i < n_kvs; ++i){
            status = fdb_snapshot_open(db[i], &snap_db[i],
                                       FDB_SNAPSHOT_INMEM);
            TEST_CHK(status == FDB_RESULT_SUCCESS);
            ctx[i].handle = snap_db[i];
            reader(&ctx[i]);
        }

        // commit single file
        status = fdb_commit(dbfile[0], FDB_COMMIT_MANUAL_WAL_FLUSH);
        assert(status == FDB_RESULT_SUCCESS);

        // write/write/snap to 16 files 1 kvs
        for (i = 0; i < n2_kvs; i += n_kvs){ // every 16 kvs is new file
            writer(db[i], i);
        }
        for (i = 0; i < n2_kvs; i += n_kvs){
            deletes(db[i], i);
        }
        for (i = 0; i < n2_kvs; i += n_kvs){ // every 16 kvs is new file
            ctx[i].handle = db[i];
            reader(&ctx[i]);
        }
        for (i = 0; i < n2_kvs; i += n_kvs){
            status = fdb_snapshot_open(db[i], &snap_db[i],
                                       FDB_SNAPSHOT_INMEM);
            assert(status == FDB_RESULT_SUCCESS);
            ctx[i].handle = snap_db[i];
            reader(&ctx[i]);
        }

        // write to 16 files 16 kvs each
        for (i = 0; i < n2_kvs; i++){
            writer(db[i], i);
        }
        for (i = 0; i < n2_kvs; ++i){
            deletes(db[i], i);
        }
        for (i = 0; i < n2_kvs; i++){
            ctx[i].handle = db[i];
            reader(&ctx[i]);
        }
        for (i = 0; i < n2_kvs; i++){
            status = fdb_snapshot_open(db[i], &snap_db[i],
                                       FDB_SNAPSHOT_INMEM);
            assert(status == FDB_RESULT_SUCCESS);
            ctx[i].handle = snap_db[i];
            reader(&ctx[i]);
        }

        // commit all
        for (i = 0;i < n_kvs; i++){
            status = fdb_commit(dbfile[i], FDB_COMMIT_MANUAL_WAL_FLUSH);
            assert(status == FDB_RESULT_SUCCESS);
        }
    }
    // compact all
    for (i = 0; i < n_kvs; i++){
        status = fdb_compact(dbfile[i], NULL);
        assert(status == FDB_RESULT_SUCCESS);
    }

    // print aggregated reader stats
    sa->aggregateAndPrintStats("ITERATOR_TEST_STATS", n_kvs * n_kvs, "ns");
    delete sa;

    // print aggregated dbfile stats
    print_db_stats(dbfile, n_kvs);

    // cleanup
    for(i = 0; i < n2_kvs; i++){
        fdb_kvs_close(db[i]);
        fdb_kvs_close(snap_db[i]);
    }
    for(i = 0; i < n_kvs; i++){
        fdb_close(dbfile[i]);
    }

    fdb_shutdown();

    (void)status;
    sprintf(cmd, "rm bench* > errorlog.txt");
    r = system(cmd);
    (void)r;

    TEST_RESULT("Benchmark done");
}

/*
 *  ===================
 *  FDB BENCH MARK TEST
 *  ===================
 *  Performs unit benchmarking with 16 dbfiles each with max 16 kvs
 */
int main(int argc, char* args[]) {

    do_bench();
}
