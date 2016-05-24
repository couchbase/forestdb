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
#include <limits.h>
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

#define TEST_FILENAME "disksim_testfile"
#define PWRITE_SLEEP_MASK 0x01
#define PWRITE_MAX_SLEEP  10

#define PREAD_SLEEP_MASK  0x02
#define PREAD_MAX_SLEEP   10

#define CLOSE_SLEEP_MASK  0x03
#define CLOSE_MAX_SLEEP   10

#define FSYNC_SLEEP_MASK  0x04
#define FSYNC_MAX_SLEEP   100

int MAX_NUM_SNAPSHOTS;
int NUM_DOCS;
int COMMIT_FREQ;
int SNAPSHOT_FREQ;
int NUM_ITERATORS;
int NUM_WRITERS;
int NUM_WRITER_ITERATIONS;
int ITERATOR_BATCH_SIZE;

typedef struct snapshot_t {
    fdb_kvs_handle *snap;
    int8_t *_key_map;
} snapshot_t;

typedef struct storage_t {
    fdb_file_handle *fhandle;
    fdb_config fconfig;
    fdb_kvs_config kvs_config;
    fdb_kvs_handle *main;
    fdb_kvs_handle *back;
    fdb_kvs_handle *def;
    int8_t *keymap;
    int8_t fflag;
    snapshot_t *snaps;
    int latest_snap_idx;
    bool shutdown;
    spin_t lock;
} storage_t;

ssize_t pwrite_cb(void *ctx, struct filemgr_ops *normal_ops,
                  fdb_fileops_handle fops_handle, void *buf, size_t count,
                  cs_off_t offset)
{
    storage_t *wctx = (storage_t *)ctx;
    if (wctx->fflag & PWRITE_SLEEP_MASK) {
        usleep(rand() % PWRITE_MAX_SLEEP);
    }
    return normal_ops->pwrite(fops_handle, buf, count, offset);
}

ssize_t pread_cb(void *ctx, struct filemgr_ops *normal_ops,
                 fdb_fileops_handle fops_handle, void *buf, size_t count,
                 cs_off_t offset)
{
    storage_t *wctx = (storage_t *)ctx;
    if (wctx->fflag & PREAD_SLEEP_MASK) {
        usleep(rand() % PREAD_MAX_SLEEP);
    }
    return normal_ops->pread(fops_handle, buf, count, offset);
}

int close_cb(void *ctx, struct filemgr_ops *normal_ops,
             fdb_fileops_handle fops_handle)
{
    storage_t *wctx = (storage_t *)ctx;
    if (wctx->fflag & CLOSE_SLEEP_MASK) {
        usleep(rand() % CLOSE_MAX_SLEEP);
    }
    return normal_ops->close(fops_handle);
}

int fsync_cb(void *ctx, struct filemgr_ops *normal_ops,
             fdb_fileops_handle fops_handle)
{
    storage_t *wctx = (storage_t *)ctx;
    if (wctx->fflag & FSYNC_SLEEP_MASK) {
        usleep(rand() % FSYNC_MAX_SLEEP);
    }
    return normal_ops->fsync(fops_handle);
}

INLINE void make_key(char *buf, int i, int8_t key_ver) {
    sprintf(buf, "%08d %d", i, key_ver);
}

fdb_status indexer_set(storage_t *st, int docid, int mutno, bool isdel)
{
    TEST_INIT();
    char mainkey[16], backkey[16];
    fdb_status s;
    int8_t key_ver;
    fdb_doc *rdoc;
    sprintf(backkey, "%08d", docid);
    fdb_doc_create(&rdoc, (void *)backkey, strlen(backkey)+1, NULL,0, NULL,0);
    s = fdb_get(st->back, rdoc);
    key_ver = st->keymap[docid];
    bool was_deleted = key_ver < 0 ? true : false;

    if (s == FDB_RESULT_SUCCESS) { // key was already inserted
        TEST_CHK(!was_deleted); // must be positive for non-deleted keys
        make_key(mainkey, docid, key_ver);
        TEST_CMP(rdoc->body, mainkey, rdoc->bodylen);
        // Use body from back index to delete key from main index
        s = fdb_del_kv(st->main, rdoc->body, rdoc->bodylen);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
    } else { // key does not exist or deleted
        TEST_CHK(s == FDB_RESULT_KEY_NOT_FOUND);
        TEST_CHK(key_ver <=0 ); // negative for deleted keys, 0 if new key
    }

    if (was_deleted) {
        key_ver = -key_ver; // flip the sign
    }
    if (key_ver == CHAR_MAX) {
        key_ver = 1;
    } else {
        key_ver++;
    }

    if (isdel) { // delete indexed key from database
        s = fdb_del_kv(st->back, (void*)backkey, strlen(backkey)+1);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        key_ver = -key_ver;
    } else { // update existing key in database, back index first, then main
        make_key(mainkey, docid, key_ver);
        s = fdb_set_kv(st->back, (void*)backkey, strlen(backkey)+1,
                mainkey, strlen(mainkey)+1);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        s = fdb_set_kv(st->main, (void *) mainkey, strlen(mainkey)+1,
                       NULL, 0);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
    }

    if (mutno && (mutno % COMMIT_FREQ) == 0) {
        s = fdb_commit(st->fhandle, FDB_COMMIT_NORMAL);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
    }

    if (mutno && (mutno % SNAPSHOT_FREQ) == 0) {
        fdb_kvs_handle *new_snapshot, *old_snapshot;
        s = fdb_snapshot_open(st->main, &new_snapshot, FDB_SNAPSHOT_INMEM);
        TEST_CHK(s == FDB_RESULT_SUCCESS);

        // Take a snapshot of main kv store as well as the key_map for reference
        spin_lock(&st->lock);

        st->latest_snap_idx = (st->latest_snap_idx + 1) % MAX_NUM_SNAPSHOTS;
        st->keymap[docid] = key_ver;
        old_snapshot = st->snaps[st->latest_snap_idx].snap; // get old snapshot
        st->snaps[st->latest_snap_idx].snap = new_snapshot; // swap with current
        memcpy(st->snaps[st->latest_snap_idx]._key_map, st->keymap, NUM_DOCS);

        spin_unlock(&st->lock);

        if (old_snapshot) {
            fdb_kvs_close(old_snapshot);
        }
    } else { // just update the reference map
        spin_lock(&st->lock);
        st->keymap[docid] = key_ver;
        spin_unlock(&st->lock);
    }

    fdb_doc_free(rdoc);

    return FDB_RESULT_SUCCESS;
}

static void *_writer_thread(void *voidargs)
{
    TEST_INIT();
    storage_t *db = (storage_t *)voidargs;
    fdb_status s;

    // open the file and the 3 kv stores - main, back and default
    s = fdb_kvs_open_default(db->fhandle, &db->def, &db->kvs_config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_kvs_open(db->fhandle, &db->main, "main", &db->kvs_config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_kvs_open(db->fhandle, &db->back, "back", &db->kvs_config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    s = fdb_set_log_callback(db->main, logCallbackFunc,
                                  (void *) "indexer_patter_main");
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_set_log_callback(db->back, logCallbackFunc,
                                  (void *) "indexer_patter_back");
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_set_log_callback(db->def, logCallbackFunc,
                                  (void *) "indexer_patter_default");
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    for (int i = 0; i < NUM_DOCS; ++i) {
        indexer_set(db, i, i, false);
    }
    printf("--------LOADING COMPLETE------\n");
    for (int j = 0; j < NUM_WRITER_ITERATIONS * NUM_DOCS; ++j) {
        int i = rand() % NUM_DOCS;
        if (rand() % 100 > 80) {
            indexer_set(db, i, j, true); // delete key
        } else {
            indexer_set(db, i, j, false); // update key
        }
    }

    thread_exit(0);
    return NULL;
}

static void *_iterator_thread(void *voidargs)
{
    TEST_INIT();
    fdb_file_handle *fhandle;
    fdb_kvs_handle *snapdb;
    fdb_iterator *it;
    int start_key;
    char buf[32];
    int num_keys;
    int end_key;
    fdb_doc *rdoc = NULL;
    int j = 0;
    int total_docs_scanned = 0;
    int snap_idx;
    fdb_status s;

    storage_t *st = (storage_t *)voidargs;
    int8_t *key_snap = alca(int8_t, NUM_DOCS);

    s = fdb_open(&fhandle, TEST_FILENAME, &st->fconfig);
    if (s != FDB_RESULT_SUCCESS) {
        printf("Iterator failed to open file %s %d\n", TEST_FILENAME, s);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
    }

    while (++j) {
        spin_lock(&st->lock);
        if (st->shutdown) {
            spin_unlock(&st->lock);
            printf("Iterator thread shutting down after %d scans..\n", j);
            break;
        }
        if (!st->snaps[st->latest_snap_idx].snap) {
            spin_unlock(&st->lock);
            usleep(10);
            --j;
            continue;
        }
        // CLONE the latest snapshot from the writer's context...
        snap_idx = st->latest_snap_idx;
        memcpy(key_snap, st->snaps[snap_idx]._key_map, NUM_DOCS);
        s = fdb_snapshot_open(st->snaps[snap_idx].snap, &snapdb,
                              FDB_SNAPSHOT_INMEM);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        spin_unlock(&st->lock);

        num_keys = ITERATOR_BATCH_SIZE;
        if (num_keys == NUM_DOCS) { // full scan
            start_key = 0;
            end_key = NUM_DOCS - 1;
        } else { // partial scan
            start_key = rand() % (NUM_DOCS - num_keys); // ensure range bounds
            end_key = start_key + num_keys;
        }

        make_key(buf, start_key, 0);
        s = fdb_iterator_init(snapdb, &it, buf, strlen(buf) + 1, NULL, 0,
                              FDB_ITR_NO_DELETES);
        for (int i = start_key; i < end_key; ++i) {
            if (key_snap[i] > 0) { // if the key was non-deleted in snapshot
                TEST_CHK(s == FDB_RESULT_SUCCESS); //next should be SUCCESS
                s = fdb_iterator_get(it, &rdoc);
                if (s == FDB_RESULT_ITERATOR_FAIL) {
                    break; // break!
                }
                TEST_CHK(s == FDB_RESULT_SUCCESS);
                make_key(buf, i, key_snap[i]);
                TEST_CMP(rdoc->key, buf, rdoc->keylen); // validate it
                fdb_doc_free(rdoc);
                rdoc = NULL;
                s = fdb_iterator_next(it);
                total_docs_scanned++;
            } else { // this key is not expected to be returned..
                continue;
            }
        }
        s = fdb_iterator_close(it);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        fdb_kvs_close(snapdb);
    }
    fdb_close(fhandle);
    printf("Total docs scanned = %d\n", total_docs_scanned);

    thread_exit(0);
    return NULL;
}

void indexer_pattern_test()
{
    TEST_INIT();

    memleak_start();
    int r;
    fdb_status s;
    fdb_config fconfig = fdb_get_default_config();
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    char temp[32];

    // SETUP Configurations...
    NUM_DOCS = 10000;
    NUM_WRITER_ITERATIONS = 3;
    COMMIT_FREQ = NUM_DOCS/10;
    SNAPSHOT_FREQ = COMMIT_FREQ / 17; // Derive snapshot freq from commit freq
    ITERATOR_BATCH_SIZE = 10;
    NUM_ITERATORS = 7;
    MAX_NUM_SNAPSHOTS = 5;
    NUM_WRITERS = 1; // Do not bump this up not safe

    fconfig.buffercache_size = 8*1024*1024;
    fconfig.flags = FDB_OPEN_FLAG_CREATE;
    fconfig.purging_interval = 0;
    fconfig.wal_threshold = 40960;
    fconfig.num_compactor_threads = 1;
    //fconfig.block_reusing_threshold = 0;
    //fconfig.num_wal_partitions = 3;

    thread_t *wtid = alca(thread_t, NUM_WRITERS);
    thread_t *tid = alca(thread_t, NUM_ITERATORS);
    void **thread_ret = alca(void *, NUM_ITERATORS);

    // Get the default callbacks which result in normal operation for other ops
    struct anomalous_callbacks *disk_sim_cb = get_default_anon_cbs();
    storage_t db;
    memset(&db, 0, sizeof(storage_t));
    db.keymap = (int8_t *)calloc(NUM_DOCS, sizeof(int8_t));
    spin_init(&db.lock);
    db.snaps = (snapshot_t *)calloc(MAX_NUM_SNAPSHOTS, sizeof(snapshot_t));
    for (int i = 0; i < MAX_NUM_SNAPSHOTS; ++i) {
        db.snaps[i]._key_map = (int8_t *)calloc(NUM_DOCS, sizeof(int8_t));
    }

    // Modify the pwrite callback to redirect to test-specific function
    disk_sim_cb->pwrite_cb = &pwrite_cb;
    disk_sim_cb->pread_cb = &pread_cb;
    disk_sim_cb->close_cb = &close_cb;
    disk_sim_cb->fsync_cb = &fsync_cb;

    // remove previous anomaly_test files
    r = system(SHELL_DEL" " TEST_FILENAME " > errorlog.txt");
    (void)r;

    // Reset anomalous behavior stats..
    filemgr_ops_anomalous_init(disk_sim_cb, &db);

    db.fconfig = fconfig;
    db.kvs_config = kvs_config;

    s = fdb_open(&db.fhandle, TEST_FILENAME, &db.fconfig);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    printf("Num docs %d Num iterations %d Commit freq %d Snapshot freq %d "
           "Iterator batch %d Num iterator threads %d\n",
           NUM_DOCS, NUM_WRITER_ITERATIONS, COMMIT_FREQ, SNAPSHOT_FREQ,
           ITERATOR_BATCH_SIZE, NUM_ITERATORS);
    printf("Wal size %" _F64 " Buffercache size %" _F64 "MB\n",
           fconfig.wal_threshold, fconfig.buffercache_size/1024/1024);
    for (r = 0; r < NUM_WRITERS; ++r) {
        thread_create(&wtid[r], _writer_thread, &db);
    }

    usleep(1);

    for (int i = 0; i < NUM_ITERATORS; ++i) {
        thread_create(&tid[i], _iterator_thread, &db);
    }

    for (int i = 0; i < NUM_WRITERS; ++i) {
        thread_join(wtid[i], &thread_ret[i]);
    }

    spin_lock(&db.lock);
    db.shutdown = true;
    spin_unlock(&db.lock);

    for (int i = 0; i < NUM_ITERATORS; ++i) {
        thread_join(tid[i], &thread_ret[i]);
    }

    printf("Done with iterations.. Stats..\n");
    // also get latency stats..
    for (int i = 0; i < FDB_LATENCY_NUM_STATS; ++i) {
        fdb_latency_stat stat;
        memset(&stat, 0, sizeof(fdb_latency_stat));
        s = fdb_get_latency_stats(db.fhandle, &stat, i);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        fprintf(stderr, "%s:\t%u\t%u\t%u\t%" _F64 "\n",
                fdb_latency_stat_name(i),
                stat.lat_min, stat.lat_avg, stat.lat_max, stat.lat_count);
    }

    // free all resources
    fdb_close(db.fhandle);
    spin_destroy(&db.lock);
    free(db.keymap);
    for (int i = 0; i < MAX_NUM_SNAPSHOTS; ++i) {
        free(db.snaps[i]._key_map);
    }
    free(db.snaps);
    fdb_shutdown();

    memleak_end();

    sprintf(temp, "indexer pattern test:");

    TEST_RESULT(temp);
}

int main(){
    indexer_pattern_test();

    return 0;
}
