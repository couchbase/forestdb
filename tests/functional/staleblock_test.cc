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
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#if !defined(WIN32) && !defined(_WIN32)
#include <signal.h>
#include <unistd.h>
#endif

#include "test.h"
#include "filemgr.h"
#include "staleblock.h"
#include "internal_types.h"
#include "libforestdb/forestdb.h"
#include "functional_util.h"

/*
 * Verify that blocks can be reclaimed when
 * default block reuse threshold is used.
 *
 * When threshold is 0 or 100 blocks should
 * not be reusable
 */
void verify_staleblock_reuse_param_test() {
    TEST_INIT();
    memleak_start();

    uint64_t i;
    int r;
    const int kv = 512;
    char keybuf[kv];
    char bodybuf[kv];
    fdb_status status;
    fdb_file_handle *dbfile;
    fdb_kvs_handle *db;
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    sb_decision_t sb_decision;
    fdb_file_info file_info;

    // set block reuse threshold = 65
    fdb_config fconfig = fdb_get_default_config();
    fconfig.compaction_threshold = 0;
    fconfig.block_reusing_threshold = 65;

start_data_loading:
    // remove previous staleblktest files
    r = system(SHELL_DEL" staleblktest* > errorlog.txt");
    (void)r;

    fdb_open(&dbfile, "./staleblktest1", &fconfig);
    fdb_kvs_open_default(dbfile, &db, &kvs_config);

    // create num_keeping_headers+1
    for (i = 0; i < fconfig.num_keeping_headers + 1; i++) {
        sprintf(keybuf, "key");
        status = fdb_set_kv(db, keybuf, kv, NULL, 0);
        TEST_STATUS(status);
        status = fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);
        TEST_STATUS(status);
    }

    // load until exceeding SB_MIN_BLOCK_REUSING_FILESIZE
    i = 0;
    do {
        sprintf(keybuf, "key");
        sprintf(bodybuf, "body%d", static_cast<int>(i));
        status = fdb_set_kv(db, keybuf, kv, bodybuf, kv);
        TEST_STATUS(status);
        i++;
        status = fdb_get_file_info(dbfile, &file_info);
        TEST_STATUS(status);
    } while (file_info.file_size < SB_MIN_BLOCK_REUSING_FILESIZE);

    // expect block reclaim only for valid threshold value
    sb_decision = sb_check_block_reusing(db);
    if (fconfig.block_reusing_threshold == 65) {
        TEST_CHK(sb_decision == SBD_RECLAIM);
    } else {
        TEST_CHK(sb_decision == SBD_NONE);
    }

    // intermediate cleanup
    status = fdb_close(dbfile);
    TEST_STATUS(status);
    fdb_shutdown();

    // run again with different config
    if (fconfig.block_reusing_threshold == 65) {
        // disable with 0
        fconfig.block_reusing_threshold = 0;
        goto start_data_loading;
    } else if (fconfig.block_reusing_threshold == 0) {
        // disable with 100
        fconfig.block_reusing_threshold = 100;
        goto start_data_loading;
    }

    memleak_end();
    TEST_RESULT("verify staleblock reuse param test");
}

void fillstr(char *str, char c, int n) {
    int i;
    for (i = 0; i < n - 1; ++i) {
        str[i] = c;
    }
    str[i] = '\0';
}

/*
 * verify_staleblock_reuse_param_test:
 *     create 2*num_keeping_headers and open snapshot
 *     at halfway point. enter block reuse state
 *     verify snapshot data remains unaffected
 */
void reuse_with_snapshot_test() {
    TEST_INIT();
    memleak_start();

    int i, n, r;
    const int kv = 512;
    char keybuf[kv];
    char bodybuf[kv];
    void *rvalue;
    size_t rvalue_len;
    fdb_status status;
    fdb_file_handle *dbfile;
    fdb_kvs_handle *db, *snap_db;
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    sb_decision_t sb_decision;
    fdb_file_info file_info;

    fdb_config fconfig = fdb_get_default_config();
    fconfig.compaction_threshold = 0;
    fconfig.block_reusing_threshold = 65;
    fconfig.num_keeping_headers = 10;

    // remove previous staleblktest files
    r = system(SHELL_DEL" staleblktest* > errorlog.txt");
    (void)r;

    fdb_open(&dbfile, "./staleblktest1", &fconfig);
    fdb_kvs_open_default(dbfile, &db, &kvs_config);

    // create 2*num_keeping_headers
    n = 2 * fconfig.num_keeping_headers;
    for (i = 0; i < n; i++) {
        fillstr(keybuf, 'k', kv);
        sprintf(bodybuf, "orig_body%d", i+1);
        status = fdb_set_kv(db, keybuf, strlen(keybuf),
                            bodybuf, strlen(bodybuf) + 1);
        TEST_STATUS(status);
        status = fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);
        TEST_STATUS(status);
    }

    // load until exceeding SB_MIN_BLOCK_REUSING_FILESIZE
    i = 0;
    do {
        fillstr(keybuf, 'r', kv);
        fillstr(bodybuf, 'y', kv);
        status = fdb_set_kv(db, keybuf, strlen(keybuf),
                            bodybuf, strlen(bodybuf) + 1);
        TEST_STATUS(status);
        i++;
        status = fdb_get_file_info(dbfile, &file_info);
        TEST_STATUS(status);
    } while (file_info.file_size < SB_MIN_BLOCK_REUSING_FILESIZE);

    sb_decision = sb_check_block_reusing(db);
    TEST_CHK(sb_decision == SBD_RECLAIM);

    // open snapshot
    status = fdb_snapshot_open(db, &snap_db, 8);
    TEST_STATUS(status);

    // commit
    status = fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);
    TEST_STATUS(status);

    // write until blocks are no longer being reused
    i = 0;
    do {
        sprintf(keybuf, "key%d", i);
        fillstr(bodybuf, 'z', kv);
        status = fdb_set_kv(db, keybuf, strlen(keybuf),
                            bodybuf, strlen(bodybuf));
        TEST_STATUS(status);
        sb_decision = sb_check_block_reusing(db);
        i++;
    } while (sb_decision != SBD_NONE);

    // delete original keys
    n = 2 * fconfig.num_keeping_headers;
    for (i = 0; i < n; i++) {
        fillstr(keybuf, 'k', kv);
        status = fdb_del_kv(db, keybuf, strlen(keybuf));
        TEST_STATUS(status);
    }

    // commit
    status = fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);
    TEST_STATUS(status);

    fillstr(keybuf, 'k', kv);
    sprintf(bodybuf, "orig_body%d", 8);

    // check key does not exist in main kv
    status = fdb_get_kv(db, keybuf, strlen(keybuf),
                        &rvalue, &rvalue_len);
    TEST_CHK(status == FDB_RESULT_KEY_NOT_FOUND);

    // check still exists in snapshot data
    status = fdb_get_kv(snap_db, keybuf, strlen(keybuf),
                        &rvalue, &rvalue_len);
    TEST_STATUS(status);
    TEST_CMP(rvalue, bodybuf, rvalue_len);

    status = fdb_free_block(rvalue);
    TEST_STATUS(status);
    status = fdb_kvs_close(snap_db);
    TEST_STATUS(status);
    status = fdb_kvs_close(db);
    TEST_STATUS(status);
    status = fdb_close(dbfile);
    TEST_STATUS(status);
    fdb_shutdown();

    memleak_end();
    TEST_RESULT("reuse with snapshot test");
}

void verify_minimum_num_keeping_headers_param_test() {
    memleak_start();
    TEST_INIT();

    int i, r;
    fdb_file_handle* dbfile;
    fdb_kvs_handle* db;
    fdb_kvs_handle* snap_db;
    fdb_status status;
    fdb_config fconfig = fdb_get_default_config();
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    fdb_file_info file_info;

    r = system(SHELL_DEL" staleblktest* > errorlog.txt");
    (void)r;

    // init
    fconfig.compaction_threshold = 0;

    // open with zero num_keeping_headers parameter
    fconfig.num_keeping_headers = 0;
    status = fdb_open(&dbfile, (char *)"./staleblktest1", &fconfig);
    // should fail
    TEST_CHK(status != FDB_RESULT_SUCCESS);

    // open with single keeping header
    fconfig.num_keeping_headers = 1;
    status = fdb_open(&dbfile, (char *)"./staleblktest1", &fconfig);
    TEST_STATUS(status);
    status = fdb_kvs_open(dbfile, &db, (char *)"num_keep", &kvs_config);
    TEST_STATUS(status);

    const char *key = "key";
    const char *val = "val";
    // 10 commits
    for (i = 0; i < 10; ++i) {
        status = fdb_set_kv(db, key, strlen(key) + 1,
                            val, strlen(val) + 1);
        TEST_STATUS(status);
        status = fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);
        TEST_STATUS(status);
    }

    // open snapshot on 9th commit
    status = fdb_snapshot_open(db, &snap_db, 9);
    TEST_STATUS(status);

    // load until exceeding SB_MIN_BLOCK_REUSING_FILESIZE
    i = 0;
    do {
        status = fdb_set_kv(db, key, strlen(key) + 1, val, strlen(val) + 1);
        TEST_STATUS(status);
        i++;
        status = fdb_get_file_info(dbfile, &file_info);
        TEST_STATUS(status);
    } while (file_info.file_size <= SB_MIN_BLOCK_REUSING_FILESIZE);

    // close snapshot (reader)
    status = fdb_kvs_close(snap_db);
    TEST_STATUS(status);

    // 11th commit causes reclaim and loss of 9th header
    status = fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);
    TEST_STATUS(status);

    // attempt to open new snapshot on 9th commit
    status = fdb_snapshot_open(db, &snap_db, 9);
    TEST_CHK(status == FDB_RESULT_NO_DB_INSTANCE);

    // open new snapshot on 10th commit
    status = fdb_snapshot_open(db, &snap_db, 10);
    TEST_STATUS(status);

    // cleanup
    status = fdb_close(dbfile);
    TEST_STATUS(status);
    status = fdb_shutdown();
    TEST_STATUS(status);

    memleak_end();
    TEST_RESULT("verify minimum num keeping headers param test");
}

void verify_high_num_keeping_headers_param_test() {
    memleak_start();
    TEST_INIT();

    int i, r;
    int low_seq = 0;
    int nheaders=100;
    char keybuf[16];
    void *rvalue;
    size_t rvalue_len;

    fdb_file_handle* dbfile;
    fdb_kvs_handle* db;
    fdb_kvs_handle* snap_db;
    fdb_status status;
    fdb_config fconfig = fdb_get_default_config();
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    fdb_file_info file_info;

    r = system(SHELL_DEL" staleblktest* > errorlog.txt");
    (void)r;

    // init
    fconfig.compaction_threshold = 0;
    fconfig.num_keeping_headers = nheaders;
    status = fdb_open(&dbfile, "./staleblktest1", &fconfig);
    TEST_STATUS(status);
    status = fdb_kvs_open(dbfile, &db, "num_keep", &kvs_config);
    TEST_STATUS(status);

    const char *key = "key";
    const char *val = "val";

    // load until exceeding SB_MIN_BLOCK_REUSING_FILESIZE
    i = 0;
    do {
        status = fdb_set_kv(db, key, strlen(key) + 1, val, strlen(val) + 1);
        TEST_STATUS(status);
        i++;
        status = fdb_get_file_info(dbfile, &file_info);
        TEST_STATUS(status);
    } while (file_info.file_size <= SB_MIN_BLOCK_REUSING_FILESIZE);

    // create lowest commit
    status = fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);
    TEST_STATUS(status);
    low_seq = i;

    // create 100 headers
    for (i = 0; i < nheaders; ++i) {
        sprintf(keybuf, "key%d", i);
        status = fdb_set_kv(db, keybuf, strlen(keybuf), (char *)"reu", 4);
        TEST_STATUS(status);
        status = fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);
        TEST_STATUS(status);
    }

    // make sure all blocks up to kept headers are reused
    i = low_seq;
    while (--i) {
        status = fdb_set_kv(db, key, strlen(key) + 1, val, strlen(val) + 1);
        TEST_STATUS(status);
    }

    status = fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);
    TEST_STATUS(status);

    // -101 commit fail
    status = fdb_snapshot_open(db, &snap_db, low_seq);
    TEST_CHK(status == FDB_RESULT_NO_DB_INSTANCE);

    // -100 commit pass
    low_seq++;
    status = fdb_snapshot_open(db, &snap_db, low_seq);
    TEST_STATUS(status);

    status = fdb_get_kv(db, keybuf, strlen(keybuf), &rvalue, &rvalue_len);
    TEST_STATUS(status);

    // cleanup
    status = fdb_free_block(rvalue);
    TEST_STATUS(status);
    status = fdb_kvs_close(snap_db);
    TEST_STATUS(status);
    status = fdb_close(dbfile);
    TEST_STATUS(status);
    status = fdb_shutdown();
    TEST_STATUS(status);

    memleak_end();
    TEST_RESULT("verify high num keeping headers param test");
}

void snapshot_before_block_reuse_test(bool inmem) {
    memleak_start();
    TEST_INIT();

    int i, j, n, r;
    void *rvalue;
    size_t rvalue_len;
    char bodybuf[256];
    fdb_file_handle* dbfile;
    fdb_kvs_handle *db, *snap_db;
    fdb_status status;
    fdb_config fconfig = fdb_get_default_config();
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    sb_decision_t sb_decision;
    fdb_file_info file_info;

    r = system(SHELL_DEL" staleblktest* > errorlog.txt");
    (void)r;

    fconfig.num_keeping_headers = 1;
    status = fdb_open(&dbfile, "./staleblktest1", &fconfig);
    TEST_STATUS(status);
    status = fdb_kvs_open_default(dbfile, &db, &kvs_config);
    TEST_STATUS(status);

    const char *key = "key";
    const char *val = "snp";

    // set key
    status = fdb_set_kv(db, key, strlen(key) + 1, val, strlen(val) + 1);
    TEST_STATUS(status);

    // commit
    status = fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);
    TEST_STATUS(status);

    // open snapshot
    if (inmem) {
        status = fdb_snapshot_open(db, &snap_db, FDB_SNAPSHOT_INMEM);
        TEST_STATUS(status);
    } else {
        status = fdb_snapshot_open(db, &snap_db, 1);
        TEST_STATUS(status);
    }

    val = "val";

    // initial load to reuse
    i = 0;
    do {
        status = fdb_set_kv(db, key, strlen(key) + 1, val, strlen(val) + 1);
        TEST_STATUS(status);
        i++;
        status = fdb_get_file_info(dbfile, &file_info);
        TEST_STATUS(status);
    } while (file_info.file_size <= SB_MIN_BLOCK_REUSING_FILESIZE);

    // 5 update cycles of created items
    for (n = 0; n < 5; n++) {
        for(j = 0; j < i; j++) {
            status = fdb_set_kv(db, key, strlen(key) + 1, val, strlen(val) + 1);
            TEST_STATUS(status);
        }
        // commit
        status = fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);
        TEST_STATUS(status);
    }

    // verify in reclaim mode
    sb_decision = sb_check_block_reusing(db);
    TEST_CHK(sb_decision == SBD_RECLAIM);

    // expect pre-reuse data retained
    status = fdb_get_kv(snap_db, key, strlen(key) + 1, &rvalue, &rvalue_len);
    TEST_STATUS(status);
    TEST_CMP(rvalue, (char *)"snp", rvalue_len);

    // close snapshot
    status = fdb_kvs_close(snap_db);
    TEST_STATUS(status);

    // do another update cycle
    for (j = 0; j < i; j++) {
        // commit
        status = fdb_set_kv(db, key, strlen(key) + 1, val, strlen(val) + 1);
        TEST_STATUS(status);
    }
    status = fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);
    TEST_STATUS(status);

    // attempt to open again will fail
    status = fdb_snapshot_open(db, &snap_db, 1);
    if (status == FDB_RESULT_SUCCESS) {
        // close incase kv was unexpectedly opened
        status = fdb_kvs_close(snap_db);
        TEST_STATUS(status);
    }
    TEST_CHK(status == FDB_RESULT_NO_DB_INSTANCE);

    status = fdb_free_block(rvalue);
    TEST_STATUS(status);
    status = fdb_kvs_close(db);
    TEST_STATUS(status);
    status = fdb_close(dbfile);
    TEST_STATUS(status);
    fdb_shutdown();

    memleak_end();

    sprintf(bodybuf,"snapshot before block reuse test %s", inmem ?
            "in-mem snapshot" : "disk snapshot");
    TEST_RESULT(bodybuf);
}

void snapshot_after_block_reuse_test() {
    memleak_start();
    TEST_INIT();

    int i, r;
    int low_seq = 0;
    int nheaders=5;
    char keybuf[16];

    fdb_file_handle* dbfile;
    fdb_kvs_handle* db;
    fdb_kvs_handle* snap_db;
    fdb_status status;
    fdb_config fconfig = fdb_get_default_config();
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    fdb_file_info file_info;

    r = system(SHELL_DEL" staleblktest* > errorlog.txt");
    (void)r;

    // init
    fconfig.compaction_threshold = 0;
    fconfig.num_keeping_headers = nheaders;
    status = fdb_open(&dbfile, "./staleblktest1", &fconfig);
    TEST_STATUS(status);
    status = fdb_kvs_open(dbfile, &db, "num_keep", &kvs_config);
    TEST_STATUS(status);

    const char *key = "key";
    const char *val = "val";

    // load until exceeding SB_MIN_BLOCK_REUSING_FILESIZE
    i = 0;
    do {
        status = fdb_set_kv(db, key, strlen(key) + 1, val, strlen(val) + 1);
        TEST_STATUS(status);
        i++;
        status = fdb_get_file_info(dbfile, &file_info);
        TEST_STATUS(status);
    } while (file_info.file_size <= SB_MIN_BLOCK_REUSING_FILESIZE);

    // create lowest commit
    status = fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);
    TEST_STATUS(status);
    low_seq = i;

    // create nheaders
    for (i = 0; i < nheaders + 5; ++i) {
        sprintf(keybuf, "key%d", i);
        status = fdb_set_kv(db, keybuf, strlen(keybuf), (char *)"reu", 4);
        TEST_STATUS(status);
        status = fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);
        TEST_STATUS(status);
    }

    // make sure all blocks up to kept headers are reused
    i = low_seq;
    while (--i) {
        status = fdb_set_kv(db, key, strlen(key) + 1, val, strlen(val) + 1);
        TEST_STATUS(status);
    }
    status = fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);
    TEST_STATUS(status);

    // open snapshot on lowest seqno available
    low_seq += 6;
    status = fdb_snapshot_open(db, &snap_db, low_seq);
    TEST_STATUS(status);
    status = fdb_kvs_close(snap_db);
    TEST_STATUS(status);

    // open snapshot using seqno already reclaimed
    status = fdb_snapshot_open(db, &snap_db, low_seq-1);
    TEST_CHK(status != FDB_RESULT_SUCCESS);

    status = fdb_kvs_close(db);
    TEST_STATUS(status);
    status = fdb_close(dbfile);
    TEST_STATUS(status);
    fdb_shutdown();

    memleak_end();
    TEST_RESULT("snapshot after block reuse test");
}

void snapshot_inmem_before_block_reuse_test() {
    memleak_start();
    TEST_INIT();

    int i, j, n, r;
    void *rvalue;
    size_t rvalue_len;
    fdb_file_handle* dbfile;
    fdb_kvs_handle *db, *snap_db;
    fdb_status status;
    fdb_config fconfig = fdb_get_default_config();
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    sb_decision_t sb_decision;
    fdb_file_info file_info;

    r = system(SHELL_DEL" staleblktest* > errorlog.txt");
    (void)r;

    fconfig.num_keeping_headers = 1;
    status = fdb_open(&dbfile, "./staleblktest1", &fconfig);
    TEST_STATUS(status);
    status = fdb_kvs_open_default(dbfile, &db, &kvs_config);
    TEST_STATUS(status);

    const char* key = "key";
    const char* val = "snp";

    // set key
    status = fdb_set_kv(db, key, strlen(key) + 1, val, strlen(val) + 1);
    TEST_STATUS(status);

    // commit
    status = fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);
    TEST_STATUS(status);

    // open snapshot
    status = fdb_snapshot_open(db, &snap_db, FDB_SNAPSHOT_INMEM);
    TEST_STATUS(status);

    val = "val";

    // initial load to reuse
    i = 0;
    do {
        status = fdb_set_kv(db, key, strlen(key) + 1, val, strlen(val) + 1);
        TEST_STATUS(status);
        i++;
        status = fdb_get_file_info(dbfile, &file_info);
        TEST_STATUS(status);
    } while (file_info.file_size <= SB_MIN_BLOCK_REUSING_FILESIZE);

    // 5 update cycles of created items
    for (n = 0; n < 5; n++) {
        for (j = 0; j < i; j++) {
            status = fdb_set_kv(db, key, strlen(key) + 1, val, strlen(val) + 1);
            TEST_STATUS(status);
        }
        // commit
        status = fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);
        TEST_STATUS(status);
    }

    // verify in reclaim mode
    sb_decision = sb_check_block_reusing(db);
    TEST_CHK(sb_decision == SBD_RECLAIM);

    // expect pre-reuse data retained
    status = fdb_get_kv(snap_db, key, strlen(key) + 1, &rvalue, &rvalue_len);
    TEST_STATUS(status);
    TEST_CMP(rvalue, (char *)"snp", rvalue_len);

    // close snapshot
    status = fdb_kvs_close(snap_db);
    TEST_STATUS(status);

    // do another update cycle
    for (j = 0; j < i; j++) {
        // commit
        status = fdb_set_kv(db, key, strlen(key) + 1, val, strlen(val) + 1);
        TEST_STATUS(status);
    }
    status = fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);
    TEST_STATUS(status);

    // attempt to open again will fail
    status = fdb_snapshot_open(db, &snap_db, 1);
    if (status == FDB_RESULT_SUCCESS) {
        // close incase kv was unexpectedly opened
        status = fdb_kvs_close(snap_db);
        TEST_STATUS(status);
    }
    TEST_CHK(status == FDB_RESULT_NO_DB_INSTANCE);

    status = fdb_free_block(rvalue);
    TEST_STATUS(status);
    status = fdb_kvs_close(db);
    TEST_STATUS(status);
    status = fdb_close(dbfile);
    TEST_STATUS(status);
    fdb_shutdown();

    memleak_end();
    TEST_RESULT("snapshot inmem before block reuse test");
}

void variable_value_size_test() {
    TEST_INIT();
    memleak_start();

    uint64_t i;
    int j, n, r;
    const int ndocs = 3;
    int blen;
    char keybuf[256];
    char *bodybuf = new char[1024 * 5120];
    void *rvalue;
    size_t rvalue_len;
    fdb_status status;
    fdb_file_handle *dbfile;
    fdb_kvs_handle *db;
    fdb_kvs_handle *snap_db, *snap_db2;
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    sb_decision_t sb_decision;
    fdb_file_info file_info;

    fdb_config fconfig = fdb_get_default_config();
    fconfig.compaction_threshold = 0;
    fconfig.block_reusing_threshold = 65;

    // remove previous staleblktest files
    r = system(SHELL_DEL" staleblktest* > errorlog.txt");
    (void)r;

    fdb_open(&dbfile, "./staleblktest1", &fconfig);
    fdb_kvs_open_default(dbfile, &db, &kvs_config);

    // load with doc sizes 512, 1024, 1536
    n = 0;
    for (i = 0; i < fconfig.num_keeping_headers + 1; i++) {
        for (j = 1; j <= ndocs; j++) {
            blen = j * 512;
            sprintf(keybuf, "%d_key", blen);
            fillstr(bodybuf, 'a', blen);    // Max blen allowed: 1024*5120
            status = fdb_set_kv(db, keybuf, strlen(keybuf) + 1,
                                bodybuf, strlen(bodybuf) + 1);
            TEST_STATUS(status);
            n++;
        }
        status = fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);
        TEST_STATUS(status);
    }

    // open disk snapshot
    status = fdb_snapshot_open(db, &snap_db, n);
    TEST_STATUS(status);

    // update docs with sizes 1024, 2048, 3072
    i = 0;
    do {
        for (j = 1;j <= ndocs; j++) {
            blen = j * 1024;
            sprintf(keybuf, "%d_key", blen);
            fillstr(bodybuf, 'b', blen);
            status = fdb_set_kv(db, keybuf, strlen(keybuf) + 1,
                                bodybuf, strlen(bodybuf) + 1);
            TEST_STATUS(status);
        }
        i++;
        status = fdb_get_file_info(dbfile, &file_info);
        TEST_STATUS(status);
    } while (file_info.file_size < SB_MIN_BLOCK_REUSING_FILESIZE);

    sb_decision = sb_check_block_reusing(db);
    TEST_CHK(sb_decision == SBD_RECLAIM);

    status = fdb_commit(dbfile, FDB_COMMIT_NORMAL);
    TEST_STATUS(status);

    // create in mem snapshot
    status = fdb_snapshot_open(db, &snap_db2, FDB_SNAPSHOT_INMEM);
    TEST_STATUS(status);

    // update cycle with small values
    while (--i) {
        blen = i * 8;
        sprintf(keybuf, "%d_key", blen);
        fillstr(bodybuf, 'c', blen);
        status = fdb_set_kv(db, keybuf, strlen(keybuf) + 1,
                            bodybuf, strlen(bodybuf) + 1);
        TEST_STATUS(status);
        if ((i % 10) == 0) {
            status = fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);
            TEST_STATUS(status);
        }
    }
    status = fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);
    TEST_STATUS(status);

    // write very large value
    sprintf(keybuf, "%d_key", 512);
    fillstr(bodybuf, 'a', 1024 * 5120);
    status = fdb_set_kv(db, keybuf, strlen(keybuf) + 1,
                        bodybuf, strlen(bodybuf) + 1);
    TEST_STATUS(status);
    status = fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);
    TEST_STATUS(status);

    // verify disk snapshot
    blen = 512;
    sprintf(keybuf, "%d_key", blen);
    fillstr(bodybuf, 'a', blen);
    status = fdb_get_kv(snap_db, keybuf, strlen(keybuf) + 1,
                        &rvalue, &rvalue_len);
    TEST_STATUS(status);
    TEST_CMP(bodybuf, rvalue, rvalue_len);
    status = fdb_free_block(rvalue);
    TEST_STATUS(status);

    // verify in mem snapshot
    blen = 2048;
    sprintf(keybuf, "%d_key", blen);
    fillstr(bodybuf, 'b', blen);
    status = fdb_get_kv(snap_db2, keybuf, strlen(keybuf) + 1,
                        &rvalue, &rvalue_len);
    TEST_STATUS(status);
    TEST_CMP(bodybuf, rvalue, rvalue_len);
    status = fdb_free_block(rvalue);
    TEST_STATUS(status);

    delete[] bodybuf;

    // cleanup
    status = fdb_kvs_close(db);
    TEST_STATUS(status);
    status = fdb_kvs_close(snap_db);
    TEST_STATUS(status);
    status = fdb_kvs_close(snap_db2);
    TEST_STATUS(status);
    status = fdb_close(dbfile);
    TEST_STATUS(status);
    fdb_shutdown();

    memleak_end();
    TEST_RESULT("variable value size test");
}

void rollback_with_num_keeping_headers() {
    TEST_INIT();
    memleak_start();

    int i, n, r;
    char keybuf[256];
    char bodybuf[1024];
    fdb_status status;
    fdb_file_handle *dbfile;
    fdb_kvs_handle *db;
    fdb_kvs_info kvs_info;
    sb_decision_t sb_decision;
    fdb_file_info file_info;

    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    fdb_config fconfig = fdb_get_default_config();
    fconfig.compaction_threshold = 0;
    fconfig.block_reusing_threshold = 65;
    fconfig.num_keeping_headers = 1;

    // remove previous staleblktest files
    r = system(SHELL_DEL" staleblktest* > errorlog.txt");
    (void)r;

    fdb_open(&dbfile, "./staleblktest1", &fconfig);
    fdb_kvs_open_default(dbfile, &db, &kvs_config);

    // create 10 headers
    for (i = 0; i < 10; i++) {
        sprintf(keybuf, "%dkey",i);
        fillstr(bodybuf, 'b', 512);
        status = fdb_set_kv(db, keybuf, strlen(keybuf),
                            bodybuf, strlen(bodybuf));
        TEST_STATUS(status);
        status = fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);
        TEST_STATUS(status);
    }

    // load until exceeding SB_MIN_BLOCK_REUSING_FILESIZE
    i = 0;
    do {
        sprintf(keybuf, "0key");
        fillstr(bodybuf, 'c', 128);
        status = fdb_set_kv(db, keybuf, strlen(keybuf),
                            bodybuf, strlen(bodybuf));
        TEST_STATUS(status);
        i++;
        status = fdb_get_file_info(dbfile, &file_info);
        TEST_STATUS(status);
    } while (file_info.file_size < SB_MIN_BLOCK_REUSING_FILESIZE);
    n = i;

    // expect block reclaim
    sb_decision = sb_check_block_reusing(db);
    TEST_CHK(sb_decision == SBD_RECLAIM);

    // reclaim old header via 11th commit
    status = fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);
    TEST_STATUS(status);

    // load unique keys to reuse old blocks
    for (i = 0; i < n; i++) {
        sprintf(keybuf, "%dkey",i);
        fillstr(bodybuf, 'd', 512);
        status = fdb_set_kv(db, keybuf, strlen(keybuf),
                            bodybuf, strlen(bodybuf));
        TEST_STATUS(status);
    }

    // do rollback to 10th headers
    status = fdb_rollback(&db, 10);
    TEST_STATUS(status);

    // expect only 10 docs
    status = fdb_get_kvs_info(db, &kvs_info);
    TEST_STATUS(status);
    TEST_CHK(kvs_info.doc_count == 10);

    // cleanup
    status = fdb_kvs_close(db);
    TEST_STATUS(status);
    status = fdb_close(dbfile);
    TEST_STATUS(status);
    fdb_shutdown();

    memleak_end();
    TEST_RESULT("rollback with num keeping headers");
}

void crash_and_recover_with_num_keeping_test() {
    TEST_INIT();
    memleak_start();

    int i, r, ndocs;
    int nheaders = 10;
    size_t last_seqno;
    char keybuf[256];
    char bodybuf[512];

    fdb_status status;
    fdb_file_handle *dbfile;
    fdb_kvs_handle *db, *snap_db;
    fdb_file_info file_info;
    fdb_kvs_info kvs_info;
    sb_decision_t sb_decision;

    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    fdb_config fconfig = fdb_get_default_config();
    fconfig.compaction_threshold = 0;
    fconfig.block_reusing_threshold = 65;
    fconfig.num_keeping_headers = nheaders;

    // remove previous staleblktest files
    r = system(SHELL_DEL" staleblktest* > errorlog.txt");
    (void)r;

    fdb_open(&dbfile, "./staleblktest1file.1", &fconfig);
    fdb_kvs_open(dbfile, &db, "./staleblktest1", &kvs_config);

    // create num_keeping_headers+1
    for (i = 0; i < nheaders + 1; i++) {
        sprintf(keybuf, "%dkey",i);
        fillstr(bodybuf, 'b', 512);
        status = fdb_set_kv(db, keybuf, strlen(keybuf),
                            bodybuf, strlen(bodybuf));
        TEST_STATUS(status);
        status = fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);
        TEST_STATUS(status);
    }

    // load until exceeding SB_MIN_BLOCK_REUSING_FILESIZE
    i = 0;
    do {
        sprintf(keybuf, "0key");
        fillstr(bodybuf, 'c', 128);
        status = fdb_set_kv(db, keybuf, strlen(keybuf),
                            bodybuf, strlen(bodybuf));
        TEST_STATUS(status);
        i++;
        status = fdb_get_file_info(dbfile, &file_info);
        TEST_STATUS(status);
    } while (file_info.file_size < SB_MIN_BLOCK_REUSING_FILESIZE);
    ndocs = i;

    // expect block reclaim
    sb_decision = sb_check_block_reusing(db);
    TEST_CHK(sb_decision == SBD_RECLAIM);

    status = fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);
    TEST_STATUS(status);
    status = fdb_get_kvs_info(db, &kvs_info);
    TEST_STATUS(status);
    last_seqno = kvs_info.last_seqnum;

    // create num_keeping_headers
    for (i = 0; i < nheaders; i++) {
        sprintf(keybuf, "%dkey",i);
        fillstr(bodybuf, 'd', 64);
        status = fdb_set_kv(db, keybuf, strlen(keybuf),
                            bodybuf, strlen(bodybuf));
        TEST_STATUS(status);
        status = fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);
        TEST_STATUS(status);
    }

    // preemptive shutdown
    status = fdb_kvs_close(db);
    TEST_STATUS(status);
    status = fdb_close(dbfile);
    TEST_STATUS(status);
    fdb_shutdown();

    // reopen
    status = fdb_open(&dbfile, "./staleblktest1file.1", &fconfig);
    TEST_STATUS(status);
    fdb_kvs_open(dbfile, &db, "./staleblktest1", &kvs_config);
    TEST_STATUS(status);

    status = fdb_get_file_info(dbfile, &file_info);
    TEST_STATUS(status);
    r = _disk_dump("./staleblktest1file.1", file_info.file_size,
                   (2 * fconfig.blocksize) + (fconfig.blocksize / 4));
    TEST_CHK(r >= 0);

    // snapshot to last keeping header
    status = fdb_snapshot_open(db, &snap_db, last_seqno);
    TEST_STATUS(status);

    // rollback to last keepheader
    status = fdb_rollback(&db, last_seqno);
    TEST_STATUS(status);

    // manual commit
    status = fdb_compact(dbfile, "./staleblktest1file.3");
    TEST_STATUS(status);

    // delete items
    for (i = 0; i < nheaders + 1; i++) {
        sprintf(keybuf, "%dkey",i);
        status = fdb_del_kv(db, keybuf, strlen(keybuf));
        TEST_STATUS(status);
        // commit
        status = fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);
        TEST_STATUS(status);
    }

    // not reusing blocks
    sb_decision = sb_check_block_reusing(db);
    TEST_CHK(sb_decision == SBD_NONE);

    // append until reuse
    for (i = 0; i < ndocs; i++) {
        sprintf(keybuf, "0key");
        fillstr(bodybuf, 'e', 512);
        status = fdb_set_kv(db, keybuf, strlen(keybuf),
                            bodybuf, strlen(bodybuf));
        TEST_STATUS(status);
    }
    sb_decision = sb_check_block_reusing(db);
    TEST_CHK(sb_decision == SBD_RECLAIM);

    status = fdb_kvs_close(snap_db);
    TEST_STATUS(status);
    status = fdb_kvs_close(db);
    TEST_STATUS(status);
    status = fdb_close(dbfile);
    TEST_STATUS(status);
    fdb_shutdown();

    memleak_end();
    TEST_RESULT("crash and recover with num keeping test");
}

void reuse_on_delete_test() {
    TEST_INIT();
    memleak_start();

    int i, r, ndocs;
    int nheaders = 10;
    char keybuf[256];
    char bodybuf[512];

    fdb_status status;
    fdb_file_handle *dbfile;
    fdb_kvs_handle *db;
    sb_decision_t sb_decision;
    fdb_file_info file_info;

    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    fdb_config fconfig = fdb_get_default_config();
    fconfig.compaction_threshold = 0;
    fconfig.block_reusing_threshold = 65;
    fconfig.num_keeping_headers = nheaders;

    // remove previous staleblktest files
    r = system(SHELL_DEL" staleblktest* > errorlog.txt");
    (void)r;

    fdb_open(&dbfile, "./staleblktest1", &fconfig);
    fdb_kvs_open_default(dbfile, &db, &kvs_config);

    // create num_keeping_headers+1
    for (i = 0; i < nheaders + 1; i++) {
        sprintf(keybuf, "%dkey",i);
        fillstr(bodybuf, 'b', 512);
        status = fdb_set_kv(db, keybuf, strlen(keybuf),
                            bodybuf, strlen(bodybuf));
        TEST_STATUS(status);
        status = fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);
        TEST_STATUS(status);
    }

    // load until exceeding SB_MIN_BLOCK_REUSING_FILESIZE
    i = 0;
    do {
        sprintf(keybuf, "%dkey",i);
        fillstr(bodybuf, 'c', 128);
        status = fdb_set_kv(db, keybuf, strlen(keybuf),
                            bodybuf, strlen(bodybuf));
        TEST_STATUS(status);
        i++;
        status = fdb_get_file_info(dbfile, &file_info);
        TEST_STATUS(status);
    } while (file_info.file_size < SB_MIN_BLOCK_REUSING_FILESIZE);
    ndocs = i;

    // expect NO REUSE
    sb_decision = sb_check_block_reusing(db);
    TEST_CHK(sb_decision == SBD_NONE);
    status = fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);
    TEST_STATUS(status);

    // delete so that file becomes stale
    for (i = 0; i < ndocs; ++i) {
        sprintf(keybuf, "%dkey",i);
        status = fdb_del_kv(db, keybuf, strlen(keybuf));
        TEST_STATUS(status);
    }

    sb_decision = sb_check_block_reusing(db);
    TEST_CHK(sb_decision == SBD_RECLAIM);

    // reload 1/4 all keys again and expect no file size growth
    // since all docs being reused
    for (i = 0; i < ndocs / 4; ++i) {
        sprintf(keybuf, "%dkey",i);
        fillstr(bodybuf, 'd', 128);
        status = fdb_set_kv(db, keybuf, strlen(keybuf),
                            bodybuf, strlen(bodybuf));
        TEST_STATUS(status);
        i++;
    }

    // expect to still be in reuse mode
    sb_decision = sb_check_block_reusing(db);
    TEST_CHK(sb_decision == SBD_RECLAIM);

    status = fdb_close(dbfile);
    TEST_STATUS(status);
    status = fdb_shutdown();
    TEST_STATUS(status);

    memleak_end();
    TEST_RESULT("reuse on delete test");
}

void fragmented_reuse_test() {
    TEST_INIT();
    memleak_start();

    int i, r, ndocs;
    int nheaders = 10;
    char keybuf[256];
    char bodybuf[512];
    size_t fpos;

    fdb_status status;
    fdb_file_handle *dbfile;
    fdb_kvs_handle *db;
    sb_decision_t sb_decision;
    fdb_file_info file_info;

    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    fdb_config fconfig = fdb_get_default_config();
    fconfig.compaction_threshold = 0;
    fconfig.block_reusing_threshold = 35;
    fconfig.num_keeping_headers = nheaders;

    // remove previous staleblktest files
    r = system(SHELL_DEL" staleblktest* > errorlog.txt");
    (void)r;

    fdb_open(&dbfile, "./staleblktest1", &fconfig);
    fdb_kvs_open_default(dbfile, &db, &kvs_config);

    // satisfy reuse constraints
    for (i = 0; i < nheaders + 1; i++) {
        sprintf(keybuf, "%dkey",i);
        fillstr(bodybuf, 'a', 512);
        status = fdb_set_kv(db, keybuf, strlen(keybuf),
                            bodybuf, strlen(bodybuf));
        TEST_STATUS(status);
        status = fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);
        TEST_STATUS(status);
    }
    i = 0;
    do {
        sprintf(keybuf, "%dkey",i);
        fillstr(bodybuf, 'b', 128);
        status = fdb_set_kv(db, keybuf, strlen(keybuf),
                            bodybuf, strlen(bodybuf));
        TEST_STATUS(status);
        i++;
        status = fdb_get_file_info(dbfile, &file_info);
        TEST_STATUS(status);
    } while (file_info.file_size < SB_MIN_BLOCK_REUSING_FILESIZE);
    ndocs = i;

    // make 25% of file stale
    for (i = 0; i < ndocs / 4; i++) {
        sprintf(keybuf, "%dkey",i);
        status = fdb_del_kv(db, keybuf, strlen(keybuf));
        TEST_STATUS(status);
    }

    // verify blocks not being reused
    sb_decision = sb_check_block_reusing(db);
    TEST_CHK(sb_decision == SBD_NONE);

    // manual compaction
    fpos = filemgr_get_pos(db->file);
    status = fdb_compact(dbfile, "staleblktest_compact");
    TEST_STATUS(status);
    TEST_CHK(fpos > filemgr_get_pos(db->file));

    // making additional 25% of file stale should NOT go into
    // block reuse.  without compaction we would be 50% stale
    for (i = ndocs / 4; i < ndocs / 2; i++) {
        sprintf(keybuf, "%dkey",i);
        status = fdb_del_kv(db, keybuf, strlen(keybuf));
        TEST_STATUS(status);
    }
    sb_decision = sb_check_block_reusing(db);
    TEST_CHK(sb_decision == SBD_NONE);

    // delete rest of docs
    for (i = ndocs / 2; i < ndocs; i++) {
        sprintf(keybuf, "%dkey",i);
        status = fdb_del_kv(db, keybuf, strlen(keybuf));
        TEST_STATUS(status);
    }

    // restore nheaders again
    for (i = 0; i < nheaders + 1; i++) {
        status = fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);
        TEST_STATUS(status);
    }

    sb_decision = sb_check_block_reusing(db);
    TEST_CHK(sb_decision != SBD_NONE);

    status = fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);
    TEST_STATUS(status);
    status = fdb_close(dbfile);
    TEST_STATUS(status);
    status = fdb_shutdown();
    TEST_STATUS(status);

    memleak_end();
    TEST_RESULT("fragmented reuse test");
}

void enter_reuse_via_separate_kvs_test() {
    TEST_INIT();
    memleak_start();

    int i, r, ndocs;
    int nheaders = 10;
    char keybuf[256];
    char bodybuf[512];

    fdb_status status;
    fdb_file_handle *dbfile;
    fdb_kvs_handle *db, *db2;
    fdb_doc *rdoc = NULL;
    fdb_iterator *iterator;
    sb_decision_t sb_decision;
    fdb_file_info file_info;

    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    fdb_config fconfig = fdb_get_default_config();
    fconfig.compaction_threshold = 0;
    fconfig.block_reusing_threshold = 35;
    fconfig.num_keeping_headers = nheaders;

    // remove previous staleblktest files
    r = system(SHELL_DEL" staleblktest* > errorlog.txt");
    (void)r;

    fdb_open(&dbfile, "./staleblktest1", &fconfig);
    fdb_kvs_open(dbfile, &db, "db", &kvs_config);
    fdb_kvs_open(dbfile, &db2, "db2", &kvs_config);

    // load docs into db and db2
    for (i = 0; i < nheaders; i++) {
        sprintf(keybuf, "%dkey",i);
        fillstr(bodybuf, 'a', 12);
        status = fdb_set_kv(db, keybuf, strlen(keybuf),
                            bodybuf, strlen(bodybuf));
        TEST_STATUS(status);
        status = fdb_set_kv(db2, keybuf, strlen(keybuf),
                            bodybuf, strlen(bodybuf));
        TEST_STATUS(status);
        status = fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);
        TEST_STATUS(status);
    }

    // enter reuse via db
    i = 0;
    do {
        sprintf(keybuf, "0key");
        fillstr(bodybuf, 'b', 128);
        status = fdb_set_kv(db, keybuf, strlen(keybuf),
                            bodybuf, strlen(bodybuf));
        TEST_STATUS(status);
        i++;
        status = fdb_get_file_info(dbfile, &file_info);
        TEST_STATUS(status);
    } while (file_info.file_size < SB_MIN_BLOCK_REUSING_FILESIZE);
    ndocs = i;

    sb_decision = sb_check_block_reusing(db);
    TEST_CHK(sb_decision == SBD_RECLAIM);

    // commit
    status = fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);
    TEST_STATUS(status);

    // reuse blocks
    for (i = 0; i < ndocs; i++) {
        sprintf(keybuf, "key%d", i);
        fillstr(bodybuf, 'c', 128);
        status = fdb_set_kv(db, keybuf, strlen(keybuf),
                            bodybuf, strlen(bodybuf));
        TEST_STATUS(status);
    }
    status = fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);
    TEST_STATUS(status);

    // check that docs from db2 not lost
    fdb_iterator_init(db2, &iterator, NULL, 0, NULL, 0, FDB_ITR_NONE);
    i = 0;
    do {
        status = fdb_iterator_get(iterator, &rdoc);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        fdb_doc_free(rdoc);
        rdoc = NULL;
        i++;
    } while (fdb_iterator_next(iterator) != FDB_RESULT_ITERATOR_FAIL);
    TEST_CHK(i==10);
    fdb_iterator_close(iterator);

    status = fdb_kvs_close(db);
    TEST_STATUS(status);
    status = fdb_kvs_close(db2);
    TEST_STATUS(status);
    status = fdb_close(dbfile);
    TEST_STATUS(status);
    fdb_shutdown();

    memleak_end();
    TEST_RESULT("enter reuse via separate kvs test");
}

void child_function() {
    int i;
    char keybuf[256];
    char bodybuf[512];
    fdb_file_handle *dbfile;
    fdb_kvs_handle *db;
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    fdb_config fconfig = fdb_get_default_config();
    fconfig.block_reusing_threshold = 65;
    fconfig.num_keeping_headers = 5;

    fdb_open(&dbfile, "./staleblktest1", &fconfig);
    fdb_kvs_open(dbfile, &db, "db", &kvs_config);

    // load docs into db and db2
    i = 0;
    while (true) {
        sprintf(keybuf, "key%d",i);
        sprintf(bodybuf, "seqno%d",i);
        fdb_set_kv(db, keybuf, strlen(keybuf), bodybuf, strlen(bodybuf));
        // create seqno every 100 updates
        if ((i % 100) == 0) {
            if ((i % 500) == 0) { // wal flush every 500 updates
                fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);
            } else {
                fdb_commit(dbfile, FDB_COMMIT_NORMAL);
            }
        }
        i++;
    }
}

#if !defined(WIN32) && !defined(_WIN32)
void superblock_recovery_test() {
    TEST_INIT();
    memleak_start();

    int r;
    uint64_t i, num_markers;
    void *rvalue;
    size_t rvalue_len;
    char keybuf[256];
    char bodybuf[256];
    pid_t child_id;

    fdb_seqnum_t seqno;
    fdb_file_handle *dbfile;
    fdb_kvs_handle *db, *snap_db;
    fdb_snapshot_info_t *markers;
    fdb_status status;
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    fdb_config fconfig = fdb_get_default_config();
    fdb_file_info file_info;

    // remove previous staleblktest files
    r = system(SHELL_DEL" staleblktest* > errorlog.txt");
    (void)r;

    status = fdb_open(&dbfile, "./staleblktest1", &fconfig);
    TEST_STATUS(status);
    status = fdb_kvs_open(dbfile, &db, "db", &kvs_config);
    TEST_STATUS(status);

    // load until exceeding SB_MIN_BLOCK_REUSING_FILESIZE
    for (i = 0; i < fconfig.num_keeping_headers + 1; i++) {
        sprintf(keybuf, "key");
        status = fdb_set_kv(db, keybuf, strlen(keybuf), NULL, 0);
        TEST_STATUS(status);
        status = fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);
        TEST_STATUS(status);
    }

    status = fdb_get_file_info(dbfile, &file_info);
    TEST_STATUS(status);

    while (file_info.file_size < SB_MIN_BLOCK_REUSING_FILESIZE) {
        sprintf(keybuf, "key");
        sprintf(bodybuf, "body%d", static_cast<int>(i));
        status = fdb_set_kv(db, keybuf, strlen(keybuf),
                            bodybuf, strlen(bodybuf));
        TEST_STATUS(status);
        status = fdb_get_file_info(dbfile, &file_info);
        TEST_STATUS(status);
    };

    TEST_CHK(sb_check_block_reusing(db) == SBD_RECLAIM);

    // close previous handle
    status = fdb_kvs_close(db);
    TEST_STATUS(status);
    status = fdb_close(dbfile);
    TEST_STATUS(status);

    // fork child
    child_id = fork();

    if (child_id == 0) {
        child_function();
    }

    // wait 3s
    sleep(3);

    // kill child
    kill(child_id, SIGUSR1);
    // reopen and recover

    status = fdb_open(&dbfile, "./staleblktest1", &fconfig);
    TEST_STATUS(status);
    status = fdb_kvs_open(dbfile, &db, "db", &kvs_config);
    TEST_STATUS(status);

    // get known key
    sprintf(keybuf, "key0");
    status = fdb_get_kv(db, keybuf, strlen(keybuf), &rvalue, &rvalue_len);
    TEST_STATUS(status);
    status = fdb_free_block(rvalue);
    TEST_STATUS(status);

    // compact upto marker
    status = fdb_get_all_snap_markers(dbfile, &markers, &num_markers);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    TEST_CHK(num_markers == fconfig.num_keeping_headers);
    status = fdb_compact_upto(dbfile, NULL, markers[4].marker);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // open snapshot on marker
    seqno = markers[4].kvs_markers->seqnum;
    status = fdb_snapshot_open(db, &snap_db, seqno);
    TEST_STATUS(status);

    status = fdb_free_snap_markers(markers, num_markers);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // get known key
    sprintf(keybuf, "key0");
    status = fdb_get_kv(snap_db, keybuf, strlen(keybuf), &rvalue, &rvalue_len);
    TEST_STATUS(status);

    // check value
    TEST_CMP(rvalue, "seqno0", rvalue_len);
    status = fdb_free_block(rvalue);
    TEST_STATUS(status);

    status = fdb_kvs_close(snap_db);
    TEST_STATUS(status);
    status = fdb_kvs_close(db);
    TEST_STATUS(status);
    status = fdb_close(dbfile);
    TEST_STATUS(status);
    fdb_shutdown();

    memleak_end();
    TEST_RESULT("superblock recovery test");
}
#endif

void reclaim_rollback_point_test() {
    memleak_start();
    TEST_INIT();

    int i, r;
    int low_seq = 0;
    int nheaders=5;
    int ndocs=30000;
    char keybuf[16];

    fdb_file_handle* dbfile;
    fdb_kvs_handle* db;
    fdb_status status;
    fdb_config fconfig = fdb_get_default_config();
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    fdb_file_info file_info;

    void *value_out;
    size_t valuelen_out;

    r = system(SHELL_DEL" staleblktest* > errorlog.txt");
    (void)r;

    // init
    fconfig.compaction_threshold = 0;
    fconfig.num_keeping_headers = nheaders;
    status = fdb_open(&dbfile, "./staleblktest1", &fconfig);
    TEST_STATUS(status);
    status = fdb_kvs_open(dbfile, &db, "db", &kvs_config);
    TEST_STATUS(status);

    const char *key = "key";
    const char *val = "val";

    // load n docs
    for (i=0; i<ndocs; ++i) {
        sprintf(keybuf, "key%d", i);
        status = fdb_set_kv(db, keybuf, strlen(keybuf), (char *)"reu", 4);
        TEST_STATUS(status);
    }
    status = fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);
    TEST_STATUS(status);
    low_seq = i;

    // load until exceeding SB_MIN_BLOCK_REUSING_FILESIZE
    i = 0;
    do {
        status = fdb_set_kv(db, key, strlen(key) + 1, val, strlen(val) + 1);
        TEST_STATUS(status);
        i++;
        status = fdb_get_file_info(dbfile, &file_info);
        TEST_STATUS(status);
    } while (file_info.file_size <= SB_MIN_BLOCK_REUSING_FILESIZE);

    status = fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);
    TEST_STATUS(status);

    // overwrite n docs
    for (i=0; i<ndocs; ++i) {
        sprintf(keybuf, "key%d", i);
        status = fdb_set_kv(db, keybuf, strlen(keybuf), (char *)"reu2", 5);
        TEST_STATUS(status);
    }
    status = fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);
    TEST_STATUS(status);

    // rollback to the first commit
    status = fdb_rollback(&db, low_seq);
    TEST_STATUS(status);

    // retrieve docs
    for (i=0; i<ndocs; ++i) {
        sprintf(keybuf, "key%d", i);
        status = fdb_get_kv(db, keybuf, strlen(keybuf), &value_out, &valuelen_out);
        TEST_STATUS(status);
        free(value_out);
    }

    // create nheaders
    for (i = 0; i < nheaders; ++i) {
        sprintf(keybuf, "key%d", i);
        status = fdb_set_kv(db, keybuf, strlen(keybuf), (char *)"reu", 4);
        TEST_STATUS(status);
        status = fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);
        TEST_STATUS(status);
    }

    // append some data & commit
    // now old blocks will be reclaimed
    for (i=0; i<ndocs; ++i) {
        status = fdb_set_kv(db, key, strlen(key) + 1, val, strlen(val) + 1);
        TEST_STATUS(status);
    }
    status = fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);
    TEST_STATUS(status);

    // append more data .. now reusable blocks are overwritten
    for (i=0; i<ndocs; ++i) {
        status = fdb_set_kv(db, key, strlen(key) + 1, val, strlen(val) + 1);
        TEST_STATUS(status);
    }
    status = fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);
    TEST_STATUS(status);

    // retrieve docs
    for (i=0; i<ndocs; ++i) {
        sprintf(keybuf, "key%d", i);
        status = fdb_get_kv(db, keybuf, strlen(keybuf), &value_out, &valuelen_out);
        TEST_STATUS(status);
        free(value_out);
    }

    status = fdb_kvs_close(db);
    TEST_STATUS(status);
    status = fdb_close(dbfile);
    TEST_STATUS(status);
    fdb_shutdown();

    memleak_end();
    TEST_RESULT("reclaim rollback point test");
}

int main() {

    /* Test resuse of stale blocks with block_reusing_threshold
       set at 0, 65, 100 */
    verify_staleblock_reuse_param_test();
    reuse_with_snapshot_test();

    /* Test reclaiming of stale blocks while varying
       num_keeping_headers */
    verify_minimum_num_keeping_headers_param_test();
    verify_high_num_keeping_headers_param_test();

    /* Test to verify in-memory and disk snapshots before
       block reuse */
    snapshot_before_block_reuse_test(false);
    snapshot_before_block_reuse_test(true);

    /* Test to verify snapshot after block reuse */
    snapshot_after_block_reuse_test();

    /* Test block reusage with keys having variable value sizes */
    variable_value_size_test();

    /* Test rollback with block reusage */
    rollback_with_num_keeping_headers();

    /* Test block resuage with deletes */
    reuse_on_delete_test();

    /* Test block reusage with manual compaction */
    fragmented_reuse_test();

    /* Test to verify reuse mode with one kvstore does not affect others */
    enter_reuse_via_separate_kvs_test();

#if !defined(WIN32) && !defined(_WIN32)
    /* Test recovery from superblock corruption */
    superblock_recovery_test();
#endif

    /* Test rollback, verify snapshot, manual compaction upon recovery
       after crash */
    crash_and_recover_with_num_keeping_test();

    reclaim_rollback_point_test();

    return 0;
}
