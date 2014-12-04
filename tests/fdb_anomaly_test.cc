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
#include "filemgr_ops.h"

void logCallbackFunc(int err_code,
                     const char *err_msg,
                     void *pCtxData) {
    fprintf(stderr, "%s - error code: %d, error message: %s\n",
            (char *) pCtxData, err_code, err_msg);
}

void write_failure_test()
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
    (void)rdoc;

    fdb_config fconfig = fdb_get_default_config();
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    fconfig.wal_threshold = 1024;
    fconfig.compaction_threshold = 0;
    fconfig.buffercache_size = 0;

    // open and close db with a create flag.
    fconfig.flags = FDB_OPEN_FLAG_CREATE;
    status = fdb_open(&dbfile, "./dummy1", &fconfig);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    TEST_CHK(!strcmp(fdb_error_msg(status), "success"));
    fdb_close(dbfile);

    // reopen db
    fdb_open(&dbfile, "./dummy1",&fconfig);
    fdb_kvs_open_default(dbfile, &db, &kvs_config);
    status = fdb_set_log_callback(db, logCallbackFunc, (void *) "write_failure_test");
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // insert documents
    i = 0;
    sprintf(keybuf, "key%d", i);
    sprintf(metabuf, "meta%d", i);
    sprintf(bodybuf, "body%d", i);
    fdb_doc_create(&doc[i], (void*)keybuf, strlen(keybuf),
            (void*)metabuf, strlen(metabuf), (void*)bodybuf, strlen(bodybuf));

    // Cause write failures..
    filemgr_anomalous_writes_set(1);
    status = fdb_set(db, doc[i]);
    TEST_CHK(status == FDB_RESULT_WRITE_FAIL);
    // Restore normal operation..
    filemgr_anomalous_writes_set(0);

    status = fdb_set(db, doc[i]);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // Cause write failures..
    filemgr_anomalous_writes_set(1);
    status = fdb_commit(dbfile, FDB_COMMIT_NORMAL);
    TEST_CHK(status == FDB_RESULT_WRITE_FAIL);

    // Restore normal operation..
    filemgr_anomalous_writes_set(0);
    status = fdb_commit(dbfile, FDB_COMMIT_NORMAL);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // close the db
    fdb_kvs_close(db);
    fdb_close(dbfile);

    // free all documents
    fdb_doc_free(doc[0]);

    // free all resources
    fdb_shutdown();

    memleak_end();

    TEST_RESULT("write failure test");
}

int main(){

    filemgr_ops_anomalous_init();
    write_failure_test();

    return 0;
}
