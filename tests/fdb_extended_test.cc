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

#define KSIZE (32)
#define MSIZE (32)
#define VSIZE (100)

static size_t num_readers(4);

void _set_random_string(char *str, int len)
{
    str[len--] = 0;
    do {
        str[len] = '!' + random('~'-'!');
    } while(len--);
}

void _set_random_string_smallabt(char *str, int len)
{
    str[len--] = 0;
    do {
        str[len] = 'a' + random('z'-'a');
    } while(len--);
}

void logCallbackFunc(int err_code,
                     const char *err_msg,
                     void *pCtxData) {
    fprintf(stderr, "%s - error code: %d, error message: %s\n",
            (char *) pCtxData, err_code, err_msg);
}

typedef enum {
    MULTI_READERS, // Normal readers
    MULTI_SNAPSHOT_READERS, // Snapshot readers
    MULTI_MIXED_READERS // Normal and snapshot readers
} multi_reader_type;

typedef enum {
    MANUAL_COMPACTION, // manual compaction
    DAEMON_COMPACTION // daemon compaction
} compaction_type;

struct reader_thread_args {
    int tid;
    size_t ndocs;
    fdb_doc **doc;
    fdb_config *config;
    int check_body;
};

struct writer_thread_args {
    int tid;
    size_t ndocs;
    fdb_doc **doc;
    size_t batch_size;
    size_t compact_period;
    fdb_config *config;
};

typedef void *(thread_func) (void *);

void setWithRandomKeys(fdb_handle *db, fdb_doc **doc, int num_docs) {
    TEST_INIT();
    fdb_status status;
    char keybuf[1024], metabuf[1024], bodybuf[1024];

    // insert documents
    for (int i = 0; i < num_docs; ++i){
        _set_random_string_smallabt(keybuf, KSIZE);
        _set_random_string_smallabt(metabuf, MSIZE);
        _set_random_string(bodybuf, VSIZE);
        status = fdb_doc_create(&doc[i], (void*)keybuf, KSIZE,
                                (void*)metabuf, MSIZE, (void*)bodybuf, VSIZE);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        fdb_set(db, doc[i]);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
    }

    // commit
    fdb_commit(db, FDB_COMMIT_NORMAL);
}

void *_reader_thread(void *voidargs)
{
    TEST_INIT();

    struct reader_thread_args *args = (struct reader_thread_args *)voidargs;
    fdb_handle *db;
    fdb_status status;
    fdb_doc *rdoc;
    fdb_config fconfig = *(args->config);

    fconfig.flags = FDB_OPEN_FLAG_RDONLY;
    status = fdb_open(&db, "./test.fdb", &fconfig);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_set_log_callback(db, logCallbackFunc,
                                  (void *) "reader_thread");
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    int num_docs = args->ndocs / 5;
    for (int j = 0; j < num_docs; ++j) {
        int i = rand() % args->ndocs;
        fdb_doc_create(&rdoc, args->doc[i]->key, args->doc[i]->keylen, NULL, 0, NULL, 0);
        status = fdb_get(db, rdoc);
        assert(status == FDB_RESULT_SUCCESS);
        if (args->check_body) {
            assert(!memcmp(rdoc->body, args->doc[i]->body, rdoc->bodylen));
        }
        fdb_doc_free(rdoc);
    }

    fdb_close(db);
    thread_exit(0);

    return NULL;
}

void *_snapshot_reader_thread(void *voidargs)
{
    TEST_INIT();

    struct reader_thread_args *args = (struct reader_thread_args *)voidargs;
    fdb_handle *db;
    fdb_handle *snap_db;
    fdb_status status;
    fdb_doc *rdoc;
    fdb_config fconfig = *(args->config);

    fconfig.flags = FDB_OPEN_FLAG_RDONLY;
    status = fdb_open(&db, "./test.fdb", &fconfig);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_set_log_callback(db, logCallbackFunc,
                                  (void *) "reader_thread");
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    status = fdb_snapshot_open(db, &snap_db, args->ndocs);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    int num_docs = args->ndocs / 5;
    for (int j = 0; j < num_docs; ++j) {
        int i = rand() % args->ndocs;
        fdb_doc_create(&rdoc, args->doc[i]->key, args->doc[i]->keylen, NULL, 0, NULL, 0);
        status = fdb_get(snap_db, rdoc);
        assert(status == FDB_RESULT_SUCCESS);
        assert(!memcmp(rdoc->body, args->doc[i]->body, rdoc->bodylen));
        fdb_doc_free(rdoc);
    }

    // create an iterator on the snapshot for a specific range
    int i = 90000;
    fdb_iterator *iterator;
    fdb_iterator_sequence_init(snap_db, &iterator, 90000, 100000, FDB_ITR_NONE);
    // repeat until fail
    while(1){
        status = fdb_iterator_next(iterator, &rdoc);
        if (status == FDB_RESULT_ITERATOR_FAIL) break;

        TEST_CHK(!memcmp(rdoc->key, args->doc[i-1]->key, rdoc->keylen));
        TEST_CHK(!memcmp(rdoc->meta, args->doc[i-1]->meta, rdoc->metalen));
        TEST_CHK(!memcmp(rdoc->body, args->doc[i-1]->body, rdoc->bodylen));

        fdb_doc_free(rdoc);
        ++i;
    }
    fdb_iterator_close(iterator);

    fdb_close(snap_db);
    fdb_close(db);
    thread_exit(0);

    return NULL;
}

void *_writer_thread(void *voidargs)
{
    TEST_INIT();

    struct writer_thread_args *args = (struct writer_thread_args *)voidargs;
    fdb_handle *db;
    fdb_status status;
    fdb_doc *rdoc;
    fdb_config fconfig = *(args->config);

    fconfig.flags = 0;
    status = fdb_open(&db, "./test.fdb", &fconfig);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_set_log_callback(db, logCallbackFunc,
                                  (void *) "writer_thread");
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    int count = 0;
    int file_name_rev = 1;
    char bodybuf[1024], temp[1024];
    int num_docs = args->ndocs / 5;
    for (int j = 0; j < num_docs; ++j) {
        int i = rand() % args->ndocs;
        _set_random_string(bodybuf, VSIZE);
        status = fdb_doc_create(&rdoc, args->doc[i]->key, args->doc[i]->keylen,
                                args->doc[i]->meta, args->doc[i]->metalen, bodybuf, VSIZE);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        status = fdb_set(db, rdoc);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        fdb_doc_free(rdoc);
        ++count;
        if (count % args->batch_size == 0) {
            status = fdb_commit(db, FDB_COMMIT_NORMAL);
            TEST_CHK(status == FDB_RESULT_SUCCESS);
        }
        if (args->config->compaction_mode == FDB_COMPACTION_MANUAL &&
            count % args->compact_period == 0) {
            sprintf(temp, "./test.fdb.%d", file_name_rev++);
            status = fdb_compact(db, temp);
            TEST_CHK(status == FDB_RESULT_SUCCESS);
        }
    }

    fdb_close(db);
    thread_exit(0);

    return NULL;
}

void test_multi_readers(multi_reader_type reader_type,
                        const char *test_name) {
    TEST_INIT();
    memleak_start();

    int r;
    int num_docs = 100000;
    fdb_handle *db;
    fdb_status status;

    // remove previous dummy files
    r = system(SHELL_DEL" test.fdb* > errorlog.txt");

    fdb_config fconfig = fdb_get_default_config();
    status = fdb_open(&db, "./test.fdb", &fconfig);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    fdb_doc **doc = alca(fdb_doc*, num_docs);
    // Load the initial documents with random keys.
    setWithRandomKeys(db, doc, num_docs);
    fdb_close(db);

    // create reader threads.
    thread_t *tid = alca(thread_t, num_readers);
    void **thread_ret = alca(void *, num_readers);
    struct reader_thread_args *args = alca(struct reader_thread_args, num_readers);
    for (int i = 0; i < num_readers; ++i){
        args[i].tid = i;
        args[i].ndocs = num_docs;
        args[i].doc = doc;
        args[i].config = &fconfig;
        args[i].check_body = 1;
        if (reader_type == MULTI_READERS) {
            thread_create(&tid[i], _reader_thread, &args[i]);
        } else if (reader_type == MULTI_SNAPSHOT_READERS) {
            thread_create(&tid[i], _snapshot_reader_thread, &args[i]);
        } else { // mixed
            if (i % 2) {
                thread_create(&tid[i], _reader_thread, &args[i]);
            } else {
                thread_create(&tid[i], _snapshot_reader_thread, &args[i]);
            }
        }
    }

    // wait for thread termination
    for (int i = 0; i < num_readers; ++i){
        thread_join(tid[i], &thread_ret[i]);
    }

    // free all documents
    for (int i = 0 ; i < num_docs; ++i){
        fdb_doc_free(doc[i]);
    }

    // shutdown
    fdb_shutdown();

    memleak_end();
    TEST_RESULT(test_name);
}

void test_writer_multi_readers(multi_reader_type reader_type,
                               compaction_type comp_type,
                               const char *test_name) {
    TEST_INIT();
    memleak_start();

    int r;
    int num_docs = 100000;
    fdb_handle *db;
    fdb_status status;

    // remove previous dummy files
    r = system(SHELL_DEL" test.fdb* > errorlog.txt");

    fdb_config fconfig = fdb_get_default_config();
    if (comp_type == DAEMON_COMPACTION) {
        fconfig.compaction_mode = FDB_COMPACTION_AUTO;
        fconfig.compaction_threshold = 10;
        fconfig.compactor_sleep_duration = 5;
    }

    status = fdb_open(&db, "./test.fdb", &fconfig);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    fdb_doc **doc = alca(fdb_doc*, num_docs);
    // Load the initial documents with random keys.
    setWithRandomKeys(db, doc, num_docs);
    fdb_close(db);

    // create one writer thread and multiple reader threads.
    thread_t *tid = alca(thread_t, num_readers + 1);
    void **thread_ret = alca(void *, num_readers + 1);
    struct reader_thread_args *args = alca(struct reader_thread_args, num_readers);
    int i = 0;
    for (; i < num_readers; ++i){
        args[i].tid = i;
        args[i].ndocs = num_docs;
        args[i].doc = doc;
        args[i].config = &fconfig;
        if (reader_type == MULTI_READERS) {
            args[i].check_body = 0;
            thread_create(&tid[i], _reader_thread, &args[i]);
        } else if (reader_type == MULTI_SNAPSHOT_READERS) {
            args[i].check_body = 1;
            thread_create(&tid[i], _snapshot_reader_thread, &args[i]);
        } else { // mixed
            if (i % 2) {
                args[i].check_body = 0;
                thread_create(&tid[i], _reader_thread, &args[i]);
            } else {
                args[i].check_body = 1;
                thread_create(&tid[i], _snapshot_reader_thread, &args[i]);
            }
        }
    }

    struct writer_thread_args wargs;
    wargs.tid = i;
    wargs.ndocs = num_docs;
    wargs.doc = doc;
    wargs.config = &fconfig;
    wargs.batch_size = 100; // Do commit every 100 updates
    wargs.compact_period = 10000; // Do compaction every 10000 updates
    thread_create(&tid[i], _writer_thread, &wargs);

    // wait for thread termination
    for (int i = 0; i < (num_readers + 1); ++i) {
        thread_join(tid[i], &thread_ret[i]);
    }

    // free all documents
    for (int i = 0 ; i < num_docs; ++i) {
        fdb_doc_free(doc[i]);
    }

    // shutdown
    fdb_shutdown();

    memleak_end();
    TEST_RESULT(test_name);
}

int main() {
    // Read-only with multiple readers.
    test_multi_readers(MULTI_READERS, "test multi readers");
    test_multi_readers(MULTI_SNAPSHOT_READERS, "test multi snapshot readers");
    test_multi_readers(MULTI_MIXED_READERS, "test multi mixed readers");

    // Execute a writer with a manual compaction and multiple readers together.
    test_writer_multi_readers(MULTI_READERS, MANUAL_COMPACTION,
                              "test a single writer and multi readers");
    test_writer_multi_readers(MULTI_SNAPSHOT_READERS, MANUAL_COMPACTION,
                              "test a single writer and multi snapshot readers");
    test_writer_multi_readers(MULTI_MIXED_READERS, MANUAL_COMPACTION,
                              "test a single writer and multi mixed readers");

    // Execute a writer, a compaction daemon, and multiple readers together.
    test_writer_multi_readers(MULTI_READERS, DAEMON_COMPACTION,
                              "test a single writer, a compaction daemon, "
                              "and multi readers");
    test_writer_multi_readers(MULTI_SNAPSHOT_READERS, DAEMON_COMPACTION,
                              "test a single writer, a compaction daemon, "
                              "and multi snapshot readers");
    test_writer_multi_readers(MULTI_MIXED_READERS, DAEMON_COMPACTION,
                              "test a single writer, a compaction daemon, "
                              "and multi mixed readers");

    return 0;
}
