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
#include "functional_util.h"

#define KSIZE (32)
#define MSIZE (32)
#define VSIZE (100)

#include <vector>

#define FDB_ENCRYPTION_BOGUS (-1)

static size_t num_readers(2);
static const char *test_filename;

static mutex_t rollback_mutex;
static volatile bool rollback_done(false);

typedef enum {
    REGULAR_WRITER,
    TRANSACTIONAL_WRITER
} writer_type;

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
    std::vector<fdb_doc *> *docs;
    fdb_config *config;
    fdb_kvs_config *kvs_config;
    int check_body;
};

struct writer_thread_args {
    writer_type wtype;
    int tid;
    size_t ndocs;
    std::vector<fdb_doc *> *docs;
    size_t batch_size;
    size_t compact_period;
    fdb_config *config;
    fdb_kvs_config *kvs_config;
};

struct compactor_thread_args {
    int tid;
    fdb_config *config;
    fdb_kvs_config *kvs_config;
};

typedef void *(thread_func) (void *);

static fdb_encryption_algorithm_t cur_encryption;

static fdb_config getDefaultConfig(void) {
    fdb_config c = fdb_get_default_config();
    c.seqtree_opt = FDB_SEQTREE_USE; // enable seqtree for get_byseq
    c.encryption_key.algorithm = cur_encryption;
    _set_random_string((char*)c.encryption_key.bytes, sizeof(c.encryption_key.bytes));
    return c;
}

static void loadDocsWithRandomKeys(fdb_file_handle *dbfile,
                                   fdb_kvs_handle *db,
                                   std::vector<fdb_doc *> *docs,
                                   int num_docs) {
    TEST_INIT();
    fdb_status status;
    char keybuf[256], metabuf[256], bodybuf[256];

    // insert documents
    for (int i = 0; i < num_docs; ++i){
        _set_random_string_smallabt(keybuf, KSIZE);
        _set_random_string_smallabt(metabuf, MSIZE);
        _set_random_string(bodybuf, VSIZE);
        status = fdb_doc_create(&((*docs)[i]),
                                (void*)keybuf, KSIZE,
                                (void*)metabuf, MSIZE,
                                (void*)bodybuf, VSIZE);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        fdb_set(db, docs->at(i));
        TEST_CHK(status == FDB_RESULT_SUCCESS);
    }

    // commit
    fdb_commit(dbfile, FDB_COMMIT_NORMAL);
}

static void updateDocsWithRandomKeys(fdb_file_handle *dbfile,
                                     fdb_kvs_handle *db,
                                     std::vector<fdb_doc *> *docs,
                                     int start_doc,
                                     int end_doc) {
    TEST_INIT();
    fdb_status status;
    char metabuf[256], bodybuf[256];

    // insert documents
    for (int i = start_doc; i < end_doc; ++i) {
        _set_random_string_smallabt(metabuf, MSIZE);
        _set_random_string(bodybuf, VSIZE);
        status = fdb_doc_update(&((*docs)[i]),
                                (void*)metabuf, MSIZE,
                                (void*)bodybuf, VSIZE);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        fdb_set(db, docs->at(i));
        TEST_CHK(status == FDB_RESULT_SUCCESS);
    }

    // commit
    fdb_commit(dbfile, FDB_COMMIT_NORMAL);
}

static void *_reader_thread(void *voidargs)
{
    TEST_INIT();

    struct reader_thread_args *args = (struct reader_thread_args *)voidargs;
    fdb_file_handle *dbfile;
    fdb_kvs_handle *db;
    fdb_status status;
    fdb_doc *rdoc = NULL;
    fdb_config fconfig = *(args->config);
    fdb_kvs_config kvs_config = *(args->kvs_config);

    fconfig.flags = FDB_OPEN_FLAG_RDONLY;
    status = fdb_open(&dbfile, test_filename, &fconfig);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_kvs_open_default(dbfile, &db, &kvs_config);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_set_log_callback(db, logCallbackFunc,
                                  (void *) "reader_thread");
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    int num_docs = args->ndocs / 5;
    for (int j = 0; j < num_docs; ++j) {
        int i = rand() % args->ndocs;
        fdb_doc_create(&rdoc, args->docs->at(i)->key,
                       args->docs->at(i)->keylen, NULL, 0, NULL, 0);
        status = fdb_get(db, rdoc);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        if (args->check_body) {
            TEST_CHK(!memcmp(rdoc->body, args->docs->at(i)->body, rdoc->bodylen));
        }
        fdb_doc_free(rdoc);
        rdoc = NULL;
    }

    fdb_close(dbfile);
    thread_exit(0);

    return NULL;
}

static void *_rollback_reader_thread(void *voidargs)
{
    TEST_INIT();

    struct reader_thread_args *args = (struct reader_thread_args *)voidargs;
    fdb_file_handle *dbfile;
    fdb_kvs_handle *db;
    fdb_status status;
    fdb_doc *rdoc = NULL;
    fdb_config fconfig = *(args->config);
    fdb_kvs_config kvs_config = *(args->kvs_config);

    fconfig.flags = FDB_OPEN_FLAG_RDONLY;
    status = fdb_open(&dbfile, test_filename, &fconfig);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_kvs_open_default(dbfile, &db, &kvs_config);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_set_log_callback(db, logCallbackFunc,
                                  (void *) "reader_thread");
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    int num_docs = args->ndocs / 5;
    for (int j = 0; j < num_docs; ++j) {
        int i = rand() % args->ndocs;
        fdb_doc_create(&rdoc, args->docs->at(i)->key,
                       args->docs->at(i)->keylen, NULL, 0, NULL, 0);
        mutex_lock(&rollback_mutex);
        status = fdb_get(db, rdoc);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        if (i < 50000) {
            TEST_CHK(rdoc->seqnum == args->docs->at(i)->seqnum);
            TEST_CHK(!memcmp(rdoc->body, args->docs->at(i)->body, rdoc->bodylen));
        } else {
            if (rollback_done) {
                TEST_CHK(rdoc->seqnum != args->docs->at(i)->seqnum);
            } else {
                TEST_CHK(rdoc->seqnum == args->docs->at(i)->seqnum);
                TEST_CHK(!memcmp(rdoc->body, args->docs->at(i)->body, rdoc->bodylen));
            }
        }
        mutex_unlock(&rollback_mutex);
        fdb_doc_free(rdoc);
        rdoc = NULL;
    }

    fdb_kvs_close(db);
    fdb_close(dbfile);
    thread_exit(0);

    return NULL;
}

static void *_snapshot_reader_thread(void *voidargs)
{
    TEST_INIT();

    struct reader_thread_args *args = (struct reader_thread_args *)voidargs;
    fdb_file_handle *dbfile;
    fdb_kvs_handle *db;
    fdb_kvs_handle *snap_db;
    fdb_status status;
    fdb_doc *rdoc = NULL;
    fdb_config fconfig = *(args->config);
    fdb_kvs_config kvs_config = *(args->kvs_config);

    fconfig.flags = FDB_OPEN_FLAG_RDONLY;
    status = fdb_open(&dbfile, test_filename, &fconfig);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_kvs_open_default(dbfile, &db, &kvs_config);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_set_log_callback(db, logCallbackFunc,
                                  (void *) "snapshot_reader_thread");
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    status = fdb_snapshot_open(db, &snap_db, args->ndocs);
    TEST_CHK(status == FDB_RESULT_SUCCESS || status == FDB_RESULT_NO_DB_INSTANCE);
    if (status == FDB_RESULT_NO_DB_INSTANCE) {
        fdb_kvs_close(db);
        fdb_close(dbfile);
        thread_exit(0);
        return NULL;
    }

    int num_docs = args->ndocs / 5;
    for (int j = 0; j < num_docs; ++j) {
        int i = rand() % args->ndocs;
        fdb_doc_create(&rdoc, args->docs->at(i)->key,
                       args->docs->at(i)->keylen, NULL, 0, NULL, 0);
        status = fdb_get(snap_db, rdoc);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        TEST_CHK(!memcmp(rdoc->body, args->docs->at(i)->body, rdoc->bodylen));
        fdb_doc_free(rdoc);
        rdoc = NULL;
    }

    // create an iterator on the snapshot for a specific range
    int i = 90000;
    fdb_iterator *iterator;
    fdb_iterator_sequence_init(snap_db, &iterator, 90000, 100000, FDB_ITR_NONE);
    // repeat until fail
    do {
        status = fdb_iterator_get(iterator, &rdoc);
        TEST_CHK(status == FDB_RESULT_SUCCESS);

        TEST_CHK(!memcmp(rdoc->key, args->docs->at(i-1)->key, rdoc->keylen));
        TEST_CHK(!memcmp(rdoc->meta, args->docs->at(i-1)->meta, rdoc->metalen));
        TEST_CHK(!memcmp(rdoc->body, args->docs->at(i-1)->body, rdoc->bodylen));

        fdb_doc_free(rdoc);
        rdoc = NULL;
        ++i;
    } while (fdb_iterator_next(iterator) == FDB_RESULT_SUCCESS);
    fdb_iterator_close(iterator);

    fdb_kvs_close(snap_db);
    fdb_kvs_close(db);
    fdb_close(dbfile);
    thread_exit(0);

    return NULL;
}

static void *_rollback_snapshot_reader_thread(void *voidargs)
{
    TEST_INIT();

    struct reader_thread_args *args = (struct reader_thread_args *)voidargs;
    fdb_file_handle *dbfile;
    fdb_kvs_handle *db;
    fdb_kvs_handle *snap_db;
    fdb_status status;
    fdb_doc *rdoc = NULL;
    fdb_config fconfig = *(args->config);
    fdb_kvs_config kvs_config = *(args->kvs_config);

    fconfig.flags = FDB_OPEN_FLAG_RDONLY;
    status = fdb_open(&dbfile, test_filename, &fconfig);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_kvs_open_default(dbfile, &db, &kvs_config);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_set_log_callback(db, logCallbackFunc,
                                  (void *) "rollback_reader_thread");
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    while (1) {
        mutex_lock(&rollback_mutex);
        if (rollback_done) {
            mutex_unlock(&rollback_mutex);
            break;
        }
        mutex_unlock(&rollback_mutex);
        sleep(1);
    }

    status = fdb_snapshot_open(db, &snap_db, 200000);
    TEST_CHK(status == FDB_RESULT_NO_DB_INSTANCE);
    status = fdb_snapshot_open(db, &snap_db, 150000);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    int num_docs = args->ndocs / 5;
    for (int j = 0; j < num_docs; ++j) {
        int i = rand() % args->ndocs;
        fdb_doc_create(&rdoc, args->docs->at(i)->key,
                       args->docs->at(i)->keylen, NULL, 0, NULL, 0);
        status = fdb_get(snap_db, rdoc);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        if (i < 50000) {
            TEST_CHK(rdoc->seqnum == args->docs->at(i)->seqnum);
            TEST_CHK(!memcmp(rdoc->body, args->docs->at(i)->body, rdoc->bodylen));
        } else {
            TEST_CHK(rdoc->seqnum != args->docs->at(i)->seqnum);
        }
        fdb_doc_free(rdoc);
        rdoc = NULL;
    }

    // create an iterator on the snapshot for a sepcfic range
    int i = 40000;
    fdb_iterator *iterator;
    fdb_iterator_sequence_init(snap_db, &iterator, 140000, 150000, FDB_ITR_NONE);
    // repeat until fail
    do {
        status = fdb_iterator_get(iterator, &rdoc);
        TEST_CHK(status == FDB_RESULT_SUCCESS);

        TEST_CHK(!memcmp(rdoc->key, args->docs->at(i-1)->key, rdoc->keylen));
        TEST_CHK(!memcmp(rdoc->meta, args->docs->at(i-1)->meta, rdoc->metalen));
        TEST_CHK(!memcmp(rdoc->body, args->docs->at(i-1)->body, rdoc->bodylen));

        fdb_doc_free(rdoc);
        rdoc = NULL;
        ++i;
    } while (fdb_iterator_next(iterator) == FDB_RESULT_SUCCESS);
    fdb_iterator_close(iterator);

    fdb_kvs_close(snap_db);
    fdb_kvs_close(db);
    fdb_close(dbfile);
    thread_exit(0);

    return NULL;
}

static void *_writer_thread(void *voidargs)
{
    TEST_INIT();

    struct writer_thread_args *args = (struct writer_thread_args *)voidargs;
    fdb_file_handle *dbfile;
    fdb_kvs_handle *db;
    fdb_status status;
    fdb_doc *rdoc = NULL;
    fdb_config fconfig = *(args->config);
    fdb_kvs_config kvs_config = *(args->kvs_config);

    fconfig.flags = 0;
    status = fdb_open(&dbfile, test_filename, &fconfig);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_kvs_open_default(dbfile, &db, &kvs_config);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_set_log_callback(db, logCallbackFunc,
                                  (void *) "writer_thread");
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    int count = 0;
    int trans_begin = 0;
    int file_name_rev = 1;
    char bodybuf[1024], temp[1024];
    int num_docs = args->ndocs / 5;
    for (int j = 0; j < num_docs; ++j) {
        if (!trans_begin && args->wtype == TRANSACTIONAL_WRITER) {
            status = fdb_begin_transaction(dbfile, FDB_ISOLATION_READ_COMMITTED);
            TEST_CHK(status == FDB_RESULT_SUCCESS);
            trans_begin = 1;
        }

        int i = rand() % args->ndocs;
        _set_random_string(bodybuf, VSIZE);
        status = fdb_doc_create(&rdoc, args->docs->at(i)->key,
                                args->docs->at(i)->keylen,
                                args->docs->at(i)->meta,
                                args->docs->at(i)->metalen, bodybuf, VSIZE);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        status = fdb_set(db, rdoc);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        fdb_doc_free(rdoc);
        rdoc = NULL;

        ++count;
        if (count % args->batch_size == 0) {
            if (args->wtype == REGULAR_WRITER) {
                status = fdb_commit(dbfile, FDB_COMMIT_NORMAL);
                TEST_CHK(status == FDB_RESULT_SUCCESS);
            } else { // Transactional writer
                if (trans_begin) {
                    status = fdb_end_transaction(dbfile, FDB_COMMIT_NORMAL);
                    TEST_CHK(status == FDB_RESULT_SUCCESS);
                    trans_begin = 0;
                }
            }
        }
        if (args->config->compaction_mode == FDB_COMPACTION_MANUAL &&
            count % args->compact_period == 0) {
            sprintf(temp, "./test.fdb.%d", file_name_rev++);
            status = fdb_compact(dbfile, temp);
            TEST_CHK(status == FDB_RESULT_SUCCESS);
        }
    }

    fdb_kvs_close(db);
    fdb_close(dbfile);
    thread_exit(0);

    return NULL;
}

static void *_compactor_thread(void *voidargs)
{
    TEST_INIT();

    struct compactor_thread_args *args = (struct compactor_thread_args *)voidargs;
    fdb_file_handle *dbfile;
    fdb_kvs_handle *db;
    fdb_status status;
    fdb_config fconfig = *(args->config);
    fdb_kvs_config kvs_config = *(args->kvs_config);

    fconfig.flags = 0;
    status = fdb_open(&dbfile, test_filename, &fconfig);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_kvs_open_default(dbfile, &db, &kvs_config);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_set_log_callback(db, logCallbackFunc,
                                  (void *) "compactor_thread");
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    int file_name_rev = 1;
    char temp[1024];
    sprintf(temp, "./test.fdb.%d", file_name_rev++);

    status = fdb_compact(dbfile, temp);
    TEST_CHK(status == FDB_RESULT_SUCCESS ||
             status == FDB_RESULT_FAIL_BY_ROLLBACK);

    fdb_kvs_close(db);
    fdb_close(dbfile);
    thread_exit(0);

    return NULL;
}

static void test_multi_readers(multi_reader_type reader_type,
                               const char *test_name) {
    TEST_INIT();
    memleak_start();

    int r;
    int num_docs = 100000;
    fdb_file_handle *dbfile;
    fdb_kvs_handle *db;
    fdb_status status;
    size_t n_readers = num_readers;

    // remove previous extended_test files
    r = system(SHELL_DEL" test.fdb* > errorlog.txt");
    (void)r;

    fdb_config fconfig = getDefaultConfig();
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    status = fdb_open(&dbfile, test_filename, &fconfig);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_kvs_open_default(dbfile, &db, &kvs_config);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    status = fdb_set_log_callback(db, logCallbackFunc,
                                  (void *) "multi_reader_thread");
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // Create a vector of docs on the heap
    std::vector<fdb_doc *> docs(num_docs, nullptr);

    // Load the initial documents with random keys.
    loadDocsWithRandomKeys(dbfile, db, &docs, num_docs);
    fdb_kvs_close(db);
    fdb_close(dbfile);

    // create reader threads.
    thread_t *tid = alca(thread_t, n_readers);
    void **thread_ret = alca(void *, n_readers);
    struct reader_thread_args *args = alca(struct reader_thread_args, n_readers);
    for (size_t i = 0; i < n_readers; ++i){
        args[i].tid = i;
        args[i].ndocs = num_docs;
        args[i].docs = &docs;
        args[i].config = &fconfig;
        args[i].kvs_config = &kvs_config;
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
    for (size_t i = 0; i < n_readers; ++i){
        thread_join(tid[i], &thread_ret[i]);
    }

    // free all documents
    for (int i = 0 ; i < num_docs; ++i){
        fdb_doc_free(docs.at(i));
    }

    // shutdown
    fdb_shutdown();

    memleak_end();
    TEST_RESULT(test_name);
}

static void test_writer_multi_readers(writer_type wtype,
                                      multi_reader_type reader_type,
                                      compaction_type comp_type,
                                      const char *test_name) {
    TEST_INIT();
    memleak_start();

    int r;
    int num_docs = 100000;
    fdb_file_handle *dbfile;
    fdb_kvs_handle *db;
    fdb_status status;

    // remove previous extended_test files
    r = system(SHELL_DEL" test.fdb* > errorlog.txt");
    (void)r;

    fdb_config fconfig = getDefaultConfig();
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    if (comp_type == DAEMON_COMPACTION) {
        fconfig.compaction_mode = FDB_COMPACTION_AUTO;
        fconfig.compaction_threshold = 10;
        fconfig.compactor_sleep_duration = 5;
    }

    status = fdb_open(&dbfile, test_filename, &fconfig);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_kvs_open_default(dbfile, &db, &kvs_config);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    status = fdb_set_log_callback(db, logCallbackFunc,
                                  (void *) "writer_multi_reader_thread");
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // Create a vector of docs on the heap
    std::vector<fdb_doc *> docs(num_docs, nullptr);

    // Load the initial documents with random keys.
    loadDocsWithRandomKeys(dbfile, db, &docs, num_docs);
    fdb_kvs_close(db);
    fdb_close(dbfile);

    // create one writer thread and multiple reader threads.
    thread_t *tid = alca(thread_t, num_readers + 1);
    void **thread_ret = alca(void *, num_readers + 1);
    struct reader_thread_args *args = alca(struct reader_thread_args, num_readers);
    size_t i = 0;
    for (; i < num_readers; ++i){
        args[i].tid = i;
        args[i].ndocs = num_docs;
        args[i].docs = &docs;
        args[i].config = &fconfig;
        args[i].kvs_config = &kvs_config;
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
    wargs.wtype = wtype;
    wargs.tid = i;
    wargs.ndocs = num_docs;
    wargs.docs = &docs;
    wargs.config = &fconfig;
    wargs.kvs_config = &kvs_config;
    wargs.batch_size = 100; // Do commit every 100 updates
    wargs.compact_period = 10000; // Do compaction every 10000 updates
    thread_create(&tid[i], _writer_thread, &wargs);

    // wait for thread termination
    for (size_t i = 0; i < (num_readers + 1); ++i) {
        thread_join(tid[i], &thread_ret[i]);
    }

    // free all documents
    for (int i = 0 ; i < num_docs; ++i){
        fdb_doc_free(docs.at(i));
    }

    // shutdown
    fdb_shutdown();

    memleak_end();
    TEST_RESULT(test_name);
}

static void test_rollback_multi_readers(multi_reader_type reader_type,
                                        const char *test_name) {
    TEST_INIT();
    memleak_start();

    int r;
    int num_docs = 100000;
    fdb_file_handle *dbfile;
    fdb_kvs_handle *db;
    fdb_status status;
    size_t n_readers = num_readers;

    // remove previous extended_test files
    r = system(SHELL_DEL" test.fdb* > errorlog.txt");
    (void)r;

    rollback_done = false;

    fdb_config fconfig = getDefaultConfig();
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    status = fdb_open(&dbfile, test_filename, &fconfig);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_kvs_open_default(dbfile, &db, &kvs_config);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_set_log_callback(db, logCallbackFunc,
                                  (void *) "writer_multi_reader_thread");
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // Create a vector of docs on the heap
    std::vector<fdb_doc *> docs(num_docs, nullptr);

    // Load the initial documents with random keys.
    loadDocsWithRandomKeys(dbfile, db, &docs, num_docs);
    // Update the first half of documents, so that the last seq number becomes 150000.
    updateDocsWithRandomKeys(dbfile, db, &docs, 0, num_docs/2);
    // Update the rest of documents, so that the last seq number becomes 200000.
    updateDocsWithRandomKeys(dbfile, db, &docs, num_docs/2, num_docs);

    // Init the rollback mutex.
    mutex_init(&rollback_mutex);

    // create reader threads.
    thread_t *tid = alca(thread_t, n_readers);
    void **thread_ret = alca(void *, n_readers);
    struct reader_thread_args *args = alca(struct reader_thread_args,
                                           n_readers);
    for (size_t i = 0; i < n_readers; ++i){
        args[i].tid = i;
        args[i].ndocs = num_docs;
        args[i].docs = &docs;
        args[i].config = &fconfig;
        args[i].kvs_config = &kvs_config;
        args[i].check_body = 1;
        if (reader_type == MULTI_READERS) {
            thread_create(&tid[i], _rollback_reader_thread, &args[i]);
        } else if (reader_type == MULTI_SNAPSHOT_READERS) {
            thread_create(&tid[i], _rollback_snapshot_reader_thread, &args[i]);
        } else { // mixed
            if (i % 2) {
                thread_create(&tid[i], _rollback_reader_thread, &args[i]);
            } else {
                thread_create(&tid[i], _rollback_snapshot_reader_thread, &args[i]);
            }
        }
    }

    // rollback to a seq num 150000
    mutex_lock(&rollback_mutex);
    status = fdb_rollback(&db, 150000);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    rollback_done = true;
    mutex_unlock(&rollback_mutex);

    status = fdb_kvs_close(db);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_close(dbfile);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // wait for thread termination
    for (size_t i = 0; i < n_readers; ++i){
        thread_join(tid[i], &thread_ret[i]);
    }

    // free all documents
    for (int i = 0 ; i < num_docs; ++i){
        fdb_doc_free(docs.at(i));
    }
    mutex_destroy(&rollback_mutex);

    // shutdown
    fdb_shutdown();

    memleak_end();
    TEST_RESULT(test_name);
}

static void test_rollback_compaction(const char *test_name) {
    TEST_INIT();
    memleak_start();

    int r;
    int num_docs = 100000;
    fdb_file_handle *dbfile;
    fdb_kvs_handle *db;
    fdb_status status;

    // remove previous extended_test files
    r = system(SHELL_DEL" test.fdb* > errorlog.txt");
    (void)r;

    rollback_done = false;

    fdb_config fconfig = getDefaultConfig();
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    status = fdb_open(&dbfile, test_filename, &fconfig);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_kvs_open_default(dbfile, &db, &kvs_config);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    status = fdb_set_log_callback(db, logCallbackFunc,
                                  (void *) "rollback_compactor_thread");
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // Create a vector of docs on the heap
    std::vector<fdb_doc *> docs(num_docs, nullptr);

    // Load the initial documents with random keys.
    loadDocsWithRandomKeys(dbfile, db, &docs, num_docs);
    // Update the first half of documents, so that the last seq number becomes 150000.
    updateDocsWithRandomKeys(dbfile, db, &docs, 0, num_docs/2);
    // Update the rest of documents, so that the last seq number becomes 200000.
    updateDocsWithRandomKeys(dbfile, db, &docs, num_docs/2, num_docs);

    // create compaction thread.
    thread_t tid;
    void *thread_ret;
    struct compactor_thread_args args;
    args.config = &fconfig;
    args.kvs_config = &kvs_config;
    thread_create(&tid, _compactor_thread, &args);

    // Sleep 10 ms for the compaction.
    usleep(10000);

    // rollback to a seq num 150000 while compaction is running.
    status = fdb_rollback(&db, 150000);
    TEST_CHK(status == FDB_RESULT_SUCCESS ||
             status == FDB_RESULT_NO_DB_INSTANCE);
    if (status == FDB_RESULT_NO_DB_INSTANCE) {
        fdb_file_info info;
        fdb_get_file_info(dbfile, &info);
        // Since compaction succeeded,
        // filename must be different to the original name.
        TEST_CHK(strcmp(info.filename, test_filename));
    }

    status = fdb_kvs_close(db);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_close(dbfile);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // wait for compactor termination
    thread_join(tid, &thread_ret);

    // free all documents
    for (int i = 0 ; i < num_docs; ++i){
        fdb_doc_free(docs.at(i));
    }

    // shutdown
    fdb_shutdown();

    memleak_end();
    TEST_RESULT(test_name);
}

void run_tests_with_encryption(fdb_encryption_algorithm_t encryption) {
    fprintf(stderr, "----testing with encryption algorithm %d\n", encryption);
    cur_encryption = encryption;

    // Read-only with multiple readers.
    test_multi_readers(MULTI_READERS, "test multi readers");
    test_multi_readers(MULTI_SNAPSHOT_READERS, "test multi snapshot readers");
    test_multi_readers(MULTI_MIXED_READERS, "test multi mixed readers");

    // Execute a writer with a manual compaction and multiple readers together.
    test_writer_multi_readers(REGULAR_WRITER, MULTI_READERS, MANUAL_COMPACTION,
                              "test a single writer and multi readers");
    test_writer_multi_readers(REGULAR_WRITER, MULTI_SNAPSHOT_READERS,
                              MANUAL_COMPACTION,
                              "test a single writer and multi snapshot readers");
    test_writer_multi_readers(REGULAR_WRITER, MULTI_MIXED_READERS,
                              MANUAL_COMPACTION,
                              "test a single writer and multi mixed readers");

    // Execute a writer, a compaction daemon, and multiple readers together.
    test_writer_multi_readers(REGULAR_WRITER, MULTI_READERS, DAEMON_COMPACTION,
                              "test a single writer, a compaction daemon, "
                              "and multi readers");
    test_writer_multi_readers(REGULAR_WRITER, MULTI_SNAPSHOT_READERS,
                              DAEMON_COMPACTION,
                              "test a single writer, a compaction daemon, "
                              "and multi snapshot readers");
    test_writer_multi_readers(REGULAR_WRITER, MULTI_MIXED_READERS,
                              DAEMON_COMPACTION,
                              "test a single writer, a compaction daemon, "
                              "and multi mixed readers");

    // Execute a transactional writer with a manual compaction and
    // multiple readers together.
    test_writer_multi_readers(TRANSACTIONAL_WRITER, MULTI_READERS,
                              MANUAL_COMPACTION,
                              "test a transactional writer and "
                              "multi readers");
    test_writer_multi_readers(TRANSACTIONAL_WRITER, MULTI_SNAPSHOT_READERS,
                              MANUAL_COMPACTION,
                              "test a transactional writer and "
                              "multi snapshot readers");
    test_writer_multi_readers(TRANSACTIONAL_WRITER, MULTI_MIXED_READERS,
                              MANUAL_COMPACTION,
                              "test a transactional writer and "
                              "multi mixed readers");

    // Execute a transactional writer, a compaction daemon, and
    // multiple readers together.
    test_writer_multi_readers(TRANSACTIONAL_WRITER, MULTI_READERS,
                              DAEMON_COMPACTION,
                              "test a transactional writer, a compaction daemon, "
                              "and multi readers");
    test_writer_multi_readers(TRANSACTIONAL_WRITER, MULTI_SNAPSHOT_READERS,
                              DAEMON_COMPACTION,
                              "test a transactional writer, a compaction daemon, "
                              "and multi snapshot readers");
    test_writer_multi_readers(TRANSACTIONAL_WRITER, MULTI_MIXED_READERS,
                              DAEMON_COMPACTION,
                              "test a transactional writer, a compaction daemon, "
                              "and multi mixed readers");

    // Execute a rollback and multiple readers together.
    test_rollback_multi_readers(MULTI_READERS, "test a rollback and multi readers");
    test_rollback_multi_readers(MULTI_SNAPSHOT_READERS,
                                "test a rollback and multi snapshot readers");
    test_rollback_multi_readers(MULTI_MIXED_READERS,
                                "test a rollback and multi mixed readers");
    test_rollback_compaction("test concurrent rollback and compaction");
}

int main() {
    test_filename = "./test.fdb_a";
    run_tests_with_encryption(FDB_ENCRYPTION_NONE);
    test_filename = "./test.fdb_b";
    run_tests_with_encryption(FDB_ENCRYPTION_BOGUS);
    test_filename = "./test.fdb_c";
#if defined(_CRYPTO_CC) || defined(_CRYPTO_LIBTOMCRYPT) || defined(_CRYPTO_OPENSSL)
    run_tests_with_encryption(FDB_ENCRYPTION_AES256);
#endif
    return 0;
}
