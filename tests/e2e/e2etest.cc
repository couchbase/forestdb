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
#include <errno.h>
#if !defined(WIN32) && !defined(_WIN32)
#include <unistd.h>
#endif

#include "filemgr_ops.h"
#include "filemgr.h"

#include "libforestdb/forestdb.h"
#include "test.h"
#include "e2espec.h"

void load_persons(storage_t *st) {
    int i, n=100;
    person_t p;

    // store and index person docs
    for (i = 0; i < n; ++i) {
        gen_person(&p);
        e2e_fdb_set_person(st, &p);
    }

#ifdef __DEBUG_E2E
    printf("[%s] load persons: %03d docs created\n",st->keyspace, n);
#endif
}

void delete_persons(storage_t *st) {
    TEST_INIT();

    fdb_doc *rdoc = NULL;
    fdb_status status;
    fdb_iterator *it;
    person_t *p;
    int i, n = 0;

    // delete every 5th doc
    status = fdb_iterator_sequence_init(st->all_docs, &it, 0, 0,
                                        FDB_ITR_NO_DELETES);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    i = 0;
    do {
        status = fdb_iterator_get(it, &rdoc);
        TEST_CHK (status == FDB_RESULT_SUCCESS);
        if ((i % 5) == 0) {

            p = (person_t *)rdoc->body;
            // ensure the requester has created this key
            if (strcmp(p->keyspace, st->keyspace) == 0) {
                e2e_fdb_del_person(st, p);
                n++;
            }

        }
        fdb_doc_free(rdoc);
        rdoc=NULL;
        i++;
    } while (fdb_iterator_next(it) != FDB_RESULT_ITERATOR_FAIL);

    fdb_iterator_close(it);

#ifdef __DEBUG_E2E
    sprintf(rbuf, "[%s] delete persons: %03d docs deleted\n",st->keyspace, n);
    TEST_RESULT(rbuf);
#endif
}

/*
 * reset params used to index storage
 * delete old docs that are part of new index
 * so that they are not included at verification time
 */
void update_index(storage_t *st, bool checkpointing) {

    TEST_INIT();

    fdb_iterator *it;
    person_t *p = NULL;
    fdb_doc *rdoc = NULL;
    fdb_status status;
    int n = 0;
    size_t vallen;
    char *mink = st->index_params->min;
    char *maxk = st->index_params->max;
    char rbuf[256];

    // change storage index range
    reset_storage_index(st);

    if (checkpointing) {
        start_checkpoint(st);
    }
    status = fdb_iterator_init(st->index1, &it, mink, 12,
                               maxk, 12, FDB_ITR_NO_DELETES);
    if (status != FDB_RESULT_SUCCESS) {
        // no items within min max range
        TEST_CHK(status == FDB_RESULT_ITERATOR_FAIL);
    }



    do {
        status = fdb_iterator_get(it, &rdoc);
        if (status == FDB_RESULT_SUCCESS) {
            status = fdb_get_kv(st->all_docs,
                                rdoc->body, rdoc->bodylen,
                                (void **)&p, &vallen);
            if (status == FDB_RESULT_SUCCESS) {
                if (strcmp(p->keyspace, st->keyspace) == 0) {
                    e2e_fdb_del_person(st, p);
                    n++;
                }
                free(p);
                p=NULL;
            }
            fdb_doc_free(rdoc);
            rdoc=NULL;
        }
    } while (fdb_iterator_next(it) != FDB_RESULT_ITERATOR_FAIL);

    if (checkpointing) {
        end_checkpoint(st);
    }

    fdb_iterator_close(it);

    // reset verification chkpoint
    st->v_chk->num_indexed = 0;
    st->v_chk->sum_age_indexed = 0;

    sprintf(rbuf, "update index: %03d docs deleted", n);
#ifdef __DEBUG_E2E
    TEST_RESULT(rbuf);
#endif
}

// --- verify ----
// 1. check that num of keys within index are correct
// 2. check that age index total is correct for specified range
// 3. check that doc count is as expected
void verify_db(storage_t *st) {

    TEST_INIT();

    checkpoint_t *db_checkpoint = create_checkpoint(st, END_CHECKPOINT);
    int db_ndocs = db_checkpoint->ndocs;
    int exp_ndocs = st->v_chk->ndocs;
    int exp_nidx = st->v_chk->num_indexed;
    int db_nidx = db_checkpoint->num_indexed;
    int db_suma = db_checkpoint->sum_age_indexed;
    int exp_suma = st->v_chk->sum_age_indexed;
    fdb_kvs_info info;
    char rbuf[256];

    e2e_fdb_commit(st->main, st->walflush);

    fdb_get_kvs_info(st->index1, &info);

#ifdef __DEBUG_E2E
    int val1, val2;
    fdb_iterator *it;
    fdb_doc *rdoc = NULL;
    if (db_ndocs != exp_ndocs) {
        // for debugging: currently inaccurate for concurrency patterns
        fdb_get_kvs_info(st->all_docs, &info);
        val1 = info.doc_count;
        (void)val1;
        val2 = 0;
        fdb_iterator_init(st->index1, &it, NULL, 0,
                          NULL, 0, FDB_ITR_NONE);
        do {
            fdb_iterator_get(it, &rdoc);
            if (!rdoc->deleted) {
                val2++;
            }
            fdb_doc_free(rdoc);
            rdoc=NULL;
        } while (fdb_iterator_next(it) != FDB_RESULT_ITERATOR_FAIL);
        printf("ndocs_debug: kvs_info(%d) == exp_ndocs(%d) ?\n", val1,exp_ndocs);
        printf("ndocs_debug: kvs_info(%d) == itr_count(%d) ?\n", val1, val2);
        fdb_iterator_close(it);
    }
    printf("[%s] db_ndix(%d) == exp_nidx(%d)\n", st->keyspace, db_nidx, exp_nidx);
#endif

    free(db_checkpoint);
    db_checkpoint=NULL;
    //TEST_CHK(db_nidx==exp_nidx);
    //TEST_CHK(db_suma==exp_suma);

    sprintf(rbuf, "[%s] verifydb: ndocs(%d=%d), nidx(%d=%d), sumage(%d=%d)\n",
            st->keyspace,
            db_ndocs, exp_ndocs,
            db_nidx, exp_nidx,
            db_suma, exp_suma);
#ifdef __DEBUG_E2E
    TEST_RESULT(rbuf);
#endif
}


/*
 * compares a db where src is typically from
 * a rollback state of live data and replay is a
 * db to use for comparison  of expected data
 */
void db_compare(fdb_kvs_handle *src, fdb_kvs_handle *replay) {

    TEST_INIT();

    int ndoc1, ndoc2;
    fdb_kvs_info info;
    fdb_iterator *it;
    fdb_doc *rdoc = NULL;
    fdb_doc *vdoc = NULL;
    fdb_status status;
    char rbuf[256];

    fdb_get_kvs_info(src, &info);
    ndoc1 = info.doc_count;
    fdb_get_kvs_info(replay, &info);
    ndoc2 = info.doc_count;

    TEST_CHK(ndoc1 == ndoc2);

    // all docs in replay db must be in source db with same status
    status = fdb_iterator_sequence_init(replay, &it, 0, 0, FDB_ITR_NONE);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    do {
        status = fdb_iterator_get_metaonly(it, &rdoc);
        TEST_CHK(status == FDB_RESULT_SUCCESS);

        fdb_doc_create(&vdoc, rdoc->key, rdoc->keylen,
                              rdoc->meta, rdoc->metalen,
                              rdoc->body, rdoc->bodylen);
        // lookup by key
        status = fdb_get(src, vdoc);

        if (rdoc->deleted) {
            TEST_CHK(status == FDB_RESULT_KEY_NOT_FOUND);
        } else {
            TEST_CHK(status == FDB_RESULT_SUCCESS);
        }

        fdb_doc_free(rdoc);
        fdb_doc_free(vdoc);
        rdoc=NULL;
        vdoc=NULL;

    } while (fdb_iterator_next(it) != FDB_RESULT_ITERATOR_FAIL);
    fdb_iterator_close(it);

    sprintf(rbuf, "db compare: src(%d) == replay(%d)", ndoc1, ndoc2);
#ifdef __DEBUG_E2E
    TEST_RESULT(rbuf);
#endif
}

/*
 * populate replay db up to specified seqnum
 */
void load_replay_kvs(storage_t *st, fdb_kvs_handle *replay_kvs, fdb_seqnum_t seqnum) {

    TEST_INIT();

    fdb_iterator *it;
    fdb_doc *rdoc = NULL;
    fdb_status status;
    transaction_t *tx;


    // iterator end at seqnum
    status = fdb_iterator_sequence_init(st->rtx, &it, 0, seqnum,
                                        FDB_ITR_NONE);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    do {
        status = fdb_iterator_get(it, &rdoc);
        TEST_CHK(status == FDB_RESULT_SUCCESS);

        tx = (transaction_t *)rdoc->body;
        if (tx->type == SET_PERSON) {
            status = fdb_set_kv(replay_kvs,
                                tx->refkey,
                                tx->refkey_len,
                                NULL,0);
            TEST_CHK(status == FDB_RESULT_SUCCESS);
        }
        if (tx->type == DEL_PERSON) {
            status = fdb_del_kv(replay_kvs,
                                tx->refkey,
                                tx->refkey_len);
            TEST_CHK(status == FDB_RESULT_SUCCESS);
        }
        fdb_doc_free(rdoc);
        rdoc=NULL;

    } while (fdb_iterator_next(it) != FDB_RESULT_ITERATOR_FAIL);
    fdb_iterator_close(it);

}

/*
 * replay records db up to a checkpoint into another db
 * rollback all_docs to that checkpoint
 * compare all_docs at that state to new doc
 */
void replay(storage_t *st) {
    TEST_INIT();

    int i;
    size_t v;
    char kvsbuf[10];
    fdb_file_handle *dbfile;
    fdb_kvs_handle *replay_kvs;
    fdb_config fconfig = fdb_get_default_config();
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    fconfig.wal_threshold = 1024;
    fconfig.flags = FDB_OPEN_FLAG_CREATE;
    fconfig.seqtree_opt = FDB_SEQTREE_USE; // enable seqtree since get_byseq
    fconfig.compaction_threshold = 10;
    fdb_iterator *it;
    fdb_status status;
    fdb_doc *rdoc = NULL;
    fdb_kvs_info info;
    transaction_t *tx;
    checkpoint_t *chk;
    fdb_seqnum_t rollback_seqnum;

    // create replay kvs
    status = fdb_open(&dbfile, E2EDB_RECORDS, &fconfig);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    e2e_fdb_commit(st->main, st->walflush);
    status = fdb_get_kvs_info(st->all_docs, &info);
    TEST_CHK(status == FDB_RESULT_SUCCESS);


    // iterate over records kv and replay transactions
    status = fdb_iterator_sequence_init(st->rtx, &it, 0, 0, FDB_ITR_NONE);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // seek to end so we can reverse iterate
    // seq iterators cannot seek
    do {
        ;
    } while (fdb_iterator_next(it) != FDB_RESULT_ITERATOR_FAIL);


    // reverse iterate from highest to lowest checkpoint
    i=0;
    while (fdb_iterator_prev(it) != FDB_RESULT_ITERATOR_FAIL) {
        status = fdb_iterator_get(it, &rdoc);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        tx = (transaction_t *)rdoc->body;
        if (tx->type == END_CHECKPOINT) {

            sprintf(kvsbuf, "rkvs%d", i);
            status = fdb_kvs_open(dbfile, &replay_kvs, kvsbuf,  &kvs_config);
            TEST_CHK(status == FDB_RESULT_SUCCESS);

            // load replay db up to this seqnum
            load_replay_kvs(st, replay_kvs, rdoc->seqnum);

            // get checkpoint doc for rollback
            status = fdb_get_kv(st->chk, tx->refkey, tx->refkey_len,
                                (void **)&chk, &v);

            TEST_CHK(status == FDB_RESULT_SUCCESS);
            rollback_seqnum = chk->seqnum_all;
;
#ifdef __DEBUG_E2E
            printf("rollback to %llu\n", chk->seqnum_all);
#endif
            status = fdb_rollback(&st->all_docs, rollback_seqnum);
            if (status == FDB_RESULT_NO_DB_INSTANCE) {
                free(chk);
                // drop replay kvs
                status = fdb_kvs_close(replay_kvs);
                TEST_CHK(status == FDB_RESULT_SUCCESS);
                status = fdb_kvs_remove(dbfile, kvsbuf);
                TEST_CHK(status == FDB_RESULT_SUCCESS);
                break;
            }
            TEST_CHK(status == FDB_RESULT_SUCCESS);
            free(chk);
            chk=NULL;
            // after rollback, WAL entries should be flushed for
            // accurate # docs count comparison with 'replay_kvs'.
            e2e_fdb_commit(st->main, true);

            status = fdb_get_kvs_info(st->rtx, &info);
            TEST_CHK(status == FDB_RESULT_SUCCESS);

            // compare rollback and replay db
            e2e_fdb_commit(dbfile, st->walflush);
            db_compare(st->all_docs, replay_kvs);

            // drop replay kvs
            status = fdb_kvs_close(replay_kvs);
            TEST_CHK(status == FDB_RESULT_SUCCESS);
            status = fdb_kvs_remove(dbfile, kvsbuf);
            TEST_CHK(status == FDB_RESULT_SUCCESS);
            i++;
        }
        fdb_doc_free(rdoc);
        rdoc=NULL;
    }

    fdb_iterator_close(it);
    fdb_close(dbfile);

}

/* do forward previous and seek operations on main kv */
void *iterate_thread(void *args) {

    TEST_INIT();

    int i, j;
    fdb_config *fconfig = (fdb_config *)args;
    fdb_file_handle *dbfile;
    fdb_iterator *it;
    fdb_doc *rdoc = NULL;
    fdb_open(&dbfile, E2EDB_MAIN, fconfig);
    fdb_kvs_handle *all_docs, *snap_db;
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    fdb_status status;
    person_t p;

    for (i = 0; i < 50; i++) {
        fdb_kvs_open(dbfile, &all_docs, E2EKV_ALLDOCS,  &kvs_config);

        if ((i % 2) == 0) { //snapshot
            status = fdb_snapshot_open(all_docs, &snap_db, FDB_SNAPSHOT_INMEM);
            TEST_CHK(status == FDB_RESULT_SUCCESS);
            status = fdb_iterator_init(snap_db, &it, NULL, 0, NULL, 0, FDB_ITR_NONE);
            TEST_CHK(status == FDB_RESULT_SUCCESS);
        } else {
            status = fdb_iterator_init(all_docs, &it, NULL, 0, NULL, 0, FDB_ITR_NONE);
            TEST_CHK(status == FDB_RESULT_SUCCESS);
        }
        j = 0;
        // forward
        do {
            status = fdb_iterator_get(it, &rdoc);
            if (j) {
                TEST_CHK(status == FDB_RESULT_SUCCESS);
            }
            fdb_doc_free(rdoc);
            rdoc = NULL;
            j++;
        } while (fdb_iterator_next(it) != FDB_RESULT_ITERATOR_FAIL);
        // reverse and seek ahead
        for (j = 0; j < 10; j++) {
            while (fdb_iterator_prev(it) != FDB_RESULT_ITERATOR_FAIL) {
                status = fdb_iterator_get(it, &rdoc);
                TEST_CHK(status == FDB_RESULT_SUCCESS);
                fdb_doc_free(rdoc);
                rdoc = NULL;
            }
            gen_person(&p);

            // seek using random person key
            if (j % 2 == 0) { // seek higher
                fdb_iterator_seek(it, p.key, strlen(p.key), FDB_ITR_SEEK_HIGHER);
            } else {
                fdb_iterator_seek(it, p.key, strlen(p.key), FDB_ITR_SEEK_LOWER);
            }
        }
        fdb_iterator_close(it);
        if ((i % 2) == 0) {
            fdb_kvs_close(snap_db);
        }
        fdb_kvs_close(all_docs);
    }

    fdb_doc_free(rdoc);
    rdoc = NULL;
    fdb_close(dbfile);
    return NULL;
}

void *compact_thread(void *args) {
    int i;
    fdb_config *fconfig = (fdb_config *)args;
    fdb_file_handle *dbfile;
    fdb_open(&dbfile, E2EDB_MAIN, fconfig);
    for (i = 0; i < 3; ++i) {
        sleep(2);
#ifdef __DEBUG_E2E
        printf("compact: %d\n", i);
#endif
        fdb_compact(dbfile, NULL);
    }
    fdb_close(dbfile);
    return NULL;
}

void *compact_upto_thread(void *args) {
    TEST_INIT();

    int i;
    uint64_t num_markers;
    fdb_snapshot_info_t *markers;
    fdb_status status;

    fdb_config *fconfig = (fdb_config *)args;
    fdb_file_handle *dbfile;
    fdb_open(&dbfile, E2EDB_MAIN, fconfig);
    for (i = 0; i < 10; ++i) {
        sleep(1);
        status = fdb_get_all_snap_markers(dbfile, &markers,
                                          &num_markers);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        if (num_markers == 0) {
            // No need of compaction as file is empty
            break;
        }
        status = fdb_compact_upto(dbfile, NULL, markers[0].marker);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        fdb_free_snap_markers(markers, num_markers);
    }
    fdb_close(dbfile);
    return NULL;
}

void e2e_async_compact_pattern(int n_checkpoints, fdb_config fconfig,
                               bool deletes, bool walflush) {
    TEST_INIT();
    int n, i;
    storage_t *st;
    checkpoint_t verification_checkpoint;
    idx_prams_t index_params;
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    fdb_kvs_info info;
    fdb_kvs_handle *snap_db;
    fdb_status status;
    thread_t tid;
    void *thread_ret;
    n_checkpoints = n_checkpoints * LOAD_FACTOR;

    memleak_start();

    // init
    rm_storage_fs();
    gen_index_params(&index_params);
    memset(&verification_checkpoint, 0, sizeof(checkpoint_t));

    // setup
    st = init_storage(&fconfig, &fconfig, &kvs_config,
            &index_params, &verification_checkpoint, walflush);

    // create compaction thread
    thread_create(&tid, compact_thread, (void*)&fconfig);

    // test
    for ( n = 0; n < n_checkpoints; ++n) {

#ifdef __DEBUG_E2E
        printf("checkpoint: %d\n", n);
#endif
        load_persons(st);
        for (i=0;i<100;++i) {
#ifdef __DEBUG_E2E
            printf("\n\n----%d----\n", i);
#endif
            load_persons(st);
            if (deletes) {
                delete_persons(st);
            }
            e2e_fdb_commit(st->main, walflush);
            status = fdb_get_kvs_info(st->all_docs, &info);
            TEST_CHK(status == FDB_RESULT_SUCCESS);
            status = fdb_snapshot_open(st->all_docs, &snap_db, info.last_seqnum);
            TEST_CHK(status == FDB_RESULT_SUCCESS);
            update_index(st, true);
            verify_db(st);
            fdb_kvs_close(snap_db);
        }
    }

    thread_join(tid, &thread_ret);
    // teardown
    e2e_fdb_shutdown(st);

    memleak_end();
}

void e2e_kvs_index_pattern(int n_checkpoints, fdb_config fconfig,
                           bool deletes, bool walflush) {

    int n, i;
    storage_t *st;
    checkpoint_t verification_checkpoint;
    idx_prams_t index_params;
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    n_checkpoints = n_checkpoints * LOAD_FACTOR;

    memleak_start();

    // init
    rm_storage_fs();
    gen_index_params(&index_params);
    memset(&verification_checkpoint, 0, sizeof(checkpoint_t));

    // setup
    st = init_storage(&fconfig, &fconfig, &kvs_config,
                      &index_params, &verification_checkpoint, walflush);

    // test
    for (n = 0; n < n_checkpoints; ++n) {

        // checkpoint
        start_checkpoint(st);

        for (i = 0; i < 100; ++i) {
#ifdef __DEBUG_E2E
            printf("\n\n----%d----\n", i);
#endif
            load_persons(st);
            if (deletes) {
                delete_persons(st);
            }
            verify_db(st);
        }

        // end checkpoint
        end_checkpoint(st);

        // change index range
        update_index(st, true);
        verify_db(st);

    }

    if (fconfig.compaction_mode != FDB_COMPACTION_AUTO) {
        /* replay involves rollbacks but
         * cannot rollback pre compact due to BUG: MB-13130
         */
        replay(st);
    }

    // teardown
    e2e_fdb_shutdown(st);

    memleak_end();
}

void *scan_thread(void *args) {
    int i = 0;
    fdb_kvs_handle *scan_kv = (fdb_kvs_handle *)args;

    for (i = 0; i < 20; ++i) {
        scan(NULL, scan_kv);
    }
    return NULL;
}

void *disk_read_thread(void *args) {
    TEST_INIT();
    int n;
    uint64_t i;
    int seqno;
    uint64_t num_markers;
    fdb_snapshot_info_t *markers;
    fdb_kvs_handle *snap_db;
    fdb_status status;
    fdb_doc *doc;
    person_t p;
    fdb_doc_create(&doc, NULL, 0, NULL, 0, NULL, 0);

    storage_t *st = (storage_t *)args;

    for (n = 0; n < 10; ++n) {
        status = fdb_get_all_snap_markers(st->main, &markers,
                                          &num_markers);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        for (i = 0; i < num_markers; i++) {
            // open disk snapshot to each marker
            seqno = markers[i].kvs_markers[0].seqnum;
            if (!seqno) {
                continue;
            }
            status = fdb_snapshot_open(st->all_docs, &snap_db, seqno);
            if (status == FDB_RESULT_SUCCESS) {
                doc->seqnum = seqno;
                // can get doc
                status = fdb_get_byseq(snap_db, doc);
                TEST_CHK(status == FDB_RESULT_SUCCESS);

                // verify
                memcpy(&p, (person_t *)doc->body, sizeof(person_t));
                TEST_CHK(p.age <= seqno)
            }
        }
        fdb_free_snap_markers(markers, num_markers);
    }

    fdb_doc_free(doc);
    return NULL;
}


void *writer_thread(void *args) {

    storage_t *st = (storage_t *)args;
    for (int i = 0; i < 5; ++i) {
        load_persons(st);
        if (i == 5) {
            delete_persons(st);
        }
    }
    return NULL;
}

void *seq_writer_thread(void *args) {

    int j, i = 0, n=10000;
    person_t p;
    storage_t *st = (storage_t *)args;
    for (j = 0; j < 10; ++j) {
        for (i = 0; i < n; ++i) {
            gen_person(&p);
            p.age = i;
            sprintf(p.key, "person%d", i);
            e2e_fdb_set_person(st, &p);
        }
        e2e_fdb_commit(st->main, true);
    }
    return NULL;
}

void *update_thread(void *args) {
    TEST_INIT();

    int i = 0, n=100000;
    person_t p;
    fdb_kvs_handle *kv = (fdb_kvs_handle *)args;

    // only generate 1 person type
    gen_person(&p);
    for (i = 0; i < n; ++i) {
        fdb_set_kv(kv, p.key, strlen(p.key),
                   p.name, strlen(p.name));
    }
    return NULL;
}


/*
 * perform many fdb features against concurrent handlers
 * to verify robustness of db.  this pattern is qualified by
 * completion without faults data corrections and has relaxed error handling.
 */
void e2e_robust_pattern(fdb_config fconfig) {

    int i;
    int n_writers = 10;
    int n_scanners = 10;
    storage_t **st = alca(storage_t *, n_writers);
    storage_t **st2 = alca(storage_t *, n_writers);
    checkpoint_t *verification_checkpoint = alca(checkpoint_t, n_writers);
    idx_prams_t *index_params = alca(idx_prams_t, n_writers);
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    thread_t *tid_sc = alca(thread_t, n_scanners);
    void **thread_ret_sc = alca(void *, n_scanners);
    thread_t *tid_wr = alca(thread_t, n_writers);
    void **thread_ret_wr = alca(void *, n_writers);
    fdb_kvs_handle **scan_kv = alca(fdb_kvs_handle *, n_scanners);
    thread_t c_tid, i_tid;
    void *c_ret, *i_ret;

    memleak_start();

    // init
    rm_storage_fs();

    // init storage handles
    // the nth writer is commit handler
    for (i = 0;i < n_writers; ++i) {
        gen_index_params(&index_params[i]);
        memset(&verification_checkpoint[i], 0, sizeof(checkpoint_t));
        st[i] = init_storage(&fconfig, &fconfig, &kvs_config,
                &index_params[i], &verification_checkpoint[i], true);
        st2[i] = init_storage(&fconfig, &fconfig, &kvs_config,
                &index_params[i], &verification_checkpoint[i], true);
        memcpy(st2[i]->keyspace, st[i]->keyspace, KEYSPACE_LEN);
    }

    // load init data
    for (i = 0; i < 100; ++i) {
        load_persons(st[0]);
    }

    thread_create(&c_tid, compact_thread, (void*)&fconfig);
    thread_create(&i_tid, iterate_thread, (void*)&fconfig);

    for (int n = 0; n < 10; ++n) {
        // start writer threads
        for (i = 0; i < n_writers - 1; ++i) {
            st[i]->verify_set = false;
            thread_create(&tid_wr[i], writer_thread, (void*)st[i]);
        }


        // start scanner threads
        for (i = 0; i < n_scanners; ++i) {
            scan_kv[i] = scan(st2[i], NULL);
            thread_create(&tid_sc[i], scan_thread, (void*)scan_kv[i]);
        }

        e2e_fdb_commit(st[n_writers-1]->main, true);

        // join scan threads
        for (i = 0; i < n_scanners; ++i) {
            thread_join(tid_sc[i], &thread_ret_sc[i]);
            fdb_kvs_close(scan_kv[i]);
        }

        // join writer threads
        for (i = 0; i < n_writers - 1; ++i) {
            thread_join(tid_wr[i], &thread_ret_wr[i]);
            update_index(st[i], false);
        }
        e2e_fdb_commit(st[n_writers - 1]->main, false);
    }

    thread_join(c_tid, &c_ret);
    thread_join(i_tid, &i_ret);

    for (i = 0; i < n_writers; ++i) {
        // teardown
        e2e_fdb_close(st2[i]);
        e2e_fdb_close(st[i]);
    }
    fdb_shutdown();

    memleak_end();
}

/*
 * concurrent scan pattern:
 *   start n_scanners and n_writers
 *   scanners share in-mem snapshots and writers use copies of storage_t
 */
void e2e_concurrent_scan_pattern(int n_checkpoints, int n_scanners, int n_writers,
                                 fdb_config fconfig, bool walflush) {

    int n, i;
    storage_t **st = alca(storage_t *, n_writers);
    storage_t **st2 = alca(storage_t *, n_writers);
    checkpoint_t *verification_checkpoint = alca(checkpoint_t, n_writers);
    idx_prams_t *index_params = alca(idx_prams_t, n_writers);
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    thread_t *tid_sc = alca(thread_t, n_scanners);
    void **thread_ret_sc = alca(void *, n_scanners);
    thread_t *tid_wr = alca(thread_t, n_writers);
    void **thread_ret_wr = alca(void *, n_writers);
    fdb_kvs_handle **scan_kv = alca(fdb_kvs_handle *, n_scanners);
    n_checkpoints = n_checkpoints * LOAD_FACTOR;

    memleak_start();

    // init
    rm_storage_fs();


    // init storage handles
    for (i = 0; i < n_writers; ++i) {
        gen_index_params(&index_params[i]);
        memset(&verification_checkpoint[i], 0, sizeof(checkpoint_t));
        st[i] = init_storage(&fconfig, &fconfig, &kvs_config,
                &index_params[i], &verification_checkpoint[i], walflush);
        st2[i] = init_storage(&fconfig, &fconfig, &kvs_config,
                &index_params[i], &verification_checkpoint[i], walflush);
        memcpy(st2[i]->keyspace, st[i]->keyspace, KEYSPACE_LEN);
    }

    // load init data
    start_checkpoint(st[0]);
    for (i = 0; i < 100; ++i) {
        load_persons(st[0]);
    }
    end_checkpoint(st[0]);
    verify_db(st[0]);

    for (n = 0; n < n_checkpoints; ++n) {

        // start writer threads
        for (i = 0; i < n_writers; ++i) {
            st[i]->verify_set = false;
            start_checkpoint(st[i]);
            thread_create(&tid_wr[i], writer_thread, (void*)st[i]);
        }

        // start scanner threads
        for (i = 0; i < n_scanners; ++i) {
            scan_kv[i] = scan(st2[i], NULL);
            thread_create(&tid_sc[i], scan_thread, (void*)scan_kv[i]);
        }

        // join scan threads
        for (i = 0; i < n_scanners; ++i) {
            thread_join(tid_sc[i], &thread_ret_sc[i]);
            fdb_kvs_close(scan_kv[i]);
        }

        // join writer threads
        for (i = 0; i < n_writers; ++i) {
            thread_join(tid_wr[i], &thread_ret_wr[i]);
            end_checkpoint(st[i]);
            verify_db(st[i]);
            update_index(st[i], true);
        }

    }

    for (i = 0; i < n_writers; ++i) {
        // teardown
        e2e_fdb_close(st2[i]);
        e2e_fdb_close(st[i]);
    }
    fdb_shutdown();

    memleak_end();
}


void e2e_index_basic_test() {

    TEST_INIT();
    memleak_start();

    randomize();
    // configure
    fdb_config fconfig = fdb_get_default_config();
    fconfig.wal_threshold = 1024;
    fconfig.flags = FDB_OPEN_FLAG_CREATE;
    fconfig.durability_opt = FDB_DRB_ASYNC;
    fconfig.seqtree_opt = FDB_SEQTREE_USE; // enable seqtree since get_byseq

    // test
    e2e_kvs_index_pattern(1, fconfig, true, false); // normal commit
    e2e_kvs_index_pattern(1, fconfig, true, true);  // wal commit

    memleak_end();
    TEST_RESULT("TEST: e2e index basic test");
}

void e2e_index_walflush_test_no_deletes_auto_compact() {

    TEST_INIT();
    memleak_start();

    randomize();
    // configure
    fdb_config fconfig = fdb_get_default_config();
    fconfig.wal_threshold = 1024;
    fconfig.flags = FDB_OPEN_FLAG_CREATE;
    fconfig.durability_opt = FDB_DRB_ASYNC;
    fconfig.compaction_mode=FDB_COMPACTION_AUTO;
    fconfig.seqtree_opt = FDB_SEQTREE_USE; // enable seqtree since get_byseq

    // test
    e2e_kvs_index_pattern(10, fconfig, false, true);

    memleak_end();
    TEST_RESULT("TEST: e2e index walflush test no deletes auto compact");
}

void e2e_index_walflush_autocompact_test() {

    TEST_INIT();
    memleak_start();

    randomize();
    // opts
    fdb_config fconfig = fdb_get_default_config();
    fconfig.wal_threshold = 1024;
    fconfig.flags = FDB_OPEN_FLAG_CREATE;
    fconfig.durability_opt = FDB_DRB_ASYNC;
    fconfig.compaction_mode=FDB_COMPACTION_AUTO;
    fconfig.seqtree_opt = FDB_SEQTREE_USE; // enable seqtree since get_byseq

    // test
    e2e_kvs_index_pattern(2, fconfig, true, true);

    memleak_end();
    TEST_RESULT("TEST: e2e index walflush autocompact test");

}

void e2e_index_normal_commit_autocompact_test() {

    TEST_INIT();
    memleak_start();

    randomize();
    // opts
    fdb_config fconfig = fdb_get_default_config();
    fconfig.wal_threshold = 1024;
    fconfig.flags = FDB_OPEN_FLAG_CREATE;
    fconfig.durability_opt = FDB_DRB_NONE;
    fconfig.compaction_mode=FDB_COMPACTION_AUTO;
    fconfig.seqtree_opt = FDB_SEQTREE_USE; // enable seqtree since get_byseq

    // test
    e2e_kvs_index_pattern(2, fconfig, true, false);

    memleak_end();
    TEST_RESULT("TEST: e2e index normal commit autocompact test");
}

void e2e_async_manual_compact_test() {
    TEST_INIT();
    memleak_start();

    randomize();
    // opts
    fdb_config fconfig = fdb_get_default_config();
    fconfig.wal_threshold = 1024;
    fconfig.flags = FDB_OPEN_FLAG_CREATE;
    fconfig.durability_opt = FDB_DRB_ASYNC;

    // test
    e2e_async_compact_pattern(10, fconfig, false, true);
    memleak_end();
    TEST_RESULT("TEST: e2e async manual compact test");
}


void e2e_concurrent_scan_test() {
    TEST_INIT();
    memleak_start();

    randomize();
    fdb_config fconfig = fdb_get_default_config();
    fconfig.wal_threshold = 1024;
    fconfig.flags = FDB_OPEN_FLAG_CREATE;
    fconfig.compaction_mode=FDB_COMPACTION_AUTO;
    fconfig.durability_opt = FDB_DRB_ASYNC;
    fconfig.purging_interval = 30; // retain deleted docs for iteration
    fconfig.seqtree_opt = FDB_SEQTREE_USE; // enable seqtree since get_byseq

    // test
    e2e_concurrent_scan_pattern(3, 5, 5, fconfig, true);
    // normal_commit
    e2e_concurrent_scan_pattern(3, 5, 5, fconfig, false);

    memleak_end();
    TEST_RESULT("TEST: e2e concurrent scan");
}

void e2e_robust_test() {
    TEST_INIT();

    randomize();
    fdb_config fconfig = fdb_get_default_config();
    fconfig.wal_threshold = 1024;
    fconfig.flags = FDB_OPEN_FLAG_CREATE;
    fconfig.compaction_mode=FDB_COMPACTION_AUTO;
    fconfig.durability_opt = FDB_DRB_ASYNC;
    fconfig.seqtree_opt = FDB_SEQTREE_USE; // enable seqtree since get_byseq
    // to allow iterators to validate docs across async compaction
    // specify purging_interval so deleted docs are not dropped by
    // compactor immediately..
    fconfig.purging_interval = 80;

    // test
    e2e_robust_pattern(fconfig);

    TEST_RESULT("TEST: e2e robust test");
}

void e2e_scan_compact_upto_test() {
    TEST_INIT();
    memleak_start();

    randomize();
    int n, i;
    void *thread_ret;
    bool walflush = true;
    int n_checkpoints =  LOAD_FACTOR;

    fdb_config fconfig = fdb_get_default_config();
    fconfig.flags = FDB_OPEN_FLAG_CREATE;
    fconfig.compaction_threshold = 0;
    fconfig.durability_opt = FDB_DRB_ASYNC;
    fconfig.purging_interval = 30; // retain deleted docs for iteration

    storage_t *st;
    checkpoint_t verification_checkpoint;
    idx_prams_t index_params;
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    fdb_kvs_info info;
    fdb_kvs_handle *snap_db;
    fdb_status status;
    thread_t tid;

    // init
    rm_storage_fs();
    gen_index_params(&index_params);
    memset(&verification_checkpoint, 0, sizeof(checkpoint_t));

    // setup
    st = init_storage(&fconfig, &fconfig, &kvs_config,
                      &index_params, &verification_checkpoint, walflush);

    // create compaction thread
    thread_create(&tid, compact_upto_thread, (void*)&fconfig);

    // test
    for (n = 0; n < n_checkpoints; ++n) {
        load_persons(st);
        for (i = 0; i < 100; ++i) {
            load_persons(st);
            e2e_fdb_commit(st->main, walflush);
            status = fdb_get_kvs_info(st->all_docs, &info);
            TEST_CHK(status == FDB_RESULT_SUCCESS);
            fdb_snapshot_open(st->all_docs, &snap_db, info.last_seqnum);
            TEST_CHK(status == FDB_RESULT_SUCCESS);
            update_index(st, true);
            verify_db(st);
            fdb_kvs_close(snap_db);
        }
    }

    thread_join(tid, &thread_ret);

    // teardown
    e2e_fdb_shutdown(st);
    memleak_end();
    TEST_RESULT("TEST: e2e concurrent compact upto");
}

void *kv_thread(void *args) {
    // This thread stores and indexes person docs

    TEST_INIT();
    uint64_t i;
    uint64_t num_markers;
    fdb_snapshot_info_t *markers;
    fdb_status status;

    storage_t *st = (storage_t *)args;
    status = fdb_get_all_snap_markers(st->main, &markers,
                                      &num_markers);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    for (i = 0; i < num_markers; i += 10) {
        load_persons(st);
    }
    fdb_free_snap_markers(markers, num_markers);
    return NULL;
}

// This function identifies the latest superblock
// add adds garbage to it.
void corrupt_latest_superblock(const char* filename) {
    /*
     * Note that each block is 4096 bytes.
     * - There are 4 superblocks which constitute the
     *   first 4 blocks of the file.
     * - The 8 bytes following the first 8 bytes of a
     *   superblock contains the block revision num.
     */
    struct filemgr_ops *ops = get_filemgr_ops();
    int64_t offset = 8;
    int latest_sb = 0;
    fdb_fileops_handle fops_handle;
    FileMgr::fileOpen(filename, ops, &fops_handle, O_RDWR, 0644);
    uint64_t buf, highest_rev = 0;
    for (int i = 0; i < 4; ++i) {    // num of superblocks: 4
        if (ops->pread(fops_handle, &buf, sizeof(uint64_t),
                       offset) == sizeof(uint64_t)) {
            buf = _endian_decode(buf);
            assert(buf != highest_rev);
            if (buf > highest_rev) {
                highest_rev = buf;
                latest_sb = i;
            }
            offset += 4096;
        } else {
            fprintf(stderr, "Warning: Could not find the latest superblock!\n");
            FileMgr::fileClose(ops, fops_handle);
            return;
        }
    }
    // Write garbage at a random offset that would fall within
    // the latest super block
    uint64_t garbage = rand();
    offset = latest_sb * 4096 + (rand() % (4095 - sizeof(garbage)));
    if (ops->pwrite(fops_handle, &garbage, sizeof(garbage),
                    offset) != sizeof(garbage)) {
        fprintf(stderr,
                "\nWarning: Could not write garbage into the superblock!");
    }
    FileMgr::fileClose(ops, fops_handle);
}

void e2e_crash_recover_test(bool do_rollback) {

    TEST_INIT();
    memleak_start();

    randomize();

    bool walflush = true;
    int i, n;
    int n_checkpoints =  2;

    rm_storage_fs();
    storage_t *st;
    checkpoint_t verification_checkpoint;
    idx_prams_t index_params;
    fdb_kvs_handle *snap_db;
    fdb_kvs_info info;
    fdb_status status;

    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    fdb_config fconfig = fdb_get_default_config();
    fconfig.flags = FDB_OPEN_FLAG_CREATE;
    fconfig.compaction_threshold = 0;
    fconfig.durability_opt = FDB_DRB_ASYNC;
    fconfig.purging_interval = 30; // retain deleted docs for iteration

    gen_index_params(&index_params);
    memset(&verification_checkpoint, 0, sizeof(checkpoint_t));
    st = init_storage(&fconfig, &fconfig, &kvs_config,
                      &index_params, &verification_checkpoint, walflush);

    for (i = 0; i < 100; ++i) {
        load_persons(st);
        e2e_fdb_commit(st->main, true);
    }

    fdb_seqnum_t seqno;
    uint64_t k, num_markers;
    fdb_snapshot_info_t *markers;

    if (do_rollback) {
        status = fdb_get_all_snap_markers(st->main, &markers,
                                          &num_markers);
        TEST_CHK(status == FDB_RESULT_SUCCESS);

        for (k = 0; k < num_markers; k += 10) {
            // rollback to each marker
            seqno = markers[k].kvs_markers[0].seqnum;
            status = fdb_rollback(&st->all_docs, seqno);
            TEST_CHK(status == FDB_RESULT_SUCCESS);
        }
        fdb_free_snap_markers(markers, num_markers);
    } else {
        status = fdb_get_all_snap_markers(st->main, &markers,
                                          &num_markers);
        TEST_CHK(status == FDB_RESULT_SUCCESS);

        for (k = 0; k < num_markers; k += 10) {
            load_persons(st);
        }
        fdb_free_snap_markers(markers, num_markers);
    }

    // close storage
    e2e_fdb_close(st);

    corrupt_latest_superblock(E2EDB_MAIN);

    // reopen storage
    gen_index_params(&index_params);
    memset(&verification_checkpoint, 0, sizeof(checkpoint_t));
    st = init_storage(&fconfig, &fconfig, &kvs_config,
                      &index_params, &verification_checkpoint, walflush);

    // run verifiable workload
    for (n = 0; n < n_checkpoints; ++n) {
        load_persons(st);
        for (i = 0; i < 100; ++i) {
            load_persons(st);
            e2e_fdb_commit(st->main, walflush);
            status = fdb_get_kvs_info(st->all_docs, &info);
            TEST_CHK(status == FDB_RESULT_SUCCESS);
            fdb_snapshot_open(st->all_docs, &snap_db, info.last_seqnum);
            TEST_CHK(status == FDB_RESULT_SUCCESS);
            update_index(st, true);
            verify_db(st);
            fdb_kvs_close(snap_db);
        }
    }

    // teardown
    e2e_fdb_shutdown(st);
    memleak_end();
    if (do_rollback) {
        TEST_RESULT("TEST: e2e crash recover test with rollback");
    } else {
        TEST_RESULT("TEST: e2e crash recover test");
    }
}

void e2e_concurrent_reader_writer(bool do_compaction) {
    TEST_INIT();
    memleak_start();

    randomize();
    fdb_config fconfig = fdb_get_default_config();
    // to allow iterators to validate docs across async compaction
    // specify purging_interval so deleted docs are not dropped by
    // compactor immediately..
    fconfig.purging_interval = 80;
    fconfig.seqtree_opt = FDB_SEQTREE_USE; // enable seqtree since get_byseq

    // init
    rm_storage_fs();

    // test
    int i;
    int n_writers = 2;
    int n_scanners = 2;
    storage_t **st = alca(storage_t *, n_writers);
    storage_t **st2 = alca(storage_t *, n_writers);
    checkpoint_t *verification_checkpoint = alca(checkpoint_t, n_writers);
    idx_prams_t *index_params = alca(idx_prams_t, n_writers);
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    thread_t *tid_sc = alca(thread_t, n_scanners);
    void **thread_ret_sc = alca(void *, n_scanners);
    thread_t *tid_wr = alca(thread_t, n_writers);
    void **thread_ret_wr = alca(void *, n_writers);
    fdb_kvs_handle **scan_kv = alca(fdb_kvs_handle *, n_scanners);
    thread_t c_tid;
    void *c_ret;

    // init storage handles
    // the nth writer is commit handler
    for (i = 0; i < n_writers; ++i) {
        gen_index_params(&index_params[i]);
        memset(&verification_checkpoint[i], 0, sizeof(checkpoint_t));
        st[i] = init_storage(&fconfig, &fconfig, &kvs_config,
                             &index_params[i], &verification_checkpoint[i],
                             true);
        st2[i] = init_storage(&fconfig, &fconfig, &kvs_config,
                              &index_params[i], &verification_checkpoint[i],
                              true);
        memcpy(st2[i]->keyspace, st[i]->keyspace, KEYSPACE_LEN);
    }

    if (do_compaction) {
        thread_create(&c_tid, compact_thread, (void*)&fconfig);
    }

    // start new item thread
    thread_create(&tid_wr[0], seq_writer_thread, (void*)st[0]);
    // start update thread
    thread_create(&tid_wr[1], update_thread, (void*)st[1]->index1);

    // start disk-snapshot thread
    scan_kv[0] = scan(st2[0], NULL);
    thread_create(&tid_sc[0], disk_read_thread, (void*)st[1]);
    // start mem-snapshot thread
    scan_kv[1] = scan(st2[1], NULL);
    thread_create(&tid_sc[1], scan_thread, (void*)scan_kv[1]);

    // join threads
    thread_join(tid_wr[0], &thread_ret_wr[0]);
    thread_join(tid_wr[1], &thread_ret_wr[1]);
    thread_join(tid_sc[1], &thread_ret_sc[1]);
    thread_join(tid_sc[0], &thread_ret_sc[0]);
    if (do_compaction) {
        thread_join(c_tid, &c_ret);
    }

    // commit
    e2e_fdb_commit(st[0]->main, false);

    for (i = 0; i < n_writers; ++i) {
        // teardown
        e2e_fdb_close(st2[i]);
        e2e_fdb_close(st[i]);
    }
    fdb_shutdown();

    memleak_end();
    if (do_compaction) {
        TEST_RESULT("TEST: e2e concurrent reader writer test with compaction");
    } else {
        TEST_RESULT("TEST: e2e concurrent reader writer test");
    }
}

void e2e_multi_dbfile_concurrent_wr() {
    TEST_INIT();
    memleak_start();
    int i, r;
    int nf = 16;
    char buf[64];
    thread_t *tid_wr = alca(thread_t, nf);
    void **thread_ret_wr = alca(void *, nf);
    fdb_file_handle **dbfiles = alca(fdb_file_handle*, nf);
    fdb_kvs_handle **kvs = alca(fdb_kvs_handle*, nf);
    fdb_status status;
    randomize();
    rm_storage_fs();
    r = system(SHELL_DEL" e2edb_ex* > errorlog.txt");
    (void)r;

    // create dbfiles
    fdb_config fconfig = fdb_get_default_config();
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    fconfig.compaction_mode  = FDB_COMPACTION_MANUAL;

    for (i = 0; i < nf; i++) {
        sprintf(buf, "e2edb_ex%d", i);
        status = fdb_open(&dbfiles[i], buf, &fconfig);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        status = fdb_kvs_open_default(dbfiles[i], &kvs[i], &kvs_config);
        TEST_CHK(status == FDB_RESULT_SUCCESS);

        // run update thread on each file to enter reuse
        thread_create(&tid_wr[i], update_thread, (void*)kvs[i]);
    }

    // join and commit
    for (i = 0; i < nf; i++) {
        thread_join(tid_wr[i], &thread_ret_wr[i]);
        fdb_commit(dbfiles[i], FDB_COMMIT_MANUAL_WAL_FLUSH);
        fdb_close(dbfiles[i]);
    }

    fdb_shutdown();
    memleak_end();
    TEST_RESULT("TEST: e2e multi dbfile concurrent wr");
}

void e2e_multi_kvs_concurrent_wr() {
    TEST_INIT();
    memleak_start();
    int i, j, r;
    int nf = 8;
    char buf[64];
    char body[64];

    thread_t *tid_wr = alca(thread_t, nf);
    void **thread_ret_wr = alca(void *, nf);
    fdb_file_handle *dbfile;
    fdb_kvs_handle **kvs = alca(fdb_kvs_handle*, nf);
    fdb_doc *rdoc = NULL;
    fdb_status status;
    randomize();
    rm_storage_fs();
    r = system(SHELL_DEL" e2edb_main > errorlog.txt");
    fdb_iterator *it;
    (void)r;

    // create dbfile
    fdb_config fconfig = fdb_get_default_config();
    fconfig.num_keeping_headers = 10;
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    fconfig.compaction_mode  = FDB_COMPACTION_MANUAL;
    fdb_open(&dbfile, "e2edb_main", &fconfig);

    // open dbfiles
    for (i = 0; i < nf; i++) {
        sprintf(buf, "e2edb_kv%d", i);
        status = fdb_kvs_open(dbfile, &kvs[i], buf, &kvs_config);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
    }

    // initial commits
    for (j = 0; j < 10; j++) {
        for (i = 0; i < nf; i++) {
            sprintf(buf, "%dkey%d", j, i);
            sprintf(body, "commit%d", j);
            status = fdb_set_kv(kvs[i], buf, strlen(buf), body, strlen(body));
            TEST_CHK(status == FDB_RESULT_SUCCESS);
        }
        status = fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
    }

    // run update thread on each file to enter reuse
    for (i = 0; i < nf; i++) {
        thread_create(&tid_wr[i], update_thread, (void*)kvs[i]);
    }

    // join and rollback
    for (i = 0; i < nf; i++) {
        thread_join(tid_wr[i], &thread_ret_wr[i]);
        status = fdb_rollback(&kvs[i], 7);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
    }

    status = fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    for (i = 0; i < nf; i++) {
        // verify rollback kvs
        status = fdb_iterator_init(kvs[i], &it, NULL, 0,
                                   NULL, 0, FDB_ITR_NONE);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        j = 0;
        do {
            status = fdb_iterator_get(it, &rdoc);
            TEST_CHK (status == FDB_RESULT_SUCCESS);
            fdb_doc_free(rdoc);
            rdoc=NULL;
            j++;
        } while (fdb_iterator_next(it) != FDB_RESULT_ITERATOR_FAIL);
        TEST_CHK(j==7);
        fdb_iterator_close(it);
    }

    fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);
    fdb_close(dbfile);
    fdb_shutdown();

    memleak_end();

    r = system(SHELL_DEL" e2edb_main > errorlog.txt");
    (void)r;

    TEST_RESULT("TEST: e2e multi kvs concurrent wr test");
}

void e2e_multi_kvs_concurrent_wr_compact() {
    TEST_INIT();
    memleak_start();
    int i, j, r;
    int nf = 4;
    char buf[64];

    thread_t *tid_wr = alca(thread_t, nf*nf);
    void **thread_ret_wr = alca(void *, nf*nf);
    fdb_file_handle **dbfiles = alca(fdb_file_handle*, nf);
    fdb_kvs_handle **kvs = alca(fdb_kvs_handle*, nf*nf);
    fdb_status status;
    randomize();
    rm_storage_fs();
    r = system(SHELL_DEL" e2edb_ex* > errorlog.txt");
    (void)r;

    // create dbfile
    fdb_config fconfig = fdb_get_default_config();
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    fconfig.compaction_mode  = FDB_COMPACTION_MANUAL;

    // open dbfiles
    for (i = 0; i < nf; ++i) {
        sprintf(buf, "e2edb_ex%d", i);
        status = fdb_open(&dbfiles[i], buf, &fconfig);
        TEST_CHK(status == FDB_RESULT_SUCCESS);

        for (j = i*nf; j < (i * nf + nf); ++j) {
            sprintf(buf, "e2edb_kv%d", j);
            status = fdb_kvs_open(dbfiles[i], &kvs[j], buf, &kvs_config);
            TEST_CHK(status == FDB_RESULT_SUCCESS);
        }
    }

    // initial commits
    for (i = 0; i < nf; i++) {
        status = fdb_commit(dbfiles[i], FDB_COMMIT_MANUAL_WAL_FLUSH);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
    }

    // run update thread on each file to enter reuse
    for (i = 0; i < (nf * nf); i++) {
        thread_create(&tid_wr[i], update_thread, (void*)kvs[i]);
    }

    // join update threads
    for (i = 0; i < (nf * nf); i++) {
      thread_join(tid_wr[i], &thread_ret_wr[i]);
      TEST_CHK(status == FDB_RESULT_SUCCESS);
    }

    // more commits
    for (i = 0; i < nf; i++) {
        status = fdb_commit(dbfiles[i], FDB_COMMIT_MANUAL_WAL_FLUSH);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
    }

    for (i = 0; i < nf; i++) {
        fdb_close(dbfiles[i]);
    }
    fdb_shutdown();
    memleak_end();

    TEST_RESULT("TEST: e2e multi kvs concurrent wr test with compaction");
}

int main() {

    // Note: following tests are temporarily disabled due to
    // the keeping header violation issue by rollback/snapshot API.
    //
    //   - e2e_multi_kvs_concurrent_wr();

    /* Multiple kvstores under reuse with rollback */
    // e2e_multi_kvs_concurrent_wr();

    /* Multiple kvstores under reuse with rollback and compaction */
    e2e_multi_kvs_concurrent_wr_compact();

    /* Multiple dbfiles after stale block reuse */
    e2e_multi_dbfile_concurrent_wr();

    /* Concurrent readers and writers after stale block reuse, without
       and with compaction */
    e2e_concurrent_reader_writer(false);
    e2e_concurrent_reader_writer(true);     // w.compaction

    e2e_robust_test();
    e2e_concurrent_scan_test();
    e2e_async_manual_compact_test();
    e2e_index_basic_test();
    e2e_index_walflush_test_no_deletes_auto_compact();
    e2e_index_walflush_autocompact_test();
    e2e_index_normal_commit_autocompact_test();

    /* Data loading with concurrent compaction */
    e2e_scan_compact_upto_test();

    /* Crash recovery with e2e workload, without and with a rollback */
    e2e_crash_recover_test(false);
    e2e_crash_recover_test(true);           // w.rollback

    return 0;
}
