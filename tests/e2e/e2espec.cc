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
#include "e2espec.h"
#include "test.h"


void gen_random(char *s, const int len) {
    if (len < 1){
        return;
    }

    static const char alphanum[] =
        "0123456789"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz";

    for (int i = 0; i < len; ++i) {
        s[i] = alphanum[rand() % (sizeof(alphanum) - 1)];
    }
    s[len-1] = '\0';
}

void gen_person(person_t *p){

    p->age = rand() % 100;
    gen_random(p->key, 64);
    gen_random(p->name, 128);
    gen_random(p->city, 12);
    gen_random(p->state, 2);
    gen_random(p->desc, 512);
}

void gen_index_params(idx_prams_t *params){
    const int len = 12;
    char min[len], max[len], tmp[len];

    // generate some random range
    gen_random(min,len);
    gen_random(max,len);

    if(strcmp(max, min) < 0){
        // swap min max
        memcpy(tmp, min, strlen(min));
        memcpy(min, max, strlen(max));
        memcpy(max, tmp, strlen(max));
    }
    sprintf(params->min, "%s", min);
    sprintf(params->max, "%s", max);
}

void reset_storage_index(storage_t *st){
    gen_index_params(st->index_params);
}

storage_t *init_storage(fdb_config *m_fconfig,
                  fdb_config *r_fconfig,
                  fdb_kvs_config *kvs_config,
                  idx_prams_t *idxp, checkpoint_t *v_chk,
                  bool walflush)
{

    storage_t *st = (storage_t *)malloc(sizeof(storage_t));
    st->v_chk = v_chk;
    st->index_params = idxp;
    st->walflush = walflush;

    // init dbs
    fdb_open(&st->main, E2EDB_MAIN, m_fconfig);
    fdb_kvs_open(st->main, &st->all_docs, E2EKV_ALLDOCS,  kvs_config);
    fdb_kvs_open(st->main, &st->index1, E2EKV_INDEX1,  kvs_config);
    fdb_kvs_open(st->main, &st->index2, E2EKV_INDEX2,  kvs_config);

    fdb_open(&st->records, E2EDB_RECORDS, r_fconfig);
    fdb_kvs_open(st->records, &st->rtx, E2EKV_RECORDS,  kvs_config);
    fdb_kvs_open(st->records, &st->chk, E2EKV_CHECKPOINTS,  kvs_config);
    return st;
}

void e2e_fdb_shutdown(storage_t *st){

    fdb_close(st->main);
    fdb_close(st->records);
    fdb_shutdown();
    free(st);
}

void rm_storage_fs()
{
    // remove previous dummy files
    int r;
    char cmd[64];

    sprintf(cmd, SHELL_DEL" %s*>errorlog.txt", E2EDB_MAIN);
    r = system(cmd);
    (void)r;

    sprintf(cmd, SHELL_DEL" %s*>errorlog.txt", E2EDB_RECORDS);
    r = system(cmd);
    (void)r;
}

/*
 * save a transaction doc into the records db
 */
void save_tx(storage_t *st, void *key, size_t keylen, tx_type_t type){

    TEST_INIT();
    char txkey[12];
    transaction_t *tx;
    fdb_status status;

    gen_random(txkey, 12);
    tx = (transaction_t*)malloc(sizeof(transaction_t));
    memset(tx, 0, sizeof(transaction_t));
    tx->type = type;
    tx->refkey_len = keylen;
    memcpy(tx->refkey, key, keylen);

    status = fdb_set_kv(st->rtx, txkey, 12,
                        tx, sizeof(transaction_t));
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    free(tx);
    tx=NULL;

}

/*
 * check whether doc is within storage index range
 *
 * TODO: custom compare
 */
bool is_indexed(idx_prams_t *idxp, person_t *p){

    char *mink = idxp->min;
    char *maxk = idxp->max;
    if ((strcmp(p->name, mink) >= 0) &&
           (strcmp(p->name, maxk) <= 0)){
            return true;
    }
    return false;
}

/*
 * 1. save a person doc into main db
 * 2. update indexes to reflect new doc
 * 3. record set transaction in records db
 */
void e2e_fdb_set_person(storage_t *st, person_t *p){

    TEST_INIT();
    fdb_status status;
    fdb_doc *doc;
    bool indexed;
    bool existed;

    fdb_doc_create(&doc, p->key, strlen(p->key),
                   NULL, 0, p, sizeof(person_t));
    status = fdb_get(st->all_docs, doc);
    existed = (status == FDB_RESULT_SUCCESS);

    // main person.key -> person doc
    status = fdb_set(st->all_docs, doc);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // index person.name -> person doc
    status = fdb_set_kv(st->index1, p->name, strlen(p->name), doc->key, doc->keylen);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // index person.name -> person age
    status = fdb_set_kv(st->index2, p->name, strlen(p->name), (void *)&p->age, sizeof(int));
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // update transaction db
    save_tx(st, doc->key, doc->keylen, SET_PERSON);

    if(!existed){  // new doc
        indexed = is_indexed(st->index_params, p);
        if(indexed){  // within storage index
            // update verification checkpoint
            st->v_chk->num_indexed++;
            st->v_chk->sum_age_indexed+=p->age;
        }
        st->v_chk->ndocs += 1;
    }

    fdb_doc_free(doc);
    doc=NULL;

}

/*
 * 1. remove a person doc from main db
 * 2. update indexes to reflect new doc
 * 3. record delete transaction in records db
 */
void e2e_fdb_del_person(storage_t *st, person_t *p){
    TEST_INIT();

    fdb_status status;
    fdb_doc *doc = NULL;
    bool indexed;
    bool existed;

    fdb_doc_create(&doc, p->key, strlen(p->key), NULL, 0, NULL, 0);

    status = fdb_get(st->all_docs, doc);
    existed = (status == FDB_RESULT_SUCCESS);

    // main person.key -> person doc
    status = fdb_del(st->all_docs, doc);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // index person.name -> person doc
    status = fdb_del_kv(st->index1, p->name, strlen(p->name));
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // index person.name -> person age
    status = fdb_del_kv(st->index2, p->name, strlen(p->name));
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // update transaction db
    save_tx(st, doc->key, doc->keylen, DEL_PERSON);

    if(existed){ // check if was indexed
        indexed = is_indexed(st->index_params, p);
        if(indexed){  // within storage index
            // update verification checkpoint
            st->v_chk->num_indexed--;
            st->v_chk->sum_age_indexed-=p->age;
        }
        st->v_chk->ndocs -= 1;
    }

    fdb_doc_free(doc);
    doc=NULL;

}

void e2e_fdb_commit(fdb_file_handle* fhandle, bool walflush){

    TEST_INIT();

    fdb_status status;

    if(walflush){
        status = fdb_commit(fhandle, FDB_COMMIT_MANUAL_WAL_FLUSH);
    } else { // normal
        status = fdb_commit(fhandle, FDB_COMMIT_NORMAL);
    }

    TEST_CHK(status == FDB_RESULT_SUCCESS);

}

/*
 * begin a new transaction and update storage state
 */
void start_checkpoint(storage_t *st)
{
    TEST_INIT();

    checkpoint_t *chk;
    fdb_status status;
    fdb_doc *chk_doc = NULL;
    char rbuf[256];

    status = fdb_begin_transaction(st->records, FDB_ISOLATION_READ_COMMITTED);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // create opening checkpoint doc
    chk = create_checkpoint(st, START_CHECKPOINT);
    fdb_doc_create(&chk_doc, chk->key, strlen(chk->key),
                   NULL, 0, chk, sizeof(checkpoint_t));

    // save checkpoint transaction
    save_tx(st, chk_doc->key, chk_doc->keylen, START_CHECKPOINT);
    status = fdb_set(st->chk, chk_doc);
    TEST_CHK(status == FDB_RESULT_SUCCESS);


#ifdef __DEBUG_E2E
    sprintf(rbuf, "start checkpoint[seqno:%llu]",chk->seqnum_all);
    TEST_RESULT(rbuf);
#endif

    free(chk);
    fdb_doc_free(chk_doc);
    chk_doc=NULL;
    chk=NULL;


}

/*
 * save current state of db keeping track of last seqnum for rollback
 * also close open transactions and commit all file handles
 *
 * returns key of checkpoint doc for verification
 */
void end_checkpoint(storage_t *st)
{
    TEST_INIT();

    fdb_status status;
    fdb_doc *chk_doc = NULL;
    checkpoint_t *chk;
    char rbuf[256];

    // create closing checkpoint doc
    chk = create_checkpoint(st, END_CHECKPOINT);
    fdb_doc_create(&chk_doc, chk->key, strlen(chk->key),
                   NULL, 0, chk, sizeof(checkpoint_t));

    // save checkpoint transaction
    save_tx(st, chk_doc->key, chk_doc->keylen, END_CHECKPOINT);

    // end transaction and commit records db
    if(st->walflush){
        status = fdb_end_transaction(st->records, FDB_COMMIT_MANUAL_WAL_FLUSH);
    } else {
        status = fdb_end_transaction(st->records, FDB_COMMIT_NORMAL);
    }

    // save checkpoint doc
    status = fdb_set(st->chk, chk_doc);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

#ifdef __DEBUG_E2E
    sprintf(rbuf, "end checkpoint[seqno:%llu]",chk->seqnum_all);
    TEST_RESULT(rbuf);
#endif

    free(chk);
    fdb_doc_free(chk_doc);
    chk_doc=NULL;
    chk=NULL;

}


/*
 * cancel checkpoint currently in progress
 * requires deleting docs set within this checkpoint
 * from indexes
 */
void e2e_fdb_cancel_checkpoint(storage_t *st)
{
    TEST_INIT();

    fdb_kvs_info info;
    fdb_doc *doc = NULL;
    fdb_status status;
    checkpoint_t *chk;
    char rbuf[256];

    status = fdb_get_kvs_info(st->chk, &info);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // get last stored checkpoint
    status = fdb_doc_create(&doc, NULL, 0, NULL, 0, NULL, 0);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    doc->seqnum = info.last_seqnum;
    fdb_get_byseq(st->chk, doc);
    chk = (checkpoint_t *)doc->body;

    // last check point must be start
    TEST_CHK(chk->type == START_CHECKPOINT);

    // rollback main kv and indexes
    status = fdb_rollback(&st->all_docs, chk->seqnum_all);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_rollback(&st->index1, chk->seqnum_idx1);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_rollback(&st->index2, chk->seqnum_idx2);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // restore checkpoint
    memcpy(st->v_chk, chk, sizeof(checkpoint_t));

    // cancel
    status = fdb_abort_transaction(st->records);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    sprintf(rbuf, "revert to checkpoint[seqno:%llu]\n",chk->seqnum_all);
    TEST_RESULT(rbuf);
}

/*
 * make a new checkpoint doc based on state of current storage
 */
checkpoint_t* create_checkpoint(storage_t *st, tx_type_t type)
{
    TEST_INIT();

    fdb_status status;
    fdb_kvs_info info;
    fdb_iterator *it;
    fdb_doc *rdoc = NULL;
    fdb_kvs_handle *snap_kv1, *snap_kv2;
    char *mink = st->index_params->min;
    char *maxk = st->index_params->max;
    checkpoint_t *chk = (checkpoint_t *)malloc(sizeof(checkpoint_t));
    memset(chk, 0, sizeof(checkpoint_t));

    // commit
    e2e_fdb_commit(st->main, st->walflush);

    // get last seqnum of main kvs and indees
    status = fdb_get_kvs_info(st->all_docs, &info);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    chk->seqnum_all = info.last_seqnum;
    status = fdb_get_kvs_info(st->index1, &info);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    chk->seqnum_idx1 = info.last_seqnum;
    status = fdb_get_kvs_info(st->index2, &info);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    chk->seqnum_idx2 = info.last_seqnum;


    // generate check point stats based on current state of db
    gen_random(chk->key, 12);
    chk->ndocs = info.doc_count;
    chk->balance = 0;
    chk->type = type;

    //use snapshot based iterator
    status = fdb_snapshot_open(st->index1, &snap_kv1, chk->seqnum_idx1);
    TEST_CHK (status == FDB_RESULT_SUCCESS);
    status = fdb_snapshot_open(st->index2, &snap_kv2, chk->seqnum_idx2);
    TEST_CHK (status == FDB_RESULT_SUCCESS);

    status = fdb_iterator_init(snap_kv1, &it, mink, 12,
                               maxk, 12, FDB_ITR_NO_DELETES);
    if (status == FDB_RESULT_SUCCESS) {
        do {
            status = fdb_iterator_get(it, &rdoc);
            if (status == FDB_RESULT_SUCCESS){
                if ((strcmp((char *)rdoc->key, mink) >= 0) &&
                       (strcmp((char *)rdoc->key, maxk) <= 0)){
                    // doc was in range of current index
                    chk->num_indexed++;

                    // get from 2nd idx
                    status = fdb_get(snap_kv2, rdoc);
                    TEST_CHK (status == FDB_RESULT_SUCCESS);
                    chk->sum_age_indexed+= *((int *)rdoc->body);
                }
                fdb_doc_free(rdoc);
                rdoc=NULL;
            }
        } while (fdb_iterator_next(it) != FDB_RESULT_ITERATOR_FAIL);
    }

    fdb_iterator_close(it);
    fdb_kvs_close(snap_kv1);
    fdb_kvs_close(snap_kv2);

    return chk;
}


