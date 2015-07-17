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

#include "libforestdb/forestdb.h"

//#define __DEBUG_E2E

#ifdef __cplusplus
extern "C" {
#endif

static const char E2EDB_MAIN[] = "e2edb_main";
static const char E2EDB_RECORDS[] = "e2edb_records";
static const char E2EKV_ALLDOCS[] = "e2ekv_alldocs";
static const char E2EKV_INDEX1[] = "e2ekv_index1";
static const char E2EKV_INDEX2[] = "e2ekv_index2";
static const char E2EKV_RECORDS[] = "e2ekv_rtx";
static const char E2EKV_CHECKPOINTS[] = "e2ekv_chk";
static const char RECORD_DOCKEY[] = "e2edoc_records";
static const int KEYSPACE_LEN = 6;
static const int MAXKEY_LEN = 1024;
static const int MAXITR_LEN = 12;

static const int LOAD_FACTOR = 1;

typedef uint16_t tx_type_t;
enum {
    SET_PERSON = 0x01,
    DEL_PERSON = 0x02,
    ACC_DEPOSIT = 0x03,
    ACC_WITHDRAW = 0x04,
    START_CHECKPOINT = 0x05,
    END_CHECKPOINT = 0x06
};

typedef struct {
    char key[MAXKEY_LEN];
    char name[MAXKEY_LEN];
    char city[256];
    char state[256];
    char desc[1024];
    char keyspace[KEYSPACE_LEN];
    int age;
}person_t;

typedef struct {
    char min[MAXITR_LEN];
    char max[MAXITR_LEN];
}idx_prams_t;

typedef struct {
    int amount;
    char refkey[MAXKEY_LEN];
    size_t refkey_len;
    tx_type_t type;
}transaction_t;

typedef struct {
    char key[MAXKEY_LEN];
    int ndocs;
    int num_indexed;
    int sum_age_indexed;
    uint16_t balance;
    fdb_seqnum_t seqnum_all;
    fdb_seqnum_t seqnum_idx1;
    fdb_seqnum_t seqnum_idx2;
    tx_type_t type;
}checkpoint_t;


typedef struct {

    fdb_file_handle *main;
    fdb_kvs_handle *all_docs;
    fdb_kvs_handle *index1;
    fdb_kvs_handle *index2;

    fdb_file_handle *records;
    fdb_kvs_handle *rtx;
    fdb_kvs_handle *chk;
    checkpoint_t *v_chk;
    idx_prams_t *index_params;

    char keyspace[KEYSPACE_LEN];
    bool walflush;
    bool verify_set;
}storage_t;

// generators
void gen_random(char *s, const int len);
void gen_index_params(idx_prams_t *params);
void gen_person(person_t *p);

// fdb wrappers
void e2e_fdb_set_person(storage_t *st, person_t *p);
void e2e_fdb_del_person(storage_t *st, person_t *p);
void e2e_fdb_cancel_checkpoint(storage_t *st);
void e2e_fdb_commit(fdb_file_handle* fhandle, bool walflush);
void e2e_fdb_close(storage_t *st);
void e2e_fdb_shutdown(storage_t *st);

// checkpointing
void start_checkpoint(storage_t *st);
void end_checkpoint(storage_t *st);
checkpoint_t* create_checkpoint(storage_t *st, tx_type_t type);

// storage
storage_t *init_storage(fdb_config *m_fconfig, fdb_config *r_fconfig,
        fdb_kvs_config *kvs_config, idx_prams_t *idxp,
        checkpoint_t *v_chk, bool walflush);

void reset_storage_index(storage_t *st);
void rm_storage_fs();

// utility
bool is_indexed(idx_prams_t *idxp, person_t *p);
void save_tx(storage_t *st, void *key, size_t keylen, tx_type_t type);
fdb_kvs_handle *scan(storage_t *st, fdb_kvs_handle *reuse_kv);

#ifdef __cplusplus
}
#endif
