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

#include "internal_types.h"
#include "functional_util.h"

// lexicographically compares two variable-length binary streams
#define MIN(a,b) (((a)<(b))?(a):(b))
static int _multi_kv_test_keycmp(void *key1, size_t keylen1, void *key2, size_t keylen2)
{
    if (keylen1 == keylen2) {
        return memcmp(key1, key2, keylen1);
    }else {
        size_t len = MIN(keylen1, keylen2);
        int cmp = memcmp(key1, key2, len);
        if (cmp != 0) return cmp;
        else {
            return (int)((int)keylen1 - (int)keylen2);
        }
    }
}


#define MULTI_KV_VAR_CMP (0x1)
void multi_kv_test(uint8_t opt, size_t chunksize)
{
    TEST_INIT();

    int n = 100;
    int i, r;
    char key[256], meta[256], value[256];
    char keystr[] = "key%06d";
    char metastr[] = "meta%06d";
    char metastr_kv[] = "meta%06d(kv)";
    char valuestr[] = "value%08d";
    char valuestr_kv[] = "value%08d (kv instance)";
    void *value_out;
    size_t valuelen;

    char *kvs_names[] = {NULL, (char*)"kv1"};
    fdb_custom_cmp_variable functions[] = {_multi_kv_test_keycmp,
                                           _multi_kv_test_keycmp};

    fdb_file_handle *dbfile;
    fdb_kvs_handle *db, *kv1;
    fdb_config config;
    fdb_kvs_config kvs_config;
    fdb_doc *doc;
    fdb_file_info file_info;
    fdb_kvs_info kvs_info;
    fdb_status s;

    sprintf(value, SHELL_DEL" multi_kv_test*");
    r = system(value);
    (void)r;

    memleak_start();

    config = fdb_get_default_config();
    kvs_config = fdb_get_default_kvs_config();
    config.seqtree_opt = FDB_SEQTREE_USE; // enable seqtree since get_byseq
    config.chunksize = chunksize;
    config.multi_kv_instances = true;
    config.wal_threshold = 50;
    config.buffercache_size = 0;

    s = fdb_open(&dbfile, "./multi_kv_test", &config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    if (opt & MULTI_KV_VAR_CMP) {
        kvs_config.custom_cmp = _multi_kv_test_keycmp;
    }
    s = fdb_kvs_open_default(dbfile, &db, &kvs_config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    // insert using 'default' instance
    for (i=0;i<n;++i) {
        sprintf(key, keystr, i);
        sprintf(meta, metastr, i);
        sprintf(value, valuestr, i);
        fdb_doc_create(&doc, key, strlen(key)+1, meta,
                           strlen(meta)+1, value, strlen(value)+1);
        s = fdb_set(db, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        fdb_doc_free(doc);
    }

    // retrieve from WAL
    for (i=0;i<n;++i){
        // by key
        sprintf(key, keystr, i);
        sprintf(meta, metastr, i);
        sprintf(value, valuestr, i);
        s = fdb_get_kv(db, key, strlen(key)+1, &value_out, &valuelen);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(value, value_out, valuelen);
        fdb_free_block(value_out);

        // metaonly by key
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, NULL, 0);
        s = fdb_get_metaonly(db, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(doc->key, key, doc->keylen);
        TEST_CMP(doc->meta, meta, doc->metalen);
        fdb_doc_free(doc);

        // by seq
        fdb_doc_create(&doc, NULL, 0, NULL, 0, NULL, 0);
        doc->seqnum = i+1;
        s = fdb_get_byseq(db, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(doc->key, key, doc->keylen);
        TEST_CMP(doc->body, value, doc->bodylen);
        fdb_doc_free(doc);

        // metaonly by seq
        fdb_doc_create(&doc, NULL, 0, NULL, 0, NULL, 0);
        doc->seqnum = i+1;
        s = fdb_get_metaonly_byseq(db, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(doc->key, key, doc->keylen);
        TEST_CMP(doc->meta, meta, doc->metalen);
        fdb_doc_free(doc);
    }
    s = fdb_commit(dbfile, FDB_COMMIT_NORMAL);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    // info check
    s = fdb_get_file_info(dbfile, &file_info);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    TEST_CHK(file_info.doc_count == (uint64_t)n);
    TEST_CHK(file_info.num_kv_stores == 1);
    s = fdb_get_kvs_info(db, &kvs_info);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    TEST_CHK(kvs_info.doc_count == (uint64_t)n);

    kvs_config.create_if_missing = false;
    s = fdb_kvs_open(dbfile, &kv1, "kv1", &kvs_config);
    TEST_CHK(s != FDB_RESULT_SUCCESS); // must fail

    kvs_config.create_if_missing = true;
    s = fdb_kvs_open(dbfile, &kv1, "kv1", &kvs_config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    // insert using 'kv1' instance
    for (i=0;i<n;++i){
        sprintf(key, keystr, i);
        sprintf(meta, metastr_kv, i);
        sprintf(value, valuestr_kv, i);
        fdb_doc_create(&doc, key, strlen(key)+1, meta,
                           strlen(meta)+1, value, strlen(value)+1);
        s = fdb_set(kv1, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        fdb_doc_free(doc);
    }

    // retrieve from WAL
    for (i=0;i<n;++i){
        // by key
        sprintf(key, keystr, i);
        sprintf(meta, metastr_kv, i);
        sprintf(value, valuestr_kv, i);
        s = fdb_get_kv(kv1, key, strlen(key)+1, &value_out, &valuelen);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(value, value_out, valuelen);
        fdb_free_block(value_out);

        // metaonly by key
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, NULL, 0);
        s = fdb_get_metaonly(kv1, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(doc->key, key, doc->keylen);
        TEST_CMP(doc->meta, meta, doc->metalen);
        fdb_doc_free(doc);

        // by seq
        fdb_doc_create(&doc, NULL, 0, NULL, 0, NULL, 0);
        doc->seqnum = i+1;
        s = fdb_get_byseq(kv1, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(doc->key, key, doc->keylen);
        TEST_CMP(doc->body, value, doc->bodylen);
        fdb_doc_free(doc);

        // metaonly by seq
        fdb_doc_create(&doc, NULL, 0, NULL, 0, NULL, 0);
        doc->seqnum = i+1;
        s = fdb_get_metaonly_byseq(kv1, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(doc->key, key, doc->keylen);
        TEST_CMP(doc->meta, meta, doc->metalen);
        fdb_doc_free(doc);
    }
    s = fdb_commit(dbfile, FDB_COMMIT_NORMAL);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    // retrieve from hb+trie
    for (i=0;i<n;++i){
        // ==== the default instance ====
        // by key
        sprintf(key, keystr, i);
        sprintf(meta, metastr, i);
        sprintf(value, valuestr, i);
        s = fdb_get_kv(db, key, strlen(key)+1, &value_out, &valuelen);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(value, value_out, valuelen);
        fdb_free_block(value_out);

        // metaonly by key
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, NULL, 0);
        s = fdb_get_metaonly(db, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(doc->key, key, doc->keylen);
        TEST_CMP(doc->meta, meta, doc->metalen);
        fdb_doc_free(doc);

        // by seq
        fdb_doc_create(&doc, NULL, 0, NULL, 0, NULL, 0);
        doc->seqnum = i+1;
        s = fdb_get_byseq(db, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(doc->key, key, doc->keylen);
        TEST_CMP(doc->body, value, doc->bodylen);
        fdb_doc_free(doc);

        // metaonly by seq
        fdb_doc_create(&doc, NULL, 0, NULL, 0, NULL, 0);
        doc->seqnum = i+1;
        s = fdb_get_metaonly_byseq(db, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(doc->key, key, doc->keylen);
        TEST_CMP(doc->meta, meta, doc->metalen);

        // by offset
        s = fdb_get_byoffset(db, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(doc->key, key, doc->keylen);
        TEST_CMP(doc->body, value, doc->bodylen);
        fdb_doc_free(doc);

        // ==== 'kv1' instance ====
        // by key
        sprintf(meta, metastr_kv, i);
        sprintf(value, valuestr_kv, i);
        s = fdb_get_kv(kv1, key, strlen(key)+1, &value_out, &valuelen);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(value, value_out, valuelen);
        fdb_free_block(value_out);

        // metaonly by key
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, NULL, 0);
        s = fdb_get_metaonly(kv1, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(doc->key, key, doc->keylen);
        TEST_CMP(doc->meta, meta, doc->metalen);
        fdb_doc_free(doc);

        // by seq
        fdb_doc_create(&doc, NULL, 0, NULL, 0, NULL, 0);
        doc->seqnum = i+1;
        s = fdb_get_byseq(kv1, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(doc->key, key, doc->keylen);
        TEST_CMP(doc->body, value, doc->bodylen);
        fdb_doc_free(doc);

        // metaonly by seq
        fdb_doc_create(&doc, NULL, 0, NULL, 0, NULL, 0);
        doc->seqnum = i+1;
        s = fdb_get_metaonly_byseq(kv1, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(doc->key, key, doc->keylen);
        TEST_CMP(doc->meta, meta, doc->metalen);

        // by offset
        s = fdb_get_byoffset(kv1, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(doc->key, key, doc->keylen);
        TEST_CMP(doc->body, value, doc->bodylen);
        fdb_doc_free(doc);
    }

    // info check
    s = fdb_get_file_info(dbfile, &file_info);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    TEST_CHK(file_info.doc_count == (uint64_t)n*2);
    TEST_CHK(file_info.num_kv_stores == 2);
    s = fdb_get_kvs_info(db, &kvs_info);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    TEST_CHK(kvs_info.doc_count == (uint64_t)n);
    s = fdb_get_kvs_info(kv1, &kvs_info);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    TEST_CHK(kvs_info.doc_count == (uint64_t)n);

    s = fdb_kvs_close(kv1);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_close(dbfile);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    if (opt & MULTI_KV_VAR_CMP) {
        s = fdb_open_custom_cmp(&dbfile, "./multi_kv_test", &config,
                                2, kvs_names, functions);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
    } else {
        s = fdb_open(&dbfile, "./multi_kv_test", &config);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
    }
    s = fdb_kvs_open(dbfile, &db, NULL, &kvs_config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_kvs_open(dbfile, &kv1, "kv1", &kvs_config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    // retrieve check after reopen
    for (i=0;i<n;++i){
        sprintf(key, keystr, i);
        sprintf(value, valuestr, i);
        s = fdb_get_kv(db, key, strlen(key)+1, &value_out, &valuelen);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(value, value_out, valuelen);
        s = fdb_free_block(value_out);
        TEST_CHK(s == FDB_RESULT_SUCCESS);

        sprintf(value, valuestr_kv, i);
        s = fdb_get_kv(kv1, key, strlen(key)+1, &value_out, &valuelen);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(value, value_out, valuelen);
        s = fdb_free_block(value_out);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
    }
    // info check after reopen
    s = fdb_get_file_info(dbfile, &file_info);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    TEST_CHK(file_info.doc_count == (uint64_t)n*2);
    s = fdb_get_kvs_info(db, &kvs_info);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    TEST_CHK(kvs_info.doc_count == (uint64_t)n);
    s = fdb_get_kvs_info(kv1, &kvs_info);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    TEST_CHK(kvs_info.doc_count == (uint64_t)n);

    s = fdb_compact(dbfile, "./multi_kv_test2");
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    // retrieve check after compaction
    for (i=0;i<n;++i){
        sprintf(key, keystr, i);
        sprintf(value, valuestr, i);
        s = fdb_get_kv(db, key, strlen(key)+1, &value_out, &valuelen);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(value, value_out, valuelen);
        fdb_free_block(value_out);

        sprintf(value, valuestr_kv, i);
        s = fdb_get_kv(kv1, key, strlen(key)+1, &value_out, &valuelen);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(value, value_out, valuelen);
        fdb_free_block(value_out);
    }
    // info check after compaction
    s = fdb_get_file_info(dbfile, &file_info);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    TEST_CHK(file_info.doc_count == (uint64_t)n*2);
    s = fdb_get_kvs_info(db, &kvs_info);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    TEST_CHK(kvs_info.doc_count == (uint64_t)n);
    s = fdb_get_kvs_info(kv1, &kvs_info);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    TEST_CHK(kvs_info.doc_count == (uint64_t)n);

    // reopen using "default" KVS name
    fdb_kvs_close(db);
    s = fdb_kvs_open(dbfile, &db, "default", &kvs_config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    for (i=0;i<n;++i){
        sprintf(key, keystr, i);
        sprintf(value, valuestr, i);
        s = fdb_get_kv(db, key, strlen(key)+1, &value_out, &valuelen);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(value, value_out, valuelen);
        fdb_free_block(value_out);
    }

    s = fdb_kvs_remove(dbfile, "kv1");
    // must fail due to opened handle
    TEST_CHK(s != FDB_RESULT_SUCCESS);

    // Close "kv1" handle
    s = fdb_kvs_close(kv1);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    // re-open with a new file handle
    fdb_file_handle *fhandle;
    if (opt & MULTI_KV_VAR_CMP) {
        s = fdb_open_custom_cmp(&fhandle, "./multi_kv_test2", &config,
                                2, kvs_names, functions);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
    } else {
        s = fdb_open(&fhandle, "./multi_kv_test2", &config);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
    }
    s = fdb_kvs_open(fhandle, &kv1, "kv1", &kvs_config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    // Try to remove "kv1" again, but should fail
    s = fdb_kvs_remove(dbfile, "kv1");
    TEST_CHK(s == FDB_RESULT_KV_STORE_BUSY);

    // closing super handles also closes all other sub-handles;
    s = fdb_close(fhandle);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_close(dbfile);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    // re-open
    if (opt & MULTI_KV_VAR_CMP) {
        s = fdb_open_custom_cmp(&dbfile, "./multi_kv_test2", &config,
                                2, kvs_names, functions);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
    } else {
        s = fdb_open(&dbfile, "./multi_kv_test2", &config);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
    }

    // remove "kv1" instance
    s = fdb_kvs_remove(dbfile, "kv1");
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_kvs_open(dbfile, &db, "default", &kvs_config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_kvs_open(dbfile, &kv1, "kv1", &kvs_config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    for (i=0;i<n;++i){
        sprintf(key, keystr, i);
        sprintf(value, valuestr, i);
        s = fdb_get_kv(db, key, strlen(key)+1, &value_out, &valuelen);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(value, value_out, valuelen);
        fdb_free_block(value_out);

        s = fdb_get_kv(kv1, key, strlen(key)+1, &value_out, &valuelen);
        TEST_CHK(s != FDB_RESULT_SUCCESS);
    }
    s = fdb_kvs_close(db);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_kvs_close(kv1);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    // remove "default" instance
    s = fdb_kvs_remove(dbfile, "default");
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_kvs_open(dbfile, &db, "default", &kvs_config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    for (i=0;i<n;++i){
        sprintf(key, keystr, i);
        s = fdb_get_kv(db, key, strlen(key)+1, &value_out, &valuelen);
        TEST_CHK(s != FDB_RESULT_SUCCESS);
    }
    s = fdb_kvs_close(db);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    // remove the empty "kv1" instance
    s = fdb_kvs_remove(dbfile, "kv1");
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    s = fdb_close(dbfile);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    s = fdb_shutdown();
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    memleak_end();

    if (opt & MULTI_KV_VAR_CMP) {
        TEST_RESULT("multiple KV instances basic test "
                    "(custom key order)");
    } else {
        TEST_RESULT("multiple KV instances basic test");
    }
}

void multi_kv_iterator_key_test(uint8_t opt, size_t chunksize)
{
    TEST_INIT();

    int n = 100;
    int i, r;
    char key[256], value[256];
    char keystr[] = "key%06d";
    char valuestr[] = "value%08d(%s)";
    fdb_file_handle *dbfile;
    fdb_kvs_handle *db, *kv1, *kv2;
    fdb_config config;
    fdb_kvs_config kvs_config;
    fdb_doc *doc = NULL;
    fdb_iterator *it;
    fdb_status s;

    sprintf(value, SHELL_DEL" multi_kv_test*");
    r = system(value);
    (void)r;

    memleak_start();

    config = fdb_get_default_config();
    kvs_config = fdb_get_default_kvs_config();
    config.seqtree_opt = FDB_SEQTREE_USE; // enable seqtree since get_byseq
    config.chunksize = chunksize;
    config.multi_kv_instances = true;
    config.wal_threshold = 1000;
    config.buffercache_size = 0;

    s = fdb_open(&dbfile, "./multi_kv_test", &config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    if (opt & MULTI_KV_VAR_CMP) {
        kvs_config.custom_cmp = _multi_kv_test_keycmp;
    }
    s = fdb_kvs_open(dbfile, &db, NULL, &kvs_config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_kvs_open(dbfile, &kv1, "kv1", &kvs_config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_kvs_open(dbfile, &kv2, "kv2", &kvs_config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    for (i=0;i<n;i+=2) {
        sprintf(key, keystr, i);
        sprintf(value, valuestr, i, "default");
        s = fdb_set_kv(db, key, strlen(key)+1, value, strlen(value)+1);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        sprintf(value, valuestr, i, "kv1");
        s = fdb_set_kv(kv1, key, strlen(key)+1, value, strlen(value)+1);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        sprintf(value, valuestr, i, "kv2");
        s = fdb_set_kv(kv2, key, strlen(key)+1, value, strlen(value)+1);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
    }
    fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);

    for (i=1;i<n;i+=2) {
        sprintf(key, keystr, i);
        sprintf(value, valuestr, i, "default");
        s = fdb_set_kv(db, key, strlen(key)+1, value, strlen(value)+1);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        sprintf(value, valuestr, i, "kv1");
        s = fdb_set_kv(kv1, key, strlen(key)+1, value, strlen(value)+1);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        sprintf(value, valuestr, i, "kv2");
        s = fdb_set_kv(kv2, key, strlen(key)+1, value, strlen(value)+1);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
    }
    fdb_commit(dbfile, FDB_COMMIT_NORMAL);

    // iterate on default KV instance
    i = 0;
    s = fdb_iterator_init(db, &it, NULL, 0, NULL, 0, FDB_ITR_NONE);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    do {
        s = fdb_iterator_get(it, &doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        sprintf(key, keystr, i);
        sprintf(value, valuestr, i, "default");
        TEST_CMP(doc->key, key, doc->keylen);
        TEST_CMP(doc->body, value, doc->bodylen);
        r = ((i%2 == 0)?(i/2):(50+i/2)) +1;
        TEST_CHK(doc->seqnum == (fdb_seqnum_t)r);
        fdb_doc_free(doc);
        doc = NULL;
        i++;
    } while (fdb_iterator_next(it) == FDB_RESULT_SUCCESS);
    TEST_CHK(i == n);
    fdb_iterator_close(it);

    // iterate in kv1 instance
    i = 0;
    s = fdb_iterator_init(kv1, &it, NULL, 0, NULL, 0, FDB_ITR_NONE);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    do {
        s = fdb_iterator_get(it, &doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        sprintf(key, keystr, i);
        sprintf(value, valuestr, i, "kv1");
        TEST_CMP(doc->key, key, doc->keylen);
        TEST_CMP(doc->body, value, doc->bodylen);
        r = ((i%2 == 0)?(i/2):(50+i/2)) +1;
        TEST_CHK(doc->seqnum == (fdb_seqnum_t)r);
        fdb_doc_free(doc);
        doc = NULL;
        i++;
    } while (fdb_iterator_next(it) == FDB_RESULT_SUCCESS);
    TEST_CHK(i == n);
    // reverse iterate in kv1 instance
    TEST_CHK(fdb_iterator_prev(it) == FDB_RESULT_SUCCESS);
    do {
        s = fdb_iterator_get(it, &doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        i--;
        sprintf(key, keystr, i);
        sprintf(value, valuestr, i, "kv1");
        TEST_CMP(doc->key, key, doc->keylen);
        TEST_CMP(doc->body, value, doc->bodylen);
        r = ((i%2 == 0)?(i/2):(50+i/2)) +1;
        TEST_CHK(doc->seqnum == (fdb_seqnum_t)r);
        fdb_doc_free(doc);
        doc = NULL;
    } while (fdb_iterator_prev(it) == FDB_RESULT_SUCCESS);
    TEST_CHK(i == 0);
    fdb_iterator_close(it);

    // iterate in kv2 instance
    i = 0;
    s = fdb_iterator_init(kv2, &it, NULL, 0, NULL, 0, FDB_ITR_NONE);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    do {
        s = fdb_iterator_get(it, &doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        sprintf(key, keystr, i);
        sprintf(value, valuestr, i, "kv2");
        TEST_CMP(doc->key, key, doc->keylen);
        TEST_CMP(doc->body, value, doc->bodylen);
        fdb_doc_free(doc);
        doc = NULL;
        i++;
    } while (fdb_iterator_next(it) == FDB_RESULT_SUCCESS);
    TEST_CHK(i == n);
    fdb_iterator_close(it);

    // partial iterate in kv1 instance
    i = 40;
    char key2[256];
    sprintf(key, keystr, 40);
    sprintf(key2, keystr, 59);
    s = fdb_iterator_init(kv1, &it, key, strlen(key)+1, key2, strlen(key2)+1,
                          FDB_ITR_NONE);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    do {
        s = fdb_iterator_get(it, &doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        sprintf(key, keystr, i);
        sprintf(value, valuestr, i, "kv1");
        TEST_CMP(doc->key, key, doc->keylen);
        TEST_CMP(doc->body, value, doc->bodylen);
        fdb_doc_free(doc);
        doc = NULL;
        i++;
    } while (fdb_iterator_next(it) == FDB_RESULT_SUCCESS);
    TEST_CHK(i == 60);
    fdb_iterator_close(it);

    s = fdb_kvs_close(kv1);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_kvs_close(kv2);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_close(dbfile);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_shutdown();
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    memleak_end();

    if (opt & MULTI_KV_VAR_CMP) {
        TEST_RESULT("multiple KV instances iterator test "
                    "(custom key order)");
    } else {
        TEST_RESULT("multiple KV instances iterator test");
    }
}

void multi_kv_iterator_seq_test(uint8_t opt, size_t chunksize)
{
    TEST_INIT();

    int n = 100;
    int i, r;
    char key[256], value[256];
    char keyBuf[256], valueBuf[256];
    char keystr[] = "key%06d";
    char valuestr[] = "value%08d(%s)";
    fdb_file_handle *dbfile;
    fdb_kvs_handle *db, *kv1, *kv2;
    fdb_config config;
    fdb_kvs_config kvs_config;
    fdb_doc *doc;
    fdb_iterator *it;
    fdb_status s;
    fdb_seqnum_t seqnum;

    sprintf(value, SHELL_DEL" multi_kv_test*");
    r = system(value);
    (void)r;

    memleak_start();

    config = fdb_get_default_config();
    kvs_config = fdb_get_default_kvs_config();
    config.seqtree_opt = FDB_SEQTREE_USE; // enable seqtree since get_byseq
    config.chunksize = chunksize;
    config.multi_kv_instances = true;
    config.wal_threshold = 1000;
    config.buffercache_size = 0;

    s = fdb_open(&dbfile, "./multi_kv_test", &config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    if (opt & MULTI_KV_VAR_CMP) {
        kvs_config.custom_cmp = _multi_kv_test_keycmp;
    }
    s = fdb_kvs_open(dbfile, &db, NULL, &kvs_config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_kvs_open(dbfile, &kv1, "kv1", &kvs_config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_kvs_open(dbfile, &kv2, "kv2", &kvs_config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    // write documents first time
    for (i=0;i<n;++i){
        sprintf(key, keystr, i);
        sprintf(value, valuestr, i, "default");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, value, strlen(value)+1);
        s = fdb_set(db, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        fdb_doc_free(doc);
        sprintf(value, valuestr, i, "kv1");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, value, strlen(value)+1);
        s = fdb_set(kv1, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        fdb_doc_free(doc);
        sprintf(value, valuestr, i, "kv2");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, value, strlen(value)+1);
        s = fdb_set(kv2, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        fdb_doc_free(doc);
    }
    s = fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    // re-write documents
    for (i=0;i<n;++i){
        sprintf(key, keystr, i);
        sprintf(value, valuestr, i, "default_second");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, value, strlen(value)+1);
        s = fdb_set(db, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        fdb_doc_free(doc);
        sprintf(value, valuestr, i, "kv1_second");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, value, strlen(value)+1);
        s = fdb_set(kv1, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        fdb_doc_free(doc);
        sprintf(value, valuestr, i, "kv2_second");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, value, strlen(value)+1);
        s = fdb_set(kv2, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        fdb_doc_free(doc);
    }
    s = fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    // write third time (even number docs only)
    for (i=0;i<n;i+=2){
        sprintf(key, keystr, i);
        sprintf(value, valuestr, i, "default_third");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, value, strlen(value)+1);
        s = fdb_set(db, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        fdb_doc_free(doc);
        sprintf(value, valuestr, i, "kv1_third");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, value, strlen(value)+1);
        s = fdb_set(kv1, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        fdb_doc_free(doc);
        sprintf(value, valuestr, i, "kv2_third");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, value, strlen(value)+1);
        s = fdb_set(kv2, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        fdb_doc_free(doc);
    }
    s = fdb_commit(dbfile, FDB_COMMIT_NORMAL);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    // pre-allocate memory and re-use it for the iterator return document
    s = fdb_doc_create(&doc, NULL, 0, NULL, 0, NULL, 0);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    doc->key = &keyBuf[0];
    doc->body = &valueBuf[0];

    // iterate in default KV instance
    i = 1;
    s = fdb_iterator_sequence_init(db, &it, 0, 0, FDB_ITR_NONE);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    while (fdb_iterator_next(it) == FDB_RESULT_SUCCESS) {
        s = fdb_iterator_get(it, &doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        i++;
    }
    TEST_CHK(i == n);
    fdb_iterator_close(it);

    // iterate in KV1
    i = 0;
    s = fdb_iterator_sequence_init(kv1, &it, 0, 0, FDB_ITR_NONE);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    do {
        s = fdb_iterator_get(it, &doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        if (i < 50) {
            r = i*2 + 1;
            seqnum = 100 + (i+1)*2;
            sprintf(value, valuestr, r, "kv1_second");
        } else {
            r = (i-50)*2;
            seqnum = 151 + i;
            sprintf(value, valuestr, r, "kv1_third");
        }
        sprintf(key, keystr, r);
        TEST_CMP(key, doc->key, doc->keylen);
        TEST_CMP(value, doc->body, doc->bodylen);
        TEST_CHK(doc->seqnum == seqnum);
        i++;
    } while (fdb_iterator_next(it) == FDB_RESULT_SUCCESS);
    TEST_CHK(i == n);
    // reverse iterate in KV1
    TEST_CHK(fdb_iterator_prev(it) == FDB_RESULT_SUCCESS);
    do {
        s = fdb_iterator_get(it, &doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        i--;
        if (i < 50) {
            r = i*2 + 1;
            seqnum = 100 + (i+1)*2;
            sprintf(value, valuestr, r, "kv1_second");
        } else {
            r = (i-50)*2;
            seqnum = 151 + i;
            sprintf(value, valuestr, r, "kv1_third");
        }
        sprintf(key, keystr, r);
        TEST_CMP(key, doc->key, doc->keylen);
        TEST_CMP(value, doc->body, doc->bodylen);
        TEST_CHK(doc->seqnum == seqnum);
    } while (fdb_iterator_prev(it) == FDB_RESULT_SUCCESS);
    TEST_CHK(i == 0);
    fdb_iterator_close(it);

    // iterate in KV2
    i = 0;
    s = fdb_iterator_sequence_init(kv2, &it, 0, 0, FDB_ITR_NONE);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    do {
        s = fdb_iterator_get(it, &doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        if (i < 50) {
            r = i*2 + 1;
            seqnum = 100 + (i+1)*2;
            sprintf(value, valuestr, r, "kv2_second");
        } else {
            r = (i-50)*2;
            seqnum = 151 + i;
            sprintf(value, valuestr, r, "kv2_third");
        }
        (void)seqnum;
        sprintf(key, keystr, r);
        i++;
    } while (fdb_iterator_next(it) == FDB_RESULT_SUCCESS);
    TEST_CHK(i == n);
    fdb_iterator_close(it);

    // partial iterate in KV1
    i = 0;
    s = fdb_iterator_sequence_init(kv1, &it, 150, 220, FDB_ITR_NONE);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    do {
        s = fdb_iterator_get(it, &doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        //printf("%d %s %s %d\n", i, (char*)doc->key, (char*)doc->body, (int)doc->seqnum);
        if (i<26) {
            r = 49 + i*2;
            seqnum = i*2 + 150;
            sprintf(value, valuestr, r, "kv1_second");
        } else {
            r = (i-26)*2;
            seqnum = 201 + (i-26);
            sprintf(value, valuestr, r, "kv1_third");
        }
        (void)seqnum;
        i++;
    } while (fdb_iterator_next(it) == FDB_RESULT_SUCCESS);
    TEST_CHK(i == 71);
    fdb_iterator_close(it);

    s = fdb_kvs_close(kv1);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_kvs_close(kv2);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_close(dbfile);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_shutdown();
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    // free up the pre-allocated buffer for iterator return document
    doc->key = NULL;
    doc->body = NULL;
    s = fdb_doc_free(doc);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    memleak_end();

    if (opt & MULTI_KV_VAR_CMP) {
        TEST_RESULT("multiple KV instances sequence iterator test "
                    "(custom key order)");
    } else {
        TEST_RESULT("multiple KV instances sequence iterator test");
    }
}

void multi_kv_txn_test(uint8_t opt, size_t chunksize)
{
    TEST_INIT();

    int n = 100;
    int i, r;
    char key[256], value[256];
    char keystr[] = "key%06d";
    char valuestr[] = "value%08d(%s)";
    fdb_file_handle *dbfile, *dbfile_txn1;
    fdb_kvs_handle *db, *kv1, *kv2;
    fdb_kvs_handle *txn1, *txn1_kv1, *txn1_kv2;
    fdb_config config;
    fdb_kvs_config kvs_config;
    fdb_doc *doc;
    fdb_status s;

    char *kvs_names[] = {(char*)"default", (char*)"kv1", (char*)"kv2"};
    fdb_custom_cmp_variable functions[] = {_multi_kv_test_keycmp,
                                           _multi_kv_test_keycmp,
                                           _multi_kv_test_keycmp};

    sprintf(value, SHELL_DEL" multi_kv_test*");
    r = system(value);
    (void)r;

    memleak_start();

    config = fdb_get_default_config();
    kvs_config = fdb_get_default_kvs_config();
    config.seqtree_opt = FDB_SEQTREE_USE; // enable seqtree since get_byseq
    config.chunksize = chunksize;
    config.multi_kv_instances = true;
    config.wal_threshold = 1000;
    config.buffercache_size = 0;

    s = fdb_open(&dbfile, "./multi_kv_test", &config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    if (opt & MULTI_KV_VAR_CMP) {
        kvs_config.custom_cmp = _multi_kv_test_keycmp;
    }
    s = fdb_kvs_open(dbfile, &db, NULL, &kvs_config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_kvs_open(dbfile, &kv1, "kv1", &kvs_config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_kvs_open(dbfile, &kv2, "kv2", &kvs_config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    // write documents first time
    for (i=0;i<n;++i){
        sprintf(key, keystr, i);
        sprintf(value, valuestr, i, "default");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, value, strlen(value)+1);
        s = fdb_set(db, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        fdb_doc_free(doc);
        sprintf(value, valuestr, i, "kv1");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, value, strlen(value)+1);
        s = fdb_set(kv1, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        fdb_doc_free(doc);
        sprintf(value, valuestr, i, "kv2");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, value, strlen(value)+1);
        s = fdb_set(kv2, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        fdb_doc_free(doc);
    }
    s = fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    // begin a transaction
    if (opt & MULTI_KV_VAR_CMP) {
        s = fdb_open_custom_cmp(&dbfile_txn1, "./multi_kv_test", &config,
                                3, kvs_names, functions);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
    } else {
        s = fdb_open(&dbfile_txn1, "./multi_kv_test", &config);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
    }
    s = fdb_kvs_open(dbfile_txn1, &txn1, NULL, &kvs_config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_kvs_open(dbfile_txn1, &txn1_kv1, "kv1", &kvs_config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_kvs_open(dbfile_txn1, &txn1_kv2, "kv2", &kvs_config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_begin_transaction(dbfile_txn1, FDB_ISOLATION_READ_COMMITTED);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    for (i=0;i<n;++i){
        sprintf(key, keystr, i);
        sprintf(value, valuestr, i, "default(txn)");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, value, strlen(value)+1);
        s = fdb_set(txn1, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        fdb_doc_free(doc);
        sprintf(value, valuestr, i, "kv1(txn)");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, value, strlen(value)+1);
        s = fdb_set(txn1_kv1, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        fdb_doc_free(doc);
        sprintf(value, valuestr, i, "kv2(txn)");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, value, strlen(value)+1);
        s = fdb_set(txn1_kv2, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        fdb_doc_free(doc);
    }

    // retrieve before commit (dirty read through the transaction)
    for (i=0;i<n;++i){
        sprintf(key, keystr, i);
        sprintf(value, valuestr, i, "default(txn)");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, NULL, 0);
        s = fdb_get(txn1, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(value, doc->body, doc->bodylen);
        fdb_doc_free(doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        sprintf(value, valuestr, i, "kv1(txn)");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, NULL, 0);
        s = fdb_get(txn1_kv1, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(value, doc->body, doc->bodylen);
        fdb_doc_free(doc);
        sprintf(value, valuestr, i, "kv2(txn)");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, NULL, 0);
        s = fdb_get(txn1_kv2, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(value, doc->body, doc->bodylen);
        fdb_doc_free(doc);
    }

    // retrieve before commit (isolation test)
    for (i=0;i<n;++i){
        sprintf(key, keystr, i);
        sprintf(value, valuestr, i, "default");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, NULL, 0);
        s = fdb_get(db, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(value, doc->body, doc->bodylen);
        fdb_doc_free(doc);
        sprintf(value, valuestr, i, "kv1");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, NULL, 0);
        s = fdb_get(kv1, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(value, doc->body, doc->bodylen);
        fdb_doc_free(doc);
        sprintf(value, valuestr, i, "kv2");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, NULL, 0);
        s = fdb_get(kv2, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(value, doc->body, doc->bodylen);
        fdb_doc_free(doc);
    }

    s = fdb_end_transaction(dbfile_txn1, FDB_COMMIT_NORMAL);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    // retrieve after commit (through the transaction)
    for (i=0;i<n;++i){
        sprintf(key, keystr, i);
        sprintf(value, valuestr, i, "default(txn)");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, NULL, 0);
        s = fdb_get(txn1, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(value, doc->body, doc->bodylen);
        fdb_doc_free(doc);
        sprintf(value, valuestr, i, "kv1(txn)");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, NULL, 0);
        s = fdb_get(txn1_kv1, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(value, doc->body, doc->bodylen);
        fdb_doc_free(doc);
        sprintf(value, valuestr, i, "kv2(txn)");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, NULL, 0);
        s = fdb_get(txn1_kv2, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(value, doc->body, doc->bodylen);
        fdb_doc_free(doc);
    }

    // retrieve after commit (isolation test)
    for (i=0;i<n;++i){
        sprintf(key, keystr, i);
        sprintf(value, valuestr, i, "default(txn)");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, NULL, 0);
        s = fdb_get(db, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(value, doc->body, doc->bodylen);
        fdb_doc_free(doc);
        sprintf(value, valuestr, i, "kv1(txn)");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, NULL, 0);
        s = fdb_get(kv1, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(value, doc->body, doc->bodylen);
        fdb_doc_free(doc);
        sprintf(value, valuestr, i, "kv2(txn)");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, NULL, 0);
        s = fdb_get(kv2, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(value, doc->body, doc->bodylen);
        fdb_doc_free(doc);
    }

    // reopen
    s = fdb_kvs_close(txn1_kv1);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_kvs_close(txn1_kv2);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_close(dbfile_txn1);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_kvs_close(kv1);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_kvs_close(kv2);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_close(dbfile);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    if (opt & MULTI_KV_VAR_CMP) {
        s = fdb_open_custom_cmp(&dbfile, "./multi_kv_test", &config,
                                3, kvs_names, functions);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
    } else {
        s = fdb_open(&dbfile, "./multi_kv_test", &config);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
    }
    s = fdb_kvs_open(dbfile, &db, NULL, &kvs_config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_kvs_open(dbfile, &kv1, "kv1", &kvs_config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_kvs_open(dbfile, &kv2, "kv2", &kvs_config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    // retrieve after reopen
    for (i=0;i<n;++i){
        sprintf(key, keystr, i);
        sprintf(value, valuestr, i, "default(txn)");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, NULL, 0);
        s = fdb_get(db, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(value, doc->body, doc->bodylen);
        fdb_doc_free(doc);
        sprintf(value, valuestr, i, "kv1(txn)");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, NULL, 0);
        s = fdb_get(kv1, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(value, doc->body, doc->bodylen);
        fdb_doc_free(doc);
        sprintf(value, valuestr, i, "kv2(txn)");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, NULL, 0);
        s = fdb_get(kv2, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(value, doc->body, doc->bodylen);
        fdb_doc_free(doc);
    }

    // begin a transaction
    if (opt & MULTI_KV_VAR_CMP) {
        s = fdb_open_custom_cmp(&dbfile_txn1, "./multi_kv_test", &config,
                                3, kvs_names, functions);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
    } else {
        s = fdb_open(&dbfile_txn1, "./multi_kv_test", &config);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
    }
    s = fdb_kvs_open(dbfile_txn1, &txn1, NULL, &kvs_config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_kvs_open(dbfile_txn1, &txn1_kv1, "kv1", &kvs_config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_kvs_open(dbfile_txn1, &txn1_kv2, "kv2", &kvs_config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_begin_transaction(dbfile_txn1, FDB_ISOLATION_READ_COMMITTED);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    for (i=0;i<n;++i){
        sprintf(key, keystr, i);
        sprintf(value, valuestr, i, "default(txn_abort)");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, value, strlen(value)+1);
        s = fdb_set(txn1, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        fdb_doc_free(doc);
        sprintf(value, valuestr, i, "kv1(txn_abort)");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, value, strlen(value)+1);
        s = fdb_set(txn1_kv1, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        fdb_doc_free(doc);
        sprintf(value, valuestr, i, "kv2(txn_abort)");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, value, strlen(value)+1);
        s = fdb_set(txn1_kv2, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        fdb_doc_free(doc);
    }

    // abort the transaction
    s = fdb_abort_transaction(dbfile_txn1);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    // reopen
    s = fdb_kvs_close(txn1_kv1);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_kvs_close(txn1_kv2);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_close(dbfile_txn1);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_kvs_close(kv1);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_kvs_close(kv2);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_close(dbfile);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    if (opt & MULTI_KV_VAR_CMP) {
        s = fdb_open_custom_cmp(&dbfile, "./multi_kv_test", &config,
                                3, kvs_names, functions);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
    } else {
        s = fdb_open(&dbfile, "./multi_kv_test", &config);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
    }
    s = fdb_kvs_open(dbfile, &db, NULL, &kvs_config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_kvs_open(dbfile, &kv1, "kv1", &kvs_config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_kvs_open(dbfile, &kv2, "kv2", &kvs_config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    // retrieve after reopen
    for (i=0;i<n;++i){
        sprintf(key, keystr, i);
        sprintf(value, valuestr, i, "default(txn)");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, NULL, 0);
        s = fdb_get(db, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(value, doc->body, doc->bodylen);
        fdb_doc_free(doc);
        sprintf(value, valuestr, i, "kv1(txn)");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, NULL, 0);
        s = fdb_get(kv1, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(value, doc->body, doc->bodylen);
        fdb_doc_free(doc);
        sprintf(value, valuestr, i, "kv2(txn)");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, NULL, 0);
        s = fdb_get(kv2, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(value, doc->body, doc->bodylen);
        fdb_doc_free(doc);
    }

    // get KVS names
    fdb_kvs_name_list kvs_name_list;
    s = fdb_get_kvs_name_list(dbfile, &kvs_name_list);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    TEST_CHK(kvs_name_list.num_kvs_names == 3);
    for (i=0; (size_t)i<kvs_name_list.num_kvs_names;++i){
        TEST_CHK(!strcmp(kvs_name_list.kvs_names[i], kvs_names[i]));
    }
    fdb_free_kvs_name_list(&kvs_name_list);

    s = fdb_kvs_close(kv1);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_kvs_close(kv2);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_close(dbfile);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    s = fdb_shutdown();
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    memleak_end();

    if (opt & MULTI_KV_VAR_CMP) {
        TEST_RESULT("multiple KV instances transaction test "
                    "(custom key order)");
    } else {
        TEST_RESULT("multiple KV instances transaction test");
    }
}

void multi_kv_snapshot_test(uint8_t opt, size_t chunksize)
{
    TEST_INIT();

    int n = 100;
    int i, r;
    char key[256], value[256];
    char keystr[] = "key%06d";
    char valuestr[] = "value%08d(%s)";
    fdb_file_handle *dbfile;
    fdb_kvs_handle *db, *kv1, *kv2;
    fdb_kvs_handle *snap1, *snap2;
    fdb_seqnum_t seq1, seq2;
    fdb_config config;
    fdb_kvs_config kvs_config;
    fdb_doc *doc;
    fdb_status s;

    sprintf(value, SHELL_DEL" multi_kv_test*");
    r = system(value);
    (void)r;

    memleak_start();

    config = fdb_get_default_config();
    kvs_config = fdb_get_default_kvs_config();
    config.seqtree_opt = FDB_SEQTREE_USE; // enable seqtree since get_byseq
    config.chunksize = chunksize;
    config.multi_kv_instances = true;
    config.wal_threshold = 1000;
    config.buffercache_size = 0;

    s = fdb_open(&dbfile, "./multi_kv_test", &config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    if (opt & MULTI_KV_VAR_CMP) {
        kvs_config.custom_cmp = _multi_kv_test_keycmp;
    }
    s = fdb_kvs_open(dbfile, &db, NULL, &kvs_config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_kvs_open(dbfile, &kv1, "kv1", &kvs_config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_kvs_open(dbfile, &kv2, "kv2", &kvs_config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    // write documents first time
    for (i=0;i<n;++i){
        sprintf(key, keystr, i);
        sprintf(value, valuestr, i, "default(commit1)");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, value, strlen(value)+1);
        s = fdb_set(db, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        fdb_doc_free(doc);
        sprintf(value, valuestr, i, "kv1(commit1)");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, value, strlen(value)+1);
        s = fdb_set(kv1, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        fdb_doc_free(doc);
        sprintf(value, valuestr, i, "kv2(commit1)");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, value, strlen(value)+1);
        s = fdb_set(kv2, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        fdb_doc_free(doc);
    }
    s = fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_get_kvs_seqnum(kv1, &seq1);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    // write documents second time
    for (i=0;i<n;++i){
        sprintf(key, keystr, i);
        sprintf(value, valuestr, i, "default(commit2)");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, value, strlen(value)+1);
        s = fdb_set(db, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        fdb_doc_free(doc);
        sprintf(value, valuestr, i, "kv1(commit2)");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, value, strlen(value)+1);
        s = fdb_set(kv1, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        fdb_doc_free(doc);
        sprintf(value, valuestr, i, "kv2(commit2)");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, value, strlen(value)+1);
        s = fdb_set(kv2, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        fdb_doc_free(doc);
    }
    s = fdb_commit(dbfile, FDB_COMMIT_NORMAL);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_get_kvs_seqnum(kv2, &seq2);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    // write documents third time
    for (i=0;i<n;++i){
        sprintf(key, keystr, i);
        sprintf(value, valuestr, i, "default(commit3)");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, value, strlen(value)+1);
        s = fdb_set(db, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        fdb_doc_free(doc);
        sprintf(value, valuestr, i, "kv1(commit3)");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, value, strlen(value)+1);
        s = fdb_set(kv1, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        fdb_doc_free(doc);
        sprintf(value, valuestr, i, "kv2(commit3)");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, value, strlen(value)+1);
        s = fdb_set(kv2, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        fdb_doc_free(doc);
    }
    s = fdb_commit(dbfile, FDB_COMMIT_NORMAL);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    // create snapshots
    s = fdb_snapshot_open(kv1, &snap1, seq1);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_snapshot_open(kv2, &snap2, seq2);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    // retrieve
    for (i=0;i<n;++i){
        sprintf(key, keystr, i);
        sprintf(value, valuestr, i, "kv1(commit3)");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, NULL, 0);
        s = fdb_get(kv1, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(value, doc->body, doc->bodylen);
        fdb_doc_free(doc);

        sprintf(value, valuestr, i, "kv2(commit3)");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, NULL, 0);
        s = fdb_get(kv2, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(value, doc->body, doc->bodylen);
        fdb_doc_free(doc);

        sprintf(value, valuestr, i, "kv1(commit1)");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, NULL, 0);
        s = fdb_get(snap1, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(value, doc->body, doc->bodylen);
        fdb_doc_free(doc);

        sprintf(value, valuestr, i, "kv2(commit2)");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, NULL, 0);
        s = fdb_get(snap2, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(value, doc->body, doc->bodylen);
        fdb_doc_free(doc);
    }

    s = fdb_kvs_close(snap1);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_kvs_close(snap2);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    s = fdb_kvs_close(kv1);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_kvs_close(kv2);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_close(dbfile);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    s = fdb_shutdown();
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    memleak_end();

    if (opt & MULTI_KV_VAR_CMP) {
        TEST_RESULT("multiple KV instances snapshot test "
                    "(custom key order)");
    } else {
        TEST_RESULT("multiple KV instances snapshot test");
    }
}

void multi_kv_rollback_test(uint8_t opt, size_t chunksize)
{
    TEST_INIT();

    int n = 100;
    int i, r;
    char key[256], value[256];
    char keystr[] = "key%06d";
    char valuestr[] = "value%08d(%s)";
    fdb_file_handle *dbfile;
    fdb_kvs_handle *db, *kv1, *kv2;
    fdb_seqnum_t seq1, seq2, seq3;
    fdb_config config;
    fdb_kvs_config kvs_config;
    fdb_doc *doc;
    fdb_status s;

    char *kvs_names[] = {NULL, (char*)"kv1", (char*)"kv2"};
    fdb_custom_cmp_variable functions[] = {_multi_kv_test_keycmp,
                                           _multi_kv_test_keycmp,
                                           _multi_kv_test_keycmp};

    sprintf(value, SHELL_DEL" multi_kv_test*");
    r = system(value);
    (void)r;

    memleak_start();

    config = fdb_get_default_config();
    kvs_config = fdb_get_default_kvs_config();
    config.seqtree_opt = FDB_SEQTREE_USE; // enable seqtree since get_byseq
    config.chunksize = chunksize;
    config.multi_kv_instances = true;
    config.wal_threshold = 1000;
    config.buffercache_size = 0;
    // for rollback, disable block reusing
    config.block_reusing_threshold = 0;

    if (opt & MULTI_KV_VAR_CMP) {
        s = fdb_open_custom_cmp(&dbfile, "./multi_kv_test", &config,
                                3, kvs_names, functions);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
    } else {
        s = fdb_open(&dbfile, "./multi_kv_test", &config);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
    }
    s = fdb_kvs_open(dbfile, &db, NULL, &kvs_config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_kvs_open(dbfile, &kv1, "kv1", &kvs_config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_kvs_open(dbfile, &kv2, "kv2", &kvs_config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    // write documents first time
    for (i=0;i<n;++i){
        sprintf(key, keystr, i);
        sprintf(value, valuestr, i, "default(commit1)");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, value, strlen(value)+1);
        s = fdb_set(db, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        fdb_doc_free(doc);
        sprintf(value, valuestr, i, "kv1(commit1)");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, value, strlen(value)+1);
        s = fdb_set(kv1, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        if (i%15 == 0) s = fdb_set(kv1, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        fdb_doc_free(doc);
        sprintf(value, valuestr, i, "kv2(commit1)");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, value, strlen(value)+1);
        s = fdb_set(kv2, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        if (i%27 == 0) s = fdb_set(kv2, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        fdb_doc_free(doc);
    }
    s = fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_get_kvs_seqnum(kv1, &seq1);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    // write documents second time
    for (i=0;i<n;++i){
        sprintf(key, keystr, i);
        sprintf(value, valuestr, i, "default(commit2)");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, value, strlen(value)+1);
        s = fdb_set(db, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        fdb_doc_free(doc);
        sprintf(value, valuestr, i, "kv1(commit2)");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, value, strlen(value)+1);
        s = fdb_set(kv1, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        if (i%15 == 0) s = fdb_set(kv1, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        fdb_doc_free(doc);
        sprintf(value, valuestr, i, "kv2(commit2)");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, value, strlen(value)+1);
        s = fdb_set(kv2, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        if (i%27 == 0) s = fdb_set(kv2, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        fdb_doc_free(doc);
    }
    s = fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_get_kvs_seqnum(db, &seq2);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    // write documents third time
    for (i=0;i<n;++i){
        sprintf(key, keystr, i);
        sprintf(value, valuestr, i, "default(commit3)");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, value, strlen(value)+1);
        s = fdb_set(db, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        fdb_doc_free(doc);
        sprintf(value, valuestr, i, "kv1(commit3)");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, value, strlen(value)+1);
        s = fdb_set(kv1, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        if (i%15 == 0) s = fdb_set(kv1, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        fdb_doc_free(doc);
        sprintf(value, valuestr, i, "kv2(commit3)");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, value, strlen(value)+1);
        s = fdb_set(kv2, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        if (i%27 == 0) s = fdb_set(kv2, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        fdb_doc_free(doc);
    }
    s = fdb_commit(dbfile, FDB_COMMIT_NORMAL);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_get_kvs_seqnum(kv2, &seq3);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    // write documents third time
    for (i=0;i<n;++i){
        sprintf(key, keystr, i);
        sprintf(value, valuestr, i, "default(commit4)");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, value, strlen(value)+1);
        s = fdb_set(db, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        fdb_doc_free(doc);
        sprintf(value, valuestr, i, "kv1(commit4)");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, value, strlen(value)+1);
        s = fdb_set(kv1, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        if (i%15 == 0) s = fdb_set(kv1, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        fdb_doc_free(doc);
        sprintf(value, valuestr, i, "kv2(commit4)");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, value, strlen(value)+1);
        s = fdb_set(kv2, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        if (i%27 == 0) s = fdb_set(kv2, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        fdb_doc_free(doc);
    }
    s = fdb_commit(dbfile, FDB_COMMIT_NORMAL);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    // rollback kv1 using seq1
    s = fdb_rollback(&kv1, seq1);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    // retrieve check
    for (i=0;i<n;++i){
        sprintf(key, keystr, i);
        sprintf(value, valuestr, i, "default(commit4)");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, NULL, 0);
        s = fdb_get(db, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(value, doc->body, doc->bodylen);
        fdb_doc_free(doc);
        sprintf(value, valuestr, i, "kv1(commit1)");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, NULL, 0);
        s = fdb_get(kv1, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(value, doc->body, doc->bodylen);
        fdb_doc_free(doc);
        sprintf(value, valuestr, i, "kv2(commit4)");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, NULL, 0);
        s = fdb_get(kv2, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(value, doc->body, doc->bodylen);
        fdb_doc_free(doc);
    }

    // rollback db using seq2
    s = fdb_rollback(&db, seq2);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    // retrieve check
    for (i=0;i<n;++i){
        sprintf(key, keystr, i);
        sprintf(value, valuestr, i, "default(commit2)");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, NULL, 0);
        s = fdb_get(db, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(value, doc->body, doc->bodylen);
        fdb_doc_free(doc);
        sprintf(value, valuestr, i, "kv1(commit1)");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, NULL, 0);
        s = fdb_get(kv1, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(value, doc->body, doc->bodylen);
        fdb_doc_free(doc);
        sprintf(value, valuestr, i, "kv2(commit4)");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, NULL, 0);
        s = fdb_get(kv2, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(value, doc->body, doc->bodylen);
        fdb_doc_free(doc);
    }

    // rollback db using seq3
    s = fdb_rollback(&kv2, seq3);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    // retrieve check
    for (i=0;i<n;++i){
        sprintf(key, keystr, i);
        sprintf(value, valuestr, i, "default(commit2)");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, NULL, 0);
        s = fdb_get(db, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(value, doc->body, doc->bodylen);
        fdb_doc_free(doc);
        sprintf(value, valuestr, i, "kv1(commit1)");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, NULL, 0);
        s = fdb_get(kv1, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(value, doc->body, doc->bodylen);
        fdb_doc_free(doc);
        sprintf(value, valuestr, i, "kv2(commit3)");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, NULL, 0);
        s = fdb_get(kv2, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(value, doc->body, doc->bodylen);
        fdb_doc_free(doc);
    }

    // close & re-open
    s = fdb_kvs_close(kv1);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_kvs_close(kv2);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_close(dbfile);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    if (opt & MULTI_KV_VAR_CMP) {
        s = fdb_open_custom_cmp(&dbfile, "./multi_kv_test", &config,
                                3, kvs_names, functions);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
    } else {
        s = fdb_open(&dbfile, "./multi_kv_test", &config);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
    }
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    fdb_kvs_open(dbfile, &db, NULL, &kvs_config);
    fdb_kvs_open(dbfile, &kv1, "kv1", &kvs_config);
    fdb_kvs_open(dbfile, &kv2, "kv2", &kvs_config);

    // retrieve check after re-open
    for (i=0;i<n;++i){
        sprintf(key, keystr, i);
        sprintf(value, valuestr, i, "default(commit2)");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, NULL, 0);
        s = fdb_get(db, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(value, doc->body, doc->bodylen);
        fdb_doc_free(doc);
        sprintf(value, valuestr, i, "kv1(commit1)");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, NULL, 0);
        s = fdb_get(kv1, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(value, doc->body, doc->bodylen);
        fdb_doc_free(doc);
        sprintf(value, valuestr, i, "kv2(commit3)");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, NULL, 0);
        s = fdb_get(kv2, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(value, doc->body, doc->bodylen);
        fdb_doc_free(doc);
    }

    fdb_kvs_close(kv1);
    fdb_kvs_close(kv2);
    fdb_close(dbfile);

    fdb_shutdown();

    memleak_end();

    if (opt & MULTI_KV_VAR_CMP) {
        TEST_RESULT("multiple KV instances rollback test "
                    "(custom key order)");
    } else {
        TEST_RESULT("multiple KV instances rollback test");
    }
}

void multi_kv_custom_cmp_test()
{
    TEST_INIT();

    int n = 1000;
    int i, r;
    char key[256], value[256];
    char keyBuf[256], valueBuf[256];
    char keystr[] = "key%06d";
    char valuestr[] = "value%08d(%s)";
    fdb_file_handle *dbfile;
    fdb_kvs_handle *db, *kv1, *kv2;
    fdb_config config;
    fdb_kvs_config kvs_config;
    fdb_doc *doc;
    fdb_iterator *it;
    fdb_status s;

    sprintf(value, SHELL_DEL" multi_kv_test*");
    r = system(value);
    (void)r;

    memleak_start();

    config = fdb_get_default_config();
    kvs_config = fdb_get_default_kvs_config();
    config.seqtree_opt = FDB_SEQTREE_USE; // enable seqtree since get_byseq
    config.multi_kv_instances = true;
    config.wal_threshold = 256;
    config.wal_flush_before_commit = false;
    config.buffercache_size = 0;

    s = fdb_open(&dbfile, "./multi_kv_test", &config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_kvs_open(dbfile, &db, NULL, &kvs_config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    // insert using 'default' instance
    for (i=0;i<n;++i) {
        sprintf(key, keystr, i);
        sprintf(value, valuestr, i, "default");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, value, strlen(value)+1);
        s = fdb_set(db, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        fdb_doc_free(doc);
    }
    s = fdb_commit(dbfile, FDB_COMMIT_NORMAL);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    // create 'kv1' using custom cmp function
    kvs_config.custom_cmp = _multi_kv_test_keycmp;
    s = fdb_kvs_open(dbfile, &kv1, "kv1", &kvs_config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    // insert using 'kv1' instance
    for (i=0;i<n;++i) {
        sprintf(key, keystr, i);
        sprintf(value, valuestr, i, "kv1_custom_cmp");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, value, strlen(value)+1);
        s = fdb_set(kv1, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        fdb_doc_free(doc);
    }
    s = fdb_commit(dbfile, FDB_COMMIT_NORMAL);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    // retrieve check
    for (i=0;i<n;++i) {
        sprintf(key, keystr, i);
        sprintf(value, valuestr, i, "default");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, NULL, 0);
        s = fdb_get(db, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(value, doc->body, doc->bodylen);
        fdb_doc_free(doc);

        sprintf(value, valuestr, i, "kv1_custom_cmp");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, NULL, 0);
        s = fdb_get(kv1, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(value, doc->body, doc->bodylen);
        fdb_doc_free(doc);
    }

    // close & reopen handles
    s = fdb_close(dbfile);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    kvs_config.custom_cmp = NULL;
    s = fdb_open(&dbfile, "./multi_kv_test", &config);
    TEST_CHK(s != FDB_RESULT_SUCCESS); // must fail

    { // retry with wrong cmp function
        char *kvs_names[] = {NULL};
        fdb_custom_cmp_variable functions[] = {_multi_kv_test_keycmp};
        s = fdb_open_custom_cmp(&dbfile, "./multi_kv_test", &config,
                                1, kvs_names, functions);
        TEST_CHK(s != FDB_RESULT_SUCCESS); // must fail
    }

    { // retry with correct function
        char *kvs_names[] = {(char*)"kv1"};
        fdb_custom_cmp_variable functions[] = {_multi_kv_test_keycmp};
        s = fdb_open_custom_cmp(&dbfile, "./multi_kv_test", &config,
                                1, kvs_names, functions);
        TEST_CHK(s == FDB_RESULT_SUCCESS); // must succeed this time
    }

    s = fdb_kvs_open(dbfile, &db, NULL, &kvs_config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_kvs_open(dbfile, &kv1, "kv1", &kvs_config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    // retrieve check
    for (i=0;i<n;++i) {
        sprintf(key, keystr, i);
        sprintf(value, valuestr, i, "default");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, NULL, 0);
        s = fdb_get(db, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(value, doc->body, doc->bodylen);
        fdb_doc_free(doc);

        sprintf(value, valuestr, i, "kv1_custom_cmp");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, NULL, 0);
        s = fdb_get(kv1, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(value, doc->body, doc->bodylen);
        fdb_doc_free(doc);
    }

    // create one more KV store
    kvs_config.custom_cmp = NULL;
    s = fdb_kvs_open(dbfile, &kv2, "kv2", &kvs_config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    // insert using 'kv2' instance
    for (i=0;i<n;++i) {
        sprintf(key, keystr, i);
        sprintf(value, valuestr, i, "kv2");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, value, strlen(value)+1);
        s = fdb_set(kv2, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        fdb_doc_free(doc);
    }
    s = fdb_commit(dbfile, FDB_COMMIT_NORMAL);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    // retrieve check
    for (i=0;i<n;++i) {
        sprintf(key, keystr, i);
        sprintf(value, valuestr, i, "default");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, NULL, 0);
        s = fdb_get(db, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(value, doc->body, doc->bodylen);
        fdb_doc_free(doc);

        sprintf(value, valuestr, i, "kv1_custom_cmp");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, NULL, 0);
        s = fdb_get(kv1, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(value, doc->body, doc->bodylen);
        fdb_doc_free(doc);

        sprintf(value, valuestr, i, "kv2");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, NULL, 0);
        s = fdb_get(kv2, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(value, doc->body, doc->bodylen);
        fdb_doc_free(doc);
    }

    // update all documents
    for (i=0;i<n;++i) {
        sprintf(key, keystr, i);
        sprintf(value, valuestr, i, "default(updated)");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, value, strlen(value)+1);
        s = fdb_set(db, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        fdb_doc_free(doc);

        sprintf(key, keystr, i);
        sprintf(value, valuestr, i, "kv1_custom_cmp(updated)");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, value, strlen(value)+1);
        s = fdb_set(kv1, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        fdb_doc_free(doc);

        sprintf(key, keystr, i);
        sprintf(value, valuestr, i, "kv2(updated)");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, value, strlen(value)+1);
        s = fdb_set(kv2, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        fdb_doc_free(doc);
    }
    // WAL flush at once
    s = fdb_commit(dbfile, FDB_COMMIT_NORMAL);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    // retrieve check
    for (i=0;i<n;++i) {
        sprintf(key, keystr, i);
        sprintf(value, valuestr, i, "default(updated)");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, NULL, 0);
        s = fdb_get(db, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(value, doc->body, doc->bodylen);
        fdb_doc_free(doc);

        sprintf(value, valuestr, i, "kv1_custom_cmp(updated)");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, NULL, 0);
        s = fdb_get(kv1, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(value, doc->body, doc->bodylen);
        fdb_doc_free(doc);

        sprintf(value, valuestr, i, "kv2(updated)");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, NULL, 0);
        s = fdb_get(kv2, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(value, doc->body, doc->bodylen);
        fdb_doc_free(doc);
    }

    // do compaction
    s = fdb_compact(dbfile, "./multi_kv_test2");
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    // retrieve check
    for (i=0;i<n;++i) {
        sprintf(key, keystr, i);
        sprintf(value, valuestr, i, "default(updated)");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, NULL, 0);
        s = fdb_get(db, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(value, doc->body, doc->bodylen);
        fdb_doc_free(doc);

        sprintf(value, valuestr, i, "kv1_custom_cmp(updated)");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, NULL, 0);
        s = fdb_get(kv1, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(value, doc->body, doc->bodylen);
        fdb_doc_free(doc);

        sprintf(value, valuestr, i, "kv2(updated)");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, NULL, 0);
        s = fdb_get(kv2, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(value, doc->body, doc->bodylen);
        fdb_doc_free(doc);
    }

    // pre-allocate memory and re-use it for the iterator return document
    s = fdb_doc_create(&doc, NULL, 0, NULL, 0, NULL, 0);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    doc->key = &keyBuf[0];
    doc->body = &valueBuf[0];

    // create full iterator for 'kv1'
    i = 0;
    s = fdb_iterator_init(kv1, &it, NULL, 0, NULL, 0, FDB_ITR_NONE);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    do {
        s = fdb_iterator_get(it, &doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        sprintf(key, keystr, i);
        sprintf(value, valuestr, i, "kv1_custom_cmp(updated)");
        TEST_CMP(doc->key, key, doc->keylen);
        TEST_CMP(doc->body, value, doc->bodylen);
        i++;
    } while (fdb_iterator_next(it) == FDB_RESULT_SUCCESS);
    TEST_CHK(i == n);
    s = fdb_iterator_close(it);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    s = fdb_close(dbfile);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_shutdown();
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    // release the pre-allocated memory for the iterator return document
    doc->key = NULL;
    doc->body = NULL;
    s = fdb_doc_free(doc);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    memleak_end();

    TEST_RESULT("multiple KV instances custom comparison function test");
}

void multi_kv_fdb_open_custom_cmp_test()
{
    // Unit test for MB-12593
    TEST_INIT();

    int n = 1000;
    int i, r;
    char key[256], value[256];
    char keystr[] = "key%06d";
    char valuestr[] = "value%08d(%s)";
    fdb_file_handle *dbfile;
    fdb_kvs_handle *db, *kv1, *kv2;
    fdb_config config;
    fdb_kvs_config kvs_config;
    fdb_doc *doc;
    fdb_status s;

    char *kvs_names[] = {(char*)"default", (char*)"kv1", (char*)"kv2"};
    fdb_custom_cmp_variable functions[] = {_multi_kv_test_keycmp,
                                           _multi_kv_test_keycmp,
                                           NULL};

    sprintf(value, SHELL_DEL" multi_kv_test*");
    r = system(value);
    (void)r;

    memleak_start();

    config = fdb_get_default_config();
    kvs_config = fdb_get_default_kvs_config();
    config.seqtree_opt = FDB_SEQTREE_USE; // enable seqtree since get_byseq
    config.multi_kv_instances = true;
    config.wal_threshold = 256;
    config.wal_flush_before_commit = false;
    config.buffercache_size = 0;

    s = fdb_open_custom_cmp(&dbfile, "./multi_kv_test", &config,
                            3, kvs_names, functions);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_kvs_open(dbfile, &db, NULL, &kvs_config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_kvs_open(dbfile, &kv1, "kv1", &kvs_config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    kvs_config.custom_cmp = _multi_kv_test_keycmp;
    s = fdb_kvs_open(dbfile, &kv2, "kv2", &kvs_config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    // insert using 'default' instance
    for (i=0;i<n;++i) {
        sprintf(key, keystr, i);
        sprintf(value, valuestr, i, "default");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, value, strlen(value)+1);
        s = fdb_set(db, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        fdb_doc_free(doc);
    }

    // insert using 'kv1' instance
    for (i=0;i<n;++i) {
        sprintf(key, keystr, i);
        sprintf(value, valuestr, i, "kv1_custom_cmp");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, value, strlen(value)+1);
        s = fdb_set(kv1, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        fdb_doc_free(doc);
    }

    // insert using 'kv2' instance
    for (i=0;i<n;++i) {
        sprintf(key, keystr, i);
        sprintf(value, valuestr, i, "kv2");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, value, strlen(value)+1);
        s = fdb_set(kv2, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        fdb_doc_free(doc);
    }
    s = fdb_commit(dbfile, FDB_COMMIT_NORMAL);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_close(dbfile);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    s = fdb_open(&dbfile, "./multi_kv_test", &config);
    TEST_CHK(s != FDB_RESULT_SUCCESS); // must fail

    s = fdb_open_custom_cmp(&dbfile, "./multi_kv_test", &config,
                            3, kvs_names, functions);
    TEST_CHK(s != FDB_RESULT_SUCCESS); // must fail

    functions[2] = _multi_kv_test_keycmp;
    s = fdb_open_custom_cmp(&dbfile, "./multi_kv_test", &config,
                            3, kvs_names, functions);
    TEST_CHK(s == FDB_RESULT_SUCCESS); // must succeed
    s = fdb_kvs_open(dbfile, &db, NULL, &kvs_config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_kvs_open(dbfile, &kv1, "kv1", &kvs_config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_kvs_open(dbfile, &kv2, "kv2", &kvs_config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    // retrieve check
    for (i=0;i<n;++i) {
        sprintf(key, keystr, i);
        sprintf(value, valuestr, i, "default");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, NULL, 0);
        s = fdb_get(db, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(value, doc->body, doc->bodylen);
        fdb_doc_free(doc);

        sprintf(value, valuestr, i, "kv1_custom_cmp");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, NULL, 0);
        s = fdb_get(kv1, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(value, doc->body, doc->bodylen);
        fdb_doc_free(doc);

        sprintf(value, valuestr, i, "kv2");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, NULL, 0);
        s = fdb_get(kv2, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(value, doc->body, doc->bodylen);
        fdb_doc_free(doc);
    }

    s = fdb_close(dbfile);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_shutdown();
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    memleak_end();

    TEST_RESULT("multiple KV instances fdb_open_custom_cmp test");
}

void multi_kv_use_existing_mode_test()
{
    TEST_INIT();

    int n = 1000;
    int i, r;
    char key[256], value[256];
    char keystr[] = "key%06d";
    char valuestr[] = "value%08d(%s)";
    fdb_file_handle *dbfile;
    fdb_kvs_handle *db;
    fdb_config config;
    fdb_kvs_config kvs_config;
    fdb_doc *doc;
    fdb_status s;

    sprintf(value, SHELL_DEL" multi_kv_test*");
    r = system(value);
    (void)r;

    memleak_start();

    config = fdb_get_default_config();
    kvs_config = fdb_get_default_kvs_config();
    config.seqtree_opt = FDB_SEQTREE_USE; // enable seqtree since get_byseq
    config.wal_threshold = 256;
    config.buffercache_size = 0;

    // create DB file under multi KV instance mode
    config.multi_kv_instances = true;
    s = fdb_open(&dbfile, "./multi_kv_test_multi", &config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_kvs_open(dbfile, &db, NULL, &kvs_config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    // insert using 'default' instance
    for (i=0;i<n;++i) {
        sprintf(key, keystr, i);
        sprintf(value, valuestr, i, "default");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, value, strlen(value)+1);
        s = fdb_set(db, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        fdb_doc_free(doc);
    }

    s = fdb_commit(dbfile, FDB_COMMIT_NORMAL);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_close(dbfile);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    // open under single KV instance mode
    config.multi_kv_instances = false;
    s = fdb_open(&dbfile, "./multi_kv_test_multi", &config);
    TEST_CHK(s == FDB_RESULT_SUCCESS); // must succeed
    s = fdb_kvs_open(dbfile, &db, NULL, &kvs_config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    // retrieve check
    for (i=0;i<n;++i) {
        sprintf(key, keystr, i);
        sprintf(value, valuestr, i, "default");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, NULL, 0);
        s = fdb_get(db, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(value, doc->body, doc->bodylen);
        fdb_doc_free(doc);
    }

    s = fdb_close(dbfile);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    // create DB file under single KV instance mode
    config.multi_kv_instances = false;
    s = fdb_open(&dbfile, "./multi_kv_test_single", &config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_kvs_open(dbfile, &db, NULL, &kvs_config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    // insert using 'default' instance
    for (i=0;i<n;++i) {
        sprintf(key, keystr, i);
        sprintf(value, valuestr, i, "default");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, value, strlen(value)+1);
        s = fdb_set(db, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        fdb_doc_free(doc);
    }

    s = fdb_commit(dbfile, FDB_COMMIT_NORMAL);
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    s = fdb_close(dbfile);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    // open under multi KV instance mode
    config.multi_kv_instances = true;
    s = fdb_open(&dbfile, "./multi_kv_test_single", &config);
    TEST_CHK(s == FDB_RESULT_SUCCESS); // must succeed
    s = fdb_kvs_open(dbfile, &db, NULL, &kvs_config);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    // retrieve check
    for (i=0;i<n;++i) {
        sprintf(key, keystr, i);
        sprintf(value, valuestr, i, "default");
        fdb_doc_create(&doc, key, strlen(key)+1, NULL, 0, NULL, 0);
        s = fdb_get(db, doc);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
        TEST_CMP(value, doc->body, doc->bodylen);
        fdb_doc_free(doc);
    }

    s = fdb_close(dbfile);
    TEST_CHK(s == FDB_RESULT_SUCCESS);

    s = fdb_shutdown();
    TEST_CHK(s == FDB_RESULT_SUCCESS);
    memleak_end();

    TEST_RESULT("multiple KV instances use existing mode test");
}

void *_opening_thread(void *args) {
    int nhandles = 100;
    fdb_file_handle **dbfile = alca(fdb_file_handle *, nhandles);
    fdb_config fconfig = fdb_get_default_config();
    fdb_status s;
    TEST_INIT();

    for (int i = 0; i < nhandles; ++i) {
        s = fdb_open(&dbfile[i], "multi_kv_test2", &fconfig);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
    }
    for (int i = 0; i < nhandles; ++i) {
        s = fdb_close(dbfile[i]);
        TEST_CHK(s == FDB_RESULT_SUCCESS);
    }
    thread_exit(0);
    return NULL;
}

void multi_kv_open_test()
{
    TEST_INIT();
    memleak_start();

    int n = 256;
    int nthreads = 7;
    thread_t *tid = alca(thread_t, nthreads);
    fdb_file_handle *dbfile;
    fdb_status status;
    fdb_config fconfig;
    fdb_kvs_config kvs_config;

    // remove previous multi_kv_test files
    int r = system(SHELL_DEL" multi_kv_test* > errorlog.txt");
    (void)r;

    fconfig = fdb_get_default_config();
    kvs_config = fdb_get_default_kvs_config();

    // open db
    status = fdb_open(&dbfile, "multi_kv_test2", &fconfig);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    for (int i = 0; i < nthreads; ++i) {
        thread_create(&tid[i], _opening_thread, NULL);
    }
    for (int i = 0; i < n; ++i) {
        fdb_kvs_handle *db;
        char kvname[8];
        sprintf(kvname, "kv_%d", i);
        status = fdb_kvs_open(dbfile, &db, kvname, &kvs_config);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
    }

    for (int i = 0; i < nthreads; ++i) {
        void *thread_ret;
        thread_join(tid[i], &thread_ret);
    }

    status = fdb_close(dbfile);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_shutdown();
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    memleak_end();
    TEST_RESULT("multi KV creation with parallel open");
}
void multi_kv_close_test()
{
    TEST_INIT();
    memleak_start();

    int i, r;
    int n = 10;
    fdb_file_handle *dbfile1;
    fdb_kvs_handle *db1, *db2, *db3, *db4, *db5;
    fdb_doc **doc = alca(fdb_doc*, n);
    fdb_doc *rdoc;
    fdb_status status;
    fdb_config fconfig;
    fdb_kvs_config kvs_config;

    char keybuf[256], metabuf[256], bodybuf[256];

    // remove previous multi_kv_test files
    r = system(SHELL_DEL" multi_kv_test* > errorlog.txt");
    (void)r;

    fconfig = fdb_get_default_config();
    fconfig.buffercache_size = 0;
    fconfig.seqtree_opt = FDB_SEQTREE_USE; // enable seqtree since get_byseq
    fconfig.wal_threshold = 8;
    fconfig.flags = FDB_OPEN_FLAG_CREATE;
    fconfig.purging_interval = 0;
    fconfig.compaction_threshold = 0;
    fconfig.wal_flush_before_commit = true;

    kvs_config = fdb_get_default_kvs_config();

    // open db
    fdb_open(&dbfile1, "multi_kv_test1", &fconfig);
    fdb_kvs_open(dbfile1, &db1, "db1", &kvs_config);
    fdb_kvs_open(dbfile1, &db2, "db2", &kvs_config);
    fdb_kvs_open(dbfile1, &db3, "db3", &kvs_config);
    fdb_kvs_open(dbfile1, &db4, "db4", &kvs_config);
    fdb_kvs_open(dbfile1, &db5, "db5", &kvs_config);

    // insert documents
    for (i=0;i<n;++i){
        sprintf(keybuf, "key%d", i);
        sprintf(metabuf, "meta%d", i);
        sprintf(bodybuf, "body%d", i);
        fdb_doc_create(&doc[i], (void*)keybuf, strlen(keybuf),
            (void*)metabuf, strlen(metabuf), (void*)bodybuf, strlen(bodybuf));
        fdb_set(db1, doc[i]);
        fdb_set(db2, doc[i]);
        fdb_set(db3, doc[i]);
        fdb_set(db4, doc[i]);
        fdb_set(db5, doc[i]);
    }
    // close db3,4
    fdb_kvs_close(db3);
    fdb_kvs_close(db4);


    // insert documents
    for (i=0;i<n;++i){
        fdb_set(db1, doc[i]);
        fdb_set(db2, doc[i]);
        fdb_set(db5, doc[i]);
    }

    // remove db1
    fdb_kvs_close(db1);
    status = fdb_kvs_remove(dbfile1,"db1");
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // commit
    status = fdb_commit(dbfile1, FDB_COMMIT_NORMAL);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // remove db5
    fdb_kvs_close(db5);
    status = fdb_kvs_remove(dbfile1, "db5");
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // attempt to read from remaining open kvs
    for (i=0; i<n; i++){
        fdb_doc_create(&rdoc, doc[i]->key, doc[i]->keylen, NULL, 0, NULL, 0);
        status = fdb_get(db2, rdoc);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        fdb_doc_free(rdoc);
    }

    // close db2
    status = fdb_kvs_close(db2);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // free resources
    for (i=0; i<n; i++){
       status = fdb_doc_free(doc[i]);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
    }

    status = fdb_close(dbfile1);
    TEST_CHK(status == FDB_RESULT_SUCCESS);
    status = fdb_shutdown();
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    memleak_end();
    TEST_RESULT("multi KV close");
}

int main(){
    int i, j;
    uint8_t opt;
    size_t chunksize;

    multi_kv_open_test();
    for (j=0;j<3;++j) {
        if (j==0) {
            chunksize = 8;
        } else if (j==1) {
            chunksize = 16;
        } else {
            chunksize = 32;
        }
        printf("Chunk size: %d bytes\n", (int)chunksize);
        for (i=0;i<2;++i){
            opt = (i==0)?(0x0):(MULTI_KV_VAR_CMP);
            multi_kv_test(opt, chunksize);
            multi_kv_iterator_key_test(opt, chunksize);
            multi_kv_iterator_seq_test(opt, chunksize);
            multi_kv_txn_test(opt, chunksize);
            multi_kv_snapshot_test(opt, chunksize);
            multi_kv_rollback_test(opt, chunksize);
        }
    }
    multi_kv_custom_cmp_test();
    multi_kv_fdb_open_custom_cmp_test();
    multi_kv_use_existing_mode_test();
    multi_kv_close_test();

    return 0;
}
