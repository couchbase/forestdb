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

#include "hbtrie.h"
#include "test.h"
#include "btreeblock.h"
#include "docio.h"
#include "filemgr.h"
#include "filemgr_ops.h"
#include "common.h"
#include "list.h"

uint32_t _set_doc(struct docio_object *doc, char *key, char *meta, char *body)
{
    strcpy((char*)doc->key, key);
    doc->length.keylen = strlen((char*)doc->key);
    strcpy((char*)doc->meta, meta);
    doc->length.metalen = strlen((char*)doc->meta);
    strcpy((char*)doc->body, body);
    doc->length.bodylen = strlen((char*)doc->body);

    return sizeof(struct docio_length) + doc->length.keylen +
           doc->length.metalen + doc->length.bodylen;
}

size_t _readkey_wrap(void *handle, uint64_t offset, void *buf)
{
    keylen_t keylen;
    offset = _endian_decode(offset);
    docio_read_doc_key((struct docio_handle * )handle, offset, &keylen, buf);
    return keylen;
}

void hbtrie_key_test()
{
    TEST_INIT();

    struct hbtrie trie;
    int i,j;

    trie.chunksize = 4;

    const char *key[] = {"abc", "abcd", "abcde", "abcdef", "abcdefg", "abcdefgh"};
    char buf[256];
    int keylen;

    for (i=0;i<6;++i){
        keylen = _hbtrie_reform_key(&trie, (void*)key[i], strlen(key[i]), (void*)buf);

        DBG("keylen: %2d , ", keylen);
        for (j=0;j<keylen;++j) {
            printf("%02x ", (uint8_t)buf[j]);
        }
        printf("\n");
    }

    TEST_RESULT("hbtrie key test");
}

void _key_expand(char *key_ori, char *key_out, int rpt)
{
    size_t i;
    for (i=0;i<strlen(key_ori);++i){
        memset(key_out + i*rpt, *(key_ori + i), rpt-1);
        memset(key_out + (i+1)*rpt - 1, '_', 1);
    }
    memset(key_out + i*rpt, 0, 1);
}

void basic_test()
{
    TEST_INIT();

    int blocksize = 256;
    struct btreeblk_handle bhandle;
    struct docio_handle dhandle;
    struct filemgr *file;
    struct hbtrie trie;
    struct docio_object doc;
    struct filemgr_config config;
    uint64_t offset, offset_old, _offset;
    uint32_t docsize;
    char keybuf[256], metabuf[256], bodybuf[256];
    char dockey[256], meta[256], body[256];
    uint8_t valuebuf[8];
    hbtrie_result r;
    struct hbtrie_iterator it;
    size_t keylen;

    int i, n=7, rr;
    char **key = alca(char*, n);
    const char *key_ori[] = {"aaaa", "aaab", "aaac", "aba", "aaba", "bbbb", "aaac"};
    for (i=0;i<n;++i) {
        key[i] = alca(char, 256);
    }

    rr = system(SHELL_DEL " hbtrie_testfile");
    (void)rr;

    memset(&doc, 0, sizeof(struct docio_object));
    doc.key = (void*)keybuf;
    doc.meta = (void*)metabuf;
    doc.body = (void*)bodybuf;

    memset(&config, 0, sizeof(config));
    config.blocksize = blocksize;
    config.ncacheblock = 0;
    config.flag = 0x0;
    config.options = FILEMGR_CREATE;
    config.chunksize = sizeof(uint64_t);
    config.num_wal_shards = 8;

    filemgr_open_result result = filemgr_open((char *) "./hbtrie_testfile",
                                              get_filemgr_ops(), &config, NULL);
    file = result.file;
    docio_init(&dhandle, file, false);
    btreeblk_init(&bhandle, file, blocksize);

    hbtrie_init(&trie, 8, 8, blocksize, BLK_NOT_FOUND,
        (void*)&bhandle, btreeblk_get_ops(), (void*)&dhandle, _readkey_wrap);
    for (i=0;i<n;++i){
        _key_expand((char *) key_ori[i], key[i], 8);
        sprintf(dockey, "%s", key[i]);
        sprintf(meta, "metadata_%03d", i);
        sprintf(body, "body_%03d", i);
        docsize = _set_doc(&doc, dockey, meta, body);
        TEST_CHK(docsize != 0);
        offset = docio_append_doc(&dhandle, &doc, 0, 0);
        _offset = _endian_encode(offset);
        hbtrie_insert(&trie, (void*)key[i], strlen(key[i]),
                      (void*)&_offset, (void*)&offset_old);
        btreeblk_end(&bhandle);
    }

    hbtrie_remove(&trie, (void*)key[0], strlen(key[0]));
    btreeblk_end(&bhandle);

    filemgr_commit(file, true, NULL);

    for (i=0;i<n;++i) {
        if (i!=2) {
            r = hbtrie_find(&trie, (void*)key[i], strlen(key[i]), (void*)valuebuf);
            if (i>0) {
                TEST_CHK(r != HBTRIE_RESULT_FAIL);

                memcpy(&offset, valuebuf, 8);
                offset = _endian_decode(offset);
                docio_read_doc(&dhandle, offset, &doc, true);
                sprintf(meta, "metadata_%03d", i);
                sprintf(body, "body_%03d", i);
                TEST_CHK(!memcmp(doc.key, key[i], doc.length.keylen));
                TEST_CHK(!memcmp(doc.meta, meta, doc.length.metalen));
                TEST_CHK(!memcmp(doc.body, body, doc.length.bodylen));
            }else{
                TEST_CHK(r == HBTRIE_RESULT_FAIL);
            }
        }
    }

    DBG("trie root bid %" _F64 "\n", trie.root_bid);

    hbtrie_iterator_init(&trie, &it, NULL, 0);
    while(1){
        r = hbtrie_next(&it, (void*)keybuf, &keylen, (void*)&offset);
        if (r==HBTRIE_RESULT_FAIL) break;
        offset = _endian_decode(offset);
        docio_read_doc(&dhandle, offset, &doc, true);
        keybuf[keylen] = 0;
        DBG("%s\n", keybuf);
    }
    hbtrie_iterator_free(&it);

    filemgr_close(file, true, NULL, NULL);
    filemgr_shutdown();

    TEST_RESULT("basic test");
}

void _set_random_key(char *key, int len)
{
    key[len--] = 0;
    do {
        key[len] = '!' + random('~'-'!');
    } while(len--);
}

void large_test()
{
    TEST_INIT();

    int blocksize = 4096 * 1;
    struct btreeblk_handle bhandle;
    struct docio_handle dhandle;
    struct filemgr *file;
    struct hbtrie trie;
    struct docio_object doc;
    struct filemgr_config config;
    uint32_t docsize;
    char keybuf[256], metabuf[256], bodybuf[256];
    char dockey[256], meta[256], body[256];
    uint8_t valuebuf[8];
    hbtrie_result r;

    int i, k, n=100000, m=1, rr;
    size_t keylen = 8;
    char **key;
    uint64_t *offset;
    uint64_t _offset;

    key = (char **)malloc(sizeof(char*) * n);
    offset = (uint64_t *)malloc(sizeof(uint64_t) * n);

    doc.key = (void*)keybuf;
    doc.meta = (void*)metabuf;
    doc.body = (void*)bodybuf;

    memset(&config, 0, sizeof(config));
    config.blocksize = blocksize;
    config.ncacheblock = 0 * 1024 * 128;
    config.flag = 0;
    config.options = FILEMGR_CREATE;
    config.chunksize = sizeof(uint64_t);
    config.num_wal_shards = 8;

    DBG("filemgr, bcache init .. \n");
    rr = system(SHELL_DEL" hbtrie_testfile");
    (void)rr;
    filemgr_open_result result = filemgr_open((char *) "./hbtrie_testfile",
                                              get_filemgr_ops(), &config, NULL);
    file = result.file;
    docio_init(&dhandle, file, false);
    btreeblk_init(&bhandle, file, blocksize);

    hbtrie_init(&trie, 8, 8, blocksize, BLK_NOT_FOUND,
        (void*)&bhandle, btreeblk_get_ops(), (void*)&dhandle, _readkey_wrap);
    TEST_TIME();

    for (k=0;k<m;++k) {
        DBG("doc append .. \n");
        for (i=(n/m)*k;i<(n/m)*(k+1);++i){
            key[i] = (char *)malloc(keylen+1);
            _set_random_key(key[i], keylen);

            //DBG("%s\n", key[i]);
            sprintf(dockey, "%s", key[i]);
            sprintf(meta, "m");
            sprintf(body, "body_%3d", i);
            docsize = _set_doc(&doc, dockey, meta, body);
            TEST_CHK(docsize != 0);
            offset[i] = docio_append_doc(&dhandle, &doc, 0, 0);
        }
        TEST_TIME();

        DBG("hbtrie update .. \n");
        for (i=(n/m)*k;i<(n/m)*(k+1);++i){
            hbtrie_insert(&trie, (void*)key[i], strlen(key[i]),
                          (void*)&offset[i], (void*)&_offset);
            btreeblk_end(&bhandle);
        }
        TEST_TIME();

        DBG("filemgr commit .. \n");
        filemgr_commit(file, true, NULL);
        TEST_TIME();
    }

    for (k=0;k<m;++k) {
        DBG("doc append .. \n");
        for (i=(n/m)*k;i<(n/m)*(k+1);++i){
            sprintf(dockey, "%s", key[i]);
            sprintf(meta, "me");
            sprintf(body, "body2_%3d", i);
            docsize = _set_doc(&doc, dockey, meta, body);
            TEST_CHK(docsize != 0);
            offset[i] = docio_append_doc(&dhandle, &doc, 0, 0);
        }
        TEST_TIME();

        DBG("hbtrie update .. \n");
        for (i=(n/m)*k;i<(n/m)*(k+1);++i){
            hbtrie_insert(&trie, (void*)key[i], strlen(key[i]),
                          (void*)&offset[i], (void*)&_offset);
            btreeblk_end(&bhandle);
        }
        TEST_TIME();

        DBG("filemgr commit .. \n");
        filemgr_commit(file, true, NULL);
        TEST_TIME();
    }

    DBG("hbtrie search .. \n");
    for (i=0;i<n;++i) {
        //DBG("key %s\n", key[i]);
        r = hbtrie_find(&trie, (void*)key[i], strlen(key[i]), (void*)valuebuf);
        btreeblk_end(&bhandle);
        TEST_CHK(r != HBTRIE_RESULT_FAIL);

        if (r != HBTRIE_RESULT_FAIL) {
            memcpy(&_offset, valuebuf, 8);
            docio_read_doc(&dhandle, _offset, &doc, true);

            sprintf(meta, "me");
            sprintf(body, "body2_%3d", i);
            TEST_CHK(!memcmp(doc.key, key[i], doc.length.keylen));
            TEST_CHK(!memcmp(doc.meta, meta, doc.length.metalen));
            TEST_CHK(!memcmp(doc.body, body, doc.length.bodylen));

        }
    }
    TEST_TIME();

    DBG("hbtrie iterator ..\n");
    struct hbtrie_iterator it;
    hbtrie_iterator_init(&trie, &it, NULL, 0);
    for (i=0;i<n;++i){
        r = hbtrie_next(&it, (void*)keybuf, &keylen, (void*)&_offset);
        TEST_CHK(r != HBTRIE_RESULT_FAIL);
        btreeblk_end(&bhandle);
        docio_read_doc(&dhandle, _offset, &doc, true);
        /*
        keybuf[keylen] = 0;
        DBG("%s\n", keybuf);*/
    }
    hbtrie_iterator_free(&it);


    TEST_TIME();

    DBG("trie root bid %" _F64 "\n", trie.root_bid);

    filemgr_close(file, true, NULL, NULL);
    filemgr_shutdown();

    TEST_RESULT("large test");
}

char **_skew_key_ptr;
size_t _readkey_wrap_memory(void *handle, uint64_t offset, void *buf)
{
    keylen_t keylen;
    offset = _endian_decode(offset);
    keylen = strlen(_skew_key_ptr[offset]);
    memcpy(buf, _skew_key_ptr[offset], keylen);
    return keylen;
}

void skew_basic_test()
{
    TEST_INIT();

    int blocksize = 256;
    struct btreeblk_handle bhandle;
    struct docio_handle dhandle;
    struct filemgr *file;
    struct hbtrie trie;
    struct filemgr_config config;
    uint8_t value_buf[8];
    struct hbtrie_iterator it;
    hbtrie_result hr;
    size_t keylen;
    uint64_t offset, _offset;

    memleak_start();

    int i, n=22, rr;
    const char *key_const[] = {
        "aaaaaaa_",
        "aaaaaaa_aaaaaaa_",
        "aaaaaaa_aaaaaaa_aaaaaaa_",
        "bbbbbbb_",
        "bbbbbbb_bbbbbbb_",
        "bbbbbbb_bbbbccc_",
        "ccccccc_",
        "ccccccc_aaa",
        "ccccccc_aa",
        "dddddd_d",
        //"dddddd_dddaddd_d",
        "dddddd_ddddddd_d",
        "dddddd_ddddddd_ddddddd_ddddaaa_",
        "dddddd_ddddddd_dbddddb_",
        "dddddd_ddddddd_dcddddc_",
        "dddddd_ddddddd_ddddddd_ddddbbb_",
        "dddddd_ddddddd_dedddde_temp1",
        "dddddd_ddddddd_dfddddf_temp2",
        "dddddd_ddddddd_dgddddg_temp3",
        "dddddd_ddddddd_dhddddh_temp4",
        "dddddd_ddddddd_diddddi_",
        "dddddd_ddddddd_djddddj_",
        "dddddd_ddddddd_dkddddk_",
        };
    char **key_cpy = alca(char *, n);
    char key_buf[256];

    for (i=0;i<n;++i){
        key_cpy[i] = alca(char, strlen(key_const[i])+1);
        strcpy(key_cpy[i], key_const[i]);
    }
    _skew_key_ptr = key_cpy;

    rr = system(SHELL_DEL " hbtrie_testfile");
    (void)rr;

    memset(&config, 0, sizeof(config));
    config.blocksize = blocksize;
    config.ncacheblock = 0;
    config.flag = 0x0;
    config.options = FILEMGR_CREATE;
    config.chunksize = sizeof(uint64_t);
    config.num_wal_shards = 8;

    filemgr_open_result result = filemgr_open((char*)"./hbtrie_testfile",
                                              get_filemgr_ops(), &config, NULL);
    file = result.file;
    docio_init(&dhandle, file, false);
    btreeblk_init(&bhandle, file, blocksize);

    hbtrie_init(&trie, 8, 8, blocksize, BLK_NOT_FOUND,
        (void *)&bhandle, btreeblk_get_ops(), (void *)&dhandle, _readkey_wrap_memory);
    hbtrie_set_flag(&trie, HBTRIE_FLAG_COMPACT);
    hbtrie_set_leaf_height_limit(&trie, 1);

    for (i=0;i<n;++i){
        offset = i;
        _offset = _endian_encode(offset);
        hbtrie_insert(&trie, (void *)key_cpy[i], strlen(key_cpy[i]),
                      (void *)&_offset, (void *)value_buf);
        btreeblk_end(&bhandle);
    }

    // find all keys
    for (i=0;i<n;++i){
        hbtrie_find(&trie, (void *)key_cpy[i], strlen(key_cpy[i]),
                    (void *)&offset);
        btreeblk_end(&bhandle);
        offset = _endian_decode(offset);
        printf("%s\n", key_cpy[offset]);
    }

    // range scan from the beginning
    printf("\n");
    hr = hbtrie_iterator_init(&trie, &it, NULL, 0);
    while (hr == HBTRIE_RESULT_SUCCESS) {
        hr = hbtrie_next(&it, (void *)key_buf, &keylen, (void *)&offset);
        btreeblk_end(&bhandle);
        if (hr != HBTRIE_RESULT_SUCCESS) break;
        key_buf[keylen]=0;
        printf("%s %d\n", key_buf, (int)keylen);
    }
    hbtrie_iterator_free(&it);

    // range scan from the middle
    printf("\n");
    sprintf(key_buf, "aaaaaaa_aaaaaaa_a");
    hr = hbtrie_iterator_init(&trie, &it, (void*)key_buf, strlen(key_buf));
    while (hr == HBTRIE_RESULT_SUCCESS) {
        hr = hbtrie_next(&it, (void*)key_buf, &keylen, (void*)&offset);
        btreeblk_end(&bhandle);
        if (hr != HBTRIE_RESULT_SUCCESS) break;
        key_buf[keylen]=0;
        printf("%s %d\n", key_buf, (int)keylen);
    }
    hbtrie_iterator_free(&it);

    // remove metasection key
    hr = hbtrie_remove(&trie, (void*)key_cpy[6], strlen(key_cpy[6]));
    TEST_CHK(hr == HBTRIE_RESULT_SUCCESS);
    btreeblk_end(&bhandle);
    sprintf(key_buf, "aaaaaaa_a");  // not exist key
    hr = hbtrie_remove(&trie, (void*)key_buf, strlen(key_buf));    // must fail
    TEST_CHK(hr != HBTRIE_RESULT_SUCCESS);
    btreeblk_end(&bhandle);
    hr = hbtrie_remove(&trie, (void*)key_cpy[4], strlen(key_cpy[4]));
    TEST_CHK(hr == HBTRIE_RESULT_SUCCESS);
    btreeblk_end(&bhandle);

    // update metasection key
    offset = 3;
    _offset = _endian_encode(offset);
    hr = hbtrie_insert(&trie, (void*)key_cpy[offset], strlen(key_cpy[offset]),
                       (void*)&_offset, (void*)value_buf);
    TEST_CHK(hr == HBTRIE_RESULT_SUCCESS);
    btreeblk_end(&bhandle);

    // update leaf tree key
    offset = 1;
    _offset = _endian_encode(offset);
    hr = hbtrie_insert(&trie, (void*)key_cpy[offset], strlen(key_cpy[offset]),
                       (void*)&_offset, (void*)value_buf);
    TEST_CHK(hr == HBTRIE_RESULT_UPDATE);
    btreeblk_end(&bhandle);

    // update normal tree key
    offset = 16;
    _offset = _endian_encode(offset);
    hr = hbtrie_insert(&trie, (void*)key_cpy[offset], strlen(key_cpy[offset]),
                       (void*)&_offset, (void*)value_buf);
    TEST_CHK(hr == HBTRIE_RESULT_UPDATE);
    btreeblk_end(&bhandle);

    // range scan from the beginning
    printf("\n");
    hr = hbtrie_iterator_init(&trie, &it, NULL, 0);
    while (hr == HBTRIE_RESULT_SUCCESS) {
        hr = hbtrie_next(&it, (void*)key_buf, &keylen, (void*)&offset);
        btreeblk_end(&bhandle);
        if (hr != HBTRIE_RESULT_SUCCESS) break;
        key_buf[keylen]=0;
        printf("%s %d\n", key_buf, (int)keylen);
    }
    hbtrie_iterator_free(&it);

    // range scan from the beginning (using wo key API)
    printf("\n");
    hr = hbtrie_iterator_init(&trie, &it, NULL, 0);
    while (hr == HBTRIE_RESULT_SUCCESS) {
        hr = hbtrie_next_value_only(&it, (void*)&offset);
        btreeblk_end(&bhandle);
        if (hr != HBTRIE_RESULT_SUCCESS) break;
        key_buf[keylen]=0;
        offset = _endian_decode(offset);
        printf("%s %d\n", key_cpy[offset], (int)offset);
    }
    hbtrie_iterator_free(&it);

    filemgr_commit(file, true, NULL);

    hbtrie_free(&trie);
    docio_free(&dhandle);
    btreeblk_free(&bhandle);
    filemgr_close(file, true, NULL, NULL);
    filemgr_shutdown();

    memleak_end();

    TEST_RESULT("skew basic test");
}

#define HB_KEYSTR "key%06d"
size_t _readkey_wrap_memory_itr(void *handle, uint64_t offset, void *buf)
{
    offset = _endian_decode(offset);
    memset(buf, 0, 16);
    sprintf((char*)buf, HB_KEYSTR, (int)offset);
    return strlen((char*)buf);
}

void hbtrie_reverse_iterator_test()
{
    TEST_INIT();

    int ksize = 8, vsize = 8, r, n=30, c;
    int nodesize = 256;
    uint64_t i, v, v_out;
    char key[256], key_temp[256];
    size_t keylen;
    struct filemgr *file;
    struct btreeblk_handle bhandle;
    struct hbtrie trie;
    struct hbtrie_iterator hit;
    struct filemgr_config config;
    hbtrie_result hr;
    filemgr_open_result fr;
    char *fname = (char *) "./hbtrie_testfile";

    r = system(SHELL_DEL" hbtrie_testfile");
    (void)r;
    memleak_start();

    memset(&config, 0, sizeof(config));
    config.blocksize = nodesize;
    config.options = FILEMGR_CREATE;
    config.chunksize = ksize;
    config.num_wal_shards = 8;

    fr = filemgr_open(fname, get_filemgr_ops(), &config, NULL);
    file = fr.file;

    btreeblk_init(&bhandle, file, nodesize);
    hbtrie_init(&trie, ksize, vsize, nodesize, BLK_NOT_FOUND,
        &bhandle, btreeblk_get_ops(), NULL, _readkey_wrap_memory_itr);

    for (i=0;i<(uint64_t)n;++i){
        v = _endian_encode(i);
        sprintf(key, HB_KEYSTR, (int)i);
        hbtrie_insert(&trie, key, strlen(key), &v, &v_out);
        btreeblk_end(&bhandle);
    }

    c = 0;
    hbtrie_iterator_init(&trie, &hit, NULL, 0);
    while( (hr=hbtrie_next(&hit, key, &keylen, &v)) == HBTRIE_RESULT_SUCCESS) {
        btreeblk_end(&bhandle);
        v = _endian_decode(v);
        sprintf(key_temp, HB_KEYSTR, (int)c);
        TEST_CHK(!memcmp(key, key_temp, keylen));
        TEST_CHK(v == (uint64_t)c);
        c++;
    }
    btreeblk_end(&bhandle);
    hbtrie_iterator_free(&hit);
    TEST_CHK(c == n);

    c = 0;
    hbtrie_iterator_init(&trie, &hit, NULL, 0);
    while(1) {
        hr=hbtrie_prev(&hit, key, &keylen, &v);
        btreeblk_end(&bhandle);
        if (hr != HBTRIE_RESULT_SUCCESS) break;
        v = _endian_decode(v);
        c++;
    }
    btreeblk_end(&bhandle);
    hbtrie_iterator_free(&hit);
    TEST_CHK(c == 0);

    c = 0;
    sprintf(key, HB_KEYSTR, (int)n*2);
    hbtrie_iterator_init(&trie, &hit, key, strlen(key));
    while(1) {
        hr=hbtrie_prev(&hit, key, &keylen, &v);
        btreeblk_end(&bhandle);
        if (hr != HBTRIE_RESULT_SUCCESS) break;
        v = _endian_decode(v);
        sprintf(key_temp, HB_KEYSTR, (int)(n-c-1));
        TEST_CHK(!memcmp(key, key_temp, keylen));
        TEST_CHK(v == (uint64_t)n-c-1);
        c++;
    }
    btreeblk_end(&bhandle);
    hbtrie_iterator_free(&hit);
    TEST_CHK(c == n);

    c = 0;
    sprintf(key, HB_KEYSTR"xx", (int)n/2);
    hbtrie_iterator_init(&trie, &hit, key, strlen(key));
    while(1) {
        hr=hbtrie_prev(&hit, key, &keylen, &v);
        btreeblk_end(&bhandle);
        if (hr != HBTRIE_RESULT_SUCCESS) break;
        v = _endian_decode(v);
        sprintf(key_temp, HB_KEYSTR, (int)((n/2)-c));
        TEST_CHK(!memcmp(key, key_temp, keylen));
        TEST_CHK(v == (uint64_t)(n/2)-c);
        c++;
    }
    btreeblk_end(&bhandle);
    hbtrie_iterator_free(&hit);
    TEST_CHK(c == (n/2)+1);

    c = -1;
    hbtrie_iterator_init(&trie, &hit, NULL, 0);
    for (i=0;i<21;++i){
        c++;
        hr=hbtrie_next(&hit, key, &keylen, &v);
        TEST_CHK(hr != HBTRIE_RESULT_FAIL);
        btreeblk_end(&bhandle);
        v = _endian_decode(v);
        sprintf(key_temp, HB_KEYSTR, (int)c);
        TEST_CHK(!memcmp(key, key_temp, keylen));
        TEST_CHK(v == (uint64_t)c);
    }
    for (i=0;i<10;++i){
        c--;
        hr=hbtrie_prev(&hit, key, &keylen, &v);
        TEST_CHK(hr != HBTRIE_RESULT_FAIL);
        btreeblk_end(&bhandle);
        v = _endian_decode(v);
        sprintf(key_temp, HB_KEYSTR, (int)c);
        TEST_CHK(!memcmp(key, key_temp, keylen));
        TEST_CHK(v == (uint64_t)c);
    }
    for (i=0;i<19;++i){
        c++;
        hr=hbtrie_next(&hit, key, &keylen, &v);
        TEST_CHK(hr != HBTRIE_RESULT_FAIL);
        btreeblk_end(&bhandle);
        v = _endian_decode(v);
        sprintf(key_temp, HB_KEYSTR, (int)c);
        TEST_CHK(!memcmp(key, key_temp, keylen));
        TEST_CHK(v == (uint64_t)c);
    }
    hr=hbtrie_next(&hit, key, &keylen, &v);
    btreeblk_end(&bhandle);
    TEST_CHK(hr == HBTRIE_RESULT_FAIL);
    hbtrie_iterator_free(&hit);

    hbtrie_free(&trie);
    btreeblk_free(&bhandle);
    filemgr_close(file, true, NULL, NULL);
    filemgr_shutdown();
    memleak_end();

    TEST_RESULT("HB+trie reverse iterator test");
}

size_t _key_wrap_partial_update(void *handle, uint64_t offset, void *buf)
{
    char keystr[] = "key%05d%08d%08d";
    offset = _endian_decode(offset);
    offset = offset % 100; // to handle same key different value
    memset(buf, 0, strlen(keystr)+1);
    sprintf((char*)buf, keystr, (int)(offset/9), (int)((offset/3)%3), (int)(offset%3));
    return strlen((char*)buf);
}

void hbtrie_partial_update_test()
{
    TEST_INIT();

    int ksize = 8, vsize = 8, r, n=27;
    int nodesize = 256;
    uint64_t i, v, v_out;
    uint64_t v1[3], v2[9];
    char key[256];
    char keystr[] = "key%05d%08d%08d";
    struct filemgr *file;
    struct btreeblk_handle bhandle;
    struct hbtrie trie;
    struct filemgr_config config;
    hbtrie_result hr;
    filemgr_open_result fr;
    char *fname = (char *) "./hbtrie_testfile";

    memleak_start();

    r = system(SHELL_DEL" hbtrie_testfile");
    (void)r;

    memset(&config, 0, sizeof(config));
    config.blocksize = nodesize;
    config.options = FILEMGR_CREATE;
    config.chunksize = ksize;
    config.num_wal_shards = 8;

    fr = filemgr_open(fname, get_filemgr_ops(), &config, NULL);
    file = fr.file;

    btreeblk_init(&bhandle, file, nodesize);
    hbtrie_init(&trie, ksize, vsize, nodesize, BLK_NOT_FOUND,
        &bhandle, btreeblk_get_ops(), NULL, _key_wrap_partial_update);

    for (i=0;i<(uint64_t)n;++i) {
        v = _endian_encode(i);
        sprintf(key, keystr, (int)(i/9), (int)((i/3)%3), (int)(i%3));
        hbtrie_insert(&trie, key, strlen(key), &v, &v_out);
        btreeblk_end(&bhandle);
    }
    filemgr_commit(file, true, NULL);
    //printf("root: %lx\n", trie.root_bid);

    // retrieve check
    for (i=0;i<(uint64_t)n;++i) {
        sprintf(key, keystr, (int)(i/9), (int)((i/3)%3), (int)(i%3));
        hbtrie_find(&trie, key, strlen(key), &v);
        btreeblk_end(&bhandle);
        v = _endian_decode(v);
        TEST_CHK(v == i);
    }

    // retrieve partial key & temporarily save
    for (i=0;i<3;++i){
        sprintf(key, "key%05d", (int)i);
        hbtrie_find_partial(&trie, key, strlen(key), &v);
        btreeblk_end(&bhandle);
        v1[i] = v;
        v = _endian_decode(v);
    }
    for (i=0;i<9;++i){
        sprintf(key, "key%05d%08d", (int)(i/3), (int)(i%3));
        hbtrie_find_partial(&trie, key, strlen(key), &v);
        btreeblk_end(&bhandle);
        v2[i] = v;
        v = _endian_decode(v);
    }

    // update: using value + 100 (will point to same key)
    for (i=0;i<(uint64_t)n;++i) {
        v = _endian_encode(i+100);
        sprintf(key, keystr, (int)(i/9), (int)((i/3)%3), (int)(i%3));
        hbtrie_insert(&trie, key, strlen(key), &v, &v_out);
        btreeblk_end(&bhandle);
    }
    filemgr_commit(file, true, NULL);

    // replace the first-level chunks by old values
    for (i=0;i<3;++i){
        sprintf(key, "key%05d", (int)i);
        hbtrie_insert_partial(&trie, key, strlen(key), &v1[i], &v_out);
        btreeblk_end(&bhandle);
    }
    filemgr_commit(file, true, NULL);

    // retrieve check
    for (i=0;i<(uint64_t)n;++i) {
        sprintf(key, keystr, (int)(i/9), (int)((i/3)%3), (int)(i%3));
        hbtrie_find(&trie, key, strlen(key), &v);
        btreeblk_end(&bhandle);
        v = _endian_decode(v);
        TEST_CHK(v == i);
    }

    // update again: using value + 200 (will point to same key)
    for (i=0;i<(uint64_t)n;++i) {
        v = _endian_encode(i+200);
        sprintf(key, keystr, (int)(i/9), (int)((i/3)%3), (int)(i%3));
        hbtrie_insert(&trie, key, strlen(key), &v, &v_out);
        btreeblk_end(&bhandle);
    }
    filemgr_commit(file, true, NULL);

    // replace the second-level chunks by old values
    for (i=0;i<9;++i){
        sprintf(key, "key%05d%08d", (int)(i/3), (int)(i%3));
        hbtrie_insert_partial(&trie, key, strlen(key), &v2[i], &v_out);
        btreeblk_end(&bhandle);
    }
    filemgr_commit(file, true, NULL);

    // retrieve check
    for (i=0;i<(uint64_t)n;++i) {
        sprintf(key, keystr, (int)(i/9), (int)((i/3)%3), (int)(i%3));
        hbtrie_find(&trie, key, strlen(key), &v);
        btreeblk_end(&bhandle);
        v = _endian_decode(v);
        TEST_CHK(v == i);
    }

    // partially remove
    i = 1;
    sprintf(key, "key%05d%08d", (int)(i/3), (int)(i%3));
    hbtrie_remove_partial(&trie, key, strlen(key));
    btreeblk_end(&bhandle);

    i = 1;
    sprintf(key, "key%05d", (int)i);
    hbtrie_remove_partial(&trie, key, strlen(key));
    btreeblk_end(&bhandle);
    filemgr_commit(file, true, NULL);

    // retrieve check
    for (i=0;i<(uint64_t)n;++i) {
        sprintf(key, keystr, (int)(i/9), (int)((i/3)%3), (int)(i%3));
        hr = hbtrie_find(&trie, key, strlen(key), &v);
        btreeblk_end(&bhandle);
        v = _endian_decode(v);

        if ( ((i/9) == 0 && ((i/3)%3) == 1) ||
              (i/9) == 1) {
            TEST_CHK(hr != HBTRIE_RESULT_SUCCESS);
        } else {
            TEST_CHK(hr == HBTRIE_RESULT_SUCCESS);
        }
    }

    hbtrie_free(&trie);
    btreeblk_free(&bhandle);
    filemgr_close(file, true, NULL, NULL);
    filemgr_shutdown();
    memleak_end();

    TEST_RESULT("HB+trie partial update test");
}

int main(){
#ifdef _MEMPOOL
    mempool_init();
#endif

    //hbtrie_key_test();
    basic_test();
    skew_basic_test();
    hbtrie_reverse_iterator_test();
    hbtrie_partial_update_test();
    //large_test();

    return 0;
}
