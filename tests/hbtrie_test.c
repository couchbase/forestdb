#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "hbtrie.h"
#include "test.h"
#include "btreeblock.h"
#include "docio.h"
#include "filemgr.h"
#include "filemgr_ops_linux.h"
#include "common.h"

uint32_t _set_doc(struct docio_object *doc, char *key, char *meta, char *body)
{
    strcpy(doc->key, key);
    doc->length.keylen = strlen(doc->key);
    strcpy(doc->meta, meta);
    doc->length.metalen = strlen(doc->meta);
    strcpy(doc->body, body);
    doc->length.bodylen = strlen(doc->body);

    return sizeof(struct docio_length) + doc->length.keylen + doc->length.metalen + doc->length.bodylen;
}

size_t _readkey_wrap(void *handle, uint64_t offset, void *buf)
{
    keylen_t keylen;
    docio_read_doc_key((struct docio_handle * )handle, offset, &keylen, buf);
    return keylen;
}

void hbtrie_key_test()
{
    TEST_INIT();

    struct hbtrie trie;
    int i,j,n;

    trie.chunksize = 4;

    char *key[] = {"abc", "abcd", "abcde", "abcdef", "abcdefg", "abcdefgh"};
    char buf[256];
    int keylen;

    for (i=0;i<6;++i){
        keylen = _hbtrie_reform_key(&trie, key[i], strlen(key[i]), buf);

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
    int i;
    for (i=0;i<strlen(key_ori);++i){
        memset(key_out + i*rpt, *(key_ori + i), rpt);
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
    uint64_t offset, offset_old;
    uint32_t docsize;
    char keybuf[256], metabuf[256], bodybuf[256];
    char dockey[256], meta[256], body[256];
    uint8_t valuebuf[8];
    hbtrie_result r;
    struct hbtrie_iterator it;
    size_t keylen;

    int i, j, n=7, rr;
    char key[n][256];
    char *key_ori[] = {"aaaa", "aaab", "aaac", "aba", "aaba", "bbbb", "aaac"};

    rr = system("rm -rf ./dummy");

    doc.key = keybuf;
    doc.meta = metabuf;
    doc.body = bodybuf;

    memset(&config, 0, sizeof(config));
    config.blocksize = blocksize;
    config.ncacheblock = 1024;
    config.flag = 0x0;

    file = filemgr_open("./dummy", get_linux_filemgr_ops(), &config);
    docio_init(&dhandle, file);
    btreeblk_init(&bhandle, file, blocksize);

    hbtrie_init(&trie, 8, 8, blocksize, BLK_NOT_FOUND,
        &bhandle, btreeblk_get_ops(), &dhandle, _readkey_wrap);

    for (i=0;i<n;++i){
        _key_expand(key_ori[i], key[i], 8);
        sprintf(dockey, "%s", key[i]);
        sprintf(meta, "metadata_%03d", i);
        sprintf(body, "body_%03d", i);
        docsize = _set_doc(&doc, dockey, meta, body);
        offset = docio_append_doc(&dhandle, &doc);
        hbtrie_insert(&trie, key[i], strlen(key[i]), &offset, &offset_old);
        btreeblk_end(&bhandle);
    }

    hbtrie_remove(&trie, key[0], strlen(key[0]));
    btreeblk_end(&bhandle);

    filemgr_commit(file);

    for (i=0;i<n;++i) {
        if (i!=2) {
            r = hbtrie_find(&trie, key[i], strlen(key[i]), valuebuf);
            if (i>0) {
                TEST_CHK(r != HBTRIE_RESULT_FAIL);

                memcpy(&offset, valuebuf, 8);
                docio_read_doc(&dhandle, offset, &doc);
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

    DBG("trie root bid %"_F64"\n", trie.root_bid);

    hbtrie_iterator_init(&trie, &it, NULL, 0);
    while(1){
        r = hbtrie_next(&it, keybuf, &keylen, &offset);
        if (r==HBTRIE_RESULT_FAIL) break;
        docio_read_doc(&dhandle, offset, &doc);
        keybuf[keylen] = 0;
        DBG("%s\n", keybuf);
    }
    r = hbtrie_iterator_free(&it);

    filemgr_close(file);
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

    int i, j, k, n=1000000, m=1, rr;
    size_t keylen = 8;
    char **key;
    uint64_t *offset;
    uint64_t _offset;
    int sw;

    key = (char **)malloc(sizeof(char*) * n);
    offset = (uint64_t *)malloc(sizeof(uint64_t) * n);

    doc.key = keybuf;
    doc.meta = metabuf;
    doc.body = bodybuf;

    memset(&config, 0, sizeof(config));
    config.blocksize = blocksize;
    config.ncacheblock = 0 * 1024 * 128;
    config.flag = 0;

    DBG("filemgr, bcache init .. \n");
    rr = system("rm -rf ./dummy");
    file = filemgr_open("./dummy", get_linux_filemgr_ops(), &config);
    docio_init(&dhandle, file);
    btreeblk_init(&bhandle, file, blocksize);

    hbtrie_init(&trie, 8, 8, blocksize, BLK_NOT_FOUND,
        &bhandle, btreeblk_get_ops(), &dhandle, _readkey_wrap);
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
            offset[i] = docio_append_doc(&dhandle, &doc);
        }
        TEST_TIME();

        DBG("hbtrie update .. \n");
        for (i=(n/m)*k;i<(n/m)*(k+1);++i){
            hbtrie_insert(&trie, key[i], strlen(key[i]), offset + i, &_offset);
            btreeblk_end(&bhandle);
        }
        TEST_TIME();

        DBG("filemgr commit .. \n");
        filemgr_commit(file);
        TEST_TIME();
    }

    for (k=0;k<m;++k) {
        DBG("doc append .. \n");
        for (i=(n/m)*k;i<(n/m)*(k+1);++i){
            sprintf(dockey, "%s", key[i]);
            sprintf(meta, "me");
            sprintf(body, "body2_%3d", i);
            docsize = _set_doc(&doc, dockey, meta, body);
            offset[i] = docio_append_doc(&dhandle, &doc);
        }
        TEST_TIME();

        DBG("hbtrie update .. \n");
        for (i=(n/m)*k;i<(n/m)*(k+1);++i){
            hbtrie_insert(&trie, key[i], strlen(key[i]), offset + i, &_offset);
            btreeblk_end(&bhandle);
        }
        TEST_TIME();

        DBG("filemgr commit .. \n");
        filemgr_commit(file);
        TEST_TIME();
    }

    DBG("hbtrie search .. \n");
    for (i=0;i<n;++i) {
        //DBG("key %s\n", key[i]);
        r = hbtrie_find(&trie, key[i], strlen(key[i]), valuebuf);
        btreeblk_end(&bhandle);
        TEST_CHK(r != HBTRIE_RESULT_FAIL);

        if (r != HBTRIE_RESULT_FAIL) {
            memcpy(&_offset, valuebuf, 8);
            docio_read_doc(&dhandle, _offset, &doc);

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
        r = hbtrie_next(&it, keybuf, &keylen, &_offset);
        btreeblk_end(&bhandle);
        docio_read_doc(&dhandle, _offset, &doc);
        /*
        keybuf[keylen] = 0;
        DBG("%s\n", keybuf);*/
    }
    hbtrie_iterator_free(&it);


    TEST_TIME();

    DBG("trie root bid %"_F64"\n", trie.root_bid);

    filemgr_close(file);
    filemgr_shutdown();

    TEST_RESULT("large test");
}

int main(){
    #ifdef _MEMPOOL
        mempool_init();
    #endif

    //hbtrie_key_test();
    //basic_test();
    large_test();

    return 0;
}
