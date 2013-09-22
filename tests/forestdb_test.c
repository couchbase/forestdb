#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "hbtrie.h"
#include "test.h"
#include "btreeblock.h"
#include "docio.h"
#include "filemgr.h"
#include "filemgr_ops_linux.h"
#include "forestdb.h"

#include "memleak.h"

void basic_test()
{
    TEST_INIT();

    memleak_start();

    int i, r;
    int n = 10;
    fdb_handle db;
    fdb_config config;
    fdb_doc *doc[n], *rdoc;
    fdb_status status;
    
    char keybuf[256], metabuf[256], bodybuf[256], temp[256];

    // configuration
    memset(&config, 0, sizeof(fdb_config));
    config.chunksize = config.offsetsize = sizeof(uint64_t);
    config.buffercache_size = 1 * 1024 * 1024;
    config.wal_threshold = 1024;
    config.seqtree = FDB_SEQTREE_USE;
    config.flag = 0;

    // remove previous dummy files
    r = system("rm -rf ./dummy* > errorlog.txt");
    
    // open and close db
    fdb_open(&db, "./dummy1", config);
    fdb_close(&db);

    // reopen db
    fdb_open(&db, "./dummy1", config);

    // insert documents
    for (i=0;i<n;++i){
        sprintf(keybuf, "key%d", i);
        sprintf(metabuf, "meta%d", i);
        sprintf(bodybuf, "body%d", i);
        fdb_doc_create(&doc[i], 
            keybuf, strlen(keybuf), metabuf, strlen(metabuf), bodybuf, strlen(bodybuf));
        fdb_set(&db, doc[i]);
    }

    // remove document #5
    fdb_doc_create(&rdoc, doc[5]->key, doc[5]->keylen, doc[5]->meta, doc[5]->metalen, NULL, 0);
    fdb_set(&db, rdoc);
    fdb_doc_free(rdoc);

    // commit
    fdb_commit(&db);

    // close the db
    fdb_close(&db);

    // reopen
    fdb_open(&db, "./dummy1", config);

    // update document #0 and #1
    for (i=0;i<2;++i){
        sprintf(metabuf, "meta2%d", i);
        sprintf(bodybuf, "body2%d", i);
        fdb_doc_update(&doc[i], metabuf, strlen(metabuf), bodybuf, strlen(bodybuf));
        fdb_set(&db, doc[i]);
    }

    // commit
    fdb_commit(&db);

    // retrieve documents
    for (i=0;i<n;++i){
        // search by key
        fdb_doc_create(&rdoc, doc[i]->key, doc[i]->keylen, NULL, 0, NULL, 0);
        status = fdb_get(&db, rdoc);

        if (i != 5) {
            // updated documents
            TEST_CHK(status == FDB_RESULT_SUCCESS);
            TEST_CHK(!memcmp(rdoc->meta, doc[i]->meta, rdoc->metalen));
            TEST_CHK(!memcmp(rdoc->body, doc[i]->body, rdoc->bodylen));
        } else {
            // removed document
            TEST_CHK(status == FDB_RESULT_FAIL);
        }

        // free result document
        fdb_doc_free(rdoc);
    }

    // do compaction
    fdb_compact(&db, "./dummy2");

    // retrieve documents after compaction
    for (i=0;i<n;++i){
        // search by key
        fdb_doc_create(&rdoc, doc[i]->key, doc[i]->keylen, NULL, 0, NULL, 0);
        status = fdb_get(&db, rdoc);

        if (i != 5) {
            // updated documents
            TEST_CHK(status == FDB_RESULT_SUCCESS);
            TEST_CHK(!memcmp(rdoc->meta, doc[i]->meta, rdoc->metalen));
            TEST_CHK(!memcmp(rdoc->body, doc[i]->body, rdoc->bodylen));
        } else {
            // removed document
            TEST_CHK(status == FDB_RESULT_FAIL);
        }

        // free result document
        fdb_doc_free(rdoc);
    }
    
    // retrieve documents by sequence number
    for (i=0;i<n;++i){
        // search by seq
        fdb_doc_create(&rdoc, NULL, 0, NULL, 0, NULL, 0);
        rdoc->seqnum = i;
        status = fdb_get_byseq(&db, rdoc);

        if ( (i>=2 && i<=4) || (i>=6 && i<=9) || (i>=11 && i<=12)) {
            // updated documents
            TEST_CHK(status == FDB_RESULT_SUCCESS);
        } else {
            // removed document
            TEST_CHK(status == FDB_RESULT_FAIL);
        }

        // free result document
        fdb_doc_free(rdoc);
    }

    // free all documents
    for (i=0;i<n;++i){
        fdb_doc_free(doc[i]);
    }

    // do one more compaction
    fdb_compact(&db, "./dummy3");

    // close db file
    fdb_close(&db);

    // free all resources
    fdb_shutdown();

    memleak_end();

    TEST_RESULT("basic test");
}

void wal_commit_test()
{
    TEST_INIT();

    memleak_start();

    int i, r;
    int n = 10;
    fdb_handle db;
    fdb_config config;
    fdb_doc *doc[n], *rdoc;
    fdb_status status;
    
    char keybuf[256], metabuf[256], bodybuf[256], temp[256];

    // configuration
    memset(&config, 0, sizeof(fdb_config));
    config.chunksize = config.offsetsize = sizeof(uint64_t);
    config.buffercache_size = 1 * 1024 * 1024;
    config.wal_threshold = 1024;
    config.seqtree = FDB_SEQTREE_USE;
    config.flag = 0;

    // remove previous dummy files
    r = system("rm -rf ./dummy* > errorlog.txt");
    
    // open db
    fdb_open(&db, "./dummy1", config);

    // insert half documents
    for (i=0;i<n/2;++i){
        sprintf(keybuf, "key%d", i);
        sprintf(metabuf, "meta%d", i);
        sprintf(bodybuf, "body%d", i);
        fdb_doc_create(&doc[i], 
            keybuf, strlen(keybuf), metabuf, strlen(metabuf), bodybuf, strlen(bodybuf));
        fdb_set(&db, doc[i]);
    }

    // commit
    fdb_commit(&db);

    // insert the other half documents
    for (i=n/2;i<n;++i){
        sprintf(keybuf, "key%d", i);
        sprintf(metabuf, "meta%d", i);
        sprintf(bodybuf, "body%d", i);
        fdb_doc_create(&doc[i], 
            keybuf, strlen(keybuf), metabuf, strlen(metabuf), bodybuf, strlen(bodybuf));
        fdb_set(&db, doc[i]);
    }

    // close the db
    fdb_close(&db);

    // reopen
    fdb_open(&db, "./dummy1", config);

    // retrieve documents
    for (i=0;i<n;++i){
        // search by key
        fdb_doc_create(&rdoc, doc[i]->key, doc[i]->keylen, NULL, 0, NULL, 0);
        status = fdb_get(&db, rdoc);

        if (i < n/2) {
            // committed documents
            TEST_CHK(status == FDB_RESULT_SUCCESS);
            TEST_CHK(!memcmp(rdoc->meta, doc[i]->meta, rdoc->metalen));
            TEST_CHK(!memcmp(rdoc->body, doc[i]->body, rdoc->bodylen));
        } else {
            // not committed document
            TEST_CHK(status == FDB_RESULT_FAIL);
        }

        // free result document
        fdb_doc_free(rdoc);
    }

    // close db file
    fdb_close(&db);

    // free all resources
    fdb_shutdown();

    memleak_end();

    TEST_RESULT("WAL commit test");
}


void _set_random_string(char *str, int len)
{
    str[len--] = 0;
    do {
        str[len] = '!' + random('~'-'!');
    } while(len--);
}

int main(){
    basic_test();
    wal_commit_test();
    
    return 0;
}
