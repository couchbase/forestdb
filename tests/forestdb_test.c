#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <pthread.h>
#include <time.h>

#include "hbtrie.h"
#include "test.h"
#include "btreeblock.h"
#include "docio.h"
#include "filemgr.h"
#include "filemgr_ops_linux.h"
#include "forestdb.h"

#include "memleak.h"

#define NCORES (sysconf(_SC_NPROCESSORS_ONLN))

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
    config.buffercache_size = 0 * 1024 * 1024;
    config.wal_threshold = 1024;
    config.seqtree_opt = FDB_SEQTREE_USE;
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
    config.buffercache_size = 0 * 1024 * 1024;
    config.wal_threshold = 1024;
    config.seqtree_opt = FDB_SEQTREE_USE;
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

    // free all documents
    for (i=0;i<n;++i){
        fdb_doc_free(doc[i]);
    }

    // close db file
    fdb_close(&db);

    // free all resources
    fdb_shutdown();

    memleak_end();

    TEST_RESULT("WAL commit test");
}

void multi_version_test()
{
    TEST_INIT();

    memleak_start();

    int i, r;
    int n = 2;
    fdb_handle db, db_new;
    fdb_config config;
    fdb_doc *doc[n], *rdoc;
    fdb_status status;
    
    char keybuf[256], metabuf[256], bodybuf[256], temp[256];

    // configuration
    memset(&config, 0, sizeof(fdb_config));
    config.chunksize = config.offsetsize = sizeof(uint64_t);
    config.buffercache_size = 1 * 1024 * 1024;
    config.wal_threshold = 1024;
    config.seqtree_opt = FDB_SEQTREE_USE;
    config.flag = 0;

    // remove previous dummy files
    r = system("rm -rf ./dummy* > errorlog.txt");
    
    // open db
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

    // manually flush WAL
    fdb_flush_wal(&db);
    // commit
    fdb_commit(&db);

    // open same db file using a new handle
    fdb_open(&db_new, "./dummy1", config);

    // update documents using the old handle
    for (i=0;i<n;++i){
        sprintf(metabuf, "meta2%d", i);
        sprintf(bodybuf, "body2%d", i);
        fdb_doc_update(&doc[i], metabuf, strlen(metabuf), bodybuf, strlen(bodybuf));
        fdb_set(&db, doc[i]);
    }

    // manually flush WAL and commit using the old handle
    fdb_flush_wal(&db);
    fdb_commit(&db);

    // retrieve documents using the old handle
    for (i=0;i<n;++i){
        // search by key
        fdb_doc_create(&rdoc, doc[i]->key, doc[i]->keylen, NULL, 0, NULL, 0);
        status = fdb_get(&db, rdoc);

        TEST_CHK(status == FDB_RESULT_SUCCESS);
        TEST_CHK(!memcmp(rdoc->meta, doc[i]->meta, rdoc->metalen));
        TEST_CHK(!memcmp(rdoc->body, doc[i]->body, rdoc->bodylen));

        // free result document
        fdb_doc_free(rdoc);
    }
    
    // retrieve documents using the new handle
    for (i=0;i<n;++i){
        // search by key
        fdb_doc_create(&rdoc, doc[i]->key, doc[i]->keylen, NULL, 0, NULL, 0);
        status = fdb_get(&db_new, rdoc);

        TEST_CHK(status == FDB_RESULT_SUCCESS);
        TEST_CHK(!memcmp(rdoc->meta, doc[i]->meta, rdoc->metalen));
        TEST_CHK(!memcmp(rdoc->body, doc[i]->body, rdoc->bodylen));

        // free result document
        fdb_doc_free(rdoc);
    }

    // close and re-open the new handle
    fdb_close(&db_new);
    fdb_open(&db_new, "./dummy1", config);

    // retrieve documents using the new handle
    for (i=0;i<n;++i){
        // search by key
        fdb_doc_create(&rdoc, doc[i]->key, doc[i]->keylen, NULL, 0, NULL, 0);
        status = fdb_get(&db_new, rdoc);

        TEST_CHK(status == FDB_RESULT_SUCCESS);
        // the new version of data should be read
        TEST_CHK(!memcmp(rdoc->meta, doc[i]->meta, rdoc->metalen));
        TEST_CHK(!memcmp(rdoc->body, doc[i]->body, rdoc->bodylen));

        // free result document
        fdb_doc_free(rdoc);
    }
    

    // free all documents
    for (i=0;i<n;++i){
        fdb_doc_free(doc[i]);
    }

    // close db file
    fdb_close(&db);
    fdb_close(&db_new);

    // free all resources
    fdb_shutdown();

    memleak_end();

    TEST_RESULT("multi version test");
}

void compact_wo_reopen_test()
{
    TEST_INIT();

    memleak_start();

    int i, r;
    int n = 3;
    fdb_handle db, db_new;
    fdb_config config;
    fdb_doc *doc[n], *rdoc;
    fdb_status status;
    
    char keybuf[256], metabuf[256], bodybuf[256], temp[256];

    // configuration
    memset(&config, 0, sizeof(fdb_config));
    config.chunksize = config.offsetsize = sizeof(uint64_t);
    config.buffercache_size = 1 * 1024 * 1024;
    config.wal_threshold = 1024;
    config.seqtree_opt = FDB_SEQTREE_USE;
    config.flag = 0;

    // remove previous dummy files
    r = system("rm -rf ./dummy* > errorlog.txt");
    
    // open db
    fdb_open(&db, "./dummy1", config);
    fdb_open(&db_new, "./dummy1", config);

    // insert documents
    for (i=0;i<n;++i){
        sprintf(keybuf, "key%d", i);
        sprintf(metabuf, "meta%d", i);
        sprintf(bodybuf, "body%d", i);
        fdb_doc_create(&doc[i], 
            keybuf, strlen(keybuf), metabuf, strlen(metabuf), bodybuf, strlen(bodybuf));
        fdb_set(&db, doc[i]);
    }

    // remove doc   
    fdb_doc_create(&rdoc, doc[1]->key, doc[1]->keylen, doc[1]->meta, doc[1]->metalen, NULL, 0);
    fdb_set(&db, rdoc);
    fdb_doc_free(rdoc);

    // manually flush WAL
    fdb_flush_wal(&db);
    // commit
    fdb_commit(&db);

    // perform compaction using one handle
    fdb_compact(&db, "./dummy2");

    // retrieve documents using the other handle without close/re-open
    for (i=0;i<n;++i){
        // search by key
        fdb_doc_create(&rdoc, doc[i]->key, doc[i]->keylen, NULL, 0, NULL, 0);
        status = fdb_get(&db_new, rdoc);

        if (i != 1) {    
            TEST_CHK(status == FDB_RESULT_SUCCESS);
            TEST_CHK(!memcmp(rdoc->meta, doc[i]->meta, rdoc->metalen));
            TEST_CHK(!memcmp(rdoc->body, doc[i]->body, rdoc->bodylen));
        }else{
            TEST_CHK(status == FDB_RESULT_FAIL);
        }

        // free result document
        fdb_doc_free(rdoc);
    }
    // check the other handle's filename
    TEST_CHK(!strcmp("./dummy2", db_new.file->filename));

    // free all documents
    for (i=0;i<n;++i){
        fdb_doc_free(doc[i]);
    }

    // close db file
    fdb_close(&db);
    fdb_close(&db_new);

    // free all resources
    fdb_shutdown();

    memleak_end();

    TEST_RESULT("compaction without reopen test");
}

struct timespec _time_gap(struct timespec a, struct timespec b) 
{
	struct timespec ret;
	if (b.tv_nsec >= a.tv_nsec) {
		ret.tv_nsec = b.tv_nsec - a.tv_nsec;
		ret.tv_sec = b.tv_sec - a.tv_sec;
	}else{
		ret.tv_nsec = 1000000000 + b.tv_nsec - a.tv_nsec;
		ret.tv_sec = b.tv_sec - a.tv_sec - 1;
	}
	return ret;
}

struct work_thread_args{
    int tid;
    size_t ndocs;
    size_t writer;
    fdb_config *config;
    fdb_doc **doc;
    size_t time_sec;
    size_t nbatch;
    size_t compact_term;
};

#define FILENAME "./dummy"
#define KSIZE (100)
#define VSIZE (100)
#define IDX_DIGIT (7)
#define IDX_DIGIT_STR "7"

void *_worker_thread(void *voidargs)
{
    struct timespec ts_begin, ts_cur, ts_gap;
    struct work_thread_args *args = (struct work_thread_args *)voidargs;
    int i, r, k, c, commit_count, filename_count;
    fdb_handle db;
    fdb_status status;
    fdb_doc *rdoc;
    char temp[1024];
    
    char cnt_str[IDX_DIGIT+1];
    int cnt_int;

    filename_count = 1;
    sprintf(temp, FILENAME"%d", filename_count);
    fdb_open(&db, temp, *(args->config));

    clock_gettime(CLOCK_REALTIME, &ts_begin);

    c = cnt_int = commit_count = 0;
    cnt_str[IDX_DIGIT] = 0;
    
    while(1){
        i = rand() % args->ndocs;
        fdb_doc_create(&rdoc, args->doc[i]->key, args->doc[i]->keylen, NULL, 0, NULL, 0);
        status = fdb_get(&db, rdoc);
        
        assert(status == FDB_RESULT_SUCCESS);
        assert(!memcmp(rdoc->body, args->doc[i]->body, (IDX_DIGIT+1)));

        if (args->writer) {
            // if writer,
            // copy and parse the counter in body            
            memcpy(cnt_str, rdoc->body+(IDX_DIGIT+1), IDX_DIGIT);
            cnt_int = atoi(cnt_str);

            // increase and rephrase
            sprintf(cnt_str, "%0"IDX_DIGIT_STR"d", ++cnt_int);
            memcpy(rdoc->body+(IDX_DIGIT+1), cnt_str, IDX_DIGIT);
            
            // update and commit
            status = fdb_set(&db, rdoc);

            if (args->nbatch > 0) {
                if (c % args->nbatch == 0) {
                    // commit for every NBATCH
                    fdb_commit(&db);
                    commit_count++;
                    
                    if (args->compact_term == commit_count && args->compact_term > 0) {
                        // do compaction for every COMPACT_TERM batch
                        sprintf(temp, FILENAME"%d", ++filename_count);
                        fdb_compact(&db, temp);
                        commit_count = 0;
                    }
                }
            }
        }
        fdb_doc_free(rdoc);
        c++;
        
        clock_gettime(CLOCK_REALTIME, &ts_cur);
        ts_gap = _time_gap(ts_begin, ts_cur);
        if (ts_gap.tv_sec >= args->time_sec) break;
    }

    DBG("Thread #%d (%s) %d ops / %d seconds\n", 
        args->tid, (args->writer)?("writer"):("reader"), c, (int)args->time_sec);
    
    fdb_flush_wal(&db);
    fdb_commit(&db);

    fdb_close(&db);    
}

void multi_thread_test(
    size_t ndocs, size_t wal_threshold, size_t time_sec, 
    size_t nbatch, size_t compact_term, size_t nwriters, size_t nreaders)
{
    TEST_INIT();

    int i, r, idx_digit, temp_len;
    int n = nwriters + nreaders;;
    pthread_t tid[n];
    void *thread_ret[n];
    struct work_thread_args args[n];
    struct timespec ts_begin, ts_cur, ts_gap;
    fdb_handle db, db_new;
    fdb_config config;
    fdb_doc *doc[ndocs], *rdoc;
    fdb_status status;
    
    char keybuf[1024], metabuf[1024], bodybuf[1024], temp[1024];

    idx_digit = IDX_DIGIT;

    // remove previous dummy files
    r = system("rm -rf "FILENAME"* > errorlog.txt");

    memleak_start();

    // configuration
    memset(&config, 0, sizeof(fdb_config));
    config.chunksize = config.offsetsize = sizeof(uint64_t);
    config.buffercache_size = (uint64_t)16 * 1024 * 1024;
    config.wal_threshold = wal_threshold;
    config.seqtree_opt = FDB_SEQTREE_USE;
    config.flag = 0;
    config.durability_opt = FDB_DRB_NONE;

    // initial population ===
    DBG("Initialize..\n");    
    // open db
    fdb_open(&db, FILENAME"1", config);

    clock_gettime(CLOCK_REALTIME, &ts_begin);

    // insert documents
    for (i=0;i<ndocs;++i){
        _set_random_string_smallabt(temp, KSIZE - (IDX_DIGIT+1));
        sprintf(keybuf, "k%0"IDX_DIGIT_STR"d%s", i, temp);
        
        sprintf(metabuf, "m%0"IDX_DIGIT_STR"d", i);

        _set_random_string_smallabt(temp, VSIZE-(IDX_DIGIT*2+1));
        sprintf(bodybuf, "b%0"IDX_DIGIT_STR"d%0"IDX_DIGIT_STR"d%s", i, 0, temp);
        
        fdb_doc_create(&doc[i], 
            keybuf, strlen(keybuf), metabuf, strlen(metabuf), bodybuf, strlen(bodybuf));
        fdb_set(&db, doc[i]);
    }

    fdb_flush_wal(&db);
    fdb_commit(&db);

    clock_gettime(CLOCK_REALTIME, &ts_cur);
    ts_gap = _time_gap(ts_begin, ts_cur);
    //DBG("%d.%09d seconds elapsed\n", (int)ts_gap.tv_sec, (int)ts_gap.tv_nsec);

    fdb_close(&db);
    // end of population ===

    // drop OS's page cache
    //r = system("free && sync && echo 3 > /proc/sys/vm/drop_caches && free");

    // create workers
    for (i=0;i<n;++i){
        args[i].tid = i;
        args[i].writer = ((i<nwriters)?(1):(0));
        args[i].ndocs = ndocs;
        args[i].config = &config;
        args[i].doc = doc;
        args[i].time_sec = time_sec;
        args[i].nbatch = nbatch;
        args[i].compact_term = compact_term;
        pthread_create(&tid[i], NULL, _worker_thread, &args[i]);
    }

    fprintf(stderr, "wait for %d seconds..\n", (int)time_sec);

    // wait for thread termination
    for (i=0;i<n;++i){
        pthread_join(tid[i], &thread_ret[i]);
    }

    // free all documents
    for (i=0;i<ndocs;++i){
        fdb_doc_free(doc[i]);
    }   

    // shutdown
    fdb_shutdown();

    memleak_end();

    TEST_RESULT("multi thread test");
}

int main(){
    basic_test();
    wal_commit_test();
    multi_version_test();
    compact_wo_reopen_test();
    multi_thread_test(40*1024, 1024, 10, 100, 100, 1, 7);
    
    return 0;
}
