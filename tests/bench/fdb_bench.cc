#include <stdio.h>
#include "config.h"
#include "timing.h"
#include "libforestdb/forestdb.h"

#include "test.h"

struct thread_context {
    fdb_kvs_handle *handle;
    ts_nsec latency1;
    ts_nsec latency2;
    float avg_latency1;
    float avg_latency2;
};

void print_stat(const char *name, float latency){
    printf("%-15s %f\n", name, latency);
}

void print_stats(fdb_file_handle *h){
    TEST_INIT();

    int i;
    fdb_status status;
    fdb_latency_stat stat;
    const char *name;

    for (i=0;i<FDB_LATENCY_NUM_STATS;i++){
        memset(&stat, 0, sizeof(fdb_latency_stat));
        status = fdb_get_latency_stats(h, &stat, i);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        if(stat.lat_count==0){
          continue;
        }
        name = fdb_latency_stat_name(i);
        printf("%-15s %u\n", name, stat.lat_avg);
    }
}

void print_stats_aggregate(fdb_file_handle **dbfiles, int nfiles){
    TEST_INIT();

    int i,j;
    uint32_t cnt, sum, avg = 0;
    fdb_status status;
    fdb_latency_stat stat;
    const char *name;

    for (i=0;i<FDB_LATENCY_NUM_STATS;i++){

        cnt = 0; sum = 0;

        // avg of each stat across dbfiles
        for(j=0;j<nfiles;j++){
            memset(&stat, 0, sizeof(fdb_latency_stat));
            status = fdb_get_latency_stats(dbfiles[j], &stat, i);
            TEST_CHK(status == FDB_RESULT_SUCCESS);
            cnt += stat.lat_count;
            sum += stat.lat_avg;
        }
        if(cnt > 0){
          name = fdb_latency_stat_name(i);
          avg = sum/nfiles;
          printf("%-15s %u\n", name, avg);
        }
    }
}

void str_gen(char *s, const int len) {
    int i = 0;
    static const char alphanum[] =
        "0123456789"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz";
    size_t n_ch = strlen(alphanum);

    if (len < 1){
        return;
    }

    // return same ordering of chars
    while(i<len){
        s[i] = alphanum[i%n_ch];
        i++;
    }
    s[len-1] = '\0';
}

void swap(char *x, char *y)
{
    char temp;
    temp = *x;
    *x = *y;
    *y = temp;
}

void permute(fdb_kvs_handle *kv, char *a, int l, int r)
{

    int i;
    char keybuf[256], metabuf[256], bodybuf[512];
    fdb_doc *doc = NULL;
    str_gen(bodybuf, 64);

    if (l == r) {
        sprintf(keybuf, a, l);
        sprintf(metabuf, "meta%d", r);
        fdb_doc_create(&doc, (void*)keybuf, strlen(keybuf),
            (void*)metabuf, strlen(metabuf), (void*)bodybuf, strlen(bodybuf));
        fdb_set(kv, doc);
        fdb_doc_free(doc);
    } else {
        for (i = l; i <= r; i++) {
            swap((a+l), (a+i));
            permute(kv, a, l+1, r);
            swap((a+l), (a+i)); //backtrack
        }
    }
}

void setup_db(fdb_file_handle **fhandle, fdb_kvs_handle **kv){

    int r;
    char cmd[64];

    fdb_status status;
    fdb_config config;
    fdb_kvs_config kvs_config;
    kvs_config = fdb_get_default_kvs_config();
    config = fdb_get_default_config();
    config.durability_opt = FDB_DRB_ASYNC;
    config.compaction_mode = FDB_COMPACTION_MANUAL;

    // cleanup first
    sprintf(cmd, SHELL_DEL" %s*>errorlog.txt", BENCHDB_NAME);
    r = system(cmd);
    (void)r;

    status = fdb_open(fhandle, BENCHDB_NAME, &config);
    assert(status == FDB_RESULT_SUCCESS);

    status = fdb_kvs_open(*fhandle, kv, BENCHKV_NAME , &kvs_config);
    assert(status == FDB_RESULT_SUCCESS);
}


void sequential_set(bool walflush){

    TEST_INIT();

    int i, n = NDOCS;
    ts_nsec latency, latency_tot = 0, latency_tot2 = 0;
    float latency_avg = 0;
    char keybuf[256], metabuf[256], bodybuf[512];

    fdb_file_handle *fhandle;
    fdb_status status;
    fdb_kvs_handle *kv, *snap_kv;
    fdb_doc *doc = NULL;
    fdb_iterator *iterator;

    printf("\nBENCH-SEQUENTIAL_SET-WALFLUSH-%d \n", walflush);

    // setup
    setup_db(&fhandle, &kv);
    str_gen(bodybuf, 64);

    // create
    for (i=0;i<n;++i){
        sprintf(keybuf, "key%d", i);
        sprintf(metabuf, "meta%d", i);
        fdb_doc_create(&doc, (void*)keybuf, strlen(keybuf),
            (void*)metabuf, strlen(metabuf), (void*)bodybuf, strlen(bodybuf));
        status = fdb_set(kv, doc);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        fdb_doc_free(doc);
        doc = NULL;
    }


    // commit
    status = fdb_commit(fhandle, FDB_COMMIT_MANUAL_WAL_FLUSH);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // create an iterator for full range
    latency = timed_fdb_iterator_init(kv, &iterator);
    print_stat(ST_ITR_INIT, latency);

    for (i=0;i<n;++i){

        // sum time of all gets
        latency = timed_fdb_iterator_get(iterator, &doc);
        if(latency == ERR_NS){ break; }
        latency_tot += latency;

        // sum time of calls to next
        latency = timed_fdb_iterator_next(iterator);
        if(latency == ERR_NS){ break; }
        latency_tot2 += latency;

        fdb_doc_free(doc);
        doc = NULL;
    }

    latency_avg = float(latency_tot)/float(n);
    print_stat(ST_ITR_GET, latency_avg);

    latency_avg = float(latency_tot2)/float(n);
    print_stat(ST_ITR_NEXT, latency_avg);

    latency = timed_fdb_iterator_close(iterator);
    print_stat(ST_ITR_CLOSE, latency);

    // get
    for (i=0;i<n;++i){
        sprintf(keybuf, "key%d", i);
        fdb_doc_create(&doc, keybuf, strlen(keybuf), NULL, 0, NULL, 0);
        status = fdb_get(kv, doc);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        fdb_doc_free(doc);
        doc = NULL;
    }

    // snapshot
    status = fdb_snapshot_open(kv, &snap_kv, FDB_SNAPSHOT_INMEM);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // compact
    status = fdb_compact(fhandle, NULL);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // delete
    latency_tot = 0;
    for (i=0;i<n;++i){
        sprintf(keybuf, "key%d", i);
        fdb_doc_create(&doc, keybuf, strlen(keybuf), NULL, 0, NULL, 0);
        latency = timed_fdb_delete(kv, doc);
        latency_tot += latency;
        fdb_doc_free(doc);
        doc = NULL;
    }

    latency_avg = float(latency_tot)/float(n);
    print_stat(ST_DELETE, latency_avg);

    print_stats(fhandle);

    latency = timed_fdb_kvs_close(snap_kv);
    print_stat(ST_SNAP_CLOSE, latency);

    latency = timed_fdb_kvs_close(kv);
    print_stat(ST_KV_CLOSE, latency);

    latency = timed_fdb_close(fhandle);
    print_stat(ST_FILE_CLOSE, latency);

    latency = timed_fdb_shutdown();
    print_stat(ST_SHUTDOWN, latency);
}

void permutated_keyset()
{
    TEST_INIT();

    char str[] = "abc123";
    int n = strlen(str);
    ts_nsec latency, latency_tot = 0, latency_tot2 = 0;
    float latency_avg = 0;

    fdb_doc *rdoc = NULL;
    fdb_file_handle *fhandle;
    fdb_iterator *iterator;
    fdb_kvs_handle *kv;
    fdb_status status;

    printf("\nBENCH-PERMUTATED_KEYSET\n");

    // setup
    setup_db(&fhandle, &kv);

    // load permuated keyset
    permute(kv, str, 0, n-1);

    status = fdb_commit(fhandle, FDB_COMMIT_MANUAL_WAL_FLUSH);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // create an iterator for full range
    latency = timed_fdb_iterator_init(kv, &iterator);
    print_stat(ST_ITR_INIT, latency);


    // repeat until fail
    do {
        // sum time of all gets
        latency = timed_fdb_iterator_get(iterator, &rdoc);
        fdb_doc_free(rdoc);
        rdoc = NULL;
        if(latency == ERR_NS){ break; }
        latency_tot += latency;

        // sum time of calls to next
        latency = timed_fdb_iterator_next(iterator);
        if(latency == ERR_NS){ break; }
        latency_tot2 += latency;

    } while (latency != ERR_NS);


    latency_avg = float(latency_tot)/float(n);
    print_stat(ST_ITR_GET, latency_avg);

    latency_avg = float(latency_tot2)/float(n);
    print_stat(ST_ITR_NEXT, latency_avg);

    latency = timed_fdb_iterator_close(iterator);
    print_stat(ST_ITR_CLOSE, latency);

    print_stats(fhandle);

    latency = timed_fdb_kvs_close(kv);
    print_stat(ST_KV_CLOSE, latency);

    latency = timed_fdb_close(fhandle);
    print_stat(ST_FILE_CLOSE, latency);

    latency = timed_fdb_shutdown();
    print_stat(ST_SHUTDOWN, latency);
}

void *writer_thread(void *args){
    TEST_INIT();

    thread_context *ctx= (thread_context*)args;
    fdb_kvs_handle *db = ctx->handle;
    char keybuf[KEY_SIZE];

    // load a permutated keyset
    str_gen(keybuf, KEY_SIZE);
    permute(db, keybuf, 0, PERMUTED_BYTES);
    return NULL;
}

void *reader_thread(void *args){
    TEST_INIT();

    thread_context *ctx= (thread_context*)args;
    fdb_kvs_handle *db = ctx->handle;
    fdb_iterator *iterator;
    fdb_doc *rdoc = NULL;
    ts_nsec latency = 0;
    float a_latency1 = 0.0, a_latency2 = 0.0;
    int samples = 0;

    latency = timed_fdb_iterator_init(db, &iterator);
    ctx->latency1 = latency;

    // repeat until fail
    do {
        // sum time of all gets
        latency = timed_fdb_iterator_get(iterator, &rdoc);
        fdb_doc_free(rdoc);
        rdoc = NULL;
        if(latency == ERR_NS){ break; }
        a_latency1 += latency;

        // sum time of calls to next
        latency = timed_fdb_iterator_next(iterator);
        if(latency == ERR_NS){ break; }
        a_latency2 += latency;

        samples++;

    } while (latency != ERR_NS);

    a_latency1 = a_latency1/samples;
    a_latency2 = a_latency2/samples;

    // get latency
    ctx->avg_latency1 = a_latency1;
    // seek latency
    ctx->avg_latency2 = a_latency2;
    // close latency
    latency = timed_fdb_iterator_close(iterator);
    ctx->latency2 = latency;

    return NULL;
}


void single_file_single_kvs(int n_threads){

    printf("\nBENCH-SINGLE_FILE_SINGLE_KVS\n");

    TEST_INIT();
    memleak_start();

    int i, r;
    ts_nsec latency =0, latency2= 0;
    float a_latency1 = 0, a_latency2 = 0;
    char cmd[64];


    fdb_status status;
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    fdb_config fconfig = fdb_get_default_config();

    thread_t *tid = alca(thread_t, n_threads);
    void **thread_ret = alca(void *, n_threads);
    thread_context *ctx = alca(thread_context, n_threads);

    sprintf(cmd, SHELL_DEL" bench* > errorlog.txt");
    r = system(cmd);
    (void)r;

    // init db with flags
    fdb_file_handle *dbfile;
    fdb_kvs_handle **db = alca(fdb_kvs_handle*, n_threads);
    fdb_kvs_handle **snap_db = alca(fdb_kvs_handle*, n_threads);
    fconfig.compaction_mode = FDB_COMPACTION_MANUAL;
    fconfig.auto_commit = false;

    status = fdb_open(&dbfile, "bench1", &fconfig);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    for (i=0;i<n_threads;++i){
        status = fdb_kvs_open(dbfile, &db[i], "db1", &kvs_config);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        ctx[i].handle = db[i];
        thread_create(&tid[i], writer_thread, (void*)&ctx[i]);
    }

    for (i=0;i<n_threads;++i){
        thread_join(tid[i], &thread_ret[i]);
    }

    status = fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // compact
    status = fdb_compact(dbfile, NULL);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // snapshot
    for (i=0;i<n_threads;++i){
        status = fdb_snapshot_open(db[i], &snap_db[i], FDB_SNAPSHOT_INMEM);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
    }

    // n concurrent readers with snap_db
    latency = 0; latency2 = 0; a_latency1 = 0; a_latency2 = 0;
    for (i=0;i<n_threads;++i){
        ctx[i].handle = snap_db[i];
        thread_create(&tid[i], reader_thread, (void*)&ctx[i]);
    }
    for (i=0;i<n_threads;++i){
        thread_join(tid[i], &thread_ret[i]);
        latency += ctx[i].latency1;
        latency2 += ctx[i].latency2;
        a_latency1 += ctx[i].avg_latency1;
        a_latency2 += ctx[i].avg_latency2;
    }
    latency = latency/n_threads;
    print_stat(ST_ITR_INIT, latency);
    a_latency1 = a_latency1/n_threads;
    print_stat(ST_ITR_GET, a_latency1);
    a_latency2 = a_latency2/n_threads;
    print_stat(ST_ITR_NEXT, a_latency2);
    latency2 = latency2/n_threads;
    print_stat(ST_ITR_CLOSE, latency2);

    // close snap and db
    latency = 0;
    for (i=0;i<n_threads;++i){
        latency += timed_fdb_kvs_close(snap_db[i]);
    }
    latency = latency/n_threads;
    print_stat(ST_SNAP_CLOSE, latency);

    print_stats(dbfile);

    // close
    latency = 0;
    for (i=0;i<n_threads;++i){
        latency += timed_fdb_kvs_close(db[i]);
    }
    latency = latency/n_threads;
    print_stat(ST_KV_CLOSE, latency);

    latency = timed_fdb_close(dbfile);
    print_stat(ST_FILE_CLOSE, latency);

    latency = timed_fdb_shutdown();
    print_stat(ST_SHUTDOWN, latency);

    memleak_end();
}

void single_file_multi_kvs(int n_threads){
    printf("\nBENCH-SINGLE_FILE_MULTI_KVS\n");

    TEST_INIT();
    memleak_start();

    int i, r;
    char cmd[64], db_name[64];
    ts_nsec latency =0, latency2= 0;
    float a_latency1 = 0, a_latency2 = 0;

    fdb_status status;
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    fdb_config fconfig = fdb_get_default_config();

    thread_t *tid = alca(thread_t, n_threads);
    void **thread_ret = alca(void *, n_threads);
    thread_context *ctx = alca(thread_context, n_threads);

    sprintf(cmd, SHELL_DEL" bench* > errorlog.txt");
    r = system(cmd);
    (void)r;

    // init db with flags
    fdb_file_handle *dbfile;
    fdb_kvs_handle **db = alca(fdb_kvs_handle*, n_threads);
    fdb_kvs_handle **snap_db = alca(fdb_kvs_handle*, n_threads);
    fconfig.compaction_mode = FDB_COMPACTION_MANUAL;
    fconfig.auto_commit = false;

    status = fdb_open(&dbfile, "bench1", &fconfig);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    for (i=0;i<n_threads;++i){
        sprintf(db_name, "db%d", i);
        status = fdb_kvs_open(dbfile, &db[i], db_name, &kvs_config);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
        ctx[i].handle = db[i];
        thread_create(&tid[i], writer_thread, (void*)&ctx[i]);
    }

    for (i=0;i<n_threads;++i){
        thread_join(tid[i], &thread_ret[i]);
    }

    status = fdb_commit(dbfile, FDB_COMMIT_MANUAL_WAL_FLUSH);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // compact
    status = fdb_compact(dbfile, NULL);
    TEST_CHK(status == FDB_RESULT_SUCCESS);

    // snapshot
    for (i=0;i<n_threads;++i){
        status = fdb_snapshot_open(db[i], &snap_db[i], FDB_SNAPSHOT_INMEM);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
    }

    // readers
    latency = 0; latency2 = 0; a_latency1 = 0; a_latency2 = 0;
    for (i=0;i<n_threads;++i){
        ctx[i].handle = snap_db[i];
        thread_create(&tid[i], reader_thread, (void*)&ctx[i]);
    }
    for (i=0;i<n_threads;++i){
        thread_join(tid[i], &thread_ret[i]);
        latency += ctx[i].latency1;
        latency2 += ctx[i].latency2;
        a_latency1 += ctx[i].avg_latency1;
        a_latency2 += ctx[i].avg_latency2;
    }
    latency = latency/n_threads;
    print_stat(ST_ITR_INIT, latency);
    a_latency1 = a_latency1/n_threads;
    print_stat(ST_ITR_GET, a_latency1);
    a_latency2 = a_latency2/n_threads;
    print_stat(ST_ITR_NEXT, a_latency2);
    latency2 = latency2/n_threads;
    print_stat(ST_ITR_CLOSE, latency2);

    // close snap and db
    latency = 0;
    for (i=0;i<n_threads;++i){
        latency += timed_fdb_kvs_close(snap_db[i]);
    }
    latency = latency/n_threads;
    print_stat(ST_SNAP_CLOSE, latency);

    print_stats(dbfile);

    // close
    latency = 0;
    for (i=0;i<n_threads;++i){
        latency += timed_fdb_kvs_close(db[i]);
    }
    latency = latency/n_threads;
    print_stat(ST_KV_CLOSE, latency);

    latency = timed_fdb_close(dbfile);
    print_stat(ST_FILE_CLOSE, latency);

    latency = timed_fdb_shutdown();
    print_stat(ST_SHUTDOWN, latency);

    memleak_end();
}

void multi_file_single_kvs(int n_threads){
    printf("\nBENCH-MULTI_FILE_SINGLE_KVS\n");

    TEST_INIT();
    memleak_start();

    int i, r;
    char cmd[64], fname[64];
    ts_nsec latency =0, latency2= 0;
    float a_latency1 = 0, a_latency2 = 0;

    fdb_status status;
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    fdb_config fconfig = fdb_get_default_config();

    thread_t *tid = alca(thread_t, n_threads);
    void **thread_ret = alca(void *, n_threads);
    thread_context *ctx = alca(thread_context, n_threads);

    sprintf(cmd, SHELL_DEL" bench* > errorlog.txt");
    r = system(cmd);
    (void)r;

    // init db with flags
    fdb_file_handle **dbfile = alca(fdb_file_handle*, n_threads);
    fdb_kvs_handle **db = alca(fdb_kvs_handle*, n_threads);
    fdb_kvs_handle **snap_db = alca(fdb_kvs_handle*, n_threads);
    fconfig.compaction_mode = FDB_COMPACTION_MANUAL;
    fconfig.auto_commit = false;

    for (i=0;i<n_threads;++i){
        sprintf(fname, "bench%d",i);
        status = fdb_open(&dbfile[i], fname, &fconfig);
        TEST_CHK(status == FDB_RESULT_SUCCESS);

        // all same kv='db1'
        status = fdb_kvs_open(dbfile[i], &db[i],
                              "db1", &kvs_config);
        TEST_CHK(status == FDB_RESULT_SUCCESS);

        ctx[i].handle = db[i];
        thread_create(&tid[i], writer_thread, (void*)&ctx[i]);
    }

    for (i=0;i<n_threads;++i){
        thread_join(tid[i], &thread_ret[i]);
    }

    // commit
    for (i=0;i<n_threads;++i){
        status = fdb_commit(dbfile[i], FDB_COMMIT_MANUAL_WAL_FLUSH);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
    }

    // compact
    for (i=0;i<n_threads;++i){
        status = fdb_compact(dbfile[i], NULL);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
    }

    // snapshot
    for (i=0;i<n_threads;++i){
        status = fdb_snapshot_open(db[i], &snap_db[i], FDB_SNAPSHOT_INMEM);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
    }

    // readers
    latency = 0; latency2 = 0; a_latency1 = 0; a_latency2 = 0;
    for (i=0;i<n_threads;++i){
        ctx[i].handle = snap_db[i];
        thread_create(&tid[i], reader_thread, (void*)&ctx[i]);
    }
    for (i=0;i<n_threads;++i){
        thread_join(tid[i], &thread_ret[i]);
        latency += ctx[i].latency1;
        latency2 += ctx[i].latency2;
        a_latency1 += ctx[i].avg_latency1;
        a_latency2 += ctx[i].avg_latency2;
    }
    latency = latency/n_threads;
    print_stat(ST_ITR_INIT, latency);
    a_latency1 = a_latency1/n_threads;
    print_stat(ST_ITR_GET, a_latency1);
    a_latency2 = a_latency2/n_threads;
    print_stat(ST_ITR_NEXT, a_latency2);
    latency2 = latency2/n_threads;
    print_stat(ST_ITR_CLOSE, latency2);

    // close snap and db
    latency = 0;
    for (i=0;i<n_threads;++i){
        latency += timed_fdb_kvs_close(snap_db[i]);
    }
    latency = latency/n_threads;
    print_stat(ST_SNAP_CLOSE, latency);

    print_stats_aggregate(dbfile, n_threads);

    // close
    latency = 0;
    for (i=0;i<n_threads;++i){
        latency += timed_fdb_kvs_close(db[i]);
    }
    latency = latency/n_threads;
    print_stat(ST_KV_CLOSE, latency);

    for (i=0;i<n_threads;++i){
        latency = timed_fdb_close(dbfile[i]);
    }
    latency = latency/n_threads;
    print_stat(ST_FILE_CLOSE, latency);

    latency = timed_fdb_shutdown();
    print_stat(ST_SHUTDOWN, latency);

    memleak_end();
}

void multi_file_multi_kvs(int n_threads){
    printf("\nBENCH-MULTI_FILE_MULTI_KVS\n");

    TEST_INIT();
    memleak_start();

    int i, j, r;
    char cmd[64], fname[64], dbname[64];
    int n2_threads = n_threads*n_threads;
    ts_nsec latency =0, latency2= 0;
    float a_latency1 = 0, a_latency2 = 0;

    fdb_status status;
    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    fdb_config fconfig = fdb_get_default_config();

    thread_t *tid = alca(thread_t, n2_threads);
    void **thread_ret = alca(void *, n2_threads);
    thread_context *ctx = alca(thread_context, n2_threads);

    sprintf(cmd, SHELL_DEL" bench* > errorlog.txt");
    r = system(cmd);
    (void)r;

    // init db with flags
    fdb_file_handle **dbfile = alca(fdb_file_handle*, n_threads);
    fdb_kvs_handle **db = alca(fdb_kvs_handle*, n2_threads);
    fdb_kvs_handle **snap_db = alca(fdb_kvs_handle*, n2_threads);
    fconfig.compaction_mode = FDB_COMPACTION_MANUAL;
    fconfig.auto_commit = false;

    for (i=0; i < n_threads; ++i){
        sprintf(fname, "bench%d",i);
        status = fdb_open(&dbfile[i], fname, &fconfig);
        TEST_CHK(status == FDB_RESULT_SUCCESS);

        for (j=i*n_threads; j < (i*n_threads + n_threads); ++j){
            sprintf(dbname, "db%d",j);
            status = fdb_kvs_open(dbfile[i], &db[j],
                                  dbname, &kvs_config);
            TEST_CHK(status == FDB_RESULT_SUCCESS);
            ctx[j].handle = db[j];
            thread_create(&tid[j], writer_thread, (void*)&ctx[j]);
        }
    }

    for (i=0;i<n2_threads;++i){
        thread_join(tid[i], &thread_ret[i]);
    }

    // commit
    for (i=0;i<n_threads;++i){
        status = fdb_commit(dbfile[i], FDB_COMMIT_MANUAL_WAL_FLUSH);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
    }

    // compact
    for (i=0;i<n_threads;++i){
        status = fdb_compact(dbfile[i], NULL);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
    }

    // snapshot
    latency = 0;
    for (i=0;i<n2_threads;++i){
        status = fdb_snapshot_open(db[i], &snap_db[i], FDB_SNAPSHOT_INMEM);
        TEST_CHK(status == FDB_RESULT_SUCCESS);
    }

    // readers
    latency = 0; latency2 = 0; a_latency1 = 0; a_latency2 = 0;
    for (i=0;i<n2_threads;++i){
        ctx[i].handle = snap_db[i];
        thread_create(&tid[i], reader_thread, (void*)&ctx[i]);
    }
    for (i=0;i<n2_threads;++i){
        thread_join(tid[i], &thread_ret[i]);
        latency += ctx[i].latency1;
        latency2 += ctx[i].latency2;
        a_latency1 += ctx[i].avg_latency1;
        a_latency2 += ctx[i].avg_latency2;
    }
    latency = latency/n2_threads;
    print_stat(ST_ITR_INIT, latency);
    a_latency1 = a_latency1/n2_threads;
    print_stat(ST_ITR_GET, a_latency1);
    a_latency2 = a_latency2/n2_threads;
    print_stat(ST_ITR_NEXT, a_latency2);
    latency2 = latency2/n2_threads;
    print_stat(ST_ITR_CLOSE, latency2);

    // close snap and db
    latency = 0;
    for (i=0;i<n2_threads;++i){
        latency += timed_fdb_kvs_close(snap_db[i]);
    }
    latency = latency/n2_threads;
    print_stat(ST_SNAP_CLOSE, latency);

    print_stats_aggregate(dbfile, n_threads);

    // close
    latency = 0;
    for (i=0;i<n2_threads;++i){
        latency += timed_fdb_kvs_close(db[i]);
    }
    latency = latency/n2_threads;
    print_stat(ST_KV_CLOSE, latency);

    for (i=0;i<n_threads;++i){
        latency = timed_fdb_close(dbfile[i]);
    }
    latency = latency/n_threads;
    print_stat(ST_FILE_CLOSE, latency);

    latency = timed_fdb_shutdown();
    print_stat(ST_SHUTDOWN, latency);

    memleak_end();
}

int main(int argc, char* args[])
{
    sequential_set(true);
    sequential_set(false);
    permutated_keyset();

    // threaded
    single_file_single_kvs(10);
    single_file_multi_kvs(10);
    multi_file_single_kvs(10);
    multi_file_multi_kvs(10);

}
