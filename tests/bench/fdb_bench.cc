#include <stdio.h>
#include "config.h"
#include "timing.h"
#include "libforestdb/forestdb.h"

#include "test.h"

void print_stat(const char *name, float latency){
    printf("%-15s %f\n", name, latency);
}

void str_gen(char *s, const int len) {
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

    int i, n = NDOCS;
    uint64_t latency, latency_tot = 0, latency_tot2 = 0;
    float latency_avg = 0;
    char keybuf[256], metabuf[256], bodybuf[512];

    fdb_file_handle *fhandle;
    fdb_kvs_handle *kv, *snap_kv;
    fdb_doc **doc = alca(fdb_doc*, n);
    fdb_doc *rdoc = NULL;
    fdb_iterator *iterator;

    printf("\nBENCH-SEQUENTIAL_SET-WALFLUSH-%d \n", walflush);

    // setup
    setup_db(&fhandle, &kv);

    // create
    for (i=0;i<n;++i){
        sprintf(keybuf, "key%d", i);
        sprintf(metabuf, "meta%d", i);
        str_gen(bodybuf, 256);
        fdb_doc_create(&doc[i], (void*)keybuf, strlen(keybuf),
            (void*)metabuf, strlen(metabuf), (void*)bodybuf, strlen(bodybuf));
        latency = timed_fdb_set(kv, doc[i]);
        latency_tot += latency;
    }
    latency_avg = float(latency_tot)/float(n);
    print_stat(ST_SET, latency_avg);

    // commit
    latency = timed_fdb_commit(fhandle, walflush);
    if(walflush){
      print_stat(ST_COMMIT_WAL, latency);
    } else {
      print_stat(ST_COMMIT_NORM, latency);
    }

    // create an iterator for full range
    latency = timed_fdb_iterator_init(kv, &iterator);
    print_stat(ST_ITR_INIT, latency);

    for (i=0;i<n;++i){

        // sum time of all gets
        latency = timed_fdb_iterator_get(iterator, &rdoc);
        if(latency == ERR_NS){ break; }
        latency_tot += latency;

        // sum time of calls to next
        latency = timed_fdb_iterator_next(iterator);
        if(latency == ERR_NS){ break; }
        latency_tot2 += latency;

        fdb_doc_free(rdoc);
        rdoc = NULL;
    }

    latency_avg = float(latency_tot)/float(n);
    print_stat(ST_ITR_GET, latency_avg);

    latency_avg = float(latency_tot2)/float(n);
    print_stat(ST_ITR_NEXT, latency_avg);

    latency = timed_fdb_iterator_close(iterator);
    print_stat(ST_ITR_CLOSE, latency);

    // get
    latency_tot = 0;
    for (i=0;i<n;++i){
        fdb_doc_create(&rdoc, doc[i]->key, doc[i]->keylen, NULL, 0, NULL, 0);
        latency = timed_fdb_get(kv, rdoc);
        latency_tot += latency;
    }
    latency_avg = float(latency_tot)/float(n);
    print_stat(ST_GET, latency_avg);

    // snapshot
    latency = timed_fdb_snapshot(kv, &snap_kv);
    print_stat(ST_SNAP_OPEN, latency);

    // compact
    latency = timed_fdb_compact(fhandle);
    print_stat(ST_COMPACT, latency);

    // delete
    latency_tot = 0;
    for (i=0;i<n;++i){
        fdb_doc_create(&rdoc, doc[i]->key, doc[i]->keylen, NULL, 0, NULL, 0);
        latency = timed_fdb_delete(kv, rdoc);
        latency_tot += latency;
    }
    latency_avg = float(latency_tot)/float(n);
    print_stat(ST_DELETE, latency_avg);

    latency = timed_fdb_kvs_close(snap_kv);
    print_stat(ST_SNAP_CLOSE, latency);

    latency = timed_fdb_kvs_close(kv);
    print_stat(ST_KV_CLOSE, latency);

    latency = timed_fdb_close(fhandle);
    print_stat(ST_FILE_CLOSE, latency);

    latency = timed_fdb_shutdown();
    print_stat(ST_SHUTDOWN, latency);
}

int main(int argc, char* args[])
{
  sequential_set(true);
  sequential_set(false);
}
