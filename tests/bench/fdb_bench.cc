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

void swap(char *x, char *y)
{
    char temp;
    temp = *x;
    *x = *y;
    *y = temp;
}

/* Function to print permutations of string
   This function takes three parameters:
   1. String
   2. Starting index of the string
   3. Ending index of the string.
   http://www.geeksforgeeks.org/write-a-c-program-to-print-all-permutations-of-a-given-string/
   */
int permute(fdb_kvs_handle *kv, char *a, int l, int r)
{

    int i;
    char keybuf[256], metabuf[256], bodybuf[512];
    fdb_doc *doc = NULL;
    ts_nsec latency = 0;

    if (l == r) {
        sprintf(keybuf, a, l);
        sprintf(metabuf, "meta%d", r);
        str_gen(bodybuf, 64);
        fdb_doc_create(&doc, (void*)keybuf, strlen(keybuf),
            (void*)metabuf, strlen(metabuf), (void*)bodybuf, strlen(bodybuf));
        latency = timed_fdb_set(kv, doc);
        fdb_doc_free(doc);
        return latency;
    } else {
        for (i = l; i <= r; i++) {
            swap((a+l), (a+i));
            latency+=permute(kv, a, l+1, r);
            swap((a+l), (a+i)); //backtrack
        }
    }
    return latency;
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
    ts_nsec latency, latency_tot = 0, latency_tot2 = 0;
    float latency_avg = 0;
    char keybuf[256], metabuf[256], bodybuf[512];

    fdb_file_handle *fhandle;
    fdb_kvs_handle *kv, *snap_kv;
    fdb_doc *doc = NULL;
    fdb_iterator *iterator;

    printf("\nBENCH-SEQUENTIAL_SET-WALFLUSH-%d \n", walflush);

    // setup
    setup_db(&fhandle, &kv);

    // create
    for (i=0;i<n;++i){
        sprintf(keybuf, "key%d", i);
        sprintf(metabuf, "meta%d", i);
        str_gen(bodybuf, 256);
        fdb_doc_create(&doc, (void*)keybuf, strlen(keybuf),
            (void*)metabuf, strlen(metabuf), (void*)bodybuf, strlen(bodybuf));
        latency = timed_fdb_set(kv, doc);
        latency_tot += latency;
	fdb_doc_free(doc);
	doc = NULL;
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
    latency_tot = 0;
    for (i=0;i<n;++i){
        sprintf(keybuf, "key%d", i);
        fdb_doc_create(&doc, keybuf, strlen(keybuf), NULL, 0, NULL, 0);
        latency = timed_fdb_get(kv, doc);
        latency_tot += latency;
        fdb_doc_free(doc);
        doc = NULL;
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
        sprintf(keybuf, "key%d", i);
        fdb_doc_create(&doc, keybuf, strlen(keybuf), NULL, 0, NULL, 0);
        latency = timed_fdb_delete(kv, doc);
        latency_tot += latency;
        fdb_doc_free(doc);
        doc = NULL;
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

void permutated_keyset()
{

    char str[] = "abc123";
    int n = strlen(str);
    ts_nsec latency, latency_tot = 0, latency_tot2 = 0;
    float latency_avg = 0;

    fdb_doc *rdoc = NULL;
    fdb_file_handle *fhandle;
    fdb_iterator *iterator;
    fdb_kvs_handle *kv;

    printf("\nBENCH-PERMUTATED_KEYSET\n");

    // setup
    setup_db(&fhandle, &kv);

    // load permuated keyset
    latency = permute(kv, str, 0, n-1);
    print_stat(ST_SET, latency);

    latency = timed_fdb_commit(fhandle, true);
    print_stat(ST_COMMIT_WAL, latency);

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
    permutated_keyset();
}
