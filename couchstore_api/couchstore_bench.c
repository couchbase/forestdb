#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <assert.h>
#include <sys/types.h>
#include <unistd.h> 
#include <pthread.h>

#include "couch_common.h"
#include "couch_db.h"
#include "adv_random.h"
#include "stopwatch.h"
#include "iniparser.h"
#include "forestdb.h"

#include "arch.h"
#include "option.h"
#include "debug.h"
#include "crc32.h"

#include "memleak.h"

#ifdef __DEBUG
#ifndef __DEBUG_COUCHBENCH
    #undef DBG
    #undef DBGCMD
    #undef DBGSW
    #define DBG(args...)
    #define DBGCMD(command...)
    #define DBGSW(n, command...) 
#endif
#endif

int _basic_callback(Db *db, DocInfo *docinfo, void *ctx)
{
    //printf("%s %ld %ld %ld %ld\n", docinfo->id.buf, docinfo->db_seq, docinfo->rev_seq, docinfo->size, docinfo->bp);
    return 0;
}

void _basic_test()
{
    Db *db;
    Doc doc[10];
    sized_buf ids[10];
    DocInfo info[10], *rinfo;
    couchstore_save_options options;
    couchstore_error_t err;
    int i, ret;
    char key[256];
    char data[256]="this_is_data";
    char meta[256]="meta";

    ret = system("rm ./dummy -rf");
    couchstore_open_db("./dummy", COUCHSTORE_OPEN_FLAG_CREATE, &db);

    for (i=0;i<10;++i){
        sprintf(key,"%07d",i);

        memset(&doc[i], 0, sizeof(Doc));
        memset(&info[i], 0, sizeof(DocInfo));

        doc[i].id.buf = (char *)malloc(strlen(key)+1);
        doc[i].id.size = strlen(key)+1;
        memcpy(doc[i].id.buf, key, doc[i].id.size);

        doc[i].data.buf = (char *)malloc(strlen(data)+1);
        doc[i].data.size = strlen(data)+1;
        memcpy(doc[i].data.buf, data, doc[i].data.size);

        info[i].id = doc[i].id;
        info[i].rev_seq = i*10;
        info[i].rev_meta.size = strlen(meta) + 1;
        info[i].rev_meta.buf = meta;
        info[i].deleted = 0;
        info[i].content_meta = 0;

        err = couchstore_save_document(db, &doc[i], &info[i], 0);
    }

    couchstore_commit(db);

    for (i=0;i<10;++i){
        sprintf(key,"%07d",i);        
        ids[i].buf = (char *)malloc(strlen(key)+1);
        ids[i].size = strlen(key)+1;
        memcpy(ids[i].buf, key, ids[i].size);
        err = couchstore_docinfo_by_id(db, key, strlen(key)+1, &rinfo);
/*
        if (err==0)
            printf("%s %ld %ld %ld %ld\n", rinfo->id.buf, rinfo->db_seq, rinfo->rev_seq, rinfo->size, rinfo->bp);
*/
        couchstore_free_docinfo(rinfo);
    }
    couchstore_docinfos_by_id(db, ids, 10, 0, _basic_callback, NULL);
    
    couchstore_close_db(db);
}

struct bench_info {
    size_t ndocs;
    char *filename;
    size_t nfiles;

    size_t nthreads;
    size_t pop_batchsize;
    uint8_t pop_commit;

    struct rndinfo keylen;
    struct rndinfo bodylen;
    size_t nbatches;
    size_t nops;
    size_t bench_secs;
    struct rndinfo batch_dist;
    struct rndinfo rbatchsize;
    struct rndinfo wbatchsize;
    struct rndinfo op_dist;
    size_t batchrange;
    uint8_t read_query_byseq;

    // percentage
    size_t write_prob;
    size_t compact_thres;
};

#define MIN(a,b) (((a)<(b))?(a):(b))

int _cmp_docs(const void *a, const void *b)
{
    Doc *aa, *bb;
    aa = (Doc *)a;
    bb = (Doc *)b;

    if (aa->id.size == bb->id.size) return memcmp(aa->id.buf, bb->id.buf, aa->id.size);
    else {
        size_t len = MIN(aa->id.size , bb->id.size);
        int cmp = memcmp(aa->id.buf, bb->id.buf, len);
        if (cmp != 0) return cmp;
        else {
            return (aa->id.size - bb->id.size);
        }
    }
}

static uint8_t metabuf[256];

#define PRINT_TIME(t,str) \
    printf("%d.%03d"str, (int)(t).tv_sec, (int)(t).tv_usec / 1000);

uint64_t get_filesize(char *filename)
{
    struct stat filestat;
    stat(filename, &filestat);
    return filestat.st_size;
}

char * print_filesize_approx(uint64_t size, char *output)
{
    if (size < 1024*1024) {
        sprintf(output, "%.2f KB", (double)size / 1024);
    }else if (size >= 1024*1024 && size < 1024*1024*1024) {
        sprintf(output, "%.2f MB", (double)size / (1024*1024));
    }else {
        sprintf(output, "%.2f GB", (double)size / (1024*1024*1024));    
    }
    return output;
}

void print_filesize(char *filename)
{
    char buf[256];
    uint64_t size = get_filesize(filename);
    
    printf("file size : %lu bytes (%s)\n", (unsigned long)size, print_filesize_approx(size, buf));
}

int empty_callback(Db *db, DocInfo *docinfo, void *ctx)
{
    return 0;
}

uint32_t _idx2crc(size_t idx, uint32_t seed)
{
    uint64_t idx64 = idx;
    return crc32_8(&idx64, sizeof(idx64), seed);
}

size_t _crc2keylen(struct bench_info *binfo, uint32_t crc)
{
    BDR_RNG_VARS_SET(crc);
    size_t r;

    rngz = crc;

    BDR_RNG_NEXTPAIR;
    r = get_random(&binfo->keylen, rngz, rngz2);
    if (r < 8) r = 8;
    if (r > 250) r = 250;

    return r;
}

void _crc2key(uint32_t crc, char *buf, size_t len)
{
    int i, j;
    BDR_RNG_VARS_SET(crc);
    rngz = crc;

    for (i=0;i<len;i+=1){        
        BDR_RNG_NEXT;
        //buf[i] = '!' + (rngz%('~'-'!'));
        //buf[i] = 'a' + (rngz%('z'-'a'));
        buf[i] = rngz & 0xff;
    }
}

void _create_doc(struct bench_info *binfo, size_t idx, Doc **pdoc, DocInfo **pinfo)
{
    BDR_RNG_VARS;
    Doc *doc = *pdoc;
    DocInfo *info = *pinfo;
    int i, r, j;
    uint64_t idx64 = idx;
    uint32_t crc;

    crc = _idx2crc(idx, 0);
    rngz = crc;

    if (!doc) 
        doc = (Doc *)malloc(sizeof(Doc));
    
    doc->id.size = _crc2keylen(binfo, crc);
    doc->id.buf = (char *)malloc(doc->id.size);

    _crc2key(crc, doc->id.buf, doc->id.size);

    BDR_RNG_NEXTPAIR;
    BDR_RNG_NEXTPAIR;
    r = get_random(&binfo->bodylen, rngz, rngz2);
    if (r < 8) r = 8;
    
    doc->data.size = r;
    doc->data.size = (size_t)((doc->data.size+1) / (sizeof(uint64_t)*1)) * (sizeof(uint64_t)*1);
    doc->data.buf = (char *)malloc(doc->data.size);

    if (!info) 
        info = (DocInfo*)malloc(sizeof(DocInfo));
    
    memset(info, 0, sizeof(DocInfo));
    info->id = doc->id;
    info->rev_meta.buf = (char *)metabuf;
    info->rev_meta.size = 4;

    *pdoc = doc;
    *pinfo = info;
}

struct pop_thread_args {
    int n;
    Db **db;
    struct bench_info *binfo;
};

#define SET_DOC_RANGE(ndocs, nfiles, idx, begin, end) \
    begin = (ndocs) * ((idx)+0) / (nfiles); \
    end = (ndocs) * ((idx)+1) / (nfiles);

void * pop_thread(void *voidargs)
{
    int i, k, c, n;
    struct pop_thread_args *args = voidargs;
    struct bench_info *binfo = args->binfo;
    size_t batchsize = args->binfo->pop_batchsize;
    Db *db;
    Doc **docs;
    DocInfo **infos;

    docs = (Doc**)calloc(batchsize, sizeof(Doc*));
    infos = (DocInfo**)calloc(batchsize, sizeof(DocInfo*));

    for (k=args->n; k<binfo->nfiles; k+=binfo->nthreads) {
        printf("#%d ", k);
        fflush(stdout);
        
        db = args->db[k];
        SET_DOC_RANGE(binfo->ndocs, binfo->nfiles, k, c, n);

        while(c < n) {
            for (i=c; (i<c+batchsize && i<n); ++i){
                _create_doc(binfo, i, &docs[i-c], &infos[i-c]);
            }
            couchstore_save_documents(db, docs, infos, i-c, 0x0);
            if (binfo->pop_commit) couchstore_commit(db);

            // free
            for (i=c; (i<c+batchsize && i<n); ++i){
                free(docs[i-c]->id.buf);
                free(docs[i-c]->data.buf);
            }
            c = i;
        }
        if (!binfo->pop_commit) couchstore_commit(db);

    }

    for (i=0;i<batchsize;++i){
        if (docs[i]) free(docs[i]);
        if (infos[i]) free(infos[i]);
    }

    free(docs);
    free(infos);    
    pthread_exit(NULL);
    return NULL;
}

void population(Db **db, struct bench_info *binfo)
{
    int i;
    pthread_t tid[binfo->nthreads];
    void *ret[binfo->nthreads];
    struct pop_thread_args args[binfo->nthreads];


    for (i=0;i<binfo->nthreads;++i){
        args[i].n = i;
        args[i].db = db;
        args[i].binfo = binfo;
        pthread_create(&tid[i], NULL, pop_thread, &args[i]);
    }

    for (i=0;i<binfo->nthreads;++i){
        pthread_join(tid[i], &ret[i]);
    }
    
/*
    for (i=0;i<binfo->nthreads;++i){
        args[i].n = i;
        args[i].db = db;
        args[i].binfo = binfo;
        pop_thread(&args[i]);
    }
*/
    printf("\n");
}

void print_proc_io_stat(char *buf)
{
#ifdef __PRINT_IOSTAT
    printf("\n");
    sprintf(buf, "cat /proc/%d/io", getpid());
    int ret = system(buf);
#endif
}

void do_bench(struct bench_info *binfo)
{
    BDR_RNG_VARS;
    int i, j, ret, r;
    Db *db[binfo->nfiles];
    DbInfo *dbinfo;
    Doc **rq_docs;
    DocInfo **rq_infos;
    char curfile[256], newfile[256], keybuf[256], bodybuf[1024], cmd[256];
    char fsize1[128], fsize2[128];
    struct stopwatch sw, sw_compaction, progress;
    struct rndinfo write_mode_random;
    struct timeval gap;
    //struct stat filestat;
    sized_buf *ids;
    uint64_t *seqs;
    uint32_t crc;
    size_t curfile_no, doc_range_begin, doc_range_end, ndocs_file;
    int write_mode, write_mode_r;
    int batchsize, op_med, op_count_read, op_count_write;
    int compaction_no[binfo->nfiles], total_compaction = 0;
    double rw_factor;
    uint64_t appended_size, previous_filesize[binfo->nfiles], total_dbsize = 0;
    DBGCMD( int rarray[3000]; );

    memleak_start();

    dbinfo = (DbInfo *)malloc(sizeof(DbInfo));

    stopwatch_init(&sw);
    stopwatch_init(&sw_compaction);

    // erase previous db file    
    printf("initialize\n");
    
    sprintf(cmd, "rm %s* -rf 2> errorlog.txt", binfo->filename);
    ret = system(cmd);

    for (i=0;i<binfo->nfiles;++i){
        compaction_no[i] = 0;
        sprintf(curfile, "%s%d.%d", binfo->filename, i, compaction_no[i]);
        couchstore_open_db(curfile, COUCHSTORE_OPEN_FLAG_CREATE, &db[i]);
    }


    // ==== population ====
    printf("\npopulating\n");

    stopwatch_start(&sw);
    population(db, binfo);
    gap = stopwatch_stop(&sw);

    PRINT_TIME(gap, " sec elapsed\n");

    for (i=0;i<binfo->nfiles;++i){
        compaction_no[i] = 0;
        sprintf(curfile, "%s%d.%d", binfo->filename, i, compaction_no[i]);
        previous_filesize[i] = get_filesize(curfile);
        total_dbsize += previous_filesize[i];
    }
    printf("total file size : %u files, %lu bytes (%s)\n", 
        (int)binfo->nfiles, (unsigned long)total_dbsize, print_filesize_approx(total_dbsize, bodybuf));

    print_proc_io_stat(cmd);

    // ==== perform benchmark ====
    printf("\nbenchmark\n");
    appended_size = 0;
    op_count_read = op_count_write = 0;
    write_mode_random.type = RND_UNIFORM;
    write_mode_random.a = 0;
    write_mode_random.b = 65536 * 256;
    
    if (binfo->batch_dist.type == RND_NORMAL) {
        rw_factor = (double)binfo->rbatchsize.a / (double)binfo->wbatchsize.a;
    }else{
        rw_factor = (double)(binfo->rbatchsize.a + binfo->rbatchsize.b) /
            (double)(binfo->wbatchsize.a + binfo->wbatchsize.b);    
    }

    // timer for total elapsed time
    stopwatch_init(&sw);
    // timer for periodic stdout print
    stopwatch_init(&progress);
    
    stopwatch_start(&sw);
    stopwatch_start(&progress);
    
    for (i=0;(i<binfo->nbatches || binfo->nbatches == 0);++i){

        // decide write or read
        BDR_RNG_NEXTPAIR;
        write_mode_r = get_random(&write_mode_random, rngz, rngz2);
        write_mode = ( ((double)binfo->write_prob * 256.0 / 100.0 * rw_factor * 65536) > write_mode_r);

        // randomly set batchsize
        BDR_RNG_NEXTPAIR;
        if (write_mode) {
            batchsize = get_random(&binfo->wbatchsize, rngz, rngz2);
            if (batchsize <= 0) batchsize = 1;
        }else{
            batchsize = get_random(&binfo->rbatchsize, rngz, rngz2);
            if (batchsize <= 0) batchsize = 1;
        }

        // ramdomly set document distribution for batch
        BDR_RNG_NEXTPAIR;
        op_med = get_random(&binfo->batch_dist, rngz, rngz2);
        if (op_med < 0) op_med = 0;
        if (op_med >= binfo->ndocs) op_med = binfo->ndocs - 1;
        
        if (binfo->op_dist.type == RND_NORMAL){
            binfo->op_dist.a = op_med;
            binfo->op_dist.b = binfo->batchrange/4;
        }else {
            binfo->op_dist.a = op_med - binfo->batchrange/2;
            binfo->op_dist.b = op_med + binfo->batchrange/2;
            if (binfo->op_dist.a < 0) binfo->op_dist.a = 0;
            if (binfo->op_dist.b >= binfo->ndocs) binfo->op_dist.b = binfo->ndocs;
        }

        // randomly pick target file
        BDR_RNG_NEXT;
        curfile_no = rngz % binfo->nfiles;
        SET_DOC_RANGE(binfo->ndocs, binfo->nfiles, curfile_no, doc_range_begin, doc_range_end);
        ndocs_file = doc_range_end - doc_range_begin;
        
        if (write_mode) {
            // write (update)
            rq_docs = (Doc **)calloc(batchsize, sizeof(Doc *));
            rq_infos = (DocInfo **)calloc(batchsize, sizeof(DocInfo *));

            for (j=0;j<batchsize;++j){
                BDR_RNG_NEXTPAIR;
                r = get_random(&binfo->op_dist, rngz, rngz2);
                if (r < 0) r = (r+binfo->ndocs) % binfo->ndocs;
                if (r >= binfo->ndocs) r = r % binfo->ndocs;

                r = (r % ndocs_file) + doc_range_begin;

                _create_doc(binfo, r, &rq_docs[j], &rq_infos[j]);
            }

            couchstore_save_documents(db[curfile_no], rq_docs, rq_infos, batchsize, 0x0);            
            couchstore_commit(db[curfile_no]);
            op_count_write += batchsize;

            for (j=0;j<batchsize;++j){
                free(rq_docs[j]->id.buf);
                free(rq_docs[j]->data.buf);
                free(rq_docs[j]);
                free(rq_infos[j]);
            }

            free(rq_docs);
            free(rq_infos);

        }else{        
            // read
            int r_arr[batchsize];
            uint32_t crc_arr[batchsize];
            
            if (binfo->read_query_byseq) {
                seqs = (uint64_t *)malloc(sizeof(uint64_t) * batchsize);
            }else{
                ids = (sized_buf *)malloc(sizeof(sized_buf) * batchsize);
            }

            for (j=0;j<batchsize;++j){
                
                BDR_RNG_NEXTPAIR;
                r = get_random(&binfo->op_dist, rngz, rngz2);
                if (r < 0) r = (r+binfo->ndocs) % binfo->ndocs;;
                if (r >= binfo->ndocs) r = r % binfo->ndocs;

                r = (r % ndocs_file) + doc_range_begin;
                r_arr[j] = r;

                if (binfo->read_query_byseq) {
                    //seqs[j] = infos[r]->db_seq;
                    seqs[j] = 0;
                }else{
                    //ids[j] = docs[r]->id;
                    crc = _idx2crc(r, 0);
                    crc_arr[j] = crc;
                    ids[j].size = _crc2keylen(binfo, crc);
                    ids[j].buf = (char*)malloc(ids[j].size);
                    _crc2key(crc, ids[j].buf, ids[j].size);
                }
            }

            if (binfo->read_query_byseq){
                couchstore_docinfos_by_sequence(db[curfile_no], seqs, batchsize, 0x0, empty_callback, NULL);
                free(seqs);
            }else{
                couchstore_docinfos_by_id(db[curfile_no], ids, batchsize, 0x0, empty_callback, NULL);

                for (j=0;j<batchsize;++j){
                    free(ids[j].buf);
                }                
                free(ids);
            }
            op_count_read += batchsize;
        }

        stopwatch_stop(&progress);
        if (progress.elapsed.tv_sec * 10 + progress.elapsed.tv_usec / 100000 > 0){
            // for every 0.1 sec, print current status
            uint64_t cur_size;
        
            stopwatch_init(&progress);

            couchstore_db_info(db[curfile_no], dbinfo);
            strcpy(curfile, dbinfo->filename);
            cur_size = get_filesize(curfile);
                        
            stopwatch_stop(&sw);
            printf("\r");

            if (binfo->nbatches > 0) {
                printf("%5.1f %% (", i*100.0 / (binfo->nbatches-1));
                gap = sw.elapsed;
                PRINT_TIME(gap, " s , "); 
            }else if (binfo->bench_secs > 0){
                printf("(");
                gap = sw.elapsed;
                PRINT_TIME(gap, " s / ");
                printf("%d s , ", (int)binfo->bench_secs); 
            }else {
                printf("%5.1f %% (", (op_count_read+op_count_write)*100.0 / (binfo->nops-1));
                gap = sw.elapsed;
                PRINT_TIME(gap, " s , ");                 
            }
            printf("%.2f ops)", 
                (double)(op_count_read + op_count_write) / (gap.tv_sec + (double)gap.tv_usec / 1000000.0));
            print_filesize_approx(cur_size, fsize1);
            print_filesize_approx(dbinfo->space_used, fsize2);
            printf(" (%s / %s)", fsize1, fsize2);
            
            fflush(stdout);
            stopwatch_start(&sw);

            // valid:invalid size check
            if ( (cur_size > dbinfo->space_used) && (binfo->compact_thres > 0) &&
                ((cur_size - dbinfo->space_used) > 
                ((double)binfo->compact_thres/100.0)*(double)cur_size) ) {
                
                // compaction                
                compaction_no[curfile_no]++;
                sprintf(newfile, "%s%d.%d", binfo->filename, (int)curfile_no, compaction_no[curfile_no]);
                printf(" [ compaction #%d %s >> %s ]", compaction_no[curfile_no], curfile, newfile);
                fflush(stdout);

                appended_size += (get_filesize(curfile) - previous_filesize[curfile_no]);

                stopwatch_start(&sw_compaction);
                couchstore_compact_db(db[curfile_no], newfile);
                couchstore_close_db(db[curfile_no]);
                stopwatch_stop(&sw_compaction);

                previous_filesize[curfile_no] = get_filesize(newfile);

                // erase previous db file    
                sprintf(cmd, "rm %s -rf 2> errorlog.txt", curfile);
                ret = system(cmd);

                // open new db file
                strcpy(curfile, newfile);
                couchstore_open_db(curfile, COUCHSTORE_OPEN_FLAG_CREATE, &db[curfile_no]);
            }

            if (sw.elapsed.tv_sec >= binfo->bench_secs && binfo->bench_secs > 0) break;
        }      

        if ((op_count_read + op_count_write) >= binfo->nops && binfo->nops > 0) break;
        
        stopwatch_start(&progress);
    }
    printf("\n");

    for (i=0;i<binfo->nfiles;++i){
        couchstore_commit(db[i]);
        couchstore_close_db(db[i]);
    }

    stopwatch_stop(&sw);
    gap = sw.elapsed;
    PRINT_TIME(gap, " sec elapsed\n");

    printf("%d read, %d write operations\n", op_count_read, op_count_write);

    printf("total %d operations (%.2f ops)\n", 
        op_count_read + op_count_write, 
        (double)(op_count_read + op_count_write) / (gap.tv_sec + (double)gap.tv_usec / 1000000.0));

    total_dbsize = 0;
    for (i=0;i<binfo->nfiles;++i){
        total_compaction += compaction_no[i];
        sprintf(curfile, "%s%d.%d", binfo->filename, i, compaction_no[i]);
        total_dbsize += get_filesize(curfile);
        appended_size += (get_filesize(curfile) - previous_filesize[i]);
    }
    printf("total file size : %u files, %lu bytes (%s)\n", 
        (int)binfo->nfiles, (unsigned long)total_dbsize, print_filesize_approx(total_dbsize, bodybuf));
    
    printf("total %lu bytes (%s) written\n", appended_size, print_filesize_approx(appended_size, bodybuf));

    printf("compaction : occurred %d times, ", total_compaction);
    PRINT_TIME(sw_compaction.elapsed, " sec elapsed\n");

    print_proc_io_stat(cmd);
    printf("\n");

    //fdb_shutdown();
    free(dbinfo);
    
    memleak_end();    
}

void _print_benchinfo(struct bench_info *binfo)
{
    printf(" === benchmark configuration ===\n");
    printf("filename: %s#\n", binfo->filename);
    printf("the number of documents (i.e. working set size): %d\n", (int)binfo->ndocs);
    printf("the number of files: %d\n", (int)binfo->nfiles);
    //printf("the number of population workers: %d\n", (int)binfo->nthreads);
    
    printf("key length distribution: %s(%d,%d)\n", 
        (binfo->keylen.type == RND_NORMAL)?"Norm":"Uniform", (int)binfo->keylen.a, (int)binfo->keylen.b);
    printf("body length distribution: %s(%d,%d)\n", 
        (binfo->bodylen.type == RND_NORMAL)?"Norm":"Uniform", (int)binfo->bodylen.a, (int)binfo->bodylen.b);

    if (binfo->nbatches > 0) {
        printf("the number of operation batches for benchmark: %lu\n", (unsigned long)binfo->nbatches);
    }
    if (binfo->nops > 0){
        printf("the number of operations for benchmark: %lu\n", (unsigned long)binfo->nops);
    }
    if (binfo->bench_secs > 0){
        printf("benchmark duration: %lu seconds\n", (unsigned long)binfo->bench_secs);
    }

    printf("read batch size distribution: %s(%d,%d)\n",
        (binfo->rbatchsize.type == RND_NORMAL)?"Norm":"Uniform", (int)binfo->rbatchsize.a, (int)binfo->rbatchsize.b);
    printf("read query: by %s\n", (binfo->read_query_byseq)?"sequence":"id");
    printf("write batch size distribution: %s(%d,%d)\n",
        (binfo->wbatchsize.type == RND_NORMAL)?"Norm":"Uniform", (int)binfo->wbatchsize.a, (int)binfo->wbatchsize.b);
    printf("operations in a batch: %s distribution\n",     (binfo->op_dist.type == RND_NORMAL)?"Norm":"Uniform");
    printf("the range of operations in a batch: -%d ~ +%d (total %d)\n", 
        (int)binfo->batchrange/2 , (int)binfo->batchrange/2, (int)binfo->batchrange);
    printf("the proportion of write operations: %d %%\n", (int)binfo->write_prob);
    printf("compaction threshold: %d %%\n", (int)binfo->compact_thres);
    printf("\n");
}

struct bench_info get_benchinfo()
{
    static dictionary *cfg;    
    cfg = iniparser_new("./bench_config.ini");
    
    struct bench_info binfo;
    char *str;
    char *filename = (char*)malloc(256);
    size_t ncores = sysconf(_SC_NPROCESSORS_ONLN);

    binfo.ndocs = iniparser_getint(cfg, "document:ndocs", 10000);
    binfo.filename = filename;

    str = iniparser_getstring(cfg, "db_file:filename", "./dummy");
    strcpy(binfo.filename, str);
    binfo.nfiles = iniparser_getint(cfg, "db_file:nfiles", 1);

    binfo.nthreads = iniparser_getint(cfg, "population:nthreads", ncores*2);
    if (binfo.nthreads < 1) binfo.nthreads = ncores*2;
    if (binfo.nthreads > binfo.nfiles) binfo.nthreads = binfo.nfiles;
    
    binfo.pop_batchsize = iniparser_getint(cfg, "population:batchsize", 4096);

    str = iniparser_getstring(cfg, "population:periodic_commit", "yes");
    if (str[0] == 'n' || binfo.nthreads == 1) binfo.pop_commit = 0;
    else binfo.pop_commit = 1;
    
    str = iniparser_getstring(cfg, "key_length:distribution", "normal");
    if (str[0] == 'n') {
        binfo.keylen.type = RND_NORMAL;
        binfo.keylen.a = iniparser_getint(cfg, "key_length:median", 64);
        binfo.keylen.b = iniparser_getint(cfg, "key_length:standard_deviation", 8);
    }else{
        binfo.keylen.type = RND_UNIFORM;
        binfo.keylen.a = iniparser_getint(cfg, "key_length:lower_bound", 32);
        binfo.keylen.b = iniparser_getint(cfg, "key_length:upper_bound", 96);        
    }

    str = iniparser_getstring(cfg, "body_length:distribution", "normal");
    if (str[0] == 'n') {
        binfo.bodylen.type = RND_NORMAL;
        binfo.bodylen.a = iniparser_getint(cfg, "body_length:median", 512);
        binfo.bodylen.b = iniparser_getint(cfg, "body_length:standard_deviation", 32);
    }else{
        binfo.bodylen.type = RND_UNIFORM;
        binfo.bodylen.a = iniparser_getint(cfg, "body_length:lower_bound", 448);
        binfo.bodylen.b = iniparser_getint(cfg, "body_length:upper_bound", 576);
    }

    binfo.nbatches = iniparser_getint(cfg, "operation:nbatches", 0);
    binfo.nops = iniparser_getint(cfg, "operation:nops", 0);
    binfo.bench_secs = iniparser_getint(cfg, "operation:duration", 0);
    if (binfo.nbatches == 0 && binfo.nops == 0 && binfo.bench_secs == 0) {
        binfo.bench_secs = 60;
    }
    
    str = iniparser_getstring(cfg, "operation:batchsize_distribution", "normal");
    if (str[0] == 'n') {
        binfo.rbatchsize.type = RND_NORMAL;
        binfo.rbatchsize.a = iniparser_getint(cfg, "operation:read_batchsize_median", 3);
        binfo.rbatchsize.b = iniparser_getint(cfg, "operation:read_batchsize_standard_deviation", 1);
        binfo.wbatchsize.type = RND_NORMAL;
        binfo.wbatchsize.a = iniparser_getint(cfg, "operation:write_batchsize_median", 1000);
        binfo.wbatchsize.b = iniparser_getint(cfg, "operation:write_batchsize_standard_deviation", 125);
    }else{
        binfo.rbatchsize.type = RND_UNIFORM;
        binfo.rbatchsize.a = iniparser_getint(cfg, "operation:read_batchsize_lower_bound", 1);
        binfo.rbatchsize.b = iniparser_getint(cfg, "operation:read_batchsize_upper_bound", 5);
        binfo.wbatchsize.type = RND_UNIFORM;
        binfo.wbatchsize.a = iniparser_getint(cfg, "operation:write_batchsize_lower_bound", 750);
        binfo.wbatchsize.b = iniparser_getint(cfg, "operation:write_batchsize_upper_bound", 1250);
    }

    str = iniparser_getstring(cfg, "operation:read_query", "key");
    if (str[0] == 'k' || str[0] == 'i') {
        binfo.read_query_byseq = 0;
    }else {
        // by_seq is not supported now..
        //binfo.read_query_byseq = 1;
        binfo.read_query_byseq = 0;
    }
        
    binfo.batch_dist.type = RND_UNIFORM;
    binfo.batch_dist.a = 0;
    binfo.batch_dist.b = binfo.ndocs;

    str = iniparser_getstring(cfg, "operation:operation_distribution", "normal");
    if (str[0] == 'n') {
        binfo.op_dist.type = RND_NORMAL;
    }else{
        binfo.op_dist.type = RND_UNIFORM;
    }
    binfo.batchrange = iniparser_getint(cfg, "operation:batch_range", binfo.ndocs);

    binfo.write_prob = iniparser_getint(cfg, "operation:write_ratio_percent", 20);

    binfo.compact_thres = iniparser_getint(cfg, "compaction:threshold", 30);

    iniparser_free(cfg);

    return binfo;
}

int main(){
    srand(0x12341234);

    struct bench_info binfo;

    binfo = get_benchinfo();

    _print_benchinfo(&binfo);
    do_bench(&binfo);
    
    return 0;
}

