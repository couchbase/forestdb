#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <assert.h>

#include "couch_common.h"
#include "couch_db.h"
#include "adv_random.h"
#include "stopwatch.h"
#include "iniparser.h"

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
    char *filename2;
    struct rndinfo keylen;
    struct rndinfo bodylen;
    size_t nops;
    size_t bench_secs;
    struct rndinfo batch_dist;
    struct rndinfo rbatchsize;
    struct rndinfo wbatchsize;
    struct rndinfo op_dist;
    size_t batchrange;

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

size_t _create_docs(Doc *docs[], DocInfo *infos[], struct bench_info *binfo)
{
    BDR_RNG_VARS;
    int i, j, r;
    int keylen;
    size_t totalsize = 0;

    for (i=0;i<binfo->ndocs;++i) {
        docs[i] = (Doc *)malloc(sizeof(Doc));

        BDR_RNG_NEXTPAIR;
        r = get_random(&binfo->keylen, rngz, rngz2);
        if (r < 8) r = 8;
        if (r > 200) r = 200;
        
        docs[i]->id.size = r;
        docs[i]->id.buf = (char *)malloc(docs[i]->id.size);

        for (j=0;j<docs[i]->id.size;++j){
            BDR_RNG_NEXTPAIR;
            docs[i]->id.buf[j] = '!' + (rngz%('~'-'!'));
        }
        /*
        docs[i]->id.size = 8;
        docs[i]->id.buf = (char *)malloc(docs[i]->id.size);
        sprintf(docs[i]->id.buf, "%08d", i);
*/
        BDR_RNG_NEXTPAIR;
        r = get_random(&binfo->bodylen, rngz, rngz2);
        if (r < 8) r = 8;
        docs[i]->data.size = r;
        docs[i]->data.size = (size_t)((docs[i]->data.size+1) / (sizeof(uint64_t)*1)) * (sizeof(uint64_t)*1);
        docs[i]->data.buf = (char *)malloc(docs[i]->data.size);

        for (j=0;j<docs[i]->data.size;j+=sizeof(uint64_t)) {
            BDR_RNG_NEXTPAIR;
            memcpy(docs[i]->data.buf + j, &rngz, sizeof(uint64_t));
            //docs[i]->data.buf[j] = 'a' + rngz%('z'-'a');
        }

        infos[i] = (DocInfo*)malloc(sizeof(DocInfo));
        memset(infos[i], 0, sizeof(DocInfo));
        infos[i]->id = docs[i]->id;
        infos[i]->rev_meta.buf = (char *)metabuf;
        infos[i]->rev_meta.size = 4;

        totalsize += (docs[i]->id.size + docs[i]->data.size + infos[i]->rev_meta.size);
    }

    return totalsize;
}

#define PRINT_TIME(t,str) \
    printf("%d.%03d"str, (int)(t).tv_sec, (int)(t).tv_usec / 1000);

void print_filesize(char *filename)
{
    int r;
    struct stat filestat;
    uint64_t size; 

    stat(filename, &filestat);
    size = filestat.st_size;
    
    printf("file size : %lu bytes ", (unsigned long)filestat.st_size);
    if (size >= 1024 && size < 1024*1024) {
        printf("(%.2f KB)\n", (double)size / 1024);
    }else if (size >= 1024*1024 && size < 1024*1024*1024) {
        printf("(%.2f MB)\n", (double)size / (1024*1024));
    }else {
        printf("(%.2f GB)\n", (double)size / (1024*1024*1024));    
    }
}

int empty_callback(Db *db, DocInfo *docinfo, void *ctx)
{
    return 0;
}

void do_bench(struct bench_info *binfo)
{
    BDR_RNG_VARS;
    int i, j, ret, r;
    Db *db;
    DbInfo *dbinfo;
    Doc **docs, **rq_docs;
    DocInfo **infos, **rq_infos;
    char curfile[256], newfile[256], keybuf[256], bodybuf[1024], cmd[256];
    struct stopwatch sw, sw_compaction, progress;
    struct rndinfo write_mode_random;
    struct timeval gap;
    struct stat filestat;
    sized_buf *ids;
    int prog_dot, write_mode, write_mode_r;
    int batchsize, op_med, op_count_read, op_count_write;
    int compaction_no = 0;
    double rw_factor;
    uint64_t workingset_size, appended_size;

    dbinfo = (DbInfo *)malloc(sizeof(DbInfo));

    stopwatch_init(&sw);
    stopwatch_init(&sw_compaction);

    printf("create %d docs\n", (int)binfo->ndocs);
    stopwatch_start(&sw);
    docs = (Doc **)malloc(sizeof(Doc *) * binfo->ndocs);
    infos = (DocInfo **)malloc(sizeof(DocInfo *) * binfo->ndocs);
    workingset_size = _create_docs(docs, infos, binfo);
    gap = stopwatch_stop(&sw);
    PRINT_TIME(gap, " sec elapsed\n");

    //qsort(docs, binfo->ndocs, sizeof(Doc), _cmp_docs);

    // erase previous db file    
    sprintf(cmd, "rm %s* -rf 2> errorlog.txt", binfo->filename);
    ret = system(cmd);

    sprintf(curfile, "%s%d", binfo->filename, compaction_no);
    couchstore_open_db(curfile, COUCHSTORE_OPEN_FLAG_CREATE, &db);

    printf("\npopulating\n");
    stopwatch_start(&sw);
    couchstore_save_documents(db, docs, infos, binfo->ndocs, 0x0);
    couchstore_commit(db);
    gap = stopwatch_stop(&sw);
    PRINT_TIME(gap, " sec elapsed\n");
    print_filesize(curfile);

    printf("\nbenchmark\n");
    op_count_read = op_count_write = prog_dot = 0;
    write_mode_random.type = RND_UNIFORM;
    write_mode_random.a = 0;
    write_mode_random.b = 65536 * 256;
    
    if (binfo->batch_dist.type == RND_NORMAL) {
        rw_factor = (double)binfo->rbatchsize.a / (double)binfo->wbatchsize.a;
    }else{
        rw_factor = (double)(binfo->rbatchsize.a + binfo->rbatchsize.b) /
            (double)(binfo->wbatchsize.a + binfo->wbatchsize.b);    
    }

    stopwatch_init(&sw);
    stopwatch_init(&progress);
    
    stopwatch_start(&sw);
    stopwatch_start(&progress);
    
    for (i=0;(i<binfo->nops || binfo->nops == 0);++i){        
        BDR_RNG_NEXTPAIR;
        write_mode_r = get_random(&write_mode_random, rngz, rngz2);
        write_mode = ( ((double)binfo->write_prob * 256.0 / 100.0 * rw_factor * 65536) > write_mode_r);
    
        BDR_RNG_NEXTPAIR;
        if (write_mode) {
            batchsize = get_random(&binfo->wbatchsize, rngz, rngz2);
            if (batchsize <= 0) batchsize = 1;
        }else{
            batchsize = get_random(&binfo->rbatchsize, rngz, rngz2);
            if (batchsize <= 0) batchsize = 1;
        }

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

        //printf("batchsize %d median %d\n", batchsize, op_med);
        if (i==149516) {
            int asdf = 0;
        }
        
        if (write_mode) {
            // write (update)
            rq_docs = (Doc **)malloc(sizeof(Doc *) * batchsize);
            rq_infos = (DocInfo **)malloc(sizeof(DocInfo *) * batchsize);

            for (j=0;j<batchsize;++j){
                BDR_RNG_NEXTPAIR;
                r = get_random(&binfo->op_dist, rngz, rngz2);
                if (r < 0) r = (r+binfo->ndocs) % binfo->ndocs;
                if (r >= binfo->ndocs) r = r % binfo->ndocs;

                rq_docs[j] = docs[j];
                rq_infos[j] = infos[j];

                appended_size += (rq_docs[j]->id.size + rq_docs[j]->data.size + rq_infos[j]->rev_meta.size);
            }

            couchstore_save_documents(db, rq_docs, rq_infos, batchsize, 0x0);
            couchstore_commit(db);
            op_count_write += batchsize;

            free(rq_docs);
            free(rq_infos);

        }else{        
            // read
            ids = (sized_buf *)malloc(sizeof(sized_buf) * batchsize);

            for (j=0;j<batchsize;++j){
                BDR_RNG_NEXTPAIR;
                r = get_random(&binfo->op_dist, rngz, rngz2);
                if (r < 0) r = (r+binfo->ndocs) % binfo->ndocs;;
                if (r >= binfo->ndocs) r = r % binfo->ndocs;

                ids[j] = docs[r]->id;
            }

            couchstore_docinfos_by_id(db, ids, batchsize, 0x0, empty_callback, NULL);
            op_count_read += batchsize;
            free(ids);
        }

        stopwatch_stop(&progress);
        if (progress.elapsed.tv_sec * 10 + progress.elapsed.tv_usec / 100000 > 0){
        
            stopwatch_init(&progress);

            stat(curfile, &filestat);
            couchstore_db_info(db, dbinfo);
                        
            stopwatch_stop(&sw);
            printf("\r");
            //for (j=0;j<prog_dot;++j) printf("=");
            if (binfo->nops > 0) {
                printf("%5.1f %% (", i*100.0 / (binfo->nops-1));
                gap = sw.elapsed;
                PRINT_TIME(gap, " s , "); 
            }else{
                printf("(");
                gap = sw.elapsed;
                PRINT_TIME(gap, " s / ");
                printf("%d s , ", (int)binfo->bench_secs); 
            }
            printf("%.2f ops)", 
                (double)(op_count_read + op_count_write) / (gap.tv_sec + (double)gap.tv_usec / 1000000.0));
            printf(" (%lld / %lld)", (long long int)filestat.st_size, (long long int)dbinfo->space_used);
            prog_dot++;
            fflush(stdout);
            stopwatch_start(&sw);

            if ( (filestat.st_size > dbinfo->space_used) && 
                ((filestat.st_size - dbinfo->space_used) > 
                ((double)binfo->compact_thres/100.0)*(double)filestat.st_size) ) {
                // compaction
                printf("\r<compaction>");
                fflush(stdout);
                sprintf(newfile, "%s%d", binfo->filename, ++compaction_no);

                stopwatch_start(&sw_compaction);
                couchstore_compact_db(db, newfile);
                couchstore_close_db(db);
                stopwatch_stop(&sw_compaction);

                // erase previous db file    
                sprintf(cmd, "rm %s -rf 2> errorlog.txt", curfile);
                ret = system(cmd);

                strcpy(curfile, newfile);
                couchstore_open_db(curfile, COUCHSTORE_OPEN_FLAG_CREATE, &db);
                stat(curfile, &filestat);
            }

            if (sw.elapsed.tv_sec >= binfo->bench_secs && binfo->bench_secs > 0) break;
        }      
        stopwatch_start(&progress);
    }
    printf("\n");
    stopwatch_stop(&sw);
    gap = sw.elapsed;
    PRINT_TIME(gap, " sec elapsed\n");
    printf("%d read, %d write operations\n", op_count_read, op_count_write);
    printf("total %d operations (%.2f ops)\n", 
        op_count_read + op_count_write, 
        (double)(op_count_read + op_count_write) / (gap.tv_sec + (double)gap.tv_usec / 1000000.0));
    print_filesize(curfile);

    printf("compaction : occurred %d times, ", compaction_no);
    PRINT_TIME(sw_compaction.elapsed, " sec elapsed\n");

    printf("\n");
}

static dictionary *cfg;

void _print_benchinfo(struct bench_info *binfo)
{
    printf(" === benchmark configuration ===\n");
    printf("filename: %s#\n", binfo->filename);
    printf("the number of documents (i.e. working set size): %d\n", (int)binfo->ndocs);
    printf("key length distribution: %s(%d,%d)\n", 
        (binfo->keylen.type == RND_NORMAL)?"Norm":"Uniform", (int)binfo->keylen.a, (int)binfo->keylen.b);
    printf("body length distribution: %s(%d,%d)\n", 
        (binfo->bodylen.type == RND_NORMAL)?"Norm":"Uniform", (int)binfo->bodylen.a, (int)binfo->bodylen.b);

	if (binfo->nops > 0) {
        printf("the number of operation batches: %d\n", (int)binfo->nops);
    }else{
        printf("benchmark duration: %d seconds\n", (int)binfo->bench_secs);
    }

    printf("read batch size distribution: %s(%d,%d)\n",
        (binfo->rbatchsize.type == RND_NORMAL)?"Norm":"Uniform", (int)binfo->rbatchsize.a, (int)binfo->rbatchsize.b);
    printf("write batch size distribution: %s(%d,%d)\n",
        (binfo->wbatchsize.type == RND_NORMAL)?"Norm":"Uniform", (int)binfo->wbatchsize.a, (int)binfo->wbatchsize.b);
    printf("operations in a batch: %s distribution\n",     (binfo->op_dist.type == RND_NORMAL)?"Norm":"Uniform");
    printf("the range of operations in a batch: -%d ~ +%d (total %d)\n", 
        (int)binfo->batchrange/2 , (int)binfo->batchrange/2, (int)binfo->batchrange);
    printf("the proportion of write operations: %d %%\n", (int)binfo->write_prob);
    printf("compaction threshold: %d %%\n", (int)binfo->compact_thres);
    printf("\n");
}

int main(){
    srand(0x12341234);
    //_basic_test();
    //_rand_gen_test();

    cfg = iniparser_new("./bench_config.ini");
    
    char *str;
    char filename1[256];
    char filename2[256];
    struct bench_info binfo;
    int range_percent;

    binfo.ndocs = iniparser_getint(cfg, "document:ndocs", 10000);
    binfo.filename = filename1;
    binfo.filename2 = filename2;

    str = iniparser_getstring(cfg, "db_file:filename", "./dummy");
    strcpy(binfo.filename, str);
    /*
    str = iniparser_getstring(cfg, "db_file:filename2", "./dummy2");
    strcpy(binfo.filename2, str);
    */
    
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

    binfo.nops = iniparser_getint(cfg, "operation:nbatches", 0);
    binfo.bench_secs = iniparser_getint(cfg, "operation:duration", 0);
    
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
        
    binfo.batch_dist.type = RND_UNIFORM;
    binfo.batch_dist.a = 0;
    binfo.batch_dist.b = binfo.ndocs;

    str = iniparser_getstring(cfg, "operation:operation_distribution", "normal");
    if (str[0] == 'n') {
        binfo.op_dist.type = RND_NORMAL;
    }else{
        binfo.op_dist.type = RND_UNIFORM;
    }
    //binfo.op_dist.type = RND_UNIFORM;
    binfo.batchrange = iniparser_getint(cfg, "operation:batch_range", 1000);

    binfo.write_prob = iniparser_getint(cfg, "operation:write_ratio_percent", 20);

    binfo.compact_thres = iniparser_getint(cfg, "compaction:threshold", 70);

    _print_benchinfo(&binfo);
    do_bench(&binfo);
    
    iniparser_free(cfg);
    
    return 0;
}

