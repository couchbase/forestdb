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
	printf("%s %ld %ld %ld %ld\n", docinfo->id.buf, docinfo->db_seq, docinfo->rev_seq, docinfo->size, docinfo->bp);
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
		if (err==0)
			printf("%s %ld %ld %ld %ld\n", rinfo->id.buf, rinfo->db_seq, rinfo->rev_seq, rinfo->size, rinfo->bp);

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
	struct rndinfo batchsize;
	struct rndinfo batch_dist;
	struct rndinfo op_dist;
	size_t batchrange;

	// percentage
	size_t write_prob;
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

void _create_docs(Doc *docs[], DocInfo *infos[], struct bench_info *binfo)
{
	BDR_RNG_VARS;
	int i, j, r;
	int keylen;

	for (i=0;i<binfo->ndocs;++i) {
		docs[i] = (Doc *)malloc(sizeof(Doc));

		BDR_RNG_NEXTPAIR;
		r = get_random(&binfo->keylen, rngz, rngz2);
		if (r < 8) r = 8;
		docs[i]->id.size = r;
		docs[i]->id.buf = (char *)malloc(docs[i]->id.size);

		for (j=0;j<docs[i]->id.size;++j){
			BDR_RNG_NEXTPAIR;
			docs[i]->id.buf[j] = '!' + (rngz%('~'-'!'));
		}

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
		infos[i]->rev_meta.buf = metabuf;
		infos[i]->rev_meta.size = 4;
	
	}
}

#define PRINT_TIME(t) \
	printf("%d.%06d sec elapsed\n", (int)(t).tv_sec, (int)(t).tv_usec);

void print_filesize(char *filename)
{
	int r;
	struct stat filestat;
	uint64_t size; 

	stat(filename, &filestat);
	size = filestat.st_size;
	
	printf("file size : %ld bytes ", filestat.st_size);
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
	Doc **docs, **rq_docs;
	DocInfo **infos, **rq_infos;
	char keybuf[256], bodybuf[1024], cmd[256];
	struct stopwatch sw;
	struct timeval gap;
	sized_buf *ids;
	int prog_dot;
	int batchsize, op_med, op_count_read, op_count_write;

	stopwatch_init(&sw);

	printf("create %d docs\n", (int)binfo->ndocs);
	stopwatch_start(&sw);
	docs = (Doc **)malloc(sizeof(Doc *) * binfo->ndocs);
	infos = (DocInfo **)malloc(sizeof(DocInfo *) * binfo->ndocs);
	_create_docs(docs, infos, binfo);
	gap = stopwatch_stop(&sw);
	PRINT_TIME(gap);

	//qsort(docs, binfo->ndocs, sizeof(Doc), _cmp_docs);

	sprintf(cmd, "rm ./%s -rf", binfo->filename);
	ret = system(cmd);
	sprintf(cmd, "rm ./%s -rf", binfo->filename2);
	ret = system(cmd);

	couchstore_open_db(binfo->filename, COUCHSTORE_OPEN_FLAG_CREATE, &db);

	printf("\npopulation\n");
	stopwatch_start(&sw);
	couchstore_save_documents(db, docs, infos, binfo->ndocs, 0x0);
	couchstore_commit(db);
	gap = stopwatch_stop(&sw);
	PRINT_TIME(gap);
	print_filesize(binfo->filename);

	printf("\nbenchmark\n");
	op_count_read = op_count_write = prog_dot = 0;
	stopwatch_start(&sw);
	for (i=0;i<binfo->nops;++i){		
		BDR_RNG_NEXTPAIR;
		batchsize = get_random(&binfo->batchsize, rngz, rngz2);
		if (batchsize <= 0) batchsize = 1;

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
		BDR_RNG_NEXTPAIR;
		if ((rngz%100) < binfo->write_prob) {
			// write (update)
			rq_docs = (Doc **)malloc(sizeof(Doc *) * batchsize);
			rq_infos = (DocInfo **)malloc(sizeof(DocInfo *) * batchsize);

			for (j=0;j<batchsize;++j){
				BDR_RNG_NEXTPAIR;
				r = get_random(&binfo->op_dist, rngz, rngz2);
				if (r < 0) r = (r+binfo->ndocs) % binfo->ndocs;;
				if (r >= binfo->ndocs) r = r % binfo->ndocs;

				rq_docs[j] = docs[j];
				rq_infos[j] = infos[j];
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

		if (prog_dot < (i*53)/(binfo->nops-1)){
			printf("\r");
			for (j=0;j<prog_dot;++j) printf("=");
			printf("> %.1f %%", i*100.0 / (binfo->nops-1));
			prog_dot++;
			fflush(stdout);
		}		
	}
	printf("\n");
	gap = stopwatch_stop(&sw);
	PRINT_TIME(gap);
	printf("%d read, %d write operations\n", op_count_read, op_count_write);
	printf("total %d operations (%.2f ops)\n", 
		op_count_read + op_count_write, 
		(double)(op_count_read + op_count_write) / (gap.tv_sec + (double)gap.tv_usec / 1000000.0));
	print_filesize(binfo->filename);

	printf("\ncompaction\n");
	stopwatch_start(&sw);
	couchstore_compact_db(db, binfo->filename2);

	printf("\nclose\n");
	couchstore_close_db(db);
	gap = stopwatch_stop(&sw);
	PRINT_TIME(gap);

	print_filesize(binfo->filename2);

	printf("\n");
}

static dictionary *cfg;

void _print_benchinfo(struct bench_info *binfo)
{
	printf(" === benchmark configuration ===\n");
	printf("filename (before compaction): %s\n", binfo->filename);
	printf("filename (after compaction): %s\n", binfo->filename2);
	printf("the number of documents (i.e. working set size): %d\n", (int)binfo->ndocs);
	printf("key length distribution: %s(%d,%d)\n", 
		(binfo->keylen.type == RND_NORMAL)?"Norm":"Uniform", (int)binfo->keylen.a, (int)binfo->keylen.b);
	printf("body length distribution: %s(%d,%d)\n", 
		(binfo->bodylen.type == RND_NORMAL)?"Norm":"Uniform", (int)binfo->bodylen.a, (int)binfo->bodylen.b);
	printf("the number of operation batches: %d\n", (int)binfo->nops);
	printf("batch size distribution: %s(%d,%d)\n",
		(binfo->batchsize.type == RND_NORMAL)?"Norm":"Uniform", (int)binfo->batchsize.a, (int)binfo->batchsize.b);
	printf("operations in a batch: %s distribution\n", 	(binfo->op_dist.type == RND_NORMAL)?"Norm":"Uniform");
	printf("the range of operations in a batch: %d\n", (int)binfo->batchrange);
	printf("the proportion of write operations: %d %%\n", (int)binfo->write_prob);
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

	str = iniparser_getstring(cfg, "db_file:filename1", "./dummy");
	strcpy(binfo.filename, str);
	str = iniparser_getstring(cfg, "db_file:filename2", "./dummy2");
	strcpy(binfo.filename2, str);
	
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

	binfo.nops = iniparser_getint(cfg, "operation:nbatches", 1000);
	str = iniparser_getstring(cfg, "operation:batchsize_distribution", "normal");
	if (str[0] == 'n') {
		binfo.batchsize.type = RND_NORMAL;
		binfo.batchsize.a = iniparser_getint(cfg, "operation:batchsize_median", 1000);
		binfo.batchsize.b = iniparser_getint(cfg, "operation:batchsize_standard_deviation", 125);
	}else{
		binfo.batchsize.type = RND_UNIFORM;
		binfo.batchsize.a = iniparser_getint(cfg, "operation:batchsize_lower_bound", 750);
		binfo.batchsize.b = iniparser_getint(cfg, "operation:batchsize_upper_bound", 1250);
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
	range_percent = iniparser_getint(cfg, "operation:batch_range_percent", 25);
	binfo.batchrange = (size_t)(binfo.ndocs / (100.0 / (double)range_percent));

	binfo.write_prob = iniparser_getint(cfg, "operation:write_ratio_percent", 20);

	_print_benchinfo(&binfo);
	do_bench(&binfo);
	
	iniparser_free(cfg);
	
	return 0;
}

