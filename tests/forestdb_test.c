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

void _set_doc(fdb_doc *doc, char *key, char *meta, char *body)
{
	doc->keylen = strlen(key);
	doc->metalen = (meta)?strlen(meta):0;
	doc->bodylen = (body)?strlen(body):0;
	doc->key = key;
	doc->meta = meta;
	doc->body = body;
}

void basic_test()
{
	TEST_INIT();

	fdb_handle db;
	fdb_config config;
	fdb_doc doc, *rdoc;
	fdb_status status;
	
	int i, n=10, r;
	char keybuf[256], metabuf[256], bodybuf[256], temp[256];
	
	config.chunksize = sizeof(uint64_t);
	config.offsetsize = sizeof(uint64_t);
	config.buffercache_size = 1 * 1024 * 1024;
	config.wal_threshold = 1024;
	config.flag = 0;

	r = system("rm -rf ./dummy");
	r = system("rm -rf ./dummy2");
	
	fdb_open(&db, "./dummy", config);
	fdb_close(&db);
	
	TEST_TIME();

	fdb_open(&db, "./dummy", config);

	// insert documents
	for (i=0;i<n;++i){
		sprintf(keybuf, "key%d", i);
		sprintf(metabuf, "meta%d", i);
		sprintf(bodybuf, "body%d", i);
		
		_set_doc(&doc, keybuf, metabuf, bodybuf);
		fdb_set(&db, &doc);
	}

	// remove document
	sprintf(keybuf, "key%d", 5);
	_set_doc(&doc, keybuf, NULL, NULL);
	fdb_set(&db, &doc);

	fdb_close(&db);

	TEST_TIME();

	fdb_open(&db, "./dummy", config);

	// update existing documents
	for (i=0;i<2;++i){
		sprintf(keybuf, "key%d", i);
		sprintf(metabuf, "meta2%d", i);
		sprintf(bodybuf, "body2%d", i);
		_set_doc(&doc, keybuf, metabuf, bodybuf);
		fdb_set(&db, &doc);
	}

	// retrieve documents
	for (i=0;i<n;++i){
		sprintf(keybuf, "key%d", i);

		fdb_doc_create(&rdoc, keybuf, strlen(keybuf), NULL, 0, NULL, 0);
		status = fdb_get(&db, rdoc);

		if (i<2) {
			sprintf(temp, "meta2%d", i);
			TEST_CHK(!memcmp(rdoc->meta, temp, rdoc->metalen));
			sprintf(temp, "body2%d", i);
			TEST_CHK(!memcmp(rdoc->body, temp, rdoc->bodylen));
		}else if (i!=5) {
			sprintf(temp, "meta%d", i);
			TEST_CHK(!memcmp(rdoc->meta, temp, rdoc->metalen));
			sprintf(temp, "body%d", i);
			TEST_CHK(!memcmp(rdoc->body, temp, rdoc->bodylen));		
		}else {
			TEST_CHK(status == FDB_RESULT_FAIL);
		}

		fdb_doc_free(rdoc);
	}

	fdb_compact(&db, "./dummy2");
	
	fdb_close(&db);
	
	TEST_TIME();

	TEST_RESULT("basic test");
}

void _set_random_string(char *str, int len)
{
	str[len--] = 0;
	do {
		str[len] = '!' + random('~'-'!');
	} while(len--);
}

void large_test(size_t ndocs, size_t keylen, size_t metalen, size_t bodylen)
{
	TEST_INIT();

	fdb_handle db;
	fdb_config config;
	fdb_doc **doc, **rdoc;
	fdb_status status;
	
	int i, n=ndocs, r;
	char keybuf[keylen+1], metabuf[metalen+1], bodybuf[bodylen+1], temp[256];
	
	config.chunksize = sizeof(uint64_t);
	config.offsetsize = sizeof(uint64_t);
	config.buffercache_size = 1024 * 1024 * 1024;
	config.wal_threshold = 1<<19;
	config.flag = 0;

	doc = (fdb_doc**)malloc(sizeof(fdb_doc*) * ndocs);
	rdoc = (fdb_doc**)malloc(sizeof(fdb_doc*) * ndocs);

	DBG("initialization\n");

	r = system("rm -rf ./dummy");
	r = system("rm -rf ./dummy2");
	
	fdb_open(&db, "./dummy", config);
	fdb_close(&db);

	TEST_TIME();

	DBG("create %"_F64" random docs\n", ndocs);
	for (i=0;i<ndocs;++i){
		_set_random_string(keybuf, keylen);
		_set_random_string(metabuf, metalen);
		_set_random_string(bodybuf, bodylen);
		fdb_doc_create(&doc[i], keybuf, keylen, metabuf, metalen, bodybuf, bodylen);
	}
	TEST_TIME();

	fdb_open(&db, "./dummy", config);

	// insert documents
	DBG("set\n");
	for (i=0;i<n;++i){
		status = fdb_set(&db, doc[i]);
		TEST_CHK(status == FDB_RESULT_SUCCESS);
	}
	TEST_TIME();

	DBG("commit\n");
	fdb_commit(&db);
	TEST_TIME();

	// update documents
	DBG("update\n");
	for (i=0;i<n;++i){
		status = fdb_set(&db, doc[i]);
		TEST_CHK(status == FDB_RESULT_SUCCESS);
	}
	TEST_TIME();

	DBG("commit\n");
	fdb_commit(&db);
	TEST_TIME();
	
	// retrieve documents
	DBG("get\n");
	for (i=0;i<n;++i){
		fdb_doc_create(&rdoc[i], doc[i]->key, doc[i]->keylen, NULL, 0, NULL, 0);
		status = fdb_get(&db, rdoc[i]);
		TEST_CHK(status == FDB_RESULT_SUCCESS);
	}
	TEST_TIME();

	DBG("verifying\n");
	for (i=0;i<n;++i){
		TEST_CHK(!memcmp(rdoc[i]->meta, doc[i]->meta, rdoc[i]->metalen));
		TEST_CHK(!memcmp(rdoc[i]->body, doc[i]->body, rdoc[i]->bodylen));		
		fdb_doc_free(rdoc[i]);
	}
	TEST_TIME();

	DBG("compaction\n");
	fdb_compact(&db, "./dummy2");
	TEST_TIME();

	DBG("close\n");
	fdb_close(&db);
	TEST_TIME();

	TEST_RESULT("large test");
}


int main(){
	//basic_test();
	large_test(1000000, 32, 32, 512);

	return 0;
}
