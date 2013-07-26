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

int main(){
	basic_test();

	return 0;
}
