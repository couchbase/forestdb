#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "couch_common.h"
#include "couch_db.h"

void basic_bench()
{
	Db *db;
	Doc doc[10];
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
		err = couchstore_docinfo_by_id(db, key, strlen(key)+1, &rinfo);
		if (err==0)
			printf("%s %ld %ld %ld %ld\n", rinfo->id.buf, rinfo->db_seq, rinfo->rev_seq, rinfo->size, rinfo->bp);
	}
	
	couchstore_close_db(db);
}

int main(){
	basic_bench();

	return 0;
}

