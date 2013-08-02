#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "forestdb.h"
#include "couch_db.h"

#define META_BUF_MAXLEN 256

struct _db {
	fdb_handle fdb;
	uint64_t seqnum;
};

LIBCOUCHSTORE_API
couchstore_error_t couchstore_open_db(const char *filename,
                                      couchstore_open_flags flags,
                                      Db **pDb)
{
    return couchstore_open_db_ex(filename, flags,
                                 NULL, pDb);
}

LIBCOUCHSTORE_API
couchstore_error_t couchstore_open_db_ex(const char *filename,
                                         couchstore_open_flags flags,
                                         const couch_file_ops *ops,
                                         Db **pDb)
{
	fdb_config config;
	fdb_status status;
	char *fname = (char *)filename;

	config.chunksize = sizeof(uint64_t);
	config.offsetsize = sizeof(uint64_t);
	config.buffercache_size = 1024 * 1024 * 1024;
	config.wal_threshold = 128 * 1024;
	config.flag = 0;

	*pDb = (Db*)malloc(sizeof(Db));
	(*pDb)->seqnum = 0;
	status = fdb_open(&((*pDb)->fdb), fname, config);
	
	return COUCHSTORE_SUCCESS;
}

LIBCOUCHSTORE_API
couchstore_error_t couchstore_close_db(Db *db)
{
	fdb_close(&db->fdb);
	free(db);

    return COUCHSTORE_SUCCESS;
}

size_t _docinfo_to_buf(DocInfo *docinfo, void *buf)
{
	// db_seq, rev_seq, deleted, content_meta, rev_meta (size), rev_meta (buf)
	size_t offset = 0;
	
	memcpy(buf + offset, &docinfo->db_seq, sizeof(docinfo->db_seq));
	offset += sizeof(docinfo->db_seq);

	memcpy(buf + offset, &docinfo->rev_seq, sizeof(docinfo->rev_seq));
	offset += sizeof(docinfo->rev_seq);

	memcpy(buf + offset, &docinfo->deleted, sizeof(docinfo->deleted));
	offset += sizeof(docinfo->deleted);

	memcpy(buf + offset, &docinfo->content_meta, sizeof(docinfo->content_meta));
	offset += sizeof(docinfo->content_meta);
	
	memcpy(buf + offset, &docinfo->rev_meta.size, sizeof(docinfo->rev_meta.size));
	offset += sizeof(docinfo->rev_meta.size);

	if (docinfo->rev_meta.size > 0) {
		memcpy(buf + offset, docinfo->rev_meta.buf, docinfo->rev_meta.size);
		offset += docinfo->rev_meta.size;
	}

	return offset;
}

void _buf_to_docinfo(void *buf, size_t size, DocInfo *docinfo)
{
	size_t offset = 0;

	memcpy(&docinfo->db_seq, buf + offset, sizeof(docinfo->db_seq));
	offset += sizeof(docinfo->db_seq);

	memcpy(&docinfo->rev_seq, buf + offset, sizeof(docinfo->rev_seq));
	offset += sizeof(docinfo->rev_seq);

	memcpy(&docinfo->deleted, buf + offset, sizeof(docinfo->deleted));
	offset += sizeof(docinfo->deleted);

	memcpy(&docinfo->content_meta, buf + offset, sizeof(docinfo->content_meta));
	offset += sizeof(docinfo->content_meta);

	memcpy(&docinfo->rev_meta.size, buf + offset, sizeof(docinfo->rev_meta.size));
	offset += sizeof(docinfo->rev_meta.size);

	if (docinfo->rev_meta.size > 0) {
		docinfo->rev_meta.buf = (char *)malloc(docinfo->rev_meta.size);
		memcpy(docinfo->rev_meta.buf, buf + offset, docinfo->rev_meta.size);
		offset += docinfo->rev_meta.size;
	}else{
		docinfo->rev_meta.buf = NULL;
	}
}

LIBCOUCHSTORE_API
couchstore_error_t couchstore_save_documents(Db *db, Doc* const docs[], DocInfo *infos[], 
		unsigned numdocs, couchstore_save_options options)
{
	unsigned i;
	fdb_doc _doc;
	fdb_status status;
	uint8_t buf[META_BUF_MAXLEN];

	for (i=0;i<numdocs;++i){
		_doc.key = docs[i]->id.buf;
		_doc.keylen = docs[i]->id.size;
		_doc.body = docs[i]->data.buf;
		_doc.bodylen = docs[i]->data.size;
		infos[i]->db_seq = db->seqnum++;
		_doc.metalen = _docinfo_to_buf(infos[i], buf);
		_doc.meta = buf;

		status = fdb_set(&db->fdb, &_doc);
	}
	
	return COUCHSTORE_SUCCESS;
}

LIBCOUCHSTORE_API
couchstore_error_t couchstore_save_document(Db *db, const Doc *doc, DocInfo *info, 
		couchstore_save_options options)
{
    return couchstore_save_documents(db, (Doc**)&doc, (DocInfo**)&info, 1, options);
}


LIBCOUCHSTORE_API
couchstore_error_t couchstore_docinfo_by_id(Db *db, const void *id, size_t idlen, DocInfo **pInfo)
{
	fdb_doc _doc;
	fdb_status status;
	uint64_t offset;
	
	_doc.key = (void *)id;
	_doc.keylen = idlen;

	status = fdb_get_metaonly(&db->fdb, &_doc, &offset);

	*pInfo = (DocInfo *)malloc(sizeof(DocInfo));
	(*pInfo)->id.buf = (char *)id;
	(*pInfo)->id.size = idlen;
	(*pInfo)->size = _doc.bodylen;
	(*pInfo)->bp = offset;
	_buf_to_docinfo(_doc.meta, _doc.metalen, (*pInfo));

	free(_doc.meta);

	return COUCHSTORE_SUCCESS;
}

LIBCOUCHSTORE_API
couchstore_error_t couchstore_docinfos_by_id(Db *db, const sized_buf ids[], unsigned numDocs,
		couchstore_docinfos_options options, couchstore_changes_callback_fn callback, void *ctx)
{
	return COUCHSTORE_SUCCESS;
}

LIBCOUCHSTORE_API
void couchstore_free_docinfo(DocInfo *docinfo)
{
    free(docinfo);
}

LIBCOUCHSTORE_API
couchstore_error_t couchstore_commit(Db *db)
{
	return COUCHSTORE_SUCCESS;
}

