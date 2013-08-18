#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>

#include "forestdb.h"
#include "couch_db.h"
#include "debug.h"

#define META_BUF_MAXLEN 256

struct _db {
    fdb_handle fdb;
    char *filename;
    uint64_t seqnum;
    size_t btree_fanout;
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
    fdb_handle *fdb;
    char *fname = (char *)filename;

    memset(&config, 0, sizeof(fdb_config));
    config.chunksize = sizeof(uint64_t);
    config.offsetsize = sizeof(uint64_t);
    config.buffercache_size = (uint64_t)2048 * 1024 * 1024;
    config.wal_threshold = 32 * 1024;
    config.seqtree = FDB_SEQTREE_USE;
    config.flag = 0;

    *pDb = (Db*)malloc(sizeof(Db));
    (*pDb)->seqnum = 0;
    (*pDb)->filename = (char *)malloc(strlen(filename)+1);
    strcpy((*pDb)->filename, filename);
    fdb = &((*pDb)->fdb);

    status = fdb_open(fdb, fname, config);
    
    return COUCHSTORE_SUCCESS;
}

LIBCOUCHSTORE_API
couchstore_error_t couchstore_close_db(Db *db)
{
    fdb_close(&db->fdb);
    free(db);

    return COUCHSTORE_SUCCESS;
}

LIBCOUCHSTORE_API
couchstore_error_t couchstore_db_info(Db *db, DbInfo* info)
{
    size_t btree_fanout;

    info->filename = db->filename;
    info->doc_count = db->fdb.ndocs;
    info->deleted_count = 0;
    info->header_position = 0;
    info->last_sequence = db->seqnum;
    info->space_used = db->fdb.datasize;
    // hb-trie size (estimated as worst case)
    info->space_used += (db->fdb.ndocs / (db->fdb.btree_fanout / 2)) * db->fdb.config.blocksize;
    // b-tree size (estimated as worst case)
    info->space_used += (db->fdb.ndocs / (db->fdb.btree_fanout / 2)) * db->fdb.config.blocksize;
    
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
        //docinfo->rev_meta.buf = (char *)malloc(docinfo->rev_meta.size);
        docinfo->rev_meta.buf = ((char *)docinfo) + sizeof(DocInfo);
        memcpy(docinfo->rev_meta.buf, buf + offset, docinfo->rev_meta.size);
        offset += docinfo->rev_meta.size;
    }else{
        docinfo->rev_meta.buf = NULL;
    }
}

LIBCOUCHSTORE_API
couchstore_error_t couchstore_docinfo_by_id(Db *db, const void *id, size_t idlen, DocInfo **pInfo)
{
    fdb_doc _doc;
    fdb_status status;
    uint64_t offset;
    size_t rev_meta_size;
    size_t meta_offset;

    meta_offset = sizeof(uint64_t)*2 + sizeof(int) + sizeof(couchstore_content_meta_flags);
    
    _doc.key = (void *)id;
    _doc.keylen = idlen;
    _doc.meta = _doc.body = NULL;

    status = fdb_get_metaonly(&db->fdb, &_doc, &offset);
    memcpy(&rev_meta_size, _doc.meta + meta_offset, sizeof(size_t));

    *pInfo = (DocInfo *)malloc(sizeof(DocInfo) + rev_meta_size);
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
    int i;
    fdb_doc _doc;
    fdb_status status;
    DocInfo *docinfo;
    uint64_t offset;
    size_t rev_meta_size, max_meta_size = 256;
    size_t meta_offset;

    DBGSW(0, int temp=0; );

    meta_offset = sizeof(uint64_t)*2 + sizeof(int) + sizeof(couchstore_content_meta_flags);

    docinfo = (DocInfo*)malloc(sizeof(DocInfo) + max_meta_size);

    for (i=0;i<numDocs;++i){
        _doc.key = (void*)ids[i].buf;
        _doc.keylen = ids[i].size;
        _doc.meta = _doc.body = NULL;

        status = fdb_get_metaonly(&db->fdb, &_doc, &offset);
        assert(status != FDB_RESULT_FAIL);
        
        memcpy(&rev_meta_size, _doc.meta + meta_offset, sizeof(size_t));
        if (rev_meta_size > max_meta_size) {
            max_meta_size = rev_meta_size;
            docinfo = (DocInfo*)realloc(docinfo, sizeof(DocInfo) + max_meta_size);
        }

        memset(docinfo, 0, sizeof(DocInfo));
        docinfo->id.buf = ids[i].buf;
        docinfo->id.size = ids[i].size;
        docinfo->size = _doc.bodylen;
        docinfo->bp = offset;
        _buf_to_docinfo(_doc.meta, _doc.metalen, docinfo);
        free(_doc.meta);

        callback(db, docinfo, ctx);
    }

    free(docinfo);

    return COUCHSTORE_SUCCESS;
}

LIBCOUCHSTORE_API
void couchstore_free_docinfo(DocInfo *docinfo)
{
    //free(docinfo->rev_meta.buf);
    free(docinfo);
}

LIBCOUCHSTORE_API
couchstore_error_t couchstore_commit(Db *db)
{
    fdb_commit(&db->fdb);
    return COUCHSTORE_SUCCESS;
}

LIBCOUCHSTORE_API
couchstore_error_t couchstore_compact_db_ex(Db* source, const char* target_filename,
        uint64_t flags, const couch_file_ops *ops)
{
    char *new_filename = (char *)target_filename;
    fdb_compact(&source->fdb, new_filename);
    return COUCHSTORE_SUCCESS;
}

LIBCOUCHSTORE_API
couchstore_error_t couchstore_compact_db(Db* source, const char* target_filename)
{
    return couchstore_compact_db_ex(source, target_filename, 0x0, NULL);
}

