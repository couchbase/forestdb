#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <sys/stat.h>

#include "leveldb/c.h"
#include "couch_db.h"
#include "debug.h"
#include "option.h"

#define BUF_MAXLEN 65536

struct _db {
    leveldb_t *db;
    leveldb_options_t *options;
    leveldb_readoptions_t *read_options;
    leveldb_writeoptions_t *write_options;
    char *filename;
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
    Db *ppdb;
    char *err;
    
    *pDb = (Db*)malloc(sizeof(Db));
    ppdb = *pDb;

    ppdb->filename = (char*)malloc(strlen(filename)+1);
    strcpy(ppdb->filename, filename);

    ppdb->options = leveldb_options_create();
    leveldb_options_set_create_if_missing(ppdb->options, 1);
    leveldb_options_set_compression(ppdb->options, 0);
    ppdb->db = leveldb_open(ppdb->options, ppdb->filename, &err);

    ppdb->read_options = leveldb_readoptions_create();
    ppdb->write_options = leveldb_writeoptions_create();
    leveldb_writeoptions_set_sync(ppdb->write_options, 1);
    
    return COUCHSTORE_SUCCESS;
}

LIBCOUCHSTORE_API
couchstore_error_t couchstore_close_db(Db *db)
{
    leveldb_close(db->db);
    free(db->filename);
    free(db);

    return COUCHSTORE_SUCCESS;
}

LIBCOUCHSTORE_API
couchstore_error_t couchstore_db_info(Db *db, DbInfo* info)
{
    struct stat filestat;

    info->filename = db->filename;
    info->doc_count = 0;
    info->deleted_count = 0;
    info->header_position = 0;
    info->last_sequence = 0;

    stat(db->filename, &filestat);
    info->space_used = filestat.st_size;
    
    return COUCHSTORE_SUCCESS;
}

size_t _docinfo_to_buf(DocInfo *docinfo, void *buf)
{
    // [db_seq,] rev_seq, deleted, content_meta, rev_meta (size), rev_meta (buf)
    size_t offset = 0;

    /*memcpy(buf + offset, &docinfo->db_seq, sizeof(docinfo->db_seq));
    offset += sizeof(docinfo->db_seq);*/

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
    uint16_t metalen;
    uint8_t buf[BUF_MAXLEN];
    char *err;
    leveldb_writebatch_t *wb;

    wb = leveldb_writebatch_create();

    for (i=0;i<numdocs;++i){

        metalen = _docinfo_to_buf(infos[i], buf);
        memmove(buf + sizeof(metalen), buf, metalen);
        memcpy(buf, &metalen, sizeof(metalen));
        memcpy(buf + sizeof(metalen) + metalen, docs[i]->data.buf, docs[i]->data.size);

        leveldb_writebatch_put(wb, 
            docs[i]->id.buf, docs[i]->id.size, buf, sizeof(metalen) + metalen + docs[i]->data.size);

        infos[i]->db_seq = 0;
    }
    leveldb_write(db->db, db->write_options, wb, &err);
    leveldb_writebatch_destroy(wb);
    
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
    
    /*memcpy(&docinfo->db_seq, buf + offset, sizeof(docinfo->db_seq));
    offset += sizeof(docinfo->db_seq);*/

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
    char *err;
    void *value;
    size_t valuelen;
    size_t rev_meta_size;
    size_t meta_offset;

    value = leveldb_get(db->db, db->read_options, id, idlen, &valuelen, &err);

    meta_offset = sizeof(uint64_t)*1 + sizeof(int) + sizeof(couchstore_content_meta_flags);
    memcpy(&rev_meta_size, value + sizeof(uint16_t) + meta_offset, sizeof(size_t));

    *pInfo = (DocInfo *)malloc(sizeof(DocInfo) + rev_meta_size);
    (*pInfo)->id.buf = (char *)id;
    (*pInfo)->id.size = idlen;
    (*pInfo)->size = idlen + valuelen;
    (*pInfo)->bp = 0;
    (*pInfo)->db_seq = 0;
    _buf_to_docinfo(value + sizeof(uint16_t), valuelen, (*pInfo));

    free(value);

    return COUCHSTORE_SUCCESS;
}

LIBCOUCHSTORE_API
couchstore_error_t couchstore_docinfos_by_id(Db *db, const sized_buf ids[], unsigned numDocs,
        couchstore_docinfos_options options, couchstore_changes_callback_fn callback, void *ctx)
{
    int i;
    DocInfo *docinfo;
    char *err;
    void *value;
    size_t valuelen;
    size_t rev_meta_size, max_meta_size = 256;
    size_t meta_offset;

    meta_offset = sizeof(uint64_t)*1 + sizeof(int) + sizeof(couchstore_content_meta_flags);
    docinfo = (DocInfo*)malloc(sizeof(DocInfo) + max_meta_size);

    for (i=0;i<numDocs;++i){
        value = leveldb_get(db->db, db->read_options, ids[i].buf, ids[i].size, &valuelen, &err);
       
        memcpy(&rev_meta_size, value + sizeof(uint16_t) + meta_offset, sizeof(size_t));
        if (rev_meta_size > max_meta_size) {
            max_meta_size = rev_meta_size;
            docinfo = (DocInfo*)realloc(docinfo, sizeof(DocInfo) + max_meta_size);
        }

        memset(docinfo, 0, sizeof(DocInfo));
        docinfo->id.buf = ids[i].buf;
        docinfo->id.size = ids[i].size;
        docinfo->size = ids[i].size + valuelen;
        docinfo->bp = 0;
        docinfo->db_seq = 0;
        _buf_to_docinfo(value + sizeof(uint16_t), valuelen, docinfo);
        free(value);

        callback(db, docinfo, ctx);
    }

    free(docinfo);

    return COUCHSTORE_SUCCESS;
}

LIBCOUCHSTORE_API
couchstore_error_t couchstore_docinfos_by_sequence(Db *db,
                                                   const uint64_t sequence[],
                                                   unsigned numDocs,
                                                   couchstore_docinfos_options options,
                                                   couchstore_changes_callback_fn callback,
                                                   void *ctx)
{
    // do nothing

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
    // do nothing (automatically performed at the end of each write batch)

    return COUCHSTORE_SUCCESS;
}

LIBCOUCHSTORE_API
couchstore_error_t couchstore_compact_db_ex(Db* source, const char* target_filename,
        uint64_t flags, const couch_file_ops *ops)
{
    return COUCHSTORE_SUCCESS;
}

LIBCOUCHSTORE_API
couchstore_error_t couchstore_compact_db(Db* source, const char* target_filename)
{
    return couchstore_compact_db_ex(source, target_filename, 0x0, NULL);
}

