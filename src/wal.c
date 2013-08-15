/*
 * Copyright 2013 Jung-Sang Ahn <jungsang.ahn@gmail.com>.
 * All Rights Reserved.
 */

#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdint.h>

#include "filemgr.h"
#include "common.h"
#include "hash.h"
#include "docio.h"
#include "wal.h"
#include "hash_functions.h"
#include "hbtrie.h"
#include "crc32.h"

#include "forestdb.h"

#ifdef __DEBUG
#ifndef __DEBUG_WAL
    #undef DBG
    #undef DBGCMD
    #define DBG(args...)
    #define DBGCMD(command...)
#endif
#endif

#ifdef __FDB_SEQTREE
    #define SEQTREE(args...) args
#else
    #define SEQTREE(args...)
#endif

INLINE uint32_t _wal_hash_bykey(struct hash *hash, struct hash_elem *e)
{
    struct wal_item *item = _get_entry(e, struct wal_item, he_key);
    //return hash_djb2(item->key, MIN(8, item->keylen)) & ((uint64_t)hash->nbuckets - 1);
    return crc32_8(item->key, MIN(8, item->keylen), 0) & ((uint64_t)hash->nbuckets - 1);
}

INLINE int _wal_cmp_bykey(struct hash_elem *a, struct hash_elem *b)
{
    keylen_t minkeylen;
    struct wal_item *aa, *bb;
    aa = _get_entry(a, struct wal_item, he_key);
    bb = _get_entry(b, struct wal_item, he_key);

    if (aa->keylen != bb->keylen) return ((int)aa->keylen - (int)bb->keylen);
    return memcmp(aa->key, bb->key, aa->keylen);
}

#ifdef __FDB_SEQTREE

INLINE uint32_t _wal_hash_byseq(struct hash *hash, struct hash_elem *e)
{
    struct wal_item *item = _get_entry(e, struct wal_item, he_seq);
    return (item->seqnum) & ((uint64_t)hash->nbuckets - 1);
}

INLINE int _wal_cmp_byseq(struct hash_elem *a, struct hash_elem *b)
{
    keylen_t minkeylen;
    struct wal_item *aa, *bb;
    aa = _get_entry(a, struct wal_item, he_seq);
    bb = _get_entry(b, struct wal_item, he_seq);

    return _CMP_U64(aa->seqnum, bb->seqnum);
}

#endif

wal_result wal_init(struct filemgr *file, int nbucket)
{
    file->wal->size = 0;
    hash_init(&file->wal->hash_bykey, nbucket, _wal_hash_bykey, _wal_cmp_bykey);
    SEQTREE(hash_init(&file->wal->hash_byseq, nbucket, _wal_hash_byseq, _wal_cmp_byseq));
    list_init(&file->wal->list);

    DBG("wal item size %d\n", (int)sizeof(struct wal_item));
    return WAL_RESULT_SUCCESS;
}

wal_result wal_insert(struct filemgr *file, fdb_doc *doc, uint64_t offset)
{
    struct wal_item *item;
    struct wal_item query;
    struct hash_elem *e;
    void *key = doc->key;
    size_t keylen = doc->keylen;

    query.key = key;
    query.keylen = keylen;
    SEQTREE( memcpy(&query.seqnum, doc->meta, sizeof(fdb_seqnum_t)) );

    #ifdef __FDB_SEQTREE
        e = hash_find(&file->wal->hash_byseq, &query.he_seq);
    #else
        e = hash_find(&file->wal->hash_bykey, &query.he_key);
    #endif

    if (e) {
        #ifdef __FDB_SEQTREE
            item = _get_entry(e, struct wal_item, he_seq);
        #else
            item = _get_entry(e, struct wal_item, he_key);
        #endif

        item->doc_size = doc->keylen + doc->metalen + doc->bodylen + sizeof(struct docio_length);
        item->offset = offset;
        item->action = WAL_ACT_INSERT;
    }else{
        item = (struct wal_item *)mempool_alloc(sizeof(struct wal_item));
        item->keylen = keylen;
        
        //3 KEY should be copied or just be linked?
        #ifdef __WAL_KEY_COPY
            item->key = (void *)mempool_alloc(item->keylen);
            memcpy(item->key, key, item->keylen);
        #else
            item->key = key;
        #endif

        SEQTREE( item->seqnum = query.seqnum );
        item->action = WAL_ACT_INSERT;
        item->offset = offset;
        item->doc_size = doc->keylen + doc->metalen + doc->bodylen + sizeof(struct docio_length);

        hash_insert(&file->wal->hash_bykey, &item->he_key);
        SEQTREE( hash_insert(&file->wal->hash_byseq, &item->he_seq) );
            
        list_push_back(&file->wal->list, &item->list_elem);
        file->wal->size++;
    }

    return WAL_RESULT_SUCCESS;
}

wal_result wal_find(struct filemgr *file, fdb_doc *doc, uint64_t *offset)
{
    struct wal_item *item = NULL;
    struct wal_item query;
    struct hash_elem *e = NULL;
    void *key = doc->key;
    size_t keylen = doc->keylen;

#ifdef __FDB_SEQTREE
    if (doc->meta == NULL) {
        query.key = key;
        query.keylen = keylen;
        e = hash_find(&file->wal->hash_bykey, &query.he_key);
        if (e) {
            item = _get_entry(e, struct wal_item, he_key);
            if (item->action == WAL_ACT_INSERT) {
                *offset = item->offset;
                return WAL_RESULT_SUCCESS;
            }
        }
    } else {
        memcpy(&query.seqnum, doc->meta, sizeof(fdb_seqnum_t));
        e = hash_find(&file->wal->hash_byseq, &query.he_seq);
        if (e) {
            item = _get_entry(e, struct wal_item, he_seq);
            if (item->action == WAL_ACT_INSERT) {
                *offset = item->offset;
                return WAL_RESULT_SUCCESS;
            }
        }
    }
#else
    query.key = key;
    query.keylen = keylen;
    e = hash_find(&file->wal->hash_bykey, &query.he_key);
    if (e) {
        item = _get_entry(e, struct wal_item, he_key);
        if (item->action == WAL_ACT_INSERT) {
            *offset = item->offset;
            return WAL_RESULT_SUCCESS;
        }
    }
#endif
    return WAL_RESULT_FAIL;
}

wal_result wal_remove(struct filemgr *file, fdb_doc *doc)
{
    struct wal_item *item;
    struct wal_item query;
    struct hash_elem *e;
    void *key = doc->key;
    size_t keylen = doc->keylen;

    query.key = key;
    query.keylen = keylen;
    SEQTREE( memcpy(&query.seqnum, doc->meta, sizeof(fdb_seqnum_t)) );

    /*
    #ifdef __FDB_SEQTREE
        e = hash_find(&file->wal->hash_byseq, &query.he_seq);
    #else*/
        e = hash_find(&file->wal->hash_bykey, &query.he_key);
    //#endif
    
    if (e) {
        /*
        #ifdef __FDB_SEQTREE
            item = _get_entry(e, struct wal_item, he_seq);
        #else*/
            item = _get_entry(e, struct wal_item, he_key);
        //#endif
        
        if (item->action == WAL_ACT_INSERT) {
            item->action = WAL_ACT_REMOVE;
        }
    }else{
        item = (struct wal_item *)mempool_alloc(sizeof(struct wal_item));
        item->keylen = keylen;
        #ifdef __WAL_KEY_COPY
            item->key = (void *)mempool_alloc(item->keylen);
            memcpy(item->key, key, item->keylen);
        #else
            item->key = key;
        #endif
    
        //SEQTREE( item->seqnum = query.seqnum );    
        item->action = WAL_ACT_REMOVE;
        hash_insert(&file->wal->hash_bykey, &item->he_key);
        SEQTREE( hash_insert(&file->wal->hash_byseq, &item->he_seq) );
        list_push_back(&file->wal->list, &item->list_elem);
        file->wal->size++;        
    }
    return WAL_RESULT_SUCCESS;
}

wal_result wal_flush(struct filemgr *file, void *dbhandle, wal_flush_func *func)
{
    int i;
    struct list_elem *e;
    struct hash_elem *h;
    struct wal_item *item;
    DBGCMD(
        struct timeval a,b,rr;
        gettimeofday(&a, NULL);
    );

    DBG("wal size: %"_F64"\n", file->wal->size);

    e = list_begin(&file->wal->list);
    while(e){
        item = _get_entry(e, struct wal_item, list_elem);
        e = list_remove(&file->wal->list, e);
        hash_remove(&file->wal->hash_bykey, &item->he_key);
        SEQTREE( hash_remove(&file->wal->hash_byseq, &item->he_seq) );
        func(dbhandle, item);

        #ifdef __WAL_KEY_COPY
            mempool_free(item->key);
        #endif
        mempool_free(item);
    }
    file->wal->size = 0;

    DBGCMD(
        gettimeofday(&b, NULL);
        rr = _utime_gap(a,b);        
    );
    DBG("wal flushed, %"_FSEC".%06"_FUSEC" sec elapsed.\n", rr.tv_sec, rr.tv_usec);

    return WAL_RESULT_SUCCESS;
}

size_t wal_get_size(struct filemgr *file) 
{
    return file->wal->size;
}


