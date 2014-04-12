/* -*- Mode: C++; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2010 Couchbase, Inc
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
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
#include "crc32.h"

#include "memleak.h"

#ifdef __DEBUG
#ifndef __DEBUG_WAL
    #undef DBG
    #undef DBGCMD
    #undef DBGSW
    #define DBG(...)
    #define DBGCMD(...)
    #define DBGSW(n, ...)
#endif
#endif

#ifdef __FDB_SEQTREE
    #define SEQTREE(...) __VA_ARGS__
#else
    #define SEQTREE(...)
#endif

INLINE uint32_t _wal_hash_bykey(struct hash *hash, struct hash_elem *e)
{
    struct wal_item *item = _get_entry(e, struct wal_item, he_key);
    // using only first 8 bytes
    return crc32_8(item->key, MIN(8, item->keylen), 0) & ((uint64_t)hash->nbuckets - 1);
}

INLINE int _wal_cmp_bykey(struct hash_elem *a, struct hash_elem *b)
{
    struct wal_item *aa, *bb;
    aa = _get_entry(a, struct wal_item, he_key);
    bb = _get_entry(b, struct wal_item, he_key);

    if (aa->keylen == bb->keylen) return memcmp(aa->key, bb->key, aa->keylen);
    else {
        size_t len = MIN(aa->keylen , bb->keylen);
        int cmp = memcmp(aa->key, bb->key, len);
        if (cmp != 0) return cmp;
        else {
            return (int)((int)aa->keylen - (int)bb->keylen);
        }
    }
}

#ifdef __FDB_SEQTREE

INLINE uint32_t _wal_hash_byseq(struct hash *hash, struct hash_elem *e)
{
    struct wal_item *item = _get_entry(e, struct wal_item, he_seq);
    return (item->seqnum) & ((uint64_t)hash->nbuckets - 1);
}

INLINE int _wal_cmp_byseq(struct hash_elem *a, struct hash_elem *b)
{
    struct wal_item *aa, *bb;
    aa = _get_entry(a, struct wal_item, he_seq);
    bb = _get_entry(b, struct wal_item, he_seq);

    return _CMP_U64(aa->seqnum, bb->seqnum);
}

#endif

wal_result wal_init(struct filemgr *file, int nbucket)
{
    file->wal->flag = WAL_FLAG_INITIALIZED;
    file->wal->size = 0;
    file->wal->num_deletes = 0;
    file->wal->last_commit = NULL;
    file->wal->wal_dirty = FDB_WAL_CLEAN;
    hash_init(&file->wal->hash_bykey, nbucket, _wal_hash_bykey, _wal_cmp_bykey);
    SEQTREE(hash_init(&file->wal->hash_byseq, nbucket, _wal_hash_byseq,
                       _wal_cmp_byseq));
    list_init(&file->wal->list);
    spin_init(&file->wal->lock);

    DBG("wal item size %d\n", (int)sizeof(struct wal_item));
    return WAL_RESULT_SUCCESS;
}

int wal_is_initialized(struct filemgr *file)
{
    return file->wal->flag & WAL_FLAG_INITIALIZED;
}

static wal_result _wal_insert(struct filemgr *file,
                              fdb_doc *doc,
                              uint64_t offset,
                              int is_compactor)
{
    struct wal_item *item;
    struct wal_item query;
    struct hash_elem *e;
    void *key = doc->key;
    size_t keylen = doc->keylen;

    query.key = key;
    query.keylen = keylen;
    SEQTREE( query.seqnum = doc->seqnum; );

    spin_lock(&file->wal->lock);

    e = hash_find(&file->wal->hash_bykey, &query.he_key);

    if (e) {
        // already exist

        // if this entry is inserted by compactor, AND
        // the other entry for the same key already exists,
        // then we know that the other entry is inserted by the other writer.
        // AND also the other entry is always fresher than
        // the entry inserted by compactor.
        // Thus, we ignore the entry by compactor.
        if (!is_compactor) {
            item = _get_entry(e, struct wal_item, he_key);
            item->flag &= ~WAL_ITEM_FLUSH_READY;

            #ifdef __FDB_SEQTREE
                hash_remove(&file->wal->hash_byseq, &item->he_seq);
                item->seqnum = query.seqnum;
                hash_insert(&file->wal->hash_byseq, &item->he_seq);
            #endif

            if (item->action == WAL_ACT_INSERT) {
                if (!doc->bodylen) {
                    ++file->wal->num_deletes;
                }
            } else {
                if (doc->bodylen) {
                    --file->wal->num_deletes;
                }
            }

            item->doc_size = doc->size_ondisk;
            item->offset = offset;
            item->action = doc->bodylen > 0 ? WAL_ACT_INSERT : WAL_ACT_LOGICAL_REMOVE;

            // move to the end of list
            list_remove(&file->wal->list, &item->list_elem);
            list_push_back(&file->wal->list, &item->list_elem);
        }

    } else {
        // not exist .. create new one
        item = (struct wal_item *)mempool_alloc(sizeof(struct wal_item));
        item->keylen = keylen;
        item->flag = 0x0;
    #ifdef __WAL_KEY_COPY
        item->key = (void *)mempool_alloc(item->keylen);
        memcpy(item->key, key, item->keylen);
    #else
        item->key = key;
    #endif

        SEQTREE( item->seqnum = query.seqnum );
        item->action = doc->bodylen > 0 ? WAL_ACT_INSERT : WAL_ACT_LOGICAL_REMOVE;
        item->offset = offset;
        item->doc_size = doc->size_ondisk;

        hash_insert(&file->wal->hash_bykey, &item->he_key);
        SEQTREE( hash_insert(&file->wal->hash_byseq, &item->he_seq) );

        list_push_back(&file->wal->list, &item->list_elem);
        ++file->wal->size;
        if (!doc->bodylen) {
            ++file->wal->num_deletes;
        }
    }

    spin_unlock(&file->wal->lock);

    return WAL_RESULT_SUCCESS;
}

wal_result wal_insert(struct filemgr *file, fdb_doc *doc, uint64_t offset)
{
    return _wal_insert(file, doc, offset, 0);
}

wal_result wal_insert_by_compactor(struct filemgr *file,
                                   fdb_doc *doc,
                                   uint64_t offset)
{
    return _wal_insert(file, doc, offset, 1);
}

wal_result wal_find(struct filemgr *file, fdb_doc *doc, uint64_t *offset)
{
    struct wal_item *item = NULL;
    struct wal_item query;
    struct hash_elem *e = NULL;
    void *key = doc->key;
    size_t keylen = doc->keylen;

    spin_lock(&file->wal->lock);

#ifdef __FDB_SEQTREE
    if (doc->seqnum == SEQNUM_NOT_USED || (key && keylen>0)) {
        // search by key
        query.key = key;
        query.keylen = keylen;
        e = hash_find(&file->wal->hash_bykey, &query.he_key);
        if (e) {
            item = _get_entry(e, struct wal_item, he_key);
            *offset = item->offset;
            if (item->action == WAL_ACT_INSERT) {
                doc->deleted = false;
            } else {
                doc->deleted = true;
            }
            spin_unlock(&file->wal->lock);
            return WAL_RESULT_SUCCESS;
        }
    } else {
        // search by seqnum
        query.seqnum = doc->seqnum;
        e = hash_find(&file->wal->hash_byseq, &query.he_seq);
        if (e) {
            item = _get_entry(e, struct wal_item, he_seq);
            *offset = item->offset;
            if (item->action == WAL_ACT_INSERT) {
                doc->deleted = false;
            } else {
                doc->deleted = true;
            }
            spin_unlock(&file->wal->lock);
            return WAL_RESULT_SUCCESS;
        }
    }
#else
    // seq-tree is not used .. just search by key
    query.key = key;
    query.keylen = keylen;
    e = hash_find(&file->wal->hash_bykey, &query.he_key);
    if (e) {
        item = _get_entry(e, struct wal_item, he_key);
        *offset = item->offset;
        if (item->action == WAL_ACT_INSERT) {
            doc->deleted = false;
        } else {
            doc->deleted = true;
        }
        spin_unlock(&file->wal->lock);
        return WAL_RESULT_SUCCESS;
    }
#endif
    spin_unlock(&file->wal->lock);
    return WAL_RESULT_FAIL;
}

wal_result wal_remove(struct filemgr *file, fdb_doc *doc)
{
    //3 search by key only
    struct wal_item *item;
    struct wal_item query;
    struct hash_elem *e;
    void *key = doc->key;
    size_t keylen = doc->keylen;

    query.key = key;
    query.keylen = keylen;
    SEQTREE(
        query.seqnum = doc->seqnum;
    );

    spin_lock(&file->wal->lock);

    e = hash_find(&file->wal->hash_bykey, &query.he_key);

    if (e) {
        // already exist

        item = _get_entry(e, struct wal_item, he_key);
        item->flag &= ~WAL_ITEM_FLUSH_READY;

#ifdef __FDB_SEQTREE
        hash_remove(&file->wal->hash_byseq, &item->he_seq);
        item->seqnum = query.seqnum;
        hash_insert(&file->wal->hash_byseq, &item->he_seq);
#endif
        if (item->action == WAL_ACT_INSERT) {
            item->action = WAL_ACT_REMOVE;
            ++file->wal->num_deletes;
        }

        // move to the end of list
        list_remove(&file->wal->list, &item->list_elem);
        list_push_back(&file->wal->list, &item->list_elem);
    } else {
        item = (struct wal_item *)mempool_alloc(sizeof(struct wal_item));
        item->keylen = keylen;
        item->flag = 0x0;
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
        ++file->wal->size;
        ++file->wal->num_deletes;
    }

    spin_unlock(&file->wal->lock);
    return WAL_RESULT_SUCCESS;
}

wal_result wal_commit(struct filemgr *file)
{
    spin_lock(&file->wal->lock);
    file->wal->last_commit = list_end(&file->wal->list);
    spin_unlock(&file->wal->lock);
    return WAL_RESULT_SUCCESS;
}

int _wal_flush_cmp(struct avl_node *a, struct avl_node *b, void *aux)
{
    struct wal_item *aa, *bb;
    aa = _get_entry(a, struct wal_item, avl);
    bb = _get_entry(b, struct wal_item, avl);

    if (aa->old_offset < bb->old_offset) {
        return -1;
    } else if (aa->old_offset > bb->old_offset) {
        return 1;
    } else {
        // old_offset can be 0 if the document was newly inserted
        if (aa->offset < bb->offset) {
            return -1;
        } else if (aa->offset > bb->offset) {
            return 1;
        } else {
            return 0;
        }
    }
}

wal_result wal_flush(struct filemgr *file,
                     void *dbhandle,
                     wal_flush_func *flush_func,
                     wal_get_old_offset_func *get_old_offset)
{
    int i;
    struct avl_tree tree;
    struct avl_node *a;
    struct list_elem *e;
    struct hash_elem *h;
    struct wal_item *item;
    size_t count = 0;

    // sort by old byte-offset of the document (for sequential access)
    spin_lock(&file->wal->lock);
    avl_init(&tree, NULL);
    e = list_begin(&file->wal->list);
    while(e){
        item = _get_entry(e, struct wal_item, list_elem);
        if (item->action == WAL_ACT_LOGICAL_REMOVE ||
            item->action == WAL_ACT_REMOVE) {
            --file->wal->num_deletes;
        }
        item->old_offset = get_old_offset(dbhandle, item);
        item->flag |= WAL_ITEM_FLUSH_READY;
        avl_insert(&tree, &item->avl, _wal_flush_cmp);
        e = list_next(e);
        list_remove(&file->wal->list, &item->list_elem);
        count++;
        file->wal->size--;
    }
    file->wal->last_commit = list_begin(&file->wal->list);
    spin_unlock(&file->wal->lock);

    // scan and flush entries in the avl-tree
    a = avl_first(&tree);
    while (a) {
        spin_lock(&file->wal->lock);

        item = _get_entry(a, struct wal_item, avl);
        a = avl_next(a);
        avl_remove(&tree, &item->avl);

        // check weather this item is updated after insertion into tree
        if (item->flag & WAL_ITEM_FLUSH_READY) {
            hash_remove(&file->wal->hash_bykey, &item->he_key);
            SEQTREE( hash_remove(&file->wal->hash_byseq, &item->he_seq) );
            flush_func(dbhandle, item);
#ifdef __WAL_KEY_COPY
            mempool_free(item->key);
#endif
            mempool_free(item);
        }

        spin_unlock(&file->wal->lock);
    }

    return WAL_RESULT_SUCCESS;
}


// discard entries that are not committed (i.e. all entries after the last commit)
wal_result wal_close(struct filemgr *file)
{
    struct wal_item *item;
    struct list_elem *e;

    spin_lock(&file->wal->lock);

    if (file->wal->last_commit) {
        // if LAST_COMMIT is not NULL, then discard non-committed items
        e = list_next(file->wal->last_commit);
    }else{
        // if LAST_COMMIT is NULL, then start from the beginning (discard all entries)
        e = list_begin(&file->wal->list);
    }

    while(e){
        item = _get_entry(e, struct wal_item, list_elem);
        if (item->action == WAL_ACT_LOGICAL_REMOVE ||
            item->action == WAL_ACT_REMOVE) {
            --file->wal->num_deletes;
        }
        e = list_remove(&file->wal->list, e);
        hash_remove(&file->wal->hash_bykey, &item->he_key);
        SEQTREE( hash_remove(&file->wal->hash_byseq, &item->he_seq) );

    #ifdef __WAL_KEY_COPY
        mempool_free(item->key);
    #endif
        mempool_free(item);

        file->wal->size--;
    }

    spin_unlock(&file->wal->lock);
    return WAL_RESULT_SUCCESS;
}

// discard all WAL entries
wal_result wal_shutdown(struct filemgr *file)
{
    file->wal->last_commit = NULL;
    return wal_close(file);
}

size_t wal_get_size(struct filemgr *file)
{
    return file->wal->size;
}

size_t wal_get_num_deletes(struct filemgr *file) {
    return file->wal->num_deletes;
}

size_t wal_get_datasize(struct filemgr *file)
{
    size_t datasize = 0;
    struct list_elem *e;
    struct hash_elem *h;
    struct wal_item *item;

    spin_lock(&file->wal->lock);

    e = list_begin(&file->wal->list);
    while(e){
        item = _get_entry(e, struct wal_item, list_elem);
        datasize += item->doc_size;
        e = list_next(e);
    }
    spin_unlock(&file->wal->lock);

    return datasize;
}

void wal_set_dirty_status(struct filemgr *file, wal_dirty_t status)
{
    spin_lock(&file->wal->lock);
    file->wal->wal_dirty = status;
    spin_unlock(&file->wal->lock);
}

wal_dirty_t wal_get_dirty_status(struct filemgr *file)
{
    wal_dirty_t ret;
    spin_lock(&file->wal->lock);
    ret = file->wal->wal_dirty;
    spin_unlock(&file->wal->lock);
    return ret;
}


