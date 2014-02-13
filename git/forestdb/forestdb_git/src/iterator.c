/*
 * Copyright 2014 Jung-Sang Ahn <jungsang.ahn@gmail.com>.
 * All Rights Reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>

#include "hbtrie.h"
#include "docio.h"
#include "btreeblock.h"
#include "forestdb.h"
#include "common.h"
#include "wal.h"
#include "rbwrap.h"
#include "list.h"

#include "memleak.h"

#ifdef __DEBUG
#ifndef __DEBUG_FDB
    #undef DBG
    #undef DBGCMD
    #undef DBGSW
    #define DBG(args...)
    #define DBGCMD(command...)
    #define DBGSW(n, command...)
#endif
#endif

struct iterator_wal_entry{
    void *key;
    wal_item_action action;
    uint16_t keylen;
    uint64_t offset;
    struct rb_node rb;
};

// lexicographically compares two variable-length binary streams
int _fdb_keycmp(void *key1, size_t keylen1, void *key2, size_t keylen2)
{
    if (keylen1 == keylen2) {
        return memcmp(key1, key2, keylen1);
    }else {
        size_t len = MIN(keylen1, keylen2);
        int cmp = memcmp(key1, key2, len);
        if (cmp != 0) return cmp;
        else {
            return (int)((int)keylen1 - (int)keylen2);
        }
    }
}

int _fdb_wal_rb_cmp(struct rb_node *a, struct rb_node *b, void *aux)
{
    struct iterator_wal_entry *aa, *bb;
    aa = _get_entry(a, struct iterator_wal_entry, rb);
    bb = _get_entry(b, struct iterator_wal_entry, rb);
    return _fdb_keycmp(aa->key, aa->keylen, bb->key, bb->keylen);
}

fdb_status fdb_iterator_init(fdb_handle *handle,
                             fdb_iterator *iterator,
                             void *start_key,
                             size_t start_keylen,
                             void *end_key,
                             size_t end_keylen,
                             fdb_iterator_opt_t opt)
{
    int cmp;
    hbtrie_result hr;
    struct list_elem *e;
    struct wal_item *wal_item;
    struct iterator_wal_entry *snap_item;

    if (handle == NULL || iterator == NULL) {
        return FDB_RESULT_INVALID_ARGS;
    }

    iterator->handle = *handle;
    iterator->hbtrie_iterator = (struct hbtrie_iterator *)malloc(sizeof(struct hbtrie_iterator));
    iterator->opt = opt;

    iterator->_key = (void*)malloc(FDB_MAX_KEYLEN);
    iterator->_keylen = 0;
    iterator->_offset = BLK_NOT_FOUND;

    if (start_key == NULL) start_keylen = 0;
    if (end_key == NULL) {
        iterator->end_key = NULL;
        end_keylen = 0;
    }else{
        iterator->end_key = (void*)malloc(end_keylen);
        memcpy(iterator->end_key, end_key, end_keylen);
    }
    iterator->end_keylen = end_keylen;

    // create an iterator handle for hb-trie
    hr = hbtrie_iterator_init(
        handle->trie, iterator->hbtrie_iterator, start_key, start_keylen);

    if (hr == HBTRIE_RESULT_FAIL)
        return FDB_RESULT_FAIL;

    // create a snapshot for WAL (rb-tree)
    // (from the beginning to the last committed element)

    // init rb-tree
    iterator->wal_rb = (struct rb_root*)malloc(sizeof(struct rb_root));
    rbwrap_init(iterator->wal_rb, NULL);

    spin_lock(&handle->file->wal->lock);
    e = list_begin(&handle->file->wal->list);
    while(e) {
        wal_item = _get_entry(e, struct wal_item, list_elem);
        if (start_key) {
            cmp = _fdb_keycmp(start_key, start_keylen,
                wal_item->key, wal_item->keylen);
        }else{
            cmp = 0;
        }

        if (cmp <= 0) {
            // copy from WAL_ITEM
            snap_item = (struct iterator_wal_entry*)malloc(sizeof(struct iterator_wal_entry));
            snap_item->keylen = wal_item->keylen;
            snap_item->key = (void*)malloc(snap_item->keylen);
            memcpy(snap_item->key, wal_item->key, snap_item->keylen);
            snap_item->action = wal_item->action;
            snap_item->offset = wal_item->offset;

            // insert into rb-tree
            rbwrap_insert(iterator->wal_rb, &snap_item->rb, _fdb_wal_rb_cmp);
        }

        if (e == handle->file->wal->last_commit) break;
        e = list_next(e);
    }
    iterator->rb_cursor = rb_first(iterator->wal_rb);

    spin_unlock(&handle->file->wal->lock);

    return FDB_RESULT_SUCCESS;
}

// DOC returned by this function must be freed using 'fdb_doc_free'
fdb_status fdb_iterator_next_offset(fdb_iterator *iterator,
                                    fdb_doc **doc,
                                    uint64_t *doc_offset_out)
{
    int cmp;
    void *key;
    size_t keylen;
    uint64_t offset;
    hbtrie_result hr;
    fdb_status fs;
    struct docio_object _doc;
    struct iterator_wal_entry *snap_item = NULL;

start:
    key = iterator->_key;

    // retrieve from hb-trie
    if (iterator->_offset == BLK_NOT_FOUND) {
        // no key waiting for being returned
        // get next key from hb-trie
        hr = hbtrie_next(
            iterator->hbtrie_iterator, key, &iterator->_keylen, &iterator->_offset);
        btreeblk_end(iterator->handle.bhandle);
    }
    keylen = iterator->_keylen;
    offset = iterator->_offset;

    if (hr == HBTRIE_RESULT_FAIL && iterator->rb_cursor == NULL) {
        return FDB_RESULT_FAIL;
    }

    while (iterator->rb_cursor) {
        // get the current item of rb-tree
        snap_item = _get_entry(iterator->rb_cursor, struct iterator_wal_entry, rb);
        if (hr != HBTRIE_RESULT_FAIL) {
            cmp = _fdb_keycmp(snap_item->key, snap_item->keylen, key, keylen);
        }else{
            // no more docs in hb-trie
            cmp = -1;
        }

        if (cmp <= 0) {
            // key[WAL] <= key[hb-trie] .. take key[WAL] first
            iterator->rb_cursor = rb_next(iterator->rb_cursor);

            if (cmp < 0) {
                if (snap_item->action == WAL_ACT_REMOVE) {
                    // this key is removed .. get next key[WAL]
                    continue;
                }
            }else{
                iterator->_offset = BLK_NOT_FOUND;
                if (snap_item->action == WAL_ACT_REMOVE) {
                    // the key is removed .. start over again
                    goto start;
                }
            }

            key = snap_item->key;
            keylen = snap_item->keylen;
            offset = snap_item->offset;
        }
        break;
    }

    if (offset == iterator->_offset) {
        // take key[hb-trie] & and fetch the next key[hb-trie] at next turn
        iterator->_offset = BLK_NOT_FOUND;
    }

    if (iterator->end_key) {
        cmp = _fdb_keycmp(iterator->end_key, iterator->end_keylen, key, keylen);
        if (cmp < 0) {
            // current key (KEY) is lexicographically greater than END_KEY
            // terminate the iteration
            return FDB_RESULT_FAIL;
        }
    }

    if (doc_offset_out) *doc_offset_out = offset;
    _doc.key = key;
    _doc.length.keylen = keylen;
    _doc.meta = NULL;
    _doc.body = NULL;
    if (iterator->opt == FDB_ITR_METAONLY) {
        docio_read_doc_key_meta(iterator->handle.dhandle, offset, &_doc);
    }else{
        docio_read_doc(iterator->handle.dhandle, offset, &_doc);
    }

    fs = fdb_doc_create(doc, key, keylen, NULL, 0, NULL, 0);
    if (fs == FDB_RESULT_FAIL) {
        return FDB_RESULT_INVALID_ARGS;
    }

    (*doc)->meta = _doc.meta;
    (*doc)->metalen = _doc.length.metalen;
    if (iterator->opt != FDB_ITR_METAONLY) {
        (*doc)->body = _doc.body;
        (*doc)->bodylen = _doc.length.bodylen;
    }

    return FDB_RESULT_SUCCESS;
}

fdb_status fdb_iterator_next(fdb_iterator *iterator, fdb_doc **doc)
{
    return fdb_iterator_next_offset(iterator, doc, NULL);
}

fdb_status fdb_iterator_close(fdb_iterator *iterator)
{
    hbtrie_result hr;
    struct rb_node *r;
    struct iterator_wal_entry *snap_item;

    hr = hbtrie_iterator_free(iterator->hbtrie_iterator);
    free(iterator->hbtrie_iterator);
    if (iterator->end_key)
        free(iterator->end_key);

    r = rb_first(iterator->wal_rb);
    while(r) {
        snap_item = _get_entry(r, struct iterator_wal_entry, rb);
        r = rb_next(r);
        rb_erase(&snap_item->rb, iterator->wal_rb);

        free(snap_item->key);
        free(snap_item);
    }

    free(iterator->wal_rb);
    free(iterator->_key);

    return FDB_RESULT_SUCCESS;
}

