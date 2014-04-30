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

#include "common.h"
#include "avltree.h"
#include "snapshot.h"

#include "memleak.h"

#ifdef __DEBUG
#ifndef __DEBUG_SNAP
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

// lexicographically compares two variable-length binary streams
int _snp_keycmp(void *key1, size_t keylen1, void *key2, size_t keylen2)
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

int _snp_seqnum_cmp(struct avl_node *a, struct avl_node *b, void *aux)
{
    struct snap_wal_entry *aa, *bb;
    aa = _get_entry(a, struct snap_wal_entry, avl_seq);
    bb = _get_entry(b, struct snap_wal_entry, avl_seq);
    return (aa->seqnum - bb->seqnum);
}

int _snp_wal_cmp(struct avl_node *a, struct avl_node *b, void *aux)
{
    fdb_handle *handle = (fdb_handle*)aux;
    struct snap_wal_entry *aa, *bb;
    aa = _get_entry(a, struct snap_wal_entry, avl);
    bb = _get_entry(b, struct snap_wal_entry, avl);

    if (handle->config.cmp_fixed) {
        // custom compare function for fixed-size key
        return handle->config.cmp_fixed(aa->key, bb->key);
    } else if (handle->config.cmp_variable) {
        // custom compare function for variable-length key
        return handle->config.cmp_variable(aa->key, aa->keylen,
                                           bb->key, bb->keylen);
    } else {
        return _snp_keycmp(aa->key, aa->keylen, bb->key, bb->keylen);
    }
}


wal_result snap_init(struct snap_handle *shandle, fdb_handle *handle)
{
    shandle->key_tree = (struct avl_tree *) malloc(sizeof(struct avl_tree));
    if (!shandle->key_tree) {
        return WAL_RESULT_FAIL;
    }
    avl_init(shandle->key_tree, (void *) handle);
    shandle->seq_tree = (struct avl_tree *) malloc(sizeof(struct avl_tree));
    if (!shandle->seq_tree) {
        return WAL_RESULT_FAIL;
    }
    avl_init(shandle->seq_tree, NULL);
    return WAL_RESULT_SUCCESS;
}

wal_result snap_insert(struct snap_handle *shandle, fdb_doc *doc,
                        uint64_t offset)
{
    struct snap_wal_entry query;
    struct snap_wal_entry *item;
    struct avl_node *node;
    memset(&query, 0, sizeof(snap_wal_entry));
    query.key = doc->key;
    query.keylen = doc->keylen;
    node = avl_search(shandle->key_tree, &query.avl, _snp_wal_cmp);

    if (!node) {
        item = (struct snap_wal_entry *) malloc(sizeof(struct snap_wal_entry));
        item->keylen = doc->keylen;
        item->key = doc->key;
        item->seqnum = doc->seqnum;
        item->action = (doc->bodylen > 0) ? WAL_ACT_INSERT :
                                            WAL_ACT_LOGICAL_REMOVE;
        item->offset = offset;
        avl_insert(shandle->key_tree, &item->avl, _snp_wal_cmp);
        avl_insert(shandle->seq_tree, &item->avl_seq, _snp_seqnum_cmp);
        return WAL_RESULT_SUCCESS;
    } else {
        // replace existing node with new values so there are no duplicates
        item = _get_entry(node, struct snap_wal_entry, avl);
        free(item->key);
        item->keylen = doc->keylen;
        item->key = doc->key;
        if (item->seqnum != doc->seqnum) { // Re-index duplicate into seqtree
            item->seqnum = doc->seqnum;
            avl_remove(shandle->seq_tree, &item->avl_seq);
            avl_insert(shandle->seq_tree, &item->avl_seq, _snp_seqnum_cmp);
        }
        item->action = (doc->bodylen > 0) ? WAL_ACT_INSERT :
                                            WAL_ACT_LOGICAL_REMOVE;
        item->offset = offset;
    }

    return WAL_RESULT_FAIL;
}

wal_result snap_find(struct snap_handle *shandle, fdb_doc *doc,
                      uint64_t *offset)
{
    struct snap_wal_entry query;
    struct avl_node *node;
    memset(&query, 0, sizeof(snap_wal_entry));
    if (doc->seqnum == SEQNUM_NOT_USED || (doc->key && doc->keylen > 0)) {
        if (!shandle->key_tree) {
            return WAL_RESULT_FAIL;
        }
        // search by key
        query.key = doc->key;
        query.keylen = doc->keylen;
        node = avl_search(shandle->key_tree, &query.avl, _snp_wal_cmp);
        if (!node) {
            return WAL_RESULT_FAIL;
        } else {
            struct snap_wal_entry *item;
            item = _get_entry(node, struct snap_wal_entry, avl);
            *offset = item->offset;
            if (item->action == WAL_ACT_INSERT) {
                doc->deleted = true;
            } else {
                doc->deleted = false;
            }
            return WAL_RESULT_SUCCESS;
        }
    } else {
        if (!shandle->seq_tree) {
            return WAL_RESULT_FAIL;
        }
        // search by sequence number
        query.seqnum = doc->seqnum;
        node = avl_search(shandle->seq_tree, &query.avl_seq, _snp_seqnum_cmp);
        if (!node) {
            return WAL_RESULT_FAIL;
        } else {
            struct snap_wal_entry *item;
            item = _get_entry(node, struct snap_wal_entry, avl_seq);
            *offset = item->offset;
            if (item->action == WAL_ACT_INSERT) {
                doc->deleted = true;
            } else {
                doc->deleted = false;
            }
            return WAL_RESULT_SUCCESS;
        }
    }
    return WAL_RESULT_FAIL;
}

wal_result snap_close(struct snap_handle *shandle)
{
    struct avl_node *a;
    struct snap_wal_entry *snap_item;

    if (shandle->key_tree) {
        a = avl_first(shandle->key_tree);
        while (a) {
            snap_item = _get_entry(a, struct snap_wal_entry, avl);
            a = avl_next(a);
            avl_remove(shandle->key_tree, &snap_item->avl);
            free(snap_item->key);
            free(snap_item);
        }
        free(shandle->key_tree);
        free(shandle->seq_tree);
    }
    return WAL_RESULT_SUCCESS;
}
