/* -*- Mode: C++; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * Hash Table
 * (C) 2013  Jung-Sang Ahn <jungsang.ahn@gmail.com>
 */

#include <stdio.h>
#include <stdlib.h>
#include "hash.h"
#include "memleak.h"

#ifdef _HASH_LOCK
    #define IFDEF_LOCK(...) __VA_ARGS__
#else
    #define IFDEF_LOCK(...)
#endif

#ifdef _HASH_TREE
int _hash_cmp_wrap(struct avl_node *a, struct avl_node *b, void *aux)
{
    return ((struct hash *)aux)->cmp(
        _get_entry(a, struct hash_elem, avl),
        _get_entry(b, struct hash_elem, avl));
}
#endif

void hash_init(struct hash *hash, int nbuckets, hash_hash_func *hash_func, hash_cmp_func *cmp_func)
{
    int i;
    hash->nbuckets = nbuckets;
#ifdef _HASH_TREE
    hash->buckets = (struct avl_tree *)malloc(sizeof(struct avl_tree) * hash->nbuckets);
#else
    hash->buckets = (struct list *)malloc(sizeof(struct list) * hash->nbuckets);
#endif

    IFDEF_LOCK( hash->locks = (spin_t*)malloc(sizeof(spin_t) * hash->nbuckets) );

    for (i=0;i<hash->nbuckets;++i){
#ifdef _HASH_TREE
        avl_init(hash->buckets + i, (void *)hash);
#else
        list_init(hash->buckets + i);
#endif

        IFDEF_LOCK( spin_init(hash->locks + i); );
    }

    hash->hash_func = hash_func;
    hash->cmp = cmp_func;
}

void hash_insert(struct hash *hash, struct hash_elem *e)
{
    int bucket = hash->hash_func(hash, e);

    IFDEF_LOCK( spin_lock(hash->locks + bucket) );

#ifdef _HASH_TREE
    avl_insert(hash->buckets + bucket, &e->avl, _hash_cmp_wrap);
#else
    list_push_back(hash->buckets + bucket, &e->list_elem);
#endif

    IFDEF_LOCK( spin_unlock(hash->locks + bucket) );
}

struct hash_elem * hash_find(struct hash *ht, struct hash_elem *e)
{
    int bucket = ht->hash_func(ht, e);
    struct hash_elem *elem = NULL;

    IFDEF_LOCK( spin_lock(ht->locks + bucket) );

#ifdef _HASH_TREE
    struct avl_node *node;
    node = avl_search(ht->buckets + bucket, &e->avl, _hash_cmp_wrap);
    if (node) {
        IFDEF_LOCK( spin_unlock(ht->locks + bucket) );
        elem = _get_entry(node, struct hash_elem, avl);
        return elem;
    }
#else
    struct list_elem *le = list_begin(ht->buckets + bucket);
    while(le) {
        elem = _get_entry(le, struct hash_elem, list_elem);
        if (!ht->cmp(e, elem)) {
            IFDEF_LOCK( spin_unlock(ht->locks + bucket) );
            return elem;
        }
        le = list_next(le);
    }
#endif

    IFDEF_LOCK( spin_unlock(ht->locks + bucket) );
    return NULL;
}

struct hash_elem * hash_remove(struct hash *hash, struct hash_elem *e)
{
    int bucket = hash->hash_func(hash, e);
    struct hash_elem *hash_elem;

    IFDEF_LOCK( spin_lock(hash->locks + bucket) );

#ifdef _HASH_TREE
    struct avl_node *node;
    node = avl_search(hash->buckets + bucket, &e->avl, _hash_cmp_wrap);
    if (node) {
        avl_remove(hash->buckets + bucket, node);
        IFDEF_LOCK( spin_unlock(hash->locks + bucket) );
        hash_elem = _get_entry(node, struct hash_elem, avl);
        return hash_elem;
    }

#else
    struct list_elem *le;
    le = list_begin(hash->buckets + bucket);
    while(le) {
        hash_elem = _get_entry(le, struct hash_elem, list_elem);
        if (!hash->cmp(e, hash_elem)) {
            list_remove(hash->buckets + bucket, le);

            IFDEF_LOCK( spin_unlock(hash->locks + bucket) );

            return hash_elem;
        }
        le = list_next(le);
    }
#endif

    IFDEF_LOCK( spin_unlock(hash->locks + bucket) );

    return NULL;
}

void hash_free(struct hash *hash)
{
    free(hash->buckets);
    IFDEF_LOCK( free((void *)hash->locks) );
}

void hash_free_active(struct hash *hash, hash_free_func *free_func)
{
    int i;

#ifdef _HASH_TREE
    struct avl_node *node;
#else
    struct list_elem *e, *e_next;
#endif

    struct hash_elem *h;

    for (i=0;i<hash->nbuckets;++i){
#ifdef _HASH_TREE
        node = avl_first(hash->buckets + i);
        while(node){
            h = _get_entry(node, struct hash_elem, avl);
            node = avl_next(node);
            avl_remove(hash->buckets + i, &h->avl);
            free_func(h);
        }

#else
        e = list_begin(hash->buckets + i);
        while(e) {
            e_next = list_remove(hash->buckets + i, e);
            h = _get_entry(e, struct hash_elem, list_elem);
            free_func(h);
            e = e_next;
        }

#endif
    }

    hash_free(hash);
}

