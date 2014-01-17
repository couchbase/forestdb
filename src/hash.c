/*
 * Copyright 2013 Jung-Sang Ahn <jungsang.ahn@gmail.com>.
 * All Rights Reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include "hash.h"
#include "memleak.h"

#ifdef _HASH_LOCK
    #define IFDEF_LOCK(command...) command
#else
    #define IFDEF_LOCK(command...)
#endif

#ifdef _HASH_RBTREE
int _hash_cmp_rbwrap(struct rb_node *a, struct rb_node *b, void *aux)
{
/*
    struct hash *hash = (struct hash *)aux;
    struct hash_elem *aa, *bb;
    aa = _get_entry(a, struct hash_elem, rb_node);
    bb = _get_entry(b, struct hash_elem, rb_node);
    return hash->cmp(aa, bb);*/
    return ((struct hash *)aux)->cmp(
        _get_entry(a, struct hash_elem, rb_node),
        _get_entry(b, struct hash_elem, rb_node));
}
#endif

void hash_init(struct hash *hash, int nbuckets, hash_hash_func *hash_func, hash_cmp_func *cmp_func)
{
    int i;
    hash->nbuckets = nbuckets;
    #ifdef _HASH_RBTREE
        hash->buckets = (struct rb_root *)malloc(sizeof(struct rb_root) * hash->nbuckets);
    #else
        hash->buckets = (struct list *)malloc(sizeof(struct list) * hash->nbuckets);
    #endif

    IFDEF_LOCK( hash->locks = (spin_t*)malloc(sizeof(spin_t) * hash->nbuckets) );

    for (i=0;i<hash->nbuckets;++i){
        #ifdef _HASH_RBTREE
            rbwrap_init(hash->buckets + i, (void *)hash);
        #else
            list_init(hash->buckets + i);
        #endif

        IFDEF_LOCK( *(hash->locks + i) = SPIN_INITIALIZER );
    }
    hash->hash = hash_func;
    hash->cmp = cmp_func;
}

void hash_insert(struct hash *hash, struct hash_elem *e)
{
    int bucket = hash->hash(hash, e);

    IFDEF_LOCK( spin_lock(hash->locks + bucket) );

    #ifdef _HASH_RBTREE
        rbwrap_insert(hash->buckets + bucket, &e->rb_node, _hash_cmp_rbwrap);
    #else
        list_push_back(hash->buckets + bucket, &e->list_elem);
    #endif

    IFDEF_LOCK( spin_unlock(hash->locks + bucket) );
}

struct hash_elem * hash_find(struct hash *ht, struct hash_elem *e)
{
    int bucket = ht->hash(ht, e);
    struct hash_elem *elem = NULL;

    IFDEF_LOCK( spin_lock(ht->locks + bucket) );

#ifdef _HASH_RBTREE
    struct rb_node *rb;
    rb = rbwrap_search(ht->buckets + bucket, &e->rb_node, _hash_cmp_rbwrap);
    if (rb) {
        IFDEF_LOCK( spin_unlock(ht->locks + bucket) );
        elem = _get_entry(rb, struct hash_elem, rb_node);
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
    int bucket = hash->hash(hash, e);
    struct hash_elem *hash_elem;

    IFDEF_LOCK( spin_lock(hash->locks + bucket) );

    #ifdef _HASH_RBTREE
        struct rb_node *rb;
        rb = rbwrap_search(hash->buckets + bucket, &e->rb_node, _hash_cmp_rbwrap);
        if (rb) {
            rb_erase(rb, hash->buckets + bucket);
            IFDEF_LOCK( spin_unlock(hash->locks + bucket) );
            hash_elem = _get_entry(rb, struct hash_elem, rb_node);
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

    #ifdef _HASH_RBTREE
        struct rb_node *r, *r_next;;
    #else
        struct list_elem *e, *e_next;
    #endif

    struct hash_elem *h;

    for (i=0;i<hash->nbuckets;++i){
        #ifdef _HASH_RBTREE
            r = rb_first(hash->buckets + i);
            while(r){
                h = _get_entry(r, struct hash_elem, rb_node);
                r = rb_next(r);
                rb_erase(&h->rb_node, hash->buckets + i);
                free_func(h);
                //r = rb_first(hash->buckets + i);
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

