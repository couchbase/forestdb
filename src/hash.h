/*
 * Copyright 2013 Jung-Sang Ahn <jungsang.ahn@gmail.com>.
 * All Rights Reserved.
 */

#ifndef _JSAHN_HASH_H
#define _JSAHN_HASH_H

#include <stdint.h>
#define _HASH_RBTREE

#ifdef _HASH_RBTREE
    #include "rbwrap.h"
#else
    #include "list.h"
#endif

//#define _HASH_LOCK
#ifdef _HASH_LOCK
    #include "arch.h"
#endif

struct hash_elem {
    #ifdef _HASH_RBTREE
        struct rb_node rb_node;
    #else
        struct list_elem list_elem;
    #endif
};

struct hash;

typedef uint32_t hash_hash_func(struct hash *hash, struct hash_elem *e);
typedef int hash_cmp_func(struct hash_elem *a, struct hash_elem *b);
//typedef int hash_cmp_func(void *a, void *b);
typedef void hash_free_func(struct hash_elem *e);

struct hash {
    size_t nbuckets;
    #ifdef _HASH_RBTREE
        struct rb_root *buckets;
    #else
        struct list *buckets;
    #endif
    
    hash_hash_func *hash;
    hash_cmp_func *cmp;
    #ifdef _HASH_RBTREE
        rbwrap_cmp_func *rb_cmp;
    #endif

#ifdef _HASH_LOCK
    // define locks for each bucket
    spin_t *locks;
#endif
};

void hash_init(struct hash *hash, int nbuckets, hash_hash_func *hash_func, hash_cmp_func *cmp_func);
void hash_insert(struct hash *hash, struct hash_elem *e);
struct hash_elem * hash_find(struct hash *hash, struct hash_elem *e);
struct hash_elem * hash_remove(struct hash *hash, struct hash_elem *e);
void hash_free(struct hash *hash);
void hash_free_active(struct hash *hash, hash_free_func *free_func);

#endif
