/* -*- Mode: C++; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * Hash Table
 * (C) 2013  Jung-Sang Ahn <jungsang.ahn@gmail.com>
 */

#ifndef _JSAHN_HASH_H
#define _JSAHN_HASH_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define _HASH_TREE
#ifdef _HASH_TREE
    #include "avltree.h"
#else
    #include "list.h"
#endif

//#define _HASH_LOCK
#ifdef _HASH_LOCK
    #include "arch.h"
#endif

struct hash_elem {
#ifdef _HASH_TREE
    struct avl_node avl;
#else
    struct list_elem list_elem;
#endif
};

struct hash;

typedef uint32_t hash_hash_func(struct hash *hash, struct hash_elem *e);
typedef int hash_cmp_func(struct hash_elem *a, struct hash_elem *b);
//typedef int hash_cmp_func(void *a, void *b);
typedef void hash_free_func(struct hash_elem *e);
typedef void *hash_check_func(struct hash_elem *e, void *ctx);

struct hash {
    size_t nbuckets;
#ifdef _HASH_TREE
    struct avl_tree *buckets;
#else
    struct list *buckets;
#endif

    hash_hash_func *hash_func;
    hash_cmp_func *cmp;
#ifdef _HASH_TREE
    avl_cmp_func *avl_cmp;
#endif

#ifdef _HASH_LOCK
    // define locks for each bucket
    spin_t *locks;
#endif
};

void hash_init(struct hash *hash, int nbuckets, hash_hash_func *hash_func, hash_cmp_func *cmp_func);
void hash_insert(struct hash *hash, struct hash_elem *e);
void hash_insert_by_hash_val(struct hash *hash, struct hash_elem *e, uint32_t hash_val);
struct hash_elem * hash_find(struct hash *hash, struct hash_elem *e);
struct hash_elem * hash_find_by_hash_val(struct hash *hash, struct hash_elem *e,
                                         uint32_t hash_val);
void *hash_scan(struct hash *hash, hash_check_func *check_func, void *ctx);
struct hash_elem * hash_remove(struct hash *hash, struct hash_elem *e);
void hash_free(struct hash *hash);
void hash_free_active(struct hash *hash, hash_free_func *free_func);

#ifdef __cplusplus
}
#endif

#endif
