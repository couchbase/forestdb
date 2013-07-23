/*
 * Copyright 2013 Jung-Sang Ahn <jungsang.ahn@gmail.com>.
 * All Rights Reserved.
 */

#ifndef _JSAHN_HASH_H
#define _JSAHN_HASH_H

#include <stdint.h>
#include "list.h"

#define _HASH_LOCK
#ifdef _HASH_LOCK

#ifdef __APPLE__

	#ifndef spin_t
	// spinlock
	#include <libkern/OSAtomic.h>
	#define spin_t OSSpinLock
	#define spin_lock(arg) OSSpinLockLock(arg)
	#define spin_unlock(arg) OSSpinLockUnlock(arg)
	#define SPIN_INITIALIZER 0
	#endif
	
#elif __linux

	#ifndef spin_t
	// spinlock
	#include <pthread.h>
	#define spin_t pthread_spinlock_t
	#define spin_lock(arg) pthread_spin_lock(arg)
	#define spin_unlock(arg) pthread_spin_unlock(arg)
	#define SPIN_INITIALIZER 1
	#endif
	
#else
	#define INLINE make_error
#endif

#endif

struct hash_elem {
	struct list_elem list_elem;
};

struct hash;

typedef uint32_t hash_hash_func(struct hash *hash, struct hash_elem *e);
typedef int hash_cmp_func(struct hash_elem *a, struct hash_elem *b);
typedef void hash_free_func(struct hash_elem *e);

struct hash {
	size_t nbuckets;
	struct list *buckets;
	
	hash_hash_func *hash;
	hash_cmp_func *cmp;

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
