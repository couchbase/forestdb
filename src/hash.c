/*
 * Copyright 2013 Jung-Sang Ahn <jungsang.ahn@gmail.com>.
 * All Rights Reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include "hash.h"

#ifdef _HASH_LOCK
	#define IFDEF_LOCK(command...) command
#else
	#define IFDEF_LOCK(command...) 
#endif

void hash_init(struct hash *hash, int nbuckets, hash_hash_func *hash_func, hash_cmp_func *cmp_func)
{
	int i;
	hash->nbuckets = nbuckets;
	hash->buckets = (struct list *)malloc(sizeof(struct list) * hash->nbuckets);

	IFDEF_LOCK( hash->locks = (spin_t*)malloc(sizeof(spin_t) * hash->nbuckets) );

	for (i=0;i<hash->nbuckets;++i){
		list_init(hash->buckets + i);
		
		IFDEF_LOCK( *(hash->locks + i) = SPIN_INITIALIZER );
	}	
	hash->hash = hash_func;
	hash->cmp = cmp_func;
}

void hash_insert(struct hash *hash, struct hash_elem *e)
{
	int bucket = hash->hash(hash, e);
	
	IFDEF_LOCK( spin_lock(hash->locks + bucket) );

	list_push_back(hash->buckets + bucket, &e->list_elem);

	IFDEF_LOCK( spin_unlock(hash->locks + bucket) );
}

struct hash_elem * hash_find(struct hash *hash, struct hash_elem *e)
{
	int bucket = hash->hash(hash, e);
	struct list_elem *list_elem;
	struct hash_elem *hash_elem;

	IFDEF_LOCK( spin_lock(hash->locks + bucket) );
	
	list_elem = list_begin(hash->buckets + bucket);
	while(list_elem) {
		hash_elem = _get_entry(list_elem, struct hash_elem, list_elem);
		if (!hash->cmp(e, hash_elem)) {
			IFDEF_LOCK( spin_unlock(hash->locks + bucket) );
			
			return hash_elem;
		}
		list_elem = list_next(list_elem);
	}
	
	IFDEF_LOCK( spin_unlock(hash->locks + bucket) );

	return NULL;
}

struct hash_elem * hash_remove(struct hash *hash, struct hash_elem *e)
{
	int bucket = hash->hash(hash, e);
	struct list_elem *list_elem;
	struct hash_elem *hash_elem;

	IFDEF_LOCK( spin_lock(hash->locks + bucket) );

	list_elem = list_begin(hash->buckets + bucket);
	while(list_elem) {
		hash_elem = _get_entry(list_elem, struct hash_elem, list_elem);
		if (!hash->cmp(e, hash_elem)) {
			list_remove(hash->buckets + bucket, list_elem);

			IFDEF_LOCK( spin_unlock(hash->locks + bucket) );
			
			return hash_elem;
		}
		list_elem = list_next(list_elem);
	}
	
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
	struct list_elem *e, *e_next;
	struct hash_elem *h;
	
	for (i=0;i<hash->nbuckets;++i){
		e = list_begin(hash->buckets + i);
		while(e) {
			e_next = list_remove(hash->buckets + i, e);
			h = _get_entry(e, struct hash_elem, list_elem);
			free_func(h);
			e = e_next;
		}
	}

	hash_free(hash);
}

