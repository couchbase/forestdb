#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "mempool.h"
#include "list.h"

#ifdef __DEBUG
	#include <stdio.h>
	#define DBG(args...) fprintf(stderr, args)
	#define DBGCMD(command...) command
#else
	#define DBG(args...)
	#define DBGCMD(command...)
#endif

//#define __DEBUG_MEMPOOL
#ifdef __DEBUG
#ifndef __DEBUG_MEMPOOL
	#undef DBG
	#undef DBGCMD
	#define DBG(args...)
	#define DBGCMD(command...)
#endif
#endif


#ifdef __APPLE__
	#define INLINE extern inline

	#define _F64 "lld"
	#define _FSEC "ld"
	#define _FUSEC "d"

	#ifndef spin_t
	// spinlock
	#include <libkern/OSAtomic.h>
	#define spin_t OSSpinLock
	#define spin_lock(arg) OSSpinLockLock(arg)
	#define spin_unlock(arg) OSSpinLockUnlock(arg)
	#define SPIN_INITIALIZER 0
	#endif
	
#elif __linux
	#define INLINE __inline

	#define _F64 "ld"
	#define _FSEC "ld"
	#define _FUSEC "ld"

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

#define N_LISTS (1)
#define N_INIT_ITEMS (128)
#define SPACE_LIMIT_FOR_LIST (8*1024*1024)
#define MINSIZE (32)
#define SIZE_THRES1 (128)
#define SIZE_THRES2 (512)
#define MAXSIZE (4096)

#define CHK_POW2(v) (!((uint64_t)v & ((uint64_t)v - 0x1)))

#define random_custom(prev, num) (prev) = ((prev)+811)&((num)-1)

#ifndef _get_entry
#define _get_entry(ELEM, STRUCT, MEMBER) \
	((STRUCT *) ((uint8_t *) (ELEM) - offsetof (STRUCT, MEMBER)))
#endif

static spin_t initial_lock = SPIN_INITIALIZER;
static int mempool_initialized = 0;
static int l1cache_linesize;

struct mempool_list_set {
	struct list list;
	spin_t lock;
};

struct mempool_item {
	struct mempool_list_set *listset;
	struct list_elem le;
	//void *dummy[5];	// for cache align
};

struct mempool_bucket {
	struct mempool_list_set listset[N_LISTS];
	uint32_t size;
	uint32_t rvalue;
};

struct mempool_bucket bucket[10];
struct mempool_bucket *bucketmap[MAXSIZE+1];

void mempool_init()
{
	if (!mempool_initialized) {

		spin_lock(&initial_lock);

		if (mempool_initialized) {
			spin_unlock(&initial_lock);
			return;
		}

		int i, j, k, c, n, ret;
		struct mempool_item *item;

		l1cache_linesize = 64; //sysconf(_SC_LEVEL1_DCACHE_LINESIZE);
		DBG("L1 dcache linesize %d\n", l1cache_linesize);

		c=0;
		for (i=MINSIZE; i<=MAXSIZE; i*=2) {
			bucket[c].rvalue = 0;
			bucket[c].size = i;

			n = SPACE_LIMIT_FOR_LIST / (N_LISTS * bucket[c].size);
			if (bucket[c].size < SIZE_THRES1) n = n * 8;
			else n = n / 8;
			
			DBG("size %d n %d\n", bucket[c].size, n);
			
			for (j=0;j<N_LISTS;++j){
				list_init(&bucket[c].listset[j].list);
				bucket[c].listset[j].lock = SPIN_INITIALIZER;
				
				for (k=0;k<n;++k){
					item = (struct mempool_item *)malloc(sizeof(struct mempool_item) + bucket[c].size);
					/*
					ret = posix_memalign(
						(void **)&item, l1cache_linesize, sizeof(struct mempool_item) + bucket[c].size);*/
					item->listset = &bucket[c].listset[j];

					list_push_front(&item->listset->list, &item->le);
				}
			}
			c++;
		}

		c = 0;
		for (i=0;i<=MAXSIZE;++i){
			if (i > bucket[c].size) c++;
			bucketmap[i] = &bucket[c];
		}

		DBG("memory pool initialized, item size %d\n", (int)sizeof(struct mempool_item));

		mempool_initialized = 1;
		spin_unlock(&initial_lock);
	}
}

void * mempool_alloc(size_t size)
{
	int ret;
	struct list_elem *e;
	struct mempool_bucket *b;
	struct mempool_item *item;
	uint32_t idx; 

	b = bucketmap[size];
	idx = b->rvalue;
	b->rvalue = random_custom(b->rvalue, N_LISTS);
	
	spin_lock(&b->listset[idx].lock);
	e = list_pop_front(&b->listset[idx].list);
	spin_unlock(&b->listset[idx].lock);

	if (e){
		item = _get_entry(e, struct mempool_item, le);
		//DBG("mem pool hit from list %lx size %d\n", (uint64_t)item->listset, b->size);
	}else{
		item = (struct mempool_item *)malloc(sizeof(struct mempool_item) + b->size);
		//ret = posix_memalign((void **)&item, l1cache_linesize, sizeof(struct mempool_item) + b->size);
		item->listset = &b->listset[idx];		
		//DBG("mem pool miss, created at list %lx size %d\n", (uint64_t)item->listset, b->size);
	}
		
	return (void *)((uint8_t *)item + sizeof(struct mempool_item));
}

void mempool_free(void *addr)
{
	struct mempool_item *item;
	item = (struct mempool_item *)((uint8_t*)addr - sizeof(struct mempool_item));

	spin_lock(&item->listset->lock);
	list_push_front(&item->listset->list, &item->le);
	spin_unlock(&item->listset->lock);

	//DBG("free and return at list %lx\n", (uint64_t)item->listset);
}


