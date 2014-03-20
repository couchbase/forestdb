/* -*- Mode: C++; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * Simple Memory Leakage Detection Tool
 * (C) 2013  Jung-Sang Ahn <jungsang.ahn@gmail.com>
 * see https://github.com/greensky00/memleak
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#if !defined(__APPLE__)
#include <malloc.h>
#endif

#include "arch.h"

#define _MALLOC_OVERRIDE
#define INIT_VAL (0xff)
#define FREE_VAL (0x11)
//#define _WARN_NOT_ALLOCATED_MEMORY
//#define _PRINT_DBG

#ifdef _PRINT_DBG
    #define DBG(args...) fprintf(stderr, args)
#else
    #define DBG(args...)
#endif

#include "avltree.h"

struct memleak_item {
    uint64_t addr;
    char *file;
    size_t size;
    size_t line;
    struct avl_node avl;
};

static struct avl_tree tree_index;
static uint8_t start_sw = 0;
static spin_t lock;

int memleak_cmp(struct avl_node *a, struct avl_node *b, void *aux)
{
    struct memleak_item *aa, *bb;
    aa = _get_entry(a, struct memleak_item, avl);
    bb = _get_entry(b, struct memleak_item, avl);
    if (aa->addr < bb->addr) return -1;
    else if (aa->addr > bb->addr) return 1;
    else return 0;
}

void memleak_start()
{
    spin_init(&lock);
    avl_init(&tree_index, NULL);
    start_sw = 1;
}

void memleak_end()
{
    size_t count = 0;
    struct avl_node *a;
    struct memleak_item *item;

    spin_lock(&lock);

    start_sw = 0;

    a = avl_first(&tree_index);
    while(a){
        item = _get_entry(a, struct memleak_item, avl);
        a = avl_next(a);
        avl_remove(&tree_index, &item->avl);

        fprintf(stderr, "address 0x%016lx (allocated at %s:%lu, size %lu) is not freed\n",
            (unsigned long)item->addr, item->file, item->line, item->size);
        free(item);
        count++;
    }
    if (count > 0) fprintf(stderr, "total %d objects\n", (int)count);

    spin_unlock(&lock);
}

void _memleak_add_to_index(void *addr, size_t size, char *file, size_t line, uint8_t init_val)
{
    DBG("malloc at %s:%ld, size %ld\n", file, line, size);
    struct memleak_item *item = (struct memleak_item *)malloc(sizeof(struct memleak_item));
    item->addr = (uint64_t)addr;
    item->file = file;
    item->line = line;
    item->size = size;
#ifdef INIT_VAL
    memset(addr, init_val, size);
#endif
    avl_insert(&tree_index, &item->avl, memleak_cmp);
}

void * memleak_alloc(size_t size, char *file, size_t line)
{
    spin_lock(&lock);

    void *addr = malloc(size);
    if (addr && start_sw) {
        _memleak_add_to_index(addr, size, file, line, INIT_VAL);
    }

    spin_unlock(&lock);
    return addr;
}

void * memleak_calloc(size_t nmemb, size_t size, char *file, size_t line)
{
    spin_lock(&lock);

    void *addr = calloc(nmemb, size);
    if (addr && start_sw) {
        _memleak_add_to_index(addr, size, file, line, 0x0);
    }

    spin_unlock(&lock);
    return addr;
}

#ifndef WIN32
// posix only
int memleak_posix_memalign(void **memptr, size_t alignment, size_t size, char *file, size_t line)
{
    spin_lock(&lock);

    int ret = posix_memalign(memptr, alignment, size);
    if (ret==0 && start_sw)
    {
        _memleak_add_to_index(*memptr, size, file, line, INIT_VAL);
    }

    spin_unlock(&lock);
    return ret;
}
#endif

void *memleak_realloc(void *ptr, size_t size)
{
    spin_lock(&lock);

    void *addr = realloc(ptr, size);
    if (addr && start_sw) {
        struct avl_node *a;
        struct memleak_item *item, query;

        query.addr = (uint64_t)ptr;
        a = avl_search(&tree_index, &query.avl, memleak_cmp);
        if (a) {
            item = _get_entry(a, struct memleak_item, avl);
            DBG("realloc from address 0x%016lx (allocated at %s:%ld, size %ld)\n\tto address 0x%016lx (size %ld)\n",
                item->addr, item->file, item->line, item->size, (uint64_t)addr, size);
            avl_remove(&tree_index, a);
            _memleak_add_to_index(addr, size, item->file, item->line, INIT_VAL);
            free(item);
        }
    }

    spin_unlock(&lock);
    return addr;
}

void memleak_free(void *addr, char *file, size_t line)
{
    struct avl_node *a;
    struct memleak_item *item, query;
    spin_lock(&lock);

    if (start_sw) {

        query.addr = (uint64_t)addr;
        a = avl_search(&tree_index, &query.avl, memleak_cmp);
        if (!a) {
#ifdef _WARN_NOT_ALLOCATED_MEMORY
            fprintf(stderr, "try to free not allocated memory address 0x%016lx at %s:%ld\n",
                (long unsigned int)addr, file, line);
#endif
            spin_unlock(&lock);
            return;
        }

        item = _get_entry(a, struct memleak_item, avl);
        DBG("free address 0x%016lx (allocated at %s:%ld, size %ld)\n",
            item->addr, item->file, item->line, item->size);
#ifdef FREE_VAL
        memset(addr, FREE_VAL, item->size);
#endif

        avl_remove(&tree_index, a);
        free(item);
    }
    free(addr);

    spin_unlock(&lock);
}

