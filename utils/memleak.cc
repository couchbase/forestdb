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
#if !defined(__APPLE__)
#include <malloc.h>
#endif

#include "arch.h"

#define _MALLOC_OVERRIDE
#define INIT_VAL (0x77)
#define FREE_VAL (0xff)
//#define _WARN_NOT_ALLOCATED_MEMORY
//#define _PRINT_DBG
#if !defined(_WIN32) && !defined(WIN32)
//#define _STACK_BACKTRACE
//#define _LIBBFD
#endif

#include "memleak.h"

#ifdef _STACK_BACKTRACE
#include <execinfo.h>

#ifdef _LIBBFD
#include <dlfcn.h>
#include <signal.h>
#include <bfd.h>
#include <unistd.h>

/* globals retained across calls to resolve. */
static bfd* abfd = 0;
static asymbol **syms = 0;
static asection *text = 0;

static void resolve(void *address, char **file, char **func, unsigned *line) {
    if (!abfd) {
        char ename[1024];
        int l = readlink("/proc/self/exe",ename,sizeof(ename));
        if (l == -1) {
            perror("failed to find executable\n");
            return;
        }
        ename[l] = 0;

        bfd_init();

        abfd = bfd_openr(ename, 0);
        if (!abfd) {
            perror("bfd_openr failed: ");
            return;
        }

        bfd_check_format(abfd,bfd_object);

        unsigned storage_needed = bfd_get_symtab_upper_bound(abfd);
        syms = (asymbol **) malloc(storage_needed);
        unsigned cSymbols = bfd_canonicalize_symtab(abfd, syms);

        text = bfd_get_section_by_name(abfd, ".text");
    }

    long offset = ((long)address) - text->vma;
    if (offset > 0) {
        bfd_find_nearest_line(abfd, text, syms, offset,
            (const char**)file, (const char**)func, line);
    }
}

#endif  // _LIBBFD

#endif  // _STACK_BACKTRACE


#ifdef _PRINT_DBG
    #define DBG(...) fprintf(stderr, __VA_ARGS__)
#else
    #define DBG(...)
#endif

#include "avltree.h"

struct memleak_item {
    uint64_t addr;
    char *file;
    size_t size;
    size_t line;
    struct avl_node avl;
#ifdef _STACK_BACKTRACE
    size_t bt_size;
    void **btrace;
#endif
#ifdef _CHK_MODIFY_AFTER_FREE
    uint8_t freed;
#endif
};

static struct avl_tree tree_index;
static uint8_t start_sw = 0;
static spin_t lock;

// LCOV_EXCL_START
int memleak_cmp(struct avl_node *a, struct avl_node *b, void *aux)
{
    struct memleak_item *aa, *bb;
    aa = _get_entry(a, struct memleak_item, avl);
    bb = _get_entry(b, struct memleak_item, avl);
    if (aa->addr < bb->addr) return -1;
    else if (aa->addr > bb->addr) return 1;
    else return 0;
}
// LCOV_EXCL_STOP

LIBMEMLEAK_API
void memleak_start()
{
    spin_init(&lock);
    avl_init(&tree_index, NULL);
    start_sw = 1;
}

LIBMEMLEAK_API
void memleak_end()
{
    uint8_t is_leaked;
    size_t count = 0;
    struct avl_node *a;
    struct memleak_item *item;
#ifdef _STACK_BACKTRACE
    int i;
    char **strs;
    char *file, *func;
    unsigned line;
#endif

    spin_lock(&lock);

    start_sw = 0;

    a = avl_first(&tree_index);
    while(a){
        item = _get_entry(a, struct memleak_item, avl);
        a = avl_next(a);
        avl_remove(&tree_index, &item->avl);
        is_leaked = 1;

#ifdef _CHK_MODIFY_AFTER_FREE
        int i;
        uint8_t *addr;
        if (item->freed) {
            is_leaked = 0;
            addr = (uint8_t*)item->addr;
            for (i=0;i<item->size;++i){
                if (*(addr + i) != FREE_VAL) {
                    fprintf(stderr,
                            "address 0x%016lx (allocated at %s:%lu, size %lu) "
                            "has been modified after being freed\n",
                            (unsigned long)item->addr, item->file,
                            item->line, item->size);
                    break;
                }
            }
            free(addr);
        }
#endif // _CHK_MODIFY_AFTER_FREE

        if (is_leaked) {
            fprintf(stderr, "address 0x%016lx (allocated at %s:%lu, size %lu) "
                            "is not freed\n",
                    (unsigned long)item->addr, item->file,
                    (unsigned long)item->line, (unsigned long)item->size);
            count++;
#ifdef _STACK_BACKTRACE
            strs = backtrace_symbols(item->btrace, item->bt_size);
            for (i=0;i<item->bt_size;++i){
#ifdef _LIBBFD
                resolve(item->btrace[i], &file, &func, &line);
                fprintf(stderr, "    %s [%s:%d]\n", func, file, line);
#else // _LIBBFD
                fprintf(stderr, "    %s\n", strs[i]);
#endif // _LIBBFD
            }
            free(item->btrace);
#endif // _STACK_BACKTRACE
        }
        free(item);
    }
    if (count > 0) fprintf(stderr, "total %d objects\n", (int)count);

    spin_unlock(&lock);
}

// LCOV_EXCL_START
void _memleak_add_to_index(void *addr, size_t size, char *file, size_t line, uint8_t init_val)
{
    DBG("malloc at %s:%ld, size %ld\n", file, line, size);
    struct memleak_item *item = (struct memleak_item *)malloc(sizeof(struct memleak_item));
    item->addr = (uint64_t)addr;
    item->file = file;
    item->line = line;
    item->size = size;
#ifdef INIT_VAL
    if (init_val == INIT_VAL) {
        memset(addr, init_val, size);
    }
#endif
#ifdef _STACK_BACKTRACE
    void *temp_stack[256];
    item->bt_size = backtrace(temp_stack, 256);
    item->btrace = (void**)malloc(sizeof(void*) * item->bt_size);
    memcpy(item->btrace, temp_stack, sizeof(void*) * item->bt_size);
#endif
#ifdef _CHK_MODIFY_AFTER_FREE
    item->freed = 0;
#endif
    avl_insert(&tree_index, &item->avl, memleak_cmp);
}
// LCOV_EXCL_STOP

// LCOV_EXCL_START
LIBMEMLEAK_API
void * memleak_alloc(size_t size, char *file, size_t line)
{
    void *addr = (void*)malloc(size);
    if (addr && start_sw) {
        spin_lock(&lock);
        _memleak_add_to_index(addr, size, file, line, INIT_VAL);
        spin_unlock(&lock);
    }

    return addr;
}
// LCOV_EXCL_STOP

// LCOV_EXCL_START
LIBMEMLEAK_API
void * memleak_calloc(size_t nmemb, size_t size, char *file, size_t line)
{
    void *addr = (void *)calloc(nmemb, size);
    if (addr && start_sw) {
        spin_lock(&lock);
        _memleak_add_to_index(addr, size, file, line, 0x0);
        spin_unlock(&lock);
    }

    return addr;
}
// LCOV_EXCL_STOP

#if !defined(WIN32)

#if !defined(__ANDROID__)
// posix only
// LCOV_EXCL_START
LIBMEMLEAK_API
int memleak_posix_memalign(void **memptr, size_t alignment, size_t size, char *file, size_t line)
{

    int ret = posix_memalign(memptr, alignment, size);
    if (ret==0 && start_sw)
    {
        spin_lock(&lock);
        _memleak_add_to_index(*memptr, size, file, line, INIT_VAL);
        spin_unlock(&lock);
    }

    return ret;
}
// LCOV_EXCL_STOP
#else // not __ANDROID__
LIBMEMLEAK_API
void * memleak_memalign(size_t size, size_t alignment, char *file, size_t line)
{
    void *addr = memalign(alignment, size);
    if (addr && start_sw)
    {
        spin_lock(&lock);
        _memleak_add_to_index(addr, size, file, line, INIT_VAL);
        spin_unlock(&lock);
    }
    return addr;
}
#endif

#else // not WIN32

LIBMEMLEAK_API
void * memleak_aligned_malloc(size_t size, size_t alignment, char *file, size_t line)
{
    void *addr = (void*)_aligned_malloc(size, alignment);
    if (addr && start_sw) {
        spin_lock(&lock);
        _memleak_add_to_index(addr, size, file, line, INIT_VAL);
        spin_unlock(&lock);
    }
    return addr;
}

LIBMEMLEAK_API
void memleak_aligned_free(void *addr, char *file, size_t line)
{
    struct avl_node *a;
    struct memleak_item *item, query;

    if (start_sw) {
        spin_lock(&lock);

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
#ifdef _STACK_BACKTRACE
        free(item->btrace);
#endif
        free(item);
        spin_unlock(&lock);
    }
    _aligned_free(addr);
}

#endif // not WIN32

// LCOV_EXCL_START
LIBMEMLEAK_API
void *memleak_realloc(void *ptr, size_t size)
{

    void *addr = (void *)realloc(ptr, size);
    if (addr && start_sw) {
        spin_lock(&lock);
        struct avl_node *a;
        struct memleak_item *item, query;

        query.addr = (uint64_t)ptr;
        a = avl_search(&tree_index, &query.avl, memleak_cmp);
        if (a) {
            item = _get_entry(a, struct memleak_item, avl);
            DBG("realloc from address 0x%016lx (allocated at %s:%ld, size %ld)\n\tto address 0x%016lx (size %ld)\n",
                item->addr, item->file, item->line, item->size, (uint64_t)addr, size);
            avl_remove(&tree_index, a);
            _memleak_add_to_index(addr, size, item->file, item->line, 0);
#ifdef _STACK_BACKTRACE
            free(item->btrace);
#endif
            free(item);
        }
        spin_unlock(&lock);
    }

    return addr;
}
// LCOV_EXCL_STOP

// LCOV_EXCL_START
LIBMEMLEAK_API
void memleak_free(void *addr, char *file, size_t line)
{
    struct avl_node *a;
    struct memleak_item *item, query;

    if (start_sw) {
        spin_lock(&lock);

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

#ifdef _STACK_BACKTRACE
        free(item->btrace);
#endif

#ifndef _CHK_MODIFY_AFTER_FREE
        avl_remove(&tree_index, a);
        free(item);
#else
        item->freed = 1;
#endif
        spin_unlock(&lock);
    }
#ifndef _CHK_MODIFY_AFTER_FREE
    free(addr);
#endif
}
// LCOV_EXCL_STOP

