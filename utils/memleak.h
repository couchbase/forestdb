/*
 * Copyright 2013 Jung-Sang Ahn <jungsang.ahn@gmail.com>.
 * All Rights Reserved.
 */

#ifndef _JSAHN_MEMLEAK_H
#define _JSAHN_MEMLEAK_H

#include <stdint.h>

#ifndef _MALLOC_OVERRIDE
    #define malloc(size) memleak_alloc(size, __FILE__, __LINE__)
    #define calloc(nmemb, size) memleak_calloc(nmemb, size, __FILE__, __LINE__)
    #define realloc(ptr, size) memleak_realloc(ptr, size);
    #define posix_memalign(memptr, alignment, size) \
        memleak_posix_memalign(memptr, alignment, size, __FILE__, __LINE__)
    #define free memleak_free
#endif

void memleak_start();
void memleak_end();

void * memleak_alloc(size_t size, char *file, size_t line);
void * memleak_calloc(size_t nmemb, size_t size, char *file, size_t line);
int memleak_posix_memalign(void **memptr, size_t alignment, size_t size, char *file, size_t line);
void *memleak_realloc(void *ptr, size_t size);
void memleak_free(void *addr);

#endif
