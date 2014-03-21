/* -*- Mode: C++; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * Simple Memory Leakage Detection Tool
 * (C) 2013  Jung-Sang Ahn <jungsang.ahn@gmail.com>
 * see https://github.com/greensky00/memleak
 */

#ifndef _JSAHN_MEMLEAK_H
#define _JSAHN_MEMLEAK_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define _MALLOC_OVERRIDE
#ifndef _MALLOC_OVERRIDE
    #define _MALLOC_OVERRIDE
    #define malloc(size) memleak_alloc(size, __FILE__, __LINE__)
    #define calloc(nmemb, size) memleak_calloc(nmemb, size, __FILE__, __LINE__)
    #define realloc(ptr, size) memleak_realloc(ptr, size);
    #define free(addr) memleak_free(addr, __FILE__, __LINE__)
#ifndef WIN32
    #define posix_memalign(memptr, alignment, size) \
            memleak_posix_memalign(memptr, alignment, size, __FILE__, __LINE__)
#endif
#endif

void memleak_start();
void memleak_end();

void * memleak_alloc(size_t size, char *file, size_t line);
void * memleak_calloc(size_t nmemb, size_t size, char *file, size_t line);
void * memleak_memalign(size_t alignment, size_t size, char *file, size_t line);
void *memleak_realloc(void *ptr, size_t size);
void memleak_free(void *addr, char *file, size_t line);
#ifndef WIN32
int memleak_posix_memalign(void **memptr, size_t alignment, size_t size, char *file, size_t line);
#endif

#ifdef __cplusplus
}
#endif

#endif
