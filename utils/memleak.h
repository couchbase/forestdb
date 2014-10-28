/* -*- Mode: C++; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * Simple Memory Leakage Detection Tool
 * (C) 2013  Jung-Sang Ahn <jungsang.ahn@gmail.com>
 * see https://github.com/greensky00/memleak
 */

#ifndef _JSAHN_MEMLEAK_H
#define _JSAHN_MEMLEAK_H

#include <stdint.h>

#ifdef _MSC_VER
    #ifdef forestdb_EXPORTS
        #define LIBMEMLEAK_API extern __declspec(dllexport)
    #else
        #define LIBMEMLEAK_API
    #endif
#elif __GNUC__
    #define LIBMEMLEAK_API __attribute ((visibility("default")))
#else
    #define LIBMEMLEAK_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

#ifndef _MEMLEAK_ENABLE
#define _MALLOC_OVERRIDE
#endif
#ifndef _MALLOC_OVERRIDE
    #define _MALLOC_OVERRIDE
    #define malloc(size) memleak_alloc(size, (char*)__FILE__, __LINE__)
    #define calloc(nmemb, size) memleak_calloc(nmemb, size, (char*)__FILE__, __LINE__)
    #define realloc(ptr, size) memleak_realloc(ptr, size);
    #define free(addr) memleak_free(addr, (char*)__FILE__, __LINE__)

#if !defined(WIN32)

#if !defined(__ANDROID__)
    #define posix_memalign(memptr, alignment, size) \
        memleak_posix_memalign(memptr, alignment, size, (char*)__FILE__, __LINE__)
#else // not __ANDROID__
    #define memalign(alignment, size) \
        memleak_memalign(alignment, size, (char*)__FILE__, __LINE__)
#endif // not __ANDROID__

#else // not WIN32
    #define _aligned_malloc(size, align) \
        memleak_aligned_malloc(size, align, (char*)__FILE__, __LINE__)
    #define _aligned_free(addr) \
        memleak_aligned_free(addr, (char*)__FILE__, __LINE__)
#endif // not WIN32

#endif // not _MALLOC_OVERRIDE

LIBMEMLEAK_API
void memleak_start();

LIBMEMLEAK_API
void memleak_end();

LIBMEMLEAK_API
void * memleak_alloc(size_t size, char *file, size_t line);

LIBMEMLEAK_API
void * memleak_calloc(size_t nmemb, size_t size, char *file, size_t line);

LIBMEMLEAK_API
void * memleak_memalign(size_t alignment, size_t size, char *file, size_t line);

LIBMEMLEAK_API
void *memleak_realloc(void *ptr, size_t size);

LIBMEMLEAK_API
void memleak_free(void *addr, char *file, size_t line);

#ifndef WIN32
LIBMEMLEAK_API
int memleak_posix_memalign(void **memptr, size_t alignment, size_t size, char *file, size_t line);
#else
LIBMEMLEAK_API
void * memleak_aligned_malloc(size_t size, size_t alignment, char *file, size_t line);
LIBMEMLEAK_API
void memleak_aligned_free(void *addr, char *file, size_t line);
#endif

#ifdef __cplusplus
}
#endif

#endif
