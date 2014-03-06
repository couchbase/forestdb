/* -*- Mode: C++; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2010 Couchbase, Inc
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 */

#ifndef _JSAHN_MEMLEAK_H
#define _JSAHN_MEMLEAK_H

#include <stdint.h>

#define _MALLOC_OVERRIDE
#ifndef _MALLOC_OVERRIDE
    #define _MALLOC_OVERRIDE
    #define malloc(size) memleak_alloc(size, __FILE__, __LINE__)
    #define calloc(nmemb, size) memleak_calloc(nmemb, size, __FILE__, __LINE__)
    #define realloc(ptr, size) memleak_realloc(ptr, size);
    #define posix_memalign(memptr, alignment, size) \
        memleak_posix_memalign(memptr, alignment, size, __FILE__, __LINE__)
    #define free(addr) memleak_free(addr, __FILE__, __LINE__)
#endif

void memleak_start();
void memleak_end();


void * memleak_alloc(size_t size, char *file, size_t line);
void * memleak_calloc(size_t nmemb, size_t size, char *file, size_t line);
void * memleak_memalign(size_t alignment, size_t size, char *file, size_t line);
int memleak_posix_memalign(void **memptr, size_t alignment, size_t size, char *file, size_t line);
void *memleak_realloc(void *ptr, size_t size);
void memleak_free(void *addr, char *file, size_t line);

#endif
