#ifndef _JSAHN_MEMPOOL_H
#define _JSAHN_MEMPOOL_H

#include <stdlib.h>

#define _MEMPOOL

void mempool_init();
void mempool_shutdown();
void * mempool_alloc(size_t size);
void mempool_free(void *addr);

#endif
