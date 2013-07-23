/*
 * Copyright 2013 Jung-Sang Ahn <jungsang.ahn@gmail.com>.
 * All Rights Reserved.
 */

#ifndef _JSAHN_BLOCKCACHE_H
#define _JSAHN_BLOCKCACHE_H

#include "filemgr.h"

void bcache_init(int nblock, int blocksize);
int bcache_read(struct filemgr *file, bid_t bid, void *buf);
int bcache_write(struct filemgr *file, bid_t bid, void *buf, int dirty);
void bcache_flush(struct filemgr *file);
void bcache_free();

#endif
