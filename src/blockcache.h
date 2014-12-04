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

#ifndef _JSAHN_BLOCKCACHE_H
#define _JSAHN_BLOCKCACHE_H

#include "filemgr.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    BCACHE_REQ_CLEAN,
    BCACHE_REQ_DIRTY
} bcache_dirty_t;

void bcache_init(int nblock, int blocksize);
int bcache_read(struct filemgr *file, bid_t bid, void *buf);
void bcache_invalidate_block(struct filemgr *file, bid_t bid);
int bcache_write(struct filemgr *file, bid_t bid, void *buf, bcache_dirty_t dirty);
int bcache_write_partial(struct filemgr *file, bid_t bid, void *buf, size_t offset, size_t len);
void bcache_remove_dirty_blocks(struct filemgr *file);
void bcache_remove_clean_blocks(struct filemgr *file);
void bcache_remove_file(struct filemgr *file);
fdb_status bcache_flush(struct filemgr *file);
void bcache_shutdown();
uint64_t bcache_get_num_free_blocks();
void bcache_print_items();
void bcache_update_file_status(struct filemgr *file, file_status_t status);

#ifdef __cplusplus
}
#endif

#endif
