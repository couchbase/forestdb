/*
 * Copyright 2013 Jung-Sang Ahn <jungsang.ahn@gmail.com>.
 * All Rights Reserved.
 */

#ifndef _JSAHN_BTREEBLOCK_H
#define _JSAHN_BTREEBLOCK_H

#include "filemgr.h"
#include "list.h"
#include "btree.h"

struct btreeblk_handle{
	uint32_t nodesize;
	uint16_t nnodeperblock;
	struct list alc_list;
	struct list read_list;
	struct filemgr *file;
};

struct btree_blk_ops *btreeblk_get_ops();
void btreeblk_init(struct btreeblk_handle *handle, struct filemgr *file, int nodesize);
void btreeblk_end(struct btreeblk_handle *handle);

#endif
