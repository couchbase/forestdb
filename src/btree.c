/*
 * Copyright 2013 Jung-Sang Ahn <jungsang.ahn@gmail.com>.
 * All Rights Reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "btree.h"
#include "btree_kv.h"
#include "common.h"

#define __DEBUG_BTREE
#ifdef __DEBUG
#ifndef __DEBUG_BTREE
	#undef DBG
	#undef DBGCMD
	#define DBG(args...)
	#define DBGCMD(command...)
#endif
#endif

INLINE struct bnode *_fetch_bnode(void *addr)
{
	struct bnode *node = (struct bnode *)addr;
	if (!(node->flag & BNODE_MASK_METADATA)) {
		// no metadata
		node->data = addr + sizeof(struct bnode);
	}else{
		// metadata
		metasize_t metasize;
		memcpy(&metasize, addr + sizeof(struct bnode), sizeof(metasize_t));
		node->data = addr + sizeof(struct bnode) + sizeof(metasize_t) + metasize;
	}
	return node;
}

INLINE int _bnode_size(struct btree *btree, struct bnode *node)
{
	if (node->flag & BNODE_MASK_METADATA) {
		metasize_t size;
		memcpy(&size, (void *)node + sizeof(struct bnode), sizeof(metasize_t));
		return sizeof(struct bnode) + (btree->ksize + btree->vsize) * node->nentry + size + sizeof(metasize_t);
	}else{
		return sizeof(struct bnode) + (btree->ksize + btree->vsize) * node->nentry;
	}
}

// return true if there is enough space to insert one or more kv-pair into the NODE
INLINE int _bnode_size_check(struct btree *btree, struct bnode *node) 
{
	return ( _bnode_size(btree, node) + btree->ksize + btree->vsize <= btree->blksize );
}

INLINE struct bnode * _btree_init_node(struct btree *btree, void *addr, bnode_flag_t flag, uint16_t level, struct btree_meta *meta)
{
	struct bnode *node = (struct bnode *)addr;
	
	node->kvsize = btree->ksize<<4 | btree->vsize;
	node->nentry = 0;
	node->level = level;
	node->flag = flag;
	if ((flag & BNODE_MASK_METADATA) && meta) {
		memcpy(addr + sizeof(struct bnode), &meta->size, sizeof(metasize_t));
		memcpy(addr + sizeof(struct bnode) + sizeof(metasize_t), meta->data, meta->size);
		node->data = addr + sizeof(struct bnode) + sizeof(metasize_t) + meta->size;
	}else{
		node->data = addr + sizeof(struct bnode);
	}

	return node;
}

metasize_t btree_read_meta(struct btree *btree, void *buf)
{
	void *addr;
	void *ptr;
	metasize_t size;
	struct bnode *node;

	addr = btree->blk_ops->blk_read(btree->blk_handle, btree->root_bid);
	node = _fetch_bnode(addr);
	if (node->flag & BNODE_MASK_METADATA) {
		ptr = addr + sizeof(struct bnode);
		memcpy(&size, ptr, sizeof(metasize_t));
		memcpy(buf, ptr + sizeof(metasize_t), size);
	}else{
		size = 0;
	}
	
	return size;
}

void btree_update_meta(struct btree *btree, struct btree_meta *meta)
{
	void *addr;
	void *ptr;
	metasize_t metasize;
	metasize_t old_metasize;
	struct bnode *node;
	bid_t new_bid;

	// read root node
	addr = btree->blk_ops->blk_read(btree->blk_handle, btree->root_bid);
	node = _fetch_bnode(addr);

	ptr = addr + sizeof(struct bnode);
	metasize = old_metasize = 0;
	
	if (node->flag & BNODE_MASK_METADATA) {
		memcpy(&old_metasize, ptr, sizeof(metasize_t));
	}

	if (meta) {
		metasize = meta->size;

		// new meta size cannot be larger than old meta size
		assert(metasize <= old_metasize);

		// overwrite
		if (meta->size > 0) {
			memcpy(ptr, &metasize, sizeof(metasize_t));
			memcpy(ptr + sizeof(metasize_t), meta->data, metasize);
			node->flag |= BNODE_MASK_METADATA;
		}else{
			// clear the flag
			node->flag &= ~BNODE_MASK_METADATA;
		}
		// move kv-pairs (only if meta size is changed)
		if (metasize < old_metasize){
			memmove(ptr + sizeof(metasize_t) + metasize, node->data, node->nentry * (btree->ksize + btree->vsize));
			node->data -= (old_metasize - metasize);
		}

	}else {
		memmove(ptr, node->data, node->nentry * (btree->ksize + btree->vsize));
		node->data -= (old_metasize + sizeof(metasize_t));
		// clear the flag
		node->flag &= ~BNODE_MASK_METADATA;
	}

	if (!btree->blk_ops->blk_is_writable(btree->blk_handle, btree->root_bid)) {
		// already flushed block -> cannot overwrite, we have to move to new block
		addr = btree->blk_ops->blk_move(btree->blk_handle, btree->root_bid, &btree->root_bid);
	}else{
		btree->blk_ops->blk_set_dirty(btree->blk_handle, btree->root_bid);
	}
}

btree_result btree_init_from_bid(
		struct btree *btree, void *blk_handle,
		struct btree_blk_ops *blk_ops, 	struct btree_kv_ops *kv_ops,
		uint32_t nodesize, bid_t root_bid)
{
	void *addr;
	struct bnode *root;

	btree->blk_ops = blk_ops;
	btree->blk_handle = blk_handle;
	btree->kv_ops = kv_ops;
	btree->blksize = nodesize;
	btree->root_bid = root_bid;

	addr = btree->blk_ops->blk_read(btree->blk_handle, btree->root_bid);
	root = _fetch_bnode(addr);
	#ifdef _BNODE_COMP
		btree->blk_ops->blk_set_uncomp_size(btree->blk_handle, btree->root_bid, _bnode_size(btree, root));
	#endif

	btree->root_flag = root->flag;
	btree->height = root->level;
	_get_kvsize(root->kvsize, btree->ksize, btree->vsize);

	return BTREE_RESULT_SUCCESS;
}

btree_result btree_init(
		struct btree *btree, void *blk_handle,
		struct btree_blk_ops *blk_ops, 	struct btree_kv_ops *kv_ops,
		uint32_t nodesize, uint8_t ksize, uint8_t vsize,
		bnode_flag_t flag, struct btree_meta *meta)
{
	void *addr;
	struct bnode *root;

	btree->root_flag = BNODE_MASK_ROOT | flag;
	btree->blk_ops = blk_ops;
	btree->blk_handle = blk_handle;
	btree->kv_ops = kv_ops;
	btree->height = 1;
	btree->blksize = nodesize;
	btree->ksize = ksize;
	btree->vsize = vsize;
	if (meta) btree->root_flag |= BNODE_MASK_METADATA;

	// create the first root node
	addr = btree->blk_ops->blk_alloc(btree->blk_handle, &btree->root_bid);
	root = _btree_init_node(btree, addr, btree->root_flag, BNODE_MASK_ROOT, meta);
	#ifdef _BNODE_COMP
		btree->blk_ops->blk_set_uncomp_size(btree->blk_handle, btree->root_bid, _bnode_size(btree, root));
	#endif

	DBG("root kvsize %0x\n", root->kvsize);

	return BTREE_RESULT_SUCCESS;
}

/*
return index# of largest key equal or smaller than KEY
example)
node: [2 4 6 8]
key: 5
largest key equal or smaller than KEY: 4
return: 1 (index# of the key '4') 
*/
idx_t _btree_find_entry(struct btree *btree, struct bnode *node, void *key)
{
	idx_t start, end, middle;
	uint8_t k[btree->ksize], dummy[btree->vsize];
	int cmp;

	start = middle = 0;
	end = node->nentry;

	if (end > 0) {
		// compare with smallest key
		btree->kv_ops->get_kv(node, 0, k, dummy);
		// smaller than smallest key
		if (btree->kv_ops->cmp(key, k) < 0) return BTREE_IDX_NOT_FOUND;
		
		// compare with largest key
		btree->kv_ops->get_kv(node, end-1, k, dummy);
		// larger than largest key
		if (btree->kv_ops->cmp(key, k) >= 0) return end-1;

		// binary search
		while(start+1 < end) {
			middle = (start + end) >> 1;

			// get key at middle
			btree->kv_ops->get_kv(node, middle, k, dummy);
			cmp = btree->kv_ops->cmp(key, k);
			if (cmp < 0) end = middle;
			else if (cmp > 0) start = middle;
			else return middle;
		}
		return start;
	}
	return BTREE_IDX_NOT_FOUND;
}

idx_t _btree_add_entry(struct btree *btree, struct bnode *node, void *key, void *value)
{
	idx_t idx, idx_insert;
	void *ptr;
	uint8_t k[btree->ksize], v[btree->vsize];
	
	if (node->nentry > 0) {
		idx = _btree_find_entry(btree, node, key);

		if (idx == BTREE_IDX_NOT_FOUND) idx_insert = 0;
		else {
			btree->kv_ops->get_kv(node, idx, k, v);
			if (!btree->kv_ops->cmp(key, k)) { 
				// if same key already exists -> update its value
				btree->kv_ops->set_kv(node, idx, key, value);
				return idx;				
			}else{
				idx_insert = idx+1;		
			}
		}

		if (idx_insert < node->nentry) {
			ptr = node->data;

			/*
			shift [idx+1, nentry) key-value pairs to right 
			example)
			idx = 1 (i.e. idx_insert = 2)
			[2 4 6 8] -> [2 4 _ 6 8]
			return 2
			*/
			memmove(
				ptr + ( (idx_insert+1) * (btree->ksize + btree->vsize) ) , /* destination */
				ptr + ( (idx_insert) * (btree->ksize + btree->vsize) ) , /* source */
				( node->nentry - (idx_insert) ) * (btree->ksize + btree->vsize)  /* length */ );
		}

	}else{
		idx_insert = 0;
	}

	// add at idx_insert
	btree->kv_ops->set_kv(node, idx_insert, key, value);
	node->nentry++;	

	return idx_insert;
}

idx_t _btree_remove_entry(struct btree *btree, struct bnode *node, void *key)
{
	idx_t idx;
	void *ptr;
	
	if (node->nentry > 0) {
		idx = _btree_find_entry(btree, node, key);

		if (idx == BTREE_IDX_NOT_FOUND) return idx;

		ptr = node->data;

		/*
		shift [idx+1, nentry) key-value pairs to left
		example)
		idx = 2
		[2 4 6 8 10] -> [2 4 8 10]
		return 2
		*/
		memmove(
			ptr + ( idx * (btree->ksize + btree->vsize) ) , /* destination */
			ptr + ( (idx+1) * (btree->ksize + btree->vsize) ) , /* source */
			( node->nentry - (idx+1) ) * (btree->ksize + btree->vsize)  /* length */ );

		node->nentry--;

		return idx;
		
	}else{
		return BTREE_IDX_NOT_FOUND;
	}
}


void _btree_print_node(struct btree *btree, int depth, bid_t bid)
{
	int i;
	uint8_t k[btree->ksize], v[btree->vsize];
	void *addr;
	struct bnode *node;
	struct bnode *child;

	addr = btree->blk_ops->blk_read(btree->blk_handle, bid);
	node = _fetch_bnode(addr);

	DBG("[d:%d n:%d f:%x b:%"_F64" ", node->level, node->nentry, node->flag, bid);

	for (i=0;i<node->nentry;++i){
		btree->kv_ops->get_kv(node, i, k, v);
		DBG("(%"_F64" %"_F64")", *(uint64_t*)k, *(uint64_t*)v);
	}
	DBG("]\n");
	if (depth > 1) {
		for (i=0;i<node->nentry;++i){
			btree->kv_ops->get_kv(node, i, k, v);
			_btree_print_node(btree, depth-1, btree->kv_ops->value2bid(v));
		}
	}
}

void btree_print_node(struct btree *btree)
{
	void *addr;

	DBG("tree height: %d\n", btree->height);
	_btree_print_node(btree, btree->height, btree->root_bid);
}

btree_result btree_iterator_init(struct btree *btree, struct btree_iterator *it, void *initial_key)
{
	int i;

	it->btree = *btree;
	it->curkey = (void *)malloc(btree->ksize);
	if (initial_key) {
		// set initial key if exists
		memcpy(it->curkey, initial_key, btree->ksize);
	}else{
		// NULL initial key .. set minimum key (start from leftmost key)
		memset(it->curkey, 0, btree->ksize);
	}
	it->bid = (bid_t*)malloc(sizeof(bid_t) * btree->height);
	it->idx = (idx_t*)malloc(sizeof(idx_t) * btree->height);
	for (i=0;i<btree->height;++i){
		it->bid[i] = BTREE_BLK_NOT_FOUND;
		it->idx[i] = BTREE_IDX_NOT_FOUND;
	}
	it->bid[btree->height-1] = btree->root_bid;
	
	return BTREE_RESULT_SUCCESS;
}

btree_result btree_iterator_free(struct btree_iterator *it)
{
	free(it->curkey);
	free(it->bid);
	free(it->idx);
	return BTREE_RESULT_SUCCESS;
}

btree_result _btree_next(struct btree_iterator *it, void *key_buf, void *value_buf, int depth)
{
	struct btree *btree;
	btree = &it->btree;
	int i;
	uint8_t k[btree->ksize], v[btree->vsize];
	void *addr;
	struct bnode *node;
	btree_result r;

	addr = btree->blk_ops->blk_read(btree->blk_handle, it->bid[depth]);
	node = _fetch_bnode(addr);
	
	if (it->idx[depth] == BTREE_IDX_NOT_FOUND) {
		// curkey: lastly returned key
		it->idx[depth] = _btree_find_entry(btree, node, it->curkey);
		if (it->idx[depth] == BTREE_IDX_NOT_FOUND) {
			it->idx[depth] = 0;
		}
	}

	if (it->idx[depth] >= node->nentry) {
		// out of bound .. go up to parent node
		return BTREE_RESULT_FAIL;
	}

	if (depth > 0) {
		// index node
		btree->kv_ops->get_kv(node, it->idx[depth], k, v);
		it->bid[depth-1] = btree->kv_ops->value2bid(v);
		r = _btree_next(it, key_buf, value_buf, depth-1);
		
		if (r == BTREE_RESULT_FAIL) {
			// move index to right
			it->idx[depth]++;
			
			if (it->idx[depth] >= node->nentry){
				// out of bound .. go up to parent node
				return BTREE_RESULT_FAIL;
			}else{
				btree->kv_ops->get_kv(node, it->idx[depth], k, v);
				it->bid[depth-1] = btree->kv_ops->value2bid(v);
				// reset child index
				for (i=depth-1; i>=0; --i)
					it->idx[i] = BTREE_IDX_NOT_FOUND;
				// retry
				r = _btree_next(it, key_buf, value_buf, depth-1);
			}
		}
		return r;
	}else{
		// leaf node
		btree->kv_ops->get_kv(node, it->idx[depth], key_buf, value_buf);
		memcpy(it->curkey, key_buf, btree->ksize);
		it->idx[depth]++;
		return BTREE_RESULT_SUCCESS;
	}
}

btree_result btree_next(struct btree_iterator *it, void *key_buf, void *value_buf)
{
	return _btree_next(it, key_buf, value_buf, it->btree.height-1);
}

btree_result btree_find(struct btree *btree, void *key, void *value_buf)
{
	void *addr;
	uint8_t k[btree->ksize], v[btree->vsize];
	idx_t idx[btree->height];
	bid_t bid[btree->height];
	struct bnode *node[btree->height];
	int i;

	// set root
	bid[btree->height-1] = btree->root_bid;

	for (i=btree->height-1; i>=0; --i) {
		// read block using bid
		addr = btree->blk_ops->blk_read(btree->blk_handle, bid[i]);
		// fetch node structure from block
		node[i] = _fetch_bnode(addr);

		// lookup key in current node
		idx[i] = _btree_find_entry(btree, node[i], key);

		if (idx[i] == BTREE_IDX_NOT_FOUND) {
			// not found .. return NULL
			if (btree->blk_ops->blk_operation_end) btree->blk_ops->blk_operation_end(btree->blk_handle);
			return BTREE_RESULT_FAIL;
		}

		btree->kv_ops->get_kv(node[i], idx[i], k, v);

		if (i>0) {
			// index (non-leaf) node
			// get bid of child node from value
			bid[i-1] = btree->kv_ops->value2bid(v);
		}else{
			// leaf node
			// return (address of) value if KEY == k
			if (!btree->kv_ops->cmp(key, k)) {
				memcpy(value_buf, v, btree->vsize);
			}else{
				if (btree->blk_ops->blk_operation_end) btree->blk_ops->blk_operation_end(btree->blk_handle);
				return BTREE_RESULT_FAIL;
			}
		}
	}
	if (btree->blk_ops->blk_operation_end) btree->blk_ops->blk_operation_end(btree->blk_handle);
	return BTREE_RESULT_SUCCESS;
}

btree_result btree_insert(struct btree *btree, void *key, void *value)
{
	void *addr; 
	uint8_t k[btree->ksize], v[btree->vsize];
	// index# and block ID for each level
	idx_t idx[btree->height];
	bid_t bid[btree->height];
	// flags
	int8_t modified[btree->height], moved[btree->height], ins[btree->height];
	// key, value to be inserted
	uint8_t key_ins[btree->height][btree->ksize];
	uint8_t value_ins[btree->height][btree->vsize];
	// index# where kv is inserted
	idx_t idx_ins[btree->height];
	struct bnode *node[btree->height];
	int i;

	// initialize flags
	//for (i=0;i<btree->height;++i) moved[i] = modified[i] = ins[i] = 0;
	memset(moved, 0, sizeof(int8_t) * btree->height);
	memset(modified, 0, sizeof(int8_t) * btree->height);
	memset(ins, 0, sizeof(int8_t) * btree->height);	
	
	// copy key-value pair to be inserted into leaf node
	memcpy(key_ins[0], key, btree->ksize);
	memcpy(value_ins[0], value, btree->vsize);
	ins[0] = 1;

	// set root node
	bid[btree->height-1] = btree->root_bid;

	// find path from root to leaf
	for (i=btree->height-1; i>=0; --i){
		// read block using bid
		addr = btree->blk_ops->blk_read(btree->blk_handle, bid[i]);
		// fetch node structure from block
		node[i] = _fetch_bnode(addr);
		
		// lookup key in current node
		idx[i] = _btree_find_entry(btree, node[i], key);

		if (i > 0) {
			// index (non-leaf) node
			if (idx[i] == BTREE_IDX_NOT_FOUND)
				// KEY is smaller than the smallest key in this node .. just follow the smallest key
				idx[i] = 0;

			// get bid of child node from value
			btree->kv_ops->get_kv(node[i], idx[i], k, v);
			bid[i-1] = btree->kv_ops->value2bid(v);			
		}else{
			// leaf node .. do nothing
		}
	}

	// cascaded insert from leaf to root
	for (i=0;i<btree->height;++i){
		
		if (idx[i] != BTREE_IDX_NOT_FOUND)
			btree->kv_ops->get_kv(node[i], idx[i], k, v);

		if (i > 0) {
			// in case of index node
			// when KEY is smaller than smallest key in index node
  			if (idx[i] == 0 && btree->kv_ops->cmp(key, k) < 0) {
				// change node's smallest key
				btree->kv_ops->set_kv(node[i], idx[i], key, v);
				memcpy(k, key, btree->ksize);
				modified[i] = 1;
			}

			// when child node is moved to new block
			if (moved[i-1]) {
				// replace the bid (value)
				btree->kv_ops->set_kv(node[i], idx[i], k, btree->kv_ops->bid2value(&bid[i-1]));
				modified[i] = 1;
			}
		}		

		if (ins[i]) {
			// there is a key-value pair to be inserted into this (level of) node
		
			// check whether btree node space is enough to add new key-value pair or not, OR
			// action is not insertion but update (key_ins exists in current node)
		#ifndef _BNODE_COMP
			int _size_check = _bnode_size_check(btree, node[i]);
		#else
			size_t compsize = btree->blk_ops->blk_comp_size(btree->blk_handle, bid[i]);
			int _size_check = (compsize + 2*(btree->ksize + btree->vsize) <= btree->blksize);
		#endif
			
			if (_size_check || (idx[i] != BTREE_IDX_NOT_FOUND && !btree->kv_ops->cmp(key_ins[i], k)) ) {
				// enough

				// insert
				idx_ins[i] = _btree_add_entry(btree, node[i], key_ins[i], value_ins[i]);
				modified[i] = 1;
				
			}else {
				// not enough .. split the node
				bid_t new_bid;
				struct bnode *new_node;
				int nentry1, nentry2;
				
				// allocate new block for latter half
				addr = btree->blk_ops->blk_alloc(btree->blk_handle, &new_bid);
				new_node = _btree_init_node(btree, addr, 0x0, node[i]->level, NULL);

				if (btree->root_flag & BNODE_MASK_SEQTREE) {
					// sequential tree -> make left node (old node) full, rignt node (new node) empty
					nentry1 = node[i]->nentry;
					nentry2 = 0;
				}else{
					// ordinary tree -> even split
					nentry1 = node[i]->nentry / 2;
					nentry2 = node[i]->nentry - nentry1;
				}
				
				// copy latter half kv-pairs to new node
				memcpy(
					new_node->data,
					node[i]->data + (btree->ksize + btree->vsize) * nentry1,
					(btree->ksize + btree->vsize) * nentry2);

				// header
				node[i]->nentry = nentry1;
				new_node->nentry = nentry2;
				modified[i] = 1;

				if (btree->root_flag & BNODE_MASK_SEQTREE) {
					// always insert in right (new) node
					_btree_add_entry(btree, new_node, key_ins[i], value_ins[i]);
				}else{
					// normal tree -> insert kv-pair to appropriate node
					btree->kv_ops->get_kv(new_node, 0, k, v);
					if (btree->kv_ops->cmp(key, k) < 0) {
						idx_ins[i] = _btree_add_entry(btree, node[i], key_ins[i], value_ins[i]);
					}else{
						_btree_add_entry(btree, new_node, key_ins[i], value_ins[i]);
					}
				}
				
				#ifdef _BNODE_COMP
					btree->blk_ops->blk_set_uncomp_size(btree->blk_handle, new_bid, _bnode_size(btree, new_node));
				#endif

				if (i+1 < btree->height) {
					// non-root node
					// reserve kv-pair to be inserted into parent node
					// btree->kv_ops->get_kv(new_node, 0, k, v);
					memcpy(key_ins[i+1], k, btree->ksize);
					memcpy(value_ins[i+1], &new_bid, btree->vsize);
					ins[i+1] = 1;
				}else{
					// root node -> height grow up
					// allocate new block for new root node
					bid_t new_root_bid;
					struct bnode *new_root;
					uint8_t buf[btree->blksize];
					struct btree_meta meta;

					meta.size = btree_read_meta(btree, buf);
					meta.data = buf;
					// remove metadata section of existing node (this node is not root anymore)
					btree_update_meta(btree, NULL);
					
					addr = btree->blk_ops->blk_alloc(btree->blk_handle, &new_root_bid);
					if (meta.size > 0) 
						new_root = _btree_init_node(btree, addr, btree->root_flag, node[i]->level + 1, &meta);
					else
						new_root = _btree_init_node(btree, addr, btree->root_flag, node[i]->level + 1, NULL);
					
					// clear old root node flag
					node[i]->flag &= ~BNODE_MASK_ROOT;
					node[i]->flag &= ~BNODE_MASK_SEQTREE;
					// change root bid
					btree->root_bid = new_root_bid;
					
					// move the former node if not dirty
					if (!btree->blk_ops->blk_is_writable(btree->blk_handle, bid[i])) {
						addr = btree->blk_ops->blk_move(btree->blk_handle, bid[i], &bid[i]);
						node[i] = _fetch_bnode(addr);
					}else{
						btree->blk_ops->blk_set_dirty(btree->blk_handle, bid[i]);
					}
					
					// insert two kv-pair that point to two child nodes
					btree->kv_ops->get_kv(node[i], 0, k, v);
					_btree_add_entry(btree, new_root, k, btree->kv_ops->bid2value(&bid[i]));
					btree->kv_ops->get_kv(new_node, 0, k, v);
					_btree_add_entry(btree, new_root, k, btree->kv_ops->bid2value(&new_bid));

					#ifdef _BNODE_COMP
						btree->blk_ops->blk_set_uncomp_size(btree->blk_handle, bid[i], _bnode_size(btree, node[i]));
						btree->blk_ops->blk_set_uncomp_size(btree->blk_handle, new_root_bid, 
							_bnode_size(btree, new_root));
					#endif

					btree->height++;
					DBG("height grow\n");

					if (btree->blk_ops->blk_operation_end) btree->blk_ops->blk_operation_end(btree->blk_handle);					
					return BTREE_RESULT_SUCCESS;
				}	
			}
		}

		if (modified[i]) {
			// when node is modified			
			if (!btree->blk_ops->blk_is_writable(btree->blk_handle, bid[i])) {
				// already flushed block -> cannot overwrite, we have to move to new block
				// get new bid[i]
				addr = btree->blk_ops->blk_move(btree->blk_handle, bid[i], &bid[i]);
				node[i] = _fetch_bnode(addr);
				moved[i] = 1;

				if (i+1 == btree->height) 
					// if moved node is root node
					btree->root_bid = bid[i];
			}else{
				btree->blk_ops->blk_set_dirty(btree->blk_handle, bid[i]);
			}
			
			#ifdef _BNODE_COMP
				btree->blk_ops->blk_set_uncomp_size(btree->blk_handle, bid[i], _bnode_size(btree, node[i]));
			#endif
		}
		
	}

	if (btree->blk_ops->blk_operation_end) btree->blk_ops->blk_operation_end(btree->blk_handle);
	return BTREE_RESULT_SUCCESS;
	
}

btree_result btree_remove(struct btree *btree, void *key)
{
	void *addr;
	uint8_t k[btree->ksize], v[btree->vsize];
	uint8_t kk[btree->ksize], vv[btree->vsize];
	// index# and block ID for each level
	idx_t idx[btree->height];
	bid_t bid[btree->height];
	// flags
	int8_t modified[btree->height], moved[btree->height], rmv[btree->height];
	// index# of removed key
	idx_t idx_rmv[btree->height];
	struct bnode *node[btree->height];
	int i;

	// initialize flags
	for (i=0;i<btree->height;++i) {
		moved[i] = modified[i] = rmv[i] = 0;
	}
	
	rmv[0] = 1;

	// set root
	bid[btree->height-1] = btree->root_bid;

	// find path from root to leaf
	for (i=btree->height-1; i>=0; --i) {
		// read block using bid
		addr = btree->blk_ops->blk_read(btree->blk_handle, bid[i]);
		// fetch node structure from block
		node[i] = _fetch_bnode(addr);

		// lookup key in current node
		idx[i] = _btree_find_entry(btree, node[i], key);

		if (idx[i] == BTREE_IDX_NOT_FOUND) {
			// not found
			if (btree->blk_ops->blk_operation_end) btree->blk_ops->blk_operation_end(btree->blk_handle);
			return BTREE_RESULT_FAIL;
		}

		btree->kv_ops->get_kv(node[i], idx[i], k, v);

		if (i>0) {
			// index (non-leaf) node
			// get bid of child node from value
			bid[i-1] = btree->kv_ops->value2bid(v);
		}else{
			// leaf node
		}
	}

	// cascaded remove from leaf to root
	for (i=0;i<btree->height;++i){
		// in case of index node
		if (i > 0) {
			btree->kv_ops->get_kv(node[i], idx[i], k, v);

			// when child node's smallest key is changed due to remove
  			if (node[i-1]->nentry > 0) {
				btree->kv_ops->get_kv(node[i-1], 0, kk, vv);
				if (btree->kv_ops->cmp(kk, k)) {
					// change current node's corresponding key
					btree->kv_ops->set_kv(node[i], idx[i], kk, v);
					memcpy(k, kk, btree->ksize);
					modified[i] = 1;
				}
			}

			// when child node is moved to new block
			if (moved[i-1]) {
				// replace the bid (value)
				btree->kv_ops->set_kv(node[i], idx[i], k, btree->kv_ops->bid2value(&bid[i-1]));
				modified[i] = 1;
			}
		}		

		if (rmv[i]) {
			// there is a key-value pair to be removed			
			btree->kv_ops->get_kv(node[i], idx[i], k, v);
			idx_rmv[i] = _btree_remove_entry(btree, node[i], k);
			modified[i] = 1;

			/* 
			remove the node when
			1. non-root node has no kv-pair or
			2. root node has less or equal than one kv-pair
			*/
			if ((node[i]->nentry < 1 && i+1 < btree->height) || (node[i]->nentry <= 1 && i+1 == btree->height)) {
				// remove the node
				if (i+1 < btree->height) {
					// if non-root node
					rmv[i+1] = 1;
				}else{
					// if root node
					btree->height--;
					btree->kv_ops->get_kv(node[i], 0, k, v);
					btree->root_bid = btree->kv_ops->value2bid(v);
				}
			}
		}

		if (modified[i]) {
			// when node is modified			
			if (!btree->blk_ops->blk_is_writable(btree->blk_handle, bid[i])) {
				// already flushed block -> cannot overwrite, we have to move to new block
				// get new bid[i]
				addr = btree->blk_ops->blk_move(btree->blk_handle, bid[i], &bid[i]);
				node[i] = _fetch_bnode(addr);
				moved[i] = 1;

				if (i+1 == btree->height) 
					// if moved node is root node
					btree->root_bid = bid[i];
			}else{
				btree->blk_ops->blk_set_dirty(btree->blk_handle, bid[i]);
			}
			
			#ifdef _BNODE_COMP
				btree->blk_ops->blk_set_uncomp_size(btree->blk_handle, bid[i], _bnode_size(btree, node[i]));
			#endif
		}		
	}

	if (btree->blk_ops->blk_operation_end) btree->blk_ops->blk_operation_end(btree->blk_handle);
	return BTREE_RESULT_SUCCESS;
}

btree_result btree_operation_end(struct btree *btree)
{
	if (btree->blk_ops->blk_operation_end) btree->blk_ops->blk_operation_end(btree->blk_handle);
	return BTREE_RESULT_SUCCESS;
}


