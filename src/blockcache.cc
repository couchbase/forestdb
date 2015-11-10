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

#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#if !defined(WIN32) && !defined(_WIN32)
#include <sys/time.h>
#endif

#include "hash_functions.h"
#include "common.h"
#include "libforestdb/fdb_errors.h"
#include "hash.h"
#include "list.h"
#include "blockcache.h"
#include "avltree.h"
#include "atomic.h"

#include "memleak.h"

#ifdef __DEBUG
#ifndef __DEBUG_BCACHE
    #undef DBG
    #undef DBGCMD
    #undef DBGSW
    #define DBG(...)
    #define DBGCMD(...)
    #define DBGSW(n, ...)
#endif
#endif

// global lock
static spin_t bcache_lock;

// hash table for filename
static struct hash fnamedic;

// free block list
static volatile size_t freelist_count;
static struct list freelist;
static spin_t freelist_lock;

static const size_t MAX_VICTIM_SELECTIONS = 5;

// file structure list
static size_t num_files;
static size_t file_array_capacity;
static fnamedic_item ** file_list;
static struct list file_zombies;
static rw_spin_t filelist_lock; // Reader-Writer spinlock for the file list.

//static struct list cleanlist, dirtylist;
//static uint64_t nfree, nclean, ndirty;
static uint64_t bcache_nblock;

static int bcache_blocksize;
static size_t bcache_flush_unit;

struct bcache_shard {
    spin_t lock;
    // list for clean blocks
    struct list cleanlist;
    // tree for normal dirty blocks
    struct avl_tree tree;
    // tree for index nodes
    struct avl_tree tree_idx;
    // hash table for block lookup
    struct hash hashtable;
    // list elem for shard LRU
    struct list_elem le;
};

struct fnamedic_item {
    char *filename;
    uint16_t filename_len;
    uint32_t hash;

    // current opened filemgr instance
    // (can be changed on-the-fly when file is closed and re-opened)
    struct filemgr *curfile;

    // Shards of the block cache for a file.
    struct bcache_shard *shards;

    // list elem for FILE_ZOMBIE
    struct list_elem le;
    // hash elem for FNAMEDIC
    struct hash_elem hash_elem;

    atomic_uint32_t ref_count;
    atomic_uint64_t nvictim;
    atomic_uint64_t nitems;
    atomic_uint64_t nimmutable;
    atomic_uint64_t access_timestamp;
    size_t num_shards;
};

#define BCACHE_DIRTY (0x1)
#define BCACHE_IMMUTABLE (0x2)
#define BCACHE_FREE (0x4)

static void *buffercache_addr = NULL;

struct bcache_item {
    // BID
    bid_t bid;
    // contents address
    void *addr;
    // hash elem for lookup hash table
    struct hash_elem hash_elem;
    // list elem for {free, clean, dirty} lists
    struct list_elem list_elem;
    // flag
    uint8_t flag;
    // score
    uint8_t score;
};

struct dirty_item {
    struct bcache_item *item;
    struct avl_node avl;
};

INLINE int _dirty_cmp(struct avl_node *a, struct avl_node *b, void *aux)
{
    struct dirty_item *aa, *bb;
    aa = _get_entry(a, struct dirty_item, avl);
    bb = _get_entry(b, struct dirty_item, avl);

    #ifdef __BIT_CMP
        return _CMP_U64(aa->item->bid , bb->item->bid);

    #else
        if (aa->item->bid < bb->item->bid) return -1;
        else if (aa->item->bid > bb->item->bid) return 1;
        else return 0;

    #endif
}

INLINE uint32_t _fname_hash(struct hash *hash, struct hash_elem *e)
{
    struct fnamedic_item *item;
    item = _get_entry(e, struct fnamedic_item, hash_elem);
    return item->hash % ((unsigned)(BCACHE_NDICBUCKET));
}

INLINE int _fname_cmp(struct hash_elem *a, struct hash_elem *b)
{
    size_t len;
    struct fnamedic_item *aa, *bb;
    aa = _get_entry(a, struct fnamedic_item, hash_elem);
    bb = _get_entry(b, struct fnamedic_item, hash_elem);

    if (aa->filename_len == bb->filename_len) {
        return memcmp(aa->filename, bb->filename, aa->filename_len);
    }else {
        len = MIN(aa->filename_len , bb->filename_len);
        int cmp = memcmp(aa->filename, bb->filename, len);
        if (cmp != 0) return cmp;
        else {
            return (int)((int)aa->filename_len - (int)bb->filename_len);
        }
    }
}

INLINE uint32_t _bcache_hash(struct hash *hash, struct hash_elem *e)
{
    struct bcache_item *item = _get_entry(e, struct bcache_item, hash_elem);
    return (item->bid) % ((uint32_t)BCACHE_NBUCKET);
}

INLINE int _bcache_cmp(struct hash_elem *a, struct hash_elem *b)
{
    struct bcache_item *aa, *bb;
    aa = _get_entry(a, struct bcache_item, hash_elem);
    bb = _get_entry(b, struct bcache_item, hash_elem);

    #ifdef __BIT_CMP

        return _CMP_U64(aa->bid, bb->bid);

    #else

        if (aa->bid == bb->bid) return 0;
        else if (aa->bid < bb->bid) return -1;
        else return 1;

    #endif
}

#define _list_empty(list) (list.head == NULL)
#define _tree_empty(tree) (tree.root == NULL)

static void _acquire_all_shard_locks(struct fnamedic_item *fname) {
    size_t i = 0;
    for (; i < fname->num_shards; ++i) {
        spin_lock(&fname->shards[i].lock);
    }
}

static void _release_all_shard_locks(struct fnamedic_item *fname) {
    size_t i = 0;
    for (; i < fname->num_shards; ++i) {
        spin_unlock(&fname->shards[i].lock);
    }
}

static bool _file_empty(struct fnamedic_item *fname) {
    bool empty = true;
    size_t i = 0;
    _acquire_all_shard_locks(fname);
    for (; i < fname->num_shards; ++i) {
        if (!(_list_empty(fname->shards[i].cleanlist) &&
              _tree_empty(fname->shards[i].tree) &&
              _tree_empty(fname->shards[i].tree_idx))) {
            empty = false;
            break;
        }
    }
    _release_all_shard_locks(fname);
    return empty;
}

INLINE bool _shard_empty(struct bcache_shard *bshard) {
    // Caller should grab the shard lock before calling this function.
    return _list_empty(bshard->cleanlist) &&
           _tree_empty(bshard->tree) &&
           _tree_empty(bshard->tree_idx);
}

struct fnamedic_item *_bcache_get_victim()
{
    struct fnamedic_item *ret = NULL;
    uint64_t min_timestamp = (uint64_t) -1;
    uint64_t victim_timestamp;
    int victim_idx;
    size_t num_attempts;

    rw_spin_read_lock(&filelist_lock);
    // Pick the victim that has the smallest access timestamp among files randomly selected.
    num_attempts = num_files / 10 + 1;
     if (num_attempts > MAX_VICTIM_SELECTIONS) {
         num_attempts = MAX_VICTIM_SELECTIONS;
     } else {
         if(num_attempts == 1 && num_files > 1) {
             ++num_attempts;
         }
     }
     for (size_t i = 0; i < num_attempts && num_files; ++i) {
         victim_idx = rand() % num_files;
         victim_timestamp = atomic_get_uint64_t(&file_list[victim_idx]->access_timestamp);
         if (victim_timestamp < min_timestamp &&
             atomic_get_uint64_t(&file_list[victim_idx]->nitems)) {
             min_timestamp = victim_timestamp;
             ret = file_list[victim_idx];
         }
     }

    if (ret) {
        atomic_incr_uint32_t(&ret->ref_count);
    }
    rw_spin_read_unlock(&filelist_lock);

    return ret;
}

static struct bcache_item *_bcache_alloc_freeblock()
{
    struct list_elem *e = NULL;
    struct bcache_item *item;

    spin_lock(&freelist_lock);
    e = list_pop_front(&freelist);
    if (e) {
        freelist_count--;
    }
    spin_unlock(&freelist_lock);

    if (e) {
        item = _get_entry(e, struct bcache_item, list_elem);
        return item;
    }
    return NULL;
}

static void _bcache_release_freeblock(struct bcache_item *item)
{
    spin_lock(&freelist_lock);
    item->flag = BCACHE_FREE;
    item->score = 0;
    list_push_front(&freelist, &item->list_elem);
    freelist_count++;
    spin_unlock(&freelist_lock);
}

static struct fnamedic_item *_next_dead_fname_zombie(void) {
    struct list_elem *e;
    struct fnamedic_item *fname_item;
    bool found = false;
    rw_spin_write_lock(&filelist_lock);
    e = list_begin(&file_zombies);
    while (e) {
        fname_item = _get_entry(e, struct fnamedic_item, le);
        if (atomic_get_uint32_t(&fname_item->ref_count) == 0) {
            list_remove(&file_zombies, e);
            found = true;
            break;
        } else {
            e = list_next(e);
        }
    }
    rw_spin_write_unlock(&filelist_lock);
    return found ? fname_item : NULL;
}

static void _fname_free(struct fnamedic_item *fname);

static void _garbage_collect_zombie_fnames(void) {
    struct fnamedic_item *fname_item = _next_dead_fname_zombie();
    while (fname_item) {
        _fname_free(fname_item);
        fname_item = _next_dead_fname_zombie();
    }
}

struct dirty_bid {
    bid_t bid;
    struct avl_node avl;
};

INLINE int _dirty_bid_cmp(struct avl_node *a, struct avl_node *b, void *aux)
{
    struct dirty_bid *aa, *bb;
    aa = _get_entry(a, struct dirty_bid, avl);
    bb = _get_entry(b, struct dirty_bid, avl);

    #ifdef __BIT_CMP
        return _CMP_U64(aa->bid , bb->bid);

    #else
        if (aa->bid < bb->bid) return -1;
        else if (aa->bid > bb->bid) return 1;
        else return 0;

    #endif
}

static void _free_dirty_bids(struct dirty_bid **dirty_bids, size_t n) {
    size_t i = 0;
    for (; i < n; ++i) {
        if (dirty_bids[i]) {
            mempool_free(dirty_bids[i]);
        }
    }
}

// Flush some consecutive or all dirty blocks for a given file and
// move them to the clean list.
static fdb_status _flush_dirty_blocks(struct fnamedic_item *fname_item,
                                      bool sync, bool flush_all,
                                      bool immutables_only)
{
    void *buf = NULL;
    struct list_elem *prevhead = NULL;
    struct avl_tree *cur_tree = NULL;
    struct avl_node *node = NULL;
    struct dirty_bid *dbid = NULL;
    uint64_t count = 0;
    ssize_t ret = 0;
    bid_t start_bid = 0, prev_bid = 0;
    void *ptr = NULL;
    uint8_t marker = 0x0;
    fdb_status status = FDB_RESULT_SUCCESS;
    bool o_direct = false;
    bool data_block_completed = false;
    struct avl_tree dirty_blocks; // Cross-shard dirty block list for sequential writes.

    if (fname_item->curfile->config->flag & _ARCH_O_DIRECT) {
        o_direct = true;
    }

    // scan and write back dirty blocks sequentially for O_DIRECT option.
    if (sync && o_direct) {
        malloc_align(buf, FDB_SECTOR_SIZE, bcache_flush_unit);
        _acquire_all_shard_locks(fname_item);
    }

    prev_bid = start_bid = BLK_NOT_FOUND;
    count = 0;

    avl_init(&dirty_blocks, NULL);

    // Try to flush the dirty data blocks first and then index blocks.
    size_t i = 0;
    bool consecutive_blocks = true;
    struct dirty_bid **dirty_bids = alca(struct dirty_bid *, fname_item->num_shards);
    memset(dirty_bids, 0x0, sizeof(dirty_bid *) * fname_item->num_shards);
    while (1) {
        if (!(node = avl_first(&dirty_blocks))) {
            for (i = 0; i < fname_item->num_shards; ++i) {
                if (!(sync && o_direct)) {
                    spin_lock(&fname_item->shards[i].lock);
                }
                if (!data_block_completed) {
                    node = avl_first(&fname_item->shards[i].tree);
                } else {
                    node = avl_first(&fname_item->shards[i].tree_idx);
                }
                if (node) {
                    struct dirty_item *ditem = _get_entry(node,
                                                struct dirty_item, avl);
                    if (!immutables_only || // don't load mutable items
                        ditem->item->flag & BCACHE_IMMUTABLE) {
                        if (!dirty_bids[i]) {
                            dirty_bids[i] = (struct dirty_bid *)
                                mempool_alloc(sizeof(struct dirty_bid));
                        }
                        dirty_bids[i]->bid = ditem->item->bid;
                        avl_insert(&dirty_blocks, &dirty_bids[i]->avl,
                                   _dirty_bid_cmp);
                    }
                }
                if (!(sync && o_direct)) {
                    spin_unlock(&fname_item->shards[i].lock);
                }
            }
            if (!(node = avl_first(&dirty_blocks))) {
                if (!data_block_completed) {
                    data_block_completed = true;
                    if (count > 0 && !flush_all) {
                        // Finished flushing some dirty data blocks.
                        // Not move over to the dirty index block list because
                        // flush_all is not requestd.
                        break;
                    }
                    continue;
                } else {
                    break;
                }
            }
        }

        dbid = _get_entry(node, struct dirty_bid, avl);

        size_t shard_num = dbid->bid % fname_item->num_shards;
        if (!(sync && o_direct)) {
            spin_lock(&fname_item->shards[shard_num].lock);
        }
        if (!data_block_completed) {
            cur_tree = &fname_item->shards[shard_num].tree;
        } else {
            cur_tree = &fname_item->shards[shard_num].tree_idx;
        }

        struct dirty_item *dirty_block = NULL;
        bool item_exist = false;
        node = avl_first(cur_tree);
        if (node) {
            dirty_block = _get_entry(node, struct dirty_item, avl);
            if (dbid->bid == dirty_block->item->bid) {
                item_exist = true;
            }
        }
        // remove from the cross-shard dirty block list.
        avl_remove(&dirty_blocks, &dbid->avl);
        if (!item_exist) {
            // The original first item in the shard dirty block list was removed.
            // Grab the next one from the cross-shard dirty block list.
            if (!(sync && o_direct)) {
                spin_unlock(&fname_item->shards[shard_num].lock);
            }
            if (immutables_only &&
                !atomic_get_uint64_t(&fname_item->nimmutable)) {
                break;
            }
            continue;
        }

        consecutive_blocks = true;
        // if BID of next dirty block is not consecutive .. stop
        if (dirty_block->item->bid != prev_bid + 1 && prev_bid != BLK_NOT_FOUND &&
            sync) {
            if (flush_all) {
                consecutive_blocks = false;
            } else {
                if (!(sync && o_direct)) {
                    spin_unlock(&fname_item->shards[shard_num].lock);
                }
                break;
            }
        }
        // set START_BID if this is the start block for a single batch write.
        if (start_bid == BLK_NOT_FOUND) {
            start_bid = dirty_block->item->bid;
        }
        // set PREV_BID and go to next block
        prev_bid = dirty_block->item->bid;

        // set PTR and get block MARKER
        ptr = dirty_block->item->addr;
        marker = *((uint8_t*)(ptr) + bcache_blocksize-1);

        node = avl_next(node);
        // Get the next dirty block from the victim shard and insert it into
        // the cross-shard dirty block list.
        if (node) {
            struct dirty_item *ditem = _get_entry(node, struct dirty_item,
                                                  avl);
            if (!immutables_only || ditem->item->flag & BCACHE_IMMUTABLE) {
                dbid->bid = ditem->item->bid;
                avl_insert(&dirty_blocks, &dbid->avl, _dirty_bid_cmp);
            }
        }

        // remove from the shard dirty block list.
        avl_remove(cur_tree, &dirty_block->avl);
        if (dirty_block->item->flag & BCACHE_IMMUTABLE) {
            atomic_decr_uint64_t(&fname_item->nimmutable);
            if (!(sync && o_direct)) {
                spin_unlock(&fname_item->shards[shard_num].lock);
            }
        }

        if (sync) {
            // copy to buffer
#ifdef __CRC32
            if (marker == BLK_MARKER_BNODE) {
                // b-tree node .. calculate crc32 and put it into the block
                memset((uint8_t *)(ptr) + BTREE_CRC_OFFSET,
                       0xff, BTREE_CRC_FIELD_LEN);
                uint32_t crc = get_checksum(reinterpret_cast<const uint8_t*>(ptr),
                                            bcache_blocksize,
                                            fname_item->curfile->crc_mode);
                crc = _endian_encode(crc);
                memcpy((uint8_t *)(ptr) + BTREE_CRC_OFFSET, &crc, sizeof(crc));
            }
#endif
            if (o_direct) {
                if (count > 0 && !consecutive_blocks) {
                    size_t bytes_written;
                    // Note that this path can be only executed in flush_all case.
                    bytes_written = (size_t)filemgr_write_blocks(fname_item->curfile,
                                                                 buf, count, start_bid);
                    if (bytes_written != count * bcache_blocksize) {
                        count = 0;
                        status = FDB_RESULT_WRITE_FAIL;
                        break;
                    }
                    // Start a new batch again.
                    count = 0;
                    start_bid = dirty_block->item->bid;
                }
                memcpy((uint8_t *)(buf) + count*bcache_blocksize,
                       dirty_block->item->addr, bcache_blocksize);
            } else {
                ret = filemgr_write_blocks(fname_item->curfile,
                                           dirty_block->item->addr,
                                           1,
                                           dirty_block->item->bid);
                if (ret != bcache_blocksize) {
                    if (!(dirty_block->item->flag & BCACHE_IMMUTABLE) &&
                        !(sync && o_direct)) {
                        spin_unlock(&fname_item->shards[shard_num].lock);
                    }
                    status = FDB_RESULT_WRITE_FAIL;
                    break;
                }
            }
        }

        if (!(sync && o_direct)) {
            if (dirty_block->item->flag & BCACHE_IMMUTABLE) {
                spin_lock(&fname_item->shards[shard_num].lock);
            }
        }

        dirty_block->item->flag &= ~(BCACHE_DIRTY);
        dirty_block->item->flag &= ~(BCACHE_IMMUTABLE);
        // move to the shard clean block list.
        prevhead = fname_item->shards[shard_num].cleanlist.head;
        (void)prevhead;
        list_push_front(&fname_item->shards[shard_num].cleanlist,
                        &dirty_block->item->list_elem);

        fdb_assert(!(dirty_block->item->flag & BCACHE_FREE),
                   dirty_block->item->flag, BCACHE_FREE);
        fdb_assert(dirty_block->item->list_elem.prev == NULL &&
                   prevhead == dirty_block->item->list_elem.next,
                   prevhead, dirty_block->item->list_elem.next);
        mempool_free(dirty_block);

        if (!(sync && o_direct)) {
            spin_unlock(&fname_item->shards[shard_num].lock);
        }

        count++;
        if (count*bcache_blocksize >= bcache_flush_unit && sync) {
            if (flush_all) {
                if (o_direct) {
                    ret = filemgr_write_blocks(fname_item->curfile, buf, count, start_bid);
                    if ((size_t)ret != count * bcache_blocksize) {
                        count = 0;
                        status = FDB_RESULT_WRITE_FAIL;
                        break;
                    }
                    count = 0;
                    start_bid = BLK_NOT_FOUND;
                    prev_bid = BLK_NOT_FOUND;
                }
            } else {
                break;
            }
        }
    }

    // synchronize
    if (sync && o_direct) {
        if (count > 0) {
            ret = filemgr_write_blocks(fname_item->curfile, buf, count, start_bid);
            if ((size_t)ret != count * bcache_blocksize) {
                status = FDB_RESULT_WRITE_FAIL;
            }
        }
        _release_all_shard_locks(fname_item);
        free_align(buf);
    }

    _free_dirty_bids(dirty_bids, fname_item->num_shards);
    return status;
}

// perform eviction
static struct list_elem * _bcache_evict(struct fnamedic_item *curfile)
{
    size_t n_evict;
    struct list_elem *e = NULL;
    struct bcache_item *item;
    struct fnamedic_item *victim = NULL;

    // We don't need to grab the global buffer cache lock here because
    // the file's buffer cache instance (fnamedic_item) can be freed only if
    // there are no database handles opened for that file.

    while (victim == NULL) {
        // select a victim file
        victim = _bcache_get_victim();
        while(victim) {
            // check whether this file has at least one block to be evictied
            if (atomic_get_uint64_t(&victim->nitems)) {
                // select this file as victim
                break;
            } else {
                atomic_decr_uint32_t(&victim->ref_count);
                victim = NULL; // Try to select a victim again
            }
        }
    }
    fdb_assert(victim, victim, NULL);

    atomic_incr_uint64_t(&victim->nvictim);

    // select the clean blocks from the victim file
    n_evict = 0;
    while(n_evict < BCACHE_EVICT_UNIT) {
        size_t num_shards = victim->num_shards;
        size_t i = random(num_shards);
        bool found_victim_shard = false;
        bcache_shard *bshard = NULL;

        for (size_t to_visit = num_shards; to_visit; --to_visit) {
            i = (i + 1) % num_shards; // Round robin over empty shards..
            bshard = &victim->shards[i];
            spin_lock(&bshard->lock);
            if (_shard_empty(bshard)) {
                spin_unlock(&bshard->lock);
                continue;
            }
            e = list_pop_back(&bshard->cleanlist);
            if(!e) {
                spin_unlock(&bshard->lock);
                // When the victim shard has no clean block, evict some dirty blocks
                // from shards.
                if (_flush_dirty_blocks(victim, true, false, false)
                    != FDB_RESULT_SUCCESS) {
                    atomic_decr_uint32_t(&victim->ref_count);
                    return NULL;
                }
                continue; // Select a victim shard again.
            }

            item = _get_entry(e, struct bcache_item, list_elem);
#ifdef __BCACHE_SECOND_CHANCE
            // repeat until zero-score item is found
            if (item->score == 0) {
                found_victim_shard = true;
                break;
            } else {
                // give second chance to the item
                item->score--;
                list_push_front(&bshard->cleanlist, &item->list_elem);
                spin_unlock(&bshard->lock);
            }
#else
            found_victim_shard = true;
            break;
#endif
        }
        if (!found_victim_shard) {
            // We couldn't find any non-empty shards even after 'num_shards'
            // attempts.
            // The file is *likely* empty. Note that it is OK to return NULL
            // even if the file is not empty because the caller will retry again.
            atomic_decr_uint32_t(&victim->ref_count);
            return NULL;
        }

        atomic_decr_uint64_t(&victim->nitems);
        // remove from hash and insert into freelist
        hash_remove(&bshard->hashtable, &item->hash_elem);
        // add to freelist
        _bcache_release_freeblock(item);
        n_evict++;

        spin_unlock(&bshard->lock);

        if (atomic_get_uint64_t(&victim->nitems) == 0) {
            break;
        }
    }

    atomic_decr_uint32_t(&victim->ref_count);
    return &item->list_elem;
}

static struct fnamedic_item * _fname_create(struct filemgr *file) {
    // TODO: we MUST NOT directly read file sturcture

    struct fnamedic_item *fname_new;
    // Before we create a new filename entry, garbage collect zombies
    _garbage_collect_zombie_fnames();
    fname_new = (struct fnamedic_item *)malloc(sizeof(struct fnamedic_item));

    fname_new->filename_len = strlen(file->filename);
    fname_new->filename = (char *)malloc(fname_new->filename_len + 1);
    memcpy(fname_new->filename, file->filename, fname_new->filename_len);
    fname_new->filename[fname_new->filename_len] = 0;

    // calculate hash value
    fname_new->hash = get_checksum(reinterpret_cast<const uint8_t*>(fname_new->filename),
                                   fname_new->filename_len,
                                   file->crc_mode);
    fname_new->curfile = file;
    atomic_init_uint64_t(&fname_new->nvictim, 0);
    atomic_init_uint64_t(&fname_new->nitems, 0);
    atomic_init_uint64_t(&fname_new->nimmutable, 0);
    atomic_init_uint32_t(&fname_new->ref_count, 0);
    atomic_init_uint64_t(&fname_new->access_timestamp, 0);
    if (file->config->num_bcache_shards) {
        fname_new->num_shards = file->config->num_bcache_shards;
    } else {
        fname_new->num_shards = DEFAULT_NUM_BCACHE_PARTITIONS;
    }
    // For random eviction among shards
    randomize();

    fname_new->shards = (bcache_shard *)
        malloc(sizeof(struct bcache_shard) * fname_new->num_shards);
    size_t i = 0;
    for (; i < fname_new->num_shards; ++i) {
        // initialize tree
        avl_init(&fname_new->shards[i].tree, NULL);
        avl_init(&fname_new->shards[i].tree_idx, NULL);
        // initialize clean list
        list_init(&fname_new->shards[i].cleanlist);
        // initialize hash table
        hash_init(&fname_new->shards[i].hashtable, BCACHE_NBUCKET,
                  _bcache_hash, _bcache_cmp);
        spin_init(&fname_new->shards[i].lock);
    }

    // insert into fname dictionary
    hash_insert(&fnamedic, &fname_new->hash_elem);
    file->bcache = fname_new;

    rw_spin_write_lock(&filelist_lock);
    if (num_files == file_array_capacity) {
        file_array_capacity *= 2;
        file_list = (struct fnamedic_item **) realloc(file_list, file_array_capacity);
    }
    file_list[num_files++] = fname_new;
    rw_spin_write_unlock(&filelist_lock);

    return fname_new;
}

static bool _fname_try_free(struct fnamedic_item *fname)
{
    bool ret = true;

    rw_spin_write_lock(&filelist_lock);
    // Remove from the file list array
    bool found = false;
    for (size_t i = 0; i < num_files; ++i) {
        if (file_list[i] == fname) {
            found = true;
        }
        if (found && (i+1 < num_files)) {
            file_list[i] = file_list[i+1];
        }
    }
    if (!found) {
        rw_spin_write_unlock(&filelist_lock);
        DBG("Error: fnamedic_item instance for a file '%s' can't be "
            "found in the buffer cache's file list.\n", fname->filename);
        return false;
    }

    file_list[num_files - 1] = NULL;
    --num_files;
    if (atomic_get_uint32_t(&fname->ref_count) != 0) {
        // This item is a victim by another thread's _bcache_evict()
        list_push_front(&file_zombies, &fname->le);
        ret = false; // Delay deletion
    }

    rw_spin_write_unlock(&filelist_lock);
    return ret;
}

static void _fname_free(struct fnamedic_item *fname)
{
    // file must be empty
    if (!_file_empty(fname)) {
        DBG("Warning: failed to free fnamedic_item instance for a file '%s' "
            "because the fnamedic_item instance is not empty!\n",
            fname->filename);
        return;
    }
    uint32_t ref_count = atomic_get_uint32_t(&fname->ref_count);
    if (ref_count != 0) {
        DBG("Warning: failed to free fnamedic_item instance for a file '%s' "
            "because its ref counter is not zero!\n",
            fname->filename);
        return;
    }

    // free hash
    size_t i = 0;
    for (; i < fname->num_shards; ++i) {
        hash_free(&fname->shards[i].hashtable);
        spin_destroy(&fname->shards[i].lock);
    }

    free(fname->shards);
    free(fname->filename);
    atomic_destroy_uint32_t(&fname->ref_count);
    atomic_destroy_uint64_t(&fname->nvictim);
    atomic_destroy_uint64_t(&fname->nitems);
    atomic_destroy_uint64_t(&fname->nimmutable);
    atomic_destroy_uint64_t(&fname->access_timestamp);
    free(fname);
}

INLINE void _bcache_set_score(struct bcache_item *item)
{
#ifdef __CRC32
    uint8_t marker;

    // set PTR and get block MARKER
    marker = *((uint8_t*)(item->addr) + bcache_blocksize-1);
    if (marker == BLK_MARKER_BNODE ) {
        // b-tree node .. set item's score to 1
        item->score = 1;
    } else {
        item->score = 0;
    }
#endif
}

int bcache_read(struct filemgr *file, bid_t bid, void *buf)
{
    struct hash_elem *h;
    struct bcache_item *item;
    struct bcache_item query;
    struct fnamedic_item *fname;

    // Note that we don't need to grab bcache_lock here as the block cache
    // is already created and binded when the file is created or opened for
    // the first time.
    fname = file->bcache;

    if (fname) {
        // file exists
        // set query
        query.bid = bid;
        // Update the access timestamp.
        struct timeval tp;
        gettimeofday(&tp, NULL); // TODO: Need to implement a better way of
                                 // getting the timestamp to avoid the overhead of
                                 // gettimeofday()
        atomic_store_uint64_t(&fname->access_timestamp,
                              (uint64_t) (tp.tv_sec * 1000000 + tp.tv_usec));

        size_t shard_num = bid % fname->num_shards;
        spin_lock(&fname->shards[shard_num].lock);

        // search shard hash table
        h = hash_find(&fname->shards[shard_num].hashtable, &query.hash_elem);
        if (h) {
            // cache hit
            item = _get_entry(h, struct bcache_item, hash_elem);
            if (item->flag & BCACHE_FREE) {
                spin_unlock(&fname->shards[shard_num].lock);
                DBG("Warning: failed to read the buffer cache entry for a file '%s' "
                    "because the entry belongs to the free list!\n",
                    file->filename);
                return 0;
            }

            // move the item to the head of list if the block is clean
            // (don't care if the block is dirty)
            if (!(item->flag & BCACHE_DIRTY)) {
                // TODO: Scanning the list would cause some overhead. We need to devise
                // the better data structure to provide a fast lookup for the clean list.
                list_remove(&fname->shards[shard_num].cleanlist, &item->list_elem);
                list_push_front(&fname->shards[shard_num].cleanlist, &item->list_elem);
            }

            memcpy(buf, item->addr, bcache_blocksize);
            _bcache_set_score(item);

            spin_unlock(&fname->shards[shard_num].lock);

            return bcache_blocksize;
        } else {
            // cache miss
            spin_unlock(&fname->shards[shard_num].lock);
        }
    }

    // does not exist .. cache miss
    return 0;
}

bool bcache_invalidate_block(struct filemgr *file, bid_t bid)
{
    struct hash_elem *h;
    struct bcache_item *item;
    struct bcache_item query;
    struct fnamedic_item *fname;
    bool ret = false;

    // Note that we don't need to grab bcache_lock here as the block cache
    // is already created and binded when the file is created or opened for
    // the first time.
    fname = file->bcache;

    if (fname) {
        // file exists
        // set query
        query.bid = bid;
        // Update the access timestamp.
        struct timeval tp;
        gettimeofday(&tp, NULL);
        atomic_store_uint64_t(&fname->access_timestamp,
                              (uint64_t) (tp.tv_sec * 1000000 + tp.tv_usec));

        size_t shard_num = bid % fname->num_shards;
        spin_lock(&fname->shards[shard_num].lock);

        // search BHASH
        h = hash_find(&fname->shards[shard_num].hashtable, &query.hash_elem);
        if (h) {
            // cache hit
            item = _get_entry(h, struct bcache_item, hash_elem);
            if (item->flag & BCACHE_FREE) {
                spin_unlock(&fname->shards[shard_num].lock);
                DBG("Warning: failed to invalidate the buffer cache entry for a file '%s' "
                    "because the entry belongs to the free list!\n",
                    file->filename);
                return false;
            }

            if (!(item->flag & BCACHE_DIRTY)) {
                atomic_decr_uint64_t(&fname->nitems);
                // only for clean blocks
                // remove from hash and insert into freelist
                hash_remove(&fname->shards[shard_num].hashtable, &item->hash_elem);
                // remove from clean list
                list_remove(&fname->shards[shard_num].cleanlist, &item->list_elem);
                spin_unlock(&fname->shards[shard_num].lock);

                // add to freelist
                _bcache_release_freeblock(item);
                ret = true;
            } else {
                item->flag |= BCACHE_IMMUTABLE; // (stale index node block)
                atomic_incr_uint64_t(&fname->nimmutable);
                spin_unlock(&fname->shards[shard_num].lock);
            }
        } else {
            // cache miss
            spin_unlock(&fname->shards[shard_num].lock);
        }
    }
    return ret;
}

int bcache_write(struct filemgr *file,
                 bid_t bid,
                 void *buf,
                 bcache_dirty_t dirty,
                 bool final_write)
{
    struct hash_elem *h = NULL;
    struct bcache_item *item;
    struct bcache_item query;
    struct fnamedic_item *fname_new;

    fname_new = file->bcache;
    if (fname_new == NULL) {
        spin_lock(&bcache_lock);
        fname_new = file->bcache;
        if (fname_new == NULL) {
            // filename doesn't exist in filename dictionary .. create
            fname_new = _fname_create(file);
        }
        spin_unlock(&bcache_lock);
    }

    // Update the access timestamp.
    struct timeval tp;
    gettimeofday(&tp, NULL);
    atomic_store_uint64_t(&fname_new->access_timestamp,
                          (uint64_t) (tp.tv_sec * 1000000 + tp.tv_usec));

    size_t shard_num = bid % fname_new->num_shards;
    // set query
    query.bid = bid;

    spin_lock(&fname_new->shards[shard_num].lock);

    // search hash table
    h = hash_find(&fname_new->shards[shard_num].hashtable, &query.hash_elem);
    if (h == NULL) {
        // cache miss
        // get a free block
        while ((item = _bcache_alloc_freeblock()) == NULL) {
            // no free block .. perform eviction
            spin_unlock(&fname_new->shards[shard_num].lock);

            _bcache_evict(fname_new);

            spin_lock(&fname_new->shards[shard_num].lock);
        }

        // re-search hash table
        h = hash_find(&fname_new->shards[shard_num].hashtable, &query.hash_elem);
        if (h == NULL) {
            // insert into hash table
            item->bid = bid;
            item->flag = BCACHE_FREE;
            hash_insert(&fname_new->shards[shard_num].hashtable, &item->hash_elem);
            h = &item->hash_elem;
        } else {
            // insert into freelist again
            _bcache_release_freeblock(item);
            item = _get_entry(h, struct bcache_item, hash_elem);
        }
    } else {
        item = _get_entry(h, struct bcache_item, hash_elem);
    }

    fdb_assert(h, h, NULL);

    if (item->flag & BCACHE_FREE) {
        atomic_incr_uint64_t(&fname_new->nitems);
    }

    // remove from the list if the block is in clean list
    if (!(item->flag & BCACHE_DIRTY) && !(item->flag & BCACHE_FREE)) {
        list_remove(&fname_new->shards[shard_num].cleanlist, &item->list_elem);
    }
    item->flag &= ~BCACHE_FREE;

    if (dirty == BCACHE_REQ_DIRTY) {
        // DIRTY request
        // to avoid re-insert already existing item into tree
        if (!(item->flag & BCACHE_DIRTY)) {
            // dirty block
            // insert into tree
            struct dirty_item *ditem;
            uint8_t marker;

            ditem = (struct dirty_item *)
                    mempool_alloc(sizeof(struct dirty_item));
            ditem->item = item;

            marker = *((uint8_t*)buf + bcache_blocksize-1);
            if (marker == BLK_MARKER_BNODE) {
                // b-tree node
                avl_insert(&fname_new->shards[shard_num].tree_idx, &ditem->avl, _dirty_cmp);
            } else {
                if (final_write) {
                    item->flag |= BCACHE_IMMUTABLE; // (fully written doc block)
                    atomic_incr_uint64_t(&fname_new->nimmutable);
                }
                avl_insert(&fname_new->shards[shard_num].tree, &ditem->avl,
                           _dirty_cmp);
            }
        }
        item->flag |= BCACHE_DIRTY;
    } else {
        // CLEAN request
        // insert into clean list only when it was originally clean
        if (!(item->flag & BCACHE_DIRTY)) {
            list_push_front(&fname_new->shards[shard_num].cleanlist, &item->list_elem);
            item->flag &= ~(BCACHE_DIRTY);
        }
    }

    memcpy(item->addr, buf, bcache_blocksize);
    _bcache_set_score(item);

    spin_unlock(&fname_new->shards[shard_num].lock);

    return bcache_blocksize;
}

int bcache_write_partial(struct filemgr *file,
                         bid_t bid,
                         void *buf,
                         size_t offset,
                         size_t len,
                         bool final_write)
{
    struct hash_elem *h;
    struct bcache_item *item;
    struct bcache_item query;
    struct fnamedic_item *fname_new;

    fname_new = file->bcache;
    if (fname_new == NULL) {
        spin_lock(&bcache_lock);
        fname_new = file->bcache;
        if (fname_new == NULL) {
            // filename doesn't exist in filename dictionary .. create
            fname_new = _fname_create(file);
        }
        spin_unlock(&bcache_lock);
    }

    // Update the access timestamp.
    struct timeval tp;
    gettimeofday(&tp, NULL);
    atomic_store_uint64_t(&fname_new->access_timestamp,
                          (uint64_t) (tp.tv_sec * 1000000 + tp.tv_usec));

    size_t shard_num = bid % fname_new->num_shards;
    // set query
    query.bid = bid;

    spin_lock(&fname_new->shards[shard_num].lock);

    // search hash table
    h = hash_find(&fname_new->shards[shard_num].hashtable, &query.hash_elem);
    if (h == NULL) {
        // cache miss .. partial write fail .. return 0
        spin_unlock(&fname_new->shards[shard_num].lock);
        return 0;

    } else {
        // cache hit .. get the block
        item = _get_entry(h, struct bcache_item, hash_elem);
    }

    if (item->flag & BCACHE_FREE) {
        DBG("Warning: failed to write on the buffer cache entry for a file '%s' "
            "because the entry belongs to the free list!\n",
            file->filename);
        return 0;
    }

    // check whether this is dirty block
    // to avoid re-insert already existing item into tree
    if (!(item->flag & BCACHE_DIRTY)) {
        // this block was clean block
        uint8_t marker;
        struct dirty_item *ditem;

        // remove from clean list
        list_remove(&fname_new->shards[shard_num].cleanlist, &item->list_elem);

        ditem = (struct dirty_item *)mempool_alloc(sizeof(struct dirty_item));
        ditem->item = item;

        // insert into tree
        marker = *((uint8_t*)item->addr + bcache_blocksize-1);
        if (marker == BLK_MARKER_BNODE ) {
            // b-tree node
            avl_insert(&fname_new->shards[shard_num].tree_idx, &ditem->avl, _dirty_cmp);
        } else {
            avl_insert(&fname_new->shards[shard_num].tree, &ditem->avl,
                       _dirty_cmp);
            if (final_write) {
                item->flag |= BCACHE_IMMUTABLE; // (fully written doc block)
                atomic_incr_uint64_t(&fname_new->nimmutable);
            }
        }
    } else if (!(item->flag & BCACHE_IMMUTABLE)) {
        if (final_write) {
            item->flag |= BCACHE_IMMUTABLE; // (fully written doc block)
            atomic_incr_uint64_t(&fname_new->nimmutable);
        }
    }

    // always set this block as dirty
    item->flag |= BCACHE_DIRTY;

    memcpy((uint8_t *)(item->addr) + offset, buf, len);
    _bcache_set_score(item);

    spin_unlock(&fname_new->shards[shard_num].lock);

    return len;
}

// flush and synchronize a batch of contiguous dirty immutable blocks in file
// dirty blocks will be changed to clean blocks (not discarded)
// Note: This function can be invoked as part of background flushing
fdb_status bcache_flush_immutable(struct filemgr *file)
{
    struct fnamedic_item *fname_item;
    fdb_status status = FDB_RESULT_SUCCESS;
    fname_item = file->bcache;
    if (fname_item) {
        status = _flush_dirty_blocks(fname_item, true, true, true);
    }
    return status;
}

// remove all dirty blocks of the FILE
// (they are only discarded and not written back)
void bcache_remove_dirty_blocks(struct filemgr *file)
{
    struct fnamedic_item *fname_item;

    fname_item = file->bcache;

    if (fname_item) {
        // Note that this function is only invoked as part of database file close or
        // removal when there are no database handles for a given file. Therefore,
        // we don't need to grab all the shard locks at once.

        // remove all dirty blocks
        _flush_dirty_blocks(fname_item, false, true, false);
    }
}

// remove all clean blocks of the FILE
void bcache_remove_clean_blocks(struct filemgr *file)
{
    struct list_elem *e;
    struct bcache_item *item;
    struct fnamedic_item *fname_item;

    fname_item = file->bcache;

    if (fname_item) {
        // Note that this function is only invoked as part of database file close or
        // removal when there are no database handles for a given file. Therefore,
        // we don't need to grab all the shard locks at once.

        // remove all clean blocks from each shard in a file.
        size_t i = 0;
        for (; i < fname_item->num_shards; ++i) {
            spin_lock(&fname_item->shards[i].lock);
            e = list_begin(&fname_item->shards[i].cleanlist);
            while(e){
                item = _get_entry(e, struct bcache_item, list_elem);
                // remove from clean list
                e = list_remove(&fname_item->shards[i].cleanlist, e);
                // remove from hash table
                hash_remove(&fname_item->shards[i].hashtable, &item->hash_elem);
                // insert into free list
                _bcache_release_freeblock(item);
            }
            spin_unlock(&fname_item->shards[i].lock);
        }
    }
}

// remove file from filename dictionary
// MUST sure that there is no dirty block belongs to this FILE
// (or memory leak occurs)
bool bcache_remove_file(struct filemgr *file)
{
    bool rv = false;
    struct fnamedic_item *fname_item;

    // Before proceeding with deletion, garbage collect zombie files
    _garbage_collect_zombie_fnames();
    fname_item = file->bcache;

    if (fname_item) {
        // acquire lock
        spin_lock(&bcache_lock);
        // file must be empty
        if (!_file_empty(fname_item)) {
            spin_unlock(&bcache_lock);
            DBG("Warning: failed to remove fnamedic_item instance for a file '%s' "
                "because the fnamedic_item instance is not empty!\n",
                file->filename);
            return rv;
        }

        // remove from fname dictionary hash table
        hash_remove(&fnamedic, &fname_item->hash_elem);
        spin_unlock(&bcache_lock);

        // We don't need to grab the file buffer cache's partition locks
        // at once because this function is only invoked when there are
        // no database handles that access the file.
        if (_fname_try_free(fname_item)) {
            _fname_free(fname_item); // no other callers accessing this file
            rv = true;
        } // else fnamedic_item is in use by _bcache_evict. Deletion delayed
    }
    return rv;
}

// flush and synchronize all dirty blocks of the FILE
// dirty blocks will be changed to clean blocks (not discarded)
fdb_status bcache_flush(struct filemgr *file)
{
    struct fnamedic_item *fname_item;
    fdb_status status = FDB_RESULT_SUCCESS;

    fname_item = file->bcache;

    if (fname_item) {
        // Note that this function is invoked as part of a commit operation while
        // the filemgr's lock is already grabbed by a committer.
        // Therefore, we don't need to grab all the shard locks at once.
        status = _flush_dirty_blocks(fname_item, true, true, false);
    }
    return status;
}

void bcache_init(int nblock, int blocksize)
{
    int i;
    struct bcache_item *item;
    uint8_t *block_ptr;

    list_init(&freelist);
    list_init(&file_zombies);

    hash_init(&fnamedic, BCACHE_NDICBUCKET, _fname_hash, _fname_cmp);

    bcache_blocksize = blocksize;
    bcache_flush_unit = BCACHE_FLUSH_UNIT;
    bcache_nblock = nblock;
    spin_init(&bcache_lock);
    spin_init(&freelist_lock);
    rw_spin_init(&filelist_lock);
    freelist_count = 0;

    num_files = 0;
    file_array_capacity = 4096; // Initial capacity of file list array.
    file_list = (fnamedic_item **) calloc(file_array_capacity, sizeof(fnamedic_item *));
    // Allocate entire buffer cache memory
    block_ptr = (uint8_t *)malloc((uint64_t)bcache_blocksize * nblock);
    buffercache_addr = block_ptr;

    for (i=0;i<nblock;++i){
        item = (struct bcache_item *)malloc(sizeof(struct bcache_item));

        item->bid = BLK_NOT_FOUND;
        item->flag = 0x0 | BCACHE_FREE;
        item->score = 0;
        item->addr = block_ptr;
        block_ptr += bcache_blocksize;

        list_push_front(&freelist, &item->list_elem);
        freelist_count++;
    }
}

uint64_t bcache_get_num_free_blocks()
{
    return freelist_count;
}

uint64_t bcache_get_num_blocks(struct filemgr *file)
{
    struct fnamedic_item *fname = file->bcache;
    if (fname) {
        return atomic_get_uint64_t(&fname->nitems);
    }
    return 0;
}

uint64_t bcache_get_num_immutable(struct filemgr *file)
{
    struct fnamedic_item *fname = file->bcache;
    if (fname) {
        return atomic_get_uint64_t(&fname->nimmutable);
    }
    return 0;

}

// LCOV_EXCL_START
void bcache_print_items()
{
    size_t n=1;
    size_t nfiles, nitems, nfileitems, nclean, ndirty;
    size_t scores[100], i, scores_local[100];
    size_t docs, bnodes;
    size_t docs_local, bnodes_local;
    uint8_t *ptr;

    nfiles = nitems = nfileitems = nclean = ndirty = 0;
    docs = bnodes = 0;
    memset(scores, 0, sizeof(size_t)*100);

    struct fnamedic_item *fname;
    struct bcache_item *item;
    struct dirty_item *dirty;
    struct list_elem *ee;
    struct avl_node *a;

    printf(" === Block cache statistics summary ===\n");
    printf("%3s %20s (%6s)(%6s)(c%6s d%6s)",
        "No", "Filename", "#Pages", "#Evict", "Clean", "Dirty");
#ifdef __CRC32
    printf("%6s%6s", "Doc", "Node");
#endif
    for (i=0;i<=n;++i) {
        printf("   [%d] ", (int)i);
    }
    printf("\n");

    for (size_t idx = 0; idx < num_files; ++idx) {
        fname = file_list[idx];
        memset(scores_local, 0, sizeof(size_t)*100);
        nfileitems = nclean = ndirty = 0;
        docs_local = bnodes_local = 0;

        size_t i = 0;
        for (; i < fname->num_shards; ++i) {
            ee = list_begin(&fname->shards[i].cleanlist);
            a = avl_first(&fname->shards[i].tree);

            while(ee){
                item = _get_entry(ee, struct bcache_item, list_elem);
                scores[item->score]++;
                scores_local[item->score]++;
                nitems++;
                nfileitems++;
                nclean++;
#ifdef __CRC32
                ptr = (uint8_t*)item->addr + bcache_blocksize - 1;
                switch (*ptr) {
                case BLK_MARKER_BNODE:
                    bnodes_local++;
                    break;
                case BLK_MARKER_DOC:
                    docs_local++;
                    break;
                }
#endif
                ee = list_next(ee);
            }
            while(a){
                dirty = _get_entry(a, struct dirty_item, avl);
                item = dirty->item;
                scores[item->score]++;
                scores_local[item->score]++;
                nitems++;
                nfileitems++;
                ndirty++;
#ifdef __CRC32
                ptr = (uint8_t*)item->addr + bcache_blocksize - 1;
                switch (*ptr) {
                case BLK_MARKER_BNODE:
                    bnodes_local++;
                    break;
                case BLK_MARKER_DOC:
                    docs_local++;
                    break;
                }
#endif
                a = avl_next(a);
            }
        }

        printf("%3d %20s (%6d)(%6d)(c%6d d%6d)",
               (int)nfiles+1, fname->filename,
               (int)atomic_get_uint64_t(&fname->nitems),
               (int)atomic_get_uint64_t(&fname->nvictim),
               (int)nclean, (int)ndirty);
        printf("%6d%6d", (int)docs_local, (int)bnodes_local);
        for (i=0;i<=n;++i){
            printf("%6d ", (int)scores_local[i]);
        }
        printf("\n");

        docs += docs_local;
        bnodes += bnodes_local;

        nfiles++;
    }
    printf(" ===\n");

    printf("%d files %d items\n", (int)nfiles, (int)nitems);
    for (i=0;i<=n;++i){
        printf("[%d]: %d\n", (int)i, (int)scores[i]);
    }
    printf("Documents: %d blocks\n", (int)docs);
    printf("Index nodes: %d blocks\n", (int)bnodes);
}
// LCOV_EXCL_STOP

// LCOV_EXCL_START
INLINE void _bcache_free_bcache_item(struct hash_elem *h)
{
    struct bcache_item *item = _get_entry(h, struct bcache_item, hash_elem);
    free(item);
}
// LCOV_EXCL_STOP

// LCOV_EXCL_START
INLINE void _bcache_free_fnamedic(struct hash_elem *h)
{
    size_t i = 0;
    struct fnamedic_item *item;
    item = _get_entry(h, struct fnamedic_item, hash_elem);

    for (; i < item->num_shards; ++i) {
        hash_free_active(&item->shards[i].hashtable, _bcache_free_bcache_item);
        spin_destroy(&item->shards[i].lock);
    }

    free(item->shards);
    free(item->filename);

    atomic_destroy_uint32_t(&item->ref_count);
    atomic_destroy_uint64_t(&item->nvictim);
    atomic_destroy_uint64_t(&item->nitems);
    atomic_destroy_uint64_t(&item->access_timestamp);
    free(item);
}
// LCOV_EXCL_STOP

void bcache_shutdown()
{
    struct bcache_item *item;
    struct list_elem *e;

    e = list_begin(&freelist);
    while(e) {
        item = _get_entry(e, struct bcache_item, list_elem);
        e = list_remove(&freelist, e);
        freelist_count--;
        free(item);
    }

    // Force clean zombies if any
    e = list_begin(&file_zombies);
    while (e) {
        struct fnamedic_item *fname = _get_entry(e, struct fnamedic_item, le);
        e = list_remove(&file_zombies, e);
        _fname_free(fname);
    }
    // Free the file list array
    free(file_list);

    // Free entire buffercache memory
    free(buffercache_addr);

    spin_lock(&bcache_lock);
    hash_free_active(&fnamedic, _bcache_free_fnamedic);
    spin_unlock(&bcache_lock);

    spin_destroy(&bcache_lock);
    spin_destroy(&freelist_lock);
    rw_spin_destroy(&filelist_lock);
}

