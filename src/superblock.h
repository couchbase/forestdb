/* -*- Mode: C++; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2015 Couchbase, Inc
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

#ifndef _FDB_SUPERBLOCK_H
#define _FDB_SUPERBLOCK_H

#include "libforestdb/fdb_types.h"
#include "libforestdb/fdb_errors.h"
#include "common.h"

#include "filemgr.h"
#include "avltree.h"
#include "atomic.h"
#include "docio.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Superblock config options that are passed to sb_init() API.
 */
struct sb_config {
    /**
     * Number of superblocks that are concurrently maintained for crash recovery.
     */
    uint8_t num_sb;
};

/**
 * Reserved bitmap is destroyed or not initialized.
 */
#define SB_RSV_VOID (0x0)
/**
 * Reserved bitmap is being initialized (not ready to use).
 */
#define SB_RSV_INITIALIZING (0x1)
/**
 * Reserved bitmap is being written into the DB file.
 */
#define SB_RSV_WRITING (0x2)
/**
 * Reserved bitmap is now available.
 */
#define SB_RSV_READY (0xffff)

/**
 * Pre-reclaimed reusable block bitmap info.
 * Each attribute is same as that in superblock.
 */
struct sb_rsv_bmp {
    /**
     * Revision number of the reserved bitmap.
     */
    uint64_t bmp_revnum;
    /**
     * Number of bits in the bitmap. Each bit represents a block.
     */
    uint64_t bmp_size;
    /**
     * Pointer to the bitmap.
     */
    uint8_t *bmp;
    /**
     * Bitmap index for fast searching of next reusable block.
     */
    struct avl_tree bmp_idx;
    /**
     * Pointer to array of bitmap document offsets, where a bitmap document is a
     * system documents containing a part of the bitmap.
     */
    bid_t *bmp_doc_offset;
    /**
     * Pointer to array of bitmap document in-memory objects.
     */
    struct docio_object *bmp_docs;
    /**
     * Number of bitmap documents.
     */
    uint64_t num_bmp_docs;
    /**
     * Current number of free blocks in the bitmap.
     */
    uint64_t num_free_blocks;
    /**
     * BID of a block to be allocated next time.
     */
    bid_t cur_alloc_bid;
    /**
     * Revision number of the oldest header that is not reclaimed yet and is currently
     * active in the file.
     */
    uint64_t min_live_hdr_revnum;
    /**
     * BID of the oldest header that is not reclaimed yet and is currently active in the
     * file.
     */
    bid_t min_live_hdr_bid;
    /**
     * Status of the reserved bitmap.
     */
    atomic_uint32_t status;
};

/**
 * Superblock structure definition.
 */
struct superblock {
    /**
     * Superblock configuration.
     */
    struct sb_config *config;
    /**
     * Current revision number of superblock. This value increases whenever superblock
     * is written back into file.
     */
    uint64_t revnum;
    /**
     * Current revision number of bitmap in superblock. This value increases whenever
     * ForestDB reclaims stale blocks and accordingly bitmap is updated.
     */
    uint64_t bmp_revnum;
    /**
     * Number of bits in the bitmap. Each bit represents a block.
     */
    uint64_t bmp_size;
    /**
     * Pointer to the bitmap.
     */
    uint8_t *bmp;
    /**
     * Number of bits in the previous bitmap. Each bit represents a block.
     */
    uint64_t bmp_prev_size;
    /**
     * Pointer to the previous (previous bitmap revnum) bitmap.
     */
    uint8_t *bmp_prev;
    /**
     * Bitmap index for fast searching of next reusable block.
     */
    struct avl_tree bmp_idx;
    /**
     * Pointer to array of bitmap document offsets, where a bitmap document is a
     * system documents containing a part of the bitmap.
     */
    bid_t *bmp_doc_offset;
    /**
     * Pointer to array of bitmap document in-memory objects.
     */
    struct docio_object *bmp_docs;
    /**
     * Number of bitmap documents.
     */
    uint64_t num_bmp_docs;
    /**
     * Initial number of free blocks in the bitmap right after the bitmap is updated.
     */
    uint64_t num_init_free_blocks;
    /**
     * Current number of free blocks in the bitmap.
     */
    uint64_t num_free_blocks;
    /**
     * Reserved bitmap for the next round block reuse.
     */
    struct sb_rsv_bmp *rsv_bmp;
    /**
     * BID of a block to be allocated next time.
     */
    bid_t cur_alloc_bid;
    /**
     * BID of the last header.
     */
    bid_t last_hdr_bid;
    /**
     * Revision number of the oldest header that is not reclaimed yet and is currently
     * active in the file.
     */
    uint64_t min_live_hdr_revnum;
    /**
     * BID of the oldest header that is not reclaimed yet and is currently active in the
     * file.
     */
    bid_t min_live_hdr_bid;
    /**
     * Revision number of the last header.
     */
    uint64_t last_hdr_revnum;
    /**
     * Number of allocated blocks since the last superblock sync.
     */
    uint64_t num_alloc;
};

struct sb_ops {
    fdb_status (*init)(struct filemgr *file,
                       struct sb_config sconfig,
                       err_log_callback *log_callback);
    struct sb_config (*get_default_config)();
    fdb_status (*read_latest)(struct filemgr *file,
                              struct sb_config sconfig,
                              err_log_callback *log_callback);
    bid_t (*alloc_block)(struct filemgr *file);
    bool (*is_writable)(struct filemgr *file, bid_t bid);
    bool (*is_valid)(struct filemgr *file, bid_t bid);
    uint64_t (*get_bmp_revnum)(struct filemgr *file);
    uint64_t (*get_min_live_revnum)(struct filemgr *file);
    fdb_status (*release)(struct filemgr *file);
};

/**
 * Create system docs for bitmap and append them into the file.
 *
 * @param handle Pointer to ForestDB KV store handle.
 * @return void.
 */
void sb_bmp_append_doc(fdb_kvs_handle *handle);

/**
 * Create system docs for reserved bitmap and append them into the file.
 *
 * @param handle Pointer to ForestDB KV store handle.
 * @return void.
 */
void sb_rsv_append_doc(fdb_kvs_handle *handle);

/**
 * Read bitmap docs from file and reconstruct bitmap.
 *
 * @param handle Pointer to ForestDB KV store handle.
 * @return FDB_RESULT_SUCCESS on success.
 */
fdb_status sb_bmp_fetch_doc(fdb_kvs_handle *handle);

/**
 * Update in-memory structure of superblock using current header info.
 *
 * @param handle Pointer to ForestDB KV store handle.
 * @return void.
 */
void sb_update_header(fdb_kvs_handle *handle);

/**
 * Reset counter for the number of block allocation.
 *
 * @param handle Pointer to ForestDB KV store handle.
 * @return void.
 */
void sb_reset_num_alloc(fdb_kvs_handle *handle);

/**
 * Write back superblock info into the file.
 *
 * @param handle Pointer to ForestDB KV store handle.
 * @return FDB_RESULT_SUCCESS on success.
 */
fdb_status sb_sync_circular(fdb_kvs_handle *handle);
/**
 * Check if superblock needs to be written back into the file.
 *
 * @param handle Pointer to ForestDB KV store handle.
 * @return True if superblock meets the sync period.
 */
bool sb_check_sync_period(fdb_kvs_handle *handle);

/**
 * Reusable block reclaim logic decision.
 */
typedef enum {
    /**
     * Do nothing.
     */
    SBD_NONE = 0,
    /**
     * Reclaim reusable blocks and update the bitmap immediately.
     */
    SBD_RECLAIM = 1,
    /**
     * Reclaim reusable blocks but reserve them for the next round.
     */
    SBD_RESERVE = 2,
    /**
     * Discard the current bitmap and take the reserved bitmap.
     */
    SBD_SWITCH = 3
} sb_decision_t;

/**
 * Check if more blocks need to be reclaimed for being reused.
 *
 * @param handle Pointer to ForestDB KV store handle.
 * @return True if block reusing is necessary.
 */
sb_decision_t sb_check_block_reusing(fdb_kvs_handle *handle);

/**
 * Reclaim stale blocks and update the in-memory structure of bitmap in superblock.
 *
 * @param handle Pointer to ForestDB KV store handle.
 * @return True if block reclaiming succeeded.
 */
bool sb_reclaim_reusable_blocks(fdb_kvs_handle *handle);

/**
 * Switch reserved blocks to currently being used blocks.
 *
 * @param file Pointer to file manager handle.
 * @return True if switching succeeded.
 */
bool sb_switch_reserved_blocks(struct filemgr *file);

/**
 * Reclaim stale blocks for the next round block reuse and create an in-memory
 * structure for the reserved bitmap array.
 *
 * @param handle Pointer to ForestDB KV store handle.
 * @return True if block reclaiming succeeded.
 */
bool sb_reserve_next_reusable_blocks(fdb_kvs_handle *handle);

/**
 * Restore all remaining reusable blocks including reserved blocks
 * into stale tree again.
 *
 * @param handle Pointer to ForestDB KV store handle.
 * @return void.
 */
void sb_return_reusable_blocks(fdb_kvs_handle *handle);

/**
 * Set bitmap bits for the given blocks.
 *
 * @param bmp Pointer to bitmap array.
 * @param bid Starting BID.
 * @param len Number of blocks.
 * @return void.
 */
void sb_bmp_set(uint8_t *bmp, bid_t bid, uint64_t len);
/**
 * Clear bitmap bits for the given blocks.
 *
 * @param bmp Pointer to bitmap array.
 * @param bid Starting BID.
 * @param len Number of blocks.
 * @return void.
 */
void sb_bmp_clear(uint8_t *bmp, bid_t bid, uint64_t len);
/**
 * Initialize bitmap masks for bitmap operations.
 *
 * @return void.
 */
void sb_bmp_mask_init();
/**
 * Investigate if the given block is writable.
 *
 * @param file Pointer to filemgr handle.
 * @param bid ID of block.
 * @return True if the block is writable.
 */
bool sb_bmp_is_writable(struct filemgr *file, bid_t bid);
/**
 * Investigate if the given block is active.
 *
 * @param file Pointer to filemgr handle.
 * @param bid ID of block.
 * @return True if the block is active (i.e., not stale).
 */
bool sb_bmp_is_active_block(struct filemgr *file, bid_t bid);

/**
 * Initialize superblock structure.
 *
 * @param file Pointer to filemgr handle.
 * @param sconfig Superblock configuration.
 * @param log_callback Pointer to log callback function.
 * @return FDB_RESULT_SUCCESS on success.
 */
fdb_status sb_init(struct filemgr *file, struct sb_config sconfig,
                   err_log_callback * log_callback);

/**
 * Write a superblock with the given ID.
 *
 * @param file Pointer to filemgr handle.
 * @param sb_no Superblock ID.
 * @param log_callback Pointer to log callback function.
 * @return FDB_RESULT_SUCCESS on success.
 */
fdb_status sb_write(struct filemgr *file, size_t sb_no,
                    err_log_callback * log_callback);

/**
 * Read all superblocks and take the most recent superblock.
 *
 * @param file Pointer to filemgr handle.
 * @param sconfig Superblock configuration.
 * @param log_callback Pointer to log callback function.
 * @return FDB_RESULT_SUCCESS on success.
 */
fdb_status sb_read_latest(struct filemgr *file,
                          struct sb_config sconfig,
                          err_log_callback *log_callback);

/**
 * Allocate a free block by referring the bitmap in superblock, in a circular manner.
 *
 * @param file Pointer to filemgr handle.
 * @return ID of the allocated block. BLK_NOT_FOUND if there is no free block in the
 *         bitmap.
 */
bid_t sb_alloc_block(struct filemgr *file);

/**
 * Get the current revision number of bitmap in superblock.
 *
 * @param file Pointer to filemgr handle.
 * @return Bitmap revision number.
 */
uint64_t sb_get_bmp_revnum(struct filemgr *file);

/**
 * Get the oldest active header revision number.
 *
 * @param file Pointer to filemgr handle.
 * @return Header revision number.
 */
uint64_t sb_get_min_live_revnum(struct filemgr *file);

/**
 * Get the number of free blocks in the bitmap of superblock.
 *
 * @param file Pointer to filemgr handle.
 * @return Number of free blocks.
 */
uint64_t sb_get_num_free_blocks(struct filemgr *file);

/**
 * Free all in-memory superblock structures.
 *
 * @param file Pointer to filemgr handle.
 * @return FDB_RESULT_SUCCESS on success.
 */
fdb_status sb_free(struct filemgr *file);

/**
 * Get the default superblock configurations.
 *
 * @return sb_config instance that contains the default configurations.
 */
struct sb_config sb_get_default_config();

#ifdef __cplusplus
}
#endif

#endif /* _FDB_SUPERBLOCK_H */

