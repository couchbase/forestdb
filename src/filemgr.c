/*
 * Copyright 2013 Jung-Sang Ahn <jungsang.ahn@gmail.com>.
 * All Rights Reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <assert.h>
#include <sys/stat.h>

#include "filemgr.h"
#include "hash_functions.h"
#include "blockcache.h"
#include "wal.h"
#include "crc32.h"
#include "list.h"

#include "memleak.h"

#ifdef __DEBUG
#ifndef __DEBUG_FILEMGR
    #undef DBG
    #undef DBGCMD
    #undef DBGSW
    #define DBG(args...)
    #define DBGCMD(command...)
    #define DBGSW(n, command...) 
#endif
#endif

// NBUCKET must be power of 2
#define NBUCKET (1024)
#define FILEMGR_MAGIC (0xdeadcafebeefbeef)

// global static variables
static spin_t initial_lock = SPIN_INITIALIZER;
static int filemgr_initialized = 0;
static struct filemgr_config global_config;
static struct hash hash;
static spin_t filemgr_openlock;

static size_t filemgr_sys_pagesize;

struct temp_buf_item{
    void *addr;
    struct list_elem le;
};
static struct list temp_buf;
static spin_t temp_buf_lock;

uint32_t _file_hash(struct hash *hash, struct hash_elem *e)
{
    struct filemgr *file = _get_entry(e, struct filemgr, e);
    int len = strlen(file->filename);
    int offset = MIN(len, 8);
    return hash_djb2(file->filename + (len - offset), offset) & ((unsigned)(NBUCKET-1));
}

int _file_cmp(struct hash_elem *a, struct hash_elem *b)
{
    struct filemgr *aa, *bb;
    aa = _get_entry(a, struct filemgr, e);
    bb = _get_entry(b, struct filemgr, e);
    return strcmp(aa->filename, bb->filename);

/*
    if (aa->filename_len == bb->filename_len) {
        return memcmp(aa->filename, bb->filename, aa->filename_len);
    }else {
        uint16_t len = MIN(aa->filename_len , bb->filename_len);
        int cmp = memcmp(aa->filename, bb->filename, len);
        if (cmp != 0) return cmp;
        else {
            return (int)((int)aa->filename_len - (int)bb->filename_len);
        }
    }*/
}

void filemgr_init(struct filemgr_config *config)
{
    int i, ret;
    uint32_t *temp;

     spin_lock(&initial_lock);
    if (!filemgr_initialized) {
        global_config = *config;

        if (global_config.ncacheblock > 0) 
            bcache_init(global_config.ncacheblock, global_config.blocksize);
        
        hash_init(&hash, NBUCKET, _file_hash, _file_cmp);

        filemgr_sys_pagesize = sysconf(_SC_PAGESIZE);

        // initialize temp buffer
        list_init(&temp_buf);
        temp_buf_lock = SPIN_INITIALIZER;

        // initialize global lock
        filemgr_openlock = SPIN_INITIALIZER;

        // set the initialize flag
        filemgr_initialized = 1;
    }
    spin_unlock(&initial_lock);
}

void * _filemgr_get_temp_buf()
{
    struct list_elem *e;
    struct temp_buf_item *item;

    spin_lock(&temp_buf_lock);
    e = list_pop_front(&temp_buf);
    if (e) {
        item = _get_entry(e, struct temp_buf_item, le);
    }else{
        void *addr;
        
        int ret = posix_memalign(&addr, FDB_SECTOR_SIZE,
            global_config.blocksize + sizeof(struct temp_buf_item));
        assert(ret == 0);
        /*
        addr = memalign(FDB_SECTOR_SIZE, global_config.blocksize + sizeof(struct temp_buf_item));
        assert(addr);*/

        item = addr + global_config.blocksize;
        item->addr = addr;
    }
    spin_unlock(&temp_buf_lock);
    
    return item->addr;
}

void _filemgr_release_temp_buf(void *buf)
{
    struct temp_buf_item *item;

    spin_lock(&temp_buf_lock);
    item = (struct temp_buf_item*)((void*)buf + global_config.blocksize);
    list_push_front(&temp_buf, &item->le);
    spin_unlock(&temp_buf_lock);    
}

void _filemgr_shutdown_temp_buf()
{
    struct list_elem *e;
    struct temp_buf_item *item;
    size_t count=0;

    spin_lock(&temp_buf_lock);
    e = list_begin(&temp_buf);
    while(e){
        item = _get_entry(e, struct temp_buf_item, le);
        e = list_remove(&temp_buf, e);
        free(item->addr);
        count++;
    }
    spin_unlock(&temp_buf_lock);
}

void _filemgr_read_header(struct filemgr *file)
{
    uint8_t marker[BLK_MARKER_SIZE];
    filemgr_magic_t magic;
    filemgr_header_len_t len;
    void *buf;

    // get temp buffer
    buf = _filemgr_get_temp_buf();

    if (file->pos > 0) {

        file->ops->pread(file->fd, buf, file->blocksize, file->pos - file->blocksize);
        memcpy(marker, buf + file->blocksize - BLK_MARKER_SIZE, BLK_MARKER_SIZE);
        
        if (marker[0] == BLK_MARKER_DBHEADER) {
            memcpy(&magic, buf + file->blocksize - sizeof(magic) - BLK_MARKER_SIZE, sizeof(magic));
            if (magic == FILEMGR_MAGIC) {
                memcpy(&len, buf + file->blocksize - sizeof(magic) - sizeof(len) - BLK_MARKER_SIZE, sizeof(len));
                file->header.data = (void *)malloc(len);
                
                memcpy(file->header.data, buf, len);
                memcpy(&file->header.revnum, buf + len, sizeof(filemgr_header_revnum_t));
                file->header.size = len;

                return;
            }
        }
    }

    // release temp buffer
    _filemgr_release_temp_buf(buf);
    
    file->header.size = 0;
    file->header.revnum = 0;
    file->header.data = NULL;
}

struct filemgr * filemgr_open(char *filename, struct filemgr_ops *ops,
                              struct filemgr_config *config)
{
    struct filemgr *file = NULL;
    struct filemgr query;
    struct hash_elem *e = NULL;
    int create_flag = 0x0;
    int file_flag = 0x0;

    create_flag = (O_CREAT);
    file_flag = O_RDWR | create_flag | config->flag;

    // global initialization
    // initialized only once at first time
    if (!filemgr_initialized) {
        filemgr_init(config);
    }

    // check whether file is already opened or not
    query.filename = filename;
    spin_lock(&filemgr_openlock);
    e = hash_find(&hash, &query.e);

    if (e) {
        // already opened (return existing structure)
        file = _get_entry(e, struct filemgr, e);

        spin_lock(&file->lock);
        spin_unlock(&filemgr_openlock);

        file->ref_count++;
        // if file was closed before
        if (file->status == FILE_CLOSED) {
            file->fd = file->ops->open(file->filename, file_flag, 0666);
            file->status = FILE_NORMAL;
        }
        spin_unlock(&file->lock);
        
    } else {
        // open (newly create)
        file = (struct filemgr*)malloc(sizeof(struct filemgr));
        file->filename_len = strlen(filename);
        file->filename = (char*)malloc(file->filename_len + 1);
        strcpy(file->filename, filename);

        file->ref_count = 1;

        file->wal = (struct wal *)malloc(sizeof(struct wal));
        file->wal->flag = 0x0;

        file->ops = ops;
        file->blocksize = global_config.blocksize;
        file->status = FILE_NORMAL;
        file->config = &global_config;
        file->new_file = NULL;

        file->fd = file->ops->open(file->filename, file_flag, 0666);
        file->pos = file->last_commit = file->ops->goto_eof(file->fd);

        file->bcache = NULL;
        
        _filemgr_read_header(file);
        
        file->lock = SPIN_INITIALIZER;
        mutex_init(&file->mutex);
        
        hash_insert(&hash, &file->e);

        spin_unlock(&filemgr_openlock);
    }
    file->sync = (config->async)?(0):(1);

    return file;
}

uint64_t filemgr_update_header(struct filemgr *file, void *buf, size_t len)
{
    uint64_t ret;
    
    spin_lock(&file->lock);

    if (file->header.data == NULL) {
        file->header.data = (void *)malloc(len);
    }else if (file->header.size < len){
        file->header.data = (void *)realloc(file->header.data, len);
    }
    memcpy(file->header.data, buf, len);
    file->header.size = len;
    ++(file->header.revnum);
    ret = file->header.revnum;

    spin_unlock(&file->lock);

    return ret;
}

filemgr_header_revnum_t filemgr_get_header_revnum(struct filemgr *file)
{
    filemgr_header_revnum_t ret;
    spin_lock(&file->lock);
    ret = file->header.revnum;
    spin_unlock(&file->lock);
    return ret;
}

char* filemgr_get_filename_ptr(struct filemgr *file, char **filename, uint16_t *len)
{
    spin_lock(&file->lock);
    *filename = file->filename;
    *len = file->filename_len;
    spin_unlock(&file->lock);
    return *filename;
}

void* filemgr_fetch_header(struct filemgr *file, void *buf, size_t *len)
{
    spin_lock(&file->lock);

    if (file->header.size > 0) {
        if (buf == NULL) {
            buf = (void*)malloc(file->header.size);
        }
        memcpy(buf, file->header.data, file->header.size);
    }
    *len = file->header.size;
    
    spin_unlock(&file->lock);

    return buf;
}

void filemgr_close(struct filemgr *file)
{
    // remove filemgr structure if no thread refers to the file
    spin_lock(&file->lock);
    if (--(file->ref_count) == 0) {
        spin_unlock(&file->lock);                
        if (global_config.ncacheblock > 0) {
            // discard all dirty blocks belong to this file
            bcache_remove_dirty_blocks(file);
        }
        
        spin_lock(&file->lock);
        if (wal_is_initialized(file)) {
            wal_close(file);
        }

        file->ops->close(file->fd);
        if (file->status == FILE_REMOVED_PENDING) {
            // remove file

            // we can release lock becuase no one will open this file
            spin_unlock(&file->lock);
            
            remove(file->filename);
            filemgr_remove_file(file);

            return;
        }else{
            file->status = FILE_CLOSED;
        }
    }
    spin_unlock(&file->lock);
}

void _filemgr_free_func(struct hash_elem *h)
{
    struct filemgr *file = _get_entry(h, struct filemgr, e);

    // remove all cached blocks
    if (global_config.ncacheblock > 0) {
        bcache_remove_dirty_blocks(file);
        bcache_remove_clean_blocks(file);
        bcache_remove_file(file);
    }

    // destroy WAL
    if (wal_is_initialized(file)) {        
        wal_shutdown(file);
        hash_free(&file->wal->hash_bykey);
    #ifdef __FDB_SEQTREE
        hash_free(&file->wal->hash_byseq);
    #endif
    }

    free(file->wal);

    // free filename and header
    free(file->filename);
    free(file->header.data);

    // free file structure
    free(file);
}

// permanently remove file from cache (not just close)
void filemgr_remove_file(struct filemgr *file)
{
    assert(file);
    assert(file->ref_count <= 0);
    
    // remove from global hash table
    spin_lock(&filemgr_openlock);    
    assert(hash_remove(&hash, &file->e));
    spin_unlock(&filemgr_openlock);

    _filemgr_free_func(&file->e);
}

void filemgr_shutdown()
{
    if (filemgr_initialized) {
        int i;

        spin_lock(&initial_lock);

        hash_free_active(&hash, _filemgr_free_func);
        if (global_config.ncacheblock > 0) {
            bcache_shutdown();
        }
        filemgr_initialized = 0;
        _filemgr_shutdown_temp_buf();
        
        spin_unlock(&initial_lock);
    }
}

bid_t filemgr_get_next_alloc_block(struct filemgr *file)
{
    bid_t bid = file->pos / file->blocksize;
    return bid;
}

bid_t filemgr_alloc(struct filemgr *file)
{
    spin_lock(&file->lock);
    bid_t bid = file->pos / file->blocksize;
    file->pos += file->blocksize;
    spin_unlock(&file->lock);
    
    return bid;
}

void filemgr_alloc_multiple(struct filemgr *file, int nblock, bid_t *begin, bid_t *end)
{
    spin_lock(&file->lock);
    *begin = file->pos / file->blocksize;
    *end = *begin + nblock - 1;
    file->pos += file->blocksize * nblock;
    spin_unlock(&file->lock);
}

// atomically allocate NBLOCK blocks only when current file position is same to nextbid
bid_t filemgr_alloc_multiple_cond(
    struct filemgr *file, bid_t nextbid, int nblock, bid_t *begin, bid_t *end)
{
    bid_t bid;
    spin_lock(&file->lock);
    bid = file->pos / file->blocksize;
    if (bid == nextbid) {
        *begin = file->pos / file->blocksize;
        *end = *begin + nblock - 1;
        file->pos += file->blocksize * nblock;        
    }else{
        *begin = BLK_NOT_FOUND;
        *end = BLK_NOT_FOUND;
    }
    spin_unlock(&file->lock);
    return bid;
}

INLINE void _filemgr_crc32_check(struct filemgr *file, void *buf)
{
    if ( *((uint8_t*)buf + file->blocksize-1) == BLK_MARKER_BNODE ) {
        uint32_t crc_file, crc;
        memcpy(&crc_file, buf + 8, sizeof(crc_file));
        memset(buf + 8, 0xff, sizeof(void *));
        crc = crc32_8(buf, file->blocksize, 0);
        assert(crc == crc_file);
    }
}

void filemgr_read(struct filemgr *file, bid_t bid, void *buf)
{
    int r;
    uint64_t pos = bid * file->blocksize;
    assert(pos < file->pos);

    if (global_config.ncacheblock > 0) {
        r = bcache_read(file, bid, buf);
        if (r == 0) {
            // cache miss
            if (file->status != FILE_COMPACT_OLD_SCAN) {
                // if normal file, just read a block
                r = file->ops->pread(file->fd, buf, file->blocksize, pos);
                assert(r == file->blocksize);
                
                #ifdef __CRC32
                    _filemgr_crc32_check(file, buf);
                #endif

                bcache_write(file, bid, buf, BCACHE_CLEAN);
            }else{
                // if file is undergoing compaction, bulk read and bulk cache prefetch
                uint64_t pos_bulk;
                uint64_t count_bulk;
                uint64_t nblocks, i;
                void *bulk_buf;
                
                pos_bulk = (bid / FILEMGR_BULK_READ);
                pos_bulk *= FILEMGR_BULK_READ * file->blocksize;
                count_bulk = FILEMGR_BULK_READ * file->blocksize;
                if (pos_bulk + count_bulk > file->last_commit) {
                    count_bulk = file->last_commit - pos_bulk;
                }
                nblocks = count_bulk / file->blocksize;
                r = posix_memalign(&bulk_buf, FDB_SECTOR_SIZE, count_bulk);
                r = file->ops->pread(file->fd, bulk_buf, count_bulk, pos_bulk);
                assert(r > 0);

                for (i=0;i<nblocks;++i){
                    bcache_write(file, pos_bulk / file->blocksize + i, 
                        bulk_buf + i*file->blocksize, BCACHE_CLEAN);
                }
                memcpy(buf, bulk_buf + (bid*file->blocksize - pos_bulk), file->blocksize);
                
                free(bulk_buf);
            }
        }
    } else {
        r = file->ops->pread(file->fd, buf, file->blocksize, pos);
        assert(r == file->blocksize);
        
        #ifdef __CRC32
            _filemgr_crc32_check(file, buf);
        #endif
    }
}

void filemgr_write_offset(struct filemgr *file, bid_t bid, uint64_t offset, uint64_t len, void *buf)
{
    assert(offset + len <= file->blocksize);

    int r = 0;
    uint64_t pos = bid * file->blocksize + offset;
    assert(pos >= file->last_commit);

    if (global_config.ncacheblock > 0) {
        if (len == file->blocksize) {
            // write entire block .. we don't need to read previous block
            bcache_write(file, bid, buf, BCACHE_DIRTY);
        }else {
            // partially write buffer cache first
            r = bcache_write_partial(file, bid, buf, offset, len);
            if (r == 0) {    
                // cache miss
                // write partially .. we have to read previous contents of the block
                void *_buf = _filemgr_get_temp_buf();

                r = file->ops->pread(file->fd, _buf, file->blocksize, bid * file->blocksize);
                memcpy(_buf + offset, buf, len);
                bcache_write(file, bid, _buf, BCACHE_DIRTY);

                _filemgr_release_temp_buf(_buf);
            }
        }
    }else{

        #ifdef __CRC32
            if (len == file->blocksize) {
                uint8_t marker = *((uint8_t*)buf + file->blocksize - 1);
                if (marker == BLK_MARKER_BNODE) {
                    memset(buf + 8, 0xff, sizeof(void *));
                    uint32_t crc32 = crc32_8(buf, file->blocksize, 0);
                    memcpy(buf + 8, &crc32, sizeof(crc32));
                }
            }
        #endif    
        r = file->ops->pwrite(file->fd, buf, len, pos);
        assert(r == len);
    }
}

void filemgr_write(struct filemgr *file, bid_t bid, void *buf)
{
    filemgr_write_offset(file, bid, 0, file->blocksize, buf);
}

int filemgr_is_writable(struct filemgr *file, bid_t bid)
{
    spin_lock(&file->lock);
    uint64_t pos = bid * file->blocksize;
    int cond = (pos >= file->last_commit && pos < file->pos);
    spin_unlock(&file->lock);
    
    return cond;
}

void filemgr_commit(struct filemgr *file)
{
    uint16_t header_len = file->header.size;
    filemgr_magic_t magic = FILEMGR_MAGIC;

    if (global_config.ncacheblock > 0) {
        bcache_flush(file);
    }

    spin_lock(&file->lock);
    
    if (file->header.size > 0 && file->header.data) {
        void *buf = _filemgr_get_temp_buf();
        uint8_t marker[BLK_MARKER_SIZE];

        // header data
        memcpy(buf, file->header.data, header_len);
        // header rev number
        memcpy(buf + header_len, &file->header.revnum, sizeof(filemgr_header_revnum_t));

        // header length    
        memcpy(buf + (file->blocksize - sizeof(filemgr_magic_t) - sizeof(header_len) - BLK_MARKER_SIZE),
            &header_len, sizeof(header_len));
        // magic number
        memcpy(buf + (file->blocksize - sizeof(filemgr_magic_t) - BLK_MARKER_SIZE),
            &magic, sizeof(magic));

        // marker
        memset(marker, BLK_MARKER_DBHEADER, BLK_MARKER_SIZE);
        memcpy(buf + file->blocksize - BLK_MARKER_SIZE, marker, BLK_MARKER_SIZE);

        file->ops->pwrite(file->fd, buf, file->blocksize, file->pos);
        file->pos += file->blocksize;

        _filemgr_release_temp_buf(buf);
    }
    // race condition?
    file->last_commit = file->pos;

    spin_unlock(&file->lock);

    if (file->sync) {
        file->ops->fdatasync(file->fd);
    }
}

void filemgr_sync(struct filemgr *file)
{
    if (global_config.ncacheblock > 0) {
        bcache_flush(file);
    }

    file->ops->fdatasync(file->fd);
}

void filemgr_update_file_status(struct filemgr *file, file_status_t status)
{
    spin_lock(&file->lock);
    file->status = status;
    spin_unlock(&file->lock);
}

void filemgr_remove_pending(struct filemgr *old_file, struct filemgr *new_file)
{
    assert(new_file);

    spin_lock(&old_file->lock);
    if (old_file->ref_count > 0) {
        // delay removing
        old_file->new_file = new_file;
        old_file->status = FILE_REMOVED_PENDING;
        spin_unlock(&old_file->lock);
    }else{
        // immediatly remove
        spin_unlock(&old_file->lock);
        remove(old_file->filename);
        filemgr_remove_file(old_file);
    }
}

file_status_t filemgr_get_file_status(struct filemgr *file)
{
    spin_lock(&file->lock);
    file_status_t status = file->status;
    spin_unlock(&file->lock);
    return status;
}

void filemgr_mutex_lock(struct filemgr *file)
{
    mutex_lock(&file->mutex);
}

void filemgr_mutex_unlock(struct filemgr *file)
{
    mutex_unlock(&file->mutex);
}

