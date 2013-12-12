/*
 * Copyright 2013 Jung-Sang Ahn <jungsang.ahn@gmail.com>.
 * All Rights Reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>

#include "filemgr.h"
#include "hbtrie.h"
#include "btree.h"
#include "btree_kv.h"
#include "docio.h"
#include "btreeblock.h"
#include "forestdb.h"
#include "common.h"
#include "wal.h"
#include "filemgr_ops_linux.h"
#include "crc32.h"

#include "memleak.h"

#ifdef __DEBUG
#ifndef __DEBUG_FDB
    #undef DBG
    #undef DBGCMD
    #undef DBGSW
    #define DBG(args...)
    #define DBGCMD(command...)
    #define DBGSW(n, command...) 
#else
    static int compact_count=0;
#endif
#endif

#ifdef __FDB_SEQTREE
    #define SEQTREE(args...) args
#else
    #define SEQTREE(args...)
#endif

INLINE size_t _fdb_readkey_wrap(void *handle, uint64_t offset, void *buf)
{
    keylen_t keylen;
    docio_read_doc_key((struct docio_handle *)handle, offset, &keylen, buf);
    return keylen;
}

INLINE void _fdb_fetch_header(
    void *header_buf, 
    size_t header_len, 
    bid_t *trie_root_bid, 
    bid_t *seq_root_bid, 
    fdb_seqnum_t *seqnum,
    uint64_t *ndocs,
    uint64_t *datasize,
    uint64_t *last_header_bid)
{
    size_t offset = 0;
    seq_memcpy(trie_root_bid, header_buf + offset, sizeof(bid_t), offset);
    seq_memcpy(seq_root_bid, header_buf + offset, sizeof(bid_t), offset);
    seq_memcpy(seqnum, header_buf + offset, sizeof(fdb_seqnum_t), offset);        
    seq_memcpy(ndocs, header_buf + offset, sizeof(uint64_t), offset);
    seq_memcpy(datasize, header_buf + offset, sizeof(uint64_t), offset);
    seq_memcpy(last_header_bid, header_buf + offset, 
        sizeof(uint64_t), offset);
}

fdb_status fdb_open(fdb_handle *handle, char *filename, fdb_config config)
{
    DBGCMD(
        struct timeval _a_,_b_,_rr_;
        gettimeofday(&_a_, NULL);
    );

    struct filemgr_config fconfig;
    bid_t trie_root_bid = BLK_NOT_FOUND;
    bid_t seq_root_bid = BLK_NOT_FOUND;
    fdb_seqnum_t seqnum = 0;
    uint8_t header_buf[FDB_BLOCKSIZE];
    size_t header_len = 0;

#ifdef _MEMPOOL
    mempool_init();
#endif

    fconfig.blocksize = config.blocksize = FDB_BLOCKSIZE;
    fconfig.ncacheblock = config.buffercache_size / FDB_BLOCKSIZE;
    fconfig.flag = 0x0;
    if (config.durability_opt & 0x1) {
        fconfig.flag |= _ARCH_O_DIRECT;
    }
    if (config.durability_opt & 0x2) {
        fconfig.async = 1;
    }else {
        fconfig.async = 0;
    }
    
    handle->fileops = get_linux_filemgr_ops();
    handle->btreeblkops = btreeblk_get_ops();
    handle->file = filemgr_open(filename, handle->fileops, fconfig);
    handle->trie = (struct hbtrie *)malloc(sizeof(struct hbtrie));
    handle->bhandle = (struct btreeblk_handle *)malloc(sizeof(struct btreeblk_handle));
    handle->dhandle = (struct docio_handle *)malloc(sizeof(struct docio_handle));
    handle->config = config;
    handle->btree_fanout = fconfig.blocksize / (config.chunksize+config.offsetsize);
    handle->last_header_bid = BLK_NOT_FOUND;
    handle->lock = SPIN_INITIALIZER;

    handle->datasize = handle->ndocs = 0;

    if (!wal_is_initialized(handle->file)) {
        handle->wal_dirty = FDB_WAL_CLEAN;
        wal_init(handle->file, FDB_WAL_NBUCKET);
    }

    docio_init(handle->dhandle, handle->file);
    btreeblk_init(handle->bhandle, handle->file, handle->file->blocksize);

    filemgr_fetch_header(handle->file, header_buf, &header_len);
    if (header_len > 0) {             
        uint32_t crc_file, crc;
        
        crc = crc32_8(header_buf, header_len - sizeof(crc), 0);
        memcpy(&crc_file, header_buf + (header_len - sizeof(crc)), sizeof(crc_file));
        assert(crc == crc_file);
        
        _fdb_fetch_header(header_buf, header_len, &trie_root_bid, &seq_root_bid, &seqnum,
            &handle->ndocs, &handle->datasize, &handle->last_header_bid);
    }
    handle->cur_header_revnum = filemgr_get_header_revnum(handle->file);
    
    hbtrie_init(handle->trie, config.chunksize, config.offsetsize, handle->file->blocksize, trie_root_bid, 
        handle->bhandle, handle->btreeblkops, handle->dhandle, _fdb_readkey_wrap);

#ifdef __FDB_SEQTREE
    if (handle->config.seqtree_opt == FDB_SEQTREE_USE) {
        handle->seqnum = seqnum;
        struct btree_kv_ops *kv_ops = (struct btree_kv_ops *)malloc(sizeof(struct btree_kv_ops));
        memcpy(kv_ops, handle->trie->btree_kv_ops, sizeof(struct btree_kv_ops));
        kv_ops->cmp = _cmp_uint64_t;
        
        handle->seqtree = (struct btree*)malloc(sizeof(struct btree));
        if (seq_root_bid == BLK_NOT_FOUND) {
            btree_init(handle->seqtree, handle->bhandle, handle->btreeblkops, kv_ops, 
                handle->trie->btree_nodesize, sizeof(fdb_seqnum_t), handle->trie->valuelen, 
                0x0, NULL);
         }else{
             btree_init_from_bid(handle->seqtree, handle->bhandle, handle->btreeblkops, kv_ops, 
                 handle->trie->btree_nodesize, seq_root_bid);
         }
    }else{
        handle->seqtree = NULL;
    }
#endif

    btreeblk_end(handle->bhandle);

    DBGCMD(
        gettimeofday(&_b_, NULL);
        _rr_ = _utime_gap(_a_,_b_);        
    );
    DBG("fdb_open %s, %"_FSEC".%06"_FUSEC" sec elapsed.\n", 
        filename, _rr_.tv_sec, _rr_.tv_usec);

    return FDB_RESULT_SUCCESS;
}

fdb_status fdb_doc_create(fdb_doc **doc, void *key, size_t keylen, void *meta, size_t metalen,
    void *body, size_t bodylen)
{
    if (doc == NULL) return FDB_RESULT_FAIL;
    *doc = (fdb_doc*)malloc(sizeof(fdb_doc));
    if (*doc == NULL) return FDB_RESULT_FAIL;

#ifdef __FDB_SEQTREE
    (*doc)->seqnum = SEQNUM_NOT_USED;
#endif

    if (key && keylen>0) {
        (*doc)->key = (void *)malloc(keylen);
        if ((*doc)->key == NULL) return FDB_RESULT_FAIL;
        memcpy((*doc)->key, key, keylen);
        (*doc)->keylen = keylen;
    }else{
        (*doc)->key = NULL;
        (*doc)->keylen = 0;
    }
    
    if (meta && metalen > 0) {
        (*doc)->meta = (void *)malloc(metalen);
        if ((*doc)->meta == NULL) return FDB_RESULT_FAIL;
        memcpy((*doc)->meta, meta, metalen);
        (*doc)->metalen = metalen;
    }else{
        (*doc)->meta = NULL;
        (*doc)->metalen = 0;
    }
    
    if (body && bodylen > 0) {
        (*doc)->body = (void *)malloc(bodylen);
        if ((*doc)->body == NULL) return FDB_RESULT_FAIL;
        memcpy((*doc)->body, body, bodylen);
        (*doc)->bodylen = bodylen;
    }else{
        (*doc)->body = NULL;
        (*doc)->bodylen = 0;
    }

    return FDB_RESULT_SUCCESS;
}

fdb_status fdb_doc_update(fdb_doc **doc, void *meta, size_t metalen, void *body, size_t bodylen)
{
    if (doc == NULL) return FDB_RESULT_FAIL;
    if (*doc == NULL) return FDB_RESULT_FAIL;

    if (meta && metalen > 0) {
        // free previous metadata
        free((*doc)->meta);
        // allocate new metadata
        (*doc)->meta = (void *)malloc(metalen);
        if ((*doc)->meta == NULL) return FDB_RESULT_FAIL;
        memcpy((*doc)->meta, meta, metalen);
        (*doc)->metalen = metalen;
    }

    if (body && bodylen > 0) {
        // free previous body
        free((*doc)->body);
        // allocate new body
        (*doc)->body = (void *)malloc(bodylen);
        if ((*doc)->body == NULL) return FDB_RESULT_FAIL;
        memcpy((*doc)->body, body, bodylen);
        (*doc)->bodylen = bodylen;
    }
    
    return FDB_RESULT_SUCCESS;
}

// doc MUST BE allocated by malloc
fdb_status fdb_doc_free(fdb_doc *doc)
{
    if (doc->key) free(doc->key);
    if (doc->meta) free(doc->meta);
    if (doc->body) free(doc->body);
    free(doc);
    return FDB_RESULT_SUCCESS;
}

/*
INLINE size_t _fdb_get_docsize(struct docio_object *doc)
{
    size_t ret = doc->length.keylen  + doc->length.metalen + doc->length.bodylen + sizeof(struct docio_length);
    #ifdef __FDB_SEQTREE
        ret += sizeof(fdb_seqnum_t);
    #endif
    #ifdef __CRC32
        ret += sizeof(uint32_t);
    #endif

    return ret;    
}
*/

INLINE size_t _fdb_get_docsize(struct docio_length len)
{
    size_t ret = 
        len.keylen + 
        len.metalen + 
        len.bodylen + 
        sizeof(struct docio_length);
    
    #ifdef __FDB_SEQTREE
        ret += sizeof(fdb_seqnum_t);
    #endif
    
    #ifdef __CRC32
        ret += sizeof(uint32_t);
    #endif

    return ret;
}

INLINE void _fdb_wal_flush_func(void *voidhandle, struct wal_item *item)
{
    hbtrie_result hr;
    btree_result br;
    fdb_handle *handle = (fdb_handle *)voidhandle;
    uint64_t old_offset;

    if (item->action == WAL_ACT_INSERT) {
        hr = hbtrie_insert(handle->trie, item->key, item->keylen, &item->offset, &old_offset);
        btreeblk_end(handle->bhandle);

        SEQTREE( 
            if (handle->config.seqtree_opt == FDB_SEQTREE_USE) {
                br = btree_insert(handle->seqtree, &item->seqnum, &item->offset);
                btreeblk_end(handle->bhandle);
            }
        );
        
        if (hr == HBTRIE_RESULT_SUCCESS) {
            handle->ndocs++;
            handle->datasize += item->doc_size;
        }else{
            // update            
            struct docio_length len;
            // this block is already cached when we call HBTRIE_INSERT .. no additional block access
            len = docio_read_doc_length(handle->dhandle, old_offset);
            handle->datasize -= _fdb_get_docsize(len);
            //handle->datasize -= _wal_get_docsize(len);
            
            handle->datasize += item->doc_size;
        }
    }else{
        // TODO: set delete flag and update
    }
}

void _fdb_sync_db_header(fdb_handle *handle)
{
    uint64_t cur_revnum = filemgr_get_header_revnum(handle->file);
    if (handle->cur_header_revnum != cur_revnum) {
        void *header_buf = NULL;
        size_t header_len;

        header_buf = filemgr_fetch_header(handle->file, NULL, &header_len);
        if (header_len > 0) {             
            bid_t new_seq_root;
            _fdb_fetch_header(header_buf, header_len, 
                &handle->trie->root_bid, &new_seq_root, &handle->seqnum,
                &handle->ndocs, &handle->datasize, &handle->last_header_bid);
            if (new_seq_root != handle->seqtree->root_bid) {
                btree_init_from_bid(
                    handle->seqtree, handle->seqtree->blk_handle, 
                    handle->seqtree->blk_ops, handle->seqtree->kv_ops, 
                    handle->seqtree->blksize, new_seq_root);
            }
        }
        if (header_buf) {
            free(header_buf);
        }
    }
}

void _fdb_check_file_reopen(fdb_handle *handle)
{
    if (filemgr_get_file_status(handle->file) == FILE_REMOVED_PENDING) {
        assert(handle->file->new_file);

        struct filemgr *new_file = handle->file->new_file;
        fdb_config config = handle->config;

        fdb_close(handle);
        fdb_open(handle, new_file->filename, config);
    }
}

fdb_status fdb_get(fdb_handle *handle, fdb_doc *doc)
{
    void *header_buf;
    size_t header_len;
    uint64_t offset;
    struct docio_object _doc;
    wal_result wr;
    hbtrie_result hr = HBTRIE_RESULT_FAIL;

    if (doc->key == NULL || doc->keylen == 0) return FDB_RESULT_INVALID_ARGS;

    _fdb_check_file_reopen(handle);
    _fdb_sync_db_header(handle);

    wr = wal_find(handle->file, doc, &offset);

    if (wr == WAL_RESULT_FAIL) {
        hr = hbtrie_find(handle->trie, doc->key, doc->keylen, &offset);
        btreeblk_end(handle->bhandle);
    }

    if (wr != WAL_RESULT_FAIL || hr != HBTRIE_RESULT_FAIL) {
        _doc.key = doc->key;
        _doc.length.keylen = doc->keylen;
        _doc.meta = doc->meta;
        _doc.body = doc->body;
        docio_read_doc(handle->dhandle, offset, &_doc);

        if (_doc.length.keylen != doc->keylen) return FDB_RESULT_FAIL;

        doc->seqnum = _doc.seqnum;
        doc->metalen = _doc.length.metalen;
        doc->bodylen = _doc.length.bodylen;
        doc->key = _doc.key;
        doc->meta = _doc.meta;
        doc->body = _doc.body;

        return FDB_RESULT_SUCCESS;
    }

    return FDB_RESULT_FAIL;
}

// search document metadata using key
fdb_status fdb_get_metaonly(fdb_handle *handle, fdb_doc *doc, uint64_t *body_offset)
{
    uint64_t offset;
    struct docio_object _doc;
    wal_result wr;
    hbtrie_result hr;

    if (doc->key == NULL || doc->keylen == 0) return FDB_RESULT_INVALID_ARGS;

    _fdb_check_file_reopen(handle);
    _fdb_sync_db_header(handle);
    
    wr = wal_find(handle->file, doc, &offset);

    if (wr == WAL_RESULT_FAIL) {
        hr = hbtrie_find(handle->trie, doc->key, doc->keylen, &offset);
        btreeblk_end(handle->bhandle);
    }

    if (wr != WAL_RESULT_FAIL || hr != HBTRIE_RESULT_FAIL) {
        _doc.key = doc->key;
        _doc.length.keylen = doc->keylen;
        _doc.meta = _doc.body = NULL;
        *body_offset = docio_read_doc_key_meta(handle->dhandle, offset, &_doc);

        if (_doc.length.keylen != doc->keylen) return FDB_RESULT_FAIL;

        doc->seqnum = _doc.seqnum;
        doc->metalen = _doc.length.metalen;
        doc->bodylen = _doc.length.bodylen;
        doc->key = _doc.key;
        doc->meta = _doc.meta;
        doc->body = _doc.body;

        return FDB_RESULT_SUCCESS;
    }

    return FDB_RESULT_FAIL;
}

#ifdef __FDB_SEQTREE

// search document using sequence number
fdb_status fdb_get_byseq(fdb_handle *handle, fdb_doc *doc)
{
    uint64_t offset;
    struct docio_object _doc;
    wal_result wr;
    btree_result br = BTREE_RESULT_FAIL;
    //fdb_seqnum_t seqnum;

    if (doc->seqnum == SEQNUM_NOT_USED) return FDB_RESULT_INVALID_ARGS;
    
    wr = wal_find(handle->file, doc, &offset);

    if (wr == WAL_RESULT_FAIL) {
        br = btree_find(handle->seqtree, &doc->seqnum, &offset);
        btreeblk_end(handle->bhandle);
    }

    if (wr != WAL_RESULT_FAIL || br != BTREE_RESULT_FAIL) {
        _doc.key = doc->key;
        _doc.meta = doc->meta;
        _doc.body = doc->body;
        docio_read_doc(handle->dhandle, offset, &_doc);

        assert(doc->seqnum == _doc.seqnum);

        doc->keylen = _doc.length.keylen;
        doc->metalen = _doc.length.metalen;
        doc->bodylen = _doc.length.bodylen;
        doc->key = _doc.key;
        doc->meta = _doc.meta;
        doc->body = _doc.body;

        return FDB_RESULT_SUCCESS;
    }

    return FDB_RESULT_FAIL;
}

// search document metadata using sequence number
fdb_status fdb_get_metaonly_byseq(fdb_handle *handle, fdb_doc *doc, uint64_t *body_offset)
{
    uint64_t offset;
    struct docio_object _doc;
    wal_result wr;
    //hbtrie_result hr;
    btree_result br;

    if (doc->seqnum == SEQNUM_NOT_USED) return FDB_RESULT_INVALID_ARGS;
    
    wr = wal_find(handle->file, doc, &offset);

    if (wr == WAL_RESULT_FAIL) {
        //hr = hbtrie_find(handle->trie, doc->key, doc->keylen, &offset);
        br = btree_find(handle->seqtree, &doc->seqnum, &offset);
        btreeblk_end(handle->bhandle);
    }

    if (wr != WAL_RESULT_FAIL || br != HBTRIE_RESULT_FAIL) {
        _doc.key = doc->key;
        _doc.meta = _doc.body = NULL;
        *body_offset = docio_read_doc_key_meta(handle->dhandle, offset, &_doc);

        assert(doc->seqnum == _doc.seqnum);
        
        doc->keylen = _doc.length.keylen;
        doc->metalen = _doc.length.metalen;
        doc->bodylen = _doc.length.bodylen;
        doc->key = _doc.key;
        doc->meta = _doc.meta;
        doc->body = _doc.body;

        return FDB_RESULT_SUCCESS;
    }

    return FDB_RESULT_FAIL;
}
#endif

fdb_status fdb_set(fdb_handle *handle, fdb_doc *doc)
{
    uint64_t offset;
    struct docio_object _doc;
    
    if ( (doc->key == NULL) || (doc->keylen == 0) ||
        (doc->metalen > 0 && doc->meta == NULL) || 
        (doc->bodylen > 0 && doc->body == NULL)) return FDB_RESULT_INVALID_ARGS;

    _fdb_check_file_reopen(handle);
    _fdb_sync_db_header(handle);
    
    _doc.length.keylen = doc->keylen;
    _doc.length.metalen = doc->metalen;
    _doc.length.bodylen = doc->bodylen;
    _doc.key = doc->key;

#ifdef __FDB_SEQTREE
    if (handle->config.seqtree_opt == FDB_SEQTREE_USE) {
        //_doc.seqnum = doc->seqnum;
        spin_lock(&handle->lock);
        _doc.seqnum = doc->seqnum = handle->seqnum++;
        spin_unlock(&handle->lock);
    }else{
        _doc.seqnum = SEQNUM_NOT_USED;
    }
#endif

    _doc.meta = doc->meta;
    _doc.body = doc->body;

    if (_doc.body) {
        offset = docio_append_doc(handle->dhandle, &_doc);
        wal_insert(handle->file, doc, offset);
    }else{
        //remove
        wal_remove(handle->file, doc);
    }
    if (handle->wal_dirty == FDB_WAL_CLEAN) {
        handle->wal_dirty = FDB_WAL_DIRTY;
    }

#ifdef __WAL_FLUSH_BEFORE_COMMIT
    if (wal_get_size(handle->file) > handle->config.wal_threshold) {
        wal_flush(handle->file, (void *)handle, _fdb_wal_flush_func);
        handle->wal_dirty = FDB_WAL_PENDING;
    }
#endif

    return FDB_RESULT_SUCCESS;
}

uint64_t _fdb_set_file_header(fdb_handle *handle)
{
    /*
    <ForestDB header>
    [0000]: BID of root node of root B+Tree of HB+Trie: 8 bytes
    [0008]: BID of root node of seq B+Tree: 8 bytes (optional)
    [0016]: the current DB sequence number: 8 bytes (optional)
    [0024]: # of live documents: 8 bytes
    [0032]: Data size (byte): 8 bytes
    [0040]: File offset of the DB header created when last WAL flush: 8 bytes
    [0048]: CRC32: 4 bytes
    [total size: 52 bytes]
    */
    uint8_t buf[256];
    size_t offset = 0;
    uint32_t crc;

    // hb+trie root bid
    seq_memcpy(buf + offset, &handle->trie->root_bid, sizeof(handle->trie->root_bid), offset);

#ifdef __FDB_SEQTREE
    if (handle->config.seqtree_opt == FDB_SEQTREE_USE) {
        // b+tree root bid
        seq_memcpy(buf + offset, &handle->seqtree->root_bid, 
            sizeof(handle->seqtree->root_bid), offset);
        // sequence number
        seq_memcpy(buf + offset, &handle->seqnum, sizeof(handle->seqnum), offset);
    }else{
        memset(buf + offset, 0, sizeof(uint64_t) + sizeof(handle->seqnum));
        offset += sizeof(uint64_t) + sizeof(handle->seqnum);
    }
#else
    memset(buf + offset, 0, sizeof(uint64_t) + sizeof(handle->seqnum));
    offset += sizeof(uint64_t) + sizeof(handle->seqnum);
#endif

    // # docs
    seq_memcpy(buf + offset, &handle->ndocs, sizeof(handle->ndocs), offset);
    // data size
    seq_memcpy(buf + offset, &handle->datasize, sizeof(handle->datasize), offset);
    // last header bid
    seq_memcpy(buf + offset, &handle->last_header_bid, 
        sizeof(handle->last_header_bid), offset);

    // crc32
    crc = crc32_8(buf, offset, 0);
    seq_memcpy(buf + offset, &crc, sizeof(crc), offset);
    
    return filemgr_update_header(handle->file, buf, offset);
}

fdb_status fdb_commit(fdb_handle *handle)
{
    btreeblk_end(handle->bhandle);
    if (wal_get_size(handle->file) > handle->config.wal_threshold || 
        handle->wal_dirty == FDB_WAL_PENDING) {
        // wal flush when 
        // 1. wal size exceeds threshold
        // 2. wal is already flushed before commit (in this case flush the rest of entries)
        wal_flush(handle->file, handle, _fdb_wal_flush_func);
        handle->wal_dirty = FDB_WAL_CLEAN;
    }else{
        // otherwise just commit wal
        wal_commit(handle->file);
    }

    if (handle->wal_dirty == FDB_WAL_CLEAN) {
        //3 <not sure whether this is bug-free or not>
        handle->last_header_bid = filemgr_get_next_alloc_block(handle->file);
    }
    handle->cur_header_revnum = _fdb_set_file_header(handle);    
    filemgr_commit(handle->file);
    return FDB_RESULT_SUCCESS;
}

INLINE int _fdb_cmp_uint64_t(const void *key1, const void *key2)
{
    uint64_t a,b;
    a = *(uint64_t*)key1;
    b = *(uint64_t*)key2;
    /*
    if (*a<*b) return -1;
    if (*a>*b) return 1;
    return 0;*/
    return _CMP_U64(a, b);
}

fdb_status fdb_compact(fdb_handle *handle, char *new_filename)
{
    struct filemgr *new_file, *old_file;
    struct filemgr_config fconfig;
    struct btreeblk_handle *new_bhandle;
    struct docio_handle *new_dhandle;
    struct hbtrie *new_trie;
    struct btree *new_seqtree, *old_seqtree;
    struct hbtrie_iterator it;
    struct btree_iterator bit;
    struct docio_object doc;
    uint8_t k[HBTRIE_MAX_KEYLEN];
    size_t keylen;
    uint64_t offset, new_offset, *offset_arr, i, count, new_datasize;
    fdb_seqnum_t seqnum;
    hbtrie_result hr;

    wal_flush(handle->file, handle, _fdb_wal_flush_func);
    handle->wal_dirty = FDB_WAL_CLEAN;
    handle->last_header_bid = 
        (handle->file->pos) / handle->file->blocksize;
    _fdb_set_file_header(handle);
    btreeblk_end(handle->bhandle);

    fconfig.blocksize = FDB_BLOCKSIZE;
    fconfig.ncacheblock = handle->config.buffercache_size / FDB_BLOCKSIZE;
    fconfig.flag = 0x0;
    if (handle->config.durability_opt & 0x1) {
        fconfig.flag |= _ARCH_O_DIRECT;
    }
    if (handle->config.durability_opt & 0x2) {
        fconfig.async = 1;
    }else {
        fconfig.async = 0;
    }

    // open new file
    new_file = filemgr_open(new_filename, handle->fileops, fconfig);

    // create new hb-trie and related handles
    new_bhandle = (struct btreeblk_handle *)malloc(sizeof(struct btreeblk_handle));
    new_dhandle = (struct docio_handle *)malloc(sizeof(struct docio_handle));
    new_trie = (struct hbtrie *)malloc(sizeof(struct hbtrie));

    wal_init(new_file, handle->config.wal_threshold);
    docio_init(new_dhandle, new_file);
    btreeblk_init(new_bhandle, new_file, new_file->blocksize);
    hbtrie_init(new_trie, handle->trie->chunksize, handle->trie->valuelen, new_file->blocksize,
        BLK_NOT_FOUND, new_bhandle, handle->btreeblkops, new_dhandle, _fdb_readkey_wrap);

    #ifdef __FDB_SEQTREE
        if (handle->config.seqtree_opt == FDB_SEQTREE_USE) {
            // if we use sequence number tree
            new_seqtree = (struct btree *)malloc(sizeof(struct btree));
            old_seqtree = handle->seqtree;
            
            btree_init(new_seqtree, new_bhandle, old_seqtree->blk_ops,
                old_seqtree->kv_ops, old_seqtree->blksize, old_seqtree->ksize, old_seqtree->vsize, 
                0x0, NULL);
        }
    #endif

    count = new_datasize = 0;

    #ifdef __FDB_SORTED_COMPACTION
        // allocate offset array
        offset_arr = (uint64_t*)malloc(sizeof(uint64_t) * handle->ndocs);
        
        // scan all live documents in the trie
        hr = hbtrie_iterator_init(handle->trie, &it, NULL, 0);

        while( hr != HBTRIE_RESULT_FAIL ) {
            
            hr = hbtrie_next(&it, k, &keylen, &offset);
            btreeblk_end(handle->bhandle);
            
            if ( hr == HBTRIE_RESULT_FAIL ) break;

            assert(count < handle->ndocs);
            offset_arr[count] = offset;
            count++;
        }

        hr = hbtrie_iterator_free(&it);

        // sort in offset order
        qsort(offset_arr, count, sizeof(uint64_t), _fdb_cmp_uint64_t);
        filemgr_update_file_status(handle->file, FILE_COMPACT_OLD);
        filemgr_update_file_status(new_file, FILE_COMPACT_NEW);
        
        for (i=0;i<count;++i){
            doc.key = k;
            doc.length.keylen = keylen;
            //doc.meta = sandbox;
            doc.meta = NULL;
            doc.body = NULL;
            docio_read_doc(handle->dhandle, offset_arr[i], &doc);

            // re-write to new file
            new_offset = docio_append_doc(new_dhandle, &doc);
            free(doc.meta);
            free(doc.body);
            new_datasize += _fdb_get_docsize(doc.length);

            hbtrie_insert(new_trie, k, doc.length.keylen, &new_offset, NULL);
            btreeblk_end(new_bhandle);

            #ifdef __FDB_SEQTREE
                if (handle->config.seqtree_opt == FDB_SEQTREE_USE) {
                    btree_insert(new_seqtree, &doc.seqnum, &new_offset);
                    btreeblk_end(new_bhandle);                
                }
            #endif        
        }
        free(offset_arr);

    #else

        // scan all live documents in the trie
        filemgr_update_file_status(handle->file, FILE_COMPACT_OLD);
        filemgr_update_file_status(new_file, FILE_COMPACT_NEW);

        hr = hbtrie_iterator_init(handle->trie, &it, NULL, 0);

        while( hr != HBTRIE_RESULT_FAIL ) {

            if (count == 16254) {
                size_t a=0;
            }
            
            hr = hbtrie_next(&it, k, &keylen, &offset);
            btreeblk_end(handle->bhandle);
            
            if ( hr == HBTRIE_RESULT_FAIL ) break;

            doc.key = k;
            doc.length.keylen = keylen;
            //doc.meta = sandbox;
            doc.meta = NULL;
            doc.body = NULL;
            docio_read_doc(handle->dhandle, offset, &doc);

            // re-write to new file
            new_offset = docio_append_doc(new_dhandle, &doc);
            free(doc.meta);
            free(doc.body);
            new_datasize += _fdb_get_docsize(doc.length);            
            
            hbtrie_insert(new_trie, k, doc.length.keylen, &new_offset, NULL);
            btreeblk_end(new_bhandle);

            #ifdef __FDB_SEQTREE
                if (handle->config.seqtree_opt == FDB_SEQTREE_USE) {
                    btree_insert(new_seqtree, &doc.seqnum, &new_offset);
                    btreeblk_end(new_bhandle);                
                }
            #endif

            count++;
        }

        hr = hbtrie_iterator_free(&it);
    #endif

    DBG("\nkey count: %"_F64"\n", count);

    handle->ndocs = count;
    handle->datasize = new_datasize;

    old_file = handle->file;
    filemgr_close(old_file);
    handle->file = new_file;

    btreeblk_free(handle->bhandle);
    free(handle->bhandle);
    handle->bhandle = new_bhandle;

    docio_free(handle->dhandle);
    free(handle->dhandle);
    handle->dhandle = new_dhandle;

    hbtrie_free(handle->trie);
    free(handle->trie);
    handle->trie = new_trie;

    #ifdef __FDB_SEQTREE
        if (handle->config.seqtree_opt == FDB_SEQTREE_USE) {
            free(handle->seqtree);
            handle->seqtree = new_seqtree;
        }
    #endif

    filemgr_update_file_status(new_file, FILE_NORMAL);
    fdb_commit(handle);

    wal_shutdown(old_file);

    // removing file is pended until there is no handle referring the file
    filemgr_remove_pending(old_file, new_file);

    return FDB_RESULT_SUCCESS;
}

// manually flush WAL entries into index
fdb_status fdb_flush_wal(fdb_handle *handle)
{
    if (wal_get_size(handle->file) > 0) {
        wal_flush(handle->file, handle, _fdb_wal_flush_func);
        handle->wal_dirty = FDB_WAL_PENDING;
    }
    return FDB_RESULT_SUCCESS;
}

fdb_status fdb_close(fdb_handle *handle)
{
    //wal_close(handle->file);
    filemgr_close(handle->file);
    docio_free(handle->dhandle);
    btreeblk_end(handle->bhandle);
    btreeblk_free(handle->bhandle);
    hbtrie_free(handle->trie);
    free(handle->trie);
    #ifdef __FDB_SEQTREE
    if (handle->config.seqtree_opt == FDB_SEQTREE_USE) {
        free(handle->seqtree->kv_ops);
        free(handle->seqtree);
    }
    #endif
    free(handle->bhandle);
    free(handle->dhandle);
    return FDB_RESULT_SUCCESS;
}

// roughly estimate the space occupied db handle HANDLE
size_t fdb_estimate_space_used(fdb_handle *handle)
{
    size_t ret = 0;

    ret += handle->datasize;
    // hb-trie size (estimated as worst case)
    ret += (handle->ndocs / (handle->btree_fanout * 3 / 4)) * handle->config.blocksize;
    // b-tree size (estimated as worst case)
    ret += (handle->ndocs / (handle->btree_fanout * 3 / 4)) * handle->config.blocksize;

    ret += wal_get_datasize(handle->file);
    
    return ret;
}

fdb_status fdb_shutdown()
{
    filemgr_shutdown();
#ifdef _MEMPOOL
    mempool_shutdown();
#endif    
}


