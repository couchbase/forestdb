/*
 * Copyright 2013 Jung-Sang Ahn <jungsang.ahn@gmail.com>.
 * All Rights Reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>

//[[ ogh : for swat 
#include <scsi/sg.h>
#include <errno.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <linux/fs.h>

#ifndef OPENSSD
	#define OPENSSD "/dev/sg1"
#endif
#define NEW_FILE "/home/gihwan/openssd/compaction"
#ifndef SG_OPENSSD
	#define SG_OPENSSD "/dev/sg1"
#endif
//ogh]]

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


/*	[[ogh 
	SWAT: Swap and Trim command protocol 
*/

/* 
Prototype: init_sg_io_hdr(struct sg_io_hdr* io_hdr)
Description : initialize sg_io_hdr structure to be used as argument of swat()
			  io_hdr->cmdp should be connected with buffer for cdb
Calling : After io_hdr.cmdp = cdb; io_hdr.cmd_len=sizeof(cdb); in caller function, 
		  init_sg_io_hdr(&io_hdr);
Return value : none
*/
void init_sg_io_hdr(struct sg_io_hdr* io_hdr)
{
	// sg_io means "SCSI Genric IO"
	memset(io_hdr, 0 , sizeof(struct sg_io_hdr));

	//default setting for sg_io
	io_hdr->interface_id = 'S';
	io_hdr->dxfer_direction = SG_DXFER_NONE;
	io_hdr->timeout = 5000;
	
	memset(io_hdr->cmdp, 0 , sizeof(unsigned char) * io_hdr->cmd_len );

	//default setting for sg_io 
	//and now we use trim command to implement SWAT()
	//We don't send/recieve any buffer to/from disk, 
	//and we don't get any sg_status info.
	io_hdr->cmdp[0] = 0x85;
	io_hdr->cmdp[1] = ((3<<1) | 0x01);
	io_hdr->cmdp[2] = 0x00;
	io_hdr->cmdp[4] = 1;
	io_hdr->cmdp[6] = 0xEF;
	io_hdr->cmdp[14] = 0x06; // trim command number
}
/*
	Prototype: swat(file_descriptor, sg_io_hdr, old_offset, new_offset)
						(int)		(struct)	(uint64_t)	(uint64_t)
	Description :
		old_offset means "offset that will be pointed"
		new_offset means "offset that will point physical offset of old_offset"
	Calling :
		In the fdb_get() like function, 
			swat(fd, &io_hdr, new_doc's offset, old_doc's offset);
			because old_offset will remain.
		In the fdb_compact() like function,
			swat(fd, &io_hdr, old_file_doc's offset, new_file_doc's offset);
			because new_file will remain.
	Return : 0-no error, 1-failed to ioctl
*/

int swat(int fd, struct sg_io_hdr* io_hdr, 
				uint64_t old_offset, uint64_t new_offset)
{
	unsigned char *cdb = io_hdr->cmdp;

	// Offset that will be pointed
	cdb[13] = (old_offset >> 24);
	cdb[12] = (old_offset >> 16);
	cdb[10] = (old_offset >> 8);
	cdb[8] = (old_offset);

	// Offset that will point physical offset of above 
	cdb[3] = (new_offset >> 24);
	cdb[11] = (new_offset > 16);
	cdb[9] = (new_offset >> 8);
	cdb[7] = (new_offset) ;

	//error return 1, no error return 0
	return -1 == ioctl(fd, SG_IO, io_hdr)? 1 : 0;
}

//ogh]]




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

INLINE void _fdb_restore_wal(fdb_handle *handle)
{
    struct filemgr *file = handle->file;
    uint32_t blocksize = handle->file->blocksize;
    uint64_t last_header_bid = handle->last_header_bid;
    uint64_t header_blk_pos = file->pos ? file->pos - blocksize : 0;
    uint64_t offset = 0; //assume everything from first block needs restoration
    uint8_t *buf;

    filemgr_mutex_lock(file);
    if (last_header_bid != BLK_NOT_FOUND) {
        offset = (last_header_bid + 1) * blocksize;
    }

    // If a valid last header was retrieved and it matches the current header
    // OR if WAL already had entries populated, then no crash recovery needed
    if (!header_blk_pos || header_blk_pos <= offset || wal_get_size(file)) {
        filemgr_mutex_unlock(file);
        return;
    }

    for (; offset < header_blk_pos;
        offset = ((offset / blocksize) + 1) * blocksize) { // next block's off
        if (!docio_check_buffer(handle->dhandle, offset / blocksize)) {
            continue;
        } else do {
            struct docio_object doc;
            uint64_t _offset;
            memset(&doc, 0, sizeof(doc));
            _offset = docio_read_doc(handle->dhandle, offset, &doc);
            if (doc.key) {
                fdb_doc wal_doc;
                wal_doc.keylen = doc.length.keylen;
                wal_doc.metalen = doc.length.metalen;
                wal_doc.bodylen = doc.length.bodylen;
                wal_doc.key = doc.key;
#ifdef __FDB_SEQTREE
                wal_doc.seqnum = doc.seqnum;
#endif
                wal_doc.meta = doc.meta;
                wal_insert(file, &wal_doc, offset, WAL_ACT_INSERT);
                free(doc.key);
                free(doc.meta);
                free(doc.body);
                offset = _offset;
            } else {
                offset = _offset;
                break;
            }
        } while (offset + sizeof(struct docio_length) < header_blk_pos);
    }
    filemgr_mutex_unlock(file);
}

fdb_status fdb_open(fdb_handle *handle, char *filename, fdb_config *config)
{
    struct filemgr_config fconfig;
    bid_t trie_root_bid = BLK_NOT_FOUND;
    bid_t seq_root_bid = BLK_NOT_FOUND;
    fdb_seqnum_t seqnum = 0;
    uint8_t header_buf[FDB_BLOCKSIZE];
    size_t header_len = 0;

#ifdef _MEMPOOL
    mempool_init();
#endif

    fconfig.blocksize = config->blocksize = FDB_BLOCKSIZE;
    fconfig.ncacheblock = config->buffercache_size / FDB_BLOCKSIZE;
    fconfig.flag = 0x0;
    if (config->durability_opt & FDB_DRB_ODIRECT) {fconfig.flag |= _ARCH_O_DIRECT;}
    if (config->durability_opt & FDB_DRB_ASYNC) {fconfig.async = 1;}
    else {fconfig.async = 0;}

    handle->fileops = get_linux_filemgr_ops();
    handle->btreeblkops = btreeblk_get_ops();
    handle->file = filemgr_open(filename, handle->fileops, &fconfig);
    handle->trie = (struct hbtrie *)malloc(sizeof(struct hbtrie));
    handle->bhandle = (struct btreeblk_handle *)malloc(sizeof(struct btreeblk_handle));
    handle->dhandle = (struct docio_handle *)malloc(sizeof(struct docio_handle));
    handle->config = *config;
    handle->btree_fanout = fconfig.blocksize / (config->chunksize+config->offsetsize);
    handle->last_header_bid = BLK_NOT_FOUND;

    handle->datasize = handle->ndocs = 0;

    if (!wal_is_initialized(handle->file)) {
        wal_init(handle->file, FDB_WAL_NBUCKET);
    }

    docio_init(handle->dhandle, handle->file);
    btreeblk_init(handle->bhandle, handle->file, handle->file->blocksize);

    filemgr_fetch_header(handle->file, header_buf, &header_len);
    if (header_len > 0) {
        _fdb_fetch_header(header_buf, header_len, &trie_root_bid, &seq_root_bid, &seqnum,
            &handle->ndocs, &handle->datasize, &handle->last_header_bid);
    }
    handle->cur_header_revnum = filemgr_get_header_revnum(handle->file);

    hbtrie_init(handle->trie, config->chunksize, config->offsetsize, handle->file->blocksize, trie_root_bid,
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

    _fdb_restore_wal(handle);

    btreeblk_end(handle->bhandle);

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

/// real WAL function
INLINE void _fdb_wal_flush_func(void *voidhandle, struct wal_item *item)
{
    hbtrie_result hr;
    btree_result br;
    fdb_handle *handle = (fdb_handle *)voidhandle;
    uint64_t old_offset;

    if (item->action == WAL_ACT_INSERT
#ifndef SWAT
			|| item->action == WAL_ACT_UPDATE
#endif
			) {
			//read block if it is not in cache. 
			// *gihwan* we don't need to call this if we use SWAT
			// check new_dat or not , if new data is inserted than should call 

			// if old_offset exist ( updated data) do not call hbtrie_insert()
			// if old_offset is NaN, call hbtrie_insert()
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

            handle->datasize += item->doc_size;
        }
    }
#ifdef SWAT
	/* using swap */
	else if(item->action == WAL_ACT_UPDATE)
	{
			// TODO: SWAT 
            struct docio_length len;
            // this block is already cached when we call HBTRIE_INSERT .. no additional block access
            len = docio_read_doc_length(handle->dhandle, old_offset);
            handle->datasize -= _fdb_get_docsize(len);

            handle->datasize += item->doc_size;
	}
	/* using swap */
#endif
	else{
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
        fdb_open(handle, new_file->filename, &config);
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
        if (docio_read_doc(handle->dhandle, offset, &_doc) == offset) {
            return FDB_RESULT_FAIL;
        }

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
        if (*body_offset == offset) return FDB_RESULT_FAIL;

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

    if (doc->seqnum == SEQNUM_NOT_USED) return FDB_RESULT_INVALID_ARGS;

    _fdb_check_file_reopen(handle);
    _fdb_sync_db_header(handle);

    wr = wal_find(handle->file, doc, &offset);

    if (wr == WAL_RESULT_FAIL) {
        br = btree_find(handle->seqtree, &doc->seqnum, &offset);
        btreeblk_end(handle->bhandle);
    }

    if (wr != WAL_RESULT_FAIL || br != BTREE_RESULT_FAIL) {
        _doc.key = doc->key;
        _doc.meta = doc->meta;
        _doc.body = doc->body;
        if (docio_read_doc(handle->dhandle, offset, &_doc) == offset) {
            return FDB_RESULT_FAIL;
        }

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
    btree_result br;

    if (doc->seqnum == SEQNUM_NOT_USED) return FDB_RESULT_INVALID_ARGS;

    _fdb_check_file_reopen(handle);
    _fdb_sync_db_header(handle);

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
        if (*body_offset == offset) return FDB_RESULT_FAIL;

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
        (doc->bodylen > 0 && doc->body == NULL)) {
        return FDB_RESULT_INVALID_ARGS;
    }

    _fdb_check_file_reopen(handle);
    _fdb_sync_db_header(handle);

    filemgr_mutex_lock(handle->file);

    _doc.length.keylen = doc->keylen;
    _doc.length.metalen = doc->metalen;
    _doc.length.bodylen = doc->bodylen;
    _doc.key = doc->key;

#ifdef __FDB_SEQTREE
    if (handle->config.seqtree_opt == FDB_SEQTREE_USE) {
        //_doc.seqnum = doc->seqnum;
        _doc.seqnum = doc->seqnum = handle->seqnum++;
    }else{
        _doc.seqnum = SEQNUM_NOT_USED;
    }
#endif

    _doc.meta = doc->meta;
    _doc.body = doc->body;

    if (_doc.body) {
        offset = docio_append_doc(handle->dhandle, &_doc);
#if 1
		//original source code 
        wal_insert(handle->file, doc, offset, WAL_ACT_INSERT);
#else
		// gihwan for SWAT
		// check old data is or not 
		struct hbtrie_iterator it;
		size_t keylen;
		uint64_t old_offset;
		hbtrie_result hr=HBTRIE_RESULT_FAIL;

		// search from hbtrie 
		// it means old data exist 
        hr = hbtrie_find(handle->trie, doc->key, doc->keylen, &old_offset);
	    btreeblk_end(handle->bhandle);

	    if ( hr == HBTRIE_RESULT_FAIL ){
			offset = docio_append_doc(handle->dhandle, &_doc);
			wal_insert(handle->file, doc, offset, WAL_ACT_INSERT);
		}
		else
		{	
			//TODO: If we use bcache, then we have to write new doc
			// 		to bcache of old_offset, 
			//		because, after wal_flush before commit
			//		offset of doc in hbtrie isn't changed. 
			//		Thus, fdb_get() will read doc from old_offset. 
			//FIXME: To do this way, MVCC is not guaranteed. 
			// 		 should be considered about this. 
			
			//TODO: As mentioned above, call write_to_bcache_only() like function.

			// [Description] 
			//	insert into wal_buffer and change wal state to WAL_ACT_UPDATE
			//	WAL_ACT_UPDATE means "Do not change offset of key in hbtrie 
			//	when wal_flush operation".
			wal_insert(handle->file, doc, offset, WAL_ACT_UPDATE);

			//TODO:	When fdb_commit() is issued, we should call SWAT() 
			// 		to change internal mapping table of SSD.
			//TODO: Define SWAT(old_offset, new_offset) function. 
		}
#endif
    }else{
        //remove
        wal_remove(handle->file, doc);
    }
    if (wal_get_dirty_status(handle->file)== FDB_WAL_CLEAN) {
        wal_set_dirty_status(handle->file, FDB_WAL_DIRTY);
    }

#ifdef __WAL_FLUSH_BEFORE_COMMIT
    if (wal_get_size(handle->file) > handle->config.wal_threshold) {
        wal_flush(handle->file, (void *)handle, _fdb_wal_flush_func);
        wal_set_dirty_status(handle->file, FDB_WAL_PENDING);
    }
#endif

    filemgr_mutex_unlock(handle->file);
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
    [total size: 52 bytes] BLK_DBHEADER_SIZE must be incremented on new fields
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

//TODO:	When fdb_commit() is issued, we should call SWAT() 
// 		to change internal mapping table of SSD.
//TODO: Define SWAT(old_offset, new_offset) function. 
fdb_status fdb_commit(fdb_handle *handle)
{
    filemgr_mutex_lock(handle->file);

    btreeblk_end(handle->bhandle);
    if (wal_get_size(handle->file) > handle->config.wal_threshold ||
        wal_get_dirty_status(handle->file) == FDB_WAL_PENDING) {
        // wal flush when
        // 1. wal size exceeds threshold
        // 2. wal is already flushed before commit (in this case flush the rest of entries)
		
		// this is what actually operate merge. 
        wal_flush(handle->file, handle, _fdb_wal_flush_func);
        wal_set_dirty_status(handle->file, FDB_WAL_CLEAN);
    }else{
        // otherwise just commit wal
			// check the point of committed WAL
			// do not operate others. 
        wal_commit(handle->file);
    }

    if (wal_get_dirty_status(handle->file) == FDB_WAL_CLEAN) {
        //3 <not sure whether this is bug-free or not>
        handle->last_header_bid = filemgr_get_next_alloc_block(handle->file);
    }
    handle->cur_header_revnum = _fdb_set_file_header(handle);
    filemgr_commit(handle->file);
	// write once for every dirty block(bulk sequential write)
	// TODO: call SWAT for all docs which was written to disk. 


    filemgr_mutex_unlock(handle->file);
    return FDB_RESULT_SUCCESS;
}

INLINE int _fdb_cmp_uint64_t(const void *key1, const void *key2)
{
#ifdef __BIT_CMP

    uint64_t a,b;
    a = *(uint64_t*)key1;
    b = *(uint64_t*)key2;
    return _CMP_U64(a, b);

#else

    if (*a<*b) return -1;
    if (*a>*b) return 1;
    return 0;

#endif
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
    uint8_t k[HBTRIE_MAX_KEYLEN], oldfile_mutex_unlock;
    size_t keylen;
    uint64_t offset, new_offset, *offset_arr, i, count, new_datasize;
    fdb_seqnum_t seqnum;
    hbtrie_result hr;

    // prevent update to the target file
    filemgr_mutex_lock(handle->file);

    // if the file is already compacted by other thread
    if (filemgr_get_file_status(handle->file) == FILE_REMOVED_PENDING) {
        filemgr_mutex_unlock(handle->file);

        // update handle and return
        _fdb_check_file_reopen(handle);
        _fdb_sync_db_header(handle);

        return FDB_RESULT_FAIL;
    }

    // invalid filename, old filename == new filename
    if (!strcmp(new_filename, handle->file->filename)) {
        filemgr_mutex_unlock(handle->file);
        return FDB_RESULT_INVALID_ARGS;
    }

    // flush WAL and set DB header
    wal_flush(handle->file, handle, _fdb_wal_flush_func);
    // afther flushing WAL
    wal_set_dirty_status(handle->file, FDB_WAL_CLEAN);
    handle->last_header_bid =
        (handle->file->pos) / handle->file->blocksize;
    _fdb_set_file_header(handle);
    btreeblk_end(handle->bhandle);

    // set filemgr configuration
    fconfig.blocksize = handle->config.blocksize;
    fconfig.ncacheblock = handle->config.buffercache_size / handle->config.blocksize;
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
    new_file = filemgr_open(new_filename, handle->fileops, &fconfig);

    // prevent update to the new_file
    filemgr_mutex_lock(new_file);

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

    // free the iterator
    hr = hbtrie_iterator_free(&it);
    // scan all live documents in the trie
    filemgr_update_file_status(handle->file, FILE_COMPACT_OLD);
    filemgr_update_file_status(new_file, FILE_COMPACT_NEW);


    #ifdef __FDB_SORTED_COMPACTION
        qsort(offset_arr, count, sizeof(uint64_t), _fdb_cmp_uint64_t);
    #endif
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

    // allow update to new_file
    filemgr_mutex_unlock(new_file);

    fdb_commit(handle);

    wal_shutdown(old_file);

    // removing file is pended until there is no handle referring the file
    oldfile_mutex_unlock = (old_file->ref_count == 0)?(0):(1);
    filemgr_remove_pending(old_file, new_file);
    if (oldfile_mutex_unlock) filemgr_mutex_unlock(old_file);

    return FDB_RESULT_SUCCESS;
}

// manually flush WAL entries into index
fdb_status fdb_flush_wal(fdb_handle *handle)
{
    filemgr_mutex_lock(handle->file);

    if (wal_get_size(handle->file) > 0) {
        wal_flush(handle->file, handle, _fdb_wal_flush_func);
        wal_set_dirty_status(handle->file, FDB_WAL_PENDING);
    }

    filemgr_mutex_unlock(handle->file);
    return FDB_RESULT_SUCCESS;
}

fdb_status fdb_close(fdb_handle *handle)
{
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
    size_t fanout = handle->btree_fanout;
#ifdef __UTREE
    fanout = fanout / 3;
#endif

    ret += handle->datasize;
    // hb-trie size (estimated as worst case)
    ret += (handle->ndocs / (fanout * 3 / 4)) * handle->config.blocksize;
    // b-tree size (estimated as worst case)
    ret += (handle->ndocs / (fanout * 3 / 4)) * handle->config.blocksize;

    ret += wal_get_datasize(handle->file);

    return ret;
}

fdb_status fdb_shutdown()
{
    filemgr_shutdown();
#ifdef _MEMPOOL
    mempool_shutdown();
#endif

    return FDB_RESULT_SUCCESS;
}


