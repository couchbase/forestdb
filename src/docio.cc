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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "docio.h"
#include "wal.h"
#include "crc32.h"
#ifdef _DOC_COMP
#include "snappy-c.h"
#endif

#include "memleak.h"

void docio_init(struct docio_handle *handle,
                struct filemgr *file,
                uint8_t compress_document_body)
{
    int ret;

    handle->file = file;
    handle->curblock = BLK_NOT_FOUND;
    handle->curpos = 0;
    handle->lastbid = BLK_NOT_FOUND;
    handle->compress_document_body = compress_document_body;
    malloc_align(handle->readbuffer, FDB_SECTOR_SIZE, file->blocksize);
}

void docio_free(struct docio_handle *handle)
{
    free_align(handle->readbuffer);
}

#ifdef __CRC32
#define _add_blk_marker(file, bid, blocksize, marker, log_callback) \
    filemgr_write_offset((file), (bid), (blocksize), BLK_MARKER_SIZE, (marker), (log_callback))
#else
#define _add_blk_marker(file, bid, blocksize, marker, log_callback)
#endif

bid_t docio_append_doc_raw(struct docio_handle *handle, uint64_t size, void *buf)
{
    bid_t bid;
    uint32_t offset;
    uint8_t marker[BLK_MARKER_SIZE];
    size_t blocksize = handle->file->blocksize;
    size_t real_blocksize = blocksize;
    err_log_callback *log_callback = handle->log_callback;
#ifdef __CRC32
    blocksize -= BLK_MARKER_SIZE;
    memset(marker, BLK_MARKER_DOC, BLK_MARKER_SIZE);
#endif

    if (handle->curblock == BLK_NOT_FOUND) {
        // allocate new block
        handle->curblock = filemgr_alloc(handle->file, log_callback);
        handle->curpos = 0;
    }
    if (!filemgr_is_writable(handle->file, handle->curblock)) {
        // allocate new block
        handle->curblock = filemgr_alloc(handle->file, log_callback);
        handle->curpos = 0;
    }

    if (size <= blocksize - handle->curpos) {
        // simply append to current block
        offset = handle->curpos;
        _add_blk_marker(handle->file, handle->curblock, blocksize, marker, log_callback);
        filemgr_write_offset(handle->file, handle->curblock, offset, size, buf, log_callback);
        handle->curpos += size;

        return handle->curblock * real_blocksize + offset;

    }else{
        // not simply fitted into current block
        bid_t begin, end, i, startpos;
        uint32_t nblock = size / blocksize;
        uint32_t remain = size % blocksize;
        uint64_t remainsize = size;

    #ifdef DOCIO_BLOCK_ALIGN
        offset = blocksize - handle->curpos;
        if (remain <= blocksize - handle->curpos &&
            filemgr_alloc_multiple_cond(handle->file, handle->curblock+1,
                                        nblock + ((remain>offset)?1:0), &begin, &end,
                                        log_callback) == handle->curblock+1) {

            // start from current block
            assert(begin == handle->curblock + 1);

            _add_blk_marker(handle->file, handle->curblock, blocksize, marker, log_callback);
            if (offset > 0) {
                filemgr_write_offset(handle->file, handle->curblock, handle->curpos,
                                     offset, buf, log_callback);
            }
            remainsize -= offset;

            startpos = handle->curblock * real_blocksize + handle->curpos;
        } else {
            // next block to be allocated is not continuous .. allocate new multiple blocks
            filemgr_alloc_multiple(handle->file, nblock+((remain>0)?1:0),
                                   &begin, &end, log_callback);
            offset = 0;

            startpos = begin * real_blocksize;
        }

    #else
        // simple append mode .. always append at the end of file
        offset = blocksize - handle->curpos;
        if (filemgr_alloc_multiple_cond(handle->file, handle->curblock+1,
                                        nblock + ((remain>offset)?1:0), &begin, &end,
                                        log_callback) == handle->curblock+1) {
            // start from current block
            assert(begin == handle->curblock + 1);

            _add_blk_marker(handle->file, handle->curblock, blocksize, marker, log_callback);
            if (offset > 0) {
                filemgr_write_offset(handle->file, handle->curblock, handle->curpos,
                                     offset, buf, log_callback);
            }
            remainsize -= offset;

            startpos = handle->curblock * real_blocksize + handle->curpos;
        } else {
            // next block to be allocated is not continuous .. allocate new multiple blocks
            filemgr_alloc_multiple(handle->file, nblock+((remain>0)?1:0),
                                   &begin, &end, log_callback);
            offset = 0;

            startpos = begin * real_blocksize;
        }

    #endif

        for (i=begin; i<=end; ++i) {
            handle->curblock = i;
            if (remainsize >= blocksize) {
                // write entire block
                _add_blk_marker(handle->file, i, blocksize, marker, log_callback);
                filemgr_write(handle->file, i, (uint8_t *)buf + offset, log_callback);
                offset += blocksize;
                remainsize -= blocksize;
                handle->curpos = blocksize;

            } else {
                // write rest of document
                assert(i==end);
                _add_blk_marker(handle->file, i, blocksize, marker, log_callback);
                filemgr_write_offset(handle->file, i, 0, remainsize,
                                     (uint8_t *)buf + offset, log_callback);
                offset += remainsize;
                handle->curpos = remainsize;
            }
        }

        return startpos;
    }

    return 0;
}

#ifdef __ENDIAN_SAFE
INLINE struct docio_length _docio_length_encode(struct docio_length length)
{
    struct docio_length ret;
    ret = length;
    ret.keylen = _endian_encode(length.keylen);
    ret.metalen = _endian_encode(length.metalen);
    ret.bodylen = _endian_encode(length.bodylen);
    ret.bodylen_ondisk = _endian_encode(length.bodylen_ondisk);
    return ret;
}
INLINE struct docio_length _docio_length_decode(struct docio_length length)
{
    struct docio_length ret;
    ret = length;
    ret.keylen = _endian_decode(length.keylen);
    ret.metalen = _endian_decode(length.metalen);
    ret.bodylen = _endian_decode(length.bodylen);
    ret.bodylen_ondisk = _endian_decode(length.bodylen_ondisk);
    return ret;
}
#else
#define _docio_length_encode(a)
#define _docio_length_decode(a)
#endif

INLINE uint8_t _docio_length_checksum(struct docio_length length)
{
    return (uint8_t)(
        crc32_8(&length,
                sizeof(keylen_t) + sizeof(uint16_t) + sizeof(uint32_t)*2,
                0)
        & 0xff);
}

#define DOCIO_NORMAL (0x00)
#define DOCIO_COMPACT (0x01)
#define DOCIO_COMPRESSED (0x02)
INLINE bid_t _docio_append_doc(struct docio_handle *handle, struct docio_object *doc)
{
    int ret;
    size_t _len;
    uint32_t offset = 0;
    uint32_t crc;
    uint32_t compbuf_len, _compbuf_len;
    uint64_t docsize;
    void *buf;
    void *compbuf;
    bid_t ret_offset;
    fdb_seqnum_t _seqnum;
    timestamp_t _timestamp;
    struct docio_length length, _length;
    err_log_callback *log_callback = handle->log_callback;

    length = doc->length;
    length.bodylen_ondisk = length.bodylen;

#ifdef _DOC_COMP
    if (doc->length.bodylen > 0 && handle->compress_document_body) {
        compbuf_len = snappy_max_compressed_length(length.bodylen);
        compbuf = (void *)malloc(compbuf_len);

        _len = compbuf_len;
        ret = snappy_compress((char*)doc->body, length.bodylen, (char*)compbuf, &_len);
        if (ret < 0) {
            if (log_callback && log_callback->callback) {
                char msg[1024];
                sprintf(msg, "Error in compressing the doc body of key '%s'",
                        (char *) doc->key);
                log_callback->callback(FDB_RESULT_COMPRESSION_FAIL, msg,
                                       log_callback->ctx_data);
            }
            // we use BLK_NOT_FOUND for error code of appending instead of 0
            // because document can be written at the byte offset 0
            return BLK_NOT_FOUND;
        }

        length.bodylen_ondisk = compbuf_len = _len;
        length.flag |= DOCIO_COMPRESSED;

        docsize = sizeof(struct docio_length) + length.keylen + length.metalen;
        docsize += compbuf_len;
    } else {
        docsize = sizeof(struct docio_length) + length.keylen + length.metalen + length.bodylen;
    }
#else
    docsize = sizeof(struct docio_length) + length.keylen + length.metalen + length.bodylen;
#endif
    docsize += sizeof(timestamp_t);

#ifdef __FDB_SEQTREE
    docsize += sizeof(fdb_seqnum_t);
#endif
#ifdef __CRC32
    docsize += sizeof(crc);
#endif

    doc->length = length;
    buf = (void *)malloc(docsize);

    _length = _docio_length_encode(length);

    // calculate checksum of LENGTH using crc
    _length.checksum = _docio_length_checksum(_length);

    memcpy((uint8_t *)buf + offset, &_length, sizeof(struct docio_length));
    offset += sizeof(struct docio_length);

    // copy key
    memcpy((uint8_t *)buf + offset, doc->key, length.keylen);
    offset += length.keylen;

    // copy timestamp
    _timestamp = _endian_encode(doc->timestamp);
    memcpy((uint8_t*)buf + offset, &_timestamp, sizeof(_timestamp));
    offset += sizeof(_timestamp);

#ifdef __FDB_SEQTREE
    // copy seqeunce number (optional)
    _seqnum = _endian_encode(doc->seqnum);
    memcpy((uint8_t *)buf + offset, &_seqnum, sizeof(fdb_seqnum_t));
    offset += sizeof(fdb_seqnum_t);
#endif

    // copy metadata (optional)
    if (length.metalen > 0) {
        memcpy((uint8_t *)buf + offset, doc->meta, length.metalen);
        offset += length.metalen;
    }

    // copy body (optional)
    if (length.bodylen > 0) {
        if (length.flag & DOCIO_COMPRESSED) {
            // compressed body
            memcpy((uint8_t*)buf + offset, compbuf, compbuf_len);
            offset += compbuf_len;
            free(compbuf);
        } else {
            memcpy((uint8_t *)buf + offset, doc->body, length.bodylen);
            offset += length.bodylen;
        }
    }

#ifdef __CRC32
    crc = crc32_8(buf, docsize - sizeof(crc), 0);
    memcpy((uint8_t *)buf + offset, &crc, sizeof(crc));
#endif

    ret_offset = docio_append_doc_raw(handle, docsize, buf);
    free(buf);

    return ret_offset;
}

bid_t docio_append_doc_compact(struct docio_handle *handle, struct docio_object *doc)
{
    doc->length.flag = DOCIO_COMPACT;
    return _docio_append_doc(handle, doc);
}

bid_t docio_append_doc(struct docio_handle *handle, struct docio_object *doc)
{
    doc->length.flag = DOCIO_NORMAL;
    return _docio_append_doc(handle, doc);
}

INLINE void _docio_read_through_buffer(struct docio_handle *handle, bid_t bid,
                                       err_log_callback *log_callback)
{
    // to reduce the overhead from memcpy the same block
    if (handle->lastbid != bid) {
        filemgr_read(handle->file, bid, handle->readbuffer, log_callback);

        if (filemgr_is_writable(handle->file, bid)) {
            // this block can be modified later .. must be re-read
            handle->lastbid = BLK_NOT_FOUND;
        }else{
            handle->lastbid = bid;
        }
    }
}

uint64_t _docio_read_length(struct docio_handle *handle,
                            uint64_t offset,
                            struct docio_length *length,
                            err_log_callback *log_callback)
{
    size_t blocksize = handle->file->blocksize;
    size_t real_blocksize = blocksize;
#ifdef __CRC32
    blocksize -= BLK_MARKER_SIZE;
#endif

    if (filemgr_get_pos(handle->file) < (offset + sizeof(struct docio_length))) {
        return offset;
    }

    bid_t bid = offset / real_blocksize;
    uint32_t pos = offset % real_blocksize;
    void *buf = handle->readbuffer;
    uint32_t restsize;

    restsize = blocksize - pos;
    // read length structure
    _docio_read_through_buffer(handle, bid, log_callback);

    if (restsize >= sizeof(struct docio_length)) {
        memcpy(length, (uint8_t *)buf + pos, sizeof(struct docio_length));
        pos += sizeof(struct docio_length);

    }else{
        memcpy(length, (uint8_t *)buf + pos, restsize);
        // read additional block
        bid++;
        _docio_read_through_buffer(handle, bid, log_callback);
        // memcpy rest of data
        memcpy((uint8_t *)length + restsize, buf, sizeof(struct docio_length) - restsize);
        pos = sizeof(struct docio_length) - restsize;
    }

    return bid * real_blocksize + pos;
}

uint64_t _docio_read_doc_component(struct docio_handle *handle,
                                   uint64_t offset,
                                   uint32_t len,
                                   void *buf_out,
                                   err_log_callback *log_callback)
{
    uint32_t rest_len;
    size_t blocksize = handle->file->blocksize;
    size_t real_blocksize = blocksize;
#ifdef __CRC32
    blocksize -= BLK_MARKER_SIZE;
#endif

    bid_t bid = offset / real_blocksize;
    uint32_t pos = offset % real_blocksize;
    //uint8_t buf[handle->file->blocksize];
    void *buf = handle->readbuffer;
    uint32_t restsize;

    rest_len = len;

    while(rest_len > 0) {
        _docio_read_through_buffer(handle, bid, log_callback);
        restsize = blocksize - pos;

        if (restsize >= rest_len) {
            memcpy((uint8_t *)buf_out + (len - rest_len), (uint8_t *)buf + pos, rest_len);
            pos += rest_len;
            rest_len = 0;
        }else{
            memcpy((uint8_t *)buf_out + (len - rest_len), (uint8_t *)buf + pos, restsize);
            bid++;
            pos = 0;
            rest_len -= restsize;

            if (rest_len > 0 &&
                bid >= filemgr_get_pos(handle->file) / handle->file->blocksize) {
                // no more data in the file .. the file is corrupted
                if (log_callback && log_callback->callback) {
                    char msg[1024];
                    sprintf(msg, "Fatal error!!! Database file '%s' is corrupted.",
                            handle->file->filename);
                    log_callback->callback(FDB_RESULT_FILE_CORRUPTION, msg,
                                           log_callback->ctx_data);
                }
                // TODO: Need to return a better error code.
                return 0;
            }
        }
    }

    return bid * real_blocksize + pos;
}

#ifdef _DOC_COMP

uint64_t _docio_read_doc_component_comp(struct docio_handle *handle,
                                        uint64_t offset,
                                        uint32_t len,
                                        uint32_t comp_len,
                                        void *buf_out,
                                        void *comp_data_out,
                                        err_log_callback *log_callback)
{
    int ret;
    size_t uncomp_size;
    uint64_t _offset;

    _offset = _docio_read_doc_component(handle, offset,
                                        comp_len, comp_data_out, log_callback);
    if (_offset == 0) {
        return 0;
    }

    uncomp_size = len;
    ret = snappy_uncompress((char*)comp_data_out, comp_len,
                            (char*)buf_out, &uncomp_size);
    if (ret < 0) return 0;

    assert(uncomp_size == len);
    return _offset;
}

#endif

// return length.keylen = 0 if failure
struct docio_length docio_read_doc_length(struct docio_handle *handle, uint64_t offset)
{
    uint8_t checksum;
    uint64_t _offset;
    struct docio_length length, _length;
    err_log_callback *log_callback = handle->log_callback;

    _offset = _docio_read_length(handle, offset, &_length, log_callback);
    if (_offset == offset) {
        length.keylen = 0;
        return length;
    }

    // checksum check
    checksum = _docio_length_checksum(_length);
    if (checksum != _length.checksum) {
        if (log_callback && log_callback->callback) {
            char msg[1024];
            sprintf(msg, "doc_length checksum mismatch error in a database file '%s'",
                    handle->file->filename);
            log_callback->callback(FDB_RESULT_CHECKSUM_ERROR, msg, log_callback->ctx_data);
        }
        length.keylen = 0;
        return length;
    }

    length = _docio_length_decode(_length);
    if (length.keylen == 0 || length.keylen > FDB_MAX_KEYLEN) {
        length.keylen = 0;
        return length;
    }

    // document size check
    if (offset + sizeof(struct docio_length) +
        length.keylen + length.metalen + length.bodylen_ondisk >
        filemgr_get_pos(handle->file)) {
        if (log_callback && log_callback->callback) {
            char msg[1024];
            sprintf(msg, "Fatal error!!! Database file '%s' is corrupted.",
                    handle->file->filename);
            log_callback->callback(FDB_RESULT_FILE_CORRUPTION, msg,
                                   log_callback->ctx_data);
        }
        length.keylen = 0;
        return length;
    }

    return length;
}

// return length.keylen = 0 if failure
void docio_read_doc_key(struct docio_handle *handle, uint64_t offset,
                        keylen_t *keylen, void *keybuf)
{
    uint8_t checksum;
    uint64_t _offset;
    struct docio_length length, _length;
    err_log_callback *log_callback = handle->log_callback;

    _offset = _docio_read_length(handle, offset, &_length, log_callback);
    if (_offset == offset) {
        *keylen = 0;
        return;
    }

    // checksum check
    checksum = _docio_length_checksum(_length);
    if (checksum != _length.checksum) {
        if (log_callback && log_callback->callback) {
            char msg[1024];
            sprintf(msg, "doc_length checksum mismatch error in a database file '%s'",
                    handle->file->filename);
            log_callback->callback(FDB_RESULT_CHECKSUM_ERROR, msg, log_callback->ctx_data);
        }
        *keylen = 0;
        return;
    }

    length = _docio_length_decode(_length);
    if (length.keylen == 0 || length.keylen > FDB_MAX_KEYLEN) {
        *keylen = 0;
        return;
    }

    // document size check
    if (offset + sizeof(struct docio_length) +
        length.keylen + length.metalen + length.bodylen_ondisk >
        filemgr_get_pos(handle->file)) {
        if (log_callback && log_callback->callback) {
            char msg[1024];
            sprintf(msg, "Fatal error!!! Database file '%s' is corrupted.",
                    handle->file->filename);
            log_callback->callback(FDB_RESULT_FILE_CORRUPTION, msg,
                                   log_callback->ctx_data);
        }
        *keylen = 0;
        return;
    }

    assert(length.keylen < FDB_MAX_KEYLEN);

    _offset = _docio_read_doc_component(handle, _offset, length.keylen, keybuf, log_callback);
    *keylen = length.keylen;
}

static void free_docio_object(struct docio_object *doc, uint8_t key_alloc,
                              uint8_t meta_alloc, uint8_t body_alloc) {
    if (!doc) {
        return;
    }

    if (key_alloc) {
        free(doc->key);
        doc->key = NULL;
    }
    if (meta_alloc) {
        free(doc->meta);
        doc->meta = NULL;
    }
    if (body_alloc) {
        free(doc->body);
        doc->body = NULL;
    }
}

uint64_t docio_read_doc_key_meta(struct docio_handle *handle, uint64_t offset,
                                 struct docio_object *doc)
{
    uint8_t checksum;
    uint64_t _offset;
    int key_alloc = 0;
    int meta_alloc = 0;
    fdb_seqnum_t _seqnum;
    timestamp_t _timestamp;
    struct docio_length _length;
    err_log_callback *log_callback = handle->log_callback;

    _offset = _docio_read_length(handle, offset, &_length, log_callback);
    if (_offset == offset) {
        return offset;
    }

    // checksum check
    checksum = _docio_length_checksum(_length);
    if (checksum != _length.checksum) {
        if (log_callback && log_callback->callback) {
            char msg[1024];
            sprintf(msg, "doc_length checksum mismatch error in a database file '%s'",
                    handle->file->filename);
            log_callback->callback(FDB_RESULT_CHECKSUM_ERROR, msg, log_callback->ctx_data);
        }
        return offset;
    }

    doc->length = _docio_length_decode(_length);
    if (doc->length.keylen == 0 || doc->length.keylen > FDB_MAX_KEYLEN) {
        return offset;
    }

    // document size check
    if (offset + sizeof(struct docio_length) +
        doc->length.keylen + doc->length.metalen + doc->length.bodylen_ondisk >
        filemgr_get_pos(handle->file)) {
        if (log_callback && log_callback->callback) {
            char msg[1024];
            sprintf(msg, "Fatal error!!! Database file '%s' is corrupted.",
                    handle->file->filename);
            log_callback->callback(FDB_RESULT_FILE_CORRUPTION, msg,
                                   log_callback->ctx_data);
        }
        return offset;
    }

    if (doc->key == NULL) {
        doc->key = (void *)malloc(doc->length.keylen);
        key_alloc = 1;
    }
    if (doc->meta == NULL) {
        doc->meta = (void *)malloc(doc->length.metalen);
        meta_alloc = 1;
    }

    assert(doc->key && doc->meta);

    _offset = _docio_read_doc_component(handle, _offset, doc->length.keylen,
                                        doc->key, log_callback);
    if (_offset == 0) {
        free_docio_object(doc, key_alloc, meta_alloc, 0);
        return offset;
    }

    // read timestamp
    _offset = _docio_read_doc_component(handle, _offset,
                                        sizeof(timestamp_t),
                                        &_timestamp, log_callback);
    if (_offset == 0) {
        free_docio_object(doc, key_alloc, meta_alloc, 0);
        return offset;
    }
    doc->timestamp = _endian_decode(_timestamp);

#ifdef __FDB_SEQTREE
    // copy sequence number (optional)
    _offset = _docio_read_doc_component(handle, _offset, sizeof(fdb_seqnum_t),
                                        (void *)&_seqnum, log_callback);
    if (_offset == 0) {
        free_docio_object(doc, key_alloc, meta_alloc, 0);
        return offset;
    }
    doc->seqnum = _endian_decode(_seqnum);
#endif

    _offset = _docio_read_doc_component(handle, _offset, doc->length.metalen,
                                        doc->meta, log_callback);
    if (_offset == 0) {
        free_docio_object(doc, key_alloc, meta_alloc, 0);
        return offset;
    }

    return _offset;
}

uint64_t docio_read_doc(struct docio_handle *handle, uint64_t offset,
                        struct docio_object *doc)
{
    uint8_t checksum;
    uint32_t comp_len;
    uint64_t _offset;
    int key_alloc = 0;
    int meta_alloc = 0;
    int body_alloc = 0;
    fdb_seqnum_t _seqnum;
    timestamp_t _timestamp;
    void *comp_body = NULL;
    struct docio_length _length;
    err_log_callback *log_callback = handle->log_callback;

    _offset = _docio_read_length(handle, offset, &_length, log_callback);
    if (_offset == offset) {
        return offset;
    }

    // checksum check
    checksum = _docio_length_checksum(_length);
    if (checksum != _length.checksum) {
        if (log_callback && log_callback->callback) {
            char msg[1024];
            sprintf(msg, "doc_length checksum mismatch error in a database file '%s'",
                    handle->file->filename);
            log_callback->callback(FDB_RESULT_CHECKSUM_ERROR, msg, log_callback->ctx_data);
        }
        return offset;
    }

    doc->length = _docio_length_decode(_length);
    if (doc->length.keylen == 0 || doc->length.keylen > FDB_MAX_KEYLEN) {
        return offset;
    }

    // document size check
    if (offset + sizeof(struct docio_length) +
        doc->length.keylen + doc->length.metalen + doc->length.bodylen_ondisk >
        filemgr_get_pos(handle->file)) {
        if (log_callback && log_callback->callback) {
            char msg[1024];
            sprintf(msg, "Fatal error!!! Database file '%s' is corrupted.",
                    handle->file->filename);
            log_callback->callback(FDB_RESULT_FILE_CORRUPTION, msg,
                                   log_callback->ctx_data);
        }
        return offset;
    }

    if (doc->key == NULL) {
        doc->key = (void *)malloc(doc->length.keylen);
        key_alloc = 1;
    }
    if (doc->meta == NULL) {
        doc->meta = (void *)malloc(doc->length.metalen);
        meta_alloc = 1;
    }
    if (doc->body == NULL) {
        doc->body = (void *)malloc(doc->length.bodylen);
        body_alloc = 1;
    }

    assert(doc->key && doc->meta && doc->body);

    _offset = _docio_read_doc_component(handle, _offset,
                                        doc->length.keylen,
                                        doc->key,
                                        log_callback);
    if (_offset == 0) {
        free_docio_object(doc, key_alloc, meta_alloc, body_alloc);
        return offset;
    }

    // read timestamp
    _offset = _docio_read_doc_component(handle, _offset,
                                        sizeof(timestamp_t),
                                        &_timestamp,
                                        log_callback);
    if (_offset == 0) {
        free_docio_object(doc, key_alloc, meta_alloc, body_alloc);
        return offset;
    }
    doc->timestamp = _endian_decode(_timestamp);

#ifdef __FDB_SEQTREE
    // copy seqeunce number (optional)
    _offset = _docio_read_doc_component(handle, _offset,
                                        sizeof(fdb_seqnum_t),
                                        (void *)&_seqnum,
                                        log_callback);
    if (_offset == 0) {
        free_docio_object(doc, key_alloc, meta_alloc, body_alloc);
        return offset;
    }
    doc->seqnum = _endian_decode(_seqnum);
#endif

    _offset = _docio_read_doc_component(handle, _offset, doc->length.metalen,
                                        doc->meta, log_callback);
    if (_offset == 0) {
        free_docio_object(doc, key_alloc, meta_alloc, body_alloc);
        return offset;
    }

#ifdef _DOC_COMP
    if (doc->length.flag & DOCIO_COMPRESSED) {
        comp_body = (void*)malloc(doc->length.bodylen_ondisk);
        _offset = _docio_read_doc_component_comp(handle, _offset, doc->length.bodylen,
                                                 doc->length.bodylen_ondisk, doc->body,
                                                 comp_body, log_callback);
        if (_offset == 0) {
            if (comp_body) {
                free(comp_body);
            }
            free_docio_object(doc, key_alloc, meta_alloc, body_alloc);
            return offset;
        }
    } else {
        _offset = _docio_read_doc_component(handle, _offset, doc->length.bodylen,
                                            doc->body, log_callback);
        if (_offset == 0) {
            free_docio_object(doc, key_alloc, meta_alloc, body_alloc);
            return offset;
        }
    }
#else
    _offset = _docio_read_doc_component(handle, _offset, doc->length.bodylen,
                                        doc->body, log_callback);
    if (_offset == 0) {
        if (comp_body) {
            free(comp_body);
        }
        free_docio_object(doc, key_alloc, meta_alloc, body_alloc);
        return offset;
    }
#endif

#ifdef __CRC32
    uint32_t crc_file, crc;
    _offset = _docio_read_doc_component(handle, _offset, sizeof(crc_file),
                                        (void *)&crc_file, log_callback);
    if (_offset == 0) {
        if (comp_body) {
            free(comp_body);
        }
        free_docio_object(doc, key_alloc, meta_alloc, body_alloc);
        return offset;
    }

    crc = crc32_8((void *)&_length, sizeof(_length), 0);
    crc = crc32_8(doc->key, doc->length.keylen, crc);
    crc = crc32_8((void *)&_timestamp, sizeof(timestamp_t), crc);
    crc = crc32_8((void *)&_seqnum, sizeof(fdb_seqnum_t), crc);
    crc = crc32_8(doc->meta, doc->length.metalen, crc);
    if (doc->length.flag & DOCIO_COMPRESSED) {
        crc = crc32_8(comp_body, doc->length.bodylen_ondisk, crc);
        if (comp_body) {
            free(comp_body);
        }
    } else {
        crc = crc32_8(doc->body, doc->length.bodylen, crc);
    }
    if (crc != crc_file) {
        if (log_callback && log_callback->callback) {
            char msg[1024];
            sprintf(msg, "doc_body checksum mismatch error in a database file '%s'",
                    handle->file->filename);
            log_callback->callback(FDB_RESULT_CHECKSUM_ERROR, msg, log_callback->ctx_data);
        }
        free_docio_object(doc, key_alloc, meta_alloc, body_alloc);
        return offset;
    }
#endif
    return _offset;
}

int docio_check_buffer(struct docio_handle *handle, bid_t bid)
{
    uint8_t marker[BLK_MARKER_SIZE];
    err_log_callback *log_callback = handle->log_callback;
    _docio_read_through_buffer(handle, bid, log_callback);
    marker[0] = *(((uint8_t *)handle->readbuffer)
                 + handle->file->blocksize - BLK_MARKER_SIZE);
    return (marker[0] == BLK_MARKER_DOC);
}

int docio_check_compact_doc(struct docio_handle *handle,
                            struct docio_object *doc)
{
    if (doc->length.flag & DOCIO_COMPACT) return 1;
    else return 0;
}


