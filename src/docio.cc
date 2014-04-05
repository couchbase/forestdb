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

#include "memleak.h"

void docio_init(struct docio_handle *handle, struct filemgr *file)
{
    int ret;
    //size_t filemgr_sys_pagesize = sysconf(_SC_PAGESIZE);

    handle->file = file;
    handle->curblock = BLK_NOT_FOUND;
    handle->curpos = 0;
    handle->lastbid = BLK_NOT_FOUND;
    //handle->readbuffer = (void *)mempool_alloc(file->blocksize);
    malloc_align(handle->readbuffer, FDB_SECTOR_SIZE, file->blocksize);
}

void docio_free(struct docio_handle *handle)
{
    free_align(handle->readbuffer);
}

#ifdef __CRC32
    #define _add_blk_marker(file, bid, blocksize, marker) \
        filemgr_write_offset((file), (bid), (blocksize), BLK_MARKER_SIZE, (marker))
#else
    #define _add_blk_marker(file, bid, blocksize, marker)
#endif

INLINE bid_t docio_append_doc_raw(struct docio_handle *handle, uint64_t size, void *buf)
{
    bid_t bid;
    uint32_t offset;
    uint8_t marker[BLK_MARKER_SIZE];
    size_t blocksize = handle->file->blocksize;
    size_t real_blocksize = blocksize;
#ifdef __CRC32
    blocksize -= BLK_MARKER_SIZE;
    memset(marker, BLK_MARKER_DOC, BLK_MARKER_SIZE);
#endif

    if (handle->curblock == BLK_NOT_FOUND) {
        // allocate new block
        handle->curblock = filemgr_alloc(handle->file);
        handle->curpos = 0;
    }
    if (!filemgr_is_writable(handle->file, handle->curblock)) {
        // allocate new block
        handle->curblock = filemgr_alloc(handle->file);
        handle->curpos = 0;
    }

    if (size <= blocksize - handle->curpos) {
        // simply append to current block
        offset = handle->curpos;
        _add_blk_marker(handle->file, handle->curblock, blocksize, marker);
        filemgr_write_offset(handle->file, handle->curblock, offset, size, buf);
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
                nblock + ((remain>offset)?1:0), &begin, &end) == handle->curblock+1) {

            // start from current block
            assert(begin == handle->curblock + 1);

            _add_blk_marker(handle->file, handle->curblock, blocksize, marker);
            if (offset > 0) {
                filemgr_write_offset(handle->file, handle->curblock, handle->curpos, offset, buf);
            }
            remainsize -= offset;

            startpos = handle->curblock * real_blocksize + handle->curpos;
        }else {
            // next block to be allocated is not continuous .. allocate new multiple blocks
            filemgr_alloc_multiple(handle->file, nblock+((remain>0)?1:0), &begin, &end);
            offset = 0;

            startpos = begin * real_blocksize;
        }

    #else
        // simple append mode .. always append at the end of file
        offset = blocksize - handle->curpos;
        if (filemgr_alloc_multiple_cond(handle->file, handle->curblock+1,
                nblock + ((remain>offset)?1:0), &begin, &end) == handle->curblock+1) {
            // start from current block
            assert(begin == handle->curblock + 1);

            _add_blk_marker(handle->file, handle->curblock, blocksize, marker);
            if (offset > 0) {
                filemgr_write_offset(handle->file, handle->curblock, handle->curpos, offset, buf);
            }
            remainsize -= offset;

            startpos = handle->curblock * real_blocksize + handle->curpos;
        }else {
            // next block to be allocated is not continuous .. allocate new multiple blocks
            filemgr_alloc_multiple(handle->file, nblock+((remain>0)?1:0), &begin, &end);
            offset = 0;

            startpos = begin * real_blocksize;
        }

    #endif

        for (i=begin; i<=end; ++i) {
            handle->curblock = i;
            if (remainsize >= blocksize) {
                // write entire block
                _add_blk_marker(handle->file, i, blocksize, marker);
                filemgr_write(handle->file, i, (uint8_t *)buf + offset);
                offset += blocksize;
                remainsize -= blocksize;
                handle->curpos = blocksize;

            }else{
                // write rest of document
                assert(i==end);
                _add_blk_marker(handle->file, i, blocksize, marker);
                filemgr_write_offset(handle->file, i, 0, remainsize, (uint8_t *)buf + offset);
                offset += remainsize;
                handle->curpos = remainsize;
            }
        }

        return startpos;
    }

    return 0;
}

#ifdef __ENDIAN_SAFE
INLINE struct docio_length _docio_encode(struct docio_length length)
{
    struct docio_length ret;
    ret = length;
    ret.keylen = _endian_encode(length.keylen);
    ret.metalen = _endian_encode(length.metalen);
    ret.bodylen = _endian_encode(length.bodylen);
    return ret;
}
INLINE struct docio_length _docio_decode(struct docio_length length)
{
    struct docio_length ret;
    ret = length;
    ret.keylen = _endian_decode(length.keylen);
    ret.metalen = _endian_decode(length.metalen);
    ret.bodylen = _endian_decode(length.bodylen);
    return ret;
}
#else
#define _docio_encode(a)
#define _docio_decode(a)
#endif

INLINE uint8_t _docio_length_checksum(struct docio_length length)
{
    return (uint8_t)(
        crc32_8(&length,
                sizeof(keylen_t) + sizeof(uint16_t) + sizeof(uint32_t),
                0)
        & 0xff);
}

#define DOCIO_NORMAL (0x00)
#define DOCIO_COMPACT (0xcc)
INLINE bid_t _docio_append_doc(struct docio_handle *handle, struct docio_object *doc)
{
    uint32_t offset = 0;
    uint32_t crc;
    uint64_t docsize;
    size_t compbuf_len;
    void *buf;
    void *compbuf;
    bid_t ret_offset;
    fdb_seqnum_t _seqnum;
    struct docio_length length, _length;

    length = doc->length;

#ifdef _DOC_COMP
    if (doc->length.bodylen > 0) {
        compbuf_len = snappy_max_compressed_length(length.bodylen);
        compbuf = (void *)malloc(compbuf_len);

        snappy_compress(doc->body, length.bodylen, compbuf, &compbuf_len);
        length.bodylen = compbuf_len;
    }
#endif

    docsize = sizeof(struct docio_length) + length.keylen + length.metalen + length.bodylen;
#ifdef __FDB_SEQTREE
    docsize += sizeof(fdb_seqnum_t);
#endif
#ifdef __CRC32
    docsize += sizeof(crc);
#endif
    buf = (void *)malloc(docsize);

    _length = _docio_encode(length);

    // calculate checksum of LENGTH using crc
    _length.checksum = _docio_length_checksum(_length);

    memcpy((uint8_t *)buf + offset, &_length, sizeof(struct docio_length));
    offset += sizeof(struct docio_length);

    // copy key
    memcpy((uint8_t *)buf + offset, doc->key, length.keylen);
    offset += length.keylen;

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
#ifdef _DOC_COMP
        memcpy(buf + offset, compbuf, length.bodylen);
        free(compbuf);
#else
        memcpy((uint8_t *)buf + offset, doc->body, length.bodylen);
#endif
        offset += length.bodylen;
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

INLINE void _docio_read_through_buffer(struct docio_handle *handle, bid_t bid)
{
    // to reduce the overhead from memcpy the same block
    if (handle->lastbid != bid) {
        filemgr_read(handle->file, bid, handle->readbuffer);

        if (filemgr_is_writable(handle->file, bid)) {
            // this block can be modified later .. must be re-read
            handle->lastbid = BLK_NOT_FOUND;
        }else{
            handle->lastbid = bid;
        }
    }
}

uint64_t _docio_read_length(struct docio_handle *handle, uint64_t offset, struct docio_length *length)
{
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

    restsize = blocksize - pos;
    // read length structure
    _docio_read_through_buffer(handle, bid);

    if (restsize >= sizeof(struct docio_length)) {
        memcpy(length, (uint8_t *)buf + pos, sizeof(struct docio_length));
        pos += sizeof(struct docio_length);

    }else{
        memcpy(length, (uint8_t *)buf + pos, restsize);
        // read additional block
        bid++;
        _docio_read_through_buffer(handle, bid);
        // memcpy rest of data
        memcpy((uint8_t *)length + restsize, buf, sizeof(struct docio_length) - restsize);
        pos = sizeof(struct docio_length) - restsize;
    }

    return bid * real_blocksize + pos;
}

uint64_t _docio_read_doc_component(struct docio_handle *handle,
                                   uint64_t offset,
                                   uint32_t len,
                                   void *buf_out)
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
        //filemgr_read(handle->file, bid, buf);
        _docio_read_through_buffer(handle, bid);
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

            if (bid >= filemgr_get_pos(handle->file) / handle->file->blocksize) {
                // no more data in the file .. the file is corrupted
                return 0;
            }
        }
    }

    return bid * real_blocksize + pos;
}

#ifdef _DOC_COMP

uint64_t _docio_read_doc_component_comp(struct docio_handle *handle, uint64_t offset, uint32_t *len, void *buf_out)
{
    uint32_t rest_len;
    size_t blocksize = handle->file->blocksize;
    bid_t bid = offset / blocksize;
    uint32_t pos = offset % blocksize;
    //uint8_t buf[handle->file->blocksize];
    void *buf = handle->readbuffer;
    void *temp_buf;
    uint32_t restsize;
    size_t uncomp_size;

    temp_buf = (void *)malloc(*len);
    rest_len = *len;

    while(rest_len > 0) {
        //filemgr_read(handle->file, bid, buf);
        _docio_read_through_buffer(handle, bid);
        restsize = blocksize - pos;

        if (restsize >= rest_len) {
            memcpy(temp_buf + (*len - rest_len), buf + pos, rest_len);
            pos += rest_len;
            rest_len = 0;
        }else{
            memcpy(temp_buf + (*len - rest_len), buf + pos, restsize);
            bid++;
            pos = 0;
            rest_len -= restsize;
        }
    }

    snappy_uncompressed_length(temp_buf, *len, &uncomp_size);
    snappy_uncompress(temp_buf, *len, buf_out, &uncomp_size);
    *len = uncomp_size;

    free(temp_buf);

    return bid * blocksize + pos;
}

#endif

// return length.keylen = 0 if failure
struct docio_length docio_read_doc_length(struct docio_handle *handle, uint64_t offset)
{
    uint8_t checksum;
    uint64_t _offset;
    struct docio_length length, _length;

    _offset = _docio_read_length(handle, offset, &_length);

    // checksum check
    checksum = _docio_length_checksum(_length);
    if (checksum != _length.checksum) {
        length.keylen = 0;
        return length;
    }

    length = _docio_decode(_length);
    if (length.keylen == 0 || length.keylen > FDB_MAX_KEYLEN) {
        length.keylen = 0;
        return length;
    }

    // document size check
    if (offset + sizeof(struct docio_length) +
        length.keylen + length.metalen + length.bodylen >
        filemgr_get_pos(handle->file)) {
        length.keylen = 0;
        return length;
    }

    return length;
}

// return length.keylen = 0 if failure
void docio_read_doc_key(struct docio_handle *handle, uint64_t offset, keylen_t *keylen, void *keybuf)
{
    uint8_t checksum;
    uint64_t _offset;
    struct docio_length length, _length;

    _offset = _docio_read_length(handle, offset, &_length);

    // checksum check
    checksum = _docio_length_checksum(_length);
    if (checksum != _length.checksum) {
        *keylen = 0;
        return;
    }

    length = _docio_decode(_length);
    if (length.keylen == 0 || length.keylen > FDB_MAX_KEYLEN) {
        *keylen = 0;
        return;
    }

    // document size check
    if (offset + sizeof(struct docio_length) +
        length.keylen + length.metalen + length.bodylen >
        filemgr_get_pos(handle->file)) {
        *keylen = 0;
        return;
    }

    assert(length.keylen < FDB_MAX_KEYLEN);

    _offset = _docio_read_doc_component(handle, _offset, length.keylen, keybuf);
    *keylen = length.keylen;
}

uint64_t docio_read_doc_key_meta(struct docio_handle *handle, uint64_t offset, struct docio_object *doc)
{
    uint8_t checksum;
    uint64_t _offset;
    struct docio_length _length;

    _offset = _docio_read_length(handle, offset, &_length);

    // checksum check
    checksum = _docio_length_checksum(_length);
    if (checksum != _length.checksum) {
        return offset;
    }

    doc->length = _docio_decode(_length);
    if (doc->length.keylen == 0 || doc->length.keylen > FDB_MAX_KEYLEN) {
        return offset;
    }

    // document size check
    if (offset + sizeof(struct docio_length) +
        doc->length.keylen + doc->length.metalen + doc->length.bodylen >
        filemgr_get_pos(handle->file)) {
        return offset;
    }

    if (doc->key == NULL) doc->key = (void *)malloc(doc->length.keylen);
    if (doc->meta == NULL) doc->meta = (void *)malloc(doc->length.metalen);

    assert(doc->key && doc->meta);

    _offset = _docio_read_doc_component(handle, _offset, doc->length.keylen, doc->key);
    if (_offset == 0) return offset;

#ifdef __FDB_SEQTREE
    // copy seqeunce number (optional)
    _offset = _docio_read_doc_component(handle, _offset,
                                        sizeof(fdb_seqnum_t), (void *)&doc->seqnum);
    if (_offset == 0) return offset;
#endif

    _offset = _docio_read_doc_component(handle, _offset, doc->length.metalen, doc->meta);
    if (_offset == 0) return offset;

    return _offset;
}

uint64_t docio_read_doc(struct docio_handle *handle, uint64_t offset,
                        struct docio_object *doc)
{
    uint8_t checksum;
    uint64_t _offset;
    int key_alloc = 0;
    int meta_alloc = 0;
    int body_alloc = 0;
    fdb_seqnum_t _seqnum;
    struct docio_length _length;

    _offset = _docio_read_length(handle, offset, &_length);

    // checksum check
    checksum = _docio_length_checksum(_length);
    if (checksum != _length.checksum) {
        return offset;
    }

    doc->length = _docio_decode(_length);
    if (doc->length.keylen == 0 || doc->length.keylen > FDB_MAX_KEYLEN) {
        return offset;
    }

    // document size check
    if (offset + sizeof(struct docio_length) +
        doc->length.keylen + doc->length.metalen + doc->length.bodylen >
        filemgr_get_pos(handle->file)) {
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

    _offset = _docio_read_doc_component(handle, _offset, doc->length.keylen, doc->key);
    if (_offset == 0) return offset;

#ifdef __FDB_SEQTREE
    // copy seqeunce number (optional)
    _offset = _docio_read_doc_component(handle, _offset,
                                        sizeof(fdb_seqnum_t), (void *)&_seqnum);
    if (_offset == 0) return offset;
    doc->seqnum = _endian_decode(_seqnum);
#endif

    _offset = _docio_read_doc_component(handle, _offset, doc->length.metalen, doc->meta);
    if (_offset == 0) return offset;

#ifdef _DOC_COMP
    _offset = _docio_read_doc_component_comp(handle, _offset, &doc->length.bodylen, doc->body);
    if (_offset == 0) return offset;
#else
    _offset = _docio_read_doc_component(handle, _offset, doc->length.bodylen, doc->body);
    if (_offset == 0) return offset;
#endif

#ifdef __CRC32
    uint32_t crc_file, crc;
    _offset = _docio_read_doc_component(handle, _offset, sizeof(crc_file), (void *)&crc_file);
    if (_offset == 0) return offset;

    crc = crc32_8((void *)&_length, sizeof(_length), 0);
    crc = crc32_8(doc->key, doc->length.keylen, crc);
    crc = crc32_8((void *)&_seqnum, sizeof(fdb_seqnum_t), crc);
    crc = crc32_8(doc->meta, doc->length.metalen, crc);
    crc = crc32_8(doc->body, doc->length.bodylen, crc);
    if (crc != crc_file) {
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
        return offset;
    }
#endif
    return _offset;
}

int docio_check_buffer(struct docio_handle *handle, bid_t bid)
{
    uint8_t marker[BLK_MARKER_SIZE];
    _docio_read_through_buffer(handle, bid);
    marker[0] = *(((uint8_t *)handle->readbuffer)
                 + handle->file->blocksize - BLK_MARKER_SIZE);
    return (marker[0] == BLK_MARKER_DOC);
}

int docio_check_compact_doc(struct docio_handle *handle,
                            struct docio_object *doc)
{
    if (doc->length.flag == DOCIO_COMPACT) return 1;
    else return 0;
}


