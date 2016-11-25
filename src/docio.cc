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
#include "fdb_internal.h"
#include "version.h"
#ifdef _DOC_COMP
#include "snappy-c.h"
#endif

#include "memleak.h"

DocioHandle::DocioHandle(FileMgr *file, bool compress_doc_body,
                         ErrLogCallback *log_callback) :
   file_Docio(file), curblock(BLK_NOT_FOUND), curpos(0), cur_bmp_revnum_hash(0),
   compress_document_body(compress_doc_body),
   log_callback(log_callback), lastbid(BLK_NOT_FOUND),
   lastBmpRevnum(0), readbuffer(NULL)
{
    malloc_align(readbuffer, FDB_SECTOR_SIZE, file->getBlockSize());
}

DocioHandle::~DocioHandle()
{
    if (readbuffer) { // let out-of-scope destructor co-exist with exlpicit
        free_align(readbuffer); // calls to the destructor (make idempotent)
        readbuffer = NULL;
    }
}

#ifdef __CRC32
fdb_status _add_blk_marker(FileMgr *file, bid_t bid, uint64_t blocksize,
                           void *marker, ErrLogCallback *log_callback) {
    return file->writeOffset(bid, blocksize, BLK_MARKER_SIZE, marker,
                             false, log_callback);
}
#else
#define _add_blk_marker(file, bid, blocksize, marker, log_callback) \
    FDB_RESULT_SUCCESS
#endif

inline
fdb_status DocioHandle::_fillZero_Docio(bid_t bid,
                                         size_t pos)
{
    // Fill next few bytes (sizeof(struct docio_length)) with zero
    // to avoid false positive docio_length checksum during file scanning.
    // (Note that the checksum value of zero-filled docio_length is 0x6F.)

    size_t blocksize = file_Docio->getBlockSize();
    size_t len_size = sizeof(struct docio_length);
    uint8_t *zerobuf = alca(uint8_t, len_size);

#ifdef __CRC32
    if (ver_non_consecutive_doc(file_Docio->getVersion())) {
        // new version: support non-consecutive document block
        blocksize -= DOCBLK_META_SIZE;
    } else {
        // old version: block marker only
        blocksize -= BLK_MARKER_SIZE;
    }
#endif

    if (pos + len_size <= blocksize) {
        // enough space in the block
        memset(zerobuf, 0x0, len_size);
        return file_Docio->writeOffset(bid, pos, len_size,
                                       zerobuf, false, log_callback);
    } else {
        // lack of space .. we don't need to fill zero bytes.
        return FDB_RESULT_SUCCESS;
    }
}

bid_t DocioHandle::appendDocRaw_Docio(uint64_t size, void *buf)
{
    uint32_t offset;
    uint8_t marker[BLK_MARKER_SIZE];
    size_t blocksize = file_Docio->getBlockSize();
    size_t real_blocksize = blocksize;
    size_t remaining_space;
    bool non_consecutive = ver_non_consecutive_doc(file_Docio->getVersion());
    struct docblk_meta blk_meta;

    memset(&blk_meta, 0x0, sizeof(blk_meta));
    blk_meta.marker = BLK_MARKER_DOC;
    (void)blk_meta;

#ifdef __CRC32
    if (non_consecutive) {
        // new version: support non-consecutive document block
        blocksize -= DOCBLK_META_SIZE;
    } else {
        // old version: block marker only
        blocksize -= BLK_MARKER_SIZE;
    }
    memset(marker, BLK_MARKER_DOC, BLK_MARKER_SIZE);
#endif

    if (curblock == BLK_NOT_FOUND) {
        // allocate new block
        cur_bmp_revnum_hash = file_Docio->getSbBmpRevnum() & BMP_REVNUM_MASK;
        curblock = file_Docio->alloc_FileMgr(log_callback);
        curpos = 0;
    }
    if (!file_Docio->isWritable(curblock)) {
        // mark remaining space in old block as stale
        if (curpos < real_blocksize) {
            // this function will calculate block marker size automatically.
            file_Docio->markDocStale(real_blocksize * curblock + curpos,
                                  blocksize - curpos);
        }
        // allocate new block
        cur_bmp_revnum_hash =file_Docio->getSbBmpRevnum() & BMP_REVNUM_MASK;
        curblock = file_Docio->alloc_FileMgr(log_callback);
        curpos = 0;
    }
    blk_meta.sb_bmp_revnum_hash = _endian_encode(cur_bmp_revnum_hash);

    remaining_space = blocksize - curpos;
    if (size <= remaining_space) {
        fdb_status fs = FDB_RESULT_SUCCESS;
        // simply append to current block
        offset = curpos;

        if (non_consecutive) {
            // set next BID
            blk_meta.next_bid = BLK_NOT_FOUND;
            // write meta
            fs = file_Docio->writeOffset(curblock,
                                      blocksize, sizeof(blk_meta), &blk_meta,
                                      false, log_callback);
        } else {
            fs = _add_blk_marker(file_Docio, curblock, blocksize, marker,
                                 log_callback);
        }


        if (fs != FDB_RESULT_SUCCESS) {
            fdb_log(log_callback, fs,
                    "Error in appending a doc block marker for a block id %" _F64
                    " into a database file '%s'", curblock,
                    file_Docio->getFileName());
            return BLK_NOT_FOUND;
        }
        fs = file_Docio->writeOffset(curblock, offset, size,
                                  buf, (size == remaining_space), log_callback);
        if (fs != FDB_RESULT_SUCCESS) {
            fdb_log(log_callback, fs,
                    "Error in writing a doc block with id %" _F64 ", offset %d, size %"
                    _F64 " to a database file '%s'", curblock, offset, size,
                    file_Docio->getFileName());
            return BLK_NOT_FOUND;
        }
        curpos += size;

        if (_fillZero_Docio(curblock, curpos) !=
            FDB_RESULT_SUCCESS) {
            return BLK_NOT_FOUND;
        }

        return curblock * real_blocksize + offset;

    } else { // insufficient space to fit entire document into current block
        bid_t begin, end, i, startpos;
        bid_t *block_list, block_list_size = 0;
        uint16_t *bmp_revnum_list;
        uint32_t nblock = size / blocksize;
        uint32_t remain = size % blocksize;
        uint64_t remainsize = size;
        fdb_status fs = FDB_RESULT_SUCCESS;

        // as blocks may not be consecutive, we need to maintain
        // the list of BIDs.
        block_list = (bid_t *)alca(bid_t, nblock+1);
        bmp_revnum_list = (uint16_t *)alca(uint16_t, nblock+1);

#ifdef DOCIO_BLOCK_ALIGN
        offset = blocksize - curpos;
        if (remain <= blocksize - curpos &&
            file_Docio->allocMultipleCond(curblock+1,
                                          nblock + ((remain>offset)?1:0),
                                          &begin, &end,
                                          log_callback) == curblock+1) {

            // start from current block
            if (begin != (curblock + 1)) {
                fdb_log(log_callback, fs,
                        "Error in allocating blocks starting from block id %" _F64
                        " in a database file '%s'", curblock + 1,
                        file_Docio->getFileName());
                return BLK_NOT_FOUND;
            }

            fs = _add_blk_marker(file_Docio, curblock, blocksize,
                                 marker, log_callback);
            if (fs != FDB_RESULT_SUCCESS) {
                fdb_log(log_callback, fs,
                        "Error in appending a doc block marker for a block id %" _F64
                        " into a database file '%s'", curblock,
                        file_Docio->getFileName());
                return BLK_NOT_FOUND;
            }
            if (offset > 0) {
                fs = file_Docio->writeOffset(curblock,
                                          curpos, offset, buf,
                                          true, // mark block as immutable
                                          log_callback);
                if (fs != FDB_RESULT_SUCCESS) {
                    fdb_log(log_callback, fs,
                            "Error in writing a doc block with id %" _F64 ", offset %d, "
                            "size %" _F64 " to a database file '%s'", curblock,
                            offset, size, file_Docio->getFileName());
                    return BLK_NOT_FOUND;
                }
            }
            remainsize -= offset;

            startpos = curblock * real_blocksize + curpos;
        } else {
            // next block to be allocated is not continuous .. allocate new multiple blocks
            file_Docio->allocMultiple(nblock+((remain>0)?1:0),
                                      &begin, &end, log_callback);
            offset = 0;

            startpos = begin * real_blocksize;
        }

#else
        // Simple append mode
        // The given doc is appended at the byte offset right next the last doc.
        // Note that block allocation can be non-consecutive.
        offset = blocksize - curpos;

        if (non_consecutive) {
            // new version: support non-consecutive allocation

            bool new_block = false;
            bool start_from_new_block = false;

            if (remain > offset) {
                // if the current block cannot accommodate the remaining length
                // of the document, allocate an additional block.
                new_block = true;
            }

            block_list_size = nblock + ((new_block)?1:0);
            for (i=0; i<block_list_size; ++i) {
                bmp_revnum_list[i] = file_Docio->getSbBmpRevnum() &
                                     BMP_REVNUM_MASK;
                block_list[i] = file_Docio->alloc_FileMgr(log_callback);

                if (i == 0 && curblock != BLK_NOT_FOUND &&
                    block_list[i] > curblock+1) {
                    // if the first new allocated block is not consecutive
                    // from the current block, start writing document from
                    // the new block.
                    start_from_new_block = true;
                    // since we won't write into the current block,
                    // allocate one more block if necessary.
                    if (remain && !new_block) {
                        new_block = true;
                        block_list_size++;
                    }
                }
            }

            if (offset > 0 && !start_from_new_block) {
                // start from the current block

                // set next BID
                blk_meta.next_bid = _endian_encode(block_list[0]);
                // write meta
                fs = file_Docio->writeOffset(curblock,
                                          blocksize, sizeof(blk_meta), &blk_meta,
                                          false, log_callback);
                if (fs != FDB_RESULT_SUCCESS) {
                    fdb_log(log_callback, fs,
                            "Error in appending a doc block metadata for a block id %" _F64
                            " into a database file '%s'", curblock,
                            file_Docio->getFileName());
                    return BLK_NOT_FOUND;
                }

                // write the front part of the doc
                if (offset > 0) {
                    fs = file_Docio->writeOffset(curblock,
                                              curpos, offset, buf,
                                              true, // mark block as immutable
                                              log_callback);
                    if (fs != FDB_RESULT_SUCCESS) {
                        fdb_log(log_callback, fs,
                                "Error in writing a doc block with id %" _F64 ", offset %d, "
                                "size %" _F64 " to a database file '%s'", curblock,
                                offset, size, file_Docio->getFileName());
                        return BLK_NOT_FOUND;
                    }
                }
                remainsize -= offset;

                startpos = curblock * real_blocksize + curpos;
            } else {
                // mark remaining space in the current block as stale
                if (curblock != BLK_NOT_FOUND &&
                    curpos < real_blocksize) {
                    file_Docio->markDocStale(real_blocksize * curblock + curpos,
                                          blocksize - curpos);
                }
                offset = 0;
                startpos = block_list[0] * real_blocksize;
            }

        } else {
            // old version: consecutive allocation only

            if (file_Docio->allocMultipleCond(curblock+1,
                                              nblock + ((remain>offset)?1:0),
                                              &begin, &end,
                                              log_callback) == curblock+1) {
                // start from current block
                if (begin != (curblock + 1)) {
                    fdb_log(log_callback, fs,
                            "Error in allocating blocks starting from block id %" _F64
                            " in a database file '%s'", curblock + 1,
                            file_Docio->getFileName());
                    return BLK_NOT_FOUND;
                }

                fs = _add_blk_marker(file_Docio, curblock, blocksize,
                                     marker, log_callback);
                if (fs != FDB_RESULT_SUCCESS) {
                    fdb_log(log_callback, fs,
                            "Error in appending a doc block marker for a block id %" _F64
                            " into a database file '%s'", curblock,
                            file_Docio->getFileName());
                    return BLK_NOT_FOUND;
                }
                if (offset > 0) {
                    fs = file_Docio->writeOffset(curblock,
                                              curpos, offset, buf,
                                              true, // mark block as immutable
                                              log_callback);
                    if (fs != FDB_RESULT_SUCCESS) {
                        fdb_log(log_callback, fs,
                                "Error in writing a doc block with id %" _F64 ", offset %d, "
                                "size %" _F64 " to a database file '%s'", curblock,
                                offset, size, file_Docio->getFileName());
                        return BLK_NOT_FOUND;
                    }
                }
                remainsize -= offset;

                startpos = curblock * real_blocksize + curpos;
            } else {
                // next block to be allocated is not continuous
                // mark remaining space in the old block as stale
                if (curblock != BLK_NOT_FOUND &&
                    curpos < real_blocksize) {
                    file_Docio->markDocStale(real_blocksize * curblock + curpos,
                                          blocksize - curpos);
                }
                // allocate new multiple blocks
                file_Docio->allocMultiple(nblock+((remain>0)?1:0),
                                          &begin, &end, log_callback);
                offset = 0;

                startpos = begin * real_blocksize;
            }

            block_list_size = end - begin + 1;
            for (i=0; i<block_list_size; ++i) {
                block_list[i] = begin+i;
            }

        } // if (non_consecutive)

#endif

        for (i=0; i<block_list_size; ++i) {
            curblock = block_list[i];
            cur_bmp_revnum_hash = bmp_revnum_list[i];
            blk_meta.sb_bmp_revnum_hash = _endian_encode(cur_bmp_revnum_hash);

            if (non_consecutive) {
                if (i < block_list_size - 1) {
                    blk_meta.next_bid = _endian_encode(block_list[i+1]);
                } else {
                    // the last block .. set next BID '0xffff...'
                    memset(&blk_meta.next_bid, 0xff, sizeof(blk_meta.next_bid));
                }
            }

            // write meta (new) or block marker (old)
            if (non_consecutive) {
                fs = file_Docio->writeOffset(curblock,
                                          blocksize, sizeof(blk_meta), &blk_meta,
                                          false, log_callback);
            } else {
                fs = _add_blk_marker(file_Docio, block_list[i], blocksize, marker,
                                     log_callback);
            }
            if (fs != FDB_RESULT_SUCCESS) {
                fdb_log(log_callback, fs,
                        "Error in appending a doc block marker for a block "
                        "id %" _F64 " into a database file '%s'", block_list[i],
                        file_Docio->getFileName());
                return BLK_NOT_FOUND;
            }

            if (remainsize >= blocksize) {
                // write entire block

                fs = file_Docio->writeOffset(block_list[i], 0, blocksize,
                                          (uint8_t *)buf + offset,
                                          true, // mark block as immutable
                                          log_callback);
                if (fs != FDB_RESULT_SUCCESS) {
                    fdb_log(log_callback, fs,
                            "Error in writing an entire doc block with id %"
                            _F64 ", size %" _F64 " to a database file '%s'",
                            block_list[i],
                            static_cast<uint64_t>(blocksize),
                            file_Docio->getFileName());
                    return BLK_NOT_FOUND;
                }
                offset += blocksize;
                remainsize -= blocksize;
                curpos = blocksize;

            } else {
                // write rest of document
                fdb_assert(i==block_list_size-1, i, block_list_size-1);

                fs = file_Docio->writeOffset(block_list[i], 0, remainsize,
                                          (uint8_t *)buf + offset,
                                          (remainsize == blocksize),
                                          log_callback);
                if (fs != FDB_RESULT_SUCCESS) {
                    fdb_log(log_callback, fs,
                            "Error in writing a doc block with id %" _F64 ", "
                            "size %" _F64 " to a database file '%s'",
                            block_list[i], remainsize,
                            file_Docio->getFileName());
                    return BLK_NOT_FOUND;
                }
                offset += remainsize;
                curpos = remainsize;

                if (_fillZero_Docio(block_list[i], curpos) !=
                    FDB_RESULT_SUCCESS) {
                    return BLK_NOT_FOUND;
                }
            }
        }

        return startpos;
    }

    return 0;
}

static struct docio_length _encode_length(struct docio_length length) {
    struct docio_length ret;
    ret = length;
    ret.keylen = _endian_encode(length.keylen);
    ret.metalen = _endian_encode(length.metalen);
    ret.bodylen = _endian_encode(length.bodylen);
    ret.bodylen_ondisk = _endian_encode(length.bodylen_ondisk);
    return ret;
}

static struct docio_length _decode_length(struct docio_length length) {
    struct docio_length ret;
    ret = length;
    ret.keylen = _endian_decode(length.keylen);
    ret.metalen = _endian_decode(length.metalen);
    ret.bodylen = _endian_decode(length.bodylen);
    ret.bodylen_ondisk = _endian_decode(length.bodylen_ondisk);
    return ret;
}

struct docio_length DocioHandle::encodeLength_Docio(struct docio_length length) {
    return _encode_length(length);
}

struct docio_length DocioHandle::decodeLength_Docio(struct docio_length length) {
    return _decode_length(length);
}

#ifdef __ENDIAN_SAFE
inline struct docio_length
DocioHandle::_encodeLength_Docio(struct docio_length length)
{
    return _encode_length(length);
}

inline struct docio_length
DocioHandle::_decodeLength_Docio(struct docio_length length)
{
    return _decode_length(length);
}
#else
#define _encodeLength_Docio(a)
#define _decodeLength_Docio(a)
#endif

inline uint8_t
DocioHandle::_docio_length_checksum(struct docio_length length)
{
    return uint8_t(get_checksum(reinterpret_cast<const uint8_t*>(&length),
                                sizeof(keylen_t) + sizeof(uint16_t)
                                + sizeof(uint32_t)*2,
                                file_Docio->getCrcMode()) & 0xff);
}

inline bid_t DocioHandle::_appendDoc_Docio(struct docio_object *doc)
{
    size_t _len;
    uint32_t offset = 0;
    uint32_t crc;
    uint64_t docsize;
    void *buf = NULL;
    bid_t ret_offset;
    fdb_seqnum_t _seqnum;
    timestamp_t _timestamp;
    struct docio_length length, _length;

    length = doc->length;
    length.bodylen_ondisk = length.bodylen;

#ifdef _DOC_COMP
    int ret;
    void *compbuf = NULL;
    uint32_t compbuf_len = 0;
    if (doc->length.bodylen > 0 && compress_document_body) {
        compbuf_len = snappy_max_compressed_length(length.bodylen);
        compbuf = (void *)malloc(compbuf_len);

        _len = compbuf_len;
        ret = snappy_compress((char*)doc->body, length.bodylen, (char*)compbuf, &_len);
        if (ret < 0) { // LCOV_EXCL_START
            fdb_log(log_callback, FDB_RESULT_COMPRESSION_FAIL,
                    "Error in compressing the doc body of key '%s' from "
                    "a database file '%s'",
                    (char *) doc->key, file_Docio->getFileName());
            free(compbuf);
            // we use BLK_NOT_FOUND for error code of appending instead of 0
            // because document can be written at the byte offset 0
            return BLK_NOT_FOUND;
        } // LCOV_EXCL_STOP

        length.bodylen_ondisk = compbuf_len = _len;
        length.flag |= DOCIO_COMPRESSED;

        docsize = sizeof(struct docio_length) + length.keylen + length.metalen;
        docsize += compbuf_len;
    } else {
        docsize = sizeof(struct docio_length) + length.keylen + length.metalen + length.bodylen;
        compbuf_len = length.bodylen;
    }
#else
    docsize = sizeof(struct docio_length) + length.keylen + length.metalen + length.bodylen;
#endif
    docsize += sizeof(timestamp_t);

    docsize += sizeof(fdb_seqnum_t);

#ifdef __CRC32
    docsize += sizeof(crc);
#endif

    doc->length = length;
    buf = (void *)malloc(docsize);

    _length = _encodeLength_Docio(length);

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

    // copy seqeunce number (optional)
    _seqnum = _endian_encode(doc->seqnum);
    memcpy((uint8_t *)buf + offset, &_seqnum, sizeof(fdb_seqnum_t));
    offset += sizeof(fdb_seqnum_t);

    // copy metadata (optional)
    if (length.metalen > 0) {
        memcpy((uint8_t *)buf + offset, doc->meta, length.metalen);
        offset += length.metalen;
    }

    // copy body (optional)
    if (length.bodylen > 0) {
#ifdef _DOC_COMP
        if (length.flag & DOCIO_COMPRESSED) {
            // compressed body
            if (compbuf) {
                memcpy((uint8_t*)buf + offset, compbuf, compbuf_len);
                offset += compbuf_len;
                free(compbuf);
            }
        } else {
            memcpy((uint8_t *)buf + offset, doc->body, length.bodylen);
            offset += length.bodylen;
        }
#else
        memcpy((uint8_t *)buf + offset, doc->body, length.bodylen);
        offset += length.bodylen;
#endif
    }

#ifdef __CRC32
    crc = get_checksum(reinterpret_cast<const uint8_t*>(buf),
                       docsize - sizeof(crc),
                       file_Docio->getCrcMode());
    memcpy((uint8_t *)buf + offset, &crc, sizeof(crc));
#endif

    ret_offset = appendDocRaw_Docio(docsize, buf);
    free(buf);

    return ret_offset;
}

bid_t DocioHandle::appendCommitMark_Docio(uint64_t doc_offset)
{
    // Note: should adapt DOCIO_COMMIT_MARK_SIZE if this function is modified.
    uint32_t offset = 0;
    uint64_t docsize;
    uint64_t _doc_offset;
    void *buf;
    bid_t ret_offset;
    struct docio_length length, _length;

    memset(&length, 0, sizeof(struct docio_length));
    length.flag = DOCIO_TXN_COMMITTED;

    docsize = sizeof(struct docio_length) + sizeof(doc_offset);
    buf = (void *)malloc(docsize);

    _length = _encodeLength_Docio(length);

    // calculate checksum of LENGTH using crc
    _length.checksum = _docio_length_checksum(_length);

    memcpy((uint8_t *)buf + offset, &_length, sizeof(struct docio_length));
    offset += sizeof(struct docio_length);

    // copy doc_offset
    _doc_offset = _endian_encode(doc_offset);
    memcpy((uint8_t *)buf + offset, &_doc_offset, sizeof(_doc_offset));

    ret_offset = appendDocRaw_Docio(docsize, buf);
    free(buf);

    return ret_offset;
}

bid_t DocioHandle::appendDoc_Docio(struct docio_object *doc,
                       uint8_t deleted, uint8_t txn_enabled)
{
    doc->length.flag = DOCIO_NORMAL;
    if (deleted) {
        doc->length.flag |= DOCIO_DELETED;
    }
    if (txn_enabled) {
        doc->length.flag |= DOCIO_TXN_DIRTY;
    }
    return _appendDoc_Docio(doc);
}

bid_t DocioHandle::appendSystemDoc_Docio(struct docio_object *doc)
{
    doc->length.flag = DOCIO_NORMAL | DOCIO_SYSTEM;
    return _appendDoc_Docio(doc);
}

inline
fdb_status DocioHandle::_readThroughBuffer_Docio(bid_t bid,
                                                   bool read_on_cache_miss)
{
    fdb_status status = FDB_RESULT_SUCCESS;

    // if superblock's BMP revnum has been changed,
    // then 'lastbid' should be reset as it might be reused.
    if (lastbid != BLK_NOT_FOUND &&
        file_Docio->getSbBmpRevnum() != lastBmpRevnum) {
        lastbid = BLK_NOT_FOUND;
    }

    // to reduce the overhead from memcpy the same block
    if (lastbid != bid) {
        status = file_Docio->read_FileMgr(bid, readbuffer,
                                          log_callback, read_on_cache_miss);
        if (status != FDB_RESULT_SUCCESS) {
            if (read_on_cache_miss) {
                fdb_log(log_callback, status,
                        "Error in reading a doc block with id %" _F64 " from "
                        "a database file '%s'", bid, file_Docio->getFileName());
            }
            // we must reset 'lastbid' here because now 'readbuffer'
            // may contain other data unrelated to 'lastbid'.
            lastbid = BLK_NOT_FOUND;
            return status;
        }

        if (file_Docio->isWritable(bid)) {
            // this block can be modified later .. must be re-read
            lastbid = BLK_NOT_FOUND;
        } else {
            lastbid = bid;
            lastBmpRevnum = file_Docio->getSbBmpRevnum();
        }
    }

    return status;
}

inline
bool DocioHandle::_checkBuffer_Docio(uint64_t bmp_revnum)
{
    size_t blocksize = file_Docio->getBlockSize();
    bool non_consecutive = ver_non_consecutive_doc(file_Docio->getVersion());
    struct docblk_meta blk_meta;

    if (non_consecutive) {
        // new version: support non-consecutive document block
        blocksize -= DOCBLK_META_SIZE;
        memcpy(&blk_meta, (uint8_t*)readbuffer + blocksize, sizeof(blk_meta));
    } else {
        // old version: block marker only
        blocksize -= BLK_MARKER_SIZE;
        memcpy(&blk_meta.marker, (uint8_t*)readbuffer + blocksize,
               sizeof(blk_meta.marker));
    }

    if (blk_meta.marker != BLK_MARKER_DOC) {
        return false;
    }

    if (non_consecutive && bmp_revnum != (uint64_t)-1) {
        uint16_t revnum_hash = _endian_decode(blk_meta.sb_bmp_revnum_hash);
        if (revnum_hash == (bmp_revnum & BMP_REVNUM_MASK)) {
            return true;
        } else {
            return false;
        }
    }
    return true;
}

int64_t DocioHandle::_readLength_Docio(uint64_t offset,
                                  struct docio_length *length,
                                  bool read_on_cache_miss)
{
    size_t blocksize = file_Docio->getBlockSize();
    size_t real_blocksize = blocksize;
    bool non_consecutive = ver_non_consecutive_doc(file_Docio->getVersion());
    struct docblk_meta blk_meta;
#ifdef __CRC32
    if (non_consecutive) {
        // new version: support non-consecutive document block
        blocksize -= DOCBLK_META_SIZE;
    } else {
        // old version: block marker only
        blocksize -= BLK_MARKER_SIZE;
    }
#endif

    bid_t bid = offset / real_blocksize;
    uint32_t pos = offset % real_blocksize;
    void *buf = readbuffer;
    uint32_t restsize = 0;

    if (blocksize > pos) {
        restsize = blocksize - pos;
    }

    // read length structure
    fdb_status fs = _readThroughBuffer_Docio(bid, read_on_cache_miss);
    if (fs != FDB_RESULT_SUCCESS) {
        if (read_on_cache_miss) {
            fdb_log(log_callback, fs,
                    "Error in reading a doc length from offset %" _F64
                    " in block id %" _F64
                    " from a database file '%s'", offset, bid,
                    file_Docio->getFileName());
        }
        return (int64_t) fs;
    }
    if (!_checkBuffer_Docio((uint64_t)-1)) {
        return (int64_t) FDB_RESULT_READ_FAIL; // Need to define a better error code
    }

    if (restsize >= sizeof(struct docio_length)) {
        memcpy(length, (uint8_t *)buf + pos, sizeof(struct docio_length));
        pos += sizeof(struct docio_length);

    } else {
        if (restsize > 0) {
            memcpy(length, (uint8_t *)buf + pos, restsize);
        }
        // read additional block
        if (non_consecutive) {
            memcpy(&blk_meta, (uint8_t*)buf + blocksize, sizeof(blk_meta));
            bid = _endian_decode(blk_meta.next_bid);
            if (bid == BLK_NOT_FOUND) {
                // Reached the last block. Simply return the offset that is passed to
                // this function.
                memset(length, 0x0, sizeof(struct docio_length));
                return offset;
            }
        } else {
            bid++;
        }

        fs = _readThroughBuffer_Docio(bid, true);
        if (fs != FDB_RESULT_SUCCESS) {
            fdb_log(log_callback, fs,
                    "Error in reading a doc length from an additional block "
                    "offset %" _F64 " in block id %" _F64
                    " from a database file '%s'", offset,
                    bid, file_Docio->getFileName());
            return (int64_t) fs;
        }
        if (!_checkBuffer_Docio((uint64_t)-1)) {
            return (int64_t) FDB_RESULT_READ_FAIL; // Need to define a better error code
        }
        // memcpy rest of data
        memcpy((uint8_t *)length + restsize, buf,
               sizeof(struct docio_length) - restsize);
        pos = sizeof(struct docio_length) - restsize;
    }

    return bid * real_blocksize + pos;
}

int64_t DocioHandle::_readDocComponent_Docio(uint64_t offset,
                                               uint32_t len,
                                               void *buf_out)
{
    uint32_t rest_len;
    size_t blocksize = file_Docio->getBlockSize();
    size_t real_blocksize = blocksize;
    bool non_consecutive = ver_non_consecutive_doc(file_Docio->getVersion());
    struct docblk_meta blk_meta;
#ifdef __CRC32
    if (non_consecutive) {
        // new version: support non-consecutive document block
        blocksize -= DOCBLK_META_SIZE;
    } else {
        // old version: block marker only
        blocksize -= BLK_MARKER_SIZE;
    }
#endif

    bid_t bid = offset / real_blocksize;
    uint32_t pos = offset % real_blocksize;
    void *buf = readbuffer;
    uint32_t restsize;
    fdb_status fs = FDB_RESULT_SUCCESS;

    rest_len = len;

    while(rest_len > 0) {
        fs = _readThroughBuffer_Docio(bid, true);
        if (fs != FDB_RESULT_SUCCESS) {
            fdb_log(log_callback, fs,
                    "Error in reading a doc block with block id %" _F64 " from "
                    "a database file '%s'", bid, file_Docio->getFileName());
            return (int64_t)fs;
        }
        restsize = blocksize - pos;

        if (restsize >= rest_len) {
            memcpy((uint8_t *)buf_out + (len - rest_len), (uint8_t *)buf + pos, rest_len);
            pos += rest_len;
            rest_len = 0;
        }else{
            memcpy((uint8_t *)buf_out + (len - rest_len), (uint8_t *)buf + pos, restsize);

            if (non_consecutive) {
                memcpy(&blk_meta, (uint8_t*)buf + blocksize, sizeof(blk_meta));
                bid = _endian_decode(blk_meta.next_bid);
            } else {
                bid++;
            }

            pos = 0;
            rest_len -= restsize;

            if (rest_len > 0 &&
                bid >= file_Docio->getPos() / file_Docio->getBlockSize()) {
                // no more data in the file .. the file is corrupted
                fdb_log(log_callback, FDB_RESULT_FILE_CORRUPTION,
                        "Fatal error!!! Database file '%s' is corrupted.",
                        file_Docio->getFileName());
                return (int64_t)FDB_RESULT_FILE_CORRUPTION;
            }
        }
    }

    return bid * real_blocksize + pos;
}

#ifdef _DOC_COMP

int64_t DocioHandle::_readCompressedDocComponent_Docio(uint64_t offset,
                                                    uint32_t len,
                                                    uint32_t comp_len,
                                                    void *buf_out,
                                                    void *comp_data_out)
{
    int ret;
    size_t uncomp_size;
    int64_t _offset;

    _offset = _readDocComponent_Docio(offset, comp_len, comp_data_out);
    if (_offset < 0) {
        fdb_log(log_callback, (fdb_status) _offset,
                "Error in reading the file with offset %" _F64 ", length %d "
                "from a database file '%s'", offset, len,
                file_Docio->getFileName());
        return _offset;
    }

    uncomp_size = len;
    ret = snappy_uncompress((char*)comp_data_out, comp_len,
                            (char*)buf_out, &uncomp_size);
    if (ret < 0) {
        fdb_log(log_callback, FDB_RESULT_COMPRESSION_FAIL,
                "Error in decompressing the data that was read with the file "
                "offset %" _F64 ", length %d from a database file '%s'",
                offset, len, file_Docio->getFileName());
        return (int64_t) FDB_RESULT_COMPRESSION_FAIL;
    }
    if (uncomp_size != len) {
        fdb_log(log_callback, FDB_RESULT_COMPRESSION_FAIL,
                "Error in decompressing the data with the file offset "
                "%" _F64 " in a database file '%s', because the uncompressed length %" _F64
                " is not same as the expected length %d",
                offset, file_Docio->getFileName(),
                static_cast<uint64_t>(uncomp_size), len);
        return (int64_t) FDB_RESULT_COMPRESSION_FAIL;
    }
    return _offset;
}

#endif

/**
 * Helper function that validates offset and checksum
 */
bool DocioHandle::validateChecksum_Docio(bool read_on_cache_miss,
                                    int64_t *offset,
                                    struct docio_length *length,
                                    fdb_status *status)
{
    uint8_t checksum;
    int64_t _offset;
    struct docio_length zero_length;

    _offset = _readLength_Docio(*offset, length, true);
    if (_offset < 0) {
        if (read_on_cache_miss) {
            fdb_log(log_callback, (fdb_status) _offset,
                    "Error in reading the doc length metadata with "
                    "offset %" _F64 " from a database file '%s'",
                    *offset, file_Docio->getFileName());
        }
        *status = (fdb_status) _offset;
        return false;;
    }
    *offset = _offset;

    memset(&zero_length, 0x0, sizeof(struct docio_length));
    if (memcmp(length, &zero_length, sizeof(struct docio_length)) == 0) {
        // If all the fields in docio_length are zero, then it means that the rest of
        // the current block, which starts at offset, is zero-filled and can be skipped.
        *status = FDB_RESULT_SUCCESS;
        return false;
    }

    // checksum check
    checksum = _docio_length_checksum(*length);
    if (checksum != length->checksum) {
        fdb_log(log_callback, FDB_RESULT_CHECKSUM_ERROR,
                "doc_length checksum mismatch error in a database file '%s'"
                " crc %x != %x (crc in doc) keylen %d metalen %d bodylen %d "
                "bodylen_ondisk %d offset %" _F64, file_Docio->getFileName(),
                checksum, length->checksum, length->keylen, length->metalen,
                length->bodylen, length->bodylen_ondisk,
                static_cast<uint64_t>(_offset));
        *status = FDB_RESULT_CHECKSUM_ERROR;
        return false;
    }

    return true;
}

fdb_status DocioHandle::readDocLength_Docio(struct docio_length *length,
                                              uint64_t offset)
{
    fdb_status status = FDB_RESULT_SUCCESS;
    struct docio_length _length;
    int64_t _offset = offset;

    if (!validateChecksum_Docio(true, &_offset, &_length, &status)) {
        if (status == FDB_RESULT_SUCCESS) {
            *length = _length;
        }
        return status;
    }

    *length = _decodeLength_Docio(_length);
    if (length->keylen == 0 || length->keylen > FDB_MAX_KEYLEN_INTERNAL) {
        fdb_log(log_callback, FDB_RESULT_FILE_CORRUPTION,
                "Error in decoding the doc length metadata in file %s"
                " crc %x keylen %d metalen %d bodylen %d "
                "bodylen_ondisk %d offset %" _F64, file_Docio->getFileName(),
                _length.checksum, _length.keylen, _length.metalen,
                _length.bodylen, _length.bodylen_ondisk, offset);
        return FDB_RESULT_FILE_CORRUPTION;
    }

    return FDB_RESULT_SUCCESS;
}

fdb_status DocioHandle::readDocKey_Docio(uint64_t offset,
                              keylen_t *keylen, void *keybuf)
{
    fdb_status status = FDB_RESULT_SUCCESS;
    struct docio_length length, _length;
    int64_t _offset = offset;

    if (!validateChecksum_Docio(true, &_offset, &_length, &status)) {
        if (status == FDB_RESULT_SUCCESS) {
            *keylen = 0;
        }
        return status;
    }

    length = _decodeLength_Docio(_length);
    if (length.keylen == 0 || length.keylen > FDB_MAX_KEYLEN_INTERNAL) {
        fdb_log(log_callback, FDB_RESULT_FILE_CORRUPTION,
                "Error in decoding the doc key length metadata in file %s"
                " crc %x keylen %d metalen %d bodylen %d "
                "bodylen_ondisk %d offset %" _F64, file_Docio->getFileName(),
                _length.checksum, _length.keylen, _length.metalen,
                _length.bodylen, _length.bodylen_ondisk, offset);
        return FDB_RESULT_FILE_CORRUPTION;
    }

    _offset = _readDocComponent_Docio(_offset, length.keylen,
                                        keybuf);
    if (_offset < 0) {
        fdb_log(log_callback, (fdb_status) _offset,
                "Error in reading a key with offset %" _F64 ", length %d "
                "from a database file '%s'", _offset, length.keylen,
                file_Docio->getFileName());
        return (fdb_status) _offset;
    }

    *keylen = length.keylen;
    return FDB_RESULT_SUCCESS;
}

void free_docio_object(struct docio_object *doc, bool key_alloc,
                       bool meta_alloc, bool body_alloc) {
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

int64_t DocioHandle::readDocKeyMeta_Docio(uint64_t offset,
                                struct docio_object *doc,
                                bool read_on_cache_miss)
{
    bool key_alloc = false, meta_alloc = false;
    fdb_seqnum_t _seqnum;
    timestamp_t _timestamp;

    fdb_status status = FDB_RESULT_SUCCESS;
    struct docio_length _length;
    int64_t _offset = offset;

    if (!validateChecksum_Docio(read_on_cache_miss,
                                 &_offset, &_length, &status)) {
        if (status == FDB_RESULT_SUCCESS) {
            doc->length = _length;
        }
        return (int64_t) status;
    }

    doc->length = _decodeLength_Docio(_length);
    if (doc->length.keylen == 0 || doc->length.keylen > FDB_MAX_KEYLEN_INTERNAL) {
        fdb_log(log_callback, FDB_RESULT_FILE_CORRUPTION,
                "Error in decoding the doc length metadata (key length: %d) from "
                "a database file '%s'", doc->length.keylen, file_Docio->getFileName());
        return (int64_t) FDB_RESULT_FILE_CORRUPTION;
    }

    if (doc->key == NULL) {
        doc->key = (void *)malloc(doc->length.keylen);
        key_alloc = true;
    }
    if (doc->meta == NULL && doc->length.metalen) {
        doc->meta = (void *)malloc(doc->length.metalen);
        meta_alloc = true;
    }

    _offset = _readDocComponent_Docio(_offset, doc->length.keylen,
                                        doc->key);
    if (_offset < 0) {
        fdb_log(log_callback, (fdb_status) _offset,
                "Error in reading a key with offset %" _F64 ", length %d "
                "from a database file '%s'", offset, doc->length.keylen,
                file_Docio->getFileName());
        free_docio_object(doc, key_alloc, meta_alloc, false);
        return _offset;
    }

    // read timestamp
    _offset = _readDocComponent_Docio(_offset,
                                        sizeof(timestamp_t),
                                        &_timestamp);
    if (_offset < 0) {
        fdb_log(log_callback, (fdb_status) _offset,
                "Error in reading a timestamp with offset %" _F64
                ", length %" _F64
                " from a database file '%s'", offset,
                static_cast<uint64_t>(sizeof(timestamp_t)),
                file_Docio->getFileName());
        free_docio_object(doc, key_alloc, meta_alloc, false);
        return _offset;
    }
    doc->timestamp = _endian_decode(_timestamp);

    // copy sequence number (optional)
    _offset = _readDocComponent_Docio(_offset, sizeof(fdb_seqnum_t),
                                        (void *)&_seqnum);
    if (_offset < 0) {
        fdb_log(log_callback, (fdb_status) _offset,
                "Error in reading a sequence number with offset %" _F64
                ", length %" _F64
                " from a database file '%s'", offset,
                static_cast<uint64_t>(sizeof(fdb_seqnum_t)),
                file_Docio->getFileName());
        free_docio_object(doc, key_alloc, meta_alloc, false);
        return _offset;
    }
    doc->seqnum = _endian_decode(_seqnum);

    _offset = _readDocComponent_Docio(_offset, doc->length.metalen,
                                        doc->meta);
    if (_offset < 0) {
        fdb_log(log_callback, (fdb_status) _offset,
                "Error in reading the doc metadata with offset %" _F64 ", length %d "
                "from a database file '%s'", offset, doc->length.metalen,
                file_Docio->getFileName());
        free_docio_object(doc, key_alloc, meta_alloc, false);
        return _offset;
    }

    bool free_meta = meta_alloc && !doc->length.metalen;
    free_docio_object(doc, false, free_meta, false);

    return _offset;
}

int64_t DocioHandle::readDoc_Docio(uint64_t offset,
                       struct docio_object *doc,
                       bool read_on_cache_miss)
{
    bool key_alloc = false, meta_alloc = false, body_alloc = false;
    fdb_seqnum_t _seqnum;
    timestamp_t _timestamp;
    void *comp_body = NULL;

    fdb_status status = FDB_RESULT_SUCCESS;
    struct docio_length _length;
    int64_t _offset = offset;

    if (!validateChecksum_Docio(read_on_cache_miss,
                                 &_offset, &_length, &status)) {
        if (status == FDB_RESULT_SUCCESS) {
            doc->length = _length;
        }
        return (int64_t) status;
    }

    doc->length = _decodeLength_Docio(_length);
    if (doc->length.flag & DOCIO_TXN_COMMITTED) {
        // transaction commit mark
        // read the corresponding doc offset

        // If TXN_COMMITTED flag is set, this doc is not an actual doc, but a
        // transaction commit marker. Thus, all lengths should be zero.
        if (doc->length.keylen || doc->length.metalen ||
            doc->length.bodylen || doc->length.bodylen_ondisk) {
            fdb_log(log_callback, FDB_RESULT_FILE_CORRUPTION,
                    "File corruption: Doc length fields in a transaction commit marker "
                    "was not zero in a database file '%s' offset %" _F64,
                    file_Docio->getFileName(), offset);
            free_docio_object(doc, key_alloc, meta_alloc, body_alloc);
            return (int64_t) FDB_RESULT_FILE_CORRUPTION;
        }

        uint64_t doc_offset;
        _offset = _readDocComponent_Docio(_offset,
                                            sizeof(doc_offset), &doc_offset);
        if (_offset < 0) {
            fdb_log(log_callback, (fdb_status) _offset,
                    "Error in reading an offset of a committed doc from an offset %" _F64
                    " in a database file '%s'", offset, file_Docio->getFileName());
            free_docio_object(doc, key_alloc, meta_alloc, body_alloc);
            return _offset;
        }
        doc->doc_offset = _endian_decode(doc_offset);
        // The offset of the actual document that pointed by this commit marker
        // should not be greater than the file size.
        if (doc->doc_offset > file_Docio->getPos()) {
            fdb_log(log_callback, FDB_RESULT_FILE_CORRUPTION,
                    "File corruption: Offset %" _F64 " of the actual doc pointed by the "
                    "commit marker is greater than the size %" _F64 " of a database file '%s'",
                    doc->doc_offset, file_Docio->getPos(),
                    file_Docio->getFileName());
            free_docio_object(doc, key_alloc, meta_alloc, body_alloc);
            return (int64_t) FDB_RESULT_FILE_CORRUPTION;
        }
        return _offset;
    }

    if (doc->length.keylen == 0 || doc->length.keylen > FDB_MAX_KEYLEN_INTERNAL) {
        fdb_log(log_callback, FDB_RESULT_FILE_CORRUPTION,
                "Error in decoding the doc length metadata (key length: %d) from "
                "a database file '%s' offset %" _F64, doc->length.keylen,
                file_Docio->getFileName(), offset);
        return (int64_t) FDB_RESULT_FILE_CORRUPTION;
    }

    if (doc->key == NULL) {
        doc->key = (void *)malloc(doc->length.keylen);
        key_alloc = true;
    }
    if (doc->meta == NULL && doc->length.metalen) {
        doc->meta = (void *)malloc(doc->length.metalen);
        meta_alloc = true;
    }
    if (doc->body == NULL && doc->length.bodylen) {
        doc->body = (void *)malloc(doc->length.bodylen);
        body_alloc = true;
    }

    _offset = _readDocComponent_Docio(_offset,
                                        doc->length.keylen,
                                        doc->key);
    if (_offset < 0) {
        fdb_log(log_callback, (fdb_status) _offset,
                "Error in reading a key with offset %" _F64 ", length %d "
                "from a database file '%s'", offset, doc->length.keylen,
                file_Docio->getFileName());
        free_docio_object(doc, key_alloc, meta_alloc, body_alloc);
        return _offset;
    }

    // read timestamp
    _offset = _readDocComponent_Docio(_offset,
                                        sizeof(timestamp_t),
                                        &_timestamp);
    if (_offset < 0) {
        fdb_log(log_callback, (fdb_status) _offset,
                "Error in reading a timestamp with offset %" _F64 ", length %"
                _F64 " from a database file '%s'", offset,
                static_cast<uint64_t>(sizeof(timestamp_t)),
                file_Docio->getFileName());
        free_docio_object(doc, key_alloc, meta_alloc, body_alloc);
        return _offset;
    }
    doc->timestamp = _endian_decode(_timestamp);

    // copy seqeunce number (optional)
    _offset = _readDocComponent_Docio(_offset,
                                        sizeof(fdb_seqnum_t),
                                        (void *)&_seqnum);
    if (_offset < 0) {
        fdb_log(log_callback, (fdb_status) _offset,
                "Error in reading a sequence number with offset %" _F64
                ", length %" _F64 " from a database file '%s'", offset,
                static_cast<uint64_t>(sizeof(fdb_seqnum_t)),
                file_Docio->getFileName());
        free_docio_object(doc, key_alloc, meta_alloc, body_alloc);
        return _offset;
    }
    doc->seqnum = _endian_decode(_seqnum);

    _offset = _readDocComponent_Docio(_offset, doc->length.metalen,
                                        doc->meta);
    if (_offset < 0) {
        fdb_log(log_callback, (fdb_status) _offset,
                "Error in reading the doc metadata with offset %" _F64 ", length %d "
                "from a database file '%s'", offset, doc->length.metalen,
                file_Docio->getFileName());
        free_docio_object(doc, key_alloc, meta_alloc, body_alloc);
        return _offset;
    }

#ifdef _DOC_COMP
    if (doc->length.flag & DOCIO_COMPRESSED) {
        comp_body = (void*)malloc(doc->length.bodylen_ondisk);
        _offset = _readCompressedDocComponent_Docio(_offset, doc->length.bodylen,
                                                 doc->length.bodylen_ondisk, doc->body,
                                                 comp_body);
        if (_offset < 0) {
            fdb_log(log_callback, (fdb_status) _offset,
                    "Error in reading a compressed doc with offset %" _F64 ", length %d "
                    "from a database file '%s'", offset, doc->length.bodylen,
                    file_Docio->getFileName());
            if (comp_body) {
                free(comp_body);
            }
            free_docio_object(doc, key_alloc, meta_alloc, body_alloc);
            return _offset;
        }
    } else {
        _offset = _readDocComponent_Docio(_offset, doc->length.bodylen,
                                            doc->body);
        if (_offset < 0) {
            fdb_log(log_callback, (fdb_status) _offset,
                    "Error in reading a doc with offset %" _F64 ", length %d "
                    "from a database file '%s'", offset, doc->length.bodylen,
                    file_Docio->getFileName());
            free_docio_object(doc, key_alloc, meta_alloc, body_alloc);
            return _offset;
        }
    }
#else
    _offset = _readDocComponent_Docio(_offset, doc->length.bodylen,
                                        doc->body);
    if (_offset < 0) {
        fdb_log(log_callback, (fdb_status) _offset,
                "Error in reading a doc with offset %" _F64 ", length %d "
                "from a database file '%s'", offset, doc->length.bodylen,
                file_Docio->getFileName());
        free_docio_object(doc, key_alloc, meta_alloc, body_alloc);
        return _offset;
    }
#endif

#ifdef __CRC32
    uint32_t crc_file, crc;
    _offset = _readDocComponent_Docio(_offset, sizeof(crc_file),
                                        (void *)&crc_file);
    if (_offset < 0) {
        fdb_log(log_callback, (fdb_status) _offset,
                "Error in reading a doc's CRC value with offset %" _F64
                ", length %" _F64
                " from a database file '%s'", offset,
                static_cast<uint64_t>(sizeof(crc_file)),
                file_Docio->getFileName());
        if (comp_body) {
            free(comp_body);
        }
        free_docio_object(doc, key_alloc, meta_alloc, body_alloc);
        return _offset;
    }

    crc = get_checksum(reinterpret_cast<const uint8_t*>(&_length),
                       sizeof(_length),
                       file_Docio->getCrcMode());
    crc = get_checksum(reinterpret_cast<const uint8_t*>(doc->key),
                       doc->length.keylen,
                       crc,
                       file_Docio->getCrcMode());
    crc = get_checksum(reinterpret_cast<const uint8_t*>(&_timestamp),
                       sizeof(timestamp_t),
                       crc,
                       file_Docio->getCrcMode());
    crc = get_checksum(reinterpret_cast<const uint8_t*>(&_seqnum),
                       sizeof(fdb_seqnum_t),
                       crc,
                       file_Docio->getCrcMode());
    crc = get_checksum(reinterpret_cast<const uint8_t*>(doc->meta),
                       doc->length.metalen,
                       crc,
                       file_Docio->getCrcMode());

    if (doc->length.flag & DOCIO_COMPRESSED) {
        crc = get_checksum(reinterpret_cast<const uint8_t*>(comp_body),
                           doc->length.bodylen_ondisk,
                           crc,
                           file_Docio->getCrcMode());
        if (comp_body) {
            free(comp_body);
        }
    } else {
        crc = get_checksum(reinterpret_cast<const uint8_t*>(doc->body),
                           doc->length.bodylen,
                           crc,
                           file_Docio->getCrcMode());
    }
    if (crc != crc_file) {
        fdb_log(log_callback, FDB_RESULT_CHECKSUM_ERROR,
                "doc_body checksum mismatch error in a database file '%s'"
                " crc %x != %x (crc in doc) keylen %d metalen %d bodylen %d "
                "bodylen_ondisk %d offset %" _F64, file_Docio->getFileName(),
                crc, crc_file, _length.keylen, _length.metalen,
                _length.bodylen, _length.bodylen_ondisk, offset);
        free_docio_object(doc, key_alloc, meta_alloc, body_alloc);
        return (int64_t) FDB_RESULT_CHECKSUM_ERROR;
    }
#endif

    uint8_t free_meta = meta_alloc && !doc->length.metalen;
    uint8_t free_body = body_alloc && !doc->length.bodylen;
    free_docio_object(doc, false, free_meta, free_body);

    return _offset;
}

int DocioHandle::_submitAsyncIORequests_Docio(struct docio_object *doc_array,
                                     size_t doc_idx,
                                     struct async_io_handle *aio_handle,
                                     int size,
                                     size_t *sum_doc_size,
                                     bool keymeta_only)
{
#ifdef _ASYNC_IO
#if !defined(WIN32) && !defined(_WIN32)
    struct io_event* io_evt = NULL;
    uint8_t *buf = NULL;
    uint64_t offset = 0, _offset = 0;
    int num_events = 0;

    int num_sub = file_Docio->getOps()->aio_submit(file_Docio->getFopsHandle(),
                                                   aio_handle, size);
    if (num_sub < 0) {
        // Error loggings
        char errno_msg[512];
        file_Docio->getOps()->get_errno_str(file_Docio->getFopsHandle(),
                                            errno_msg, 512);
        fdb_log(log_callback, (fdb_status) num_sub,
                "Error in submitting async I/O requests to a file '%s', errno msg: %s",
                file_Docio->getFileName(), errno_msg);
        return num_sub;
    } else if (num_sub != size) {
        // Error loggings
        char errno_msg[512];
        file_Docio->getOps()->get_errno_str(file_Docio->getFopsHandle(),
                                            errno_msg, 512);
        fdb_log(log_callback, (fdb_status) num_sub,
                "Error in submitting async I/O requests to a file '%s', errno msg: %s, "
                "%d requests were submitted, but only %d requests were processed",
                file_Docio->getFileName(), errno_msg, size, num_sub);
        return num_sub;
    }

    while (num_sub > 0) {
        num_events = file_Docio->getOps()->aio_getevents(file_Docio->getFopsHandle(),
                                                         aio_handle, 1,
                                                         num_sub, (unsigned int) -1);
        if (num_events < 0) {
            // Error loggings
            char errno_msg[512];
            file_Docio->getOps()->get_errno_str(file_Docio->getFopsHandle(),
                                                errno_msg, 512);
            fdb_log(log_callback, (fdb_status) num_events,
                    "Error in getting async I/O events from the completion queue "
                    "for a file '%s', errno msg: %s", file_Docio->getFileName(), errno_msg);
            return num_events;
        }
        num_sub -= num_events;
        for (io_evt = aio_handle->events; num_events > 0; --num_events, ++io_evt) {
            buf = (uint8_t *) io_evt->obj->u.c.buf;
            offset = *((uint64_t *) io_evt->data); // Original offset.

            // Set the docio handle's buffer to the AIO buffer to read
            // a doc from the AIO buffer. If adddtional blocks need to be
            // read, then they will be sequentially read through the synchronous
            // I/O path (i.e., buffer cache -> disk read if cache miss).
            // As these additional blocks are sequential reads, we don't expect
            // asynchronous I/O to give us performance boost.
            void *tmp_buffer = readbuffer;
            readbuffer = buf;
            lastbid = offset / aio_handle->block_size;
            memset(&doc_array[doc_idx], 0x0, sizeof(struct docio_object));
            if (keymeta_only) {
                _offset = readDocKeyMeta_Docio(offset,
                                                  &doc_array[doc_idx], true);
            } else {
                _offset = readDoc_Docio(offset, &doc_array[doc_idx],
                                         true);
            }
            if (_offset <= 0) {
                ++doc_idx;
                readbuffer = tmp_buffer;
                lastbid = BLK_NOT_FOUND;
                continue;
            }
            readbuffer = tmp_buffer;
            lastbid = BLK_NOT_FOUND;

            (*sum_doc_size) += _fdb_get_docsize(doc_array[doc_idx].length);
            if (keymeta_only) {
                (*sum_doc_size) -= doc_array[doc_idx].length.bodylen_ondisk;
            }
            ++doc_idx;
        }
    }
    return size;
#else // Plan to implement async I/O in other OSs (e.g., Windows, OSx)
    return 0;
#endif
#else // Async I/O is not supported in the current OS.
    return 0;
#endif
}

size_t DocioHandle::batchReadDocs_Docio(uint64_t *offset_array,
                             struct docio_object *doc_array,
                             size_t array_size,
                             size_t data_size_threshold,
                             size_t batch_size_threshold,
                             struct async_io_handle *aio_handle,
                             bool keymeta_only)
{
    size_t i = 0;
    size_t sum_doc_size = 0;
    size_t doc_idx = 0;
    size_t block_size = file_Docio->getBlockSize();
    uint64_t _offset = 0;
    int aio_size = 0;
    bool read_fail = false;
    bool read_on_cache_miss = true;

    if (aio_handle) {
        // If async I/O is supported, we will then read non-resident docs from disk
        // by using async I/O operations.
        read_on_cache_miss = false;
    }

    for (i = 0; i < array_size && i < batch_size_threshold &&
           sum_doc_size < data_size_threshold; ++i) {
        memset(&doc_array[doc_idx], 0x0, sizeof(struct docio_object));
        if (keymeta_only) {
            _offset = readDocKeyMeta_Docio(offset_array[i], &doc_array[doc_idx],
                                              read_on_cache_miss);
        } else {
            _offset = readDoc_Docio(offset_array[i], &doc_array[doc_idx],
                                     read_on_cache_miss);
        }
        if (_offset <= 0) {
            if (aio_handle) {
                // The page is not resident in the cache.
                // Prepare and perform Async I/O.
                file_Docio->getOps()->aio_prep_read(file_Docio->getFopsHandle(),
                                                    aio_handle, aio_size,
                                                    block_size, offset_array[i]);
                if (++aio_size == (int) aio_handle->queue_depth) {
                    int num_sub = _submitAsyncIORequests_Docio(doc_array, doc_idx,
                                                            aio_handle, aio_size,
                                                            &sum_doc_size,
                                                            keymeta_only);
                    if (num_sub < 0 || num_sub != aio_size) {
                        read_fail = true;
                        break;
                    }
                    aio_size = 0;
                    doc_idx += num_sub;
                }
            } else {
                ++doc_idx; // Error in reading a doc.
            }
        } else {
            sum_doc_size += _fdb_get_docsize(doc_array[doc_idx].length);
            if (keymeta_only) {
                sum_doc_size -= doc_array[doc_idx].length.bodylen_ondisk;
            }
            ++doc_idx;
        }
    }

    if (aio_size && !read_fail) {
        int num_sub = _submitAsyncIORequests_Docio(doc_array, doc_idx,
                                                aio_handle, aio_size,
                                                &sum_doc_size, keymeta_only);
        if (num_sub < 0) {
            read_fail = true;
        } else {
            doc_idx += num_sub;
        }
    }

    if (read_fail) {
        for (i = 0; i < batch_size_threshold; ++i) {
            free(doc_array[i].key);
            free(doc_array[i].meta);
            free(doc_array[i].body);
            doc_array[i].key = doc_array[i].meta = doc_array[i].body = NULL;
        }
        return (size_t) -1;
    }

    return doc_idx;
}

bool DocioHandle::checkBuffer_Docio(bid_t bid,
                        uint64_t sb_bmp_revnum)
{
    _readThroughBuffer_Docio(bid, true);
    return _checkBuffer_Docio(sb_bmp_revnum);
}

