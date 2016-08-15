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

#ifndef _JSAHN_DOCIO_H
#define _JSAHN_DOCIO_H

#include "filemgr.h"
#include "common.h"

typedef uint16_t keylen_t;
typedef uint32_t timestamp_t;

class DocioHandle {
public:
    DocioHandle(FileMgr *file, bool compress_body,
                ErrLogCallback *log_callback);
    ~DocioHandle();

    /**
     * Directly append a docio_object buffer to disk
     *
     * @Param size - size of buffer to be appended
     * @param buf - actual buffer to be appended to disk
     * @return new final offset on completion
     */
    bid_t appendDocRaw_Docio(uint64_t size, void *buf);

    /**
     * Append a system doc with commit info for transactional commits
     * @param doc_offset - the offset into file to append the commit mark doc
     * @return - return offset indicating end point of appended doc
     */
    bid_t appendCommitMark_Docio(uint64_t doc_offset);

    /**
     * Append a doc into the document blocks of the file
     * @param doc - the doc to be persisted
     * @param deleted - is the doc deleted
     * @param txn_enabled - is it an uncommitted transactional doc
     * @return - return offset indicating end point of appended doc
     */
    bid_t appendDoc_Docio(struct docio_object *doc,
                          uint8_t deleted, uint8_t txn_enabled);

    /**
     * Append a system doc into the document blocks of the file
     * @param doc - the doc to be persisted
     * @return - return offset indicating end point of appended doc
     */
    bid_t appendSystemDoc_Docio(struct docio_object *doc);

    /**
     * Retrieve the length info of a KV item at a given file offset.
     *
     * @Param length Pointer to docio_length instance to be populated
     * @param offset File offset to a KV item
     * @return FDB_RESULT_SUCCESS on success
     */
    fdb_status readDocLength_Docio(struct docio_length *length,
                                   uint64_t offset);

    /**
     * Read a key and its length at a given file offset.
     *
     * @param offset File offset to a KV item
     * @param keylen Pointer to a key length variable
     * @param keybuf Pointer to a key buffer
     * @return FDB_RESULT_SUCCESS on success
     */
    fdb_status readDocKey_Docio(uint64_t offset,
                                keylen_t *keylen,
                                void *keybuf);

    /**
     * Read a key and its metadata at a given file offset.
     *
     * @param offset File offset to a KV item
     * @param doc Pointer to docio_object instance
     * @param read_on_cache_miss Flag indicating if a disk read should be performed
     *        on cache miss
     * @return next offset right after a key and its metadata on succcessful read,
     *         otherwise, the corresponding error code is returned.
     */
    int64_t readDocKeyMeta_Docio(uint64_t offset,
                                 struct docio_object *doc,
                                 bool read_on_cache_miss);

    /**
     * Read a KV item at a given file offset.
     *
     * @param offset File offset to a KV item
     * @param doc Pointer to docio_object instance
     * @param read_on_cache_miss Flag indicating if a disk read should be performed
     *        on cache miss
     * @return next offset right after a key and its value on succcessful read,
     *         otherwise, the corresponding error code is returned.
     */
    int64_t readDoc_Docio(uint64_t offset,
                          struct docio_object *doc,
                          bool read_on_cache_miss);

    /**
     * Read a batch of docs using async reads if possible
     *
     * @param offset_array - offsets to read from
     * @param doc_array - read docs
     * @param array_size
     * @param data_size_threshold - max size of async reads
     * @param batch_size_threshold -
     * @param async_io_handle - handle to the aio
     * @return number of docs read.
     */
    size_t batchReadDocs_Docio(uint64_t *offset_array,
                               struct docio_object *doc_array,
                               size_t array_size,
                               size_t data_size_threshold,
                               size_t batch_size_threshold,
                               struct async_io_handle *aio_handle,
                               bool keymeta_only);

    /**
     * Check if the given block is a valid document block.
     * The bitmap revision number of
     * the document block should match the passed revision number.
     *
     * @param bid ID of the block.
     * @param sb_bmp_revnum Revision number of bitmap in superblock.
     *        If the value is
     *        -1, this function does not care about revision number.
     * @return True if valid.
     */
    bool checkBuffer_Docio(bid_t bid, uint64_t sb_bmp_revnum);

    /**
     * Clear the cache of any previously read document block.
     */
    void reset_Docio() {
        curblock = BLK_NOT_FOUND;
    }

    /**
     * Validate the checksum of a docio length buffer
     */
    bool validateChecksum_Docio(bool read_on_cache_miss,
                                int64_t *offset,
                                struct docio_length *length,
                                fdb_status *status);

    FileMgr *getFile() const {
        return file_Docio;
    }

    ErrLogCallback *getLogCallback() const {
        return log_callback;
    }
    void setLogCallback(ErrLogCallback *logCallback) {
        log_callback = logCallback;
    }

    bid_t getCurBlock() const {
        return curblock;
    }
    uint32_t getCurPos() const {
        return curpos;
    }
    uint16_t getCurBmpRevnumHash() const {
        return cur_bmp_revnum_hash;
    }
    bid_t getLastBid() const {
        return lastbid;
    }
    void *getReadBuffer() const {
        return readbuffer;
    }
    bool isDocBodyCompressed() const {
        return compress_document_body;
    }

    static struct docio_length encodeLength_Docio(struct docio_length length);

    static struct docio_length decodeLength_Docio(struct docio_length length);

private:
    fdb_status _fillZero_Docio(bid_t bid, size_t pos);

    int _submitAsyncIORequests_Docio(struct docio_object *doc_array,
                                     size_t doc_idx,
                                     struct async_io_handle *aio_handle,
                                     int size,
                                     size_t *sum_doc_size,
                                     bool keymeta_only);

    struct docio_length _encodeLength_Docio(struct docio_length length);

    struct docio_length _decodeLength_Docio(struct docio_length length);
    uint8_t _docio_length_checksum(struct docio_length length);
    bid_t _appendDoc_Docio(struct docio_object *doc);

    fdb_status _readThroughBuffer_Docio(bid_t bid, bool read_on_cache_miss);
    bool _checkBuffer_Docio(uint64_t bmp_revnum);
    int64_t _readLength_Docio(uint64_t offset,
                              struct docio_length *length,
                              bool read_on_cache_miss);

    int64_t _readDocComponent_Docio(uint64_t offset,
                                    uint32_t len,
                                    void *buf_out);

    int64_t _readCompressedDocComponent_Docio(uint64_t offset,
                                              uint32_t len,
                                              uint32_t comp_len,
                                              void *buf_out,
                                              void *comp_data_out);

    FileMgr *file_Docio;
    bid_t curblock;
    uint32_t curpos;
    uint16_t cur_bmp_revnum_hash;
    // for buffer purpose
    bool compress_document_body;
    ErrLogCallback *log_callback;
    bid_t lastbid;
    uint64_t lastBmpRevnum;
    void *readbuffer;
    DISALLOW_COPY_AND_ASSIGN(DocioHandle);
};

#define DOCIO_NORMAL (0x00)
#define DOCIO_COMPACT (0x01)
#define DOCIO_COMPRESSED (0x02)
#define DOCIO_DELETED (0x04)
#define DOCIO_TXN_DIRTY (0x08)
#define DOCIO_TXN_COMMITTED (0x10)
#define DOCIO_SYSTEM (0x20) /* system document */
#ifdef DOCIO_LEN_STRUCT_ALIGN
    // this structure will occupy 16 bytes
    struct docio_length {
        keylen_t keylen;
        uint16_t metalen;
        uint32_t bodylen;
        uint32_t bodylen_ondisk;
        uint8_t flag;
        uint8_t checksum;
    };
#else
    // this structure will occupy 14 bytes
    struct __attribute__ ((packed)) docio_length {
        keylen_t keylen;
        uint16_t metalen;
        uint32_t bodylen;
        uint32_t bodylen_ondisk;
        uint8_t flag;
        uint8_t checksum;
    };
#endif

struct docio_object {
    struct docio_length length;
    timestamp_t timestamp;
    void *key;
    union {
        fdb_seqnum_t seqnum;
        uint64_t doc_offset;
    };
    void *meta;
    void *body;
};

#define DOCIO_COMMIT_MARK_SIZE (sizeof(struct docio_length) + sizeof(uint64_t))

void free_docio_object(struct docio_object *doc, bool key_alloc,
                       bool meta_alloc, bool body_alloc);

#endif
