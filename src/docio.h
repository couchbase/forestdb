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

#ifdef __cplusplus
extern "C" {
#endif

#define DOCIO_NORMAL (0x00)
#define DOCIO_COMPACT (0x01)
#define DOCIO_COMPRESSED (0x02)
#define DOCIO_DELETED (0x04)

typedef uint16_t keylen_t;
typedef uint32_t timestamp_t;

struct docio_handle {
    struct filemgr *file;
    bid_t curblock;
    uint32_t curpos;
    // for buffer purpose
    bid_t lastbid;
    void *readbuffer;
    err_log_callback *log_callback;
    uint8_t compress_document_body;
};

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
    fdb_seqnum_t seqnum;
    void *meta;
    void *body;
};

void docio_init(struct docio_handle *handle,
                struct filemgr *file,
                uint8_t compress_document_body);
void docio_free(struct docio_handle *handle);

bid_t docio_append_doc_raw(struct docio_handle *handle,
                           uint64_t size,
                           void *buf);
bid_t docio_append_doc_compact(struct docio_handle *handle,
                               struct docio_object *doc,
                               uint8_t deleted);
bid_t docio_append_doc(struct docio_handle *handle,
                       struct docio_object *doc,
                       uint8_t deleted);

struct docio_length docio_read_doc_length(struct docio_handle *handle,
                                          uint64_t offset);
void docio_read_doc_key(struct docio_handle *handle,
                        uint64_t offset,
                        keylen_t *keylen,
                        void *keybuf);
uint64_t docio_read_doc_key_meta(struct docio_handle *handle,
                                 uint64_t offset,
                                 struct docio_object *doc);
uint64_t docio_read_doc(struct docio_handle *handle,
                        uint64_t offset,
                        struct docio_object *doc);

int docio_check_buffer(struct docio_handle *dhandle, bid_t check_bid);
int docio_check_compact_doc(struct docio_handle *handle,
                            struct docio_object *doc);

#ifdef __cplusplus
}
#endif

#endif
