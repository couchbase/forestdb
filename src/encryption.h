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

#ifndef _FDB_ENCRYPTION_H
#define _FDB_ENCRYPTION_H

#include "libforestdb/fdb_types.h"
#include "libforestdb/fdb_errors.h"
#include "common.h"

// A very simple but insecure algorithm for testing purposes only.
enum {
    FDB_ENCRYPTION_BOGUS = -1
};

// An "object" that can perform encryption.
typedef struct {
    const struct encryption_ops *ops;       // callbacks
    fdb_encryption_key key;                 // key + algorithm
    uint8_t extra[32];                      // scratch space for encryptor to use
} encryptor;

// Initializes an encryptor given a key.
fdb_status fdb_init_encryptor(encryptor*,
                              const fdb_encryption_key*);

// Decrypts a block of data.
fdb_status fdb_decrypt_block(encryptor*,
                             void *buf,
                             size_t blocksize,
                             bid_t bid);

// Encrypts one or more consecutive blocks of data.
fdb_status fdb_encrypt_blocks(encryptor*,
                              void *dst_buf,
                              const void *src_buf,
                              size_t blocksize,
                              unsigned num_blocks,
                              bid_t start_bid);

// Callbacks provided by an encryption implementation.
typedef struct encryption_ops {
    fdb_status (*setup)(encryptor*);
    fdb_status (*crypt)(encryptor*,
                        bool encrypt,
                        void *dst_buf,
                        const void *src_buf,
                        size_t size,
                        bid_t bid);
} encryption_ops;

// Provides the encryption_ops (callbacks) for a particular algorithm.
const encryption_ops* get_encryption_ops(fdb_encryption_algorithm_t);

// Declarations of encryption_ops for specific algorithms.
// Will be NULL if not implemented on the current platform.
extern const encryption_ops* const fdb_encryption_ops_aes;
extern const encryption_ops* const fdb_encryption_ops_bogus;

#endif /* _FDB_ENCRYPTION_H */
