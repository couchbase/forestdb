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

#include "encryption.h"

// Bogus encryption for test purposes. Simply adds the same number to each byte in a block.
// The number is the LSB of the block number xor'ed with the first byte of the key.

fdb_status bogus_setup(encryptor *e) {
    return FDB_RESULT_SUCCESS;
}

static fdb_status bogus_crypt(encryptor *e,
                              bool encrypt,
                              void *dst_buf,
                              const void *src_buf,
                              size_t size,
                              bid_t bid)
{
    int8_t delta = (bid & 0xFF) ^ e->key.bytes[0];
    if (!encrypt)
        delta = -delta;
    const uint8_t *src = (const uint8_t *)src_buf;
    uint8_t *dst = (uint8_t *)dst_buf;
    while (size-- > 0) {
        *dst++ = *src++ + delta;
    }
    return FDB_RESULT_SUCCESS;
}

static encryption_ops bogus_ops = {
    bogus_setup,
    bogus_crypt
};

const encryption_ops* const fdb_encryption_ops_bogus = &bogus_ops;
