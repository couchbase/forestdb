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
#include "crypto_primitives.h"
#include <string.h>

#if AES256_AVAILABLE && SHA256_AVAILABLE

static fdb_status aes_setup(encryptor *e) {
    // There must be room enough for AES keys in the provided structs:
    // (This would be a compile-time assert if C supported those.)
    assert(sizeof(e->key.bytes) == 32);
    assert(sizeof(e->extra) >= 32);
    // Precompute an auxiliary key by generating a SHA256 digest of the main key:
    sha256(&e->key.bytes, sizeof(e->key.bytes), e->extra);
    return FDB_RESULT_SUCCESS;
}

static fdb_status aes_crypt(encryptor *e,
                            bool encrypt,
                            void *dst_buf,
                            const void *src_buf,
                            size_t size,
                            bid_t bid)
{
    // Derive an IV as per the Encrypted Salt-Sector Initialization Value (ESSIV) algorithm
    // by encrypting the block number using the auxiliary key (a digest of the key.)
    // See https://en.wikipedia.org/wiki/Disk_encryption_theory
    uint8_t iv[16] = {0};
    uint64_t bigBlockNo = _endian_encode(bid);
    memcpy(&iv, &bigBlockNo, sizeof(bigBlockNo));
    if (!aes256(true, e->extra, NULL, &iv, &iv, sizeof(iv)))
        return FDB_RESULT_CRYPTO_ERROR;

    // Now encrypt/decrypt the block using the main key and the IV:
    if (!aes256(encrypt, e->key.bytes, iv, dst_buf, src_buf, size))
        return FDB_RESULT_CRYPTO_ERROR;
    return FDB_RESULT_SUCCESS;
}

static encryption_ops aes_ops = {
    aes_setup,
    aes_crypt
};

const encryption_ops* const fdb_encryption_ops_aes = &aes_ops;

#else // AES not available:

const encryption_ops* const fdb_encryption_ops_aes = NULL;

#endif // AES256_AVAILABLE && SHA256_AVAILABLE
