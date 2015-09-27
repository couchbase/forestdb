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
#include <string.h>

//#define FDB_LOG_CRYPTO

fdb_status fdb_init_encryptor(encryptor *e,
                              const fdb_encryption_key *key)
{
    if (key->algorithm == FDB_ENCRYPTION_NONE) {
        e->ops = NULL;
        return FDB_RESULT_SUCCESS;
    }
#ifdef FDB_LOG_CRYPTO
    fprintf(stderr, "CRYPT: Initializing context for key %d:%llx\n",
            key->algorithm, *(uint64_t*)key->bytes);
#endif
    e->ops = get_encryption_ops(key->algorithm);
    if (!e->ops)
        return FDB_RESULT_CRYPTO_ERROR; // unsupported algorithm
    e->key = *key;
    return e->ops->setup(e);
}

fdb_status fdb_decrypt_block(encryptor *e,
                             void *buf,
                             size_t blocksize,
                             bid_t bid)
{
#ifdef FDB_LOG_CRYPTO
    fprintf(stderr, "CRYPT: Decrypting block #%llu with key %d:%llx\n",
            bid, e->key.algorithm, *(uint64_t*)e->key.bytes);
#endif
    return e->ops->crypt(e, false, buf, buf, blocksize, bid);
}

fdb_status fdb_encrypt_blocks(encryptor *e,
                              void *dst_buf,
                              const void *src_buf,
                              size_t blocksize,
                              unsigned num_blocks,
                              bid_t start_bid)
{
#ifdef FDB_LOG_CRYPTO
    fprintf(stderr, "CRYPT: Encrypting blocks #%llu-%llu with key %d:%llx\n",
            start_bid, start_bid+num_blocks-1,
            e->key.algorithm, *(uint64_t*)e->key.bytes);
#endif
    fdb_status status = FDB_RESULT_SUCCESS;
    for (unsigned i = 0; i < num_blocks; i++) {
        status = e->ops->crypt(e,
                               true,
                               (uint8_t*)dst_buf + i*blocksize,
                               (const uint8_t*)src_buf + i*blocksize,
                               blocksize,
                               start_bid + i);
        if (status != FDB_RESULT_SUCCESS)
            break;
    }
    return status;
}

const encryption_ops* get_encryption_ops(fdb_encryption_algorithm_t algorithm) {
    switch (algorithm) {
        case FDB_ENCRYPTION_AES256:
            return fdb_encryption_ops_aes;
        case FDB_ENCRYPTION_BOGUS:
            return fdb_encryption_ops_bogus;
        default:
            return NULL;
    }
}
