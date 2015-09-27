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

#ifndef _FDB_CRYPTO_PRIMITIVES_H
#define _FDB_CRYPTO_PRIMITIVES_H

// Defines inline functions sha256 and aes256 if implementations are available.
// Callers can use "#if AES_AVAILABLE" to conditionalize code based on availability.

#if defined(__APPLE__)

    // iOS and Mac OS implementation based on system-level CommonCrypto library:
    #include <CommonCrypto/CommonDigest.h>
    #include <CommonCrypto/CommonCryptor.h>
    #include <assert.h>

    static inline void sha256(const void *src_buf,
                              size_t size,
                              void *digest)
    {
        CC_SHA256(src_buf, size, (uint8_t*)digest);
    }

    static bool aes256(bool encrypt,
                       const void *key,
                       const void *iv,
                       void *dst_buf,
                       const void *src_buf,
                       size_t size)
    {
        size_t outSize;
        CCCryptorStatus status = CCCrypt((encrypt ? kCCEncrypt : kCCDecrypt),
                                         kCCAlgorithmAES128, 0,
                                         key, kCCKeySizeAES256,
                                         iv,
                                         src_buf, size, dst_buf, size, &outSize);
        assert(status != kCCParamError && status != kCCBufferTooSmall && status != kCCUnimplemented);
        return status == kCCSuccess;
    }

    #define AES256_AVAILABLE 1
    #define SHA256_AVAILABLE 1

#else

    #define AES256_AVAILABLE 0
    #define SHA256_AVAILABLE 0

#endif


#endif /* _FDB_CRYPTO_PRIMITIVES_H */
