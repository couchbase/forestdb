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

#if defined(_CRYPTO_CC)

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
        assert(status != kCCParamError && status != kCCBufferTooSmall &&
               status != kCCUnimplemented);
        return status == kCCSuccess;
    }

    #define AES256_AVAILABLE 1
    #define SHA256_AVAILABLE 1

#elif defined(_CRYPTO_LIBTOMCRYPT)

    #include <tomcrypt.h>

    static inline void sha256(const void *src_buf,
                              size_t size,
                              void *digest)
    {
        unsigned long dummy = size;
        register_hash(&sha256_desc);
        hash_memory(find_hash("sha256"), (const unsigned char*)src_buf,
                    (unsigned long)size, (unsigned char*)digest, &dummy);
    }

    static bool aes256(bool encrypt,
                       const void *key,
                       const void *iv,
                       void *dst_buf,
                       const void *src_buf,
                       size_t size)
    {
        if(register_cipher(&rijndael_desc) != CRYPT_OK) {
            return false;
        }

        int cipher_idx = find_cipher("rijndael");
        symmetric_CBC cbc;
        uint8_t tmpiv[16] = {0};
        if (iv == NULL) {
            iv = tmpiv;
        }

        int err = cbc_start(cipher_idx, (const unsigned char*)iv,
                            (const unsigned char*)key, 32, 0, &cbc);
        if (err != CRYPT_OK) {
            return false;
        }

        if (encrypt) {
            err = cbc_encrypt((const unsigned char*)src_buf, (unsigned char*)dst_buf,
                              size, &cbc);
        } else {
            err = cbc_decrypt((const unsigned char*)src_buf, (unsigned char*)dst_buf,
                              size, &cbc);
        }

        if(err != CRYPT_OK) {
            return false;
        }
        err = cbc_done(&cbc);

        return err == CRYPT_OK;
    }

    #define AES256_AVAILABLE 1
    #define SHA256_AVAILABLE 1

#elif defined(_CRYPTO_OPENSSL)

    #include <openssl/aes.h>
    #include <openssl/sha.h>

    static inline void sha256(const void *src_buf,
                              size_t size,
                              void *digest)
    {
        SHA256_CTX sha256;
        SHA256_Init(&sha256);
        SHA256_Update(&sha256, src_buf, size);
        SHA256_Final((unsigned char*)digest, &sha256);
    }

    static inline bool aes256(bool encrypt,
                              const void *key,
                              const void *iv,
                              void *dst_buf,
                              const void *src_buf,
                              size_t size)
    {
        AES_KEY aes_key;
        uint8_t tmpiv[16] = {0};

        if(iv == NULL) {
            iv = tmpiv;
        }

        if(encrypt) {
            AES_set_encrypt_key((const unsigned char*)key, 256, &aes_key);
            AES_cbc_encrypt((const unsigned char*)src_buf, (unsigned char*)dst_buf,
                            size, &aes_key, (unsigned char *)iv, AES_ENCRYPT);
        } else {
            AES_set_decrypt_key((const unsigned char*)key, 256, &aes_key);
            AES_cbc_encrypt((const unsigned char*)src_buf, (unsigned char*)dst_buf,
                            size, &aes_key, (unsigned char *)iv, AES_DECRYPT);
        }

        return true;
    }

    #define AES256_AVAILABLE 1
    #define SHA256_AVAILABLE 1

#else

    #define AES256_AVAILABLE 0
    #define SHA256_AVAILABLE 0

#endif


#endif /* _FDB_CRYPTO_PRIMITIVES_H */
