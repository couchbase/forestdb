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

/*
 * Checksum abstraction functions.
 *
 * ForestDB evolved to support a software CRC and platform's CRC32-C.
 * This module provides an API for checking and creating checksums
 * utilising the correct method based upon the callers crc_mode.
 */


#include <stdlib.h>
#include <assert.h>
#ifdef _CRC32C
// Linking with platform for crc32c
# include <platform/crc32c.h>
#else
#include <stdint.h>
// Define a crc32c which does nothing but assert.
static uint32_t crc32c(const uint8_t* buf,
                size_t buf_len,
                uint32_t pre) {
    // Non couchbase builds are configured to never turn on crc32c.
    assert(false);
    return 0;
}
#endif
# include "checksum.h"
#include "crc32.h"

/*
 * Get a checksum of buf for buf_len bytes.
 *
 * mode = UNKNOWN is an invalid input (triggers assert).
 */
uint32_t get_checksum(const uint8_t* buf,
                      size_t buf_len,
                      uint32_t pre,
                      crc_mode_e mode) {
    if (mode == CRC32C) {
        return crc32c(buf, buf_len, pre);
    } else {
        assert(mode == CRC32);
        return crc32_8((void *)buf, buf_len, pre);
    }
}

/*
 * Get a checksum of buf for buf_len bytes.
 *
 * The pre value is set to 0.
 *
 * mode = UNKNOWN is an invalid input (triggers assert).
 */
uint32_t get_checksum(const uint8_t* buf,
                      size_t buf_len,
                      crc_mode_e mode) {
    return get_checksum(buf, buf_len, 0, mode);
}

/*
 * Perform an integrity check of buf for buf_len bytes.
 *
 * A checksum of buf is created and compared against checksum argument.
 *
 * mode = UNKNOWN is an acceptable input. All modes are tried before failing.
 *
 *
 * Returns true success (checksums match), false for failure.
 */
bool perform_integrity_check(const uint8_t* buf,
                            size_t buf_len,
                            uint32_t checksum,
                            crc_mode_e mode) {
    bool success = false;
#ifdef _CRC32C
    if (mode == CRC_UNKNOWN || mode == CRC32C) {
        success = checksum == crc32c(buf, buf_len, 0);
        if (!success && mode == CRC_UNKNOWN) {
            success = checksum == crc32_8((void *)buf, buf_len, 0);
        }
    } else
#endif
    {
        success = checksum == crc32_8((void *)buf, buf_len, 0);
    }
    return success;
}

/*
 * Detect the CRC mode by performing an integrity check against the
 * two CRC functions ForestDB files could be written with.
 *
 * Returns true if a match is found and sets mode to the correct mode.
 * Returns false if no match and sets mode to CRC_UNKNOWN.
 */
bool detect_and_check_crc(const uint8_t* buf,
                          size_t buf_len,
                          uint32_t checksum,
                          crc_mode_e* mode) {
    *mode = CRC_UNKNOWN;
#ifdef _CRC32C
    if (perform_integrity_check(buf, buf_len, checksum, CRC32C)) {
        *mode = CRC32C;
        return true;
    } else
#endif
    if (perform_integrity_check(buf, buf_len, checksum, CRC32)) {
        *mode = CRC32;
        return true;
    }

    return false;
}
