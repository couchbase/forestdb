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

#pragma once

#include <stddef.h>
#include <stdint.h>

enum crc_mode_e {
    CRC_UNKNOWN,
    CRC32,
    CRC32C,
#ifdef _CRC32C
    CRC_DEFAULT = CRC32C // Couchbase builds pickup crc32c from plaform
#else
    CRC_DEFAULT = CRC32 // Non-couchbase falls back to bundled utils/crc32.cc
#endif
};

/*
 * Get a checksum of buf for buf_len bytes.
 *
 * mode = UNKNOWN is an invalid input (triggers assert).
 */
uint32_t get_checksum(const uint8_t* buf,
                      size_t buf_len,
                      uint32_t pre,
                      crc_mode_e mode);

/*
 * Get a checksum of buf for buf_len bytes.
 *
 * The pre value is set to 0.
 *
 * mode = UNKNOWN is an invalid input (triggers assert).
 */
uint32_t get_checksum(const uint8_t* buf,
                      size_t buf_len,
                      crc_mode_e mode);

/*
 * Get a checksum of buf for buf_len bytes.
 *
 * The CRC is generated using the default mode for the build of ForestDB.
 * The pre value is set to 0.
 *
 */
inline uint32_t get_checksum(const uint8_t* buf,
                             size_t buf_len) {
    return get_checksum(buf, buf_len, 0, CRC_DEFAULT);
}

/*
 * Perform an integrity check of buf for buf_len bytes.
 *
 * A checksum of buf is created and compared against checksum argument.
 *
 * mode = UNKNOWN is an acceptable input. All modes are tried before failing.
 *
 * Returns true success (checksums match), false for failure.
 */
bool perform_integrity_check(const uint8_t* buf,
                             size_t buf_len,
                             uint32_t checksum,
                             crc_mode_e mode);

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
                          crc_mode_e* mode);
