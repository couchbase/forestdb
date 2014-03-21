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

#ifndef _JSAHN_HASH_FUNCTIONS_H
#define _JSAHN_HASH_FUNCTIONS_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

uint32_t hash_djb2(uint8_t *value, int len);
uint32_t hash_djb2_last8(uint8_t *value, int len);
uint32_t hash_uint_modular(uint64_t value, uint64_t mod);
uint32_t hash_shuffle_2uint(uint64_t a, uint64_t b);

#ifdef __cplusplus
}
#endif

#endif
