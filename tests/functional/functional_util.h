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

#ifndef _FUNCTIONAL_UTIL_H
#define _FUNCTIONAL_UTIL_H

#include <stdio.h>
#include "common.h"
#include "filemgr_ops.h"

#ifdef __cplusplus
extern "C" {
#endif

void _set_random_string(char *str, int len);

void _set_random_string_smallabt(char *str, int len);

int _disk_dump(const char *filepath, const size_t pos, const size_t bytes);

void logCallbackFunc(int err_code,
                     const char *err_msg,
                     void *pCtxData);

#ifdef __cplusplus
}
#endif

#endif
