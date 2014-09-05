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

#ifndef _CONFIGURATION_H
#define _CONFIGURATION_H

#include <stdint.h>

#include "common.h"
#include "internal_types.h"

#ifdef __cplusplus
extern "C" {
#endif

    fdb_config get_default_config(void);
    fdb_kvs_config get_default_kvs_config(void);

    bool validate_fdb_config(fdb_config *fconfig);
    bool validate_fdb_kvs_config(fdb_kvs_config *kvs_config);

#ifdef __cplusplus
}
#endif

#endif
