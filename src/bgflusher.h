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

#ifndef _FDB_BGFLUSHER_H
#define _FDB_BGFLUSHER_H

#include <time.h>

#include "internal_types.h"

#ifdef __cplusplus
extern "C" {
#endif

struct bgflusher_config{
    size_t num_threads;
};

void bgflusher_init(struct bgflusher_config *config);
void bgflusher_shutdown();
fdb_status bgflusher_register_file(struct filemgr *file,
                                   fdb_config *config,
                                   err_log_callback *log_callback);
void bgflusher_switch_file(struct filemgr *old_file, struct filemgr *new_file,
                           err_log_callback *log_callback);
void bgflusher_deregister_file(struct filemgr *file);

#ifdef __cplusplus
}
#endif

#endif // _FDB_BGFLUSHER_H
