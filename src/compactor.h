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

#ifndef _FDB_COMPACTOR_H
#define _FDB_COMPACTOR_H

#include <time.h>

#include "internal_types.h"

#ifdef __cplusplus
extern "C" {
#endif

struct compactor_config{
    size_t sleep_duration;
};

void compactor_init(struct compactor_config *config);
void compactor_shutdown();
bool compactor_switch_compaction_flag(struct filemgr *file, bool flag);
fdb_status compactor_register_file(struct filemgr *file,
                                   fdb_config *config,
                                   struct list *cmp_func_list);
void compactor_deregister_file(struct filemgr *file);
void compactor_change_threshold(struct filemgr *file, size_t new_threshold);
void compactor_switch_file(struct filemgr *old_file, struct filemgr *new_file);
void compactor_get_virtual_filename(const char *filename,
                                    char *virtual_filename);
fdb_status compactor_get_actual_filename(const char *filename,
                                         char *actual_filename,
                                         fdb_compaction_mode_t comp_mode);
void compactor_get_next_filename(char *file, char *nextfile);
bool compactor_is_valid_mode(const char *filename, fdb_config *config);

fdb_status compactor_destroy_file(char *filename,
                                  fdb_config *config);

#if !defined(WIN32) && !defined(_WIN32)
struct timespec convert_reltime_to_abstime(unsigned int ms);
#endif

#ifdef __cplusplus
}
#endif

#endif
