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

#ifndef _FDB_INTERNAL_H
#define _FDB_INTERNAL_H

#include <stdint.h>
#include "common.h"
#include "internal_types.h"

#ifdef __cplusplus
extern "C" {
#endif

void fdb_check_file_reopen(fdb_handle *handle);
void fdb_link_new_file(fdb_handle *handle);
void fdb_sync_db_header(fdb_handle *handle);

void fdb_fetch_header(void *header_buf, bid_t *trie_root_bid,
                      bid_t *seq_root_bid, uint64_t *ndocs,
                      uint64_t *nlivenodes, uint64_t *datasize,
                      uint64_t *last_header_bid, char **new_filename,
                      char **old_filename);

fdb_status fdb_open_for_compactor(fdb_handle **ptr_handle,
                                  const char *filename,
                                  fdb_config *config);

fdb_status fdb_compact_file(fdb_handle *handle,
                            const char *new_filename);

#ifdef __cplusplus
}
#endif

#endif
