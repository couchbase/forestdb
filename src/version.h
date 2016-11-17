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

#ifndef _FDB_VERSION_H
#define _FDB_VERSION_H

#include "libforestdb/fdb_types.h"
#include "libforestdb/fdb_errors.h"
#include "common.h"

#include "filemgr.h"

INLINE filemgr_magic_t ver_get_latest_magic() {
    return FILEMGR_LATEST_MAGIC;
}
bool ver_is_valid_magic(filemgr_magic_t magic);
bool ver_is_magic_000(filemgr_magic_t magic);
bool ver_is_atleast_magic_001(filemgr_magic_t magic);
bool ver_staletree_support(filemgr_magic_t magic);
bool ver_superblock_support(filemgr_magic_t magic);
bool ver_non_consecutive_doc(filemgr_magic_t magic);
bool ver_btreev2_format(filemgr_magic_t magic);
size_t ver_get_new_filename_off(filemgr_magic_t magic);

/**
 * Return the version of a given file's magic value
 *
 * @param magic ForestDB file magic value
 * @return Version of a given file's magic value
 */
const char* ver_get_version_string(filemgr_magic_t magic);

/**
 * Return the offset of last_wal_flush_header field in a commit header
 */
size_t ver_get_last_wal_flush_hdr_off(filemgr_magic_t magic);

#endif /* _FDB_VERSION_H */

