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

#include "version.h"
#include <string.h>

bool ver_is_valid_magic(filemgr_magic_t magic)
{
    if ( magic == FILEMGR_MAGIC_000 ||
        (magic >= FILEMGR_MAGIC_001 && magic <= FILEMGR_LATEST_MAGIC)) {
        return true;
    }
    return false;
}

bool ver_is_magic_000(filemgr_magic_t magic)
{
    if (magic == FILEMGR_MAGIC_000) {
        return true;
    }
    return false;
}

bool ver_is_atleast_magic_001(filemgr_magic_t magic)
{
    // All magic numbers since FILEMGR_MAGIC_001
    if (magic >= FILEMGR_MAGIC_001 && magic <= FILEMGR_LATEST_MAGIC) {
        return true;
    }
    return false;
}

bool ver_staletree_support(filemgr_magic_t magic)
{
    // All magic numbers since FILEMGR_MAGIC_002
    if (magic >= FILEMGR_MAGIC_002 && magic <= FILEMGR_LATEST_MAGIC) {
        return true;
    }
    return false;
}

bool ver_non_consecutive_doc(filemgr_magic_t magic)
{
    // All magic numbers since FILEMGR_MAGIC_002
    if (magic >= FILEMGR_MAGIC_002 && magic <= FILEMGR_LATEST_MAGIC) {
        return true;
    }
    return false;
}

bool ver_superblock_support(filemgr_magic_t magic)
{
    // All magic numbers since FILEMGR_MAGIC_002
    if (magic >= FILEMGR_MAGIC_002 && magic <= FILEMGR_LATEST_MAGIC) {
        return true;
    }
    return false;
}

bool ver_btreev2_format(filemgr_magic_t magic)
{
    // All magic numbers since FILEMGR_MAGIC_003
    if (magic >= FILEMGR_MAGIC_003) {
        return true;
    }
    return false;
}

size_t ver_get_new_filename_off(filemgr_magic_t magic) {
    switch(magic) {
        case FILEMGR_MAGIC_000: return 64;
        case FILEMGR_MAGIC_001: return 72;
        case FILEMGR_MAGIC_002: return 80;
        case FILEMGR_MAGIC_003: return 80;
    }
    return (size_t) -1;
}

size_t ver_get_last_wal_flush_hdr_off(filemgr_magic_t magic) {
    switch(magic) {
        case FILEMGR_MAGIC_000: return 40;
        case FILEMGR_MAGIC_001: return 48;
        case FILEMGR_MAGIC_002: return 56;
        case FILEMGR_MAGIC_003: return 56;
    }
    return (size_t) -1;
}

const char* ver_get_version_string(filemgr_magic_t magic) {
    switch (magic) {
    case FILEMGR_MAGIC_000:
        return "ForestDB v1.x format";
    case FILEMGR_MAGIC_001:
        return "ForestDB v1.x format";
    case FILEMGR_MAGIC_002:
        return "ForestDB v2.x format";
    case FILEMGR_MAGIC_003:
        return "ForestDB v3.x format";
    }
    return "unknown";
}
