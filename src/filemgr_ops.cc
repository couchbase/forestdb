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

#include "filemgr_ops.h"

struct filemgr_ops * get_win_filemgr_ops();
struct filemgr_ops * get_linux_filemgr_ops();

struct filemgr_ops * get_filemgr_ops()
{
#if defined(WIN32) || defined(_WIN32)
    // windows
    return get_win_filemgr_ops();
#else
    // linux, mac os x
    return get_linux_filemgr_ops();
#endif
}
