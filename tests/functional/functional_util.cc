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

#include "functional_util.h"
#include "filemgr.h"

void _set_random_string(char *str, int len)
{
    str[len--] = 0;
    do {
        str[len] = '!' + random('~'-'!');
    } while (len--);
}

void _set_random_string_smallabt(char *str, int len)
{
    str[len--] = 0;
    do {
        str[len] = 'a' + random('z'-'a');
    } while (len--);
}

int _disk_dump(const char *filepath, size_t pos, size_t bytes) {
    struct filemgr_ops *ops = get_filemgr_ops();
    fdb_fileops_handle fileops_handle;
    fdb_status fs = FileMgr::fileOpen(filepath, ops, &fileops_handle,
                                      O_CREAT| O_RDWR, 0666);
    if (fs != FDB_RESULT_SUCCESS) {
        fprintf(stderr, "failure to open %s\n", filepath);
        return (int)fs;
    }
    char *buf = (char *)malloc(bytes);
    if (!buf) {
        FileMgr::fileClose(ops, fileops_handle);
        return -2;
    }
    if (ops->pwrite(fileops_handle, buf, bytes, pos) != (int) bytes) {
        FileMgr::fileClose(ops, fileops_handle);
        return -1;
    }
    FileMgr::fileClose(ops, fileops_handle);
    free(buf);
    return (int)fs;
}

void logCallbackFunc(int err_code,
                     const char *err_msg,
                     void *pCtxData) {
    fprintf(stderr, "%s - error code: %d, error message: %s\n",
            (char *) pCtxData, err_code, err_msg);
}

