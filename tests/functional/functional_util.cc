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
    int fd = ops->open(filepath, O_CREAT| O_RDWR, 0666);
    if (fd < 0) {
        fprintf(stderr, "failure to open %s\n", filepath);
        return fd;
    }
    char *buf = (char *)malloc(bytes);
    if (!buf) {
        return -2;
    }
    if (ops->pwrite(fd, buf, bytes, pos) != (int) bytes) {
        return -1;
    }
    ops->close(fd);
    free(buf);
    return fd;
}

void logCallbackFunc(int err_code,
                     const char *err_msg,
                     void *pCtxData) {
    fprintf(stderr, "%s - error code: %d, error message: %s\n",
            (char *) pCtxData, err_code, err_msg);
}

