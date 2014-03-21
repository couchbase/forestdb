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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "filemgr.h"
#include "filemgr_ops.h"
#include "test.h"

void basic_test()
{
    TEST_INIT();

    struct filemgr *file;
    struct filemgr_config config;
    const char *dbheader = "dbheader";
    const char *dbheader2 = "dbheader2222222222";
    char buf[256];
    int len;

    memset(&config, 0, sizeof(config));
    config.blocksize = 4096;
    config.ncacheblock = 1024;

    file = filemgr_open((char *) "./dummy", get_filemgr_ops(), &config);
    file = filemgr_open((char *) "./dummy", get_filemgr_ops(), &config);

    filemgr_update_header(file, (void*)dbheader, strlen(dbheader)+1);

    filemgr_close(file);
    file = filemgr_open((char *) "./dummy", get_filemgr_ops(), &config);

    memcpy(buf, file->header.data, file->header.size);
    printf("%s\n", buf);

    filemgr_update_header(file, (void*)dbheader2, strlen(dbheader2) + 1);

    filemgr_close(file);

    TEST_RESULT("basic test");
}

void mt_init_test()
{
    TEST_INIT();

    TEST_RESULT("multi threaded initialization test");
}

int main()
{
    int r = system(SHELL_DEL" dummy");

    basic_test();
    mt_init_test();

    return 0;
}
