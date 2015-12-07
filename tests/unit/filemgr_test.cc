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

void basic_test(fdb_encryption_algorithm_t encryption)
{
    TEST_INIT();

    struct filemgr *file;
    struct filemgr_config config;
    const char *dbheader = "dbheader";
    const char *dbheader2 = "dbheader2222222222";
    char buf[256];

    memset(&config, 0, sizeof(config));
    config.blocksize = 4096;
    config.ncacheblock = 1024;
    config.options = FILEMGR_CREATE;
    config.num_wal_shards = 8;

    config.encryption_key.algorithm = encryption;
    memset(&config.encryption_key.bytes, 0x55, sizeof(config.encryption_key.bytes));

    filemgr_open_result result = filemgr_open((char *) "./filemgr_testfile",
                                              get_filemgr_ops(), &config, NULL);
    result = filemgr_open((char *) "./filemgr_testfile", get_filemgr_ops(), &config, NULL);
    file = result.file;

    filemgr_update_header(file, (void*)dbheader, strlen(dbheader)+1, true);

    filemgr_close(file, true, NULL, NULL);
    result = filemgr_open((char *) "./filemgr_testfile", get_filemgr_ops(), &config, NULL);
    file = result.file;

    memcpy(buf, file->header.data, file->header.size);
    printf("%s\n", buf);

    filemgr_update_header(file, (void*)dbheader2, strlen(dbheader2) + 1, true);

    filemgr_close(file, true, NULL, NULL);

    sprintf(buf, "basic test, encryption=%d", (int)encryption);
    TEST_RESULT(buf);
}

void mt_init_test()
{
    TEST_INIT();

    TEST_RESULT("multi threaded initialization test");
}

int main()
{
    int r = system(SHELL_DEL" filemgr_testfile");
    (void)r;

    basic_test(FDB_ENCRYPTION_NONE);
    basic_test(FDB_ENCRYPTION_BOGUS);
    mt_init_test();

    return 0;
}
