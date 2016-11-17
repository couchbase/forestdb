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

    FileMgr *file;
    FileMgrConfig config(4096, 1024, 1048576, 0, 0, FILEMGR_CREATE,
                         FDB_SEQTREE_NOT_USE, 0, 8, 0, encryption,
                         0x55, 0, 0);
    const char *dbheader = "dbheader";
    const char *dbheader2 = "dbheader2222222222";
    char buf[256];

    std::string fname("./filemgr_testfile");
    filemgr_open_result result = FileMgr::open(fname,
                                               get_filemgr_ops(),
                                               &config, NULL);
    result = FileMgr::open(fname, get_filemgr_ops(), &config, NULL);
    file = result.file;

    file->updateHeader((void*)dbheader, strlen(dbheader)+1);

    FileMgr::close(file, true, NULL, NULL);
    result = FileMgr::open(fname, get_filemgr_ops(), &config, NULL);
    file = result.file;

    memcpy(buf, file->accessHeader()->data, file->accessHeader()->size);
    printf("%s\n", buf);

    file->updateHeader((void*)dbheader2, strlen(dbheader2) + 1);

    FileMgr::close(file, true, NULL, NULL);

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
