#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include "filemgr.h"
#include "filemgr_ops_linux.h"
#include "test.h"

void basic_test()
{
    TEST_INIT();

    struct filemgr *file;
    struct filemgr_config config;
    char *dbheader = "dbheader";
    char *dbheader2 = "dbheader2222222222";
    char buf[256];
    int len;

    memset(&config, 0, sizeof(config));
    config.blocksize = 4096;
    config.ncacheblock = 1024;

    file = filemgr_open("./dummy", get_linux_filemgr_ops(), &config);
    file = filemgr_open("./dummy", get_linux_filemgr_ops(), &config);

    filemgr_update_header(file, dbheader, strlen(dbheader)+1);

    filemgr_close(file);
    file = filemgr_open("./dummy", get_linux_filemgr_ops(), &config);

    memcpy(buf, file->header.data, file->header.size);
    printf("%s\n", buf);

    filemgr_update_header(file, dbheader2, strlen(dbheader2) + 1);

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
    int r = system("rm -rf ./dummy");

    basic_test();
    mt_init_test();

    return 0;
}
