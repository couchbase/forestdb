#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "test.h"
#include "blockcache.h"
#include "filemgr.h"
#include "filemgr_ops_linux.h"

void basic_test()
{
	TEST_INIT();

	struct filemgr *file;
	struct filemgr_config config;
	bid_t bid;
	int i, j;
	uint8_t buf[4096];

	config.blocksize = 4096;
	config.ncacheblock = 5;
	file = filemgr_open("./dummy", get_linux_filemgr_ops(), config);

	for (i=0;i<5;++i) {
		filemgr_alloc(file);
		filemgr_write(file, i, buf);
	}
	filemgr_commit(file);
	for (i=5;i<10;++i) {
		filemgr_alloc(file);
		filemgr_write(file, i, buf);
	}
	filemgr_commit(file);
	
	filemgr_read(file, 8, buf);
	filemgr_read(file, 9, buf);

	filemgr_read(file, 1, buf);
	filemgr_read(file, 2, buf);
	filemgr_read(file, 3, buf);

	filemgr_read(file, 7, buf);
	filemgr_read(file, 1, buf);
	filemgr_read(file, 9, buf);

	filemgr_alloc(file);
	filemgr_write(file, 10, buf);

	TEST_RESULT("basic test");
}

void basic_test2()
{
	TEST_INIT();

	struct filemgr *file;
	struct filemgr_config config;
	bid_t bid;
	int i, j;
	uint8_t buf[4096];

	config.blocksize = 4096;
	config.ncacheblock = 5;
	file = filemgr_open("./dummy", get_linux_filemgr_ops(), config);

	for (i=0;i<5;++i) {
		filemgr_alloc(file);
		filemgr_write(file, i, buf);
	}
	for (i=5;i<10;++i) {
		filemgr_alloc(file);
		filemgr_write(file, i, buf);
	}
	filemgr_commit(file);

	TEST_RESULT("basic test");

}

int main()
{
	int r;
	r = system("rm -rf ./dummy");
	basic_test2();

	return 0;
}
