#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "test.h"
#include "crc32.h"

int main()
{
    TEST_INIT();

    size_t len = 1024*1024*1024 + 7;
    void *dummy;
    size_t i;
    uint32_t r1, r2;

    dummy = (void *)malloc(len);
    for (i=0;i<len/sizeof(size_t); i+=sizeof(size_t)) {
        memcpy(dummy+i, &i, sizeof(size_t));
    }

    TEST_TIME();

    r1 = crc32_8(dummy, len, 0);

    TEST_TIME();

    r2 = crc32_1(dummy, len, 0);

    TEST_TIME();

    DBG("crc value: %u %u\n", r1, r2);

    free(dummy);

    TEST_RESULT("crc32 slicing-8 test");
    return 0;
}
