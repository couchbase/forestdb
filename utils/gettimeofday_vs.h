#pragma once

#define NOMINMAX 1
#include <winsock2.h>
#undef NOMINMAX
#include <time.h>
#include <Windows.h>

struct timezone
{
    int  tz_minuteswest; /* minutes W of Greenwich */
    int  tz_dsttime;     /* type of dst correction */
};

int gettimeofday_vs(struct timeval *tv, void *tz);

