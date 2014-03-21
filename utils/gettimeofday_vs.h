#ifndef _JSAHN_GETTIMEOFDAY_VS
#define _JSAHN_GETTIMEOFDAY_VS

#include <time.h>
#include <Windows.h>

#ifdef __cplusplus
extern "C" {
#endif

struct timezone
{
    int  tz_minuteswest; /* minutes W of Greenwich */
    int  tz_dsttime;     /* type of dst correction */
};

int gettimeofday_vs(struct timeval *tv, struct timezone *tz);

#ifdef __cplusplus
}
#endif

#endif
