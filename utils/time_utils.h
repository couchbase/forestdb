#ifndef _JSAHN_TIME_UTILS_H
#define _JSAHN_TIME_UTILS_H

#include <time.h>
#include <sys/time.h>

static struct timespec _ntime_gap(struct timespec a, struct timespec b) 
{
    struct timespec ret;
    if (b.tv_nsec >= a.tv_nsec) {
        ret.tv_nsec = b.tv_nsec - a.tv_nsec;
        ret.tv_sec = b.tv_sec - a.tv_sec;
    }else{
        ret.tv_nsec = 1000000000 + b.tv_nsec - a.tv_nsec;
        ret.tv_sec = b.tv_sec - a.tv_sec - 1;
    }
    return ret;
}

static struct timeval _utime_gap(struct timeval a, struct timeval b) 
{
    struct timeval ret;
    if (b.tv_usec >= a.tv_usec) {
        ret.tv_usec = b.tv_usec - a.tv_usec;
        ret.tv_sec = b.tv_sec - a.tv_sec;
    }else{
        ret.tv_usec = 1000000 + b.tv_usec - a.tv_usec;
        ret.tv_sec = b.tv_sec - a.tv_sec - 1;
    }
    return ret;
}

#endif
