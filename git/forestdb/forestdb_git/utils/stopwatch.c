#include <stdlib.h>

#include "stopwatch.h"

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

void stopwatch_init(struct stopwatch *sw)
{
    sw->elapsed.tv_sec = 0;
    sw->elapsed.tv_usec = 0;
}

void stopwatch_start(struct stopwatch *sw)
{
    gettimeofday(&sw->start, NULL);
}

int stopwatch_check_ms(struct stopwatch *sw, size_t ms)
{
    struct timeval cur, gap;
    gettimeofday(&cur, NULL);
    gap = _utime_gap(sw->start, cur);
    if (gap.tv_sec * 1000 + gap.tv_usec / 1000 >= ms) {
        return 1;
    }
    return 0;
}

int stopwatch_check_us(struct stopwatch *sw, size_t us)
{
    struct timeval cur, gap;
    gettimeofday(&cur, NULL);
    gap = _utime_gap(sw->start, cur);
    if (gap.tv_sec * 1000000 + gap.tv_usec >= us) {
        return 1;
    }
    return 0;
}

struct timeval stopwatch_stop(struct stopwatch *sw)
{
    struct timeval end, gap;
    gettimeofday(&end, NULL);
    gap = _utime_gap(sw->start, end);
    sw->elapsed.tv_sec += gap.tv_sec;
    sw->elapsed.tv_usec += gap.tv_usec;
    if (sw->elapsed.tv_usec >= 1000000) {
        sw->elapsed.tv_usec -= 1000000;
        sw->elapsed.tv_sec++;
    }

    return gap;
}
