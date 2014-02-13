#ifndef _JSAHN_STOPWATCH_H
#define _JSAHN_STOPWATCH_H

#include <sys/time.h>

struct stopwatch {
    struct timeval elapsed;
    struct timeval start;
};

void stopwatch_init(struct stopwatch *sw);
void stopwatch_start(struct stopwatch *sw);
int stopwatch_check_ms(struct stopwatch *sw, size_t ms);
int stopwatch_check_us(struct stopwatch *sw, size_t us);
struct timeval stopwatch_stop(struct stopwatch *sw);

#endif
