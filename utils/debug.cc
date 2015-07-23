#include "debug.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "time_utils.h"
#if !defined(WIN32) && !defined(_WIN32)
#include <execinfo.h>
#endif // !defined(WIN32) && !defined(_WIN32)

#define N_DBG_SWITCH (256)

static uint8_t _global_dbg_switch[N_DBG_SWITCH];
static void* _global_dbg_addr[N_DBG_SWITCH];
static uint64_t _global_dbg_uint64_t[N_DBG_SWITCH];

// LCOV_EXCL_START
void _dbg_sw_set(int n)
{
    _global_dbg_switch[n] = 1;
}

void _dbg_sw_clear(int n)
{
    _global_dbg_switch[n] = 0;
}

void _dbg_set_addr(int n, void *addr)
{
    _global_dbg_addr[n] = addr;
}

void * _dbg_get_addr(int n)
{
    return _global_dbg_addr[n];
}

void _dbg_set_uint64_t(int n, uint64_t val)
{
    _global_dbg_uint64_t[n] = val;
}

uint64_t _dbg_get_uint64_t(int n)
{
    return _global_dbg_uint64_t[n];
}

int _dbg_is_sw_set(int n)
{
    return _global_dbg_switch[n];
}

void _dbg_assert(int line, const char *file, uint64_t val, uint64_t expected) {
    char *hang_process;
     fprintf(stderr, "Assertion in %p != %p in %s:%d\n",
            (void *)val, (void *)expected, file, line);

#if !defined(WIN32) && !defined(_WIN32)
     void *callstack[10];
     char **backtrace_buf;
     int frames = backtrace(callstack, 10);
     backtrace_buf = backtrace_symbols(callstack, frames);
     if (backtrace_buf) {
         for (int i = 0; i < frames; ++i) {
             fprintf(stderr, "%d : %s\n", i, backtrace_buf[i]);
         } // (no need to free memory as process is crashing)
     }
#endif // !defined(WIN32) && !defined(_WIN32)
     hang_process = getenv("HANG_ON_ASSERTION");
     if (hang_process) {
         fprintf(stderr, "Hanging process...");
         fprintf(stderr, "\n");
         while (1) {
             usleep(1000);
         }
     }
}
// LCOV_EXCL_STOP

