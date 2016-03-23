#include "debug.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "time_utils.h"

#include "backtrace.h"
#include "breakpad.h"
#include "fdb_internal.h"

#define N_DBG_SWITCH (256)

static uint8_t _global_dbg_switch[N_DBG_SWITCH];
static void* _global_dbg_addr[N_DBG_SWITCH];
static uint64_t _global_dbg_uint64_t[N_DBG_SWITCH];

fdb_fatal_error_callback fatal_error_callback = nullptr;

// minidump_dir used by breakpad
static const char* minidump_dir = nullptr;

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

void _dbg_set_minidump_dir(const char *pathname)
{
    minidump_dir = pathname;
}

static void write_callback(void *ctx, const char *frame) {
    fprintf(stderr, "\t%s\n", frame);
}

void fdb_assert_die(const char* expression, const char* file, int line,
                    uint64_t val, uint64_t expected) {
    fprintf(stderr, "assertion failed [%s] at %s:%u (%p != %p)\n",
            expression, file, line, (void*)val, (void*)expected);

    fprintf(stderr, "Called from:\n");
    print_backtrace(write_callback, nullptr);

    fflush(stderr);

    // Invoke the fatal error callback if registered.
    if (fatal_error_callback != nullptr) {
        fatal_error_callback();
    }

    char *hang_process = getenv("HANG_ON_ASSERTION");
    if (hang_process) {
        fprintf(stderr, "Hanging process...");
        fprintf(stderr, "\n");
        while (1) {
            usleep(1000);
        }
    }

    // Initialize breakpad to create minidump for the
    // following abort
    initialize_breakpad(minidump_dir);

    abort();
}

// LCOV_EXCL_STOP
