#pragma once

#include <stdint.h>
#include "time_utils.h"
#include <libforestdb/fdb_errors.h>

#ifdef __DEBUG
    #include <stdio.h>

    #define DBG(...) printf(__VA_ARGS__)
    #define DBGCMD(...) __VA_ARGS__
    #define DBGSW(n, ...) if (_dbg_is_sw_set(n)) {__VA_ARGS__; }
#else
    #define DBG(...)
    #define DBGCMD(...)
    #define DBGSW(n, ...)
#endif

void _dbg_sw_set(int n);
void _dbg_sw_clear(int n);
int _dbg_is_sw_set(int n);

void _dbg_set_addr(int n, void *addr);
void * _dbg_get_addr(int n);

void _dbg_set_uint64_t(int n, uint64_t val);
uint64_t _dbg_get_uint64_t(int n);

fdb_status _dbg_install_handler(void);
fdb_status _dbg_destroy_altstack(void);
fdb_status _dbg_handle_crashes(const char *pathname);

void dbg_print_buf(void *buf, uint64_t buflen, bool hex, int align);
