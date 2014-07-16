#ifndef _JSAHN_DEBUG_H
#define _JSAHN_DEBUG_H

#include <stdint.h>

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

#endif
