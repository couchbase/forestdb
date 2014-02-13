#ifndef _JSAHN_DEBUG_H
#define _JSAHN_DEBUG_H

#ifdef __DEBUG
    #include <stdio.h>

    #define DBG(args...) fprintf(stderr, args)
    #define DBGCMD(command...) command
    #define DBGSW(n, args...) if (_dbg_is_sw_set(n)) {args; }
#else
    #define DBG(args...)
    #define DBGCMD(command...)
    #define DBGSW(n, args...)
#endif

void _dbg_sw_set(int n);
void _dbg_sw_clear(int n);
int _dbg_is_sw_set(int n);

void _dbg_set_addr(int n, void *addr);
void * _dbg_get_addr(int n);

void _dbg_set_uint64_t(int n, uint64_t val);
uint64_t _dbg_get_uint64_t(int n);

#endif
