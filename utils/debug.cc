#include "debug.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

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

// Only if HANG_ON_CRASH is set in environment variable, hang process
static void _dbg_hang_process(void)
{
    char *hang_process = getenv("HANG_ON_CRASH");
    if (hang_process) {
        fprintf(stderr, "Hanging process...");
        fprintf(stderr, "\n");
        while (1) {
            usleep(1000);
        }
    }
}

// to profile first install perf
// echo 0 > /proc/sys/kernel/kptr_restrict
#if defined(__linux__) && !defined(__ANDROID__) && !defined(_DISABLE_SIGHANDLER)
#include <string.h>
#include <dlfcn.h>
#include <ucontext.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>

void sigalrm_handler(int sig) {
    fdb_assert(false, false, false);
}

static struct sigaction caller_sigact;
static stack_t __sigstack;
static void sigsegv_handler(int sig, siginfo_t *siginfo, void *context)
{
    ucontext *u = (ucontext *)context;
#ifdef REG_RIP // Test if the Program Counter is 64 bits
    unsigned char *pc = (unsigned char *)u->uc_mcontext.gregs[REG_RIP];
#else // 32 bit machine, PC is stored in %eip register
    unsigned char *pc = (unsigned char *)u->uc_mcontext.gregs[REG_EIP];
#endif // REG_RIP for 64-bit machines

    Dl_info info;
    if (dladdr(pc, &info)) { // Determine location of the segfault..
        if (strstr(info.dli_fname, "libforestdb")) {
            fprintf(stderr,
                    "Caught SIGSEGV in libforestdb at %s\n", info.dli_sname);
            // first restore original handler whatever it may be..
            // so that if BREAKPAD is not available we get a core dump..
            sigaction(SIGSEGV, &caller_sigact, NULL);
            _dbg_hang_process();
            initialize_breakpad(minidump_dir);
            return; // let breakpad dump backtrace and crash..
        }
    }
    // If not from forestdb, and caller has a signal handler, invoke it..
    if (caller_sigact.sa_sigaction && caller_sigact.sa_flags & SA_SIGINFO) {
        caller_sigact.sa_sigaction(sig, siginfo, context);
    } else if (caller_sigact.sa_sigaction) { // Not in forestdb and no handler from caller
        caller_sigact.sa_handler(sig);
    } else {
        // first restore original handler whatever it may be..
        // so that if BREAKPAD is not available we get a core dump..
        sigaction(SIGSEGV, &caller_sigact, NULL);
        _dbg_hang_process();
        initialize_breakpad(minidump_dir); // let breakpad handle it..
    }
}

INLINE fdb_status _dbg_init_altstack(void)
{
    __sigstack.ss_sp = malloc(SIGSTKSZ);
    __sigstack.ss_size = SIGSTKSZ;
    __sigstack.ss_flags = 0;
    return FDB_RESULT_SUCCESS;
}

fdb_status _dbg_install_handler(void)
{
    // -- install segmentation fault handler using sigaction ---
    struct sigaction sa;
    if (sigaltstack(&__sigstack, NULL) == -1) {
        fprintf(stderr, "SIGSEGV AltStack failed to register\n");
        return FDB_RESULT_INVALID_ARGS;
    }
    sigemptyset(&sa.sa_mask);
    sa.sa_sigaction = sigsegv_handler;
    sa.sa_flags = SA_RESTART | SA_ONSTACK | SA_SIGINFO;
    if (sigaction(SIGSEGV, &sa, &caller_sigact) == -1) {
        fprintf(stderr, "SIGSEGV handler failed to register\n");
        return FDB_RESULT_INVALID_ARGS;
    }
    return FDB_RESULT_SUCCESS;
}

fdb_status _dbg_destroy_altstack()
{
    if (__sigstack.ss_sp) {
        free(__sigstack.ss_sp);
        __sigstack.ss_sp = NULL;
    }
    return FDB_RESULT_SUCCESS;
}

# else
fdb_status _dbg_init_altstack() { return FDB_RESULT_SUCCESS; }
fdb_status _dbg_destroy_altstack() { return FDB_RESULT_SUCCESS; }
fdb_status _dbg_install_handler() { return FDB_RESULT_SUCCESS; }
#endif // #if defined(__linux__) && !defined(__ANDROID__)

fdb_status _dbg_handle_crashes(const char *pathname)
{
    if (pathname) {
        minidump_dir = pathname;
        _dbg_init_altstack(); // one time stack install
        return _dbg_install_handler();
    } else {
        return FDB_RESULT_SUCCESS;
    }
}

void fdb_assert_die(const char* expression, const char* file, int line,
                    uint64_t val, uint64_t expected) {
    fprintf(stderr, "assertion failed [%s] at %s:%u (%p != %p)\n",
            expression, file, line, (void*)val, (void*)expected);

    // Invoke the fatal error callback if registered.
    if (fatal_error_callback != nullptr) {
        fatal_error_callback();
    }

    _dbg_hang_process(); // Only if HANG_ON_CRASH is set in env

    // Initialize breakpad to create minidump for the
    // following abort
    initialize_breakpad(minidump_dir);

    fflush(stderr);

    abort();
}

void dbg_print_buf(void *buf, uint64_t buflen, bool hex, int align)
{
    if (buf) {
        if (!hex) {
            // plaintext
            fprintf(stderr, "%.*s\n", (int)buflen, (char*)buf);
        } else {
            // hex dump
            size_t i, j;
            fprintf(stderr, "(hex) 0x%" _X64 ", %" _F64 " (0x%" _X64 ") bytes\n",
                    (uint64_t)buf, buflen, buflen);
            for (i=0;i<buflen;i+=align) {
                fprintf(stderr, "   %04x   ", (int)i);
                for (j=i; j<i+align; ++j){
                    if (j<buflen) {
                        fprintf(stderr, "%02x ", ((uint8_t*)buf)[j]);
                    } else {
                        fprintf(stderr, "   ");
                    }
                    if ((j+1)%8 == 0) {
                        fprintf(stderr, " ");
                    }
                }
                fprintf(stderr, " ");
                for (j=i; j<i+align && j<buflen; ++j){
                    // print only readable ascii character
                    fprintf(stderr, "%c",
                     (0x20 <= ((char*)buf)[j] && ((char*)buf)[j] <= 0x7d)?
                               ((char*)buf)[j] : '.'  );
                }
                fprintf(stderr, "\n");
            }
        }
    } else {
        fprintf(stderr, "(null)\n");
    }
}

// LCOV_EXCL_STOP
