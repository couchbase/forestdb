/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2016 Couchbase, Inc
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 */

#include <strings.h>
#include <cstdio>

#if defined(WIN32)
#   include <Dbghelp.h>
# else
#   include <execinfo.h>    // for backtrace()
#   include <dlfcn.h>       // for dladdr()
#   include <stddef.h>      // for ptrdiff_t
#endif

#include "backtrace.h"

// Maximum number of frames that will be printed.
#define MAX_FRAMES 50

/**
 * Populates buf with a description of the given address in the program.
 **/
static void describe_address(char* msg, size_t len, void* addr) {
#if defined(WIN32)

    // Get module information
    IMAGEHLP_MODULE64 module_info;
    module_info.SizeOfStruct = sizeof(IMAGEHLP_MODULE64);
    SymGetModuleInfo64(GetCurrentProcess(), (DWORD64)addr, &module_info);

    // Get symbol information.
    DWORD64 displacement = 0;
    char buffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(TCHAR)];
    PSYMBOL_INFO sym_info = (PSYMBOL_INFO)buffer;
    sym_info->SizeOfStruct = sizeof(SYMBOL_INFO);
    sym_info->MaxNameLen = MAX_SYM_NAME;

    if (SymFromAddr(GetCurrentProcess(), (DWORD64)addr, &displacement,
                    sym_info)) {
        snprintf(msg, len, "%s(%s+%lld) [0x%p]",
                 module_info.ImageName ? module_info.ImageName : "",
                 sym_info->Name, displacement, addr);
    } else {
        // No symbol found.
        snprintf(msg, len, "[0x%p]", addr);
    }
#else // !WIN32
    Dl_info info;
    int status = dladdr(addr, &info);

    if (status != 0 &&
        info.dli_fname != NULL &&
        info.dli_fname[0] != '\0') {

        if (info.dli_saddr == 0) {
            // No offset calculation possible.
            snprintf(msg, len, "%s(%s) [%p]",
                    info.dli_fname,
                    info.dli_sname ? info.dli_sname : "",
                    addr);
        } else {
            char sign;
            ptrdiff_t offset;
            if (addr >= info.dli_saddr) {
                sign = '+';
                offset = (char*)addr - (char*)info.dli_saddr;
            } else {
                sign = '-';
                offset = (char*)info.dli_saddr - (char*)addr;
            }
            snprintf(msg, len, "%s(%s%c%#tx) [%p]",
                    info.dli_fname,
                    info.dli_sname ? info.dli_sname : "",
                    sign, offset, addr);
        }
    } else {
        // No symbol found.
        snprintf(msg, len, "[%p]", addr);
    }
#endif // WIN32
}

void print_backtrace(write_cb_t write_cb, void* context) {
    void* frames[MAX_FRAMES];
#if defined(WIN32)
    int active_frames = CaptureStackBackTrace(0, MAX_FRAMES, frames, NULL);
    SymInitialize(GetCurrentProcess(), NULL, TRUE);
#else
    int active_frames = backtrace(frames, MAX_FRAMES);
#endif

    // Note we start from 1 to skip our own frame.
    for (int ii = 1; ii < active_frames; ii++) {
        // Fixed-sized buffer; possible that description will be cropped.
        char msg[200];
        describe_address(msg, sizeof(msg), frames[ii]);
        write_cb(context, msg);
    }
    if (active_frames == MAX_FRAMES) {
        write_cb(context, "<frame limit reached, possible truncation>");
    }
}
