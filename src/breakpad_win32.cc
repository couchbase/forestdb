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

#include "breakpad.h"

#include "client/windows/handler/exception_handler.h"

#include <stdio.h>
#include <stdlib.h>

using namespace google_breakpad;
static ExceptionHandler* handler = nullptr;

/* Called when an exception triggers a dump, outputs details to caller's logs */
static bool dumpCallback(const wchar_t* dump_path, const wchar_t* minidump_id,
                         void* context, EXCEPTION_POINTERS* exinfo,
                         MDRawAssertionInfo* assertion, bool succeeded) {
    fprintf(stderr, "Breakpad caught a crash in forestdb. Writing crash dump "
            "to %S\\%S before terminating.\n", dump_path, minidump_id);

    return succeeded;
}

static void create_breakpad(const char* minidump_dir) {
    // Takes a wchar_t* on Windows.
    size_t len = strlen(minidump_dir) + 1;
    wchar_t* wc_minidump_dir = new wchar_t[len];
    size_t wlen = 0;
    mbstowcs_s(&wlen, wc_minidump_dir, len, minidump_dir, _TRUNCATE);

    handler = new ExceptionHandler(wc_minidump_dir,
                                   /*filter*/nullptr,
                                   dumpCallback,
                                   /*callback-context*/NULL,
                                   ExceptionHandler::HANDLER_ALL,
                                   MiniDumpNormal,
                                   /*pipe*/(wchar_t*) nullptr,
                                   /*custom_info*/nullptr);

    delete[] wc_minidump_dir;
}

void initialize_breakpad(const char* minidump_dir) {
    // We cannot actually change any of breakpad's setings once created, only
    // remove it and re-create with new settings.
    destroy_breakpad();

    if (minidump_dir != nullptr && minidump_dir[0] != '\0') {
        create_breakpad(minidump_dir);
    }
}

void destroy_breakpad(void) {
    delete handler;
    handler = nullptr;
}
