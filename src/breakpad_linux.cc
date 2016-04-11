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

#include "client/linux/handler/exception_handler.h"

#include <stdio.h>
#include <stdlib.h>

using namespace google_breakpad;
static ExceptionHandler* handler = nullptr;

/* Called when an exception triggers a dump, outputs details to caller's logs */
static bool dumpCallback(const MinidumpDescriptor& descriptor,
                         void* context, bool succeeded) {
    fprintf(stderr, "Breakpad caught a crash in forestdb. Writing crash dump "
            "to %s before terminating.\n", descriptor.path());

    return succeeded;
}

static void create_breakpad(const char* minidump_dir) {
    MinidumpDescriptor descriptor(minidump_dir);
    handler = new ExceptionHandler(descriptor,
                                   /*filter*/nullptr,
                                   dumpCallback,
                                   /*callback-context*/nullptr,
                                   /*install_handler*/true,
                                   /*server_fd*/-1);
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
