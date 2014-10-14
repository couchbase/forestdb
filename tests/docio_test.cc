/* -*- Mode: C++; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2010 Couchbase, Inc
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "docio.h"
#include "filemgr.h"
#include "filemgr_ops.h"
#include "test.h"

uint32_t _set_doc(struct docio_object *doc, char *key, char *meta, char *body)
{
    strcpy((char*)doc->key, key);
    doc->length.keylen = strlen((char*)doc->key) + 1;
    strcpy((char*)doc->meta, meta);
    doc->length.metalen = strlen((char*)doc->meta) + 1;
    strcpy((char*)doc->body, body);
    doc->length.bodylen = strlen((char*)doc->body) + 1;

    return sizeof(struct docio_length) + doc->length.keylen + doc->length.metalen + doc->length.bodylen;
}

void basic_test()
{
    TEST_INIT();

    uint64_t offset;
    uint32_t docsize;
    int r;
    int blocksize = 128;
    struct docio_handle handle;
    struct filemgr *file;
    char keybuf[1024];
    char metabuf[1024];
    char bodybuf[4096];
    struct docio_object doc;
    struct filemgr_config config;
    char *fname = (char *) "./dummy";

    handle.log_callback = NULL;

    doc.key = (void*)keybuf;
    doc.meta = (void*)metabuf;
    doc.body = (void*)bodybuf;

    memset(&config, 0, sizeof(config));
    config.blocksize = blocksize;
    config.ncacheblock = 1024;
    config.options = FILEMGR_CREATE;
    r = system(SHELL_DEL " dummy");
    filemgr_open_result result = filemgr_open(fname, get_filemgr_ops(), &config, NULL);
    file = result.file;
    docio_init(&handle, file, false);

    docsize = _set_doc(&doc, (char *) "this_is_key", (char *) "this_is_metadata",
                       (char *) "this_is_body_lawiefjaawleif");
    offset = docio_append_doc(&handle, &doc, 0, 0);
    DBG("docsize %d written at %" _F64 "\n", docsize, offset);

    docsize = _set_doc(&doc, (char *) "this_is_key2", (char *) "this_is_metadata2",
                       (char *) "hello_world");
    offset = docio_append_doc(&handle, &doc, 0, 0);
    DBG("docsize %d written at %" _F64 "\n", docsize, offset);

    docsize = _set_doc(&doc, (char *) "key3", (char *) "a", (char *) "b");
    offset = docio_append_doc(&handle, &doc, 0, 0);
    DBG("docsize %d written at %" _F64 "\n", docsize, offset);

    docsize = _set_doc(&doc, (char *) "key4", (char *) "a", (char *) "b");
    offset = docio_append_doc(&handle, &doc, 0, 0);
    DBG("docsize %d written at %" _F64 "\n", docsize, offset);

    docsize = _set_doc(&doc, (char *) "key5", (char *) "a", (char *) "b");
    offset = docio_append_doc(&handle, &doc, 0, 0);
    DBG("docsize %d written at %" _F64 "\n", docsize, offset);

    doc.length.keylen = 1;
    doc.length.metalen = 1;
    doc.length.bodylen = 190;
    docsize = 12 + 182;
    offset = docio_append_doc(&handle, &doc, 0, 0);
    DBG("docsize %d written at %" _F64 "\n", docsize, offset);

    keylen_t keylen;
    docio_read_doc_key(&handle, 81, &keylen, (void*)keybuf);
    DBG("keylen %d %s\n", keylen, keybuf);

    filemgr_commit(file, NULL);
    filemgr_close(file, true, NULL, NULL);

    TEST_RESULT("basic test");
}

int main()
{
    #ifdef _MEMPOOL
        mempool_init();
    #endif


    basic_test();

    return 0;
}
