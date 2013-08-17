#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include "docio.h"
#include "filemgr.h"
#include "filemgr_ops_linux.h"
#include "test.h"

uint32_t _set_doc(struct docio_object *doc, char *key, char *meta, char *body)
{
    strcpy(doc->key, key);
    doc->length.keylen = strlen(doc->key) + 1;
    strcpy(doc->meta, meta);
    doc->length.metalen = strlen(doc->meta) + 1;
    strcpy(doc->body, body);
    doc->length.bodylen = strlen(doc->body) + 1;

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

    doc.key = keybuf;
    doc.meta = metabuf;
    doc.body = bodybuf;

    config.blocksize = blocksize;
    config.ncacheblock = 1024;
    r = system("rm -rf ./dummy");
    file = filemgr_open("./dummy", get_linux_filemgr_ops(), config);
    docio_init(&handle, file);

    docsize = _set_doc(&doc, "this_is_key", "this_is_metadata", "this_is_body_lawiefjaawleif");    
    offset = docio_append_doc(&handle, &doc);
    DBG("docsize %d written at %"_F64"\n", docsize, offset);

    docsize = _set_doc(&doc, "this_is_key2", "this_is_metadata2", "hello_world");    
    offset = docio_append_doc(&handle, &doc);
    DBG("docsize %d written at %"_F64"\n", docsize, offset);

    docsize = _set_doc(&doc, "key3", "a", "b");    
    offset = docio_append_doc(&handle, &doc);
    DBG("docsize %d written at %"_F64"\n", docsize, offset);

    docsize = _set_doc(&doc, "key4", "a", "b");    
    offset = docio_append_doc(&handle, &doc);
    DBG("docsize %d written at %"_F64"\n", docsize, offset);

    docsize = _set_doc(&doc, "key5", "a", "b");    
    offset = docio_append_doc(&handle, &doc);
    DBG("docsize %d written at %"_F64"\n", docsize, offset);

    doc.length.keylen = 1;
    doc.length.metalen = 1;
    doc.length.bodylen = 190;
    docsize = 12 + 182;
    offset = docio_append_doc(&handle, &doc);
    DBG("docsize %d written at %"_F64"\n", docsize, offset);

    keylen_t keylen;
    docio_read_doc_key(&handle, 69, &keylen, keybuf);
    DBG("keylen %d %s\n", keylen, keybuf);

    filemgr_commit(file);
    filemgr_close(file);

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
