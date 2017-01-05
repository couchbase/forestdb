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

#include "dump_common.h"

void print_usage(void)
{
    printf("\nUsage: forestdb_dump [OPTION]... [filename]\n"
    "\nOptions:\n"
    "\n      --header-only         only print the header of a given ForestDB file"
    "\n      --key <key>           dump only specified document"
    "\n      --kvs <KV store name> name of KV store to be dumped"
    "\n      --byid                sort output by document id"
    "\n      --byseq               sort output by sequence number"
    "\n      --hex-key             convert document id to hex (for binary key)"
    "\n      --hex-body            convert document body data to hex (for binary data)"
    "\n      --hex-align           number of bytes of hex alignment (default 16)"
    "\n      --plain-meta          print meta data in plain text (default hex)"
    "\n      --no-body             do not retrieve document bodies"
    "\n      --no-meta             do not print meta data of documents"
    "\n");
}

typedef enum  {
    SCAN_BY_KEY = 1,
    SCAN_BY_SEQ = 2,
} scan_mode_t;

struct dump_option{
    char *dump_file;
    char *one_key;
    char *one_kvs;
    int hex_align;
    bool no_body;
    bool no_meta;
    bool print_key_in_hex;
    bool print_plain_meta;
    bool print_body_in_hex;
    bool print_header_only;
    scan_mode_t scan_mode;
};

INLINE void print_buf(fdb_kvs_handle *db, void *buf, size_t buflen, bool hex,
                      int align)
{
    if (buf) {
        if (!hex) {
            // plaintext
            printf("%.*s\n", (int)buflen, (char*)buf);
        } else {
            // hex dump
            size_t i, j;
            printf("(hex)\n");
            for (i=0;i<buflen;i+=align) {
                printf("        ");
                for (j=i; j<i+align; ++j){
                    if (j<buflen) {
                        printf("%02x ", ((uint8_t*)buf)[j]);
                    } else {
                        printf("   ");
                    }
                    if ((j+1)%8 == 0) {
                        printf(" ");
                    }
                }
                printf(" ");
                for (j=i; j<i+align && j<buflen; ++j){
                    // print only readable ascii character
                    printf("%c",
                     (0x20 <= ((char*)buf)[j] && ((char*)buf)[j] <= 0x7d)?
                               ((char*)buf)[j] : '.'  );
                }
                printf("\n");
            }
        }
    } else {
        printf("(null)\n");
    }
}

void print_doc(fdb_kvs_handle *db,
               char *kvs_name,
               uint64_t offset,
               struct dump_option *opt)
{
    uint8_t is_wal_entry;
    int64_t _offset;
    void *key;
    keylen_t keylen;
    fdb_status wr;
    fdb_doc fdoc;
    struct docio_object doc;
    struct _fdb_key_cmp_info cmp_info;

    memset(&doc, 0, sizeof(struct docio_object));

    _offset = db->dhandle->readDoc_Docio(offset, &doc, true);
    if (_offset <= 0) {
        return;
    }
    if (doc.length.flag & DOCIO_TXN_COMMITTED) {
        offset = doc.doc_offset;
        _offset = db->dhandle->readDoc_Docio(offset, &doc, true);
        if (_offset <= 0) {
            return;
        }
    }

    if (db->kvs) {
        key = (uint8_t*)doc.key + sizeof(fdb_kvs_id_t);
        keylen = doc.length.keylen - sizeof(fdb_kvs_id_t);
    } else {
        key = doc.key;
        keylen = doc.length.keylen;
    }

    printf("Doc ID: ");
    print_buf(db, key, keylen,
              opt->print_key_in_hex, opt->hex_align);
    if (kvs_name) {
        printf("    KV store name: %s\n", kvs_name);
    }
    if (doc.seqnum != SEQNUM_NOT_USED) {
        printf("    Sequence number: %" _F64 "\n", doc.seqnum);
    }
    printf("    Byte offset: %" _F64 "\n", offset);

    cmp_info.kvs_config = db->kvs_config;
    cmp_info.kvs = db->kvs;
    fdoc.key = doc.key;
    fdoc.keylen = doc.length.keylen;
    wr = db->file->getWal()->find_Wal(db->file->getGlobalTxn(), &cmp_info,
                                      db->shandle, &fdoc, &offset);
    is_wal_entry = (wr == FDB_RESULT_SUCCESS)?(1):(0);
    printf("    Indexed by %s\n", (is_wal_entry)?("WAL"):("the main index"));
    printf("    Length: %d (key), %d (metadata), %d (body)\n",
           keylen, doc.length.metalen, doc.length.bodylen);
    if (doc.length.flag & DOCIO_COMPRESSED) {
        printf("    Compressed body size on disk: %d\n",
               doc.length.bodylen_ondisk);
    }
    if (doc.length.flag & DOCIO_DELETED) {
        printf("    Status: deleted (timestamp: %u)\n", doc.timestamp);
    } else {
        if (doc.length.flag & DOCIO_COMPACT) {
            printf("    Status: normal (written during compaction)\n");
        } else {
            printf("    Status: normal\n");
        }
    }
    if (!opt->no_meta) {
        printf("    Metadata: ");
        print_buf(db, doc.meta, doc.length.metalen,
                  !opt->print_plain_meta, opt->hex_align);
    }
    if (!opt->no_body) {
        printf("    Body: ");
        print_buf(db, doc.body, doc.length.bodylen,
                  opt->print_body_in_hex, opt->hex_align);
    }
    printf("\n");

    free(doc.key);
    free(doc.meta);
    free(doc.body);
}

int scan_docs(fdb_kvs_handle *db, struct dump_option *opt, char *kvs_name)
{
    uint64_t offset;
    fdb_iterator *fit;
    fdb_status fs;
    fdb_doc *fdoc = NULL;

    if (opt->one_key) {
        fdb_doc_create(&fdoc, opt->one_key,
                       strnlen(opt->one_key,FDB_MAX_KEYLEN), NULL, 0, NULL, 0);
       fs = fdb_get(db, fdoc);
       if (fs == FDB_RESULT_SUCCESS) {
           offset = fdoc->offset;
           print_doc(db, kvs_name, offset, opt);
       } else { // MB-22046: Also need to be able to print deleted doc
           fs = fdb_get_metaonly(db, fdoc);
           if (fs == FDB_RESULT_SUCCESS) {
               offset = fdoc->offset;
               print_doc(db, kvs_name, offset, opt);
           } else {
               return -1;
           }
       }
       fdb_doc_free(fdoc);
       fdoc = NULL;
    } else if (opt->scan_mode == SCAN_BY_KEY) {
        fs = fdb_iterator_init(db, &fit, NULL, 0, NULL, 0, 0x0);
        if (fs != FDB_RESULT_SUCCESS) {
            return -2;
        }
        do {
            if (fdb_iterator_get(fit, &fdoc) == FDB_RESULT_SUCCESS) {
                offset = fdoc->offset;
                print_doc(db, kvs_name, offset, opt);
                fdb_doc_free(fdoc);
                fdoc = NULL;
            }
        } while(fdb_iterator_next(fit) == FDB_RESULT_SUCCESS);
        fdb_iterator_close(fit);
    } else if (opt->scan_mode == SCAN_BY_SEQ) {
        fs = fdb_iterator_sequence_init(db, &fit, 0, -1, 0x0);
        if (fs != FDB_RESULT_SUCCESS) {
            return -2;
        }
        do {
            if (fdb_iterator_get(fit, &fdoc) == FDB_RESULT_SUCCESS) {
                offset = fdoc->offset;
                print_doc(db, kvs_name, offset, opt);
                fdb_doc_free(fdoc);
                fdoc = NULL;
            }
        } while(fdb_iterator_next(fit) == FDB_RESULT_SUCCESS);
        fdb_iterator_close(fit);
    }

    return 0;
}

int process_file(struct dump_option *opt)
{
    int i, ret;
    fdb_file_handle *dbfile;
    fdb_kvs_handle *db;
    fdb_config config;
    fdb_kvs_config kvs_config;
    fdb_kvs_name_list name_list;
    fdb_status fs;
    char *filename = opt->dump_file;

    config = fdb_get_default_config();
    config.buffercache_size = 0;
    config.flags = FDB_OPEN_FLAG_RDONLY;
    fs = fdb_open(&dbfile, filename, &config);
    if (fs != FDB_RESULT_SUCCESS) {
        printf("\nUnable to open %s\n", filename);
        return -3;
    }
    if (!opt->one_key && !opt->one_kvs) {
        // MB-22046: Avoid dumping header for specific kvs or specific key dump
        print_header(dbfile->getRootHandle());
        if (opt->print_header_only) {
            return 0;
        }
    }

    kvs_config = fdb_get_default_kvs_config();

    if (dbfile->getRootHandle()->config.multi_kv_instances) {
        fdb_get_kvs_name_list(dbfile, &name_list);
        for (i=0; (uint64_t)i<name_list.num_kvs_names; ++i) {
            if (opt->one_kvs &&
                strcmp(opt->one_kvs, name_list.kvs_names[i])) {
                continue;
            }

            fs = fdb_kvs_open(dbfile, &db, name_list.kvs_names[i], &kvs_config);
            if (fs != FDB_RESULT_SUCCESS) {
                printf("\nUnable to open KV store %s\n", name_list.kvs_names[i]);
                continue;
            }
            if (db->kvs_config.custom_cmp) {
                printf("\nUnable to dump KV store %s due to "
                       "customized comparison function\n", name_list.kvs_names[i]);
                fdb_kvs_close(db);
                continue;
            }

            ret = scan_docs(db, opt, name_list.kvs_names[i]);
            if (ret == -1 && opt->one_kvs) {
                // Only print key not found if a specific key is accompanied by
                // a specific kv store.
                // Otherwise scan all kv stores for the same key..
                printf("KV store '%s': key not found\n", name_list.kvs_names[i]);
            }
            fdb_kvs_close(db);
        }

        fdb_free_kvs_name_list(&name_list);
    } else {
        fs = fdb_kvs_open(dbfile, &db, NULL, &kvs_config);
        if (fs != FDB_RESULT_SUCCESS) {
            printf("\nUnable to open KV store\n");
            return -3;
        }

        printf("\n");
        ret = scan_docs(db, opt, NULL);
        if (ret == -1) {
            printf("Key not found\n");
        }
        fdb_kvs_close(db);
    }

    fs = fdb_close(dbfile);
    if (fs != FDB_RESULT_SUCCESS) {
        printf("\nUnable to close %s\n", filename);
        return -4;
    }

    fdb_shutdown();
    return 0;
}

int parse_options(int argc, char **argv, struct dump_option *opt)
{
    // Unfortunately, we cannot use getopt generally
    // because Windows doesn't support it ..
    int i = 1;

    if (argc < 2) {
        print_usage();
        return -1;
    }

    // load default options ...
    memset(opt, 0, sizeof(struct dump_option));
    opt->hex_align = 16;
    opt->scan_mode = SCAN_BY_KEY;

    for (i = 1; i < argc; ++i) {
        if (argv[i][0] == '-' && argv[i][1] == '-') {
            if (strncmp(argv[i], "--key", 16) == 0) {
                opt->one_key = argv[++i];
            } else if (strncmp(argv[i], "--kvs", 16) == 0) {
                opt->one_kvs = argv[++i];
            } else if (strncmp(argv[i], "--no-body", 16) == 0) {
                opt->no_body = true;
            } else if (strncmp(argv[i], "--no-meta", 16) == 0) {
                opt->no_meta = true;
            } else if (strncmp(argv[i], "--hex-key", 16) == 0) {
                opt->print_key_in_hex = true;
            } else if (strncmp(argv[i], "--plain-meta", 16) == 0) {
                opt->print_plain_meta = true;
            } else if (strncmp(argv[i], "--hex-body", 16) == 0) {
                opt->print_body_in_hex = true;
            } else if (strncmp(argv[i], "--hex-align", 16) == 0) {
                opt->hex_align = atoi(argv[++i]);
            } else if (strncmp(argv[i], "--byid", 16) == 0) {
                opt->scan_mode = SCAN_BY_KEY;
            } else if (strncmp(argv[i], "--byseq", 16) == 0) {
                opt->scan_mode = SCAN_BY_SEQ;
            } else if (strncmp(argv[i], "--header-only", 13) == 0) {
                opt->print_header_only = true;
            } else {
                printf("\nUnknown option %s\n", argv[i]);
                print_usage();
                return -2;
            }
        } else {
            opt->dump_file = argv[i];
        }
    }

    return 0;
}

int main(int argc, char **argv)
{
    memleak_start();

    struct dump_option opt;
    int ret = parse_options(argc, argv, &opt);

    if (ret) {
        memleak_end();
        return ret;
    }

    ret = process_file(&opt);

    memleak_end();
    return ret;
}
