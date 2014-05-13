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
#include <fcntl.h>
#include <time.h>
#if !defined(WIN32) && !defined(_WIN32)
#include <sys/time.h>
#endif

#include "libforestdb/forestdb.h"
#include "filemgr.h"
#include "list.h"
#include "hbtrie.h"
#include "btree.h"
#include "btree_var_kv_ops.h"
#include "docio.h"
#include "btreeblock.h"
#include "common.h"
#include "wal.h"
#include "snapshot.h"
#include "filemgr_ops.h"
#include "crc32.h"
#include "configuration.h"
#include "internal_types.h"
#include "compactor.h"
#include "iniparser.h"
#include "memleak.h"

#ifdef __DEBUG
#ifndef __DEBUG_FDB
    #undef DBG
    #undef DBGCMD
    #undef DBGSW
    #define DBG(...)
    #define DBGCMD(...)
    #define DBGSW(n, ...)
#endif
#endif

void print_header(fdb_handle *db)
{
    uint8_t header_buf[FDB_BLOCKSIZE];
    uint64_t ndocs;
    uint64_t ndocs_wal_inserted, ndocs_wal_deleted;
    uint64_t nlivenodes;
    uint64_t datasize;
    uint64_t datasize_wal;
    uint64_t last_header_bid;
    size_t header_len;
    char *compacted_filename = NULL;
    char *prev_filename = NULL;
    bid_t trie_root_bid;
    bid_t seq_root_bid;
    fdb_seqnum_t seqnum;
    filemgr_header_revnum_t revnum;

    printf("DB header info:\n");

    filemgr_fetch_header(db->file, header_buf, &header_len);
    if (header_len > 0) {
        _fdb_fetch_header(header_buf, &trie_root_bid,
                          &seq_root_bid, &ndocs, &nlivenodes,
                          &datasize, &last_header_bid,
                          &compacted_filename, &prev_filename);
        seqnum = filemgr_get_seqnum(db->file);
        revnum = filemgr_get_header_revnum(db->file);
        ndocs_wal_inserted = wal_get_size(db->file);
        ndocs_wal_deleted = wal_get_num_deletes(db->file);
        datasize_wal = wal_get_datasize(db->file);

        printf("    DB header length: %d bytes\n", (int)header_len);
        printf("    DB header revision number: %d\n", (int)revnum);
        printf("    HB+trie root BID: %"_F64" (0x%llx, byte offset: %"_F64")\n",
               trie_root_bid, trie_root_bid, trie_root_bid * FDB_BLOCKSIZE);
        printf("    Seq B+tree root BID: %"_F64" (0x%llx, byte offset: %"_F64")\n",
               seq_root_bid, seq_root_bid, seq_root_bid * FDB_BLOCKSIZE);
        printf("    # documents in the main index: %"_F64" / "
               "in WAL: %"_F64" (insert), %"_F64" (remove)\n",
               ndocs, ndocs_wal_inserted, ndocs_wal_deleted);
        printf("    # live index nodes: %"_F64" (%"_F64" bytes)\n",
               nlivenodes, nlivenodes * FDB_BLOCKSIZE);
        printf("    Total document size: %"_F64" bytes, (index: %"_F64" bytes, "
               "WAL: %"_F64" bytes)\n",
               datasize + datasize_wal, datasize, datasize_wal);
        printf("    DB header BID of the last WAL flush: %"_F64
               " (0x%llx, byte offset: %"_F64")\n",
               last_header_bid, last_header_bid, last_header_bid * FDB_BLOCKSIZE);
        printf("    Last sequence number: %"_F64"\n", seqnum);
        if (compacted_filename) {
            printf("    Next file after compaction: %s\n", compacted_filename);
        }
        if (prev_filename) {
            printf("    Previous file before compaction: %s\n", prev_filename);
            free(prev_filename);
        }

    } else {
        printf("    No header exists.\n");
    }
}

typedef enum  {
    SCAN_WAL_FIRST_INDEX_NEXT = 1,
    SCAN_BY_KEY = 2,
    SCAN_BY_SEQ = 3,
} scan_mode_t;

struct dump_option{
    int hex_align;
    bool print_body;
    bool print_meta;
    bool print_key_in_hex;
    bool print_meta_in_hex;
    bool print_body_in_hex;
    scan_mode_t scan_mode;
};

INLINE void print_buf(fdb_handle *db, void *buf, size_t buflen, bool hex, int align)
{
    if (buf) {
        if (!hex) {
            // plaintext
            printf("%.*s\n", (int)buflen, buf);
        } else {
            // hex dump
            int i, j;
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
                    printf("%c", (0x20 <= ((char*)buf)[j] && ((char*)buf)[j] <= 0x7d)?
                                     ((char*)buf)[j] : '.'  );
                }
                printf("\n");
            }
        }
    } else {
        printf("(null)\n");
    }
}

void print_doc(fdb_handle *db,
               uint64_t offset,
               struct dump_option *opt,
               uint8_t is_wal_entry)
{
    uint64_t _offset;
    struct docio_object doc;

    memset(&doc, 0, sizeof(struct docio_object));

    _offset = docio_read_doc(db->dhandle, offset, &doc);
    if (_offset == offset) {
        return;
    }

    printf("Doc ID: ");
    print_buf(db, doc.key, doc.length.keylen,
              opt->print_key_in_hex, opt->hex_align);
    if (db->config.seqtree_opt == FDB_SEQTREE_USE) {
        printf("    Sequence number: %"_F64"\n", doc.seqnum);
    }
    printf("    Byte offset: %"_F64"\n", offset);
    printf("    Indexed by %s\n", (is_wal_entry)?("WAL"):("the main index"));
    printf("    Length: %d (key), %d (metadata), %d (body)\n",
           doc.length.keylen, doc.length.metalen, doc.length.bodylen);
    if (doc.length.flag & DOCIO_COMPRESSED) {
        printf("    Compressed body size on disk: %d\n", doc.length.bodylen_ondisk);
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
    if (opt->print_meta) {
        printf("    Metadata: ");
        print_buf(db, doc.meta, doc.length.metalen,
                  opt->print_meta_in_hex, opt->hex_align);
    }
    if (opt->print_body) {
        printf("    Body: ");
        print_buf(db, doc.body, doc.length.bodylen,
                  opt->print_body_in_hex, opt->hex_align);
    }
    printf("\n");
}

void scan_docs(fdb_handle *db, struct dump_option *opt)
{
    uint8_t *keybuf = alca(uint8_t, FDB_MAX_KEYLEN);
    uint64_t offset;
    size_t keylen;
    hbtrie_result hr;
    fdb_iterator *fit;
    fdb_status fs;
    fdb_doc *fdoc;
    wal_result wr;
    struct list_elem *e;
    struct wal_item *witem;
    struct hbtrie_iterator it;

    if (opt->scan_mode == SCAN_WAL_FIRST_INDEX_NEXT) {
        // scan wal first
        e = list_begin(&db->file->wal->list);
        while(e) {
            witem = _get_entry(e, struct wal_item, list_elem);
            print_doc(db, witem->offset, opt, 1);
            e = list_next(e);
        }

        // scan hb+trie next
        hr = hbtrie_iterator_init(db->trie, &it, NULL, 0);
        while (hr == HBTRIE_RESULT_SUCCESS) {
            hr = hbtrie_next_value_only(&it, (void*)&offset);
            btreeblk_end(db->bhandle);
            if (hr == HBTRIE_RESULT_SUCCESS) {
                offset = _endian_decode(offset);
                print_doc(db, offset, opt, 0);
            }
        }
        hbtrie_iterator_free(&it);

    } else if (opt->scan_mode == SCAN_BY_KEY) {

        fs = fdb_iterator_init(db, &fit, NULL, 0, NULL, 0, 0x0);
        while (fs == FDB_RESULT_SUCCESS) {
            fs = fdb_iterator_next(fit, &fdoc);
            if (fs == FDB_RESULT_SUCCESS) {
                // retrieve WAL
                wr = wal_find(db->file, fdoc, &offset);
                print_doc(db, fdoc->offset, opt, (wr == WAL_RESULT_SUCCESS));
                fdb_doc_free(fdoc);
            }
        }
        fdb_iterator_close(fit);

    } else if (opt->scan_mode == SCAN_BY_SEQ) {

        fs = fdb_iterator_sequence_init(db, &fit, 0, -1, 0x0);
        while (fs == FDB_RESULT_SUCCESS) {
            fs = fdb_iterator_next(fit, &fdoc);
            if (fs == FDB_RESULT_SUCCESS) {
                // retrieve WAL
                wr = wal_find(db->file, fdoc, &offset);
                print_doc(db, fdoc->offset, opt, (wr == WAL_RESULT_SUCCESS));
                fdb_doc_free(fdoc);
            }
        }
        fdb_iterator_close(fit);

    }
}

void process_file(char *filename, struct dump_option *opt)
{
    fdb_handle *db;
    fdb_config config;
    fdb_status fs;

    config = fdb_get_default_config();
    config.buffercache_size = 0;
    config.flags = FDB_OPEN_FLAG_RDONLY;
    fs = fdb_open(&db, filename, &config);
    assert(fs == FDB_RESULT_SUCCESS);

    print_header(db);

    printf("\n");
    scan_docs(db, opt);

    fs = fdb_close(db);
    assert(fs == FDB_RESULT_SUCCESS);

    fdb_shutdown();
}

void get_option_from_ini(char *ini_file, struct dump_option *opt)
{
    char *str;
    static dictionary *cfg;

    // if the ini file doesn't exist, the default options will be configured
    if (ini_file) {
        cfg = iniparser_new(ini_file);
    } else {
        cfg = NULL;
    }

    str = iniparser_getstring(cfg, (char*)"doc:print_body", (char*)"y");
    opt->print_body = (str[0] == 'Y' || str[0] == 'y')?(true):(false);

    str = iniparser_getstring(cfg, (char*)"doc:print_meta", (char*)"y");
    opt->print_meta = (str[0] == 'Y' || str[0] == 'y')?(true):(false);

    str = iniparser_getstring(cfg, (char*)"doc:print_key_in_hex", (char*)"n");
    opt->print_key_in_hex = (str[0] == 'Y' || str[0] == 'y')?(true):(false);

    str = iniparser_getstring(cfg, (char*)"doc:print_meta_in_hex", (char*)"y");
    opt->print_meta_in_hex = (str[0] == 'Y' || str[0] == 'y')?(true):(false);

    str = iniparser_getstring(cfg, (char*)"doc:print_body_in_hex", (char*)"n");
    opt->print_body_in_hex = (str[0] == 'Y' || str[0] == 'y')?(true):(false);

    opt->hex_align = iniparser_getint(cfg, (char*)"hex:hex_align", 16);

    str = iniparser_getstring(cfg, (char*)"scan:scan_mode",
                              (char*)"wal_first_index_next");
    if (str[0] == 'w' || str[0] == 'W') {
        opt->scan_mode = SCAN_WAL_FIRST_INDEX_NEXT;
    } else if (str[0] == 'k' || str[0] == 'K') {
        opt->scan_mode = SCAN_BY_KEY;
    } else if (str[0] == 's' || str[0] == 'S') {
        opt->scan_mode = SCAN_BY_SEQ;
    }

}

struct parse_result{
    char *ini_file;
    char *dump_file;
};
struct parse_result parse_options(int argc, char **argv)
{
    // Unfortunately, we cannot use getopt generally
    // because Windows doesn't support it ..
    int i;
    struct parse_result ret;

    memset(&ret, 0, sizeof(struct parse_result));
    for (i=1; i<argc; ++i){
        if (argv[i][0] == '-') {
            switch (argv[i][1]) {
                case 'o':
                    if (argc > i+1) {
                        ret.ini_file = argv[++i];
                    }
                    break;
            }
        } else {
            if (ret.dump_file == NULL) {
                ret.dump_file = argv[i];
            }
        }
    }

    return ret;
}

void print_usage(void)
{
    printf("\nUsage: forestdb_dump [OPTION]... [filename]\n"
           "\nOptions:\n"
           "  -o INI_FILE      use INI_FILE as a configuration file\n"
           "\n"
          );
}

int main(int argc, char **argv)
{
    struct dump_option opt;
    struct parse_result parse;

    if (argc < 2) {
        print_usage();
        return 0;
    }
    parse = parse_options(argc, argv);

    get_option_from_ini(parse.ini_file, &opt);
    process_file(parse.dump_file, &opt);
    return 0;
}
