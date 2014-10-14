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
#include "fdb_internal.h"
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
#include "configuration.h"
#include "internal_types.h"
#include "compactor.h"
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

void print_usage(void)
{
    printf("\nUsage: forestdb_dump [OPTION]... [filename]\n"
    "\nOptions:\n"
    "\n      --key <key>  dump only specified document"
    "\n      --byid       sort output by document id"
    "\n      --byseq      sort output by sequence number"
    "\n      --hex-key    convert document id to hex (for binary key)"
    "\n      --hex-body   convert document body data to hex (for binary data)"
    "\n      --hex-align  number of bytes of hex alignment (default 16)"
    "\n      --plain-meta print meta data in plain text (default hex)"
    "\n      --no-body    do not retrieve document bodies"
    "\n      --no-meta    do not print meta data of documents"
    "\n");
}

INLINE int is_subblock(bid_t subbid)
{
    uint8_t flag;
    flag = (subbid >> (8 * (sizeof(bid_t)-2))) & 0x00ff;
    return flag;
}

INLINE void subbid2bid(bid_t subbid, size_t *subblock_no, size_t *idx, bid_t *bid)
{
    uint8_t flag;
    flag = (subbid >> (8 * (sizeof(bid_t)-2))) & 0x00ff;
    *subblock_no = flag >> 5;
    // to distinguish subblock_no==0 to non-subblock
    *subblock_no -= 1;
    *idx = flag & (0x20 - 0x01);
    *bid = ((bid_t)(subbid << 16)) >> 16;
}

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
    size_t subblock_no, idx;
    char *compacted_filename = NULL;
    char *prev_filename = NULL;
    bid_t bid;
    bid_t trie_root_bid;
    bid_t seq_root_bid;
    fdb_seqnum_t seqnum;
    filemgr_header_revnum_t revnum;

    printf("DB header info:\n");

    filemgr_fetch_header(db->file, header_buf, &header_len);
    if (header_len > 0) {
        fdb_fetch_header(header_buf, &trie_root_bid,
                         &seq_root_bid, &ndocs, &nlivenodes,
                         &datasize, &last_header_bid,
                         &compacted_filename, &prev_filename);
        seqnum = filemgr_get_seqnum(db->file);
        revnum = filemgr_get_header_revnum(db->file);
        ndocs_wal_inserted = wal_get_size(db->file);
        ndocs_wal_deleted = wal_get_num_deletes(db->file);
        datasize_wal = wal_get_datasize(db->file);

        bid = filemgr_get_header_bid(db->file);
        printf("    BID: %" _F64 " (0x%" _X64 ", byte offset: %" _F64 ")\n",
               bid, bid, bid * FDB_BLOCKSIZE);
        printf("    DB header length: %d bytes\n", (int)header_len);
        printf("    DB header revision number: %d\n", (int)revnum);

        if (trie_root_bid != BLK_NOT_FOUND) {
            if (!is_subblock(trie_root_bid)) {
                // normal block
                printf("    HB+trie root BID: %" _F64 " (0x%" _X64 ", byte offset: %" _F64 ")\n",
                       trie_root_bid, trie_root_bid, trie_root_bid * FDB_BLOCKSIZE);
            } else {
                // sub-block
                subbid2bid(trie_root_bid, &subblock_no, &idx, &bid);
                printf("    HB+trie root BID: %" _F64 ", %d-byte subblock #%zu",
                       bid, db->bhandle->sb[subblock_no].sb_size, idx);
                printf(" (0x%" _X64 ", byte offset: %" _F64 ")\n", trie_root_bid,
                       bid * FDB_BLOCKSIZE + db->bhandle->sb[subblock_no].sb_size * idx);
            }
        } else {
            printf("    HB+trie root BID: not exist\n");
        }

        if (seq_root_bid != BLK_NOT_FOUND) {
            if (!is_subblock(seq_root_bid)) {
                // normal block
                printf("    Seq B+tree root BID: %" _F64 " (0x%" _X64 ", byte offset: %" _F64 ")\n",
                       seq_root_bid, seq_root_bid, seq_root_bid * FDB_BLOCKSIZE);
            } else {
                // sub-block
                subbid2bid(seq_root_bid, &subblock_no, &idx, &bid);
                printf("    Seq B+tree root BID: %" _F64 ", %d-byte subblock #%zu",
                       bid, db->bhandle->sb[subblock_no].sb_size, idx);
                printf(" (0x%" _X64 ", byte offset: %" _F64 ")\n", seq_root_bid,
                       bid * FDB_BLOCKSIZE + db->bhandle->sb[subblock_no].sb_size * idx);
            }
        } else {
            printf("    Seq B+tree root BID: not exist\n");
        }

        printf("    # documents in the main index: %" _F64 " / "
               "in WAL: %" _F64 " (insert), %" _F64 " (remove)\n",
               ndocs, ndocs_wal_inserted, ndocs_wal_deleted);
        printf("    # live index nodes: %" _F64 " (%" _F64 " bytes)\n",
               nlivenodes, nlivenodes * FDB_BLOCKSIZE);
        printf("    Total document size: %" _F64 " bytes, (index: %" _F64 " bytes, "
               "WAL: %" _F64 " bytes)\n",
               datasize + datasize_wal, datasize, datasize_wal);

        if (last_header_bid != BLK_NOT_FOUND) {
            printf("    DB header BID of the last WAL flush: %" _F64 
                   " (0x%" _X64 ", byte offset: %" _F64 ")\n",
                   last_header_bid, last_header_bid, last_header_bid * FDB_BLOCKSIZE);
        } else {
            printf("    DB header BID of the last WAL flush: not exist\n");
        }

        printf("    Last sequence number: %" _F64 "\n", seqnum);
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
    SCAN_BY_KEY = 1,
    SCAN_BY_SEQ = 2,
} scan_mode_t;

struct dump_option{
    char *dump_file;
    char *one_key;
    int hex_align;
    bool no_body;
    bool no_meta;
    bool print_key_in_hex;
    bool print_plain_meta;
    bool print_body_in_hex;
    scan_mode_t scan_mode;
};

INLINE void print_buf(fdb_handle *db, void *buf, size_t buflen, bool hex,
                      int align)
{
    if (buf) {
        if (!hex) {
            // plaintext
            printf("%.*s\n", (int)buflen, (char*)buf);
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

void print_doc(fdb_handle *db,
               uint64_t offset,
               struct dump_option *opt,
               uint8_t is_wal_entry)
{
    uint64_t _offset;
    struct docio_object doc;

    memset(&doc, 0, sizeof(struct docio_object));

start:
    _offset = docio_read_doc(db->dhandle, offset, &doc);
    if (_offset == offset) {
        return;
    }
    if (doc.length.flag & DOCIO_TXN_COMMITTED) {
        offset = doc.doc_offset;
        _offset = docio_read_doc(db->dhandle, offset, &doc);
        if (_offset == offset) {
            return;
        }
    }

    printf("Doc ID: ");
    print_buf(db, doc.key, doc.length.keylen,
              opt->print_key_in_hex, opt->hex_align);
    if (db->config.seqtree_opt == FDB_SEQTREE_USE) {
        printf("    Sequence number: %" _F64 "\n", doc.seqnum);
    }
    printf("    Byte offset: %" _F64 "\n", offset);
    printf("    Indexed by %s\n", (is_wal_entry)?("WAL"):("the main index"));
    printf("    Length: %d (key), %d (metadata), %d (body)\n",
           doc.length.keylen, doc.length.metalen, doc.length.bodylen);
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
    struct list_elem *e, *ee;
    struct wal_item_header *witem_header;
    struct wal_item *witem;
    struct hbtrie_iterator it;

    if (opt->one_key) {
        fdb_doc_create(&fdoc, opt->one_key,
                       strnlen(opt->one_key,FDB_MAX_KEYLEN), NULL, 0, NULL, 0);
       fs = fdb_get(db, fdoc);
       if (fs == FDB_RESULT_SUCCESS) {
           offset = fdoc->offset;
           wr = wal_find(&db->file->global_txn, db->file, fdoc, &offset);
           print_doc(db, offset, opt, (wr == WAL_RESULT_SUCCESS));
       } else {
           printf("Key not found\n");
       }
       fdb_doc_free(fdoc);
    } else if (opt->scan_mode == SCAN_BY_KEY) {
        fs = fdb_iterator_init(db, &fit, NULL, 0, NULL, 0, 0x0);
        if (fs != FDB_RESULT_SUCCESS) {
            return;
        }
        while (fs == FDB_RESULT_SUCCESS) {
            fs = fdb_iterator_next(fit, &fdoc);
            if (fs == FDB_RESULT_SUCCESS) {
                offset = fdoc->offset;
                // retrieve WAL
                wr = wal_find(&db->file->global_txn, db->file, fdoc, &offset);
                print_doc(db, offset, opt, (wr == WAL_RESULT_SUCCESS));
                fdb_doc_free(fdoc);
            }
        }
        fdb_iterator_close(fit);
    } else if (opt->scan_mode == SCAN_BY_SEQ) {
        fs = fdb_iterator_sequence_init(db, &fit, 0, -1, 0x0);
        if (fs != FDB_RESULT_SUCCESS) {
            return;
        }
        while (fs == FDB_RESULT_SUCCESS) {
            fs = fdb_iterator_next(fit, &fdoc);
            if (fs == FDB_RESULT_SUCCESS) {
                offset = fdoc->offset;
                // retrieve WAL
                wr = wal_find(&db->file->global_txn, db->file, fdoc, &offset);
                print_doc(db, offset, opt, (wr == WAL_RESULT_SUCCESS));
                fdb_doc_free(fdoc);
            }
        }
        fdb_iterator_close(fit);
    }
}

int process_file(struct dump_option *opt)
{
    fdb_handle *db;
    fdb_config config;
    fdb_status fs;
    char *filename = opt->dump_file;

    config = fdb_get_default_config();
    config.buffercache_size = 0;
    config.flags = FDB_OPEN_FLAG_RDONLY;
    fs = fdb_open(&db, filename, &config);
    if (fs != FDB_RESULT_SUCCESS) {
        printf("\nUnable to open %s\n", filename);
        return -3;
    }

    print_header(db);

    printf("\n");
    scan_docs(db, opt);

    fs = fdb_close(db);
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
