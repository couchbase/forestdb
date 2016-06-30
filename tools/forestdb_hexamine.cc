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

#define MAX_FILE_SIZE 1610612736 // 1.5 GB
/**
 * How to Use this tool to examine forestdb files with help of gdb
 * ---------------------------------------------------------------
 * This tool will read ALL the blocks of the file into the db[] array
 * and loop forever. gdb can be attached to the process to examine blocks.
 * Example..
 *   bash$ gdb ./forestdb_hexamine
 *     (gdb) r path.to.forestdb.file
 * It will print all DB header indexes as it reads
 * DB Header 1
 * DB Header 3
 * DB Header 106
 * File scanned and headers decoded
 * gdb --pid=6575
 * Process 6575 stopped
 * p db[106]
 * (dblock) $0 = {
 *   trie_root_raw = 9007199254741048
 *   seqtree_root_raw = 9288674231451704
 *   num_docs = 1
 *   num_nodes = 0
 *   data_size = 24371
 *   last_wal_flush_bid = 106
 *   kv_info_offset = 229176
 *    = (hdr_flags = 3, flags = void * = 0x0000000000000003)
 *   new_filename_len = 0
 *   old_filename_len = 0
 *   bytes = "y\x85I\x9b"
 *   trie_root_bid = 56
 *   trie_subblock_no = 0
 *   trie_idx = 0
 *   seqtree_root_bid = 56
 *   seqtree_subblock_no = 0
 *   seqtree_idx = 1
 *   delta_size = 40
 *   prev_hdr_bid = 3
 *   hdr_len = 72
 *  = (magic_bytes = 16045704242864832239, magic = void * = 0xdeadcafebeefbeef)
 *   marker = '?'
 * }
 *
 */
void print_usage(void)
{
    printf("\nUsage: forestdb_hexamine [OPTION]... [filename]\n"
    "\n-  Loads entire file in memory and hangs in gdb_loop for examination\n"
    "\nOptions:\n"
    "\n      --print-header     displays KV info (for non-corrupted files)"
    "\n      --headers-only     only dump contents of all DB headers and exit"
    "\n      --max-filesize     reset maximum file size (default 1.5GB)"
    "\n");
}

struct input_option{
    char *filename;
    bool print_header;
    bool headers_only;
    uint64_t max_filesize;
};

enum blk_type {
    BNODE_BLK = 0xff,
    DBHEADER_BLK = 0xee,
    DOC_BLK = 0xdd
};

#define BLK_SIZE 4096
#pragma pack(1)

typedef
struct db_header {
    uint64_t trie_root_raw;
    uint64_t seqtree_root_raw;
    uint64_t staletree_root_raw;
    uint64_t num_docs;
    uint64_t num_deletes;
    uint64_t num_nodes;
    uint64_t data_size;
    uint64_t last_wal_flush_bid;
    uint64_t kv_info_offset;
    union {
        uint64_t hdr_flags;
        void    *flags;
    };
    uint16_t new_filename_len;
    uint16_t old_filename_len;

    char bytes[3937];

    // The variables below are pseudo variables for debugging & not in header..
    uint64_t revnum;
    uint64_t seqnum;
    uint64_t trie_root_bid;
    uint64_t trie_subblock_no;
    uint64_t trie_idx;
    uint64_t seqtree_root_bid;
    uint64_t seqtree_subblock_no;
    uint64_t seqtree_idx;

    // The ones below are real variables defined in the DB header...
    uint64_t delta_size;
    uint64_t prev_hdr_bid;
    uint16_t hdr_len;
    union {
        uint64_t magic_bytes;
        void   *magic;
    };
    uint8_t marker;
}dblock;

void decode_dblock(void *block) {
    dblock *_db = (dblock *)block;
    size_t subblock_no, idx;
    _db->trie_root_raw = _endian_decode(_db->trie_root_raw);
    _db->seqtree_root_raw =_endian_decode(_db->seqtree_root_raw);
    _db->staletree_root_raw=_endian_decode(_db->staletree_root_raw);
    _db->num_docs = _endian_decode(_db->num_docs);
    _db->num_deletes = _endian_decode(_db->num_deletes);
    _db->num_nodes = _endian_decode(_db->num_nodes);
    _db->data_size = _endian_decode(_db->data_size);
    _db->last_wal_flush_bid = _endian_decode(_db->
            last_wal_flush_bid);
    _db->kv_info_offset = _endian_decode(_db->kv_info_offset);
    _db->hdr_flags = _endian_decode(_db->hdr_flags);

    _db->new_filename_len = _endian_decode(_db->new_filename_len);
    _db->old_filename_len = _endian_decode(_db->old_filename_len);
    if (!is_subblock(_db->trie_root_raw)) {
        _db->trie_root_bid = _db->trie_root_raw;
        _db->trie_subblock_no = 0;
        _db->trie_idx = 0;
    } else {
        subbid2bid(_db->trie_root_raw,
                   &subblock_no,
                   &idx,
                   &_db->trie_root_bid);
        _db->trie_subblock_no = subblock_no;
        _db->trie_idx = idx;
    }
    if (!is_subblock(_db->seqtree_root_raw)) {
        _db->seqtree_root_bid = _db->trie_root_raw;
        _db->seqtree_subblock_no = 0;
        _db->seqtree_idx = 0;
    } else {
        subbid2bid(_db->seqtree_root_raw,
                   &subblock_no,
                   &idx,
                   &_db->seqtree_root_bid);
        _db->seqtree_subblock_no = subblock_no;
        _db->seqtree_idx = idx;
    }
    _db->delta_size = _endian_decode(_db->delta_size);
    _db->prev_hdr_bid = _endian_decode(_db->prev_hdr_bid);
    _db->magic_bytes = _endian_decode(_db->magic_bytes);
    _db->hdr_len = _endian_decode(_db->hdr_len);
    _db->revnum = *(uint64_t*)((char*)block + _db->hdr_len);
    _db->revnum = _endian_decode(_db->revnum);
    _db->seqnum = *(uint64_t*)((char*)block + _db->hdr_len + sizeof(uint64_t));
    _db->seqnum = _endian_decode(_db->seqnum);
}

dblock *db;

void gdb_sleep(void) {
    usleep(1000);
}

int process_file(struct input_option *opt)
{
    fdb_file_handle *dbfile = NULL;
    fdb_config config;
    fdb_fileops_handle fileops_handle;
    char *filename = opt->filename;
    uint64_t file_size;
    size_t num_blocks;
    FileMgr file;
    uint8_t block_buf[BLK_SIZE];
    fdb_status fs;

    config = fdb_get_default_config();
    config.buffercache_size = 0;
    config.flags = FDB_OPEN_FLAG_RDONLY;
    file.setOps(get_filemgr_ops());
    fs = FileMgr::fileOpen(filename, file.getOps(), &fileops_handle,
                           O_RDWR, 0666);

    if (fs != FDB_RESULT_SUCCESS) {
        printf("\nUnable to open %s\n", filename);
        return -1;
    }

    file_size = file.getOps()->file_size(fileops_handle, filename);
    num_blocks = file_size / BLK_SIZE;

    if (opt->print_header) {
        fs = fdb_open(&dbfile, filename, &config);
        if (fs != FDB_RESULT_SUCCESS) {
            printf("\nUnable to open %s\n", filename);
            return -1;
        }
        print_header(dbfile->getRootHandle());
        fdb_snapshot_info_t *markers;
        uint64_t num_markers;
        fs = fdb_get_all_snap_markers(dbfile, &markers, &num_markers);
        if (fs != FDB_RESULT_SUCCESS) {
            printf("\nNo commit headers found in file %s\n", filename);
            return -2;
        }
        for (uint64_t i = 0; i < num_markers; ++i) {
            printf("DB Header at bid %" _F64 ": with %" _F64 " kv stores\n",
                markers[i].marker, markers[i].num_kvs_markers);
            for (int64_t j = 0; j < markers[i].num_kvs_markers; ++j) {
                printf("\t KVS %s at seqnum %" _F64 "\n",
                    markers[i].kvs_markers[j].kv_store_name,
                    markers[i].kvs_markers[j].seqnum);
            }
        }
        fdb_free_snap_markers(markers, num_markers);
    }
    if (opt->headers_only) {
        for (uint64_t i = 0; i < num_blocks; ++i) {
            ssize_t rv = file.getOps()->pread(fileops_handle, &block_buf, BLK_SIZE,
                                             i * BLK_SIZE);
            if (rv != BLK_SIZE) {
                fdb_close(dbfile);
                return FDB_RESULT_READ_FAIL;
            }
            db = (dblock *)&block_buf;

            if (db->marker == DBHEADER_BLK) {
                printf("\n-------DB Header %" _F64 " at offset %" _F64
                        "--------" , i, i * BLK_SIZE);
                decode_dblock(db);
                printf("\ntrie_root_raw = %p", (void*)db->trie_root_raw);
                printf("\nseqtree_root_raw = %p", (void*)db->seqtree_root_raw);
                printf("\nnum_docs = %" _F64, db->num_docs);
                printf("\nnum_nodes = %" _F64, db->num_nodes);
                printf("\ndatasize = %" _F64, db->data_size);
                printf("\nlast_wal_flush_bid = %" _F64, db->last_wal_flush_bid);
                printf("\nkv_info_offset = %" _F64, db->kv_info_offset);
                printf("\nflags = %p", db->flags);
                printf("\nnew_filename_len = %d", db->new_filename_len);
                printf("\nold_filename_len = %d", db->old_filename_len);
                printf("\ntrie_root_bid = %" _F64, db->trie_root_bid);
                printf("\ntrie_subblock_no = %" _F64, db->trie_subblock_no);
                printf("\ntrie_idx = %" _F64, db->trie_idx);
                printf("\nseqtree_root_bid = %" _F64, db->seqtree_root_bid);
                printf("\nseqtree_subblock_no = %" _F64,
                                                 db->seqtree_subblock_no);
                printf("\nseqtree_idx = %" _F64, db->seqtree_idx);
                printf("\ndelta size = %" _F64, db->delta_size);
                printf("\nprev_hdr_bid = %" _F64, db->prev_hdr_bid);
                printf("\nhdr_len = %d", db->hdr_len);
                printf("\nmagic = %p", db->magic);
            }
        }

    } else {
        if (file_size > opt->max_filesize) {
            printf("\n File %s size %" _F64" exceeds max size of %" _F64" \n",
                    filename, file_size, opt->max_filesize);

            if (opt->print_header) {
                fdb_close(dbfile);
            }
            return -1;
        }

        db = (dblock *) malloc(file_size);
        if (!db) {
            printf("\nUnable to allocate memory of %" _F64" bytes\n",
            file_size);

            if (opt->print_header) {
                fdb_close(dbfile);
            }
            return -1;
        }
        for (uint64_t i = 0; i < num_blocks; ++i) {
            ssize_t rv = file.getOps()->pread(fileops_handle, &db[i], BLK_SIZE,
                                              i * BLK_SIZE);
            if (rv != BLK_SIZE) {
                if (opt->print_header) {
                    fdb_close(dbfile);
                }
                free(db);
                return FDB_RESULT_READ_FAIL;
            }
            if (db[i].marker == DBHEADER_BLK) {
                printf("\nDB Header %" _F64, i);
                decode_dblock(&db[i]);
            }
        }
#if !defined(WIN32) && !defined(_WIN32)
        printf("\nFile scanned and headers decoded\n gdb --pid=%d\n", getpid());
#endif
        while (1) {
            gdb_sleep();
        }
        free(db);
    }

    if (opt->print_header) {
        fs = fdb_close(dbfile);
        if (fs != FDB_RESULT_SUCCESS) {
            printf("\nUnable to close %s\n", filename);
            return -4;
        }
    }

    FileMgr::fileClose(file.getOps(), fileops_handle);
    return -1;
}

int parse_options(int argc, char **argv, struct input_option *opt)
{
    // Unfortunately, we cannot use getopt generally
    // because Windows doesn't support it ..
    int i = 1;

    if (argc < 2) {
        print_usage();
        return -1;
    }

    for (i = 1; i < argc; ++i) {
        if (argv[i][0] == '-' && argv[i][1] == '-') {
            if (strncmp(argv[i], "--print-header", 16) == 0) {
                opt->print_header = true;
            } else if (strncmp(argv[i], "--headers-only", 16) == 0) {
                opt->headers_only = true;
            } else if (strncmp(argv[i], "--max-filesize", 16) == 0) {
                sscanf(argv[++i], "%" _F64, &opt->max_filesize);
            } else {
                printf("\nUnknown option %s\n", argv[i]);
                print_usage();
                return -2;
            }
        } else {
            opt->filename = argv[i];
        }
    }

    return 0;
}

int main(int argc, char **argv)
{
    struct input_option opt;
    memset(&opt, 0 , sizeof(struct input_option));
    opt.max_filesize = MAX_FILE_SIZE;
    memleak_start();
    int ret = parse_options(argc, argv, &opt);

    if (ret) {
        memleak_end();
        return ret;
    }

    ret = process_file(&opt);

    fdb_shutdown();
    memleak_end();
    return ret;
}
