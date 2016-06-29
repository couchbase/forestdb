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

int _kvs_cmp_name_fdb_dump(struct avl_node *a,
                                  struct avl_node *b,
                                  void *aux)
{
    struct kvs_node *aa, *bb;
    aa = _get_entry(a, struct kvs_node, avl_name);
    bb = _get_entry(b, struct kvs_node, avl_name);
    return strcmp(aa->kvs_name, bb->kvs_name);
}

void print_header(fdb_kvs_handle *db)
{
    uint8_t header_buf[FDB_BLOCKSIZE];
    uint64_t ndocs;
    uint64_t ndocs_wal_inserted, ndocs_wal_deleted;
    uint64_t nlivenodes;
    uint64_t ndeletes;
    uint64_t datasize;
    uint64_t datasize_wal;
    uint64_t last_header_bid;
    uint64_t kv_info_offset;
    uint64_t header_flags;
    uint64_t version;
    size_t header_len;
    size_t subblock_no, idx;
    char *compacted_filename = NULL;
    char *prev_filename = NULL;
    bid_t bid;
    bid_t trie_root_bid;
    bid_t seq_root_bid;
    bid_t stale_root_bid;
    fdb_seqnum_t seqnum;
    filemgr_header_revnum_t revnum;

    printf("DB header info:\n");

    db->file->getHeader(header_buf, &header_len, NULL, NULL, NULL);
    version = db->file->getVersion();
    if (header_len > 0) {
        fdb_fetch_header(version, header_buf, &trie_root_bid, &seq_root_bid,
                         &stale_root_bid, &ndocs, &ndeletes, &nlivenodes,
                         &datasize, &last_header_bid, &kv_info_offset,
                         &header_flags, &compacted_filename, &prev_filename);
        revnum = db->file->getHeaderRevnum();

        bid = db->file->getHeaderBid();
        printf("    BID: %" _F64 " (0x%" _X64 ", byte offset: %" _F64 ")\n",
               bid, bid, bid * FDB_BLOCKSIZE);
        printf("    DB header length: %d bytes\n", (int)header_len);
        printf("    DB header revision number: %d\n", (int)revnum);
        printf("    DB file version: %s\n", fdb_get_file_version(db->fhandle));

        struct btreeblk_subblocks *subblock = db->bhandle->getSubblockArray();

        if (trie_root_bid != BLK_NOT_FOUND) {
            if (!is_subblock(trie_root_bid)) {
                // normal block
                printf("    HB+trie root BID: %" _F64 " (0x%" _X64 ", byte offset: %" _F64 ")\n",
                       trie_root_bid, trie_root_bid, trie_root_bid * FDB_BLOCKSIZE);
            } else {
                // sub-block
                subbid2bid(trie_root_bid, &subblock_no, &idx, &bid);
                printf("    HB+trie root BID: %" _F64 ", %d-byte subblock #%" _F64,
                       bid, subblock[subblock_no].sb_size, (uint64_t) idx);
                printf(" (0x%" _X64 ", byte offset: %" _F64 ")\n", trie_root_bid,
                       bid * FDB_BLOCKSIZE + subblock[subblock_no].sb_size * idx);
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
                printf("    Seq B+tree root BID: %" _F64 ", %d-byte subblock #%" _F64,
                       bid, subblock[subblock_no].sb_size, (uint64_t) idx);
                printf(" (0x%" _X64 ", byte offset: %" _F64 ")\n", seq_root_bid,
                       bid * FDB_BLOCKSIZE + subblock[subblock_no].sb_size * idx);
            }
        } else {
            printf("    Seq B+tree root BID: not exist\n");
        }

        if (stale_root_bid != BLK_NOT_FOUND) {
            if (!is_subblock(stale_root_bid)) {
                // normal block
                printf("    Stale B+tree root BID: %" _F64 " (0x%" _X64 ", byte offset: %" _F64 ")\n",
                       stale_root_bid, stale_root_bid, stale_root_bid * FDB_BLOCKSIZE);
            } else {
                // sub-block
                subbid2bid(stale_root_bid, &subblock_no, &idx, &bid);
                printf("    Stale B+tree root BID: %" _F64 ", %d-byte subblock #%" _F64,
                       bid, subblock[subblock_no].sb_size, (uint64_t) idx);
                printf(" (0x%" _X64 ", byte offset: %" _F64 ")\n", stale_root_bid,
                       bid * FDB_BLOCKSIZE + subblock[subblock_no].sb_size * idx);
            }
        } else {
            printf("    Stale B+tree root BID: not exist\n");
        }

        if (last_header_bid != BLK_NOT_FOUND) {
            printf("    DB header BID of the last WAL flush: %" _F64
                   " (0x%" _X64 ", byte offset: %" _F64 ")\n",
                   last_header_bid, last_header_bid, last_header_bid * FDB_BLOCKSIZE);
        } else {
            printf("    DB header BID of the last WAL flush: not exist\n");
        }

        if (db->config.multi_kv_instances) {
            // multi KV instance mode
            uint64_t i;
            fdb_kvs_name_list name_list;
            struct kvs_node *node, query;
            struct avl_node *a;

            ndocs = db->file->getKvsStatOps()->statGetSum(KVS_STAT_NDOCS);
            ndeletes = db->file->getKvsStatOps()->statGetSum(KVS_STAT_NDELETES);
            nlivenodes = db->file->getKvsStatOps()->statGetSum(KVS_STAT_NLIVENODES);
            ndocs_wal_inserted = db->file->getWal()->getSize_Wal();
            ndocs_wal_deleted = db->file->getWal()->getNumDeletes_Wal();
            datasize = db->file->getKvsStatOps()->statGetSum(KVS_STAT_DATASIZE);
            datasize_wal = db->file->getWal()->getDataSize_Wal();

            printf("    # documents in the main index: %" _F64
                   ", %" _F64 "deleted / "
                   "in WAL: %" _F64 " (insert), %" _F64 " (remove)\n",
                   ndocs, ndeletes, ndocs_wal_inserted, ndocs_wal_deleted);
            printf("    # live index nodes: %" _F64 " (%" _F64 " bytes)\n",
                   nlivenodes, nlivenodes * FDB_BLOCKSIZE);
            printf("    Total document size: %" _F64 " bytes, (index: %" _F64 " bytes, "
                   "WAL: %" _F64 " bytes)\n",
                   datasize + datasize_wal, datasize, datasize_wal);

            fdb_get_kvs_name_list(db->fhandle, &name_list);

            printf("    # KV stores: %d\n", (int)name_list.num_kvs_names);
            for (i=0; i<name_list.num_kvs_names; ++i){
                if (strcmp(name_list.kvs_names[i], DEFAULT_KVS_NAME)) {
                    query.kvs_name = name_list.kvs_names[i];
                    a = avl_search(db->file->getKVHeader_UNLOCKED()->idx_name,
                                   &query.avl_name,
                                   _kvs_cmp_name_fdb_dump);
                    if (!a) {
                        continue;
                    }

                    printf("      KV store name: %s\n", name_list.kvs_names[i]);
                    node = _get_entry(a, struct kvs_node, avl_name);
                    seqnum = node->seqnum;
                    ndocs = node->stat.ndocs;
                    ndeletes = node->stat.ndeletes;
                    nlivenodes = node->stat.nlivenodes;
                    ndocs_wal_inserted = node->stat.wal_ndocs - node->stat.wal_ndeletes;
                    ndocs_wal_deleted = node->stat.wal_ndeletes;
                    datasize = node->stat.datasize;
                } else { // default KVS
                    printf("      KV store name: %s\n", name_list.kvs_names[i]);
                    ndocs = db->file->accessHeader()->stat.ndocs;
                    ndeletes = db->file->accessHeader()->stat.ndeletes;
                    nlivenodes = db->file->accessHeader()->stat.nlivenodes;
                    seqnum = db->file->accessHeader()->seqnum;
                    ndocs_wal_inserted = db->file->accessHeader()->stat.wal_ndocs -
                                         db->file->accessHeader()->stat.wal_ndeletes;
                    ndocs_wal_deleted = db->file->accessHeader()->stat.wal_ndeletes;
                    datasize = db->file->accessHeader()->stat.datasize;
                }

                printf("      # documents in the main index: %" _F64
                       ", %" _F64 "deleted / "
                       "in WAL: %" _F64 " (insert), %" _F64 " (remove)\n",
                       ndocs, ndeletes, ndocs_wal_inserted, ndocs_wal_deleted);
                printf("      # live index nodes: %" _F64 " (%" _F64 " bytes)\n",
                       nlivenodes, nlivenodes * FDB_BLOCKSIZE);
                printf("      Total document size: %" _F64 " bytes\n", datasize);
                printf("      Last sequence number: %" _F64 "\n", seqnum);
                printf("\n");
            }

            fdb_free_kvs_name_list(&name_list);

        } else {
            // single KV instance mode
            seqnum = db->file->getSeqnum();
            ndocs_wal_inserted = db->file->getWal()->getSize_Wal();
            ndocs_wal_deleted = db->file->getWal()->getNumDeletes_Wal();
            datasize_wal = db->file->getWal()->getDataSize_Wal();

            printf("    # documents in the main index: %" _F64
            ", %" _F64 "deleted / "
                   "in WAL: %" _F64 " (insert), %" _F64 " (remove)\n",
                   ndocs, ndeletes, ndocs_wal_inserted, ndocs_wal_deleted);
            printf("    # live index nodes: %" _F64 " (%" _F64 " bytes)\n",
                   nlivenodes, nlivenodes * FDB_BLOCKSIZE);
            printf("    Total document size: %" _F64 " bytes, (index: %" _F64 " bytes, "
                   "WAL: %" _F64 " bytes)\n",
                   datasize + datasize_wal, datasize, datasize_wal);
            printf("    Last sequence number: %" _F64 "\n", seqnum);
        }

        if (compacted_filename) {
            printf("    Next file after compaction: %s\n", compacted_filename);
        }
        if (prev_filename) {
            printf("    Previous file before compaction: %s\n", prev_filename);
            free(prev_filename);
        }

    } else {
        printf("    No header exists.\n");
        printf("    DB file version: %s\n", fdb_get_file_version(db->fhandle));
    }
}
