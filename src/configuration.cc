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

#include <sys/types.h>
#include <sys/stat.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <assert.h>

#include "configuration.h"
#include "filemgr.h"
#include "filemgr_ops.h"
#include "cJSON.h"


void set_default_fdb_config(fdb_config *fconfig) {
    if (fconfig) {
        fconfig->chunksize = fconfig->offsetsize = sizeof(uint64_t);
        fconfig->blocksize = FDB_BLOCKSIZE; // 4KB by default.
        fconfig->buffercache_size = 134217728; // 128MB by default.
        fconfig->wal_threshold = 4096; // 4096 WAL entries by default.
        fconfig->fileops = NULL; // Not to use any customized file ops by default.
        fconfig->seqtree_opt = FDB_SEQTREE_USE; // Use a seq btree by default.
        fconfig->durability_opt = FDB_DRB_NONE; // Use a synchronous commit by default.
        fconfig->max_seqnum = 0; // Only used for snapshots. 0 indicates no snapshot.
        fconfig->flags = 0;
        fconfig->compaction_buf_maxsize = 16777216; // 16MB by default.
        fconfig->cleanup_cache_onclose = 1; // Clean up cache entries when a file is closed.
        fconfig->aux = NULL;
    }
}

static int validConfigParam(cJSON *param) {
    cJSON *default_value = cJSON_GetObjectItem(param, "default");
    if (!default_value) {
        return 0;
    }

    cJSON *validator = cJSON_GetObjectItem(param, "validator");
    if (!validator) {
        return 0;
    }

    if (default_value->type == cJSON_Number) {
        cJSON *range = cJSON_GetObjectItem(validator, "range");
        if (!range) {
            return 0;
        }
        cJSON *max = cJSON_GetObjectItem(range, "max");
        cJSON *min = cJSON_GetObjectItem(range, "min");
        if (!max || !min || max->type != cJSON_Number || min->type != cJSON_Number) {
            return 0;
        }
        if (min->valuedouble <= default_value->valuedouble &&
            default_value->valuedouble <= max->valuedouble) {
            // Should check the validness by comparing their double values
            // because some number-type config params have a range beyond 4 bytes.
            return 1; // Valid config parameter value
        }
    } else if (default_value->type == cJSON_String) {
        cJSON *value_list = cJSON_GetObjectItem(validator, "enum");
        if (!value_list) {
            return 0;
        }

        int valid = 0;
        int size = cJSON_GetArraySize(value_list);
        for(int i = 0; i < size; ++i) {
            cJSON *elm = cJSON_GetArrayItem(value_list, i);
            if (!strcmp(default_value->valuestring, elm->valuestring)) {
                valid = 1;
                break;
            }
        }
        if (valid) {
            return 1; // valid config parameter value
        }
    }

    return 0;
}

void parse_fdb_config(const char *fdb_config_file, fdb_config *fconfig) {
    assert(fconfig);

    if (fdb_config_file) {
        filemgr_ops *file_ops = get_filemgr_ops();
        cs_off_t file_size = file_ops->file_size(fdb_config_file);
        if (file_size == FDB_RESULT_READ_FAIL) {
            fprintf(stderr, "Error in calling file_size() on an JSON config file \"%s\"\n",
                    fdb_config_file);
            set_default_fdb_config(fconfig);
            return;
        }

        int fd = file_ops->open(fdb_config_file, O_RDONLY, 0666);
        if (fd < 0) {
            fprintf(stderr, "Error in calling open() on an JSON config file \"%s\"\n",
                    fdb_config_file);
            set_default_fdb_config(fconfig);
            return;
        }

        char *json_data = (char *) malloc(file_size + 1);
        json_data[file_size] = '\0';
        char *buf = json_data;
        ssize_t bytesread = 0;
        cs_off_t offset = 0;

        bytesread = file_ops->pread(fd, buf, file_size, offset);

        if (bytesread < 0) {
            free(json_data);
            fprintf(stderr, "Error in calling pread() on an JSON config file \"%s\"\n",
                    fdb_config_file);
            set_default_fdb_config(fconfig);
            return;
        }
        if (file_ops->close(fd) != FDB_RESULT_SUCCESS) {
            free(json_data);
            fprintf(stderr, "Error in calling close() on an JSON config file \"%s\"\n",
                    fdb_config_file);
            set_default_fdb_config(fconfig);
            return;
        }

        cJSON *jsonObj = cJSON_Parse(json_data);
        if (!jsonObj) {
            free(json_data);
            fprintf(stderr, "Error in parsing an JSON config file \"%s\"\n",
                    fdb_config_file);
            set_default_fdb_config(fconfig);
            return;
        }

        cJSON *configs = cJSON_GetObjectItem(jsonObj,"configs");
        if (!configs) {
            cJSON_Delete(jsonObj);
            free(json_data);
            fprintf(stderr, "Error in retrieving \"configs\" JSON object from "
                    "an JSON config file \"%s\"\n", fdb_config_file);
            set_default_fdb_config(fconfig);
            return;
        }

        cJSON *chunk_size = cJSON_GetObjectItem(configs, "chunk_size");
        if (validConfigParam(chunk_size)) {
            fconfig->chunksize = cJSON_GetObjectItem(chunk_size, "default")->valueint;
        } else {
            fconfig->chunksize = sizeof(uint64_t);
        }

        cJSON *bcache_size = cJSON_GetObjectItem(configs, "buffer_cache_size");
        if (validConfigParam(bcache_size)) {
            fconfig->buffercache_size =
                (uint64_t) cJSON_GetObjectItem(bcache_size, "default")->valuedouble;
        } else {
            fconfig->buffercache_size = 134217728; // 128MB by default.
        }

        cJSON *wal_threshold = cJSON_GetObjectItem(configs, "wal_threshold");
        if (validConfigParam(wal_threshold)) {
            fconfig->wal_threshold =
                (uint64_t) cJSON_GetObjectItem(wal_threshold, "default")->valuedouble;
        } else {
            fconfig->wal_threshold = 4096;
        }

        cJSON *enable_seqtree = cJSON_GetObjectItem(configs, "enable_seq_btree");
        if (validConfigParam(enable_seqtree)) {
            char *val = cJSON_GetObjectItem(enable_seqtree, "default")->valuestring;
            if (strcmp(val, "true") == 0) {
                fconfig->seqtree_opt = FDB_SEQTREE_USE;
            } else {
                fconfig->seqtree_opt = FDB_SEQTREE_NOT_USE;
            }
        } else {
            fconfig->seqtree_opt = FDB_SEQTREE_USE;
        }

        cJSON *durability_option = cJSON_GetObjectItem(configs, "durability_option");
        if (validConfigParam(durability_option)) {
            char *val = cJSON_GetObjectItem(durability_option, "default")->valuestring;
            if (strcmp(val, "sync_commit") == 0) {
                fconfig->durability_opt = FDB_DRB_NONE;
            } else if (strcmp(val, "sync_o_direct_commit") == 0) {
                fconfig->durability_opt = FDB_DRB_ODIRECT;
            } else if (strcmp(val, "async_commit") == 0) {
                fconfig->durability_opt = FDB_DRB_ASYNC;
            } else if (strcmp(val, "async_o_direct_commit") == 0) {
                fconfig->durability_opt = FDB_DRB_ODIRECT_ASYNC;
            }
        } else {
            fconfig->durability_opt = FDB_DRB_NONE; // Use a synchronous commit by default.
        }

        cJSON *comp_buf_size = cJSON_GetObjectItem(configs, "compaction_buf_size");
        if (validConfigParam(comp_buf_size)) {
            fconfig->compaction_buf_maxsize =
                (uint32_t) cJSON_GetObjectItem(comp_buf_size, "default")->valueint;
        } else {
            fconfig->compaction_buf_maxsize = 16777216; // 16MB by default.
        }

        cJSON *cleanup_cache_onclose = cJSON_GetObjectItem(configs,
                                                            "cleanup_cache_on_close");
        if (validConfigParam(cleanup_cache_onclose)) {
            char *val = cJSON_GetObjectItem(cleanup_cache_onclose, "default")->valuestring;
            if (strcmp(val, "true") == 0) {
                fconfig->cleanup_cache_onclose = 1;
            } else {
                fconfig->cleanup_cache_onclose = 0;
            }
        } else {
            fconfig->cleanup_cache_onclose = 1;
        }

        fconfig->offsetsize = sizeof(uint64_t);
        fconfig->blocksize = FDB_BLOCKSIZE; // 4KB by default.
        fconfig->fileops = NULL; // Not to use any customized file ops by default.
        fconfig->max_seqnum = 0; // No snapshot marker by default.
        fconfig->flags = 0;
        fconfig->aux = NULL;

        cJSON_Delete(jsonObj);
        free(json_data);
    } else {
        set_default_fdb_config(fconfig);
    }
}
