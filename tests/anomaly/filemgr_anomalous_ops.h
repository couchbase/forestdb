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

#ifndef _FILEMGR_ANOMALOUS_OPS
#define _FILEMGR_ANOMALOUS_OPS

#ifdef __cplusplus
extern "C" {
#endif

struct filemgr_ops * get_filemgr_ops();
void filemgr_ops_set_anomalous(int behavior);

// These callbacks allow test-suite to control how the file ops should behave
// If these return 0, then normal operation will happen,
// If these return a non-zero value, then the file ops will return the same result
struct anomalous_callbacks {
    int (*open_cb)(void *ctx, struct filemgr_ops *normal_ops,
                   const char *pathname, int flags, mode_t mode);
    ssize_t (*pwrite_cb)(void *ctx, struct filemgr_ops *normal_ops,
                         int fd, void *buf, size_t count, cs_off_t offset);
    ssize_t (*pread_cb)(void *ctx, struct filemgr_ops *normal_ops,
                        int fd, void *buf, size_t count, cs_off_t offset);
    int (*close_cb)(void *ctx, struct filemgr_ops *normal_ops, int fd);
    cs_off_t (*goto_eof_cb)(void *ctx, struct filemgr_ops *normal_ops, int fd);
    cs_off_t (*file_size_cb)(void *ctx, struct filemgr_ops *normal_ops,
                             const char *filename);
    int (*fdatasync_cb)(void *ctx, struct filemgr_ops *normal_ops, int fd);
    int (*fsync_cb)(void *ctx, struct filemgr_ops *normal_ops, int fd);
    void (*get_errno_str_cb)(void *ctx, struct filemgr_ops *normal_ops,
                             char *buf, size_t size);
};

struct anomalous_callbacks * get_default_anon_cbs();
void filemgr_ops_anomalous_init(struct anomalous_callbacks *cbs, void *ctx);

#ifdef __cplusplus
}
#endif

#endif
