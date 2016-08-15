/* -*- Mode: C++; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
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

#include "libforestdb/forestdb.h"
#include "test.h"

#include "commit_log.h"
#include "docio.h"
#include "time_utils.h"

void basic_operation_test()
{
    TEST_INIT();

    int i, r, n=500000;
    CommitLog *clog;
    CommitLogConfig *config;
    char keybuf[256], valuebuf[256];
    void *ret;
    struct filemgr_ops *ops = get_filemgr_ops();
    CommitLogEntry entry;

    r = system(SHELL_DEL" commit_log_testfile* > errorlog.txt");
    (void)r;

    config = new CommitLogConfig(ops);
    clog = new CommitLog(std::string("commit_log_testfile"), config);

    for (i=0; i<n; ++i) {
        sprintf(keybuf, "key%06d", i);
        sprintf(valuebuf, "value%06d", i);
        entry.clear();
        entry.setSeqnum(i+1);
        entry.setKey(keybuf, strlen(keybuf)+1);
        entry.setBody(valuebuf, strlen(valuebuf)+1);
        clog->appendLogEntry(&entry, ret);
        TEST_CMP(valuebuf, ret, strlen(valuebuf)+1);
    }

    clog->commitLog(1, 0);

    delete clog;
    delete config;

    TEST_RESULT("basic operation test");
}

void single_writer_speed_test()
{
    TEST_INIT();

    int i, r, n=4000000;
    CommitLog *clog;
    CommitLogConfig *config;
    char keybuf[256], valuebuf[256];
    void *ret;
    uint64_t gap;
    struct filemgr_ops *ops = get_filemgr_ops();
    CommitLogEntry entry;
    struct timeval begin, end;

    r = system(SHELL_DEL" commit_log_testfile* > errorlog.txt");
    (void)r;

    config = new CommitLogConfig(ops);
    clog = new CommitLog(std::string("commit_log_testfile"), config);

    gettimeofday(&begin, NULL);

    for (i=0; i<n; ++i) {
        sprintf(keybuf, "key%06d", i);
        sprintf(valuebuf, "value%06d", i);
        entry.clear();
        entry.setSeqnum(i+1);
        entry.setKey(keybuf, strlen(keybuf)+1);
        entry.setBody(valuebuf, strlen(valuebuf)+1);
        clog->appendLogEntry(&entry, ret);

        if (i == n/2) {
            clog->commitLog(1, 1);
        }
    }

    gettimeofday(&end, NULL);

    gap = timeval_to_us(_utime_gap(begin, end));
    printf("%d docs, %" _F64 " us (%" _F64 " ops/sec)\n", n, gap, (uint64_t)n*1000000/gap);

    clog->commitLog(2, 2);
    clog->commitLog(3, 3);

    delete clog;
    delete config;

    TEST_RESULT("single writer speed test");
}

struct cl_writer_args {
    int id;
    int n_docs;
    CommitLog *clog;
    void **ret;
};

void *cl_writer(void *voidargs)
{
    TEST_INIT();
    int i;
    char keybuf[256], valuebuf[256];
    CommitLogEntry entry;
    struct cl_writer_args *args = static_cast<struct cl_writer_args*>(voidargs);

    args->ret = (void**)calloc(args->n_docs, sizeof(void *));

    for (i=0; i<args->n_docs; ++i) {
        sprintf(keybuf, "[%d]key%06d", args->id, i);
        sprintf(valuebuf, "[%d]value%06d", args->id, i);
        entry.clear();
        entry.setSeqnum(args->id*args->n_docs + i + 1);
        entry.setKey(keybuf, strlen(keybuf)+1);
        entry.setBody(valuebuf, strlen(valuebuf)+1);
        args->clog->appendLogEntry(&entry, args->ret[i]);
    }

    return NULL;
}

void racing_multi_writers_test()
{
    TEST_INIT();

    int i, j, r, n_writers=4, n_docs=1000000;
    CommitLog *clog;
    CommitLogConfig *config;
    char valuebuf[256];
    struct filemgr_ops *ops = get_filemgr_ops();
    struct cl_writer_args args[16];
    struct timeval begin, end;
    thread_t tid[16];
    void *thread_ret;

    r = system(SHELL_DEL" commit_log_testfile* > errorlog.txt");
    (void)r;

    config = new CommitLogConfig(ops);
    clog = new CommitLog(std::string("commit_log_testfile"), config);

    gettimeofday(&begin, NULL);

    // spawn threads
    for (i=0; i<n_writers; ++i) {
        args[i].id = i;
        args[i].clog = clog;
        args[i].n_docs = n_docs;
        thread_create(&tid[i], cl_writer, (void*)&args[i]);
    }

    // wait
    for (i=0; i<n_writers; ++i) {
        thread_join(tid[i], &thread_ret);
    }

    gettimeofday(&end, NULL);

    uint64_t gap, total_docs;
    gap = timeval_to_us(_utime_gap(begin, end));
    total_docs = (uint64_t)n_docs * n_writers;
    printf("%d writers, %" _F64 " docs, %" _F64 " us (%" _F64 " ops/sec)\n",
           n_writers, total_docs, gap, total_docs*1000000/gap);

    // integrity check
    for (j=0; j<n_writers; ++j) {
        for (i=0; i<args[j].n_docs; ++i) {
            sprintf(valuebuf, "[%d]value%06d", args[j].id, i);
            TEST_CMP(valuebuf, args[j].ret[i], strlen(valuebuf)+1);
        }
        free(args[j].ret);
    }

    delete clog;
    delete config;

    TEST_RESULT("racing multi writers test");
}

struct recover_callback_args {
    uint64_t doc_count;
    uint64_t commit_count;
    char* uncomp_buf;
    size_t uncomp_buflen;
};
CommitLogScanDecision recover_callback(CommitLogEntry* entry,
                                       bool is_system_doc,
                                       void* offset_value,
                                       void* offset_entry,
                                       uint64_t log_id,
                                       void* ctx)
{
    TEST_INIT();
    struct recover_callback_args *args = static_cast<struct recover_callback_args*>(ctx);

    if (is_system_doc) {
        uint64_t revnum, txn_id;
        if (entry->getCommitMarker(revnum, txn_id)) {
            args->commit_count++;
        }
    } else {
        if (entry->isCompressed()) {
            void *key, *meta, *value;
            char keybuf[256], metabuf[256], valuebuf[256];

            if (args->uncomp_buf) {
                key = entry->getKey(args->uncomp_buf, args->uncomp_buflen);
                meta = entry->getMeta(args->uncomp_buf, args->uncomp_buflen);
                value = entry->getBody(args->uncomp_buf, args->uncomp_buflen);
            } else {
                key = entry->getKey();
                meta = entry->getMeta();
                value = entry->getBody();
            }

            sprintf(keybuf, "key%06d", (int)args->doc_count);
            sprintf(metabuf, "meta%06d", (int)args->doc_count);
            sprintf(valuebuf, "value%06d", (int)args->doc_count);
            TEST_CMP(key, keybuf, entry->getKeyLen());
            TEST_CMP(meta, metabuf, entry->getMetaLen());
            TEST_CMP(value, valuebuf, entry->getBodyLen());
        }
        args->doc_count++;
    }

    return CommitLogScanDecision::COMMIT_LOG_SCAN_CONTINUE;
}

void recover_commit_log_test()
{
    TEST_INIT();

    int i, r, n=1000000;
    CommitLog *clog;
    CommitLogConfig *config;
    char keybuf[256], valuebuf[256];
    void *ret;
    struct filemgr_ops *ops = get_filemgr_ops();
    CommitLogEntry entry;

    r = system(SHELL_DEL" commit_log_testfile* > errorlog.txt");
    (void)r;

    config = new CommitLogConfig(ops);
    clog = new CommitLog(std::string("commit_log_testfile"), config);

    for (i=0; i<n; ++i) {
        sprintf(keybuf, "key%06d", i);
        sprintf(valuebuf, "value%06d", i);
        entry.clear();
        entry.setSeqnum(i+1);
        entry.setKey(keybuf, strlen(keybuf)+1);
        entry.setBody(valuebuf, strlen(valuebuf)+1);
        clog->appendLogEntry(&entry, ret);

        if (i == n/2) {
            clog->commitLog(1, 1);
        }
    }
    clog->commitLog(2, 1);

    // now free commit log instance and re-load
    delete clog;

    struct recover_callback_args args;
    args.doc_count = args.commit_count = 0;
    clog = new CommitLog(std::string("commit_log_testfile"), config);
    clog->reconstructLog(recover_callback, &args);

    TEST_CHK(args.doc_count == static_cast<uint64_t>(n));
    TEST_CHK(args.commit_count == 2);

    // append more logs
    for (i=0; i<n; ++i) {
        sprintf(keybuf, "key%06d", i);
        sprintf(valuebuf, "value%06d", i);
        entry.clear();
        entry.setSeqnum(i+1);
        entry.setKey(keybuf, strlen(keybuf)+1);
        entry.setBody(valuebuf, strlen(valuebuf)+1);
        clog->appendLogEntry(&entry, ret);
    }

    // sync
    clog->commitLog(3, 1);

    delete clog;
    delete config;

    TEST_RESULT("recover commit log test");
}

void large_document_test()
{
    TEST_INIT();

    int i, r, n=1000000;
    CommitLog *clog;
    CommitLogConfig *config;
    char keybuf[256], valuebuf[256];
    void *ret, *ret_large;
    struct filemgr_ops *ops = get_filemgr_ops();
    CommitLogEntry entry;

    r = system(SHELL_DEL" commit_log_testfile* > errorlog.txt");
    (void)r;

    config = new CommitLogConfig(ops);
    clog = new CommitLog(std::string("commit_log_testfile"), config);

    // insert some docs
    for (i=0; i<n/100; ++i) {
        sprintf(keybuf, "key%06d", i);
        sprintf(valuebuf, "value%06d", i);
        entry.clear();
        entry.setSeqnum(i+1);
        entry.setKey(keybuf, strlen(keybuf)+1);
        entry.setBody(valuebuf, strlen(valuebuf)+1);
        clog->appendLogEntry(&entry, ret);
    }

    // insert a doc larger than a commit log file
    size_t large_doc_size = config->fileSizeLimit * 2;
    void *temp_buf = (void*)malloc(large_doc_size);

    memset(temp_buf, 'x', large_doc_size);
    sprintf(keybuf, "key%06d", i);
    entry.clear();
    entry.setSeqnum(i+1);
    entry.setKey(keybuf, strlen(keybuf)+1);
    entry.setBody(temp_buf, large_doc_size);
    clog->appendLogEntry(&entry, ret_large);

    // insert more small docs
    for (i=0; i<n; ++i) {
        sprintf(keybuf, "key%06d", i);
        sprintf(valuebuf, "value%06d", i);
        entry.clear();
        entry.setSeqnum(i+1);
        entry.setKey(keybuf, strlen(keybuf)+1);
        entry.setBody(valuebuf, strlen(valuebuf)+1);
        clog->appendLogEntry(&entry, ret);
    }

    TEST_CMP(ret_large, temp_buf, large_doc_size);

    free(temp_buf);
    delete clog;
    delete config;

    TEST_RESULT("large document test");
}

void destroy_log_test()
{
    TEST_INIT();

    int i, r, n=1000000;
    CommitLog *clog;
    CommitLogConfig *config;
    char keybuf[256], valuebuf[256];
    void *ret;
    struct filemgr_ops *ops = get_filemgr_ops();
    CommitLogEntry entry;

    r = system(SHELL_DEL" commit_log_testfile* > errorlog.txt");
    (void)r;

    config = new CommitLogConfig(ops);
    clog = new CommitLog(std::string("commit_log_testfile"), config);

    // insert some docs
    for (i=0; i<n; ++i) {
        sprintf(keybuf, "key%06d", i);
        sprintf(valuebuf, "value%06d", i);
        entry.clear();
        entry.setSeqnum(i+1);
        entry.setKey(keybuf, strlen(keybuf)+1);
        entry.setBody(valuebuf, strlen(valuebuf)+1);
        clog->appendLogEntry(&entry, ret);
    }

    // commit and keep log ID
    uint64_t log_id = 0;
    clog->commitLog(1, 1, log_id);

    // insert more docs
    for (i=0; i<n; ++i) {
        sprintf(keybuf, "key%06d", i);
        sprintf(valuebuf, "value%06d", i);
        entry.clear();
        entry.setSeqnum(i+1);
        entry.setKey(keybuf, strlen(keybuf)+1);
        entry.setBody(valuebuf, strlen(valuebuf)+1);
        clog->appendLogEntry(&entry, ret);
    }

    // destroy logs upto (log_id - 1)
    clog->destroyLogUpto(log_id - 1);

    // close, re-open, and reconstruct
    delete clog;

    struct recover_callback_args args;
    memset(&args, 0x0, sizeof(args));
    clog = new CommitLog(std::string("commit_log_testfile"), config);
    clog->reconstructLog(recover_callback, &args);

    TEST_CHK(args.doc_count >= (uint64_t)n);
    TEST_CHK(args.doc_count < (uint64_t)n*2);
    TEST_CHK(args.commit_count == 1);

    delete clog;
    delete config;

    TEST_RESULT("destroy log test");
}

void read_log_test()
{
    TEST_INIT();

    int i, r, n=1000000;
    CommitLog *clog;
    CommitLogConfig *config;
    char keybuf[256], valuebuf[256];
    void *ret, *ret2;
    struct filemgr_ops *ops = get_filemgr_ops();
    CommitLogEntry entry;
    uint64_t log_id = 0, max_log_id = 0;
    uint64_t log_doc_counter[64];

    memset(&log_doc_counter, 0x0, sizeof(uint64_t) * 64);

    r = system(SHELL_DEL" commit_log_testfile* > errorlog.txt");
    (void)r;

    config = new CommitLogConfig(ops);
    clog = new CommitLog(std::string("commit_log_testfile"), config);

    // insert docs
    for (i=0; i<n; ++i) {
        sprintf(keybuf, "key%06d", i);
        sprintf(valuebuf, "value%06d", i);
        entry.clear();
        entry.setSeqnum(i+1);
        entry.setKey(keybuf, strlen(keybuf)+1);
        entry.setBody(valuebuf, strlen(valuebuf)+1);
        clog->appendLogEntry(&entry, ret, ret2, log_id, false);

        log_doc_counter[log_id]++;
        if (log_id > max_log_id) {
            max_log_id = log_id;
        }
    }

    uint64_t count_sum = 0;
    struct recover_callback_args args;

    for (uint64_t j=0; j<=max_log_id; ++j) {
        memset(&args, 0x0, sizeof(args));
        clog->readLog(j, recover_callback, &args);

        TEST_CHK(log_doc_counter[j] == args.doc_count);
        count_sum += log_doc_counter[j];
    }
    TEST_CHK(count_sum == static_cast<uint64_t>(n));

    delete clog;
    delete config;

    TEST_RESULT("read log test");
}

void commit_log_compression_test()
{
    TEST_INIT();

    int i, r, n=1000000;
    CommitLog *clog;
    CommitLogConfig *config;
    char keybuf[256], metabuf[256], valuebuf[256];
    void *ret;
    struct filemgr_ops *ops = get_filemgr_ops();
    CommitLogEntry entry;

    r = system(SHELL_DEL" commit_log_testfile* > errorlog.txt");
    (void)r;

    config = new CommitLogConfig(ops);
    config->compression = true;
    clog = new CommitLog(std::string("commit_log_testfile"), config);

    for (i=0; i<n; ++i) {
        sprintf(keybuf, "key%06d", i);
        sprintf(metabuf, "meta%06d", i);
        sprintf(valuebuf, "value%06d", i);
        entry.clear();
        entry.setSeqnum(i+1);
        entry.setKey(keybuf, strlen(keybuf)+1);
        entry.setMeta(metabuf, strlen(metabuf)+1);
        entry.setBody(valuebuf, strlen(valuebuf)+1);
        clog->appendLogEntry(&entry, ret);

        if (i == n/2) {
            clog->commitLog(1, 1);
        }
    }
    clog->commitLog(2, 1);

    // now free commit log instance and re-load
    delete clog;

    struct recover_callback_args args;
    memset(&args, 0x0, sizeof(args));

    // recover without given uncompression buffer
    clog = new CommitLog(std::string("commit_log_testfile"), config);
    clog->reconstructLog(recover_callback, &args);

    TEST_CHK(args.doc_count == static_cast<uint64_t>(n));
    TEST_CHK(args.commit_count == 2);

    delete clog;

    memset(&args, 0x0, sizeof(args));
    args.uncomp_buflen = 1024*1024;
    args.uncomp_buf = (char*)malloc(args.uncomp_buflen);

    // recover with given uncompression buffer
    clog = new CommitLog(std::string("commit_log_testfile"), config);
    clog->reconstructLog(recover_callback, &args);

    TEST_CHK(args.doc_count == static_cast<uint64_t>(n));
    TEST_CHK(args.commit_count == 2);

    delete clog;
    delete config;

    free(args.uncomp_buf);

    TEST_RESULT("commit log compression test");
}

int main()
{
    basic_operation_test();
    single_writer_speed_test();
    racing_multi_writers_test();
    recover_commit_log_test();
    large_document_test();
    destroy_log_test();
    read_log_test();
    commit_log_compression_test();

    return 0;
}

