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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>

#if !defined(WIN32) && !defined(_WIN32)
#include <dirent.h>
#include <unistd.h>
#include <sys/mman.h>
#endif

#include "commit_log.h"
#include "fdb_internal.h"
#include "docio.h"

#ifdef _DOC_COMP
#include "snappy-c.h"
#endif

CommitLogFile::CommitLogFile(uint64_t _id,
                             CommitLog *_parent,
                             uint64_t _size_limit,
                             struct filemgr_ops *_file_ops,
                             crc_mode_e _crc_mode)
    : id(_id),
      curOffset(0),
      writable(true),
      addr(nullptr),
      aux(nullptr),
      parent(_parent),
      fileSizeLimit(_size_limit),
      fileOps(_file_ops),
      crcMode(_crc_mode)
{
    char id_cstr[64];
    fdb_status fs;

    sprintf(id_cstr, ".log%08" _F64, id);
    logFileName = parent->getDbName() + std::string(id_cstr);

    fs = fileOps->open(logFileName.c_str(), &fopsHandle, O_CREAT | O_RDWR, 0666);
    if (fs != FDB_RESULT_SUCCESS) {
        writable = false;
        return;
    }

    cs_off_t file_offset = fileOps->goto_eof(fopsHandle);
    if (file_offset) {
        // file already exists
        fileSizeLimit = file_offset;
        curOffset = file_offset;
        // existing files are immutable
        writable = false;
    } else {
        // allocate file blocks before calling mmap()
        ssize_t r = fileOps->pwrite(fopsHandle, (void*)"x", 1, fileSizeLimit-1);
        if (r != 1) {
            fileOps->close(fopsHandle);
            writable = false;
            return;
        }
    }

    addr = fileOps->mmap(fopsHandle, fileSizeLimit, &aux);
    if (addr == NULL) {
        fileOps->close(fopsHandle);
        writable = false;
        return;
    }
}

CommitLogFile::~CommitLogFile()
{
    fileOps->munmap(fopsHandle, addr, fileSizeLimit, aux);
    fileOps->close(fopsHandle);
}

bool CommitLogFile::isWritable() {
    return writable;
}

bool CommitLogFile::setImmutable() {
    bool expected = true;
    if (writable.compare_exchange_strong(expected, false)) {
        // succeeded
        return true;
    }
    // failed (already immutable)
    return false;
}

bool CommitLogFile::allocSpace(uint64_t size, uint64_t& offset_out)
{
    do {
        uint64_t expected;

        if (!writable) {
            // already became immutable (by other thread)
            return false;
        }

        expected = curOffset;
        if (expected + size > fileSizeLimit) {
            // exceeds the file size limit
            setImmutable();
            return false;
        }

        if (curOffset.compare_exchange_strong(expected, expected+size)) {
            offset_out = expected;
            break;
        }
    } while (true);

    return true;
}

fdb_status CommitLogFile::writeEntry(CommitLogEntry *entry,
                                     uint64_t offset,
                                     void*& ptr_value,
                                     void*& ptr_entry,
                                     bool sync)
{
    if (!addr) {
        // mmap has not been initiated.
        return FDB_RESULT_WRITE_FAIL;
    }

    ptr_entry = static_cast<uint8_t*>(addr) + offset;

    entry->exportRawData(ptr_entry, ptr_value, crcMode);

    if (sync) {
        fdb_status fs = this->fsyncLogFile();
        if (fs != FDB_RESULT_SUCCESS) {
            return fs;
        }
    }

    return FDB_RESULT_SUCCESS;
}

void CommitLogFile::scanLogFile(CommitLogScanCallback cb, void *ctx)
{
    void* ptr_value;
    uint64_t offset = 0;
    uint64_t raw_size;
    bool is_valid;
    fdb_status fs;
    CommitLogEntry log_entry;
    CommitLogScanDecision sd;

    if (!addr) {
        // mmap has not been initiated.
        return;
    }

    while (offset < fileSizeLimit) {
        // check if there is enough space for length meta structure
        if (offset + CommitLogEntry::getLengthMetaSize() > fileSizeLimit) {
            // no more docs
            return;
        }

        is_valid = CommitLogEntry::isValidEntry((uint8_t*)addr + offset, crcMode, raw_size);
        if (!is_valid) {
            // no more docs .. abort scanning
            return;
        }

        // check if raw size is valid
        if (offset + raw_size > fileSizeLimit) {
            // length meta corrupted
            return;
        }

        // read the raw data
        log_entry.clear();
        fs = log_entry.importRawData((uint8_t*)addr + offset, ptr_value, crcMode);
        if (fs != FDB_RESULT_SUCCESS) {
            // log entry corrupted
            return;
        }

        // invoke callback function with the log entry
        sd = cb(&log_entry, log_entry.checkFlag(DOCIO_SYSTEM),
                ptr_value, (uint8_t*)addr + offset, id, ctx);
        if (sd == CommitLogScanDecision::COMMIT_LOG_SCAN_ABORT) {
            return;
        }

        offset += raw_size;
    }
}

fdb_status CommitLogFile::fsyncLogFile()
{
    return static_cast<fdb_status>(fileOps->fsync(fopsHandle));
}


CommitLogEntry::CommitLogEntry(struct docio_object *doc)
{
    length = doc->length;
    timestamp = doc->timestamp;
    seqnum = doc->seqnum;
    txnId = 0; // global transaction
    key = doc->key;
    meta = doc->meta;
    body = doc->body;
    localKeyBuf = localValueBuf = nullptr;
    compBuf = uncompBuf = nullptr;
    compBufLen = 0;
}

CommitLogEntry::CommitLogEntry(void *_key, size_t _keylen,
                               void *_meta, size_t _metalen,
                               void *_body, size_t _bodylen,
                               fdb_seqnum_t _seqnum,
                               timestamp_t _timestamp,
                               uint64_t _txn_id)
{
    length.keylen = _keylen;
    length.metalen = _metalen;
    length.bodylen = _bodylen;
    key = _key;
    meta = _meta;
    body = _body;
    seqnum = _seqnum;
    timestamp = _timestamp;
    txnId = _txn_id;
    localKeyBuf = localValueBuf = nullptr;
    compBuf = uncompBuf = nullptr;
    compBufLen = 0;
}

CommitLogEntry::CommitLogEntry(void *_key, size_t _keylen,
                               void *_body, size_t _bodylen,
                               fdb_seqnum_t _seqnum,
                               timestamp_t _timestamp,
                               uint64_t _txn_id)
{
    CommitLogEntry(_key, _keylen, nullptr, 0, _body, _bodylen,
                   _seqnum, _timestamp, _txn_id);
}

CommitLogEntry::CommitLogEntry(void *_key, size_t _keylen,
                               fdb_seqnum_t _seqnum,
                               timestamp_t _timestamp,
                               uint64_t _txn_id)
{
    CommitLogEntry(_key, _keylen, nullptr, 0, nullptr, 0,
                   _seqnum, _timestamp, _txn_id);
}

CommitLogEntry::~CommitLogEntry()
{
    free(localKeyBuf);
    free(localValueBuf);
    free(compBuf);
    free(uncompBuf);
}

void CommitLogEntry::clear()
{
    key = meta = body = nullptr;
    memset(&length, 0x0, sizeof(length));
    timestamp = 0;
    seqnum = 0;
    txnId = 0;
    free(compBuf);
    free(uncompBuf);
    compBuf = nullptr;
    uncompBuf = nullptr;
    compBufLen = 0;
}

void CommitLogEntry::setKey(void *_key, size_t _keylen) {
    key = _key;
    length.keylen = _keylen;
}

void CommitLogEntry::setMeta(void *_meta, size_t _metalen) {
    meta = _meta;
    length.metalen = _metalen;
}

void CommitLogEntry::setBody(void *_body, size_t _bodylen) {
    body = _body;
    length.bodylen = _bodylen;
}

int CommitLogEntry::uncompressLogEntry(char*& buf, size_t& buflen)
{
#ifdef _DOC_COMP
    if (!uncompBuf) {
        // uncompress data
        int ret;

        if (!buf) {
            // buffer is not given .. allocate local buffer (i.e., uncompBuf)
            buflen = length.keylen + length.metalen + length.bodylen;
            uncompBuf = (char*)malloc(buflen);
            buf = uncompBuf;
        }
        // if buffer is given, uncompress the data into the given buffer.

        ret = snappy_uncompress((char*)key, length.bodylen_ondisk,
                                (char*)buf, &buflen);
        if (ret < 0) {
            // uncompression fail
            fdb_log(NULL, FDB_RESULT_COMPRESSION_FAIL,
                    "Error in decompressing log entry 0x%" _X64,
                    (uint64_t)this);
            free(uncompBuf);
            uncompBuf = nullptr;
            return ret;
        }

    } else {
        // previous uncompressed buffer already exists.
        buf = uncompBuf;
        buflen = length.keylen + length.metalen + length.bodylen;
    }
#endif

    return buflen;
}

void* CommitLogEntry::getKey(char* buf, size_t buflen) {

#ifdef _DOC_COMP
    if (checkFlag(DOCIO_COMPRESSED)) {
        int ret;
        ret = uncompressLogEntry(buf, buflen);
        if (ret < 0) {
            return NULL;
        }
        // 'key' is located at the offset 0
        return buf;
    }
#endif

    return key;
}

void* CommitLogEntry::getMeta(char* buf, size_t buflen) {

#ifdef _DOC_COMP
    if (checkFlag(DOCIO_COMPRESSED)) {
        int ret;
        ret = uncompressLogEntry(buf, buflen);
        if (ret < 0) {
            return NULL;
        }
        // 'meta' is located at the offset length.keylen
        return buf + length.keylen;
    }
#endif

    return meta;
}

void* CommitLogEntry::getBody(char* buf, size_t buflen) {
#ifdef _DOC_COMP
    if (checkFlag(DOCIO_COMPRESSED)) {
        int ret;
        ret = uncompressLogEntry(buf, buflen);
        if (ret < 0) {
            return NULL;
        }
        // 'body' is located at the offset length.keylen + length.metalen
        return buf + length.keylen + length.metalen;
    }
#endif

    return body;
}

void CommitLogEntry::setSeqnum(fdb_seqnum_t _seqnum) {
    seqnum = _seqnum;
}

void CommitLogEntry::setTimestamp(timestamp_t _timestamp) {
    timestamp = _timestamp;
}

void CommitLogEntry::setTxnId(uint64_t _txn_id) {
    txnId = _txn_id;
}

fdb_status CommitLogEntry::calculateBodyLenOnDisk(bool compression) {

#ifdef _DOC_COMP
    if (compression && !checkFlag(DOCIO_SYSTEM)) {
        int ret;
        size_t compressed_len = 0;
        size_t offset = 0;
        size_t uncomp_len = length.keylen + length.metalen + length.bodylen;
        char *uncomp_buf;

        compBufLen = snappy_max_compressed_length(uncomp_len);
        compBuf = (char*)malloc(compBufLen);

        uncomp_buf = (char*)malloc(uncomp_len);
        memcpy(uncomp_buf + offset, key, length.keylen);
        offset += length.keylen;
        memcpy(uncomp_buf + offset, meta, length.metalen);
        offset += length.metalen;
        memcpy(uncomp_buf + offset, body, length.bodylen);
        offset += length.bodylen;

        compressed_len = compBufLen;
        ret = snappy_compress((char*)uncomp_buf, offset, compBuf, &compressed_len);
        free(uncomp_buf);

        if (ret < 0) {
            free(compBuf);
            compBuf = nullptr;
            compBufLen = 0;
            return FDB_RESULT_COMPRESSION_FAIL;
        }

        // successfully compressed
        length.bodylen_ondisk = compressed_len;
        setFlag(DOCIO_COMPRESSED);
        return FDB_RESULT_SUCCESS;
    }
#endif

    length.bodylen_ondisk = length.bodylen;
    return FDB_RESULT_SUCCESS;
}

uint64_t CommitLogEntry::getRawSize() {
    uint64_t ret = 0;

    ret += sizeof(struct docio_length);
    if (checkFlag(DOCIO_COMPRESSED)) {
        ret += length.bodylen_ondisk;
    } else {
        ret += length.keylen + length.metalen + length.bodylen_ondisk;
    }
    ret += sizeof(txnId);
    ret += sizeof(timestamp_t);
    ret += sizeof(fdb_seqnum_t);
    // CRC
    ret += sizeof(uint32_t);

    return ret;
}

uint64_t CommitLogEntry::getRawSize(struct docio_length length) {
    uint64_t ret = 0;

    ret += sizeof(struct docio_length);
    if (length.flag & DOCIO_COMPRESSED) {
        ret += length.bodylen_ondisk;
    } else {
        ret += length.keylen + length.metalen + length.bodylen_ondisk;
    }
    ret += sizeof(uint64_t);
    ret += sizeof(timestamp_t);
    ret += sizeof(fdb_seqnum_t);
    // CRC
    ret += sizeof(uint32_t);

    return ret;
}

void CommitLogEntry::exportRawData(void *addr,
                                   void*& ptr_value,
                                   crc_mode_e crc_mode)
{
    uint32_t crc, _crc;
    uint64_t offset = 0;
    uint64_t _txn_id;
    timestamp_t _timestamp;
    fdb_seqnum_t _seqnum;
    struct docio_length _length;

    // length meta data structure
    _length = DocioHandle::encodeLength_Docio(length);

    _length.checksum =
        get_checksum((uint8_t*)&_length,
                     sizeof(keylen_t) + sizeof(uint16_t) + sizeof(uint32_t)*2,
                     crc_mode) & 0xff;

    memcpy((uint8_t*)addr + offset, &_length, sizeof(struct docio_length));
    offset += sizeof(struct docio_length);

    // transaction ID
    _txn_id = _endian_encode(txnId);
    memcpy((uint8_t*)addr + offset, &_txn_id, sizeof(_txn_id));
    offset += sizeof(_txn_id);

    // timestamp
    _timestamp = _endian_encode(timestamp);
    memcpy((uint8_t*)addr + offset, &_timestamp, sizeof(_timestamp));
    offset += sizeof(_timestamp);

    // sequence number
    _seqnum = _endian_encode(seqnum);
    memcpy((uint8_t*)addr + offset, &_seqnum, sizeof(_seqnum));
    offset += sizeof(_seqnum);

#ifdef _DOC_COMP
    if (checkFlag(DOCIO_COMPRESSED)) {
        // compressed (key + metadata + body)
        ptr_value = (uint8_t*)addr + offset;

        memcpy((uint8_t*)addr + offset, compBuf, length.bodylen_ondisk);
        offset += length.bodylen_ondisk;

        free(compBuf);
        compBuf = nullptr;
        compBufLen = 0;
    }
#endif

    if (!checkFlag(DOCIO_COMPRESSED)) {
        // key
        memcpy((uint8_t*)addr + offset, key, length.keylen);
        offset += length.keylen;

        // metadata
        if (length.metalen) {
            memcpy((uint8_t*)addr + offset, meta, length.metalen);
            offset += length.metalen;
        }

        ptr_value = (uint8_t*)addr + offset;

        // body
        if (length.bodylen) {
            memcpy((uint8_t*)addr + offset, body, length.bodylen);
            offset += length.bodylen;
        }
    }

    // CRC
    crc = get_checksum((uint8_t*)addr, offset, crc_mode);
    _crc = _endian_encode(crc);
    memcpy((uint8_t*)addr + offset, &_crc, sizeof(_crc));
}

fdb_status CommitLogEntry::importRawData(void *addr,
                                         void*& ptr_value,
                                         crc_mode_e crc_mode)
{
    uint32_t crc, crc_file, _crc_file;
    uint64_t offset = 0;
    uint64_t _txn_id;
    timestamp_t _timestamp;
    fdb_seqnum_t _seqnum;
    struct docio_length _length;

    // length meta data structure
    memcpy(&_length, (uint8_t*)addr + offset, sizeof(struct docio_length));
    length = DocioHandle::decodeLength_Docio(_length);
    offset += sizeof(struct docio_length);

    // transaction ID
    memcpy(&_txn_id, (uint8_t*)addr + offset, sizeof(_txn_id));
    txnId = _endian_decode(_txn_id);
    offset += sizeof(_txn_id);

    // timestamp
    memcpy(&_timestamp, (uint8_t*)addr + offset, sizeof(_timestamp));
    timestamp = _endian_decode(_timestamp);
    offset += sizeof(_timestamp);

    // sequence number
    memcpy(&_seqnum, (uint8_t*)addr + offset, sizeof(_seqnum));
    seqnum = _endian_decode(_seqnum);
    offset += sizeof(_seqnum);

#ifdef _DOC_COMP
    if (checkFlag(DOCIO_COMPRESSED)) {
        // compressed (key + metadata + body)
        ptr_value = (uint8_t*)addr + offset;
        offset += length.bodylen_ondisk;

        key = meta = body = ptr_value;
    }
#endif

    if (!checkFlag(DOCIO_COMPRESSED)) {
        // key
        key = (uint8_t*)addr + offset;
        offset += length.keylen;

        // metadata
        if (length.metalen) {
            meta = (uint8_t*)addr + offset;
            offset += length.metalen;
        }

        ptr_value = (uint8_t*)addr + offset;

        // body
        if (length.bodylen) {
            body = (uint8_t*)addr + offset;
            offset += length.bodylen;
        }
    }

    // CRC
    memcpy(&_crc_file, (uint8_t*)addr + offset, sizeof(_crc_file));
    crc_file = _endian_decode(_crc_file);
    crc = get_checksum((uint8_t*)addr, offset, crc_mode);
    if (crc != crc_file) {
        return FDB_RESULT_CHECKSUM_ERROR;
    }

    return FDB_RESULT_SUCCESS;
}

bool CommitLogEntry::isValidEntry(void *addr,
                                  crc_mode_e crc_mode,
                                  uint64_t& raw_size_out)
{
    uint8_t checksum;
    struct docio_length length, _length;

    // read from memory
    memcpy(&_length, addr, sizeof(_length));
    length = DocioHandle::decodeLength_Docio(_length);

    // calculate checksum
    checksum = get_checksum((uint8_t*)&_length,
                            sizeof(keylen_t) + sizeof(uint16_t) + sizeof(uint32_t)*2,
                            crc_mode) & 0xff;

    // check checksum
    if (checksum != length.checksum) {
        return false;
    }

    raw_size_out = CommitLogEntry::getRawSize(length);

    return true;
}

void CommitLogEntry::setCommitMarker(uint64_t revnum, uint64_t txn_id)
{
    size_t offset = 0;
    uint64_t log_version = COMMIT_LOG_CURRENT_VERSION;
    uint64_t dummy64;

    clear();

    if (!localKeyBuf) {
        localKeyBuf = (char*)calloc(64, sizeof(char));
    }
    if (!localValueBuf) {
        localValueBuf = (char*)calloc(64, sizeof(char));
    }

    sprintf(localKeyBuf, "commit_%" _F64, revnum);

    // << body structure >>
    // 0x00: version info (8 bytes)
    // 0x08: revnum (8 bytes)
    // 0x10: txn_id (8 bytes)
    dummy64 = _endian_encode(log_version);
    memcpy(localValueBuf + offset, &dummy64, sizeof(dummy64));
    offset += sizeof(dummy64);

    dummy64 = _endian_encode(revnum);
    memcpy(localValueBuf + offset, &dummy64, sizeof(dummy64));
    offset += sizeof(dummy64);

    dummy64 = _endian_encode(txn_id);
    memcpy(localValueBuf + offset, &dummy64, sizeof(dummy64));
    offset += sizeof(dummy64);

    setKey(localKeyBuf, strlen(localKeyBuf)+1);
    setBody(localValueBuf, offset);
    setFlag(DOCIO_SYSTEM);
}

bool CommitLogEntry::getCommitMarker(uint64_t& revnum, uint64_t& txn_id)
{
    size_t offset = 0;
    uint64_t log_version;
    uint64_t dummy64;

    if (!checkFlag(DOCIO_SYSTEM)) {
        // not a system doc
        return false;
    }

    if (memcmp(key, "commit_", 7)) {
        // not a commit system doc
        return false;
    }

    // version info
    memcpy(&dummy64, (uint8_t*)body + offset, sizeof(dummy64));
    log_version = _endian_decode(dummy64);
    (void)log_version;
    offset += sizeof(dummy64);

    // commit revision number
    memcpy(&dummy64, (uint8_t*)body + offset, sizeof(dummy64));
    revnum = _endian_decode(dummy64);
    offset += sizeof(dummy64);

    // transaction ID
    memcpy(&dummy64, (uint8_t*)body + offset, sizeof(dummy64));
    txn_id = _endian_decode(dummy64);

    return true;
}

CommitLog::CommitLog()
    : config(),
      idCounter(0),
      curFile(nullptr)
{ }

CommitLog::CommitLog(std::string _dbname,
                     CommitLogConfig *_config)
    : config(_config),
      dbName(_dbname),
      idCounter(0),
      curFile(nullptr)
{ }

CommitLog::~CommitLog()
{
    std::lock_guard<std::mutex> lock(logManagementLock);

    auto entry = files.begin();
    CommitLogFile *target_file;

    while (entry != files.end()) {
        target_file = *entry;
        entry = files.erase(entry);

        delete target_file;
    }
}

inline
fdb_status CommitLog::_appendLogEntry(CommitLogEntry *entry,
                                      void*& ptr_value,
                                      void*& ptr_entry,
                                      uint64_t& log_id,
                                      bool sync)
{
    uint64_t offset;
    uint64_t entry_size;
    bool res = false;
    CommitLogFile *target_file = curFile;
    fdb_status fs;

    fs = entry->calculateBodyLenOnDisk(config->compression);
    if (fs == FDB_RESULT_COMPRESSION_FAIL) {
        fdb_log(NULL, FDB_RESULT_COMPRESSION_FAIL,
                "Error in compressing the log entry of key '%s'",
                (char *)entry->getKey());
        return fs;
    }

    if ( !target_file ) {
        createNewLogFile();
        target_file = curFile;
    }

    entry_size = entry->getRawSize();
    if (entry_size > config->fileSizeLimit) {
        // a single doc size is greater than the mmap file size

        // make the current log file immutable
        curFile.load()->setImmutable();

        // create a new log file whose size is 'entry_size + regular file size'.
        // Allocate enough space to handle the case that other concurrent writer
        // appends its log before the current writer (i.e., caller of this
        // function) completes this function.
        createNewLogFile(entry_size + config->fileSizeLimit);
        target_file = curFile;
    }

    do {
        res = target_file->allocSpace(entry->getRawSize(), offset);
        if (!res) {
            if (entry_size > config->fileSizeLimit) {
                createNewLogFile(entry_size + config->fileSizeLimit);
            } else {
                createNewLogFile();
            }
            target_file = curFile;
        }
    } while (!res);

    if (sync) {
        // call fsync for all previous non-synced files
        // (except for the current file)

        // remove from 'dirtyFiles' with lock first, and then
        // call fsync() without lock next.
        std::list<CommitLogFile*> sync_list;
        CommitLogFile *log_file;

        {
            std::lock_guard<std::mutex> lock(logManagementLock);
            auto log_file_entry = dirtyFiles.begin();
            while ( log_file_entry != dirtyFiles.end() ) {
                log_file = *log_file_entry;
                if ( log_file->getLogId() >= target_file->getLogId() ) {
                    break;
                }

                // remove from 'dirtyFiles' and insert into 'sync_list'.
                log_file_entry = dirtyFiles.erase(log_file_entry);
                sync_list.push_back(log_file);
            }
        }

        // TODO: what if log files are destroyed by other thread?
        auto sync_entry = sync_list.begin();
        while ( sync_entry != sync_list.end() ) {
            log_file = *sync_entry;
            if ( log_file->getLogId() >= target_file->getLogId() ) {
                break;
            }
            log_file->fsyncLogFile();
            sync_entry = sync_list.erase(sync_entry);
        }
    }

    log_id = target_file->getLogId();
    return target_file->writeEntry(entry, offset, ptr_value, ptr_entry, sync);
}

fdb_status CommitLog::appendLogEntry(CommitLogEntry *entry,
                                     void*& ptr_value,
                                     bool sync)
{
    uint64_t log_id = 0;
    void *ptr_entry = nullptr;
    return _appendLogEntry(entry, ptr_value, ptr_entry, log_id, sync);
}

fdb_status CommitLog::appendLogEntry(CommitLogEntry *entry,
                                     void*& ptr_value,
                                     void*& ptr_entry,
                                     bool sync)
{
    uint64_t log_id = 0;
    return _appendLogEntry(entry, ptr_value, ptr_entry, log_id, sync);
}

fdb_status CommitLog::appendLogEntry(CommitLogEntry *entry,
                                     void*& ptr_value,
                                     void*& ptr_entry,
                                     uint64_t& log_id,
                                     bool sync)
{
    return _appendLogEntry(entry, ptr_value, ptr_entry, log_id, sync);
}

inline
fdb_status CommitLog::_commitLog(uint64_t revnum, uint64_t txn_id, uint64_t& log_id)
{
    // append a system doc for commitLog
    CommitLogEntry commit_entry;

    commit_entry.setCommitMarker(revnum, txn_id);

    void *ptr_value = nullptr;
    void *ptr_entry = nullptr;
    return appendLogEntry(&commit_entry, ptr_value, ptr_entry,
                          log_id, config->sync);
}

fdb_status CommitLog::commitLog(uint64_t revnum, uint64_t txn_id)
{
    uint64_t log_id = 0;
    return _commitLog(revnum, txn_id, log_id);
}

fdb_status CommitLog::commitLog(uint64_t revnum, uint64_t txn_id, uint64_t& log_id)
{
    return _commitLog(revnum, txn_id, log_id);
}

fdb_status CommitLog::createNewLogFile(uint64_t excess_size)
{
    if ( curFile.load() == nullptr || !curFile.load()->isWritable() ) {
        // writable log file doesn't exist

        // create & open a new mmap file
        std::lock_guard<std::mutex> lock(logManagementLock);

        if (curFile.load() && curFile.load()->isWritable()) {
            return FDB_RESULT_SUCCESS;
        }

        CommitLogFile *latest = nullptr;

        if (excess_size) {
            // we need a log file with larger limit
            latest = new CommitLogFile(idCounter, this,
                                       excess_size,
                                       config->fileOps,
                                       config->crcMode);
        } else {
            latest = new CommitLogFile(idCounter, this,
                                       config->fileSizeLimit,
                                       config->fileOps,
                                       config->crcMode);
        }

        if (!latest->isWritable()) {
            // creation failed
            return FDB_RESULT_OPEN_FAIL;
        }

        files.push_back(latest);
        dirtyFiles.push_back(latest);
        curFile = latest;
        idCounter++;
    }

    return FDB_RESULT_SUCCESS;
}

void CommitLog::parseFileName(std::string& name_str,
                              std::map<uint64_t, std::string>& file_map)
{
    // get log ID from the file name
    // 1) get the position of ".log".
    size_t ext_pos = name_str.rfind(".log");
    if (ext_pos == std::string::npos) {
        // name_str doesn't contain ".log".
        return;
    }

    // 2) parse & extract log ID number
    std::string id_str = name_str.substr(ext_pos+4);
    uint64_t log_id = std::stoi(id_str);

    // insert {id, filename} into the given map
    file_map.insert( std::make_pair(log_id, name_str) );
}

void CommitLog::scanLogFiles(std::map<uint64_t, std::string>& file_map,
                             uint64_t& min_id,
                             uint64_t& max_id)
{
    // find all log files in the directory
    std::string query;
    std::string name_str;

#if !defined(WIN32) && !defined(_WIN32)
    DIR *dir_info;
    struct dirent *dir_entry;
    std::string dir_name;
    size_t pos;

    pos = dbName.find_last_of("/\\");
    if (pos != std::string::npos) {
        dir_name = dbName.substr(0, pos);
    } else {
        dir_name = "./";
    }

    dir_info = opendir(dir_name.c_str());
    if (dir_info != NULL) {
        while ((dir_entry = readdir(dir_info))) {

            // log file should include sub-string ".log"
            name_str = std::string(dir_entry->d_name);
            query = dbName + ".log";
            pos = name_str.find(query);
            if (pos != std::string::npos) {
                parseFileName(name_str, file_map);
            }
        }
        closedir(dir_info);
    }

#else
    // Windows
    WIN32_FIND_DATA filedata;
    HANDLE hfind;

    // find all files start with '[dbname].log'
    query = dbName + ".log*";
    hfind = FindFirstFile(query.c_str(), &filedata);
    while (hfind != INVALID_HANDLE_VALUE) {

        name_str = std::string(filedata.cFileName);
        parseFileName(name_str, file_map);

        if (!FindNextFile(hfind, &filedata)) {
            FindClose(hfind);
            hfind = INVALID_HANDLE_VALUE;
        }
    }

#endif

    min_id = max_id = 0;
    {
        auto entry = file_map.begin();
        if (entry != file_map.end()) {
            min_id = (uint64_t)entry->first;
        }
    }

    {
        auto entry = file_map.rbegin();
        if (entry != file_map.rend()) {
            max_id = (uint64_t)entry->first;
        }
    }
}

fdb_status CommitLog::reconstructLog(CommitLogScanCallback cb, void *ctx)
{
    std::lock_guard<std::mutex> lock(logManagementLock);

    uint64_t min_id, max_id;
    std::map<uint64_t, std::string> file_map;
    CommitLogFile *log_file;

    if (files.begin() != files.end()) {
        // log files already exists
        return FDB_RESULT_SUCCESS;
    }

    scanLogFiles(file_map, min_id, max_id);

    for (auto &entry : file_map) {
        log_file = new CommitLogFile(entry.first, this, config->fileSizeLimit,
                                     config->fileOps, config->crcMode);
        log_file->scanLogFile(cb, ctx);

        // insert into 'files' only, those files don't need to be synced.
        files.push_back(log_file);
    }

    idCounter = max_id+1;
    curFile = nullptr;

    return FDB_RESULT_SUCCESS;
}

fdb_status CommitLog::readLog(uint64_t log_id, CommitLogScanCallback cb, void *ctx)
{
    CommitLogFile *target_file = nullptr;

    // find log file from 'files' list
    {
        std::lock_guard<std::mutex> lock(logManagementLock);
        CommitLogFile *log_file;

        for (auto &logfile_entry : files) {
            log_file = logfile_entry;
            if (log_file->getLogId() == log_id) {
                target_file = log_file;
                break;
            }
            if (log_file->getLogId() > log_id) {
                // log file for 'log_id' does not exist
                break;
            }
        }
    }

    if (target_file) {
        target_file->scanLogFile(cb, ctx);
        return FDB_RESULT_SUCCESS;
    }

    return FDB_RESULT_LOG_FILE_NOT_FOUND;
}

fdb_status CommitLog::destroyLogUpto(uint64_t log_id_upto)
{

    CommitLogFile *log_file;
    std::string log_filename;
    std::list<CommitLogFile*> destroy_list;

    // erase from each list with lock, and then
    // remove file without the lock.
    {
        std::lock_guard<std::mutex> lock(logManagementLock);

        auto dirtyLogEntry = dirtyFiles.begin();
        while (dirtyLogEntry != dirtyFiles.end()) {
            log_file = *dirtyLogEntry;
            if (log_file->getLogId() <= log_id_upto) {
                dirtyLogEntry = dirtyFiles.erase(dirtyLogEntry);
            } else {
                break;
            }
        }

        auto logEntry = files.begin();
        while (logEntry != files.end()) {
            log_file = *logEntry;
            if (log_file->getLogId() <= log_id_upto) {
                // erase from 'files' and insert into 'destroy_list'.
                logEntry = files.erase(logEntry);
                destroy_list.push_back(log_file);
            } else {
                break;
            }
        }
    }

    for (auto &logEntry : destroy_list) {
        log_file = logEntry;

        log_filename = log_file->getFileName();
        delete log_file;

        int ret = remove(log_filename.c_str());
        if (ret != 0) {
            char errno_msg[512];
            config->fileOps->get_errno_str(
                static_cast<fdb_fileops_handle>(NULL), errno_msg, 512);

            fdb_log(NULL, FDB_RESULT_COMPRESSION_FAIL,
                    "Error status code: %d, Error in REMOVE on a "
                    "log file '%s', %s",
                    ret, log_filename.c_str(), errno_msg);

        }
    }

    return FDB_RESULT_SUCCESS;
}

