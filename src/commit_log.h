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

#pragma once

#include <string>
#include <list>
#include <mutex>

#include "libforestdb/forestdb.h"
#include "common.h"
#include "internal_types.h"
#include "filemgr_ops.h"
#include "checksum.h"
#include "docio.h"

#define COMMIT_LOG_CURRENT_VERSION (0x0)

class CommitLog;

class CommitLogEntry;

/**
 * Commit Log scanning decision.
 * If COMMIT_LOG_SCAN_ABORT is returned by callback function, then scanning the
 * log file is stopped immediately, although there are remaining entries in the
 * rest of the log file space.
 */
enum class CommitLogScanDecision {
    COMMIT_LOG_SCAN_CONTINUE,
    COMMIT_LOG_SCAN_ABORT
};

/**
 * Pointer type definition of a callback function for commit log file scanning.
 *
 * @param entry Log entry read from the log file.
 * @param is_system_doc True if the log entry contains system information.
 * @param ptr_value Pointer to value.
 * @param ptr_entry Pointer to the memory location where the log entry is stored.
 * @param log_id ID of the commit log file where the log entry belongs to.
 * @param ctx Pointer to the context given by user.
 * @return Decision by callback function.
 */
typedef CommitLogScanDecision
        (*CommitLogScanCallback)(CommitLogEntry* entry,
                                 bool is_system_doc,
                                 void* ptr_value,
                                 void* ptr_entry,
                                 uint64_t log_id,
                                 void* ctx);

/**
 * Commit log file class definition.
 * Each class instance corresponds to each commit log file.
 */
class CommitLogFile {
public:
    /**
     * Constructor.
     *
     * @param _id ID of the commit log file.
     * @param _parent Pointer to the owner commit log instance.
     * @param _size_limit Maximum file size of the commit log file.
     * @param _file_ops Pointer to FileMgr ops wrapper instance.
     * @param _crc_mode CRC mode.
     */
    CommitLogFile(uint64_t _id,
                  CommitLog *_parent,
                  uint64_t _size_limit,
                  struct filemgr_ops *_file_ops,
                  crc_mode_e _crc_mode);

    /**
     * Destructor.
     */
    ~CommitLogFile();

    /**
     * Check if the log file is writable.
     *
     * @return True if writable.
     */
    bool isWritable();

    /**
     * Atomically clear the writable flag of the log file.
     *
     * @return False if the log file is already immutable.
     */
    bool setImmutable();

    /**
     * Atomically allocate space for the given size.
     *
     * @param size Size of the region to be allocated.
     * @param offset_out Reference to byte offset of the region that will be
     *        allocated as a result of this function call.
     * @return True if allocation succeeded.
     */
    bool allocSpace(uint64_t size, uint64_t& offset_out);

    /**
     * Write a log entry into the given byte offset of the log file.
     *
     * @param entry Log entry to be written.
     * @param offset Byte offset where the log entry will be written.
     * @param ptr_value Reference to the pointer to the memory location where
     *        value will be store as a result of this function call.
     * @param ptr_entry Reference to the pointer to the memory location where
     *        log entry will be store as a result of this function call.
     * @param sync Flag to call fsync() after writing the log entry.
     * @return FDB_RESULT_SUCCESS on success.
     */
    fdb_status writeEntry(CommitLogEntry *entry,
                          uint64_t offset,
                          void*& ptr_value,
                          void*& ptr_entry,
                          bool sync = false);

    /**
     * Scan the given commit log file.
     *
     * @param cb Callback function that will be invoked for every log entry.
     * @param ctx Context data given by user.
     */
    void scanLogFile(CommitLogScanCallback cb, void *ctx);

    /**
     * Invoke fsync() on the log file.
     *
     * @return FDB_RESULT_SUCCESS on success.
     */
    fdb_status fsyncLogFile();

    std::string getFileName() const {
        return logFileName;
    }

    uint64_t getLogId() const {
        return id;
    }

private:
    // Log ID.
    uint64_t id;
    // Commit log file name.
    std::string logFileName;
    // Current byte offset of the log file.
    std::atomic<uint64_t> curOffset;
    // Flag that indicates if the log file is writable.
    std::atomic<bool> writable;
    // Pointer to memory-mapped location.
    void *addr;
    // Used for windows mmap handle.
    void *aux;
    // Pointer to the owner commit log instance.
    CommitLog *parent;
    // Maximum log file size.
    uint64_t fileSizeLimit;
    // Pointer to FileMgr ops wrapper instance.
    struct filemgr_ops *fileOps;
    // File ops handle for the log file.
    fdb_fileops_handle fopsHandle;
    // CRC mode.
    crc_mode_e crcMode;
};



/**
 * Commit log entry class definition.
 */
class CommitLogEntry {
public:

    /**
     * Default constructor.
     */
    CommitLogEntry() :
        timestamp(0), seqnum(0), key(nullptr), meta(nullptr), body(nullptr),
        txnId(0), localKeyBuf(nullptr), localValueBuf(nullptr),
        compBuf(nullptr), uncompBuf(nullptr), compBufLen(0)
    {
        memset(&length, 0x0, sizeof(length));
    }

    /**
     * Construct a log entry from the given DocIO object.
     *
     * @param doc Pointer to DocIo object.
     */
    CommitLogEntry(struct docio_object *doc);

    /**
     * Construct a log entry using the given data.
     *
     * @param _key Pointer to key.
     * @param _keylen Key length.
     * @param _meta Pointer to meta data.
     * @param _metalen Meta length.
     * @param _body Pointer to value.
     * @param _bodylen Value length.
     * @param _seqnum Sequence number.
     * @param _timestamp Time-stamp.
     * @param _txn_id Transaction ID.
     */
    CommitLogEntry(void *_key, size_t _keylen,
                   void *_meta, size_t _metalen,
                   void *_body, size_t _bodylen,
                   fdb_seqnum_t _seqnum,
                   timestamp_t _timestamp = 0,
                   uint64_t _txn_id = 0);

    CommitLogEntry(void *_key, size_t _keylen,
                   void *_body, size_t _bodylen,
                   fdb_seqnum_t _seqnum,
                   timestamp_t _timestamp = 0,
                   uint64_t _txn_id = 0);

    CommitLogEntry(void *_key, size_t _keylen,
                   fdb_seqnum_t _seqnum,
                   timestamp_t _timestamp = 0,
                   uint64_t _txn_id = 0);

    // Destructor
    ~CommitLogEntry();

    // Clear all member variable of the log entry
    void clear();

    void setKey(void *_key, size_t _keylen);

    void setMeta(void *_meta, size_t _metalen);

    void setBody(void *_body, size_t _bodylen);

    void setSeqnum(fdb_seqnum_t _seqnum);

    void setTimestamp(timestamp_t _timestamp);

    void setTxnId(uint64_t _txn_id);

    uint8_t getFlag() const {
        return length.flag;
    }

    bool checkFlag(uint8_t _mask) {
        return (_mask & length.flag);
    }

    void setFlag(uint8_t _mask) {
        length.flag |= _mask;
    }

    void clearFlag(uint8_t _mask) {
        length.flag &= ~_mask;
    }

    void resetFlag() {
        length.flag = 0x0;
    }

    bool isCompressed() {
        return length.flag & DOCIO_COMPRESSED;
    }

    /**
     * Calculate on-disk body length. If compression is disabled, it is same
     * as the actual body length.
     */
    fdb_status calculateBodyLenOnDisk(bool compression = false);

    /**
     * Get key of the log entry.
     *
     * @param buf Temporary buffer for uncompression. It should be bigger than
     *        the sum of key length, meta data length, and value length.
     *        If not manually given, log entry allocates and uses its local buffer.
     * @param buflen Length of the temporary buffer.
     * @return Pointer to key.
     */
    void* getKey(char* buf = NULL, size_t buflen = 0);

    /**
     * Get meta data of the log entry.
     *
     * @param buf Temporary buffer for uncompression. It should be bigger than
     *        the sum of key length, meta data length, and value length.
     *        If not manually given, log entry allocates and uses its local buffer.
     * @param buflen Length of the temporary buffer.
     * @return Pointer to meta data.
     */
    void* getMeta(char* buf = NULL, size_t buflen = 0);

    /**
     * Get body (value) of the log entry.
     *
     * @param buf Temporary buffer for uncompression. It should be bigger than
     *        the sum of key length, meta data length, and value length.
     *        If not manually given, log entry allocates and uses its local buffer.
     * @param buflen Length of the temporary buffer.
     * @return Pointer to body (value).
     */
    void* getBody(char* buf = NULL, size_t buflen = 0);

    keylen_t getKeyLen() const {
        return length.keylen;
    }

    uint16_t getMetaLen() const {
        return length.metalen;
    }

    uint32_t getBodyLen() const {
        return length.bodylen;
    }

    struct docio_length getLength() const {
        return length;
    }

    fdb_seqnum_t getSeqnum() const {
        return seqnum;
    }

    uint64_t getTxnId() const {
        return txnId;
    }

    timestamp_t getTimestamp() const {
        return timestamp;
    }

    /**
     * Calculate the raw data size of the log entry.
     */
    uint64_t getRawSize();

    /**
     * Calculate the raw data size of a log entry, using its length info.
     */
    static uint64_t getRawSize(struct docio_length length);

    /**
     * Return the size of length meta data structure.
     */
    static inline size_t getLengthMetaSize() {
        return sizeof(struct docio_length);
    }

    /**
     * Export log entry data into the given memory address.
     *
     * @param addr Memory address.
     * @param ptr_value Reference to the pointer to memory region where value
     *        will be stored as a result of this function call.
     * @param crc_mode CRC mode.
     */
    void exportRawData(void* addr,
                       void*& ptr_value,
                       crc_mode_e crc_mode);

    /**
     * Import log entry data from the given memory address.
     *
     * @param addr Memory address.
     * @param ptr_value Reference to the pointer to memory region where value
     *        is located.
     * @param crc_mode CRC mode.
     * @return
     */
    fdb_status importRawData(void* addr,
                             void*& ptr_value,
                             crc_mode_e crc_mode);

    /**
     * Check if the log entry at the given memory address is valid or not.
     *
     * @param addr Memory address.
     * @param crc_mode CRC mode.
     * @param raw_size_out Raw data size of the log entry.
     * @return True if the log entry is valid.
     */
    static bool isValidEntry(void* addr,
                             crc_mode_e crc_mode,
                             uint64_t& raw_size_out);

    /**
     * Set commit marker info to the log entry.
     *
     * @param revnum Commit revision number.
     * @param txn_id Transaction ID.
     */
    void setCommitMarker(uint64_t revnum, uint64_t txn_id);

    /**
     * Get commit marker info from the log entry.
     *
     * @param revnum Reference to commit revision number.
     * @param txn_id Reference to transaction ID.
     * @return True if the log entry is a valid commit marker.
     */
    bool getCommitMarker(uint64_t& revnum, uint64_t& txn_id);

private:
    // Length meta data.
    struct docio_length length;
    // Time-stamp.
    timestamp_t timestamp;
    // Sequence number.
    fdb_seqnum_t seqnum;
    // Key
    void *key;
    // Meta data
    void *meta;
    // Body (value)
    void *body;
    // Transaction ID
    uint64_t txnId;

    /**
     * Locally allocated key region used for commit marker.
     * It will be freed when the log entry instance is deleted.
     */
    char *localKeyBuf;
    /**
     * Locally allocated value region used for commit marker.
     * It will be freed when the log entry instance is deleted.
     */
    char *localValueBuf;

    // Temporary buffer for compression.
    char *compBuf;
    // Temporary buffer for uncompression.
    char *uncompBuf;
    // Length of compression buffer.
    size_t compBufLen;

    int uncompressLogEntry(char*& buf, size_t& buflen);
};



/**
 * Commit log configuration class definition.
 */
class CommitLogConfig {
public:
    CommitLogConfig() :
        fileSizeLimit(FDB_DEFAULT_COMMIT_LOG_SIZE), fileOps(get_filemgr_ops()),
        crcMode(CRC_DEFAULT), sync(true), compression(false) { }

    CommitLogConfig(struct filemgr_ops *_ops,
                    uint64_t _limit = FDB_DEFAULT_COMMIT_LOG_SIZE,
                    crc_mode_e _crc_mode = CRC_DEFAULT,
                    bool _sync = true,
                    bool _compression = false) :
        fileSizeLimit(_limit), fileOps(_ops), crcMode(_crc_mode), sync(_sync),
        compression(_compression) { }

    ~CommitLogConfig() { }

    // Commit log file size.
    uint64_t fileSizeLimit;
    // FileMgr ops wrapper instance.
    struct filemgr_ops *fileOps;
    // CRC mode
    crc_mode_e crcMode;
    // Flag to call fsync() on commit operation.
    bool sync;
    // Flag to compress log entry.
    // If compression library is not linked to ForestDB module
    // (which means that _DOC_COMP macro is not defined),
    // then compression will be bypassed although this flag is set.
    bool compression;
};



/**
 * Commit log class definition.
 */
class CommitLog {
public:
    // Default constructor.
    CommitLog();

    /**
     * Constructor.
     *
     * @param _dbname Name of DB instance.
     * @param _config Commit log configuration.
     */
    CommitLog(std::string _dbname,
              CommitLogConfig *_config);

    // Destructor.
    ~CommitLog();

    /**
     * Append a log entry into the latest commit log file.
     *
     * @param entry Log entry to be written.
     * @param ptr_value Reference to pointer to the memory region that value will
     *        be stored as a result of this function call.
     * @param sync Flag to call fsync() after writing the log entry.
     * @return FDB_RESULT_SUCCESS on success.
     */
    fdb_status appendLogEntry(CommitLogEntry *entry,
                              void*& ptr_value,
                              bool sync = false);

    /**
     * Append a log entry into the latest commit log file.
     *
     * @param entry Log entry to be written.
     * @param ptr_value Reference to pointer to the memory region that value will
     *        be stored as a result of this function call.
     * @param ptr_entry Reference to pointer to the memory region that the log
     *        entry will be stored as a result of this function call.
     * @param sync Flag to call fsync() after writing the log entry.
     * @return FDB_RESULT_SUCCESS on success.
     */
    fdb_status appendLogEntry(CommitLogEntry *entry,
                              void*& ptr_value,
                              void*& ptr_entry,
                              bool sync = false);

    /**
     * Append a log entry into the latest commit log file.
     *
     * @param entry Log entry to be written.
     * @param ptr_value Reference to pointer to the memory region that value will
     *        be stored as a result of this function call.
     * @param ptr_entry Reference to pointer to the memory region that the log
     *        entry will be stored as a result of this function call.
     * @param log_id Reference to log file ID that the log entry will be written.
     * @param sync Flag to call fsync() after writing the log entry.
     * @return FDB_RESULT_SUCCESS on success.
     */
    fdb_status appendLogEntry(CommitLogEntry *entry,
                              void*& ptr_value,
                              void*& ptr_entry,
                              uint64_t& log_id,
                              bool sync);

    /**
     * Commit all dirty log entries, and append a commit marker.
     *
     * @param revnum Commit revision.
     * @param txn_id Transaction ID.
     * @return FDB_RESULT_SUCCESS on success.
     */
    fdb_status commitLog(uint64_t revnum, uint64_t txn_id);

    /**
     * Commit all dirty log entries, and append a commit marker.
     *
     * @param revnum Commit revision.
     * @param txn_id Transaction ID.
     * @param log_id Reference to log file ID that the commit marker will be written.
     * @return FDB_RESULT_SUCCESS on success.
     */
    fdb_status commitLog(uint64_t revnum, uint64_t txn_id, uint64_t& log_id);

    std::string getDbName() {
        return dbName;
    }

    /**
     * Read and reconstruct all existing commit log files.
     *
     * @param cb Callback function that will be invoked for every log entry.
     * @param ctx Context data given by user.
     * @return FDB_RESULT_SUCCESS on success.
     */
    fdb_status reconstructLog(CommitLogScanCallback cb, void *ctx);

    /**
     * Read a specific log file.
     *
     * @param log_id ID of the log file to read.
     * @param cb Callback function that will be invoked for every log entry.
     * @param ctx Context data given by user.
     * @return FDB_RESULT_SUCCESS on success.
     */
    fdb_status readLog(uint64_t log_id, CommitLogScanCallback cb, void *ctx);

    /**
     * Destroy log files up to the given ID.
     *
     * @param log_id Maximum ID of the log file to destroy.
     * @return FDB_RESULT_SUCCESS on success.
     */
    fdb_status destroyLogUpto(uint64_t log_id_upto);

private:
    // Commit log configuration.
    CommitLogConfig *config;
    // DB instance name.
    std::string dbName;
    // Atomic counter for commit log ID.
    std::atomic<uint64_t> idCounter;
    // List of commit log files.
    std::list<CommitLogFile *> files;
    // List of dirty commit log files that need to be synchronized.
    std::list<CommitLogFile *> dirtyFiles;
    // Pointer to the latest commit log file.
    std::atomic<CommitLogFile *> curFile;
    // Mutex for management of commit log file lists.
    std::mutex logManagementLock;

    /**
     * Append a log entry into the latest commit log file.
     *
     * @param entry Log entry to be written.
     * @param ptr_value Reference to pointer to the memory region that value will
     *        be stored as a result of this function call.
     * @param ptr_entry Reference to pointer to the memory region that the log
     *        entry will be stored as a result of this function call.
     * @param log_id Reference to log file ID that the log entry will be written.
     * @param sync Flag to call fsync() after writing the log entry.
     * @return FDB_RESULT_SUCCESS on success.
     */
    fdb_status _appendLogEntry(CommitLogEntry *entry,
                               void*& ptr_value,
                               void*& ptr_entry,
                               uint64_t& log_id,
                               bool sync = false);

    /**
     * Parse and extract log ID from the log file name, and insert
     * {log ID, log file name} pair into the given map.
     *
     * @param name_str Log file name.
     * @param file_map Pointer to map for indexing {log ID, log file name} pairs.
     */
    void parseFileName(std::string& name_str,
                       std::map<uint64_t, std::string>& file_map);

    /**
     * Create a new commit log file.
     *
     * @param excess_size Log file size, if want to set the file size manually.
     * @return FDB_RESULT_SUCCESS on success.
     */
    fdb_status createNewLogFile(uint64_t excess_size = 0);

    /**
     * Scan all log files in the current directory, and sort them in log ID order.
     *
     * @param file_map Pointer to map for indexing {log ID, log file name} pairs.
     * @param min_id Reference to where minimum log file ID will be stored.
     * @param max_id Reference to where maximum log file ID will be stored.
     */
    void scanLogFiles(std::map<uint64_t, std::string>& file_map,
                      uint64_t& min_id,
                      uint64_t& max_id);

    /**
     * Commit all dirty log entries, and append a commit marker.
     *
     * @param revnum Commit revision.
     * @param txn_id Transaction ID.
     * @param log_id Reference to log file ID that the commit marker will be written.
     * @return FDB_RESULT_SUCCESS on success.
     */
    fdb_status _commitLog(uint64_t revnum, uint64_t txn_id, uint64_t& log_id);

};

