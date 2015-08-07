/* -*- Mode: C++; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2015 Couchbase, Inc
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

#include <gtest/gtest.h>
#include <platform/dirutils.h>
#include <string>
#include <utility>
#include <vector>

#include "checksum.h"
#include "libforestdb/forestdb.h"
#include "test.h"
#include "internal_types.h"
#include "filemgr.h"

class CrcMigrationTest : public ::testing::Test {
public:
    void setDocuments(int docsToSet) {
        ASSERT_NE(kvs, nullptr);
        std::vector<std::pair<std::string, std::string> > documents;
        for (int ii = 0; ii < docsToSet; ii++) {
            std::string key = "key" + std::to_string(ii);
            std::string data = "document - " + std::to_string(ii);
            documents.push_back(std::make_pair(key, data));
            ASSERT_EQ(FDB_RESULT_SUCCESS, fdb_set_kv(kvs,
                                                     key.c_str(),
                                                     key.length(),
                                                     data.c_str(),
                                                     data.length()));
        }
    }

    void readAndCheckDocuments() {
        ASSERT_NE(kvs, nullptr);
        // read back and compare.
        for (auto pair : documents) {
            void* value = nullptr;
            size_t len;
            ASSERT_EQ(FDB_RESULT_SUCCESS, fdb_get_kv(kvs,
                                                     pair.first.c_str(),
                                                     pair.first.length(),
                                                     &value,
                                                     &len));
            EXPECT_EQ(len, pair.second.length());
            std::string data(reinterpret_cast<char*>(value), len);
            EXPECT_EQ(data, pair.second);
            free(value);
        }
    }

protected:

    CrcMigrationTest()
      : dbfile(nullptr),
        kvs(nullptr),
        testFile("crc_migration") {
    }

    virtual ~CrcMigrationTest() {

        if (kvs) {
            fdb_kvs_close(kvs);
        }

        if (dbfile) {
            fdb_close(dbfile);
        }

        CouchbaseDirectoryUtilities::rmrf(testFile);
    }

    fdb_file_handle *dbfile;
    fdb_kvs_handle *kvs;
    std::string testFile;
    std::vector<std::pair<std::string, std::string> > documents;
};

TEST_F(CrcMigrationTest, crc32cBuild) {
    // No point in running the test suite unless fdb is built
    // with _CRC32C support, so let's check that's happened.
#if !defined(_CRC32C)
    ASSERT_TRUE(false);
#endif
}

TEST_F(CrcMigrationTest, openLegacyCrc) {
    fdb_config fconfig = fdb_get_default_config();
    fconfig.flags |= FDB_OPEN_WITH_LEGACY_CRC;
    ASSERT_EQ(FDB_RESULT_SUCCESS, fdb_open(&dbfile,
                                           testFile.c_str(),
                                           &fconfig));
    EXPECT_EQ(CRC32, dbfile->root->file->crc_mode);
}

TEST_F(CrcMigrationTest, openNewCrc) {
    fdb_config fconfig = fdb_get_default_config();
    ASSERT_EQ(FDB_RESULT_SUCCESS, fdb_open(&dbfile,
                                           testFile.c_str(),
                                           &fconfig));
    EXPECT_EQ(CRC32C, dbfile->root->file->crc_mode);

    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    ASSERT_EQ(FDB_RESULT_SUCCESS, fdb_kvs_open(dbfile,
                                               &kvs,
                                               "db",
                                               &kvs_config));

    SCOPED_TRACE("openNewCrc - setting documents");
    setDocuments(100);
    ASSERT_EQ(FDB_RESULT_SUCCESS, fdb_commit(dbfile, FDB_COMMIT_NORMAL));
    ASSERT_EQ(FDB_RESULT_SUCCESS, fdb_kvs_close(kvs));
    ASSERT_EQ(FDB_RESULT_SUCCESS, fdb_close(dbfile));
    kvs = nullptr;
    dbfile = nullptr;

    ASSERT_EQ(FDB_RESULT_SUCCESS, fdb_open(&dbfile,
                                           testFile.c_str(),
                                           &fconfig));
    EXPECT_EQ(CRC32C, dbfile->root->file->crc_mode);
    ASSERT_EQ(FDB_RESULT_SUCCESS, fdb_kvs_open(dbfile,
                                               &kvs,
                                               "db",
                                               &kvs_config));
    SCOPED_TRACE("openNewCrc - checking documents");
    readAndCheckDocuments();
}

TEST_F(CrcMigrationTest, openLegacyCrcShouldFail) {

    // 1. create a new datafile with CRC32C
    fdb_config fconfig = fdb_get_default_config();
    ASSERT_EQ(FDB_RESULT_SUCCESS, fdb_open(&dbfile,
                                           testFile.c_str(),
                                           &fconfig));
    EXPECT_EQ(CRC32C, dbfile->root->file->crc_mode);

    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    ASSERT_EQ(FDB_RESULT_SUCCESS, fdb_kvs_open(dbfile,
                                               &kvs,
                                               "db",
                                               &kvs_config));

    SCOPED_TRACE("openLegacyCrcShouldFail - setting documents");
    setDocuments(100);
    ASSERT_EQ(FDB_RESULT_SUCCESS, fdb_commit(dbfile, FDB_COMMIT_NORMAL));
    ASSERT_EQ(FDB_RESULT_SUCCESS, fdb_kvs_close(kvs));
    ASSERT_EQ(FDB_RESULT_SUCCESS, fdb_close(dbfile));
    kvs = nullptr;
    dbfile = nullptr;

    // 2. open the existing file with CRC32
    fconfig = fdb_get_default_config();
    fconfig.flags |= FDB_OPEN_WITH_LEGACY_CRC;
    ASSERT_EQ(FDB_RESULT_INVALID_ARGS, fdb_open(&dbfile,
                                                testFile.c_str(),
                                                &fconfig));
}

//
// Test that compaction writes out new ForestDB files with CRC32C
//
TEST_F(CrcMigrationTest, compactUpgrade1) {
    fdb_config fconfig = fdb_get_default_config();
    ASSERT_EQ(FDB_RESULT_SUCCESS, fdb_open(&dbfile,
                                           testFile.c_str(),
                                           &fconfig));
    EXPECT_EQ(CRC32C, dbfile->root->file->crc_mode);

    std::string compactFile = testFile + ".compact";
    ASSERT_EQ(FDB_RESULT_SUCCESS, fdb_compact(dbfile, compactFile.c_str()));
    ASSERT_EQ(FDB_RESULT_SUCCESS, fdb_close(dbfile));

    fconfig = fdb_get_default_config();
    ASSERT_EQ(FDB_RESULT_SUCCESS, fdb_open(&dbfile,
                                           compactFile.c_str(),
                                           &fconfig));
    EXPECT_EQ(CRC32C, dbfile->root->file->crc_mode);
    ASSERT_EQ(FDB_RESULT_SUCCESS, fdb_close(dbfile));
    CouchbaseDirectoryUtilities::rmrf(compactFile);
    dbfile = nullptr;
}

//
// Test that compaction writes out new ForestDB files with CRC32C
// when the input file is CRC32
//
TEST_F(CrcMigrationTest, compactUpgrade2) {
    fdb_config fconfig = fdb_get_default_config();
    fconfig.flags |= FDB_OPEN_WITH_LEGACY_CRC;
    ASSERT_EQ(FDB_RESULT_SUCCESS, fdb_open(&dbfile,
                                           testFile.c_str(),
                                           &fconfig));
    EXPECT_EQ(CRC32, dbfile->root->file->crc_mode); // confirm CRC32

    std::string compactFile = testFile + ".compact";
    ASSERT_EQ(FDB_RESULT_SUCCESS, fdb_compact(dbfile, compactFile.c_str()));
    ASSERT_EQ(FDB_RESULT_SUCCESS, fdb_close(dbfile));

    fconfig = fdb_get_default_config();
    ASSERT_EQ(FDB_RESULT_SUCCESS, fdb_open(&dbfile,
                                           compactFile.c_str(),
                                           &fconfig));
    EXPECT_EQ(CRC32C, dbfile->root->file->crc_mode);
    ASSERT_EQ(FDB_RESULT_SUCCESS, fdb_close(dbfile));
    CouchbaseDirectoryUtilities::rmrf(compactFile);
    dbfile = nullptr;
}

TEST_F(CrcMigrationTest, compactUpgradeWithData) {
    const int docsInTest = 1000;
    fdb_config fconfig = fdb_get_default_config();


    fconfig.flags |= FDB_OPEN_WITH_LEGACY_CRC;
    ASSERT_EQ(FDB_RESULT_SUCCESS, fdb_open(&dbfile,
                                           testFile.c_str(),
                                           &fconfig));
    EXPECT_EQ(CRC32, dbfile->root->file->crc_mode);


    fdb_kvs_config kvs_config = fdb_get_default_kvs_config();
    ASSERT_EQ(FDB_RESULT_SUCCESS, fdb_kvs_open(dbfile,
                                               &kvs,
                                               "db",
                                               &kvs_config));

    // Set documents.
    SCOPED_TRACE("compactUpgradeWithData - setting documents");
    setDocuments(docsInTest);

    // Force a write again so compaction does something.
    for (auto &pair : documents) {
        pair.second.append("moar-data");
        ASSERT_EQ(FDB_RESULT_SUCCESS, fdb_set_kv(kvs,
                                                 pair.first.c_str(),
                                                 pair.first.length(),
                                                 pair.second.c_str(),
                                                 pair.second.length()));
    }
    ASSERT_EQ(FDB_RESULT_SUCCESS, fdb_commit(dbfile, FDB_COMMIT_NORMAL));

    std::string compactFile = testFile + ".compact";
    ASSERT_EQ(FDB_RESULT_SUCCESS, fdb_compact(dbfile, compactFile.c_str()));
    ASSERT_EQ(FDB_RESULT_SUCCESS, fdb_kvs_close(kvs));
    ASSERT_EQ(FDB_RESULT_SUCCESS, fdb_close(dbfile));

    // Open the compacted file and compare.
    fconfig = fdb_get_default_config();
    ASSERT_EQ(FDB_RESULT_SUCCESS, fdb_open(&dbfile,
                                           compactFile.c_str(),
                                           &fconfig));
    EXPECT_EQ(CRC32C, dbfile->root->file->crc_mode);

    ASSERT_EQ(FDB_RESULT_SUCCESS, fdb_kvs_open(dbfile,
                                               &kvs,
                                               "db",
                                               &kvs_config));

    SCOPED_TRACE("compactUpgradeWithData - checking compacted file");
    readAndCheckDocuments();

    ASSERT_EQ(FDB_RESULT_SUCCESS, fdb_kvs_close(kvs));
    ASSERT_EQ(FDB_RESULT_SUCCESS, fdb_close(dbfile));
    CouchbaseDirectoryUtilities::rmrf(compactFile);
    dbfile = nullptr; // we've tidied up
    kvs = nullptr;
}

int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
