# ForestDB

ForestDB is a key-value storage engine that is developed by Couchbase Caching and Storage Team, and its main index structure is built from [Hierarchical B+-Tree based Trie](http://db.csail.mit.edu/sigmod11contest/sigmod_2011_contest_poster_jungsang_ahn.pdf), called HB+-Trie. [HB+-Trie](http://db.csail.mit.edu/sigmod11contest/sigmod_2011_contest_poster_jungsang_ahn.pdf) was originally presented at [ACM SIGMOD 2011 Programming Contest](http://db.csail.mit.edu/sigmod11contest/), by [Jung-Sang Ahn](http://cagsky.kaist.ac.kr/jsahn/) who works at Couchbase Caching and Storage Team.

Compared with traditional B+-Tree based storage engines, ForestDB shows significantly better read and write performance with less storage overhead. ForestDB has been tested on various server OS environments (Centos, Ubuntu, Mac OS x, Windows) and mobile OSs (iOS, Android).

ForestDB is currently in [1.0 Beta](https://github.com/couchbaselabs/forestdb/wiki/ForestDB-1.0-Beta) and its GA will be released separately soon. The test coverage stats for ForestDB are available in [ForestDB Code Coverage Report](http://labs.couchbase.com/fdbcoverage/index.html).

[ForestDB benchmark program](https://github.com/couchbaselabs/ForestDB-Benchmark) is also available for performance comparisons with other key-value storage engines.

Please visit the [ForestDB wiki](https://github.com/couchbaselabs/forestdb/wiki) for more details.

## Main Features

- Keys and values are treated as an arbitrary binary.
- Applications can supply a custom compare function to support a customized key order.
- A value can be retrieved by its sequence number or disk offset in addition to a key.
- Write-Ahead Logging (WAL) and its in-memory index are used to reduce the main index lookup / update overhead.
- Multi-Version Concurrency Control (MVCC) support and append-only storage layer.
- Multiple snapshot instances can be created from a given ForestDB instance to provide different views of database.
- Rollback is supported to revert the database to a specific point.
- Ranged iteration by keys or sequence numbers is supported for a partial or full range lookup operation.
- Manual or auto compaction can be configured per ForestDB database file.
- Transactional support with read\_committed or read\_uncommitted isolation level.

## How to build

See INSTALL.MD

## How to Use

Please refer to [Public APIs](https://github.com/couchbaselabs/forestdb/wiki/Public-APIs) and tests/fdb\_functional\_test.cc in ForestDB source directory.
