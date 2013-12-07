LIST = src/list.o
LISTTEST = tests/list_test.o

RBTREE = src/rbtree.o src/rbwrap.o

MEMLEAK = utils/memleak.o $(RBTREE)

HASH = src/hash.o src/hash_functions.o $(LIST) $(RBTREE) $(MEMLEAK)
HASHTEST = tests/hash_test.o

CRC32 = utils/crc32.o $(MEMLEAK)
CRCTEST = tests/crc_test.o $(CRC32) src/hash_functions.o

MEMPOOL = src/mempool.o $(LIST) $(MEMLEAK)
MEMPOOLTEST = tests/mempool_test.o

BTREE = src/btree.o src/btree_kv.o $(MEMLEAK)

BCACHE = src/blockcache.o utils/debug.o \
	$(HASH) $(RBTREE) $(MEMPOOL) $(CRC32) $(MEMLEAK)
	
WAL = src/wal.o $(HASH) $(MEMLEAK)

FILEMGR = src/filemgr.o src/filemgr_ops_linux.o utils/debug.o \
	$(HASH) $(BCACHE) $(MEMLEAK) $(WAL)

BCACHETEST = tests/bcache_test.o $(FILEMGR)
FILEMGRTEST = tests/filemgr_test.o

BTREEBLOCK = src/btreeblock.o utils/debug.o \
	$(LIST) $(FILEMGR) $(MEMPOOL) $(CRC32) $(MEMLEAK)
BTREEBLOCKTEST = tests/btreeblock_test.o

DOCIO = src/docio.o $(FILEMGR) $(CRC32) $(MEMLEAK)
DOCIOTEST = tests/docio_test.o

HBTRIE = src/hbtrie.o $(BTREE) $(DOCIO) $(BTREEBLOCK) \
	$(LIST) $(MEMLEAK)
HBTRIETEST = tests/hbtrie_test.o

FDB = \
	src/forestdb.o src/hbtrie.o src/btree.o src/btree_kv.o \
	src/docio.o src/filemgr.o src/filemgr_ops_linux.o src/hash.o \
	src/hash_functions.o src/list.o src/rbtree.o src/rbwrap.o \
	src/btreeblock.o src/mempool.o src/wal.o src/blockcache.o utils/crc32.o \
	utils/debug.o \
    utils/memleak.o
FDB_COUCH = $(FDB) couchstore_api/couchstore_api.o

LEVELDB_COUCH = couchstore_api/couchstore_api_leveldb.o
	
FDBTEST = tests/forestdb_test.o $(MEMLEAK)

COUCHBENCH = couchstore_api/couchstore_bench.o utils/stopwatch.o utils/iniparser.o \
    utils/crc32.o utils/memleak.o src/rbtree.o src/rbwrap.o

LIBDIR=./couchstore_api/libs/
LIBRARY=forestdb
LIBCOUCHSTORE=$(LIBDIR)/libcouchstore.so.1
LIBLEVELDB=$(LIBDIR)/libleveldb.so

PROGRAMS = \
	tests/list_test \
	tests/hash_test \
	tests/mempool_test \
	tests/bcache_test \
	tests/filemgr_test \
	tests/btreeblock_test \
	tests/docio_test \
	tests/hbtrie_test \
	tests/crc_test \
	forestdb_test \
	couchstore_api/couchbench_fdb \

BENCH = \
	couchstore_api/couchbench_ori \
	couchstore_api/couchbench_level \

LDFLAGS = -pthread -lsnappy -lm -lrt
CFLAGS = \
	-g -D_GNU_SOURCE \
	-I./include -I./src -I./utils \
	-D__DEBUG -fPIC \
	-O3 -fomit-frame-pointer \
	
all: $(PROGRAMS)

lib: $(FDB)
	$(CC) $(CFLAGS) -shared $(LDFLAGS) -o lib$(LIBRARY).so $(FDB)

lib_couch: $(FDB_COUCH)
	$(CC) $(CFLAGS) -shared $(LDFLAGS) -o lib$(LIBRARY)_couch.so $(FDB_COUCH)
	
tests/list_test: $(LISTTEST) $(LIST) 
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

tests/hash_test: $(HASHTEST) $(HASH) 
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)
	
tests/mempool_test: $(MEMPOOLTEST) $(MEMPOOL) 
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

tests/bcache_test: $(BCACHETEST) $(BCACHE) 
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

tests/filemgr_test: $(FILEMGRTEST) $(FILEMGR) 
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

tests/btreeblock_test: $(BTREEBLOCKTEST) $(BTREEBLOCK) $(BTREE)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

tests/docio_test: $(DOCIOTEST) $(DOCIO)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

tests/hbtrie_test: $(HBTRIETEST) $(HBTRIE) $(BTREE)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

tests/crc_test: $(CRCTEST)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

forestdb_test: lib $(FDBTEST)
	$(CC) $(CFLAGS) $(FDBTEST) lib$(LIBRARY).so -o $@ $(LDFLAGS)

couchstore_api/couchbench_fdb: lib_couch $(COUCHBENCH)
	$(CC) $(CFLAGS) $(COUCHBENCH) lib$(LIBRARY)_couch.so -o $@ $(LDFLAGS)
	
couchstore_api/couchbench_level: $(LEVELDB_COUCH) $(COUCHBENCH) 
	$(CC) $(CFLAGS) $(LEVELDB_COUCH) $(COUCHBENCH) $(LIBLEVELDB) -o $@ $(LDFLAGS)

couchstore_api/couchbench_ori: $(COUCHBENCH)
	$(CC) $(CFLAGS) $(COUCHBENCH) $(LIBCOUCHSTORE) -o $@ $(LDFLAGS)

test: lib forestdb_test
	LD_LIBRARY_PATH=./ ./forestdb_test

bench: lib_couch couchstore_api/couchbench_fdb
	LD_LIBRARY_PATH=./ ./couchstore_api/couchbench_fdb

other_bench: lib_couch couchstore_api/couchbench_level couchstore_api/couchbench_ori

clean:
	rm -rf src/*.o tests/*.o couchstore_api/*.o utils/*.o dummy* $(PROGRAMS) $(BENCH) ./*.so
