LIST = src/list.o
LISTTEST = tests/list_test.o

RBTREE = src/rbtree.o src/rbwrap.o

HASH = src/hash.o src/hash_functions.o $(LIST) $(RBTREE)
HASHTEST = tests/hash_test.o

MEMPOOL = src/mempool.o $(LIST)
MEMPOOLTEST = tests/mempool_test.o

BTREE = src/btree.o src/btree_kv.o

BCACHE = src/blockcache.o $(HASH) $(RBTREE) $(MEMPOOL)
FILEMGR = src/filemgr.o src/filemgr_ops_linux.o $(HASH) $(BCACHE)

BCACHETEST = tests/bcache_test.o $(FILEMGR)
FILEMGRTEST = tests/filemgr_test.o

BTREEBLOCK = src/btreeblock.o $(LIST) $(FILEMGR) $(MEMPOOL)
BTREEBLOCKTEST = tests/btreeblock_test.o

DOCIO = src/docio.o $(FILEMGR)
DOCIOTEST = tests/docio_test.o

HBTRIE = src/hbtrie.o $(BTREE) $(DOCIO) $(BTREEBLOCK) $(LIST)
HBTRIETEST = tests/hbtrie_test.o

WAL = src/wal.o $(HASH)

FDB = \
	src/forestdb.o src/hbtrie.o src/btree.o src/btree_kv.o \
	src/docio.o src/filemgr.o src/filemgr_ops_linux.o src/hash.o \
	src/hash_functions.o src/list.o src/rbtree.o src/rbwrap.o \
	src/btreeblock.o src/mempool.o src/wal.o src/blockcache.o
FDB_COUCH = $(FDB) couchstore_api/couchstore_api.o
	
FDBTEST = tests/forestdb_test.o

COUCHBENCH = couchstore_api/couchstore_bench.o utils/stopwatch.o utils/iniparser.o

LIBRARY=forestdb
LIBCOUCHSTORE=couchstore_api/libs/libcouchstore.so

PROGRAMS = \
	tests/list_test \
	tests/hash_test \
	tests/mempool_test \
	tests/bcache_test \
	tests/filemgr_test \
	tests/btreeblock_test \
	tests/docio_test \
	tests/hbtrie_test \
	forestdb_test \
	couchstore_api/couchbench_ori \
	couchstore_api/couchbench_fdb \

LDFLAGS = -pthread -lsnappy -lm
CFLAGS = \
	-g -D_GNU_SOURCE \
	-I./include -I./src -I./utils\
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

forestdb_test: lib $(FDBTEST)
	$(CC) $(CFLAGS) $(FDBTEST) lib$(LIBRARY).so -o $@ $(LDFLAGS)

couchstore_api/couchbench_fdb: lib_couch $(COUCHBENCH)
	$(CC) $(CFLAGS) $(COUCHBENCH) lib$(LIBRARY)_couch.so -o $@ $(LDFLAGS)
	
couchstore_api/couchbench_ori: $(COUCHBENCH)
	$(CC) $(CFLAGS) $(COUCHBENCH) $(LIBCOUCHSTORE) -o $@ $(LDFLAGS)
	
clean:
	rm -rf src/*.o tests/*.o dummy* $(PROGRAMS) ./*.so
