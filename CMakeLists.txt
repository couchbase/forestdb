cmake_minimum_required(VERSION 2.8)

include_directories(BEFORE ${CMAKE_SOURCE_DIR}/option)
include_directories(BEFORE ${CMAKE_SOURCE_DIR}/utils)
include_directories(BEFORE ${CMAKE_SOURCE_DIR}/src)
include_directories(BEFORE ${CMAKE_SOURCE_DIR}/include)

SET(HAVE_LEVEL:Boolean False)
SET(HAVE_COUCHSTORE:Boolean False)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D_GNU_SOURCE -D__DEBUG")

if (NOT WIN32)
   set(PTHREAD_LIB pthread)
   set(LIBM m)
   set(FORESTDB_FILE_OPS "src/filemgr_ops_linux.c")
else (NOT WIN32)
  set(FORESTDB_FILE_OPS "src/filemgr_ops_windows.c")
endif(NOT WIN32)

if ("${CMAKE_C_COMPILER_ID}" STREQUAL "Clang")
   set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Qunused-arguments -g -fomit-frame-pointer -pthread")
elseif ("${CMAKE_C_COMPILER_ID}" STREQUAL "GNU")
   set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -fomit-frame-pointer -pthread")
endif()

add_library(forestdb SHARED
            src/avltree.c
            src/blockcache.c
            src/btree.c
            src/btree_kv.c
            src/btreeblock.c
            src/docio.c
            src/filemgr.c
            src/filemgr_ops.c
            ${FORESTDB_FILE_OPS}
            src/forestdb.c
            src/hash_functions.c
            src/hbtrie.c
            src/iterator.c
            src/list.c
            src/hash.c
            src/mempool.c
            src/wal.c
            utils/crc32.c
            utils/debug.c
            utils/memleak.c)

add_library(forestdb_couch SHARED
            couchstore_api/couchstore_api.c
            src/avltree.c
            src/blockcache.c
            src/btree.c
            src/btree_kv.c
            src/btreeblock.c
            src/docio.c
            src/filemgr.c
            src/filemgr_ops.c
            ${FORESTDB_FILE_OPS}
            src/forestdb.c
            src/hash.c
            src/hash_functions.c
            src/hbtrie.c
            src/iterator.c
            src/list.c
            src/mempool.c
            src/wal.c
            utils/crc32.c
            utils/debug.c
            utils/memleak.c)

add_executable(forestdb_test
               src/avltree.c
               tests/forestdb_test.c
               utils/memleak.c)
target_link_libraries(forestdb_test forestdb ${PTHREAD_LIB} ${LIBM})

add_executable(couchbench_fdb
               couchstore_api/couchstore_bench.c
               src/avltree.c
               utils/crc32.c
               utils/iniparser.c
               utils/memleak.c
               utils/stopwatch.c)
target_link_libraries(couchbench_fdb forestdb_couch ${PTHREAD_LIB} ${LIBM})

IF (HAVE_LEVEL)
   add_executable(couchbench_level
                  couchstore_api/couchstore_api_leveldb.c
                  couchstore_api/couchstore_bench.c
                  src/avltree.c
                  utils/crc32.c
                  utils/iniparser.c
                  utils/memleak.c
                  utils/stopwatch.c)
   target_link_libraries(couchbench_level leveldb ${PTHREAD_LIB} ${LIBM})
ENDIF (HAVE_LEVEL)

if (HAVE_COUCHSTORE)
   add_executable(couchbench_ori
                  couchstore_api/couchstore_bench.c
                  src/avltree.c
                  utils/crc32.c
                  utils/iniparser.c
                  utils/memleak.c
                  utils/stopwatch.c)
   target_link_libraries(couchbench_ori couchstore ${PTHREAD_LIB} ${LIBM})
endif(HAVE_COUCHSTORE)

add_executable(hash_test
               src/avltree.c
               src/hash.c
               src/hash_functions.c
               src/list.c
               tests/hash_test.c
               utils/memleak.c)
target_link_libraries(hash_test ${PTHREAD_LIB} ${LIBM})

add_executable(mempool_test
               src/avltree.c
               src/list.c
               src/mempool.c
               tests/mempool_test.c
               utils/memleak.c)
target_link_libraries(mempool_test ${PTHREAD_LIB} ${LIBM})

add_executable(bcache_test
               tests/bcache_test.c
               src/avltree.c
               src/blockcache.c
               src/filemgr.c
               src/filemgr_ops.c
               ${FORESTDB_FILE_OPS}
               src/hash.c
               src/hash_functions.c
               src/list.c
               src/mempool.c
               src/wal.c
               utils/crc32.c
               utils/debug.c
               utils/memleak.c)
target_link_libraries(bcache_test ${PTHREAD_LIB} ${LIBM})


add_executable(filemgr_test
               tests/filemgr_test.c
               src/avltree.c
               src/blockcache.c
               src/filemgr.c
               src/filemgr_ops.c
               ${FORESTDB_FILE_OPS}
               src/hash.c
               src/hash_functions.c
               src/list.c
               src/mempool.c
               src/wal.c
               utils/crc32.c
               utils/debug.c
               utils/memleak.c)
target_link_libraries(filemgr_test ${PTHREAD_LIB} ${LIBM})

add_executable(btreeblock_test
               tests/btreeblock_test.c
               src/avltree.c
               src/blockcache.c
               src/btree.c
               src/btree_kv.c
               src/btreeblock.c
               src/filemgr.c
               src/filemgr_ops.c
               ${FORESTDB_FILE_OPS}
               src/hash.c
               src/hash_functions.c
               src/list.c
               src/mempool.c
               src/wal.c
               utils/crc32.c
               utils/debug.c
               utils/memleak.c)
target_link_libraries(btreeblock_test ${PTHREAD_LIB} ${LIBM})

add_executable(docio_test
               tests/docio_test.c
               src/avltree.c
               src/blockcache.c
               src/docio.c
               src/filemgr.c
               src/filemgr_ops.c
               ${FORESTDB_FILE_OPS}
               src/hash.c
               src/hash_functions.c
               src/list.c
               src/mempool.c
               src/wal.c
               utils/crc32.c
               utils/debug.c
               utils/memleak.c)
target_link_libraries(docio_test ${PTHREAD_LIB} ${LIBM})

add_executable(hbtrie_test
               tests/hbtrie_test.c
               src/avltree.c
               src/blockcache.c
               src/btree.c
               src/btree_kv.c
               src/btreeblock.c
               src/docio.c
               src/filemgr.c
               src/filemgr_ops.c
               ${FORESTDB_FILE_OPS}
               src/hash.c
               src/hash_functions.c
               src/hbtrie.c
               src/list.c
               src/mempool.c
               src/wal.c
               utils/crc32.c
               utils/debug.c
               utils/memleak.c)
target_link_libraries(hbtrie_test ${PTHREAD_LIB} ${LIBM})

add_executable(crc_test
               tests/crc_test.c
               src/avltree.c
               src/hash_functions.c
               utils/crc32.c
               utils/memleak.c)
target_link_libraries(crc_test ${PTHREAD_LIB} ${LIBM})

enable_testing()
add_test(forestdb_test forestdb_test)
add_test(couchbench couchbench_fdb)
add_test(hash_test hash_test)
add_test(mempool_test mempool_test)
add_test(bcache_test bcache_test)
add_test(filemgr_test filemgr_test)
add_test(btreeblock_test btreeblock_test)
add_test(docio_test docio_test)
add_test(hbtrie_test hbtrie_test)
add_test(crc_test crc_test)
