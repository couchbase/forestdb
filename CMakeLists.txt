cmake_minimum_required(VERSION 2.8)

include_directories(BEFORE ${CMAKE_SOURCE_DIR}/option)
include_directories(BEFORE ${CMAKE_SOURCE_DIR}/utils)
include_directories(BEFORE ${CMAKE_SOURCE_DIR}/src)
include_directories(BEFORE ${CMAKE_SOURCE_DIR}/include)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -D_GNU_SOURCE -D__DEBUG")
set(CMAKE_CXX_FLAGS_DEBUG "-g -O0 --coverage")

if (NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "RelWithDebInfo" CACHE STRING "Choose the type of build, options are: Debug Release RelWithDebInfo MinSizeRel." FORCE)
endif(NOT CMAKE_BUILD_TYPE)

if (NOT WIN32)
    set(PTHREAD_LIB pthread)
    set(LIBM m)
    set(FORESTDB_FILE_OPS "src/filemgr_ops_linux.cc")
    if (NOT(SNAPPY_OPTION STREQUAL "Disable"))
        set(LIBSNAPPY snappy)
        ADD_DEFINITIONS(-D_DOC_COMP=1)
    endif (NOT(SNAPPY_OPTION STREQUAL "Disable"))
else (NOT WIN32)
    set(FORESTDB_FILE_OPS "src/filemgr_ops_windows.cc")
    set(GETTIMEOFDAY_VS "utils/gettimeofday_vs.cc")
endif(NOT WIN32)

IF (_MEMLEAK EQUAL 1)
    ADD_DEFINITIONS(-D_MEMLEAK_ENABLE=1)
ELSEIF (_MEMLEAK EQUAL 2)
    ADD_DEFINITIONS(-D_MEMLEAK_ENABLE=1)
    ADD_DEFINITIONS(-D_CHK_MODIFY_AFTER_FREE=1)
ENDIF()

if ("${CMAKE_C_COMPILER_ID}" STREQUAL "Clang")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Qunused-arguments -g -fomit-frame-pointer -pthread")
elseif ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -fomit-frame-pointer -pthread")
elseif ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /wd4716 /W0")
endif()

add_library(forestdb SHARED
            src/api_wrapper.cc
            src/avltree.cc
            src/blockcache.cc
            src/btree.cc
            src/btree_kv.cc
            src/btree_prefix_kv.cc
            src/btree_str_kv.cc
            src/btree_fast_str_kv.cc
            src/btreeblock.cc
            src/compactor.cc
            src/configuration.cc
            src/docio.cc
            src/filemgr.cc
            src/filemgr_ops.cc
            ${FORESTDB_FILE_OPS}
            src/forestdb.cc
            src/hash_functions.cc
            src/hbtrie.cc
            src/iterator.cc
            src/list.cc
            src/hash.cc
            src/wal.cc
            ${GETTIMEOFDAY_VS}
            src/snapshot.cc
            src/transaction.cc
            utils/memleak.cc
            utils/crc32.cc
            utils/adler32.cc
            utils/debug.cc
            utils/cJSON.cc)
target_link_libraries(forestdb ${PTHREAD_LIB} ${LIBM} ${LIBSNAPPY})

add_executable(fdb_functional_test
               tests/fdb_functional_test.cc
               ${GETTIMEOFDAY_VS})
target_link_libraries(fdb_functional_test forestdb)

add_executable(fdb_extended_test
               tests/fdb_extended_test.cc
               ${GETTIMEOFDAY_VS})
target_link_libraries(fdb_extended_test forestdb)

add_executable(forestdb_dump
               tools/forestdb_dump.cc
               src/api_wrapper.cc
               src/avltree.cc
               src/blockcache.cc
               src/btree.cc
               src/btree_kv.cc
               src/btree_prefix_kv.cc
               src/btree_str_kv.cc
               src/btree_fast_str_kv.cc
               src/btreeblock.cc
               src/compactor.cc
               src/configuration.cc
               src/docio.cc
               src/filemgr.cc
               src/filemgr_ops.cc
               ${FORESTDB_FILE_OPS}
               src/forestdb.cc
               src/hash_functions.cc
               src/hbtrie.cc
               src/iterator.cc
               src/list.cc
               src/hash.cc
               src/wal.cc
               ${GETTIMEOFDAY_VS}
               src/snapshot.cc
               src/transaction.cc
               utils/memleak.cc
               utils/crc32.cc
               utils/adler32.cc
               utils/debug.cc
               utils/cJSON.cc
               utils/iniparser.cc)
target_link_libraries(forestdb_dump ${PTHREAD_LIB} ${LIBM} ${LIBSNAPPY})
set_target_properties(forestdb_dump PROPERTIES COMPILE_FLAGS "-D_FDB_TOOLS")

IF (INSTALL_HEADER_FILES)
   INSTALL(FILES
           include/libforestdb/forestdb.h
           include/libforestdb/fdb_types.h
           include/libforestdb/fdb_errors.h
           DESTINATION include/libforestdb)
ENDIF(INSTALL_HEADER_FILES)

INSTALL(TARGETS forestdb
        RUNTIME DESTINATION bin
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib)

INSTALL(TARGETS forestdb_dump
        RUNTIME DESTINATION bin)

add_executable(hash_test
               src/avltree.cc
               src/hash.cc
               src/hash_functions.cc
               src/list.cc
               ${GETTIMEOFDAY_VS}
               tests/hash_test.cc
               utils/memleak.cc)
target_link_libraries(hash_test ${PTHREAD_LIB} ${LIBM})

add_executable(bcache_test
               tests/bcache_test.cc
               src/avltree.cc
               src/blockcache.cc
               src/filemgr.cc
               src/filemgr_ops.cc
               ${FORESTDB_FILE_OPS}
               ${GETTIMEOFDAY_VS}
               src/hash.cc
               src/hash_functions.cc
               src/list.cc
               src/wal.cc
               src/snapshot.cc
               utils/crc32.cc
               utils/adler32.cc
               utils/debug.cc
               utils/memleak.cc)
target_link_libraries(bcache_test ${PTHREAD_LIB} ${LIBM})


add_executable(filemgr_test
               tests/filemgr_test.cc
               src/avltree.cc
               src/blockcache.cc
               src/filemgr.cc
               src/filemgr_ops.cc
               ${FORESTDB_FILE_OPS}
               ${GETTIMEOFDAY_VS}
               src/hash.cc
               src/hash_functions.cc
               src/list.cc
               src/wal.cc
               src/snapshot.cc
               utils/crc32.cc
               utils/adler32.cc
               utils/debug.cc
               utils/memleak.cc)
target_link_libraries(filemgr_test ${PTHREAD_LIB} ${LIBM})

add_executable(btreeblock_test
               tests/btreeblock_test.cc
               src/avltree.cc
               src/blockcache.cc
               src/btree.cc
               src/btree_kv.cc
               src/btreeblock.cc
               src/filemgr.cc
               src/filemgr_ops.cc
               ${FORESTDB_FILE_OPS}
               ${GETTIMEOFDAY_VS}
               src/hash.cc
               src/hash_functions.cc
               src/list.cc
               src/wal.cc
               src/snapshot.cc
               utils/crc32.cc
               utils/adler32.cc
               utils/debug.cc
               utils/memleak.cc)
target_link_libraries(btreeblock_test ${PTHREAD_LIB} ${LIBM})

add_executable(docio_test
               tests/docio_test.cc
               src/avltree.cc
               src/blockcache.cc
               src/docio.cc
               src/filemgr.cc
               src/filemgr_ops.cc
               ${FORESTDB_FILE_OPS}
               ${GETTIMEOFDAY_VS}
               src/hash.cc
               src/hash_functions.cc
               src/list.cc
               src/wal.cc
               src/snapshot.cc
               utils/crc32.cc
               utils/adler32.cc
               utils/debug.cc
               utils/memleak.cc)
target_link_libraries(docio_test ${PTHREAD_LIB} ${LIBM} ${LIBSNAPPY})

add_executable(hbtrie_test
               tests/hbtrie_test.cc
               src/avltree.cc
               src/blockcache.cc
               src/btree.cc
               src/btree_kv.cc
               src/btree_prefix_kv.cc
               src/btreeblock.cc
               src/docio.cc
               src/filemgr.cc
               src/filemgr_ops.cc
               ${FORESTDB_FILE_OPS}
               ${GETTIMEOFDAY_VS}
               src/hash.cc
               src/hash_functions.cc
               src/hbtrie.cc
               src/list.cc
               src/wal.cc
               src/snapshot.cc
               utils/crc32.cc
               utils/adler32.cc
               utils/debug.cc
               utils/memleak.cc)
target_link_libraries(hbtrie_test ${PTHREAD_LIB} ${LIBM} ${LIBSNAPPY})

add_executable(crc_test
               tests/crc_test.cc
               src/avltree.cc
               src/hash_functions.cc
               ${GETTIMEOFDAY_VS}
               utils/crc32.cc
               utils/adler32.cc
               utils/memleak.cc)
target_link_libraries(crc_test ${PTHREAD_LIB} ${LIBM})

if ("${CMAKE_BUILD_TYPE}" STREQUAL "Debug")
    set(CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR})
    INCLUDE(CodeCoverage)
    SETUP_TARGET_FOR_COVERAGE(test_coverage ctest ${CMAKE_SOURCE_DIR}/coverage)
endif()

enable_testing()
add_test(fdb_functional_test fdb_functional_test)
add_test(fdb_extended_test fdb_extended_test)
add_test(hash_test hash_test)
add_test(bcache_test bcache_test)
add_test(filemgr_test filemgr_test)
add_test(btreeblock_test btreeblock_test)
add_test(docio_test docio_test)
add_test(hbtrie_test hbtrie_test)
add_test(crc_test crc_test)
