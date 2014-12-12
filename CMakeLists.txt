cmake_minimum_required(VERSION 2.8)
project (ForestDB)

IF (${CMAKE_MAJOR_VERSION} GREATER 2)
    CMAKE_POLICY(SET CMP0042 NEW)
ENDIF (${CMAKE_MAJOR_VERSION} GREATER 2)

include_directories(BEFORE ${PROJECT_SOURCE_DIR}/option)
include_directories(BEFORE ${PROJECT_SOURCE_DIR}/utils)
include_directories(BEFORE ${PROJECT_SOURCE_DIR}/src)
include_directories(BEFORE ${PROJECT_SOURCE_DIR}/include)

if (COUCHBASE_SERVER_BUILD)
    ADD_DEFINITIONS(-D_DOC_COMP=1)
    include_directories(AFTER ${SNAPPY_INCLUDE_DIR})
else(COUCHBASE_SERVER_BUILD)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -D_GNU_SOURCE -D__DEBUG")
    if (NOT WIN32)
        set(CMAKE_CXX_FLAGS_DEBUG "-g -O0 -Wunused-variable")
        if (NOT(SNAPPY_OPTION STREQUAL "Disable"))
            LIST(APPEND CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}")
            INCLUDE(FindSnappy)
            ADD_DEFINITIONS(-D_DOC_COMP=1)
        endif (NOT(SNAPPY_OPTION STREQUAL "Disable"))
    endif(NOT WIN32)
endif(COUCHBASE_SERVER_BUILD)

if (NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "RelWithDebInfo" CACHE STRING "Choose the type of build, options are: Debug Release RelWithDebInfo MinSizeRel." FORCE)
endif(NOT CMAKE_BUILD_TYPE)

if (NOT WIN32)
    set(PTHREAD_LIB pthread)
    set(LIBM m)
    set(FORESTDB_FILE_OPS "src/filemgr_ops_linux.cc")
else (NOT WIN32)
    set(FORESTDB_FILE_OPS "src/filemgr_ops_windows.cc")
    set(GETTIMEOFDAY_VS "${PROJECT_SOURCE_DIR}/utils/gettimeofday_vs.cc")
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
    if (COUCHBASE_SERVER_BUILD)
       # using /W0 cause msvc to print out a warning that it overrides
       # previous settings (/W3 is added by default).
       # Let's just disable the ones we're "violating"
       # (we should probably fix them at some point?)
       set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /wd4716 /wd4244 /wd4267 /wd4101 /wd4800 /wd4700 /wd4018 /wd4102")
    else(COUCHBASE_SERVER_BUILD)
       set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /wd4716 /W0")
    endif(COUCHBASE_SERVER_BUILD)
endif()

add_library(forestdb SHARED
            src/api_wrapper.cc
            src/avltree.cc
            src/blockcache.cc
            src/btree.cc
            src/btree_kv.cc
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
            src/fdb_errors.cc
            src/hash_functions.cc
            src/hbtrie.cc
            src/iterator.cc
            src/list.cc
            src/hash.cc
            src/wal.cc
            ${GETTIMEOFDAY_VS}
            src/snapshot.cc
            src/transaction.cc
            src/kv_instance.cc
            utils/memleak.cc
            utils/crc32.cc
            utils/adler32.cc
            utils/debug.cc
            utils/partiallock.cc
            utils/time_utils.cc)
target_link_libraries(forestdb ${PTHREAD_LIB} ${LIBM} ${SNAPPY_LIBRARIES})

add_executable(forestdb_dump
               tools/forestdb_dump.cc
               src/api_wrapper.cc
               src/avltree.cc
               src/blockcache.cc
               src/btree.cc
               src/btree_kv.cc
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
               src/kv_instance.cc
               utils/memleak.cc
               utils/crc32.cc
               utils/adler32.cc
               utils/debug.cc
               utils/iniparser.cc
               utils/partiallock.cc
               utils/time_utils.cc)
target_link_libraries(forestdb_dump ${PTHREAD_LIB} ${LIBM} ${SNAPPY_LIBRARIES})
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


if ("${CMAKE_BUILD_TYPE}" STREQUAL "Coverage")
    if ((NOT COUCHBASE_SERVER_BUILD) AND (NOT WIN32))
        LIST(APPEND CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}")
        INCLUDE(CodeCoverage)
        SETUP_TARGET_FOR_COVERAGE(test_coverage ctest ${PROJECT_SOURCE_DIR}/coverage)
    endif((NOT COUCHBASE_SERVER_BUILD) AND (NOT WIN32))
endif()

if (("${CMAKE_BUILD_TYPE}" STREQUAL "Valgrind") AND (NOT WIN32))
    LIST(APPEND CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR})
    INCLUDE(MemoryCheck)
    SETUP_TARGET_FOR_MEMCHECK(test_valgrind ${PROJECT_BINARY_DIR}/fdb_functional_test)
endif()

# add top-level testing dir
enable_testing()
add_subdirectory("${PROJECT_SOURCE_DIR}/tests")
