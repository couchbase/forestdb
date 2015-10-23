cmake_minimum_required(VERSION 2.8)
project (ForestDB)

IF (${CMAKE_MAJOR_VERSION} GREATER 2)
    CMAKE_POLICY(SET CMP0042 NEW)
ENDIF (${CMAKE_MAJOR_VERSION} GREATER 2)

INCLUDE(CheckFunctionExists)
INCLUDE(CheckIncludeFileCXX)
INCLUDE(CheckIncludeFiles)
INCLUDE(CheckLibraryExists)
INCLUDE(CheckSymbolExists)
INCLUDE(CheckTypeSize)
INCLUDE(CTest)

include_directories(BEFORE ${PROJECT_SOURCE_DIR}/option)
include_directories(BEFORE ${PROJECT_SOURCE_DIR}/utils)
include_directories(BEFORE ${PROJECT_SOURCE_DIR}/src)
include_directories(BEFORE ${PROJECT_SOURCE_DIR}/include)
include_directories(BEFORE ${CMAKE_CURRENT_BINARY_DIR}/src)

CHECK_INCLUDE_FILES("atomic.h" HAVE_ATOMIC_H)
CHECK_INCLUDE_FILES("sched.h" HAVE_SCHED_H)

CONFIGURE_FILE (${CMAKE_CURRENT_SOURCE_DIR}/src/config.cmake.h
                ${CMAKE_CURRENT_BINARY_DIR}/src/config.h)

LIST(APPEND CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake/Modules")

if (COUCHBASE_SERVER_BUILD)
    ADD_DEFINITIONS(-D_DOC_COMP=1 -D_CRC32C=1)
    include_directories(AFTER ${SNAPPY_INCLUDE_DIR})
    include_directories(AFTER ${Platform_SOURCE_DIR}/include)
    if (MEMORY_ALLOCATOR)
        include_directories(AFTER ${MALLOC_INCLUDE_DIR})
    endif (MEMORY_ALLOCATOR)
    set(PLATFORM_LIBRARY platform)
    set(DIRUTILS_LIBRARY dirutils)
    set(GTEST_LIBRARY gtest)
else(COUCHBASE_SERVER_BUILD)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -D_GNU_SOURCE -D__DEBUG")
    if (NOT WIN32)
        if (NOT(SNAPPY_OPTION STREQUAL "Disable"))
            INCLUDE(FindSnappy)
            ADD_DEFINITIONS(-D_DOC_COMP=1)
        endif (NOT(SNAPPY_OPTION STREQUAL "Disable"))
    endif(NOT WIN32)
    if (_JEMALLOC EQUAL 1)
        INCLUDE(FindJemalloc)
    endif(_JEMALLOC EQUAL 1)
    if (EXISTS "${PROJECT_SOURCE_DIR}/platform/")
        INCLUDE(CouchbaseCodeCoverage)
        SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++0x")
        SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D_GNU_SOURCE -std=gnu99")
        INCLUDE (CMakePushCheckState)
        include_directories(BEFORE ${CMAKE_CURRENT_BINARY_DIR}/platform/include)
        ADD_SUBDIRECTORY(platform)
        set(PLATFORM_LIBRARY platform)
        ADD_DEFINITIONS(-D_CRC32C=1)
        include_directories(AFTER ${PROJECT_SOURCE_DIR}/platform/include)
    endif(EXISTS "${PROJECT_SOURCE_DIR}/platform/")
endif(COUCHBASE_SERVER_BUILD)

INCLUDE(FindAsyncIOLib)

FIND_LIBRARY(EXECINFO_LIBRARY
        NAMES execinfo)
if (EXECINFO_LIBRARY)
    set(BACKTRACE_LIBRARIES "${EXECINFO_LIBRARY}")
endif (EXECINFO_LIBRARY)

if (NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "RelWithDebInfo" CACHE STRING "Choose the type of build, options are: Debug Release RelWithDebInfo MinSizeRel." FORCE)
endif(NOT CMAKE_BUILD_TYPE)

if (NOT WIN32)
    set ( CMAKE_CXX_FLAGS_DEBUG "-O0 -Wunused-variable -Wall -pedantic -std=c++11 -Wredundant-decls")
    set(PTHREAD_LIB pthread)
    set(LIBM m)
    set(FORESTDB_FILE_OPS "src/filemgr_ops_linux.cc")
    if (NOT APPLE)
        set(LIBRT rt)
    endif (NOT APPLE)
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

IF ("${CMAKE_BUILD_TYPE}" STREQUAL "RelWithDebInfo")
    ADD_DEFINITIONS(-D_LATENCY_STATS)
ENDIF ("${CMAKE_BUILD_TYPE}" STREQUAL "RelWithDebInfo")

IF ("${CMAKE_BUILD_TYPE}" STREQUAL "Debug")
    ADD_DEFINITIONS(-D_LATENCY_STATS)
    ADD_DEFINITIONS(-D_LATENCY_STATS_DUMP_TO_FILE)
ENDIF ("${CMAKE_BUILD_TYPE}" STREQUAL "Debug")

# Uncomment the following define below to enable handle tracking on SIGABRT
# set(_TRACK_HANDLES 1)
#

IF (_TRACK_HANDLES EQUAL 1)
    ADD_DEFINITIONS(-D_TRACE_HANDLES=1)
ENDIF()

# Comment the line below to disable compiling Copy-On-Write (COW) optimizations
ADD_DEFINITIONS (-D_COW_COMPACTION=1)

if (COUCHBASE_SERVER_BUILD)
    if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC")
       # using /W0 cause msvc to print out a warning that it overrides
       # previous settings (/W3 is added by default).
       # Let's just disable the ones we're "violating"
       # (we should probably fix them at some point?)
       set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /wd4716 /wd4244 /wd4267 /wd4101 /wd4800 /wd4700 /wd4018 /wd4102")
   endif()
else()
  # If building outside CB server build, set required flags for the selected compiler.
    if ("${CMAKE_C_COMPILER_ID}" STREQUAL "Clang")
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS_RELWITHDEBINFO} -Qunused-arguments -g -fomit-frame-pointer -pthread")
    elseif ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS_RELWITHDEBINFO} -g -fomit-frame-pointer -pthread")
    elseif ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC")
       set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /wd4716 /W0")
    endif()
endif()

if (NOT COUCHBASE_SERVER_BUILD)
   INCLUDE(ThreadSanitizer)
endif()

IF (_ENCRYPTION)
    INCLUDE(FindEncryptionLib)
ENDIF (_ENCRYPTION)

add_library(forestdb SHARED
            src/api_wrapper.cc
            src/avltree.cc
            src/blockcache.cc
            src/btree.cc
            src/btree_kv.cc
            src/btree_str_kv.cc
            src/btree_fast_str_kv.cc
            src/btreeblock.cc
            src/bgflusher.cc
            src/checksum.cc
            src/compactor.cc
            src/configuration.cc
            src/docio.cc
            src/encryption.cc
            src/encryption_aes.cc
            src/encryption_bogus.cc
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
            src/version.cc
            src/staleblock.cc
            utils/memleak.cc
            utils/crc32.cc
            utils/debug.cc
            utils/partiallock.cc
            utils/time_utils.cc
            utils/timing.cc
            utils/system_resource_stats.cc)
target_link_libraries(forestdb ${PTHREAD_LIB} ${LIBM} ${SNAPPY_LIBRARIES}
                      ${ASYNC_IO_LIB} ${MALLOC_LIBRARIES} ${LIBRT}
                      ${BACKTRACE_LIBRARIES} ${PLATFORM_LIBRARY} ${CRYPTO_LIB})

add_executable(forestdb_dump
               tools/dump_common.cc
               tools/forestdb_dump.cc
               src/api_wrapper.cc
               src/avltree.cc
               src/blockcache.cc
               src/btree.cc
               src/btree_kv.cc
               src/btree_str_kv.cc
               src/btree_fast_str_kv.cc
               src/btreeblock.cc
               src/bgflusher.cc
               src/checksum.cc
               src/compactor.cc
               src/configuration.cc
               src/docio.cc
               src/encryption.cc
               src/encryption_aes.cc
               src/encryption_bogus.cc
               src/fdb_errors.cc
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
               src/version.cc
               src/staleblock.cc
               utils/memleak.cc
               utils/crc32.cc
               utils/debug.cc
               utils/iniparser.cc
               utils/partiallock.cc
               utils/time_utils.cc
               utils/timing.cc
               utils/system_resource_stats.cc)
target_link_libraries(forestdb_dump ${PTHREAD_LIB} ${LIBM} ${SNAPPY_LIBRARIES}
                      ${ASYNC_IO_LIB} ${MALLOC_LIBRARIES} ${BACKTRACE_LIBRARIES}
                      ${PLATFORM_LIBRARY} ${LIBRT} ${CRYPTO_LIB})
set_target_properties(forestdb_dump PROPERTIES COMPILE_FLAGS "-D_FDB_TOOLS")

add_executable(forestdb_hexamine
               tools/dump_common.cc
               tools/forestdb_hexamine.cc
               src/api_wrapper.cc
               src/avltree.cc
               src/blockcache.cc
               src/btree.cc
               src/btree_kv.cc
               src/btree_str_kv.cc
               src/btree_fast_str_kv.cc
               src/btreeblock.cc
               src/bgflusher.cc
               src/checksum.cc
               src/compactor.cc
               src/configuration.cc
               src/docio.cc
               src/encryption.cc
               src/encryption_aes.cc
               src/encryption_bogus.cc
               src/fdb_errors.cc
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
               src/version.cc
               src/staleblock.cc
               utils/memleak.cc
               utils/crc32.cc
               utils/debug.cc
               utils/iniparser.cc
               utils/partiallock.cc
               utils/time_utils.cc
               utils/timing.cc
               utils/system_resource_stats.cc)
target_link_libraries(forestdb_hexamine ${PTHREAD_LIB} ${LIBM} ${SNAPPY_LIBRARIES}
                      ${ASYNC_IO_LIB} ${MALLOC_LIBRARIES} ${BACKTRACE_LIBRARIES}
                      ${PLATFORM_LIBRARY} ${LIBRT} ${CRYPTO_LIB})
set_target_properties(forestdb_hexamine PROPERTIES COMPILE_FLAGS "-D_FDB_TOOLS")

if ((NOT COUCHBASE_SERVER_BUILD) OR (INSTALL_HEADER_FILES))
    INSTALL(FILES
            include/libforestdb/forestdb.h
            include/libforestdb/fdb_types.h
            include/libforestdb/fdb_errors.h
            DESTINATION include/libforestdb)
endif((NOT COUCHBASE_SERVER_BUILD) OR (INSTALL_HEADER_FILES))

INSTALL(TARGETS forestdb
        RUNTIME DESTINATION bin
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib)

INSTALL(TARGETS forestdb_dump
        RUNTIME DESTINATION bin)


if ("${CMAKE_BUILD_TYPE}" STREQUAL "Coverage")
    if ((NOT COUCHBASE_SERVER_BUILD) AND (NOT WIN32))
        INCLUDE(CodeCoverage)
        SETUP_TARGET_FOR_COVERAGE(test_coverage ctest ${PROJECT_SOURCE_DIR}/coverage)
    endif((NOT COUCHBASE_SERVER_BUILD) AND (NOT WIN32))
endif()

if (("${CMAKE_BUILD_TYPE}" STREQUAL "Valgrind") AND (NOT WIN32))
    INCLUDE(MemoryCheck)
    SETUP_TARGET_FOR_MEMCHECK(test_valgrind ${PROJECT_BINARY_DIR}/fdb_functional_test)
endif()

# add top-level testing dir
enable_testing()
add_subdirectory("${PROJECT_SOURCE_DIR}/tests")
