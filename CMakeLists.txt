cmake_minimum_required(VERSION 2.8.8)
project (ForestDB)

IF (${CMAKE_MAJOR_VERSION} GREATER 2)
    CMAKE_POLICY(SET CMP0042 NEW)
ENDIF (${CMAKE_MAJOR_VERSION} GREATER 2)

INCLUDE(CheckCXXCompilerFlag)
CHECK_CXX_COMPILER_FLAG("-std=c++11" COMPILER_SUPPORTS_CXX11)
CHECK_CXX_COMPILER_FLAG("-std=c++0x" COMPILER_SUPPORTS_CXX0X)
IF (COMPILER_SUPPORTS_CXX11)
    SET(STD_VERSION "-std=c++11")
ELSEIF(COMPILER_SUPPORTS_CXX0X)
    SET(STD_VERSION "-std=c++0x")
ELSE()
    IF (NOT WIN32)
        MESSAGE(FATAL_ERROR "Compiler ${CMAKE_CXX_COMPILER} has no C++11 support.")
    ENDIF()
ENDIF()

INCLUDE(CheckFunctionExists)
INCLUDE(CheckIncludeFileCXX)
INCLUDE(CheckIncludeFiles)
INCLUDE(CheckLibraryExists)
INCLUDE(CheckSymbolExists)
INCLUDE(CheckTypeSize)
INCLUDE(CTest)

IF (EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/.git)
    EXECUTE_PROCESS(COMMAND git describe --abbrev=7 --always --tags
                    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
                    OUTPUT_VARIABLE FORESTDB_VERSION
                    ERROR_QUIET
                    OUTPUT_STRIP_TRAILING_WHITESPACE)
ELSE (EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/.git)
    SET(FORESTDB_VERSION "unknown")
ENDIF (EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/.git)

include_directories(BEFORE ${PROJECT_SOURCE_DIR}/option)
include_directories(BEFORE ${PROJECT_SOURCE_DIR}/utils)
include_directories(BEFORE ${PROJECT_SOURCE_DIR}/src)
include_directories(BEFORE ${PROJECT_SOURCE_DIR}/include)
include_directories(BEFORE ${CMAKE_CURRENT_BINARY_DIR}/src)

CHECK_INCLUDE_FILES("sched.h" HAVE_SCHED_H)

CONFIGURE_FILE (${CMAKE_CURRENT_SOURCE_DIR}/src/config.cmake.h
                ${CMAKE_CURRENT_BINARY_DIR}/src/config.h)

LIST(APPEND CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake/Modules")

if (COUCHBASE_SERVER_BUILD)
    ADD_DEFINITIONS(-D_DOC_COMP=1)
    include_directories(AFTER ${SNAPPY_INCLUDE_DIR})

    if (WIN32)
       # The rest of Couchbase server use tcmalloc as the memory
       # allocator for WIN32. Override the allocator to jemalloc
       ADD_DEFINITIONS(-UHAVE_TCMALLOC)
       SET(COUCHBASE_MEMORY_ALLOCATOR "jemalloc")
       # Make sure that we define all of the variables
       include(CouchbaseMemoryAllocator)
    endif (WIN32)

    if (MEMORY_ALLOCATOR)
        include_directories(AFTER ${MALLOC_INCLUDE_DIR})
    endif (MEMORY_ALLOCATOR)
    set(DIRUTILS_LIBRARY dirutils)
    set(GTEST_LIBRARY gtest)
    if ("${CMAKE_BUILD_TYPE}" STREQUAL "Debug")
        ADD_DEFINITIONS(-D_DISABLE_SIGHANDLER=1)
    endif ("${CMAKE_BUILD_TYPE}" STREQUAL "Debug")

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
endif(COUCHBASE_SERVER_BUILD)

INCLUDE(FindAsyncIOLib)

if (NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "RelWithDebInfo" CACHE STRING "Choose the type of build, options are: Debug Release RelWithDebInfo MinSizeRel." FORCE)
endif(NOT CMAKE_BUILD_TYPE)

if (NOT LIBRT)
    unset(LIBRT CACHE)
endif (NOT LIBRT)
if (WIN32)
    set(FORESTDB_FILE_OPS "src/filemgr_ops_windows.cc")
    set(GETTIMEOFDAY_VS "${PROJECT_SOURCE_DIR}/utils/gettimeofday_vs.cc")
else (WIN32)
    set ( CMAKE_CXX_FLAGS_DEBUG "-O0 -Wunused-variable -Wall -pedantic ${STD_VERSION} -Wredundant-decls")
    set(PTHREAD_LIB pthread)
    set(LIBM m)
    set(FORESTDB_FILE_OPS "src/filemgr_ops_linux.cc")
    if (NOT APPLE)
        set(LIBRT rt)
    endif (NOT APPLE)
    FIND_LIBRARY(DL_LIBRARY NAMES dl)
    if (DL_LIBRARY)
        set(DL_LIBRARIES "${DL_LIBRARY}")
    endif (DL_LIBRARY)
endif(WIN32)

ADD_DEFINITIONS(-D_MVCC_WAL_ENABLE=1)

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

IF (COUCHBASE_SERVER_BUILD)
    # Include platform directory for Couchbase Server Builds
    INCLUDE_DIRECTORIES(BEFORE ${Platform_SOURCE_DIR}/include)
    SET(PLATFORM_LIBRARY platform)
    ADD_DEFINITIONS(-D_PLATFORM_LIB_AVAILABLE)
ENDIF()

# Comment the line below to disable compiling Copy-On-Write (COW) optimizations
ADD_DEFINITIONS (-D_COW_COMPACTION=1)

if (COUCHBASE_SERVER_BUILD)
    if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
        # Supress mismatched tags warnings seen with Clang only.
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-mismatched-tags")
        set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -Wno-mismatched-tags")
    elseif ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC")
       # using /W0 cause msvc to print out a warning that it overrides
       # previous settings (/W3 is added by default).
       # Let's just disable the ones we're "violating"
       # (we should probably fix them at some point?)
       set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /wd4716 /wd4244 /wd4267 /wd4101 /wd4800 /wd4700 /wd4018 /wd4102")
   endif()
else()
  # If building outside CB server build, set required flags for the selected compiler.
    if ("${CMAKE_C_COMPILER_ID}" STREQUAL "Clang")
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS_RELWITHDEBINFO} ${STD_VERSION} -Qunused-arguments -g -fomit-frame-pointer -pthread -Wno-mismatched-tags")
        set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -Wno-mismatched-tags")
    elseif ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS_RELWITHDEBINFO} ${STD_VERSION} -g -fomit-frame-pointer -pthread")
    elseif ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC")
       set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /wd4716 /W0")
    endif()
endif()

# Breakpad support with Couchbase Server Build only when on Windows/Linux.
if (COUCHBASE_SERVER_BUILD)
    if (BREAKPAD_FOUND)
        INCLUDE_DIRECTORIES(AFTER ${BREAKPAD_INCLUDE_DIR})
        if (WIN32)
            SET(BREAKPAD_SRC src/breakpad_win32.cc)
        elseif ("${CMAKE_SYSTEM_NAME}" STREQUAL "Linux")
            SET(BREAKPAD_SRC src/breakpad_linux.cc)
            # Breakpad has headers (which are dependencies for our breakpad
            # integration code) that don't compile cleanly as C++11, so the
            # GNU standard is used instead.
            SET_SOURCE_FILES_PROPERTIES(src/breakpad_linux.cc
                                        PROPERTIES
                                        COMPILE_FLAGS ${CB_GNU_CXX11_OPTION})
        else()
            SET(BREAKPAD_SRC src/breakpad_dummy.cc)
        endif()
    else (BREAKPAD_FOUND)
        SET(BREAKPAD_SRC src/breakpad_dummy.cc)
    endif(BREAKPAD_FOUND)
else()
    SET(BREAKPAD_SRC src/breakpad_dummy.cc)
endif()

if (NOT COUCHBASE_SERVER_BUILD)
   INCLUDE(ThreadSanitizer)
endif()

IF (_ENCRYPTION)
    INCLUDE(FindEncryptionLib)
ENDIF (_ENCRYPTION)

SET(FORESTDB_CORE_SRC
    ${PROJECT_SOURCE_DIR}/src/api_wrapper.cc
    ${PROJECT_SOURCE_DIR}/src/avltree.cc
    ${PROJECT_SOURCE_DIR}/src/bgflusher.cc
    ${PROJECT_SOURCE_DIR}/src/blockcache.cc
    ${PROJECT_SOURCE_DIR}/${BREAKPAD_SRC}
    ${PROJECT_SOURCE_DIR}/src/bnode.cc
    ${PROJECT_SOURCE_DIR}/src/bnodecache.cc
    ${PROJECT_SOURCE_DIR}/src/btree_new.cc
    ${PROJECT_SOURCE_DIR}/src/bnodemgr.cc
    ${PROJECT_SOURCE_DIR}/src/btree.cc
    ${PROJECT_SOURCE_DIR}/src/btree_kv.cc
    ${PROJECT_SOURCE_DIR}/src/btree_fast_str_kv.cc
    ${PROJECT_SOURCE_DIR}/src/btreeblock.cc
    ${PROJECT_SOURCE_DIR}/src/checksum.cc
    ${PROJECT_SOURCE_DIR}/src/commit_log.cc
    ${PROJECT_SOURCE_DIR}/src/compaction.cc
    ${PROJECT_SOURCE_DIR}/src/compactor.cc
    ${PROJECT_SOURCE_DIR}/src/configuration.cc
    ${PROJECT_SOURCE_DIR}/src/docio.cc
    ${PROJECT_SOURCE_DIR}/src/encryption.cc
    ${PROJECT_SOURCE_DIR}/src/encryption_aes.cc
    ${PROJECT_SOURCE_DIR}/src/encryption_bogus.cc
    ${PROJECT_SOURCE_DIR}/src/executorpool.cc
    ${PROJECT_SOURCE_DIR}/src/executorthread.cc
    ${PROJECT_SOURCE_DIR}/src/fdb_errors.cc
    ${PROJECT_SOURCE_DIR}/src/filemgr.cc
    ${PROJECT_SOURCE_DIR}/src/filemgr_ops.cc
    ${PROJECT_SOURCE_DIR}/src/file_handle.cc
    ${PROJECT_SOURCE_DIR}/src/forestdb.cc
    ${PROJECT_SOURCE_DIR}/src/globaltask.cc
    ${PROJECT_SOURCE_DIR}/src/hash.cc
    ${PROJECT_SOURCE_DIR}/src/hash_functions.cc
    ${PROJECT_SOURCE_DIR}/src/hbtrie.cc
    ${PROJECT_SOURCE_DIR}/src/iterator.cc
    ${PROJECT_SOURCE_DIR}/src/kvs_handle.cc
    ${PROJECT_SOURCE_DIR}/src/kv_instance.cc
    ${PROJECT_SOURCE_DIR}/src/list.cc
    ${PROJECT_SOURCE_DIR}/src/memory_pool.cc
    ${PROJECT_SOURCE_DIR}/src/staleblock.cc
    ${PROJECT_SOURCE_DIR}/src/superblock.cc
    ${PROJECT_SOURCE_DIR}/src/task_priority.cc
    ${PROJECT_SOURCE_DIR}/src/taskqueue.cc
    ${PROJECT_SOURCE_DIR}/src/transaction.cc
    ${PROJECT_SOURCE_DIR}/src/version.cc
    ${PROJECT_SOURCE_DIR}/src/wal.cc)

SET(FORESTDB_UTILS_SRC
    ${PROJECT_SOURCE_DIR}/utils/crc32.cc
    ${PROJECT_SOURCE_DIR}/utils/debug.cc
    ${PROJECT_SOURCE_DIR}/utils/memleak.cc
    ${PROJECT_SOURCE_DIR}/utils/partiallock.cc
    ${PROJECT_SOURCE_DIR}/utils/system_resource_stats.cc
    ${PROJECT_SOURCE_DIR}/utils/time_utils.cc
    ${PROJECT_SOURCE_DIR}/utils/timing.cc)

add_library(forestdb SHARED
            ${FORESTDB_FILE_OPS}
            ${GETTIMEOFDAY_VS}
            ${FORESTDB_CORE_SRC}
            ${FORESTDB_UTILS_SRC})
target_link_libraries(forestdb ${PTHREAD_LIB} ${LIBM} ${SNAPPY_LIBRARIES}
                      ${ASYNC_IO_LIB} ${MALLOC_LIBRARIES} ${PLATFORM_LIBRARY}
                      ${LIBRT} ${CRYPTO_LIB}
                      ${DL_LIBRARIES} ${BREAKPAD_LIBRARIES})

# Create objects libraries for the different "tools" parts forestdb, which can be reused
# by various targets.
add_library(FDB_TOOLS_CORE OBJECT ${FORESTDB_CORE_SRC})
set_target_properties(FDB_TOOLS_CORE PROPERTIES COMPILE_FLAGS "-D_FDB_TOOLS")

add_library(FDB_TOOLS_UTILS OBJECT ${FORESTDB_UTILS_SRC})
set_target_properties(FDB_TOOLS_UTILS PROPERTIES COMPILE_FLAGS "-D_FDB_TOOLS")

add_executable(forestdb_dump
               tools/dump_common.cc
               tools/forestdb_dump.cc
               ${FORESTDB_FILE_OPS}
               ${GETTIMEOFDAY_VS}
               $<TARGET_OBJECTS:FDB_TOOLS_CORE>
               $<TARGET_OBJECTS:FDB_TOOLS_UTILS>)
target_link_libraries(forestdb_dump ${PTHREAD_LIB} ${LIBM} ${SNAPPY_LIBRARIES}
                      ${ASYNC_IO_LIB} ${MALLOC_LIBRARIES} ${PLATFORM_LIBRARY}
                      ${LIBRT} ${CRYPTO_LIB}
                      ${DL_LIBRARIES} ${BREAKPAD_LIBRARIES})
set_target_properties(forestdb_dump PROPERTIES COMPILE_FLAGS "-D_FDB_TOOLS")

add_executable(forestdb_hexamine
               tools/dump_common.cc
               tools/forestdb_hexamine.cc
               ${FORESTDB_FILE_OPS}
               ${GETTIMEOFDAY_VS}
               $<TARGET_OBJECTS:FDB_TOOLS_CORE>
               $<TARGET_OBJECTS:FDB_TOOLS_UTILS>)
target_link_libraries(forestdb_hexamine ${PTHREAD_LIB} ${LIBM} ${SNAPPY_LIBRARIES}
                      ${ASYNC_IO_LIB} ${MALLOC_LIBRARIES} ${PLATFORM_LIBRARY}
                      ${LIBRT} ${CRYPTO_LIB}
                      ${DL_LIBRARIES} ${BREAKPAD_LIBRARIES})
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

if (COUCHBASE_SERVER_BUILD)
    ENABLE_CODE_COVERAGE_REPORT()
endif()
