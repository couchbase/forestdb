add_executable(fdb_functional_test
               ${ROOT_SRC}/api_wrapper.cc
               ${ROOT_SRC}/avltree.cc
               ${ROOT_SRC}/blockcache.cc
               ${ROOT_SRC}/btree.cc
               ${ROOT_SRC}/btree_kv.cc
               ${ROOT_SRC}/btree_str_kv.cc
               ${ROOT_SRC}/btree_fast_str_kv.cc
               ${ROOT_SRC}/btreeblock.cc
               ${ROOT_SRC}/bgflusher.cc
               ${ROOT_SRC}/checksum.cc
               ${ROOT_SRC}/compactor.cc
               ${ROOT_SRC}/configuration.cc
               ${ROOT_SRC}/docio.cc
               ${ROOT_SRC}/encryption.cc
               ${ROOT_SRC}/encryption_aes.cc
               ${ROOT_SRC}/encryption_bogus.cc
               ${ROOT_SRC}/filemgr.cc
               ${ROOT_SRC}/filemgr_ops.cc
               ${PROJECT_SOURCE_DIR}/${FORESTDB_FILE_OPS}
               ${ROOT_SRC}/forestdb.cc
               ${ROOT_SRC}/fdb_errors.cc
               ${ROOT_SRC}/hash_functions.cc
               ${ROOT_SRC}/hbtrie.cc
               ${ROOT_SRC}/iterator.cc
               ${ROOT_SRC}/list.cc
               ${ROOT_SRC}/hash.cc
               ${ROOT_SRC}/wal.cc
               ${ROOT_SRC}/snapshot.cc
               ${ROOT_SRC}/transaction.cc
               ${ROOT_SRC}/kv_instance.cc
               ${ROOT_SRC}/version.cc
               ${ROOT_SRC}/staleblock.cc
               ${ROOT_UTILS}/memleak.cc
               ${ROOT_UTILS}/crc32.cc
               ${ROOT_UTILS}/debug.cc
               ${ROOT_UTILS}/partiallock.cc
               fdb_functional_test.cc
               functional_util.cc
               ${ROOT_UTILS}/time_utils.cc
               ${ROOT_UTILS}/timing.cc
               ${ROOT_UTILS}/system_resource_stats.cc
               ${GETTIMEOFDAY_VS})
target_link_libraries(fdb_functional_test ${PTHREAD_LIB} ${LIBM}
                      ${SNAPPY_LIBRARIES} ${ASYNC_IO_LIB}
                      ${MALLOC_LIBRARIES} ${BACKTRACE_LIBRARIES}
                      ${PLATFORM_LIBRARY} ${LIBRT} ${CRYPTO_LIB})
set_target_properties(fdb_functional_test PROPERTIES COMPILE_FLAGS "-D_FDB_TOOLS")

add_executable(fdb_extended_test
               ${ROOT_SRC}/api_wrapper.cc
               ${ROOT_SRC}/avltree.cc
               ${ROOT_SRC}/blockcache.cc
               ${ROOT_SRC}/btree.cc
               ${ROOT_SRC}/btree_kv.cc
               ${ROOT_SRC}/btree_str_kv.cc
               ${ROOT_SRC}/btree_fast_str_kv.cc
               ${ROOT_SRC}/btreeblock.cc
               ${ROOT_SRC}/bgflusher.cc
               ${ROOT_SRC}/checksum.cc
               ${ROOT_SRC}/compactor.cc
               ${ROOT_SRC}/configuration.cc
               ${ROOT_SRC}/docio.cc
               ${ROOT_SRC}/encryption.cc
               ${ROOT_SRC}/encryption_aes.cc
               ${ROOT_SRC}/encryption_bogus.cc
               ${ROOT_SRC}/filemgr.cc
               ${ROOT_SRC}/filemgr_ops.cc
               ${PROJECT_SOURCE_DIR}/${FORESTDB_FILE_OPS}
               ${ROOT_SRC}/forestdb.cc
               ${ROOT_SRC}/fdb_errors.cc
               ${ROOT_SRC}/hash_functions.cc
               ${ROOT_SRC}/hbtrie.cc
               ${ROOT_SRC}/iterator.cc
               ${ROOT_SRC}/list.cc
               ${ROOT_SRC}/hash.cc
               ${ROOT_SRC}/wal.cc
               ${ROOT_SRC}/snapshot.cc
               ${ROOT_SRC}/transaction.cc
               ${ROOT_SRC}/kv_instance.cc
               ${ROOT_SRC}/version.cc
               ${ROOT_SRC}/staleblock.cc
               ${ROOT_UTILS}/memleak.cc
               ${ROOT_UTILS}/crc32.cc
               ${ROOT_UTILS}/debug.cc
               ${ROOT_UTILS}/partiallock.cc
               fdb_extended_test.cc
               functional_util.cc
               ${ROOT_UTILS}/time_utils.cc
               ${ROOT_UTILS}/timing.cc
               ${ROOT_UTILS}/system_resource_stats.cc
               ${GETTIMEOFDAY_VS})
target_link_libraries(fdb_extended_test ${PTHREAD_LIB} ${LIBM}
                      ${SNAPPY_LIBRARIES} ${ASYNC_IO_LIB}
                      ${MALLOC_LIBRARIES} ${BACKTRACE_LIBRARIES}
                      ${PLATFORM_LIBRARY} ${LIBRT} ${CRYPTO_LIB})
set_target_properties(fdb_extended_test PROPERTIES COMPILE_FLAGS "-D_FDB_TOOLS")

add_executable(compact_functional_test
               ${ROOT_SRC}/api_wrapper.cc
               ${ROOT_SRC}/avltree.cc
               ${ROOT_SRC}/bgflusher.cc
               ${ROOT_SRC}/blockcache.cc
               ${ROOT_SRC}/btree.cc
               ${ROOT_SRC}/btree_kv.cc
               ${ROOT_SRC}/btree_str_kv.cc
               ${ROOT_SRC}/btree_fast_str_kv.cc
               ${ROOT_SRC}/btreeblock.cc
               ${ROOT_SRC}/checksum.cc
               ${ROOT_SRC}/compactor.cc
               ${ROOT_SRC}/configuration.cc
               ${ROOT_SRC}/docio.cc
               ${ROOT_SRC}/encryption.cc
               ${ROOT_SRC}/encryption_aes.cc
               ${ROOT_SRC}/encryption_bogus.cc
               ${ROOT_SRC}/filemgr.cc
               ${ROOT_SRC}/filemgr_ops.cc
               ${PROJECT_SOURCE_DIR}/${FORESTDB_FILE_OPS}
               ${ROOT_SRC}/forestdb.cc
               ${ROOT_SRC}/fdb_errors.cc
               ${ROOT_SRC}/hash_functions.cc
               ${ROOT_SRC}/hbtrie.cc
               ${ROOT_SRC}/iterator.cc
               ${ROOT_SRC}/list.cc
               ${ROOT_SRC}/hash.cc
               ${ROOT_SRC}/wal.cc
               ${ROOT_SRC}/snapshot.cc
               ${ROOT_SRC}/transaction.cc
               ${ROOT_SRC}/kv_instance.cc
               ${ROOT_SRC}/version.cc
               ${ROOT_SRC}/staleblock.cc
               ${ROOT_UTILS}/memleak.cc
               ${ROOT_UTILS}/crc32.cc
               ${ROOT_UTILS}/debug.cc
               ${ROOT_UTILS}/partiallock.cc
               compact_functional_test.cc
               functional_util.cc
               ${ROOT_UTILS}/time_utils.cc
               ${ROOT_UTILS}/timing.cc
               ${ROOT_UTILS}/system_resource_stats.cc
               ${GETTIMEOFDAY_VS})
target_link_libraries(compact_functional_test ${PTHREAD_LIB} ${LIBM}
                      ${SNAPPY_LIBRARIES} ${ASYNC_IO_LIB}
                      ${MALLOC_LIBRARIES} ${BACKTRACE_LIBRARIES}
                      ${PLATFORM_LIBRARY} ${LIBRT} ${CRYPTO_LIB})
set_target_properties(compact_functional_test PROPERTIES COMPILE_FLAGS "-D_FDB_TOOLS")

add_executable(iterator_functional_test
               ${ROOT_SRC}/api_wrapper.cc
               ${ROOT_SRC}/avltree.cc
               ${ROOT_SRC}/bgflusher.cc
               ${ROOT_SRC}/blockcache.cc
               ${ROOT_SRC}/btree.cc
               ${ROOT_SRC}/btree_kv.cc
               ${ROOT_SRC}/btree_str_kv.cc
               ${ROOT_SRC}/btree_fast_str_kv.cc
               ${ROOT_SRC}/btreeblock.cc
               ${ROOT_SRC}/checksum.cc
               ${ROOT_SRC}/compactor.cc
               ${ROOT_SRC}/configuration.cc
               ${ROOT_SRC}/docio.cc
               ${ROOT_SRC}/encryption.cc
               ${ROOT_SRC}/encryption_aes.cc
               ${ROOT_SRC}/encryption_bogus.cc
               ${ROOT_SRC}/filemgr.cc
               ${ROOT_SRC}/filemgr_ops.cc
               ${PROJECT_SOURCE_DIR}/${FORESTDB_FILE_OPS}
               ${ROOT_SRC}/forestdb.cc
               ${ROOT_SRC}/fdb_errors.cc
               ${ROOT_SRC}/hash_functions.cc
               ${ROOT_SRC}/hbtrie.cc
               ${ROOT_SRC}/iterator.cc
               ${ROOT_SRC}/list.cc
               ${ROOT_SRC}/hash.cc
               ${ROOT_SRC}/wal.cc
               ${ROOT_SRC}/snapshot.cc
               ${ROOT_SRC}/transaction.cc
               ${ROOT_SRC}/kv_instance.cc
               ${ROOT_SRC}/version.cc
               ${ROOT_SRC}/staleblock.cc
               ${ROOT_UTILS}/memleak.cc
               ${ROOT_UTILS}/crc32.cc
               ${ROOT_UTILS}/debug.cc
               ${ROOT_UTILS}/partiallock.cc
               iterator_functional_test.cc
               functional_util.cc
               ${ROOT_UTILS}/time_utils.cc
               ${ROOT_UTILS}/timing.cc
               ${ROOT_UTILS}/system_resource_stats.cc
               ${GETTIMEOFDAY_VS})
target_link_libraries(iterator_functional_test ${PTHREAD_LIB} ${LIBM}
                      ${SNAPPY_LIBRARIES} ${ASYNC_IO_LIB}
                      ${MALLOC_LIBRARIES} ${BACKTRACE_LIBRARIES}
                      ${PLATFORM_LIBRARY} ${LIBRT} ${CRYPTO_LIB})
set_target_properties(iterator_functional_test PROPERTIES COMPILE_FLAGS "-D_FDB_TOOLS")

add_executable(mvcc_functional_test
               ${ROOT_SRC}/api_wrapper.cc
               ${ROOT_SRC}/avltree.cc
               ${ROOT_SRC}/bgflusher.cc
               ${ROOT_SRC}/blockcache.cc
               ${ROOT_SRC}/btree.cc
               ${ROOT_SRC}/btree_kv.cc
               ${ROOT_SRC}/btree_str_kv.cc
               ${ROOT_SRC}/btree_fast_str_kv.cc
               ${ROOT_SRC}/btreeblock.cc
               ${ROOT_SRC}/checksum.cc
               ${ROOT_SRC}/compactor.cc
               ${ROOT_SRC}/configuration.cc
               ${ROOT_SRC}/docio.cc
               ${ROOT_SRC}/encryption.cc
               ${ROOT_SRC}/encryption_aes.cc
               ${ROOT_SRC}/encryption_bogus.cc
               ${ROOT_SRC}/filemgr.cc
               ${ROOT_SRC}/filemgr_ops.cc
               ${PROJECT_SOURCE_DIR}/${FORESTDB_FILE_OPS}
               ${ROOT_SRC}/forestdb.cc
               ${ROOT_SRC}/fdb_errors.cc
               ${ROOT_SRC}/hash_functions.cc
               ${ROOT_SRC}/hbtrie.cc
               ${ROOT_SRC}/iterator.cc
               ${ROOT_SRC}/list.cc
               ${ROOT_SRC}/hash.cc
               ${ROOT_SRC}/wal.cc
               ${ROOT_SRC}/snapshot.cc
               ${ROOT_SRC}/transaction.cc
               ${ROOT_SRC}/kv_instance.cc
               ${ROOT_SRC}/version.cc
               ${ROOT_SRC}/staleblock.cc
               ${ROOT_UTILS}/memleak.cc
               ${ROOT_UTILS}/crc32.cc
               ${ROOT_UTILS}/debug.cc
               ${ROOT_UTILS}/partiallock.cc
               mvcc_functional_test.cc
               functional_util.cc
               ${ROOT_UTILS}/time_utils.cc
               ${ROOT_UTILS}/timing.cc
               ${ROOT_UTILS}/system_resource_stats.cc
               ${GETTIMEOFDAY_VS})
target_link_libraries(mvcc_functional_test ${PTHREAD_LIB} ${LIBM}
                      ${SNAPPY_LIBRARIES} ${ASYNC_IO_LIB}
                      ${MALLOC_LIBRARIES} ${BACKTRACE_LIBRARIES}
                      ${PLATFORM_LIBRARY} ${LIBRT} ${CRYPTO_LIB})
set_target_properties(mvcc_functional_test PROPERTIES COMPILE_FLAGS "-D_FDB_TOOLS")

add_executable(multi_kv_functional_test
               ${ROOT_SRC}/api_wrapper.cc
               ${ROOT_SRC}/avltree.cc
               ${ROOT_SRC}/bgflusher.cc
               ${ROOT_SRC}/blockcache.cc
               ${ROOT_SRC}/btree.cc
               ${ROOT_SRC}/btree_kv.cc
               ${ROOT_SRC}/btree_str_kv.cc
               ${ROOT_SRC}/btree_fast_str_kv.cc
               ${ROOT_SRC}/btreeblock.cc
               ${ROOT_SRC}/checksum.cc
               ${ROOT_SRC}/compactor.cc
               ${ROOT_SRC}/configuration.cc
               ${ROOT_SRC}/docio.cc
               ${ROOT_SRC}/encryption.cc
               ${ROOT_SRC}/encryption_aes.cc
               ${ROOT_SRC}/encryption_bogus.cc
               ${ROOT_SRC}/filemgr.cc
               ${ROOT_SRC}/filemgr_ops.cc
               ${PROJECT_SOURCE_DIR}/${FORESTDB_FILE_OPS}
               ${ROOT_SRC}/forestdb.cc
               ${ROOT_SRC}/fdb_errors.cc
               ${ROOT_SRC}/hash_functions.cc
               ${ROOT_SRC}/hbtrie.cc
               ${ROOT_SRC}/iterator.cc
               ${ROOT_SRC}/list.cc
               ${ROOT_SRC}/hash.cc
               ${ROOT_SRC}/wal.cc
               ${ROOT_SRC}/snapshot.cc
               ${ROOT_SRC}/transaction.cc
               ${ROOT_SRC}/kv_instance.cc
               ${ROOT_SRC}/version.cc
               ${ROOT_SRC}/staleblock.cc
               ${ROOT_UTILS}/memleak.cc
               ${ROOT_UTILS}/crc32.cc
               ${ROOT_UTILS}/debug.cc
               ${ROOT_UTILS}/partiallock.cc
               multi_kv_functional_test.cc
               functional_util.cc
               ${ROOT_UTILS}/time_utils.cc
               ${ROOT_UTILS}/timing.cc
               ${ROOT_UTILS}/system_resource_stats.cc
               ${GETTIMEOFDAY_VS})
target_link_libraries(multi_kv_functional_test ${PTHREAD_LIB} ${LIBM}
                      ${SNAPPY_LIBRARIES} ${ASYNC_IO_LIB}
                      ${MALLOC_LIBRARIES} ${BACKTRACE_LIBRARIES}
                      ${PLATFORM_LIBRARY} ${LIBRT} ${CRYPTO_LIB})
set_target_properties(multi_kv_functional_test PROPERTIES COMPILE_FLAGS "-D_FDB_TOOLS")

add_executable(big_concurrency_test
               ${ROOT_SRC}/api_wrapper.cc
               ${ROOT_SRC}/avltree.cc
               ${ROOT_SRC}/bgflusher.cc
               ${ROOT_SRC}/blockcache.cc
               ${ROOT_SRC}/btree.cc
               ${ROOT_SRC}/btree_kv.cc
               ${ROOT_SRC}/btree_str_kv.cc
               ${ROOT_SRC}/btree_fast_str_kv.cc
               ${ROOT_SRC}/btreeblock.cc
               ${ROOT_SRC}/checksum.cc
               ${ROOT_SRC}/compactor.cc
               ${ROOT_SRC}/configuration.cc
               ${ROOT_SRC}/docio.cc
               ${ROOT_SRC}/encryption.cc
               ${ROOT_SRC}/encryption_aes.cc
               ${ROOT_SRC}/encryption_bogus.cc
               ${ROOT_SRC}/filemgr.cc
               ${ROOT_SRC}/filemgr_ops.cc
               ${PROJECT_SOURCE_DIR}/${FORESTDB_FILE_OPS}
               ${ROOT_SRC}/forestdb.cc
               ${ROOT_SRC}/fdb_errors.cc
               ${ROOT_SRC}/hash_functions.cc
               ${ROOT_SRC}/hbtrie.cc
               ${ROOT_SRC}/iterator.cc
               ${ROOT_SRC}/list.cc
               ${ROOT_SRC}/hash.cc
               ${ROOT_SRC}/wal.cc
               ${ROOT_SRC}/snapshot.cc
               ${ROOT_SRC}/transaction.cc
               ${ROOT_SRC}/kv_instance.cc
               ${ROOT_SRC}/version.cc
               ${ROOT_SRC}/staleblock.cc
               ${ROOT_UTILS}/memleak.cc
               ${ROOT_UTILS}/crc32.cc
               ${ROOT_UTILS}/debug.cc
               ${ROOT_UTILS}/partiallock.cc
               big_concurrency_test.cc
               ${ROOT_UTILS}/time_utils.cc
               ${ROOT_UTILS}/timing.cc
               ${ROOT_UTILS}/system_resource_stats.cc
               ${GETTIMEOFDAY_VS})
target_link_libraries(big_concurrency_test ${PTHREAD_LIB} ${LIBM}
                      ${SNAPPY_LIBRARIES} ${ASYNC_IO_LIB}
                      ${MALLOC_LIBRARIES} ${BACKTRACE_LIBRARIES}
                      ${PLATFORM_LIBRARY} ${LIBRT} ${CRYPTO_LIB})
set_target_properties(big_concurrency_test PROPERTIES COMPILE_FLAGS
                      "-D_FDB_TOOLS")

add_executable(big_compaction_test
               ${ROOT_SRC}/api_wrapper.cc
               ${ROOT_SRC}/avltree.cc
               ${ROOT_SRC}/bgflusher.cc
               ${ROOT_SRC}/blockcache.cc
               ${ROOT_SRC}/btree.cc
               ${ROOT_SRC}/btree_kv.cc
               ${ROOT_SRC}/btree_str_kv.cc
               ${ROOT_SRC}/btree_fast_str_kv.cc
               ${ROOT_SRC}/btreeblock.cc
               ${ROOT_SRC}/checksum.cc
               ${ROOT_SRC}/compactor.cc
               ${ROOT_SRC}/configuration.cc
               ${ROOT_SRC}/docio.cc
               ${ROOT_SRC}/encryption.cc
               ${ROOT_SRC}/encryption_aes.cc
               ${ROOT_SRC}/encryption_bogus.cc
               ${ROOT_SRC}/encryption.cc
               ${ROOT_SRC}/encryption_aes.cc
               ${ROOT_SRC}/encryption_bogus.cc
               ${ROOT_SRC}/filemgr.cc
               ${ROOT_SRC}/filemgr_ops.cc
               ${PROJECT_SOURCE_DIR}/${FORESTDB_FILE_OPS}
               ${ROOT_SRC}/forestdb.cc
               ${ROOT_SRC}/fdb_errors.cc
               ${ROOT_SRC}/hash_functions.cc
               ${ROOT_SRC}/hbtrie.cc
               ${ROOT_SRC}/iterator.cc
               ${ROOT_SRC}/list.cc
               ${ROOT_SRC}/hash.cc
               ${ROOT_SRC}/wal.cc
               ${ROOT_SRC}/snapshot.cc
               ${ROOT_SRC}/transaction.cc
               ${ROOT_SRC}/kv_instance.cc
               ${ROOT_SRC}/version.cc
               ${ROOT_SRC}/staleblock.cc
               ${ROOT_UTILS}/memleak.cc
               ${ROOT_UTILS}/crc32.cc
               ${ROOT_UTILS}/debug.cc
               ${ROOT_UTILS}/partiallock.cc
               big_compaction_test.cc
               ${ROOT_UTILS}/time_utils.cc
               ${ROOT_UTILS}/timing.cc
               ${ROOT_UTILS}/system_resource_stats.cc
               ${GETTIMEOFDAY_VS})
target_link_libraries(big_compaction_test ${PTHREAD_LIB} ${LIBM}
                      ${SNAPPY_LIBRARIES} ${ASYNC_IO_LIB}
                      ${MALLOC_LIBRARIES} ${BACKTRACE_LIBRARIES}
                      ${PLATFORM_LIBRARY} ${LIBRT} ${CRYPTO_LIB})
set_target_properties(big_compaction_test PROPERTIES COMPILE_FLAGS
                      "-D_FDB_TOOLS")

if (COUCHBASE_SERVER_BUILD)
add_executable(crc_migration_test
               crc_migration.cc
               ${ROOT_SRC}/checksum.cc
               ${ROOT_UTILS}/crc32.cc
               ${ROOT_UTILS}/debug.cc)
target_link_libraries(crc_migration_test
                      ${DIRUTILS_LIBRARY}
                      ${PLATFORM_LIBRARY}
                      ${GTEST_LIBRARY}
                      ${BACKTRACE_LIBRARIES}
                      forestdb)
target_include_directories(crc_migration_test
                           PUBLIC
                           ${gtest_SOURCE_DIR}/include)

add_test(crc_migration_test crc_migration_test)
endif(COUCHBASE_SERVER_BUILD)


# add test target
add_test(fdb_functional_test fdb_functional_test)
add_test(fdb_extended_test fdb_extended_test)
add_test(compact_functional_test compact_functional_test)
add_test(iterator_functional_test iterator_functional_test)
add_test(mvcc_functional_test mvcc_functional_test)
add_test(multi_kv_functional_test multi_kv_functional_test)


ADD_CUSTOM_TARGET(functional_tests
    COMMAND ctest
)
