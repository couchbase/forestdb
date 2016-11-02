# every file same as FORESTDB_CORE_SRC execept filemgr_ops.cc replaced
# with filemgr_anomalous_ops.cc
SET(FORESTDB_COMMON_CORE_SRC
    ${PROJECT_SOURCE_DIR}/src/api_wrapper.cc
    ${PROJECT_SOURCE_DIR}/src/avltree.cc
    ${PROJECT_SOURCE_DIR}/src/bgflusher.cc
    ${PROJECT_SOURCE_DIR}/src/blockcache.cc
    ${PROJECT_SOURCE_DIR}/src/bnode.cc
    ${PROJECT_SOURCE_DIR}/src/bnodecache.cc
    ${PROJECT_SOURCE_DIR}/${BREAKPAD_SRC}
    ${PROJECT_SOURCE_DIR}/src/btree.cc
    ${PROJECT_SOURCE_DIR}/src/btree_kv.cc
    ${PROJECT_SOURCE_DIR}/src/btree_new.cc
    ${PROJECT_SOURCE_DIR}/src/bnode.cc
    ${PROJECT_SOURCE_DIR}/src/bnodemgr.cc
    ${PROJECT_SOURCE_DIR}/src/bnodecache.cc
    ${PROJECT_SOURCE_DIR}/src/btree_fast_str_kv.cc
    ${PROJECT_SOURCE_DIR}/src/btreeblock.cc
    ${PROJECT_SOURCE_DIR}/src/checksum.cc
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
    ${PROJECT_SOURCE_DIR}/src/file_handle.cc
    ${PROJECT_SOURCE_DIR}/src/forestdb.cc
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
    ${PROJECT_SOURCE_DIR}/src/taskqueue.cc
    ${PROJECT_SOURCE_DIR}/src/transaction.cc
    ${PROJECT_SOURCE_DIR}/src/version.cc
    ${PROJECT_SOURCE_DIR}/src/wal.cc)

add_library(FDB_TOOLS_CCORE OBJECT ${FORESTDB_COMMON_CORE_SRC})
set_target_properties(FDB_TOOLS_CCORE PROPERTIES
                      COMPILE_FLAGS "-D_FDB_TOOLS ${CB_GNU_CXX11_OPTION}")

add_executable(fdb_anomaly_test
               $<TARGET_OBJECTS:FDB_TOOLS_CCORE>
               filemgr_anomalous_ops.cc
               ${PROJECT_SOURCE_DIR}/${FORESTDB_FILE_OPS}
               fdb_anomaly_test.cc
               ${GETTIMEOFDAY_VS}
               $<TARGET_OBJECTS:FDB_TOOLS_UTILS>)
target_link_libraries(fdb_anomaly_test ${PTHREAD_LIB} ${LIBM}
                      ${SNAPPY_LIBRARIES} ${ASYNC_IO_LIB}
                      ${MALLOC_LIBRARIES} ${PLATFORM_LIBRARY}
                      ${LIBRT} ${CRYPTO_LIB}
                      ${DL_LIBRARIES} ${BREAKPAD_LIBRARIES})
set_target_properties(fdb_anomaly_test PROPERTIES COMPILE_FLAGS "-D_FDB_TOOLS")

add_executable(disk_sim_test
               $<TARGET_OBJECTS:FDB_TOOLS_CCORE>
               filemgr_anomalous_ops.cc
               ${PROJECT_SOURCE_DIR}/${FORESTDB_FILE_OPS}
               disk_sim_test.cc
               ${GETTIMEOFDAY_VS}
               $<TARGET_OBJECTS:FDB_TOOLS_UTILS>)
target_link_libraries(disk_sim_test ${PTHREAD_LIB} ${LIBM}
                      ${SNAPPY_LIBRARIES} ${ASYNC_IO_LIB}
                      ${MALLOC_LIBRARIES} ${PLATFORM_LIBRARY}
                      ${LIBRT} ${CRYPTO_LIB}
                      ${DL_LIBRARIES} ${BREAKPAD_LIBRARIES})
set_target_properties(disk_sim_test PROPERTIES COMPILE_FLAGS "-D_FDB_TOOLS")

# add test target
add_test(fdb_anomaly_test fdb_anomaly_test)
add_test(disk_sim_test disk_sim_test)

ADD_CUSTOM_TARGET(anomaly_tests
    COMMAND ctest
)
