add_executable(fdb_anomaly_test
               ${ROOT_SRC}/atomic.cc
               ${ROOT_SRC}/api_wrapper.cc
               ${ROOT_SRC}/avltree.cc
               ${ROOT_SRC}/blockcache.cc
               ${ROOT_SRC}/btree.cc
               ${ROOT_SRC}/btree_kv.cc
               ${ROOT_SRC}/btree_str_kv.cc
               ${ROOT_SRC}/btree_fast_str_kv.cc
               ${ROOT_SRC}/btreeblock.cc
               ${ROOT_SRC}/compactor.cc
               ${ROOT_SRC}/configuration.cc
               ${ROOT_SRC}/docio.cc
               ${ROOT_SRC}/filemgr.cc
               filemgr_anomalous_ops.cc
               ${PROJECT_SOURCE_DIR}/${FORESTDB_FILE_OPS}
               ${ROOT_SRC}/forestdb.cc
               ${ROOT_SRC}/fdb_errors.cc
               ${ROOT_SRC}/hash_functions.cc
               ${ROOT_SRC}/hbtrie.cc
               ${ROOT_SRC}/iterator.cc
               fdb_anomaly_test.cc
               ${ROOT_SRC}/list.cc
               ${ROOT_SRC}/hash.cc
               ${ROOT_SRC}/wal.cc
               ${GETTIMEOFDAY_VS}
               ${ROOT_SRC}/snapshot.cc
               ${ROOT_SRC}/transaction.cc
               ${ROOT_SRC}/kv_instance.cc
               ${ROOT_UTILS}/memleak.cc
               ${ROOT_UTILS}/crc32.cc
               ${ROOT_UTILS}/adler32.cc
               ${ROOT_UTILS}/debug.cc
               ${ROOT_UTILS}/partiallock.cc
               ${ROOT_UTILS}/time_utils.cc
               ${ROOT_UTILS}/get_memory_size.cc)
target_link_libraries(fdb_anomaly_test ${PTHREAD_LIB} ${LIBM}
                      ${SNAPPY_LIBRARIES})
set_target_properties(fdb_anomaly_test PROPERTIES COMPILE_FLAGS "-D_FDB_TOOLS")



# add test target
add_test(fdb_anomaly_test fdb_anomaly_test)
ADD_CUSTOM_TARGET(anomaly_tests
    COMMAND ctest
)
