add_executable(hash_test
               ${ROOT_SRC}/avltree.cc
               ${ROOT_SRC}/hash.cc
               ${ROOT_SRC}/hash_functions.cc
               ${ROOT_SRC}/list.cc
               ${GETTIMEOFDAY_VS}
               hash_test.cc
               ${ROOT_UTILS}/memleak.cc
               ${ROOT_UTILS}/time_utils.cc)
target_link_libraries(hash_test ${PTHREAD_LIB} ${LIBM} ${MALLOC_LIBRARIES}
                      ${PLATFORM_LIBRARY} ${LIBRT})

add_executable(mempool_test
               mempool_test.cc
               ${ROOT_SRC}/memory_pool.cc
               ${PROJECT_SOURCE_DIR}/${BREAKPAD_SRC}
               ${GETTIMEOFDAY_VS}
               ${ROOT_UTILS}/time_utils.cc
               $<TARGET_OBJECTS:TEST_STAT_AGG>)
target_link_libraries(mempool_test ${PTHREAD_LIB} ${LIBM}
                      ${ASYNC_IO_LIB} ${MALLOC_LIBRARIES}
                      ${PLATFORM_LIBRARY} ${LIBRT} ${CRYPTO_LIB}
                      ${DL_LIBRARIES} ${BREAKPAD_LIBRARIES})
set_target_properties(mempool_test PROPERTIES COMPILE_FLAGS "${CB_GNU_CXX11_OPTION}")

add_executable(execpool_test
               execpool_test.cc
               $<TARGET_OBJECTS:FDB_TOOLS_CORE>
               $<TARGET_OBJECTS:FDB_TOOLS_UTILS>
               ${PROJECT_SOURCE_DIR}/${FORESTDB_FILE_OPS}
               ${GETTIMEOFDAY_VS}
               $<TARGET_OBJECTS:TEST_STAT_AGG>)
target_link_libraries(execpool_test ${PTHREAD_LIB} ${LIBM} ${SNAPPY_LIBRARIES}
                      ${ASYNC_IO_LIB} ${MALLOC_LIBRARIES}
                      ${PLATFORM_LIBRARY} ${LIBRT} ${CRYPTO_LIB}
                      ${DL_LIBRARIES} ${BREAKPAD_LIBRARIES})
set_target_properties(execpool_test PROPERTIES COMPILE_FLAGS "${CB_GNU_CXX11_OPTION}")

add_executable(bcache_test
               bcache_test.cc
               $<TARGET_OBJECTS:FDB_TOOLS_CORE>
               $<TARGET_OBJECTS:FDB_TOOLS_UTILS>
               ${PROJECT_SOURCE_DIR}/${FORESTDB_FILE_OPS}
               ${GETTIMEOFDAY_VS})
target_link_libraries(bcache_test ${PTHREAD_LIB} ${LIBM} ${SNAPPY_LIBRARIES}
                      ${ASYNC_IO_LIB} ${MALLOC_LIBRARIES}
                      ${PLATFORM_LIBRARY} ${LIBRT} ${CRYPTO_LIB}
                      ${DL_LIBRARIES} ${BREAKPAD_LIBRARIES})
set_target_properties(bcache_test PROPERTIES COMPILE_FLAGS "${CB_GNU_CXX11_OPTION}")

add_executable(filemgr_test
               filemgr_test.cc
               $<TARGET_OBJECTS:FDB_TOOLS_CORE>
               $<TARGET_OBJECTS:FDB_TOOLS_UTILS>
               ${PROJECT_SOURCE_DIR}/${FORESTDB_FILE_OPS}
               ${GETTIMEOFDAY_VS})
target_link_libraries(filemgr_test ${PTHREAD_LIB} ${LIBM} ${SNAPPY_LIBRARIES}
                      ${ASYNC_IO_LIB} ${MALLOC_LIBRARIES}
                      ${PLATFORM_LIBRARY} ${LIBRT} ${CRYPTO_LIB}
                      ${DL_LIBRARIES} ${BREAKPAD_LIBRARIES})
set_target_properties(filemgr_test PROPERTIES COMPILE_FLAGS "${CB_GNU_CXX11_OPTION}")

add_executable(btreeblock_test
               btreeblock_test.cc
               $<TARGET_OBJECTS:FDB_TOOLS_CORE>
               $<TARGET_OBJECTS:FDB_TOOLS_UTILS>
               ${PROJECT_SOURCE_DIR}/${FORESTDB_FILE_OPS}
               ${GETTIMEOFDAY_VS})
target_link_libraries(btreeblock_test ${PTHREAD_LIB} ${LIBM} ${SNAPPY_LIBRARIES}
                      ${ASYNC_IO_LIB} ${MALLOC_LIBRARIES}
                      ${PLATFORM_LIBRARY} ${LIBRT} ${CRYPTO_LIB}
                      ${DL_LIBRARIES} ${BREAKPAD_LIBRARIES})
set_target_properties(btreeblock_test PROPERTIES COMPILE_FLAGS "${CB_GNU_CXX11_OPTION}")

add_executable(commit_log_test
               commit_log_test.cc
               $<TARGET_OBJECTS:FDB_TOOLS_CORE>
               $<TARGET_OBJECTS:FDB_TOOLS_UTILS>
               ${PROJECT_SOURCE_DIR}/${FORESTDB_FILE_OPS}
               ${GETTIMEOFDAY_VS})
target_link_libraries(commit_log_test ${PTHREAD_LIB} ${LIBM} ${SNAPPY_LIBRARIES}
                      ${ASYNC_IO_LIB} ${MALLOC_LIBRARIES}
                      ${PLATFORM_LIBRARY} ${LIBRT} ${CRYPTO_LIB}
                      ${DL_LIBRARIES} ${BREAKPAD_LIBRARIES})
set_target_properties(commit_log_test PROPERTIES COMPILE_FLAGS "${CB_GNU_CXX11_OPTION}")

add_executable(docio_test
               docio_test.cc
               $<TARGET_OBJECTS:FDB_TOOLS_CORE>
               $<TARGET_OBJECTS:FDB_TOOLS_UTILS>
               ${PROJECT_SOURCE_DIR}/${FORESTDB_FILE_OPS}
               ${GETTIMEOFDAY_VS})
target_link_libraries(docio_test ${PTHREAD_LIB} ${LIBM} ${SNAPPY_LIBRARIES}
                      ${ASYNC_IO_LIB} ${MALLOC_LIBRARIES}
                      ${PLATFORM_LIBRARY} ${LIBRT} ${CRYPTO_LIB}
                      ${DL_LIBRARIES} ${BREAKPAD_LIBRARIES})
set_target_properties(docio_test PROPERTIES COMPILE_FLAGS "${CB_GNU_CXX11_OPTION}")

add_executable(hbtrie_test
               hbtrie_test.cc
               $<TARGET_OBJECTS:FDB_TOOLS_CORE>
               $<TARGET_OBJECTS:FDB_TOOLS_UTILS>
               ${PROJECT_SOURCE_DIR}/${FORESTDB_FILE_OPS}
               ${GETTIMEOFDAY_VS})
target_link_libraries(hbtrie_test ${PTHREAD_LIB} ${LIBM} ${SNAPPY_LIBRARIES}
                      ${ASYNC_IO_LIB} ${MALLOC_LIBRARIES}
                      ${PLATFORM_LIBRARY} ${LIBRT} ${CRYPTO_LIB}
                      ${DL_LIBRARIES} ${BREAKPAD_LIBRARIES})
set_target_properties(hbtrie_test PROPERTIES COMPILE_FLAGS "${CB_GNU_CXX11_OPTION}")

add_executable(btree_new_test
               btree_new_test.cc
               $<TARGET_OBJECTS:FDB_TOOLS_CORE>
               $<TARGET_OBJECTS:FDB_TOOLS_UTILS>
               ${PROJECT_SOURCE_DIR}/${FORESTDB_FILE_OPS}
               ${GETTIMEOFDAY_VS})
target_link_libraries(btree_new_test ${PTHREAD_LIB} ${LIBM} ${SNAPPY_LIBRARIES}
                      ${ASYNC_IO_LIB} ${MALLOC_LIBRARIES}
                      ${PLATFORM_LIBRARY} ${LIBRT} ${CRYPTO_LIB}
                      ${DL_LIBRARIES} ${BREAKPAD_LIBRARIES})
set_target_properties(btree_new_test PROPERTIES COMPILE_FLAGS "${CB_GNU_CXX11_OPTION}")

add_executable(btree_kv_test
               btree_kv_test.cc
               ${ROOT_SRC}/btree_kv.cc
               ${ROOT_SRC}/avltree.cc
               ${GETTIMEOFDAY_VS}
               ${ROOT_UTILS}/memleak.cc
               ${ROOT_UTILS}/time_utils.cc)
target_link_libraries(btree_kv_test ${LIBM} ${MALLOC_LIBRARIES}
                      ${PLATFORM_LIBRARY} ${LIBRT})

add_executable(bnodecache_test
               bnodecache_test.cc
               $<TARGET_OBJECTS:FDB_TOOLS_CORE>
               $<TARGET_OBJECTS:FDB_TOOLS_UTILS>
               ${PROJECT_SOURCE_DIR}/${FORESTDB_FILE_OPS}
               ${GETTIMEOFDAY_VS}
               $<TARGET_OBJECTS:TEST_STAT_AGG>)
target_link_libraries(bnodecache_test ${PTHREAD_LIB} ${LIBM} ${SNAPPY_LIBRARIES}
                      ${ASYNC_IO_LIB} ${MALLOC_LIBRARIES}
                      ${PLATFORM_LIBRARY} ${LIBRT} ${CRYPTO_LIB}
                      ${DL_LIBRARIES} ${BREAKPAD_LIBRARIES})
set_target_properties(bnodecache_test PROPERTIES COMPILE_FLAGS "${CB_GNU_CXX11_OPTION}")

# add test target
add_test(hash_test hash_test)
add_test(mempool_test mempool_test)
add_test(execpool_test execpool_test)
add_test(bcache_test bcache_test)
add_test(filemgr_test filemgr_test)
add_test(btreeblock_test btreeblock_test)
add_test(commit_log_test commit_log_test)
add_test(docio_test docio_test)
add_test(hbtrie_test hbtrie_test)
add_test(btree_kv_test btree_kv_test)
add_test(btree_new_test btree_new_test)
add_test(bnodecache_test bnodecache_test)

ADD_CUSTOM_TARGET(unit_tests
    COMMAND ctest
)
