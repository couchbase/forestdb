add_executable(fdb_functional_test
               ${PROJECT_SOURCE_DIR}/${FORESTDB_FILE_OPS}
               fdb_functional_test.cc
               functional_util.cc
               ${GETTIMEOFDAY_VS}
               $<TARGET_OBJECTS:FDB_TOOLS_CORE>
               $<TARGET_OBJECTS:FDB_TOOLS_UTILS>)
target_link_libraries(fdb_functional_test ${PTHREAD_LIB} ${LIBM}
                      ${SNAPPY_LIBRARIES} ${ASYNC_IO_LIB}
                      ${MALLOC_LIBRARIES} ${PLATFORM_LIBRARY}
                      ${LIBRT} ${CRYPTO_LIB}
                      ${DL_LIBRARIES} ${BREAKPAD_LIBRARIES})
set_target_properties(fdb_functional_test PROPERTIES COMPILE_FLAGS "-D_FDB_TOOLS")

add_executable(fdb_extended_test
               ${PROJECT_SOURCE_DIR}/${FORESTDB_FILE_OPS}
               fdb_extended_test.cc
               functional_util.cc
               ${GETTIMEOFDAY_VS}
               $<TARGET_OBJECTS:FDB_TOOLS_CORE>
               $<TARGET_OBJECTS:FDB_TOOLS_UTILS>)
target_link_libraries(fdb_extended_test ${PTHREAD_LIB} ${LIBM}
                      ${SNAPPY_LIBRARIES} ${ASYNC_IO_LIB}
                      ${MALLOC_LIBRARIES} ${PLATFORM_LIBRARY}
                      ${LIBRT} ${CRYPTO_LIB}
                      ${DL_LIBRARIES} ${BREAKPAD_LIBRARIES})
set_target_properties(fdb_extended_test PROPERTIES COMPILE_FLAGS "-D_FDB_TOOLS")

add_executable(compact_functional_test
               ${PROJECT_SOURCE_DIR}/${FORESTDB_FILE_OPS}
               compact_functional_test.cc
               functional_util.cc
               ${GETTIMEOFDAY_VS}
               $<TARGET_OBJECTS:FDB_TOOLS_CORE>
               $<TARGET_OBJECTS:FDB_TOOLS_UTILS>)
target_link_libraries(compact_functional_test ${PTHREAD_LIB} ${LIBM}
                      ${SNAPPY_LIBRARIES} ${ASYNC_IO_LIB}
                      ${MALLOC_LIBRARIES} ${PLATFORM_LIBRARY} ${LIBRT}
                      ${CRYPTO_LIB}
                      ${DL_LIBRARIES} ${BREAKPAD_LIBRARIES})
set_target_properties(compact_functional_test PROPERTIES COMPILE_FLAGS "-D_FDB_TOOLS")

add_executable(iterator_functional_test
               ${PROJECT_SOURCE_DIR}/${FORESTDB_FILE_OPS}
               iterator_functional_test.cc
               functional_util.cc
               ${GETTIMEOFDAY_VS}
               $<TARGET_OBJECTS:FDB_TOOLS_CORE>
               $<TARGET_OBJECTS:FDB_TOOLS_UTILS>)
target_link_libraries(iterator_functional_test ${PTHREAD_LIB} ${LIBM}
                      ${SNAPPY_LIBRARIES} ${ASYNC_IO_LIB}
                      ${MALLOC_LIBRARIES} ${PLATFORM_LIBRARY}
                      ${LIBRT} ${CRYPTO_LIB}
                      ${DL_LIBRARIES} ${BREAKPAD_LIBRARIES})
set_target_properties(iterator_functional_test PROPERTIES COMPILE_FLAGS "-D_FDB_TOOLS")

add_executable(mvcc_functional_test
               ${PROJECT_SOURCE_DIR}/${FORESTDB_FILE_OPS}
               mvcc_functional_test.cc
               functional_util.cc
               ${GETTIMEOFDAY_VS}
               $<TARGET_OBJECTS:FDB_TOOLS_CORE>
               $<TARGET_OBJECTS:FDB_TOOLS_UTILS>)
target_link_libraries(mvcc_functional_test ${PTHREAD_LIB} ${LIBM}
                      ${SNAPPY_LIBRARIES} ${ASYNC_IO_LIB}
                      ${MALLOC_LIBRARIES} ${PLATFORM_LIBRARY}
                      ${LIBRT} ${CRYPTO_LIB}
                      ${DL_LIBRARIES} ${BREAKPAD_LIBRARIES})
set_target_properties(mvcc_functional_test PROPERTIES COMPILE_FLAGS "-D_FDB_TOOLS")

add_executable(multi_kv_functional_test
               ${PROJECT_SOURCE_DIR}/${FORESTDB_FILE_OPS}
               multi_kv_functional_test.cc
               functional_util.cc
               ${GETTIMEOFDAY_VS}
               $<TARGET_OBJECTS:FDB_TOOLS_CORE>
               $<TARGET_OBJECTS:FDB_TOOLS_UTILS>)
target_link_libraries(multi_kv_functional_test ${PTHREAD_LIB} ${LIBM}
                      ${SNAPPY_LIBRARIES} ${ASYNC_IO_LIB}
                      ${MALLOC_LIBRARIES} ${PLATFORM_LIBRARY}
                      ${LIBRT} ${CRYPTO_LIB}
                      ${DL_LIBRARIES} ${BREAKPAD_LIBRARIES})
set_target_properties(multi_kv_functional_test PROPERTIES COMPILE_FLAGS "-D_FDB_TOOLS")

add_executable(big_concurrency_test
               ${PROJECT_SOURCE_DIR}/${FORESTDB_FILE_OPS}
               big_concurrency_test.cc
               ${GETTIMEOFDAY_VS}
               $<TARGET_OBJECTS:FDB_TOOLS_CORE>
               $<TARGET_OBJECTS:FDB_TOOLS_UTILS>)
target_link_libraries(big_concurrency_test ${PTHREAD_LIB} ${LIBM}
                      ${SNAPPY_LIBRARIES} ${ASYNC_IO_LIB}
                      ${MALLOC_LIBRARIES} ${PLATFORM_LIBRARY}
                      ${LIBRT} ${CRYPTO_LIB}
                      ${DL_LIBRARIES} ${BREAKPAD_LIBRARIES})
set_target_properties(big_concurrency_test PROPERTIES COMPILE_FLAGS
                      "-D_FDB_TOOLS")

add_executable(big_compaction_test
               ${PROJECT_SOURCE_DIR}/${FORESTDB_FILE_OPS}
               big_compaction_test.cc
               ${GETTIMEOFDAY_VS}
               $<TARGET_OBJECTS:FDB_TOOLS_CORE>
               $<TARGET_OBJECTS:FDB_TOOLS_UTILS>)
target_link_libraries(big_compaction_test ${PTHREAD_LIB} ${LIBM}
                      ${SNAPPY_LIBRARIES} ${ASYNC_IO_LIB}
                      ${MALLOC_LIBRARIES} ${PLATFORM_LIBRARY}
                      ${LIBRT} ${CRYPTO_LIB}
                      ${DL_LIBRARIES} ${BREAKPAD_LIBRARIES})
set_target_properties(big_compaction_test PROPERTIES COMPILE_FLAGS
                      "-D_FDB_TOOLS")

add_executable(staleblock_test
               ${PROJECT_SOURCE_DIR}/${FORESTDB_FILE_OPS}
               staleblock_test.cc
               functional_util.cc
               ${GETTIMEOFDAY_VS}
               $<TARGET_OBJECTS:FDB_TOOLS_CORE>
               $<TARGET_OBJECTS:FDB_TOOLS_UTILS>)
target_link_libraries(staleblock_test ${PTHREAD_LIB} ${LIBM}
                      ${SNAPPY_LIBRARIES} ${ASYNC_IO_LIB}
                      ${MALLOC_LIBRARIES} ${PLATFORM_LIBRARY}
                      ${LIBRT} ${CRYPTO_LIB}
                      ${DL_LIBRARIES} ${BREAKPAD_LIBRARIES})
set_target_properties(staleblock_test PROPERTIES COMPILE_FLAGS "-D_FDB_TOOLS")

# add test target
add_test(fdb_functional_test fdb_functional_test)
add_test(fdb_extended_test fdb_extended_test)
add_test(compact_functional_test compact_functional_test)
add_test(iterator_functional_test iterator_functional_test)
add_test(mvcc_functional_test mvcc_functional_test)
add_test(multi_kv_functional_test multi_kv_functional_test)
add_test(staleblock_test staleblock_test)


ADD_CUSTOM_TARGET(functional_tests
    COMMAND ctest
)
