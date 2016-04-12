add_executable(fdb_microbench
               fdb_bench.cc
               ${PROJECT_SOURCE_DIR}/${FORESTDB_FILE_OPS}
               $<TARGET_OBJECTS:FDB_TOOLS_CORE>
               $<TARGET_OBJECTS:FDB_TOOLS_UTILS>
               $<TARGET_OBJECTS:TEST_STAT_AGG>
               ${GETTIMEOFDAY_VS})
target_link_libraries(fdb_microbench ${PTHREAD_LIB} ${LIBM}
                      ${SNAPPY_LIBRARIES} ${ASYNC_IO_LIB}
                      ${MALLOC_LIBRARIES} ${PLATFORM_LIBRARY}
                      ${LIBRT} ${CRYPTO_LIB}
                      ${DL_LIBRARIES} ${BREAKPAD_LIBRARIES})
set_target_properties(fdb_microbench PROPERTIES COMPILE_FLAGS "-D_FDB_TOOLS")


# add test target
add_test(fdb_microbench fdb_microbench)
ADD_CUSTOM_TARGET(fdbench-micro
    COMMAND ctest
)
