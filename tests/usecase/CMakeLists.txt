add_executable(usecase_test
               usecase_test.cc
               ${PROJECT_SOURCE_DIR}/${FORESTDB_FILE_OPS}
               $<TARGET_OBJECTS:FDB_TOOLS_CORE>
               $<TARGET_OBJECTS:FDB_TOOLS_UTILS>
               $<TARGET_OBJECTS:TEST_STAT_AGG>
               ${GETTIMEOFDAY_VS})
target_link_libraries(usecase_test ${PTHREAD_LIB} ${LIBM}
                      ${SNAPPY_LIBRARIES} ${ASYNC_IO_LIB}
                      ${MALLOC_LIBRARIES} ${PLATFORM_LIBRARY}
                      ${LIBRT} ${CRYPTO_LIB}
                      ${DL_LIBRARIES} ${BREAKPAD_LIBRARIES})
set_target_properties(usecase_test PROPERTIES COMPILE_FLAGS "-D_FDB_TOOLS")

add_executable(endurance_test
               endurance_test.cc
               ${PROJECT_SOURCE_DIR}/${FORESTDB_FILE_OPS}
               $<TARGET_OBJECTS:FDB_TOOLS_CORE>
               $<TARGET_OBJECTS:FDB_TOOLS_UTILS>
               $<TARGET_OBJECTS:TEST_STAT_AGG>
               ${GETTIMEOFDAY_VS})
target_link_libraries(endurance_test ${PTHREAD_LIB} ${LIBM}
                      ${SNAPPY_LIBRARIES} ${ASYNC_IO_LIB}
                      ${MALLOC_LIBRARIES} ${PLATFORM_LIBRARY}
                      ${LIBRT} ${CRYPTO_LIB}
                      ${DL_LIBRARIES} ${BREAKPAD_LIBRARIES})
set_target_properties(endurance_test PROPERTIES COMPILE_FLAGS "-D_FDB_TOOLS")

# add test target
add_test(usecase_test usecase_test)
add_test(endurance_test endurance_test)

ADD_CUSTOM_TARGET(usecase_tests
    COMMAND ctest
)
