add_executable(fdb_functional_test
               fdb_functional_test.cc
               ${PROJECT_SOURCE_DIR}/${GETTIMEOFDAY_VS})
target_link_libraries(fdb_functional_test forestdb)

add_executable(fdb_extended_test
               fdb_extended_test.cc
               ${PROJECT_SOURCE_DIR}/${GETTIMEOFDAY_VS})
target_link_libraries(fdb_extended_test forestdb)

# add test target
add_test(fdb_functional_test fdb_functional_test)
add_test(fdb_extended_test fdb_extended_test)
ADD_CUSTOM_TARGET(functional_tests
    COMMAND ctest
)
