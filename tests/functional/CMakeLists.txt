add_executable(fdb_functional_test
               fdb_functional_test.cc
               functional_util.cc
               ${ROOT_UTILS}/time_utils.cc
               ${GETTIMEOFDAY_VS})
target_link_libraries(fdb_functional_test forestdb)

add_executable(fdb_extended_test
               fdb_extended_test.cc
               functional_util.cc
               ${ROOT_UTILS}/time_utils.cc
               ${GETTIMEOFDAY_VS})
target_link_libraries(fdb_extended_test forestdb)

add_executable(compact_functional_test
               compact_functional_test.cc
               functional_util.cc
               ${ROOT_UTILS}/time_utils.cc
               ${GETTIMEOFDAY_VS})
target_link_libraries(compact_functional_test forestdb)

add_executable(iterator_functional_test
               iterator_functional_test.cc
               functional_util.cc
               ${ROOT_UTILS}/time_utils.cc
               ${GETTIMEOFDAY_VS})
target_link_libraries(iterator_functional_test forestdb)

add_executable(mvcc_functional_test
               mvcc_functional_test.cc
               functional_util.cc
               ${ROOT_UTILS}/time_utils.cc
               ${GETTIMEOFDAY_VS})
target_link_libraries(mvcc_functional_test forestdb)

add_executable(multi_kv_functional_test
               multi_kv_functional_test.cc
               functional_util.cc
               ${ROOT_UTILS}/time_utils.cc
               ${GETTIMEOFDAY_VS})
target_link_libraries(multi_kv_functional_test forestdb)

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
