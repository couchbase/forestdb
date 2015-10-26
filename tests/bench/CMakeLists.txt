add_executable(fdb_bench
               fdb_bench.cc
               ${PROJECT_SOURCE_DIR}/utils/timing.cc
               ${GETTIMEOFDAY_VS})

if ((NOT WIN32) AND (NOT APPLE))
  target_link_libraries(fdb_bench forestdb ${BACKTRACE_LIBRARIES} -lrt)
else ((NOT WIN32) AND (NOT APPLE))
  target_link_libraries(fdb_bench forestdb ${BACKTRACE_LIBRARIES})
endif ((NOT WIN32) AND (NOT APPLE))


# add test target
add_test(fdb_bench fdb_bench)
ADD_CUSTOM_TARGET(benchmark
    COMMAND ctest
  )
