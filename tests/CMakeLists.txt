SET(STAT_AGGREGATOR
    ${PROJECT_SOURCE_DIR}/tests/stats-agg/stat_aggregator.cc)
add_library(TEST_STAT_AGG OBJECT ${STAT_AGGREGATOR})

set(ROOT_SRC ${PROJECT_SOURCE_DIR}/src)
set(ROOT_UTILS ${PROJECT_SOURCE_DIR}/utils)
set(UNIT_TEST_DIR ${CMAKE_CURRENT_SOURCE_DIR}/unit)
set(FUNCTIONAL_TEST_DIR ${CMAKE_CURRENT_SOURCE_DIR}/functional)
set(ANOMALY_TEST_DIR ${CMAKE_CURRENT_SOURCE_DIR}/anomaly)
set(E2E_TEST_DIR ${CMAKE_CURRENT_SOURCE_DIR}/e2e)
set(MICRO_BENCH_DIR ${CMAKE_CURRENT_SOURCE_DIR}/fdbench-micro)
set(USECASE_TEST_DIR ${CMAKE_CURRENT_SOURCE_DIR}/usecase)

include_directories(BEFORE ${CMAKE_CURRENT_SOURCE_DIR}/include)
include_directories(BEFORE ${PROJECT_SOURCE_DIR}/tests/stats-agg)

# import each test suite
add_subdirectory("${UNIT_TEST_DIR}")
add_subdirectory("${FUNCTIONAL_TEST_DIR}")
add_subdirectory("${ANOMALY_TEST_DIR}")
add_subdirectory("${E2E_TEST_DIR}")
add_subdirectory("${MICRO_BENCH_DIR}")
add_subdirectory("${USECASE_TEST_DIR}")
