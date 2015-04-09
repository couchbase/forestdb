add_executable(e2etest
               e2etest.cc
               e2espec.cc
               ${GETTIMEOFDAY_VS})
target_link_libraries(e2etest forestdb)


# add test target
# add_test(e2etest e2etest)
ADD_CUSTOM_TARGET(e2etests
    COMMAND ctest
)
