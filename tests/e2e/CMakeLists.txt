add_executable(e2etest
               e2etest.cc
               e2espec.cc
               ${GETTIMEOFDAY_VS})
target_link_libraries(e2etest forestdb ${BACKTRACE_LIBRARIES})


# add test target
IF (_ENABLE_E2E_TEST EQUAL 1)
    add_test(e2etest e2etest)
    ADD_CUSTOM_TARGET(e2etests
        COMMAND ctest
    )
ENDIF()
