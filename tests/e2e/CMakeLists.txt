add_executable(e2etest
               e2etest.cc
               e2espec.cc
               ${PROJECT_SOURCE_DIR}/${FORESTDB_FILE_OPS}
               $<TARGET_OBJECTS:FDB_TOOLS_CORE>
               $<TARGET_OBJECTS:FDB_TOOLS_UTILS>
               ${GETTIMEOFDAY_VS})
target_link_libraries(e2etest ${PTHREAD_LIB} ${LIBM}
                      ${SNAPPY_LIBRARIES} ${ASYNC_IO_LIB}
                      ${MALLOC_LIBRARIES} ${PLATFORM_LIBRARY}
                      ${LIBRT} ${CRYPTO_LIB}
                      ${DL_LIBRARIES} ${BREAKPAD_LIBRARIES})
set_target_properties(e2etest PROPERTIES COMPILE_FLAGS "-D_FDB_TOOLS")

# add test target
add_test(e2etest e2etest)
ADD_CUSTOM_TARGET(e2etests
    COMMAND ctest
)
