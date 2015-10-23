# Locate async I/O libraries on a host OS.

IF (UNIX)
    FIND_PATH(ASYNC_IO_INCLUDE_DIR libaio.h
              PATH_SUFFIXES include
              PATHS
                  ~/Library/Frameworks
                  /Library/Frameworks
                  /usr/local
                  /opt/local
                  /opt/csw
                  /opt)

    FIND_LIBRARY(ASYNC_IO_LIBRARIES
                 NAMES aio
                 PATHS
                     ~/Library/Frameworks
                     /Library/Frameworks
                     /usr/local
                     /opt/local
                     /opt/csw
                     /opt)
ELSEIF (WIN32)
ENDIF()

IF (ASYNC_IO_LIBRARIES AND ASYNC_IO_INCLUDE_DIR)
    MESSAGE(STATUS "Found async I/O libraries in ${ASYNC_IO_INCLUDE_DIR} :
            ${ASYNC_IO_LIBRARIES}")
    ADD_DEFINITIONS(-D_ASYNC_IO=1)
    set(ASYNC_IO_LIB ${ASYNC_IO_LIBRARIES})
    include_directories(AFTER ${ASYNC_IO_INCLUDE_DIR})
    MARK_AS_ADVANCED(ASYNC_IO_INCLUDE_DIR ASYNC_IO_LIBRARIES)
ELSE (ASYNC_IO_LIBRARIES AND ASYNC_IO_INCLUDE_DIR)
    MESSAGE(STATUS "Can't find async I/O libraries")
ENDIF (ASYNC_IO_LIBRARIES AND ASYNC_IO_INCLUDE_DIR)
