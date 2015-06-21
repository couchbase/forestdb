# Locate jemalloc libraries on a host OS.

IF (UNIX)
    FIND_PATH(JEMALLOC_INCLUDE_DIR jemalloc/jemalloc.h
              PATH_SUFFIXES include
              PATHS
                  ~/Library/Frameworks
                  /Library/Frameworks
                  /usr/local
                  /opt/local
                  /opt/csw
                  /opt)

    FIND_LIBRARY(JEMALLOC_LIBRARIES
                 NAMES jemalloc
                 PATHS
                     ~/Library/Frameworks
                     /Library/Frameworks
                     /usr/local
                     /opt/local
                     /opt/csw
                     /opt)
ELSEIF (WIN32)
ENDIF()

IF (JEMALLOC_LIBRARIES)
    MESSAGE(STATUS "Found jemalloc libraries in ${JEMALLOC_INCLUDE_DIR} :
            ${JEMALLOC_LIBRARIES}")
    ADD_DEFINITIONS(-D_JEMALLOC=1)
    set(MALLOC_LIBRARIES ${JEMALLOC_LIBRARIES})
    include_directories(AFTER ${JEMALLOC_INCLUDE_DIR})
    MARK_AS_ADVANCED(MALLOC_INCLUDE_DIR JEMALLOC_LIBRARIES)
ELSE (JEMALLOC_LIBRARIES)
    MESSAGE(FATAL_ERROR "Can't find jemalloc libraries")
ENDIF (JEMALLOC_LIBRARIES)
