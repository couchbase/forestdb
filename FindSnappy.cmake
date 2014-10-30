# Locate snappy library
# This module defines
#  SNAPPY_FOUND, if false, do not try to link with snappy
#  LIBSNAPPY, Library path and libs
#  SNAPPY_INCLUDE_DIR, where to find the ICU headers

FIND_PATH(SNAPPY_INCLUDE_DIR snappy.h
          HINTS
               ENV SNAPPY_DIR
          PATH_SUFFIXES include
          PATHS
               ~/Library/Frameworks
               /Library/Frameworks
               /opt/local
               /opt/csw
               /opt/snappy
               /opt)

FIND_LIBRARY(LIBSNAPPY
             NAMES snappy
             HINTS
                 ENV SNAPPY_DIR
             PATHS
                 ~/Library/Frameworks
                 /Library/Frameworks
                 /opt/local
                 /opt/csw
                 /opt/snappy
                 /opt)

IF (LIBSNAPPY)
  MESSAGE(STATUS "Found snappy in ${SNAPPY_INCLUDE_DIR} : ${LIBSNAPPY}")
ELSE (LIBSNAPPY)
  MESSAGE(FATAL_ERROR "Can't build forestdb without Snappy")
ENDIF (LIBSNAPPY)

MARK_AS_ADVANCED(SNAPPY_INCLUDE_DIR LIBSNAPPY)
