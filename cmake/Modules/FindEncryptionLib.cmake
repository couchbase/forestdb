# Locate the encryption library given by the build environment

IF ("${_ENCRYPTION}" STREQUAL "commoncrypto")
    IF (APPLE)
        ADD_DEFINITIONS(-D_CRYPTO_CC=1)
    ELSE (APPLE)
        MESSAGE(FATAL_ERROR "commoncrypto lib is only available in Apple systems")
    ENDIF (APPLE)

ELSEIF ("${_ENCRYPTION}" STREQUAL "openssl")
    INCLUDE(FindOpenSSL)

    IF (OPENSSL_FOUND)
        include_directories(AFTER ${OPENSSL_INCLUDE_DIR})
        MESSAGE(STATUS "Found openssl in ${OPENSSL_INCLUDE_DIR} : ${OPENSSL_LIBRARIES}")
    ELSE (OPENSSL_FOUND)
        MESSAGE(FATAL_ERROR "Can't find openssl library")
    ENDIF (OPENSSL_FOUND)

    MARK_AS_ADVANCED(OPENSSL_INCLUDE_DIR OPENSSL_LIBRARIES)
    ADD_DEFINITIONS(-D_CRYPTO_OPENSSL=1)
    set(CRYPTO_LIB ${OPENSSL_CRYPTO_LIBRARY})

ELSEIF ("${_ENCRYPTION}" STREQUAL "libtomcrypt")
    FIND_PATH(LIBTOMCRYPT_INCLUDE_DIR tomcrypt.h
          PATH_SUFFIXES include
          PATHS
               ~/Library/Frameworks
               /Library/Frameworks
               /usr/local
               /usr
               /opt/local
               /opt/csw
               /opt)

    FIND_LIBRARY(LIBTOMCRYPT_LIBRARIES
                 NAMES tomcrypt
                 PATHS
                     ~/Library/Frameworks
                     /Library/Frameworks
                     /usr/local
                     /usr
                     /opt/local
                     /opt/csw
                     /opt)

    IF (LIBTOMCRYPT_LIBRARIES)
        include_directories(AFTER ${LIBTOMCRYPT_INCLUDE_DIR})
        MESSAGE(STATUS "Found libtomcrypt in ${LIBTOMCRYPT_INCLUDE_DIR} : ${LIBTOMCRYPT_LIBRARIES}")
    ELSE (LIBTOMCRYPT_LIBRARIES)
        MESSAGE(FATAL_ERROR "Can't find libtomcrypt library")
    ENDIF (LIBTOMCRYPT_LIBRARIES)

    MARK_AS_ADVANCED(LIBTOMCRYPT_INCLUDE_DIR LIBTOMCRYPT_LIBRARIES)
    ADD_DEFINITIONS(-D_CRYPTO_LIBTOMCRYPT=1)
    set(CRYPTO_LIB ${LIBTOMCRYPT_LIBRARIES})

ELSE()
    MESSAGE(FATAL_ERROR "Can't find the cryto library ${_ENCRYPTION}")
ENDIF()
