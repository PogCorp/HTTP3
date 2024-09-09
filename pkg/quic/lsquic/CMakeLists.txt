CMAKE_MINIMUM_REQUIRED(VERSION 3.5)
PROJECT(http-lsquic-adapter C)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(CC gcc-9)
set(CXX g++-9)

IF(CMAKE_BUILD_TYPE STREQUAL "")
    SET(CMAKE_BUILD_TYPE Debug)
ENDIF()
MESSAGE(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
IF (CMAKE_BUILD_TYPE STREQUAL Debug)
    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -O0")
    SET(BUILD_LSQUIC true)
ENDIF()
SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} $ENV{EXTRA_CFLAGS}")

IF(BUILD_LSQUIC)
    MESSAGE(STATUS "Building lsquic:")
    INCLUDE_DIRECTORIES(boringssl/include)
    INCLUDE_DIRECTORIES(lsquic/include)
    INCLUDE_DIRECTORIES(lsquic/src/liblsquic)
    INCLUDE_DIRECTORIES(include)
    ADD_LIBRARY(lsquic_adapter SHARED ./src/logger.c ./src/cert.c ./src/server.c ./src/keylog.c ./src/ancillary.c)
    TARGET_LINK_LIBRARIES(lsquic_adapter PRIVATE
        ${CMAKE_SOURCE_DIR}/lsquic/src/liblsquic/liblsquic.so
        ${CMAKE_SOURCE_DIR}/boringssl/crypto/libcrypto.so
        ${CMAKE_SOURCE_DIR}/boringssl/ssl/libssl.so z ev m)
    add_executable(echo_test.out cmd/echo_test.c)
    target_link_libraries(echo_test.out lsquic_adapter)
ENDIF()

MESSAGE(STATUS "Compiler flags: ${CMAKE_C_FLAGS}")
