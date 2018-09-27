cmake_minimum_required(VERSION 3.1)

project(rsa_cpp)

find_package(OpenSSL REQUIRED)

set(CMAKE_CXX_STANDARD 11)

set(SOURCES ${PROJECT_SOURCE_DIR}/rsa.cpp ${PROJECT_SOURCE_DIR}/base64.h)

add_library(rsa STATIC ${SOURCES})

target_link_libraries(rsa OpenSSL::SSL)

add_executable(test test.cpp)

target_link_libraries(test rsa)

