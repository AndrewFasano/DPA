list(APPEND CMAKE_PREFIX_PATH "/dynamorio/build/cmake")

project(mytracer)

cmake_minimum_required(VERSION 2.8)
find_package(DynamoRIO)

set(DRTRACE_C_FLAGS "-g3 -O3 -Wall -Wextra -Wno-unused-parameter -DPAGE_SIZE=2048")
set(DRTRACE_CXX_FLAGS "${DRTRACE_C_FLAGS} -std=c++0x")

set(CMAKE_C_FLAGS "${DRTRACE_C_FLAGS}")
set(CMAKE_CXX_FLAGS "${DRTRACE_CXX_FLAGS}")

add_library(mytracer SHARED mytracer.c)
#target_link_libraries(mytracer)

configure_DynamoRIO_client(mytracer)
use_DynamoRIO_extension(mytracer drcontainers)
use_DynamoRIO_extension(mytracer drsyms)
target_link_libraries(mytracer -Wl,-no-undefined)
