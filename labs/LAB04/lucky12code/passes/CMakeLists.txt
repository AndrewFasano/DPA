cmake_minimum_required(VERSION 3.0)
project(TestPasses)
set(LLVM_ROOT "/usr/lib/llvm-10/lib/cmake/llvm/" CACHE PATH "Root of LLVM install.")

find_package(LLVM REQUIRED CONFIG)

separate_arguments(LLVM_DEFINITIONS_LIST NATIVE_COMMAND ${LLVM_DEFINITIONS})
add_definitions(${LLVM_DEFINITIONS_LIST})
include_directories(${LLVM_INCLUDE_DIRS})

add_subdirectory(hello)
add_subdirectory(helloputs)
add_subdirectory(luckysan)
