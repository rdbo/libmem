cmake_minimum_required(VERSION 3.10)
project(TestDLL)


set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
add_library(TestDLL SHARED TestDLL.cpp TestDLL.h)
target_compile_definitions(TestDLL PRIVATE TESTDLL_EXPORTS)

