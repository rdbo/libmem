cmake_minimum_required(VERSION 3.0)

project(libmem C)

add_library(libmem STATIC libmem/libmem.c libmem/libmem.h)
target_include_directories(libmem PUBLIC ${PROJECT_SOURCE_DIR}/libmem)
