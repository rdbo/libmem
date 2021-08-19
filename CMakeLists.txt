cmake_minimum_required(VERSION 3.0)

project(libmem C)

message("[*] Platform: ${CMAKE_SYSTEM_NAME}")

set(LIBMEM_DIR "${CMAKE_SOURCE_DIR}/libmem")
set(LIBMEM_SRC "${LIBMEM_DIR}/libmem.c")
set(TESTS_DIR "${CMAKE_SOURCE_DIR}/tests")
set(TEST1_SRC "${TESTS_DIR}/test1.c")
set(TEST2_SRC "${TESTS_DIR}/test2.c")

if(NOT MSVC)
	add_compile_options(-Wall -Wextra -Wpedantic)
endif()

add_library(libmem SHARED ${LIBMEM_SRC})
set_target_properties(libmem PROPERTIES PREFIX "")
target_compile_definitions(libmem PUBLIC LM_EXPORT)

add_executable(test1 ${TEST1_SRC})
target_include_directories(test1 PUBLIC ${LIBMEM_DIR})
target_link_libraries(test1 libmem)

add_library(libtest SHARED ${LIBMEM_SRC})
target_include_directories(libtest PUBLIC ${LIBMEM_DIR})
set_target_properties(libtest PROPERTIES PREFIX "")

add_executable(test2 ${TEST2_SRC})
target_include_directories(test2 PUBLIC ${LIBMEM_DIR})
target_link_libraries(test2 libmem)

if(${CMAKE_SYSTEM_NAME} MATCHES Windows)
	target_link_libraries(libmem user32 psapi)
	target_compile_definitions(test1 PUBLIC LIBTEST_PATH="libtest.dll")
	target_compile_definitions(test2 PUBLIC LIBTEST_PATH="libtest.dll" TEST1_NAME="test1.exe")
elseif(${CMAKE_SYSTEM_NAME} MATCHES Linux OR ${CMAKE_SYSTEM_NAME} MATCHES Android)
	target_link_libraries(libmem dl)
	target_compile_definitions(test1 PUBLIC LIBTEST_PATH="libtest.so")
	target_compile_definitions(test2 PUBLIC LIBTEST_PATH="libtest.dll" TEST1_NAME="test1")
elseif(${CMAKE_SYSTEM_NAME} MATCHES FreeBSD)
	target_link_libraries(libmem dl kvm procstat elf)
	target_compile_definitions(test1 PUBLIC LIBTEST_PATH="libtest.so")
	target_compile_definitions(test2 PUBLIC LIBTEST_PATH="libtest.dll" TEST1_NAME="test1")
else()
	message("[!] Unsupported platform")
	target_compile_definitions(test1 PUBLIC LIBTEST_PATH="libtest.so")
	target_compile_definitions(test2 PUBLIC LIBTEST_PATH="libtest.dll" TEST1_NAME="test1")
endif()
