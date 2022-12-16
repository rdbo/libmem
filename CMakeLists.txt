cmake_minimum_required(VERSION 3.24)

include(ExternalProject)

project(libmem C)

set(CAPSTONE_DIR "${PROJECT_SOURCE_DIR}/capstone")
ExternalProject_Add(capstone-engine SOURCE_DIR ${CAPSTONE_DIR} INSTALL_COMMAND echo CMAKE_ARGS -DCMAKE_BUILD_TYPE=Release -DCAPSTONE_ARCHITECTURE_DEFAULT=ON -DCAPSTONE_BUILD_TESTS=OFF -DCAPSTONE_BUILD_CSTOOL=OFF -DCAPSTONE_INSTALL=OFF)

message(STATUS "[*] Platform: ${CMAKE_SYSTEM_NAME}")

set(LIBMEM_DIR "${PROJECT_SOURCE_DIR}/libmem")
set(LIBMEM_SRC "${LIBMEM_DIR}/libmem.c")
set(LIBMEM_DEPS "capstone")

set(TESTS_DIR "${PROJECT_SOURCE_DIR}/tests")
set(TEST1_SRC "${TESTS_DIR}/test1.c")
set(TEST2_SRC "${TESTS_DIR}/test2.c")

option(LIBMEM_BUILD_TESTS OFF) # builds the optional libmem test libraries.
option(LIBMEM_BUILD_STATIC ON) # builds libmem as a static library.

if(NOT MSVC)
	add_compile_options(-Wall -Wextra -Wpedantic)
endif()

if (LIBMEM_BUILD_STATIC)
	add_library(libmem STATIC ${LIBMEM_SRC})
else()
	add_library(libmem SHARED ${LIBMEM_SRC})
endif()

target_include_directories(libmem PUBLIC ${PROJECT_SOURCE_DIR})

set_target_properties(libmem PROPERTIES PREFIX "")
target_compile_definitions(libmem PUBLIC LM_EXPORT)

if (LIBMEM_BUILD_TESTS)
	add_executable(test1 ${TEST1_SRC})
	target_include_directories(test1 PUBLIC ${LIBMEM_DIR})
	target_link_libraries(test1 libmem)

	add_library(libtest SHARED ${LIBMEM_SRC})
	target_include_directories(libtest PUBLIC ${LIBMEM_DIR})
	set_target_properties(libtest PROPERTIES PREFIX "")

	add_executable(test2 ${TEST2_SRC})
	target_include_directories(test2 PUBLIC ${LIBMEM_DIR})
	target_link_libraries(test2 libmem)
endif()

if(${CMAKE_SYSTEM_NAME} MATCHES Windows)
	set(LIBMEM_DEPS ${LIBMEM_DEPS} user32 psapi)
	target_link_libraries(libmem ${})

	if (LIBMEM_BUILD_TESTS)
		target_compile_definitions(test1 PUBLIC LIBTEST_PATH="libtest.dll")
		target_compile_definitions(test2 PUBLIC LIBTEST_PATH="libtest.dll" TEST1_NAME="test1.exe")
	endif()
elseif(${CMAKE_SYSTEM_NAME} MATCHES Linux OR ${CMAKE_SYSTEM_NAME} MATCHES Android)
	set(LIBMEM_DEPS ${LIBMEM_DEPS} dl)
	target_link_libraries(libmem ${LIBMEM_DEPS})

	if (LIBMEM_BUILD_TESTS)
		target_compile_definitions(test1 PUBLIC LIBTEST_PATH="libtest.so")
		target_compile_definitions(test2 PUBLIC LIBTEST_PATH="libtest.so" TEST1_NAME="test1")
	endif()
elseif(${CMAKE_SYSTEM_NAME} MATCHES FreeBSD)
	target_link_libraries(libmem dl kvm procstat elf)

	if (LIBMEM_BUILD_TESTS)
		target_compile_definitions(test1 PUBLIC LIBTEST_PATH="libtest.so")
		target_compile_definitions(test2 PUBLIC LIBTEST_PATH="libtest.so" TEST1_NAME="test1")
	endif()
else()
	message(FATAL_ERROR "[!] Unsupported platform")
	if (LIBMEM_BUILD_TESTS)
		target_compile_definitions(test1 PUBLIC LIBTEST_PATH="libtest.so")
		target_compile_definitions(test2 PUBLIC LIBTEST_PATH="libtest.so" TEST1_NAME="test1")
	endif()
endif()
