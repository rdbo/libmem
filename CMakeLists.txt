cmake_minimum_required(VERSION 3.24)

include(ExternalProject)

project(libmem C)

message(STATUS "[*] Platform: ${CMAKE_SYSTEM_NAME}")

option(LIBMEM_BUILD_TESTS "Build tests" OFF) # builds the optional libmem test libraries.
option(LIBMEM_BUILD_STATIC "Build a static library" ON) # builds libmem as a static library.

set(CAPSTONE_DIR "${PROJECT_SOURCE_DIR}/capstone")
set(CAPSTONE_INC "${CAPSTONE_DIR}/include")
set(CAPSTONE_IMPORT_DIR "${PROJECT_BINARY_DIR}/capstone-engine-prefix/src/capstone-engine-build")
ExternalProject_Add(capstone-engine SOURCE_DIR ${CAPSTONE_DIR} INSTALL_COMMAND echo CMAKE_ARGS -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE} -DCAPSTONE_ARCHITECTURE_DEFAULT=ON -DCAPSTONE_BUILD_TESTS=OFF -DCAPSTONE_BUILD_CSTOOL=OFF -DCAPSTONE_INSTALL=OFF -DCMAKE_POSITION_INDEPENDENT_CODE=ON)
add_library(capstone STATIC IMPORTED)
set_target_properties(capstone PROPERTIES IMPORTED_LOCATION ${CAPSTONE_IMPORT_DIR}/libcapstone.a)

set(KEYSTONE_DIR "${PROJECT_SOURCE_DIR}/keystone")
set(KEYSTONE_INC "${KEYSTONE_DIR}/include")
set(KEYSTONE_IMPORT_DIR "${PROJECT_BINARY_DIR}/keystone-engine-prefix/src/keystone-engine-build/llvm/lib")
ExternalProject_Add(keystone-engine SOURCE_DIR ${KEYSTONE_DIR} INSTALL_COMMAND echo CMAKE_ARGS -DBUILD_LIBS_ONLY=1 -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE} -DCMAKE_POSITION_INDEPENDENT_CODE=ON)
add_library(keystone STATIC IMPORTED)
set_target_properties(keystone PROPERTIES IMPORTED_LOCATION ${KEYSTONE_IMPORT_DIR}/libkeystone.a)

set(LIBMEM_DIR "${PROJECT_SOURCE_DIR}/libmem")
set(LIBMEM_INC "${LIBMEM_DIR}/include")
set(LIBMEM_SRC "${LIBMEM_DIR}/src/libmem.c")
set(LIBMEM_DEPS capstone keystone stdc++ m)

if(NOT MSVC)
	add_compile_options(-Wall -Wextra -Wpedantic)
	if ("${CMAKE_BUILD_TYPE}" STREQUAL "Debug")
		add_compile_options(-g -ggdb)
	endif()
endif()

if (LIBMEM_BUILD_STATIC)
	add_library(libmem STATIC ${LIBMEM_SRC})
else()
	add_library(libmem SHARED ${LIBMEM_SRC})
endif()

include_directories(${PROJECT_SOURCE_DIR} ${LIBMEM_INC} ${CAPSTONE_INC} ${KEYSTONE_INC})
set_target_properties(libmem PROPERTIES PREFIX "")
target_compile_definitions(libmem PUBLIC LM_EXPORT)
add_dependencies(libmem capstone-engine keystone-engine)

if (LIBMEM_BUILD_TESTS)
	set(TESTS_DIR "${PROJECT_SOURCE_DIR}/tests")
	set(TEST1_SRC "${TESTS_DIR}/test1.c")
	set(TEST2_SRC "${TESTS_DIR}/test2.c")

	add_executable(test1 ${TEST1_SRC})
	target_include_directories(test1 PUBLIC ${LIBMEM_INC})
	target_link_libraries(test1 libmem)

	add_library(libtest SHARED ${LIBMEM_SRC})
	target_include_directories(libtest PUBLIC ${LIBMEM_INC})
	set_target_properties(libtest PROPERTIES PREFIX "")

	add_executable(test2 ${TEST2_SRC})
	target_include_directories(test2 PUBLIC ${LIBMEM_INC})
	target_link_libraries(test2 libmem)
endif()

if(${CMAKE_SYSTEM_NAME} MATCHES Windows)
	set(LIBMEM_DEPS ${LIBMEM_DEPS} user32 psapi)
	target_link_libraries(libmem ${LIBMEM_DEPS})

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
	set(LIBMEM_DEPS ${LIBMEM_DEPS} dl kvm procstat elf)
	target_link_libraries(libmem ${LIBMEM_DEPS})

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
