cmake_minimum_required(VERSION 3.22.1)

include(ExternalProject)

project(libmem)

message(STATUS "[*] Platform: ${CMAKE_SYSTEM_NAME}")

option(LIBMEM_BUILD_TESTS "Build tests" ON)
option(LIBMEM_BUILD_STATIC "Build a static library" OFF)
option(LIBMEM_BUILD_32 "Build for 32 bits" OFF)

message(STATUS "[*] Build tests: ${LIBMEM_BUILD_TESTS}")
message(STATUS "[*] Build static library: ${LIBMEM_BUILD_STATIC}")
message(STATUS "[*] Build for 32 bits: ${LIBMEM_BUILD_32}")

if(LIBMEM_BUILD_32 AND NOT ${CMAKE_SYSTEM_NAME} STREQUAL Windows)
    # To compile 32 bits for Windows, use the x86 Visual Studio developer console instead of the x64 Native Tools console
    set(CMAKE_C_FLAGS ${CMAKE_C_FLAGS} -m32)
    set(CMAKE_CXX_FLAGS ${CMAKE_CXX_FLAGS} -m32)
    add_compile_options(-m32)
    add_link_options(-m32)
endif()

message(STATUS "CMAKE_C_FLAGS: ${CMAKE_C_FLAGS}")
message(STATUS "CMAKE_CXX_FLAGS: ${CMAKE_CXX_FLAGS}")

set(CAPSTONE_DIR "${PROJECT_SOURCE_DIR}/capstone")
set(CAPSTONE_INC "${CAPSTONE_DIR}/include")
set(CAPSTONE_IMPORT_DIR "${PROJECT_BINARY_DIR}/capstone-engine-prefix/src/capstone-engine-build")
set(CAPSTONE_CMAKE_ARGS -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE} -DCMAKE_C_FLAGS=${CMAKE_C_FLAGS} -DCMAKE_CXX_FLAGS=${CMAKE_CXX_FLAGS} -DCAPSTONE_ARCHITECTURE_DEFAULT=ON -DCAPSTONE_BUILD_TESTS=OFF -DCAPSTONE_BUILD_CSTOOL=OFF -DCAPSTONE_INSTALL=OFF -DCAPSTONE_BUILD_SHARED=OFF -DCMAKE_POSITION_INDEPENDENT_CODE=ON -DCAPSTONE_ARCHITECTURE_DEFAULT=OFF -DCAPSTONE_BUILD_STATIC_RUNTIME=OFF)
if(${CMAKE_SYSTEM_PROCESSOR} STREQUAL "aarch64")
	set(CAPSTONE_CMAKE_ARGS ${CAPSTONE_CMAKE_ARGS} -DCAPSTONE_ARM64_SUPPORT=ON)
elseif(${CMAKE_SYSTEM_PROCESSOR} STREQUAL "arm")
	set(CAPSTONE_CMAKE_ARGS ${CAPSTONE_CMAKE_ARGS} -DCAPSTONE_ARM_SUPPORT=ON)
else()
	set(CAPSTONE_CMAKE_ARGS ${CAPSTONE_CMAKE_ARGS} -DCAPSTONE_X86_SUPPORT=ON)
endif()
ExternalProject_Add(capstone-engine SOURCE_DIR ${CAPSTONE_DIR} INSTALL_COMMAND "" CMAKE_ARGS ${CAPSTONE_CMAKE_ARGS})
add_library(capstone STATIC IMPORTED)
set_target_properties(capstone PROPERTIES IMPORTED_LOCATION ${CAPSTONE_IMPORT_DIR}/${CMAKE_STATIC_LIBRARY_PREFIX}capstone${CMAKE_STATIC_LIBRARY_SUFFIX})

set(KEYSTONE_DIR "${PROJECT_SOURCE_DIR}/keystone")
set(KEYSTONE_INC "${KEYSTONE_DIR}/include")
set(KEYSTONE_IMPORT_DIR "${PROJECT_BINARY_DIR}/keystone-engine-prefix/src/keystone-engine-build/llvm/lib")
set(KEYSTONE_CMAKE_ARGS -DBUILD_LIBS_ONLY=1 -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE} -DCMAKE_C_FLAGS=${CMAKE_C_FLAGS} -DCMAKE_CXX_FLAGS=${CMAKE_CXX_FLAGS} -DCMAKE_POSITION_INDEPENDENT_CODE=ON -DKEYSTONE_BUILD_STATIC_RUNTIME=OFF)
if(${CMAKE_SYSTEM_PROCESSOR} STREQUAL "aarch64")
	set(KEYSTONE_CMAKE_ARGS ${KEYSTONE_CMAKE_ARGS} -DLLVM_TARGETS_TO_BUILD=AArch64)
elseif(${CMAKE_SYSTEM_PROCESSOR} STREQUAL "arm")
	set(KEYSTONE_CMAKE_ARGS ${KEYSTONE_CMAKE_ARGS} -DLLVM_TARGETS_TO_BUILD=ARM)
else()
	set(KEYSTONE_CMAKE_ARGS ${KEYSTONE_CMAKE_ARGS} -DLLVM_TARGETS_TO_BUILD=X86)
endif()
ExternalProject_Add(keystone-engine SOURCE_DIR ${KEYSTONE_DIR} INSTALL_COMMAND "" CMAKE_ARGS ${KEYSTONE_CMAKE_ARGS})
add_library(keystone STATIC IMPORTED)
set_target_properties(keystone PROPERTIES IMPORTED_LOCATION ${KEYSTONE_IMPORT_DIR}/${CMAKE_STATIC_LIBRARY_PREFIX}keystone${CMAKE_STATIC_LIBRARY_SUFFIX})

set(LIEF_DIR "${PROJECT_SOURCE_DIR}/LIEF")
set(LIEF_INC "${LIEF_DIR}/include" "${PROJECT_BINARY_DIR}/lief-project-prefix/src/lief-project-build/include")
set(LIEF_IMPORT_DIR "${PROJECT_BINARY_DIR}/lief-project-prefix/src/lief-project-build")
set(LIEF_CMAKE_ARGS -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE} -DCMAKE_C_FLAGS=${CMAKE_C_FLAGS} -DCMAKE_CXX_FLAGS=${CMAKE_CXX_FLAGS} -DLIEF_USE_CCACHE=OFF -DLIEF_ENABLE_JSON=OFF -DLIEF_FROZEN_ENABLED=OFF -DLIEF_MACHO=OFF -DLIEF_OAT=OFF -DLIEF_DEX=OFF -DLIEF_VDEX=OFF -DLIEF_ART=OFF -DLIEF_EXTERNAL_LEAF=OFF -DLIEF_EXTERNAL_SPAN_DIR=OFF -DLIEF_FUZZING=OFF -DLIEF_PROFILING=OFF -DLIEF_COVERAGE=OFF -DLIEF_EXAMPLES=OFF -DLIEF_TESTS=OFF -DLIEF_DOC=OFF)
if(${CMAKE_SYSTEM_NAME} STREQUAL Windows OR ${CMAKE_SYSTEM_NAME} STREQUAL CYGWIN)
        set(LIEF_CMAKE_ARGS ${LIEF_CMAKE_ARGS} -DLIEF_ELF=OFF)
else()
        set(LIEF_CMAKE_ARGS ${LIEF_CMAKE_ARGS} -DLIEF_PE=OFF)
endif()
ExternalProject_Add(lief-project SOURCE_DIR ${LIEF_DIR} INSTALL_COMMAND "" CMAKE_ARGS ${LIEF_CMAKE_ARGS})
add_library(LIEF STATIC IMPORTED)
set_target_properties(LIEF PROPERTIES IMPORTED_LOCATION ${LIEF_IMPORT_DIR}/${CMAKE_STATIC_LIBRARY_PREFIX}LIEF${CMAKE_STATIC_LIBRARY_SUFFIX})

set(LLVM_DIR "${PROJECT_SOURCE_DIR}/llvm")
set(LLVM_INC "${LLVM_DIR}/include")
file(GLOB_RECURSE LLVM_SRC "${LLVM_DIR}/lib/*.cpp")
add_library(llvm STATIC ${LLVM_SRC})
set_target_properties(llvm PROPERTIES POSITION_INDEPENDENT_CODE True)
target_compile_features(llvm PUBLIC cxx_std_17)

set(LIBMEM_DIR "${PROJECT_SOURCE_DIR}/libmem")
set(LIBMEM_INC "${LIBMEM_DIR}/include")
file(GLOB_RECURSE LIBMEM_SRC "${LIBMEM_DIR}/src/*.c" "${LIBMEM_DIR}/src/*.cpp")
set(LIBMEM_DEPS capstone keystone LIEF llvm)

if("${CMAKE_BUILD_TYPE}" STREQUAL "Debug")
	if(NOT MSVC)
		add_compile_options(-Wall -Wextra -Wpedantic -g -ggdb)
	endif()
endif()

if (LIBMEM_BUILD_STATIC)
	add_library(libmem STATIC ${LIBMEM_SRC})
	if(NOT ${CMAKE_SYSTEM_NAME} STREQUAL Windows AND NOT ${CMAKE_SYSTEM_NAME} STREQUAL CYGWIN)
		add_custom_command(
			TARGET libmem POST_BUILD
			WORKING_DIRECTORY ${PROJECT_BINARY_DIR}
			COMMAND sh ${PROJECT_SOURCE_DIR}/makebundle.sh
		)
	endif()
else()
	add_library(libmem SHARED ${LIBMEM_SRC})
endif()

include_directories(${PROJECT_SOURCE_DIR} ${LIBMEM_INC} ${CAPSTONE_INC} ${KEYSTONE_INC} ${LIEF_INC} ${LLVM_INC})
set_target_properties(libmem PROPERTIES POSITION_INDEPENDENT_CODE True INCLUDES ${LIBMEM_INC})
target_compile_definitions(libmem PUBLIC LM_EXPORT)
add_dependencies(libmem capstone-engine keystone-engine lief-project)

if (LIBMEM_BUILD_TESTS)
	set(TESTS_DIR "${PROJECT_SOURCE_DIR}/tests")
	set(TEST1_SRC "${TESTS_DIR}/test1.c")
	set(TEST2_SRC "${TESTS_DIR}/test2.c")
	file(GLOB_RECURSE UNIT_SRC "${TESTS_DIR}/unit/*.c")
	set(LIBTEST_SRC "${TESTS_DIR}/libtest.c")
	set(LIBTEST_PATH "${PROJECT_BINARY_DIR}/libtest${CMAKE_SHARED_LIBRARY_SUFFIX}")
	cmake_path(NATIVE_PATH LIBTEST_PATH LIBTEST_PATH)
	string(REPLACE "\\" "\\\\" LIBTEST_PATH "${LIBTEST_PATH}")

	add_executable(test1 ${TEST1_SRC})
	target_include_directories(test1 PUBLIC ${LIBMEM_INC})
	target_link_libraries(test1 libmem)

	add_library(libtest SHARED ${LIBTEST_SRC})
	target_include_directories(libtest PUBLIC ${LIBMEM_INC})
	set_target_properties(libtest PROPERTIES PREFIX "")
	target_compile_definitions(test1 PUBLIC LIBTEST_PATH="${LIBTEST_PATH}")

	add_executable(test2 ${TEST2_SRC})
	target_include_directories(test2 PUBLIC ${LIBMEM_INC})
	target_link_libraries(test2 libmem)
	target_compile_definitions(test2 PUBLIC LIBTEST_PATH="${LIBTEST_PATH}" TEST1_NAME="test1${CMAKE_EXECUTABLE_SUFFIX}")

	add_executable(unit ${UNIT_SRC})
	target_include_directories(unit PUBLIC ${LIBMEM_INC})
	target_link_libraries(unit libmem)
endif()

if(${CMAKE_SYSTEM_NAME} STREQUAL Windows OR ${CMAKE_SYSTEM_NAME} STREQUAL CYGWIN)
	set(LIBMEM_DEPS ${LIBMEM_DEPS} user32 psapi ntdll)
elseif(${CMAKE_SYSTEM_NAME} STREQUAL Linux OR ${CMAKE_SYSTEM_NAME} STREQUAL Android)
	set(LIBMEM_DEPS ${LIBMEM_DEPS} dl stdc++ m)
elseif(${CMAKE_SYSTEM_NAME} STREQUAL FreeBSD)
	set(LIBMEM_DEPS ${LIBMEM_DEPS} dl kvm procstat elf stdc++ m)
else()
	message(FATAL_ERROR "[!] Unsupported platform")
endif()

target_link_libraries(libmem ${LIBMEM_DEPS})

if(${CMAKE_SYSTEM_NAME} STREQUAL Windows OR ${CMAKE_SYSTEM_NAME} STREQUAL CYGWIN)
	if(NOT ${CMAKE_SYSTEM_NAME} STREQUAL CYGWIN)
		cmake_path(SET CMAKE_INSTALL_PREFIX "$ENV{ProgramFiles}")
	else(${})
		execute_process(COMMAND cygpath -u "$PROGRAMFILES"
				OUTPUT_VARIABLE CMAKE_INSTALL_PREFIX)
	endif()
	set(CMAKE_INSTALL_PREFIX "${CMAKE_INSTALL_PREFIX}/libmem")
	execute_process(COMMAND mkdir "${CMAKE_INSTALL_PREFIX}")
else()
	set(CMAKE_INSTALL_PREFIX "/usr")
endif()

install(TARGETS libmem
	LIBRARY DESTINATION lib)

install(TARGETS libmem
	RUNTIME DESTINATION lib)

install(DIRECTORY ${LIBMEM_INC}/libmem DESTINATION include)

