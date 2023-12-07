cmake_minimum_required(VERSION 3.22.1)

include(ExternalProject)

project(libmem
	LANGUAGES
	C
	CXX
	ASM
)

message(STATUS
	"[*] Platform: ${CMAKE_SYSTEM_NAME}"
)

option(LIBMEM_BUILD_TESTS
	"Build tests"
	OFF
)

option(LIBMEM_BUILD_STATIC
	"Build a static library"
	OFF
)

option(LIBMEM_BUILD_32
	"Build for 32 bits"
	OFF
)

message(STATUS
	"[*] Build tests: ${LIBMEM_BUILD_TESTS}"
)

message(STATUS
	"[*] Build static library: ${LIBMEM_BUILD_STATIC}"
)

message(STATUS
	"[*] Build for 32 bits: ${LIBMEM_BUILD_32}"
)

if(LIBMEM_BUILD_32 AND NOT ${CMAKE_SYSTEM_NAME} STREQUAL Windows)
    # To compile 32 bits for Windows, use the x86 Visual Studio developer console instead of the x64 Native Tools console
    set(CMAKE_C_FLAGS ${CMAKE_C_FLAGS} -m32)
    set(CMAKE_CXX_FLAGS ${CMAKE_CXX_FLAGS} -m32)
    add_compile_options(-m32)
    add_link_options(-m32)
endif()

message(STATUS "CMAKE_C_FLAGS: ${CMAKE_C_FLAGS}")
message(STATUS "CMAKE_CXX_FLAGS: ${CMAKE_CXX_FLAGS}")

# External dependencies
set(EXTERNAL_DEPENDENCIES_DIR "${PROJECT_SOURCE_DIR}/external")
set(CAPSTONE_DIR "${EXTERNAL_DEPENDENCIES_DIR}/capstone")
set(CAPSTONE_INC "${CAPSTONE_DIR}/include")
set(CAPSTONE_IMPORT_DIR "${PROJECT_BINARY_DIR}/external/capstone-engine-prefix/src/capstone-engine-build")
set(KEYSTONE_DIR "${EXTERNAL_DEPENDENCIES_DIR}/keystone")
set(KEYSTONE_INC "${KEYSTONE_DIR}/include")
set(KEYSTONE_IMPORT_DIR "${PROJECT_BINARY_DIR}/external/keystone-engine-prefix/src/keystone-engine-build/llvm/lib")
set(LIEF_DIR "${EXTERNAL_DEPENDENCIES_DIR}/LIEF")
set(LIEF_IMPORT_DIR "${PROJECT_BINARY_DIR}/external/lief-project-prefix/src/lief-project-build")
set(LIEF_INC "${LIEF_DIR}/include" "${LIEF_IMPORT_DIR}/include")
set(LLVM_DIR "${EXTERNAL_DEPENDENCIES_DIR}/llvm")
set(LLVM_INC "${LLVM_DIR}/include")
set(INJECTOR_DIR "${EXTERNAL_DEPENDENCIES_DIR}/injector")
set(INJECTOR_INC "${INJECTOR_DIR}/include")

add_subdirectory("${EXTERNAL_DEPENDENCIES_DIR}")
add_library(capstone STATIC IMPORTED)
set_target_properties(capstone PROPERTIES IMPORTED_LOCATION ${CAPSTONE_IMPORT_DIR}/${CMAKE_STATIC_LIBRARY_PREFIX}capstone${CMAKE_STATIC_LIBRARY_SUFFIX})
add_library(keystone STATIC IMPORTED)
set_target_properties(keystone PROPERTIES IMPORTED_LOCATION ${KEYSTONE_IMPORT_DIR}/${CMAKE_STATIC_LIBRARY_PREFIX}keystone${CMAKE_STATIC_LIBRARY_SUFFIX})
add_library(LIEF STATIC IMPORTED)
set_target_properties(LIEF PROPERTIES IMPORTED_LOCATION ${LIEF_IMPORT_DIR}/${CMAKE_STATIC_LIBRARY_PREFIX}LIEF${CMAKE_STATIC_LIBRARY_SUFFIX})
# End of external dependencies

set(LIBMEM_DIR "${PROJECT_SOURCE_DIR}")
set(LIBMEM_INC "${LIBMEM_DIR}/include")
file(GLOB LIBMEM_SRC "${LIBMEM_DIR}/src/*.c" "${LIBMEM_DIR}/src/*.cpp")
if(${CMAKE_SYSTEM_NAME} STREQUAL Windows OR ${CMAKE_SYSTEM_NAME} STREQUAL CYGWIN)
	file(GLOB_RECURSE LIBMEM_INTERNAL_SRC "${LIBMEM_DIR}/src/internal/win/*.c")
else()
	file(GLOB_RECURSE LIBMEM_INTERNAL_SRC "${LIBMEM_DIR}/src/internal/unix/*.c")
endif()
set(LIBMEM_SRC
	${LIBMEM_SRC}
	${LIBMEM_INTERNAL_SRC}
)
set(LIBMEM_DEPS
	capstone
	keystone
	LIEF
	llvm
)

if("${CMAKE_BUILD_TYPE}" STREQUAL "Debug")
	if(NOT MSVC)
		add_compile_options(-Wall
			-Wextra
			-Wpedantic
			-g
			-ggdb
			-O0
                        -fprofile-arcs
			-ftest-coverage
		)
	endif()
endif()

if (LIBMEM_BUILD_STATIC)
	add_library(libmem STATIC ${LIBMEM_SRC})
	if(NOT ${CMAKE_SYSTEM_NAME} STREQUAL Windows AND NOT ${CMAKE_SYSTEM_NAME} STREQUAL CYGWIN)
		add_custom_command(
			TARGET libmem POST_BUILD
			WORKING_DIRECTORY ${PROJECT_BINARY_DIR}
			COMMAND sh ${PROJECT_SOURCE_DIR}/tools/makebundle.sh
		)
	endif()
else()
	add_library(libmem SHARED ${LIBMEM_SRC})
endif()
target_include_directories(libmem PRIVATE "${LIBMEM_DIR}/src")

include_directories(${PROJECT_SOURCE_DIR}
	${LIBMEM_INC}
	${CAPSTONE_INC}
	${KEYSTONE_INC}
	${LIEF_INC}
	${LLVM_INC}
	${INJECTOR_INC}
)

if (LIBMEM_BUILD_TESTS)
	set(TESTS_DIR "${PROJECT_SOURCE_DIR}/tests")
	add_subdirectory(${TESTS_DIR})
endif()

set_target_properties(libmem PROPERTIES POSITION_INDEPENDENT_CODE True INCLUDES ${LIBMEM_INC})
target_compile_definitions(libmem PUBLIC LM_EXPORT)
add_dependencies(libmem
	capstone-engine
	keystone-engine
	lief-project
)

if(${CMAKE_SYSTEM_NAME} STREQUAL Windows OR ${CMAKE_SYSTEM_NAME} STREQUAL CYGWIN)
	set(LIBMEM_DEPS
		${LIBMEM_DEPS}
		user32
		psapi
		ntdll
	)
elseif(${CMAKE_SYSTEM_NAME} STREQUAL Linux OR ${CMAKE_SYSTEM_NAME} STREQUAL Android)
	set(LIBMEM_DEPS 
		${LIBMEM_DEPS}
		dl
		stdc++
		m
	)
elseif(${CMAKE_SYSTEM_NAME} STREQUAL FreeBSD)
	set(LIBMEM_DEPS
		${LIBMEM_DEPS}
		dl
		kvm
		procstat
		elf
		stdc++
		m
	)
else()
	message(FATAL_ERROR "[!] Unsupported platform")
endif()

if(NOT ${CMAKE_SYSTEM_NAME} STREQUAL "FreeBSD")
	set(LIBMEM_DEPS ${LIBMEM_DEPS} injector)
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
