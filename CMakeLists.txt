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

option(LIBMEM_DEEP_TESTS
	"Enable extra testing features for deep testing"
	OFF
)

option(LIBMEM_BUILD_STATIC
	"Build a static library"
	OFF
)

set(LIBMEM_ARCH ${CMAKE_SYSTEM_PROCESSOR} CACHE STRING "Force a specific architecture")

message(STATUS
	"[*] Architecture: ${LIBMEM_ARCH}"
)

message(STATUS
	"[*] Build tests: ${LIBMEM_BUILD_TESTS}"
)

message(STATUS
	"[*] Deep tests: ${LIBMEM_DEEP_TESTS}"
)

message(STATUS
	"[*] Build static library: ${LIBMEM_BUILD_STATIC}"
)

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
set(LLVM_DIR "${EXTERNAL_DEPENDENCIES_DIR}/llvm")
set(LLVM_INC "${LLVM_DIR}/include")

add_subdirectory("${EXTERNAL_DEPENDENCIES_DIR}")
add_library(capstone STATIC IMPORTED)
set_target_properties(capstone PROPERTIES IMPORTED_LOCATION ${CAPSTONE_IMPORT_DIR}/${CMAKE_STATIC_LIBRARY_PREFIX}capstone${CMAKE_STATIC_LIBRARY_SUFFIX})
add_library(keystone STATIC IMPORTED)
set_target_properties(keystone PROPERTIES IMPORTED_LOCATION ${KEYSTONE_IMPORT_DIR}/${CMAKE_STATIC_LIBRARY_PREFIX}keystone${CMAKE_STATIC_LIBRARY_SUFFIX})
# End of external dependencies

set(LIBMEM_DIR "${PROJECT_SOURCE_DIR}")
set(LIBMEM_INC "${LIBMEM_DIR}/include")
set(INTERNAL_DIR "${LIBMEM_DIR}/internal")
set(COMMON_DIR "${LIBMEM_DIR}/src/common")

if(${CMAKE_SYSTEM_NAME} STREQUAL Windows OR ${CMAKE_SYSTEM_NAME} STREQUAL CYGWIN)
	file(GLOB_RECURSE LIBMEM_SRC "${LIBMEM_DIR}/src/win/*.c" "${LIBMEM_DIR}/src/common/*.c" "${LIBMEM_DIR}/src/common/*.cpp" "${INTERNAL_DIR}/winutils/*.c" "${INTERNAL_DIR}/demangler/*.cpp")
elseif(${CMAKE_SYSTEM_NAME} STREQUAL Linux)
	if(${LIBMEM_ARCH} STREQUAL x86_64)
		set(LIBMEM_ARCH_SRC "${LIBMEM_DIR}/src/common/arch/x86.c" "${LIBMEM_DIR}/src/linux/ptrace/x64/*.c")
	elseif(${LIBMEM_ARCH} STREQUAL i686 OR ${LIBMEM_ARCH} STREQUAL i386)
		set(LIBMEM_ARCH_SRC "${LIBMEM_DIR}/src/common/arch/x86.c" "${LIBMEM_DIR}/src/linux/ptrace/x86/*.c")
	endif()
	file(GLOB LIBMEM_SRC ${LIBMEM_ARCH_SRC} "${LIBMEM_DIR}/src/linux/*.c" "${LIBMEM_DIR}/src/linux/ptrace/*.c" "${LIBMEM_DIR}/src/common/*.c" "${LIBMEM_DIR}/src/common/*.cpp" "${INTERNAL_DIR}/posixutils/*.c" "${INTERNAL_DIR}/elfutils/*.c" "${INTERNAL_DIR}/demangler/*.cpp")
elseif(${CMAKE_SYSTEM_NAME} STREQUAL FreeBSD)
	if(${LIBMEM_ARCH} STREQUAL x86_64 OR ${LIBMEM_ARCH} STREQUAL amd64)
		set(LIBMEM_ARCH_SRC "${LIBMEM_DIR}/src/common/arch/x86.c" "${LIBMEM_DIR}/src/freebsd/ptrace/x64/*.c")
	elseif(${LIBMEM_ARCH} STREQUAL i686 OR ${LIBMEM_ARCH} STREQUAL i386)
		set(LIBMEM_ARCH_SRC "${LIBMEM_DIR}/src/common/arch/x86.c" "${LIBMEM_DIR}/src/freebsd/ptrace/x86/*.c")
	endif()
	file(GLOB LIBMEM_SRC ${LIBMEM_ARCH_SRC} "${LIBMEM_DIR}/src/freebsd/*.c" "${LIBMEM_DIR}/src/freebsd/ptrace/*.c" "${LIBMEM_DIR}/src/common/*.c" "${LIBMEM_DIR}/src/common/*.cpp" "${INTERNAL_DIR}/posixutils/*.c" "${INTERNAL_DIR}/elfutils/*.c" "${INTERNAL_DIR}/demangler/*.cpp")
endif()
set(LIBMEM_DEPS
	capstone
	keystone
	llvm
)

if (LIBMEM_BUILD_STATIC)
	add_library(libmem STATIC ${LIBMEM_SRC})
	target_compile_definitions(libmem PUBLIC LM_STATIC)
else()
	add_library(libmem SHARED ${LIBMEM_SRC})
	target_compile_definitions(libmem PUBLIC LM_EXPORT)
endif()
target_include_directories(libmem PRIVATE "${LIBMEM_DIR}/src" "${INTERNAL_DIR}" "${COMMON_DIR}")

include_directories(${PROJECT_SOURCE_DIR}
	${LIBMEM_INC}
	${CAPSTONE_INC}
	${KEYSTONE_INC}
	${LLVM_INC}
)

if (LIBMEM_BUILD_TESTS)
	set(TESTS_DIR "${PROJECT_SOURCE_DIR}/tests")
	add_subdirectory(${TESTS_DIR})
endif()

set_target_properties(libmem PROPERTIES POSITION_INDEPENDENT_CODE True INCLUDES ${LIBMEM_INC})
add_dependencies(libmem
	capstone-engine
	keystone-engine
)

if(${CMAKE_SYSTEM_NAME} STREQUAL Windows OR ${CMAKE_SYSTEM_NAME} STREQUAL CYGWIN)
	set(LIBMEM_DEPS
		${LIBMEM_DEPS}
		user32
		psapi
		ntdll
  		shell32
	)
	target_compile_definitions(libmem PUBLIC alloca=_alloca)
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

target_link_libraries(libmem ${LIBMEM_DEPS})
if(LIBMEM_BUILD_STATIC)
	# Create a bundled static library containing all dependencies (to mimic the shared library behavior)
	set_target_properties(libmem PROPERTIES OUTPUT_NAME "libmem_partial")
	set(libmem_bundle_files "$<TARGET_FILE:libmem>")

	get_target_property(libmem_link_libraries libmem LINK_LIBRARIES)
	foreach(libmem_link_library IN LISTS libmem_link_libraries)
		if(TARGET "${libmem_link_library}")
			list(APPEND libmem_bundle_files "$<TARGET_FILE:${libmem_link_library}>")
		endif()
	endforeach()

	if(NOT ${CMAKE_SYSTEM_NAME} STREQUAL Windows AND NOT ${CMAKE_SYSTEM_NAME} STREQUAL CYGWIN)
		file(WRITE "${CMAKE_BINARY_DIR}/liblibmem.ar.in" "CREATE liblibmem.a\n" )
		foreach(libmem_bundle_file IN LISTS libmem_bundle_files)
			file(APPEND "${CMAKE_BINARY_DIR}/liblibmem.ar.in" "ADDLIB ${libmem_bundle_file}\n")
		endforeach()
		file(APPEND "${CMAKE_BINARY_DIR}/liblibmem.ar.in" "SAVE\nEND\n")
		file(GENERATE OUTPUT "${CMAKE_BINARY_DIR}/liblibmem.ar" INPUT "${CMAKE_BINARY_DIR}/liblibmem.ar.in")

		add_custom_command(
			TARGET libmem POST_BUILD
			WORKING_DIRECTORY "${CMAKE_BINARY_DIR}"
			COMMAND "${CMAKE_AR}" -M < "${CMAKE_BINARY_DIR}/liblibmem.ar"
			COMMENT "Bundling liblibmem.a"
			VERBATIM
		)
	elseif(MSVC)
		find_program(LIB_EXECUTABLE lib)
		add_custom_command(
			TARGET libmem POST_BUILD
			WORKING_DIRECTORY "${CMAKE_BINARY_DIR}"
			COMMAND "${LIB_EXECUTABLE}" /NOLOGO /OUT:libmem.lib ${libmem_bundle_files}
			COMMENT "Bundling libmem.lib"
			VERBATIM
		)
	else()
		message(WARNING "Static library bundling not supported on this platform")
	endif()
endif()

if(${CMAKE_SYSTEM_NAME} STREQUAL Windows OR ${CMAKE_SYSTEM_NAME} STREQUAL CYGWIN)
	if(NOT ${CMAKE_SYSTEM_NAME} STREQUAL CYGWIN)
		cmake_path(SET CMAKE_INSTALL_PREFIX "$ENV{ProgramFiles}")
	else()
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
