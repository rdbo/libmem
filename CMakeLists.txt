cmake_minimum_required(VERSION 3.0)

project(libmem C)

message("[*] Platform: ${CMAKE_SYSTEM_NAME}")

set(LIBMEM_DIR "${CMAKE_SOURCE_DIR}/libmem")
set(LIBMEM_SRC "${LIBMEM_DIR}/libmem.c")
set(TESTS_DIR "${CMAKE_SOURCE_DIR}/tests")
set(TESTS_SRC "${TESTS_DIR}/tests.c")

if(MSVC)
	add_compile_options(/W4 /WX)
else()
	add_compile_options(-Wall -Wextra -Wpedantic)
endif()

add_library(libmem SHARED ${LIBMEM_SRC})
set_target_properties(libmem PROPERTIES PREFIX "")
target_compile_definitions(libmem PUBLIC LM_EXPORT)

add_executable(tests ${TESTS_SRC})
target_include_directories(tests PUBLIC ${LIBMEM_DIR})
target_link_libraries(tests libmem)

if(${CMAKE_SYSTEM_NAME} MATCHES Windows)
	target_link_libraries(libmem user32 psapi)
	target_compile_definitions(tests PUBLIC TARGET_NAME="tests.exe")
elseif(${CMAKE_SYSTEM_NAME} MATCHES Linux)
	target_link_libraries(libmem dl)
	target_compile_definitions(tests PUBLIC TARGET_NAME="tests")
elseif(${CMAKE_SYSTEM_NAME} MATCHES FreeBSD)
	target_link_libraries(libmem dl kvm procstat elf)
	target_compile_definitions(tests PUBLIC TARGET_NAME="tests")
else()
	message("[!] Unsupported platform")
	target_compile_definitions(tests PUBLIC TARGET_NAME="tests")
endif()
