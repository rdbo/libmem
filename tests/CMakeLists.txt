file(GLOB_RECURSE UNIT_SRC "${TESTS_DIR}/unit/*.c")
set(TARGET_SRC "${TESTS_DIR}/target.c")
set(LIBTEST_SRC "${TESTS_DIR}/libtest.c")
set(LIBTEST_PATH "${PROJECT_BINARY_DIR}/tests/libtest${CMAKE_SHARED_LIBRARY_SUFFIX}")
set(CPPTESTS_SRC "${TESTS_DIR}/cpptests.cpp")
cmake_path(NATIVE_PATH LIBTEST_PATH LIBTEST_PATH)
string(REPLACE "\\" "\\\\" LIBTEST_PATH "${LIBTEST_PATH}")

add_library(libtest SHARED ${LIBTEST_SRC})
target_include_directories(libtest
    PUBLIC
    ${LIBMEM_INC}
)
set_target_properties(libtest PROPERTIES PREFIX "")

add_executable(unit ${UNIT_SRC})
target_include_directories(unit
    PUBLIC
    ${LIBMEM_INC}
)
target_link_libraries(unit libmem)
target_compile_definitions(unit PUBLIC LIBTEST_PATH="${LIBTEST_PATH}" TARGET_NAME="target${CMAKE_EXECUTABLE_SUFFIX}")

add_executable(target ${TARGET_SRC})
target_include_directories(target
    PUBLIC
    ${LIBMEM_INC}
)
target_link_libraries(target libmem)

add_executable(cpptests ${CPPTESTS_SRC})
target_link_libraries(cpptests libmem)
