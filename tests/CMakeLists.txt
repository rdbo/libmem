set(TEST1_SRC "${TESTS_DIR}/test1.c")
set(TEST2_SRC "${TESTS_DIR}/test2.c")
file(GLOB_RECURSE UNIT_SRC "${TESTS_DIR}/unit/*.c")
set(TARGET_SRC "${TESTS_DIR}/target.c")
set(LIBTEST_SRC "${TESTS_DIR}/libtest.c")
set(LIBTEST_PATH "${PROJECT_BINARY_DIR}/tests/libtest${CMAKE_SHARED_LIBRARY_SUFFIX}")
cmake_path(NATIVE_PATH LIBTEST_PATH LIBTEST_PATH)
string(REPLACE "\\" "\\\\" LIBTEST_PATH "${LIBTEST_PATH}")

add_executable(test1 ${TEST1_SRC})
target_include_directories(test1
    PUBLIC
    ${LIBMEM_INC}
)
target_link_libraries(test1 libmem)

add_library(libtest SHARED ${LIBTEST_SRC})
target_include_directories(libtest
    PUBLIC
    ${LIBMEM_INC}
)
set_target_properties(libtest PROPERTIES PREFIX "")
target_compile_definitions(test1 PUBLIC LIBTEST_PATH="${LIBTEST_PATH}")

add_executable(test2 ${TEST2_SRC})
target_include_directories(test2
    PUBLIC
    ${LIBMEM_INC}
)
target_link_libraries(test2 libmem)
target_compile_definitions(test2 PUBLIC LIBTEST_PATH="${LIBTEST_PATH}" TEST1_NAME="test1${CMAKE_EXECUTABLE_SUFFIX}")

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
