set(CMAKE_SYSTEM_NAME Windows)
set(WIN32 1)
set(MINGW 1)

# Determine MinGW prefix based on architecture and runtime
# MINGW_RUNTIME can be "msvcrt" or "ucrt"
if(NOT DEFINED MINGW_RUNTIME)
  set(MINGW_RUNTIME "msvcrt" CACHE STRING "MinGW runtime: msvcrt or ucrt")
endif()

# Determine MinGW prefix based on architecture and runtime
# Note: UCRT only supports 64-bit (x86_64), not 32-bit (i686)
if(CMAKE_SYSTEM_PROCESSOR STREQUAL "i686")
  if(MINGW_RUNTIME STREQUAL "ucrt")
    message(FATAL_ERROR "UCRT only supports 64-bit architectures. Cannot use UCRT with i686/i386/x86. Use msvcrt instead.")
  else()
    set(MINGW_PREFIX "i686-w64-mingw32" CACHE STRING "")
  endif()
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64|amd64")
  if(MINGW_RUNTIME STREQUAL "ucrt")
    set(MINGW_PREFIX "x86_64-w64-mingw32ucrt" CACHE STRING "")
  else()
    set(MINGW_PREFIX "x86_64-w64-mingw32" CACHE STRING "")
  endif()
else()
  # Try to find which compiler is available
  if(MINGW_RUNTIME STREQUAL "ucrt")
    # UCRT only supports 64-bit, so only search for x86_64
    find_program(_MINGW_X86_64_GCC NAMES x86_64-w64-ucrt64-gcc)
    if(_MINGW_X86_64_GCC)
      set(MINGW_PREFIX "x86_64-w64-ucrt64" CACHE STRING "")
    else()
      message(FATAL_ERROR "Unable to find x86_64 UCRT compiler. CMAKE_SYSTEM_PROCESSOR=${CMAKE_SYSTEM_PROCESSOR}, MINGW_RUNTIME=${MINGW_RUNTIME}")
    endif()
  else()
    find_program(_MINGW_I686_GCC NAMES i686-w64-mingw32-gcc)
    find_program(_MINGW_X86_64_GCC NAMES x86_64-w64-mingw32-gcc)
    
    if(_MINGW_X86_64_GCC)
      set(MINGW_PREFIX "x86_64-w64-mingw32" CACHE STRING "")
    elseif(_MINGW_I686_GCC)
      set(MINGW_PREFIX "i686-w64-mingw32" CACHE STRING "")
    else()
      message(FATAL_ERROR "Unable to determine MinGW prefix. CMAKE_SYSTEM_PROCESSOR=${CMAKE_SYSTEM_PROCESSOR}, MINGW_RUNTIME=${MINGW_RUNTIME}")
    endif()
  endif()
endif()

find_program(CMAKE_C_COMPILER NAMES ${MINGW_PREFIX}-gcc REQUIRED)
find_program(CMAKE_CXX_COMPILER NAMES ${MINGW_PREFIX}-g++ REQUIRED)
find_program(CMAKE_AR NAMES ${MINGW_PREFIX}-ar)
find_program(CMAKE_RANLIB NAMES ${MINGW_PREFIX}-ranlib)
find_program(CMAKE_STRIP NAMES ${MINGW_PREFIX}-strip)

# Set find root paths
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)

