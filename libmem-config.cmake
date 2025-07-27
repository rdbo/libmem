# libmem config to download and use pre-built binaries
#
# Config source: https://github.com/rdbo/libmem
# Config author: Nathan Poirier <nathan@poirier.io>
# Config version: 2023-12-10.0
#
# Minimum required CMake version: 3.21
#
# Example usage:
#   project(my-project)
#   [...]
#   include(FetchContent)
#   fetchcontent_declare(libmem-config URL "https://raw.githubusercontent.com/rdbo/libmem/config-v1/libmem-config.cmake" DOWNLOAD_NO_EXTRACT TRUE)
#   fetchcontent_makeavailable(libmem-config)
#   set(CMAKE_PREFIX_PATH "${libmem-config_SOURCE_DIR}" "${CMAKE_PREFIX_PATH}")
#
#   set(LIBMEM_DOWNLOAD_VERSION "5.1.0")
#   find_package(libmem CONFIG REQUIRED)
#   [...]
#   target_link_libraries(my-target PRIVATE libmem::libmem)
#
# Input variables:
#   LIBMEM_ROOT (optional)
#     Path to the root folder of the pre-built version of libmem (containing include and lib folders).
#     If empty, the pre-built version of libmem will be downloaded automatically.
#
#   LIBMEM_DOWNLOAD_URL (optional)
#     URL for downloading the archive containing the pre-built version of libmem.
#     "{{version}}" will be replaced by the value of LIBMEM_DOWNLOAD_VERSION.
#     "{{target}}" will be replaced by the value of LIBMEM_DOWNLOAD_TARGET.
#     Default: libmem's GitHub releases are used (see https://github.com/rdbo/libmem/releases).
#
#   LIBMEM_DOWNLOAD_VERSION (required if LIBMEM_ROOT is empty and LIBMEM_DOWNLOAD_URL contains "{{version}}")
#     libmem version to download, used to construct LIBMEM_DOWNLOAD_URL.
#     Example: "5.1.0"
#
#   LIBMEM_DOWNLOAD_TARGET (optional)
#     libmem target to download, used to construct LIBMEM_DOWNLOAD_URL.
#     If empty, the target is detected automatically based on the target platform and architecture.
#     Example: "x86_64-windows-msvc-static-md"
#
#   LIBMEM_USE_SHARED_LIBS (optional)
#     Whether to use libmem as a shared library (ON) or as a static library (OFF).
#     Default: OFF
#
#   LIBMEM_MSVC_CRT (optional, MSVC only)
#     MSVC runtime library to use: "MD" or "MT" (then MDd or MTd are automatically used for debug builds).
#     Default: "MD"
#
# Defined variables:
#   Optional input variables (see above) will be initialized to their default/auto-detected values.
#
#   LIBMEM_FOUND
#     Indicate whether libmem was found.
#
#   LIBMEM_INCLUDE_DIRS (if LIBMEM_FOUND)
#     List of include directories for libmem.
#     It is recommended to use the target libmem::libmem instead of this variable (see below).
#
#   LIBMEM_LIBRARIES (if LIBMEM_FOUND)
#     List of libraries for libmem.
#     It is recommended to use the target libmem::libmem instead of this variable (see below).
#
# Defined targets:
#   libmem::libmem (if LIBMEM_FOUND)
#     CMake target for libmem.
#

if(CMAKE_VERSION VERSION_LESS 3.21.0)
  message(WARNING "libmem-config.cmake requires CMake 3.21 or newer (you are using ${CMAKE_VERSION})")
endif()

set(LIBMEM_ROOT "" CACHE PATH "Path to the root folder of the pre-built version of libmem (containing include and lib folders, downloaded automatically if empty)")
set(LIBMEM_DOWNLOAD_URL "https://github.com/rdbo/libmem/releases/download/{{version}}/libmem-{{version}}-{{target}}.tar.gz" CACHE STRING "URL for downloading the archive containing the pre-built version of libmem")
set(LIBMEM_DOWNLOAD_VERSION "" CACHE STRING "libmem version to download, used to construct LIBMEM_DOWNLOAD_URL (e.g. \"5.1.0\")")
set(LIBMEM_DOWNLOAD_TARGET "" CACHE STRING "libmem target to download, used to construct LIBMEM_DOWNLOAD_URL (detected automatically if empty)")
set(LIBMEM_USE_SHARED_LIBS OFF CACHE BOOL "Whether to use libmem as a shared library (ON) or as a static library (OFF)")

if (MSVC)
  set(LIBMEM_MSVC_CRT "MD" CACHE STRING "MSVC runtime library to use: \"MD\" or \"MT\" (ignored if LIBMEM_USE_SHARED_LIBS is ON)")
  if (NOT LIBMEM_MSVC_CRT MATCHES "^(MD|MT)$")
    message(FATAL_ERROR "LIBMEM_MSVC_CRT must be either \"MD\" or \"MT\" (then MDd or MTd are automatically used for debug builds)")
  endif ()
endif ()

function(_libmem_message _libmem_message_TYPE _libmem_message_MESSAGE)
  if (NOT ${CMAKE_FIND_PACKAGE_NAME}_FIND_QUIETLY) # defined by find_package(libmem [...] QUIET)
    message(${_libmem_message_TYPE} ${_libmem_message_MESSAGE})
  endif ()
endfunction()

# Download libmem if needed (when LIBMEM_ROOT is not set)
if (NOT LIBMEM_ROOT)
  # Construct the final download URL by replacing placeholders
  if (LIBMEM_DOWNLOAD_URL MATCHES "{{version}}")
    # Version must always be explicitly set
    # We could use the latest version from GitHub releases, but it would be less reliable, less reproducible, etc.
    if (NOT LIBMEM_DOWNLOAD_VERSION)
      message(FATAL_ERROR "Unknown libmem version to download, please set LIBMEM_DOWNLOAD_VERSION")
    endif ()
    string(REPLACE "{{version}}" "${LIBMEM_DOWNLOAD_VERSION}" LIBMEM_DOWNLOAD_URL "${LIBMEM_DOWNLOAD_URL}")
  endif ()

  if (LIBMEM_DOWNLOAD_URL MATCHES "{{target}}")
    # Target can be explicitly set, or we try to detect it automatically
    if (NOT LIBMEM_DOWNLOAD_TARGET)
      # 1. Detect target platform
      if (MSVC)
        set(_LIBMEM_DOWNLOAD_TARGET_PLATFORM "windows-msvc")
      elseif (CMAKE_SYSTEM_NAME MATCHES "Linux")
        set(_LIBMEM_DOWNLOAD_TARGET_PLATFORM "linux-gnu")
      endif ()

      # 2. Detect target architecture
      string(TOLOWER "${CMAKE_SYSTEM_PROCESSOR}" _LIBMEM_LOWER_SYSTEM_PROCESSOR)
      if (_LIBMEM_LOWER_SYSTEM_PROCESSOR MATCHES "(aarch64|arm64)")
        set(_LIBMEM_DOWNLOAD_TARGET_ARCH "aarch64")
      elseif (_LIBMEM_LOWER_SYSTEM_PROCESSOR MATCHES "(x86.64|amd64|x64)")
        if (CMAKE_SIZEOF_VOID_P EQUAL 8)
          set(_LIBMEM_DOWNLOAD_TARGET_ARCH "x86_64")
        elseif (CMAKE_SIZEOF_VOID_P EQUAL 4)
          set(_LIBMEM_DOWNLOAD_TARGET_ARCH "i686")
        endif ()
      elseif (_LIBMEM_LOWER_SYSTEM_PROCESSOR MATCHES "(i.86|x86)")
        set(_LIBMEM_DOWNLOAD_TARGET_ARCH "i686")
      endif ()

      # 3. Detect target variant
      if (MSVC)
        if (LIBMEM_USE_SHARED_LIBS)
          set(_LIBMEM_DOWNLOAD_TARGET_VARIANT "shared-md")
        elseif (LIBMEM_MSVC_CRT STREQUAL "MD")
          set(_LIBMEM_DOWNLOAD_TARGET_VARIANT "static-md")
        else ()
          set(_LIBMEM_DOWNLOAD_TARGET_VARIANT "static-mt")
        endif ()
      elseif (LIBMEM_USE_SHARED_LIBS)
        set(_LIBMEM_DOWNLOAD_TARGET_VARIANT "shared")
      else ()
        set(_LIBMEM_DOWNLOAD_TARGET_VARIANT "static")
      endif ()

      # Check that all variables were set and construct the final target
      if (NOT _LIBMEM_DOWNLOAD_TARGET_ARCH OR NOT _LIBMEM_DOWNLOAD_TARGET_PLATFORM OR NOT _LIBMEM_DOWNLOAD_TARGET_VARIANT)
        message(NOTICE "CMAKE_SYSTEM_NAME: ${CMAKE_SYSTEM_NAME}")
        message(NOTICE "MSVC: ${MSVC}")
        message(NOTICE "CMAKE_SYSTEM_PROCESSOR: ${CMAKE_SYSTEM_PROCESSOR}")
        message(NOTICE "CMAKE_SIZEOF_VOID_P: ${CMAKE_SIZEOF_VOID_P}")
        message(FATAL_ERROR "Unable to determine libmem target to download, please set LIBMEM_DOWNLOAD_TARGET (e.g. \"x86_64-windows-msvc-static-md\")")
      endif ()
      set(LIBMEM_DOWNLOAD_TARGET "${_LIBMEM_DOWNLOAD_TARGET_ARCH}-${_LIBMEM_DOWNLOAD_TARGET_PLATFORM}-${_LIBMEM_DOWNLOAD_TARGET_VARIANT}")
      _libmem_message(STATUS "Detected libmem target: ${LIBMEM_DOWNLOAD_TARGET}")
    endif ()

    string(REPLACE "{{target}}" "${LIBMEM_DOWNLOAD_TARGET}" LIBMEM_DOWNLOAD_URL "${LIBMEM_DOWNLOAD_URL}")
  endif ()

  # Use the download URL as download cache key
  # This way, the archive will be re-downloaded if the URL changes
  # Since the URL contains the version, it will be re-downloaded if the version changes
  string(SHA1 _LIBMEM_DOWNLOAD_NAME "${LIBMEM_DOWNLOAD_URL}")
  set(_LIBMEM_DOWNLOAD_NAME "libmem-${_LIBMEM_DOWNLOAD_NAME}")
  set(_LIBMEM_DOWNLOAD_DIR "${CMAKE_CURRENT_BINARY_DIR}/${_LIBMEM_DOWNLOAD_NAME}")

  # Download and extract libmem if the download directory doesn't exist or is empty
  file(GLOB _LIBMEM_DOWNLOAD_DIR_CHILDREN "${_LIBMEM_DOWNLOAD_DIR}/*")
  if (NOT _LIBMEM_DOWNLOAD_DIR_CHILDREN)
    # Download the archive if it doesn't exist
    set(_LIBMEM_DOWNLOAD_FILE "${_LIBMEM_DOWNLOAD_DIR}.tar.gz")
    if (NOT EXISTS "${_LIBMEM_DOWNLOAD_FILE}")
      _libmem_message(STATUS "Downloading libmem from ${LIBMEM_DOWNLOAD_URL} (to ${_LIBMEM_DOWNLOAD_FILE})")
      file(DOWNLOAD "${LIBMEM_DOWNLOAD_URL}" "${_LIBMEM_DOWNLOAD_FILE}"
          SHOW_PROGRESS
          STATUS _LIBMEM_DOWNLOAD_STATUS
          LOG _LIBMEM_DOWNLOAD_LOG
      )
      list(GET _LIBMEM_DOWNLOAD_STATUS 0 LIBMEM_DOWNLOAD_STATUS_CODE)
      if (NOT LIBMEM_DOWNLOAD_STATUS_CODE EQUAL 0)
        file(REMOVE "${_LIBMEM_DOWNLOAD_FILE}")
        message(NOTICE "${_LIBMEM_DOWNLOAD_LOG}")
        message(FATAL_ERROR "libmem download failed with status: ${_LIBMEM_DOWNLOAD_STATUS}")
      endif ()
    endif ()

    # Extract the archive
    _libmem_message(STATUS "Extracting libmem to ${_LIBMEM_DOWNLOAD_DIR}")
    file(ARCHIVE_EXTRACT
        INPUT "${_LIBMEM_DOWNLOAD_FILE}"
        DESTINATION "${_LIBMEM_DOWNLOAD_DIR}"
    )
    file(GLOB _LIBMEM_DOWNLOAD_DIR_CHILDREN "${_LIBMEM_DOWNLOAD_DIR}/*") # important: update the list of children
  endif ()

  # Finally, set LIBMEM_ROOT
  if (_LIBMEM_DOWNLOAD_DIR_CHILDREN MATCHES ";")
    # If there are multiple children, use the download directory as root
    set(LIBMEM_ROOT "${_LIBMEM_DOWNLOAD_DIR}")
  else ()
    # If there is only one child folder, use it as root
    set(LIBMEM_ROOT "${_LIBMEM_DOWNLOAD_DIR_CHILDREN}")
  endif ()
  _libmem_message(STATUS "Using libmem from: ${LIBMEM_DOWNLOAD_URL} (downloaded to ${LIBMEM_ROOT})")
else ()
  _libmem_message(STATUS "Using libmem from: ${LIBMEM_ROOT}")
endif ()

# Find intermediate files
function(_libmem_find_library
    _libmem_get_library_DEBUG_VAR
    _libmem_get_library_RELEASE_VAR
    _libmem_get_library_NAME
    _libmem_get_library_EXTENSION
)
  if (WIN32)
    set(_libmem_get_library_debug "${LIBMEM_ROOT}/lib/debug/${_libmem_get_library_NAME}.${_libmem_get_library_EXTENSION}")
    set(_libmem_get_library_release "${LIBMEM_ROOT}/lib/release/${_libmem_get_library_NAME}.${_libmem_get_library_EXTENSION}")
  else ()
    set(_libmem_get_library_debug "${LIBMEM_ROOT}/lib/lib${_libmem_get_library_NAME}.${_libmem_get_library_EXTENSION}")
    set(_libmem_get_library_release "${_libmem_get_library_debug}")
  endif ()

  # Set output variables (empty if the file doesn't exist)
  if (EXISTS "${_libmem_get_library_debug}")
    set(${_libmem_get_library_DEBUG_VAR} "${_libmem_get_library_debug}" PARENT_SCOPE)
  else ()
    set(${_libmem_get_library_DEBUG_VAR} "${_libmem_get_library_DEBUG_VAR}-NOTFOUND" PARENT_SCOPE)
  endif ()
  if (EXISTS "${_libmem_get_library_release}")
    set(${_libmem_get_library_RELEASE_VAR} "${_libmem_get_library_release}" PARENT_SCOPE)
  else ()
    set(${_libmem_get_library_RELEASE_VAR} "${_libmem_get_library_RELEASE_VAR}-NOTFOUND" PARENT_SCOPE)
  endif ()
endfunction()

set(_LIBMEM_REQUIRED_VARS "")

list(APPEND _LIBMEM_REQUIRED_VARS "_LIBMEM_INCLUDE_DIR")
if (EXISTS "${LIBMEM_ROOT}/include/libmem/libmem.h")
  set(_LIBMEM_INCLUDE_DIR "${LIBMEM_ROOT}/include")
else ()
  set(_LIBMEM_INCLUDE_DIR "")
endif ()

list(APPEND _LIBMEM_REQUIRED_VARS "_LIBMEM_DEBUG_LIBRARY" "_LIBMEM_RELEASE_LIBRARY")
if (WIN32)
  _libmem_find_library(_LIBMEM_DEBUG_LIBRARY _LIBMEM_RELEASE_LIBRARY "libmem" "lib")
  if (LIBMEM_USE_SHARED_LIBS)
    # _LIBMEM_DEBUG_LIBRARY and _LIBMEM_RELEASE_LIBRARY point to an import library,
    # ensure that the corresponding DLLs are available
    list(APPEND _LIBMEM_REQUIRED_VARS "_LIBMEM_DEBUG_DLL" "_LIBMEM_RELEASE_DLL")
    _libmem_find_library(_LIBMEM_DEBUG_DLL _LIBMEM_RELEASE_DLL "libmem" "dll")
  endif ()
else ()
  if (LIBMEM_USE_SHARED_LIBS)
    _libmem_find_library(_LIBMEM_DEBUG_LIBRARY _LIBMEM_RELEASE_LIBRARY "libmem" "so")
  else ()
    _libmem_find_library(_LIBMEM_DEBUG_LIBRARY _LIBMEM_RELEASE_LIBRARY "libmem" "a")
  endif ()
endif ()

# Use find_package_handle_standard_args to check find_package conditions
# It will set LIBMEM_FOUND
include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(libmem
    DEFAULT_MSG
    ${_LIBMEM_REQUIRED_VARS}
)

# If libmem was found, define output variables and targets
if (LIBMEM_FOUND)
  set(LIBMEM_INCLUDE_DIRS "${_LIBMEM_INCLUDE_DIR}")
  set(LIBMEM_LIBRARIES
      "$<$<CONFIG:DEBUG>:${_LIBMEM_DEBUG_LIBRARY}>"
      "$<$<NOT:$<CONFIG:DEBUG>>:${_LIBMEM_RELEASE_LIBRARY}>"
  )
  _libmem_message(STATUS "Found libmem include dirs: ${LIBMEM_INCLUDE_DIRS}")
  _libmem_message(STATUS "Found libmem libraries: ${LIBMEM_LIBRARIES}")

  add_library(libmem INTERFACE)
  add_library(libmem::libmem ALIAS libmem)

  target_include_directories(libmem INTERFACE "${LIBMEM_INCLUDE_DIRS}")
  target_link_libraries(libmem INTERFACE "${LIBMEM_LIBRARIES}")
endif ()

# Hide internal variables
mark_as_advanced(
    _LIBMEM_LOWER_SYSTEM_PROCESSOR
    _LIBMEM_DOWNLOAD_TARGET_ARCH
    _LIBMEM_DOWNLOAD_TARGET_PLATFORM
    _LIBMEM_DOWNLOAD_TARGET_VARIANT
    _LIBMEM_DOWNLOAD_NAME
    _LIBMEM_DOWNLOAD_DIR
    _LIBMEM_DOWNLOAD_FILE
    _LIBMEM_DOWNLOAD_STATUS
    _LIBMEM_DOWNLOAD_LOG
    _LIBMEM_DOWNLOAD_DIR_CHILDREN
    _LIBMEM_REQUIRED_VARS
    _LIBMEM_INCLUDE_DIR
    _LIBMEM_DEBUG_LIBRARY
    _LIBMEM_RELEASE_LIBRARY
    _LIBMEM_DEBUG_DLL
    _LIBMEM_RELEASE_DLL
)
