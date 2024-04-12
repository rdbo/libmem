#!/usr/bin/env bash
set -Eeuo pipefail
shopt -s inherit_errexit

declare -gr NIX_PLATFORMS=(
  # Linux (GNU/glibc)
  i686-linux-gnu
  x86_64-linux-gnu
  aarch64-linux-gnu
  # Linux (Alpine/musl)
  i686-linux-musl
  x86_64-linux-musl
  aarch64-linux-musl
)
declare -gr NIX_VARIANTS=(
  shared
  static
)

declare -gr WINDOWS_PLATFORMS=(
  # Windows (MSVC)
  i686-windows-msvc
  x86_64-windows-msvc
  aarch64-windows-msvc
)
declare -gr WINDOWS_VARIANTS=(
  shared-md
  static-md
  static-mt
)

SCRIPT_DIR=$(dirname -- "$(realpath -m -- "$0")")
declare -gr SCRIPT_DIR
PROJECT_DIR=$(dirname -- "$SCRIPT_DIR")
declare -gr PROJECT_DIR

function define_targets() {
  local platform variant
  TARGETS=()
  for platform in "${NIX_PLATFORMS[@]}"; do
    for variant in "${NIX_VARIANTS[@]}"; do
      TARGETS+=("${platform}-${variant}")
    done
  done
  for platform in "${WINDOWS_PLATFORMS[@]}"; do
    for variant in "${WINDOWS_VARIANTS[@]}"; do
      TARGETS+=("${platform}-${variant}")
    done
  done
  declare -gr TARGETS
}

function print_usage() {
  cat <<EOF
Usage: $(basename -- "$0") <target>

Environment variables:
  LIBMEM_BUILD_OUT_DIR: The output directory (default: "build/out/libmem-local-\${target}").
  LIBMEM_BUILD_SKIP_ARCHIVE: Skip the final archive creation (default: false).

Supported targets:
$(printf '  - %s\n' "${TARGETS[@]}")
EOF
}

function main() {
  define_targets
  echo "$TARGETS"

  if [[ $# -ne 1 ]]; then
    print_usage >&2
    return 1
  fi

  local target=$1
  if ! array_contains "$target" "${TARGETS[@]}"; then
    printf 'error: Unknown target: %s\n' "$target" >&2
    return 1
  fi

  local source_dir=${PROJECT_DIR}
  local out_dir
  if [[ -n "${LIBMEM_BUILD_OUT_DIR:-}" ]]; then
    out_dir=$(realpath -m -- "$LIBMEM_BUILD_OUT_DIR")
    if [[ -d "$out_dir" ]]; then
      printf 'error: Output directory already exists: %s\n' "$out_dir" >&2
      return 1
    fi
  else
    out_dir=$(realpath -m -- "build/out/libmem-local-${target}")
    rm -rf -- "$out_dir"
  fi
  mkdir -p -- "$out_dir"

  printf 'Target: %s\n' "$target"
  printf 'Source directory: %s\n' "$source_dir"
  printf 'Output directory: %s\n' "$out_dir"
  printf '\n'

  case "$target" in
  *-linux-*) _build_in_docker "$target" "$source_dir" "$out_dir" ;;
  *) _build_locally "$target" "$source_dir" "$out_dir" ;;
  esac

  if [[ "${LIBMEM_BUILD_SKIP_ARCHIVE:-}" != true ]]; then
    printf '[+] Create archive\n'
    tar -czf "${out_dir}.tar.gz" --owner=0 --group=0 --numeric-owner -C "$(dirname -- "$out_dir")" "$(basename -- "$out_dir")"
  fi

  printf '[+] Done\n'
}

function _build_in_docker() {
  local target=$1 source_dir=$2 out_dir=$3

  local docker_os=unknown docker_platform=unknown
  case "$target" in
  *-linux-gnu-*) docker_os=linux-gnu ;;
  *-linux-musl-*) docker_os=linux-musl ;;
  esac
  case "$target" in
  i686-linux-gnu-*)
    # cross-compile i686 from x86_64 (CMake is no longer compiled for i686 and we can't rely on the old distro package)
    docker_platform=linux/amd64
    docker_os+='-crossbuild-i686'
    ;;
  i686-*) docker_platform=linux/386 ;;
  x86_64-*) docker_platform=linux/amd64 ;;
  aarch64-*) docker_platform=linux/arm64 ;;
  esac

  local docker_image="libmem-build-${docker_os}-${docker_platform##*/}"
  docker build --platform "$docker_platform" -t "$docker_image" -f "${SCRIPT_DIR}/docker-env/${docker_os}.Dockerfile" "${SCRIPT_DIR}/docker-env"
  docker run --platform "$docker_platform" --rm \
    -e "PUID=$(id -u)" \
    -e "PGID=$(id -g)" \
    -e "_TARGET=${target}" \
    -e "_SOURCE_DIR=/source" \
    -e "_BUILD_DIR=/build" \
    -e "_OUT_DIR=/out" \
    -v "${source_dir}:/source:ro" \
    -v "${out_dir}:/out:rw" \
    -i "$docker_image" \
    bash <<<"set -Eeuo pipefail; shopt -s inherit_errexit; $(declare -f do_build); do_build; exit 0"
}

function _build_locally() {
  local target=$1 source_dir=$2 out_dir=$3

  local local_env local_env_arch
  local_env=$(awk -F- '{print $2"-"$3}' <<<"$target") # keep only the middle part
  local_env_arch=${target%%-*} # remove everything after the first dash

  init_temp_dir
  _=_ \
    _TARGET="$target" \
    _SOURCE_DIR="$source_dir" \
    _BUILD_DIR="${g_temp_dir}/build" \
    _OUT_DIR="$out_dir" \
    "${SCRIPT_DIR}/local-env/${local_env}.sh" "$local_env_arch" \
    bash <<<"set -Eeuo pipefail; shopt -s inherit_errexit; $(declare -f do_build); do_build; exit 0"
}

# Perform the build and copy the results to the output directory.
# This function must be self-contained and exportable.
# Inputs:
#   _TARGET: The target to build.
#   _SOURCE_DIR: The absolute path to the source directory.
#   _BUILD_DIR: The absolute path to the build directory.
#   _OUT_DIR: The absolute path to the output directory.
function do_build() {
  true "${_TARGET?required}" "${_SOURCE_DIR?required}" "${_BUILD_DIR?required}" "${_OUT_DIR?required}"

  # Build using CMake
  function build_variant() {
    local variant_name=$1
    local variant_build_type=$2
    local variant_conf=("${@:3}")
    printf '[+] Build (%s)\n' "$variant_name"

    # Prepare config
    case "$_TARGET" in
    *-windows-msvc-*)
      variant_conf+=(-G 'NMake Makefiles')
      ;;
    *)
      local flags
      case "$_TARGET" in
      i686-*) flags='-m32 -march=prescott'; variant_conf+=(-D LIBMEM_ARCH="i686") ;;
      x86_64-*) flags='-march=westmere'; variant_conf+=(-D LIBMEM_ARCH="x86_64") ;;
      aarch64-*) flags='-march=armv8-a' ;;
      esac
      variant_conf+=(-G 'Unix Makefiles' -DCMAKE_C_FLAGS="$flags" -DCMAKE_CXX_FLAGS="$flags")
      ;;
    esac
    variant_conf+=(-DLIBMEM_BUILD_TESTS='OFF')

    # Build using CMake
    local variant_build_dir="${_BUILD_DIR}/${variant_name}"
    set -x
    cmake -S "$_SOURCE_DIR" -B "$variant_build_dir" -DCMAKE_BUILD_TYPE="$variant_build_type" "${variant_conf[@]}"
    cmake --build "$variant_build_dir" --config "$variant_build_type" --parallel "$(nproc)"
    { set +x; } 2>/dev/null

    # Copy libraries
    local variant_out_dir="${_OUT_DIR}/lib/${variant_name}"
    mkdir -p -- "$variant_out_dir"
    function copy_lib() {
      install -vD -m644 -- "${variant_build_dir}/${1}" "${variant_out_dir}/${2:-$(basename -- "$1")}"
    }
    case "$_TARGET" in
    *-windows-msvc-shared*) copy_lib 'libmem.dll'; copy_lib 'libmem.lib' ;; # NOTE: 'libmem.lib' is used for load-time linking
    *-windows-msvc-static*) copy_lib 'libmem.lib' ;;
    *-shared) copy_lib 'liblibmem.so' ;;
    *-static) copy_lib 'liblibmem.a' ;;
    esac
  }

  case "$_TARGET" in
  *-windows-msvc-shared-md)
    build_variant release Release -DLIBMEM_BUILD_STATIC=OFF -DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreadedDLL
    build_variant debug Debug -DLIBMEM_BUILD_STATIC=OFF -DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreadedDebugDLL
    ;;
  *-windows-msvc-static-md)
    build_variant release Release -DLIBMEM_BUILD_STATIC=ON -DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreadedDLL
    build_variant debug Debug -DLIBMEM_BUILD_STATIC=ON -DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreadedDebugDLL
    ;;
  *-windows-msvc-static-mt)
    build_variant release Release -DLIBMEM_BUILD_STATIC=ON -DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded
    build_variant debug Debug -DLIBMEM_BUILD_STATIC=ON -DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreadedDebug
    ;;
  *-shared)
    build_variant ./ Release -DLIBMEM_BUILD_STATIC=OFF
    ;;
  *-static)
    build_variant ./ Release -DLIBMEM_BUILD_STATIC=ON
    ;;
  esac

  # Copy headers
  printf '[+] Copy headers\n'
  mkdir -p -- "${_OUT_DIR}/include"
  cp -rT -- "${_SOURCE_DIR}/include" "${_OUT_DIR}/include"

  # Copy licenses
  printf '[+] Copy licenses\n'
  mkdir -p -- "${_OUT_DIR}/licenses"
  function copy_licenses() {
    local name=$1
    local dir="${_SOURCE_DIR}/${2:-$name}"
    find "$dir" -maxdepth 1 -type f \( -iname 'license*' -o -iname 'copying*' -o -iname 'exception*' \) | while read -r file; do
      local file_name
      file_name=$(basename -- "$file")
      file_name=${file_name%.*} # remove extension
      file_name=${file_name,,}  # lowercase
      install -vD -m644 -- "$file" "${_OUT_DIR}/licenses/${name}-${file_name}.txt"
    done
  }
  copy_licenses 'libmem' './'
  copy_licenses 'capstone' 'external/capstone'
  copy_licenses 'keystone' 'external/keystone'
  copy_licenses 'llvm' 'external/llvm'

  # Add stdlib information (glibc version, musl version)
  printf '[+] Add stdlib information\n'
  case "$_TARGET" in
  *-linux-gnu-*)
    # ldd --version can cause exit 141 when stdout is closed early.
    { ldd --version || true; } | head -n1 | awk '{print $NF}' | install -vD -m644 -- /dev/stdin "${_OUT_DIR}/GLIBC_VERSION.txt"
    ;;
  *-linux-musl-*)
    apk info musl 2>/dev/null | head -n1 | awk '{print $1}' | sed 's/^musl-//' | install -vD -m644 -- /dev/stdin "${_OUT_DIR}/MUSL_VERSION.txt"
    ;;
  *-windows-msvc-*)
    printf '%s\n' "${VCTOOLSVERSION:-${VSCMD_ARG_VCVARS_VER:-}}" | install -vD -m644 -- /dev/stdin "${_OUT_DIR}/MSVC_VERSION.txt"
    printf '%s\n' "${WINDOWSSDKVERSION:-}" | install -vD -m644 -- /dev/stdin "${_OUT_DIR}/WINSDK_VERSION.txt"
    ;;
  esac
}

# Ensure that the temporary directory exists and is set to an absolute path.
# This directory will be automatically deleted when the script exits.
# This function is idempotent.
# Outputs:
#   g_temp_dir: The absolute path to the temporary directory.
function init_temp_dir() {
  if [[ -v g_temp_dir ]]; then
    return
  fi

  g_temp_dir=$(mktemp -d)
  declare -gr g_temp_dir

  # shellcheck disable=SC2317
  function __temp_dir_cleanup() { rm -rf -- "$g_temp_dir"; }
  trap __temp_dir_cleanup INT TERM EXIT
}

# Check if an array contains a value.
# Inputs:
#   $1: The value to check for.
#   $2+: The array to check.
# Returns:
#   0 if the array contains the value,
#   1 otherwise.
function array_contains() {
  local value=$1
  local element
  for element in "${@:2}"; do
    if [[ "$element" == "$value" ]]; then
      return 0
    fi
  done
  return 1
}

eval 'main "$@";exit "$?"'
