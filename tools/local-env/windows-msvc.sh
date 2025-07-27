#!/usr/bin/env sh

_arch=$1
shift

_host_arch=amd64
case "$_arch" in
i686) _target_arch=x86 ;;
x86_64) _target_arch=amd64 ;;
aarch64) _target_arch=arm64 ;;
*)
  echo "Unknown arch: $_arch"
  exit 1
  ;;
esac
if [ "$_host_arch" = "$_target_arch" ]; then
  _vcvars_arch=$_host_arch
else
  _vcvars_arch="${_host_arch}_${_target_arch}"
fi

case "$_arch" in
aarch64)
  # aarch64 require v143 toolset (to support ARM64/ARM64EC and MT/MTd runtime)
  _vcvars_ver=auto
  ;;
*)
  # default to v141 toolset (goal is to support the lowest version possible)
  _vcvars_ver=auto
  ;;
esac

. "$(dirname -- "$0")/../../external/vcvars-bash/vcvarsrun.sh" all # dump toolset versions
exec "$(dirname -- "$0")/../../external/vcvars-bash/vcvarsrun.sh" "$_vcvars_arch" -vcvars_ver="$_vcvars_ver" -- "$@"
