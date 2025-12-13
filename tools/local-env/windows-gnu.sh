#!/usr/bin/env sh

_arch=$1
shift

case "$_arch" in
i686)
  _mingw_prefix=i686-w64-mingw32
  ;;
x86_64)
  _mingw_prefix=x86_64-w64-mingw32
  ;;
*)
  echo "Unknown arch: $_arch"
  exit 1
  ;;
esac

# Set up MinGW-w64 environment
export CC="${_mingw_prefix}-gcc"
export CXX="${_mingw_prefix}-g++"
export AR="${_mingw_prefix}-ar"
export RANLIB="${_mingw_prefix}-ranlib"
export STRIP="${_mingw_prefix}-strip"
export PKG_CONFIG="${_mingw_prefix}-pkg-config"

# Execute the command
exec "$@"



