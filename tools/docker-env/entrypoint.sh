#!/usr/bin/env sh
set -eu

groupmod -o -g "${PGID:-1000}" build
usermod -o -u "${PUID:-1000}" build

if [ ! -d /build ]; then
  mkdir /build
  chown build:build /build
fi

command=${1:-sh}
command=$(which -- "${command}" || {
  echo "${command}: not found" >&2
  return 1
})
shift
exec su build -s "$command" -- "$@"
