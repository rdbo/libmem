#!/bin/sh

if [ $# -ne 1 ]; then
    echo "[*] Usage: ./build.sh <example>"
    echo "[*] Example: ./build.sh process_enumeration"
    exit 1
fi

if [ ! -f "$1.c" ]; then
    echo "[*] Invalid Example: $1"
    exit 1
fi

cc -o "$1" -g "$1.c" -llibmem

