#!/bin/bash
# CC Build (x86_64)

if [ ! -d ./bin ]; then
	mkdir ./bin
fi

if [ ! -d ./bin/x64 ]; then
	mkdir ./bin/x64
fi

if [ ! -d ./bin/x64/obj ]; then
	mkdir ./bin/x64/obj
fi

find ./bin -type f -delete

cc -g -m64 -o ./bin/x64/obj/libmem.o -D LIBMEM_EXPORT -c -shared -fPIC ../libmem/libmem.c

if [[ "$OSTYPE" == "linux"* ]]; then
    cc -g -m64 -o ./bin/x64/libmem.so -D LIBMEM_EXPORT -shared -fPIC ./bin/x64/obj/libmem.o -ldl
elif [[ "$OSTYPE" == *"BSD"* ]]; then
    cc -g -m64 -o ./bin/x64/libmem.so -D LIBMEM_EXPORT -shared -fPIC ./bin/x64/obj/libmem.o -ldl -lkvm -lprocstat
fi