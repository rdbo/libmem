#!/bin/bash
# CC Build (x86_32)

if [ ! -d ./bin ]; then
	mkdir ./bin
fi

if [ ! -d ./bin/x86 ]; then
	mkdir ./bin/x86
fi

if [ ! -d ./bin/x86/obj ]; then
	mkdir ./bin/x86/obj
fi

find ./bin -type f -delete

cc -g -m32 -o ./bin/x86/obj/libmem.o -D LIBMEM_EXPORT -c -shared -fPIC ../libmem/libmem.c

if [[ "$OSTYPE" == "linux"* ]]; then
    cc -g -m32 -o ./bin/x86/libmem.so -D LIBMEM_EXPORT -shared -fPIC ./bin/x86/obj/libmem.o -ldl
elif [[ "$OSTYPE" == *"BSD"* ]]; then
    cc -g -m32 -o ./bin/x86/libmem.so -D LIBMEM_EXPORT -shared -fPIC ./bin/x86/obj/libmem.o -ldl -lkvm -lprocstat
fi
