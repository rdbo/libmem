#!/bin/bash

if [[ "$OSTYPE" == "linux"* ]]; then
    cc -g -o example example.c ../libmem/libmem.c -ldl
elif [[ "$OSTYPE" == *"BSD"* ]]; then
    cc -g -o example example.c ../libmem/libmem.c -ldl -lkvm -lprocstat
fi