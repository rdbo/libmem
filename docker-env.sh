#!/bin/sh

mkdir -p build
docker build -t libmem .
docker run -v "$(pwd)/build:/app/build" -it libmem

