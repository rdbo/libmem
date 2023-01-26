#!/bin/sh

docker run --rm --privileged multiarch/qemu-user-static --reset -p yes
mkdir -p build-aarch64
docker build --platform linux/arm64 -t libmem-aarch64 .
docker run --platform linux/arm64 -v "$(pwd)/build-aarch64:/app/build-aarch64" -it libmem-aarch64

