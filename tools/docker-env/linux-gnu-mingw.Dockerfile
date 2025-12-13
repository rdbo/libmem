FROM debian:trixie

# Create Debian Buster image for building Windows binaries using MinGW-w64

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -yqq --no-install-recommends \
        build-essential \
        ca-certificates \
        g++-mingw-w64-i686 \
        g++-mingw-w64-x86-64 \
        g++-mingw-w64-ucrt64 \
        gcc-mingw-w64-i686 \
        gcc-mingw-w64-x86-64 \
        gcc-mingw-w64-ucrt64 \
        ninja-build \
        python3 \
        wget \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /cmake /usr

RUN wget -O- "https://github.com/Kitware/CMake/releases/download/v3.27.8/cmake-3.27.8-linux-$(uname -m).tar.gz" \
      | tar -xz --strip-components=1 -C /cmake

RUN cp -r /cmake/. /usr/

RUN groupadd -g 911 build \
    && useradd -mN -u 911 -g 911 build

RUN test -f /usr/bin/python || ln -s /usr/bin/python3 /usr/bin/python

COPY --chmod=700 entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]

