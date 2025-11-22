FROM debian:oldstable

# Create Debian Buster (glibc 2.28) image for cross-building i686 linux GNU binaries

RUN dpkg --add-architecture i386 \
    && apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -yqq --no-install-recommends \
        build-essential \
        crossbuild-essential-i386 \
        ca-certificates \
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

ENV CC="i686-linux-gnu-gcc" \
    CXX="i686-linux-gnu-g++"
