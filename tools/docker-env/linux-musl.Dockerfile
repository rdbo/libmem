FROM alpine:3.16

# Create Alpine 3.16 (musl 1.2.3) image for building linux MUSL binaries

RUN apk --update --no-cache add \
        bash \
        build-base \
        cmake \
        python3 \
        shadow

RUN addgroup -g 911 build \
    && adduser -D -u 911 -G build build

RUN test -f /usr/bin/python || ln -s /usr/bin/python3 /usr/bin/python

COPY --chmod=700 entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
