FROM alpine:latest

WORKDIR /app

ENTRYPOINT ["/bin/sh"]

RUN apk update
RUN apk add gcc g++ gdb git cmake make python3 linux-headers

COPY . .
