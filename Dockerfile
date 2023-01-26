FROM alpine:latest

WORKDIR /app

RUN apk update
RUN apk add gcc g++ git cmake make python3 linux-headers

COPY . .

ENTRYPOINT ["/bin/sh"]

