FROM golang:1.13.0-alpine as builder
MAINTAINER github.com/UnAfraid/subspace

ARG BUILD_VERSION=unknown

WORKDIR /app/
COPY . .

ENV GODEBUG="netdns=go http2server=0"
ENV CGO_ENABLED=0
ENV GOOS=linux
ENV GOARCH=amd64

RUN go get -u github.com/jteeuwen/go-bindata/...
RUN go generate -mod=vendor ./...
RUN go build -mod=vendor -o app --compiler gc --ldflags "-extldflags -static -s -w -X main.version=${BUILD_VERSION}"

FROM phusion/baseimage:0.11
ENV DEBIAN_FRONTEND noninteractive

RUN apt-get update \
    && apt-get install -y ca-certificates iproute2 iptables dnsmasq socat

COPY --from=builder /app/app /app
COPY --from=builder /app/entrypoint.sh /entrypoint.sh

EXPOSE 80/tcp
ENTRYPOINT ["/entrypoint.sh"]
CMD [ "/sbin/my_init" ]
