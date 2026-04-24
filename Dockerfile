# syntax=docker/dockerfile:1.4
FROM --platform=$BUILDPLATFORM golang:latest as builder

ARG TARGETOS
ARG TARGETARCH
ARG TARGETVARIANT
ARG CGO_ENABLED=1
ARG BUILDPLATFORM

RUN apt-get update && apt-get install -y gcc
RUN if [ "${TARGETARCH}" = "arm64" ]; then apt-get install -y gcc-aarch64-linux-gnu; fi
RUN if [ "${TARGETARCH}" = "amd64" ]; then apt-get install -y gcc-x86-64-linux-gnu; fi

RUN mkdir /app
WORKDIR /app

COPY . .

ENV CGO_ENABLED=1
ENV GOOS=${TARGETOS}
ENV GOARCH=${TARGETARCH}

RUN if [ "${TARGETARCH}" = "amd64" ]; then \
        export CC=x86_64-linux-gnu-gcc && \
        export CXX=x86_64-linux-gnu-g++ && \
        export CGO_ENABLED=1; \
    elif [ "${TARGETARCH}" = "arm64" ]; then \
        export CC=aarch64-linux-gnu-gcc && \
        export CXX=aarch64-linux-gnu-g++ && \
        export CGO_ENABLED=1; \
    else \
        echo "Unknown architecture" && exit 1; \
    fi && \
    go clean -modcache && \
    go mod download && \
    go build -o authservice ./cmd/authservice/main.go

# Runtime stage
FROM --platform=$TARGETPLATFORM debian:bookworm-slim
WORKDIR /app
COPY --from=builder /app/authservice .
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
CMD ["./authservice"]
