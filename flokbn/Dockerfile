# ────────────────
# 1. Builder stage
# ────────────────
# Runs on the build host's platform and cross-compiles for the target, so
# `docker buildx build --platform linux/amd64,linux/arm64` needs no emulation.
FROM --platform=$BUILDPLATFORM golang:1.23-alpine AS builder

# Set by BuildKit from --platform (default: the build host's platform).
ARG TARGETOS=linux
ARG TARGETARCH

# Version stamp reported by `flokbn --version`. Override at build time:
#   docker build --build-arg VERSION=1.2.3 \
#                --build-arg COMMIT=<commit sha> \
#                --build-arg DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ) ./flokbn
ARG VERSION=dev
ARG COMMIT=unknown
ARG DATE=unknown

RUN apk add --no-cache ca-certificates

WORKDIR /src
COPY src/ .

RUN CGO_ENABLED=0 \
    GOOS=${TARGETOS} \
    GOARCH=${TARGETARCH} \
    go build -trimpath \
      -ldflags="-s -w \
        -X github.com/ChristianF88/flokbn/version.Version=${VERSION} \
        -X github.com/ChristianF88/flokbn/version.Commit=${COMMIT} \
        -X github.com/ChristianF88/flokbn/version.Date=${DATE}" \
      -o flokbn .

# ────────────────
# 2. Runtime stage
# ────────────────
FROM alpine:3.20

RUN apk add --no-cache ca-certificates coreutils

# Create non-root user and group
RUN addgroup -g 1000 flokbn && \
    adduser -D -u 1000 -G flokbn flokbn

# Create data directory with proper ownership
RUN mkdir -p /data && \
    chown -R flokbn:flokbn /data

COPY --from=builder /src/flokbn /flokbn
RUN chown flokbn:flokbn /flokbn

# Switch to non-root user
USER flokbn

EXPOSE 9000 8666

# Default: live mode with the config mounted at /config/flokbn.toml.
# Arguments to `docker run` replace CMD, so other subcommands work too:
#   docker run --rm -v "$PWD:/logs:ro" flokbn static --logfile /logs/access.log --plain
ENTRYPOINT ["/flokbn"]
CMD ["live", "--config", "/config/flokbn.toml"]
