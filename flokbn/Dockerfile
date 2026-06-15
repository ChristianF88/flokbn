# ────────────────
# 1. Builder stage
# ────────────────
FROM golang:1.23-alpine AS builder

RUN apk add --no-cache ca-certificates

WORKDIR /src
COPY src/ .

RUN CGO_ENABLED=0 \
    GOOS=linux \
    GOARCH=amd64 \
    go build -ldflags="-s -w" -o flokbn .

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

ENTRYPOINT ["/flokbn", "live", "--config", "/config/flokbn.toml"]
