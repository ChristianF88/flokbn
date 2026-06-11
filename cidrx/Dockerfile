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
    go build -ldflags="-s -w" -o cidrx .

# ────────────────
# 2. Runtime stage
# ────────────────
FROM alpine:3.20

RUN apk add --no-cache ca-certificates coreutils

# Create non-root user and group
RUN addgroup -g 1000 cidrx && \
    adduser -D -u 1000 -G cidrx cidrx

# Create data directory with proper ownership
RUN mkdir -p /data && \
    chown -R cidrx:cidrx /data

COPY --from=builder /src/cidrx /cidrx
RUN chown cidrx:cidrx /cidrx

# Switch to non-root user
USER cidrx

EXPOSE 9000 8666

ENTRYPOINT ["/cidrx", "live", "--config", "/config/cidrx.toml"]
