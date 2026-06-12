---
title: "Installation"
description: "How to install cidrx on your system"
summary: "Step-by-step instructions for installing cidrx from source or using Docker"
date: 2025-10-09T10:00:00+00:00
lastmod: 2026-06-11T10:00:00+00:00
draft: false
weight: 110
toc: true
seo:
  title: "Install cidrx"
  description: "Complete installation guide for cidrx including source builds, Docker, and dependencies"
  canonical: ""
  noindex: false
---

## Prebuilt Binaries (Recommended)

Every release ships static binaries - no Go toolchain required. Download the archive for your platform from the [releases page](https://github.com/ChristianF88/cidrx/releases/latest):

| Platform | Archive |
|----------|---------|
| Linux x86_64 | `cidrx_<version>_Linux_x86_64.tar.gz` |
| Linux arm64 | `cidrx_<version>_Linux_arm64.tar.gz` |
| Linux armv7 (e.g. Raspberry Pi) | `cidrx_<version>_Linux_armv7.tar.gz` |
| macOS Intel | `cidrx_<version>_Darwin_x86_64.tar.gz` |
| macOS Apple Silicon | `cidrx_<version>_Darwin_arm64.tar.gz` |
| Windows x86_64 | `cidrx_<version>_Windows_x86_64.zip` |

Unpack and put the binary on your `PATH`:

```bash
tar -xzf cidrx_*_Linux_x86_64.tar.gz
sudo mv cidrx /usr/local/bin/
cidrx --help
```

Each release includes a `checksums.txt`; verify your download with `sha256sum -c checksums.txt`.

## Prerequisites (building from source)

- **Go 1.23 or later** (for building from source)
- **Docker** (optional, for containerized deployment)
- **Git** (for cloning the repository)

## Installation from Source

### Clone the Repository

```bash
git clone https://github.com/ChristianF88/cidrx.git
cd cidrx/cidrx/src
```

### Build the Binary

Basic build:

```bash
go build -o cidrx .
```

Build with optimizations (smaller binary, slightly faster):

```bash
go build -ldflags="-s -w" -o cidrx .
```

The `-ldflags="-s -w"` flags strip debug information and symbol tables, reducing binary size.

### Verify Installation

```bash
./cidrx --help
```

### Install System-Wide (Optional)

```bash
sudo mv cidrx /usr/local/bin/
```

## Docker Installation

### Build Docker Image

From the `cidrx` directory (not `cidrx/src`):

```bash
cd cidrx/cidrx
docker build -t cidrx .
```

### Run Docker Container

```bash
docker run -v /var/log:/logs cidrx static \
  --logfile /logs/nginx/access.log \
  --clusterArgSets 1000,24,32,0.1 \
  --plain
```

With configuration file:

```bash
docker run \
  -v /etc/cidrx:/config \
  -v /var/log:/logs \
  cidrx static --config /config/cidrx.toml --plain
```

See [Docker Testing Guide]({{< relref "/docs/guides/docker-testing/" >}}) for the full test environment.

## Development Setup

Working on cidrx itself? The [Developer Guide]({{< relref "/docs/contributing/developer-guide/" >}}) covers dependencies, tests, static analysis, and benchmarks.

## File Permissions

cidrx needs read access to log files and write access to jail/ban files:

```bash
sudo mkdir -p /etc/cidrx /var/lib/cidrx
sudo usermod -a -G adm cidrx-user
sudo chown cidrx-user:cidrx-user /var/lib/cidrx
```

## Platform Notes

- **Linux**: No special considerations. cidrx is optimized for Linux.
- **macOS**: Works without issues. Use `brew install go` if needed.
- **Windows**: Use WSL2 for best compatibility.

## Troubleshooting

**`go: command not found`** - Install Go from https://golang.org/dl/

**`package X is not in GOROOT`** - Run `go mod download` to fetch dependencies.

**`permission denied` reading logs** - Add your user to the `adm` group: `sudo usermod -a -G adm $USER`

**Cannot create jail file** - Ensure the directory exists and is writable.

## Next Steps

Head over to the [Quick Start]({{< relref "/docs/getting-started/quick-start/" >}}) to run your first analysis. For production deployment, see the [Live Protection Guide]({{< relref "/docs/guides/live-protection/" >}}).
