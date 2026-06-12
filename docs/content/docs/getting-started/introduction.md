---
title: "Introduction"
description: "Overview of cidrx - High-performance IP clustering and blacklist generation tool"
summary: "Learn what cidrx does, its key features, and how it groups IPs into CIDR ranges"
date: 2025-10-09T10:00:00+00:00
lastmod: 2025-11-26T10:00:00+00:00
draft: false
weight: 100
toc: true
seo:
  title: "Introduction to cidrx"
  description: "Discover cidrx - a high-performance tool for IP clustering and blacklist generation through intelligent log analysis"
  canonical: ""
  noindex: false
---

## What is cidrx?

cidrx is an IP clustering tool that analyzes HTTP logs and groups IP addresses into CIDR ranges for blacklist generation. Inspired by fail2ban.

## Key Features

- **Static Mode**: Analyze historical log files
- **Live Mode**: Real-time protection with automated banning
- **Automatic IP Clustering**: Groups IPs into CIDR ranges without manual configuration
- **Multi-Trie Detection**: Run multiple detection configurations simultaneously
- **Flexible Filtering**: Whitelist/blacklist support with regex-based User-Agent and endpoint filtering
- **Multiple Output Formats**: JSON, compact JSON, plain text, and interactive TUI

## How It Works

1. **Log Parsing**: Parses HTTP logs using configurable [format strings]({{< relref "/docs/reference/log-formats/" >}})
2. **Filtering**: Applies time-based, pattern-based, and list-based [filters]({{< relref "/docs/reference/filtering/" >}})
3. **Trie Building**: Constructs IP address tries for efficient clustering
4. **Cluster Detection**: Identifies CIDR ranges using configurable [parameters]({{< relref "/docs/reference/clustering/" >}})
5. **Jail Management**: Maintains persistent state of detected ranges

## Use Cases

- **Emergency Response**: Quickly identify and block high-volume networks
- **Real-Time Protection**: Continuous monitoring with automatic banning
- **Forensic Analysis**: Investigate specific time periods

## Limitations

- **IPv4 Only**: Currently only IPv4 addresses are supported. IPv6 is not implemented yet.
- **Lumberjack Protocol**: Live mode uses the Lumberjack protocol for log ingestion. HTTP/JSON API support is planned for future releases.
- **Fixed Live Log Layout**: Live mode expects the standard combined log format with the client IP as the first field. Configurable [format strings]({{< relref "/docs/reference/log-formats/" >}}) apply to static mode only.
- **Single IP Field**: Log format must contain exactly one `%h` (IP address) field. Multiple IP fields are not supported.
- **No Duplicate Fields**: Log format cannot contain duplicate field specifiers (e.g., two `%t` timestamp fields or two `%s` status fields).

## Next Steps

Ready to get started? Check out the [Installation Guide]({{< relref "/docs/getting-started/installation/" >}}) to install cidrx, or jump straight to the [Quick Start]({{< relref "/docs/getting-started/quick-start/" >}}) to see it in action.
