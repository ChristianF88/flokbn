---
title: "Log Formats"
description: "Log format specifiers for parsing HTTP access logs"
summary: "Complete reference for flokbn log format specifiers and common format patterns"
date: 2025-10-09T10:00:00+00:00
lastmod: 2026-06-18T10:00:00+00:00
draft: false
weight: 230
slug: "log-formats"
toc: true
seo:
  title: "flokbn Log Format Reference"
  description: "Learn how to configure flokbn to parse Apache, Nginx, and custom log formats"
  canonical: ""
  noindex: false
---

flokbn parses HTTP access logs using a format string that maps log fields to specifiers.

Format strings apply to **static mode only**. Live mode parses incoming events with a fixed combined-log layout (client IP as the first field) - see the [Live Protection Guide]({{< relref "/docs/guides/live-protection/" >}}).

## Format Specifiers

| Specifier | Description | Example Value | Required |
|-----------|-------------|---------------|----------|
| `%h` | IP address | `192.0.2.1` | **Yes** (exactly one) |
| `%t` | Timestamp | `09/Oct/2025:10:15:23 +0000` | No |
| `%r` | Request line (method + URI + protocol) | `GET /index.html HTTP/1.1` | No |
| `%m` | HTTP method (standalone) | `GET` | No |
| `%U` | URI path (standalone) | `/index.html` | No |
| `%s` | HTTP status code | `200` | No |
| `%b` | Response bytes | `1234` | No |
| `%u` | User-Agent | `Mozilla/5.0...` | No |
| `%^` | Skip field (any value) | *(ignored)* | No (unlimited) |

**Constraints**: Exactly one `%h` is required. Each field specifier may appear at most once (e.g., two `%t` fields are not allowed); only `%^` (skip) may repeat. IPv4 only.

## Common Formats

### Nginx Combined (default)

```nginx
# nginx.conf
log_format combined '$remote_addr - $remote_user [$time_local] '
                    '"$request" $status $body_bytes_sent '
                    '"$http_referer" "$http_user_agent"';
```

```
--logFormat "%h %^ %^ [%t] \"%r\" %s %b \"%^\" \"%u\""
```

### Nginx with X-Forwarded-For

When a reverse proxy logs the real client IP in a trailing field:

```nginx
log_format proxy '$remote_addr $http_x_forwarded_for - [$time_local] '
                 '"$request" $status $body_bytes_sent '
                 '"$http_referer" "$http_user_agent" "$http_x_real_ip"';
```

Place `%h` at the position of the real client IP:

```
--logFormat "%^ %^ %^ [%t] \"%r\" %s %b \"%^\" \"%u\" \"%h\""
```

This is the compiled-in default format.

#### Address lists (X-Forwarded-For)

If the field behind `%h` holds a comma-separated list, as `$http_x_forwarded_for` does (`"198.51.100.1, 203.0.113.7"`), flokbn uses the **rightmost** address. Each proxy appends the address it received the connection from, so the last element is the one written by the proxy next to the logging server. Everything to its left arrived inside the request and is whatever the client chose to send. If the rightmost element is not an IPv4 address (`unknown`, IPv6, empty), the line counts as an invalid IP; flokbn never falls back to an element further left.

{{< callout context="caution" title="Only trust what your own proxy wrote" icon="outline/alert-triangle" >}}
A forwarded address is only as trustworthy as the proxy that wrote it. Point `%h` at such a field only when **all** of these hold:

- the logging server is reachable solely through your own proxy, so no client can send the header directly;
- that proxy appends the peer address itself (nginx: `proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;`) or overwrites the header;
- there is exactly one such proxy in front of the logging server. With a chain of your own proxies the rightmost element is the previous proxy, not the client.

When in doubt, log a field your server derives itself (nginx `$remote_addr`, or `$realip_remote_addr` with the realip module restricted by `set_real_ip_from`) and use that for `%h`. Otherwise a client can put any address into the header and get it banned.
{{< /callout >}}

### Apache Combined

```apache
LogFormat "%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-agent}i\"" combined
```

```
--logFormat "%h %^ %^ [%t] \"%r\" %s %b \"%^\" \"%u\""
```

### Apache Common (no User-Agent)

```apache
LogFormat "%h %l %u %t \"%r\" %>s %b" common
```

```
--logFormat "%h %^ %^ [%t] \"%r\" %s %b"
```

### Nginx Behind CloudFlare

```
--logFormat "%^ %h %^ [%t] \"%r\" %s %b \"%^\" \"%u\""
```

### Apache Behind AWS ALB

```
--logFormat "%^ %h %^ %^ [%t] \"%r\" %s %b"
```

### Custom Pipe-Delimited

Log: `192.0.2.1|09/Oct/2025:10:15:23|GET|/index.html|200`

```
--logFormat "%h|[%t]|%m|%U|%s"
```

### Syslog Prefix

Log: `Oct  9 10:15:23 webserver nginx: 192.0.2.1 - - [09/Oct/2025:10:15:23] "GET /" 200`

```
--logFormat "%^ %^ %^ %^ %^ %h %^ %^ [%t] \"%r\" %s"
```

## Field Details

### IP Address (%h)

A dotted IPv4 address with four octets of one to three digits each, every octet at most 255. Anything else (`1.2..34`, `1.2.34.`, IPv6, a hostname, `-`) is counted under `skipped_invalid_ips` and reported in the `invalid_ips_skipped` warning; it is never repaired into an address.

### Timestamp (%t)

Expected format: `DD/MMM/YYYY:HH:MM:SS ±ZZZZ`

Months: Jan, Feb, Mar, Apr, May, Jun, Jul, Aug, Sep, Oct, Nov, Dec. Timezone is optional.

The value is validated, not guessed: every digit position must hold a digit and the date and time must exist (`31/Apr`, `29/Feb` outside a leap year, hour `24`, minute or second `60` are rejected). A line with an invalid timestamp is kept but carries no timestamp: it sorts before every real time, so a trie with a `startTime` excludes it (a trie with only an `endTime` does not).

**Timezone handling is identical in both modes.** When the `±ZZZZ` offset is present (a 26-byte field like `06/Jul/2025:19:57:26 +0200`), both the static parser and live mode parse it and the timestamp is the true instant it denotes. When the offset is absent (a 20-byte field like `06/Jul/2025:19:57:26`), both modes treat the wall-clock as **UTC**. So static and live agree byte-for-byte on the same line. Practical rule: an offset-less log is interpreted as UTC, so keep offset-less timestamps and your `--startTime`/`--endTime` values both in UTC, or include the `±ZZZZ` offset in your log so the instant is unambiguous.

Include surrounding brackets in the format string if present in the log:

```
[%t]   # log has: [09/Oct/2025:10:15:23 +0000]
%t     # log has: 09/Oct/2025:10:15:23
```

### Request Line (%r)

Extracts method, URI path, and HTTP version from a combined field like `"GET /index.html HTTP/1.1"`. Use `%m` and `%U` instead when method and URI are in separate fields.

### User-Agent (%u)

Parses the User-Agent string. Must be quoted in the format string if quoted in the log.

### Skip Field (%^)

Use `%^` for any field you don't need. Can appear unlimited times.

Write `\"%^\"` for a field the log quotes (the Referer in a combined log) so the format documents the real layout. As a safety net, a value that starts with a double quote is always read up to its closing quote, even when the format leaves that slot bare: a Referer such as `"http://a b"` is one field, never two. Without that rule a space inside a quoted, client-controlled field would shift every later field and a client could choose the address that `%h` reads.

## Format String Rules

1. **Whitespace** in the format string must match whitespace in the log
2. **Quotes** in the format string must match quotes in the log (`\"%r\"` for `"GET /"`, `\"%^\"` for a quoted field you skip)
3. **Brackets** must be included if present (`[%t]` for `[timestamp]`)
4. **Delimiters** must match (spaces, pipes, etc.)

## Testing Your Format

```bash
# Create a one-line test file
echo '192.0.2.1 - - [09/Oct/2025:10:15:23 +0000] "GET / HTTP/1.1" 200 1234 "-" "curl"' > test.log

# Test parsing
flokbn static --logfile test.log \
  --logFormat "%h %^ %^ [%t] \"%r\" %s %b \"%^\" \"%u\"" \
  --clusterArgSets 1,32,32,0.01 \
  --plain
```

If parsing succeeds, you'll see `Total Requests: 1` in the output.

### Debugging Tips

1. Start with the minimal format `"%h"` and add fields incrementally
2. Count the fields in a sample log line and match with specifiers
3. Verify quotes and brackets match exactly

## TOML Configuration

In TOML, specify the format in the `[static]` section:

```toml
[static]
logFile = "/var/log/nginx/access.log"
logFormat = "%h %^ %^ [%t] \"%r\" %s %b \"%^\" \"%u\""
```

## Performance

Simpler formats parse marginally faster. The difference is usually <5% unless processing 10M+ requests. Only extract fields you actually filter on.
