---
title: "Log Formats"
description: "Log format specifiers for parsing HTTP access logs"
summary: "Complete reference for flokbn log format specifiers and common format patterns"
date: 2025-10-09T10:00:00+00:00
lastmod: 2026-11-24T10:00:00+00:00
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

Format strings apply to **both modes**, and both compile them with the same parser: `static --logFormat` / `[static] logFormat` describes the lines of the log file, `live --logFormat` / `[live] logFormat` describes the `message` of each shipped event. The two modes have **different defaults** - see [Defaults](#defaults) - and live mode adds a few rules of its own, listed under [Live Mode](#live-mode).

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

**Filters need their field.** A filter that reads a field the format does not extract is rejected at startup, in both modes: `useragentRegex` and the User-Agent whitelist/blacklist need `%u`, `endpointRegex` needs `%r` or `%U`, `startTime`/`endTime` (static mode) need `%t`. Keep those specifiers in the format when you use the filter - see [Config File]({{< relref "/docs/reference/config-file/#validation-rules" >}}).

## Defaults

| Mode | Default format | Client IP read from |
|------|----------------|---------------------|
| `static` | `%^ %^ %^ [%t] "%r" %s %b "%^" "%u" "%h"` | the **last** field (a trailing, quoted `X-Forwarded-For` / real-IP field) |
| `live` | `%h %^ %^ [%t] "%r" %s %b "%^" "%u"` | the **first** field (plain combined log) |

The defaults differ for a historical reason that is also a practical one. Live mode has always read the first field: that is where a web server puts the client address, and Filebeat ships the line unchanged, so existing deployments keep working without a `logFormat`. Static mode was built around logs written behind a reverse proxy, with the real client in a trailing field.

The consequence: **a `logFormat` set for one mode does not apply to the other.** If static and live mode read the same log, set the same format string in both places (`[static] logFormat` and `[live] logFormat`). Read with the wrong default, a proxied log yields the proxy's address for every request - and flokbn would detect and ban your proxy.

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

Log: `192.0.2.1|[09/Oct/2025:10:15:23 +0000]|GET|/index.html|200`

```
--logFormat "%h|[%t]|%m|%U|%s"
```

The same works with any single-character delimiter (`,`, `;`, tab) and with quoted fields: `%h|\"%r\"|%s|\"%u\"` for `192.0.2.1|"GET / HTTP/1.1"|200|"curl/8"`. Two rules apply to delimiter-separated logs:

- A free-text value that is neither quoted nor bracketed (`%U`, `%u`, `%r`, `%t`, `%^`) runs to its delimiter, spaces included: `%h|%t|%U|%s` reads `192.0.2.1|09/Oct/2025:10:15:23 +0000|/a b|200` correctly in static mode. An address, a method, a status and a byte count (`%h`, `%m`, `%s`, `%b`) cannot contain a space and end at the delimiter **or at a space**. Live mode ends every bare value at the first space - see [Spaces in bare fields](#spaces-in-bare-fields).
- An empty value between two delimiters (`192.0.2.1||GET`) is one empty field.

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

The value is validated, not guessed: every digit position must hold a digit and the date and time must exist (`31/Apr`, `29/Feb` outside a leap year, hour `24`, minute or second `60` are rejected). In static mode a line with an invalid timestamp is kept but carries no timestamp: it sorts before every real time, so a trie with a `startTime` excludes it (a trie with only an `endTime` does not). In live mode such a line is dropped and counted as a parse error, because a sliding window cannot place it in time.

**Timezone handling is identical in both modes** - it is the same code. When the `±ZZZZ` offset is present (a 26-byte field like `06/Jul/2025:19:57:26 +0200`), the timestamp is the true instant it denotes. When the offset is absent (a 20-byte field like `06/Jul/2025:19:57:26`), or is not written as ` ±ZZZZ` directly behind the seconds, the wall-clock is read as **UTC**. Practical rule: an offset-less log is interpreted as UTC, so keep offset-less timestamps and your `--startTime`/`--endTime` values both in UTC, or include the `±ZZZZ` offset in your log so the instant is unambiguous.

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

## Spaces in bare fields

A *bare* field is one the format neither quotes nor brackets: `%^`, `%U`, `%s` as opposed to `\"%r\"` or `[%t]`. A bare value has no closing character, so it is read up to the next space. That is a problem when the value is free text chosen by the client. The standard example is the user name of the combined log format (`$remote_user`, Apache `%u`): it is whatever the client sent as its HTTP basic-auth name, spaces included. Read naively, `john doe` is two fields, every field behind it sits one slot off, and the line is either dropped as an invalid address or - worse - `%h` is read from a field the client also controls.

flokbn therefore lets **the literals of the format delimit the fields**. A space inside a bare field has no influence on the fields behind it when the format is *properly specified* for that field, which means that one of these follows it:

| What follows the bare field in the format | Example | How the end of the field is found |
|---|---|---|
| a bracketed timestamp | `%^ [%t]` | The timestamp is recognised by its content: the fields from `%t` on are read from the first `[...]` behind the field that holds a valid timestamp. |
| a quoted field | `%^ \"%r\"` | The quoted field starts at the next double quote that follows a space. |
| a bracketed timestamp, then a quoted field | `%^ [%t] \"%r\"` | Both of the above; in addition the timestamp used is the bracketed field directly in front of that quote, so a timestamp forged inside the user name is not taken. |
| a delimiter other than a space | `%U\|`, `%^,`, `[%^]`, the last field of a quoted group (`%^\"`) | The value runs to that delimiter (applies to the free-text specifiers `%^`, `%U`, `%u`, `%r`, `%t`). |

Both default formats are properly specified for the user name: it is followed by ` [%t] \"%r\"`.

The format is **inherently ambiguous** where a bare field is followed by a single space and another bare field - `%^ %^`, `%U %s`, `%^ %h`. Nothing in the format says which of the two a space belongs to, so there the first space ends the field, as it always has. In practice:

- In a run of bare fields in front of an anchor (`%h %^ %^ [%t]`), fields are counted from the left. A space in one of them shifts the *remaining fields of the same run* and nothing else. That is harmless when the client-controlled field is the last of the run (the user name is), and it is why `%h` belongs in front of a client-controlled bare field, never directly behind one.
- Bare fields behind the timestamp (`[%t] %m %U %s`) have no anchor in front of them. Quote them in the log, or separate them with a delimiter other than a space.

**What a client can still do** - none of this is specific to flokbn, but you should know it:

- **Servers that do not escape quotes.** Everything above assumes that a double quote written by a client arrives escaped in the log (nginx writes `\x22`, Apache `\"`; both are the default). With nginx `escape=none`, or a log written by an application that does not escape, a client can write quotes, and with them complete fake fields.
- **A bare field directly in front of a bare `%h`** (`%^ %h`), or any other ambiguous pair: the space shifts the second field. A shifted `%h` is not an address, so the line is counted under `skipped_invalid_ips` - the client is not detected.
- **A bare field behind the timestamp** (`[%t] %m`): a bracketed token in the user name (`a [x]`) is taken for the timestamp, and the line is shifted from there.
- **An unclosed bracket in the user name** (`a [`) swallows the real timestamp. The line keeps its address and all other fields but has no timestamp, like any line with an invalid one; a trie with a `startTime` excludes it.
- **Fewer fields than the format says** in front of the timestamp is a different log layout, not an attack; static mode does not guess it (live mode does, see below). Set a matching `logFormat`.
- A value the format quotes must be quoted in the log. A bare value in such a slot is still accepted where it always was (a bare `-` behind a status or byte count, for instance), but directly behind a bare free-text field or the timestamp it is taken for overflow of that field.

If you do not need the user name, the simplest protection is not to log it (nginx: write `-` instead of `$remote_user`), or to quote it in the log (`\"$remote_user\"`, `\"%^\"` in the format).

Lines that follow their format are parsed exactly as before and at the same speed; the rules above only come into play for a line that does not fit. Live mode implements the first rule only, see the next section.

## Live Mode

Live mode parses the `message` of every shipped event with its `logFormat` (default: client IP first, see [Defaults](#defaults)). On top of the rules above:

- **`%t` is required.** A sliding window is bounded in time; a format without `%t` is rejected at startup.
- **A line is dropped** (and counted in `ingest.parse_errors_total`) when its `%h` value is not a valid IPv4 address - this includes every IPv6 address and `0.0.0.0` - or when its timestamp is invalid. Everything else is kept: a truncated line or a non-numeric status still counts as a request from that address.
- **Re-alignment on the timestamp.** Fields are taken by position, so a space inside an unquoted field shifts every field behind it. In the combined log format the user name in front of the timestamp is such a field, and it is whatever the client sent as its HTTP basic-auth name. When the timestamp does not parse at its position and the format brackets it (`[%t]`), live mode takes the first `[...]` in the line that holds a valid timestamp as the `%t` field and reads the fields before and after it relative to that. A client therefore cannot keep its requests out of the window with a space in its user name. The same mechanism accepts lines with more or fewer fields in front of the timestamp than the format says - but set a matching `logFormat` rather than relying on it.

{{< callout context="caution" title="Unquoted free-text fields stay client-controlled" icon="outline/alert-triangle" >}}
Re-alignment cannot tell a forged timestamp from the real one: a client whose user name is itself a bracketed, valid, old timestamp gets its requests stamped with that time, and they expire from the window at once. If you do not need the user name in the log, drop it from the web server's log format (nginx: write `-` instead of `$remote_user`) or quote it (`"$remote_user"` with `\"%^\"` in the format); a quoted field cannot shift the others. Static mode re-aligns on the timestamp too, and has further rules that live mode lacks (it uses the timestamp directly in front of the quoted request, and it re-aligns on quotes and non-space delimiters) - see [Spaces in bare fields](#spaces-in-bare-fields).
{{< /callout >}}

```toml
[live]
port = "8080"
# client IP in a trailing forwarded field, as written behind a reverse proxy
logFormat = "%^ %^ %^ [%t] \"%r\" %s %b \"%^\" \"%u\" \"%h\""
```

## Lines

One request per line, terminated by `\n` or `\r\n`. The rules are the same for small and large files:

- **Blank lines** are skipped. They are not requests and are not counted as invalid.
- **Lines longer than 2 MiB** are skipped and reported in an `oversized_lines` warning; the rest of the file is analysed normally.
- A line whose `%h` field is not a valid IPv4 address is counted under `skipped_invalid_ips`.

## Format String Rules

1. **Whitespace** in the format string must match whitespace in the log
2. **Quotes** in the format string must match quotes in the log (`\"%r\"` for `"GET /"`, `\"%^\"` for a quoted field you skip)
3. **Brackets** must be included if present (`[%t]` for `[timestamp]`)
4. **Delimiters** must match (spaces, pipes, etc.)
5. **Quoted groups**: several fields inside one pair of quotes (`\"%^ %U %^\"` for `"GET /x HTTP/1.1"` when you want the path via `%U`) must begin with `%^` (it absorbs the opening quote) and be followed by a space. A group followed by another delimiter (`\"%^ %U %^\"|%s`) is rejected at startup; use `\"%r\"` there instead.
6. **Free-text bare fields need something behind them.** A bare field whose value the client chooses (the user name) should be followed by `[%t]`, a quoted field or a delimiter other than a space - see [Spaces in bare fields](#spaces-in-bare-fields).
7. **Literal words are not matched.** Only the specifiers and the single character after each one are compiled. A standalone word such as `- -` between specifiers is not consumed from the log, so write `%h %^ %^ [%t]`, not `%h - - [%t]`.

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

In TOML, specify the format in the `[static]` section (and, for live mode, separately in the `[live]` section - see [Live Mode](#live-mode)):

```toml
[static]
logFile = "/var/log/nginx/access.log"
logFormat = "%h %^ %^ [%t] \"%r\" %s %b \"%^\" \"%u\""
```

## Performance

Simpler formats parse marginally faster. The difference is usually <5% unless processing 10M+ requests. Only extract fields you actually filter on.
