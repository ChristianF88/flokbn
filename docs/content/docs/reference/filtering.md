---
title: "Filtering"
description: "Whitelist, blacklist, regex, and time-based filtering"
summary: "Complete reference for all flokbn filtering mechanisms and file formats"
date: 2025-10-09T10:00:00+00:00
lastmod: 2026-06-11T10:00:00+00:00
draft: false
weight: 250
slug: "filtering"
toc: true
seo:
  title: "flokbn Filtering Reference"
  description: "Learn how to configure flokbn filtering with whitelists, blacklists, and regex patterns"
  canonical: ""
  noindex: false
---

flokbn filters traffic in two distinct layers: **per-request filters** decide which requests enter the analysis (trie/window), and **ban-pipeline filters** shape what the detections turn into bans.

## How the Filters Compose

Per-request, before a request enters analysis:

1. **Time window** - requests outside startTime/endTime are dropped
2. **User-Agent regex / Endpoint regex** - only matching requests are analyzed
3. **User-Agent whitelist** - matching requests are excluded from analysis, and their source IPs are immunized against bans
4. **User-Agent blacklist** - matching requests mark their source IP for force-jailing (the request itself is still analyzed)

In the ban pipeline, after clustering:

5. **IP whitelist** - detected CIDRs covered by a whitelist entry are removed before they reach the jail, and the whitelist is subtracted again from everything published (ban file, `/bans`)
6. **IP blacklist** - manual always-ban CIDRs, appended to the published ban list

CIDR ranges (`cidrRanges` / `--rangesCidr`) are **not** a filter in either layer - they only add [per-range request counts](#cidr-range-reporting) to the report.

**The whitelist always wins**: over detections, over active bans, and over the manual blacklist.

## IP Whitelist

Whitelisted CIDRs can never be banned. The whitelist is applied to detected clusters before the jail update and subtracted from every published ban list - it does not exclude the traffic from analysis or statistics.

All list files (IP and User-Agent, whitelist and blacklist) are loaded **once at startup**. In live mode, restart flokbn to pick up edits; a malformed list file fails loudly at startup rather than silently banning protected ranges.

### File Format

One CIDR per line. Comments with `#`. Blank lines ignored.

```
# /etc/flokbn/whitelist.txt

# Internal networks
10.0.0.0/8
172.16.0.0/12
192.168.0.0/16

# Office networks
192.0.2.0/24

# CDN providers - copy your CDN's published ranges here

# Monitoring services
198.51.100.50/32    # uptime checker
198.51.100.51/32    # status-page probe
```

### Usage

TOML:
```toml
[global]
whitelist = "/etc/flokbn/whitelist.txt"
```

CLI:
```bash
--whitelist /etc/flokbn/whitelist.txt
```

## IP Blacklist

Blacklisted CIDRs are **always banned**: they are appended to the published ban list regardless of detection results. The blacklist does not restrict which traffic is analyzed.

### File Format

Same format as whitelist:

```
# /etc/flokbn/blacklist.txt

# Known abusive ranges
203.0.113.0/25

# Confirmed IPs
203.0.113.200/32
```

### Combined Usage

Whitelist and blacklist can be used together. The whitelist wins: any blacklist entry covered by a whitelist entry is dropped from the published ban list.

## User-Agent Whitelist

Requests whose User-Agent is listed are excluded from analysis, and their source IPs are immunized against bans. Matching is a **case-insensitive exact match** of the full User-Agent string (not substring, not regex).

### File Format

One **full User-Agent string** per line (the exact value the client sends). Comments with `#`. Blank lines ignored.

```
# /etc/flokbn/ua_whitelist.txt

# Search engine bots (full UA strings as sent by the client)
Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)
Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)

# Monitoring and uptime
Mozilla/5.0+(compatible; UptimeRobot/2.0; http://www.uptimerobot.com/)
```

A request is excluded if its User-Agent **exactly equals** a listed string (case-insensitive). For partial matches use `--useragentRegex` instead.

## User-Agent Blacklist

Requests whose User-Agent is listed get their source IP **force-jailed** as a /32 - no clustering threshold needs to be met. Matching is the same **case-insensitive exact match** of the full User-Agent string. If the same string appears in both lists, the whitelist wins.

### File Format

```
# /etc/flokbn/ua_blacklist.txt

# Exact UA strings of tools you always want banned
sqlmap/1.7.2#stable (http://sqlmap.org)
curl/8.5.0
python-requests/2.31.0
Go-http-client/1.1
```

## User-Agent Regex

Pattern-based filtering using Go regex (RE2 syntax).

### Usage

TOML (per-trie):
```toml
[static.user_agent_filter]
useragentRegex = ".*bot.*"
```

CLI:
```bash
--useragentRegex ".*bot.*|.*scanner.*"
```

### Common Patterns

```
".*bot.*"                                  # Any bot
"curl|wget|python-requests"               # Generic tools
"(?i).*scanner.*"                          # Case insensitive
"python-(requests|urllib)"                 # Grouped alternation
```

### Regex Syntax (RE2)

`.` any character, `*` zero or more, `+` one or more, `?` zero or one, `|` OR, `()` grouping, `[]` character class, `\\` escape, `(?i)` case insensitive.

### Required-Literal Prefilter

flokbn automatically derives the literals a regex *must* contain (e.g. `bot` from `.*bot.*`, or `curl`/`wget` from `curl|wget`) and screens each input with fast substring checks before running the full regex engine. Semantics are unchanged - the prefilter only skips inputs the regex would reject anyway - but patterns with distinctive required literals filter large logs considerably faster. Patterns without any required literal (e.g. `.*`) fall back to running the regex directly.

## Endpoint Regex

Filter by URL path pattern. Same RE2 syntax.

### Usage

TOML:
```toml
[static.api_abuse]
endpointRegex = "/api/.*"
```

CLI:
```bash
--endpointRegex "/api/.*"
```

### Common Patterns

```
"/api/.*"                              # All API endpoints
"/admin/.*|/wp-admin/.*"               # Admin panels
"/login|/signin|/auth"                 # Login pages
"/api/v1/(login|auth|register)"        # Specific API routes
".*\\.php|.*\\.asp"                    # Script extensions
"/api/.*|/admin/.*|/login"             # Combined
```

## Time Window

Filter requests by timestamp range.

### CLI Format

Flexible format: `YYYY-MM-DD`, `YYYY-MM-DD HH`, or `YYYY-MM-DD HH:MM`.

```bash
--startTime "2025-01-15 14:00" --endTime "2025-01-15 16:00"
--startTime "2025-01-15"       --endTime "2025-01-15 23:59"
```

### TOML Format

RFC3339:

```toml
startTime = "2025-01-15T14:00:00Z"
endTime = "2025-01-15T16:00:00Z"
```

## CIDR Range Reporting

Report request counts for specific networks. This is a **reporting feature, not a filter**: every range listed gets its own request count and traffic share in the output, while the analysis - including clustering - still sees all traffic.

TOML:
```toml
cidrRanges = ["203.0.113.0/24", "198.51.100.0/24"]
```

CLI:
```bash
--rangesCidr "203.0.113.0/24" --rangesCidr "198.51.100.0/24"
```

Useful for keeping an eye on known problematic ASNs or following up on previously detected ranges.

## Combining Filters

### Exclude Legitimate, Detect Everything

```toml
[global]
whitelist = "/etc/flokbn/whitelist.txt"
userAgentWhitelist = "/etc/flokbn/ua_whitelist.txt"

[static.general]
clusterArgSets = [[1000, 24, 32, 0.1]]
useForJail = [true]
```

### Filter by User-Agent Pattern

```toml
[static.ua_filter]
useragentRegex = ".*bot.*"
clusterArgSets = [[100, 30, 32, 0.05]]
useForJail = [true]

[static.endpoint_filter]
endpointRegex = "/login|/wp-login\\.php"
clusterArgSets = [[50, 30, 32, 0.05]]
useForJail = [true]
```

### Tiered Analysis

```toml
[static.tier1_large]
clusterArgSets = [[10000, 16, 24, 0.3]]
useForJail = [true]

[static.tier2_medium]
clusterArgSets = [[1000, 24, 28, 0.1]]
useForJail = [true]

[static.tier3_focused]
useragentRegex = ".*bot.*"
clusterArgSets = [[100, 30, 32, 0.05]]
useForJail = [true]
```

## Performance Tips

- Prefer regex patterns with distinctive required literals (`sqlmap|nikto` over `.*`) so the prefilter can skip the regex engine for most lines.
- Use User-Agent whitelist/blacklist files instead of regex when matching exact strings - the exact matcher is a single O(1) map lookup.
- Regex patterns are compiled once at startup (per trie/window), never per line.

## Troubleshooting

**No results**: Filters may be too restrictive. Run without filters first, then add one at a time.

**Too many results**: Add a whitelist, increase cluster thresholds, or use more specific regex.

**Regex not matching**: Test with `echo "User-Agent string" | grep -E "pattern"`. Check for case sensitivity (`(?i)` for case-insensitive).
