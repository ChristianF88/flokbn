# flokbn Configuration Guide

Complete reference for flokbn configuration options, both CLI and TOML file formats.

## Configuration Methods

flokbn supports two configuration approaches:

1. **CLI Flags**: For quick one-off analysis
2. **TOML Config File**: For complex setups with multiple tries

**Note**: `--config` is mostly exclusive with individual flags, but a few output/log flags may be combined with it. In static mode, only `--tui`, `--compact`, and `--plain` are allowed alongside `--config`; in live mode, only `--logLevel` is. All other per-run flags are rejected when `--config` is used.

## CLI Configuration

### Static Mode CLI

Analyze historical log files.

#### Core Options

```bash
--config value          # Path to TOML config file (exclusive with other flags)
--logfile value         # Path to log file (required if not using --config)
--logFormat value       # Log format string (default: "%^ %^ %^ [%t] \"%r\" %s %b %^ \"%u\" \"%h\"")
```

#### Clustering Options

```bash
--clusterArgSets value  # Clustering parameters (repeatable)
                        # Format: minClusterSize,minDepth,maxDepth,meanSubnetDifference
                        # Example: --clusterArgSets 1000,24,32,0.1
```

#### Time Filtering

```bash
--startTime value       # Start time for analysis
                        # Formats: YYYY-MM-DD, YYYY-MM-DD HH, YYYY-MM-DD HH:MM
                        # Example: --startTime "2025-01-15 10:00"

--endTime value         # End time for analysis
                        # Same formats as startTime
```

#### Pattern Filtering

```bash
--useragentRegex value  # Filter by User-Agent regex
                        # Example: --useragentRegex ".*bot.*|.*scanner.*"

--endpointRegex value   # Filter by endpoint regex
                        # Example: --endpointRegex "/api/.*"

--rangesCidr value      # Analyze specific CIDR ranges (repeatable)
                        # Example: --rangesCidr "203.0.113.0/24"
```

#### Whitelist/Blacklist

```bash
--whitelist value               # IP/CIDR whitelist file (never banned)
--blacklist value               # IP/CIDR blacklist file (always banned)
--userAgentWhitelist value      # User-Agent whitelist patterns
--userAgentBlacklist value      # User-Agent blacklist patterns
```

#### Jail Management

```bash
--jailFile value        # Jail state persistence file
                        # Example: --jailFile /tmp/jail.json

--banFile value         # Ban list output file
                        # Example: --banFile /tmp/ban.txt
```

#### Output Options

```bash
--plotPath value        # Heatmap HTML output path
                        # Example: --plotPath /tmp/heatmap.html

--compact               # Output compact JSON (default: false)
--plain                 # Output plain text format (default: false)
--tui                   # Launch interactive TUI mode (default: false)
```

#### Complete Static Mode Example

```bash
./flokbn static \
  --logfile /var/log/nginx/access.log \
  --logFormat "%^ %^ %^ [%t] \"%r\" %s %b %^ \"%u\" \"%h\"" \
  --startTime "2025-01-15" \
  --endTime "2025-01-15 23:59" \
  --clusterArgSets 1000,24,32,0.1 \
  --clusterArgSets 5000,20,28,0.2 \
  --clusterArgSets 10000,16,24,0.3 \
  --useragentRegex ".*bot.*|.*scanner.*" \
  --endpointRegex "/api/.*" \
  --rangesCidr "203.0.113.0/24" \
  --rangesCidr "198.51.100.0/24" \
  --whitelist /etc/flokbn/whitelist.txt \
  --blacklist /etc/flokbn/blacklist.txt \
  --userAgentWhitelist /etc/flokbn/ua_whitelist.txt \
  --userAgentBlacklist /etc/flokbn/ua_blacklist.txt \
  --jailFile /tmp/jail.json \
  --banFile /tmp/ban.txt \
  --plotPath /tmp/heatmap.html \
  --plain
```

### Live Mode CLI

Real-time traffic analysis with automatic banning.

#### Core Options

```bash
--config value          # Path to TOML config file (exclusive with other flags)
--port value            # Port to listen on (required if not using --config)
```

#### Sliding Window Options

```bash
--slidingWindowMaxTime value        # Maximum time duration for sliding window
                                    # Format: duration string (e.g., "2h", "30m", "1h30m")
                                    # Default: 2h0m0s

--slidingWindowMaxSize value        # Maximum number of requests in window
                                    # Default: 100000

--sleepBetweenIterations value      # Sleep duration between iterations (seconds)
                                    # Default: 10
```

#### Clustering Options

```bash
--clusterArgSet value   # Clustering parameters (repeatable)
                        # Format: minClusterSize,minDepth,maxDepth,meanSubnetDifference
                        # Example: --clusterArgSet 1000,24,32,0.1
```

#### Pattern Filtering

```bash
--useragentRegex value  # Filter by User-Agent regex
--endpointRegex value   # Filter by endpoint regex
```

#### Whitelist/Blacklist

```bash
--whitelist value               # IP/CIDR whitelist file
--blacklist value               # IP/CIDR blacklist file
--userAgentWhitelist value      # User-Agent whitelist patterns
--userAgentBlacklist value      # User-Agent blacklist patterns
```

#### Jail Management

```bash
--jailFile value        # Jail state persistence file (required)
--banFile value         # Ban list output file (required)
```

#### Complete Live Mode Example

```bash
./flokbn live \
  --port 8080 \
  --slidingWindowMaxTime 2h \
  --slidingWindowMaxSize 100000 \
  --sleepBetweenIterations 10 \
  --clusterArgSet 1000,24,32,0.1 \
  --clusterArgSet 5000,20,28,0.2 \
  --useragentRegex ".*scanner.*" \
  --endpointRegex "/admin.*" \
  --whitelist /etc/flokbn/whitelist.txt \
  --blacklist /etc/flokbn/blacklist.txt \
  --jailFile /tmp/jail.json \
  --banFile /tmp/ban.txt
```

## TOML Configuration File

For complex setups with multiple tries, use TOML configuration.

### File Structure

```toml
[global]          # Global settings (required for live mode, optional for static mode)
[static]          # Static mode settings (optional)
[live]            # Live mode settings (optional)
[static.NAME]     # Named static analysis trie (repeatable)
[live.NAME]       # Named live sliding window (repeatable)
```

### Global Configuration

Required for live mode. Optional for static mode.

```toml
[global]
# Jail and ban file paths (required)
jailFile = "/tmp/flokbn_jail.json"
banFile = "/tmp/flokbn_ban.txt"

# Optional whitelist/blacklist files
whitelist = "/etc/flokbn/whitelist.txt"
blacklist = "/etc/flokbn/blacklist.txt"
userAgentWhitelist = "/etc/flokbn/ua_whitelist.txt"
userAgentBlacklist = "/etc/flokbn/ua_blacklist.txt"
```

### Static Mode Configuration

#### Base Static Config

```toml
[static]
logFile = "/var/log/nginx/access.log"
logFormat = "%^ %^ %^ [%t] \"%r\" %s %b %^ \"%u\" \"%h\""
plotPath = "/tmp/heatmap.html"  # Optional
```

#### Static Analysis Tries

Each `[static.NAME]` section creates an independent trie.

```toml
[static.trie_name]
# Optional: Time range filtering
startTime = "2025-01-15T00:00:00Z"
endTime = "2025-01-15T23:59:59Z"

# Optional: Pattern filtering
useragentRegex = ".*bot.*|.*scanner.*"
endpointRegex = "/api/.*"

# Optional: CIDR range analysis
cidrRanges = ["203.0.113.0/24", "198.51.100.0/24"]

# Optional: Clustering parameters (array of arrays)
# Format: [minClusterSize, minDepth, maxDepth, meanSubnetDifference]
clusterArgSets = [
    [1000, 24, 32, 0.1],
    [5000, 20, 28, 0.2],
    [10000, 16, 24, 0.3]
]

# Optional: Jail usage flags (one per clusterArgSet)
# true = add detected CIDRs to jail, false = report only
useForJail = [true, true, false]
```

#### Complete Static Example

```toml
[global]
jailFile = "/tmp/jail.json"
banFile = "/tmp/ban.txt"
whitelist = "/etc/flokbn/whitelist.txt"

[static]
logFile = "/var/log/nginx/access.log"
logFormat = "%^ %^ %^ [%t] \"%r\" %s %b %^ \"%u\" \"%h\""
plotPath = "/tmp/heatmap.html"

[static.comprehensive_scan]
cidrRanges = ["203.0.113.0/24", "198.51.100.0/24"]
clusterArgSets = [
    [1000, 24, 32, 0.1],
    [5000, 20, 28, 0.2]
]
useForJail = [true, true]

[static.security_scanners]
useragentRegex = ".*scanner.*|.*nikto.*|.*sqlmap.*"
clusterArgSets = [[100, 30, 32, 0.05]]
useForJail = [true]

[static.admin_attacks]
endpointRegex = "/admin.*|/wp-admin.*|/phpmyadmin.*"
startTime = "2025-01-15T00:00:00Z"
endTime = "2025-01-15T23:59:59Z"
clusterArgSets = [[50, 32, 32, 0.1]]
useForJail = [true]

[static.api_abuse]
endpointRegex = "/api/.*"
clusterArgSets = [
    [500, 28, 32, 0.1],
    [2000, 24, 28, 0.2]
]
useForJail = [true, false]
```

### Live Mode Configuration

#### Base Live Config

```toml
[live]
port = "8080"        # Required: Port to listen on
readTimeout = "5s"   # Optional: TCP read timeout (duration string, default "5s")
```

#### Live Sliding Windows

Each `[live.NAME]` section creates an independent sliding window with its own trie.

```toml
[live.window_name]
# Required: Sliding window parameters
slidingWindowMaxTime = "2h"      # Duration string: "1h", "30m", "2h30m"
slidingWindowMaxSize = 100000    # Maximum requests in window
sleepBetweenIterations = 10      # Seconds between analysis cycles

# Optional: Pattern filtering
useragentRegex = ".*bot.*"
endpointRegex = "/api/.*"

# Required: Clustering parameters (array of arrays)
clusterArgSets = [
    [1000, 24, 32, 0.1],
    [5000, 20, 28, 0.2]
]

# Required: Jail usage flags (one per clusterArgSet)
useForJail = [true, true]
```

#### Complete Live Example

```toml
[global]
jailFile = "/data/jail.json"
banFile = "/data/ban.txt"
whitelist = "/etc/flokbn/whitelist.txt"

[live]
port = "8080"

[live.realtime_protection]
# General protection with 2-hour window
slidingWindowMaxTime = "2h"
slidingWindowMaxSize = 100000
sleepBetweenIterations = 10
clusterArgSets = [
    [1000, 24, 32, 0.1],
    [5000, 20, 28, 0.2]
]
useForJail = [true, true]

[live.scanner_detection]
# Fast scanner detection with 1-hour window
slidingWindowMaxTime = "1h"
slidingWindowMaxSize = 50000
sleepBetweenIterations = 5
useragentRegex = ".*scanner.*|.*bot.*|.*crawler.*"
clusterArgSets = [[100, 30, 32, 0.05]]
useForJail = [true]

[live.api_protection]
# API-specific protection with 30-minute window
slidingWindowMaxTime = "30m"
slidingWindowMaxSize = 20000
sleepBetweenIterations = 3
endpointRegex = "/api/.*"
clusterArgSets = [
    [200, 28, 32, 0.1],
    [1000, 24, 28, 0.2]
]
useForJail = [true, false]

[live.admin_protection]
# Admin panel protection with aggressive detection
slidingWindowMaxTime = "15m"
slidingWindowMaxSize = 5000
sleepBetweenIterations = 2
endpointRegex = "/admin.*|/wp-admin.*"
clusterArgSets = [[10, 32, 32, 0.05]]
useForJail = [true]
```

## Clustering Parameters

Understanding the clustering parameter format: `[minClusterSize, minDepth, maxDepth, meanSubnetDifference]`

### Parameters Explained

1. **minClusterSize** (uint32): Minimum number of IPs to form a cluster
   - Larger = fewer, larger clusters
   - Smaller = more, smaller clusters
   - Example: 1000 = need at least 1000 IPs to detect

2. **minDepth** (uint32): Minimum CIDR prefix length to consider
   - Range: 0-32
   - Smaller = larger network ranges
   - Example: 24 = /24 networks (256 IPs) minimum

3. **maxDepth** (uint32): Maximum CIDR prefix length to consider
   - Range: 0-32
   - Larger = smaller network ranges
   - Example: 32 = /32 (single IP) maximum

4. **meanSubnetDifference** (float64): Clustering threshold
   - Range: 0.0-1.0
   - Lower = more aggressive clustering (more sensitive)
   - Higher = less aggressive clustering (less sensitive)
   - Example: 0.1 = tight clustering, 0.3 = loose clustering

### Common Clustering Configurations

```toml
# Large botnets (10,000+ IPs from /16-/24 ranges)
clusterArgSets = [[10000, 16, 24, 0.2]]

# Medium attacks (1,000+ IPs from /24-/32 ranges)
clusterArgSets = [[1000, 24, 32, 0.1]]

# Small coordinated attacks (100+ IPs)
clusterArgSets = [[100, 28, 32, 0.05]]

# Scanner detection (even single IPs)
clusterArgSets = [[1, 32, 32, 0.05]]

# Multi-tier detection (combine multiple configurations)
clusterArgSets = [
    [10000, 16, 24, 0.3],  # Large networks
    [1000, 24, 28, 0.2],   # Medium networks
    [100, 28, 32, 0.1]     # Small clusters
]
```

## Whitelist/Blacklist Files

### IP/CIDR Format

```
# Comments start with #, on their own line or trailing a CIDR.
# A trailing inline # comment is stripped; the bare CIDR before it is loaded.

# Internal network
192.168.0.0/16
10.0.0.0/8        # Private network
203.0.113.42/32   # Specific IP
```

### User-Agent Whitelist/Blacklist Files (Exact Match)

User-Agent whitelist/blacklist files are matched by **case-insensitive full-string equality** (not substrings, not regex). Each line is a complete User-Agent header value. Comments start with `#`, on their own line or trailing a value, and a trailing `#...` is stripped from the value before matching. Because the first `#` ends the value, a User-Agent that itself contains a literal `#` cannot be listed here — match it with the per-trie `--useragentRegex` flag (or the `useragentRegex` config key) instead, which is the actual regex mechanism.

```
# Legitimate crawlers (whitelist) - exact full User-Agent strings
Googlebot/2.1 (+http://www.google.com/bot.html)
Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)

# Security scanners (blacklist) - exact full User-Agent strings
sqlmap/1.7.2 (https://sqlmap.org)
Mozilla/5.00 (Nikto/2.1.6) (Evasions:None) (Test:Port Check)   # web scanner
```

## Log Format Configuration

Default log format for Apache/Nginx combined logs:

```
%^ %^ %^ [%t] "%r" %s %b %^ "%u" "%h"
```

### Format Specifiers

- `%h` - IP address (required, exactly one)
- `%t` - Timestamp [DD/MMM/YYYY:HH:MM:SS +ZZZZ]
- `%r` - Request line "METHOD URI VERSION"
- `%m` - HTTP method (standalone)
- `%U` - URI path (standalone)
- `%s` - HTTP status code
- `%b` - Response bytes
- `%u` - User-Agent string
- `%^` - Skip field (unlimited)

### Common Log Formats

```bash
# Apache Combined with X-Forwarded-For
--logFormat "%^ %^ %^ [%t] \"%r\" %s %b %^ \"%u\" \"%h\""

# Standard Apache Combined
--logFormat "%h %^ %^ [%t] \"%r\" %s %b %^ \"%u\""

# Nginx Access Log
--logFormat "%h %^ %^ [%t] \"%r\" %s %b %^ \"%u\""

# Custom with standalone method/URI
--logFormat "%h [%t] %m %U %^ %s %b"
```

## Usage Examples

### Quick Analysis

```bash
./flokbn static \
  --logfile /var/log/nginx/access.log \
  --clusterArgSets 1000,24,32,0.1 \
  --plain
```

### Time-Bounded Analysis

```bash
./flokbn static \
  --logfile access.log \
  --startTime "2025-01-15 10:00" \
  --endTime "2025-01-15 14:00" \
  --clusterArgSets 500,28,32,0.1 \
  --plain
```

### Scanner Detection

```bash
./flokbn static \
  --logfile access.log \
  --useragentRegex ".*scanner.*|.*nikto.*" \
  --clusterArgSets 100,30,32,0.05 \
  --jailFile /tmp/jail.json \
  --banFile /tmp/ban.txt \
  --plain
```

### Multi-Trie Analysis with Config

```bash
./flokbn static --config /etc/flokbn/production.toml --plain
```

### Live Mode with Config

```bash
./flokbn live --config /etc/flokbn/live.toml
```

## Best Practices

1. **Start with config files** for production deployments
2. **Use multiple clusterArgSets** for different threat sizes
3. **Set useForJail=[false]** for experimental detection rules
4. **Use whitelist files** to prevent blocking legitimate traffic
5. **Monitor jail.json** to understand ban progression
6. **Use plain text output** during testing for readability
7. **Enable TUI mode** for interactive analysis
8. **Test regex patterns** before deploying to live mode
