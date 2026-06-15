---
title: "Live Protection"
description: "Step-by-step guide to real-time IP range detection with flokbn"
summary: "Complete walkthrough of live mode for continuous monitoring and automatic blocking"
date: 2025-10-09T10:00:00+00:00
lastmod: 2026-06-12T10:00:00+00:00
draft: false
weight: 820
slug: "live-protection-guide"
toc: true
seo:
  title: "flokbn Live Protection Guide"
  description: "Learn how to deploy flokbn in live mode for real-time IP cluster detection"
  canonical: ""
  noindex: false
---

Live mode provides real-time detection by continuously monitoring incoming logs via the Lumberjack protocol and automatically detecting and blocking high-volume IP ranges.

## How Live Mode Works

- Receives logs from Filebeat/Logstash via the Lumberjack protocol (TCP)
- Waits for the first shipper connection at startup, then loops: read a batch, update every sliding window, run every cluster arg set, update jail and ban file, sleep
- The sleep between iterations is the **largest** `sleepBetweenIterations` across all configured windows - one loop drives all windows
- Multiple windows (own filters, sizes, cluster arg sets) share one jail and one ban file
- Repeat offenders escalate through 5 jail stages: 10 minutes, 4 hours, 7 days, 30 days, 180 days
- Whitelist/blacklist and User-Agent list files are loaded **once at startup** - restart flokbn to pick up edits

## Quick Start (CLI)

```bash
./flokbn live --port 8080 \
  --jailFile /etc/flokbn/jail.json \
  --banFile /etc/flokbn/ban.txt \
  --slidingWindowMaxTime 2h \
  --slidingWindowMaxSize 100000
```

Flags-only mode runs a single sliding window; multiple windows and the HTTP stats endpoints require a config file. For all CLI flags, see [CLI Flags]({{< relref "/docs/reference/cli-flags/" >}}).

## Configuration File (Recommended)

For production, use a [config file]({{< relref "/docs/reference/config-file/" >}}) with multiple windows:

```bash
./flokbn live --config /etc/flokbn/config.toml
```

See [Config File]({{< relref "/docs/reference/config-file/" >}}) for the complete live example with multiple windows.

## Sliding Window Parameters

### Time Window

Controls how far back to keep request history:

```toml
slidingWindowMaxTime = "2h"    # 2 hours
slidingWindowMaxTime = "30m"   # 30 minutes
```

Longer windows catch slower patterns but use more memory.

### Size Limit

Maximum requests in memory:

```toml
slidingWindowMaxSize = 100000   # ~5-10 MB
slidingWindowMaxSize = 50000    # ~2.5-5 MB
```

### Iteration Interval

How often detection runs (seconds):

```toml
sleepBetweenIterations = 10    # Every 10 seconds
sleepBetweenIterations = 5     # Every 5 seconds (more CPU, faster detection)
```

With multiple windows, the single detection loop sleeps for the **largest** value across all windows - a `5` next to a `10` still iterates every 10 seconds.

## Filebeat Integration

Configure Filebeat to ship logs to flokbn:

```yaml
# filebeat.yml
filebeat.inputs:
  - type: log
    enabled: true
    paths:
      - /var/log/nginx/access.log

output.logstash:
  hosts: ["flokbn-host:8080"]
  compression_level: 3
```

```bash
sudo systemctl restart filebeat
```

### Expected log line format

Live mode parses each event's `message` field itself and expects the standard **combined log format with the client IP as the first field**:

```
192.0.2.1 - - [09/Oct/2025:10:15:23 +0000] "GET / HTTP/1.1" 200 1234 "-" "curl/8.5.0"
```

The configurable `--logFormat` string applies to **static mode only** - it has no effect on live ingestion. If your web server logs a proxy IP first, change its `log_format` so the real client IP leads the line (rather than reordering fields on the flokbn side, which live mode does not support). Lines that don't parse are counted as parse errors in `/stats` and skipped.

## Firewall Integration

Monitor the ban file and update iptables rules when it changes:

```bash
#!/bin/bash
# watch-banfile.sh
BANFILE="/etc/flokbn/ban.txt"
LAST_HASH=""

while true; do
  CURRENT_HASH=$(md5sum "$BANFILE" | cut -d' ' -f1)
  if [ "$CURRENT_HASH" != "$LAST_HASH" ]; then
    iptables -F FLOKBN-BLOCK 2>/dev/null || iptables -N FLOKBN-BLOCK
    grep -v '^#' "$BANFILE" | while read -r cidr; do
      [ -n "$cidr" ] && iptables -A FLOKBN-BLOCK -s "$cidr" -j DROP
    done
    LAST_HASH="$CURRENT_HASH"
  fi
  sleep 10
done
```

The ban file contains `#` comment lines alongside the CIDRs (hence the `grep -v '^#'`) - see the [Ban File Format]({{< relref "/docs/reference/output-formats/#ban-file-format" >}}) for the exact format and further integration patterns (nginx and more).

## Production Deployment

### systemd Service

Create `/etc/systemd/system/flokbn.service`:

```ini
[Unit]
Description=flokbn IP Cluster Detection
After=network.target filebeat.service
Wants=filebeat.service

[Service]
Type=simple
User=flokbn
Group=flokbn
ExecStart=/usr/local/bin/flokbn live --config /etc/flokbn/config.toml
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/flokbn /etc/flokbn

[Install]
WantedBy=multi-user.target
```

```bash
sudo useradd -r -s /bin/false flokbn
sudo mkdir -p /var/lib/flokbn /etc/flokbn
sudo chown flokbn:flokbn /var/lib/flokbn /etc/flokbn
sudo systemctl daemon-reload
sudo systemctl enable flokbn
sudo systemctl start flokbn
```

### Log Rotation

```
# /etc/logrotate.d/flokbn
/var/log/flokbn/*.log {
    daily
    rotate 14
    compress
    delaycompress
    notifempty
    create 0640 flokbn flokbn
}
```

## Logging

Live mode writes leveled, timestamped log lines to **stderr**: one summary line per detection iteration (window size, batch size, detected/merged/jailed counts, timings) plus warnings and errors. Configure via the `[log]` section ([Config File]({{< relref "/docs/reference/config-file/" >}})) or override the level with `--logLevel`:

```toml
[log]
level = "info"   # debug, info, warn, error
format = "text"  # text or json
```

## HTTP Endpoints

For machine-readable live data, set `statsListen` in `[live]` (config file only - no CLI flag). Bind to localhost unless you have a reason not to:

```toml
[live]
port = "8080"
statsListen = "127.0.0.1:8666"
topTalkers = 5   # optional: top-N IPs per window in /stats
```

| Endpoint | Content |
|----------|---------|
| `GET /stats` | JSON snapshot of the last iteration: `ingest` (connection, queue, totals, parse errors), `windows` (size, accepted/rejected counts, per-set detections and timings, optional `top_talkers`), `jail` (active bans per stage with start/expiry), `lists`, `loop` |
| `GET /bans` | The ban file content last written to disk, verbatim (`text/plain`) |
| `GET /metrics` | Prometheus exposition format; all metrics are prefixed `flokbn_` (ingest, window, cluster, jail, ban-file, and loop families) |

All three return `503` with a `Retry-After` header until the loop has completed its first iteration. The snapshot updates once per iteration, not per request.

## Monitoring

```bash
# View live logs
journalctl -u flokbn -f

# Monitor ban file
tail -f /etc/flokbn/ban.txt

# Check jail state
cat /etc/flokbn/jail.json | jq '.Cells | length'
```

The jail file uses a tiered cell structure with escalating bans (stage 1-5: 10 minutes, 4 hours, 7 days, 30 days, 180 days; re-detection after expiry moves a range to the next stage). See [Internals]({{< relref "/docs/architecture/internals/" >}}) for the jail data model.

## Troubleshooting

### No Logs Received

```bash
telnet flokbn-host 8080              # Test port
journalctl -u filebeat -f           # Check Filebeat
netstat -tlnp | grep 8080           # Verify listening
```

### High Memory Usage

Reduce window parameters:
```toml
slidingWindowMaxSize = 50000
slidingWindowMaxTime = "1h"
```

### False Positives

Add [whitelists]({{< relref "/docs/reference/filtering/" >}}) and increase [cluster thresholds]({{< relref "/docs/reference/clustering/" >}}).

## Best Practices

1. **Maintain whitelists** - live mode bans automatically, so legitimate ranges must be protected up front
2. **Use multiple windows** - different window sizes and cluster arg sets catch different traffic patterns
3. **Rehearse with the [Docker demo stack]({{< relref "/docs/guides/docker-testing/" >}})** - it shows the full closed loop (detection, firewall enforcement, ban expiry, Grafana dashboard) against simulated traffic before you touch production
