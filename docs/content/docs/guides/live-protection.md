---
title: "Live Protection Guide"
description: "Step-by-step guide to real-time IP range detection with cidrx"
summary: "Complete walkthrough of live mode for continuous monitoring and automatic blocking"
date: 2025-10-09T10:00:00+00:00
lastmod: 2025-11-26T10:00:00+00:00
draft: false
weight: 820
toc: true
seo:
  title: "cidrx Live Protection Guide"
  description: "Learn how to deploy cidrx in live mode for real-time IP cluster detection"
  canonical: ""
  noindex: false
---

Live mode provides real-time detection by continuously monitoring incoming logs via the Lumberjack protocol and automatically detecting and blocking high-volume IP ranges.

## How Live Mode Works

- Receives logs from Filebeat/Logstash via Lumberjack protocol
- Maintains sliding windows of recent requests in memory
- Runs detection on a configurable timer (every N seconds)
- Automatically updates jail and ban files when new ranges are detected
- Multiple independent windows can run concurrently

## Quick Start (CLI)

```bash
./cidrx live --port 8080 \
  --jailFile /etc/cidrx/jail.json \
  --banFile /etc/cidrx/ban.txt \
  --slidingWindowMaxTime 2h \
  --slidingWindowMaxSize 100000
```

For all CLI flags, see [CLI Flags]({{< relref "/docs/reference/cli-flags/" >}}).

## Configuration File (Recommended)

For production, use a [config file]({{< relref "/docs/reference/config-file/" >}}) with multiple windows:

```bash
./cidrx live --config /etc/cidrx/config.toml
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

## Filebeat Integration

Configure Filebeat to ship logs to cidrx:

```yaml
# filebeat.yml
filebeat.inputs:
  - type: log
    enabled: true
    paths:
      - /var/log/nginx/access.log

output.logstash:
  hosts: ["cidrx-host:8080"]
  compression_level: 3
```

```bash
sudo systemctl restart filebeat
```

## Firewall Integration

### iptables

Monitor the ban file and update rules:

```bash
#!/bin/bash
# watch-banfile.sh
BANFILE="/etc/cidrx/ban.txt"
LAST_HASH=""

while true; do
  CURRENT_HASH=$(md5sum "$BANFILE" | cut -d' ' -f1)
  if [ "$CURRENT_HASH" != "$LAST_HASH" ]; then
    iptables -F CIDRX-BLOCK 2>/dev/null || iptables -N CIDRX-BLOCK
    while read cidr; do
      iptables -A CIDRX-BLOCK -s "$cidr" -j DROP
    done < "$BANFILE"
    LAST_HASH="$CURRENT_HASH"
  fi
  sleep 10
done
```

### nginx

```bash
sed 's/^/deny /; s/$/;/' /etc/cidrx/ban.txt > /etc/nginx/cidrx-bans.conf
nginx -s reload
```

See [Output Formats]({{< relref "/docs/reference/output-formats/" >}}) for more firewall integration patterns.

## Production Deployment

### systemd Service

Create `/etc/systemd/system/cidrx.service`:

```ini
[Unit]
Description=cidrx IP Cluster Detection
After=network.target filebeat.service
Wants=filebeat.service

[Service]
Type=simple
User=cidrx
Group=cidrx
ExecStart=/usr/local/bin/cidrx live --config /etc/cidrx/config.toml
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/cidrx /etc/cidrx

[Install]
WantedBy=multi-user.target
```

```bash
sudo useradd -r -s /bin/false cidrx
sudo mkdir -p /var/lib/cidrx /etc/cidrx
sudo chown cidrx:cidrx /var/lib/cidrx /etc/cidrx
sudo systemctl daemon-reload
sudo systemctl enable cidrx
sudo systemctl start cidrx
```

### Log Rotation

```
# /etc/logrotate.d/cidrx
/var/log/cidrx/*.log {
    daily
    rotate 14
    compress
    delaycompress
    notifempty
    create 0640 cidrx cidrx
}
```

## Logging

Live mode writes leveled, timestamped log lines to **stderr**: one summary line per detection iteration (window size, batch size, detected/merged/jailed counts, timings) plus warnings and errors. Configure via the `[log]` section ([Config File]({{< relref "/docs/reference/config-file/" >}})) or override the level with `--logLevel`:

```toml
[log]
level = "info"   # debug, info, warn, error
format = "text"  # text or json
```

For machine-readable live data (detections, jail state, ban list), use the HTTP endpoints enabled by `statsListen` in `[live]`: `GET /stats` (JSON snapshot) and `GET /bans` (current ban file).

## Monitoring

```bash
# View live logs
journalctl -u cidrx -f

# Monitor ban file
tail -f /etc/cidrx/ban.txt

# Check jail state
cat /etc/cidrx/jail.json | jq '.Cells | length'
```

The jail file uses a tiered cell structure with escalating bans. See [Internals]({{< relref "/docs/architecture/internals/" >}}) for the jail data model.

## Troubleshooting

### No Logs Received

```bash
telnet cidrx-host 8080              # Test port
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

1. **Start conservative** -- high thresholds, monitor for 24 hours
2. **Maintain whitelists** -- protect legitimate traffic
3. **Multiple windows** -- different windows for different traffic patterns
4. **Regular backups** -- back up jail files and configurations
5. **Test in staging** -- use the [Docker environment]({{< relref "/docs/guides/docker-testing/" >}}) first
