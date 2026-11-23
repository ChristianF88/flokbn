---
title: "Live Protection"
description: "Step-by-step guide to real-time IP range detection with flokbn"
summary: "Complete walkthrough of live mode for continuous monitoring and automatic blocking"
date: 2025-10-09T10:00:00+00:00
lastmod: 2026-11-23T10:00:00+00:00
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

{{< callout context="caution" title="Live mode ignores logFormat: the client IP must be the first field" icon="outline/alert-triangle" >}}
Live mode does **not** use the configurable log format. It always takes the text before the first space of each line as the client IP and expects the standard combined log layout after it. `flokbn live` has no `--logFormat` flag, `[live]` has no `logFormat` key, and a `logFormat` under `[static]` has no effect here.

This matters most behind a proxy or load balancer. Static mode's **default** format reads the client IP from the *last* field (an `X-Forwarded-For` layout); live mode reads the *first* field of the very same line - which is then your proxy's address. flokbn would cluster and ban your own proxy. Before enabling live mode, make sure your web server writes the real client IP first (see [Expected log line format](#expected-log-line-format)), and whitelist your proxy addresses as a safety net.
{{< /callout >}}

## How Live Mode Works

- Receives logs from Filebeat/Logstash via the Lumberjack protocol (TCP, optionally TLS), on `127.0.0.1` unless `listen` says otherwise
- Starts its loop right away - it does not block until a shipper connects: read the queued batches, update every sliding window, run every cluster arg set, update the jail, sleep. The jail and ban files are written only when their content changed
- While no traffic arrives, an idle heartbeat keeps expiring window entries and bans, so bans lift and the published numbers decay without new log lines
- The sleep between iterations is the **largest** `sleepBetweenIterations` across all configured windows - one loop drives all windows
- Multiple windows (own filters, sizes, cluster arg sets) share one jail and one ban file
- Repeat offenders escalate through 5 jail stages: 10 minutes, 4 hours, 7 days, 30 days, 180 days
- Whitelist/blacklist and User-Agent list files are loaded **once at startup** - restart flokbn to pick up edits

## Quick Start (CLI)

```bash
flokbn live --port 8080 \
  --jailFile /var/lib/flokbn/jail.json \
  --banFile /var/lib/flokbn/ban.txt \
  --slidingWindowMaxTime 2h \
  --slidingWindowMaxSize 100000
```

This listens on `127.0.0.1:8080`; add `--listen <address>` to accept shippers from other hosts (read [Security Considerations](#security-considerations) first). Flags-only mode runs a single sliding window; multiple windows, TLS for the listener and the HTTP stats endpoints require a config file. For all CLI flags, see [CLI Flags]({{< relref "/docs/reference/cli-flags/" >}}).

## Configuration File (Recommended)

For production, use a [config file]({{< relref "/docs/reference/config-file/" >}}) with multiple windows:

```bash
flokbn live --config /etc/flokbn/config.toml
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

A window that omits the key uses `10`, the same default as the `--sleepBetweenIterations` flag. An explicit `0` means no pause between iterations; a negative value is rejected at startup. With multiple windows, the single detection loop sleeps for the **largest** value across all windows - a `5` next to a `10` still iterates every 10 seconds.

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

flokbn listens on `127.0.0.1` unless `[live] listen` (or `--listen`) says otherwise. With Filebeat on the same host, point `hosts` at `127.0.0.1:8080`; for a remote Filebeat, set `listen` and protect the port as described in [Security Considerations](#security-considerations) - ideally with [mutual TLS](#tls-and-mutual-tls-for-the-ingest-listener).

flokbn logs `Filebeat connected` and `Filebeat disconnected` (with the remote address and the number of open connections) whenever a shipper connects or leaves. The startup line `waiting for Filebeat to connect` only says the listener is up; it is not followed by a blocking wait.

### Expected log line format

Live mode parses each event's `message` field itself and expects the standard **combined log format with the client IP as the first field**:

```
192.0.2.1 - - [09/Oct/2025:10:15:23 +0000] "GET / HTTP/1.1" 200 1234 "-" "curl/8.5.0"
```

The configurable `--logFormat` string applies to **static mode only** - it has no effect on live ingestion, and a format you tuned for static mode says nothing about what live mode will read. The first space-separated token is the client IP, always.

If your web server logs a proxy IP first, change its `log_format` so the real client IP leads the line (rather than reordering fields on the flokbn side, which live mode does not support). For nginx behind a trusted proxy, either let the `realip` module rewrite `$remote_addr` (`set_real_ip_from <proxy>; real_ip_header X-Forwarded-For;`) and keep the stock format, or define a format that starts with the address your own proxy appended. Only that element of `X-Forwarded-For` is trustworthy; the rest of the header is supplied by the client.

A quick check before going live: take one line from the log Filebeat ships and confirm that its first field is a client address, not your proxy's. Lines that don't parse are counted as parse errors in `/stats` and skipped - but a line with the *wrong* IP first parses fine, so the parse-error counter will not warn you.

**Timestamps must agree with the clock of the flokbn host.** The sliding window expires entries by comparing each request's log timestamp with the wall clock. Log the UTC offset (`[09/Oct/2025:10:15:23 +0200]`, the nginx and Apache default); a timestamp without an offset is read as UTC. If the two disagree, detection silently stops working: requests stamped older than `slidingWindowMaxTime` expire the moment they arrive, and requests stamped in the future are clamped to their arrival time. When more than half of a batch is affected, flokbn logs the warning `most request timestamps fall outside the sliding window on arrival` (at most once per minute and window) with the counts of `stale` and `future` requests - see [Troubleshooting](#nothing-is-ever-detected).

## Security Considerations

Live mode turns log lines into bans automatically, so everything that can influence its input or read its output is security-relevant.

{{< callout context="caution" title="The ingest port does not authenticate shippers unless you enable mutual TLS" icon="outline/alert-triangle" >}}
By default the Lumberjack listener is plain TCP: no authentication, no encryption. Whoever can open a connection to it can send forged log events - and with enough of them get arbitrary IP ranges banned (for example your own customers, or a monitoring service). That is why it binds to `127.0.0.1` unless you say otherwise. Client certificates (`tlsClientCA`) are the only authentication the port has; `tlsCert`/`tlsKey` alone encrypt the stream but still accept any client.
{{< /callout >}}

- **Ingest listener (`[live] listen`, `--listen`).** The listener binds to `127.0.0.1` by default, which fits a Filebeat running on the same host. To accept logs from another host or container, set `listen` explicitly (for example `listen = "0.0.0.0"` or one specific interface address; an address or host name without a port) **and** control who can use the port: require client certificates (below), or admit only your log shippers with a firewall rule, a private network, or a tunnel. Never expose it to the internet unauthenticated. When the listener is bound to a non-loopback address and mutual TLS is not enabled, flokbn logs a warning at every start (`ingest listener is reachable from other hosts and does not authenticate clients ...`); it still starts, because a firewalled port is a legitimate setup.
- **HTTP endpoints (`statsListen`).** `/stats`, `/bans` and `/metrics` are unauthenticated too. `/stats` returns your whitelist and blacklist CIDRs, the paths of the list, jail and ban files, and the exact detection thresholds of every cluster arg set - enough for an attacker to stay just below them. The server is off unless `statsListen` is set; when you set it, keep it on loopback (`127.0.0.1:8666`) or put it behind a reverse proxy that authenticates. If a remote enforcement point needs the ban list, expose only `/bans` through that proxy.
- **User-Agent whitelist.** The User-Agent is client-controlled: one request with a listed string makes the sender's IP immune, including against the manual blacklist. See the warning in [Filtering]({{< relref "/docs/reference/filtering/#user-agent-whitelist" >}}).
- **Client IP behind a proxy.** flokbn bans whatever address the log line names as the client. If that address comes from an `X-Forwarded-For` header, only the element appended by **your own** proxy is trustworthy; anything to its left was supplied by the client and can name any address they want banned. See [Log Formats]({{< relref "/docs/reference/log-formats/" >}}).
- **Jail and ban files.** Keep them in a directory only the flokbn user can write (for example `/var/lib/flokbn`), not in a world-writable location such as `/tmp`: whoever can write the ban file controls your firewall rules.

### TLS and mutual TLS for the ingest listener

TLS is configured in the `[live]` section of the config file; there are no CLI flags for it.

```toml
[live]
port = "8080"
listen = "0.0.0.0"
tlsCert = "/etc/flokbn/tls/server.crt"            # listener certificate (PEM)
tlsKey = "/etc/flokbn/tls/server.key"             # its private key (PEM)
tlsClientCA = "/etc/flokbn/tls/shippers-ca.crt"   # optional: require client certificates signed by this CA
```

| Keys set | Listener | Who can send events |
|----------|----------|---------------------|
| none | plain TCP | anyone who can reach the port |
| `tlsCert` + `tlsKey` | TLS (1.2 or newer) | anyone who can reach the port - the stream is encrypted, the client is not checked |
| `tlsCert` + `tlsKey` + `tlsClientCA` | mutual TLS | only clients presenting a certificate signed by a CA in the bundle |

`tlsCert` and `tlsKey` must be set together, and `tlsClientCA` requires both. The files are loaded and checked at startup, before the port is bound: a missing file, a key that does not match the certificate, or a CA bundle without a certificate aborts the start. They are read once - restart flokbn after rotating a certificate. The startup line `starting live loop` reports the mode as `tls=off`, `tls=server` or `tls=mutual`.

The matching Filebeat side:

```yaml
output.logstash:
  hosts: ["flokbn-host:8080"]
  ssl.certificate_authorities: ["/etc/filebeat/flokbn-ca.crt"]   # CA that signed flokbn's tlsCert
  ssl.certificate: "/etc/filebeat/shipper.crt"                    # only for mutual TLS
  ssl.key: "/etc/filebeat/shipper.key"                            # only for mutual TLS
```

The listener certificate must be valid for the name Filebeat connects to (`flokbn-host` above).

### Protocol limits

The listener enforces fixed limits before it allocates memory for anything a peer announces, so a malformed or hostile stream cannot exhaust memory. They are not configurable and sit far above what Filebeat sends by default (2048 events per batch):

| Limit | Value | When exceeded |
|-------|-------|---------------|
| Events per batch (window) | 65,536 | connection closed |
| Size of one event | 1 MiB | connection closed |
| Size of one batch after decompression, and of one compressed frame | 32 MiB | connection closed |
| Bytes held for batches being read or waiting for the detection loop | 512 MiB | shippers are held back (keepalives, no data loss) until the loop catches up |
| Simultaneous connections | 64 | further connections are closed on accept |

A connection closed for a protocol or limit violation is logged as `Filebeat disconnected: protocol violation` with the reason; a rejected one as `ingest connection rejected: connection limit reached`. `readTimeout` (default `5s`) bounds how long a shipper may take to deliver a batch it has announced, and the TLS handshake; an idle connection between batches is not timed out.

## Firewall Integration

Monitor the ban file and update iptables rules when it changes:

```bash
#!/bin/bash
# watch-banfile.sh
BANFILE="/var/lib/flokbn/ban.txt"
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
ReadWritePaths=/var/lib/flokbn

[Install]
WantedBy=multi-user.target
```

```bash
sudo useradd -r -s /bin/false flokbn
sudo mkdir -p /var/lib/flokbn /etc/flokbn
sudo chown flokbn:flokbn /var/lib/flokbn   # state: jail and ban file
sudo chmod 750 /var/lib/flokbn
# /etc/flokbn (config, list files) stays root-owned: the service only reads it
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

Live mode writes leveled, timestamped log lines to **stderr**: one summary line per detection iteration (window size, batch size, detected/merged/jailed counts, whether the ban and jail files were written, timings), shipper connects and disconnects, plus warnings and errors. The fields are listed under [Log Lines]({{< relref "/docs/reference/output-formats/#log-lines" >}}). Configure via the `[log]` section ([Config File]({{< relref "/docs/reference/config-file/" >}})) or override the level with `--logLevel`:

```toml
[log]
level = "info"   # debug, info, warn, error
format = "text"  # text or json
```

## HTTP Endpoints

For machine-readable live data, set `statsListen` in `[live]` (config file only - no CLI flag). The endpoints are unauthenticated and `/stats` discloses your whitelist and detection thresholds, so bind to loopback or put an authenticating reverse proxy in front (see [Security Considerations](#security-considerations)):

```toml
[live]
port = "8080"
statsListen = "127.0.0.1:8666"
topTalkers = 5   # optional: top-N IPs per window in /stats
```

| Endpoint | Content |
|----------|---------|
| `GET /stats` | JSON snapshot of the last iteration: `ingest` (open shipper connections, queue, totals, parse errors), `windows` (size, accepted/rejected counts, per-set detections and timings, optional `top_talkers`), `jail` (active bans per stage with start/expiry), `lists`, `loop` |
| `GET /bans` | The ban file content last written to disk, verbatim (`text/plain`) |
| `GET /metrics` | Prometheus exposition format; all metrics are prefixed `flokbn_` (ingest, window, cluster, jail, ban-file, and loop families) |

All three return `503` with a `Retry-After` header until the loop has published its first snapshot (after the first iteration or the first idle heartbeat). The snapshot updates once per iteration or heartbeat, not per request. The fields and metrics are listed in [Output Formats]({{< relref "/docs/reference/output-formats/#http-endpoints" >}}).

## Monitoring

```bash
# View live logs
journalctl -u flokbn -f

# Monitor ban file
tail -f /var/lib/flokbn/ban.txt

# Check jail state
cat /var/lib/flokbn/jail.json | jq '.Cells | length'
```

The jail file uses a tiered cell structure with escalating bans (stage 1-5: 10 minutes, 4 hours, 7 days, 30 days, 180 days; re-detection after expiry moves a range to the next stage). See [Internals]({{< relref "/docs/architecture/internals/" >}}) for the jail data model.

## Troubleshooting

### No Logs Received

```bash
telnet flokbn-host 8080              # Test port
journalctl -u filebeat -f           # Check Filebeat
netstat -tlnp | grep 8080           # Verify listening
```

- `netstat` shows the address the listener is bound to. If it is `127.0.0.1:8080` and Filebeat runs on another host, set `[live] listen` (or `--listen`).
- A shipper that reaches flokbn produces a `Filebeat connected` log line, and `ingest.connected` in `/stats` (`flokbn_ingest_connected` in `/metrics`) turns true. Both stay false/absent while only the listener is up.
- With TLS enabled, a shipper without matching `ssl.*` settings connects and is dropped again: look for `Filebeat disconnected` lines with a `TLS handshake` reason.
- If connections are established but `ingest.parse_errors_total` grows with every batch, the lines are not in the [expected format](#expected-log-line-format).

### Nothing Is Ever Detected

If batches arrive (`batch` > 0 in the iteration lines) but `window` stays near zero, the log timestamps disagree with the clock of the flokbn host and requests expire as soon as they arrive. flokbn says so with the warning `most request timestamps fall outside the sliding window on arrival`; its `stale` and `future` fields tell which way the clocks differ. The usual cause is a log format without a UTC offset on a web server that is not on UTC (such timestamps are read as UTC). Log the offset, or fix the clock on the log host.

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
