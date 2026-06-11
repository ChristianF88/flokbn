---
title: "Detection Walkthrough"
description: "End-to-end guide to detecting and blocking high-volume IP ranges with cidrx"
summary: "Step-by-step walkthrough from detection to blocking using cidrx"
date: 2025-10-09T10:00:00+00:00
lastmod: 2025-11-26T10:00:00+00:00
draft: false
weight: 840
toc: true
seo:
  title: "Detection Walkthrough with cidrx"
  description: "Step-by-step walkthrough of detecting and blocking high-volume IP ranges using cidrx"
  canonical: ""
  noindex: false
---

This guide walks through a complete detection and response scenario: from initial analysis through blocking and ongoing protection.

## Scenario

Your web server is experiencing high request volume, slow responses, and many requests from unknown IPs.

## Step 1: Initial Analysis

Run a broad scan:

```bash
./cidrx static \
  --logfile /var/log/nginx/access.log \
  --clusterArgSets 1000,24,32,0.1 \
  --plain
```

## Step 2: Examine Results

cidrx outputs detected ranges:

```
CLUSTERING RESULTS
Set 1: min_size=1000, depth=24-32, threshold=0.10
Detected Threat Ranges:
  198.51.100.0/24        15,243 requests  ( 12.34%)
  203.0.113.128/25        8,891 requests  (  7.20%)
  198.51.100.42/32        3,456 requests  (  2.80%)
```

Analysis: `/24` = large cluster (256 IPs), `/25` = medium cluster (128 IPs), `/32` = single high-volume IP.

## Step 3: Refine Detection

Use multiple [cluster arg sets]({{< relref "/docs/reference/clustering/" >}}) to catch different traffic patterns:

```bash
./cidrx static \
  --logfile /var/log/nginx/access.log \
  --clusterArgSets 500,28,32,0.1 \
  --clusterArgSets 2000,20,28,0.2 \
  --clusterArgSets 10000,16,24,0.3 \
  --plain
```

## Step 4: Filter False Positives

Add a [whitelist]({{< relref "/docs/reference/filtering/" >}}):

```bash
./cidrx static \
  --logfile /var/log/nginx/access.log \
  --whitelist /etc/cidrx/whitelist.txt \
  --clusterArgSets 1000,24,32,0.1 \
  --plain
```

## Step 5: Generate Block List

```bash
./cidrx static \
  --logfile /var/log/nginx/access.log \
  --clusterArgSets 1000,24,32,0.1 \
  --jailFile /tmp/jail.json \
  --banFile /tmp/ban.txt \
  --plain
```

## Step 6: Block Traffic

Apply the ban file to your firewall. See [Output Formats]({{< relref "/docs/reference/output-formats/" >}}) for iptables, nginx, and other integration patterns.

```bash
while read cidr; do
  iptables -I INPUT -s "$cidr" -j DROP
done < /tmp/ban.txt
```

## Step 7: Enable Real-Time Protection

Switch to [live mode]({{< relref "/docs/guides/live-protection/" >}}) for ongoing protection:

```bash
./cidrx live --config /etc/cidrx/config.toml
```

See the [Live Protection Guide]({{< relref "/docs/guides/live-protection/" >}}) for Filebeat setup, systemd, and monitoring.

## Step 8: Investigate Traffic Patterns

Filter by endpoint to focus on specific areas:

```bash
./cidrx static --logfile /var/log/nginx/access.log \
  --endpointRegex "/api/.*|/admin/.*" \
  --clusterArgSets 500,28,32,0.1 --plain
```

## Troubleshooting

**No ranges detected?** Lower minSize, check [log format]({{< relref "/docs/reference/log-formats/" >}}) matches.

**Too many false positives?** Add IPs to [whitelist]({{< relref "/docs/reference/filtering/" >}}), increase [threshold]({{< relref "/docs/reference/clustering/" >}}).

**Performance issues?** See [Performance]({{< relref "/docs/architecture/performance/" >}}).
