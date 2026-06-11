package cli

import (
	"bytes"
	"fmt"
	"strings"
)

// renderMetrics renders a statsSnapshot in the Prometheus text exposition
// format (version 0.0.4). Hand-rolled on purpose: the snapshot already holds
// every value, so a client library would only add a dependency. Read-side
// cold path, same as /stats.
func renderMetrics(sn *statsSnapshot) []byte {
	var b bytes.Buffer

	writeMetric(&b, "cidrx_uptime_seconds", "gauge",
		"Seconds since the live loop started.",
		sample{value: float64(sn.UptimeS)})

	connected := 0.0
	if sn.Ingest.Connected {
		connected = 1.0
	}
	writeMetric(&b, "cidrx_ingest_connected", "gauge",
		"Whether the ingestor is connected (1) or closed (0).",
		sample{value: connected})
	writeMetric(&b, "cidrx_ingest_queue_depth", "gauge",
		"Batches buffered in the ingest queue.",
		sample{value: float64(sn.Ingest.QueueDepth)})
	writeMetric(&b, "cidrx_ingest_batches_total", "counter",
		"Batches received since startup.",
		sample{value: float64(sn.Ingest.BatchesTotal)})
	writeMetric(&b, "cidrx_ingest_requests_total", "counter",
		"Requests parsed since startup.",
		sample{value: float64(sn.Ingest.RequestsTotal)})
	writeMetric(&b, "cidrx_ingest_parse_errors_total", "counter",
		"Log lines that failed to parse since startup.",
		sample{value: float64(sn.Ingest.ParseErrorsTotal)})
	writeMetric(&b, "cidrx_ingest_malformed_fields_total", "counter",
		"Parsed lines with malformed fields since startup.",
		sample{value: float64(sn.Ingest.MalformedFieldsTotal)})

	uniqueIPs := make([]sample, len(sn.Windows))
	requests := make([]sample, len(sn.Windows))
	accepted := make([]sample, len(sn.Windows))
	rejected := make([]sample, len(sn.Windows))
	var detected, clusterDur []sample
	for i := range sn.Windows {
		w := &sn.Windows[i]
		labels := `window="` + escapeLabel(w.Name) + `"`
		uniqueIPs[i] = sample{labels: labels, value: float64(w.SizeIPs)}
		requests[i] = sample{labels: labels, value: float64(w.Requests)}
		accepted[i] = sample{labels: labels, value: float64(w.AcceptedTotal)}
		rejected[i] = sample{labels: labels, value: float64(w.RejectedByFilterTotal)}
		for _, cs := range w.ClusterSets {
			setLabels := fmt.Sprintf(`window="%s",set="%d:%s:%.2f"`,
				escapeLabel(w.Name), cs.Params.MinSize, cs.Params.Depth, cs.Params.Threshold)
			detected = append(detected, sample{labels: setLabels, value: float64(len(cs.DetectedNow))})
			clusterDur = append(clusterDur, sample{labels: setLabels, value: float64(cs.LastDurationUS) / 1e6})
		}
	}
	writeMetric(&b, "cidrx_window_unique_ips", "gauge",
		"Unique IPs currently in the sliding window.", uniqueIPs...)
	writeMetric(&b, "cidrx_window_requests", "gauge",
		"Requests currently in the sliding window.", requests...)
	writeMetric(&b, "cidrx_window_accepted_total", "counter",
		"Requests accepted into the window since startup.", accepted...)
	writeMetric(&b, "cidrx_window_rejected_by_filter_total", "counter",
		"Requests rejected by window filters since startup.", rejected...)
	writeMetric(&b, "cidrx_cluster_detected", "gauge",
		"CIDRs detected by this cluster arg set in the last iteration.", detected...)
	writeMetric(&b, "cidrx_cluster_duration_seconds", "gauge",
		"Clustering runtime of this arg set in the last iteration.", clusterDur...)

	writeMetric(&b, "cidrx_jail_active", "gauge",
		"Active bans in the jail (pre-whitelist truth).",
		sample{value: float64(sn.Jail.TotalActive)})
	banSamples := make([]sample, len(sn.Jail.ActiveBans))
	for i, ban := range sn.Jail.ActiveBans {
		banSamples[i] = sample{
			labels: fmt.Sprintf(`cidr="%s",stage="%d"`, escapeLabel(ban.CIDR), ban.Stage),
			value:  1,
		}
	}
	writeMetric(&b, "cidrx_ban_active", "gauge",
		"One series per actively banned CIDR (1 while banned; capped like jail.active_bans).",
		banSamples...)
	stageSamples := make([]sample, len(sn.Jail.Stages))
	for i, st := range sn.Jail.Stages {
		stageSamples[i] = sample{
			labels: fmt.Sprintf(`stage="%d"`, st.Stage),
			value:  float64(st.Active),
		}
	}
	writeMetric(&b, "cidrx_jail_stage_active", "gauge",
		"Active bans per jail stage.", stageSamples...)

	writeMetric(&b, "cidrx_ban_file_entries", "gauge",
		"CIDR entries in the last published ban file.",
		sample{value: float64(sn.Lists.BanFile.Entries)})

	ua := sn.Lists.UserAgentLists
	writeMetric(&b, "cidrx_ua_list_hits_total", "counter",
		"Requests matching a User-Agent list since startup.",
		sample{labels: `list="whitelist"`, value: float64(ua.WhitelistHitsTotal)},
		sample{labels: `list="blacklist"`, value: float64(ua.BlacklistHitsTotal)})
	writeMetric(&b, "cidrx_ua_list_active_ips", "gauge",
		"IPs currently tracked per User-Agent list (TTL-purged).",
		sample{labels: `list="whitelist"`, value: float64(ua.ActiveWhitelistIPs)},
		sample{labels: `list="blacklist"`, value: float64(ua.ActiveBlacklistIPs)})

	writeMetric(&b, "cidrx_loop_iterations_total", "counter",
		"Live loop iterations since startup.",
		sample{value: float64(sn.Loop.Iterations)})
	writeMetric(&b, "cidrx_loop_duration_seconds", "gauge",
		"Duration of the last loop iteration.",
		sample{value: float64(sn.Loop.LastDurationMS) / 1e3})

	return b.Bytes()
}

// sample is one exposition line: optional label pairs (already rendered,
// without braces) and the value.
type sample struct {
	labels string
	value  float64
}

func writeMetric(b *bytes.Buffer, name, typ, help string, samples ...sample) {
	fmt.Fprintf(b, "# HELP %s %s\n# TYPE %s %s\n", name, help, name, typ)
	for _, s := range samples {
		if s.labels == "" {
			fmt.Fprintf(b, "%s %g\n", name, s.value)
		} else {
			fmt.Fprintf(b, "%s{%s} %g\n", name, s.labels, s.value)
		}
	}
}

// escapeLabel escapes a label value per the exposition format: backslash,
// double quote, and newline.
func escapeLabel(v string) string {
	if !strings.ContainsAny(v, "\\\"\n") {
		return v
	}
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)
	return r.Replace(v)
}
