package cli

import (
	"strings"
	"testing"

	"github.com/ChristianF88/flokbn/output"
)

// metricsTestSnapshot builds a synthetic snapshot covering every metric
// family renderMetrics emits.
func metricsTestSnapshot() *statsSnapshot {
	sn := &statsSnapshot{
		SchemaVersion: statsSchemaVersion,
		UptimeS:       42,
	}
	sn.Ingest = ingestStats{
		Connected:            true,
		QueueDepth:           3,
		BatchesTotal:         7,
		RequestsTotal:        1234,
		ParseErrorsTotal:     2,
		MalformedFieldsTotal: 1,
	}
	sn.Windows = []windowStats{
		{
			Name:                  "general_detection",
			SizeIPs:               11,
			Requests:              200,
			AcceptedTotal:         500,
			RejectedByFilterTotal: 5,
			ClusterSets: []clusterSetStats{
				{
					Params:         clusterParams{MinSize: 50, Depth: "24-32", Threshold: 0.2},
					UseForJail:     true,
					LastDurationUS: 1500,
					DetectedNow:    []output.LiveCIDR{{CIDR: "172.16.1.0/27"}},
				},
			},
		},
		{Name: "aggressive_detection", SizeIPs: 33, Requests: 900},
	}
	sn.Jail = jailStats{
		TotalActive: 4,
		Stages: []jailStage{
			{Stage: 1, Active: 3},
			{Stage: 2, Active: 1},
		},
		ActiveBans: []activeBanJSON{
			{CIDR: "172.16.16.0/24", Stage: 1},
			{CIDR: "172.16.1.0/27", Stage: 2},
		},
	}
	sn.Lists.BanFile.Entries = 6
	sn.Lists.UserAgentLists = uaListsStats{
		WhitelistHitsTotal: 10,
		BlacklistHitsTotal: 20,
		ActiveWhitelistIPs: 1,
		ActiveBlacklistIPs: 2,
	}
	sn.Loop = loopStats{Iterations: 99, LastDurationMS: 250}
	return sn
}

func TestRenderMetrics_ValuesAndLabels(t *testing.T) {
	got := string(renderMetrics(metricsTestSnapshot()))

	wantLines := []string{
		"flokbn_uptime_seconds 42",
		"flokbn_ingest_connected 1",
		"flokbn_ingest_queue_depth 3",
		"flokbn_ingest_batches_total 7",
		"flokbn_ingest_requests_total 1234",
		"flokbn_ingest_parse_errors_total 2",
		"flokbn_ingest_malformed_fields_total 1",
		`flokbn_window_unique_ips{window="general_detection"} 11`,
		`flokbn_window_unique_ips{window="aggressive_detection"} 33`,
		`flokbn_window_requests{window="general_detection"} 200`,
		`flokbn_window_accepted_total{window="general_detection"} 500`,
		`flokbn_window_rejected_by_filter_total{window="general_detection"} 5`,
		`flokbn_cluster_detected{window="general_detection",set="50:24-32:0.20"} 1`,
		`flokbn_cluster_duration_seconds{window="general_detection",set="50:24-32:0.20"} 0.0015`,
		"flokbn_jail_active 4",
		`flokbn_ban_active{cidr="172.16.16.0/24",stage="1"} 1`,
		`flokbn_ban_active{cidr="172.16.1.0/27",stage="2"} 1`,
		`flokbn_jail_stage_active{stage="1"} 3`,
		`flokbn_jail_stage_active{stage="2"} 1`,
		"flokbn_ban_file_entries 6",
		`flokbn_ua_list_hits_total{list="whitelist"} 10`,
		`flokbn_ua_list_hits_total{list="blacklist"} 20`,
		`flokbn_ua_list_active_ips{list="whitelist"} 1`,
		`flokbn_ua_list_active_ips{list="blacklist"} 2`,
		"flokbn_loop_iterations_total 99",
		"flokbn_loop_duration_seconds 0.25",
	}
	for _, want := range wantLines {
		if !strings.Contains(got, want+"\n") {
			t.Errorf("metrics output missing line %q\noutput:\n%s", want, got)
		}
	}
}

func TestRenderMetrics_HelpAndTypeLines(t *testing.T) {
	got := string(renderMetrics(metricsTestSnapshot()))

	// Every sample line's metric name must have HELP and TYPE headers, and
	// counters must carry the _total suffix.
	for _, line := range strings.Split(strings.TrimSpace(got), "\n") {
		if strings.HasPrefix(line, "#") {
			continue
		}
		name := line
		if i := strings.IndexAny(line, "{ "); i >= 0 {
			name = line[:i]
		}
		if !strings.Contains(got, "# HELP "+name+" ") {
			t.Errorf("metric %q has no HELP line", name)
		}
		if !strings.Contains(got, "# TYPE "+name+" ") {
			t.Errorf("metric %q has no TYPE line", name)
		}
	}
	for _, line := range strings.Split(got, "\n") {
		if !strings.HasPrefix(line, "# TYPE ") {
			continue
		}
		parts := strings.Fields(line) // ["#", "TYPE", name, type]
		if parts[3] == "counter" && !strings.HasSuffix(parts[2], "_total") {
			t.Errorf("counter %q does not end in _total", parts[2])
		}
	}
}

func TestRenderMetrics_LabelEscaping(t *testing.T) {
	sn := metricsTestSnapshot()
	sn.Windows[0].Name = `we"ird\name` + "\nx"
	got := string(renderMetrics(sn))

	want := `flokbn_window_unique_ips{window="we\"ird\\name\nx"} 11`
	if !strings.Contains(got, want+"\n") {
		t.Errorf("escaped label line %q missing\noutput:\n%s", want, got)
	}
}

func TestMetricsEndpoint(t *testing.T) {
	srv := newTestStatsServer(t)

	// 503 with Retry-After before the first snapshot.
	status, header, _ := httpGet(t, srv, "/metrics")
	if status != 503 {
		t.Fatalf("GET /metrics before snapshot status = %d, want 503", status)
	}
	if header.Get("Retry-After") == "" {
		t.Error("503 response missing Retry-After header")
	}

	srv.publish(metricsTestSnapshot())
	status, header, body := httpGet(t, srv, "/metrics")
	if status != 200 {
		t.Fatalf("GET /metrics status = %d, want 200", status)
	}
	if ct := header.Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("Content-Type = %q, want text/plain prefix", ct)
	}
	if !strings.Contains(string(body), "flokbn_jail_active 4\n") {
		t.Errorf("/metrics body missing jail gauge:\n%s", body)
	}
}

func BenchmarkRenderMetrics(b *testing.B) {
	sn := metricsTestSnapshot()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = renderMetrics(sn)
	}
}
