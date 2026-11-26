package cli

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	v2 "github.com/elastic/go-lumber/client/v2"

	"github.com/ChristianF88/flokbn/logparser"
)

// liveLogFormatConfig writes a live config with a stats server and top talkers
// on, plus the given extra [live] lines.
func liveLogFormatConfig(t *testing.T, port, statsAddr, liveBody string) string {
	t.Helper()
	dir := t.TempDir()
	return writeFile(t, dir, "live.toml", `
[global]
jailFile = "`+filepath.Join(dir, "jail.json")+`"
banFile = "`+filepath.Join(dir, "ban.txt")+`"

[live]
port = "`+port+`"
statsListen = "`+statsAddr+`"
topTalkers = 3
`+liveBody+`

[live.win]
slidingWindowMaxTime = "1h"
slidingWindowMaxSize = 1000
sleepBetweenIterations = 1
clusterArgSets = [[100000, 24, 32, 0.5]]
useForJail = [true]
`)
}

// shipAndReadTopTalker ships lines to the live process and polls /stats until all
// of them are counted, then returns the ingest counters and the busiest IP.
func shipAndReadTopTalker(t *testing.T, port, statsAddr string, lines []string) (requests, parseErrors uint64, top string) {
	t.Helper()
	client, err := v2.SyncDial(net.JoinHostPort("127.0.0.1", port), v2.Timeout(5*time.Second))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()
	events := make([]interface{}, len(lines))
	for i, line := range lines {
		events[i] = map[string]interface{}{"message": line}
	}
	if _, err := client.Send(events); err != nil {
		t.Fatalf("send: %v", err)
	}

	var snap struct {
		Ingest struct {
			RequestsTotal    uint64 `json:"requests_total"`
			ParseErrorsTotal uint64 `json:"parse_errors_total"`
		} `json:"ingest"`
		Windows []struct {
			TopTalkers []struct {
				IP string `json:"ip"`
			} `json:"top_talkers"`
		} `json:"windows"`
	}
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get("http://" + statsAddr + "/stats")
		if err == nil {
			err = json.NewDecoder(resp.Body).Decode(&snap)
			resp.Body.Close()
			done := snap.Ingest.RequestsTotal+snap.Ingest.ParseErrorsTotal >= uint64(len(lines))
			if err == nil && done && (snap.Ingest.RequestsTotal == 0 ||
				(len(snap.Windows) == 1 && len(snap.Windows[0].TopTalkers) > 0)) {
				if len(snap.Windows) == 1 && len(snap.Windows[0].TopTalkers) > 0 {
					top = snap.Windows[0].TopTalkers[0].IP
				}
				return snap.Ingest.RequestsTotal, snap.Ingest.ParseErrorsTotal, top
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("/stats never showed %d shipped lines; last snapshot: %+v", len(lines), snap)
	return 0, 0, ""
}

// TestLiveLogFormat_EndToEnd runs the real binary and ships lines that carry a
// proxy address first and the client in a trailing forwarded field.
//
//   - Without logFormat, live mode reads the first field, as it always did:
//     the proxy is the talker. This is the default existing deployments rely on.
//   - With [live] logFormat set to the static default, the same lines yield the
//     client.
func TestLiveLogFormat_EndToEnd(t *testing.T) {
	now := time.Now().UTC().Format("02/Jan/2006:15:04:05 -0700")
	var lines []string
	for i := 0; i < 20; i++ {
		lines = append(lines, fmt.Sprintf(`10.9.9.9 - - [%s] "GET /p/%d HTTP/1.1" 200 5 "-" "UA" "198.51.100.1, 203.0.113.7"`, now, i))
	}

	cases := []struct {
		name, liveBody, wantFormat, wantTop string
	}{
		{"default reads the first field", "", logparser.DefaultLiveLogFormat, "10.9.9.9"},
		{"configured format reads the forwarded field", `logFormat = '` + logparser.DefaultLogFormat + `'`, logparser.DefaultLogFormat, "203.0.113.7"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			port := freePort(t)
			statsAddr := net.JoinHostPort("127.0.0.1", freePort(t))
			p := startLive(t, "--config", liveLogFormatConfig(t, port, statsAddr, tc.liveBody))

			// The effective format is on the startup line (slog quotes it).
			if !strings.Contains(p.stderr(), "log_format=") ||
				!strings.Contains(strings.ReplaceAll(p.stderr(), `\"`, `"`), tc.wantFormat) {
				t.Errorf("startup log does not show the effective log format %q:\n%s", tc.wantFormat, p.stderr())
			}

			requests, parseErrors, top := shipAndReadTopTalker(t, port, statsAddr, lines)
			if requests != uint64(len(lines)) || parseErrors != 0 {
				t.Errorf("requests_total = %d, parse_errors_total = %d; want %d, 0", requests, parseErrors, len(lines))
			}
			if top != tc.wantTop {
				t.Errorf("top talker = %q, want %q", top, tc.wantTop)
			}
			p.stop(t)
		})
	}
}

// --logFormat on the live command: an invalid format, or one whose fields do
// not serve the configured filters, stops at the config barrier before the
// listener is bound.
func TestLiveLogFormat_FlagValidatedAtBarrier(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"no %h", []string{"--logFormat", `[%t] "%r"`}, "[live] invalid logFormat"},
		{"no %t", []string{"--logFormat", `%h "%r"`}, "no %t field"},
		{"useragentRegex without %u", []string{"--logFormat", `%h [%t] "%r"`, "--useragentRegex", "bot"}, "[live.cli_default] useragentRegex"},
		{"endpointRegex without %r", []string{"--logFormat", `%h [%t] "%u"`, "--endpointRegex", "^/x"}, "[live.cli_default] endpointRegex"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			args := append([]string{"live",
				"--port", freePort(t),
				"--jailFile", filepath.Join(dir, "jail.json"),
				"--banFile", filepath.Join(dir, "ban.txt")}, tc.args...)
			stdout, stderr, code := runFlokbn(t, args...)
			if code != 1 {
				t.Fatalf("expected exit 1, got %d\nstderr:\n%s", code, stderr)
			}
			if !strings.Contains(stderr, tc.want) {
				t.Errorf("stderr lacks %q:\n%s", tc.want, stderr)
			}
			if strings.Contains(stdout+stderr, "starting live loop") {
				t.Errorf("listener was bound despite the invalid log format:\n%s", stdout+stderr)
			}
		})
	}
}

// With --config the format comes from the file; --logFormat next to it is
// refused like every other non-output flag.
func TestLiveLogFormat_FlagNotAllowedWithConfig(t *testing.T) {
	cfg := liveLogFormatConfig(t, freePort(t), net.JoinHostPort("127.0.0.1", freePort(t)), "")
	_, stderr, code := runFlokbn(t, "live", "--config", cfg, "--logFormat", logparser.DefaultLogFormat)
	if code == 0 {
		t.Fatalf("expected a non-zero exit\nstderr:\n%s", stderr)
	}
	if !strings.Contains(stderr, `--config cannot be combined with "--logFormat"`) {
		t.Errorf("stderr lacks the flag conflict:\n%s", stderr)
	}
}
