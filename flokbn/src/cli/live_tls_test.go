package cli

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	v2 "github.com/elastic/go-lumber/client/v2"

	"github.com/ChristianF88/flokbn/testutil"
)

func liveTLSConfigFile(t *testing.T, port, tlsBody string) string {
	t.Helper()
	dir := t.TempDir()
	return writeFile(t, dir, "live.toml", `
[global]
jailFile = "`+filepath.Join(dir, "jail.json")+`"
banFile = "`+filepath.Join(dir, "ban.txt")+`"

[live]
port = "`+port+`"
listen = "0.0.0.0"
`+tlsBody+`

[live.win]
slidingWindowMaxTime = "1m"
slidingWindowMaxSize = 1000
sleepBetweenIterations = 1
clusterArgSets = [[100, 24, 32, 0.5]]
useForJail = [true]
`)
}

// TestLiveTLS_MutualEndToEnd runs the real binary with tlsCert/tlsKey/
// tlsClientCA: a shipper with a client certificate is served, one without is
// not, and an exposed-but-authenticated listener does not trigger the
// "does not authenticate clients" warning.
func TestLiveTLS_MutualEndToEnd(t *testing.T) {
	f := testutil.WriteTLSFiles(t)
	port := freePort(t)
	p := startLive(t, "--config", liveTLSConfigFile(t, port, `
tlsCert = "`+f.ServerCert+`"
tlsKey = "`+f.ServerKey+`"
tlsClientCA = "`+f.CA+`"
`))
	if !strings.Contains(p.stderr(), "tls=mutual") {
		t.Errorf("startup log lacks tls=mutual:\n%s", p.stderr())
	}
	if strings.Contains(p.stderr(), "does not authenticate clients") {
		t.Errorf("mTLS listener must not be reported as unauthenticated:\n%s", p.stderr())
	}

	caPEM, err := os.ReadFile(f.CA)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caPEM)
	send := func(cfg *tls.Config) error {
		client, err := v2.SyncDialWith(func(network, addr string) (net.Conn, error) {
			return tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, network, addr, cfg)
		}, net.JoinHostPort("127.0.0.1", port), v2.Timeout(5*time.Second))
		if err != nil {
			return err
		}
		defer client.Close()
		_, err = client.Send([]interface{}{map[string]interface{}{
			"message": `203.0.113.7 - - [12/Mar/2024:15:04:05 -0700] "GET /ok HTTP/1.1" 200 5 "-" "UA"`,
		}})
		return err
	}

	anonymous := &tls.Config{RootCAs: pool, ServerName: "localhost"}
	if err := send(anonymous); err == nil {
		t.Error("shipper without a client certificate was served by an mTLS listener")
	}

	cert, err := tls.LoadX509KeyPair(f.ClientCert, f.ClientKey)
	if err != nil {
		t.Fatal(err)
	}
	authenticated := &tls.Config{RootCAs: pool, ServerName: "localhost", Certificates: []tls.Certificate{cert}}
	if err := send(authenticated); err != nil {
		t.Errorf("shipper with a valid client certificate was rejected: %v", err)
	}
	p.stop(t)
}

// TLS without a client CA encrypts but does not authenticate, so an exposed
// listener still gets the warning.
func TestLiveTLS_ServerOnlyStillWarnsWhenExposed(t *testing.T) {
	f := testutil.WriteTLSFiles(t)
	port := freePort(t)
	p := startLive(t, "--config", liveTLSConfigFile(t, port, `
tlsCert = "`+f.ServerCert+`"
tlsKey = "`+f.ServerKey+`"
`))
	if !strings.Contains(p.stderr(), "tls=server") {
		t.Errorf("startup log lacks tls=server:\n%s", p.stderr())
	}
	if !strings.Contains(p.stderr(), "does not authenticate clients") {
		t.Errorf("exposed listener without client certificates must warn:\n%s", p.stderr())
	}
	p.stop(t)
}

// Broken TLS settings stop the process at the config barrier: no listener is
// bound and nothing falls back to plain TCP.
func TestLiveTLS_BadSettingsFailBeforeBind(t *testing.T) {
	f := testutil.WriteTLSFiles(t)
	cfg := liveTLSConfigFile(t, freePort(t), `
tlsCert = "`+f.ServerCert+`"
tlsKey = "/nonexistent/server.key"
`)
	stdout, stderr, code := runFlokbn(t, "live", "--config", cfg)
	if code != 1 {
		t.Fatalf("expected exit 1, got %d\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}
	if !strings.Contains(stderr, "invalid ingest TLS settings") {
		t.Errorf("stderr lacks the TLS diagnostic:\n%s", stderr)
	}
	if strings.Contains(stdout+stderr, "starting live loop") {
		t.Errorf("listener was bound despite broken TLS settings:\n%s", stdout+stderr)
	}
}
