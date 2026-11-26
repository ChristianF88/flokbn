package config

import (
	"crypto/tls"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ChristianF88/flokbn/testutil"
)

func liveTLSConfig(body string) string {
	return liveListenBase + "\n[live]\nport = \"9000\"\n" + body
}

func TestIngestTLS_OffByDefault(t *testing.T) {
	cfg, err := loadConfigString(t, liveTLSConfig(""))
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	tlsCfg, err := cfg.IngestTLSConfig()
	if err != nil || tlsCfg != nil {
		t.Errorf("IngestTLSConfig() = %v, %v; want nil, nil without TLS keys", tlsCfg, err)
	}
	if got, err := (&Config{}).IngestTLSConfig(); got != nil || err != nil {
		t.Errorf("IngestTLSConfig() without [live] = %v, %v; want nil, nil", got, err)
	}
}

func TestIngestTLS_ServerOnly(t *testing.T) {
	f := testutil.WriteTLSFiles(t)
	cfg, err := loadConfigString(t, liveTLSConfig(`
tlsCert = "`+f.ServerCert+`"
tlsKey = "`+f.ServerKey+`"
`))
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if diags := cfg.Validate(LiveMode); diags.HasErrors() {
		t.Fatalf("valid TLS config rejected:\n%s", diags.Report())
	}
	tlsCfg, err := cfg.IngestTLSConfig()
	if err != nil {
		t.Fatalf("IngestTLSConfig: %v", err)
	}
	if len(tlsCfg.Certificates) != 1 {
		t.Errorf("got %d certificates, want 1", len(tlsCfg.Certificates))
	}
	if tlsCfg.ClientAuth != tls.NoClientCert {
		t.Errorf("ClientAuth = %v, want NoClientCert without tlsClientCA", tlsCfg.ClientAuth)
	}
	if tlsCfg.MinVersion < tls.VersionTLS12 {
		t.Errorf("MinVersion = %x, want at least TLS 1.2", tlsCfg.MinVersion)
	}
}

func TestIngestTLS_MutualRequiresClientCert(t *testing.T) {
	f := testutil.WriteTLSFiles(t)
	cfg, err := loadConfigString(t, liveTLSConfig(`
tlsCert = "`+f.ServerCert+`"
tlsKey = "`+f.ServerKey+`"
tlsClientCA = "`+f.CA+`"
`))
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	tlsCfg, err := cfg.IngestTLSConfig()
	if err != nil {
		t.Fatalf("IngestTLSConfig: %v", err)
	}
	if tlsCfg.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Errorf("ClientAuth = %v, want RequireAndVerifyClientCert", tlsCfg.ClientAuth)
	}
	if tlsCfg.ClientCAs == nil {
		t.Error("ClientCAs is nil, want the tlsClientCA pool")
	}
}

// Broken TLS settings are reported by Validate - before any port is bound -
// instead of silently falling back to plain TCP.
func TestIngestTLS_InvalidSettingsAreDiagnosed(t *testing.T) {
	f := testutil.WriteTLSFiles(t)
	notPEM := filepath.Join(t.TempDir(), "not-a-cert.pem")
	if err := os.WriteFile(notPEM, []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := map[string]struct{ body, want string }{
		"cert without key": {`tlsCert = "` + f.ServerCert + `"`, "tlsCert and tlsKey must be set together"},
		"key without cert": {`tlsKey = "` + f.ServerKey + `"`, "tlsCert and tlsKey must be set together"},
		"client CA alone":  {`tlsClientCA = "` + f.CA + `"`, "tlsClientCA needs tlsCert and tlsKey"},
		"missing cert file": {`tlsCert = "/nonexistent/server.crt"
tlsKey = "` + f.ServerKey + `"`, "loading tlsCert/tlsKey"},
		"key of another cert": {`tlsCert = "` + f.ServerCert + `"
tlsKey = "` + f.ClientKey + `"`, "loading tlsCert/tlsKey"},
		"missing client CA": {`tlsCert = "` + f.ServerCert + `"
tlsKey = "` + f.ServerKey + `"
tlsClientCA = "/nonexistent/ca.crt"`, "reading tlsClientCA"},
		"client CA not PEM": {`tlsCert = "` + f.ServerCert + `"
tlsKey = "` + f.ServerKey + `"
tlsClientCA = "` + notPEM + `"`, "contains no PEM certificate"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			report := loadAndReport(t, liveTLSConfig(tc.body), LiveMode)
			if !strings.Contains(report, "invalid ingest TLS settings") || !strings.Contains(report, tc.want) {
				t.Errorf("report lacks %q:\n%s", tc.want, report)
			}
		})
	}
}

func TestIngestTLS_WrongTypeIsHardError(t *testing.T) {
	_, err := loadConfigString(t, liveTLSConfig(`tlsCert = true`))
	if err == nil || !strings.Contains(err.Error(), "tlsCert must be a string") {
		t.Errorf("LoadConfig error = %v, want \"tlsCert must be a string\"", err)
	}
}
