package ingestor

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"os"
	"testing"
	"time"

	v2 "github.com/elastic/go-lumber/client/v2"

	"github.com/ChristianF88/flokbn/testutil"
)

func serverTLS(t *testing.T, f testutil.TLSFiles, mutual bool) *tls.Config {
	t.Helper()
	cert, err := tls.LoadX509KeyPair(f.ServerCert, f.ServerKey)
	if err != nil {
		t.Fatalf("loading server key pair: %v", err)
	}
	cfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	if mutual {
		cfg.ClientCAs = caPool(t, f)
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return cfg
}

func caPool(t *testing.T, f testutil.TLSFiles) *x509.CertPool {
	t.Helper()
	pem, err := os.ReadFile(f.CA)
	if err != nil {
		t.Fatalf("reading CA: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		t.Fatal("CA file holds no certificate")
	}
	return pool
}

func clientTLS(t *testing.T, f testutil.TLSFiles, withCert bool) *tls.Config {
	t.Helper()
	cfg := &tls.Config{RootCAs: caPool(t, f), ServerName: "localhost", MinVersion: tls.VersionTLS12}
	if withCert {
		cert, err := tls.LoadX509KeyPair(f.ClientCert, f.ClientKey)
		if err != nil {
			t.Fatalf("loading client key pair: %v", err)
		}
		cfg.Certificates = []tls.Certificate{cert}
	}
	return cfg
}

// sendOverTLS sends one event through go-lumber's client over TLS and
// returns the send error.
func sendOverTLS(t *testing.T, ing *TCPIngestor, cfg *tls.Config) error {
	t.Helper()
	client, err := v2.SyncDialWith(func(network, addr string) (net.Conn, error) {
		return tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, network, addr, cfg)
	}, ing.Addr().String(), v2.Timeout(5*time.Second))
	if err != nil {
		return err
	}
	defer client.Close()
	_, err = client.Send([]interface{}{map[string]interface{}{"message": testLine}})
	return err
}

func TestTLS_ServerOnlyAcceptsVerifiedSession(t *testing.T) {
	f := testutil.WriteTLSFiles(t)
	ing, _ := startIngestor(t, Options{TLS: serverTLS(t, f, false)})

	if err := sendOverTLS(t, ing, clientTLS(t, f, false)); err != nil {
		t.Fatalf("send over TLS: %v", err)
	}
	if got := readAll(t, ing, 1); got[0].URI != "/ok" {
		t.Errorf("request = %+v, want URI /ok", got[0])
	}
}

// A plain-TCP Lumberjack client must not get through a TLS listener.
func TestTLS_PlainClientIsRejected(t *testing.T) {
	f := testutil.WriteTLSFiles(t)
	ing, _ := startIngestor(t, Options{TLS: serverTLS(t, f, false)})

	c := dialRaw(t, ing)
	if _, err := c.Write(append(windowFrame(1), jsonFrame(1, messageJSON(testLine))...)); err != nil {
		t.Fatalf("write: %v", err)
	}
	// The server answers the bogus handshake with a TLS alert and closes; it
	// never sends a Lumberjack ack.
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 64)
	for {
		n, err := c.Read(buf)
		if n >= 2 && buf[0] == '2' && buf[1] == 'A' {
			t.Fatal("plain client got a Lumberjack ack from a TLS listener")
		}
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				t.Fatal("TLS listener kept a plain connection open")
			}
			break
		}
	}
	waitFor(t, 5*time.Second, "connection to be dropped", func() bool {
		return ing.Stats().OpenConnections == 0
	})
	if st := ing.Stats(); st.QueueDepth != 0 || st.BatchesTotal != 0 {
		t.Errorf("stats = %+v, want nothing ingested from a plain client", st)
	}
}

// With a client CA configured, only clients presenting a certificate signed
// by it are served: this is the port's authentication.
func TestTLS_MutualRequiresClientCertificate(t *testing.T) {
	f := testutil.WriteTLSFiles(t)
	ing, _ := startIngestor(t, Options{TLS: serverTLS(t, f, true)})

	if err := sendOverTLS(t, ing, clientTLS(t, f, false)); err == nil {
		t.Fatal("client without a certificate was served by an mTLS listener")
	}
	if st := ing.Stats(); st.QueueDepth != 0 {
		t.Fatalf("QueueDepth = %d, want 0: an unauthenticated batch was queued", st.QueueDepth)
	}

	// A certificate from a different CA is no better than none.
	other := testutil.WriteTLSFiles(t)
	foreign := clientTLS(t, f, false)
	cert, err := tls.LoadX509KeyPair(other.ClientCert, other.ClientKey)
	if err != nil {
		t.Fatalf("loading foreign client key pair: %v", err)
	}
	foreign.Certificates = []tls.Certificate{cert}
	if err := sendOverTLS(t, ing, foreign); err == nil {
		t.Fatal("client with a certificate from another CA was served by an mTLS listener")
	}
	if st := ing.Stats(); st.QueueDepth != 0 {
		t.Fatalf("QueueDepth = %d, want 0: an unauthenticated batch was queued", st.QueueDepth)
	}

	if err := sendOverTLS(t, ing, clientTLS(t, f, true)); err != nil {
		t.Fatalf("client with a valid certificate rejected: %v", err)
	}
	if got := readAll(t, ing, 1); len(got) != 1 {
		t.Errorf("got %d requests, want 1", len(got))
	}
}

// A peer that connects and never starts the handshake is dropped after the
// read timeout instead of holding a connection slot forever.
func TestTLS_HandshakeIsBounded(t *testing.T) {
	f := testutil.WriteTLSFiles(t)
	ing, _ := startIngestor(t, Options{TLS: serverTLS(t, f, false), ReadTimeout: 100 * time.Millisecond})
	c := dialRaw(t, ing)
	expectClosed(t, c)
	waitFor(t, 5*time.Second, "connection to be dropped", func() bool {
		return ing.Stats().OpenConnections == 0
	})
}
