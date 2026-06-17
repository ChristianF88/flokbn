package ingestor

import (
	"fmt"
	"testing"
	"time"

	v2 "github.com/elastic/go-lumber/client/v2"
)

// apacheLine builds a combined-log-format line that parseEvent understands.
func apacheLine(ip string, ts time.Time, uri string) string {
	return fmt.Sprintf(`%s - - [%s] "GET %s HTTP/1.1" 200 123 "-" "TestUA"`,
		ip, ts.Format("02/Jan/2006:15:04:05 -0700"), uri)
}

func lumberEvent(ip string, ts time.Time, uri string) interface{} {
	return map[string]interface{}{"message": apacheLine(ip, ts, uri)}
}

// newTestIngestor listens on an ephemeral localhost port and registers
// cleanup. The read timeout is generous: it is never a synchronization
// mechanism, only a guard against dead connections.
func newTestIngestor(t *testing.T) *TCPIngestor {
	t.Helper()
	ing, err := NewTCPIngestor("127.0.0.1:0", time.Second)
	if err != nil {
		t.Fatalf("NewTCPIngestor: %v", err)
	}
	t.Cleanup(func() { ing.Close() })
	return ing
}

// waitFor polls cond every 5ms until it holds or the failure deadline hits.
func waitFor(t *testing.T, deadline time.Duration, desc string, cond func() bool) {
	t.Helper()
	end := time.Now().Add(deadline)
	for time.Now().Before(end) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", desc)
}

func TestTCPIngestor_AcceptSendReadBatch(t *testing.T) {
	ing := newTestIngestor(t)
	if err := ing.Accept(); err != nil {
		t.Fatalf("Accept: %v", err)
	}

	client, err := v2.SyncDial(ing.Addr().String())
	if err != nil {
		t.Fatalf("SyncDial: %v", err)
	}
	defer client.Close()

	now := time.Now()
	events := []interface{}{
		lumberEvent("192.0.2.1", now, "/a"),
		lumberEvent("192.0.2.2", now, "/b"),
		lumberEvent("192.0.2.3", now, "/c"),
	}
	seq, err := client.Send(events)
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if seq != 3 {
		t.Fatalf("Send seq = %d, want 3", seq)
	}

	// Send returning means the batch was ACKed, and ACK happens after the
	// batch entered the events channel: one ReadBatch must see all 3.
	got, err := ing.ReadBatch()
	if err != nil {
		t.Fatalf("ReadBatch: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("ReadBatch returned %d requests, want 3", len(got))
	}
	if got[0].IP.String() != "192.0.2.1" || got[1].IP.String() != "192.0.2.2" || got[2].IP.String() != "192.0.2.3" {
		t.Errorf("unexpected IPs: %v %v %v", got[0].IP, got[1].IP, got[2].IP)
	}
	if got[0].IPUint32 == 0 {
		t.Error("IPUint32 not set on parsed request")
	}
	if got[0].URI != "/a" {
		t.Errorf("URI = %q, want /a", got[0].URI)
	}
	if got[0].UserAgent != "TestUA" {
		t.Errorf("UserAgent = %q, want TestUA", got[0].UserAgent)
	}
	if got[0].Status != 200 {
		t.Errorf("Status = %d, want 200", got[0].Status)
	}
}

func TestTCPIngestor_MultipleSendsAccumulate(t *testing.T) {
	ing := newTestIngestor(t)
	if err := ing.Accept(); err != nil {
		t.Fatalf("Accept: %v", err)
	}

	client, err := v2.SyncDial(ing.Addr().String())
	if err != nil {
		t.Fatalf("SyncDial: %v", err)
	}
	defer client.Close()

	now := time.Now()
	if _, err := client.Send([]interface{}{
		lumberEvent("198.51.100.1", now, "/x"),
		lumberEvent("198.51.100.2", now, "/y"),
	}); err != nil {
		t.Fatalf("first Send: %v", err)
	}
	if _, err := client.Send([]interface{}{
		lumberEvent("198.51.100.3", now, "/z"),
	}); err != nil {
		t.Fatalf("second Send: %v", err)
	}

	got, err := ing.ReadBatch()
	if err != nil {
		t.Fatalf("ReadBatch: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("ReadBatch returned %d requests, want 3 (both sends drained)", len(got))
	}
}

func TestTCPIngestor_CloseTransitionsIsClosed(t *testing.T) {
	ing := newTestIngestor(t)
	if err := ing.Accept(); err != nil {
		t.Fatalf("Accept: %v", err)
	}

	client, err := v2.SyncDial(ing.Addr().String())
	if err != nil {
		t.Fatalf("SyncDial: %v", err)
	}
	if _, err := client.Send([]interface{}{
		lumberEvent("203.0.113.7", time.Now(), "/q"),
	}); err != nil {
		t.Fatalf("Send: %v", err)
	}

	if err := client.Close(); err != nil {
		t.Fatalf("client Close: %v", err)
	}
	// Closing the ingestor closes the lumber server, which closes
	// ReceiveChan; the pump goroutine then flips the closed flag.
	ing.Close() // double-close of the listener via cleanup is tolerated

	waitFor(t, 5*time.Second, "ingestor to report closed", ing.IsClosed)

	// The already-received batch must still be readable, then empty reads
	// return cleanly with no error.
	got, err := ing.ReadBatch()
	if err != nil {
		t.Fatalf("ReadBatch after close: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("ReadBatch returned %d requests, want the 1 buffered request", len(got))
	}
	got, err = ing.ReadBatch()
	if err != nil {
		t.Fatalf("second ReadBatch after close: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("second ReadBatch returned %d requests, want 0", len(got))
	}
}

// TestTCPIngestor_CloseNoSpuriousError is the URGENT-09 repro: Close() used to
// close the lumber server (which already closes the listener) and THEN close
// the listener a second time, storing a spurious "use of closed network
// connection" error and discarding the real server error. Close must now return
// nil for a healthy shutdown and stay idempotent across repeated calls.
func TestTCPIngestor_CloseNoSpuriousError(t *testing.T) {
	t.Run("after Accept", func(t *testing.T) {
		ing := newTestIngestor(t)
		if err := ing.Accept(); err != nil {
			t.Fatalf("Accept: %v", err)
		}
		if err := ing.Close(); err != nil {
			t.Errorf("first Close() = %v, want nil (no double-close error)", err)
		}
		// Idempotent: repeated Close calls return the same (nil) result.
		if err := ing.Close(); err != nil {
			t.Errorf("second Close() = %v, want nil (idempotent)", err)
		}
		if !ing.IsClosed() {
			// IsClosed flips once the pump goroutine observes the closed channel.
			waitFor(t, 5*time.Second, "ingestor to report closed", ing.IsClosed)
		}
	})

	t.Run("without Accept (listener-only path)", func(t *testing.T) {
		ing := newTestIngestor(t)
		// server is nil: Close must close the listener and report no error.
		if err := ing.Close(); err != nil {
			t.Errorf("Close() without Accept = %v, want nil", err)
		}
		if err := ing.Close(); err != nil {
			t.Errorf("second Close() = %v, want nil (idempotent)", err)
		}
	})
}

func TestTCPIngestor_IsClosedBeforeAccept(t *testing.T) {
	ing := newTestIngestor(t)
	if !ing.IsClosed() {
		t.Error("IsClosed() = false before Accept, want true (no server yet)")
	}
}

func TestTCPIngestor_NewBadAddrFails(t *testing.T) {
	ing, err := NewTCPIngestor("127.0.0.1:1:bogus", time.Second)
	if err == nil {
		ing.Close()
		t.Fatal("NewTCPIngestor with malformed address succeeded, want error")
	}
}
