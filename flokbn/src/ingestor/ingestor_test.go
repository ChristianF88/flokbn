package ingestor

import (
	"net"
	"testing"

	lj "github.com/elastic/go-lumber/lj"
)

func TestParseEvent_MissingMessageField(t *testing.T) {
	evt := map[string]interface{}{}
	var req Request
	_, err := parseEvent(evt, &req)
	if err == nil || err.Error() != "missing message field" {
		t.Errorf("expected missing message field error, got %v", err)
	}
}

func TestParseEvent_InvalidIP(t *testing.T) {
	log := `notanip - - [12/Mar/2024:15:04:05 -0700] "GET / HTTP/1.1" 200 10 "-" "UA"`
	evt := map[string]interface{}{"message": log}
	var req Request
	_, err := parseEvent(evt, &req)
	if err == nil || err.Error() != "invalid IP" {
		t.Errorf("expected invalid IP error, got %v", err)
	}
}

func TestParseEvent_InvalidTimestamp(t *testing.T) {
	log := `192.168.1.1 - - [badtime] "GET / HTTP/1.1" 200 10 "-" "UA"`
	evt := map[string]interface{}{"message": log}
	var req Request
	_, err := parseEvent(evt, &req)
	if err == nil {
		t.Errorf("expected error for invalid timestamp, got nil")
	}
}

func TestParseEvent_SetsIPUint32(t *testing.T) {
	log := `192.168.1.100 - - [12/Mar/2024:15:04:05 -0700] "GET / HTTP/1.1" 200 10 "-" "UA"`
	evt := map[string]interface{}{"message": log}
	var req Request
	_, err := parseEvent(evt, &req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// 192.168.1.100 = (192<<24) | (168<<16) | (1<<8) | 100 = 3232235876
	want := uint32(192)<<24 | uint32(168)<<16 | uint32(1)<<8 | 100
	if req.IPUint32 != want {
		t.Errorf("expected IPUint32 %d, got %d", want, req.IPUint32)
	}
	if req.IP.String() != "192.168.1.100" {
		t.Errorf("expected IP 192.168.1.100, got %v", req.IP)
	}
}

func TestParseEvent_UnknownMethod(t *testing.T) {
	log := `192.168.1.1 - - [12/Mar/2024:15:04:05 -0700] "FOO /foo HTTP/1.1" 404 0 "-" "UA"`
	evt := map[string]interface{}{"message": log}
	var req Request
	_, err := parseEvent(evt, &req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.Method != UNKNOWN {
		t.Errorf("expected UNKNOWN method, got %v", req.Method)
	}
	if req.Status != 404 {
		t.Errorf("expected status 404, got %v", req.Status)
	}
	if req.UserAgent != "UA" {
		t.Errorf("expected UserAgent UA, got %v", req.UserAgent)
	}
}

func TestParseEvent_MissingUserAgent(t *testing.T) {
	// Only 5 quotes, so user agent will be empty
	log := `192.168.1.1 - - [12/Mar/2024:15:04:05 -0700] "GET / HTTP/1.1" 200 10 "-" `
	evt := map[string]interface{}{"message": log}
	var req Request
	_, err := parseEvent(evt, &req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.UserAgent != "" {
		t.Errorf("expected empty UserAgent, got %v", req.UserAgent)
	}
}

// TestParseEvent_TruncatedAtRequestEndQuote is the exact URGENT-01 repro: a
// message ending precisely at the closing request-line quote. Before the
// bounds-check, msg[end+2:] panicked (end+2 == len(msg)+1). It must now parse
// without panic, leaving Status and Bytes at zero and returning no error.
func TestParseEvent_TruncatedAtRequestEndQuote(t *testing.T) {
	log := `192.168.1.1 - - [12/Mar/2024:15:04:05 -0700] "GET / HTTP/1.1"`
	evt := map[string]interface{}{"message": log}
	var req Request
	malformed, err := parseEvent(evt, &req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if malformed != 0 {
		t.Errorf("expected 0 malformed fields, got %d", malformed)
	}
	if req.Status != 0 {
		t.Errorf("expected Status 0, got %d", req.Status)
	}
	if req.Bytes != 0 {
		t.Errorf("expected Bytes 0, got %d", req.Bytes)
	}
	if req.Method != GET {
		t.Errorf("expected GET method, got %v", req.Method)
	}
	if req.URI != "/" {
		t.Errorf("expected URI /, got %v", req.URI)
	}
}

// TestReadBatch_SurvivesTruncatedEvent proves the live-loop path (ReadBatch ->
// parseEventSafe -> parseEvent) does not panic on the truncated line and that
// the bounds-checked event parses successfully (it is a valid request, just
// without a status/bytes tail), so it IS included in output and is NOT counted
// as a parse error.
func TestReadBatch_SurvivesTruncatedEvent(t *testing.T) {
	ing := &TCPIngestor{
		events: make(chan *lj.Batch, 1),
	}
	truncated := `192.168.1.1 - - [12/Mar/2024:15:04:05 -0700] "GET / HTTP/1.1"`
	valid := `10.0.0.1 - - [12/Mar/2024:15:04:05 -0700] "GET /ok HTTP/1.1" 200 1 "-" "UA"`
	ing.events <- makeBatch(
		map[string]interface{}{"message": truncated},
		map[string]interface{}{"message": valid},
	)

	got, err := ing.ReadBatch()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Both events parse: truncated one (no status/bytes tail) + the valid one.
	if len(got) != 2 {
		t.Fatalf("expected 2 results, got %d", len(got))
	}
	if got[0].URI != "/" || got[0].Status != 0 || got[0].Bytes != 0 {
		t.Errorf("truncated event mis-parsed: %+v", got[0])
	}
	if got[1].URI != "/ok" {
		t.Errorf("expected second URI /ok, got %v", got[1].URI)
	}

	// The truncated line is handled by the bounds-check, NOT the recover path,
	// so it must not be counted as a parse error.
	st := ing.Stats()
	if st.ParseErrorsTotal != 0 {
		t.Errorf("ParseErrorsTotal = %d, want 0 (truncated line parses cleanly)", st.ParseErrorsTotal)
	}
	if st.RequestsTotal != 2 {
		t.Errorf("RequestsTotal = %d, want 2", st.RequestsTotal)
	}
	if st.MalformedFieldsTotal != 0 {
		t.Errorf("MalformedFieldsTotal = %d, want 0", st.MalformedFieldsTotal)
	}
}

// TestParseEventSafe_Transparent verifies the recover wrapper is transparent
// for normal input: it returns exactly what parseEvent returns (same malformed
// count, same error) for valid and for already-erroring events, so the
// recover() guard adds no behavior change on the non-panicking path.
func TestParseEventSafe_Transparent(t *testing.T) {
	valid := `192.168.1.1 - - [12/Mar/2024:15:04:05 -0700] "GET / HTTP/1.1" 200 10 "-" "UA"`
	var a, b Request
	mA, eA := parseEvent(map[string]interface{}{"message": valid}, &a)
	mB, eB := parseEventSafe(map[string]interface{}{"message": valid}, &b)
	if mA != mB || (eA == nil) != (eB == nil) {
		t.Errorf("safe wrapper diverged on valid: (%d,%v) vs (%d,%v)", mA, eA, mB, eB)
	}
	// Request contains a net.IP slice, so compare the parsed fields directly.
	if a.IPUint32 != b.IPUint32 || a.Status != b.Status || a.Bytes != b.Bytes ||
		a.Method != b.Method || a.URI != b.URI || a.UserAgent != b.UserAgent ||
		!a.Timestamp.Equal(b.Timestamp) || !a.IP.Equal(b.IP) {
		t.Errorf("safe wrapper produced different Request: %+v vs %+v", a, b)
	}

	// Erroring input: missing message field must still surface as an error
	// (not a recovered panic) with malformed == 0.
	m, err := parseEventSafe(map[string]interface{}{}, &Request{})
	if err == nil {
		t.Errorf("expected error for missing message field, got nil")
	}
	if m != 0 {
		t.Errorf("expected 0 malformed, got %d", m)
	}
}

func makeBatch(events ...interface{}) *lj.Batch {
	return &lj.Batch{
		Events: events,
	}
}

func TestReadBatch_EmptyChannel(t *testing.T) {
	ing := &TCPIngestor{
		events: make(chan *lj.Batch),
	}
	// Channel is empty, should return empty slice
	got, err := ing.ReadBatch()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected empty result, got %v", got)
	}
}

func TestReadBatch_ClosedChannel(t *testing.T) {
	ing := &TCPIngestor{
		events: make(chan *lj.Batch),
	}
	close(ing.events)
	got, err := ing.ReadBatch()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected empty result, got %v", got)
	}
}

func TestReadBatch_ValidEvents(t *testing.T) {
	ing := &TCPIngestor{
		events: make(chan *lj.Batch, 1),
	}
	log := `127.0.0.1 - - [12/Mar/2024:15:04:05 -0700] "GET /foo HTTP/1.1" 200 123 "-" "TestUA"`
	evt := map[string]interface{}{"message": log}
	ing.events <- makeBatch(evt)
	got, err := ing.ReadBatch()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 result, got %d", len(got))
	}
	wantIP := net.ParseIP("127.0.0.1")
	if !got[0].IP.Equal(wantIP) {
		t.Errorf("expected IP %v, got %v", wantIP, got[0].IP)
	}
	if got[0].Method != GET {
		t.Errorf("expected GET method, got %v", got[0].Method)
	}
	if got[0].URI != "/foo" {
		t.Errorf("expected URI /foo, got %v", got[0].URI)
	}
	if got[0].Status != 200 {
		t.Errorf("expected status 200, got %v", got[0].Status)
	}
	if got[0].Bytes != 123 {
		t.Errorf("expected bytes 123, got %v", got[0].Bytes)
	}
	if got[0].UserAgent != "TestUA" {
		t.Errorf("expected UserAgent TestUA, got %v", got[0].UserAgent)
	}
}

func TestReadBatch_MultipleEventsAndBatches(t *testing.T) {
	ing := &TCPIngestor{
		events: make(chan *lj.Batch, 2),
	}
	log1 := `10.0.0.1 - - [12/Mar/2024:15:04:05 -0700] "POST /bar HTTP/1.1" 201 10 "-" "UA1"`
	log2 := `10.0.0.2 - - [12/Mar/2024:15:05:05 -0700] "GET /baz HTTP/1.1" 404 0 "-" "UA2"`
	evt1 := map[string]interface{}{"message": log1}
	evt2 := map[string]interface{}{"message": log2}
	ing.events <- makeBatch(evt1)
	ing.events <- makeBatch(evt2)
	got, err := ing.ReadBatch()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 results, got %d", len(got))
	}
	if got[0].IP.String() != "10.0.0.1" || got[1].IP.String() != "10.0.0.2" {
		t.Errorf("unexpected IPs: %v, %v", got[0].IP, got[1].IP)
	}
	if got[0].Method != POST || got[1].Method != GET {
		t.Errorf("unexpected methods: %v, %v", got[0].Method, got[1].Method)
	}
}

func TestReadBatch_SkipsInvalidEvents(t *testing.T) {
	ing := &TCPIngestor{
		events: make(chan *lj.Batch, 1),
	}
	// First event is invalid (missing message), second is valid
	evt1 := map[string]interface{}{}
	log := `127.0.0.1 - - [12/Mar/2024:15:04:05 -0700] "GET /ok HTTP/1.1" 200 1 "-" "UA"`
	evt2 := map[string]interface{}{"message": log}
	ing.events <- makeBatch(evt1, evt2)
	got, err := ing.ReadBatch()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 valid result, got %d", len(got))
	}
	if got[0].URI != "/ok" {
		t.Errorf("expected URI /ok, got %v", got[0].URI)
	}
}

func TestReadBatch_NonMapEventsAreIgnored(t *testing.T) {
	ing := &TCPIngestor{
		events: make(chan *lj.Batch, 1),
	}
	ing.events <- makeBatch("not a map", 123, nil)
	got, err := ing.ReadBatch()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected 0 results, got %d", len(got))
	}
}
