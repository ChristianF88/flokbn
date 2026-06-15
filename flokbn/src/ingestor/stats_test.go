package ingestor

import (
	"testing"
	"time"

	lj "github.com/elastic/go-lumber/lj"
)

func TestParseEvent_CountsMalformedStatusAndBytes(t *testing.T) {
	cases := []struct {
		name          string
		log           string
		wantMalformed int
		wantStatus    uint16
		wantBytes     uint32
	}{
		{
			name:          "BothValid",
			log:           `192.168.1.1 - - [12/Mar/2024:15:04:05 -0700] "GET / HTTP/1.1" 200 10 "-" "UA"`,
			wantMalformed: 0, wantStatus: 200, wantBytes: 10,
		},
		{
			name:          "BadStatus",
			log:           `192.168.1.1 - - [12/Mar/2024:15:04:05 -0700] "GET / HTTP/1.1" oops 10 "-" "UA"`,
			wantMalformed: 1, wantStatus: 0, wantBytes: 10,
		},
		{
			name:          "BadBytes",
			log:           `192.168.1.1 - - [12/Mar/2024:15:04:05 -0700] "GET / HTTP/1.1" 200 - "-" "UA"`,
			wantMalformed: 1, wantStatus: 200, wantBytes: 0,
		},
		{
			name:          "BothBad",
			log:           `192.168.1.1 - - [12/Mar/2024:15:04:05 -0700] "GET / HTTP/1.1" oops - "-" "UA"`,
			wantMalformed: 2, wantStatus: 0, wantBytes: 0,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var req Request
			malformed, err := parseEvent(map[string]interface{}{"message": tc.log}, &req)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if malformed != tc.wantMalformed {
				t.Errorf("malformed = %d, want %d", malformed, tc.wantMalformed)
			}
			if req.Status != tc.wantStatus {
				t.Errorf("Status = %d, want %d", req.Status, tc.wantStatus)
			}
			if req.Bytes != tc.wantBytes {
				t.Errorf("Bytes = %d, want %d", req.Bytes, tc.wantBytes)
			}
		})
	}
}

func TestReadBatch_UpdatesStats(t *testing.T) {
	ing := &TCPIngestor{
		events: make(chan *lj.Batch, 4),
	}

	if st := ing.Stats(); st != (IngestStats{}) {
		t.Errorf("fresh ingestor Stats() = %+v, want zero value", st)
	}

	valid := `10.0.0.1 - - [12/Mar/2024:15:04:05 -0700] "GET /a HTTP/1.1" 200 5 "-" "UA"`
	badStatus := `10.0.0.2 - - [12/Mar/2024:15:04:05 -0700] "GET /b HTTP/1.1" oops 5 "-" "UA"`
	unparseable := map[string]interface{}{} // missing message field
	before := time.Now()
	ing.events <- makeBatch(
		map[string]interface{}{"message": valid},
		map[string]interface{}{"message": badStatus},
		unparseable,
		"not a map", // ignored entirely, no counter
	)
	ing.events <- makeBatch(map[string]interface{}{"message": valid})

	got, err := ing.ReadBatch()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("expected 3 parsed requests, got %d", len(got))
	}

	st := ing.Stats()
	if st.BatchesTotal != 2 {
		t.Errorf("BatchesTotal = %d, want 2", st.BatchesTotal)
	}
	if st.RequestsTotal != 3 {
		t.Errorf("RequestsTotal = %d, want 3", st.RequestsTotal)
	}
	if st.ParseErrorsTotal != 1 {
		t.Errorf("ParseErrorsTotal = %d, want 1", st.ParseErrorsTotal)
	}
	if st.MalformedFieldsTotal != 1 {
		t.Errorf("MalformedFieldsTotal = %d, want 1", st.MalformedFieldsTotal)
	}
	if st.QueueDepth != 0 {
		t.Errorf("QueueDepth = %d, want 0 after drain", st.QueueDepth)
	}
	if st.LastBatchAt.Before(before) || st.LastBatchAt.After(time.Now()) {
		t.Errorf("LastBatchAt = %v, want within [%v, now]", st.LastBatchAt, before)
	}
}
