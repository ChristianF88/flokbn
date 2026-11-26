package cli

import (
	"sync"
	"testing"
	"time"

	"github.com/ChristianF88/flokbn/accesslog"
	"github.com/ChristianF88/flokbn/config"
	"github.com/ChristianF88/flokbn/ingestor"
)

// ============================================================================
// A5: the batch queued right before the ingestor closes is not skipped
// ============================================================================

// lateBatchIngestor reproduces the shutdown race: its first ReadBatch finds
// the queue empty, then a batch is queued and the ingestor closes before the
// loop asks IsClosed.
type lateBatchIngestor struct {
	mu    sync.Mutex
	late  []accesslog.Request
	reads int
}

func (l *lateBatchIngestor) Accept() error { return nil }
func (l *lateBatchIngestor) Close() error  { return nil }

func (l *lateBatchIngestor) ReadBatch() ([]accesslog.Request, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.reads++
	if l.reads == 1 {
		return nil, nil
	}
	batch := l.late
	l.late = nil
	return batch, nil
}

func (l *lateBatchIngestor) IsClosed() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.reads >= 1
}

func (l *lateBatchIngestor) Stats() ingestor.IngestStats { return ingestor.IngestStats{} }

func TestRunLiveLoop_FinalBatchBeforeCloseIsProcessed(t *testing.T) {
	now := time.Now()
	ing := &lateBatchIngestor{late: hotBlock(10, 5, 5, now, "/api/item")}
	cfg := newLiveConfig(t, map[string]*config.SlidingTrieConfig{
		"w": newWindowConfig(t, "", true),
	})
	h := startLoop(t, ing, cfg)
	if err := h.wait(10 * time.Second); err != nil {
		t.Fatalf("runLiveLoop returned error: %v", err)
	}

	var batches []int
	for _, ev := range iterationEvents(h.drainEvents()) {
		batches = append(batches, parseIteration(t, ev.rec).Batch)
	}
	if len(batches) != 1 || batches[0] != 256 {
		t.Fatalf("iterations processed batches %v, want exactly one of 256 requests (the batch queued before the close)", batches)
	}
	if bans := banCIDRs(t, cfg.GetBanFile()); len(bans) != 1 || bans[0] != "10.5.5.0/24" {
		t.Errorf("ban file CIDRs = %v, want [10.5.5.0/24] from the final batch", bans)
	}
}
