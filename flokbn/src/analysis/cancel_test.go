package analysis

import (
	"context"
	"errors"
	"os"
	"sync/atomic"
	"testing"
)

// cancelAfterCtx reports "not cancelled" for the first okChecks calls of Err
// and context.Canceled from then on, so a test can cancel a run at a chosen
// checkpoint without racing the analysis.
type cancelAfterCtx struct {
	context.Context
	okChecks int32
	checks   atomic.Int32
}

func (c *cancelAfterCtx) Err() error {
	if c.checks.Add(1) > c.okChecks {
		return context.Canceled
	}
	return nil
}

func assertNoPublish(t *testing.T, jailFile, banFile string) {
	t.Helper()
	for _, f := range []string{jailFile, banFile} {
		if _, err := os.Stat(f); !os.IsNotExist(err) {
			t.Errorf("cancelled run must not write %s (stat err = %v)", f, err)
		}
	}
}

// TestStaticWithRequestsCtxCancelledBeforeStart: an already cancelled context
// returns before any parsing - no requests, no trie results, no jail/ban files.
func TestStaticWithRequestsCtxCancelledBeforeStart(t *testing.T) {
	cfg := publishErrorCfg(t, t.TempDir(), false)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	out, requests, err := StaticWithRequestsCtx(ctx, cfg)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if out == nil {
		t.Fatal("expected an output object next to the error")
	}
	if requests != nil || len(out.Tries) != 0 || out.General.TotalRequests != 0 {
		t.Errorf("cancelled-before-start run did work: %d requests, %d tries, total %d",
			len(requests), len(out.Tries), out.General.TotalRequests)
	}
	if len(out.Errors) != 0 {
		t.Errorf("cancellation is not an analysis error, got %+v", out.Errors)
	}
	assertNoPublish(t, cfg.GetJailFile(), cfg.GetBanFile())
}

// TestStaticWithRequestsCtxCancelledBeforePublish: a run cancelled after the
// trie phase hands back the parsed requests but skips the jail/ban side
// effects. Same on the empty-log exit, which would otherwise still publish.
func TestStaticWithRequestsCtxCancelledBeforePublish(t *testing.T) {
	for _, filtered := range []bool{false, true} {
		cfg := publishErrorCfg(t, t.TempDir(), filtered)
		ctx := &cancelAfterCtx{Context: context.Background(), okChecks: 1}

		out, requests, err := StaticWithRequestsCtx(ctx, cfg)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("filtered=%v: err = %v, want context.Canceled", filtered, err)
		}
		if len(requests) != 300 || out.General.TotalRequests != 300 {
			t.Errorf("filtered=%v: got %d requests (total %d), want the 300 parsed ones",
				filtered, len(requests), out.General.TotalRequests)
		}
		if len(out.Errors) != 0 {
			t.Errorf("filtered=%v: cancellation is not an analysis error, got %+v", filtered, out.Errors)
		}
		if got := ctx.checks.Load(); got != 2 {
			t.Errorf("filtered=%v: context checked %d times, want 2 (before parsing, before publishing)", filtered, got)
		}
		assertNoPublish(t, cfg.GetJailFile(), cfg.GetBanFile())
	}

	t.Run("empty_log", func(t *testing.T) {
		cfg := publishCfg(t, t.TempDir(), "")
		ctx := &cancelAfterCtx{Context: context.Background(), okChecks: 1}

		out, requests, err := StaticWithRequestsCtx(ctx, cfg)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("err = %v, want context.Canceled", err)
		}
		if len(requests) != 0 || out.General.TotalRequests != 0 {
			t.Errorf("empty log produced %d requests (total %d)", len(requests), out.General.TotalRequests)
		}
		assertNoPublish(t, cfg.GetJailFile(), cfg.GetBanFile())
	})
}
