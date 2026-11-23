package cli

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sync"
	"syscall"
	"testing"
	"time"
)

// ============================================================================
// A6: second signal forces exit
// ============================================================================

type exitRecorder struct {
	mu    sync.Mutex
	codes []int
	ch    chan struct{}
}

func newExitRecorder() *exitRecorder { return &exitRecorder{ch: make(chan struct{}, 4)} }

func (e *exitRecorder) exit(code int) {
	e.mu.Lock()
	e.codes = append(e.codes, code)
	e.mu.Unlock()
	e.ch <- struct{}{}
}

func (e *exitRecorder) calls() []int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]int(nil), e.codes...)
}

func TestWatchShutdownSignals_SecondSignalForcesExit(t *testing.T) {
	sig := make(chan os.Signal, 2)
	finished := make(chan struct{})
	defer close(finished)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	exits := newExitRecorder()
	go watchShutdownSignals(sig, finished, cancel, slog.New(slog.NewTextHandler(io.Discard, nil)), exits.exit)

	// First signal: graceful shutdown only.
	sig <- syscall.SIGINT
	select {
	case <-ctx.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("first signal did not cancel the live loop")
	}
	select {
	case <-exits.ch:
		t.Fatalf("first signal forced an exit (codes %v), want graceful shutdown only", exits.calls())
	case <-time.After(100 * time.Millisecond):
	}

	// Second signal while shutdown is still in progress: must not be swallowed.
	sig <- syscall.SIGINT
	select {
	case <-exits.ch:
	case <-time.After(5 * time.Second):
		t.Fatal("second signal was swallowed: no forced exit")
	}
	if got := exits.calls(); len(got) != 1 || got[0] != 1 {
		t.Errorf("exit calls = %v, want [1]", got)
	}
}

func TestWatchShutdownSignals_ReturnsWhenLoopFinishes(t *testing.T) {
	for _, afterFirstSignal := range []bool{false, true} {
		t.Run(fmt.Sprintf("afterFirstSignal=%v", afterFirstSignal), func(t *testing.T) {
			sig := make(chan os.Signal, 2)
			finished := make(chan struct{})
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			exits := newExitRecorder()
			returned := make(chan struct{})
			go func() {
				watchShutdownSignals(sig, finished, cancel, slog.New(slog.NewTextHandler(io.Discard, nil)), exits.exit)
				close(returned)
			}()
			if afterFirstSignal {
				sig <- syscall.SIGTERM
				<-ctx.Done()
			}
			close(finished)
			select {
			case <-returned:
			case <-time.After(5 * time.Second):
				t.Fatal("signal watcher did not return after the live loop finished")
			}
			if got := exits.calls(); len(got) != 0 {
				t.Errorf("exit calls = %v, want none", got)
			}
		})
	}
}
