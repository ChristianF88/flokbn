package cli

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"time"
)

// statsServer serves the live loop's latest statsSnapshot over HTTP
// (GET /stats as JSON, GET /bans as the verbatim ban-file content). The loop
// publishes immutable snapshots through an atomic pointer and never blocks
// on consumers; handlers serialize on demand.
type statsServer struct {
	ln   net.Listener
	srv  *http.Server
	snap atomic.Pointer[statsSnapshot]
	done chan struct{} // closed when Serve returns
}

// newStatsServer binds the listener immediately so a bad listen address
// fails fast, before the live loop starts.
func newStatsServer(listenAddr string) (*statsServer, error) {
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return nil, err
	}
	s := &statsServer{ln: ln, done: make(chan struct{})}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /stats", s.handleStats)
	mux.HandleFunc("GET /bans", s.handleBans)
	mux.HandleFunc("GET /metrics", s.handleMetrics)
	s.srv = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	return s, nil
}

// addr returns the bound listen address (resolves ":0" in tests).
func (s *statsServer) addr() string {
	return s.ln.Addr().String()
}

func (s *statsServer) start() {
	go func() {
		// Serve returns http.ErrServerClosed after Shutdown; nothing to do
		// with it either way, done signals the exit.
		_ = s.srv.Serve(s.ln)
		close(s.done)
	}()
}

func (s *statsServer) shutdown() {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = s.srv.Shutdown(ctx)
	<-s.done
}

func (s *statsServer) publish(sn *statsSnapshot) {
	s.snap.Store(sn)
}

// loadOr503 returns the latest snapshot, or replies 503 (with Retry-After)
// and returns nil when the loop has not published one yet.
func (s *statsServer) loadOr503(w http.ResponseWriter) *statsSnapshot {
	sn := s.snap.Load()
	if sn == nil {
		w.Header().Set("Retry-After", "5")
		http.Error(w, "no snapshot yet", http.StatusServiceUnavailable)
		return nil
	}
	return sn
}

func (s *statsServer) handleStats(w http.ResponseWriter, _ *http.Request) {
	sn := s.loadOr503(w)
	if sn == nil {
		return
	}
	body, err := json.MarshalIndent(sn, "", "  ")
	if err != nil {
		http.Error(w, "marshaling snapshot: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(body)
}

func (s *statsServer) handleBans(w http.ResponseWriter, _ *http.Request) {
	sn := s.loadOr503(w)
	if sn == nil {
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = io.WriteString(w, sn.banFileContent)
}

func (s *statsServer) handleMetrics(w http.ResponseWriter, _ *http.Request) {
	sn := s.loadOr503(w)
	if sn == nil {
		return
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	_, _ = w.Write(renderMetrics(sn))
}
