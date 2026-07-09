package sinks

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"
)

// StatsSource is anything that exposes the guard's running counters. The
// decisions.Recorder satisfies it via its Stats method, so the metrics server
// reads live numbers without importing (or coupling tightly to) the Recorder.
type StatsSource interface {
	Stats() (total, denies, errors, dropped int)
}

// MetricsServer serves a tiny Prometheus text-exposition-format /metrics
// endpoint on a configured addr, exposing the counters already tracked by the
// Recorder. No external prometheus client dep - the text format is hand-written.
type MetricsServer struct {
	addr string
	src  StatsSource
	srv  *http.Server
}

// NewMetrics builds (but does not start) the metrics server.
func NewMetrics(addr string, src StatsSource) *MetricsServer {
	m := &MetricsServer{addr: addr, src: src}
	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", m.handle)
	m.srv = &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	return m
}

// Serve binds the listener and serves until ctx is cancelled, then shuts the
// server down cleanly. Binding synchronously (before the serve loop) means a bad
// addr surfaces as an error to the caller instead of vanishing in a goroutine.
func (m *MetricsServer) Serve(ctx context.Context) error {
	ln, err := net.Listen("tcp", m.addr)
	if err != nil {
		return err
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = m.srv.Shutdown(shutdownCtx)
	}()
	if err := m.srv.Serve(ln); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

// handle renders the current counters as Prometheus text exposition format.
func (m *MetricsServer) handle(w http.ResponseWriter, _ *http.Request) {
	total, denies, errors, dropped := m.src.Stats()
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	writeMetrics(w, total, denies, errors, dropped)
}

// writeMetrics writes the exposition text. Split out from handle so tests can
// assert the exact format without spinning up a server.
func writeMetrics(w interface{ Write([]byte) (int, error) }, total, denies, errors, dropped int) {
	metric := func(name, help, typ string, val int) {
		fmt.Fprintf(w, "# HELP %s %s\n", name, help)
		fmt.Fprintf(w, "# TYPE %s %s\n", name, typ)
		fmt.Fprintf(w, "%s %d\n", name, val)
	}
	metric("aarvion_guard_decisions_total", "Total decisions recorded.", "counter", total)
	metric("aarvion_guard_denies_total", "Total deny decisions recorded.", "counter", denies)
	metric("aarvion_guard_errors_total", "Total CP-push errors.", "counter", errors)
	metric("aarvion_guard_dropped_total", "Total decisions dropped at the backlog cap.", "counter", dropped)
	metric("aarvion_guard_up", "1 if the guard metrics endpoint is serving.", "gauge", 1)
}
