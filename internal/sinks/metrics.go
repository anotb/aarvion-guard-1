package sinks

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

// StatsSource is anything that exposes the guard's running counters. The
// decisions.Recorder satisfies it via its Stats method, so the metrics server
// reads live numbers without importing (or coupling tightly to) the Recorder.
type StatsSource interface {
	Stats() (total, denies, errors, dropped int)
}

// HostStatsSource exposes per-host request/spend tallies. The HostMeter sink
// satisfies it, so the metrics server can render per-destination series without
// coupling to the meter's internals. A nil HostStatsSource means no per-host
// series are emitted.
type HostStatsSource interface {
	Snapshot() []HostSample
}

// MetricsServer serves a tiny Prometheus text-exposition-format /metrics
// endpoint on a configured addr, exposing the counters already tracked by the
// Recorder. No external prometheus client dep - the text format is hand-written.
type MetricsServer struct {
	addr    string
	src     StatsSource
	hostSrc HostStatsSource
	srv     *http.Server
}

// NewMetrics builds (but does not start) the metrics server. hostSrc is optional
// (nil disables the per-host series).
func NewMetrics(addr string, src StatsSource, hostSrc HostStatsSource) *MetricsServer {
	m := &MetricsServer{addr: addr, src: src, hostSrc: hostSrc}
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
	if m.hostSrc != nil {
		writeHostMetrics(w, m.hostSrc.Snapshot())
	}
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

// writeHostMetrics renders the per-destination-host series: a request counter
// split by decision, and an estimated-spend gauge. Split out from handle so
// tests can assert the exact exposition text without a server.
func writeHostMetrics(w interface{ Write([]byte) (int, error) }, samples []HostSample) {
	if len(samples) == 0 {
		return
	}
	fmt.Fprint(w, "# HELP aarvion_guard_host_requests_total Requests per destination host, split by decision.\n")
	fmt.Fprint(w, "# TYPE aarvion_guard_host_requests_total counter\n")
	for _, s := range samples {
		h := escapeLabelValue(s.Host)
		fmt.Fprintf(w, "aarvion_guard_host_requests_total{host=\"%s\",decision=\"allow\"} %d\n", h, s.Allow)
		fmt.Fprintf(w, "aarvion_guard_host_requests_total{host=\"%s\",decision=\"deny\"} %d\n", h, s.Deny)
	}
	fmt.Fprint(w, "# HELP aarvion_guard_host_estimated_spend_usd Estimated USD spend per host (allowed requests x configured per-request cost).\n")
	fmt.Fprint(w, "# TYPE aarvion_guard_host_estimated_spend_usd gauge\n")
	for _, s := range samples {
		fmt.Fprintf(w, "aarvion_guard_host_estimated_spend_usd{host=\"%s\"} %.6f\n", escapeLabelValue(s.Host), s.SpendUSD)
	}
}

// escapeLabelValue escapes a Prometheus label value: backslash, double-quote,
// and newline, per the text exposition format. Hostnames don't normally contain
// these, but a spoofed/garbage Host must not be able to break the output.
func escapeLabelValue(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	return s
}
