// Package sinks holds the guard's pluggable, config-driven observability
// outputs. Each runs ALONGSIDE the existing CP push, fed from the same decision
// stream (via the decisions.Sink hook), so they work regardless of inspect mode.
//
// The import direction is one-way: sinks imports decisions for the Record type;
// decisions never imports sinks (it only knows the Sink interface). This keeps
// net/http and file specifics out of the decision funnel and avoids an import
// cycle.
package sinks

import (
	"bufio"
	"encoding/json"
	"os"
	"sync"

	"github.com/aarvion-ai/aarvion-guard/internal/decisions"
)

// jsonlBuffer bounds the in-memory backlog of rows waiting to be written. The
// decision path never blocks on disk: at the cap we drop the row and count it.
const jsonlBuffer = 4096

// JSONLSink appends every recorded decision as one JSON object per line to an
// on-box file (a forensic copy that survives a CP outage). Record hands the row
// to a buffered channel and returns immediately; a single writer goroutine owns
// the file. Writes never block the decision path - if the buffer is full the row
// is dropped and counted.
type JSONLSink struct {
	ch      chan decisions.Record
	f       *os.File
	w       *bufio.Writer
	done    chan struct{}
	closeMu sync.Mutex
	closed  bool

	mu      sync.Mutex
	dropped int
}

// NewJSONL opens (creating if absent) the audit file in append mode at 0600 and
// starts the writer goroutine. The caller must Close the sink on shutdown to
// flush and release the file.
func NewJSONL(path string) (*JSONLSink, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	s := &JSONLSink{
		ch:   make(chan decisions.Record, jsonlBuffer),
		f:    f,
		w:    bufio.NewWriter(f),
		done: make(chan struct{}),
	}
	go s.run()
	return s, nil
}

// Record is the decisions.Sink hook. It is non-blocking: the row is dropped
// (and counted) rather than blocking the decision path when the buffer is full.
func (s *JSONLSink) Record(rec decisions.Record) {
	select {
	case s.ch <- rec:
	default:
		s.mu.Lock()
		s.dropped++
		s.mu.Unlock()
	}
}

// run is the single writer goroutine. It owns the file and buffered writer, so
// no locking is needed around the write itself.
func (s *JSONLSink) run() {
	defer close(s.done)
	for rec := range s.ch {
		s.writeLine(rec)
	}
}

func (s *JSONLSink) writeLine(rec decisions.Record) {
	b, err := json.Marshal(rec)
	if err != nil {
		return
	}
	if _, err := s.w.Write(b); err != nil {
		return
	}
	_ = s.w.WriteByte('\n')
	// Flush per line: an audit sink's value is durability, and a decision stream
	// is low-volume relative to disk throughput.
	_ = s.w.Flush()
}

// Dropped reports rows shed because the writer could not keep up (buffer full).
func (s *JSONLSink) Dropped() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.dropped
}

// Close stops the writer goroutine, flushes any buffered bytes, and closes the
// file. Safe to call more than once.
func (s *JSONLSink) Close() error {
	s.closeMu.Lock()
	if s.closed {
		s.closeMu.Unlock()
		return nil
	}
	s.closed = true
	close(s.ch)
	s.closeMu.Unlock()

	<-s.done // wait for the writer to drain the channel
	if err := s.w.Flush(); err != nil {
		s.f.Close()
		return err
	}
	return s.f.Close()
}
