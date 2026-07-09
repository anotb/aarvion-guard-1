package sinks

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/aarvion-ai/aarvion-guard/internal/decisions"
)

// webhookQueue bounds the outstanding deny-webhook backlog. Denies are rare
// relative to allows, so this is generous; at the cap we drop and count rather
// than block the decision path.
const webhookQueue = 256

// webhookTimeout keeps a slow or hung endpoint from tying up the worker.
const webhookTimeout = 5 * time.Second

// denyPayload is the small JSON body POSTed on each deny.
type denyPayload struct {
	Host      string `json:"host"`
	Method    string `json:"method"`
	Path      string `json:"path"`
	Decision  string `json:"decision"`
	Reason    string `json:"reason"`
	PolicyID  string `json:"policy_id"`
	Timestamp string `json:"timestamp"`
	Origin    string `json:"origin"`
}

// WebhookSink fires a fire-and-forget POST to a configured URL on each deny.
// Record enqueues the payload and returns immediately; a single bounded worker
// drains the queue with a short per-request timeout. Non-deny rows are ignored.
// If the queue is full the deny is dropped and counted - the decision path is
// never blocked.
type WebhookSink struct {
	url    string
	client *http.Client
	ch     chan denyPayload
	done   chan struct{}

	closeMu sync.Mutex
	closed  bool

	mu      sync.Mutex
	dropped int
}

// NewWebhook starts the worker goroutine posting denies to url.
func NewWebhook(url string) *WebhookSink {
	s := &WebhookSink{
		url:    url,
		client: &http.Client{Timeout: webhookTimeout},
		ch:     make(chan denyPayload, webhookQueue),
		done:   make(chan struct{}),
	}
	go s.run()
	return s
}

// Record is the decisions.Sink hook. Only denies fire; everything else is a
// no-op. Non-blocking: a full queue drops the deny and counts it.
func (s *WebhookSink) Record(rec decisions.Record) {
	if rec.Decision != "deny" {
		return
	}
	p := denyPayload{
		Host:      rec.Host,
		Method:    rec.Method,
		Path:      rec.Path,
		Decision:  rec.Decision,
		Reason:    rec.Reason,
		PolicyID:  rec.PolicyID,
		Timestamp: rec.Timestamp,
		Origin:    rec.Origin,
	}
	select {
	case s.ch <- p:
	default:
		s.mu.Lock()
		s.dropped++
		s.mu.Unlock()
	}
}

func (s *WebhookSink) run() {
	defer close(s.done)
	for p := range s.ch {
		s.post(p)
	}
}

func (s *WebhookSink) post(p denyPayload) {
	body, err := json.Marshal(p)
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), webhookTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.url, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return
	}
	// Drain + close so the connection can be reused; the response is ignored
	// (fire-and-forget).
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
}

// Dropped reports denies shed because the worker queue was full.
func (s *WebhookSink) Dropped() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.dropped
}

// Close stops the worker after draining any queued denies. Safe to call more
// than once.
func (s *WebhookSink) Close() {
	s.closeMu.Lock()
	if s.closed {
		s.closeMu.Unlock()
		return
	}
	s.closed = true
	close(s.ch)
	s.closeMu.Unlock()
	<-s.done
}
