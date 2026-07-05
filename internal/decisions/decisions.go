package decisions

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"sync"
	"time"
)

// Record is one egress decision, shaped to the CP's DecisionIn model. Only the
// fields the guard populates are set; the rest serialize as null/zero.
type Record struct {
	Seq            int    `json:"seq"`
	Timestamp      string `json:"timestamp"`
	Method         string `json:"method"`
	Path           string `json:"path"`
	Host           string `json:"host"`
	Decision       string `json:"decision"`
	Enforced       bool   `json:"enforced"`
	PolicyID       string `json:"policy_id,omitempty"`
	Reason         string `json:"reason,omitempty"`
	LatencyMs      int    `json:"latency_ms"`
	BundleRevision string `json:"bundle_revision,omitempty"`
	Redactions     string `json:"redactions,omitempty"`
	ReplicaID      string `json:"replica_id,omitempty"`
	Surface        string `json:"surface,omitempty"`
	EntityID       string `json:"entity_id,omitempty"`
	Direction      string `json:"direction,omitempty"`
	PrevHash       string `json:"prev_hash"`
	RowHash        string `json:"row_hash"`
}

// hashFields matches the data plane's chain ordering so the CP verifier can
// walk this guard's chain. json.Marshal per value + Python-default spacing.
var hashFields = []string{
	"seq", "timestamp", "direction", "surface", "entity_id", "jsonrpc_method",
	"method", "path", "host", "decision", "policy_id", "reason",
	"caller_principal_id", "caller_session_id", "caller_source",
	"contract_version", "redactions", "prev_hash",
}

func rowHash(fields map[string]any) string {
	keys := make([]string, len(hashFields))
	copy(keys, hashFields)
	sort.Strings(keys)
	var b bytes.Buffer
	b.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			b.WriteString(", ")
		}
		kb, _ := json.Marshal(k)
		b.Write(kb)
		b.WriteString(": ")
		vb, _ := json.Marshal(fields[k])
		b.Write(vb)
	}
	b.WriteByte('}')
	sum := sha256.Sum256(b.Bytes())
	return hex.EncodeToString(sum[:])
}

// Recorder accumulates decisions, collapses repeated identical allows, and
// pushes batches to the CP.
type Recorder struct {
	cpURL     string
	tenant    string
	entityID  string
	token     string
	dpID      string

	mu      sync.Mutex
	seq     int
	prev    string
	pending []Record
	sampled map[string]int

	denies int
	errors int
	total  int
}

func New(cpURL, tenant, entityID, token, dpID string) *Recorder {
	return &Recorder{
		cpURL:    cpURL,
		tenant:   tenant,
		entityID: entityID,
		token:    token,
		dpID:     dpID,
		prev:     "0",
		sampled:  map[string]int{},
	}
}

// Add records a decision. Denies/redacts are always queued; repeated identical
// allows are collapsed within the flush window to avoid flooding the CP.
func (r *Recorder) Add(method, host, path, decision, policyID, reason, redactions string, enforced bool, latencyMs int) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.total++
	if decision == "deny" {
		r.denies++
	}

	if decision == "allow" {
		sig := method + " " + host + path
		if _, seen := r.sampled[sig]; seen {
			r.sampled[sig]++
			return
		}
		r.sampled[sig] = 1
	}

	r.seq++
	rec := Record{
		Seq:        r.seq,
		Timestamp:  time.Now().UTC().Format(time.RFC3339Nano),
		Method:     method,
		Path:       path,
		Host:       host,
		Decision:   decision,
		Enforced:   enforced,
		PolicyID:   policyID,
		Reason:     reason,
		LatencyMs:  latencyMs,
		Redactions: redactions,
		ReplicaID:  r.dpID,
		Surface:    "egress",
		EntityID:   r.entityID,
		Direction:  "egress",
		PrevHash:   r.prev,
	}
	rec.RowHash = rowHash(map[string]any{
		"seq": rec.Seq, "timestamp": rec.Timestamp, "direction": rec.Direction,
		"surface": rec.Surface, "entity_id": rec.EntityID, "jsonrpc_method": nil,
		"method": rec.Method, "path": rec.Path, "host": rec.Host,
		"decision": rec.Decision, "policy_id": nullable(rec.PolicyID),
		"reason": nullable(rec.Reason), "caller_principal_id": nil,
		"caller_session_id": nil, "caller_source": nil, "contract_version": nil,
		"redactions": nullable(rec.Redactions), "prev_hash": rec.PrevHash,
	})
	r.prev = rec.RowHash
	r.pending = append(r.pending, rec)
}

func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// RunPush flushes queued decisions to the CP on an interval until ctx ends.
func (r *Recorder) RunPush(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			r.flush(context.Background())
			return
		case <-t.C:
			r.flush(ctx)
		}
	}
}

func (r *Recorder) flush(ctx context.Context) {
	r.mu.Lock()
	if len(r.pending) == 0 {
		r.sampled = map[string]int{}
		r.mu.Unlock()
		return
	}
	batch := r.pending
	r.pending = nil
	r.sampled = map[string]int{}
	r.mu.Unlock()

	payload := map[string]any{"dp_id": r.dpID, "decisions": batch}
	body, err := json.Marshal(payload)
	if err != nil {
		return
	}

	url := fmt.Sprintf("%s/api/v1/agents/%s/%s/decisions", r.cpURL, r.tenant, r.entityID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+r.token)

	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		r.mu.Lock()
		r.errors++
		r.pending = append(batch, r.pending...)
		r.mu.Unlock()
		return
	}
	resp.Body.Close()
}

// Stats returns running counters for the heartbeat.
func (r *Recorder) Stats() (total, denies, errors int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.total, r.denies, r.errors
}
