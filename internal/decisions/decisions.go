package decisions

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"sync"
	"time"
)

// maxPending caps the queued-record backlog. On a prolonged CP outage the queue
// would otherwise grow unbounded and OOM the guard. At the cap we drop the
// NEWEST record (before it is chained) so the hash-chain of queued rows stays
// gap-free - dropping an already-chained row would break linkage verification.
const maxPending = 50000

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

// hashFields is the ordered field set hashed into each row's row_hash. The CP's
// decision-chain verify is linkage-only (each row's prev_hash == the prior row's
// row_hash per writer), so this just has to be internally consistent - it does
// NOT need to byte-match the Python DP shipper's row_hash. If the CP ever starts
// recomputing decision hashes, this must be reconciled with the DP shipper.
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
	statePath string

	mu      sync.Mutex
	seq     int
	prev    string
	pending []Record
	sampled map[string]int

	denies  int
	errors  int
	total   int
	dropped int
}

type chainState struct {
	Seq  int    `json:"seq"`
	Prev string `json:"prev"`
}

func New(cpURL, tenant, entityID, token, dpID, statePath string) *Recorder {
	r := &Recorder{
		cpURL:     cpURL,
		tenant:    tenant,
		entityID:  entityID,
		token:     token,
		dpID:      dpID,
		statePath: statePath,
		prev:      "0",
		sampled:   map[string]int{},
	}
	// Resume the hash chain from where the CP last acknowledged, so a restart
	// (same dp_id writer) links to the prior row instead of re-seeding at "0"
	// and breaking chain verification.
	if statePath != "" {
		if b, err := os.ReadFile(statePath); err == nil {
			var st chainState
			if json.Unmarshal(b, &st) == nil && st.Prev != "" {
				r.seq = st.Seq
				r.prev = st.Prev
			}
		}
	}
	return r
}

// saveState persists the cursor after a successful push, so recovery resumes
// from the last row the CP actually received.
func (r *Recorder) saveState(seq int, prev string) {
	if r.statePath == "" {
		return
	}
	b, err := json.Marshal(chainState{Seq: seq, Prev: prev})
	if err != nil {
		return
	}
	_ = os.WriteFile(r.statePath, b, 0o600)
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

	// Enforce the backlog cap before touching the chain. Dropping here - after
	// the collapse bookkeeping but before we assign seq/prev/hash - keeps the
	// queued rows contiguous: we never chain a row we then discard.
	if len(r.pending) >= maxPending {
		r.dropped++
		return
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
		r.requeue(batch)
		return
	}
	// Drain + close in every path so the connection can be reused.
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	// A non-2xx means the CP did NOT store the batch. Treat it exactly like a
	// transport failure: re-queue and do NOT advance the persisted cursor.
	// saveState-ing here would push the chain cursor past a row the CP never
	// received, permanently corrupting chain verification.
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		r.requeue(batch)
		return
	}

	last := batch[len(batch)-1]
	r.saveState(last.Seq, last.RowHash)
}

// requeue puts a failed batch back at the head of the pending queue and bumps
// the error counter. The batch is prepended so ordering (and thus chain
// linkage) is preserved against records added while the flush was in flight.
func (r *Recorder) requeue(batch []Record) {
	r.mu.Lock()
	r.errors++
	r.pending = append(batch, r.pending...)
	r.mu.Unlock()
}

// Stats returns running counters for the heartbeat. dropped is the number of
// records shed at the backlog cap (a CP-outage signal worth surfacing).
func (r *Recorder) Stats() (total, denies, errors, dropped int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.total, r.denies, r.errors, r.dropped
}
