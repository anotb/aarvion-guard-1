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

	// Governance metadata (set by the runtime PDP path). These are row metadata
	// only: they are NOT fed into rowHash, so a governed row's row_hash matches
	// what the proxy path would produce for the same core decision. Do not add
	// any of these to hashFields without reconciling the DP shipper + CP verify.
	CallerPrincipalID string `json:"caller_principal_id,omitempty"`
	CallerSessionID   string `json:"caller_session_id,omitempty"`
	CallerSource      string `json:"caller_source,omitempty"`
	Phase             string `json:"phase,omitempty"`
	Origin            string `json:"origin,omitempty"`

	PrevHash string `json:"prev_hash"`
	RowHash  string `json:"row_hash"`
}

// Origin distinguishes where a decision was made: the transparent/forward proxy
// (MITM egress) versus the runtime PDP over the local socket.
const (
	OriginProxy   = "proxy"
	OriginRuntime = "runtime"
)

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

// Sink is an optional side-channel that observes every finalized decision row
// (the same rows queued for the CP push). Implementations live in
// internal/sinks and are injected via SetSink; this package stays free of
// net/http and file specifics so there is no import cycle - sinks imports
// decisions for the Record type, decisions never imports sinks. Record is called
// on the decision path while the Recorder lock is held, so implementations MUST
// NOT block (buffer + hand off to a goroutine).
type Sink interface {
	Record(Record)
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
	sink    Sink

	denies  int
	errors  int
	total   int
	dropped int
}

// SetSink attaches an optional observability sink. A nil sink (the default) is
// safe: the sink hook in chain() is skipped entirely. Set once at startup,
// before any decisions flow.
func (r *Recorder) SetSink(s Sink) {
	r.mu.Lock()
	r.sink = s
	r.mu.Unlock()
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

// Add records a proxy (MITM egress) decision. Denies/redacts are always queued;
// repeated identical allows are collapsed within the flush window to avoid
// flooding the CP.
func (r *Recorder) Add(method, host, path, decision, policyID, reason, redactions string, enforced bool, latencyMs int) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Collapse only *unmarked* allows (a plain OPA/essential allow). A marked allow
	// carries an audit-critical reason - a break_glass bypass or an observe-mode
	// novel_host_observed flag - and must be recorded every time, never deduped, so
	// the bypass window / observation is fully visible in the forensic chain.
	if decision == "allow" && reason == "" && r.collapse(method, host, path) {
		r.total++
		return
	}

	// Enforce the backlog cap before touching the chain. Dropping here - after
	// the collapse bookkeeping but before we assign seq/prev/hash - keeps the
	// queued rows contiguous: we never chain a row we then discard.
	if len(r.pending) >= maxPending {
		r.dropped++
		return
	}

	r.chain(Record{
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
		Origin:     OriginProxy,
	})
}

// AddGoverned records a runtime PDP decision. The caller supplies a Record with
// its governance metadata (caller_*, surface, phase) already set; this stamps
// the writer-owned fields (seq, prev/row hash, dp/entity, origin) and queues it.
// The metadata fields are NOT hashed, so the row_hash matches the proxy path's
// for an equivalent core decision.
func (r *Recorder) AddGoverned(rec Record) {
	r.mu.Lock()
	defer r.mu.Unlock()

	rec.ReplicaID = r.dpID
	rec.EntityID = r.entityID
	rec.Origin = OriginRuntime
	if rec.Direction == "" {
		rec.Direction = rec.Surface
	}
	if len(r.pending) >= maxPending {
		r.dropped++
		return
	}
	r.chain(rec)
}

// collapse reports whether an allow with this signature has already been queued
// in the current flush window (caller holds the lock). It updates the sample
// counter as a side effect.
func (r *Recorder) collapse(method, host, path string) bool {
	sig := method + " " + host + path
	if _, seen := r.sampled[sig]; seen {
		r.sampled[sig]++
		return true
	}
	r.sampled[sig] = 1
	return false
}

// chain stamps the seq + hash-chain linkage onto rec and appends it (caller
// holds the lock). The row_hash inputs are fixed and must stay byte-identical
// across the proxy and runtime paths - governance metadata on rec is not hashed.
func (r *Recorder) chain(rec Record) {
	r.total++
	if rec.Decision == "deny" {
		r.denies++
	}

	r.seq++
	rec.Seq = r.seq
	rec.PrevHash = r.prev
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

	// Fan the finalized row out to the optional observability sink (JSONL,
	// metrics, deny webhook). This runs on the decision path under the lock, so
	// the sink contract is non-blocking: it must buffer and hand off. A nil sink
	// (no observability configured) skips this entirely.
	if r.sink != nil {
		r.sink.Record(rec)
	}
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
