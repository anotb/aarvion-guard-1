// Package govern implements the local Policy Decision Point (PDP): a
// Unix-domain-socket server the OpenClaw runtime calls (as a Policy Enforcement
// Point) to approve each action BEFORE it runs. Governance here lives above the
// transport - no MITM, no CA - and reuses the same OPA policy the egress proxy
// evaluates.
package govern

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/aarvion-ai/aarvion-guard/internal/decisions"
	"github.com/aarvion-ai/aarvion-guard/internal/mitm"
	"github.com/aarvion-ai/aarvion-guard/internal/policy"
)

// contractVersion is the wire contract this server speaks. Requests carry it and
// it is echoed into the OPA input so packs can branch on it later.
const contractVersion = "1"

// maxRecentNonces hard-caps the replay set's memory. It is generous so normal
// traffic never hits it (TTL expiry keeps the live set to roughly rate*ttl);
// only a flood reaches it, at which point new nonces are rejected (fail-closed)
// rather than evicted - so an attacker can't flush a victim's live nonce to
// replay it.
const maxRecentNonces = 200000

// nonceTTL binds a nonce's replay-protection to time, not just volume: a nonce
// is remembered for this long regardless of how many others arrive.
const nonceTTL = 2 * time.Minute

// maxNonceLen bounds a single nonce so a caller can't bloat the replay set with
// huge strings.
const maxNonceLen = 256

// maxRequestBytes caps the decision-request body. This socket is the trust
// boundary for a possibly-hostile local agent; without a cap a giant JSON body
// would OOM the PDP before any policy check runs.
const maxRequestBytes = 1 << 20 // 1 MiB

// Config parametrizes the PDP server. Token and PeerUID are the two mandatory
// auth factors; FailMode selects the per-surface posture when OPA is unreachable.
type Config struct {
	SocketPath string
	Token      string
	PeerUID    uint32
	FailMode   map[string]string
	Essential  mitm.EssentialSet
}

// Server is the PDP. It owns the socket lifecycle and delegates decisions to OPA
// via the shared policy client, recording each into the decision chain.
type Server struct {
	cfg   Config
	pol   *policy.Client
	rec   *decisions.Recorder
	seen  *nonceSet
	nowFn func() time.Time
}

// New builds a PDP server. The policy client and recorder are shared with the
// egress proxy so both paths write to the same decision chain and OPA.
func New(cfg Config, pol *policy.Client, rec *decisions.Recorder) *Server {
	return &Server{
		cfg:   cfg,
		pol:   pol,
		rec:   rec,
		seen:  newNonceSet(maxRecentNonces, nonceTTL),
		nowFn: time.Now,
	}
}

// ListenAndServe binds the socket (0600) and serves until ctx is cancelled. A
// stale socket from a prior crash is removed first so bind never fails on it.
func (s *Server) ListenAndServe(ctx context.Context) error {
	if s.cfg.SocketPath == "" {
		return fmt.Errorf("govern: socket path is required")
	}
	// Both auth factors must be real. An empty token makes
	// subtle.ConstantTimeCompare("","")==1, silently disabling the bearer factor
	// and leaving the PDP guarded by peer-uid alone.
	if s.cfg.Token == "" {
		return fmt.Errorf("govern: socket token is required")
	}
	// Remove a stale socket so bind doesn't fail on "address already in use".
	_ = os.Remove(s.cfg.SocketPath)

	// Create the socket 0600 atomically via umask, so there is no window between
	// Listen and Chmod where a process of another uid could connect.
	prev := syscall.Umask(0o177)
	ln, err := net.Listen("unix", s.cfg.SocketPath)
	syscall.Umask(prev)
	if err != nil {
		return err
	}
	if err := os.Chmod(s.cfg.SocketPath, 0o600); err != nil {
		ln.Close()
		return err
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/govern", s.handleGovern)
	mux.HandleFunc("/v1/govern/health", s.handleHealth)

	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       20 * time.Second,
		WriteTimeout:      20 * time.Second,
		IdleTimeout:       60 * time.Second,
		// Stash the kernel-verified peer uid on each connection so handlers can
		// enforce the uid check without re-reading the socket.
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			uid, err := peerUID(c)
			return context.WithValue(ctx, peerUIDKey{}, peerUIDResult{uid: uid, err: err})
		},
	}

	// done unblocks the shutdown watcher if Serve returns on its own (a fatal
	// listener error), so the goroutine can't leak waiting on ctx forever.
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
		case <-done:
			return
		}
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
	}()

	err = srv.Serve(ln)
	_ = os.Remove(s.cfg.SocketPath)
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}

type peerUIDKey struct{}

type peerUIDResult struct {
	uid uint32
	err error
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.authOK(r) {
		writeAuthError(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}

func (s *Server) handleGovern(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.peerOK(r) {
		http.Error(w, "peer not permitted", http.StatusForbidden)
		return
	}
	if !s.tokenOK(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var req Request
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBytes)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if req.Nonce == "" || len(req.Nonce) > maxNonceLen {
		http.Error(w, "nonce required", http.StatusBadRequest)
		return
	}
	if !s.seen.add(req.Nonce, s.nowFn()) {
		// A live replay, or the replay set is full under a flood: reject either
		// way so a captured nonce can't be re-approved.
		http.Error(w, "nonce replayed", http.StatusConflict)
		return
	}

	resp := s.decide(r.Context(), &req)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// decide evaluates OPA (with the fail-mode fallback) and records the decision.
func (s *Server) decide(ctx context.Context, req *Request) *Response {
	start := s.nowFn()
	hreq := req.Attributes.Request.HTTP

	dec, err := s.pol.GovernEval(ctx, s.buildInput(req))
	if err != nil {
		dec = s.failMode(req)
	}
	latency := int(s.nowFn().Sub(start).Milliseconds())

	verdict := VerdictAllow
	decision := "allow"
	if !dec.Allowed {
		verdict = VerdictDeny
		decision = "deny"
	}

	s.rec.AddGoverned(decisions.Record{
		Timestamp:         s.nowFn().UTC().Format(time.RFC3339Nano),
		Method:            hreq.Method,
		Path:              hreq.Path,
		Host:              hreq.Host,
		Decision:          decision,
		Enforced:          dec.Enforced,
		PolicyID:          dec.PolicyID,
		Reason:            dec.Reason,
		LatencyMs:         latency,
		Redactions:        dec.Redactions,
		Surface:           req.Ctx.Surface,
		Phase:             req.Ctx.Phase,
		CallerPrincipalID: req.Ctx.Caller.PrincipalID,
		CallerSessionID:   req.Ctx.Caller.SessionID,
		CallerSource:      req.Ctx.Caller.Source,
	})

	return &Response{
		DecisionID: newDecisionID(),
		Nonce:      req.Nonce,
		Verdict:    verdict,
		HTTPStatus: dec.HTTPStatus,
		PolicyID:   dec.PolicyID,
		Reason:     dec.Reason,
		Redactions: dec.Redactions,
	}
}

// buildInput assembles the extended OPA input from the request: the http block
// (which today's packs match on) plus forward-looking caller/action context.
func (s *Server) buildInput(req *Request) policy.GovernInput {
	h := req.Attributes.Request.HTTP
	return policy.GovernInput{
		ContractVersion: contractVersion,
		Ctx: map[string]any{
			"surface": req.Ctx.Surface,
			"phase":   req.Ctx.Phase,
			"caller": map[string]any{
				"principal_id": req.Ctx.Caller.PrincipalID,
				"session_id":   req.Ctx.Caller.SessionID,
				"source":       req.Ctx.Caller.Source,
				"trust":        req.Ctx.Caller.Trust,
				"run_id":       req.Ctx.Caller.RunID,
				"tool":         req.Ctx.Caller.Tool,
			},
		},
		Action: map[string]any{
			"tool":        req.Action.Tool,
			"operation":   req.Action.Operation,
			"args":        req.Action.Args,
			"args_digest": req.Action.ArgsDigest,
		},
		Attributes: policy.HTTPAttributes(h.Method, h.Host, h.Path, h.Body, h.Headers),
	}
}

func (s *Server) authOK(r *http.Request) bool { return s.peerOK(r) && s.tokenOK(r) }

// tokenOK compares the presented bearer token to the configured one in constant
// time, so a mismatch can't be found by timing.
func (s *Server) tokenOK(r *http.Request) bool {
	if s.cfg.Token == "" {
		return false // never let an unset token disable the factor
	}
	got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	return subtle.ConstantTimeCompare([]byte(got), []byte(s.cfg.Token)) == 1
}

// peerOK enforces that the connecting process runs as the configured uid. The
// uid is read from the kernel (SO_PEERCRED / LOCAL_PEERCRED) at connect time and
// cannot be forged by the peer.
func (s *Server) peerOK(r *http.Request) bool {
	v, ok := r.Context().Value(peerUIDKey{}).(peerUIDResult)
	if !ok || v.err != nil {
		return false
	}
	return v.uid == s.cfg.PeerUID
}

func writeAuthError(w http.ResponseWriter, r *http.Request) {
	// Health reuses the same two factors; report peer failures as 403, token as
	// 401, so a caller can tell which factor it flunked.
	if v, ok := r.Context().Value(peerUIDKey{}).(peerUIDResult); !ok || v.err != nil {
		http.Error(w, "peer not permitted", http.StatusForbidden)
		return
	}
	http.Error(w, "unauthorized", http.StatusUnauthorized)
}

func newDecisionID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// nonceSet is a thread-safe recent-nonce set for replay rejection. Validity is
// bound to time (ttl), not just volume, so an attacker can't flood the set to
// evict a victim's live nonce and replay it. A generous size cap bounds memory;
// at the cap new nonces are rejected (fail-closed) rather than evicted.
type nonceSet struct {
	mu   sync.Mutex
	max  int
	ttl  time.Duration
	seen map[string]time.Time
}

func newNonceSet(max int, ttl time.Duration) *nonceSet {
	return &nonceSet{max: max, ttl: ttl, seen: make(map[string]time.Time)}
}

// add records a nonce seen at now and reports whether it is fresh (true) and so
// accepted. It returns false for a still-live replay, or when the set is full.
func (n *nonceSet) add(nonce string, now time.Time) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	cutoff := now.Add(-n.ttl)
	for k, t := range n.seen {
		if t.Before(cutoff) {
			delete(n.seen, k)
		}
	}
	if _, ok := n.seen[nonce]; ok {
		return false // any surviving entry is within ttl: a live replay
	}
	if len(n.seen) >= n.max {
		return false // full under a flood: reject rather than evict a live nonce
	}
	n.seen[nonce] = now
	return true
}
