package govern

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aarvion-ai/aarvion-guard/internal/decisions"
	"github.com/aarvion-ai/aarvion-guard/internal/mitm"
	"github.com/aarvion-ai/aarvion-guard/internal/normalize"
	"github.com/aarvion-ai/aarvion-guard/internal/overlay"
	"github.com/aarvion-ai/aarvion-guard/internal/policy"
)

const testToken = "s3cr3t-token"

// opaStub returns an httptest.Server that answers the envoy authz entrypoint
// with the given allowed verdict. policy.New prepends http://, so we hand it the
// server's host:port. Real OPA over UDS can't be spun up in a test, and it
// isn't needed: the guard only speaks HTTP to OPA.
func opaStub(t *testing.T, allowed bool) *policy.Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/data/envoy/authz/allow" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		body := map[string]any{"result": map[string]any{
			"allowed":     allowed,
			"http_status": map[bool]int{true: 200, false: 403}[allowed],
			"headers": map[string]string{
				"x-policy-violated": "pol-1",
				"x-policy-reason":   "test-reason",
			},
		}}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(body)
	}))
	t.Cleanup(srv.Close)
	return policy.New(strings.TrimPrefix(srv.URL, "http://"))
}

// unreachableOPA points the policy client at a closed port so every Eval errors,
// exercising the fail-mode path.
func unreachableOPA(t *testing.T) *policy.Client {
	t.Helper()
	// 127.0.0.1:0 is never listening; the dial fails fast.
	return policy.New("127.0.0.1:1")
}

func testRecorder(t *testing.T) *decisions.Recorder {
	t.Helper()
	return decisions.New("http://cp", "tenant", "entity", "tok", "dp", filepath.Join(t.TempDir(), "chain.json"))
}

// shortSocketPath returns a socket path short enough for the ~104-byte sun_path
// limit (macOS temp dirs are long enough to blow past it), cleaned up after.
func shortSocketPath(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "gv")
	if err != nil {
		t.Fatalf("mkdtemp: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return filepath.Join(dir, "g.sock")
}

// startServer boots a govern server on a temp socket and returns a client that
// dials it. PeerUID defaults to the current uid so the peer check passes.
func startServer(t *testing.T, cfg Config, pol *policy.Client) (*http.Client, string) {
	t.Helper()
	if cfg.SocketPath == "" {
		cfg.SocketPath = shortSocketPath(t)
	}
	if cfg.Token == "" {
		cfg.Token = testToken
	}
	// The test process is the connecting peer, so accept its own uid.
	cfg.PeerUID = uint32(os.Getuid())

	srv := New(cfg, pol, testRecorder(t))
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	errCh := make(chan error, 1)
	go func() { errCh <- srv.ListenAndServe(ctx) }()
	waitForSocket(t, cfg.SocketPath, errCh)

	client := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", cfg.SocketPath)
		},
	}}
	return client, cfg.SocketPath
}

func waitForSocket(t *testing.T, path string, errCh <-chan error) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-errCh:
			t.Fatalf("server exited early: %v", err)
		default:
		}
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("socket %s never appeared", path)
}

// sampleRequest builds a valid decision request with the given nonce/method/host.
func sampleRequest(nonce, method, host string) Request {
	return Request{
		ContractVersion: "1",
		Nonce:           nonce,
		Ctx: Ctx{
			Surface: "send",
			Phase:   "pre",
			Caller:  Caller{PrincipalID: "p1", SessionID: "s1", Source: "runtime"},
		},
		Action: Action{Tool: "http", Operation: "post"},
		Attributes: Attributes{Request: AttributesRequest{HTTP: HTTP{
			Method: method, Host: host, Path: "/x",
		}}},
	}
}

// post sends a decision request. token=="" omits the Authorization header.
func post(t *testing.T, client *http.Client, sock, token string, req Request) *http.Response {
	t.Helper()
	body, _ := json.Marshal(req)
	// The URL host is ignored - DialContext always hits the socket - but must be
	// syntactically valid.
	hr, err := http.NewRequest(http.MethodPost, "http://unix/v1/govern", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		hr.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := client.Do(hr)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	return resp
}

func decode(t *testing.T, resp *http.Response) Response {
	t.Helper()
	defer resp.Body.Close()
	var out Response
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return out
}

// An empty configured token must be rejected at startup: otherwise
// ConstantTimeCompare("","")==1 would silently disable the bearer factor.
func TestEmptyTokenRejectedAtStartup(t *testing.T) {
	srv := New(Config{SocketPath: shortSocketPath(t), Token: "", PeerUID: uint32(os.Getuid())}, opaStub(t, true), testRecorder(t))
	err := srv.ListenAndServe(context.Background())
	if err == nil || !strings.Contains(err.Error(), "token") {
		t.Fatalf("empty token must be rejected at startup; got %v", err)
	}
}

// A body larger than the cap must be rejected (not buffered), so a hostile
// same-uid caller can't OOM the PDP.
func TestOversizedBodyRejected(t *testing.T) {
	client, sock := startServer(t, Config{}, opaStub(t, true))
	req := sampleRequest("nbig", "POST", "api.example.com")
	req.Attributes.Request.HTTP.Body = strings.Repeat("a", maxRequestBytes+1024)
	resp := post(t, client, sock, testToken, req)
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		t.Fatalf("oversized body accepted; want a 4xx")
	}
}

// Replay protection is bound to time, and a flood cannot evict a victim's live
// nonce (the set fails closed at the cap rather than evicting).
func TestNonceSetTimeExpiryAndFloodResistance(t *testing.T) {
	t0 := time.Unix(1_000_000, 0)

	ns := newNonceSet(100, time.Minute)
	if !ns.add("n", t0) {
		t.Fatal("first use should be accepted")
	}
	if ns.add("n", t0.Add(time.Second)) {
		t.Fatal("replay within ttl must be rejected")
	}
	if !ns.add("n", t0.Add(2*time.Minute)) {
		t.Fatal("after ttl the nonce should be forgotten and re-acceptable")
	}

	// Flood the set past its cap within the window; the victim (added first) must
	// still be remembered, so its nonce can't be replayed.
	fs := newNonceSet(100, time.Minute)
	fs.add("victim", t0)
	for i := 0; i < 500; i++ {
		fs.add("flood-"+strconv.Itoa(i), t0.Add(time.Duration(i)*time.Millisecond))
	}
	if fs.add("victim", t0.Add(time.Second)) {
		t.Fatal("victim nonce was evicted by a flood - replay protection defeated")
	}
}

func TestMissingTokenUnauthorized(t *testing.T) {
	client, sock := startServer(t, Config{}, opaStub(t, true))
	resp := post(t, client, sock, "", sampleRequest("n1", "POST", "api.example.com"))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no token: got %d want 401", resp.StatusCode)
	}
}

func TestBadTokenUnauthorized(t *testing.T) {
	client, sock := startServer(t, Config{}, opaStub(t, true))
	resp := post(t, client, sock, "wrong-token", sampleRequest("n1", "POST", "api.example.com"))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("bad token: got %d want 401", resp.StatusCode)
	}
}

func TestEmptyNonceBadRequest(t *testing.T) {
	client, sock := startServer(t, Config{}, opaStub(t, true))
	resp := post(t, client, sock, testToken, sampleRequest("", "POST", "api.example.com"))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("empty nonce: got %d want 400", resp.StatusCode)
	}
}

func TestReplayedNonceConflict(t *testing.T) {
	client, sock := startServer(t, Config{}, opaStub(t, true))

	first := post(t, client, sock, testToken, sampleRequest("dup", "POST", "api.example.com"))
	first.Body.Close()
	if first.StatusCode != http.StatusOK {
		t.Fatalf("first request: got %d want 200", first.StatusCode)
	}

	second := post(t, client, sock, testToken, sampleRequest("dup", "POST", "api.example.com"))
	defer second.Body.Close()
	if second.StatusCode != http.StatusConflict {
		t.Fatalf("replay: got %d want 409", second.StatusCode)
	}
}

func TestAllowVerdictEchoesNonce(t *testing.T) {
	client, sock := startServer(t, Config{}, opaStub(t, true))
	resp := post(t, client, sock, testToken, sampleRequest("n-allow", "POST", "api.example.com"))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("got %d want 200", resp.StatusCode)
	}
	out := decode(t, resp)
	if out.Verdict != VerdictAllow {
		t.Fatalf("verdict: got %q want allow", out.Verdict)
	}
	if out.Nonce != "n-allow" {
		t.Fatalf("nonce not echoed: got %q", out.Nonce)
	}
	if out.DecisionID == "" {
		t.Fatal("decision_id empty")
	}
}

func TestDenyVerdict(t *testing.T) {
	client, sock := startServer(t, Config{}, opaStub(t, false))
	resp := post(t, client, sock, testToken, sampleRequest("n-deny", "POST", "api.example.com"))
	out := decode(t, resp)
	if out.Verdict != VerdictDeny {
		t.Fatalf("verdict: got %q want deny", out.Verdict)
	}
	if out.Nonce != "n-deny" {
		t.Fatalf("nonce not echoed: got %q", out.Nonce)
	}
}

// A policy that sets x-aarvion-verdict=ask (with allowed=false) must surface as
// an "ask" verdict with the prompt plumbed through, so the PEP can pause the tool
// call for owner approval instead of hard-denying it.
func TestAskVerdict(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"result": map[string]any{
			"allowed":     false,
			"http_status": 202,
			"headers": map[string]string{
				"x-aarvion-verdict": "ask",
				"x-policy-violated": "govern.ask.approval_required.v1",
				"x-policy-reason":   "approval required: demo",
			},
		}})
	}))
	t.Cleanup(srv.Close)
	pol := policy.New(strings.TrimPrefix(srv.URL, "http://"))

	client, sock := startServer(t, Config{}, pol)
	resp := post(t, client, sock, testToken, sampleRequest("n-ask", "POST", "api.example.com"))
	out := decode(t, resp)
	if out.Verdict != VerdictAsk {
		t.Fatalf("verdict: got %q want ask", out.Verdict)
	}
	if out.Ask == nil || out.Ask.Prompt == "" {
		t.Fatalf("ask prompt not plumbed: %+v", out.Ask)
	}
	if out.Nonce != "n-ask" {
		t.Fatalf("nonce not echoed: got %q", out.Nonce)
	}
}

// With OPA unreachable, a non-read surface (send) must fail closed.
func TestFailModeSendDenies(t *testing.T) {
	client, sock := startServer(t, Config{}, unreachableOPA(t))
	resp := post(t, client, sock, testToken, sampleRequest("n-fail-send", "POST", "api.example.com"))
	out := decode(t, resp)
	if out.Verdict != VerdictDeny {
		t.Fatalf("send fail-mode: got %q want deny", out.Verdict)
	}
	if out.Reason != "policy_unavailable" {
		t.Fatalf("reason: got %q want policy_unavailable", out.Reason)
	}
}

// With OPA unreachable, a read to an essential host is the one escape hatch.
func TestFailModeEssentialReadAllows(t *testing.T) {
	client, sock := startServer(t, Config{
		Essential: mitm.Essentials([]string{"api.anthropic.com"}),
	}, unreachableOPA(t))
	req := sampleRequest("n-fail-read", "GET", "api.anthropic.com")
	req.Ctx.Surface = "egress"
	resp := post(t, client, sock, testToken, req)
	out := decode(t, resp)
	if out.Verdict != VerdictAllow {
		t.Fatalf("essential read fail-mode: got %q want allow", out.Verdict)
	}
	if out.Reason != "policy_unavailable_essential" {
		t.Fatalf("reason: got %q want policy_unavailable_essential", out.Reason)
	}
}

// A read to a NON-essential host still fails closed.
func TestFailModeNonEssentialReadDenies(t *testing.T) {
	client, sock := startServer(t, Config{
		Essential: mitm.Essentials([]string{"api.anthropic.com"}),
	}, unreachableOPA(t))
	req := sampleRequest("n-fail-nonessential", "GET", "evil.example.com")
	req.Ctx.Surface = "egress"
	resp := post(t, client, sock, testToken, req)
	out := decode(t, resp)
	if out.Verdict != VerdictDeny {
		t.Fatalf("non-essential read: got %q want deny", out.Verdict)
	}
}

// testOverlay builds an in-memory tighten-only overlay store from the given rules.
func testOverlay(t *testing.T, rules ...overlay.Rule) *overlay.Store {
	t.Helper()
	st, err := overlay.Load(filepath.Join(t.TempDir(), "overlay.json"))
	if err != nil {
		t.Fatalf("overlay load: %v", err)
	}
	if err := st.Replace(rules); err != nil {
		t.Fatalf("overlay replace: %v", err)
	}
	return st
}

// A tighten-only overlay deny rule turns a base ALLOW into a deny on the PDP path.
func TestOverlayTightensAllowToDeny(t *testing.T) {
	ov := testOverlay(t, overlay.Rule{
		ID:      "blk-host",
		Verdict: overlay.VerdictDeny,
		Reason:  "blocked by local overlay",
		Enabled: true,
		Match:   overlay.Match{HostSuffixes: []string{"blocked.example.com"}},
	})
	client, sock := startServer(t, Config{Overlay: ov}, opaStub(t, true))

	resp := post(t, client, sock, testToken, sampleRequest("n-ov-deny", "POST", "blocked.example.com"))
	out := decode(t, resp)
	if out.Verdict != VerdictDeny {
		t.Fatalf("verdict: got %q want deny", out.Verdict)
	}

	// A host the rule doesn't match stays on the base allow.
	resp = post(t, client, sock, testToken, sampleRequest("n-ov-allow", "POST", "fine.example.com"))
	if out := decode(t, resp); out.Verdict != VerdictAllow {
		t.Fatalf("non-matching host: got %q want allow", out.Verdict)
	}
}

// A tighten-only overlay ask rule escalates a base ALLOW to human approval. Unlike
// egress, the PDP supports "ask", so it stays an ask (not a deny).
func TestOverlayEscalatesAllowToAsk(t *testing.T) {
	ov := testOverlay(t, overlay.Rule{
		ID:      "ask-host",
		Verdict: overlay.VerdictAsk,
		Reason:  "needs owner approval",
		Enabled: true,
		Match:   overlay.Match{HostSuffixes: []string{"review.example.com"}},
	})
	client, sock := startServer(t, Config{Overlay: ov}, opaStub(t, true))

	resp := post(t, client, sock, testToken, sampleRequest("n-ov-ask", "POST", "review.example.com"))
	out := decode(t, resp)
	if out.Verdict != VerdictAsk {
		t.Fatalf("verdict: got %q want ask", out.Verdict)
	}
}

// The overlay now sees the SEMANTIC facets the normalizer produces, not just the
// raw command. A shell action "bird tweet hello" classifies to {surface:twitter,
// verb:post}; a semantic overlay rule matching that surface+verb must escalate the
// base ALLOW to deny with a "local_overlay:" reason. This proves the normalizer is
// wired into the PDP -> overlay path (the base OPA must ALLOW so the tighten-only
// overlay is even consulted).
func TestOverlaySemanticSurfaceVerbDeny(t *testing.T) {
	ov := testOverlay(t, overlay.Rule{
		ID:      "no-tweets",
		Verdict: overlay.VerdictDeny,
		Reason:  "twitter is read-only",
		Enabled: true,
		Match: overlay.Match{
			Surfaces: []string{"twitter"},
			Verbs:    []string{"post"},
		},
	})
	client, sock := startServer(t, Config{Overlay: ov}, opaStub(t, true))

	req := sampleRequest("n-sem-tweet", "POST", "api.example.com")
	req.Action = Action{Tool: "exec", Args: "bird tweet hello"}
	req.Ctx.Surface = "exec"

	resp := post(t, client, sock, testToken, req)
	out := decode(t, resp)
	if out.Verdict != VerdictDeny {
		t.Fatalf("semantic post: got verdict %q want deny", out.Verdict)
	}
	if !strings.HasPrefix(out.Reason, "local_overlay:") {
		t.Fatalf("reason not from overlay: got %q want local_overlay: prefix", out.Reason)
	}

	// A read-only twitter verb (bird search) must NOT trip the post rule, so the
	// base allow stands - confirming the facet match is verb-specific.
	req2 := sampleRequest("n-sem-search", "POST", "api.example.com")
	req2.Action = Action{Tool: "exec", Args: "bird search cats"}
	req2.Ctx.Surface = "exec"
	if out := decode(t, post(t, client, sock, testToken, req2)); out.Verdict != VerdictAllow {
		t.Fatalf("bird search should stay allowed: got %q", out.Verdict)
	}
}

// captureSink records every finalized decision row so a test can assert the
// audit metadata the HTTP response doesn't carry (Enforced, WouldBe).
type captureSink struct {
	mu   sync.Mutex
	rows []decisions.Record
}

func (c *captureSink) Record(rec decisions.Record) {
	c.mu.Lock()
	c.rows = append(c.rows, rec)
	c.mu.Unlock()
}

func (c *captureSink) last() (decisions.Record, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.rows) == 0 {
		return decisions.Record{}, false
	}
	return c.rows[len(c.rows)-1], true
}

// captureObserver records every BehaviourObserver call so a test can assert the
// PDP invokes the observer with the would-be verdict + enforced flag.
type captureObserver struct {
	mu    sync.Mutex
	calls []observeCall
}

type observeCall struct {
	principal string
	wouldBe   string
	enforced  bool
	surface   string
	verb      string
}

func (o *captureObserver) Observe(sem normalize.Action, principal, wouldBe string, enforced bool) {
	o.mu.Lock()
	o.calls = append(o.calls, observeCall{
		principal: principal, wouldBe: wouldBe, enforced: enforced,
		surface: sem.Surface, verb: sem.Verb,
	})
	o.mu.Unlock()
}

func (o *captureObserver) last() (observeCall, bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if len(o.calls) == 0 {
		return observeCall{}, false
	}
	return o.calls[len(o.calls)-1], true
}

// startServerWithRecorder is startServer but lets the caller supply the recorder
// (so a capture sink can be attached) and returns the recorder.
func startServerWithRecorder(t *testing.T, cfg Config, pol *policy.Client, rec *decisions.Recorder) (*http.Client, string) {
	t.Helper()
	if cfg.SocketPath == "" {
		cfg.SocketPath = shortSocketPath(t)
	}
	if cfg.Token == "" {
		cfg.Token = testToken
	}
	cfg.PeerUID = uint32(os.Getuid())

	srv := New(cfg, pol, rec)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	errCh := make(chan error, 1)
	go func() { errCh <- srv.ListenAndServe(ctx) }()
	waitForSocket(t, cfg.SocketPath, errCh)

	client := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", cfg.SocketPath)
		},
	}}
	return client, cfg.SocketPath
}

// An Observe-marked overlay deny rule must NOT change the effective verdict (the
// response stays allow), but the recorded row is marked non-enforcing with the
// would-be deny, and the behaviour observer is called with those facts. This is
// the learn-mode mechanic: watch what a rule WOULD block without blocking it.
func TestObserveModeRecordsWouldBeAndStillAllows(t *testing.T) {
	ov := testOverlay(t, overlay.Rule{
		ID:      "observe-no-tweets",
		Verdict: overlay.VerdictDeny,
		Reason:  "would block tweets",
		Enabled: true,
		Observe: true,
		Match: overlay.Match{
			Surfaces: []string{"twitter"},
			Verbs:    []string{"post"},
		},
	})

	sink := &captureSink{}
	obs := &captureObserver{}
	rec := decisions.New("http://cp", "tenant", "entity", "tok", "dp", filepath.Join(t.TempDir(), "chain.json"))
	rec.SetSink(sink)

	client, sock := startServerWithRecorder(t, Config{Overlay: ov, Observer: obs}, opaStub(t, true), rec)

	req := sampleRequest("n-observe", "POST", "api.example.com")
	req.Action = Action{Tool: "exec", Args: "bird tweet hello"}
	req.Ctx.Surface = "exec"

	out := decode(t, post(t, client, sock, testToken, req))
	if out.Verdict != VerdictAllow {
		t.Fatalf("observe rule must not change verdict: got %q want allow", out.Verdict)
	}

	row, ok := sink.last()
	if !ok {
		t.Fatal("no decision row recorded")
	}
	if row.Decision != "allow" {
		t.Fatalf("recorded decision: got %q want allow", row.Decision)
	}
	if row.Enforced {
		t.Fatalf("observe row must be non-enforcing: Enforced=%v want false", row.Enforced)
	}
	if row.WouldBe != "deny" {
		t.Fatalf("observe row WouldBe: got %q want deny", row.WouldBe)
	}

	call, ok := obs.last()
	if !ok {
		t.Fatal("behaviour observer not called")
	}
	if call.wouldBe != "deny" || call.enforced {
		t.Fatalf("observer call: got wouldBe=%q enforced=%v want deny/false", call.wouldBe, call.enforced)
	}
	if call.surface != "twitter" || call.verb != "post" {
		t.Fatalf("observer semantic: got surface=%q verb=%q want twitter/post", call.surface, call.verb)
	}
}

// An enforcing (non-observe) overlay deny rule still denies AND still notifies
// the observer, with enforced=true and the would-be = the actual verdict.
func TestObserverCalledOnEnforcedDecision(t *testing.T) {
	ov := testOverlay(t, overlay.Rule{
		ID:      "enforce-no-tweets",
		Verdict: overlay.VerdictDeny,
		Reason:  "blocks tweets",
		Enabled: true,
		Match: overlay.Match{
			Surfaces: []string{"twitter"},
			Verbs:    []string{"post"},
		},
	})
	obs := &captureObserver{}
	rec := decisions.New("http://cp", "tenant", "entity", "tok", "dp", filepath.Join(t.TempDir(), "chain.json"))

	client, sock := startServerWithRecorder(t, Config{Overlay: ov, Observer: obs}, opaStub(t, true), rec)

	req := sampleRequest("n-enforced", "POST", "api.example.com")
	req.Action = Action{Tool: "exec", Args: "bird tweet hello"}
	req.Ctx.Surface = "exec"

	out := decode(t, post(t, client, sock, testToken, req))
	if out.Verdict != VerdictDeny {
		t.Fatalf("enforce rule verdict: got %q want deny", out.Verdict)
	}
	call, ok := obs.last()
	if !ok {
		t.Fatal("observer not called on enforced decision")
	}
	if call.wouldBe != "deny" || !call.enforced {
		t.Fatalf("observer call: got wouldBe=%q enforced=%v want deny/true", call.wouldBe, call.enforced)
	}
}

// fakeApprover records Open calls and answers Status from a canned verdict, so a
// test can assert the PDP opens a pending on ask and the approvals endpoint
// reports it.
type fakeApprover struct {
	mu      sync.Mutex
	opened  []ApprovalRequest
	verdict string // returned by Status for a known id
	known   bool   // whether Status reports the id at all
}

func (f *fakeApprover) Open(req ApprovalRequest) {
	f.mu.Lock()
	f.opened = append(f.opened, req)
	f.known = true
	if f.verdict == "" {
		f.verdict = "pending"
	}
	f.mu.Unlock()
}

func (f *fakeApprover) Status(id string) (string, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.known {
		return "", false
	}
	return f.verdict, true
}

func (f *fakeApprover) lastOpened() (ApprovalRequest, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.opened) == 0 {
		return ApprovalRequest{}, false
	}
	return f.opened[len(f.opened)-1], true
}

// askOPA returns a policy client whose OPA always answers ask (allowed=false +
// x-aarvion-verdict=ask), so the decision is an ask regardless of the request.
func askOPA(t *testing.T) *policy.Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"result": map[string]any{
			"allowed":     false,
			"http_status": 202,
			"headers": map[string]string{
				"x-aarvion-verdict": "ask",
				"x-policy-violated": "govern.ask.approval_required.v1",
				"x-policy-reason":   "approval required",
			},
		}})
	}))
	t.Cleanup(srv.Close)
	return policy.New(strings.TrimPrefix(srv.URL, "http://"))
}

// getApproval issues GET /v1/approvals/{id} over the same socket, returning the
// raw response so a test can assert status + body.
func getApproval(t *testing.T, client *http.Client, id, token string) *http.Response {
	t.Helper()
	hr, err := http.NewRequest(http.MethodGet, "http://unix/v1/approvals/"+id, nil)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		hr.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := client.Do(hr)
	if err != nil {
		t.Fatalf("get approval: %v", err)
	}
	return resp
}

// An ask decision must register a pending with the Approver (using the SAME
// decision_id returned to the PEP), and GET /v1/approvals/{id} must report it.
func TestAskOpensPendingAndApprovalsEndpointReports(t *testing.T) {
	appr := &fakeApprover{}
	client, sock := startServer(t, Config{Approver: appr}, askOPA(t))

	req := sampleRequest("n-ask-open", "POST", "api.example.com")
	req.Action = Action{Tool: "exec", Args: "gog gmail send --to a@x.com"}
	req.Ctx.Surface = "exec"
	req.Ctx.Caller.PrincipalID = "llm-mail"

	out := decode(t, post(t, client, sock, testToken, req))
	if out.Verdict != VerdictAsk {
		t.Fatalf("verdict: got %q want ask", out.Verdict)
	}
	if out.DecisionID == "" {
		t.Fatal("ask response missing decision_id")
	}

	opened, ok := appr.lastOpened()
	if !ok {
		t.Fatal("Approver.Open not called on ask")
	}
	if opened.DecisionID != out.DecisionID {
		t.Fatalf("pending id %q != response decision_id %q", opened.DecisionID, out.DecisionID)
	}
	if opened.Principal != "llm-mail" {
		t.Fatalf("pending principal: got %q want llm-mail", opened.Principal)
	}
	if opened.Surface != "email" || opened.Verb != "send" {
		t.Fatalf("pending semantic: got surface=%q verb=%q want email/send", opened.Surface, opened.Verb)
	}
	if opened.Reason == "" {
		t.Fatal("pending reason empty")
	}

	resp := getApproval(t, client, out.DecisionID, testToken)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("approvals endpoint: got %d want 200", resp.StatusCode)
	}
	var body struct {
		Status string `json:"status"`
		Reason string `json:"reason"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode approval: %v", err)
	}
	if body.Status != "pending" {
		t.Fatalf("approval status: got %q want pending", body.Status)
	}
}

// The approvals endpoint reflects a resolved verdict once the Approver flips it.
func TestApprovalsEndpointReportsResolvedVerdict(t *testing.T) {
	appr := &fakeApprover{verdict: "allow"}
	client, sock := startServer(t, Config{Approver: appr}, askOPA(t))

	req := sampleRequest("n-ask-resolved", "POST", "api.example.com")
	req.Action = Action{Tool: "exec", Args: "gog gmail send --to a@x.com"}
	req.Ctx.Surface = "exec"
	out := decode(t, post(t, client, sock, testToken, req))

	resp := getApproval(t, client, out.DecisionID, testToken)
	defer resp.Body.Close()
	var body struct {
		Status string `json:"status"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&body)
	if body.Status != "allow" {
		t.Fatalf("resolved status: got %q want allow", body.Status)
	}
}

// An unknown decision id on the approvals endpoint is a 404.
func TestApprovalsEndpointUnknownID(t *testing.T) {
	client, _ := startServer(t, Config{Approver: &fakeApprover{}}, opaStub(t, true))
	resp := getApproval(t, client, "does-not-exist", testToken)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown id: got %d want 404", resp.StatusCode)
	}
}

// The approvals endpoint is peer+token gated like /v1/govern: no token → 401.
func TestApprovalsEndpointRequiresToken(t *testing.T) {
	client, _ := startServer(t, Config{Approver: &fakeApprover{}}, opaStub(t, true))
	resp := getApproval(t, client, "any", "")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no token: got %d want 401", resp.StatusCode)
	}
}

// With no Approver configured the PDP behaves as today: an ask verdict is still
// returned to the PEP, no pending is opened, and the approvals endpoint 404s.
func TestAskWithoutApproverStillAsks(t *testing.T) {
	client, sock := startServer(t, Config{}, askOPA(t))
	req := sampleRequest("n-ask-noappr", "POST", "api.example.com")
	req.Action = Action{Tool: "exec", Args: "gog gmail send --to a@x.com"}
	req.Ctx.Surface = "exec"
	out := decode(t, post(t, client, sock, testToken, req))
	if out.Verdict != VerdictAsk {
		t.Fatalf("verdict: got %q want ask", out.Verdict)
	}
	resp := getApproval(t, client, out.DecisionID, testToken)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("no approver → approvals endpoint should 404: got %d", resp.StatusCode)
	}
}

// The overlay is tighten-only: when the base policy DENIES, a matching overlay
// rule must not be consulted and can never loosen the deny.
func TestOverlayNeverLoosensBaseDeny(t *testing.T) {
	ov := testOverlay(t, overlay.Rule{
		ID:      "would-ask",
		Verdict: overlay.VerdictAsk,
		Reason:  "irrelevant on a base deny",
		Enabled: true,
		Match:   overlay.Match{HostSuffixes: []string{"blocked.example.com"}},
	})
	client, sock := startServer(t, Config{Overlay: ov}, opaStub(t, false))

	resp := post(t, client, sock, testToken, sampleRequest("n-ov-basedeny", "POST", "blocked.example.com"))
	if out := decode(t, resp); out.Verdict != VerdictDeny {
		t.Fatalf("base deny must stand: got %q want deny", out.Verdict)
	}
}
