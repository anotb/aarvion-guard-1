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
	"testing"
	"time"

	"github.com/aarvion-ai/aarvion-guard/internal/decisions"
	"github.com/aarvion-ai/aarvion-guard/internal/mitm"
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
