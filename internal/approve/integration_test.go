package approve

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aarvion-ai/aarvion-guard/internal/decisions"
	"github.com/aarvion-ai/aarvion-guard/internal/govern"
	"github.com/aarvion-ai/aarvion-guard/internal/policy"
)

// TestAskThroughPDPOpensPendingAndResolves is the end-to-end proof of the Phase C
// approval flow using the REAL approve.Manager wired into the REAL govern PDP
// (not a fake): an ask verdict opens a pending under the decision_id handed to the
// PEP; GET /v1/approvals/{id} reports "pending"; a console/Telegram Resolve("allow")
// flips it; the same endpoint then reports "allow". This is the exact chain the PEP
// poll (awaitApproval) drives, exercised over the Unix socket.
func TestAskThroughPDPOpensPendingAndResolves(t *testing.T) {
	const token = "s3cr3t-token"

	// The real approval hub: a pending store + Manager, no Telegram (console-only).
	store := NewStore()
	mgr := NewManager(store, nil, 90*time.Second)

	// OPA stub that always answers ask, so the PDP's final verdict is ask.
	opa := askOPAStub(t)

	sock := shortSocketPath(t)
	srv := govern.New(govern.Config{
		SocketPath: sock,
		Token:      token,
		PeerUID:    uint32(os.Getuid()),
		Approver:   mgr, // <-- the real Manager, not a fake
	}, opa, testRecorder(t))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() { errCh <- srv.ListenAndServe(ctx) }()
	waitForSocket(t, sock, errCh)

	client := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", sock)
		},
	}}

	// 1. Drive a request through the PDP. The OPA stub forces ask.
	reqBody := map[string]any{
		"contract_version": "1",
		"nonce":            "n-integration-1",
		"ctx": map[string]any{
			"surface": "exec",
			"phase":   "pre",
			"caller":  map[string]any{"principal_id": "llm-mail", "source": "openclaw"},
		},
		"action": map[string]any{"tool": "exec", "operation": "exec", "args": "gog gmail send --to a@x.com"},
		"attributes": map[string]any{
			"request": map[string]any{"http": map[string]any{"method": "POST", "host": "api.example.com", "path": "/x"}},
		},
	}
	out := postGovern(t, client, token, reqBody)

	if out.Verdict != govern.VerdictAsk {
		t.Fatalf("verdict: got %q want ask", out.Verdict)
	}
	if out.DecisionID == "" {
		t.Fatal("ask response missing decision_id")
	}
	id := out.DecisionID

	// 2. The real Manager opened a pending under that exact id, and it is pending.
	if v, ok := mgr.Status(id); !ok || v != VerdictPending {
		t.Fatalf("Manager.Status after ask: got %q/%v want pending/true", v, ok)
	}

	// 3. GET /v1/approvals/{id} (what the PEP polls) reports pending.
	if got := getApprovalStatus(t, client, token, id); got != "pending" {
		t.Fatalf("approvals endpoint before resolve: got %q want pending", got)
	}

	// 4. The owner resolves it (console POST / Telegram tap both land here).
	if !mgr.Resolve(id, VerdictAllow, "console") {
		t.Fatalf("Resolve(allow) on a pending id should win")
	}

	// 5. Status and the endpoint now report allow: the PEP poll would proceed.
	if v, ok := mgr.Status(id); !ok || v != VerdictAllow {
		t.Fatalf("Manager.Status after resolve: got %q/%v want allow/true", v, ok)
	}
	if got := getApprovalStatus(t, client, token, id); got != "allow" {
		t.Fatalf("approvals endpoint after resolve: got %q want allow", got)
	}

	// 6. A resolved pending is out of the inbox, and a second resolve is a no-op.
	if len(mgr.List()) != 0 {
		t.Fatalf("resolved pending should leave the inbox, got %d", len(mgr.List()))
	}
	if mgr.Resolve(id, VerdictDeny, "console") {
		t.Fatalf("double-resolve must be a no-op")
	}
}

// askOPAStub returns a policy client whose OPA always answers ask (allowed=false +
// x-aarvion-verdict=ask), forcing the PDP's final verdict to ask.
func askOPAStub(t *testing.T) *policy.Client {
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

func testRecorder(t *testing.T) *decisions.Recorder {
	t.Helper()
	return decisions.New("http://cp", "tenant", "entity", "tok", "dp", filepath.Join(t.TempDir(), "chain.json"))
}

// shortSocketPath returns a socket path short enough for the ~104-byte sun_path
// limit (macOS temp dirs blow past it), cleaned up after the test.
func shortSocketPath(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "ap")
	if err != nil {
		t.Fatalf("mkdtemp: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return filepath.Join(dir, "g.sock")
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
	t.Fatal("socket did not appear in time")
}

func postGovern(t *testing.T, client *http.Client, token string, body map[string]any) govern.Response {
	t.Helper()
	raw, _ := json.Marshal(body)
	hr, err := http.NewRequest(http.MethodPost, "http://unix/v1/govern", bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	hr.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(hr)
	if err != nil {
		t.Fatalf("post govern: %v", err)
	}
	defer resp.Body.Close()
	var out govern.Response
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode govern response: %v", err)
	}
	return out
}

func getApprovalStatus(t *testing.T, client *http.Client, token, id string) string {
	t.Helper()
	hr, err := http.NewRequest(http.MethodGet, "http://unix/v1/approvals/"+id, nil)
	if err != nil {
		t.Fatal(err)
	}
	hr.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(hr)
	if err != nil {
		t.Fatalf("get approval: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("approvals endpoint: status %d", resp.StatusCode)
	}
	var body struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode approval: %v", err)
	}
	return body.Status
}
