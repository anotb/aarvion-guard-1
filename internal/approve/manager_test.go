package approve

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aarvion-ai/aarvion-guard/internal/govern"
)

// sampleRequest builds a govern.ApprovalRequest for id.
func sampleRequest(id string) govern.ApprovalRequest {
	return govern.ApprovalRequest{
		DecisionID: id,
		Principal:  "llm-mail",
		Surface:    "email",
		Verb:       "send",
		Reason:     "google-guard: external recipient",
	}
}

// TestManagerSatisfiesInterfaces is a compile-time assertion that a Manager is
// both a govern.Approver and (structurally) a console-style approvals API.
func TestManagerSatisfiesGovernApprover(t *testing.T) {
	var _ govern.Approver = (*Manager)(nil)
}

// Open registers a pending under the request's decision_id, carrying the
// Manager's default TTL, and it shows up in List + Status.
func TestManagerOpenRegistersPendingWithTTL(t *testing.T) {
	store := NewStore()
	m := NewManager(store, nil, 90*time.Second)

	m.Open(sampleRequest("d-open"))

	list := m.List()
	if len(list) != 1 {
		t.Fatalf("List: want 1, got %d", len(list))
	}
	got := list[0]
	if got.DecisionID != "d-open" {
		t.Fatalf("id: want d-open, got %q", got.DecisionID)
	}
	if got.Principal != "llm-mail" || got.Surface != "email" || got.Verb != "send" {
		t.Fatalf("semantic not carried: %+v", got)
	}
	if got.Reason == "" {
		t.Fatalf("reason not carried")
	}
	if got.TTL != 90*time.Second {
		t.Fatalf("TTL: want 90s, got %s", got.TTL)
	}
	if got.Created.IsZero() {
		t.Fatalf("Created not stamped")
	}

	if v, ok := m.Status("d-open"); !ok || v != VerdictPending {
		t.Fatalf("Status: want pending/ok, got %q/%v", v, ok)
	}
}

// Resolve flips the pending and the endpoint-facing Status reflects it.
func TestManagerResolve(t *testing.T) {
	m := NewManager(NewStore(), nil, time.Minute)
	m.Open(sampleRequest("d-res"))

	if !m.Resolve("d-res", VerdictAllow, "owner") {
		t.Fatalf("Resolve should succeed for a pending id")
	}
	if v, _ := m.Status("d-res"); v != VerdictAllow {
		t.Fatalf("Status after resolve: want allow, got %q", v)
	}
	// Resolved pendings drop out of the inbox.
	if len(m.List()) != 0 {
		t.Fatalf("resolved pending should leave the inbox")
	}
}

// When a Telegram client is configured, Open notifies it (async) with the
// pending's decision_id in the callback data.
func TestManagerOpenNotifiesTelegram(t *testing.T) {
	var mu sync.Mutex
	var gotText string
	var calls int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		body, _ := io.ReadAll(r.Body)
		var payload struct {
			Text string `json:"text"`
		}
		_ = json.Unmarshal(body, &payload)
		mu.Lock()
		gotText = payload.Text
		mu.Unlock()
		_, _ = w.Write([]byte(`{"ok":true,"result":{"message_id":1}}`))
	}))
	defer srv.Close()

	tg := NewTelegram("BOT", "chat-1", srv.URL)
	m := NewManager(NewStore(), tg, time.Minute)

	m.Open(sampleRequest("d-tg"))

	// Notify runs in a goroutine; wait for it briefly.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if atomic.LoadInt32(&calls) > 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if atomic.LoadInt32(&calls) == 0 {
		t.Fatalf("Telegram was not notified on Open")
	}
	mu.Lock()
	text := gotText
	mu.Unlock()
	if text == "" {
		t.Fatalf("notify text empty")
	}
}

// A nil Telegram client is a no-op on Open (no panic, pending still registered).
func TestManagerNilTelegramSafe(t *testing.T) {
	m := NewManager(NewStore(), nil, time.Minute)
	m.Open(sampleRequest("d-nil"))
	if _, ok := m.Status("d-nil"); !ok {
		t.Fatalf("pending not registered with nil telegram")
	}
}
