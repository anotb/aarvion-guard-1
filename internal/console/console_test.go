package console

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/aarvion-ai/aarvion-guard/internal/approve"
	"github.com/aarvion-ai/aarvion-guard/internal/overlay"
	"github.com/aarvion-ai/aarvion-guard/internal/packs"
	"github.com/aarvion-ai/aarvion-guard/internal/sinks"
)

const testToken = "s3cr3t-token"

func newTestServer(t *testing.T, cfg Config) *Server {
	t.Helper()
	if cfg.Token == "" {
		cfg.Token = testToken
	}
	return New(cfg)
}

func newOverlay(t *testing.T) *overlay.Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "overlay.json")
	st, err := overlay.Load(path)
	if err != nil {
		t.Fatalf("overlay.Load: %v", err)
	}
	return st
}

func do(t *testing.T, srv *Server, method, target, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, target, r)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	srv.mux.ServeHTTP(rec, req)
	return rec
}

func decode(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatalf("decode body %q: %v", rec.Body.String(), err)
	}
	return m
}

// fakeCP records calls for assertions.
type fakeCP struct {
	mu           sync.Mutex
	pushCalls    int
	lastPushed   []overlay.Rule
	statusCalls  int
	statusReturn SyncStatus
	statusErr    error
	pushErr      error
}

func (f *fakeCP) Status(ctx context.Context) (SyncStatus, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.statusCalls++
	return f.statusReturn, f.statusErr
}

func (f *fakeCP) PushOverlay(ctx context.Context, rules []overlay.Rule) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pushCalls++
	f.lastPushed = rules
	return f.pushErr
}

func (f *fakeCP) pushes() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.pushCalls
}

// --- Auth ---

func TestAPIRequiresBearer(t *testing.T) {
	srv := newTestServer(t, Config{Overlay: newOverlay(t)})

	endpoints := []struct {
		method, path string
	}{
		{http.MethodGet, "/api/status"},
		{http.MethodGet, "/api/feed"},
		{http.MethodGet, "/api/overlay"},
		{http.MethodPut, "/api/overlay"},
		{http.MethodPost, "/api/sync"},
		{http.MethodGet, "/api/packs"},
		{http.MethodPut, "/api/packs"},
		{http.MethodGet, "/api/learn"},
		{http.MethodPost, "/api/learn/promote"},
		{http.MethodGet, "/api/approvals"},
		{http.MethodPost, "/api/approvals/abc"},
	}

	for _, ep := range endpoints {
		// No token => 401.
		rec := do(t, srv, ep.method, ep.path, "", "")
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s %s without token: got %d, want 401", ep.method, ep.path, rec.Code)
		}
		// Wrong token => 401.
		rec = do(t, srv, ep.method, ep.path, "wrong", "")
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s %s wrong token: got %d, want 401", ep.method, ep.path, rec.Code)
		}
	}
}

func TestStatusWithBearer(t *testing.T) {
	srv := newTestServer(t, Config{Entity: "guard-1", Tenant: "acme", Overlay: newOverlay(t)})
	rec := do(t, srv, http.MethodGet, "/api/status", testToken, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200 (%s)", rec.Code, rec.Body.String())
	}
	m := decode(t, rec)
	if m["entity"] != "guard-1" || m["tenant"] != "acme" {
		t.Errorf("status identity mismatch: %v", m)
	}
	sync, ok := m["sync"].(map[string]any)
	if !ok || sync["state"] != "unknown" {
		t.Errorf("expected sync.state=unknown when CP nil, got %v", m["sync"])
	}
	if m["overlay_rules"].(float64) != 0 {
		t.Errorf("expected overlay_rules=0, got %v", m["overlay_rules"])
	}
}

// --- Overlay round-trip ---

func TestOverlayGetPutRoundTrip(t *testing.T) {
	ov := newOverlay(t)
	srv := newTestServer(t, Config{Overlay: ov})

	// Initially empty.
	rec := do(t, srv, http.MethodGet, "/api/overlay", testToken, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET overlay: got %d", rec.Code)
	}
	m := decode(t, rec)
	if rules, ok := m["rules"].([]any); !ok || len(rules) != 0 {
		t.Fatalf("expected 0 rules initially, got %v", m["rules"])
	}

	// PUT a valid deny rule.
	putBody := `{"rules":[{"id":"r1","description":"block rm","match":{"command_contains":["rm -rf"]},"verdict":"deny","reason":"dangerous","enabled":true}]}`
	rec = do(t, srv, http.MethodPut, "/api/overlay", testToken, putBody)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT overlay: got %d, want 200 (%s)", rec.Code, rec.Body.String())
	}
	m = decode(t, rec)
	if m["ok"] != true {
		t.Errorf("expected ok=true, got %v", m)
	}

	// GET again reflects the write.
	rec = do(t, srv, http.MethodGet, "/api/overlay", testToken, "")
	m = decode(t, rec)
	rules, ok := m["rules"].([]any)
	if !ok || len(rules) != 1 {
		t.Fatalf("expected 1 rule after PUT, got %v", m["rules"])
	}
	r0 := rules[0].(map[string]any)
	if r0["id"] != "r1" || r0["verdict"] != "deny" {
		t.Errorf("round-trip rule mismatch: %v", r0)
	}

	// Confirm it persisted through the real Store.
	if got := ov.Rules(); len(got) != 1 || got[0].ID != "r1" {
		t.Errorf("store did not persist rule: %v", got)
	}
}

func TestOverlayPutRejectsAllowVerdict(t *testing.T) {
	srv := newTestServer(t, Config{Overlay: newOverlay(t)})
	putBody := `{"rules":[{"id":"bad","match":{"tools":["x"]},"verdict":"allow","enabled":true}]}`
	rec := do(t, srv, http.MethodPut, "/api/overlay", testToken, putBody)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("PUT allow-verdict: got %d, want 400 (%s)", rec.Code, rec.Body.String())
	}
	m := decode(t, rec)
	if _, ok := m["error"]; !ok {
		t.Errorf("expected error field, got %v", m)
	}
}

// --- Feed ---

func TestFeedNewestFirst(t *testing.T) {
	dir := t.TempDir()
	feed := filepath.Join(dir, "decisions.jsonl")
	lines := []string{
		`{"n":1,"tool":"a"}`,
		`{"n":2,"tool":"b"}`,
		`{"n":3,"tool":"c"}`,
	}
	if err := os.WriteFile(feed, []byte(strings.Join(lines, "\n")+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	srv := newTestServer(t, Config{FeedPath: feed, Overlay: newOverlay(t)})

	rec := do(t, srv, http.MethodGet, "/api/feed?limit=2", testToken, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET feed: got %d", rec.Code)
	}
	m := decode(t, rec)
	rows, ok := m["rows"].([]any)
	if !ok || len(rows) != 2 {
		t.Fatalf("expected 2 rows, got %v", m["rows"])
	}
	// Newest-first: last two lines are n=2, n=3; newest-first => 3 then 2.
	first := rows[0].(map[string]any)
	second := rows[1].(map[string]any)
	if first["n"].(float64) != 3 || second["n"].(float64) != 2 {
		t.Errorf("expected newest-first [3,2], got [%v,%v]", first["n"], second["n"])
	}
}

func TestFeedMissingFile(t *testing.T) {
	srv := newTestServer(t, Config{FeedPath: filepath.Join(t.TempDir(), "nope.jsonl"), Overlay: newOverlay(t)})
	rec := do(t, srv, http.MethodGet, "/api/feed", testToken, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET feed missing: got %d", rec.Code)
	}
	m := decode(t, rec)
	rows, ok := m["rows"].([]any)
	if !ok || len(rows) != 0 {
		t.Errorf("expected empty rows for missing file, got %v", m["rows"])
	}
}

// --- Sync ---

func TestSyncCallsPushOverlay(t *testing.T) {
	ov := newOverlay(t)
	if err := ov.Replace([]overlay.Rule{
		{ID: "r1", Match: overlay.Match{Tools: []string{"shell"}}, Verdict: overlay.VerdictAsk, Enabled: true},
	}); err != nil {
		t.Fatal(err)
	}
	cp := &fakeCP{statusReturn: SyncStatus{State: "synced", Pending: 0}}
	srv := newTestServer(t, Config{Overlay: ov, CP: cp})

	rec := do(t, srv, http.MethodPost, "/api/sync", testToken, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("POST sync: got %d, want 200 (%s)", rec.Code, rec.Body.String())
	}
	if cp.pushes() != 1 {
		t.Errorf("expected PushOverlay called once, got %d", cp.pushes())
	}
	if len(cp.lastPushed) != 1 || cp.lastPushed[0].ID != "r1" {
		t.Errorf("PushOverlay received wrong rules: %v", cp.lastPushed)
	}
	m := decode(t, rec)
	if m["state"] != "synced" {
		t.Errorf("expected state=synced, got %v", m["state"])
	}
}

func TestSyncNoCP(t *testing.T) {
	srv := newTestServer(t, Config{Overlay: newOverlay(t)})
	rec := do(t, srv, http.MethodPost, "/api/sync", testToken, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("POST sync no CP: got %d", rec.Code)
	}
	m := decode(t, rec)
	if m["state"] != "unknown" {
		t.Errorf("expected state=unknown, got %v", m["state"])
	}
}

// --- Static UI ---

func TestStaticUIServedWithoutToken(t *testing.T) {
	srv := newTestServer(t, Config{Overlay: newOverlay(t)})
	rec := do(t, srv, http.MethodGet, "/", "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /: got %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "<") {
		t.Errorf("expected HTML body, got %q", rec.Body.String())
	}
}

// The SPA references the three new views so a smoke check of the served page
// catches an index.html that lost the packs/learning/approvals tabs.
func TestStaticUIReferencesNewViews(t *testing.T) {
	srv := newTestServer(t, Config{Overlay: newOverlay(t)})
	rec := do(t, srv, http.MethodGet, "/", "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /: got %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{"Packs", "Learning", "Approvals"} {
		if !strings.Contains(body, want) {
			t.Errorf("index.html missing view reference %q", want)
		}
	}
}

func newPacks(t *testing.T) *packs.Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "packs.json")
	ps, err := packs.Load(path)
	if err != nil {
		t.Fatalf("packs.Load: %v", err)
	}
	return ps
}

// --- Packs ---

func TestPacksGetReturnsCatalogWhenStoreEmpty(t *testing.T) {
	srv := newTestServer(t, Config{Overlay: newOverlay(t), Packs: newPacks(t)})
	rec := do(t, srv, http.MethodGet, "/api/packs", testToken, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET packs: got %d (%s)", rec.Code, rec.Body.String())
	}
	m := decode(t, rec)
	list, ok := m["packs"].([]any)
	if !ok || len(list) != len(packs.Catalog()) {
		t.Fatalf("expected %d catalog packs, got %v", len(packs.Catalog()), m["packs"])
	}
}

func TestPacksPutPersistsAndTriggersOnPacksChanged(t *testing.T) {
	ps := newPacks(t)
	var gotSet packs.Set
	var calls int
	srv := newTestServer(t, Config{
		Overlay: newOverlay(t),
		Packs:   ps,
		OnPacksChanged: func(s packs.Set) error {
			calls++
			gotSet = s
			return nil
		},
	})

	body := `{"packs":[{"id":"social-guard","title":"Social","mode":"enforce"}]}`
	rec := do(t, srv, http.MethodPut, "/api/packs", testToken, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT packs: got %d (%s)", rec.Code, rec.Body.String())
	}
	m := decode(t, rec)
	if m["ok"] != true {
		t.Errorf("expected ok=true, got %v", m)
	}

	// Persisted through the real store.
	if got := ps.Set(); len(got.Packs) != 1 || got.Packs[0].ID != "social-guard" || got.Packs[0].Mode != "enforce" {
		t.Errorf("store did not persist packs: %+v", got)
	}
	// OnPacksChanged fired exactly once with the saved set.
	if calls != 1 {
		t.Errorf("expected OnPacksChanged called once, got %d", calls)
	}
	if len(gotSet.Packs) != 1 || gotSet.Packs[0].ID != "social-guard" {
		t.Errorf("OnPacksChanged got wrong set: %+v", gotSet)
	}
}

func TestPacksPutRejectsInvalidMode(t *testing.T) {
	srv := newTestServer(t, Config{Overlay: newOverlay(t), Packs: newPacks(t)})
	body := `{"packs":[{"id":"social-guard","title":"Social","mode":"bogus"}]}`
	rec := do(t, srv, http.MethodPut, "/api/packs", testToken, body)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("PUT bad mode: got %d, want 400 (%s)", rec.Code, rec.Body.String())
	}
}

func TestPacksNilStoreDegradesGracefully(t *testing.T) {
	srv := newTestServer(t, Config{Overlay: newOverlay(t)})
	rec := do(t, srv, http.MethodGet, "/api/packs", testToken, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET packs nil store: got %d", rec.Code)
	}
	m := decode(t, rec)
	// Falls back to the built-in catalog.
	list, ok := m["packs"].([]any)
	if !ok || len(list) != len(packs.Catalog()) {
		t.Errorf("expected catalog fallback, got %v", m["packs"])
	}
}

// --- Learning ---

// fakeBehaviour returns a canned profile.
type fakeBehaviour struct{ profile sinks.Profile }

func (f fakeBehaviour) Profile() sinks.Profile { return f.profile }

func TestLearnReturnsProfileAndProposal(t *testing.T) {
	prof := sinks.Profile{
		GeneratedAt: "2026-07-10T00:00:00Z",
		Entries: []sinks.ProfileEntry{
			{Principal: "llm-twitter", Surface: "twitter", Verb: "read", Count: 3},
		},
	}
	srv := newTestServer(t, Config{
		Overlay:   newOverlay(t),
		Packs:     newPacks(t),
		Behaviour: fakeBehaviour{profile: prof},
	})
	rec := do(t, srv, http.MethodGet, "/api/learn", testToken, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET learn: got %d (%s)", rec.Code, rec.Body.String())
	}
	m := decode(t, rec)
	p, ok := m["profile"].(map[string]any)
	if !ok {
		t.Fatalf("expected profile object, got %v", m["profile"])
	}
	entries, ok := p["entries"].([]any)
	if !ok || len(entries) != 1 {
		t.Fatalf("expected 1 profile entry, got %v", p["entries"])
	}
	if _, ok := m["proposal"].(map[string]any); !ok {
		t.Fatalf("expected proposal object, got %v", m["proposal"])
	}
}

func TestLearnPromoteReplacesPacksAndRecompiles(t *testing.T) {
	prof := sinks.Profile{
		Entries: []sinks.ProfileEntry{
			{Principal: "llm-twitter", Surface: "twitter", Verb: "read", Count: 5},
		},
	}
	ps := newPacks(t)
	var calls int
	srv := newTestServer(t, Config{
		Overlay:        newOverlay(t),
		Packs:          ps,
		Behaviour:      fakeBehaviour{profile: prof},
		OnPacksChanged: func(packs.Set) error { calls++; return nil },
	})
	rec := do(t, srv, http.MethodPost, "/api/learn/promote", testToken, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("POST promote: got %d (%s)", rec.Code, rec.Body.String())
	}
	if calls != 1 {
		t.Errorf("expected OnPacksChanged once, got %d", calls)
	}
	// The promoted set (proposal) was persisted; dlp-guard is always proposed.
	got := ps.Set()
	var haveDLP bool
	for _, p := range got.Packs {
		if p.ID == "dlp-guard" {
			haveDLP = true
		}
	}
	if !haveDLP {
		t.Errorf("expected promoted set to include dlp-guard, got %+v", got)
	}
}

// --- Approvals ---

// fakeApprovals is an in-memory ApprovalsAPI double.
type fakeApprovals struct {
	pending  []approve.Pending
	resolved map[string]string // id -> verdict
}

func (f *fakeApprovals) List() []approve.Pending { return f.pending }

func (f *fakeApprovals) Resolve(id, verdict, who string) bool {
	for _, p := range f.pending {
		if p.DecisionID == id {
			if f.resolved == nil {
				f.resolved = map[string]string{}
			}
			f.resolved[id] = verdict
			return true
		}
	}
	return false
}

func TestApprovalsListReturnsPending(t *testing.T) {
	fa := &fakeApprovals{pending: []approve.Pending{
		{DecisionID: "d1", Principal: "main", Surface: "email", Verb: "send", Reason: "external recipient"},
	}}
	srv := newTestServer(t, Config{Overlay: newOverlay(t), Approvals: fa})
	rec := do(t, srv, http.MethodGet, "/api/approvals", testToken, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET approvals: got %d", rec.Code)
	}
	m := decode(t, rec)
	list, ok := m["pending"].([]any)
	if !ok || len(list) != 1 {
		t.Fatalf("expected 1 pending, got %v", m["pending"])
	}
	p0 := list[0].(map[string]any)
	if p0["decision_id"] != "d1" || p0["verb"] != "send" {
		t.Errorf("pending shape mismatch: %v", p0)
	}
}

func TestApprovalsResolve(t *testing.T) {
	fa := &fakeApprovals{pending: []approve.Pending{{DecisionID: "d1"}}}
	srv := newTestServer(t, Config{Overlay: newOverlay(t), Approvals: fa})
	rec := do(t, srv, http.MethodPost, "/api/approvals/d1", testToken, `{"verdict":"allow"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST approvals/d1: got %d (%s)", rec.Code, rec.Body.String())
	}
	if fa.resolved["d1"] != "allow" {
		t.Errorf("expected d1 resolved allow, got %v", fa.resolved)
	}
}

func TestApprovalsResolveUnknownIs404(t *testing.T) {
	fa := &fakeApprovals{}
	srv := newTestServer(t, Config{Overlay: newOverlay(t), Approvals: fa})
	rec := do(t, srv, http.MethodPost, "/api/approvals/nope", testToken, `{"verdict":"deny"}`)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("POST unknown approval: got %d, want 404 (%s)", rec.Code, rec.Body.String())
	}
}

func TestApprovalsResolveRejectsBadVerdict(t *testing.T) {
	fa := &fakeApprovals{pending: []approve.Pending{{DecisionID: "d1"}}}
	srv := newTestServer(t, Config{Overlay: newOverlay(t), Approvals: fa})
	rec := do(t, srv, http.MethodPost, "/api/approvals/d1", testToken, `{"verdict":"maybe"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("POST bad verdict: got %d, want 400 (%s)", rec.Code, rec.Body.String())
	}
}

func TestApprovalsNilDegradesGracefully(t *testing.T) {
	srv := newTestServer(t, Config{Overlay: newOverlay(t)})
	rec := do(t, srv, http.MethodGet, "/api/approvals", testToken, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET approvals nil: got %d", rec.Code)
	}
	m := decode(t, rec)
	list, ok := m["pending"].([]any)
	if !ok || len(list) != 0 {
		t.Errorf("expected empty pending for nil Approvals, got %v", m["pending"])
	}
}
