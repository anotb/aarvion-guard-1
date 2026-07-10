package approve

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func newPending(id string, ttl time.Duration) Pending {
	return Pending{
		DecisionID: id,
		Principal:  "llm-twitter",
		Surface:    "twitter",
		Verb:       "post",
		Reason:     "social-guard",
		Created:    time.Now(),
		TTL:        ttl,
	}
}

func TestOpenListShowsPending(t *testing.T) {
	s := NewStore()
	s.Open(newPending("d1", time.Minute))

	list := s.List()
	if len(list) != 1 {
		t.Fatalf("List: want 1 pending, got %d", len(list))
	}
	if list[0].DecisionID != "d1" {
		t.Fatalf("List: want d1, got %q", list[0].DecisionID)
	}

	verdict, ok := s.Status("d1")
	if !ok {
		t.Fatalf("Status(d1): want ok, got !ok")
	}
	if verdict != "pending" {
		t.Fatalf("Status(d1): want pending, got %q", verdict)
	}
}

func TestResolveAllow(t *testing.T) {
	s := NewStore()
	s.Open(newPending("d1", time.Minute))

	if !s.Resolve("d1", "allow", "owner") {
		t.Fatalf("Resolve(d1, allow): want true")
	}

	verdict, ok := s.Status("d1")
	if !ok {
		t.Fatalf("Status(d1): want ok after resolve")
	}
	if verdict != "allow" {
		t.Fatalf("Status(d1): want allow, got %q", verdict)
	}

	// Resolved pendings drop out of the pending list.
	for _, p := range s.List() {
		if p.DecisionID == "d1" {
			t.Fatalf("List: d1 should no longer be pending")
		}
	}
}

func TestResolveDeny(t *testing.T) {
	s := NewStore()
	s.Open(newPending("d1", time.Minute))

	if !s.Resolve("d1", "deny", "owner") {
		t.Fatalf("Resolve(d1, deny): want true")
	}
	verdict, ok := s.Status("d1")
	if !ok || verdict != "deny" {
		t.Fatalf("Status(d1): want deny/ok, got %q/%v", verdict, ok)
	}
}

func TestDoubleResolveNoOp(t *testing.T) {
	s := NewStore()
	s.Open(newPending("d1", time.Minute))

	if !s.Resolve("d1", "allow", "owner") {
		t.Fatalf("first Resolve: want true")
	}
	if s.Resolve("d1", "deny", "attacker") {
		t.Fatalf("second Resolve: want false (idempotent no-op)")
	}
	// The first verdict must stand.
	verdict, _ := s.Status("d1")
	if verdict != "allow" {
		t.Fatalf("Status(d1) after double resolve: want allow, got %q", verdict)
	}
}

func TestResolveUnknownID(t *testing.T) {
	s := NewStore()
	if s.Resolve("nope", "allow", "owner") {
		t.Fatalf("Resolve(unknown): want false")
	}
}

func TestStatusUnknownID(t *testing.T) {
	s := NewStore()
	if _, ok := s.Status("nope"); ok {
		t.Fatalf("Status(unknown): want ok=false")
	}
}

func TestRejectInvalidVerdict(t *testing.T) {
	s := NewStore()
	s.Open(newPending("d1", time.Minute))
	if s.Resolve("d1", "maybe", "owner") {
		t.Fatalf("Resolve with invalid verdict: want false")
	}
	verdict, _ := s.Status("d1")
	if verdict != "pending" {
		t.Fatalf("after invalid resolve: want still pending, got %q", verdict)
	}
}

func TestReapPastTTLDenies(t *testing.T) {
	s := NewStore()
	created := time.Now()
	p := newPending("d1", time.Minute)
	p.Created = created
	s.Open(p)

	// Not yet expired.
	s.Reap(created.Add(30 * time.Second))
	if v, _ := s.Status("d1"); v != "pending" {
		t.Fatalf("before TTL: want pending, got %q", v)
	}

	// Past TTL.
	s.Reap(created.Add(2 * time.Minute))
	v, ok := s.Status("d1")
	if !ok || v != "deny" {
		t.Fatalf("after TTL reap: want deny/ok, got %q/%v", v, ok)
	}

	// It must fall out of the pending list.
	for _, pl := range s.List() {
		if pl.DecisionID == "d1" {
			t.Fatalf("List: reaped d1 should not be pending")
		}
	}
}

func TestReapRecordsTimeoutWho(t *testing.T) {
	s := NewStore()
	created := time.Now()
	p := newPending("d1", time.Minute)
	p.Created = created
	s.Open(p)

	s.Reap(created.Add(2 * time.Minute))

	// A subsequent human resolution must not override the timeout deny.
	if s.Resolve("d1", "allow", "owner") {
		t.Fatalf("Resolve after reap: want false (already resolved by timeout)")
	}
}

func TestListSortedByCreatedPendingFirst(t *testing.T) {
	s := NewStore()
	base := time.Now()

	p2 := newPending("later", time.Minute)
	p2.Created = base.Add(2 * time.Second)
	p1 := newPending("earlier", time.Minute)
	p1.Created = base.Add(1 * time.Second)

	s.Open(p2)
	s.Open(p1)

	list := s.List()
	if len(list) != 2 {
		t.Fatalf("List: want 2, got %d", len(list))
	}
	if list[0].DecisionID != "earlier" || list[1].DecisionID != "later" {
		t.Fatalf("List: want [earlier, later], got [%s, %s]", list[0].DecisionID, list[1].DecisionID)
	}
}

func TestMirrorWritesFile(t *testing.T) {
	dir := t.TempDir()
	mirror := filepath.Join(dir, "pending")
	s := NewStoreWithMirror(mirror)

	s.Open(newPending("d1", time.Minute))

	path := filepath.Join(mirror, "d1.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("mirror file after Open: %v", err)
	}
	var rec struct {
		DecisionID string `json:"decision_id"`
		Verdict    string `json:"verdict"`
		Who        string `json:"who"`
	}
	if err := json.Unmarshal(data, &rec); err != nil {
		t.Fatalf("mirror file parse: %v", err)
	}
	if rec.DecisionID != "d1" || rec.Verdict != VerdictPending {
		t.Fatalf("mirror after Open: got %+v", rec)
	}

	// A 0600 file under a 0700 dir.
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Fatalf("mirror file perm: want 0600, got %v", fi.Mode().Perm())
	}
	if di, _ := os.Stat(mirror); di.Mode().Perm() != 0o700 {
		t.Fatalf("mirror dir perm: want 0700, got %v", di.Mode().Perm())
	}

	// Resolving updates the mirror in place.
	s.Resolve("d1", "allow", "owner")
	data, _ = os.ReadFile(path)
	_ = json.Unmarshal(data, &rec)
	if rec.Verdict != VerdictAllow || rec.Who != "owner" {
		t.Fatalf("mirror after Resolve: got %+v", rec)
	}
}

func TestConcurrentResolveOnlyOneWins(t *testing.T) {
	s := NewStore()
	s.Open(newPending("d1", time.Minute))

	const n = 20
	results := make(chan bool, n)
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		go func() {
			<-start
			results <- s.Resolve("d1", "allow", "owner")
		}()
	}
	close(start)

	wins := 0
	for i := 0; i < n; i++ {
		if <-results {
			wins++
		}
	}
	if wins != 1 {
		t.Fatalf("concurrent Resolve: want exactly 1 winner, got %d", wins)
	}
}
