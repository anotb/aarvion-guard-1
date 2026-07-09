package decisions

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func readCursor(t *testing.T, path string) (chainState, bool) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		return chainState{}, false
	}
	var st chainState
	if err := json.Unmarshal(b, &st); err != nil {
		t.Fatalf("bad state file: %v", err)
	}
	return st, true
}

// A restart (same dp_id) must resume the chain from the last persisted row, so
// the next decision links to it instead of re-seeding at "0" (which broke the
// CP's chain verification at every restart boundary).
func TestChainResumesAcrossRestart(t *testing.T) {
	p := filepath.Join(t.TempDir(), "chain.json")

	r1 := New("http://cp", "t", "e", "tok", "dp", p)
	r1.Add("POST", "api.github.com", "/x", "deny", "pol", "r", "", true, 1)
	r1.Add("POST", "api.github.com", "/y", "deny", "pol", "r", "", true, 1)
	last := r1.pending[len(r1.pending)-1]
	r1.saveState(last.Seq, last.RowHash) // simulate the persist after a successful push

	r2 := New("http://cp", "t", "e", "tok", "dp", p)
	if r2.prev != last.RowHash || r2.seq != last.Seq {
		t.Fatalf("cursor not resumed: seq=%d prev=%q want seq=%d prev=%q", r2.seq, r2.prev, last.Seq, last.RowHash)
	}
	r2.Add("POST", "api.github.com", "/z", "deny", "pol", "r", "", true, 1)
	got := r2.pending[0]
	if got.PrevHash != last.RowHash {
		t.Fatalf("chain broken across restart: new prev=%q want %q", got.PrevHash, last.RowHash)
	}
	if got.Seq != last.Seq+1 {
		t.Fatalf("seq not continued: got %d want %d", got.Seq, last.Seq+1)
	}
}

func TestNoStateFileSeedsGenesis(t *testing.T) {
	r := New("http://cp", "t", "e", "tok", "dp", filepath.Join(t.TempDir(), "missing.json"))
	if r.prev != "0" || r.seq != 0 {
		t.Fatalf("genesis wrong: seq=%d prev=%q", r.seq, r.prev)
	}
}

// A non-2xx from the CP means it did NOT store the batch. flush must NOT advance
// the persisted cursor (doing so would push the chain past a row the CP never
// received) and must re-queue the batch for a later retry.
func TestFlushServerErrorDoesNotAdvanceCursorAndRequeues(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	p := filepath.Join(t.TempDir(), "chain.json")
	r := New(srv.URL, "t", "e", "tok", "dp", p)
	r.Add("POST", "api.github.com", "/x", "deny", "pol", "r", "", true, 1)
	r.Add("POST", "api.github.com", "/y", "deny", "pol", "r", "", true, 1)
	want := r.pending // capture before flush

	r.flush(context.Background())

	if _, ok := readCursor(t, p); ok {
		t.Fatal("cursor advanced on a 500 response - chain corruption risk")
	}
	if len(r.pending) != len(want) {
		t.Fatalf("batch not re-queued: pending=%d want=%d", len(r.pending), len(want))
	}
	if r.pending[0].RowHash != want[0].RowHash || r.pending[1].RowHash != want[1].RowHash {
		t.Fatal("re-queued batch lost its order/identity")
	}
	if _, _, errs, _ := r.Stats(); errs != 1 {
		t.Fatalf("errors counter not bumped: got %d want 1", errs)
	}
}

// A 2xx means the CP stored the batch, so the persisted cursor must advance to
// the last row and the queue must drain.
func TestFlushSuccessAdvancesCursor(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	p := filepath.Join(t.TempDir(), "chain.json")
	r := New(srv.URL, "t", "e", "tok", "dp", p)
	r.Add("POST", "api.github.com", "/x", "deny", "pol", "r", "", true, 1)
	r.Add("POST", "api.github.com", "/y", "deny", "pol", "r", "", true, 1)
	last := r.pending[len(r.pending)-1]

	r.flush(context.Background())

	st, ok := readCursor(t, p)
	if !ok {
		t.Fatal("cursor not persisted on 200")
	}
	if st.Seq != last.Seq || st.Prev != last.RowHash {
		t.Fatalf("cursor wrong: got seq=%d prev=%q want seq=%d prev=%q", st.Seq, st.Prev, last.Seq, last.RowHash)
	}
	if len(r.pending) != 0 {
		t.Fatalf("queue not drained after success: %d pending", len(r.pending))
	}
}

// A 2xx that isn't 200 (e.g. 204 No Content) must count as success — proving the
// push check is a 2xx-range test, not an == 200 test that would wrongly re-queue
// and stall the chain on a perfectly-accepted push.
func TestFlush2xxNon200IsSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent) // 204
	}))
	defer srv.Close()

	p := filepath.Join(t.TempDir(), "chain.json")
	r := New(srv.URL, "t", "e", "tok", "dp", p)
	r.Add("POST", "api.github.com", "/x", "deny", "pol", "r", "", true, 1)
	last := r.pending[len(r.pending)-1]

	r.flush(context.Background())

	st, ok := readCursor(t, p)
	if !ok {
		t.Fatal("204 must be treated as success and persist the cursor")
	}
	if st.Seq != last.Seq || st.Prev != last.RowHash {
		t.Fatalf("cursor wrong on 204: got seq=%d prev=%q want seq=%d prev=%q", st.Seq, st.Prev, last.Seq, last.RowHash)
	}
	if _, _, errs, _ := r.Stats(); errs != 0 {
		t.Fatalf("204 bumped the error counter (%d); it must be a success", errs)
	}
}

// At the backlog cap, further Adds must be dropped (incrementing the dropped
// counter) without growing pending or advancing the chain, and the rows already
// queued must keep contiguous prev/row linkage.
func TestAddAtCapDropsNewestAndKeepsChainContiguous(t *testing.T) {
	r := New("http://cp", "t", "e", "tok", "dp", "")

	// Fill to exactly the cap. Distinct paths avoid the allow-collapse; use deny
	// so every record is queued.
	for i := 0; i < maxPending; i++ {
		r.Add("POST", "api.github.com", pathN(i), "deny", "pol", "r", "", true, 1)
	}
	if len(r.pending) != maxPending {
		t.Fatalf("did not fill to cap: pending=%d want=%d", len(r.pending), maxPending)
	}
	seqAtCap := r.seq
	prevAtCap := r.prev

	// Over-cap Adds are dropped.
	for i := 0; i < 5; i++ {
		r.Add("POST", "api.github.com", pathN(maxPending+i), "deny", "pol", "r", "", true, 1)
	}
	if len(r.pending) != maxPending {
		t.Fatalf("pending grew past cap: %d", len(r.pending))
	}
	if r.seq != seqAtCap || r.prev != prevAtCap {
		t.Fatal("chain advanced while dropping - a dropped row must never be chained")
	}
	if _, _, _, dropped := r.Stats(); dropped != 5 {
		t.Fatalf("dropped counter wrong: got %d want 5", dropped)
	}

	// Every queued row must link to the one before it.
	for i := 1; i < len(r.pending); i++ {
		if r.pending[i].PrevHash != r.pending[i-1].RowHash {
			t.Fatalf("chain gap at index %d: prev=%q want %q", i, r.pending[i].PrevHash, r.pending[i-1].RowHash)
		}
	}
}

func pathN(i int) string {
	return "/p/" + strconv.Itoa(i)
}
