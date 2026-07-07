package decisions

import (
	"path/filepath"
	"testing"
)

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
