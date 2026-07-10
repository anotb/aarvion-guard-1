package sinks

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aarvion-ai/aarvion-guard/internal/govern"
	"github.com/aarvion-ai/aarvion-guard/internal/normalize"
)

// Compile-time guarantee that *Behaviour satisfies the observer interface the
// PDP wires in, so a signature drift on either side fails the build here rather
// than at the cmd/guard wiring site.
var _ govern.BehaviourObserver = (*Behaviour)(nil)

// at builds a clock stuck at a fixed hour so the hour histogram is deterministic.
func at(hour int) func() time.Time {
	ts := time.Date(2026, 7, 9, hour, 30, 0, 0, time.UTC)
	return func() time.Time { return ts }
}

func readBehaviourFile(t *testing.T, path string) Profile {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read profile: %v", err)
	}
	var p Profile
	if err := json.Unmarshal(b, &p); err != nil {
		t.Fatalf("unmarshal profile: %v", err)
	}
	return p
}

// entryFor finds the profile entry for a {principal,surface,verb} key.
func entryFor(p Profile, principal, surface, verb string) (ProfileEntry, bool) {
	for _, e := range p.Entries {
		if e.Principal == principal && e.Surface == surface && e.Verb == verb {
			return e, true
		}
	}
	return ProfileEntry{}, false
}

// Feeding a series of semantic actions builds the expected per-key profile:
// counts, target tallies, the hour histogram, last_seen, and the would-block
// counter (incremented when a would-be verdict is deny/ask).
func TestBehaviourBuildsProfile(t *testing.T) {
	b := NewBehaviour(filepath.Join(t.TempDir(), "behaviour-profile.json"), 0)
	b.now = at(14)

	// llm-twitter reads twice, then a post that WOULD be denied.
	b.Observe(normalize.Action{Surface: "twitter", Verb: "read"}, "llm-twitter", "allow", true)
	b.Observe(normalize.Action{Surface: "twitter", Verb: "read"}, "llm-twitter", "allow", true)
	b.Observe(normalize.Action{Surface: "twitter", Verb: "post"}, "llm-twitter", "deny", false)

	// main sends email to two recipients across two calls (one repeat).
	b.Observe(normalize.Action{Surface: "email", Verb: "send", Targets: []string{"a@x.com"}}, "main", "allow", true)
	b.Observe(normalize.Action{Surface: "email", Verb: "send", Targets: []string{"a@x.com", "b@y.com"}}, "main", "ask", true)

	p := b.Profile()

	read, ok := entryFor(p, "llm-twitter", "twitter", "read")
	if !ok {
		t.Fatal("missing llm-twitter/twitter/read entry")
	}
	if read.Count != 2 {
		t.Fatalf("read count: got %d want 2", read.Count)
	}
	if read.WouldBlock != 0 {
		t.Fatalf("read would_block: got %d want 0", read.WouldBlock)
	}
	if read.Hours[14] != 2 {
		t.Fatalf("read hours[14]: got %d want 2", read.Hours[14])
	}
	if read.LastSeen == "" {
		t.Fatalf("read last_seen empty")
	}

	post, ok := entryFor(p, "llm-twitter", "twitter", "post")
	if !ok {
		t.Fatal("missing llm-twitter/twitter/post entry")
	}
	if post.Count != 1 || post.WouldBlock != 1 {
		t.Fatalf("post count/would_block: got %d/%d want 1/1", post.Count, post.WouldBlock)
	}

	send, ok := entryFor(p, "main", "email", "send")
	if !ok {
		t.Fatal("missing main/email/send entry")
	}
	if send.Count != 2 {
		t.Fatalf("send count: got %d want 2", send.Count)
	}
	// a@x.com seen twice, b@y.com once.
	if send.Targets["a@x.com"] != 2 || send.Targets["b@y.com"] != 1 {
		t.Fatalf("send targets: got %v want a@x.com:2 b@y.com:1", send.Targets)
	}
	// The "ask" would-be counts as a would-block.
	if send.WouldBlock != 1 {
		t.Fatalf("send would_block: got %d want 1", send.WouldBlock)
	}
}

// The target set is bounded: once the cap is hit, no new distinct targets are
// added, but existing ones keep counting (so the profile can't grow unbounded).
func TestBehaviourTargetsBounded(t *testing.T) {
	b := NewBehaviour(filepath.Join(t.TempDir(), "behaviour-profile.json"), 0)
	b.now = at(9)

	for i := 0; i < maxProfileTargets+20; i++ {
		tgt := "user" + itoa(i) + "@x.com"
		b.Observe(normalize.Action{Surface: "email", Verb: "send", Targets: []string{tgt}}, "main", "allow", true)
	}
	// An already-seen target must still count up.
	b.Observe(normalize.Action{Surface: "email", Verb: "send", Targets: []string{"user0@x.com"}}, "main", "allow", true)

	e, ok := entryFor(b.Profile(), "main", "email", "send")
	if !ok {
		t.Fatal("missing entry")
	}
	if len(e.Targets) > maxProfileTargets {
		t.Fatalf("targets unbounded: got %d want <= %d", len(e.Targets), maxProfileTargets)
	}
	if e.Targets["user0@x.com"] != 2 {
		t.Fatalf("existing target not counted after cap: got %d want 2", e.Targets["user0@x.com"])
	}
}

// Close forces a final 0600 write, and the persisted file round-trips back into
// an equivalent Profile.
func TestBehaviourPersistsOnClose(t *testing.T) {
	path := filepath.Join(t.TempDir(), "behaviour-profile.json")
	b := NewBehaviour(path, 0)
	b.now = at(3)

	b.Observe(normalize.Action{Surface: "github", Verb: "push"}, "ci", "allow", true)
	b.Observe(normalize.Action{Surface: "github", Verb: "force_push"}, "ci", "deny", true)

	if err := b.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("file mode: got %v want 0600", fi.Mode().Perm())
	}

	p := readBehaviourFile(t, path)
	if _, ok := entryFor(p, "ci", "github", "push"); !ok {
		t.Fatal("push entry lost across persist")
	}
	fp, ok := entryFor(p, "ci", "github", "force_push")
	if !ok {
		t.Fatal("force_push entry lost across persist")
	}
	if fp.WouldBlock != 1 {
		t.Fatalf("force_push would_block after reload: got %d want 1", fp.WouldBlock)
	}
	if p.GeneratedAt == "" {
		t.Fatalf("generated_at empty")
	}
}

// Profile() output is deterministic: entries sorted by principal/surface/verb.
func TestBehaviourProfileDeterministic(t *testing.T) {
	b := NewBehaviour(filepath.Join(t.TempDir(), "behaviour-profile.json"), 0)
	b.now = at(1)
	b.Observe(normalize.Action{Surface: "twitter", Verb: "post"}, "z-agent", "allow", true)
	b.Observe(normalize.Action{Surface: "email", Verb: "send"}, "a-agent", "allow", true)
	b.Observe(normalize.Action{Surface: "email", Verb: "read"}, "a-agent", "allow", true)

	p := b.Profile()
	for i := 1; i < len(p.Entries); i++ {
		prev, cur := p.Entries[i-1], p.Entries[i]
		if lessEntry(cur, prev) {
			t.Fatalf("entries not sorted at %d: %+v before %+v", i, prev, cur)
		}
	}
}

// lessEntry mirrors the intended sort order for the determinism assertion.
func lessEntry(a, bb ProfileEntry) bool {
	if a.Principal != bb.Principal {
		return a.Principal < bb.Principal
	}
	if a.Surface != bb.Surface {
		return a.Surface < bb.Surface
	}
	return a.Verb < bb.Verb
}

// itoa avoids pulling strconv into the test just for one conversion.
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var buf [20]byte
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	return string(buf[pos:])
}
