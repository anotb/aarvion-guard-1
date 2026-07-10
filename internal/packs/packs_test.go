package packs

import (
	"os"
	"path/filepath"
	"sort"
	"testing"
)

func newStore(t *testing.T, set Set) *Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "packs.json")
	s, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if err := s.Replace(set); err != nil {
		t.Fatalf("Replace: %v", err)
	}
	return s
}

func TestLoadMissingFileEmptySet(t *testing.T) {
	path := filepath.Join(t.TempDir(), "does-not-exist.json")
	s, err := Load(path)
	if err != nil {
		t.Fatalf("Load missing file: unexpected error %v", err)
	}
	if got := s.Set(); len(got.Packs) != 0 {
		t.Fatalf("expected empty set, got %d packs", len(got.Packs))
	}
	if s.Path() != path {
		t.Fatalf("Path()=%q want %q", s.Path(), path)
	}
}

func TestLoadBadJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "packs.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("expected error loading bad JSON, got nil")
	}
}

func TestReplaceRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "packs.json")
	s, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	in := Set{Packs: []Pack{
		{
			ID:    "social-guard",
			Title: "Social media (Twitter/X) guardrails",
			Mode:  "enforce",
			Params: map[string]any{
				"allow_read": true,
				"accounts":   []any{"me"},
			},
			PerAgent: map[string]string{"llm-twitter": "enforce"},
		},
		{ID: "dlp-guard", Title: "Secret & PII leak prevention", Mode: "observe"},
	}}
	if err := s.Replace(in); err != nil {
		t.Fatalf("Replace: %v", err)
	}

	// Persisted file is 0600.
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("file perm=%o want 0600", perm)
	}

	// Reload from disk into a fresh store; must match.
	s2, err := Load(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	got := s2.Set()
	if len(got.Packs) != 2 {
		t.Fatalf("reloaded %d packs want 2", len(got.Packs))
	}
	if got.Packs[0].ID != "social-guard" || got.Packs[0].Mode != "enforce" {
		t.Fatalf("pack[0] = %+v", got.Packs[0])
	}
	if got.Packs[0].PerAgent["llm-twitter"] != "enforce" {
		t.Fatalf("per-agent lost: %+v", got.Packs[0].PerAgent)
	}
	if got.Packs[0].Params["allow_read"] != true {
		t.Fatalf("params lost: %+v", got.Packs[0].Params)
	}
}

func TestReplaceInvalidModeRejected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "packs.json")
	s, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	err = s.Replace(Set{Packs: []Pack{
		{ID: "social-guard", Title: "X", Mode: "block"},
	}})
	if err == nil {
		t.Fatal("expected error for invalid mode, got nil")
	}
	// A rejected Replace must not write the file.
	if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
		t.Fatalf("file should not exist after rejected Replace, stat err=%v", statErr)
	}
}

func TestReplaceEachValidMode(t *testing.T) {
	for _, mode := range []string{"off", "observe", "ask", "enforce"} {
		s := newStore(t, Set{Packs: []Pack{{ID: "dlp-guard", Title: "X", Mode: mode}}})
		if got := s.Set().Packs[0].Mode; got != mode {
			t.Fatalf("mode round-trip: got %q want %q", got, mode)
		}
	}
}

func TestReplaceEmptyModeRejected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "packs.json")
	s, _ := Load(path)
	if err := s.Replace(Set{Packs: []Pack{{ID: "dlp-guard", Title: "X", Mode: ""}}}); err == nil {
		t.Fatal("expected error for empty mode, got nil")
	}
}

func TestReplaceDuplicateIDRejected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "packs.json")
	s, _ := Load(path)
	err := s.Replace(Set{Packs: []Pack{
		{ID: "dlp-guard", Title: "X", Mode: "off"},
		{ID: "dlp-guard", Title: "Y", Mode: "off"},
	}})
	if err == nil {
		t.Fatal("expected error for duplicate id, got nil")
	}
}

func TestReplaceEmptyIDRejected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "packs.json")
	s, _ := Load(path)
	if err := s.Replace(Set{Packs: []Pack{{ID: "", Title: "X", Mode: "off"}}}); err == nil {
		t.Fatal("expected error for empty id, got nil")
	}
}

func TestReplaceMissingTitleRejected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "packs.json")
	s, _ := Load(path)
	if err := s.Replace(Set{Packs: []Pack{{ID: "dlp-guard", Title: "", Mode: "off"}}}); err == nil {
		t.Fatal("expected error for missing title, got nil")
	}
}

func TestReplaceUnknownIDAllowed(t *testing.T) {
	// Forward-compat: an unknown pack id must be accepted.
	s := newStore(t, Set{Packs: []Pack{{ID: "future-guard", Title: "Future", Mode: "off"}}})
	if got := s.Set().Packs[0].ID; got != "future-guard" {
		t.Fatalf("unknown id lost: %q", got)
	}
}

func TestCatalog(t *testing.T) {
	cat := Catalog()
	if len(cat) != 7 {
		t.Fatalf("Catalog() returned %d packs, want 7", len(cat))
	}

	want := []string{
		"social-guard", "google-guard", "comms-guard",
		"dlp-guard", "api-guard", "github-guard", "infra-guard",
	}
	gotIDs := make([]string, len(cat))
	seen := map[string]struct{}{}
	for i, p := range cat {
		gotIDs[i] = p.ID
		if _, dup := seen[p.ID]; dup {
			t.Fatalf("duplicate catalog id %q", p.ID)
		}
		seen[p.ID] = struct{}{}
		if p.Title == "" {
			t.Fatalf("pack %q has empty Title", p.ID)
		}
		if p.Mode != "observe" {
			t.Fatalf("pack %q default Mode=%q want observe", p.ID, p.Mode)
		}
	}

	sortedGot := append([]string(nil), gotIDs...)
	sortedWant := append([]string(nil), want...)
	sort.Strings(sortedGot)
	sort.Strings(sortedWant)
	for i := range sortedWant {
		if sortedGot[i] != sortedWant[i] {
			t.Fatalf("catalog ids = %v, want (as set) %v", gotIDs, want)
		}
	}

	// The default catalog must itself be a valid, persistable Set.
	if err := (&Store{path: filepath.Join(t.TempDir(), "packs.json")}).Replace(Set{Packs: cat}); err != nil {
		t.Fatalf("default catalog is not a valid Set: %v", err)
	}
}

func TestCatalogDefaultParams(t *testing.T) {
	byID := map[string]Pack{}
	for _, p := range Catalog() {
		byID[p.ID] = p
	}

	if got := byID["social-guard"].Params["allow_read"]; got != true {
		t.Fatalf("social-guard allow_read=%v want true", got)
	}
	if got := byID["google-guard"].Params["allow_calendar_read"]; got != true {
		t.Fatalf("google-guard allow_calendar_read=%v want true", got)
	}
	if got := byID["dlp-guard"].Params["block_secrets"]; got != true {
		t.Fatalf("dlp-guard block_secrets=%v want true", got)
	}
	if got := byID["dlp-guard"].Params["ask_on_pii"]; got != true {
		t.Fatalf("dlp-guard ask_on_pii=%v want true", got)
	}
	if got := byID["api-guard"].Params["block_destructive"]; got != true {
		t.Fatalf("api-guard block_destructive=%v want true", got)
	}

	// comms-guard has nested quiet_hours defaults.
	qh, ok := byID["comms-guard"].Params["quiet_hours"].(map[string]any)
	if !ok {
		t.Fatalf("comms-guard quiet_hours not a map: %T", byID["comms-guard"].Params["quiet_hours"])
	}
	if qh["start"] != "23:00" || qh["end"] != "07:00" {
		t.Fatalf("comms-guard quiet_hours = %+v want 23:00-07:00", qh)
	}
}
