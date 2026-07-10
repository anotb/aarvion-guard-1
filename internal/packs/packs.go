// Package packs implements the consumer-facing policy pack layer: a small,
// declarative set of per-surface guardrails an operator toggles (off/observe/
// ask/enforce) instead of hand-authoring overlay rules or rego. The schema and
// persistence live here; the two compilers (overlay + rego) that turn a Set of
// packs into enforceable policy build on this type.
//
// Persistence mirrors internal/overlay: a missing file yields an empty Set,
// Replace validates then writes atomically at 0600, and the on-disk shape is
// {"packs":[...]}.
//
// This package imports the standard library only.
package packs

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// Modes are the four levels an operator sets a pack to. off disables the pack;
// observe records what enforcement would do without changing the outcome (the
// first-run learn posture); ask escalates matches for confirmation; enforce
// blocks destructive matches and asks on the softer ones.
const (
	ModeOff     = "off"
	ModeObserve = "observe"
	ModeAsk     = "ask"
	ModeEnforce = "enforce"
)

// Pack is a single consumer guardrail. ID is a stable identifier (see Catalog
// for the built-ins); Title is human-facing; Mode is one of the Mode* values;
// Params holds pack-specific configuration (allowlists, quiet hours, toggles);
// PerAgent optionally overrides Mode for a named caller principal.
type Pack struct {
	ID       string            `json:"id"`
	Title    string            `json:"title"`
	Mode     string            `json:"mode"`
	Params   map[string]any    `json:"params,omitempty"`
	PerAgent map[string]string `json:"per_agent,omitempty"`
}

// Set is the operator's full pack configuration; the on-disk shape.
type Set struct {
	Packs []Pack `json:"packs"`
}

// Store is a file-backed set of packs. It is safe for concurrent use.
type Store struct {
	mu   sync.RWMutex
	path string
	set  Set
}

// Load reads the pack Set from path. A missing file yields an empty Set and a
// nil error. Malformed JSON yields an error.
func Load(path string) (*Store, error) {
	s := &Store{path: path}
	if err := s.reload(); err != nil {
		return nil, err
	}
	return s, nil
}

// Path returns the file path backing the store.
func (s *Store) Path() string { return s.path }

// Set returns a snapshot copy of the current pack Set.
func (s *Store) Set() Set {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return cloneSet(s.set)
}

// reload re-reads the backing file into memory. A missing file resets the
// store to an empty Set. Malformed JSON returns an error and leaves the
// in-memory Set unchanged.
func (s *Store) reload() error {
	data, err := os.ReadFile(s.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			s.mu.Lock()
			s.set = Set{}
			s.mu.Unlock()
			return nil
		}
		return err
	}
	var set Set
	if len(data) > 0 {
		if err := json.Unmarshal(data, &set); err != nil {
			return fmt.Errorf("packs: parse %s: %w", s.path, err)
		}
	}
	s.mu.Lock()
	s.set = set
	s.mu.Unlock()
	return nil
}

// Replace validates set and, if valid, writes it to disk atomically (0600) and
// swaps it into memory. Validation requires every id to be non-empty and
// unique, every Title non-empty, and every Mode to be one of the Mode* values.
// Unknown ids are accepted for forward-compatibility.
func (s *Store) Replace(set Set) error {
	if err := validate(set); err != nil {
		return err
	}

	stored := cloneSet(set)

	data, err := json.MarshalIndent(stored, "", "  ")
	if err != nil {
		return fmt.Errorf("packs: marshal: %w", err)
	}
	data = append(data, '\n')

	if err := atomicWrite(s.path, data); err != nil {
		return err
	}

	s.mu.Lock()
	s.set = stored
	s.mu.Unlock()
	return nil
}

// validate enforces the schema rules: unique non-empty ids, a Title on each
// pack, and a known Mode.
func validate(set Set) error {
	seen := make(map[string]struct{}, len(set.Packs))
	for i, p := range set.Packs {
		if p.ID == "" {
			return fmt.Errorf("packs: pack %d: empty id", i)
		}
		if _, dup := seen[p.ID]; dup {
			return fmt.Errorf("packs: duplicate pack id %q", p.ID)
		}
		seen[p.ID] = struct{}{}

		if p.Title == "" {
			return fmt.Errorf("packs: pack %q: empty title", p.ID)
		}
		if !validMode(p.Mode) {
			return fmt.Errorf("packs: pack %q: mode %q not one of off|observe|ask|enforce", p.ID, p.Mode)
		}
	}
	return nil
}

func validMode(mode string) bool {
	switch mode {
	case ModeOff, ModeObserve, ModeAsk, ModeEnforce:
		return true
	default:
		return false
	}
}

// cloneSet deep-copies a Set so stored/returned data never aliases the caller's
// maps and slices.
func cloneSet(set Set) Set {
	out := Set{}
	if set.Packs == nil {
		return out
	}
	out.Packs = make([]Pack, len(set.Packs))
	for i, p := range set.Packs {
		out.Packs[i] = clonePack(p)
	}
	return out
}

func clonePack(p Pack) Pack {
	cp := Pack{ID: p.ID, Title: p.Title, Mode: p.Mode}
	if p.Params != nil {
		cp.Params = cloneMap(p.Params)
	}
	if p.PerAgent != nil {
		cp.PerAgent = make(map[string]string, len(p.PerAgent))
		for k, v := range p.PerAgent {
			cp.PerAgent[k] = v
		}
	}
	return cp
}

// cloneMap deep-copies a params map, recursing into nested maps and slices so
// no nested structure is shared with the caller.
func cloneMap(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = cloneValue(v)
	}
	return out
}

func cloneValue(v any) any {
	switch t := v.(type) {
	case map[string]any:
		return cloneMap(t)
	case []any:
		s := make([]any, len(t))
		for i, e := range t {
			s[i] = cloneValue(e)
		}
		return s
	default:
		return v
	}
}

// atomicWrite writes data to path via a temp file in the same directory
// followed by a rename, with 0600 permissions.
func atomicWrite(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".packs-*.tmp")
	if err != nil {
		return fmt.Errorf("packs: create temp: %w", err)
	}
	tmpName := tmp.Name()

	cleanup := func() {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
	}

	if err := tmp.Chmod(0o600); err != nil {
		cleanup()
		return fmt.Errorf("packs: chmod temp: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		cleanup()
		return fmt.Errorf("packs: write temp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		cleanup()
		return fmt.Errorf("packs: sync temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("packs: close temp: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("packs: rename temp: %w", err)
	}
	return nil
}
