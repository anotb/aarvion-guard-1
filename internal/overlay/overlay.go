// Package overlay implements a tighten-only local policy overlay.
//
// The overlay is consulted by the caller ONLY when the base policy decision
// already ALLOWED an action. Match yields at most a deny/ask verdict, so an
// overlay rule can only make the effective policy STRICTER, never looser. This
// is the safety guarantee of the package: there is no code path by which the
// overlay can turn a base deny/ask into an allow.
//
// This package imports the standard library only. It has no dependencies on
// other guard packages.
package overlay

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Verdict is the outcome an overlay rule can impose. Tighten-only: the only
// permitted verdicts are deny and ask.
type Verdict string

const (
	// VerdictDeny blocks the action outright.
	VerdictDeny Verdict = "deny"
	// VerdictAsk escalates the action for confirmation.
	VerdictAsk Verdict = "ask"
)

// Action is the concrete action being judged against the overlay rules.
//
// The first block of fields are the original network/tool facets. The second
// block are the semantic facets produced by the normalizer (surface/verb/etc.),
// consumed by the semantic Match facets below.
type Action struct {
	Tool    string
	Command string
	Host    string
	Method  string
	Path    string
	Surface string

	// Semantic facets (populated by internal/normalize on the PDP path).
	Verb      string          // send|read|delete|share|post|reply|dm|follow|push|...
	Binary    string          // gog|bird|gh|git|curl|docker|... ("" for native tools)
	Channel   string          // telegram|discord|whatsapp|reddit|...
	Principal string          // caller principal_id
	Targets   []string        // recipients / repo / file id / host
	Findings  []string        // DLP labels: "secret:ghp"|"pii:email"|...
	Flags     map[string]bool // force|external_recipient|public_share|destructive|...
	Now       time.Time       // evaluation time, for time-window facets
}

// Match describes the facets a rule tests against an Action. A rule matches
// when EVERY non-empty facet matches (AND across facets), and within a single
// facet any one entry matching is sufficient (OR within a facet). A Match with
// no populated facets NEVER matches.
type Match struct {
	// Tools matches Action.Tool by exact (case-sensitive) tool name.
	Tools []string `json:"tools,omitempty"`
	// CommandContains matches when Action.Command contains any listed
	// substring, compared case-insensitively.
	CommandContains []string `json:"command_contains,omitempty"`
	// HostSuffixes matches Action.Host by exact host or by ".suffix" domain
	// (case-insensitive). A bare "example.com" entry matches the host
	// "example.com" and any subdomain "sub.example.com".
	HostSuffixes []string `json:"host_suffixes,omitempty"`
	// Methods matches Action.Method by exact HTTP method, case-insensitive.
	Methods []string `json:"methods,omitempty"`

	// --- semantic facets (Task A3) ---

	// Surfaces matches Action.Surface by exact name, case-insensitive (OR).
	Surfaces []string `json:"surfaces,omitempty"`
	// Verbs matches Action.Verb by exact name, case-insensitive (OR).
	Verbs []string `json:"verbs,omitempty"`
	// Principals matches Action.Principal (caller principal_id) by exact name,
	// case-insensitive (OR).
	Principals []string `json:"principals,omitempty"`
	// Channels matches Action.Channel by exact name, case-insensitive (OR).
	Channels []string `json:"channels,omitempty"`
	// FlagsAll matches only when EVERY named flag is present and true in
	// Action.Flags (AND).
	FlagsAll []string `json:"flags_all,omitempty"`
	// FindingsAny matches when ANY listed DLP label is present in
	// Action.Findings, case-insensitive (OR).
	FindingsAny []string `json:"findings_any,omitempty"`
	// NotTargets is a recipient/host allowlist inversion: it matches when NONE
	// of Action.Targets is in this set (case-insensitive). If Action.Targets is
	// empty it does NOT match, so targetless actions are never blocked by it.
	NotTargets []string `json:"not_targets,omitempty"`
	// TimeWindow matches when Action.Now (local time) falls inside the window,
	// handling midnight wraparound. A zero Action.Now never matches.
	TimeWindow *Window `json:"time_window,omitempty"`
}

// Window is a wall-clock time window used by the TimeWindow facet (e.g. quiet
// hours). Start and End are "HH:MM" 24-hour local times; the window is
// [Start, End) and wraps across midnight when End <= Start (e.g. 23:00-07:00).
// Days optionally restricts the window to given weekdays; empty means every
// day. Day entries are matched case-insensitively as lowercased 3-letter
// (mon..sun) or full names (monday..sunday).
type Window struct {
	Start string   `json:"start"`
	End   string   `json:"end"`
	Days  []string `json:"days,omitempty"`
}

// Rule is a single overlay policy entry.
type Rule struct {
	ID          string  `json:"id"`
	Description string  `json:"description,omitempty"`
	Match       Match   `json:"match"`
	Verdict     Verdict `json:"verdict"`
	Reason      string  `json:"reason,omitempty"`
	Enabled     bool    `json:"enabled"`
}

// file is the on-disk representation: {"rules":[...]}.
type file struct {
	Rules []Rule `json:"rules"`
}

// Store is a file-backed, hot-reloadable set of overlay rules. It is safe for
// concurrent use.
type Store struct {
	mu    sync.RWMutex
	path  string
	rules []Rule
}

// Load reads the overlay rules from path. A missing file yields an empty store
// and a nil error. Malformed JSON yields an error.
func Load(path string) (*Store, error) {
	s := &Store{path: path}
	if err := s.Reload(); err != nil {
		return nil, err
	}
	return s, nil
}

// Path returns the file path backing the store.
func (s *Store) Path() string {
	return s.path
}

// Rules returns a snapshot copy of the current rules.
func (s *Store) Rules() []Rule {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Rule, len(s.rules))
	copy(out, s.rules)
	return out
}

// Reload re-reads the backing file into memory. A missing file resets the
// store to empty. Malformed JSON returns an error and leaves the in-memory
// rules unchanged.
func (s *Store) Reload() error {
	data, err := os.ReadFile(s.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			s.mu.Lock()
			s.rules = nil
			s.mu.Unlock()
			return nil
		}
		return err
	}
	var f file
	if len(data) > 0 {
		if err := json.Unmarshal(data, &f); err != nil {
			return fmt.Errorf("overlay: parse %s: %w", s.path, err)
		}
	}
	s.mu.Lock()
	s.rules = f.Rules
	s.mu.Unlock()
	return nil
}

// Replace validates rules (tighten-only) and, if valid, writes them to disk
// atomically (0600) and swaps them into memory. Validation requires every
// Verdict to be deny or ask, and every ID to be non-empty and unique.
func (s *Store) Replace(rules []Rule) error {
	if err := validate(rules); err != nil {
		return err
	}

	// Copy defensively so later caller mutations don't affect the store.
	stored := make([]Rule, len(rules))
	copy(stored, rules)

	data, err := json.MarshalIndent(file{Rules: stored}, "", "  ")
	if err != nil {
		return fmt.Errorf("overlay: marshal: %w", err)
	}
	data = append(data, '\n')

	if err := atomicWrite(s.path, data); err != nil {
		return err
	}

	s.mu.Lock()
	s.rules = stored
	s.mu.Unlock()
	return nil
}

// Match returns the first ENABLED rule whose Match matches a, and true. If no
// enabled rule matches it returns the zero Rule and false.
func (s *Store) Match(a Action) (Rule, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, r := range s.rules {
		if !r.Enabled {
			continue
		}
		if r.Match.matches(a) {
			return r, true
		}
	}
	return Rule{}, false
}

// matches reports whether m matches a. Every non-empty facet must match (AND);
// within a facet, any entry matching suffices (OR). An all-empty Match never
// matches.
func (m Match) matches(a Action) bool {
	if m.empty() {
		return false
	}

	if len(m.Tools) > 0 && !matchTools(m.Tools, a.Tool) {
		return false
	}
	if len(m.CommandContains) > 0 && !matchCommandContains(m.CommandContains, a.Command) {
		return false
	}
	if len(m.HostSuffixes) > 0 && !matchHostSuffixes(m.HostSuffixes, a.Host) {
		return false
	}
	if len(m.Methods) > 0 && !matchMethods(m.Methods, a.Method) {
		return false
	}
	// Semantic facets (AND across facets, OR within each unless noted).
	if len(m.Surfaces) > 0 && !matchEqualFoldAny(m.Surfaces, a.Surface) {
		return false
	}
	if len(m.Verbs) > 0 && !matchEqualFoldAny(m.Verbs, a.Verb) {
		return false
	}
	if len(m.Principals) > 0 && !matchEqualFoldAny(m.Principals, a.Principal) {
		return false
	}
	if len(m.Channels) > 0 && !matchEqualFoldAny(m.Channels, a.Channel) {
		return false
	}
	if len(m.FlagsAll) > 0 && !matchFlagsAll(m.FlagsAll, a.Flags) {
		return false
	}
	if len(m.FindingsAny) > 0 && !matchFindingsAny(m.FindingsAny, a.Findings) {
		return false
	}
	if len(m.NotTargets) > 0 && !matchNotTargets(m.NotTargets, a.Targets) {
		return false
	}
	if m.TimeWindow != nil && !m.TimeWindow.matches(a.Now) {
		return false
	}
	return true
}

// empty reports whether no facet is populated. An empty Match never matches.
func (m Match) empty() bool {
	return len(m.Tools) == 0 && len(m.CommandContains) == 0 &&
		len(m.HostSuffixes) == 0 && len(m.Methods) == 0 &&
		len(m.Surfaces) == 0 && len(m.Verbs) == 0 &&
		len(m.Principals) == 0 && len(m.Channels) == 0 &&
		len(m.FlagsAll) == 0 && len(m.FindingsAny) == 0 &&
		len(m.NotTargets) == 0 && m.TimeWindow == nil
}

// matchTools matches tool name exactly (case-sensitive).
func matchTools(tools []string, tool string) bool {
	for _, t := range tools {
		if t == tool {
			return true
		}
	}
	return false
}

// matchCommandContains matches a case-insensitive substring of command.
func matchCommandContains(subs []string, command string) bool {
	lc := strings.ToLower(command)
	for _, sub := range subs {
		if strings.Contains(lc, strings.ToLower(sub)) {
			return true
		}
	}
	return false
}

// matchHostSuffixes matches host by exact host or ".suffix" domain,
// case-insensitively. A bare "example.com" entry matches "example.com" and any
// "sub.example.com".
func matchHostSuffixes(suffixes []string, host string) bool {
	lh := strings.ToLower(strings.TrimSuffix(host, "."))
	for _, suf := range suffixes {
		ls := strings.ToLower(strings.TrimSuffix(suf, "."))
		if ls == "" {
			continue
		}
		// Normalise a leading dot: ".example.com" and "example.com" behave
		// the same for suffix matching.
		bare := strings.TrimPrefix(ls, ".")
		if lh == bare {
			return true
		}
		if strings.HasSuffix(lh, "."+bare) {
			return true
		}
	}
	return false
}

// matchMethods matches HTTP method exactly, case-insensitively.
func matchMethods(methods []string, method string) bool {
	for _, m := range methods {
		if strings.EqualFold(m, method) {
			return true
		}
	}
	return false
}

// matchEqualFoldAny reports whether value equals any listed entry,
// case-insensitively. An empty value never matches (so an unset facet on the
// action does not satisfy a populated rule facet).
func matchEqualFoldAny(list []string, value string) bool {
	if value == "" {
		return false
	}
	for _, e := range list {
		if strings.EqualFold(e, value) {
			return true
		}
	}
	return false
}

// matchFlagsAll reports whether every named flag is present and true in flags.
func matchFlagsAll(names []string, flags map[string]bool) bool {
	for _, n := range names {
		if !flags[n] {
			return false
		}
	}
	return true
}

// matchFindingsAny reports whether any listed label is present in findings,
// compared case-insensitively (OR).
func matchFindingsAny(labels, findings []string) bool {
	for _, want := range labels {
		for _, f := range findings {
			if strings.EqualFold(want, f) {
				return true
			}
		}
	}
	return false
}

// matchNotTargets implements the recipient/host allowlist inversion. It matches
// when NONE of targets is in the allowlist (case-insensitive). Empty targets
// never match, so a targetless action is never blocked by a NotTargets facet.
func matchNotTargets(allowlist, targets []string) bool {
	if len(targets) == 0 {
		return false
	}
	for _, t := range targets {
		for _, allowed := range allowlist {
			if strings.EqualFold(t, allowed) {
				// A target is on the allowlist: spare the whole action.
				return false
			}
		}
	}
	return true
}

// matches reports whether now (interpreted in its own location) falls inside
// the window [Start, End), handling midnight wraparound, and on an allowed day.
// A zero now never matches.
func (w *Window) matches(now time.Time) bool {
	if now.IsZero() {
		return false
	}
	if !w.dayAllowed(now.Weekday()) {
		return false
	}
	start, okS := parseHHMM(w.Start)
	end, okE := parseHHMM(w.End)
	if !okS || !okE {
		return false
	}
	cur := now.Hour()*60 + now.Minute()
	if start == end {
		// Zero-width window matches nothing.
		return false
	}
	if start < end {
		// Same-day window [start, end).
		return cur >= start && cur < end
	}
	// Wraparound window, e.g. 23:00-07:00: inside if at/after start OR before end.
	return cur >= start || cur < end
}

// dayAllowed reports whether d is permitted by the window's Days list. An empty
// list means every day.
func (w *Window) dayAllowed(d time.Weekday) bool {
	if len(w.Days) == 0 {
		return true
	}
	short := strings.ToLower(d.String()[:3]) // "mon".."sun"
	full := strings.ToLower(d.String())      // "monday".."sunday"
	for _, e := range w.Days {
		le := strings.ToLower(strings.TrimSpace(e))
		if le == short || le == full {
			return true
		}
	}
	return false
}

// parseHHMM parses a "HH:MM" 24-hour time into minutes-since-midnight.
func parseHHMM(s string) (int, bool) {
	t, err := time.Parse("15:04", strings.TrimSpace(s))
	if err != nil {
		return 0, false
	}
	return t.Hour()*60 + t.Minute(), true
}

// validate enforces the tighten-only invariant and ID rules.
func validate(rules []Rule) error {
	seen := make(map[string]struct{}, len(rules))
	for i, r := range rules {
		if r.ID == "" {
			return fmt.Errorf("overlay: rule %d: empty ID", i)
		}
		if _, dup := seen[r.ID]; dup {
			return fmt.Errorf("overlay: duplicate rule ID %q", r.ID)
		}
		seen[r.ID] = struct{}{}

		switch r.Verdict {
		case VerdictDeny, VerdictAsk:
			// tighten-only: OK
		default:
			return fmt.Errorf("overlay: rule %q: verdict %q is not tighten-only (want deny or ask)", r.ID, r.Verdict)
		}
	}
	return nil
}

// atomicWrite writes data to path via a temp file in the same directory
// followed by a rename, with 0600 permissions.
func atomicWrite(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".overlay-*.tmp")
	if err != nil {
		return fmt.Errorf("overlay: create temp: %w", err)
	}
	tmpName := tmp.Name()

	cleanup := func() {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
	}

	if err := tmp.Chmod(0o600); err != nil {
		cleanup()
		return fmt.Errorf("overlay: chmod temp: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		cleanup()
		return fmt.Errorf("overlay: write temp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		cleanup()
		return fmt.Errorf("overlay: sync temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("overlay: close temp: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("overlay: rename temp: %w", err)
	}
	return nil
}
