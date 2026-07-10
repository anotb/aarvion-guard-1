package packs

import (
	"sort"

	"github.com/aarvion-ai/aarvion-guard/internal/sinks"
)

// maxAllowlistSeed bounds how many observed targets are seeded into a pack's
// allowlist. Beyond this the set is treated as too sprawling to be a "small
// stable set" and the allowlist is left empty (the pack still asks) rather than
// pinned to a long, noisy list the operator never chose.
const maxAllowlistSeed = 10

// sensitiveVerbs are the write/reach-out verbs that, once observed for a
// principal, mean the surface's pack should ask rather than silently allow.
var sensitiveVerbs = map[string]bool{
	"send":   true,
	"post":   true,
	"dm":     true,
	"follow": true,
	"delete": true,
	"share":  true,
}

// surfacePack maps a normalized surface to the built-in pack that governs it.
// Surfaces with no pack (exec/unknown) are absent and produce no proposal.
var surfacePack = map[string]string{
	"twitter":  "social-guard",
	"email":    "google-guard",
	"file":     "google-guard",
	"doc":      "google-guard",
	"sheet":    "google-guard",
	"calendar": "google-guard",
	"comms":    "comms-guard",
	"api":      "api-guard",
	"github":   "github-guard",
	"infra":    "infra-guard",
}

// packAllowlistKey names the Params allowlist a pack seeds from observed
// sensitive-verb targets. Packs absent here take no seeded allowlist.
var packAllowlistKey = map[string]string{
	"google-guard": "contact_allowlist",
	"comms-guard":  "recipient_allowlist",
}

// packAgg accumulates, per pack, what a profile implies: whether any principal
// did a sensitive verb (→ ask globally), which principals were read-only on the
// pack's surfaces (→ per-agent enforce lock), and the observed sensitive-verb
// targets (→ allowlist seed).
type packAgg struct {
	sensitive bool
	// readOnly[p] stays true only while principal p has done exclusively read
	// verbs on this pack's surfaces; any non-read verb clears it.
	readOnly map[string]bool
	targets  map[string]struct{}
}

// ProposeFromProfile derives a tightened pack Set from observed behaviour.
// Deterministic: identical profiles yield identical Sets, pack ids sorted.
//
// Rules:
//   - dlp-guard is always proposed at enforce (secret/PII leaks are never
//     something an agent should have been doing, so there's nothing to learn).
//   - A principal that only ever did read verbs on a surface locks that
//     surface's pack to enforce for that principal (PerAgent), turning observed
//     read-only usage into an enforced read-only contract.
//   - A principal that did a sensitive verb (send/post/dm/follow/delete/share)
//     puts the relevant pack in ask globally. If the observed targets are a
//     small stable set they seed the pack's allowlist (contact_allowlist /
//     recipient_allowlist).
//   - Surfaces never observed are left at their Catalog default (not fabricated
//     into the proposal), the sole exception being dlp-guard.
func ProposeFromProfile(p sinks.Profile) Set {
	aggs := map[string]*packAgg{}
	agg := func(pack string) *packAgg {
		a := aggs[pack]
		if a == nil {
			a = &packAgg{
				readOnly: map[string]bool{},
				targets:  map[string]struct{}{},
			}
			aggs[pack] = a
		}
		return a
	}

	for _, e := range p.Entries {
		pack, ok := surfacePack[e.Surface]
		if !ok {
			continue // exec / unknown / unmapped surface → nothing to propose
		}
		a := agg(pack)

		if sensitiveVerbs[e.Verb] {
			a.sensitive = true
			// A sensitive verb clears any read-only lock for this principal:
			// the agent is not read-only on this surface.
			a.readOnly[e.Principal] = false
			for t := range e.Targets {
				if t != "" {
					a.targets[t] = struct{}{}
				}
			}
			continue
		}

		if e.Verb == "read" {
			// Only lock a principal read-only if it has not already shown a
			// non-read verb on this pack's surfaces.
			if _, seen := a.readOnly[e.Principal]; !seen {
				a.readOnly[e.Principal] = true
			}
			continue
		}

		// A non-read, non-sensitive verb (e.g. like) is neither a lock nor an
		// ask trigger, but it does mean the principal isn't read-only.
		a.readOnly[e.Principal] = false
	}

	packs := make([]Pack, 0, len(aggs)+1)

	// dlp-guard is always enforced.
	packs = append(packs, Pack{
		ID:    "dlp-guard",
		Title: catalogTitle("dlp-guard"),
		Mode:  ModeEnforce,
	})

	for id, a := range aggs {
		pack := Pack{
			ID:    id,
			Title: catalogTitle(id),
			Mode:  ModeObserve, // learn-posture base; per-agent locks tighten it
		}

		if a.sensitive {
			pack.Mode = ModeAsk
			if key := packAllowlistKey[id]; key != "" {
				if seed := seedAllowlist(a.targets); seed != nil {
					pack.Params = map[string]any{key: seed}
				}
			}
		}

		// Per-agent read-only locks: only principals still marked read-only.
		locked := make([]string, 0, len(a.readOnly))
		for principal, ro := range a.readOnly {
			if ro {
				locked = append(locked, principal)
			}
		}
		if len(locked) > 0 {
			pack.PerAgent = map[string]string{}
			for _, principal := range locked {
				pack.PerAgent[principal] = ModeEnforce
			}
		}

		packs = append(packs, pack)
	}

	sort.Slice(packs, func(i, j int) bool { return packs[i].ID < packs[j].ID })
	return Set{Packs: packs}
}

// seedAllowlist returns the observed targets as a sorted []any when the set is
// small and stable enough to pin; nil when empty or too sprawling.
func seedAllowlist(targets map[string]struct{}) []any {
	if len(targets) == 0 || len(targets) > maxAllowlistSeed {
		return nil
	}
	sorted := make([]string, 0, len(targets))
	for t := range targets {
		sorted = append(sorted, t)
	}
	sort.Strings(sorted)
	out := make([]any, len(sorted))
	for i, t := range sorted {
		out[i] = t
	}
	return out
}

// catalogTitle returns the built-in title for a pack id so proposed packs carry
// the same human label as the catalog (and pass Set validation, which requires a
// non-empty title). Unknown ids fall back to the id itself.
func catalogTitle(id string) string {
	for _, p := range Catalog() {
		if p.ID == id {
			return p.Title
		}
	}
	return id
}
