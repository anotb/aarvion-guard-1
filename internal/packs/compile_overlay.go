package packs

import (
	"fmt"
	"sort"

	"github.com/aarvion-ai/aarvion-guard/internal/overlay"
)

// riskLevel is a built-in rule's intrinsic risk. hard rules gate destructive or
// irreversible actions; soft rules gate sensitive-but-recoverable ones. The
// mode->verdict transform reads it: in enforce, hard->deny and soft->ask; in
// ask, everything->ask; in observe, the intrinsic verdict applies but the rule
// is recorded-only (Observe=true); off emits nothing.
type riskLevel int

const (
	riskSoft riskLevel = iota
	riskHard
)

// builtin is one built-in guardrail: a Match plus its intrinsic risk and a
// human reason. The pack id and per-pack index are added at compile time to
// form the stable rule id.
type builtin struct {
	match  overlay.Match
	sev    riskLevel
	reason string
	descr  string
}

// packModeRank orders the four modes by strictness so a per-agent override is
// only applied when it is STRICTER than the pack's own mode (overlay is
// tighten-only; a looser per-agent override is dropped, the CP rego can loosen).
func packModeRank(mode string) int {
	switch mode {
	case ModeEnforce:
		return 3
	case ModeAsk:
		return 2
	case ModeObserve:
		return 1
	default: // off / unknown
		return 0
	}
}

// verdictFor applies the mode->verdict transform to a built-in's risk level. It
// returns the verdict and whether the rule is recorded-only (Observe).
func verdictFor(mode string, sev riskLevel) (overlay.Verdict, bool) {
	switch mode {
	case ModeEnforce:
		if sev == riskHard {
			return overlay.VerdictDeny, false
		}
		return overlay.VerdictAsk, false
	case ModeAsk:
		return overlay.VerdictAsk, false
	case ModeObserve:
		// Intrinsic verdict, but recorded-only.
		if sev == riskHard {
			return overlay.VerdictDeny, true
		}
		return overlay.VerdictAsk, true
	default:
		return "", false
	}
}

// CompileOverlay turns a Set of packs into a deterministic, tighten-only slice
// of overlay rules. Every enabled pack (mode != off) contributes its built-in
// rules under the mode->verdict transform; per-agent overrides that are stricter
// than the pack mode add principal-scoped copies ordered before the base rules.
//
// Rule ids have the stable form pack:<id>:base:<nn> and
// pack:<id>:agent:<principal>:<nn>; the returned slice is sorted by id so the
// output is byte-identical across calls (and so per-agent rules, which sort
// before "base", precede the pack's base rules).
func CompileOverlay(s Set) []overlay.Rule {
	var out []overlay.Rule

	for _, p := range s.Packs {
		if !isEnabled(p.Mode) {
			continue
		}
		builtins := builtinsFor(p)
		if len(builtins) == 0 {
			continue
		}

		// Per-agent overrides, applied only when stricter than the pack mode.
		principals := stricterPerAgent(p)
		for _, pr := range principals {
			mode := p.PerAgent[pr]
			for i, b := range builtins {
				if r, ok := ruleFrom(b, mode, agentRuleID(p.ID, pr, i), []string{pr}); ok {
					out = append(out, r)
				}
			}
		}

		// Base (unscoped) rules at the pack mode.
		for i, b := range builtins {
			if r, ok := ruleFrom(b, p.Mode, baseRuleID(p.ID, i), nil); ok {
				out = append(out, r)
			}
		}
	}

	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// ruleFrom instantiates a built-in as a concrete overlay.Rule under mode. It
// returns ok=false when the mode emits nothing (off) or the built-in produced no
// usable verdict. When principals is non-nil it scopes the rule to those callers.
func ruleFrom(b builtin, mode, id string, principals []string) (overlay.Rule, bool) {
	verdict, observe := verdictFor(mode, b.sev)
	if verdict == "" {
		return overlay.Rule{}, false
	}
	m := b.match // value copy; slices are shared but never mutated after build
	if len(principals) > 0 {
		m.Principals = principals
	}
	return overlay.Rule{
		ID:          id,
		Description: b.descr,
		Match:       m,
		Verdict:     verdict,
		Reason:      b.reason,
		Enabled:     true,
		Observe:     observe,
	}, true
}

// isEnabled reports whether a pack mode contributes any rules.
func isEnabled(mode string) bool { return packModeRank(mode) > 0 }

// stricterPerAgent returns the principals whose per-agent override is strictly
// stricter than the pack mode, sorted for determinism. Looser or equal overrides
// are dropped (overlay is tighten-only).
func stricterPerAgent(p Pack) []string {
	base := packModeRank(p.Mode)
	var out []string
	for pr, mode := range p.PerAgent {
		if packModeRank(mode) > base {
			out = append(out, pr)
		}
	}
	sort.Strings(out)
	return out
}

func baseRuleID(packID string, n int) string {
	return fmt.Sprintf("pack:%s:base:%02d", packID, n)
}

func agentRuleID(packID, principal string, n int) string {
	return fmt.Sprintf("pack:%s:agent:%s:%02d", packID, principal, n)
}

// builtinsFor returns the ordered built-in rules for a pack id, reading any
// pack Params it needs (allowlists, quiet hours, toggles). An unknown id yields
// no built-ins.
func builtinsFor(p Pack) []builtin {
	switch p.ID {
	case "social-guard":
		return socialGuardBuiltins(p)
	case "google-guard":
		return googleGuardBuiltins(p)
	case "comms-guard":
		return commsGuardBuiltins(p)
	case "dlp-guard":
		return dlpGuardBuiltins(p)
	case "api-guard":
		return apiGuardBuiltins(p)
	case "github-guard":
		return githubGuardBuiltins(p)
	case "infra-guard":
		return infraGuardBuiltins(p)
	default:
		return nil
	}
}

// --- per-pack built-ins ---

func socialGuardBuiltins(_ Pack) []builtin {
	// Posting-as-you is high stakes; the read verb is deliberately excluded so
	// reads stay allowed.
	return []builtin{{
		match: overlay.Match{
			Surfaces: []string{"twitter"},
			Verbs:    []string{"post", "reply", "dm", "follow", "like"},
		},
		sev:    riskHard,
		reason: "social_guard:write",
		descr:  "Posting or interacting as you on Twitter/X",
	}}
}

func googleGuardBuiltins(p Pack) []builtin {
	out := []builtin{
		{
			match:  overlay.Match{Surfaces: []string{"file"}, Verbs: []string{"delete"}},
			sev:    riskHard,
			reason: "google_guard:drive_delete",
			descr:  "Deleting a Drive file",
		},
		{
			match:  overlay.Match{Verbs: []string{"delete"}, FlagsAll: []string{"force"}},
			sev:    riskHard,
			reason: "google_guard:force_delete",
			descr:  "Force-deleting (skips trash)",
		},
		{
			match:  overlay.Match{Verbs: []string{"share"}, FlagsAll: []string{"public_share"}},
			sev:    riskHard,
			reason: "google_guard:public_share",
			descr:  "Sharing publicly (anyone with the link)",
		},
	}

	// Email send: if a contact_allowlist is configured, gate only sends to
	// non-contacts; otherwise gate all sends.
	allow := ovStringSlice(p.Params, "contact_allowlist")
	if len(allow) > 0 {
		out = append(out, builtin{
			match: overlay.Match{
				Surfaces:   []string{"email"},
				Verbs:      []string{"send"},
				NotTargets: allow,
			},
			sev:    riskSoft,
			reason: "google_guard:email_noncontact",
			descr:  "Emailing a non-contact",
		})
	} else {
		out = append(out, builtin{
			match:  overlay.Match{Surfaces: []string{"email"}, Verbs: []string{"send"}},
			sev:    riskSoft,
			reason: "google_guard:email_send",
			descr:  "Sending email",
		})
	}
	return out
}

func commsGuardBuiltins(p Pack) []builtin {
	var out []builtin

	// Message to a non-allowlisted recipient (only when an allowlist exists;
	// without one, an unconditioned send rule would be noisy, so we gate on the
	// allowlist inversion only).
	if allow := ovStringSlice(p.Params, "recipient_allowlist"); len(allow) > 0 {
		out = append(out, builtin{
			match: overlay.Match{
				Surfaces:   []string{"comms"},
				Verbs:      []string{"send"},
				NotTargets: allow,
			},
			sev:    riskSoft,
			reason: "comms_guard:non_recipient",
			descr:  "Messaging a non-allowlisted recipient",
		})
	}

	// Quiet hours: gate sends inside the window.
	if w := ovQuietHours(p.Params); w != nil {
		out = append(out, builtin{
			match: overlay.Match{
				Surfaces:   []string{"comms"},
				Verbs:      []string{"send"},
				TimeWindow: w,
			},
			sev:    riskSoft,
			reason: "comms_guard:quiet_hours",
			descr:  "Messaging during quiet hours",
		})
	}
	return out
}

func dlpGuardBuiltins(p Pack) []builtin {
	out := []builtin{{
		match: overlay.Match{FindingsAny: []string{
			"secret:ghp", "secret:anthropic", "secret:openai", "secret:aws", "secret:1password",
		}},
		sev:    riskHard,
		reason: "dlp_guard:secret",
		descr:  "Payload contains a secret",
	}}
	if ovBoolParam(p.Params, "ask_on_pii") {
		out = append(out, builtin{
			match:  overlay.Match{FindingsAny: []string{"pii:email", "pii:phone"}},
			sev:    riskSoft,
			reason: "dlp_guard:pii",
			descr:  "Payload contains PII",
		})
	}
	return out
}

func apiGuardBuiltins(p Pack) []builtin {
	var out []builtin

	if ovBoolParamDefault(p.Params, "block_destructive", true) {
		out = append(out, builtin{
			match:  overlay.Match{Surfaces: []string{"api"}, FlagsAll: []string{"delete_verb"}},
			sev:    riskHard,
			reason: "api_guard:destructive",
			descr:  "Destructive HTTP method (DELETE/PUT/PATCH)",
		})
	}

	// Host allowlist inversion. NOTE (normalizer gap): the normalizer populates
	// Action.Targets with the FULL URL (see internal/normalize classifyWebFetch
	// and matchCurl), not the bare host, and sets Action.Host separately. This
	// NotTargets rule compares the host allowlist against those full-URL targets,
	// so it will NOT fire as written. The rule is emitted regardless so the shape
	// is stable and the integrator can extend the normalizer to also push the
	// host into Targets (or add a NotHosts facet). Flagged in the task notes.
	if allow := ovStringSlice(p.Params, "host_allowlist"); len(allow) > 0 {
		out = append(out, builtin{
			match: overlay.Match{
				Surfaces:   []string{"api"},
				NotTargets: allow,
			},
			sev:    riskSoft,
			reason: "api_guard:host_not_allowlisted",
			descr:  "Egress to a non-allowlisted host",
		})
	}
	return out
}

func githubGuardBuiltins(_ Pack) []builtin {
	return []builtin{
		{
			match:  overlay.Match{Surfaces: []string{"github"}, Verbs: []string{"force_push"}},
			sev:    riskHard,
			reason: "github_guard:force_push",
			descr:  "Force-pushing to a repo",
		},
		{
			match:  overlay.Match{Verbs: []string{"repo_delete"}},
			sev:    riskHard,
			reason: "github_guard:repo_delete",
			descr:  "Deleting a repo or branch",
		},
		{
			match:  overlay.Match{Surfaces: []string{"github"}, Verbs: []string{"secret_set"}},
			sev:    riskHard,
			reason: "github_guard:secret_set",
			descr:  "Setting a repo/actions secret",
		},
		{
			match:  overlay.Match{CommandContains: []string{".github/workflows"}},
			sev:    riskSoft,
			reason: "github_guard:workflow_edit",
			descr:  "Editing a CI workflow",
		},
	}
}

func infraGuardBuiltins(_ Pack) []builtin {
	return []builtin{
		{
			match:  overlay.Match{Surfaces: []string{"infra"}, FlagsAll: []string{"destructive"}},
			sev:    riskHard,
			reason: "infra_guard:destructive",
			descr:  "Destructive infrastructure action",
		},
		{
			match: overlay.Match{CommandContains: []string{
				"docker system prune",
				"systemctl stop",
				"systemctl disable",
				"shutdown",
				"reboot",
			}},
			sev:    riskHard,
			reason: "infra_guard:dangerous_command",
			descr:  "Dangerous infrastructure command",
		},
	}
}

// --- param readers ---

// quietHours reads a {start,end,days} quiet_hours param into an overlay.Window,
// returning nil when absent or malformed (no start/end).
func ovQuietHours(params map[string]any) *overlay.Window {
	raw, ok := params["quiet_hours"].(map[string]any)
	if !ok {
		return nil
	}
	start, _ := raw["start"].(string)
	end, _ := raw["end"].(string)
	if start == "" || end == "" {
		return nil
	}
	w := &overlay.Window{Start: start, End: end}
	if days := ovToStringSlice(raw["days"]); len(days) > 0 {
		w.Days = days
	}
	return w
}

// stringSlice reads a []any/[]string param as a []string, dropping non-strings
// and empties. It returns nil when the key is absent or empty.
func ovStringSlice(params map[string]any, key string) []string {
	if params == nil {
		return nil
	}
	return ovToStringSlice(params[key])
}

func ovToStringSlice(v any) []string {
	switch t := v.(type) {
	case []string:
		out := make([]string, 0, len(t))
		for _, e := range t {
			if e != "" {
				out = append(out, e)
			}
		}
		if len(out) == 0 {
			return nil
		}
		return out
	case []any:
		out := make([]string, 0, len(t))
		for _, e := range t {
			if s, ok := e.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		if len(out) == 0 {
			return nil
		}
		return out
	default:
		return nil
	}
}

// boolParam reads a bool param, defaulting to false.
func ovBoolParam(params map[string]any, key string) bool {
	return ovBoolParamDefault(params, key, false)
}

// boolParamDefault reads a bool param, returning def when absent or non-bool.
func ovBoolParamDefault(params map[string]any, key string, def bool) bool {
	if params == nil {
		return def
	}
	if v, ok := params[key].(bool); ok {
		return v
	}
	return def
}
