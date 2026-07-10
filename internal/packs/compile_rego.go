package packs

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// EmitRego compiles a pack Set into a single `package envoy.authz` rego module
// plus a data document. Unlike the overlay compiler (tighten-only, local), the
// rego is FULL-STRENGTH: it denies outright and asks via the same decision
// object internal/policy parses (result {allowed, http_status, headers{
// x-policy-violated, x-policy-reason, and for ask x-aarvion-verdict:"ask" with
// http_status 202}}). The decision precedence mirrors examples/govern.rego:
// deny (hard, 403) beats ask (soft, 202) beats the default allow (200).
//
// The module reads pack modes from data.packs, so one module governs any mode
// combination without recompilation: the operator restages only data.json to
// retune. Mode transform (matches the overlay compiler):
//   - enforce: hard rules deny, soft rules ask.
//   - ask:     every rule asks.
//   - observe: recorded-only locally; the full-strength CP rego does NOT block
//     in observe (nor off), so neither contributes an enforcing clause.
//
// PerAgent[principal]=mode narrows a principal-scoped copy of a pack's rules at
// that mode, but ONLY when stricter than the pack mode (enforce>ask>observe>
// off): a looser per-agent override is dropped, mirroring the tighten-only
// overlay. A principal-scoped clause reads its effective mode from
// data.packs[id].per_agent[principal] at eval time and gates on principal_id,
// so the same module retunes per-agent from data alone.
//
// data is deterministic pretty-printed JSON: {"packs": {id: {mode, params,
// per_agent}}}. Both return values are stable across calls for a given Set.
func EmitRego(s Set) (rego string, data []byte) {
	return emitRegoModule(s), emitData(s)
}

// severity is a rule's intrinsic risk: hard (destructive/irreversible) denies
// under enforce; soft (sensitive but recoverable) asks.
type severity int

const (
	sevHard severity = iota
	sevSoft
)

// regoRule is one logical guardrail: a rego condition (a list of expressions
// ANDed together) plus its intrinsic severity and a stable id.
type regoRule struct {
	id   string
	sev  severity
	cond []string
}

// packEmitter produces the logical rules for one pack id from its params.
type packEmitter func(p Pack) []regoRule

// regoEmitters maps pack id -> its rule generator. Unknown ids emit nothing.
var regoEmitters = map[string]packEmitter{
	"social-guard": emitSocial,
	"google-guard": emitGoogle,
	"comms-guard":  emitComms,
	"dlp-guard":    emitDLP,
	"api-guard":    emitAPI,
	"github-guard": emitGithub,
	"infra-guard":  emitInfra,
}

// regoClause is a concrete rego clause to render: body expressions and a verdict
// (deny or ask). A hard rule yields both a deny and an ask clause.
type regoClause struct {
	id   string
	ask  bool
	body []string
}

// ============================================================================
// Module assembly
// ============================================================================

func emitRegoModule(s Set) string {
	var clauses []regoClause

	for _, p := range regoSortedPacks(s.Packs) {
		emit := regoEmitters[p.ID]
		if emit == nil {
			continue
		}
		rules := emit(p)
		if len(rules) == 0 {
			continue
		}

		modeExpr := modeVar(p.ID)
		for _, r := range rules {
			clauses = append(clauses, expand(r, modeExpr, nil, "")...)
		}

		for _, principal := range regoSortedKeys(p.PerAgent) {
			if !stricter(p.PerAgent[principal], p.Mode) {
				continue // looser override dropped (tighten-only parity)
			}
			pModeExpr := perAgentVar(p.ID, principal)
			gate := []string{principalGate(principal)}
			for _, r := range rules {
				clauses = append(clauses, expand(r, pModeExpr, gate, principal)...)
			}
		}
	}

	denies := map[string][]string{}
	asks := map[string][]string{}
	for _, c := range clauses {
		if c.ask {
			asks[c.id] = c.body
		} else {
			denies[c.id] = c.body
		}
	}

	var b strings.Builder
	b.WriteString(regoHeader)
	b.WriteString(emitModeVars(s))
	for _, id := range regoSortedMapKeys(denies) {
		b.WriteString(renderViolation(id, denies[id]))
	}
	for _, id := range regoSortedMapKeys(asks) {
		b.WriteString(renderAsk(id, asks[id]))
	}
	b.WriteString(regoDecision)
	return b.String()
}

// expand turns one logical rule into concrete deny/ask clauses under a mode
// expression. gate holds extra prefix expressions (the principal gate for scoped
// rules); principal disambiguates scoped clause ids.
func expand(r regoRule, modeExpr string, gate []string, principal string) []regoClause {
	id := r.id
	if principal != "" {
		id = scopedID(r.id, principal)
	}
	base := append(append([]string{}, gate...), r.cond...)

	if r.sev == sevHard {
		deny := append([]string{eq(modeExpr, ModeEnforce)}, base...)
		ask := append([]string{eq(modeExpr, ModeAsk)}, base...)
		return []regoClause{
			{id: id, ask: false, body: deny},
			{id: id, ask: true, body: ask},
		}
	}
	ask := append([]string{inEnforceOrAsk(modeExpr)}, base...)
	return []regoClause{{id: id, ask: true, body: ask}}
}

// ============================================================================
// Fixed rego text
// ============================================================================

const regoHeader = `# Aarvion governance packs — generated by internal/packs.EmitRego.
#
# Full-strength CP policy for beta.aarvion.ai: denies/asks equivalently to the
# local overlay but may deny outright. Evaluated at data.envoy.authz.allow for
# every governed OpenClaw tool call. Pack modes live in data.packs so the same
# module retunes from data.json alone. DO NOT EDIT BY HAND — regenerate via
# ` + "`go test ./internal/packs/ -run Snapshot -update`" + `.
package envoy.authz

import rego.v1

default allow := {"allowed": true, "http_status": 200}

# --- semantic action + caller (from the guard normalizer) ---
surface := lower(object.get(input, ["action", "semantic", "surface"], ""))
verb := lower(object.get(input, ["action", "semantic", "verb"], ""))
command := lower(object.get(input, ["action", "semantic", "raw"], ""))
host := lower(object.get(input, ["action", "semantic", "host"], ""))
findings := object.get(input, ["action", "semantic", "findings"], [])
flags := object.get(input, ["action", "semantic", "flags"], {})
targets := object.get(input, ["action", "semantic", "targets"], [])
principal := lower(object.get(input, ["ctx", "caller", "principal_id"], ""))

# in_window reports whether minute-of-day m falls in a wraparound quiet-hours
# window that crosses midnight (end <= start), e.g. 23:00-07:00.
in_window(m, start, end) if m >= start
in_window(m, start, end) if m < end

`

const regoDecision = `# --- decision: deny (hard) > ask (approval) > allow (default) ---

allow := decision if {
	count(violations) > 0
	ids := sort([v.id | some v in violations])
	texts := sort([v.text | some v in violations])
	decision := {
		"allowed": false,
		"http_status": 403,
		"headers": {
			"x-policy-violated": concat(",", ids),
			"x-policy-reason": sprintf("blocked: %s", [concat("; ", texts)]),
		},
	}
}

allow := decision if {
	count(violations) == 0
	count(ask_reasons) > 0
	decision := {
		"allowed": false,
		"http_status": 202,
		"headers": {
			"x-aarvion-verdict": "ask",
			"x-policy-violated": "govern.ask.approval_required.v1",
			"x-policy-reason": sprintf("approval required: %s", [concat("; ", sort(ask_reasons))]),
		},
	}
}
`

// ============================================================================
// Mode vars + data document
// ============================================================================

// emitModeVars appends the mode_<id> and per-agent mode vars used by clause
// gates, reading data.packs directly (a subtree distinct from data.envoy.authz,
// so no recursion). Deterministic: sorted by var name.
func emitModeVars(s Set) string {
	lines := map[string]string{}
	for _, p := range regoSortedPacks(s.Packs) {
		if regoEmitters[p.ID] == nil {
			continue
		}
		lines[modeVar(p.ID)] = fmt.Sprintf(
			"%s := object.get(data.packs, [%q, \"mode\"], \"off\")", modeVar(p.ID), p.ID)
		for _, principal := range regoSortedKeys(p.PerAgent) {
			if !stricter(p.PerAgent[principal], p.Mode) {
				continue
			}
			v := perAgentVar(p.ID, principal)
			lines[v] = fmt.Sprintf(
				"%s := object.get(data.packs, [%q, \"per_agent\", %q], \"off\")", v, p.ID, principal)
		}
	}
	if len(lines) == 0 {
		return ""
	}
	keys := make([]string, 0, len(lines))
	for k := range lines {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteString("# --- pack modes (from data.packs) ---\n")
	for _, k := range keys {
		b.WriteString(lines[k])
		b.WriteByte('\n')
	}
	b.WriteByte('\n')
	return b.String()
}

// emitData renders {"packs": {id: {mode, params, per_agent}}} as deterministic
// pretty JSON (MarshalIndent sorts map keys).
func emitData(s Set) []byte {
	packMap := map[string]any{}
	for _, p := range s.Packs {
		entry := map[string]any{"mode": p.Mode}
		if len(p.Params) > 0 {
			entry["params"] = p.Params
		}
		if len(p.PerAgent) > 0 {
			pa := map[string]any{}
			for k, v := range p.PerAgent {
				pa[k] = v
			}
			entry["per_agent"] = pa
		}
		packMap[p.ID] = entry
	}
	out, err := json.MarshalIndent(map[string]any{"packs": packMap}, "", "  ")
	if err != nil {
		return []byte(fmt.Sprintf("{\"packs\":{},\"error\":%q}\n", err.Error()))
	}
	return append(out, '\n')
}

// ============================================================================
// Per-pack rule generators (severities mirror the overlay compiler)
// ============================================================================

// social-guard: twitter write verbs are hard.
func emitSocial(_ Pack) []regoRule {
	return []regoRule{{
		id:  "govern.social.write.v1",
		sev: sevHard,
		cond: []string{
			`surface == "twitter"`,
			verbIn("post", "reply", "dm", "follow", "like"),
		},
	}}
}

// google-guard: drive delete + public share are hard; email send is soft
// (gated by contact_allowlist when present).
func emitGoogle(p Pack) []regoRule {
	rules := []regoRule{
		{
			id:  "govern.google.drive_delete.v1",
			sev: sevHard,
			cond: []string{
				surfaceIn("file", "doc", "sheet", "drive"),
				`verb == "delete"`,
			},
		},
		{
			id:  "govern.google.public_share.v1",
			sev: sevHard,
			cond: []string{
				surfaceIn("file", "doc", "sheet", "drive"),
				`verb == "share"`,
				flagTrue("public_share"),
			},
		},
	}
	send := regoRule{
		id:   "govern.google.email_send.v1",
		sev:  sevSoft,
		cond: []string{`surface == "email"`, `verb == "send"`},
	}
	if allow := regoStringList(p.Params, "contact_allowlist"); len(allow) > 0 {
		send.cond = append(send.cond, notTargets(allow)...)
	}
	rules = append(rules, send)
	return rules
}

// comms-guard: messaging sends during quiet hours ask; off-allowlist recipients
// ask.
func emitComms(p Pack) []regoRule {
	var rules []regoRule
	base := []string{`surface == "comms"`, `verb in {"send", "post", "dm", "reply"}`}

	if allow := regoStringList(p.Params, "recipient_allowlist"); len(allow) > 0 {
		cond := append(append([]string{}, base...), notTargets(allow)...)
		rules = append(rules, regoRule{id: "govern.comms.off_allowlist.v1", sev: sevSoft, cond: cond})
	}
	if qh, ok := p.Params["quiet_hours"].(map[string]any); ok {
		start, _ := qh["start"].(string)
		end, _ := qh["end"].(string)
		if start != "" && end != "" {
			cond := append(append([]string{}, base...), quietHoursCond(start, end)...)
			rules = append(rules, regoRule{id: "govern.comms.quiet_hours.v1", sev: sevSoft, cond: cond})
		}
	}
	return rules
}

// dlp-guard: secret findings are hard; PII findings are soft (only when
// ask_on_pii).
func emitDLP(p Pack) []regoRule {
	var rules []regoRule
	if regoBool(p.Params, "block_secrets", true) {
		rules = append(rules, regoRule{
			id: "govern.dlp.secret.v1", sev: sevHard, cond: findingPrefix("secret:"),
		})
	}
	if regoBool(p.Params, "ask_on_pii", false) {
		rules = append(rules, regoRule{
			id: "govern.dlp.pii.v1", sev: sevSoft, cond: findingPrefix("pii:"),
		})
	}
	return rules
}

// api-guard: destructive API calls + off-allowlist hosts are hard.
func emitAPI(p Pack) []regoRule {
	var rules []regoRule
	if regoBool(p.Params, "block_destructive", true) {
		rules = append(rules, regoRule{
			id:   "govern.api.destructive.v1",
			sev:  sevHard,
			cond: []string{`surface == "api"`, anyFlag("delete_verb", "destructive")},
		})
	}
	if allow := regoStringList(p.Params, "host_allowlist"); len(allow) > 0 {
		rules = append(rules, regoRule{
			id:   "govern.api.off_allowlist_host.v1",
			sev:  sevHard,
			cond: append([]string{`surface == "api"`}, hostNotAllowed(allow)...),
		})
	}
	return rules
}

// github-guard: force-push / repo-delete / secret-set are hard; push + workflow
// edits are soft.
func emitGithub(_ Pack) []regoRule {
	return []regoRule{
		{id: "govern.github.force_push.v1", sev: sevHard, cond: []string{`surface == "github"`, `verb == "force_push"`}},
		{id: "govern.github.repo_delete.v1", sev: sevHard, cond: []string{`surface == "github"`, `verb == "repo_delete"`}},
		{id: "govern.github.secret_set.v1", sev: sevHard, cond: []string{`surface == "github"`, `verb == "secret_set"`}},
		{id: "govern.github.push.v1", sev: sevSoft, cond: []string{`surface == "github"`, `verb == "push"`}},
		{id: "govern.github.workflow_edit.v1", sev: sevSoft, cond: []string{commandContains(".github/workflows")}},
	}
}

// infra-guard: destructive infra flag + dangerous command substrings are hard.
func emitInfra(_ Pack) []regoRule {
	rules := []regoRule{
		{id: "govern.infra.destructive.v1", sev: sevHard, cond: []string{`surface == "infra"`, flagTrue("destructive")}},
	}
	for i, sub := range infraDenySubstrings {
		rules = append(rules, regoRule{
			id: fmt.Sprintf("govern.infra.dangerous_%d.v1", i), sev: sevHard, cond: []string{commandContains(sub)},
		})
	}
	return rules
}

// infraDenySubstrings ports the existing infra denylist to command-substring
// matches (kept in sync with examples/govern.rego's infra_denylist).
var infraDenySubstrings = []string{
	"docker rm -f", "docker system prune", "docker volume rm",
	"systemctl stop", "systemctl disable", "launchctl unload",
	"kill -9 1", "shutdown", "reboot", "halt",
}

// ============================================================================
// Rego condition builders
// ============================================================================

func verbIn(verbs ...string) string    { return "verb in " + regoStrSet(verbs) }
func surfaceIn(surf ...string) string  { return "surface in " + regoStrSet(surf) }
func flagTrue(name string) string      { return fmt.Sprintf("object.get(flags, %q, false) == true", name) }
func commandContains(sub string) string {
	return fmt.Sprintf("contains(command, %q)", strings.ToLower(sub))
}

func anyFlag(names ...string) string {
	return fmt.Sprintf("count([fl | some fl in %s; object.get(flags, fl, false) == true]) > 0",
		regoStrSet(names))
}

func findingPrefix(prefix string) []string {
	return []string{"some f in findings", fmt.Sprintf("startswith(lower(f), %q)", prefix)}
}

// notTargets fires when at least one target exists and NONE of the targets is on
// the allowlist (mirrors overlay.matchNotTargets: any allowlisted target spares
// the action).
func notTargets(allow []string) []string {
	return []string{
		"count(targets) > 0",
		fmt.Sprintf("allowed_t := %s", regoStringSet(allow)),
		"count([t | some t in targets; allowed_t[lower(t)]]) == 0",
	}
}

// hostNotAllowed fires when the egress host is not a suffix-match of any
// allowlisted host.
func hostNotAllowed(allow []string) []string {
	return []string{
		`host != ""`,
		fmt.Sprintf("allowed_h := %s", regoStringSet(allow)),
		"count([h | some h in allowed_h; endswith(host, h)]) == 0",
	}
}

// quietHoursCond fires when the action minute-of-day is inside [start, end),
// handling midnight wraparound. The guard supplies now_minute; absent -> no fire.
func quietHoursCond(start, end string) []string {
	sMin := hhmmToMinutes(start)
	eMin := hhmmToMinutes(end)
	lines := []string{
		`now_min := object.get(input, ["action", "semantic", "now_minute"], -1)`,
		`now_min >= 0`,
	}
	if sMin < eMin {
		lines = append(lines, fmt.Sprintf("now_min >= %d", sMin), fmt.Sprintf("now_min < %d", eMin))
	} else {
		lines = append(lines, fmt.Sprintf("in_window(now_min, %d, %d)", sMin, eMin))
	}
	return lines
}

// ============================================================================
// Rego literal + naming helpers
// ============================================================================

// regoStrSet renders a rego set literal {"a", "b"} from raw strings (order
// preserved; used for verb/surface enumerations that are already canonical).
func regoStrSet(items []string) string {
	quoted := make([]string, len(items))
	for i, it := range items {
		quoted[i] = fmt.Sprintf("%q", it)
	}
	return "{" + strings.Join(quoted, ", ") + "}"
}

// regoStringSet renders a rego set literal from allowlist entries, lowercased,
// deduped and sorted for deterministic, case-insensitive membership.
func regoStringSet(items []string) string {
	seen := map[string]struct{}{}
	var uniq []string
	for _, it := range items {
		l := strings.ToLower(it)
		if _, ok := seen[l]; ok {
			continue
		}
		seen[l] = struct{}{}
		uniq = append(uniq, l)
	}
	sort.Strings(uniq)
	return regoStrSet(uniq)
}

func principalGate(principal string) string {
	return fmt.Sprintf("principal == %q", strings.ToLower(principal))
}

func eq(modeExpr, mode string) string { return fmt.Sprintf("%s == %q", modeExpr, mode) }

func inEnforceOrAsk(modeExpr string) string {
	return fmt.Sprintf("%s in {%q, %q}", modeExpr, ModeEnforce, ModeAsk)
}

// modeVar is the rego identifier for a pack's base mode. Hyphens in pack ids are
// illegal in rego identifiers, so they become underscores.
func modeVar(packID string) string { return "mode_" + identSafe(packID) }

// perAgentVar is the rego identifier for a pack's per-agent mode.
func perAgentVar(packID, principal string) string {
	return "peragent_" + identSafe(packID) + "_" + identSafe(strings.ToLower(principal))
}

// scopedID appends a principal segment so per-agent clauses have distinct ids.
func scopedID(id, principal string) string {
	return id + ".agent." + identSafe(strings.ToLower(principal))
}

// identSafe maps an id/principal to a rego-safe identifier fragment.
func identSafe(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	return b.String()
}

// modeRank orders modes by strictness for the per-agent tighten-only check.
func modeRank(mode string) int {
	switch mode {
	case ModeEnforce:
		return 3
	case ModeAsk:
		return 2
	case ModeObserve:
		return 1
	default:
		return 0
	}
}

// stricter reports whether override mode a is strictly stricter than base b.
func stricter(a, b string) bool { return modeRank(a) > modeRank(b) }

// ============================================================================
// Rendering + ordering + param accessors
// ============================================================================

func renderViolation(id string, body []string) string {
	var b strings.Builder
	b.WriteString("violations contains v if {\n")
	for _, line := range body {
		fmt.Fprintf(&b, "\t%s\n", line)
	}
	fmt.Fprintf(&b, "\tv := {\"id\": %q, \"text\": %q}\n", id, reasonFor(id))
	b.WriteString("}\n\n")
	return b.String()
}

func renderAsk(id string, body []string) string {
	var b strings.Builder
	b.WriteString("ask_reasons contains r if {\n")
	for _, line := range body {
		fmt.Fprintf(&b, "\t%s\n", line)
	}
	fmt.Fprintf(&b, "\tr := %q\n", reasonFor(id))
	b.WriteString("}\n\n")
	return b.String()
}

// reasonFor derives a human reason from a clause id, e.g.
// "govern.social.write.v1" -> "social write" and
// "govern.infra.dangerous_3.v1.agent.llm" -> "infra dangerous 3 (agent llm)".
func reasonFor(id string) string {
	base := id
	agent := ""
	if i := strings.Index(id, ".agent."); i >= 0 {
		base = id[:i]
		agent = id[i+len(".agent."):]
	}
	base = strings.TrimPrefix(base, "govern.")
	// Drop a trailing version segment (".v1", ".v2", ...).
	if i := strings.LastIndex(base, "."); i >= 0 {
		if seg := base[i+1:]; len(seg) >= 2 && seg[0] == 'v' && isDigits(seg[1:]) {
			base = base[:i]
		}
	}
	base = strings.ReplaceAll(base, ".", " ")
	base = strings.ReplaceAll(base, "_", " ")
	if agent != "" {
		base += " (agent " + agent + ")"
	}
	return base
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func regoSortedPacks(packs []Pack) []Pack {
	out := append([]Pack(nil), packs...)
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func regoSortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func regoSortedMapKeys(m map[string][]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// regoStringList extracts a []string param, dropping non-strings and empties.
func regoStringList(params map[string]any, key string) []string {
	raw, ok := params[key]
	if !ok {
		return nil
	}
	arr, ok := raw.([]any)
	if !ok {
		return nil
	}
	var out []string
	for _, v := range arr {
		if s, ok := v.(string); ok && s != "" {
			out = append(out, s)
		}
	}
	return out
}

// regoBool reads a bool param, defaulting when absent.
func regoBool(params map[string]any, key string, def bool) bool {
	if params == nil {
		return def
	}
	if v, ok := params[key].(bool); ok {
		return v
	}
	return def
}

// hhmmToMinutes parses "HH:MM" into minutes-since-midnight; a bad value yields 0.
func hhmmToMinutes(s string) int {
	parts := strings.SplitN(strings.TrimSpace(s), ":", 2)
	if len(parts) != 2 {
		return 0
	}
	return atoiSafe(parts[0])*60 + atoiSafe(parts[1])
}

func atoiSafe(s string) int {
	n := 0
	for _, r := range strings.TrimSpace(s) {
		if r < '0' || r > '9' {
			return n
		}
		n = n*10 + int(r-'0')
	}
	return n
}
