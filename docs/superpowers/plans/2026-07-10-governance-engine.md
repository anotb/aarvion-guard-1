# OpenClaw Governance Engine Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn aarvion-guard into a semantic, per-surface governance engine for the real tools OpenClaw agents use (gog/bird/gh/native comms/api), with consumer-friendly policy packs, learn-mode, and human approvals.

**Architecture:** A guard-side semantic normalizer classifies each tool call into a typed action; the existing PDP passes it to OPA and to the tighten-only overlay. Consumer "packs" compile to overlay rules (local, safe-by-construction) and to rego+data (CP-signed on beta). Learn-mode observes behaviour then proposes policy; an ask verdict is resolved by a Telegram approver + console inbox.

**Tech Stack:** Go 1.26 (guard), TypeScript (OpenClaw plugin, `pnpm`/`tsc`), OPA/rego (policy), embedded HTML/JS SPA (console), Telegram Bot API.

## Global Constraints

- Go module: `github.com/aarvion-ai/aarvion-guard`. Go 1.26 at `/opt/homebrew/bin`.
- Every task ends green under `go build ./... && go vet ./... && go test ./... -race`.
- New Go packages import the standard library only where the existing sibling does (e.g. `internal/overlay` is stdlib-only — keep it that way). No new third-party deps without justification.
- `internal/overlay` tighten-only invariant is sacred: overlay verdicts are ONLY `deny` or `ask`; `Replace` validation must keep rejecting anything else.
- Files holding secrets or under `~/.aarvion` are written `0600` via the existing atomic-write pattern; dirs `0700`.
- Plugin (`clients/openclaw-plugin`) must build with ZERO `openclaw` imports and typecheck clean.
- Delivery branch: `feat/governance-engine` (already created, off `release/openclaw-governance`). New PR to fork `anotb/aarvion-guard-1`. NEVER push to `Aarvion-AI/*`.
- Live mini tests always revert clean (uninstall plugin, restore configs, stop procs). Mini = `macmini` (192.168.1.5), uid 501, passwordless sudo, forward/no-inspect only.
- Honest framing in all docs: same-uid ⇒ proves the governance PATH, not a tamper-proof boundary.

---

# PHASE A — Semantic engine

Produces: `internal/normalize` (typed actions + DLP), overlay semantic facets, `input.action.semantic` wired into the PDP, semantic fields in the audit. This is the foundation every pack builds on.

### Task A1: `internal/normalize` — types + native-tool mapping

**Files:**
- Create: `internal/normalize/normalize.go`, `internal/normalize/dlp.go`
- Test: `internal/normalize/normalize_test.go`, `internal/normalize/dlp_test.go`

**Interfaces:**
- Produces:
  ```go
  package normalize
  type Action struct {
      Surface  string            // email|file|calendar|doc|sheet|twitter|comms|github|api|exec|infra|unknown
      Verb     string            // send|read|delete|share|post|reply|dm|follow|like|push|force_push|repo_delete|call|run|...
      Binary   string            // gog|bird|gh|git|curl|wget|docker|systemctl|launchctl|"" (non-shell)
      Account  string
      Channel  string            // telegram|discord|whatsapp|reddit|imessage|""
      Targets  []string
      Host     string
      Flags    map[string]bool   // force|external_recipient|public_share|destructive|delete_verb
      Findings []string          // DLP labels: "secret:ghp"|"secret:openai"|"secret:aws"|"secret:1password"|"pii:email"|"pii:phone"
      Raw      string            // bounded (≤16KiB)
  }
  // Classify maps a tool call to a semantic Action. tool is the OpenClaw tool
  // name; args is the raw args (string command for shell tools, or a
  // map[string]any of params for native tools); surface is the PEP's coarse tag.
  func Classify(tool string, args any, surface string) Action
  // ScanDLP returns DLP labels found in s (secret markers + coarse PII).
  func ScanDLP(s string) []string
  ```

- [ ] **Step 1:** Write `dlp_test.go`: `ScanDLP("token ghp_"+strings.Repeat("a",36))` → contains `"secret:ghp"`; `ScanDLP("sk-ant-…")` → `"secret:anthropic"`; `ScanDLP("AKIA"+strings.Repeat("A",16))` → `"secret:aws"`; `ScanDLP("op://vault/item")` → `"secret:1password"`; `ScanDLP("me@x.com")` → `"pii:email"`; `ScanDLP("call +1 415 555 0132")` → `"pii:phone"`; `ScanDLP("hello")` → empty.
- [ ] **Step 2:** Run `go test ./internal/normalize/ -run DLP` → FAIL (no package).
- [ ] **Step 3:** Implement `dlp.go`: compile package-level regexes once; return sorted unique labels. Keep patterns conservative (low false-positive) — anchor secret markers, require plausible lengths.
- [ ] **Step 4:** `go test ./internal/normalize/ -run DLP -race` → PASS.
- [ ] **Step 5:** Write `normalize_test.go` for native tools: `Classify("web_fetch", map[string]any{"url":"https://api.x.com/v2/DELETE","method":"DELETE"}, "egress")` → `{Surface:"api",Verb:"delete",Host:"api.x.com",Flags:{delete_verb:true}}`; `Classify("message", map[string]any{"channel":"telegram","to":"mum","text":"hi ghp_…"}, "send")` → `{Surface:"comms",Verb:"send",Channel:"telegram",Targets:["mum"],Findings:["secret:ghp"]}`; `Classify("read", "…","tool")` → `{Surface:"unknown"|"read",Verb:"read"}` (read-only).
- [ ] **Step 6:** Run → FAIL.
- [ ] **Step 7:** Implement `normalize.go` native-tool branch (map params → Action; run ScanDLP over text/body/url; Raw bounded). Shell branch returns `{Surface:"exec",Verb:"run",Raw:cmd,Findings:ScanDLP(cmd)}` for now (A2 adds binaries).
- [ ] **Step 8:** `go test ./internal/normalize/ -race` → PASS.
- [ ] **Step 9:** Commit `feat: normalize package — typed actions + DLP scan (native tools)`.

### Task A2: `internal/normalize` — shell CLI matchers (gog/bird/gh/git/curl/docker)

**Files:**
- Create: `internal/normalize/argv.go` (shlex splitter), `internal/normalize/binaries.go` (per-binary matchers)
- Modify: `internal/normalize/normalize.go` (shell branch → dispatch to binary matchers)
- Test: `internal/normalize/argv_test.go`, `internal/normalize/binaries_test.go`

**Interfaces:**
- Produces: `func splitArgs(cmd string) []string` (POSIX-ish; handles quotes/escapes; unbalanced → best-effort). Binary matchers are internal; behaviour is asserted through `Classify`.

- [ ] **Step 1:** `argv_test.go`: `splitArgs(`gog gmail send --to "a b@x.com" --body 'hi'`)` → `["gog","gmail","send","--to","a b@x.com","--body","hi"]`.
- [ ] **Step 2:** FAIL → implement `argv.go` → PASS.
- [ ] **Step 3:** `binaries_test.go` table (assert via `Classify(tool="exec", args=cmd, "exec")`):
  - `gog gmail send --to a@x.com` → `{email, send, external_recipient? depends on allowlist→leave false here, Targets:[a@x.com]}`
  - `gog drive delete 123 --force` → `{file, delete, Flags:{force:true,destructive:true}}`
  - `gog drive share 123 --role anyone` → `{doc|file, share, Flags:{public_share:true}}`
  - `bird tweet "hello"` → `{twitter, post}`; `bird reply …` → `{twitter, reply}`; `bird follow x` → `{twitter, follow}`; `bird search x` / `bird whoami` → `{twitter, read}`
  - `gh repo delete o/r --yes` → `{github, repo_delete}`; `git push --force` → `{github, force_push}`; `git push` → `{github, push}`
  - `curl -X DELETE https://api.x/thing` → `{api, delete, Host:"api.x"}`
  - `docker system prune -f` → `{infra, destructive, Binary:docker}`
- [ ] **Step 4:** FAIL → implement `binaries.go` matchers + wire dispatch in `normalize.go` (identify binary from argv[0] basename; unknown binary → `{exec, run}`) → PASS under `-race`.
- [ ] **Step 5:** Commit `feat: normalize CLI matchers (gog/bird/gh/git/curl/docker)`.

### Task A3: overlay semantic facets

**Files:**
- Modify: `internal/overlay/overlay.go` (extend `Action` + `Match` + `matches`), `internal/overlay/overlay_test.go`

**Interfaces:**
- Produces: `overlay.Action` gains `Verb, Binary, Channel, Principal string`, `Targets, Findings []string`, `Flags map[string]bool`, `Now time.Time`. `overlay.Match` gains:
  ```go
  Surfaces   []string `json:"surfaces,omitempty"`    // OR, exact ci
  Verbs      []string `json:"verbs,omitempty"`        // OR, exact ci
  Principals []string `json:"principals,omitempty"`   // OR, exact ci (caller principal_id)
  Channels   []string `json:"channels,omitempty"`     // OR, exact ci
  FlagsAll   []string `json:"flags_all,omitempty"`    // AND: every named flag must be true
  FindingsAny []string `json:"findings_any,omitempty"`// OR: any listed DLP label present
  NotTargets []string `json:"not_targets,omitempty"`  // matches when NO target is in this allowlist (host/recipient allowlist inversion)
  TimeWindow *Window  `json:"time_window,omitempty"`  // matches when Action.Now is inside [Start,End] local (quiet hours)
  ```
  `Window{Start, End string /*"23:00"*/, Days []string}`. AND-across-facets / OR-within preserved; all-empty Match still never matches. Tighten-only validation unchanged.

- [ ] **Step 1:** Add table tests: a rule with `Surfaces:["twitter"],Verbs:["post","reply","dm","follow"]` matches a `post` action, not a `read`; `Principals:["llm-twitter"]` gates by caller; `FindingsAny:["secret:ghp"]` fires on a DLP hit; `NotTargets:["a@x.com"]` fires when recipient is `b@y.com` (external), not when `a@x.com`; `TimeWindow{23:00–07:00}` matches a 02:00 Now, not a 12:00 Now.
- [ ] **Step 2:** FAIL → implement facet matchers (reuse ci helpers; `NotTargets` = none-of-targets-in-set; `TimeWindow` handles wraparound midnight) → PASS `-race`.
- [ ] **Step 3:** Commit `feat: overlay semantic facets (surface/verb/principal/flags/findings/time)`.

### Task A4: wire semantic into the PDP + audit

**Files:**
- Modify: `internal/govern/govern.go` (`buildInput` adds `input.action.semantic`; `decide` builds the extended `overlay.Action` from the normalized action + caller; passes `Now`), `internal/decisions/decisions.go` (add non-hashed `Surface`/`Verb`/... already has Surface; add `Verb`, `Findings` as non-hashed fields on `Record`), `internal/govern/govern_test.go`
- Test: extend `govern_test.go` (a request whose command is `bird tweet x` + an overlay rule `{Surfaces:[twitter],Verbs:[post],Verdict:deny}` → response verdict `deny`, reason `local_overlay:…`).

**Interfaces:**
- Consumes: `normalize.Classify`, extended `overlay.Action`.
- Produces: OPA input now contains `input.action.semantic.{surface,verb,...}`; overlay sees semantic facets on the PDP path. `decisions.Record` gains `Verb string` + `Findings []string` (both `,omitempty`, EXCLUDED from the row hash — mirror how Surface/caller fields are excluded).

- [ ] **Step 1:** Write the govern_test case above → FAIL.
- [ ] **Step 2:** In `decide`: `sem := normalize.Classify(req.Action.Tool, req.Action.Args, req.Ctx.Surface)`; build `overlay.Action{Tool, Command:commandString, Host, Method, Path, Surface, Verb:sem.Verb, Binary:sem.Binary, Channel:sem.Channel, Principal:req.Ctx.Caller.PrincipalID, Targets:sem.Targets, Findings:sem.Findings, Flags:sem.Flags, Now:s.nowFn()}`. In `buildInput` add `"semantic": sem` to the action map.
- [ ] **Step 3:** Verify hash-chain stability: add a test asserting two records identical but for `Verb`/`Findings` produce the SAME `row_hash` (fields excluded from hash).
- [ ] **Step 4:** `go test ./... -race` → PASS. Commit `feat: wire semantic action into PDP eval, overlay, and audit`.

### Task A5: Phase A local e2e

**Files:** Create `docs/superpowers/plans/artifacts/` note only if needed; e2e lives in scratchpad (not committed).
- [ ] Build guard; run OPA + a stand-in permissive CP bundle + the guard; write a `packs.json`-free `overlay.json` by hand with a semantic rule; POST synthetic `/v1/govern` requests for `bird tweet`, `gog drive delete --force`, a DLP-tripping `message`; assert deny/ask; confirm semantic+findings in `decisions.jsonl`. Document the result in the phase-A commit message. (No code commit; gate only.)

---

# PHASE B — Packs + learn-mode

Produces: `internal/packs` (schema + two compilers), the 7 packs, learn profile→propose→promote. Depends on Phase A.

### Task B1: `internal/packs` — schema + persistence

**Files:** Create `internal/packs/packs.go`, `internal/packs/packs_test.go`. Add `config.PacksPath()` = `~/.aarvion/packs.json`.

**Interfaces:**
```go
package packs
type Pack struct { ID, Title, Mode string; Params map[string]any; PerAgent map[string]string }
type Set struct { Packs []Pack }
func Load(path string) (*Store, error)          // missing file → empty
func (s *Store) Set() Set
func (s *Store) Replace(Set) error              // atomic 0600 write, validate ids unique + mode∈{off,observe,ask,enforce}
func Catalog() []Pack                           // the 7 built-in packs with default Mode + Params
```
- [ ] TDD: Load-missing→empty; Replace→persist→reload; invalid mode rejected; `Catalog()` returns 7 packs with stable ids (`social-guard`,`google-guard`,`comms-guard`,`dlp-guard`,`api-guard`,`github-guard`,`infra-guard`). Commit.

### Task B2: `internal/packs` — overlay compiler (the 7 packs)

**Files:** Create `internal/packs/compile_overlay.go`, `internal/packs/compile_overlay_test.go`.

**Interfaces:** `func CompileOverlay(s Set) []overlay.Rule` — deterministic (sorted, stable ids `pack:<id>:<n>`). Each enabled non-off pack emits rules per §5 of the spec, using semantic facets. `observe` mode → emit rules with `Verdict:ask` but a marker in the ID/Reason so the caller records them non-enforcing (see B4); `ask`→ask; `enforce`→deny for destructive/hard rules, ask for the softer ones. `PerAgent[principal]=mode` narrows a copy of the pack's rules with `Principals:[principal]`.

- [ ] TDD per pack: assert `CompileOverlay` on a `Set{social-guard:enforce}` yields a rule matching `{twitter, post}`→deny; `google-guard:enforce` yields drive-delete→deny + email-send→ask; `dlp-guard:enforce` yields `FindingsAny:[secret:*]`→deny; `comms-guard` with `Params{quiet_hours:{23:00-07:00}}`→a TimeWindow ask rule; `api-guard` host-allowlist→NotTargets deny; `github-guard`/`infra-guard` port the existing denylists to verbs. Golden-compare the full rule set for the default catalog. Commit.

### Task B3: `internal/packs` — rego emitter (CP/beta)

**Files:** Create `internal/packs/compile_rego.go`, `_test.go`; write the emitted example packs to `examples/packs/` (one `.rego` per pack + a `data.json`).
**Interfaces:** `func EmitRego(s Set) (rego string, data []byte)` producing `package envoy.authz` rules equivalent to the overlay rules but full-strength (may deny outright), matching on `input.action.semantic.*` + `input.ctx.caller` + `data.packs`.
- [ ] TDD: emitted rego parses (`opa parse`/`opa check` via `exec` in the test, skipped if `opa` absent) and, fed a representative input through `opa eval`, denies a `bird tweet` when `social-guard` enabled. Snapshot the emitted files under `examples/packs/`. Commit.

### Task B4: learn-mode — behaviour profile + observe recording

**Files:** Modify `internal/sinks/learn.go` (or add `internal/sinks/behaviour.go`) + `internal/decisions/decisions.go` (add non-hashed `WouldBe string`). Modify `internal/govern/decide` so an overlay rule whose ID marks it `observe` sets `Enforced:false` + `WouldBe:<verdict>` and does NOT change the effective allow. Extend the console feed to surface it.
**Interfaces:** `behaviour.Profile` keyed `{principal,surface,verb}` → `{count, targets set, hourHistogram [24]int, lastSeen}`; `func (o *Observer) Record(sem normalize.Action, principal string, wouldBe string)`; persisted `~/.aarvion/behaviour-profile.json` 0600.
- [ ] TDD: feeding N semantic actions builds the expected profile; observe-mode rule yields `Enforced:false,WouldBe:"deny"` while the action still allows. Commit.

### Task B5: learn-mode — propose + promote

**Files:** Create `internal/packs/propose.go`, `_test.go`.
**Interfaces:** `func ProposeFromProfile(p behaviour.Profile) packs.Set` — seen-safe → allow (omit), never-seen sensitive verbs (post/send/delete/share/dm/follow) → the relevant pack in `ask`, known-destructive → `enforce`. Deterministic.
- [ ] TDD: a profile where `llm-twitter` only ever `read` → proposal enables `social-guard:enforce` for that agent; a profile where `main` sent email to 3 addrs → `google-guard:ask` with those 3 as the contact allowlist. Commit.

### Task B6: Phase B local e2e
- [ ] Compile the default catalog → overlay; run guard+OPA+CP; drive semantic actions through `/v1/govern`; assert each pack's headline behaviour; run learn observe → propose → promote → re-drive shows enforcement. Gate only.

---

# PHASE C — Consumer surfaces (console + Telegram approver)

### Task C1: `internal/approve` — pending store + resolution
**Files:** Create `internal/approve/approve.go`, `_test.go`.
**Interfaces:**
```go
type Pending struct { DecisionID, Principal, Surface, Verb, Reason string; Created time.Time; TTL time.Duration }
type Store struct{ ... }              // in-memory + optional ~/.aarvion/pending/ mirror
func (s *Store) Open(p Pending) (resolved <-chan string)   // "allow"|"deny"
func (s *Store) Resolve(id, verdict, who string) bool
func (s *Store) List() []Pending
func (s *Store) reap(now time.Time)   // TTL → deny
```
- [ ] TDD: Open→List shows it; Resolve("allow") delivers on the channel + removes; TTL reap resolves "deny"; double-resolve is a no-op. Commit.

### Task C2: `internal/approve` — Telegram bot client
**Files:** Create `internal/approve/telegram.go`, `_test.go` (httptest stub for `api.telegram.org`; base URL injectable).
**Interfaces:** `func (t *Telegram) Ask(p Pending) error` (sendMessage + inline keyboard approve/deny with callback_data=decisionID:verdict); `func (t *Telegram) Poll(ctx, resolve func(id,verdict,who string))` (getUpdates long-poll; maps callback → Resolve; answerCallbackQuery). Config `Approve` struct (spec §3.4) added to `config.go`.
- [ ] TDD against the stub: Ask posts the right payload; a simulated callback update drives `resolve(id,"allow",chatUser)`. Commit.

### Task C3: wire approver into the PDP path
**Files:** Modify `internal/govern/govern.go` (on `ask` verdict, `Open` a pending + fire Telegram Ask; return `ask` + `decision_id` fast), add `GET /v1/approvals/{id}` handler returning `{status: pending|allow|deny}`. Modify `cmd/guard/main.go` to construct the approver from config + start the Telegram poller. 
- [ ] TDD: an ask decision opens a pending and the approvals endpoint reports it; resolving flips it. Commit. (Plugin poll wiring in C5.)

### Task C4: console API + UI — Packs, Learning, Approvals
**Files:** Modify `internal/console/console.go` (routes: `GET/PUT /api/packs`, `GET /api/learn`, `POST /api/learn/promote`, `GET /api/approvals`, `POST /api/approvals/{id}`), `internal/console/ui/*` (embedded SPA: three new views). All new `/api/*` bearer-gated like existing routes; root SPA token-free.
- [ ] TDD (Go): `PUT /api/packs` with a valid Set writes packs.json + recompiles overlay; `POST /api/approvals/{id}` resolves a pending. UI: manual + a smoke test that the SPA served at `/` references the new views. Commit.

### Task C5: plugin — ask polling + surface completeness
**Files:** Modify `clients/openclaw-plugin/src/plugin.ts` (on `ask`: use native `requireApproval`, and if it exposes an async wait, poll `GET /v1/approvals/{id}` via the guard client until resolved/timeout). Modify `clients/openclaw-plugin/src/guard-client.ts` if a poll helper is needed. Keep zero `openclaw` imports; `tsc` clean.
- [ ] TDD (TS e2e.ts): an ask verdict pauses; a resolved-allow proceeds; timeout denies. Build `dist`. Commit.

### Task C6: Phase C local e2e
- [ ] Full loop with a stubbed Telegram: pack in ask mode → action → pending appears in `/api/approvals` and the stub "taps approve" → action proceeds; console Packs toggle recompiles overlay live. Gate only.

---

# PHASE D — Prove on the mini + ship

### Task D1: live mini proof
- [ ] Cross-build arm64 guard; on the mini: pair a fresh TEST entity, `onboard`, install+enable plugin. Run REAL `openclaw agent --local` turns: `bird tweet` → blocked; `bird search` → allowed; `gog gmail send …` → ask → (with the user's real Telegram bot) approve on phone → proceeds; `gog drive delete --force` → denied; a `message` containing a secret → denied by dlp-guard. Verify semantic + caller + findings in the hash-chained audit. Capture evidence.
- [ ] Revert clean: uninstall plugin, restore `guard.json`/gateway env, stop guard+OPA. Confirm moltbot pristine.

### Task D2: docs
- [ ] Update top-level `README.md` (semantic packs headline), `clients/openclaw-plugin/README.md`, `docs/ROADMAP.md` (waves done), new `docs/POLICY-PACKS.md` (consumer catalog), `docs/PRODUCT-FLOW.md` (learn→approve). Keep the same-uid honesty note. Commit.

### Task D3: beta.aarvion.ai staging
- [ ] Stage the emitted packs on beta for the live entity via the site (browser), so the same packs are toggleable there and pulled signed. Document what was staged.

### Task D4: PR
- [ ] Push `feat/governance-engine` to fork; open a NEW PR to `Aarvion-AI/aarvion-guard` (base main) from the fork, titled + bodied as the launch story. Do not merge (no org write).

## Self-Review notes
- Spec coverage: normalizer (A1-A2), overlay facets (A3), wiring/audit (A4), packs schema+2 compilers (B1-B3), the 7 packs (B2/B3), learn observe/propose/promote (B4-B5), approver+telegram+inbox (C1-C4), plugin ask poll (C5), console UI (C4), mini proof (D1), docs (D2), beta (D3), PR (D4). All spec §3-§7 items map to a task.
- Tighten-only invariant preserved: local packs compile ONLY to deny/ask overlay rules; `overlay.validate` unchanged.
- Type consistency: `normalize.Action` fields consumed identically by overlay wiring (A4) and rego emitter (B3); `overlay.Action`/`Match` extensions defined in A3 and used in A4/B2.
