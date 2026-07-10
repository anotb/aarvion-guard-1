# Design: A real governance engine for real OpenClaw usage

Date: 2026-07-10
Branch (target): `feat/governance-engine` (new, off `release/openclaw-governance`), delivered as a NEW PR to the fork (`anotb/aarvion-guard-1`); anotb is pull-only on the org repo.
Status: approved in brainstorming; ready to turn into an implementation plan.

## 1. Problem

`aarvion-guard` today can *see* every OpenClaw tool call (the PEP plugin funnels them through OpenClaw's single `before_tool_call` chokepoint to the guard PDP over a Unix socket), and it can return **allow / deny / ask**. But policy is written as **fragile substring matches on the raw command** (`contains(cmd, "rm -rf")`). Two problems:

1. **It doesn't understand real tools.** The mac mini's agents act on the world through concrete CLIs and channels: `gog` (Google: Gmail send, Drive delete, Docs share, Calendar), `bird` (X/Twitter post/reply/DM/follow), `gh`/`git` (GitHub), native `telegram`/`discord`/`qqbot`/WhatsApp channels, a `reddit-digest` agent, and arbitrary API calls via `web_fetch`/curl. Substring matching against these is brittle (flag reordering, quoting, subcommand variants) and blind to *intent* (send vs read, delete vs list, external vs internal recipient).
2. **A normal person can't write it.** rego substring lists are not a consumer artifact. The `twitter-x` skill literally says "⛔ STRICT READ-ONLY — NEVER post/reply/DM/follow" — but that is *prompt text*, enforced by nothing. An agent that ignores it (or is prompt-injected) posts as the owner.

The goal: turn the guard from a network egress filter + generic action gate into a **semantic, per-surface governance engine** with **consumer-friendly policy packs**, so soft prompt instructions become hard, audited, human-approvable policy.

## 2. Non-goals and honest constraints

- **Not a tamper-proof boundary on the mini.** The guard and moltbot share uid 501 there. A same-uid compromise can unset the plugin's env, kill the guard, or edit config. This proves the governance *path*, not an unbypassable boundary; real enforcement needs uid separation (Linux service account) or a system extension. Docs must say this plainly.
- **Model's streamed response stays ungoverned.** The runtime hook governs tool *actions* (the PEP), not the model's rustls-terminated response stream. Out of scope.
- **No OpenClaw source changes.** The plugin stays an external, installable, `registerTrustedToolPolicy` plugin (the only config-reachable veto path).
- **Redact verdict stays plumbed-but-not-enforced.** We add semantics + ask over Telegram; field-level redaction remains a later phase.

## 3. Architecture

Four layers, added around the existing PDP without changing its security invariants.

```
OpenClaw tool call
   │  (PEP plugin: registerTrustedToolPolicy → /v1/govern over UDS, raw tool+params)
   ▼
guard PDP  internal/govern.decide
   │  1. NORMALIZE ──────────────► internal/normalize: raw {tool,args} → SemanticAction
   │  2. base OPA eval (CP bundle) ─ unchanged; sees input.action.semantic now too
   │  3. tighten-only overlay ─────► internal/overlay (extended: matches semantic facets)
   │        └── local packs compiled to overlay rules by internal/packs
   │  4. verdict allow/deny/ask
   │        └── ask → internal/approve (Telegram DM + console inbox) → allow/deny
   ▼
record → decisions hash-chain (semantic fields added) → sinks (learn profile, metrics, webhook, CP push)
```

**Key invariant preserved:** local packs run as the **tighten-only overlay**, consulted only when the base policy already ALLOWED. They can only add deny/ask, never loosen a signed decision. This is exactly the right safety posture for consumer toggles, and it reuses the structural guarantee already proven in `internal/overlay`. Full-strength (allow-or-deny) packs live in the CP-signed bundle on beta.aarvion.ai as rego.

### 3.1 Semantic normalizer — `internal/normalize` (new, Go, authoritative)

Pure, dependency-free package. Input: `tool string`, `args any` (string cmd for shell tools, structured params otherwise), `surface string`. Output:

```go
type SemanticAction struct {
    Surface  string            // email|file|calendar|doc|twitter|comms|github|api|exec|infra|unknown
    Verb     string            // send|read|delete|share|post|reply|dm|follow|push|force_push|repo_delete|call|...
    Binary   string            // gog|bird|gh|git|curl|docker|... (shell only)
    Account  string            // e.g. @Anot, an email account
    Channel  string            // telegram|discord|whatsapp|reddit|...
    Targets  []string          // recipients / repo / file id / host
    Host     string            // egress host for URL/api verbs
    Flags    map[string]bool   // force, external_recipient, public_share, destructive
    Findings []string          // DLP hits: secret markers / PII classes seen in payload
    Raw      string            // bounded raw command/summary, for forensics
}
```

Mechanism:
- A small **argv splitter** (shlex-like) + **per-binary matchers**: `gog <service> <verb>`, `bird <verb>`, `gh <noun> <verb>`, `git ... push [--force]`, `curl -X <verb> <url>`, `docker/systemctl/launchctl`. Each matcher maps subcommand+flags → `{Surface, Verb, Flags}` and extracts targets (`--to`, positional ids, urls).
- **Native tools** (`message`, `sessions_send`, `web_fetch`) map directly from structured params.
- **DLP scan** over the payload/body populates `Findings` (secret markers `ghp_`/`sk-`/`AKIA`/1Password refs, and coarse PII regexes). This is where "no secrets in outbound" gets its signal.
- Unknown binary/tool → `Surface:"unknown"`, empty verb; policy can choose to ask on unknowns.

Wiring: `govern.buildInput` adds `input.action.semantic = SemanticAction`; `govern.decide` populates an extended `overlay.Action` with the semantic fields. The normalizer is guard-side so the plugin can't lie its way past semantic policy (modulo the same-uid caveat, which is orthogonal).

### 3.2 Policy packs — `internal/packs` (new) + example rego

A **pack** = a named, parameterized policy unit with a plain-English identity and three modes.

```go
type Pack struct {
    ID       string              // "social-guard"
    Title    string              // "Social media guardrails"
    Mode     string              // observe|ask|enforce|off
    Params   map[string]any      // pack-specific (allowlists, quiet hours, accounts)
    PerAgent map[string]string   // principal_id → mode override (e.g. llm-twitter: enforce)
}
type PackSet struct { Packs []Pack }   // persisted ~/.aarvion/packs.json (0600), console-edited
```

Two compile targets from one definition:
- **Local compiler** `packs.CompileOverlay(PackSet, ...) []overlay.Rule` — emits tighten-only overlay rules (deny/ask only). This is what the console writes; enforced in-process by the extended overlay matcher. `observe` mode emits rules tagged non-enforcing (recorded as "would-be", see §3.3).
- **CP/rego emitter** `packs.EmitRego(PackSet) (rego string, data json)` — emits full-strength rego + `data.json` for the CP-signed bundle, so the *same* pack is enable-able on beta.aarvion.ai. Shipped as example packs under `examples/packs/*.rego` and stageable on the site.

The 7 packs (details in §5) are the product surface. `internal/overlay` gains semantic facets (`Surfaces`, `Verbs`, `Principals`, `FlagsAll`, `FindingsAny`, plus a time-window facet for quiet hours) so a pack rule like "twitter post/reply/dm → deny for llm-twitter" is expressible without substrings. The tighten-only validation invariant is unchanged (verdicts remain deny/ask only).

### 3.3 Learn mode — extend `internal/sinks/learn.go` + `internal/packs`

- **Observe:** packs in `observe` mode are evaluated but their verdict is recorded as `would_be` on the decision (a new non-hashed field), and the action proceeds. The learn sink accumulates a **semantic behaviour profile** keyed by `{principal, surface, verb}` with target sets, counts, and time-of-day histogram, written to `~/.aarvion/behaviour-profile.json` (0600).
- **Promote:** `packs.ProposeFromProfile(profile) PackSet` turns the profile into a starter policy: seen-safe patterns → allow (i.e. no rule), never-seen sensitive verbs (post/send/delete/share) → ask, known-destructive → deny. The console **Learning** panel renders the profile + proposal; **Protect me now** writes the compiled overlay. This is the "mix of observe + tighten" default: ship in observe, one informed click to ask-heavy enforce.

### 3.4 Human approvals — `internal/approve` (new) + console inbox

When a verdict resolves to `ask`:
- A **pending-approval store** (in-memory + `~/.aarvion/pending/` for crash visibility) records `{decision_id, principal, semantic action, reason, created, ttl}`.
- **Telegram approver:** if configured (`approve.telegram.{bot_token, chat_id}`), the guard sends the owner a DM — "Agent `llm-twitter` wants to **twitter.post**: '…'. ✅ Approve / ❌ Deny" — via the Bot API `sendMessage` with an inline keyboard, and resolves the pending item from the button callback (`getUpdates` long-poll or webhook; long-poll is simplest and needs no inbound port). Independent of OpenClaw (must not route approvals through the governed agent).
- **Console inbox:** the same pending item appears in the `:8790` console; approve/deny there resolves it too.
- **Timeout → deny** (fail-safe). Every resolution (who/how/when) is hash-chained into the audit.
- **PEP contract:** the PDP still returns `ask` fast; the plugin uses OpenClaw's native `requireApproval` to pause the tool call, and polls the guard `GET /v1/approvals/{decision_id}` (new) until resolved or timeout. This avoids holding the govern socket open for minutes. Exact sync-vs-poll wiring pinned in the plan; the store + Telegram bot + console inbox are the substance.

Config additions:
```go
type Approve struct {
    Enabled  bool
    TimeoutSeconds int
    Telegram struct { BotToken string; ChatID string }   // token via ~/.aarvion; owner supplies
}
```

### 3.5 Consumer surfaces — extend `internal/console`

The existing loopback console (`:8790`, token-gated `/api/*`, embedded SPA) gains three views:
- **Packs board:** each pack as a card with an on/off + mode dropdown (observe/ask/enforce) + per-agent tier chips. Saving `PUT /api/packs` compiles to the overlay.
- **Learning panel:** the behaviour profile + the generated proposal + **Protect me now**.
- **Approvals inbox:** the pending queue with approve/deny, live.

The `aarvion-guard dashboard` command already opens it pre-authed. All new endpoints are bearer-gated exactly like the existing overlay routes.

## 4. beta.aarvion.ai integration

The user can edit policy on the site directly. The pack schema is shared, so:
- The **rego emitter** produces the packs as CP-signable policy + `data.json`.
- I stage the packs on beta (via the site / browser, as prior sessions did) so the same "Twitter read-only" etc. are toggleable there against the live entity, and the guard's OPA pulls them signed.
- Division of labor: guard-side engine + local console + example packs ship in this repo (new PR to fork); the CP-side enable/sign is done on beta directly (anotb can't push org repos).

## 5. The packs

Each: id · what it governs · default posture. Per-agent overrides via `PerAgent`.

1. **social-guard** (`bird`/twitter): read-only enforce OR ask-before post/reply/DM/follow/like, per account. Default for `llm-twitter`: enforce read-only. *Makes the read-only skill actually strict.*
2. **google-guard** (`gog`): ask-before email send; deny send to non-contacts (allowlist param); **deny Drive delete / empty-trash / `--force`**; deny "anyone-with-link" doc sharing; calendar read-only for others.
3. **comms-guard** (telegram/discord/whatsapp/reddit via `message`/`sessions_send`): recipient allowlist; quiet hours (time-window facet); per-channel rate cap; no first-contact DMs.
4. **dlp-guard** (all outbound bodies): secret markers + PII in tweet/email/message/API body → deny or ask. Driven by normalizer `Findings`.
5. **api-guard** (`web_fetch`/curl): host allowlist; deny destructive verbs (DELETE/PUT) to prod hosts; per-API rate + $budget (reuse `internal/ratelimit` + spend meter).
6. **github-guard** (`gh`/`git`): force-push, repo/branch delete, workflow/secret edits, release publish. Extends the existing example rules into a real pack.
7. **infra-guard** (`docker`/`systemctl`/`launchctl`/truenas): destructive ops deny. Extends existing infra denylist.

## 6. Testing

- **Unit (Go):** `internal/normalize` table tests (every binary/verb/flag combo, quoting edge cases, DLP hits); `internal/packs` compile → overlay rules + rego snapshot; extended `internal/overlay` semantic-facet matching; `internal/approve` store + timeout + Telegram client (httptest stub for the Bot API). `go build/vet/test ./... -race` green.
- **Local e2e (scratchpad):** real guard + OPA + stand-in CP + a driver that POSTs semantic actions to `/v1/govern` and asserts allow/deny/ask per pack; approvals resolved via a stubbed Bot API; learn→promote round-trip.
- **Live on the mini (Phase D):** pair a fresh test entity, install the plugin, run REAL `openclaw agent --local` turns exercising `gog`/`bird`/comms (e.g. `bird tweet` → blocked; benign `bird search` → allowed; `gog gmail send` → ask → approve on Telegram → proceeds; `gog drive delete --force` → denied). Verify caller identity + semantic fields in the hash-chained audit. Revert clean (uninstall plugin, restore configs, stop procs) exactly as prior sessions.

## 7. Delivery

- New branch `feat/governance-engine` off `release/openclaw-governance`. New PR to the fork. Do not push to the org repo.
- Stage the packs on beta.aarvion.ai for the live entity.
- Update: top-level `README.md`, `clients/openclaw-plugin/README.md`, `docs/ROADMAP.md` (mark waves done), a new `docs/POLICY-PACKS.md` (the consumer catalog), and `docs/PRODUCT-FLOW.md` (learn→promote→approve).

## 8. Build phasing (each phase = its own Opus-agent workflow)

- **A — Engine:** `internal/normalize` + overlay semantic facets + `input.action.semantic` wiring + audit fields. Unit + local e2e green.
- **B — Packs + learn:** `internal/packs` (both compilers) + the 7 packs (overlay + example rego) + learn profile/propose/promote. Unit + local e2e green.
- **C — Surfaces:** console Packs/Learning/Approvals UI + `internal/approve` (Telegram + inbox) + config. Local e2e green; Telegram wired against the user's real bot when they supply the token.
- **D — Prove + ship:** live mini proof (real gog/bird/comms turns), revert, new branch + PR, stage on beta, docs.

## 9. Risks / open questions

- **Ask latency vs socket timeouts:** approvals can take minutes; the PDP write timeout is 20s. Resolved by the return-ask-then-poll design (§3.4); confirm the plugin's `requireApproval` can wait on a poll, else fall back to a bounded synchronous approver with its own listener.
- **Argv parsing coverage:** normalizer can't understand every CLI; unknown → `unknown` surface, and packs can ask-on-unknown. Ship with the binaries the mini actually uses; make matchers data-extensible.
- **Two policy engines (overlay vs rego):** intentional — local tighten-only (safe by construction) vs CP full-strength (signed). One pack schema, two emitters, kept in sync by golden tests.
- **Telegram bot credential:** owner-supplied (@BotFather). Console inbox is the working path until then.
