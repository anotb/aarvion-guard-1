# SPEC — In-Runtime Governance Hook (Option C)

> **Status:** Draft for review · 2026-07-08 · owners TBD
> **Context:** Network MITM cannot do body-level governance of OpenClaw without breaking it (the agent's non-Node clients reject the guard CA). See [ROADMAP.md](ROADMAP.md) and the MITM postmortem. This spec designs the alternative: govern *above* the transport, inside the OpenClaw runtime, calling the same policy engine the guard already runs.
> **One line:** Turn OpenClaw's tool-dispatch layer into a Policy Enforcement Point (PEP) that asks the guard, a local Policy Decision Point (PDP), to approve each dispatched action before it runs.
> **Read §0 first.** This design has hard preconditions and named residuals. It is a real improvement over MITM, not a complete solution. The parts that are net-new builds, unverified assumptions, and things it explicitly does not solve are called out throughout and collected in §18.

---

## 0. What this does and does not solve (read first)

**Solves (real wins over MITM):**
- Reads method / path / body / structured tool args in plaintext for **every** client, with no CA and no MITM, for actions that flow through a governed dispatcher.
- Carries **caller identity** (agent / session / source / trust / tool) into the decision and the audit chain — *conditional on* the preconditions below.
- Governs non-HTTP tool actions (Home Assistant service calls, homelab CRUD, 1Password reads) that a network proxy can never parse.
- Cannot be skipped by a prompt-injected agent *for the actions the dispatcher mediates* (unlike the env-proxy model, which the agent evades by not using the proxy).

**Does NOT solve (be honest with the team):**
- **The streamed model completion is still ungoverned.** The hook governs the *decision to call* the model and the request args, but the response tokens arrive inside the same rustls client that defeated MITM. This is the MITM wall relocated, not removed (§5, §18).
- **Egress that never enters the dispatcher is ungoverned at body level by both layers.** A skill doing its own HTTPS over a pinned/rustls client, or an `exec`'d shell one-liner opening a raw socket / `curl` / nested interpreter, is invisible to the hook (never dispatched) and to the proxy backstop (host-level `CONNECT` only). Closing this needs network-namespace/seccomp egress lockdown or a host firewall (§11, §18).
- **Under same-uid deployment, the identity, tamper-evidence, and socket-auth guarantees all collapse** (§12). uid/sandbox separation is a **precondition**, not a nice-to-have.
- **Redaction and `ask` (HITL) do not exist today** and are net-new phase-5 builds, not inherited capabilities (§8, §14, §18).
- Whether OpenClaw has a *single* dispatch chokepoint to wrap is **unverified**. `exec-approvals` is the only confirmed seam; the rest may be N integrations (§5, §14, §18).

Everything below is written to make those boundaries explicit rather than hide them.

## 1. Motivation

The guard governs by MITM-terminating TLS to read method/path/body. That requires every HTTP client inside OpenClaw to trust the guard's CA. It doesn't: the Node clients honor `NODE_EXTRA_CA_CERTS`, but the model client (Rust/rustls) and others ship their own root stores and reject the CA. Turning on inspection blocks the model traffic and kills the agent. Without inspection the guard sees only `CONNECT host` for HTTPS, so the method/path policy catalog is inert.

Governing *inside the runtime*, before an action is dispatched, gives us method, path, body, tool name, structured args, and which agent/session asked, in plaintext, for every client, with no certificate in the loop.

OpenClaw already does exactly this for one surface. `exec-approvals` gates shell execution via a local Unix socket (`~/.openclaw/exec-approvals.sock`) with a bearer token, per-agent allowlists, and `openclaw approvals get/set/allowlist`. Option C generalizes that seam and points it at the guard as the decision engine.

## 2. Goals / Non-goals

**Goals**
- Govern the dispatched-action surface (tool/skill calls, egress a skill declares, `exec`, outbound sends, and dispatcher-re-ingested responses) with full fidelity, for every client, no MITM.
- Carry caller identity into every decision and the hash-chain, **given the §12 preconditions**.
- Reuse the guard's OPA sidecar, signed-bundle pull + HS256 verify, decision hash-chain, control-plane push, and heartbeat. These stay; the guard gains a new local decision endpoint and some new fields/verdicts (§10, §14 — this is *extension*, not zero-change reuse).
- Reuse the existing signed policy bundle contract for HTTP-shaped actions, so vendor packs keep matching.
- Support four verdicts: `allow`, `deny`, `redact`, `ask` (last two are net-new, §8/§14).
- Fail safe (capability-based, default-closed for mutating/egress) and observable when the PDP is unavailable.

**Non-goals**
- Replacing the network proxy. It stays as a **host-level** backstop for egress that bypassed a governed tool. It does not add body-level coverage for pinned/non-proxy clients.
- Governing processes outside OpenClaw (still the proxy's job).
- Claiming coverage of surfaces not inventoried (§5, §14).

## 3. Background: the pieces we have, and what they actually are

**Guard side (this repo).** `internal/policy` POSTs an Envoy `ext_authz`-shaped input to OPA at `/v1/data/envoy/authz/allow` and decodes **only** `result.{allowed, http_status, headers}`, scraping `policy_id`/`reason`/`redactions`/`enforced` from **response headers** (`policy.go:75-92`). `internal/decisions` records into a per-writer hash-chain and batches to the CP. `internal/opa` supervises the OPA **child process** (loopback HTTP on `127.0.0.1:8181`, restarted with backoff up to 30s, `opa.go:157-188`).

**Two facts that correct the earlier draft:**
- The decision record's `caller_principal_id/session_id/source` are **hash-input keys pinned to literal `nil`** (`decisions.go:179-184`), **not fields on the `Record` struct** (`decisions.go:19-38`), and the CP push payload carries none of them. Adding real caller identity is a **code change** to `Record`, the CP `DecisionIn` model, and the Python DP shipper — not "populating reserved fields."
- `Recorder.Add` has a fixed positional signature with `Surface`/`Direction` hard-coded to `"egress"` (`decisions.go:140,172-174`). Runtime decisions need a new `Record`-taking variant.

**OpenClaw side.** `exec-approvals.json`: `{ version, socket: { path, token }, defaults, agents }`, managed by `openclaw approvals`. A local socket + token + per-agent config, gating exec. That is the PEP shape we extend — **for exec**. Other surfaces are not yet shown to share it (§5).

## 4. Design overview

Split enforcement from decision:
- **PEP (OpenClaw runtime):** a governor in each action-dispatch path. Before an action runs, it builds a decision request (with a per-call nonce and an args digest) and calls the PDP over a local socket, then enforces the verdict.
- **PDP (the guard):** a local decision endpoint that evaluates the OPA bundle (extended input), records the decision, and returns a verdict. Chain / CP push / dashboard are reused; the record schema and result decoding are **extended** (§10).

```
             ┌──────────────────────── OpenClaw runtime ────────────────────────┐
   channels  │   plan → dispatch(action) ──[PEP: governor]── execute            │
   cron ───▶ │                                 │  ▲                              │
   gmail     │                          request │  │ verdict                     │
             └─────────────────────────────────┼──┼──────────────────────────────┘
                                                ▼  │  UDS + token + SO_PEERCRED uid-match
             ┌──────────────────────── aarvion-guard (PDP) ─────────────────────┐
             │   govern socket → OPA eval (loopback HTTP) → decision chain → CP  │
             └───────────────────────────────────────────────────────────────────┘
                                                │
                     network forward proxy (host-level backstop, unchanged)
```

## 5. What gets governed — and the dispatch inventory this depends on

**Precondition (gate before committing):** the central premise is that OpenClaw's action surfaces funnel through a small number of dispatch chokepoints. **Only `exec` is verified.** Before adopting Option C, produce a **dispatch-path inventory**: grep the moltbot runtime for every place a tool/skill/MCP/browser/exec/send/egress action is invoked, and classify each as (a) already funnels through the exec-approvals-style dispatcher, (b) has its own dispatch we must wrap, or (c) bypasses dispatch entirely (→ residual, §11). Rollout is gated per-seam on this inventory. If the surfaces don't share a chokepoint, Option C is **N integrations of varying difficulty**, not one.

Intended surfaces (each a separate wrapping task until the inventory says otherwise):

| Surface | Examples on this instance | PEP sends | Status |
|---|---|---|---|
| `exec` | shell commands | command + argv + cwd | **seam exists** (exec-approvals) |
| `tool` | `homeassistant.call_service`, `nocodb.*`, `karakeep.*`, `1password.get` | tool id, operation, structured args | needs seam |
| `mcp` | arbitrary MCP server tools | `mcp:<server>.<tool>` + raw args (normalization, §10) | needs seam |
| `egress` | HTTP a skill declares | `attributes.request.http` (existing shape) | needs seam |
| `send` | twitter-x / discord / telegram / gmail / imessage | channel, recipient, body | needs seam |
| `response` | tool results + egress responses **re-ingested by the dispatcher** | status, headers, bounded body | needs seam; **excludes the model token stream (§18)** |

The model output *proposes* a tool call as data; the dispatcher (trusted code, not the model) makes the govern call and enforces. That is what makes the hook unbypassable **for dispatched actions**. Actions the model routes *around* the dispatcher (raw socket in an exec'd child, a skill's own fetch over a pinned client) are residuals (§11).

## 6. The decision protocol

### 6.1 Transport & authentication
Unix domain socket, file mode `0600`, owned by the guard's uid. Every request carries `Authorization: Bearer <token>` (provisioned at `init`, never exposed into agent/tool/log context). **Mandatory:** the PDP performs a peer-credential uid check on every connection — `SO_PEERCRED` (Linux) / `LOCAL_PEERCRED` (darwin) — and accepts only the configured PEP uid. There is **no peer-cred check in the codebase today**; this is net-new and load-bearing. See §12 for why the token alone is worthless under same-uid.

`POST /v1/govern` (decision) and `GET /v1/govern/health` (readiness, distinct from "eval failed", §13). Synchronous: the call blocks the action until a verdict or timeout.

### 6.2 Request (PEP → PDP) — `contract_version: "1"`
```json
{
  "contract_version": "1",
  "nonce": "b64-128bit",                     // per-call, echoed in the response (anti-replay, §12)
  "ctx": {
    "surface": "tool",                       // exec|tool|mcp|egress|send|response
    "phase": "pre",                          // pre|post
    "caller": {                              // stamped by the PEP; trust bounded by §12
      "principal_id": "agent:llm-twitter",
      "session_id": "agent:llm-twitter:tg-6575353438",
      "source": "telegram",
      "trust": "owner",                      // owner|member|group|untrusted|unattended
      "run_id": "864f0dc2-…",
      "tool": "twitter-x.post"
    }
  },
  "action": {                                // for non-HTTP tool/exec/mcp/send
    "tool": "homeassistant.call_service",
    "operation": "lock.unlock",
    "args": { "entity_id": "lock.front_door" },
    "args_digest": "sha256:…"                // over a deep-frozen snapshot (§12 TOCTOU)
  },
  "attributes": {                            // for egress-shaped actions — SAME as today
    "request": { "http": { "method": "POST", "host": "api.x.com", "path": "/2/tweets",
                           "body": "…", "headers": { … } } }
  }
}
```
`surface`/`phase` in the request are **labels for the PDP's convenience only**. The PEP's *enforcement* read/write classification comes from the dispatcher's own trusted knowledge of the tool, never from these model-adjacent fields (§13).

### 6.3 Response (PDP → PEP)
```json
{
  "decision_id": "01J…", "nonce": "b64-128bit",   // must echo the request nonce
  "verdict": "ask",                                // allow|deny|redact|ask
  "http_status": 202,
  "policy_id": "starter.home_safety.v1",
  "reason": "unlocking the front door needs owner approval",
  "redactions": [ { "path": "$.args.token", "replacement": "***" } ],   // phase-5, §8
  "exec_args_digest": "sha256:…",                  // for redact: the exact post-redaction args to run
  "obligations": { "audit": true, "notify_owner": true },
  "ask": { "channel": "telegram", "target": "6575353438", "timeout_s": 120,
           "ticket": "gr_…", "on_timeout": "deny" },
  "ttl_ms": 0                                       // >0 permits a bounded PEP allow-cache (§13)
}
```

### 6.4 OPA result contract — extension, not reuse
The current decoder reads only `result.{allowed, http_status, headers}`. Two options; **pick (ii) for v1** to stay backward-compatible with the header-based packs:
- **(i)** Add a structured result object and extend `policy.Decision` with `Verdict/Redactions/Obligations/Ask` (cleaner, but touches every pack's result shape).
- **(ii)** Express the superset as additional `result.headers` entries (`x-aarvion-verdict`, `x-aarvion-ask`, `x-aarvion-redactions-json`, …), decoded by an extended `policy.Eval`. Existing packs that only set `allowed`/existing headers keep working untouched.

Either way this is a **guard code change** (`internal/policy`), listed in §14. **Open:** whether to add a separate entrypoint `/v1/data/aarvion/govern` instead of overloading `envoy.authz` (§16) — recommended, because the real starter packs use an aggregator/`deny_verdicts` pattern and the superset should not be retrofitted into whatever aggregation they use.

## 7. Caller identity (the keystone — with the asterisk)

In-runtime, the dispatcher knows which agent/session/channel/tool originated an action, so it stamps `ctx.caller`. This fills the chain's identity gap and unlocks per-agent and trust-aware policy.

**But identity is only as trustworthy as the PEP's plumbing, and the PDP cannot independently verify it.** The PDP trusts `ctx.caller` **only after** the peer-cred check establishes that the caller is the real PEP (§12). Within that, some fields are stronger than others: `principal_id`/`session_id` derived from authenticated session/routing state are trustworthy; a `source`/`trust` or upstream-agent id propagated from message content or a peer agent in a multi-agent setup is **partly attacker-influenced**. The spec's rule: the PEP MUST derive identity from authenticated transport/session state and MUST NOT accept principal/trust asserted in message content or from a peer agent without re-authentication. So "identity is free and trustworthy" is **conditional**, not absolute.

## 8. Verdicts and enforcement

| Verdict | PEP behavior |
|---|---|
| `allow` | Execute normally. |
| `deny` | Abort. Return a tool result to the agent: `blocked by policy: <reason>` (so the model adapts, not crashes). Record the deny. |
| `redact` | **Net-new.** Rewrite args/body per `redactions` **before** executing, then execute the redacted form. See TOCTOU note below. |
| `ask` | **Net-new.** Suspend the action, open a HITL ticket, notify the owner on the named channel, resolve or apply `on_timeout`. |

**`redact` / `args_digest` contradiction (must resolve):** `redact` mutates args *after* the decision, so what executes is by construction not what was hashed in the request. Rule: for `redact`, the PDP returns `exec_args_digest` over the post-redaction args, and the executed action must match that digest; the audit row covers the redacted form. Otherwise `redact` is an unaudited mutation. Today **no redaction is applied anywhere** (`Decision.Redactions` is a logged string, never enforced; `proxy.go:190-197` copies bodies through untouched), so this is a phase-5 build with its own wire-type and JSONPath-over-arbitrary-tool-args design, not an inherited capability.

**`ask` needs bounds** (§13): async ticket + resume is preferred over a multi-minute synchronous block; cap outstanding asks per entity with a shed/deny policy; define interaction with the agent run's own timeout so a suspended action isn't duplicated or orphaned on resume.

## 9. Policy authoring impact

For HTTP-shaped actions the input is unchanged, so existing vendor packs keep matching — **asserted, not demonstrated: the starter `.rego` packs are not in this repo**, so their shape (single allow-object vs aggregator/`deny_verdicts`) and their compatibility with new input keys are unverified. **Action:** commit the actual starter packs (or an appendix) and show the additive keys (`ctx.caller.*`, `ctx.surface`, `action.*`) threading through, or adopt the separate `/v1/data/aarvion/govern` entrypoint so the superset never retrofits into the packs' aggregation.

New/upgraded packs can key on `ctx.caller.principal_id` (per-agent scoping), `ctx.caller.trust`/`source` (context-aware), and structured tool actions (`action.tool == "homeassistant.call_service" && action.operation == "lock.unlock"`) instead of guessing from a URL. This is what lets the catalog finally cover the home/homelab/secrets/"acting-as-you" surface it's missing.

**MCP arg normalization (open):** MCP tools take server-defined arbitrary JSON the guard has zero knowledge of. Define a naming convention (`mcp:<server>.<tool>`) and whether args are passed raw (bundle author reverse-engineers each server's params) or via a per-tool adapter registry. This is the difference between clean rules and unmaintainable ones.

## 10. Audit & recording (guard-side code changes)

PEP-originated decisions flow into the same chain + CP push, but this requires real changes, not reuse:
- **Add fields** `caller_principal_id/session_id/source`, `surface`, `phase`, `origin` (`runtime`|`proxy`), `contract_version` to the `Record` struct, the CP `DecisionIn` model, and the Python DP shipper — **in lockstep**. Populating the *hash-input* caller keys is linkage-safe today (CP verify is `prev_hash == prior row_hash`, `decisions.go:41-44`), but `origin` is a **new hashed field** that must land on the Go recorder and the DP shipper simultaneously, and stay in lockstep before any CP-side hash recomputation.
- **Add a `Record`-taking `Add` variant** (the current positional signature hard-codes `Surface="egress"`).
- **Fix the allow-collapse key.** Today it is `method + " " + host + path` (`decisions.go:150`) and collapsed repeats are **dropped, not chained**. For runtime surfaces, tool/exec/send actions have no host/path, so distinct calls (and different agents) collapse together — discarding the identity that is the whole point. Extend the collapse key to `caller.principal_id + surface + tool/operation + args_digest`, make the PEP allow-cache key **identical** so they can't disagree, and decide explicitly: are collapsed allows dropped or counted+chained? A complete per-action audit chain and client-side caching+collapse are mutually exclusive — **pick one and state which actions are guaranteed to leave a row** (§18).
- **Throughput:** `Recorder` guards all state with one mutex and computes the sha256 rowHash *inline while holding it* (`decisions.go:83,141-186`). Under Option C that lock sees every action, not just egress. Move hashing off the lock (lock only to append + advance `prev`) or record async via a buffered channel so the govern response returns on the verdict. State the sequential-chain throughput ceiling; decide whether proxy and runtime share one `dp_id` writer (one interleaved chain) or separate writers (two chains).
- **`LatencyMs`** is an `int` (`decisions.go:29`); change to sub-ms resolution so the tail is observable.

## 11. Coexistence with the network proxy, and the residual

Hook is primary and full-fidelity; the proxy is a **host-level** backstop (it is `CONNECT`-only for cert-pinned hosts, `proxy.go:21-22,141`, so it adds no body-level coverage for the clients that matter). Coverage set:

> **covered = { actions through a governed dispatcher } ∪ { egress via a proxy-honoring, MITM-accepting client }**
> **residual (ungoverned at body level by BOTH layers) = a skill's own HTTPS over a rustls/pinned or non-proxy client, or an `exec`'d process opening a raw socket / nested interpreter / `curl`.**

To close the residual you need one of: (a) run `exec`'d children and skills under the guard's network namespace + seccomp so their egress is forced back through the proxy; (b) a host firewall pinning all outbound to the proxy; (c) argv-level policy that denies raw-socket/interpreter/`curl` invocations by default. The spec must state which it adopts; until then the residual is real and named.

## 12. Trust and threat model

**Why the hook resists a prompt-injected agent — and the limit of that claim.** Enforcement lives in trusted dispatch code above the model; the model emits a proposed call as data and cannot invoke "skip governance." This holds **only for actions the dispatcher mediates.** The same model can emit an action whose *arguments* are the bypass (an `exec` of a shell one-liner that opens a raw socket or `curl`s a proxied host). So "unbypassable" is scoped to dispatched actions, with §11's residuals, and `exec` in particular needs argv-level default-deny of interpreters/raw egress.

**Preconditions (not deferrable):**
- **uid / sandbox separation is required.** If the PEP and hostile skills share a uid, no local check distinguishes them: the bearer token buys nothing, `SO_PEERCRED` matches the attacker too, and the guard's `guard.json` / CA key / `signing_secret` / `enrollment_token` / CP token are readable by the agent. **Same-uid deployment VOIDS the tamper-evidence, identity-trust, and socket-auth guarantees.** The guard must run as a distinct uid (or the skills sandboxed) so its secrets are `0600` to a principal the agent can't read. This is a precondition of the whole design, not a later roadmap item.
- **Socket auth = token + mandatory `SO_PEERCRED`/`LOCAL_PEERCRED` uid-match** (net-new, §6.1). The token is defense-in-depth only.

**Other controls:**
- **Anti-TOCTOU:** the PEP deep-freezes (clones) args at digest time, and re-hashes-and-compares immediately before dispatch, dispatching strictly from the immutable snapshot. `redact` uses `exec_args_digest` (§8).
- **Anti-replay:** per-call `nonce` the PDP echoes and binds into the audit row; the PEP rejects any response whose `nonce`/`args_digest` doesn't match the outstanding request. Nothing binds a verdict to a single use otherwise (`decision_id` is minted by the PDP).
- **Allow-cache is an attack surface:** cache hits execute with **no PDP call and no audit row**, keyed on attacker-shaped `(caller, action-digest)`. Bound it hard: sub-second TTL, per-process only, evict on any bundle activation, never cache `obligations`/`ask`/`redact`, and either still emit a sampled audit row on hit or accept the gap **in writing** (§18).
- **DoS:** all actions route through one PDP → an agent can flood it to force timeouts. Per-caller rate-limiting at the PDP, plus a global PDP-unhealthy tripwire that fails **closed** for everything mutating regardless of per-surface config (§13).

## 13. Failure modes, availability, performance

- **Capability-based fail policy, default-closed.** HTTP-verb / `surface` classification is unsafe (a `GET https://attacker/?secret=…` exfiltrates; an MCP tool named `get_x` may mutate; and `surface`/`phase` are model-adjacent). Classify by **data-egress capability from the dispatcher's own trusted tool knowledge**: any tool that returns a secret, and any egress whose destination isn't on an essential allowlist, **fails closed** even if nominally a "read." The fail-open set is an explicit bundle allowlist of genuinely inert reads (local stat, non-secret metadata). All `tool`/`mcp` surfaces default fail-closed unless a pack/registry marks them read-only. Add a `tool` entry to the `fail_mode` map.
- **PDP lifecycle / OPA restart.** OPA is a **child process** restarted with backoff up to 30s (`opa.go:157-188`); during a crash/restart/bundle-reload every eval fails for up to 30s. Specify: `GET /v1/govern/health` readiness distinct from "eval failed"; keep the last-known-good bundle **warm** across OPA restarts (embed OPA as a library, or a warm standby) so the gap is milliseconds not 30s; a bounded "PDP warming" state that applies the bootstrap posture (not per-call fail flips); defined behavior for in-flight evals on restart; **mutating actions fail closed during warming.**
- **Latency (measured, not asserted).** `policy.Eval` is an HTTP POST over loopback TCP to a separate OPA process with a 5s client timeout — **not** in-memory. State a realistic budget measured under concurrency (p99 after N concurrent evals over the loopback path), or embed OPA as a library and re-benchmark. Do not ship a sub-ms claim without a measurement.
- **Throughput ceiling** from the single mutex-serialized chain (§10) — state it, don't discover it in prod.
- **`ask`** is unbounded by design (human); opt-in per rule, async ticket + resume, per-entity outstanding-ask cap (§8).

## 14. Rollout

Gated on the §5 dispatch inventory. Each phase shippable and reversible.

0. **Guard code prerequisites.** `Record`/CP/DP-shipper field additions + `Record`-taking `Add` (§10); extended `policy.Eval` result decode (§6.4); the `/v1/govern` UDS endpoint with token + `SO_PEERCRED` + health (§6.1); capability fail-mode + rate-limit + warm-bundle (§13). No OpenClaw change yet; test with a CLI client.
1. **Wrap `exec`** (the only confirmed seam). Point the existing exec-approvals path at the guard PDP. Lowest risk, immediate caller identity on exec, plus argv-level default-deny for raw-egress (§11/§12).
2. **Sends.** twitter-x / discord / telegram / gmail — approve-before-send + per-agent send allowlists. The demo that sells the product.
3. **Tool actions + homelab.** `homeassistant.call_service`, homelab CRUD, `1password.get`. Author the missing personal-agent packs.
4. **MCP + declared egress**, with the arg-normalization decision (§9).
5. **`redact` + `ask` + `response` (re-ingested only)** — net-new builds with their own designs and test surface.
6. **Demote MITM to backstop** and adopt a residual-closure (§11).

## 15. moltbot integration requirements

The integration contract the spec assumes OpenClaw provides, per dispatch point. Mark which exist:
1. A **caller-context object at the call site** (agent/session/source/trust/tool). — *exec only, today.*
2. **Resolved tool id / operation / structured args** before execution. — *exec only.*
3. A **synchronous block/deny** return path. — *exec only.*
4. An **arg-rewrite** path for `redact`. — *new.*
5. A **suspend / resume-or-cancel** path for `ask`. — *new.*
6. Identity derived from **authenticated session/routing state**, not message content (§7). — *new guarantee.*

"Identity is free" is true only where moltbot surfaces (1) at the seam. Any surface missing (1)–(3) is a moltbot build item, not just a guard one.

## 16. Concrete interfaces (v1)

**Guard config (`guard.json`):**
```json
"govern": {
  "socket": { "path": "~/.aarvion/govern.sock", "token": "<provisioned at init>", "peer_uid": 501 },
  "fail_mode": { "read_allowlist_only": true, "write": "closed", "send": "closed",
                 "exec": "closed", "tool": "closed", "mcp": "closed" },
  "allow_cache_ttl_ms": 500,
  "rate_limit_per_caller_qps": 50
}
```
**Errors (PDP):** `401` bad token / peer-uid mismatch · `400` malformed / nonce missing · `409` nonce replay · `503` PDP warming (PEP applies fail_mode) · `200` verdict.

## 17. Why this beats MITM (scoped)

| | Network MITM | Runtime hook |
|---|---|---|
| Reads body of **dispatched** actions | Only if client trusts CA | Yes, plaintext |
| Works for rustls / pinned clients | No (breaks agent) | Yes, **for dispatched actions** |
| Governs the model's streamed response | No | **No** (relocated wall, §18) |
| Governs egress that bypasses dispatch | Host-level only | **No** (residual, §11) |
| Caller identity | No | Yes, **given §12 preconditions** |
| Real redaction | No | Net-new build (§8) |
| Breaks model streaming | Yes | No (doesn't touch it) |
| Bypassable by the agent | Yes (skip proxy) | No **for dispatched actions**; residuals otherwise |
| Governs non-HTTP tool actions | No | Yes |

## 18. Limitations (state these to the team)

1. **Uncooperative TLS egress is unsolved by both layers.** A skill's own HTTPS over a pinned/rustls/non-proxy client, or an `exec`'d raw socket, is seen by neither the hook nor the proxy (CONNECT-only). Only netns/seccomp lockdown or a host firewall closes it.
2. **The model's streamed completion is not governed.** The hook governs the decision to call the model and the request args (a real win); the response tokens arrive in the same rustls client that defeated MITM. `phase=post` covers only dispatcher-re-ingested results.
3. **Same-uid deployment collapses the guarantees.** Identity, tamper-evidence, and socket-auth all assume the PEP and hostile skills are different principals.
4. **Redaction and `ask` are net-new**, not inherited. Nothing redacts today; there is no HITL plumbing.
5. **Caller identity is conditional** on the PEP's authenticated identity plumbing and is partly attacker-influenced in multi-agent/hostile-upstream setups; the PDP takes it on faith after the peer-cred check.
6. **The single local PDP is a DoS chokepoint and a throughput ceiling** (one OPA HTTP process behind one mutex-serialized chain).
7. **Cached and collapsed allows create audit gaps.** You cannot claim a complete per-action chain *and* client caching + collapse; pick, and state which actions are guaranteed a row.
8. **A single dispatch chokepoint is unverified.** exec-approvals is the only confirmed seam; the rest may be N integrations.
9. **The starter packs' backward-compat is asserted, not demonstrated** (the `.rego` isn't in this repo).

## 19. Open questions

- `ask` ownership: PEP-notifies vs PDP-tracks-ticket (leaning PEP-notifies, PDP-tracks, async resume).
- Separate `/v1/data/aarvion/govern` entrypoint vs `envoy.authz` superset (leaning separate, §6.4/§9).
- Embed OPA as a library vs keep the child process (affects §13 warm-bundle + latency).
- One `dp_id` writer (interleaved proxy+runtime chain) vs two (§10).
- MCP arg normalization: raw vs per-tool adapter registry (§9).
- Residual-closure choice: netns/seccomp vs host firewall vs argv default-deny (§11).
