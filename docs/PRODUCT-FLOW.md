# Aarvion for OpenClaw — the product flow (end to end)

How a real user goes from "I have an OpenClaw agent" to "it's governed, it watches
before it blocks, and it pings my phone before it does anything risky — and I tune it
from the cloud dashboard or a local console on the box." Written as a product, not a
tool: signup → install → govern → **learn → protect → approve** → customize, with the
trust model made explicit and every step tagged **[EXISTS]** (shipped or on PR #28),
**[on `feat/governance-engine`]** (the semantic packs / learn / approvals work), or
**[GAP]** (needs building).

## Three components, one trust chain

```
  aarvion.ai (control plane, SaaS)        your machine (data plane)
  ┌────────────────────────────┐         ┌───────────────────────────────┐
  │ signup · entities · keys   │  signed │ aarvion-guard (PDP)            │
  │ policy editor · decision   │ bundle  │  • pulls + verifies policy     │
  │ feed · bundle build+sign   │ ───────►│  • /v1/govern UDS  ◄──────┐    │
  └────────────────────────────┘ ◄─────  │  • pushes decisions       │    │
                                 decisions└───────────────────────────┼────┘
                                                                       │ tool call
                                          ┌────────────────────────────┴───┐
                                          │ OpenClaw + @aarvion plugin (PEP)│
                                          └─────────────────────────────────┘
```

- **Control plane (aarvion.ai)** — the SaaS. Owns policy, signs bundles, stores the
  decision audit, hosts the dashboard.
- **Guard (data plane)** — runs where OpenClaw runs. Pulls the signed policy,
  enforces it, exposes the local `/v1/govern` socket, pushes decisions back.
- **Plugin (PEP)** — inside OpenClaw. Calls the guard before every tool call.

The guard trusts **only CP-signed bundles**, so all policy authority lives in the
control plane. That's what makes dashboard customization safe and instant.

## The keys — four secrets, three of them invisible to the user

| Secret | Who holds it | Role | User sees it? |
|---|---|---|---|
| **Pairing code** | dashboard → user | one-time; claimed once for entity creds | **yes** (the one thing they copy) |
| **Signing secret** (per-entity, HS256) | CP + `guard.json` | trust anchor — only the CP can sign a bundle the guard will load | no |
| **Enrollment token** (per-entity) | CP + `guard.json` | authenticates the guard's calls to CP (bundle pull, decision push, heartbeat) | no |
| **Govern socket token** (local) | `guard.json` + OpenClaw env | guard ↔ plugin auth on the machine | no |

The user copies **one** thing — the pairing code. Everything else is derived and
managed. That's the bar for non-dev onboarding.

## The flow

### 1. Sign up → create an entity → get a pairing code  **[EXISTS]**
On aarvion.ai the user makes an account and an "entity" (an agent or a fleet). The
dashboard shows a one-line install command with a **pairing code** baked in. The CP
already exposes `/api/openclaw/pair/claim`.

### 2. One command installs + pairs + wires everything  **[partly EXISTS, needs one wrapper]**
Target UX — a single command from the dashboard:
```sh
npx @aarvionai/guard onboard <PAIRING_CODE>
```
It runs, in order:
1. Download the guard binary **with the PDP** — **[GAP: needs v0.3.0 release; PR #28 unmerged]**
2. `aarvion-guard init <code>` → claim entity creds → write `guard.json` (entity_id, signing_secret, bundle_url, enrollment_token) — **[EXISTS]**
3. Add a `govern.socket` block (generate socket path + local token) + fail_mode — **[GAP: small `init` addition]**
4. Install the guard as a service and start it → pulls the signed bundle → PDP socket up — **[EXISTS for run/service; add socket]**
5. `openclaw plugins install @aarvion/openclaw-guard && openclaw plugins enable aarvion-guard` — **[GAP: publish the plugin]**
6. Write `OPENCLAW_GUARD_{ENABLED,SOCKET,TOKEN,FAIL_MODE,TOOLS}` into OpenClaw's service-env — **[GAP: onboarding locates OpenClaw's env]**
7. `openclaw gateway restart` — **[EXISTS]**

Result: every agent action is governed. **This wrapper (`onboard`) is the single
biggest virality lever** — it collapses ~6 developer steps into one.

### 3. See it work + customize (dashboard)  **[decision feed EXISTS; cloud editor is the GAP]**
- **Decision feed** — the guard already pushes every allow/deny/ask (hash-chained,
  with the agent + session id) to the CP. The dashboard renders it: "blocked
  `git push --force` from agent *ops* 2m ago." **[guard side EXISTS; dashboard view GAP]**
- **Policy editor** — toggle packs (observe ↔ ask ↔ enforce), set allowlists/thresholds,
  per-agent trust, and where `ask` approvals are routed. On save the CP **rebuilds
  + re-signs** the entity's bundle. The guard picks it up on its next poll (5–15s),
  **no restart, no redeploy**. **[GAP: CP editor + re-sign pipeline]**

The data plane already honors whatever the CP signs (proxy *and* `/v1/govern`), so
"customizable policies on aarvion.ai" needs **zero guard changes** — it's a control-
plane feature.

### 4. Change things locally, now — the governance console  **[EXISTS; tested (unit + integration)]**
The cloud editor is still the GAP, but the "how do I customize?" answer already ships
on the box. After `init`/`onboard` the guard runs a **local governance console** (on by
default). One command opens it, pre-authed:
```sh
aarvion-guard dashboard
```
- **Console** (`internal/console`) — binds **127.0.0.1:8790 only**, `/api/*` gated by a
  bearer token at `~/.aarvion/console-token` (0600), serves an embedded dark
  aarvion-styled SPA at `/`. Routes: `GET /api/status`, `GET /api/feed` (the live
  decision feed, same hash-chained allow/deny/ask stream), `GET`/`PUT /api/overlay`,
  `POST /api/sync`, plus the pack/learn/approval routes the consumer views in §5 use
  (`GET`/`PUT /api/packs`, `GET /api/learn`, `POST /api/learn/promote`,
  `GET /api/approvals`, `POST /api/approvals/{id}`).
- **Tighten-only overlay** (`internal/overlay`, `~/.aarvion/overlay.json`) — local rules
  that can only **ADD** deny/ask, never loosen a CP-signed decision. Evaluated *after* the
  base OPA decision and only when it **ALLOWED** — a structural tighten-only guarantee, not
  a convention. Egress match → deny; PDP (tool) match → deny or ask (owner approval).
  Matches on tool, command substring, host suffix, method.
- **Sync** (`internal/cpsync`) — overlay edits best-effort push to
  `{cp}/api/v1/entities/{tenant}/{entityID}/overlay`; the console shows sync status and
  **degrades gracefully** if the CP lacks the endpoint. The CP-signed bundle stays
  authoritative; the local overlay can only tighten.

So the two consoles split cleanly: **beta.aarvion.ai** stays the authoritative multi-fleet
console (policy, re-sign, cross-machine feed); the **local console** is for the single-box
operator who wants to tighten *right now* without a CP round-trip. Covered by the integration
tests: a deny rule authored via the console API makes the matching host return **403** (reason
`local_overlay: …`) while a non-matching host stays **200**; a non-tightening `PUT` is
rejected **400**; unauth `/api/overlay` returns **401**; the blocked decision shows up
hash-chained in the feed.

### 5. The consumer journey — observe → "Protect me now" → approve on your phone  **[EXISTS on `feat/governance-engine`; designed + tested (unit + integration)]**
Raw overlay rules ("deny host suffix X, ask on tool Y") are still a developer artifact.
The consumer path sits on top of them: named **policy packs** an operator toggles, a
**learn** posture that watches before it blocks, one button to turn learning into
enforcement, and an **ask** that reaches the owner on their phone. This is what a
non-developer actually touches — the overlay is the compiler target underneath.

**What a pack is.** A pack (`internal/packs`) is a per-surface guardrail with a plain
title and one of four modes — `off` / `observe` / `ask` / `enforce` — plus optional
per-agent overrides. Seven ship in the catalog:

| Pack | Governs | What enforce does |
|---|---|---|
| **social-guard** | Twitter/X (`bird`) | read-only or ask before post/reply/DM/follow, per account |
| **google-guard** | Gmail / Drive / Docs / Calendar (`gog`) | ask on email send; deny Drive delete / `--force`; deny anyone-with-link sharing |
| **comms-guard** | Telegram / Discord / WhatsApp / Reddit (`message`, `sessions_send`) | recipient allowlist, quiet hours |
| **dlp-guard** | all outbound bodies | secret markers (`ghp_`/`sk-`/`AKIA`/1Password) + PII → deny or ask |
| **api-guard** | `web_fetch` / curl | host allowlist; deny destructive HTTP verbs (DELETE/PUT/PATCH) |
| **github-guard** | `gh` / `git` | force-push, repo/branch delete, workflow/secret edits |
| **infra-guard** | `docker` / `systemctl` / truenas | destructive ops deny |

The packs read the **semantic action** (`internal/normalize`), not the raw command: each
tool call is classified into `{surface, verb, targets, host, flags, findings}` so "twitter
post" and "gmail send to a non-contact" are matched by intent, not by substring. Packs
compile **tighten-only** into the local overlay — same structural guarantee as §4, they
can only *add* deny/ask, never loosen a CP-signed decision.

**a. Onboard ships in observe — nothing is blocked yet.** Every pack defaults to
`observe`. On the first run the guard records what each agent *actually does* (the
behaviour profile, `~/.aarvion/behaviour-profile.json`, keyed by `{principal, surface,
verb}`) and records what enforcement *would have* done (`would_be` on each decision) —
but changes no outcome. The console **Learning** panel (`GET /api/learn`) renders the
profile: "agent *llm-twitter* did `twitter.read` 44× and never posted; agent *ops*
pushed to 3 repos." You see your fleet before you gate it. Nothing breaks on day one,
which is the whole point of shipping in observe.

**b. "Protect me now" promotes to ask-heavy enforce.** One click (`POST
/api/learn/promote`) turns the observed profile into a starter policy
(`packs.ProposeFromProfile`) and makes it live — persisted and recompiled into the
overlay, **no restart**. The proposal is deliberately conservative:
- an agent that was **only ever read-only** on a surface gets that surface **locked to
  enforce** for it (observed read-only becomes an enforced read-only contract);
- any **sensitive verb** it was seen doing (send/post/dm/follow/delete/share) flips the
  pack to **ask** (with a small, stable target set seeded into the allowlist if one
  exists);
- **dlp-guard is always enforce** — a leaking secret is never something to "learn as
  normal."

So the default after promotion is ask-heavy: destructive things deny, the softer
sensitive things ask, and read-only agents are pinned read-only. You can still hand-tune
any pack's mode or per-agent override on the **Packs** board (`PUT /api/packs`, recompiles
on save).

**c. An ask reaches the owner on their phone.** When a verdict resolves to `ask`, the PDP
returns `ask` immediately and opens a pending approval (`internal/approve`) — it does not
hold the govern socket for minutes. The pending fans out two ways:
- **Telegram** — if `approve.telegram.{bot_token, chat_id}` is set, the guard DMs the
  owner off the hot path: "Agent `llm-twitter` wants to **twitter.post**: '…'. ✅ Approve
  / ❌ Deny." The owner taps a button on their phone; the callback resolves the pending.
  The bot is independent of OpenClaw — approvals must never route back through the
  governed agent.
- **Console inbox** — the same pending appears in the local console (`GET /api/approvals`;
  resolve with `POST /api/approvals/{id}`). Either channel resolves it; exactly one
  resolution wins.

The PEP plugin holds the tool call and polls `GET /v1/approvals/{id}` until it flips
(falling back to OpenClaw's native `requireApproval` only against an older guard that
returns no `decision_id`). **Timeout → deny** (fail-safe; the plugin's approval window
defaults to 90s, `OPENCLAW_GUARD_APPROVAL_TIMEOUT_MS`).
Every resolution — who approved, how, when — is hash-chained into the same audit as the
decision. So the loop is: agent tries something sensitive → you get a tap-to-approve on
your phone → allow or deny → it proceeds or stops, and it's all on the record.

Status: designed, and tested at unit + integration level (normalizer tables, pack
compile → overlay/rego, approve store + timeout + Telegram client against an httptest
stub, learn→promote round-trip). The live mini proof (real `gog`/`bird`/comms turns,
approve-on-Telegram) is run and evidenced separately.

> **Same-uid caveat, again.** On the single-box mini the guard and OpenClaw share uid
> 501, so this proves the governance *path*, not a tamper-proof boundary: a same-uid
> compromise can still unset the plugin's env, kill the guard, or edit `packs.json`. Real
> enforcement needs uid separation (a service account) or a system extension. And note
> the guard governs tool **actions** — the model's streamed response is not governed. This
> is a real, audited, human-approvable action gate; it is **not** unbypassable, and we
> don't claim it is.

### 6. Future customization  **[design]**
The consumer surface (packs, learn→promote, Telegram/console approvals) ships locally on
`feat/governance-engine` today; the cloud side mirrors it. Everything CP-side is
dashboard-driven and hot-reloaded via the signed bundle: the **same seven packs** (the
pack schema has a rego emitter, so a pack is enable-able on beta.aarvion.ai against the
live entity, pulled signed), per-agent trust tiers, more `ask`-approval channels (Slack
alongside Telegram), spend caps, allowlists. The guard stays a thin enforcement point
(base bundle from the CP, local overlay tightening on top). Fleet-scale: one entity per
agent, or a shared policy across a fleet.

## What has to ship, in order

1. **Grant `anotb` write on Aarvion-AI/aarvion-guard** (or an org admin merges) —
   today it's pull-only, so #28 can't be merged from here. *This blocks 2.*
2. **Merge #28 + tag `v0.3.0`** → guard binaries that include the PDP.
3. **Publish `@aarvion/openclaw-guard`** (npm + ClawHub).
4. **Build `aarvion-guard onboard`** (the one-command wrapper in step 2).
5. **CP dashboard**: policy editor + decision feed + re-sign pipeline (step 3).
6. **Demo clip** + PH copy leading with the wedge: *governs what your agent does,
   not just what it connects to — install a plugin, don't fork your agent.*

Items 2–4 are in this repo (buildable here once access lands). 1 and 5 are org/CP.
Until 5 lands, the **local governance console + tighten-only overlay** (step 4) plus the
**packs / learn / phone-approval consumer journey** (step 5, on `feat/governance-engine`)
already answer "how do I customize?" and "how do I get told before something risky
happens?" on the box, with best-effort sync to the CP. Same-uid caveat still applies:
this is the governance path, not a tamper-proof boundary — hard enforcement wants guard +
agent on separate uids.
