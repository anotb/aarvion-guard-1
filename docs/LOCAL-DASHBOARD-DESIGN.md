# Local governance console — design options

> **Status: IMPLEMENTED (2026-07-10).** Shipped design = **Option 1 (local
> console) + Option 3 (tighten-only overlay)**. Option 2 (guard signs locally)
> was explicitly **not** chosen. Built, `go build/vet/test ./... -race` green, and
> live-proven end to end (real proxy + real OPA + stand-in CP). Packages:
> `internal/overlay`, `internal/console` (+ embedded SPA `internal/console/ui`),
> `internal/cpsync`. See **What shipped** below; the option write-ups keep their
> original framing with a per-option disposition.

A dashboard that runs **on the operator's machine, next to the guard** — for people
who want to watch decisions and change policy/config locally, without the
beta.aarvion.ai UI — while staying **gated to aarvion** and **synced** to the cloud
(edit local *or* cloud, kept consistent). This is not the aarvion.ai app; it's a
small local operator console the guard ships/serves.

## What shipped (2026-07-10)

The delivered console is **Option 1 + Option 3**: a local viewer/edit console over
a **tighten-only** local overlay, with best-effort cloud sync. Option 2 stays off
the table (the guard holds `signing_secret` only to *verify* CP bundles; it never
mints authoritative policy).

- **Tighten-only overlay** (`internal/overlay`). On-disk `~/.aarvion/overlay.json`
  (atomic write, `0600`). A rule can only **add** a deny or ask, never loosen a
  CP-signed decision. It's evaluated in Go **after** the base OPA decision and
  **only when the base ALLOWED** — that "only on allow" gate is the structural
  guarantee of tighten-only (a base deny is never reconsulted).
  - On the egress/proxy path (`internal/mitm.Decide`) a match becomes a **deny**
    (a proxy can't pause), with reason `local_overlay: …`.
  - On the agent-action PDP path (`internal/govern.decide`) a match escalates to
    **deny** or **ask** (owner approval), since the PDP supports human-in-the-loop.
  - **Match facets:** `Tools` (exact tool name), `CommandContains`
    (case-insensitive substring of the action's args), `HostSuffixes` (host or
    `.suffix`), `Methods` — AND across non-empty facets, OR within each.
  - `Replace()` validates tighten-only (verdict must be `deny`|`ask`, IDs non-empty
    and unique) and rejects anything else.
- **Local console** (`internal/console` + embedded SPA `internal/console/ui`,
  dark aarvion-styled). Binds **`127.0.0.1:8790`** only. Every `/api/*` route is
  gated by a per-run bearer token (`crypto/subtle`) written to
  `~/.aarvion/console-token` (`0600`); the UI at `/` is token-free and reads `?t=`.
  Routes: `GET /api/status`, `GET /api/feed?limit=N` (tails the decision JSONL),
  `GET/PUT /api/overlay` (PUT returns **400** on a non-tightening rule),
  `POST /api/sync`. On by default after `init`/`onboard`.
- **Cloud sync** (`internal/cpsync`). Every overlay edit best-effort POSTs to
  `{cp}/api/v1/entities/{tenant}/{entityID}/overlay`; the console surfaces sync
  status and degrades gracefully (`ErrUnsupported`) if the CP lacks the endpoint.
  This is the "change locally, cloud stays in sync" story. beta.aarvion.ai remains
  the authoritative multi-fleet console + policy editor; the local console is for a
  single-box operator who wants to tighten *now*, without a CP round-trip.
- **CLI.** `aarvion-guard run` serves the console + shares **one** overlay store
  across proxy/transparent/PDP + the editor (in-process edits take effect
  immediately; a 3s reloader also picks up out-of-band file edits).
  `aarvion-guard dashboard` opens the console in the browser pre-authed.
- **Live proof (local e2e).** Authored a deny rule for `httpbin.org` via
  `PUT /api/overlay` → proxied `GET https://httpbin.org/get` returned **403** with
  reason `local_overlay: …`; a non-matching host (`example.com`) still returned
  **200**; both decisions appeared hash-chained in `/api/feed`; a `PUT` with
  `verdict:"allow"` was rejected **400** "not tighten-only"; unauth `/api/overlay`
  → **401**.

Still future (honestly labeled): redaction rewriting is plumbed but **not
enforced**; per-rule **TTL/expiry**; **conflict resolution** when cloud and local
diverge.

## What the architecture forces (the real constraints)

1. **The guard enforces only policy it trusts.** Today its OPA pulls the CP's
   HS256-**signed** bundle and verifies it with the per-entity `signing_secret`
   (`internal/opa/opa.go` renders `keys.aarvion.key` from that secret). The guard
   has a bundle **verifier**, not a **builder** — it never compiles or signs
   policy. So a local edit only takes effect if something the guard trusts
   produces the policy.
2. **It must stay gated to aarvion.** Only the entitled account may change policy,
   even locally — so "localhost = trusted" is *not* enough; the local UI needs a
   real aarvion identity.
3. **Two writers ⇒ reconciliation.** If policy can change in the cloud *and*
   locally, one must be authoritative or they diverge.
4. **The live feed is already local.** The guard writes an on-box hash-chained
   decision log (`~/.aarvion/chain.json` + the audit JSONL). So a local decision
   feed needs **zero** cloud round-trip — it can even be more real-time than the
   cloud view.

The good news: the guard already holds `signing_secret` (to verify). So local
signing is *possible* (same key + keyid the CP uses) — it's a capability we'd add,
not a new secret to expose.

## Where it's served

`aarvion-guard dashboard` → a small web console on `127.0.0.1:<port>`, gated by an
aarvion session, that reads the guard's local decision log + config and talks to
the CP for policy sync. The web app can reuse aarvion-ui's design system
(prebuilt, `go:embed`'d into the guard binary) so it looks like aarvion without
being the aarvion.ai app. Offline-capable for viewing.

## Gating to aarvion (auth)

- **A. Device-code OAuth (recommended).** The console opens an aarvion URL; the
  user approves in a browser already logged into aarvion; the guard receives a
  short-lived token bound to the paired entity. Real entitlement, good UX.
- **B. Reuse the enrolled creds** already in `guard.json` (the guard is enrolled).
  Simplest, but conflates *machine* identity with *user* identity — weaker for a
  "who may change policy" gate.
- **C. Dashboard token** minted in the cloud UI, pasted locally. Explicit, simple.

Recommend **A**, fall back to **C**. In all cases the console is bound to the
entity in `guard.json`, so it can only govern this install.

## Three options for local edits + sync

### Option 1 — Local console, cloud signs (thin, safest) · MVP · SHIPPED
Local UI = the live on-box decision feed + the current policy (read from the
pulled bundle). **Editing** submits the change to the CP (via the aarvion
session); the CP validates + re-signs the entity bundle; the guard pulls it in
5–15s and enforces.
- **Sync:** trivially consistent — CP is the only writer/signer, local is a viewer
  + a remote-edit client.
- **+** Trust model unchanged, zero divergence, least new code. **−** Editing needs
  connectivity to aarvion (viewing works offline).
- **Disposition: SHIPPED.** This is the console shell — the live on-box feed +
  read-through of the active policy, gated locally. Loosening still routes through
  the CP; the local *editing* that ships is the Option-3 tighten-only overlay
  below, not arbitrary cloud-signed edits.

### Option 2 — Local-first, guard signs, async sync (powerful, heaviest)
The guard gains a policy **compiler + signer**: a local edit is compiled to rego,
signed locally with the `signing_secret` it already holds, loaded into its OPA
immediately (instant, offline enforcement), and queued to push to the CP when
online.
- **Sync:** bidirectional; CP is the merge authority; a *local-ahead /
  cloud-ahead / conflict* state with last-writer or explicit resolve.
- **+** True offline/air-gapped authoring, instant enforcement. **−** The guard
  becomes a signer/compiler (real new capability), divergence + conflict handling,
  two sources of truth. No *new* secret exposure, but the key's role widens from
  verify to author.
- **Disposition: NOT CHOSEN.** Deliberately rejected. The guard holds
  `signing_secret` only to *verify* CP bundles; it must never mint authoritative
  policy. The tighten-only overlay (Option 3) gives local, offline-enforced
  edits *without* making the guard a signer, so this option's cost buys nothing we
  need.

### Option 3 — Local overlay on the cloud base (clean + safe) · recommended direction · SHIPPED
The CP-signed bundle stays the authoritative **base** (org-wide). The local
console authors a **local overlay** — per-machine/entity rules the guard evaluates
**on top of** the base.
- **Safety property:** constrain the overlay to **tighten-only** — it may add
  denies / stricter asks, never loosen the base. Then even a locally-authored
  overlay is safe (it can't weaken org policy), which sidesteps signing for the
  common "make it stricter here" case. Loosening still routes through the CP.
- **Sync:** the overlay is a first-class **entity-scoped** object pushed to
  aarvion (visible in the cloud dashboard, promotable to org policy). Pull keeps
  the base fresh.
- **+** Clean base/overlay separation, no base divergence, a real safety
  guarantee, natural sync story. **−** Two-layer evaluation in the guard; loosening
  needs the CP.
- **Disposition: SHIPPED** as `internal/overlay` (see **What shipped**). Tighten-only
  is enforced structurally: the overlay is consulted in Go *after* the base OPA
  decision and *only when the base allowed*, so it can only add friction. Sync via
  `internal/cpsync` best-effort pushes each edit to the CP. Conflict resolution
  (cloud vs local divergence) and per-rule TTL remain future work.

## Recommended flow

*Followed as written (Option 1, then Option 3); done as of 2026-07-10.*

1. **MVP = Option 1.** ✅ Local console with the live on-box feed + read-only policy,
   served on loopback. (Shipped auth is a per-run loopback **bearer token** written
   `0600` to `~/.aarvion/console-token`, not the device-code OAuth this doc
   originally floated — loopback + one-shot token was enough for the single-box
   operator; device-code stays open for a future multi-user story.)
2. **Then Option 3.** ✅ Added the **tighten-only local overlay** (`internal/overlay`)
   with best-effort cloud sync (`internal/cpsync`) — the honest answer to "change
   things locally (or cloud, synced)" with a safety guarantee and no divergence of
   the org base.
3. **Option 2** — not built, and not planned unless arbitrary *offline loosening*
   becomes a hard requirement. It's the most capable and the most dangerous.

## Source of truth + sync semantics

- **CP is authoritative for the org base** (always signed there).
- **Local overlay is authoritative for its own entity/machine scope**, synced up.
- **Sync status surfaced everywhere:** `In sync` · `Local ahead (N pending)` ·
  `Cloud ahead (pull)` · `Conflict (resolve)`.
- **Everything gated:** any change requires a valid aarvion session tied to the
  entity — local convenience, cloud entitlement.

## Build seams (this repo) — as built

- `aarvion-guard dashboard` → embedded, gated local web server. ✅ `internal/console`
  binds `127.0.0.1:8790`; the SPA is `go:embed`'d from `internal/console/ui`
  (dark aarvion-styled). `aarvion-guard run` serves it alongside the proxy/PDP.
- **Feed API:** ✅ `GET /api/feed?limit=N` tails the on-box decision JSONL (the
  hash-chained log, already written) — no CP.
- **Policy read:** ✅ `GET /api/status` surfaces entity/tenant + state for display.
- **Edit (Opt 1):** the shipped local edit is the tighten-only overlay below;
  base-loosening still routes through the CP (not a local proxy endpoint).
- **Overlay (Opt 3):** ✅ `internal/overlay` — a shared local store
  (`~/.aarvion/overlay.json`, atomic `0600`); the guard evaluates base+overlay
  (`internal/mitm.Decide`, `internal/govern.decide`), `Replace()` is the
  **tighten-only validator**, and `internal/cpsync` pushes each edit to the CP as
  entity policy. `GET/PUT /api/overlay` is the editor (PUT 400s a non-tightening rule).
- **Auth:** ✅ per-run loopback **bearer token** (`crypto/subtle`, `~/.aarvion/console-token`,
  `0600`); the UI reads `?t=`. Bound to this install. (Device-code against aarvion
  remains a future option for a multi-user gate.)

Same-uid caveat still applies to *enforcement* (guard vs agent on separate uids);
it doesn't change this console's design.
