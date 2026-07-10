# Local governance console — design options

A dashboard that runs **on the operator's machine, next to the guard** — for people
who want to watch decisions and change policy/config locally, without the
beta.aarvion.ai UI — while staying **gated to aarvion** and **synced** to the cloud
(edit local *or* cloud, kept consistent). This is not the aarvion.ai app; it's a
small local operator console the guard ships/serves.

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

### Option 1 — Local console, cloud signs (thin, safest) · MVP
Local UI = the live on-box decision feed + the current policy (read from the
pulled bundle). **Editing** submits the change to the CP (via the aarvion
session); the CP validates + re-signs the entity bundle; the guard pulls it in
5–15s and enforces.
- **Sync:** trivially consistent — CP is the only writer/signer, local is a viewer
  + a remote-edit client.
- **+** Trust model unchanged, zero divergence, least new code. **−** Editing needs
  connectivity to aarvion (viewing works offline).

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

### Option 3 — Local overlay on the cloud base (clean + safe) · recommended direction
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

## Recommended flow

1. **MVP = Option 1.** Local console with the live on-box feed + read-only policy +
   edit-via-CP, gated by device-code aarvion auth. Ships value fast, changes
   nothing about trust. Most of the "just let me see/change things locally" desire
   is satisfied here.
2. **Then Option 3.** Add a **tighten-only local overlay** synced as entity policy —
   this is the honest answer to "change things locally (or cloud, synced)" with a
   safety guarantee and no divergence of the org base.
3. **Option 2 only** if arbitrary *offline loosening* is a hard requirement — it's
   the most capable and the most dangerous.

## Source of truth + sync semantics

- **CP is authoritative for the org base** (always signed there).
- **Local overlay is authoritative for its own entity/machine scope**, synced up.
- **Sync status surfaced everywhere:** `In sync` · `Local ahead (N pending)` ·
  `Cloud ahead (pull)` · `Conflict (resolve)`.
- **Everything gated:** any change requires a valid aarvion session tied to the
  entity — local convenience, cloud entitlement.

## Build seams (this repo)

- `aarvion-guard dashboard` → embedded, gated local web server (`go:embed` static
  UI; reuse aarvion-ui tokens/components at build time).
- **Feed API:** read the on-box `chain.json` + audit JSONL (already written) — no CP.
- **Policy read:** expose the active bundle's policy for display.
- **Edit (Opt 1):** proxy to the CP policy endpoints using the aarvion session.
- **Overlay (Opt 3):** a local overlay store; the guard's OPA loads base+overlay;
  a **tighten-only validator**; push the overlay to the CP as entity policy.
- **Auth:** device-code against aarvion; token bound to the entity in `guard.json`.

Same-uid caveat still applies to *enforcement* (guard vs agent on separate uids);
it doesn't change this console's design.
