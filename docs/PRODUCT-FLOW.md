# Aarvion for OpenClaw — the product flow (end to end)

How a real user goes from "I have an OpenClaw agent" to "it's governed, and I tune
it from a dashboard." Written as a product, not a tool: signup → install → govern
→ customize, with the trust model made explicit and every step tagged
**[EXISTS]** (shipped or on PR #28) or **[GAP]** (needs building).

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

### 3. See it work + customize (dashboard)  **[decision feed EXISTS; editor is the GAP]**
- **Decision feed** — the guard already pushes every allow/deny/ask (hash-chained,
  with the agent + session id) to the CP. The dashboard renders it: "blocked
  `git push --force` from agent *ops* 2m ago." **[guard side EXISTS; dashboard view GAP]**
- **Policy editor** — toggle packs (monitor ↔ enforce), set allowlists/thresholds,
  per-agent trust, and where `ask` approvals are routed. On save the CP **rebuilds
  + re-signs** the entity's bundle. The guard picks it up on its next poll (5–15s),
  **no restart, no redeploy**. **[GAP: CP editor + re-sign pipeline]**

The data plane already honors whatever the CP signs (proxy *and* `/v1/govern`), so
"customizable policies on aarvion.ai" needs **zero guard changes** — it's a control-
plane feature.

### 4. Future customization  **[design]**
Everything is dashboard-driven and hot-reloaded via the signed bundle: new policy
packs, per-agent trust tiers, `ask`-approval channels (phone/Slack), spend caps,
allowlists. The guard stays a thin enforcement point. Fleet-scale: one entity per
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
Same-uid caveat still applies: hard enforcement wants guard + agent on separate uids.
