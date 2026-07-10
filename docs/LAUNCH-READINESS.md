# Launch readiness — governing OpenClaw, for non-devs (the road to viral)

Honest assessment of the new-user journey and what stands between "cool demo" and
"a normal OpenClaw user installs this and tells their friends." Written after
proving the action-governance path works live on a stock OpenClaw.

## The uncomfortable headline

**What we proved works is not what a new user installs today.**

- The published onboarding is `npx @aarvionai/guard run`. That npm shim
  (`@aarvionai/guard@0.2.6`) downloads the **v0.2.6 guard binary** = `origin/main`.
- `origin/main` has **zero** govern-PDP or plugin files (`internal/govern`,
  `clients/openclaw-plugin` don't exist there). It is the **network egress
  proxy** only.
- The network proxy is the surface we already know is a dead end for OpenClaw:
  in inspect mode it breaks the agent (its rustls model client rejects the guard
  CA); in no-inspect mode it's host-level-blind for HTTPS. It governs *which host*,
  never *what the agent does*.
- The compelling product — the **installable plugin** that governs the agent's
  **actions** (shell/git/gh, sends, web, files, MCP) with allow/deny/ask, and
  that we proved blocks a real `git push --force` on a stock OpenClaw without
  touching it — lives only on the **unmerged `release/openclaw-governance`
  branch (PR #28)**. It has never shipped.

So step one of "go viral" is not a feature. It's: **ship the thing that works.**

## The new-user journey today, step by step (and where a non-dev falls off)

| # | Step | Non-dev friction |
|---|------|------------------|
| 1 | Land on `beta.aarvion.ai/openclaw` | fine |
| 2 | Sign up / pair (entity id + enrollment token) | ok if the dashboard does it |
| 3 | `npx @aarvionai/guard run` | installs the **wrong** guard (network proxy, no action governance) |
| 4 | Route OpenClaw egress through it (HTTP_PROXY) + trust a CA | dev-level; and inspect-mode **breaks their agent** |
| 5 | Actually govern *actions* | **not possible** with the shipped path |

And the path that *does* govern actions (the plugin) currently needs a developer to:
run a guard with a `govern.socket` block, run OPA with a `.rego` policy, hand-write
`guard.json`, export five `OPENCLAW_GUARD_*` env vars, then
`openclaw plugins install --link` + `enable`. **A non-dev cannot do any of that.**
The functionality is real; the setup is a wall.

## Should policies be customizable on beta.aarvion.ai? Yes — and the guard already supports it

The guard's OPA pulls a **signed bundle per entity** from the control plane
(`cp-beta.aarvion.ai/.../policy.tar.gz`, HS256-verified). That bundle already
carries `config/starter/data.json` with per-pack `enabled`/`mode`
(`monitor`/`enforce`). **So policies are already server-hosted and configurable in
principle — the data plane needs no change to honor CP-authored policy.**

What's missing is the **control-plane UI + pipeline**, not guard support:

- A dashboard on beta.aarvion.ai to toggle packs (monitor ↔ enforce), set
  thresholds/allowlists, choose per-agent trust, and edit the govern packs
  (the `examples/govern.rego` shipped here is the productization seed).
- A build-and-sign step that recompiles the entity's bundle and re-signs it with
  the entity key, so `guard` picks it up on its next poll (5–15s) — no restart.
- Surfacing the **decision feed** (the hash-chained audit the guard already
  emits) back in the dashboard so a user sees what got blocked/asked and can
  tune policy from real events. (The local console below already does exactly
  this on-box; the CP just needs to do it centrally.)

This is a CP/control-plane feature (a different service than this guard repo). The
guard side is ready: it already evaluates and enforces whatever the CP signs, on
both the network path and the `/v1/govern` runtime path.

**Update (PR #28): the single-box version of this now ships in the guard itself.**
A **local governance console** (`internal/console`) serves a loopback-only
(127.0.0.1:8790), bearer-token-gated (`~/.aarvion/console-token`, 0600) dark
aarvion-styled SPA with a **live hash-chained decision feed**, a **tighten-only
overlay editor**, and a **sync-now** button. It's **on by default** after
`init`/`onboard`; `aarvion-guard dashboard` opens it pre-authed. The overlay
(`internal/overlay`, `~/.aarvion/overlay.json`) is local deny/ask rules that
**can never loosen a CP-signed decision** — evaluated only after the base OPA
decision *allowed*, matching on tool / command-substring / host-suffix / method,
and wired into **both** enforcement paths (egress proxy → deny; agent-action PDP
→ deny or ask). Edits **best-effort push to the control plane** (`internal/cpsync`)
and degrade gracefully if the CP doesn't support them. beta.aarvion.ai stays
authoritative; the local console is the single-box **quick-tighten** path, not a
replacement for the CP dashboard above.

## Path to viral (prioritized)

1. **Ship the plugin.** Publish `@aarvion/openclaw-guard` to npm (and ClawHub) so
   `openclaw plugins install @aarvion/openclaw-guard` resolves.
   (`clients/openclaw-plugin/LAUNCH-BACKLOG.md` Task 1.)
2. **Cut a guard release with the govern PDP.** Merge #28, tag `v0.3.0`, publish
   binaries — so `npx @aarvionai/guard` installs a guard that actually has the
   `/v1/govern` socket.
3. **Make onboarding one command.** `npx @aarvionai/guard run` should: install the
   guard-with-PDP, generate the socket + token, write `guard.json`, **install +
   enable the OpenClaw plugin, and set the `OPENCLAW_GUARD_*` env** — collapsing
   the 6 dev steps into one. This is the single biggest virality lever.
4. **CP-hosted, editable policies** (above) so a non-dev customizes in the
   dashboard, never touching `.rego`.
5. **The hero demo** (`LAUNCH-BACKLOG.md` Task 3): a 30–60s clip of an agent's
   `git push --force` blocked, an `ask` pausing for phone approval, and per-agent
   trust. This is the PH post.
6. **Lead with the wedge that only we can do:** "governs what your agent *does*,
   not just what it connects to — install a plugin, don't fork your agent." The
   force-push block is the shareable moment.

## What is actually done vs. pending

- **Done + proven live:** action governance across all surfaces (deny/allow),
  installable plugin on a stock OpenClaw (no fork), hash-chained audit with caller
  identity, ask verdict (guard-side coded + unit-tested; plugin returns
  `requireApproval`), and the **local governance console + tighten-only overlay**
  (loopback console, live decision feed, quick-tighten deny/ask that can't loosen
  a CP decision, best-effort CP sync) — enforced on **both** the egress and
  agent-action paths and covered by new mitm + govern unit tests. All in PR #28,
  `go build/vet/test ./... -race` green, e2e-proven live 2026-07-10 (console UI
  200, unauth API 401, authored deny → proxied request 403 with reason
  `local_overlay:...`, non-match 200, non-tightening PUT rejected 400).
- **Pending for launch:** publish the plugin (1), release the PDP-enabled guard
  (2), one-command onboarding (3), CP policy dashboard (4), demo clip (5). Items
  1, 3, 5 are captured as backlog/handoff tasks. The **CP dashboard (4)** is
  now partly de-risked: the local console proves the feed + tighten-and-sync UX
  end-to-end, so the CP side is UI/pipeline work over a shape that's already live.
- **Still-open blockers (do not mark done):** macOS codesign/notarization; npm
  publish of `@aarvionai/guard`; the openclaw-plugin needs npm publish **and** a
  real approval-socket for hard `ask` enforcement (today it's a `trustedToolPolicy`
  veto seam, not a blocking prompt).
- **Honest caveat unchanged:** tamper-proof enforcement needs the guard on a
  separate uid from the agent; same-uid governs the decision path only.
