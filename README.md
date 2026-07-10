# aarvion-guard

Govern what your local OpenClaw agents actually **do**. A single Go binary that
turns each tool call into a typed action — *send an email via `gog`, tweet via
`bird`, DM on Telegram, delete a Drive file, hit an API* — and rules on it with
consumer-friendly **policy packs**, backed by a signed OPA policy and a
tamper-evident hash-chain. Not just which hosts the agent can reach: what it does
on them, on your behalf.

## What it governs

OpenClaw's agents act on the world through concrete CLIs and channels. The guard
sits on OpenClaw's `before_tool_call` chokepoint (via an installable plugin, no
fork), **normalizes** each raw tool call into a typed action
`{surface, verb, targets, host, flags, findings}`, and matches policy against
that — not against fragile command substrings. Surfaces it understands today:

- **Google (`gog`)** — Gmail send, Drive delete / empty-trash, Docs share,
  Calendar. *"Send vs read, delete vs list, `--force` vs not, external vs internal
  recipient."*
- **Twitter/X (`bird`)** — post, reply, DM, follow, like vs. read-only search.
- **GitHub (`gh` / `git`)** — push, force-push, repo/branch delete, workflow &
  secret edits.
- **Native comms** (`message` / `sessions_send`) — Telegram, Discord, WhatsApp,
  Reddit.
- **APIs (`web_fetch` / `curl`)** — host, HTTP verb (a `DELETE` to a prod host
  reads differently from a `GET`).
- **Infra (`docker` / `systemctl` / `launchctl` / truenas)** — destructive ops.

Every normalized action also gets a **DLP scan** of its payload: secret markers
(`ghp_`, `sk-…`, `AKIA…`, 1Password refs) and coarse PII (email, phone). So "no
secrets leaving in an outbound tweet/email/message" becomes a signal a policy can
act on. Unknown binaries normalize to `surface: unknown` — a pack can choose to
**ask** on those.

This is the point of the semantic layer: the `twitter-x` skill can *say*
"⛔ READ-ONLY — never post/reply/DM/follow", but that's prompt text enforced by
nothing. An agent that ignores it (or gets prompt-injected) posts as you. A pack
makes that instruction hard, audited, and human-approvable.

## Three verdicts

Every action resolves to one of:

- **allow** — proceeds, recorded.
- **deny** — blocked, recorded with the reason.
- **ask** — paused for your approval (see below). Timeout → **deny** (fail-safe).

## Policy packs

A **pack** is a named policy unit with a plain-English identity and a mode
(`off` / `observe` / `ask` / `enforce`), plus per-agent overrides — so "read-only
Twitter" can be `enforce` for the `llm-twitter` agent and `observe` for
everything else. Seven ship today:

| Pack | Governs | Out of the box |
|---|---|---|
| **social-guard** | `bird` / Twitter | read-only, or ask-before post/reply/DM/follow |
| **google-guard** | `gog` | ask-before email send; deny Drive delete / `--force`; deny anyone-with-link sharing |
| **comms-guard** | Telegram / Discord / WhatsApp / Reddit | recipient allowlist, quiet hours |
| **dlp-guard** | all outbound bodies | secret / PII in a send → deny or ask |
| **api-guard** | `web_fetch` / `curl` | host allowlist; deny destructive HTTP verbs (DELETE/PUT/PATCH) |
| **github-guard** | `gh` / `git` | force-push, repo/branch delete, secret set, workflow edits |
| **infra-guard** | `docker` / `systemctl` / truenas | destructive ops denied |

One pack schema, two compile targets. Locally, packs compile to **tighten-only
overlay rules** enforced in-process (they can only *add* a deny or ask, never
loosen a signed decision — the same safety invariant as the manual overlay
editor). For the fleet, the same pack emits full-strength rego + `data.json` for
the CP-signed bundle on `beta.aarvion.ai`, so a pack you tune locally is
enable-able against your live entity. Example rego lives in
[`examples/packs/`](examples/packs/).

## Learn mode — ship in observe, protect in one click

You don't have to write policy from a cold start. Packs ship in **observe**: they
evaluate but block nothing, and the guard records what each agent *actually*
does — a behaviour profile keyed by `{agent, surface, verb}` with target sets,
counts, and a time-of-day histogram.

When you've seen enough, **Protect me now** turns that profile into a proposal:
read-only agents get locked to read-only, sensitive verbs (send / post / delete /
share) become **ask**, DLP goes to **enforce**. One click compiles it to the
overlay. Observe first, then tighten to exactly what your agents needed anyway.

## Approvals — your phone or the console

An **ask** waits for a human. Two independent ways to resolve it:

- **Telegram** — with a bot token configured
  (`approve.telegram.{bot_token, chat_id}`, owner-supplied via @BotFather), the
  guard DMs you: *"Agent `llm-twitter` wants to **twitter.post**: '…'. ✅ Approve /
  ❌ Deny."* You tap a button on your phone. This path is deliberately independent
  of OpenClaw — approvals never route through the governed agent.
- **Console inbox** — the same pending item appears in the local console; approve
  or deny there.

Either resolves it; a timeout denies. Every resolution (who, how, when) is
hash-chained into the audit. Mechanically, the PDP returns `ask` fast and the
plugin polls `GET /v1/approvals/{id}` until it resolves, so a minutes-long
approval doesn't hold the govern socket open.

## Local console

The guard serves a loopback console (`127.0.0.1:8790`, gated by a per-run bearer
token at `~/.aarvion/console-token`, 0600) with three views: a **Packs board**
(toggle + mode + per-agent chips), a **Learning** panel (profile + *Protect me
now*), and an **Approvals** inbox. Open it pre-authed:

```
aarvion-guard dashboard   # opens http://127.0.0.1:8790 in your browser
```

`beta.aarvion.ai` remains the authoritative multi-fleet dashboard; this console
is for the single-box operator who wants to see and tighten *now*.

## Proven live

Verified end-to-end on a real OpenClaw box (macOS, forward / no-inspect), then
torn down clean. Same binary, real OPA + CP bundle, real `bird` / `gog` on `PATH`:

| Action | Verdict | Classified as |
|---|---|---|
| `bird tweet …` — a **real `main`-agent turn on stock OpenClaw** | **blocked**: *"Command blocked by PreToolUse hook: Aarvion guard: social_guard:write"* | `twitter.post` |
| `echo …` — real agent turn | allow, ran | `exec.run` |
| `gog drive delete … --force` | deny | `file.delete` |
| Telegram message carrying `ghp_…` | deny | `comms.send` + `secret:ghp` |
| `gog gmail send` to a stranger | ask | `email.send` + `pii:email` |
| `bird search` | allow | `twitter.read` |

The `ask` loop resolved end-to-end: a pending appeared in the console inbox with
its caller + verb, and approving it flipped the guard's `GET /v1/approvals/{id}`
from `pending` → `allow` — the exact call the plugin polls. Every decision landed
in the hash-chained audit with its semantic verb, DLP findings, and caller
identity. (Telegram approvals are unit-tested against a stubbed Bot API and wired;
the live phone-tap just needs a bot token.)

## Quickstart

```
npx @aarvionai/guard onboard <pairing-code>   # pair + PDP + plugin + wire + restart
aarvion-guard dashboard                       # open the local console
```

`onboard` claims a one-time pairing code from the Aarvion dashboard, installs the
PEP plugin into your stock OpenClaw, wires it, and starts governing. Plugin
detail and a multi-surface example policy:
[`clients/openclaw-plugin/`](clients/openclaw-plugin/). The end-to-end product
flow (signup → pair → install → govern → learn → approve) is in
[`docs/PRODUCT-FLOW.md`](docs/PRODUCT-FLOW.md).

Prefer the pieces separately:

```
npx @aarvionai/guard init <pairing-code>   # pair only; wire OpenClaw egress + PDP
# or
curl -fsSL get.aarvion.ai | sh
```

The guard self-provisions `opa` on first `run` (pinned build into
`~/.aarvion/bin`; set `AARVION_OPA_SHA256` to enforce a checksum). Releases are
cut by `.github/workflows/release.yml` on a `v*` tag (Linux ships
unconditionally; macOS signing/notarization is gated on `APPLE_*` secrets).

**Prerequisites:** an Aarvion account + pairing code (dashboard "Govern OpenClaw"
page), a local OpenClaw install, and network access on first `run` to fetch `opa`.

## Honest about what this is (and isn't)

Read this before you trust it as a boundary.

- **It proves the governance *path*, not a tamper-proof boundary — in the
  single-box deployment.** The guard and OpenClaw share a uid there, so a
  same-uid compromise could unset the plugin's env, kill the guard, or edit its
  config. Real, unbypassable enforcement needs uid separation (a service account)
  or a system extension. The action-governance work is tested (unit +
  integration) and **verified live on a real OpenClaw box** (see *Proven live*) —
  but that proves the governance path works, not that it's unbypassable on a
  shared uid; treat the local console as a strong operator control, not a sandbox
  around a hostile process.
- **The model's streamed response stays ungoverned.** The hook governs tool
  *actions* (the PEP), not the model's response stream. Tool actions are
  governed; text the model emits is not.
- **Don't call it "unbypassable."** The overlay's *tighten-only* guarantee (a
  local rule can never loosen a signed decision) is structural and holds. The
  process boundary, on a shared uid, does not — and we won't pretend otherwise.

## Also here: network egress

Before the action layer, the guard governs **network egress** — it routes
OpenClaw's egress through a local forward proxy / transparent redirect and rules
host-by-host. Useful, but blind to *intent*: host rules can't tell
`git push --force` from `git status`, and an agent's own TLS client rejects the
guard CA, so bodies stay opaque in forward mode. That's exactly the gap the action
layer fills. The forward proxy was the original **P1 / B0** milestone — proving
the full control-plane contract (pairing → bundle pull → decision → dashboard)
with zero kernel-interception risk.

### Transparent mode (P2 / B1) — Linux

`init --transparent` (Linux) sets up bypass-proof kernel interception: OpenClaw
runs in a dedicated **group**, an iptables/ip6tables `nat OUTPUT` redirect sends
that group's TCP 80/443 to the guard (loopback and the guard's own traffic
excluded, v4+v6), and the guard recovers each connection's original destination
via `SO_ORIGINAL_DST`. 443 is MITM'd with the local CA (streaming-aware, so SSE
survives); 80 is read directly. Nothing OpenClaw does — Node `fetch`, raw sockets,
`unset HTTPS_PROXY` — escapes, because the match is on identity, not env.

```
sudo aarvion-guard run                 # installs the redirect, starts OPA + guard
aarvion-guard exec -- <start OpenClaw>  # runs OpenClaw inside the governed group
```

Identity is **group-based, not uid-swap**, so OpenClaw keeps ownership of its own
`~/.openclaw` files. The redirect is always torn down on stop (fail-safe) so a
crash can't black-hole egress.

**macOS transparent is not here yet** and it is *not* a pf job: pf's `rdr` covers
forwarded traffic, not a machine's own local egress. Bypass-proof macOS needs a
`NETransparentProxyProvider` system extension (separate signed track). On macOS
today the guard runs in forward-proxy mode. Windows (WFP) is P5.

### Run on boot / self-heal (P3)

```
sudo aarvion-guard service install    # systemd (Linux) / launchd (macOS), Restart=always
aarvion-guard repair                  # unstick egress after a hard crash
```

The service keeps the guard up; on each start it clears any redirect orphaned by a
prior crash before installing fresh rules, and always tears the redirect down on
stop. `repair` is the manual escape hatch if egress ever gets stuck without
dropping the pairing.

## What works today

- `onboard <code>` — one command: pair + install the PDP + install & wire the
  OpenClaw plugin + restart, governing in one shot.
- `init <code>` — claim a one-time pairing code, store enrollment creds
  (`~/.aarvion/guard.json`, 0600), render the OPA config, wire OpenClaw's egress.
- `run` — supervise the OPA sidecar (bundle pull + HS256 verify), serve the
  forward proxy + `/v1/govern` PDP + local console, push sampled decisions +
  heartbeats to the control plane.
- `dashboard` — open the loopback console (Packs / Learning / Approvals) pre-authed.
- Semantic action normalization + 7 policy packs (observe / ask / enforce, per-agent).
- Learn-mode profile + one-click promote; Telegram + console approvals.
- Fail-closed with an essential-allow list (LLM providers) when OPA is down.
- `status`, `uninstall` (restores the OpenClaw env, keeps the CP entity).

## Not yet

macOS/Windows transparent egress, cert-pinned host passthrough (needs pre-handshake
SNI peek), body-level HTTPS in forward mode, DNS gating, field-level redaction
rewriting (verdict plumbed, not enforced), macOS notarization (needs your Apple
cert).

## Build / release

```
make build                    # local binary → dist/
make release VERSION=v0.1.0   # cross-compiled darwin/linux amd64+arm64 → dist/
go build ./cmd/guard          # requires `opa` on PATH or ~/.aarvion/bin/opa
```

macOS artifacts still need `codesign` + notarization and Windows needs Authenticode
before distribution (env-gated).

## Layout

```
cmd/guard        CLI: init / onboard / run / dashboard / exec / service / update / repair / status / uninstall / version
internal/config  guard.json state (0600)
internal/pair    /api/openclaw/pair/claim client
internal/opa     OPA config render + sidecar supervisor
internal/policy  OPA eval client (envoy/authz/allow shape)
internal/normalize  raw {tool,args} → typed SemanticAction {surface,verb,targets,host,flags,findings} + DLP scan
internal/packs   7 consumer policy packs; two compilers (tighten-only overlay + full-strength rego)
internal/govern  PDP decide: normalize → base OPA eval → overlay → verdict
internal/approve pending-approval store + Telegram approver + console inbox; GET /v1/approvals/{id}
internal/overlay tighten-only local override store (semantic facets; deny/ask only, never loosen)
internal/console loopback console: Packs board + Learning panel + Approvals inbox + decision feed (embedded SPA)
internal/sinks   decision sinks: learn behaviour profile, metrics, webhook, CP push
internal/proxy   forward proxy (CONNECT + absolute-form HTTP)
internal/cpsync  pushes local overlay + reports sync status to the control plane
internal/ca      machine-local CA + on-the-fly leaf minting
internal/intercept  kernel redirect backends (linux iptables; darwin stub) + SO_ORIGINAL_DST
internal/tproxy  transparent server: SNI-terminate, MITM (streaming) or passthrough
internal/decisions  hash-chained records + allow-sampling + push loop
internal/heartbeat  fleet heartbeat
internal/svc     boot service install (systemd / launchd)
internal/wiring  OpenClaw detect + service-env proxy injection
examples/packs   full-strength rego + data.json emitted from the packs (CP bundle)
packaging/       install.sh (curl|sh), Homebrew formula, + Makefile release targets
```
