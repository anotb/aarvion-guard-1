# aarvion-guard

Govern your local OpenClaw with Aarvion. A single Go binary that enforces a
signed OPA policy at a local checkpoint, and writes every decision to a
tamper-evident hash-chain. It governs OpenClaw **two ways**:

1. **Network egress** — routes OpenClaw's egress through a local forward proxy /
   transparent redirect and rules on it host-by-host.
2. **Agent actions** — a local **PDP** (`/v1/govern` over a Unix socket) that an
   OpenClaw plugin calls *before every tool call* to allow / deny / ask. This is
   the runtime governance hook ("Option C"): it governs what the agent **does**
   (shell, github, file writes, sends, web, MCP tools) — not just which hosts it
   talks to — **without modifying or forking OpenClaw**. See
   [`clients/openclaw-plugin/`](clients/openclaw-plugin/).

The forward proxy started as **P1 / B0** — proving the full control-plane
contract from Go (pairing → bundle pull → decision → dashboard) with **zero
kernel-interception risk**. Transparent, bypass-proof interception is **B1/P2**.
See `../OPENCLAW_GUARD_B_PLAN.md`.

## Govern agent actions — the runtime hook (Option C)

The network proxy can't see *what an agent is doing* (an agent's own TLS client
rejects the guard CA, and host-level rules can't tell `git push --force` from
`git status`). The runtime hook fixes that: OpenClaw's own `trustedToolPolicy`
seam calls the guard's PDP before each tool runs, so a policy can block a
dangerous shell command, a force-push, a secret leaving in a message, or an
egress to a bad host — and **ask** for your approval on the risky-but-maybe-fine
ones. It ships as an installable plugin (no OpenClaw source changes), backed by
the same signed OPA engine + hash-chain as the proxy. Quickstart, install, and a
multi-surface example policy: [`clients/openclaw-plugin/`](clients/openclaw-plugin/).

## What works today (B0)

- `init <code>` — claim a one-time pairing code from the Aarvion backend, store
  enrollment creds (`~/.aarvion/guard.json`, 0600), render the OPA config, and
  wire OpenClaw's egress (`HTTPS_PROXY` into its gateway service-env, backed up).
- `run` — supervise the OPA sidecar (bundle pull + HS256 verify), serve the
  forward proxy, push sampled decisions + heartbeats to the control plane.
- HTTPS governed at host level via CONNECT; plain HTTP sees full method/path.
- Fail-closed with an essential-allow list (LLM providers) when OPA is down.
- `status`, `uninstall` (restores the OpenClaw env, keeps the CP entity).

## Transparent mode (P2 / B1) — Linux

`init --transparent` (Linux) sets up bypass-proof kernel interception: OpenClaw
runs in a dedicated **group**, an iptables/ip6tables `nat OUTPUT` redirect sends
that group's TCP 80/443 to the guard (loopback and the guard's own traffic
excluded, v4+v6), and the guard recovers each connection's original destination
via `SO_ORIGINAL_DST`. 443 is MITM'd with the local CA (streaming-aware, so SSE
survives); 80 is read directly. Nothing OpenClaw does — Node `fetch`, raw
sockets, `unset HTTPS_PROXY` — escapes, because the match is on identity, not env.

```
sudo aarvion-guard run                 # installs the redirect, starts OPA + guard
aarvion-guard exec -- <start OpenClaw>  # runs OpenClaw inside the governed group
```

Identity is **group-based, not uid-swap** (locked decision §12.1), so OpenClaw
keeps ownership of its own `~/.openclaw` files. The redirect is always torn down
on stop (fail-safe) so a crash can't black-hole egress.

**macOS transparent is not here yet** and it is *not* a pf job: pf's `rdr` covers
forwarded traffic, not a machine's own local egress. Bypass-proof macOS needs a
`NETransparentProxyProvider` system extension (separate signed track). On macOS
today the guard runs in forward-proxy mode. Windows (WFP) is P5.

## Run on boot / self-heal (P3)

```
sudo aarvion-guard service install    # systemd (Linux) / launchd (macOS), Restart=always
aarvion-guard repair                  # unstick egress after a hard crash
```

The service keeps the guard up (`Restart=always` / `KeepAlive`); on each start
the guard clears any redirect orphaned by a prior crash before installing fresh
rules, and always tears the redirect down on stop. `repair` is the manual
escape hatch if egress is ever stuck without dropping the pairing.

## Build / release

```
make build                    # local binary → dist/
make release VERSION=v0.1.0   # cross-compiled darwin/linux amd64+arm64 → dist/
```

macOS artifacts still need `codesign` + notarization and Windows needs
Authenticode before distribution (env-gated; see `../OPENCLAW_GUARD_B_PLAN.md` §8).

## Install

```
npx @aarvionai/guard init <pairing-code>   # from the Aarvion dashboard
# or
curl -fsSL get.aarvion.ai | sh
```

The guard **self-provisions `opa`** on first `run` (downloads a pinned build into
`~/.aarvion/bin`; set `AARVION_OPA_SHA256` to enforce a checksum pin). Releases
are cut by `.github/workflows/release.yml` on a `v*` tag (Linux ships
unconditionally; macOS signing/notarization is gated on `APPLE_*` secrets).

## Not yet

macOS/Windows transparent, cert-pinned host passthrough (needs pre-handshake SNI
peek), body-level HTTPS in forward mode (MITM-inside-CONNECT), DNS gating,
redaction rewriting, macOS notarization (needs your Apple cert).

## Layout

```
cmd/guard        CLI: init / run / exec / service / repair / status / uninstall / version
internal/config  guard.json state (0600)
internal/pair    /api/openclaw/pair/claim client
internal/opa     OPA config render + sidecar supervisor
internal/policy  OPA eval client (envoy/authz/allow shape)
internal/proxy   forward proxy (CONNECT + absolute-form HTTP)
internal/ca      machine-local CA + on-the-fly leaf minting
internal/intercept  kernel redirect backends (linux iptables; darwin stub) + SO_ORIGINAL_DST
internal/tproxy  transparent server: SNI-terminate, MITM (streaming) or passthrough
internal/decisions  hash-chained records + allow-sampling + push loop
internal/heartbeat  fleet heartbeat
internal/svc     boot service install (systemd / launchd)
internal/wiring  OpenClaw detect + service-env proxy injection
packaging/       install.sh (curl|sh), Homebrew formula, + Makefile release targets
```

## Build

```
go build ./cmd/guard          # requires the `opa` binary on PATH or ~/.aarvion/bin/opa
```

## Prerequisites to run end-to-end

- An Aarvion account and a pairing code from the dashboard "Govern OpenClaw" page.
- A local OpenClaw install (for the wiring step).
- Network access on first `run` so the guard can fetch `opa` (or pre-place it on
  PATH / `~/.aarvion/bin/opa`).
