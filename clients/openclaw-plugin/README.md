# @aarvion/openclaw-guard

**Governance for your AI agent — install a plugin, don't fork your agent runtime.**

Aarvion Guard gives an [OpenClaw](https://openclaw.ai) agent a policy brain for its
**actions**. Before the agent runs *any* tool — a shell command, a file write, a
tweet, a Gmail send, a message it sends as you, a web request, an external MCP
tool — the guard classifies what the call actually *does* and decides:
**allow**, **deny**, or **ask** (pause for a human). Decisions are made by a
local, signed OPA policy engine plus a set of consumer **policy packs**, and
written to a tamper-evident hash-chained audit tagged with which agent and
session made the call.

You install it into a **stock OpenClaw** like any other plugin and enable it in
config. It changes **zero lines** of OpenClaw source and needs no rebuild — it
registers a `trustedToolPolicy` (OpenClaw's own tool-veto seam) and depends on
nothing but Node built-ins.

```
   OpenClaw agent          this plugin (PEP)              aarvion-guard (PDP)
  ┌──────────────┐  tool   ┌───────────────┐  /v1/govern  ┌──────────────────┐
  │ wants to run │ ──────► │ trustedTool   │ ───────────► │ normalize → OPA + │
  │ a tool call  │         │ Policy.eval() │   UDS + auth  │ packs + hash-chain│
  └──────────────┘ ◄────── └───────────────┘ ◄─────────── └──────────────────┘
       runs / blocked /      allow · deny · ask              signed policy,
       waits-for-approval                                    audited decision
```

## What it governs

The policy fires for **every** tool the agent calls. Guard-side, each raw call is
run through a **semantic normalizer** that turns `{tool, args}` into a typed
action — `{surface, verb, targets, host, flags, findings}` — so policy is written
against *intent* (send vs read, delete vs list, external vs internal recipient),
not brittle substring matches on a command line. That means you govern the whole
action surface, and you govern it by what it means:

| Surface | Tools it recognises | Example policy |
|---|---|---|
| Shell / exec | `exec`, `bash` | block `rm -rf /`, fork bombs, disk wipes |
| **Twitter / X** | `bird` (post/reply/dm/follow/like) | keep the "read-only" agent actually read-only |
| **Google** | `gog` (Gmail send, Drive delete, Docs share, Calendar) | ask before send; deny Drive `--force` delete; deny anyone-with-link sharing |
| **GitHub** | `git`, `gh` | block force-push, repo/branch delete, `.github/workflows` edits |
| Comms / act-as-you | `message`, `sessions_send` → Telegram/Discord/WhatsApp/Reddit | recipient allowlist, quiet hours |
| Web egress / API | `web_fetch`, `curl` | ask on non-allowlisted hosts; deny destructive verbs (DELETE/PUT/PATCH) |
| Infra | `docker`, `systemctl`, `launchctl` | block destructive ops |
| Secret / PII exfil | *(any surface)* | block a `ghp_…`/`sk-ant-…`/`AKIA…` token or PII in any outbound body |
| External tools | any MCP `<server>__<tool>` | governed the same way, per-tool policy |

Unknown binaries fall through to a `unknown` surface — a pack can choose to *ask*
on those rather than wave them through.

`OPENCLAW_GUARD_TOOLS` picks the set the plugin forwards: `actions` (default —
everything except read-only tools like `read`/`grep`/`ls`/`web_search`), `all`,
or `exec`.

## Policy packs

You don't hand-write rego to use this. The guard ships **seven consumer packs**,
each a named per-surface guardrail with a mode of `off | observe | ask | enforce`
and optional per-agent overrides:

- **social-guard** (`bird`) — read-only enforce, or ask-before post/reply/DM/follow.
- **google-guard** (`gog`) — ask before Gmail send; deny Drive delete / `--force`; deny anyone-with-link sharing.
- **comms-guard** — recipient allowlist, quiet hours (Telegram / Discord / WhatsApp / Reddit).
- **dlp-guard** — secret markers + PII in any outbound body → deny or ask.
- **api-guard** (`web_fetch`/`curl`) — host allowlist; deny destructive HTTP verbs (DELETE/PUT/PATCH).
- **github-guard** (`git`/`gh`) — force-push, repo/branch delete, workflow/secret edits.
- **infra-guard** (`docker`/`systemctl`/`launchctl`) — destructive ops deny.

Every pack ships in **observe** mode. First run is a **learn** posture: the guard
records what each agent actually does and what enforcement *would* have done,
blocking nothing. When you're ready, one click (**Protect me now** in the console)
promotes a proposal — read-only agents locked, sensitive verbs → ask, DLP always
enforce — into real enforcement. The packs are edited from the local console; the
same pack schema also compiles to full-strength signed rego for the cloud bundle
on beta.aarvion.ai.

## Three verdicts

- **allow** → the call proceeds.
- **deny** → OpenClaw refuses the call; the process / action never runs.
- **ask** → a human must approve before the call runs. This is where the plugin
  now does more than the old native timeout (see below).

## The `ask` path — approve from your phone

When the guard returns **ask**, it has already opened a **pending approval**,
DM'd the owner over **Telegram** (Approve / Deny buttons), and surfaced the same
item in the console **Approvals inbox**. The plugin then **polls the guard**
(`GET /v1/approvals/{id}` over the same socket) until the owner resolves it:

- owner taps **Approve** (Telegram) or approves in the console → the call runs;
- owner taps **Deny**, or the budget elapses with no answer → the call is blocked.

So approval happens **out-of-band**, over a channel the governed agent doesn't
control — not by holding the tool call open on a native timer, and not routed
through the agent being governed. A no-answer **times out to a deny**
(fail-safe), so a risky action is never quietly allowed. If it's ever pointed at
an older guard that doesn't return a `decision_id`, the plugin falls back to
OpenClaw's native `requireApproval` prompt, which also times out to deny.

## Install (no OpenClaw changes)

```sh
# build the package
npm install && npm run build

# install into your stock OpenClaw (published, or from a local path)
openclaw plugins install @aarvion/openclaw-guard
# during development, link a local checkout:
openclaw plugins install ./clients/openclaw-plugin --link

# explicitly enable it (required to register a governing policy — you consciously
# trust the governor):
openclaw plugins enable aarvion-guard
```

Point the plugin at the guard via the OpenClaw process environment (e.g. its
`service-env`):

```sh
OPENCLAW_GUARD_ENABLED=1
OPENCLAW_GUARD_SOCKET=/Users/you/.aarvion/govern.sock
OPENCLAW_GUARD_TOKEN=<the guard.json govern.socket.token>
OPENCLAW_GUARD_FAIL_MODE=closed   # deny when the guard is unreachable (recommended)
OPENCLAW_GUARD_TOOLS=actions      # actions (default) | all | exec

# ask-verdict polling (optional; sensible defaults shown):
OPENCLAW_GUARD_APPROVAL_TIMEOUT_MS=90000   # total window to wait for a human
OPENCLAW_GUARD_APPROVAL_POLL_MS=2000       # re-poll cadence while pending
OPENCLAW_GUARD_TIMEOUT_MS=2000             # per-request socket timeout
```

On the guard side, enable the PDP in `~/.aarvion/guard.json`:

```json
{
  "govern": {
    "socket": { "path": "/Users/you/.aarvion/govern.sock", "token": "<random-secret>", "peer_uid": 501 },
    "fail_mode": { "exec": "closed", "tool": "closed", "egress": "closed", "send": "closed", "mcp": "closed" }
  }
}
```

`peer_uid` is the uid the OpenClaw process runs as (`id -u`). Disabled (no
`OPENCLAW_GUARD_ENABLED`, or a missing socket/token) the plugin is a no-op —
behavior is unchanged.

To route `ask` approvals to Telegram, give the guard a bot token + chat id (via
`~/.aarvion`, owner-supplied from @BotFather). Until then the console
**Approvals inbox** is the working approval path.

Open the local console — Packs board, Learning panel, Approvals inbox — with:

```sh
aarvion-guard dashboard   # opens 127.0.0.1:8790, token-gated, pre-authed
```

A multi-surface example policy (dangerous-exec, GitHub, egress, secret-exfil, and
an `ask` path) is in [`examples/govern.rego`](./examples/govern.rego).

## Security precondition (read this)

The guard's guarantees hold only when the **guard and the agent run as different
uids**. On a single-user host they share a uid, so this governs the *decision
path* but is **not** a tamper-proof boundary: a same-uid agent could unset the
env, kill the guard, or edit its config. For real enforcement, run the guard as a
separate service account (Linux) or under a system extension. This is a
precondition of the design, not a limitation of the plugin — don't read it as
"unbypassable".

One more honest scope line: the guard governs tool **actions**, not the model's
streamed response. The runtime hook sits at OpenClaw's `before_tool_call`
chokepoint; the model's own output stream is out of scope.

## Design

Self-contained: the package declares its own minimal slice of the OpenClaw host
API, so it builds and loads with **zero `openclaw` imports** — only Node
built-ins. `e2e.ts` is a standalone proof against a running guard. The semantic
normalizer, decision hash-chain, policy packs, and OPA engine all live guard-side
(so the plugin can't lie its way past semantic policy, modulo the same-uid
caveat), and are the same components the network egress proxy uses — both
governance paths evaluate one signed policy and write one audit trail. This is
designed and tested (unit + integration); a separate live proof on the mini adds
real-agent evidence.
