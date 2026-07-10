# @aarvion/openclaw-guard

**Governance for your AI agent — install a plugin, don't fork your agent runtime.**

Aarvion Guard gives an [OpenClaw](https://openclaw.ai) agent a policy brain for its
**actions**. Before the agent runs *any* tool — a shell command, a file write, a
message it sends as you, a web request, an external MCP tool — the guard decides:
**allow**, **deny**, or **ask** (pause for your approval). Decisions are made by a
local, signed OPA policy engine and written to a tamper-evident hash-chained
audit, tagged with which agent and session made the call.

You install it into a **stock OpenClaw** like any other plugin and enable it in
config. It changes **zero lines** of OpenClaw source and needs no rebuild — it
registers a `trustedToolPolicy` (OpenClaw's own tool-veto seam) and depends on
nothing but Node built-ins.

```
   OpenClaw agent          this plugin (PEP)              aarvion-guard (PDP)
  ┌──────────────┐  tool   ┌───────────────┐  /v1/govern  ┌──────────────────┐
  │ wants to run │ ──────► │ trustedTool   │ ───────────► │ OPA policy + fail │
  │ a tool call  │         │ Policy.eval() │   UDS + auth  │ mode + hash-chain │
  └──────────────┘ ◄────── └───────────────┘ ◄─────────── └──────────────────┘
       runs / blocked /      allow · deny · ask              signed policy,
       pauses-for-approval                                   audited decision
```

## What it governs

The policy fires for **every** tool the agent calls, so you govern the whole
action surface, not just shell:

| Surface | Tools | Example policy |
|---|---|---|
| Shell / exec | `exec`, `bash` | block `rm -rf /`, fork bombs, disk wipes |
| **GitHub** (shell) | `git`, `gh`, `curl` | block force-push, repo/branch delete, `.github/workflows` edits |
| Web egress | `web_fetch` | block SSRF / non-allowlisted hosts |
| Comms / act-as-you | `message`, `sessions_send` | block sends containing secrets; approve external recipients |
| Filesystem | `write`, `edit`, `apply_patch` | gate writes to protected paths |
| Secret exfil | *(any surface)* | block a `ghp_…`/`AKIA…` token in a command or payload |
| External tools | any MCP `<server>__<tool>` | governed the same way, per-tool policy |

`OPENCLAW_GUARD_TOOLS` picks the set: `actions` (default — everything except
read-only tools like `read`/`grep`/`ls`/`web_search`), `all`, or `exec`.

## Three verdicts

- **allow** → the call proceeds.
- **deny** → OpenClaw refuses the call; the process/action never runs.
- **ask** → OpenClaw *pauses for your approval* (its native approval flow). No
  answer times out to a deny, so a risky action is never quietly allowed.

## Proven live

On a stock OpenClaw, with real agent turns, the guard:

- blocked `git push --force` → *"Aarvion guard: blocked: git force-push"*
- blocked a `web_fetch` to a policy-blocked host (a non-shell surface)
- allowed benign commands
- recorded every decision in the hash-chain with the agent's session id

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
`OPENCLAW_GUARD_ENABLED`) the plugin is a no-op — behavior is unchanged.

A multi-surface example policy (dangerous-exec, GitHub, egress, secret-exfil, and
an `ask` path) is in [`examples/govern.rego`](./examples/govern.rego).

## Security precondition (read this)

The guard's guarantees hold only when the **guard and the agent run as different
uids**. On a single-user host they share a uid, so this governs the *decision
path* but is **not** a tamper-proof boundary: a same-uid agent could unset the
env, kill the guard, or edit its config. For real enforcement, run the guard as a
separate service account (Linux) or under a system extension. This is a
precondition of the design, not a limitation of the plugin.

## Design

Self-contained: the package declares its own minimal slice of the OpenClaw host
API, so it builds and loads with **zero `openclaw` imports** — only Node
built-ins. `e2e.ts` is a standalone proof against a running guard. The guard-side
PDP, decision hash-chain, and OPA policy engine are the same ones the network
egress proxy uses, so both governance paths evaluate one signed policy and write
one audit trail.
