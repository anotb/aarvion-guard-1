# @aarvion/openclaw-guard

Governs OpenClaw agent **actions** by calling a local Aarvion guard **PDP** over a
Unix socket before a governed tool runs, and vetoing the call on a deny.

**You do not modify or rebuild OpenClaw.** This is a standalone plugin package you
install into a stock OpenClaw the same way as any other plugin, then enable in
config. It registers a `trustedToolPolicy` (OpenClaw's sanctioned tool-veto seam)
and depends on nothing from the OpenClaw source — only Node built-ins.

## What happens at runtime

1. An agent calls a governed tool (`exec` / `bash` / `shell`).
2. Before dispatch, OpenClaw asks every enabled trusted tool policy to `evaluate`
   the call. This plugin's policy sends the command + caller identity (agentId,
   sessionKey) to the guard at `POST /v1/govern` over its Unix socket (bearer
   token + kernel peer-uid auth + a fresh nonce).
3. The guard evaluates OPA and returns `allow` or `deny`. On `deny`, the policy
   returns `{ block: true, blockReason }`; OpenClaw refuses the call and the
   process never spawns.
4. Every decision is written to the guard's hash-chained audit with the caller
   identity and `origin=runtime`.

## Install (no OpenClaw changes)

```sh
# build the package
npm install && npm run build

# install into your stock OpenClaw (published, or from this local path)
openclaw plugin install @aarvion/openclaw-guard
# or, during development:
openclaw plugin install ./clients/openclaw-plugin
```

Enable it and point it at the guard, in your OpenClaw config:

```jsonc
{
  "plugins": {
    "entries": {
      // explicit enable is REQUIRED for a plugin to register a trusted tool
      // policy - you consciously trust the governor.
      "aarvion-guard": { "enabled": true }
    }
  }
}
```

Set the guard connection via the OpenClaw process environment (e.g. its
`service-env`):

```
OPENCLAW_GUARD_ENABLED=1
OPENCLAW_GUARD_SOCKET=/Users/you/.aarvion/govern.sock
OPENCLAW_GUARD_TOKEN=<the guard.json govern.socket.token>
OPENCLAW_GUARD_FAIL_MODE=closed   # deny when the guard is unreachable (recommended)
```

On the guard side, enable the PDP in `~/.aarvion/guard.json`:

```json
{
  "govern": {
    "socket": { "path": "/Users/you/.aarvion/govern.sock", "token": "<random-secret>", "peer_uid": 501 },
    "fail_mode": { "exec": "closed", "tool": "closed" }
  }
}
```

`peer_uid` is the uid the OpenClaw process runs as (`id -u`). Disabled (no
`OPENCLAW_GUARD_ENABLED`) the plugin is a no-op and behavior is unchanged.

An example govern policy for the exec surface is in
[`examples/govern-policy/exec.rego`](../../examples/govern-policy/exec.rego).

## Security precondition (read this)

The guard's guarantees hold only when the **guard and the agent run as different
uids**. On a single-user host they share a uid, so this governs the *decision
path* but is **not** a tamper-proof boundary: a same-uid agent could unset the
env, kill the guard, or edit its config. For real enforcement, run the guard as a
separate service account (Linux) or under a system extension. This is a
precondition of the design, not a limitation of the plugin.

## Scope

Phase 1 governs the shell/exec surface (`GOVERNED_TOOLS`). Extend that set as more
surfaces (sends, MCP tools, homelab actions) are mapped. `e2e.ts` is a standalone
proof against a running guard.
