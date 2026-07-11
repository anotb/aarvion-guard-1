# Governing the OpenClaw plugin from beta.aarvion.ai (control plane)

How the guard's runtime plugin governance connects to the Aarvion control plane
(`cp-beta.aarvion.ai`, repo `Aarvion-AI/aarvion-governance-server`), so a policy
authored in the cloud dashboard governs what your OpenClaw agents *do* — not just
what they reach on the network.

## The three governance layers (they are complementary)

1. **CP egress starter packs** — `cp/cp-api/starter/*.rego` (github, gworkspace,
   slack, whatsapp, discord, reddit, email, telegram, aws, stripe, ...). These
   match the *egress* HTTP shape (`input.attributes.request.http.{host,path,method}`),
   e.g. Reddit write = `POST oauth.reddit.com/api/submit`. They fire when the
   guard inspects egress (MITM/transparent). In no-inspect mode, egress paths are
   opaque, so these do not fire.
2. **CP rule-builder (`mcp_*` conditions)** — the dashboard's "New rule" builder.
   Its conditions compile (via `cp/cp-api/rego_gen.py`) to the **mcp-norm/v1**
   input shape:
   - `mcp_tool` → `input.mcp.tool.name`
   - `mcp_side_effects` → `input.mcp.tool.side_effects` (`reversible` |
     `irreversible` | `potentially_irreversible`)
   - `mcp_method` → `input.mcp.jsonrpc_method`
   - `mcp_caller_source` → `input.mcp.caller.source` (`verified` | `self_asserted`
     | `unattributed`)
   - `mcp_surface` → `input.mcp.surface` (the const `"mcp"`)
3. **The guard's runtime plugin** — governs the OpenClaw *tool action* at the PDP
   *before* egress, sending `input.action.semantic.{surface,verb,flags,findings}`.
   Works in no-inspect mode; understands `bird tweet` as `twitter.post`.

## The gap, and the fix

The guard's PDP historically sent only `input.action.*` + `input.attributes.*`.
The CP rule-builder's `mcp_*` conditions read `input.mcp.*` — which the guard did
not emit — so a cloud-authored rule could not fire on the plugin's tool actions.

**Fix (guard-side, this repo):** `internal/govern` now also emits the
**mcp-norm/v1** block on every PDP request (`Server.mcpInput`, wired into
`buildInput`; `input.mcp` added to `policy.GovernInput`). It maps the normalized
semantic action into the CP's contract:

| mcp-norm/v1 field | source |
|---|---|
| `mcp.surface` | `"mcp"` (const, per contract) |
| `mcp.entity_id` | the guard's paired entity |
| `mcp.jsonrpc_method` | `action.operation` (else `tools/call`) |
| `mcp.tool.name` | the CLI binary (`bird`/`gog`/`gh`) else the tool name (`Bash`) |
| `mcp.tool.side_effects` | verb → `reversible` (read) / `irreversible` (post/send/delete/...) / `potentially_irreversible` |
| `mcp.caller.source` | `self_asserted` when a principal is present, else `unattributed` |
| `mcp.arguments` | the tool args |
| `mcp.openclaw.{surface,verb}` | **extension** — the exact semantic surface/verb, for a future verb-granular CP contract |

Now a CP rule-builder policy governs the plugin's actions. Example — block the
`bird` CLI from irreversible writes for one agent:

```
WHEN ALL MATCH:
  mcp_tool          eq   bird
  mcp_side_effects  in   [irreversible, potentially_irreversible]
  mcp_caller_source eq   self_asserted
THEN: deny
```

## Honest limitation

`mcp_surface` is the const `"mcp"` in mcp-norm/v1, so you cannot yet write
`mcp_surface eq twitter` — surface/verb granularity comes from `mcp.tool.name` +
`mcp.tool.side_effects` (coarser than the guard's local packs, which match
`surface=twitter, verb=post`). For verb-granular cloud rules, the CP would add an
OpenClaw-action contract + subject family (e.g. `action_surface`/`action_verb`
reading `input.mcp.openclaw.*`, which the guard already emits). That is a
control-plane change (`Aarvion-AI/aarvion-governance-server`:
`cp/cp-api/rules_schema.py` + `rego_gen.py`), tracked as a follow-up.

## Creating policies via the API

The CP is reachable at `https://api-beta.aarvion.ai` (BFF `aarvion-service-backend`
forwards `/api/gov/policies*` to `cp/cp-api` with a service token). Public routes:

- `POST /api/gov/policies` — `{ "name": "...", "agentId": "<entity>" }`
- `POST /api/gov/policies/{name}/rules` —
  ```jsonc
  {
    "name": "no-bird-writes", "policy_id": "no-bird-writes",
    "action": "deny", "reason": "social write-guard",
    "match": { "all": [
      { "subject": "mcp_tool", "op": "eq", "value": "bird" },
      { "subject": "mcp_side_effects", "op": "in", "value": ["irreversible","potentially_irreversible"] }
    ], "any": [] }
  }
  ```
- `PUT /api/gov/policies/{name}/default` — `{ "default": "allow" }` (tighten-only:
  default allow + specific denies, so nothing else breaks)

Per-rule verdict is `allow`/`deny` only; `ask` and observe/enforce mode are
pack/overlay concepts, not per-rule fields.

**Auth:** these calls need a credential. Do NOT reuse a browser session token
(that's credential harvesting). Use either the dashboard UI (which carries its own
auth) or a purpose-minted **dev-key** (`POST /api/v1/agents/{tenant}/{agentId}/dev-keys`),
then `Authorization: Bearer <dev-key>`. Label policies clearly (e.g. prefix
`aarvion-plugin-`) so they are easy to find and remove.

## End-to-end verification (recommended before trusting cloud rules)

Because the `subject → input path` compiler lives in the CP (remote), verify once
that a cloud rule actually reaches the guard: create the `no-bird-writes` policy
for your entity, let the guard pull the re-signed bundle, then drive a `bird tweet`
through the PDP and confirm the base OPA denies it (not just the local overlay).
