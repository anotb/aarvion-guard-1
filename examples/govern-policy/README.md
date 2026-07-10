# Example govern policy pack — exec surface

`exec.rego` is a starter OPA policy for the **runtime governance PDP**
(`/v1/govern` → `policy.GovernEval` → `data.envoy.authz.allow`). It decides on the
*action* the PEP sends — the literal command in `input.action.args.cmd` plus
caller identity in `input.ctx.caller` — rather than only on network shape. It
allows by default and denies a set of known-dangerous commands (destructive
filesystem ops, fork bombs, disk wipes, credential-store reads, cloud
metadata-SSRF, secret markers), returning the `x-policy-violated` /
`x-policy-reason` headers the guard decodes into a verdict.

This fills the gap noted in the runtime-governance-hook spec: the starter govern
`.rego` packs weren't in the repo. It pairs with the OpenClaw guard PEP plugin
(`extensions/aarvion-guard/` in the OpenClaw fork), which sends exec commands to
the guard before running them.

## Verifying it decides correctly (offline)

```sh
opa eval -i action.json -d exec.rego 'data.envoy.authz.allow' -f pretty
# where action.json is the unwrapped input, e.g.
#   {"action":{"args":{"cmd":"rm -rf / --no-preserve-root"}}}
```

Benign commands return `{"allowed": true, ...}`; a matched pattern returns
`{"allowed": false, "http_status": 403, "headers": {...}}`.

## Loading it into the guard's OPA

The guard renders `opa-config.yaml` to pull the **signed CP bundle**; the
production path is to publish this pack (enabled + enforce) through the control
plane so the guard's own signed pipeline serves it. For local development, point
the guard's `opa_addr` at an OPA instance you run with this policy
(`opa run --server --addr 127.0.0.1:8181 exec.rego`) — the PDP evaluates whatever
answers at `opa_addr`.

The denylist here is illustrative, not exhaustive — a real deployment authors
patterns per policy and per agent trust level.
