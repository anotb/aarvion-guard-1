# Aarvion govern policy pack: exec surface.
#
# Evaluated by the guard's PDP (/v1/govern -> policy.GovernEval -> OPA at
# data.envoy.authz.allow), the SAME entrypoint the egress proxy uses. The govern
# PEP (OpenClaw's exec dispatch) sends the literal command in input.action.args.cmd
# plus caller identity in input.ctx.caller, so this pack decides on the actual
# action about to run - not just its network shape.
#
# Verdict contract (decoded by internal/policy.eval):
#   allow -> {"allowed": true,  "http_status": 200}
#   deny  -> {"allowed": false, "http_status": 403,
#             "headers": {"x-policy-violated": <id>, "x-policy-reason": <text>}}
package envoy.authz

import rego.v1

# Default posture: allow. A personal-agent operator starts permissive on exec and
# denies the known-dangerous, rather than default-deny (which would break the
# agent's normal shell use). Tighten per deployment.
default allow := {"allowed": true, "http_status": 200}

# The command the PEP is asking to run, lowercased for matching. object.get keeps
# this robust when a non-exec surface omits action.args.cmd.
cmd := lower(object.get(input, ["action", "args", "cmd"], ""))

# Dangerous substrings. Illustrative, not exhaustive: destructive filesystem ops,
# fork bombs, disk wipes, credential-store reads, cloud metadata SSRF, and a
# couple of secret-exfil markers. A real deployment authors these per policy pack.
denylist := [
	"rm -rf /",
	"rm -rf /*",
	":(){",           # fork bomb
	"mkfs",
	"dd if=/dev",
	"/etc/shadow",
	"169.254.169.254", # cloud instance-metadata SSRF
	"sk-ant-",         # anthropic key leaking into an argv
	"aws_secret_access_key",
]

# Every denylist pattern present in the command.
hits contains p if {
	some p in denylist
	contains(cmd, p)
}

# Deny when any dangerous pattern matched. Single conditional value + the default
# above means exactly one of them applies, so there is no rule conflict.
allow := {
	"allowed": false,
	"http_status": 403,
	"headers": {
		"x-policy-violated": "govern.exec.dangerous_command.v1",
		"x-policy-reason": sprintf("blocked dangerous command (matched: %s)", [concat(", ", sort(hits))]),
	},
} if {
	count(hits) > 0
}
