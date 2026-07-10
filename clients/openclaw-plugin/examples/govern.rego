# Aarvion govern policy pack: multi-surface.
#
# Evaluated by the guard PDP (/v1/govern -> data.envoy.authz.allow) for EVERY
# governed OpenClaw tool call. The PEP plugin sends:
#   input.action.tool            the tool name (exec, web_fetch, message, or an
#                                external MCP tool "<server>__<tool>")
#   input.action.args.cmd        the literal shell command (shell tools only)
#   input.attributes.request.http.host   the egress host for URL-bearing tools
#   input.attributes.request.http.body   a scannable summary (command / url / text)
#   input.ctx.caller             agent/session identity
#
# Allow by default; deny known-dangerous actions across shell, github, egress and
# secret-exfil surfaces. Illustrative denylists - a real deployment tailors these
# per policy pack and per agent trust level.
package envoy.authz

import rego.v1

default allow := {"allowed": true, "http_status": 200}

tool := lower(object.get(input, ["action", "tool"], ""))
cmd := lower(object.get(input, ["action", "args", "cmd"], ""))
host := lower(object.get(input, ["attributes", "request", "http", "host"], ""))
body := lower(object.get(input, ["attributes", "request", "http", "body"], ""))

exec_denylist := ["rm -rf /", "rm -rf /*", ":(){", "mkfs", "dd if=/dev", "/etc/shadow", "aarvion_block_demo"]
secret_markers := ["ghp_", "github_pat_", "ghs_", "sk-ant-", "aws_secret_access_key", "akia"]
blocked_hosts := ["169.254.169.254", "metadata.google.internal", "aarvion-blocked.example"]

# Destructive infra commands. Illustrative; a real pack tailors these.
infra_denylist := [
	"docker rm -f", "docker system prune", "docker volume rm",
	"systemctl stop", "systemctl disable", "launchctl unload",
	"kill -9 1", "shutdown", "reboot", "halt",
]

# --- per-agent trust: caller identity flows in from the PEP, so a policy can give
# different agents different powers. Illustrative allow-set; a real deployment
# sources this from config/data (per-agent capability tiers). ---
principal := lower(object.get(input, ["ctx", "caller", "principal_id"], ""))

trusted_write_agents := {"main", "ops"}

# --- violations (a set of {id, text}) ---

violations contains v if {
	some p in exec_denylist
	contains(cmd, p)
	v := {"id": "govern.exec.dangerous_command.v1", "text": sprintf("dangerous command (%s)", [p])}
}

# Destructive infra ops.
violations contains v if {
	some p in infra_denylist
	contains(cmd, p)
	v := {"id": "govern.infra.destructive.v1", "text": sprintf("destructive infra op (%s)", [p])}
}

# Per-agent trust: an agent not in the trusted-write set cannot push to git at all
# (a stricter gate than the universal force-push rule, which applies to everyone).
violations contains v if {
	not trusted_write_agents[principal]
	regex.match(`\bgit\b`, cmd)
	contains(cmd, "push")
	v := {
		"id": "govern.trust.untrusted_git_write.v1",
		"text": sprintf("agent %q is not trusted to push to git", [principal]),
	}
}

# GitHub: force-push
violations contains v if {
	contains(cmd, "push")
	regex.match(`\bgit\b`, cmd)
	some f in ["--force", "--force-with-lease", "-f "]
	contains(cmd, f)
	v := {"id": "govern.github.force_push.v1", "text": "git force-push"}
}

# GitHub: repo/branch delete (gh CLI or raw API)
violations contains v if {
	regex.match(`gh\s+repo\s+delete`, cmd)
	v := {"id": "govern.github.repo_delete.v1", "text": "gh repo delete"}
}

violations contains v if {
	contains(cmd, "api.github.com/repos/")
	regex.match(`(-x|--request)\s+delete`, cmd)
	v := {"id": "govern.github.repo_delete.v1", "text": "github repo delete via api"}
}

# GitHub: CI/workflow or secret changes
violations contains v if {
	contains(cmd, ".github/workflows")
	v := {"id": "govern.github.workflow_edit.v1", "text": "edit to .github/workflows"}
}

violations contains v if {
	regex.match(`gh\s+(secret|variable)\s+set`, cmd)
	v := {"id": "govern.github.secret_set.v1", "text": "gh secret/variable set"}
}

# Secret exfil: a credential-looking token in the command OR any action body
violations contains v if {
	some p in secret_markers
	contains(cmd, p)
	v := {"id": "govern.secret.token_in_argv.v1", "text": "secret token in command"}
}

violations contains v if {
	some p in secret_markers
	contains(body, p)
	v := {"id": "govern.secret.token_in_action.v1", "text": "secret token in action payload"}
}

# Web egress (any URL-bearing tool, incl. web_fetch and MCP) to a blocked host
violations contains v if {
	some h in blocked_hosts
	contains(host, h)
	v := {"id": "govern.egress.blocked_host.v1", "text": sprintf("blocked egress host (%s)", [h])}
}

# --- ask: actions that need human-in-the-loop owner approval (not an outright
# deny). The PEP turns an "ask" verdict into a pause-for-approval. ---

ask_reasons contains r if {
	contains(cmd, "aarvion_ask_demo")
	r := "demo approval marker"
}

# Example realistic gate: a normal (non-force) push to a protected repo needs a
# human ok, while a force-push is a hard deny above.
ask_reasons contains r if {
	contains(cmd, "git push")
	not contains(cmd, "--force")
	contains(cmd, "protected-repo")
	r := "push to a protected repo"
}

# Per-agent trust: an agent not in the trusted-write set may not send messages
# "as you" without approval (a compromised or lower-trust agent shouldn't quietly
# DM your contacts).
ask_reasons contains r if {
	not trusted_write_agents[principal]
	tool in {"message", "sessions_send"}
	r := sprintf("agent %q sending as you needs approval", [principal])
}

# --- decision: deny (hard) > ask (approval) > allow (default) ---

allow := decision if {
	count(violations) > 0
	ids := sort([v.id | some v in violations])
	texts := sort([v.text | some v in violations])
	decision := {
		"allowed": false,
		"http_status": 403,
		"headers": {
			"x-policy-violated": concat(",", ids),
			"x-policy-reason": sprintf("blocked: %s", [concat("; ", texts)]),
		},
	}
}

allow := decision if {
	count(violations) == 0
	count(ask_reasons) > 0
	decision := {
		"allowed": false,
		"http_status": 202,
		"headers": {
			"x-aarvion-verdict": "ask",
			"x-policy-violated": "govern.ask.approval_required.v1",
			"x-policy-reason": sprintf("approval required: %s", [concat("; ", sort(ask_reasons))]),
		},
	}
}
