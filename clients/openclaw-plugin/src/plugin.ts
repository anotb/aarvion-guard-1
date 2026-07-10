// Registers the Aarvion guard as an OpenClaw trusted tool policy (the PEP).
//
// This package is fully self-contained: it declares the minimal slice of the
// OpenClaw plugin host API it depends on, so it builds and loads with ZERO
// dependency on the OpenClaw source. It is installed into a stock OpenClaw with
// `openclaw plugin install` and enabled in config - OpenClaw's own code is never
// modified or rebuilt.
import { evaluateGuard } from "./guard-client.js";

// --- Minimal host API surface (structural; matches OpenClaw's plugin SDK) ---

/** The tool call OpenClaw is about to run. */
export interface ToolPolicyEvent {
	toolName?: string;
	params?: Record<string, unknown>;
}

/** Caller context OpenClaw provides for the decision. */
export interface ToolPolicyContext {
	toolName: string;
	agentId?: string;
	sessionKey?: string;
}

/** Return `{ block: true, blockReason }` to veto; return nothing to allow. */
export type ToolPolicyDecision =
	| { block?: boolean; blockReason?: string; params?: Record<string, unknown> }
	| { allow?: boolean; reason?: string }
	| void;

export interface TrustedToolPolicy {
	id: string;
	description: string;
	evaluate: (
		event: ToolPolicyEvent,
		ctx: ToolPolicyContext,
	) => ToolPolicyDecision | Promise<ToolPolicyDecision>;
}

/** The one host method this plugin uses. */
export interface GuardHostApi {
	registerTrustedToolPolicy: (policy: TrustedToolPolicy) => void;
}

// Phase 1 governs the shell/exec surface. Extend as more surfaces are mapped.
const GOVERNED_TOOLS = new Set(["exec", "bash", "shell"]);

export function registerAarvionGuardPlugin(api: GuardHostApi): void {
	api.registerTrustedToolPolicy({
		id: "aarvion-guard-exec",
		description: "Denies agent tool calls that the Aarvion guard PDP rejects (exec surface).",
		evaluate: async (event, ctx) => {
			const toolName = event.toolName ?? ctx.toolName;
			if (!GOVERNED_TOOLS.has(toolName)) return;

			const rawCommand = event.params?.command;
			const command = typeof rawCommand === "string" ? rawCommand : "";
			if (!command) return;

			const verdict = await evaluateGuard({
				command,
				toolName,
				agentId: ctx.agentId,
				sessionKey: ctx.sessionKey,
			});
			if (verdict.verdict === "deny") {
				const detail = verdict.reason ?? verdict.policyId ?? "denied";
				return { block: true, blockReason: `Aarvion guard: ${detail}` };
			}
			// No veto -> the guard allowed it; native allowlist/approvals still apply.
			return;
		},
	});
}
