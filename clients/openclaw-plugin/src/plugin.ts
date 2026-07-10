// Registers the Aarvion guard as an OpenClaw trusted tool policy (the PEP).
//
// The policy fires before EVERY tool call OpenClaw makes - shell, file writes,
// comms/sends, web egress, and external MCP server tools - and asks the local
// guard PDP whether to allow it. On a deny the call is vetoed and the process /
// action never runs. Which tools are actually sent to the guard is controlled by
// the guard client (OPENCLAW_GUARD_TOOLS: actions|all|exec, default "actions").
//
// Self-contained: declares the minimal slice of the OpenClaw host API it uses, so
// it builds and loads with ZERO dependency on the OpenClaw source.
import { evaluateGuard } from "./guard-client.js";

export interface ToolPolicyEvent {
	toolName?: string;
	params?: Record<string, unknown>;
}

export interface ToolPolicyContext {
	toolName: string;
	agentId?: string;
	sessionKey?: string;
}

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

export interface GuardHostApi {
	registerTrustedToolPolicy: (policy: TrustedToolPolicy) => void;
}

export function registerAarvionGuardPlugin(api: GuardHostApi): void {
	api.registerTrustedToolPolicy({
		id: "aarvion-guard",
		description: "Governs agent tool calls (shell, files, comms, egress, MCP) via the Aarvion guard PDP.",
		evaluate: async (event, ctx) => {
			const toolName = event.toolName ?? ctx.toolName;
			if (!toolName) return;

			const verdict = await evaluateGuard({
				toolName,
				params: event.params ?? {},
				agentId: ctx.agentId,
				sessionKey: ctx.sessionKey,
			});
			if (verdict.verdict === "deny") {
				const detail = verdict.reason ?? verdict.policyId ?? "denied";
				return { block: true, blockReason: `Aarvion guard: ${detail}` };
			}
			// No veto -> the guard allowed it (or the tool isn't governed); native
			// allowlist/approvals still apply.
			return;
		},
	});
}
