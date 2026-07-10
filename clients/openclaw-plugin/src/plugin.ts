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
import { awaitApproval, evaluateGuard, resolveGuardConfig } from "./guard-client.js";

export interface ToolPolicyEvent {
	toolName?: string;
	params?: Record<string, unknown>;
}

export interface ToolPolicyContext {
	toolName: string;
	agentId?: string;
	sessionKey?: string;
}

/** A human-in-the-loop approval prompt (OpenClaw pauses the tool call for it). */
export interface ApprovalRequest {
	title: string;
	description: string;
	severity?: "info" | "warning" | "critical";
	timeoutMs?: number;
	timeoutBehavior?: "allow" | "deny";
}

export type ToolPolicyDecision =
	| { block?: boolean; blockReason?: string; params?: Record<string, unknown> }
	| { requireApproval: ApprovalRequest }
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

			const config = resolveGuardConfig();
			const verdict = await evaluateGuard(
				{
					toolName,
					params: event.params ?? {},
					agentId: ctx.agentId,
					sessionKey: ctx.sessionKey,
				},
				config,
			);
			if (verdict.verdict === "deny") {
				const detail = verdict.reason ?? verdict.policyId ?? "denied";
				return { block: true, blockReason: `Aarvion guard: ${detail}` };
			}
			if (verdict.verdict === "ask") {
				// Third verdict: a human must approve. The guard has already opened a
				// pending, notified the owner over Telegram, and surfaced it in the
				// console inbox. We poll GET /v1/approvals/{id} over the same socket
				// until the owner taps approve/deny or we hit the budget.
				if (verdict.decisionId) {
					const outcome = await awaitApproval(verdict.decisionId, config);
					if (outcome === "allow") return; // owner approved -> let the call run
					return {
						block: true,
						blockReason: `Aarvion guard: ${verdict.reason ?? "approval denied or timed out"}`,
					};
				}
				// Older guard with no decision_id: fall back to OpenClaw's native
				// approval flow. If no one responds it times out to a deny (fail-safe).
				return {
					requireApproval: {
						title: "Aarvion guard — approval required",
						description: `Aarvion guard: ${verdict.reason ?? "this action needs your approval"}`,
						severity: "warning",
						timeoutBehavior: "deny",
					},
				};
			}
			// No veto -> the guard allowed it (or the tool isn't governed); native
			// allowlist/approvals still apply.
			return;
		},
	});
}
