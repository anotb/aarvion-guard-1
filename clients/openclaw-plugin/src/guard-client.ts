// Aarvion guard client: asks the local guard PDP (/v1/govern over a Unix socket)
// whether a tool ACTION is allowed. Governs ANY OpenClaw tool call - shell, file
// writes, comms/sends, web egress, and external MCP server tools - not just exec.
// HTTP/1.1 over the socket; two auth factors (bearer token + kernel peer uid) plus
// a fresh nonce per request. Never throws; fail-mode on any transport failure.
import { randomBytes } from "node:crypto";
import { request as httpRequest } from "node:http";

export type GuardFailMode = "closed" | "open";

/** Which tools the plugin sends to the guard. */
export type GovernMode = "actions" | "all" | "exec";

export interface GuardConfig {
	enabled: boolean;
	socketPath: string | null;
	token: string | null;
	failMode: GuardFailMode;
	timeoutMs: number;
	governMode: GovernMode;
}

export interface GuardVerdict {
	verdict: "allow" | "deny";
	reason?: string;
	policyId?: string;
	decisionId?: string;
	failMode?: boolean;
}

export interface GuardActionInput {
	toolName: string;
	params: Record<string, unknown>;
	agentId?: string;
	sessionKey?: string;
}

const DEFAULT_TIMEOUT_MS = 2_000;
const MAX_FIELD_BYTES = 16_384; // bound any single string so we never trip the guard's 1MiB cap

// Shell/command-runner tools whose payload is a literal command string.
const SHELL_TOOLS = new Set(["exec", "bash", "shell", "sh", "command"]);

// Read-only / meta tools that neither mutate, egress, nor act as the user. Exempt
// by default (governMode "actions") to keep latency off pure reads. "all" governs
// them too; "exec" governs only shell tools.
const READONLY_TOOLS = new Set([
	"read", "grep", "find", "ls", "web_search", "tool_search", "tool_describe",
	"tool_search_code", "tool_call", "get_goal", "sessions_list", "sessions_history",
	"session_status", "agents_list", "update_plan", "pdf", "transcripts", "heartbeat_respond",
]);

// An external MCP-server tool surfaces as "<server>__<tool>".
function isMcpTool(toolName: string): boolean {
	return toolName.includes("__");
}

/** Does this tool get sent to the guard under the current mode? */
export function shouldGovern(toolName: string, mode: GovernMode): boolean {
	if (mode === "all") return true;
	if (mode === "exec") return SHELL_TOOLS.has(toolName);
	// "actions": everything that could mutate/egress/act - i.e. not a known read-only
	// tool. All MCP tools are governed (they're external, high-value).
	return isMcpTool(toolName) || !READONLY_TOOLS.has(toolName);
}

/** Coarse surface tag so the guard's per-surface fail_mode applies correctly. */
function surfaceFor(toolName: string): string {
	if (SHELL_TOOLS.has(toolName)) return "exec";
	if (isMcpTool(toolName)) return "mcp";
	if (toolName === "web_fetch") return "egress";
	if (toolName === "message" || toolName === "sessions_send" || toolName === "nodes") return "send";
	return "tool";
}

function asString(v: unknown): string | undefined {
	return typeof v === "string" ? v : undefined;
}

function truncate(s: string): string {
	return s.length > MAX_FIELD_BYTES ? `${s.slice(0, MAX_FIELD_BYTES)}…[truncated]` : s;
}

/** Shallow copy of params with oversized string fields truncated. */
function boundedArgs(params: Record<string, unknown>): Record<string, unknown> {
	const out: Record<string, unknown> = {};
	for (const [k, v] of Object.entries(params)) {
		out[k] = typeof v === "string" ? truncate(v) : v;
	}
	return out;
}

/** The literal shell command for a shell tool, if any. */
function shellCommand(toolName: string, params: Record<string, unknown>): string | undefined {
	if (!SHELL_TOOLS.has(toolName)) return undefined;
	return asString(params.command) ?? asString(params.cmd) ?? asString(params.input);
}

/**
 * Derive the {host, path, body} the guard's OPA sees under attributes.request.http.
 * - shell: body = the command (so command + secret-in-argv policies apply)
 * - web egress: host/path = the target URL (so egress-host policies apply)
 * - comms/other: body = a compact human-readable summary of the action
 */
function deriveHttp(toolName: string, params: Record<string, unknown>): { host: string; path: string; body: string } {
	const cmd = shellCommand(toolName, params);
	if (cmd !== undefined) return { host: "exec.local", path: "/", body: truncate(cmd) };

	const url = asString(params.url) ?? asString(params.uri);
	if (url) {
		try {
			const u = new URL(url);
			return { host: u.host, path: u.pathname || "/", body: truncate(url) };
		} catch {
			/* fall through */
		}
	}

	// comms / act-as-user and generic tools: summarize recipient + body-ish fields.
	const parts = [params.target, params.to, params.channel, params.channelId, params.agentId, params.path]
		.map(asString)
		.filter(Boolean);
	const text = [params.message, params.text, params.content, params.caption]
		.map(asString)
		.filter(Boolean)
		.join(" ");
	const summary = [parts.join("/"), text].filter(Boolean).join(" :: ") || safeJson(params);
	return { host: `tool.${toolName}`, path: "/", body: truncate(summary) };
}

function safeJson(params: Record<string, unknown>): string {
	try {
		return truncate(JSON.stringify(params));
	} catch {
		return "";
	}
}

function envFlag(value: string | undefined): boolean {
	if (!value) return false;
	const v = value.trim().toLowerCase();
	return v === "1" || v === "true" || v === "yes" || v === "on";
}

export function resolveGuardConfig(env: NodeJS.ProcessEnv = process.env): GuardConfig {
	const socketPath = env.OPENCLAW_GUARD_SOCKET?.trim() || null;
	const token = env.OPENCLAW_GUARD_TOKEN?.trim() || null;
	const failMode: GuardFailMode = env.OPENCLAW_GUARD_FAIL_MODE?.trim() === "open" ? "open" : "closed";
	const modeRaw = env.OPENCLAW_GUARD_TOOLS?.trim().toLowerCase();
	const governMode: GovernMode = modeRaw === "all" ? "all" : modeRaw === "exec" ? "exec" : "actions";
	const parsedTimeout = Number.parseInt(env.OPENCLAW_GUARD_TIMEOUT_MS?.trim() ?? "", 10);
	const timeoutMs = Number.isFinite(parsedTimeout) && parsedTimeout > 0 ? parsedTimeout : DEFAULT_TIMEOUT_MS;
	return {
		enabled: envFlag(env.OPENCLAW_GUARD_ENABLED) && Boolean(socketPath) && Boolean(token),
		socketPath,
		token,
		failMode,
		timeoutMs,
		governMode,
	};
}

function buildGovernBody(input: GuardActionInput): string {
	const nonce = randomBytes(16).toString("hex");
	const { toolName, params } = input;
	const http = deriveHttp(toolName, params);
	const cmd = shellCommand(toolName, params);
	return JSON.stringify({
		contract_version: "1",
		nonce,
		ctx: {
			surface: surfaceFor(toolName),
			phase: "pre",
			caller: {
				principal_id: input.agentId,
				session_id: input.sessionKey,
				source: "openclaw",
				tool: toolName,
				trust: "untrusted",
			},
		},
		action: {
			tool: toolName,
			operation: cmd !== undefined ? "exec" : "call",
			args: { ...boundedArgs(params), ...(cmd !== undefined ? { cmd } : {}) },
		},
		attributes: {
			request: { http: { method: "POST", host: http.host, path: http.path, body: http.body, headers: {} } },
		},
	});
}

interface GovernResponse {
	verdict?: string;
	reason?: string;
	policy_id?: string;
	decision_id?: string;
}

function parseVerdict(raw: string): GuardVerdict | null {
	let parsed: GovernResponse;
	try {
		parsed = JSON.parse(raw) as GovernResponse;
	} catch {
		return null;
	}
	if (parsed.verdict !== "allow" && parsed.verdict !== "deny") return null;
	return { verdict: parsed.verdict, reason: parsed.reason, policyId: parsed.policy_id, decisionId: parsed.decision_id };
}

export function requestGuardVerdict(input: GuardActionInput, config: GuardConfig): Promise<GuardVerdict | null> {
	if (!config.socketPath || !config.token) return Promise.resolve(null);
	const body = buildGovernBody(input);
	return new Promise<GuardVerdict | null>((resolve) => {
		let settled = false;
		const done = (v: GuardVerdict | null): void => {
			if (settled) return;
			settled = true;
			resolve(v);
		};
		const req = httpRequest(
			{
				socketPath: config.socketPath as string,
				path: "/v1/govern",
				method: "POST",
				headers: {
					"content-type": "application/json",
					"content-length": Buffer.byteLength(body),
					authorization: `Bearer ${config.token}`,
				},
				timeout: config.timeoutMs,
			},
			(res) => {
				const chunks: Buffer[] = [];
				res.on("data", (c: Buffer) => chunks.push(c));
				res.on("end", () => done(parseVerdict(Buffer.concat(chunks).toString("utf8"))));
			},
		);
		req.on("error", () => done(null));
		req.on("timeout", () => {
			req.destroy();
			done(null);
		});
		req.end(body);
	});
}

/**
 * The high-level entry the plugin policy calls for every tool. Returns a concrete
 * verdict: a no-op allow when disabled or when the tool isn't governed under the
 * current mode, the guard's policy verdict when reachable, or the configured
 * fail-mode when it isn't (default fail-closed -> deny). Never throws.
 */
export async function evaluateGuard(
	input: GuardActionInput,
	config: GuardConfig = resolveGuardConfig(),
): Promise<GuardVerdict> {
	if (!config.enabled) return { verdict: "allow" };
	if (!shouldGovern(input.toolName, config.governMode)) return { verdict: "allow" };
	const verdict = await requestGuardVerdict(input, config);
	if (verdict) return verdict;
	if (config.failMode === "open") {
		return { verdict: "allow", failMode: true, reason: "guard_unreachable_fail_open" };
	}
	return { verdict: "deny", failMode: true, reason: "guard_unreachable_fail_closed", policyId: "guard.pep.fail_closed" };
}
