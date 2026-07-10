// Aarvion guard client: asks the local guard PDP (/v1/govern over a Unix socket)
// whether an action is allowed. HTTP/1.1 over the socket; two auth factors the
// guard enforces (bearer token + kernel-verified peer uid) plus a fresh nonce
// per request for replay protection. Never throws; on any transport failure it
// returns a fail-mode verdict so a guard hiccup can't crash a tool call.
import { randomBytes } from "node:crypto";
import { request as httpRequest } from "node:http";

export type GuardFailMode = "closed" | "open";

export interface GuardConfig {
	enabled: boolean;
	socketPath: string | null;
	token: string | null;
	failMode: GuardFailMode;
	timeoutMs: number;
}

export interface GuardVerdict {
	verdict: "allow" | "deny";
	reason?: string;
	policyId?: string;
	decisionId?: string;
	/** True when the verdict came from fail-mode (guard unreachable), not policy. */
	failMode?: boolean;
}

export interface GuardActionInput {
	command: string;
	toolName?: string;
	agentId?: string;
	sessionKey?: string;
	cwd?: string;
}

const DEFAULT_TIMEOUT_MS = 2_000;

function envFlag(value: string | undefined): boolean {
	if (!value) return false;
	const v = value.trim().toLowerCase();
	return v === "1" || v === "true" || v === "yes" || v === "on";
}

/**
 * Resolve guard config from the environment. The socket path + token are
 * deployment secrets, so env is the right channel (the gateway's service-env).
 * Disabled unless the flag AND a socket AND a token are all present.
 */
export function resolveGuardConfig(env: NodeJS.ProcessEnv = process.env): GuardConfig {
	const socketPath = env.OPENCLAW_GUARD_SOCKET?.trim() || null;
	const token = env.OPENCLAW_GUARD_TOKEN?.trim() || null;
	const failMode: GuardFailMode = env.OPENCLAW_GUARD_FAIL_MODE?.trim() === "open" ? "open" : "closed";
	const parsedTimeout = Number.parseInt(env.OPENCLAW_GUARD_TIMEOUT_MS?.trim() ?? "", 10);
	const timeoutMs = Number.isFinite(parsedTimeout) && parsedTimeout > 0 ? parsedTimeout : DEFAULT_TIMEOUT_MS;
	return {
		enabled: envFlag(env.OPENCLAW_GUARD_ENABLED) && Boolean(socketPath) && Boolean(token),
		socketPath,
		token,
		failMode,
		timeoutMs,
	};
}

function buildGovernBody(input: GuardActionInput): string {
	const nonce = randomBytes(16).toString("hex");
	return JSON.stringify({
		contract_version: "1",
		nonce,
		ctx: {
			surface: "exec",
			phase: "pre",
			caller: {
				principal_id: input.agentId,
				session_id: input.sessionKey,
				source: "openclaw",
				tool: input.toolName ?? "bash",
				trust: "untrusted",
			},
		},
		action: {
			tool: input.toolName ?? "bash",
			operation: "exec",
			args: { cmd: input.command, cwd: input.cwd },
		},
		// The command doubles as the http "body" so body-scanning packs (e.g. secret
		// exfil) also catch secrets that leak into an argv.
		attributes: {
			request: {
				http: { method: "POST", host: "exec.local", path: "/", body: input.command, headers: {} },
			},
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
	return {
		verdict: parsed.verdict,
		reason: parsed.reason,
		policyId: parsed.policy_id,
		decisionId: parsed.decision_id,
	};
}

/**
 * POST the action to the guard and return its verdict. The guard answers 200 for
 * allow and 403 for deny, BOTH carrying a JSON verdict body, so we parse the body
 * regardless of status and only fall back to null (transport failure) when there
 * is no parseable verdict (e.g. 401 auth failure, timeout, socket down).
 */
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
 * High-level entry the plugin policy calls. Always resolves to a concrete
 * verdict: a no-op allow when disabled, the guard's policy verdict when
 * reachable, or the configured fail-mode when it isn't (default fail-closed ->
 * deny, since a governance layer that fails open is theater).
 */
export async function evaluateGuard(
	input: GuardActionInput,
	config: GuardConfig = resolveGuardConfig(),
): Promise<GuardVerdict> {
	if (!config.enabled) return { verdict: "allow" };
	const verdict = await requestGuardVerdict(input, config);
	if (verdict) return verdict;
	if (config.failMode === "open") {
		return { verdict: "allow", failMode: true, reason: "guard_unreachable_fail_open" };
	}
	return { verdict: "deny", failMode: true, reason: "guard_unreachable_fail_closed", policyId: "guard.pep.fail_closed" };
}
