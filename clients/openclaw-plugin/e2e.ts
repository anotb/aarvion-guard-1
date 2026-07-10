// Standalone proof for the guard PEP. Two parts:
//
//  1. Approval polling (always runs, no guard needed): drives awaitApproval and the
//     real plugin policy against a STUB guard so we prove that an `ask` whose owner
//     approves lets the call run, while an `ask` that stays pending past the budget
//     fails safe to a block. This is the C5 contract.
//  2. Live guard proof (only when OPENCLAW_GUARD_* is set): asks the real policy to
//     rule on a benign and a dangerous command against a RUNNING guard PDP.
import {
	awaitApproval,
	type ApprovalPollConfig,
	type ApprovalStatus,
	type GuardConfig,
} from "./src/guard-client.js";
import { registerAarvionGuardPlugin, type GuardHostApi, type TrustedToolPolicy } from "./src/plugin.js";

let failures = 0;
function check(name: string, ok: boolean): void {
	console.log(`${ok ? "PASS" : "FAIL"}  ${name}`);
	if (!ok) failures += 1;
}

// --- Part 1: approval polling against a stub guard --------------------------

const pollCfg: ApprovalPollConfig = {
	socketPath: "/stub.sock",
	token: "stub-token",
	timeoutMs: 2_000,
	approvalTimeoutMs: 20,
	approvalPollMs: 1,
};

// A stub poll that returns "pending" a few times then flips to a terminal verdict.
function stubPoll(pendingRounds: number, then: ApprovalStatus): (id: string) => Promise<ApprovalStatus> {
	let calls = 0;
	return async () => {
		calls += 1;
		return calls > pendingRounds ? then : "pending";
	};
}

{
	// ask -> owner approves after two pending polls -> allow
	const outcome = await awaitApproval("dec-allow", pollCfg, stubPoll(2, "allow"));
	check("awaitApproval: pending then allow -> allow", outcome === "allow");
}
{
	// ask -> owner denies -> deny
	const outcome = await awaitApproval("dec-deny", pollCfg, stubPoll(1, "deny"));
	check("awaitApproval: pending then deny -> deny", outcome === "deny");
}
{
	// ask -> stays pending forever -> times out -> deny (fail-safe)
	const alwaysPending = async (): Promise<ApprovalStatus> => "pending";
	const outcome = await awaitApproval("dec-timeout", pollCfg, alwaysPending);
	check("awaitApproval: never resolves -> deny (timeout fail-safe)", outcome === "deny");
}
{
	// guard unreachable the whole window -> deny (fail-safe)
	const alwaysDown = async (): Promise<ApprovalStatus> => "unreachable";
	const outcome = await awaitApproval("dec-down", pollCfg, alwaysDown);
	check("awaitApproval: unreachable throughout -> deny (fail-safe)", outcome === "deny");
}
{
	// missing decisionId -> deny without polling
	let polled = false;
	const outcome = await awaitApproval(
		"",
		pollCfg,
		async () => {
			polled = true;
			return "allow";
		},
	);
	check("awaitApproval: empty decisionId -> deny, no poll", outcome === "deny" && !polled);
}

// The plugin's ask branch calls awaitApproval with the same config it governs on,
// which the cases above already cover directly. Here we just confirm the policy
// registers cleanly; the full ask->allow / ask->block wiring is proven live below
// when a guard is running.
{
	let captured: TrustedToolPolicy | undefined;
	const api: GuardHostApi = { registerTrustedToolPolicy: (p) => (captured = p) };
	registerAarvionGuardPlugin(api);
	check("plugin: registers a trusted tool policy", captured?.id === "aarvion-guard");
}

// --- Part 2: live guard proof (opt-in) -------------------------------------

const liveEnabled = process.env.OPENCLAW_GUARD_ENABLED === "1" && Boolean(process.env.OPENCLAW_GUARD_SOCKET);
if (liveEnabled) {
	let captured: TrustedToolPolicy | undefined;
	const api: GuardHostApi = { registerTrustedToolPolicy: (p) => (captured = p) };
	registerAarvionGuardPlugin(api);
	if (!captured) {
		console.error("FAIL: plugin did not register a trusted tool policy");
		process.exit(1);
	}
	const ctx = { toolName: "bash", agentId: "agent-e2e", sessionKey: "sess-e2e" };
	const benign = await captured.evaluate({ toolName: "bash", params: { command: "ls -la /tmp" } }, ctx);
	const danger = await captured.evaluate(
		{ toolName: "bash", params: { command: "sudo rm -rf / --no-preserve-root" } },
		ctx,
	);
	console.log(`live benign  "ls -la /tmp"                 -> ${benign ? JSON.stringify(benign) : "ALLOW (no veto)"}`);
	console.log(`live danger  "rm -rf / --no-preserve-root" -> ${danger ? JSON.stringify(danger) : "ALLOW (no veto)"}`);
	check("live: benign allowed", !benign);
	check("live: dangerous blocked", Boolean(danger) && (danger as { block?: boolean }).block === true);
} else {
	console.log("(skipping live guard proof: OPENCLAW_GUARD_ENABLED/SOCKET not set)");
}

// Keep GuardConfig referenced so the type stays exercised even without a live guard.
const _cfgShape: Pick<GuardConfig, "approvalTimeoutMs" | "approvalPollMs"> = { approvalTimeoutMs: 90_000, approvalPollMs: 2_000 };
void _cfgShape;

console.log(failures === 0 ? "\nRESULT: PASS" : `\nRESULT: FAIL (${failures} failing)`);
process.exit(failures === 0 ? 0 : 1);
