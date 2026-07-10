// Standalone proof: exercises the REAL plugin policy against a RUNNING guard PDP.
// Registers the policy via a fake host api, captures it, then asks it to rule on
// a benign and a dangerous command.
// Run with OPENCLAW_GUARD_ENABLED=1 + OPENCLAW_GUARD_SOCKET + OPENCLAW_GUARD_TOKEN.
import { registerAarvionGuardPlugin, type GuardHostApi, type TrustedToolPolicy } from "./src/plugin.js";

let captured: TrustedToolPolicy | undefined;
const fakeApi: GuardHostApi = {
	registerTrustedToolPolicy: (p) => {
		captured = p;
	},
};

registerAarvionGuardPlugin(fakeApi);

if (!captured) {
	console.error("FAIL: plugin did not register a trusted tool policy");
	process.exit(1);
}
console.log(`registered trusted tool policy: ${captured.id}`);

const ctx = { toolName: "bash", agentId: "agent-e2e", sessionKey: "sess-e2e" };
const benign = await captured.evaluate({ toolName: "bash", params: { command: "ls -la /tmp" } }, ctx);
const danger = await captured.evaluate(
	{ toolName: "bash", params: { command: "sudo rm -rf / --no-preserve-root" } },
	ctx,
);

console.log(`benign  "ls -la /tmp"                 -> ${benign ? JSON.stringify(benign) : "ALLOW (no veto)"}`);
console.log(`danger  "rm -rf / --no-preserve-root" -> ${danger ? JSON.stringify(danger) : "ALLOW (no veto)"}`);

const ok = !benign && Boolean(danger) && (danger as { block?: boolean }).block === true;
console.log(ok ? "\nRESULT: PASS (benign allowed, dangerous blocked by the guard)" : "\nRESULT: FAIL");
process.exit(ok ? 0 : 1);
