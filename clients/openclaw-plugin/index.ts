// Aarvion Guard — OpenClaw plugin entrypoint.
//
// A stock OpenClaw loads this module's default export as a plugin definition.
// It's a plain object (the SDK's definePluginEntry is just a passthrough), so
// this package needs no `openclaw` import and loads from any install location.
import { registerAarvionGuardPlugin } from "./src/plugin.js";

export default {
	id: "aarvion-guard",
	name: "Aarvion Guard",
	description: "Governs agent tool calls through the local Aarvion guard policy decision point (PDP).",
	configSchema: { type: "object", additionalProperties: false, properties: {} },
	register: registerAarvionGuardPlugin,
};
