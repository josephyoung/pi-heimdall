/**
 * heimdall — guardian extension for pi
 *
 * A single extension that provides multiple security guards:
 *   - secret-guard: blocks secret key references in bash, redacts values from output
 *   - command-policy-guard: enforces repo command policies from heimdall.json
 *   - env-protect: blocks read tool calls targeting .env files
 *   - kubectl-secret-guard: blocks risky kubectl commands (get secrets, patch finalizers, exec)
 *   - sops-secret-guard: blocks sops decrypt invocations
 *   - sandbox-guard: OS-level filesystem sandboxing via bwrap (always-on)
 *
 * Config is loaded from two locations and deep-merged (project overrides user):
 *   - User-level:   ~/.pi/agent/heimdall.json
 *   - Project-level: <cwd>/.pi/heimdall.json
 *
 * sandbox-guard always runs (when enabled in config).
 *
 * The following guards can be disabled via the `disabled` array:
 *   - secret-guard, command-policy-guard, env-protect,
 *   - kubectl-secret-guard, sops-secret-guard
 *
 * ```json
 * {
 *   "disabled": ["env-protect", "kubectl-secret-guard"],
 *   "sandbox": { ... },
 *   "commandPolicies": [ ... ]
 * }
 * ```
 */

import { type ExtensionAPI, getAgentDir } from "@mariozechner/pi-coding-agent";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import type { HeimdallConfig } from "../guards/types.js";

import { registerSecretGuard } from "../guards/secret-guard.js";
import { registerCommandPolicyGuard } from "../guards/command-policy-guard.js";
import { registerEnvProtect } from "../guards/env-protect.js";
import { registerKubectlSecretGuard } from "../guards/kubectl-secret-guard.js";
import { registerSopsSecretGuard } from "../guards/sops-secret-guard.js";
import { registerSandboxGuard } from "../guards/sandbox-guard.js";

const OPT_OUT_GUARD_IDS = [
	"secret-guard",
	"command-policy-guard",
	"env-protect",
	"kubectl-secret-guard",
	"sops-secret-guard",
] as const;

/**
 * Deep merge: project overrides user. Objects merge recursively.
 * Arrays concatenate (project appends to user).
 * Primitives and null from project win.
 */
function deepMerge(base: HeimdallConfig, overrides: HeimdallConfig): HeimdallConfig {
	const result = { ...base };
	for (const key of Object.keys(overrides) as (keyof HeimdallConfig)[]) {
		const ov = overrides[key];
		if (ov === undefined) continue;
		const bv = base[key];
		if (
			typeof ov === "object" && ov !== null && !Array.isArray(ov) &&
			typeof bv === "object" && bv !== null && !Array.isArray(bv)
		) {
			(result as Record<string, unknown>)[key] = deepMerge(
				bv as HeimdallConfig,
				ov as HeimdallConfig,
			);
		} else if (Array.isArray(ov) && Array.isArray(bv)) {
			(result as Record<string, unknown>)[key] = [...bv, ...ov];
		} else {
			(result as Record<string, unknown>)[key] = ov;
		}
	}
	return result;
}

function loadConfigFile(path: string): HeimdallConfig | null {
	if (!existsSync(path)) return null;
	try {
		const raw = readFileSync(path, "utf-8");
		const parsed = JSON.parse(raw);
		if (parsed && typeof parsed === "object") return parsed;
	} catch {
		// Parse error — skip
	}
	return null;
}

export default function heimdall(pi: ExtensionAPI) {
	let config: HeimdallConfig = {};
	const disabledSet = new Set<string>();

	pi.on("session_start", async (_event, ctx) => {
		config = {};
		disabledSet.clear();

		const userConfig = loadConfigFile(join(getAgentDir(), "heimdall.json"));
		const projectConfig = loadConfigFile(join(ctx.cwd, ".pi", "heimdall.json"));

		if (userConfig || projectConfig) {
			const merged = deepMerge(userConfig ?? {}, projectConfig ?? {});
			config = merged;
		}

		if (Array.isArray(config.disabled)) {
			for (const d of config.disabled) {
				disabledSet.add(d);
			}
		}

		const disabledCount = [...disabledSet].filter((d) => OPT_OUT_GUARD_IDS.includes(d as typeof OPT_OUT_GUARD_IDS[number])).length;
		const active = OPT_OUT_GUARD_IDS.length - disabledCount + 1; // +1 for sandbox-guard
		const disabled = disabledCount > 0
			? ` (disabled: ${[...disabledSet].filter((d) => OPT_OUT_GUARD_IDS.includes(d as typeof OPT_OUT_GUARD_IDS[number])).join(", ")})`
			: "";
		ctx.ui.notify(`heimdall: ${active} guards active${disabled}`, "info");
	});

	// Always registered, but runtime behavior follows current loaded config.
	registerSandboxGuard(pi, () => config);

	// Opt-out guards
	registerSecretGuard(pi, disabledSet);
	registerCommandPolicyGuard(pi, () => config, disabledSet);
	registerEnvProtect(pi, disabledSet);
	registerKubectlSecretGuard(pi, disabledSet);
	registerSopsSecretGuard(pi, disabledSet);
}
