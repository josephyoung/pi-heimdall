import type { ExtensionAPI } from "@mariozechner/pi-coding-agent";

export interface HeimdallConfig {
	disabled?: string[];
	sandbox?: Partial<SandboxConfig>;
	commandPolicies?: CommandPolicy[];
}

export interface CommandPolicy {
	name: string;
	blocked: string[];
	message: string;
}

export interface SandboxConfig {
	enabled: boolean;
	networkAccess: boolean;
	writableRoots: string[];
	systemPaths: string[];
	etcReal: string[];
	etcSynthetic: Record<string, string>;
	envAllowlist: string[];
	extraReadPaths: string[];
	denyReadGlobs: string[];
}

/** Guards that can be disabled via the `disabled` array in heimdall.json. */
export type OptOutGuardId =
	| "secret-guard"
	| "command-policy-guard"
	| "env-protect"
	| "kubectl-secret-guard"
	| "sops-secret-guard";

export interface GuardRegisterFn {
	(pi: ExtensionAPI, config: HeimdallConfig): void | Promise<void>;
}
