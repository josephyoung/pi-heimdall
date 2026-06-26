import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";

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
	enabled?: boolean;
	network?: "host" | "none";
	userNamespace?: boolean;
	paths?: Record<string, SandboxPathEntry | SandboxPathEntry[]>;
	env?: {
		allow?: string[] | null;
		deny?: string[] | null;
		set?: Record<string, string | null>;
	};
}

export interface SandboxPathEntry {
	path?: string;
	content?: string;
	mode?: "read" | "write" | "deny";
}

export interface NormalizedSandboxConfig {
	enabled: boolean;
	network: "host" | "none";
	userNamespace: boolean;
	paths: Record<string, SandboxPathEntry[]>;
	env: {
		allow: string[] | null;
		deny: string[] | null;
		set: Record<string, string | null>;
	};
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
