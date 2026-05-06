/**
 * sandbox-guard
 *
 * OS-level filesystem sandboxing for bash commands using bubblewrap (bwrap).
 * Overrides the built-in bash tool with a sandboxed version when enabled.
 *
 * Config comes from the shared HeimdallConfig (loaded by the entry point).
 */

import {
	createBashTool,
	isToolCallEventType,
	type BashOperations,
	type ExtensionAPI,
} from "@mariozechner/pi-coding-agent";
import { existsSync, lstatSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { join, resolve } from "node:path";
import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import type { HeimdallConfig, NormalizedSandboxConfig, SandboxConfig, SandboxPathEntry } from "./types.js";

const DEFAULT_ENV_DENY = ["*_TOKEN", "*_SECRET", "*_PASSWORD", "*_KEY"];

const DEFAULT_PRIVATE_PATHS = [
	"~/Private",
	"~/.ssh",
	"~/.config",
	"~/.aws",
	"~/.azure",
	"~/.gcloud",
	"~/.oci",
	"~/.kube",
	"~/.docker",
	"~/.gnupg",
	"~/.sops",
	"~/.age",
	"~/.password-store",
	"~/.terraform.d",
	"~/.vault-token",
	"~/.netrc",
	"~/.npmrc",
	"~/.pypirc",
	"~/.cargo/credentials",
	"~/.cargo/credentials.toml",
	// AI coding tools (CLI agents, AI-native IDEs) — API keys commonly stored here.
	// This list is not exhaustive; users should extend it in .pi/heimdall.json.
	"~/.claude",
	"~/.codex",
	"~/.forge",
	"~/.cursor",
	"~/.windsurf",
	"~/.antigravity",
	"~/.kiro",
	"~/.augment",
	"~/.zed",
	"~/.aider",
	"~/.gemini",
	"~/.continue",
	"~/.codeium",
	"~/.openai",
	"~/.anthropic",

	// Editor / IDE configs (may contain stored auth tokens)
	"~/.vscode",
	"~/.vscode-server",
	"~/.code",
	"~/.config/JetBrains",
	"~/.local/share/JetBrains",
	"~/.config/nvim",
	"~/.local/share/nvim",
	"~/.vim",
	"~/.viminfo",
];

const DEFAULT_PRIVATE_PATH_DENIES = Object.fromEntries(
	DEFAULT_PRIVATE_PATHS.map((path) => [path, { mode: "deny" } satisfies SandboxPathEntry]),
) as Record<string, SandboxPathEntry>;

const DEFAULT_PATHS: Record<string, SandboxPathEntry | SandboxPathEntry[]> = {
	".": { mode: "write" },
	"/tmp": { mode: "write" },
	"~/.pi": { mode: "write" },
	...DEFAULT_PRIVATE_PATH_DENIES,

	"/usr": {},
	"/opt": {},
	"/srv": {},
	"/etc": {},
	"/nix/store": {},
	"/run/current-system/sw": {},

	// Legacy/non-usr-merged Linux compatibility. Symlinks into already-mounted
	// prefixes are skipped during normalization, so these are harmless on modern distros.
	"/bin": {},
	"/sbin": {},
	"/lib": {},
	"/lib64": {}
};

const DEFAULT_SANDBOX_CONFIG: NormalizedSandboxConfig = {
	enabled: false,
	network: "host",
	paths: normalizePaths(DEFAULT_PATHS),
	env: {
		allow: null,
		deny: DEFAULT_ENV_DENY,
		set: {},
	},
};

function normalizePaths(
	paths: Record<string, SandboxPathEntry | SandboxPathEntry[]> = {},
): Record<string, SandboxPathEntry[]> {
	const result: Record<string, SandboxPathEntry[]> = {};
	for (const [prefix, entries] of Object.entries(paths)) {
		result[prefix] = (Array.isArray(entries) ? entries : [entries]).map((entry) => ({ ...entry }));
	}
	return result;
}

function isLegacySandboxConfig(config: unknown): config is Record<string, unknown> {
	return !!config && typeof config === "object" && (
		"networkAccess" in config ||
		"writableRoots" in config ||
		"systemPaths" in config ||
		"etcReal" in config ||
		"etcSynthetic" in config ||
		"envAllowlist" in config ||
		"extraReadPaths" in config
	);
}

function legacyPaths(config: Record<string, unknown>): Record<string, SandboxPathEntry | SandboxPathEntry[]> {
	const paths: Record<string, SandboxPathEntry[]> = {};
	const push = (prefix: string, entry: SandboxPathEntry = {}) => {
		paths[prefix] = [...(paths[prefix] ?? []), entry];
	};

	for (const path of arrayOfStrings(config.systemPaths)) push(path);
	for (const path of arrayOfStrings(config.extraReadPaths)) push(path);
	for (const path of arrayOfStrings(config.etcReal)) push("/etc", { path });
	for (const path of arrayOfStrings(config.writableRoots)) push(path, { mode: "write" });
	if (config.etcSynthetic && typeof config.etcSynthetic === "object" && !Array.isArray(config.etcSynthetic)) {
		for (const [path, content] of Object.entries(config.etcSynthetic as Record<string, unknown>)) {
			if (typeof content === "string") push("/etc", { path, content });
		}
	}

	return paths;
}

function arrayOfStrings(value: unknown): string[] {
	return Array.isArray(value) ? value.filter((item): item is string => typeof item === "string") : [];
}

export function normalizeSandboxConfig(config?: SandboxConfig | Record<string, unknown>): NormalizedSandboxConfig {
	const sandbox = (config ?? {}) as SandboxConfig;
	const legacy = isLegacySandboxConfig(config) ? config : null;
	const paths = legacy ? legacyPaths(legacy) : sandbox.paths;
	const envAllow = legacy && Array.isArray(legacy.envAllowlist)
		? arrayOfStrings(legacy.envAllowlist)
		: sandbox.env?.allow;

	const mergedPaths = expandPathKeys({
		...DEFAULT_SANDBOX_CONFIG.paths,
		...normalizePaths(paths),
	});

	// Add HOME as read-only by default so users can reference config files
	// and provide deny rules. User/project config can override with { mode: "write" }.
	const homeDir = process.env.HOME;
	if (homeDir && !(homeDir in mergedPaths)) {
		mergedPaths[homeDir] = [{}];
	}

	return {
		enabled: sandbox.enabled ?? DEFAULT_SANDBOX_CONFIG.enabled,
		network: sandbox.network ?? (legacy?.networkAccess === false ? "none" : DEFAULT_SANDBOX_CONFIG.network),
		paths: mergedPaths,
		env: {
			allow: envAllow === undefined ? DEFAULT_SANDBOX_CONFIG.env.allow : envAllow,
			deny: sandbox.env?.deny === undefined ? DEFAULT_SANDBOX_CONFIG.env.deny : sandbox.env.deny,
			set: sandbox.env?.set === undefined ? DEFAULT_SANDBOX_CONFIG.env.set : sandbox.env.set,
		},
	};
}

/** Resolve ~ and $VAR/${VAR} references in path strings. */
function expandPath(path: string): string {
	if (path.startsWith("~")) {
		if (path === "~" || path.startsWith("~/")) {
			const home = process.env.HOME;
			if (home) return home + path.slice(1);
		}
	}
	return path.replace(/\$\{?(\w+)\}?/g, (_m, name: string) => process.env[name] ?? "");
}

function expandPathKeys<T extends SandboxPathEntry>(paths: Record<string, T[]>): Record<string, T[]> {
	const result: Record<string, T[]> = {};
	for (const [key, entries] of Object.entries(paths)) {
		result[expandPath(key)] = entries;
	}
	return result;
}

function resolveSandboxPath(path: string, cwd: string): string {
	const expanded = expandPath(path);
	if (expanded === ".") return cwd;
	return expanded.startsWith("/") ? expanded : resolve(cwd, expanded);
}

function pathMatchesPrefix(path: string, prefix: string): boolean {
	return path === prefix || path.startsWith(`${prefix}/`);
}

export interface SandboxPathAccess {
	access: "none" | "read" | "write";
	synthetic: boolean;
	matchedPath?: string;
}

export function getSandboxPathAccess(
	config: NormalizedSandboxConfig,
	cwd: string,
	rawPath: string,
): SandboxPathAccess {
	const target = resolveSandboxPath(rawPath.replace(/^@/, ""), cwd);
	let best: { specificity: number; order: number; access: "none" | "read" | "write"; synthetic: boolean; matchedPath: string } | null = null;
	let order = 0;

	for (const [prefix, entries] of Object.entries(config.paths)) {
		for (const entry of entries) {
			const entryTarget = resolveSandboxPath(entry.path ?? prefix, cwd);
			const matches = entry.path ? target === entryTarget : pathMatchesPrefix(target, entryTarget);
			if (!matches) {
				order++;
				continue;
			}

			const candidate = {
				specificity: entryTarget.length + (entry.path ? 10_000 : 0),
				order,
				access: entry.mode === "write" ? "write" as const : entry.mode === "deny" ? "none" as const : "read" as const,
				synthetic: entry.content !== undefined,
				matchedPath: entryTarget,
			};
			if (!best || candidate.specificity > best.specificity ||
				(candidate.specificity === best.specificity && candidate.order > best.order)) {
				best = candidate;
			}
			order++;
		}
	}

	return best
		? { access: best.access, synthetic: best.synthetic, matchedPath: best.matchedPath }
		: { access: "none", synthetic: false };
}

function canReadSandboxPath(config: NormalizedSandboxConfig, cwd: string, path: string): boolean {
	const access = getSandboxPathAccess(config, cwd, path);
	// Synthetic mounts do not exist on the host filesystem. Letting the built-in
	// read tool read that path would expose the host file instead of sandbox content.
	return access.access !== "none" && !access.synthetic;
}

function canWriteSandboxPath(config: NormalizedSandboxConfig, cwd: string, path: string): boolean {
	const access = getSandboxPathAccess(config, cwd, path);
	return access.access === "write" && !access.synthetic;
}

function isCompatibilitySymlink(path: string, mountedPrefixes: Set<string>): boolean {
	try {
		const stat = lstatSync(path);
		if (!stat.isSymbolicLink()) return false;
		const target = resolve(path);
		for (const prefix of mountedPrefixes) {
			if (target === prefix || target.startsWith(`${prefix}/`)) return true;
		}
	} catch {
		return false;
	}
	return false;
}

function syntheticFilename(target: string): string {
	return target.replace(/[^a-zA-Z0-9._-]/g, "_") || "synthetic";
}

export function buildBwrapArgs(
	config: NormalizedSandboxConfig,
	cwd: string,
	syntheticDir: string,
	command: string,
): string[] {
	const args: string[] = [];
	const readPrefixMounts: string[] = [];
	const writeMounts: string[] = [];
	const overlayReadMounts: Array<{ source: string; target: string }> = [];

	args.push("--tmpfs", "/");
	args.push("--dev", "/dev");

	for (const [prefix, entries] of Object.entries(config.paths)) {
		for (const entry of entries) {
			const target = resolveSandboxPath(entry.path ?? prefix, cwd);
			if (entry.content !== undefined) {
				const syntheticFile = join(syntheticDir, syntheticFilename(target));
				writeFileSync(syntheticFile, entry.content, "utf-8");
				overlayReadMounts.push({ source: syntheticFile, target });
				continue;
			}

			if (entry.mode === "deny" || !existsSync(target)) continue;

			if (entry.mode === "write") {
				writeMounts.push(target);
			} else if (entry.path) {
				overlayReadMounts.push({ source: target, target });
			} else {
				readPrefixMounts.push(target);
			}
		}
	}

	const mountedReadPrefixes = new Set<string>();
	for (const target of dedupe(readPrefixMounts)) {
		if (isCompatibilitySymlink(target, mountedReadPrefixes)) continue;
		args.push("--ro-bind", target, target);
		mountedReadPrefixes.add(target);
	}

	for (const target of dedupe(writeMounts)) {
		args.push("--bind", target, target);
	}

	for (const { source, target } of dedupeMounts(overlayReadMounts)) {
		args.push("--ro-bind", source, target);
	}

	args.push("--unshare-user");
	args.push("--unshare-pid");
	if (config.network === "none") args.push("--unshare-net");
	args.push("--proc", "/proc");
	args.push("--die-with-parent");
	args.push("--new-session");
	args.push("--");
	args.push("bash", "-c", command);

	return args;
}

function dedupe(values: string[]): string[] {
	return [...new Set(values)];
}

function dedupeMounts(mounts: Array<{ source: string; target: string }>): Array<{ source: string; target: string }> {
	const seen = new Set<string>();
	const result: Array<{ source: string; target: string }> = [];
	for (const mount of mounts) {
		const key = `${mount.source}\0${mount.target}`;
		if (seen.has(key)) continue;
		seen.add(key);
		result.push(mount);
	}
	return result;
}

function globToRegExp(pattern: string): RegExp {
	const escaped = pattern.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*");
	return new RegExp(`^${escaped}$`);
}

export function filterEnv(
	envConfig: NormalizedSandboxConfig["env"],
	currentEnv: Record<string, string>,
): Record<string, string> {
	const allow = envConfig.allow;
	const deny = envConfig.deny;
	const allowPatterns = allow?.map(globToRegExp) ?? null;
	const denyPatterns = deny?.map(globToRegExp) ?? [];
	const result: Record<string, string> = {};

	for (const [key, value] of Object.entries(currentEnv)) {
		const allowed = allowPatterns === null || allowPatterns.some((pattern) => pattern.test(key));
		const denied = denyPatterns.some((pattern) => pattern.test(key));
		if (allowed && !denied) result[key] = value;
	}

	for (const [key, value] of Object.entries(envConfig.set ?? {})) {
		if (value === null) {
			delete result[key];
		} else {
			result[key] = value;
		}
	}

	return result;
}

/** @deprecated use filterEnv({ allow, deny, set }, env). */
export function stripEnv(
	allowlist: string[],
	currentEnv: Record<string, string>,
): Record<string, string> {
	return filterEnv({ allow: allowlist, deny: null, set: {} }, currentEnv);
}

function findBwrap(): string | null {
	const pathEnv = process.env.PATH ?? "";
	for (const dir of pathEnv.split(":")) {
		const candidate = join(dir, "bwrap");
		if (existsSync(candidate)) return candidate;
	}
	for (const loc of ["/usr/bin/bwrap", "/usr/local/bin/bwrap"]) {
		if (existsSync(loc)) return loc;
	}
	return null;
}

function createSandboxedBashOps(config: NormalizedSandboxConfig, cwd: string): BashOperations {
	return {
		async exec(command, execCwd, { onData, signal, timeout }) {
			const workDir = execCwd || cwd;
			if (!existsSync(workDir)) {
				throw new Error(`Working directory does not exist: ${workDir}`);
			}

			const syntheticDir = join(
				process.env.TMPDIR || "/tmp",
				`heimdall-sandbox-${randomUUID()}`,
			);
			mkdirSync(syntheticDir, { recursive: true });

			try {
				const bwrapPath = findBwrap();
				if (!bwrapPath) {
					throw new Error("bubblewrap (bwrap) not found. Install it to enable sandboxing.");
				}

				const bwrapArgs = buildBwrapArgs(config, cwd, syntheticDir, command);
				const cleanEnv = filterEnv(config.env, process.env as Record<string, string>);

				return await new Promise((resolve, reject) => {
					const child = spawn(bwrapPath, bwrapArgs, {
						cwd: workDir,
						env: cleanEnv,
						detached: true,
						stdio: ["ignore", "pipe", "pipe"],
					});

					let timedOut = false;
					let timeoutHandle: NodeJS.Timeout | undefined;

					if (timeout !== undefined && timeout > 0) {
						timeoutHandle = setTimeout(() => {
							timedOut = true;
							if (child.pid) {
								try { process.kill(-child.pid, "SIGKILL"); } catch { child.kill("SIGKILL"); }
							}
						}, timeout * 1000);
					}

					child.stdout?.on("data", onData);
					child.stderr?.on("data", onData);

					child.on("error", (err) => {
						if (timeoutHandle) clearTimeout(timeoutHandle);
						reject(err);
					});

					const onAbort = () => {
						if (child.pid) {
							try { process.kill(-child.pid, "SIGKILL"); } catch { child.kill("SIGKILL"); }
						}
					};

					signal?.addEventListener("abort", onAbort, { once: true });

					child.on("close", (code) => {
						if (timeoutHandle) clearTimeout(timeoutHandle);
						signal?.removeEventListener("abort", onAbort);

						if (signal?.aborted) {
							reject(new Error("aborted"));
						} else if (timedOut) {
							reject(new Error(`timeout:${timeout}`));
						} else {
							resolve({ exitCode: code ?? 1 });
						}
					});
				});
			} finally {
				try { rmSync(syntheticDir, { recursive: true, force: true }); } catch { /* best effort */ }
			}
		},
	};
}

export function registerSandboxGuard(pi: ExtensionAPI, getHeimdallConfig: () => HeimdallConfig): void {
	let sandboxConfig: NormalizedSandboxConfig | null = null;
	let sandboxCwd = process.cwd();
	let bwrapAvailable = false;

	pi.registerFlag("no-sandbox", {
		description: "Disable OS-level sandboxing for bash commands",
		type: "boolean",
		default: false,
	});

	pi.on("session_start", async (_event, ctx) => {
		sandboxCwd = ctx.cwd;
		const noSandbox = pi.getFlag("no-sandbox") as boolean;
		if (noSandbox) {
			sandboxConfig = null;
			bwrapAvailable = false;
			ctx.ui.notify("heimdall sandbox: disabled via --no-sandbox", "warning");
			return;
		}

		const config = normalizeSandboxConfig(getHeimdallConfig().sandbox as SandboxConfig | undefined);
		sandboxConfig = null;
		bwrapAvailable = false;
		if (!config.enabled) {
			return;
		}

		if (process.platform !== "linux") {
			ctx.ui.notify(
				`heimdall sandbox: not supported on ${process.platform} (Linux only)`,
				"warning",
			);
			return;
		}

		const bwrap = findBwrap();
		if (!bwrap) {
			ctx.ui.notify(
				"heimdall sandbox: bwrap not found. Install bubblewrap to enable sandboxing.",
				"warning",
			);
			return;
		}

		bwrapAvailable = true;
		sandboxConfig = config;

		const entries = Object.values(config.paths).flat();
		const writeCount = entries.filter((entry) => entry.mode === "write").length;
		const envIcon = config.env.allow === null ? "E∞" : `E${config.env.allow.length}`;
		const networkIcon = config.network === "host" ? "↔" : "⊘";
		const theme = ctx.ui.theme;
		ctx.ui.setStatus(
			"heimdall-sandbox",
			[
				theme.fg("accent", "🛡"),
				theme.fg("success", `✎${writeCount}`),
				theme.fg("muted", envIcon),
				theme.fg(config.network === "host" ? "success" : "warning", networkIcon),
			].join(theme.fg("dim", "│")),
		);
		ctx.ui.notify("heimdall sandbox: active", "info");
	});

	const localCwd = process.cwd();
	const localBash = createBashTool(localCwd);

	pi.registerTool({
		...localBash,
		label: "bash (heimdall sandbox)",
		async execute(id, params, signal, onUpdate, _ctx) {
			if (!sandboxConfig || !bwrapAvailable) {
				return localBash.execute(id, params, signal, onUpdate);
			}

			const sandboxedBash = createBashTool(sandboxCwd, {
				operations: createSandboxedBashOps(sandboxConfig, sandboxCwd),
			});
			return sandboxedBash.execute(id, params, signal, onUpdate);
		},
	});

	pi.on("user_bash", () => {
		if (!sandboxConfig || !bwrapAvailable) return undefined;
		return {
			operations: createSandboxedBashOps(sandboxConfig, sandboxCwd),
		};
	});

	pi.on("tool_call", async (event, ctx) => {
		if (!sandboxConfig || !sandboxConfig.enabled) return undefined;

		const block = (operation: "read" | "write", path: string) => {
			const reason =
				`Blocked: ${event.toolName} attempted to ${operation} "${path}" outside the heimdall sandbox path policy. ` +
				`Use a path mounted with ${operation === "write" ? 'mode "write"' : 'read access'} in sandbox.paths, or ask the user to adjust .pi/heimdall.json.`;
			if (ctx.hasUI) ctx.ui.notify(`heimdall sandbox: blocked ${event.toolName} ${path}`, "warning");
			return { block: true as const, reason };
		};

		const input = event.input as Record<string, unknown>;
		const path = typeof input.path === "string" ? input.path : ".";

		if (isToolCallEventType("read", event) || event.toolName === "grep" || event.toolName === "find" || event.toolName === "ls") {
			if (!canReadSandboxPath(sandboxConfig, sandboxCwd, path)) return block("read", path);
			return undefined;
		}

		if (isToolCallEventType("write", event) || isToolCallEventType("edit", event)) {
			if (typeof input.path !== "string") return undefined;
			if (!canWriteSandboxPath(sandboxConfig, sandboxCwd, input.path)) return block("write", input.path);
		}

		return undefined;
	});

	pi.registerCommand("sandbox", {
		description: "Show heimdall sandbox configuration",
		handler: async (_args, ctx) => {
			if (!sandboxConfig) {
				ctx.ui.notify("heimdall sandbox: disabled", "info");
				return;
			}

			const lines = [
				"heimdall sandbox configuration:",
				"",
				`Network: ${sandboxConfig.network === "host" ? "shared (host)" : "isolated"}`,
				`Env allow: ${sandboxConfig.env.allow === null ? "inherited" : sandboxConfig.env.allow.join(", ")}`,
				`Env deny: ${sandboxConfig.env.deny?.join(", ") || "(none)"}`,
				"Paths:",
				...Object.entries(sandboxConfig.paths).flatMap(([prefix, entries]) =>
					entries.map((entry) => {
						const target = entry.path ?? prefix;
						const kind = entry.content === undefined ? target : `${target} (synthetic)`;
						return `  ${prefix}: ${kind} [${entry.mode ?? "read"}]`;
					}),
				),
			];
			ctx.ui.notify(lines.join("\n"), "info");
		},
	});
}
