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
	getAgentDir,
	isFindToolResult,
	isGrepToolResult,
	isLsToolResult,
	isToolCallEventType,
	type BashOperations,
	type ExtensionAPI,
} from "@earendil-works/pi-coding-agent";
import { existsSync, lstatSync, mkdirSync, writeFileSync, rmSync, realpathSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
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
	"/bin": {},
	"/sbin": {},
	"/lib": {},
	"/lib64": {},
};

const DEFAULT_SANDBOX_CONFIG: NormalizedSandboxConfig = {
	enabled: false,
	network: "host",
	userNamespace: true,
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

	const homeDir = process.env.HOME;
	if (homeDir && !(homeDir in mergedPaths)) {
		mergedPaths[homeDir] = [{}];
	}

	return {
		enabled: sandbox.enabled ?? DEFAULT_SANDBOX_CONFIG.enabled,
		network: sandbox.network ?? (legacy?.networkAccess === false ? "none" : DEFAULT_SANDBOX_CONFIG.network),
		userNamespace: sandbox.userNamespace ?? DEFAULT_SANDBOX_CONFIG.userNamespace,
		paths: mergedPaths,
		env: {
			allow: envAllow === undefined ? DEFAULT_SANDBOX_CONFIG.env.allow : envAllow,
			deny: sandbox.env?.deny === undefined ? DEFAULT_SANDBOX_CONFIG.env.deny : sandbox.env.deny,
			set: sandbox.env?.set === undefined ? DEFAULT_SANDBOX_CONFIG.env.set : sandbox.env.set,
		},
	};
}

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

function realpathOrNull(path: string): string | null {
	try {
		return realpathSync(path);
	} catch {
		return null;
	}
}

export function heimdallConfigPaths(cwd: string, agentDir = getAgentDir()): string[] {
	const result = new Set<string>();
	for (const path of [
		join(agentDir, "heimdall.json"),
		join(cwd, ".pi", "heimdall.json"),
	]) {
		const resolved = resolve(path);
		result.add(resolved);
		const real = realpathOrNull(resolved);
		if (real) result.add(real);
	}
	return [...result];
}

function pathCandidates(rawPath: string, cwd: string): string[] {
	const result = new Set<string>();
	const resolved = resolveSandboxPath(rawPath.replace(/^@/, ""), cwd);
	result.add(resolved);
	const real = realpathOrNull(resolved);
	if (real) result.add(real);
	return [...result];
}

export function isProtectedHeimdallConfigPath(
	rawPath: string,
	cwd: string,
	protectedPaths: string[],
): boolean {
	const protectedSet = new Set(protectedPaths);
	return pathCandidates(rawPath, cwd).some((path) => protectedSet.has(path));
}

export function protectHeimdallConfigPaths(
	config: NormalizedSandboxConfig,
	protectedPaths: string[],
): NormalizedSandboxConfig {
	if (process.env.HEIMDALL_PROTECT_CONFIG_OVERLAY === "0") return config;

	const paths = { ...config.paths };
	for (const path of protectedPaths) {
		// ponytail: synthetic empty file hides config contents; broader parent masking if existence must be hidden too.
		paths[path] = [...(paths[path] ?? []), { path, content: "" }];
	}
	return { ...config, paths };
}

function resolveToolOutputPath(rawSearchPath: unknown, cwd: string, outputPath: string): string {
	const cleanOutputPath = outputPath.replace(/\/$/, "");
	if (cleanOutputPath.startsWith("/")) return cleanOutputPath;

	const searchRoot = resolveSandboxPath(
		typeof rawSearchPath === "string" && rawSearchPath ? rawSearchPath : ".",
		cwd,
	);
	let base = searchRoot;
	try {
		if (!lstatSync(searchRoot).isDirectory()) base = dirname(searchRoot);
	} catch {
		// Keep searchRoot as the base; tool output is already best-effort text.
	}
	return resolve(base, cleanOutputPath);
}

function isToolNoticeLine(line: string): boolean {
	return /^\[(?:\d+ .* limit|Truncated:|Showing )/.test(line.trim());
}

function filterLines(
	text: string,
	isProtectedLine: (line: string) => boolean,
	emptyText: string,
): string {
	const lines = text.split("\n");
	let changed = false;
	const kept = lines.filter((line) => {
		const drop = isProtectedLine(line);
		if (drop) changed = true;
		return !drop;
	});
	if (!changed) return text;

	const withoutStaleNotices = kept.filter((line) => !isToolNoticeLine(line));
	const visible = withoutStaleNotices.filter((line) => line.trim().length > 0);
	return visible.length > 0 ? withoutStaleNotices.join("\n").trimEnd() : emptyText;
}

function isProtectedOutputPath(
	rawSearchPath: unknown,
	outputPath: string,
	cwd: string,
	protectedPaths: string[],
): boolean {
	return isProtectedHeimdallConfigPath(
		resolveToolOutputPath(rawSearchPath, cwd, outputPath),
		cwd,
		protectedPaths,
	);
}

function grepOutputPath(line: string): string | null {
	const match = line.match(/^(.+?)(?::\d+:|-\d+-)/);
	return match?.[1] ?? null;
}

export function filterProtectedHeimdallConfigOutput(
	toolName: "grep" | "find" | "ls",
	text: string,
	input: Record<string, unknown>,
	cwd: string,
	protectedPaths: string[],
): string {
	if (protectedPaths.length === 0) return text;

	if (toolName === "grep") {
		return filterLines(text, (line) => {
			const outputPath = grepOutputPath(line);
			return outputPath !== null && isProtectedOutputPath(input.path, outputPath, cwd, protectedPaths);
		}, "No matches found");
	}

	if (toolName === "find") {
		return filterLines(text, (line) => (
			line.trim().length > 0 &&
			!isToolNoticeLine(line) &&
			isProtectedOutputPath(input.path, line.trim(), cwd, protectedPaths)
		), "No files found matching pattern");
	}

	return filterLines(text, (line) => (
		line.trim().length > 0 &&
		!isToolNoticeLine(line) &&
		isProtectedOutputPath(input.path, line.trim(), cwd, protectedPaths)
	), "(empty directory)");
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

export interface ResolverSupportMounts {
	dirs: string[];
	mount?: { source: string; target: string };
}

function isMounted(path: string, mountedPrefixes: Set<string>): boolean {
	for (const prefix of mountedPrefixes) {
		if (path === prefix || path.startsWith(`${prefix}/`)) return true;
	}
	return false;
}

function parentDirs(path: string): string[] {
	const dirs: string[] = [];
	let current = dirname(path);
	while (current !== "/" && current !== ".") {
		dirs.unshift(current);
		current = dirname(current);
	}
	return dirs;
}

export function resolverSupportMounts(
	resolvPath: string,
	realPath: string,
	mountedPrefixes: Set<string>,
): ResolverSupportMounts {
	if (realPath === resolvPath || isMounted(realPath, mountedPrefixes)) {
		return { dirs: [] };
	}

	return {
		dirs: parentDirs(realPath).filter((dir) => !isMounted(dir, mountedPrefixes)),
		mount: { source: realPath, target: realPath },
	};
}

function hostResolverSupportMounts(config: NormalizedSandboxConfig, cwd: string, mountedPrefixes: Set<string>): ResolverSupportMounts {
	if (config.network !== "host") return { dirs: [] };
	if (getSandboxPathAccess(config, cwd, "/etc/resolv.conf").access === "none") return { dirs: [] };

	try {
		if (!lstatSync("/etc/resolv.conf").isSymbolicLink()) return { dirs: [] };
		return resolverSupportMounts("/etc/resolv.conf", realpathSync("/etc/resolv.conf"), mountedPrefixes);
	} catch {
		return { dirs: [] };
	}
}

function syntheticFilename(target: string): string {
	return target.replace(/[^a-zA-Z0-9._-]/g, "_") || "synthetic";
}

function bwrapBindRoot(): string | null {
	const raw = process.env.HEIMDALL_BWRAP_BIND_ROOT;
	if (!raw) return null;

	const root = raw.replace(/\/+$/, "") || "/";
	if (!root.startsWith("/") || root === "/") {
		throw new Error("Invalid HEIMDALL_BWRAP_BIND_ROOT: expected an absolute path below /");
	}
	return root;
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
	const bindKernelFs = process.env.HEIMDALL_BWRAP_BIND_KERNEL_FS === "1";
	const bindRoot = bwrapBindRoot();

	args.push("--tmpfs", "/");
	if (bindKernelFs) {
		args.push("--dev-bind", "/dev", "/dev");
	} else {
		args.push("--dev", "/dev");
	}

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
				writeMounts.push(bindRoot && pathMatchesPrefix(target, bindRoot) ? bindRoot : target);
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
		mountedReadPrefixes.add(target);
	}

	const resolverMounts = hostResolverSupportMounts(config, cwd, mountedReadPrefixes);
	for (const dir of resolverMounts.dirs) {
		args.push("--dir", dir);
	}
	if (resolverMounts.mount) {
		args.push("--ro-bind", resolverMounts.mount.source, resolverMounts.mount.target);
	}

	for (const { source, target } of dedupeMounts(overlayReadMounts)) {
		args.push("--ro-bind", source, target);
	}

	if (config.userNamespace) args.push("--unshare-user");
	args.push("--unshare-pid");
	if (config.network === "none") args.push("--unshare-net");
	if (bindKernelFs) {
		args.push("--ro-bind", "/proc", "/proc");
	} else {
		args.push("--proc", "/proc");
	}
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

function protectedConfigBashBlockReason(reason: string): string {
	return `Blocked: bash cannot run because Heimdall Protected Configuration cannot be hidden without an active sandbox (${reason}).`;
}

function createBlockedBashOps(reason: string): BashOperations {
	return {
		async exec() {
			throw new Error(protectedConfigBashBlockReason(reason));
		},
	};
}

export function registerSandboxGuard(pi: ExtensionAPI, getHeimdallConfig: () => HeimdallConfig): void {
	let sandboxConfig: NormalizedSandboxConfig | null = null;
	let sandboxCwd = process.cwd();
	let bwrapAvailable = false;
	let sandboxUnavailableReason = "sandbox is not active";
	let protectedConfigPaths = heimdallConfigPaths(sandboxCwd);

	pi.registerFlag("no-sandbox", {
		description: "Disable OS-level sandboxing for bash commands",
		type: "boolean",
		default: false,
	});

	pi.on("session_start", async (_event, ctx) => {
		sandboxCwd = ctx.cwd;
		protectedConfigPaths = heimdallConfigPaths(ctx.cwd);
		const noSandbox = pi.getFlag("no-sandbox") as boolean;
		if (noSandbox) {
			sandboxConfig = null;
			bwrapAvailable = false;
			sandboxUnavailableReason = "disabled via --no-sandbox";
			ctx.ui.notify("heimdall sandbox: disabled via --no-sandbox", "warning");
			return;
		}

		const config = protectHeimdallConfigPaths(
			normalizeSandboxConfig(getHeimdallConfig().sandbox as SandboxConfig | undefined),
			protectedConfigPaths,
		);
		sandboxConfig = null;
		bwrapAvailable = false;
		sandboxUnavailableReason = "disabled by configuration";
		if (!config.enabled) {
			return;
		}

		if (process.platform !== "linux") {
			sandboxUnavailableReason = `not supported on ${process.platform}`;
			ctx.ui.notify(
				`heimdall sandbox: not supported on ${process.platform} (Linux only)`,
				"warning",
			);
			return;
		}

		const bwrap = findBwrap();
		if (!bwrap) {
			sandboxUnavailableReason = "bubblewrap not found";
			ctx.ui.notify(
				"heimdall sandbox: bwrap not found. Install bubblewrap to enable sandboxing.",
				"warning",
			);
			return;
		}

		bwrapAvailable = true;
		sandboxConfig = config;
		sandboxUnavailableReason = "";

		const entries = Object.values(config.paths).flat();
		const writeCount = entries.filter((entry) => entry.mode === "write").length;
		const envIcon = config.env.allow === null ? "E∞" : `E${config.env.allow.length}`;
		const networkIcon = config.network === "host" ? "↔" : "⊘";
		const userNamespaceIcon = config.userNamespace ? "U" : "U⊘";
		const theme = ctx.ui.theme;
		ctx.ui.setStatus(
			"heimdall-sandbox",
			[
				theme.fg("accent", "🛡"),
				theme.fg("success", `✎${writeCount}`),
				theme.fg("muted", envIcon),
				theme.fg(config.network === "host" ? "success" : "warning", networkIcon),
				theme.fg(config.userNamespace ? "success" : "warning", userNamespaceIcon),
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
				throw new Error(protectedConfigBashBlockReason(sandboxUnavailableReason));
			}

			const sandboxedBash = createBashTool(sandboxCwd, {
				operations: createSandboxedBashOps(sandboxConfig, sandboxCwd),
			});
			return sandboxedBash.execute(id, params, signal, onUpdate);
		},
	});

	pi.on("user_bash", () => {
		if (!sandboxConfig || !bwrapAvailable) {
			return {
				operations: createBlockedBashOps(sandboxUnavailableReason),
			};
		}
		return {
			operations: createSandboxedBashOps(sandboxConfig, sandboxCwd),
		};
	});

	pi.on("tool_call", async (event, ctx) => {
		const block = (operation: "read" | "write", path: string) => {
			const reason =
				`Blocked: ${event.toolName} attempted to ${operation} "${path}" outside the heimdall sandbox path policy. ` +
				`Use a path mounted with ${operation === "write" ? 'mode "write"' : "read access"} in sandbox.paths, or ask the user to adjust .pi/heimdall.json.`;
			if (ctx.hasUI) ctx.ui.notify(`heimdall sandbox: blocked ${event.toolName} ${path}`, "warning");
			return { block: true as const, reason };
		};

		const input = event.input as Record<string, unknown>;
		const path = typeof input.path === "string" ? input.path : ".";

		if (isToolCallEventType("bash", event) && (!sandboxConfig || !bwrapAvailable)) {
			return {
				block: true as const,
				reason: protectedConfigBashBlockReason(sandboxUnavailableReason),
			};
		}

		const blockProtectedConfig = (operation: "read" | "write", protectedPath: string) => {
			const reason = `Blocked: ${event.toolName} attempted to ${operation} Heimdall Protected Configuration.`;
			if (ctx.hasUI) ctx.ui.notify(`heimdall sandbox: blocked ${event.toolName} ${protectedPath}`, "warning");
			return { block: true as const, reason };
		};

		if (typeof input.path === "string" && isProtectedHeimdallConfigPath(input.path, sandboxCwd, protectedConfigPaths)) {
			if (isToolCallEventType("read", event) || event.toolName === "grep" || event.toolName === "find" || event.toolName === "ls") {
				return blockProtectedConfig("read", input.path);
			}
			if (isToolCallEventType("write", event) || isToolCallEventType("edit", event)) {
				return blockProtectedConfig("write", input.path);
			}
		}

		if (!sandboxConfig || !sandboxConfig.enabled) return undefined;

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

	pi.on("tool_result", async (event) => {
		if (!isGrepToolResult(event) && !isFindToolResult(event) && !isLsToolResult(event)) return undefined;

		let changed = false;
		const content = event.content.map((part) => {
			if (part.type !== "text") return part;
			const text = filterProtectedHeimdallConfigOutput(
				event.toolName,
				part.text,
				event.input,
				sandboxCwd,
				protectedConfigPaths,
			);
			if (text === part.text) return part;
			changed = true;
			return { ...part, text };
		});

		return changed ? { content } : undefined;
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
				`User namespace: ${sandboxConfig.userNamespace ? "enabled" : "disabled"}`,
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
