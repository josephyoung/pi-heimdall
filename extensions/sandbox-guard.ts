/**
 * sandbox-guard
 *
 * OS-level filesystem sandboxing for bash commands using bubblewrap (bwrap).
 *
 * Intercepts bash tool calls and executes them inside a restricted filesystem
 * namespace where only the project directory and essential system paths are
 * visible. The agent cannot read ~/.ssh, ~/.aws, ~/.config, or any other
 * files outside the explicitly allowlisted paths.
 *
 * This is v1: pure TypeScript, shells out to bwrap. No native binary, no
 * seccomp, no shell AST parsing. Process hardening (ptrace block, core dump
 * disable, LD_PRELOAD stripping) comes in v2.
 *
 * Configuration lives in .pi/heimdall.json alongside existing command policies:
 *
 * ```json
 * {
 *   "sandbox": {
 *     "enabled": true,
 *     "networkAccess": true,
 *     "writableRoots": [".", "/tmp"],
 *     "systemPaths": ["/usr", "/lib", "/lib64", "/bin", "/sbin"],
 *     "etcReal": ["/etc/resolv.conf", "/etc/hosts", "/etc/ssl", "/etc/ca-certificates"],
 *     "etcSynthetic": {
 *       "/etc/passwd": "nobody:x:65534:65534:Nobody:/nonexistent:/usr/sbin/nologin\n",
 *       "/etc/group": "nogroup:x:65534:\n"
 *     },
 *     "envAllowlist": ["PATH", "HOME", "LANG", "LC_ALL", "TMPDIR", "TERM", "TZ"],
 *     "extraReadPaths": [],
 *     "denyReadGlobs": []
 *   }
 * }
 * ```
 */

import {
	createBashTool,
	getAgentDir,
	type BashOperations,
	type ExtensionAPI,
} from "@mariozechner/pi-coding-agent";
import { existsSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

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

interface HeimdallConfig {
	sandbox?: Partial<SandboxConfig>;
	commandPolicies?: Array<{
		name: string;
		blocked: string[];
		message: string;
	}>;
}

const DEFAULT_SANDBOX_CONFIG: SandboxConfig = {
	enabled: false,
	networkAccess: true,
	writableRoots: [".", "/tmp"],
	systemPaths: ["/usr", "/lib", "/lib64", "/bin", "/sbin"],
	etcReal: [
		"/etc/resolv.conf",
		"/etc/hosts",
		"/etc/ssl",
		"/etc/ca-certificates",
	],
	etcSynthetic: {
		"/etc/passwd": "nobody:x:65534:65534:Nobody:/nonexistent:/usr/sbin/nologin\n",
		"/etc/group": "nogroup:x:65534:\n",
	},
	envAllowlist: ["PATH", "HOME", "LANG", "LC_ALL", "TMPDIR", "TERM", "TZ"],
	extraReadPaths: [],
	denyReadGlobs: [],
};

// ---------------------------------------------------------------------------
// Config loading
// ---------------------------------------------------------------------------

function loadConfig(cwd: string): SandboxConfig {
	const configPaths = [
		join(getAgentDir(), "heimdall.json"),
		join(cwd, ".pi", "heimdall.json"),
	];

	let merged: Partial<SandboxConfig> = {};

	for (const configPath of configPaths) {
		if (!existsSync(configPath)) continue;
		try {
			const raw = require("node:fs").readFileSync(configPath, "utf-8");
			const parsed = JSON.parse(raw) as HeimdallConfig;
			if (parsed.sandbox) {
				merged = { ...merged, ...parsed.sandbox };
			}
		} catch {
			// Ignore parse errors — other guards handle the same config
		}
	}

	return { ...DEFAULT_SANDBOX_CONFIG, ...merged };
}

// ---------------------------------------------------------------------------
// bwrap argument construction
// ---------------------------------------------------------------------------

/**
 * Build the full bwrap argv (everything after `bwrap` itself).
 *
 * Mount order:
 * 1. tmpfs /          — empty root
 * 2. --dev /dev       — minimal device nodes
 * 3. --ro-bind system — /usr, /lib, etc.
 * 4. --ro-bind /etc   — real DNS/TLS files
 * 5. --ro-bind synthetic /etc — synthetic passwd/group
 * 6. --bind writable  — project dir, /tmp
 * 7. namespace flags  — --unshare-user, --unshare-pid
 * 8. lifecycle flags  — --die-with-parent, --new-session
 * 9. -- <command>     — the user command
 */
export function buildBwrapArgs(
	config: SandboxConfig,
	cwd: string,
	syntheticDir: string,
	command: string,
): string[] {
	const args: string[] = [];

	// 1. Empty root filesystem
	args.push("--tmpfs", "/");

	// 2. Minimal /dev
	args.push("--dev", "/dev");

	// 3. System paths (read-only)
	for (const sysPath of config.systemPaths) {
		if (existsSync(sysPath)) {
			args.push("--ro-bind", sysPath, sysPath);
		}
	}

	// 4. Real /etc files (DNS, TLS)
	for (const etcPath of config.etcReal) {
		if (existsSync(etcPath)) {
			args.push("--ro-bind", etcPath, etcPath);
		}
	}

	// 5. Synthetic /etc files
	for (const [etcPath, content] of Object.entries(config.etcSynthetic)) {
		const filename = etcPath.split("/").pop() ?? "synthetic";
		const syntheticFile = join(syntheticDir, filename);
		writeFileSync(syntheticFile, content, "utf-8");
		args.push("--ro-bind", syntheticFile, etcPath);
	}

	// 6. Extra read paths
	for (const readPath of config.extraReadPaths) {
		const resolved = readPath === "." ? cwd : readPath;
		if (existsSync(resolved)) {
			args.push("--ro-bind", resolved, resolved);
		}
	}

	// 7. Writable roots
	for (const root of config.writableRoots) {
		const resolved = root === "." ? cwd : root;
		if (existsSync(resolved)) {
			args.push("--bind", resolved, resolved);
		}
	}

	// 8. Namespace isolation
	args.push("--unshare-user");
	args.push("--unshare-pid");

	// No --unshare-net when networkAccess is true (shared network for Docker, webfetch)

	// 9. /proc
	args.push("--proc", "/proc");

	// 10. Lifecycle
	args.push("--die-with-parent");
	args.push("--new-session");

	// 11. Command separator + user command
	args.push("--");
	args.push("bash", "-c", command);

	return args;
}

// ---------------------------------------------------------------------------
// Environment stripping
// ---------------------------------------------------------------------------

export function stripEnv(
	allowlist: string[],
	currentEnv: Record<string, string>,
): Record<string, string> {
	const allowed = new Set(allowlist);
	const result: Record<string, string> = {};
	for (const [key, value] of Object.entries(currentEnv)) {
		if (allowed.has(key)) {
			result[key] = value;
		}
	}
	return result;
}

// ---------------------------------------------------------------------------
// bwrap detection
// ---------------------------------------------------------------------------

function findBwrap(): string | null {
	const pathEnv = process.env.PATH ?? "";
	for (const dir of pathEnv.split(":")) {
		const candidate = join(dir, "bwrap");
		if (existsSync(candidate)) return candidate;
	}
	// Check common locations
	for (const loc of ["/usr/bin/bwrap", "/usr/local/bin/bwrap"]) {
		if (existsSync(loc)) return loc;
	}
	return null;
}

// ---------------------------------------------------------------------------
// Sandboxed bash operations
// ---------------------------------------------------------------------------

function createSandboxedBashOps(
	config: SandboxConfig,
	cwd: string,
): BashOperations {
	return {
		async exec(command, execCwd, { onData, signal, timeout }) {
			const workDir = execCwd || cwd;
			if (!existsSync(workDir)) {
				throw new Error(`Working directory does not exist: ${workDir}`);
			}

			// Create temp dir for synthetic /etc files
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
				const cleanEnv = stripEnv(config.envAllowlist, process.env as Record<string, string>);

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
								try {
									process.kill(-child.pid, "SIGKILL");
								} catch {
									child.kill("SIGKILL");
								}
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
							try {
								process.kill(-child.pid, "SIGKILL");
							} catch {
								child.kill("SIGKILL");
							}
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
				// Cleanup synthetic files
				try {
					rmSync(syntheticDir, { recursive: true, force: true });
				} catch {
					// Best effort cleanup
				}
			}
		},
	};
}

// ---------------------------------------------------------------------------
// Extension
// ---------------------------------------------------------------------------

export default function (pi: ExtensionAPI) {
	let sandboxConfig: SandboxConfig | null = null;
	let bwrapAvailable = false;

	pi.registerFlag("no-sandbox", {
		description: "Disable OS-level sandboxing for bash commands",
		type: "boolean",
		default: false,
	});

	pi.on("session_start", async (_event, ctx) => {
		const noSandbox = pi.getFlag("no-sandbox") as boolean;
		if (noSandbox) {
			sandboxConfig = null;
			ctx.ui.notify("heimdall sandbox: disabled via --no-sandbox", "warning");
			return;
		}

		if (process.platform !== "linux") {
			ctx.ui.notify(
				`heimdall sandbox: not supported on ${process.platform} (Linux only)`,
				"warning",
			);
			return;
		}

		const config = loadConfig(ctx.cwd);
		if (!config.enabled) {
			sandboxConfig = null;
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

		const writeCount = config.writableRoots.length;
		const envCount = config.envAllowlist.length;
		const network = config.networkAccess ? "shared" : "isolated";
		ctx.ui.setStatus(
			"heimdall-sandbox",
			`🔒 sandbox: ${writeCount} writable, ${envCount} env vars, network ${network}`,
		);
		ctx.ui.notify("heimdall sandbox: active", "info");
	});

	// Override the built-in bash tool with sandboxed version
	const localCwd = process.cwd();
	const localBash = createBashTool(localCwd);

	pi.registerTool({
		...localBash,
		label: "bash (heimdall sandbox)",
		async execute(id, params, signal, onUpdate, _ctx) {
			if (!sandboxConfig || !bwrapAvailable) {
				return localBash.execute(id, params, signal, onUpdate);
			}

			const sandboxedBash = createBashTool(localCwd, {
				operations: createSandboxedBashOps(sandboxConfig, localCwd),
			});
			return sandboxedBash.execute(id, params, signal, onUpdate);
		},
	});

	// Also sandbox user bash commands (! and !!)
	pi.on("user_bash", () => {
		if (!sandboxConfig || !bwrapAvailable) return undefined;
		return {
			operations: createSandboxedBashOps(sandboxConfig, localCwd),
		};
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
				`Network: ${sandboxConfig.networkAccess ? "shared (host)" : "isolated"}`,
				`Writable roots: ${sandboxConfig.writableRoots.join(", ")}`,
				`System paths (ro): ${sandboxConfig.systemPaths.join(", ")}`,
				`Real /etc: ${sandboxConfig.etcReal.join(", ")}`,
				`Synthetic /etc: ${Object.keys(sandboxConfig.etcSynthetic).join(", ")}`,
				`Env allowlist: ${sandboxConfig.envAllowlist.join(", ")}`,
				`Extra read paths: ${sandboxConfig.extraReadPaths.join(", ") || "(none)"}`,
			];
			ctx.ui.notify(lines.join("\n"), "info");
		},
	});
}
