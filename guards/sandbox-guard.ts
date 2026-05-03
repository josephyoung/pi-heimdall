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
	type BashOperations,
	type ExtensionAPI,
} from "@mariozechner/pi-coding-agent";
import { existsSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import type { HeimdallConfig, SandboxConfig } from "./types.js";

const DEFAULT_SANDBOX_CONFIG: SandboxConfig = {
	enabled: false,
	networkAccess: true,
	writableRoots: [".", "/tmp"],
	systemPaths: ["/usr", "/lib", "/lib64", "/bin", "/sbin"],
	etcReal: ["/etc/resolv.conf", "/etc/hosts", "/etc/ssl", "/etc/ca-certificates"],
	etcSynthetic: {
		"/etc/passwd": "nobody:x:65534:65534:Nobody:/nonexistent:/usr/sbin/nologin\n",
		"/etc/group": "nogroup:x:65534:\n",
	},
	envAllowlist: ["PATH", "HOME", "LANG", "LC_ALL", "TMPDIR", "TERM", "TZ"],
	extraReadPaths: [],
	denyReadGlobs: [],
};

export function buildBwrapArgs(
	config: SandboxConfig,
	cwd: string,
	syntheticDir: string,
	command: string,
): string[] {
	const args: string[] = [];

	args.push("--tmpfs", "/");
	args.push("--dev", "/dev");

	for (const sysPath of config.systemPaths) {
		if (existsSync(sysPath)) {
			args.push("--ro-bind", sysPath, sysPath);
		}
	}

	for (const etcPath of config.etcReal) {
		if (existsSync(etcPath)) {
			args.push("--ro-bind", etcPath, etcPath);
		}
	}

	for (const [etcPath, content] of Object.entries(config.etcSynthetic)) {
		const filename = etcPath.split("/").pop() ?? "synthetic";
		const syntheticFile = join(syntheticDir, filename);
		writeFileSync(syntheticFile, content, "utf-8");
		args.push("--ro-bind", syntheticFile, etcPath);
	}

	for (const readPath of config.extraReadPaths) {
		const resolved = readPath === "." ? cwd : readPath;
		if (existsSync(resolved)) {
			args.push("--ro-bind", resolved, resolved);
		}
	}

	for (const root of config.writableRoots) {
		const resolved = root === "." ? cwd : root;
		if (existsSync(resolved)) {
			args.push("--bind", resolved, resolved);
		}
	}

	args.push("--unshare-user");
	args.push("--unshare-pid");
	args.push("--proc", "/proc");
	args.push("--die-with-parent");
	args.push("--new-session");
	args.push("--");
	args.push("bash", "-c", command);

	return args;
}

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

function createSandboxedBashOps(config: SandboxConfig, cwd: string): BashOperations {
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

export function registerSandboxGuard(pi: ExtensionAPI, heimdallConfig: HeimdallConfig): void {
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

		const sandbox = heimdallConfig.sandbox;
		const config: SandboxConfig = { ...DEFAULT_SANDBOX_CONFIG, ...(sandbox ?? {}) };
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
