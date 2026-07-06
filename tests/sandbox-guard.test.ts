import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { existsSync, mkdirSync, rmSync, readFileSync, symlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
	buildBwrapArgs,
	filterEnv,
	filterProtectedHeimdallConfigOutput,
	getSandboxPathAccess,
	heimdallConfigPaths,
	isProtectedHeimdallConfigPath,
	normalizeSandboxConfig,
	protectHeimdallConfigPaths,
	registerSandboxGuard,
	resolverSupportMounts,
	stripEnv,
} from "../guards/sandbox-guard";
import type { HeimdallConfig } from "../guards/types";

function sandboxGuardHarness(cwd: string, config: HeimdallConfig) {
	const handlers: Record<string, Array<(event: any, ctx: any) => any>> = {};
	let bash: any;
	const ctx = {
		cwd,
		hasUI: false,
		ui: {
			notify: () => undefined,
			setStatus: () => undefined,
			theme: {
				fg: (_kind: string, text: string) => text,
			},
		},
	};
	const pi = {
		registerFlag: () => undefined,
		getFlag: () => false,
		registerTool: (tool: any) => {
			if (tool.name === "bash") bash = tool;
		},
		registerCommand: () => undefined,
		on: (event: string, handler: (event: any, ctx: any) => any) => {
			handlers[event] = [...(handlers[event] ?? []), handler];
		},
	};

	registerSandboxGuard(pi as any, () => config);

	return {
		get bash() {
			return bash;
		},
		startSession: () => handlers.session_start[0]({}, ctx),
		toolCall: (toolName: string, input: Record<string, unknown>) => (
			handlers.tool_call[0]({ type: "tool_call", toolCallId: "1", toolName, input }, ctx)
		),
		toolResult: (toolName: string, input: Record<string, unknown>, text: string) => (
			handlers.tool_result[0]({
				type: "tool_result",
				toolCallId: "1",
				toolName,
				input,
				content: [{ type: "text", text }],
				isError: false,
				details: undefined,
			}, ctx)
		),
	};
}

describe("sandbox-guard", () => {
	describe("filterEnv", () => {
		it("inherits env by default and applies deny globs", () => {
			const env = {
				PATH: "/usr/bin",
				HOME: "/home/user",
				AWS_SECRET_ACCESS_KEY: "super-secret-key",
				DATABASE_URL: "postgres://user:pass@localhost/db",
				GITHUB_TOKEN: "ghp_abc123",
			};

			const result = filterEnv({ allow: null, deny: ["AWS_*", "GITHUB_TOKEN"] }, env);

			expect(result).toEqual({
				PATH: "/usr/bin",
				HOME: "/home/user",
				DATABASE_URL: "postgres://user:pass@localhost/db",
			});
		});

		it("allows an explicit allow list", () => {
			const env = { PATH: "/usr/bin", HOME: "/home/user", SECRET: "value" };
			const result = filterEnv({ allow: ["PATH", "HOME"], deny: null }, env);
			expect(result).toEqual({ PATH: "/usr/bin", HOME: "/home/user" });
		});

		it("lets deny override allow", () => {
			const env = { PATH: "/usr/bin", GITHUB_TOKEN: "token" };
			const result = filterEnv({ allow: ["PATH", "GITHUB_TOKEN"], deny: ["*_TOKEN"] }, env);
			expect(result).toEqual({ PATH: "/usr/bin" });
		});

		it("treats an empty allow list as no inherited env", () => {
			const env = { PATH: "/usr/bin" };
			const result = filterEnv({ allow: [], deny: null, set: {} }, env);
			expect(result).toEqual({});
		});

		it("applies set overrides after allow and deny", () => {
			const env = { PATH: "/usr/bin", GITHUB_TOKEN: "token", HOME: "/home/user" };
			const result = filterEnv({
				allow: ["PATH", "GITHUB_TOKEN", "HOME"],
				deny: ["*_TOKEN"],
				set: {
					PATH: "/custom/bin:/usr/bin",
					GITHUB_TOKEN: "explicit",
					HOME: null,
				},
			}, env);
			expect(result).toEqual({
				PATH: "/custom/bin:/usr/bin",
				GITHUB_TOKEN: "explicit",
			});
		});

		it("keeps stripEnv compatibility", () => {
			const result = stripEnv(["PATH"], { PATH: "/usr/bin", SECRET: "value" });
			expect(result).toEqual({ PATH: "/usr/bin" });
		});
	});

	describe("normalizeSandboxConfig", () => {
		it("defaults to disabled", () => {
			expect(normalizeSandboxConfig().enabled).toBe(false);
		});

		it("defaults user namespace isolation to enabled", () => {
			expect(normalizeSandboxConfig({ enabled: true }).userNamespace).toBe(true);
		});

		it("allows disabling user namespace isolation", () => {
			expect(normalizeSandboxConfig({ enabled: true, userNamespace: false }).userNamespace).toBe(false);
		});

		it("denies sensitive home paths by default", () => {
			const previousHome = process.env.HOME;
			process.env.HOME = "/home/user";

			try {
				const config = normalizeSandboxConfig({ enabled: true });
				const privatePaths = [
					"/home/user/Private",
					"/home/user/.ssh",
					"/home/user/.config",
					"/home/user/.aws",
					"/home/user/.azure",
					"/home/user/.gcloud",
					"/home/user/.oci",
					"/home/user/.kube",
					"/home/user/.docker",
					"/home/user/.gnupg",
					"/home/user/.sops",
					"/home/user/.age",
					"/home/user/.password-store",
					"/home/user/.terraform.d",
					"/home/user/.vault-token",
					"/home/user/.netrc",
					"/home/user/.npmrc",
					"/home/user/.pypirc",
					"/home/user/.cargo/credentials",
					"/home/user/.cargo/credentials.toml",
					"/home/user/.claude",
					"/home/user/.codex",
					"/home/user/.forge",
					"/home/user/.cursor",
					"/home/user/.windsurf",
					"/home/user/.openai",
					"/home/user/.anthropic",
				];

				for (const path of privatePaths) {
					expect(config.paths[path]).toEqual([{ mode: "deny" }]);
					expect(getSandboxPathAccess(config, "/repo", `${path}/secret`).access).toBe("none");
				}
			} finally {
				if (previousHome === undefined) {
					delete process.env.HOME;
				} else {
					process.env.HOME = previousHome;
				}
			}
		});

		it("uses simplified paths and env schema", () => {
			const config = normalizeSandboxConfig({
				enabled: true,
				network: "none",
				paths: {
					"./src": { mode: "write" },
					"/etc": [{ path: "/etc/hosts" }],
				},
				env: { allow: ["PATH"], deny: ["*_TOKEN"] },
			});

			expect(config.enabled).toBe(true);
			expect(config.network).toBe("none");
			expect(config.paths["./src"]).toEqual([{ mode: "write" }]);
			expect(config.paths["/etc"]).toEqual([{ path: "/etc/hosts" }]);
			expect(config.env).toEqual({ allow: ["PATH"], deny: ["*_TOKEN"], set: {} });
		});

		it("maps legacy config to the new internal shape", () => {
			const config = normalizeSandboxConfig({
				enabled: true,
				networkAccess: false,
				writableRoots: [".", "/tmp"],
				systemPaths: ["/usr"],
				etcReal: ["/etc/hosts"],
				etcSynthetic: { "/etc/passwd": "synthetic" },
				envAllowlist: ["PATH"],
			});

			expect(config.network).toBe("none");
			expect(config.paths["."]).toContainEqual({ mode: "write" });
			expect(config.paths["/usr"]).toEqual([{}]);
			expect(config.paths["/etc"]).toEqual([
				{ path: "/etc/hosts" },
				{ path: "/etc/passwd", content: "synthetic" },
			]);
			expect(config.env.allow).toEqual(["PATH"]);
		});
	});

	describe("getSandboxPathAccess", () => {
		const cwd = "/repo";

		it("allows reads under read prefixes", () => {
			const config = normalizeSandboxConfig({ enabled: true, paths: { "./docs": {} } });
			expect(getSandboxPathAccess(config, cwd, "./docs/guide.md").access).toBe("read");
		});

		it("allows writes under write prefixes", () => {
			const config = normalizeSandboxConfig({ enabled: true, paths: { "./src": { mode: "write" } } });
			expect(getSandboxPathAccess(config, cwd, "./src/main.ts").access).toBe("write");
		});

		it("lets specific read paths override writable prefixes", () => {
			const config = normalizeSandboxConfig({
				enabled: true,
				paths: {
					".": [
						{ mode: "write" },
						{ path: "./.git" },
					],
				},
			});
			expect(getSandboxPathAccess(config, cwd, "./package.json").access).toBe("write");
			expect(getSandboxPathAccess(config, cwd, "./.git").access).toBe("read");
		});

		it("marks synthetic paths so host reads can be blocked", () => {
			const config = normalizeSandboxConfig({
				enabled: true,
				paths: { "/etc": [{ path: "/etc/passwd", content: "synthetic" }] },
			});
			expect(getSandboxPathAccess(config, cwd, "/etc/passwd")).toEqual({
				access: "read",
				synthetic: true,
				matchedPath: "/etc/passwd",
			});
		});

		it("denies paths outside configured prefixes", () => {
			const config = normalizeSandboxConfig({ enabled: true, paths: { "./src": { mode: "write" } } });
			expect(getSandboxPathAccess(config, cwd, "/home/user/.ssh/id_rsa").access).toBe("none");
		});
	});

	describe("protected Heimdall configuration", () => {
		let projectDir: string;
		let agentDir: string;
		let syntheticDir: string;
		let projectConfig: string;
		let agentConfig: string;
		let protectedPaths: string[];

		beforeEach(() => {
			const suffix = `${Date.now()}-${Math.random().toString(16).slice(2)}`;
			projectDir = join(tmpdir(), `heimdall-test-project-${suffix}`);
			agentDir = join(tmpdir(), `heimdall-test-agent-${suffix}`);
			syntheticDir = join(tmpdir(), `heimdall-test-synthetic-${suffix}`);
			projectConfig = join(projectDir, ".pi", "heimdall.json");
			agentConfig = join(agentDir, "heimdall.json");
			mkdirSync(join(projectDir, ".pi"), { recursive: true });
			mkdirSync(agentDir, { recursive: true });
			mkdirSync(syntheticDir, { recursive: true });
			writeFileSync(projectConfig, "{\"sandbox\":{\"enabled\":true}}\n");
			writeFileSync(agentConfig, "{\"disabled\":[\"secret-guard\"]}\n");
			protectedPaths = heimdallConfigPaths(projectDir, agentDir);
		});

		afterEach(() => {
			rmSync(projectDir, { recursive: true, force: true });
			rmSync(agentDir, { recursive: true, force: true });
			rmSync(syntheticDir, { recursive: true, force: true });
		});

		it("protects project and user config paths, including symlink aliases", () => {
			const link = join(projectDir, "linked-heimdall.json");
			symlinkSync(projectConfig, link);

			expect(protectedPaths).toContain(projectConfig);
			expect(protectedPaths).toContain(agentConfig);
			expect(isProtectedHeimdallConfigPath("./.pi/heimdall.json", projectDir, protectedPaths)).toBe(true);
			expect(isProtectedHeimdallConfigPath(link, projectDir, protectedPaths)).toBe(true);
		});

		it("uses synthetic protected entries to beat writable project policies", () => {
			const config = protectHeimdallConfigPaths(
				normalizeSandboxConfig({
					enabled: true,
					paths: {
						".": { mode: "write" },
						"./.pi/heimdall.json": { mode: "write" },
					},
				}),
				protectedPaths,
			);

			expect(getSandboxPathAccess(config, projectDir, "./package.json").access).toBe("write");
			expect(getSandboxPathAccess(config, projectDir, "./.pi/heimdall.json")).toEqual({
				access: "read",
				synthetic: true,
				matchedPath: projectConfig,
			});
		});

		it("mounts protected config as empty synthetic content for bash", () => {
			const config = protectHeimdallConfigPaths(
				normalizeSandboxConfig({ enabled: true, paths: { ".": { mode: "write" } } }),
				[projectConfig],
			);
			const args = buildBwrapArgs(config, projectDir, syntheticDir, "cat .pi/heimdall.json");
			const targetIdx = args.lastIndexOf(projectConfig);

			expect(args[targetIdx - 2]).toBe("--ro-bind");
			expect(readFileSync(args[targetIdx - 1], "utf8")).toBe("");
		});

		it("filters protected config matches from grep output without blocking broad search", () => {
			const output = [
				".pi/heimdall.json:1: {\"disabled\":[\"secret-guard\"]}",
				".pi/heimdall.json-2- context",
				"src/main.ts:3: safe",
				"",
				"[100 matches limit reached. Use limit=200 for more, or refine pattern]",
			].join("\n");

			expect(filterProtectedHeimdallConfigOutput("grep", output, { path: "." }, projectDir, protectedPaths))
				.toBe("src/main.ts:3: safe");
		});

		it("filters protected config paths from find output", () => {
			const output = [
				".pi/heimdall.json",
				".pi/taskplane.json",
				"",
				"[1000 results limit reached. Use limit=2000 for more, or refine pattern]",
			].join("\n");

			expect(filterProtectedHeimdallConfigOutput("find", output, { path: "." }, projectDir, protectedPaths))
				.toBe(".pi/taskplane.json");
			expect(filterProtectedHeimdallConfigOutput("find", ".pi/heimdall.json", { path: "." }, projectDir, protectedPaths))
				.toBe("No files found matching pattern");
		});

		it("filters protected config entries from ls output", () => {
			expect(filterProtectedHeimdallConfigOutput("ls", "heimdall.json\ntaskplane.json", { path: ".pi" }, projectDir, protectedPaths))
				.toBe("taskplane.json");
			expect(filterProtectedHeimdallConfigOutput("ls", "heimdall.json", { path: ".pi" }, projectDir, protectedPaths))
				.toBe("(empty directory)");
		});

		it("blocks registered file tool calls to protected config while allowing nearby .pi files", async () => {
			const harness = sandboxGuardHarness(projectDir, { sandbox: { enabled: false } });
			await harness.startSession();

			for (const toolName of ["read", "grep", "find", "ls"] as const) {
				const result = await harness.toolCall(toolName, { path: ".pi/heimdall.json" });
				expect(result).toMatchObject({
					block: true,
					reason: expect.stringContaining("Protected Configuration"),
				});
			}
			for (const toolName of ["write", "edit"] as const) {
				const result = await harness.toolCall(toolName, { path: ".pi/heimdall.json" });
				expect(result).toMatchObject({
					block: true,
					reason: expect.stringContaining("Protected Configuration"),
				});
			}

			expect(await harness.toolCall("read", { path: ".pi/taskplane.json" })).toBeUndefined();
		});

		it("filters protected config from registered search tool results", async () => {
			const harness = sandboxGuardHarness(projectDir, { sandbox: { enabled: false } });
			await harness.startSession();

			const result = await harness.toolResult("grep", { path: "." }, ".pi/heimdall.json:1: secret\nsrc/main.ts:2: safe");

			expect(result?.content).toEqual([{ type: "text", text: "src/main.ts:2: safe" }]);
		});

		it("blocks registered bash when the sandbox cannot hide protected config", async () => {
			const harness = sandboxGuardHarness(projectDir, { sandbox: { enabled: false } });
			await harness.startSession();

			expect(await harness.toolCall("bash", { command: "cat .pi/heimdall.json" })).toMatchObject({
				block: true,
				reason: expect.stringContaining("Protected Configuration cannot be hidden without an active sandbox"),
			});
			await expect(harness.bash.execute("1", { command: "cat .pi/heimdall.json" }, undefined, undefined, {}))
				.rejects.toThrow("Protected Configuration cannot be hidden without an active sandbox");
		});
	});

	describe("resolverSupportMounts", () => {
		it("adds parent dirs and real resolver bind for systemd-resolved symlinks", () => {
			const support = resolverSupportMounts(
				"/etc/resolv.conf",
				"/run/systemd/resolve/stub-resolv.conf",
				new Set(["/etc"]),
			);

			expect(support).toEqual({
				dirs: ["/run", "/run/systemd", "/run/systemd/resolve"],
				mount: {
					source: "/run/systemd/resolve/stub-resolv.conf",
					target: "/run/systemd/resolve/stub-resolv.conf",
				},
			});
		});

		it("does not add a bind when the resolver target is already mounted", () => {
			const support = resolverSupportMounts(
				"/etc/resolv.conf",
				"/run/systemd/resolve/stub-resolv.conf",
				new Set(["/etc", "/run"]),
			);

			expect(support).toEqual({ dirs: [] });
		});

		it("does not add a bind when resolv.conf is not a symlink", () => {
			const support = resolverSupportMounts("/etc/resolv.conf", "/etc/resolv.conf", new Set(["/etc"]));

			expect(support).toEqual({ dirs: [] });
		});

		it("allows explicit deny of resolv.conf to suppress resolver support", () => {
			const config = normalizeSandboxConfig({
				enabled: true,
				paths: { "/etc": [{ path: "/etc/resolv.conf", mode: "deny" }] },
			});

			expect(getSandboxPathAccess(config, "/repo", "/etc/resolv.conf").access).toBe("none");
		});
	});

	describe("buildBwrapArgs", () => {
		let syntheticDir: string;
		let projectDir: string;
		const expectArgSequence = (args: string[], sequence: string[]) => {
			expect(args.join("\0")).toContain(sequence.join("\0"));
		};

		beforeEach(() => {
			syntheticDir = join(tmpdir(), `heimdall-test-synthetic-${Date.now()}`);
			projectDir = join(tmpdir(), `heimdall-test-project-${Date.now()}`);
			mkdirSync(syntheticDir, { recursive: true });
			mkdirSync(projectDir, { recursive: true });
		});

		afterEach(() => {
			try {
				rmSync(syntheticDir, { recursive: true, force: true });
				rmSync(projectDir, { recursive: true, force: true });
			} catch {
				// best effort
			}
		});

		it("starts with tmpfs root and mounts minimal /dev", () => {
			const args = buildBwrapArgs(normalizeSandboxConfig({ enabled: true }), projectDir, syntheticDir, "echo hello");
			expect(args[0]).toBe("--tmpfs");
			expect(args[1]).toBe("/");
			const devIdx = args.indexOf("--dev");
			expect(args[devIdx + 1]).toBe("/dev");
		});

		it("keeps default bwrap device and proc mounts", () => {
			const previousBindKernelFs = process.env.HEIMDALL_BWRAP_BIND_KERNEL_FS;
			const previousBindRoot = process.env.HEIMDALL_BWRAP_BIND_ROOT;
			delete process.env.HEIMDALL_BWRAP_BIND_KERNEL_FS;
			delete process.env.HEIMDALL_BWRAP_BIND_ROOT;

			try {
				const config = normalizeSandboxConfig({ enabled: true, paths: { ".": { mode: "write" } } });
				const args = buildBwrapArgs(config, projectDir, syntheticDir, "echo hello");

				expect(args).toContain("--dev");
				expect(args).not.toContain("--dev-bind");
				expect(args).toContain("--proc");
				expect(args.join("\0")).not.toContain(["--ro-bind", "/proc", "/proc"].join("\0"));
				const bindIdx = args.indexOf("--bind");
				expect(args[bindIdx + 1]).toBe(projectDir);
				expect(args[bindIdx + 2]).toBe(projectDir);
			} finally {
				if (previousBindKernelFs === undefined) {
					delete process.env.HEIMDALL_BWRAP_BIND_KERNEL_FS;
				} else {
					process.env.HEIMDALL_BWRAP_BIND_KERNEL_FS = previousBindKernelFs;
				}
				if (previousBindRoot === undefined) {
					delete process.env.HEIMDALL_BWRAP_BIND_ROOT;
				} else {
					process.env.HEIMDALL_BWRAP_BIND_ROOT = previousBindRoot;
				}
			}
		});

		it("can bind host /dev and /proc instead of mounting nested kernel filesystems", () => {
			const previous = process.env.HEIMDALL_BWRAP_BIND_KERNEL_FS;
			process.env.HEIMDALL_BWRAP_BIND_KERNEL_FS = "1";

			try {
				const args = buildBwrapArgs(normalizeSandboxConfig({ enabled: true }), projectDir, syntheticDir, "echo hello");

				expectArgSequence(args, ["--dev-bind", "/dev", "/dev"]);
				expectArgSequence(args, ["--ro-bind", "/proc", "/proc"]);
				expect(args).not.toContain("--dev");
				expect(args).not.toContain("--proc");
			} finally {
				if (previous === undefined) {
					delete process.env.HEIMDALL_BWRAP_BIND_KERNEL_FS;
				} else {
					process.env.HEIMDALL_BWRAP_BIND_KERNEL_FS = previous;
				}
			}
		});

		it("mounts default system prefixes read-only when present", () => {
			const args = buildBwrapArgs(normalizeSandboxConfig({ enabled: true }), projectDir, syntheticDir, "echo hello");
			for (const sysPath of ["/usr", "/opt", "/srv", "/etc", "/nix/store", "/run/current-system/sw"]) {
				if (existsSync(sysPath)) {
					expect(args).toContain("--ro-bind");
					expect(args).toContain(sysPath);
				}
			}
		});

		it("mounts prefix entries as read-only by default", () => {
			const readDir = join(projectDir, "docs");
			mkdirSync(readDir);
			const config = normalizeSandboxConfig({ enabled: true, paths: { "./docs": {} } });
			const args = buildBwrapArgs(config, projectDir, syntheticDir, "echo hello");
			expect(args).toContain("--ro-bind");
			expect(args).toContain(readDir);
		});

		it("mounts write mode entries writable", () => {
			const srcDir = join(projectDir, "src");
			mkdirSync(srcDir);
			const config = normalizeSandboxConfig({ enabled: true, paths: { "./src": { mode: "write" } } });
			const args = buildBwrapArgs(config, projectDir, syntheticDir, "echo hello");
			expect(args).toContain("--bind");
			expect(args).toContain(srcDir);
		});

		it("mounts specific path entries read-only under their prefix", () => {
			const config = normalizeSandboxConfig({ enabled: true, paths: { "/etc": [{ path: "/etc/hosts" }] } });
			const args = buildBwrapArgs(config, projectDir, syntheticDir, "echo hello");
			if (existsSync("/etc/hosts")) {
				expect(args).toContain("--ro-bind");
				expect(args).toContain("/etc/hosts");
			}
		});

		it("creates synthetic files for content entries", () => {
			const config = normalizeSandboxConfig({
				enabled: true,
				paths: { "/etc": [{ path: "/etc/passwd", content: "nobody\n" }] },
			});
			const args = buildBwrapArgs(config, projectDir, syntheticDir, "echo hello");
			const sourceIdx = args.indexOf("/etc/passwd") - 1;
			const syntheticFile = args[sourceIdx];
			expect(readFileSync(syntheticFile, "utf8")).toBe("nobody\n");
			expect(args).toContain("/etc/passwd");
		});

		it("resolves '.' to cwd", () => {
			const config = normalizeSandboxConfig({ enabled: true, paths: { ".": { mode: "write" } } });
			const args = buildBwrapArgs(config, projectDir, syntheticDir, "echo hello");
			const bindIdx = args.indexOf("--bind");
			expect(args[bindIdx + 1]).toBe(projectDir);
			expect(args[bindIdx + 2]).toBe(projectDir);
		});

		it("can promote writable mounts under an absolute bwrap bind root", () => {
			const previous = process.env.HEIMDALL_BWRAP_BIND_ROOT;
			const bindRoot = join(projectDir, "opt", "dano");
			const workspace = join(bindRoot, "runtime-data", "workspaces", "ws_1");
			mkdirSync(workspace, { recursive: true });
			process.env.HEIMDALL_BWRAP_BIND_ROOT = bindRoot;

			try {
				const config = normalizeSandboxConfig({ enabled: true, paths: { ".": { mode: "write" } } });
				const args = buildBwrapArgs(config, workspace, syntheticDir, "echo hello");

				expectArgSequence(args, ["--bind", bindRoot, bindRoot]);
				expect(args).not.toContain(workspace);
			} finally {
				if (previous === undefined) {
					delete process.env.HEIMDALL_BWRAP_BIND_ROOT;
				} else {
					process.env.HEIMDALL_BWRAP_BIND_ROOT = previous;
				}
			}
		});

		it("normalizes a trailing slash in the bwrap bind root", () => {
			const previous = process.env.HEIMDALL_BWRAP_BIND_ROOT;
			const bindRoot = join(projectDir, "opt", "dano");
			const workspace = join(bindRoot, "runtime-data", "workspaces", "ws_1");
			mkdirSync(workspace, { recursive: true });
			process.env.HEIMDALL_BWRAP_BIND_ROOT = `${bindRoot}/`;

			try {
				const config = normalizeSandboxConfig({ enabled: true, paths: { ".": { mode: "write" } } });
				const args = buildBwrapArgs(config, workspace, syntheticDir, "echo hello");

				expectArgSequence(args, ["--bind", bindRoot, bindRoot]);
			} finally {
				if (previous === undefined) {
					delete process.env.HEIMDALL_BWRAP_BIND_ROOT;
				} else {
					process.env.HEIMDALL_BWRAP_BIND_ROOT = previous;
				}
			}
		});

		it("rejects unsafe bwrap bind roots", () => {
			const previous = process.env.HEIMDALL_BWRAP_BIND_ROOT;
			const config = normalizeSandboxConfig({ enabled: true, paths: { ".": { mode: "write" } } });

			try {
				for (const bindRoot of ["relative/path", "/"]) {
					process.env.HEIMDALL_BWRAP_BIND_ROOT = bindRoot;
					expect(() => buildBwrapArgs(config, projectDir, syntheticDir, "echo hello")).toThrow(
						"Invalid HEIMDALL_BWRAP_BIND_ROOT",
					);
				}
			} finally {
				if (previous === undefined) {
					delete process.env.HEIMDALL_BWRAP_BIND_ROOT;
				} else {
					process.env.HEIMDALL_BWRAP_BIND_ROOT = previous;
				}
			}
		});

		it("supports network isolation", () => {
			const config = normalizeSandboxConfig({ enabled: true, network: "none" });
			const args = buildBwrapArgs(config, projectDir, syntheticDir, "echo hello");
			expect(args).toContain("--unshare-net");
		});

		it("keeps host network by default", () => {
			const args = buildBwrapArgs(normalizeSandboxConfig({ enabled: true }), projectDir, syntheticDir, "echo hello");
			expect(args).not.toContain("--unshare-net");
		});

		it("adds user namespace isolation by default", () => {
			const args = buildBwrapArgs(normalizeSandboxConfig({ enabled: true, paths: {} }), projectDir, syntheticDir, "echo hello");
			expect(args).toContain("--unshare-user");
		});

		it("omits user namespace isolation when disabled", () => {
			const config = normalizeSandboxConfig({ enabled: true, userNamespace: false, paths: {} });
			const args = buildBwrapArgs(config, projectDir, syntheticDir, "echo hello");
			expect(args).not.toContain("--unshare-user");
		});

		it("ends with the command", () => {
			const args = buildBwrapArgs(normalizeSandboxConfig({ enabled: true }), projectDir, syntheticDir, "npm test");
			const sepIdx = args.indexOf("--");
			expect(args[sepIdx + 1]).toBe("bash");
			expect(args[sepIdx + 2]).toBe("-c");
			expect(args[sepIdx + 3]).toBe("npm test");
		});

		it("skips non-existent paths", () => {
			const config = normalizeSandboxConfig({ enabled: true, paths: { "/definitely/does/not/exist": {} } });
			const args = buildBwrapArgs(config, projectDir, syntheticDir, "echo hello");
			expect(args).not.toContain("/definitely/does/not/exist");
		});
	});
});
