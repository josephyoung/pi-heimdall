import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { existsSync, mkdirSync, rmSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { buildBwrapArgs, filterEnv, getSandboxPathAccess, normalizeSandboxConfig, resolverSupportMounts, stripEnv } from "../guards/sandbox-guard";

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

		it("supports network isolation", () => {
			const config = normalizeSandboxConfig({ enabled: true, network: "none" });
			const args = buildBwrapArgs(config, projectDir, syntheticDir, "echo hello");
			expect(args).toContain("--unshare-net");
		});

		it("keeps host network by default", () => {
			const args = buildBwrapArgs(normalizeSandboxConfig({ enabled: true }), projectDir, syntheticDir, "echo hello");
			expect(args).not.toContain("--unshare-net");
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
