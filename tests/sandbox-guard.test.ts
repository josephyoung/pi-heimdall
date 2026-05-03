import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { existsSync, mkdirSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { buildBwrapArgs, stripEnv } from "../guards/sandbox-guard";

describe("sandbox-guard", () => {
	describe("stripEnv", () => {
		it("only keeps allowlisted env vars", () => {
			const env = {
				PATH: "/usr/bin",
				HOME: "/home/user",
				LANG: "en_US.UTF-8",
				AWS_SECRET_ACCESS_KEY: "super-secret-key",
				DATABASE_URL: "postgres://user:pass@localhost/db",
				GITHUB_TOKEN: "ghp_abc123",
			};

			const result = stripEnv(["PATH", "HOME", "LANG"], env);

			expect(result).toEqual({
				PATH: "/usr/bin",
				HOME: "/home/user",
				LANG: "en_US.UTF-8",
			});
			expect(result).not.toHaveProperty("AWS_SECRET_ACCESS_KEY");
			expect(result).not.toHaveProperty("DATABASE_URL");
			expect(result).not.toHaveProperty("GITHUB_TOKEN");
		});

		it("returns empty object when no env vars match allowlist", () => {
			const env = { SECRET: "value" };
			const result = stripEnv(["PATH"], env);
			expect(result).toEqual({});
		});

		it("handles empty allowlist", () => {
			const env = { PATH: "/usr/bin" };
			const result = stripEnv([], env);
			expect(result).toEqual({});
		});

		it("handles empty env", () => {
			const result = stripEnv(["PATH"], {});
			expect(result).toEqual({});
		});
	});

	describe("buildBwrapArgs", () => {
		const defaultConfig = {
			enabled: true,
			networkAccess: true,
			writableRoots: [".", "/tmp"] as string[],
			systemPaths: ["/usr", "/lib", "/lib64", "/bin", "/sbin"] as string[],
			etcReal: [
				"/etc/resolv.conf",
				"/etc/hosts",
				"/etc/ssl",
				"/etc/ca-certificates",
			] as string[],
			etcSynthetic: {
				"/etc/passwd": "nobody:x:65534:65534:Nobody:/nonexistent:/usr/sbin/nologin\n",
				"/etc/group": "nogroup:x:65534:\n",
			} as Record<string, string>,
			envAllowlist: ["PATH", "HOME", "LANG"],
			extraReadPaths: [] as string[],
			denyReadGlobs: [] as string[],
		};

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

		it("starts with tmpfs root", () => {
			const args = buildBwrapArgs(defaultConfig, projectDir, syntheticDir, "echo hello");
			expect(args[0]).toBe("--tmpfs");
			expect(args[1]).toBe("/");
		});

		it("mounts minimal /dev", () => {
			const args = buildBwrapArgs(defaultConfig, projectDir, syntheticDir, "echo hello");
			const devIdx = args.indexOf("--dev");
			expect(devIdx).toBeGreaterThanOrEqual(0);
			expect(args[devIdx + 1]).toBe("/dev");
		});

		it("mounts system paths read-only", () => {
			const args = buildBwrapArgs(defaultConfig, projectDir, syntheticDir, "echo hello");
			for (const sysPath of ["/usr", "/lib", "/bin", "/sbin"]) {
				if (existsSync(sysPath)) {
					expect(args).toContain("--ro-bind");
					expect(args).toContain(sysPath);
				}
			}
		});

		it("mounts project directory as writable", () => {
			const config = { ...defaultConfig, writableRoots: [projectDir, "/tmp"] };
			const args = buildBwrapArgs(config, projectDir, syntheticDir, "echo hello");
			expect(args).toContain("--bind");
			expect(args).toContain(projectDir);
		});

		it("mounts /tmp as writable", () => {
			const args = buildBwrapArgs(defaultConfig, projectDir, syntheticDir, "echo hello");
			expect(args).toContain("--bind");
			expect(args).toContain("/tmp");
		});

		it("includes namespace isolation flags", () => {
			const args = buildBwrapArgs(defaultConfig, projectDir, syntheticDir, "echo hello");
			expect(args).toContain("--unshare-user");
			expect(args).toContain("--unshare-pid");
			expect(args).toContain("--proc");
		});

		it("includes lifecycle flags", () => {
			const args = buildBwrapArgs(defaultConfig, projectDir, syntheticDir, "echo hello");
			expect(args).toContain("--die-with-parent");
			expect(args).toContain("--new-session");
		});

		it("does NOT include --unshare-net when networkAccess is true", () => {
			const args = buildBwrapArgs(defaultConfig, projectDir, syntheticDir, "echo hello");
			expect(args).not.toContain("--unshare-net");
		});

		it("ends with the command", () => {
			const args = buildBwrapArgs(defaultConfig, projectDir, syntheticDir, "npm test");
			const sepIdx = args.indexOf("--");
			expect(sepIdx).toBeGreaterThanOrEqual(0);
			expect(args[sepIdx + 1]).toBe("bash");
			expect(args[sepIdx + 2]).toBe("-c");
			expect(args[sepIdx + 3]).toBe("npm test");
		});

		it("creates synthetic /etc files", () => {
			buildBwrapArgs(defaultConfig, projectDir, syntheticDir, "echo hello");
			expect(existsSync(join(syntheticDir, "passwd"))).toBe(true);
			expect(existsSync(join(syntheticDir, "group"))).toBe(true);
		});

		it("resolves '.' in writableRoots to cwd", () => {
			const config = { ...defaultConfig, writableRoots: [".", "/tmp"] };
			const args = buildBwrapArgs(config, projectDir, syntheticDir, "echo hello");
			const bindIdx = args.indexOf("--bind");
			expect(args[bindIdx + 1]).toBe(projectDir);
			expect(args[bindIdx + 2]).toBe(projectDir);
		});

		it("skips non-existent system paths", () => {
			const config = {
				...defaultConfig,
				systemPaths: ["/definitely/does/not/exist", "/usr"],
			};
			const args = buildBwrapArgs(config, projectDir, syntheticDir, "echo hello");
			expect(args).not.toContain("/definitely/does/not/exist");
		});

		it("skips non-existent etcReal paths", () => {
			const config = {
				...defaultConfig,
				etcReal: ["/etc/nonexistent-file"],
			};
			const args = buildBwrapArgs(config, projectDir, syntheticDir, "echo hello");
			expect(args).not.toContain("/etc/nonexistent-file");
		});
	});
});
