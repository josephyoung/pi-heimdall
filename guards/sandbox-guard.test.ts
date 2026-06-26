import { describe, expect, it } from "vitest";
import { buildBwrapArgs, normalizeSandboxConfig } from "./sandbox-guard.js";

const cwd = process.cwd();
const syntheticDir = process.env.TMPDIR || "/tmp";

describe("sandbox user namespace configuration", () => {
	it("defaults userNamespace to true", () => {
		const config = normalizeSandboxConfig({ enabled: true });

		expect(config.userNamespace).toBe(true);
	});

	it("allows disabling user namespace isolation", () => {
		const config = normalizeSandboxConfig({ enabled: true, userNamespace: false });

		expect(config.userNamespace).toBe(false);
	});

	it("adds --unshare-user by default", () => {
		const config = normalizeSandboxConfig({ enabled: true, paths: {} });
		const args = buildBwrapArgs(config, cwd, syntheticDir, "echo ok");

		expect(args).toContain("--unshare-user");
	});

	it("omits --unshare-user when userNamespace is false", () => {
		const config = normalizeSandboxConfig({ enabled: true, userNamespace: false, paths: {} });
		const args = buildBwrapArgs(config, cwd, syntheticDir, "echo ok");

		expect(args).not.toContain("--unshare-user");
	});
});
