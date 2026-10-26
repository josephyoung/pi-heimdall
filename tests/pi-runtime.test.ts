import { mkdtemp, mkdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { expect, it, vi } from "vitest";
import {
	DefaultResourceLoader, ExtensionRunner, ModelRegistry, ModelRuntime,
	SessionManager, SettingsManager,
} from "@earendil-works/pi-coding-agent";

it("loads Heimdall in Pi 1.4.0 and enforces guards through its actual tool event runner", async () => {
	const root = await mkdtemp(join(tmpdir(), "heimdall-pi-runtime-"));
	const cwd = join(root, "workspace"), agentDir = join(root, "agent");
	await mkdir(cwd); await mkdir(agentDir);
	vi.stubEnv("PI_CODING_AGENT_DIR", agentDir);
	try {
		const loader = new DefaultResourceLoader({ cwd, agentDir,
			settingsManager: SettingsManager.inMemory(), noExtensions: true,
			noSkills: true, noPromptTemplates: true, noThemes: true, noContextFiles: true,
			additionalExtensionPaths: [resolve("extensions/heimdall.ts")] });
		await loader.reload();
		const loaded = loader.getExtensions();
		expect(loaded.errors).toEqual([]);
		expect(loaded.extensions).toHaveLength(1);
		const models = await ModelRuntime.create({ authPath: join(agentDir, "auth.json"),
			modelsPath: join(agentDir, "models.json"), allowModelNetwork: false, refreshOnCreate: false });
		const runner = new ExtensionRunner(loaded.extensions, loaded.runtime, cwd,
			SessionManager.inMemory(cwd), new ModelRegistry(models));
		const errors: unknown[] = [];
		runner.onError(error => errors.push(error));
		await runner.emit({ type: "session_start", reason: "startup" });
		expect(await runner.emitToolCall({ type: "tool_call", toolName: "read",
			toolCallId: "secret", input: { path: ".env" } })).toMatchObject({ block: true });
		expect(await runner.emitToolCall({ type: "tool_call", toolName: "bash",
			toolCallId: "kubectl", input: { command: "kubectl get secrets" } })).toMatchObject({ block: true });
		expect(await runner.emitToolCall({ type: "tool_call", toolName: "read",
			toolCallId: "example", input: { path: ".env.example" } })).toBeUndefined();
		expect(errors).toEqual([]);
	} finally {
		vi.unstubAllEnvs();
		await rm(root, { recursive: true, force: true });
	}
});
