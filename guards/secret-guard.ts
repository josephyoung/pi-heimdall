/**
 * secret-guard
 *
 * Project-scoped secret protection driven by a `.env.json` file at the project
 * root. The file is a flat object whose keys name environment variables that
 * are considered secret.
 *
 * Behavior:
 *   1. `tool_call` (bash): blocks commands referencing secret key names
 *   2. `tool_result` (bash): redacts secret values from output (plaintext,
 *      base64, rot13, reversed, hex, hexdump)
 */

import {
	isToolCallEventType,
	isBashToolResult,
	type ExtensionAPI,
} from "@earendil-works/pi-coding-agent";
import { readFile } from "node:fs/promises";
import { join } from "node:path";

type SecretValues = Record<string, string>;

const REDACTED = "[REDACTED]";

function escapeRegex(s: string): string {
	return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function rot13(input: string): string {
	return input.replace(/[a-zA-Z]/g, (c) => {
		const base = c <= "Z" ? 65 : 97;
		return String.fromCharCode(((c.charCodeAt(0) - base + 13) % 26) + base);
	});
}

function extractDecodedText(output: string): string | null {
	const lines = output.split("\n");
	const decoded: string[] = [];
	let hasHexFormat = false;

	for (const line of lines) {
		const pipeMatch = line.match(/\|([^|]+)\|/);
		if (pipeMatch) {
			hasHexFormat = true;
			decoded.push(pipeMatch[1] ?? "");
			continue;
		}

		const xxdMatch = line.match(
			/^(?:[0-9a-f]+:\s+)?(?:[0-9a-f]{2,4}(?:\s+[0-9a-f]{2,4})*)\s{2,}(\S.*)$/i,
		);
		if (xxdMatch) {
			hasHexFormat = true;
			decoded.push(xxdMatch[1] ?? "");
			continue;
		}

		if (/^\d+\s+/.test(line) && !line.includes("|")) {
			const parts = line.split(/^\d+\s+/);
			if (parts.length > 1 && parts[1] && /\S\s+\S/.test(parts[1])) {
				hasHexFormat = true;
				decoded.push(parts[1].replace(/\s+/g, ""));
			}
		}
	}

	return hasHexFormat ? decoded.join("") : null;
}

function containsSecretInHex(output: string, secretValues: SecretValues): boolean {
	const lower = output.toLowerCase();
	const stripped = lower.replace(/[^0-9a-f]/g, "");

	for (const [key, value] of Object.entries(secretValues)) {
		const fullValue = `${key}=${value}`;
		const hex = Buffer.from(fullValue).toString("hex");

		if (lower.includes(hex)) return true;
		if (stripped.includes(hex)) return true;
	}
	return false;
}

function redactOutput(output: string, secretValues: SecretValues): string {
	const decoded = extractDecodedText(output);
	if (decoded) {
		for (const [key, value] of Object.entries(secretValues)) {
			if (!value) continue;
			if (!decoded.includes(`${key}=`)) continue;
			const tail = value.substring(0, Math.max(5, value.length - 2));
			if (decoded.includes(value) || decoded.includes(tail)) {
				return REDACTED;
			}
		}
	}

	if (containsSecretInHex(output, secretValues)) {
		return REDACTED;
	}

	let result = output;

	for (const [key, value] of Object.entries(secretValues)) {
		if (!value) continue;
		const fullValue = `${key}=${value}`;

		result = result.split(fullValue).join(REDACTED);
		result = result
			.split(Buffer.from(fullValue).toString("base64"))
			.join(REDACTED);
		result = result
			.split(Buffer.from(`${fullValue}\n`).toString("base64"))
			.join(REDACTED);
		result = result.split(rot13(fullValue)).join(REDACTED);
		result = result.split(fullValue.split("").reverse().join("")).join(REDACTED);
	}

	result = result.replace(
		/(\b\w*(?:SECRET|KEY|TOKEN|PASSWORD|PASS|APIKEY|CREDENTIAL|PRIVATE)=)\S*/gi,
		`$1${REDACTED}`,
	);

	return result;
}

export function registerSecretGuard(pi: ExtensionAPI, disabledSet: Set<string>): void {
	let secretKeys: string[] = [];
	let secretValues: SecretValues = {};
	let keyPattern: RegExp | null = null;

	async function loadEnvJson(cwd: string): Promise<void> {
		secretKeys = [];
		secretValues = {};
		keyPattern = null;

		const envPath = join(cwd, ".env.json");
		let parsed: Record<string, unknown>;
		try {
			const raw = await readFile(envPath, "utf8");
			parsed = JSON.parse(raw) as Record<string, unknown>;
		} catch {
			return;
		}

		if (!parsed || typeof parsed !== "object") return;

		secretKeys = Object.keys(parsed).filter((k) => k !== "sops");
		for (const key of secretKeys) {
			const val = process.env[key];
			if (typeof val === "string" && val.length > 0) {
				secretValues[key] = val;
			}
		}

		if (secretKeys.length > 0) {
			const escaped = secretKeys.map(escapeRegex);
			keyPattern = new RegExp(`\\b(?:${escaped.join("|")})\\b`, "i");
		}
	}

	pi.on("session_start", async (_event, ctx) => {
		if (disabledSet.has("secret-guard")) return;
		await loadEnvJson(ctx.cwd);
	});

	pi.on("tool_call", async (event, ctx) => {
		if (disabledSet.has("secret-guard")) return undefined;
		if (!isToolCallEventType("bash", event)) return undefined;
		if (!keyPattern) return undefined;

		const command = event.input.command;
		if (typeof command !== "string") return undefined;

		const match = command.match(keyPattern);
		if (!match) return undefined;

		if (ctx.hasUI) {
			ctx.ui.notify(`heimdall: blocked bash referencing secret "${match[0]}"`, "warning");
		}

		return {
			block: true,
			reason:
				`Blocked: command references secret "${match[0]}". ` +
				`This is protected by pi-heimdall/secret-guard based on .env.json. ` +
				`Ask the user to run this command directly in their terminal if needed. ` +
				`Never attempt to bypass this protection or ask the user to disable it.`,
		};
	});

	pi.on("tool_result", async (event, _ctx) => {
		if (disabledSet.has("secret-guard")) return undefined;
		if (!isBashToolResult(event)) return undefined;

		const hasValues = Object.keys(secretValues).length > 0;

		let changed = false;
		const newContent = event.content.map((part) => {
			if (part.type !== "text") return part;
			if (typeof part.text !== "string") return part;

			const next = redactOutput(part.text, hasValues ? secretValues : {});
			if (next === part.text) return part;

			changed = true;
			return { ...part, text: next };
		});

		if (!changed) return undefined;
		return { content: newContent };
	});
}
