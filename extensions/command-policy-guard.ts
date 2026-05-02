/**
 * command-policy-guard
 *
 * Blocks bash commands that violate repo policy as defined in `.pi/heimdall.json`.
 *
 * Config format (`.pi/heimdall.json`):
 * {
 *   "commandPolicies": [
 *     {
 *       "name": "no-cargo-test",
 *       "blocked": ["cargo", "test"],
 *       "message": "Use `mise test` or `mise run test` instead of `cargo test`."
 *     },
 *     {
 *       "name": "no-cargo-nextest",
 *       "blocked": ["cargo", "nextest"],
 *       "message": "Use `mise test` or `mise run --force test` instead of `cargo nextest`."
 *     }
 *   ]
 * }
 *
 * Uses `shell-quote` for proper shell tokenization. The parsed token stream
 * is split on shell operators (;, &&, ||, |) into command segments. Each
 * segment's command tokens are matched against configured policies after
 * stripping env assignments, wrapper commands, and shell prefix tokens.
 *
 * Bypass hardening:
 *   - shell-quote handles backslash escapes, quote splicing, etc.
 *   - Path-qualified commands match by basename.
 *   - Shell -c invocations are recursively parsed.
 *   - Heredoc bodies are detected and skipped.
 *   - Known wrapper commands and shell prefixes are stripped.
 */

import { isToolCallEventType, type ExtensionAPI } from "@mariozechner/pi-coding-agent";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { parse as shellParse, type ParseEntry } from "shell-quote";

interface CommandPolicy {
	name: string;
	blocked: string[];
	message: string;
}

interface HeimdallConfig {
	commandPolicies?: CommandPolicy[];
}

const COMMAND_SEPARATORS = new Set([";", "&&", "||", "|", "(", ")"]);

const WRAPPER_COMMANDS = new Set([
	"sudo",
	"doas",
	"pkexec",
	"env",
	"exec",
	"nice",
	"ionice",
	"chrt",
	"taskset",
	"command",
	"time",
	"timeout",
	"strace",
	"gdb",
	"lldb",
	"valgrind",
	"eval",
]);

const SHELL_COMMANDS = new Set([
	"bash",
	"sh",
	"zsh",
	"dash",
	"ksh",
	"ash",
	"fish",
]);

const SHELL_PREFIX_TOKENS = new Set(["{", "("]);

const REDIRECT_OPS = new Set([">", ">>", "<", ">&", "<&", ">|", "&>", "&>>", "<<<"]);

/**
 * Extract the basename of a path-qualified command.
 * `/usr/bin/cargo` → `cargo`, `./cargo` → `cargo`, `cargo` → `cargo`.
 */
function tokenBasename(token: string): string {
	if (!token.includes("/")) return token;
	const lastSlash = token.lastIndexOf("/");
	return lastSlash >= 0 ? token.substring(lastSlash + 1) : token;
}

/**
 * Check if a parsed entry is a plain string (not an operator/comment/glob object).
 */
function isStringToken(t: ParseEntry): t is string {
	return typeof t === "string";
}

/**
 * Check if a parsed entry is a specific operator.
 */
function isOp(t: ParseEntry, op: string): boolean {
	return typeof t === "object" && "op" in t && t.op === op;
}

/**
 * Split the parsed token stream into command segments at shell operators
 * that act as command separators. Heredoc bodies are detected and skipped.
 */
function splitCommandSegments(tokens: ParseEntry[]): string[][] {
	const segments: string[][] = [];
	let current: string[] = [];
	let heredocDelim: string | null = null;

	for (let i = 0; i < tokens.length; i++) {
		const t = tokens[i]!;

		// If we're inside a heredoc body, skip until we see the delimiter.
		if (heredocDelim !== null) {
			if (isStringToken(t) && t === heredocDelim) {
				heredocDelim = null;
			}
			continue;
		}

		// Detect heredoc start: two consecutive < operators followed by a word.
		if (
			isOp(t, "<") &&
			i + 1 < tokens.length &&
			isOp(tokens[i + 1]!, "<")
		) {
			i++; // skip second <
			// Next string token is the delimiter.
			if (i + 1 < tokens.length && isStringToken(tokens[i + 1]!)) {
				i++;
				heredocDelim = (tokens[i]! as string).replace(/^['"]|['"]$/g, "");
			}
			continue;
		}

		// Command separator operators split into a new segment.
		if (typeof t === "object" && "op" in t && COMMAND_SEPARATORS.has(t.op)) {
			if (current.length > 0) {
				segments.push(current);
				current = [];
			}
			continue;
		}

		// Skip redirect operators and their targets.
		if (typeof t === "object" && "op" in t && REDIRECT_OPS.has(t.op)) {
			// Skip the next token (the redirect target) if it's a string.
			if (i + 1 < tokens.length && isStringToken(tokens[i + 1]!)) {
				i++;
			}
			continue;
		}

		// Plain string token — add to current segment.
		if (isStringToken(t)) {
			current.push(t);
		}

		// Comments and globs are silently ignored.
	}

	if (current.length > 0) {
		segments.push(current);
	}

	return segments;
}

/**
 * Find the first policy that matches a command segment, after skipping
 * env assignments, wrappers, and shell prefixes.
 */
function matchSegment(
	tokens: string[],
	policies: CommandPolicy[],
	checkRecursive: (cmd: string) => CommandPolicy | null,
): CommandPolicy | null {
	let pos = 0;

	// Skip leading KEY=value environment assignments.
	while (pos < tokens.length && /^[A-Za-z_][A-Za-z0-9_]*=/.test(tokens[pos]!)) {
		pos++;
	}

	// Skip known wrapper commands and shell prefix tokens.
	while (
		pos < tokens.length &&
		(WRAPPER_COMMANDS.has(tokens[pos]!) ||
			SHELL_PREFIX_TOKENS.has(tokens[pos]!))
	) {
		pos++;
	}

	// Detect shell -c 'command' for recursive parsing.
	if (
		pos + 2 < tokens.length &&
		SHELL_COMMANDS.has(tokens[pos]!) &&
		tokens[pos + 1] === "-c" &&
		tokens[pos + 2] !== undefined
	) {
		const cmdString = tokens[pos + 2]!;
		const subResult = checkRecursive(cmdString);
		if (subResult) return subResult;
	}

	// Match against policies using the remaining tokens.
	const effective = tokens.slice(pos);

	for (const policy of policies) {
		if (effective.length < policy.blocked.length) continue;

		let match = true;
		for (let i = 0; i < policy.blocked.length; i++) {
			const got = effective[i]!;
			const want = policy.blocked[i]!;
			if (i === 0) {
				// First token: allow basename matching for path-qualified commands.
				if (got !== want && tokenBasename(got) !== want) {
					match = false;
					break;
				}
			} else {
				if (got !== want) {
					match = false;
					break;
				}
			}
		}

		if (match) return policy;
	}

	return null;
}

/**
 * Full pipeline: parse → split segments → match.
 *
 * Note: `shell-parse` treats bare newlines as whitespace, so it won't
 * split `echo foo\ncargo test` into two commands. The `;`, `&&`, `||`,
 * `|` operators are the reliable command separators. In practice an LLM
 * generating a single bash tool call uses those operators, not bare newlines.
 */
function checkCommand(
	command: string,
	policies: CommandPolicy[],
): CommandPolicy | null {
	const parsed = shellParse(command);
	const segments = splitCommandSegments(parsed);
	const check = (cmd: string): CommandPolicy | null => checkCommand(cmd, policies);

	for (const segment of segments) {
		const policy = matchSegment(segment, policies, check);
		if (policy) return policy;
	}

	return null;
}

// ── Extension ──

export default function (pi: ExtensionAPI) {
	let policies: CommandPolicy[] = [];

	async function loadConfig(cwd: string): Promise<void> {
		policies = [];

		const configPath = join(cwd, ".pi", "heimdall.json");
		let parsed: HeimdallConfig;
		try {
			const raw = await readFile(configPath, "utf8");
			parsed = JSON.parse(raw) as HeimdallConfig;
		} catch {
			return;
		}

		if (!parsed || typeof parsed !== "object") return;
		policies = parsed.commandPolicies ?? [];
	}

	pi.on("session_start", async (_event, ctx) => {
		await loadConfig(ctx.cwd);
	});

	pi.on("tool_call", async (event, ctx) => {
		if (!isToolCallEventType("bash", event)) return undefined;
		if (policies.length === 0) return undefined;

		const command = event.input.command;
		if (typeof command !== "string") return undefined;

		const policy = checkCommand(command, policies);
		if (policy) {
			const reason =
				`Blocked: command violates repo policy "${policy.name}".\n` +
				`${policy.message}\n` +
				`This is protected by pi-heimdall/command-policy-guard. ` +
				`Ask the user to run this command directly in their terminal if needed. ` +
				`Never attempt to bypass this protection or ask the user to disable it.`;

			if (ctx.hasUI) {
				ctx.ui.notify(
					`heimdall: blocked policy violation (${policy.name})`,
					"warning",
				);
			}

			return { block: true, reason };
		}

		return undefined;
	});
}
