/**
 * sops-secret-guard
 *
 * Blocks any `sops` invocation in the bash tool that decrypts content.
 *
 * Modes covered:
 *   sops decrypt <file>        — subcommand
 *   sops --decrypt / -d <file> — long/short flag
 *   sops exec-env <file> <cmd> — decrypts into environment
 *   sops exec-file <file> <cmd>— decrypts to a temp file
 *   sops edit <file>           — decrypts for editing
 *   sops <file>                — bare invocation (decrypts for editing)
 *
 * "sops as a command" means sops appears at:
 *   - start of string / after a shell terminator (; | & \n), with optional whitespace
 *   - after -- (end-of-options marker), e.g. `mise exec -- sops ...`
 *   - optionally preceded by KEY=val env assignments
 *
 * Safe subcommands pass through via a negative lookahead:
 *   encrypt/--encrypt/-e, rotate/--rotate/-r, publish, keyservice, filestatus,
 *   groups, updatekeys, set, unset, completion, help, h, --version/-v
 *
 * Ported from opencode plugin `sops-secret-guard.ts`.
 */

import { isToolCallEventType, type ExtensionAPI } from "@mariozechner/pi-coding-agent";

// One segment atom: any char that is not a shell terminator, plus escaped newlines.
const SEG = "(?:[^;|&\\n]|\\\\\\n)";

const START = "(?:(?:^|[;|&\\n])\\s*)";
const ENV_PREFIX = "(?:[A-Z_][A-Z0-9_]*=[^\\s]*\\s+)*";
const CMD_SOPS = `(?:${START}${ENV_PREFIX}sops\\b)`;
const CMD_SOPS_AFTER_DASHDASH = `(?:--\\s+${ENV_PREFIX}sops\\b)`;
const SOPS_CMD = `(?:${CMD_SOPS}|${CMD_SOPS_AFTER_DASHDASH})`;

const NO_SAFE_AHEAD =
	`(?!${SEG}*\\b(?:encrypt|rotate|publish|keyservice|filestatus|groups|updatekeys|set|unset|completion|help|h)\\b)` +
	`(?!${SEG}*(?:--encrypt\\b|--rotate\\b|-e\\b|-r\\b))` +
	`(?!${SEG}*(?:--version\\b|-v\\b))`;

export const SOPS_DECRYPT = new RegExp(
	// Alt 1: explicit decrypt subcommands
	`${SOPS_CMD}${SEG}*\\b(?:decrypt|exec-env|exec-file|edit)\\b` +
		// Alt 2: --decrypt or -d flag
		`|${SOPS_CMD}${SEG}*(?:--decrypt\\b|-d\\b)` +
		// Alt 3: bare invocation — no safe subcommand/flag in this segment
		`|${SOPS_CMD}${NO_SAFE_AHEAD}`,
	"m",
);

export default function (pi: ExtensionAPI) {
	pi.on("tool_call", async (event, ctx) => {
		if (!isToolCallEventType("bash", event)) return undefined;

		const command = event.input.command;
		if (typeof command !== "string") return undefined;
		if (!SOPS_DECRYPT.test(command)) return undefined;

		if (ctx.hasUI) {
			ctx.ui.notify("heimdall: blocked sops decrypt", "warning");
		}

		return {
			block: true,
			reason:
				`Blocked: command would decrypt secrets via sops. ` +
				`This is protected by pi-heimdall/sops-secret-guard. ` +
				`Ask the user to run this command directly in their terminal if needed. ` +
				`Never attempt to bypass this protection or ask the user to disable it.`,
		};
	});
}
