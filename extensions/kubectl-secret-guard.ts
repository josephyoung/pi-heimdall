/**
 * kubectl-secret-guard
 *
 * Blocks three classes of risky kubectl invocations inside the bash tool:
 *
 *   1. `kubectl get secrets` / `kubectl get secret`
 *   2. `kubectl patch ... finalizers` — bypasses Kubernetes deletion safeguards
 *   3. `kubectl exec` into a pod that would leak secrets via:
 *        - reading `app.ini`
 *        - reading anything under `/var/run/secrets`
 *        - running `env` / `printenv`
 *
 * Regex matches within a single shell segment (terminators: ; | & newline),
 * so a separate `kubectl get pods` earlier in the same script does not trip
 * the guard for an unrelated later command.
 *
 * Ported from opencode plugin `kubectl-secret-guard.ts`.
 */

import { isToolCallEventType, type ExtensionAPI } from "@mariozechner/pi-coding-agent";

// One segment atom: any char that is not a shell terminator, plus escaped newlines.
const SEG = "(?:[^;|&\\n]|\\\\\\n)";

export const KUBECTL_BLOCKED = new RegExp(
	`\\bkubectl\\b${SEG}*\\b(?:(get\\b${SEG}*\\bsecrets?\\b)|(patch\\b${SEG}*finalizers)|(exec\\b${SEG}*(?:app\\.ini|/var/run/secrets|\\bprintenv\\b|\\benv\\b)))`,
);

function getBlockReason(command: string): string | null {
	const m = KUBECTL_BLOCKED.exec(command);
	if (!m) return null;

	const trailer =
		`This is protected by pi-heimdall/kubectl-secret-guard. ` +
		`Ask the user to run this command directly in their terminal if needed. ` +
		`Never attempt to bypass this protection or ask the user to disable it.`;

	if (m[1]) {
		return `Blocked: command would execute "kubectl get secret". ${trailer}`;
	}
	if (m[2]) {
		return (
			`Blocked: command would patch finalizers. ` +
			`Removing finalizers bypasses Kubernetes deletion safeguards and can cause resource leaks. ` +
			trailer
		);
	}
	return (
		`Blocked: command would exec into a pod and access sensitive data ` +
		`(app.ini, /var/run/secrets, or environment variables). ` +
		trailer
	);
}

export default function (pi: ExtensionAPI) {
	pi.on("tool_call", async (event, ctx) => {
		if (!isToolCallEventType("bash", event)) return undefined;

		const command = event.input.command;
		if (typeof command !== "string") return undefined;

		const reason = getBlockReason(command);
		if (!reason) return undefined;

		if (ctx.hasUI) {
			ctx.ui.notify("heimdall: blocked risky kubectl command", "warning");
		}

		return { block: true, reason };
	});
}
