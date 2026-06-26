import { describe, expect, it } from "vitest";
import { checkCommand } from "../guards/command-policy-guard";

const policies = [
	{
		name: "no-cargo-test",
		blocked: ["cargo", "test"],
		message: "Use mise test instead.",
	},
];

describe("command-policy-guard regressions", () => {
	it("leaves escaped double-quoted heredoc mode so later blocked commands are still checked", () => {
		const command = String.raw`cat <<\"EOF\"
ignored
EOF; cargo test`;

		expect(checkCommand(command, policies)?.name).toBe("no-cargo-test");
	});

	it("ignores blocked-looking commands inside a double-quoted heredoc body", () => {
		const command = "cat <<\"EOF\"\ncargo test\nEOF";

		expect(checkCommand(command, policies)).toBeNull();
	});
});
