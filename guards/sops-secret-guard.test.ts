import { describe, expect, it } from "vitest";
import { SOPS_DECRYPT } from "./sops-secret-guard.js";

describe("sops secret guard", () => {
	it("blocks decrypting sops commands", () => {
		expect(SOPS_DECRYPT.test("sops decrypt secrets.yaml")).toBe(true);
		expect(SOPS_DECRYPT.test("sops -d secrets.yaml")).toBe(true);
		expect(SOPS_DECRYPT.test("sops --decrypt secrets.yaml")).toBe(true);
		expect(SOPS_DECRYPT.test("mise exec -- sops decrypt secrets.yaml")).toBe(true);
	});

	it("blocks bare sops file access", () => {
		expect(SOPS_DECRYPT.test("sops secrets.yaml")).toBe(true);
	});

	it("allows safe sops commands", () => {
		expect(SOPS_DECRYPT.test("sops --version")).toBe(false);
		expect(SOPS_DECRYPT.test("sops encrypt secrets.yaml")).toBe(false);
	});
});
