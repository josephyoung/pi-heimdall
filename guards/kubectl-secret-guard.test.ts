import { describe, expect, it } from "vitest";
import { KUBECTL_BLOCKED } from "./kubectl-secret-guard.js";

describe("kubectl secret guard", () => {
	it("blocks reading Kubernetes secrets", () => {
		expect(KUBECTL_BLOCKED.test("kubectl get secret")).toBe(true);
		expect(KUBECTL_BLOCKED.test("kubectl get secrets -n default")).toBe(true);
	});

	it("blocks finalizer patching", () => {
		expect(KUBECTL_BLOCKED.test("kubectl patch pod demo -p '{\"metadata\":{\"finalizers\":[]}}'")).toBe(true);
	});

	it("blocks pod exec commands that access sensitive data", () => {
		expect(KUBECTL_BLOCKED.test("kubectl exec pod/demo -- printenv")).toBe(true);
		expect(KUBECTL_BLOCKED.test("kubectl exec pod/demo -- cat /var/run/secrets/kubernetes.io/serviceaccount/token")).toBe(true);
	});
});
